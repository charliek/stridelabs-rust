//! `tracing` subscriber setup.
//!
//! Carried over from an existing service's `observability::logging::init`,
//! which hard-codes the format switch behind a service-specific env-var read
//! taken inside the
//! function. A shared crate can't assume every consumer wants that exact
//! variable name (or wants an env var at all — a test harness might want to
//! force JSON unconditionally), so here the format is a plain parameter;
//! callers that do want env-var control read it themselves (e.g. via
//! `stridelabs_config::env_or("LOG_FORMAT", "text")`) and pass the result in.
//!
//! The one opinion this module does hold is [`LogFormat::from_environment`]:
//! readable text in development, Cloud Logging lines everywhere else — the
//! rule StrideLabs services already applied by hand, made the default so new
//! services don't each re-derive it.
//!
//! [`TargetCaps`] (through [`init_logging_with`]) is new here: per-target
//! level ceilings that hold even when `RUST_LOG` replaces the default
//! filter, for a dependency whose verbose output is a leak (a WebSocket
//! client that logs every frame, credentials included, at `trace`).
//! [`try_init_logging_with`] installs the same thing and says whether it did,
//! for a caller that must not run with those caps out of force.

use std::sync::Once;

use tracing::level_filters::LevelFilter;
use tracing::{Metadata, Subscriber};
use tracing_log::{AsLog, LogTracer};
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Layer};

use crate::cloud::CloudLayer;

/// Log output format, selected by the caller.
///
/// `#[non_exhaustive]` so a new format isn't a breaking change for a
/// consumer that matches on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogFormat {
    /// Human-readable, for local development.
    Text,
    /// tracing-subscriber's line-delimited JSON
    /// (`{timestamp, level, fields: {message, …}, target}`, plus — for an
    /// event inside a span — `span`, the innermost span's fields, and
    /// `spans`, every entered span's fields root first).
    Json,
    /// One Google Cloud Logging structured JSON object per line (`severity`,
    /// a top-level `message`, `httpRequest`, request/trace correlation) —
    /// see [`crate::cloud`]. For deployed services.
    Cloud,
}

impl LogFormat {
    /// The format for a deployment environment name: [`LogFormat::Text`]
    /// for exactly `"development"`, [`LogFormat::Cloud`] for anything else.
    ///
    /// The comparison is exact — no trimming or case folding — matching
    /// Python `stridelabs-logging`'s `ENVIRONMENT != "development"` rule, so
    /// a mistyped value fails toward structured lines: harmless noise in a
    /// terminal, where plain text in production would be unsearchable.
    pub fn from_environment(env: &str) -> Self {
        if env == "development" {
            Self::Text
        } else {
            Self::Cloud
        }
    }
}

/// Per-target level ceilings that hold whatever the level filter says —
/// including a `RUST_LOG` that replaced the default one. Installed by
/// [`init_logging_with`].
///
/// Each cap is a target and the most verbose level it may log at. A span or
/// event is dropped when its level is more verbose than the cap of a target
/// it falls under; everything else goes on to the level filter untouched.
/// The caps are a second filter, checked *in addition to* the level filter,
/// so they can only remove: neither `RUST_LOG=trace` nor
/// `RUST_LOG=tungstenite=trace` lifts a capped target above its cap. A capped
/// span is never created, so its fields reach no line either.
///
/// # Matching
///
/// A target falls under a cap when it *is* the cap's target or a module path
/// beneath it: a cap on `tungstenite` covers `tungstenite` and
/// `tungstenite::protocol::frame`, but not `tungstenite_extra` (an
/// `EnvFilter` directive matches any target that merely starts with the same
/// characters). The comparison is exact, case included. When several caps
/// cover one target (`tungstenite` and `tungstenite::protocol`, or the same
/// target twice) every one of them applies, so the strictest wins whatever
/// the order — a more specific cap cannot loosen a broader one, the way a
/// more specific `EnvFilter` directive would.
///
/// A trailing `::` is ignored, so `tungstenite::` is the same cap as
/// `tungstenite`. An empty target (`""`, or `"::"` once its `::` is ignored)
/// is **not** a wildcard: by the rule above it covers only a target that is
/// empty or starts with `::`, which no module path does, so it caps nothing
/// a crate logs.
///
/// A record from the `log` crate (tungstenite logs through `log`, and
/// [`init_logging`] bridges it into `tracing`) is matched on the record's own
/// target, just as `EnvFilter` matches it.
///
/// A capped span takes its fields with it, correlation included: capping
/// this crate's `stridelabs_observability` target below `INFO` drops
/// [`RequestLogLayer`](crate::RequestLogLayer)'s request span, so the lines
/// inside each request lose their `requestId` and trace.
///
/// ```
/// use stridelabs_observability::{init_logging_with, LogFormat, TargetCaps};
/// use tracing::level_filters::LevelFilter;
/// use tracing::Level;
///
/// // tungstenite logs every WebSocket frame it reads or writes at `trace`,
/// // payload included; at `info` it logs a handful of connection warnings.
/// let caps = TargetCaps::new()
///     .cap("tungstenite", Level::INFO)
///     .cap("tokio_tungstenite", Level::INFO)
///     // `LevelFilter::OFF` silences a target entirely.
///     .cap("chatty_dependency", LevelFilter::OFF);
/// init_logging_with(LogFormat::Text, "info", &caps);
/// ```
#[derive(Debug, Clone, Default)]
pub struct TargetCaps {
    caps: Vec<(String, LevelFilter)>,
}

impl TargetCaps {
    /// No caps: [`init_logging_with`] with this installs exactly what
    /// [`init_logging`] does.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cap `target`, and every module path beneath it, at `max_level` (a
    /// [`tracing::Level`], or a [`LevelFilter`] — `LevelFilter::OFF` drops
    /// all of the target's output). A trailing `::` on `target` is ignored.
    /// See the [type docs](Self) for the matching rule.
    #[must_use]
    pub fn cap(mut self, target: impl Into<String>, max_level: impl Into<LevelFilter>) -> Self {
        let mut target = target.into();
        // `tungstenite::` reads as "the tungstenite module tree", but kept
        // as written it would cover only targets spelled `tungstenite::::…`,
        // which don't exist — leaving the crate it names uncapped.
        target.truncate(target.trim_end_matches("::").len());
        self.caps.push((target, max_level.into()));
        self
    }

    /// Whether a span or event with `metadata` is within every cap that
    /// covers its target.
    fn allows(&self, metadata: &Metadata<'_>) -> bool {
        let level = metadata.level();
        self.caps
            .iter()
            .all(|(target, max_level)| level <= max_level || !covers(target, metadata.target()))
    }
}

/// Whether `target` is `cap` itself or a module path beneath it.
fn covers(cap: &str, target: &str) -> bool {
    target
        .strip_prefix(cap)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
}

/// [`TargetCaps`] as a global filter layer.
///
/// Not tracing-subscriber's `Targets`, which can express a ceiling but
/// matches by plain prefix (`tungstenite` would cover `tungstenite_extra`),
/// lets the most specific directive win (a looser sub-module cap would undo
/// a stricter crate-wide one), and, given the `TRACE` default it needs to
/// pass every uncapped target, reports `TRACE` as its level hint.
/// `Layered` keeps the most verbose of its layers' hints, so that would raise
/// the subscriber's hint to `TRACE` whatever the level filter says — and
/// `try_init` hands that hint to the `log` bridge as its max level, so every
/// `log::trace!` in the process would be formatted only to be dropped. This
/// layer gives no hint (the default `None`), which leaves the level filter's
/// as the subscriber's: caps only remove, so it is still an upper bound.
///
/// `register_callsite` is the default, derived from `enabled`: the caps
/// never change, so a callsite's answer can be cached.
struct CapsLayer(TargetCaps);

impl<S: Subscriber> Layer<S> for CapsLayer {
    fn enabled(&self, metadata: &Metadata<'_>, _: Context<'_, S>) -> bool {
        self.0.allows(metadata)
    }
}

static INIT: Once = Once::new();

/// Initialize the global `tracing` subscriber.
///
/// The level filter is read from the standard `RUST_LOG` env var if set,
/// else falls back to `default_filter` (callers pass their own
/// service-specific fallback, e.g. `"info"` or `"info,sqlx=warn"` — this
/// crate doesn't hard-code a house filter string).
///
/// `RUST_LOG` replaces `default_filter` wholesale, so a cap written into
/// `default_filter` (`"info,tungstenite=info"`) is gone the moment
/// `RUST_LOG` is set. Caps that must hold whatever the filter go to
/// [`init_logging_with`] instead; this is that function with no caps.
///
/// Idempotent: safe to call more than once (e.g. once per test in a suite
/// that shares a process) — only the first call installs a subscriber.
/// Later calls, even with a different `format`/`default_filter`, are a
/// silent no-op; `tracing_subscriber`'s global subscriber can only be set
/// once per process, so there is nothing more this could do (and no way to
/// signal "you asked for something different" back to a caller that isn't
/// checking a return value).
///
/// The same reasoning applies when *something else* already installed a
/// global subscriber (a test harness, or a host that configures its own
/// before calling this): `try_init` is used rather than `init` so that case
/// is the same silent no-op instead of a panic. A library helper has no
/// business aborting a process over whose logging is already set up.
pub fn init_logging(format: LogFormat, default_filter: &str) {
    init_logging_with(format, default_filter, &TargetCaps::new());
}

/// [`init_logging`], plus `caps`: per-target level ceilings checked in
/// addition to the level filter, so they hold whether that filter came from
/// `RUST_LOG` or from `default_filter` (see [`TargetCaps`]).
///
/// Shares [`init_logging`]'s one-time initialization and its rules: only the
/// first call to either function in a process installs a subscriber, and
/// every later call to either — whatever its arguments, caps included — is
/// a silent no-op, as is any call made after something else installed a
/// global subscriber. So call this before anything else sets logging up:
/// caps passed to a call that doesn't install are not in force.
///
/// Nothing here tells the caller whether its caps took. When they guard a
/// secret (a relay capping the WebSocket client that logs its API key), call
/// [`try_init_logging_with`] instead and refuse to start on an error.
pub fn init_logging_with(format: LogFormat, default_filter: &str, caps: &TargetCaps) {
    // Every way this can fail is the documented silent no-op.
    let _ = try_init_logging_with(format, default_filter, caps);
}

/// [`init_logging_with`], reporting whether *this* call installed logging:
/// `Ok(())` only when it installed both the global `tracing` subscriber
/// (level filter, `caps` and `format`'s output) and the bridge that sends
/// `log`-crate records through it.
///
/// For when the caps must be in force: an earlier `init_logging(.., "trace")`,
/// a host's own subscriber, or a `log` logger set first each leave
/// `init_logging_with`'s caps out of force without a word. Here each is an
/// error the caller can refuse to start on.
///
/// Shares the one-time initialization of [`init_logging`] and
/// [`init_logging_with`]: whichever of the three is called first in a
/// process makes the one attempt to install, and every later call to this
/// one returns [`LoggingInitError::AlreadyInitialized`] — whether that
/// attempt succeeded or not, and whatever caps it had. A global subscriber
/// can't be replaced, so a second call could install nothing, and it can't
/// tell whether the caps in force are the ones it was handed. (Later calls to
/// the other two stay silent no-ops.)
///
/// ```no_run
/// use stridelabs_observability::{try_init_logging_with, LogFormat, TargetCaps};
/// use tracing::Level;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let caps = TargetCaps::new()
///         .cap("tungstenite", Level::INFO)
///         .cap("tokio_tungstenite", Level::INFO);
///     // Without the caps, `RUST_LOG=trace` would log the relay's API key.
///     try_init_logging_with(LogFormat::Text, "info", &caps)?;
///     // ... start the relay
///     Ok(())
/// }
/// ```
///
/// # Errors
///
/// - [`LoggingInitError::AlreadyInitialized`]: an earlier call to this,
///   [`init_logging`] or [`init_logging_with`] made the one attempt; this
///   call installed nothing.
/// - [`LoggingInitError::SubscriberAlreadySet`]: something outside this
///   crate installed a global `tracing` subscriber first; this call
///   installed nothing.
/// - [`LoggingInitError::LogBridgeNotInstalled`]: the subscriber is
///   installed, caps included, but a `log` logger was set first, so `log`
///   records still go to it and bypass the caps.
pub fn try_init_logging_with(
    format: LogFormat,
    default_filter: &str,
    caps: &TargetCaps,
) -> Result<(), LoggingInitError> {
    // Stays the error unless the closure runs: `call_once` skips it, after
    // waiting for a concurrent first call to finish, once `INIT` is done.
    let mut outcome = Err(LoggingInitError::AlreadyInitialized);
    INIT.call_once(|| {
        let rust_log = std::env::var(EnvFilter::DEFAULT_ENV).ok();
        outcome = install(subscriber(
            level_filter(rust_log.as_deref(), default_filter),
            caps,
            format,
            std::io::stdout,
            SystemTime,
        ));
    });
    outcome
}

/// Why [`try_init_logging_with`] did not install logging, or installed only
/// part of it.
///
/// `#[non_exhaustive]` so a new failure isn't a breaking change for a
/// consumer that matches on this.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoggingInitError {
    /// An earlier call to [`init_logging`], [`init_logging_with`] or
    /// [`try_init_logging_with`] in this process already made the one
    /// attempt to install (successful or not). This call installed nothing,
    /// so its caps are not necessarily in force.
    #[error("logging was already initialized in this process; this call installed nothing")]
    AlreadyInitialized,
    /// A global `tracing` subscriber was already installed by something
    /// other than this crate. This call installed nothing: its caps are not
    /// in force.
    #[error("a global tracing subscriber was already installed; this call installed nothing")]
    SubscriberAlreadySet,
    /// The `tracing` subscriber was installed, caps included, but a `log`
    /// logger had already been set, so the bridge from `log` into `tracing`
    /// could not be. `log`-crate records (tungstenite's among them) go to
    /// that logger, and neither the caps nor the level filter apply to them.
    /// The subscriber stays installed: it can't be taken back.
    #[error(
        "the tracing subscriber was installed, but a `log` logger was already set, \
         so `log` records bypass it and its caps"
    )]
    LogBridgeNotInstalled,
}

/// tracing-subscriber's `try_init`, one step at a time so each failure gets
/// its own error: `try_init` folds a refused subscriber and a refused `log`
/// bridge into one opaque error, and they mean different things — nothing
/// installed, or `log` records escaping the caps.
fn install(subscriber: impl Subscriber + Send + Sync + 'static) -> Result<(), LoggingInitError> {
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| LoggingInitError::SubscriberAlreadySet)?;
    // After the subscriber, as `try_init` does it: the bridge's max level is
    // the installed subscriber's max-level hint, so `log` records the level
    // filter would drop anyway are skipped before they are built.
    LogTracer::builder()
        .with_max_level(LevelFilter::current().as_log())
        .init()
        .map_err(|_| LoggingInitError::LogBridgeNotInstalled)
}

/// The level filter: `rust_log` — the value of `RUST_LOG`, if set — when it
/// parses, else `default_filter`.
///
/// `EnvFilter::try_from_default_env()` with the variable read lifted out, so
/// tests hand it a value instead of mutating the process environment. Same
/// rules: a set but invalid `RUST_LOG` falls back to `default_filter` whole,
/// rather than keeping its valid directives.
fn level_filter(rust_log: Option<&str>, default_filter: &str) -> EnvFilter {
    rust_log
        .and_then(|directives| EnvFilter::builder().parse(directives).ok())
        .unwrap_or_else(|| EnvFilter::new(default_filter))
}

/// The subscriber [`init_logging_with`] installs: the level filter, then the
/// caps, then `format`'s output layer — split out, like [`format_layer`], so
/// tests run this exact stack under a thread-scoped subscriber.
fn subscriber<W, T>(
    filter: EnvFilter,
    caps: &TargetCaps,
    format: LogFormat,
    make_writer: W,
    timer: T,
) -> impl Subscriber + Send + Sync + 'static
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
    T: FormatTime + Send + Sync + 'static,
{
    tracing_subscriber::registry()
        .with(filter)
        .with(CapsLayer(caps.clone()))
        .with(format_layer(format, make_writer, timer))
}

/// The output layer for `format`, writing through `make_writer` and stamping
/// lines with `timer`.
///
/// Split out of [`init_logging`] so tests drive the exact layer production
/// installs through a capturing writer and a fixed clock, under a
/// thread-scoped subscriber — the global one can't be inspected or replaced
/// once a test installs it. Production passes [`SystemTime`], which is every
/// format's default clock, so `with_timer` changes nothing there.
fn format_layer<S, W, T>(
    format: LogFormat,
    make_writer: W,
    timer: T,
) -> Box<dyn Layer<S> + Send + Sync>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
    T: FormatTime + Send + Sync + 'static,
{
    match format {
        LogFormat::Text => fmt::layer()
            .with_timer(timer)
            .with_writer(make_writer)
            .boxed(),
        LogFormat::Json => fmt::layer()
            .json()
            .with_timer(timer)
            .with_writer(make_writer)
            .boxed(),
        LogFormat::Cloud => CloudLayer::new(make_writer).with_timer(timer).boxed(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::{json, Value};
    use tracing::Level;
    use tracing_log::log;

    use super::*;
    use crate::test_support::{Capture, FixedTime, FIXED_TIMESTAMP};

    const FORMATS: [LogFormat; 3] = [LogFormat::Text, LogFormat::Json, LogFormat::Cloud];

    /// Run `f` with `format`'s production layer, on the fixed clock, as the
    /// only output.
    fn capture(format: LogFormat, f: impl FnOnce()) -> Capture {
        Capture::run(|writer| format_layer(format, writer, FixedTime), f)
    }

    /// Run `f` under the whole stack [`init_logging_with`] installs —
    /// `rust_log` standing in for the `RUST_LOG` value — on the fixed clock.
    fn capture_stack(
        format: LogFormat,
        rust_log: Option<&str>,
        default_filter: &str,
        caps: &TargetCaps,
        f: impl FnOnce(),
    ) -> Capture {
        let capture = Capture::default();
        let filter = level_filter(rust_log, default_filter);
        let stack = subscriber(filter, caps, format, capture.clone(), FixedTime);
        tracing::subscriber::with_default(stack, f);
        capture
    }

    /// A WebSocket relay's caps: the two crates that log every frame at
    /// `trace`.
    fn tungstenite_caps() -> TargetCaps {
        TargetCaps::new()
            .cap("tungstenite", Level::INFO)
            .cap("tokio_tungstenite", Level::INFO)
    }

    /// One event per (target, level) worth asking about, each with a message
    /// naming both, so a line is attributable whatever the format.
    fn emit_tungstenite_and_app() {
        tracing::trace!(target: "tungstenite::protocol", "tungstenite-trace");
        tracing::debug!(target: "tungstenite::protocol", "tungstenite-debug");
        tracing::info!(target: "tungstenite::protocol", "tungstenite-info");
        tracing::warn!(target: "tungstenite::protocol", "tungstenite-warn");
        tracing::trace!(target: "tokio_tungstenite", "tokio-tungstenite-trace");
        tracing::trace!(target: "app", "app-trace");
        tracing::debug!(target: "app", "app-debug");
    }

    /// The messages `capture` wrote, in order: for `Text`, each line's last
    /// word, which is where these tests' one-word messages land.
    fn messages(format: LogFormat, capture: &Capture) -> Vec<String> {
        match format {
            LogFormat::Text => capture
                .lines()
                .iter()
                .map(|line| line.rsplit(' ').next().unwrap_or_default().to_owned())
                .collect(),
            LogFormat::Json => capture
                .json_lines()
                .iter()
                .map(|line| line["fields"]["message"].as_str().unwrap().to_owned())
                .collect(),
            LogFormat::Cloud => capture
                .json_lines()
                .iter()
                .map(|line| line["message"].as_str().unwrap().to_owned())
                .collect(),
        }
    }

    #[test]
    fn double_init_does_not_panic() {
        // The calls deliberately differ (format and filter) to prove the
        // later ones are true no-ops, not just "happen to look the same".
        init_logging(LogFormat::Text, "info");
        init_logging(LogFormat::Json, "debug");
        init_logging(LogFormat::Cloud, "warn");
    }

    /// What `init_logging_with` swallows, reported: whichever test in this
    /// binary called `init_logging` first, the one attempt has been made by
    /// the time this asks. (A first call, and the other two errors, each
    /// need a process of their own: see `tests/try_init_logging_*.rs`.)
    #[test]
    fn try_init_after_any_earlier_init_reports_already_initialized() {
        init_logging(LogFormat::Text, "info");
        let outcome = try_init_logging_with(LogFormat::Cloud, "trace", &tungstenite_caps());
        assert!(
            matches!(outcome, Err(LoggingInitError::AlreadyInitialized)),
            "{outcome:?}"
        );
    }

    #[test]
    fn from_environment_is_text_only_for_exactly_development() {
        assert_eq!(LogFormat::from_environment("development"), LogFormat::Text);
        for env in ["production", "staging", "", "Development", " development"] {
            assert_eq!(
                LogFormat::from_environment(env),
                LogFormat::Cloud,
                "{env:?}"
            );
        }
    }

    #[test]
    fn each_format_writes_its_own_shape() {
        let hello = || tracing::info!(target: "app", "hello");

        let text = capture(LogFormat::Text, hello).lines().remove(0);
        assert!(text.contains("hello"), "{text}");
        assert!(
            serde_json::from_str::<Value>(&text).is_err(),
            "Text is not JSON: {text}"
        );

        let json = capture(LogFormat::Json, hello).json_lines().remove(0);
        assert_eq!(json["fields"]["message"], "hello");

        let cloud = capture(LogFormat::Cloud, hello).json_lines().remove(0);
        assert_eq!(cloud["severity"], "INFO");
        assert_eq!(cloud["message"], "hello");
    }

    /// Pins `Json` to tracing-subscriber's shape, which consumers depend on:
    /// the Cloud work must not leak into it.
    #[test]
    fn json_format_shape_is_unchanged() {
        let lines = capture(LogFormat::Json, || {
            let span = tracing::info_span!("outer", id = 7);
            let _entered = span.enter();
            tracing::info!(target: "app", user = "alice", "hello");
        })
        .json_lines();

        let line = &lines[0];
        let keys: BTreeSet<&str> = line
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from(["timestamp", "level", "fields", "target", "span", "spans"])
        );
        assert_eq!(line["level"], "INFO");
        assert_eq!(line["fields"], json!({"message": "hello", "user": "alice"}));
        assert_eq!(line["target"], "app");
        assert_eq!(line["span"], json!({"id": 7, "name": "outer"}));
    }

    /// The same pin, byte for byte: key order and spacing included.
    #[test]
    fn json_format_bytes_are_unchanged() {
        let lines = capture(LogFormat::Json, || {
            let span = tracing::info_span!("outer", id = 7);
            let _entered = span.enter();
            tracing::info!(target: "app", user = "alice", "hello");
        })
        .lines();

        assert_eq!(
            lines,
            [format!(
                concat!(
                    r#"{{"timestamp":"{}","level":"INFO","fields":{{"message":"hello","user":"alice"}},"#,
                    r#""target":"app","span":{{"id":7,"name":"outer"}},"spans":[{{"id":7,"name":"outer"}}]}}"#,
                ),
                FIXED_TIMESTAMP
            )]
        );
    }

    #[test]
    fn caps_drop_a_capped_target_above_its_cap_in_every_format() {
        for format in FORMATS {
            let capture = capture_stack(
                format,
                None,
                "trace",
                &tungstenite_caps(),
                emit_tungstenite_and_app,
            );
            assert_eq!(
                messages(format, &capture),
                [
                    "tungstenite-info",
                    "tungstenite-warn",
                    "app-trace",
                    "app-debug"
                ],
                "{format:?}"
            );
        }
    }

    /// What the caps exist for: `RUST_LOG` replaces the default filter, and
    /// still cannot lift a capped target — not with a blanket level, not by
    /// naming the target, not with a directive more specific than the cap.
    #[test]
    fn rust_log_cannot_lift_a_cap() {
        for (rust_log, expected) in [
            (
                "trace",
                &[
                    "tungstenite-info",
                    "tungstenite-warn",
                    "app-trace",
                    "app-debug",
                ][..],
            ),
            (
                "tungstenite=trace",
                &["tungstenite-info", "tungstenite-warn"][..],
            ),
            (
                "tungstenite::protocol=trace,tokio_tungstenite=trace",
                &["tungstenite-info", "tungstenite-warn"][..],
            ),
        ] {
            // `error` as the default, which would write none of these: every
            // line proves `rust_log` is the filter in force.
            let capture = capture_stack(
                LogFormat::Cloud,
                Some(rust_log),
                "error",
                &tungstenite_caps(),
                emit_tungstenite_and_app,
            );
            assert_eq!(messages(LogFormat::Cloud, &capture), expected, "{rust_log}");
        }
    }

    /// Caps only remove, so the level filter's hint stays the subscriber's.
    /// `try_init` hands it to the `log` bridge as its max level, and a hint
    /// raised to `TRACE` would have every `log::trace!` in the process
    /// formatted only to be dropped.
    #[test]
    fn caps_leave_the_max_level_hint_to_the_level_filter() {
        for (filter, expected) in [
            ("info", LevelFilter::INFO),
            ("warn,app=debug", LevelFilter::DEBUG),
        ] {
            for caps in [TargetCaps::new(), tungstenite_caps()] {
                let filter = level_filter(None, filter);
                let stack = subscriber(
                    filter,
                    &caps,
                    LogFormat::Cloud,
                    Capture::default(),
                    FixedTime,
                );
                assert_eq!(stack.max_level_hint(), Some(expected), "{caps:?}");
            }
        }
    }

    #[test]
    fn a_cap_covers_its_target_and_the_module_paths_beneath_it_only() {
        let caps = TargetCaps::new().cap("tungstenite", Level::INFO);
        let capture = capture_stack(LogFormat::Cloud, None, "trace", &caps, || {
            tracing::trace!(target: "tungstenite", "exact");
            tracing::trace!(target: "tungstenite::protocol::frame", "nested");
            tracing::trace!(target: "tungstenite_extra", "sibling");
            tracing::trace!(target: "tungstenite_extra::protocol", "sibling-nested");
            tracing::trace!(target: "tokio_tungstenite", "suffix");
            tracing::trace!(target: "Tungstenite", "case");
        });
        assert_eq!(
            messages(LogFormat::Cloud, &capture),
            ["sibling", "sibling-nested", "suffix", "case"]
        );
    }

    /// `tungstenite::` is `tungstenite`: kept as written, it would match
    /// only `tungstenite::::…` and leave the crate uncapped.
    #[test]
    fn a_trailing_double_colon_is_the_same_cap() {
        for target in ["tungstenite::", "tungstenite::::"] {
            let caps = TargetCaps::new().cap(target, Level::INFO);
            let capture = capture_stack(LogFormat::Cloud, None, "trace", &caps, || {
                tracing::trace!(target: "tungstenite", "exact");
                tracing::trace!(target: "tungstenite::protocol", "nested");
                tracing::trace!(target: "tungstenite_extra", "sibling");
                tracing::info!(target: "tungstenite::protocol", "nested-info");
            });
            assert_eq!(
                messages(LogFormat::Cloud, &capture),
                ["sibling", "nested-info"],
                "{target:?}"
            );
        }
    }

    /// An empty cap is not a wildcard (`EnvFilter`'s bare level is): it
    /// covers only an empty or `::`-led target, which no module path is.
    #[test]
    fn an_empty_target_caps_no_module_path() {
        for target in ["", "::"] {
            let caps = TargetCaps::new().cap(target, LevelFilter::OFF);
            let capture = capture_stack(LogFormat::Cloud, None, "trace", &caps, || {
                tracing::trace!(target: "app", "app");
                tracing::error!(target: "tungstenite::protocol", "nested");
                tracing::error!(target: "", "empty");
                tracing::error!(target: "::led", "colon-led");
            });
            assert_eq!(
                messages(LogFormat::Cloud, &capture),
                ["app", "nested"],
                "{target:?}"
            );
        }
    }

    #[test]
    fn every_cap_covering_a_target_applies_so_the_strictest_wins() {
        let caps = TargetCaps::new()
            .cap("tungstenite", Level::INFO)
            // Looser and more specific: does not loosen the crate-wide cap.
            .cap("tungstenite::protocol", Level::TRACE)
            // Stricter and more specific: tightens it.
            .cap("tungstenite::handshake", Level::WARN)
            // The same target twice, in either order.
            .cap("app", LevelFilter::OFF)
            .cap("app", Level::ERROR);
        let capture = capture_stack(LogFormat::Cloud, None, "trace", &caps, || {
            tracing::debug!(target: "tungstenite::protocol", "protocol-debug");
            tracing::info!(target: "tungstenite::protocol", "protocol-info");
            tracing::info!(target: "tungstenite::handshake", "handshake-info");
            tracing::warn!(target: "tungstenite::handshake", "handshake-warn");
            tracing::error!(target: "app", "app-error");
        });
        assert_eq!(
            messages(LogFormat::Cloud, &capture),
            ["protocol-info", "handshake-warn"]
        );
    }

    /// A capped span is never created, so none of its fields reach a line —
    /// not in `Text`'s span prefix, not in `Json`'s `spans`, and not as the
    /// `requestId` `Cloud` lifts from the nearest span declaring one.
    #[test]
    fn a_capped_span_never_reaches_a_line() {
        for format in FORMATS {
            let lines = capture_stack(format, None, "trace", &tungstenite_caps(), || {
                let request = tracing::info_span!(
                    target: "app",
                    "request",
                    { crate::REQUEST_ID_FIELD } = "request-id-kept"
                );
                let _request = request.enter();
                let frame = tracing::trace_span!(
                    target: "tungstenite::protocol",
                    "frame",
                    { crate::REQUEST_ID_FIELD } = "SECRET-FRAME"
                );
                let _frame = frame.enter();
                tracing::info!(target: "app", "inside");
            })
            .lines();
            let [line] = &lines[..] else {
                panic!("{format:?}: expected one line, got {lines:?}");
            };
            assert!(line.contains("inside"), "{format:?}: {line}");
            assert!(line.contains("request-id-kept"), "{format:?}: {line}");
            assert!(!line.contains("SECRET-FRAME"), "{format:?}: {line}");
        }
    }

    /// A `log`-crate record (tungstenite logs through `log`), handed to the
    /// current subscriber by tracing-log's `format_trace`: the path the
    /// bridge `init_logging` installs (`LogTracer`) takes once a record
    /// passes its max-level check.
    fn log_record(target: &str, level: log::Level, message: &str) {
        tracing_log::format_trace(
            &log::Record::builder()
                .target(target)
                .level(level)
                .args(format_args!("{message}"))
                .build(),
        )
        .unwrap();
    }

    #[test]
    fn log_crate_records_are_capped_on_their_own_target() {
        for format in FORMATS {
            let capture = capture_stack(format, None, "trace", &tungstenite_caps(), || {
                let frame = "tungstenite::protocol::frame";
                log_record(frame, log::Level::Trace, "log-tungstenite-trace");
                log_record(frame, log::Level::Debug, "log-tungstenite-debug");
                log_record(frame, log::Level::Info, "log-tungstenite-info");
                log_record("tokio_tungstenite", log::Level::Trace, "log-tokio-trace");
                log_record("app", log::Level::Trace, "log-app-trace");
            });
            assert_eq!(
                messages(format, &capture),
                ["log-tungstenite-info", "log-app-trace"],
                "{format:?}"
            );
        }
    }

    /// `init_logging` is `init_logging_with` with no caps: that stack must
    /// write exactly what the stack without a caps layer wrote, spans and
    /// all, in every format.
    #[test]
    fn without_caps_the_stack_writes_what_it_always_did() {
        let emit = || {
            let span = tracing::info_span!("outer", id = 7);
            let _entered = span.enter();
            emit_tungstenite_and_app();
        };
        for format in FORMATS {
            let with_no_caps =
                capture_stack(format, Some("trace"), "info", &TargetCaps::new(), emit);
            let before = Capture::default();
            let stack = tracing_subscriber::registry()
                .with(level_filter(Some("trace"), "info"))
                .with(format_layer(format, before.clone(), FixedTime));
            tracing::subscriber::with_default(stack, emit);

            assert_eq!(with_no_caps.lines(), before.lines(), "{format:?}");
            // Not vacuous: everything was written, the would-be capped
            // target included.
            assert_eq!(
                messages(format, &with_no_caps),
                [
                    "tungstenite-trace",
                    "tungstenite-debug",
                    "tungstenite-info",
                    "tungstenite-warn",
                    "tokio-tungstenite-trace",
                    "app-trace",
                    "app-debug",
                ],
                "{format:?}"
            );
        }
    }

    /// The `RUST_LOG` seam keeps `EnvFilter::try_from_default_env`'s rules:
    /// a value that parses replaces the default — an empty one included,
    /// which parses to a filter with no directives — and one that doesn't,
    /// even in part, leaves the default whole.
    #[test]
    fn rust_log_replaces_the_default_filter_unless_it_is_invalid() {
        let written = |rust_log: Option<&str>| {
            let capture = capture_stack(
                LogFormat::Cloud,
                rust_log,
                "debug",
                &TargetCaps::new(),
                || {
                    tracing::trace!(target: "app", "trace");
                    tracing::debug!(target: "app", "debug");
                    tracing::info!(target: "app", "info");
                },
            );
            messages(LogFormat::Cloud, &capture)
        };
        assert_eq!(written(None), ["debug", "info"]);
        assert_eq!(written(Some("info")), ["info"]);
        assert_eq!(written(Some("app=trace")), ["trace", "debug", "info"]);
        assert_eq!(written(Some("")), [] as [&str; 0]);
        assert_eq!(written(Some("app=loud")), ["debug", "info"]);
        assert_eq!(written(Some("trace,app=loud")), ["debug", "info"]);
    }
}
