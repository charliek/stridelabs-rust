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

use std::sync::Once;

use tracing::Subscriber;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::MakeWriter;
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
    /// (`{timestamp, level, fields: {message, …}, target, span}`).
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

static INIT: Once = Once::new();

/// Initialize the global `tracing` subscriber.
///
/// The level filter is read from the standard `RUST_LOG` env var if set,
/// else falls back to `default_filter` (callers pass their own
/// service-specific fallback, e.g. `"info"` or `"info,sqlx=warn"` — this
/// crate doesn't hard-code a house filter string).
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
    INIT.call_once(|| {
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(format_layer(format, std::io::stdout, SystemTime))
            .try_init();
    });
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

    use super::*;
    use crate::test_support::{Capture, FixedTime, FIXED_TIMESTAMP};

    /// Run `f` with `format`'s production layer, on the fixed clock, as the
    /// only output.
    fn capture(format: LogFormat, f: impl FnOnce()) -> Capture {
        Capture::run(|writer| format_layer(format, writer, FixedTime), f)
    }

    #[test]
    fn double_init_does_not_panic() {
        // The calls deliberately differ (format and filter) to prove the
        // later ones are true no-ops, not just "happen to look the same".
        init_logging(LogFormat::Text, "info");
        init_logging(LogFormat::Json, "debug");
        init_logging(LogFormat::Cloud, "warn");
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
}
