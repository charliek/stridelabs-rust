//! A `tracing` layer that writes Google Cloud Logging structured lines.
//!
//! Cloud Run forwards every stdout line to Cloud Logging, which parses a JSON
//! line into `jsonPayload` and promotes a few [special fields] out of it:
//! `severity` colours and filters the entry, `message` is its summary line,
//! `httpRequest` fills the request-log columns, and
//! `logging.googleapis.com/trace` groups every entry of one request under its
//! trace. tracing-subscriber's own JSON ([`LogFormat::Json`]) calls the level
//! `level`, nests the message under `fields` and carries no trace, so Cloud
//! Logging shows each of its lines as a DEFAULT-severity entry with no
//! summary. [`CloudLayer`] writes the shape Python's `stridelabs-logging`
//! `CloudLoggingFormatter` writes, so Python and Rust services read the same
//! in the console:
//!
//! | key | value |
//! |---|---|
//! | `severity` | `TRACE`/`DEBUG` → `DEBUG`, `INFO` → `INFO`, `WARN` → `WARNING`, `ERROR` → `ERROR` |
//! | `message` | the event's message, at top level (`""` when the event has none) |
//! | `logger` | the event's target |
//! | `timestamp` | RFC 3339, UTC |
//! | `httpRequest` | an object assembled from the event's `httpRequest.*` fields |
//! | `requestId`, `logging.googleapis.com/trace` | lifted from the enclosing request span |
//! | anything else | the event's remaining fields, flattened at top level |
//!
//! One JSON object per line, keys in the order above. Field values keep
//! their JSON type: integers and floats stay numbers, booleans stay
//! booleans, and anything recorded with `%`/`?` (or as a `&str`) is a string.
//! A value whose `Debug`/`Display` impl returns an error is written as the
//! string `<unformattable>`, keeping the key and the rest of the line:
//! `format!` would panic there, and a log line must never take its caller
//! down.
//!
//! # `httpRequest`
//!
//! An event field named `httpRequest.<key>` becomes `<key>` inside the
//! `httpRequest` object instead of a top-level key, so
//! `info!(httpRequest.status = 200, httpRequest.latency = "0.123s", "…")`
//! writes `"httpRequest":{"status":200,"latency":"0.123s"}`. tracing has no
//! nested field values, and dotted field names are how it spells structure.
//!
//! # Precedence
//!
//! Each key is written once, and the first writer wins: the core keys
//! (`severity`, `message`, `logger`, `timestamp`) always come from the event
//! itself, then `httpRequest` from the prefixed fields, then the two
//! correlation keys from the enclosing span, then the event's remaining
//! fields, skipping any whose name is already taken. So `info!(severity =
//! "ERROR", "…")` cannot forge a severity, and an event's own `requestId`
//! field loses to the request span's inside a request (outside one, nothing
//! else claims the key, so it is written). That is Python's precedence
//! (`payload.setdefault`, core fields first) with one deliberate change:
//! Python lets an event's fields beat the request context, but here the
//! span's id is the one resolved for the whole request — the one every other
//! line of that request carries — so it is the one that must win.
//!
//! # The request-span contract
//!
//! Any span that declares a field named [`REQUEST_ID_FIELD`] or
//! [`TRACE_FIELD`] supplies that key to every event inside it, however
//! deeply the event is nested in other spans. Walking outward from the
//! event, the nearest span that has *recorded* a key supplies it, key by key
//! — so a nested span can override an outer one's id, and a field declared
//! [`tracing::field::Empty`] and recorded later counts from the moment it is
//! recorded. Values are taken as strings: record them with `%value` or as a
//! `&str` (`?value` records the `Debug` form, quotes included).
//!
//! The field names *are* the output keys, so there is no mapping to keep in
//! sync and the `Text` format shows the same key the Cloud console does.
//! `logging.googleapis.com/trace` is not a Rust identifier, which tracing
//! handles with a constant in braces:
//!
//! ```
//! use stridelabs_observability::{REQUEST_ID_FIELD, REQUEST_SPAN_NAME, TRACE_FIELD};
//!
//! let request_id = "4bf92f3577b34da6a3ce929d0e0e4736";
//! let trace: Option<String> = Some("projects/my-project/traces/4bf92f35".into());
//!
//! let span = tracing::info_span!(
//!     REQUEST_SPAN_NAME,
//!     { REQUEST_ID_FIELD } = %request_id,
//!     // `None` leaves the field unrecorded, so no trace key is written.
//!     { TRACE_FIELD } = trace.as_deref(),
//! );
//! let _entered = span.enter();
//! tracing::info!("handled"); // carries `requestId` and the trace
//! ```
//!
//! The formatter keys off the field names, not the span name:
//! [`REQUEST_SPAN_NAME`] is only the name a request span is given. That
//! lets a unit of work that isn't an HTTP request (a background job, say)
//! correlate its lines by declaring `requestId` on its own span, and it
//! means tower-http's `TraceLayer` span — also named `request`, but carrying
//! neither field — can never shadow the ids. A span the subscriber's filter
//! disables is never created, so open the request span at a level the
//! filter enables, or the lines inside it lose their ids.
//!
//! Other spans' fields are not written: a Cloud line is the event plus the
//! request's correlation keys, not the whole span stack.
//!
//! # Why a `Layer` rather than a `FormatEvent`
//!
//! Plugging a formatter into `fmt::layer().event_format(..)` would only see a
//! span's fields as the text the field formatter already rendered, so lifting
//! `requestId` would mean re-parsing that text for every span on every event
//! (what tracing-subscriber's own JSON format does). As a [`Layer`], this
//! keeps just the two correlation values as typed strings in the span's
//! extensions when the span is created or recorded, and spans that declare
//! neither field cost nothing.
//!
//! [special fields]: https://cloud.google.com/logging/docs/structured-logging#structured_logging_special_fields
//! [`LogFormat::Json`]: crate::LogFormat::Json

use std::fmt;
use std::io::Write as _;

use serde_json::Value;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

/// The name a request span is given: what the request-logging layer opens
/// around each request, so the spans read the same in every service's `Text`
/// output and a filter can target them (`RUST_LOG=[request]=…`). Not
/// load-bearing for correlation — see the [module docs](self) for why
/// lifting keys off the field names instead.
pub const REQUEST_SPAN_NAME: &str = "request";

/// The span field (and output key) carrying the request id. Matches Python
/// `stridelabs-logging`'s `requestId` key.
pub const REQUEST_ID_FIELD: &str = "requestId";

/// The span field (and output key) carrying the Cloud Trace resource name,
/// `projects/{project}/traces/{trace_id}` — the special field Cloud Logging
/// groups a request's entries by.
pub const TRACE_FIELD: &str = "logging.googleapis.com/trace";

/// Event fields with this prefix are gathered into the `httpRequest` object.
const HTTP_REQUEST_PREFIX: &str = "httpRequest.";
const HTTP_REQUEST_KEY: &str = "httpRequest";

/// A [`Layer`] writing each event as one Google Cloud Logging JSON line. See
/// the [module docs](self) for the shape and the request-span contract.
///
/// The layer formats; it doesn't filter. Compose it with whatever filter you
/// want (`registry().with(filter).with(CloudLayer::new(std::io::stdout))`),
/// which is also how a test captures lines: hand it a [`MakeWriter`] over a
/// shared buffer and install the subscriber with
/// [`tracing::subscriber::with_default`] rather than globally.
#[derive(Debug, Clone)]
pub struct CloudLayer<W, T = SystemTime> {
    make_writer: W,
    timer: T,
}

impl<W> CloudLayer<W>
where
    W: for<'w> MakeWriter<'w> + 'static,
{
    /// A layer writing through `make_writer` (e.g. `std::io::stdout`),
    /// timestamped from the system clock.
    pub fn new(make_writer: W) -> Self {
        Self {
            make_writer,
            timer: SystemTime,
        }
    }
}

impl<W, T> CloudLayer<W, T> {
    /// Replace the clock, mirroring `fmt::Layer::with_timer`. Meant for
    /// tests that compare whole lines: Cloud Logging needs an RFC 3339 UTC
    /// timestamp, which the default [`SystemTime`] writes and an arbitrary
    /// [`FormatTime`] may not.
    pub fn with_timer<T2>(self, timer: T2) -> CloudLayer<W, T2>
    where
        T2: FormatTime + 'static,
    {
        CloudLayer {
            make_writer: self.make_writer,
            timer,
        }
    }
}

impl<S, W, T> Layer<S> for CloudLayer<W, T>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + 'static,
    T: FormatTime + 'static,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let fields = attrs.metadata().fields();
        if fields.field(REQUEST_ID_FIELD).is_none() && fields.field(TRACE_FIELD).is_none() {
            return;
        }
        // Formatted before the extensions are locked, for the reason
        // `on_record` gives.
        let mut correlation = Correlation::default();
        attrs.record(&mut correlation);
        if let Some(span) = ctx.span(id) {
            // `replace`, not `insert`: two `CloudLayer`s in one stack (stdout
            // plus a capture, say) both reach here for the same span, and
            // `insert` panics on a duplicate. They record the same values.
            span.extensions_mut().replace(correlation);
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        // Format first, lock second. Recording runs the value's
        // `Debug`/`Display`, which may itself log; that event reads this
        // same span's extensions (`enclosing_correlation`), and `Span::record`
        // doesn't suppress re-entry the way event dispatch does — so
        // formatting under the write lock would deadlock the thread on itself.
        let mut recorded = Correlation::default();
        values.record(&mut recorded);
        if recorded.request_id.is_none() && recorded.trace.is_none() {
            return;
        }
        if let Some(span) = ctx.span(id) {
            if let Some(correlation) = span.extensions_mut().get_mut::<Correlation>() {
                correlation.merge(recorded);
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        // `render` can only fail serializing a `str`/`Value` into a `Vec`,
        // which doesn't happen; a logging layer must never panic its caller,
        // so if it ever did, the line is dropped instead.
        let Ok(line) = self.render(event, &ctx) else {
            return;
        };
        // One `write_all` per line, so concurrent events don't interleave
        // mid-line (stdout holds its lock for the whole call). A write error
        // (stdout closed) has nowhere to be reported but the log itself.
        let _ = self
            .make_writer
            .make_writer_for(event.metadata())
            .write_all(&line);
    }
}

impl<W, T: FormatTime> CloudLayer<W, T> {
    fn render<S>(&self, event: &Event<'_>, ctx: &Context<'_, S>) -> serde_json::Result<Vec<u8>>
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        let meta = event.metadata();
        let mut fields = EventFields {
            is_log_record: is_log_record(meta),
            ..EventFields::default()
        };
        event.record(&mut fields);
        let correlation = enclosing_correlation(event, ctx);

        let mut line = Vec::with_capacity(256);
        line.push(b'{');
        str_entry(&mut line, "severity", severity(meta.level()))?;
        str_entry(
            &mut line,
            "message",
            fields.message.as_deref().unwrap_or(""),
        )?;
        let logger = fields.log_target.as_deref().unwrap_or(meta.target());
        str_entry(&mut line, "logger", logger)?;
        // A clock that fails to format leaves the key out rather than
        // writing something unparseable: Cloud Logging then stamps the entry
        // with its receive time, which is the right fallback.
        let mut timestamp = String::new();
        if self
            .timer
            .format_time(&mut Writer::new(&mut timestamp))
            .is_ok()
        {
            str_entry(&mut line, "timestamp", &timestamp)?;
        }
        // Reserved whether or not the timestamp was written, so an event
        // field can't stand in for a clock failure.
        let mut taken = vec!["severity", "message", "logger", "timestamp"];

        if !fields.http_request.is_empty() {
            key(&mut line, HTTP_REQUEST_KEY)?;
            line.push(b'{');
            write_fields(&mut line, &fields.http_request, &mut Vec::new())?;
            line.push(b'}');
            taken.push(HTTP_REQUEST_KEY);
        }
        if let Some(request_id) = &correlation.request_id {
            str_entry(&mut line, REQUEST_ID_FIELD, request_id)?;
            taken.push(REQUEST_ID_FIELD);
        }
        if let Some(trace) = &correlation.trace {
            str_entry(&mut line, TRACE_FIELD, trace)?;
            taken.push(TRACE_FIELD);
        }
        write_fields(&mut line, &fields.rest, &mut taken)?;
        line.extend_from_slice(b"}\n");
        Ok(line)
    }
}

/// Cloud Logging's `LogSeverity` names. It has no TRACE, so TRACE shares
/// DEBUG; WARN is spelled out.
fn severity(level: &Level) -> &'static str {
    match *level {
        Level::TRACE | Level::DEBUG => "DEBUG",
        Level::INFO => "INFO",
        Level::WARN => "WARNING",
        Level::ERROR => "ERROR",
    }
}

/// Whether `meta` belongs to an event `tracing-log`'s `LogTracer` forwarded
/// from the `log` crate — which `init_logging` installs, via `try_init`, so
/// dependencies that log through `log` aren't lost. Such an event's target is
/// the literal `log`, with the real target and source location riding along
/// as `log.*` fields. tracing-subscriber's formatters undo that with
/// tracing-log's `NormalizeEvent`; matching `LogTracer`'s fixed callsite name
/// and target does the same here without depending on tracing-log directly.
fn is_log_record(meta: &Metadata<'_>) -> bool {
    meta.target() == "log" && meta.name() == "log event"
}

/// The correlation keys a span supplies, kept in its extensions from
/// creation (and updated on `record`) so events read them back typed.
#[derive(Debug, Default)]
struct Correlation {
    request_id: Option<String>,
    trace: Option<String>,
}

impl Correlation {
    /// Overwrite each key `newer` recorded; keep the rest.
    fn merge(&mut self, newer: Correlation) {
        if newer.request_id.is_some() {
            self.request_id = newer.request_id;
        }
        if newer.trace.is_some() {
            self.trace = newer.trace;
        }
    }

    fn slot(&mut self, field: &Field) -> Option<&mut Option<String>> {
        match field.name() {
            REQUEST_ID_FIELD => Some(&mut self.request_id),
            TRACE_FIELD => Some(&mut self.trace),
            _ => None,
        }
    }
}

impl Visit for Correlation {
    fn record_str(&mut self, field: &Field, value: &str) {
        if let Some(slot) = self.slot(field) {
            *slot = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // Checked before formatting, so a request span's other fields
        // aren't rendered just to be thrown away.
        if let Some(slot) = self.slot(field) {
            *slot = Some(debug_string(value));
        }
    }
}

/// Walk the event's spans from the innermost outward; the first span to
/// supply each key is the nearest.
fn enclosing_correlation<S>(event: &Event<'_>, ctx: &Context<'_, S>) -> Correlation
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let mut found = Correlation::default();
    let Some(scope) = ctx.event_scope(event) else {
        return found;
    };
    for span in scope {
        if let Some(correlation) = span.extensions().get::<Correlation>() {
            if found.request_id.is_none() {
                found.request_id.clone_from(&correlation.request_id);
            }
            if found.trace.is_none() {
                found.trace.clone_from(&correlation.trace);
            }
        }
        if found.request_id.is_some() && found.trace.is_some() {
            break;
        }
    }
    found
}

/// An event's fields, sorted into the line's parts as they're visited.
/// Field names are `&'static str` (tracing's callsite metadata), so neither
/// list allocates for its keys.
#[derive(Default)]
struct EventFields {
    is_log_record: bool,
    message: Option<String>,
    log_target: Option<String>,
    http_request: Vec<(&'static str, Value)>,
    rest: Vec<(&'static str, Value)>,
}

impl EventFields {
    fn record_value(&mut self, field: &Field, value: Value) {
        // A raw-identifier field (`r#type = …`) is named `r#type`; drop the
        // prefix, as tracing-subscriber's own JSON format does.
        let name = field.name();
        let name = name.strip_prefix("r#").unwrap_or(name);
        match name {
            "message" => self.message = Some(into_string(value)),
            "log.target" if self.is_log_record => self.log_target = Some(into_string(value)),
            // The rest of a `log` record's metadata (module path, file,
            // line) is source location, which Python's lines don't carry
            // either. A native event's own `log.*` fields are kept.
            _ if self.is_log_record && name.starts_with("log.") => {}
            _ => match name.strip_prefix(HTTP_REQUEST_PREFIX) {
                Some(key) => self.http_request.push((key, value)),
                None => self.rest.push((name, value)),
            },
        }
    }
}

/// What a value whose formatting fails is written as.
const UNFORMATTABLE: &str = "<unformattable>";

/// `value`'s `Debug` form (for a `%`-recorded value, its `Display`), or
/// [`UNFORMATTABLE`] when the impl returns an error. `format!` panics on that
/// error; writing into a `String` reports it instead.
fn debug_string(value: &dyn fmt::Debug) -> String {
    let mut out = String::new();
    match fmt::Write::write_fmt(&mut out, format_args!("{value:?}")) {
        Ok(()) => out,
        Err(fmt::Error) => UNFORMATTABLE.to_owned(),
    }
}

fn into_string(value: Value) -> String {
    match value {
        Value::String(s) => s,
        other => other.to_string(),
    }
}

impl Visit for EventFields {
    fn record_f64(&mut self, field: &Field, value: f64) {
        // JSON has no NaN or infinity; write those as strings rather than
        // collapsing them to `null`, which would hide what was logged.
        let value = serde_json::Number::from_f64(value)
            .map_or_else(|| Value::String(value.to_string()), Value::Number);
        self.record_value(field, value);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, Value::from(value));
    }

    // The default 128-bit visitors fall back to `record_debug`, which would
    // turn an `i128` that fits a JSON number into a string.
    fn record_i128(&mut self, field: &Field, value: i128) {
        let value =
            i64::try_from(value).map_or_else(|_| Value::String(value.to_string()), Value::from);
        self.record_value(field, value);
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        let value =
            u64::try_from(value).map_or_else(|_| Value::String(value.to_string()), Value::from);
        self.record_value(field, value);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, Value::Bool(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, Value::from(value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_value(field, Value::String(debug_string(value)));
    }
}

// The line is written by hand, key by key, because the key order is part of
// the output: `serde_json::Map` sorts its keys, and turning on serde_json's
// `preserve_order` here would flip `Map` to insertion order for every crate
// in a consumer's graph (Cargo unifies features).

/// Append `"key":` to the object under construction, after a comma unless
/// it's the object's first entry.
fn key(line: &mut Vec<u8>, key: &str) -> serde_json::Result<()> {
    if line.last() != Some(&b'{') {
        line.push(b',');
    }
    serde_json::to_writer(&mut *line, key)?;
    line.push(b':');
    Ok(())
}

fn str_entry(line: &mut Vec<u8>, name: &str, value: &str) -> serde_json::Result<()> {
    key(line, name)?;
    serde_json::to_writer(&mut *line, value)
}

/// Append each field whose name isn't in `taken`, claiming it — so a key
/// already written, or repeated within `fields`, is written only once.
fn write_fields(
    line: &mut Vec<u8>,
    fields: &[(&'static str, Value)],
    taken: &mut Vec<&'static str>,
) -> serde_json::Result<()> {
    for (name, value) in fields {
        if taken.contains(name) {
            continue;
        }
        taken.push(name);
        key(line, name)?;
        serde_json::to_writer(&mut *line, value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Capture, FixedTime, FIXED_TIMESTAMP};

    /// Run `f` with a [`CloudLayer`] on the fixed clock as the only output,
    /// every level enabled.
    fn capture_cloud(f: impl FnOnce()) -> Capture {
        Capture::run(|writer| CloudLayer::new(writer).with_timer(FixedTime), f)
    }

    /// The line prefix every `INFO` event from target `app` starts with.
    fn info_prefix() -> String {
        format!(
            r#"{{"severity":"INFO","message":"hi","logger":"app","timestamp":"{FIXED_TIMESTAMP}""#
        )
    }

    #[test]
    fn golden_line_for_a_plain_event() {
        let capture = capture_cloud(|| tracing::info!(target: "app", order = 42, "hi"));

        assert_eq!(
            capture.lines(),
            [format!(r#"{},"order":42}}"#, info_prefix())]
        );
    }

    #[test]
    fn severity_maps_every_tracing_level() {
        let capture = capture_cloud(|| {
            tracing::trace!("t");
            tracing::debug!("d");
            tracing::info!("i");
            tracing::warn!("w");
            tracing::error!("e");
        });

        let severities: Vec<String> = capture
            .json_lines()
            .iter()
            .map(|line| line["severity"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(severities, ["DEBUG", "DEBUG", "INFO", "WARNING", "ERROR"]);
    }

    #[test]
    fn message_is_top_level_and_always_present() {
        let capture = capture_cloud(|| {
            tracing::info!(target: "app", user = "alice", "signed in after {} tries", 3);
            tracing::info!(target: "app", user = "bob");
        });

        let lines = capture.json_lines();
        assert_eq!(lines[0]["message"], "signed in after 3 tries");
        assert_eq!(lines[0]["user"], "alice");
        assert!(
            lines[0].get("fields").is_none(),
            "nothing nests under `fields`"
        );
        assert_eq!(
            lines[1]["message"], "",
            "a message-less event still has the key"
        );
    }

    #[test]
    fn event_fields_never_override_core_keys() {
        let capture = capture_cloud(|| {
            let request = tracing::info_span!(
                REQUEST_SPAN_NAME,
                { REQUEST_ID_FIELD } = "req-1",
                { TRACE_FIELD } = "projects/p/traces/t1",
            );
            let _request = request.enter();
            tracing::info!(
                target: "app",
                severity = "ERROR",
                logger = "spoofed",
                timestamp = "spoofed",
                { REQUEST_ID_FIELD } = "spoofed",
                { TRACE_FIELD } = "spoofed",
                httpRequest = "spoofed",
                httpRequest.status = 503,
                user = "alice",
                "hi"
            );
        });

        assert_eq!(
            capture.lines(),
            [format!(
                concat!(
                    r#"{},"httpRequest":{{"status":503}},"requestId":"req-1","#,
                    r#""logging.googleapis.com/trace":"projects/p/traces/t1","user":"alice"}}"#,
                ),
                info_prefix()
            )]
        );
    }

    #[test]
    fn correlation_fields_on_an_event_fill_in_outside_a_request_span() {
        // Nothing else claims the keys here, so the event's own values are
        // written (Python's `setdefault` semantics).
        let capture = capture_cloud(|| {
            // A braced constant can't be an event's first field (tracing's
            // macro reads it as a field block), hence the leading `job`.
            tracing::info!(target: "app", job = 7, { REQUEST_ID_FIELD } = "job-7", "hi");
        });

        assert_eq!(capture.json_lines()[0][REQUEST_ID_FIELD], "job-7");
    }

    #[test]
    fn http_request_is_assembled_with_json_types_kept() {
        let capture = capture_cloud(|| {
            // `event!`, not `info!`: `info!(target: …)` can't parse a dotted
            // name as its first field (a tracing macro ambiguity).
            tracing::event!(
                target: "app",
                Level::INFO,
                httpRequest.requestMethod = "GET",
                httpRequest.requestUrl = %"https://example.com/a?b=1",
                httpRequest.status = 200u16,
                httpRequest.latency = "0.123s",
                httpRequest.cacheHit = false,
                "hi"
            );
        });

        assert_eq!(
            capture.lines(),
            [format!(
                concat!(
                    r#"{},"httpRequest":{{"requestMethod":"GET","requestUrl":"https://example.com/a?b=1","#,
                    r#""status":200,"latency":"0.123s","cacheHit":false}}}}"#,
                ),
                info_prefix()
            )]
        );
    }

    #[test]
    fn trace_and_request_id_lift_into_a_handler_log_nested_in_the_request_span() {
        let capture = capture_cloud(|| {
            {
                let request = tracing::info_span!(
                    REQUEST_SPAN_NAME,
                    { REQUEST_ID_FIELD } = %"4bf92f35",
                    { TRACE_FIELD } = "projects/p/traces/abc",
                );
                let _request = request.enter();
                let handler = tracing::info_span!("create_order", user = "alice");
                let _handler = handler.enter();
                tracing::info!(target: "app", "hi");
            }
            tracing::info!(target: "app", "hi");
        });

        assert_eq!(
            capture.lines(),
            [
                // The handler span's own `user` field is not written.
                format!(
                    r#"{},"requestId":"4bf92f35","logging.googleapis.com/trace":"projects/p/traces/abc"}}"#,
                    info_prefix()
                ),
                // Once the request span is exited, lines carry neither key.
                format!("{}}}", info_prefix()),
            ]
        );
    }

    #[test]
    fn nearest_span_supplies_each_key_including_fields_recorded_later() {
        let capture = capture_cloud(|| {
            let outer = tracing::info_span!(
                REQUEST_SPAN_NAME,
                { REQUEST_ID_FIELD } = "outer",
                { TRACE_FIELD } = "projects/p/traces/outer",
            );
            let _outer = outer.enter();
            let inner = tracing::info_span!(
                REQUEST_SPAN_NAME,
                { REQUEST_ID_FIELD } = tracing::field::Empty
            );
            let _inner = inner.enter();
            tracing::info!("declared, not yet recorded");
            inner.record(REQUEST_ID_FIELD, "inner");
            tracing::info!("recorded");
        });

        let lines = capture.json_lines();
        assert_eq!(lines[0][REQUEST_ID_FIELD], "outer");
        assert_eq!(lines[1][REQUEST_ID_FIELD], "inner");
        // The inner span never declared a trace, so the outer one's applies.
        assert_eq!(lines[1][TRACE_FIELD], "projects/p/traces/outer");
    }

    #[test]
    fn real_timestamp_is_rfc3339_utc() {
        use time::format_description::well_known::Rfc3339;
        use time::{Duration, OffsetDateTime, UtcOffset};

        let before = OffsetDateTime::now_utc();
        let capture = Capture::run(CloudLayer::new, || tracing::info!("tick"));
        let after = OffsetDateTime::now_utc();

        let line = &capture.json_lines()[0];
        let timestamp = line["timestamp"].as_str().unwrap();
        let parsed = OffsetDateTime::parse(timestamp, &Rfc3339)
            .unwrap_or_else(|e| panic!("{timestamp:?} is not RFC 3339: {e}"));
        assert_eq!(parsed.offset(), UtcOffset::UTC, "{timestamp:?} is not UTC");
        // The clock is the real one: the stamp falls between the two reads
        // (with slack for the stamp's microsecond truncation).
        let slack = Duration::seconds(1);
        assert!(
            before - slack <= parsed && parsed <= after + slack,
            "{timestamp:?} outside [{before}, {after}]"
        );
    }

    #[test]
    fn log_crate_records_use_their_real_target_and_drop_log_metadata() {
        let capture = capture_cloud(|| {
            // The shape `LogTracer` forwards for
            // `log::info!(target: "hyper::proto", "hi")`. A real `log`
            // record needs the process-global `log` logger, which a test
            // can't install without racing every other test.
            tracing::event!(
                name: "log event",
                target: "log",
                Level::INFO,
                log.target = "hyper::proto",
                log.module_path = "hyper::proto::h1",
                log.file = "src/proto/h1.rs",
                log.line = 42u32,
                "hi"
            );
            // A native event's own `log.*` field is just a field.
            tracing::event!(target: "app", Level::INFO, log.target = "kept", "hi");
        });

        assert_eq!(
            capture.lines(),
            [
                format!(
                    r#"{{"severity":"INFO","message":"hi","logger":"hyper::proto","timestamp":"{FIXED_TIMESTAMP}"}}"#
                ),
                format!(r#"{},"log.target":"kept"}}"#, info_prefix()),
            ]
        );
    }

    #[test]
    fn numbers_beyond_json_range_are_written_as_strings() {
        let capture = capture_cloud(|| {
            tracing::info!(
                target: "app",
                small = 7i128,
                huge = u128::MAX,
                nan = f64::NAN,
                ratio = 0.5,
                "hi"
            );
        });

        let line = &capture.json_lines()[0];
        assert_eq!(line["small"], 7, "an i128 that fits stays a number");
        assert_eq!(line["huge"], u128::MAX.to_string());
        assert_eq!(line["nan"], "NaN");
        assert_eq!(line["ratio"], 0.5);
    }

    /// Emits an event from inside its own `Display`, as a value that logs
    /// while being formatted can.
    struct LogsWhenFormatted(&'static str);

    impl fmt::Display for LogsWhenFormatted {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            tracing::info!(target: "app", "formatting");
            f.write_str(self.0)
        }
    }

    #[test]
    fn recording_a_value_that_logs_while_formatting_does_not_deadlock() {
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::Duration;

        // On its own thread so a regression — the thread blocked on its own
        // span-extension lock — fails the test after a bound instead of
        // hanging the suite.
        let (done, finished) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let capture = capture_cloud(|| {
                let request = tracing::info_span!(
                    REQUEST_SPAN_NAME,
                    { REQUEST_ID_FIELD } = tracing::field::Empty
                );
                let _request = request.enter();
                request.record(
                    REQUEST_ID_FIELD,
                    tracing::field::display(LogsWhenFormatted("req-9")),
                );
                tracing::info!(target: "app", "hi");
            });
            let _ = done.send(capture);
        });
        let capture = match finished.recv_timeout(Duration::from_secs(10)) {
            Ok(capture) => capture,
            Err(RecvTimeoutError::Timeout) => {
                panic!("deadlocked: recording a value whose Display logs never returned")
            }
            Err(RecvTimeoutError::Disconnected) => {
                std::panic::resume_unwind(worker.join().unwrap_err())
            }
        };

        assert_eq!(
            capture.lines(),
            [
                // Logged mid-record, before the id is stored.
                format!(
                    r#"{{"severity":"INFO","message":"formatting","logger":"app","timestamp":"{FIXED_TIMESTAMP}"}}"#
                ),
                format!(r#"{},"requestId":"req-9"}}"#, info_prefix()),
            ]
        );
    }

    /// A value whose `Debug` and `Display` both fail, as a buggy impl can.
    struct Unformattable;

    impl fmt::Debug for Unformattable {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            Err(fmt::Error)
        }
    }

    impl fmt::Display for Unformattable {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            Err(fmt::Error)
        }
    }

    #[test]
    fn a_value_that_fails_to_format_is_written_as_a_placeholder() {
        let capture = capture_cloud(|| {
            let request = tracing::info_span!(
                REQUEST_SPAN_NAME,
                { REQUEST_ID_FIELD } = tracing::field::Empty
            );
            let _request = request.enter();
            request.record(REQUEST_ID_FIELD, tracing::field::display(Unformattable));
            tracing::info!(
                target: "app",
                via_debug = ?Unformattable,
                via_display = %Unformattable,
                "{}",
                Unformattable
            );
        });

        assert_eq!(
            capture.lines(),
            [format!(
                concat!(
                    r#"{{"severity":"INFO","message":"<unformattable>","logger":"app","timestamp":"{}","#,
                    r#""requestId":"<unformattable>","via_debug":"<unformattable>","via_display":"<unformattable>"}}"#,
                ),
                FIXED_TIMESTAMP
            )]
        );
    }

    #[test]
    fn hostile_values_and_names_still_make_one_object_with_unique_keys() {
        let text = "say \"hi\" \\ back\nnext line\ttab\u{1}end";
        let capture = capture_cloud(|| {
            tracing::event!(
                target: "app",
                Level::INFO,
                text = text,
                "we\"ird key" = 1,
                httpRequest = "plain",
                "httpRequest." = "empty sub-key",
                httpRequest.status = 200,
                "message with\na newline"
            );
        });

        let lines = capture.lines();
        assert_eq!(
            lines.len(),
            1,
            "a newline in a value split the line: {lines:?}"
        );
        // `json_lines` itself fails on anything but one object with unique
        // keys at every depth.
        let line = &capture.json_lines()[0];
        assert_eq!(line["message"], "message with\na newline");
        assert_eq!(line["text"], text);
        assert_eq!(line["we\"ird key"], 1);
        assert_eq!(
            line["httpRequest"],
            serde_json::json!({"": "empty sub-key", "status": 200}),
            "the assembled object wins over the plain `httpRequest` field"
        );
    }
}
