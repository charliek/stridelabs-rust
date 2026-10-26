//! A `tower` layer writing one Cloud Logging request entry per request.
//!
//! [`RequestLogLayer`] is the Rust half of Python `stridelabs-logging`'s
//! `RequestLoggingMiddleware`. For every request it:
//!
//! 1. **Establishes the request id** — an existing [`RequestId`] extension,
//!    else a reasonable incoming `x-request-id` header (the same rule
//!    [`RequestIdLayer`] applies), else a fresh 32-hex-character id — and
//!    inserts it as the request's [`RequestId`] extension.
//! 2. **Opens the request span** ([`REQUEST_SPAN_NAME`]) carrying
//!    [`REQUEST_ID_FIELD`] and, when a project is configured and
//!    `X-Cloud-Trace-Context` parses, [`TRACE_FIELD`]
//!    (`projects/{project}/traces/{trace_id}`). The inner service's `call`
//!    and every poll of its response future run inside it, so lines logged
//!    by the handler's future — across `.await`s — carry both keys under
//!    [`CloudLayer`](crate::CloudLayer). See [what inherits the
//!    span](#what-inherits-the-span) for what doesn't.
//! 3. **Writes one event when the response head is ready**, on target
//!    [`REQUEST_LOG_TARGET`] (`stridelabs.request`, Python's logger name),
//!    with message `"METHOD PATH STATUS"` and the `httpRequest` fields
//!    `requestMethod`, `requestUrl`, `status`, `latency` (`"0.123s"`),
//!    `protocol` (`HTTP/1.1`), `userAgent` and `remoteIp`.
//!
//! # Status and level
//!
//! | how the request ended | `status` | level |
//! |---|---|---|
//! | the inner service returned a response | its status | `ERROR` ≥ 500, `WARN` ≥ 400, else `INFO` |
//! | … carrying a [`RequestLogLevel`] extension less severe than that | its status | the extension's |
//! | the inner service returned `Err` (propagated unchanged) | 500 | `ERROR` |
//! | the inner service panicked (the panic propagates unchanged) | 500 | `ERROR` |
//! | the response future was dropped first (client abort, shutdown drain) | 499 | `WARN` |
//!
//! 499 is the client-closed-request convention Python uses: hyper drops a
//! request's future when its client disconnects, and Cloud Run drains
//! in-flight requests on every deploy and scale-down, so these are routine
//! and must not paint the dashboards with server errors. A panic is told
//! apart from an abort by a flag the layer raises only while the inner
//! service's own code runs (its `call`, and each poll of its future): a
//! panic out of that code drops the pending entry mid-unwind with the flag
//! still up, before the runtime (or anything else up the stack) catches the
//! panic. An entry dropped any other way — including by an unrelated panic
//! unwinding through code that owns the future — is a 499.
//!
//! A response may **lower** its entry's level, never raise it: a handler,
//! an extractor's rejection or an inner layer inserts [`RequestLogLevel`]
//! into the response's extensions, and the entry takes that level only when
//! it is less severe than the status's. Lower-only keeps the decision with
//! the code that made it: an app may quieten an expected, attacker-driven
//! 5xx it chose to return — a `503` for a token naming an unknown key id,
//! refused because the key set was refetched moments ago, would otherwise
//! put one `ERROR` per forged request on the dashboards — but nothing can
//! re-rank an entry upward, and a 5xx the app didn't decide on (a response
//! without the extension, an `Err`, a panic) stays `ERROR`. A raise or an
//! equal level is ignored, and the three failure rows never consult it:
//! there is no response to carry one. Under [`CloudLayer`](crate::CloudLayer)
//! `DEBUG` and `TRACE` are both written as `"severity":"DEBUG"` (Cloud
//! Logging has no `TRACE`); a filter still sees the real level, so a
//! lowered entry can fall below it and not be written at all.
//!
//! "Ends" means the inner service's response future completed — the
//! response *head* is ready. The layer wraps that future, not the body, and
//! leaves the response type unchanged. `latency` runs from the layer
//! receiving the request to that moment: for an ordinary response that is
//! the whole request, but for a streamed body (server-sent events, a large
//! download) it stops before the first body byte is produced, let alone
//! sent, and a client that disconnects mid-stream has already been logged
//! with the head's status. Python's middleware, which wraps the whole ASGI
//! call, measures through the last byte and logs such an abort as a
//! `WARNING`.
//!
//! # What inherits the span
//!
//! Exactly the code that runs inside the response future: the inner
//! service's `call`, and the handler's future on every poll, before and
//! after each `.await`. Two kinds of request work run outside it and do not
//! inherit `requestId` or the trace:
//!
//! - **a streamed response body**, polled by the server after the head has
//!   been returned (an SSE stream, a chunked download);
//! - **anything `tokio::spawn`ed** (or otherwise handed to another task).
//!
//! To carry correlation into either, capture the span inside the handler
//! — `let span = tracing::Span::current();` — and attach it: spawn
//! `task.instrument(span)` (with [`tracing::Instrument`]), and in a stream,
//! `.instrument(span.clone())` the future that produces each chunk (or wrap
//! synchronous chunk work in `span.in_scope(..)`).
//!
//! # Make it the outermost layer
//!
//! A layer only sees what reaches it, so this one goes **outside** every
//! layer that can answer on its own (CORS preflights and refusals, security
//! headers, auth): that is what makes the logged status the status the
//! client got, and what gets short-circuited requests logged at all. In
//! axum the last `.layer(..)` call is the outermost:
//!
//! ```no_run
//! use axum::{routing::get, Router};
//! use stridelabs_observability::{RequestIdLayer, RequestLogConfig, RequestLogLayer};
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "ok" }))
//!     .layer(RequestIdLayer) // optional: echoes `x-request-id`
//!     .layer(RequestLogLayer::new(
//!         RequestLogConfig::from_env().with_skip_paths(["/health/live", "/health/ready"]),
//!     ));
//! ```
//!
//! Because this layer establishes the id first, a [`RequestIdLayer`] inside
//! it reuses that id instead of resolving its own, so the logged `requestId`
//! is always the echoed `x-request-id`. **This layer never writes a response
//! header** — a service that wants the id echoed adds [`RequestIdLayer`];
//! one that deliberately sends no such header (tapper) doesn't.
//!
//! # What is never logged
//!
//! Request bodies, and request headers other than `User-Agent` — so never
//! the `Authorization` value, cookies or API keys. Headers are read for
//! exactly four other purposes and never written out as such: `Host` and
//! `X-Forwarded-Proto` rebuild `requestUrl` — userinfo (`alice:secret@`)
//! stripped from the host, a host that isn't a plausible `host[:port]`
//! replaced by `unknown`, and any scheme but `http`/`https` ignored — and
//! `X-Forwarded-For` and `X-Real-IP` give `remoteIp`. The query string is
//! logged inside
//! `requestUrl` with the values of sensitive parameters
//! ([`DEFAULT_REDACTED_QUERY_PARAMS`], or the list given to
//! [`RequestLogConfig::with_redacted_query_params`]) replaced by `REDACTED`,
//! because some clients can only send a token as `?token=…`. The message's
//! path never carries the query.
//!
//! # `remoteIp`
//!
//! The last `X-Forwarded-For` entry: Google's front end *appends* the
//! connecting address to whatever the client sent, so earlier entries are
//! client-controlled. Then `X-Real-IP`, then the connection's peer address
//! when the `axum` feature is on and the server was started with
//! `into_make_service_with_connect_info::<SocketAddr>()` (axum's
//! `ConnectInfo<SocketAddr>` extension is the only place a peer address
//! appears on an `http::Request`, and naming it needs axum). Forensics only:
//! never an input to an auth decision.
//!
//! # Filtering
//!
//! The request span is an `INFO` span on this module's target
//! (`stridelabs_observability::request_log`); the entry is an event on
//! [`REQUEST_LOG_TARGET`]. They are separate targets on purpose:
//! `RUST_LOG=info,stridelabs.request=warn` drops the `INFO` request entries
//! and keeps the span, so handler lines keep their ids. A filter that
//! disables the span itself (anything stricter than `info` for this crate)
//! removes `requestId` and the trace from every line of the request — see
//! [`crate::cloud`] on disabled spans.
//!
//! # Skip paths
//!
//! A request whose path *exactly* equals a configured skip path (no prefix
//! or pattern matching; the raw path, before percent-decoding) passes
//! through untouched: no id, no span, no entry. Meant for health probes,
//! which the platform's own request log already records.
//!
//! [`RequestIdLayer`]: crate::RequestIdLayer

use std::borrow::Cow;
use std::future::Future;
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http::header::{AsHeaderName, HOST, USER_AGENT};
use http::{Extensions, HeaderMap, Method, Request, Response, Version};
use tower::{Layer, Service};
use tracing::{Instrument, Level, Span};

use crate::cloud::{REQUEST_ID_FIELD, REQUEST_SPAN_NAME, TRACE_FIELD};
use crate::request_id::{self, RequestId};

/// The target of the per-request entry, written as the Cloud line's
/// `logger`. Matches Python `stridelabs-logging`'s request logger name, so a
/// Cloud Logging query (`jsonPayload.logger="stridelabs.request"`) finds
/// both languages' request entries.
pub const REQUEST_LOG_TARGET: &str = "stridelabs.request";

/// A response extension that **lowers** the level of the request's entry.
///
/// Inserted into the response's extensions by a handler, an extractor's
/// rejection or a layer inside [`RequestLogLayer`], which reads it when the
/// response head reaches it. Honoured only when it is less severe than the
/// level the status gives (`ERROR` ≥ 500, `WARN` ≥ 400, else `INFO`): a raise
/// or an equal level is ignored, and an inner `Err`, a panic or a dropped
/// future (no response) keep their `ERROR`, `ERROR` and `WARN`. See the
/// [module docs](self#status-and-level) for why it only lowers.
///
/// Only the event's level changes: the status, message and `httpRequest`
/// fields are the same, and the extension itself is never written out.
///
/// ```
/// use axum::{http::StatusCode, response::IntoResponse, Extension};
/// use stridelabs_observability::RequestLogLevel;
/// use tracing::Level;
///
/// // An expected, client-driven 503: its entry is INFO instead of ERROR.
/// async fn handler() -> impl IntoResponse {
///     (
///         StatusCode::SERVICE_UNAVAILABLE,
///         Extension(RequestLogLevel(Level::INFO)),
///     )
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLogLevel(pub Level);

/// Query parameters whose values are replaced by `REDACTED` in
/// `httpRequest.requestUrl` unless [`RequestLogConfig::with_redacted_query_params`]
/// says otherwise. The same list as Python `stridelabs-logging`, matched the
/// same way: the name is percent-decoded, then compared Unicode-lowercased
/// (Python's `.lower()`), so `TOKEN`, `%74oken` and `to%E2%84%AAen` (a Kelvin
/// sign, which lowercases to `k`) all count as `token`.
pub const DEFAULT_REDACTED_QUERY_PARAMS: &[&str] = &[
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "api_key",
    "apikey",
    "password",
    "secret",
    "key",
];

/// Where the GCP project for trace correlation is read from, first match
/// winning: what Cloud Run documents, then the name StrideLabs services
/// already carry in their own config.
const PROJECT_ENV_VARS: [&str; 2] = ["GOOGLE_CLOUD_PROJECT", "GOOGLE_PROJECT_ID"];

const CLOUD_TRACE_HEADER: &str = "x-cloud-trace-context";
const X_FORWARDED_FOR: &str = "x-forwarded-for";
const X_FORWARDED_PROTO: &str = "x-forwarded-proto";
const X_REAL_IP: &str = "x-real-ip";

/// nginx's client-closed-request status, which Python logs for an aborted
/// request too. Not a status any response carries, so `http` has no name
/// for it.
const CLIENT_CLOSED_REQUEST: u16 = 499;
const INTERNAL_SERVER_ERROR: u16 = 500;

/// [`RequestLogLayer`]'s settings. Start from [`RequestLogConfig::from_env`]
/// (or [`RequestLogConfig::from_lookup`]) and adjust with the `with_*`
/// methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLogConfig {
    skip_paths: Vec<String>,
    project_id: Option<String>,
    redacted_query_params: Vec<String>,
}

impl RequestLogConfig {
    /// The defaults, with the project read from the process environment:
    /// `GOOGLE_CLOUD_PROJECT`, else `GOOGLE_PROJECT_ID`. See
    /// [`RequestLogConfig::from_lookup`].
    pub fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// The defaults, with the project read through `lookup`:
    /// `GOOGLE_CLOUD_PROJECT`, else `GOOGLE_PROJECT_ID`, an empty value
    /// counting as unset (Python's `or` chain). No paths are skipped, and the
    /// redacted parameters are [`DEFAULT_REDACTED_QUERY_PARAMS`].
    ///
    /// The seam [`RequestLogConfig::from_env`] plugs `std::env::var` into, so
    /// tests (and services whose settings come from elsewhere) supply values
    /// without touching the process environment.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            skip_paths: Vec::new(),
            project_id: PROJECT_ENV_VARS
                .iter()
                .find_map(|name| lookup(name).filter(|value| !value.is_empty())),
            redacted_query_params: DEFAULT_REDACTED_QUERY_PARAMS
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
        }
    }

    /// Paths that bypass the layer entirely — no request id, no span, no
    /// entry. Matched exactly against the raw request path (`/health` does
    /// not skip `/health/live`). Replaces any previous list.
    pub fn with_skip_paths<I, P>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        self.skip_paths = paths.into_iter().map(Into::into).collect();
        self
    }

    /// The GCP project trace ids are qualified with. `None` (or an empty
    /// string) turns trace correlation off; everything else still works.
    pub fn with_project_id(mut self, project_id: Option<String>) -> Self {
        self.project_id = project_id.filter(|project| !project.is_empty());
        self
    }

    /// Query parameters whose values are redacted from `requestUrl`, matched
    /// case-insensitively (Unicode lowercase) after percent-decoding the
    /// name; kept lowercased. Replaces the list, defaults included; to
    /// extend it, chain onto [`DEFAULT_REDACTED_QUERY_PARAMS`].
    pub fn with_redacted_query_params<I, P>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        self.redacted_query_params = names
            .into_iter()
            .map(|name| name.into().to_lowercase())
            .collect();
        self
    }

    fn skips(&self, path: &str) -> bool {
        self.skip_paths.iter().any(|skip| skip == path)
    }

    /// `X-Cloud-Trace-Context: TRACE_ID[/SPAN_ID][;o=OPTIONS]` as Cloud
    /// Logging's trace resource name, or `None` when no project is
    /// configured or the header is absent or malformed. Cloud Logging
    /// silently drops a malformed trace reference, so the id must be exactly
    /// 32 hex digits.
    fn trace(&self, headers: &HeaderMap) -> Option<String> {
        let project = self.project_id.as_deref()?;
        let header = headers.get(CLOUD_TRACE_HEADER)?.to_str().ok()?;
        // Options may follow without a span segment (`TRACE_ID;o=1`).
        let trace_id = header.split(['/', ';']).next()?;
        let well_formed = trace_id.len() == 32 && trace_id.bytes().all(|b| b.is_ascii_hexdigit());
        well_formed.then(|| format!("projects/{project}/traces/{trace_id}"))
    }

    fn is_redacted(&self, raw_name: &str) -> bool {
        // Decoded because every framework's parser decodes it: `api%5Fkey`
        // reaches a handler as `api_key`. Lossy and Unicode-lowercased as
        // Python's `unquote_plus(name).lower()` is, so the two redact the
        // same names; the configured names are already lowercase.
        let name = String::from_utf8_lossy(&decode_query_component(raw_name)).to_lowercase();
        self.redacted_query_params.contains(&name)
    }
}

/// A [`tower::Layer`] writing one request entry per request and opening the
/// request span around it. See the [module docs](self) for the entry, the
/// request-id rule, and why it belongs outermost.
#[derive(Debug, Clone)]
pub struct RequestLogLayer {
    config: Arc<RequestLogConfig>,
}

impl RequestLogLayer {
    /// A layer with the given settings.
    pub fn new(config: RequestLogConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for RequestLogLayer {
    type Service = RequestLogService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestLogService {
            inner,
            config: Arc::clone(&self.config),
        }
    }
}

/// The [`tower::Service`] installed by [`RequestLogLayer`]. See the layer's
/// docs for behavior.
#[derive(Debug, Clone)]
pub struct RequestLogService<S> {
    inner: S,
    config: Arc<RequestLogConfig>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RequestLogService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        if self.config.skips(req.uri().path()) {
            return Box::pin(self.inner.call(req));
        }

        let id = request_id::resolve(&req);
        let trace = self.config.trace(req.headers());
        let span = tracing::info_span!(
            REQUEST_SPAN_NAME,
            { REQUEST_ID_FIELD } = %id,
            { TRACE_FIELD } = trace.as_deref(),
        );
        // Built before the request moves into the inner service. Owning the
        // span is what lets the entry be written inside it even from `Drop`.
        let mut entry = PendingEntry::start(&req, &self.config, span.clone());
        req.extensions_mut().insert(RequestId(id));

        // `call` itself runs inside the span too: a service may do (and log)
        // real work before returning its future. `inside_inner` brackets the
        // inner service's own code, here and around each poll below, so
        // `Drop` can tell a panic out of it from an unrelated unwind.
        entry.inside_inner = true;
        let fut = span.in_scope(|| self.inner.call(req));
        entry.inside_inner = false;
        let fut = fut.instrument(span);
        Box::pin(async move {
            let mut fut = pin!(fut);
            let result = std::future::poll_fn(|cx| {
                entry.inside_inner = true;
                let poll = fut.as_mut().poll(cx);
                entry.inside_inner = false;
                poll
            })
            .await;
            match &result {
                Ok(res) => entry.finish(
                    res.status().as_u16(),
                    res.extensions().get::<RequestLogLevel>().copied(),
                ),
                Err(_) => entry.finish(INTERNAL_SERVER_ERROR, None),
            }
            result
        })
    }
}

/// What the request entry needs, captured when the request arrives and
/// written exactly once: by [`PendingEntry::finish`], or by `Drop` as a 499
/// when the response future is dropped before the inner service answers.
struct PendingEntry {
    span: Span,
    method: Method,
    path: String,
    request_url: String,
    protocol: &'static str,
    user_agent: Option<String>,
    remote_ip: Option<String>,
    start: Instant,
    /// Up exactly while the inner service's own code runs — its `call`, or
    /// a poll of its future. A panic out of that code leaves it up.
    inside_inner: bool,
    written: bool,
}

impl PendingEntry {
    fn start<B>(req: &Request<B>, config: &RequestLogConfig, span: Span) -> Self {
        Self {
            span,
            method: req.method().clone(),
            path: req.uri().path().to_owned(),
            request_url: request_url(req, config),
            protocol: protocol(req.version()),
            user_agent: header(req.headers(), USER_AGENT).map(Cow::into_owned),
            remote_ip: remote_ip(req.headers(), req.extensions()),
            start: Instant::now(),
            inside_inner: false,
            written: false,
        }
    }

    /// Writes the entry at [`entry_level`]'s level.
    fn finish(&mut self, status: u16, requested: Option<RequestLogLevel>) {
        // Marked first: if writing ever panicked, `Drop` must not try again.
        self.written = true;
        let latency = format_latency(self.start.elapsed());
        let _entered = self.span.enter();

        // A level is part of an event's static callsite, so each level gets
        // its own `event!`; the field list is written once, here.
        macro_rules! entry {
            ($level:expr) => {
                tracing::event!(
                    target: REQUEST_LOG_TARGET,
                    $level,
                    httpRequest.requestMethod = self.method.as_str(),
                    httpRequest.requestUrl = self.request_url.as_str(),
                    httpRequest.status = status,
                    httpRequest.latency = latency.as_str(),
                    httpRequest.protocol = self.protocol,
                    // `None` records nothing, so the key is left out.
                    httpRequest.userAgent = self.user_agent.as_deref(),
                    httpRequest.remoteIp = self.remote_ip.as_deref(),
                    "{} {} {}",
                    self.method,
                    self.path,
                    status
                )
            };
        }
        match entry_level(status, requested) {
            Level::ERROR => entry!(Level::ERROR),
            Level::WARN => entry!(Level::WARN),
            Level::INFO => entry!(Level::INFO),
            Level::DEBUG => entry!(Level::DEBUG),
            Level::TRACE => entry!(Level::TRACE),
        }
    }
}

/// The entry's level: `ERROR` ≥ 500, `WARN` ≥ 400, else `INFO`, unless the
/// response asked for a less severe one.
fn entry_level(status: u16, requested: Option<RequestLogLevel>) -> Level {
    let by_status = if status >= 500 {
        Level::ERROR
    } else if status >= 400 {
        Level::WARN
    } else {
        Level::INFO
    };
    match requested {
        // `tracing` orders levels by verbosity, not severity: a LESS severe
        // level compares GREATER (TRACE > DEBUG > INFO > WARN > ERROR). So
        // `>` is "lowers"; a raise or an equal level keeps the status's.
        Some(RequestLogLevel(level)) if level > by_status => level,
        _ => by_status,
    }
}

impl Drop for PendingEntry {
    fn drop(&mut self) {
        if self.written {
            return;
        }
        // Dropped mid-unwind with `inside_inner` still up means the inner
        // service itself panicked — in its synchronous `call`, or while being
        // polled: a panic out of `poll` drops the async block's live locals,
        // this entry among them, before anything up the stack can catch it.
        // That is a server failure. Any other drop is a 499, including one
        // during an unrelated panic that unwinds through whatever owns this
        // future: the request didn't fail, it was abandoned.
        let status = if self.inside_inner && std::thread::panicking() {
            INTERNAL_SERVER_ERROR
        } else {
            CLIENT_CLOSED_REQUEST
        };
        // No response, so no `RequestLogLevel` to consult.
        self.finish(status, None);
    }
}

/// A header's value as text, or `None` when absent. Header values may carry
/// any byte but control characters, so the conversion is lossy rather than
/// `to_str`'s all-or-nothing: a non-ASCII `User-Agent` is logged with a
/// replacement character instead of being dropped.
fn header(headers: &HeaderMap, name: impl AsHeaderName) -> Option<Cow<'_, str>> {
    headers
        .get(name)
        .map(|value| String::from_utf8_lossy(value.as_bytes()))
}

/// The full URL per Cloud Logging's `HttpRequest.requestUrl`: the scheme the
/// client used (the first `X-Forwarded-Proto` entry, which is what the edge
/// terminated TLS on), the host it asked for, and the raw path and query
/// with sensitive parameter values redacted.
///
/// The scheme and host are client-supplied text outside the query, so
/// neither is copied verbatim: see [`forwarded_scheme`] and
/// [`loggable_host`]. A host that fails the check falls back to the URI's
/// authority (checked the same way) and then to the placeholder `unknown`,
/// keeping the URL absolute rather than logging the suspect text.
fn request_url<B>(req: &Request<B>, config: &RequestLogConfig) -> String {
    let headers = req.headers();
    let uri = req.uri();
    let scheme = header(headers, X_FORWARDED_PROTO)
        .and_then(|value| forwarded_scheme(&value))
        // `http` admits only RFC 3986 scheme characters here, so the URI's
        // scheme can't smuggle anything in.
        .or_else(|| uri.scheme_str())
        .unwrap_or("http");
    let host_header = header(headers, HOST);
    // An HTTP/2 request carries its host as the URI's authority, not a
    // `Host` header.
    let host = host_header
        .as_deref()
        .and_then(loggable_host)
        .or_else(|| {
            uri.authority()
                .and_then(|authority| loggable_host(authority.as_str()))
        })
        .unwrap_or("unknown");
    let path = uri.path();
    match uri.query().filter(|query| !query.is_empty()) {
        Some(query) => format!("{scheme}://{host}{path}?{}", redact_query(query, config)),
        None => format!("{scheme}://{host}{path}"),
    }
}

/// The scheme an `X-Forwarded-Proto` value names: its first comma-separated
/// entry, trimmed, if that is `http` or `https` (in any case). Anything else
/// is treated as no header at all — a client-written value can't be allowed
/// to put arbitrary text (`https://evil/?token=…`) at the front of the URL.
fn forwarded_scheme(value: &str) -> Option<&'static str> {
    let scheme = value.split(',').next()?.trim();
    if scheme.eq_ignore_ascii_case("https") {
        Some("https")
    } else if scheme.eq_ignore_ascii_case("http") {
        Some("http")
    } else {
        None
    }
}

/// The part of `authority` (a `Host` header or a URI authority) fit to log
/// as the host: without its userinfo — everything through the last `@`,
/// which can carry a password (`alice:secret@example.com`) — and only if what
/// remains could be a `host[:port]`: non-empty printable ASCII with no `/`,
/// `?`, `#` or `\`. Otherwise `None`, so text that could pose as part of
/// the path or query, outside the query redaction, is never written. Real
/// hosts are ASCII on the wire (IDNs travel as punycode), so nothing a
/// well-behaved client sends is lost.
fn loggable_host(authority: &str) -> Option<&str> {
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_userinfo, host)| host);
    let plausible = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'/' | b'?' | b'#' | b'\\'));
    plausible.then_some(host)
}

/// `query` with each sensitive parameter's value replaced by `REDACTED`.
/// Works on the raw, still percent-encoded query and keeps the raw name, so
/// the logged URL round-trips byte for byte except for the scrubbed values.
/// A parameter without `=` has no value to hide and is kept as is.
fn redact_query(query: &str, config: &RequestLogConfig) -> String {
    query
        .split('&')
        .map(|part| match part.split_once('=') {
            Some((name, _)) if config.is_redacted(name) => Cow::Owned(format!("{name}=REDACTED")),
            _ => Cow::Borrowed(part),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// `application/x-www-form-urlencoded` decoding of one query name (`+` is a
/// space, `%XX` a byte), as raw bytes for the caller to read as UTF-8. An
/// incomplete or non-hex `%` escape is kept literally, as Python's
/// `unquote_plus` (and every lenient parser) keeps it.
fn decode_query_component(raw: &str) -> Vec<u8> {
    fn hex(byte: Option<&u8>) -> Option<u8> {
        char::from(*byte?).to_digit(16).map(|digit| digit as u8)
    }

    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        match byte {
            b'+' => decoded.push(b' '),
            b'%' => {
                if let (Some(high), Some(low)) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) {
                    decoded.push(high << 4 | low);
                    i += 2;
                } else {
                    decoded.push(b'%');
                }
            }
            other => decoded.push(other),
        }
        i += 1;
    }
    decoded
}

/// The client's address — see the [module docs](self#remoteip) for the
/// order and why the *last* forwarded entry. Of several `X-Forwarded-For`
/// lines, the last is the one the edge appended to.
fn remote_ip(headers: &HeaderMap, extensions: &Extensions) -> Option<String> {
    let non_empty = |value: &str| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    };
    headers
        .get_all(X_FORWARDED_FOR)
        .iter()
        .next_back()
        .and_then(|value| {
            non_empty(
                String::from_utf8_lossy(value.as_bytes())
                    .rsplit(',')
                    .next()?,
            )
        })
        .or_else(|| non_empty(&header(headers, X_REAL_IP)?))
        .or_else(|| peer_ip(extensions))
}

/// The connection's peer address from axum's `ConnectInfo` — present only
/// when the server was built with `into_make_service_with_connect_info`.
#[cfg(feature = "axum")]
fn peer_ip(extensions: &Extensions) -> Option<String> {
    extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|axum::extract::ConnectInfo(addr)| addr.ip().to_string())
}

#[cfg(not(feature = "axum"))]
fn peer_ip(_extensions: &Extensions) -> Option<String> {
    None
}

/// `HTTP/<version>` as Cloud Logging and Python's middleware spell it, where
/// HTTP/2 and HTTP/3 have no minor version.
fn protocol(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        // HTTP/1.1, and the fallback: `http` defines no other versions, and
        // 1.1 is what Python assumes when the server doesn't say.
        _ => "HTTP/1.1",
    }
}

/// Seconds with millisecond precision and an `s` suffix — the `Duration`
/// JSON form Cloud Logging's `httpRequest.latency` takes, and Python's
/// `f"{seconds:.3f}s"`.
fn format_latency(elapsed: Duration) -> String {
    format!("{:.3}s", elapsed.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::panic::{self, AssertUnwindSafe};
    use std::task::Waker;

    use axum::body::Body;
    use axum::extract::Extension;
    use axum::routing::get;
    use axum::Router;
    use http::{HeaderValue, StatusCode};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::cloud::CloudLayer;
    use crate::request_id::{RequestIdLayer, REQUEST_ID_HEADER};
    use crate::test_support::{Capture, FixedTime, FIXED_TIMESTAMP};

    const PROJECT: &str = "my-project";
    const TRACE_ID: &str = "105445aa7843bc8bf206b12000100000";

    /// Name/value pairs: a case's request headers, or its environment.
    type Headers = &'static [(&'static str, &'static str)];

    /// Defaults with no project configured.
    fn config() -> RequestLogConfig {
        RequestLogConfig::from_lookup(|_| None)
    }

    /// Defaults with [`PROJECT`] configured through the environment seam.
    fn config_with_project() -> RequestLogConfig {
        RequestLogConfig::from_lookup(|name| {
            (name == "GOOGLE_CLOUD_PROJECT").then(|| PROJECT.to_owned())
        })
    }

    fn cloud_layer(writer: Capture) -> CloudLayer<Capture, FixedTime> {
        CloudLayer::new(writer).with_timer(FixedTime)
    }

    /// Drive `fut` to completion on a current-thread runtime — so every task
    /// runs on this thread, under the thread-scoped capturing subscriber —
    /// and return what it wrote alongside its output.
    fn drive<T>(fut: impl Future<Output = T>) -> (Capture, T) {
        drive_under(cloud_layer, fut)
    }

    /// [`drive`], under the layer `make_layer` builds over the capture.
    fn drive_under<L, T>(
        make_layer: impl FnOnce(Capture) -> L,
        fut: impl Future<Output = T>,
    ) -> (Capture, T)
    where
        L: tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
    {
        let mut output = None;
        let capture = Capture::run(make_layer, || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            output = Some(runtime.block_on(fut));
        });
        (capture, output.unwrap())
    }

    /// The router most tests send requests through: a handler for every
    /// status they need, plus one that logs.
    fn app() -> Router {
        Router::new()
            .route("/orders", get(|| async { "ok" }))
            .route("/missing", get(|| async { StatusCode::NOT_FOUND }))
            .route(
                "/broken",
                get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            )
            .route(
                "/unavailable",
                get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
            )
            .route("/created", get(|| async { StatusCode::CREATED }))
            .route(
                "/moved",
                get(|| async { (StatusCode::FOUND, [("location", "/orders")]) }),
            )
            .route(
                "/health/live",
                get(|| async {
                    tracing::info!(target: "app", "probe");
                    "ok"
                }),
            )
            .route(
                "/handled",
                get(|| async {
                    // A handler span nested inside the request span, as a
                    // `#[instrument]`ed handler would open.
                    tracing::info_span!("create_order", user = "alice")
                        .in_scope(|| tracing::info!(target: "app", "creating order"));
                    "ok"
                }),
            )
            .route(
                "/suspended",
                get(|| async {
                    tracing::info!(target: "app", "before");
                    // Returns `Pending` once: the rest runs on a later poll.
                    tokio::task::yield_now().await;
                    tracing::info!(target: "app", "after");
                    "ok"
                }),
            )
            .route(
                "/filtered",
                get(|| async {
                    tracing::debug!(target: "app", "below the filter");
                    tracing::info!(target: "app", "handled");
                    "ok"
                }),
            )
            .route(
                "/spawned",
                get(|| async {
                    let bare = tokio::spawn(async { tracing::info!(target: "app", "bare") });
                    let span = tracing::Span::current();
                    let carried = tokio::spawn(
                        async { tracing::info!(target: "app", "carried") }.instrument(span),
                    );
                    bare.await.unwrap();
                    carried.await.unwrap();
                    "ok"
                }),
            )
    }

    fn logged(config: RequestLogConfig) -> Router {
        app().layer(RequestLogLayer::new(config))
    }

    /// A `GET` of `uri` carrying `headers`, in order.
    fn get_with_headers(uri: &str, headers: Headers) -> http::request::Builder {
        headers
            .iter()
            .fold(Request::get(uri), |req, (name, value)| {
                req.header(*name, *value)
            })
    }

    async fn send(router: Router, req: http::request::Builder) -> Response<Body> {
        router
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// Every captured line, with a request entry's `httpRequest.latency`
    /// value replaced by `<latency>` after checking it has the `0.123s`
    /// shape — the one value in an entry no test can pin.
    fn golden_lines(capture: &Capture) -> Vec<String> {
        capture
            .lines()
            .into_iter()
            .map(|line| {
                if line.contains(r#""logger":"stridelabs.request""#) {
                    without_latency(&line)
                } else {
                    line
                }
            })
            .collect()
    }

    fn without_latency(line: &str) -> String {
        const KEY: &str = r#""latency":""#;
        let start = line
            .find(KEY)
            .unwrap_or_else(|| panic!("no latency: {line}"))
            + KEY.len();
        let end = start + line[start..].find('"').unwrap();
        let latency = &line[start..end];
        let (whole, fraction) = latency
            .strip_suffix('s')
            .and_then(|seconds| seconds.split_once('.'))
            .unwrap_or_else(|| panic!("latency {latency:?} is not `<seconds>.<millis>s`"));
        assert!(
            !whole.is_empty()
                && whole.bytes().all(|b| b.is_ascii_digit())
                && fraction.len() == 3
                && fraction.bytes().all(|b| b.is_ascii_digit()),
            "latency {latency:?} is not `<seconds>.<millis>s`"
        );
        format!("{}<latency>{}", &line[..start], &line[end..])
    }

    /// The lines on [`REQUEST_LOG_TARGET`] only.
    fn entries(capture: &Capture) -> Vec<Value> {
        capture
            .json_lines()
            .into_iter()
            .filter(|line| line["logger"] == REQUEST_LOG_TARGET)
            .collect()
    }

    fn only_entry(capture: &Capture) -> Value {
        let mut entries = entries(capture);
        assert_eq!(entries.len(), 1, "{:?}", capture.lines());
        entries.remove(0)
    }

    #[test]
    fn one_golden_line_per_request() {
        let (capture, res) = drive(send(
            logged(config()),
            Request::get("/orders?page=2")
                .header(HOST, "api.example.com")
                .header(USER_AGENT, "curl/8.4.0")
                .header(X_FORWARDED_FOR, "203.0.113.7")
                .header(REQUEST_ID_HEADER, "req-1"),
        ));

        assert_eq!(res.status(), StatusCode::OK);
        let lines = golden_lines(&capture);
        assert_eq!(
            lines,
            [format!(
                concat!(
                    r#"{{"severity":"INFO","message":"GET /orders 200","logger":"stridelabs.request","#,
                    r#""timestamp":"{}","httpRequest":{{"requestMethod":"GET","#,
                    r#""requestUrl":"http://api.example.com/orders?page=2","status":200,"#,
                    r#""latency":"<latency>","protocol":"HTTP/1.1","userAgent":"curl/8.4.0","#,
                    r#""remoteIp":"203.0.113.7"}},"requestId":"req-1"}}"#,
                ),
                FIXED_TIMESTAMP
            )]
        );
    }

    #[test]
    fn severity_follows_the_status() {
        for (path, status, severity) in [
            ("/orders", 200, "INFO"),
            ("/created", 201, "INFO"),
            ("/moved", 302, "INFO"),
            ("/missing", 404, "WARNING"),
            ("/nowhere", 404, "WARNING"), // axum's own fallback
            ("/broken", 500, "ERROR"),
        ] {
            let (capture, _) = drive(send(logged(config()), Request::get(path)));

            let entry = only_entry(&capture);
            assert_eq!(entry["severity"], severity, "{path}");
            assert_eq!(entry["httpRequest"]["status"], status, "{path}");
            assert_eq!(entry["message"], format!("GET {path} {status}"), "{path}");
        }
    }

    /// A logged router whose `/r` answers `status` with `level` as its
    /// [`RequestLogLevel`], the way a handler sets one.
    fn lowered(status: StatusCode, level: Level) -> Router {
        Router::new()
            .route(
                "/r",
                get(move || async move { (status, Extension(RequestLogLevel(level))) }),
            )
            .layer(RequestLogLayer::new(config()))
    }

    #[test]
    fn levels_compare_by_verbosity_and_only_a_lower_one_is_taken() {
        // The ordering the comparison in `entry_level` relies on: a LESS
        // severe level compares GREATER.
        assert!(Level::TRACE > Level::DEBUG);
        assert!(Level::DEBUG > Level::INFO);
        assert!(Level::INFO > Level::WARN);
        assert!(Level::WARN > Level::ERROR);

        let requests = [
            Level::ERROR,
            Level::WARN,
            Level::INFO,
            Level::DEBUG,
            Level::TRACE,
        ];
        for (status, expected) in [
            (
                503,
                [
                    Level::ERROR,
                    Level::WARN,
                    Level::INFO,
                    Level::DEBUG,
                    Level::TRACE,
                ],
            ),
            (
                404,
                [
                    Level::WARN,
                    Level::WARN,
                    Level::INFO,
                    Level::DEBUG,
                    Level::TRACE,
                ],
            ),
            (
                200,
                [
                    Level::INFO,
                    Level::INFO,
                    Level::INFO,
                    Level::DEBUG,
                    Level::TRACE,
                ],
            ),
        ] {
            for (requested, expected) in requests.into_iter().zip(expected) {
                assert_eq!(
                    entry_level(status, Some(RequestLogLevel(requested))),
                    expected,
                    "{status} asking for {requested}"
                );
            }
        }
        assert_eq!(entry_level(503, None), Level::ERROR);
        assert_eq!(entry_level(404, None), Level::WARN);
        assert_eq!(entry_level(200, None), Level::INFO);
    }

    #[test]
    fn a_lower_level_on_the_response_is_honoured() {
        for (status, level, severity) in [
            (503, Level::WARN, "WARNING"),
            (503, Level::INFO, "INFO"),
            (503, Level::DEBUG, "DEBUG"),
            // Cloud Logging has no TRACE: the formatter writes it as DEBUG.
            (503, Level::TRACE, "DEBUG"),
            (500, Level::INFO, "INFO"),
            (404, Level::INFO, "INFO"),
            (404, Level::DEBUG, "DEBUG"),
            (200, Level::DEBUG, "DEBUG"),
        ] {
            let code = StatusCode::from_u16(status).unwrap();
            let (capture, res) = drive(send(lowered(code, level), Request::get("/r")));

            assert_eq!(res.status(), code);
            let entry = only_entry(&capture);
            assert_eq!(entry["severity"], severity, "{status} at {level}");
            assert_eq!(
                entry["httpRequest"]["status"], status,
                "{status} at {level}"
            );
            assert_eq!(
                entry["message"],
                format!("GET /r {status}"),
                "{status} at {level}"
            );
        }
    }

    #[test]
    fn a_raise_or_an_equal_level_is_ignored() {
        for (status, level, severity) in [
            (200, Level::ERROR, "INFO"),
            (200, Level::WARN, "INFO"),
            (404, Level::ERROR, "WARNING"),
            // Equal: the same level either way, so nothing to see but that
            // it is still the status's.
            (503, Level::ERROR, "ERROR"),
            (404, Level::WARN, "WARNING"),
            (200, Level::INFO, "INFO"),
        ] {
            let code = StatusCode::from_u16(status).unwrap();
            let (capture, _) = drive(send(lowered(code, level), Request::get("/r")));

            assert_eq!(
                only_entry(&capture)["severity"],
                severity,
                "{status} at {level}"
            );
        }
    }

    #[test]
    fn a_5xx_without_the_extension_stays_an_error() {
        for (path, status) in [("/unavailable", 503), ("/broken", 500)] {
            let (capture, _) = drive(send(logged(config()), Request::get(path)));

            let entry = only_entry(&capture);
            assert_eq!(entry["severity"], "ERROR", "{path}");
            assert_eq!(entry["httpRequest"]["status"], status, "{path}");
        }
    }

    #[test]
    fn one_golden_line_for_a_lowered_entry() {
        let (capture, _) = drive(send(
            lowered(StatusCode::SERVICE_UNAVAILABLE, Level::INFO),
            Request::get("/r")
                .header(HOST, "api.example.com")
                .header(USER_AGENT, "curl/8.4.0")
                .header(X_FORWARDED_FOR, "203.0.113.7")
                .header(REQUEST_ID_HEADER, "req-1"),
        ));

        assert_eq!(
            golden_lines(&capture),
            [format!(
                concat!(
                    r#"{{"severity":"INFO","message":"GET /r 503","logger":"stridelabs.request","#,
                    r#""timestamp":"{}","httpRequest":{{"requestMethod":"GET","#,
                    r#""requestUrl":"http://api.example.com/r","status":503,"#,
                    r#""latency":"<latency>","protocol":"HTTP/1.1","userAgent":"curl/8.4.0","#,
                    r#""remoteIp":"203.0.113.7"}},"requestId":"req-1"}}"#,
                ),
                FIXED_TIMESTAMP
            )]
        );
    }

    #[test]
    fn a_filter_sees_the_lowered_level() {
        use tracing_subscriber::{EnvFilter, Layer as _};

        // TRACE and DEBUG share a severity, so only a filter tells them apart.
        for (filter, level, kept) in [
            ("info", Level::INFO, Some("INFO")),
            ("info", Level::DEBUG, None),
            ("debug", Level::DEBUG, Some("DEBUG")),
            ("debug", Level::TRACE, None),
            ("trace", Level::TRACE, Some("DEBUG")),
        ] {
            let (capture, res) = drive_under(
                |writer| EnvFilter::new(filter).and_then(cloud_layer(writer)),
                send(
                    lowered(StatusCode::SERVICE_UNAVAILABLE, level),
                    Request::get("/r"),
                ),
            );

            assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
            let severities: Vec<Value> = entries(&capture)
                .into_iter()
                .map(|entry| entry["severity"].clone())
                .collect();
            let expected: Vec<Value> = kept.into_iter().map(Value::from).collect();
            assert_eq!(severities, expected, "{filter} at {level}");
        }
    }

    #[test]
    fn a_streamed_response_is_logged_at_its_heads_level() {
        use axum::response::sse::{Event, Sse};

        let router = Router::new()
            .route(
                "/events",
                get(|| async {
                    // A body that never ends: the entry can only come from
                    // the head.
                    let events = futures_util::stream::pending::<Result<Event, Infallible>>();
                    (Extension(RequestLogLevel(Level::DEBUG)), Sse::new(events))
                }),
            )
            .layer(RequestLogLayer::new(config()));

        let (capture, res) = drive(send(router, Request::get("/events")));

        assert_eq!(res.headers()["content-type"], "text/event-stream");
        let entry = only_entry(&capture);
        assert_eq!(entry["severity"], "DEBUG");
        assert_eq!(entry["message"], "GET /events 200");
    }

    #[test]
    fn a_level_set_by_an_inner_layer_is_honoured() {
        // An inner layer that quietens one expected 503, with this crate's
        // own `RequestIdLayer` between it and the logger: the extension
        // travels on the response through both.
        let router = app()
            .layer(axum::middleware::map_response(
                |mut res: Response<Body>| async move {
                    if res.status() == StatusCode::SERVICE_UNAVAILABLE {
                        res.extensions_mut().insert(RequestLogLevel(Level::INFO));
                    }
                    res
                },
            ))
            .layer(RequestIdLayer)
            .layer(RequestLogLayer::new(config()));

        for (path, severity) in [("/unavailable", "INFO"), ("/broken", "ERROR")] {
            let (capture, res) = drive(send(router.clone(), Request::get(path)));

            assert!(res.headers().contains_key(REQUEST_ID_HEADER), "{path}");
            assert_eq!(only_entry(&capture)["severity"], severity, "{path}");
        }
    }

    /// A request carrying a [`RequestLogLevel`] in its own extensions, where
    /// the layer must never look.
    fn asking_for_debug<B>(uri: &str, body: B) -> Request<B> {
        let mut req = Request::get(uri).body(body).unwrap();
        req.extensions_mut().insert(RequestLogLevel(Level::DEBUG));
        req
    }

    #[test]
    fn a_failed_or_abandoned_request_never_takes_a_level() {
        // An inner `Err`: no response to carry a level.
        let svc =
            RequestLogLayer::new(config()).layer(tower::service_fn(|_req: Request<()>| async {
                Err::<Response<()>, _>("upstream refused")
            }));
        let (capture, result) = drive(svc.oneshot(asking_for_debug("/boom", ())));
        assert!(result.is_err());
        let entry = only_entry(&capture);
        assert_eq!(
            (&entry["severity"], &entry["httpRequest"]["status"]),
            (&Value::from("ERROR"), &Value::from(500))
        );

        // A panic, out of a handler whose response would have carried one.
        let router = Router::new()
            .route(
                "/explode",
                get(|| async {
                    if true {
                        panic!("handler exploded");
                    }
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Extension(RequestLogLevel(Level::DEBUG)),
                    )
                }),
            )
            .layer(RequestLogLayer::new(config()));
        let capture = Capture::run(cloud_layer, || {
            let mut svc = router;
            let mut fut = Box::pin(svc.call(asking_for_debug("/explode", Body::empty())));
            let mut cx = Context::from_waker(Waker::noop());
            panic::catch_unwind(AssertUnwindSafe(|| fut.as_mut().poll(&mut cx)))
                .expect_err("the handler's panic propagates");
            drop(fut);
        });
        let entry = only_entry(&capture);
        assert_eq!(
            (&entry["severity"], &entry["httpRequest"]["status"]),
            (&Value::from("ERROR"), &Value::from(500))
        );

        // A dropped future, whose response would have carried one.
        let router = Router::new()
            .route(
                "/slow",
                get(|| async {
                    std::future::pending::<()>().await;
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Extension(RequestLogLevel(Level::DEBUG)),
                    )
                }),
            )
            .layer(RequestLogLayer::new(config()));
        let capture = Capture::run(cloud_layer, || {
            let mut svc = router;
            let mut fut = Box::pin(svc.call(asking_for_debug("/slow", Body::empty())));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(fut.as_mut().poll(&mut cx).is_pending());
            drop(fut);
        });
        let entry = only_entry(&capture);
        assert_eq!(
            (&entry["severity"], &entry["httpRequest"]["status"]),
            (&Value::from("WARNING"), &Value::from(499))
        );
    }

    #[test]
    fn an_inner_error_is_logged_as_a_500_and_propagated_unchanged() {
        let svc =
            RequestLogLayer::new(config()).layer(tower::service_fn(|_req: Request<()>| async {
                Err::<Response<()>, _>("upstream refused")
            }));

        let (capture, result) = drive(svc.oneshot(Request::get("/boom").body(()).unwrap()));

        assert_eq!(result.unwrap_err(), "upstream refused");
        let entry = only_entry(&capture);
        assert_eq!(entry["severity"], "ERROR");
        assert_eq!(entry["httpRequest"]["status"], 500);
        assert_eq!(entry["message"], "GET /boom 500");
    }

    #[test]
    fn a_panicking_handler_is_logged_as_a_500_and_the_panic_propagates() {
        let router = Router::new()
            .route(
                "/explode",
                get(|| async {
                    if true {
                        panic!("handler exploded");
                    }
                    "unreachable"
                }),
            )
            .layer(RequestLogLayer::new(config()));

        let capture = Capture::run(cloud_layer, || {
            let mut svc = router;
            let req = Request::get("/explode").body(Body::empty()).unwrap();
            let mut fut = Box::pin(svc.call(req));
            // What tokio's task harness does with a task that panics: catch
            // the panic out of `poll`, *then* drop the future, no longer
            // unwinding — so the entry must be written during the unwind.
            let mut cx = Context::from_waker(Waker::noop());
            let payload = panic::catch_unwind(AssertUnwindSafe(|| fut.as_mut().poll(&mut cx)))
                .expect_err("the handler's panic propagates through the layer");
            assert_eq!(payload.downcast_ref::<&str>(), Some(&"handler exploded"));
            drop(fut);
        });

        // Exactly one entry, the 500, written before the drop.
        let entry = only_entry(&capture);
        assert_eq!(entry["severity"], "ERROR");
        assert_eq!(entry["httpRequest"]["status"], 500);
        assert_eq!(entry["message"], "GET /explode 500");
    }

    #[test]
    fn a_service_panicking_in_call_is_logged_as_a_500() {
        let mut svc = RequestLogLayer::new(config()).layer(tower::service_fn(
            |_req: Request<()>| -> std::future::Ready<Result<Response<()>, Infallible>> {
                panic!("call exploded")
            },
        ));

        let mut outcome = None;
        let capture = Capture::run(cloud_layer, || {
            let req = Request::get("/explode").body(()).unwrap();
            outcome = Some(panic::catch_unwind(AssertUnwindSafe(|| svc.call(req))));
        });

        assert!(outcome.unwrap().is_err(), "the panic propagates");
        let entry = only_entry(&capture);
        assert_eq!(entry["severity"], "ERROR");
        assert_eq!(entry["httpRequest"]["status"], 500);
    }

    #[test]
    fn a_dropped_response_future_is_logged_as_a_499_warning() {
        let router = Router::new()
            .route(
                "/slow",
                get(|| async {
                    tracing::info!(target: "app", "started");
                    std::future::pending::<&'static str>().await
                }),
            )
            .layer(RequestLogLayer::new(config()));

        let capture = Capture::run_with(cloud_layer, |capture| {
            let mut svc = router;
            let mut cx = Context::from_waker(Waker::noop());
            let req = Request::get("/slow")
                .header(REQUEST_ID_HEADER, "req-499")
                .body(Body::empty())
                .unwrap();
            let mut fut = Box::pin(svc.call(req));

            assert!(fut.as_mut().poll(&mut cx).is_pending());
            assert_eq!(
                capture.lines().len(),
                1,
                "only the handler's line before the drop: {:?}",
                capture.lines()
            );
            drop(fut);
        });

        let lines = golden_lines(&capture);
        assert_eq!(
            lines,
            [
                format!(
                    r#"{{"severity":"INFO","message":"started","logger":"app","timestamp":"{FIXED_TIMESTAMP}","requestId":"req-499"}}"#
                ),
                format!(
                    concat!(
                        r#"{{"severity":"WARNING","message":"GET /slow 499","logger":"stridelabs.request","#,
                        r#""timestamp":"{}","httpRequest":{{"requestMethod":"GET","requestUrl":"http://unknown/slow","#,
                        r#""status":499,"latency":"<latency>","protocol":"HTTP/1.1"}},"requestId":"req-499"}}"#,
                    ),
                    FIXED_TIMESTAMP
                ),
            ]
        );
    }

    #[test]
    fn an_unrelated_panic_dropping_a_pending_future_is_a_499() {
        let router = Router::new()
            .route("/slow", get(std::future::pending::<&'static str>))
            .layer(RequestLogLayer::new(config()));

        let capture = Capture::run(cloud_layer, || {
            let mut svc = router;
            let req = Request::get("/slow").body(Body::empty()).unwrap();
            let mut fut = Box::pin(svc.call(req));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(fut.as_mut().poll(&mut cx).is_pending());

            // Work that owns the in-flight request fails on its own; the
            // unwind drops the request's future. The request didn't panic.
            let outcome = panic::catch_unwind(AssertUnwindSafe(move || {
                let _in_flight = fut;
                panic!("unrelated failure");
            }));
            assert!(outcome.is_err());
        });

        let entry = only_entry(&capture);
        assert_eq!(entry["severity"], "WARNING");
        assert_eq!(entry["httpRequest"]["status"], 499);
    }

    #[test]
    fn handler_lines_inherit_the_request_id_and_trace() {
        let (capture, _) = drive(send(
            logged(config_with_project()),
            Request::get("/handled")
                .header("X-Cloud-Trace-Context", format!("{TRACE_ID}/1;o=1"))
                .header(REQUEST_ID_HEADER, "req-7"),
        ));

        let trace = format!("projects/{PROJECT}/traces/{TRACE_ID}");
        let lines = golden_lines(&capture);
        assert_eq!(
            lines,
            [
                // The handler span's own `user` field is not written; the
                // request span's two keys are.
                format!(
                    concat!(
                        r#"{{"severity":"INFO","message":"creating order","logger":"app","timestamp":"{}","#,
                        r#""requestId":"req-7","logging.googleapis.com/trace":"{}"}}"#,
                    ),
                    FIXED_TIMESTAMP, trace
                ),
                format!(
                    concat!(
                        r#"{{"severity":"INFO","message":"GET /handled 200","logger":"stridelabs.request","#,
                        r#""timestamp":"{}","httpRequest":{{"requestMethod":"GET","requestUrl":"http://unknown/handled","#,
                        r#""status":200,"latency":"<latency>","protocol":"HTTP/1.1"}},"#,
                        r#""requestId":"req-7","logging.googleapis.com/trace":"{}"}}"#,
                    ),
                    FIXED_TIMESTAMP, trace
                ),
            ]
        );
    }

    /// The request's two correlation keys on `line`, as written.
    fn ids(line: &Value) -> (Option<&str>, Option<&str>) {
        (
            line.get(REQUEST_ID_FIELD).and_then(Value::as_str),
            line.get(TRACE_FIELD).and_then(Value::as_str),
        )
    }

    /// A request carrying a fixed id and a parseable trace header.
    fn correlated(uri: &str) -> http::request::Builder {
        Request::get(uri)
            .header("X-Cloud-Trace-Context", format!("{TRACE_ID}/1;o=1"))
            .header(REQUEST_ID_HEADER, "req-7")
    }

    #[test]
    fn handler_lines_after_an_await_keep_the_ids() {
        let (capture, _) = drive(send(
            logged(config_with_project()),
            correlated("/suspended"),
        ));

        let trace = format!("projects/{PROJECT}/traces/{TRACE_ID}");
        let lines = capture.json_lines();
        let messages: Vec<&str> = lines
            .iter()
            .map(|line| line["message"].as_str().unwrap())
            .collect();
        assert_eq!(messages, ["before", "after", "GET /suspended 200"]);
        for line in &lines {
            assert_eq!(ids(line), (Some("req-7"), Some(trace.as_str())), "{line}");
        }
    }

    #[test]
    fn a_production_info_filter_keeps_the_ids() {
        use tracing_subscriber::{EnvFilter, Layer as _};

        // `init_logging`'s shape: the filter, then the output layer.
        let (capture, _) = drive_under(
            |writer| EnvFilter::new("info").and_then(cloud_layer(writer)),
            send(logged(config_with_project()), correlated("/filtered")),
        );

        let trace = format!("projects/{PROJECT}/traces/{TRACE_ID}");
        let lines = capture.json_lines();
        let messages: Vec<&str> = lines
            .iter()
            .map(|line| line["message"].as_str().unwrap())
            .collect();
        assert_eq!(messages, ["handled", "GET /filtered 200"], "the filter ran");
        for line in &lines {
            assert_eq!(ids(line), (Some("req-7"), Some(trace.as_str())), "{line}");
        }
    }

    #[test]
    fn spawned_work_carries_the_ids_only_when_the_span_is_attached() {
        let (capture, _) = drive(send(logged(config_with_project()), correlated("/spawned")));

        let trace = format!("projects/{PROJECT}/traces/{TRACE_ID}");
        let lines = capture.json_lines();
        let line = |message: &str| {
            lines
                .iter()
                .find(|line| line["message"] == message)
                .unwrap_or_else(|| panic!("no {message:?} line: {lines:?}"))
        };
        assert_eq!(
            ids(line("bare")),
            (None, None),
            "a bare spawn loses the span"
        );
        assert_eq!(
            ids(line("carried")),
            (Some("req-7"), Some(trace.as_str())),
            "the documented `.instrument(Span::current())` recipe"
        );
    }

    #[test]
    fn trace_header_variants_that_parse() {
        for (header, trace_id) in [
            (format!("{TRACE_ID};o=1"), TRACE_ID.to_owned()),
            (TRACE_ID.to_owned(), TRACE_ID.to_owned()),
            (
                TRACE_ID.to_ascii_uppercase() + "/42",
                TRACE_ID.to_ascii_uppercase(),
            ),
        ] {
            let (capture, _) = drive(send(
                logged(config_with_project()),
                Request::get("/orders").header("X-Cloud-Trace-Context", &header),
            ));

            assert_eq!(
                only_entry(&capture)[TRACE_FIELD],
                format!("projects/{PROJECT}/traces/{trace_id}"),
                "{header:?}"
            );
        }
    }

    #[test]
    fn no_trace_key_without_a_project_or_with_a_malformed_header() {
        let valid = format!("{TRACE_ID}/1;o=1");
        let cases = [
            (config(), valid.clone()),
            (config_with_project().with_project_id(None), valid.clone()),
            (config_with_project(), TRACE_ID[..31].to_owned()),
            (config_with_project(), format!("{TRACE_ID}0")),
            (config_with_project(), format!("{}g/1", &TRACE_ID[..31])),
            (config_with_project(), String::new()),
            (config_with_project(), "/1;o=1".to_owned()),
        ];
        for (config, header) in cases {
            let (capture, _) = drive(send(
                logged(config),
                Request::get("/handled").header("X-Cloud-Trace-Context", &header),
            ));

            let lines = capture.json_lines();
            assert_eq!(lines.len(), 2, "{header:?}");
            for line in lines {
                assert!(line.get(TRACE_FIELD).is_none(), "{header:?}: {line}");
                assert!(line.get(REQUEST_ID_FIELD).is_some(), "{header:?}: {line}");
            }
        }
    }

    #[test]
    fn sensitive_query_values_are_redacted_and_the_rest_kept() {
        let (capture, _) = drive(send(
            logged(config()),
            Request::get(
                "/orders?token=tok-secret&page=2&API%5FKEY=k-secret&Key=x-secret&password&q=token&a+b=1",
            ),
        ));

        let entry = only_entry(&capture);
        assert_eq!(
            entry["httpRequest"]["requestUrl"],
            "http://unknown/orders?token=REDACTED&page=2&API%5FKEY=REDACTED&Key=REDACTED&password&q=token&a+b=1"
        );
        assert_eq!(
            entry["message"], "GET /orders 200",
            "no query in the message"
        );
        for line in capture.lines() {
            assert!(!line.contains("-secret"), "{line}");
        }
    }

    #[test]
    fn redacted_parameters_are_configurable() {
        // Configured in mixed case: matching is case-insensitive both ways.
        let config = config().with_redacted_query_params(
            DEFAULT_REDACTED_QUERY_PARAMS.iter().copied().chain(["Sig"]),
        );
        let (capture, _) = drive(send(
            logged(config),
            Request::get("/orders?sig=s-secret&token=t-secret&page=2"),
        ));

        assert_eq!(
            only_entry(&capture)["httpRequest"]["requestUrl"],
            "http://unknown/orders?sig=REDACTED&token=REDACTED&page=2"
        );
    }

    #[test]
    fn skip_paths_emit_nothing() {
        let config = config().with_skip_paths(["/health/live"]);

        let (capture, res) = drive(send(logged(config.clone()), Request::get("/health/live")));
        assert_eq!(res.status(), StatusCode::OK);
        // The handler's own line is all there is, carrying no request id:
        // the layer opened no span.
        assert_eq!(
            capture.lines(),
            [format!(
                r#"{{"severity":"INFO","message":"probe","logger":"app","timestamp":"{FIXED_TIMESTAMP}"}}"#
            )]
        );

        // Exact match only: neither a longer nor a shorter path is skipped.
        for path in ["/health/live/", "/health"] {
            let (capture, _) = drive(send(logged(config.clone()), Request::get(path)));
            assert_eq!(entries(&capture).len(), 1, "{path}");
        }
    }

    #[test]
    fn no_response_header_is_added() {
        let request = || {
            Request::get("/orders")
                .header(REQUEST_ID_HEADER, "req-1")
                .header("X-Cloud-Trace-Context", TRACE_ID)
        };
        let (_, bare) = drive(send(app(), request()));
        let (capture, with_layer) = drive(send(logged(config_with_project()), request()));

        assert_eq!(entries(&capture).len(), 1, "the layer ran");
        assert_eq!(with_layer.headers(), bare.headers());
        assert!(with_layer.headers().get(REQUEST_ID_HEADER).is_none());
    }

    #[test]
    fn credentials_and_bodies_never_reach_a_line() {
        let router = Router::new()
            .route(
                "/login",
                axum::routing::post(|body: String| async move {
                    tracing::info!(target: "app", bytes = body.len(), "login attempt");
                    StatusCode::UNAUTHORIZED
                }),
            )
            .layer(RequestLogLayer::new(config_with_project()));
        let req = Request::post("/login")
            .header("Authorization", "Bearer secret-value")
            .header("Cookie", "session=secret-value")
            .header("X-Api-Key", "secret-value")
            .header("Proxy-Authorization", "Basic secret-value")
            .body(Body::from("password=secret-value"))
            .unwrap();

        let (capture, res) = drive(router.oneshot(req));

        assert_eq!(res.unwrap().status(), StatusCode::UNAUTHORIZED);
        let lines = capture.lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        for line in lines {
            assert!(!line.contains("secret-value"), "{line}");
        }
    }

    #[test]
    fn logged_request_id_is_the_echoed_one_with_request_id_layer_inside() {
        let router = Router::new()
            .route(
                "/",
                get(|Extension(RequestId(id)): Extension<RequestId>| async move { id }),
            )
            .layer(RequestIdLayer)
            .layer(RequestLogLayer::new(config()));

        let invalid = "has space";
        for incoming in [None, Some("client-id-1"), Some(invalid)] {
            let mut req = Request::get("/");
            if let Some(id) = incoming {
                req = req.header(REQUEST_ID_HEADER, HeaderValue::from_static(id));
            }
            let (capture, (echoed, seen)) = drive(async {
                let res = send(router.clone(), req).await;
                let echoed = res.headers()[REQUEST_ID_HEADER]
                    .to_str()
                    .unwrap()
                    .to_owned();
                let body = axum::body::to_bytes(res.into_body(), usize::MAX)
                    .await
                    .unwrap();
                (echoed, String::from_utf8(body.to_vec()).unwrap())
            });

            let logged = only_entry(&capture)[REQUEST_ID_FIELD]
                .as_str()
                .unwrap()
                .to_owned();
            assert_eq!(logged, echoed, "{incoming:?}");
            assert_eq!(seen, echoed, "the handler's extension, {incoming:?}");
            match incoming {
                Some(id) if id != invalid => assert_eq!(logged, id),
                _ => {
                    assert_eq!(logged.len(), 32, "{incoming:?}: {logged}");
                    assert!(logged.bytes().all(|b| b.is_ascii_hexdigit()), "{logged}");
                }
            }
        }
    }

    #[test]
    fn an_existing_request_id_extension_is_reused() {
        let mut req = Request::get("/orders")
            .header(REQUEST_ID_HEADER, "from-header")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(RequestId("from-outer-layer".to_owned()));

        let (capture, _) = drive(logged(config()).oneshot(req));

        assert_eq!(only_entry(&capture)[REQUEST_ID_FIELD], "from-outer-layer");
    }

    #[test]
    fn remote_ip_is_the_last_forwarded_entry_then_x_real_ip() {
        let cases: [(Headers, Option<&str>); 6] = [
            (
                &[(X_FORWARDED_FOR, "198.51.100.1, 203.0.113.7")],
                Some("203.0.113.7"),
            ),
            (
                &[
                    (X_FORWARDED_FOR, "198.51.100.1"),
                    (X_FORWARDED_FOR, "10.0.0.1,203.0.113.9 "),
                ],
                Some("203.0.113.9"),
            ),
            (
                &[(X_FORWARDED_FOR, "203.0.113.7"), (X_REAL_IP, "192.0.2.1")],
                Some("203.0.113.7"),
            ),
            (
                &[
                    (X_FORWARDED_FOR, "198.51.100.1, "),
                    (X_REAL_IP, "192.0.2.1"),
                ],
                Some("192.0.2.1"),
            ),
            (&[(X_REAL_IP, "192.0.2.1")], Some("192.0.2.1")),
            (&[], None),
        ];
        for (headers, expected) in cases {
            let (capture, _) = drive(send(logged(config()), get_with_headers("/orders", headers)));

            let entry = only_entry(&capture);
            assert_eq!(
                entry["httpRequest"].get("remoteIp").and_then(Value::as_str),
                expected,
                "{headers:?}"
            );
        }
    }

    #[cfg(feature = "axum")]
    #[test]
    fn remote_ip_falls_back_to_the_peer_address() {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let peer = SocketAddr::from(([192, 0, 2, 10], 4242));
        let cases: [(Headers, &str); 2] = [
            (&[], "192.0.2.10"),
            (&[(X_FORWARDED_FOR, "203.0.113.7")], "203.0.113.7"),
        ];
        for (headers, expected) in cases {
            let mut req = get_with_headers("/orders", headers)
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));

            let (capture, _) = drive(logged(config()).oneshot(req));

            assert_eq!(
                only_entry(&capture)["httpRequest"]["remoteIp"],
                expected,
                "{headers:?}"
            );
        }
    }

    #[test]
    fn request_url_uses_the_forwarded_scheme_and_the_host() {
        let cases: [(Headers, &str, &str); 4] = [
            (
                &[
                    (X_FORWARDED_PROTO, "https, http"),
                    ("host", "api.example.com"),
                ],
                "/orders?page=2",
                "https://api.example.com/orders?page=2",
            ),
            (
                &[(X_FORWARDED_PROTO, " "), ("host", "api.example.com:8443")],
                "/orders",
                "http://api.example.com:8443/orders",
            ),
            // An absolute-form (or HTTP/2) request carries scheme and host
            // in the URI.
            (
                &[],
                "https://h2.example.com/orders?",
                "https://h2.example.com/orders",
            ),
            (&[], "/orders", "http://unknown/orders"),
        ];
        for (headers, uri, expected) in cases {
            let (capture, _) = drive(send(logged(config()), get_with_headers(uri, headers)));

            assert_eq!(
                only_entry(&capture)["httpRequest"]["requestUrl"],
                expected,
                "{uri}"
            );
        }
    }

    #[test]
    fn query_names_match_after_unicode_lowercasing() {
        // `%E2%84%AA` is U+212A KELVIN SIGN, which lowercases to an ASCII
        // `k`: Python's `.lower()` redacts `to\u{212A}en` as `token`.
        let (capture, _) = drive(send(
            logged(config()),
            Request::get("/orders?to%E2%84%AAen=k-secret&TOKEN=u-secret&page=2"),
        ));

        assert_eq!(
            only_entry(&capture)["httpRequest"]["requestUrl"],
            "http://unknown/orders?to%E2%84%AAen=REDACTED&TOKEN=REDACTED&page=2"
        );
        for line in capture.lines() {
            assert!(!line.contains("-secret"), "{line}");
        }
    }

    #[test]
    fn request_url_never_carries_userinfo_or_suspect_host_text() {
        let cases: [(Headers, &str, &str); 9] = [
            (
                &[],
                "https://alice:secret@example.com/orders",
                "https://example.com/orders",
            ),
            (
                &[("host", "alice:secret@api.example.com:8443")],
                "/orders",
                "http://api.example.com:8443/orders",
            ),
            (
                &[("host", "a@b:secret@api.example.com")],
                "/orders",
                "http://api.example.com/orders",
            ),
            (
                &[("host", "evil.example?token=secret")],
                "/orders",
                "http://unknown/orders",
            ),
            (
                &[("host", "evil.example#secret")],
                "/orders",
                "http://unknown/orders",
            ),
            (
                &[("host", "evil.example secret")],
                "/orders",
                "http://unknown/orders",
            ),
            (
                &[("host", "evil.example\tsecret")],
                "/orders",
                "http://unknown/orders",
            ),
            (
                &[("host", "evil.example/secret")],
                "/orders",
                "http://unknown/orders",
            ),
            // A rejected `Host` falls back to the URI's authority.
            (
                &[("host", "secret?x")],
                "https://good.example/orders",
                "https://good.example/orders",
            ),
        ];
        for (headers, uri, expected) in cases {
            let (capture, _) = drive(send(logged(config()), get_with_headers(uri, headers)));

            assert_eq!(
                only_entry(&capture)["httpRequest"]["requestUrl"],
                expected,
                "{headers:?} {uri}"
            );
            for line in capture.lines() {
                assert!(!line.contains("secret"), "{headers:?} {uri}: {line}");
            }
        }
    }

    #[test]
    fn only_http_or_https_is_taken_from_x_forwarded_proto() {
        let cases: [(&str, &str); 6] = [
            ("HTTPS", "https://api.example.com/orders"),
            (" http , https", "http://api.example.com/orders"),
            ("javascript", "http://api.example.com/orders"),
            (
                "https://evil.example/?token=secret",
                "http://api.example.com/orders",
            ),
            ("ftp, https", "http://api.example.com/orders"),
            ("", "http://api.example.com/orders"),
        ];
        for (proto, expected) in cases {
            let (capture, _) = drive(send(
                logged(config()),
                Request::get("/orders")
                    .header(HOST, "api.example.com")
                    .header(X_FORWARDED_PROTO, proto),
            ));

            assert_eq!(
                only_entry(&capture)["httpRequest"]["requestUrl"],
                expected,
                "{proto:?}"
            );
            for line in capture.lines() {
                assert!(!line.contains("evil"), "{proto:?}: {line}");
            }
        }
    }

    #[test]
    fn protocol_is_spelled_as_cloud_logging_expects() {
        for (version, expected) in [
            (Version::HTTP_10, "HTTP/1.0"),
            (Version::HTTP_11, "HTTP/1.1"),
            (Version::HTTP_2, "HTTP/2"),
        ] {
            let (capture, _) = drive(send(
                logged(config()),
                Request::get("/orders").version(version),
            ));

            assert_eq!(
                only_entry(&capture)["httpRequest"]["protocol"],
                expected,
                "{version:?}"
            );
        }
    }

    #[test]
    fn latency_has_millisecond_precision_and_a_seconds_suffix() {
        assert_eq!(format_latency(Duration::from_millis(123)), "0.123s");
        assert_eq!(format_latency(Duration::from_micros(1_500_400)), "1.500s");
        assert_eq!(format_latency(Duration::ZERO), "0.000s");
    }

    #[test]
    fn project_comes_from_google_cloud_project_then_google_project_id() {
        let project = |vars: Headers| {
            RequestLogConfig::from_lookup(|name| {
                vars.iter()
                    .find(|(var, _)| *var == name)
                    .map(|(_, value)| (*value).to_owned())
            })
            .project_id
        };

        assert_eq!(
            project(&[("GOOGLE_CLOUD_PROJECT", "a"), ("GOOGLE_PROJECT_ID", "b")]),
            Some("a".to_owned())
        );
        assert_eq!(project(&[("GOOGLE_PROJECT_ID", "b")]), Some("b".to_owned()));
        assert_eq!(
            project(&[("GOOGLE_CLOUD_PROJECT", ""), ("GOOGLE_PROJECT_ID", "b")]),
            Some("b".to_owned()),
            "empty counts as unset"
        );
        assert_eq!(project(&[]), None);
        assert_eq!(
            config().with_project_id(Some(String::new())).project_id,
            None
        );
    }

    #[test]
    fn defaults_skip_nothing_and_redact_pythons_list() {
        let config = config();
        assert!(config.skip_paths.is_empty());
        // Python `stridelabs-logging`'s `_REDACTED_QUERY_PARAMS`, spelled out
        // rather than compared to the constant, which would pass any list.
        assert_eq!(
            config.redacted_query_params,
            [
                "token",
                "access_token",
                "refresh_token",
                "id_token",
                "client_secret",
                "api_key",
                "apikey",
                "password",
                "secret",
                "key",
            ]
        );
    }

    #[test]
    fn query_names_are_form_decoded_before_matching() {
        assert_eq!(decode_query_component("api%5Fkey"), b"api_key");
        assert_eq!(decode_query_component("a+b%2"), b"a b%2");
        assert_eq!(decode_query_component("%zz%4"), b"%zz%4");
        assert_eq!(decode_query_component("%E2%82%AC"), "€".as_bytes());
    }
}
