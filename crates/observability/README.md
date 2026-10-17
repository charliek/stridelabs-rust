# stridelabs-observability

`tracing` subscriber setup (human-readable text, tracing-subscriber JSON, or
Google Cloud Logging structured lines), real `tower` request-logging and
request-id layers, and (behind a feature) Prometheus recorder wiring, for
StrideLabs services.

A new service's default is two lines — Cloud Logging lines everywhere but
development, and the request-logging layer outermost:

```rust
init_logging(LogFormat::from_environment(&env_or("ENVIRONMENT", "development")), "info");
// ...
let app = router.layer(RequestLogLayer::new(RequestLogConfig::from_env()));
```

## Feature topology

`default = []`. Two optional features:

| Feature | Default | Adds |
|---|---|---|
| `prometheus` | off | `metrics` + `metrics-exporter-prometheus`: recorder installation, `status_class`, `DURATION_BUCKETS` |
| `axum` | off | `axum` itself: `RequestLogLayer` falls back to the connection's peer address for `remoteIp` |

`logging`, `cloud`, `request_log` and `request_id` have no feature gate —
every consumer wants tracing, request logs and a request id, so gating them
would only add friction. Most services don't render `/metrics`, so
`prometheus` stays off by default and its dependencies (`metrics`,
`metrics-exporter-prometheus`) aren't pulled in unless asked for.

`axum` exists because a peer address reaches an `http::Request` only as
axum's `ConnectInfo<SocketAddr>` extension (set by
`into_make_service_with_connect_info`), and reading a typed extension means
naming its type. Every layer here is otherwise plain `tower`/`http`. Behind
Cloud Run (or any proxy) `X-Forwarded-For` always carries the client, so the
fallback only matters for a service exposed directly; turning the feature on
in a service that already uses axum adds nothing to its graph beyond axum's
default features.

## Adding the dependency

Pin the tag:

```toml
[dependencies]
stridelabs-observability = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.7.0" }

# with Prometheus wiring:
stridelabs-observability = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.7.0", features = ["prometheus"] }

# with the peer-address fallback for request logs (and Prometheus wiring):
stridelabs-observability = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.7.0", features = ["axum", "prometheus"] }
```

(During development against an unreleased commit, pin `rev = "<sha>"` instead
of `tag`.) See the workspace root README for the local `[patch]`
co-development snippet.

## `logging` — tracing subscriber setup

```rust
use stridelabs_config::env_or;
use stridelabs_observability::{init_logging, LogFormat};

// Text in development, Cloud Logging lines everywhere else. Read the
// environment name from your own config — this crate reads no env var for
// the format.
init_logging(LogFormat::from_environment(&env_or("ENVIRONMENT", "development")), "info");
```

`init_logging(format, default_filter)`:

- Filter: `RUST_LOG` if set, else `default_filter` — pass your own
  service-specific fallback string (an adopting service keeps its existing
  fallback string unchanged; this crate doesn't own that string).
- Format — a plain parameter, not an env var read inside the function, so
  callers control how it is sourced:
  - `LogFormat::Text`: human-readable, for a terminal.
  - `LogFormat::Json`: tracing-subscriber's line-delimited JSON,
    `{timestamp, level, fields: {message, …}, target}` plus `span`/`spans`
    for an event inside a span. Unchanged from earlier releases; nothing in
    it is Cloud Logging-specific.
  - `LogFormat::Cloud`: one Google Cloud Logging structured object per line
    (see [`cloud`](#cloud--google-cloud-logging-lines) below). What a
    deployed service wants.
- `LogFormat::from_environment(env)` is `Text` for exactly `"development"`
  and `Cloud` for anything else, compared exactly (no trimming or case
  folding) — Python `stridelabs-logging`'s `ENVIRONMENT != "development"`
  rule, so a mistyped value fails toward structured lines.
- `LogFormat` is `#[non_exhaustive]`: a `match` on it needs a wildcard arm.
- Idempotent: only the first call in a process installs the global
  subscriber (`tracing_subscriber`'s global subscriber can only be set
  once); later calls, even with different arguments, are a silent no-op.
  Safe to call from every integration test's setup.

## `cloud` — Google Cloud Logging lines

`LogFormat::Cloud` installs `CloudLayer`, which writes the shape Python
`stridelabs-logging`'s `CloudLoggingFormatter` writes, so Python and Rust
services read the same in the Cloud console:

| key | value |
|---|---|
| `severity` | `TRACE`/`DEBUG` → `DEBUG`, `INFO` → `INFO`, `WARN` → `WARNING`, `ERROR` → `ERROR` |
| `message` | the event's message, top level (`""` when it has none) |
| `logger` | the event's target |
| `timestamp` | RFC 3339, UTC |
| `httpRequest` | an object assembled from the event's `httpRequest.*` fields |
| `requestId`, `logging.googleapis.com/trace` | lifted from the enclosing request span |
| anything else | the event's other fields, flattened at top level |

Core keys always come from the event itself, so no field can forge a
severity; inside a request span its id beats an event's own `requestId`.
`CloudLayer` is public for composing your own subscriber
(`registry().with(filter).with(CloudLayer::new(std::io::stdout))`).

**The request-span contract.** Any span declaring a field named
`REQUEST_ID_FIELD` (`requestId`) or `TRACE_FIELD`
(`logging.googleapis.com/trace`) supplies that key to every event inside
it, however deeply nested; the nearest span that has recorded a key wins.
`RequestLogLayer` opens exactly such a span (named `REQUEST_SPAN_NAME`,
`request`) around every request, so you rarely open one yourself — but a
background job can, to correlate its own lines:

```rust
use stridelabs_observability::{REQUEST_ID_FIELD, REQUEST_SPAN_NAME, TRACE_FIELD};

let span = tracing::info_span!(
    REQUEST_SPAN_NAME,
    { REQUEST_ID_FIELD } = %job_id,
    { TRACE_FIELD } = trace.as_deref(), // `None` writes no trace key
);
```

Record the values with `%` or as a `&str`. A span the subscriber's filter
disables is never created, so the lines inside it lose their ids: keep the
filter at `info` or below for this crate.

## `request_log` — one request entry per request

```rust
use axum::{routing::get, Router};
use stridelabs_observability::{RequestIdLayer, RequestLogConfig, RequestLogLayer};

let app: Router = Router::new()
    .route("/", get(|| async { "ok" }))
    .route("/health/live", get(|| async { "ok" }))
    // ...every other layer (CORS, security headers, auth) goes here...
    .layer(RequestIdLayer) // optional: echo `x-request-id` on responses
    .layer(RequestLogLayer::new(
        RequestLogConfig::from_env().with_skip_paths(["/health/live"]),
    )); // LAST, so it is the OUTERMOST layer
```

**Make it the outermost layer** (in axum, the last `.layer(..)` call). A
layer sees only what reaches it: outermost, it logs the status the client
actually got, including requests an inner layer answers on its own (a CORS
preflight or refusal, an auth rejection).

For every request that isn't skipped it:

1. **Establishes the request id**: an existing `RequestId` extension, else
   a valid incoming `x-request-id` (`RequestIdLayer`'s rule), else 32 fresh
   hex characters; inserted as the `RequestId` extension. It **never writes
   a response header** — add `RequestIdLayer` *inside* it to echo the id,
   which then reuses this one, so the echoed header and the logged
   `requestId` are always the same value.
2. **Opens the request span** with `requestId` and, when a project is
   configured and `X-Cloud-Trace-Context: TRACE_ID[/SPAN_ID][;o=…]` carries
   a 32-hex-digit trace id, `logging.googleapis.com/trace` =
   `projects/{project}/traces/{TRACE_ID}` (no trace key otherwise). The
   inner service's `call` and every poll of its response future run inside
   it, so lines the handler's future logs — before and after each `.await`
   — carry both keys. A streamed body and spawned tasks don't; see
   [what inherits the span](#what-inherits-the-span).
3. **Writes one event** on target `stridelabs.request`
   (`REQUEST_LOG_TARGET`, Python's logger name) when the inner service's
   response future completes: message `"METHOD PATH STATUS"`, and `httpRequest.{requestMethod,
   requestUrl, status, latency, protocol, userAgent, remoteIp}`. Under
   `LogFormat::Cloud`:

   ```json
   {"severity":"INFO","message":"GET /orders 200","logger":"stridelabs.request","timestamp":"…","httpRequest":{"requestMethod":"GET","requestUrl":"https://api.example.com/orders?page=2","status":200,"latency":"0.012s","protocol":"HTTP/1.1","userAgent":"curl/8.4.0","remoteIp":"203.0.113.7"},"requestId":"4bf92f3577b34da6a3ce929d0e0e4736","logging.googleapis.com/trace":"projects/my-project/traces/105445aa7843bc8bf206b12000100000"}
   ```

| how the request ended | `status` | level |
|---|---|---|
| a response | its status | `ERROR` ≥ 500, `WARN` ≥ 400, else `INFO` |
| the inner service returned `Err` (propagated unchanged) | 500 | `ERROR` |
| the inner service panicked (the panic propagates unchanged) | 500 | `ERROR` |
| the response future was dropped first (client abort, shutdown drain, or an unrelated panic unwinding through its owner) | 499 | `WARN` |

The entry is written when the response *head* is ready — the layer wraps
the response future, never the body, and leaves the response type
unchanged. So `latency` runs from the layer receiving the request to the
head being ready: for a streamed body (server-sent events) it ends before
the first body byte is produced, let alone sent, and a disconnect
mid-stream is not a 499 (the head's status was already logged).

### What inherits the span

Exactly the code that runs inside the response future: the inner service's
`call`, and the handler's future on every poll. Two kinds of request work
run outside it and lose `requestId` and the trace:

- **a streamed response body**, polled by the server after the head is
  returned (an SSE stream, a chunked download);
- **anything `tokio::spawn`ed** (or handed to another task).

Carry the correlation in by capturing the span inside the handler and
attaching it:

```rust
use tracing::Instrument;

let span = tracing::Span::current(); // inside the handler: the request span
tokio::spawn(background_work().instrument(span.clone()));
// in a streamed body: `.instrument(span.clone())` the future producing each
// chunk, or `span.in_scope(|| …)` around synchronous chunk work.
```

Fields:

- `requestUrl`: scheme, host, then the raw path and query with the values
  of sensitive query parameters replaced by `REDACTED`. The scheme and host
  are client-written text outside the query, so neither is copied blindly:
  - scheme: the first `X-Forwarded-Proto` entry only if it is `http` or
    `https` (any case; anything else counts as no header), else the URI's
    scheme, else `http`;
  - host: `Host`, else the URI's authority, each with any userinfo
    (`alice:secret@`) removed and used only if what's left is a plausible
    `host[:port]` — printable ASCII with no `/`, `?`, `#` or `\` — else the
    placeholder `unknown`.
- `latency`: seconds to three decimals, `"0.123s"`.
- `protocol`: `HTTP/1.0`, `HTTP/1.1`, `HTTP/2`, `HTTP/3`.
- `remoteIp`: the last `X-Forwarded-For` entry (Google's front end appends
  the real client to whatever the client sent, so only the last is
  trustworthy), else `X-Real-IP`, else — with the `axum` feature and a
  server built with `into_make_service_with_connect_info::<SocketAddr>()` —
  the peer address. For forensics, never for auth decisions.

**Never logged:** request bodies, and request headers other than
`User-Agent` — so never `Authorization`, cookies or API keys. `Host`,
`X-Forwarded-Proto`, `X-Forwarded-For` and `X-Real-IP` are read only to
build `requestUrl` and `remoteIp`. The message's path never includes the
query string.

`RequestLogConfig`:

| setting | default | |
|---|---|---|
| `with_skip_paths(paths)` | none | exact raw-path matches that bypass the layer entirely: no id, no span, no entry (meant for health probes) |
| `with_project_id(Option<String>)` | `GOOGLE_CLOUD_PROJECT`, else `GOOGLE_PROJECT_ID` (empty = unset) | `None` turns trace correlation off |
| `with_redacted_query_params(names)` | `DEFAULT_REDACTED_QUERY_PARAMS`: `token`, `access_token`, `refresh_token`, `id_token`, `client_secret`, `api_key`, `apikey`, `password`, `secret`, `key` | matched after percent-decoding the name, Unicode-lowercased as Python's `.lower()` is (`TOKEN`, `%74oken`, `to%E2%84%AAen` all redact); replaces the list, so chain onto the default to extend it |

`RequestLogConfig::from_env()` reads the project from the process
environment; `RequestLogConfig::from_lookup(|name| …)` takes any lookup, so
tests never mutate process env.

**Filtering.** The entry's target (`stridelabs.request`) is separate from
the span's (`stridelabs_observability::request_log`), so
`RUST_LOG=info,stridelabs.request=warn` drops successful-request entries
while handler lines keep their ids. The span itself is `INFO`: a filter
stricter than `info` for this crate disables it, and every line of the
request loses its ids.

## `request_id` — a real tower layer

```rust
use axum::{routing::get, Router};
use stridelabs_observability::RequestIdLayer;

let app: Router = Router::new()
    .route("/", get(|| async { "ok" }))
    .layer(RequestIdLayer);
```

`RequestIdLayer` is a plain [`tower::Layer`] built on `tower`/`http` directly
(not `axum`), so it works with any `http::Request`/`http::Response`-based
service — axum's `Router` is one such service, since axum re-exports the
same `http` crate types. No `tokio` dependency beyond what `tower` itself
needs; nothing here assumes a particular async runtime.

Behavior:

- Reuses an existing `RequestId` extension — the one an outer
  `RequestLogLayer` established — so the echoed id is the logged id.
- Otherwise reuses the inbound `x-request-id` header if it is non-empty, at
  most 128 bytes, and entirely ASCII-graphic; otherwise generates a fresh id
  (32 lowercase hex characters from two random `u64`s). An extension is held
  to the same rule, and one that fails it is replaced.
- Inserts the resolved id into the request's extensions as `RequestId(pub
  String)`, so downstream handlers/middleware can read it (e.g. to attach to
  a log span, or forward to an upstream call).
- Echoes the resolved id on the `x-request-id` response header —
  **including error responses**: the layer wraps the whole inner
  `Service::call` future, not a success-only branch, so a 500 gets the
  header too.

`REQUEST_ID_HEADER` is exported as the header name constant (`"x-request-id"`)
in case a caller needs to reference it directly (e.g. when forwarding it to
an upstream in a proxy).

## `prometheus` feature — recorder + conventions

```rust
use stridelabs_observability::{install, status_class, DURATION_BUCKETS};

// Idempotent; call again anywhere to get the same handle. Errs only if
// something outside this crate already installed a global recorder.
let handle = install()?;
// axum: .route("/metrics", get(move || async move { handle.render() }))

let class = status_class(response_status.as_u16()); // "2xx", "4xx", ...
```

- `install()` sets the global Prometheus recorder once and applies
  `DURATION_BUCKETS` to every metric whose name ends in `duration_seconds`
  (the house naming convention for a duration histogram, e.g.
  `http_request_duration_seconds`). Safe to call from multiple places and
  from several threads at once (the first install is serialized); every call
  returns a clone of the same handle. It returns
  `Result<_, PrometheusInstallError>` rather than panicking: only this crate's
  own callers are serialized, so a host that installed its own recorder first
  is a real condition a library should report, not abort on.
- `status_class(u16) -> &'static str` buckets a numeric status code into
  `"1xx"`..`"5xx"` (or `"other"` outside that range) — keeps label
  cardinality low (a handful of values, not hundreds of codes) when used as
  a metric label.
- `DURATION_BUCKETS` is exported so a consumer's own duration histograms can
  reuse the same boundaries even outside the `duration_seconds`-suffix
  convention `install()` applies automatically.

**Deliberately not extracted:** the domain-specific metric wrappers
(`record_request`, the `InFlight` RAII gauge guard, shadow-traffic and
circuit-breaker gauges, …). Those are bound to the originating service's own proxy
domain and its specific metric names — not a generic primitive. A consumer defines
its own metric names and emits through the `metrics` facade directly
(`counter!`, `histogram!`, `gauge!`); this module only owns recorder
installation and the `status_class`/`DURATION_BUCKETS` conventions.

[`tower::Layer`]: https://docs.rs/tower/latest/tower/trait.Layer.html
