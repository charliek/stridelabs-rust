# stridelabs-observability

`tracing` subscriber setup, a real `tower` request-id layer, and (behind a
feature) Prometheus recorder wiring, for StrideLabs services. Extracted from
limen's `observability` module.

## Feature topology

`default = []`. One optional feature:

| Feature | Default | Adds |
|---|---|---|
| `prometheus` | off | `metrics` + `metrics-exporter-prometheus`: recorder installation, `status_class`, `DURATION_BUCKETS` |

`logging` and `request_id` have no feature gate — every consumer wants
tracing and a request id, so gating them would only add friction. Most
services don't render `/metrics`, so `prometheus` stays off by default and
its dependencies (`metrics`, `metrics-exporter-prometheus`) aren't pulled in
unless asked for.

## Adding the dependency

```toml
[dependencies]
stridelabs-observability = { git = "ssh://git@github.com/charliek/stridelabs-rust.git", tag = "v0.1.0" }

# with Prometheus wiring:
stridelabs-observability = { git = "ssh://git@github.com/charliek/stridelabs-rust.git", tag = "v0.1.0", features = ["prometheus"] }
```

(During development against an unreleased commit, pin `rev = "<sha>"`
instead of `tag`; see the workspace root README for the local `[patch]`
co-development snippet.)

## `logging` — tracing subscriber setup

```rust
use stridelabs_observability::{init_logging, LogFormat};

// Read the format from your own config however you like — this crate
// doesn't hard-code an env var name.
let format = if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
    LogFormat::Json
} else {
    LogFormat::Text
};

init_logging(format, "info");
```

`init_logging(format, default_filter)`:

- Filter: `RUST_LOG` if set, else `default_filter` — pass your own
  service-specific fallback string (e.g. spendwise-rs keeps its current
  fallback string unchanged at adoption; this crate doesn't own that
  string).
- Format: `LogFormat::Text` (human-readable) or `LogFormat::Json`
  (line-delimited, for production log aggregation) — a plain parameter, not
  an env var read inside the function, so callers control how the format is
  sourced.
- Idempotent: only the first call in a process installs the global
  subscriber (`tracing_subscriber`'s global subscriber can only be set
  once); later calls, even with different arguments, are a silent no-op.
  Safe to call from every integration test's setup.

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

- Reuses the inbound `x-request-id` header if it is non-empty, at most 128
  bytes, and entirely ASCII-graphic; otherwise generates a fresh id (32
  lowercase hex characters from two random `u64`s).
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

- `install()` sets the global Prometheus recorder once (`OnceLock`-memoized)
  and applies `DURATION_BUCKETS` to every metric whose name ends in
  `duration_seconds` (the house naming convention for a duration histogram,
  e.g. `http_request_duration_seconds`). Safe to call from multiple places;
  every call returns a clone of the same handle. It returns
  `Result<_, PrometheusInstallError>` rather than panicking: `OnceLock` only
  serializes this crate's own callers, so a host that installed its own
  recorder first is a real condition a library should report, not abort on.
- `status_class(u16) -> &'static str` buckets a numeric status code into
  `"1xx"`..`"5xx"` (or `"other"` outside that range) — keeps label
  cardinality low (a handful of values, not hundreds of codes) when used as
  a metric label.
- `DURATION_BUCKETS` is exported so a consumer's own duration histograms can
  reuse the same boundaries even outside the `duration_seconds`-suffix
  convention `install()` applies automatically.

**Not ported from limen:** the domain-specific metric wrappers
(`record_request`, the `InFlight` RAII gauge guard, shadow-traffic and
circuit-breaker gauges, …). Those are bound to limen's shadow-proxy domain
and its specific metric names — not a generic primitive. A consumer defines
its own metric names and emits through the `metrics` facade directly
(`counter!`, `histogram!`, `gauge!`); this module only owns recorder
installation and the `status_class`/`DURATION_BUCKETS` conventions.

[`tower::Layer`]: https://docs.rs/tower/latest/tower/trait.Layer.html
