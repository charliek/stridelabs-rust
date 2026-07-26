# stridelabs-http

The house `AppError` → HTTP convention, a security-headers layer, an
explicit-origin CORS builder, graceful-shutdown primitives, and the
mechanical layer of a reverse proxy, for StrideLabs axum services. Extracted
from spendwise-rs's `error.rs` and limen's `http/`.

## Feature topology

`default = []`. `error`, `headers` and `shutdown` are unconditional — every
axum service wants all three, so gating them would only add friction.

| Feature | Default | Adds |
|---|---|---|
| `cors` | off | `cors_layer`, via `tower-http/cors` |
| `proxy` | off | the `proxy` module, via `reqwest`/`url`/`bytes`/`futures` |

`proxy` is the gate that matters: it pulls in an HTTP *client* and a TLS
stack. A service that only answers requests should never compile that, which
is why the proxy primitives live behind a feature instead of in a crate
everyone already depends on.

`tokio` is a **non-optional** dependency (`signal`, `sync`, `macros`) because
`shutdown` is signal/watch machinery. A service with no tokio in its graph
has no server to shut down gracefully, so gating it would buy nobody a leaner
build.

## Adding the dependency

```toml
[dependencies]
stridelabs-http = { git = "ssh://git@github.com/charliek/stridelabs-rust.git", tag = "v0.1.0" }

# with the CORS layer builder:
stridelabs-http = { git = "ssh://git@github.com/charliek/stridelabs-rust.git", tag = "v0.1.0", features = ["cors"] }

# for a service that proxies to an upstream:
stridelabs-http = { git = "ssh://git@github.com/charliek/stridelabs-rust.git", tag = "v0.1.0", features = ["proxy"] }
```

(During development against an unreleased commit, pin `rev = "<sha>"`
instead of `tag`; see the workspace root README for the local `[patch]`
co-development snippet.)

## `error` — `AppError` and the wire contract

```rust
use anyhow::Context;
use stridelabs_http::{AppError, AppResult};

async fn get_widget(id: &str) -> AppResult<String> {
    if id.is_empty() {
        return Err(AppError::BadRequest("id must not be empty".into()));
    }
    // Any `anyhow::Error` converts via `#[from]` -> AppError::Internal.
    let raw = std::fs::read_to_string(id).context("reading widget")?;
    Ok(raw)
}
```

Note the `.context(..)`: `?` performs exactly one `From` hop, so a concrete
error like `std::io::Error` has to become an `anyhow::Error` first. Handlers
whose helpers already return `anyhow::Result` get the conversion for free.

Every error renders as the same body:

```json
{"error": {"message": "id must not be empty", "type": "Bad Request"}}
```

- `type` is the status's canonical reason phrase (`"error"` for the rare
  status that has none).
- `message` is the variant's payload **verbatim** — treat it as a public,
  user-readable sentence.
- Except for `Internal`, whose `anyhow::Error` is logged at `error!` level
  and replaced with the fixed string `"internal server error"`. Server-side
  detail never reaches a client.

| Variant | Status |
|---|---|
| `BadRequest` | 400 |
| `Unauthorized` | 401 |
| `Forbidden` | 403 |
| `NotFound` | 404 |
| `Conflict` | 409 |
| `TooManyRequests` | 429 |
| `BadGateway` | 502 |
| `Custom { status, .. }` | caller-chosen (4xx) |
| `Internal` | 500 |

`AppError::status()` is public, so a consumer can classify an error (metrics
label, log field) without rendering it.

### App-specific statuses

There is no `PaymentRequired` variant — a budget is spendwise's concern, not
a shared crate's. Statuses this enum doesn't name go through the one
constructor for `Custom`:

```rust
use http::StatusCode;
use stridelabs_http::AppError;

fn payment_required(msg: impl Into<String>) -> AppError {
    AppError::custom_client(StatusCode::PAYMENT_REQUIRED, msg)
}
```

`custom_client` is restricted to **4xx** by a `debug_assert!`: its message is
returned to the client verbatim, which is precisely what `Internal`'s
redaction exists to prevent for server errors. Debug and test builds panic on
a 5xx; release builds pass it through. That's deliberate — a 5xx here is a
programming error to catch in CI, not a runtime condition every call site
should have to handle, and quietly rewriting it to a 500 in release would
hide the bug. `Custom` is `#[non_exhaustive]`, so `custom_client` is the only
way to build one from outside this crate.

### Why `anyhow` is in a shared crate's public API

The workspace convention is typed (`thiserror`) errors, no `anyhow`, in
library APIs. `AppError::Internal(#[from] anyhow::Error)` is the documented
exception: it sits at the *application* boundary, where failure modes are
open-ended by nature and the detail is logged and discarded rather than
matched on, and `#[from]` is what makes `?` work across a handler's whole zoo
of dependencies. The asymmetry with `stridelabs-config`'s typed errors is
intentional.

## `headers` — the security baseline

```rust
use axum::{routing::get, Router};
use stridelabs_http::security_headers;

let app: Router = Router::new()
    .route("/", get(|| async { "ok" }))
    .layer(security_headers());
```

Sets three headers on **every** response, including 4xx/5xx:

| Header | Value |
|---|---|
| `x-content-type-options` | `nosniff` |
| `x-frame-options` | `DENY` |
| `referrer-policy` | `strict-origin-when-cross-origin` |

Values are *overriding*: a handler that set its own is replaced. A baseline
any handler can silently opt out of isn't a baseline — a route that genuinely
needs different framing rules shouldn't be behind this layer.

The return type is a named unit struct, `SecurityHeadersLayer`, so it can be
stored in a struct field or named as a return type — and so that adding a
fourth header later isn't a breaking change for anyone who wrote that name
down. (It mirrors how `stridelabs-observability` exposes `RequestIdLayer`.)

## `cors` feature — an explicit-origin layer

```rust
use axum::{routing::get, Router};
use http::{header, Method};
use stridelabs_http::cors_layer;

// `CORS_ORIGINS=["https://a.example.com","https://b.example.com"]` — the
// workspace's house format for a string list. Don't hand-roll a comma split;
// `stridelabs-config` owns this parse and the two must agree.
let origins: Vec<String> = stridelabs_config::parse_string_array("CORS_ORIGINS")?;

let mut app: Router = Router::new().route("/", get(|| async { "ok" }));
if !origins.is_empty() {
    app = app.layer(cors_layer(
        &origins,
        &[Method::GET, Method::POST],
        &[header::AUTHORIZATION, header::CONTENT_TYPE],
    ));
}
```

- **Policy is caller-supplied.** Origins, methods and headers are all
  parameters; nothing about one service's front-end is baked in here.
- Credentials are always allowed — every StrideLabs browser client
  authenticates with a cookie or an `Authorization` header.
- An origin string that isn't a valid header value is skipped with a
  `tracing::warn!` naming it. That's a deployment-config typo: the useful
  behavior is a service that boots, serves its other origins, and says so
  loudly — not a boot failure, and not a silent misconfiguration.
- Wire it conditionally (as above). An empty origin list produces a layer
  that allows nothing, which is rarely what "CORS is off" should mean.

**On the `Any` + credentials panic:** `tower_http::cors::Any` combined with
`allow_credentials(true)` panics at runtime (a wildcard
`access-control-allow-origin` is invalid on a credentialed response per the
CORS spec). This signature makes that combination unrepresentable —
credentials are always on and origins can only arrive as concrete strings —
so the failure is ruled out by construction rather than by a warning someone
has to read.

## `shutdown` — signal and flag primitives

```rust
# async fn example(listener: tokio::net::TcpListener, app: axum::Router) {
axum::serve(listener, app)
    .with_graceful_shutdown(stridelabs_http::shutdown_signal())
    .await
    .unwrap();
# }
```

- `shutdown_signal()` resolves on SIGINT (Ctrl-C) or, on unix, SIGTERM.
  Non-unix targets get the Ctrl-C arm only.
- `wait_for_shutdown(rx: watch::Receiver<bool>)` resolves when the flag flips
  to `true`, **or immediately if it is already set** — that check is what
  makes a one-sender/many-servers fan-out correct. It also returns when every
  sender is dropped.

**Not extracted:** limen's bounded drain (stop accepting, then wait out
in-flight requests up to a timeout). It's embedded in that service's
`serve_with_shutdown` and entangled with its config and background tasks —
there is no standalone primitive to lift, and inventing one here would be
designing a new API rather than sharing a proven one. The drain stays
app-side.

`shutdown_signal` has no unit test: exercising it means delivering a real
signal to the test process, which races every other test in the binary. Its
body is a `select!` over two `tokio::signal` futures with no logic of its
own. `wait_for_shutdown` is fully tested.

## `proxy` feature — reverse-proxy primitives

Ported from limen (a reverse proxy for service migrations) with no behavior
change — specifically the parts that are generic HTTP-proxy plumbing rather
than limen's own shadow-traffic and comparison machinery, which stays there.

```rust
use stridelabs_http::proxy::{
    build_upstream_url, filter_headers, relay_response, Direction, UpstreamClient,
};
use url::Url;

async fn proxy(
    path: &str,
    query: Option<&str>,
    headers: &http::HeaderMap,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    let client = UpstreamClient::build(true, None)?;
    let base = Url::parse("https://upstream.internal")?;
    let url = build_upstream_url(&base, path, query).ok_or("path would be rewritten")?;

    let upstream = client
        .inner()
        .get(url)
        .headers(filter_headers(headers, Direction::Request))
        .send()
        .await?;

    Ok(relay_response(upstream))
}
```

| Item | What it does |
|---|---|
| `HOP_BY_HOP` | The RFC 7230 §6.1 header list, as `&[&str]` (lowercased) |
| `filter_headers(&HeaderMap, Direction)` | The copy that may cross a hop |
| `connection_tokens(&HeaderMap)` | Header names banned by a `Connection` list |
| `request_has_body(&HeaderMap)` | Body presence from framing headers alone |
| `build_upstream_url(&Url, path, query)` | Origin + path/query, or `None` |
| `Buffered` / `buffer_or_stream(resp, limit)` | Bounded buffering that still serves the body |
| `relay_response` / `response_from_parts` | `reqwest` → axum translation |
| `UpstreamClient::build(verify, ca_pem)` | The pooled client |

Four behaviors are worth knowing about, because each is a bug someone
re-introduces every time this layer gets rewritten:

- **Repeated headers stay repeated.** The header copy appends. An
  `insert`-based copy silently collapses `set-cookie` to its last value,
  which surfaces months later as "users occasionally get logged out". Tested
  on both `filter_headers` and the full relay.
- **A path that would be rewritten is refused.** `build_upstream_url`
  returns `None` when normalization changes the path (`/public/../admin`
  collapses to `/admin`). If the edge authorizes the raw path and the
  upstream gets the collapsed one, every prefix-based rule in front of the
  proxy has been bypassed. Refusing is the only answer that can't be wrong —
  the two parties already disagree about what was requested.
- **Redirects are relayed, never followed** (`redirect::Policy::none()`). A
  3xx is the client's to act on; chasing it returns the client a response
  from a URL it never asked for, fetched from the proxy's network position
  rather than the client's.
- **Bounding a body doesn't cost the client the body.** `buffer_or_stream`
  reads up to `limit` and, the moment it would be exceeded, returns
  `TooLarge` carrying a `Body` of the already-read prefix chained to the rest
  of the upstream stream. The client is served every byte; only whatever
  wanted to *inspect* the bytes gives up. Exactly `limit` buffers,
  `limit + 1` streams.

`UpstreamClient::build` takes `(verify_certificates: bool, ca_bundle_pem:
Option<&[u8]>)` rather than limen's config struct, so adopting these
primitives doesn't mean adopting limen's configuration model. Reading the
bundle is the caller's job — hence bytes, and hence no `CaRead` variant in
`ClientBuildError`. Per-request timeouts are also left to call sites: they
are per-route policy and don't belong on a client shared by every route.

**Not included: a proxy handler.** Routing, retries, timeouts, circuit
breaking, shadowing, metrics — that's policy, it differs per service, and it
stays in the service. This is the mechanical layer underneath it.
