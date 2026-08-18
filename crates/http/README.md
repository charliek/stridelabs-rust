# stridelabs-http

The house `AppError` → HTTP convention, a security-headers layer, an
explicit-origin CORS builder, graceful-shutdown primitives, the mechanical
layer of a reverse proxy, and the mechanics of publishing an OpenAPI document,
for StrideLabs axum services.

## Feature topology

`default = []`. `error`, `headers`, `methods` and `shutdown` are
unconditional — every axum service wants all four, so gating them would only
add friction.

| Feature | Default | Adds |
|---|---|---|
| `cors` | off | `cors_layer`, via `tower-http/cors` |
| `openapi` | off | the `openapi` module — spec canonicalization, `(method, path)` enumeration, committed-spec freshness check — via `utoipa` |
| `proxy` | off | the `proxy` module — and `AppError::bad_gateway_upstream`, which takes a `reqwest::Error` — via `reqwest`/`url`/`bytes`/`futures` (and `tokio/time`) |

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
stridelabs-http = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.4.0" }

# with the CORS layer builder:
stridelabs-http = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.4.0", features = ["cors"] }

# for a service that proxies to an upstream:
stridelabs-http = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.4.0", features = ["proxy"] }

# for a service that publishes an OpenAPI document:
stridelabs-http = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.4.0", features = ["openapi"] }
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

`BadGateway`'s payload is verbatim like every other variant's, which is a trap
when the thing that failed is a `reqwest` call — see
`AppError::bad_gateway_upstream` under the `proxy` feature below, and the
redaction bullet next to it.

### App-specific statuses

There is no `PaymentRequired` variant — a budget is one service's concern, not
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

## `methods` — truthful method classification

`axum::routing::MethodRouter` gets two things wrong for a route that only
names the methods it serves: a bare `get()` route answers `HEAD` from the
`GET` handler instead of `405`ing it, and every 405 it does produce carries
axum's own auto-generated `Allow` header, which lists that same implicit
`HEAD` even when the route never registered one. `methods` closes both,
without pulling in anything the `proxy` feature exists to gate — it's pure
`axum::routing`, so it's unconditional like `error`/`headers`/`shutdown`.

```rust
use axum::http::Method;
use axum::routing::{get, MethodRouter};
use axum::Router;
use stridelabs_http::{default_refusal, refusing_unserved_over, CLASSIFIED_METHODS};

let get_only: MethodRouter = refusing_unserved_over(
    /* universe */ CLASSIFIED_METHODS.iter(),
    /* served   */ &[Method::GET],
    get(|| async { "hi" }),
    default_refusal,
);
let app: Router = Router::new().route("/widgets", get_only);
// HEAD, POST, PUT, … now 405 with `Allow: GET` — never a silent 200 from
// the GET handler, never a lying `Allow: GET, HEAD`.
```

`universe` and `served` are both `&[Method]`-shaped (`served` literally is
one; `universe`'s `impl IntoIterator<Item = &Method>` accepts one directly,
no `.iter()` needed) — a call that transposes them compiles without error
and silently classifies nothing the way the caller intended. There is no
type-level guard against this; naming the two positions at the call site (as
above) is the cheapest defense.

| Item | What it does |
|---|---|
| `CLASSIFIED_METHODS` | The nine methods `MethodFilter` can represent — the right universe for a route that should 405 anything it doesn't serve |
| `method_filter(methods)` → `Option<MethodFilter>` | OR-folds `methods`; `None` on an empty input (never a panic) |
| `refusing_unserved_over(universe, served, router, refusal_builder)` | Adds a refusal endpoint for `universe` minus `served` to `router`, with a truthful `Allow` |
| `default_refusal(allow)` | The crate's out-of-the-box refusal body: `405`, that `Allow` header, empty body |

- **The universe is the caller's choice, not a hard-coded constant.** A
  literal route passes `CLASSIFIED_METHODS` (all nine); a reverse proxy that
  has never handled `CONNECT` on a given leg can pass
  `CLASSIFIED_METHODS.iter().filter(|m| **m != Method::CONNECT)` instead, so
  an unhandled `CONNECT` keeps falling through to axum's own fallback rather
  than picking up a new (untested) truthful answer as a side effect of
  adopting this helper. That's the adoption shape of slauth, the StrideLabs
  auth service — not a recommendation; a service with no such history should
  classify all nine.
- **Serving the whole universe is a no-op, not a panic.** If `served`
  already covers everything in `universe`, `refusing_unserved_over` returns
  `router` unchanged; there is nothing left to refuse. `method_filter`
  mirrors this at one level down — an empty input is `None`, never a panic,
  because a shared crate can't assume every caller derives its input from a
  route's own non-empty method list the way the single adoption target does.
- **Duplicate methods are fine.** OR-ing the same `MethodFilter` bit twice
  is a no-op, so a served or universe list with repeats folds the same as
  its deduplicated form.
- **An unsupported method is a programmer error, not a runtime one.** Every
  `CLASSIFIED_METHODS` entry has a `MethodFilter`; a caller-constructed
  extension method (`Method::from_bytes(b"CUSTOM")`) doesn't.
  `method_filter` `debug_assert!`s on it in debug/test builds and silently
  drops it from the fold in release, so one bad entry doesn't take the
  route's whole method policy down with it.
- **The refusal body is yours to shape.** `default_refusal` is `405` +
  `Allow` + empty body. A consumer with its own error envelope (slauth's
  `{"detail": "..."}`) passes its own closure instead — `refusal_builder`
  only ever has to turn the already-computed, truthful `Allow` value into a
  full response.
- **Generic over the router's state**, with the same bounds
  `MethodRouter::on` itself needs (`Clone + Send + Sync + 'static`) and
  nothing more, so it composes under any axum service's own `AppState`.
- **`OPTIONS` needs a CORS layer in front of it.** `CLASSIFIED_METHODS`
  claims `OPTIONS`, which is only safe when a CORS layer answers preflight
  **before** routing — a real preflight then never reaches this module's
  refusal endpoint, only a bare `OPTIONS` does. With no such layer, judging
  the full nine-method universe 405s real preflight requests, breaking every
  cross-origin caller. Pair it with this crate's own `cors` feature
  (`cors_layer`, applied outermost) or drop `OPTIONS` from `universe`.

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

**Not extracted:** the originating proxy's bounded drain (stop accepting, then
wait out in-flight requests up to a timeout). It's embedded in that service's
`serve_with_shutdown` and entangled with its config and background tasks —
there is no standalone primitive to lift, and inventing one here would be
designing a new API rather than sharing a proven one. The drain stays
app-side.

`shutdown_signal` has no unit test: exercising it means delivering a real
signal to the test process, which races every other test in the binary. Its
body is a `select!` over two `tokio::signal` futures with no logic of its
own. `wait_for_shutdown` is fully tested.

## `openapi` feature — spec mechanics, not a spec

The parts of publishing an OpenAPI document that every service gets wrong the
same way. Everything here takes an
`utoipa::openapi::OpenApi` the *caller* built and knows nothing about what is
in it.

| Item | What it does |
|---|---|
| `to_pretty_json(&OpenApi)` | Pretty JSON with alphabetical keys at every nesting level |
| `expected_file_contents(&OpenApi)` | The above, plus the one trailing newline a committed file carries |
| `documented_pairs(&OpenApi)` | Every `(METHOD, path)` pair in the document, as a `BTreeSet` |
| `expected_pairs(&[("GET", "/x")])` | The expected side of that comparison, converted once here instead of in every consumer |
| `find_operation(&OpenApi, "GET", "/x")` → `Result<&Operation, OperationNotFound>` | The `Operation` at a method+path, or which of the three ways the lookup missed |
| `expect_operation(&OpenApi, "GET", "/x")` → `&Operation` | The same, panicking with that message — the test form |
| `check_committed_spec(path, &OpenApi, cmd)` → `Result<(), SpecFreshnessError>` | Committed file vs. fresh export |
| `assert_committed_spec_is_fresh(path, &OpenApi, cmd)` | The same, panicking with the report — the test form |

That is the whole surface. Two pairs of it are a typed-error primitive plus a
panicking wrapper, because the test form is what a consumer writes and the
`Result` form is what an `xtask` or CI helper needs; each pair renders one
message, so the two can't drift. The exhaustive method↔operation-slot mapping
underneath stays **private** — see the module docs for why publishing an
`[HttpMethod; 8]` would make its *length* part of the contract.

### Wiring it up

An `openapi` CLI subcommand that writes the committed file, and the test that
keeps it honest:

```rust,ignore
// src/main.rs — `svc openapi > openapi.json`
fn main() {
    if std::env::args().nth(1).as_deref() == Some("openapi") {
        // No config, no database, no listener: `OpenApiRouter<S>` is generic
        // over the state type until `with_state` is called, so the document
        // builds from nothing.
        println!("{}", stridelabs_http::openapi::to_pretty_json(&spec()));
        return;
    }
    // …
}
```

```rust,ignore
// tests/openapi_shape.rs
use stridelabs_http::openapi::{
    assert_committed_spec_is_fresh, documented_pairs, expect_operation, expected_pairs,
};

#[test]
fn the_documented_path_method_set_is_exact() {
    assert_eq!(
        documented_pairs(&svc::openapi::spec()),
        expected_pairs(&[("GET", "/api/v1/session"), ("POST", "/api/v1/pat")]),
    );
}

#[test]
fn every_route_documents_its_expected_status_codes() {
    let table: &[(&str, &str, &[&str])] = &[
        ("GET", "/api/v1/session", &["200"]),
        ("POST", "/api/v1/pat", &["201", "401", "422"]),
    ];

    let spec = svc::openapi::spec();
    for (method, path, expected) in table {
        // A miss says which of the three it was — no such path, no such
        // method *on* that path (naming the ones it does document), or a
        // typo'd method spelling. `find_operation` is the `Result` form if
        // you'd rather render your own.
        let operation = expect_operation(&spec, method, path);
        let mut actual: Vec<&str> =
            operation.responses.responses.keys().map(String::as_str).collect();
        actual.sort_unstable();
        assert_eq!(actual, *expected, "{method} {path} status codes");
    }
}

#[test]
fn the_committed_openapi_json_matches_a_fresh_export() {
    assert_committed_spec_is_fresh(
        concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.json"),
        &svc::openapi::spec(),
        "cargo run --bin svc -- openapi > openapi.json",
    );
}
```

The regeneration command is a **parameter** because it differs per service —
per binary, even — and it is reproduced verbatim in the failure message, so
the person reading a red CI job gets a line they can paste rather than a
diff they have to interpret.

### Adoption checklist: pin the spec file to LF

The freshness check compares bytes, and the export always writes LF. Add this
to the repository's `.gitattributes` **as part of adopting the helper**, not
after a contributor on Windows trips over it:

```gitattributes
openapi.json text eol=lf
```

Without it, a checkout with `core.autocrlf=true` materializes the
LF-committed file with CRLF endings, and the check fails on every line,
forever, with nothing wrong in the spec. Line endings are deliberately **not**
normalized before comparing: normalizing would let a CRLF working copy pass
and then hand a whole-document diff to whoever next regenerates the file,
with the real cause (a checkout setting) nowhere in sight. Instead the CRLF
case is detected and the report names it, along with the `.gitattributes`
line that fixes it.

### Why `to_pretty_json` exists at all

A committed `openapi.json` is only reviewable, and only checkable against a
fresh export, if rendering the same document twice produces the same bytes —
and a service does not control that on its own. `utoipa`'s `Paths` is a
`BTreeMap` *unless* its `preserve_path_order` feature is on, and the nested
`serde_json::Value` fields further down flip from sorted to insertion-ordered
the moment **anything** in the dependency graph enables `serde_json`'s
`preserve_order`. Cargo unifies features across the whole graph, so a
transitive dependency three levels away can silently reorder a service's
committed spec and fail its freshness test with a diff nobody can explain.
Rebuilding every object through a `BTreeMap` here is immune to all of it.

That claim is defended by tests that would otherwise be vacuous, which is
worth knowing about before someone "cleans up" the wiring: with
`preserve_order` off, a `serde_json::Map` **is** a `BTreeMap`, so a
`Value::Object` is sorted before `canonicalize` ever sees it and deleting the
function would fail no assertion. This crate's `[dev-dependencies]` therefore
enable `serde_json/preserve_order` — which under resolver v2 reaches only
test targets, never a `cargo build` or any consumer's graph — and one test
asserts the hazard is actually reproduced before the others rely on it. Drop
that dev-dependency and the suite says so.

`check_committed_spec` also names the invisible-byte cases explicitly — CRLF
line endings, a missing trailing newline, a doubled one — because those are
the failures that otherwise produce a "the files look identical" diff.

### What this deliberately does not do

There is **no `ApiDoc`, no security schemes, no `info`/`servers`/`tags`
block, no route list, no exclusion list, and no Swagger-UI wiring.** That is
all policy: slauth documents a Kratos session cookie plus a PAT bearer with
its own fixed, recognizable prefix, while a resource server documents a
slauth-issued JWT
bearer plus a PAT bearer with a different prefix, and neither one's document
root is a thing the other could adopt. A "spec builder" here would have to
guess at that shape and be wrong for at least one consumer.

### Two conventions that live in the module docs, not here

Two things are worth carrying between services even though they are not code
and can't be enforced from a crate: **prefer structural exclusion to a
maintained exclusion list** (and know where its silent hole is), and **apply a
version prefix with `OpenApiRouter::nest`, never `axum::Router::nest`**.

Both are stated in full, once, in the `openapi` module docs —
[`crates/http/src/openapi.rs`](src/openapi.rs), rendered by `cargo doc -p
stridelabs-http --features openapi --open`. They are **not** restated here on
purpose: this convention was previously written out at length in three places,
and a wrong version of the `nest`/`merge` claim propagated into two
repositories before review caught it. One copy, next to the
`documented_pairs` that guards both.

**On the exhaustive match** and **on `utoipa`'s features** (this crate enables
no schema features because it derives no schemas; a consumer declares its own
`utoipa` with whatever its types need and Cargo unifies them) — likewise the
module docs, which carry the reasoning and the utoipa-5.x details.

## `proxy` feature — reverse-proxy primitives

Carried over from a production reverse proxy (used for service migrations)
with no behavior change — specifically the parts that are generic HTTP-proxy
plumbing rather than that proxy's own shadow-traffic and comparison
machinery, which stays there.

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
| `Buffered` / `buffer_or_stream(resp, limit)` | Size-bounded buffering that still serves the body |
| `buffer_or_stream_within(resp, limit, deadline)` | The same, also bounded in time |
| `buffer_request_or_stream(body, limit)` | The same bound over an axum request `Body` |
| `apply_forwarded(&mut HeaderMap, Option<IpAddr>, &ForwardedPolicy)` | `X-Forwarded-*` synthesis under an explicit trust policy |
| `relay_response` / `response_from_parts` | `reqwest` → axum translation |
| `UpstreamClient::build(verify, ca_pem)` | The pooled client |
| `UpstreamFailure::classify(&reqwest::Error)` | The error reduced to predicates + a total `UpstreamCategory` — no URL, no message |
| `UpstreamFailure::log(message)` | That classification as `tracing` fields, at `ERROR` |
| `AppError::bad_gateway_upstream(&reqwest::Error)` | A `502` with a fixed body, logging the classification (also `_with_context` for a per-call-site log message) |

Seven behaviors are worth knowing about, because each is a bug someone
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
  `limit + 1` streams. `buffer_request_or_stream` applies the identical bound
  to an axum request `Body`, for a caller that needs the uploaded bytes twice.
- **A size cap is not a time cap.** A body that trickles — or stalls outright
  — stays under `limit` forever, so a size-bounded read waits as long as the
  upstream cares to take. `buffer_or_stream_within` adds a deadline and
  demotes to `TimedOut` (the same prefix-plus-remainder `Body`) when it
  passes. The timer is one pinned `Sleep` given the `biased` first look in a
  `select!`, deliberately *not* a per-chunk `tokio::time::timeout_at`: a fresh
  `Sleep` is never ready on its first poll, so against an upstream whose
  chunks are always immediately ready a `timeout_at` timer is never reached
  and the deadline never fires. There is a test that fails on exactly and only
  that revert.

- **`X-Forwarded-*` is client input until a hop says otherwise.** An upstream
  that reads `X-Forwarded-Proto` to decide "this request was secure" trusts
  whichever hop wrote it — and if the proxy forwards a client-supplied value,
  that hop is the client. `apply_forwarded` makes the choice explicit per leg:
  `XfpPolicy::Override(scheme)` replaces every inbound line with one
  authoritative value, `PreserveTrustedOrSet(scheme)` keeps what arrived
  (correct only if the ingress strips or always sets the header), `Untouched`
  does nothing. There is no `Default` on any of these types; the scheme is
  applied *after* the generic `overrides` list, so the policy wins
  structurally; and the header's authority lives in `XfpPolicy` alone —
  naming `x-forwarded-proto` in `overrides` is a `debug_assert` under *any*
  policy, and the pair is dropped in release. `Override` is fail-closed: the
  inbound header is removed first, and a scheme that isn't a URI scheme per
  RFC 3986 (`"https, http"` included) is not written, so the upstream sees no
  header rather than the caller's claim. `XffPolicy` covers the chain:
  `Append` (the originating proxy's multi-line-aware append, one combined line out, an
  existing chain preserved when there is no peer) or `FillIfAbsent` (slauth's
  post-allow-list fill).

- **An upstream error is not a message you may show anyone.**
  `reqwest::Error`'s `Display` ends with `" for url ({url})"` and its `Debug`
  prints the same URL as a field — host, port, path *and query string*. So
  `AppError::BadGateway(format!("upstream: {e}"))` hands the caller the
  upstream's address (exactly the class of leak this module exists to close
  — an internal provider base URL configured via environment is a realistic
  example), and `tracing::error!(error = ?e, …)` puts it in the logs.
  `UpstreamFailure::classify` is the alternative: four `reqwest` predicates,
  the `Option<StatusCode>` that only `error_for_status` ever produces, and a
  **total** `category` — because all four predicates can be false at once
  (a builder-, redirect- or decode-class error), and an all-false log line
  says nothing. `AppError::bad_gateway_upstream` is the constructor on top:
  the client message is a constant, so the body is byte-identical whatever
  failed and against whichever URL. A service with a **different error
  envelope** (slauth's `{"detail": …}`) adopts `classify` + `log` only and
  keeps its own error type and bodies — which is why the classification is a
  separate primitive rather than a method on `AppError`.

`Buffered` is `#[non_exhaustive]`, so a `match` on it needs a wildcard arm.
`UpstreamFailure` and `UpstreamCategory` are too — the first because
`reqwest` can grow a predicate, the second because it can grow an error kind.

`UpstreamClient::build` takes `(verify_certificates: bool, ca_bundle_pem:
Option<&[u8]>)` rather than the originating proxy's config struct, so adopting
these primitives doesn't mean adopting that proxy's configuration model. Reading the
bundle is the caller's job — hence bytes, and hence no `CaRead` variant in
`ClientBuildError`. Per-request timeouts are also left to call sites: they
are per-route policy and don't belong on a client shared by every route.

**Not included: a proxy handler.** Routing, retries, timeouts, circuit
breaking, shadowing, metrics — that's policy, it differs per service, and it
stays in the service. This is the mechanical layer underneath it.
