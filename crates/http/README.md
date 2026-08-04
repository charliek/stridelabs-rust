# stridelabs-http

The house `AppError` → HTTP convention, a security-headers layer, an
explicit-origin CORS builder, graceful-shutdown primitives, the mechanical
layer of a reverse proxy, and the mechanics of publishing an OpenAPI document,
for StrideLabs axum services. Extracted from spendwise-rs's `error.rs`,
limen's `http/`, and slauth's `http/openapi.rs`.

## Feature topology

`default = []`. `error`, `headers` and `shutdown` are unconditional — every
axum service wants all three, so gating them would only add friction.

| Feature | Default | Adds |
|---|---|---|
| `cors` | off | `cors_layer`, via `tower-http/cors` |
| `openapi` | off | the `openapi` module — spec canonicalization, `(method, path)` enumeration, committed-spec freshness check — via `utoipa` |
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
stridelabs-http = { git = "ssh://git@github.com/charliek/stridelabs-rust.git", tag = "v0.3.0" }

# with the CORS layer builder:
stridelabs-http = { git = "ssh://git@github.com/charliek/stridelabs-rust.git", tag = "v0.3.0", features = ["cors"] }

# for a service that proxies to an upstream:
stridelabs-http = { git = "ssh://git@github.com/charliek/stridelabs-rust.git", tag = "v0.3.0", features = ["proxy"] }

# for a service that publishes an OpenAPI document:
stridelabs-http = { git = "ssh://git@github.com/charliek/stridelabs-rust.git", tag = "v0.3.0", features = ["openapi"] }
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

## `openapi` feature — spec mechanics, not a spec

The parts of publishing an OpenAPI document that every service gets wrong the
same way, extracted from slauth's `src/http/openapi.rs` and
`tests/openapi_shape.rs`. Everything here takes an
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
all policy: slauth documents a Kratos session cookie plus a `slp_live_…` PAT
bearer, spendwise documents a slauth-issued JWT bearer plus a PAT bearer with
a different prefix, and neither one's document root is a thing the other
could adopt. A "spec builder" here would have to guess at that shape and be
wrong for at least one consumer.

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
repositories before review caught it (#11, slauth#35). One copy, next to the
`documented_pairs` that guards both.

**On the exhaustive match** and **on `utoipa`'s features** (this crate enables
no schema features because it derives no schemas; a consumer declares its own
`utoipa` with whatever its types need and Cargo unifies them) — likewise the
module docs, which carry the reasoning and the utoipa-5.x details.

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
