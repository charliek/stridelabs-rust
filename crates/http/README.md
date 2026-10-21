# stridelabs-http

The house `AppError` → HTTP convention, a security-headers layer, an
explicit-origin CORS builder, graceful-shutdown primitives, the mechanical
layer of a reverse proxy, the mechanics of publishing an OpenAPI document, an
SSRF-hardened outbound fetch, and the process-wide rustls provider install,
for StrideLabs axum services.

## Feature topology

`default = []`. `error`, `headers`, `methods` and `shutdown` are
unconditional — every axum service wants all four, so gating them would only
add friction.

| Feature | Default | Adds |
|---|---|---|
| `cors` | off | `cors_layer`, via `tower-http/cors` |
| `openapi` | off | the `openapi` module — spec canonicalization, `(method, path)` enumeration, committed-spec freshness check — via `utoipa` |
| `proxy` | off | the `proxy` module — and `AppError::bad_gateway_upstream`, which takes a `reqwest::Error` — via `reqwest` 0.13 (with its `rustls` TLS feature)/`url`/`bytes`/`futures` (and `tokio/time`) |
| `ssrf` | off | the `ssrf` module — `fetch_public` and `fetch_public_response`, an SSRF-hardened fetch of a URL somebody else chose (public-address policy, DNS pinning, capped body, a `User-Agent`, accepted statuses, the answering hop) — via the same `reqwest`/`url`/`bytes`/`futures` as `proxy` (and `tokio/time`, `tokio/net`) |
| `ssrf-decompress` | off | `ssrf` plus `FetchPolicy::with_decompression`: opt-in gzip and deflate decoding of a fetched body, capped on its decoded size, via `flate2` 1.1.10+ (`rust_backend`: miniz_oxide, crc32fast, adler2, simd-adler32; pure Rust, no C toolchain). Implies `ssrf`. Off for an image fetch |
| `ssrf-test-support` | off | `ssrf::LoopbackTestServer` and `FetchPolicy::with_loopback_test_server`: point a fetch at a local TLS test server. Implies `ssrf`. Enable from `[dev-dependencies]` and **check the shipped graph for it** (see "Testing against it" below) |
| `tls` | off | the `tls` module — `install_default_provider`, which makes aws-lc-rs the process's rustls `CryptoProvider` — via `rustls` 0.23 (`aws_lc_rs` + `std`, no defaults) |
| `redact-url` | off | `redact_url`: a URL as `scheme://host[:port]/path`, with userinfo, query and fragment dropped, for a log line or a `Debug` impl. Via `url` alone (the same optional dependency `proxy` and `ssrf` use), none of their client stack |

`proxy` is the gate that matters: it pulls in an HTTP *client* and a TLS
stack. A service that only answers requests should never compile that, which
is why the proxy primitives live behind a feature instead of in a crate
everyone already depends on.

`ssrf` is the same gate for the same reason, and shares `proxy`'s one
reqwest declaration, so a service with both compiles the client once. Between
them they are the only features in this workspace that turn on reqwest's TLS
(`tls` adds a direct `rustls` dependency, but only to install a provider, and
stridelabs-redis turns on redis-rs's). reqwest 0.13's `rustls` means
rustls's aws-lc-rs provider (unless the process installed a default provider
first; aws-lc-sys is a C build) and `rustls-platform-verifier`: the OS trust
store plus `UpstreamClient::build`'s `ca_bundle_pem`, and **no bundled
roots** — 0.12's webpki roots are gone. On Linux that store is the
system CA bundle (`SSL_CERT_FILE`/`SSL_CERT_DIR` respected), so an image
without `ca-certificates` fails `UpstreamClient::build(true, None)` with
`ClientBuildError::Build`. Keep aws-lc-rs the only rustls provider in the
consumer's graph: rustls `ring` from anywhere else (redis-rs 0.27's
`tls-rustls`, sqlx `tls-rustls-ring`) next to it makes
`rustls::ClientConfig::builder()` panic.

`tokio` is a **non-optional** dependency (`signal`, `sync`, `macros`) because
`shutdown` is signal/watch machinery. A service with no tokio in its graph
has no server to shut down gracefully, so gating it would buy nobody a leaner
build.

## Adding the dependency

```toml
[dependencies]
stridelabs-http = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.8.0" }

# with the CORS layer builder:
stridelabs-http = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.8.0", features = ["cors"] }

# for a service that proxies to an upstream:
stridelabs-http = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.8.0", features = ["proxy"] }

# for a service that publishes an OpenAPI document:
stridelabs-http = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.8.0", features = ["openapi"] }

# for a service that fetches user-supplied URLs, and installs the rustls provider at startup:
stridelabs-http = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.8.0", features = ["ssrf", "tls"] }

# to name configured URLs in logs without their credentials:
stridelabs-http = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.8.0", features = ["redact-url"] }

# for a feed fetcher that decodes gzip and deflate:
stridelabs-http = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.8.0", features = ["ssrf-decompress", "tls"] }

[dev-dependencies]
# its tests, to fetch from a local TLS server (never in [dependencies]):
stridelabs-http = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.8.0", features = ["ssrf-test-support"] }
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
  route's own non-empty method list the way slauth's own route list does.
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
- Every response the layer touches carries one `vary: origin,
  access-control-request-method, access-control-request-headers` header —
  set explicitly (a test pins it), so a tower-http upgrade can't change what a
  shared cache keys on.
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

**Not extracted:** the bounded drain of the reverse proxy these primitives
came from (stop accepting, then
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
repositories before review caught it (#11). One copy, next to the
`documented_pairs` that guards both.

**On the exhaustive match** and **on `utoipa`'s features** (this crate enables
no schema features because it derives no schemas; a consumer declares its own
`utoipa` with whatever its types need and Cargo unifies them) — likewise the
module docs, which carry the reasoning and the utoipa 5.x/6.x details.

### Version pairing: utoipa 6 and utoipa-axum 0.3

This crate builds against `utoipa` 6, and every function above takes a
`utoipa::openapi::OpenApi` (`find_operation` and `expect_operation` also return
a `utoipa::openapi::path::Operation`), so a consumer must be on utoipa 6 too:
two `utoipa` majors in one graph are two unrelated `OpenApi` types. A service
that registers routes through `utoipa_axum::router::OpenApiRouter` pairs it
with **utoipa-axum 0.3**, the release that requires utoipa 6; 0.2 only supports
utoipa 5. The `nest`/`merge`/`route` behaviour described in the module docs is
unchanged by the move: utoipa-axum's `router.rs` is byte-identical in 0.2.0 and
0.3.0. Moving from utoipa 5 to 6 also changes what utoipa-gen derives, so diff
a regenerated `openapi.json` and run your OpenAPI validator rather than
expecting a one-line diff. Known differences: a derived `Option<T>` field's
`oneOf` lists the `$ref` first and `null` second; a non-nullable `$ref` field
with `title` or `default` loses its `oneOf` wrapper; an empty response
description serializes as `{}`, which OpenAPI 3.1 rejects (always give a
description); and an `inline` unit-enum field that also carries a title, a
description (a doc comment counts), a default, `read_only` or `write_only`
derives an unsatisfiable `allOf` (reference the enum instead of inlining it).
See the CHANGELOG's 0.5.0 entry.

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

Eight behaviors are worth knowing about, because each is a bug someone
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
- **Bodies are relayed, never decoded.** `UpstreamClient` switches off each
  of reqwest's decoders (`no_gzip()`, `no_brotli()`, `no_zstd()`,
  `no_deflate()`), so a coded upstream body reaches the client byte for byte
  under its own `Content-Encoding`, and no request asks for a coding the
  client did not. They are off by default only until some crate in the
  consumer's graph turns on reqwest's `gzip` (or another decoder) feature,
  which feature unification then turns on for every client in the binary.
  This crate's test build turns the gzip one on (a dev-dependency, absent
  from the shipped graph), so the test that pins the relay runs against a
  live decoder, next to one showing a plain client does decode.
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
  `Append` (the originating reverse proxy's multi-line-aware append, one combined line out, an
  existing chain preserved when there is no peer) or `FillIfAbsent` (slauth's
  post-allow-list fill).

- **An upstream error is not a message you may show anyone.**
  `reqwest::Error`'s `Display` ends with `" for url ({url})"` and its `Debug`
  prints the same URL as a field — host, port, path *and query string*. So
  `AppError::BadGateway(format!("upstream: {e}"))` hands the caller the
  upstream's address (exactly the class of leak this module exists to close
  — an internal provider base URL configured via environment is a realistic
  example), and `tracing::error!(error = ?e, …)` puts it in the logs. Since
  reqwest 0.13 that includes a body-read failure from `Response::bytes()` or
  `json()`, which 0.12 rendered without one; `e.without_url()` strips it when
  rendering the error is really what you want.
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
Option<&[u8]>)` rather than the originating reverse proxy's config struct, so adopting
these primitives doesn't mean adopting that proxy's configuration model. Reading the
bundle is the caller's job — hence bytes, and hence no `CaRead` variant in
`ClientBuildError`. Per-request timeouts are also left to call sites: they
are per-route policy and don't belong on a client shared by every route.

**Not included: a proxy handler.** Routing, retries, timeouts, circuit
breaking, shadowing, metrics — that's policy, it differs per service, and it
stays in the service. This is the mechanical layer underneath it.

## `tls` feature — the process's one rustls provider

```rust,ignore
fn main() {
    // after logging is up, before anything connects
    stridelabs_http::tls::install_default_provider();
    // …
}
```

rustls needs a process-level `CryptoProvider`. When none was installed,
`rustls::ClientConfig::builder()` derives one from rustls's crate features and
**panics** if the unified graph names zero providers or two (`ring` next to
`aws_lc_rs`) — at the first TLS connect through such a builder, not at compile
time. `install_default_provider()` installs aws-lc-rs once at startup so no
later builder falls back on the feature-derived default; reqwest and sqlx name
their provider themselves, so it is for everything else (`rediss://` through
redis-rs, the next dependency).

- Returns `ProviderInstall::Installed`, or `ProviderInstall::AlreadyInstalled`
  when something got there first. That is accepted, not an error: rustls
  allows one install per process and no replacement, and in a graph that
  follows the [one-provider rule](../../README.md#one-crypto-provider-aws-lc-rs)
  the earlier provider is aws-lc-rs too.
- The compile-time half stays yours: keep `ring` out of the graph (the
  workspace CI's `cargo tree` listing guard is the pattern to copy).
- Lifted from slauth's `tls.rs`; tapper and limen carry the same function.
  It lives here, not in `stridelabs-auth`, which is guarded to stay
  rustls-free.

`tests/tls_provider.rs` is one test in its own process (the provider is
process-global): the first call installs aws-lc-rs, the second reports
`AlreadyInstalled` and leaves it, and `ClientConfig::builder()` then uses it.

## `redact-url` feature — a URL for a log line

```rust
use stridelabs_http::redact_url;

tracing::info!(upstream = %redact_url(&config.upstream_url), "relaying");

assert_eq!(
    redact_url("https://user:SECRET@api.example.com:8443/v1/feed?token=SECRET#top"),
    "https://api.example.com:8443/v1/feed",
);
```

`redact_url(raw)` renders `raw` as `scheme://host[:port]/path`: the userinfo,
query and fragment, which is where a URL carries a credential (`user:pass@`,
`?token=…`), are dropped. It is for a URL a service names on purpose: a log
field, or a config struct's `Debug`.

- **Parsed as the client parses it.** `url::Url` is what `reqwest::Url` is,
  so the host shown is the host a client dials, normalised the way the client
  sees it: scheme and host lowercased, an internationalised host as punycode,
  IPv6 in canonical form, the scheme's default port dropped, and an
  `http(s)`/`ws(s)` URL's empty path shown as `/`
  (`https://auth.example.com:443?token=…` → `https://auth.example.com/`).
  Other schemes keep an empty path empty
  (`rediss://default:SECRET@cache.example.com:6379` →
  `rediss://cache.example.com:6379`).
- **Unparseable means nothing of the input.** A string that does not parse
  to a URL with a host renders as the fixed `<unparseable URL>`. That covers
  a bare `host/path`, a relative reference, `mailto:`, `file:///…` and `""`.
  Where its credential would start is exactly what cannot be known.
- **The path is kept.** A credential in the path itself (`/hooks/SECRET`)
  looks like a route, so a URL like that needs a rule of its own.
- It does not make a `reqwest::Error` safe to render: that error's `Display`
  quotes the URL it failed on, query included. Strip it with
  `.without_url()` first.

The rule is stridelabs-auth's for `SlauthConfig`'s `Debug`. stridelabs-auth
keeps a crate-private copy because it depends on this crate only behind its
`http` feature.

## `ssrf` feature — SSRF-hardened outbound fetch

Every server-side fetch of a URL a user, an LLM or an attacker chose goes
through `fetch_public` (body and content type) or `fetch_public_response`
(the answering hop's status, URL and headers as well). On Cloud Run the
threat is reaching the metadata
server (`169.254.169.254`, `metadata.google.internal`) or another internal
service. Ported from Python `stridelabs.mcp.ssrf` (stridelabs-mcp 0.4.0): the
same steps, in the same order, with the same client-safe messages.
Image-specific policy (content type, magic bytes, `data:` URIs) is not here;
it layers on top.

```rust
use std::time::Duration;
use http::HeaderValue;
use stridelabs_http::ssrf::{fetch_public, FetchPolicy, SsrfError};

async fn fetch_image(url: &str) -> Result<bytes::Bytes, SsrfError> {
    let policy = FetchPolicy::new("image", 10 * 1024 * 1024) // label, max_bytes
        .with_scheme_error("Only https:// image URLs (or data: URIs) are allowed.")
        .with_too_large_error("The image is too large (max 10 MB).")
        .with_timeout(Duration::from_secs(10))
        .with_accept(HeaderValue::from_static("image/*"));
    let fetched = fetch_public(url, &policy).await?; // Fetched { body, content_type }
    Ok(fetched.body)
}
```

| Item | What it does |
|---|---|
| `fetch_public(&str, &FetchPolicy)` → `Result<Fetched, SsrfError>` | The whole guarded fetch: body and content type |
| `fetch_public_response(&str, &FetchPolicy)` → `Result<FetchResponse, SsrfError>` | The same fetch, answering with the hop that answered: `body`, `content_type`, `status`, `final_url` (`url::Url`), `headers`, `redirects`. `#[non_exhaustive]`; `From<FetchResponse> for Fetched` |
| `FetchPolicy::new(label, max_bytes)` | The strict policy: https only, no redirects, 10 s, `200` only, no `Accept` or `User-Agent`, `identity` only, system DNS, public addresses only |
| `.with_allowed_schemes(AllowedSchemes)` | `HttpsOnly` (default) or `HttpAndHttps` (feeds) |
| `.with_scheme_error` / `.with_too_large_error` | Replace those two messages |
| `.with_timeout(Duration)` | The wall-clock budget for everything — DNS, connects, TLS, body, decoding, every hop |
| `.with_max_redirects(u32)` | Follow up to this many (default 0), each hop validated and pinned afresh |
| `.with_accept(HeaderValue)` | The `Accept` header to send |
| `.with_user_agent(HeaderValue)` | The `User-Agent` to send on every hop (default none) |
| `.with_accepted_statuses(AcceptedStatuses)` | `OkOnly` (default, `== 200`) or `AnySuccess` (any 2xx) |
| `.with_decompression(Decompression)` | Feature `ssrf-decompress`: `Off` (default) or `GzipDeflate` |
| `.with_resolver(impl HostResolver)` | The DNS seam: `SystemResolver` by default, or any `Fn(String, u16) -> impl Future<Output = io::Result<Vec<IpAddr>>>` |
| `is_public_address(IpAddr)` | The address policy on its own |
| `SsrfError` | Every failure; `Display` is the client-safe message |

### The policy, in order, with Python's exact messages

| Step | Message |
|---|---|
| Parse | `Invalid URL.` (also a `Location` that cannot be joined) |
| Scheme allowlist | `Only https:// URLs are allowed.` / `Only http://, https:// URLs are allowed.` / your text. A string with no scheme at all gets this one too, as in Python |
| Embedded credentials | `URLs with embedded credentials are not allowed.` |
| Metadata names (`metadata.google.internal`, any subdomain, `metadata`) | `That host is not allowed.` |
| IP-literal host outside the policy | `URL host is not a public address.` |
| Resolver error, or no answers | `Could not resolve the URL host.` |
| **Any** answer outside the policy | `URL host resolves to a non-public address.` |
| A 3xx with redirects off (any 3xx, as Python's `is_redirect`) | `URL redirects are not allowed.` |
| Chain longer than `max_redirects` | `Too many redirects.` |
| A status the policy does not accept (by default, anything but 200) | `{Label} fetch failed with HTTP {code}.` |
| Numeric `Content-Length` over the cap, or the stream passing it (a coded body: the wire cap, or decoded, `max_bytes`) | `The fetched {label} is too large.` / your text |
| The budget runs out (decoding included) | `{Label} fetch timed out.` |
| A `Content-Encoding` the policy does not decode (by default, anything but `identity`; see below), or a corrupt or truncated coded body | `Could not fetch the {label} URL.` |
| Anything else (connect, TLS, a certificate for another name, a broken body, a 3xx with no `Location`) | `Could not fetch the {label} URL.` |

`{Label}` is Python's `str.capitalize`. No message ever carries an address, a
port or an underlying error; transport detail is logged at `debug` with
`reqwest::Error::without_url` and goes nowhere else.

That is this crate's own logging. reqwest, hyper and hyper-util log too, and
their `DEBUG`/`TRACE` events name the destination host and the pinned address
being connected to — outside this crate's control. Run production at `info`
(or keep those crates at `info` in the filter).

### Compressed responses: refused, unless the policy decodes

By default every request sends `Accept-Encoding: identity`, reqwest's
decoders are switched off per client (`no_gzip()`, `no_brotli()`,
`no_zstd()`, `no_deflate()` — this crate enables none of those features, but
a consumer's graph may, and Cargo would unify them in), and a response whose
`Content-Encoding` is anything but `identity` (case-insensitive, every header
and every comma-separated coding; an empty value included) is refused as
`Could not fetch the {label} URL.`

A deliberate difference from Python, whose httpx decodes gzip and deflate
(brotli and zstd when installed): decoding returns bytes the server did not
send, under the type it claimed, and with no decoder there is no
decompression bomb to bound. An image fetch keeps it that way
(stridelabs-mcp's `ImageFetcher` never decodes).

A feed fetcher, whose servers compress whatever they are asked for, opts in
with feature `ssrf-decompress` and `.with_decompression(Decompression::GzipDeflate)`:

- **Asked for:** `Accept-Encoding: gzip, deflate`.
- **Classified:** an identity-encoded response is read as before. Otherwise,
  identity tokens are dropped across every `Content-Encoding` header and
  exactly one token must remain: `gzip`, `x-gzip` or `deflate`,
  case-insensitively. Stacked codings (`gzip, gzip`), `br`, `zstd`, and
  anything else are refused.
- **Two caps:** an identity body keeps `max_bytes`. A coded one is capped on
  the wire, declared and streamed, at `max_bytes + max_bytes / 8 + 4096`
  (saturating) — the slack covers incompressible data's stored blocks, and
  the cap stops a server streaming empty members at CPU cost for the whole
  budget — and decoded, at `max_bytes`, inclusive. Either is `TooLarge`.
- **Precedence:** first the deadline: once it has passed, the answer is
  `TimedOut`, whatever the decode came to (a body, `TooLarge`, a
  corruption).
- **Decoded in bounded steps:** the wire body is read whole, then decoded
  with flate2's readers in steps of at most 16 KiB in and 32 KiB out, with a
  `yield_now` between steps — so a cancelled fetch stops at once and no
  blocking thread is left running (the reason it is not `spawn_blocking`).
  A body of thousands of tiny gzip members is many short steps, never one
  long one. The fetch's deadline is checked before every step and again on
  every answer the decode gives, an empty body's included: a decode still
  running when the budget runs out, or answering after it, is `TimedOut`. A
  single step is bounded work, but it is not preempted; the deadline can be
  overrun by at most the step in progress. A step asks for at most one byte
  past what the decoded cap leaves, so passing the cap is `TooLarge` within
  that step, and nothing past the cap is stored.
- **gzip:** every member, back to back (flate2's `MultiGzDecoder`), each
  header and CRC32/ISIZE trailer checked. Anything after a member that is
  not another member, zero padding included, is corrupt.
- **deflate:** zlib-wrapped (`ZlibDecoder`), or raw deflate
  (`DeflateDecoder`) when the body does not start with a zlib header: a
  server that labels raw deflate `deflate`, which browsers accept too. Each
  must reach the stream's end; bytes after the end are ignored.
- **Never a partial body:** corrupt or truncated input is `FetchFailed`. An
  empty wire body is an empty body, with no decode.
- **The headers describe the wire:** `FetchResponse::headers` keeps the
  `Content-Encoding` and `Content-Length` the server sent.
- **Memory:** buffer **capacities**, not only lengths, are capped (each
  buffer grows by doubling, clamped to its cap, and output past the cap is
  refused before anything is reserved for it). At most: the wire buffer's
  cap (`max_bytes + max_bytes / 8 + 4096`), the decoded body's `max_bytes`,
  one 32 KiB step buffer, the inflater's state (its 32 KiB window and
  tables), and, for gzip, the current member's header fields, which flate2
  keeps while it decodes that member (its extra field, file name and
  comment, each at most 64 KiB: about 192 KiB) — a little over
  `2.125 × max_bytes` plus about a quarter of a MiB in all. While a buffer
  grows, the reallocation can briefly hold its previous, smaller allocation
  too. An identity body holds one buffer of at most `max_bytes`. The two
  body buffers (wire and decoded) are reserved fallibly, and a refused
  reservation is `FetchFailed`; the fetch is not otherwise allocation-safe
  (the step buffer, the inflater's state, the gzip header fields and the
  fetch's other small allocations are ordinary ones, which abort on failure
  as anywhere in Rust).

### The address policy

Hand-written, because `IpAddr::is_global` is unstable. Source: the **IANA IPv4
and IPv6 Special-Purpose Address Registries** (both "Last Updated
2025-10-09"), **retrieved 2026-10-17**. Every row whose "Globally Reachable"
is False is denied; rows marked N/A or blank, and globally reachable rows
nested inside a non-reachable block, are decided toward denial.

- **IPv4 denied:** `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (CGNAT),
  `127.0.0.0/8`, `169.254.0.0/16` and `169.254.169.254` by name,
  `172.16.0.0/12`, `192.0.0.0/24` (whole, including its anycast `.9`/`.10`),
  `192.0.2.0/24`, `192.88.99.0/24` (whole: deprecated 6to4 relay + 6a44),
  `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`,
  multicast `224.0.0.0/4`, and `240.0.0.0/4` including `255.255.255.255`.
- **IPv6:** IPv4-mapped `::ffff:0:0/96` and the NAT64 well-known prefix
  `64:ff9b::/96` are unwrapped and the embedded IPv4 judged by the IPv4
  policy. Everything outside Global Unicast `2000::/3` is denied (`::`,
  `::1`, IPv4-compatible, `64:ff9b:1::/48`, `100::/64`, `100:0:0:1::/64`,
  `5f00::/16`, `fc00::/7`, `fe80::/10`, site-local `fec0::/10`, `ff00::/8`,
  every reserved block). Inside it: `2001::/23` (whole — Teredo, benchmarking,
  ORCHID and the reachable anycast/AMT/AS112 more-specifics alike),
  `2001:db8::/32`, `3fff::/20`, and 6to4 `2002::/16` (denied, not unwrapped:
  its IPv4 names a relay, not the host).

Against Python's `ipaddress`-flag policy this denies everything Python denies
except a NAT64 `64:ff9b::/96` address wrapping a *public* IPv4 (Python calls
the whole prefix reserved; unwrapping keeps DNS64 networks working and still
refuses `64:ff9b::169.254.169.254`), and additionally denies `192.0.0.9`,
`192.0.0.10`, `192.88.99.0/24`, the reachable `2001::/23` more-specifics and
`fec0::/10`, which Python lets through. The full table is in the
`is_public_address` docs; the tests check every row at its first and last
address and at both neighbours.

### Pinning and the hostname invariant

Pinning is only as good as the agreement between the name the policy checked,
the name the connection was pinned under, and the name actually requested.
Here that is structural:

- The URL is parsed with `url` (WHATWG: IDNA, lower-casing), trailing dots are
  stripped, and the request URL is **rebuilt around that normalized host**:
  the deny-list, the resolver, the pin, SNI, certificate verification and the
  `Host` header all see one string.
- Each hop builds a **fresh `reqwest::Client`** (no pooled connection carries
  an earlier decision) whose DNS resolver answers **only** that name, with the
  validated address, and errors for every other name — no fallback to system
  DNS. If the request and the pin ever disagreed, the request would fail
  rather than resolve the stranger.
- `no_proxy()`, so neither a configured nor an environment proxy
  (`HTTPS_PROXY`, `ALL_PROXY`) makes the connection; redirects are followed
  here, never by reqwest.
- All answers must be public; IPv4 is preferred for the pin. IP-literal hosts
  skip DNS and are judged directly. The port is the URL's.

### Feed options: the user agent, statuses, the answering hop

```rust
use std::time::Duration;
use http::HeaderValue;
use stridelabs_http::ssrf::{
    fetch_public_response, AcceptedStatuses, AllowedSchemes, Decompression, FetchPolicy,
};

async fn fetch_feed(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let policy = FetchPolicy::new("feed", 10 * 1024 * 1024)
        .with_allowed_schemes(AllowedSchemes::HttpAndHttps)
        .with_timeout(Duration::from_secs(30))
        .with_max_redirects(10)
        .with_accepted_statuses(AcceptedStatuses::AnySuccess)
        .with_user_agent(HeaderValue::from_static("example-feeds/1.0"))
        .with_decompression(Decompression::GzipDeflate); // feature `ssrf-decompress`
    let response = fetch_public_response(url, &policy).await?;
    // response.status, .final_url, .headers, .redirects, .body
    Ok(())
}
```

- **The `User-Agent` is trusted configuration, never a secret.** It goes
  on every hop, cross-host redirects included, to hosts a redirect chooses,
  as `Accept` does. There is no other way to add a request header.
- **Statuses:** `OkOnly` is `== 200`; `AnySuccess` is any 2xx, and a `204`
  or `206` returns its body, possibly empty. Everything else is
  `HttpStatus`.
- **The answer is the last hop's:** `final_url` is the URL it requested —
  normalized (IDNA, lower case, no trailing dot, default port elided, WHATWG
  path rules), never with userinfo — and `status`, `headers` (as parsed, not
  byte-verbatim) and `content_type` are its. `url::Url` is therefore public
  API of `ssrf`, as it already was of `proxy`. **`final_url` and `headers`
  are not client-safe**: they can name the redirect target and carry
  `Set-Cookie`. `FetchResponse`'s `Debug` prints the body length, the
  status, the URL with its query and fragment redacted, the header names and
  the redirect count; `Fetched`'s prints the body length alone.
- **Basic auth stays out:** `user:pass@` is `EmbeddedCredentials` on the
  first URL and on every `Location`, under every option.
- **A default policy is v0.8.0's, byte for byte**: `tests/ssrf_pinning.rs`
  compares a default fetch's request line and full header set against a
  snapshot (`tests/fixtures/default_request.snapshot`) recorded by the same
  test on the v0.8.0 tree, and `fetch_public`'s `Fetched` values against
  v0.8.0's.

### Testing against it

`with_resolver` fakes DNS, so every rejection can be tested with no network.
Proving the *connection* needs a real TLS server — a loopback address behind a
private CA, exactly what the strict policy refuses. The `ssrf-test-support`
feature adds the one way through:

```rust,ignore
use stridelabs_http::ssrf::{FetchPolicy, LoopbackTestServer};

let server = LoopbackTestServer::new("127.0.0.1".parse()?, ca_pem.as_bytes())?;
let policy = FetchPolicy::new("image", 1024)
    .with_resolver(|_host: String, _port| async { Ok(vec!["127.0.0.1".parse().unwrap()]) })
    .with_loopback_test_server(server);
```

It admits **the loopback addresses it names** (`new` takes one, `also_at`
adds another; anything not loopback is refused at construction) next to the
public-address policy — every other private address, a mixed DNS answer
included, is still refused — and trusts **that CA alone** instead of the
platform roots.

What the gate does and does not promise:

- **Without the feature** the type, the policy field and the setter are
  compiled out; no build without it can admit a non-public address.
- **With it**, nothing changes for a policy until code explicitly calls
  `with_loopback_test_server`.
- **Whether it reaches a shipped binary is yours to check.** Enabling it from
  `[dev-dependencies]` keeps it out of a plain `cargo build`, but Cargo
  unifies dev-dependency features into the library under `--all-targets`, and
  a normal dependency anywhere in the workspace can enable it for every
  member. Guard the release graph:

  ```sh
  cargo tree -p <service> -e normal,features -i stridelabs-http --prefix none \
    | grep -F 'stridelabs-http feature "ssrf-test-support"' && exit 1 || true
  ```

This crate's `tests/ssrf_pinning.rs` uses it against an rcgen-issued
certificate for `images.test` to prove the request reaches the pinned address
with SNI and `Host` on the name, that a certificate for another name (or for
the pinned IP) fails, the trailing-dot/IDNA/case normalization end to end,
per-hop re-validation of redirects — including a hop whose predecessor's
server held its connection open (keep-alive) for the same authority while DNS
re-pinned it to a second server on `[::1]` — the body cap over the wire, the
`identity`-only content coding, the budget against a stalled server and
across a chain of individually short hops, and — in a child process born with
`HTTPS_PROXY` set, with a positive control — that an environment proxy is
never used. It also proves the feed options on the wire: the default
request's snapshot, the `Accept` and `User-Agent` on every hop of a
cross-host chain, the status policies, the answering hop's URL, headers and
redirect count, ten redirects followed and the eleventh refused, and (with
`ssrf-decompress`) every coding, both caps, and a corrupt body refused.

### Differences from Python

- **One normalized host string**, enforced by the resolver, instead of
  httpx's `sni_hostname` extension; the URL is rebuilt around it.
- **IPv6 policy differences** as listed under *The address policy*.
- **Alternative IPv4 spellings** (`0x7f.1`, `2130706433`, `127.1`) are parsed
  as the address they are (WHATWG) and judged as literals.
- **The resolver returns `IpAddr`s**, so Python's "an answer that does not
  parse" case cannot arise; an IPv6 scope id is dropped (only link-local and
  multicast carry one, and both are denied).
- **No content coding by default**: `Accept-Encoding: identity`, and any
  other `Content-Encoding` refused rather than decoded; with
  `ssrf-decompress`, gzip and deflate decoded under two caps, where httpx
  decodes the first gzip member only, accepts a truncated one, decodes
  stacked codings and passes unknown ones through (above).
- **Over a real HTTP/1.1 connection an understated `Content-Length` truncates
  the body** (hyper frames by it) instead of overrunning; the streaming cap is
  what bounds a chunked or unframed body, and the unit tests keep Python's
  "lying header" assertion against a raw stream.
