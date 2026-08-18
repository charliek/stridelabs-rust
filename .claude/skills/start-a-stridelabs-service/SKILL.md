---
name: start-a-stridelabs-service
description: Scaffold a new StrideLabs axum service from scratch, wired onto the five stridelabs-{config,observability,http,auth,testing} crates with the openapi feature (committed spec + freshness test + route-pinning test + Spectral CI) from the first commit. Use when starting a brand-new Rust service in the StrideLabs fleet — a cold session with no other context should be able to follow this alone and end with a compiling service that documents itself correctly.
---

# Start a StrideLabs service

This skill scaffolds a new axum-based Rust service the way the `backend-rs`
service of slauth, the StrideLabs auth service, and this workspace's own
conventions expect: the five
`stridelabs-*` crates as dependencies, `AppError` from `stridelabs-http`
instead of a hand-rolled error type, and an OpenAPI document that is
committed, tested for freshness, and pinned to an exact route list from
commit one — not bolted on later.

**This skill teaches mechanics and gotchas. It does not restate the crates'
own documentation.** Read the crate READMEs for API details as you go —
this skill tells you *which* function to reach for and *why the pitfalls
exist*, not what every parameter does:

- `crates/config/README.md` — env-var + layered-file config
- `crates/observability/README.md` — tracing init, request-id layer, Prometheus
- `crates/http/README.md` — `AppError`, security headers, `methods`, `openapi`, `proxy`
- `crates/auth/README.md` — JWKS verification, PAT hashing
- `crates/testing/README.md` — fail-loud Postgres pool, oneshot router tests, wiremock stub
- root `README.md` — consuming these crates (git dep forms, `[patch]` local co-dev, feature topology table)

All five paths above are relative to the `stridelabs-rust` checkout this
skill lives in.

## Before you start

### Reaching `cargo`

This workspace's Rust toolchain is mise-managed, not a bare PATH install
(`CLAUDE.md`: "Reach Cargo through mise: `mise exec -- cargo …`"). `mise
exec` resolves its toolchain pin from a `.mise.toml` in the **current**
directory (or an ancestor) — running it from somewhere with no `.mise.toml`
above it does not fall back to `stridelabs-rust`'s pin just because that
checkout happens to be a sibling directory. Give the new service its own
pin, matching `stridelabs-rust`'s (Step 1 lists this file):

```toml
# .mise.toml, at the new service's root
[tools]
rust = "1.97.1"
```

Run `mise trust` once from the new service's directory before the first
`mise exec` call — a `.mise.toml` mise has never seen before (any fresh
clone or, here, a scaffold that just wrote its own) is untrusted by default,
and `mise exec` refuses to read it until you do, failing with a trust
error rather than silently falling back to a bare `cargo`.

With that in place, every `cargo` invocation below — from inside the new
service's directory — is `mise exec -- cargo ...`. If `mise` genuinely isn't
installed in a given environment, a bare `cargo`/`rustc` on PATH is the
fallback (same posture `scripts/lint.sh` and the `cargo-fmt-check`
pre-commit hook take elsewhere in this fleet) — try `mise exec -- cargo
--version` first and fall back to plain `cargo --version` only if that
errors.

## Before you start: two decisions

### 1. Choosing how to consume the crates

Check whether a local checkout of `stridelabs-rust` exists as a **sibling
directory** of the new service — i.e. `../stridelabs-rust/crates` exists
relative to the new service's root:

- **If it exists** (local co-development, or a sandboxed/offline
  environment with no guaranteed GitHub auth — including a cold-run of this
  very skill): use **path dependencies** straight into that checkout. No
  network fetch, no auth needed, and it always resolves to exactly the code
  on disk. This is the mechanism this skill's own cold-run tests use.

  ```toml
  [dependencies]
  stridelabs-config = { path = "../stridelabs-rust/crates/config" }
  stridelabs-observability = { path = "../stridelabs-rust/crates/observability" }
  stridelabs-http = { path = "../stridelabs-rust/crates/http", default-features = false, features = ["openapi"] }
  stridelabs-auth = { path = "../stridelabs-rust/crates/auth" }

  [dev-dependencies]
  stridelabs-testing = { path = "../stridelabs-rust/crates/testing" }
  ```

- **If it does not exist**: use the real **git dependency** form — this is
  what a production service's committed `Cargo.toml` should carry, and what
  CI will actually fetch. Pin a tag if one is cut; otherwise pin the exact
  commit `rev`. See the root README's "Consuming these crates" section for
  the exact `tag =` / `rev =` forms.

  ```toml
  [dependencies]
  stridelabs-config = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.4.0" }
  # ... same git =/tag = for the other four crates, feature flags as below
  ```

A service that starts in path-dependency mode (local co-dev) and later
moves to a real repo should switch every `stridelabs-*` line to the git
form before its first CI run — CI has no sibling checkout on disk. The
`templates/ci.yml` skeleton below assumes the git form and says so.

Don't try to detect this automatically inside `Cargo.toml` itself (Cargo has
no conditional dependency sources) — decide once, at scaffold time, and
write the form that matches your situation.

### 2. Templates vs. instructions

Three files below are provided as **verbatim templates** in this skill's
`templates/` directory, because getting them almost-right is worse than not
having them: `.spectral.yaml` (a wrong or missing pin silently changes what
CI lints), the `.gitattributes` fragment (a missing line makes the freshness
test fail mysteriously and only on some checkouts), and a CI workflow
skeleton (the lane list itself — fmt / clippy --all-features -D warnings /
test / doc / Spectral — is easy to get subtly wrong, e.g. forgetting
`--all-features` on clippy and missing a feature-gated lint). Everything
else below (Cargo.toml shape, source layout, the openapi wiring) is
instructions with example code inline, because it necessarily varies by
service name, route list, and domain — a template would just be
copy-pasted and renamed anyway.

## Step 1 — crate layout

A new service is a plain Cargo **package** (not a workspace) with both a
`[lib]` and a `[[bin]]` target, matching the shape of slauth's `backend-rs` — the
lib target is what lets `tests/openapi_shape.rs` (an integration test,
outside the crate) import the service's own `openapi::spec()`.

```text
<service>/
  Cargo.toml
  Cargo.lock                  # generated + COMMITTED before the first CI run — see below
  rust-toolchain.toml        # pin the same toolchain stridelabs-rust pins (see its rust-toolchain.toml)
  .mise.toml                  # same pin, mise form — see "Reaching cargo" above
  .gitattributes             # the templates/gitattributes.fragment line
  .spectral.yaml             # templates/.spectral.yaml, verbatim
  openapi.json                # committed; generated in Step 5
  src/
    lib.rs
    main.rs
    state.rs                  # AppState
    openapi.rs                 # ApiDoc + router() + spec() — Step 4
    health.rs                  # plain axum, deliberately unannotated — Step 3
    ping.rs                    # (or your first real route) utoipa-annotated — Step 4
  tests/
    openapi_shape.rs           # Step 5
  .github/workflows/ci.yml    # templates/ci.yml, filled in
```

Copy `templates/.spectral.yaml` and `templates/ci.yml` verbatim (filling in
the `<service>` name and toolchain version in the CI file's comments/
`toolchain:` line). Append `templates/gitattributes.fragment`'s content to
`.gitattributes` (create the file if the service has none yet).

`.spectral.yaml` is a dotfile — a bare `ls` in the new service's root won't
show it, so a copy that silently failed (wrong destination, typo'd filename)
is easy to miss. Confirm it's actually there with `ls -a` (or `ls -la`)
before moving on.

**Generate and commit `Cargo.lock` before enabling CI.** `templates/ci.yml`
runs `cargo clippy`, `cargo test`, `cargo build` and `cargo doc` all with
`--locked` — that flag makes Cargo error out, rather than write a fresh
lockfile, whenever `Cargo.lock` is missing or stale. Run `cargo build` (or
`mise exec -- cargo build`) once locally after `Cargo.toml` has its real
dependency set (Step 2) to generate the file, then commit it alongside the
rest of the scaffold — a scaffold pushed without it fails every `--locked`
step in the first CI run.

## Step 2 — `Cargo.toml`

```toml
[package]
name = "pingd"                # replace with the service's real name throughout
version = "0.1.0"
edition = "2021"
rust-version = "1.97"

[lib]
name = "pingd"
path = "src/lib.rs"

[[bin]]
name = "pingd"
path = "src/main.rs"

[dependencies]
tokio = { version = "1", features = ["full"] }
axum = "0.8"
tower = { version = "0.5", features = ["util"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"

# utoipa: default features on, so the derive macros come along. Pin the
# same MAJOR this workspace's stridelabs-http/openapi feature builds
# against (utoipa = "5") — verify against stridelabs-rust/Cargo.toml if in
# doubt, since a mismatched major here vs. what utoipa-axum expects fails
# to compile with a confusing trait-not-satisfied error, not a version
# error.
utoipa = { version = "5" }
utoipa-axum = "0.2"

# The five stridelabs-* crates — see "Choosing how to consume the crates"
# above for path vs. git dependency form. `stridelabs-http` needs its
# `openapi` feature turned on (off by default — see that crate's README
# feature-topology table); `default-features = false` is NOT required
# unless you also want to opt out of something else this service doesn't
# use (nothing here does, so it's shown for clarity, not necessity).
stridelabs-config = { path = "../stridelabs-rust/crates/config" }
stridelabs-observability = { path = "../stridelabs-rust/crates/observability" }
stridelabs-http = { path = "../stridelabs-rust/crates/http", features = ["openapi"] }
# `stridelabs-auth` has no unconditional route in a brand-new service —
# still declared per the house convention (every service starts on all
# five crates), with its `axum`/`http` features turned on the moment a
# route needs `Verifier`/`bearer_token`. A ping-only service can leave both
# off; see crates/auth/README.md's feature table before your first
# protected route.
stridelabs-auth = { path = "../stridelabs-rust/crates/auth" }

# The one sanctioned `anyhow` boundary — see the requirement right below.
# Declared here, not left implicit, so the Step 3 handler example (which
# does `?` into `anyhow::Result`) actually compiles as written.
anyhow = "1"

[dev-dependencies]
stridelabs-testing = { path = "../stridelabs-rust/crates/testing" }
tower = { version = "0.5", features = ["util"] }
http-body-util = "0.1"
```

Requirement, not a suggestion: **no `anyhow` outside `AppError::Internal`.**
`stridelabs-http::AppError` already carries the one sanctioned `anyhow`
boundary (see its README's "Why `anyhow` is in a shared crate's public API"
section) — a handler that needs to bail out of a zoo of fallible calls does
so with `?` into `anyhow::Result`, converted at the boundary via
`AppError::Internal`'s `#[from]`. Nowhere else in the service should import
`anyhow` directly; every other error surface is a `thiserror` enum, matched
on, not stringified.

## Step 3 — `AppState`, `main.rs`, and the unannotated health route

Use `stridelabs_http::AppError` as the handler error type — do not write a
new one. If the service later needs domain-specific errors, model them as a
`thiserror` enum and either implement `From<YourError> for AppError`
mapping each variant to a real status, or fold them into
`anyhow::Error` and let `?` cross into `AppError::Internal` (only when the
detail really is meant to be opaque to the client).

```rust
// src/state.rs
#[derive(Clone)]
pub struct AppState {
    // fields as the service needs them (a DB pool, a Verifier, ...) — empty
    // is fine for a service with no routes that need shared state yet.
}
```

```rust
// src/health.rs — deliberately PLAIN axum, never utoipa. This is what
// keeps /health out of the OpenAPI document BY CONSTRUCTION (see Step 4's
// gotcha #1) rather than by remembering to exclude it.
use axum::routing::get;
use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/health", get(|| async { "ok" }))
}
```

```rust
// src/main.rs
use axum::routing::get;
use axum::Router;

mod health;
mod openapi;
mod ping;
mod state;

#[tokio::main]
async fn main() {
    // `svc openapi > openapi.json` — the CLI subcommand the freshness test
    // and CI's regeneration instructions both point at. No config, no
    // listener: openapi::spec() builds without an AppState (see Step 4).
    if std::env::args().nth(1).as_deref() == Some("openapi") {
        println!("{}", stridelabs_http::openapi::to_pretty_json(&openapi::spec()));
        return;
    }

    stridelabs_observability::init_logging(stridelabs_observability::LogFormat::Text, "info");

    let state = state::AppState {};

    // split_for_parts() hands back the plain axum Router<AppState> half to
    // merge here, and the OpenApi document half — the proven pattern this
    // is lifted from (slauth's backend-rs `src/http/server.rs`). Do NOT call
    // `.with_state()` on the OpenApiRouter directly and try to convert that
    // into a plain Router to merge — split first, merge the axum half, and
    // apply `.with_state()` once at the very end of the whole Router chain,
    // same as any other axum router built from several merged pieces.
    let (api_v1, api_doc) = openapi::router().split_for_parts();
    let spec_json: std::sync::Arc<str> = stridelabs_http::openapi::to_pretty_json(&api_doc).into();

    let app: Router = Router::new()
        .merge(health::router())
        .route(
            "/openapi.json",
            get(move || {
                let spec_json = spec_json.clone();
                async move { ([("content-type", "application/json")], spec_json.to_string()) }
            }),
        )
        .merge(api_v1)
        .with_state(state)
        .layer(stridelabs_http::security_headers());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(stridelabs_http::shutdown_signal())
        .await
        .unwrap();
}
```

```rust
// src/lib.rs — exists so tests/openapi_shape.rs can `use <service>::openapi`.
pub mod openapi;
pub mod ping;
pub mod state;
```

## Step 4 — the OpenAPI document: `src/openapi.rs` and the first annotated route

This is the load-bearing part. `stridelabs_http::openapi` (feature
`openapi`) already carries the spec MECHANICS this used to require
hand-writing (canonical JSON serializer, exhaustive `(method, path)`
enumeration, committed-file freshness check) — extracted from exactly this
pattern in slauth's own service. **Use its functions directly; do not
re-derive them.**
The service only writes the document's *policy*: what `info`/`tags`/
`servers` say, which routers get merged in, and the version prefix.

```rust
// src/ping.rs — a utoipa-annotated route, i.e. IN the document.
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::state::AppState;

#[derive(serde::Serialize, ToSchema)]
pub struct Pong {
    pub message: String,
}

// The explicit `description =` matters: Spectral's operation-description
// rule runs at Step 7's `--fail-severity=warn`, and a one-line doc comment
// becomes only the `summary` — utoipa maps only lines after the first to
// `description` (see templates/.spectral.yaml's header).
#[utoipa::path(
    get,
    path = "/ping",
    tag = "ping",
    description = "Liveness example — returns a static pong body.",
    responses((status = 200, body = Pong))
)]
async fn ping() -> axum::Json<Pong> {
    axum::Json(Pong { message: "pong".to_string() })
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(ping))
}
```

```rust
// src/openapi.rs
use utoipa::OpenApi as OpenApiDerive;
use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

#[derive(OpenApiDerive)]
#[openapi(
    info(
        title = "pingd",
        version = "0.1.0",
        // Spectral's info-description rule wants more than the title
        // restated — replace this with a real paragraph covering what the
        // service's API surface is and what it deliberately excludes
        // (health checks, internal-only routes).
        description = "Example ping service scaffolded by the \
                        start-a-stridelabs-service skill — replace this \
                        with a real description of the service's API \
                        surface.",
        // Satisfies Spectral's info-contact rule (contact-properties, off
        // by default, additionally wants all three of name/url/email — cheap
        // to satisfy now). Replace with this service's real owner/contact.
        contact(
            name = "StrideLabs",
            url = "https://github.com/charliek/stridelabs-rust",
            email = "engineering@stridelabs.example"
        )
    ),
    // Spectral's oas3-api-servers rule wants a non-empty `servers` array —
    // see templates/.spectral.yaml's header comment.
    servers((url = "/", description = "This service, relative to wherever it is deployed.")),
    // The load-bearing rule here is operation-tag-defined: every tag a
    // route uses (here, `ping.rs`'s `#[utoipa::path(tag = "ping")]`) must
    // be declared in this document-level `tags` array — declaring it here,
    // not just on the route, is what avoids a fix-and-regenerate cycle at
    // Step 7's Spectral lint. Add one entry per tag the service actually
    // uses. (openapi-tags/tag-description are off by default; the
    // description is cheap to carry anyway.)
    tags(
        (name = "ping", description = "Liveness/example route — replace with this service's real tags.")
    )
)]
struct ApiDoc;

/// Nested under `/v1` with `OpenApiRouter::nest` — see the gotcha below on
/// why `nest`, never `merge`, and never a conversion to `axum::Router`
/// first.
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi()).nest("/v1", crate::ping::router())
}

/// The document alone — what the `openapi` CLI subcommand, the freshness
/// test, and the route-pinning test all read from. Building it needs no
/// `AppState`: `OpenApiRouter<S>` is generic over `S` purely as a marker
/// until `.with_state()` is called.
pub fn spec() -> utoipa::openapi::OpenApi {
    router().split_for_parts().1
}
```

### Gotcha 1 — structural exclusion has a silent hole; the route-pinning test is the actual guard

A route reaches the document by living on an `OpenApiRouter` built with
`.routes(routes!(...))`. `src/health.rs` above never imports `utoipa` at
all, so `/health` is excluded *structurally* — there's no flag to flip and
no exclusion list to keep in sync. **This is convention, not the guard.**
`OpenApiRouter::route`/`route_service` are silent pass-throughs to their
`axum::Router` equivalents: they register a live route and add *nothing* to
the document. A route registered that way is live and undocumented without
ever leaving `OpenApiRouter` — the escape hatch is silent. The actual guard
is a route-pinning test (Step 5) asserting the exact `(method, path)` set:
that's what turns a `.route` that should have been `.routes(routes!(...))`
into a failing assertion instead of a quiet gap.

### Gotcha 2 — `OpenApiRouter::nest`, never `merge`, never `axum::Router::nest`

**Verified against this workspace's own vendored `utoipa-axum` 0.2.0
source** (`~/.cargo/registry/src/.../utoipa-axum-0.2.0/src/router.rs`,
`nest`/`merge` — this claim has been stated wrong in this fleet's docs
twice before, so it is stated here only after reading the actual
implementation, not carried forward from memory):

- `OpenApiRouter::nest(prefix, router)` prefixes **both halves**: it calls
  `self.0.nest(path, router.0)` on the underlying `axum::Router` AND
  `self.1.nest_with_path_composer(...)` on the `utoipa::openapi::OpenApi`
  paths, with the same path-composition logic — so the document's path keys
  and the live axum routes agree, byte for byte.
- `OpenApiRouter::merge(router)` takes **no path argument at all** and
  combines both halves as-is (`self.0.merge(router.0)`,
  `self.1.merge(router.1)`) — the right tool for assembling sibling
  routers that don't need a shared prefix, the wrong one for applying a
  version prefix.
- The drift hazard: converting to a bare `axum::Router` first (via
  `.into()`/`split_for_parts()`) and nesting *that* — `axum::Router::nest`
  only prefixes the runtime routes; the OpenAPI document (built separately,
  or already split off) keeps its unprefixed path keys, and the spec
  silently describes URLs the service doesn't serve at those keys. Nothing
  in the type system stops this; the route-pinning test (Step 5) is what
  catches it, because the prefixed paths simply won't be in
  `documented_pairs`'s output.

`src/ping.rs`'s router is merged into `src/openapi.rs`'s document via
`.nest("/v1", ...)` above for exactly this reason — never swap it for
`.merge(...)` if the intent is a version prefix.

### Gotcha 3 — the committed spec file must be LF, always

Covered by `templates/gitattributes.fragment` (Step 1) — `check_committed_spec`
compares the committed file byte-for-byte against a fresh export, and the
export side always writes LF. Skipping the `.gitattributes` line means the
freshness test fails on every line on a checkout with `core.autocrlf=true`,
with nothing wrong in the spec itself.

## Step 5 — the two openapi tests, and the committed file

```rust
// tests/openapi_shape.rs
use pingd::openapi; // replace `pingd` with the service's crate name
use stridelabs_http::openapi::{assert_committed_spec_is_fresh, documented_pairs, expected_pairs};

/// The route-pinning test — Gotcha 1's actual guard. An exact
/// (method, path) snapshot: a route added without #[utoipa::path], or one
/// annotated that should have stayed excluded, changes this set and fails
/// loudly here instead of drifting silently.
#[test]
fn the_documented_path_method_set_is_exact() {
    assert_eq!(
        documented_pairs(&openapi::spec()),
        expected_pairs(&[("GET", "/v1/ping")]),
    );
}

/// The freshness gate: openapi.json must be exactly what `<service>
/// openapi` prints today. CI's Spectral step lints the CONTENT of the
/// committed file; this is what proves the committed file is still what
/// the code actually exports.
#[test]
fn the_committed_openapi_json_matches_a_fresh_export() {
    assert_committed_spec_is_fresh(
        concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.json"),
        &openapi::spec(),
        "cargo run --bin pingd -- openapi > openapi.json",
    );
}
```

Generate and commit the spec file itself — don't hand-write it:

```bash
mise exec -- cargo run --bin pingd -- openapi > openapi.json
mise exec -- cargo test    # both tests above must pass, including the freshness check
bunx @stoplight/spectral-cli@6.16.2 lint openapi.json --fail-severity=warn
```

If the freshness test fails immediately after this with a CRLF-shaped diff
(every line differs), you skipped Step 1's `.gitattributes` line and need to
re-checkout the file after adding it.

## Step 6 — conventions checklist (state these as requirements, not suggestions)

- **Typed (`thiserror`) errors everywhere except the one sanctioned
  `anyhow` boundary**: `AppError::Internal`. No other `anyhow::Error` in a
  public function signature anywhere in this service.
- **Tests fail loudly, never skip.** `stridelabs_testing::require_postgres`
  is the house pattern: it panics naming the env var and the command to
  bring the dependency up, rather than printing a note and returning `None`.
  Do not write a `pool_or_skip()`-shaped helper for any external dependency
  a service's tests need — a green suite must mean the behavior it claims
  to cover actually ran.
- **No env mutation in tests.** `std::env::set_var` in a test races every
  other test in the same binary (Rust runs tests in threads within one
  process). `stridelabs-config`'s `env_or`/`env_parse` and
  `stridelabs-testing`'s `require_postgres` both route through an
  *injectable lookup* internally for exactly this reason — follow the same
  pattern for anything this service reads from the environment in a way its
  own tests need to vary: inject the lookup, don't mutate the process.
- **`OpenApiRouter::nest` for versioning, never `merge`** — Gotcha 2.
- **The route-pinning test is not optional** — a service with routes but no
  `documented_pairs` assertion has structural exclusion with no guard on
  the escape hatch (Gotcha 1).

## Step 7 — final verification (what "done" means)

```bash
mise exec -- cargo build                                  # compiles
mise exec -- cargo test                                   # openapi freshness + route-pinning tests pass
mise exec -- cargo fmt --all -- --check
mise exec -- cargo clippy --all-targets --all-features -- -D warnings
bunx @stoplight/spectral-cli@6.16.2 lint openapi.json --fail-severity=warn
```

All five must be clean before considering the scaffold finished. This is
also exactly what `templates/ci.yml`'s `build-test` job runs — a green local
run here is a green CI run there (once the service's `Cargo.toml` is on the
git-dependency form; see "Choosing how to consume the crates" above).
