# stridelabs-rust

Shared Rust crates for StrideLabs services — the Rust twin of
[stridelabs-python](https://github.com/charliek/stridelabs-python). Common
patterns and practices live here once, so services stay consistent.

**Status: all eight crates implemented.** The workspace scaffold (Cargo
workspace, CI, toolchain pins) and `stridelabs-config`,
`stridelabs-observability`, `stridelabs-http`, `stridelabs-auth`,
`stridelabs-testing`, `stridelabs-mcp`, `stridelabs-redis` and
`stridelabs-gcp` are all in place. See each crate's own README for its full
API and feature topology.

## Crates

| Crate | Status | Contents | Seeded from |
|---|---|---|---|
| `stridelabs-config` | Implemented | Env-var config helpers + layered file loading with field-pathed errors | Two existing services' config loaders |
| `stridelabs-observability` | Implemented | tracing init (text/JSON/Cloud Logging), request-ID and request-logging tower layers, Prometheus wiring | A production reverse proxy's `observability` module; Python `stridelabs-logging`'s Cloud Logging format and request middleware |
| `stridelabs-http` | Implemented | `AppError`→`IntoResponse` convention, security-headers + CORS layers, graceful shutdown, reverse-proxy primitives (feature `proxy`), an SSRF-hardened outbound fetch (feature `ssrf`), the process-wide rustls provider install (feature `tls`), OpenAPI spec mechanics (feature `openapi`) | An existing service's `error.rs`, a reverse proxy's HTTP layer, the `http/openapi.rs` and `tls.rs` of slauth, the StrideLabs auth service, and Python `stridelabs.mcp.ssrf` |
| `stridelabs-auth` | Implemented | slauth resource-server client: rate-limited JWKS cache, RS256 verification, bearer extraction, slauth PAT validation, PAT hashing, offline test-key minting | An existing service's `auth/` module; Python `stridelabs-auth`'s `PATValidator` |
| `stridelabs-testing` | Implemented | Fail-loud real-Postgres pool and real-Redis probe, `oneshot` axum router-test helpers, a one-line wiremock JSON stub | Existing integration-test idioms, hardened |
| `stridelabs-mcp` | Implemented | The middle of an MCP server on rmcp: RFC 9728 protected-resource metadata, slauth bearer verification at the MCP boundary (audience = the resource URL, 503 on an issuer outage), a stateless Streamable HTTP router, a scoped, rate-limited, audited tool boundary, and slauth PATs as a credential; behind features, a Redis-backed limiter and PAT cache, an SSRF-hardened image fetch and a CORS preset | Python `stridelabs-mcp` (itself extracted from slaudio's MCP surface) |
| `stridelabs-redis` | Implemented | A lazy, single-flight Redis handle: an atomic fixed-window counter that is never replayed, idempotent `GET` / `SET EX` | tapper's hardened rate-limiter connection slot |
| `stridelabs-gcp` | Implemented | Policy-free Google Cloud building blocks on the consumer's `reqwest::Client`: an ADC access-token provider, a small GCS JSON-API client, Vertex AI `generateContent` (feature `vertex`) | tapper's and parcel's GCS clients; google-auth's ADC chain and google-genai's Vertex rules, as imgmcp used them |

See [§ Feature topology](#feature-topology-all-eight-crates) below for what
each crate turns on by default versus behind a feature flag.

## Conventions

- Cargo virtual workspace; lockstep versions via `[workspace.package]`; shared
  `[workspace.lints]` and `[workspace.dependencies]`.
- **`publish = false` on every crate.** These never go to crates.io — see
  [Consuming these crates](#consuming-these-crates) for how a service
  actually depends on them.
- **Tests fail loudly on a missing external dependency — never skip.**
  `stridelabs-testing::require_postgres` is the concrete example: it panics
  with a message naming the env var and the compose/`make up` command rather
  than silently skipping the test, which is exactly the `pool_or_skip()`
  pattern it exists to replace (nine of eleven test files in one service had
  their own copy). A green test suite must mean the behavior it claims to
  cover actually ran.
- OpenAPI default for services: utoipa 6 + utoipa-axum 0.3, Swagger UI dev-gated,
  spec exported and linted in CI.
- Issuer-side JWT helpers stay app-local until a second issuer exists (same
  "defer until a second consumer" rule as stridelabs-python).

## Consuming these crates

None of these crates are published to crates.io (`publish = false`
everywhere) — they're consumed as a **git dependency**, pinned to either a
release tag or a commit rev, fetched over plain `https`.

This repository is public, so it's reachable anonymously over plain `https`
— no credentials needed.

### Adding the dependency

Once a version is tagged, pin the tag:

```toml
[dependencies]
stridelabs-config = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.7.0" }
```

Before the first tag exists — or when depending on a reviewed-but-unreleased
change — pin the exact commit instead:

```toml
[dependencies]
stridelabs-config = { git = "https://github.com/charliek/stridelabs-rust.git", rev = "<full commit sha>" }
```

`rev` pins are meant to be temporary: once the corresponding change is
released and tagged, bump the consumer back to `tag = "vX.Y.Z"` so its
manifest reads the same way for everyone, forever. Every crate is versioned
in lockstep (one `[workspace.package].version` for the whole workspace), so a
consumer pins **one** tag/rev for however many of the eight crates it uses.

### MSRV policy

The minimum supported Rust version is `rust-version` in the workspace
`Cargo.toml` (currently 1.97, in force since v0.2.0). It tracks the minor
version of the pinned toolchain (`rust-toolchain.toml`, currently 1.97.1):
a patch bump of the toolchain leaves it alone, and moving the pin to a new
minor moves it too. Cargo rejects a consumer on an older compiler from the
declared `rust-version` alone, even where the source would still build, so an
MSRV bump is a minor release (0.x), and its CHANGELOG section carries this
line, with X the new version:

> Minimum supported Rust version raised to X. Consumers must be on Rust X or newer. Earlier tags are unaffected.

A tag is immutable, so a consumer pinned to an earlier tag keeps that tag's
manifest and the MSRV it declares. That fixes this workspace's source, not the
consumer's dependency graph: transitive versions come from the consumer's own
`Cargo.lock` (keep it committed), not from this repository's, so a fresh
resolve can pick up a registry release that needs a newer compiler than the
tag declares.

### Local co-development

While iterating on a change to this workspace *and* a consumer at the same
time, override the git dependency with a path via `[patch]` in the
consumer's root `Cargo.toml` — never committed, since it points outside that
repository:

```toml
[patch."https://github.com/charliek/stridelabs-rust.git"]
stridelabs-config = { path = "../stridelabs-rust/crates/config" }
stridelabs-observability = { path = "../stridelabs-rust/crates/observability" }
stridelabs-http = { path = "../stridelabs-rust/crates/http" }
stridelabs-auth = { path = "../stridelabs-rust/crates/auth" }
stridelabs-testing = { path = "../stridelabs-rust/crates/testing" }
stridelabs-mcp = { path = "../stridelabs-rust/crates/mcp" }
stridelabs-redis = { path = "../stridelabs-rust/crates/redis" }
stridelabs-gcp = { path = "../stridelabs-rust/crates/gcp" }
```

`[patch]` keys the whole *source* (the git URL), not one crate — list every
crate from this workspace the consumer actually depends on, whether directly
or transitively (e.g. `stridelabs-auth`'s `http` feature depends on
`stridelabs-http`, so the consumer's `[patch]` block needs both if it uses
that feature). A patch entry for a crate the consumer doesn't depend on is
harmless — Cargo only applies the ones that match a real dependency — so
listing all eight up front, as above, is the simplest thing that stays correct
as a consumer's dependency set grows. The `[patch]` key must match the
`https://…` source URL the consumer's `[dependencies]` actually used.

A patch only takes effect if the consumer's `Cargo.lock` can use it. A consumer
locked to another version of this library (say `0.4.0` while the workspace is
at `0.5.0`) leaves the patch **silently unused** and keeps building the old git
dependency, so after adding the block:

1. Move the locked crates onto it: `cargo update -p stridelabs-config -p
   stridelabs-http …`, one `-p` for each `stridelabs-*` package the consumer's
   `Cargo.lock` names.
2. Check it took: `cargo tree -i stridelabs-config` (or `cargo metadata`) shows
   the local path rather than the git URL. Cargo prints "patch … was not used in
   the crate graph" when it did not.

`scripts/downstream-check.sh` is the automated form: it does both against this
checkout for tapper, slauth, limen or spendwise-rs, then proves with `cargo
metadata` that every `stridelabs-*` package is this checkout's own crate.

### Feature topology (all eight crates)

Every crate that defines optional features defaults to `default = []` — a
consumer opts into the heavier parts of its dependency graph (a TLS stack, a
database driver, a metrics exporter) explicitly, one feature at a time.
`stridelabs-config` is the exception: it has no feature flags at all, since
everything it provides is unconditional. Full detail — including *why* each
gate exists — lives in each crate's own README; this is the map of what turns
on what.

| Crate | Feature | Default | Adds |
|---|---|---|---|
| `stridelabs-config` | *(none — everything is unconditional)* | — | — |
| `stridelabs-observability` | `prometheus` | off | `metrics` + `metrics-exporter-prometheus`: recorder install, `status_class`, `DURATION_BUCKETS` |
| `stridelabs-observability` | `axum` | off | `RequestLogLayer`'s peer-address fallback for `remoteIp`, read from axum's `ConnectInfo<SocketAddr>` |
| `stridelabs-http` | `cors` | off | `cors_layer`, via `tower-http/cors` |
| `stridelabs-http` | `openapi` | off | spec canonicalization, `(method, path)` enumeration, committed-spec freshness check, via `utoipa` |
| `stridelabs-http` | `proxy` | off | reverse-proxy primitives, via `reqwest` (with `rustls`: the aws-lc-rs provider and the OS trust store)/`url`/`bytes`/`futures` |
| `stridelabs-http` | `ssrf` | off | `fetch_public`, the SSRF-hardened fetch of a URL somebody else chose (public-address policy, DNS pinning, capped body), via the same `reqwest`/`url`/`bytes`/`futures` as `proxy` |
| `stridelabs-http` | `ssrf-test-support` | off | `ssrf::LoopbackTestServer`, to point a fetch at a local TLS test server — `[dev-dependencies]` only |
| `stridelabs-http` | `tls` | off | `tls::install_default_provider`, making aws-lc-rs the process's rustls provider, via `rustls` |
| `stridelabs-auth` | `axum` | off | `bearer_token(&Parts)`, via the `http` types crate |
| `stridelabs-auth` | `http` | off | `From<AuthError> for stridelabs_http::AppError` |
| `stridelabs-auth` | `test-support` | off | offline JWT minting against two committed throwaway keypairs |
| `stridelabs-testing` | `postgres` | off | `require_postgres`, via `sqlx`'s Postgres driver + `url` |
| `stridelabs-testing` | `redis` | off | `require_redis`, via redis-rs (no TLS) + `url` |
| `stridelabs-mcp` | `test-support` | off | MCP access-token minting for a `ProtectedResource` (via `stridelabs-auth/test-support`) and the committed `tools/list` freshness check; with `image-fetch`, also stridelabs-http's `ssrf-test-support` |
| `stridelabs-mcp` | `cors` | off | `cors_layer()`, the app-wide CORS preset, via `tower-http/cors` |
| `stridelabs-mcp` | `redis` | off | `RedisRateLimiter` and `RedisPatCache`, via `stridelabs-redis` |
| `stridelabs-mcp` | `image-fetch` | off | `ImageFetcher`, via stridelabs-http's `ssrf` + `base64` |
| `stridelabs-mcp` | `live-tests` | off | **not for consumers**: compiles the crate's real-Redis suite |
| `stridelabs-redis` | `live-tests` | off | **not for consumers**: compiles the crate's real-Redis suite (everything else is unconditional) |
| `stridelabs-gcp` | `service-account-key` | off | `service_account` credentials: RS256 assertion signing via jsonwebtoken's `use_pem` |
| `stridelabs-gcp` | `vertex` | off | the `vertex` module (no extra dependency) |

`stridelabs-testing`'s `oneshot` and `wiremock` modules have no feature gate
of their own — both are cheap and every consumer of the crate wants them; only
the Postgres driver and the Redis client are worth gating.

`stridelabs-http`'s `proxy` and `ssrf` are the only features anywhere here
that turn on reqwest's TLS (`stridelabs-mcp`'s `image-fetch` reaches it
through `ssrf`); `stridelabs-http`'s `tls` adds a direct `rustls` dependency
only to install the provider. `stridelabs-redis` turns on redis-rs's
`tokio-rustls-comp` for `rediss://`, so `stridelabs-mcp`'s `redis` brings
rustls too, with no crypto provider of its own (see below).
`stridelabs-auth`, `stridelabs-gcp` and `stridelabs-mcp`'s core have none —
they take the consumer's `reqwest::Client`, so the TLS stack and the
process's rustls provider stay the consumer's choice (and `stridelabs-mcp`
builds rmcp with no HTTP-client feature) — and `stridelabs-testing`'s Postgres
pool and Redis probe talk to their servers in the clear.

### One crypto provider: aws-lc-rs

`stridelabs-auth` signs and verifies JWTs with jsonwebtoken 11's `aws_lc_rs`
backend (as does `stridelabs-gcp`'s `service-account-key`), and `proxy`'s and
`ssrf`'s TLS uses rustls's aws-lc-rs provider. jsonwebtoken (10+) and rustls
both choose their crypto from crate features at runtime, and Cargo unifies
features across a consumer's whole graph, so a second backend anywhere in
that graph does not fail the build: the process panics at its first JWT sign
or verify, or its first `rustls::ClientConfig::builder()`. The consumer rule:

- **Never enable jsonwebtoken `rust_crypto`**, on your own jsonwebtoken or
  anywhere else in your graph. Next to this workspace's `aws_lc_rs` it makes
  jsonwebtoken panic, `stridelabs-auth`'s verification and test-token minting
  included, and it brings back the `rsa` crate (RUSTSEC-2023-0071, no fix).
- **Use aws-lc-rs as the only rustls provider**: no rustls `ring` feature
  (redis-rs 0.27's `tls-rustls`, sqlx `tls-rustls-ring`, …). Install it as
  the process default at startup, before anything connects:
  `stridelabs_http::tls::install_default_provider()` (feature `tls`). A
  `rediss://` dial through `stridelabs-redis` needs it, since that crate
  picks no provider of its own, and so does any other
  `rustls::ClientConfig::builder()` your graph relies on.

Nothing checks either rule at compile time. For the jsonwebtoken half, a test
that mints and verifies a token (`stridelabs_auth::test_support`, feature
`test-support`) panics in your own CI when the rule is broken; this
workspace's own tests do exactly that.
