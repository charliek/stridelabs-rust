# stridelabs-rust

Shared Rust crates for StrideLabs services — the Rust twin of
[stridelabs-python](https://github.com/charliek/stridelabs-python). Common
patterns and practices live here once, so services stay consistent.

**Status: all five crates implemented.** The workspace scaffold (Cargo
workspace, CI, toolchain pins) and `stridelabs-config`,
`stridelabs-observability`, `stridelabs-http`, `stridelabs-auth` and
`stridelabs-testing` are all in place. See each crate's own README for its
full API and feature topology.

## Crates

| Crate | Status | Contents | Seeded from |
|---|---|---|---|
| `stridelabs-config` | Implemented | Env-var config helpers + layered file loading with field-pathed errors | Two existing services' config loaders |
| `stridelabs-observability` | Implemented | tracing init (json/pretty), request-ID tower layer, Prometheus wiring | A production reverse proxy's `observability` module |
| `stridelabs-http` | Implemented | `AppError`→`IntoResponse` convention, security-headers + CORS layers, graceful shutdown, reverse-proxy primitives (feature `proxy`), OpenAPI spec mechanics (feature `openapi`) | An existing service's `error.rs`, a reverse proxy's HTTP layer, and the `http/openapi.rs` of slauth, the StrideLabs auth service |
| `stridelabs-auth` | Implemented | slauth resource-server client: rate-limited JWKS cache, RS256 verification, bearer extraction, PAT hashing, offline test-key minting | An existing service's `auth/` module |
| `stridelabs-testing` | Implemented | Fail-loud real-Postgres pool, `oneshot` axum router-test helpers, a one-line wiremock JSON stub | Existing integration-test idioms, hardened |

See [§ Feature topology](#feature-topology-all-five-crates) below for what
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
- OpenAPI default for services: utoipa 5 + utoipa-axum, Swagger UI dev-gated,
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
stridelabs-config = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.4.0" }
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
consumer pins **one** tag/rev for however many of the five crates it uses.

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
```

`[patch]` keys the whole *source* (the git URL), not one crate — list every
crate from this workspace the consumer actually depends on, whether directly
or transitively (e.g. `stridelabs-auth`'s `http` feature depends on
`stridelabs-http`, so the consumer's `[patch]` block needs both if it uses
that feature). A patch entry for a crate the consumer doesn't depend on is
harmless — Cargo only applies the ones that match a real dependency — so
listing all five up front, as above, is the simplest thing that stays correct
as a consumer's dependency set grows. The `[patch]` key must match the
`https://…` source URL the consumer's `[dependencies]` actually used.

### Feature topology (all five crates)

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
| `stridelabs-http` | `cors` | off | `cors_layer`, via `tower-http/cors` |
| `stridelabs-http` | `openapi` | off | spec canonicalization, `(method, path)` enumeration, committed-spec freshness check, via `utoipa` |
| `stridelabs-http` | `proxy` | off | reverse-proxy primitives, via `reqwest`/`url`/`bytes`/`futures` |
| `stridelabs-auth` | `axum` | off | `bearer_token(&Parts)`, via the `http` types crate |
| `stridelabs-auth` | `http` | off | `From<AuthError> for stridelabs_http::AppError` |
| `stridelabs-auth` | `test-support` | off | offline JWT minting against two committed throwaway keypairs |
| `stridelabs-testing` | `postgres` | off | `require_postgres`, via `sqlx`'s Postgres driver + `url` |

`stridelabs-testing`'s `oneshot` and `wiremock` modules have no feature gate
of their own — both are cheap and every consumer of the crate wants them; only
the Postgres driver is worth gating.
