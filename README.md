# stridelabs-rust

Shared Rust crates for StrideLabs services — the Rust twin of
[stridelabs-python](https://github.com/charliek/stridelabs-python). Common
patterns and practices live here once, so services stay consistent.

**Status: bootstrapped.** The workspace scaffold (Cargo workspace, CI, toolchain
pins) and the first four crates — `stridelabs-config`,
`stridelabs-observability`, `stridelabs-http` and `stridelabs-auth` — are
implemented. The remaining crate below is still planned. See
`slauth/plans/rust-migration.md` for scope and sequencing, and each crate's
own README once it lands.

## Crates

| Crate | Status | Contents | Seeded from |
|---|---|---|---|
| `stridelabs-config` | Implemented | Env-var config helpers + layered file loading with field-pathed errors | spendwise-rs `config.rs`, limen `config/load.rs` |
| `stridelabs-observability` | Implemented | tracing init (json/pretty), request-ID tower layer, Prometheus wiring | limen `observability/` |
| `stridelabs-http` | Implemented | `AppError`→`IntoResponse` convention, security-headers + CORS layers, graceful shutdown, reverse-proxy primitives (feature `proxy`) | spendwise-rs `error.rs`, limen `http/` |
| `stridelabs-auth` | Implemented | slauth resource-server client: rate-limited JWKS cache, RS256 verification, bearer extraction, PAT hashing, offline test-key minting | spendwise-rs `auth/` |
| `stridelabs-testing` | Planned | `oneshot` router-test helpers, fail-loud real-Postgres harness, wiremock conveniences | spendwise-rs test idioms, hardened |

## Conventions

- Cargo virtual workspace; lockstep versions via `[workspace.package]`; shared
  `[workspace.lints]` and `[workspace.dependencies]`.
- Consumed as a **git dependency** pinned to a tag (release-accepted) or a
  commit rev (PR-accepted, pending release):

  ```toml
  [dependencies]
  stridelabs-config = { git = "ssh://git@github.com/charliek/stridelabs-rust.git", tag = "v0.1.0" }
  ```

  For local co-development against an unpublished change, override it with
  `[patch]` in the consumer's root `Cargo.toml`:

  ```toml
  [patch."ssh://git@github.com/charliek/stridelabs-rust.git"]
  stridelabs-config = { path = "../stridelabs-rust/crates/config" }
  ```

- Integration tests **fail loudly** when a required dependency (e.g. Postgres)
  is unreachable — never skip.
- OpenAPI default for services: utoipa 5 + utoipa-axum, Swagger UI dev-gated,
  spec exported and linted in CI.
- Issuer-side JWT helpers stay app-local until a second issuer exists (same
  "defer until a second consumer" rule as stridelabs-python).
