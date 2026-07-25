# stridelabs-rust

Shared Rust crates for StrideLabs services — the Rust twin of
[stridelabs-python](https://github.com/charliek/stridelabs-python). Common
patterns and practices live here once, so services stay consistent.

**Status: pre-bootstrap.** The workspace is scaffolded by slice 02 of the slauth
Rust migration roadmap (`slauth/plans/rust-migration.md`), which is the source of
truth for scope and sequencing until this repo is established.

## Planned crates

| Crate | Contents | Seeded from |
|---|---|---|
| `stridelabs-config` | Env-var config helpers + layered file loading with field-pathed errors | spendwise-rs `config.rs`, limen `config/load.rs` |
| `stridelabs-observability` | tracing init (json/pretty), request-ID tower layer, Prometheus wiring | limen `observability/` |
| `stridelabs-http` | `AppError`→`IntoResponse` convention, security-headers + CORS layers, proxy primitives, graceful shutdown | spendwise-rs `error.rs`, limen `http/` |
| `stridelabs-auth` | slauth resource-server client: JWKS cache, RS256 verification, PAT hashing, offline test-key minting | spendwise-rs `auth/` |
| `stridelabs-testing` | `oneshot` router-test helpers, fail-loud real-Postgres harness, wiremock conveniences | spendwise-rs test idioms, hardened |

## Conventions (to be codified during bootstrap)

- Cargo virtual workspace; lockstep versions via `[workspace.package]`; shared
  `[workspace.lints]` and `[workspace.dependencies]`.
- Consumed as a **git dependency** pinned to a tag, with `[patch]` for local
  co-development.
- Integration tests **fail loudly** when a required dependency (e.g. Postgres)
  is unreachable — never skip.
- OpenAPI default for services: utoipa 5 + utoipa-axum, Swagger UI dev-gated,
  spec exported and linted in CI.
- Issuer-side JWT helpers stay app-local until a second issuer exists (same
  "defer until a second consumer" rule as stridelabs-python).
