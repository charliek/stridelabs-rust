# CLAUDE.md — stridelabs-rust conventions

Conventions and context for working in this repository (for contributors and
coding agents). Read this before making changes.

## What this is

Shared Rust crates for StrideLabs services — the Rust twin of
[stridelabs-python](https://github.com/charliek/stridelabs-python). Patterns
that show up in every service (config loading, observability, HTTP
error/CORS/proxy plumbing, JWT verification against slauth — the StrideLabs
auth service — test harnesses) are solved once here instead of copy-pasted per
repo. The crates are extracted from existing StrideLabs services (same
author, near identical conventions), then proven by adopting them back into
one of them.

This is a **library-only workspace, never a running service**: no binary, no
`main.rs`, no deployed container. `docker-compose.yml` exists solely to give
`stridelabs-testing`'s fail-loud Postgres tests something real to fail loudly
against.

## Versioning and consumption

- **Lockstep versioning**: every crate in the workspace ships at the same
  `[workspace.package].version`, bumped together regardless of which crate(s)
  actually changed. There is no independent per-crate release cadence.
- **`publish = false` on every crate.** These are never pushed to crates.io.
  Consumers add a **git dependency** pinned to a tag (release-accepted) or a
  commit rev (PR-accepted, pending release) — see each crate's README for the
  exact `[dependencies]` snippet and the `[patch]` snippet for local
  co-development.
- `Cargo.lock` is committed; CI runs every command with `--locked` so a
  consumer's build is never surprised by a dependency it didn't review.

## Toolchain

- Rust is pinned to **1.97.1** via both `.mise.toml` and `rust-toolchain.toml`.
  Reach Cargo through mise: `mise exec -- cargo …` (or `mise exec -- make …`).
- `.cargo/config.toml` sets `resolver.incompatible-rust-versions = "fallback"`
  so the dependency graph resolves against the pinned compiler instead of
  grabbing a transitive crate that needs a newer rustc.
- Local infra: `docker compose up -d` (Postgres 16 on host port 5438 rather than
  5432, so it doesn't collide with other local Postgres stacks).

## Quality gate (run before every commit)

```bash
mise exec -- cargo fmt --all
mise exec -- cargo clippy --workspace --all-targets --all-features -- -D warnings
mise exec -- cargo test --workspace
```

`mise exec -- make check` runs fmt-check + clippy + test together. CI
(`.github/workflows/ci.yml`) additionally runs the full test suite with
`--all-features`, a `--no-default-features` build, and `cargo doc`, all
`--locked`, against a live Postgres service.

**DB-touching tests need `docker compose up -d` (or `make up`) running
first.** `cargo test --workspace` (default features) never needs it —
`stridelabs-testing`'s `postgres` feature is off by default, so those tests
don't even compile into that run. They *do* compile and run under
`mise exec -- make test-all-features` (`cargo test --workspace
--all-features`), which is why that's the lane to run before trusting a
change touches Postgres correctly — and why CI runs it against a live
Postgres service rather than only the default-features lane. If Postgres
isn't up, `require_postgres`'s own test panics loudly (that's the point);
it will not silently skip.

## Crate map

All five crates are implemented: `stridelabs-config`, `stridelabs-observability`,
`stridelabs-http`, `stridelabs-auth` and `stridelabs-testing`.

| Crate | Status | Contents |
|---|---|---|
| `stridelabs-config` | Implemented | Env-var helpers (`env_or`/`env_parse`/`parse_string_array`), layered YAML/JSON file loading with field-pathed errors, a validation-error accumulator + socket/fraction checks |
| `stridelabs-observability` | Implemented | tracing init (json/pretty), a `RequestIdLayer` tower middleware, optional Prometheus wiring |
| `stridelabs-http` | Implemented | `AppError`→`IntoResponse` convention, security-headers layer, CORS layer (feature `cors`), graceful-shutdown helpers, reverse-proxy primitives (feature `proxy`), OpenAPI spec mechanics — canonical serialization, route enumeration, committed-spec freshness (feature `openapi`) |
| `stridelabs-auth` | Implemented | slauth resource-server client: rate-limited JWKS cache, RS256 verification, bearer extraction (feature `axum`), PAT hashing, offline test-key minting (feature `test-support`) |
| `stridelabs-testing` | Implemented | Fail-loud real-Postgres pool (feature `postgres`), `oneshot` axum router-test helpers, a one-line wiremock JSON stub |

Each crate documents its own **feature topology** in its README — most are
`default = []` so a consumer's dependency graph stays as lean as it wants.

## Conventions

- **Typed errors (`thiserror`) inside these crates.** `anyhow` is deliberately
  *not* used here even though it shows up at consumers' binary/app boundaries
  — a shared library crate's public error type is part of its contract, so it
  stays enumerable and matchable. (The one documented exception is
  `stridelabs-http`'s `AppError::Internal(#[from] anyhow::Error)`, which exists
  because `anyhow` is the right tool at the axum-app boundary; see that crate's
  README.)
- Match the surrounding code's comment density and idiom; comments explain
  *why*, not *what*.
- Every crate's feature topology is documented in its own README, not just
  inferred from `Cargo.toml`.
- **Tests fail loudly on a missing external dependency — never skip.**
  `stridelabs-testing::require_postgres` panics with a message naming the env
  var and the compose command rather than silently short-circuiting; crates
  that need Postgres for their own tests use it the same way. A green test
  suite must mean the behavior was actually exercised.
- Unit tests never mutate process environment variables (`std::env::set_var`
  in a test is a race with every other test in the binary). Code that reads
  env vars is routed through an injectable lookup seam so tests can supply a
  fake without touching the real environment.

## Commits

Each commit: implement → quality gate green → simplify
pass → review → quality gate green → commit. Keep commits scoped to a crate or
a coherent slice of one; feature branches land as a reviewed PR (not committed
directly to `main`).
