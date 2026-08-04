//! Test-only helpers for StrideLabs services: a fail-loud Postgres pool
//! (feature `postgres`), `tower::ServiceExt::oneshot` helpers for axum
//! `Router`s, and a one-line wiremock JSON stub.
//!
//! Extracted from the ad hoc idioms duplicated across spendwise-rs's
//! integration tests: nine of its eleven test files carried their own
//! `setup()`/`pool_or_skip()` pair that **silently skipped** whenever
//! Postgres wasn't reachable, and its own copy of the `get`/`body_json`
//! oneshot pair (e.g. `tests/auth.rs:23-53`). This crate exists to kill the
//! first pattern outright and let the second be written once.
//!
//! # Feature topology
//!
//! `default = []`. `oneshot` and `wiremock` are unconditional — both are tiny
//! and neither pulls in anything a test binary doesn't already need.
//!
//! Note that feature-gated items are named in plain code spans, never
//! intra-doc links: they are off by default, so a link would be an
//! unresolved-link warning on `cargo doc` without `--all-features` (which is
//! how a consumer documenting its own graph usually builds). They appear in
//! the sidebar once the matching feature is on, which is the only time they
//! exist at all.
//!
//! | Feature | Default | Adds |
//! |---|---|---|
//! | `postgres` | off | `postgres::require_postgres`, via `sqlx`/`url` |
//!
//! `postgres` is gated because `sqlx`'s Postgres driver drags in a real
//! network/TLS stack; a consumer whose tests never touch a database
//! shouldn't compile it just to get the `oneshot` helpers.
//!
//! # Fail loud, never skip
//!
//! `postgres::require_postgres` **panics** — with a message naming the URL
//! it tried (password redacted), the `DATABASE_URL` env var, and the command
//! to start the database — rather than returning `None` for a test to shrug
//! off. A green test suite must mean the behavior it claims to cover was
//! actually exercised; see the crate README for the pattern a consumer builds
//! on top (migrations, seeding).

pub mod oneshot;
pub mod wiremock;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "postgres")]
pub use postgres::require_postgres;

pub use oneshot::{body_json, get, post_json, req};
pub use wiremock::serve_json;
