//! Test-only helpers for StrideLabs services: a fail-loud Postgres pool
//! (feature `postgres`), a fail-loud Redis probe (feature `redis`), a guard
//! that keeps a suite's test URL on this machine ([`require_local_url`]),
//! `tower::ServiceExt::oneshot` helpers for axum `Router`s, and a one-line
//! wiremock JSON stub.
//!
//! Extracted from the ad hoc idioms duplicated across an existing service's
//! integration tests: nine of its eleven test files carried their own
//! `setup()`/`pool_or_skip()` pair that **silently skipped** whenever
//! Postgres wasn't reachable, and its own copy of the `get`/`body_json`
//! oneshot pair. This crate exists to kill the
//! first pattern outright and let the second be written once.
//!
//! # Feature topology
//!
//! `default = []`. `oneshot`, `wiremock` and `local` are unconditional — all
//! are small and none pulls in anything a test binary doesn't already need
//! (`local` reads URLs with the `url` crate wiremock already brings).
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
//! | `postgres` | off | `postgres::require_postgres` and `postgres::require_postgres_at`, via `sqlx` |
//! | `redis` | off | `redis::require_redis` and its `RedisServer`, and `redis::require_local_redis_url` with its `RedisDbPolicy`, via `redis` |
//!
//! `postgres` is gated because `sqlx`'s Postgres driver drags in a real
//! network stack; a consumer whose tests never touch a database shouldn't
//! compile it just to get the `oneshot` helpers. The driver is built **without
//! TLS**: `require_postgres` connects to a local or CI Postgres in the clear,
//! and a `sslmode=require` URL is refused rather than silently downgraded.
//! (A TLS feature on this crate's `sqlx` would also unify into the consumer's
//! graph, where `ring` next to another rustls provider makes
//! `rustls::ClientConfig::builder()` panic.)
//!
//! `redis` is gated for the same reason, and is built without TLS for the
//! same reason: the probe talks to a local or CI Redis in the clear.
//!
//! # Fail loud, never skip
//!
//! `postgres::require_postgres` and `redis::require_redis` **panic** — with a
//! message naming the URL they tried (password redacted), the env var they
//! read (`DATABASE_URL`, `REDIS_URL`), and the command to start the server —
//! rather than returning `None` for a test to shrug off. A green test suite
//! must mean the behavior it claims to cover was actually exercised; see the
//! crate README for the pattern a consumer builds on top (migrations,
//! seeding).

pub mod local;
pub mod oneshot;
pub mod wiremock;

#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "redis")]
pub mod redis;

#[cfg(any(feature = "postgres", feature = "redis"))]
mod redact;

#[cfg(feature = "redis")]
pub use crate::redis::{require_local_redis_url, require_redis, RedisDbPolicy, RedisServer};
#[cfg(feature = "postgres")]
pub use postgres::{require_postgres, require_postgres_at};

pub use local::require_local_url;
pub use oneshot::{body_json, get, post_json, req};
pub use wiremock::serve_json;

/// A fake environment for the `*_from` lookup seams' tests: the pairs given,
/// nothing else.
#[cfg(test)]
fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    let map: std::collections::HashMap<&str, &str> = pairs.iter().copied().collect();
    move |key| map.get(key).map(|value| value.to_string())
}
