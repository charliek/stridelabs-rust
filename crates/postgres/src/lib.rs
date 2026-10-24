//! Postgres connection hygiene on sqlx for StrideLabs services: the checks a
//! `DATABASE_URL` passes before sqlx parses it, a `sqlx::Error` rendered
//! without anything a server or a URL put into it, a pool built without
//! connecting, Neon pooler detection, and the sqlx log targets a consumer
//! caps.
//!
//! Extracted from tapper-rs's `db.rs` (itself hardened from lumen-rs's copy),
//! checked against slaudio's `parse_connect_options`, so that the three apps
//! hold one set of rules. What stays with each app: normalising an app's own
//! URL spellings first (tapper's and lumen's `postgresql+asyncpg://`), the
//! readiness probe, the migration runner, and whether a detected pooler is
//! refused.
//!
//! | Item | |
//! |---|---|
//! | [`connect_options`] | a URL checked, then parsed into sqlx's options: a query-parameter allow-list, no `search_path`, no NUL byte, no password file; refusals ([`UrlRefusal`]) never print a value |
//! | [`error_summary`] | a `sqlx::Error` as its SQLSTATE and a fixed description, or a fixed class name |
//! | [`lazy_pool`] | a pool built from checked options with [`PoolSettings`], without connecting |
//! | [`neon_pooler`] | whether options reach Neon's pooled endpoint ([`PoolerRef`]) |
//! | [`LOG_CAPS`] | the sqlx targets that log a raw error, a server notice or a URL value, to cap off |
//!
//! # Feature topology
//!
//! `default = []`, and nothing a consumer turns on: the only feature,
//! `live-tests`, compiles this crate's own real-Postgres suite. sqlx is a
//! required dependency with the Postgres driver and the Tokio runtime only;
//! **TLS is the consumer's choice**, made on its own sqlx (see the crate
//! README for why this crate names none).

mod connect;
mod pool;
mod pooler;
mod summary;

pub use connect::{connect_options, UrlRefusal, IGNORED_URL_PARAMETERS, SUPPORTED_URL_PARAMETERS};
pub use pool::{lazy_pool, PoolSettings};
pub use pooler::{neon_pooler, neon_pooler_host, PoolerRef};
pub use summary::{error_summary, ErrorSummary};

use tracing::level_filters::LevelFilter;

/// The sqlx log targets that can write a raw error, a server-supplied text
/// or a URL parameter's value, each with the ceiling to cap it at: all off,
/// at every level.
///
/// - **`sqlx_core::pool`** logs a raw `sqlx::Error` (its `Display`, so the
///   server's message, which quotes the value it rejected) from the pool's
///   own background work, which no consumer code sees first: the WARN when a
///   connection's on-release ping fails (reached when a request is cancelled
///   while a statement is outstanding, and the statement's error is drained
///   by the ping), the ERROR from `after_connect`, the DEBUG when a close
///   fails or `min_connections` upkeep fails, the INFO when an idle
///   connection's ping fails. Every failure a consumer acts on still reaches
///   it as an `Err`, which it renders through [`error_summary`].
/// - **`sqlx_postgres::options`** WARNs every URL parameter it does not
///   recognise WITH its value, and a malformed password-file line verbatim.
///   [`connect_options`] makes both unreachable (the allow-list; no password
///   file), and the cap keeps them so for a URL that reaches sqlx another
///   way.
/// - **`sqlx::postgres::notice`** logs every notice the server sends
///   (`NoticeResponse`: NOTICE at INFO, WARNING at WARN, and so on) with its
///   message verbatim, and a notice quotes whatever value it is about. One
///   arrives on a connection that SUCCEEDS, so no `Err` reaches
///   [`error_summary`]: an `application_name` longer than the server's
///   63-byte identifier limit, which [`connect_options`] accepts, is
///   truncated with a NOTICE quoting the original. A consumer that wants the
///   notices of its own SQL (`RAISE NOTICE`) can replace this cap with a
///   looser one, knowing what they can carry.
/// - **`sqlx_postgres::message`** decodes the server's wire messages; its
///   one log line today (DEBUG, `message::copy`) prints the body of a
///   `CopyDone` the server should have sent empty, verbatim. Off, so that a
///   misbehaving peer's bytes never reach a log, and so that whatever a
///   later sqlx logs while decoding server messages is off too. (Not driven
///   by a test: reaching it takes a peer that breaks the COPY protocol.)
///
/// **Not capped**, after reading every log call in sqlx-core and
/// sqlx-postgres 0.9: `sqlx::query` (the application's own SQL text, with
/// row counts and timings; bind parameters are never logged, so it carries a
/// value only if the application put one into its SQL), `sqlx::pool::acquire`
/// (timings), `sqlx_postgres::connection` (TRACE type resolution: the
/// schema's type names and OIDs, and the catalog query; DEBUG statement
/// metadata), `sqlx_postgres::advisory_lock` (the lock key the application
/// chose), `sqlx_postgres::types` (a byte count), and `sqlx_core::net::tls`
/// (local certificate-store errors). sqlx-core's `sqlx_core::config` logs the
/// `sqlx.toml` it read, but only under its compile-time macros, which this
/// crate does not build.
///
/// Plain `(target, level)` pairs rather than a `stridelabs-observability`
/// `TargetCaps`, so this crate depends on no logging setup: fold them into
/// the consumer's own caps (each cap covers the target's module tree).
///
/// ```
/// use stridelabs_observability::TargetCaps;
///
/// let caps = stridelabs_postgres::LOG_CAPS
///     .iter()
///     .fold(TargetCaps::new(), |caps, (target, level)| caps.cap(*target, *level));
/// # let _ = caps;
/// ```
pub const LOG_CAPS: [(&str, LevelFilter); 4] = [
    ("sqlx_core::pool", LevelFilter::OFF),
    ("sqlx_postgres::options", LevelFilter::OFF),
    ("sqlx::postgres::notice", LevelFilter::OFF),
    ("sqlx_postgres::message", LevelFilter::OFF),
];

#[cfg(test)]
#[path = "../tests/common/recorded.rs"]
mod recorded;

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use sqlx::postgres::PgConnectOptions;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;
    use crate::recorded::{capped_off, Recorded};

    /// sqlx's URL parser logs an unrecognised parameter WITH its value, under
    /// a target [`LOG_CAPS`] turns off (so a sqlx upgrade that moved the
    /// module would fail here, not leak quietly); `connect_options` refuses
    /// the same URL before sqlx sees it, so nothing is logged at all.
    #[test]
    fn sqlx_logs_an_unrecognised_parameter_under_a_capped_target() {
        const URL: &str = "postgres://u:p@h/db?secret_param=log-cap-canary";

        let sqlx = Recorded::default();
        tracing::subscriber::with_default(
            tracing_subscriber::registry().with(sqlx.clone()),
            || {
                let _ = PgConnectOptions::from_str(URL);
            },
        );
        let events = sqlx.events();
        assert_eq!(events.len(), 1, "{events:?}");
        let (target, fields) = &events[0];
        assert!(fields.contains("log-cap-canary"), "premise: {fields}");
        assert!(capped_off(&LOG_CAPS, target), "{target} is not capped off");

        let ours = Recorded::default();
        tracing::subscriber::with_default(
            tracing_subscriber::registry().with(ours.clone()),
            || {
                assert!(connect_options(URL).is_err());
            },
        );
        assert!(ours.events().is_empty());
    }

    #[test]
    fn the_caps_cover_their_module_trees_only() {
        for (target, capped) in [
            ("sqlx_core::pool", true),
            ("sqlx_core::pool::inner", true),
            ("sqlx_postgres::options::parse", true),
            ("sqlx::postgres::notice", true),
            ("sqlx_postgres::message::copy", true),
            ("sqlx_core::pool_extra", false),
            ("sqlx::postgres::notices", false),
            ("sqlx::query", false),
            ("sqlx::pool::acquire", false),
        ] {
            assert_eq!(capped_off(&LOG_CAPS, target), capped, "{target}");
        }
    }
}
