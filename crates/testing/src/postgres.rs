//! A fail-loud real-Postgres pool for integration tests (feature `postgres`).
//!
//! Ported from the `setup()`/`pool_or_skip()` pair duplicated across nine of
//! spendwise-rs's eleven test files (e.g. `tests/auth.rs:23-40`,
//! `tests/db.rs:14-31`), minus the one thing that made it worth replacing:
//! when Postgres wasn't reachable, those helpers printed a note to stderr and
//! returned `None`, and every call site treated that as "skip this test". A
//! green `cargo test` run under that pattern proves nothing about whether the
//! database-backed behavior actually works — it might never have run at all.
//!
//! [`require_postgres`] panics instead, with a message that names the exact
//! URL it tried (password redacted), the `DATABASE_URL` env var, and the
//! command to bring the database up. There is no `Option`/`Result` return to
//! quietly not-handle.
//!
//! # What this crate does *not* do
//!
//! Running migrations, seeding fixtures, and per-suite isolation are the
//! consuming application's job, not this crate's — a shared test helper has
//! no business knowing an app's migration runner or schema. The intended
//! shape, once a consumer adopts this crate, is its own
//! `tests/common/mod.rs` wrapping [`require_postgres`] in a `migrated_pool`
//! / `seeded_pool` pair — see the crate README's "fail loud, never skip"
//! section for the full illustrative example.
//!
//! Test isolation beyond that (a fresh schema per test, transactional
//! rollback) is explicitly out of scope for this crate's first version;
//! spendwise-rs keeps its existing shared-database, random-UUID-identifier
//! strategy. Schema-per-test is future work.

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// The env var [`require_postgres`] checks before falling back to its
/// `default_url` argument.
const DATABASE_URL_VAR: &str = "DATABASE_URL";

/// How long to wait for a connection before giving up. Short on purpose: a
/// local or CI Postgres that is actually up answers in milliseconds, and a
/// test suite hanging for the default `sqlx` timeout on a *down* database is
/// its own kind of unhelpful failure.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// A small pool is the right size for a test process: enough for a handful
/// of concurrent queries within one test binary, never meant to be shared
/// across a fleet of them.
const MAX_CONNECTIONS: u32 = 5;

/// Connect to Postgres for a test, or panic with an actionable message.
///
/// Reads `DATABASE_URL` from the environment; if it is unset, connects to
/// `default_url` instead — pass your compose/CI database's URL there (see
/// the module docs' `migrated_pool` example). Runs **no migrations**: the
/// returned pool talks to whatever schema is already there.
///
/// # Panics
///
/// If the connection cannot be established within 2 seconds, this panics
/// with a message naming:
///
/// - the URL it tried, with the password portion replaced by `***`,
/// - the `DATABASE_URL` env var, so a misconfigured environment is obvious,
/// - the command to start the local database (`docker compose up -d`, or
///   `make up` in a repo with that Makefile target).
///
/// This never returns `None` or skips silently — see the crate docs for why.
pub async fn require_postgres(default_url: &str) -> PgPool {
    let url = std::env::var(DATABASE_URL_VAR).unwrap_or_else(|_| default_url.to_string());
    require_postgres_at(&url).await
}

/// The env-free seam behind [`require_postgres`], so unit tests can exercise
/// the connect/panic path with a URL of their own choosing instead of
/// mutating the real process environment (`std::env::set_var` in a test
/// races every other test in the binary — the workspace convention this
/// crate follows everywhere else, see `stridelabs-config`).
async fn require_postgres_at(url: &str) -> PgPool {
    match PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .acquire_timeout(CONNECT_TIMEOUT)
        .connect(url)
        .await
    {
        Ok(pool) => pool,
        Err(err) => panic!("{}", connection_failure_message(url, &err)),
    }
}

fn connection_failure_message(url: &str, err: &sqlx::Error) -> String {
    format!(
        "\n\
        could not connect to Postgres at {redacted}\n\
        \n\
        error: {err}\n\
        \n\
        stridelabs-testing::require_postgres never skips a test for a \
        missing database — fix the connection instead of ignoring this \
        panic:\n\
        \n\
        - start the local database: `docker compose up -d` (or `make up`)\n\
        - or point {var} at a Postgres instance that is actually reachable\n",
        redacted = redact_password(url),
        var = DATABASE_URL_VAR,
    )
}

/// Mask the password segment of a `postgres://` URL so a panic message (which
/// test runners happily print to CI logs) never carries a real credential.
///
/// Anything that doesn't parse as a URL at all is reported as opaque rather
/// than echoed verbatim — the failure mode this exists to prevent is a typo'd
/// URL that still happens to contain a password-shaped substring.
fn redact_password(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            if parsed.password().is_some() {
                // `set_password` only fails for URLs that "cannot have a
                // password" (e.g. `data:` URLs); a parsed `postgres://` URL
                // that already reported a password always accepts a new one.
                let _ = parsed.set_password(Some("***"));
            }
            // sqlx also accepts credentials as QUERY parameters
            // (`?password=...`), which `Url::password()` never sees — mask
            // those too, case-insensitively, or the authority-only check
            // above becomes a leak for that URL shape.
            let query_masked: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| {
                    if k.eq_ignore_ascii_case("password") {
                        (k.into_owned(), "***".to_string())
                    } else {
                        (k.into_owned(), v.into_owned())
                    }
                })
                .collect();
            if query_masked.iter().any(|(_, v)| v == "***") {
                parsed
                    .query_pairs_mut()
                    .clear()
                    .extend_pairs(query_masked.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            }
            parsed.to_string()
        }
        Err(_) => "<a DATABASE_URL that failed to parse>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The URL the compose file and CI's Postgres service both serve:
    /// `docker-compose.yml` maps port 5438, `POSTGRES_PASSWORD=localdev`,
    /// `POSTGRES_DB=stridelabs_test`. CI additionally exports this exact
    /// string as `DATABASE_URL`, so this test exercises the public,
    /// env-reading entry point rather than the private `_at` seam — the one
    /// place in this crate's own tests where that's the point.
    const COMPOSE_URL: &str = "postgres://postgres:localdev@localhost:5438/stridelabs_test";

    #[tokio::test]
    async fn require_postgres_connects_to_the_compose_database() {
        let pool = require_postgres(COMPOSE_URL).await;

        let row: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("query the compose Postgres");
        assert_eq!(row.0, 1);
    }

    #[tokio::test]
    #[should_panic(expected = "could not connect to Postgres")]
    async fn an_unreachable_database_panics_with_an_actionable_message() {
        // Port 1 on loopback: nothing listens there, and the attempt fails
        // fast without waiting out the full acquire timeout. Passed directly
        // to the private seam so this test never touches `DATABASE_URL`.
        let _ =
            require_postgres_at("postgres://postgres:localdev@127.0.0.1:1/stridelabs_test").await;
    }

    #[test]
    fn redact_password_masks_only_the_password() {
        let redacted =
            redact_password("postgres://postgres:hunter2@localhost:5438/stridelabs_test");

        assert!(!redacted.contains("hunter2"), "{redacted}");
        assert!(redacted.contains("postgres://postgres:***@"), "{redacted}");
        assert!(redacted.contains("localhost:5438"), "{redacted}");
        assert!(redacted.contains("stridelabs_test"), "{redacted}");
    }

    #[test]
    fn redact_password_is_a_no_op_without_one() {
        let url = "postgres://postgres@localhost:5438/stridelabs_test";
        assert_eq!(redact_password(url), url);
    }

    #[test]
    fn redact_password_on_unparsable_input_stays_opaque() {
        let redacted = redact_password("not a url");
        assert!(!redacted.contains("not a url"));
    }

    #[test]
    fn redact_password_masks_query_parameter_credentials_too() {
        // sqlx also accepts `?password=...`, which `Url::password()` never
        // sees — regression for a review-found leak where this shape sailed
        // through the authority-only mask.
        for url in [
            "postgres://user@localhost:5438/db?password=hunter2",
            "postgres://user@localhost:5438/db?PASSWORD=hunter2&sslmode=disable",
        ] {
            let redacted = redact_password(url);
            assert!(!redacted.contains("hunter2"), "{redacted}");
            assert!(redacted.contains("***"), "{redacted}");
        }
    }

    #[test]
    fn the_panic_message_never_leaks_the_password() {
        // A direct assertion on the message builder, in addition to the
        // dedicated `redact_password` unit tests above: this is the exact
        // string `require_postgres_at` panics with, built the same way a
        // real connection failure would build it.
        let err = sqlx::Error::Configuration("simulated failure".into());
        let message = connection_failure_message(
            "postgres://postgres:hunter2@127.0.0.1:1/stridelabs_test",
            &err,
        );

        assert!(!message.contains("hunter2"), "{message}");
        assert!(message.contains("DATABASE_URL"), "{message}");
        assert!(message.contains("docker compose up -d"), "{message}");
        assert!(message.contains("make up"), "{message}");
    }

    #[test]
    fn an_unreachable_database_panic_carries_no_password_end_to_end() {
        // Belt and suspenders over the two tests above: actually panic
        // `require_postgres_at` (via a real failed connection attempt, not a
        // simulated error) and inspect the live payload, so a future change
        // that bypasses `connection_failure_message` would still be caught.
        let url = "postgres://postgres:hunter2@127.0.0.1:1/stridelabs_test";

        let result = std::panic::catch_unwind(|| {
            // Single-threaded: this drives exactly one future to completion,
            // so the multi-thread scheduler's worker-pool spin-up/teardown
            // would be pure overhead here.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build a runtime for this sync test");
            rt.block_on(require_postgres_at(url))
        });

        let payload = result.expect_err("connecting to port 1 must fail");
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("<non-string panic payload>");

        assert!(!message.contains("hunter2"), "{message}");
        assert!(
            message.contains("could not connect to Postgres"),
            "{message}"
        );
    }
}
