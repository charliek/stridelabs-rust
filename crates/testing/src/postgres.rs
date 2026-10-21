//! A fail-loud real-Postgres pool for integration tests (feature `postgres`).
//!
//! Carried over from the `setup()`/`pool_or_skip()` pair duplicated across
//! nine of eleven test files in an existing service, minus the one thing that
//! made it worth replacing:
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
//! adopting services keep whatever shared-database strategy they already use
//! (for example random UUID identifiers per test). Schema-per-test is future
//! work.

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::redact::{redact_password, UrlShape};

/// The env var [`require_postgres`] checks before falling back to its
/// `default_url` argument.
const DATABASE_URL_VAR: &str = "DATABASE_URL";

/// What a URL must look like to be rendered (password masked) in a panic
/// message; anything else is shown as a placeholder.
const DATABASE_URL_SHAPE: UrlShape = UrlShape {
    env_var: DATABASE_URL_VAR,
    schemes: &["postgres", "postgresql"],
};

/// The same, for [`require_postgres_at`]'s argument: its placeholder names
/// the URL the caller passed, not a variable the helper never reads.
const ARGUMENT_URL_SHAPE: UrlShape = UrlShape {
    env_var: "URL passed to require_postgres_at",
    schemes: &["postgres", "postgresql"],
};

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
/// Reads `DATABASE_URL` from the environment; if it is unset (or empty),
/// connects to `default_url` instead — pass your compose/CI database's URL
/// there (see the module docs' `migrated_pool` example). Runs **no
/// migrations**: the returned pool talks to whatever schema is already there.
///
/// `DATABASE_URL` wins over the argument, so this is for the database a
/// suite starts from. A URL the test built itself (one carrying a per-test
/// `search_path`, say) goes to [`require_postgres_at`], which connects to
/// exactly the URL it is given.
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
    require_postgres_from(default_url, |var| std::env::var(var).ok()).await
}

/// The env-injectable seam behind [`require_postgres`], as `require_redis`
/// has, so unit tests reach its panic without mutating the environment.
async fn require_postgres_from(default_url: &str, get: impl Fn(&str) -> Option<String>) -> PgPool {
    connect(&resolve_url(default_url, get), UrlSource::Environment).await
}

/// `DATABASE_URL` when set and non-empty, else `default_url`. Empty counts
/// as unset, as it does for `require_redis` and `stridelabs-config`'s
/// `env_or`: that is how a variable someone left unfilled arrives from
/// compose or CI. The lookup is injected so that unit tests never mutate the
/// real process environment (`std::env::set_var` in a test races every
/// other test in the binary — the workspace convention, see
/// `stridelabs-config`).
fn resolve_url(default_url: &str, get: impl Fn(&str) -> Option<String>) -> String {
    get(DATABASE_URL_VAR)
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| default_url.to_string())
}

/// Connect to exactly `url` for a test, or panic with an actionable message.
///
/// [`require_postgres`] without the environment: `DATABASE_URL` is not read,
/// so the pool is on the URL given, with every option it carries. Use it for
/// a URL a test derived from the one its suite started from, such as a
/// schema of its own:
///
/// ```no_run
/// # fn suite_database_url() -> String { String::new() }
/// # async fn example() {
/// use stridelabs_testing::require_postgres_at;
///
/// // The suite's database (`DATABASE_URL` or its compose default), resolved
/// // once, so that every pool below is on the same server.
/// let base = suite_database_url();
/// let admin = require_postgres_at(&base).await;
/// sqlx::query("CREATE SCHEMA IF NOT EXISTS t_example")
///     .execute(&admin)
///     .await
///     .unwrap();
/// // A schema of its own, as one more query parameter: the base may carry
/// // a query already (`?sslmode=disable`). Under `require_postgres`, a set
/// // `DATABASE_URL` would replace this URL, search_path and all.
/// let separator = if base.contains('?') { '&' } else { '?' };
/// let schema_url = format!("{base}{separator}options=-c%20search_path%3Dt_example");
/// let pool = require_postgres_at(&schema_url).await;
/// # let _ = pool;
/// # }
/// ```
///
/// # Panics
///
/// As [`require_postgres`] does, within 2 seconds and with the URL redacted,
/// except that the message says to check the URL passed: `DATABASE_URL`
/// plays no part here, so pointing it elsewhere would change nothing.
pub async fn require_postgres_at(url: &str) -> PgPool {
    connect(url, UrlSource::Argument).await
}

/// Where the URL a probe dials came from, which decides what its panic tells
/// the caller to fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrlSource {
    /// [`require_postgres`]: `DATABASE_URL`, or the default it fell back to.
    Environment,
    /// [`require_postgres_at`]: exactly the URL the caller passed.
    Argument,
}

async fn connect(url: &str, source: UrlSource) -> PgPool {
    match PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .acquire_timeout(CONNECT_TIMEOUT)
        .connect(url)
        .await
    {
        Ok(pool) => pool,
        Err(err) => panic!("{}", connection_failure_message(url, &err, source)),
    }
}

fn connection_failure_message(url: &str, err: &sqlx::Error, source: UrlSource) -> String {
    let (helper, fix, shape) = match source {
        UrlSource::Environment => (
            "require_postgres",
            format!("point {DATABASE_URL_VAR} at a Postgres instance that is actually reachable"),
            &DATABASE_URL_SHAPE,
        ),
        UrlSource::Argument => (
            "require_postgres_at",
            "check the URL you passed: require_postgres_at connects to exactly that URL \
             and reads no environment variable"
                .to_owned(),
            &ARGUMENT_URL_SHAPE,
        ),
    };
    format!(
        "\n\
        could not connect to Postgres at {redacted}\n\
        \n\
        error: {err}\n\
        \n\
        stridelabs-testing::{helper} never skips a test for a missing \
        database — fix the connection instead of ignoring this panic:\n\
        \n\
        - start the local database: `docker compose up -d` (or `make up`)\n\
        - or {fix}\n",
        redacted = redact_password(url, shape),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The URL the compose file and CI's Postgres service both serve:
    /// `docker-compose.yml` maps port 5438, `POSTGRES_PASSWORD=localdev`,
    /// `POSTGRES_DB=stridelabs_test`. CI additionally exports this exact
    /// string as `DATABASE_URL`, so the first test exercises the public,
    /// env-reading entry point rather than the `_at` form — the one place in
    /// this crate's own tests where that's the point.
    const COMPOSE_URL: &str = "postgres://postgres:localdev@localhost:5438/stridelabs_test";

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: std::collections::HashMap<&str, &str> = pairs.iter().copied().collect();
        move |key| map.get(key).map(|value| value.to_string())
    }

    /// The database the tests reach: `DATABASE_URL` (read, never written)
    /// or the compose URL, by `require_postgres`'s own precedence.
    fn test_database_url() -> String {
        resolve_url(COMPOSE_URL, |var| std::env::var(var).ok())
    }

    #[tokio::test]
    async fn require_postgres_connects_to_the_compose_database() {
        let pool = require_postgres(COMPOSE_URL).await;

        let row: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("query the compose Postgres");
        assert_eq!(row.0, 1);
    }

    /// Pins "stridelabs-testing has no TLS": sqlx is built without any `tls-*`
    /// feature (one would unify `ring` into every consumer's test graph), so
    /// a URL that demands TLS must fail loudly instead of being downgraded to
    /// plaintext. Aimed at the database the test above reaches (read-only env
    /// lookup, same precedence as `require_postgres`), so the refusal seen is
    /// sqlx's and not a connection error.
    #[tokio::test]
    #[should_panic(expected = "built without TLS support")]
    async fn a_url_that_requires_tls_is_refused_not_downgraded() {
        let mut url = url::Url::parse(&test_database_url()).expect("parse the test database URL");
        url.query_pairs_mut().append_pair("sslmode", "require");

        let _ = require_postgres_at(url.as_str()).await;
    }

    #[test]
    fn database_url_takes_precedence_over_the_default() {
        let url = resolve_url(
            COMPOSE_URL,
            lookup(&[("DATABASE_URL", "postgres://ci-postgres:5432/ci")]),
        );
        assert_eq!(url, "postgres://ci-postgres:5432/ci");
    }

    /// An empty `DATABASE_URL` is a variable left unfilled, not a URL: the
    /// default answers, as it does for `require_redis`.
    #[test]
    fn an_unset_or_empty_database_url_falls_back_to_the_default() {
        assert_eq!(resolve_url(COMPOSE_URL, lookup(&[])), COMPOSE_URL);
        assert_eq!(
            resolve_url(COMPOSE_URL, lookup(&[("DATABASE_URL", "")])),
            COMPOSE_URL
        );
    }

    /// `require_postgres_at` connects to the URL it is given, options and
    /// all: a `search_path` a test chose is the pool's. (`require_postgres`
    /// would have dialled a set `DATABASE_URL` instead, as CI's is, and lost
    /// it.)
    #[tokio::test]
    async fn require_postgres_at_connects_to_exactly_its_url() {
        let mut url = url::Url::parse(&test_database_url()).expect("parse the test database URL");
        url.query_pairs_mut()
            .append_pair("options", "-c search_path=stridelabs_testing_at");

        let pool = require_postgres_at(url.as_str()).await;
        let search_path: String = sqlx::query_scalar("SHOW search_path")
            .fetch_one(&pool)
            .await
            .expect("read the pool's search_path");
        assert_eq!(search_path, "stridelabs_testing_at");
    }

    #[tokio::test]
    #[should_panic(expected = "could not connect to Postgres")]
    async fn an_unreachable_database_panics_with_an_actionable_message() {
        // Port 1 on loopback: nothing listens there, and the attempt fails
        // fast without waiting out the full acquire timeout. Passed directly
        // to `require_postgres_at` so this test never reads `DATABASE_URL`.
        let _ =
            require_postgres_at("postgres://postgres:localdev@127.0.0.1:1/stridelabs_test").await;
    }

    #[test]
    fn the_panic_message_never_leaks_the_password() {
        // A direct assertion on the message builder, in addition to the
        // dedicated `redact_password` unit tests in `crate::redact`: this is
        // the exact string each entry point panics with, built the same way
        // a real connection failure would build it.
        let err = sqlx::Error::Configuration("simulated failure".into());
        for source in [UrlSource::Environment, UrlSource::Argument] {
            let message = connection_failure_message(
                "postgres://postgres:hunter2@127.0.0.1:1/stridelabs_test",
                &err,
                source,
            );

            assert!(!message.contains("hunter2"), "{source:?}: {message}");
            assert!(
                message.contains("docker compose up -d"),
                "{source:?}: {message}"
            );
            assert!(message.contains("make up"), "{source:?}: {message}");
        }
    }

    /// Each entry point's panic names the fix that reaches it:
    /// `require_postgres` reads `DATABASE_URL`, so pointing it elsewhere
    /// helps; `require_postgres_at` reads nothing, so only the URL passed
    /// can be wrong, and the variable is not mentioned at all.
    #[test]
    fn each_entry_point_names_the_fix_that_reaches_it() {
        let err = sqlx::Error::Configuration("simulated failure".into());
        let url = "postgres://postgres:localdev@127.0.0.1:1/stridelabs_test";

        let from_env = connection_failure_message(url, &err, UrlSource::Environment);
        assert!(
            from_env.contains("stridelabs-testing::require_postgres never skips"),
            "{from_env}"
        );
        assert!(from_env.contains("point DATABASE_URL at"), "{from_env}");
        assert!(!from_env.contains("check the URL you passed"), "{from_env}");

        let from_argument = connection_failure_message(url, &err, UrlSource::Argument);
        assert!(
            from_argument.contains("stridelabs-testing::require_postgres_at never skips"),
            "{from_argument}"
        );
        assert!(
            from_argument.contains("check the URL you passed"),
            "{from_argument}"
        );
        assert!(!from_argument.contains("DATABASE_URL"), "{from_argument}");

        // A URL too malformed to render is replaced by a placeholder, which
        // names where it came from: the variable, or the argument.
        let malformed = "postgres:/postgres:hunter2@127.0.0.1:1/stridelabs_test";
        let from_env = connection_failure_message(malformed, &err, UrlSource::Environment);
        assert!(!from_env.contains("hunter2"), "{from_env}");
        assert!(
            from_env.contains("<a DATABASE_URL that is not a well-formed URL (not shown)>"),
            "{from_env}"
        );
        let from_argument = connection_failure_message(malformed, &err, UrlSource::Argument);
        assert!(!from_argument.contains("hunter2"), "{from_argument}");
        assert!(
            from_argument.contains(
                "<a URL passed to require_postgres_at that is not a well-formed URL (not shown)>"
            ),
            "{from_argument}"
        );
        assert!(!from_argument.contains("DATABASE_URL"), "{from_argument}");
    }

    /// The live panic payload of `future`, driven to its failure.
    fn live_panic_message(future: impl std::future::Future<Output = PgPool>) -> String {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Single-threaded: this drives exactly one future to completion,
            // so the multi-thread scheduler's worker-pool spin-up/teardown
            // would be pure overhead here.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build a runtime for this sync test");
            rt.block_on(future)
        }));
        let payload = result.expect_err("connecting to port 1 must fail");
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "<non-string panic payload>".to_string())
    }

    #[test]
    fn an_unreachable_database_panic_carries_no_password_end_to_end() {
        // Belt and suspenders over the tests above: actually panic each
        // entry point (via a real failed connection attempt, not a simulated
        // error) and inspect the live payload, so a future change that
        // bypasses `connection_failure_message` would still be caught.
        // `require_postgres` goes through its lookup seam, handed a fake
        // `DATABASE_URL`, so the real environment is never touched.
        let url = "postgres://postgres:hunter2@127.0.0.1:1/stridelabs_test";

        let from_argument = live_panic_message(require_postgres_at(url));
        assert!(!from_argument.contains("hunter2"), "{from_argument}");
        assert!(
            from_argument.contains("could not connect to Postgres"),
            "{from_argument}"
        );
        assert!(
            from_argument.contains("check the URL you passed"),
            "{from_argument}"
        );

        let from_env = live_panic_message(require_postgres_from(
            COMPOSE_URL,
            lookup(&[("DATABASE_URL", url)]),
        ));
        assert!(!from_env.contains("hunter2"), "{from_env}");
        assert!(
            from_env
                .contains("could not connect to Postgres at postgres://postgres:***@127.0.0.1:1/"),
            "{from_env}"
        );
        assert!(from_env.contains("point DATABASE_URL at"), "{from_env}");
    }
}
