//! stridelabs-postgres against a real Postgres (feature `live-tests`; CI's
//! all-features lane). `require_postgres` panics when there is no server
//! (`docker compose up -d`), so this suite never passes by skipping.
//!
//! Every pool here is built the way a consumer builds one: `connect_options`
//! over the URL, then `lazy_pool`. Nothing is created that outlives a test.

use std::time::Duration;

use sqlx::postgres::PgPool;
use stridelabs_postgres::{connect_options, error_summary, lazy_pool, PoolSettings, LOG_CAPS};
use stridelabs_testing::require_postgres;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::Layer as _;

#[path = "common/recorded.rs"]
mod recorded;
use recorded::{capped_off, Recorded};

/// `docker-compose.yml`'s Postgres. CI sets `DATABASE_URL` to the same.
const COMPOSE_URL: &str = "postgres://postgres:localdev@localhost:5438/stridelabs_test";

const CANARY: &str = "live-db-canary";

/// The database `require_postgres` reaches: `DATABASE_URL` (read, never
/// written) or the compose URL, by its own precedence.
fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .ok()
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| COMPOSE_URL.to_owned())
}

/// `database_url()` with `query` appended.
fn database_url_with(query: &str) -> String {
    let base = database_url();
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}{query}")
}

/// A lazy pool on the test database, after `require_postgres` has proved the
/// server is up (or panicked saying how to start it).
async fn pool(url: &str, settings: PoolSettings) -> PgPool {
    let _ = require_postgres(COMPOSE_URL).await;
    let options =
        connect_options(url).unwrap_or_else(|refusal| panic!("the test URL is refused: {refusal}"));
    lazy_pool(options, settings)
}

/// The pool connects on first use, not before, and then serves queries.
#[tokio::test]
async fn a_lazy_pool_connects_on_first_use() {
    let pool = pool(
        &database_url(),
        PoolSettings::default().with_max_connections(2),
    )
    .await;
    assert_eq!(pool.size(), 0, "built without connecting");

    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .expect("SELECT 1");
    assert_eq!(one, 1);
    assert!(pool.size() >= 1);
    pool.close().await;
}

/// A real database error whose message quotes the value it rejected is
/// summarised as its SQLSTATE: a bad cast in a query, and a startup option
/// the server refuses at connect (its value echoed back in a FATAL). The
/// control is sqlx's own text, which carries the canary.
#[tokio::test]
async fn a_real_database_error_is_summarised_without_its_message() {
    let pool = pool(&database_url(), PoolSettings::default()).await;
    let cast = sqlx::query_scalar::<_, i32>("SELECT $1::int")
        .bind(CANARY)
        .fetch_one(&pool)
        .await
        .expect_err("not an integer");
    assert!(cast.to_string().contains(CANARY), "premise: {cast}");
    assert_eq!(
        error_summary(&cast).to_string(),
        "database error SQLSTATE 22P02 (data exception)"
    );
    pool.close().await;

    let refused = pool_with_startup_option().await;
    let at_connect = sqlx::query("SELECT 1")
        .execute(&refused)
        .await
        .expect_err("the server refuses the setting's value");
    assert!(
        at_connect.to_string().contains(CANARY),
        "premise: {at_connect}"
    );
    assert_eq!(
        error_summary(&at_connect).to_string(),
        "database error SQLSTATE 22023 (invalid parameter value)"
    );
    refused.close().await;
}

/// A pool whose startup options carry a `statement_timeout` value the
/// server refuses (and quotes), which `connect_options` has no reason to.
async fn pool_with_startup_option() -> PgPool {
    pool(
        &database_url_with(&format!("options=-c%20statement_timeout%3D{CANARY}")),
        PoolSettings::default().with_acquire_timeout(Duration::from_secs(5)),
    )
    .await
}

/// sqlx's pool logs a raw error, message and all, from work no caller sees
/// first (here: an `after_connect` hook that fails with the canary), under a
/// target `LOG_CAPS` turns off. A sqlx upgrade that moved the module would
/// fail here rather than leak quietly. The caller itself sees only a timeout.
///
/// A current-thread runtime (`#[tokio::test]`'s default) runs the pool's
/// connect on this thread, so the scoped subscriber sees it.
#[tokio::test]
async fn the_pool_logs_raw_errors_under_a_capped_target() {
    let _ = require_postgres(COMPOSE_URL).await;
    let options = connect_options(&database_url()).expect("the test URL");
    let pool = PoolSettings::default()
        .with_acquire_timeout(Duration::from_millis(500))
        .pool_options()
        .after_connect(|_connection, _meta| {
            Box::pin(async { Err(sqlx::Error::Protocol(CANARY.to_owned())) })
        })
        .connect_lazy_with(options);

    let recorded = Recorded::default();
    let guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(recorded.clone()));
    let error = sqlx::query("SELECT 1")
        .execute(&pool)
        .await
        .expect_err("every connection fails its after_connect");
    drop(guard);
    pool.close().await;
    assert_eq!(
        error_summary(&error).to_string(),
        "timed out waiting for a pool connection"
    );

    let events = recorded.events();
    let leaking: Vec<_> = events
        .iter()
        .filter(|(_, fields)| fields.contains(CANARY))
        .collect();
    assert!(!leaking.is_empty(), "premise: sqlx logged it: {events:?}");
    for (target, _) in leaking {
        assert!(
            capped_off(&LOG_CAPS, target),
            "{target} logs the raw error and is not capped off"
        );
    }
}

/// A server notice quotes whatever value it is about, and sqlx logs each one
/// verbatim (`sqlx::postgres::notice`) from inside a connection that
/// SUCCEEDS, so `error_summary` never sees it. Here: an `application_name`
/// past the server's 63-byte identifier limit, which `connect_options`
/// accepts and the server truncates with a NOTICE quoting the original.
///
/// Everything sqlx logs at TRACE is recorded twice in the same run: as is,
/// to prove the server really sent the notice and sqlx really logged the
/// canary (the premise), and through `LOG_CAPS` (`TargetCaps`' covering
/// rule), where the canary must not appear.
#[tokio::test]
async fn a_server_notice_quoting_a_value_is_capped_off() {
    let long_name = format!("{CANARY}{}", "a".repeat(64));
    let pool = pool(
        &database_url_with(&format!("application_name={long_name}")),
        PoolSettings::default().with_max_connections(1),
    )
    .await;

    let everything = Recorded::default();
    let capped = Recorded::default();
    let subscriber = tracing_subscriber::registry()
        .with(everything.clone())
        .with(capped.clone().with_filter(filter_fn(|metadata| {
            !capped_off(&LOG_CAPS, metadata.target())
        })));
    let guard = tracing::subscriber::set_default(subscriber);
    let name: String = sqlx::query_scalar("SELECT current_setting('application_name')")
        .fetch_one(&pool)
        .await
        .expect("the connection succeeds");
    drop(guard);
    pool.close().await;

    assert!(
        name.len() < long_name.len() && long_name.starts_with(&name),
        "premise: the server truncated the name"
    );
    let noticed: Vec<_> = everything
        .events()
        .into_iter()
        .filter(|(_, fields)| fields.contains(CANARY))
        .collect();
    assert!(
        noticed
            .iter()
            .any(|(target, _)| target == "sqlx::postgres::notice"),
        "premise: sqlx logged the server's notice: {noticed:?}"
    );
    let leaked: Vec<_> = capped
        .events()
        .into_iter()
        .filter(|(_, fields)| fields.contains(CANARY))
        .collect();
    assert!(leaked.is_empty(), "the caps let it through: {leaked:?}");
}
