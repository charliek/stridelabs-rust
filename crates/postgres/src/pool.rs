//! [`lazy_pool`]: a pool built from checked options, without connecting.

use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;

/// The pool settings each app chooses: how many connections, how long a
/// caller waits for one, and when connections are retired. The defaults are
/// sqlx 0.9's own (10 connections, 30 s to wait for one, an idle connection
/// closed after 10 minutes, every connection retired after 30, each pinged
/// before it is handed out), pinned here so that a sqlx upgrade cannot move
/// them under a consumer.
///
/// ```
/// use std::time::Duration;
/// use stridelabs_postgres::PoolSettings;
///
/// // tapper's: 15 connections, 30 s to wait for one.
/// let tapper = PoolSettings::default().with_max_connections(15);
/// // slaudio's: Neon idles connections after 300 s, so retire them first.
/// let slaudio = PoolSettings::default()
///     .with_max_connections(30)
///     .with_max_lifetime(Some(Duration::from_secs(280)))
///     .with_idle_timeout(Some(Duration::from_secs(240)));
/// # let _ = (tapper, slaudio);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PoolSettings {
    /// The most connections the pool opens. At least 1: a pool of none
    /// never hands one out, so every caller waits out `acquire_timeout`.
    pub max_connections: u32,
    /// How long a caller waits for a connection (connecting included) before
    /// it fails with `sqlx::Error::PoolTimedOut`.
    pub acquire_timeout: Duration,
    /// How long a connection may sit idle before the pool closes it; `None`
    /// keeps it.
    pub idle_timeout: Option<Duration>,
    /// How long a connection lives before the pool retires it; `None` keeps
    /// it for good.
    pub max_lifetime: Option<Duration>,
    /// Whether a connection is pinged before it is handed out.
    pub test_before_acquire: bool,
}

impl Default for PoolSettings {
    fn default() -> Self {
        PoolSettings {
            max_connections: 10,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Some(Duration::from_secs(10 * 60)),
            max_lifetime: Some(Duration::from_secs(30 * 60)),
            test_before_acquire: true,
        }
    }
}

impl PoolSettings {
    /// Replace [`max_connections`](Self::max_connections).
    #[must_use]
    pub fn with_max_connections(mut self, max_connections: u32) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Replace [`acquire_timeout`](Self::acquire_timeout).
    #[must_use]
    pub fn with_acquire_timeout(mut self, acquire_timeout: Duration) -> Self {
        self.acquire_timeout = acquire_timeout;
        self
    }

    /// Replace [`idle_timeout`](Self::idle_timeout).
    #[must_use]
    pub fn with_idle_timeout(mut self, idle_timeout: Option<Duration>) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    /// Replace [`max_lifetime`](Self::max_lifetime).
    #[must_use]
    pub fn with_max_lifetime(mut self, max_lifetime: Option<Duration>) -> Self {
        self.max_lifetime = max_lifetime;
        self
    }

    /// Replace [`test_before_acquire`](Self::test_before_acquire).
    #[must_use]
    pub fn with_test_before_acquire(mut self, test_before_acquire: bool) -> Self {
        self.test_before_acquire = test_before_acquire;
        self
    }

    /// sqlx's pool options with these settings, for a consumer that needs
    /// more than [`lazy_pool`] sets (an `after_connect` hook, say).
    pub fn pool_options(&self) -> PgPoolOptions {
        PgPoolOptions::new()
            .max_connections(self.max_connections)
            .acquire_timeout(self.acquire_timeout)
            .idle_timeout(self.idle_timeout)
            .max_lifetime(self.max_lifetime)
            .test_before_acquire(self.test_before_acquire)
    }
}

/// The pool for `options` with `settings`, **without connecting**.
///
/// Laziness is the point: a database that is down must not stop a process
/// from coming up, because a process that never binds its listener cannot
/// serve the readiness probe that would report the outage. Building the pool
/// does no I/O; the first query connects, and its failure reaches the caller
/// as an `Err` (render it with [`error_summary`](crate::error_summary)).
///
/// Built from options, never from a URL string: pass what
/// [`connect_options`](crate::connect_options) returned, so sqlx parses
/// nothing that was not checked, reads no password file, and sends no
/// `search_path` and no NUL at startup.
///
/// Call it inside a Tokio runtime: sqlx spawns the pool's maintenance task
/// as it builds the pool.
///
/// ```
/// use stridelabs_postgres::{connect_options, lazy_pool, PoolSettings};
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), stridelabs_postgres::UrlRefusal> {
/// // Port 1: nothing listens there, and the pool is built all the same.
/// let options = connect_options("postgres://app:secret@127.0.0.1:1/app")?;
/// let pool = lazy_pool(options, PoolSettings::default());
/// assert_eq!(pool.size(), 0);
/// # Ok(())
/// # }
/// ```
pub fn lazy_pool(options: PgConnectOptions, settings: PoolSettings) -> PgPool {
    settings.pool_options().connect_lazy_with(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defaults are sqlx's own, and each `with_*` replaces exactly its
    /// setting in the pool options handed to sqlx.
    #[test]
    fn the_settings_reach_sqlxs_pool_options() {
        let defaults = PoolSettings::default().pool_options();
        let sqlx = PgPoolOptions::new();
        assert_eq!(defaults.get_max_connections(), sqlx.get_max_connections());
        assert_eq!(defaults.get_acquire_timeout(), sqlx.get_acquire_timeout());
        assert_eq!(defaults.get_idle_timeout(), sqlx.get_idle_timeout());
        assert_eq!(defaults.get_max_lifetime(), sqlx.get_max_lifetime());
        assert_eq!(
            defaults.get_test_before_acquire(),
            sqlx.get_test_before_acquire()
        );

        let options = PoolSettings::default()
            .with_max_connections(30)
            .with_acquire_timeout(Duration::from_secs(5))
            .with_idle_timeout(Some(Duration::from_secs(240)))
            .with_max_lifetime(None)
            .with_test_before_acquire(false)
            .pool_options();
        assert_eq!(options.get_max_connections(), 30);
        assert_eq!(options.get_acquire_timeout(), Duration::from_secs(5));
        assert_eq!(options.get_idle_timeout(), Some(Duration::from_secs(240)));
        assert_eq!(options.get_max_lifetime(), None);
        assert!(!options.get_test_before_acquire());
    }

    /// Building the pool does no I/O: nothing listens on port 1, and the
    /// pool is built, empty, with the settings given. Its first query then
    /// fails as an `Err` whose summary is a fixed text.
    #[tokio::test]
    async fn building_the_pool_does_no_io() {
        let options =
            crate::connect_options("postgres://u:secret@127.0.0.1:1/db").expect("a usable URL");
        let pool = lazy_pool(
            options,
            PoolSettings::default()
                .with_max_connections(3)
                .with_acquire_timeout(Duration::from_millis(500)),
        );
        assert_eq!(pool.size(), 0);
        assert_eq!(pool.options().get_max_connections(), 3);

        let error = sqlx::query("SELECT 1")
            .execute(&pool)
            .await
            .expect_err("nothing listens on port 1");
        let summary = crate::error_summary(&error).to_string();
        assert!(
            summary == "timed out waiting for a pool connection"
                || summary.starts_with("I/O error ("),
            "{summary}"
        );
        assert!(!summary.contains("secret"), "{summary}");
    }
}
