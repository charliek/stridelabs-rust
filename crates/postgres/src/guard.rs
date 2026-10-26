//! The begin guard (feature `guard`): [`GuardedPool`], a pool whose
//! transactions begin with a bounded, cancel-safe `BEGIN`, and whose released
//! connections are probed while a `BEGIN` given up on may still be answered.
//!
//! **Why `PgPool::begin` is not enough.** In sqlx 0.9 a `BEGIN` cut off after
//! the server received it, but before its answer arrived, hands the
//! connection back to the pool INSIDE the transaction. The connection's
//! transaction depth is raised only once the answer is read
//! (`sqlx-postgres/src/transaction.rs`), a dropped transaction queues its
//! `ROLLBACK` only at a depth above zero, and the pool's on-release `ping`
//! just drains the late answer. The next borrower's "autocommit" statements
//! then silently join a transaction nobody commits. A client hanging up while
//! a handler awaits `pool.begin()`, or a timeout around one, is exactly that
//! cut. And a `BEGIN` the peer never answers keeps its slot for as long as
//! the peer stays silent.
//!
//! **What the guard does instead** ([`GuardedConnection::begin`]):
//! - the `BEGIN`, and the transaction's `SET LOCAL` bounds after it
//!   ([`TxBounds`]), run in a task of their own, so a caller dropped
//!   meanwhile drops only the task's handle: the task still reads the
//!   answers, and a transaction nobody takes is dropped at depth one, which
//!   queues its `ROLLBACK`;
//! - each of the two is bounded by [`BeginGuard::begin_timeout`]. Giving up
//!   on one cannot mean simply dropping sqlx's future: sqlx 0.9 never gives
//!   the connection back mid-`BEGIN`, so dropping the future releases it to
//!   the pool, and a late answer would put it back inside the transaction. So
//!   the task opens THIS pool's quarantine window FIRST, then drops the
//!   future;
//! - while the window is open, every connection released to the pool is
//!   probed with a bounded `ROLLBACK` ([`BeginGuard::probe_timeout`]): it
//!   ends a late answer's transaction, or, when the connection cannot answer,
//!   hands it to sqlx to close.
//!
//! Each [`GuardedPool`] has its own window (built by [`GuardedPool::lazy`] or
//! [`GuardedPool::sibling`]), so one pool's stuck `BEGIN` never costs another
//! pool's releases a probe. The README states what this guarantees and the
//! residuals it does not close.

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use futures_util::FutureExt as _;
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPool};
use sqlx::{Executor as _, Postgres, Transaction};

use crate::{error_summary, PoolSettings, UrlRefusal};

/// The tracing target of the guard's two WARN lines.
const TARGET: &str = "stridelabs_postgres::guard";

/// [`BeginGuard`]'s default probe timeout: a healthy round trip is
/// milliseconds, and a connection whose `BEGIN` answer never came cannot
/// answer at all.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// [`BeginGuard`]'s default window: the least time a quarantine window stays
/// open, a margin for a busy runtime to run the abandoned connection's
/// release, which sqlx spawned as the connection was dropped.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(30);

/// The longest `begin_timeout` or probe timeout a [`BeginGuard`] accepts (10
/// minutes). Generous by design: the ceiling only rules out a timer that
/// cannot be set (`tokio::time::timeout` silently sets no deadline at all
/// when `now + duration` overflows) and absurd configuration.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(600);

/// The longest window a [`BeginGuard`] accepts (1 hour), so that opening one
/// can never overflow an `Instant`.
pub const MAX_WINDOW: Duration = Duration::from_secs(3600);

/// The longest `application_name` [`GuardedPool::sibling`] accepts:
/// PostgreSQL's `NAMEDATALEN - 1`. A longer name is truncated by the server
/// with a NOTICE that quotes it.
pub const MAX_APPLICATION_NAME_BYTES: usize = 63;

// ── BeginGuard ──────────────────────────────────────────────────────────

/// How a [`GuardedPool`] bounds a `BEGIN` and probes its releases: the
/// `BEGIN` (and `SET LOCAL`) timeout, the probe timeout and the window.
///
/// Its constructors are `const fn`s that refuse an unsupported duration with
/// a panic, which is a compile error in a `const`, so a consumer that holds
/// its guard as a `const` cannot ship one:
///
/// ```
/// use std::time::Duration;
/// use stridelabs_postgres::BeginGuard;
///
/// // lumen's: a 5 s BEGIN, a 1 s probe, a 30 s window.
/// const GUARD: BeginGuard = BeginGuard::new(Duration::from_secs(5))
///     .with_probe_timeout(Duration::from_secs(1))
///     .with_window(Duration::from_secs(30));
/// assert_eq!(GUARD.begin_timeout(), Duration::from_secs(5));
/// ```
///
/// ```compile_fail
/// use std::time::Duration;
/// use stridelabs_postgres::BeginGuard;
///
/// const GUARD: BeginGuard = BeginGuard::new(Duration::from_secs(5)).with_window(Duration::MAX);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeginGuard {
    begin_timeout: Duration,
    probe_timeout: Duration,
    window: Duration,
}

impl BeginGuard {
    /// A guard whose `BEGIN` (and `SET LOCAL`) is given up on after
    /// `begin_timeout`, with [`DEFAULT_PROBE_TIMEOUT`] and [`DEFAULT_WINDOW`].
    /// There is no default bound: it is the consumer's policy.
    ///
    /// # Panics
    /// When `begin_timeout` is zero or over [`MAX_TIMEOUT`] (at compile time
    /// in a `const`).
    #[must_use]
    pub const fn new(begin_timeout: Duration) -> BeginGuard {
        assert!(!begin_timeout.is_zero(), "BeginGuard: a zero begin_timeout");
        assert!(
            begin_timeout.as_nanos() <= MAX_TIMEOUT.as_nanos(),
            "BeginGuard: begin_timeout over MAX_TIMEOUT"
        );
        BeginGuard {
            begin_timeout,
            probe_timeout: DEFAULT_PROBE_TIMEOUT,
            window: DEFAULT_WINDOW,
        }
    }

    /// Replace the probe timeout: how long a released connection's
    /// `ROLLBACK` probe may take before the connection is handed to sqlx to
    /// close.
    ///
    /// # Panics
    /// When `timeout` is zero or over [`MAX_TIMEOUT`] (at compile time in a
    /// `const`).
    #[must_use]
    pub const fn with_probe_timeout(mut self, timeout: Duration) -> BeginGuard {
        assert!(!timeout.is_zero(), "BeginGuard: a zero probe timeout");
        assert!(
            timeout.as_nanos() <= MAX_TIMEOUT.as_nanos(),
            "BeginGuard: probe timeout over MAX_TIMEOUT"
        );
        self.probe_timeout = timeout;
        self
    }

    /// Replace the window: the least time the pool's quarantine stays open
    /// after a `BEGIN` is given up on. It also stays open until the pool's
    /// `max_connections` releases have been probed (README, "The window").
    ///
    /// # Panics
    /// When `window` is over [`MAX_WINDOW`] (at compile time in a `const`).
    #[must_use]
    pub const fn with_window(mut self, window: Duration) -> BeginGuard {
        assert!(
            window.as_nanos() <= MAX_WINDOW.as_nanos(),
            "BeginGuard: window over MAX_WINDOW"
        );
        self.window = window;
        self
    }

    /// How long a `BEGIN`, and then its `SET LOCAL`, may go unanswered.
    pub const fn begin_timeout(&self) -> Duration {
        self.begin_timeout
    }

    /// How long a released connection's `ROLLBACK` probe may take.
    pub const fn probe_timeout(&self) -> Duration {
        self.probe_timeout
    }

    /// The least time a quarantine window stays open.
    pub const fn window(&self) -> Duration {
        self.window
    }
}

// ── TxBounds ────────────────────────────────────────────────────────────

/// A transaction's `lock_timeout` and `statement_timeout`, in milliseconds,
/// sent as the transaction's first statement, right after `BEGIN`
/// ([`TxBounds::sql`]), or [`TxBounds::NONE`] for none.
///
/// Both are `SET LOCAL`: they end with the transaction, so a connection goes
/// back to the pool with the server's defaults. They go as ONE simple query,
/// so the server applies both or neither.
///
/// ```
/// use stridelabs_postgres::TxBounds;
///
/// const REQUEST: TxBounds = TxBounds::from_millis(5_000, 10_000);
/// assert_eq!(
///     REQUEST.sql().as_deref(),
///     Some("SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '10000ms'")
/// );
/// assert_eq!(TxBounds::NONE.sql(), None);
/// ```
///
/// [`TxBounds::from_millis`] refuses bounds the server would refuse or that
/// make no sense, at compile time in a `const`: a zero lock timeout (use
/// [`TxBounds::NONE`]),
///
/// ```compile_fail
/// const ZERO: stridelabs_postgres::TxBounds = stridelabs_postgres::TxBounds::from_millis(0, 10);
/// ```
///
/// a lock timeout that is not below the statement timeout,
///
/// ```compile_fail
/// const EQUAL: stridelabs_postgres::TxBounds = stridelabs_postgres::TxBounds::from_millis(10, 10);
/// ```
///
/// and a statement timeout over PostgreSQL's ceiling ([`TxBounds::MAX_MILLIS`]):
///
/// ```compile_fail
/// const BIG: stridelabs_postgres::TxBounds =
///     stridelabs_postgres::TxBounds::from_millis(1, 2_147_483_648);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxBounds {
    /// 0, with `statement_ms` 0, only in [`TxBounds::NONE`].
    lock_ms: u32,
    statement_ms: u32,
}

impl TxBounds {
    /// No bounds: nothing is sent after `BEGIN`.
    pub const NONE: TxBounds = TxBounds {
        lock_ms: 0,
        statement_ms: 0,
    };

    /// PostgreSQL's ceiling for both settings, in milliseconds (`INT_MAX`).
    pub const MAX_MILLIS: u32 = 2_147_483_647;

    /// **A test seam, not for consumers:** bounds the server refuses (SQLSTATE
    /// `22023`, both over [`TxBounds::MAX_MILLIS`]), for a test of a failed
    /// `SET LOCAL`. [`TxBounds::from_millis`] cannot build them.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub const REFUSED_BY_THE_SERVER: TxBounds = TxBounds {
        lock_ms: u32::MAX - 1,
        statement_ms: u32::MAX,
    };

    /// A `lock_timeout` of `lock_ms` and a `statement_timeout` of
    /// `statement_ms`, both in milliseconds.
    ///
    /// # Panics
    /// When `lock_ms` is 0, `lock_ms >= statement_ms`, or `statement_ms` is
    /// over [`TxBounds::MAX_MILLIS`] (at compile time in a `const`).
    #[must_use]
    pub const fn from_millis(lock_ms: u32, statement_ms: u32) -> TxBounds {
        assert!(lock_ms > 0, "TxBounds: lock_ms is 0 (use TxBounds::NONE)");
        assert!(
            lock_ms < statement_ms,
            "TxBounds: lock_ms must be below statement_ms"
        );
        assert!(
            statement_ms <= TxBounds::MAX_MILLIS,
            "TxBounds: above PostgreSQL's ceiling"
        );
        TxBounds {
            lock_ms,
            statement_ms,
        }
    }

    /// Whether these are [`TxBounds::NONE`].
    pub const fn is_none(&self) -> bool {
        self.statement_ms == 0
    }

    /// The `lock_timeout`, or `None` for [`TxBounds::NONE`].
    pub const fn lock_timeout(&self) -> Option<Duration> {
        if self.is_none() {
            None
        } else {
            Some(Duration::from_millis(self.lock_ms as u64))
        }
    }

    /// The `statement_timeout`, or `None` for [`TxBounds::NONE`].
    pub const fn statement_timeout(&self) -> Option<Duration> {
        if self.is_none() {
            None
        } else {
            Some(Duration::from_millis(self.statement_ms as u64))
        }
    }

    /// The one simple query sent right after `BEGIN`, or `None` for
    /// [`TxBounds::NONE`]. Rendered from two integers, so it carries nothing
    /// a caller could inject.
    pub fn sql(&self) -> Option<String> {
        (!self.is_none()).then(|| {
            format!(
                "SET LOCAL lock_timeout = '{}ms'; SET LOCAL statement_timeout = '{}ms'",
                self.lock_ms, self.statement_ms
            )
        })
    }
}

impl fmt::Debug for TxBounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_none() {
            return f.write_str("TxBounds::NONE");
        }
        f.debug_struct("TxBounds")
            .field("lock_ms", &self.lock_ms)
            .field("statement_ms", &self.statement_ms)
            .finish()
    }
}

// ── The window ──────────────────────────────────────────────────────────

/// One pool's quarantine window, its clock passed in (so the tests can step
/// past the deadline without waiting it out).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Window {
    /// Not before this: the latest opening plus the guard's window. `None`
    /// while closed.
    until: Option<Instant>,
    /// Releases still to probe since the latest opening.
    probes_owed: u32,
}

impl Window {
    const CLOSED: Window = Window {
        until: None,
        probes_owed: 0,
    };

    /// Open (or hold open) the window at `now`: until `length` from now at
    /// least (an earlier opening's later deadline is kept), and until
    /// `probes` more releases have been probed.
    fn open(&mut self, now: Instant, length: Duration, probes: u32) {
        let until = now + length;
        self.until = Some(self.until.map_or(until, |current| current.max(until)));
        self.probes_owed = probes;
    }

    /// Whether a release at `now` is probed, counted as one if so. Open
    /// while the deadline is ahead OR probes are still owed; closed (and
    /// reset) once neither holds.
    fn probe(&mut self, now: Instant) -> bool {
        let Some(until) = self.until else {
            return false;
        };
        if now < until || self.probes_owed > 0 {
            self.probes_owed = self.probes_owed.saturating_sub(1);
            return true;
        }
        *self = Window::CLOSED;
        false
    }
}

/// One pool's guard state: its guard, the probes an opening owes (the pool's
/// `max_connections`) and its window, behind a `std` mutex held for one
/// decision and never across an `.await`. It holds no pool, so there is no
/// reference cycle through the pool's `after_release` hook.
struct Quarantine {
    guard: BeginGuard,
    probes: u32,
    window: Mutex<Window>,
}

impl Quarantine {
    fn lock(&self) -> MutexGuard<'_, Window> {
        self.window.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn open(&self, now: Instant) {
        self.lock().open(now, self.guard.window, self.probes);
    }

    fn probe(&self, now: Instant) -> bool {
        self.lock().probe(now)
    }
}

/// Why a `BEGIN` (or its `SET LOCAL`) was given up on: the `cause` field of
/// the guard's first WARN line.
#[derive(Clone, Copy)]
enum Cause {
    Timeout,
    Error,
    Panic,
    SetLocalTimeout,
}

impl Cause {
    const fn as_str(self) -> &'static str {
        match self {
            Cause::Timeout => "timeout",
            Cause::Error => "error",
            Cause::Panic => "panic",
            Cause::SetLocalTimeout => "set_local_timeout",
        }
    }
}

// ── GuardedPool ─────────────────────────────────────────────────────────

/// A pool whose transactions begin through the guard
/// ([`GuardedPool::begin`], [`GuardedConnection::begin`]), with a quarantine
/// window of its own, which its `after_release` hook reads.
///
/// It derefs to sqlx's [`PgPool`], so autocommit statements run on it as on
/// any pool (`sqlx::query(…).execute(&*pool)`, or `&pool` where a `&PgPool`
/// is expected). Its own `acquire` and `begin` shadow sqlx's, so
/// `pool.begin()` and `pool.acquire()` with sqlx's arguments do not compile.
/// The `Deref` still exposes sqlx's other entry points
/// (`try_begin`, `begin_with`, `(*pool).acquire()`, `set_connect_options`,
/// building a pool from `pool.options().clone()`, a raw `BEGIN`): none of
/// them has the guard, so a consumer forbids them (README, "What the type
/// guarantees").
///
/// Clones share the pool and its window. Its `Debug` prints the pool's size
/// and the guard, never the connect options (sqlx's `Debug` of them prints
/// the password).
#[derive(Clone)]
pub struct GuardedPool {
    pool: PgPool,
    quarantine: Arc<Quarantine>,
}

impl GuardedPool {
    /// The pool for `options` with `settings`, guarded by `guard`, **without
    /// connecting** (as [`lazy_pool`](crate::lazy_pool), whose rules it
    /// keeps: pass what [`connect_options`](crate::connect_options)
    /// returned). Its window owes `settings.max_connections` probes per
    /// opening.
    ///
    /// The pool's `after_release` hook is the guard's: `lazy` takes no other.
    ///
    /// Call it inside a Tokio runtime: sqlx spawns the pool's maintenance
    /// task as it builds the pool.
    ///
    /// ```
    /// use std::time::Duration;
    /// use stridelabs_postgres::{connect_options, BeginGuard, GuardedPool, PoolSettings};
    ///
    /// const GUARD: BeginGuard = BeginGuard::new(Duration::from_secs(5));
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> Result<(), stridelabs_postgres::UrlRefusal> {
    /// // Port 1: nothing listens there, and the pool is built all the same.
    /// let options = connect_options("postgres://app:secret@127.0.0.1:1/app")?;
    /// let pool = GuardedPool::lazy(options, PoolSettings::default(), GUARD);
    /// assert_eq!(pool.size(), 0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn lazy(
        options: PgConnectOptions,
        settings: PoolSettings,
        guard: BeginGuard,
    ) -> GuardedPool {
        let quarantine = Arc::new(Quarantine {
            guard,
            probes: settings.max_connections,
            window: Mutex::new(Window::CLOSED),
        });
        let hook = Arc::clone(&quarantine);
        let pool = settings
            .pool_options()
            .after_release(move |connection, _metadata| {
                // Decided as the release runs, under the mutex, before any
                // await: the future only runs the probe.
                let probe = hook.probe(Instant::now());
                let timeout = hook.guard.probe_timeout;
                Box::pin(async move {
                    if !probe {
                        return Ok(true);
                    }
                    release_probe(connection, timeout).await
                })
            })
            .connect_lazy_with(options);
        GuardedPool { pool, quarantine }
    }

    /// A second pool on this one's connect options, with `settings`, THIS
    /// pool's [`BeginGuard`] and a window of its own (so neither pool's stuck
    /// `BEGIN` probes the other's releases). Nothing changes in the options
    /// but, if given, `application_name`. A pool that needs other options or
    /// another guard is built with [`GuardedPool::lazy`] on the consumer's own
    /// checked options.
    ///
    /// The name is checked, since sqlx copies it into the startup packet as
    /// given: printable ASCII only (so no NUL, which would end the field and
    /// start another startup parameter), 1 to [`MAX_APPLICATION_NAME_BYTES`]
    /// bytes (under the server's truncation, whose NOTICE would quote it).
    ///
    /// Like [`GuardedPool::lazy`], call it inside a Tokio runtime.
    ///
    /// # Errors
    /// [`UrlRefusal::NulByte`]`("application_name")` for a NUL byte;
    /// [`UrlRefusal::InvalidValue`]`("application_name")` when it is empty,
    /// over [`MAX_APPLICATION_NAME_BYTES`] bytes, or holds anything but
    /// printable ASCII (`0x20..=0x7E`). Neither prints the name.
    pub fn sibling(
        &self,
        settings: PoolSettings,
        application_name: Option<&str>,
    ) -> Result<GuardedPool, UrlRefusal> {
        let mut options = (*self.pool.connect_options()).clone();
        if let Some(name) = application_name {
            check_application_name(name)?;
            options = options.application_name(name);
        }
        Ok(GuardedPool::lazy(options, settings, self.quarantine.guard))
    }

    /// The guard this pool was built with.
    pub fn guard(&self) -> BeginGuard {
        self.quarantine.guard
    }

    /// A connection out of the pool within `bound` (or the pool's own
    /// `acquire_timeout`, whichever passes first). No transaction: what runs
    /// on it autocommits, and [`GuardedConnection::begin`] opens one. A
    /// checkout cut off by `bound` has handed out nothing (sqlx gives back a
    /// connection it had acquired).
    ///
    /// # Errors
    /// [`sqlx::Error::PoolTimedOut`] when `bound` passes first; otherwise the
    /// pool's own error.
    pub async fn acquire(&self, bound: Duration) -> Result<GuardedConnection, sqlx::Error> {
        let connection = tokio::time::timeout(bound, self.pool.acquire())
            .await
            .unwrap_or(Err(sqlx::Error::PoolTimedOut))?;
        Ok(GuardedConnection {
            connection,
            quarantine: Arc::clone(&self.quarantine),
        })
    }

    /// A transaction: [`GuardedPool::acquire`] within `bound`, then
    /// [`GuardedConnection::begin`] with `bounds`.
    ///
    /// # Errors
    /// Either step's error.
    pub async fn begin(
        &self,
        bound: Duration,
        bounds: TxBounds,
    ) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
        self.acquire(bound).await?.begin(bounds).await
    }

    /// **A test seam, not for consumers:** replace this pool's window with
    /// one opened at `opened` (a moment ago, or more than the window ago),
    /// with all of its probes owed, so a test can see what the window does
    /// without a `BEGIN` given up on, or past its deadline without waiting it
    /// out.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn set_window_opened_at(&self, opened: Instant) {
        let mut window = self.quarantine.lock();
        *window = Window::CLOSED;
        window.open(opened, self.quarantine.guard.window, self.quarantine.probes);
    }
}

impl Deref for GuardedPool {
    type Target = PgPool;

    fn deref(&self) -> &PgPool {
        &self.pool
    }
}

impl fmt::Debug for GuardedPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardedPool")
            .field("size", &self.pool.size())
            .field("guard", &self.quarantine.guard)
            .finish_non_exhaustive()
    }
}

/// [`GuardedPool::sibling`]'s check of an `application_name`.
fn check_application_name(name: &str) -> Result<(), UrlRefusal> {
    if name.contains('\0') {
        return Err(UrlRefusal::NulByte("application_name"));
    }
    if name.is_empty()
        || name.len() > MAX_APPLICATION_NAME_BYTES
        || !name.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(UrlRefusal::InvalidValue("application_name"));
    }
    Ok(())
}

// ── GuardedConnection ───────────────────────────────────────────────────

/// A connection checked out of a [`GuardedPool`] ([`GuardedPool::acquire`]),
/// carrying that pool's window, so [`GuardedConnection::begin`] always opens
/// the right one.
///
/// It derefs to sqlx's [`PgConnection`]: statements run on `&mut *connection`
/// (or `&mut connection` where a `&mut PgConnection` is expected) and
/// autocommit. Dropping it returns the connection to its pool. Its `Debug`
/// prints nothing of the connection.
pub struct GuardedConnection {
    connection: PoolConnection<Postgres>,
    quarantine: Arc<Quarantine>,
}

impl GuardedConnection {
    /// **A transaction on this connection, begun so that no cancellation can
    /// abandon it half-way and no peer can hold it unbounded.**
    ///
    /// A plain `BEGIN`, then, at depth one, `bounds`' `SET LOCAL` statement
    /// ([`TxBounds::sql`]; nothing for [`TxBounds::NONE`]), both in a spawned
    /// task that owns the connection, each within the guard's
    /// [`begin_timeout`](BeginGuard::begin_timeout). A caller dropped
    /// meanwhile drops only the task's handle: the task still reads both
    /// answers, and the transaction it built is then dropped at depth one,
    /// which queues the `ROLLBACK` that sqlx's release `ping` flushes.
    ///
    /// When the `BEGIN` goes unanswered past the bound, fails, or panics, or
    /// the `SET LOCAL` goes unanswered past it, the task opens this pool's
    /// quarantine window BEFORE it drops the `BEGIN` (or the transaction), and
    /// logs it (target `stridelabs_postgres::guard`, WARN, `a BEGIN was
    /// abandoned; probing released connections`, `cause` = `timeout`,
    /// `error`, `panic` or `set_local_timeout`). A `SET LOCAL` the server
    /// refuses opens nothing: the peer answered, and the transaction is
    /// dropped at depth one.
    ///
    /// Uses sqlx's `#[doc(hidden)]` `Transaction::begin` (README).
    ///
    /// # Errors
    /// - an I/O `TimedOut` error when the `BEGIN`, or then the `SET LOCAL`,
    ///   goes unanswered for the bound (`error_summary`: `I/O error
    ///   (TimedOut)`);
    /// - the `BEGIN`'s own error (sqlx's `BeginFailed` for an answer that is
    ///   not in a transaction), or the `SET LOCAL`'s (a refusal: SQLSTATE
    ///   `22023`, say);
    /// - [`sqlx::Error::WorkerCrashed`] when the `BEGIN` panicked, or the task
    ///   never answered (the runtime is shutting down).
    pub async fn begin(
        self,
        bounds: TxBounds,
    ) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
        let GuardedConnection {
            connection,
            quarantine,
        } = self;
        tokio::spawn(begin_within(connection, quarantine, bounds))
            .await
            .unwrap_or(Err(sqlx::Error::WorkerCrashed))
    }

    /// The connection, out of its pool for good: its slot is freed now, and
    /// the connection is closed when it is dropped (sqlx's
    /// `PoolConnection::detach`). For work whose disposal must not wait on
    /// the pool's release path.
    pub fn detach(self) -> PgConnection {
        self.connection.detach()
    }
}

impl Deref for GuardedConnection {
    type Target = PgConnection;

    fn deref(&self) -> &PgConnection {
        &self.connection
    }
}

impl DerefMut for GuardedConnection {
    fn deref_mut(&mut self) -> &mut PgConnection {
        &mut self.connection
    }
}

impl fmt::Debug for GuardedConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardedConnection").finish_non_exhaustive()
    }
}

/// [`GuardedConnection::begin`]'s task: the `BEGIN` within the bound, the
/// window opened before the future (and with it the connection) is dropped
/// on any way out but success; then the bounds statement.
async fn begin_within(
    connection: PoolConnection<Postgres>,
    quarantine: Arc<Quarantine>,
    bounds: TxBounds,
) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let bound = quarantine.guard.begin_timeout;
    let mut begin = AssertUnwindSafe(Transaction::begin(connection, None)).catch_unwind();
    let (outcome, cause) = match tokio::time::timeout(bound, &mut begin).await {
        Ok(Ok(Ok(transaction))) => return set_local(transaction, &quarantine, bounds).await,
        Ok(Ok(Err(error))) => (Err(error), Cause::Error),
        Ok(Err(_panic)) => (Err(sqlx::Error::WorkerCrashed), Cause::Panic),
        Err(_elapsed) => (Err(timed_out()), Cause::Timeout),
    };
    abandon(&quarantine, cause);
    drop(begin);
    outcome
}

/// The bounds statement at depth one, within the guard's `begin_timeout`. A
/// TIMEOUT opens the window before the transaction (and its connection) is
/// dropped, as an unanswered `BEGIN` does: the peer answered the `BEGIN` and
/// went silent, and without a probe the release's `ping` would wait on it. A
/// refusal opens nothing: the dropped transaction queues its `ROLLBACK`, and
/// the peer is answering.
async fn set_local(
    mut transaction: Transaction<'static, Postgres>,
    quarantine: &Quarantine,
    bounds: TxBounds,
) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let Some(sql) = bounds.sql() else {
        return Ok(transaction);
    };
    let statement = sqlx::raw_sql(sqlx::AssertSqlSafe(sql)).execute(&mut *transaction);
    match tokio::time::timeout(quarantine.guard.begin_timeout, statement).await {
        Ok(Ok(_)) => Ok(transaction),
        Ok(Err(error)) => Err(error),
        Err(_elapsed) => {
            abandon(quarantine, Cause::SetLocalTimeout);
            drop(transaction);
            Err(timed_out())
        }
    }
}

/// Open the pool's window, then say so: the guard's first line.
fn abandon(quarantine: &Quarantine, cause: Cause) {
    quarantine.open(Instant::now());
    tracing::warn!(
        target: TARGET,
        cause = cause.as_str(),
        "a BEGIN was abandoned; probing released connections"
    );
}

fn timed_out() -> sqlx::Error {
    sqlx::Error::Io(std::io::ErrorKind::TimedOut.into())
}

/// The probe of a release in an open window: `Ok(true)` keeps the connection
/// (sqlx then pings it, as without the hook); `Err` hands it to sqlx to close
/// (`close_hard`), logged first: the guard's second line. "Closed" there
/// means a close REQUESTED; sqlx's own disposal can still wait on a silent
/// peer (README, residual 3).
async fn release_probe(
    connection: &mut PgConnection,
    timeout: Duration,
) -> Result<bool, sqlx::Error> {
    let failure = match tokio::time::timeout(timeout, connection.execute("ROLLBACK")).await {
        Ok(Ok(_)) => return Ok(true),
        Ok(Err(error)) => error,
        Err(_elapsed) => timed_out(),
    };
    tracing::warn!(
        target: TARGET,
        error = %error_summary(&failure),
        "a released connection failed its probe; closed"
    );
    Err(failure)
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

    use super::*;

    const PROBES: u32 = 15;

    fn seconds(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// **U1.** Closed until opened. Before its deadline every release is
    /// probed, however many. Re-opened, so that all `PROBES` are owed again,
    /// and then read past its deadline, it probes exactly the probes it
    /// still owes, then closes and resets. The control: a closed window
    /// probes nothing.
    #[test]
    fn the_window_needs_its_deadline_and_its_probes() {
        let t0 = Instant::now();
        let mut window = Window::CLOSED;
        for at in [0, 1, 31, 3600] {
            assert!(
                !window.probe(t0 + seconds(at)),
                "closed: no probe at {at} s"
            );
        }
        assert_eq!(window, Window::CLOSED);

        window.open(t0, DEFAULT_WINDOW, PROBES);
        for _ in 0..(PROBES * 3) {
            assert!(window.probe(t0 + seconds(1)), "inside the deadline");
        }
        assert_eq!(window.probes_owed, 0, "the probes are spent");
        assert!(window.probe(t0 + seconds(29)), "still inside the deadline");

        window.open(t0 + seconds(10), DEFAULT_WINDOW, PROBES);
        assert!(window.probe(t0 + seconds(11)));
        assert!(window.probe(t0 + seconds(12)));
        let past = t0 + seconds(10) + DEFAULT_WINDOW + seconds(1);
        for owed in (1..=PROBES - 2).rev() {
            assert_eq!(window.probes_owed, owed);
            assert!(window.probe(past), "past the deadline, {owed} probes owed");
        }
        assert!(!window.probe(past), "past the deadline, none owed: closed");
        assert_eq!(window, Window::CLOSED, "and reset");
        assert!(!window.probe(t0 + seconds(11)), "a reset window is closed");
    }

    /// **U2.** A release the runtime ran late (a busy process) but still
    /// inside the deadline is probed, however many hot releases came first.
    /// The control: the same release past the deadline, after `PROBES`
    /// probes, is not.
    #[test]
    fn a_delayed_abandoned_release_inside_the_deadline_is_probed() {
        let t0 = Instant::now();
        let mut window = Window::CLOSED;
        window.open(t0, DEFAULT_WINDOW, PROBES);
        for _ in 0..40 {
            assert!(window.probe(t0 + seconds(1)), "a hot release");
        }
        assert!(window.probe(t0 + seconds(29)), "the abandoned one, late");

        let mut control = Window::CLOSED;
        control.open(t0, DEFAULT_WINDOW, PROBES);
        for _ in 0..PROBES {
            assert!(control.probe(t0 + seconds(1)));
        }
        assert!(
            !control.probe(t0 + seconds(31)),
            "control: past the deadline with no probe owed"
        );
    }

    /// **U3, the documented residual (README, residual 2).** The owed probes
    /// count RELEASES: when the process is paused past the deadline and hot
    /// releases run before the abandoned one, they spend the probes, and the
    /// abandoned release (the 16th here) is not probed.
    #[test]
    fn hot_releases_past_the_deadline_spend_the_owed_probes() {
        let t0 = Instant::now();
        let mut window = Window::CLOSED;
        window.open(t0, DEFAULT_WINDOW, PROBES);
        let past = t0 + DEFAULT_WINDOW + seconds(1);
        for _ in 0..PROBES {
            assert!(window.probe(past), "a hot release spends a probe");
        }
        assert!(!window.probe(past), "the abandoned release, 16th: unprobed");
        assert_eq!(window, Window::CLOSED);
    }

    /// **U4.** A second opening keeps the later of the two deadlines and owes
    /// all the probes again. The control: a single opening's deadline is its
    /// own plus the window.
    #[test]
    fn overlapping_openings_extend_to_the_later_deadline_and_reset_the_probes() {
        let t0 = Instant::now();
        let mut window = Window::CLOSED;
        window.open(t0 + seconds(10), DEFAULT_WINDOW, PROBES);
        assert!(window.probe(t0 + seconds(11)));
        assert_eq!(window.probes_owed, PROBES - 1);
        window.open(t0, DEFAULT_WINDOW, PROBES);
        assert_eq!(
            window.until,
            Some(t0 + seconds(10) + DEFAULT_WINDOW),
            "the later deadline is kept"
        );
        assert_eq!(window.probes_owed, PROBES, "all the probes are owed again");

        let mut single = Window::CLOSED;
        single.open(t0, DEFAULT_WINDOW, PROBES);
        assert_eq!(single.until, Some(t0 + DEFAULT_WINDOW), "control");
    }

    /// **U5.** The bounds render as pinned (lumen's three), `NONE` renders
    /// nothing, the getters read back, `Debug` is fixed; the three refusals
    /// panic at run time too (their `compile_fail` doctests are on
    /// [`TxBounds`]).
    #[test]
    fn the_bounds_render_as_pinned() {
        for (bounds, sql) in [
            (
                TxBounds::from_millis(5_000, 10_000),
                "SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '10000ms'",
            ),
            (
                TxBounds::from_millis(3_000, 5_000),
                "SET LOCAL lock_timeout = '3000ms'; SET LOCAL statement_timeout = '5000ms'",
            ),
            (
                TxBounds::from_millis(1_000, 2_000),
                "SET LOCAL lock_timeout = '1000ms'; SET LOCAL statement_timeout = '2000ms'",
            ),
        ] {
            assert_eq!(bounds.sql().as_deref(), Some(sql), "the pinned text");
            assert!(!bounds.is_none());
        }
        let request = TxBounds::from_millis(5_000, 10_000);
        assert_eq!(request.lock_timeout(), Some(seconds(5)));
        assert_eq!(request.statement_timeout(), Some(seconds(10)));
        assert_eq!(
            format!("{request:?}"),
            "TxBounds { lock_ms: 5000, statement_ms: 10000 }"
        );

        assert!(TxBounds::NONE.is_none());
        assert_eq!(TxBounds::NONE.sql(), None);
        assert_eq!(TxBounds::NONE.lock_timeout(), None);
        assert_eq!(TxBounds::NONE.statement_timeout(), None);
        assert_eq!(format!("{:?}", TxBounds::NONE), "TxBounds::NONE");

        let ceiling = TxBounds::from_millis(1, TxBounds::MAX_MILLIS);
        assert_eq!(
            ceiling.sql().as_deref(),
            Some("SET LOCAL lock_timeout = '1ms'; SET LOCAL statement_timeout = '2147483647ms'")
        );
        for (lock_ms, statement_ms) in [(0, 1), (2, 2), (3, 2), (1, TxBounds::MAX_MILLIS + 1)] {
            assert!(
                catch_unwind(|| TxBounds::from_millis(lock_ms, statement_ms)).is_err(),
                "from_millis({lock_ms}, {statement_ms}) is refused"
            );
        }
    }

    /// **U6.** `new` takes the defaults; each builder replaces its duration;
    /// the maxima themselves are accepted, and anything zero (but a window)
    /// or over them panics (a `compile_fail` doctest on [`BeginGuard`] holds
    /// it for a `const`).
    #[test]
    fn the_guard_refuses_unsupported_durations() {
        let guard = BeginGuard::new(seconds(5));
        assert_eq!(guard.begin_timeout(), seconds(5));
        assert_eq!(guard.probe_timeout(), DEFAULT_PROBE_TIMEOUT);
        assert_eq!(guard.probe_timeout(), seconds(1));
        assert_eq!(guard.window(), DEFAULT_WINDOW);
        assert_eq!(guard.window(), seconds(30));
        let tuned = guard
            .with_probe_timeout(Duration::from_millis(500))
            .with_window(Duration::ZERO);
        assert_eq!(tuned.begin_timeout(), seconds(5));
        assert_eq!(tuned.probe_timeout(), Duration::from_millis(500));
        assert_eq!(tuned.window(), Duration::ZERO);

        let widest = BeginGuard::new(MAX_TIMEOUT)
            .with_probe_timeout(MAX_TIMEOUT)
            .with_window(MAX_WINDOW);
        assert_eq!(widest.begin_timeout(), MAX_TIMEOUT);
        assert_eq!(widest.probe_timeout(), MAX_TIMEOUT);
        assert_eq!(widest.window(), MAX_WINDOW);

        let nanosecond = Duration::from_nanos(1);
        for timeout in [Duration::ZERO, MAX_TIMEOUT + nanosecond, Duration::MAX] {
            assert!(
                catch_unwind(|| BeginGuard::new(timeout)).is_err(),
                "new({timeout:?}) is refused"
            );
            assert!(
                catch_unwind(|| guard.with_probe_timeout(timeout)).is_err(),
                "with_probe_timeout({timeout:?}) is refused"
            );
        }
        for window in [MAX_WINDOW + nanosecond, Duration::MAX] {
            assert!(
                catch_unwind(|| guard.with_window(window)).is_err(),
                "with_window({window:?}) is refused"
            );
        }
    }

    /// **U7.** `lazy` does no I/O (nothing listens on port 1) and its
    /// settings reach sqlx's pool options. `sibling` keeps the parent's
    /// options (`None`), or changes only `application_name`; it carries the
    /// parent's guard, and each pool has its own window: one opened leaves
    /// the other closed. `Debug` never prints the URL's password.
    #[tokio::test]
    async fn a_guarded_pool_is_built_without_io_with_its_settings() {
        const CANARY: &str = "guarded-pool-canary";
        let options = crate::connect_options(&format!(
            "postgres://app:{CANARY}@127.0.0.1:1/db?application_name=parent"
        ))
        .expect("a usable URL");
        let guard = BeginGuard::new(seconds(5)).with_window(seconds(7));
        let settings = PoolSettings::default()
            .with_max_connections(3)
            .with_acquire_timeout(Duration::from_millis(500))
            .with_test_before_acquire(false);
        let parent = GuardedPool::lazy(options, settings, guard);
        assert_eq!(parent.size(), 0, "built without connecting");
        let pool_options = parent.options();
        assert_eq!(pool_options.get_max_connections(), 3);
        assert_eq!(
            pool_options.get_acquire_timeout(),
            Duration::from_millis(500)
        );
        assert!(!pool_options.get_test_before_acquire());
        assert_eq!(
            parent.quarantine.probes, 3,
            "an opening owes max_connections"
        );
        assert_eq!(parent.guard(), guard);

        let same = parent
            .sibling(PoolSettings::default().with_max_connections(2), None)
            .expect("no name to check");
        let renamed = parent
            .sibling(PoolSettings::default(), Some("svc"))
            .expect("a valid name");
        for (sibling, name) in [(&same, "parent"), (&renamed, "svc")] {
            let (theirs, ours) = (sibling.connect_options(), parent.connect_options());
            assert_eq!(theirs.get_application_name(), Some(name));
            assert_eq!(theirs.get_host(), ours.get_host());
            assert_eq!(theirs.get_port(), ours.get_port());
            assert_eq!(theirs.get_username(), ours.get_username());
            assert_eq!(theirs.get_database(), ours.get_database());
            assert_eq!(
                format!("{:?}", theirs.get_ssl_mode()),
                format!("{:?}", ours.get_ssl_mode())
            );
            assert_eq!(theirs.get_options(), ours.get_options());
            assert_eq!(sibling.guard(), guard, "the parent's guard");
        }
        let now = Instant::now();
        same.quarantine.open(now);
        assert!(same.quarantine.probe(now), "the sibling's window is open");
        assert!(!parent.quarantine.probe(now), "the parent's is not");
        assert!(!renamed.quarantine.probe(now), "nor the other sibling's");
        assert_eq!(same.quarantine.probes, 2, "the sibling's own settings");
        assert_eq!(same.options().get_max_connections(), 2);
        parent.quarantine.open(now);
        assert!(parent.quarantine.probe(now));
        assert!(!renamed.quarantine.probe(now));
        assert_eq!(
            parent.quarantine.lock().until,
            Some(now + seconds(7)),
            "the guard's window"
        );

        for pool in [&parent, &same, &renamed] {
            let debug = format!("{pool:?}");
            assert!(
                debug.starts_with("GuardedPool { size: 0, guard: BeginGuard {"),
                "{debug}"
            );
            assert!(!debug.contains(CANARY), "{debug}");
        }
        assert!(
            format!("{:?}", parent.connect_options()).contains(CANARY),
            "premise: sqlx's own Debug prints the password"
        );
    }

    /// **U8.** `sibling`'s name check: printable ASCII, 1 to 63 bytes; a NUL
    /// is named as one.
    #[test]
    fn application_names_are_checked() {
        for good in [
            "lumen-usage",
            "x",
            " ~",
            &"a".repeat(MAX_APPLICATION_NAME_BYTES),
        ] {
            assert_eq!(check_application_name(good), Ok(()), "{good:?}");
        }
        assert_eq!(
            check_application_name("x\0search_path\0y"),
            Err(UrlRefusal::NulByte("application_name"))
        );
        for bad in [
            "",
            "tab\there",
            "line\nbreak",
            "del\u{7f}",
            "caf\u{e9}",
            &"a".repeat(MAX_APPLICATION_NAME_BYTES + 1),
        ] {
            assert_eq!(
                check_application_name(bad),
                Err(UrlRefusal::InvalidValue("application_name")),
                "{bad:?}"
            );
        }
    }

    /// `sibling` refuses a bad name before it builds anything.
    #[tokio::test]
    async fn a_sibling_with_a_bad_name_is_refused() {
        let options =
            crate::connect_options("postgres://app@127.0.0.1:1/db").expect("a usable URL");
        let parent = GuardedPool::lazy(
            options,
            PoolSettings::default(),
            BeginGuard::new(seconds(1)),
        );
        assert_eq!(
            parent
                .sibling(PoolSettings::default(), Some("x\0search_path\0y"))
                .map(drop),
            Err(UrlRefusal::NulByte("application_name"))
        );
        assert_eq!(
            parent.sibling(PoolSettings::default(), Some("")).map(drop),
            Err(UrlRefusal::InvalidValue("application_name"))
        );
    }

    /// The call shapes a consumer relies on compile (never run): a guarded
    /// pool where a `&PgPool` is expected, a guarded connection where a
    /// `&mut PgConnection` is, a transaction from either, `Send` futures.
    #[allow(dead_code)]
    async fn call_shapes(pool: GuardedPool) -> Result<(), sqlx::Error> {
        async fn reads(_: &PgPool) {}
        async fn on_connection(_: &mut PgConnection) {}
        fn is_send<T: Send>(_: &T) {}
        fn is_send_sync<T: Send + Sync + 'static>() {}
        is_send_sync::<GuardedPool>();
        is_send_sync::<GuardedConnection>();

        reads(&pool).await;
        sqlx::query("SELECT 1").execute(&*pool).await?;
        let mut connection = pool.acquire(seconds(5)).await?;
        on_connection(&mut connection).await;
        sqlx::query("SELECT 1").execute(&mut *connection).await?;
        let mut transaction = connection.begin(TxBounds::from_millis(1, 2)).await?;
        sqlx::query("SELECT 1").execute(&mut *transaction).await?;
        transaction.commit().await?;
        let begin = pool.begin(seconds(5), TxBounds::NONE);
        is_send(&begin);
        begin.await?.rollback().await?;
        let detached: PgConnection = pool.acquire(seconds(5)).await?.detach();
        drop(detached);
        Ok(())
    }
}
