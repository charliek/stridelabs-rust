//! The begin guard against a real Postgres (feature `live-tests`; CI's
//! all-features lane). `require_postgres` panics when there is no server
//! (`docker compose up -d`), so this suite never passes by skipping.
//!
//! Most tests reach the server through `common/pg_fault.rs`'s relay, which
//! holds or rewrites the answer to the first `BEGIN` (or to the statement
//! after it) and records what each pool's connections ran. Every pool has an
//! `application_name` of its own (`sl-guard-<test>-<pid>-<n>`), so
//! `pg_stat_activity` is read for that pool's backends only, and every test
//! that writes has a table of its own, dropped at the end. Each test runs on
//! a current-thread runtime (`#[tokio::test]`'s default), so the scoped
//! subscriber that records the guard's lines sees every task's events. Each
//! runs under a 30 s deadline, its table's setup included, and a test's
//! table is dropped within 10 s more, whatever the test did.
//!
//! The guard here is fast (`GUARD`: a 1 s `BEGIN`, a 500 ms probe, a 5 s
//! window), so no test waits out lumen's production 5 s / 30 s. Every test
//! has its negative control: the same fault without the guard (a pool
//! without the hook, or sqlx's own `begin`), or the window left closed.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures_util::FutureExt as _;

use sqlx::postgres::{PgConnectOptions, PgConnection, PgPool};
use sqlx::Row as _;
use stridelabs_postgres::{
    connect_options, error_summary, lazy_pool, BeginGuard, GuardedPool, PoolSettings, TxBounds,
};
use stridelabs_testing::require_postgres;
use tokio::task::JoinHandle;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::Layer as _;

#[allow(dead_code, reason = "shared with tests/live.rs, which uses all of it")]
#[path = "common/recorded.rs"]
mod recorded;
use recorded::Recorded;

#[path = "common/pg_fault.rs"]
mod pg_fault;
use pg_fault::{Fault, Relay};

/// `docker-compose.yml`'s Postgres. CI sets `DATABASE_URL` to the same.
const COMPOSE_URL: &str = "postgres://postgres:localdev@localhost:5438/stridelabs_test";

/// The guard under test: fast, so a test waits seconds, not lumen's 30.
const GUARD: BeginGuard = BeginGuard::new(Duration::from_secs(1))
    .with_probe_timeout(Duration::from_millis(500))
    .with_window(Duration::from_secs(5));

/// A slow test machine's allowance on top of the guard's own bounds.
const MARGIN: Duration = Duration::from_secs(2);

/// A checkout's bound in these tests (the pools are idle; it never binds).
const BOUND: Duration = Duration::from_secs(5);

/// lumen's request bounds (design §2.2's first pinned string).
const REQUEST: TxBounds = TxBounds::from_millis(5_000, 10_000);

/// How long a fault may take to fire once its `BEGIN` is on its way.
const REACH: Duration = Duration::from_secs(5);

/// The longest a test may run, polling included (and, for a test with a
/// [`Server`], its table's setup): a stalled socket or server fails it
/// rather than hanging the suite.
const DEADLINE: Duration = Duration::from_secs(30);

/// The longest a test's table may take to drop, after the test: a bound of
/// its own, so cleanup runs even when the test used all of [`DEADLINE`].
const CLEANUP: Duration = Duration::from_secs(10);

/// Written (in the SQL text, so the relay's statement log carries it) by
/// every durability check; no recorded event may carry it.
const TABLE_CANARY: &str = "sl-guard-table-canary";

/// The guard's tracing target and its two lines (design §3.1, exact).
const GUARD_TARGET: &str = "stridelabs_postgres::guard";
const ABANDONED: &str = "a BEGIN was abandoned; probing released connections";
const PROBE_FAILED: &str = "a released connection failed its probe; closed";

/// Within the bound and the probe of a `BEGIN` reaching the server, with
/// room for a busy machine: by then a guarded pool has its slot back.
fn slot_back_within() -> Duration {
    GUARD.begin_timeout() + GUARD.probe_timeout() + MARGIN
}

/// The database `require_postgres` reaches: `DATABASE_URL` (read, never
/// written) or the compose URL, by its own precedence.
fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .ok()
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| COMPOSE_URL.to_owned())
}

fn upstream() -> PgConnectOptions {
    connect_options(&database_url())
        .unwrap_or_else(|refusal| panic!("the test URL is refused: {refusal}"))
}

/// The URL's password: a canary no recorded event may carry.
fn password_canary() -> String {
    let password = url::Url::parse(&database_url())
        .expect("the test URL parses")
        .password()
        .unwrap_or_default()
        .to_owned();
    assert!(
        password.len() >= 4,
        "premise: the test URL carries a password to look for"
    );
    password
}

/// A pool `application_name` no other pool in any test process shares.
fn unique(test: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    format!(
        "sl-guard-{test}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

fn settings(max_connections: u32) -> PoolSettings {
    PoolSettings::default()
        .with_max_connections(max_connections)
        .with_acquire_timeout(BOUND)
}

/// A guarded pool through `relay`, its connections tagged `name`, warmed:
/// one connection open and back in the pool.
async fn guarded(relay: &Relay, name: &str, max_connections: u32) -> GuardedPool {
    let pool = GuardedPool::lazy(relay.options(name), settings(max_connections), GUARD);
    warm(&pool).await;
    pool
}

/// The control's pool: the same, WITHOUT the guard's hook (`lazy_pool`).
async fn unguarded(relay: &Relay, name: &str, max_connections: u32) -> PgPool {
    let pool = lazy_pool(relay.options(name), settings(max_connections));
    warm(&pool).await;
    pool
}

async fn warm(pool: &PgPool) {
    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .expect("a first connection through the relay");
    until_released(pool).await;
}

/// Until every connection of `pool` is back in it: idle, its release (and
/// any probe of it) done.
async fn until_released(pool: &PgPool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while pool.num_idle() != pool.size() as usize {
        assert!(Instant::now() < deadline, "a connection never came back");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The contamination detector (design F1): over the SIMPLE protocol, true
/// outside a transaction and false inside one.
async fn outside_a_transaction(connection: &mut PgConnection) -> bool {
    sqlx::raw_sql("SELECT now() = statement_timestamp()")
        .fetch_one(connection)
        .await
        .expect("the detector runs")
        .get::<bool, _>(0)
}

async fn backend_pid(pool: &PgPool) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(pool)
        .await
        .expect("read the backend's pid")
}

/// One autocommit `SELECT 1` on `pool`, then until its connection is back.
async fn select_one(pool: &PgPool) {
    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .expect("a statement on the pool");
    until_released(pool).await;
}

/// A caller beginning a guarded transaction on `pool` with `bounds`, in a
/// task of its own (so a test can abort it), which drops it on success.
fn spawn_begin(pool: &GuardedPool, bounds: TxBounds) -> JoinHandle<Result<(), sqlx::Error>> {
    let pool = pool.clone();
    tokio::spawn(async move { pool.begin(BOUND, bounds).await.map(drop) })
}

/// Abort `caller` and wait for it to end.
async fn cancel<T>(caller: JoinHandle<T>) {
    caller.abort();
    let _ = caller.await;
}

/// `caller`'s outcome, which must come within [`slot_back_within`]: `what`
/// was given up on within the bound.
async fn given_up_within_the_bound(
    caller: JoinHandle<Result<(), sqlx::Error>>,
    what: &str,
) -> Result<(), sqlx::Error> {
    tokio::time::timeout(slot_back_within(), caller)
        .await
        .unwrap_or_else(|_| panic!("{what} was given up on within the bound"))
        .expect("the caller's task")
}

/// Run `body` under [`DEADLINE`], failing loudly if it runs over.
async fn within_deadline(test: &str, body: impl std::future::Future<Output = ()>) {
    if tokio::time::timeout(DEADLINE, body).await.is_err() {
        panic!("{test} did not finish within {DEADLINE:?}: a socket or the server stalled");
    }
}

/// What a test sees the server through: a direct pool (`require_postgres`,
/// not the relay) and a table of its own, dropped by [`Server::run`].
struct Server {
    direct: PgPool,
    table: String,
    writes: AtomicUsize,
    /// The test's [`DEADLINE`], counted from before its table's setup.
    deadline: Instant,
}

impl Server {
    /// The direct pool and the test's table, within the test's
    /// [`DEADLINE`] (which [`Server::run`] goes on counting).
    async fn start(test: &str) -> Server {
        let deadline = Instant::now() + DEADLINE;
        let table = format!("guard_{test}_{}", std::process::id());
        let setup = async {
            let direct = require_postgres(COMPOSE_URL).await;
            for statement in [
                format!("DROP TABLE IF EXISTS {table}"),
                format!("CREATE TABLE {table} (note text NOT NULL)"),
            ] {
                sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
                    .execute(&direct)
                    .await
                    .expect("set up the test's table");
            }
            direct
        };
        let direct = tokio::time::timeout_at(deadline.into(), setup)
            .await
            .unwrap_or_else(|_| panic!("{test}: setting up its table overran {DEADLINE:?}"));
        Server {
            direct,
            table,
            writes: AtomicUsize::new(0),
            deadline,
        }
    }

    /// The backends tagged `name`: how many, and how many of them are idle
    /// in a transaction.
    async fn backends(&self, name: &str) -> (i64, i64) {
        sqlx::query_as(
            "SELECT count(*), count(*) FILTER (WHERE state LIKE 'idle in transaction%') \
             FROM pg_stat_activity WHERE application_name = $1",
        )
        .bind(name)
        .fetch_one(&self.direct)
        .await
        .expect("read pg_stat_activity")
    }

    /// An autocommit write through `pool`, its value in the SQL text
    /// (carrying [`TABLE_CANARY`]): whether another connection sees it at
    /// once (durable on its own, not joined to a transaction nobody
    /// commits).
    async fn write_is_durable(&self, pool: &PgPool) -> bool {
        let note = format!(
            "{TABLE_CANARY}-{}",
            self.writes.fetch_add(1, Ordering::SeqCst)
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "INSERT INTO {} (note) VALUES ('{note}')",
            self.table
        )))
        .execute(pool)
        .await
        .expect("an autocommit write through the pool");
        let seen: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {} WHERE note = $1",
            self.table
        )))
        .bind(&note)
        .fetch_one(&self.direct)
        .await
        .expect("read the write from another connection");
        seen == 1
    }

    /// Until `pool`'s slots are all free (idle, or closed) and none of its
    /// backends is idle in a transaction, within [`slot_back_within`] of
    /// `held_at`; then an autocommit write through it is durable.
    ///
    /// The whole observation is under one absolute deadline (a stalled
    /// `pg_stat_activity` read fails it rather than waiting), and a recovery
    /// is accepted only if it was seen by the deadline: Tokio's `timeout`
    /// polls the observation before its timer, so a success that became
    /// ready late would otherwise pass.
    async fn assert_the_slot_comes_back(
        &self,
        pool: &GuardedPool,
        name: &str,
        held_at: Instant,
        what: &str,
    ) {
        let deadline = held_at + slot_back_within();
        let mut last_stuck = None;
        let observation = async {
            loop {
                let (_, stuck) = self.backends(name).await;
                let free = pool.num_idle() == pool.size() as usize;
                let seen_at = Instant::now();
                if free && stuck == 0 {
                    return seen_at;
                }
                last_stuck = Some(stuck);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        let Ok(seen_at) = tokio::time::timeout_at(deadline.into(), observation).await else {
            panic!(
                "{what}: the slot is still taken after {:?} (pool size {}, idle {}, backends \
                 idle in transaction at the last look: {last_stuck:?})",
                slot_back_within(),
                pool.size(),
                pool.num_idle()
            );
        };
        assert!(
            seen_at <= deadline,
            "{what}: the slot came back only {:?} after the BEGIN reached the relay, past {:?}",
            seen_at - held_at,
            slot_back_within()
        );
        assert!(
            self.write_is_durable(pool).await,
            "{what}: the autocommit write is durable on its own"
        );
    }

    /// Run `body` within what is left of the test's [`DEADLINE`], then drop
    /// the test's table whatever happened (a failed assertion included),
    /// within [`CLEANUP`]. The body's failure is the one reported: a cleanup
    /// that fails or overruns after it is only noted.
    async fn run(&self, test: &str, body: impl std::future::Future<Output = ()>) {
        let timed = async {
            if tokio::time::timeout_at(self.deadline.into(), body)
                .await
                .is_err()
            {
                panic!("{test} did not finish within {DEADLINE:?}: a socket or the server stalled");
            }
        };
        let outcome = AssertUnwindSafe(timed).catch_unwind().await;
        let drop_table = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP TABLE IF EXISTS {}",
            self.table
        )))
        .execute(&self.direct);
        let cleanup = match tokio::time::timeout(CLEANUP, drop_table).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(format!(
                "dropping {} failed: {}",
                self.table,
                error_summary(&error)
            )),
            Err(_) => Err(format!("dropping {} overran {CLEANUP:?}", self.table)),
        };
        match (outcome, cleanup) {
            (Err(panic), Ok(())) => std::panic::resume_unwind(panic),
            (Err(panic), Err(cleanup)) => {
                eprintln!("{test}: after its failure, {cleanup}");
                std::panic::resume_unwind(panic);
            }
            (Ok(()), Err(cleanup)) => panic!("{test}: {cleanup}"),
            (Ok(()), Ok(())) => {}
        }
    }
}

/// The control's half: past [`slot_back_within`] of `held_at`, `pool`'s one
/// slot is STILL taken (sqlx's release `ping` waits on the silent relay).
/// Then the relay is shut down, which frees it.
async fn assert_the_slot_stays_taken(pool: &PgPool, relay: &Relay, held_at: Instant, what: &str) {
    tokio::time::sleep_until((held_at + slot_back_within()).into()).await;
    assert_eq!(
        (pool.size(), pool.num_idle()),
        (1, 0),
        "{what}: without the guard the slot should still be taken"
    );
    relay.shutdown();
    until_released(pool).await;
    pool.close().await;
}

/// Every event the test's thread emits, recorded twice: everything, and
/// INFO and above (what a production subscriber writes).
struct Logs {
    everything: Recorded,
    info_up: Recorded,
    _default: tracing::subscriber::DefaultGuard,
}

impl Logs {
    fn install() -> Logs {
        let everything = Recorded::default();
        let info_up = Recorded::default();
        let subscriber = tracing_subscriber::registry()
            .with(everything.clone())
            .with(info_up.clone().with_filter(LevelFilter::INFO));
        Logs {
            _default: tracing::subscriber::set_default(subscriber),
            everything,
            info_up,
        }
    }

    /// The guard's lines (their fields), in order.
    fn guard_lines(&self) -> Vec<String> {
        self.everything
            .events()
            .into_iter()
            .filter(|(target, _)| target == GUARD_TARGET)
            .map(|(_, fields)| fields)
            .collect()
    }

    /// How many first lines with `cause`.
    fn abandoned(&self, cause: &str) -> usize {
        let cause = format!(" cause=\"{cause}\"");
        self.guard_lines()
            .iter()
            .filter(|fields| fields.contains(ABANDONED) && fields.contains(&cause))
            .count()
    }

    /// How many second lines with `error`.
    fn probe_failures(&self, error: &str) -> usize {
        let error = format!(" error={error}");
        self.guard_lines()
            .iter()
            .filter(|fields| fields.contains(PROBE_FAILED) && fields.ends_with(&error))
            .count()
    }

    /// **G9.** No event at INFO or above, of any target, and no guard line
    /// at all, carries the URL's password or the table canary. The premises:
    /// the canary went through the relay (its statement log), and a
    /// recorded event CAN carry it (sqlx's DEBUG statement log does), so the
    /// scan is not vacuous.
    fn assert_no_canary(&self, relay: &Relay) {
        let password = password_canary();
        assert!(
            relay.statements().iter().any(|s| s.contains(TABLE_CANARY)),
            "premise: the canary went through the relay"
        );
        assert!(
            self.everything
                .events()
                .iter()
                .any(|(target, fields)| target == "sqlx::query" && fields.contains(TABLE_CANARY)),
            "premise: sqlx's DEBUG statement log carries the canary"
        );
        for (target, fields) in self.info_up.events() {
            assert!(
                !fields.contains(TABLE_CANARY) && !fields.contains(&password),
                "an event under {target} carries a canary: {fields}"
            );
        }
        for fields in self.guard_lines() {
            assert!(
                !fields.contains(TABLE_CANARY) && !fields.contains(&password),
                "a guard line carries a canary: {fields}"
            );
        }
    }
}

// ── The window (lumen's tests/release_check.rs) ─────────────────────────

/// **R1.** Past its deadline, the window still probes until it has made its
/// probes: a pool of 3 used one connection at a time, its window set as
/// opened more than the window ago (a process paused that long), probes
/// the next 3 releases (each `SELECT 1` followed by the probe's `ROLLBACK`)
/// and not the 4th. The control: a window never opened probes none.
#[tokio::test]
async fn a_window_past_its_deadline_probes_until_its_probes_are_made() {
    within_deadline("R1", async {
        let relay = Relay::start(upstream(), Fault::None).await;
        let opened = Instant::now()
            .checked_sub(GUARD.window() + Duration::from_secs(60))
            .expect("this machine has been up longer than the window");
        for open in [false, true] {
            let name = unique("r1");
            let pool = guarded(&relay, &name, 3).await;
            if open {
                pool.set_window_opened_at(opened);
            }
            let before = relay.statements_of(&name).len();
            for _ in 0..4 {
                select_one(&pool).await;
            }
            let ran = relay.statements_of(&name)[before..].to_vec();
            let expected: Vec<&str> = if open {
                vec![
                    "SELECT 1", "ROLLBACK", "SELECT 1", "ROLLBACK", "SELECT 1", "ROLLBACK",
                    "SELECT 1",
                ]
            } else {
                vec!["SELECT 1"; 4]
            };
            assert_eq!(ran, expected, "window opened: {open}");
            assert_eq!(relay.pids_of(&name).len(), 1, "one connection throughout");
            pool.close().await;
        }
    })
    .await;
}

/// **R2.** A healthy connection probed in an open window is kept, not
/// closed: a guarded transaction commits, its release is probed (the last
/// statement is the probe's `ROLLBACK`), and the same backend serves the
/// next checkout. The control: the same with the window closed, no
/// `ROLLBACK`.
#[tokio::test]
async fn a_healthy_connection_probed_in_an_open_window_is_kept_and_reused() {
    within_deadline("R2", async {
        let relay = Relay::start(upstream(), Fault::None).await;
        for open in [false, true] {
            let name = unique("r2");
            let pool = guarded(&relay, &name, 1).await;
            let before_pid = backend_pid(&pool).await;
            until_released(&pool).await;
            if open {
                pool.set_window_opened_at(Instant::now());
            }
            let before = relay.statements_of(&name).len();
            let mut transaction = pool.begin(BOUND, REQUEST).await.expect("a transaction");
            sqlx::query("SELECT 1")
                .execute(&mut *transaction)
                .await
                .expect("a statement in it");
            transaction.commit().await.expect("it commits");
            until_released(&pool).await;

            let ran = relay.statements_of(&name)[before..].to_vec();
            assert!(ran.iter().any(|s| s == "COMMIT"), "committed: {ran:?}");
            if open {
                assert_eq!(
                    ran.last().map(String::as_str),
                    Some("ROLLBACK"),
                    "the release was probed: {ran:?}"
                );
            } else {
                assert!(!ran.iter().any(|s| s == "ROLLBACK"), "control: {ran:?}");
            }
            assert_eq!(pool.size(), 1, "the connection was kept");
            assert_eq!(backend_pid(&pool).await, before_pid, "the same backend");
            assert_eq!(relay.pids_of(&name).len(), 1, "never reconnected");
            pool.close().await;
        }
    })
    .await;
}

/// Check one connection out of `pool`, open a transaction on it that sqlx
/// does not track (a raw `BEGIN`, which is what a `BEGIN` answered after
/// the guard gave up on it leaves behind), release it, and check one out
/// again: whether it is the same backend, and whether it is still inside
/// the transaction (the simple-protocol detector).
async fn released_inside_a_transaction(pool: &PgPool) -> (bool, bool) {
    let mut connection = pool.acquire().await.expect("a checkout");
    let first: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *connection)
        .await
        .expect("read the backend's pid");
    sqlx::raw_sql("BEGIN; SET LOCAL application_name = 'sl-guard-canary'")
        .execute(&mut *connection)
        .await
        .expect("open a transaction sqlx does not track");
    drop(connection);
    until_released(pool).await;
    let mut connection = pool.acquire().await.expect("a second checkout");
    let second: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *connection)
        .await
        .expect("read the backend's pid");
    let inside = !outside_a_transaction(&mut connection).await;
    (first == second, inside)
}

/// **R3.** A guarded pool with its window open probes a connection released
/// inside a transaction sqlx does not know of: the `ROLLBACK` ends it and
/// the connection is kept, so the next checkout is the same backend,
/// outside any transaction. The premise: on a plain `lazy_pool`, the same
/// release hands the next checkout the same backend still inside.
#[tokio::test]
async fn a_guarded_pool_probes_a_connection_released_inside_a_transaction() {
    within_deadline("R3", async {
        let _ = require_postgres(COMPOSE_URL).await;
        let plain = lazy_pool(upstream(), settings(1));
        assert_eq!(
            released_inside_a_transaction(&plain).await,
            (true, true),
            "premise: without the guard, the same backend, still inside"
        );
        plain.close().await;

        let pool = GuardedPool::lazy(upstream(), settings(1), GUARD);
        pool.set_window_opened_at(Instant::now());
        assert_eq!(
            released_inside_a_transaction(&pool).await,
            (true, false),
            "the probed connection is kept, outside the transaction"
        );
        pool.close().await;
    })
    .await;
}

// ── A BEGIN cut off, unanswered, or answered late (lumen's tests/auth.rs) ──

/// **G1.** A caller cut off after Postgres received its `BEGIN` but before
/// the answer came back leaves no transaction behind: the guard's task
/// reads the answer and drops the transaction at depth one. The relay holds
/// the answer until the caller is aborted, then lets it through. After: no
/// backend idle in a transaction, and an autocommit write is durable. The
/// control: sqlx's own `begin` (through the guarded pool's `Deref`, the
/// hole the README names) cut off the same way leaves the connection idle
/// in the transaction, and the write joins it, invisible.
#[tokio::test]
async fn a_begin_cut_off_half_way_leaves_no_transaction() {
    let server = Server::start("g1").await;
    server
        .run("G1", async {
            for guarded_begin in [false, true] {
                let relay = Relay::start(upstream(), Fault::HoldBeginAnswer).await;
                let name = unique("g1");
                let pool = guarded(&relay, &name, 1).await;
                let caller = {
                    let pool = pool.clone();
                    tokio::spawn(async move {
                        if guarded_begin {
                            let _ = pool.begin(BOUND, TxBounds::NONE).await;
                        } else {
                            let _ = PgPool::begin(&pool).await;
                        }
                    })
                };
                relay.until_fired(REACH).await;
                cancel(caller).await;
                relay.release();
                until_released(&pool).await;
                assert_eq!(relay.fired(), 1);

                let (_, stuck) = server.backends(&name).await;
                let durable = server.write_is_durable(&pool).await;
                if guarded_begin {
                    assert_eq!(stuck, 0, "the guarded begin left no transaction");
                    assert!(durable, "the autocommit write is durable on its own");
                } else {
                    assert_eq!(stuck, 1, "control: sqlx's begin left one");
                    assert!(!durable, "control: the write joined it");
                }
                pool.close().await;
            }
        })
        .await;
}

/// The control of G2 and G3: a pool WITHOUT the hook, the same `BEGIN`
/// never answered and cut off (by an outer `begin_timeout`, or by aborting
/// the caller): sqlx's release `ping` waits on the silent relay, so the
/// slot is NOT back within the same margin.
async fn an_unguarded_begin_never_answered_keeps_its_slot(abort: bool) {
    let relay = Relay::start(upstream(), Fault::HoldBeginAnswer).await;
    let pool = unguarded(&relay, &unique("unguarded"), 1).await;
    let caller = {
        let pool = pool.clone();
        tokio::spawn(async move {
            if abort {
                let _ = pool.begin().await;
            } else {
                let _ = tokio::time::timeout(GUARD.begin_timeout(), pool.begin()).await;
            }
        })
    };
    let held_at = relay.until_fired(REACH).await;
    if abort {
        caller.abort();
    }
    let _ = caller.await;
    assert_the_slot_stays_taken(&pool, &relay, held_at, "an unguarded BEGIN never answered").await;
}

/// **G2.** A `BEGIN` that is never answered gives its slot back within the
/// bound. The peer keeps the socket open and never answers (over
/// plaintext, as the relay is). The caller gets an I/O `TimedOut` error
/// once `begin_timeout` passes; the release's probe gets no answer either,
/// so the connection is closed, the slot is free, no backend is left idle
/// in a transaction, and the pool serves the next caller. One line of each
/// kind. The control: [`an_unguarded_begin_never_answered_keeps_its_slot`].
#[tokio::test]
async fn a_begin_never_answered_gives_its_slot_back_within_the_bound() {
    let server = Server::start("g2").await;
    server
        .run("G2", async {
            let logs = Logs::install();
            let relay = Relay::start(upstream(), Fault::HoldBeginAnswer).await;
            let name = unique("g2");
            let pool = guarded(&relay, &name, 1).await;
            // Before the guard's timer can start: the lower bound's origin.
            let started = Instant::now();
            let caller = spawn_begin(&pool, TxBounds::NONE);
            let held_at = relay.until_fired(REACH).await;
            let outcome = given_up_within_the_bound(caller, "the BEGIN").await;
            let (since_start, since_held) = (started.elapsed(), held_at.elapsed());
            let failure = outcome.expect_err("an unanswered BEGIN is an error");
            assert_eq!(error_summary(&failure).to_string(), "I/O error (TimedOut)");
            assert!(
                since_start >= GUARD.begin_timeout(),
                "not before the bound: {since_start:?} after the begin started"
            );
            assert!(
                since_held < slot_back_within(),
                "within it: {since_held:?} after the BEGIN reached the relay"
            );
            server
                .assert_the_slot_comes_back(&pool, &name, held_at, "G2")
                .await;
            assert_eq!(relay.fired(), 1);
            assert_eq!(logs.abandoned("timeout"), 1, "{:?}", logs.guard_lines());
            assert_eq!(
                logs.probe_failures("I/O error (TimedOut)"),
                1,
                "{:?}",
                logs.guard_lines()
            );
            assert_eq!(logs.guard_lines().len(), 2, "{:?}", logs.guard_lines());
            logs.assert_no_canary(&relay);
            pool.close().await;

            an_unguarded_begin_never_answered_keeps_its_slot(false).await;
        })
        .await;
}

/// **G3.** The same with the caller gone: it is aborted while its `BEGIN`
/// is held. Nobody is left to see the error, and the guard's task still
/// gives the `BEGIN` up and gets the slot back. The control: the unguarded
/// pool's caller aborted the same way keeps the slot.
#[tokio::test]
async fn a_caller_dropped_on_a_begin_never_answered_frees_its_slot() {
    let server = Server::start("g3").await;
    server
        .run("G3", async {
            let logs = Logs::install();
            let relay = Relay::start(upstream(), Fault::HoldBeginAnswer).await;
            let name = unique("g3");
            let pool = guarded(&relay, &name, 1).await;
            let caller = spawn_begin(&pool, TxBounds::NONE);
            let held_at = relay.until_fired(REACH).await;
            cancel(caller).await;
            server
                .assert_the_slot_comes_back(&pool, &name, held_at, "G3")
                .await;
            assert_eq!(relay.fired(), 1);
            assert_eq!(logs.abandoned("timeout"), 1, "{:?}", logs.guard_lines());
            assert_eq!(
                logs.probe_failures("I/O error (TimedOut)"),
                1,
                "{:?}",
                logs.guard_lines()
            );
            logs.assert_no_canary(&relay);
            pool.close().await;

            an_unguarded_begin_never_answered_keeps_its_slot(true).await;
        })
        .await;
}

/// **G4.** A `BEGIN` answered only after the bound (the caller has its
/// error by then) never puts its connection back inside the transaction
/// the late answer opened: the probe drains the answer and ends the
/// transaction (or closes the connection). No backend idle in a
/// transaction; the next checkout is outside one; an autocommit write is
/// durable. The control: without the hook, the same late answer is drained
/// by sqlx's `ping`, and the next checkout is inside the transaction.
#[tokio::test]
async fn a_begin_answered_after_the_bound_never_returns_inside_its_transaction() {
    let server = Server::start("g4").await;
    server
        .run("G4", async {
            let logs = Logs::install();
            let relay = Relay::start(upstream(), Fault::HoldBeginAnswer).await;
            let name = unique("g4");
            let pool = guarded(&relay, &name, 1).await;
            let caller = spawn_begin(&pool, TxBounds::NONE);
            let held_at = relay.until_fired(REACH).await;
            let outcome = given_up_within_the_bound(caller, "the BEGIN").await;
            assert!(outcome.is_err(), "the caller had its error first");
            relay.release();
            server
                .assert_the_slot_comes_back(&pool, &name, held_at, "G4")
                .await;
            let mut connection = pool.acquire(BOUND).await.expect("a checkout");
            assert!(
                outside_a_transaction(&mut connection).await,
                "the next checkout is outside any transaction"
            );
            drop(connection);
            until_released(&pool).await;
            assert_eq!(relay.fired(), 1);
            assert_eq!(logs.abandoned("timeout"), 1, "{:?}", logs.guard_lines());
            logs.assert_no_canary(&relay);
            pool.close().await;

            // The control.
            let relay = Relay::start(upstream(), Fault::HoldBeginAnswer).await;
            let name = unique("g4");
            let pool = unguarded(&relay, &name, 1).await;
            let late = tokio::time::timeout(GUARD.begin_timeout(), pool.begin()).await;
            assert!(late.is_err(), "control: the outer bound cut it off");
            relay.release();
            until_released(&pool).await;
            let mut connection = pool.acquire().await.expect("a checkout");
            assert!(
                !outside_a_transaction(&mut connection).await,
                "control: without the hook the next checkout is inside the transaction"
            );
            drop(connection);
            until_released(&pool).await;
            assert_eq!(server.backends(&name).await.1, 1, "control: idle in it");
            pool.close().await;
        })
        .await;
}

/// **G5, two pools.** A `BEGIN` stuck on pool A opens A's window only: A's
/// next release is probed (its `ROLLBACK` follows its statement), while B,
/// A's sibling on the same relay, runs 5 statements meanwhile with no
/// `ROLLBACK` on any of B's connections. One first line in all. The
/// control: B's own window opened, B's next release IS probed, so the
/// observation would have seen one.
#[tokio::test]
async fn a_stuck_begin_on_one_pool_probes_none_of_its_siblings_releases() {
    let server = Server::start("g5").await;
    server
        .run("G5", async {
            let logs = Logs::install();
            let relay = Relay::start(upstream(), Fault::HoldBeginAnswer).await;
            let a_name = unique("g5a");
            let a = guarded(&relay, &a_name, 2).await;
            let b_name = unique("g5b");
            let b = a
                .sibling(settings(2), Some(&b_name))
                .expect("a valid application_name");
            assert_eq!(b.guard(), GUARD, "the sibling inherits the guard");
            warm(&b).await;
            assert_eq!(relay.pids_of(&b_name).len(), 1, "B's connections are B's");

            let caller = spawn_begin(&a, TxBounds::NONE);
            let held_at = relay.until_fired(REACH).await;
            let outcome = given_up_within_the_bound(caller, "A's BEGIN").await;
            assert!(outcome.is_err());

            // A's window is open (for GUARD.window()): B's releases meanwhile.
            let b_before = relay.statements_of(&b_name).len();
            for _ in 0..5 {
                select_one(&b).await;
            }
            assert_eq!(
                relay.statements_of(&b_name)[b_before..],
                vec!["SELECT 1"; 5],
                "no release of B's was probed"
            );

            // A's own next release, once its abandoned connection is gone.
            server
                .assert_the_slot_comes_back(&a, &a_name, held_at, "G5's pool A")
                .await;
            let a_before = relay.statements_of(&a_name).len();
            select_one(&a).await;
            assert_eq!(
                relay.statements_of(&a_name)[a_before..],
                ["SELECT 1", "ROLLBACK"],
                "A's release was probed: its window is open"
            );
            assert!(
                Instant::now() < held_at + GUARD.begin_timeout() + GUARD.window(),
                "all of the above ran inside A's window"
            );
            assert_eq!(logs.abandoned("timeout"), 1, "{:?}", logs.guard_lines());
            assert_eq!(
                logs.guard_lines()
                    .iter()
                    .filter(|fields| fields.contains(ABANDONED))
                    .count(),
                1,
                "one first line in all"
            );

            // The control: B's own window.
            b.set_window_opened_at(Instant::now());
            let b_before = relay.statements_of(&b_name).len();
            select_one(&b).await;
            assert_eq!(
                relay.statements_of(&b_name)[b_before..],
                ["SELECT 1", "ROLLBACK"],
                "control: B's release is probed once B's window is open"
            );
            logs.assert_no_canary(&relay);
            a.close().await;
            b.close().await;
        })
        .await;
}

/// **G6.** The bounds are the transaction's first statement, exactly
/// [`TxBounds::sql`], and the server applies them: inside, `lock_timeout`
/// and `statement_timeout` read `5s` and `10s`; after `COMMIT`, on the same
/// connection, `0`. The control: [`TxBounds::NONE`] sends nothing between
/// `BEGIN` and the work, and the server's defaults stand.
#[tokio::test]
async fn the_bounds_are_the_first_statement_and_the_server_applies_them() {
    const READ: &str =
        "SELECT current_setting('lock_timeout'), current_setting('statement_timeout')";
    let server = Server::start("g6").await;
    server
        .run("G6", async {
            let logs = Logs::install();
            let relay = Relay::start(upstream(), Fault::None).await;
            let name = unique("g6");
            let pool = guarded(&relay, &name, 1).await;
            for bounds in [TxBounds::NONE, REQUEST] {
                let before = relay.statements_of(&name).len();
                let mut transaction = pool.begin(BOUND, bounds).await.expect("a transaction");
                let inside: (String, String) = sqlx::query_as(READ)
                    .fetch_one(&mut *transaction)
                    .await
                    .expect("read the settings inside");
                transaction.commit().await.expect("it commits");
                let after: (String, String) = sqlx::query_as(READ)
                    .fetch_one(&*pool)
                    .await
                    .expect("read the settings after");
                until_released(&pool).await;

                let ran = relay.statements_of(&name)[before..].to_vec();
                if bounds.is_none() {
                    assert_eq!(ran[..3], ["BEGIN", READ, "COMMIT"], "control: {ran:?}");
                    assert_eq!(inside, ("0".to_owned(), "0".to_owned()), "control");
                } else {
                    let sql = bounds.sql().expect("bounds");
                    assert_eq!(
                        sql,
                        "SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '10000ms'"
                    );
                    assert_eq!(ran[..4], ["BEGIN", sql.as_str(), READ, "COMMIT"], "{ran:?}");
                    assert_eq!(inside, ("5s".to_owned(), "10s".to_owned()));
                }
                assert_eq!(after, ("0".to_owned(), "0".to_owned()), "local to it");
            }
            assert_eq!(relay.pids_of(&name).len(), 1, "one connection throughout");
            assert!(server.write_is_durable(&pool).await);
            assert!(logs.guard_lines().is_empty(), "{:?}", logs.guard_lines());
            logs.assert_no_canary(&relay);
            pool.close().await;
        })
        .await;
}

/// **G7.** A `BEGIN` that fails AFTER the server entered the transaction
/// (the relay swallows the server's answer and tells the client it failed,
/// idle) opens the window, so its release is probed and the next checkout
/// is outside any transaction. On a current-thread runtime the release
/// (spawned as sqlx dropped the connection inside its own future) cannot
/// run before the window opens: README, residual 1. The control: the same
/// fault on a pool without the hook, through sqlx's own `begin`, hands the
/// next checkout a connection inside the transaction.
#[tokio::test(flavor = "current_thread")]
async fn a_begin_error_after_the_server_entered_the_transaction_is_probed_on_a_current_thread_runtime(
) {
    let server = Server::start("g7").await;
    server
        .run("G7", async {
            let logs = Logs::install();
            let relay = Relay::start(upstream(), Fault::AnswerBeginWithError).await;
            let name = unique("g7");
            let pool = guarded(&relay, &name, 1).await;
            let failure = pool
                .begin(BOUND, TxBounds::NONE)
                .await
                .expect_err("the BEGIN failed");
            assert!(matches!(failure, sqlx::Error::Database(_)), "{failure:?}");
            assert_eq!(
                error_summary(&failure).to_string(),
                "database error SQLSTATE XX000 (internal error)"
            );
            assert_eq!(relay.fired(), 1);
            until_released(&pool).await;
            let mut connection = pool.acquire(BOUND).await.expect("a checkout");
            assert!(
                outside_a_transaction(&mut connection).await,
                "the probe ended the transaction"
            );
            drop(connection);
            until_released(&pool).await;
            assert_eq!(server.backends(&name).await.1, 0);
            assert!(server.write_is_durable(&pool).await);
            assert_eq!(logs.abandoned("error"), 1, "{:?}", logs.guard_lines());
            assert_eq!(logs.guard_lines().len(), 1, "{:?}", logs.guard_lines());
            logs.assert_no_canary(&relay);
            pool.close().await;

            // The control.
            let relay = Relay::start(upstream(), Fault::AnswerBeginWithError).await;
            let name = unique("g7");
            let pool = unguarded(&relay, &name, 1).await;
            let failure = pool.begin().await.expect_err("control: the BEGIN failed");
            assert!(matches!(failure, sqlx::Error::Database(_)), "{failure:?}");
            assert_eq!(relay.fired(), 1);
            until_released(&pool).await;
            let mut connection = pool.acquire().await.expect("a checkout");
            assert!(
                !outside_a_transaction(&mut connection).await,
                "control: without the hook the next checkout is inside the transaction"
            );
            drop(connection);
            pool.close().await;
        })
        .await;
}

/// **G8.** A `SET LOCAL` the server refuses (`TxBounds::REFUSED_BY_THE_SERVER`,
/// SQLSTATE `22023`) is an error at depth one: the transaction is dropped,
/// its `ROLLBACK` queued and flushed by the release, and the next borrower
/// is outside any transaction with the server's `lock_timeout`. No guard
/// line and no WARN at all: the peer answered. The control: valid bounds
/// on the same connection succeed.
#[tokio::test]
async fn a_refused_set_local_leaves_a_clean_connection() {
    within_deadline("G8", async {
        let logs = Logs::install();
        let relay = Relay::start(upstream(), Fault::None).await;
        let name = unique("g8");
        let pool = guarded(&relay, &name, 1).await;
        let pid = backend_pid(&pool).await;
        until_released(&pool).await;

        let before = relay.statements_of(&name).len();
        let failure = pool
            .begin(BOUND, TxBounds::REFUSED_BY_THE_SERVER)
            .await
            .expect_err("the server refuses the bounds");
        assert_eq!(
            error_summary(&failure).to_string(),
            "database error SQLSTATE 22023 (invalid parameter value)"
        );
        until_released(&pool).await;
        let refused = TxBounds::REFUSED_BY_THE_SERVER.sql().expect("bounds");
        assert_eq!(
            relay.statements_of(&name)[before..],
            ["BEGIN", refused.as_str(), "ROLLBACK"],
            "the dropped transaction's ROLLBACK, flushed by the release"
        );

        let mut connection = pool.acquire(BOUND).await.expect("a checkout");
        assert!(outside_a_transaction(&mut connection).await);
        let lock: String = sqlx::query_scalar("SELECT current_setting('lock_timeout')")
            .fetch_one(&mut *connection)
            .await
            .expect("read lock_timeout");
        assert_eq!(lock, "0");
        drop(connection);
        until_released(&pool).await;
        assert!(logs.guard_lines().is_empty(), "{:?}", logs.guard_lines());
        let logged = logs.info_up.events();
        assert!(
            logged.is_empty(),
            "nothing logged at INFO or above: {logged:?}"
        );

        // The control: valid bounds, the same connection.
        let mut transaction = pool.begin(BOUND, REQUEST).await.expect("valid bounds");
        sqlx::query("SELECT 1")
            .execute(&mut *transaction)
            .await
            .expect("a statement in it");
        transaction.commit().await.expect("it commits");
        assert_eq!(
            backend_pid(&pool).await,
            pid,
            "the same connection throughout"
        );
        pool.close().await;
    })
    .await;
}

// ── An unanswered SET LOCAL (design D3) ─────────────────────────────────

/// **G10.** A peer that answers the `BEGIN` and then never answers the
/// bounds statement: the caller has an I/O `TimedOut` about
/// `begin_timeout` after the statement went out, the window opens
/// (`cause=set_local_timeout`), the probe fails, the connection is closed,
/// and the slot is back within the margin with no backend idle in a
/// transaction. The control: the same `BEGIN` and `SET LOCAL` on a pool
/// without the hook, the transaction dropped after an outer `begin_timeout`:
/// the release's `ping` waits on the silent peer, and the slot stays taken.
#[tokio::test]
async fn an_unanswered_set_local_opens_the_window_and_gives_the_slot_back() {
    let server = Server::start("g10").await;
    server
        .run("G10", async {
            let logs = Logs::install();
            let relay = Relay::start(upstream(), Fault::HoldSetLocalAnswer).await;
            let name = unique("g10");
            let pool = guarded(&relay, &name, 1).await;
            // Before the guard's timers can start: the lower bound's origin.
            let started = Instant::now();
            let caller = spawn_begin(&pool, REQUEST);
            let held_at = relay.until_fired(REACH).await;
            let outcome = given_up_within_the_bound(caller, "the SET LOCAL").await;
            let since_start = started.elapsed();
            let failure = outcome.expect_err("an unanswered SET LOCAL is an error");
            assert_eq!(error_summary(&failure).to_string(), "I/O error (TimedOut)");
            assert!(
                since_start >= GUARD.begin_timeout(),
                "not before the bound: {since_start:?} after the begin started"
            );
            server
                .assert_the_slot_comes_back(&pool, &name, held_at, "G10")
                .await;
            assert_eq!(relay.fired(), 1);
            assert_eq!(
                logs.abandoned("set_local_timeout"),
                1,
                "{:?}",
                logs.guard_lines()
            );
            assert_eq!(
                logs.probe_failures("I/O error (TimedOut)"),
                1,
                "{:?}",
                logs.guard_lines()
            );
            assert_eq!(logs.guard_lines().len(), 2, "{:?}", logs.guard_lines());
            logs.assert_no_canary(&relay);
            pool.close().await;

            // The control.
            let relay = Relay::start(upstream(), Fault::HoldSetLocalAnswer).await;
            let pool = unguarded(&relay, &unique("g10"), 1).await;
            let caller = {
                let pool = pool.clone();
                tokio::spawn(async move {
                    let mut transaction = pool.begin().await.expect("control: BEGIN answered");
                    let sql = REQUEST.sql().expect("bounds");
                    let set = sqlx::raw_sql(sqlx::AssertSqlSafe(sql)).execute(&mut *transaction);
                    let _ = tokio::time::timeout(GUARD.begin_timeout(), set).await;
                })
            };
            let held_at = relay.until_fired(REACH).await;
            let _ = caller.await;
            assert_the_slot_stays_taken(&pool, &relay, held_at, "G10's control").await;
        })
        .await;
}

/// **G11.** A caller cancelled while its `SET LOCAL`'s answer is held. (a)
/// The answer comes 200 ms later: the guard's task reads it and drops its
/// transaction at depth one, so no backend is idle in a transaction, an
/// autocommit write is durable, and nothing is logged. (b) It never comes:
/// after `begin_timeout` the TASK opens the window (`set_local_timeout`)
/// though nobody waits, and the slot is back within the margin. The
/// control of (b): the bounds statement run in the CALLER's future (the
/// guard's `BEGIN`, then the statement outside the task) and the caller
/// aborted: no window opens, and the slot stays taken.
#[tokio::test]
async fn a_caller_cancelled_while_its_set_local_answer_is_held_leaves_no_transaction() {
    let server = Server::start("g11").await;
    server
        .run("G11", async {
            let logs = Logs::install();

            // (a) released after 200 ms.
            let relay = Relay::start(upstream(), Fault::HoldSetLocalAnswer).await;
            let name = unique("g11a");
            let pool = guarded(&relay, &name, 1).await;
            let caller = spawn_begin(&pool, REQUEST);
            relay.until_fired(REACH).await;
            cancel(caller).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            relay.release();
            until_released(&pool).await;
            assert_eq!(relay.fired(), 1);
            assert_eq!(
                server.backends(&name).await.1,
                0,
                "(a): no transaction left"
            );
            assert!(server.write_is_durable(&pool).await, "(a): durable");
            assert!(
                logs.guard_lines().is_empty(),
                "(a): the peer answered: {:?}",
                logs.guard_lines()
            );
            assert!(
                relay
                    .statements_of(&name)
                    .windows(2)
                    .any(|pair| pair[0] == REQUEST.sql().expect("bounds") && pair[1] == "ROLLBACK"),
                "(a): the task's dropped transaction queued its ROLLBACK: {:?}",
                relay.statements_of(&name)
            );
            logs.assert_no_canary(&relay);
            pool.close().await;

            // (b) never released.
            let relay = Relay::start(upstream(), Fault::HoldSetLocalAnswer).await;
            let name = unique("g11b");
            let pool = guarded(&relay, &name, 1).await;
            let caller = spawn_begin(&pool, REQUEST);
            let held_at = relay.until_fired(REACH).await;
            cancel(caller).await;
            server
                .assert_the_slot_comes_back(&pool, &name, held_at, "G11 (b)")
                .await;
            assert_eq!(relay.fired(), 1);
            assert_eq!(
                logs.abandoned("set_local_timeout"),
                1,
                "(b): {:?}",
                logs.guard_lines()
            );
            assert_eq!(logs.guard_lines().len(), 2, "(b): {:?}", logs.guard_lines());
            logs.assert_no_canary(&relay);
            pool.close().await;

            // (b)'s control: the bounds statement in the caller's future.
            let relay = Relay::start(upstream(), Fault::HoldSetLocalAnswer).await;
            let pool = guarded(&relay, &unique("g11c"), 1).await;
            let caller = {
                let pool = pool.clone();
                tokio::spawn(async move {
                    let mut transaction = pool
                        .begin(BOUND, TxBounds::NONE)
                        .await
                        .expect("control: BEGIN answered");
                    let sql = REQUEST.sql().expect("bounds");
                    let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
                        .execute(&mut *transaction)
                        .await;
                })
            };
            let held_at = relay.until_fired(REACH).await;
            cancel(caller).await;
            let lines_before = logs.guard_lines().len();
            assert_the_slot_stays_taken(&pool, &relay, held_at, "G11's control").await;
            assert_eq!(
                logs.guard_lines().len(),
                lines_before,
                "control: no window opened"
            );
        })
        .await;
}
