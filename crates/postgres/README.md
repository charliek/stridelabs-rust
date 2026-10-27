# stridelabs-postgres

Postgres connection hygiene on sqlx for StrideLabs services: the checks a
`DATABASE_URL` passes **before sqlx parses it**, a `sqlx::Error` rendered
**without anything a server or a URL put into it**, a pool built **without
connecting**, **Neon pooler detection**, the **sqlx log targets** to cap, and
(feature `guard`) **the begin guard**: transactions that begin with a
bounded, cancel-safe `BEGIN`, on a pool that probes its releases while a
`BEGIN` given up on may still be answered.
Extracted from tapper-rs's `db.rs` (itself hardened from lumen-rs's copy) and
checked against slaudio's `parse_connect_options`, so the apps hold one set of
rules instead of three copies.

What stays with each app: normalising its own URL spellings first (tapper's
and lumen's SQLAlchemy `postgresql+asyncpg://`, Neon's `channel_binding`), the
readiness probe, the migration runner, and whether a detected pooler is
refused.

## Adding the dependency

```toml
[dependencies]
stridelabs-postgres = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.11.0" }
# Your own sqlx picks the TLS stack (see "Feature topology"):
sqlx = { version = "0.9", default-features = false, features = ["runtime-tokio", "postgres", "tls-rustls-aws-lc-rs"] }
```

New in v0.10.0. During development against an unreleased commit, pin
`rev = "<sha>"` instead of `tag`; see the workspace root README for the local
`[patch]` co-development snippet.

For the begin guard (new in v0.11.0), name `features = ["guard"]` in `[dependencies]`, and
`features = ["guard", "test-support"]` in `[dev-dependencies]` if your tests
use its two seams (never `test-support` in `[dependencies]`).

## Using it

```rust,no_run
use stridelabs_postgres::{connect_options, error_summary, lazy_pool, PoolSettings};

# async fn example(database_url: &str) {
// At boot: checks the URL, parses it, performs no I/O. A refusal names a
// parameter or a field from the crate's own lists, never a value, so it is
// safe to log and the process can keep booting (and report itself degraded).
let pool = match connect_options(database_url) {
    Ok(options) => Some(lazy_pool(options, PoolSettings::default().with_max_connections(15))),
    Err(refusal) => {
        tracing::error!(%refusal, "DATABASE_URL refused");
        None
    }
};

// Every database error is rendered through `error_summary`.
if let Some(pool) = &pool {
    if let Err(error) = sqlx::query("SELECT 1").execute(pool).await {
        tracing::warn!(error = %error_summary(&error), "readiness check failed");
    }
}
# }
```

| API | What it does |
|---|---|
| `connect_options(url) -> Result<PgConnectOptions, UrlRefusal>` | The URL checked, then parsed by sqlx: a query-parameter allow-list, no `search_path`, no NUL byte, no password file (below). |
| `UrlRefusal` | `NotAUrl`, `Scheme`, `UnsupportedParameters { named, unnamed }`, `InvalidValue`, `Unparseable`, `SearchPath`, `NulByte`. `#[non_exhaustive]`; its text never carries a value. |
| `SUPPORTED_URL_PARAMETERS`, `IGNORED_URL_PARAMETERS` | The lists the allow-list is made of. |
| `error_summary(&sqlx::Error) -> ErrorSummary` | `database error SQLSTATE 23505 (unique violation)`, `I/O error (ConnectionRefused)`, `protocol error`, …: a SQLSTATE and a fixed description, or a fixed class name. Its `Debug` is its `Display`. |
| `lazy_pool(options, PoolSettings) -> PgPool` | The pool, built without connecting (inside a Tokio runtime). |
| `PoolSettings` | `max_connections`, `acquire_timeout`, `idle_timeout`, `max_lifetime`, `test_before_acquire`; defaults are sqlx 0.9's own, pinned. `pool_options()` hands sqlx's `PgPoolOptions` to a consumer that needs more (an `after_connect` hook). |
| `neon_pooler(&PgConnectOptions) -> Option<PoolerRef>` | Whether the options reach Neon's pooled endpoint: by a `-pooler` host label, or by `endpoint=…-pooler` in the startup options (`options=` or `PGOPTIONS`). Detection only. |
| `neon_pooler_url(url, &PgConnectOptions) -> Option<PoolerRef>` | `neon_pooler`, plus the hosts the URL names that sqlx will not dial (its authority while `?host=`/`?hostaddr=` redirects, an overridden `host` value): an ambiguous URL, which a migration runner refuses too. Pass the options `connect_options(url)` returned; the refusal is then one `match` (`Some(pooler) => Err(…)`, `None => Ok(options)`). |
| `neon_pooler_host(&str) -> Option<PoolerRef>` | The host half: whether one host string has a `-pooler` label, as is or percent-decoded. |
| `LOG_CAPS` | `sqlx_core::pool`, `sqlx_postgres::options`, `sqlx::postgres::notice` and `sqlx_postgres::message`, each `OFF`, to fold into the consumer's log caps. |

**Never log the options themselves**: sqlx's derived `Debug` of
`PgConnectOptions` prints the password. Log the `UrlRefusal`, never
`?options`.

### The URL rules

- **An allow-list, because sqlx logs and quotes values.** sqlx's URL parser
  WARNs every parameter it does not recognise with its value, and its errors
  quote a bad value (`unknown value "…" for ssl_mode`). A credential pasted
  into the wrong parameter would reach a log. So a parameter must be one
  sqlx applies (`SUPPORTED_URL_PARAMETERS`: libpq's spellings), or a libpq
  setting sqlx has no equivalent for that is accepted, validated and not
  passed on (`IGNORED_URL_PARAMETERS`: `connect_timeout`, the `keepalives*`,
  `target_session_attrs` = `any`/`read-write`). Anything else is refused:
  by name if the crate recognises it (sqlx's aliases, `channel_binding`,
  `passfile`, …), and as a count otherwise, since an unknown name can be a
  pasted credential. The values sqlx would quote (`sslmode`, `port`,
  `hostaddr`) are checked first.
- **No password file, ever.** sqlx falls back to `PGPASSFILE` or `~/.pgpass`
  when neither the URL nor `PGPASSWORD` supplies a password, and logs a
  malformed line of it verbatim. When nothing supplies one, sqlx is handed an
  explicitly empty password, which is what it would send anyway, and the
  file is never opened.
- **No `search_path`.** Startup options (`PGOPTIONS`, then every `options=`)
  that set `search_path` are refused, in every spelling the server honours:
  they are read with the server's own tokeniser (`pg_split_opts`, the
  vertical tab included) and `getopt` rules (`-c`, `--`, `-` for `_`, any
  case, escapes). A setting whose name merely contains the words
  (`myapp.search_path_hint`) passes.
- **No NUL byte** in anything sqlx copies into the startup packet or the
  password message: every query value, the URL's user, password, database
  and host (percent-decoded), what sqlx parsed (its `PG*` defaults included),
  and `PGUSER`, `PGDATABASE`, `PGAPPNAME`, `PGOPTIONS`, `PGHOST`,
  `PGHOSTADDR`, `PGPASSWORD`. PostgreSQL reads the packet with `strlen`, so
  `application_name=x%00search_path%00y` would otherwise send
  `search_path=y` past every other check.

**Neon's connection string** carries `channel_binding=require`, which is
refused by name: sqlx 0.9 cannot do channel binding, so accepting it would
leave a `require` silently unenforced. Remove it (as tapper's and lumen's
normalisers do) before calling `connect_options`. Its `sslmode=require` and
`options=endpoint%3D<id>` pass.

## The begin guard (feature `guard`)

**Why `pool.begin()` is not enough.** In sqlx 0.9 a `BEGIN` cut off after
the server received it, but before its answer arrived, hands the connection
back to the pool INSIDE the transaction: the transaction depth is raised only
once the answer is read, a dropped transaction queues its `ROLLBACK` only at
a depth above zero, and the pool's release `ping` just drains the late
answer. The next borrower's "autocommit" statements then join a transaction
nobody commits. A client hanging up while a handler awaits `pool.begin()`, or
a timeout around one, is that cut. And a `BEGIN` the peer never answers holds
its slot for as long as the peer stays silent.

```rust,no_run
use std::time::Duration;
use stridelabs_postgres::{connect_options, BeginGuard, GuardedPool, PoolSettings, TxBounds};

// The consumer's policy, checked at compile time (a const).
const GUARD: BeginGuard = BeginGuard::new(Duration::from_secs(5))
    .with_probe_timeout(Duration::from_secs(1))
    .with_window(Duration::from_secs(30));
const REQUEST_BOUNDS: TxBounds = TxBounds::from_millis(5_000, 10_000);

# async fn example(database_url: &str) -> Result<(), Box<dyn std::error::Error>> {
let pool = GuardedPool::lazy(
    connect_options(database_url)?,
    PoolSettings::default().with_max_connections(15),
    GUARD,
);

// A transaction: the checkout within 30 s, then BEGIN and its bounds.
let mut transaction = pool.begin(Duration::from_secs(30), REQUEST_BOUNDS).await?;
sqlx::query("UPDATE things SET seen = now()").execute(&mut *transaction).await?;
transaction.commit().await?;

// Autocommit work runs on the pool as on any `PgPool` (it derefs to one).
sqlx::query("SELECT 1").execute(&*pool).await?;

// A connection first, a transaction on it later.
let mut connection = pool.acquire(Duration::from_secs(5)).await?;
sqlx::query("SELECT 1").execute(&mut *connection).await?;
let transaction = connection.begin(TxBounds::NONE).await?;
// A second pool on the same checked options, with a window of its own.
let ledger = pool.sibling(PoolSettings::default().with_max_connections(3), Some("app-ledger"))?;
# Ok(())
# }
```

| API | What it does |
|---|---|
| `BeginGuard::new(begin_timeout)` | The guard: how long a `BEGIN` (and then its `SET LOCAL`) may go unanswered; required, no default. `.with_probe_timeout(d)` (default 1 s) and `.with_window(d)` (default 30 s). `const fn`s: a zero timeout, a timeout over `MAX_TIMEOUT` (10 min) or a window over `MAX_WINDOW` (1 h) panics, which is a compile error in a `const`. Getters `begin_timeout()`, `probe_timeout()`, `window()`. |
| `TxBounds::from_millis(lock_ms, statement_ms)` | A transaction's `lock_timeout` and `statement_timeout`, sent as ONE simple query right after `BEGIN` (`sql()`: `SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '10000ms'`), so the server applies both or neither. `const fn`: `lock_ms` 0, `lock_ms >= statement_ms`, or `statement_ms` over `MAX_MILLIS` (PostgreSQL's `INT_MAX`) panics. `TxBounds::NONE` sends nothing. Getters `is_none()`, `lock_timeout()`, `statement_timeout()`. |
| `GuardedPool::lazy(options, PoolSettings, BeginGuard)` | The pool, built without connecting (as `lazy_pool`, inside a Tokio runtime), with the guard's `after_release` hook over a window of its own. Derefs to `PgPool`. |
| `GuardedPool::sibling(settings, Option<&str>)` | A second pool on this one's connect options, with this one's `BeginGuard` and its own window; only `application_name` may change, and it is checked: printable ASCII, 1 to 63 bytes (`MAX_APPLICATION_NAME_BYTES`), else `UrlRefusal::NulByte` / `InvalidValue("application_name")`. |
| `GuardedPool::acquire(bound)` | A `GuardedConnection` within `bound` (or the pool's own `acquire_timeout`, whichever passes first); `PoolTimedOut` past it. |
| `GuardedPool::begin(bound, TxBounds)` | `acquire(bound)`, then `GuardedConnection::begin`. |
| `GuardedConnection::begin(TxBounds)` | `BEGIN`, then the bounds statement, both in a spawned task, each within `begin_timeout` (below). |
| `GuardedConnection::detach()` | The `PgConnection`, out of the pool for good (sqlx's `PoolConnection::detach`): the slot is freed now. |
| `GuardedConnection` | Derefs (mutably) to `PgConnection`: statements on `&mut *connection` autocommit. |
| `guard()` | The `BeginGuard` a pool was built with. |

Errors stay `sqlx::Error`, rendered by `error_summary` like any other:

| Outcome | `Err` | `error_summary` | Window |
|---|---|---|---|
| checkout past `bound` or the pool's `acquire_timeout` | `PoolTimedOut` | `timed out waiting for a pool connection` | no |
| `BEGIN` unanswered for `begin_timeout` | `Io(TimedOut)` | `I/O error (TimedOut)` | yes, `cause=timeout` |
| `BEGIN` failed (server, I/O, protocol; or answered outside a transaction: `BeginFailed`) | that error | its class or SQLSTATE | yes, `cause=error` |
| a panic in the `BEGIN` | `WorkerCrashed` | `the connection worker crashed` | yes, `cause=panic` |
| the task cancelled at runtime shutdown | `WorkerCrashed` | `the connection worker crashed` | no |
| `SET LOCAL` refused | `Database` | e.g. `database error SQLSTATE 22023 (invalid parameter value)` | no |
| `SET LOCAL` unanswered for `begin_timeout` | `Io(TimedOut)` | `I/O error (TimedOut)` | yes, `cause=set_local_timeout` |

### How it works

- **The `BEGIN` and the bounds statement run in a spawned task** that owns
  the connection; the caller awaits its handle. A caller dropped meanwhile
  drops only the handle: the task still reads both answers, and the
  transaction it built (nobody takes it) is dropped at depth one, which
  queues the `ROLLBACK` that the release's `ping` flushes.
- **Each is bounded by `begin_timeout`.** Giving up cannot mean simply
  dropping sqlx's future: sqlx 0.9 never gives the connection back
  mid-`BEGIN`, so the drop releases it to the pool, and a late answer would
  put it back inside the transaction. So on a timeout, an error or a caught
  panic, the task opens THIS pool's **quarantine window** first and only then
  drops the future (or the transaction). A `SET LOCAL` the server refuses
  opens nothing: the peer answered, and the transaction is dropped at depth
  one.
- **The window.** While it is open, every connection released to the pool is
  probed with `ROLLBACK`, within `probe_timeout`: a late answer is drained
  first (sqlx waits for every outstanding answer before a statement), the
  transaction ends, and the connection is kept; one that cannot answer is
  handed to sqlx to close. The window stays open until BOTH its deadline
  (`window` after the latest opening) has passed AND the pool's
  `max_connections` releases have been probed since; a second opening keeps
  the later deadline and owes all the probes again.
- **Per pool.** `lazy` and `sibling` each allocate their own window, which
  the pool's own `after_release` hook reads (sqlx stores the hook in that
  pool's inner state, and every release of one of its connections runs it).
  So one pool's stuck `BEGIN` never costs another pool's releases a probe,
  and a `GuardedConnection` carries its pool's window, so `begin` always
  opens the right one.

### What the type guarantees, and what it does not

It guarantees **connection ownership through its API**: `GuardedPool`'s
`begin` and `acquire` shadow sqlx's (`pool.begin()` and `pool.acquire()` with
sqlx's arguments do not compile), and so does `GuardedConnection::begin`.

It does NOT guarantee **exclusive transaction entry**. `Deref` keeps sqlx's
other entry points reachable, and none of them has the bound or the probe:

- transaction entry: `try_begin`, `begin_with`, `try_begin_with`,
  `PgPool::begin(&pool)`, `Connection::begin` on `&mut *connection`, and a
  raw `BEGIN` / `START TRANSACTION` in SQL;
- an unguarded connection: `(*pool).acquire()`, `try_acquire`;
- option mutation: `set_connect_options` replaces the checked options of a
  live pool;
- pool construction: a pool built from `pool.options().clone()` (or with
  `PgPoolOptions`, `connect_lazy_with`, `lazy_pool`) has no guard, or SHARES
  this pool's window (cloning the options clones the hook).

These are a **caller precondition**. Forbid them in a source scan of your
own `src/` (outside the module that builds the pool): every sqlx transaction
entry point above, raw `BEGIN`/`START TRANSACTION` literals, `PoolConnection<`,
`.try_acquire(`, `PgPoolOptions`/`PoolOptions`, `connect_lazy`/`connect_with`,
`lazy_pool`, `.set_connect_options(`, `.options().clone()`, and the two
`test-support` seams; give the scan a negative fixture per rule.

### Guaranteed, and the residuals

- **The bound (scheduling permitting):** the caller has its answer within
  `begin_timeout` of the `BEGIN` being sent, plus at most another
  `begin_timeout` for the `SET LOCAL`, whatever the peer does. A paused
  process (CPU throttling) answers nobody meanwhile, and Tokio's `timeout`
  polls the inner future before its timer, so an answer ready by the time
  the task runs after the deadline is accepted.
- **A timeout** (`BEGIN` or `SET LOCAL`): the task still owns the future or
  the transaction when the bound fires, and the window opens before the
  drop, so the abandoned connection's release, spawned at the drop, finds it
  open. A late answer is then ended by the probe, unless residual 2 applies.
- **Residual 1, the error/panic race (narrowed, not closed).** On a `BEGIN`
  error or panic, sqlx drops the connection INSIDE its own future, before the
  task sees the outcome, and the drop spawns the release. There is no
  `.await` between that and the opening, so the release cannot run first on
  a current-thread runtime, nor on the multi-thread runtime while Tokio holds
  it in the worker's LIFO slot; it can when the release goes to the stealable
  run queue, and then goes back unprobed. (The crate's test pins the
  current-thread case.)
- **Residual 2, release order.** The owed probes count RELEASES, not
  connections: if the process pauses past the deadline and hot connections'
  releases run before the abandoned one, they spend the probes, and the late
  answer's connection goes back inside its transaction. The deadline is the
  real guarantee; the owed probes only narrow the paused-process case, and
  assume Tokio runs queued releases roughly in arrival order.
- **Residual 3, the silent peer.** Once a connection is handed back to
  sqlx, its disposal is sqlx's, and unbounded: over TLS, `close_hard`'s
  shutdown flush can wait on the peer; after a probe that succeeds, sqlx's
  release `ping` sends a `Sync` the peer can withhold. sqlx 0.9 sets no TCP
  keepalive and has no socket hook (`IGNORED_URL_PARAMETERS`), so TCP never
  notices a peer that goes silent. Over plaintext the probe's timeout does
  free the slot.
- **Residual 4, single occupancy and the entry points.** A `GuardedPool`'s
  `after_release` hook is the guard's: `lazy` takes no other, and a later
  feature that needs the hook must compose with the guard's. A pool not
  built by `lazy`/`sibling`, or a transaction begun through a `Deref` hole
  (above), gets neither the bound nor the probe.
- **Also outside:** a task cancelled at runtime shutdown (`WorkerCrashed`,
  no window).

### Preconditions and dependencies

- **`sibling` inherits the parent's `BeginGuard`.** A pool that needs other
  timeouts (or other options) is built with `GuardedPool::lazy` on your own
  checked options.
- **Install `LOG_CAPS`.** When a probe fails, sqlx logs its own WARN (`error
  from after_release`, target `sqlx_core::pool`) with the RAW error next to
  the guard's value-free line. Only a subscriber that installs `LOG_CAPS`
  hides it: exporting the constant filters nothing.
- **sqlx's `Transaction::begin` is `#[doc(hidden)]`.** The guard calls it
  (it is what `Pool::begin` calls once its checkout returns), for a
  `Transaction<'static, _>` that owns its pooled connection. The workspace
  requires `sqlx = "0.9"`; a sqlx bump re-runs the guard's live suite (CI's
  all-features lane).
- `lazy` and `sibling` must be called inside a Tokio runtime.

### Tracing

Two WARN lines, target `stridelabs_postgres::guard`, fixed text, no SQL, no
options, no PID:

| Message | Fields |
|---|---|
| `a BEGIN was abandoned; probing released connections` | `cause` = `timeout`, `error`, `panic` or `set_local_timeout` |
| `a released connection failed its probe; closed` | `error` = `error_summary` of the failure (e.g. `I/O error (TimedOut)`) |

"Closed" means a close REQUESTED: the line is written before sqlx's
`close_hard` starts, which can still wait (residual 3).

## Feature topology

| Feature | Default | Adds |
|---|---|---|
| `guard` | off | the begin guard: `GuardedPool`, `GuardedConnection`, `BeginGuard`, `TxBounds`, `DEFAULT_PROBE_TIMEOUT`, `DEFAULT_WINDOW`, `MAX_TIMEOUT`, `MAX_WINDOW`, `MAX_APPLICATION_NAME_BYTES`; `tokio` (`rt`, `time`) and `futures-util` (`std`) become direct dependencies, both already in every sqlx graph |
| `test-support` | off | `guard`, plus two hidden seams for tests: `GuardedPool::set_window_opened_at` (the window as if opened at an instant, all its probes owed) and `TxBounds::REFUSED_BY_THE_SERVER` (bounds the server refuses, SQLSTATE `22023`). `[dev-dependencies]` only |
| `live-tests` | off | **not for consumers**: compiles the crate's real-Postgres suites (`tests/live.rs`, `tests/guard.rs`), which panic without the compose Postgres |

sqlx is a required dependency with exactly two features, `postgres` and
`runtime-tokio`: no `macros`, no `time`, no `migrate`. The guard's `tokio`
names `rt` and `time`, but the workspace's tokio entry is `full` and
inheritance can only add, so the list documents intent (Tokio is in every
consumer's graph already, through sqlx's `runtime-tokio`).

**No TLS feature.** Like `stridelabs-auth` and `stridelabs-gcp`, this crate
picks no TLS stack; the consumer's own sqlx does, and Cargo unifies it into
this crate's. Name `tls-rustls-aws-lc-rs` there, the house provider (see the
workspace README's "One crypto provider: aws-lc-rs"); never `tls-rustls-ring`.
A TLS feature here would put its provider next to the consumer's choice, and
would unify into `stridelabs-testing`'s TLS-free pool in this workspace's own
all-features build. Without any TLS feature, sqlx refuses an `sslmode` that
needs TLS when it connects ("built without TLS support"), never downgrading.

`LOG_CAPS` are plain `(target, LevelFilter)` pairs, not a
`stridelabs-observability` `TargetCaps`, so the crate depends on no logging
setup:

```rust
let caps = stridelabs_postgres::LOG_CAPS
    .iter()
    .fold(stridelabs_observability::TargetCaps::new(), |caps, (target, level)| {
        caps.cap(*target, *level)
    });
```

All four targets are off at every level:

- `sqlx_core::pool` logs a raw `sqlx::Error` (the server's message) from its
  own background work;
- `sqlx_postgres::options` logs an unrecognised URL parameter's value
  (`connect_options` makes that unreachable; the cap keeps it so for a URL
  that reaches sqlx another way);
- `sqlx::postgres::notice` logs every server notice verbatim, and a notice
  quotes whatever value it is about, on a connection that succeeds, so no
  error is ever summarised: an `application_name` past the server's 63-byte
  identifier limit (which `connect_options` accepts) is truncated with a
  NOTICE quoting the original. A consumer that wants its own SQL's notices
  (`RAISE NOTICE`) replaces this cap with a looser one;
- `sqlx_postgres::message` decodes the server's wire messages, and today
  logs (DEBUG) the body of a `CopyDone` a misbehaving peer sent non-empty,
  verbatim.

The crate's tests pin the first three to where sqlx 0.9 really logs (the
notice one against the compose Postgres, with a real truncation notice);
the fourth is capped from reading sqlx's source, since reaching it takes a
peer that breaks the COPY protocol. Every other sqlx 0.9 log call was read
and left uncapped, each for a reason in `LOG_CAPS`' docs: `sqlx::query`
logs the application's own SQL text and timings (never bind parameters),
and the rest log timings, counts, type names, or the advisory-lock key the
application chose.

## Tests

`cargo test -p stridelabs-postgres` needs no services: every URL rule has a
test with a passing control, the environment rules go through a lookup seam
(no `set_var`), and the password-file rule runs in a child process whose
environment alone carries `PGPASSFILE`. `--features live-tests` (the
workspace's all-features lane) adds the real-Postgres suite: a lazy pool's
first connection, real database errors summarised without their message, and
the pool's own log target. It uses `stridelabs-testing`'s `require_postgres`,
which panics, never skips, when the compose Postgres is down
(`docker compose up -d`).

The guard's unit tests (the window's rules on a test clock, the bounds'
rendering and refusals, the duration limits, `sibling`'s name check and
isolation) compile under `guard`; its `compile_fail` doctests pin the
`const` refusals. Its live suite (`tests/guard.rs`, under `live-tests`)
drives a guarded pool through a small fault relay
(`tests/common/pg_fault.rs`) that holds the first `BEGIN`'s answer, answers
it with a synthesised error after the server entered the transaction, or
holds the answer to the statement after it: a `BEGIN` cut off, never
answered, answered late or failed, a bounds statement never answered or
refused, two sibling pools, and the window's own rules, each against its
control (the same fault without the guard).
