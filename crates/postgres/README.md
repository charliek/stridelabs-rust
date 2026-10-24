# stridelabs-postgres

Postgres connection hygiene on sqlx for StrideLabs services: the checks a
`DATABASE_URL` passes **before sqlx parses it**, a `sqlx::Error` rendered
**without anything a server or a URL put into it**, a pool built **without
connecting**, **Neon pooler detection**, and the **sqlx log targets** to cap.
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
stridelabs-postgres = { git = "https://github.com/charliek/stridelabs-rust.git", rev = "<sha>" }
# Your own sqlx picks the TLS stack (see "Feature topology"):
sqlx = { version = "0.9", default-features = false, features = ["runtime-tokio", "postgres", "tls-rustls-aws-lc-rs"] }
```

The crate is unreleased: pin `rev = "<sha>"` until a tag contains it, then
`tag = "vX.Y.Z"`. See the workspace root README for the local `[patch]`
co-development snippet.

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

## Feature topology

| Feature | Default | Adds |
|---|---|---|
| `live-tests` | off | **not for consumers**: compiles the crate's real-Postgres suite (`tests/live.rs`), which panics without the compose Postgres |

Nothing else is optional. sqlx is a required dependency with exactly two
features, `postgres` and `runtime-tokio`: no `macros`, no `time`, no
`migrate`.

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
