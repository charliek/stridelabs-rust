# stridelabs-redis

A lazy, shared Redis connection for StrideLabs services, and what the
services so far have wanted from it: an **atomic fixed-window counter** (rate
limiting) that is never replayed, idempotent **`GET` / `SET … EX`** helpers (a
TTL cache), the caller's own **Lua scripts** (`EVAL`) under a **replay policy
the caller chooses**, and **`PING`** (a readiness probe). Lifted out of
tapper's hardened rate-limiter connection slot so the next service does not
write a fourth copy.

## Adding the dependency

```toml
[dependencies]
stridelabs-redis = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.8.0" }
```

(`v0.7.0` is the first release with this crate. During development against
an unreleased commit, pin `rev = "<sha>"` instead of `tag`; see the workspace
root README for the local `[patch]` co-development snippet.)

## Using it

```rust,no_run
use stridelabs_redis::RedisHandle;

# async fn example() -> Result<(), stridelabs_redis::RedisError> {
// At boot: parses the URL, performs no I/O.
let redis = RedisHandle::open("rediss://default:password@example.upstash.io:6379")?;

// A per-minute window for one subject and class: the caller builds the key
// (window number included) and owns the limit.
let window = 1_760_000_000 / 60;
let count = redis.fixed_window_hit(&format!("mcp:rl:alice:read:{window}"), 60).await?;

// A TTL cache.
redis.set_ex("pat:validate:3f2a", r#"{"sub":"alice"}"#, 120).await?;
let cached = redis.get("pat:validate:3f2a").await?;

// A script of your own. It counts, so a second run would change the
// outcome: it is sent at most once.
let spent: i64 = redis
    .eval(
        "return redis.call('INCRBY', KEYS[1], ARGV[1])",
        &["budget:alice:2026-10-20"],
        &[1_500_u64.into()],
        stridelabs_redis::Replay::Never,
    )
    .await?;

// `/health/ready`.
redis.ping().await?;
# let _ = (count, cached, spent);
# Ok(())
# }
```

| API | What it does |
|---|---|
| `RedisHandle::open(url)` / `open_with(url, RedisOptions)` | Parse the URL; no I/O. `RedisOptions` carries the dial (1 s) and response (500 ms) timeouts. |
| `fixed_window_hit(key, window_secs) -> u64` | Atomic Lua `INCR`, plus `EXPIRE window_secs` when the count is 1. Returns the count, this hit included. Never replayed. |
| `get(key) -> Option<String>` | `GET`. Retried once on a fresh connection after an I/O failure on a cached one. |
| `set_ex(key, value, ttl_secs)` | `SET key value EX ttl_secs`. Retried like `get`. |
| `eval::<T>(script, keys, args, replay) -> T` | `EVAL script numkeys keys… args…`; `T` is `i64` or `Vec<i64>` (`EvalReply`), args are `EvalArg`s (text or integers, via `.into()`). Replayed only as `replay` says. |
| `ping()` | `PING`; `Ok(())` on `PONG`. Retried like `get`. |
| `Replay` | `Never` / `OnceOnFreshConnection` — the policy `eval`'s caller chooses (see below). |
| `MAX_TTL_SECS` | The longest window or TTL accepted: ten years (315,360,000 s). |
| `RedisError` | `InvalidUrl`, `InvalidArgument`, `Connect`, `Io`, `Command`. Each carries a fixed summary, never redis-rs's or the server's text (see below). |

Four contracts the signatures do not show:

- **`fixed_window_hit` needs a key namespace of its own.** The TTL is set only
  when the `INCR` creates the key, so a key that already holds an integer
  with no TTL (written by anything else) is counted up forever and never
  repaired. Prefix the windows with something nothing else writes under.
- **`set_ex`'s retry is idempotent in the cache sense, not a conditional
  write.** The retry — or a first attempt that lands late — restarts the TTL
  and overwrites whatever another writer stored in between: right for a TTL
  cache whose writers store the same answer, wrong for compare-and-set.
- **`eval` is a raw `EVAL`**: the script travels with every call. No
  `EVALSHA` / `SCRIPT LOAD` cache that a restart or failover empties, and no
  redis-rs `script` feature (or its `sha1_smol`) in the graph. Pass every key
  the script touches in `keys`.
- **Windows and TTLs are checked before any I/O**: `1..=MAX_TTL_SECS`, or
  `InvalidArgument`. An `EXPIRE` Redis refuses (zero deletes the key; above
  what it can represent, `expire.c` answers "invalid expire time") would run
  after the script's `INCR`, which a script error does not roll back — a
  counter at 1 with no TTL, i.e. a window that never ends.

`RedisHandle` is `Clone` (an `Arc` bump; every clone shares the connection),
and its `Debug` never prints the URL.

## The connection is lazy

Nothing dials at boot, so a process whose Redis is down still starts and
serves everything that does not need Redis. The first command dials:

- **Single flight.** Concurrent calls that find no connection share one dial
  and its outcome. N callers against a dead Redis cost one dial timeout, not N
  queued ones; the next call after a failure dials afresh.
- **The dial outlives a cancelled caller.** It runs as its own task and
  settles the connection slot itself, so a caller that gives up (a client
  disconnecting mid-dial) never leaves the handle stuck.
- **A broken connection is dropped and the next command redials.** Any
  failure to read a valid reply — a reset or closed socket, a reply that
  misses the response timeout, or one that is not well-formed RESP —
  discards the cached connection. The discard is
  **generation-guarded**: each dial is numbered, and a late failure from an
  older connection (a call that was still holding it while another call had
  already reconnected) cannot discard the newer one.
- A server error reply (`WRONGTYPE`, a script error) proves the connection
  works, and does not discard it.

## Replay policy

| Command | After an I/O failure |
|---|---|
| `fixed_window_hit` | **Never replayed.** Redis may have run the `INCR` before the reply was lost, so a retry could count one hit twice. The caller gets `RedisError::Io` (`is_outcome_unknown()` is `true`); a rate limiter fails open on it. |
| `get`, `set_ex`, `ping` | Idempotent: sent **once more** on a fresh connection — but only after an I/O failure on a connection that was already cached (the kind that can die while idle). A connection the call dialled itself is never retried on, and neither is a malformed reply: it is outcome-unknown, but not a stale connection. If the fresh connection cannot be made, the caller gets the **first** attempt's `Io` (outcome unknown: that `SET` may have run), not the dial's `Connect`. |
| `eval` | **The caller's `Replay`.** `Replay::Never` behaves like `fixed_window_hit`; `Replay::OnceOnFreshConnection` like `get`. |

So one fixed-window hit takes at most a dial plus a response timeout (1.5 s by
default), and an idempotent call at most response + dial + response (2 s) —
the budget a readiness endpoint's `ping` needs.

### Choosing `eval`'s `Replay`

There is no default: only the code that wrote a script knows whether running
it twice is harmless. When in doubt, `Never`.

- **`Replay::Never`** — sent at most once. For anything a second run would
  change: an `INCR`/`INCRBY` charge, a lease acquire or takeover, **any
  script that writes**. A lost reply is `RedisError::Io` with
  `is_outcome_unknown()`: the script may have run, may not, or may still
  run (the request can be delayed on the dropped connection). That stays
  unknown. A later read shows the current state, not what became of the
  attempt, and is no reason to resend.
- **`Replay::OnceOnFreshConnection`** — a script whose reply was lost after
  it ran **is sent again**: the handle cannot tell a request that never
  arrived from a reply that never came back. The first attempt may have
  executed, may even land after the retry, and other clients' commands can
  run in between. So only for a script whose second execution is harmless
  under all of that: a read, or a write that is idempotent in its value
  **and its TTL effects** on a key no other writer races. The caller gets
  the retry's answer, which can differ from what the first attempt answered.

```rust,no_run
use stridelabs_redis::Replay;

# async fn example(redis: &stridelabs_redis::RedisHandle, token: &str) -> Result<(), stridelabs_redis::RedisError> {
// Read-only: a second run changes nothing, so a lost reply may be retried.
let spent_and_ttl: Vec<i64> = redis
    .eval(
        "return {tonumber(redis.call('GET', KEYS[1]) or 0), redis.call('PTTL', KEYS[1])}",
        &["budget:alice:2026-10-20"],
        &[],
        Replay::OnceOnFreshConnection,
    )
    .await?;

// A lease takeover writes: sent at most once.
const TAKE_OVER: &str = "
local previous = redis.call('GET', KEYS[1])
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
if previous and previous ~= ARGV[1] then return 1 end
return 0
";
let took_over: i64 = redis
    .eval(TAKE_OVER, &["lease:alice"], &[token.into(), 30_000_u64.into()], Replay::Never)
    .await?;
# let _ = (spent_and_ttl, took_over);
# Ok(())
# }
```

Why the takeover must not be replayed, even though it writes the caller's
own token every time: A's `SET` runs and its reply is lost; B takes the lease
over; A's replay overwrites B's token and reports success, so both believe
they hold it. Even with no B, the replay restarts the lease's TTL.

And what an `Io` error from it means: the takeover may have run, may not,
or may still run. Reading the lease back shows who holds it *now*. It does
not show whether this attempt ran (it may land after the read; the lease may
have expired or been taken since), so it is no licence to retry. The safe
responses: treat the session as **not** owning the lease until a later read
shows its own token, or end the session.

A script error (`redis.error_reply`, a Lua runtime or compile error, an
error from a `redis.call`) is `RedisError::Command`: Redis answered, nothing
is retried under either policy, and the connection stays cached.

## Errors

The variants answer what the caller can conclude about the command:

| Variant | Sent? | Ran? |
|---|---|---|
| `InvalidUrl` | no (raised by `open`) | no |
| `InvalidArgument` (a window or TTL outside `1..=MAX_TTL_SECS`, a zero timeout) | no | no |
| `Connect` (refused, DNS, TLS, `AUTH`, dial timeout) | no | no |
| `Io` (no valid reply: connection failed, response timeout, malformed RESP) | maybe | **unknown** |
| `Command` (a well-formed error reply — a script error included — or a value of the wrong type) | yes | Redis answered |

The line between `Io` and `Command` is whether a well-formed reply was read,
not redis-rs's `ErrorKind`: in redis-rs 1.7.1 `ErrorKind::Parse` covers both a
malformed reply (outcome unknown) and a well-formed reply of the wrong type
(Redis answered). The handle reads the raw reply first and decodes it
separately, so the two cannot be confused.

A malformed URL is refused by `open`, at boot, rather than per command: a
limiter that fails open on Redis errors would otherwise run unlimited in
production with nothing but warnings to show for it.

### What an error carries: a fixed summary, never anyone's text

Every payload is a summary this crate composes from fixed strings. It never
copies redis-rs's text or the server's, because both quote what they were
sent, and any of that can be a password, a key, a token or a user id:

- A server refusing a handshake echoes it. With `?protocol=resp3` and
  `HELLO` renamed or disabled, the reply is `unknown command 'HELLO', with
  args beginning with: '3' 'AUTH' '<user>' '<password>'`.
- An unknown command echoes its arguments: `… 'EVAL', with args beginning
  with: '<script>' '1' '<key>' '<token>'`.
- A compile error quotes the script's source, and `error(…)` and
  `redis.error_reply(…)` say whatever the script put in them, the error's
  first word (its "code") included.
- redis-rs quotes the bytes of a reply that is not RESP, the value of a
  reply that does not convert, and the URL's `protocol` value in one of its
  URL checks.

What each variant carries:

| Variant | Its payload |
|---|---|
| `InvalidUrl` | Which URL check failed, from a fixed list ("Invalid database number", "Missing hostname", "Invalid protocol version", …), or that redis-rs does not accept the URL. Never the URL or any part of it. |
| `InvalidArgument` | Which of this crate's checks failed. |
| `Connect`, `Io` | The failure's class: "timed out", "connection refused", "the connection was closed or reset", an I/O error's kind (`InvalidData`, …), "the reply was not well-formed RESP", "authentication failed", or an error reply as below. A refused handshake is still `Connect`. |
| `Command` | For an error reply: its code, **when it is one Redis itself defines** (`ERR`, `WRONGTYPE`, `NOSCRIPT`, `BUSY`, `READONLY`, `OOM`, `NOAUTH`, `LOADING`, …), with a fixed description of that class. Any other code is reported as undefined, never echoed, since a script picks its own. For a reply that did not convert: "incompatible type". For a reply `eval` or `ping` did not expect: its shape ("the script answered a string, not an array of integers"). |

That holds for `Display`, `Debug` and the payload string itself, so a
consumer may log, store or wrap any of them. The server's own words are not
kept at all: to see them while debugging a script, reproduce the command
with `redis-cli`. The crate's own log lines (a retried command, a dropped
connection) use the same summaries.

`EvalArg`'s `Debug` names each argument's kind (and a text's length), never
its value: `EvalArg(<text, 12 bytes>)`, `EvalArg(<integer>)`.

`EvalReply` decodes strictly: `i64` takes only an integer reply, and
`Vec<i64>` only an array of integers. Only a Lua `nil` ends a table early
(`{1, nil, 3}` arrives as `[1]`). A `false` becomes a nil *element*
(`{1, false, 3}` arrives as `[1, nil, 3]`, which `Vec<i64>` refuses), and a
nil reply is not an empty array. A script that wrote before returning a reply
that does not decode still wrote: the `Command` error says Redis ran it.

## TLS and the crypto provider (read this before using `rediss://`)

redis-rs is built with `tokio-rustls-comp`: Upstash serves only `rediss://`,
and without a TLS feature redis-rs refuses such a URL outright. Certificates
are verified against the OS trust store (`rustls-native-certs`, as reqwest's
`rustls` does elsewhere in this workspace), so the runtime image needs
`ca-certificates`. `rediss://…#insecure` (no certificate verification) is
refused by `open`.

**This crate installs no rustls crypto provider, and selects none.** A
`rediss://` dial calls `rustls::ClientConfig::builder()`, which takes the
process-default provider. Install aws-lc-rs once at startup, before the first
command:

```rust,ignore
stridelabs_http::tls::install_default_provider(); // stridelabs-http, feature `tls`
```

Without an installed default, rustls falls back to the one provider its crate
features name across your whole graph — and panics if there are none, or two
(`ring` next to aws-lc-rs). The panic is on the dial's own task, so (with
`panic = "unwind"`) every dial then fails as `RedisError::Connect` instead of
taking the process down; a limiter failing open on that would quietly stop
limiting. No plain-`redis://` dev or CI run reaches that code, so settle it
at startup, not by luck. This crate pulls no `ring`: redis
1.x's rustls has default features off (0.27's `tls-rustls` forced `ring`), and
the workspace CI's "compiles no ring" guard holds it there.

## Feature topology

`default = []`, and there are no consumer features: everything above is
unconditional.

| Feature | Default | Adds |
|---|---|---|
| `live-tests` | off | **Not for consumers.** Compiles this crate's real-Redis suite (`tests/live.rs`), which needs a running Redis and panics without one. On in the workspace's all-features lane. |

## Tests

- **Offline (always run):** URL parsing and redaction, timeouts, the
  window/TTL range, dial timeouts against a server that never answers and an
  unroutable address, single-flight failed dials (deterministic: every caller
  provably joined before the dial is released), the generation guard with a
  real stale failure, a dial outliving a cancelled caller, reply decoding;
  `EVAL`'s wire order (numkeys, keys, then arguments) and strict
  `EvalReply` decoding that never echoes the value, `EvalArg`'s `Debug`
  never printing a value, `eval` honouring the caller's `Replay` on a cached
  connection that never answers, `ping` against a closed port, bounded by
  each timeout, and `Ok` only on the `PONG` status (a scripted loopback
  server answers anything else); and error text: through a scripted server,
  every command's `Command` error shows a code Redis defines and withholds
  the server's text (an echoed argument, a script-chosen code, a value a
  conversion quotes) in `Display`, `Debug` and the payload; a refused
  handshake (`HELLO 3 AUTH` echoed, a refused RESP2 `AUTH`, a refused
  `SELECT`, and a `SELECT` refused after `AUTH` or `HELLO 3 AUTH` with a
  canary user and password succeeded) is `Connect` without the
  credentials or the echoed argument; every summary for a code Redis
  raises before running the command says it was refused; a URL refusal names the
  check, never the URL; and a failure below the reply (an I/O error's
  message, redis-rs's detail, a malformed reply's bytes) is described by its
  class.
- **Live (`live-tests`, needs `docker compose up -d redis`):** against a real
  Redis, mostly through an in-test TCP proxy that counts dials and loses
  replies or connections on demand — TTL set on the first hit only,
  atomicity under 100 concurrent hits, key isolation, `GET` / `SET EX` with
  TTL, the longest window and TTL accepted and an out-of-range one leaving no
  counter, no replay after a lost reply, a connection lost with its reply or
  a malformed reply, no retry of a malformed `GET` reply, reconnect after the
  connection dies or the server restarts, one-shot retries of idempotent
  commands, single-flight first dials and redials (overlap forced), the
  generation guard end to end, and a cancelled hit; `eval`'s keys and
  arguments arriving in order and its integer replies, `{1, false, 3}`
  refused and `{1, nil, 3}` read as `[1]`, script errors as `Command` errors
  carrying no script, key or argument, Redis diagnostics that quote a canary
  (an argument raised as the code, after `ERR`, in a runtime error, inside an
  array; the source in a compile error) in no rendering of the error nor its
  payload, the same for a server with `EVAL` renamed (the proxy renames one
  request, and Redis echoes the script, key and argument) and one with
  `HELLO` renamed (Redis echoes `3 AUTH alice <password>`; the dial fails as
  `Connect` without it), the proxy's request rewrite surviving a split
  read, `Replay::Never` not re-sent and `OnceOnFreshConnection`
  retried after the cached connection died, a lost reply leaving one run
  under `Never` and two under `OnceOnFreshConnection`, and `ping`'s retry
  and failure while Redis is down (each of these deletes the keys it
  wrote).

`stridelabs-testing`'s `require_redis` (feature `redis`) is the probe: it
reads `REDIS_URL` before the compose default `redis://localhost:6390/0`.

## Not included

Connection pools (one multiplexed connection is the right shape for these
command patterns), pub/sub, cluster and sentinel support, `EVALSHA` script
caching, a general command API (`eval` covers the rest: its reply types are
`i64` and `Vec<i64>`, and more can be added), and rate-limit *policy* (key
layout, limits, fail-open) — that lives in the consumer, or in
`stridelabs-mcp`'s `redis` feature.
