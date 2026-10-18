# stridelabs-redis

A lazy, shared Redis connection for StrideLabs services, and the two things
every service so far has wanted from it: an **atomic fixed-window counter**
(rate limiting) that is never replayed, and idempotent **`GET` / `SET … EX`**
helpers (a TTL cache). Lifted out of tapper's hardened rate-limiter connection
slot so the next service does not write a fourth copy.

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
# let _ = (count, cached);
# Ok(())
# }
```

| API | What it does |
|---|---|
| `RedisHandle::open(url)` / `open_with(url, RedisOptions)` | Parse the URL; no I/O. `RedisOptions` carries the dial (1 s) and response (500 ms) timeouts. |
| `fixed_window_hit(key, window_secs) -> u64` | Atomic Lua `INCR`, plus `EXPIRE window_secs` when the count is 1. Returns the count, this hit included. Never replayed. |
| `get(key) -> Option<String>` | `GET`. Retried once on a fresh connection after an I/O failure on a cached one. |
| `set_ex(key, value, ttl_secs)` | `SET key value EX ttl_secs`. Retried like `get`. |
| `MAX_TTL_SECS` | The longest window or TTL accepted: ten years (315,360,000 s). |
| `RedisError` | `InvalidUrl`, `InvalidArgument`, `Connect`, `Io`, `Command` — see below. |

Three contracts the signatures do not show:

- **`fixed_window_hit` needs a key namespace of its own.** The TTL is set only
  when the `INCR` creates the key, so a key that already holds an integer
  with no TTL (written by anything else) is counted up forever and never
  repaired. Prefix the windows with something nothing else writes under.
- **`set_ex`'s retry is idempotent in the cache sense, not a conditional
  write.** The retry — or a first attempt that lands late — restarts the TTL
  and overwrites whatever another writer stored in between: right for a TTL
  cache whose writers store the same answer, wrong for compare-and-set.
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
| `get`, `set_ex` | Idempotent: sent **once more** on a fresh connection — but only after an I/O failure on a connection that was already cached (the kind that can die while idle). A connection the call dialled itself is never retried on, and neither is a malformed reply: it is outcome-unknown, but not a stale connection. If the fresh connection cannot be made, the caller gets the **first** attempt's `Io` (outcome unknown: that `SET` may have run), not the dial's `Connect`. |

So one fixed-window hit takes at most a dial plus a response timeout (1.5 s by
default), and an idempotent call at most response + dial + response (2 s).

## Errors

The variants answer what the caller can conclude about the command:

| Variant | Sent? | Ran? |
|---|---|---|
| `InvalidUrl` | no (raised by `open`) | no |
| `InvalidArgument` (a window or TTL outside `1..=MAX_TTL_SECS`, a zero timeout) | no | no |
| `Connect` (refused, DNS, TLS, `AUTH`, dial timeout) | no | no |
| `Io` (no valid reply: connection failed, response timeout, malformed RESP) | maybe | **unknown** |
| `Command` (a well-formed error reply, or a value of the wrong type) | yes | Redis answered |

The line between `Io` and `Command` is whether a well-formed reply was read,
not redis-rs's `ErrorKind`: in redis-rs 1.7.1 `ErrorKind::Parse` covers both a
malformed reply (outcome unknown) and a well-formed reply of the wrong type
(Redis answered). The handle reads the raw reply first and decodes it
separately, so the two cannot be confused.

A malformed URL is refused by `open`, at boot, rather than per command: a
limiter that fails open on Redis errors would otherwise run unlimited in
production with nothing but warnings to show for it. No variant ever carries
the URL or its password.

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
  real stale failure, a dial outliving a cancelled caller, reply decoding.
- **Live (`live-tests`, needs `docker compose up -d redis`):** against a real
  Redis, mostly through an in-test TCP proxy that counts dials and loses
  replies or connections on demand — TTL set on the first hit only,
  atomicity under 100 concurrent hits, key isolation, `GET` / `SET EX` with
  TTL, the longest window and TTL accepted and an out-of-range one leaving no
  counter, no replay after a lost reply, a connection lost with its reply or
  a malformed reply, no retry of a malformed `GET` reply, reconnect after the
  connection dies or the server restarts, one-shot retries of idempotent
  commands, single-flight first dials and redials (overlap forced), the
  generation guard end to end, and a cancelled hit.

`stridelabs-testing`'s `require_redis` (feature `redis`) is the probe: it
reads `REDIS_URL` before the compose default `redis://localhost:6390/0`.

## Not included

Connection pools (one multiplexed connection is the right shape for these
command patterns), pub/sub, cluster and sentinel support, `EVALSHA` script
caching, and rate-limit *policy* (key layout, limits, fail-open) — that lives
in the consumer, or in `stridelabs-mcp`'s `redis` feature.
