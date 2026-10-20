//! A lazy, shared Redis connection for StrideLabs services, with what the
//! services so far have wanted from it: an atomic fixed-window counter (rate
//! limiting), `GET` / `SET … EX` (a TTL cache), a caller's own Lua scripts
//! under a replay policy the caller chooses, and `PING` (a readiness probe).
//!
//! ```no_run
//! # async fn example() -> Result<(), stridelabs_redis::RedisError> {
//! use stridelabs_redis::RedisHandle;
//!
//! // At boot: parses the URL, performs no I/O.
//! let redis = RedisHandle::open("rediss://default:password@example.upstash.io:6379")?;
//!
//! // Per request: the first call dials; every clone shares the connection.
//! let window = 1_760_000_000 / 60;
//! let count = redis.fixed_window_hit(&format!("mcp:rl:alice:read:{window}"), 60).await?;
//! if count > 60 {
//!     // over the limit
//! }
//!
//! redis.set_ex("pat:validate:3f2a…", r#"{"sub":"alice"}"#, 120).await?;
//! let cached: Option<String> = redis.get("pat:validate:3f2a…").await?;
//!
//! // A script, sent at most once: a second run would count twice.
//! let spent: i64 = redis
//!     .eval(
//!         "return redis.call('INCRBY', KEYS[1], ARGV[1])",
//!         &["budget:alice:2026-10-20"],
//!         &[1_500_u64.into()],
//!         stridelabs_redis::Replay::Never,
//!     )
//!     .await?;
//!
//! // `/health/ready`.
//! redis.ping().await?;
//! # let _ = (cached, spent);
//! # Ok(())
//! # }
//! ```
//!
//! # The connection is lazy
//!
//! [`RedisHandle::open`] parses the URL and stops there, so a process whose
//! Redis is down still boots and still serves everything that does not need
//! it. The first command dials and caches one multiplexed connection, which
//! every clone of the handle shares:
//!
//! - **Single flight.** Concurrent calls that find no connection share ONE
//!   dial and its outcome, success or failure; the next call after a failed
//!   dial dials afresh.
//! - **Timeouts.** A dial gets 1 s (TCP, TLS and the connection-setup
//!   commands together), and each command 500 ms for its reply, both
//!   configurable through [`RedisOptions`].
//! - **A broken connection is dropped, and the NEXT command redials.** Any
//!   failure to read a valid reply (a reset socket, a closed connection, a
//!   response timeout, a reply that is not RESP) discards the cached
//!   connection — generation-guarded, so a late failure from an older
//!   connection cannot discard a newer one.
//!
//! Modelled on tapper's hardened rate-limiter slot, not on an eager-at-boot
//! handle that never reconnects. See [`handle`] for the state machine.
//!
//! # Replay policy
//!
//! Whether a command may be sent again after an I/O failure depends on
//! whether running it twice is harmless:
//!
//! - [`RedisHandle::fixed_window_hit`] is **never replayed**. A lost reply
//!   does not mean a lost `INCR` — Redis may have run it — so a retry could
//!   count one hit twice. The error ([`RedisError::Io`]) goes to the caller,
//!   whose policy (a rate limiter fails open) decides what happens.
//! - [`RedisHandle::get`], [`RedisHandle::set_ex`] and [`RedisHandle::ping`]
//!   are idempotent, and may be retried **once**, on a fresh connection,
//!   after an I/O failure on a connection that was already cached (the kind
//!   that can go stale while idle). A connection dialled by the call itself
//!   is never retried on, and neither is a malformed reply.
//! - [`RedisHandle::eval`] runs a script only its caller understands, so the
//!   **caller chooses**, with a [`Replay`]: [`Replay::Never`] (sent at most
//!   once) for any script that writes — it counts, it acquires or takes a
//!   lease over — and [`Replay::OnceOnFreshConnection`] (the retry above)
//!   only for one whose second execution is harmless: a read, or a write
//!   idempotent in its value and its TTL effects on a key no other writer
//!   races. Under the second, a script whose reply was lost after it ran
//!   **is** run again — possibly after other clients' commands — and the
//!   caller gets the retry's answer.
//!
//! Windows and TTLs are checked against `1..=`[`MAX_TTL_SECS`] before any
//! I/O.
//!
//! [`RedisError`]'s variants say what the caller can conclude: whether the
//! command was sent, and whether its outcome is known.
//!
//! # TLS: `rediss://`, and the consumer's crypto provider
//!
//! redis-rs is built with `tokio-rustls-comp`, because Upstash serves only
//! `rediss://` (and without a TLS feature redis-rs refuses such a URL at
//! `open`). Certificates are verified against the OS trust store, so the
//! runtime image needs `ca-certificates`; `rediss://…#insecure` is refused.
//!
//! **This crate installs no rustls crypto provider.** A `rediss://` dial calls
//! `rustls::ClientConfig::builder()`, which uses the process-default provider
//! — so a consumer installs aws-lc-rs once at startup, before the first dial
//! (`stridelabs_http::tls::install_default_provider`, feature `tls` of
//! `stridelabs-http`). Without one installed, rustls falls back to the single
//! provider its crate features name, and panics if there are none or two.
//! (That panic happens on the dial's own task, so under `panic = "unwind"` the
//! handle reports it as [`RedisError::Connect`] on every dial rather than
//! taking the process down — a startup bug either way.) No plain-`redis://`
//! dev or CI run exercises that path, which is why it is the consumer's
//! startup code, not luck, that must settle it.
//!
//! # Feature topology
//!
//! `default = []`, and there are no consumer-facing features: everything
//! above is unconditional. `live-tests` exists only to compile this crate's
//! own real-Redis suite (it needs a running Redis); consumers never enable it.
//!
//! # What errors carry: a fixed summary, never anyone's text
//!
//! Every [`RedisError`] payload is a summary this crate composes from fixed
//! strings. It never copies redis-rs's text or the server's, because both
//! quote what they were sent: a server refusing a handshake echoes `HELLO 3
//! AUTH <user> <password>`, an unknown command echoes its arguments, a
//! script's compile error quotes its source, `error(…)` /
//! `redis.error_reply(…)` say whatever the script put in them (the error's
//! first word, its "code", included), and redis-rs quotes the bytes of a
//! reply that is not RESP, the value of one that does not convert, and the
//! URL's `protocol` value in one of its URL checks. What each variant
//! carries:
//!
//! - `InvalidUrl`: which URL check failed, from a fixed list, or that
//!   redis-rs does not accept the URL. Never the URL or any part of it.
//! - `InvalidArgument`: which of this crate's checks failed.
//! - `Connect` and `Io`: the failure's class. That is "timed out",
//!   "connection refused", "the connection was closed or reset", an I/O
//!   error's kind (`InvalidData`, …), "the reply was not well-formed RESP",
//!   "authentication failed", or an error reply as below. A refused
//!   handshake is still `Connect`.
//! - `Command`: an error reply's code when it is one Redis itself defines
//!   (`ERR`, `WRONGTYPE`, `NOSCRIPT`, `BUSY`, `READONLY`, `OOM`, …), with a
//!   fixed description of its class. Any other code is reported as
//!   undefined, never echoed, since a script can pick its own. Or that a
//!   reply did not convert to the command's type, or the shape of a reply
//!   `eval` or `ping` did not expect.
//!
//! That holds for `Display`, `Debug` and the payload string itself, so a
//! consumer may log, store or wrap any of them. The server's own words are
//! not kept: to see them while debugging, reproduce the command with
//! `redis-cli`. This crate's own log lines (a retried command, a dropped
//! connection) use the same summaries. [`RedisHandle`]'s `Debug` names only
//! its timeouts and whether it is connected, and [`EvalArg`]'s `Debug`
//! names each argument's kind (and a text's length), never its value.

pub mod handle;

mod commands;
mod error;

pub use commands::{EvalArg, EvalReply, MAX_TTL_SECS};
pub use error::RedisError;
pub use handle::{
    RedisHandle, RedisOptions, Replay, DEFAULT_DIAL_TIMEOUT, DEFAULT_RESPONSE_TIMEOUT,
};
