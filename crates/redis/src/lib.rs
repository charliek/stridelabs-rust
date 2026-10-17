//! A lazy, shared Redis connection for StrideLabs services, with the two
//! things every service so far has wanted from it: an atomic fixed-window
//! counter (rate limiting) and `GET` / `SET … EX` (a TTL cache).
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
//! # let _ = cached;
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
//! - [`RedisHandle::get`] and [`RedisHandle::set_ex`] are idempotent, and may
//!   be retried **once**, on a fresh connection, after an I/O failure on a
//!   connection that was already cached (the kind that can go stale while
//!   idle). A connection dialled by the call itself is never retried on, and
//!   neither is a malformed reply.
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
//! # Errors never carry the URL
//!
//! A Redis URL holds its password in the userinfo. [`RedisError`] holds
//! redis-rs's rendering of a failure, which never includes the connection
//! info, and [`RedisHandle`]'s `Debug` names only its timeouts and whether it
//! is connected.

pub mod handle;

mod commands;
mod error;

pub use commands::MAX_TTL_SECS;
pub use error::RedisError;
pub use handle::{RedisHandle, RedisOptions, DEFAULT_DIAL_TIMEOUT, DEFAULT_RESPONSE_TIMEOUT};
