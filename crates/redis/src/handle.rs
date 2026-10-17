//! [`RedisHandle`] — one lazily dialled, shared Redis connection.
//!
//! # The states
//!
//! ```text
//!   Empty ──(a call needs a connection)──────────────────▶ Dialing{g}
//!   Dialing{g} ──(the dial succeeded)────────────────────▶ Ready{g}
//!   Dialing{g} ──(the dial failed)───────────────────────▶ Empty      every waiter gets the error
//!   Dialing{g} ──(the dial task was dropped unfinished)──▶ Empty      every waiter gets an error
//!   Ready{g} ──(a round-trip on g failed at the I/O level)──▶ Empty   ONLY for g
//! ```
//!
//! `g` is the dial's generation: each dial is numbered, and a failure is
//! reported with the generation of the connection it happened on. Only
//! `Ready` at that same generation is reset, so a failure on an old
//! connection that is only now being reported — a call that was still holding
//! it when another call had already replaced it — cannot discard the newer
//! connection, or touch a dial in flight.
//!
//! # Single flight
//!
//! A call that finds the slot `Empty` starts THE dial; a call that finds it
//! `Dialing` joins that dial and gets its outcome — the connection or the
//! error. N concurrent first calls against a dead Redis therefore cost one
//! dial timeout, not N of them in a queue; the next call after a failure
//! dials afresh. The dial runs as its own spawned task that settles the slot
//! itself (through a drop guard, even when the task is dropped
//! unfinished), so a dial outlives a caller that gives up on it and the slot
//! never stays `Dialing` with no one left to finish it.
//!
//! This is tapper's hardened rate-limiter slot (`tapper-rs/src/rate_limit.rs`,
//! its D-31 and T2 fixes), lifted out of the limiter so every consumer gets it.

use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use futures::future::{BoxFuture, FutureExt, Shared};
use redis::aio::{ConnectionLike, MultiplexedConnection};

use crate::RedisError;

/// The dial timeout [`RedisOptions::default`] uses: the TCP connect, the TLS
/// handshake and redis-rs's connection-setup pipeline (`AUTH`, `SELECT`,
/// `CLIENT SETINFO`) together.
pub const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(1);

/// The response timeout [`RedisOptions::default`] uses: how long one command
/// waits for its reply before it fails with [`RedisError::Io`].
pub const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);

/// The two timeouts a [`RedisHandle`] dials and talks with.
///
/// The defaults (1 s and 500 ms, the same values redis-rs 1.x itself defaults
/// to) bound the worst case of one call: a fixed-window hit takes at most a
/// dial plus one response timeout (1.5 s), and an idempotent `GET` / `SET EX`
/// that is retried after a cached connection died at most one response
/// timeout, a dial and another response timeout (2 s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RedisOptions {
    /// See [`DEFAULT_DIAL_TIMEOUT`].
    pub dial_timeout: Duration,
    /// See [`DEFAULT_RESPONSE_TIMEOUT`].
    pub response_timeout: Duration,
}

impl Default for RedisOptions {
    fn default() -> Self {
        RedisOptions {
            dial_timeout: DEFAULT_DIAL_TIMEOUT,
            response_timeout: DEFAULT_RESPONSE_TIMEOUT,
        }
    }
}

impl RedisOptions {
    /// Replace the dial timeout. It must be non-zero
    /// ([`RedisHandle::open_with`] refuses zero).
    #[must_use]
    pub fn with_dial_timeout(mut self, timeout: Duration) -> Self {
        self.dial_timeout = timeout;
        self
    }

    /// Replace the response timeout. It must be non-zero
    /// ([`RedisHandle::open_with`] refuses zero).
    #[must_use]
    pub fn with_response_timeout(mut self, timeout: Duration) -> Self {
        self.response_timeout = timeout;
        self
    }
}

/// A lazy, shared connection to one Redis server.
///
/// Building one performs **no I/O**: [`RedisHandle::open`] only parses the
/// URL, so a process whose Redis is down still boots. The first command dials
/// (single-flight, see the module docs) and caches one multiplexed connection
/// that every clone of the handle shares; a command that fails at the I/O
/// level drops that connection, and the next command dials again.
///
/// Clone it freely — a clone is an [`Arc`] bump, and every clone shares the
/// one connection. Every call must run inside a Tokio runtime (the dial is a
/// spawned task, and redis-rs spawns each connection's driver).
///
/// Its `Debug` output names the timeouts and the connection's state, never
/// the URL: a Redis URL carries its password in the userinfo.
#[derive(Clone)]
pub struct RedisHandle {
    shared: Arc<SharedState>,
}

/// Whether a failed command may be sent again on a fresh connection. See the
/// crate docs' replay policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Replay {
    /// A mutating command (the fixed-window `INCR`): Redis may have run it
    /// before the reply was lost, so the error goes to the caller.
    Never,
    /// An idempotent command (`GET`, `SET … EX`): sending it twice leaves
    /// Redis as sending it once would, so ONE retry is allowed — and only
    /// after an I/O-level failure on a connection that was already cached,
    /// the one kind that can have gone stale while idle.
    OnceOnFreshConnection,
}

struct SharedState {
    client: redis::Client,
    /// The dial and response timeouts, in the form redis-rs takes them.
    config: redis::AsyncConnectionConfig,
    /// The same timeouts, kept for `Debug`.
    options: RedisOptions,
    slot: Mutex<ConnectionSlot>,
}

/// What [`SharedState::slot`] guards. The lock is a [`std::sync::Mutex`] and
/// is **never held across an `await`**: every critical section reads or
/// replaces the state, then drops the guard, and anything replaced is dropped
/// after the guard.
struct ConnectionSlot {
    state: Slot,
    /// How many dials this handle has started — and so the generation of the
    /// newest one. `wrapping_add`, so not even the 2^64th dial can panic
    /// under the lock.
    dials: u64,
}

enum Slot {
    /// Never dialled, or the last dial or connection failed.
    Empty,
    /// A dial is in flight; every call that arrives now joins it.
    Dialing { generation: u64, dial: SharedDial },
    /// The cached connection, from dial number `generation`.
    Ready {
        generation: u64,
        connection: MultiplexedConnection,
    },
}

type DialOutcome = Result<MultiplexedConnection, redis::RedisError>;

/// One dial's outcome, awaitable by every caller that joined it. Both halves
/// of [`DialOutcome`] are `Clone` (a multiplexed connection is a handle to one
/// socket; redis 1.x's error derives `Clone`), which [`Shared`] requires. It
/// is only the receiving end of the dial task's channel, so the slot holding
/// it is not a reference cycle.
type SharedDial = Shared<BoxFuture<'static, DialOutcome>>;

/// A connection handed out by [`SharedState::lease`], and where it came from.
struct Lease {
    /// The dial that produced it — what a failure on it reports.
    generation: u64,
    connection: MultiplexedConnection,
    /// It was already `Ready` when asked for, rather than dialled or joined
    /// mid-dial by this call. Only such a connection can have died while it
    /// sat idle, so only a failure on one earns an idempotent retry.
    cached: bool,
}

/// Turn the raw reply into `T`. Everything here happens AFTER a complete,
/// well-formed reply was read, so every failure is [`RedisError::Command`]:
/// Redis answered with an error, or with a value of another type. (Doing the
/// conversion here rather than through `Cmd::query_async` is what keeps a
/// conversion failure apart from a malformed reply: redis-rs 1.7.1 reports
/// both as `ErrorKind::Parse`. See [`crate::error`].)
fn decode<T: redis::FromRedisValue>(reply: redis::Value) -> Result<T, RedisError> {
    let reply = reply
        .extract_error()
        .map_err(|error| RedisError::Command(error.to_string()))?;
    T::from_redis_value(reply).map_err(|error| RedisError::Command(error.to_string()))
}

/// `lock`, recovering from poison. No critical section here can leave the
/// slot half-updated (each is one read or one `mem::replace`), so a panic
/// elsewhere while holding it says nothing about the slot's consistency.
fn lock(slot: &Mutex<ConnectionSlot>) -> MutexGuard<'_, ConnectionSlot> {
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

impl RedisHandle {
    /// A handle for the server at `url`, with [`RedisOptions::default`].
    /// **No I/O** — see the type's docs.
    ///
    /// `url` is anything redis-rs accepts: `redis://[user][:password@]host[:port][/db]`,
    /// `rediss://…` for TLS (Upstash), or a `redis+unix://` / `unix://` socket
    /// path.
    ///
    /// # Errors
    ///
    /// [`RedisError::InvalidUrl`] when the URL does not parse, or asks for
    /// `rediss://…#insecure` (TLS with no certificate verification, which
    /// this crate never dials). Refusing here, at construction, rather than
    /// at the first command is deliberate: a consumer's rate limiter fails
    /// open on Redis errors, so a malformed URL that only failed per command
    /// would silently disable it in production instead of failing the boot.
    /// The error never contains the URL.
    pub fn open(url: &str) -> Result<RedisHandle, RedisError> {
        RedisHandle::open_with(url, RedisOptions::default())
    }

    /// [`RedisHandle::open`] with explicit timeouts.
    ///
    /// # Errors
    ///
    /// As [`RedisHandle::open`], and [`RedisError::InvalidArgument`] for a
    /// zero timeout (which would fail every dial or every command; a
    /// consumer reading `0` from config as "no timeout" would otherwise turn
    /// its Redis off without a word).
    pub fn open_with(url: &str, options: RedisOptions) -> Result<RedisHandle, RedisError> {
        if options.dial_timeout.is_zero() {
            return Err(RedisError::InvalidArgument(
                "the dial timeout must be non-zero",
            ));
        }
        if options.response_timeout.is_zero() {
            return Err(RedisError::InvalidArgument(
                "the response timeout must be non-zero",
            ));
        }
        let client =
            redis::Client::open(url).map_err(|error| RedisError::InvalidUrl(error.to_string()))?;
        if let redis::ConnectionAddr::TcpTls { insecure: true, .. } =
            client.get_connection_info().addr()
        {
            return Err(RedisError::InvalidUrl(
                "`#insecure` (TLS without certificate verification) is not supported".to_string(),
            ));
        }
        Ok(RedisHandle::from_client(client, options))
    }

    /// The constructor behind [`RedisHandle::open_with`], once the URL is
    /// accepted. Separate so the unit tests can hand in a client built from a
    /// `ConnectionInfo` no URL can express (`CLIENT SETINFO` skipped).
    fn from_client(client: redis::Client, options: RedisOptions) -> RedisHandle {
        RedisHandle {
            shared: Arc::new(SharedState {
                client,
                config: redis::AsyncConnectionConfig::new()
                    .set_connection_timeout(Some(options.dial_timeout))
                    .set_response_timeout(Some(options.response_timeout)),
                options,
                slot: Mutex::new(ConnectionSlot {
                    state: Slot::Empty,
                    dials: 0,
                }),
            }),
        }
    }

    /// Send `command` and read its reply as `T`, under `replay`'s policy.
    pub(crate) async fn query<T: redis::FromRedisValue>(
        &self,
        command: &redis::Cmd,
        replay: Replay,
    ) -> Result<T, RedisError> {
        let lease = self.shared.lease().await?;
        let error = match self.shared.send(&lease, command).await {
            Ok(reply) => return decode(reply),
            Err(error) => error,
        };
        // The retry is for a connection that died while idle, which surfaces
        // as an I/O-kind error. A malformed reply is outcome-unknown too, but
        // earns no retry: the replay policy does not widen with the
        // classification.
        if !(replay == Replay::OnceOnFreshConnection && lease.cached && error.is_io_error()) {
            return Err(RedisError::no_valid_reply(&error));
        }
        // How often a cached connection turns out dead is worth seeing (it
        // is what an idle timeout at the server, or a platform's connection
        // reset, costs), and the caller sees `Ok` if the retry lands.
        tracing::warn!(
            %error,
            "the cached Redis connection failed; retrying an idempotent command once on a fresh one"
        );
        drop(lease);
        // `send` has already discarded the failed generation, so this lease
        // is a new dial — or a newer connection another call just made.
        //
        // If it cannot be had, the first attempt's error stands: that
        // command may have run before its reply was lost, and a reconnect
        // failing says nothing about it. Reporting the dial's `Connect`
        // ("never sent") instead would erase that outcome-unknown.
        let retry = match self.shared.lease().await {
            Ok(retry) => retry,
            Err(reconnect) => {
                tracing::debug!(error = %reconnect, "no fresh Redis connection for the retry");
                return Err(RedisError::no_valid_reply(&error));
            }
        };
        let reply = self
            .shared
            .send(&retry, command)
            .await
            .map_err(|error| RedisError::no_valid_reply(&error))?;
        decode(reply)
    }
}

impl fmt::Debug for RedisHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let connection = match lock(&self.shared.slot).state {
            Slot::Empty => "none",
            Slot::Dialing { .. } => "dialing",
            Slot::Ready { .. } => "ready",
        };
        f.debug_struct("RedisHandle")
            .field("dial_timeout", &self.shared.options.dial_timeout)
            .field("response_timeout", &self.shared.options.response_timeout)
            .field("connection", &connection)
            .finish_non_exhaustive()
    }
}

impl SharedState {
    /// The cached connection, the one being dialled right now, or a new dial.
    ///
    /// **The dial task is spawned after the lock is released**: a runtime
    /// that is shutting down drops a task inside `spawn`, and dropping a dial
    /// task takes the lock to empty the slot — spawning under the lock would
    /// deadlock on it.
    async fn lease(self: &Arc<Self>) -> Result<Lease, RedisError> {
        let mut task = None;
        let (generation, dial) = {
            let mut slot = lock(&self.slot);
            match &slot.state {
                Slot::Ready {
                    generation,
                    connection,
                } => {
                    return Ok(Lease {
                        generation: *generation,
                        connection: connection.clone(),
                        cached: true,
                    })
                }
                Slot::Dialing { generation, dial } => (*generation, dial.clone()),
                Slot::Empty => {
                    slot.dials = slot.dials.wrapping_add(1);
                    let generation = slot.dials;
                    let (dial_task, dial) = self.new_dial(generation);
                    slot.state = Slot::Dialing {
                        generation,
                        dial: dial.clone(),
                    };
                    task = Some(dial_task);
                    (generation, dial)
                }
            }
        };
        if let Some(task) = task {
            drop(tokio::spawn(task));
        }
        let connection = dial
            .await
            .map_err(|error| RedisError::Connect(error.to_string()))?;
        Ok(Lease {
            generation,
            connection,
            cached: false,
        })
    }

    /// Dial number `generation`, unspawned, and its shareable outcome. The
    /// task owns the [`DialSettlement`] from the start, so however it ends
    /// the slot is settled before any waiter sees the outcome.
    fn new_dial(
        self: &Arc<Self>,
        generation: u64,
    ) -> (impl Future<Output = ()> + Send + 'static, SharedDial) {
        let (waiters, outcome) = tokio::sync::oneshot::channel();
        let settlement = DialSettlement {
            shared: Arc::downgrade(self),
            generation,
            waiters: Some(waiters),
        };
        let client = self.client.clone();
        let config = self.config.clone();
        let task = async move {
            let outcome = client
                .get_multiplexed_async_connection_with_config(&config)
                .await;
            settlement.settle(outcome);
        };
        let dial = async move {
            outcome.await.unwrap_or_else(|_closed| {
                Err(redis::RedisError::from(std::io::Error::other(
                    "the dial task ended without an outcome (its runtime shut down, or it panicked)",
                )))
            })
        }
        .boxed()
        .shared();
        (task, dial)
    }

    /// Send `command` on `lease`'s connection and read its raw reply — a
    /// server error reply included, as a value: an `Err` here means NO valid
    /// reply was read. Every such failure discards the connection (if it is
    /// still the cached one; see [`SharedState::discard`]): a dead socket, a
    /// reply that missed the response timeout (it may never arrive, and the
    /// multiplexer matches replies to requests in order), and a malformed
    /// reply (the stream is no longer in step) all leave it untrustworthy.
    async fn send(
        &self,
        lease: &Lease,
        command: &redis::Cmd,
    ) -> Result<redis::Value, redis::RedisError> {
        let mut connection = lease.connection.clone();
        let result = connection.req_packed_command(command).await;
        if let Err(error) = &result {
            if self.discard(lease.generation) {
                tracing::debug!(%error, "dropped the cached Redis connection; the next command redials");
            }
        }
        result
    }

    /// Record how dial `generation` ended: `Dialing{g}` becomes `Ready{g}`, or
    /// `Empty` without a connection. Anything else is left alone.
    fn settle_dial(&self, generation: u64, connection: Option<&MultiplexedConnection>) {
        let replaced = {
            let mut slot = lock(&self.slot);
            if !matches!(slot.state, Slot::Dialing { generation: current, .. } if current == generation)
            {
                return;
            }
            let settled = match connection {
                Some(connection) => Slot::Ready {
                    generation,
                    connection: connection.clone(),
                },
                None => Slot::Empty,
            };
            std::mem::replace(&mut slot.state, settled)
        };
        drop(replaced);
    }

    /// Empty the slot if — and only if — it still caches the connection from
    /// dial `generation`. **The generation guard**: a call still holding an
    /// older connection can fail after another call has already replaced it,
    /// and that late failure must neither discard the newer connection nor
    /// abandon a dial in flight. `true` when it discarded something.
    fn discard(&self, generation: u64) -> bool {
        let replaced = {
            let mut slot = lock(&self.slot);
            if !matches!(slot.state, Slot::Ready { generation: current, .. } if current == generation)
            {
                return false;
            }
            std::mem::replace(&mut slot.state, Slot::Empty)
        };
        drop(replaced);
        true
    }
}

/// What a dial task owns so the slot is settled however the task ends:
/// [`DialSettlement::settle`] when it finishes, and `Drop` when it is dropped
/// unfinished (a runtime shutting down drops every task it still holds, and
/// Tokio drops a task whose poll panicked). Either way the slot is settled
/// BEFORE any waiter can see the outcome, so a waiter that receives a failure
/// knows the next call dials afresh rather than joining the dial that failed.
struct DialSettlement {
    /// [`Weak`], so a dial never keeps its handle alive, and a dial that
    /// outlives every clone of its handle has nothing left to settle. Taken
    /// by `settle`, so `Drop` does not settle twice.
    shared: Weak<SharedState>,
    generation: u64,
    /// The [`SharedDial`]'s other end; `None` once the outcome is sent.
    waiters: Option<tokio::sync::oneshot::Sender<DialOutcome>>,
}

impl DialSettlement {
    fn settle(mut self, outcome: DialOutcome) {
        if let Some(shared) = std::mem::take(&mut self.shared).upgrade() {
            shared.settle_dial(self.generation, outcome.as_ref().ok());
        }
        if let Some(waiters) = self.waiters.take() {
            // Refused only when nobody is listening any more: every waiter
            // has gone and the slot has let go of this dial.
            let _ = waiters.send(outcome);
        }
    }
}

impl Drop for DialSettlement {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            shared.settle_dial(self.generation, None);
        }
        // Closing the channel after the slot is emptied, so a waiter woken by
        // the close finds `Empty`.
        drop(self.waiters.take());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use redis::IntoConnectionInfo;

    use super::*;

    /// A loopback listener that accepts every connection, counts it, holds it
    /// open and never writes a byte: a "Redis" whose TCP connect succeeds
    /// and which then never answers anything.
    async fn silent_listener() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let address = listener.local_addr().expect("the bound address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(socket);
            }
        });
        (address, accepted)
    }

    /// Wait briefly for `accepted` to reach `expected`, then require exactly it.
    async fn await_accepts(accepted: &AtomicUsize, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while accepted.load(Ordering::SeqCst) < expected && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            expected,
            "one dial is one TCP connection"
        );
    }

    /// A listener that accepts and holds every connection, never writing a
    /// byte, until `release` is notified; then it closes them all, and closes
    /// every later connection as soon as it accepts it. A dial against it
    /// stays pending (redis-rs waits for its `CLIENT SETINFO` replies) for
    /// exactly as long as the test wants, then fails — no clock involved.
    async fn stalling_listener() -> (
        std::net::SocketAddr,
        Arc<AtomicUsize>,
        Arc<tokio::sync::Notify>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let address = listener.local_addr().expect("the bound address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let (counter, released) = (Arc::clone(&accepted), Arc::clone(&release));
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                tokio::select! {
                    Ok((socket, _)) = listener.accept() => {
                        counter.fetch_add(1, Ordering::SeqCst);
                        held.push(socket);
                    }
                    () = released.notified() => break,
                }
            }
            drop(held);
            while let Ok((socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(socket);
            }
        });
        (address, accepted, release)
    }

    /// A handle on `address` whose dials SUCCEED against [`silent_listener`]:
    /// RESP2, database 0, no password and `CLIENT SETINFO` skipped leave
    /// redis-rs's setup pipeline empty, so a TCP accept is a connection.
    fn handshake_free_handle(address: std::net::SocketAddr, options: RedisOptions) -> RedisHandle {
        let info = format!("redis://{address}/0")
            .into_connection_info()
            .expect("a loopback Redis URL");
        let settings = info.redis_settings().clone().set_skip_set_lib_name();
        let client = redis::Client::open(info.set_redis_settings(settings)).expect("a client");
        RedisHandle::from_client(client, options)
    }

    fn generation_of(handle: &RedisHandle) -> Option<u64> {
        match lock(&handle.shared.slot).state {
            Slot::Ready { generation, .. } => Some(generation),
            _ => None,
        }
    }

    #[test]
    fn the_default_timeouts_are_one_second_and_500_ms() {
        let options = RedisOptions::default();
        assert_eq!(options.dial_timeout, Duration::from_secs(1));
        assert_eq!(options.response_timeout, Duration::from_millis(500));
        let tuned = options
            .with_dial_timeout(Duration::from_millis(250))
            .with_response_timeout(Duration::from_millis(100));
        assert_eq!(tuned.dial_timeout, Duration::from_millis(250));
        assert_eq!(tuned.response_timeout, Duration::from_millis(100));
    }

    #[test]
    fn a_zero_timeout_is_refused() {
        for options in [
            RedisOptions::default().with_dial_timeout(Duration::ZERO),
            RedisOptions::default().with_response_timeout(Duration::ZERO),
        ] {
            let error = RedisHandle::open_with("redis://localhost:6379/0", options)
                .expect_err("a zero timeout fails every call");
            assert!(matches!(error, RedisError::InvalidArgument(_)), "{error:?}");
        }
    }

    /// Construction is a parse, not a dial: nothing listens on port 1, and a
    /// handle for it still opens, instantly, and starts with no connection.
    #[test]
    fn open_performs_no_io() {
        let started = Instant::now();
        let handle = RedisHandle::open("redis://127.0.0.1:1/0").expect("a well-formed URL");
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(format!("{handle:?}").contains(r#"connection: "none""#));
        assert_eq!(lock(&handle.shared.slot).dials, 0, "nothing dialled");
    }

    #[test]
    fn a_malformed_url_is_an_error_and_never_echoes_the_url() {
        for url in [
            "",
            "not a url",
            "http://:hunter2@localhost:6379/0",
            "redis://:hunter2@/0",
            "redis://:hunter2@localhost:6379/not-a-db",
            "redis://:hunter2@0.0.0.0:6379/0",
        ] {
            let error = RedisHandle::open(url).expect_err(url);
            assert!(
                matches!(error, RedisError::InvalidUrl(_)),
                "{url}: {error:?}"
            );
            for rendered in [error.to_string(), format!("{error:?}")] {
                assert!(!rendered.contains("hunter2"), "{url}: {rendered}");
                assert!(!rendered.contains("localhost"), "{url}: {rendered}");
            }
        }
    }

    /// The TLS feature is compiled in (without it `Client::open` refuses
    /// every `rediss://` URL), and an Upstash-shaped URL opens with no I/O.
    #[test]
    fn a_rediss_url_is_accepted() {
        RedisHandle::open("rediss://default:hunter2@example.upstash.io:6379")
            .expect("rediss:// needs redis's tokio-rustls-comp");
    }

    #[test]
    fn insecure_tls_is_refused() {
        let error = RedisHandle::open("rediss://:hunter2@localhost:6380/#insecure")
            .expect_err("#insecure skips certificate verification");
        assert!(matches!(error, RedisError::InvalidUrl(_)), "{error:?}");
        assert!(!error.to_string().contains("hunter2"), "{error}");
    }

    #[test]
    fn debug_never_prints_the_url() {
        let handle = RedisHandle::open("redis://default:hunter2@redis.internal.example:6390/3")
            .expect("a well-formed URL");
        let rendered = format!("{handle:?} {:?}", handle.clone());
        for secret in [
            "hunter2",
            "default",
            "redis.internal.example",
            "6390",
            "redis://",
        ] {
            assert!(!rendered.contains(secret), "{secret} in {rendered}");
        }
        assert!(rendered.contains("RedisHandle"), "{rendered}");
    }

    /// A refused dial (nothing on port 1) is [`RedisError::Connect`], and
    /// neither rendering carries the URL's password.
    #[tokio::test]
    async fn a_refused_dial_is_a_connect_error_without_the_password() {
        let handle = RedisHandle::open("redis://:hunter2@127.0.0.1:1/0").expect("a URL");
        let error = handle
            .fixed_window_hit("k", 60)
            .await
            .expect_err("nothing listens on port 1");
        assert!(matches!(error, RedisError::Connect(_)), "{error:?}");
        assert!(!error.is_outcome_unknown());
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(!rendered.contains("hunter2"), "{rendered}");
        }
        assert!(format!("{handle:?}").contains(r#"connection: "none""#));
    }

    /// A server that completes the TCP handshake and then never answers
    /// redis-rs's setup pipeline: the dial timeout ends the wait.
    #[tokio::test]
    async fn a_dial_that_never_completes_times_out() {
        let (address, accepted) = silent_listener().await;
        let options = RedisOptions::default().with_dial_timeout(Duration::from_millis(200));
        let handle = RedisHandle::open_with(&format!("redis://{address}/0"), options).unwrap();

        let started = Instant::now();
        let error = handle.get("k").await.expect_err("the server never answers");
        let elapsed = started.elapsed();

        assert!(matches!(error, RedisError::Connect(_)), "{error:?}");
        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        await_accepts(&accepted, 1).await;
    }

    /// TEST-NET-1 (RFC 5737) is never routed: the connect either black-holes
    /// (and the dial timeout ends it) or fails at once — never longer.
    #[tokio::test]
    async fn a_black_hole_dial_is_bounded_by_the_dial_timeout() {
        let options = RedisOptions::default().with_dial_timeout(Duration::from_millis(200));
        let handle = RedisHandle::open_with("redis://192.0.2.1:6379/0", options).unwrap();

        let started = Instant::now();
        let error = handle
            .fixed_window_hit("k", 60)
            .await
            .expect_err("TEST-NET-1 is unroutable");

        assert!(matches!(error, RedisError::Connect(_)), "{error:?}");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }

    /// Single flight, failing: sixteen first calls made while the one dial
    /// is pending all join it — one dial, one TCP connection — and when it
    /// fails, every one of them gets the error. The next call after the
    /// failure dials afresh: a failure is not cached.
    ///
    /// Deterministic, not timed. On this single-threaded runtime the dial is
    /// a spawned task that cannot run until the test yields, so each call,
    /// polled once, is provably waiting on it (the shared dial's strong count
    /// is the slot's plus one per caller); and the dial then fails only when
    /// the test releases the listener, under a dial timeout no run reaches.
    #[tokio::test]
    async fn concurrent_first_calls_share_one_failed_dial() {
        let (address, accepted, release) = stalling_listener().await;
        let options = RedisOptions::default().with_dial_timeout(Duration::from_secs(30));
        let handle = RedisHandle::open_with(&format!("redis://{address}/0"), options).unwrap();

        let keys: Vec<String> = (0..16).map(|i| format!("k{i}")).collect();
        let mut calls: Vec<_> = keys
            .iter()
            .map(|key| Box::pin(handle.fixed_window_hit(key, 60)))
            .collect();
        for call in &mut calls {
            assert!(futures::poll!(call).is_pending(), "waiting on the dial");
        }
        let waiting = match &lock(&handle.shared.slot).state {
            Slot::Dialing { dial, .. } => dial.strong_count(),
            _ => panic!("the first call started a dial"),
        };
        assert_eq!(
            waiting,
            Some(1 + 16),
            "the slot and every caller hold the one dial"
        );
        assert_eq!(lock(&handle.shared.slot).dials, 1);
        await_accepts(&accepted, 1).await;

        release.notify_one();
        for result in futures::future::join_all(calls).await {
            let error = result.expect_err("the dial failed");
            assert!(matches!(error, RedisError::Connect(_)), "{error:?}");
        }
        assert_eq!(
            lock(&handle.shared.slot).dials,
            1,
            "one dial for sixteen callers"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 1);

        let _ = handle
            .get("k")
            .await
            .expect_err("the listener now closes at once");
        await_accepts(&accepted, 2).await;
        assert_eq!(lock(&handle.shared.slot).dials, 2);
    }

    /// A window or TTL outside `1..=MAX_TTL_SECS` is refused before anything
    /// is dialled or sent — above the bound, a refused `EXPIRE` would run
    /// after the script's `INCR` and leave the counter without a TTL.
    #[tokio::test]
    async fn an_out_of_range_window_or_ttl_is_refused_without_io() {
        let (address, accepted) = silent_listener().await;
        let handle = RedisHandle::open(&format!("redis://{address}/0")).unwrap();

        for secs in [0, crate::MAX_TTL_SECS + 1, i64::MAX as u64, u64::MAX] {
            let error = handle
                .fixed_window_hit("k", secs)
                .await
                .expect_err("window");
            assert!(
                matches!(error, RedisError::InvalidArgument(_)),
                "{secs}: {error:?}"
            );
            let error = handle.set_ex("k", "v", secs).await.expect_err("ttl");
            assert!(
                matches!(error, RedisError::InvalidArgument(_)),
                "{secs}: {error:?}"
            );
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 0, "nothing was dialled");
    }

    /// **The generation guard, with a real stale failure.** A command sent
    /// on generation 1 is still waiting for its reply when generation 1 is
    /// reported dead and generation 2 is dialled; when that old command
    /// finally fails (its response timeout), it reports generation 1 — and
    /// generation 2 must stay cached, with no third dial.
    #[tokio::test]
    async fn a_stale_failure_does_not_discard_a_newer_connection() {
        let (address, accepted) = silent_listener().await;
        let options = RedisOptions::default().with_response_timeout(Duration::from_millis(200));
        let handle = handshake_free_handle(address, options);
        let shared = Arc::clone(&handle.shared);

        let first = shared.lease().await.expect("dial 1");
        assert_eq!((first.generation, first.cached), (1, false));
        await_accepts(&accepted, 1).await;

        // The old command: on the wire on generation 1, never answered.
        let old_command = {
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                let mut ping = redis::cmd("PING");
                ping.arg("old");
                shared.send(&first, &ping).await
            })
        };

        // Meanwhile generation 1 is reported dead, and generation 2 is made.
        assert!(shared.discard(1), "generation 1 was the cached connection");
        let second = shared.lease().await.expect("dial 2");
        assert_eq!((second.generation, second.cached), (2, false));
        await_accepts(&accepted, 2).await;

        // Now the old command's failure lands.
        let error = old_command
            .await
            .expect("the task")
            .expect_err("nobody ever answers");
        assert!(error.is_io_error(), "a response timeout: {error}");

        assert_eq!(
            generation_of(&handle),
            Some(2),
            "a stale failure discarded the newer connection"
        );
        let third = shared.lease().await.expect("the cached connection");
        assert_eq!((third.generation, third.cached), (2, true));
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "and nothing redialled");

        // A failure on the CURRENT generation does reset it.
        assert!(shared.discard(2));
        assert_eq!(generation_of(&handle), None);
    }

    /// A caller that gives up mid-dial does not take the dial with it: the
    /// spawned task finishes, settles the slot, and the next caller is handed
    /// the cached connection without a second dial.
    #[tokio::test]
    async fn a_dial_outlives_a_cancelled_caller() {
        let (address, accepted) = silent_listener().await;
        let handle = handshake_free_handle(address, RedisOptions::default());

        // Poll the call once — which starts the dial, a spawned task this
        // single-threaded runtime has not run yet — and give up on it.
        let mut call = Box::pin(handle.get("k"));
        assert!(
            futures::poll!(&mut call).is_pending(),
            "waiting on its dial"
        );
        drop(call);
        let rendered = format!("{handle:?}");
        assert!(rendered.contains(r#"connection: "dialing""#), "{rendered}");

        let deadline = Instant::now() + Duration::from_secs(2);
        while generation_of(&handle).is_none() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            generation_of(&handle),
            Some(1),
            "the dial settled the slot itself"
        );

        let lease = handle.shared.lease().await.expect("the cached connection");
        assert_eq!((lease.generation, lease.cached), (1, true));
        assert_eq!(lock(&handle.shared.slot).dials, 1, "one dial in all");
        await_accepts(&accepted, 1).await;
    }

    /// After a well-formed reply, every failure is `Command`: the value is
    /// not what the caller asked for, but Redis answered. (A server error
    /// reply reaches `decode` the same way, as a `Value::ServerError`; the
    /// live suite drives that one, as no public constructor builds it.)
    #[test]
    fn a_well_formed_reply_of_the_wrong_type_is_a_command_error() {
        let error = decode::<u64>(redis::Value::BulkString(b"not a number".to_vec()))
            .expect_err("text is not a count");
        assert!(matches!(error, RedisError::Command(_)), "{error:?}");
        assert!(!error.is_outcome_unknown());

        let error = decode::<Option<String>>(redis::Value::BulkString(vec![0xff, 0xfe]))
            .expect_err("not UTF-8");
        assert!(matches!(error, RedisError::Command(_)), "{error:?}");

        assert_eq!(decode::<u64>(redis::Value::Int(7)).unwrap(), 7);
        assert_eq!(decode::<Option<String>>(redis::Value::Nil).unwrap(), None);
    }
}
