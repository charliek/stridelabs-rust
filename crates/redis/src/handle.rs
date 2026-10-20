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
/// to) bound the worst case of one call: a fixed-window hit (or an `eval`
/// under [`Replay::Never`]) takes at most a dial plus one response timeout
/// (1.5 s), and an idempotent `GET` / `SET EX` / `PING` (or an `eval` under
/// [`Replay::OnceOnFreshConnection`]) that is retried after a cached
/// connection died at most one response timeout, a dial and another
/// response timeout (2 s).
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

/// Whether a command that got no valid reply may be sent again, once, on a
/// fresh connection.
///
/// Every built-in command fixes its own ([`RedisHandle::fixed_window_hit`]
/// `Never`; [`RedisHandle::get`], [`RedisHandle::set_ex`] and
/// [`RedisHandle::ping`] `OnceOnFreshConnection`); [`RedisHandle::eval`]
/// runs a script only its caller understands, so the caller chooses — see
/// the crate docs' replay policy. There is deliberately no `Default`: the
/// question is whether running the command twice is harmless, and only the
/// code that wrote the command can answer it. When in doubt, `Never`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Replay {
    /// Sent **at most once**. When no valid reply is read the caller gets
    /// [`RedisError::Io`] — the command may or may not have run, and may
    /// still run later — and nothing is sent again. That outcome stays
    /// unknown: a later read shows the current state, not what became of
    /// this attempt, so it is no reason to resend; act as if the command
    /// may have run. For anything a second run would change: an `INCR`, a
    /// lease acquire or takeover, **any script that writes**.
    Never,
    /// Sent once more, on a fresh connection, after an I/O-level failure (a
    /// dead socket, a reply that missed the response timeout) on a
    /// connection that was **already cached** — the kind that can go stale
    /// while idle — and in no other case: a connection the call dialled
    /// itself is never retried on, a malformed reply earns no retry, and an
    /// error Redis answered ([`RedisError::Command`]) is final.
    ///
    /// **A command whose reply was lost after it ran IS sent again.** The
    /// handle cannot tell a request that never arrived from a reply that
    /// never came back, so the first attempt may well have executed — and
    /// can even land after the retry — and other clients' commands can run
    /// between the two. Only for a command whose second execution is
    /// harmless under all of that: a read, or a write that is idempotent in
    /// its value AND its TTL effects on a key no other writer races (a
    /// replayed `SET … PX` restarts the TTL; a replayed lease claim
    /// overwrites a holder that took the lease in between). The caller gets
    /// the retry's reply, which can differ from what the first attempt
    /// answered.
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

/// A dial's outcome, its failure already [`RedisError::Connect`]: made where
/// the dial ends, so redis-rs's text — a refused handshake echoes the
/// `AUTH`/`HELLO` it was sent — never travels further than that.
type DialOutcome = Result<MultiplexedConnection, RedisError>;

/// One dial's outcome, awaitable by every caller that joined it. Both halves
/// of [`DialOutcome`] are `Clone` (a multiplexed connection is a handle to one
/// socket; [`RedisError`] derives `Clone`), which [`Shared`] requires. It
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
///
/// Every `Command` error any command produces is made here or by a shape
/// check after it, so this is where the server's text — which can quote the
/// command's keys, arguments and script — is dropped for a fixed summary
/// (see [`crate::error`]).
fn decode<T: redis::FromRedisValue>(reply: redis::Value) -> Result<T, RedisError> {
    let reply = reply
        .extract_error()
        .map_err(|error| RedisError::error_reply(&error))?;
    T::from_redis_value(reply).map_err(|error| RedisError::unconvertible(&error))
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
        let client = redis::Client::open(url).map_err(|error| RedisError::invalid_url(&error))?;
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
            error = %crate::error::describe(&error),
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
        let connection = dial.await?;
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
                .await
                .map_err(|error| RedisError::connect(&error));
            settlement.settle(outcome);
        };
        let dial = async move {
            outcome.await.unwrap_or_else(|_closed| {
                Err(RedisError::Connect(
                    "the dial task ended without an outcome (its runtime shut down, or it panicked)"
                        .to_owned(),
                ))
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
                tracing::debug!(
                    error = %crate::error::describe(error),
                    "dropped the cached Redis connection; the next command redials"
                );
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
        setinfo_free_handle(&format!("redis://{address}/0"), options)
    }

    /// A handle on `url` with `CLIENT SETINFO` skipped, so its setup
    /// pipeline is exactly what the URL asks for: `HELLO 3 AUTH …` for
    /// `?protocol=resp3` with credentials, `AUTH …` for credentials alone,
    /// `SELECT n` for a database other than 0 — one command, one reply.
    fn setinfo_free_handle(url: &str, options: RedisOptions) -> RedisHandle {
        let info = url.into_connection_info().expect("a loopback Redis URL");
        let settings = info.redis_settings().clone().set_skip_set_lib_name();
        let client = redis::Client::open(info.set_redis_settings(settings)).expect("a client");
        RedisHandle::from_client(client, options)
    }

    /// `error` rendered every way a consumer could: `Display`, `Debug` (plain
    /// and alternate) and the payload itself, plain and quoted — none may
    /// contain `canary`.
    fn assert_canary_nowhere(error: &RedisError, canary: &str) {
        let payload = match error {
            RedisError::InvalidUrl(payload)
            | RedisError::Connect(payload)
            | RedisError::Io(payload)
            | RedisError::Command(payload) => payload.clone(),
            RedisError::InvalidArgument(reason) => (*reason).to_owned(),
        };
        for rendered in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
            format!("{payload:?}"),
            payload,
        ] {
            assert!(!rendered.contains(canary), "{canary} in {rendered}");
        }
    }

    /// Every request a [`scripted_listener`] has read, as its words.
    type Heard = Arc<Mutex<Vec<Vec<String>>>>;

    /// A loopback "Redis" that reads whole requests (arrays of bulk
    /// strings, all redis-rs sends), records each, and answers it with
    /// `answer(words)` — a server that can accept one command and refuse
    /// the next.
    async fn scripted_listener(answer: fn(&[String]) -> String) -> (std::net::SocketAddr, Heard) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let address = listener.local_addr().expect("the bound address");
        let heard = Heard::default();
        let recorded = Arc::clone(&heard);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let mut buffered = Vec::new();
                    let mut chunk = vec![0_u8; 64 * 1024];
                    while let Ok(read) = socket.read(&mut chunk).await {
                        if read == 0 {
                            return;
                        }
                        buffered.extend_from_slice(&chunk[..read]);
                        while let Some((words, length)) = parse_request(&buffered) {
                            buffered.drain(..length);
                            let reply = answer(&words);
                            lock_heard(&recorded).push(words);
                            if socket.write_all(reply.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        (address, heard)
    }

    fn lock_heard(heard: &Mutex<Vec<Vec<String>>>) -> MutexGuard<'_, Vec<Vec<String>>> {
        heard.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The words of the whole request at the start of `buffer`, and its
    /// length — or `None` until all of it has arrived.
    fn parse_request(buffer: &[u8]) -> Option<(Vec<String>, usize)> {
        fn line(buffer: &[u8], at: usize, kind: u8) -> Option<(usize, usize)> {
            let rest = buffer.get(at..)?;
            let end = rest.windows(2).position(|window| window == b"\r\n")?;
            assert_eq!(rest[0], kind, "redis-rs sends arrays of bulk strings");
            let number = std::str::from_utf8(&rest[1..end]).ok()?.parse().ok()?;
            Some((number, at + end + 2))
        }
        let (count, mut at) = line(buffer, 0, b'*')?;
        let mut words = Vec::with_capacity(count);
        for _ in 0..count {
            let (length, data) = line(buffer, at, b'$')?;
            at = data + length + 2;
            let word = buffer.get(data..data + length)?;
            words.push(String::from_utf8_lossy(word).into_owned());
            if buffer.len() < at {
                return None;
            }
        }
        Some((words, at))
    }

    /// A loopback "Redis" that answers every request it reads with `reply`,
    /// verbatim, whatever the request was. Against [`handshake_free_handle`]
    /// the dial sends nothing, so each read is one command — and each
    /// command gets exactly `reply`.
    async fn answering_listener(reply: Vec<u8>) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let address = listener.local_addr().expect("the bound address");
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut request = vec![0_u8; 64 * 1024];
                    while let Ok(read) = socket.read(&mut request).await {
                        if read == 0 || socket.write_all(&reply).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        address
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
    /// reply reaches `decode` the same way, as a `Value::ServerError`;
    /// `no_command_error_shows_the_servers_text` and the live suite drive
    /// that one through a server.)
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

    /// `PING` against a port nothing listens on is [`RedisError::Connect`]
    /// (never sent), well inside the dial timeout: a refused connect is
    /// reported, not waited out.
    #[tokio::test]
    async fn ping_against_a_closed_port_fails_within_the_dial_timeout() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("a loopback port, closed again when its listener drops");
        let options = RedisOptions::default().with_dial_timeout(Duration::from_secs(2));
        let handle = RedisHandle::open_with(&format!("redis://{closed}/0"), options).unwrap();

        let started = Instant::now();
        let error = handle.ping().await.expect_err("nothing listens there");
        let elapsed = started.elapsed();

        assert!(matches!(error, RedisError::Connect(_)), "{error:?}");
        assert!(!error.is_outcome_unknown());
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        assert!(format!("{handle:?}").contains(r#"connection: "none""#));
    }

    /// A server that accepts and never answers: `PING`'s dial ends at the
    /// dial timeout.
    #[tokio::test]
    async fn ping_is_bounded_by_the_dial_timeout() {
        let (address, accepted) = silent_listener().await;
        let options = RedisOptions::default().with_dial_timeout(Duration::from_millis(200));
        let handle = RedisHandle::open_with(&format!("redis://{address}/0"), options).unwrap();

        let started = Instant::now();
        let error = handle.ping().await.expect_err("the server never answers");
        let elapsed = started.elapsed();

        assert!(matches!(error, RedisError::Connect(_)), "{error:?}");
        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        await_accepts(&accepted, 1).await;
    }

    /// Connected, `PING` waits for its reply no longer than the response
    /// timeout. The connection was dialled by this call, so the failure
    /// earns no retry: one dial, one wait, and an outcome-unknown `Io`.
    #[tokio::test]
    async fn ping_is_bounded_by_the_response_timeout() {
        let (address, accepted) = silent_listener().await;
        let options = RedisOptions::default().with_response_timeout(Duration::from_millis(200));
        let handle = handshake_free_handle(address, options);

        let started = Instant::now();
        let error = handle.ping().await.expect_err("PING is never answered");
        let elapsed = started.elapsed();

        assert!(matches!(error, RedisError::Io(_)), "{error:?}");
        assert!(error.is_outcome_unknown());
        assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        assert_eq!(lock(&handle.shared.slot).dials, 1, "not retried");
        await_accepts(&accepted, 1).await;
    }

    /// `PING` is `Ok(())` only on the `PONG` status. Any other well-formed
    /// answer — another status, `PONG` as a bulk string, a number, an error
    /// reply — is a `Command` error (Redis answered), and the connection it
    /// came over stays cached.
    #[tokio::test]
    async fn ping_is_ok_only_on_a_pong_status() {
        let address = answering_listener(b"+PONG\r\n".to_vec()).await;
        let handle = handshake_free_handle(address, RedisOptions::default());
        handle.ping().await.expect("the PONG status");

        for (reply, expected) in [
            (
                &b"+NOTPONG\r\n"[..],
                "PING was answered with a status, not PONG",
            ),
            (
                b"$4\r\nPONG\r\n",
                "PING was answered with a string, not PONG",
            ),
            (b":1\r\n", "PING was answered with an integer, not PONG"),
            (
                b"-LOADING Redis is loading\r\n",
                "the server answered LOADING",
            ),
        ] {
            let address = answering_listener(reply.to_vec()).await;
            let handle = handshake_free_handle(address, RedisOptions::default());
            let error = handle.ping().await.expect_err(expected);
            assert!(matches!(error, RedisError::Command(_)), "{error:?}");
            assert!(error.to_string().contains(expected), "{error}");
            assert_eq!(generation_of(&handle), Some(1), "{expected}: still cached");
        }
    }

    /// **No command's error carries the server's text.** Every `Command`
    /// error comes through `decode`, so an error reply quoting what it was
    /// sent (Redis's `unknown command … with args beginning with:`), one
    /// whose code a script chose, and a value redis-rs's conversion quotes
    /// are all summarised — in `Display`, `Debug` and the payload alike, for
    /// `eval`, the fixed window, `GET`, `SET EX` and `PING`.
    #[tokio::test]
    async fn no_command_error_carries_the_servers_text() {
        const CANARY: &str = "user_01CANARYVALUE";

        fn assert_withheld(error: &RedisError, summary: &str) {
            assert!(matches!(error, RedisError::Command(_)), "{error:?}");
            assert_canary_nowhere(error, CANARY);
            assert!(error.to_string().contains(summary), "{summary}: {error}");
        }

        let error_replies = [
            (
                format!(
                    "-ERR unknown command 'EVAL', with args beginning with: 'return 1' '1' '{CANARY}'\r\n"
                ),
                "the server answered ERR",
            ),
            (
                format!("-{CANARY} raised by a script\r\n"),
                "whose code Redis does not define",
            ),
        ];
        for (reply, summary) in error_replies {
            let address = answering_listener(reply.into_bytes()).await;
            let handle = handshake_free_handle(address, RedisOptions::default());
            let errors = [
                handle
                    .eval::<i64>("return 1", &["k"], &["a".into()], Replay::Never)
                    .await
                    .map(drop),
                handle.fixed_window_hit("k", 60).await.map(drop),
                handle.get("k").await.map(drop),
                handle.set_ex("k", "v", 60).await.map(drop),
                handle.ping().await,
            ];
            for error in errors {
                assert_withheld(&error.expect_err("an error reply"), summary);
            }
            assert_eq!(generation_of(&handle), Some(1), "error replies keep it");
        }

        let address =
            answering_listener(format!("${}\r\n{CANARY}\r\n", CANARY.len()).into_bytes()).await;
        let handle = handshake_free_handle(address, RedisOptions::default());
        let error = handle
            .fixed_window_hit("k", 60)
            .await
            .expect_err("text is not a count");
        assert_withheld(&error, "incompatible type");
    }

    /// **A refused handshake never carries what the dial sent.** A server
    /// that does not know `HELLO` (or `AUTH`) echoes it — credentials
    /// included — and a refused `SELECT` comes back with the server's
    /// detail; each dial fails as `Connect` naming only the class.
    #[tokio::test]
    async fn a_refused_handshake_never_carries_the_credentials() {
        const CANARY: &str = "CANARYPASSWORD";

        let cases = [
            (
                "alice:CANARYPASSWORD@",
                "/0?protocol=resp3",
                format!("-ERR unknown command 'HELLO', with args beginning with: '3' 'AUTH' 'alice' '{CANARY}' \r\n"),
                "the server answered ERR",
            ),
            (
                "alice:CANARYPASSWORD@",
                "/0",
                format!("-ERR unknown command 'AUTH', with args beginning with: 'alice' '{CANARY}' \r\n"),
                "authentication failed",
            ),
            (
                "",
                "/7",
                format!("-ERR {CANARY}\r\n"),
                "the server answered ERR",
            ),
        ];
        for (userinfo, path, reply, summary) in cases {
            let address = answering_listener(reply.into_bytes()).await;
            let handle = setinfo_free_handle(
                &format!("redis://{userinfo}{address}{path}"),
                RedisOptions::default(),
            );
            let error = handle.ping().await.expect_err("the handshake is refused");
            assert!(matches!(error, RedisError::Connect(_)), "{path}: {error:?}");
            assert_canary_nowhere(&error, CANARY);
            assert!(error.to_string().contains(summary), "{path}: {error}");
            assert_eq!(generation_of(&handle), None, "nothing cached");
        }
    }

    /// **A `SELECT` refused after a SUCCESSFUL authentication carries
    /// neither the credentials nor its argument.** The URL carries a canary
    /// user and password and a canary database; the scripted server accepts
    /// `AUTH` (RESP2) or `HELLO 3 AUTH` (RESP3), then answers `SELECT` with
    /// Redis's unknown-command diagnostic, which echoes the database it was
    /// sent. The dial fails as `Connect` naming only the class.
    #[tokio::test]
    async fn a_select_refused_after_authentication_carries_no_credentials() {
        const USER: &str = "CANARYUSER";
        const PASSWORD: &str = "CANARYPASSWORD";
        const DATABASE: &str = "7346";

        fn answer(words: &[String]) -> String {
            match words[0].as_str() {
                "AUTH" => "+OK\r\n".to_owned(),
                "HELLO" => "%1\r\n$6\r\nserver\r\n$5\r\nredis\r\n".to_owned(),
                "SELECT" => format!(
                    "-ERR unknown command 'SELECT', with args beginning with: '{}' \r\n",
                    words[1]
                ),
                other => panic!("the handshake sent {other}"),
            }
        }

        let credentials = |hello: &[&str]| -> Vec<Vec<String>> {
            let select = vec!["SELECT".to_owned(), DATABASE.to_owned()];
            let auth = hello.iter().map(|word| (*word).to_owned()).collect();
            vec![auth, select]
        };
        for (query, expected) in [
            ("", credentials(&["AUTH", USER, PASSWORD])),
            (
                "?protocol=resp3",
                credentials(&["HELLO", "3", "AUTH", USER, PASSWORD]),
            ),
        ] {
            let (address, heard) = scripted_listener(answer).await;
            let handle = setinfo_free_handle(
                &format!("redis://{USER}:{PASSWORD}@{address}/{DATABASE}{query}"),
                RedisOptions::default(),
            );
            let error = handle.ping().await.expect_err("SELECT is refused");
            assert!(
                matches!(error, RedisError::Connect(_)),
                "{query}: {error:?}"
            );
            for canary in [USER, PASSWORD, DATABASE] {
                assert_canary_nowhere(&error, canary);
            }
            assert!(
                error.to_string().contains("the server answered ERR"),
                "{query}: {error}"
            );
            assert_eq!(
                *lock_heard(&heard),
                expected,
                "{query}: authenticated with the canaries, then refused SELECT"
            );
            assert_eq!(generation_of(&handle), None, "nothing cached");
        }
    }

    /// A URL redis-rs refuses names the check that failed, from a fixed
    /// list — never the URL: its "Invalid protocol version" appends the
    /// URL's own `protocol` value.
    #[test]
    fn a_url_refusal_names_the_check_never_the_url() {
        const CANARY: &str = "CANARYQUERY";

        for (url, check) in [
            (
                format!("redis://localhost:6379/0?protocol={CANARY}"),
                "Invalid protocol version",
            ),
            (
                format!("redis://:{CANARY}@localhost:6379/{CANARY}"),
                "Invalid database number",
            ),
            (format!("{CANARY}://localhost"), "Redis URL did not parse"),
        ] {
            let error = RedisHandle::open(&url).expect_err(&url);
            assert!(matches!(error, RedisError::InvalidUrl(_)), "{error:?}");
            assert_canary_nowhere(&error, CANARY);
            assert_eq!(error.to_string(), format!("invalid Redis URL: {check}"));
        }
    }

    /// `eval` runs under the caller's [`Replay`]. Its connection is a CACHED
    /// one whose reply never comes (the response timeout ends each wait):
    /// `Never` gives up after that one attempt, with no second dial;
    /// `OnceOnFreshConnection` dials once more and sends it again (and that
    /// is never answered either). The live suite shows the same against a
    /// real Redis, and what each choice does to a script's effects.
    #[tokio::test]
    async fn eval_runs_under_the_callers_replay() {
        for (replay, dials) in [(Replay::Never, 1), (Replay::OnceOnFreshConnection, 2)] {
            let (address, accepted) = silent_listener().await;
            let options = RedisOptions::default().with_response_timeout(Duration::from_millis(100));
            let handle = handshake_free_handle(address, options);
            let lease = handle.shared.lease().await.expect("a handshake-free dial");
            assert_eq!((lease.generation, lease.cached), (1, false));
            drop(lease);

            let error = handle
                .eval::<i64>("return 1", &[], &[], replay)
                .await
                .expect_err("never answered");

            assert!(matches!(error, RedisError::Io(_)), "{replay:?}: {error:?}");
            assert_eq!(lock(&handle.shared.slot).dials, dials, "{replay:?}");
            await_accepts(&accepted, usize::try_from(dials).unwrap()).await;
        }
    }
}
