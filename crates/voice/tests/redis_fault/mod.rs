//! A TCP relay between a stridelabs-redis `RedisHandle` under test and the
//! test Redis that can fail the connection the handle has CACHED, lose a
//! reply after its command ran, or hold new connections back — the
//! instrument for every replay test: a `fixed_window_hit` or an
//! `eval(.., Replay::Never)` must run at most once, and an
//! `eval(.., Replay::OnceOnFreshConnection)` at most twice (plan 015 C-5;
//! first built for the connection slot the handle replaced, plan 011 §3.7).
//!
//! Lives at `tests/redis_fault/mod.rs`, not `tests/redis_fault.rs`: a file one
//! level deeper is never its own test binary, only a module of whichever
//! binary declares it — `tests/budget.rs` (the charge's lost-answer replay)
//! and `tests/lease.rs` (the ticket's, the acquire's and the meter's).
//!
//! Copied from tapper (`tapper-rs/tests/redis_fault/mod.rs` at `82be95f`),
//! which keeps its own copy for its turn limiter; only these lines and the
//! name of the URL's variable in two messages differ.
//!
//! **Why a relay and not `CLIENT KILL`.** `CLIENT KILL` is server-wide — it has
//! no database filter — so it would also kill every parallel test's
//! connection in this binary and the dev stack's. The relay's faults reach
//! only the connections that pass through it, and only the handle under test
//! is pointed at it.
//!
//! What it does to the connections it carries:
//!
//! - [`RedisRelay::sever`] closes every connection open right now, the way an
//!   idle timeout or a Cloud Run reset does: the next command on one fails at
//!   once.
//! - [`RedisRelay::blackhole`] silences every connection open right now, both
//!   ways, and leaves it open — a path that drops packets: the next command on
//!   one times out.
//! - [`RedisRelay::arm`] queues an [`EvalFault`] for the next `EVAL` any
//!   connection carries — faults apply in the order they were armed.
//! - [`RedisRelay::gate`] holds every NEW connection (accepted, nothing
//!   relayed) until [`RedisRelay::open_gate`] — a redial in flight.
//! - It counts the connections it accepted (one per dial) and the `EVAL`s it
//!   carried (`fixed_window_hit` is an `EVAL` too).
//!
//! It frames both directions into whole RESP2 commands and answers. What
//! happens to a command is decided as soon as its NAME has arrived — so
//! faults follow the order commands were sent — but only a WHOLE command is
//! ever delivered, held or released, however TCP splits it; and each answer
//! is matched to its command. So the test Redis must speak plain `redis://`
//! with RESP2; a `rediss://` or RESP3 URL is refused loudly.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::join_all;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};

/// The longest a fault-injection test may run. Each drives real sockets
/// through a failure, and a socket that stalls without closing would
/// otherwise hang the suite instead of failing it.
pub const FAULT_TEST_DEADLINE: Duration = Duration::from_secs(30);

/// Run `body` — a test's whole body, polling included — under
/// [`FAULT_TEST_DEADLINE`], failing loudly if it runs over.
pub async fn within_deadline(test: &str, body: impl std::future::Future<Output = ()>) {
    if tokio::time::timeout(FAULT_TEST_DEADLINE, body)
        .await
        .is_err()
    {
        panic!("{test} did not finish within {FAULT_TEST_DEADLINE:?}: a socket stalled");
    }
}

/// What the relay does to the next `EVAL` a connection carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalFault {
    /// Deliver the `EVAL` — so it runs — and swallow its answer and every
    /// byte Redis sends on that connection after it, leaving the connection
    /// open. The client gives up after its response timeout.
    LoseAnswer,
    /// Deliver the `EVAL`, read its answer — so it has run — and close both
    /// sockets without passing the answer on. The client sees its connection
    /// die mid-command.
    LoseAnswerAndClose,
    /// Deliver neither the `EVAL` nor anything after it on that connection
    /// until [`RedisRelay::release_held`]. The client gives up after its
    /// response timeout; the server side stays open so the `EVAL` can still
    /// land LATE, when the test says.
    Hold,
    /// Deliver the `EVAL` and pass its answer on, but only this long after
    /// Redis sent it: a slow round trip that still succeeds (it must stay
    /// under the client's response timeout).
    DelayAnswer(Duration),
}

/// A relay to the test Redis. Dropping it closes every connection it holds.
pub struct RedisRelay {
    /// The URL the handle under test opens: the test Redis's own — database
    /// number and credentials included — with the relay's address in place
    /// of the server's.
    pub url: String,
    shared: Arc<Shared>,
    accepting: tokio::task::JoinHandle<()>,
}

/// What the relay's tasks share.
#[derive(Default)]
struct Shared {
    accepted: AtomicUsize,
    evals: AtomicUsize,
    holding: AtomicUsize,
    /// How many of the `holding` connections have been released.
    released: AtomicUsize,
    armed: Mutex<VecDeque<EvalFault>>,
    /// One control channel per connection accepted.
    connections: Mutex<Vec<mpsc::UnboundedSender<Control>>>,
    /// `true` while new connections are held at the gate; it starts open
    /// (`false`, the default).
    gate: watch::Sender<bool>,
}

/// What a test can ask of one connection's task.
enum Control {
    /// Close both sockets; the sender is dropped once they are closed.
    Sever(oneshot::Sender<()>),
    /// Stop relaying in both directions, and acknowledge.
    Blackhole(oneshot::Sender<()>),
    /// Deliver what is held, and answer `true` once Redis has answered every
    /// command in it (the held `EVAL` has run) — a held command still
    /// arriving is delivered once whole, and waited for too — or `false` at
    /// once if nothing was held.
    Release(oneshot::Sender<bool>),
}

impl RedisRelay {
    /// Start a relay to `upstream_url`, the test Redis.
    pub async fn start(upstream_url: &str) -> RedisRelay {
        let mut url = redis::parse_redis_url(upstream_url)
            .filter(|url| url.scheme() == "redis")
            .filter(|url| {
                url.query_pairs()
                    .all(|(name, value)| name != "protocol" || matches!(&*value, "2" | "resp2"))
            })
            .unwrap_or_else(|| {
                panic!(
                    "the Redis fault relay reads the command stream to find EVAL, and \
                     frames RESP2 to match each answer to its command, so \
                     REDIS_URL must be a plain redis:// URL speaking RESP2 (TLS \
                     would hide the commands; RESP3 answers are not framed)"
                )
            });
        let upstream = format!(
            "{}:{}",
            url.host_str().expect("REDIS_URL names a host"),
            url.port().unwrap_or(6379)
        );

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a relay port");
        let address = listener.local_addr().expect("the relay's address");
        // Everything else — credentials, database number — carries over.
        url.set_ip_host(address.ip())
            .expect("an IP address is a valid redis:// host");
        url.set_port(Some(address.port()))
            .expect("a redis:// URL takes a port");

        let shared = Arc::new(Shared::default());
        let accepting = tokio::spawn({
            let shared = Arc::clone(&shared);
            async move {
                while let Ok((client, _)) = listener.accept().await {
                    let (control, inbox) = mpsc::unbounded_channel();
                    shared.connections.lock().expect("registry").push(control);
                    shared.accepted.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(relay_one(
                        client,
                        upstream.clone(),
                        Arc::clone(&shared),
                        inbox,
                    ));
                }
            }
        });
        RedisRelay {
            url: url.into(),
            shared,
            accepting,
        }
    }

    /// How many connections the relay has accepted — one per dial.
    pub fn accepted(&self) -> usize {
        self.shared.accepted.load(Ordering::SeqCst)
    }

    /// How many `EVAL`s the handle has sent through the relay — delivered,
    /// held or swallowed alike.
    pub fn evals(&self) -> usize {
        self.shared.evals.load(Ordering::SeqCst)
    }

    /// How many connections have started holding an `EVAL` back
    /// ([`EvalFault::Hold`]) — from the moment its name arrived, which may
    /// be before the rest of it has.
    pub fn holding(&self) -> usize {
        self.shared.holding.load(Ordering::SeqCst)
    }

    /// Apply `fault` to the next `EVAL` no earlier fault is waiting for.
    pub fn arm(&self, fault: EvalFault) {
        self.shared.armed.lock().expect("armed").push_back(fault);
    }

    /// Hold every connection accepted from now on until [`Self::open_gate`].
    pub fn gate(&self) {
        self.shared.gate.send_replace(true);
    }

    /// Let held and future connections through.
    pub fn open_gate(&self) {
        self.shared.gate.send_replace(false);
    }

    /// Close every connection open now, and return once each is closed.
    pub async fn sever(&self) {
        // Each reply closes when its connection's task has dropped both
        // sockets (or had already ended): either way they are gone.
        join_all(self.ask(Control::Sever)).await;
    }

    /// Silence every connection open now, both ways, leaving it open.
    pub async fn blackhole(&self) {
        join_all(self.ask(Control::Blackhole)).await;
    }

    /// Deliver every held `EVAL` (and whatever queued behind it), and return
    /// once Redis has answered every command delivered — once each has RUN.
    /// Returns how many connections were holding.
    ///
    /// Waits (up to ten seconds) for a hold to have started first, and a
    /// held `EVAL` still arriving is delivered — and answered — once whole:
    /// so however TCP split it, asking too early cannot release nothing.
    pub async fn release_held(&self) -> usize {
        self.await_count(
            "held EVALs not yet released",
            |relay| {
                relay
                    .holding()
                    .saturating_sub(relay.shared.released.load(Ordering::SeqCst))
            },
            1,
        )
        .await;
        join_all(self.ask(Control::Release))
            .await
            .into_iter()
            .filter(|landed| *landed == Ok(true))
            .count()
    }

    /// Wait (up to ten seconds) until `count` — one of the counters above —
    /// reaches `at_least`.
    pub async fn await_count(
        &self,
        what: &str,
        count: impl Fn(&RedisRelay) -> usize,
        at_least: usize,
    ) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let seen = count(self);
            if seen >= at_least {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the relay saw {seen} {what} after 10s, expected at least {at_least}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Send one control message to every connection still running, and
    /// collect the replies to await.
    fn ask<T>(&self, message: impl Fn(oneshot::Sender<T>) -> Control) -> Vec<oneshot::Receiver<T>> {
        let mut connections = self.shared.connections.lock().expect("registry");
        connections.retain(|control| !control.is_closed());
        connections
            .iter()
            .filter_map(|control| {
                let (reply, answer) = oneshot::channel();
                control.send(message(reply)).ok().map(|()| answer)
            })
            .collect()
    }
}

impl Drop for RedisRelay {
    fn drop(&mut self) {
        self.accepting.abort();
        // Every connection's task ends when its control channel closes.
        self.shared.connections.lock().expect("registry").clear();
    }
}

/// The name of the command at the start of `bytes` — a RESP2 array of bulk
/// strings, `*<n>\r\n$<length>\r\n<name>\r\n…` — once all of the name has
/// arrived, whether or not the rest of the command has.
fn command_name(bytes: &[u8]) -> Option<&[u8]> {
    let line_end = |from: usize| {
        bytes
            .get(from..)?
            .windows(2)
            .position(|pair| pair == b"\r\n")
            .map(|at| from + at)
    };
    assert!(
        bytes.first().is_none_or(|kind| *kind == b'*'),
        "the handle sent something other than a RESP2 command"
    );
    let header = line_end(0)? + 2;
    let name = line_end(header)? + 2;
    assert_eq!(
        bytes.get(header),
        Some(&b'$'),
        "a RESP2 command's name is a bulk string"
    );
    let length: usize = std::str::from_utf8(&bytes[header + 1..name - 2])
        .ok()
        .and_then(|length| length.parse().ok())
        .expect("a bulk string's length");
    bytes.get(name..name + length)
}

/// Whether `command` — whole, or with its name in — is `name`.
fn is(command: &[u8], name: &str) -> bool {
    command_name(command).is_some_and(|found| found.eq_ignore_ascii_case(name.as_bytes()))
}

/// What becomes of the command arriving from the client: decided as soon as
/// its name is in — so faults apply in the order commands were SENT — and
/// carried out only once all of it is.
#[derive(Debug, Clone, Copy)]
enum Fate {
    /// Written on to Redis, with the fault armed for it, if any.
    Deliver(Option<EvalFault>),
    /// Held, as the `EVAL` that starts holding or behind it, until released
    /// — or delivered once whole, if released while still arriving.
    Hold,
    /// Blackholed: it goes nowhere.
    Drop,
}

/// The length of the whole RESP2 frame at the start of `bytes` — a command
/// (an array of bulk strings) or an answer — or `None` while part of it has
/// yet to arrive.
fn frame_length(bytes: &[u8]) -> Option<usize> {
    let (&kind, _) = bytes.split_first()?;
    let line = bytes.windows(2).position(|pair| pair == b"\r\n")?;
    let body = line + 2;
    let size = || -> i64 {
        std::str::from_utf8(&bytes[1..line])
            .ok()
            .and_then(|size| size.parse().ok())
            .unwrap_or_else(|| panic!("a malformed RESP2 size: {:?}", &bytes[..line]))
    };
    match kind {
        b'+' | b'-' | b':' => Some(body),
        // `$-1` is a nil: no body.
        b'$' => match usize::try_from(size()) {
            Err(_) => Some(body),
            Ok(length) => {
                let end = body + length + 2;
                (bytes.len() >= end).then_some(end)
            }
        },
        b'*' => {
            let mut end = body;
            for _ in 0..size().max(0) {
                end += frame_length(&bytes[end..])?;
            }
            Some(end)
        }
        other => panic!(
            "the Redis fault relay frames RESP2 only, and met a {:?} frame",
            char::from(other)
        ),
    }
}

/// One connection's commands matched to Redis's answers. Redis answers each
/// command on a connection once, in the order it read them, so counting
/// whole answers says which commands have RUN.
#[derive(Default)]
struct Exchange {
    /// How many commands were written on to Redis and not yet answered.
    unanswered: usize,
    /// From Redis, not yet a whole answer.
    received: Vec<u8>,
}

impl Exchange {
    /// A whole command has just been written on to Redis.
    fn sent(&mut self) {
        self.unanswered += 1;
    }

    /// `bytes` have just come from Redis. Returns how many answers they
    /// complete.
    fn received(&mut self, bytes: &[u8]) -> usize {
        self.received.extend_from_slice(bytes);
        let mut answers = 0;
        while let Some(length) = frame_length(&self.received) {
            self.received.drain(..length);
            self.unanswered = self
                .unanswered
                .checked_sub(1)
                .expect("Redis answered a command the relay never wrote to it");
            answers += 1;
        }
        answers
    }
}

/// Relay one accepted connection to `upstream` until either side closes or
/// a fault ends it.
async fn relay_one(
    client: TcpStream,
    upstream: String,
    shared: Arc<Shared>,
    mut control: mpsc::UnboundedReceiver<Control>,
) {
    // The gate: accepted, nothing relayed — the client's handshake waits in
    // the socket — until it opens.
    let mut gate = shared.gate.subscribe();
    while *gate.borrow_and_update() {
        tokio::select! {
            changed = gate.changed() => if changed.is_err() { return },
            message = control.recv() => match message {
                None => return,
                Some(Control::Sever(closed)) => {
                    drop(client);
                    drop(closed);
                    return;
                }
                Some(Control::Blackhole(done)) => {
                    let _ = done.send(());
                }
                Some(Control::Release(done)) => {
                    let _ = done.send(false);
                }
            },
        }
    }

    let Ok(server) = TcpStream::connect(&upstream).await else {
        return;
    };
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let mut from_client = vec![0_u8; 64 * 1024];
    let mut from_server = vec![0_u8; 64 * 1024];
    // Client bytes not yet a whole command, and — once its name is in — the
    // fate of the command they start.
    let mut incoming: Vec<u8> = Vec::new();
    let mut fate: Option<Fate> = None;
    let mut client_open = true;
    let mut blackholed = false;
    // `LoseAnswer` fired: nothing from Redis reaches the client again.
    let mut silenced = false;
    // `LoseAnswerAndClose` fired: Redis's next answer ends the connection.
    let mut close_on_answer = false;
    // `DelayAnswer` fired: Redis's next answer is passed on this late.
    let mut delay_answer: Option<Duration> = None;
    // `Hold` fired: every whole command the client sends from the EVAL on
    // waits here.
    let mut held: Option<Vec<Vec<u8>>> = None;
    // Released: told once Redis has answered what was held, with the number
    // of answers still owed until it has.
    let mut landing: Option<(oneshot::Sender<bool>, usize)> = None;
    let mut exchange = Exchange::default();

    let severed = loop {
        tokio::select! {
            message = control.recv() => match message {
                None => return,
                Some(Control::Sever(closed)) => break closed,
                Some(Control::Blackhole(done)) => {
                    blackholed = true;
                    let _ = done.send(());
                }
                Some(Control::Release(done)) => match held.take() {
                    Some(commands) => {
                        if server_write.write_all(&commands.concat()).await.is_err() {
                            return;
                        }
                        for _ in &commands {
                            exchange.sent();
                        }
                        shared.released.fetch_add(1, Ordering::SeqCst);
                        // Answers come in order, so what was held has all run
                        // once every command written so far is answered —
                        // and, if a held one is still arriving (the held
                        // EVAL itself, perhaps), once that one is too: it is
                        // delivered when whole.
                        let arriving = usize::from(matches!(fate, Some(Fate::Hold)));
                        landing = Some((done, exchange.unanswered + arriving));
                    }
                    None => {
                        let _ = done.send(false);
                    }
                },
            },
            read = client_read.read(&mut from_client), if client_open => {
                let Ok(count @ 1..) = read else {
                    // The client is gone. A held EVAL outlives it — the
                    // client gave up on it, the server never saw it — so the
                    // server side stays open until it is released.
                    client_open = false;
                    if held.is_none() && landing.is_none() {
                        return;
                    }
                    continue;
                };
                incoming.extend_from_slice(&from_client[..count]);
                while !incoming.is_empty() {
                    // Blackholed, a command goes nowhere. Otherwise it is held
                    // (behind an EVAL already held, or as the EVAL that
                    // starts holding) or written on to Redis.
                    if fate.is_none() {
                        fate = Some(if blackholed {
                            Fate::Drop
                        } else if held.is_some() {
                            Fate::Hold
                        } else {
                            let Some(name) = command_name(&incoming) else {
                                break;
                            };
                            if !name.eq_ignore_ascii_case(b"EVAL") {
                                Fate::Deliver(None)
                            } else {
                                match shared.armed.lock().expect("armed").pop_front() {
                                    Some(EvalFault::Hold) => {
                                        held = Some(Vec::new());
                                        shared.holding.fetch_add(1, Ordering::SeqCst);
                                        Fate::Hold
                                    }
                                    fault => Fate::Deliver(fault),
                                }
                            }
                        });
                    }
                    let Some(length) = frame_length(&incoming) else {
                        break;
                    };
                    let command: Vec<u8> = incoming.drain(..length).collect();
                    shared
                        .evals
                        .fetch_add(usize::from(is(&command, "EVAL")), Ordering::SeqCst);
                    let fate = match fate.take().expect("decided before the command was whole") {
                        _ if blackholed => Fate::Drop,
                        // Released while it was still arriving: delivered
                        // now that it is whole.
                        Fate::Hold if held.is_none() => Fate::Deliver(None),
                        fate => fate,
                    };
                    match fate {
                        Fate::Drop => {}
                        Fate::Hold => held.as_mut().expect("holding").push(command),
                        Fate::Deliver(fault) => {
                            match fault {
                                Some(EvalFault::LoseAnswer) => silenced = true,
                                Some(EvalFault::LoseAnswerAndClose) => close_on_answer = true,
                                Some(EvalFault::DelayAnswer(delay)) => delay_answer = Some(delay),
                                Some(EvalFault::Hold) | None => {}
                            }
                            if server_write.write_all(&command).await.is_err() {
                                return;
                            }
                            exchange.sent();
                        }
                    }
                }
            },
            read = server_read.read(&mut from_server) => {
                let Ok(count @ 1..) = read else { return };
                // Counted whatever then becomes of the answer: Redis sent it,
                // so its command has run.
                let answers = exchange.received(&from_server[..count]);
                if let Some((landed, owed)) = landing.take() {
                    if owed > answers {
                        landing = Some((landed, owed - answers));
                    } else {
                        // Redis answered all that was held: it has run.
                        let _ = landed.send(true);
                        if !client_open {
                            return;
                        }
                    }
                }
                if close_on_answer {
                    // The EVAL has run; its answer is lost with the
                    // connection.
                    return;
                }
                if blackholed || silenced || !client_open {
                    continue;
                }
                if let Some(delay) = delay_answer.take() {
                    tokio::time::sleep(delay).await;
                }
                if client_write.write_all(&from_server[..count]).await.is_err() {
                    client_open = false;
                }
            },
        }
    };
    // Both sockets close before the severing test is told they have.
    drop((client_read, client_write, server_read, server_write));
    drop(severed);
}
