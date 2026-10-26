//! A minimal Postgres fault relay for the guard's live suite (`tests/guard.rs`),
//! copied down from lumen-rs's `tests/pg_fault` (lumen plan 003 W3.3): a TCP
//! relay to the test database that applies ONE fault, at the first `BEGIN`
//! any of its connections sends, and records every statement it carries.
//!
//! It runs `sslmode=disable`, so it can read the messages. Both sides are
//! parsed as whole messages, however TCP splits them: the client's untyped
//! startup packet, then a type byte and an `int32` length counting itself;
//! the server's typed messages likewise. So a fault always lands on a
//! message boundary.
//!
//! **What the relay saw.** Each connection is tagged with the
//! `application_name` of its startup packet, so a test tells one pool's
//! connections from another's ([`Relay::statements_of`]). A statement is a
//! simple query's text, or the text of the prepared statement a `Bind` binds
//! (from the same connection's `Parse`). A `Sync` (sqlx's `ping`) is none. A
//! `BEGIN` is recognised by its text (a simple query whose text is `BEGIN`),
//! never by its bytes. The `BackendKeyData` PID of each connection is
//! recorded too ([`Relay::pids_of`]).
//!
//! **Faults** ([`Fault`]) are armed once, for the first `BEGIN` on any
//! connection, and counted when applied ([`Relay::fired`]), so a test that
//! asserts `fired() == 1` fails if its fault silently stopped matching.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use sqlx::postgres::{PgConnectOptions, PgSslMode};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::AbortHandle;

/// What the relay does at the first `BEGIN` it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Nothing: every message is relayed, for a test that reads what the
    /// relay saw.
    None,
    /// Forward the `BEGIN`, and hold the server's answer until
    /// [`Relay::release`] (or for good): the server has the `BEGIN`, its
    /// caller waits. Fired as the `BEGIN` is forwarded.
    HoldBeginAnswer,
    /// Forward the `BEGIN`, swallow the server's answer (its
    /// `CommandComplete` and its `ReadyForQuery`, in a transaction), and send
    /// the client a synthesised `ErrorResponse` (`XX000`) and a
    /// `ReadyForQuery` that is NOT in a transaction: the server entered the
    /// transaction, the client was told it failed. Relayed faithfully after.
    /// Fired as the synthesised answer is sent.
    AnswerBeginWithError,
    /// Relay the `BEGIN` and its answer faithfully, forward the client's next
    /// message (the transaction's bounds statement), and hold the server's
    /// answer to it until [`Relay::release`] (or for good). Fired as that
    /// message is forwarded.
    HoldSetLocalAnswer,
}

/// A running relay. Dropping it (or [`Relay::shutdown`]) closes every
/// connection it carries, both sides.
pub struct Relay {
    port: u16,
    upstream: PgConnectOptions,
    shared: Arc<Shared>,
}

struct Shared {
    fault: Fault,
    armed: AtomicBool,
    fired: AtomicUsize,
    fired_at: Mutex<Option<Instant>>,
    released: AtomicBool,
    release: tokio::sync::Notify,
    /// `(application_name, statement)`, in the order carried.
    statements: Mutex<Vec<(String, String)>>,
    /// `(application_name, backend pid)`, one per connection.
    pids: Mutex<Vec<(String, i32)>>,
    tasks: Mutex<Vec<AbortHandle>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    fn fire(&self) {
        *lock(&self.fired_at) = Some(Instant::now());
        self.fired.fetch_add(1, Ordering::SeqCst);
    }

    /// Until [`Relay::release`] has been called (at once if it has).
    async fn released(&self) {
        loop {
            // Created BEFORE the check: `notify_waiters` reaches every
            // `Notified` that exists when it is called.
            let notified = self.release.notified();
            if self.released.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

impl Relay {
    /// A relay on an ephemeral loopback port to `upstream`'s host and port,
    /// applying `fault`.
    pub async fn start(upstream: PgConnectOptions, fault: Fault) -> Relay {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a relay port");
        let port = listener.local_addr().expect("the relay's address").port();
        let shared = Arc::new(Shared {
            fault,
            armed: AtomicBool::new(fault != Fault::None),
            fired: AtomicUsize::new(0),
            fired_at: Mutex::new(None),
            released: AtomicBool::new(false),
            release: tokio::sync::Notify::new(),
            statements: Mutex::new(Vec::new()),
            pids: Mutex::new(Vec::new()),
            tasks: Mutex::new(Vec::new()),
        });
        let address = format!("{}:{}", upstream.get_host(), upstream.get_port());
        let accepting = Arc::clone(&shared);
        let accept = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let task = tokio::spawn(relay(client, address.clone(), Arc::clone(&accepting)));
                lock(&accepting.tasks).push(task.abort_handle());
            }
        });
        lock(&shared.tasks).push(accept.abort_handle());
        Relay {
            port,
            upstream,
            shared,
        }
    }

    /// The upstream's options pointed at the relay, in the clear, with
    /// `application_name` set to `name` (which tags the connection).
    pub fn options(&self, name: &str) -> PgConnectOptions {
        self.upstream
            .clone()
            .host("127.0.0.1")
            .port(self.port)
            .ssl_mode(PgSslMode::Disable)
            .application_name(name)
    }

    /// How many times the fault was applied: 0 or 1.
    pub fn fired(&self) -> usize {
        self.shared.fired.load(Ordering::SeqCst)
    }

    /// Until the fault has fired (or `within` passes, a failure): when it
    /// did.
    pub async fn until_fired(&self, within: Duration) -> Instant {
        let deadline = Instant::now() + within;
        while self.fired() == 0 {
            assert!(
                Instant::now() < deadline,
                "the fault ({:?}) never fired: no BEGIN reached the relay",
                self.shared.fault
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        lock(&self.shared.fired_at).expect("set as it fired")
    }

    /// Let a held answer through, and every later one.
    pub fn release(&self) {
        self.shared.released.store(true, Ordering::SeqCst);
        self.shared.release.notify_waiters();
    }

    /// Every statement carried so far, on every connection, in order.
    pub fn statements(&self) -> Vec<String> {
        lock(&self.shared.statements)
            .iter()
            .map(|(_, statement)| statement.clone())
            .collect()
    }

    /// The statements of the connections tagged `name`, in order.
    pub fn statements_of(&self, name: &str) -> Vec<String> {
        lock(&self.shared.statements)
            .iter()
            .filter(|(tag, _)| tag == name)
            .map(|(_, statement)| statement.clone())
            .collect()
    }

    /// The backend PIDs of the connections tagged `name`, one per
    /// connection, in the order they started.
    pub fn pids_of(&self, name: &str) -> Vec<i32> {
        lock(&self.shared.pids)
            .iter()
            .filter(|(tag, _)| tag == name)
            .map(|(_, pid)| *pid)
            .collect()
    }

    /// Close every connection the relay carries, both sides, and accept no
    /// more.
    pub fn shutdown(&self) {
        for task in lock(&self.shared.tasks).drain(..) {
            task.abort();
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Where one connection stands with the fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Relaying faithfully.
    Faithful,
    /// The server's answers are held until released (not read at all).
    Holding,
    /// `AnswerBeginWithError`: the server's answer to the `BEGIN` is being
    /// swallowed, up to its `ReadyForQuery`.
    Swallowing,
    /// `HoldSetLocalAnswer`: the `BEGIN` went through; the client's next
    /// message is the one whose answer is held.
    AfterBegin,
}

async fn relay(client: TcpStream, upstream: String, shared: Arc<Shared>) {
    let Ok(server) = TcpStream::connect(&upstream).await else {
        return;
    };
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let mut frontend = Frontend::default();
    let mut backend = Backend::default();
    let mut stage = Stage::Faithful;
    let mut from_client = vec![0_u8; 64 * 1024];
    let mut from_server = vec![0_u8; 64 * 1024];
    loop {
        let holding = stage == Stage::Holding;
        tokio::select! {
            read = client_read.read(&mut from_client) => {
                // A client closing its side closes the server's: dropping
                // both halves ends the backend too.
                let Ok(count @ 1..) = read else { return };
                for message in frontend.feed(&from_client[..count]) {
                    let statement = frontend.statement(&message);
                    let begin = statement.as_deref() == Some("BEGIN")
                        && shared.armed.swap(false, Ordering::SeqCst);
                    if let Some(statement) = statement {
                        lock(&shared.statements).push((frontend.name.clone(), statement));
                    }
                    let next = match (shared.fault, stage) {
                        (Fault::HoldBeginAnswer, _) if begin => Some(Stage::Holding),
                        (Fault::AnswerBeginWithError, _) if begin => Some(Stage::Swallowing),
                        (Fault::HoldSetLocalAnswer, _) if begin => Some(Stage::AfterBegin),
                        (Fault::HoldSetLocalAnswer, Stage::AfterBegin) => Some(Stage::Holding),
                        _ => None,
                    };
                    if server_write.write_all(&message).await.is_err() {
                        return;
                    }
                    if let Some(next) = next {
                        stage = next;
                        if next == Stage::Holding {
                            shared.fire();
                        }
                    }
                }
            }
            read = server_read.read(&mut from_server), if !holding => {
                let Ok(count @ 1..) = read else { return };
                let mut forward = Vec::new();
                for message in backend.feed(&from_server[..count]) {
                    if message[0] == b'K' && message.len() >= 9 {
                        let pid = i32::from_be_bytes(message[5..9].try_into().expect("four bytes"));
                        lock(&shared.pids).push((frontend.name.clone(), pid));
                    }
                    if stage == Stage::Swallowing {
                        if message[0] == b'Z' {
                            forward.extend_from_slice(&begin_failed());
                            stage = Stage::Faithful;
                            shared.fire();
                        }
                        continue;
                    }
                    forward.extend_from_slice(&message);
                }
                if client_write.write_all(&forward).await.is_err() {
                    return;
                }
            }
            () = shared.released(), if holding => stage = Stage::Faithful,
        }
    }
}

/// The client's side, cut into whole messages: the untyped startup packet
/// first (`sslmode=disable`: no `SSLRequest` precedes it), then typed ones.
#[derive(Default)]
struct Frontend {
    pending: Vec<u8>,
    started: bool,
    /// The startup packet's `application_name` ("" until it is read).
    name: String,
    /// Prepared statement name → its text, from this connection's `Parse`s.
    prepared: HashMap<String, String>,
}

impl Frontend {
    /// Take in `chunk`; answer every message it completes, whole and in
    /// order (the startup packet included).
    fn feed(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        self.pending.extend_from_slice(chunk);
        let mut complete = Vec::new();
        while let Some(message) = take_message(&mut self.pending, usize::from(self.started)) {
            if !self.started {
                self.started = true;
                self.name = startup_parameter(&message, "application_name").unwrap_or_default();
            }
            complete.push(message);
        }
        complete
    }

    /// The statement `message` runs, if it runs one; a `Parse` is
    /// remembered for its `Bind`.
    fn statement(&mut self, message: &[u8]) -> Option<String> {
        if !self.started || message.len() < 5 {
            return None;
        }
        let body = &message[5..];
        match message[0] {
            b'Q' => Some(c_string(body, 0).0),
            b'P' => {
                let (name, next) = c_string(body, 0);
                let (text, _) = c_string(body, next);
                self.prepared.insert(name, text);
                None
            }
            b'B' => {
                let (_portal, next) = c_string(body, 0);
                let (name, _) = c_string(body, next);
                Some(
                    self.prepared
                        .get(&name)
                        .cloned()
                        .unwrap_or_else(|| format!("<unparsed prepared statement {name:?}>")),
                )
            }
            _ => None,
        }
    }
}

/// The value of startup parameter `name` in the startup packet `message`
/// (length, protocol version, then NUL-terminated name/value pairs).
fn startup_parameter(message: &[u8], name: &str) -> Option<String> {
    let mut at = 8;
    while at < message.len() && message[at] != 0 {
        let (key, next) = c_string(message, at);
        let (value, after) = c_string(message, next);
        if key == name {
            return Some(value);
        }
        at = after;
    }
    None
}

/// The server's side, cut into whole messages (a type byte, an `int32`
/// length counting itself, the body).
#[derive(Default)]
struct Backend {
    pending: Vec<u8>,
}

impl Backend {
    fn feed(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        self.pending.extend_from_slice(chunk);
        std::iter::from_fn(|| take_message(&mut self.pending, 1)).collect()
    }
}

/// The first whole message in `pending`, drained, if `pending` holds one:
/// `at` leading bytes (1, the type byte; 0 for the untyped startup packet),
/// then an `int32` length counting itself and the body.
fn take_message(pending: &mut Vec<u8>, at: usize) -> Option<Vec<u8>> {
    let length = pending.get(at..at + 4)?;
    let end = at + u32::from_be_bytes(length.try_into().expect("four length bytes")) as usize;
    (pending.len() >= end).then(|| pending.drain(..end).collect())
}

/// The NUL-terminated string at `from` in `body`, and where the next field
/// starts.
fn c_string(body: &[u8], from: usize) -> (String, usize) {
    let end = body[from..]
        .iter()
        .position(|byte| *byte == 0)
        .map_or(body.len(), |offset| from + offset);
    (
        String::from_utf8_lossy(&body[from..end]).into_owned(),
        end + 1,
    )
}

/// `AnswerBeginWithError`'s answer: an `ErrorResponse` (`ERROR`, `XX000`,
/// a fixed message), then a `ReadyForQuery` that says idle, NOT in a
/// transaction.
fn begin_failed() -> Vec<u8> {
    let mut body = Vec::new();
    for (field, value) in [
        (b'S', "ERROR"),
        (b'V', "ERROR"),
        (b'C', "XX000"),
        (b'M', "pg_fault: injected"),
    ] {
        body.push(field);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    let length = u32::try_from(body.len() + 4).expect("a short message");
    let mut answer = vec![b'E'];
    answer.extend_from_slice(&length.to_be_bytes());
    answer.extend_from_slice(&body);
    answer.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
    answer
}
