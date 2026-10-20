//! A byte-level TCP proxy between a `RedisHandle` and the real test Redis,
//! which can lose a reply, kill connections and refuse new ones on demand —
//! the failures a real network produces, made deterministic — and rewrite a
//! request on its way in (a server with a command renamed, without touching
//! the shared server).
//!
//! A fault that loses a reply acts on the bytes coming BACK from Redis, so
//! the command it loses was executed; a test asserting "it ran exactly once"
//! knows Redis ran it. The reply faults are one-shot: the reply after the
//! lost one is forwarded again, so a command that WAS replayed on a fresh
//! connection would succeed — and be seen.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// What the proxy does with the next bytes Redis sends back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replies {
    /// Pass them through.
    Forward,
    /// Read the next reply from Redis and throw it away, keeping both
    /// sockets open (the client waits out its response timeout); forward
    /// everything after it.
    LoseNext,
    /// On the next reply from Redis, close that connection, both sides,
    /// without forwarding it: the command ran, and the connection died with
    /// its reply. Later replies are forwarded.
    CloseOnNext,
    /// Replace the next reply from Redis with bytes that are not RESP (a `?`
    /// type byte), keeping the connection open: the command ran, and what
    /// came back cannot be parsed. Later replies are forwarded.
    CorruptNext,
    /// Hold every chunk this long, then forward it.
    Delay(Duration),
}

pub struct Proxy {
    url: url::Url,
    accepted: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    replies: Arc<Mutex<Replies>>,
    rewrite: Arc<Mutex<Option<Rewrite>>>,
    refusing: Arc<AtomicBool>,
    kill: watch::Sender<u64>,
    listener: tokio::task::JoinHandle<()>,
}

/// One pending request rewrite: the first request that contains `from` has
/// it replaced by `to`.
type Rewrite = (Vec<u8>, Vec<u8>);

impl Proxy {
    /// A proxy in front of the Redis at `upstream_url` (plain `redis://`).
    pub async fn start(upstream_url: &str) -> Proxy {
        let upstream = url::Url::parse(upstream_url).expect("the probed REDIS_URL parses");
        let upstream_host = format!(
            "{}:{}",
            upstream.host_str().expect("REDIS_URL has a host"),
            upstream.port().unwrap_or(6379)
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let port = listener.local_addr().expect("the bound address").port();
        let mut url = upstream;
        url.set_host(Some("127.0.0.1")).expect("an IP host");
        url.set_port(Some(port)).expect("a port");

        let accepted = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let replies = Arc::new(Mutex::new(Replies::Forward));
        let rewrite = Arc::new(Mutex::new(None));
        let refusing = Arc::new(AtomicBool::new(false));
        let (kill, _) = watch::channel(0_u64);

        let listener = {
            let accepted = Arc::clone(&accepted);
            let active = Arc::clone(&active);
            let replies = Arc::clone(&replies);
            let rewrite = Arc::clone(&rewrite);
            let refusing = Arc::clone(&refusing);
            let kill = kill.clone();
            tokio::spawn(async move {
                while let Ok((client, _)) = listener.accept().await {
                    accepted.fetch_add(1, Ordering::SeqCst);
                    if refusing.load(Ordering::SeqCst) {
                        drop(client);
                        continue;
                    }
                    active.fetch_add(1, Ordering::SeqCst);
                    let relay = Relay {
                        upstream_host: upstream_host.clone(),
                        replies: Arc::clone(&replies),
                        rewrite: Arc::clone(&rewrite),
                        killed: kill.subscribe(),
                        active: Arc::clone(&active),
                    };
                    tokio::spawn(relay.run(client));
                }
            })
        };

        Proxy {
            url,
            accepted,
            active,
            replies,
            rewrite,
            refusing,
            kill,
            listener,
        }
    }

    /// The upstream URL (userinfo and database kept) pointed at the proxy.
    pub fn url(&self) -> String {
        self.url.to_string()
    }

    /// Every TCP connection the proxy has accepted — one per dial.
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// Wait briefly for `accepted` to reach `expected`, then require it.
    pub async fn assert_accepted(&self, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.accepted() < expected && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(self.accepted(), expected, "one dial is one TCP connection");
    }

    pub fn set_replies(&self, replies: Replies) {
        *self.replies.lock().unwrap() = replies;
    }

    /// Rewrite the next request that contains `from` — whole RESP frames,
    /// such as `$4\r\nEVAL\r\n` — into `to`, which must be as long so the
    /// framing holds; every other request passes untouched. One-shot. The
    /// proxy reassembles each request before looking (see [`Requests`]), so
    /// a request TCP split across reads is rewritten all the same.
    pub fn rewrite_next_request(&self, from: &[u8], to: &[u8]) {
        assert!(!from.is_empty(), "something to find");
        assert_eq!(from.len(), to.len(), "a rewrite keeps the framing");
        *self.rewrite.lock().unwrap() = Some((from.to_vec(), to.to_vec()));
    }

    /// Close every connection open right now, both sides, and wait until
    /// they are closed — what a Redis restart (or an idle timeout at the
    /// server) looks like to the client.
    pub async fn kill_connections(&self) {
        self.kill.send_modify(|epoch| *epoch += 1);
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.active.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            self.active.load(Ordering::SeqCst),
            0,
            "a relay outlived the kill"
        );
    }

    /// While on, accept each new connection and close it at once: a server
    /// that is down.
    pub fn set_refusing(&self, refusing: bool) {
        self.refusing.store(refusing, Ordering::SeqCst);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.listener.abort();
        self.kill.send_modify(|epoch| *epoch += 1);
    }
}

/// One proxied connection.
struct Relay {
    upstream_host: String,
    replies: Arc<Mutex<Replies>>,
    rewrite: Arc<Mutex<Option<Rewrite>>>,
    killed: watch::Receiver<u64>,
    active: Arc<AtomicUsize>,
}

impl Relay {
    async fn run(mut self, client: TcpStream) {
        if let Ok(upstream) = TcpStream::connect(&self.upstream_host).await {
            let (mut from_client, mut to_client) = client.into_split();
            let (mut from_upstream, mut to_upstream) = upstream.into_split();
            let replies = Arc::clone(&self.replies);
            let rewrite = Arc::clone(&self.rewrite);

            let requests = async {
                let mut framed = Requests::default();
                let mut buffer = vec![0_u8; 64 * 1024];
                loop {
                    let read = match from_client.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => read,
                    };
                    let whole = framed.feed(&buffer[..read], &rewrite);
                    if !whole.is_empty() && to_upstream.write_all(&whole).await.is_err() {
                        return;
                    }
                }
            };
            let answers = async {
                let mut buffer = vec![0_u8; 64 * 1024];
                loop {
                    let read = match from_upstream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => read,
                    };
                    let mode = {
                        let mut mode = replies.lock().unwrap();
                        let now = *mode;
                        if matches!(
                            now,
                            Replies::LoseNext | Replies::CloseOnNext | Replies::CorruptNext
                        ) {
                            *mode = Replies::Forward;
                        }
                        now
                    };
                    let reply: &[u8] = match mode {
                        Replies::Forward => &buffer[..read],
                        Replies::LoseNext => continue,
                        Replies::CloseOnNext => return,
                        Replies::CorruptNext => b"?not RESP\r\n",
                        Replies::Delay(delay) => {
                            tokio::time::sleep(delay).await;
                            &buffer[..read]
                        }
                    };
                    if to_client.write_all(reply).await.is_err() {
                        return;
                    }
                }
            };

            // Whichever ends first — a side closed, a fault, or a kill — the
            // four halves drop here and both sockets close.
            tokio::select! {
                () = requests => {}
                () = answers => {}
                _ = self.killed.changed() => {}
            }
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The client's byte stream reassembled into whole RESP requests — what
/// redis-rs sends, arrays of bulk strings — so that a rewrite sees each
/// request whole, however TCP split it.
#[derive(Default)]
struct Requests {
    buffered: Vec<u8>,
}

impl Requests {
    /// Take one read's `chunk`; return what to forward now: every request
    /// it completed, in order, the first to contain a pending `rewrite`'s
    /// pattern rewritten (which spends it). An incomplete request waits for
    /// the reads that complete it — Redis acts on nothing less than a whole
    /// request, so holding its start back changes nothing.
    fn feed(&mut self, chunk: &[u8], rewrite: &Mutex<Option<Rewrite>>) -> Vec<u8> {
        self.buffered.extend_from_slice(chunk);
        let mut whole = Vec::new();
        while let Some(length) = request_length(&self.buffered) {
            let mut request: Vec<u8> = self.buffered.drain(..length).collect();
            let mut pending = rewrite.lock().unwrap();
            if let Some((from, to)) = pending.as_ref() {
                if let Some(at) = request
                    .windows(from.len())
                    .position(|window| window == from.as_slice())
                {
                    request[at..at + to.len()].copy_from_slice(to);
                    *pending = None;
                }
            }
            whole.extend_from_slice(&request);
        }
        whole
    }
}

/// The length of the whole request at the start of `buffer` — `*N\r\n`,
/// then N × `$len\r\n<len bytes>\r\n` — or `None` until all of it has
/// arrived. Anything else panics: redis-rs sends nothing else, and a proxy
/// that guessed would hide it.
fn request_length(buffer: &[u8]) -> Option<usize> {
    let (count, mut at) = length_line(buffer, 0, b'*')?;
    for _ in 0..count {
        let (length, data) = length_line(buffer, at, b'$')?;
        at = data + length + 2;
        if buffer.len() < at {
            return None;
        }
        assert_eq!(&buffer[at - 2..at], b"\r\n", "a bulk string ends in CRLF");
    }
    Some(at)
}

/// The number on the `{kind}<n>\r\n` line at `at`, and where the line
/// ends — or `None` while the line is incomplete.
fn length_line(buffer: &[u8], at: usize, kind: u8) -> Option<(usize, usize)> {
    let line = buffer.get(at..)?;
    let end = line.windows(2).position(|window| window == b"\r\n")?;
    assert_eq!(line[0], kind, "redis-rs sends arrays of bulk strings");
    let number = std::str::from_utf8(&line[1..end])
        .ok()
        .and_then(|digits| digits.parse().ok())
        .expect("a RESP length");
    Some((number, at + end + 2))
}

/// A key no other test (or run) uses: the live suite shares one server.
pub fn unique_key(test: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_nanos();
    format!(
        "stridelabs-redis-test:{test}:{}:{nanos}:{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVAL: &[u8] = b"*3\r\n$4\r\nEVAL\r\n$8\r\nreturn 1\r\n$1\r\n0\r\n";
    const EVAX: &[u8] = b"*3\r\n$4\r\nEVAX\r\n$8\r\nreturn 1\r\n$1\r\n0\r\n";

    fn renaming_eval() -> Mutex<Option<Rewrite>> {
        Mutex::new(Some((
            b"$4\r\nEVAL\r\n".to_vec(),
            b"$4\r\nEVAX\r\n".to_vec(),
        )))
    }

    /// A request split across two reads ANYWHERE — inside the pattern
    /// included — is still forwarded whole and rewritten.
    #[test]
    fn a_rewrite_survives_a_request_split_across_reads() {
        for split in 1..EVAL.len() {
            let rewrite = renaming_eval();
            let mut framed = Requests::default();
            let mut forwarded = framed.feed(&EVAL[..split], &rewrite);
            forwarded.extend(framed.feed(&EVAL[split..], &rewrite));
            assert_eq!(
                String::from_utf8_lossy(&forwarded),
                String::from_utf8_lossy(EVAX),
                "split after byte {split}"
            );
            assert!(rewrite.lock().unwrap().is_none(), "the rewrite is spent");
        }
    }

    /// Pipelined requests in one read are each forwarded whole, in order;
    /// the rewrite is one-shot, and a request without its pattern passes
    /// untouched.
    #[test]
    fn pipelined_requests_pass_whole_and_the_rewrite_is_one_shot() {
        let ping: &[u8] = b"*1\r\n$4\r\nPING\r\n";
        let rewrite = renaming_eval();
        let mut framed = Requests::default();
        let forwarded = framed.feed(&[ping, EVAL, EVAL].concat(), &rewrite);
        assert_eq!(forwarded, [ping, EVAX, EVAL].concat());
        assert!(framed.buffered.is_empty(), "nothing held back");
    }
}
