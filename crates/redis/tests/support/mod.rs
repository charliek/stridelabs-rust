//! A byte-level TCP proxy between a `RedisHandle` and the real test Redis,
//! which can lose a reply, kill connections and refuse new ones on demand —
//! the failures a real network produces, made deterministic.
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
    refusing: Arc<AtomicBool>,
    kill: watch::Sender<u64>,
    listener: tokio::task::JoinHandle<()>,
}

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
        let refusing = Arc::new(AtomicBool::new(false));
        let (kill, _) = watch::channel(0_u64);

        let listener = {
            let accepted = Arc::clone(&accepted);
            let active = Arc::clone(&active);
            let replies = Arc::clone(&replies);
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
    killed: watch::Receiver<u64>,
    active: Arc<AtomicUsize>,
}

impl Relay {
    async fn run(mut self, client: TcpStream) {
        if let Ok(upstream) = TcpStream::connect(&self.upstream_host).await {
            let (mut from_client, mut to_client) = client.into_split();
            let (mut from_upstream, mut to_upstream) = upstream.into_split();
            let replies = Arc::clone(&self.replies);

            let requests = async {
                let _ = tokio::io::copy(&mut from_client, &mut to_upstream).await;
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
