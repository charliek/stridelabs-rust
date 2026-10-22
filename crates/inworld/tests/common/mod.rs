//! Shared scaffolding: a client pointed at a local server, MP3-shaped audio,
//! Inworld-shaped bodies, and a raw TCP server for what wiremock cannot do (a
//! body that streams forever, a stall after the headers, a declared length
//! that never arrives, a body cut off mid-way).
//!
//! A raw server's handlers run on tasks of their own, where a failed
//! assertion would only close a socket: [`RawServer::finish`] awaits each of
//! them and re-raises its panic in the test, so every test that starts one
//! ends by calling it.
//!
//! Every test talks to `127.0.0.1` only; none reaches the real Inworld.

// Each test binary uses a different subset.
#![allow(dead_code)]

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use stridelabs_inworld::{AudioConfig, InworldClient, InworldClientBuilder, SynthesisRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// The key every test runs with unless it says otherwise. Not a secret.
pub const KEY: &str = "dGVzdDprZXk=";

/// The model the tests name.
pub const MODEL: &str = "inworld-tts-2-flash";

/// A plain-http client the way the crate says to build one: no proxy, no
/// redirects. (`client_builder()`, under feature `client-builder`, is the
/// same plus the rustls backend, and has its own test.)
pub fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("a plain-http client builds")
}

/// A builder for a client at `base` with [`KEY`].
pub fn builder(base: &str) -> InworldClientBuilder {
    InworldClient::builder(http(), KEY).base_url(base)
}

/// A client at `base` with [`KEY`] and the default bounds.
pub fn client(base: &str) -> InworldClient {
    builder(base).build().expect("a loopback base URL builds")
}

/// A short MP3 request with nothing optional set.
pub fn request(text: &str) -> SynthesisRequest<'_> {
    SynthesisRequest::new(text, "Ashley", MODEL, AudioConfig::new("MP3"))
}

/// `len` bytes that open like an MP3 (a frame sync, then zeros).
pub fn mp3(len: usize) -> Vec<u8> {
    let mut audio = vec![0u8; len];
    audio[..2].copy_from_slice(&[0xFF, 0xF3]);
    audio
}

/// Inworld's `2xx` body for `audio`, with no `usage`.
pub fn audio_body(audio: &[u8]) -> String {
    format!(r#"{{"audioContent":"{}"}}"#, STANDARD.encode(audio))
}

/// What a raw connection handler is handed: the accepted stream, its request
/// already read in full (so closing it sends a FIN, never a reset).
pub struct Exchange {
    pub stream: TcpStream,
    pub request: Vec<u8>,
}

impl Exchange {
    /// Write `bytes` and flush.
    pub async fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await
    }

    /// Keep the connection open, reading and dropping whatever arrives, until
    /// the client hangs up: a stall that ends when the client gives up, so
    /// the handler can be awaited. A client that has not hung up within
    /// [`HOLD`] fails the test.
    pub async fn hold_until_hangup(mut self) {
        let mut sink = [0u8; 4096];
        let held = tokio::time::timeout(HOLD, async {
            while let Ok(read) = self.stream.read(&mut sink).await {
                if read == 0 {
                    return;
                }
            }
        })
        .await;
        assert!(held.is_ok(), "the client never hung up within {HOLD:?}");
    }
}

/// How long a stalled handler waits for its client to hang up, and how long
/// a test waits for a handler to finish. Every client here gives up within
/// seconds; this is only a bound on a broken one.
pub const HOLD: Duration = Duration::from_secs(30);

/// A raw HTTP/1.1 server on `127.0.0.1`: each connection's request is read,
/// then handed to the test's handler, which writes whatever it likes.
/// [`RawServer::finish`] awaits every handler and re-raises its panic.
pub struct RawServer {
    pub base_url: String,
    accepted: Arc<AtomicUsize>,
    handlers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl RawServer {
    pub async fn start<H, F>(handler: H) -> RawServer
    where
        H: Fn(Exchange) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let base_url = format!("http://{}", listener.local_addr().expect("its address"));
        let accepted = Arc::new(AtomicUsize::new(0));
        let handlers = Arc::new(Mutex::new(Vec::new()));
        let (counter, registry) = (Arc::clone(&accepted), Arc::clone(&handlers));
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let handler = Arc::clone(&handler);
                let gate = Arc::clone(&registry);
                // Registered before the handler can answer: it takes the
                // lock this holds before it reads the request, so a test
                // that got its answer always finds the handler to await.
                let mut registered = registry.lock().expect("the handler registry");
                counter.fetch_add(1, Ordering::SeqCst);
                registered.push(tokio::spawn(async move {
                    drop(gate.lock().expect("the handler registry"));
                    let request = read_request(&mut stream).await;
                    handler(Exchange { stream, request }).await;
                }));
            }
        });
        RawServer {
            base_url,
            accepted,
            handlers,
        }
    }

    /// How many connections it accepted.
    pub fn connections(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// Await every handler started so far, each within [`HOLD`], and fail
    /// the test with a handler's own panic if one failed: an assertion in a
    /// handler, or in its request read, counts. Returns how many it awaited.
    pub async fn finish(&self) -> usize {
        let handlers = std::mem::take(&mut *self.handlers.lock().expect("the handler registry"));
        let count = handlers.len();
        for handler in handlers {
            match tokio::time::timeout(HOLD, handler).await {
                Ok(Ok(())) => {}
                Ok(Err(failed)) if failed.is_panic() => {
                    std::panic::resume_unwind(failed.into_panic())
                }
                Ok(Err(failed)) => panic!("a handler was cancelled: {failed}"),
                Err(_) => panic!("a handler did not finish within {HOLD:?}"),
            }
        }
        count
    }
}

/// One request off `stream`: its head, then as much body as its
/// `Content-Length` declares.
async fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break at + 4;
        }
        let read = stream.read(&mut chunk).await.expect("the request arrives");
        assert!(read > 0, "the client closed before its request ended");
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_ascii_lowercase();
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .map_or(0, |value| value.trim().parse().expect("a numeric length"));
    while buffer.len() < head_end + length {
        let read = stream.read(&mut chunk).await.expect("the body arrives");
        assert!(read > 0, "the client closed before its body ended");
        buffer.extend_from_slice(&chunk[..read]);
    }
    buffer
}

/// Set once a handler has written (and flushed) its response's headers.
#[derive(Clone, Default)]
pub struct Flag(Arc<AtomicBool>);

impl Flag {
    pub fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Every rendering of `error` a log line could carry: `Display`, both
/// `Debug`s, and each `source()` down the chain.
pub fn renderings(error: &(dyn std::error::Error + 'static)) -> String {
    let mut rendered = format!("{error}\n{error:?}\n{error:#?}");
    let mut source = error.source();
    while let Some(cause) = source {
        rendered.push_str(&format!("\n{cause}\n{cause:?}"));
        source = cause.source();
    }
    rendered
}

/// One HTTP/2 frame on `stream` (`0` for the connection).
pub fn h2_frame_on(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("a small frame");
    let mut frame = length.to_be_bytes()[1..].to_vec();
    frame.extend_from_slice(&[kind, flags]);
    frame.extend_from_slice(&(stream & 0x7FFF_FFFF).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// A port nothing listens on: bound, then released.
pub async fn refused_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let address = listener.local_addr().expect("its address");
    drop(listener);
    format!("http://{address}")
}
