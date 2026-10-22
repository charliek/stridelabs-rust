//! Shared scaffolding: a client pointed at a local server, MP3-shaped audio,
//! Inworld-shaped bodies, and a raw TCP server for what wiremock cannot do (a
//! body that streams forever, a stall after the headers, a declared length
//! that never arrives, a body cut off mid-way).
//!
//! Every test talks to `127.0.0.1` only; none reaches the real Inworld.

// Each test binary uses a different subset.
#![allow(dead_code)]

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use stridelabs_inworld::{AudioConfig, InworldClient, InworldClientBuilder, SynthesisRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
}

/// A raw HTTP/1.1 server on `127.0.0.1`: each connection's request is read,
/// then handed to the test's handler, which writes whatever it likes. Its
/// tasks end with the test's runtime.
pub struct RawServer {
    pub base_url: String,
    accepted: Arc<AtomicUsize>,
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
        let counter = Arc::clone(&accepted);
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let request = read_request(&mut stream).await;
                    handler(Exchange { stream, request }).await;
                });
            }
        });
        RawServer { base_url, accepted }
    }

    /// How many connections it accepted.
    pub fn connections(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
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

/// Long enough that no test waits for it: a stalled handler holds its socket
/// open this long, and the test's runtime ends it first.
pub const STALL: Duration = Duration::from_secs(60);

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

/// A port nothing listens on: bound, then released.
pub async fn refused_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let address = listener.local_addr().expect("its address");
    drop(listener);
    format!("http://{address}")
}
