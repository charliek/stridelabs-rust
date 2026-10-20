//! Shared scaffolding for the integration tests: a fake environment, the
//! credential fixtures, and token-endpoint responders.
//!
//! Every key here is throwaway: the `service_account` fixtures sign with
//! stridelabs-auth's committed test keypair (`crates/auth/testdata`, never
//! trusted anywhere), and every secret-shaped string is a `CANARY` that the
//! redaction tests look for.

// Each test binary uses a different subset.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use stridelabs_gcp::auth::{AdcEnvironment, TokenOptions, TokenProvider};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

mod log_capture;
// Like the rest of this module, unused in some test binaries.
#[allow(unused_imports)]
pub use log_capture::LogCapture;

pub const CLIENT_SECRET: &str = "CANARY-CLIENT-SECRET";
pub const REFRESH_TOKEN: &str = "CANARY-REFRESH-TOKEN";
pub const ACCESS_TOKEN: &str = "CANARY-ACCESS-TOKEN";
pub const CLIENT_EMAIL: &str = "imgmcp-test@test-project.iam.gserviceaccount.com";

/// The committed throwaway PKCS#1 key (`BEGIN RSA PRIVATE KEY`).
pub const TEST_KEY_PEM: &str = include_str!("../../../auth/testdata/test_signing_key.pem");
/// Its public half.
pub const TEST_JWKS: &str = include_str!("../../../auth/testdata/test_jwks.json");

/// An [`AdcEnvironment`] made of maps. A file maps to its bytes or to the
/// `io::ErrorKind` reading it fails with; an unmapped path is `NotFound`.
#[derive(Default)]
pub struct FakeEnv {
    vars: HashMap<String, String>,
    files: HashMap<PathBuf, Result<Vec<u8>, io::ErrorKind>>,
}

impl FakeEnv {
    pub fn new() -> FakeEnv {
        FakeEnv::default()
    }

    pub fn var(mut self, name: &str, value: &str) -> FakeEnv {
        self.vars.insert(name.to_owned(), value.to_owned());
        self
    }

    pub fn file(mut self, path: &str, contents: impl Into<Vec<u8>>) -> FakeEnv {
        self.files.insert(PathBuf::from(path), Ok(contents.into()));
        self
    }

    pub fn unreadable(mut self, path: &str, kind: io::ErrorKind) -> FakeEnv {
        self.files.insert(PathBuf::from(path), Err(kind));
        self
    }
}

impl AdcEnvironment for FakeEnv {
    fn var(&self, name: &str) -> Option<String> {
        self.vars.get(name).cloned()
    }

    fn read_file(&self, path: &Path) -> io::Result<Vec<u8>> {
        match self.files.get(path) {
            Some(Ok(bytes)) => Ok(bytes.clone()),
            Some(Err(kind)) => Err(io::Error::from(*kind)),
            None => Err(io::Error::from(io::ErrorKind::NotFound)),
        }
    }
}

/// gcloud's well-known file for `HOME=/home/test`.
pub const HOME: &str = "/home/test";
pub const WELL_KNOWN: &str = "/home/test/.config/gcloud/application_default_credentials.json";

pub fn b64(text: &str) -> String {
    STANDARD.encode(text)
}

/// `authorized_user` JSON with the canary secrets.
pub fn authorized_user() -> Value {
    authorized_user_with(REFRESH_TOKEN)
}

/// `authorized_user` JSON whose refresh token is `refresh_token` — how a
/// test tells which of several user credentials reached the endpoint.
pub fn authorized_user_with(refresh_token: &str) -> Value {
    json!({
        "type": "authorized_user",
        "client_id": "test-client.apps.googleusercontent.com",
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
    })
}

/// `service_account` JSON over the committed test key, exchanging at
/// `token_uri`.
pub fn service_account(token_uri: &str) -> Value {
    service_account_with_key(token_uri, TEST_KEY_PEM)
}

pub fn service_account_with_key(token_uri: &str, private_key: &str) -> Value {
    json!({
        "type": "service_account",
        "project_id": "test-project",
        "private_key_id": "test-key-id",
        "private_key": private_key,
        "client_email": CLIENT_EMAIL,
        "client_id": "1234567890",
        "token_uri": token_uri,
    })
}

/// A credential of an arbitrary `type`, otherwise plausible.
pub fn of_type(kind: &str) -> Value {
    let mut value = authorized_user();
    value["type"] = json!(kind);
    value
}

/// A token endpoint's success body, `expires_in` included as given (`null`
/// included).
pub fn token_body(token: &str, expires_in: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }))
}

/// A token endpoint's success body with no `expires_in` field at all.
pub fn token_body_without_expiry(token: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({"access_token": token, "token_type": "Bearer"}))
}

/// The route [`routed`] sends `authorized_user` exchanges to.
pub const USER_TOKEN_PATH: &str = "/token";

/// `provider` with its user-token endpoint at `{server}/token` and its
/// metadata server at `server`.
pub fn routed(provider: TokenProvider, server: &MockServer) -> TokenProvider {
    provider.with_options(
        TokenOptions::default()
            .default_token_uri(format!("{}{USER_TOKEN_PATH}", server.uri()))
            .metadata_base_url(server.uri())
            .metadata_timeout(Duration::from_secs(2)),
    )
}

/// A metadata-server provider against `server`, with a short timeout.
pub fn metadata_provider(server: &MockServer, scopes: &[&str]) -> TokenProvider {
    routed(
        TokenProvider::metadata_server(reqwest::Client::new(), scopes),
        server,
    )
}

pub const METADATA_TOKEN_PATH: &str = "/computeMetadata/v1/instance/service-accounts/default/token";

/// Mount a metadata server on `server` that answers `token` for an hour.
pub async fn mount_metadata_token(server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path(METADATA_TOKEN_PATH))
        .respond_with(token_body(token, json!(3600)))
        .mount(server)
        .await;
}

/// The form body of a received request, as a map.
pub fn form(body: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

// --- the 401 refresh: exact counts -----------------------------------------

/// A client that never retries on its own (reqwest 0.13 retries some
/// protocol failures by default), so every request a test counts is one the
/// code under test sent.
pub fn never_retrying() -> reqwest::Client {
    reqwest::Client::builder()
        .retry(reqwest::retry::never())
        .build()
        .unwrap()
}

/// Answers its n-th request with `answers[n]`, and every one past the end
/// with the last.
pub struct Sequence {
    answers: Vec<ResponseTemplate>,
    seen: AtomicUsize,
}

impl Sequence {
    pub fn new(answers: Vec<ResponseTemplate>) -> Sequence {
        assert!(!answers.is_empty(), "a sequence needs an answer");
        Sequence {
            answers,
            seen: AtomicUsize::new(0),
        }
    }
}

impl Respond for Sequence {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let n = self.seen.fetch_add(1, Ordering::SeqCst);
        self.answers
            .get(n)
            .or(self.answers.last())
            .cloned()
            .unwrap()
    }
}

/// Plain responses of these statuses, in order.
pub fn statuses(codes: &[u16]) -> Vec<ResponseTemplate> {
    codes
        .iter()
        .map(|&code| ResponseTemplate::new(code))
        .collect()
}

/// A metadata server of its own whose n-th token request answers `answers[n]`
/// (the last repeated), so its request count is the refresh count.
pub async fn token_server(answers: Vec<ResponseTemplate>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(METADATA_TOKEN_PATH))
        .respond_with(Sequence::new(answers))
        .mount(&server)
        .await;
    server
}

/// One-hour tokens with these bearers, in order.
pub fn bearers(names: &[&str]) -> Vec<ResponseTemplate> {
    names
        .iter()
        .map(|name| token_body(name, json!(3600)))
        .collect()
}

/// A metadata-server provider on `server` that never retries.
pub fn exact_provider(server: &MockServer) -> TokenProvider {
    routed(
        TokenProvider::metadata_server(never_retrying(), &[]),
        server,
    )
}

/// Distinct bearers, minted in this order.
pub const BEARERS: [&str; 5] = ["t1", "t2", "t3", "t4", "t5"];

/// The refresh count's contract, the same for every client: (N, the API's
/// answers in order, the status the call fails with if it fails, requests
/// sent). A persistent 401 costs N + 1 requests and N refreshes, and 401 then
/// 200 within the budget succeeds.
pub const REFRESH_CASES: [(u32, &[u16], Option<u16>, usize); 6] = [
    (0, &[401, 200], Some(401), 1),
    (1, &[401, 200], None, 2),
    (1, &[401, 401, 200], Some(401), 2),
    (2, &[401, 401, 200], None, 3),
    (2, &[401], Some(401), 3),
    (2, &[200], None, 1),
];

/// How many requests `server` received.
pub async fn request_count(server: &MockServer) -> usize {
    server.received_requests().await.unwrap().len()
}

pub fn header_of(request: &Request, name: &str) -> Option<String> {
    request
        .headers
        .get(name)
        .map(|value| value.to_str().unwrap().to_owned())
}

/// The bearer each request to `server` carried, in order (`-` for none).
pub async fn bearers_sent(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| {
            header_of(request, "authorization").map_or("-".to_owned(), |value| {
                value.trim_start_matches("Bearer ").to_owned()
            })
        })
        .collect()
}

// --- a scripted HTTP/1.1 server on a raw socket ---------------------------------

/// How a [`RawServer`] answers one request.
#[derive(Clone)]
pub enum RawReply {
    /// These bytes, a whole response; the connection stays open for more.
    Full(Vec<u8>),
    /// These bytes, the start of a response that never finishes: the
    /// connection is then held, unanswered, until the client closes it.
    Stall(Vec<u8>),
    /// These bytes, a whole response, sent only once every party of the
    /// barrier has arrived: a deterministic "nobody is answered until all N
    /// requests are in". A barrier that never fills (30 s) closes the
    /// connection unanswered, so a broken test fails rather than hangs.
    AfterBarrier(Arc<tokio::sync::Barrier>, Vec<u8>),
}

/// An HTTP/1.1 server that records every request's raw bytes (head and
/// `Content-Length` body) and answers the n-th, `request`, with
/// `script(n, request)`. What wiremock cannot do: show the exact bytes on
/// the wire, stall a body after its headers, and hold answers on a barrier
/// (a wiremock responder is synchronous, on the server's one thread).
pub struct RawServer {
    pub base_url: String,
    state: Arc<RawState>,
}

/// What the accept loop and every connection share.
struct RawState {
    requests: Mutex<Vec<Vec<u8>>>,
    accepted: AtomicUsize,
    stalled_closed: AtomicBool,
    script: Box<Script>,
}

/// How a [`RawServer`] picks its answer: from the request's index and bytes.
type Script = dyn Fn(usize, &[u8]) -> RawReply + Send + Sync;

impl RawServer {
    pub async fn start(
        script: impl Fn(usize, &[u8]) -> RawReply + Send + Sync + 'static,
    ) -> RawServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(RawState {
            requests: Mutex::default(),
            accepted: AtomicUsize::new(0),
            stalled_closed: AtomicBool::new(false),
            script: Box::new(script),
        });
        let accepting = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                accepting.accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve(socket, Arc::clone(&accepting)));
            }
        });
        RawServer { base_url, state }
    }

    /// Every request so far, raw, in arrival order.
    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.state.requests.lock().unwrap().clone()
    }

    /// Connections accepted so far.
    pub fn accepted(&self) -> usize {
        self.state.accepted.load(Ordering::SeqCst)
    }

    /// Whether the client closed a connection whose response was stalled.
    pub fn stalled_connection_closed(&self) -> bool {
        self.state.stalled_closed.load(Ordering::SeqCst)
    }
}

/// Read what `socket` has next onto `buffer`; `false` once the client hung
/// up (EOF or an error).
async fn read_more(socket: &mut tokio::net::TcpStream, buffer: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 4096];
    match socket.read(&mut chunk).await {
        Ok(0) | Err(_) => false,
        Ok(read) => {
            buffer.extend_from_slice(&chunk[..read]);
            true
        }
    }
}

async fn serve(mut socket: tokio::net::TcpStream, state: Arc<RawState>) {
    let mut buffer = Vec::new();
    loop {
        let head_end = loop {
            if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break at + 4;
            }
            if !read_more(&mut socket, &mut buffer).await {
                return;
            }
        };
        let head = String::from_utf8_lossy(&buffer[..head_end]).to_ascii_lowercase();
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .map_or(0, |value| value.trim().parse::<usize>().unwrap());
        while buffer.len() < head_end + length {
            if !read_more(&mut socket, &mut buffer).await {
                return;
            }
        }
        let request: Vec<u8> = buffer.drain(..head_end + length).collect();
        let reply = {
            let mut requests = state.requests.lock().unwrap();
            let reply = (state.script)(requests.len(), &request);
            requests.push(request);
            reply
        };
        match reply {
            RawReply::Full(bytes) => {
                if socket.write_all(&bytes).await.is_err() {
                    return;
                }
            }
            RawReply::Stall(bytes) => {
                let _ = socket.write_all(&bytes).await;
                // Held until the client hangs up, bounded so a broken test
                // fails rather than hangs.
                let hung_up = tokio::time::timeout(Duration::from_secs(60), async {
                    while read_more(&mut socket, &mut buffer).await {}
                })
                .await;
                if hung_up.is_ok() {
                    state.stalled_closed.store(true, Ordering::SeqCst);
                }
                return;
            }
            RawReply::AfterBarrier(barrier, bytes) => {
                if tokio::time::timeout(Duration::from_secs(30), barrier.wait())
                    .await
                    .is_err()
                    || socket.write_all(&bytes).await.is_err()
                {
                    return;
                }
            }
        }
    }
}

/// Whether `haystack` contains `needle`, byte for byte.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// `raw` with every `from` replaced by `to`, byte for byte.
pub fn replace_bytes(raw: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.windows(from.len()).position(|window| window == from) {
        out.extend_from_slice(&rest[..at]);
        out.extend_from_slice(to);
        rest = &rest[at + from.len()..];
    }
    out.extend_from_slice(rest);
    out
}

/// `raw` with the server's `host:port` written `HOST`.
pub fn normalized(raw: &[u8], base_url: &str) -> Vec<u8> {
    replace_bytes(
        raw,
        base_url.trim_start_matches("http://").as_bytes(),
        b"HOST",
    )
}

/// `bytes` as the inside of a Rust byte-string literal.
pub fn escaped(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
}
