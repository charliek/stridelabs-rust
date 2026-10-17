//! What the HTTP suites added for rate limiting, PATs and CORS share: a
//! loopback server for an assembled app, the JWKS mock, tokens, JSON-RPC
//! messages and a capturing `tracing` subscriber. (`tests/mcp_http.rs`, the
//! v0.6.0 suite, keeps its own server, tokens and messages, and takes only
//! the capture from here.)
//!
//! `#[tokio::test]` is a current-thread runtime, so the server, rmcp's
//! per-request tasks and the client all run on the test's thread, and every
//! line a request logs lands in that test's capture.

#![allow(dead_code)] // each suite uses a different part of this

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::CONTENT_TYPE;
use serde_json::{json, Value};
use stridelabs_auth::test_support::{TestClaims, TestKey};
use stridelabs_mcp::{McpVerifier, ProtectedResource, AUDIT_TARGET};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const ISSUER: &str = "https://auth.test.stridelabs.ai";
pub const RESOURCE: &str = "https://notes.test.stridelabs.ai/mcp";

pub fn resource() -> ProtectedResource {
    ProtectedResource::new(RESOURCE, ISSUER, ["notes:read", "notes:write"]).expect("canonical")
}

/// A JWKS endpoint serving the test key (or `response`).
pub async fn jwks(response: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(response)
        .mount(&server)
        .await;
    server
}

pub async fn good_jwks() -> MockServer {
    jwks(
        ResponseTemplate::new(200).set_body_raw(TestKey::primary().jwks_json(), "application/json"),
    )
    .await
}

pub fn verifier(jwks: &MockServer) -> McpVerifier {
    McpVerifier::new(
        &resource(),
        format!("{}/jwks", jwks.uri()),
        reqwest::Client::new(),
    )
}

/// Serve `app` on a loopback port; the base URL.
pub async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback port");
    let address = listener.local_addr().expect("local address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    format!("http://{address}")
}

/// POST a JSON-RPC message to `{base}/mcp` as a Streamable HTTP client does.
///
/// Bounded at 10 s, so a server that never answers (a hung tool: the bug
/// several of these tests exist to catch) fails the test instead of hanging
/// it.
pub async fn post(base: &str, headers: &[(&str, &str)], body: &Value) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .timeout(Duration::from_secs(10))
        .header(CONTENT_TYPE, "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-06-18")
        .json(body);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.send().await.expect("the server answers")
}

/// `tools/call` `name` with `token`, and its JSON-RPC answer.
pub async fn call(base: &str, token: &str, name: &str) -> Value {
    let response = post(
        base,
        &[("authorization", token)],
        &tools_call(name, json!({})),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::OK, "{name}");
    response.json().await.expect("a JSON body")
}

pub fn tools_call(name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
}

/// The single text block of a tool result.
pub fn text_of(answer: &Value) -> &str {
    let content = answer["result"]["content"]
        .as_array()
        .unwrap_or_else(|| panic!("content blocks: {answer}"));
    assert_eq!(content.len(), 1, "{answer}");
    content[0]["text"].as_str().expect("a text block")
}

pub fn is_error(answer: &Value) -> bool {
    answer["result"]["isError"] == json!(true)
}

/// `Bearer` + a JWT for the resource, for `sub`, with `scopes`.
pub fn token(sub: &str, scopes: &str) -> String {
    let claims = TestClaims::new(ISSUER, RESOURCE)
        .subject(sub)
        .claim("scope", json!(scopes))
        .claim("client_id", json!("connector-1"));
    format!("Bearer {}", TestKey::primary().mint(&claims.build()))
}

// --- capturing log lines ------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Captured {
    pub target: String,
    pub level: tracing::Level,
    pub fields: BTreeMap<String, String>,
}

impl Captured {
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }
}

/// Every event this thread logs. `take` hands lines to a test's assertions
/// and forgets them; `everything` still covers them, so a secrecy check made
/// after a take sees every line ever written, the taken ones included.
#[derive(Clone, Default)]
pub struct Capture {
    pending: Arc<Mutex<Vec<Captured>>>,
    all: Arc<Mutex<Vec<Captured>>>,
}

impl Capture {
    /// Install for this thread; keep the guard alive for the test.
    pub fn install() -> (Capture, tracing::subscriber::DefaultGuard) {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        (capture, tracing::subscriber::set_default(subscriber))
    }

    /// The lines on `target` written since the last take, forgotten.
    pub fn take(&self, target: &str) -> Vec<Captured> {
        let mut events = self.pending.lock().expect("capture lock");
        let taken = events
            .iter()
            .filter(|event| event.target == target)
            .cloned()
            .collect();
        events.retain(|event| event.target != target);
        taken
    }

    /// The one audit line a call must have written.
    pub fn one_audit_line(&self) -> Captured {
        let mut lines = self.take(AUDIT_TARGET);
        assert_eq!(lines.len(), 1, "exactly one audit line per call: {lines:?}");
        lines.remove(0)
    }

    /// Wait (up to 10 s, generous for a stalled scheduler) for a line on
    /// `target`, not yet taken, to arrive from a task that is still running.
    pub async fn wait_for(&self, target: &str) {
        for _ in 0..1_000 {
            if self
                .pending
                .lock()
                .expect("capture lock")
                .iter()
                .any(|event| event.target == target)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no line on {target} arrived");
    }

    /// Every line written while installed, taken or not, rendered: what a
    /// "this never reaches the logs" assertion searches.
    pub fn everything(&self) -> String {
        format!("{:?}", self.all.lock().expect("capture lock"))
    }
}

struct Fields<'a>(&'a mut BTreeMap<String, String>);

impl Visit for Fields<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

impl<S: tracing::Subscriber> Layer<S> for Capture {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = BTreeMap::new();
        event.record(&mut Fields(&mut fields));
        let captured = Captured {
            target: event.metadata().target().to_owned(),
            level: *event.metadata().level(),
            fields,
        };
        self.all
            .lock()
            .expect("capture lock")
            .push(captured.clone());
        self.pending.lock().expect("capture lock").push(captured);
    }
}
