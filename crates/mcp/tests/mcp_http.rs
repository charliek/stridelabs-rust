//! End to end over a real socket: an axum app with the metadata router and
//! the authenticated MCP endpoint, a small rmcp `ServerHandler` whose tools
//! go through `ToolCall`, and a reqwest client speaking the protocol
//! revisions real clients send (2025-03-26 with no version header,
//! 2025-06-18, and 2026-07-28's per-request `_meta`).
//!
//! Every test installs a capturing `tracing` subscriber for its own thread.
//! `#[tokio::test]` is a current-thread runtime, so the server, rmcp's
//! per-request tasks and the client all run on that thread, and every audit
//! line a request produces lands in that test's capture.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, HOST, WWW_AUTHENTICATE};
use reqwest::StatusCode;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig};
use rmcp::service::RequestContext;
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler};
use serde_json::{json, Value};
use stridelabs_auth::test_support::{TestClaims, TestKey};
use stridelabs_mcp::{
    AuthMethod, McpAuthLayer, McpVerifier, Principal, ProtectedResource, ToolCall, ToolError,
    VerifyError, AUDIT_TARGET,
};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISSUER: &str = "https://auth.test.stridelabs.ai";
const RESOURCE: &str = "https://notes.test.stridelabs.ai/mcp";
const METADATA_URL: &str =
    "https://notes.test.stridelabs.ai/.well-known/oauth-protected-resource/mcp";

// --- the server under test ---------------------------------------------------

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct AddNote {
    /// The note's text.
    text: String,
}

struct Notes {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl Notes {
    #[tool(description = "Who is calling, and with which scopes.")]
    async fn whoami(&self, ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
        // What rmcp hands a tool: the HTTP request's parts, headers included.
        let saw_authorization = ctx
            .extensions
            .get::<http::request::Parts>()
            .expect("rmcp injects the request parts")
            .headers
            .contains_key("authorization");
        ToolCall::new("whoami")
            .run(&ctx, |principal| async move {
                Ok(CallToolResult::structured(json!({
                    "sub": principal.subject,
                    "scopes": principal.scopes,
                    "auth_method": principal.auth_method.as_str(),
                    "saw_authorization": saw_authorization,
                })))
            })
            .await
    }

    #[tool(description = "Add a note. Needs notes:write.")]
    async fn add_note(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(AddNote { text }): Parameters<AddNote>,
    ) -> Result<CallToolResult, ErrorData> {
        ToolCall::new("add_note")
            .scopes(["notes:write"])
            .run(&ctx, |_principal| async move {
                Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                    "added: {text}"
                ))]))
            })
            .await
    }

    #[tool(description = "Never finishes in time.")]
    async fn slow(&self, ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
        ToolCall::new("slow")
            .timeout(Duration::from_millis(50))
            .run(&ctx, |_principal| async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(CallToolResult::success(vec![]))
            })
            .await
    }

    #[tool(description = "Fails with an internal error carrying private data.")]
    async fn explode(&self, ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
        ToolCall::new("explode")
            .run(&ctx, |_principal| async move {
                let failure = std::io::Error::other("row 42 holds hunter2");
                Err(ToolError::internal(failure))
            })
            .await
    }

    #[tool(description = "Fails with a message for the model.")]
    async fn find_note(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        ToolCall::new("find_note")
            .run(&ctx, |_principal| async move {
                Err(ToolError::user("No such note."))
            })
            .await
    }

    #[tool(description = "Panics.")]
    async fn crash(&self, ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
        ToolCall::new("crash")
            .run(&ctx, |_principal| async move {
                if std::hint::black_box(true) {
                    panic!("a tool bug");
                }
                Ok(CallToolResult::success(vec![]))
            })
            .await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Notes {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

fn resource() -> ProtectedResource {
    ProtectedResource::new(RESOURCE, ISSUER, ["notes:read", "notes:write"]).expect("canonical")
}

/// A running app (metadata + endpoint) on 127.0.0.1, with its JWKS mock.
struct TestServer {
    base: String,
    http: reqwest::Client,
    _jwks: MockServer,
}

impl TestServer {
    async fn start() -> TestServer {
        TestServer::start_with(
            ResponseTemplate::new(200)
                .set_body_raw(TestKey::primary().jwks_json(), "application/json"),
        )
        .await
    }

    async fn start_with(jwks_response: ResponseTemplate) -> TestServer {
        let jwks = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(jwks_response)
            .mount(&jwks)
            .await;

        let resource = resource();
        let verifier = McpVerifier::new(
            &resource,
            format!("{}/jwks", jwks.uri()),
            reqwest::Client::new(),
        )
        .with_credential("pcl_", |token: String| async move {
            match token.as_str() {
                "pcl_owner" => Ok(Principal::new("owner-1", ["notes:read"], AuthMethod::Token)
                    .with_client_id("parcel-cli")),
                _ => Err(VerifyError::invalid("unknown token")),
            }
        });
        // The resource URL is an identifier, never dialled: the server is
        // plain http on loopback, so loopback is an extra allowed host.
        let config = stridelabs_mcp::server_config(&resource, ["127.0.0.1"]);
        let app: axum::Router = axum::Router::new()
            .route("/health", axum::routing::get(|| async { "ok" }))
            .merge(stridelabs_mcp::metadata_router(&resource))
            .merge(stridelabs_mcp::router(
                McpAuthLayer::new(verifier),
                config,
                || {
                    Ok(Notes {
                        tool_router: Notes::tool_router(),
                    })
                },
            ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let address = listener.local_addr().expect("local address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        TestServer {
            base: format!("http://{address}"),
            http: reqwest::Client::new(),
            _jwks: jwks,
        }
    }

    /// POST a JSON-RPC message to `/mcp` the way a Streamable HTTP client
    /// does, with `headers` on top (an `Authorization`, a version, a Host).
    async fn post(&self, headers: &[(&str, &str)], body: &Value) -> reqwest::Response {
        self.post_to("/mcp", headers, body).await
    }

    async fn post_to(
        &self,
        path: &str,
        headers: &[(&str, &str)],
        body: &Value,
    ) -> reqwest::Response {
        let mut request = self
            .http
            .post(format!("{}{path}", self.base))
            .header(CONTENT_TYPE, "application/json")
            .header("accept", "application/json, text/event-stream")
            .json(body);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request.send().await.expect("the server answers")
    }
}

// --- tokens and messages -------------------------------------------------------

fn token_with(claims: TestClaims) -> String {
    format!("Bearer {}", TestKey::primary().mint(&claims.build()))
}

fn mcp_claims(scopes: &str) -> TestClaims {
    TestClaims::new(ISSUER, RESOURCE)
        .subject("kratos-1")
        .claim("scope", json!(scopes))
        .claim("client_id", json!("connector-1"))
}

fn reader() -> String {
    token_with(mcp_claims("notes:read"))
}

fn writer() -> String {
    token_with(mcp_claims("notes:read notes:write"))
}

fn initialize(version: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "e2e", "version": "1.0"},
        },
    })
}

fn tools_list() -> Value {
    json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
}

fn tools_call(name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
}

/// 2026-07-28 carries the protocol in every request's `_meta`.
fn with_2026_meta(mut message: Value) -> Value {
    let params = message["params"]
        .as_object_mut()
        .expect("params are an object");
    params.insert(
        "_meta".to_owned(),
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": "e2e", "version": "1.0"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }),
    );
    message
}

async fn json_body(response: reqwest::Response) -> Value {
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .map(|value| value.to_str().expect("ASCII").to_owned());
    assert_eq!(
        content_type.as_deref(),
        Some("application/json"),
        "stateless JSON responses"
    );
    response.json().await.expect("a JSON body")
}

/// The single text block of a tool result.
fn text_of(result: &Value) -> &str {
    let content = result["content"].as_array().expect("content blocks");
    assert_eq!(content.len(), 1, "{result}");
    content[0]["text"].as_str().expect("a text block")
}

// --- capturing the audit lines ------------------------------------------------

#[derive(Debug, Clone)]
struct Captured {
    target: String,
    level: tracing::Level,
    fields: BTreeMap<String, String>,
}

/// `take_audit` forgets the lines it hands out; `everything` still covers
/// them, so a secrecy check after a take sees every line ever written.
#[derive(Clone, Default)]
struct Capture {
    pending: Arc<Mutex<Vec<Captured>>>,
    all: Arc<Mutex<Vec<Captured>>>,
}

impl Capture {
    /// Install for this thread; keep the guard alive for the test.
    fn install() -> (Capture, tracing::subscriber::DefaultGuard) {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        (capture, tracing::subscriber::set_default(subscriber))
    }

    /// The audit lines written since the last call, and forget them.
    fn take_audit(&self) -> Vec<Captured> {
        let mut events = self.pending.lock().expect("capture lock");
        let audit = events
            .iter()
            .filter(|event| event.target == AUDIT_TARGET)
            .cloned()
            .collect();
        events.retain(|event| event.target != AUDIT_TARGET);
        audit
    }

    fn everything(&self) -> String {
        format!("{:?}", self.all.lock().expect("capture lock"))
    }

    /// The one audit line a call must have written.
    fn one_audit_line(&self) -> Captured {
        let mut lines = self.take_audit();
        assert_eq!(lines.len(), 1, "exactly one audit line per call: {lines:?}");
        lines.remove(0)
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

// --- the tests ------------------------------------------------------------------

#[tokio::test]
async fn the_metadata_document_is_served_at_the_origin_root_without_auth() {
    let server = TestServer::start().await;
    let expected = json!({
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "scopes_supported": ["notes:read", "notes:write"],
        "bearer_methods_supported": ["header"],
    });

    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let response = server
            .http
            .get(format!("{}{path}", server.base))
            .send()
            .await
            .expect("answers");
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(json_body(response).await, expected, "{path}");
    }
}

#[tokio::test]
async fn an_unauthenticated_request_gets_the_discovery_challenge() {
    let server = TestServer::start().await;

    let response = server.post(&[], &initialize("2025-06-18")).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[WWW_AUTHENTICATE],
        format!("Bearer resource_metadata=\"{METADATA_URL}\", scope=\"notes:read notes:write\"")
            .as_str()
    );
    let body = json_body(response).await;
    assert_eq!(body["error"], "unauthorized");
    assert!(body["error_description"].is_string());
}

#[tokio::test]
async fn refused_tokens_get_invalid_token_whatever_the_reason() {
    let server = TestServer::start().await;
    let challenge = format!(
        "Bearer error=\"invalid_token\", error_description=\"The access token is invalid or expired.\", \
         resource_metadata=\"{METADATA_URL}\", scope=\"notes:read notes:write\""
    );
    let untrusted = format!(
        "Bearer {}",
        TestKey::secondary()
            .mint_with_kid(TestKey::primary().kid(), &mcp_claims("notes:read").build())
    );

    for (case, authorization) in [
        ("malformed", "Bearer not.a.jwt".to_owned()),
        (
            "the app's REST audience",
            token_with(TestClaims::new(ISSUER, "notes-rest-api")),
        ),
        (
            "expired",
            token_with(mcp_claims("notes:read").expires_in(-3600)),
        ),
        (
            "another issuer",
            token_with(TestClaims::new("https://evil.example", RESOURCE)),
        ),
        ("an untrusted key", untrusted),
        ("an unknown app token", "Bearer pcl_nope".to_owned()),
    ] {
        let response = server
            .post(&[("authorization", &authorization)], &tools_list())
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{case}");
        assert_eq!(
            response.headers()[WWW_AUTHENTICATE],
            challenge.as_str(),
            "{case}"
        );
        assert_eq!(
            json_body(response).await["error"],
            "invalid_token",
            "{case}"
        );
    }
}

#[tokio::test]
async fn a_jwks_outage_is_a_503_not_a_sign_out() {
    let server = TestServer::start_with(ResponseTemplate::new(500)).await;

    let response = server
        .post(&[("authorization", &reader())], &tools_list())
        .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    assert_eq!(
        json_body(response).await["error"],
        "temporarily_unavailable"
    );
}

#[tokio::test]
async fn legacy_clients_initialize_list_and_call_statelessly() {
    let (capture, _guard) = Capture::install();
    let server = TestServer::start().await;
    let token = reader();

    // 2025-03-26 clients send no version header at all; later ones send it
    // on everything after the handshake.
    for (version, version_header) in [
        ("2025-03-26", None),
        ("2025-06-18", Some("2025-06-18")),
        ("2025-11-25", Some("2025-11-25")),
    ] {
        let mut headers = vec![("authorization", token.as_str())];
        if let Some(header) = version_header {
            headers.push(("mcp-protocol-version", header));
        }

        let response = server.post(&headers, &initialize(version)).await;
        assert_eq!(response.status(), StatusCode::OK, "{version}");
        assert!(
            response.headers().get("mcp-session-id").is_none(),
            "{version}: stateless, so no session"
        );
        let init = json_body(response).await;
        assert_eq!(init["result"]["protocolVersion"], version);
        assert!(init["result"]["capabilities"]["tools"].is_object());

        let response = server
            .post(
                &headers,
                &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED, "{version}");

        let listed = json_body(server.post(&headers, &tools_list()).await).await;
        let mut names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .map(|tool| tool["name"].as_str().expect("a name"))
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "add_note",
                "crash",
                "explode",
                "find_note",
                "slow",
                "whoami"
            ],
            "{version}"
        );
        assert!(
            capture.take_audit().is_empty(),
            "listing is not a tool call"
        );

        let called = json_body(
            server
                .post(&headers, &tools_call("whoami", json!({})))
                .await,
        )
        .await;
        assert_eq!(called["id"], 3);
        assert_eq!(called["result"]["isError"], false, "{called}");
        assert_eq!(
            called["result"]["structuredContent"],
            json!({
                "sub": "kratos-1",
                "scopes": ["notes:read"],
                "auth_method": "jwt",
                // The boundary keeps the token from the tool.
                "saw_authorization": false,
            })
        );

        let line = capture.one_audit_line();
        assert_eq!(line.level, tracing::Level::INFO);
        for (field, value) in [
            ("tool", "whoami"),
            ("outcome", "ok"),
            ("sub", "kratos-1"),
            ("auth_method", "jwt"),
            ("scopes", "notes:read"),
            ("client_id", "connector-1"),
            ("required_scopes", ""),
        ] {
            assert_eq!(
                line.fields.get(field).map(String::as_str),
                Some(value),
                "{field}"
            );
        }
        assert!(line.fields.contains_key("duration_ms"));
        assert!(!line.fields.contains_key("error_class"));
        assert!(
            !capture.everything().contains("user@example.com"),
            "no email logged"
        );
    }
}

#[tokio::test]
async fn the_2026_07_28_lifecycle_works_without_initialize() {
    let (capture, _guard) = Capture::install();
    let server = TestServer::start().await;
    let token = writer();

    let discover = with_2026_meta(
        json!({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}}),
    );
    let response = server
        .post(
            &[
                ("authorization", &token),
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "server/discover"),
            ],
            &discover,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let discovered = json_body(response).await;
    assert!(
        discovered["result"]["supportedVersions"]
            .as_array()
            .expect("versions")
            .contains(&json!("2026-07-28")),
        "{discovered}"
    );

    let call = with_2026_meta(tools_call("add_note", json!({"text": "hello"})));
    let response = server
        .post(
            &[
                ("authorization", &token),
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/call"),
                ("mcp-name", "add_note"),
            ],
            &call,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let called = json_body(response).await;
    assert_eq!(called["result"]["resultType"], "complete", "{called}");
    assert_eq!(text_of(&called["result"]), "added: hello");

    let line = capture.one_audit_line();
    assert_eq!(line.fields["tool"], "add_note");
    assert_eq!(line.fields["outcome"], "ok");
    assert_eq!(line.fields["required_scopes"], "notes:write");
}

#[tokio::test]
async fn every_failure_is_a_tool_error_with_one_audit_line() {
    let (capture, _guard) = Capture::install();
    let server = TestServer::start().await;
    let headers = |token: &str| -> Vec<(&'static str, String)> {
        vec![
            ("authorization", token.to_owned()),
            ("mcp-protocol-version", "2025-06-18".to_owned()),
        ]
    };

    let scope_message = "Missing required scope(s): notes:write. This credential grants: \
                         notes:read. Reconnect with the required scopes to use this tool.";
    for (token, tool, arguments, message, outcome, error_class, level) in [
        (
            reader(),
            "add_note",
            json!({"text": "hi"}),
            scope_message,
            "denied",
            "ScopeError",
            tracing::Level::INFO,
        ),
        (
            reader(),
            "slow",
            json!({}),
            "The operation timed out. Please try again.",
            "timeout",
            "Timeout",
            tracing::Level::WARN,
        ),
        (
            reader(),
            "explode",
            json!({}),
            "Internal server error.",
            "internal",
            "std::io::error::Error",
            tracing::Level::ERROR,
        ),
        (
            reader(),
            "find_note",
            json!({}),
            "No such note.",
            "error",
            "ToolError::User",
            tracing::Level::INFO,
        ),
        (
            reader(),
            "crash",
            json!({}),
            "Internal server error.",
            "internal",
            "panic",
            tracing::Level::ERROR,
        ),
    ] {
        let headers = headers(&token);
        let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();

        let response = server.post(&headers, &tools_call(tool, arguments)).await;

        assert_eq!(response.status(), StatusCode::OK, "{tool}");
        let body = json_body(response).await;
        assert!(
            body.get("error").is_none(),
            "{tool}: a tool error, not a protocol error"
        );
        assert_eq!(body["result"]["isError"], true, "{tool}");
        assert_eq!(text_of(&body["result"]), message, "{tool}");

        let line = capture.one_audit_line();
        assert_eq!(line.fields["tool"], tool);
        assert_eq!(line.fields["outcome"], outcome, "{tool}");
        assert_eq!(line.fields["error_class"], error_class, "{tool}");
        assert_eq!(line.level, level, "{tool}");
        assert_eq!(line.fields["sub"], "kratos-1", "{tool}");
    }

    assert!(
        !capture.everything().contains("hunter2"),
        "an internal error's message is never logged"
    );
}

#[tokio::test]
async fn app_credentials_work_end_to_end() {
    let (capture, _guard) = Capture::install();
    let server = TestServer::start().await;

    let called = json_body(
        server
            .post(
                &[("authorization", "Bearer pcl_owner")],
                &tools_call("whoami", json!({})),
            )
            .await,
    )
    .await;

    assert_eq!(
        called["result"]["structuredContent"],
        json!({
            "sub": "owner-1",
            "scopes": ["notes:read"],
            "auth_method": "token",
            "saw_authorization": false,
        })
    );
    let line = capture.one_audit_line();
    assert_eq!(line.fields["auth_method"], "token");
    assert_eq!(line.fields["client_id"], "parcel-cli");
}

#[tokio::test]
async fn a_host_outside_allowed_hosts_is_refused() {
    let server = TestServer::start().await;
    let token = reader();

    let response = server
        .post(
            &[("authorization", &token), (HOST.as_str(), "evil.example")],
            &tools_list(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.text().await.expect("body"),
        "Forbidden: Host header is not allowed"
    );

    // The resource's own host is allowed, on any port.
    for host in ["notes.test.stridelabs.ai", "notes.test.stridelabs.ai:8443"] {
        let response = server
            .post(
                &[("authorization", &token), (HOST.as_str(), host)],
                &tools_list(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{host}");
    }
}

#[tokio::test]
async fn only_the_exact_endpoint_path_is_mcp() {
    let server = TestServer::start().await;
    let token = reader();

    for path in ["/mcp/", "/mcp/anything", "/mcpx"] {
        let response = server
            .post_to(path, &[("authorization", &token)], &tools_list())
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }

    // Stateless with no event store: POST is the only method.
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&token).expect("ASCII"),
    );
    headers.insert("accept", HeaderValue::from_static("text/event-stream"));
    let response = server
        .http
        .get(format!("{}/mcp", server.base))
        .headers(headers)
        .send()
        .await
        .expect("answers");
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    // Without a token, the challenge comes first whatever the method.
    let response = server
        .http
        .get(format!("{}/mcp", server.base))
        .send()
        .await
        .expect("answers");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_tool_served_without_the_auth_layer_is_not_authenticated() {
    // The wiring mistake `ToolCall` guards against: rmcp's service mounted
    // directly, with no `McpAuthLayer` to put a principal in the request.
    use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
    use rmcp::transport::streamable_http_server::StreamableHttpService;

    let (capture, _guard) = Capture::install();
    let service = StreamableHttpService::new(
        || {
            Ok(Notes {
                tool_router: Notes::tool_router(),
            })
        },
        Arc::new(NeverSessionManager::default()),
        stridelabs_mcp::server_config(&resource(), ["127.0.0.1"]),
    );
    let app = axum::Router::new().route_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback port");
    let address = listener.local_addr().expect("local address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let response = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header(CONTENT_TYPE, "application/json")
        .header("accept", "application/json, text/event-stream")
        .json(&tools_call("add_note", json!({"text": "hi"})))
        .send()
        .await
        .expect("answers");
    let body = json_body(response).await;

    assert_eq!(body["result"]["isError"], true);
    assert_eq!(text_of(&body["result"]), "Not authenticated.");
    let line = capture.one_audit_line();
    assert_eq!(line.fields["outcome"], "denied");
    assert_eq!(line.fields["error_class"], "NotAuthenticated");
    assert_eq!(line.fields["required_scopes"], "notes:write");
    assert!(!line.fields.contains_key("sub"), "no caller to name");
}
