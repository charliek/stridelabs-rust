//! `cors_layer()` applied app-wide in front of the metadata router and the
//! authenticated endpoint (feature `cors`): it answers preflights before the
//! auth layer, and decorates every answer — a `200`, the auth layer's `401`
//! and `503` — so a browser client can read `WWW-Authenticate`.

mod support;

use reqwest::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, WWW_AUTHENTICATE,
};
use reqwest::StatusCode;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler};
use serde_json::json;
use stridelabs_mcp::{cors_layer, McpAuthLayer, ToolCall};
use support::*;
use wiremock::ResponseTemplate;

struct Ping {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl Ping {
    #[tool(description = "Liveness.")]
    async fn ping(&self, ctx: RequestContext<RoleServer>) -> Result<CallToolResult, ErrorData> {
        ToolCall::new("ping")
            .run(&ctx, |_principal| async move {
                Ok(CallToolResult::success(vec![ContentBlock::text("pong")]))
            })
            .await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Ping {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

/// The app as a service assembles it: metadata + endpoint, CORS outermost.
async fn start(jwks: &wiremock::MockServer) -> String {
    let resource = resource();
    let app = axum::Router::new()
        .merge(stridelabs_mcp::metadata_router(&resource))
        .merge(stridelabs_mcp::router(
            McpAuthLayer::new(verifier(jwks)),
            stridelabs_mcp::server_config(&resource, ["127.0.0.1"]),
            || {
                Ok(Ping {
                    tool_router: Ping::tool_router(),
                })
            },
        ))
        .layer(cors_layer());
    serve(app).await
}

fn header(response: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<&str> {
    response
        .headers()
        .get(name)
        .map(|value| value.to_str().expect("ASCII"))
}

fn assert_decorated(response: &reqwest::Response) {
    assert_eq!(header(response, ACCESS_CONTROL_ALLOW_ORIGIN), Some("*"));
    let exposed: Vec<String> = header(response, ACCESS_CONTROL_EXPOSE_HEADERS)
        .unwrap_or_default()
        .split(',')
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();
    for name in ["mcp-session-id", "www-authenticate"] {
        assert!(exposed.iter().any(|e| e == name), "{name} in {exposed:?}");
    }
    assert_eq!(header(response, ACCESS_CONTROL_ALLOW_CREDENTIALS), None);
}

async fn cross_origin_post(base: &str, authorization: Option<&str>) -> reqwest::Response {
    let mut headers = vec![("origin", "https://claude.ai")];
    if let Some(authorization) = authorization {
        headers.push(("authorization", authorization));
    }
    post(base, &headers, &tools_call("ping", json!({}))).await
}

#[tokio::test]
async fn a_preflight_is_answered_before_auth_with_the_request_mirrored() {
    let jwks = good_jwks().await;
    let base = start(&jwks).await;

    for origin in [
        "https://claude.ai",
        "https://chatgpt.com",
        "https://evil.example",
    ] {
        let response = reqwest::Client::new()
            .request(reqwest::Method::OPTIONS, format!("{base}/mcp"))
            .header(ORIGIN, origin)
            .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(
                ACCESS_CONTROL_REQUEST_HEADERS,
                "authorization,content-type,mcp-protocol-version",
            )
            .send()
            .await
            .expect("answers");

        assert_eq!(response.status(), StatusCode::OK, "{origin}");
        assert_eq!(header(&response, ACCESS_CONTROL_ALLOW_ORIGIN), Some("*"));
        assert_eq!(
            header(&response, ACCESS_CONTROL_ALLOW_METHODS),
            Some("POST")
        );
        // Mirrored: a `*` would not cover Authorization.
        assert_eq!(
            header(&response, ACCESS_CONTROL_ALLOW_HEADERS),
            Some("authorization,content-type,mcp-protocol-version")
        );
        assert_eq!(header(&response, ACCESS_CONTROL_MAX_AGE), Some("600"));
        assert_eq!(header(&response, ACCESS_CONTROL_ALLOW_CREDENTIALS), None);
        assert_eq!(header(&response, WWW_AUTHENTICATE), None, "auth never ran");
    }
}

#[tokio::test]
async fn an_authenticated_answer_is_decorated() {
    let jwks = good_jwks().await;
    let base = start(&jwks).await;

    let response = cross_origin_post(&base, Some(&token("alice", "notes:read"))).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_decorated(&response);
    let answer: serde_json::Value = response.json().await.expect("JSON");
    assert_eq!(text_of(&answer), "pong");
}

#[tokio::test]
async fn the_401_challenge_is_decorated_and_readable() {
    let jwks = good_jwks().await;
    let base = start(&jwks).await;

    for authorization in [None, Some("Bearer not.a.jwt")] {
        let response = cross_origin_post(&base, authorization).await;

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{authorization:?}"
        );
        assert_decorated(&response);
        assert!(header(&response, WWW_AUTHENTICATE)
            .expect("the challenge")
            .contains("resource_metadata="));
    }
}

#[tokio::test]
async fn a_503_is_decorated() {
    let jwks = support::jwks(ResponseTemplate::new(500)).await;
    let base = start(&jwks).await;

    let response = cross_origin_post(&base, Some(&token("alice", "notes:read"))).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_decorated(&response);
}

#[tokio::test]
async fn the_metadata_document_is_decorated_too() {
    let jwks = good_jwks().await;
    let base = start(&jwks).await;

    let response = reqwest::Client::new()
        .get(format!("{base}/.well-known/oauth-protected-resource/mcp"))
        .header(ORIGIN, "https://claude.ai")
        .send()
        .await
        .expect("answers");

    assert_eq!(response.status(), StatusCode::OK);
    assert_decorated(&response);
}
