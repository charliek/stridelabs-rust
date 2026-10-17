//! The MCP endpoint's HTTP boundary: bearer authentication and its
//! RFC 6750 / RFC 9728 challenges.
//!
//! [`McpAuthLayer`] wraps the endpoint's service. Per request:
//!
//! | Request | Response |
//! |---|---|
//! | no bearer token (no `Authorization`, another scheme, an empty credential) | `401`, `WWW-Authenticate: Bearer resource_metadata="…", scope="…"` — **no** `error` (RFC 6750 §3.1: a request that carried no credential gets no error code) |
//! | a token the verifier refuses ([`VerifyError::Invalid`]) | `401`, `Bearer error="invalid_token", error_description="…", resource_metadata="…", scope="…"` |
//! | the verifier could not decide ([`VerifyError::Unavailable`]) | `503`, `{"error":"temporarily_unavailable", …}` — the client keeps its token |
//! | a valid token missing a [boundary-level scope](McpAuthLayer::with_required_scopes) | `403`, `Bearer error="insufficient_scope", …, scope="…"` |
//! | a valid token | the request, with its [`Principal`] in the extensions and its `Authorization` header removed |
//!
//! Every refusal has a JSON body `{"error": …, "error_description": …}`.
//! Descriptions are fixed text: the verifier's reason (which says *which*
//! check failed) is logged, never returned, because telling a caller which
//! check its token failed is an oracle for whoever is assembling one.
//!
//! The `Authorization` header goes no further than this layer. rmcp hands
//! every tool the request's `Parts`, headers included, and the MCP spec
//! forbids passing a client's token through to anything else; without the
//! header, a tool can neither forward the token nor log it with a
//! `?parts`. The [`Principal`] is what a tool needs.
//!
//! `resource_metadata` points a client at the RFC 9728 document
//! ([`ProtectedResource::metadata_url`]), which names the authorization
//! server; `scope` is the resource's scope hint
//! ([`ProtectedResource::scope_hint`]), omitted when empty.
//!
//! Authorization per tool (scopes) is the [tool boundary](crate::ToolCall)'s
//! job, not this layer's: a `ping` tool needs no scope, and refusing a whole
//! connection for one tool's scope would hide every other tool. The
//! boundary-level required scopes exist for the rare endpoint where *every*
//! request needs the same scope; by default there are none.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes, HttpBody};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, Request, Response, StatusCode};
use axum::BoxError;
use futures::future::BoxFuture;
use serde_json::json;
use stridelabs_auth::bearer_token;
use tower::{Layer, Service};

use crate::principal::Principal;
use crate::resource::ProtectedResource;
use crate::verifier::{McpVerifier, VerifyError};

/// The `tracing` target of the boundary's own log lines.
pub const AUTH_LOG_TARGET: &str = "stridelabs.mcp.auth";

const MISSING_DESCRIPTION: &str =
    "Authentication required: send an access token for this resource as a Bearer token.";
const INVALID_DESCRIPTION: &str = "The access token is invalid or expired.";
const INSUFFICIENT_DESCRIPTION: &str = "The access token lacks a scope this endpoint requires.";
const UNAVAILABLE_DESCRIPTION: &str =
    "The access token could not be verified right now; retry with the same token shortly.";

/// A tower [`Layer`] authenticating every request to the MCP endpoint.
///
/// Built from the [`McpVerifier`], which carries the [`ProtectedResource`]
/// the challenges describe. [`crate::router`] applies it; it is public for an
/// app that assembles the endpoint's service itself.
#[derive(Debug, Clone)]
pub struct McpAuthLayer {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    verifier: McpVerifier,
    required_scopes: BTreeSet<String>,
    /// The two fixed `401` challenges, built once.
    missing_challenge: HeaderValue,
    invalid_challenge: HeaderValue,
}

impl McpAuthLayer {
    /// Authenticate with `verifier`, requiring no scope at the boundary.
    pub fn new(verifier: McpVerifier) -> McpAuthLayer {
        McpAuthLayer::build(verifier, BTreeSet::new())
    }

    /// Additionally require every request's credential to grant all of
    /// `scopes` (`403 insufficient_scope` otherwise). Per-tool scopes, with
    /// [`crate::ToolCall::scopes`], are the norm; this is for an endpoint
    /// whose every request needs the same one.
    pub fn with_required_scopes<I, S>(self, scopes: I) -> McpAuthLayer
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let verifier = self.shared.verifier.clone();
        McpAuthLayer::build(verifier, scopes.into_iter().map(Into::into).collect())
    }

    /// The resource whose endpoint this layer guards.
    pub fn resource(&self) -> &ProtectedResource {
        self.shared.verifier.resource()
    }

    fn build(verifier: McpVerifier, required_scopes: BTreeSet<String>) -> McpAuthLayer {
        let resource = verifier.resource();
        let missing_challenge = challenge(resource, None, resource.scope_hint());
        let invalid_challenge = challenge(
            resource,
            Some(("invalid_token", INVALID_DESCRIPTION)),
            resource.scope_hint(),
        );
        McpAuthLayer {
            shared: Arc::new(Shared {
                verifier,
                required_scopes,
                missing_challenge,
                invalid_challenge,
            }),
        }
    }
}

impl<S> Layer<S> for McpAuthLayer {
    type Service = McpAuthService<S>;

    fn layer(&self, inner: S) -> McpAuthService<S> {
        McpAuthService {
            inner,
            shared: Arc::clone(&self.shared),
        }
    }
}

/// The service [`McpAuthLayer`] produces.
#[derive(Debug, Clone)]
pub struct McpAuthService<S> {
    inner: S,
    shared: Arc<Shared>,
}

impl<S, B, ResBody> Service<Request<B>> for McpAuthService<S>
where
    S: Service<Request<B>, Response = Response<ResBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
    ResBody: HttpBody<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Response<Body>, Infallible>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        // The usual tower dance: the service polled ready is the one that
        // must be called, so take it and leave a fresh clone behind.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let shared = Arc::clone(&self.shared);

        Box::pin(async move {
            let (mut parts, body) = request.into_parts();
            let verdict = match bearer_token(&parts) {
                Ok(token) => shared.verifier.verify(token).await,
                Err(_) => return Ok(shared.missing()),
            };
            let principal = match verdict {
                Ok(principal) => principal,
                Err(VerifyError::Invalid(reason)) => {
                    tracing::debug!(target: AUTH_LOG_TARGET, %reason, "MCP credential rejected");
                    return Ok(shared.invalid());
                }
                Err(VerifyError::Unavailable(reason)) => {
                    tracing::warn!(
                        target: AUTH_LOG_TARGET,
                        %reason,
                        "MCP credential could not be verified; answering 503"
                    );
                    return Ok(unavailable());
                }
            };
            if principal.check_scopes(&shared.required_scopes).is_err() {
                tracing::debug!(
                    target: AUTH_LOG_TARGET,
                    sub = %principal.subject,
                    "MCP credential lacks a boundary-level scope"
                );
                return Ok(shared.insufficient_scope(&principal));
            }

            parts.headers.remove(AUTHORIZATION);
            parts.extensions.insert(principal);
            let response = inner.call(Request::from_parts(parts, body)).await?;
            Ok(response.map(Body::new))
        })
    }
}

impl Shared {
    fn missing(&self) -> Response<Body> {
        refusal(
            StatusCode::UNAUTHORIZED,
            Some(self.missing_challenge.clone()),
            "unauthorized",
            MISSING_DESCRIPTION,
        )
    }

    fn invalid(&self) -> Response<Body> {
        refusal(
            StatusCode::UNAUTHORIZED,
            Some(self.invalid_challenge.clone()),
            "invalid_token",
            INVALID_DESCRIPTION,
        )
    }

    /// The `scope` is what the client should ask for when it re-authorizes:
    /// what it already holds plus what is missing, so stepping up for this
    /// endpoint does not drop a scope another tool needs.
    fn insufficient_scope(&self, principal: &Principal) -> Response<Body> {
        let wanted: BTreeSet<&str> = principal
            .scopes
            .iter()
            .chain(&self.required_scopes)
            .map(String::as_str)
            // A granted scope that is not a scope token cannot be quoted
            // into the header safely; it is dropped rather than escaped.
            .filter(|scope| is_scope_token(scope))
            .collect();
        let wanted = wanted.into_iter().collect::<Vec<_>>().join(" ");
        refusal(
            StatusCode::FORBIDDEN,
            Some(challenge(
                self.verifier.resource(),
                Some(("insufficient_scope", INSUFFICIENT_DESCRIPTION)),
                &wanted,
            )),
            "insufficient_scope",
            INSUFFICIENT_DESCRIPTION,
        )
    }
}

fn unavailable() -> Response<Body> {
    refusal(
        StatusCode::SERVICE_UNAVAILABLE,
        None,
        "temporarily_unavailable",
        UNAVAILABLE_DESCRIPTION,
    )
}

fn refusal(
    status: StatusCode,
    challenge: Option<HeaderValue>,
    error: &str,
    description: &str,
) -> Response<Body> {
    let body = json!({ "error": error, "error_description": description }).to_string();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Some(challenge) = challenge {
        headers.insert(WWW_AUTHENTICATE, challenge);
    }
    response
}

/// A `Bearer` challenge: `error` and `error_description` (when given), then
/// `resource_metadata`, then `scope` (when non-empty).
fn challenge(
    resource: &ProtectedResource,
    error: Option<(&str, &str)>,
    scope: &str,
) -> HeaderValue {
    let mut params = Vec::new();
    if let Some((code, description)) = error {
        params.push(format!("error={}", quoted(code)));
        params.push(format!("error_description={}", quoted(description)));
    }
    params.push(format!(
        "resource_metadata={}",
        quoted(resource.metadata_url())
    ));
    if !scope.is_empty() {
        params.push(format!("scope={}", quoted(scope)));
    }
    HeaderValue::try_from(format!("Bearer {}", params.join(", ")))
        // Every input is a fixed string or validated by `ProtectedResource`
        // (printable ASCII, no `"` or `\`) or filtered by `is_scope_token`.
        .expect("a challenge built from validated parts is a valid header value")
}

/// An RFC 9110 quoted-string. The inputs never need it (see `challenge`),
/// but the escaping is what makes the header correct regardless.
fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        if matches!(c, '"' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// RFC 6749 §3.3 `scope-token`.
fn is_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b))
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::routing::post;
    use axum::{Extension, Router};
    use serde_json::{json, Value};
    use stridelabs_auth::test_support::{TestClaims, TestKey};
    use tower::ServiceExt;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::principal::AuthMethod;

    const ISSUER: &str = "https://auth.test.stridelabs.ai";
    const RESOURCE: &str = "https://parcel.stridelabs.ai/mcp";
    const METADATA: &str = "https://parcel.stridelabs.ai/.well-known/oauth-protected-resource/mcp";

    fn resource() -> ProtectedResource {
        ProtectedResource::new(RESOURCE, ISSUER, ["parcel:read", "parcel:write"])
            .expect("canonical")
    }

    async fn issuer(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    async fn jwks_issuer() -> MockServer {
        issuer(
            ResponseTemplate::new(200)
                .set_body_raw(TestKey::primary().jwks_json(), "application/json"),
        )
        .await
    }

    /// An endpoint that echoes the principal the layer inserted, and
    /// whether the `Authorization` header got through.
    fn app(layer: McpAuthLayer) -> Router {
        Router::new().route(
            "/mcp",
            post(
                |Extension(principal): Extension<Principal>, headers: axum::http::HeaderMap| async move {
                    axum::Json(json!({
                        "sub": principal.subject,
                        "scopes": principal.scopes,
                        "auth_method": principal.auth_method.as_str(),
                        "saw_authorization": headers.contains_key(AUTHORIZATION),
                    }))
                },
            )
            .layer(layer),
        )
    }

    fn layer_for(server: &MockServer) -> McpAuthLayer {
        McpAuthLayer::new(McpVerifier::new(
            &resource(),
            format!("{}/jwks", server.uri()),
            reqwest::Client::new(),
        ))
    }

    struct Answer {
        status: StatusCode,
        challenge: Option<String>,
        body: Value,
    }

    async fn send(app: Router, authorization: Option<&str>) -> Answer {
        let mut request = Request::builder().method("POST").uri("/mcp");
        if let Some(value) = authorization {
            request = request.header("authorization", value);
        }
        let response = app
            .oneshot(request.body(Body::empty()).expect("request"))
            .await
            .expect("infallible");
        let status = response.status();
        let challenge = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .map(|value| value.to_str().expect("ASCII header").to_owned());
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .map(|v| v.to_str().unwrap()),
            Some("application/json")
        );
        let bytes = to_bytes(response.into_body(), 1 << 16).await.expect("body");
        Answer {
            status,
            challenge,
            body: serde_json::from_slice(&bytes).expect("a JSON body"),
        }
    }

    fn token(claims: TestClaims) -> String {
        format!("Bearer {}", TestKey::primary().mint(&claims.build()))
    }

    fn mcp_claims() -> TestClaims {
        TestClaims::new(ISSUER, RESOURCE)
    }

    #[tokio::test]
    async fn no_credential_is_a_401_with_no_error_code() {
        let server = MockServer::start().await;
        for authorization in [
            None,
            Some("Basic dXNlcjpwYXNz"),
            Some("Bearer "),
            Some("token"),
        ] {
            let answer = send(app(layer_for(&server)), authorization).await;

            assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{authorization:?}");
            assert_eq!(
                answer.challenge.as_deref(),
                Some(
                    "Bearer resource_metadata=\"https://parcel.stridelabs.ai/.well-known/\
                     oauth-protected-resource/mcp\", scope=\"parcel:read parcel:write\""
                ),
                "{authorization:?}"
            );
            assert_eq!(answer.body["error"], "unauthorized");
            assert_eq!(answer.body["error_description"], MISSING_DESCRIPTION);
        }
        assert!(server
            .received_requests()
            .await
            .expect("recording")
            .is_empty());
    }

    #[tokio::test]
    async fn every_refused_token_gets_the_same_invalid_token_challenge() {
        let server = jwks_issuer().await;
        let expected = format!(
            "Bearer error=\"invalid_token\", error_description=\"{INVALID_DESCRIPTION}\", \
             resource_metadata=\"{METADATA}\", scope=\"parcel:read parcel:write\""
        );
        let wrong_key = format!(
            "Bearer {}",
            TestKey::secondary().mint_with_kid(TestKey::primary().kid(), &mcp_claims().build())
        );

        for (case, authorization) in [
            ("malformed", "Bearer not-a-jwt".to_owned()),
            (
                "wrong audience",
                token(TestClaims::new(ISSUER, "parcel-rest-api")),
            ),
            (
                "wrong issuer",
                token(TestClaims::new("https://evil.example", RESOURCE)),
            ),
            ("expired", token(mcp_claims().expires_in(-3600))),
            ("empty subject", token(mcp_claims().subject(""))),
            ("wrong key", wrong_key),
        ] {
            let answer = send(app(layer_for(&server)), Some(&authorization)).await;

            assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{case}");
            assert_eq!(
                answer.challenge.as_deref(),
                Some(expected.as_str()),
                "{case}"
            );
            assert_eq!(
                answer.body,
                json!({"error": "invalid_token", "error_description": INVALID_DESCRIPTION}),
                "{case}: the body names no specific check"
            );
        }
    }

    #[tokio::test]
    async fn a_jwks_outage_is_a_503_that_keeps_the_token() {
        let server = issuer(ResponseTemplate::new(500)).await;

        let answer = send(app(layer_for(&server)), Some(&token(mcp_claims()))).await;

        assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            answer.challenge, None,
            "no challenge: the token is not at fault"
        );
        assert_eq!(
            answer.body,
            json!({"error": "temporarily_unavailable", "error_description": UNAVAILABLE_DESCRIPTION})
        );
    }

    #[tokio::test]
    async fn a_valid_token_reaches_the_service_with_its_principal() {
        let server = jwks_issuer().await;
        let authorization = token(
            mcp_claims()
                .subject("kratos-1")
                .claim("scope", json!("parcel:read")),
        );

        let answer = send(app(layer_for(&server)), Some(&authorization)).await;

        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(
            answer.body,
            json!({
                "sub": "kratos-1",
                "scopes": ["parcel:read"],
                "auth_method": "jwt",
                "saw_authorization": false,
            })
        );
    }

    #[tokio::test]
    async fn boundary_scopes_refuse_with_insufficient_scope() {
        let server = jwks_issuer().await;
        let layer = layer_for(&server).with_required_scopes(["parcel:write"]);
        let authorization = token(mcp_claims().claim("scope", json!("parcel:read offline_access")));

        let answer = send(app(layer.clone()), Some(&authorization)).await;

        assert_eq!(answer.status, StatusCode::FORBIDDEN);
        assert_eq!(
            answer.challenge.as_deref(),
            Some(
                format!(
                    "Bearer error=\"insufficient_scope\", \
                     error_description=\"{INSUFFICIENT_DESCRIPTION}\", \
                     resource_metadata=\"{METADATA}\", \
                     scope=\"offline_access parcel:read parcel:write\""
                )
                .as_str()
            )
        );
        assert_eq!(answer.body["error"], "insufficient_scope");

        let granted = token(mcp_claims().claim("scope", json!("parcel:write")));
        assert_eq!(
            send(app(layer), Some(&granted)).await.status,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn app_credentials_reach_the_service_as_tokens() {
        let server = MockServer::start().await;
        let verifier = McpVerifier::new(&resource(), server.uri(), reqwest::Client::new())
            .with_credential("pcl_", |token: String| async move {
                if token == "pcl_good" {
                    Ok(Principal::new(
                        "owner-1",
                        ["parcel:read"],
                        AuthMethod::Token,
                    ))
                } else if token == "pcl_down" {
                    Err(VerifyError::unavailable("token store unreachable"))
                } else {
                    Err(VerifyError::invalid("unknown token"))
                }
            });
        let layer = McpAuthLayer::new(verifier);

        let ok = send(app(layer.clone()), Some("Bearer pcl_good")).await;
        assert_eq!(ok.status, StatusCode::OK);
        assert_eq!(ok.body["auth_method"], "token");

        let bad = send(app(layer.clone()), Some("Bearer pcl_bad")).await;
        assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
        assert_eq!(bad.body["error"], "invalid_token");

        let down = send(app(layer), Some("Bearer pcl_down")).await;
        assert_eq!(down.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn an_empty_scope_hint_omits_the_scope_parameter() {
        let resource = resource().with_scope_hint("").expect("empty hint");

        let header = challenge(&resource, None, resource.scope_hint());

        assert_eq!(header, format!("Bearer resource_metadata=\"{METADATA}\""));
    }

    #[test]
    fn quoted_strings_escape_quotes_and_backslashes() {
        assert_eq!(quoted("plain"), "\"plain\"");
        assert_eq!(quoted(r#"a"b\c"#), r#""a\"b\\c""#);
    }
}
