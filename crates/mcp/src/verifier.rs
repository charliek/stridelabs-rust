//! Credential verification for an MCP endpoint backed by slauth.
//!
//! [`McpVerifier`] accepts two kinds of bearer credential:
//!
//! - **slauth RS256 JWTs**, verified against slauth's JWKS with the
//!   **audience = the canonical MCP resource URL** — not the app's REST
//!   audience. An MCP connector's token is minted for the resource it named
//!   (RFC 8707), so a REST token is refused here and an MCP token is refused
//!   by the REST API: neither can be replayed against the other. The
//!   verifier builds its own [`stridelabs_auth::Verifier`] (with its own JWKS
//!   cache) from the [`ProtectedResource`], so that audience cannot drift
//!   from the metadata document's `resource`.
//! - **Credentials the app verifies itself**, selected by prefix: slauth
//!   personal access tokens (`slp_live_…`), or the app's own API tokens.
//!   Each prefix maps to a [`CredentialVerifier`] the app supplies.
//!
//! # Invalid versus unavailable
//!
//! [`VerifyError`] keeps the two failures a client must tell apart apart:
//! [`VerifyError::Invalid`] (the credential was checked and refused: `401`,
//! the client should re-authorize) and [`VerifyError::Unavailable`] (the
//! service that decides could not be reached: `503`, the client should retry
//! with the same credential). A JWKS fetch failure is `Unavailable` — never
//! sign a client out because slauth had a blip. The key set stridelabs-auth
//! cached before an outage keeps verifying tokens only until it goes stale,
//! about `JWKS_TTL` (an hour) after its last successful fetch (the exact
//! bound is in [`stridelabs_auth::jwks`]); from then until slauth answers
//! again every JWT is `Unavailable`. A long outage is a run of `503`s, never
//! of `401`s.
//!
//! # Errors never echo the credential
//!
//! The rule is stridelabs-auth's: no error carries the token, a claim value
//! or the `kid`, all attacker-supplied on exactly the requests that fail.
//! The JWT path's reasons are [`stridelabs_auth::AuthError`]'s fixed
//! phrases; a [`CredentialVerifier`] must keep to the same rule, since its
//! reasons are logged.

use std::borrow::Cow;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::Deserialize;
use stridelabs_auth::{AuthError, SlauthConfig, Verifier};

use crate::principal::{AuthMethod, Principal};
use crate::resource::ProtectedResource;

/// Why a credential was not accepted.
///
/// The payload is a reason for the logs, never shown to the client (the
/// boundary answers with fixed text), and it must never contain any part of
/// the credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The credential was checked and refused → `401 invalid_token`.
    #[error("credential rejected: {0}")]
    Invalid(Cow<'static, str>),
    /// Whatever decides could not be reached (slauth's JWKS endpoint, the
    /// app's token store, slauth's PAT introspection) → `503`. The client
    /// keeps its credential and retries.
    #[error("credential check unavailable: {0}")]
    Unavailable(Cow<'static, str>),
}

impl VerifyError {
    /// [`VerifyError::Invalid`] with a fixed reason.
    pub fn invalid(reason: impl Into<Cow<'static, str>>) -> VerifyError {
        VerifyError::Invalid(reason.into())
    }

    /// [`VerifyError::Unavailable`] with a fixed reason.
    pub fn unavailable(reason: impl Into<Cow<'static, str>>) -> VerifyError {
        VerifyError::Unavailable(reason.into())
    }
}

/// [`AuthError::Jwks`] is the server's outage, so it is `Unavailable`;
/// everything else is a verdict on the token. `AuthError`'s messages are
/// already redaction-safe (fixed phrases, URL-free), so they are kept.
impl From<AuthError> for VerifyError {
    fn from(err: AuthError) -> VerifyError {
        match err {
            AuthError::Jwks(_) => VerifyError::Unavailable(err.to_string().into()),
            _ => VerifyError::Invalid(err.to_string().into()),
        }
    }
}

/// The future a [`CredentialVerifier`] returns.
pub type VerifyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Principal, VerifyError>> + Send + 'a>>;

/// An app-supplied check for a non-JWT credential, selected by prefix with
/// [`McpVerifier::with_credential`].
///
/// Return the caller's [`Principal`] (built with [`Principal::new`]; its
/// scopes are whatever the credential grants — for slauth PATs, which carry
/// none, the app's scope ceiling), [`VerifyError::Invalid`] for a credential
/// that is unknown, revoked or expired, or [`VerifyError::Unavailable`] when
/// the store that decides could not be reached. The verifier records the
/// result as [`AuthMethod::Token`] whatever the principal says, and refuses
/// an empty subject.
///
/// Any `Fn(String) -> impl Future<Output = Result<Principal, VerifyError>>`
/// closure is one:
///
/// ```
/// use stridelabs_mcp::{AuthMethod, Principal, VerifyError};
///
/// let check = |token: String| async move {
///     match token.as_str() {
///         "pcl_good" => Ok(Principal::new("user-1", ["parcel:read"], AuthMethod::Token)),
///         _ => Err(VerifyError::invalid("unknown or revoked token")),
///     }
/// };
/// # fn assert_verifier(_: impl stridelabs_mcp::CredentialVerifier) {}
/// # assert_verifier(check);
/// ```
pub trait CredentialVerifier: Send + Sync + 'static {
    /// Verify `token` (the whole credential, prefix included).
    fn verify<'a>(&'a self, token: &'a str) -> VerifyFuture<'a>;
}

impl<F, Fut> CredentialVerifier for F
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Principal, VerifyError>> + Send + 'static,
{
    fn verify<'a>(&'a self, token: &'a str) -> VerifyFuture<'a> {
        Box::pin(self(token.to_owned()))
    }
}

/// Verifies MCP bearer credentials for one [`ProtectedResource`].
///
/// Cheap to clone, and meant to be built once: the JWKS cache lives inside.
#[derive(Clone)]
pub struct McpVerifier {
    resource: ProtectedResource,
    jwt: Verifier,
    credentials: Arc<[(String, Arc<dyn CredentialVerifier>)]>,
}

impl McpVerifier {
    /// A verifier for JWTs minted for `resource` by its issuer, fetching the
    /// issuer's keys from `jwks_url` with `http`.
    ///
    /// The audience is `resource.url()` and the issuer `resource.issuer()`,
    /// by construction. `http` is the app's client: its TLS stack is the
    /// app's choice (this crate's `reqwest` has no TLS feature).
    pub fn new(
        resource: &ProtectedResource,
        jwks_url: impl Into<String>,
        http: reqwest::Client,
    ) -> McpVerifier {
        let jwt = Verifier::new(
            SlauthConfig {
                issuer: resource.issuer().to_owned(),
                jwks_url: jwks_url.into(),
                audience: resource.url().to_owned(),
                pat_validate_url: None,
            },
            http,
        );
        McpVerifier {
            resource: resource.clone(),
            jwt,
            credentials: Arc::new([]),
        }
    }

    /// Route every credential starting with `prefix` to `verifier` instead of
    /// the JWT check.
    ///
    /// Prefixes are tried in the order they were added, and the first match
    /// wins; a JWT never matches a prefix that is not a prefix of `eyJ`. An
    /// empty prefix matches every credential, which turns the JWT path off.
    pub fn with_credential(
        mut self,
        prefix: impl Into<String>,
        verifier: impl CredentialVerifier,
    ) -> McpVerifier {
        let mut credentials = self.credentials.to_vec();
        credentials.push((prefix.into(), Arc::new(verifier)));
        self.credentials = credentials.into();
        self
    }

    /// The resource this verifier checks tokens for.
    pub fn resource(&self) -> &ProtectedResource {
        &self.resource
    }

    /// Verify a bearer credential (the part after `Bearer `).
    ///
    /// For a JWT: everything stridelabs-auth checks (an RS256-fit key under
    /// the `kid`, the signature, `exp`, `iss`, `aud`), then a non-empty
    /// `sub`. Scopes are the union of `scope` (a space-separated string) and
    /// `scp` (Hydra's array); either claim may be a string or an array.
    /// `client_id` comes from `client_id`, else `azp`. `email` and `name`
    /// are optional; an empty one counts as absent.
    pub async fn verify(&self, token: &str) -> Result<Principal, VerifyError> {
        if let Some((_, verifier)) = self
            .credentials
            .iter()
            .find(|(prefix, _)| token.starts_with(prefix.as_str()))
        {
            let mut principal = verifier.verify(token).await?;
            if principal.subject.is_empty() {
                return Err(VerifyError::invalid(
                    "credential resolved to an empty subject",
                ));
            }
            principal.auth_method = AuthMethod::Token;
            return Ok(principal);
        }

        let claims: McpClaims = self.jwt.verify_bearer_claims(token).await?;
        claims.into_principal()
    }
}

impl fmt::Debug for McpVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefixes: Vec<&str> = self
            .credentials
            .iter()
            .map(|(prefix, _)| prefix.as_str())
            .collect();
        f.debug_struct("McpVerifier")
            .field("resource", &self.resource.url())
            // stridelabs-auth's `Debug` redacts the JWKS URL.
            .field("jwt", &self.jwt)
            .field("credential_prefixes", &prefixes)
            .finish()
    }
}

/// The claims an MCP access token is read for. Everything is optional at
/// this level so that a missing claim fails a documented check, not a
/// deserialization error.
#[derive(Deserialize)]
struct McpClaims {
    #[serde(default)]
    sub: String,
    #[serde(default)]
    scope: Option<ScopeClaim>,
    #[serde(default)]
    scp: Option<ScopeClaim>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// A scope claim in either shape issuers use: a space-separated string
/// (RFC 6749 / RFC 9068 `scope`) or an array (Hydra's `scp`).
#[derive(Deserialize)]
#[serde(untagged)]
enum ScopeClaim {
    Joined(String),
    List(Vec<String>),
}

impl ScopeClaim {
    fn into_scopes(self) -> Vec<String> {
        match self {
            ScopeClaim::Joined(joined) => joined.split_whitespace().map(str::to_owned).collect(),
            // Array items are scopes already; an item with a space in it is
            // not a scope token and simply never matches a required one.
            ScopeClaim::List(list) => list.into_iter().filter(|scope| !scope.is_empty()).collect(),
        }
    }
}

impl McpClaims {
    fn into_principal(self) -> Result<Principal, VerifyError> {
        // Tools key users on the subject: an empty one would make every such
        // token the same user.
        if self.sub.is_empty() {
            return Err(AuthError::MissingSubject.into());
        }
        let present = |value: Option<String>| value.filter(|value| !value.is_empty());
        let scopes = [self.scope, self.scp]
            .into_iter()
            .flatten()
            .flat_map(ScopeClaim::into_scopes);
        let mut principal = Principal::new(self.sub, scopes, AuthMethod::Jwt);
        principal.client_id = present(self.client_id).or_else(|| present(self.azp));
        principal.email = present(self.email);
        principal.name = present(self.name);
        Ok(principal)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};
    use stridelabs_auth::test_support::{TestClaims, TestKey};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const ISSUER: &str = "https://auth.test.stridelabs.ai";

    fn resource() -> ProtectedResource {
        ProtectedResource::new(
            "https://parcel.stridelabs.ai/mcp",
            ISSUER,
            ["parcel:read", "parcel:write"],
        )
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

    fn verifier(server: &MockServer) -> McpVerifier {
        McpVerifier::new(
            &resource(),
            format!("{}/jwks", server.uri()),
            reqwest::Client::new(),
        )
    }

    fn mcp_claims() -> TestClaims {
        TestClaims::new(ISSUER, "https://parcel.stridelabs.ai/mcp")
    }

    async fn verify(claims: Value) -> Result<Principal, VerifyError> {
        let server = jwks_issuer().await;
        verifier(&server)
            .verify(&TestKey::primary().mint(&claims))
            .await
    }

    #[tokio::test]
    async fn scopes_come_from_scope_scp_or_both() {
        for (claims, expected) in [
            (
                mcp_claims().claim("scope", json!("parcel:read  parcel:write")),
                vec!["parcel:read", "parcel:write"],
            ),
            (
                mcp_claims().claim("scp", json!(["parcel:read"])),
                vec!["parcel:read"],
            ),
            (
                mcp_claims()
                    .claim("scope", json!("parcel:read offline_access"))
                    .claim("scp", json!(["parcel:write", "parcel:read", ""])),
                vec!["offline_access", "parcel:read", "parcel:write"],
            ),
            // Either claim in the other shape.
            (
                mcp_claims()
                    .claim("scope", json!(["parcel:read"]))
                    .claim("scp", json!("parcel:write")),
                vec!["parcel:read", "parcel:write"],
            ),
            (mcp_claims(), vec![]),
        ] {
            let principal = verify(claims.build()).await.expect("valid token");
            let scopes: Vec<&str> = principal.scopes.iter().map(String::as_str).collect();
            assert_eq!(scopes, expected);
            assert_eq!(principal.auth_method, AuthMethod::Jwt);
        }
    }

    #[tokio::test]
    async fn identity_claims_are_optional_and_client_id_falls_back_to_azp() {
        let principal = verify(
            mcp_claims()
                .subject("kratos-1")
                .without_email()
                .without_name()
                .claim("azp", json!("connector-azp"))
                .build(),
        )
        .await
        .expect("an MCP token needs no email");
        assert_eq!(principal.subject, "kratos-1");
        assert_eq!(principal.email, None);
        assert_eq!(principal.name, None);
        assert_eq!(principal.client_id.as_deref(), Some("connector-azp"));

        let principal = verify(
            mcp_claims()
                .email("")
                .claim("client_id", json!("connector-1"))
                .claim("azp", json!("connector-azp"))
                .build(),
        )
        .await
        .expect("valid token");
        assert_eq!(principal.email, None, "an empty email counts as absent");
        assert_eq!(principal.name.as_deref(), Some("Test User"));
        assert_eq!(principal.client_id.as_deref(), Some("connector-1"));
    }

    #[tokio::test]
    async fn an_empty_or_missing_subject_is_invalid() {
        let mut without_sub = mcp_claims().build();
        without_sub
            .as_object_mut()
            .expect("claims are an object")
            .remove("sub");

        for claims in [mcp_claims().subject("").build(), without_sub] {
            assert_eq!(
                verify(claims).await,
                Err(VerifyError::invalid("token is missing a subject claim"))
            );
        }
    }

    #[tokio::test]
    async fn a_token_for_another_audience_or_issuer_is_invalid() {
        for (claims, reason) in [
            (
                TestClaims::new(ISSUER, "parcel-rest-api"),
                "token rejected: audience is not accepted",
            ),
            (
                // The resource URL with a trailing slash is another audience.
                TestClaims::new(ISSUER, "https://parcel.stridelabs.ai/mcp/"),
                "token rejected: audience is not accepted",
            ),
            (
                TestClaims::new("https://evil.example", "https://parcel.stridelabs.ai/mcp"),
                "token rejected: issuer is not accepted",
            ),
            (
                mcp_claims().expires_in(-3600),
                "token rejected: token has expired",
            ),
        ] {
            assert_eq!(
                verify(claims.build()).await,
                Err(VerifyError::invalid(reason))
            );
        }
    }

    #[tokio::test]
    async fn a_malformed_scope_claim_is_invalid_and_not_quoted() {
        let err = verify(mcp_claims().claim("scope", json!({"hunter2": 1})).build())
            .await
            .unwrap_err();

        assert_eq!(
            err,
            VerifyError::invalid("token rejected: claims are malformed")
        );
        assert!(!err.to_string().contains("hunter2"));
    }

    #[tokio::test]
    async fn a_jwks_outage_is_unavailable_not_invalid() {
        let server = issuer(ResponseTemplate::new(500)).await;
        let token = TestKey::primary().mint(&mcp_claims().build());

        let err = verifier(&server).verify(&token).await.unwrap_err();

        assert!(matches!(err, VerifyError::Unavailable(_)), "{err}");
        assert!(!err.to_string().contains(&server.uri()), "{err}");
    }

    #[tokio::test]
    async fn prefixed_credentials_go_to_the_app_and_are_tokens() {
        // No JWKS mock: reaching the issuer for a prefixed credential is the bug.
        let server = MockServer::start().await;
        let verifier = verifier(&server)
            .with_credential("pcl_", |token: String| async move {
                match token.as_str() {
                    // Claims to be a JWT principal; recorded as a token anyway.
                    "pcl_good" => Ok(Principal::new("user-7", ["parcel:read"], AuthMethod::Jwt)),
                    "pcl_empty" => Ok(Principal::new("", ["parcel:read"], AuthMethod::Token)),
                    "pcl_down" => Err(VerifyError::unavailable("token store unreachable")),
                    _ => Err(VerifyError::invalid("unknown token")),
                }
            })
            .with_credential("slp_live_", |_token: String| async move {
                Ok(Principal::new(
                    "pat-user",
                    ["parcel:read", "parcel:write"],
                    AuthMethod::Token,
                ))
            });

        let principal = verifier.verify("pcl_good").await.expect("known token");
        assert_eq!(principal.subject, "user-7");
        assert_eq!(principal.auth_method, AuthMethod::Token);

        let principal = verifier.verify("slp_live_abc").await.expect("PAT");
        assert_eq!(principal.subject, "pat-user");

        assert_eq!(
            verifier.verify("pcl_bad").await,
            Err(VerifyError::invalid("unknown token"))
        );
        assert_eq!(
            verifier.verify("pcl_down").await,
            Err(VerifyError::unavailable("token store unreachable"))
        );
        assert_eq!(
            verifier.verify("pcl_empty").await,
            Err(VerifyError::invalid(
                "credential resolved to an empty subject"
            ))
        );
        // Not a prefix match, so the JWT path, which refuses it unfetched.
        assert_eq!(
            verifier.verify("pcx_good").await,
            Err(VerifyError::invalid("malformed token"))
        );
        assert!(server
            .received_requests()
            .await
            .expect("recording")
            .is_empty());
    }

    #[test]
    fn debug_shows_prefixes_and_no_url_secrets() {
        let verifier = McpVerifier::new(
            &resource(),
            "https://auth.example/jwks?token=SECRET",
            reqwest::Client::new(),
        )
        .with_credential("pcl_", |_: String| async {
            Err(VerifyError::invalid("never"))
        });

        let debug = format!("{verifier:?}");

        assert!(debug.contains("pcl_"), "{debug}");
        assert!(
            debug.contains("https://parcel.stridelabs.ai/mcp"),
            "{debug}"
        );
        assert!(!debug.contains("SECRET"), "{debug}");
    }
}
