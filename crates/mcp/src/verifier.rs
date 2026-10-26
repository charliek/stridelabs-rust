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
//! sign a client out because slauth had a blip. stridelabs-auth refreshes
//! its key set ahead of expiry, so a blip near the hour costs nothing while
//! requests keep arriving in the refresh window; but the set it cached
//! before an outage verifies tokens only until its TTL, exactly `JWKS_TTL`
//! (an hour) after its last successful fetch, never past it (see
//! [`stridelabs_auth::jwks`]). From then until slauth answers again every JWT
//! is `Unavailable`. Once slauth is back, the cache recovers within what is
//! left of a fetch still failing, the backoff and one successful fetch
//! (about 28 s at the defaults), provided requests keep arriving: with none,
//! the first one to arrive starts that fetch. A long outage is a run of
//! `503`s, never of `401`s. A token whose `kid` the cache has never seen,
//! presented inside its refetch floor ([`stridelabs_auth::AuthError::UnseenKid`]:
//! possibly a rotation not fetched yet), is `Unavailable` too; a retired
//! key's is `Invalid`, so a client re-authorizes at once.
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
use stridelabs_auth::{
    Audience, AuthError, ClaimChecks, JwksCache, ScreenPolicy, SlauthConfig, Verifier,
};

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

/// [`AuthError::Jwks`] is the server's outage, [`AuthError::UnseenKid`] a
/// refetch the server suppressed, and [`AuthError::UnusableKey`] (only from
/// a cache that reports unusable keys) the issuer's broken key, so all three
/// are `Unavailable`; everything else is a verdict on the token.
/// `AuthError`'s messages are already redaction-safe (fixed phrases,
/// URL-free, no kid), so they are kept.
impl From<AuthError> for VerifyError {
    fn from(err: AuthError) -> VerifyError {
        match err {
            AuthError::Jwks(_) | AuthError::UnseenKid | AuthError::UnusableKey(_) => {
                VerifyError::Unavailable(err.to_string().into())
            }
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

/// Which of a JWT's scope claims a [`McpVerifier`] reads
/// ([`McpVerifier::with_scope_source`]).
///
/// Either way, each claim may be a space-separated string or an array, and
/// either claim present in any other shape (a number, an object, an array
/// holding a non-string) is [`VerifyError::Invalid`], even one this source
/// would not read. A `null` claim counts as absent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeSource {
    /// The union of `scope` and `scp`: what every [`McpVerifier`] has always
    /// granted, and the default.
    #[default]
    Union,
    /// `scope` when the token carries it, else `scp`: the precedence fastmcp
    /// (and so a Python MCP server built on it) applies. A `scope` that is
    /// present but empty grants nothing, whatever `scp` holds. Never more
    /// than [`ScopeSource::Union`] grants: for a token carrying both, a
    /// scope only `scp` names is not granted.
    ScopeThenScp,
}

/// Why [`McpVerifier::with_cache`] refused its [`ClaimChecks`]: they would
/// check tokens for something other than the [`ProtectedResource`].
///
/// Startup configuration errors with fixed messages, quoting neither value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimChecksError {
    /// The checks' issuer is not the resource's issuer, exactly.
    #[error("the claim checks' issuer is not the MCP resource's issuer")]
    IssuerMismatch,
    /// The checks' audience is not [`Audience::Required`] with the resource
    /// URL: an MCP token must name the resource it was minted for.
    #[error("the claim checks' audience must be required and equal to the MCP resource URL")]
    AudienceMismatch,
}

/// Verifies MCP bearer credentials for one [`ProtectedResource`].
///
/// Cheap to clone, and meant to be built once: the JWKS cache lives inside.
#[derive(Clone)]
pub struct McpVerifier {
    resource: ProtectedResource,
    jwt: Verifier,
    scope_source: ScopeSource,
    credentials: Arc<[(String, Arc<dyn CredentialVerifier>)]>,
}

impl McpVerifier {
    /// A verifier for JWTs minted for `resource` by its issuer, fetching the
    /// issuer's keys from `jwks_url` with `http`.
    ///
    /// The audience is `resource.url()` and the issuer `resource.issuer()`,
    /// by construction. `http` is the app's client: its TLS stack is the
    /// app's choice (this crate's `reqwest` has no TLS feature).
    ///
    /// The claim rules are [`Verifier::new`]'s: a 60 s leeway on `exp`, and
    /// `nbf` not checked. [`McpVerifier::with_cache`] takes the consumer's.
    ///
    /// Neither of stridelabs-auth's claim type rules is on here: an `iss`
    /// array that holds the issuer passes, and so does a fractional `exp`
    /// (jsonwebtoken rounds it). Both are opt-in through
    /// [`McpVerifier::with_cache`], with
    /// `resource.claim_checks().with_integer_time_claims(true).with_string_issuer(true)`
    /// as its checks and `JwksCache::new(jwks_url, http)` in place of this
    /// function's last two arguments. Those checks have
    /// [`ProtectedResource::claim_checks`]'s defaults, `nbf` checked among
    /// them; `.with_nbf_validation(false)` keeps this function's `nbf` rule.
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
        McpVerifier::from_jwt(resource, jwt)
    }

    /// A verifier for JWTs minted for `resource`, under the consumer's
    /// `checks`, with keys from the consumer's `cache`: what
    /// [`Verifier::with_cache`] is to [`Verifier::new`], so an MCP endpoint
    /// can apply the claim rules its REST API does (a zero leeway, `nbf`
    /// checked) and the cache settings it chose
    /// ([`JwksCache::report_unusable_keys`], its TTL and refetch interval).
    ///
    /// `checks` must still be the resource's: its issuer `resource.issuer()`
    /// exactly, and its audience [`Audience::Required`] with
    /// `resource.url()`. [`ProtectedResource::claim_checks`] starts from
    /// those; anything else is a [`ClaimChecksError`], so the audience still
    /// cannot drift from the metadata document's `resource`. Pairing `cache`
    /// with the issuer is the caller's job, as for [`Verifier::with_cache`]:
    /// build it from the same configuration.
    ///
    /// The claim type rules are opt-in here, through `checks`, and off by
    /// default: [`ClaimChecks::with_integer_time_claims`] (each `exp`, `nbf`
    /// and `iat` a non-negative JSON integer) and
    /// [`ClaimChecks::with_string_issuer`] (`iss` a JSON string, never an
    /// array holding the issuer). An MCP endpoint whose REST API, or whose
    /// Python twin, refuses those tokens turns them on to match:
    ///
    /// ```no_run
    /// # fn example(http: reqwest::Client) -> Result<(), Box<dyn std::error::Error>> {
    /// use std::time::Duration;
    ///
    /// use stridelabs_auth::{JwksCache, ScreenPolicy};
    /// use stridelabs_mcp::{McpVerifier, ProtectedResource, ScopeSource};
    ///
    /// let resource = ProtectedResource::new(
    ///     "https://parcel.stridelabs.ai/mcp",
    ///     "https://auth.stridelabs.ai",
    ///     ["parcel:read"],
    /// )?;
    /// let cache = JwksCache::new("https://auth.stridelabs.ai/jwks.json", http)
    ///     .report_unusable_keys(true);
    /// let verifier = McpVerifier::with_cache(
    ///     &resource,
    ///     resource
    ///         .claim_checks()
    ///         .with_leeway(Duration::ZERO)
    ///         .with_integer_time_claims(true)
    ///         .with_string_issuer(true),
    ///     cache,
    /// )?
    /// .screen(ScreenPolicy::Strict)
    /// .with_scope_source(ScopeSource::ScopeThenScp);
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_cache(
        resource: &ProtectedResource,
        checks: ClaimChecks,
        cache: JwksCache,
    ) -> Result<McpVerifier, ClaimChecksError> {
        if checks.issuer() != resource.issuer() {
            return Err(ClaimChecksError::IssuerMismatch);
        }
        if !matches!(checks.audience(), Audience::Required(audience) if audience == resource.url())
        {
            return Err(ClaimChecksError::AudienceMismatch);
        }
        Ok(McpVerifier::from_jwt(
            resource,
            Verifier::with_cache(checks, cache),
        ))
    }

    fn from_jwt(resource: &ProtectedResource, jwt: Verifier) -> McpVerifier {
        McpVerifier {
            resource: resource.clone(),
            jwt,
            scope_source: ScopeSource::default(),
            credentials: Arc::new([]),
        }
    }

    /// This verifier with `policy` deciding what is checked before a JWT's
    /// key is looked up ([`Verifier::screen`]; [`ScreenPolicy::Basic`] by
    /// default). [`ScreenPolicy::Strict`] refuses a malformed or non-RS256
    /// token before any JWKS fetch, so never with an outage's `503`.
    #[must_use]
    pub fn screen(mut self, policy: ScreenPolicy) -> McpVerifier {
        self.jwt = self.jwt.screen(policy);
        self
    }

    /// This verifier reading scopes from `source` ([`ScopeSource::Union`] by
    /// default).
    #[must_use]
    pub fn with_scope_source(mut self, source: ScopeSource) -> McpVerifier {
        self.scope_source = source;
        self
    }

    /// The claim rules a JWT is checked against ([`Verifier::claim_checks`]).
    pub fn claim_checks(&self) -> &ClaimChecks {
        self.jwt.claim_checks()
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
    /// the `kid`, the signature, `exp`, `iss`, `aud`, and `nbf` where the
    /// claim checks say so), then a non-empty `sub`. Scopes come from `scope`
    /// (a space-separated string) and `scp` (Hydra's array) as the
    /// [`ScopeSource`] says, by default their union; either claim may be a
    /// string or an array.
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
        claims.into_principal(self.scope_source)
    }
}

impl fmt::Debug for McpVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefixes: Vec<&str> = self
            .credentials
            .iter()
            .map(|(prefix, _)| prefix.as_str())
            .collect();
        let mut debug = f.debug_struct("McpVerifier");
        debug
            .field("resource", &self.resource.url())
            // stridelabs-auth's `Debug` redacts the JWKS URL.
            .field("jwt", &self.jwt);
        // Only when opted into, so a default verifier's output is unchanged.
        if self.scope_source != ScopeSource::default() {
            debug.field("scope_source", &self.scope_source);
        }
        debug.field("credential_prefixes", &prefixes).finish()
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
    fn into_principal(self, source: ScopeSource) -> Result<Principal, VerifyError> {
        // Tools key users on the subject: an empty one would make every such
        // token the same user.
        if self.sub.is_empty() {
            return Err(AuthError::MissingSubject.into());
        }
        let present = |value: Option<String>| value.filter(|value| !value.is_empty());
        let scp = match source {
            ScopeSource::ScopeThenScp if self.scope.is_some() => None,
            _ => self.scp,
        };
        let scopes = [self.scope, scp]
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
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
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

    /// The mapping itself: an outage, a suppressed refetch and an unusable
    /// published key are `Unavailable`, a verdict on the token (an unknown or
    /// retired key included) is `Invalid`.
    #[test]
    fn auth_errors_map_to_unavailable_or_invalid() {
        for err in [
            AuthError::Jwks("endpoint returned 503".into()),
            AuthError::UnseenKid,
            AuthError::UnusableKey(stridelabs_auth::UnusableReason::Use),
        ] {
            let reason = err.to_string();
            assert_eq!(
                VerifyError::from(err),
                VerifyError::Unavailable(reason.into())
            );
        }
        for err in [
            AuthError::UnknownKid,
            AuthError::MissingKid,
            AuthError::InvalidToken("signature is invalid".into()),
        ] {
            let reason = err.to_string();
            assert_eq!(VerifyError::from(err), VerifyError::Invalid(reason.into()));
        }
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

    // --- opt-in claim checks and scope source ------------------------------

    /// The rules tapper's and lumen's REST verifiers apply: no leeway, `nbf`
    /// checked.
    fn rest_rules_verifier(server: &MockServer) -> McpVerifier {
        let resource = resource();
        McpVerifier::with_cache(
            &resource,
            resource.claim_checks().with_leeway(Duration::ZERO),
            JwksCache::new(format!("{}/jwks", server.uri()), reqwest::Client::new()),
        )
        .expect("the resource's own checks")
    }

    #[tokio::test]
    async fn with_rest_rules_a_just_expired_or_not_yet_valid_token_is_invalid() {
        let server = jwks_issuer().await;
        let key = TestKey::primary();
        let just_expired = key.mint(&mcp_claims().expires_in(-1).build());
        let not_yet_valid = key.mint(&mcp_claims().not_before_in(30).build());
        let rest_rules = rest_rules_verifier(&server);

        assert_eq!(
            rest_rules.verify(&just_expired).await,
            Err(VerifyError::invalid("token rejected: token has expired"))
        );
        assert_eq!(
            rest_rules.verify(&not_yet_valid).await,
            Err(VerifyError::invalid(
                "token rejected: token is not valid yet"
            ))
        );
        let principal = rest_rules
            .verify(&key.mint(&mcp_claims().not_before_in(-1).build()))
            .await
            .expect("a current token");
        assert_eq!(principal.auth_method, AuthMethod::Jwt);

        // `new` is unchanged: a 60 s leeway on `exp`, and `nbf` never read,
        // shown with an `nbf` no leeway would cover.
        let default = verifier(&server);
        assert_eq!(default.claim_checks().leeway(), Duration::from_secs(60));
        assert!(!default.claim_checks().validates_nbf());
        default
            .verify(&just_expired)
            .await
            .expect("within the default 60 s leeway");
        default
            .verify(&key.mint(&mcp_claims().not_before_in(600).build()))
            .await
            .expect("the default verifier does not check nbf");
    }

    #[test]
    fn claim_checks_for_anything_but_the_resource_are_refused() {
        let resource = resource();
        let url = resource.url().to_owned();
        let cache = || JwksCache::new("https://auth.example/jwks", reqwest::Client::new());

        for (checks, expected) in [
            (
                ClaimChecks::new("https://evil.example", Audience::Required(url.clone())),
                ClaimChecksError::IssuerMismatch,
            ),
            (
                ClaimChecks::new(format!("{ISSUER}/"), Audience::Required(url.clone())),
                ClaimChecksError::IssuerMismatch,
            ),
            (
                ClaimChecks::new(ISSUER, Audience::Required(format!("{url}/"))),
                ClaimChecksError::AudienceMismatch,
            ),
            (
                ClaimChecks::new(ISSUER, Audience::Required("parcel-rest-api".into())),
                ClaimChecksError::AudienceMismatch,
            ),
            (
                ClaimChecks::new(ISSUER, Audience::IfPresent(url.clone())),
                ClaimChecksError::AudienceMismatch,
            ),
            (
                ClaimChecks::new(ISSUER, Audience::NotValidated),
                ClaimChecksError::AudienceMismatch,
            ),
        ] {
            assert_eq!(
                McpVerifier::with_cache(&resource, checks, cache()).unwrap_err(),
                expected
            );
        }

        let checks = resource
            .claim_checks()
            .with_leeway(Duration::ZERO)
            .with_nbf_validation(true);
        let verifier =
            McpVerifier::with_cache(&resource, checks.clone(), cache()).expect("the resource's");
        assert_eq!(verifier.claim_checks(), &checks);
        assert_eq!(verifier.resource(), &resource);
    }

    /// `with_cache` verifies over the consumer's cache, settings and all, not
    /// one rebuilt from its URL: with unusable-key reporting on, a published
    /// key that cannot verify RS256 (`use: enc`) is the issuer's broken key,
    /// `Unavailable`; with it off (the default), the token is `Invalid`.
    #[tokio::test]
    async fn with_cache_keeps_the_consumers_cache_settings() {
        let mut jwks: Value =
            serde_json::from_str(TestKey::primary().jwks_json()).expect("the test key set");
        jwks["keys"][0]["use"] = json!("enc");
        let server = issuer(ResponseTemplate::new(200).set_body_json(&jwks)).await;
        let token = TestKey::primary().mint(&mcp_claims().build());
        let resource = resource();
        let over_cache = |report: bool| {
            let cache = JwksCache::new(format!("{}/jwks", server.uri()), reqwest::Client::new())
                .report_unusable_keys(report);
            McpVerifier::with_cache(&resource, resource.claim_checks(), cache)
                .expect("the resource's")
        };

        let reporting = over_cache(true).verify(&token).await;
        assert!(
            matches!(reporting, Err(VerifyError::Unavailable(_))),
            "{reporting:?}"
        );
        let default = over_cache(false).verify(&token).await;
        assert!(
            matches!(default, Err(VerifyError::Invalid(_))),
            "{default:?}"
        );
    }

    /// `with_cache` with both of stridelabs-auth's claim type rules on.
    fn typed_claims_verifier(server: &MockServer) -> McpVerifier {
        let resource = resource();
        McpVerifier::with_cache(
            &resource,
            resource
                .claim_checks()
                .with_integer_time_claims(true)
                .with_string_issuer(true),
            JwksCache::new(format!("{}/jwks", server.uri()), reqwest::Client::new()),
        )
        .expect("the resource's own checks")
    }

    /// The JSON text a token signed: its payload segment, decoded.
    fn signed_payload(token: &str) -> String {
        let segment = token.split('.').nth(1).expect("a payload segment");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .expect("base64url");
        String::from_utf8(payload).expect("UTF-8")
    }

    /// Two tokens for the resource, each otherwise valid: one whose `iss` is
    /// an array holding the issuer, one whose `exp` is an hour ahead plus
    /// half a second. Each signed payload is checked to carry its claim.
    fn mistyped_tokens() -> (String, String) {
        let key = TestKey::primary();
        let array_issuer = key.mint(&mcp_claims().claim("iss", json!([ISSUER])).build());
        let member = format!(r#""iss":["{ISSUER}"]"#);
        assert!(signed_payload(&array_issuer).contains(&member), "{member}");

        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after 1970")
            .as_secs()
            + 3600;
        let fractional_exp = key.mint(&mcp_claims().claim("exp", json!(exp as f64 + 0.5)).build());
        let member = format!(r#""exp":{exp}.5"#);
        assert!(
            signed_payload(&fractional_exp).contains(&member),
            "{member}"
        );
        (array_issuer, fractional_exp)
    }

    #[tokio::test]
    async fn with_cache_can_refuse_an_array_issuer_and_a_fractional_exp() {
        let server = jwks_issuer().await;
        let (array_issuer, fractional_exp) = mistyped_tokens();
        let typed = typed_claims_verifier(&server);
        assert!(typed.claim_checks().requires_string_issuer());
        assert!(typed.claim_checks().requires_integer_time_claims());

        assert_eq!(
            typed.verify(&array_issuer).await,
            Err(VerifyError::invalid(
                "token rejected: the issuer claim is not a string"
            ))
        );
        assert_eq!(
            typed.verify(&fractional_exp).await,
            Err(VerifyError::invalid(
                "token rejected: a time claim is not a whole number of seconds"
            ))
        );
        let principal = typed
            .verify(&TestKey::primary().mint(&mcp_claims().build()))
            .await
            .expect("a well-typed token");
        assert_eq!(principal.auth_method, AuthMethod::Jwt);
    }

    /// Today's default, pinned so that changing it is a conscious act:
    /// `new`, and `with_cache` over the resource's plain checks, accept an
    /// array issuer and a fractional `exp`.
    #[tokio::test]
    async fn by_default_an_array_issuer_and_a_fractional_exp_pass() {
        let server = jwks_issuer().await;
        let (array_issuer, fractional_exp) = mistyped_tokens();
        let resource = resource();
        let plain = McpVerifier::with_cache(
            &resource,
            resource.claim_checks(),
            JwksCache::new(format!("{}/jwks", server.uri()), reqwest::Client::new()),
        )
        .expect("the resource's own checks");

        for (name, verifier) in [("new", verifier(&server)), ("with_cache", plain)] {
            assert!(!verifier.claim_checks().requires_string_issuer(), "{name}");
            assert!(
                !verifier.claim_checks().requires_integer_time_claims(),
                "{name}"
            );
            for token in [&array_issuer, &fractional_exp] {
                let principal = verifier
                    .verify(token)
                    .await
                    .unwrap_or_else(|err| panic!("{name}: {err}"));
                assert_eq!(principal.subject, "test-subject", "{name}");
            }
        }
    }

    #[tokio::test]
    async fn the_strict_screen_refuses_before_any_jwks_fetch() {
        // Parses with a kid, but its payload is not UTF-8: only the strict
        // screen reads it (stridelabs-auth's `screen::check` example).
        let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsifQ.eyJ4Ijoi_yJ9.AA";
        // No JWKS mock: any fetch is a 404, so an outage.
        let server = MockServer::start().await;

        let strict = verifier(&server).screen(ScreenPolicy::Strict);
        assert_eq!(
            strict.verify(token).await,
            Err(VerifyError::invalid("malformed token"))
        );
        assert!(server
            .received_requests()
            .await
            .expect("recording")
            .is_empty());

        let basic = verifier(&server);
        assert!(matches!(
            basic.verify(token).await,
            Err(VerifyError::Unavailable(_))
        ));
    }

    async fn scopes_under(
        source: ScopeSource,
        claims: &TestClaims,
    ) -> Result<Vec<String>, VerifyError> {
        let server = jwks_issuer().await;
        let principal = verifier(&server)
            .with_scope_source(source)
            .verify(&TestKey::primary().mint(&claims.build()))
            .await?;
        Ok(principal.scopes.into_iter().collect())
    }

    #[tokio::test]
    async fn the_scope_source_decides_between_scope_and_scp() {
        // (claims, under Union, under ScopeThenScp)
        for (claims, union, scope_then_scp) in [
            (
                mcp_claims().claim("scope", json!("x:read x:write")),
                vec!["x:read", "x:write"],
                vec!["x:read", "x:write"],
            ),
            (
                mcp_claims().claim("scp", json!(["x:write"])),
                vec!["x:write"],
                vec!["x:write"],
            ),
            // Conflicting: the union grants what only `scp` names.
            (
                mcp_claims()
                    .claim("scope", json!("x:read"))
                    .claim("scp", json!(["x:write"])),
                vec!["x:read", "x:write"],
                vec!["x:read"],
            ),
            // An empty `scope` is present, so `scp` is never read.
            (
                mcp_claims()
                    .claim("scope", json!(""))
                    .claim("scp", json!(["x:write"])),
                vec!["x:write"],
                vec![],
            ),
            // A `null` one is absent.
            (
                mcp_claims()
                    .claim("scope", Value::Null)
                    .claim("scp", json!(["x:write"])),
                vec!["x:write"],
                vec!["x:write"],
            ),
            (mcp_claims(), vec![], vec![]),
        ] {
            for (source, expected) in [
                (ScopeSource::Union, union),
                (ScopeSource::ScopeThenScp, scope_then_scp),
            ] {
                assert_eq!(
                    scopes_under(source, &claims).await.expect("valid token"),
                    expected,
                    "{source:?}: {}",
                    claims.build()
                );
            }
        }
        assert_eq!(ScopeSource::default(), ScopeSource::Union);
    }

    #[tokio::test]
    async fn a_malformed_scope_claim_is_invalid_under_either_source() {
        for claims in [
            mcp_claims().claim("scope", json!({"hunter2": 1})),
            // Malformed even where ScopeThenScp would not read it.
            mcp_claims()
                .claim("scope", json!("x:read"))
                .claim("scp", json!(7)),
        ] {
            for source in [ScopeSource::Union, ScopeSource::ScopeThenScp] {
                let err = scopes_under(source, &claims).await.unwrap_err();
                assert_eq!(
                    err,
                    VerifyError::invalid("token rejected: claims are malformed"),
                    "{source:?}"
                );
                assert!(!err.to_string().contains("hunter2"));
            }
        }
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
        // The default scope source is not printed, so the default's output is
        // what it always was; an opted-into one is.
        assert!(!debug.contains("scope_source"), "{debug}");
        let debug = format!(
            "{:?}",
            verifier.with_scope_source(ScopeSource::ScopeThenScp)
        );
        assert!(debug.contains("scope_source: ScopeThenScp"), "{debug}");
    }
}
