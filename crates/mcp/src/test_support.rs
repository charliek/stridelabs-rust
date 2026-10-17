//! Offline MCP access tokens for consumers' tests (feature `test-support`).
//!
//! Tokens are signed with stridelabs-auth's committed **throwaway** test
//! keypair (see `stridelabs_auth::test_support`), shaped as slauth mints
//! them for an MCP connector: `iss` = the resource's issuer, `aud` = the
//! canonical resource URL, `scope` = a space-separated scope string.
//!
//! A consumer's end-to-end test serves the matching key set and points its
//! [`crate::McpVerifier`] at it:
//!
//! ```
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use stridelabs_mcp::test_support::{access_token, jwks_json};
//! use stridelabs_mcp::{McpVerifier, ProtectedResource};
//! use wiremock::matchers::{method, path};
//! use wiremock::{Mock, MockServer, ResponseTemplate};
//!
//! let resource = ProtectedResource::new(
//!     "https://parcel.stridelabs.ai/mcp",
//!     "https://auth.test.stridelabs.ai",
//!     ["parcel:read", "parcel:write"],
//! )?;
//! let jwks = MockServer::start().await;
//! Mock::given(method("GET"))
//!     .and(path("/jwks"))
//!     .respond_with(ResponseTemplate::new(200).set_body_raw(jwks_json(), "application/json"))
//!     .mount(&jwks)
//!     .await;
//! let verifier = McpVerifier::new(&resource, format!("{}/jwks", jwks.uri()), reqwest::Client::new());
//!
//! let token = access_token(&resource)
//!     .subject("user-1")
//!     .scopes(["parcel:read"])
//!     .mint();
//! let principal = verifier.verify(&token).await?;
//! assert_eq!(principal.subject, "user-1");
//! # Ok(())
//! # }
//! ```
//!
//! (`stridelabs_testing::serve_json(200, serde_json::from_str(jwks_json())?)`
//! is the same mock in one line; it answers every path.) Over HTTP, send the
//! token as `Authorization: Bearer {token}`. The server under test must also
//! accept the test's `Host`: pass `"127.0.0.1"` (or `"localhost"`) as an
//! extra host to [`crate::server_config`] when it listens on loopback. The
//! resource URL itself stays `https`: it is an identifier, never dialled.

use serde_json::{json, Value};
use stridelabs_auth::test_support::{TestClaims, TestKey};

use crate::resource::ProtectedResource;

/// The public half of the key [`AccessToken::mint`] signs with, as JWKS JSON
/// text: the body a mock JWKS endpoint serves.
pub fn jwks_json() -> &'static str {
    TestKey::primary().jwks_json()
}

/// A token for `resource` that its [`crate::McpVerifier`] accepts (given the
/// test JWKS): subject `test-subject`, every one of the resource's
/// `scopes_supported`, an email and a name, one hour of validity. Each setter
/// moves it one step from that.
pub fn access_token(resource: &ProtectedResource) -> AccessToken {
    AccessToken {
        claims: TestClaims::new(resource.issuer(), resource.url()),
        scopes: Some(resource.scopes_supported().to_vec()),
        key: TestKey::primary(),
    }
}

/// A token being built; see [`access_token`].
#[derive(Debug, Clone)]
pub struct AccessToken {
    claims: TestClaims,
    /// `None`: no `scope` claim at all.
    scopes: Option<Vec<String>>,
    key: TestKey,
}

impl AccessToken {
    /// Set `sub` (`""` for the empty-subject rejection).
    pub fn subject(mut self, sub: impl Into<String>) -> AccessToken {
        self.claims = self.claims.subject(sub);
        self
    }

    /// Set the `scope` claim to `scopes`, space-separated.
    pub fn scopes<I, S>(mut self, scopes: I) -> AccessToken
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = Some(scopes.into_iter().map(Into::into).collect());
        self
    }

    /// Omit the `scope` claim (for a token that carries Hydra's `scp`
    /// instead, set with [`AccessToken::claim`]).
    pub fn without_scope(mut self) -> AccessToken {
        self.scopes = None;
        self
    }

    /// Set `client_id`.
    pub fn client_id(self, client_id: impl Into<String>) -> AccessToken {
        self.claim("client_id", json!(client_id.into()))
    }

    /// Set `email`.
    pub fn email(mut self, email: impl Into<String>) -> AccessToken {
        self.claims = self.claims.email(email);
        self
    }

    /// Omit `email` (MCP tokens need not carry one).
    pub fn without_email(mut self) -> AccessToken {
        self.claims = self.claims.without_email();
        self
    }

    /// Seconds until `exp`; negative for an expired token.
    pub fn expires_in(mut self, secs: i64) -> AccessToken {
        self.claims = self.claims.expires_in(secs);
        self
    }

    /// Any other claim, applied last (so `.claim("aud", …)` mints a token
    /// for another audience).
    pub fn claim(mut self, name: impl Into<String>, value: Value) -> AccessToken {
        self.claims = self.claims.claim(name, value);
        self
    }

    /// Sign with stridelabs-auth's *secondary* test key instead, under the
    /// primary key's `kid`: a forged signature the verifier must refuse.
    pub fn signed_by_untrusted_key(mut self) -> AccessToken {
        self.key = TestKey::secondary();
        self
    }

    /// The signed JWT (without the `Bearer ` prefix).
    pub fn mint(&self) -> String {
        let mut claims = self.claims.build();
        if let (Some(scopes), Some(object)) = (&self.scopes, claims.as_object_mut()) {
            // An explicit `.claim("scope", …)` wins over the scope list.
            object
                .entry("scope")
                .or_insert_with(|| json!(scopes.join(" ")));
        }
        self.key.mint_with_kid(TestKey::primary().kid(), &claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthMethod, McpVerifier, VerifyError};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn resource() -> ProtectedResource {
        ProtectedResource::new(
            "https://parcel.stridelabs.ai/mcp",
            "https://auth.test.stridelabs.ai",
            ["parcel:read", "parcel:write"],
        )
        .expect("canonical")
    }

    async fn verifier() -> (MockServer, McpVerifier) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(jwks_json(), "application/json"))
            .mount(&server)
            .await;
        let verifier = McpVerifier::new(
            &resource(),
            format!("{}/jwks", server.uri()),
            reqwest::Client::new(),
        );
        (server, verifier)
    }

    #[tokio::test]
    async fn a_default_token_verifies_with_every_supported_scope() {
        let (_server, verifier) = verifier().await;

        let principal = verifier
            .verify(&access_token(&resource()).mint())
            .await
            .expect("valid");

        assert_eq!(principal.subject, "test-subject");
        assert_eq!(principal.auth_method, AuthMethod::Jwt);
        assert!(principal.has_scope("parcel:read") && principal.has_scope("parcel:write"));
    }

    #[tokio::test]
    async fn each_setter_shapes_the_token() {
        let (_server, verifier) = verifier().await;
        let token = access_token(&resource())
            .subject("user-9")
            .scopes(["parcel:read"])
            .client_id("connector-1")
            .without_email()
            .mint();

        let principal = verifier.verify(&token).await.expect("valid");

        assert_eq!(principal.subject, "user-9");
        assert_eq!(principal.scopes.iter().collect::<Vec<_>>(), ["parcel:read"]);
        assert_eq!(principal.client_id.as_deref(), Some("connector-1"));
        assert_eq!(principal.email, None);

        let emailed = access_token(&resource()).email("u@example.com").mint();
        let principal = verifier.verify(&emailed).await.expect("valid");
        assert_eq!(principal.email.as_deref(), Some("u@example.com"));

        let scp_only = access_token(&resource())
            .without_scope()
            .claim("scp", json!(["parcel:write"]))
            .mint();
        let principal = verifier.verify(&scp_only).await.expect("valid");
        assert_eq!(
            principal.scopes.iter().collect::<Vec<_>>(),
            ["parcel:write"]
        );

        let explicit = access_token(&resource())
            .claim("scope", json!("offline_access"))
            .mint();
        let principal = verifier.verify(&explicit).await.expect("valid");
        assert_eq!(
            principal.scopes.iter().collect::<Vec<_>>(),
            ["offline_access"]
        );
    }

    #[tokio::test]
    async fn the_rejection_shapes_are_rejected() {
        let (_server, verifier) = verifier().await;

        for (token, reason) in [
            (
                access_token(&resource()).expires_in(-3600).mint(),
                "token rejected: token has expired",
            ),
            (
                access_token(&resource()).signed_by_untrusted_key().mint(),
                "token rejected: signature is invalid",
            ),
            (
                access_token(&resource())
                    .claim("aud", json!("parcel-rest-api"))
                    .mint(),
                "token rejected: audience is not accepted",
            ),
            (
                access_token(&resource()).subject("").mint(),
                "token is missing a subject claim",
            ),
        ] {
            assert_eq!(
                verifier.verify(&token).await,
                Err(VerifyError::invalid(reason))
            );
        }
    }
}
