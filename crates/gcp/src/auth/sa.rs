//! `service_account` keys (feature `service-account-key`): sign an RS256
//! JWT-bearer assertion (RFC 7523) and exchange it at the key's `token_uri`.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

use super::adc::Fields;
use super::error::GcpAuthError;
use super::{exchange, Fetched, TokenOptions};
use crate::util::Failed;

/// The `grant_type` of the JWT-bearer flow.
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// How long the assertion claims to be valid. Google issues a one-hour access
/// token whatever it says.
const ASSERTION_LIFETIME_SECS: i64 = 3600;

/// A service-account key, parsed once. The private key is held only as a
/// signing key, never as text.
#[derive(Clone)]
pub(crate) struct ServiceAccountKey {
    client_email: String,
    /// Stamped as the assertion's `kid`, as google-auth does.
    private_key_id: Option<String>,
    /// Read from the key itself, never hardcoded, and the assertion's `aud`.
    token_uri: String,
    key: EncodingKey,
}

impl fmt::Debug for ServiceAccountKey {
    /// Destructured so a new field is a decision.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ServiceAccountKey {
            client_email,
            private_key_id: _,
            token_uri,
            key: _,
        } = self;
        f.debug_struct("ServiceAccountKey")
            .field("client_email", client_email)
            .field("token_uri", &crate::util::redact_url(token_uri))
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

impl ServiceAccountKey {
    /// `client_email`, `private_key` and `token_uri` are required — the
    /// fields google-auth's `from_service_account_info` requires.
    pub(crate) fn parse(fields: &Fields<'_>) -> Result<ServiceAccountKey, GcpAuthError> {
        let client_email = fields.required("client_email")?;
        let token_uri = fields.required("token_uri")?;
        let private_key_id = fields.optional("private_key_id")?;
        // PKCS#8 (`BEGIN PRIVATE KEY`, what Google mints) and PKCS#1 both
        // parse. The parser's error is dropped: it can name bytes of the key.
        let key = EncodingKey::from_rsa_pem(fields.required("private_key")?.as_bytes()).map_err(
            |_| {
                GcpAuthError::invalid(
                    fields.origin,
                    "field `private_key` is not a PEM-encoded RSA private key",
                )
            },
        )?;
        Ok(ServiceAccountKey {
            client_email,
            private_key_id,
            token_uri,
            key,
        })
    }

    /// The signed assertion for `scopes` at `iat` (seconds since the epoch).
    pub(crate) fn assertion(&self, scopes: &[String], iat: i64) -> Result<String, GcpAuthError> {
        let scope = scopes.join(" ");
        let claims = AssertionClaims {
            iss: &self.client_email,
            scope: &scope,
            aud: &self.token_uri,
            iat,
            exp: iat.saturating_add(ASSERTION_LIFETIME_SECS),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid.clone_from(&self.private_key_id);
        jsonwebtoken::encode(&header, &claims, &self.key).map_err(|_| GcpAuthError::Signing)
    }

    pub(crate) async fn fetch(
        &self,
        http: &reqwest::Client,
        scopes: &[String],
        options: &TokenOptions,
    ) -> Result<Fetched, Failed<GcpAuthError>> {
        let assertion = self
            .assertion(scopes, unix_now())
            .map_err(Failed::permanent)?;
        let request = http.post(&self.token_uri).form(&[
            ("grant_type", JWT_BEARER_GRANT),
            ("assertion", assertion.as_str()),
        ]);
        exchange(request, &self.token_uri, options.token_timeout).await
    }

    pub(crate) fn client_email(&self) -> &str {
        &self.client_email
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
