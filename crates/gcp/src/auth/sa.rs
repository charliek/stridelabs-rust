//! `service_account` keys (feature `service-account-key`): sign an RS256
//! JWT-bearer assertion (RFC 7523) and exchange it at the key's `token_uri`,
//! and check a key offline ([`ServiceAccountKey::validate`]).

use std::fmt;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

use super::adc::{self, Fields};
use super::error::GcpAuthError;
use super::{exchange, wrong_kind, CredentialKind, Fetched, Source, TokenOptions};
use crate::util::Failed;

/// The `grant_type` of the JWT-bearer flow.
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// How long the assertion claims to be valid. Google issues a one-hour access
/// token whatever it says.
const ASSERTION_LIFETIME_SECS: i64 = 3600;

/// A `service_account` key file, parsed: what a [`super::TokenProvider`]
/// built from it signs with. The private key is held only as a signing key,
/// never as text.
///
/// Built with [`ServiceAccountKey::from_json`], it exists to be checked
/// offline at startup with [`ServiceAccountKey::validate`], so that a key
/// that could never mint a token refuses to start instead of failing the
/// first request:
///
/// ```
/// # fn startup(http: reqwest::Client, key_json: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
/// use stridelabs_gcp::auth::{ServiceAccountKey, TokenProvider, CLOUD_PLATFORM_SCOPE};
///
/// ServiceAccountKey::from_json(key_json)?.validate()?;
/// let tokens = TokenProvider::from_service_account_json(http, &[CLOUD_PLATFORM_SCOPE], key_json)?;
/// # Ok(())
/// # }
/// ```
///
/// `Debug` prints the `client_email` and the `token_uri`'s origin
/// (`scheme://host[:port]`), never the key, the key id or the `token_uri`'s
/// path.
#[derive(Clone)]
pub struct ServiceAccountKey {
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
            .field("token_uri", &crate::util::url_origin(token_uri))
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Why [`ServiceAccountKey::validate`] refused a key: a fixed reason that
/// names the field and never its value — no key material, and no part of a
/// URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyDefect {
    /// `private_key` parses as an RSA PEM but cannot sign an RS256
    /// assertion: an RSA public key (PKCS#1 or SPKI), or a private key
    /// missing some of its fields. Parsing checks only that the PEM's DER
    /// decodes; jsonwebtoken loads the key pair when it signs.
    #[error(
        "field `private_key` parses as an RSA PEM but cannot sign an RS256 assertion \
         (a public key, or a private key missing some of its fields)"
    )]
    CannotSign,
    /// `token_uri` is not a URL.
    #[error("field `token_uri` is not a URL")]
    TokenUriUnparseable,
    /// `token_uri`'s scheme is neither `https` nor `http`.
    #[error("field `token_uri` is neither https nor http")]
    TokenUriScheme,
    /// `token_uri` is `http` to a host that is not loopback: the signed
    /// assertion would cross the network in the clear.
    #[error(
        "field `token_uri` is http to a host that is not loopback \
         (only localhost, 127.0.0.0/8 and ::1 may be plain http)"
    )]
    TokenUriPlainHttp,
    /// `token_uri` carries userinfo, a query or a fragment (an empty `?` or
    /// `#` included).
    #[error("field `token_uri` carries userinfo, a query or a fragment")]
    TokenUriCarriesExtras,
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
    /// Parse `service_account` key JSON (the contents of a key file) exactly
    /// as [`super::TokenProvider::from_service_account_json`] does. Local:
    /// nothing is sent.
    ///
    /// # Errors
    ///
    /// [`GcpAuthError::InvalidCredentials`] when it does not parse (from
    /// `credentials JSON`, naming the field, never a value);
    /// [`GcpAuthError::Unsupported`] when it is another `type`.
    pub fn from_json(json: &[u8]) -> Result<ServiceAccountKey, GcpAuthError> {
        match adc::parse_credentials(json, "credentials JSON")?.source {
            Source::ServiceAccount(key) => Ok(key),
            other => Err(wrong_kind(CredentialKind::ServiceAccount, other.kind())),
        }
    }

    /// Check, offline, what building a provider does not: that the key
    /// signs, and that its `token_uri` is a safe place to post the signed
    /// assertion. Nothing is sent.
    ///
    /// - **It signs**: one throwaway assertion is signed exactly as a token
    ///   request signs it, and dropped. Its `iat` is 0, so it expired in
    ///   1970: no copy of it could ever be exchanged.
    /// - **`token_uri` is `https`**, or `http` only to a loopback host (the
    ///   literal `localhost`, `127.0.0.0/8` or `::1`, never a name that
    ///   resolves there), with **no userinfo, query or fragment**. The
    ///   endpoint is used verbatim, and is the assertion's audience.
    ///
    /// A key that passes can still be refused by Google (revoked, deleted,
    /// a wrong key id): only the first token request can tell.
    ///
    /// # Errors
    ///
    /// The first [`KeyDefect`] found, signing first.
    pub fn validate(&self) -> Result<(), KeyDefect> {
        self.assertion(&[], 0).map_err(|_| KeyDefect::CannotSign)?;
        check_token_uri(&self.token_uri)
    }

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

/// `token_uri` under [`ServiceAccountKey::validate`]'s rule. Parsed as
/// reqwest parses it when the assertion is posted.
fn check_token_uri(token_uri: &str) -> Result<(), KeyDefect> {
    let url = reqwest::Url::parse(token_uri).map_err(|_| KeyDefect::TokenUriUnparseable)?;
    match url.scheme() {
        "https" => {}
        "http" if url.host_str().is_some_and(is_loopback_host) => {}
        "http" => return Err(KeyDefect::TokenUriPlainHttp),
        _ => return Err(KeyDefect::TokenUriScheme),
    }
    let extras = !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some();
    if extras {
        return Err(KeyDefect::TokenUriCarriesExtras);
    }
    Ok(())
}

/// A host as the URL parser left it (a name lowercased, IPv6 in brackets)
/// that is `localhost`, in `127.0.0.0/8`, or `::1`. The literal host, never
/// a DNS lookup.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
