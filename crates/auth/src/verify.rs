//! Access-token verification: the thing this crate exists for.

use std::sync::Arc;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::config::SlauthConfig;
use crate::error::{invalid_token, AuthError};
use crate::jwks::JwksCache;

/// The claims this crate reads. Anything else in the token is ignored.
///
/// slauth injects `email` and `name` at the consent step, but both are
/// declared optional here so that a token which omits them fails the
/// *documented* check ([`AuthError::MissingEmail`]) rather than a
/// deserialization error — the distinction matters when reading a log.
#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    /// The OIDC subject. `default` so an absent claim arrives as `""` and is
    /// rejected by the same check as an empty one.
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// A caller whose token passed every check.
///
/// `sub` is an **opaque** stable identifier for the end user at the issuer.
/// In a slauth deployment it happens to be the Kratos identity UUID, and
/// services key their user rows on it — but that is a fact about that
/// deployment, not a promise of this type. Nothing here parses it.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub sub: String,
    /// Non-empty, guaranteed.
    pub email: String,
    /// May be empty: a display name is not something to reject a login over.
    pub name: String,
}

/// Verifies slauth access tokens against a cached JWKS.
///
/// Cheap to clone (one `Arc`), and **meant to be cloned rather than rebuilt**:
/// the key cache lives inside, so a verifier constructed per request would
/// fetch the JWKS per request. Build one in the service's application state
/// and clone it from there.
#[derive(Debug, Clone)]
pub struct Verifier {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    config: SlauthConfig,
    jwks: JwksCache,
}

impl Verifier {
    /// Build a verifier for `config`, fetching keys with `http`.
    ///
    /// The [`JwksCache`] is constructed **here**, from `config.jwks_url`,
    /// rather than being accepted as an argument. A cache pointed at one
    /// issuer and a config naming another is a hole that no amount of
    /// verification logic can close, so the two cannot be supplied
    /// separately.
    pub fn new(config: SlauthConfig, http: reqwest::Client) -> Verifier {
        let jwks = JwksCache::new(config.jwks_url.clone(), http);
        Verifier {
            inner: Arc::new(Inner { config, jwks }),
        }
    }

    /// The configuration this verifier was built with.
    pub fn config(&self) -> &SlauthConfig {
        &self.inner.config
    }

    /// Verify a bearer token's value (the part after `Bearer `).
    ///
    /// May fetch the issuer's JWKS; see [`crate::jwks`] for when.
    pub async fn verify_bearer(&self, token: &str) -> Result<VerifiedIdentity, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::MalformedToken)?;
        let kid = header.kid.ok_or(AuthError::MissingKid)?;

        let jwks = self.inner.jwks.jwks_for_kid(&kid).await?;

        Verifier::verify_with_jwks(
            token,
            &jwks,
            &kid,
            &self.inner.config.issuer,
            &self.inner.config.audience,
        )
    }

    /// The whole of verification, minus the network.
    ///
    /// An associated function, not a method: it takes no `self`, does no I/O,
    /// and is public so a consumer can test its own wiring — or verify a token
    /// against a key set it obtained some other way — without a
    /// [`Verifier`] or an HTTP client.
    ///
    /// Checks, in order: `kid` is in the set; the key is usable; RS256
    /// signature; `exp`; `iss` equals `issuer`; `aud` contains `audience`; a
    /// non-empty `email` claim; a non-empty `sub` claim.
    pub fn verify_with_jwks(
        token: &str,
        jwks: &JwkSet,
        kid: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<VerifiedIdentity, AuthError> {
        let jwk = jwks.find(kid).ok_or(AuthError::UnknownKid)?;
        // A key the issuer published but we can't build a verifier from is the
        // issuer's problem, not the caller's — hence `Jwks`, which maps to a
        // 5xx, and not a 401 blaming a token that never got to be checked.
        let key = DecodingKey::from_jwk(jwk)
            .map_err(|_| AuthError::Jwks("key set contains an unusable signing key".into()))?;

        // `Validation::new(RS256)` pins the algorithm — an `alg: none` or
        // HS256 token (the classic "verify with the public key as an HMAC
        // secret" forgery) is rejected before the signature is even checked.
        // `exp` validation is on by default and stays on.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        // set_issuer/set_audience only validate the claims WHEN PRESENT —
        // jsonwebtoken's `Validation::new` requires only `exp`, so without
        // this line a token that simply omits `iss` or `aud` sails through.
        // (The spendwise original has this hole; hardening, not parity.)
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);

        let data = decode::<Claims>(token, &key, &validation).map_err(|err| invalid_token(&err))?;

        // Services key their user rows on email (usually a UNIQUE NOT NULL
        // column), so a missing one must be rejected rather than collapsed to
        // "" — which would make every emailless token the same user.
        let email = data
            .claims
            .email
            .filter(|email| !email.is_empty())
            .ok_or(AuthError::MissingEmail)?;

        // Hardening over the spendwise original, which accepted `sub: ""`.
        // An empty subject is the same collapse-to-one-user failure as an
        // empty email, one layer down.
        if data.claims.sub.is_empty() {
            return Err(AuthError::MissingSubject);
        }

        Ok(VerifiedIdentity {
            sub: data.claims.sub,
            email,
            name: data.claims.name.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use wiremock::{MockServer, ResponseTemplate};

    use super::*;
    use crate::mock_issuer::{issuer, jwks_url_of, primary_issuer};
    use crate::test_support::{TestClaims, TestKey, AUDIENCE, ISSUER, PRIMARY_KID};

    fn verify(token: &str) -> Result<VerifiedIdentity, AuthError> {
        Verifier::verify_with_jwks(
            token,
            &TestKey::primary().jwks(),
            PRIMARY_KID,
            ISSUER,
            AUDIENCE,
        )
    }

    fn claims() -> TestClaims {
        TestClaims::new(ISSUER, AUDIENCE)
    }

    #[test]
    fn a_good_token_yields_its_identity() {
        let token = TestKey::primary().mint(
            &claims()
                .subject("kratos-uuid-1")
                .email("u@example.com")
                .name("Test User")
                .build(),
        );

        let identity = verify(&token).expect("valid token");

        assert_eq!(identity.sub, "kratos-uuid-1");
        assert_eq!(identity.email, "u@example.com");
        assert_eq!(identity.name, "Test User");
    }

    #[test]
    fn a_missing_name_is_not_a_rejection() {
        let token = TestKey::primary().mint(&claims().without_name().build());

        assert_eq!(verify(&token).expect("valid token").name, "");
    }

    #[test]
    fn rejects_a_token_missing_its_issuer_or_audience() {
        // `set_issuer`/`set_audience` alone validate those claims only when
        // they are PRESENT — `set_required_spec_claims` is what makes
        // omission fatal. Regression test for a review-found hole (present
        // in the spendwise original too): without it, dropping `iss` or
        // `aud` from an otherwise-valid token bypassed both checks.
        for claim in ["iss", "aud"] {
            let mut claims = claims()
                .subject("kratos-uuid-1")
                .email("u@example.com")
                .build();
            claims
                .as_object_mut()
                .expect("claims build to an object")
                .remove(claim);

            let token = TestKey::primary().mint(&claims);
            let err = verify(&token).unwrap_err();

            assert!(
                matches!(err, AuthError::InvalidToken(_)),
                "token without {claim} must be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn rejects_a_malformed_token() {
        for garbage in ["", "not.a.jwt", "aaaa"] {
            let err = verify(garbage).unwrap_err();
            assert!(
                matches!(err, AuthError::InvalidToken(_)),
                "{garbage}: {err}"
            );
        }
    }

    #[test]
    fn rejects_an_unknown_kid() {
        let token = TestKey::primary().mint(&claims().build());

        let err = Verifier::verify_with_jwks(
            &token,
            &TestKey::primary().jwks(),
            "no-such-kid",
            ISSUER,
            AUDIENCE,
        )
        .unwrap_err();

        assert!(matches!(err, AuthError::UnknownKid), "{err}");
    }

    #[test]
    fn rejects_a_token_signed_by_another_key() {
        // Signed by key 2 but labelled with key 1's kid: the shape of a
        // forgery, and the reason the signature is checked against the key the
        // *set* names rather than the one the token claims.
        let token = TestKey::secondary().mint_with_kid(PRIMARY_KID, &claims().build());

        let err = verify(&token).unwrap_err();

        assert_eq!(err.to_string(), "token rejected: signature is invalid");
    }

    #[test]
    fn rejects_a_symmetric_algorithm() {
        // HS256 with the public modulus as the "secret" — the classic
        // algorithm-confusion forgery. `Validation::new(RS256)` refuses it.
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(PRIMARY_KID.to_string());
        let token = encode(
            &header,
            &claims().build(),
            &EncodingKey::from_secret(b"public key material"),
        )
        .expect("sign");

        let err = verify(&token).unwrap_err();

        assert!(matches!(err, AuthError::InvalidToken(_)), "{err}");
    }

    #[test]
    fn rejects_a_foreign_issuer() {
        let token =
            TestKey::primary().mint(&TestClaims::new("https://evil.example", AUDIENCE).build());

        let err = verify(&token).unwrap_err();

        assert_eq!(err.to_string(), "token rejected: issuer is not accepted");
    }

    #[test]
    fn rejects_another_services_audience() {
        let token = TestKey::primary().mint(&TestClaims::new(ISSUER, "some-other-app").build());

        let err = verify(&token).unwrap_err();

        assert_eq!(err.to_string(), "token rejected: audience is not accepted");
    }

    #[test]
    fn rejects_an_expired_token() {
        let token = TestKey::primary().mint(&claims().expires_in(-3600).build());

        let err = verify(&token).unwrap_err();

        assert_eq!(err.to_string(), "token rejected: token has expired");
    }

    #[test]
    fn rejects_an_empty_email() {
        let token = TestKey::primary().mint(&claims().email("").build());

        assert!(matches!(
            verify(&token).unwrap_err(),
            AuthError::MissingEmail
        ));
    }

    #[test]
    fn rejects_a_missing_email() {
        let token = TestKey::primary().mint(&claims().without_email().build());

        assert!(matches!(
            verify(&token).unwrap_err(),
            AuthError::MissingEmail
        ));
    }

    #[test]
    fn rejects_an_empty_sub() {
        let token = TestKey::primary().mint(&claims().subject("").build());

        assert!(matches!(
            verify(&token).unwrap_err(),
            AuthError::MissingSubject
        ));
    }

    #[test]
    fn rejects_a_missing_sub() {
        // No `sub` key at all, not just an empty one.
        let mut without_sub = claims().build();
        without_sub
            .as_object_mut()
            .expect("claims are an object")
            .remove("sub");
        let token = TestKey::primary().mint(&without_sub);

        assert!(matches!(
            verify(&token).unwrap_err(),
            AuthError::MissingSubject
        ));
    }

    #[test]
    fn no_error_message_contains_the_token() {
        let token = TestKey::secondary().mint_with_kid(PRIMARY_KID, &claims().build());

        let message = verify(&token).unwrap_err().to_string();

        assert!(!message.contains(&token));
        assert!(!message.contains(PRIMARY_KID));
    }

    // --- the network-facing half ------------------------------------------

    fn verifier_against(server: &MockServer) -> Verifier {
        Verifier::new(
            SlauthConfig {
                issuer: ISSUER.into(),
                jwks_url: jwks_url_of(server),
                audience: AUDIENCE.into(),
                pat_validate_url: None,
            },
            reqwest::Client::new(),
        )
    }

    #[tokio::test]
    async fn verify_bearer_fetches_the_key_set_once_for_many_tokens() {
        let server = primary_issuer(1).await;
        let verifier = verifier_against(&server);

        for i in 0..3 {
            let token = TestKey::primary().mint(&claims().subject(format!("user-{i}")).build());
            let identity = verifier.verify_bearer(&token).await.expect("valid token");
            assert_eq!(identity.sub, format!("user-{i}"));
        }
    }

    #[tokio::test]
    async fn verify_bearer_rejects_a_token_with_no_kid() {
        let server = MockServer::start().await;
        // No mock is mounted: reaching the issuer at all would be the bug.
        let verifier = verifier_against(&server);
        let token = encode(
            &Header::new(Algorithm::RS256),
            &claims().build(),
            &EncodingKey::from_rsa_pem(TestKey::primary().pem().as_bytes()).expect("key"),
        )
        .expect("sign");

        let err = verifier.verify_bearer(&token).await.unwrap_err();

        assert!(matches!(err, AuthError::MissingKid), "{err}");
    }

    #[tokio::test]
    async fn verify_bearer_rejects_garbage_without_fetching() {
        let server = MockServer::start().await;
        let verifier = verifier_against(&server);

        let err = verifier.verify_bearer("not-a-jwt").await.unwrap_err();

        assert!(matches!(err, AuthError::MalformedToken), "{err}");
    }

    #[tokio::test]
    async fn verify_bearer_surfaces_a_jwks_outage() {
        let server = issuer(ResponseTemplate::new(503), 1).await;
        let verifier = verifier_against(&server);
        let token = TestKey::primary().mint(&claims().build());

        let err = verifier.verify_bearer(&token).await.unwrap_err();

        assert!(matches!(err, AuthError::Jwks(_)), "{err}");
    }
}
