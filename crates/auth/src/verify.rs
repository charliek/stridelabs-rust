//! Access-token verification: the thing this crate exists for.

use std::sync::Arc;

use jsonwebtoken::jwk::{
    AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse,
};
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

// `Debug` stays derived here and on `Verifier`: the only URL either holds is
// inside `SlauthConfig` and `JwksCache`, whose own `Debug` impls redact it.
// `jwks::tests::debug_never_renders_url_material` renders a `Verifier` to
// hold the composition to that.
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
    /// Checks, in order: the set holds a key under `kid` that is fit for RS256
    /// signatures (an RSA key whose `alg`, `use` and `key_ops`, where present,
    /// allow it); the key is usable; RS256 signature; `exp`; `iss` equals
    /// `issuer`; `aud` contains `audience`; a non-empty `email` claim; a
    /// non-empty `sub` claim.
    pub fn verify_with_jwks(
        token: &str,
        jwks: &JwkSet,
        kid: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<VerifiedIdentity, AuthError> {
        // Only a key the issuer published for RS256 signatures may verify one.
        // `DecodingKey::from_jwk` ignores the JWK's `alg`, `use` and `key_ops`,
        // so without this an RSA key labelled for encryption (`use: enc`,
        // `alg: RSA-OAEP`, or a label jsonwebtoken 11 parses as
        // `UNKNOWN_ALGORITHM` where 9 rejected the whole set) would verify a
        // token naming its kid. A kid with no fit key is `UnknownKid` (401),
        // not `Jwks` (500): there is no signature-verification key by that
        // name, the same verdict as a kid missing from the set; and the kid is
        // the caller's choice, so a 500 would let anyone raise this service's
        // error rate against an issuer that publishes encryption keys
        // alongside its signing keys. Keys sharing a kid are all considered,
        // so an encryption key listed first does not hide the signing key.
        let jwk = jwks
            .keys
            .iter()
            .filter(|jwk| jwk.common.key_id.as_deref() == Some(kid))
            .find(|jwk| verifies_rs256(jwk))
            .ok_or(AuthError::UnknownKid)?;
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
        // (The original implementation this crate replaced omitted this
        // line and had that hole; hardening, not parity.)
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

        // Hardening over the original implementation this crate replaced,
        // which accepted `sub: ""`. An empty subject is the same
        // collapse-to-one-user failure as an empty email, one layer down.
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

/// Whether `jwk` is an RSA key its issuer allows for RS256 signature
/// verification. An absent `alg`, `use` or `key_ops` allows it (RFC 7517 makes
/// all three optional); a present one must say RS256, say `sig`, or include
/// `verify`. Anything else, an unrecognised label included, rules the key out.
fn verifies_rs256(jwk: &Jwk) -> bool {
    let common = &jwk.common;
    matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
        && common
            .key_algorithm
            .is_none_or(|alg| alg == KeyAlgorithm::RS256)
        && common
            .public_key_use
            .as_ref()
            .is_none_or(|key_use| *key_use == PublicKeyUse::Signature)
        && common
            .key_operations
            .as_ref()
            .is_none_or(|ops| ops.contains(&KeyOperations::Verify))
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::errors::ErrorKind;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::{json, Value};
    use wiremock::{MockServer, ResponseTemplate};

    use super::*;
    use crate::mock_issuer::{issuer, jwks_body, jwks_url_of, primary_issuer};
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
        // omission fatal. Regression test for a review-found hole (the
        // original implementation this crate replaced had the same gap):
        // without it, dropping `iss` or `aud` from an otherwise-valid token
        // bypassed both checks.
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

    // --- the crypto backend -------------------------------------------------

    /// jsonwebtoken 10+ takes its crypto from crate features, unified across
    /// the whole graph this test is built in (the workspace's, and in a
    /// consumer, the consumer's). With exactly one of `aws_lc_rs` and
    /// `rust_crypto` on it works; with neither, or both, it still compiles
    /// cleanly and then panics at the first sign or verify. That is how the
    /// bare 9 → 11 bump passed clippy and failed only at test time. So this
    /// signs with the test-support key and verifies the token the way a
    /// service does (JWKS over HTTP into `verify_bearer`) and with a direct
    /// `jsonwebtoken::decode`. The wrong-key decode proves the backend really
    /// checks a signature rather than accepting whatever it is handed.
    #[tokio::test]
    async fn signing_and_verifying_work_on_the_one_crypto_backend() {
        let server = primary_issuer(1).await;
        let token = TestKey::primary().mint(&claims().subject("backend-check").build());

        let identity = verifier_against(&server)
            .verify_bearer(&token)
            .await
            .expect("a minted token verifies through the JWKS path");
        assert_eq!(identity.sub, "backend-check");

        let decoding_key = |key: TestKey| {
            let jwks = key.jwks();
            DecodingKey::from_jwk(jwks.find(key.kid()).expect("the key's own kid"))
                .expect("committed test JWK is a usable RSA key")
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[AUDIENCE]);

        let data = decode::<Claims>(&token, &decoding_key(TestKey::primary()), &validation)
            .expect("a minted token decodes directly");
        assert_eq!(data.claims.sub, "backend-check");

        let err = decode::<Claims>(&token, &decoding_key(TestKey::secondary()), &validation)
            .expect_err("a token must not verify under a key that did not sign it");
        assert_eq!(err.kind(), &ErrorKind::InvalidSignature);
    }

    // --- which key may verify -----------------------------------------------

    /// One key of a committed test JWKS, as JSON, to relabel.
    fn key_json(key: TestKey) -> Value {
        let set: Value = serde_json::from_str(key.jwks_json()).expect("committed JWKS");
        set["keys"][0].clone()
    }

    /// The primary key's JWK with `changes` applied (a `null` removes the
    /// member), as JWKS text, the form the cache fetches.
    fn primary_jwks_json_with(changes: Value) -> String {
        let mut key = key_json(TestKey::primary());
        let members = key.as_object_mut().expect("a JWK is an object");
        for (name, value) in changes.as_object().expect("changes are an object") {
            if value.is_null() {
                members.remove(name);
            } else {
                members.insert(name.clone(), value.clone());
            }
        }
        json!({ "keys": [key] }).to_string()
    }

    fn parse(jwks_json: &str) -> JwkSet {
        serde_json::from_str(jwks_json).expect("parses as a JWKS")
    }

    /// A good token from the primary key, checked against `jwks`.
    fn verify_against(jwks: &JwkSet) -> Result<VerifiedIdentity, AuthError> {
        let token = TestKey::primary().mint(&claims().build());
        Verifier::verify_with_jwks(&token, jwks, PRIMARY_KID, ISSUER, AUDIENCE)
    }

    #[test]
    fn a_key_labelled_for_another_algorithm_does_not_verify() {
        // The key really did sign the token; only its `alg` label is wrong.
        // `RSA-OAEP-512` is a name jsonwebtoken does not know: 9 refused the
        // whole set over it, 11 parses it as `UNKNOWN_ALGORITHM`, and
        // `DecodingKey::from_jwk` never looks at it.
        for alg in [
            "RSA-OAEP-512",
            "RSA-OAEP",
            "RSA-OAEP-256",
            "RSA1_5",
            "RS512",
            "PS256",
        ] {
            let jwks = parse(&primary_jwks_json_with(json!({ "alg": alg })));

            let err = verify_against(&jwks).unwrap_err();

            assert!(matches!(err, AuthError::UnknownKid), "alg {alg}: {err}");
        }
    }

    #[test]
    fn a_key_for_encryption_does_not_verify() {
        let jwks = parse(&primary_jwks_json_with(json!({ "use": "enc" })));

        let err = verify_against(&jwks).unwrap_err();

        assert!(matches!(err, AuthError::UnknownKid), "{err}");
    }

    #[test]
    fn a_key_whose_operations_exclude_verify_does_not_verify() {
        for ops in [json!(["encrypt", "wrapKey"]), json!(["sign"]), json!([])] {
            let jwks = parse(&primary_jwks_json_with(json!({ "key_ops": ops })));

            let err = verify_against(&jwks).unwrap_err();

            assert!(matches!(err, AuthError::UnknownKid), "key_ops {ops}: {err}");
        }
    }

    #[test]
    fn a_non_rsa_key_under_the_kid_does_not_verify() {
        // Unlabelled, so the key type is the only thing ruling each one out:
        // an EC P-256 public key (RFC 7517 appendix A.1) and a symmetric key.
        let foreign = [
            json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                "kid": PRIMARY_KID,
            }),
            json!({ "kty": "oct", "k": "cHVibGljIGtleSBtYXRlcmlhbA", "kid": PRIMARY_KID }),
        ];
        for key in foreign {
            let jwks = parse(&json!({ "keys": [key] }).to_string());

            let err = verify_against(&jwks).unwrap_err();

            assert!(matches!(err, AuthError::UnknownKid), "{key}: {err}");
        }
    }

    #[test]
    fn a_signing_key_verifies_with_or_without_its_labels() {
        for changes in [
            json!({}),
            json!({ "use": null, "alg": null }),
            json!({ "use": null, "alg": null, "key_ops": ["verify"] }),
            json!({ "key_ops": ["sign", "verify"] }),
        ] {
            let jwks = parse(&primary_jwks_json_with(changes.clone()));

            verify_against(&jwks).unwrap_or_else(|err| panic!("{changes}: {err}"));
        }
    }

    #[test]
    fn an_encryption_key_sharing_the_kid_does_not_hide_the_signing_key() {
        // A different keypair's public half, published as an encryption key
        // under the same kid and listed first.
        let mut encryption = key_json(TestKey::secondary());
        encryption["kid"] = json!(PRIMARY_KID);
        encryption["use"] = json!("enc");
        encryption["alg"] = json!("RSA-OAEP");
        let jwks =
            parse(&json!({ "keys": [encryption, key_json(TestKey::primary())] }).to_string());

        verify_against(&jwks).expect("the signing key under the kid verifies");
    }

    #[tokio::test]
    async fn verify_bearer_refuses_a_fetched_key_labelled_for_encryption() {
        // Through the fetch: jsonwebtoken 11 parses the set (9 refused it, a
        // `Jwks` outage for every token), and the key still may not verify.
        let jwks_json = primary_jwks_json_with(json!({ "alg": "RSA-OAEP-512", "use": "enc" }));
        let server = issuer(jwks_body(&jwks_json), 1).await;
        let token = TestKey::primary().mint(&claims().build());

        let err = verifier_against(&server)
            .verify_bearer(&token)
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::UnknownKid), "{err}");
    }
}
