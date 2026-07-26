//! Offline token minting for tests (feature `test-support`).
//!
//! Everything here signs with one of **two throwaway RSA keypairs committed
//! to this repository**. Neither is a secret and neither must ever be trusted
//! anywhere: see
//! `crates/auth/testdata/README.md`. The feature gate exists to keep these
//! keys — and the ability to mint a token that this crate will accept — out of
//! a production build's API surface.
//!
//! ```
//! use stridelabs_auth::test_support::{TestClaims, TestKey};
//! use stridelabs_auth::Verifier;
//!
//! let key = TestKey::primary();
//! let token = key.mint(
//!     &TestClaims::new("https://auth.test", "my-service")
//!         .subject("user-1")
//!         .email("u@example.com")
//!         .build(),
//! );
//!
//! let identity = Verifier::verify_with_jwks(
//!     &token, &key.jwks(), key.kid(), "https://auth.test", "my-service",
//! ).unwrap();
//! assert_eq!(identity.sub, "user-1");
//! ```
//!
//! To exercise the network path too, serve [`TestKey::jwks_json`] from a
//! wiremock server and point a [`crate::SlauthConfig`]'s `jwks_url` at it.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::{json, Value};

/// The `kid` of [`TestKey::primary`].
pub const PRIMARY_KID: &str = "stridelabs-test-key-1";
/// The `kid` of [`TestKey::secondary`].
pub const SECONDARY_KID: &str = "stridelabs-test-key-2";

/// A stand-in issuer, for tests that don't care what it is.
pub const ISSUER: &str = "https://auth.test.stridelabs.ai";
/// A stand-in audience, for tests that don't care what it is.
pub const AUDIENCE: &str = "stridelabs-test-service";

const PRIMARY_PEM: &str = include_str!("../testdata/test_signing_key.pem");
const PRIMARY_JWKS: &str = include_str!("../testdata/test_jwks.json");
const SECONDARY_PEM: &str = include_str!("../testdata/test_signing_key_2.pem");
const SECONDARY_JWKS: &str = include_str!("../testdata/test_jwks_2.json");

/// One of the committed test keypairs, with its public half as a JWKS.
#[derive(Debug, Clone, Copy)]
pub struct TestKey {
    pem: &'static str,
    jwks_json: &'static str,
    kid: &'static str,
}

impl TestKey {
    /// The key a test should reach for by default.
    pub fn primary() -> TestKey {
        TestKey {
            pem: PRIMARY_PEM,
            jwks_json: PRIMARY_JWKS,
            kid: PRIMARY_KID,
        }
    }

    /// A second, unrelated keypair.
    ///
    /// For the two cases that need a key the verifier does *not* trust: a
    /// signature made by the wrong key (sign with this one, label it with
    /// [`PRIMARY_KID`] via [`TestKey::mint_with_kid`]), and a rotation the
    /// JWKS cache has to notice (serve this key's JWKS on the second fetch).
    pub fn secondary() -> TestKey {
        TestKey {
            pem: SECONDARY_PEM,
            jwks_json: SECONDARY_JWKS,
            kid: SECONDARY_KID,
        }
    }

    /// The `kid` [`TestKey::mint`] stamps on its tokens.
    pub fn kid(&self) -> &'static str {
        self.kid
    }

    /// The PKCS#1 private key, for a test that needs to sign something this
    /// module doesn't mint (a token with no `kid`, say).
    pub fn pem(&self) -> &'static str {
        self.pem
    }

    /// This key's public half as JWKS **JSON text** — the body to serve from
    /// a mock issuer endpoint.
    pub fn jwks_json(&self) -> &'static str {
        self.jwks_json
    }

    /// This key's public half, parsed.
    pub fn jwks(&self) -> JwkSet {
        serde_json::from_str(self.jwks_json).expect("committed test JWKS is valid")
    }

    /// Sign `claims` as an RS256 JWT carrying this key's `kid`.
    ///
    /// Takes anything `Serialize` — a [`TestClaims`] built value, or a
    /// hand-written `serde_json::json!` object for a shape [`TestClaims`]
    /// can't express.
    pub fn mint<T: Serialize>(&self, claims: &T) -> String {
        self.mint_with_kid(self.kid, claims)
    }

    /// As [`TestKey::mint`], but stamps a `kid` of the caller's choosing —
    /// including one that names a *different* key.
    pub fn mint_with_kid<T: Serialize>(&self, kid: &str, claims: &T) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let key =
            EncodingKey::from_rsa_pem(self.pem.as_bytes()).expect("committed test key parses");
        encode(&header, claims, &key).expect("signing a test token cannot fail")
    }
}

/// The primary test key's JWKS, parsed. Shorthand for
/// `TestKey::primary().jwks()`.
pub fn test_jwks() -> JwkSet {
    TestKey::primary().jwks()
}

/// The primary test key's JWKS as JSON text, for serving from a mock issuer.
pub fn test_jwks_json() -> &'static str {
    TestKey::primary().jwks_json()
}

/// A claim set to mint, with every field a rejection test needs to spoil.
///
/// Defaults are a token that verifies: a subject, an email, a name, and an
/// hour of validity. Each setter takes the token one step away from that.
#[derive(Debug, Clone)]
pub struct TestClaims {
    issuer: String,
    audience: String,
    sub: String,
    email: Option<String>,
    name: Option<String>,
    expires_in_secs: i64,
}

impl TestClaims {
    /// A valid claim set for `issuer`/`audience`.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> TestClaims {
        TestClaims {
            issuer: issuer.into(),
            audience: audience.into(),
            sub: "test-subject".to_string(),
            email: Some("user@example.com".to_string()),
            name: Some("Test User".to_string()),
            expires_in_secs: 3600,
        }
    }

    /// Set `sub`. Pass `""` for the empty-subject rejection case.
    ///
    /// Named `subject` rather than `sub` because a method called `sub` on a
    /// value type reads as subtraction (and clippy says so).
    pub fn subject(mut self, sub: impl Into<String>) -> TestClaims {
        self.sub = sub.into();
        self
    }

    /// Set `email`. Pass `""` for the empty-email rejection case.
    pub fn email(mut self, email: impl Into<String>) -> TestClaims {
        self.email = Some(email.into());
        self
    }

    /// Omit the `email` claim entirely.
    pub fn without_email(mut self) -> TestClaims {
        self.email = None;
        self
    }

    /// Set `name`.
    pub fn name(mut self, name: impl Into<String>) -> TestClaims {
        self.name = Some(name.into());
        self
    }

    /// Omit the `name` claim entirely.
    pub fn without_name(mut self) -> TestClaims {
        self.name = None;
        self
    }

    /// Seconds from now until `exp`. **Negative for an already-expired
    /// token** — which is how an expiry test avoids sleeping.
    pub fn expires_in(mut self, secs: i64) -> TestClaims {
        self.expires_in_secs = secs;
        self
    }

    /// Render to the JSON object [`TestKey::mint`] signs.
    pub fn build(&self) -> Value {
        let now = unix_now();
        let mut claims = json!({
            "iss": self.issuer,
            "aud": self.audience,
            "sub": self.sub,
            "iat": now,
            "exp": now + self.expires_in_secs,
        });
        let object = claims
            .as_object_mut()
            .expect("built from an object literal");
        if let Some(email) = &self.email {
            object.insert("email".to_string(), json!(email));
        }
        if let Some(name) = &self.name {
            object.insert("name".to_string(), json!(name));
        }
        claims
    }
}

fn unix_now() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is not before 1970")
        .as_secs();
    i64::try_from(seconds).expect("the year is not 292277026596")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_keypairs_are_different() {
        assert_ne!(TestKey::primary().pem(), TestKey::secondary().pem());
        assert_ne!(
            TestKey::primary().jwks_json(),
            TestKey::secondary().jwks_json()
        );
    }

    #[test]
    fn each_jwks_holds_exactly_its_own_key() {
        for key in [TestKey::primary(), TestKey::secondary()] {
            let jwks = key.jwks();
            assert_eq!(jwks.keys.len(), 1);
            assert!(jwks.find(key.kid()).is_some());
        }
    }

    #[test]
    fn the_shorthands_point_at_the_primary_key() {
        assert_eq!(test_jwks_json(), TestKey::primary().jwks_json());
        assert!(test_jwks().find(PRIMARY_KID).is_some());
    }

    #[test]
    fn omitted_claims_are_absent_not_empty() {
        let claims = TestClaims::new(ISSUER, AUDIENCE)
            .without_email()
            .without_name()
            .build();

        assert!(claims.get("email").is_none());
        assert!(claims.get("name").is_none());
        assert!(claims.get("sub").is_some());
    }

    #[test]
    fn a_negative_expiry_is_in_the_past() {
        let claims = TestClaims::new(ISSUER, AUDIENCE).expires_in(-60).build();

        assert!(claims["exp"].as_i64().expect("exp") < unix_now());
    }
}
