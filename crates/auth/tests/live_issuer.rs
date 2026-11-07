//! `stridelabs-auth` against a live issuer, over plain HTTP.
//!
//! Every test is `#[ignore]`d and **panics** when its variables are missing, so
//! a lane that forgets to provide an issuer fails loudly instead of passing
//! with nothing checked. Run them with
//! `cargo test -p stridelabs-auth --features test-support --test live_issuer -- --ignored`.
//!
//! The variables, all read once by [`harness`] and never set:
//!
//! - `STRIDELABS_TEST_ISSUER`: the issuer's base URL, `http://…` (this
//!   workspace's reqwest has no TLS, so an HTTPS issuer is not supported);
//! - `STRIDELABS_TEST_AUDIENCE`: the audience the access token was minted for;
//! - `STRIDELABS_TEST_ACCESS_TOKEN`: an access token from that issuer;
//! - `STRIDELABS_TEST_SUBJECT` and `STRIDELABS_TEST_EMAIL`: its `sub` and `email`;
//! - `STRIDELABS_TEST_ID_TOKEN`: an ID token for the same user, needed only by
//!   [`id_token_is_refused_as_an_access_token`].
//!
//! The tests obtain no token: whoever runs the issuer hands one over.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;
use stridelabs_auth::test_support::{TestClaims, TestKey};
use stridelabs_auth::{Audience, AuthError, ClaimChecks, SlauthConfig, Verifier};

struct Harness {
    issuer: String,
    audience: String,
    access_token: String,
    subject: String,
    email: String,
    /// Read here with the rest, but required only by the ID-token test.
    id_token: Option<String>,
    http: reqwest::Client,
}

fn required(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "{name} is not set: these tests need a live issuer over plain HTTP \
             (STRIDELABS_TEST_ISSUER, _AUDIENCE, _ACCESS_TOKEN, _SUBJECT, _EMAIL, \
             and _ID_TOKEN for the ID-token test); they never skip"
        ),
    }
}

/// The one place the environment is read.
fn harness() -> Harness {
    // Kept exactly as given: `iss` is compared as a string, so a trailing
    // slash is part of the issuer. Only the discovery URL drops it.
    let issuer = required("STRIDELABS_TEST_ISSUER");
    assert!(
        issuer.starts_with("http://"),
        "STRIDELABS_TEST_ISSUER must be a plain http:// URL (this workspace's reqwest has no TLS), got {issuer:?}"
    );
    Harness {
        issuer,
        audience: required("STRIDELABS_TEST_AUDIENCE"),
        access_token: required("STRIDELABS_TEST_ACCESS_TOKEN"),
        subject: required("STRIDELABS_TEST_SUBJECT"),
        email: required("STRIDELABS_TEST_EMAIL"),
        id_token: std::env::var("STRIDELABS_TEST_ID_TOKEN")
            .ok()
            .filter(|v| !v.is_empty()),
        http: reqwest::Client::new(),
    }
}

impl Harness {
    /// `jwks_uri` from the issuer's discovery document.
    async fn jwks_uri(&self) -> String {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {url} failed: {e}"));
        assert!(
            resp.status().is_success(),
            "GET {url}: expected 2xx, got {}",
            resp.status()
        );
        let doc: Value = resp
            .json()
            .await
            .unwrap_or_else(|e| panic!("GET {url}: body is not JSON: {e}"));
        doc["jwks_uri"]
            .as_str()
            .unwrap_or_else(|| panic!("discovery document at {url} has no string jwks_uri: {doc}"))
            .to_owned()
    }

    /// A fresh verifier (so an empty key cache) under the profile's rules.
    fn verifier(&self, issuer: &str, audience: &str, jwks_url: String) -> Verifier {
        Verifier::new(
            SlauthConfig {
                issuer: issuer.to_owned(),
                jwks_url,
                audience: audience.to_owned(),
                pat_validate_url: None,
            },
            self.http.clone(),
        )
    }
}

fn expect_invalid(result: Result<impl std::fmt::Debug, AuthError>, reason: &str) {
    match result {
        Err(AuthError::InvalidToken(got)) if got == reason => {}
        other => panic!("expected AuthError::InvalidToken({reason:?}), got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a live issuer: STRIDELABS_TEST_ISSUER"]
async fn profile_accepts_the_access_token() {
    let h = harness();
    let verifier = h.verifier(&h.issuer, &h.audience, h.jwks_uri().await);
    let claims: Value = verifier
        .verify_bearer_claims(&h.access_token)
        .await
        .unwrap_or_else(|e| panic!("expected the access token to verify, got {e:?}"));

    assert_eq!(claims["iss"], h.issuer.as_str(), "iss in {claims}");
    let aud_ok = match &claims["aud"] {
        Value::String(a) => *a == h.audience,
        Value::Array(a) => a.iter().any(|v| v == h.audience.as_str()),
        _ => false,
    };
    assert!(
        aud_ok,
        "expected aud to contain {:?}, got {}",
        h.audience, claims["aud"]
    );
    assert_eq!(claims["sub"], h.subject.as_str(), "sub in {claims}");
    assert_eq!(claims["email"], h.email.as_str(), "email in {claims}");
    let scp_ok = match &claims["scp"] {
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => false,
    };
    assert!(scp_ok, "expected a non-empty scp, got {}", claims["scp"]);
}

#[tokio::test]
#[ignore = "needs a live issuer: STRIDELABS_TEST_ISSUER"]
async fn for_issuer_accepts_the_access_token() {
    let h = harness();
    let checks = ClaimChecks::new(h.issuer.clone(), Audience::Required(h.audience.clone()));
    let verifier = Verifier::for_issuer(checks, h.jwks_uri().await, None, h.http.clone());
    let claims: Value = verifier
        .verify_bearer_claims(&h.access_token)
        .await
        .unwrap_or_else(|e| panic!("expected the access token to verify, got {e:?}"));
    assert_eq!(claims["sub"], h.subject.as_str(), "sub in {claims}");
}

#[tokio::test]
#[ignore = "needs a live issuer: STRIDELABS_TEST_ISSUER"]
async fn wrong_audience_is_refused() {
    let h = harness();
    let wrong = format!("wrong-audience-{:08x}", rand::random::<u32>());
    let verifier = h.verifier(&h.issuer, &wrong, h.jwks_uri().await);
    expect_invalid(
        verifier.verify_bearer(&h.access_token).await,
        "audience is not accepted",
    );
}

#[tokio::test]
#[ignore = "needs a live issuer: STRIDELABS_TEST_ISSUER"]
async fn wrong_issuer_is_refused() {
    let h = harness();
    // The right keys, a different expected `iss`: the signature verifies and
    // the issuer check is what refuses.
    let verifier = h.verifier(
        "http://wrong-issuer.invalid",
        &h.audience,
        h.jwks_uri().await,
    );
    expect_invalid(
        verifier.verify_bearer(&h.access_token).await,
        "issuer is not accepted",
    );
}

#[tokio::test]
#[ignore = "needs a live issuer: STRIDELABS_TEST_ISSUER"]
async fn tampered_signature_is_refused() {
    let h = harness();
    let (head, sig) = h
        .access_token
        .rsplit_once('.')
        .unwrap_or_else(|| panic!("the access token has no signature segment"));
    let mut raw = URL_SAFE_NO_PAD
        .decode(sig)
        .unwrap_or_else(|e| panic!("the signature segment is not base64url: {e}"));
    assert!(!raw.is_empty(), "the signature segment is empty");
    let mid = raw.len() / 2;
    raw[mid] ^= 0xff;
    let tampered = format!("{head}.{}", URL_SAFE_NO_PAD.encode(&raw));
    assert_ne!(tampered, h.access_token, "the token was not changed");

    let verifier = h.verifier(&h.issuer, &h.audience, h.jwks_uri().await);
    expect_invalid(
        verifier.verify_bearer(&tampered).await,
        "signature is invalid",
    );
}

#[tokio::test]
#[ignore = "needs a live issuer: STRIDELABS_TEST_ISSUER"]
async fn unknown_key_is_refused() {
    let h = harness();
    let claims = TestClaims::new(h.issuer.clone(), h.audience.clone()).build();
    let kid = format!("kid-not-in-the-jwks-{:08x}", rand::random::<u32>());
    let token = TestKey::primary().mint_with_kid(&kid, &claims);

    // A fresh verifier has fetched nothing, so this lookup fetches the real
    // issuer's key set, finds no such kid in it, and refuses the key.
    let verifier = h.verifier(&h.issuer, &h.audience, h.jwks_uri().await);
    match verifier.verify_bearer(&token).await {
        Err(AuthError::UnknownKid) => {}
        other => panic!("expected AuthError::UnknownKid, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a live issuer: STRIDELABS_TEST_ISSUER"]
async fn id_token_is_refused_as_an_access_token() {
    let h = harness();
    let id_token = h.id_token.clone().unwrap_or_else(|| {
        panic!("STRIDELABS_TEST_ID_TOKEN is not set: this test needs the user's ID token")
    });
    // An ID token's `aud` is the client, not the resource server.
    let verifier = h.verifier(&h.issuer, &h.audience, h.jwks_uri().await);
    expect_invalid(
        verifier.verify_bearer(&id_token).await,
        "audience is not accepted",
    );
}
