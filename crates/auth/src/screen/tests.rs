//! The screens, ported from tapper-rs's pre-lookup screen and its row-1 tests
//! (`tapper-rs/tests/auth.rs`, plan 015 C-3), through the public entry point
//! against an issuer that is down: a refusal that consulted the key set would
//! show as a request to it and as a `Jwks` error.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use jsonwebtoken::{encode, EncodingKey};
use serde_json::{json, Value};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::mock_issuer::{jwks_url_of, requests};
use crate::test_support::{TestClaims, TestKey, AUDIENCE, ISSUER, PRIMARY_KID};
use crate::{Audience, ClaimChecks, JwksCache, Verifier};

/// An issuer that answers every request 503, counting them.
async fn issuer_down() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    server
}

/// A verifier with a cold cache of its own, so that any lookup fetches.
fn verifier(server: &MockServer, policy: ScreenPolicy) -> Verifier {
    Verifier::with_cache(
        ClaimChecks::new(ISSUER, Audience::Required(AUDIENCE.into())),
        JwksCache::new(jwks_url_of(server), reqwest::Client::new()),
    )
    .screen(policy)
}

/// `token` through a fresh verifier under `policy`: the error, and how many
/// fetches it took.
async fn outcome(server: &MockServer, policy: ScreenPolicy, token: &str) -> (AuthError, usize) {
    let before = requests(server).await;
    let err = verifier(server, policy)
        .verify_bearer_claims::<Value>(token)
        .await
        .expect_err("the issuer is down, so nothing verifies");
    (err, requests(server).await - before)
}

fn claims() -> Value {
    TestClaims::new(ISSUER, AUDIENCE).build()
}

fn padded_claims(pad: usize) -> Value {
    TestClaims::new(ISSUER, AUDIENCE)
        .claim("pad", json!("x".repeat(pad)))
        .build()
}

/// `claims()` as JSON bytes with `member` (raw bytes, so they need not be
/// UTF-8) added as its last member.
fn with_member_bytes(member: &[u8]) -> Vec<u8> {
    let mut bytes = claims().to_string().into_bytes();
    assert_eq!(bytes.pop(), Some(b'}'), "claims serialize to an object");
    bytes.push(b',');
    bytes.extend_from_slice(member);
    bytes.push(b'}');
    bytes
}

/// `claims()` signed by the primary key under `alg`, with `kid`.
fn signed_as(alg: Algorithm, kid: Option<&str>) -> String {
    let key = TestKey::primary();
    let mut header = Header::new(alg);
    header.kid = kid.map(str::to_owned);
    let signing = match alg {
        Algorithm::HS256 => EncodingKey::from_secret(key.pem().as_bytes()),
        _ => EncodingKey::from_rsa_pem(key.pem().as_bytes()).expect("the test key parses"),
    };
    encode(&header, &claims(), &signing).expect("mint a token")
}

/// What a case expects: the exact refusal, by its rendering.
fn malformed() -> String {
    AuthError::MalformedToken.to_string()
}

fn invalid(reason: &str) -> String {
    AuthError::InvalidToken(reason.to_owned()).to_string()
}

fn missing_kid() -> String {
    AuthError::MissingKid.to_string()
}

/// Every token the strict screen refuses, each with its refusal: tapper's
/// row-1 cases, the structural ones and the header ones.
fn strict_refusals() -> Vec<(&'static str, String, String)> {
    let key = TestKey::primary();
    let encode_json = |json: &Value| URL_SAFE_NO_PAD.encode(json.to_string());
    let well_formed = key.mint(&claims());
    let segments: Vec<&str> = well_formed.split('.').collect();
    let [header, payload, signature] = segments[..] else {
        panic!("a minted token has three segments: {well_formed}");
    };
    let header_with = |member: &str, value: Value| {
        let mut object = json!({ "alg": "RS256", "typ": "JWT", "kid": PRIMARY_KID });
        object[member] = value;
        encode_json(&object)
    };
    // Six `~` hold one aligned 3-byte group whichever way they fall, and
    // `~~~` is `fn5+` in standard base64 (`fn5-` in base64url).
    let tilde_claims = TestClaims::new(ISSUER, AUDIENCE)
        .claim("pad", json!("~~~~~~"))
        .build()
        .to_string();
    let standard_payload = STANDARD_NO_PAD.encode(&tilde_claims);
    assert!(standard_payload.contains('+'), "{standard_payload}");
    let oversized = key.mint(&padded_claims(MAX_TOKEN_BYTES));
    assert!(oversized.len() > MAX_TOKEN_BYTES);
    let alg_none = format!(
        "{}.{}.",
        encode_json(&json!({ "alg": "none", "typ": "JWT", "kid": PRIMARY_KID })),
        encode_json(&claims())
    );
    let alg = invalid("algorithm is not accepted");
    let crit = invalid("critical header parameters are not supported");

    vec![
        ("not a token at all", "garbage".to_owned(), malformed()),
        ("empty", String::new(), malformed()),
        ("three dots of nothing", "..".to_owned(), malformed()),
        (
            "over 16 KiB, otherwise well-formed and signed",
            oversized,
            malformed(),
        ),
        ("two segments", format!("{header}.{payload}"), malformed()),
        (
            "four segments",
            format!("{well_formed}.{signature}"),
            malformed(),
        ),
        (
            "an empty header",
            format!(".{payload}.{signature}"),
            malformed(),
        ),
        (
            "an empty payload",
            format!("{header}..{signature}"),
            malformed(),
        ),
        (
            "an empty signature",
            format!("{header}.{payload}."),
            malformed(),
        ),
        (
            "alg: none, with our kid (and no signature)",
            alg_none,
            malformed(),
        ),
        (
            "the published kid's header, then `.!.!`",
            format!("{header}.!.!"),
            malformed(),
        ),
        (
            "a header that is not base64url",
            format!("{header}!.{payload}.{signature}"),
            malformed(),
        ),
        (
            "a payload that is not base64url",
            format!("{header}.{payload}!.{signature}"),
            malformed(),
        ),
        (
            "a signature that is not base64url",
            format!("{header}.{payload}.{signature}!"),
            malformed(),
        ),
        (
            "a padded signature",
            format!("{header}.{payload}.{signature}=="),
            malformed(),
        ),
        (
            "a payload in standard base64 (`+`)",
            format!("{header}.{standard_payload}.{signature}"),
            malformed(),
        ),
        (
            "a payload that is a JSON array",
            format!("{header}.{}.{signature}", encode_json(&json!([claims()]))),
            malformed(),
        ),
        (
            "a payload that is a JSON string",
            format!("{header}.{}.{signature}", encode_json(&json!("claims"))),
            malformed(),
        ),
        (
            "a payload that is JSON null",
            format!("{header}.{}.{signature}", encode_json(&json!(null))),
            malformed(),
        ),
        (
            "a payload that is not JSON",
            format!(
                "{header}.{}.{signature}",
                URL_SAFE_NO_PAD.encode("not json")
            ),
            malformed(),
        ),
        (
            "a payload object with trailing bytes",
            format!(
                "{header}.{}.{signature}",
                URL_SAFE_NO_PAD.encode(format!("{} x", claims()))
            ),
            malformed(),
        ),
        // The review's token: payload `{"x":"\xff"}`, a header naming kid
        // `k`, a one-byte signature.
        (
            "a payload string that is not UTF-8 (the review's token)",
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsifQ.eyJ4Ijoi_yJ9.AA".to_owned(),
            malformed(),
        ),
        (
            "the claims with a member whose value is not UTF-8",
            format!(
                "{header}.{}.{signature}",
                URL_SAFE_NO_PAD.encode(with_member_bytes(b"\"x\":\"\xff\""))
            ),
            malformed(),
        ),
        (
            "the claims with a member whose name is not UTF-8",
            format!(
                "{header}.{}.{signature}",
                URL_SAFE_NO_PAD.encode(with_member_bytes(b"\"\xff\":1"))
            ),
            malformed(),
        ),
        (
            "a header that is not JSON",
            format!(
                "{}.{payload}.{signature}",
                URL_SAFE_NO_PAD.encode("not json")
            ),
            malformed(),
        ),
        (
            "a kid one byte over the bound",
            format!(
                "{}.{payload}.{signature}",
                header_with("kid", json!("k".repeat(MAX_KID_BYTES + 1)))
            ),
            invalid("key id is too long"),
        ),
        (
            "a crit naming an extension",
            format!(
                "{}.{payload}.{signature}",
                header_with("crit", json!(["exp"]))
            ),
            crit.clone(),
        ),
        (
            "an empty crit",
            format!("{}.{payload}.{signature}", header_with("crit", json!([]))),
            crit.clone(),
        ),
        (
            "a null crit",
            format!("{}.{payload}.{signature}", header_with("crit", json!(null))),
            crit,
        ),
        (
            "HS256 under our kid (the public key as the secret)",
            signed_as(Algorithm::HS256, Some(PRIMARY_KID)),
            alg.clone(),
        ),
        (
            "RS512 under our kid",
            signed_as(Algorithm::RS512, Some(PRIMARY_KID)),
            alg.clone(),
        ),
        (
            "PS256 under our kid",
            signed_as(Algorithm::PS256, Some(PRIMARY_KID)),
            alg,
        ),
        ("no kid", signed_as(Algorithm::RS256, None), missing_kid()),
        (
            "an empty kid",
            signed_as(Algorithm::RS256, Some("")),
            missing_kid(),
        ),
    ]
}

/// Every strict refusal is the token's (its exact error), made before the
/// key lookup: no fetch, and no outage's error, with the issuer down. Every
/// mismatch is reported, not just the first, so a regression names each case
/// it reopens.
#[tokio::test]
async fn strict_refuses_each_malformed_token_without_a_fetch() {
    let server = issuer_down().await;

    let mut wrong = Vec::new();
    for (case, token, expected) in strict_refusals() {
        let (err, fetches) = outcome(&server, ScreenPolicy::Strict, &token).await;
        if err.to_string() != expected || fetches != 0 {
            wrong.push(format!(
                "{case}: {err} after {fetches} fetch(es), expected {expected}"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "refused only after the key lookup, or refused wrongly:\n{}",
        wrong.join("\n")
    );
}

/// The controls, in the same setup: well-formed tokens reach the key lookup
/// under the strict screen, so each fetches once and is the outage's `Jwks`,
/// including a kid of exactly the bound and an unseen kid.
#[tokio::test]
async fn strict_lets_a_well_formed_token_through_to_the_key_lookup() {
    let server = issuer_down().await;
    let key = TestKey::primary();
    let longest_kid = "k".repeat(MAX_KID_BYTES);

    for (case, token) in [
        ("the token the cases are cut from", key.mint(&claims())),
        (
            "an unseen kid",
            key.mint_with_kid("never-published", &claims()),
        ),
        (
            "a kid of exactly the bound",
            key.mint_with_kid(&longest_kid, &claims()),
        ),
    ] {
        let (err, fetches) = outcome(&server, ScreenPolicy::Strict, &token).await;
        assert!(matches!(err, AuthError::Jwks(_)), "{case}: {err}");
        assert_eq!(fetches, 1, "{case}: one fetch");
    }
}

/// The default screen is unchanged: it refuses what it always refused (a
/// header that does not parse, no `kid`) without a fetch, and lets the rest
/// of the strict screen's cases through to the key lookup, which is what
/// [`ScreenPolicy::Strict`] adds.
#[tokio::test]
async fn basic_refuses_only_an_unparseable_header_or_no_kid_before_the_lookup() {
    let server = issuer_down().await;
    let mut wrong = Vec::new();
    let mut reached = 0;

    for (case, token, _) in strict_refusals() {
        let header = decode_header(&token);
        let refused_first = match &header {
            Err(_) => Some(malformed()),
            Ok(header) if header.kid.is_none() => Some(missing_kid()),
            Ok(_) => None,
        };
        let (err, fetches) = outcome(&server, ScreenPolicy::Basic, &token).await;
        match refused_first {
            Some(expected) if err.to_string() == expected && fetches == 0 => {}
            None if fetches == 1 => reached += 1,
            _ => wrong.push(format!("{case}: {err} after {fetches} fetch(es)")),
        }
    }
    assert!(
        wrong.is_empty(),
        "the basic screen changed:\n{}",
        wrong.join("\n")
    );
    // crit (3), alg (3), an empty kid, an oversized kid, an oversized token,
    // and the payload and signature cases the header alone does not show.
    assert!(reached >= 9, "{reached} cases reached the lookup");
}

/// The size bound is [`MAX_TOKEN_BYTES`] exactly: of two well-formed, signed
/// tokens either side of it (the longest a padding claim makes within it, and
/// the shortest past it), the first reaches the key lookup and the second is
/// refused without a fetch.
#[tokio::test]
async fn strict_bounds_the_token_at_16_kib_exactly() {
    let server = issuer_down().await;
    let padded = |length: usize| TestKey::primary().mint(&padded_claims(length));
    // Base64 grows by one or two characters per byte, so stepping the pad by
    // one byte from safely under the bound finds both neighbours of it.
    let mut length = (MAX_TOKEN_BYTES - padded(0).len()) * 3 / 4 - 64;
    let mut within = padded(length);
    assert!(
        within.len() <= MAX_TOKEN_BYTES,
        "the search starts under the bound"
    );
    let past = loop {
        length += 1;
        let token = padded(length);
        if token.len() > MAX_TOKEN_BYTES {
            break token;
        }
        within = token;
    };
    assert!(
        MAX_TOKEN_BYTES - within.len() <= 1 && past.len() - MAX_TOKEN_BYTES <= 2,
        "{} and {} do not straddle {MAX_TOKEN_BYTES}",
        within.len(),
        past.len()
    );

    let (err, fetches) = outcome(&server, ScreenPolicy::Strict, &within).await;
    assert!(
        matches!(err, AuthError::Jwks(_)),
        "{} bytes: {err}",
        within.len()
    );
    assert_eq!(fetches, 1, "{} bytes: within the bound", within.len());
    let (err, fetches) = outcome(&server, ScreenPolicy::Strict, &past).await;
    assert!(
        matches!(err, AuthError::MalformedToken),
        "{} bytes: {err}",
        past.len()
    );
    assert_eq!(fetches, 0, "{} bytes: past the bound", past.len());
}

#[test]
fn the_default_policy_is_basic() {
    assert_eq!(ScreenPolicy::default(), ScreenPolicy::Basic);
}

/// Why the screen checks UTF-8 itself: skipping a member's value does not
/// validate the string it skips, so the object check alone lets the review's
/// payload through. The control: the same object with valid UTF-8 parses,
/// and with the screen's check the bad one is refused before the lookup.
#[test]
fn skipping_members_does_not_validate_utf8_so_the_screen_does() {
    let bad = b"{\"x\":\"\xff\"}";
    assert_eq!(
        URL_SAFE_NO_PAD.decode("eyJ4Ijoi_yJ9").expect("base64url"),
        bad,
        "the review's payload"
    );
    assert!(
        serde_json::from_slice::<JsonObject>(bad).is_ok(),
        "premise: the object check alone accepts it"
    );
    assert!(serde_json::from_slice::<JsonObject>(b"{\"x\":\"\xc3\xbf\"}").is_ok());

    let refused = kid_for_lookup(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsifQ.eyJ4Ijoi_yJ9.AA",
        ScreenPolicy::Strict,
    );
    assert!(
        matches!(refused, Err(AuthError::MalformedToken)),
        "{refused:?}"
    );
    let control = format!(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsifQ.{}.AA",
        URL_SAFE_NO_PAD.encode(b"{\"x\":\"\xc3\xbf\"}")
    );
    assert_eq!(
        kid_for_lookup(&control, ScreenPolicy::Strict).expect("valid UTF-8 passes"),
        "k"
    );
}
