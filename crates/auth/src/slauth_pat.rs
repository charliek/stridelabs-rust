//! slauth personal access tokens, validated by asking slauth.
//!
//! slauth issues `slp_live_…` PATs and resolves them at its validate endpoint:
//! `POST /api/v1/pat/validate` with `Authorization: Bearer <pat>` and no
//! body, answered — once the header is acceptable — with a 200 carrying
//! `{"valid": bool, "identity_id": uuid | null, "reason": string | null}`
//! (slauth `backend-rs/src/http/pat.rs`). [`PatValidator`] is that call and
//! nothing more: the Rust twin of stridelabs-python's `PATValidator`
//! (`stridelabs/auth/pat.py`), whose outcomes and messages it reproduces.
//! Caching is the consumer's to layer on top, since a cache's store and TTL
//! are app-specific, and so is what a PAT may do: slauth's answer carries an
//! identity and no scopes.
//!
//! Not to be confused with [`crate::pat`], which deals in tokens a service
//! issues for itself and looks up in its own database.
//!
//! # Outcomes
//!
//! | What happened | Result |
//! |---|---|
//! | not `slp_live_` + 43 characters ([`is_slauth_pat`]) | `Rejected("Invalid PAT format")`, without calling slauth |
//! | the answer came from anywhere but the validate URL (a redirect was followed) | `Unavailable("Authentication service error")` |
//! | no complete answer within [`PAT_VALIDATION_TIMEOUT`] | `Unavailable("Authentication service timeout")` |
//! | any other transport failure | `Unavailable("Authentication service unavailable")` |
//! | a body over [`MAX_ANSWER_BYTES`] | `Unavailable("Authentication service error")` |
//! | HTTP 401 | `Rejected("Invalid or expired PAT")` |
//! | any other status but 200, a 3xx included | `Unavailable("Authentication service error")` |
//! | a body that is not a JSON object | `Unavailable("Authentication service error")` |
//! | `valid` anything but `true` | `Rejected(<reason>)` for one of slauth's four reason codes, else `Rejected("Invalid token")` |
//! | `identity_id` not a UUID | `Unavailable("Authentication service error")` |
//! | otherwise | `Ok(identity_id)` |
//!
//! [`PatValidationError::Rejected`] is the caller's credential failing (a
//! 401). [`PatValidationError::Unavailable`] is slauth's outage, or this
//! service's misconfiguration, and never a verdict on the token (a 503).
//!
//! # Where this parts from Python, and why
//!
//! Python's behaviour is kept wherever it is defined. Where it is not — an
//! unhandled exception, or a case the type system here cannot express —
//! the answer is the nearest defined one:
//!
//! - A token that cannot travel in an HTTP header (a control character in
//!   it) is `Rejected("Invalid PAT format")`, without a call. httpx raises
//!   on it — for some characters an error Python maps to a 503, for others
//!   an unhandled exception — and no slauth PAT is shaped like that.
//! - JSON that is not an object is `Unavailable("Authentication service
//!   error")`; Python's `data.get` raised an unhandled `AttributeError`.
//! - `reason` passes through only as one of slauth's own codes
//!   (`invalid_format`, `not_found`, `revoked`, `expired`: the whole of
//!   slauth's vocabulary); anything else — another string, `null`, a
//!   non-string, an absent one — is `"Invalid token"`. Python passed any
//!   value through, which lets an endpoint that echoes its request put the
//!   token, or the URL, into an error.
//! - `identity_id` is parsed by `uuid` (hyphenated, simple, braced or URN);
//!   Python's `UUID()` also tolerates stray hyphens. slauth sends the
//!   hyphenated form.
//! - The 5 s timeout is one deadline for the whole exchange (reqwest's),
//!   where httpx's 5 s applied to each phase separately.
//! - **No redirect is trusted.** httpx followed none, so a 3xx was a service
//!   error; reqwest follows them by the injected client's policy. A verdict
//!   from wherever a redirect led — another origin, or another path — is
//!   not slauth's validate endpoint speaking, so an answer whose final URL is
//!   not the one requested is a service error, whatever it says. (reqwest
//!   also drops `Authorization` from a redirect that leaves the origin, so
//!   the PAT itself does not follow.) Pass a client built with
//!   `reqwest::redirect::Policy::none()` and no redirect is made at all.
//! - The body is read to at most [`MAX_ANSWER_BYTES`]; Python read any size.
//!
//! # Never the token, never the URL
//!
//! A [`PatValidationError`] holds one of the fixed messages above, or one
//! of slauth's four reason codes, and nothing else. The `warn` line each `Unavailable`
//! outcome logs (as Python logs one) names the failure and never the token
//! or the URL: a `reqwest::Error` is rendered `without_url()`, because the
//! validate URL is configuration, and configuration can carry a credential.
//! [`PatValidator`]'s `Debug` prints the URL as `scheme://host[:port]/path`,
//! like [`crate::SlauthConfig`]'s, and the request's `Authorization` value
//! is marked sensitive.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderValue, AUTHORIZATION};
use reqwest::StatusCode;
use serde_json::Value;
use uuid::Uuid;

use crate::config::{redact_url, SlauthConfig};

/// The prefix of every slauth-issued PAT.
pub const SLAUTH_PAT_PREFIX: &str = "slp_live_";

/// Characters after [`SLAUTH_PAT_PREFIX`]: slauth's body is 32 random bytes
/// as base64url without padding (`secrets.token_urlsafe(32)`).
const SLAUTH_PAT_BODY_CHARS: usize = 43;

/// The bound on one validation, connect to last body byte. Python's default
/// (`SlauthConfig.pat_timeout_seconds`).
pub const PAT_VALIDATION_TIMEOUT: Duration = Duration::from_secs(5);

/// The most of an answer's body that is read. slauth's answer is under 100
/// bytes; anything this large is not slauth answering, and reading it
/// unbounded would hand whatever does answer the process's memory.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// Every `reason` slauth gives with `valid: false` (`classify` in slauth's
/// `backend-rs/src/http/pat.rs`). Only these pass through to an error.
const SLAUTH_REASONS: [&str; 4] = ["invalid_format", "not_found", "revoked", "expired"];

const INVALID_FORMAT: &str = "Invalid PAT format";
const INVALID_OR_EXPIRED: &str = "Invalid or expired PAT";
const DEFAULT_REASON: &str = "Invalid token";
const SERVICE_ERROR: &str = "Authentication service error";
const SERVICE_TIMEOUT: &str = "Authentication service timeout";
const SERVICE_UNAVAILABLE: &str = "Authentication service unavailable";

/// Whether `token` has the shape of a slauth PAT: [`SLAUTH_PAT_PREFIX`] and
/// then exactly 43 characters.
///
/// Python's `is_pat_token`, to the letter: characters are Unicode scalar
/// values (Python's `len`), and their alphabet is not checked. A `true` says
/// nothing about validity — only slauth knows that.
///
/// To route a bearer token, test the prefix alone
/// (`token.starts_with(SLAUTH_PAT_PREFIX)`) and let
/// [`PatValidator::validate`] refuse a wrong shape, as the Python MCP
/// verifier does: a mangled slauth PAT is then refused as a PAT rather than
/// tried as a JWT.
pub fn is_slauth_pat(token: &str) -> bool {
    token
        .strip_prefix(SLAUTH_PAT_PREFIX)
        .is_some_and(|body| body.chars().count() == SLAUTH_PAT_BODY_CHARS)
}

/// Why a PAT was not resolved to an identity.
///
/// `Display` is the reason alone, as Python's `str(PATValidationError)` is,
/// so a consumer can put it in a response body unchanged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatValidationError {
    /// Not a valid slauth PAT: malformed, unknown, revoked or expired. The
    /// caller's credential failing — a 401. `reason` is a fixed message here
    /// or one of slauth's codes (`invalid_format`, `not_found`, `revoked`,
    /// `expired`).
    #[error("{reason}")]
    Rejected { reason: String },
    /// slauth gave no usable answer: down, slow, or answering something
    /// this client does not understand. Not a verdict on the token — a 503.
    #[error("{reason}")]
    Unavailable { reason: String },
}

impl PatValidationError {
    fn rejected(reason: &str) -> PatValidationError {
        PatValidationError::Rejected {
            reason: reason.to_owned(),
        }
    }

    fn unavailable(reason: &str) -> PatValidationError {
        PatValidationError::Unavailable {
            reason: reason.to_owned(),
        }
    }
}

/// Validates slauth PATs against slauth's validate endpoint. Stateless:
/// every call is one request.
///
/// Cheap to clone (the URL is shared, and a `reqwest::Client` is an `Arc`
/// already). Build it once with the service's shared client, so validations
/// reuse its connection pool and its TLS stack — which, as everywhere in
/// this crate, is the consumer's choice. Ideally that client is built with
/// `reqwest::redirect::Policy::none()`: a redirect is never trusted either
/// way (module docs), but with that policy none is followed at all.
#[derive(Clone)]
pub struct PatValidator {
    validate_url: Arc<str>,
    http: reqwest::Client,
    timeout: Duration,
}

impl fmt::Debug for PatValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PatValidator")
            .field("validate_url", &redact_url(&self.validate_url))
            // Never the client itself: reqwest::Client's Debug prints its
            // default headers, and an injected client may carry credentials.
            .field("http", &format_args!("reqwest::Client {{ .. }}"))
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl PatValidator {
    /// A validator calling `validate_url` — slauth's
    /// `…/api/v1/pat/validate` — with `http`.
    ///
    /// The URL is not checked here: one that cannot be requested makes
    /// every validation `Unavailable("Authentication service
    /// unavailable")`, a misconfiguration that shows up as an outage rather
    /// than as a wave of rejected tokens.
    pub fn new(validate_url: impl Into<String>, http: reqwest::Client) -> PatValidator {
        PatValidator {
            validate_url: Arc::from(validate_url.into()),
            http,
            timeout: PAT_VALIDATION_TIMEOUT,
        }
    }

    /// A validator for `config.pat_validate_url`, or `None` when the config
    /// names none — a service that takes no slauth PATs. An empty URL is
    /// none, as Python's `if not config.pat_validate_url` has it.
    pub fn from_config(config: &SlauthConfig, http: reqwest::Client) -> Option<PatValidator> {
        config
            .pat_validate_url
            .as_deref()
            .filter(|url| !url.is_empty())
            .map(|url| PatValidator::new(url, http))
    }

    /// Replace the timeout ([`PAT_VALIDATION_TIMEOUT`] by default).
    ///
    /// For tests, so a slow slauth can be simulated without a 5 s wait; the
    /// default is the contract.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> PatValidator {
        self.timeout = timeout;
        self
    }

    /// Resolve `pat` to the slauth identity it belongs to.
    ///
    /// See the module docs for every outcome.
    pub async fn validate(&self, pat: &str) -> Result<Uuid, PatValidationError> {
        if !is_slauth_pat(pat) {
            return Err(PatValidationError::rejected(INVALID_FORMAT));
        }
        // Built here rather than with `bearer_auth`, which defers a value
        // that is not a legal header to `send()` as a builder error — read
        // below as slauth being unavailable, when the fault is the token's.
        // Sensitive, so hyper and reqwest never print it in a `Debug`.
        let mut authorization = HeaderValue::try_from(format!("Bearer {pat}"))
            .map_err(|_| PatValidationError::rejected(INVALID_FORMAT))?;
        authorization.set_sensitive(true);

        // reqwest::Client has no default timeout, and the injected one may
        // not set one, so every request carries its own. Built first so the
        // URL compared below is the one reqwest actually requested (it moves
        // any userinfo out into a header).
        let request = self
            .http
            .post(&*self.validate_url)
            .header(AUTHORIZATION, authorization)
            .timeout(self.timeout)
            .build()
            .map_err(transport_failure)?;
        let requested = request.url().clone();
        let mut response = self
            .http
            .execute(request)
            .await
            .map_err(transport_failure)?;

        // Before anything the answer says, 401 included: a response from
        // wherever a redirect led is not slauth's validate endpoint
        // speaking, so neither its verdict nor its identity is trusted.
        if response.url() != &requested {
            tracing::warn!("slauth PAT validation was redirected; the answer is not trusted");
            return Err(PatValidationError::unavailable(SERVICE_ERROR));
        }

        let status = response.status();
        // Read in full before the status is looked at, as httpx's `post`
        // does: a body that times out or breaks off is the same transport
        // failure whatever status came before it. Chunk by chunk, so no
        // more than `MAX_ANSWER_BYTES` (plus one chunk) is ever held.
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport_failure)? {
            if body.len() + chunk.len() > MAX_ANSWER_BYTES {
                tracing::warn!(
                    limit = MAX_ANSWER_BYTES,
                    "slauth PAT validation answer exceeded the size limit"
                );
                return Err(PatValidationError::unavailable(SERVICE_ERROR));
            }
            body.extend_from_slice(&chunk);
        }

        if status == StatusCode::UNAUTHORIZED {
            return Err(PatValidationError::rejected(INVALID_OR_EXPIRED));
        }
        if status != StatusCode::OK {
            tracing::warn!(%status, "unexpected slauth PAT validation status");
            return Err(PatValidationError::unavailable(SERVICE_ERROR));
        }

        let Ok(Value::Object(answer)) = serde_json::from_slice::<Value>(&body) else {
            tracing::warn!(
                "slauth PAT validation answered with something other than a JSON object"
            );
            return Err(PatValidationError::unavailable(SERVICE_ERROR));
        };

        // Python's `data.get("valid") is not True`: only the JSON literal
        // `true` validates — not `"true"`, not `1`, and not an absent
        // `valid` next to an `identity_id`.
        if answer.get("valid") != Some(&Value::Bool(true)) {
            // Only slauth's own vocabulary passes through: anything else is
            // text from an endpoint answering unlike slauth, and it could be
            // an echo of the request.
            let reason = answer
                .get("reason")
                .and_then(Value::as_str)
                .filter(|reason| SLAUTH_REASONS.contains(reason))
                .unwrap_or(DEFAULT_REASON);
            return Err(PatValidationError::rejected(reason));
        }

        answer
            .get("identity_id")
            .and_then(Value::as_str)
            .and_then(|identity| Uuid::parse_str(identity).ok())
            .ok_or_else(|| {
                // The value itself stays out of the log: it is whatever the
                // endpoint said, and it said something unexpected.
                tracing::warn!("slauth PAT validation answered valid without a UUID identity_id");
                PatValidationError::unavailable(SERVICE_ERROR)
            })
    }
}

/// A request that produced no complete response: a timeout, or any other
/// transport failure (refused, reset, DNS, TLS, a body that broke off).
fn transport_failure(err: reqwest::Error) -> PatValidationError {
    // `without_url()`: a `reqwest::Error`'s `Display` otherwise ends
    // "for url (…)", query string included, and the validate URL is
    // configuration that can carry a credential.
    let timed_out = err.is_timeout();
    let err = err.without_url();
    if timed_out {
        tracing::warn!(error = %err, "slauth PAT validation timed out");
        PatValidationError::unavailable(SERVICE_TIMEOUT)
    } else {
        tracing::warn!(error = %err, "slauth PAT validation request failed");
        PatValidationError::unavailable(SERVICE_UNAVAILABLE)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use serde_json::json;
    use tracing_subscriber::fmt::MakeWriter;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// A well-formed PAT: the prefix and 43 base64url characters.
    const PAT: &str = "slp_live_Zq3-xY_7bN0pLmK2vR9sT4wU8aC1dE5fG6hJ0kMnOpQ";
    const VALIDATE_PATH: &str = "/api/v1/pat/validate";
    const IDENTITY: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn identity() -> Uuid {
        Uuid::parse_str(IDENTITY).expect("a UUID")
    }

    /// A mock slauth answering `response` to a validation of [`PAT`],
    /// expecting exactly `calls` of them (asserted when it drops). A request
    /// with any other method, path or `Authorization` gets wiremock's 404 —
    /// a service error here — and misses the count, so it fails loudly too.
    async fn slauth(response: ResponseTemplate, calls: u64) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(VALIDATE_PATH))
            .and(header("authorization", format!("Bearer {PAT}").as_str()))
            .respond_with(response)
            .expect(calls)
            .mount(&server)
            .await;
        server
    }

    fn validate_url(server: &MockServer) -> String {
        format!("{}{VALIDATE_PATH}", server.uri())
    }

    fn validator(server: &MockServer) -> PatValidator {
        PatValidator::new(validate_url(server), reqwest::Client::new())
    }

    fn answer(body: Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(body)
    }

    /// The error validating [`PAT`] against a slauth answering `response`.
    async fn failure(response: ResponseTemplate) -> PatValidationError {
        let server = slauth(response, 1).await;
        validator(&server)
            .validate(PAT)
            .await
            .expect_err("this answer must not validate")
    }

    fn rejected(reason: &str) -> PatValidationError {
        PatValidationError::Rejected {
            reason: reason.into(),
        }
    }

    fn unavailable(reason: &str) -> PatValidationError {
        PatValidationError::Unavailable {
            reason: reason.into(),
        }
    }

    #[test]
    fn is_slauth_pat_is_pythons_rule() {
        assert!(is_slauth_pat(PAT), "the fixture is well formed");
        let pat_of = |body: String| format!("{SLAUTH_PAT_PREFIX}{body}");

        assert!(is_slauth_pat(&pat_of("a".repeat(43))));
        // Characters, not bytes, and any characters at all.
        assert!(is_slauth_pat(&pat_of("é".repeat(43))));
        assert!(is_slauth_pat(&pat_of("!".repeat(43))));

        for not_a_pat in [
            String::new(),
            SLAUTH_PAT_PREFIX.to_owned(),
            pat_of("a".repeat(42)),
            pat_of("a".repeat(44)),
            // 43 bytes, 22 characters.
            pat_of(format!("{}a", "é".repeat(21))),
            format!("slp_test_{}", "a".repeat(43)),
            format!("SLP_LIVE_{}", "a".repeat(43)),
            format!(" {}", pat_of("a".repeat(42))),
            "eyJhbGciOiJSUzI1NiJ9.e30.sig".to_owned(),
        ] {
            assert!(!is_slauth_pat(&not_a_pat), "{not_a_pat:?}");
        }
    }

    #[tokio::test]
    async fn a_valid_pat_resolves_to_its_identity() {
        let server = slauth(
            answer(json!({ "valid": true, "identity_id": IDENTITY, "reason": null })),
            1,
        )
        .await;

        let identity_id = validator(&server).validate(PAT).await.expect("valid");

        assert_eq!(identity_id, identity());
        // The request itself: one POST, the PAT as a bearer token (the
        // mock's matchers), and no body.
        let requests = server.received_requests().await.expect("recording is on");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].body.is_empty(), "the validation has no body");
    }

    #[tokio::test]
    async fn every_uuid_form_slauth_might_send_is_accepted() {
        for form in [
            IDENTITY.to_owned(),
            IDENTITY.to_uppercase(),
            IDENTITY.replace('-', ""),
            format!("{{{IDENTITY}}}"),
            format!("urn:uuid:{IDENTITY}"),
        ] {
            let server = slauth(answer(json!({ "valid": true, "identity_id": form })), 1).await;

            let identity_id = validator(&server).validate(PAT).await;

            assert_eq!(identity_id, Ok(identity()), "{form}");
        }
    }

    #[tokio::test]
    async fn slauths_verdict_is_a_rejection_with_its_reason() {
        for reason in ["invalid_format", "not_found", "revoked", "expired"] {
            let err = failure(answer(json!({
                "valid": false,
                "identity_id": null,
                "reason": reason,
            })))
            .await;

            assert_eq!(err, rejected(reason));
        }
    }

    #[tokio::test]
    async fn a_verdict_without_a_string_reason_is_the_fallback() {
        for body in [
            json!({ "valid": false }),
            json!({ "valid": false, "reason": null }),
            json!({ "valid": false, "reason": 5 }),
            json!({ "valid": false, "reason": ["revoked"] }),
        ] {
            let err = failure(answer(body.clone())).await;

            assert_eq!(err, rejected("Invalid token"), "{body}");
        }
    }

    #[tokio::test]
    async fn anything_but_valid_true_is_a_rejection() {
        // Each carries a good identity, so only `valid` decides.
        for valid in [json!("true"), json!(1), Value::Null, json!({})] {
            let err = failure(answer(json!({ "valid": valid, "identity_id": IDENTITY }))).await;

            assert_eq!(err, rejected("Invalid token"), "valid {valid}");
        }
        let err = failure(answer(json!({ "identity_id": IDENTITY }))).await;
        assert_eq!(err, rejected("Invalid token"), "no valid at all");
    }

    #[tokio::test]
    async fn a_401_is_a_rejection() {
        let err = failure(ResponseTemplate::new(401)).await;

        assert_eq!(err, rejected("Invalid or expired PAT"));
    }

    #[tokio::test]
    async fn any_other_status_is_a_service_error() {
        for status in [201, 204, 302, 400, 403, 404, 429, 500, 502, 503] {
            let body = json!({ "valid": true, "identity_id": IDENTITY });

            let err = failure(ResponseTemplate::new(status).set_body_json(body)).await;

            assert_eq!(err, unavailable("Authentication service error"), "{status}");
        }
    }

    #[tokio::test]
    async fn a_slow_slauth_is_a_timeout() {
        let server = slauth(
            answer(json!({ "valid": true, "identity_id": IDENTITY }))
                .set_delay(Duration::from_secs(5)),
            1,
        )
        .await;
        let validator = validator(&server).with_timeout(Duration::from_millis(100));

        let started = Instant::now();
        let err = validator.validate(PAT).await.unwrap_err();

        assert_eq!(err, unavailable("Authentication service timeout"));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the injected timeout, not the answer, ended the call: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn the_default_timeout_is_five_seconds() {
        let validator = PatValidator::new("http://slauth.test/v", reqwest::Client::new());

        assert_eq!(validator.timeout, Duration::from_secs(5));
        assert_eq!(PAT_VALIDATION_TIMEOUT, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn an_unreachable_slauth_is_unavailable() {
        // Nothing listens on port 1.
        let validator = PatValidator::new(
            format!("http://127.0.0.1:1{VALIDATE_PATH}"),
            reqwest::Client::new(),
        );

        let err = validator.validate(PAT).await.unwrap_err();

        assert_eq!(err, unavailable("Authentication service unavailable"));
    }

    #[tokio::test]
    async fn a_body_that_is_not_a_json_object_is_a_service_error() {
        for body in ["not json", "", "{", "[]", "\"valid\"", "null", "true", "5"] {
            let err = failure(ResponseTemplate::new(200).set_body_string(body)).await;

            assert_eq!(err, unavailable("Authentication service error"), "{body:?}");
        }
    }

    #[tokio::test]
    async fn a_valid_answer_without_a_uuid_is_a_service_error() {
        for identity_id in [
            json!("not-a-uuid"),
            json!(""),
            json!("550e8400-e29b-41d4-a716-44665544000"),
            json!(5),
            Value::Null,
        ] {
            let err = failure(answer(json!({ "valid": true, "identity_id": identity_id }))).await;

            assert_eq!(
                err,
                unavailable("Authentication service error"),
                "{identity_id}"
            );
        }
        let err = failure(answer(json!({ "valid": true }))).await;
        assert_eq!(err, unavailable("Authentication service error"));
    }

    #[tokio::test]
    async fn a_malformed_pat_never_reaches_slauth() {
        // Any request at all is the bug: zero expected, whatever it carries.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(answer(json!({ "valid": true, "identity_id": IDENTITY })))
            .expect(0)
            .mount(&server)
            .await;
        let validator = validator(&server);
        let body = |tail: &str| format!("{SLAUTH_PAT_PREFIX}{}{tail}", "a".repeat(42));

        for not_a_pat in [
            String::new(),
            "not-a-pat".to_owned(),
            SLAUTH_PAT_PREFIX.to_owned(),
            body(""),
            body("aa"),
            format!("slp_test_{}", "a".repeat(43)),
            // Shaped like a PAT, but no HTTP header can carry it.
            body("\n"),
            body("\r"),
            body("\0"),
            body("\u{7f}"),
        ] {
            let err = validator.validate(&not_a_pat).await.unwrap_err();

            assert_eq!(err, rejected("Invalid PAT format"), "{not_a_pat:?}");
        }
    }

    #[test]
    fn from_config_reads_pat_validate_url() {
        let config = |pat_validate_url: Option<&str>| SlauthConfig {
            issuer: "https://auth.test".into(),
            jwks_url: "https://auth.test/jwks".into(),
            audience: "svc".into(),
            pat_validate_url: pat_validate_url.map(str::to_owned),
        };

        for none in [None, Some("")] {
            assert!(
                PatValidator::from_config(&config(none), reqwest::Client::new()).is_none(),
                "{none:?}"
            );
        }

        let validator = PatValidator::from_config(
            &config(Some("https://auth.test/api/v1/pat/validate")),
            reqwest::Client::new(),
        )
        .expect("a URL is configured");
        assert_eq!(
            &*validator.validate_url,
            "https://auth.test/api/v1/pat/validate"
        );
        assert_eq!(validator.timeout, PAT_VALIDATION_TIMEOUT);
    }

    #[tokio::test]
    async fn a_reason_outside_slauths_vocabulary_is_the_fallback() {
        let server = MockServer::start().await;
        let url = validate_url(&server);
        let body = &PAT[SLAUTH_PAT_PREFIX.len()..];
        assert_eq!(body.chars().count(), 43, "the PAT body itself");

        for reason in [
            body.to_owned(),
            PAT.to_owned(),
            format!("not_found: Bearer {PAT}"),
            url.clone(),
            format!("POST {url}"),
            String::new(),
            "REVOKED".to_owned(),
            " revoked".to_owned(),
            "revoked ".to_owned(),
            "Invalid or expired PAT".to_owned(),
        ] {
            let mock = Mock::given(method("POST"))
                .and(path(VALIDATE_PATH))
                .respond_with(answer(json!({ "valid": false, "reason": reason })))
                .expect(1)
                .mount_as_scoped(&server)
                .await;

            let err = validator(&server).validate(PAT).await.unwrap_err();

            assert_eq!(err, rejected("Invalid token"), "reason {reason:?}");
            drop(mock);
        }
    }

    // --- redirects and the size cap -------------------------------------------

    /// A slauth that answers every validation with `status` and a
    /// `Location` of `location`, `calls` times. The 3xx carries a body that
    /// would validate, so when no redirect is followed, only its status can
    /// refuse it.
    async fn redirecting(status: u16, location: &str, calls: u64) -> MockServer {
        slauth(
            ResponseTemplate::new(status)
                .set_body_json(json!({ "valid": true, "identity_id": IDENTITY }))
                .insert_header("location", location),
            calls,
        )
        .await
    }

    #[tokio::test]
    async fn a_redirected_answer_is_never_trusted() {
        // A second origin, answering whatever arrives — any method, any
        // headers — with a verdict that would validate (or reject).
        for (status, verdict) in [
            (
                302,
                answer(json!({ "valid": true, "identity_id": IDENTITY })),
            ),
            (
                307,
                answer(json!({ "valid": true, "identity_id": IDENTITY })),
            ),
            (308, ResponseTemplate::new(401)),
        ] {
            let elsewhere = MockServer::start().await;
            Mock::given(path(VALIDATE_PATH))
                .respond_with(verdict)
                .expect(1)
                .mount(&elsewhere)
                .await;
            let server = redirecting(status, &validate_url(&elsewhere), 1).await;

            let err = validator(&server).validate(PAT).await.unwrap_err();

            // The redirect really was followed and answered (`expect(1)`),
            // and the answer still decided nothing.
            assert_eq!(err, unavailable("Authentication service error"), "{status}");
            let followed = elsewhere
                .received_requests()
                .await
                .expect("recording is on");
            assert!(
                followed[0].headers.get("authorization").is_none(),
                "{status}: reqwest must not carry the PAT to another origin"
            );
        }
    }

    #[tokio::test]
    async fn a_redirect_to_another_path_on_slauth_is_not_trusted_either() {
        let server = redirecting(302, "/elsewhere", 1).await;
        Mock::given(path("/elsewhere"))
            .respond_with(answer(json!({ "valid": true, "identity_id": IDENTITY })))
            .expect(1)
            .mount(&server)
            .await;

        let err = validator(&server).validate(PAT).await.unwrap_err();

        assert_eq!(err, unavailable("Authentication service error"));
    }

    #[tokio::test]
    async fn with_redirects_off_a_3xx_is_a_service_error() {
        let elsewhere = MockServer::start().await;
        Mock::given(path(VALIDATE_PATH))
            .respond_with(answer(json!({ "valid": true, "identity_id": IDENTITY })))
            .expect(0)
            .mount(&elsewhere)
            .await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("a plain client builds");

        for status in [301, 302, 303, 307, 308] {
            let server = redirecting(status, &validate_url(&elsewhere), 1).await;
            let validator = PatValidator::new(validate_url(&server), client.clone());

            let err = validator.validate(PAT).await.unwrap_err();

            assert_eq!(err, unavailable("Authentication service error"), "{status}");
        }
    }

    /// A valid answer for [`IDENTITY`], padded with whitespace to exactly
    /// `len` bytes — still JSON, so only its size can refuse it.
    fn valid_answer_of_len(len: usize) -> ResponseTemplate {
        let mut body = json!({ "valid": true, "identity_id": IDENTITY }).to_string();
        assert!(body.len() <= len, "the answer itself fits");
        body.push_str(&" ".repeat(len - body.len()));
        ResponseTemplate::new(200).set_body_raw(body, "application/json")
    }

    #[tokio::test]
    async fn an_answer_at_the_size_cap_is_read() {
        let server = slauth(valid_answer_of_len(MAX_ANSWER_BYTES), 1).await;

        assert_eq!(validator(&server).validate(PAT).await, Ok(identity()));
    }

    #[tokio::test]
    async fn an_answer_over_the_size_cap_is_a_service_error() {
        for len in [MAX_ANSWER_BYTES + 1, 4 * 1024 * 1024] {
            let err = failure(valid_answer_of_len(len)).await;

            assert_eq!(
                err,
                unavailable("Authentication service error"),
                "{len} bytes"
            );
        }
    }

    // --- the token and URL canary --------------------------------------------

    const CANARY_MARKERS: &[&str] = &["CANARY-user", "CANARY-pass", "CANARY-token"];

    /// The validate URL at `authority`, carrying a credential in each place
    /// a URL can: userinfo, and a token in the query.
    fn canary_url(authority: impl fmt::Display) -> String {
        format!("http://CANARY-user:CANARY-pass@{authority}{VALIDATE_PATH}?token=CANARY-token")
    }

    #[track_caller]
    fn assert_clean(haystack: &str, what: &str) {
        let body = &PAT[SLAUTH_PAT_PREFIX.len()..];
        assert!(
            !haystack.contains(body),
            "{what} leaked the PAT: {haystack}"
        );
        for marker in CANARY_MARKERS {
            assert!(
                !haystack.contains(marker),
                "{what} leaked URL material ({marker:?}): {haystack}"
            );
        }
    }

    /// Every byte a fmt subscriber writes, for asserting on log lines.
    #[derive(Clone, Default)]
    struct LogSink(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log sink").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for LogSink {
        type Writer = LogSink;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl LogSink {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("log sink").clone()).expect("utf-8 logs")
        }
    }

    /// `err` from validating [`PAT`] with `validator`, and every line
    /// logged meanwhile. The subscriber is thread-local, and the tests run
    /// on a current-thread runtime, so the capture sees every line
    /// `validate` logs.
    async fn validate_captured(validator: &PatValidator) -> (PatValidationError, String) {
        let sink = LogSink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let err = validator.validate(PAT).await.unwrap_err();
        (err, sink.text())
    }

    /// One failure per arm of `validate` that talks to slauth, each against
    /// a URL full of credentials: each ends in its own verdict and logs its
    /// own warning (or none), and the error, its `Debug`, and every line
    /// logged on the way stay clean.
    #[tokio::test]
    async fn no_failure_renders_the_token_or_the_url() {
        // Mounted on path alone: reqwest turns the URL's userinfo into a
        // second `Authorization` header, which is not this test's subject.
        // Two requests each, one per pass below.
        let server = MockServer::start().await;
        let error = unavailable("Authentication service error");
        // (route, response, the verdict, the one warning it logs)
        let routes = [
            (
                "/status",
                ResponseTemplate::new(503),
                error.clone(),
                Some("unexpected slauth PAT validation status"),
            ),
            (
                "/unauthorized",
                ResponseTemplate::new(401),
                rejected("Invalid or expired PAT"),
                None,
            ),
            (
                "/garbage",
                ResponseTemplate::new(200).set_body_string("<html>"),
                error.clone(),
                Some("answered with something other than a JSON object"),
            ),
            (
                "/verdict",
                answer(json!({ "valid": false, "reason": format!("echo {PAT}") })),
                rejected("Invalid token"),
                None,
            ),
            (
                "/identity",
                answer(json!({ "valid": true, "identity_id": "nope" })),
                error.clone(),
                Some("answered valid without a UUID identity_id"),
            ),
            (
                "/oversize",
                valid_answer_of_len(MAX_ANSWER_BYTES + 1),
                error.clone(),
                Some("answer exceeded the size limit"),
            ),
            (
                "/redirect",
                ResponseTemplate::new(307)
                    .insert_header("location", format!("/target{VALIDATE_PATH}").as_str()),
                error.clone(),
                Some("was redirected; the answer is not trusted"),
            ),
            (
                "/slow",
                ResponseTemplate::new(200).set_delay(Duration::from_secs(5)),
                unavailable("Authentication service timeout"),
                Some("slauth PAT validation timed out"),
            ),
        ];
        // Where /redirect leads: a verdict that would validate.
        Mock::given(path(format!("/target{VALIDATE_PATH}")))
            .respond_with(answer(json!({ "valid": true, "identity_id": IDENTITY })))
            .expect(2)
            .mount(&server)
            .await;
        let mut cases = Vec::new();
        for (route, response, verdict, warning) in routes {
            Mock::given(path(format!("{route}{VALIDATE_PATH}")))
                .respond_with(response)
                .expect(2)
                .mount(&server)
                .await;
            let url = canary_url(format_args!("{}{route}", server.address()));
            cases.push((route, url, verdict, warning));
        }
        cases.push((
            "unreachable",
            canary_url("127.0.0.1:1"),
            unavailable("Authentication service unavailable"),
            Some("slauth PAT validation request failed"),
        ));

        // Twice, asserting on the second pass only. tracing caches each
        // callsite's interest globally, and while one scoped subscriber is
        // all that was ever registered, a `warn!` callsite that another
        // test's thread reaches first is cached as "never" — dropping this
        // test's line there. Installing a subscriber recomputes the interest
        // of every callsite already registered, so the second pass, whose
        // callsites the first registered, captures every line it logs.
        for assert in [false, true] {
            for (name, url, verdict, warning) in &cases {
                let validator = PatValidator::new(url.clone(), reqwest::Client::new())
                    .with_timeout(Duration::from_millis(200));

                let (err, logs) = validate_captured(&validator).await;
                if !assert {
                    continue;
                }

                // The intended branch, not merely some failure: its verdict,
                // and its own warning as the only one logged.
                assert_eq!(&err, verdict, "{name}");
                let warnings = logs.matches(" WARN ").count();
                match warning {
                    Some(text) => {
                        assert!(logs.contains(text), "{name}: not {text:?}: {logs:?}");
                        assert_eq!(warnings, 1, "{name}: {logs:?}");
                    }
                    None => assert_eq!(warnings, 0, "{name}: {logs:?}"),
                }

                assert_clean(&format!("{validator:?}"), &format!("{name}: Debug"));
                assert_clean(&format!("{err} / {err:?}"), name);
                assert_clean(&logs, &format!("{name}: logs"));
            }
        }
    }

    #[test]
    fn debug_names_the_endpoint_redacted() {
        let validator =
            PatValidator::new(canary_url("slauth.example:8443"), reqwest::Client::new());

        let debug = format!("{validator:?}");

        assert_clean(&debug, "Debug");
        assert!(
            debug.contains(r#""http://slauth.example:8443/api/v1/pat/validate""#),
            "Debug no longer names the endpoint: {debug}"
        );
    }
}
