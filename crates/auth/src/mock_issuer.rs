//! Wiremock scaffolding for the crate's own tests.
//!
//! `jwks.rs` and `verify.rs` both need "a server that answers `GET /jwks`",
//! and a `mod tests` is private to its file, so each had grown its own copy.
//! Kept here once instead — the same arrangement as
//! `crates/http/src/proxy/test_support.rs`.
//!
//! Not to be confused with [`crate::test_support`], which is the *public*,
//! feature-gated module consumers use to mint tokens. This one is
//! `#[cfg(test)]` and never leaves the crate.

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::test_support::test_jwks_json;

/// A 200 response carrying `json` as a JWKS body.
pub(crate) fn jwks_body(json: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(json.to_owned(), "application/json")
}

/// A mock issuer serving `body` at `/jwks`, expecting exactly `calls`
/// requests — asserted when the server drops at the end of the test.
pub(crate) async fn issuer(body: ResponseTemplate, calls: u64) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(body)
        .expect(calls)
        .mount(&server)
        .await;
    server
}

/// A 200 response carrying the primary test key's JWKS.
pub(crate) fn primary_body() -> ResponseTemplate {
    jwks_body(test_jwks_json())
}

/// The common case: an issuer serving the primary test key, hit `calls` times.
pub(crate) async fn primary_issuer(calls: u64) -> MockServer {
    issuer(primary_body(), calls).await
}

/// A mock issuer that answers its first request with `first` and its second
/// with `then`, expecting exactly those two — asserted when the server drops
/// at the end of the test. A rotation, an outage starting or ending.
pub(crate) async fn issuer_then(first: ResponseTemplate, then: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(first)
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(then)
        .expect(1)
        .mount(&server)
        .await;
    server
}

/// The JWKS endpoint of a mock issuer, as a `SlauthConfig`/`JwksCache` URL.
pub(crate) fn jwks_url_of(server: &MockServer) -> String {
    format!("{}/jwks", server.uri())
}

/// Requests the mock issuer has answered so far — checked mid-test, where
/// `expect(n)` only checks the total when the server drops.
pub(crate) async fn requests(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("wiremock records requests by default")
        .len()
}
