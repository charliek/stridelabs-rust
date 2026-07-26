//! A one-line wiremock convenience: a running mock server that answers every
//! request with one fixed JSON body and status.
//!
//! This is deliberately the *only* thing this module owns — a thin wrapper
//! around the single-response case, not a `wiremock` replacement. Anything
//! that needs to match on path/method/body, return different responses per
//! call, or assert on requests received should reach for
//! `wiremock::{Mock, MockServer, ResponseTemplate}` directly; this crate
//! depends on `wiremock` as a regular dependency precisely so a consumer's
//! tests can do that too without adding their own pin for it.

use serde_json::Value;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Start a mock HTTP server whose every request — any method, any path — is
/// answered with `status` and `body` as a JSON response.
///
/// ```no_run
/// # async fn example() -> Result<(), reqwest::Error> {
/// use serde_json::json;
/// use stridelabs_testing::serve_json;
///
/// let server = serve_json(201, json!({"id": "abc123"})).await;
///
/// let res = reqwest::get(format!("{}/anything", server.uri())).await?;
/// assert_eq!(res.status().as_u16(), 201);
/// # Ok(())
/// # }
/// ```
pub async fn serve_json(status: u16, body: Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(&server)
        .await;
    server
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn serve_json_answers_every_request_with_the_configured_body_and_status() {
        let server = serve_json(201, json!({"ok": true})).await;

        let response = reqwest::get(format!("{}/anything", server.uri()))
            .await
            .expect("request the mock server");

        assert_eq!(response.status().as_u16(), 201);
        let body: Value = response.json().await.expect("parse JSON body");
        assert_eq!(body, json!({"ok": true}));
    }

    #[tokio::test]
    async fn serve_json_answers_any_method_and_path() {
        let server = serve_json(200, json!({"ok": true})).await;
        let client = reqwest::Client::new();

        let response = client
            .post(format!("{}/some/other/path", server.uri()))
            .json(&json!({"ignored": "request body"}))
            .send()
            .await
            .expect("request the mock server");

        assert_eq!(response.status().as_u16(), 200);
    }
}
