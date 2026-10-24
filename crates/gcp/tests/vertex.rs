//! The Vertex client against wiremock: the endpoint, the auth headers, the
//! body, input validation, the response cap, and the failure modes. The pure
//! parts (hosts, the hostile-value table, request JSON, the classification
//! table) are unit tests in `src/vertex.rs`.
#![cfg(feature = "vertex")]

mod common;

use std::time::Duration;

use common::*;
use serde_json::{json, Value};
use stridelabs_gcp::vertex::{
    first_inline_image, GenerateContentRequest, GenerationConfig, ImageOutcome, Part, VertexClient,
    VertexError, DEFAULT_MAX_RESPONSE_BYTES,
};
use wiremock::matchers::{any, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MODEL_PATH: &str =
    "/v1beta1/projects/test-project/locations/global/publishers/google/models/gemini-3-pro-image-preview:generateContent";

async fn client(server: &MockServer) -> VertexClient {
    mount_metadata_token(server, "vertex-token").await;
    let tokens = metadata_provider(server, &[stridelabs_gcp::auth::CLOUD_PLATFORM_SCOPE])
        .with_quota_project(Some("quota-project".into()));
    VertexClient::new(reqwest::Client::new(), tokens, "test-project", "global")
        .unwrap()
        .with_base_url(server.uri())
}

fn request() -> GenerateContentRequest {
    GenerateContentRequest::user(vec![
        Part::from_text("make it blue"),
        Part::from_bytes("image/png", b"\x89PNG".to_vec()),
    ])
    .with_generation_config(GenerationConfig::response_modalities(["IMAGE"]))
}

#[test]
fn the_default_endpoint_is_the_global_host() {
    let tokens = stridelabs_gcp::TokenProvider::metadata_server(reqwest::Client::new(), &[]);
    let global = VertexClient::new(
        reqwest::Client::new(),
        tokens.clone(),
        "test-project",
        "global",
    )
    .unwrap();
    assert_eq!(
        global.endpoint("gemini-3-pro-image-preview").unwrap(),
        format!("https://aiplatform.googleapis.com{MODEL_PATH}")
    );
    let regional = VertexClient::new(
        reqwest::Client::new(),
        tokens,
        "test-project",
        "us-central1",
    )
    .unwrap()
    .with_api_version("v1");
    assert_eq!(
        regional.endpoint("m").unwrap(),
        "https://us-central1-aiplatform.googleapis.com/v1/projects/test-project/locations/us-central1/publishers/google/models/m:generateContent"
    );
}

/// A hostile location never builds a client; a hostile model or version
/// never gets as far as a token, let alone a request.
#[tokio::test]
async fn hostile_url_parts_send_nothing_and_fetch_no_token() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(token_body("never", json!(3600)))
        .expect(0)
        .mount(&server)
        .await;
    let tokens = metadata_provider(&server, &[]);
    let http = reqwest::Client::new;

    for location in [
        "attacker.example/",
        "attacker.example",
        "..",
        "a/b",
        "x?y",
        "x#y",
        "%2e%2e",
    ] {
        assert!(
            matches!(
                VertexClient::new(http(), tokens.clone(), "test-project", location),
                Err(VertexError::InvalidArgument(_))
            ),
            "location {location:?}"
        );
    }
    for project in [
        "attacker.example/",
        "..",
        "a/b",
        "x?y",
        "x#y",
        "%2e%2e",
        "test-project/../x",
    ] {
        assert!(
            matches!(
                VertexClient::new(http(), tokens.clone(), project, "global"),
                Err(VertexError::InvalidArgument(_))
            ),
            "project {project:?}"
        );
    }

    let vertex = VertexClient::new(http(), tokens.clone(), "test-project", "global")
        .unwrap()
        .with_base_url(server.uri());
    for model in [
        "attacker.example/",
        "..",
        ".",
        "a/b",
        "x?y",
        "x#y",
        "%2e%2e",
    ] {
        assert!(
            matches!(
                vertex.generate_content(model, &request()).await,
                Err(VertexError::InvalidArgument(_))
            ),
            "model {model:?}"
        );
    }
    for version in ["v1/../x", "..", "v1?x", "v1#x", "%2e%2e", "1"] {
        let vertex = vertex.clone().with_api_version(version);
        assert!(
            matches!(
                vertex
                    .generate_content("gemini-3.1-flash-image", &request())
                    .await,
                Err(VertexError::InvalidArgument(_))
            ),
            "version {version:?}"
        );
    }
    server.verify().await;
}

#[tokio::test]
async fn generate_content_posts_the_request_with_auth_and_parses_the_answer() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MODEL_PATH))
        .and(header("authorization", "Bearer vertex-token"))
        .and(header("x-goog-user-project", "quota-project"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "candidates": [{
                "content": {"role": "model", "parts": [
                    {"inlineData": {"mimeType": "image/png", "data": "iVBORw=="}}
                ]},
                "finishReason": "STOP",
            }],
            "modelVersion": "gemini-3-pro-image-preview",
            "usageMetadata": {"totalTokenCount": 1290},
        })))
        .expect(1)
        .mount(&server)
        .await;
    let vertex = client(&server).await;

    let response = vertex
        .generate_content("gemini-3-pro-image-preview", &request())
        .await
        .expect("a 200");

    assert_eq!(
        first_inline_image(&response),
        ImageOutcome::Image {
            bytes: b"\x89PNG".to_vec(),
            mime_type: Some("image/png".into()),
        }
    );
    let sent = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|request| request.url.path() == MODEL_PATH)
        .unwrap();
    let body: Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(
        body,
        json!({
            "contents": [{"role": "user", "parts": [
                {"text": "make it blue"},
                {"inlineData": {"mimeType": "image/png", "data": "iVBORw=="}},
            ]}],
            "generationConfig": {"responseModalities": ["IMAGE"]},
        })
    );
    server.verify().await;
}

#[tokio::test]
async fn a_blocked_answer_is_a_successful_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MODEL_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "promptFeedback": {"blockReason": "PROHIBITED_CONTENT"}
        })))
        .mount(&server)
        .await;

    let response = client(&server)
        .await
        .generate_content("gemini-3-pro-image-preview", &request())
        .await
        .unwrap();

    assert_eq!(
        first_inline_image(&response),
        ImageOutcome::Blocked {
            reason: "PROHIBITED_CONTENT".into()
        }
    );
}

/// `Display` and `Debug` say only the HTTP status and Google's
/// `error.status`. Google's `error.message` can quote the prompt — here a
/// `PROMPT-CANARY` — so it is kept, truncated, behind `sensitive_message()`
/// only. Everything else in the body never comes out at all.
#[tokio::test]
async fn a_non_2xx_logs_only_statuses_and_keeps_the_prompt_echo_apart() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MODEL_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "code": 400,
                "status": "INVALID_ARGUMENT",
                "message": format!(
                    "Unable to process prompt \"draw PROMPT-CANARY\" {}",
                    "q".repeat(5000)
                ),
                "details": [{"@type": "x", "metadata": {"debug": "CANARY-IN-DETAILS"}}],
            },
            "echo": "CANARY-OUTSIDE",
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            MODEL_PATH.replace("gemini-3-pro-image-preview", "html"),
        ))
        .respond_with(ResponseTemplate::new(503).set_body_string("<html>CANARY</html>"))
        .mount(&server)
        .await;
    let vertex = client(&server).await;

    let error = vertex
        .generate_content("gemini-3-pro-image-preview", &request())
        .await
        .unwrap_err();
    let rendered = format!("{error} | {error:?} | {error:#?}");
    assert!(!rendered.contains("CANARY"), "{rendered}");
    assert!(
        !rendered.contains("prompt"),
        "no message text at all: {rendered}"
    );
    assert_eq!(
        error.to_string(),
        "Vertex AI answered HTTP 400 (INVALID_ARGUMENT)"
    );
    let message = error
        .sensitive_message()
        .expect("kept for a deliberate reader");
    assert!(message.contains("PROMPT-CANARY"), "{message}");
    assert!(
        message.chars().count() <= 201,
        "truncated: {}",
        message.len()
    );
    assert!(!message.contains("CANARY-IN-DETAILS") && !message.contains("CANARY-OUTSIDE"));

    let error = vertex
        .generate_content("html", &request())
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "Vertex AI answered HTTP 503");
    assert_eq!(error.sensitive_message(), None);
    assert!(!format!("{error:?}").contains("CANARY"));
}

/// The `error.status` a `Status` stores, and so what `Display` and the
/// derived `Debug` show: one of google.rpc.Code's names as itself, any other
/// string as `other`. Before v0.10.0 any plain `[A-Za-z0-9_.-]{1,64}` code
/// passed through, so `CANARY_STATUS` is the behaviour change.
#[tokio::test]
async fn an_error_status_is_shown_only_from_the_list() {
    let cases = [
        ("RESOURCE_EXHAUSTED", Some("RESOURCE_EXHAUSTED")),
        ("ABORTED", Some("ABORTED")),
        ("CANARY_STATUS", Some("other")),
        ("resource_exhausted_canary", Some("other")),
        ("", None),
    ];
    for (status, shown) in cases {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(MODEL_PATH))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({
                "error": {"code": 429, "status": status, "message": "quota"}
            })))
            .mount(&server)
            .await;
        let error = client(&server)
            .await
            .generate_content("gemini-3-pro-image-preview", &request())
            .await
            .unwrap_err();
        let expected = match shown {
            Some(shown) => format!("Vertex AI answered HTTP 429 ({shown})"),
            None => "Vertex AI answered HTTP 429".to_owned(),
        };
        assert_eq!(error.to_string(), expected, "{status:?}");
        assert!(
            matches!(&error, VertexError::Status { google_status, .. }
                if google_status.as_deref() == shown),
            "{error:?}"
        );
        let debug = format!("{error:?} {error:#?}");
        assert!(!debug.to_lowercase().contains("canary"), "{debug}");
    }
}

/// A decode failure reports where, never what: serde's `Display` would quote
/// the offending value.
#[tokio::test]
async fn a_2xx_that_is_not_a_response_is_a_decode_error_that_quotes_nothing() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MODEL_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>CANARY proxy page</html>"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            MODEL_PATH.replace("gemini-3-pro-image-preview", "bad-base64"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "candidates": [{"content": {"parts": [{"inlineData": {"data": "%%%CANARY"}}]}}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            MODEL_PATH.replace("gemini-3-pro-image-preview", "wrong-type"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "candidates": [{"finishReason": ["CANARY-IN-A-VALUE"]}]
        })))
        .mount(&server)
        .await;
    let vertex = client(&server).await;

    for model in ["gemini-3-pro-image-preview", "bad-base64", "wrong-type"] {
        match vertex.generate_content(model, &request()).await {
            Err(error @ VertexError::Decode(_)) => {
                let rendered = format!("{error} {error:?}");
                assert!(!rendered.contains("CANARY"), "{model}: {rendered}");
                assert!(rendered.contains("error at line"), "{model}: {rendered}");
            }
            other => panic!("{model}: expected Decode, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_response_past_the_cap_is_too_large() {
    assert_eq!(DEFAULT_MAX_RESPONSE_BYTES, 64 * 1024 * 1024);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MODEL_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "candidates": [{"content": {"parts": [{"inlineData": {"data": "A".repeat(4096)}}]}}]
        })))
        .mount(&server)
        .await;
    let vertex = client(&server).await;

    assert!(matches!(
        vertex
            .clone()
            .with_max_response_bytes(1024)
            .generate_content("gemini-3-pro-image-preview", &request())
            .await,
        Err(VertexError::TooLarge { limit: 1024 })
    ));
    assert!(
        vertex
            .with_max_response_bytes(8192)
            .generate_content("gemini-3-pro-image-preview", &request())
            .await
            .is_ok(),
        "under the cap"
    );
}

#[tokio::test]
async fn the_timeout_bounds_the_whole_call() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MODEL_PATH))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
        .mount(&server)
        .await;
    let vertex = client(&server)
        .await
        .with_timeout(Duration::from_millis(200));

    assert!(matches!(
        vertex.generate_content("gemini-3-pro-image-preview", &request()).await,
        Err(VertexError::Timeout(timeout)) if timeout == Duration::from_millis(200)
    ));
}

#[tokio::test]
async fn a_token_failure_is_an_auth_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(METADATA_TOKEN_PATH))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let vertex = VertexClient::new(
        reqwest::Client::new(),
        metadata_provider(&server, &[]),
        "test-project",
        "global",
    )
    .unwrap()
    .with_base_url(server.uri());

    assert!(matches!(
        vertex.generate_content("m", &request()).await,
        Err(VertexError::Auth(_))
    ));
}

/// A `401` is the answer: one request and `Status { 401 }`, with no second
/// token and no replay (a caller that wants one evicts the token with
/// `TokenProvider::invalidate` and calls again).
#[tokio::test]
async fn a_401_is_one_request_and_no_replay() {
    let vertex_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MODEL_PATH))
        .respond_with(Sequence::new(vec![
            ResponseTemplate::new(401),
            ResponseTemplate::new(200).set_body_json(json!({"candidates": []})),
        ]))
        .mount(&vertex_server)
        .await;
    let tokens = token_server(bearers(&BEARERS)).await;
    let vertex = VertexClient::new(
        never_retrying(),
        exact_provider(&tokens),
        "test-project",
        "global",
    )
    .unwrap()
    .with_base_url(vertex_server.uri());

    let result = vertex
        .generate_content("gemini-3-pro-image-preview", &request())
        .await;

    assert!(
        matches!(result, Err(VertexError::Status { status: 401, .. })),
        "{result:?}"
    );
    assert_eq!(request_count(&vertex_server).await, 1, "one request");
    assert_eq!(request_count(&tokens).await, 1, "one token");
    assert_eq!(bearers_sent(&vertex_server).await, ["t1"]);
}
