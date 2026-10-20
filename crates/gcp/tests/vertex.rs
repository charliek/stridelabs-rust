//! The Vertex client against wiremock: the endpoint, the auth headers, the
//! body, input validation, the response cap, the failure modes, and the
//! opt-in 401 refresh and replay, by exact request counts. The pure parts
//! (hosts, the hostile-value table, request JSON, the classification table)
//! are unit tests in `src/vertex.rs`.
#![cfg(feature = "vertex")]

mod common;

use std::time::{Duration, Instant};

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

// --- the 401 refresh and replay ---------------------------------------------------

/// Vertex answers of these statuses, in order; a 200 is a valid (empty)
/// `generateContent` response.
fn answers(codes: &[u16]) -> Vec<ResponseTemplate> {
    codes
        .iter()
        .map(|&code| match code {
            200 => ResponseTemplate::new(200).set_body_json(json!({"candidates": []})),
            code => ResponseTemplate::new(code),
        })
        .collect()
}

/// A Vertex stand-in answering `answers` in order (the last repeated), and a
/// metadata server of its own minting `tokens` in order.
struct Rig {
    vertex: MockServer,
    tokens: MockServer,
}

impl Rig {
    async fn start(answers: Vec<ResponseTemplate>, tokens: Vec<ResponseTemplate>) -> Rig {
        let vertex = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(MODEL_PATH))
            .respond_with(Sequence::new(answers))
            .mount(&vertex)
            .await;
        Rig {
            vertex,
            tokens: token_server(tokens).await,
        }
    }

    fn client(&self) -> VertexClient {
        VertexClient::new(
            never_retrying(),
            exact_provider(&self.tokens),
            "test-project",
            "global",
        )
        .unwrap()
        .with_base_url(self.vertex.uri())
    }

    /// [`Rig::client`] with its first token already cached, so no token
    /// exchange runs before the first send of a window a test measures.
    async fn warm_client(&self) -> VertexClient {
        let tokens = exact_provider(&self.tokens);
        tokens.token().await.unwrap();
        VertexClient::new(never_retrying(), tokens, "test-project", "global")
            .unwrap()
            .with_base_url(self.vertex.uri())
    }

    /// (Vertex requests, tokens minted)
    async fn counts(&self) -> (usize, usize) {
        (
            request_count(&self.vertex).await,
            request_count(&self.tokens).await,
        )
    }
}

async fn call(vertex: &VertexClient) -> Result<(), VertexError> {
    vertex
        .generate_content("gemini-3-pro-image-preview", &request())
        .await
        .map(drop)
}

fn is_status(result: &Result<(), VertexError>, expected: u16) -> bool {
    matches!(result, Err(VertexError::Status { status, .. }) if *status == expected)
}

/// v0.8.0's behaviour, pinned: without the opt-in a 401 is one request and
/// `Status { 401 }`, with no second token. A count set alone does not turn
/// it on.
#[tokio::test]
async fn by_default_a_401_is_one_request_and_no_refresh() {
    for vertex in [
        |rig: &Rig| rig.client(),
        |rig: &Rig| rig.client().with_max_refresh_attempts(5),
    ] {
        let rig = Rig::start(answers(&[401, 200]), bearers(&BEARERS)).await;
        let vertex = vertex(&rig);
        assert!(!vertex.unauthorized_refresh());

        let result = call(&vertex).await;

        assert!(is_status(&result, 401), "{result:?}");
        assert_eq!(rig.counts().await, (1, 1), "(requests, tokens)");
    }
}

/// N = 0, 1, 2: a persistent 401 costs N + 1 requests and N refreshes, 401
/// then 200 within the budget succeeds, and each replay carries the bearer
/// just refreshed.
#[tokio::test]
async fn the_count_bounds_the_replays() {
    for (n, codes, failure, sent) in REFRESH_CASES {
        let case = format!("N = {n}, answers {codes:?}");
        let rig = Rig::start(answers(codes), bearers(&BEARERS)).await;
        let vertex = rig
            .client()
            .with_unauthorized_refresh(true)
            .with_max_refresh_attempts(n);

        let result = call(&vertex).await;

        match failure {
            None => assert!(result.is_ok(), "{case}: {result:?}"),
            Some(status) => assert!(is_status(&result, status), "{case}: {result:?}"),
        }
        assert_eq!(
            rig.counts().await,
            (sent, sent),
            "{case}: (requests, tokens)"
        );
        assert_eq!(bearers_sent(&rig.vertex).await, BEARERS[..sent], "{case}");
    }
}

#[tokio::test]
async fn the_default_count_is_two() {
    let _: fn(VertexClient, bool) -> VertexClient = VertexClient::with_unauthorized_refresh;
    let _: fn(VertexClient, u32) -> VertexClient = VertexClient::with_max_refresh_attempts;
    let _: fn(&VertexClient) -> bool = VertexClient::unauthorized_refresh;
    let _: fn(&VertexClient) -> u32 = VertexClient::max_refresh_attempts;

    let rig = Rig::start(answers(&[401]), bearers(&BEARERS)).await;
    let vertex = rig.client();
    assert_eq!(
        (vertex.unauthorized_refresh(), vertex.max_refresh_attempts()),
        (false, 2)
    );
    let vertex = vertex.with_unauthorized_refresh(true);
    assert_eq!(
        (vertex.unauthorized_refresh(), vertex.max_refresh_attempts()),
        (true, 2)
    );

    let result = call(&vertex).await;

    assert!(is_status(&result, 401), "{result:?}");
    assert_eq!(rig.counts().await, (3, 3), "3 requests, 2 refreshes");
}

/// The replay is the same POST: the JSON serialized once, so both sends
/// carry the exact same bytes and `Content-Type`. Only the bearer changes.
#[tokio::test]
async fn a_replayed_call_sends_byte_identical_json() {
    let rig = Rig::start(answers(&[401, 200]), bearers(&BEARERS)).await;
    let vertex = rig.client().with_unauthorized_refresh(true);

    call(&vertex).await.unwrap();

    let requests = rig.vertex.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let (first, replay) = (&requests[0], &requests[1]);
    assert_eq!(first.url, replay.url);
    assert_eq!(first.body, replay.body, "byte-identical");
    assert_eq!(replay.body, serde_json::to_vec(&request()).unwrap());
    for sent in [first, replay] {
        assert_eq!(
            sent.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(sent.headers.get("x-goog-user-project"), None);
    }
    assert_eq!(bearers_sent(&rig.vertex).await, ["t1", "t2"]);
}

#[tokio::test]
async fn a_same_bearer_source_replays_the_same_bearer_bounded_by_the_count() {
    let rig = Rig::start(answers(&[401]), bearers(&["same"])).await;
    let vertex = rig.client().with_unauthorized_refresh(true);

    assert!(is_status(&call(&vertex).await, 401));
    assert_eq!(rig.counts().await, (3, 3));
    assert_eq!(bearers_sent(&rig.vertex).await, ["same", "same", "same"]);
}

/// Only a completed 401 is replayed: never a 403, never a 5xx.
#[tokio::test]
async fn only_a_401_is_replayed() {
    for status in [403, 429, 500, 503] {
        let rig = Rig::start(answers(&[status, 200]), bearers(&BEARERS)).await;
        let vertex = rig.client().with_unauthorized_refresh(true);

        let result = call(&vertex).await;

        assert!(is_status(&result, status), "{status}: {result:?}");
        assert_eq!(rig.counts().await, (1, 1), "{status}");
    }
}

#[tokio::test]
async fn a_failed_refresh_is_an_auth_error_and_sends_no_replay() {
    let rig = Rig::start(
        answers(&[401, 200]),
        vec![token_body("t1", json!(3600)), ResponseTemplate::new(500)],
    )
    .await;
    let vertex = rig.client().with_unauthorized_refresh(true);

    assert!(matches!(
        call(&vertex).await,
        Err(VertexError::Auth(stridelabs_gcp::GcpAuthError::Status {
            status: 500,
            ..
        }))
    ));
    assert_eq!(rig.counts().await, (1, 2));
}

#[tokio::test]
async fn the_timeout_covers_the_replays() {
    let rig = Rig::start(
        vec![
            ResponseTemplate::new(401),
            ResponseTemplate::new(200)
                .set_body_json(json!({}))
                .set_delay(Duration::from_secs(10)),
        ],
        bearers(&BEARERS),
    )
    .await;
    let vertex = rig
        .client()
        .with_unauthorized_refresh(true)
        .with_timeout(Duration::from_millis(500));

    let started = Instant::now();
    let result = call(&vertex).await;

    assert!(matches!(result, Err(VertexError::Timeout(_))), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(
        rig.counts().await,
        (2, 2),
        "the replay was sent, inside the bound"
    );
}

/// One deadline for the whole call, never one per send: the 401 and the
/// replay's answer each take 2.5 s, 1.5 s inside the 4 s bound, but not
/// together (5 s). A deadline restarted for each send would let this
/// succeed. The first token is cached beforehand, so the only exchange in
/// the window is the replay's refresh, and the replay is still sent 1.5 s
/// before the deadline.
#[tokio::test]
async fn one_deadline_covers_the_first_send_and_the_replay_together() {
    let rig = Rig::start(
        vec![
            ResponseTemplate::new(401).set_delay(Duration::from_millis(2500)),
            ResponseTemplate::new(200)
                .set_body_json(json!({}))
                .set_delay(Duration::from_millis(2500)),
        ],
        bearers(&BEARERS),
    )
    .await;
    let vertex = rig
        .warm_client()
        .await
        .with_unauthorized_refresh(true)
        .with_timeout(Duration::from_secs(4));

    let started = Instant::now();
    let result = call(&vertex).await;
    let elapsed = started.elapsed();

    assert!(
        matches!(result, Err(VertexError::Timeout(timeout)) if timeout == Duration::from_secs(4)),
        "{result:?} after {elapsed:?}"
    );
    assert_eq!(
        rig.counts().await,
        (2, 2),
        "the replay was sent before the deadline"
    );
}

#[test]
fn a_client_debug_shows_the_refresh_toggle_and_count() {
    let tokens = stridelabs_gcp::TokenProvider::metadata_server(reqwest::Client::new(), &[]);
    let vertex =
        VertexClient::new(reqwest::Client::new(), tokens, "test-project", "global").unwrap();
    let rendered = format!("{vertex:?}");
    assert!(
        rendered.contains("unauthorized_refresh: false"),
        "{rendered}"
    );
    assert!(rendered.contains("max_refresh_attempts: 2"), "{rendered}");
    let rendered = format!(
        "{:?}",
        vertex
            .with_unauthorized_refresh(true)
            .with_max_refresh_attempts(0)
    );
    assert!(
        rendered.contains("unauthorized_refresh: true"),
        "{rendered}"
    );
    assert!(rendered.contains("max_refresh_attempts: 0"), "{rendered}");
}

/// The replay path logs the eviction, each replay and each refresh, and
/// none of it, nor the error, nor the client's `Debug`, carries a bearer.
#[tokio::test]
async fn the_replay_path_never_logs_a_bearer() {
    let capture = LogCapture::default();
    let _guard = capture.install();
    let canaries = ["CANARY-T1", "CANARY-T2", "CANARY-T3"];
    let rig = Rig::start(answers(&[401]), bearers(&canaries)).await;
    let vertex = rig.client().with_unauthorized_refresh(true);

    let error = call(&vertex).await.unwrap_err();

    assert_eq!(bearers_sent(&rig.vertex).await, canaries, "premise");
    let logs = capture.text();
    for expected in [
        "evicted a rejected GCP access token",
        "a request was answered 401; replaying it with a refreshed token",
        "generateContent",
        "refresh=2",
        "refreshed GCP access token",
    ] {
        assert!(logs.contains(expected), "{expected:?} not logged: {logs}");
    }
    let rendered = format!("{logs}\n{error} | {error:?} | {error:#?} | {vertex:?}");
    assert!(!rendered.contains("CANARY"), "a bearer leaked: {rendered}");
}
