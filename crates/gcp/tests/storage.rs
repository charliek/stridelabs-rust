//! GCS request shapes against wiremock: the paths, the encoding, the auth
//! headers, each status the operations accept or refuse, the name rules, the
//! download cap, what an error may quote, `upload_with`'s multipart bodies,
//! byte for byte, and the opt-in 401 refresh and replay, by exact request
//! counts.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use common::*;
use serde_json::json;
use stridelabs_gcp::storage::{
    public_url, GcsClient, StorageError, UploadOptions, DEFAULT_MAX_DOWNLOAD_BYTES,
};
use stridelabs_gcp::GcpAuthError;
use wiremock::matchers::{any, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const BUCKET: &str = "img-bucket";
/// A `/` and a space: both must be encoded, the slash as `%2F`.
const OBJECT: &str = "a/b c.png";
const ENCODED: &str = "a%2Fb%20c.png";

/// A client on `server` whose tokens come from the same server's metadata
/// endpoint, with a quota project so the header is visible.
async fn authorized_client(server: &MockServer) -> GcsClient {
    mount_metadata_token(server, "gcs-token").await;
    let tokens = metadata_provider(server, &[]).with_quota_project(Some("quota-project".into()));
    GcsClient::new(reqwest::Client::new(), tokens).with_base_url(&server.uri())
}

/// The one request that reached `route` (not the metadata token fetch).
async fn the_request(server: &MockServer, route_prefix: &str) -> Request {
    let mut requests: Vec<Request> = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.url.path().starts_with(route_prefix))
        .collect();
    assert_eq!(requests.len(), 1, "one request under {route_prefix}");
    requests.remove(0)
}

#[tokio::test]
async fn upload_is_a_media_post_with_the_name_encoded() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/upload/storage/v1/b/{BUCKET}/o")))
        .and(query_param("uploadType", "media"))
        .and(query_param("name", OBJECT))
        .and(header("content-type", "image/png"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": OBJECT})))
        .expect(1)
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;

    gcs.upload(
        BUCKET,
        OBJECT,
        Bytes::from_static(b"\x89PNG-bytes"),
        "image/png",
    )
    .await
    .expect("uploaded");

    let request = the_request(&server, "/upload/").await;
    assert_eq!(
        request.url.query(),
        Some(format!("uploadType=media&name={ENCODED}").as_str()),
        "the raw query, before any decoding"
    );
    assert_eq!(request.body, b"\x89PNG-bytes");
    assert_eq!(
        header_of(&request, "authorization").as_deref(),
        Some("Bearer gcs-token")
    );
    assert_eq!(
        header_of(&request, "x-goog-user-project").as_deref(),
        Some("quota-project")
    );
    server.verify().await;
}

#[tokio::test]
async fn download_reads_media_with_the_name_as_one_segment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/storage/v1/b/{BUCKET}/o/{ENCODED}")))
        .and(query_param("alt", "media"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(b"\x89PNG-bytes".to_vec(), "image/png"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;

    let (bytes, content_type) = gcs.download(BUCKET, OBJECT).await.unwrap().expect("found");

    assert_eq!(bytes, Bytes::from_static(b"\x89PNG-bytes"));
    assert_eq!(content_type.as_deref(), Some("image/png"));
    let request = the_request(&server, "/storage/").await;
    assert_eq!(
        header_of(&request, "authorization").as_deref(),
        Some("Bearer gcs-token")
    );
    server.verify().await;
}

#[tokio::test]
async fn download_of_a_missing_object_is_none_and_other_failures_are_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/storage/v1/b/{BUCKET}/o/missing")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/storage/v1/b/{BUCKET}/o/broken")))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": {"code": 500, "message": "Backend\nError"}
        })))
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;

    assert!(gcs.download(BUCKET, "missing").await.unwrap().is_none());
    let error = gcs.download(BUCKET, "broken").await.unwrap_err();
    assert!(matches!(
        error,
        StorageError::Status {
            status: 500,
            google_status: None,
            ..
        }
    ));
    assert_eq!(
        error.sensitive_message(),
        Some("Backend Error"),
        "flattened to one line"
    );
}

#[tokio::test]
async fn delete_reports_whether_there_was_an_object() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path(format!("/storage/v1/b/{BUCKET}/o/{ENCODED}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!("/storage/v1/b/{BUCKET}/o/gone")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!("/storage/v1/b/{BUCKET}/o/forbidden")))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;

    assert!(gcs.delete(BUCKET, OBJECT).await.unwrap(), "deleted");
    assert!(
        !gcs.delete(BUCKET, "gone").await.unwrap(),
        "nothing to delete"
    );
    assert!(matches!(
        gcs.delete(BUCKET, "forbidden").await,
        Err(StorageError::Status {
            operation: "delete",
            status: 403,
            ..
        })
    ));
    server.verify().await;
}

/// No operation sends anything — no token fetch, no request — for a name
/// that would become a different path once normalized.
#[tokio::test]
async fn invalid_names_are_refused_before_any_request() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;

    for object in ["u/../victim.png", "./a", "a//b", "/a", "a/", ""] {
        let refused = |result: Result<(), StorageError>| {
            assert!(
                matches!(result, Err(StorageError::InvalidObjectName { .. })),
                "{object:?}: {result:?}"
            )
        };
        refused(gcs.upload(BUCKET, object, Bytes::new(), "image/png").await);
        refused(gcs.download(BUCKET, object).await.map(drop));
        refused(gcs.delete(BUCKET, object).await.map(drop));
        refused(public_url(BUCKET, object).map(drop));
    }
    for bucket in ["..", "a/b", "UPPER", ""] {
        assert!(matches!(
            gcs.upload(bucket, "o", Bytes::new(), "image/png").await,
            Err(StorageError::InvalidBucketName { .. })
        ));
        assert!(matches!(
            public_url(bucket, "o"),
            Err(StorageError::InvalidBucketName { .. })
        ));
    }
    server.verify().await;
}

#[tokio::test]
async fn a_download_past_the_cap_is_too_large() {
    assert_eq!(DEFAULT_MAX_DOWNLOAD_BYTES, 32 * 1024 * 1024);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/storage/v1/b/{BUCKET}/o/big")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![7u8; 2048]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/storage/v1/b/{BUCKET}/o/exact")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![7u8; 1024]))
        .mount(&server)
        .await;
    let gcs = GcsClient::emulator(reqwest::Client::new(), &server.uri(), None)
        .with_max_download_bytes(1024);

    assert!(matches!(
        gcs.download(BUCKET, "big").await,
        Err(StorageError::TooLarge {
            operation: "download",
            limit: 1024
        })
    ));
    let (bytes, _) = gcs.download(BUCKET, "exact").await.unwrap().unwrap();
    assert_eq!(bytes.len(), 1024, "exactly the cap is fine");
}

/// `Display` and `Debug` say only the HTTP status and Google's
/// `error.status`. Google's `error.message` — which names the object, here a
/// `NAME-CANARY` — is kept, truncated, behind `sensitive_message()` only.
/// Everything else in the body never comes out at all.
#[tokio::test]
async fn an_error_logs_only_statuses_and_keeps_the_message_apart() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/upload/storage/v1/b/{BUCKET}/o")))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": format!("denied on a/NAME-CANARY.png {}", "m".repeat(5000)),
                "errors": [{"reason": "forbidden", "debugInfo": "CANARY-IN-ERRORS"}],
            },
            "echo": "CANARY-OUTSIDE",
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(502).set_body_string("<html>CANARY proxy page</html>"))
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;

    let error = gcs
        .upload(BUCKET, OBJECT, Bytes::new(), "image/png")
        .await
        .unwrap_err();
    let rendered = format!("{error} | {error:?} | {error:#?}");
    assert!(!rendered.contains("CANARY"), "{rendered}");
    assert!(
        !rendered.contains("denied"),
        "no message text at all: {rendered}"
    );
    assert_eq!(
        error.to_string(),
        "GCS upload answered HTTP 403 (PERMISSION_DENIED)"
    );
    let message = error
        .sensitive_message()
        .expect("kept for a deliberate reader");
    assert!(
        message.starts_with("denied on a/NAME-CANARY.png m"),
        "{message}"
    );
    assert!(
        message.chars().count() <= 201,
        "truncated: {}",
        message.len()
    );
    assert!(!message.contains("CANARY-IN-ERRORS") && !message.contains("CANARY-OUTSIDE"));

    let error = gcs.delete(BUCKET, OBJECT).await.unwrap_err();
    assert!(matches!(
        &error,
        StorageError::Status {
            status: 502,
            google_status: None,
            message: None,
            ..
        }
    ));
    assert_eq!(error.sensitive_message(), None);
    assert_eq!(error.to_string(), "GCS delete answered HTTP 502");
    assert!(!format!("{error:?}").contains("CANARY"));
}

#[tokio::test]
async fn an_emulator_without_tokens_sends_no_authorization() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    // `STORAGE_EMULATOR_HOST`'s bare `host:port` form.
    let host = server.uri().trim_start_matches("http://").to_owned();
    let gcs = GcsClient::emulator(reqwest::Client::new(), &host, None);
    assert_eq!(gcs.base_url(), server.uri());

    gcs.upload(BUCKET, OBJECT, Bytes::from_static(b"x"), "text/plain")
        .await
        .unwrap();

    let request = the_request(&server, "/upload/").await;
    assert_eq!(header_of(&request, "authorization"), None);
}

#[tokio::test]
async fn a_token_failure_is_an_auth_error_and_nothing_is_sent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(METADATA_TOKEN_PATH))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let gcs = GcsClient::new(reqwest::Client::new(), metadata_provider(&server, &[]))
        .with_base_url(&server.uri());

    assert!(matches!(
        gcs.upload(BUCKET, OBJECT, Bytes::new(), "image/png").await,
        Err(StorageError::Auth {
            operation: "upload",
            source: GcpAuthError::Status { status: 500, .. },
        })
    ));
    let requests = server.received_requests().await.unwrap();
    assert!(requests
        .iter()
        .all(|request| !request.url.path().starts_with("/upload/")));
}

#[tokio::test]
async fn an_operation_is_bounded_by_the_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/storage/v1/b/{BUCKET}/o/slow")))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
        .mount(&server)
        .await;
    let gcs = GcsClient::emulator(reqwest::Client::new(), &server.uri(), None)
        .with_timeout(Duration::from_millis(200));

    assert!(matches!(
        gcs.download(BUCKET, "slow").await,
        Err(StorageError::Timeout {
            operation: "download",
            ..
        })
    ));
}

#[test]
fn the_public_url_keeps_the_object_path() {
    assert_eq!(
        public_url(BUCKET, OBJECT).unwrap(),
        "https://storage.googleapis.com/img-bucket/a/b%20c.png"
    );
}

#[test]
fn a_client_debug_redacts_its_base_url() {
    let gcs = GcsClient::emulator(
        reqwest::Client::new(),
        "http://user:CANARY@localhost:4443/?key=CANARY",
        None,
    );
    let rendered = format!("{gcs:?}");
    assert!(!rendered.contains("CANARY"), "{rendered}");
    assert!(rendered.contains("localhost:4443"), "{rendered}");
}

// --- upload_with ----------------------------------------------------------------

/// Bytes that look like MIME framing (CRLFs, `--`, a NUL), which a multipart
/// body must carry unchanged.
const MEDIA: &[u8] = b"\x89PNG\r\n\x1a\n\0--not-a-boundary\r\n--\r\n";

/// 2025-10-09T08:53:20Z, and a nanosecond short of the next second.
fn custom_time() -> SystemTime {
    UNIX_EPOCH + Duration::new(1_760_000_000, 999_999_999)
}

/// The boundary a multipart upload declared, checked for its shape.
fn boundary_of(request: &Request) -> String {
    let content_type = header_of(request, "content-type").expect("a content type");
    let boundary = content_type
        .strip_prefix("multipart/related; boundary=")
        .unwrap_or_else(|| panic!("not multipart/related: {content_type}"));
    let random = boundary
        .strip_prefix("stridelabs-gcp-")
        .unwrap_or_else(|| panic!("the crate's prefix: {boundary}"));
    assert!(
        random.len() == 32 && random.bytes().all(|b| b.is_ascii_hexdigit()),
        "128 random bits in hex: {boundary}"
    );
    boundary.to_owned()
}

/// The exact body of a multipart upload of `media` with `metadata`.
fn multipart(boundary: &str, metadata: &str, content_type: &str, media: &[u8]) -> Vec<u8> {
    let mut body = format!(
        "--{boundary}\r\n\
         Content-Type: application/json; charset=UTF-8\r\n\
         \r\n\
         {metadata}\r\n\
         --{boundary}\r\n\
         Content-Type: {content_type}\r\n\
         \r\n"
    )
    .into_bytes();
    body.extend_from_slice(media);
    body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
    body
}

/// A server answering multipart uploads to [`BUCKET`] with 200.
async fn multipart_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/upload/storage/v1/b/{BUCKET}/o")))
        .and(query_param("uploadType", "multipart"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": OBJECT})))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn upload_with_default_options_is_the_media_upload_unchanged() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/upload/storage/v1/b/{BUCKET}/o")))
        .and(query_param("uploadType", "media"))
        .and(header("content-type", "image/png"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": OBJECT})))
        .expect(1)
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;

    gcs.upload_with(
        BUCKET,
        OBJECT,
        Bytes::from_static(MEDIA),
        "image/png",
        &UploadOptions::default(),
    )
    .await
    .expect("uploaded");

    let request = the_request(&server, "/upload/").await;
    assert_eq!(
        request.url.query(),
        Some(format!("uploadType=media&name={ENCODED}").as_str())
    );
    assert_eq!(
        request.body, MEDIA,
        "the bytes as the body, nothing around them"
    );
    assert_eq!(
        header_of(&request, "authorization").as_deref(),
        Some("Bearer gcs-token")
    );
    assert_eq!(
        header_of(&request, "x-goog-user-project").as_deref(),
        Some("quota-project")
    );
    server.verify().await;
}

/// With no options, `upload_with` accepts and refuses exactly what `upload`
/// does — content types reqwest takes that the multipart path would not
/// (surrounding spaces) included, and a CR/LF one refused by both without a
/// request.
#[tokio::test]
async fn upload_with_default_options_takes_and_refuses_what_upload_does() {
    for content_type in [
        "image/png",
        "image/png ",
        " image/png",
        "image/png\r\nX-Injected: CANARY",
    ] {
        let mut outcomes = Vec::new();
        for via_upload_with in [false, true] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(format!("/upload/storage/v1/b/{BUCKET}/o")))
                .and(query_param("uploadType", "media"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": OBJECT})))
                .mount(&server)
                .await;
            let gcs = authorized_client(&server).await;
            let bytes = Bytes::from_static(MEDIA);
            let result = if via_upload_with {
                gcs.upload_with(
                    BUCKET,
                    OBJECT,
                    bytes,
                    content_type,
                    &UploadOptions::default(),
                )
                .await
            } else {
                gcs.upload(BUCKET, OBJECT, bytes, content_type).await
            };
            let sent = server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|request| request.url.path().starts_with("/upload/"))
                .count();
            outcomes.push((result.is_ok(), sent));
        }
        assert_eq!(
            outcomes[0], outcomes[1],
            "upload vs upload_with(default) for {content_type:?}: (ok, uploads sent)"
        );
    }
}

#[tokio::test]
async fn each_option_alone_and_together_is_one_exact_multipart_upload() {
    let name = r#""name":"a/b c.png","contentType":"image/png""#;
    let cases = [
        (
            "custom time",
            UploadOptions::default().with_custom_time(custom_time()),
            "uploadType=multipart".to_owned(),
            format!(r#"{{{name},"customTime":"2025-10-09T08:53:20Z"}}"#),
        ),
        (
            "create only",
            UploadOptions::default().with_if_generation_match(0),
            "uploadType=multipart&ifGenerationMatch=0".to_owned(),
            format!("{{{name}}}"),
        ),
        (
            "a generation",
            UploadOptions::default().with_if_generation_match(1_760_000_000_123_456),
            "uploadType=multipart&ifGenerationMatch=1760000000123456".to_owned(),
            format!("{{{name}}}"),
        ),
        (
            "cache control",
            UploadOptions::default().with_cache_control("private, max-age=86400"),
            "uploadType=multipart".to_owned(),
            format!(r#"{{{name},"cacheControl":"private, max-age=86400"}}"#),
        ),
        (
            "all three",
            UploadOptions::default()
                .with_cache_control("private, max-age=86400")
                .with_if_generation_match(0)
                .with_custom_time(custom_time()),
            "uploadType=multipart&ifGenerationMatch=0".to_owned(),
            format!(
                r#"{{{name},"customTime":"2025-10-09T08:53:20Z","cacheControl":"private, max-age=86400"}}"#
            ),
        ),
    ];
    for (case, options, query, metadata) in cases {
        let server = multipart_server().await;
        let gcs = authorized_client(&server).await;

        gcs.upload_with(
            BUCKET,
            OBJECT,
            Bytes::from_static(MEDIA),
            "image/png",
            &options,
        )
        .await
        .unwrap_or_else(|error| panic!("{case}: {error}"));

        let request = the_request(&server, "/upload/").await;
        assert_eq!(request.method.as_str(), "POST", "{case}");
        assert_eq!(
            request.url.path(),
            format!("/upload/storage/v1/b/{BUCKET}/o"),
            "{case}"
        );
        assert_eq!(
            request.url.query(),
            Some(query.as_str()),
            "{case}: no name= either"
        );
        let boundary = boundary_of(&request);
        assert_eq!(
            request.body,
            multipart(&boundary, &metadata, "image/png", MEDIA),
            "{case}: {}",
            String::from_utf8_lossy(&request.body)
        );
        assert_eq!(
            header_of(&request, "authorization").as_deref(),
            Some("Bearer gcs-token"),
            "{case}"
        );
        assert_eq!(
            header_of(&request, "x-goog-user-project").as_deref(),
            Some("quota-project"),
            "{case}"
        );
    }
}

/// The name is a JSON string in the metadata part, escaped by serde_json:
/// quotes and backslashes escaped, `/` and Unicode as they are. Not a query
/// value, not a path.
#[tokio::test]
async fn awkward_names_go_in_the_json_and_nowhere_in_the_url() {
    let object = "dir/sub \"quoted\" back\\slash/日本 é.png";
    let server = multipart_server().await;
    let gcs = authorized_client(&server).await;

    gcs.upload_with(
        BUCKET,
        object,
        Bytes::from_static(MEDIA),
        "image/png",
        &UploadOptions::default().with_if_generation_match(0),
    )
    .await
    .expect("uploaded");

    let request = the_request(&server, "/upload/").await;
    assert_eq!(
        request.url.path(),
        format!("/upload/storage/v1/b/{BUCKET}/o")
    );
    assert_eq!(
        request.url.query(),
        Some("uploadType=multipart&ifGenerationMatch=0")
    );
    let metadata =
        r#"{"name":"dir/sub \"quoted\" back\\slash/日本 é.png","contentType":"image/png"}"#;
    assert_eq!(
        request.body,
        multipart(&boundary_of(&request), metadata, "image/png", MEDIA)
    );
    let parsed: serde_json::Value = serde_json::from_str(metadata).unwrap();
    assert_eq!(parsed["name"], object, "the JSON decodes to the name");
}

/// `ifGenerationMatch=0` on an existing object: GCS's 412 is a plain status
/// error. One request, no retry, and no fallback upload that would
/// overwrite.
#[tokio::test]
async fn a_failed_precondition_is_a_412_with_no_retry_and_no_fallback() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/upload/storage/v1/b/{BUCKET}/o")))
        .respond_with(ResponseTemplate::new(412).set_body_json(json!({
            "error": {
                "code": 412,
                "message": "At least one of the pre-conditions you specified did not hold: NAME-CANARY",
                "errors": [{"reason": "conditionNotMet", "location": "If-Match"}],
            }
        })))
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;

    let error = gcs
        .upload_with(
            BUCKET,
            "NAME-CANARY.png",
            Bytes::from_static(MEDIA),
            "image/png",
            &UploadOptions::default().with_if_generation_match(0),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        StorageError::Status {
            operation: "upload",
            status: 412,
            google_status: None,
            ..
        }
    ));
    assert_eq!(error.to_string(), "GCS upload answered HTTP 412");
    assert!(!format!("{error:?}").contains("CANARY"));
    assert!(error
        .sensitive_message()
        .unwrap()
        .contains("pre-conditions"));
    let request = the_request(&server, "/upload/").await;
    assert_eq!(
        request.url.query(),
        Some("uploadType=multipart&ifGenerationMatch=0"),
        "the one request was the conditional one"
    );
}

/// Every value `upload_with` interpolates is checked before a token is
/// fetched or a request sent, and the refusal quotes neither the value nor
/// the object name.
#[tokio::test]
async fn unsendable_arguments_are_refused_before_anything_is_sent() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;
    let object = "NAME-CANARY.png";
    let defaults = UploadOptions::default;

    let cases = [
        // The content type of a multipart upload (with no options it is
        // `upload`'s, tested below).
        (
            "image/png\r\nX-Injected: CANARY",
            defaults().with_if_generation_match(0),
        ),
        ("", defaults().with_if_generation_match(0)),
        (" image/png", defaults().with_if_generation_match(0)),
        ("image/CANARY-é", defaults().with_if_generation_match(0)),
        // The cache control.
        (
            "image/png",
            defaults().with_cache_control("private\r\nX-Injected: CANARY"),
        ),
        (
            "image/png",
            defaults().with_cache_control("private\nCANARY"),
        ),
        ("image/png", defaults().with_cache_control("")),
        ("image/png", defaults().with_cache_control("private ")),
        // A custom time RFC 3339 cannot write.
        (
            "image/png",
            defaults().with_custom_time(UNIX_EPOCH - Duration::from_secs(1)),
        ),
        (
            "image/png",
            defaults().with_custom_time(UNIX_EPOCH + Duration::from_secs(253_402_300_800)),
        ),
        // A negative generation.
        ("image/png", defaults().with_if_generation_match(-1)),
        ("image/png", defaults().with_if_generation_match(i64::MIN)),
    ];
    for (content_type, options) in cases {
        let error = gcs
            .upload_with(
                BUCKET,
                object,
                Bytes::from_static(MEDIA),
                content_type,
                &options,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, StorageError::InvalidArgument { .. }),
            "{content_type:?} {options:?}: {error:?}"
        );
        let rendered = format!("{error} | {error:?}");
        for secret in ["CANARY", "Injected", "\r", "\n"] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
    }
    // Names are checked first, as by every operation.
    assert!(matches!(
        gcs.upload_with(
            BUCKET,
            "a//b",
            Bytes::new(),
            "",
            &defaults().with_if_generation_match(-1)
        )
        .await,
        Err(StorageError::InvalidObjectName { .. })
    ));
    server.verify().await;
}

#[tokio::test]
async fn a_multipart_upload_to_an_emulator_without_tokens_sends_no_authorization() {
    let server = multipart_server().await;
    let host = server.uri().trim_start_matches("http://").to_owned();
    let gcs = GcsClient::emulator(reqwest::Client::new(), &host, None);

    gcs.upload_with(
        BUCKET,
        OBJECT,
        Bytes::from_static(b"x"),
        "text/plain",
        &UploadOptions::default().with_cache_control("no-store"),
    )
    .await
    .unwrap();

    let request = the_request(&server, "/upload/").await;
    assert_eq!(header_of(&request, "authorization"), None);
    assert_eq!(request.url.query(), Some("uploadType=multipart"));
}

#[tokio::test]
async fn a_multipart_upload_fails_like_upload_auth_timeout_and_status() {
    let options = UploadOptions::default().with_if_generation_match(0);

    // No token: an auth error, and no upload request.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(METADATA_TOKEN_PATH))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let gcs = GcsClient::new(reqwest::Client::new(), metadata_provider(&server, &[]))
        .with_base_url(&server.uri());
    assert!(matches!(
        gcs.upload_with(BUCKET, OBJECT, Bytes::new(), "image/png", &options)
            .await,
        Err(StorageError::Auth {
            operation: "upload",
            source: GcpAuthError::Status { status: 500, .. },
        })
    ));
    assert!(server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|request| !request.url.path().starts_with("/upload/")));

    // Too slow: the client's timeout.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
        .mount(&server)
        .await;
    let gcs = GcsClient::emulator(reqwest::Client::new(), &server.uri(), None)
        .with_timeout(Duration::from_millis(200));
    assert!(matches!(
        gcs.upload_with(BUCKET, OBJECT, Bytes::new(), "image/png", &options)
            .await,
        Err(StorageError::Timeout {
            operation: "upload",
            ..
        })
    ));

    // Refused: statuses only, the message kept apart.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "denied on NAME-CANARY.png",
            },
            "echo": "CANARY-OUTSIDE",
        })))
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;
    let error = gcs
        .upload_with(
            BUCKET,
            "NAME-CANARY.png",
            Bytes::new(),
            "image/png",
            &options,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "GCS upload answered HTTP 403 (PERMISSION_DENIED)"
    );
    let rendered = format!("{error} | {error:?} | {error:#?}");
    assert!(!rendered.contains("CANARY"), "{rendered}");
    assert!(!rendered.contains(&server.uri()), "no URL: {rendered}");
    assert_eq!(error.sensitive_message(), Some("denied on NAME-CANARY.png"));
}

// --- the 401 refresh and replay ---------------------------------------------------
//
// Every client here is built on `never_retrying()`, so each request counted
// is one the client sent, and every rig gives the tokens a server of their
// own, so its request count is the number of tokens minted.

/// Each operation, run once.
#[derive(Clone, Copy, Debug)]
enum Op {
    Upload,
    CreateOnly,
    Download,
    Delete,
}

const OPS: [Op; 4] = [Op::Upload, Op::CreateOnly, Op::Download, Op::Delete];

impl Op {
    async fn run(self, gcs: &GcsClient) -> Result<(), StorageError> {
        let media = || Bytes::from_static(MEDIA);
        match self {
            Op::Upload => gcs.upload(BUCKET, OBJECT, media(), "image/png").await,
            Op::CreateOnly => {
                gcs.upload_with(
                    BUCKET,
                    OBJECT,
                    media(),
                    "image/png",
                    &UploadOptions::default().with_if_generation_match(0),
                )
                .await
            }
            Op::Download => gcs.download(BUCKET, OBJECT).await.map(drop),
            Op::Delete => gcs.delete(BUCKET, OBJECT).await.map(drop),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Op::Upload | Op::CreateOnly => "upload",
            Op::Download => "download",
            Op::Delete => "delete",
        }
    }
}

/// A GCS stand-in answering `answers` in order (the last repeated), and a
/// metadata server minting `tokens` in order.
struct Rig {
    gcs: MockServer,
    tokens: MockServer,
}

impl Rig {
    async fn start(answers: Vec<ResponseTemplate>, tokens: Vec<ResponseTemplate>) -> Rig {
        let gcs = MockServer::start().await;
        Mock::given(any())
            .respond_with(Sequence::new(answers))
            .mount(&gcs)
            .await;
        Rig {
            gcs,
            tokens: token_server(tokens).await,
        }
    }

    fn client(&self) -> GcsClient {
        GcsClient::new(never_retrying(), exact_provider(&self.tokens))
            .with_base_url(&self.gcs.uri())
    }

    /// [`Rig::client`] with its first token already cached, so no token
    /// exchange runs before the first send of a window a test measures.
    async fn warm_client(&self) -> GcsClient {
        let tokens = exact_provider(&self.tokens);
        tokens.token().await.unwrap();
        GcsClient::new(never_retrying(), tokens).with_base_url(&self.gcs.uri())
    }

    /// (GCS requests, tokens minted)
    async fn counts(&self) -> (usize, usize) {
        (
            request_count(&self.gcs).await,
            request_count(&self.tokens).await,
        )
    }
}

fn is_status(result: &Result<(), StorageError>, op: Op, expected: u16) -> bool {
    matches!(result, Err(StorageError::Status { operation, status, .. })
        if *operation == op.name() && *status == expected)
}

/// v0.8.0's behaviour, pinned: without the opt-in a 401 is one request and
/// `Status { 401 }`, and no second token is asked for. A count set alone
/// does not turn it on.
#[tokio::test]
async fn by_default_a_401_is_one_request_and_no_refresh() {
    for op in OPS {
        for gcs in [
            |rig: &Rig| rig.client(),
            |rig: &Rig| rig.client().with_max_refresh_attempts(5),
        ] {
            let rig = Rig::start(statuses(&[401, 200]), bearers(&BEARERS)).await;
            let gcs = gcs(&rig);
            assert!(!gcs.unauthorized_refresh());

            let result = op.run(&gcs).await;

            assert!(is_status(&result, op, 401), "{op:?}: {result:?}");
            assert_eq!(rig.counts().await, (1, 1), "{op:?}: (requests, tokens)");
        }
    }
}

/// N refresh-and-replay cycles per call, N = 0, 1, 2, on every operation: a
/// persistent 401 costs N + 1 requests and N refreshes, 401 then 200 within
/// the budget succeeds, and each replay carries the bearer just refreshed.
#[tokio::test]
async fn the_count_bounds_the_replays_on_every_operation() {
    for op in OPS {
        for (n, answers, failure, sent) in REFRESH_CASES {
            let case = format!("{op:?}, N = {n}, answers {answers:?}");
            let rig = Rig::start(statuses(answers), bearers(&BEARERS)).await;
            let gcs = rig
                .client()
                .with_unauthorized_refresh(true)
                .with_max_refresh_attempts(n);

            let result = op.run(&gcs).await;

            match failure {
                None => assert!(result.is_ok(), "{case}: {result:?}"),
                Some(status) => assert!(is_status(&result, op, status), "{case}: {result:?}"),
            }
            assert_eq!(
                rig.counts().await,
                (sent, sent),
                "{case}: (requests, tokens): the first token and one refresh per replay"
            );
            assert_eq!(
                bearers_sent(&rig.gcs).await,
                BEARERS[..sent],
                "{case}: each replay carries the refreshed bearer"
            );
        }
    }
}

/// The opt-in alone is google-auth's two refreshes, and the API's shape is
/// pinned.
#[tokio::test]
async fn the_default_count_is_two() {
    let _: fn(GcsClient, bool) -> GcsClient = GcsClient::with_unauthorized_refresh;
    let _: fn(GcsClient, u32) -> GcsClient = GcsClient::with_max_refresh_attempts;
    let _: fn(&GcsClient) -> bool = GcsClient::unauthorized_refresh;
    let _: fn(&GcsClient) -> u32 = GcsClient::max_refresh_attempts;

    let rig = Rig::start(statuses(&[401]), bearers(&BEARERS)).await;
    let gcs = rig.client();
    assert_eq!(
        (gcs.unauthorized_refresh(), gcs.max_refresh_attempts()),
        (false, 2)
    );
    let gcs = gcs.with_unauthorized_refresh(true);
    assert_eq!(
        (gcs.unauthorized_refresh(), gcs.max_refresh_attempts()),
        (true, 2)
    );

    let result = Op::Download.run(&gcs).await;

    assert!(is_status(&result, Op::Download, 401), "{result:?}");
    assert_eq!(rig.counts().await, (3, 3), "3 requests, 2 refreshes");
}

/// The metadata server re-serves one bearer: every refresh returns it, so
/// every replay carries it, and the count still bounds them.
#[tokio::test]
async fn a_same_bearer_source_replays_the_same_bearer_bounded_by_the_count() {
    let rig = Rig::start(statuses(&[401]), bearers(&["same"])).await;
    let gcs = rig.client().with_unauthorized_refresh(true);

    let result = Op::Delete.run(&gcs).await;

    assert!(is_status(&result, Op::Delete, 401), "{result:?}");
    assert_eq!(rig.counts().await, (3, 3));
    assert_eq!(bearers_sent(&rig.gcs).await, ["same", "same", "same"]);
}

/// A replay is the same request: a create-only multipart upload goes out
/// again with the same `ifGenerationMatch=0`, the same boundary and the same
/// body bytes, and a media upload with the same query and bytes. Only the
/// bearer changes.
#[tokio::test]
async fn a_replayed_upload_is_the_same_request_byte_for_byte() {
    for op in [Op::CreateOnly, Op::Upload] {
        let rig = Rig::start(statuses(&[401, 200]), bearers(&BEARERS)).await;
        let gcs = rig.client().with_unauthorized_refresh(true);

        op.run(&gcs).await.unwrap();

        let requests = rig.gcs.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2, "{op:?}");
        let (first, replay) = (&requests[0], &requests[1]);
        assert_eq!(first.method, replay.method, "{op:?}");
        assert_eq!(first.url, replay.url, "{op:?}: path and query");
        assert_eq!(
            header_of(first, "content-type"),
            header_of(replay, "content-type"),
            "{op:?}: the boundary too"
        );
        assert_eq!(first.body, replay.body, "{op:?}");
        assert_eq!(
            header_of(replay, "x-goog-user-project"),
            header_of(first, "x-goog-user-project")
        );
        assert_eq!(bearers_sent(&rig.gcs).await, ["t1", "t2"], "{op:?}");
        match op {
            Op::CreateOnly => {
                assert_eq!(
                    first.url.query(),
                    Some("uploadType=multipart&ifGenerationMatch=0")
                );
                assert_eq!(
                    replay.body,
                    multipart(
                        &boundary_of(replay),
                        r#"{"name":"a/b c.png","contentType":"image/png"}"#,
                        "image/png",
                        MEDIA
                    )
                );
            }
            _ => {
                assert_eq!(
                    first.url.query(),
                    Some(format!("uploadType=media&name={ENCODED}").as_str())
                );
                assert_eq!(replay.body, MEDIA);
            }
        }
    }
}

/// Only a completed 401 is replayed: never a 403, never a 5xx, never a
/// transport failure, whose outcome for a write is unknown.
#[tokio::test]
async fn only_a_401_is_replayed() {
    for status in [403, 500, 503] {
        let rig = Rig::start(statuses(&[status, 200]), bearers(&BEARERS)).await;
        let gcs = rig.client().with_unauthorized_refresh(true);

        let result = Op::CreateOnly.run(&gcs).await;

        assert!(
            is_status(&result, Op::CreateOnly, status),
            "{status}: {result:?}"
        );
        assert_eq!(rig.counts().await, (1, 1), "{status}: (requests, tokens)");
    }

    let tokens = token_server(bearers(&BEARERS)).await;
    let gcs = GcsClient::new(never_retrying(), exact_provider(&tokens))
        .with_base_url("http://127.0.0.1:1")
        .with_unauthorized_refresh(true);
    assert!(matches!(
        gcs.delete(BUCKET, OBJECT).await,
        Err(StorageError::Request {
            operation: "delete",
            ..
        })
    ));
    assert_eq!(
        request_count(&tokens).await,
        1,
        "no refresh after a transport failure"
    );
}

/// A 401 whose body never finishes is dropped after 2 s, its connection
/// with it, and the replay goes out on a fresh connection and succeeds. The
/// operation's own 20 s bound is never reached. The window is 2 s to 4.9 s:
/// a 5 s body bound fails it, and a starved machine has almost 3 s on top
/// of the 2 s for the refresh and two local requests (the first token is
/// cached before the clock starts).
#[tokio::test]
async fn a_slow_401_body_is_dropped_after_two_seconds_and_the_replay_proceeds() {
    let raw = RawServer::start(|n, _| {
        if n == 0 {
            RawReply::Stall(
                b"HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: 1000\r\n\r\n{\"error\":"
                    .to_vec(),
            )
        } else {
            RawReply::Full(
                b"HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncontent-length: 4\r\n\r\nPNG!".to_vec(),
            )
        }
    })
    .await;
    let tokens_server = token_server(bearers(&BEARERS)).await;
    let tokens = exact_provider(&tokens_server);
    tokens.token().await.unwrap(); // t1 cached: no exchange inside the window
    let gcs = GcsClient::new(never_retrying(), tokens)
        .with_base_url(&raw.base_url)
        .with_timeout(Duration::from_secs(20))
        .with_unauthorized_refresh(true);

    let started = Instant::now();
    let (bytes, _) = gcs.download(BUCKET, OBJECT).await.unwrap().expect("found");
    let elapsed = started.elapsed();

    assert_eq!(bytes, Bytes::from_static(b"PNG!"));
    assert!(elapsed >= Duration::from_secs(2), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(4900), "{elapsed:?}");
    let requests = raw.requests();
    assert_eq!(requests.len(), 2);
    assert!(String::from_utf8_lossy(&requests[0]).contains("authorization: Bearer t1\r\n"));
    assert!(String::from_utf8_lossy(&requests[1]).contains("authorization: Bearer t2\r\n"));
    assert_eq!(raw.accepted(), 2, "the replay had to open a new connection");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !raw.stalled_connection_closed() {
        assert!(
            Instant::now() < deadline,
            "the stalled connection was never closed"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Eight operations in flight on one provider, each answered 401 on t1:
/// one of them evicts t1, one refresh mints t2, and all eight replay with it.
/// Two tokens minted in all. On worker threads, for the races.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_operations_rejected_on_one_bearer_share_one_refresh() {
    eight_rejected_on_one_bearer().await;
}

/// The same eight on one thread, where the capture sees every log line:
/// exactly one eviction among them.
#[tokio::test]
async fn concurrent_operations_rejected_on_one_bearer_make_one_eviction() {
    let capture = LogCapture::default();
    let _guard = capture.install();

    eight_rejected_on_one_bearer().await;

    let logs = capture.text();
    assert_eq!(
        logs.matches("evicted a rejected GCP access token").count(),
        1,
        "{logs}"
    );
    assert_eq!(
        logs.matches("replaying it with a refreshed token").count(),
        8,
        "{logs}"
    );
}

async fn eight_rejected_on_one_bearer() {
    // No 401 goes out until all eight t1 requests are in (a barrier, not a
    // delay), so no operation can refresh before the last one has sent t1,
    // however the runtime schedules them.
    let all_sent = Arc::new(tokio::sync::Barrier::new(8));
    let server = RawServer::start(move |_, request| {
        if contains(request, b"authorization: Bearer t1\r\n") {
            RawReply::AfterBarrier(
                Arc::clone(&all_sent),
                b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n".to_vec(),
            )
        } else {
            RawReply::Full(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec())
        }
    })
    .await;
    let tokens_server = token_server(bearers(&BEARERS)).await;
    let tokens = exact_provider(&tokens_server);
    assert_eq!(tokens.token().await.unwrap().token, "t1", "cached up front");
    let gcs = GcsClient::new(never_retrying(), tokens)
        .with_base_url(&server.base_url)
        .with_timeout(Duration::from_secs(60))
        .with_unauthorized_refresh(true);

    let mut operations = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let gcs = gcs.clone();
        operations.spawn(async move { gcs.download(BUCKET, OBJECT).await });
    }
    while let Some(result) = operations.join_next().await {
        let (bytes, _) = result.unwrap().unwrap().expect("found");
        assert_eq!(bytes, Bytes::from_static(b"ok"));
    }

    assert_eq!(
        request_count(&tokens_server).await,
        2,
        "t1, then one refresh"
    );
    let sent = server.requests();
    let with = |bearer: &str| {
        let header = format!("authorization: Bearer {bearer}\r\n");
        sent.iter()
            .filter(|request| contains(request, header.as_bytes()))
            .count()
    };
    assert_eq!((with("t1"), with("t2"), sent.len()), (8, 8, 16));
}

#[tokio::test]
async fn a_failed_refresh_is_an_auth_error_and_sends_no_replay() {
    let rig = Rig::start(
        statuses(&[401, 200]),
        vec![token_body("t1", json!(3600)), ResponseTemplate::new(500)],
    )
    .await;
    let gcs = rig.client().with_unauthorized_refresh(true);

    assert!(matches!(
        Op::Download.run(&gcs).await,
        Err(StorageError::Auth {
            operation: "download",
            source: GcpAuthError::Status { status: 500, .. },
        })
    ));
    assert_eq!(rig.counts().await, (1, 2));
}

/// The replays run inside the operation's bound: a replay that hangs is the
/// client's `Timeout`, not a wait without end.
#[tokio::test]
async fn the_timeout_covers_the_replays() {
    let rig = Rig::start(
        vec![
            ResponseTemplate::new(401),
            ResponseTemplate::new(200).set_delay(Duration::from_secs(10)),
        ],
        bearers(&BEARERS),
    )
    .await;
    let gcs = rig
        .client()
        .with_unauthorized_refresh(true)
        .with_timeout(Duration::from_millis(500));

    let started = Instant::now();
    let result = Op::Upload.run(&gcs).await;

    assert!(
        matches!(
            result,
            Err(StorageError::Timeout {
                operation: "upload",
                ..
            })
        ),
        "{result:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(
        rig.counts().await,
        (2, 2),
        "the replay was sent, inside the bound"
    );
}

/// One deadline for the whole operation, never one per send: the 401 and
/// the replay's answer each take 2.5 s, 1.5 s inside the 4 s bound, but not
/// together (5 s). A deadline restarted for each send would let this
/// succeed. The first token is cached beforehand, so the only exchange in
/// the window is the replay's refresh, and the replay is still sent 1.5 s
/// before the deadline.
#[tokio::test]
async fn one_deadline_covers_the_first_send_and_the_replay_together() {
    let rig = Rig::start(
        vec![
            ResponseTemplate::new(401).set_delay(Duration::from_millis(2500)),
            ResponseTemplate::new(200).set_delay(Duration::from_millis(2500)),
        ],
        bearers(&BEARERS),
    )
    .await;
    let gcs = rig
        .warm_client()
        .await
        .with_unauthorized_refresh(true)
        .with_timeout(Duration::from_secs(4));

    let started = Instant::now();
    let result = Op::Download.run(&gcs).await;
    let elapsed = started.elapsed();

    assert!(
        matches!(
            result,
            Err(StorageError::Timeout {
                operation: "download",
                ..
            })
        ),
        "{result:?} after {elapsed:?}"
    );
    assert_eq!(
        rig.counts().await,
        (2, 2),
        "the replay was sent before the deadline"
    );
}

#[tokio::test]
async fn an_emulator_without_tokens_never_replays() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(Sequence::new(statuses(&[401, 200])))
        .mount(&server)
        .await;
    let gcs =
        GcsClient::emulator(never_retrying(), &server.uri(), None).with_unauthorized_refresh(true);

    let result = Op::Download.run(&gcs).await;

    assert!(is_status(&result, Op::Download, 401), "{result:?}");
    assert_eq!(
        bearers_sent(&server).await,
        ["-"],
        "one request, no authorization"
    );
}

/// The budget is per call: each operation starts with its own N, whatever
/// the one before it used.
#[tokio::test]
async fn each_operation_has_a_refresh_budget_of_its_own() {
    let rig = Rig::start(statuses(&[401]), bearers(&BEARERS)).await;
    let gcs = rig
        .client()
        .with_unauthorized_refresh(true)
        .with_max_refresh_attempts(1);

    for (call, requests) in [(1, 2), (2, 4)] {
        let result = Op::Download.run(&gcs).await;
        assert!(
            is_status(&result, Op::Download, 401),
            "call {call}: {result:?}"
        );
        assert_eq!(request_count(&rig.gcs).await, requests, "call {call}");
    }
    // t1, refreshed to t2 (the first call's last 401 leaves t2 cached), then
    // the second call's one refresh, to t3.
    assert_eq!(bearers_sent(&rig.gcs).await, ["t1", "t2", "t2", "t3"]);
    assert_eq!(request_count(&rig.tokens).await, 3);
}

#[test]
fn a_client_debug_shows_the_refresh_toggle_and_count() {
    let gcs = GcsClient::emulator(reqwest::Client::new(), "localhost:4443", None)
        .with_unauthorized_refresh(true)
        .with_max_refresh_attempts(3);
    let rendered = format!("{gcs:?}");
    assert!(
        rendered.contains("unauthorized_refresh: true"),
        "{rendered}"
    );
    assert!(rendered.contains("max_refresh_attempts: 3"), "{rendered}");
    let rendered = format!(
        "{:?}",
        GcsClient::emulator(reqwest::Client::new(), "localhost:4443", None)
    );
    assert!(
        rendered.contains("unauthorized_refresh: false"),
        "{rendered}"
    );
    assert!(rendered.contains("max_refresh_attempts: 2"), "{rendered}");
}

/// Everything the replay path logs — the eviction, each replay, each
/// refresh — and every error and `Debug` it produces, is free of the
/// bearers. A current-thread runtime, so the refresh tasks log on this
/// thread, into this test's capture.
#[tokio::test]
async fn the_replay_path_never_logs_a_bearer() {
    let capture = LogCapture::default();
    let _guard = capture.install();
    let canaries = ["CANARY-T1", "CANARY-T2", "CANARY-T3"];
    let rig = Rig::start(statuses(&[401]), bearers(&canaries)).await;
    let gcs = rig.client().with_unauthorized_refresh(true);

    let error = gcs.download(BUCKET, OBJECT).await.unwrap_err();

    assert_eq!(
        bearers_sent(&rig.gcs).await,
        canaries,
        "premise: all three were sent"
    );
    let logs = capture.text();
    for expected in [
        "evicted a rejected GCP access token",
        "a request was answered 401; replaying it with a refreshed token",
        "refresh=2",
        "refreshed GCP access token",
    ] {
        assert!(logs.contains(expected), "{expected:?} not logged: {logs}");
    }
    let rendered = format!("{logs}\n{error} | {error:?} | {error:#?} | {gcs:?} | {gcs:#?}");
    assert!(!rendered.contains("CANARY"), "a bearer leaked: {rendered}");
}
