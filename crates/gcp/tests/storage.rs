//! GCS request shapes against wiremock: the paths, the encoding, the auth
//! headers, each status the operations accept or refuse, the name rules, the
//! download cap, what an error may quote, and `upload_with`'s multipart
//! bodies, byte for byte.

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn header_of(request: &Request, name: &str) -> Option<String> {
    request
        .headers
        .get(name)
        .map(|value| value.to_str().unwrap().to_owned())
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
