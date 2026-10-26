//! GCS request shapes against wiremock: the paths, the encoding, the auth
//! headers, each status the operations accept or refuse, the name rules, the
//! download cap, what an error may quote, `upload_with`'s multipart bodies,
//! byte for byte, the object-name policies, and the opt-in retry, by exact
//! request counts.

mod common;

use std::fmt::Write as _;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use common::*;
use serde_json::json;
use stridelabs_gcp::auth::{TokenOptions, TokenProvider};
use stridelabs_gcp::storage::{
    public_url, public_url_with, validate_bucket_name, GcsClient, ObjectNamePolicy, RetryPolicy,
    StorageError, UploadOptions, DEFAULT_MAX_DOWNLOAD_BYTES,
};
use stridelabs_gcp::GcpAuthError;
use wiremock::matchers::{any, header, method, path, path_regex, query_param};
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

/// `exists` is one metadata `GET` for the object's name alone: `true` on a
/// 200 whatever its body, with the object path encoded as one segment, the
/// bearer attached and `fields=name` the only query.
#[tokio::test]
async fn exists_is_true_on_a_2xx_and_asks_for_the_name_only() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/storage/v1/b/{BUCKET}/o/{ENCODED}")))
        .and(query_param("fields", "name"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": OBJECT})))
        .expect(1)
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;

    assert!(gcs.exists(BUCKET, OBJECT).await.unwrap());

    let request = the_request(&server, "/storage/").await;
    assert_eq!(request.url.query(), Some("fields=name"));
    assert_eq!(
        request.url.path(),
        format!("/storage/v1/b/{BUCKET}/o/{ENCODED}")
    );
    assert_eq!(
        header_of(&request, "authorization").as_deref(),
        Some("Bearer gcs-token")
    );
    server.verify().await;
}

/// The body of a 2xx is not read, so a huge or malformed one changes
/// nothing, and any 2xx is `true`.
#[tokio::test]
async fn exists_ignores_a_2xx_body() {
    for template in [
        ResponseTemplate::new(204),
        ResponseTemplate::new(200).set_body_string("not json at all"),
        ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 2 * 1024 * 1024]),
    ] {
        let rig = Rig::start(vec![template], bearers(&BEARERS)).await;
        let gcs = rig.client().with_max_download_bytes(16);
        assert!(gcs.exists(BUCKET, OBJECT).await.unwrap());
        assert_eq!(rig.counts().await, (1, 1));
    }
}

/// A 404 is the answer `false`, in exactly one request, under a retry
/// policy as without one; the `200` queued behind it is never reached.
#[tokio::test]
async fn exists_is_false_on_a_404_in_one_request_under_a_retry_policy() {
    let rig = Rig::start(statuses(&[404, 200]), bearers(&BEARERS)).await;
    assert!(!rig.retrying().exists(BUCKET, OBJECT).await.unwrap());
    assert_eq!(rig.counts().await, (1, 1));

    let rig = Rig::start(statuses(&[404, 200]), bearers(&BEARERS)).await;
    assert!(!rig.client().exists(BUCKET, OBJECT).await.unwrap());
    assert_eq!(rig.counts().await, (1, 1));
}

/// Any other status is `Status { operation: "exists" }`, a `403` (no
/// `storage.objects.get`) included: never `false`. Its rendering keeps the
/// object name and Google's message out, as every operation's does.
#[tokio::test]
async fn exists_reports_other_statuses_as_exists_errors_without_the_name() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/storage/"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "denied on NAME-CANARY.png",
            }
        })))
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;

    let error = gcs.exists(BUCKET, "NAME-CANARY.png").await.unwrap_err();

    assert_eq!(
        error.to_string(),
        "GCS exists answered HTTP 403 (PERMISSION_DENIED)"
    );
    let rendered = format!("{error} | {error:?} | {error:#?}");
    assert!(!rendered.contains("CANARY"), "{rendered}");
    assert!(!rendered.contains(&server.uri()), "no URL: {rendered}");
    assert_eq!(error.sensitive_message(), Some("denied on NAME-CANARY.png"));
}

/// An invalid object or bucket is refused by `exists` with neither a storage
/// request nor a token fetch, under both name policies.
#[tokio::test]
async fn exists_refuses_an_invalid_name_or_bucket_before_a_request_or_a_token() {
    let server = MockServer::start().await;
    let gcs = authorized_client(&server).await;
    for policy in [ObjectNamePolicy::Strict, ObjectNamePolicy::Literal] {
        let gcs = gcs.clone().with_object_name_policy(policy);
        for object in ["", ".", ".."] {
            let result = gcs.exists(BUCKET, object).await;
            assert!(
                matches!(result, Err(StorageError::InvalidObjectName { .. })),
                "{object:?}: {result:?}"
            );
        }
        for bucket in ["..", "a/b", "UPPER", ""] {
            let result = gcs.exists(bucket, "o").await;
            assert!(
                matches!(result, Err(StorageError::InvalidBucketName { .. })),
                "{bucket:?}: {result:?}"
            );
        }
    }
    let strict = gcs
        .clone()
        .with_object_name_policy(ObjectNamePolicy::Strict);
    for object in ["u/../victim.png", "./a", "a//b", "/a", "a/"] {
        let result = strict.exists(BUCKET, object).await;
        assert!(
            matches!(result, Err(StorageError::InvalidObjectName { .. })),
            "{object:?}: {result:?}"
        );
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "no storage request and no token fetch"
    );
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
        refused(gcs.exists(BUCKET, object).await.map(drop));
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

/// The `error.status` a GCS `Status` stores, and so what `Display` and the
/// derived `Debug` show: one of google.rpc.Code's names as itself, any other
/// string as `other` (v0.10.0: a plain code like `CANARY_STATUS` passed
/// through before).
#[tokio::test]
async fn an_error_status_is_shown_only_from_the_list() {
    for (status, shown) in [
        ("PERMISSION_DENIED", "PERMISSION_DENIED"),
        ("CANARY_STATUS", "other"),
        ("permission_denied", "other"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": {"code": 403, "status": status, "message": "denied"}
            })))
            .mount(&server)
            .await;
        let error = authorized_client(&server)
            .await
            .delete(BUCKET, OBJECT)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("GCS delete answered HTTP 403 ({shown})"),
            "{status}"
        );
        let debug = format!("{error:?} {error:#?}");
        assert!(
            debug.contains(&format!(r#"google_status: Some("{shown}")"#)),
            "{debug}"
        );
        assert!(!debug.to_lowercase().contains("canary"), "{debug}");
    }
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

// --- crc32c --------------------------------------------------------------------

/// CRC-32C's catalogue check value: the checksum of `CHECKED`, and what GCS
/// (and fake-gcs-server) writes as its `crc32c`, base64 of the big-endian
/// bytes.
const CHECKED: &[u8] = b"123456789";
const CHECKED_CRC32C: u32 = 0xE306_9283;
const CHECKED_CRC32C_B64: &str = "4waSgw==";

/// A CRC32C alone keeps the media upload: the same request as `upload`,
/// plus `X-Goog-Hash: crc32c=<base64 big-endian>`, the JSON API's
/// documented form for a media upload. Never multipart.
#[tokio::test]
async fn a_crc32c_alone_is_the_media_upload_plus_its_hash_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/upload/storage/v1/b/{BUCKET}/o")))
        .and(query_param("uploadType", "media"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": OBJECT})))
        .expect(1)
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;

    gcs.upload_with(
        BUCKET,
        OBJECT,
        Bytes::from_static(CHECKED),
        "text/plain",
        &UploadOptions::default().with_crc32c(CHECKED_CRC32C),
    )
    .await
    .expect("uploaded");

    let request = the_request(&server, "/upload/").await;
    assert_eq!(
        request.url.query(),
        Some(format!("uploadType=media&name={ENCODED}").as_str())
    );
    assert_eq!(
        request.body, CHECKED,
        "the bytes alone, as upload sends them"
    );
    assert_eq!(
        header_of(&request, "content-type").as_deref(),
        Some("text/plain")
    );
    assert_eq!(
        header_of(&request, "x-goog-hash"),
        Some(format!("crc32c={CHECKED_CRC32C_B64}"))
    );
    assert_eq!(
        request.headers.get_all("x-goog-hash").iter().count(),
        1,
        "one hash header"
    );
    assert_eq!(
        header_of(&request, "authorization").as_deref(),
        Some("Bearer gcs-token")
    );
    server.verify().await;
}

/// Without a CRC32C nothing carries a hash: `upload`, `upload_with`'s
/// default options and a multipart upload send no `X-Goog-Hash`, and the
/// multipart metadata no `crc32c`.
#[tokio::test]
async fn without_a_crc32c_no_hash_is_sent() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": OBJECT})))
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;
    let bytes = || Bytes::from_static(CHECKED);
    gcs.upload(BUCKET, OBJECT, bytes(), "text/plain")
        .await
        .unwrap();
    for options in [
        UploadOptions::default(),
        UploadOptions::default().with_cache_control("no-store"),
    ] {
        gcs.upload_with(BUCKET, OBJECT, bytes(), "text/plain", &options)
            .await
            .unwrap();
    }
    let uploads: Vec<Request> = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.url.path().starts_with("/upload/"))
        .collect();
    assert_eq!(uploads.len(), 3);
    for request in uploads {
        assert_eq!(header_of(&request, "x-goog-hash"), None, "{}", request.url);
        assert!(
            !contains(&request.body, b"crc32c"),
            "{}",
            String::from_utf8_lossy(&request.body)
        );
    }
}

/// With an option a media upload cannot carry, the upload is multipart and
/// the CRC32C rides in its metadata (`"crc32c":"<base64 big-endian>"`, the
/// JSON API's documented form for a multipart upload), last; no header.
#[tokio::test]
async fn a_crc32c_with_another_option_is_the_multipart_metadatas_crc32c() {
    let server = multipart_server().await;
    let gcs = authorized_client(&server).await;

    gcs.upload_with(
        BUCKET,
        OBJECT,
        Bytes::from_static(MEDIA),
        "image/png",
        &UploadOptions::default()
            .with_crc32c(CHECKED_CRC32C)
            .with_if_generation_match(0)
            .with_cache_control("no-store"),
    )
    .await
    .expect("uploaded");

    let request = the_request(&server, "/upload/").await;
    assert_eq!(
        request.url.query(),
        Some("uploadType=multipart&ifGenerationMatch=0")
    );
    let metadata = format!(
        r#"{{"name":"a/b c.png","contentType":"image/png","cacheControl":"no-store","crc32c":"{CHECKED_CRC32C_B64}"}}"#
    );
    assert_eq!(
        request.body,
        multipart(&boundary_of(&request), &metadata, "image/png", MEDIA),
        "{}",
        String::from_utf8_lossy(&request.body)
    );
    assert_eq!(header_of(&request, "x-goog-hash"), None);
}

/// GCS's answer to a checksum it finds wrong is a `400`: a `Status`, sent
/// once, never retried (under a retry policy too), whichever form carried
/// it.
#[tokio::test]
async fn a_checksum_gcs_refuses_is_one_400() {
    for options in [
        UploadOptions::default().with_crc32c(0),
        UploadOptions::default()
            .with_crc32c(0)
            .with_if_generation_match(0),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/upload/storage/v1/b/{BUCKET}/o")))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": {"code": 400, "message": "Provided CRC32C \"AAAAAA==\" doesn't match"}
            })))
            .mount(&server)
            .await;
        // A retrying client, capped so a regression costs three requests,
        // not a deadline's worth.
        let gcs = authorized_client(&server)
            .await
            .with_retry(ms_policy().with_max_attempts(3));

        let error = gcs
            .upload_with(
                BUCKET,
                OBJECT,
                Bytes::from_static(CHECKED),
                "text/plain",
                &options,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, StorageError::Status { status: 400, .. }),
            "{options:?}: {error:?}"
        );
        let _ = the_request(&server, "/upload/").await;
    }
}

/// **The emulator check** (`#[ignore]`d: it needs a running
/// fake-gcs-server, never real GCS). Run it with
/// `STRIDELABS_FAKE_GCS_URL=http://localhost:4443 cargo test -p
/// stridelabs-gcp --test storage -- --ignored crc32c_against_fake_gcs_server`.
/// It creates a scratch bucket, `stridelabs-crc32c-test-<random>`, and
/// deletes it.
///
/// - **The multipart form is verified**: a right `crc32c` is stored, a
///   wrong one is a `400` and writes nothing (the negative control).
/// - **The media-upload header form is not**: fake-gcs-server (1.56.1)
///   never reads `X-Goog-Hash` on a media upload, so a wrong checksum is
///   stored all the same. That is pinned here, so that the day the emulator
///   starts checking it this test fails, and the docs' UNVERIFIED note can
///   be revisited.
#[tokio::test]
#[ignore = "needs a fake-gcs-server: STRIDELABS_FAKE_GCS_URL"]
async fn crc32c_against_fake_gcs_server() {
    let Ok(base) = std::env::var("STRIDELABS_FAKE_GCS_URL") else {
        panic!(
            "STRIDELABS_FAKE_GCS_URL is not set: point it at a fake-gcs-server \
             (e.g. http://localhost:4443, `-scheme http`); this test never runs against real GCS"
        );
    };
    let base = base.trim_end_matches('/').to_owned();
    let http = reqwest::Client::new();
    let bucket = format!("stridelabs-crc32c-test-{:08x}", rand::random::<u32>());
    let created = http
        .post(format!("{base}/storage/v1/b"))
        .json(&json!({"name": bucket}))
        .send()
        .await
        .expect("the emulator answers");
    assert!(
        created.status().is_success(),
        "create {bucket}: {}",
        created.status()
    );

    let gcs = GcsClient::emulator(http.clone(), &base, None);
    let upload = |object: &'static str, options: UploadOptions| {
        let gcs = gcs.clone();
        let bucket = bucket.clone();
        async move {
            gcs.upload_with(
                &bucket,
                object,
                Bytes::from_static(CHECKED),
                "text/plain",
                &options,
            )
            .await
        }
    };
    let multipart = || UploadOptions::default().with_cache_control("no-store");
    let wrong = CHECKED_CRC32C ^ 1;

    let multipart_right = upload("multipart-right", multipart().with_crc32c(CHECKED_CRC32C)).await;
    let multipart_wrong = upload("multipart-wrong", multipart().with_crc32c(wrong)).await;
    let media_right = upload(
        "media-right",
        UploadOptions::default().with_crc32c(CHECKED_CRC32C),
    )
    .await;
    let media_wrong = upload("media-wrong", UploadOptions::default().with_crc32c(wrong)).await;
    let mut stored = Vec::new();
    for object in [
        "multipart-right",
        "multipart-wrong",
        "media-right",
        "media-wrong",
    ] {
        stored.push(
            gcs.download(&bucket, object)
                .await
                .expect("a download")
                .map(|(bytes, _)| bytes),
        );
    }

    // Clean up before asserting, so a failure leaves no bucket behind.
    for object in [
        "multipart-right",
        "multipart-wrong",
        "media-right",
        "media-wrong",
    ] {
        gcs.delete(&bucket, object).await.expect("a delete");
    }
    let deleted = http
        .delete(format!("{base}/storage/v1/b/{bucket}"))
        .send()
        .await
        .expect("the emulator answers");
    assert!(
        deleted.status().is_success(),
        "delete {bucket}: {}",
        deleted.status()
    );

    multipart_right.expect("a right crc32c in the multipart metadata is accepted");
    assert_eq!(stored[0].as_deref(), Some(CHECKED));
    assert!(
        matches!(
            multipart_wrong,
            Err(StorageError::Status { status: 400, .. })
        ),
        "a wrong crc32c in the multipart metadata is refused: {multipart_wrong:?}"
    );
    assert_eq!(stored[1], None, "and nothing was written");
    media_right.expect("a right X-Goog-Hash on a media upload is accepted");
    assert_eq!(stored[2].as_deref(), Some(CHECKED));
    // The emulator ignores the header: the reason the header form is
    // documented as UNVERIFIED. If this fails, it checks it now.
    assert!(
        media_wrong.is_ok(),
        "fake-gcs-server now refuses a wrong X-Goog-Hash on a media upload ({media_wrong:?}): \
         the header form can be verified; update the README and the CHANGELOG"
    );
    assert_eq!(stored[3].as_deref(), Some(CHECKED));
}

/// **The emulator check for `exists`** (`#[ignore]`d: it needs a running
/// fake-gcs-server, never real GCS). Run it with
/// `STRIDELABS_FAKE_GCS_URL=http://localhost:4443 cargo test -p
/// stridelabs-gcp --test storage -- --ignored exists_against_fake_gcs_server`.
/// It creates a scratch bucket, `stridelabs-exists-test-<random>`, and
/// deletes it: an uploaded object exists, a missing name does not, and a
/// deleted one no longer does.
#[tokio::test]
#[ignore = "needs a fake-gcs-server: STRIDELABS_FAKE_GCS_URL"]
async fn exists_against_fake_gcs_server() {
    let Ok(base) = std::env::var("STRIDELABS_FAKE_GCS_URL") else {
        panic!(
            "STRIDELABS_FAKE_GCS_URL is not set: point it at a fake-gcs-server \
             (e.g. http://localhost:4443, `-scheme http`); this test never runs against real GCS"
        );
    };
    let base = base.trim_end_matches('/').to_owned();
    let http = reqwest::Client::new();
    let bucket = format!("stridelabs-exists-test-{:08x}", rand::random::<u32>());
    let created = http
        .post(format!("{base}/storage/v1/b"))
        .json(&json!({"name": bucket}))
        .send()
        .await
        .expect("the emulator answers");
    assert!(
        created.status().is_success(),
        "create {bucket}: {}",
        created.status()
    );

    // A slash and a space: the name goes out as one encoded path segment.
    let object = "dir/exists probe.txt";
    let gcs = GcsClient::emulator(http.clone(), &base, None);
    let uploaded = gcs
        .upload(&bucket, object, Bytes::from_static(b"probe"), "text/plain")
        .await;
    let after_upload = gcs.exists(&bucket, object).await;
    let missing = gcs.exists(&bucket, "dir/no such object.txt").await;
    let deleted = gcs.delete(&bucket, object).await;
    let after_delete = gcs.exists(&bucket, object).await;

    // Clean up before asserting, so a failure leaves no bucket behind.
    let removed = http
        .delete(format!("{base}/storage/v1/b/{bucket}"))
        .send()
        .await
        .expect("the emulator answers");
    assert!(
        removed.status().is_success(),
        "delete {bucket}: {}",
        removed.status()
    );

    uploaded.expect("the upload");
    assert!(after_upload.expect("exists after an upload"), "uploaded");
    assert!(!missing.expect("exists of a missing name"), "missing");
    assert!(deleted.expect("the delete"), "deleted");
    assert!(!after_delete.expect("exists after a delete"), "gone");
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

// --- every operation, against a counting rig --------------------------------------
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
    /// The object existence probe.
    Exists,
    /// `bucket_reachable`.
    List,
}

const OPS: [Op; 6] = [
    Op::Upload,
    Op::CreateOnly,
    Op::Download,
    Op::Delete,
    Op::Exists,
    Op::List,
];

impl Op {
    async fn run(self, gcs: &GcsClient) -> Result<(), StorageError> {
        self.run_on(gcs, BUCKET, OBJECT).await
    }

    /// [`Op::run`] on `bucket` and `object` (which `List` does not take).
    async fn run_on(self, gcs: &GcsClient, bucket: &str, object: &str) -> Result<(), StorageError> {
        let media = || Bytes::from_static(MEDIA);
        match self {
            Op::Upload => gcs.upload(bucket, object, media(), "image/png").await,
            Op::CreateOnly => {
                gcs.upload_with(
                    bucket,
                    object,
                    media(),
                    "image/png",
                    &UploadOptions::default().with_if_generation_match(0),
                )
                .await
            }
            Op::Download => gcs.download(bucket, object).await.map(drop),
            Op::Delete => gcs.delete(bucket, object).await.map(drop),
            Op::Exists => gcs.exists(bucket, object).await.map(drop),
            Op::List => gcs.bucket_reachable(bucket).await,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Op::Upload | Op::CreateOnly => "upload",
            Op::Download => "download",
            Op::Delete => "delete",
            Op::Exists => "exists",
            Op::List => "list",
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

/// A `401` is the answer: one request, `Status { 401 }`, and no second
/// token, on every operation (a caller that wants a refreshed token evicts
/// it with `TokenProvider::invalidate` and replays itself).
#[tokio::test]
async fn a_401_is_one_request_and_no_refresh() {
    for op in OPS {
        let rig = Rig::start(statuses(&[401, 200]), bearers(&BEARERS)).await;

        let result = op.run(&rig.client()).await;

        assert!(is_status(&result, op, 401), "{op:?}: {result:?}");
        assert_eq!(rig.counts().await, (1, 1), "{op:?}: (requests, tokens)");
    }
}

// --- object names: the policies, the name table, the quoting sweep -----------------
//
// The request lines are read off a raw socket (`RawServer`): what went out is
// exactly what is compared, with nothing parsed or normalized on the way.

/// The bucket the name table is addressed in.
const NAMES_BUCKET: &str = "names-bucket";

/// The library's own name table: names GCS accepts, every one written as
/// GCS addresses it. RFC 3986's unreserved characters (`A-Z a-z 0-9 - . _
/// ~`) stay literal and everything else is percent-encoded, UTF-8 bytes in
/// upper-case hex; `/` is `%2F` in a path segment or a query value and kept
/// in a public URL's path. The rows `Strict` refuses come first.
///
/// (name, as one segment or query value, as a public URL's path)
#[rustfmt::skip]
const NAMES: [(&str, &str, &str); 31] = [
    // An empty, `.` or `..` segment, or a leading or trailing `/`: the 14
    // names `Strict` refuses.
    ("media/alice/news//daily/clip.mp3", "media%2Falice%2Fnews%2F%2Fdaily%2Fclip.mp3", "media/alice/news//daily/clip.mp3"),
    ("media/alice/./clip.mp3", "media%2Falice%2F.%2Fclip.mp3", "media/alice/./clip.mp3"),
    ("media/alice/../clip.mp3", "media%2Falice%2F..%2Fclip.mp3", "media/alice/../clip.mp3"),
    ("/leading.mp3", "%2Fleading.mp3", "/leading.mp3"),
    ("trailing/", "trailing%2F", "trailing/"),
    ("a/./b.mp3", "a%2F.%2Fb.mp3", "a/./b.mp3"),
    ("a/../b.mp3", "a%2F..%2Fb.mp3", "a/../b.mp3"),
    ("./x", ".%2Fx", "./x"),
    ("../x", "..%2Fx", "../x"),
    ("x/.", "x%2F.", "x/."),
    ("x/..", "x%2F..", "x/.."),
    (".", ".", "."),
    ("..", "..", ".."),
    ("", "", ""),
    // The 17 every policy sends.
    ("media/someone/show/20261019-070509-the-title.mp3", "media%2Fsomeone%2Fshow%2F20261019-070509-the-title.mp3", "media/someone/show/20261019-070509-the-title.mp3"),
    ("media/someone/covers/0123456789abcdef.jpg", "media%2Fsomeone%2Fcovers%2F0123456789abcdef.jpg", "media/someone/covers/0123456789abcdef.jpg"),
    ("previews/voice-a-v1.mp3", "previews%2Fvoice-a-v1.mp3", "previews/voice-a-v1.mp3"),
    ("...", "...", "..."),
    ("a b/c~d_e-f.g", "a%20b%2Fc~d_e-f.g", "a%20b/c~d_e-f.g"),
    ("a b.mp3", "a%20b.mp3", "a%20b.mp3"),
    ("a+b.mp3", "a%2Bb.mp3", "a%2Bb.mp3"),
    ("what?.mp3", "what%3F.mp3", "what%3F.mp3"),
    ("hash#tag.mp3", "hash%23tag.mp3", "hash%23tag.mp3"),
    ("100%.mp3", "100%25.mp3", "100%25.mp3"),
    ("a%2Fb.mp3", "a%252Fb.mp3", "a%252Fb.mp3"),
    ("%2e%2e", "%252e%252e", "%252e%252e"),
    ("x+y%z&=;,@!$'()*:", "x%2By%25z%26%3D%3B%2C%40%21%24%27%28%29%2A%3A", "x%2By%25z%26%3D%3B%2C%40%21%24%27%28%29%2A%3A"),
    ("\\|^`{}[]\"<>#?", "%5C%7C%5E%60%7B%7D%5B%5D%22%3C%3E%23%3F", "%5C%7C%5E%60%7B%7D%5B%5D%22%3C%3E%23%3F"),
    ("caf\u{e9}/\u{fc}\u{df}-\u{2603}-\u{1f600}.mp3", "caf%C3%A9%2F%C3%BC%C3%9F-%E2%98%83-%F0%9F%98%80.mp3", "caf%C3%A9/%C3%BC%C3%9F-%E2%98%83-%F0%9F%98%80.mp3"),
    ("caf\u{e9} \u{2603} \u{1f989}.mp3", "caf%C3%A9%20%E2%98%83%20%F0%9F%A6%89.mp3", "caf%C3%A9%20%E2%98%83%20%F0%9F%A6%89.mp3"),
    ("nul\0 tab\t cr-lf\r\n del\u{7f}", "nul%00%20tab%09%20cr-lf%0D%0A%20del%7F", "nul%00%20tab%09%20cr-lf%0D%0A%20del%7F"),
];

/// How many leading [`NAMES`] rows `Strict` refuses.
const STRICT_REFUSED: usize = 14;

/// The names no URL path segment can carry, which `Literal` refuses on a
/// download, an existence probe and a delete.
const UNSENDABLE: [&str; 3] = ["", ".", ".."];

/// The table's rule, written out independently of the crate: every UTF-8
/// byte but `A-Z a-z 0-9 - . _ ~` (and `/` when `keep_slash`) as `%XX`,
/// upper-case hex.
fn unreserved_quote(name: &str, keep_slash: bool) -> String {
    let mut out = String::new();
    for &byte in name.as_bytes() {
        if byte.is_ascii_alphanumeric() || b"_.-~".contains(&byte) || (keep_slash && byte == b'/') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// The table agrees with its own rule, row by row: it is the rule written
/// down, not a recording.
#[test]
fn the_name_table_is_the_unreserved_rule() {
    for (name, segment, path) in NAMES {
        assert_eq!(unreserved_quote(name, false), segment, "{name:?}");
        assert_eq!(unreserved_quote(name, true), path, "{name:?}");
    }
    let mut names: Vec<&str> = NAMES.iter().map(|(name, ..)| *name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), NAMES.len(), "no repeated row");
}

/// The public URL of a table row.
fn table_url(path: &str) -> String {
    format!("https://storage.googleapis.com/{NAMES_BUCKET}/{path}")
}

/// A GCS stand-in on a raw socket that accepts everything but a 1,025-byte
/// name (GCS's limit is 1,024), which it answers `400` wherever the request
/// carries it, as GCS would; and a token server.
struct NameRig {
    gcs: RawServer,
    tokens: MockServer,
}

impl NameRig {
    async fn start() -> NameRig {
        NameRig {
            gcs: RawServer::start(|_, request| {
                if contains(request, &[b'n'; 1_025]) {
                    RawReply::Full(raw_json(
                        "400 Bad Request",
                        br#"{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"The object name is too long"}}"#,
                    ))
                } else if request.starts_with(b"DELETE ") {
                    RawReply::Full(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
                } else {
                    RawReply::Full(raw_ok(br#"{"kind":"storage#object"}"#))
                }
            })
            .await,
            tokens: token_server(bearers(&["t1"])).await,
        }
    }

    fn client(&self, policy: ObjectNamePolicy) -> GcsClient {
        GcsClient::new(never_retrying(), exact_provider(&self.tokens))
            .with_base_url(&self.gcs.base_url)
            .with_object_name_policy(policy)
    }

    /// The request lines sent so far, and the tokens minted.
    async fn sent(&self) -> (Vec<String>, usize) {
        let lines = self
            .gcs
            .requests()
            .iter()
            .map(|r| request_line(r))
            .collect();
        (lines, request_count(&self.tokens).await)
    }

    /// No request path ever names the bucket itself, or the object list.
    fn assert_never_the_bucket(&self, bucket: &str) {
        for request in self.gcs.requests() {
            let line = request_line(&request);
            let path = line.split(' ').nth(1).unwrap().split('?').next().unwrap();
            assert!(
                !path.ends_with(&format!("/b/{bucket}/")) && !path.ends_with("/o/"),
                "{line}"
            );
        }
    }
}

/// The five object operations on `name`, each its own result, with the
/// create-only multipart upload as `upload_with`.
async fn every_object_op(
    gcs: &GcsClient,
    bucket: &str,
    name: &str,
) -> [Result<(), StorageError>; 5] {
    [
        Op::Upload.run_on(gcs, bucket, name).await,
        Op::CreateOnly.run_on(gcs, bucket, name).await,
        Op::Download.run_on(gcs, bucket, name).await,
        Op::Delete.run_on(gcs, bucket, name).await,
        Op::Exists.run_on(gcs, bucket, name).await,
    ]
}

/// The request lines [`every_object_op`] sends for a name quoted `quoted`,
/// its delete to `delete_path`.
fn object_op_lines(bucket: &str, quoted: &str, delete_path: &str) -> [String; 5] {
    [
        format!("POST /upload/storage/v1/b/{bucket}/o?uploadType=media&name={quoted} HTTP/1.1"),
        format!(
            "POST /upload/storage/v1/b/{bucket}/o?uploadType=multipart&ifGenerationMatch=0 HTTP/1.1"
        ),
        format!("GET /storage/v1/b/{bucket}/o/{quoted}?alt=media HTTP/1.1"),
        format!("DELETE {delete_path} HTTP/1.1"),
        format!("GET /storage/v1/b/{bucket}/o/{quoted}?fields=name HTTP/1.1"),
    ]
}

/// The metadata part's `name` in a raw multipart request.
fn multipart_name(request: &[u8]) -> String {
    let body = request_body(request);
    let metadata = body
        .split(|&b| b == b'\n')
        .nth(3)
        .expect("the metadata line");
    let metadata = metadata.strip_suffix(b"\r").unwrap_or(metadata);
    let value: serde_json::Value = serde_json::from_slice(metadata).unwrap();
    value["name"].as_str().unwrap().to_owned()
}

/// v0.8.0's rule, pinned on the name table: the 14 are refused by every
/// operation and both public URLs, with no request sent and no token
/// fetched; the 17 others go out encoded as the table says.
#[tokio::test]
async fn strict_refuses_the_same_fourteen_names_everywhere() {
    let bucket = NAMES_BUCKET;
    let rig = NameRig::start().await;
    let gcs = rig.client(ObjectNamePolicy::Strict);
    assert_eq!(
        gcs.object_name_policy(),
        ObjectNamePolicy::Strict,
        "the default"
    );
    assert_eq!(
        GcsClient::new(never_retrying(), exact_provider(&rig.tokens)).object_name_policy(),
        ObjectNamePolicy::Strict
    );

    let mut refused = 0;
    for (index, (name, segment, path)) in NAMES.into_iter().enumerate() {
        let before = rig.sent().await;
        let results = every_object_op(&gcs, bucket, name).await;
        let urls = [
            public_url(bucket, name),
            public_url_with(bucket, name, ObjectNamePolicy::Strict),
        ];
        if urls[0].is_err() {
            refused += 1;
            assert!(index < STRICT_REFUSED, "{name:?} refused");
            for result in &results {
                assert!(
                    matches!(result, Err(StorageError::InvalidObjectName { .. })),
                    "{name:?}: {result:?}"
                );
            }
            for url in &urls {
                assert!(matches!(url, Err(StorageError::InvalidObjectName { .. })));
            }
            assert_eq!(rig.sent().await, before, "{name:?}: nothing sent, no token");
        } else {
            assert!(index >= STRICT_REFUSED, "{name:?} accepted");
            for result in &results {
                assert!(result.is_ok(), "{name:?}: {result:?}");
            }
            for url in urls {
                assert_eq!(url.unwrap(), table_url(path), "{name:?}");
            }
            let requests = rig.gcs.requests();
            let sent: Vec<String> = requests[requests.len() - 5..]
                .iter()
                .map(|request| request_line(request))
                .collect();
            assert_eq!(
                sent,
                object_op_lines(
                    bucket,
                    segment,
                    &format!("/storage/v1/b/{bucket}/o/{segment}")
                ),
                "{name:?}"
            );
            assert_eq!(multipart_name(&requests[requests.len() - 4]), name);
        }
    }
    assert_eq!(refused, STRICT_REFUSED, "exactly the 14");
}

/// `public_url_with(.., Literal)` writes every table name as the table
/// says, the empty one included, and still checks the bucket.
#[test]
fn literal_public_urls_address_every_name() {
    let bucket = NAMES_BUCKET;
    for (name, _, path) in NAMES {
        assert_eq!(
            public_url_with(bucket, name, ObjectNamePolicy::Literal).unwrap(),
            table_url(path),
            "{name:?}"
        );
    }
    assert!(matches!(
        public_url_with("Not A Bucket", "x", ObjectNamePolicy::Literal),
        Err(StorageError::InvalidBucketName { .. })
    ));
    // Exact addressing, not a safe URL: the segments are written as given.
    assert_eq!(
        public_url_with(bucket, "u/../victim.png", ObjectNamePolicy::Literal).unwrap(),
        format!("https://storage.googleapis.com/{bucket}/u/../victim.png")
    );
}

/// Under `Literal` a delete goes to the name's own path for every table
/// name but the three no path segment can carry (`.` and `..` would be sent
/// to `/o/` and to the bucket itself): those are refused, with nothing sent
/// and no token.
#[tokio::test]
async fn literal_deletes_go_to_each_names_path_and_the_unsendable_are_refused() {
    let bucket = NAMES_BUCKET;
    let rig = NameRig::start().await;
    let gcs = rig.client(ObjectNamePolicy::Literal);
    for (name, segment, _) in NAMES {
        let before = rig.sent().await;
        if UNSENDABLE.contains(&name) {
            for result in [
                gcs.delete(bucket, name).await.map(drop),
                gcs.download(bucket, name).await.map(drop),
                gcs.exists(bucket, name).await.map(drop),
            ] {
                assert!(
                    matches!(result, Err(StorageError::InvalidObjectName { .. })),
                    "{name:?}: {result:?}"
                );
            }
            assert_eq!(rig.sent().await, before, "{name:?}: nothing sent, no token");
            continue;
        }
        assert!(gcs.delete(bucket, name).await.unwrap());
        let requests = rig.gcs.requests();
        assert_eq!(
            request_line(requests.last().unwrap()),
            format!("DELETE /storage/v1/b/{bucket}/o/{segment} HTTP/1.1"),
            "{name:?}"
        );
        assert!(gcs.exists(bucket, name).await.unwrap());
        let requests = rig.gcs.requests();
        assert_eq!(
            request_line(requests.last().unwrap()),
            format!("GET /storage/v1/b/{bucket}/o/{segment}?fields=name HTTP/1.1"),
            "{name:?}"
        );
    }
    rig.assert_never_the_bucket(bucket);
}

/// The hazard `Literal` must never open: `/o/..` is sent as the bucket
/// itself, and a `DELETE` there deletes an empty bucket. `delete("..")`
/// (and `"."` and `""`) is refused with nothing sent and no token fetched,
/// under a retry policy too; so is `exists`, which would otherwise read the
/// bucket's metadata as an object's.
#[tokio::test]
async fn a_literal_delete_of_dot_dot_never_reaches_the_bucket() {
    let rig = NameRig::start().await;
    let gcs = rig
        .client(ObjectNamePolicy::Literal)
        .with_retry(ms_policy());
    for name in ["..", ".", ""] {
        let result = gcs.delete(BUCKET, name).await;
        assert!(
            matches!(result, Err(StorageError::InvalidObjectName { .. })),
            "{name:?}: {result:?}"
        );
        let result = gcs.exists(BUCKET, name).await;
        assert!(
            matches!(result, Err(StorageError::InvalidObjectName { .. })),
            "{name:?}: {result:?}"
        );
    }
    assert_eq!(rig.sent().await, (Vec::new(), 0), "nothing sent, no token");
}

/// Under `Literal` both uploads send all 31 table names, the unsendable
/// three included: the media upload's `name=` is the name as one query
/// value, and the multipart metadata names the object, exactly.
#[tokio::test]
async fn literal_uploads_send_every_name() {
    let bucket = NAMES_BUCKET;
    let rig = NameRig::start().await;
    let gcs = rig.client(ObjectNamePolicy::Literal);
    for (name, segment, _) in NAMES {
        let media = || Bytes::from_static(b"clip");
        gcs.upload(bucket, name, media(), "audio/mpeg")
            .await
            .unwrap();
        gcs.upload_with(
            bucket,
            name,
            media(),
            "audio/mpeg",
            &UploadOptions::default().with_cache_control("no-store"),
        )
        .await
        .unwrap();
        let requests = rig.gcs.requests();
        let [media_upload, multipart] = &requests[requests.len() - 2..] else {
            unreachable!()
        };
        assert_eq!(
            request_line(media_upload),
            format!(
                "POST /upload/storage/v1/b/{bucket}/o?uploadType=media&name={segment} HTTP/1.1"
            ),
            "{name:?}"
        );
        assert_eq!(multipart_name(multipart), name, "{name:?}");
    }
    assert_eq!(rig.gcs.requests().len(), 62);
    rig.assert_never_the_bucket(bucket);
}

/// Odd names `Literal` sends exactly — in the path, the query and the JSON:
/// doubled, leading and trailing slashes, dot segments, the double-slash
/// slug, percent-looking text (a literal `%2e%2e` goes out as `%252e%252e`,
/// never a dot segment), backslashes, `?` and `#`.
#[tokio::test]
async fn literal_names_go_out_exactly_in_the_path_the_query_and_the_json() {
    let rig = NameRig::start().await;
    let gcs = rig.client(ObjectNamePolicy::Literal);
    for name in [
        "a//b",
        "/a",
        "a/",
        "./a",
        "a/../b",
        "media/alice/news//daily/clip.mp3",
        "%2e%2e",
        "a/%2E%2e/b",
        "a\\..\\b\\",
        "what?#x",
        "?",
        "#",
        "...",
    ] {
        let results = every_object_op(&gcs, BUCKET, name).await;
        for result in &results {
            assert!(result.is_ok(), "{name:?}: {result:?}");
        }
        let requests = rig.gcs.requests();
        let sent = &requests[requests.len() - 5..];
        let quoted = unreserved_quote(name, false);
        assert_eq!(
            sent.iter().map(|r| request_line(r)).collect::<Vec<_>>(),
            object_op_lines(
                BUCKET,
                &quoted,
                &format!("/storage/v1/b/{BUCKET}/o/{quoted}")
            ),
            "{name:?}"
        );
        assert_eq!(multipart_name(&sent[1]), name);
    }
    assert_eq!(unreserved_quote("%2e%2e", false), "%252e%252e");
    let requests = rig.gcs.requests();
    assert!(
        requests
            .iter()
            .any(|r| request_line(r)
                == format!("DELETE /storage/v1/b/{BUCKET}/o/%252e%252e HTTP/1.1"))
    );
    rig.assert_never_the_bucket(BUCKET);
}

/// Everything else is GCS's call: a 1,025-byte name (past GCS's 1,024) is
/// sent by every operation and comes back as the mock's `400`, and so do
/// the unsendable names on an upload, which carries them as a value.
#[tokio::test]
async fn literal_leaves_the_rest_to_gcs() {
    let rig = NameRig::start().await;
    let gcs = rig.client(ObjectNamePolicy::Literal);
    let long = "n".repeat(1_025);
    for (i, result) in every_object_op(&gcs, BUCKET, &long)
        .await
        .iter()
        .enumerate()
    {
        assert!(
            matches!(result, Err(StorageError::Status { status: 400, .. })),
            "op {i}: {result:?}"
        );
    }
    assert_eq!(rig.gcs.requests().len(), 5, "each sent once");

    for name in UNSENDABLE {
        let before = rig.gcs.requests().len();
        Op::Upload.run_on(&gcs, BUCKET, name).await.unwrap();
        Op::CreateOnly.run_on(&gcs, BUCKET, name).await.unwrap();
        let requests = rig.gcs.requests();
        assert_eq!(requests.len(), before + 2, "{name:?}: both sent");
        assert_eq!(multipart_name(&requests[before + 1]), name);
    }
    rig.assert_never_the_bucket(BUCKET);
}

/// The quoting sweep: `x{c}y/z{c}` for every code point from U+0001 to
/// U+2FFF, U+1F989 and U+10FFFF. `public_url_with` (either policy) keeps
/// the unreserved characters and `/` and encodes the rest everywhere
/// `Strict` accepts the name, and `Strict` refuses exactly one (`/` makes
/// `x/y/z/`, a trailing slash). On the wire, the media upload's `name=`
/// encodes `/` too.
#[tokio::test]
async fn the_quoting_sweep_keeps_only_the_unreserved_characters() {
    let names: Vec<String> = (1..0x3000)
        .chain([0x1F989, 0x10FFFF])
        .filter_map(char::from_u32)
        .map(|c| format!("x{c}y/z{c}"))
        .collect();
    assert_eq!(names.len(), 0x2FFF + 2, "no surrogate below U+3000");

    let mut strict_refused = Vec::new();
    for name in &names {
        let expected = format!(
            "https://storage.googleapis.com/{BUCKET}/{}",
            unreserved_quote(name, true)
        );
        assert_eq!(
            public_url_with(BUCKET, name, ObjectNamePolicy::Literal).unwrap(),
            expected,
            "{name:?}"
        );
        match public_url_with(BUCKET, name, ObjectNamePolicy::Strict) {
            Ok(url) => assert_eq!(url, expected, "{name:?}"),
            Err(_) => strict_refused.push(name.clone()),
        }
    }
    assert_eq!(strict_refused, ["x/y/z/"]);

    let server = RawServer::start(|_, _| RawReply::Full(raw_ok(b"{}"))).await;
    let gcs = GcsClient::emulator(never_retrying(), &server.base_url, None)
        .with_object_name_policy(ObjectNamePolicy::Literal);
    for name in &names {
        gcs.upload(BUCKET, name, Bytes::new(), "audio/mpeg")
            .await
            .unwrap();
    }
    let requests = server.requests();
    assert_eq!(requests.len(), names.len());
    for (name, request) in names.iter().zip(&requests) {
        assert_eq!(
            request_line(request),
            format!(
                "POST /upload/storage/v1/b/{BUCKET}/o?uploadType=media&name={} HTTP/1.1",
                unreserved_quote(name, false)
            ),
            "{name:?}"
        );
    }
}

// --- retry (opt-in) ---------------------------------------------------------------
//
// Real time, a millisecond policy and `never_retrying()` clients, so every
// request counted is one attempt's. The schedule itself (seven attempts at
// full jitter, the 1 ms floor, normalization) is tested on tokio's paused
// clock with synthetic attempts, in `src/retry.rs`; no socket runs there.

/// The default schedule at millisecond scale, with a deadline
/// long enough that a retry is never skipped for time.
fn ms_policy() -> RetryPolicy {
    RetryPolicy::google_default()
        .with_initial_delay(Duration::from_millis(1))
        .with_max_delay(Duration::from_millis(5))
        .with_deadline(Duration::from_secs(10))
}

impl Rig {
    fn retrying(&self) -> GcsClient {
        self.client().with_retry(ms_policy())
    }
}

/// v0.8.0's behaviour, pinned: without `with_retry` a `503` is one request
/// and `Status { 503 }`, on every operation.
#[tokio::test]
async fn without_a_policy_a_503_is_one_request() {
    for op in OPS {
        let rig = Rig::start(statuses(&[503, 200]), bearers(&BEARERS)).await;
        let gcs = rig.client();
        assert_eq!(gcs.retry_policy(), RetryPolicy::disabled());

        let result = op.run(&gcs).await;

        assert!(is_status(&result, op, 503), "{op:?}: {result:?}");
        assert_eq!(rig.counts().await, (1, 1), "{op:?}");
    }
}

/// With a policy, a `503` then a `200` succeeds in two requests on every
/// operation, the bucket probe included, on the token taken once.
#[tokio::test]
async fn a_503_then_a_200_succeeds_in_two_requests_on_every_operation() {
    for op in OPS {
        let rig = Rig::start(statuses(&[503, 200]), bearers(&BEARERS)).await;

        let result = op.run(&rig.retrying()).await;

        assert!(result.is_ok(), "{op:?}: {result:?}");
        assert_eq!(rig.counts().await, (2, 1), "{op:?}: (requests, tokens)");
        assert_eq!(bearers_sent(&rig.gcs).await, ["t1", "t1"]);
    }
}

#[tokio::test]
async fn the_six_transient_statuses_are_retried() {
    for status in [408, 429, 500, 502, 503, 504] {
        for op in OPS {
            let rig = Rig::start(statuses(&[status, 200]), bearers(&BEARERS)).await;
            let result = op.run(&rig.retrying()).await;
            assert!(result.is_ok(), "{status} {op:?}: {result:?}");
            assert_eq!(request_count(&rig.gcs).await, 2, "{status} {op:?}");
        }
    }
}

/// Every other status is the answer: one request, that status, a `401`
/// included.
#[tokio::test]
async fn other_statuses_are_not_retried_and_a_401_is_not() {
    for status in [400, 401, 403, 409, 412, 501, 505] {
        for op in OPS {
            let rig = Rig::start(statuses(&[status, 200]), bearers(&BEARERS)).await;
            let result = op.run(&rig.retrying()).await;
            assert!(
                is_status(&result, op, status),
                "{status} {op:?}: {result:?}"
            );
            assert_eq!(rig.counts().await, (1, 1), "{status} {op:?}");
        }
    }
}

/// A `404` is an answer, never retried: `None`, `false` (a delete, an
/// existence probe), or the bucket probe's `Status { 404 }`.
#[tokio::test]
async fn a_404_is_one_request_under_a_policy() {
    let rig = Rig::start(statuses(&[404, 200]), bearers(&BEARERS)).await;
    assert_eq!(rig.retrying().download(BUCKET, OBJECT).await.unwrap(), None);
    let rig = Rig::start(statuses(&[404, 200]), bearers(&BEARERS)).await;
    assert!(!rig.retrying().delete(BUCKET, OBJECT).await.unwrap());
    assert_eq!(request_count(&rig.gcs).await, 1);
    let rig = Rig::start(statuses(&[404, 200]), bearers(&BEARERS)).await;
    assert!(!rig.retrying().exists(BUCKET, OBJECT).await.unwrap());
    assert_eq!(request_count(&rig.gcs).await, 1);
    let rig = Rig::start(statuses(&[404, 200]), bearers(&BEARERS)).await;
    let result = Op::List.run(&rig.retrying()).await;
    assert!(is_status(&result, Op::List, 404), "{result:?}");
    assert_eq!(request_count(&rig.gcs).await, 1);
}

/// imgmcp's case under a policy: a create-only upload's `412` is one request
/// and the error, never a retry, never a fallback.
#[tokio::test]
async fn a_failed_precondition_is_one_request_under_a_policy() {
    let rig = Rig::start(statuses(&[412, 200]), bearers(&BEARERS)).await;
    let result = Op::CreateOnly.run(&rig.retrying()).await;
    assert!(is_status(&result, Op::CreateOnly, 412), "{result:?}");
    let sent = rig.gcs.received_requests().await.unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].url.query(),
        Some("uploadType=multipart&ifGenerationMatch=0")
    );
}

/// The attempt cap bounds the requests: a persistent `503` under a cap of
/// three is three requests and the last `503`, long before the deadline; a
/// success inside the cap is a success.
#[tokio::test]
async fn the_attempt_cap_bounds_the_requests() {
    for op in OPS {
        let rig = Rig::start(statuses(&[503]), bearers(&BEARERS)).await;
        let gcs = rig.client().with_retry(ms_policy().with_max_attempts(3));

        let result = op.run(&gcs).await;

        assert!(is_status(&result, op, 503), "{op:?}: {result:?}");
        assert_eq!(rig.counts().await, (3, 1), "{op:?}: (requests, tokens)");
    }
    let rig = Rig::start(statuses(&[503, 503, 200]), bearers(&BEARERS)).await;
    let gcs = rig.client().with_retry(ms_policy().with_max_attempts(3));
    assert!(Op::Download.run(&gcs).await.is_ok());
    assert_eq!(request_count(&rig.gcs).await, 3);
}

// --- interrupted transfers --------------------------------------------------------

const BODY: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// A raw GCS that cuts its first download off after 10 of 36 declared bytes,
/// then answers in full.
async fn cut_once() -> RawServer {
    RawServer::first_then(
        RawReply::Cut(raw_ok_cut(BODY, 10)),
        RawReply::Full(raw_ok(BODY)),
    )
    .await
}

/// A body that stops after the headers is an interrupted transfer: retried,
/// on a new connection. (What the error says is pinned on its own below, so
/// this test sees only the class.)
#[tokio::test]
async fn an_interrupted_download_is_retried_on_a_new_connection() {
    let server = cut_once().await;
    let gcs = GcsClient::emulator(never_retrying(), &server.base_url, None).with_retry(ms_policy());

    let (bytes, _) = gcs.download(BUCKET, OBJECT).await.unwrap().expect("found");

    assert_eq!(bytes, BODY);
    assert_eq!(server.requests().len(), 2);
    assert_eq!(server.accepted(), 2, "the cut connection is not reused");
}

/// The public string is v0.8.0's: without a policy an interrupted download
/// is one request and `Request { "decode error" }`.
#[tokio::test]
async fn an_interrupted_download_is_still_a_decode_error() {
    let server = cut_once().await;
    let gcs = GcsClient::emulator(never_retrying(), &server.base_url, None);

    let error = gcs.download(BUCKET, OBJECT).await.unwrap_err();

    assert!(
        matches!(&error, StorageError::Request { operation: "download", reason } if reason == "decode error"),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "GCS download request failed: decode error"
    );
    assert_eq!(server.requests().len(), 1);
}

/// A metadata server that cuts its first token body off after 12 bytes and
/// then answers in full, a GCS that serves `BODY`, and a client on both
/// under `policy`.
async fn cut_token_rig(policy: RetryPolicy) -> (RawServer, MockServer, GcsClient) {
    let token = br#"{"access_token":"t1","expires_in":3600,"token_type":"Bearer"}"#;
    let tokens = RawServer::first_then(
        RawReply::Cut(raw_ok_cut(token, 12)),
        RawReply::Full(raw_ok(token)),
    )
    .await;
    let gcs_server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(BODY))
        .mount(&gcs_server)
        .await;
    let provider = TokenProvider::metadata_server(never_retrying(), &[])
        .with_options(TokenOptions::default().metadata_base_url(tokens.base_url.clone()));
    let gcs = GcsClient::new(never_retrying(), provider)
        .with_base_url(&gcs_server.uri())
        .with_retry(policy);
    (tokens, gcs_server, gcs)
}

/// A token exchange cut off the same way fails the token transiently, and
/// the GCS operation retries it: two token connections, one GCS request.
#[tokio::test]
async fn an_interrupted_token_exchange_is_retried_by_the_operation() {
    let (tokens, gcs_server, gcs) = cut_token_rig(ms_policy()).await;

    let result = gcs.download(BUCKET, OBJECT).await;

    assert_eq!(result.unwrap().unwrap().0, BODY);
    assert_eq!(
        (tokens.accepted(), request_count(&gcs_server).await),
        (2, 1)
    );
}

/// Without a policy it is v0.8.0's `Auth { Request { "decode error" } }`,
/// and nothing reaches GCS.
#[tokio::test]
async fn an_interrupted_token_exchange_is_still_a_decode_error() {
    let (tokens, gcs_server, gcs) = cut_token_rig(RetryPolicy::disabled()).await;

    let result = gcs.download(BUCKET, OBJECT).await;

    assert!(
        matches!(
            &result,
            Err(StorageError::Auth {
                operation: "download",
                source: GcpAuthError::Request { reason, .. },
            }) if reason == "decode error"
        ),
        "{result:?}"
    );
    assert_eq!(
        (tokens.accepted(), request_count(&gcs_server).await),
        (1, 0)
    );
}

// --- bounds -----------------------------------------------------------------------

/// A 50 ms deadline against a GCS that always answers `503`. The driver
/// gives up only when the next wait (at most 1 ms here) would pass the
/// deadline, so the operation lasts more than 49 ms whatever the attempts
/// cost, then ends, with the last `503`. (How many attempts fit in the 50 ms
/// depends on the machine, so it is printed, not asserted.)
#[tokio::test]
async fn a_50_ms_deadline_ends_a_persistent_503() {
    let rig = Rig::start(statuses(&[503]), bearers(&BEARERS)).await;
    let gcs = rig.client().with_retry(
        RetryPolicy::google_default()
            .with_initial_delay(Duration::from_millis(1))
            .with_multiplier(1.0)
            .with_max_delay(Duration::from_millis(1))
            .with_deadline(Duration::from_millis(50)),
    );

    let started = Instant::now();
    let result = Op::Download.run(&gcs).await;
    let elapsed = started.elapsed();

    assert!(is_status(&result, Op::Download, 503), "{result:?}");
    let requests = request_count(&rig.gcs).await;
    assert!(
        elapsed > Duration::from_millis(49),
        "it retried until the deadline: {elapsed:?}, {requests} requests"
    );
    assert!(elapsed < Duration::from_secs(10), "it ended: {elapsed:?}");
    println!("{requests} requests in {elapsed:?}");
}

/// The client's timeout bounds each attempt, and its `Timeout` is
/// transient: an attempt that outlives it is retried, and the next one
/// succeeds.
#[tokio::test]
async fn an_attempt_past_the_timeout_is_retried() {
    let rig = Rig::start(
        vec![
            ResponseTemplate::new(200).set_delay(Duration::from_secs(5)),
            ResponseTemplate::new(200),
        ],
        bearers(&BEARERS),
    )
    .await;
    let gcs = rig.retrying().with_timeout(Duration::from_millis(300));

    let started = Instant::now();
    let result = Op::Download.run(&gcs).await;

    assert!(result.is_ok(), "{result:?}");
    assert!(
        started.elapsed() < Duration::from_millis(4_500),
        "the 5 s answer was never waited out: the attempt was cut at 300 ms"
    );
    let (requests, tokens) = rig.counts().await;
    assert!(requests >= 2, "{requests}");
    assert_eq!(tokens, 1);
}

/// A raw GCS that closes its first connection without an answer, then
/// answers `204`.
async fn drops_once() -> RawServer {
    RawServer::first_then(
        RawReply::Cut(Vec::new()),
        RawReply::Full(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()),
    )
    .await
}

/// A connection dropped before any response is retried. Accepts are
/// counted, not assumed.
#[tokio::test]
async fn a_dropped_connection_is_retried() {
    let server = drops_once().await;
    let gcs = GcsClient::emulator(never_retrying(), &server.base_url, None).with_retry(ms_policy());

    assert!(gcs.delete(BUCKET, OBJECT).await.unwrap());
    assert!(server.accepted() >= 2, "{} accepted", server.accepted());
    assert_eq!(server.requests().len(), 2);
}

/// Its public string: without a policy, one request and
/// `Request { "request error" }`.
#[tokio::test]
async fn a_dropped_connection_is_a_request_error() {
    let server = drops_once().await;
    let gcs = GcsClient::emulator(never_retrying(), &server.base_url, None);

    let error = gcs.delete(BUCKET, OBJECT).await.unwrap_err();

    assert!(
        matches!(&error, StorageError::Request { reason, .. } if reason == "request error"),
        "{error:?}"
    );
    assert_eq!(server.requests().len(), 1);
}

// --- a status line is final -----------------------------------------------------
//
// Each answer here sends its status line and headers, declares a body, and
// never sends it (`RawReply::Stall`), so the attempt's own timeout is what
// ends the body read. The error that reports it is v0.8.0's, `Timeout`; the
// status already heard decides whether the retry makes another attempt.

/// The attempt timeout these tests cut stalled bodies off with: wide
/// enough that the status line (sent at once) is always in before it.
const STALL_TIMEOUT: Duration = Duration::from_millis(500);

/// An error answer of `status` (`412 Precondition Failed`) that declares a
/// one-byte body and never sends it.
fn stalled(status: &str) -> RawReply {
    RawReply::Stall(
        format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\n")
            .into_bytes(),
    )
}

/// `op` against a GCS that answers `first`, then a 200, through an emulator
/// client with no token, `policy` and [`STALL_TIMEOUT`]: (the result, the
/// requests GCS received).
async fn after_a_stall(
    op: Op,
    first: RawReply,
    policy: RetryPolicy,
) -> (Result<(), StorageError>, usize) {
    let server = RawServer::first_then(first, RawReply::Full(raw_ok(BODY))).await;
    let gcs = GcsClient::emulator(never_retrying(), &server.base_url, None)
        .with_retry(policy)
        .with_timeout(STALL_TIMEOUT);
    let result = op.run(&gcs).await;
    (result, server.requests().len())
}

/// Every operation, concurrently, after a stall of `status`.
async fn every_op_after_a_stall(
    status: &str,
    policy: RetryPolicy,
) -> Vec<(Op, Result<(), StorageError>, usize)> {
    futures::future::join_all(OPS.map(|op| async move {
        let (result, requests) = after_a_stall(op, stalled(status), policy).await;
        (op, result, requests)
    }))
    .await
}

fn is_timeout(result: &Result<(), StorageError>, op: Op) -> bool {
    matches!(result, Err(StorageError::Timeout { operation, .. }) if *operation == op.name())
}

/// The review's case: a `412` whose error body never arrives, under a retry
/// policy. Its status line was in when the timeout cut the body off, so the
/// attempt is a `412`'s: one request, reported as v0.8.0 reported it
/// (`Timeout`), and the `200` waiting behind it is never reached.
#[tokio::test]
async fn a_412_whose_body_stalls_is_not_retried() {
    for (op, result, requests) in
        every_op_after_a_stall("412 Precondition Failed", ms_policy()).await
    {
        assert!(is_timeout(&result, op), "{op:?}: {result:?}");
        assert_eq!(requests, 1, "{op:?}: not retried");
    }
}

/// The same for a `401`: never the retry's business, however its body
/// behaves.
#[tokio::test]
async fn a_401_whose_body_stalls_is_not_retried() {
    for (op, result, requests) in every_op_after_a_stall("401 Unauthorized", ms_policy()).await {
        assert!(is_timeout(&result, op), "{op:?}: {result:?}");
        assert_eq!(requests, 1, "{op:?}: not retried");
    }
}

#[tokio::test]
async fn other_permanent_statuses_whose_bodies_stall_are_not_retried() {
    for status in [
        "400 Bad Request",
        "403 Forbidden",
        "409 Conflict",
        "501 Not Implemented",
        "505 HTTP Version Not Supported",
    ] {
        for (op, result, requests) in every_op_after_a_stall(status, ms_policy()).await {
            assert!(is_timeout(&result, op), "{status} {op:?}: {result:?}");
            assert_eq!(requests, 1, "{status} {op:?}: not retried");
        }
    }
}

/// A transient status stays transient when its body stalls: retried, and
/// the `200` behind it succeeds.
#[tokio::test]
async fn a_transient_status_whose_body_stalls_is_still_retried() {
    for status in ["503 Service Unavailable", "429 Too Many Requests"] {
        for (op, result, requests) in every_op_after_a_stall(status, ms_policy()).await {
            assert!(result.is_ok(), "{status} {op:?}: {result:?}");
            assert_eq!(requests, 2, "{status} {op:?}");
        }
    }
}

/// v0.8.0's answer, pinned: without a policy a stalled error body is the
/// operation's `Timeout` (the body read sits inside the operation's bound),
/// one request, whatever the status.
#[tokio::test]
async fn without_a_policy_a_stalled_error_body_is_a_timeout_as_in_v0_8_0() {
    for status in ["412 Precondition Failed", "503 Service Unavailable"] {
        for (op, result, requests) in every_op_after_a_stall(status, RetryPolicy::disabled()).await
        {
            assert!(is_timeout(&result, op), "{status} {op:?}: {result:?}");
            assert_eq!(requests, 1, "{status} {op:?}");
        }
    }
}

/// A metadata server answering `first` and then a token, a GCS that serves
/// `BODY`, and a client on both with a retry policy and [`STALL_TIMEOUT`];
/// the token request's own timeout is `token_timeout`.
async fn stalled_token_rig(
    first: RawReply,
    token_timeout: Duration,
) -> (RawServer, MockServer, GcsClient) {
    let token = br#"{"access_token":"t1","expires_in":3600,"token_type":"Bearer"}"#;
    let tokens = RawServer::first_then(first, RawReply::Full(raw_ok(token))).await;
    let gcs_server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(BODY))
        .mount(&gcs_server)
        .await;
    let provider = TokenProvider::metadata_server(never_retrying(), &[]).with_options(
        TokenOptions::default()
            .metadata_base_url(tokens.base_url.clone())
            .metadata_timeout(token_timeout),
    );
    let gcs = GcsClient::new(never_retrying(), provider)
        .with_base_url(&gcs_server.uri())
        .with_retry(ms_policy())
        .with_timeout(STALL_TIMEOUT);
    (tokens, gcs_server, gcs)
}

/// What the token endpoint said is the refresh's, not the attempt's: an
/// attempt cut off by its own timeout while it waits on a refresh is a
/// transient `Timeout`, whatever that refresh has heard. The next attempts
/// join the same refresh, and the operation ends with its outcome: here the
/// refresh's `400` (its body stalled until its 1.25 s timeout, mid-way
/// through the third 500 ms attempt), which is not retried. One token
/// request, nothing sent to GCS.
#[tokio::test]
async fn an_attempt_cut_off_waiting_on_a_refresh_is_retried_until_the_refresh_ends() {
    let (tokens, gcs_server, gcs) =
        stalled_token_rig(stalled("400 Bad Request"), Duration::from_millis(1_250)).await;

    let started = Instant::now();
    let result = gcs.download(BUCKET, OBJECT).await.map(drop);
    let elapsed = started.elapsed();

    assert!(
        matches!(
            &result,
            Err(StorageError::Auth {
                operation: "download",
                source: GcpAuthError::Status { status: 400, .. },
            })
        ),
        "{result:?} after {elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(1_150),
        "the attempts outlived their 500 ms timeout: {elapsed:?}"
    );
    assert_eq!(
        (tokens.accepted(), request_count(&gcs_server).await),
        (1, 0)
    );
}

/// A transient token status whose body stalls ends its refresh at the
/// refresh's 1.5 s timeout, as `Status { 503 }`, transient: a new refresh
/// gets the token.
#[tokio::test]
async fn a_transient_token_status_whose_body_stalls_is_still_retried() {
    let (tokens, gcs_server, gcs) = stalled_token_rig(
        stalled("503 Service Unavailable"),
        Duration::from_millis(1_500),
    )
    .await;

    let result = gcs.download(BUCKET, OBJECT).await;

    assert_eq!(result.unwrap().unwrap().0, BODY);
    assert_eq!(
        (tokens.accepted(), request_count(&gcs_server).await),
        (2, 1)
    );
}

// --- the access token under retry ------------------------------------------------

/// A token endpoint's `503` fails the token transiently; the operation
/// retries it, and its next attempt gets a token and succeeds.
#[tokio::test]
async fn a_503_from_the_token_endpoint_is_retried() {
    let rig = Rig::start(
        statuses(&[200]),
        vec![ResponseTemplate::new(503), token_body("t1", json!(3600))],
    )
    .await;

    let result = Op::Upload.run(&rig.retrying()).await;

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(rig.counts().await, (1, 2), "(requests, tokens)");
}

/// `invalid_grant` is the token endpoint's answer about the credential:
/// never retried, and nothing reaches GCS.
#[tokio::test]
async fn invalid_grant_is_not_retried_and_nothing_reaches_gcs() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(USER_TOKEN_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Token has been expired or revoked.",
        })))
        .mount(&server)
        .await;
    let tokens = routed(
        TokenProvider::from_authorized_user_json(
            never_retrying(),
            &[],
            authorized_user().to_string().as_bytes(),
        )
        .unwrap(),
        &server,
    );
    let gcs = GcsClient::new(never_retrying(), tokens)
        .with_base_url(&server.uri())
        .with_retry(ms_policy());

    let result = Op::Delete.run(&gcs).await;

    assert!(
        matches!(
            &result,
            Err(StorageError::Auth {
                operation: "delete",
                source: GcpAuthError::Status { status: 400, detail, .. },
            }) if detail == "invalid_grant"
        ),
        "{result:?}"
    );
    let sent = server.received_requests().await.unwrap();
    assert_eq!(sent.len(), 1, "one token request");
    assert!(sent
        .iter()
        .all(|request| request.url.path() == USER_TOKEN_PATH));
}

/// Each retry is one `debug` line with the operation, the attempt, the wait
/// and the status, and nothing the request or Google's message carried. A
/// current-thread runtime, so every line lands in this test's capture.
#[tokio::test]
async fn the_retry_path_logs_no_name_and_no_message() {
    let capture = LogCapture::default();
    let _guard = capture.install();
    let refusal = ResponseTemplate::new(503).set_body_json(json!({
        "error": {
            "code": 503,
            "status": "UNAVAILABLE",
            "message": "CANARY-MESSAGE about CANARY-NAME/clip.mp3",
        }
    }));
    let rig = Rig::start(
        vec![refusal.clone(), refusal, ResponseTemplate::new(200)],
        bearers(&["CANARY-BEARER"]),
    )
    .await;
    let gcs = rig.retrying();

    gcs.upload(
        BUCKET,
        "CANARY-NAME/clip.mp3",
        Bytes::from_static(b"clip"),
        "audio/mpeg",
    )
    .await
    .unwrap();

    let logs = capture.text();
    for expected in [
        "a GCS request failed transiently; retrying",
        "operation=\"upload\"",
        "attempt=1",
        "attempt=2",
        "status=503",
        "wait_ms=",
    ] {
        assert!(logs.contains(expected), "{expected:?} not logged: {logs}");
    }
    assert_eq!(logs.matches("failed transiently").count(), 2, "{logs}");
    assert!(!logs.contains("CANARY"), "{logs}");

    // And a final error under the policy says no more.
    let rig = Rig::start(
        vec![ResponseTemplate::new(503).set_body_json(json!({
            "error": {"code": 503, "status": "UNAVAILABLE", "message": "CANARY-MESSAGE"}
        }))],
        bearers(&BEARERS),
    )
    .await;
    let gcs = rig
        .client()
        .with_retry(ms_policy().with_deadline(Duration::from_millis(20)));
    let error = gcs.download(BUCKET, "CANARY-NAME").await.unwrap_err();
    let rendered = format!("{}\n{error} | {error:?} | {gcs:?}", capture.text());
    assert!(!rendered.contains("CANARY"), "{rendered}");
    assert_eq!(
        error.sensitive_message(),
        Some("CANARY-MESSAGE"),
        "kept apart"
    );
}

// --- the bucket pieces ------------------------------------------------------------

/// `bucket_reachable` lists at most one object, authorized like every
/// operation, and any 2xx is `Ok`.
#[tokio::test]
async fn bucket_reachable_lists_one_object() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/storage/v1/b/{BUCKET}/o")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"kind": "storage#objects"})))
        .expect(1)
        .mount(&server)
        .await;
    let gcs = authorized_client(&server).await;

    gcs.bucket_reachable(BUCKET).await.unwrap();

    let request = the_request(&server, "/storage/").await;
    assert_eq!(request.url.query(), Some("maxResults=1"));
    assert_eq!(
        header_of(&request, "authorization").as_deref(),
        Some("Bearer gcs-token")
    );
    assert_eq!(
        header_of(&request, "x-goog-user-project").as_deref(),
        Some("quota-project")
    );

    let rig = Rig::start(statuses(&[204]), bearers(&BEARERS)).await;
    rig.client().bucket_reachable(BUCKET).await.unwrap();
}

/// Anything but a 2xx is the probe's `Status { operation: "list" }`: a
/// missing bucket's `404`, and a `403` (which says nothing about whether
/// the bucket exists) with Google's code.
#[tokio::test]
async fn bucket_reachable_reports_404_and_403_as_list_statuses() {
    for (status, google) in [(404, "NOT_FOUND"), (403, "PERMISSION_DENIED")] {
        let rig = Rig::start(
            vec![ResponseTemplate::new(status).set_body_json(json!({
                "error": {"code": status, "status": google, "message": "on CANARY"}
            }))],
            bearers(&BEARERS),
        )
        .await;
        let error = rig.client().bucket_reachable(BUCKET).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("GCS list answered HTTP {status} ({google})")
        );
        assert!(matches!(
            error,
            StorageError::Status {
                operation: "list",
                ..
            }
        ));
        assert_eq!(rig.counts().await, (1, 1));
    }
}

/// The rule every operation applies to a bucket is `validate_bucket_name`,
/// and an invalid bucket is refused by each, the probe included, with the
/// same reason and nothing sent.
#[tokio::test]
async fn validate_bucket_name_is_the_rule_every_operation_applies() {
    for bucket in [
        "img-bucket",
        "imgmcp.stridelabs.ai",
        "a_b",
        "123",
        &"a".repeat(222),
    ] {
        assert!(validate_bucket_name(bucket).is_ok(), "{bucket}");
    }
    let rig = Rig::start(statuses(&[200]), bearers(&BEARERS)).await;
    for policy in [ObjectNamePolicy::Strict, ObjectNamePolicy::Literal] {
        let gcs = rig.retrying().with_object_name_policy(policy);
        for bucket in [
            "",
            "ab",
            "..",
            "a..b",
            ".abc",
            "abc.",
            "-abc",
            "Upper",
            "a/b",
            "a b",
            "a%2Fb",
            &"a".repeat(223),
        ] {
            let Err(StorageError::InvalidBucketName { reason }) = validate_bucket_name(bucket)
            else {
                panic!("{bucket:?} accepted");
            };
            let mut results = Vec::new();
            for op in OPS {
                results.push(op.run_on(&gcs, bucket, "o").await);
            }
            results.push(public_url_with(bucket, "o", policy).map(drop));
            for result in results {
                assert!(
                    matches!(&result, Err(StorageError::InvalidBucketName { reason: r }) if *r == reason),
                    "{bucket:?}: {result:?}"
                );
            }
        }
    }
    assert_eq!(rig.counts().await, (0, 0), "nothing sent, no token");
}

// --- the API --------------------------------------------------------------------------

#[test]
fn the_name_and_retry_api_is_pinned() {
    let _: fn(GcsClient, ObjectNamePolicy) -> GcsClient = GcsClient::with_object_name_policy;
    let _: fn(&GcsClient) -> ObjectNamePolicy = GcsClient::object_name_policy;
    let _: fn(GcsClient, RetryPolicy) -> GcsClient = GcsClient::with_retry;
    let _: fn(&GcsClient) -> RetryPolicy = GcsClient::retry_policy;
    let _: fn(RetryPolicy, u32) -> RetryPolicy = RetryPolicy::with_max_attempts;
    // One type at every path: the module, `storage` and the crate root.
    let _: stridelabs_gcp::retry::RetryPolicy = stridelabs_gcp::RetryPolicy::disabled();
    let _: RetryPolicy = stridelabs_gcp::retry::RetryPolicy::disabled();
    let _: fn(&str, &str, ObjectNamePolicy) -> Result<String, StorageError> = public_url_with;
    let _: fn(&str) -> Result<(), StorageError> = validate_bucket_name;
    // The crate root re-exports them.
    let _: fn(&str) -> Result<(), StorageError> = stridelabs_gcp::validate_bucket_name;
    let _ = stridelabs_gcp::public_url_with;
    let _: stridelabs_gcp::ObjectNamePolicy = stridelabs_gcp::ObjectNamePolicy::Literal;

    // `exists` is an additive `async fn` returning whether, not a body: the
    // future's output type is its signature (never polled, nothing sent).
    fn yields_a_bool<F>(_: F)
    where
        F: std::future::Future<Output = Result<bool, StorageError>>,
    {
    }
    let gcs = GcsClient::emulator(reqwest::Client::new(), "localhost:4443", None);
    yields_a_bool(gcs.exists(BUCKET, OBJECT));

    assert_eq!(ObjectNamePolicy::default(), ObjectNamePolicy::Strict);
    assert_eq!(RetryPolicy::default(), RetryPolicy::disabled());
    let google = RetryPolicy::google_default();
    assert_eq!(
        (
            google.initial_delay,
            google.multiplier,
            google.max_delay,
            google.deadline,
            google.max_attempts
        ),
        (
            Duration::from_secs(1),
            2.0,
            Duration::from_secs(60),
            Duration::from_secs(120),
            None
        )
    );
    assert_eq!(RetryPolicy::disabled().deadline, Duration::ZERO);
    assert_eq!(
        RetryPolicy::disabled().with_deadline(Duration::from_secs(120)),
        google,
        "disabled is the default schedule with no time to use it"
    );
    const QUICK: RetryPolicy = RetryPolicy::google_default()
        .with_initial_delay(Duration::from_millis(100))
        .with_multiplier(1.5)
        .with_max_delay(Duration::from_secs(2))
        .with_deadline(Duration::from_secs(10))
        .with_max_attempts(4);
    assert_eq!((QUICK.multiplier, QUICK.max_attempts), (1.5, Some(4)));
}

/// Every operation's future is `Send`, so a service can spawn it: what each
/// attempt shares across its awaits (the status line it received) is an
/// atomic, never a `Cell`.
#[test]
fn every_operation_is_send() {
    fn send<T: Send>(_: &T) {}
    let gcs = GcsClient::emulator(reqwest::Client::new(), "localhost:4443", None);
    let options = UploadOptions::default().with_if_generation_match(0);
    send(&gcs.upload(BUCKET, OBJECT, Bytes::new(), "image/png"));
    send(&gcs.upload_with(BUCKET, OBJECT, Bytes::new(), "image/png", &options));
    send(&gcs.download(BUCKET, OBJECT));
    send(&gcs.delete(BUCKET, OBJECT));
    send(&gcs.exists(BUCKET, OBJECT));
    send(&gcs.bucket_reachable(BUCKET));
}

#[test]
fn a_client_debug_shows_the_name_policy_and_the_retry_policy() {
    let gcs = GcsClient::emulator(reqwest::Client::new(), "localhost:4443", None);
    let rendered = format!("{gcs:?}");
    assert!(
        rendered.contains("object_name_policy: Strict"),
        "{rendered}"
    );
    assert!(rendered.contains("deadline: 0ns"), "{rendered}");
    let gcs = gcs
        .with_object_name_policy(ObjectNamePolicy::Literal)
        .with_retry(RetryPolicy::google_default());
    let rendered = format!("{gcs:?}");
    for expected in [
        "object_name_policy: Literal",
        "retry: RetryPolicy { initial_delay: 1s, multiplier: 2.0, max_delay: 60s, deadline: 120s, max_attempts: None }",
    ] {
        assert!(rendered.contains(expected), "{expected}: {rendered}");
    }
}
