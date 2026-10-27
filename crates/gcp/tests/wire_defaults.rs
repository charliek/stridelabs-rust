//! What a default client puts on the wire, read off a raw socket: for every
//! GCS operation and a Vertex call, the method, the path and query, the
//! headers that carry meaning (the bearer, the quota project, the content
//! type) and the body. What reqwest adds on its own (`accept`, `host`,
//! `content-length`) and the header order are the transport's, so they are
//! not asserted — except a media upload's `content-length`, which the client
//! sets by hand (an empty body would otherwise carry none).

mod common;

use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use common::*;
use stridelabs_gcp::storage::{GcsClient, UploadOptions};
use wiremock::MockServer;

const ANSWER: &[u8] =
    b"HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncontent-length: 4\r\n\r\nPNG!";

/// One request as the server received it.
struct Received {
    line: String,
    /// Lower-cased names, values as sent.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Received {
    fn parse(raw: &[u8]) -> Received {
        let head_end = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("a whole head");
        let head = std::str::from_utf8(&raw[..head_end]).expect("an ASCII head");
        let headers = head
            .split("\r\n")
            .skip(1)
            .map(|line| {
                let (name, value) = line.split_once(':').expect("a header line");
                (name.to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect();
        Received {
            line: request_line(raw),
            headers,
            body: request_body(raw).to_vec(),
        }
    }

    /// The one value of header `name`, or `None`; sent twice is a failure.
    fn header(&self, name: &str) -> Option<&str> {
        let mut values = self
            .headers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, value)| value.as_str());
        let value = values.next();
        assert!(values.next().is_none(), "{name} sent twice: {}", self.line);
        value
    }

    /// The request line, the bearer and quota project every call carries,
    /// and the content type.
    fn assert_call(&self, line: &str, content_type: Option<&str>) {
        assert_eq!(self.line, line);
        assert_eq!(
            self.header("authorization"),
            Some("Bearer wire-token"),
            "{line}"
        );
        assert_eq!(
            self.header("x-goog-user-project"),
            Some("quota-project"),
            "{line}"
        );
        assert_eq!(self.header("content-type"), content_type, "{line}");
    }
}

fn received(raw: &RawServer) -> Vec<Received> {
    raw.requests().iter().map(|r| Received::parse(r)).collect()
}

async fn tokens(server: &MockServer) -> stridelabs_gcp::TokenProvider {
    mount_metadata_token(server, "wire-token").await;
    routed(
        stridelabs_gcp::TokenProvider::metadata_server(never_retrying(), &[]),
        server,
    )
    .with_quota_project(Some("quota-project".into()))
}

#[tokio::test]
async fn a_default_gcs_client_sends_each_operations_request() {
    let token_server = MockServer::start().await;
    let raw = RawServer::start(|_, _| RawReply::Full(ANSWER.to_vec())).await;
    let gcs = GcsClient::new(never_retrying(), tokens(&token_server).await)
        .with_base_url(&raw.base_url)
        .with_timeout(Duration::from_secs(20));
    let media = Bytes::from_static(b"\x89PNG\r\n\x1a\n\0--x\r\n");

    gcs.upload("img-bucket", "a/b c.png", media.clone(), "image/png")
        .await
        .unwrap();
    gcs.upload_with(
        "img-bucket",
        "a/b c.png",
        media.clone(),
        "image/png",
        &UploadOptions::default()
            .with_if_generation_match(0)
            .with_cache_control("private, max-age=86400")
            .with_custom_time(UNIX_EPOCH + Duration::from_secs(1_760_000_000)),
    )
    .await
    .unwrap();
    assert!(gcs
        .download("img-bucket", "a/b c.png")
        .await
        .unwrap()
        .is_some());
    assert!(gcs.delete("img-bucket", "a/b c.png").await.unwrap());
    assert!(gcs.exists("img-bucket", "a/b c.png").await.unwrap());
    gcs.bucket_reachable("img-bucket").await.unwrap();

    let sent = received(&raw);
    let [media_upload, multipart, download, delete, exists, list] = &sent[..] else {
        panic!("{} requests", sent.len());
    };

    media_upload.assert_call(
        "POST /upload/storage/v1/b/img-bucket/o?uploadType=media&name=a%2Fb%20c.png HTTP/1.1",
        Some("image/png"),
    );
    assert_eq!(media_upload.body, media);

    // One boundary, declared in the header and delimiting the body.
    let content_type = multipart.header("content-type").unwrap();
    let boundary = content_type
        .strip_prefix("multipart/related; boundary=")
        .expect("a multipart/related content type");
    let random = boundary.strip_prefix("stridelabs-gcp-").unwrap();
    assert!(
        random.len() == 32 && random.bytes().all(|b| b.is_ascii_hexdigit()),
        "{boundary}"
    );
    multipart.assert_call(
        "POST /upload/storage/v1/b/img-bucket/o?uploadType=multipart&ifGenerationMatch=0 HTTP/1.1",
        Some(content_type),
    );
    let mut expected = format!(
        "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n\
         {{\"name\":\"a/b c.png\",\"contentType\":\"image/png\",\
         \"customTime\":\"2025-10-09T08:53:20Z\",\"cacheControl\":\"private, max-age=86400\"}}\r\n\
         --{boundary}\r\nContent-Type: image/png\r\n\r\n"
    )
    .into_bytes();
    expected.extend_from_slice(&media);
    expected.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
    assert_eq!(multipart.body, expected);

    download.assert_call(
        "GET /storage/v1/b/img-bucket/o/a%2Fb%20c.png?alt=media HTTP/1.1",
        None,
    );
    delete.assert_call(
        "DELETE /storage/v1/b/img-bucket/o/a%2Fb%20c.png HTTP/1.1",
        None,
    );
    exists.assert_call(
        "GET /storage/v1/b/img-bucket/o/a%2Fb%20c.png?fields=name HTTP/1.1",
        None,
    );
    list.assert_call("GET /storage/v1/b/img-bucket/o?maxResults=1 HTTP/1.1", None);
    for request in [download, delete, exists, list] {
        assert!(request.body.is_empty(), "{}", request.line);
    }
}

/// A media upload states its length, an empty one included, and states it
/// once. hyper writes no `Content-Length` for an empty body, and over
/// HTTP/1.1 Google's front end answers a `POST` without one with a 411, so
/// the length is set by hand; hyper keeps it and adds none of its own. The
/// checksum-only `upload_with` is the same media upload.
#[tokio::test]
async fn a_media_upload_states_its_length_once_an_empty_one_included() {
    let token_server = MockServer::start().await;
    let raw = RawServer::start(|_, _| RawReply::Full(ANSWER.to_vec())).await;
    let gcs = GcsClient::new(never_retrying(), tokens(&token_server).await)
        .with_base_url(&raw.base_url)
        .with_timeout(Duration::from_secs(20));
    let uploads = [Bytes::new(), Bytes::from_static(b"\x89PNG")];

    for media in &uploads {
        gcs.upload("img-bucket", "a.png", media.clone(), "image/png")
            .await
            .unwrap();
        gcs.upload_with(
            "img-bucket",
            "a.png",
            media.clone(),
            "image/png",
            &UploadOptions::default().with_crc32c(0),
        )
        .await
        .unwrap();
    }

    let sent = received(&raw);
    assert_eq!(sent.len(), 2 * uploads.len());
    for (request, media) in sent.iter().zip(uploads.iter().flat_map(|m| [m, m])) {
        request.assert_call(
            "POST /upload/storage/v1/b/img-bucket/o?uploadType=media&name=a.png HTTP/1.1",
            Some("image/png"),
        );
        // `header` fails on a field sent twice.
        let length = media.len().to_string();
        assert_eq!(
            request.header("content-length"),
            Some(length.as_str()),
            "{} bytes",
            media.len()
        );
        assert_eq!(request.header("transfer-encoding"), None);
        assert_eq!(request.body, *media);
    }
}

#[cfg(feature = "vertex")]
#[tokio::test]
async fn a_default_vertex_client_sends_the_request_as_json() {
    use serde_json::{json, Value};
    use stridelabs_gcp::vertex::{GenerateContentRequest, GenerationConfig, Part, VertexClient};

    let token_server = MockServer::start().await;
    let raw = RawServer::start(|_, _| {
        RawReply::Full(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}"
                .to_vec(),
        )
    })
    .await;
    let vertex = VertexClient::new(
        never_retrying(),
        tokens(&token_server).await,
        "test-project",
        "global",
    )
    .unwrap()
    .with_base_url(&raw.base_url);
    let request = GenerateContentRequest::user(vec![
        Part::from_text("make it \"blue\" \u{e9}"),
        Part::from_bytes("image/png", b"\x89PNG".to_vec()),
    ])
    .with_generation_config(GenerationConfig::response_modalities(["IMAGE"]));

    vertex.generate_content("m", &request).await.unwrap();

    let sent = received(&raw);
    let [call] = &sent[..] else {
        panic!("{} requests", sent.len());
    };
    call.assert_call(
        "POST /v1beta1/projects/test-project/locations/global/publishers/google/models/m:generateContent HTTP/1.1",
        Some("application/json"),
    );
    let body: Value = serde_json::from_slice(&call.body).unwrap();
    assert_eq!(
        body,
        json!({
            "contents": [{
                "role": "user",
                "parts": [
                    {"text": "make it \"blue\" \u{e9}"},
                    {"inlineData": {"mimeType": "image/png", "data": "iVBORw=="}},
                ],
            }],
            "generationConfig": {"responseModalities": ["IMAGE"]},
        })
    );
}
