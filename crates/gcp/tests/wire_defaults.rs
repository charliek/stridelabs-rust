//! What a default client puts on the wire, byte for byte: every GCS
//! operation and a Vertex call, refresh off, read off a raw socket. The
//! expected requests were recorded by running this same file on v0.8.0
//! (9a1b3e5), so a change to how requests are built (the closure that
//! rebuilds them, the body as `Bytes`, Vertex's JSON serialized once) cannot
//! change a header, its order or a body byte unnoticed. Only the server's
//! `host:port` and the multipart boundary's random bits are normalized, the
//! latter only once the header and every delimiter are shown to share one
//! boundary.
//!
//! It uses only v0.8.0's API, so it still compiles there.
//!
//! The client it injects has reqwest's decoders switched off
//! ([`wire_client`]): the requests were recorded with none compiled in, and
//! this workspace's test build now compiles the gzip one (stridelabs-http's
//! dev-dependency, for its proxy tests), whose `Accept-Encoding` would be
//! the injected client's, not this crate's.

mod common;

use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use common::*;
use stridelabs_gcp::storage::{GcsClient, UploadOptions};
use wiremock::MockServer;

const ANSWER: &[u8] =
    b"HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncontent-length: 4\r\n\r\nPNG!";

/// [`never_retrying`] with reqwest's four decoders off, as they were (not
/// compiled) when the expected requests were recorded. `no_*` exists
/// whatever reqwest's features, so this compiles on v0.8.0 too.
fn wire_client() -> reqwest::Client {
    reqwest::Client::builder()
        .retry(reqwest::retry::never())
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .build()
        .unwrap()
}

/// What every multipart boundary starts with; 32 random hex digits follow.
const BOUNDARY_PREFIX: &[u8] = b"stridelabs-gcp-";

/// `raw` with its multipart boundary's random digits written `RANDOM`, once
/// that is shown to be ONE boundary: the one its `content-type` header
/// declares, which every `stridelabs-gcp-` delimiter in the body must be
/// (and there must be delimiters). A request that declares no boundary must
/// carry none. Normalizing each occurrence on its own would let a header and
/// a body that disagree both read `RANDOM`.
fn without_boundary(raw: &[u8]) -> Result<Vec<u8>, String> {
    const DECLARED: &[u8] = b"\r\ncontent-type: multipart/related; boundary=";
    let boundary_at = |at: usize| -> Result<&[u8], String> {
        let candidate = raw
            .get(at..at + BOUNDARY_PREFIX.len() + 32)
            .ok_or("a boundary cut short")?;
        let random = &candidate[BOUNDARY_PREFIX.len()..];
        if candidate.starts_with(BOUNDARY_PREFIX)
            && random
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            Ok(candidate)
        } else {
            Err(format!("not a boundary: {}", escaped(candidate)))
        }
    };
    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("no end of the head")?;
    let occurrences: Vec<usize> = (0..raw.len())
        .filter(|&at| raw[at..].starts_with(BOUNDARY_PREFIX))
        .collect();
    let declared = raw[..head_end]
        .windows(DECLARED.len())
        .position(|window| window == DECLARED);
    let Some(declared) = declared else {
        return if occurrences.is_empty() {
            Ok(raw.to_vec())
        } else {
            Err("a boundary in a request that declares none".to_owned())
        };
    };
    let boundary = boundary_at(declared + DECLARED.len())?;
    if raw
        .get(declared + DECLARED.len() + boundary.len()..)
        .map(|rest| rest.starts_with(b"\r\n"))
        != Some(true)
    {
        return Err("the declared boundary does not end its header line".to_owned());
    }
    let delimiters: Vec<usize> = occurrences
        .into_iter()
        .filter(|&at| at > head_end)
        .collect();
    if delimiters.is_empty() {
        return Err("a declared boundary the body never uses".to_owned());
    }
    for at in delimiters {
        let delimiter = boundary_at(at)?;
        if delimiter != boundary {
            return Err(format!(
                "the body delimits with {} where the header declares {}",
                escaped(delimiter),
                escaped(boundary)
            ));
        }
    }
    Ok(replace_bytes(raw, boundary, b"stridelabs-gcp-RANDOM"))
}

/// The normalization proves the boundary is one and the same, rather than
/// assuming it: a header and a body that disagree are refused.
#[test]
fn a_boundary_the_header_and_the_body_disagree_on_is_refused() {
    let request = |declared: &str, used: &str| {
        format!(
            "POST /o HTTP/1.1\r\ncontent-type: multipart/related; boundary=stridelabs-gcp-{declared}\r\n\
             host: HOST\r\n\r\n--stridelabs-gcp-{used}\r\nmeta\r\n--stridelabs-gcp-{used}\r\n\
             media\r\n--stridelabs-gcp-{used}--"
        )
        .into_bytes()
    };
    let (a, b) = ("a".repeat(32), "b".repeat(32));

    assert_eq!(
        without_boundary(&request(&a, &a)).unwrap(),
        request("RANDOM", "RANDOM"),
        "one boundary throughout: normalized"
    );
    let refused = without_boundary(&request(&b, &a)).unwrap_err();
    assert!(refused.contains("where the header declares"), "{refused}");
    // One delimiter out of three is enough to refuse.
    let mut one_off = request(&a, &a);
    let last = one_off.len() - 34;
    one_off[last..last + 32].copy_from_slice(b.as_bytes());
    assert!(without_boundary(&one_off).is_err());
    // A body boundary with nothing declared, and a declared one never used.
    let undeclared = b"GET /o HTTP/1.1\r\n\r\n--stridelabs-gcp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert!(without_boundary(undeclared).is_err());
    let unused = format!(
        "POST /o HTTP/1.1\r\ncontent-type: multipart/related; boundary=stridelabs-gcp-{a}\r\n\r\nbody"
    );
    assert!(without_boundary(unused.as_bytes()).is_err());
    // No multipart at all: unchanged.
    let plain = b"DELETE /o HTTP/1.1\r\nhost: HOST\r\n\r\n";
    assert_eq!(without_boundary(plain).unwrap(), plain);
}

/// The requests `raw` received, normalized, each printed as a byte-string
/// literal (what the expectations below were pasted from).
fn sent(raw: &RawServer) -> Vec<Vec<u8>> {
    let sent: Vec<Vec<u8>> = raw
        .requests()
        .iter()
        .map(|request| {
            without_boundary(&normalized(request, &raw.base_url))
                .unwrap_or_else(|why| panic!("{why}"))
        })
        .collect();
    for (n, request) in sent.iter().enumerate() {
        println!("--- request {n}\nb\"{}\"", escaped(request));
    }
    sent
}

async fn tokens(server: &MockServer) -> stridelabs_gcp::TokenProvider {
    mount_metadata_token(server, "wire-token").await;
    routed(
        stridelabs_gcp::TokenProvider::metadata_server(never_retrying(), &[]),
        server,
    )
    .with_quota_project(Some("quota-project".into()))
}

/// Recorded on v0.8.0: media upload, multipart upload, download, delete.
const GCS_EXPECTED: [&[u8]; 4] = [
    b"POST /upload/storage/v1/b/img-bucket/o?uploadType=media&name=a%2Fb%20c.png HTTP/1.1\r\ncontent-type: image/png\r\nauthorization: Bearer wire-token\r\nx-goog-user-project: quota-project\r\naccept: */*\r\nhost: HOST\r\ncontent-length: 14\r\n\r\n\x89PNG\r\n\x1a\n\x00--x\r\n",
    b"POST /upload/storage/v1/b/img-bucket/o?uploadType=multipart&ifGenerationMatch=0 HTTP/1.1\r\ncontent-type: multipart/related; boundary=stridelabs-gcp-RANDOM\r\nauthorization: Bearer wire-token\r\nx-goog-user-project: quota-project\r\naccept: */*\r\nhost: HOST\r\ncontent-length: 369\r\n\r\n--stridelabs-gcp-RANDOM\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{\"name\":\"a/b c.png\",\"contentType\":\"image/png\",\"customTime\":\"2025-10-09T08:53:20Z\",\"cacheControl\":\"private, max-age=86400\"}\r\n--stridelabs-gcp-RANDOM\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n\x00--x\r\n\r\n--stridelabs-gcp-RANDOM--",
    b"GET /storage/v1/b/img-bucket/o/a%2Fb%20c.png?alt=media HTTP/1.1\r\nauthorization: Bearer wire-token\r\nx-goog-user-project: quota-project\r\naccept: */*\r\nhost: HOST\r\n\r\n",
    b"DELETE /storage/v1/b/img-bucket/o/a%2Fb%20c.png HTTP/1.1\r\nauthorization: Bearer wire-token\r\nx-goog-user-project: quota-project\r\naccept: */*\r\nhost: HOST\r\n\r\n",
];

#[tokio::test]
async fn a_default_gcs_client_sends_v080s_requests_byte_for_byte() {
    let token_server = MockServer::start().await;
    let raw = RawServer::start(|_, _| RawReply::Full(ANSWER.to_vec())).await;
    let gcs = GcsClient::new(wire_client(), tokens(&token_server).await)
        .with_base_url(&raw.base_url)
        .with_timeout(Duration::from_secs(20));
    let media = Bytes::from_static(b"\x89PNG\r\n\x1a\n\0--x\r\n");

    gcs.upload("img-bucket", "a/b c.png", media.clone(), "image/png")
        .await
        .unwrap();
    gcs.upload_with(
        "img-bucket",
        "a/b c.png",
        media,
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

    let sent = sent(&raw);
    assert_eq!(sent, GCS_EXPECTED);
}

#[cfg(feature = "vertex")]
/// Recorded on v0.8.0.
const VERTEX_EXPECTED: &[u8] = b"POST /v1beta1/projects/test-project/locations/global/publishers/google/models/m:generateContent HTTP/1.1\r\nauthorization: Bearer wire-token\r\nx-goog-user-project: quota-project\r\ncontent-type: application/json\r\naccept: */*\r\nhost: HOST\r\ncontent-length: 181\r\n\r\n{\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":\"make it \\\"blue\\\" \xc3\xa9\"},{\"inlineData\":{\"mimeType\":\"image/png\",\"data\":\"iVBORw==\"}}]}],\"generationConfig\":{\"responseModalities\":[\"IMAGE\"]}}";

#[cfg(feature = "vertex")]
#[tokio::test]
async fn a_default_vertex_client_sends_v080s_request_byte_for_byte() {
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
        wire_client(),
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

    assert_eq!(sent(&raw), [VERTEX_EXPECTED]);
}
