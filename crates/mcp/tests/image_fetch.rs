//! `ImageFetcher`: every case of Python `stridelabs-mcp`'s `test_fetch.py`,
//! with its exact messages (features `image-fetch` + `test-support`).
//!
//! Python fakes the server with an `httpx.MockTransport`; here every https
//! case goes over a real TLS connection to a raw HTTP/1.1 server on
//! `127.0.0.1`, with a certificate for `images.example.com` from a CA made
//! per test, admitted through stridelabs-http's `ssrf-test-support`
//! (`with_loopback_test_server`) next to the strict public-address policy. A
//! test resolver answers the name. The rejections that happen before any
//! connection — scheme, credentials, metadata names, IP literals, DNS
//! answers — need no server at all.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use stridelabs_mcp::image_fetch::{LoopbackTestServer, SsrfError};
use stridelabs_mcp::{ImageFetchError, ImageFetcher, ToolError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const PUBLIC_V4: &str = "93.184.216.34";
const PUBLIC_V6: &str = "2606:2800:220:1:248:1893:25c8:1946";
const HOST: &str = "images.example.com";

const MAX_BYTES: usize = 1_000_000;
const TOO_LARGE: &str = "The image is too large (max 1 MB).";

const SCHEME: &str = "Only https:// image URLs (or data: URIs) are allowed.";
const NOT_AN_IMAGE: &str =
    "URL did not return an image (Content-Type must be image/*; SVG is not supported).";
const UNSUPPORTED: &str = "The fetched content is not a supported image (JPEG, PNG, WebP, or GIF).";

/// A minimal PNG-magic payload (the sniffer checks magic bytes only).
fn png() -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    bytes.extend_from_slice(&[0; 32]);
    bytes
}

fn fetcher(max_bytes: usize) -> ImageFetcher {
    ImageFetcher::new(max_bytes, TOO_LARGE)
}

/// The message `source` is refused with, under `fetcher`.
async fn refusal(fetcher: &ImageFetcher, source: &str) -> String {
    match fetcher.fetch(source).await {
        Ok(bytes) => panic!("{source}: fetched {} bytes", bytes.len()),
        Err(error) => error.to_string(),
    }
}

fn answers(answers: &[&str]) -> Vec<IpAddr> {
    answers.iter().map(|a| a.parse().expect("an IP")).collect()
}

/// A fetcher whose resolver answers every name with `answers` (and that is
/// admitted to no server).
fn resolving(dns: &[&str]) -> ImageFetcher {
    let dns = answers(dns);
    fetcher(MAX_BYTES).with_resolver(move |_host: String, _port| {
        let dns = dns.clone();
        async move { io::Result::Ok(dns) }
    })
}

// --- a throwaway CA and a raw HTTP/1.1-over-TLS server ---------------------------

struct TestCa {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl TestCa {
    fn new() -> TestCa {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "stridelabs-mcp image test CA");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().expect("CA key");
        TestCa {
            issuer: CertifiedIssuer::self_signed(params, key).expect("self-signed CA"),
        }
    }

    fn leaf(&self, names: &[&str]) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
        let mut params = CertificateParams::new(names).expect("leaf params");
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let key = KeyPair::generate().expect("leaf key");
        let cert = params.signed_by(&key, &*self.issuer).expect("signed leaf");
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        (cert.der().clone(), key)
    }
}

/// The request head the server read.
#[derive(Debug, Clone)]
struct Seen {
    sni: Option<String>,
    headers: Vec<(String, String)>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// What the server answers: these bytes, after a delay.
#[derive(Clone)]
struct Reply {
    delay: Duration,
    bytes: Vec<u8>,
}

struct TlsServer {
    port: u16,
    ca_pem: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl TlsServer {
    /// A server whose certificate names `names` (DNS names or IPs),
    /// answering every request with `reply`.
    async fn start(names: &[&str], reply: Reply) -> TlsServer {
        let ca = TestCa::new();
        let (cert, key) = ca.leaf(names);
        // The aws-lc-rs provider named explicitly: this test binary installs
        // no process default, and must not need one.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server certificate");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((LOOPBACK, 0)).await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let seen = Arc::new(Mutex::new(Vec::new()));

        let recorded = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, reply, recorded) =
                    (acceptor.clone(), reply.clone(), Arc::clone(&recorded));
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let sni = tls.get_ref().1.server_name().map(str::to_owned);
                    if let Some(headers) = read_head(&mut tls).await {
                        recorded.lock().unwrap().push(Seen { sni, headers });
                        tokio::time::sleep(reply.delay).await;
                        let _ = tls.write_all(&reply.bytes).await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });

        TlsServer {
            port,
            ca_pem: ca.issuer.pem(),
            seen,
        }
    }

    fn url(&self, host: &str) -> String {
        format!("https://{host}:{}/cover.png", self.port)
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// A fetcher capped at `max_bytes`, whose resolver answers `dns`,
    /// admitted to this server's CA and loopback address alone.
    fn fetcher_with(&self, max_bytes: usize, dns: &[&str]) -> ImageFetcher {
        let dns = answers(dns);
        fetcher(max_bytes)
            .with_resolver(move |_host: String, _port| {
                let dns = dns.clone();
                async move { io::Result::Ok(dns) }
            })
            .with_loopback_test_server(
                LoopbackTestServer::new(LOOPBACK, self.ca_pem.as_bytes()).expect("loopback CA"),
            )
    }

    fn fetcher(&self) -> ImageFetcher {
        self.fetcher_with(MAX_BYTES, &["127.0.0.1"])
    }
}

async fn read_head<S: AsyncReadExt + Unpin>(stream: &mut S) -> Option<Vec<(String, String)>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 || buf.len() > 64 * 1024 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&buf);
    Some(
        text.split("\r\n")
            .skip(1)
            .take_while(|line| !line.is_empty())
            .filter_map(|line| line.split_once(':'))
            .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
            .collect(),
    )
}

fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Reply {
    let mut out = format!("HTTP/1.1 {status}\r\nconnection: close\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    Reply {
        delay: Duration::ZERO,
        bytes,
    }
}

fn image(content_type: &str, body: &[u8]) -> Reply {
    response(
        "200 OK",
        &[
            ("content-type", content_type),
            ("content-length", &body.len().to_string()),
        ],
        body,
    )
}

fn serve_png() -> Reply {
    image("image/png", &png())
}

fn base64(payload: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(payload)
}

fn data_uri(media_type: &str, payload: &[u8]) -> String {
    format!("data:{media_type};base64,{}", base64(payload))
}

// --- URL policy: refused before any DNS or network I/O -----------------------------

#[tokio::test]
async fn http_other_schemes_and_garbage_are_refused_naming_https() {
    let fetcher = fetcher(MAX_BYTES);
    for source in [
        "http://example.com/a.png",
        "ftp://example.com/a.png",
        "file:///etc/passwd",
        "gopher://example.com/",
        "not a url at all",
    ] {
        assert_eq!(refusal(&fetcher, source).await, SCHEME, "{source}");
    }
}

#[tokio::test]
async fn embedded_credentials_are_refused() {
    assert_eq!(
        refusal(&fetcher(MAX_BYTES), "https://user:pass@example.com/a.png").await,
        "URLs with embedded credentials are not allowed."
    );
}

#[tokio::test]
async fn metadata_hosts_are_refused() {
    let fetcher = fetcher(MAX_BYTES);
    for source in [
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://metadata.google.internal./a.png",
        "https://foo.metadata.google.internal/a.png",
        "https://metadata/computeMetadata/v1/",
    ] {
        assert_eq!(
            refusal(&fetcher, source).await,
            "That host is not allowed.",
            "{source}"
        );
    }
}

#[tokio::test]
async fn non_public_ip_literals_are_refused() {
    let fetcher = fetcher(MAX_BYTES);
    // Python's 19, in its order.
    for host in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "169.254.0.10",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "100.64.0.1",
        "[::1]",
        "[fc00::1]",
        "[fd12:3456::1]",
        "[fe80::1]",
        "[ff02::1]",
        "[::]",
        "[::ffff:127.0.0.1]",
        "[::ffff:169.254.169.254]",
        "[::ffff:10.0.0.1]",
    ] {
        assert_eq!(
            refusal(&fetcher, &format!("https://{host}/a.png")).await,
            "URL host is not a public address.",
            "{host}"
        );
    }
}

// --- DNS policy ---------------------------------------------------------------------

#[tokio::test]
async fn a_resolution_failure_or_an_empty_answer_is_a_clean_error() {
    let failing = fetcher(MAX_BYTES).with_resolver(|_host: String, _port| async {
        Err::<Vec<IpAddr>, _>(io::Error::other("NXDOMAIN"))
    });
    assert_eq!(
        refusal(&failing, "https://nxdomain.example.com/a.png").await,
        "Could not resolve the URL host."
    );
    assert_eq!(
        refusal(&resolving(&[]), "https://empty.example.com/a.png").await,
        "Could not resolve the URL host."
    );
}

#[tokio::test]
async fn any_non_public_answer_poisons_the_resolution() {
    // Python's 9 answer sets.
    for dns in [
        &["10.0.0.5"][..],
        &["127.0.0.1"],
        &["169.254.169.254"],
        &["fe80::1"],
        &["fd00::1"],
        &["::ffff:192.168.0.9"],
        &[PUBLIC_V4, "10.0.0.5"],
        &["10.0.0.5", PUBLIC_V4],
        &[PUBLIC_V6, "::1"],
    ] {
        assert_eq!(
            refusal(&resolving(dns), "https://rebind.example.com/a.png").await,
            "URL host resolves to a non-public address.",
            "{dns:?}"
        );
    }
}

// --- pinning, over a real TLS connection --------------------------------------------

#[tokio::test]
async fn an_image_comes_from_the_pinned_address_with_sni_host_and_accept_on_the_name() {
    let server = TlsServer::start(&[HOST], serve_png()).await;

    let bytes = server
        .fetcher()
        .fetch(&server.url(HOST))
        .await
        .expect("fetched");

    assert_eq!(bytes, png());
    let seen = server.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].sni.as_deref(), Some(HOST));
    assert_eq!(
        seen[0].header("host"),
        Some(format!("{HOST}:{}", server.port).as_str())
    );
    assert_eq!(seen[0].header("accept"), Some("image/*"));
    assert_eq!(seen[0].header("accept-encoding"), Some("identity"));
}

#[tokio::test]
async fn an_ip_literal_host_is_fetched_as_itself() {
    // Python's "public literal allowed": the literal passes the address
    // policy and is connected to as itself, with no DNS. A public address
    // cannot be served offline, so the literal is the test server's loopback
    // one, admitted by `with_loopback_test_server` as a public one is by the
    // policy (stridelabs-http's unit tests pin `93.184.216.34` public).
    let server = TlsServer::start(&["127.0.0.1"], serve_png()).await;
    let fetcher = server.fetcher_with(MAX_BYTES, &[]);

    let bytes = fetcher
        .fetch(&server.url("127.0.0.1"))
        .await
        .expect("fetched");

    assert_eq!(bytes, png());
    assert_eq!(server.seen()[0].sni, None, "no SNI for an IP literal");
}

#[tokio::test]
async fn ipv4_is_preferred_and_a_validated_address_pinned() {
    let server = TlsServer::start(&[HOST], serve_png()).await;
    // A public IPv6 first: pinning it would dial the internet, and fail.
    let fetcher = server.fetcher_with(MAX_BYTES, &[PUBLIC_V6, "127.0.0.1"]);

    assert_eq!(
        fetcher.fetch(&server.url(HOST)).await.expect("fetched"),
        png()
    );
}

// --- response policy ----------------------------------------------------------------

#[tokio::test]
async fn a_redirect_is_refused() {
    let server = TlsServer::start(
        &[HOST],
        response(
            "302 Found",
            &[
                ("location", "https://169.254.169.254/creds"),
                ("content-length", "0"),
            ],
            b"",
        ),
    )
    .await;
    assert_eq!(
        refusal(&server.fetcher(), &server.url(HOST)).await,
        "URL redirects are not allowed."
    );
}

#[tokio::test]
async fn a_non_200_is_refused_with_its_status() {
    let server = TlsServer::start(
        &[HOST],
        response("404 Not Found", &[("content-length", "4")], b"nope"),
    )
    .await;
    assert_eq!(
        refusal(&server.fetcher(), &server.url(HOST)).await,
        "Image fetch failed with HTTP 404."
    );
}

#[tokio::test]
async fn a_content_type_that_is_not_a_raster_image_is_refused() {
    for content_type in [
        "text/html",
        "image/svg+xml",
        "IMAGE/SVG+XML; charset=utf-8",
        "image/foo+xml",
        "application/octet-stream",
    ] {
        let server = TlsServer::start(&[HOST], image(content_type, &png())).await;
        assert_eq!(
            refusal(&server.fetcher(), &server.url(HOST)).await,
            NOT_AN_IMAGE,
            "{content_type:?}"
        );
    }
}

#[tokio::test]
async fn a_missing_content_type_is_refused() {
    let body = png();
    let server = TlsServer::start(
        &[HOST],
        response(
            "200 OK",
            &[("content-length", &body.len().to_string())],
            &body,
        ),
    )
    .await;
    assert_eq!(
        refusal(&server.fetcher(), &server.url(HOST)).await,
        NOT_AN_IMAGE
    );
}

#[tokio::test]
async fn the_content_type_is_read_case_insensitively_without_its_parameters() {
    let server = TlsServer::start(&[HOST], image("IMAGE/PNG ; charset=binary", &png())).await;
    assert_eq!(
        server
            .fetcher()
            .fetch(&server.url(HOST))
            .await
            .expect("fetched"),
        png()
    );
}

#[tokio::test]
async fn a_lying_content_type_fails_the_magic_sniff() {
    for body in [
        &b"<html><body>hi</body></html>"[..],
        b"<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"/>",
    ] {
        let server = TlsServer::start(&[HOST], image("image/png", body)).await;
        assert_eq!(
            refusal(&server.fetcher(), &server.url(HOST)).await,
            UNSUPPORTED
        );
    }
}

#[tokio::test]
async fn a_declared_oversize_is_refused_before_the_body() {
    let server = TlsServer::start(
        &[HOST],
        response(
            "200 OK",
            &[("content-type", "image/png"), ("content-length", "5000")],
            &[b'x'; 10],
        ),
    )
    .await;
    let error = server
        .fetcher_with(100, &["127.0.0.1"])
        .fetch(&server.url(HOST))
        .await
        .unwrap_err();
    assert_eq!(error, ImageFetchError::TooLarge(TOO_LARGE.to_owned()));
}

#[tokio::test]
async fn the_streaming_cap_aborts_a_body_that_keeps_going() {
    // Python's "lying Content-Length": over real HTTP/1.1 an understated
    // length truncates the body (hyper frames by it), so the stream that
    // keeps going is a chunked one with no length — 640 bytes against a
    // 100-byte cap.
    let mut body = Vec::new();
    for _ in 0..10 {
        body.extend_from_slice(b"40\r\n");
        body.extend_from_slice(&[b'x'; 64]);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");
    let server = TlsServer::start(
        &[HOST],
        response(
            "200 OK",
            &[
                ("content-type", "image/png"),
                ("transfer-encoding", "chunked"),
            ],
            &body,
        ),
    )
    .await;
    assert_eq!(
        refusal(&server.fetcher_with(100, &["127.0.0.1"]), &server.url(HOST)).await,
        TOO_LARGE
    );
}

#[tokio::test]
async fn the_wall_clock_budget_is_enforced() {
    // The server answers 100 times later than the budget, so a stalled
    // scheduler cannot let the answer win.
    let mut slow = serve_png();
    slow.delay = Duration::from_secs(5);
    let server = TlsServer::start(&[HOST], slow).await;
    let fetcher = server
        .fetcher_with(MAX_BYTES, &["127.0.0.1"])
        .with_timeout(Duration::from_millis(50));

    assert_eq!(
        refusal(&fetcher, &server.url(HOST)).await,
        "Image fetch timed out."
    );
}

#[tokio::test]
async fn a_network_error_is_a_clean_message() {
    // Connection refused: a port nothing listens on, behind a valid pin.
    let closed = TcpListener::bind((LOOPBACK, 0)).await.expect("bind");
    let port = closed.local_addr().expect("addr").port();
    drop(closed);
    let server = TlsServer::start(&[HOST], serve_png()).await;
    let refused = refusal(&server.fetcher(), &format!("https://{HOST}:{port}/a.png")).await;
    assert_eq!(refused, "Could not fetch the image URL.");
    assert!(!refused.contains("127.0.0.1"), "no internal detail");

    // A certificate for another name.
    let other = TlsServer::start(&["other.example.com"], serve_png()).await;
    assert_eq!(
        refusal(&other.fetcher(), &other.url(HOST)).await,
        "Could not fetch the image URL."
    );
}

#[tokio::test]
async fn a_compressed_response_is_refused_not_decoded() {
    let body = png();
    let server = TlsServer::start(
        &[HOST],
        response(
            "200 OK",
            &[
                ("content-type", "image/png"),
                ("content-encoding", "gzip"),
                ("content-length", &body.len().to_string()),
            ],
            &body,
        ),
    )
    .await;
    assert_eq!(
        refusal(&server.fetcher(), &server.url(HOST)).await,
        "Could not fetch the image URL."
    );
}

// --- data: URIs: no network at all ------------------------------------------------

#[tokio::test]
async fn a_data_uri_decodes_and_its_scheme_is_case_insensitive() {
    let fetcher = fetcher(MAX_BYTES);
    let uri = data_uri("image/png", &png());

    for source in [
        uri.clone(),
        uri.replacen("data:", "DATA:", 1),
        uri.replacen("data:", "DaTa:", 1),
    ] {
        assert_eq!(fetcher.fetch(&source).await.expect("decoded"), png());
    }
}

#[tokio::test]
async fn a_whitespace_wrapped_payload_decodes() {
    let encoded = base64(&png());
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(40)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect();
    let fetcher = fetcher(MAX_BYTES);

    // `\x1c` too: Python's `str.split()` counts it as whitespace.
    for separator in ["\n", "\r\n", " ", "\t", "\x1c"] {
        let uri = format!("data:image/png;base64,{}", lines.join(separator));
        assert_eq!(
            fetcher.fetch(&uri).await.expect("decoded"),
            png(),
            "{separator:?}"
        );
    }
}

#[tokio::test]
async fn the_media_type_and_parameters_are_read_as_python_reads_them() {
    let fetcher = fetcher(MAX_BYTES);
    let payload = base64(&png());
    for header in [
        "data:IMAGE/PNG;base64",
        "data: image/png ;charset=binary; BASE64 ",
        "data:image/webp;name=x.png;base64",
    ] {
        let uri = format!("{header},{payload}");
        assert_eq!(
            fetcher.fetch(&uri).await.expect("decoded"),
            png(),
            "{header}"
        );
    }
}

#[tokio::test]
async fn malformed_data_uris_are_refused_with_pythons_messages() {
    let fetcher = fetcher(MAX_BYTES);
    let hello = base64(b"hello");
    let svg = base64(b"<svg/>");
    let media =
        "data: URI must declare an image media type (JPEG, PNG, WebP, or GIF; SVG is not supported).";

    for (source, expected) in [
        (
            "data:image/png,rawbytes".to_owned(),
            "data: URIs must be base64-encoded (data:image/...;base64,...).",
        ),
        (
            "data:image/png;base64".to_owned(),
            "Invalid data: URI (missing the comma before the payload).",
        ),
        (format!("data:text/plain;base64,{hello}"), media),
        (format!("data:image/svg+xml;base64,{svg}"), media),
        (format!("data:image/x-xml;base64,{hello}"), media),
        (
            "data:image/png;base64,!!!not-base64!!!".to_owned(),
            "data: URI payload is not valid base64.",
        ),
        (
            "data:image/png;base64,QUJ".to_owned(),
            "data: URI payload is not valid base64.",
        ),
        (
            "data:image/png;base64,".to_owned(),
            "data: URI payload is empty.",
        ),
    ] {
        assert_eq!(refusal(&fetcher, &source).await, expected, "{source}");
    }
}

#[tokio::test]
async fn an_oversize_data_uri_is_refused_before_and_after_decoding() {
    // 64 bytes encode to 88 characters, over 16 * 4 / 3 + 4 = 25: refused
    // before decoding.
    let uri = data_uri("image/png", &[b'x'; 64]);
    assert_eq!(
        fetcher(16).fetch(&uri).await,
        Err(ImageFetchError::TooLarge(TOO_LARGE.to_owned()))
    );

    // 18 bytes encode to 24 characters, within that bound, and decode past
    // the 16-byte cap: refused after decoding.
    let mut png18 = png();
    png18.truncate(18);
    let uri = data_uri("image/png", &png18);
    assert_eq!(
        fetcher(16).fetch(&uri).await,
        Err(ImageFetchError::TooLarge(TOO_LARGE.to_owned()))
    );
    assert_eq!(fetcher(18).fetch(&uri).await.expect("at the cap"), png18);
}

#[tokio::test]
async fn a_payload_lying_about_its_media_type_fails_the_sniff() {
    let uri = data_uri("image/png", b"<html>not an image</html>");
    assert_eq!(refusal(&fetcher(MAX_BYTES), &uri).await, UNSUPPORTED);
}

// --- the magic sniff ------------------------------------------------------------------

#[tokio::test]
async fn the_four_formats_pass_the_sniff() {
    let fetcher = fetcher(MAX_BYTES);
    for prefix in [
        &b"\xff\xd8\xff\xe0"[..],
        b"\x89PNG\r\n\x1a\n",
        b"GIF89a",
        b"GIF87a",
        b"RIFF\x00\x00\x00\x00WEBP",
    ] {
        let mut payload = prefix.to_vec();
        payload.extend_from_slice(&[0; 16]);
        let uri = data_uri("image/png", &payload);
        assert_eq!(
            fetcher.fetch(&uri).await.expect("sniffed"),
            payload,
            "{prefix:?}"
        );
    }
}

#[tokio::test]
async fn riff_without_webp_fails_the_sniff() {
    let mut wav = b"RIFF\x00\x00\x00\x00WAVE".to_vec();
    wav.extend_from_slice(&[0; 16]);
    assert_eq!(
        refusal(&fetcher(MAX_BYTES), &data_uri("image/png", &wav)).await,
        UNSUPPORTED
    );
}

// --- the tool boundary ------------------------------------------------------------------

#[tokio::test]
async fn a_refusal_is_a_user_error_for_the_model() {
    let error = fetcher(MAX_BYTES)
        .fetch("http://example.com/a.png")
        .await
        .unwrap_err();

    assert_eq!(
        error,
        ImageFetchError::Fetch(SsrfError::SchemeNotAllowed(SCHEME.to_owned()))
    );
    assert_eq!(ToolError::from(error), ToolError::user(SCHEME));
}
