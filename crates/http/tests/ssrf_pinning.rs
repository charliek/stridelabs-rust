//! The pinning, proven against a real TLS server on loopback.
//!
//! The unit tests in `src/ssrf` cover every rejection that happens before a
//! connection. These cover what only a connection can show: that the request
//! goes to the validated address and nowhere else, that SNI, certificate
//! verification and the `Host` header stay on the normalized host name, that
//! redirects re-run the whole policy per hop, and how the body cap, the
//! budget and transport failures surface.
//!
//! The server is a few dozen lines of raw HTTP/1.1 over `tokio-rustls`, with
//! certificates for made-up `.test` names (RFC 6761: never in real DNS) from
//! a CA generated per test. It listens on `127.0.0.1` only, and its names
//! resolve nowhere — so a request that reaches it at all went to the pinned
//! address. Every policy here admits that one address through
//! `with_loopback_test_server`, next to the strict public-address policy,
//! never instead of it.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http::HeaderValue;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use stridelabs_http::ssrf::{
    fetch_public, FetchPolicy, HostResolver, LoopbackTestServer, LoopbackTestServerError, SsrfError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n-not-really-a-png";

// --- a throwaway CA ------------------------------------------------------

struct TestCa {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl TestCa {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "stridelabs-http ssrf test CA");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().expect("CA key");
        Self {
            issuer: CertifiedIssuer::self_signed(params, key).expect("self-signed CA"),
        }
    }

    fn pem(&self) -> String {
        self.issuer.pem()
    }

    /// A server certificate for `names` (DNS names or IP addresses).
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

// --- the server ----------------------------------------------------------

/// One request the server read.
#[derive(Debug, Clone)]
struct Seen {
    /// Which of this server's TCP connections it arrived on, from 0.
    connection: usize,
    /// The TLS SNI the client sent (`None` for an IP-literal URL).
    sni: Option<String>,
    path: String,
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

/// What the server does with a request.
enum Reply {
    /// Write these bytes and close.
    Send(Vec<u8>),
    /// Write these bytes and keep the connection for the next request — a
    /// persistent HTTP/1.1 connection a pooling client could reuse.
    KeepAlive(Vec<u8>),
    /// Wait, then write these bytes and close.
    After(Duration, Vec<u8>),
    /// Write these bytes, then hold the connection open forever.
    SendThenHang(Vec<u8>),
}

type Responder = dyn Fn(&Seen) -> Reply + Send + Sync;

struct TlsServer {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    failed_handshakes: Arc<AtomicUsize>,
}

impl TlsServer {
    async fn start(
        ca: &TestCa,
        names: &[&str],
        respond: impl Fn(&Seen) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind((LOOPBACK, 0)).await.expect("bind");
        Self::start_on(ca, names, listener, respond)
    }

    /// Serve on an already-bound `listener`.
    fn start_on(
        ca: &TestCa,
        names: &[&str],
        listener: TcpListener,
        respond: impl Fn(&Seen) -> Reply + Send + Sync + 'static,
    ) -> Self {
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
        let port = listener.local_addr().expect("local addr").port();

        let seen = Arc::new(Mutex::new(Vec::new()));
        let failed_handshakes = Arc::new(AtomicUsize::new(0));
        let respond: Arc<Responder> = Arc::new(respond);
        let (seen_, failed_) = (Arc::clone(&seen), Arc::clone(&failed_handshakes));
        tokio::spawn(async move {
            for connection in 0.. {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, respond) = (acceptor.clone(), Arc::clone(&respond));
                let (seen, failed) = (Arc::clone(&seen_), Arc::clone(&failed_));
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        failed.fetch_add(1, Ordering::SeqCst);
                        return;
                    };
                    let sni = tls.get_ref().1.server_name().map(str::to_owned);
                    // One request per turn; only `KeepAlive` takes another.
                    while let Some(request) = read_head(&mut tls, connection, sni.clone()).await {
                        seen.lock().unwrap().push(request.clone());
                        match respond(&request) {
                            Reply::Send(bytes) => {
                                let _ = tls.write_all(&bytes).await;
                                let _ = tls.shutdown().await;
                                return;
                            }
                            Reply::KeepAlive(bytes) => {
                                let _ = tls.write_all(&bytes).await;
                                let _ = tls.flush().await;
                            }
                            Reply::After(delay, bytes) => {
                                tokio::time::sleep(delay).await;
                                let _ = tls.write_all(&bytes).await;
                                let _ = tls.shutdown().await;
                                return;
                            }
                            Reply::SendThenHang(bytes) => {
                                let _ = tls.write_all(&bytes).await;
                                let _ = tls.flush().await;
                                std::future::pending::<()>().await;
                            }
                        }
                    }
                });
            }
        });
        Self {
            port,
            seen,
            failed_handshakes,
        }
    }

    fn url(&self, host: &str, path: &str) -> String {
        format!("https://{host}:{}{path}", self.port)
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

/// Read one request head (request line + headers).
async fn read_head<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    connection: usize,
    sni: Option<String>,
) -> Option<Seen> {
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
    let mut lines = text.split("\r\n");
    let path = lines.next()?.split(' ').nth(1)?.to_owned();
    let headers = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Some(Seen {
        connection,
        sni,
        path,
        headers,
    })
}

fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let close = [("connection", "close")];
    raw_response(status, &[&close[..], headers].concat(), body)
}

/// A response that leaves the connection open: no `Connection: close`, so
/// HTTP/1.1's default — persistent — applies.
fn persistent_response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    raw_response(status, headers, body)
}

fn raw_response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

fn ok_png() -> Reply {
    Reply::Send(response(
        "200 OK",
        &[
            ("content-type", "image/png"),
            ("content-length", &PNG.len().to_string()),
        ],
        PNG,
    ))
}

fn redirect(status: &str, location: &str) -> Reply {
    Reply::Send(response(
        status,
        &[("location", location), ("content-length", "0")],
        b"",
    ))
}

fn chunked(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for chunk in chunks {
        body.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        body.extend_from_slice(chunk);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");
    response(
        "200 OK",
        &[
            ("content-type", "image/png"),
            ("transfer-encoding", "chunked"),
        ],
        &body,
    )
}

// --- the client side -------------------------------------------------------

type Calls = Arc<Mutex<Vec<(String, u16)>>>;

/// A resolver that records each `(host, port)` it is asked and answers
/// `answer(host, call_index)`.
fn recording(
    answer: impl Fn(&str, usize) -> io::Result<Vec<IpAddr>> + Send + Sync + 'static,
) -> (impl HostResolver + 'static, Calls) {
    let calls: Calls = Arc::default();
    let seen = Arc::clone(&calls);
    let resolver = move |host: String, port: u16| {
        let index = {
            let mut calls = seen.lock().unwrap();
            calls.push((host.clone(), port));
            calls.len() - 1
        };
        let result = answer(&host, index);
        async move { result }
    };
    (resolver, calls)
}

/// Every name answers the loopback address.
fn loopback_dns() -> (impl HostResolver + 'static, Calls) {
    recording(|_, _| Ok(vec![LOOPBACK]))
}

fn policy(ca: &TestCa, resolver: impl HostResolver + 'static) -> FetchPolicy {
    let server = LoopbackTestServer::new(LOOPBACK, ca.pem().as_bytes()).expect("test server");
    FetchPolicy::new("image", 1024)
        .with_resolver(resolver)
        .with_loopback_test_server(server)
}

fn calls(calls: &Calls) -> Vec<(String, u16)> {
    calls.lock().unwrap().clone()
}

/// Wait (bounded) for something another task does.
async fn eventually(condition: impl Fn() -> bool, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// --- pinning and the hostname invariant ------------------------------------

#[tokio::test]
async fn the_request_reaches_the_pinned_address_under_the_original_host_name() {
    let ca = TestCa::new();
    let server = TlsServer::start(&ca, &["images.test"], |_| ok_png()).await;
    let (dns, asked) = loopback_dns();
    let policy = policy(&ca, dns).with_accept(HeaderValue::from_static("image/*"));

    let fetched = fetch_public(&server.url("images.test", "/cover.png"), &policy)
        .await
        .expect("the pinned fetch succeeds");

    assert_eq!(fetched.body.as_ref(), PNG);
    assert_eq!(fetched.content_type.as_deref(), Some("image/png"));
    // The server listens on 127.0.0.1 alone and `images.test` resolves
    // nowhere real: the request got here through the pin or not at all.
    let seen = server.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/cover.png");
    // TLS and HTTP both stayed on the name, never the address.
    assert_eq!(seen[0].sni.as_deref(), Some("images.test"));
    let host = format!("images.test:{}", server.port);
    assert_eq!(seen[0].header("host"), Some(host.as_str()));
    assert_eq!(seen[0].header("accept"), Some("image/*"));
    let accepts = seen[0]
        .headers
        .iter()
        .filter(|(n, _)| n == "accept")
        .count();
    assert_eq!(accepts, 1, "the policy's Accept replaces reqwest's default");
    assert_eq!(seen[0].header("accept-encoding"), Some("identity"));
    let codings = seen[0]
        .headers
        .iter()
        .filter(|(n, _)| n == "accept-encoding")
        .count();
    assert_eq!(codings, 1, "one Accept-Encoding, and it is identity");
    // Resolved once, for that name, on the URL's explicit port.
    assert_eq!(calls(&asked), [("images.test".to_owned(), server.port)]);
}

#[tokio::test]
async fn a_certificate_for_another_name_fails_the_fetch() {
    let ca = TestCa::new();
    // Positive control: the same CA, the right name, works.
    let right = TlsServer::start(&ca, &["images.test"], |_| ok_png()).await;
    let (dns, _) = loopback_dns();
    fetch_public(&right.url("images.test", "/a.png"), &policy(&ca, dns))
        .await
        .expect("the control fetch succeeds");

    // A certificate for a different name, and one for the very address the
    // connection is pinned to: verification is against the host name, so
    // neither will do.
    for names in [&["other.test"][..], &["127.0.0.1"][..]] {
        let wrong = TlsServer::start(&ca, names, |_| ok_png()).await;
        let (dns, _) = loopback_dns();
        let err = fetch_public(&wrong.url("images.test", "/a.png"), &policy(&ca, dns))
            .await
            .expect_err("the certificate does not name images.test");
        assert_eq!(
            err.to_string(),
            "Could not fetch the image URL.",
            "{names:?}"
        );
        assert!(wrong.seen().is_empty(), "{names:?}: no request was sent");
        // The server reads the client's refusal on its own task, which may
        // not have run yet when the client returns.
        eventually(
            || wrong.failed_handshakes.load(Ordering::SeqCst) == 1,
            &format!("{names:?}: the server saw the handshake refused"),
        )
        .await;
    }
}

#[tokio::test]
async fn trailing_dots_and_case_are_normalized_before_anything_sees_the_name() {
    let ca = TestCa::new();
    let server = TlsServer::start(&ca, &["images.test"], |_| ok_png()).await;
    let (dns, asked) = loopback_dns();

    fetch_public(&server.url("IMAGES.Test.", "/a.png"), &policy(&ca, dns))
        .await
        .expect("the normalized name is fetched");

    assert_eq!(calls(&asked), [("images.test".to_owned(), server.port)]);
    let seen = server.seen();
    assert_eq!(seen[0].sni.as_deref(), Some("images.test"));
    let host = format!("images.test:{}", server.port);
    assert_eq!(seen[0].header("host"), Some(host.as_str()));
}

#[tokio::test]
async fn an_idna_host_is_resolved_pinned_and_requested_in_its_ascii_form() {
    let ca = TestCa::new();
    let server = TlsServer::start(&ca, &["xn--bcher-kva.test"], |_| ok_png()).await;
    let (dns, asked) = loopback_dns();

    fetch_public(&server.url("B\u{dc}CHER.test", "/a.png"), &policy(&ca, dns))
        .await
        .expect("the punycode name is fetched");

    assert_eq!(
        calls(&asked),
        [("xn--bcher-kva.test".to_owned(), server.port)]
    );
    let seen = server.seen();
    assert_eq!(seen[0].sni.as_deref(), Some("xn--bcher-kva.test"));
    let host = format!("xn--bcher-kva.test:{}", server.port);
    assert_eq!(seen[0].header("host"), Some(host.as_str()));
}

#[tokio::test]
async fn an_ip_literal_host_is_fetched_without_dns() {
    let ca = TestCa::new();
    let server = TlsServer::start(&ca, &["127.0.0.1"], |_| ok_png()).await;
    let (dns, asked) = loopback_dns();

    let fetched = fetch_public(&server.url("127.0.0.1", "/a.png"), &policy(&ca, dns))
        .await
        .expect("the literal is fetched");

    assert_eq!(fetched.body.as_ref(), PNG);
    assert!(calls(&asked).is_empty(), "a literal is never resolved");
    let seen = server.seen();
    // Clients send no SNI for an address.
    assert_eq!(seen[0].sni, None);
    let host = format!("127.0.0.1:{}", server.port);
    assert_eq!(seen[0].header("host"), Some(host.as_str()));
}

/// DNS rebinding: the first answer is validated and pinned; a later answer
/// (here an address the policy never approved) must never be used, because
/// nothing after the pin asks the resolver again.
#[tokio::test]
async fn a_later_dns_answer_is_never_used() {
    let ca = TestCa::new();
    let server = TlsServer::start(&ca, &["images.test"], |_| ok_png()).await;
    let (dns, asked) = recording(|_, call| {
        Ok(vec![if call == 0 {
            LOOPBACK
        } else {
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
        }])
    });

    fetch_public(&server.url("images.test", "/a.png"), &policy(&ca, dns))
        .await
        .expect("the first, validated answer is the one connected to");

    assert_eq!(calls(&asked).len(), 1, "resolved exactly once for one hop");
    assert_eq!(server.seen().len(), 1);
}

#[tokio::test]
async fn a_response_without_a_content_type_reports_none() {
    let ca = TestCa::new();
    let server = TlsServer::start(&ca, &["images.test"], |_| {
        Reply::Send(response("200 OK", &[("content-length", "3")], b"abc"))
    })
    .await;
    let (dns, _) = loopback_dns();

    let fetched = fetch_public(&server.url("images.test", "/a"), &policy(&ca, dns))
        .await
        .expect("fetched");
    assert_eq!(fetched.body.as_ref(), b"abc");
    assert_eq!(fetched.content_type, None);
}

// --- the override admits one loopback address, no more ---------------------

#[test]
fn a_test_server_must_be_on_loopback_and_bring_a_ca() {
    let ca = TestCa::new();
    let pem = ca.pem();
    for address in ["10.0.0.1", "169.254.169.254", "93.184.216.34", "fe80::1"] {
        let address: IpAddr = address.parse().unwrap();
        assert!(
            matches!(
                LoopbackTestServer::new(address, pem.as_bytes()),
                Err(LoopbackTestServerError::NotLoopback(a)) if a == address
            ),
            "{address}"
        );
    }
    assert!(matches!(
        LoopbackTestServer::new(LOOPBACK, b""),
        Err(LoopbackTestServerError::EmptyCa)
    ));
    assert!(matches!(
        LoopbackTestServer::new(LOOPBACK, b"-----BEGIN CERTIFICATE-----\nnope\n"),
        Err(LoopbackTestServerError::InvalidCa(_))
    ));
    assert!(LoopbackTestServer::new("::1".parse().unwrap(), pem.as_bytes()).is_ok());
    // A second address passes the same rule as the first.
    let server = LoopbackTestServer::new(LOOPBACK, pem.as_bytes()).expect("first address");
    assert!(server.clone().also_at(Ipv6Addr::LOCALHOST.into()).is_ok());
    for address in ["10.0.0.1", "169.254.169.254", "::ffff:127.0.0.1"] {
        let address: IpAddr = address.parse().unwrap();
        assert!(
            matches!(
                server.clone().also_at(address),
                Err(LoopbackTestServerError::NotLoopback(a)) if a == address
            ),
            "also_at({address})"
        );
    }
}

#[tokio::test]
async fn the_override_admits_its_one_address_and_nothing_else() {
    let ca = TestCa::new();
    for (answers, expected) in [
        (
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))],
            SsrfError::NonPublicResolution,
        ),
        (
            vec![LOOPBACK, "10.0.0.5".parse().unwrap()],
            SsrfError::NonPublicResolution,
        ),
        (
            vec![LOOPBACK, "169.254.169.254".parse().unwrap()],
            SsrfError::NonPublicResolution,
        ),
    ] {
        let (dns, _) = recording(move |_, _| Ok(answers.clone()));
        let err = fetch_public("https://images.test/a.png", &policy(&ca, dns))
            .await
            .unwrap_err();
        assert_eq!(err, expected);
    }
    for literal in ["127.0.0.2", "[::1]", "10.0.0.1", "169.254.169.254"] {
        let (dns, _) = loopback_dns();
        let err = fetch_public(&format!("https://{literal}/a.png"), &policy(&ca, dns))
            .await
            .unwrap_err();
        assert_eq!(err, SsrfError::NonPublicHost, "{literal}");
    }
}

// --- redirects ---------------------------------------------------------------

#[tokio::test]
async fn any_3xx_is_refused_when_no_redirects_are_allowed() {
    let ca = TestCa::new();
    for status in [
        "301 Moved Permanently",
        "302 Found",
        "303 See Other",
        "307 Temporary Redirect",
        "308 Permanent Redirect",
        "300 Multiple Choices",
        "304 Not Modified",
    ] {
        let server = TlsServer::start(&ca, &["images.test"], move |_| {
            redirect(status, "https://169.254.169.254/latest/meta-data/")
        })
        .await;
        let (dns, asked) = loopback_dns();
        let err = fetch_public(&server.url("images.test", "/a.png"), &policy(&ca, dns))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "URL redirects are not allowed.",
            "{status}"
        );
        assert_eq!(
            server.seen().len(),
            1,
            "{status}: the target was not fetched"
        );
        assert_eq!(calls(&asked).len(), 1, "{status}");
    }
}

#[tokio::test]
async fn a_redirect_is_followed_with_a_fresh_resolution_and_pin_per_hop() {
    let ca = TestCa::new();
    let server = TlsServer::start(&ca, &["images.test"], |seen| match seen.path.as_str() {
        "/start" => redirect("302 Found", "/next"),
        _ => ok_png(),
    })
    .await;
    let (dns, asked) = loopback_dns();

    let fetched = fetch_public(
        &server.url("images.test", "/start"),
        &policy(&ca, dns).with_max_redirects(1),
    )
    .await
    .expect("one redirect is allowed");

    assert_eq!(fetched.body.as_ref(), PNG);
    let paths: Vec<_> = server.seen().into_iter().map(|s| s.path).collect();
    assert_eq!(paths, ["/start", "/next"]);
    // The relative Location joined onto the host name, and that hop was
    // resolved again rather than reusing the first hop's answer.
    let hop = ("images.test".to_owned(), server.port);
    assert_eq!(calls(&asked), [hop.clone(), hop]);
    for seen in server.seen() {
        assert_eq!(
            seen.header("accept-encoding"),
            Some("identity"),
            "{}",
            seen.path
        );
    }
}

#[tokio::test]
async fn a_redirect_to_another_host_is_pinned_under_that_hosts_own_name() {
    let ca = TestCa::new();
    let port = Arc::new(AtomicUsize::new(0));
    let port_ = Arc::clone(&port);
    let server = TlsServer::start(&ca, &["images.test", "cdn.test"], move |seen| {
        match seen.path.as_str() {
            "/start" => redirect(
                "307 Temporary Redirect",
                &format!("https://cdn.test:{}/next", port_.load(Ordering::SeqCst)),
            ),
            _ => ok_png(),
        }
    })
    .await;
    port.store(usize::from(server.port), Ordering::SeqCst);
    let (dns, asked) = loopback_dns();

    fetch_public(
        &server.url("images.test", "/start"),
        &policy(&ca, dns).with_max_redirects(1),
    )
    .await
    .expect("the cross-host redirect is followed");

    let seen = server.seen();
    let snis: Vec<_> = seen.iter().map(|s| s.sni.clone().unwrap()).collect();
    assert_eq!(snis, ["images.test", "cdn.test"]);
    assert_eq!(
        seen[1].header("host"),
        Some(format!("cdn.test:{}", server.port).as_str())
    );
    let names: Vec<_> = calls(&asked).into_iter().map(|(host, _)| host).collect();
    assert_eq!(names, ["images.test", "cdn.test"]);
}

/// Two listeners on one port number, one on each loopback address, so that
/// two hops of one URL authority (`images.test:<port>`) can be pinned to
/// two different servers.
async fn listeners_on_one_port() -> (TcpListener, TcpListener) {
    for _ in 0..20 {
        let v4 = TcpListener::bind((LOOPBACK, 0))
            .await
            .expect("bind 127.0.0.1");
        let port = v4.local_addr().expect("local addr").port();
        if let Ok(v6) = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
            return (v4, v6);
        }
    }
    panic!("could not bind 127.0.0.1 and [::1] on one port (is IPv6 loopback configured?)");
}

/// The per-hop client, proven against the case it exists for: hop one's
/// server keeps its connection alive (no `Connection: close`) and redirects
/// to the same scheme, host and port, while DNS now pins that authority to a
/// different server. A pooling client would send hop two down hop one's
/// open connection; a fresh client per hop connects where the new pin says.
#[tokio::test]
async fn a_redirect_never_rides_the_previous_hops_kept_alive_connection() {
    let ca = TestCa::new();
    let (v4, v6) = listeners_on_one_port().await;
    let ipv6_loopback: IpAddr = Ipv6Addr::LOCALHOST.into();
    // Both would serve either path, so only *where* each request lands can
    // tell the hops apart.
    let first = TlsServer::start_on(&ca, &["images.test"], v4, |seen| {
        Reply::KeepAlive(match seen.path.as_str() {
            "/start" => persistent_response(
                "302 Found",
                &[("location", "/next"), ("content-length", "0")],
                b"",
            ),
            _ => persistent_response("200 OK", &[("content-length", "5")], b"first"),
        })
    });
    let second = TlsServer::start_on(&ca, &["images.test"], v6, |_| {
        Reply::KeepAlive(persistent_response(
            "200 OK",
            &[("content-length", "6")],
            b"second",
        ))
    });
    assert_eq!(first.port, second.port, "one authority for both hops");
    let (dns, asked) =
        recording(move |_, call| Ok(vec![if call == 0 { LOOPBACK } else { ipv6_loopback }]));
    let server = LoopbackTestServer::new(LOOPBACK, ca.pem().as_bytes())
        .and_then(|s| s.also_at(ipv6_loopback))
        .expect("both loopback addresses");
    let policy = FetchPolicy::new("image", 1024)
        .with_resolver(dns)
        .with_loopback_test_server(server)
        .with_max_redirects(1);

    let fetched = fetch_public(&first.url("images.test", "/start"), &policy)
        .await
        .expect("both hops succeed");

    assert_eq!(
        fetched.body.as_ref(),
        b"second",
        "hop two reached its own pin"
    );
    let first_seen = first.seen();
    let second_seen = second.seen();
    let paths = |seen: &[Seen]| seen.iter().map(|s| s.path.clone()).collect::<Vec<_>>();
    assert_eq!(
        paths(&first_seen),
        ["/start"],
        "hop one only, on its open connection"
    );
    assert_eq!(paths(&second_seen), ["/next"]);
    assert_eq!(
        second_seen[0].connection, 0,
        "a new connection to the second server"
    );
    assert_eq!(calls(&asked).len(), 2, "resolved once per hop");
    // Every hop asks for the stored bytes.
    for seen in first_seen.iter().chain(&second_seen) {
        assert_eq!(
            seen.header("accept-encoding"),
            Some("identity"),
            "{}",
            seen.path
        );
    }
}

/// Every hop is validated from scratch: a Location that would be refused as
/// a first URL is refused as a redirect, before anything connects to it.
#[tokio::test]
async fn a_redirect_into_a_refused_target_is_refused_at_the_hop() {
    let ca = TestCa::new();
    let cases = [
        (
            "https://169.254.169.254/latest/",
            "URL host is not a public address.",
        ),
        (
            "https://[::ffff:10.0.0.1]/",
            "URL host is not a public address.",
        ),
        (
            "https://metadata.google.internal/",
            "That host is not allowed.",
        ),
        (
            "https://metadata./computeMetadata/v1/",
            "That host is not allowed.",
        ),
        (
            "http://images.test/a.png",
            "Only https:// URLs are allowed.",
        ),
        (
            "https://user:pw@images.test/a.png",
            "URLs with embedded credentials are not allowed.",
        ),
        (
            "https://rebind.test/a.png",
            "URL host resolves to a non-public address.",
        ),
    ];
    for (location, expected) in cases {
        let server = TlsServer::start(&ca, &["images.test"], move |_| {
            redirect("302 Found", location)
        })
        .await;
        let (dns, asked) = recording(|host, _| {
            Ok(vec![if host == "rebind.test" {
                "10.0.0.5".parse().unwrap()
            } else {
                LOOPBACK
            }])
        });
        let err = fetch_public(
            &server.url("images.test", "/a.png"),
            &policy(&ca, dns).with_max_redirects(3),
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), expected, "{location}");
        assert_eq!(
            server.seen().len(),
            1,
            "{location}: nothing else was fetched"
        );
        let resolved_rebind = calls(&asked).iter().any(|(h, _)| h == "rebind.test");
        assert_eq!(
            resolved_rebind,
            location.contains("rebind.test"),
            "{location}: only a valid name is resolved"
        );
    }
}

#[tokio::test]
async fn a_redirect_chain_longer_than_allowed_is_refused() {
    let ca = TestCa::new();
    let server = TlsServer::start(&ca, &["images.test"], |_| redirect("302 Found", "/again")).await;
    let (dns, _) = loopback_dns();

    let err = fetch_public(
        &server.url("images.test", "/a.png"),
        &policy(&ca, dns).with_max_redirects(2),
    )
    .await
    .unwrap_err();

    assert_eq!(err.to_string(), "Too many redirects.");
    assert_eq!(
        server.seen().len(),
        3,
        "the first request and two redirects"
    );
}

#[tokio::test]
async fn a_redirect_without_a_location_is_a_failed_fetch() {
    let ca = TestCa::new();
    let server = TlsServer::start(&ca, &["images.test"], |_| {
        Reply::Send(response("302 Found", &[("content-length", "0")], b""))
    })
    .await;
    let (dns, _) = loopback_dns();

    let err = fetch_public(
        &server.url("images.test", "/a.png"),
        &policy(&ca, dns).with_max_redirects(1),
    )
    .await
    .unwrap_err();
    assert_eq!(err.to_string(), "Could not fetch the image URL.");
}

// --- content coding ----------------------------------------------------------

/// The request asks for `identity`; a server that compresses anyway is
/// refused, and the body is never decoded (there is no decoder to decode
/// it with). Python's httpx would have decompressed these.
#[tokio::test]
async fn a_content_encoded_response_is_refused_and_never_decoded() {
    let ca = TestCa::new();
    for coding in [
        "gzip",
        "br",
        "deflate",
        "zstd",
        "GZIP",
        "identity, gzip",
        "gzip, identity",
        "",
    ] {
        let server = TlsServer::start(&ca, &["images.test"], move |_| {
            let body = b"\x1f\x8b\x08\x00 pretend this is gzip";
            Reply::Send(response(
                "200 OK",
                &[
                    ("content-type", "image/png"),
                    ("content-encoding", coding),
                    ("content-length", &body.len().to_string()),
                ],
                body,
            ))
        })
        .await;
        let (dns, _) = loopback_dns();
        let err = fetch_public(&server.url("images.test", "/a.png"), &policy(&ca, dns))
            .await
            .expect_err(coding);
        assert_eq!(
            err.to_string(),
            "Could not fetch the image URL.",
            "{coding:?}"
        );
        let seen = server.seen();
        assert_eq!(seen.len(), 1, "{coding:?}");
        assert_eq!(seen[0].header("accept-encoding"), Some("identity"));
    }
}

#[tokio::test]
async fn an_identity_content_encoding_is_accepted() {
    let ca = TestCa::new();
    for coding in ["identity", "Identity", "IDENTITY", "identity, identity"] {
        let server = TlsServer::start(&ca, &["images.test"], move |_| {
            Reply::Send(response(
                "200 OK",
                &[
                    ("content-type", "image/png"),
                    ("content-encoding", coding),
                    ("content-length", &PNG.len().to_string()),
                ],
                PNG,
            ))
        })
        .await;
        let (dns, _) = loopback_dns();
        let fetched = fetch_public(&server.url("images.test", "/a.png"), &policy(&ca, dns))
            .await
            .unwrap_or_else(|e| panic!("{coding:?}: {e}"));
        assert_eq!(fetched.body.as_ref(), PNG, "{coding:?}");
    }
}

// --- status, size, time, transport -------------------------------------------

#[tokio::test]
async fn any_status_but_200_is_refused() {
    let ca = TestCa::new();
    for (status, expected) in [
        ("404 Not Found", "Image fetch failed with HTTP 404."),
        ("201 Created", "Image fetch failed with HTTP 201."),
        ("204 No Content", "Image fetch failed with HTTP 204."),
        (
            "500 Internal Server Error",
            "Image fetch failed with HTTP 500.",
        ),
    ] {
        let server = TlsServer::start(&ca, &["images.test"], move |_| {
            Reply::Send(response(status, &[("content-length", "4")], b"nope"))
        })
        .await;
        let (dns, _) = loopback_dns();
        let err = fetch_public(&server.url("images.test", "/a.png"), &policy(&ca, dns))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), expected);
    }
}

#[tokio::test]
async fn a_declared_oversize_body_is_refused_before_it_is_read() {
    let ca = TestCa::new();
    // Declares 5000 bytes, sends 10, and holds the connection: reading the
    // body would wait out the budget, so refusing fast proves it was not read.
    let server = TlsServer::start(&ca, &["images.test"], |_| {
        Reply::SendThenHang(response(
            "200 OK",
            &[("content-type", "image/png"), ("content-length", "5000")],
            &[b'x'; 10],
        ))
    })
    .await;
    let (dns, _) = loopback_dns();
    let policy = policy(&ca, dns)
        .with_too_large_error("The image is too large (max 1 MB).")
        .with_timeout(Duration::from_secs(30));

    let started = Instant::now();
    let err = fetch_public(&server.url("images.test", "/a.png"), &policy)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "The image is too large (max 1 MB).");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "refused up front"
    );
}

#[tokio::test]
async fn a_streamed_body_is_cut_at_the_cap_and_exactly_the_cap_is_fine() {
    let ca = TestCa::new();
    // No Content-Length at all: only counting can stop it (1280 bytes
    // against the policy's 1024).
    let over = TlsServer::start(&ca, &["images.test"], |_| {
        Reply::Send(chunked(&vec![vec![b'x'; 64]; 20]))
    })
    .await;
    let (dns, _) = loopback_dns();
    let err = fetch_public(&over.url("images.test", "/a.png"), &policy(&ca, dns))
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "The fetched image is too large.");

    let exact = TlsServer::start(&ca, &["images.test"], |_| {
        Reply::Send(chunked(&[vec![b'x'; 1000], vec![b'y'; 24]]))
    })
    .await;
    let (dns, _) = loopback_dns();
    let fetched = fetch_public(&exact.url("images.test", "/a.png"), &policy(&ca, dns))
        .await
        .expect("exactly max_bytes is allowed");
    assert_eq!(fetched.body.len(), 1024);

    let one_over = TlsServer::start(&ca, &["images.test"], |_| {
        Reply::Send(chunked(&[vec![b'x'; 1000], vec![b'y'; 25]]))
    })
    .await;
    let (dns, _) = loopback_dns();
    let err = fetch_public(&one_over.url("images.test", "/a.png"), &policy(&ca, dns))
        .await
        .unwrap_err();
    assert!(matches!(err, SsrfError::TooLarge(_)), "{err:?}");
}

/// Python's "lying Content-Length" case has no over-the-wire twin: HTTP/1.1
/// frames the body by that header, so a server that sends more than it
/// declared is cut off at the declaration — never past the cap. (The unit
/// test `a_lying_content_length_is_cut_by_the_stream_cap` keeps Python's
/// assertion against a raw stream.)
#[tokio::test]
async fn an_understated_content_length_truncates_rather_than_overruns() {
    let ca = TestCa::new();
    let server = TlsServer::start(&ca, &["images.test"], |_| {
        Reply::Send(response(
            "200 OK",
            &[("content-type", "image/png"), ("content-length", "10")],
            &[b'x'; 4096],
        ))
    })
    .await;
    let (dns, _) = loopback_dns();

    let fetched = fetch_public(&server.url("images.test", "/a.png"), &policy(&ca, dns))
        .await
        .expect("the declared ten bytes are a complete, in-cap body");
    assert_eq!(fetched.body.len(), 10);
}

#[tokio::test]
async fn the_budget_covers_a_server_that_stalls() {
    let ca = TestCa::new();
    // One stalls before answering at all, one mid-body.
    let replies: [fn() -> Vec<u8>; 2] = [Vec::new, || {
        response(
            "200 OK",
            &[("content-type", "image/png"), ("content-length", "100")],
            &[b'x'; 10],
        )
    }];
    for reply in replies {
        let server =
            TlsServer::start(&ca, &["images.test"], move |_| Reply::SendThenHang(reply())).await;
        let (dns, _) = loopback_dns();
        let policy = policy(&ca, dns).with_timeout(Duration::from_millis(300));

        let started = Instant::now();
        let err = fetch_public(&server.url("images.test", "/a.png"), &policy)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "Image fetch timed out.");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }
}

/// The budget is one wall clock for the whole chain, not a per-hop allowance:
/// hops that each fit easily still run out of it together. With a per-hop
/// timeout this chain would instead run all eleven hops (4.4 s) and end as
/// "Too many redirects."
#[tokio::test]
async fn individually_short_hops_exhaust_one_shared_budget() {
    let ca = TestCa::new();
    let hop = Duration::from_millis(400);
    let budget = Duration::from_millis(1000);
    let server = TlsServer::start(&ca, &["images.test"], move |seen| {
        let n: u32 = seen.path.trim_start_matches("/hop").parse().unwrap_or(0);
        let next = format!("/hop{}", n + 1);
        Reply::After(
            hop,
            response(
                "302 Found",
                &[("location", &next), ("content-length", "0")],
                b"",
            ),
        )
    })
    .await;
    let (dns, _) = loopback_dns();
    let policy = policy(&ca, dns).with_max_redirects(10).with_timeout(budget);

    let started = Instant::now();
    let err = fetch_public(&server.url("images.test", "/hop0"), &policy)
        .await
        .unwrap_err();
    let elapsed = started.elapsed();

    assert_eq!(err.to_string(), "Image fetch timed out.");
    let hops = server.seen().len();
    // At least one hop completed inside the budget (each fits alone); the
    // budget ran out a few hops in, far short of the eleven allowed.
    assert!((2..=4).contains(&hops), "{hops} hops were started");
    assert!(elapsed >= budget, "{elapsed:?}");
    assert!(elapsed < budget * 3, "{elapsed:?}");
}

#[tokio::test]
async fn a_connection_failure_says_exactly_could_not_fetch() {
    // A port that was just free: connecting to it is refused.
    let port = {
        let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let ca = TestCa::new();
    let (dns, _) = loopback_dns();
    let err = fetch_public(
        &format!("https://images.test:{port}/a.png"),
        &policy(&ca, dns),
    )
    .await
    .unwrap_err();
    // Exactly: no address, port or OS error text leaks into it.
    assert_eq!(err.to_string(), "Could not fetch the image URL.");
}

// --- the environment's proxy -------------------------------------------------

const PROXY_CHILD: &str = "child_fetch_under_a_proxy_environment";

/// `HTTPS_PROXY` and friends must not route a guarded fetch: a proxy would
/// make the connection, and its DNS, from somewhere the pin does not reach.
///
/// The environment is the process's, and tests must not mutate it, so the
/// fetch runs in a fresh copy of this test binary *born* with a proxy
/// environment pointing at a trap listener here. The child also runs a
/// positive control — a plain client that does read the environment — so the
/// trap counting exactly one connection proves both that the variables were
/// live and that the guarded fetch ignored them.
#[test]
fn an_environment_proxy_is_never_used() {
    let trap = std::net::TcpListener::bind((LOOPBACK, 0)).expect("bind the trap");
    let proxy = format!("http://{}", trap.local_addr().expect("trap addr"));
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    // Accept and hang up at once, so the control fails fast. The thread
    // outlives the test (blocked in `accept`) and dies with the process.
    std::thread::spawn(move || {
        for stream in trap.incoming() {
            counted.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });

    let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"));
    child.args([PROXY_CHILD, "--exact", "--include-ignored"]);
    for var in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        child.env(var, &proxy);
    }
    child.env_remove("NO_PROXY").env_remove("no_proxy");
    let output = child.output().expect("run the child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the child failed:\n{stdout}\n{stderr}"
    );
    // An `--exact` filter that matches nothing also exits 0.
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "the child did not run exactly {PROXY_CHILD}:\n{stdout}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "only the positive control may reach the proxy"
    );
}

#[tokio::test]
#[ignore = "child of an_environment_proxy_is_never_used, which runs it in a fresh process"]
async fn child_fetch_under_a_proxy_environment() {
    let proxy = std::env::var("HTTPS_PROXY").expect(
        "premise: HTTPS_PROXY is set (this runs only through an_environment_proxy_is_never_used)",
    );
    assert!(proxy.starts_with("http://127.0.0.1:"), "{proxy}");

    let ca = TestCa::new();
    let server = TlsServer::start(&ca, &["images.test"], |_| ok_png()).await;
    let (dns, _) = loopback_dns();
    let url = server.url("images.test", "/a.png");
    let fetched = fetch_public(&url, &policy(&ca, dns))
        .await
        .expect("the guarded fetch goes direct, proxy or not");
    assert_eq!(fetched.body.as_ref(), PNG);

    // Positive control: a client that reads the environment sends this
    // request to the trap (which hangs up), never to the server.
    let control = reqwest::Client::builder()
        .build()
        .expect("control client")
        .get(&url)
        .send()
        .await;
    assert!(control.is_err(), "the trap answers nothing");
    assert_eq!(
        server.seen().len(),
        1,
        "the control never reached the server"
    );
}
