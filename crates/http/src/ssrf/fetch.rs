//! The guarded fetch: resolve, pin, request, follow (maybe), read capped.

use std::error::Error as StdError;
use std::net::{IpAddr, SocketAddr};

use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt};
use http::header::{
    ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, LOCATION,
};
use http::{HeaderMap, HeaderValue, StatusCode};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::Url;

use super::error::SsrfError;
use super::policy::FetchPolicy;
use super::target::{self, Target, TargetHost};

/// The capped body of a successful (`200 OK`) fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The body, at most the policy's `max_bytes`.
    pub body: Bytes,
    /// The response's `Content-Type`, verbatim, if it sent a readable one.
    /// Nothing here interprets it: whether it is acceptable is the caller's
    /// policy (an image fetcher requires `image/*` and still sniffs the
    /// bytes, because a header is only a claim).
    pub content_type: Option<String>,
}

/// Fetch `url` under the full SSRF policy and return the capped body.
///
/// In order — the module docs give the reasoning for each step:
///
/// 1. Validate the URL ([`SsrfError::InvalidUrl`] through
///    [`SsrfError::NonPublicHost`]) and normalize its host.
/// 2. Then, inside one wall-clock budget for everything that follows
///    ([`SsrfError::TimedOut`]), per hop:
///    - resolve a host name through the policy's resolver and require
///      **every** answer to be public ([`SsrfError::ResolutionFailed`],
///      [`SsrfError::NonPublicResolution`]), preferring IPv4 for the pin; an
///      IP literal is its own pin;
///    - send one GET through a client built for this hop alone, whose
///      resolver answers only the normalized name, with the pinned address;
///    - a 3xx is [`SsrfError::RedirectsNotAllowed`] unless the policy allows
///      redirects, in which case its `Location` is joined onto the current
///      URL and the target goes back to step 1, up to the policy's
///      `max_redirects` ([`SsrfError::TooManyRedirects`]);
///    - any status but `200` is [`SsrfError::HttpStatus`];
///    - a `Content-Encoding` other than `identity` is
///      [`SsrfError::FetchFailed`]: the request asks for `identity`, and
///      nothing here ever decompresses;
///    - a numeric `Content-Length` over `max_bytes` is
///      [`SsrfError::TooLarge`] before a byte of body is read, and so is a
///      streamed body the moment it would pass `max_bytes`.
///
/// Every other failure is [`SsrfError::FetchFailed`]. No error carries an
/// internal detail; see [`SsrfError`].
pub async fn fetch_public(url: &str, policy: &FetchPolicy) -> Result<Fetched, SsrfError> {
    // Validation does no I/O, so it sits outside the budget, as in Python.
    let target = target::validate(url, policy)?;
    match tokio::time::timeout(policy.timeout, follow(target, policy)).await {
        Ok(outcome) => outcome,
        Err(_elapsed) => Err(SsrfError::TimedOut {
            label: policy.label.clone(),
        }),
    }
}

/// What one hop produced.
enum Hop {
    Fetched(Fetched),
    /// The next URL, joined onto the current one but not yet validated.
    Redirect(Url),
}

async fn follow(mut target: Target, policy: &FetchPolicy) -> Result<Fetched, SsrfError> {
    for _hop in 0..=policy.max_redirects {
        let pinned = pin(&target, policy).await?;
        match request_once(&target, pinned, policy).await? {
            Hop::Fetched(fetched) => return Ok(fetched),
            // From scratch — scheme, credentials, metadata names, IP policy —
            // and the next iteration resolves and pins it afresh. A redirect
            // to an internal address is refused here, before any connection.
            Hop::Redirect(next) => target = target::validate(next.as_str(), policy)?,
        }
    }
    Err(SsrfError::TooManyRedirects)
}

/// The address this hop connects to.
async fn pin(target: &Target, policy: &FetchPolicy) -> Result<IpAddr, SsrfError> {
    match &target.host {
        // Judged by `validate` already; there is nothing to resolve.
        TargetHost::Ip(ip) => Ok(*ip),
        TargetHost::Name(name) => {
            let answers = policy
                .resolver
                .resolve(name.clone(), target.port)
                .await
                .map_err(|_| SsrfError::ResolutionFailed)?;
            choose_pin(&answers, |ip| policy.permits(ip))
        }
    }
}

/// Every answer must be permitted — a resolver that returns a mixed
/// public/private set is exactly the rebinding setup this refuses to race —
/// and then any member is safe to pin. IPv4 is preferred, as in Python, for
/// the broadest egress compatibility; within a family the resolver's order
/// stands.
fn choose_pin(answers: &[IpAddr], permits: impl Fn(IpAddr) -> bool) -> Result<IpAddr, SsrfError> {
    let first = *answers.first().ok_or(SsrfError::ResolutionFailed)?;
    if !answers.iter().all(|&ip| permits(ip)) {
        return Err(SsrfError::NonPublicResolution);
    }
    Ok(answers
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .unwrap_or(first))
}

/// A reqwest resolver that knows one name and one address.
///
/// reqwest hands its resolver the host of the URL it is sending to, which
/// `validate` made the normalized name. Answering only that name — and
/// erroring, never falling back to system DNS, for anything else — is what
/// makes "the name checked is the name connected to" a property of the
/// client rather than of the call site: if the request URL and the pin ever
/// disagreed, the request would fail instead of resolving the stranger.
///
/// The port is the URL's effective port. reqwest uses the URL's explicit
/// port whatever this says, and this one for a URL without one, so the two
/// always agree.
#[derive(Debug)]
struct PinnedResolver {
    /// `None` for an IP-literal host, which reqwest never resolves: then this
    /// refuses every name.
    name: Option<String>,
    addr: SocketAddr,
}

/// What a [`PinnedResolver`] answers for a name it was not built for.
#[derive(Debug, thiserror::Error)]
#[error("refusing to resolve a name this fetch did not validate and pin")]
struct UnpinnedName;

impl PinnedResolver {
    fn new(target: &Target, pinned: IpAddr) -> Self {
        let name = match &target.host {
            TargetHost::Name(name) => Some(name.clone()),
            TargetHost::Ip(_) => None,
        };
        Self {
            name,
            addr: SocketAddr::new(pinned, target.port),
        }
    }
}

impl Resolve for PinnedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let answer: Result<Addrs, Box<dyn StdError + Send + Sync>> = match &self.name {
            Some(pinned) if name.as_str() == pinned => Ok(Box::new(std::iter::once(self.addr))),
            _ => Err(Box::new(UnpinnedName)),
        };
        Box::pin(std::future::ready(answer))
    }
}

/// A client for one hop.
///
/// Fresh every time: a pooled connection is an earlier hop's decision, and
/// reusing one would connect where that decision pointed, not where this
/// one does. `pool_max_idle_per_host(0)` keeps even this client from
/// parking a connection. `no_proxy()` because a proxy would make the
/// connection — and its DNS — somewhere this pin does not reach, and it also
/// stops reqwest reading `HTTPS_PROXY`/`ALL_PROXY` from the environment.
/// Redirects are this module's to follow, so reqwest follows none.
///
/// TLS is reqwest's `rustls` default: SNI and certificate verification
/// against the URL's host, which is the normalized name — the pin changes
/// only where the TCP connection goes.
///
/// Every decoder is switched off by name. This crate enables none of
/// reqwest's `gzip`/`brotli`/`zstd`/`deflate`, but a consumer's graph can,
/// and Cargo would unify it in: these four calls keep the body this module
/// counts the body the server sent, whatever the graph says.
///
/// The price is one TLS configuration (on Linux, a read of the system roots)
/// per hop; Python pays the same for its client per hop, and a guarded fetch
/// is one user-supplied URL, not a hot path.
fn hop_client(
    target: &Target,
    pinned: IpAddr,
    policy: &FetchPolicy,
) -> reqwest::Result<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(0)
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .dns_resolver(PinnedResolver::new(target, pinned));
    #[cfg(feature = "ssrf-test-support")]
    let builder = match &policy.test_server {
        Some(server) => server.trust(builder),
        None => builder,
    };
    #[cfg(not(feature = "ssrf-test-support"))]
    let _ = policy;
    builder.build()
}

async fn request_once(
    target: &Target,
    pinned: IpAddr,
    policy: &FetchPolicy,
) -> Result<Hop, SsrfError> {
    let client = hop_client(target, pinned, policy).map_err(|e| transport_failure(e, policy))?;
    // The bytes as stored, never a compressed form: there is no decoder
    // here to hand them to, and none is wanted (see `is_identity_encoded`).
    let mut request = client
        .get(target.url.clone())
        .header(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    if let Some(accept) = &policy.accept {
        request = request.header(ACCEPT, accept.clone());
    }
    let response = request
        .send()
        .await
        .map_err(|e| transport_failure(e, policy))?;

    let status = response.status();
    // Every 3xx, as Python's `is_redirect` — a 304 or a 300 is "a redirect"
    // here too, refused or (with no usable Location) a failed fetch.
    if status.is_redirection() {
        if policy.max_redirects == 0 {
            return Err(SsrfError::RedirectsNotAllowed);
        }
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| std::str::from_utf8(value.as_bytes()).ok())
            .filter(|location| !location.is_empty())
            .ok_or_else(|| SsrfError::FetchFailed {
                label: policy.label.clone(),
            })?;
        // Joined onto the hostname URL, never onto the pinned address, so a
        // relative Location resolves against the host that was asked.
        let next = target
            .url
            .join(location)
            .map_err(|_| SsrfError::InvalidUrl)?;
        return Ok(Hop::Redirect(next));
    }
    if status != StatusCode::OK {
        return Err(SsrfError::HttpStatus {
            label: policy.label.clone(),
            status,
        });
    }
    if !is_identity_encoded(response.headers()) {
        tracing::debug!(label = %policy.label, "refusing a content-encoded response");
        return Err(SsrfError::FetchFailed {
            label: policy.label.clone(),
        });
    }
    if declared_too_large(response.headers(), policy.max_bytes) {
        return Err(policy.too_large());
    }

    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = read_capped(response.bytes_stream(), policy.max_bytes)
        .await
        .map_err(|e| match e {
            CapError::TooLarge => policy.too_large(),
            CapError::Stream(e) => transport_failure(e, policy),
        })?;
    Ok(Hop::Fetched(Fetched { body, content_type }))
}

/// Whether the body is the resource's own bytes: no `Content-Encoding` at
/// all, or only `identity` (case-insensitive, in any number of headers and
/// comma-separated codings).
///
/// Anything else is refused rather than decoded — including a server that
/// compresses although the request asked for `identity`. A deliberate
/// difference from Python, whose httpx decodes gzip/deflate (and brotli/zstd
/// when installed): with no decoder in this crate, a compressed body can
/// never be mislabelled as the image it claims to be, and there is no
/// decompression bomb to cap. An empty or unreadable value is not `identity`.
fn is_identity_encoded(headers: &HeaderMap) -> bool {
    headers.get_all(CONTENT_ENCODING).iter().all(|value| {
        value.to_str().is_ok_and(|codings| {
            codings
                .split(',')
                .all(|coding| coding.trim().eq_ignore_ascii_case("identity"))
        })
    })
}

/// A numeric `Content-Length` over the cap — refused before reading. Only a
/// claim: anything else in the header (absent, non-numeric) is left to the
/// streaming cap, which counts what actually arrives.
fn declared_too_large(headers: &HeaderMap, max_bytes: usize) -> bool {
    let Some(declared) = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    if declared.is_empty() || !declared.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // All digits; one too long for a u128 is certainly over any cap.
    declared
        .parse::<u128>()
        .map_or(true, |n| n > max_bytes as u128)
}

/// Why a capped read stopped early.
#[derive(Debug)]
enum CapError<E> {
    TooLarge,
    Stream(E),
}

/// Read `stream` to the end, or stop the moment it would pass `max_bytes`
/// (exactly `max_bytes` is fine). Counts bytes as they arrive, so a
/// `Content-Length` that understates the body cannot buy it more room.
async fn read_capped<S, E>(stream: S, max_bytes: usize) -> Result<Bytes, CapError<E>>
where
    S: Stream<Item = Result<Bytes, E>>,
{
    let mut stream = std::pin::pin!(stream);
    let mut body = BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(CapError::Stream)?;
        // `body.len() <= max_bytes` holds on entry, so this cannot underflow.
        if chunk.len() > max_bytes - body.len() {
            return Err(CapError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

/// A reqwest failure, reduced to its client-safe message. The detail is
/// logged at `debug` with the URL stripped: it is server-side diagnostics,
/// and nothing a caller should be shown.
fn transport_failure(error: reqwest::Error, policy: &FetchPolicy) -> SsrfError {
    let label = policy.label.clone();
    let timed_out = error.is_timeout();
    tracing::debug!(
        label = %label,
        connect = error.is_connect(),
        timeout = timed_out,
        body = error.is_body() || error.is_decode(),
        error = %error.without_url(),
        "guarded fetch failed"
    );
    if timed_out {
        SsrfError::TimedOut { label }
    } else {
        SsrfError::FetchFailed { label }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use futures::stream;

    use super::*;
    use crate::ssrf::{fetch_public, AllowedSchemes};

    const PUBLIC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    const PUBLIC_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(
        0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
    ));

    fn ip(addr: &str) -> IpAddr {
        addr.parse().expect("test address parses")
    }

    /// Every `(host, port)` a resolver was asked, in order.
    type Calls = Arc<Mutex<Vec<(String, u16)>>>;

    /// A policy whose resolver answers `answers` and records each call. No
    /// test here ever gets as far as a connection: each one is refused at
    /// resolution, which is the point.
    fn answering(answers: Vec<IpAddr>) -> (FetchPolicy, Calls) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        let policy = FetchPolicy::new("image", 1024).with_resolver(move |host: String, port| {
            seen.lock().unwrap().push((host, port));
            let answers = answers.clone();
            async move { Ok(answers) }
        });
        (policy, calls)
    }

    /// Consumers await this inside tool handlers and axum services, which
    /// need `Send` futures; a non-`Send` holder across an `.await` would
    /// break every one of them at their build, not this crate's.
    #[test]
    fn the_fetch_future_is_send_and_its_types_are_send_sync() {
        fn send<T: Send>(_: &T) {}
        fn send_sync<T: Send + Sync + 'static>() {}
        send_sync::<FetchPolicy>();
        send_sync::<SsrfError>();
        send_sync::<Fetched>();
        let policy = FetchPolicy::new("image", 1);
        let future = fetch_public("https://images.example.com/a.png", &policy);
        send(&future);
    }

    #[tokio::test]
    async fn a_resolver_failure_is_a_clean_error() {
        let policy = FetchPolicy::new("image", 1024).with_resolver(|_: String, _| async {
            Err(io::Error::other(
                "NXDOMAIN for 10.0.0.1 via resolver 192.168.0.1",
            ))
        });
        let err = fetch_public("https://nxdomain.example.com/a.png", &policy)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "Could not resolve the URL host.");
    }

    #[tokio::test]
    async fn an_empty_answer_is_a_clean_error() {
        let (policy, _) = answering(vec![]);
        let err = fetch_public("https://empty.example.com/a.png", &policy)
            .await
            .unwrap_err();
        assert_eq!(err, SsrfError::ResolutionFailed);
    }

    /// Python's nine `test_non_public_resolution_rejected` sets: one
    /// non-public answer poisons the whole set, wherever it sits.
    #[tokio::test]
    async fn any_non_public_answer_poisons_the_set() {
        let sets: [&[IpAddr]; 9] = [
            &[ip("10.0.0.5")],
            &[ip("127.0.0.1")],
            &[ip("169.254.169.254")],
            &[ip("fe80::1")],
            &[ip("fd00::1")],
            &[ip("::ffff:192.168.0.9")],
            &[PUBLIC_V4, ip("10.0.0.5")],
            &[ip("10.0.0.5"), PUBLIC_V4],
            &[PUBLIC_V6, ip("::1")],
        ];
        for answers in sets {
            let (policy, calls) = answering(answers.to_vec());
            let err = fetch_public("https://rebind.example.com/a.png", &policy)
                .await
                .unwrap_err();
            assert_eq!(
                err.to_string(),
                "URL host resolves to a non-public address.",
                "{answers:?}"
            );
            assert_eq!(calls.lock().unwrap().len(), 1, "{answers:?}");
        }
    }

    /// The resolver is asked for the one normalized name, with the URL's
    /// effective port.
    #[tokio::test]
    async fn the_resolver_is_asked_for_the_normalized_name_and_port() {
        for (url, expected) in [
            (
                "https://Images.Example.COM./a.png",
                ("images.example.com", 443),
            ),
            (
                "https://images.example.com.:8443/a",
                ("images.example.com", 8443),
            ),
            (
                "https://B\u{dc}CHER.example/a.png",
                ("xn--bcher-kva.example", 443),
            ),
        ] {
            let (policy, calls) = answering(vec![ip("10.0.0.1")]);
            let _ = fetch_public(url, &policy).await.unwrap_err();
            assert_eq!(
                calls.lock().unwrap().as_slice(),
                &[(expected.0.to_owned(), expected.1)],
                "{url}"
            );
        }
        let (policy, calls) = answering(vec![ip("10.0.0.1")]);
        let policy = policy.with_allowed_schemes(AllowedSchemes::HttpAndHttps);
        let _ = fetch_public("http://feeds.example.com/rss", &policy).await;
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[("feeds.example.com".to_owned(), 80)]
        );
    }

    #[tokio::test]
    async fn an_ip_literal_never_reaches_the_resolver() {
        let (policy, calls) = answering(vec![PUBLIC_V4]);
        let err = fetch_public("https://10.0.0.1/a.png", &policy)
            .await
            .unwrap_err();
        assert_eq!(err, SsrfError::NonPublicHost);
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_budget_covers_resolution() {
        let policy = FetchPolicy::new("image", 1024)
            .with_timeout(Duration::from_millis(50))
            .with_resolver(|_: String, _| std::future::pending());
        let err = fetch_public("https://slow-dns.example.com/a.png", &policy)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "Image fetch timed out.");
    }

    #[test]
    fn ipv4_is_preferred_and_the_resolver_order_otherwise_stands() {
        let all = |_: IpAddr| true;
        assert_eq!(choose_pin(&[PUBLIC_V6, PUBLIC_V4], all), Ok(PUBLIC_V4));
        assert_eq!(
            choose_pin(&[PUBLIC_V6, ip("1.1.1.1"), PUBLIC_V4], all),
            Ok(ip("1.1.1.1"))
        );
        assert_eq!(choose_pin(&[PUBLIC_V6], all), Ok(PUBLIC_V6));
        assert_eq!(
            choose_pin(&[ip("2606:4700::1111"), PUBLIC_V6], all),
            Ok(ip("2606:4700::1111"))
        );
        assert_eq!(choose_pin(&[], all), Err(SsrfError::ResolutionFailed));
    }

    fn target(url: &str) -> Target {
        let policy = FetchPolicy::new("image", 1024);
        target::validate(url, &policy).expect("valid target")
    }

    async fn ask(resolver: &PinnedResolver, name: &str) -> Result<Vec<SocketAddr>, String> {
        let name: Name = name.parse().expect("a resolvable name");
        resolver
            .resolve(name)
            .await
            .map(Iterator::collect)
            .map_err(|e| e.to_string())
    }

    #[tokio::test]
    async fn the_pinned_resolver_answers_only_the_pinned_name() {
        let resolver =
            PinnedResolver::new(&target("https://Images.Example.com.:8443/a"), PUBLIC_V4);
        assert_eq!(
            ask(&resolver, "images.example.com").await,
            Ok(vec![SocketAddr::new(PUBLIC_V4, 8443)])
        );
        // Any other spelling is a different name to a resolver, and gets no
        // answer at all — not the system's, not the pin.
        for other in [
            "other.example.com",
            "images.example.com.",
            "IMAGES.EXAMPLE.COM",
            "example.com",
            "metadata.google.internal",
            "localhost",
        ] {
            let err = ask(&resolver, other).await.expect_err(other);
            assert!(err.contains("did not validate and pin"), "{other}: {err}");
        }
    }

    #[tokio::test]
    async fn an_ip_literal_pin_resolves_nothing() {
        let resolver = PinnedResolver::new(&target("https://93.184.216.34/a"), PUBLIC_V4);
        assert!(ask(&resolver, "93.184.216.34").await.is_err());
        assert!(ask(&resolver, "example.com").await.is_err());
    }

    fn headers(content_length: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(content_length).unwrap(),
        );
        headers
    }

    #[test]
    fn only_a_numeric_content_length_over_the_cap_is_refused_up_front() {
        assert!(declared_too_large(&headers("5000"), 100));
        assert!(declared_too_large(&headers("101"), 100));
        assert!(!declared_too_large(&headers("100"), 100));
        assert!(!declared_too_large(&headers("10"), 100));
        // Too long for any integer type is still a number, and over.
        assert!(declared_too_large(&headers(&"9".repeat(60)), 100));
        // Not a number: the streaming cap decides.
        for claim in ["", "-1", "1e9", " 5000", "5000 ", "0x10000", "lots"] {
            assert!(!declared_too_large(&headers(claim), 100), "{claim:?}");
        }
        assert!(!declared_too_large(&HeaderMap::new(), 100));
    }

    fn encoded(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(CONTENT_ENCODING, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn only_identity_or_no_content_encoding_counts_as_unencoded() {
        for accepted in [
            &[][..],
            &["identity"][..],
            &["Identity"][..],
            &["IDENTITY"][..],
            &["identity, identity"][..],
            &[" identity "][..],
            &["identity", "identity"][..],
        ] {
            assert!(is_identity_encoded(&encoded(accepted)), "{accepted:?}");
        }
        for refused in [
            &["gzip"][..],
            &["GZIP"][..],
            &["br"][..],
            &["deflate"][..],
            &["zstd"][..],
            &["x-gzip"][..],
            &["identity, gzip"][..],
            &["gzip, identity"][..],
            &["identity,"][..],
            &[""][..],
            // A second header is a second claim, and is judged too.
            &["identity", "gzip"][..],
        ] {
            assert!(!is_identity_encoded(&encoded(refused)), "{refused:?}");
        }
        let mut opaque = HeaderMap::new();
        opaque.insert(
            CONTENT_ENCODING,
            HeaderValue::from_bytes(b"\xffgzip").unwrap(),
        );
        assert!(
            !is_identity_encoded(&opaque),
            "an unreadable value is not identity"
        );
    }

    fn chunks(sizes: &[usize]) -> impl Stream<Item = Result<Bytes, io::Error>> {
        let chunks: Vec<_> = sizes
            .iter()
            .map(|&n| Ok(Bytes::from(vec![b'x'; n])))
            .collect();
        stream::iter(chunks)
    }

    /// Python's `test_streaming_cap_aborts_despite_lying_content_length`:
    /// the header claims 10 bytes, the stream keeps going, and the cap — not
    /// the header — ends it. (Over a real HTTP/1.1 connection hyper frames
    /// the body by that header and stops at 10; the integration tests cover
    /// the wire with a chunked body instead.)
    #[tokio::test]
    async fn a_lying_content_length_is_cut_by_the_stream_cap() {
        assert!(!declared_too_large(&headers("10"), 100));
        let result = read_capped(chunks(&[64; 10]), 100).await;
        assert!(matches!(result, Err(CapError::TooLarge)), "{result:?}");
    }

    #[tokio::test]
    async fn the_stream_cap_is_inclusive() {
        let exact = read_capped(chunks(&[60, 40]), 100).await.unwrap();
        assert_eq!(exact.len(), 100);
        assert!(matches!(
            read_capped(chunks(&[60, 41]), 100).await,
            Err(CapError::TooLarge)
        ));
        assert!(matches!(
            read_capped(chunks(&[101]), 100).await,
            Err(CapError::TooLarge)
        ));
        assert!(read_capped(chunks(&[]), 0).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_stream_error_is_passed_up() {
        let failing = stream::iter(vec![
            Ok(Bytes::from_static(b"abc")),
            Err(io::Error::other("connection reset by 10.0.0.1")),
        ]);
        assert!(matches!(
            read_capped(failing, 100).await,
            Err(CapError::Stream(_))
        ));
    }
}
