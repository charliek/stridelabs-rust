//! The guarded fetch: resolve, pin, request, follow (maybe), read capped.

use std::cmp;
use std::collections::TryReserveError;
use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use http::header::{
    ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, USER_AGENT,
};
use http::{HeaderMap, StatusCode};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::time::Instant;
use url::Url;

#[cfg(feature = "ssrf-decompress")]
use super::decode;
use super::error::SsrfError;
use super::policy::FetchPolicy;
use super::target::{self, Target, TargetHost};

/// The capped body of a successful fetch: `200 OK`, or any status the
/// policy accepts ([`AcceptedStatuses`](super::AcceptedStatuses)).
///
/// `Debug` prints the body's length, never its bytes, and not the content
/// type (a header value), as [`FetchResponse`]'s does: a `Debug` ends up in
/// logs, and the body is whatever the URL's server chose to send.
#[derive(Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The body, at most the policy's `max_bytes`.
    pub body: Bytes,
    /// The response's `Content-Type`, verbatim, if it sent a readable one.
    /// Nothing here interprets it: whether it is acceptable is the caller's
    /// policy (an image fetcher requires `image/*` and still sniffs the
    /// bytes, because a header is only a claim).
    pub content_type: Option<String>,
}

impl fmt::Debug for Fetched {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fetched")
            .field("body", &format_args!("<{} bytes>", self.body.len()))
            .finish_non_exhaustive()
    }
}

/// Everything [`fetch_public_response`] learned from the hop that answered.
///
/// `#[non_exhaustive]`, so it can grow. Its `PartialEq`/`Eq` are part of
/// that promise: every field a later version adds will be `Eq` too.
///
/// **`final_url` and `headers` are not client-safe**, unlike
/// [`SsrfError`]: they can name the redirect target, carry `Set-Cookie`, and
/// reveal what a server said about itself. They are for the server-side
/// caller; do not echo them to whoever chose the URL. `Debug` prints the
/// body's length, never its bytes, no header value, and the URL as
/// `scheme://host[:port]/path`, its query and fragment marked redacted.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FetchResponse {
    /// The body, at most the policy's `max_bytes`: decoded when the policy
    /// decodes and the response was coded (feature `ssrf-decompress`).
    pub body: Bytes,
    /// The response's `Content-Type`, verbatim, if it sent a readable one
    /// (as in [`Fetched`]).
    pub content_type: Option<String>,
    /// The status: one the policy accepts.
    pub status: StatusCode,
    /// The URL of the hop that answered, as requested: normalized (the
    /// IDNA, lower-cased host the fetch pinned, no trailing dot, the default
    /// port elided, WHATWG path rules) and never with userinfo, which the
    /// fetch refuses. Resolve a relative link in the body against this.
    pub final_url: Url,
    /// That hop's response headers, as hyper parsed them (not
    /// byte-verbatim). On a decoded body, `Content-Length` and
    /// `Content-Encoding` here describe the bytes on the wire, not
    /// [`FetchResponse::body`].
    pub headers: HeaderMap,
    /// How many redirects were followed to reach that hop.
    pub redirects: u32,
}

impl fmt::Debug for FetchResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchResponse")
            .field("body", &format_args!("<{} bytes>", self.body.len()))
            .field("status", &self.status)
            .field("final_url", &RedactedUrl(&self.final_url))
            .field("headers", &HeaderNames(&self.headers))
            .field("redirects", &self.redirects)
            .finish_non_exhaustive()
    }
}

/// A `HeaderMap`'s names, one per value, for a `Debug` that must not print
/// the values.
struct HeaderNames<'a>(&'a HeaderMap);

impl fmt::Debug for HeaderNames<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(name, _)| name.as_str()))
            .finish()
    }
}

/// A URL as `scheme://host[:port]/path`, its query and fragment replaced by
/// markers. Userinfo is never printed (the fetch refuses it anyway).
struct RedactedUrl<'a>(&'a Url);

impl fmt::Debug for RedactedUrl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let url = self.0;
        write!(
            f,
            "{}://{}",
            url.scheme(),
            &url[url::Position::BeforeHost..url::Position::AfterPath]
        )?;
        if url.query().is_some() {
            f.write_str("?<redacted>")?;
        }
        if url.fragment().is_some() {
            f.write_str("#<redacted>")?;
        }
        Ok(())
    }
}

impl From<FetchResponse> for Fetched {
    /// The body and content type. Everything else is dropped, which is the
    /// point of the simple form.
    fn from(response: FetchResponse) -> Self {
        Fetched {
            body: response.body,
            content_type: response.content_type,
        }
    }
}

/// Fetch `url` under the full SSRF policy and return the capped body.
///
/// [`fetch_public_response`], reduced to body and content type: what an
/// image fetch needs. Every step and every error is that function's.
pub async fn fetch_public(url: &str, policy: &FetchPolicy) -> Result<Fetched, SsrfError> {
    fetch_public_response(url, policy).await.map(Fetched::from)
}

/// Fetch `url` under the full SSRF policy and return the answering hop's
/// body, status, URL and headers.
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
///      resolver answers only the normalized name, with the pinned address,
///      carrying the policy's `Accept-Encoding`, `Accept` and `User-Agent`;
///    - a 3xx is [`SsrfError::RedirectsNotAllowed`] unless the policy allows
///      redirects, in which case its `Location` is joined onto the current
///      URL and the target goes back to step 1, up to the policy's
///      `max_redirects` ([`SsrfError::TooManyRedirects`]);
///    - a status the policy does not accept (by default, any but `200`) is
///      [`SsrfError::HttpStatus`];
///    - a `Content-Encoding` other than `identity` is
///      [`SsrfError::FetchFailed`], unless the policy decodes (feature
///      `ssrf-decompress`) and it is exactly one of `gzip`, `x-gzip` or
///      `deflate`;
///    - a numeric `Content-Length` over the cap is [`SsrfError::TooLarge`]
///      before a byte of body is read, and so is a streamed body the moment
///      it would pass the cap: `max_bytes` for an unencoded body; for a
///      coded one, a wire cap of `max_bytes + max_bytes / 8 + 4096`, then
///      `max_bytes` on the decoded bytes, decoded in bounded steps that
///      yield, with the budget checked before each step and on every
///      answer, so a decode running past it or answering after it is
///      [`SsrfError::TimedOut`], whatever it came to. No body buffer's
///      capacity passes its cap. A corrupt or truncated coded body is
///      [`SsrfError::FetchFailed`], never a partial one.
///
/// Every other failure is [`SsrfError::FetchFailed`]. No error carries an
/// internal detail; see [`SsrfError`]. The response itself is not
/// client-safe; see [`FetchResponse`].
pub async fn fetch_public_response(
    url: &str,
    policy: &FetchPolicy,
) -> Result<FetchResponse, SsrfError> {
    // Validation does no I/O, so it sits outside the budget, as in Python.
    let target = target::validate(url, policy)?;
    // The budget's own end, for the decoder's checks between steps; `None`
    // where `timeout` would not fit an `Instant`, as tokio's own `timeout`
    // treats it.
    let deadline = Instant::now().checked_add(policy.timeout);
    match tokio::time::timeout(policy.timeout, follow(target, policy, deadline)).await {
        Ok(outcome) => outcome,
        Err(_elapsed) => Err(SsrfError::TimedOut {
            label: policy.label.clone(),
        }),
    }
}

/// What one hop produced.
enum Hop {
    Answer(FetchResponse),
    /// The next URL, joined onto the current one but not yet validated.
    Redirect(Url),
}

async fn follow(
    mut target: Target,
    policy: &FetchPolicy,
    deadline: Option<Instant>,
) -> Result<FetchResponse, SsrfError> {
    for hop in 0..=policy.max_redirects {
        let pinned = pin(&target, policy).await?;
        match request_once(&target, pinned, policy, hop, deadline).await? {
            Hop::Answer(response) => return Ok(response),
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
    hop: u32,
    deadline: Option<Instant>,
) -> Result<Hop, SsrfError> {
    let client = hop_client(target, pinned, policy).map_err(|e| transport_failure(e, policy))?;
    // `identity` unless the policy decodes: there is no decoder to hand a
    // compressed body to otherwise (see `is_identity_encoded`).
    let mut request = client
        .get(target.url.clone())
        .header(ACCEPT_ENCODING, policy.accept_encoding());
    if let Some(accept) = &policy.accept {
        request = request.header(ACCEPT, accept.clone());
    }
    if let Some(user_agent) = &policy.user_agent {
        request = request.header(USER_AGENT, user_agent.clone());
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
    if !policy.accepted.accepts(status) {
        return Err(SsrfError::HttpStatus {
            label: policy.label.clone(),
            status,
        });
    }
    let Some(coding) = classify(response.headers(), policy) else {
        tracing::debug!(label = %policy.label, "refusing a content-encoded response");
        return Err(SsrfError::FetchFailed {
            label: policy.label.clone(),
        });
    };
    let wire_cap = coding.wire_cap(policy.max_bytes);
    if declared_too_large(response.headers(), wire_cap) {
        return Err(policy.too_large());
    }

    let headers = response.headers().clone();
    let wire = read_capped(response.bytes_stream(), wire_cap)
        .await
        .map_err(|e| match e {
            CapError::TooLarge => policy.too_large(),
            CapError::OutOfMemory => out_of_memory(policy),
            CapError::Stream(e) => transport_failure(e, policy),
        })?;
    let body = coding.decode(Bytes::from(wire), policy, deadline).await?;
    Ok(answer(target, hop, status, headers, body))
}

/// The answer of the hop that requested `target`, the `hop`-th: its status
/// and headers, with `body`.
fn answer(target: &Target, hop: u32, status: StatusCode, headers: HeaderMap, body: Bytes) -> Hop {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    Hop::Answer(FetchResponse {
        body,
        content_type,
        status,
        final_url: target.url.clone(),
        headers,
        redirects: hop,
    })
}

/// How a response's body is read, by its `Content-Encoding`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyCoding {
    /// The resource's own bytes: read under `max_bytes`, returned as read.
    Identity,
    /// One coding the policy decodes (feature `ssrf-decompress`).
    #[cfg(feature = "ssrf-decompress")]
    Coded(decode::Coding),
}

impl BodyCoding {
    /// The cap on bytes read from the wire, declared and streamed.
    fn wire_cap(self, max_bytes: usize) -> usize {
        match self {
            Self::Identity => max_bytes,
            #[cfg(feature = "ssrf-decompress")]
            Self::Coded(_) => decode::wire_cap(max_bytes),
        }
    }

    async fn decode(
        self,
        wire: Bytes,
        policy: &FetchPolicy,
        deadline: Option<Instant>,
    ) -> Result<Bytes, SsrfError> {
        match self {
            Self::Identity => {
                let _ = (policy, deadline);
                Ok(wire)
            }
            #[cfg(feature = "ssrf-decompress")]
            Self::Coded(coding) => decode::decode(coding, &wire, policy.max_bytes, deadline)
                .await
                .map_err(|e| match e {
                    decode::DecodeError::TooLarge => policy.too_large(),
                    decode::DecodeError::TimedOut => SsrfError::TimedOut {
                        label: policy.label.clone(),
                    },
                    decode::DecodeError::Corrupt => {
                        tracing::debug!(label = %policy.label, "refusing a corrupt coded body");
                        SsrfError::FetchFailed {
                            label: policy.label.clone(),
                        }
                    }
                    decode::DecodeError::OutOfMemory => out_of_memory(policy),
                }),
        }
    }
}

/// The body's coding, or `None` to refuse it. An identity-encoded response
/// is always readable; a coded one only when the policy decodes it.
pub(super) fn classify(headers: &HeaderMap, policy: &FetchPolicy) -> Option<BodyCoding> {
    if is_identity_encoded(headers) {
        return Some(BodyCoding::Identity);
    }
    #[cfg(feature = "ssrf-decompress")]
    if policy.decompression == super::Decompression::GzipDeflate {
        return decode::classify(headers).map(BodyCoding::Coded);
    }
    let _ = policy;
    None
}

/// Whether the body is the resource's own bytes: no `Content-Encoding` at
/// all, or only `identity` (case-insensitive, in any number of headers and
/// comma-separated codings).
///
/// Anything else is refused rather than decoded — including a server that
/// compresses although the request asked for `identity` — unless the policy
/// decodes (feature `ssrf-decompress`; see `classify`). A deliberate
/// difference from Python, whose httpx decodes gzip/deflate (and brotli/zstd
/// when installed): with no decoder, a compressed body can never be
/// mislabelled as the image it claims to be, and there is no decompression
/// bomb to cap (the module docs, "Compressed responses"). An empty or
/// unreadable value is not `identity`.
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
    /// The buffer for a body within the cap could not be allocated.
    OutOfMemory,
    Stream(E),
}

/// Read `stream` to the end, or stop the moment it would pass `max_bytes`
/// (exactly `max_bytes` is fine). Counts bytes as they arrive, so a
/// `Content-Length` that understates the body cannot buy it more room. The
/// buffer's capacity never passes `max_bytes` either ([`reserve_capped`]).
async fn read_capped<S, E>(stream: S, max_bytes: usize) -> Result<Vec<u8>, CapError<E>>
where
    S: Stream<Item = Result<Bytes, E>>,
{
    let mut stream = std::pin::pin!(stream);
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(CapError::Stream)?;
        // `body.len() <= max_bytes` holds on entry, so this cannot underflow.
        if chunk.len() > max_bytes - body.len() {
            return Err(CapError::TooLarge);
        }
        reserve_capped(&mut body, chunk.len(), max_bytes).map_err(|_| CapError::OutOfMemory)?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The smallest growth [`reserve_capped`] makes, so a body of many tiny
/// chunks is not reallocated for each.
const MIN_GROWTH: usize = 8 * 1024;

/// Room in `buf` for `additional` more bytes, its capacity growing
/// geometrically (doubling, by at least [`MIN_GROWTH`]) but never past
/// `limit`: a capped buffer's allocation is bounded by its cap, where
/// `Vec`'s own doubling could hold nearly twice the cap. The caller keeps
/// `buf.len() + additional <= limit`. `Err` when the allocator refuses the
/// reservation, which the caller reports as a failed fetch.
pub(super) fn reserve_capped(
    buf: &mut Vec<u8>,
    additional: usize,
    limit: usize,
) -> Result<(), TryReserveError> {
    let needed = buf.len().saturating_add(additional);
    if needed <= buf.capacity() {
        return Ok(());
    }
    let doubled = cmp::max(buf.capacity().saturating_mul(2), MIN_GROWTH);
    let target = cmp::max(needed, cmp::min(doubled, limit));
    buf.try_reserve_exact(target - buf.len())
}

/// A body within the caps whose buffer reservation the allocator refused:
/// a failed fetch, logged. (Only these fallible reservations; the fetch's
/// other allocations are ordinary ones.)
fn out_of_memory(policy: &FetchPolicy) -> SsrfError {
    tracing::debug!(label = %policy.label, "could not allocate a capped body buffer");
    SsrfError::FetchFailed {
        label: policy.label.clone(),
    }
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
    use http::HeaderValue;

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
        send_sync::<FetchResponse>();
        send_sync::<crate::ssrf::AcceptedStatuses>();
        #[cfg(feature = "ssrf-decompress")]
        send_sync::<crate::ssrf::Decompression>();
        let policy = FetchPolicy::new("image", 1);
        let future = fetch_public("https://images.example.com/a.png", &policy);
        send(&future);
        let future = fetch_public_response("https://images.example.com/a.png", &policy);
        send(&future);
    }

    fn response(url: &str) -> FetchResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/rss+xml"),
        );
        headers.append(
            "set-cookie",
            HeaderValue::from_static("session=secret-cookie-value"),
        );
        headers.append(
            "set-cookie",
            HeaderValue::from_static("other=second-cookie-value"),
        );
        FetchResponse {
            body: Bytes::from_static(b"<rss/>"),
            content_type: Some("application/rss+xml".to_owned()),
            status: StatusCode::OK,
            final_url: Url::parse(url).unwrap(),
            headers,
            redirects: 2,
        }
    }

    #[test]
    fn a_response_converts_to_its_body_and_content_type() {
        let fetched = Fetched::from(response("https://feeds.example.com/rss"));
        assert_eq!(
            fetched,
            Fetched {
                body: Bytes::from_static(b"<rss/>"),
                content_type: Some("application/rss+xml".to_owned()),
            }
        );
    }

    /// The body's length, never its bytes, and no header value: a `Debug`
    /// ends up in logs, and the body is whatever the server sent.
    #[test]
    fn the_fetched_debug_prints_the_body_length_never_its_bytes() {
        let fetched = Fetched {
            body: Bytes::from_static(b"body-secret"),
            content_type: Some("image/x-type-secret".to_owned()),
        };
        let debug = format!("{fetched:?}");
        assert_eq!(debug, "Fetched { body: <11 bytes>, .. }");
        let pretty = format!("{fetched:#?}");
        for secret in ["body-secret", "type-secret"] {
            assert!(!debug.contains(secret), "{secret} in {debug}");
            assert!(!pretty.contains(secret), "{secret} in {pretty}");
        }
    }

    /// No header value and no query or fragment: `final_url` and `headers`
    /// are not client-safe, and a `Debug` ends up in logs.
    #[test]
    fn the_response_debug_never_prints_a_header_value_or_the_query() {
        let debug = format!(
            "{:?}",
            response("https://feeds.example.com/private/rss.xml?token=query-secret#frag-secret")
        );
        assert_eq!(
            debug,
            "FetchResponse { body: <6 bytes>, status: 200, final_url: \
             https://feeds.example.com/private/rss.xml?<redacted>#<redacted>, \
             headers: [\"content-type\", \"set-cookie\", \"set-cookie\"], redirects: 2, .. }"
        );
        for secret in [
            "query-secret",
            "frag-secret",
            "secret-cookie-value",
            "second-cookie-value",
            "application/rss+xml",
        ] {
            assert!(!debug.contains(secret), "{secret} in {debug}");
        }
        let plain = format!("{:?}", response("https://feeds.example.com/rss"));
        assert!(
            plain.contains("final_url: https://feeds.example.com/rss,"),
            "{plain}"
        );
        let fragment = format!("{:?}", response("https://feeds.example.com/rss#top"));
        assert!(
            fragment.contains("final_url: https://feeds.example.com/rss#<redacted>,"),
            "{fragment}"
        );
        let empty_query = format!("{:?}", response("https://feeds.example.com/rss?"));
        assert!(
            empty_query.contains("final_url: https://feeds.example.com/rss?<redacted>,"),
            "{empty_query}"
        );
        // Userinfo never reaches a fetched URL, and would not be printed if
        // it did; a port is kept.
        let userinfo = format!(
            "{:?}",
            response("https://user:pass-secret@feeds.example.com:8443/rss")
        );
        assert!(
            userinfo.contains("final_url: https://feeds.example.com:8443/rss,"),
            "{userinfo}"
        );
        assert!(!userinfo.contains("pass-secret"), "{userinfo}");
    }

    /// With decoding off (or the feature absent), exactly v0.8.0's check.
    #[test]
    fn without_decoding_only_identity_is_readable() {
        let policy = FetchPolicy::new("image", 1);
        assert_eq!(
            classify(&HeaderMap::new(), &policy),
            Some(BodyCoding::Identity)
        );
        assert_eq!(
            classify(&encoded(&["identity", "Identity"]), &policy),
            Some(BodyCoding::Identity)
        );
        for refused in [
            &["gzip"][..],
            &["deflate"][..],
            &["x-gzip"][..],
            &["identity", "gzip"][..],
        ] {
            assert_eq!(classify(&encoded(refused), &policy), None, "{refused:?}");
        }
        assert_eq!(BodyCoding::Identity.wire_cap(1234), 1234);
    }

    #[cfg(feature = "ssrf-decompress")]
    #[test]
    fn with_decoding_a_coded_body_gets_the_wire_cap() {
        use crate::ssrf::Decompression;
        let policy = FetchPolicy::new("feed", 1).with_decompression(Decompression::GzipDeflate);
        // Decoding never refuses what the identity check accepts.
        for identity in [
            &[][..],
            &["identity"][..],
            &["IDENTITY"][..],
            &["identity, identity"][..],
            &[" identity "][..],
            &["identity", "Identity"][..],
        ] {
            assert_eq!(
                classify(&encoded(identity), &policy),
                Some(BodyCoding::Identity),
                "{identity:?}"
            );
        }
        let gzip = classify(&encoded(&["gzip"]), &policy).expect("decoded");
        assert_eq!(gzip, BodyCoding::Coded(decode::Coding::Gzip));
        // Identity under a decoding policy keeps `max_bytes`.
        assert_eq!(BodyCoding::Identity.wire_cap(8000), 8000);
        assert_eq!(gzip.wire_cap(8000), 8000 + 1000 + 4096);
        assert_eq!(classify(&encoded(&["br"]), &policy), None);
        assert_eq!(classify(&encoded(&["gzip, gzip"]), &policy), None);
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

    /// Capacity, not only length, is capped: a body of 8 MiB + 1 bytes in
    /// 1,000-byte chunks, read under exactly that cap, one over it and one
    /// under it, never leaves the buffer holding more than the cap.
    /// (`Vec`'s or `BytesMut`'s doubling would end at 16 MiB.)
    #[tokio::test]
    async fn the_wire_buffer_never_holds_more_than_the_cap() {
        let size = (8 << 20) + 1;
        let sizes = |total: usize| {
            let mut sizes = vec![1000; total / 1000];
            sizes.push(total % 1000);
            sizes
        };
        for cap in [size, size + 1, size + 4096] {
            let body = read_capped(chunks(&sizes(size)), cap).await.unwrap();
            assert_eq!(body.len(), size);
            assert!(
                body.capacity() <= cap,
                "{cap}: capacity {}",
                body.capacity()
            );
        }
        assert!(matches!(
            read_capped(chunks(&sizes(size)), size - 1).await,
            Err(CapError::TooLarge)
        ));
        // Small bodies still grow geometrically, never by a chunk at a time.
        let mut buf = Vec::new();
        reserve_capped(&mut buf, 1, 1 << 20).unwrap();
        assert_eq!(buf.capacity(), MIN_GROWTH);
        buf.resize(MIN_GROWTH, 0);
        reserve_capped(&mut buf, 1, 1 << 20).unwrap();
        assert_eq!(buf.capacity(), 2 * MIN_GROWTH);
        // And never past the limit, even below the minimum growth.
        let mut small = Vec::new();
        reserve_capped(&mut small, 3, 10).unwrap();
        assert_eq!(small.capacity(), 10);
    }
}
