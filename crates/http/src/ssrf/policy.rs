//! [`FetchPolicy`]: what one guarded fetch is allowed to do, and the
//! resolver seam it resolves through.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use http::header::{IF_MODIFIED_SINCE, IF_NONE_MATCH};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

use super::address::is_public_address;
use super::error::SsrfError;

/// The wall-clock budget a [`FetchPolicy`] starts with: Python's
/// `timeout_seconds=10.0`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// The URL schemes a fetch accepts.
///
/// A closed set rather than a list of strings: reqwest speaks only these two,
/// and both are WHATWG "special" schemes, so `url` IDNA-normalizes their
/// hosts — which the hostname invariant depends on. An opaque-host scheme
/// could not be pinned the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AllowedSchemes {
    /// `https` only — the default, and what an image fetch wants.
    #[default]
    HttpsOnly,
    /// `http` and `https`. For a fetcher such as a feed validator, where many
    /// legitimate URLs are still plain http: the address policy, not the
    /// scheme, is the SSRF control.
    HttpAndHttps,
}

impl AllowedSchemes {
    pub(super) fn allows(self, scheme: &str) -> bool {
        match self {
            Self::HttpsOnly => scheme == "https",
            Self::HttpAndHttps => scheme == "https" || scheme == "http",
        }
    }

    /// Python's `"Only " + ", ".join(sorted(f"{s}://" ...)) + " URLs are allowed."`.
    fn default_message(self) -> &'static str {
        match self {
            Self::HttpsOnly => "Only https:// URLs are allowed.",
            Self::HttpAndHttps => "Only http://, https:// URLs are allowed.",
        }
    }
}

/// Which response statuses a fetch returns a body for.
///
/// A 3xx is never one of them: it is a redirect (or, for a 304 answering a
/// validator on the first hop, the terminal "not modified"; see
/// [`FetchPolicy::with_header`]). Every status the policy does not accept is
/// [`SsrfError::HttpStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum AcceptedStatuses {
    /// `200 OK` only — the default, and Python's.
    #[default]
    OkOnly,
    /// Any `2xx`. A `204` or a `206` returns whatever body it carries,
    /// possibly an empty one: the fetch sends no `Range`, so a `206` is the
    /// server's own choice.
    AnySuccess,
}

impl AcceptedStatuses {
    pub(super) fn accepts(self, status: StatusCode) -> bool {
        match self {
            Self::OkOnly => status == StatusCode::OK,
            Self::AnySuccess => status.is_success(),
        }
    }
}

/// Whether a fetch asks for, and decodes, compressed bodies (feature
/// `ssrf-decompress`).
///
/// Off by default, and an image fetch should keep it off: a decoded body is
/// bytes the server did not send, under the type it claimed.
#[cfg(feature = "ssrf-decompress")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Decompression {
    /// `Accept-Encoding: identity`; a response with any other coding is
    /// refused, exactly as without the feature.
    #[default]
    Off,
    /// `Accept-Encoding: gzip, deflate`. A response coded with exactly one
    /// of `gzip`, `x-gzip` or `deflate` (identity tokens aside) is decoded,
    /// with the policy's `max_bytes` capping the **decoded** body (its
    /// buffer's capacity included) and a slightly larger
    /// cap on the bytes on the wire, within the policy's timeout; anything
    /// else is refused. See the `ssrf` module docs, "Compressed responses".
    GzipDeflate,
}

/// A request header [`FetchPolicy::with_header`] refused: the fetch owns it,
/// or it could reroute, reframe or authenticate the request. The name is in
/// the message (header names are not secret).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the {0} request header is managed by the fetch and cannot be set on a policy")]
pub struct ReservedHeader(HeaderName);

impl ReservedHeader {
    /// The refused name, as [`HeaderName`] normalizes it (lower case).
    pub fn name(&self) -> &HeaderName {
        &self.0
    }
}

/// Request headers no policy may set (see [`FetchPolicy::with_header`] for
/// the classes and why). Lower case, as `HeaderName::as_str` is; every
/// `x-forwarded-*` name is refused besides these.
const RESERVED_HEADERS: [&str; 36] = [
    // Hop-by-hop and framing.
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "content-encoding",
    "expect",
    "http2-settings",
    // Routing.
    "host",
    "forwarded",
    "via",
    "max-forwards",
    "x-real-ip",
    // Method and route overrides.
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "x-original-url",
    "x-rewrite-url",
    // Cloud metadata.
    "metadata-flavor",
    "x-google-metadata-request",
    "metadata",
    "x-aws-ec2-metadata-token",
    "x-aws-ec2-metadata-token-ttl-seconds",
    // Credentials.
    "authorization",
    "proxy-authorization",
    "cookie",
    // Owned by the fetch: `with_accept`, the decompression option,
    // `with_user_agent`.
    "accept",
    "accept-encoding",
    "user-agent",
    // Not yet designed: preconditions and ranges have no semantics here yet
    // (a 412 or a 206 would be read as any other status).
    "if-match",
    "if-unmodified-since",
    "if-range",
    "range",
];

fn is_reserved(name: &HeaderName) -> bool {
    let name = name.as_str();
    RESERVED_HEADERS.contains(&name) || name.starts_with("x-forwarded-")
}

/// The two validators: sent on the first hop only, one value each.
pub(super) fn is_validator(name: &HeaderName) -> bool {
    name == IF_NONE_MATCH || name == IF_MODIFIED_SINCE
}

/// The future a [`HostResolver`] returns.
pub type ResolveFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;

/// The DNS seam (Python's `getaddrinfo` parameter): every A/AAAA address for
/// a host name.
///
/// [`fetch_public`](super::fetch_public) calls it once per hop with the
/// **normalized** host — IDNA-encoded, lower-cased, trailing dot removed —
/// and the effective port, then judges every answer itself. A resolver
/// therefore cannot widen the policy: an answer it returns is either public
/// or the fetch is refused. It is never called for an IP-literal host.
///
/// Implemented for [`SystemResolver`] and for any
/// `Fn(String, u16) -> impl Future<Output = io::Result<Vec<IpAddr>>>`, so a
/// test fakes DNS with a closure:
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
/// use stridelabs_http::ssrf::FetchPolicy;
///
/// let policy = FetchPolicy::new("image", 1024).with_resolver(|_host: String, _port: u16| async {
///     Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
/// });
/// # let _ = policy;
/// ```
pub trait HostResolver: Send + Sync {
    /// Resolve `host` (connecting on `port`) to all of its addresses. An
    /// error, or an empty list, fails the fetch as "Could not resolve the URL
    /// host."
    fn resolve(&self, host: String, port: u16) -> ResolveFuture;
}

impl<F, Fut> HostResolver for F
where
    F: Fn(String, u16) -> Fut + Send + Sync,
    Fut: Future<Output = io::Result<Vec<IpAddr>>> + Send + 'static,
{
    fn resolve(&self, host: String, port: u16) -> ResolveFuture {
        Box::pin(self(host, port))
    }
}

/// The operating system's resolver (`getaddrinfo`, on tokio's blocking
/// pool) — what a [`FetchPolicy`] uses unless told otherwise.
///
/// Answers are reduced to their IP addresses. An IPv6 scope id is dropped
/// with nothing lost: only link-local and multicast addresses carry one, and
/// the address policy denies both, so a scoped answer refuses the fetch
/// either way (and a `url` host can never spell a scope to begin with).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl HostResolver for SystemResolver {
    fn resolve(&self, host: String, port: u16) -> ResolveFuture {
        Box::pin(async move {
            let answers = tokio::net::lookup_host((host.as_str(), port)).await?;
            Ok(answers.map(|addr| addr.ip()).collect())
        })
    }
}

/// What one guarded fetch is allowed to do.
///
/// [`FetchPolicy::new`] is the strict policy: https only, no redirects, a
/// 10 s budget, `200 OK` only, no extra request headers, no content coding,
/// the system resolver, and the public-address policy with no exceptions.
/// The `with_*` methods label, tune or widen it (more schemes, redirects,
/// statuses, headers), but **none of them can let a fetch reach a non-public
/// address**. The only way to do that is the `ssrf-test-support` feature's
/// `with_loopback_test_server`, which does not exist in a build without that
/// feature, and with it admits only the loopback addresses its caller names.
///
/// ```
/// use std::time::Duration;
/// use http::HeaderValue;
/// use stridelabs_http::ssrf::FetchPolicy;
///
/// let policy = FetchPolicy::new("image", 10 * 1024 * 1024)
///     .with_scheme_error("Only https:// image URLs (or data: URIs) are allowed.")
///     .with_too_large_error("The image is too large (max 10 MB).")
///     .with_timeout(Duration::from_secs(10))
///     .with_accept(HeaderValue::from_static("image/*"));
/// # let _ = policy;
/// ```
#[derive(Clone)]
pub struct FetchPolicy {
    pub(super) label: String,
    pub(super) max_bytes: usize,
    pub(super) schemes: AllowedSchemes,
    scheme_error: Option<String>,
    too_large_error: Option<String>,
    pub(super) timeout: Duration,
    pub(super) max_redirects: u32,
    pub(super) accept: Option<HeaderValue>,
    pub(super) user_agent: Option<HeaderValue>,
    /// `with_header`'s headers, none of them reserved.
    pub(super) headers: HeaderMap,
    pub(super) accepted: AcceptedStatuses,
    #[cfg(feature = "ssrf-decompress")]
    pub(super) decompression: Decompression,
    pub(super) resolver: Arc<dyn HostResolver>,
    #[cfg(feature = "ssrf-test-support")]
    pub(super) test_server: Option<LoopbackTestServer>,
}

impl FetchPolicy {
    /// The strict policy for fetching a `label` (`"image"`, `"feed"`: it
    /// names the resource in error messages) of at most `max_bytes`.
    pub fn new(label: impl Into<String>, max_bytes: usize) -> Self {
        Self {
            label: label.into(),
            max_bytes,
            schemes: AllowedSchemes::default(),
            scheme_error: None,
            too_large_error: None,
            timeout: DEFAULT_TIMEOUT,
            max_redirects: 0,
            accept: None,
            user_agent: None,
            headers: HeaderMap::new(),
            accepted: AcceptedStatuses::default(),
            #[cfg(feature = "ssrf-decompress")]
            decompression: Decompression::default(),
            resolver: Arc::new(SystemResolver),
            #[cfg(feature = "ssrf-test-support")]
            test_server: None,
        }
    }

    /// Which schemes to accept (default [`AllowedSchemes::HttpsOnly`]).
    pub fn with_allowed_schemes(mut self, schemes: AllowedSchemes) -> Self {
        self.schemes = schemes;
        self
    }

    /// The message for a rejected scheme, replacing `Only https:// URLs are
    /// allowed.`
    pub fn with_scheme_error(mut self, message: impl Into<String>) -> Self {
        self.scheme_error = Some(message.into());
        self
    }

    /// The message for an over-cap body, replacing `The fetched {label} is
    /// too large.`
    pub fn with_too_large_error(mut self, message: impl Into<String>) -> Self {
        self.too_large_error = Some(message.into());
        self
    }

    /// The wall-clock budget for the whole fetch — resolution, connects, TLS
    /// and body, across every hop (default [`DEFAULT_TIMEOUT`]).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How many redirects to follow (default `0`: any 3xx is "URL redirects
    /// are not allowed."). Every hop is validated, resolved and pinned
    /// afresh.
    pub fn with_max_redirects(mut self, max_redirects: u32) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    /// The `Accept` header to send (default: none).
    pub fn with_accept(mut self, accept: HeaderValue) -> Self {
        self.accept = Some(accept);
        self
    }

    /// The `User-Agent` header to send on every hop (default: none),
    /// replacing any earlier one. Like [`FetchPolicy::with_header`]'s
    /// headers, it is trusted configuration and never a secret.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: HeaderValue) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    /// One more request header (default: none), or [`ReservedHeader`] when
    /// the fetch owns the name or the name could change where the request
    /// goes, how it is framed or whose it is.
    ///
    /// **Policy headers are trusted configuration, never secrets.** Except
    /// the two validators below, they go on every hop, cross-host redirects
    /// included, to hosts a redirect chooses: an `X-Api-Key`, a token or a
    /// `Referer` naming something private would leak. The reserved list
    /// protects the fetch's framing and routing; it does not sanitize an
    /// arbitrary header.
    ///
    /// - **Typed values**, so a CR or LF cannot be injected: such a
    ///   [`HeaderValue`] fails to build before it reaches a policy.
    /// - **Singletons replace**: `If-None-Match` and `If-Modified-Since`
    ///   hold one value each (an `If-None-Match` value may itself list
    ///   several entity tags). Every other name appends, and repeats go out
    ///   as separate header lines.
    /// - **Validators** (`If-None-Match`, `If-Modified-Since`) are sent on
    ///   the first hop only, to the URL the fetch was given, and dropped on
    ///   any redirect: a redirect's target is another resource, and the
    ///   cached validator does not describe it (RFC 9110 section 15.4). A
    ///   `304 Not Modified` answering them on that first hop is the
    ///   fetch's result: no body, never a redirect, whatever
    ///   [`AcceptedStatuses`] says. A `304` on a later hop was not asked for,
    ///   and is a 3xx like any other. Store a validator with the URL it came
    ///   from — the `final_url` of the response that carried it — and send it
    ///   only to that URL.
    ///
    /// Reserved, case-insensitively (the list is part of the contract;
    /// adding a name is a documented behaviour change):
    ///
    /// | Class | Names |
    /// |---|---|
    /// | Hop-by-hop and framing | `connection`, `keep-alive`, `proxy-connection`, `te`, `trailer`, `transfer-encoding`, `upgrade`, `content-length`, `content-encoding` (a GET has no body to code), `expect`, `http2-settings` |
    /// | Routing | `host`, `forwarded`, `via`, `max-forwards`, `x-real-ip`, every `x-forwarded-*` |
    /// | Method and route overrides | `x-http-method-override`, `x-http-method`, `x-method-override`, `x-original-url`, `x-rewrite-url` |
    /// | Cloud metadata | `metadata-flavor`, `x-google-metadata-request`, `metadata`, `x-aws-ec2-metadata-token`, `x-aws-ec2-metadata-token-ttl-seconds` |
    /// | Credentials | `authorization`, `proxy-authorization`, `cookie` |
    /// | Owned by the fetch | `accept` ([`FetchPolicy::with_accept`]), `accept-encoding` (the decompression option), `user-agent` ([`FetchPolicy::with_user_agent`]) |
    /// | Not yet designed | `if-match`, `if-unmodified-since`, `if-range`, `range` |
    ///
    /// ```
    /// use http::{HeaderName, HeaderValue};
    /// use stridelabs_http::ssrf::FetchPolicy;
    ///
    /// let policy = FetchPolicy::new("feed", 10 * 1024 * 1024)
    ///     .with_header(HeaderName::from_static("a-im"), HeaderValue::from_static("feed"))?;
    /// let refused = policy
    ///     .clone()
    ///     .with_header(HeaderName::from_static("authorization"), HeaderValue::from_static("x"));
    /// assert_eq!(refused.unwrap_err().name(), "authorization");
    /// # Ok::<(), stridelabs_http::ssrf::ReservedHeader>(())
    /// ```
    pub fn with_header(
        mut self,
        name: HeaderName,
        value: HeaderValue,
    ) -> Result<Self, ReservedHeader> {
        if is_reserved(&name) {
            return Err(ReservedHeader(name));
        }
        if is_validator(&name) {
            self.headers.insert(name, value);
        } else {
            self.headers.append(name, value);
        }
        Ok(self)
    }

    /// Which statuses return a body (default [`AcceptedStatuses::OkOnly`]).
    #[must_use]
    pub fn with_accepted_statuses(mut self, statuses: AcceptedStatuses) -> Self {
        self.accepted = statuses;
        self
    }

    /// Whether to ask for, and decode, gzip and deflate (feature
    /// `ssrf-decompress`; default [`Decompression::Off`]).
    #[cfg(feature = "ssrf-decompress")]
    #[must_use]
    pub fn with_decompression(mut self, decompression: Decompression) -> Self {
        self.decompression = decompression;
        self
    }

    /// The DNS seam (default [`SystemResolver`]).
    pub fn with_resolver(mut self, resolver: impl HostResolver + 'static) -> Self {
        self.resolver = Arc::new(resolver);
        self
    }

    /// Whether the policy carries a validator, which is what makes a `304`
    /// on the first hop the fetch's answer rather than a redirect.
    pub(super) fn has_validator(&self) -> bool {
        self.headers.keys().any(is_validator)
    }

    /// The `Accept-Encoding` this policy sends.
    pub(super) fn accept_encoding(&self) -> HeaderValue {
        #[cfg(feature = "ssrf-decompress")]
        if self.decompression == Decompression::GzipDeflate {
            return HeaderValue::from_static("gzip, deflate");
        }
        HeaderValue::from_static("identity")
    }

    /// The one address decision every fetch makes: the public-address
    /// policy, plus the loopback addresses a test server names when the
    /// test-support override is on.
    pub(super) fn permits(&self, ip: IpAddr) -> bool {
        #[cfg(feature = "ssrf-test-support")]
        if self
            .test_server
            .as_ref()
            .is_some_and(|s| s.addresses.contains(&ip))
        {
            return true;
        }
        is_public_address(ip)
    }

    pub(super) fn scheme_rejection(&self) -> SsrfError {
        SsrfError::SchemeNotAllowed(
            self.scheme_error
                .clone()
                .unwrap_or_else(|| self.schemes.default_message().to_owned()),
        )
    }

    pub(super) fn too_large(&self) -> SsrfError {
        SsrfError::TooLarge(
            self.too_large_error
                .clone()
                .unwrap_or_else(|| format!("The fetched {} is too large.", self.label)),
        )
    }
}

impl fmt::Debug for FetchPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("FetchPolicy");
        s.field("label", &self.label)
            .field("max_bytes", &self.max_bytes)
            .field("schemes", &self.schemes)
            .field("scheme_error", &self.scheme_error)
            .field("too_large_error", &self.too_large_error)
            .field("timeout", &self.timeout)
            .field("max_redirects", &self.max_redirects)
            .field("accept", &self.accept)
            .field("user_agent", &self.user_agent)
            // Names only: a header's value is the caller's, and this output
            // ends up in logs.
            .field("headers", &HeaderNames(&self.headers))
            .field("accepted_statuses", &self.accepted);
        #[cfg(feature = "ssrf-decompress")]
        s.field("decompression", &self.decompression);
        #[cfg(feature = "ssrf-test-support")]
        s.field("test_server", &self.test_server);
        s.finish_non_exhaustive()
    }
}

/// A `HeaderMap`'s names, one per value, for a `Debug` that must not print
/// the values.
pub(super) struct HeaderNames<'a>(pub(super) &'a HeaderMap);

impl fmt::Debug for HeaderNames<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(name, _)| name.as_str()))
            .finish()
    }
}

/// A local TLS test server a [`FetchPolicy`] may reach (feature
/// `ssrf-test-support`). **Test code only.**
///
/// The pinning can only be proven against a real server, and a test server
/// lives on loopback behind a certificate no public CA issued — the two
/// things the strict policy exists to refuse. This lifts exactly those two,
/// and no more:
///
/// - **The loopback addresses it names**, one by one (`127.0.0.0/8` or
///   `::1`; anything else is refused at construction). They are admitted
///   next to the public-address policy, not instead of it, so every other
///   private, link-local or metadata address is still refused — including in
///   a mixed DNS answer. A second address ([`LoopbackTestServer::also_at`])
///   is what lets a test pin two hops of one host name to two different
///   servers.
/// - **One trust store**: the server's CA bundle, used *instead of* the
///   platform roots, so a fetch under this policy can complete TLS with the
///   test servers and with nothing else.
///
/// # What the feature gate does and does not promise
///
/// - Without `ssrf-test-support` this type, the policy field that holds it
///   and the setter are **compiled out**; no build without the feature can
///   admit a non-public address.
/// - With it, nothing changes for a policy until code explicitly calls
///   [`FetchPolicy::with_loopback_test_server`].
/// - Whether the feature reaches a *shipped* binary is the consumer's to
///   check. `[dev-dependencies]` keeps it out of a plain `cargo build`, but
///   Cargo unifies dev-dependency features into the library under
///   `--all-targets`, and a normal dependency anywhere in the workspace can
///   turn it on for everyone. Guard the release graph: `cargo tree -p
///   <service> -e normal,features -i stridelabs-http --prefix none` must list
///   no `stridelabs-http feature "ssrf-test-support"`.
#[cfg(feature = "ssrf-test-support")]
#[derive(Clone)]
pub struct LoopbackTestServer {
    addresses: Vec<IpAddr>,
    roots: Vec<reqwest::Certificate>,
}

/// Why a [`LoopbackTestServer`] could not be built.
#[cfg(feature = "ssrf-test-support")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoopbackTestServerError {
    /// The address is not loopback, so admitting it would open a real hole.
    #[error("{0} is not a loopback address; a test server override only admits loopback")]
    NotLoopback(IpAddr),
    /// The CA bundle is not PEM certificates.
    #[error("invalid test CA bundle: {0}")]
    InvalidCa(#[source] reqwest::Error),
    /// The CA bundle holds no certificate, which would trust nothing.
    #[error("the test CA bundle holds no certificate")]
    EmptyCa,
}

#[cfg(feature = "ssrf-test-support")]
impl LoopbackTestServer {
    /// A test server at the loopback `address`, whose certificate chains to
    /// the PEM bundle `ca_pem`.
    pub fn new(address: IpAddr, ca_pem: &[u8]) -> Result<Self, LoopbackTestServerError> {
        let address = loopback(address)?;
        let roots = reqwest::Certificate::from_pem_bundle(ca_pem)
            .map_err(LoopbackTestServerError::InvalidCa)?;
        if roots.is_empty() {
            return Err(LoopbackTestServerError::EmptyCa);
        }
        Ok(Self {
            addresses: vec![address],
            roots,
        })
    }

    /// Admit one more loopback `address` (a second listener behind the same
    /// CA), under the same rule as the first.
    pub fn also_at(mut self, address: IpAddr) -> Result<Self, LoopbackTestServerError> {
        self.addresses.push(loopback(address)?);
        Ok(self)
    }

    pub(super) fn trust(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        builder.tls_certs_only(self.roots.iter().cloned())
    }
}

/// The one rule every admitted address passes: loopback, or nothing.
#[cfg(feature = "ssrf-test-support")]
fn loopback(address: IpAddr) -> Result<IpAddr, LoopbackTestServerError> {
    if address.is_loopback() {
        Ok(address)
    } else {
        Err(LoopbackTestServerError::NotLoopback(address))
    }
}

#[cfg(feature = "ssrf-test-support")]
impl fmt::Debug for LoopbackTestServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoopbackTestServer")
            .field("addresses", &self.addresses)
            .field("roots", &self.roots.len())
            .finish()
    }
}

#[cfg(feature = "ssrf-test-support")]
impl FetchPolicy {
    /// **Test code only** (feature `ssrf-test-support`): let this policy
    /// reach `server` — its named loopback addresses, through its CA alone.
    /// See [`LoopbackTestServer`] for exactly what that admits.
    pub fn with_loopback_test_server(mut self, server: LoopbackTestServer) -> Self {
        self.test_server = Some(server);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_strict_policy_is_the_default() {
        let policy = FetchPolicy::new("image", 1024);
        assert_eq!(policy.schemes, AllowedSchemes::HttpsOnly);
        assert_eq!(policy.timeout, Duration::from_secs(10));
        assert_eq!(policy.max_redirects, 0);
        assert!(policy.accept.is_none());
        assert!(policy.user_agent.is_none());
        assert!(policy.headers.is_empty());
        assert_eq!(policy.accepted, AcceptedStatuses::OkOnly);
        #[cfg(feature = "ssrf-decompress")]
        assert_eq!(policy.decompression, Decompression::Off);
        assert_eq!(policy.accept_encoding(), "identity");
        assert!(!policy.has_validator());
        assert!(!policy.permits("127.0.0.1".parse().unwrap()));
        assert!(!policy.permits("169.254.169.254".parse().unwrap()));
        assert!(policy.permits("93.184.216.34".parse().unwrap()));
    }

    fn name(name: &str) -> HeaderName {
        HeaderName::from_bytes(name.as_bytes()).expect("a valid header name")
    }

    fn value(value: &'static str) -> HeaderValue {
        HeaderValue::from_static(value)
    }

    #[test]
    fn every_reserved_name_is_refused_in_any_case() {
        let forwarded = [
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "x-forwarded-prefix",
        ];
        // Title-Case, as a caller might write it.
        fn title_case(name: &str) -> String {
            name.split('-')
                .map(|part| {
                    let mut chars = part.chars();
                    chars.next().map_or_else(String::new, |c| {
                        c.to_ascii_uppercase().to_string() + chars.as_str()
                    })
                })
                .collect::<Vec<_>>()
                .join("-")
        }
        for reserved in RESERVED_HEADERS.iter().chain(&forwarded) {
            for spelling in [
                reserved.to_string(),
                reserved.to_ascii_uppercase(),
                title_case(reserved),
            ] {
                let err = FetchPolicy::new("feed", 1)
                    .with_header(name(&spelling), value("x"))
                    .expect_err(&spelling);
                assert_eq!(err.name().as_str(), *reserved, "{spelling}");
                assert_eq!(
                    err.to_string(),
                    format!("the {reserved} request header is managed by the fetch and cannot be set on a policy")
                );
            }
        }
    }

    /// The pinned table, class by class: a name dropped from the list (or a
    /// class forgotten) fails here, not in production.
    #[test]
    fn the_reserved_list_is_the_documented_one() {
        let documented = [
            "connection",
            "keep-alive",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "content-length",
            "content-encoding",
            "expect",
            "http2-settings",
            "host",
            "forwarded",
            "via",
            "max-forwards",
            "x-real-ip",
            "x-http-method-override",
            "x-http-method",
            "x-method-override",
            "x-original-url",
            "x-rewrite-url",
            "metadata-flavor",
            "x-google-metadata-request",
            "metadata",
            "x-aws-ec2-metadata-token",
            "x-aws-ec2-metadata-token-ttl-seconds",
            "authorization",
            "proxy-authorization",
            "cookie",
            "accept",
            "accept-encoding",
            "user-agent",
            "if-match",
            "if-unmodified-since",
            "if-range",
            "range",
        ];
        let mut listed = RESERVED_HEADERS.to_vec();
        listed.sort_unstable();
        let mut expected = documented.to_vec();
        expected.sort_unstable();
        assert_eq!(listed, expected);
    }

    #[test]
    fn unreserved_names_are_accepted() {
        for allowed in [
            "a-im",
            "if-none-match",
            "if-modified-since",
            "x-custom",
            "x-forwarded",
            "x-request-id",
            "referer",
            "accept-language",
        ] {
            let policy = FetchPolicy::new("feed", 1)
                .with_header(name(allowed), value("v"))
                .unwrap_or_else(|e| panic!("{allowed}: {e}"));
            assert_eq!(policy.headers.get(allowed).unwrap(), "v");
        }
    }

    #[test]
    fn validators_replace_and_every_other_header_appends() {
        let policy = FetchPolicy::new("feed", 1)
            .with_header(name("a-im"), value("feed"))
            .and_then(|p| p.with_header(name("If-None-Match"), value("\"one\"")))
            .and_then(|p| p.with_header(name("x-custom"), value("1")))
            .and_then(|p| p.with_header(name("if-none-match"), value("\"two\", \"three\"")))
            .and_then(|p| p.with_header(name("x-custom"), value("2")))
            .and_then(|p| {
                p.with_header(
                    name("if-modified-since"),
                    value("Mon, 19 Oct 2026 00:00:00 GMT"),
                )
            })
            .and_then(|p| {
                p.with_header(
                    name("if-modified-since"),
                    value("Tue, 20 Oct 2026 00:00:00 GMT"),
                )
            })
            .expect("all allowed");
        let all = |n: &str| -> Vec<&str> {
            policy
                .headers
                .get_all(n)
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect()
        };
        assert_eq!(all("if-none-match"), ["\"two\", \"three\""]);
        assert_eq!(all("if-modified-since"), ["Tue, 20 Oct 2026 00:00:00 GMT"]);
        assert_eq!(all("x-custom"), ["1", "2"]);
        assert_eq!(all("a-im"), ["feed"]);
        assert!(policy.has_validator());
        assert!(FetchPolicy::new("feed", 1)
            .with_header(name("if-modified-since"), value("x"))
            .unwrap()
            .has_validator());
    }

    /// The values are typed: a CR or LF never reaches a policy, for either
    /// validator or any other header.
    #[test]
    fn a_header_injection_fails_before_it_reaches_a_policy() {
        for attempt in [
            "\"etag\"\r\nAuthorization: Basic eA==",
            "Mon, 19 Oct 2026\r\nHost: evil.test",
            "a\nb",
            "a\rb",
            "a\0b",
        ] {
            assert!(HeaderValue::from_str(attempt).is_err(), "{attempt:?}");
        }
        assert!(HeaderName::from_bytes(b"x-custom\r\nhost").is_err());
    }

    #[test]
    fn the_user_agent_replaces() {
        let policy = FetchPolicy::new("feed", 1)
            .with_user_agent(value("first/1"))
            .with_user_agent(value(
                "feedparser/6.0.12 +https://github.com/kurtmckee/feedparser/",
            ));
        assert_eq!(
            policy.user_agent.as_ref().unwrap(),
            "feedparser/6.0.12 +https://github.com/kurtmckee/feedparser/"
        );
    }

    #[test]
    fn accepted_statuses_follow_their_table() {
        for (code, ok_only, any_success) in [
            (200, true, true),
            (201, false, true),
            (203, false, true),
            (204, false, true),
            (206, false, true),
            (299, false, true),
            (100, false, false),
            (199, false, false),
            (300, false, false),
            (304, false, false),
            (404, false, false),
            (500, false, false),
        ] {
            let status = StatusCode::from_u16(code).unwrap();
            assert_eq!(AcceptedStatuses::OkOnly.accepts(status), ok_only, "{code}");
            assert_eq!(
                AcceptedStatuses::AnySuccess.accepts(status),
                any_success,
                "{code}"
            );
        }
    }

    #[cfg(feature = "ssrf-decompress")]
    #[test]
    fn decompression_sets_the_accept_encoding() {
        let policy = FetchPolicy::new("feed", 1).with_decompression(Decompression::GzipDeflate);
        assert_eq!(policy.accept_encoding(), "gzip, deflate");
        let off = policy.with_decompression(Decompression::Off);
        assert_eq!(off.accept_encoding(), "identity");
    }

    /// Debug keeps v0.8.0's fields as they were (the Accept value
    /// included), prints the fixed User-Agent, and prints an extra header's
    /// name, never its value.
    #[test]
    fn the_policy_debug_prints_header_names_never_their_values() {
        let policy = FetchPolicy::new("feed", 5)
            .with_accept(value("application/rss+xml"))
            .with_user_agent(value("feedparser/6.0.12"))
            .with_header(name("x-custom"), value("value-one-of-a-kind"))
            .and_then(|p| p.with_header(name("if-none-match"), value("\"etag-one-of-a-kind\"")))
            .unwrap()
            .with_accepted_statuses(AcceptedStatuses::AnySuccess);
        let debug = format!("{policy:?}");
        for expected in [
            "label: \"feed\"",
            "max_bytes: 5",
            "accept: Some(\"application/rss+xml\")",
            "user_agent: Some(\"feedparser/6.0.12\")",
            "headers: [\"x-custom\", \"if-none-match\"]",
            "accepted_statuses: AnySuccess",
        ] {
            assert!(debug.contains(expected), "{expected} not in {debug}");
        }
        assert!(!debug.contains("one-of-a-kind"), "{debug}");
    }

    #[test]
    fn default_messages_are_pythons() {
        let https = FetchPolicy::new("image", 1);
        assert_eq!(
            https.scheme_rejection().to_string(),
            "Only https:// URLs are allowed."
        );
        let both = FetchPolicy::new("feed", 1).with_allowed_schemes(AllowedSchemes::HttpAndHttps);
        assert_eq!(
            both.scheme_rejection().to_string(),
            "Only http://, https:// URLs are allowed."
        );
        assert_eq!(
            both.too_large().to_string(),
            "The fetched feed is too large."
        );
    }

    #[test]
    fn custom_messages_replace_the_defaults() {
        let policy = FetchPolicy::new("image", 1)
            .with_scheme_error("Only https:// image URLs (or data: URIs) are allowed.")
            .with_too_large_error("The image is too large (max 1 MB).");
        assert_eq!(
            policy.scheme_rejection().to_string(),
            "Only https:// image URLs (or data: URIs) are allowed."
        );
        assert_eq!(
            policy.too_large().to_string(),
            "The image is too large (max 1 MB)."
        );
    }

    #[test]
    fn schemes_are_matched_exactly() {
        assert!(AllowedSchemes::HttpsOnly.allows("https"));
        assert!(!AllowedSchemes::HttpsOnly.allows("http"));
        assert!(AllowedSchemes::HttpAndHttps.allows("http"));
        assert!(AllowedSchemes::HttpAndHttps.allows("https"));
        for other in ["ftp", "file", "gopher", "data", "ws", "wss", ""] {
            assert!(!AllowedSchemes::HttpAndHttps.allows(other), "{other}");
        }
    }
}
