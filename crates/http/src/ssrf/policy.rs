//! [`FetchPolicy`]: what one guarded fetch is allowed to do, and the
//! resolver seam it resolves through.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use http::HeaderValue;

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
/// 10 s budget, the system resolver, and the public-address policy with no
/// exceptions. Each `with_*` method narrows or labels it; **none of them can
/// let a fetch reach a non-public address**. The only way to do that is the
/// `ssrf-test-support` feature's `with_loopback_test_server`, which does not
/// exist in a build without that feature, and with it admits only the
/// loopback addresses its caller names.
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

    /// The DNS seam (default [`SystemResolver`]).
    pub fn with_resolver(mut self, resolver: impl HostResolver + 'static) -> Self {
        self.resolver = Arc::new(resolver);
        self
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
            .field("accept", &self.accept);
        #[cfg(feature = "ssrf-test-support")]
        s.field("test_server", &self.test_server);
        s.finish_non_exhaustive()
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
        assert!(!policy.permits("127.0.0.1".parse().unwrap()));
        assert!(!policy.permits("169.254.169.254".parse().unwrap()));
        assert!(policy.permits("93.184.216.34".parse().unwrap()));
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
