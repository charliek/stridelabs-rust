//! The client: its builder, its bounds, and the one call.

use std::fmt;
use std::time::Duration;

use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{StatusCode, Url};
use serde::Serialize;

use crate::error::{BuildError, MalformedReason, PerplexityError, Phase, UnavailableReason};
use crate::response::SearchAnswer;

/// Perplexity's API, the base URL a client uses unless told otherwise.
pub const DEFAULT_BASE_URL: &str = "https://api.perplexity.ai";

/// The Agent API endpoint, appended to the base URL.
pub const AGENT_PATH: &str = "/v1/agent";

/// The default [`PerplexityClient::timeout`]: the whole exchange, connect to
/// the last body byte. A `fast` search answers in a few seconds; thirty is a
/// hung provider, not a slow one.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The default [`PerplexityClient::max_response_bytes`]. A recorded `fast`
/// answer with ten results is about 15 KB; 2 MiB is two orders of magnitude
/// of headroom and still a bound.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// The default [`PerplexityClient::max_input_chars`].
pub const DEFAULT_MAX_INPUT_CHARS: usize = 2_000;

/// How hard the Agent API works on a search: its `effort`, one of the
/// documented levels, sent as its lowercase name. [`Effort::Fast`] unless
/// set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Effort {
    /// `fast`: the quickest and cheapest, and the default.
    #[default]
    Fast,
    /// `low`.
    Low,
    /// `medium`.
    Medium,
    /// `high`.
    High,
    /// `xhigh`: the most thorough.
    XHigh,
}

impl Effort {
    /// The name sent as `effort`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Effort::Fast => "fast",
            Effort::Low => "low",
            Effort::Medium => "medium",
            Effort::High => "high",
            Effort::XHigh => "xhigh",
        }
    }
}

impl fmt::Display for Effort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What every search is sent with and held to: the builder's settings, which
/// the client keeps as built.
#[derive(Debug, Clone, Copy)]
struct Settings {
    effort: Effort,
    timeout: Duration,
    max_response_bytes: usize,
    max_input_chars: usize,
    max_output_tokens: Option<u32>,
}

/// The Perplexity Agent API web-search client: one search per call,
/// bounded, classified, never retried and never logged.
///
/// Cheap to clone (the `reqwest::Client` is shared). Its `Debug` shows the
/// endpoint, the effort and the bounds, never the key.
#[derive(Clone)]
pub struct PerplexityClient {
    http: reqwest::Client,
    endpoint: Url,
    /// `Bearer <key>`, marked sensitive.
    authorization: HeaderValue,
    settings: Settings,
}

impl fmt::Debug for PerplexityClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PerplexityClient")
            .field("endpoint", &self.endpoint.as_str())
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl PerplexityClient {
    /// A builder for a client that sends `api_key` over `http`.
    ///
    /// **`http` must not follow redirects**: build it with
    /// `reqwest::redirect::Policy::none()`. The crate treats a `3xx` as
    /// [`PerplexityError::Rejected`] only when the client hands it one; a
    /// client that follows it sends the request somewhere the configuration
    /// did not name, and the guard against replaying `Authorization` to
    /// another host is lost (reqwest strips the header on a cross-origin hop,
    /// but a same-origin one keeps it, and a followed answer is read as
    /// Perplexity's).
    ///
    /// **`http` must not retry**: build it with
    /// `.retry(reqwest::retry::never())`. reqwest 0.13's default policy
    /// replays a request the server refused at the protocol level (an HTTP/2
    /// `REFUSED_STREAM`, a GOAWAY), which this crate's "exactly one exchange"
    /// would not survive; whether and when to search again is the caller's.
    ///
    /// **`http` should decode no body**: `.no_gzip().no_brotli().no_deflate()
    /// .no_zstd()`. Any of reqwest's decoders that a crate in the graph turns
    /// on decodes a coded response and drops its `Content-Length`, which
    /// defeats the pre-check ([`PerplexityClient::max_response_bytes`]): a
    /// declared-oversized body that stalls is then waited out to the timeout
    /// instead of refused at once. The chunk-by-chunk cut still bounds it.
    ///
    /// `http` should carry no default credentials, and should use no proxy
    /// the caller did not choose (`no_proxy()`: reqwest otherwise reads
    /// `HTTPS_PROXY`/`ALL_PROXY` from the environment). Its own timeout does
    /// not matter: each request carries [`PerplexityClient::timeout`].
    ///
    /// The key is used verbatim after trimming, as `Authorization: Bearer
    /// <key>`, with the header marked sensitive so hyper never renders it. A
    /// key that is empty after trimming, or holds a byte no header can carry,
    /// is refused by [`PerplexityClientBuilder::build`]. The raw key is not
    /// kept: only the header value is.
    #[must_use]
    pub fn builder(http: reqwest::Client, api_key: &str) -> PerplexityClientBuilder {
        PerplexityClientBuilder {
            http,
            authorization: authorization(api_key),
            base_url: DEFAULT_BASE_URL.to_string(),
            settings: Settings {
                effort: Effort::default(),
                timeout: DEFAULT_TIMEOUT,
                max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
                max_input_chars: DEFAULT_MAX_INPUT_CHARS,
                max_output_tokens: None,
            },
        }
    }

    /// The Agent API URL: the base URL with [`AGENT_PATH`] appended.
    #[must_use]
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// The whole exchange's deadline, connect to the last body byte, a body
    /// that stalls after its headers included. Set on each request
    /// (`RequestBuilder::timeout`), so it holds whatever the client was built
    /// with. Passing it is [`UnavailableReason::Timeout`].
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.settings.timeout
    }

    /// The most response bytes read. A `Content-Length` over it is refused
    /// unread; otherwise the body is read chunk by chunk and cut at the first
    /// chunk that would pass it, never buffered whole.
    /// [`MalformedReason::BodyTooLarge`].
    #[must_use]
    pub fn max_response_bytes(&self) -> usize {
        self.settings.max_response_bytes
    }

    /// The longest input one search may carry, in Unicode scalar values
    /// (`chars().count()`). Longer is [`PerplexityError::InputTooLong`], and
    /// nothing is sent.
    #[must_use]
    pub fn max_input_chars(&self) -> usize {
        self.settings.max_input_chars
    }

    /// The `effort` every search is sent with.
    #[must_use]
    pub fn effort(&self) -> Effort {
        self.settings.effort
    }

    /// The `max_output_tokens` every search is sent with, if any.
    #[must_use]
    pub fn max_output_tokens(&self) -> Option<u32> {
        self.settings.max_output_tokens
    }

    /// Search for `input`: one `POST {base}/v1/agent`, and the completed
    /// answer or why there is none.
    ///
    /// Nothing is retried or logged; a retry is a second billed search, and
    /// the caller decides. The input bound is checked before anything is
    /// sent. The status is classified before any body is read, and a
    /// non-`2xx` body is never read.
    ///
    /// # Errors
    ///
    /// [`PerplexityError`]; the crate docs map each answer to its variant.
    pub async fn search(&self, input: &str) -> Result<SearchAnswer, PerplexityError> {
        let max_input_chars = self.settings.max_input_chars;
        let chars = input.chars().count();
        if chars > max_input_chars {
            return Err(PerplexityError::InputTooLong {
                chars,
                max: max_input_chars,
            });
        }
        let response = self
            .http
            .post(self.endpoint.clone())
            .timeout(self.settings.timeout)
            .header(AUTHORIZATION, self.authorization.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(self.wire_body(input))
            .send()
            .await
            .map_err(|error| {
                let phase = if error.is_connect() {
                    Phase::Connect
                } else {
                    Phase::Headers
                };
                unavailable(phase, &error)
            })?;

        let status = response.status();
        // `>= 500`, not `is_server_error()`: hyper accepts any three-digit
        // status, and `600`–`999` are as unavailable as a `5xx`.
        if status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::TOO_MANY_REQUESTS
            || status.as_u16() >= 500
        {
            return Err(PerplexityError::Unavailable(UnavailableReason::Status(
                status.as_u16(),
            )));
        }
        if !status.is_success() {
            return Err(PerplexityError::Rejected {
                status: status.as_u16(),
            });
        }
        let body = read_capped(response, self.settings.max_response_bytes).await?;
        SearchAnswer::from_json(&body)
    }

    /// The JSON body: `{"effort": …, "input": …, "max_output_tokens"?: …}`,
    /// in that order, the bound omitted when unset.
    fn wire_body(&self, input: &str) -> Vec<u8> {
        #[derive(Serialize)]
        struct WireRequest<'a> {
            effort: &'static str,
            input: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            max_output_tokens: Option<u32>,
        }

        serde_json::to_vec(&WireRequest {
            effort: self.settings.effort.as_str(),
            input,
            max_output_tokens: self.settings.max_output_tokens,
        })
        // Two strings and an integer serialize infallibly.
        .expect("a search request always serializes")
    }
}

/// Settings for a [`PerplexityClient`], from [`PerplexityClient::builder`].
///
/// Its `Debug` shows neither the key nor the base URL (which is not yet
/// validated, and may carry userinfo).
pub struct PerplexityClientBuilder {
    http: reqwest::Client,
    authorization: Result<HeaderValue, BuildError>,
    base_url: String,
    settings: Settings,
}

impl fmt::Debug for PerplexityClientBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PerplexityClientBuilder")
            .field("api_key_usable", &self.authorization.is_ok())
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl PerplexityClientBuilder {
    /// The base URL the endpoint is appended to; [`DEFAULT_BASE_URL`] unless
    /// set. A path prefix is kept and a trailing slash tolerated
    /// (`http://127.0.0.1:58200/perplexity/` requests
    /// `/perplexity/v1/agent`).
    ///
    /// Checked by [`PerplexityClientBuilder::build`]: `https://`, or plain
    /// `http://` to a loopback IP literal (`127.0.0.0/8` or `[::1]`, the
    /// seam for a test's mock; not `localhost`, a name), with no userinfo,
    /// query or fragment.
    #[must_use]
    pub fn base_url(mut self, base_url: impl Into<String>) -> PerplexityClientBuilder {
        self.base_url = base_url.into();
        self
    }

    /// [`PerplexityClient::timeout`]; [`DEFAULT_TIMEOUT`] unless set. Zero is
    /// refused by [`PerplexityClientBuilder::build`].
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> PerplexityClientBuilder {
        self.settings.timeout = timeout;
        self
    }

    /// [`PerplexityClient::max_response_bytes`];
    /// [`DEFAULT_MAX_RESPONSE_BYTES`] unless set. Zero is refused.
    #[must_use]
    pub fn max_response_bytes(mut self, max_response_bytes: usize) -> PerplexityClientBuilder {
        self.settings.max_response_bytes = max_response_bytes;
        self
    }

    /// [`PerplexityClient::max_input_chars`]; [`DEFAULT_MAX_INPUT_CHARS`]
    /// unless set. Zero is refused.
    #[must_use]
    pub fn max_input_chars(mut self, max_input_chars: usize) -> PerplexityClientBuilder {
        self.settings.max_input_chars = max_input_chars;
        self
    }

    /// The `effort` sent; [`Effort::Fast`] unless set.
    #[must_use]
    pub fn effort(mut self, effort: Effort) -> PerplexityClientBuilder {
        self.settings.effort = effort;
        self
    }

    /// `max_output_tokens`, the API's own bound on the answer's length (and
    /// so on what it bills for output). Unset, it is omitted and the API's
    /// default applies. Zero is refused: the API takes an integer of at
    /// least 1. An answer the bound cut short comes back with status
    /// `incomplete`, which is [`PerplexityError::Incomplete`].
    #[must_use]
    pub fn max_output_tokens(mut self, max_output_tokens: u32) -> PerplexityClientBuilder {
        self.settings.max_output_tokens = Some(max_output_tokens);
        self
    }

    /// The client.
    ///
    /// # Errors
    ///
    /// The first [`BuildError`] found: [`BuildError::EmptyApiKey`] or
    /// [`BuildError::InvalidApiKey`] for a key
    /// [`PerplexityClient::builder`] cannot send,
    /// [`BuildError::InvalidBaseUrl`] for a base URL
    /// [`PerplexityClientBuilder::base_url`] does not accept, and a zero
    /// timeout or bound.
    pub fn build(self) -> Result<PerplexityClient, BuildError> {
        let authorization = self.authorization?;
        let endpoint = endpoint(&self.base_url)?;
        let settings = self.settings;
        if settings.timeout.is_zero() {
            return Err(BuildError::ZeroTimeout);
        }
        if settings.max_response_bytes == 0 {
            return Err(BuildError::ZeroMaxResponseBytes);
        }
        if settings.max_input_chars == 0 {
            return Err(BuildError::ZeroMaxInputChars);
        }
        if settings.max_output_tokens == Some(0) {
            return Err(BuildError::ZeroMaxOutputTokens);
        }
        Ok(PerplexityClient {
            http: self.http,
            endpoint,
            authorization,
            settings,
        })
    }
}

/// `Bearer <key>`, the key trimmed and used verbatim, marked sensitive.
fn authorization(api_key: &str) -> Result<HeaderValue, BuildError> {
    let key = api_key.trim();
    if key.is_empty() {
        return Err(BuildError::EmptyApiKey);
    }
    let mut value =
        HeaderValue::from_str(&format!("Bearer {key}")).map_err(|_| BuildError::InvalidApiKey)?;
    value.set_sensitive(true);
    Ok(value)
}

fn invalid(why: &'static str) -> BuildError {
    BuildError::InvalidBaseUrl(why)
}

/// The base URL, checked ([`PerplexityClientBuilder::base_url`]), with
/// [`AGENT_PATH`] appended.
fn endpoint(base_url: &str) -> Result<Url, BuildError> {
    let base = Url::parse(base_url).map_err(|_| invalid("it does not parse as a URL"))?;
    match base.scheme() {
        "https" => {}
        "http" => {
            let loopback = match base.host() {
                Some(url::Host::Ipv4(address)) => address.is_loopback(),
                Some(url::Host::Ipv6(address)) => address.is_loopback(),
                _ => false,
            };
            if !loopback {
                return Err(invalid(
                    "plain http is accepted only to a loopback IP address",
                ));
            }
        }
        _ => return Err(invalid("its scheme is neither https nor http")),
    }
    if !base.username().is_empty() || base.password().is_some() {
        return Err(invalid("it carries userinfo"));
    }
    if base.query().is_some() || base.fragment().is_some() {
        return Err(invalid("it carries a query or a fragment"));
    }
    // With no query or fragment, the serialization ends with the path.
    let joined = format!("{}{AGENT_PATH}", base.as_str().trim_end_matches('/'));
    Url::parse(&joined).map_err(|_| invalid("it does not parse as a URL"))
}

/// A timeout or transport failure in `phase`, as
/// [`PerplexityError::Unavailable`]. The caller drops `error` after this:
/// its source chain can carry what the peer sent (an HTTP/2 GOAWAY's debug
/// data), which `without_url()` would not remove.
fn unavailable(phase: Phase, error: &reqwest::Error) -> PerplexityError {
    PerplexityError::Unavailable(UnavailableReason::from_reqwest(phase, error))
}

/// The most body capacity reserved up front, whatever the `Content-Length`
/// declares: the buffer grows past it only as bytes actually arrive, so a
/// caller's large bound is never one large allocation a lying header asked
/// for.
const INITIAL_BODY_CAPACITY: usize = 64 * 1024;

/// The response body, refused once it passes `max_bytes`: unread when its
/// `Content-Length` already says so, and otherwise read chunk by chunk and
/// cut at the first chunk that would pass it, so a body with no (or a lying)
/// `Content-Length` is bounded too and is never buffered whole. Dropping the
/// response on the way out closes the connection. A body that breaks off is
/// the transport failing, not a malformed answer, and any failure here is a
/// [`Phase::Body`] one.
async fn read_capped(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, PerplexityError> {
    let declared = response.content_length().unwrap_or(0);
    if declared > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(PerplexityError::Malformed(MalformedReason::BodyTooLarge));
    }
    let reserve = usize::try_from(declared)
        .unwrap_or(0)
        .min(INITIAL_BODY_CAPACITY);
    let mut body = Vec::with_capacity(reserve);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| unavailable(Phase::Body, &error))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(PerplexityError::Malformed(MalformedReason::BodyTooLarge));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builder() -> PerplexityClientBuilder {
        PerplexityClient::builder(reqwest::Client::new(), "pplx-key")
    }

    #[test]
    fn the_defaults_are_lumens() {
        let client = builder().build().expect("the defaults build");
        assert_eq!(client.timeout(), Duration::from_secs(30));
        assert_eq!(client.max_response_bytes(), 2 * 1024 * 1024);
        assert_eq!(client.max_input_chars(), 2_000);
        assert_eq!(client.effort(), Effort::Fast);
        assert_eq!(client.max_output_tokens(), None);
        assert_eq!(
            client.endpoint().as_str(),
            "https://api.perplexity.ai/v1/agent"
        );
    }

    #[test]
    fn efforts_are_the_documented_names() {
        let names: Vec<_> = [
            Effort::Fast,
            Effort::Low,
            Effort::Medium,
            Effort::High,
            Effort::XHigh,
        ]
        .into_iter()
        .map(|effort| effort.to_string())
        .collect();
        assert_eq!(names, ["fast", "low", "medium", "high", "xhigh"]);
        assert_eq!(Effort::default(), Effort::Fast);
    }

    #[test]
    fn the_key_is_trimmed_used_verbatim_and_sensitive() {
        let value = authorization("  pplx-abc123 \n").expect("a usable key");
        assert_eq!(value.to_str().expect("ASCII"), "Bearer pplx-abc123");
        assert!(value.is_sensitive());
        assert_eq!(format!("{value:?}"), "Sensitive");
    }

    #[test]
    fn an_empty_or_unheaderable_key_is_refused() {
        for key in ["", "   ", "\t\n"] {
            assert_eq!(authorization(key), Err(BuildError::EmptyApiKey), "{key:?}");
        }
        for key in ["bad\u{1}key", "bad\rkey", "bad\nkey", "del\u{7f}"] {
            assert_eq!(
                authorization(key),
                Err(BuildError::InvalidApiKey),
                "{key:?}"
            );
            let built = PerplexityClient::builder(reqwest::Client::new(), key).build();
            assert_eq!(built.err(), Some(BuildError::InvalidApiKey), "{key:?}");
        }
    }

    #[test]
    fn the_base_url_is_checked() {
        for (base, expected) in [
            (
                "https://api.perplexity.ai",
                "https://api.perplexity.ai/v1/agent",
            ),
            (
                "https://api.perplexity.ai/",
                "https://api.perplexity.ai/v1/agent",
            ),
            (
                "https://proxy.example/perplexity/",
                "https://proxy.example/perplexity/v1/agent",
            ),
            (
                "http://127.0.0.1:58200/perplexity",
                "http://127.0.0.1:58200/perplexity/v1/agent",
            ),
            (
                "http://127.0.0.1:58200/perplexity/",
                "http://127.0.0.1:58200/perplexity/v1/agent",
            ),
            (
                "http://127.1.2.3:1/mock",
                "http://127.1.2.3:1/mock/v1/agent",
            ),
            ("http://[::1]:8080", "http://[::1]:8080/v1/agent"),
        ] {
            assert_eq!(
                endpoint(base).map(String::from).as_deref(),
                Ok(expected),
                "{base}"
            );
        }
        for (base, why) in [
            ("api.perplexity.ai", "it does not parse as a URL"),
            ("", "it does not parse as a URL"),
            (
                "ftp://api.perplexity.ai",
                "its scheme is neither https nor http",
            ),
            ("ws://127.0.0.1:1", "its scheme is neither https nor http"),
            (
                "http://api.perplexity.ai",
                "plain http is accepted only to a loopback IP address",
            ),
            (
                "http://localhost:8080",
                "plain http is accepted only to a loopback IP address",
            ),
            (
                "http://10.0.0.1:8080",
                "plain http is accepted only to a loopback IP address",
            ),
            (
                "http://0.0.0.0:8080",
                "plain http is accepted only to a loopback IP address",
            ),
            ("https://user:pass@api.perplexity.ai", "it carries userinfo"),
            ("https://user@api.perplexity.ai", "it carries userinfo"),
            ("http://u:p@127.0.0.1:1", "it carries userinfo"),
            (
                "https://api.perplexity.ai/?k=v",
                "it carries a query or a fragment",
            ),
            (
                "https://api.perplexity.ai/?",
                "it carries a query or a fragment",
            ),
            (
                "https://api.perplexity.ai/#f",
                "it carries a query or a fragment",
            ),
        ] {
            assert_eq!(endpoint(base), Err(invalid(why)), "{base}");
            let built = builder().base_url(base).build();
            assert_eq!(built.err(), Some(invalid(why)), "{base}");
        }
    }

    #[test]
    fn a_zero_timeout_or_bound_is_refused() {
        for (built, expected) in [
            (
                builder().timeout(Duration::ZERO).build(),
                BuildError::ZeroTimeout,
            ),
            (
                builder().max_response_bytes(0).build(),
                BuildError::ZeroMaxResponseBytes,
            ),
            (
                builder().max_input_chars(0).build(),
                BuildError::ZeroMaxInputChars,
            ),
            (
                builder().max_output_tokens(0).build(),
                BuildError::ZeroMaxOutputTokens,
            ),
        ] {
            assert_eq!(built.err(), Some(expected));
        }
        // One of each is fine.
        let client = builder()
            .timeout(Duration::from_millis(1))
            .max_response_bytes(1)
            .max_input_chars(1)
            .max_output_tokens(1)
            .effort(Effort::XHigh)
            .build()
            .expect("the smallest bounds build");
        assert_eq!(client.max_output_tokens(), Some(1));
        assert_eq!(client.effort(), Effort::XHigh);
    }

    #[test]
    fn debug_never_shows_the_key_or_an_unchecked_url() {
        let builder = PerplexityClient::builder(reqwest::Client::new(), "CANARY-KEY")
            .base_url("https://user:CANARY-URL@api.perplexity.ai");
        let rendered = format!("{builder:?} {builder:#?}");
        assert!(!rendered.contains("CANARY"), "{rendered}");
        assert!(rendered.contains("api_key_usable: true"), "{rendered}");
        let client = PerplexityClient::builder(reqwest::Client::new(), "CANARY-KEY")
            .build()
            .expect("the defaults build");
        let rendered = format!("{client:?} {client:#?}");
        assert!(!rendered.contains("CANARY"), "{rendered}");
        assert!(
            rendered.contains("https://api.perplexity.ai/v1/agent"),
            "{rendered}"
        );
    }
}
