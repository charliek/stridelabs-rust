//! The client: its builder, its bounds, and the one call.

use std::fmt;
use std::time::Duration;

use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{StatusCode, Url};

use crate::error::{
    BuildError, InworldError, MalformedReason, TransportCause, TransportStage, UnavailableReason,
};
use crate::request::SynthesisRequest;
use crate::response::{decode, Synthesis};

/// Inworld's API, the base URL a client uses unless told otherwise.
pub const DEFAULT_BASE_URL: &str = "https://api.inworld.ai";

/// The synthesis endpoint, appended to the base URL.
pub const SYNTHESIS_PATH: &str = "/tts/v1/voice";

/// The default [`InworldBounds::timeout`]: the whole exchange, connect to the
/// last body byte. A 600-character sentence synthesizes in well under a
/// second; fifteen is a hung provider, not a slow one.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// The default [`InworldBounds::max_response_bytes`]. 600 characters of
/// speech at 64 kbit/s is under 400 KB of MP3; 4 MiB is an order of magnitude
/// of headroom and still a bound.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// The default [`InworldBounds::max_audio_bytes`].
pub const DEFAULT_MAX_AUDIO_BYTES: usize = 2 * 1024 * 1024;

/// The default [`InworldBounds::max_text_chars`].
pub const DEFAULT_MAX_TEXT_CHARS: usize = 600;

/// What every synthesis is held to, set through [`InworldClientBuilder`].
/// The defaults are lumen's (and tapper's): 15 s, 4 MiB of response, 2 MiB of
/// audio, 600 characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct InworldBounds {
    /// The whole exchange's deadline, connect to the last body byte, a body
    /// that stalls after its headers included. Set on each request
    /// (`RequestBuilder::timeout`), so it holds whatever the client was built
    /// with. Passing it is [`UnavailableReason::TimedOut`].
    pub timeout: Duration,
    /// The most response bytes read. A `Content-Length` over it is refused
    /// unread; otherwise the body is read chunk by chunk and cut at the first
    /// chunk that would pass it, never buffered whole.
    /// [`MalformedReason::BodyTooLarge`].
    pub max_response_bytes: usize,
    /// The most bytes the audio may decode to: checked on the base64 length
    /// before decoding ([`MalformedReason::AudioContentTooLong`]) and on the
    /// decoded length ([`MalformedReason::AudioTooLarge`]).
    pub max_audio_bytes: usize,
    /// The longest text one synthesis may carry, in Unicode scalar values
    /// (`chars().count()`). Longer is [`InworldError::TextTooLong`], and
    /// nothing is sent.
    pub max_text_chars: usize,
}

impl InworldBounds {
    /// The defaults: [`DEFAULT_TIMEOUT`], [`DEFAULT_MAX_RESPONSE_BYTES`],
    /// [`DEFAULT_MAX_AUDIO_BYTES`] and [`DEFAULT_MAX_TEXT_CHARS`].
    pub const DEFAULT: InworldBounds = InworldBounds {
        timeout: DEFAULT_TIMEOUT,
        max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        max_audio_bytes: DEFAULT_MAX_AUDIO_BYTES,
        max_text_chars: DEFAULT_MAX_TEXT_CHARS,
    };
}

impl Default for InworldBounds {
    fn default() -> InworldBounds {
        InworldBounds::DEFAULT
    }
}

/// The Inworld text-to-speech client: one non-streaming synthesis per call,
/// bounded, classified, never retried and never logged.
///
/// Cheap to clone (the `reqwest::Client` is shared). Its `Debug` shows the
/// endpoint, the bounds, the MP3 check and whether the key is usable, never
/// the key.
#[derive(Clone)]
pub struct InworldClient {
    http: reqwest::Client,
    endpoint: Url,
    /// `Basic <key>`, marked sensitive; `None` when the key is empty or no
    /// header can carry it.
    authorization: Option<HeaderValue>,
    bounds: InworldBounds,
    mp3_check: bool,
}

impl fmt::Debug for InworldClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InworldClient")
            .field("endpoint", &self.endpoint.as_str())
            .field("api_key_usable", &self.authorization.is_some())
            .field("bounds", &self.bounds)
            .field("mp3_check", &self.mp3_check)
            .finish()
    }
}

impl InworldClient {
    /// A builder for a client that sends `api_key` over `http`.
    ///
    /// **`http` must not follow redirects**: build it with
    /// `reqwest::redirect::Policy::none()`, as `client_builder()` (feature
    /// `client-builder`) does. The crate treats a `3xx` as
    /// [`InworldError::Rejected`] only when the client hands it one; a client
    /// that follows it sends the request somewhere the configuration did not
    /// name, and the guard against replaying `Authorization` to another host
    /// is lost (reqwest strips the header on a cross-origin hop, but a
    /// same-origin one keeps it, and a followed answer is read as Inworld's).
    ///
    /// **`http` must not retry**: build it with `.retry(reqwest::retry::never())`.
    /// reqwest 0.13's default policy replays a request the server refused at
    /// the protocol level (an HTTP/2 `REFUSED_STREAM`, a GOAWAY), which this
    /// crate's "never retries" would not survive; whether and when to send a
    /// synthesis again is the caller's.
    ///
    /// **`http` should decode no body**: `.no_gzip().no_brotli().no_deflate()
    /// .no_zstd()`. Any of reqwest's decoders that a crate in the graph turns
    /// on decodes a coded response and drops its `Content-Length`, which
    /// defeats the pre-check ([`InworldBounds::max_response_bytes`]): a
    /// declared-oversized body that stalls is then waited out to the timeout
    /// instead of refused at once. The chunk-by-chunk cut still bounds it.
    ///
    /// `http` should carry no default credentials, and should use no proxy
    /// the caller did not choose (`no_proxy()`: reqwest otherwise reads
    /// `HTTPS_PROXY`/`ALL_PROXY` from the environment). Its own timeout does
    /// not matter: each request carries [`InworldBounds::timeout`].
    /// `client_builder()` (feature `client-builder`) does all of the above.
    ///
    /// The key is used verbatim after trimming (an Inworld key is already the
    /// base64 credential), as `Authorization: Basic <key>`, with the header
    /// marked sensitive so hyper never renders it. A key that is empty after
    /// trimming, or holds a byte no header can carry, makes every synthesis
    /// [`InworldError::UnusableKey`], with nothing sent.
    #[must_use]
    pub fn builder(http: reqwest::Client, api_key: &str) -> InworldClientBuilder {
        InworldClientBuilder {
            http,
            authorization: authorization(api_key),
            base_url: DEFAULT_BASE_URL.to_string(),
            bounds: InworldBounds::DEFAULT,
            mp3_check: true,
        }
    }

    /// The bounds every synthesis is held to.
    #[must_use]
    pub fn bounds(&self) -> InworldBounds {
        self.bounds
    }

    /// The synthesis URL: the base URL with [`SYNTHESIS_PATH`] appended.
    #[must_use]
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Whether a synthesis's audio must open like an MP3.
    #[must_use]
    pub fn checks_mp3(&self) -> bool {
        self.mp3_check
    }

    /// Speak `request`: one `POST {base}/tts/v1/voice`, and the decoded audio
    /// or why there is none.
    ///
    /// Nothing is retried, chunked or logged; a retry is a second billed
    /// synthesis, and the caller decides ([`InworldError::is_retryable`]).
    /// The text bound, the speaking rate and the key are checked before
    /// anything is sent.
    ///
    /// # Errors
    ///
    /// [`InworldError`]; the crate docs map each answer to its variant.
    pub async fn synthesize(
        &self,
        request: &SynthesisRequest<'_>,
    ) -> Result<Synthesis, InworldError> {
        let chars = request.text.chars().count();
        if chars > self.bounds.max_text_chars {
            return Err(InworldError::TextTooLong {
                chars,
                max: self.bounds.max_text_chars,
            });
        }
        if request
            .audio_config
            .speaking_rate
            .is_some_and(|rate| !rate.is_finite())
        {
            return Err(InworldError::SpeakingRateNotFinite);
        }
        let Some(authorization) = self.authorization.clone() else {
            return Err(InworldError::UnusableKey);
        };

        let response = self
            .http
            .post(self.endpoint.clone())
            .timeout(self.bounds.timeout)
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_TYPE, "application/json")
            .body(request.wire_body())
            .send()
            .await
            .map_err(|error| transport(TransportCause::sending(&error)))?;

        let status = response.status();
        // `>= 500`, not `is_server_error()`: hyper accepts any three-digit
        // status, and `600`–`999` are as retryable as a `5xx` (slaudio's
        // Python classifies them the same way).
        if status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::TOO_MANY_REQUESTS
            || status.as_u16() >= 500
        {
            return Err(InworldError::Unavailable {
                reason: UnavailableReason::Status(status.as_u16()),
                cause: None,
            });
        }
        if !status.is_success() {
            return Err(InworldError::Rejected {
                status: status.as_u16(),
            });
        }
        let body = read_capped(response, self.bounds.max_response_bytes).await?;
        decode(&body, self.bounds.max_audio_bytes, self.mp3_check)
    }
}

/// Settings for an [`InworldClient`], from [`InworldClient::builder`].
///
/// Its `Debug` shows neither the key nor the base URL (which is not yet
/// validated, and may carry userinfo).
pub struct InworldClientBuilder {
    http: reqwest::Client,
    authorization: Option<HeaderValue>,
    base_url: String,
    bounds: InworldBounds,
    mp3_check: bool,
}

impl fmt::Debug for InworldClientBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InworldClientBuilder")
            .field("api_key_usable", &self.authorization.is_some())
            .field("bounds", &self.bounds)
            .field("mp3_check", &self.mp3_check)
            .finish_non_exhaustive()
    }
}

impl InworldClientBuilder {
    /// The base URL the endpoint is appended to; [`DEFAULT_BASE_URL`] unless
    /// set. A path prefix is kept and a trailing slash tolerated.
    ///
    /// Checked by [`InworldClientBuilder::build`]: `https://`, or plain
    /// `http://` to a loopback IP literal (`127.0.0.0/8` or `[::1]`, the
    /// seam for a test's mock; not `localhost`, a name), with no userinfo,
    /// query or fragment.
    #[must_use]
    pub fn base_url(mut self, base_url: impl Into<String>) -> InworldClientBuilder {
        self.base_url = base_url.into();
        self
    }

    /// [`InworldBounds::timeout`]; [`DEFAULT_TIMEOUT`] unless set. Zero is
    /// refused by [`InworldClientBuilder::build`].
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> InworldClientBuilder {
        self.bounds.timeout = timeout;
        self
    }

    /// [`InworldBounds::max_response_bytes`]; [`DEFAULT_MAX_RESPONSE_BYTES`]
    /// unless set.
    #[must_use]
    pub fn max_response_bytes(mut self, max_response_bytes: usize) -> InworldClientBuilder {
        self.bounds.max_response_bytes = max_response_bytes;
        self
    }

    /// [`InworldBounds::max_audio_bytes`]; [`DEFAULT_MAX_AUDIO_BYTES`] unless
    /// set.
    #[must_use]
    pub fn max_audio_bytes(mut self, max_audio_bytes: usize) -> InworldClientBuilder {
        self.bounds.max_audio_bytes = max_audio_bytes;
        self
    }

    /// [`InworldBounds::max_text_chars`]; [`DEFAULT_MAX_TEXT_CHARS`] unless
    /// set.
    #[must_use]
    pub fn max_text_chars(mut self, max_text_chars: usize) -> InworldClientBuilder {
        self.bounds.max_text_chars = max_text_chars;
        self
    }

    /// Whether the audio must open like an MP3: an ID3v2 tag, or an MPEG
    /// frame sync (`0xFF` and a byte whose top three bits are set). **On by
    /// default.** Audio that does not is [`MalformedReason::NotMp3`]. The
    /// check is blind to the requested encoding: turn it off for anything but
    /// `MP3`.
    #[must_use]
    pub fn mp3_check(mut self, on: bool) -> InworldClientBuilder {
        self.mp3_check = on;
        self
    }

    /// The client.
    ///
    /// # Errors
    ///
    /// [`BuildError::InvalidBaseUrl`] for a base URL
    /// [`InworldClientBuilder::base_url`] does not accept, and
    /// [`BuildError::ZeroTimeout`]. The key is not an error here: an unusable
    /// one is [`InworldError::UnusableKey`] on each synthesis.
    pub fn build(self) -> Result<InworldClient, BuildError> {
        if self.bounds.timeout.is_zero() {
            return Err(BuildError::ZeroTimeout);
        }
        Ok(InworldClient {
            endpoint: endpoint(&self.base_url)?,
            http: self.http,
            authorization: self.authorization,
            bounds: self.bounds,
            mp3_check: self.mp3_check,
        })
    }
}

/// `Basic <key>`, the key trimmed and used verbatim, marked sensitive; `None`
/// for a key that is empty after trimming or that no header can carry.
fn authorization(api_key: &str) -> Option<HeaderValue> {
    let key = api_key.trim();
    if key.is_empty() {
        return None;
    }
    let mut value = HeaderValue::from_str(&format!("Basic {key}")).ok()?;
    value.set_sensitive(true);
    Some(value)
}

fn invalid(why: &'static str) -> BuildError {
    BuildError::InvalidBaseUrl(why)
}

/// The base URL, checked ([`InworldClientBuilder::base_url`]), with
/// [`SYNTHESIS_PATH`] appended.
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
    let joined = format!("{}{SYNTHESIS_PATH}", base.as_str().trim_end_matches('/'));
    Url::parse(&joined).map_err(|_| invalid("it does not parse as a URL"))
}

/// A transport failure, as [`InworldError::Unavailable`]. The caller made
/// `cause` from the `reqwest::Error` and dropped it: its source chain can
/// carry what the peer sent (an HTTP/2 GOAWAY's debug data), which
/// `without_url()` would not remove.
fn transport(cause: TransportCause) -> InworldError {
    let reason = if cause.timed_out {
        UnavailableReason::TimedOut
    } else if cause.stage == TransportStage::Connect {
        UnavailableReason::Connect
    } else {
        UnavailableReason::Transport
    };
    InworldError::Unavailable {
        reason,
        cause: Some(cause),
    }
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
/// [`TransportStage::Body`] one.
async fn read_capped(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, InworldError> {
    let declared = response.content_length().unwrap_or(0);
    if declared > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(InworldError::Malformed(MalformedReason::BodyTooLarge));
    }
    let reserve = usize::try_from(declared)
        .unwrap_or(0)
        .min(INITIAL_BODY_CAPACITY);
    let mut body = Vec::with_capacity(reserve);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| transport(TransportCause::reading_body(&error)))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(InworldError::Malformed(MalformedReason::BodyTooLarge));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_lumens() {
        assert_eq!(
            InworldBounds::default(),
            InworldBounds {
                timeout: Duration::from_secs(15),
                max_response_bytes: 4 * 1024 * 1024,
                max_audio_bytes: 2 * 1024 * 1024,
                max_text_chars: 600,
            }
        );
        let client = InworldClient::builder(reqwest::Client::new(), "key")
            .build()
            .expect("the defaults build");
        assert_eq!(client.bounds(), InworldBounds::DEFAULT);
        assert!(client.checks_mp3(), "the MP3 check is on by default");
        assert_eq!(
            client.endpoint().as_str(),
            "https://api.inworld.ai/tts/v1/voice"
        );
    }

    #[test]
    fn the_key_is_trimmed_used_verbatim_and_sensitive() {
        let value = authorization("  aWQ6c2VjcmV0 \n").expect("a usable key");
        assert_eq!(value.to_str().expect("ASCII"), "Basic aWQ6c2VjcmV0");
        assert!(value.is_sensitive());
        assert_eq!(format!("{value:?}"), "Sensitive");
    }

    #[test]
    fn an_empty_or_unheaderable_key_is_unusable() {
        for key in [
            "",
            "   ",
            "\t\n",
            "bad\u{1}key",
            "bad\rkey",
            "bad\nkey",
            "del\u{7f}",
        ] {
            assert!(authorization(key).is_none(), "{key:?}");
        }
    }

    #[test]
    fn the_base_url_is_checked() {
        for (base, expected) in [
            (
                "https://api.inworld.ai",
                "https://api.inworld.ai/tts/v1/voice",
            ),
            (
                "https://api.inworld.ai/",
                "https://api.inworld.ai/tts/v1/voice",
            ),
            (
                "https://proxy.example/inworld/",
                "https://proxy.example/inworld/tts/v1/voice",
            ),
            (
                "http://127.0.0.1:8080",
                "http://127.0.0.1:8080/tts/v1/voice",
            ),
            (
                "http://127.1.2.3:1/mock",
                "http://127.1.2.3:1/mock/tts/v1/voice",
            ),
            ("http://[::1]:8080", "http://[::1]:8080/tts/v1/voice"),
        ] {
            assert_eq!(
                endpoint(base).map(String::from).as_deref(),
                Ok(expected),
                "{base}"
            );
        }
        for (base, why) in [
            ("api.inworld.ai", "it does not parse as a URL"),
            ("", "it does not parse as a URL"),
            (
                "ftp://api.inworld.ai",
                "its scheme is neither https nor http",
            ),
            (
                "http://api.inworld.ai",
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
            ("https://user:pass@api.inworld.ai", "it carries userinfo"),
            ("https://user@api.inworld.ai", "it carries userinfo"),
            ("http://u:p@127.0.0.1:1", "it carries userinfo"),
            (
                "https://api.inworld.ai/?k=v",
                "it carries a query or a fragment",
            ),
            (
                "https://api.inworld.ai/#f",
                "it carries a query or a fragment",
            ),
        ] {
            assert_eq!(endpoint(base), Err(invalid(why)), "{base}");
        }
    }

    #[test]
    fn a_zero_timeout_is_refused() {
        let built = InworldClient::builder(reqwest::Client::new(), "key")
            .timeout(Duration::ZERO)
            .build();
        assert!(matches!(built, Err(BuildError::ZeroTimeout)), "{built:?}");
    }

    #[test]
    fn debug_never_shows_the_key() {
        let builder = InworldClient::builder(reqwest::Client::new(), "CANARY-KEY")
            .base_url("https://user:CANARY-URL@api.inworld.ai");
        let rendered = format!("{builder:?}");
        assert!(!rendered.contains("CANARY"), "{rendered}");
        assert!(rendered.contains("api_key_usable: true"), "{rendered}");
        let client = InworldClient::builder(reqwest::Client::new(), "CANARY-KEY")
            .build()
            .expect("the defaults build");
        let rendered = format!("{client:?} {client:#?}");
        assert!(!rendered.contains("CANARY"), "{rendered}");
        assert!(rendered.contains("api_key_usable: true"), "{rendered}");
    }
}
