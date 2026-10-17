//! The hardened outbound image fetch for MCP tools (feature `image-fetch`):
//! [`ImageFetcher`], the Rust twin of Python `stridelabs.mcp.fetch`.
//!
//! The only place an MCP surface should fetch an image somebody else chose.
//! The SSRF core — URL and host validation, DNS resolution with every answer
//! checked, connection pinning with SNI and `Host` kept on the name, the
//! streaming byte cap, client-safe errors — is stridelabs-http's
//! [`fetch_public`]. This module is the image layer on top:
//!
//! 1. **`https` only, or a `data:` URI** (which involves no network at all).
//! 2. **No redirects**: any 3xx is "URL redirects are not allowed."
//! 3. The download is capped at the caller's `max_bytes`, within a 10 s
//!    wall-clock budget ([`IMAGE_FETCH_TIMEOUT`]), with `Accept: image/*`.
//! 4. Content checks **after** the download: the `Content-Type` must be
//!    `image/*` and neither SVG nor XML — but it is only a claim, so the
//!    bytes must also start with the magic of a supported raster format
//!    (JPEG, PNG, GIF, WebP). SVG is a script container, and no re-encoder
//!    sanitizes it. A `data:` URI's bytes get the same sniff.
//!
//! The bytes returned are raw: the caller still runs them through its own
//! re-encode or storage pipeline, the final sanitizer.
//!
//! Every refusal is an [`ImageFetchError`] whose `Display` is Python's
//! message, byte for byte — specific, and safe to show a model or a user (no
//! address, no port, no internal error text). It converts into
//! [`ToolError::user`], so a tool body writes `fetcher.fetch(&source).await?`.
//!
//! # Differences from Python
//!
//! Those of stridelabs-http's SSRF core (its README lists them — notably a
//! compressed response, `Content-Encoding` other than `identity`, is refused
//! as "Could not fetch the image URL." rather than decoded), and:
//!
//! - the size cap's message for an https body is the caller's
//!   `too_large_detail`, as in Python, but surfaces as
//!   [`ImageFetchError::TooLarge`] on both paths, so a caller can match it.

use std::time::Duration;

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use http::HeaderValue;
use stridelabs_http::ssrf::fetch_public;
use stridelabs_http::ssrf::FetchPolicy;
#[cfg(feature = "test-support")]
pub use stridelabs_http::ssrf::LoopbackTestServer;
pub use stridelabs_http::ssrf::{HostResolver, SsrfError};

use crate::tool::ToolError;

/// The wall-clock budget for one https fetch (DNS, connect, TLS and body):
/// Python's `FETCH_TIMEOUT_SECONDS`.
pub const IMAGE_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

const SCHEME_ERROR: &str = "Only https:// image URLs (or data: URIs) are allowed.";

/// Python's `base64.b64decode(payload, validate=True)`: the standard
/// alphabet only, padding required and canonical (no missing, excess or
/// interior `=`), and — as CPython's `binascii` allows — non-zero bits in
/// the last character's unused low bits.
const STRICT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// A refused or failed image fetch. `Display` is the client-safe message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ImageFetchError {
    /// The https fetch was refused or failed: the SSRF policy (scheme,
    /// credentials, host, address, redirects), the status, the budget, the
    /// transport. Carries stridelabs-http's error, whose message is shown.
    #[error(transparent)]
    Fetch(SsrfError),
    /// Over the caller's `max_bytes`, on either path. Carries the caller's
    /// `too_large_detail`.
    #[error("{0}")]
    TooLarge(String),
    /// A `data:` URI with no `,` before its payload.
    #[error("Invalid data: URI (missing the comma before the payload).")]
    MissingComma,
    /// A `data:` URI without `;base64`.
    #[error("data: URIs must be base64-encoded (data:image/...;base64,...).")]
    NotBase64,
    /// A `data:` URI whose media type is not `image/*`, or names SVG or XML.
    #[error(
        "data: URI must declare an image media type (JPEG, PNG, WebP, or GIF; SVG is not supported)."
    )]
    DataMediaType,
    /// A `data:` URI whose payload is not strict base64.
    #[error("data: URI payload is not valid base64.")]
    InvalidBase64,
    /// A `data:` URI whose payload decodes to nothing.
    #[error("data: URI payload is empty.")]
    EmptyPayload,
    /// An https response whose `Content-Type` is not `image/*`, is SVG, or
    /// ends in `xml` (or is missing).
    #[error("URL did not return an image (Content-Type must be image/*; SVG is not supported).")]
    NotAnImage,
    /// Bytes that do not start like a JPEG, PNG, GIF or WebP, whatever the
    /// headers or the media type said.
    #[error("The fetched content is not a supported image (JPEG, PNG, WebP, or GIF).")]
    UnsupportedFormat,
}

/// Every refusal is the model's to see and act on: [`ToolError::user`].
impl From<ImageFetchError> for ToolError {
    fn from(error: ImageFetchError) -> ToolError {
        ToolError::user(error.to_string())
    }
}

/// Fetches and validates raw image bytes from an `https://` URL or a `data:`
/// URI (see the [module docs](self)).
///
/// ```no_run
/// # async fn tool(source: String) -> Result<(), stridelabs_mcp::ToolError> {
/// use stridelabs_mcp::ImageFetcher;
///
/// let fetcher = ImageFetcher::new(10 * 1024 * 1024, "The image is too large (max 10 MB).");
/// let bytes = fetcher.fetch(&source).await?; // ImageFetchError -> ToolError::user
/// # let _ = bytes;
/// # Ok(())
/// # }
/// ```
///
/// Cheap to clone; build it once.
#[derive(Debug, Clone)]
pub struct ImageFetcher {
    max_bytes: usize,
    too_large_detail: String,
    policy: FetchPolicy,
}

impl ImageFetcher {
    /// A fetcher capping images (a download, or a decoded `data:` payload)
    /// at `max_bytes`, refusing a larger one with `too_large_detail`.
    ///
    /// Its https policy is stridelabs-http's strict one, labelled `image`,
    /// with Python's messages, the same `max_bytes` cap, https only, no
    /// redirects, [`IMAGE_FETCH_TIMEOUT`] and `Accept: image/*`. The fetcher
    /// builds it itself, and the setters below change only what cannot
    /// weaken it: where names resolve, how long a fetch may take, and (for
    /// tests) one loopback TLS server to admit.
    pub fn new(max_bytes: usize, too_large_detail: impl Into<String>) -> ImageFetcher {
        let too_large_detail = too_large_detail.into();
        let policy = FetchPolicy::new("image", max_bytes)
            .with_scheme_error(SCHEME_ERROR)
            .with_too_large_error(too_large_detail.clone())
            .with_timeout(IMAGE_FETCH_TIMEOUT)
            .with_max_redirects(0)
            .with_accept(HeaderValue::from_static("image/*"));
        ImageFetcher {
            max_bytes,
            too_large_detail,
            policy,
        }
    }

    /// Resolve host names with `resolver` instead of the system's (the DNS
    /// seam; a test fakes DNS with a closure). Every answer is still judged
    /// by the public-address policy, so a resolver cannot widen it.
    ///
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr};
    /// use stridelabs_mcp::ImageFetcher;
    ///
    /// let fetcher = ImageFetcher::new(1024, "The image is too large (max 1 KB).")
    ///     .with_resolver(|_host: String, _port: u16| async {
    ///         Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
    ///     });
    /// # let _ = fetcher;
    /// ```
    #[must_use]
    pub fn with_resolver(mut self, resolver: impl HostResolver + 'static) -> ImageFetcher {
        self.policy = self.policy.with_resolver(resolver);
        self
    }

    /// Replace the wall-clock budget for one https fetch
    /// ([`IMAGE_FETCH_TIMEOUT`] by default).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> ImageFetcher {
        self.policy = self.policy.with_timeout(timeout);
        self
    }

    /// **Test code only** (feature `test-support`): also admit `server`, a
    /// local TLS server on a loopback address behind its own CA —
    /// stridelabs-http's `LoopbackTestServer`, which says exactly what that
    /// admits (its named loopback addresses next to the public-address
    /// policy, and its CA instead of the platform roots).
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn with_loopback_test_server(mut self, server: LoopbackTestServer) -> ImageFetcher {
        self.policy = self.policy.with_loopback_test_server(server);
        self
    }

    /// The raw bytes of the image at `source` — an `https://` URL or a
    /// `data:image/…;base64,…` URI — after the whole policy.
    ///
    /// # Errors
    ///
    /// An [`ImageFetchError`] for every refusal and failure; its message is
    /// safe to show the caller.
    pub async fn fetch(&self, source: &str) -> Result<Vec<u8>, ImageFetchError> {
        // RFC 2397: the scheme is case-insensitive.
        let is_data_uri = source
            .get(..5)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("data:"));
        let raw = if is_data_uri {
            self.decode_data_uri(source)?
        } else {
            self.fetch_https(source).await?
        };
        sniff(&raw)?;
        Ok(raw)
    }

    fn too_large(&self) -> ImageFetchError {
        ImageFetchError::TooLarge(self.too_large_detail.clone())
    }

    /// Decode and cap a `data:image/…;base64,…` URI, step for step as Python
    /// does.
    fn decode_data_uri(&self, uri: &str) -> Result<Vec<u8>, ImageFetchError> {
        let Some((header, payload)) = uri.split_once(',') else {
            return Err(ImageFetchError::MissingComma);
        };
        // `data:<mediatype>[;param=value]*[;base64]`; the first five bytes
        // are the ASCII scheme (checked by the caller), so slicing is safe.
        let mut parts = header[5..].split(';');
        let media_type = strip(parts.next().unwrap_or_default()).to_lowercase();
        if !parts.any(|part| strip(part).to_lowercase() == "base64") {
            return Err(ImageFetchError::NotBase64);
        }
        if !media_type.starts_with("image/")
            || media_type.contains("svg")
            || media_type.contains("xml")
        {
            return Err(ImageFetchError::DataMediaType);
        }

        // Whitespace and line wrapping are tolerated (Python's `str.split()`).
        let payload: String = payload.chars().filter(|c| !is_space(*c)).collect();
        // Capped before decoding: base64 expands ~4/3, so bound the encoded
        // length (in characters, as Python's `len`).
        let encoded_cap = (self.max_bytes.saturating_mul(4) / 3).saturating_add(4);
        if payload.chars().count() > encoded_cap {
            return Err(self.too_large());
        }
        let raw = STRICT_BASE64
            .decode(payload.as_bytes())
            .map_err(|_| ImageFetchError::InvalidBase64)?;
        if raw.is_empty() {
            return Err(ImageFetchError::EmptyPayload);
        }
        if raw.len() > self.max_bytes {
            return Err(self.too_large());
        }
        Ok(raw)
    }

    async fn fetch_https(&self, source: &str) -> Result<Vec<u8>, ImageFetchError> {
        let fetched = fetch_public(source, &self.policy)
            .await
            .map_err(|error| match error {
                SsrfError::TooLarge(detail) => ImageFetchError::TooLarge(detail),
                other => ImageFetchError::Fetch(other),
            })?;
        // Python's `content_type.split(";")[0].strip().lower()`, a missing
        // header being "".
        let content_type = fetched.content_type.as_deref().unwrap_or_default();
        let media_type = strip(content_type.split(';').next().unwrap_or_default()).to_lowercase();
        if !media_type.starts_with("image/")
            || media_type.contains("svg")
            || media_type.ends_with("xml")
        {
            return Err(ImageFetchError::NotAnImage);
        }
        Ok(Vec::from(fetched.body))
    }
}

/// Python's `str.isspace`: Unicode `White_Space` (Rust's `char::is_whitespace`)
/// plus the four ASCII information separators, `\x1c` to `\x1f`, which
/// Python counts as whitespace and Unicode does not.
fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// Python's argument-less `str.strip()`.
fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// Require the magic bytes of a supported raster format: never trust a
/// header or a declared media type.
fn sniff(raw: &[u8]) -> Result<(), ImageFetchError> {
    const JPEG: &[u8] = b"\xff\xd8\xff";
    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";
    const GIF87A: &[u8] = b"GIF87a";
    const GIF89A: &[u8] = b"GIF89a";
    let webp = raw.len() >= 12 && &raw[..4] == b"RIFF" && &raw[8..12] == b"WEBP";
    if [JPEG, PNG, GIF87A, GIF89A]
        .iter()
        .any(|magic| raw.starts_with(magic))
        || webp
    {
        Ok(())
    } else {
        Err(ImageFetchError::UnsupportedFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_is_pythons() {
        for c in [
            ' ', '\t', '\n', '\x0b', '\x0c', '\r', '\x1c', '\x1f', '\u{85}', '\u{a0}',
        ] {
            assert!(is_space(c), "{c:?}");
        }
        for c in ['\u{200b}', 'a', '=', '\0'] {
            assert!(!is_space(c), "{c:?}");
        }
        assert_eq!(strip("\x1c image/png \t"), "image/png");
    }

    #[test]
    fn base64_is_as_strict_as_pythons_validate_true() {
        // Each row checked against CPython's `base64.b64decode(s, validate=True)`.
        for (input, expected) in [
            ("QUJD", Some(&b"ABC"[..])),
            ("QUI=", Some(b"AB")),
            ("QUJ=", Some(b"AB")), // non-zero trailing bits: allowed
            ("AB==", Some(b"\x00")),
            ("", Some(b"")),
            ("AAA", None),      // incorrect padding
            ("QQ", None),       // incorrect padding
            ("AAAA====", None), // excess padding
            ("AA==AA==", None), // data after padding
            ("=AAA", None),     // leading padding
            ("AA=A", None),     // discontinuous padding
            ("A", None),
            ("AAAAA", None),
            ("QUJD!", None),
            ("QU JD", None), // whitespace is stripped before decoding, not here
        ] {
            assert_eq!(
                STRICT_BASE64.decode(input).ok().as_deref(),
                expected,
                "{input:?}"
            );
        }
    }

    #[test]
    fn the_sniff_accepts_the_four_formats_only() {
        for good in [
            &b"\xff\xd8\xff\xe0"[..],
            b"\x89PNG\r\n\x1a\n",
            b"GIF87a",
            b"GIF89a",
            b"RIFF\0\0\0\0WEBP",
        ] {
            assert_eq!(sniff(good), Ok(()), "{good:?}");
        }
        for bad in [
            &b""[..],
            b"\xff\xd8",
            b"\x89PNG\r\n\x1a",
            b"GIF88a",
            b"RIFF\0\0\0\0WAVE",
            b"RIFF\0\0\0\0WEB",
            b"<svg/>",
        ] {
            assert_eq!(
                sniff(bad),
                Err(ImageFetchError::UnsupportedFormat),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_policy_is_the_image_policy_and_the_setters_cannot_weaken_it() {
        let fetched = ImageFetcher::new(1024, "The image is too large (max 1 KB).");
        let adjusted = fetched
            .clone()
            .with_resolver(|_host: String, _port: u16| async { Ok(Vec::new()) })
            .with_timeout(Duration::from_secs(3));

        for (fetcher, timeout) in [(&fetched, "timeout: 10s"), (&adjusted, "timeout: 3s")] {
            let debug = format!("{:?}", fetcher.policy);
            assert!(debug.contains(timeout), "{timeout} in {debug}");
            for expected in [
                "label: \"image\"",
                "max_bytes: 1024",
                "HttpsOnly",
                SCHEME_ERROR,
                "The image is too large (max 1 KB).",
                "max_redirects: 0",
                "\"image/*\"",
            ] {
                assert!(debug.contains(expected), "{expected} in {debug}");
            }
        }
    }

    #[test]
    fn every_refusal_becomes_a_user_error_with_its_message() {
        let error = ImageFetchError::UnsupportedFormat;
        assert_eq!(
            ToolError::from(error),
            ToolError::user(
                "The fetched content is not a supported image (JPEG, PNG, WebP, or GIF)."
            )
        );
        assert_eq!(
            ToolError::from(ImageFetchError::Fetch(SsrfError::RedirectsNotAllowed)),
            ToolError::user("URL redirects are not allowed.")
        );
    }
}
