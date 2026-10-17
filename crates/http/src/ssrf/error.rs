//! [`SsrfError`]: every way a guarded fetch can end other than with a body.

use http::StatusCode;

/// A rejected or failed guarded fetch.
///
/// Every message is **safe to show a client** — an LLM, a tool caller, an
/// end user. None of them names an internal host, an address, a port, or the
/// text of an underlying I/O or TLS error; the texts are Python
/// `stridelabs.mcp.ssrf`'s, byte for byte, so a consumer ported from Python
/// keeps its tool errors. The detail behind a transport failure is logged at
/// `debug` (with the URL stripped) and otherwise discarded.
///
/// The variants are listed in the order [`fetch_public`](super::fetch_public)
/// can produce them. Where a message is the caller's (a custom scheme or
/// too-large text) or names the caller's resource (the `label`), the variant
/// carries it, so `Display` is all a consumer needs.
///
/// Marked `#[non_exhaustive]`: a new rejection class is a new variant, and
/// that must not break a consumer's `match`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SsrfError {
    /// The URL does not parse, has no usable host, or a redirect's
    /// `Location` cannot be joined onto the URL that produced it.
    #[error("Invalid URL.")]
    InvalidUrl,
    /// The scheme is not one the policy allows. Carries the full message:
    /// the policy's custom text, or `Only https:// URLs are allowed.` (or
    /// `Only http://, https:// URLs are allowed.`).
    ///
    /// Also what a string with no scheme at all gets (`"not a url at all"`):
    /// Python parses that as a relative URL whose empty scheme fails the
    /// allowlist, and the message is kept.
    #[error("{0}")]
    SchemeNotAllowed(String),
    /// The URL carries a username or password.
    #[error("URLs with embedded credentials are not allowed.")]
    EmbeddedCredentials,
    /// The host is a GCP metadata-server name (`metadata.google.internal`,
    /// any subdomain of it, or the short alias `metadata`).
    #[error("That host is not allowed.")]
    HostNotAllowed,
    /// The host is an IP literal outside the public-address policy.
    #[error("URL host is not a public address.")]
    NonPublicHost,
    /// The resolver failed, or answered with no addresses.
    #[error("Could not resolve the URL host.")]
    ResolutionFailed,
    /// At least one resolved address is outside the public-address policy.
    /// One is enough: a mixed answer is the DNS-rebinding setup the pinning
    /// refuses to race.
    #[error("URL host resolves to a non-public address.")]
    NonPublicResolution,
    /// The response was a 3xx and the policy allows no redirects.
    #[error("URL redirects are not allowed.")]
    RedirectsNotAllowed,
    /// The redirect chain was longer than the policy's `max_redirects`.
    #[error("Too many redirects.")]
    TooManyRedirects,
    /// The response status was not `200 OK`.
    #[error("{} fetch failed with HTTP {}.", capitalize(.label), .status.as_u16())]
    HttpStatus {
        /// The policy's label, as given (rendered capitalized).
        label: String,
        /// The status the server answered with.
        status: StatusCode,
    },
    /// The body is over the policy's byte cap — declared by `Content-Length`
    /// or counted while streaming. Carries the full message: the policy's
    /// custom text, or `The fetched {label} is too large.`
    #[error("{0}")]
    TooLarge(String),
    /// The wall-clock budget ran out (all hops, resolution included).
    #[error("{} fetch timed out.", capitalize(.label))]
    TimedOut {
        /// The policy's label, as given (rendered capitalized).
        label: String,
    },
    /// Any other transport failure — connect, TLS (a certificate that does
    /// not match the host included), a broken body, a 3xx with no usable
    /// `Location` — and a response with a `Content-Encoding` other than
    /// `identity`, which is refused rather than decoded.
    #[error("Could not fetch the {label} URL.")]
    FetchFailed {
        /// The policy's label, as given.
        label: String,
    },
}

/// Python's `str.capitalize`: the first character upper-cased and the rest
/// lower-cased, so `"image"` renders `"Image"` and `"RSS feed"` renders
/// `"Rss feed"`, exactly as the Python messages do.
fn capitalize(label: &str) -> String {
    let mut chars = label.chars();
    match chars.next() {
        Some(first) => first
            .to_uppercase()
            .chain(chars.flat_map(char::to_lowercase))
            .collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capitalize_matches_python_str_capitalize() {
        assert_eq!(capitalize("image"), "Image");
        assert_eq!(capitalize("feed"), "Feed");
        // Python lower-cases everything after the first character.
        assert_eq!(capitalize("RSS feed"), "Rss feed");
        assert_eq!(capitalize(""), "");
    }

    #[test]
    fn every_message_is_pythons_text() {
        let label = || "image".to_owned();
        let cases = [
            (SsrfError::InvalidUrl, "Invalid URL."),
            (
                SsrfError::EmbeddedCredentials,
                "URLs with embedded credentials are not allowed.",
            ),
            (SsrfError::HostNotAllowed, "That host is not allowed."),
            (
                SsrfError::NonPublicHost,
                "URL host is not a public address.",
            ),
            (
                SsrfError::ResolutionFailed,
                "Could not resolve the URL host.",
            ),
            (
                SsrfError::NonPublicResolution,
                "URL host resolves to a non-public address.",
            ),
            (
                SsrfError::RedirectsNotAllowed,
                "URL redirects are not allowed.",
            ),
            (SsrfError::TooManyRedirects, "Too many redirects."),
            (
                SsrfError::HttpStatus {
                    label: label(),
                    status: StatusCode::NOT_FOUND,
                },
                // The bare code, never `StatusCode`'s "404 Not Found".
                "Image fetch failed with HTTP 404.",
            ),
            (
                SsrfError::TimedOut { label: label() },
                "Image fetch timed out.",
            ),
            (
                SsrfError::FetchFailed { label: label() },
                "Could not fetch the image URL.",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected, "{error:?}");
        }
    }
}
