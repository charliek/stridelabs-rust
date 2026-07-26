//! Which headers may cross a proxy hop, and whether a request carries a body.

use http::HeaderMap;

/// Hop-by-hop headers (RFC 7230 §6.1) that must not be forwarded across a
/// proxy: they describe the single connection they arrived on, not the message.
///
/// Compared lowercased, which is how `HeaderName::as_str` renders them.
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Whether headers are being forwarded on the request or response leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client → upstream.
    Request,
    /// Upstream → client.
    Response,
}

/// Copy headers, dropping:
/// - hop-by-hop headers ([`HOP_BY_HOP`] — which includes `transfer-encoding`,
///   dropped in both directions since the relay re-frames the body) and any
///   header named in a `Connection` header's token list (RFC 7230 §6.1);
/// - on the **request** leg, `host` and `content-length` — the upstream client
///   sets Host and frames the streamed request body itself.
///
/// Response `content-length` is preserved: the body is relayed unchanged, so
/// the length still matches (and `HEAD`/`304` keep their meaningful length).
///
/// Repeated headers survive as repeats — the copy appends rather than inserts.
/// That is not a detail: `set-cookie` is the header that is legitimately
/// multi-valued, and an `insert`-based copy silently drops every cookie but the
/// last, which is the kind of bug that shows up as "users randomly get logged
/// out" weeks later.
pub fn filter_headers(src: &HeaderMap, direction: Direction) -> HeaderMap {
    let connection_named = connection_tokens(src);
    let mut out = HeaderMap::with_capacity(src.len());
    for (name, value) in src {
        let n = name.as_str();
        let drop = HOP_BY_HOP.contains(&n)
            || connection_named.iter().any(|t| t == n)
            || (direction == Direction::Request && (n == "host" || n == "content-length"));
        if drop {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// Whether the request carries a body, per its framing headers — a non-zero
/// `content-length` or any `transfer-encoding`.
///
/// Cheap enough to call before touching the body, which is what makes it
/// useful for deciding whether a request is replayable (a shadow or a retry
/// that cannot re-read a consumed stream must not pretend a body-bearing
/// `GET` is body-less).
pub fn request_has_body(headers: &HeaderMap) -> bool {
    if headers.contains_key("transfer-encoding") {
        return true;
    }
    headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > 0)
}

/// Lowercased header names listed in any `Connection` header's comma-separated
/// token list — these are connection-specific and must not be forwarded.
///
/// Iterates *all* `Connection` headers, not just the first: a peer is free to
/// send the list split across several lines, and forwarding a header because
/// its ban arrived on line two is a hole.
pub fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    #[test]
    fn connection_tokens_span_every_connection_header() {
        let mut headers = HeaderMap::new();
        // Split across two header lines, with a comma list, mixed case and
        // stray whitespace in each — all of it legal on the wire.
        headers.append("connection", HeaderValue::from_static("Keep-Alive, X-Foo"));
        headers.append("connection", HeaderValue::from_static("  X-Bar  ,"));

        let tokens = connection_tokens(&headers);

        assert_eq!(tokens, vec!["keep-alive", "x-foo", "x-bar"]);
    }

    #[test]
    fn connection_tokens_are_empty_without_the_header() {
        assert!(connection_tokens(&HeaderMap::new()).is_empty());
    }

    #[test]
    fn filter_drops_hop_by_hop_and_request_only_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("client.example"));
        headers.insert(
            "connection",
            HeaderValue::from_static("keep-alive, x-secret"),
        );
        headers.insert("x-secret", HeaderValue::from_static("leak"));
        headers.insert("content-length", HeaderValue::from_static("5"));
        headers.insert("te", HeaderValue::from_static("trailers"));
        headers.insert("x-tenant-id", HeaderValue::from_static("t-1"));
        headers.insert("authorization", HeaderValue::from_static("Bearer t"));

        let out = filter_headers(&headers, Direction::Request);

        assert!(out.get("host").is_none(), "upstream client sets Host");
        assert!(out.get("connection").is_none(), "hop-by-hop");
        assert!(out.get("te").is_none(), "hop-by-hop");
        assert!(out.get("content-length").is_none(), "body is re-framed");
        assert!(out.get("x-secret").is_none(), "named by Connection");
        // Custom headers are the payload of a proxy hop: they must survive.
        assert_eq!(out.get("x-tenant-id").unwrap(), "t-1");
        assert_eq!(out.get("authorization").unwrap(), "Bearer t");
    }

    #[test]
    fn filter_preserves_response_content_length_and_host() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("12"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("host", HeaderValue::from_static("upstream.internal"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));

        let out = filter_headers(&headers, Direction::Response);

        assert_eq!(out.get("content-length").unwrap(), "12");
        assert_eq!(out.get("content-type").unwrap(), "application/json");
        assert_eq!(out.get("host").unwrap(), "upstream.internal");
        assert!(out.get("transfer-encoding").is_none(), "hop-by-hop");
    }

    #[test]
    fn filter_keeps_repeated_headers_repeated() {
        let mut headers = HeaderMap::new();
        headers.append("set-cookie", HeaderValue::from_static("a=1"));
        headers.append("set-cookie", HeaderValue::from_static("b=2"));

        let out = filter_headers(&headers, Direction::Response);

        let cookies: Vec<_> = out.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 2, "an insert-based copy would keep one");
        assert_eq!(cookies[0], "a=1");
        assert_eq!(cookies[1], "b=2");
    }

    #[test]
    fn detects_request_body_presence() {
        let mut none = HeaderMap::new();
        assert!(!request_has_body(&none));
        none.insert("content-length", HeaderValue::from_static("0"));
        assert!(!request_has_body(&none));

        let mut with_len = HeaderMap::new();
        with_len.insert("content-length", HeaderValue::from_static("12"));
        assert!(request_has_body(&with_len));

        let mut chunked = HeaderMap::new();
        chunked.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        assert!(request_has_body(&chunked));
    }
}
