//! Translating between the client leg (axum) and the upstream leg (`reqwest`):
//! building the upstream URL, and handing the upstream response back.

use axum::body::Body;
use axum::response::Response;
use http::{HeaderMap, StatusCode};
use url::Url;

use super::filter::{filter_headers, Direction};

/// Build the upstream URL from the upstream origin + the request's path/query.
///
/// The upstream is expected to be an origin (`scheme://host[:port]`). Returns
/// `None` if setting the request path would change it (dot-segment collapse
/// such as `/a/../b`, or a path the URL parser re-encodes) — a proxy should
/// refuse to forward a rewritten path rather than risk sending the upstream a
/// different resource than the client asked for.
///
/// That refusal is a security property, not tidiness. `/public/../admin`
/// normalizes to `/admin`: if the edge authorizes on the raw path and the
/// upstream is handed the collapsed one, every prefix-based access rule in
/// front of this call has just been bypassed. Rejecting is the only answer
/// that cannot be wrong, since the two parties already disagree about what
/// resource was requested.
pub fn build_upstream_url(base: &Url, path: &str, query: Option<&str>) -> Option<Url> {
    let mut url = base.clone();
    url.set_path(path);
    if url.path() != path {
        return None;
    }
    url.set_query(query);
    Some(url)
}

/// Turn the upstream response into a streamed client response.
///
/// The body is never buffered: it is relayed as a stream, so an upstream
/// serving a 4 GiB file costs this process a chunk at a time. Headers go
/// through [`filter_headers`] on the response leg, which is what strips the
/// upstream's hop-by-hop headers while leaving its `content-length` and its
/// (possibly several) `set-cookie`s intact.
pub fn relay_response(resp: reqwest::Response) -> Response {
    let status = resp.status();
    let headers = filter_headers(resp.headers(), Direction::Response);
    response_from_parts(status, headers, Body::from_stream(resp.bytes_stream()))
}

/// Assemble a client response from a status, headers, and body.
///
/// Assigns the whole `HeaderMap` rather than copying entry by entry, so a
/// header that legitimately repeats (`set-cookie`) arrives at the client
/// repeated. Useful on its own when the body has already been taken from the
/// upstream response — after [`buffer_or_stream`](super::buffer_or_stream),
/// say, which consumes it.
pub fn response_from_parts(status: StatusCode, headers: HeaderMap, body: Body) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::super::test_support::{collect_body, upstream_response};
    use super::*;

    #[test]
    fn upstream_url_combines_origin_path_and_query() {
        let base = Url::parse("https://upstream.internal").unwrap();

        let url = build_upstream_url(&base, "/devices/123", Some("verbose=1")).unwrap();

        assert_eq!(
            url.as_str(),
            "https://upstream.internal/devices/123?verbose=1"
        );
    }

    #[test]
    fn upstream_url_without_query() {
        let base = Url::parse("http://localhost:3001").unwrap();

        let url = build_upstream_url(&base, "/health", None).unwrap();

        assert_eq!(url.as_str(), "http://localhost:3001/health");
    }

    #[test]
    fn upstream_url_preserves_percent_encoding() {
        let base = Url::parse("http://h").unwrap();

        let url = build_upstream_url(&base, "/a%20b", Some("q=%2F")).unwrap();

        assert_eq!(url.as_str(), "http://h/a%20b?q=%2F");
    }

    #[test]
    fn upstream_url_refuses_dot_segment_paths() {
        let base = Url::parse("http://h").unwrap();

        // Both literal and percent-encoded dot segments would be rewritten —
        // `/public/../admin` collapses to `/admin`, which is not the path any
        // edge authorization rule was applied to.
        assert!(build_upstream_url(&base, "/a/../admin", None).is_none());
        assert!(build_upstream_url(&base, "/devices/%2e%2e/admin", None).is_none());
    }

    #[tokio::test]
    async fn relay_preserves_status_and_headers() {
        let resp = upstream_response(
            http::Response::builder()
                .status(StatusCode::CREATED)
                .header("content-type", "application/json")
                .header("connection", "keep-alive"),
            "{}",
        );

        let relayed = relay_response(resp);

        assert_eq!(relayed.status(), StatusCode::CREATED);
        assert_eq!(
            relayed.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert!(relayed.headers().get("connection").is_none(), "hop-by-hop");
    }

    #[tokio::test]
    async fn relay_preserves_every_set_cookie() {
        // The canonical multi-value header. A session cookie and a CSRF cookie
        // set in one response is the everyday case, and losing one of them is
        // a silent, intermittent auth bug.
        let resp = upstream_response(
            http::Response::builder()
                .header("set-cookie", "session=abc; HttpOnly")
                .header("set-cookie", "csrf=xyz; Path=/"),
            "",
        );

        let relayed = relay_response(resp);

        let cookies: Vec<&HeaderValue> = relayed.headers().get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 2, "both cookies must reach the client");
        assert_eq!(cookies[0], "session=abc; HttpOnly");
        assert_eq!(cookies[1], "csrf=xyz; Path=/");
    }

    #[test]
    fn response_from_parts_preserves_every_set_cookie() {
        let mut headers = HeaderMap::new();
        headers.append("set-cookie", HeaderValue::from_static("session=abc"));
        headers.append("set-cookie", HeaderValue::from_static("csrf=xyz"));

        let response = response_from_parts(StatusCode::OK, headers, Body::empty());

        let cookies: Vec<&HeaderValue> = response.headers().get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0], "session=abc");
        assert_eq!(cookies[1], "csrf=xyz");
    }

    #[tokio::test]
    async fn relay_streams_the_body_unchanged() {
        let resp = upstream_response(http::Response::builder(), "hello upstream");

        let relayed = relay_response(resp);

        let body = collect_body(relayed.into_body()).await;
        assert_eq!(&body[..], b"hello upstream");
    }
}
