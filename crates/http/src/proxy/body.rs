//! Bounded body buffering, for the paths that need the bytes.
//!
//! Relaying never buffers, so an unbounded body is fine there. A body that has
//! to be *inspected* — compared against a shadow upstream, hashed, rewritten —
//! must be bounded, or a single large response is an out-of-memory. But
//! bounding must not cost the client its response: [`buffer_or_stream`] reads
//! up to the cap and, the moment a body would exceed it, falls back to
//! streaming (the already-read prefix chained with the remaining upstream
//! stream), so the client still receives the complete body and only the
//! inspection is skipped.

use axum::body::Body;
use bytes::{Bytes, BytesMut};
use futures::{stream, StreamExt};

/// The outcome of buffering a response body.
pub enum Buffered {
    /// The body fit within the limit and is fully buffered.
    Full(Bytes),
    /// The body exceeded the limit; whatever wanted the bytes must skip it.
    /// The carried [`Body`] streams the already-read prefix followed by the
    /// remaining upstream stream, so the client still receives the full,
    /// unbuffered body.
    TooLarge(Body),
    /// The upstream body stream errored before completing.
    Error,
}

/// Buffer a reqwest response body up to `limit` bytes, falling back to
/// streaming (prefix + remainder) the moment it would exceed the limit — so an
/// over-limit body is never fully buffered, yet the client is still served the
/// complete body.
///
/// The boundary is inclusive: a body of exactly `limit` bytes is buffered;
/// `limit + 1` streams.
pub async fn buffer_or_stream(resp: reqwest::Response, limit: usize) -> Buffered {
    let mut stream = resp.bytes_stream();
    let mut chunks: Vec<Bytes> = Vec::new();
    let mut total = 0usize;

    loop {
        match stream.next().await {
            Some(Ok(chunk)) => {
                total += chunk.len();
                chunks.push(chunk);
                if total > limit {
                    // Over the limit: hand the client the buffered prefix
                    // chained with the rest of the still-open stream.
                    let prefix = stream::iter(chunks.into_iter().map(Ok::<Bytes, reqwest::Error>));
                    return Buffered::TooLarge(Body::from_stream(prefix.chain(stream)));
                }
            }
            Some(Err(_)) => return Buffered::Error,
            None => break,
        }
    }

    let mut buf = BytesMut::with_capacity(total);
    for chunk in chunks {
        buf.extend_from_slice(&chunk);
    }
    Buffered::Full(buf.freeze())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{collect_body, upstream_response};
    use super::*;

    /// A `reqwest::Response` whose body is exactly `body`, delivered in one
    /// chunk.
    fn response(body: &'static [u8]) -> reqwest::Response {
        upstream_response(http::Response::builder(), body)
    }

    /// A `reqwest::Response` that yields one chunk and then fails, the way a
    /// connection dropped mid-body does.
    fn failing_response(prefix: &'static [u8]) -> reqwest::Response {
        let chunks = stream::iter(vec![
            Ok(Bytes::from_static(prefix)),
            Err(std::io::Error::other("upstream connection reset")),
        ]);
        upstream_response(
            http::Response::builder(),
            reqwest::Body::wrap_stream(chunks),
        )
    }

    #[tokio::test]
    async fn a_body_of_exactly_the_limit_is_buffered() {
        // 8 bytes, cap 8: the check is `>`, so the boundary buffers.
        match buffer_or_stream(response(b"12345678"), 8).await {
            Buffered::Full(bytes) => assert_eq!(&bytes[..], b"12345678"),
            _ => panic!("a body of exactly `limit` bytes must be buffered"),
        }
    }

    #[tokio::test]
    async fn one_byte_over_the_limit_streams_the_whole_body() {
        // 9 bytes, cap 8. The point of the fallback is that the client is
        // still served every byte — the prefix already read plus the rest of
        // the stream — even though nothing may inspect it.
        match buffer_or_stream(response(b"123456789"), 8).await {
            Buffered::TooLarge(body) => {
                assert_eq!(&collect_body(body).await[..], b"123456789");
            }
            _ => panic!("a body of `limit + 1` bytes must stream"),
        }
    }

    #[tokio::test]
    async fn an_empty_body_buffers_empty() {
        match buffer_or_stream(response(b""), 8).await {
            Buffered::Full(bytes) => assert!(bytes.is_empty()),
            _ => panic!("an empty body must buffer"),
        }
    }

    #[tokio::test]
    async fn a_stream_error_is_reported() {
        // The limit is generous, so the only reason to stop is the error.
        match buffer_or_stream(failing_response(b"partial"), 1024).await {
            Buffered::Error => {}
            _ => panic!("a mid-body stream failure must surface as Error"),
        }
    }
}
