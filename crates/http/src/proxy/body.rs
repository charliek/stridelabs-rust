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
//!
//! The same bounded read serves the *request* leg
//! ([`buffer_request_or_stream`]) for a caller that needs the uploaded bytes
//! twice — sent to the upstream and replayed to a second one. An over-limit
//! request body streams to the upstream untouched, with the replay skipped.
//!
//! Size is not the only way a body fails to arrive: one that trickles (or
//! stops entirely) is small forever and would hold the buffering open just as
//! long. [`buffer_or_stream_within`] therefore bounds the buffering *in time*
//! as well, demoting to the same prefix-plus-stream fallback at a
//! caller-supplied deadline. Reach for it on any buffering that sits on the
//! client's own response path, where the cost of waiting is paid by the
//! client rather than by a background comparison.

use axum::body::Body;
use axum::BoxError;
use bytes::{Bytes, BytesMut};
use futures::{stream, Stream, StreamExt};
use tokio::time::Instant;

/// The outcome of buffering a body.
///
/// # Non-exhaustive
///
/// Marked `#[non_exhaustive]`: a `match` on this enum outside the crate needs
/// a wildcard arm. This is the house posture for an enum whose variants track
/// a growing set of ways a bounded read can end — the same semver concern
/// [`AppError::Custom`](crate::error::AppError::Custom) handles by the same
/// attribute. It went on in the same change that added [`Buffered::TimedOut`],
/// which was itself a **breaking change** for any pre-existing exhaustive
/// `match`; doing both at once means it is the last such break this enum
/// causes.
#[non_exhaustive]
pub enum Buffered {
    /// The body fit within the limit and is fully buffered.
    Full(Bytes),
    /// The body exceeded the limit; whatever wanted the bytes must skip it.
    /// The carried [`Body`] streams the already-read prefix followed by the
    /// remaining upstream stream, so the client still receives the full,
    /// unbuffered body.
    TooLarge(Body),
    /// The deadline elapsed before the body completed; whatever wanted the
    /// bytes must skip it. Carries the same prefix-plus-remainder [`Body`] as
    /// [`Buffered::TooLarge`] — a slow body is served in full, just
    /// uninspected. Only [`buffer_or_stream_within`] can produce this.
    TimedOut(Body),
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
    buffer_bounded(resp.bytes_stream(), limit, None).await
}

/// As [`buffer_or_stream`], but also bounded in time: at `deadline` the
/// buffering is abandoned and the body is handed back as
/// [`Buffered::TimedOut`] (prefix + remainder), so a body that trickles — or
/// stalls outright — costs the client at most the caller's budget rather than
/// however long the upstream cares to take.
///
/// The deadline is absolute, not a duration, so a caller that has already
/// spent part of a request budget elsewhere can pass what is left of it.
pub async fn buffer_or_stream_within(
    resp: reqwest::Response,
    limit: usize,
    deadline: Instant,
) -> Buffered {
    buffer_bounded(resp.bytes_stream(), limit, Some(deadline)).await
}

/// Buffer a client *request* body up to `limit` bytes, so the identical bytes
/// can be sent to an upstream and replayed to another.
///
/// Same bound and same fallback as [`buffer_or_stream`]: over the limit the
/// body is never fully held in memory, and the returned [`Buffered::TooLarge`]
/// streams prefix + remainder to the upstream unchanged while the caller skips
/// the replay.
pub async fn buffer_request_or_stream(body: Body, limit: usize) -> Buffered {
    buffer_bounded(body.into_data_stream(), limit, None).await
}

/// One turn of the bounded read: the stream produced something (or ended), or
/// the deadline won the race. Carried out of the `select!` below rather than
/// returned from inside it, because the losing branch's borrow of the stream is
/// still live in there and the demotion has to *move* the stream.
enum Step<T> {
    Yielded(Option<T>),
    Expired,
}

/// The shared bounded read behind every entry point: buffer while the running
/// total stays within `limit` and (when given) the clock stays within
/// `deadline`, otherwise hand back the untouched byte sequence as a stream
/// (already-read prefix chained with the rest).
///
/// Generic over the stream and its error type, which is the whole reason there
/// is one implementation instead of three: the response leg feeds it
/// `reqwest::Response::bytes_stream`, the request leg feeds it an axum
/// `Body`'s data stream, and neither has to reimplement the bound.
///
/// The deadline is raced against the `next()` await itself rather than checked
/// between chunks, because the case that matters most is the stream that never
/// yields again: per-chunk arithmetic would never run to notice. It also has to
/// live *inside* this function — an outer `tokio::time::timeout` around the
/// whole call would drop the future that owns both the prefix and the stream,
/// leaving nothing to hand the client.
async fn buffer_bounded<S, E>(stream: S, limit: usize, deadline: Option<Instant>) -> Buffered
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: Into<BoxError> + 'static,
{
    // Boxed so the (possibly `!Unpin`) source stream can be polled here and
    // still be moved into the passthrough fallbacks below.
    let mut stream = Box::pin(stream);
    let mut chunks: Vec<Bytes> = Vec::new();
    let mut total = 0usize;

    // One timer for the whole read, pinned before the loop so every iteration
    // polls the *same* deadline rather than restarting a per-chunk budget.
    let expiry = deadline.map(tokio::time::sleep_until);
    tokio::pin!(expiry);

    loop {
        let step = match expiry.as_mut().as_pin_mut() {
            // One timer, polled *first* on every turn — both halves matter.
            // `timeout_at` gets neither: it builds a fresh `Sleep` per chunk
            // and polls the inner future ahead of it. A fresh `Sleep` is never
            // ready on its first poll (it has to register with the timer driver
            // first), so an upstream whose chunks are always immediately ready
            // means the inner future never yields, the timer is never reached,
            // and the read runs on past the deadline with the size cap as its
            // only remaining bound. Holding one registered timer and giving it
            // the `biased` first look means that once it fires, the very next
            // turn demotes — no matter how eagerly the stream is producing.
            Some(expiry) => tokio::select! {
                biased;
                () = expiry => Step::Expired,
                next = stream.next() => Step::Yielded(next),
            },
            None => Step::Yielded(stream.next().await),
        };
        // Out of budget: the client gets the prefix and the rest of the live
        // stream, exactly as it would for an over-limit body.
        let Step::Yielded(next) = step else {
            return Buffered::TimedOut(prefix_then_rest(chunks, stream));
        };
        match next {
            Some(Ok(chunk)) => {
                total += chunk.len();
                chunks.push(chunk);
                if total > limit {
                    // Over the limit: hand the client the buffered prefix
                    // chained with the rest of the still-open stream.
                    return Buffered::TooLarge(prefix_then_rest(chunks, stream));
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

/// The already-read prefix chained with the rest of the still-open stream — the
/// one body shape every demotion hands back, so the client is served the
/// complete byte sequence whichever bound was hit.
fn prefix_then_rest<S, E>(chunks: Vec<Bytes>, rest: S) -> Body
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: Into<BoxError> + 'static,
{
    let prefix = stream::iter(chunks.into_iter().map(Ok::<Bytes, E>));
    Body::from_stream(prefix.chain(rest))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

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

    // --- the time bound ----------------------------------------------------

    type Chunk = Result<Bytes, std::io::Error>;

    fn one(data: &'static str) -> Chunk {
        Ok(Bytes::from_static(data.as_bytes()))
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_never_yields_again_still_trips_the_deadline() {
        // One half of the deadline contract: no chunk ever arrives, so
        // anything that checked the budget per chunk would never run at all.
        //
        // Paused time is exact here *because* the stream stalls: the task
        // parks, the runtime goes idle, and the clock jumps straight to the
        // deadline. No wall-clock sleep, no flake.
        let stalled = stream::pending::<Chunk>();
        let deadline = Instant::now() + Duration::from_millis(20);
        assert!(matches!(
            buffer_bounded(stalled, 1024, Some(deadline)).await,
            Buffered::TimedOut(_)
        ));
    }

    /// The other half of the deadline contract, and the one a stalled-stream
    /// test cannot see: an upstream whose chunks are *always immediately
    /// ready*, staying under the size cap forever.
    ///
    /// This is the input that separates the pinned, biased timer from a
    /// per-chunk `timeout_at`. `timeout_at` polls the inner future first and
    /// builds a fresh `Sleep` each turn; a fresh `Sleep` is never ready on its
    /// first poll, so a stream that is always ready means the timer is never
    /// reached and the read runs forever with the size cap as its only bound.
    /// Every other deadline test here uses a stream that stops yielding, which
    /// a reverted implementation passes just as happily.
    ///
    /// Three runtime details make it testable, and all three are load-bearing:
    ///
    /// - **A multi-thread runtime.** The buffering task never returns
    ///   `Poll::Pending`, so it never yields to the scheduler, so a
    ///   current-thread runtime never parks and its time driver never advances
    ///   — the deadline could not fire on any implementation. With a second
    ///   worker, an idle thread drives the timer while the first one spins.
    ///   (Measured: ~35k empty chunks buffered over the 20ms window.)
    /// - **Wall-clock time, uniquely in this module.** For the same reason,
    ///   `pause()` is not an option: auto-advance only happens when the
    ///   runtime is idle, and this task is by construction never idle, so a
    ///   paused clock would never reach the deadline and the test would hang
    ///   on every implementation. The 20ms budget against a 10s verdict window
    ///   is what keeps that safe.
    /// - **Its own thread plus a channel.** A regression here is a hang, not a
    ///   failed assertion, and a hot loop that never yields cannot be
    ///   cancelled by runtime shutdown. `recv_timeout` turns the hang into a
    ///   verdict this test can report.
    #[test]
    fn an_always_ready_stream_still_trips_the_deadline() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_time()
                .build()
                .expect("runtime");
            let out = rt.block_on(async {
                // Empty chunks: always ready, and the running total never
                // moves, so the size cap can never end this read. Only the
                // clock can.
                let hot = stream::repeat_with(|| Ok::<Bytes, std::io::Error>(Bytes::new()));
                let deadline = Instant::now() + Duration::from_millis(20);
                buffer_bounded(hot, 1024, Some(deadline)).await
            });
            let _ = tx.send(matches!(out, Buffered::TimedOut(_)));
        });
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(true) => {}
            Ok(false) => panic!("an always-ready stream ended some other way than the deadline"),
            Err(_) => panic!(
                "an always-ready stream ran past its deadline — the timer is being starved by \
                 a stream that is always ready to yield"
            ),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_that_completes_inside_the_deadline_is_buffered_whole() {
        // The false-demotion control: having a deadline must not cost a body
        // that arrives in time.
        let deadline = Instant::now() + Duration::from_secs(30);
        match buffer_or_stream_within(response(b"abcd"), 1024, deadline).await {
            Buffered::Full(bytes) => assert_eq!(&bytes[..], b"abcd"),
            _ => panic!("a body that completes inside the deadline must buffer whole"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_timed_demotion_serves_the_prefix_and_the_remainder_exactly_once() {
        // The demotion is only safe if the client still gets every byte in
        // order and none twice: the prefix already read, then the rest of the
        // stream that was still open when the clock ran out.
        //
        // A channel is the deterministic way to stage that — the tail is only
        // sent *after* the demotion has been observed, so there is no race
        // over which side of the deadline it lands on.
        let (mut tx, rx) = futures::channel::mpsc::channel::<Chunk>(4);
        tx.try_send(one("12345")).expect("prefix queued");

        let resp = upstream_response(http::Response::builder(), reqwest::Body::wrap_stream(rx));
        let deadline = Instant::now() + Duration::from_secs(10);
        let out = buffer_or_stream_within(resp, 1024, deadline).await;

        tx.try_send(one("6789")).expect("remainder queued");
        drop(tx);

        match out {
            Buffered::TimedOut(body) => {
                assert_eq!(&collect_body(body).await[..], b"123456789");
            }
            _ => panic!("a body still open at the deadline must demote to TimedOut"),
        }
    }

    // --- the request leg ---------------------------------------------------

    #[tokio::test]
    async fn a_request_body_of_exactly_the_limit_is_buffered() {
        // Same inclusive boundary as the response leg, over an axum `Body`
        // instead of a `reqwest::Response`.
        match buffer_request_or_stream(Body::from("12345678"), 8).await {
            Buffered::Full(bytes) => assert_eq!(&bytes[..], b"12345678"),
            _ => panic!("a request body of exactly `limit` bytes must be buffered"),
        }
    }

    #[tokio::test]
    async fn a_request_body_one_byte_over_the_limit_streams_the_whole_body() {
        // The upstream still has to receive the request in full; only the
        // replay to a second upstream (or whatever else wanted the bytes) is
        // given up.
        match buffer_request_or_stream(Body::from("123456789"), 8).await {
            Buffered::TooLarge(body) => {
                assert_eq!(&collect_body(body).await[..], b"123456789");
            }
            _ => panic!("a request body of `limit + 1` bytes must stream"),
        }
    }

    #[tokio::test]
    async fn a_request_body_stream_error_is_reported() {
        // A client that disconnects mid-upload is the request-leg twin of an
        // upstream connection reset, and must surface the same way.
        let chunks = stream::iter(vec![
            one("partial"),
            Err(std::io::Error::other("client went away")),
        ]);
        match buffer_request_or_stream(Body::from_stream(chunks), 1024).await {
            Buffered::Error => {}
            _ => panic!("a mid-body request failure must surface as Error"),
        }
    }
}
