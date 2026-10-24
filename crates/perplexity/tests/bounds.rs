//! The response bound and the timeout, against servers that break each one
//! (stridelabs-inworld's bounds tests, for this crate's answer):
//!
//! 1. a chunked body (no `Content-Length`, as the recorded real response
//!    came) of exactly the bound is read, and one byte more is cut by the
//!    chunk loop itself;
//! 2. a declared `Content-Length` one byte over the bound is refused, and one
//!    at it read;
//! 3. a declared-oversized `Content-Length` that then stalls, which only a
//!    pre-check answers before the timeout;
//! 4. an endless chunked stream, which must be cut at the bound before the
//!    timeout (a client that buffers the whole body could only time out);
//! 5. a body cut off before its declared length;
//! 6. a stall before the headers, and one after them.
//!
//! All but 2 need a raw TCP server ([`common::RawServer`]): wiremock can
//! delay a whole response, but cannot send its headers and then stall, cut a
//! body off, or stream without end. Each test tells the outcomes apart by
//! their class, never by wall time alone: a client that failed the bound
//! would answer `Timeout`, where the bound's answer is `BodyTooLarge`. Every
//! raw server's handlers are awaited at the end ([`RawServer::finish`]), so a
//! handler's own assertion fails its test. A stalled handler holds its socket
//! until the client hangs up.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{
    answering, builder, chunk, client, completed, malformed, raw_json, unavailable, Flag, Outcome,
    RawServer, HOLD,
};
use stridelabs_perplexity::{
    MalformedReason, PerplexityClient, Phase, UnavailableReason, DEFAULT_MAX_RESPONSE_BYTES,
};

/// A completed answer padded with a field the crate ignores to exactly `len`
/// bytes.
fn padded_body(len: usize) -> String {
    let fitting = completed("Paris.");
    // `"padding":"",` is 13 bytes.
    let padding = len
        .checked_sub(fitting.len() + 13)
        .expect("a length that fits the answer");
    let mut body = fitting;
    body.insert_str(1, &format!(r#""padding":"{}","#, " ".repeat(padding)));
    assert_eq!(body.len(), len);
    body
}

/// A `padded_body(len)` search's outcome, one byte over the bound
/// (`refused`) or at it: `BodyTooLarge`, or the answer read.
fn assert_cut_or_read(outcome: Outcome, len: usize, refused: bool) {
    if refused {
        assert_eq!(
            malformed(&outcome),
            Some(MalformedReason::BodyTooLarge),
            "{len}: {outcome:?}"
        );
    } else {
        assert_eq!(outcome.expect("at the bound").text, "Paris.", "{len}");
    }
}

/// (1) Exactly the bound, and the bound plus one. A chunked
/// body (no `Content-Length`, so no pre-check) is cut by the chunk loop: one
/// byte over, arriving as its own final chunk after the bound's worth, is
/// `BodyTooLarge`; exactly the bound is read. The body is a valid answer
/// either way, so a loop that let one more chunk through would answer the
/// first, and one that cut at the bound itself would refuse the second.
#[tokio::test]
async fn a_chunked_body_at_the_bound_is_read_and_one_byte_over_is_cut() {
    let max = 64 * 1024;
    for (len, refused) in [(max + 1, true), (max, false)] {
        let body = Arc::new(padded_body(len));
        let server = RawServer::start(move |mut exchange| {
            let body = Arc::clone(&body);
            async move {
                let head = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                             transfer-encoding: chunked\r\n\r\n";
                let (most, last) = body.as_bytes().split_at(body.len() - 1);
                let mut sent = exchange.send(head).await;
                for piece in most.chunks(4096).chain([last]) {
                    sent = sent.and(exchange.send(&chunk(piece)).await);
                }
                // A refusing client may already have hung up.
                let _ = sent.and(exchange.send(b"0\r\n\r\n").await);
            }
        })
        .await;
        let perplexity = builder(&server.base_url)
            .max_response_bytes(max)
            .build()
            .expect("builds");
        assert_cut_or_read(perplexity.search("q").await, len, refused);
        drop(perplexity);
        assert_eq!(server.finish().await, 1);
    }
}

/// (2) A body whose `Content-Length` (wiremock sets
/// it) is one byte over the bound is refused; one at the bound is read.
#[tokio::test]
async fn a_declared_body_one_byte_over_the_bound_is_refused() {
    let max = 64 * 1024;
    for (len, refused) in [(max + 1, true), (max, false)] {
        let server = answering(raw_json(200, padded_body(len))).await;
        let outcome = builder(&server.uri())
            .max_response_bytes(max)
            .build()
            .expect("builds")
            .search("q")
            .await;
        assert_cut_or_read(outcome, len, refused);
    }
}

/// The head of a `200` that declares `declared` bytes.
fn declaring(declared: usize) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
         content-length: {declared}\r\n\r\n"
    )
}

/// A server that sends `head` (headers, perhaps the first bytes of a body),
/// sets `headers_sent`, and stalls until the client hangs up.
async fn sending_then_stalling(head: String, headers_sent: Flag) -> RawServer {
    RawServer::start(move |mut exchange| {
        let (head, flag) = (head.clone(), headers_sent.clone());
        async move {
            if exchange.send(head.as_bytes()).await.is_ok() {
                flag.set();
                exchange.hold_until_hangup().await;
            }
        }
    })
    .await
}

/// (3) A `Content-Length` one byte past the 2 MiB default
/// bound, then no body at all: refused unread, at once. A client that read
/// first would wait out its 5 s timeout and answer `Timeout`. The control:
/// the same stall declaring exactly the bound IS read, and so does time out
/// (in the body), which shows the declaration alone decided the first
/// answer.
#[tokio::test]
async fn a_declared_oversized_length_that_stalls_is_refused_unread() {
    let headers_sent = Flag::default();
    let server = sending_then_stalling(
        declaring(DEFAULT_MAX_RESPONSE_BYTES + 1),
        headers_sent.clone(),
    )
    .await;
    let timeout = Duration::from_secs(5);
    let perplexity = builder(&server.base_url)
        .timeout(timeout)
        .build()
        .expect("builds");
    let started = Instant::now();
    let outcome = perplexity.search("q").await;
    let elapsed = started.elapsed();
    assert!(headers_sent.is_set(), "the server never sent its headers");
    assert_eq!(
        malformed(&outcome),
        Some(MalformedReason::BodyTooLarge),
        "{outcome:?}"
    );
    assert!(
        elapsed < timeout,
        "{elapsed:?}: the declared length was not refused before the {timeout:?} timeout"
    );
    drop(perplexity);
    assert_eq!(server.finish().await, 1);

    let at_the_bound = Flag::default();
    let server =
        sending_then_stalling(declaring(DEFAULT_MAX_RESPONSE_BYTES), at_the_bound.clone()).await;
    let perplexity = builder(&server.base_url)
        .timeout(Duration::from_millis(500))
        .build()
        .expect("builds");
    let outcome = perplexity.search("q").await;
    assert!(at_the_bound.is_set(), "the server never sent its headers");
    assert_eq!(
        unavailable(&outcome),
        Some(UnavailableReason::Timeout(Phase::Body)),
        "{outcome:?}"
    );
    drop(perplexity);
    assert_eq!(server.finish().await, 1);
}

/// (4) A `200` with no `Content-Length` whose body never ends:
/// the opening of an answer, then 64 KiB chunks of padding for as long as
/// the client reads. It is cut at the 2 MiB bound, long before the 5 s
/// timeout. A client that read the body whole before measuring it could
/// only time out: `Timeout`, not `BodyTooLarge`.
#[tokio::test]
async fn an_endless_chunked_stream_is_cut_at_the_bound_before_the_timeout() {
    let server = RawServer::start(|mut exchange| async move {
        let head = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     transfer-encoding: chunked\r\n\r\n";
        if exchange.send(head).await.is_err()
            || exchange
                .send(&chunk(br#"{"status":"completed","padding":""#))
                .await
                .is_err()
        {
            return;
        }
        let padding = chunk(&[b' '; 64 * 1024]);
        let started = Instant::now();
        // Until the client hangs up (the write fails), or for longer than any
        // client here waits.
        while started.elapsed() < HOLD {
            if exchange.send(&padding).await.is_err() {
                return;
            }
        }
    })
    .await;
    let timeout = Duration::from_secs(5);
    let perplexity = builder(&server.base_url)
        .timeout(timeout)
        .build()
        .expect("builds");

    let started = Instant::now();
    let outcome = perplexity.search("q").await;
    let elapsed = started.elapsed();
    assert_eq!(
        malformed(&outcome),
        Some(MalformedReason::BodyTooLarge),
        "{outcome:?}"
    );
    assert!(
        elapsed < timeout,
        "{elapsed:?}: the stream was not cut before the {timeout:?} timeout"
    );
    drop(perplexity);
    assert_eq!(server.finish().await, 1);
}

/// (5) A body that breaks off before its declared length is the
/// transport failing in the body (`Unavailable`), not a malformed answer.
#[tokio::test]
async fn a_truncated_body_is_unavailable() {
    let server = RawServer::start(|mut exchange| async move {
        let body = completed("Paris.");
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );
        let _ = exchange.send(head.as_bytes()).await;
        let _ = exchange.send(&body.as_bytes()[..body.len() / 2]).await;
        // Dropping the stream closes it with half the body sent.
    })
    .await;
    let outcome = client(&server.base_url).search("q").await;
    assert!(
        matches!(
            unavailable(&outcome),
            Some(UnavailableReason::Transport {
                phase: Phase::Body,
                ..
            })
        ),
        "{outcome:?}"
    );
    assert_eq!(server.finish().await, 1);
}

/// (6) After the headers: a `200` whose headers (and the first
/// bytes of its body) arrive, and whose body then stalls: the timeout covers
/// the body, not just the headers, and the stall is a timeout in the body.
/// The client is built with no timeout, and with a long one: the bound is set
/// on the request, so it holds either way.
#[tokio::test]
async fn a_stall_after_the_headers_times_out_in_the_body() {
    let headers_sent = Flag::default();
    let head = format!(r#"{}{{"status":""#, declaring(64));
    let server = sending_then_stalling(head, headers_sent.clone()).await;
    let timeout = Duration::from_millis(500);
    for http in [
        common::http(),
        common::http_builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("builds"),
    ] {
        let perplexity = PerplexityClient::builder(http, common::KEY)
            .base_url(&server.base_url)
            .timeout(timeout)
            .build()
            .expect("builds");
        let started = Instant::now();
        let outcome = perplexity.search("q").await;
        let elapsed = started.elapsed();
        assert!(headers_sent.is_set(), "the server never sent its headers");
        assert_eq!(
            unavailable(&outcome),
            Some(UnavailableReason::Timeout(Phase::Body)),
            "{outcome:?}"
        );
        assert!(
            elapsed >= timeout,
            "{elapsed:?}: before the {timeout:?} bound"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "{elapsed:?}: the bound did not end the stall"
        );
    }
    assert_eq!(server.connections(), 2);
    assert_eq!(server.finish().await, 2);
}

/// (6) Before the headers: a stall before any header is a
/// timeout before the headers.
#[tokio::test]
async fn a_stall_before_the_headers_times_out_before_the_headers() {
    let server = RawServer::start(|exchange| async move {
        // Held, not dropped: a closed socket would be a broken connection.
        exchange.hold_until_hangup().await;
    })
    .await;
    let timeout = Duration::from_millis(500);
    let perplexity = builder(&server.base_url)
        .timeout(timeout)
        .build()
        .expect("builds");
    let started = Instant::now();
    let outcome = perplexity.search("q").await;
    let elapsed = started.elapsed();
    assert_eq!(
        unavailable(&outcome),
        Some(UnavailableReason::Timeout(Phase::Headers)),
        "{outcome:?}"
    );
    assert!(
        elapsed >= timeout,
        "{elapsed:?}: before the {timeout:?} bound"
    );
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    drop(perplexity);
    assert_eq!(server.finish().await, 1);
}
