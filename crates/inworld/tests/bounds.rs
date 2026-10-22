//! The bounds, against servers that break each one, including the four blind
//! spots lumen's L1.8 found in tests copied from tapper:
//!
//! 1. an endless chunked stream, which must be cut at the response bound
//!    before the timeout (a client that buffers the whole body passes a
//!    "4 MiB + 1, chunked" case, but can only time out here);
//! 2. a stall after the headers, not only before them;
//! 3. a declared-oversized `Content-Length` that then stalls, which only a
//!    pre-check answers before the timeout;
//! 4. decoded audio of `MAX_AUDIO_BYTES + 2`: `+ 1` encodes to exactly the
//!    base64 bound (2 MiB is 2 mod 3), so only `+ 2` reaches the pre-decode
//!    guard.
//!
//! The first three need a raw TCP server ([`common::RawServer`]): wiremock
//! can delay a whole response, but cannot send its headers and then stall,
//! or stream without end. Each test tells the outcomes apart by their class,
//! never by wall time alone: a client that failed the bound would answer
//! `TimedOut`, where the bound's answer is `BodyTooLarge`. Every raw server's
//! handlers are awaited at the end ([`RawServer::finish`]), so a handler's
//! own assertion fails its test. A stalled handler holds its socket until the
//! client hangs up.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{audio_body, builder, client, mp3, request, Flag, RawServer, HOLD};
use stridelabs_inworld::{
    InworldError, MalformedReason, TransportCause, TransportStage, UnavailableReason,
    DEFAULT_MAX_AUDIO_BYTES, DEFAULT_MAX_RESPONSE_BYTES,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn is_malformed(
    result: &Result<stridelabs_inworld::Synthesis, InworldError>,
) -> Option<MalformedReason> {
    match result {
        Err(InworldError::Malformed(reason)) => Some(*reason),
        _ => None,
    }
}

fn is_unavailable(
    result: &Result<stridelabs_inworld::Synthesis, InworldError>,
) -> Option<UnavailableReason> {
    match result {
        Err(InworldError::Unavailable { reason, .. }) => Some(*reason),
        _ => None,
    }
}

/// A transport failure's stage and timeout flag.
fn stage(
    result: &Result<stridelabs_inworld::Synthesis, InworldError>,
) -> Option<(TransportStage, bool)> {
    match result {
        Err(InworldError::Unavailable {
            cause: Some(TransportCause {
                stage, timed_out, ..
            }),
            ..
        }) => Some((*stage, *timed_out)),
        _ => None,
    }
}

/// Inworld's `2xx` body for a small MP3, padded with a field the crate
/// ignores to exactly `len` bytes.
fn padded_body(len: usize) -> String {
    let fitting = audio_body(&mp3(1024));
    // `"padding":"",` is 13 bytes.
    let padding = len
        .checked_sub(fitting.len() + 13)
        .expect("a length that fits the audio");
    let mut body = fitting;
    body.insert_str(1, &format!(r#""padding":"{}","#, " ".repeat(padding)));
    assert_eq!(body.len(), len);
    body
}

/// One HTTP/1.1 chunk.
fn chunk(data: &[u8]) -> Vec<u8> {
    let mut framed = format!("{:x}\r\n", data.len()).into_bytes();
    framed.extend_from_slice(data);
    framed.extend_from_slice(b"\r\n");
    framed
}

/// Required test 1. A `200` with no `Content-Length` whose body never ends:
/// the opening of an `audioContent`, then 64 KiB chunks of base64 for as long
/// as the client reads. It is cut at the 4 MiB bound, long before the 5 s
/// timeout. A client that read the body whole before measuring it could only
/// time out: `TimedOut`, not `BodyTooLarge`.
#[tokio::test]
async fn an_endless_chunked_stream_is_cut_at_the_bound_before_the_timeout() {
    let server = RawServer::start(|mut exchange| async move {
        let head = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     transfer-encoding: chunked\r\n\r\n";
        if exchange.send(head).await.is_err()
            || exchange
                .send(&chunk(br#"{"audioContent":""#))
                .await
                .is_err()
        {
            return;
        }
        let padding = chunk(&[b'A'; 64 * 1024]);
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
    let inworld = builder(&server.base_url)
        .timeout(timeout)
        .build()
        .expect("builds");

    let started = Instant::now();
    let result = inworld.synthesize(&request("hi")).await;
    let elapsed = started.elapsed();
    assert_eq!(
        is_malformed(&result),
        Some(MalformedReason::BodyTooLarge),
        "{result:?}"
    );
    assert!(
        elapsed < timeout,
        "{elapsed:?}: the stream was not cut before the {timeout:?} timeout"
    );
    drop(inworld);
    assert_eq!(server.finish().await, 1);
}

/// Required test 2. A `200` whose headers (and the first bytes of its body)
/// arrive, and whose body then stalls: the timeout covers the body, not just
/// the headers, and the stall is `TimedOut` at the timeout. The client is
/// built with no timeout, and with a long one: the bound is set on the
/// request, so it holds either way.
#[tokio::test]
async fn a_stall_after_the_headers_is_timed_out_at_the_timeout() {
    let headers_sent = Flag::default();
    let flag = headers_sent.clone();
    let server = RawServer::start(move |mut exchange| {
        let flag = flag.clone();
        async move {
            let head = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                         content-length: 64\r\n\r\n{\"audioContent\":\"";
            if exchange.send(head).await.is_ok() {
                flag.set();
                exchange.hold_until_hangup().await;
            }
        }
    })
    .await;
    let timeout = Duration::from_millis(500);
    for http in [
        common::http(),
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .build()
            .expect("builds"),
    ] {
        let inworld = stridelabs_inworld::InworldClient::builder(http, common::KEY)
            .base_url(&server.base_url)
            .timeout(timeout)
            .build()
            .expect("builds");
        let started = Instant::now();
        let result = inworld.synthesize(&request("hi")).await;
        let elapsed = started.elapsed();
        assert!(headers_sent.is_set(), "the server never sent its headers");
        assert_eq!(
            is_unavailable(&result),
            Some(UnavailableReason::TimedOut),
            "{result:?}"
        );
        // Labelled where it happened, the body read, not reqwest's decode.
        assert_eq!(
            stage(&result),
            Some((TransportStage::Body, true)),
            "{result:?}"
        );
        assert!(result.as_ref().is_err_and(InworldError::is_retryable));
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

/// The other half of test 2's contrast: a stall before any header is the
/// same `TimedOut`.
#[tokio::test]
async fn a_stall_before_the_headers_is_timed_out_at_the_timeout() {
    let server = RawServer::start(|exchange| async move {
        // Held, not dropped: a closed socket would be a broken connection.
        exchange.hold_until_hangup().await;
    })
    .await;
    let timeout = Duration::from_millis(500);
    let inworld = builder(&server.base_url)
        .timeout(timeout)
        .build()
        .expect("builds");
    let started = Instant::now();
    let result = inworld.synthesize(&request("hi")).await;
    let elapsed = started.elapsed();
    assert_eq!(
        is_unavailable(&result),
        Some(UnavailableReason::TimedOut),
        "{result:?}"
    );
    assert_eq!(
        stage(&result),
        Some((TransportStage::Request, true)),
        "{result:?}"
    );
    assert!(
        elapsed >= timeout,
        "{elapsed:?}: before the {timeout:?} bound"
    );
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    drop(inworld);
    assert_eq!(server.finish().await, 1);
}

/// A `200` that declares `declared` bytes, sends its headers, and stalls.
async fn declaring_then_stalling(declared: usize, headers_sent: Flag) -> RawServer {
    RawServer::start(move |mut exchange| {
        let flag = headers_sent.clone();
        async move {
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                 content-length: {declared}\r\n\r\n"
            );
            if exchange.send(head.as_bytes()).await.is_ok() {
                flag.set();
                exchange.hold_until_hangup().await;
            }
        }
    })
    .await
}

/// Required test 3. A `Content-Length` one byte past the 4 MiB bound, then
/// no body at all: refused unread, at once. A client that read first would
/// wait out its 5 s timeout and answer `TimedOut`. The control: the same
/// stall declaring exactly the bound IS read, and so does time out, which
/// shows the declaration alone decided the first answer.
#[tokio::test]
async fn a_declared_oversized_length_that_stalls_is_refused_unread() {
    let headers_sent = Flag::default();
    let server =
        declaring_then_stalling(DEFAULT_MAX_RESPONSE_BYTES + 1, headers_sent.clone()).await;
    let timeout = Duration::from_secs(5);
    let inworld = builder(&server.base_url)
        .timeout(timeout)
        .build()
        .expect("builds");
    let started = Instant::now();
    let result = inworld.synthesize(&request("hi")).await;
    let elapsed = started.elapsed();
    assert!(headers_sent.is_set(), "the server never sent its headers");
    assert_eq!(
        is_malformed(&result),
        Some(MalformedReason::BodyTooLarge),
        "{result:?}"
    );
    assert!(
        elapsed < timeout,
        "{elapsed:?}: the declared length was not refused before the {timeout:?} timeout"
    );
    drop(inworld);
    assert_eq!(server.finish().await, 1);

    let at_the_bound = Flag::default();
    let server = declaring_then_stalling(DEFAULT_MAX_RESPONSE_BYTES, at_the_bound.clone()).await;
    let short = Duration::from_millis(500);
    let inworld = builder(&server.base_url)
        .timeout(short)
        .build()
        .expect("builds");
    let result = inworld.synthesize(&request("hi")).await;
    assert!(at_the_bound.is_set(), "the server never sent its headers");
    assert_eq!(
        is_unavailable(&result),
        Some(UnavailableReason::TimedOut),
        "{result:?}"
    );
    drop(inworld);
    assert_eq!(server.finish().await, 1);
}

/// Required test 4. Audio of `MAX_AUDIO_BYTES + 2` is refused by the guard
/// BEFORE decoding (`AudioContentTooLong`): its base64 is one quantum longer
/// than any 2 MiB encodes to. `+ 1` is the blind spot: it encodes to exactly
/// the bound's length, passes the pre-decode guard, and only the post-decode
/// check refuses it (`AudioTooLarge`). The control: 2 MiB itself is audio.
/// Every body fits the 4 MiB response bound, so the audio bound decides.
#[tokio::test]
async fn audio_decoding_to_max_plus_two_is_refused_before_decoding() {
    use base64::Engine as _;
    let encoded_len = |len: usize| {
        base64::engine::general_purpose::STANDARD
            .encode(vec![0u8; len])
            .len()
    };
    assert_eq!(DEFAULT_MAX_AUDIO_BYTES % 3, 2, "the premise");
    assert_eq!(
        encoded_len(DEFAULT_MAX_AUDIO_BYTES + 1),
        encoded_len(DEFAULT_MAX_AUDIO_BYTES),
        "the premise: + 1 encodes to the bound's length"
    );
    assert!(encoded_len(DEFAULT_MAX_AUDIO_BYTES + 2) > encoded_len(DEFAULT_MAX_AUDIO_BYTES));

    let server = MockServer::start().await;
    let inworld = client(&server.uri());
    for (len, expected) in [
        (
            DEFAULT_MAX_AUDIO_BYTES + 2,
            Some(MalformedReason::AudioContentTooLong),
        ),
        (
            DEFAULT_MAX_AUDIO_BYTES + 1,
            Some(MalformedReason::AudioTooLarge),
        ),
        (DEFAULT_MAX_AUDIO_BYTES, None),
    ] {
        server.reset().await;
        let body = audio_body(&mp3(len));
        assert!(
            body.len() < DEFAULT_MAX_RESPONSE_BYTES,
            "within the response bound"
        );
        Mock::given(method("POST"))
            .and(path("/tts/v1/voice"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .expect(1)
            .mount(&server)
            .await;
        let result = inworld.synthesize(&request("hi")).await;
        match expected {
            Some(reason) => assert_eq!(is_malformed(&result), Some(reason), "{len}: {result:?}"),
            None => assert_eq!(
                result
                    .expect("2 MiB of audio is within the bound")
                    .audio
                    .len(),
                DEFAULT_MAX_AUDIO_BYTES
            ),
        }
        server.verify().await;
    }
}

/// A body declared and sent one byte over the response bound (wiremock sets
/// the `Content-Length`) is refused; one at the bound is read.
#[tokio::test]
async fn a_body_over_the_response_bound_is_refused() {
    let server = MockServer::start().await;
    let max = 64 * 1024;
    let inworld = builder(&server.uri())
        .max_response_bytes(max)
        .build()
        .expect("builds");
    for (body, refused) in [(padded_body(max + 1), true), (padded_body(max), false)] {
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;
        let result = inworld.synthesize(&request("hi")).await;
        if refused {
            assert_eq!(
                is_malformed(&result),
                Some(MalformedReason::BodyTooLarge),
                "{result:?}"
            );
        } else {
            assert!(result.is_ok(), "{result:?}");
        }
    }
}

/// A body that breaks off before its declared length is the transport
/// failing (`Unavailable`, retryable), not a malformed answer.
#[tokio::test]
async fn a_truncated_body_is_unavailable() {
    let server = RawServer::start(|mut exchange| async move {
        let body = audio_body(&mp3(64));
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );
        let _ = exchange.send(head.as_bytes()).await;
        let _ = exchange.send(&body.as_bytes()[..body.len() / 2]).await;
        // Dropping the stream closes it with half the body sent.
    })
    .await;
    let result = client(&server.base_url).synthesize(&request("hi")).await;
    assert_eq!(
        is_unavailable(&result),
        Some(UnavailableReason::Transport),
        "{result:?}"
    );
    assert_eq!(
        stage(&result),
        Some((TransportStage::Body, false)),
        "{result:?}"
    );
    assert_eq!(server.finish().await, 1);
}

/// A chunked body (no `Content-Length`, so no pre-check) is cut by the chunk
/// loop at exactly the bound: one byte over, arriving as its own final
/// chunk after the bound's worth, is `BodyTooLarge`; exactly the bound is
/// read. The body is valid audio either way, so a loop that let one more
/// chunk through would answer the first with audio, and one that cut at the
/// bound itself would refuse the second.
#[tokio::test]
async fn a_chunked_body_one_byte_over_the_bound_is_cut_by_the_chunk_loop() {
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
        let inworld = builder(&server.base_url)
            .max_response_bytes(max)
            .build()
            .expect("builds");
        let result = inworld.synthesize(&request("hi")).await;
        if refused {
            assert_eq!(
                is_malformed(&result),
                Some(MalformedReason::BodyTooLarge),
                "{len}: {result:?}"
            );
        } else {
            assert!(result.is_ok(), "{len}: {result:?}");
        }
        drop(inworld);
        assert_eq!(server.finish().await, 1);
    }
}
