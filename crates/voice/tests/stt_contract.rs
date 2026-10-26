//! The speech-to-text contract, the core's side (feature `live-tests`: the
//! relay needs Redis for its lease): one test per rule of `stt`'s module
//! docs (the design's §2.1 and §2.2) that the relay keeps for an adapter,
//! each against the scripted provider over real sockets
//! (`tests/relay_harness`). `Voice::new`'s refusals of an adapter's facts are
//! `tests/voice_new.rs`'s; the relay's ported suite is `tests/relay.rs`.
//!
//! - **what the events mean** — relayed in order, nothing coalesced; a
//!   cumulative partial passes through; a turn with no partial; `Ignored`
//!   counted and sent nowhere; `Finished` is done after `end` and a provider
//!   failure before it; finals flushed at the end of input, or late inside
//!   the end grace, arrive before the close; the stream's end is a drop; an
//!   error is `error{provider}`.
//! - **the provider's facts** — `configured()`, the formats (the default,
//!   the `422`s), the pacing lead, what `ready` advertises.
//! - **the session's mechanics** — the open (its only bound, a refusal, no
//!   re-dial while the client chatters, cancellation by a shutdown); the four
//!   places a future is dropped, and that nothing preempts a write; a failed
//!   write; the adapter's keepalive; the provider-run cap
//!   (`a_flooding_provider_cannot_starve_client_frames`, on a current-thread
//!   runtime under an external watchdog and on a multi-thread one); `close`
//!   and what it is told; fixed error classes; metering by bytes sent.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use chrono::Utc;
use futures::{SinkExt as _, StreamExt as _};
use stridelabs_voice::lease::audio_ms;
use stridelabs_voice::protocol::{RelayEvent, END_FRAME};
use stridelabs_voice::stt::{AudioFormat, OpenLabel, SttError, SttEvent, SttOpenError};
use stridelabs_voice::testing::{Cancelled, OpenScript, ScriptedStt, SttScript};
use stridelabs_voice::usage::VoiceMetric;
use stridelabs_voice::{ErrorClass, RelaySettings};
use tokio::time::{timeout, Instant};
use tokio_tungstenite::tungstenite::Message;

#[allow(
    dead_code,
    reason = "shared with the other live suites; this suite uses none of its faults"
)]
mod redis_fault;

#[allow(
    dead_code,
    reason = "shared with the other live suites; not every one seeds every kind of key"
)]
mod test_redis;

#[allow(dead_code, reason = "shared with tests/relay.rs")]
mod log_capture;
use log_capture::{capture_dispatch, capture_logs, Capture};

#[allow(dead_code, reason = "shared with tests/relay.rs")]
mod relay_harness;
use relay_harness::{
    pcm, provider_error, quick, session_end_for, Harness, Setup, CAPPED_TRACE, SECOND_24K,
    SESSION_END, SESSION_START, WAIT,
};

/// One 80 ms frame of 24 kHz audio.
const FRAME_80MS: usize = 3_840;

/// The script `events` at 0 ms each, then finishing after `end`.
fn at_once(events: &[SttEvent]) -> SttScript {
    events
        .iter()
        .fold(SttScript::default(), |script, event| {
            script.at(0, event.clone())
        })
        .finish_after_end()
}

// ── What the events mean (§2.1) ──────────────────────────────────────────

/// The four events become `speech_start`, `partial`, `speech_end` and
/// `end_of_turn`, in the order the provider yielded them, across two turns
/// and the audio that drives them: nothing reordered, nothing coalesced.
#[tokio::test]
async fn endpointing_events_are_relayed_in_order() {
    let harness = Harness::scripted(
        SttScript::default()
            .at(80, SttEvent::SpeechStart)
            .at(80, SttEvent::Partial("what's".into()))
            .at(160, SttEvent::Partial("what's the weather".into()))
            .at(160, SttEvent::SpeechEnd)
            .at(160, SttEvent::EndOfTurn("What's the weather?".into()))
            .at(240, SttEvent::SpeechStart)
            .at(240, SttEvent::SpeechEnd)
            .at(240, SttEvent::EndOfTurn("And tomorrow?".into()))
            .finish_after_end(),
    )
    .await;
    let mut client = harness.ready().await;
    for seed in 0..3 {
        client.audio(pcm(FRAME_80MS, seed)).await;
    }
    let mut events = Vec::new();
    for _ in 0..8 {
        events.push(client.event().await);
    }
    assert_eq!(
        events,
        [
            RelayEvent::SpeechStart,
            RelayEvent::Partial {
                text: "what's".into()
            },
            RelayEvent::Partial {
                text: "what's the weather".into()
            },
            RelayEvent::SpeechEnd,
            RelayEvent::EndOfTurn {
                text: "What's the weather?".into()
            },
            RelayEvent::SpeechStart,
            RelayEvent::SpeechEnd,
            RelayEvent::EndOfTurn {
                text: "And tomorrow?".into()
            },
        ]
    );
    client.end().await;
    assert_eq!(
        client.events_then_close().await,
        (vec![], 1000, "done".into())
    );
    harness.clean_up().await;
}

/// Cumulative partials pass through as the provider sent them, each one
/// (the client replaces the last with it), and one `EndOfTurn` counts one
/// turn on the session-end line.
#[tokio::test]
async fn cumulative_partials_pass_through_and_one_end_of_turn_counts_one_turn() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let partials = [
        "what",
        "what's the",
        "what's the weather",
        "what's the weather in",
    ];
    let mut script = vec![SttEvent::SpeechStart];
    script.extend(
        partials
            .iter()
            .map(|text| SttEvent::Partial((*text).into())),
    );
    script.extend([
        SttEvent::SpeechEnd,
        SttEvent::EndOfTurn("What's the weather in Chicago?".into()),
    ]);
    let harness = Harness::scripted(at_once(&script)).await;
    let mut client = harness.ready().await;
    client.end().await;
    let (events, code, _) = client.events_then_close().await;
    let mut expected = vec![RelayEvent::SpeechStart];
    expected.extend(partials.iter().map(|text| RelayEvent::Partial {
        text: (*text).into(),
    }));
    expected.extend([
        RelayEvent::SpeechEnd,
        RelayEvent::EndOfTurn {
            text: "What's the weather in Chicago?".into(),
        },
    ]);
    assert_eq!((events, code), (expected, 1000));
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["turns"], 1, "{line}");
    harness.clean_up().await;
}

/// A provider with no interim results: the turn is `speech_start`,
/// `speech_end`, `end_of_turn` and nothing else, and it is a turn.
#[tokio::test]
async fn a_turn_with_no_partial_is_relayed_whole() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::scripted(at_once(&[
        SttEvent::SpeechStart,
        SttEvent::SpeechEnd,
        SttEvent::EndOfTurn("Turn the lights off.".into()),
    ]))
    .await;
    let mut client = harness.ready().await;
    client.end().await;
    let (events, code, _) = client.events_then_close().await;
    assert_eq!(
        (events, code),
        (
            vec![
                RelayEvent::SpeechStart,
                RelayEvent::SpeechEnd,
                RelayEvent::EndOfTurn {
                    text: "Turn the lights off.".into()
                },
            ],
            1000
        )
    );
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["turns"], 1, "{line}");
    harness.clean_up().await;
}

/// `Ignored` (a provider data message that maps to no event) reaches no
/// client and is counted on the session-end line.
#[tokio::test]
async fn ignored_messages_are_counted_and_reach_nobody() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::scripted(at_once(&[
        SttEvent::Ignored,
        SttEvent::SpeechStart,
        SttEvent::Ignored,
        SttEvent::Ignored,
        SttEvent::EndOfTurn("Hi.".into()),
    ]))
    .await;
    let mut client = harness.ready().await;
    client.end().await;
    let (events, code, _) = client.events_then_close().await;
    assert_eq!(
        (events, code),
        (
            vec![
                RelayEvent::SpeechStart,
                RelayEvent::EndOfTurn { text: "Hi.".into() }
            ],
            1000
        )
    );
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["ignored"], 3, "{line}");
    assert_eq!(line["turns"], 1, "{line}");
    harness.clean_up().await;
}

/// `Finished` after the relay sent the end of input is the session done:
/// `1000 done`, no error event, the provider closed told the end was sent.
#[tokio::test]
async fn finished_after_end_is_done_1000() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::scripted(SttScript::default().finish_after_end()).await;
    let mut client = harness.ready().await;
    client.audio(pcm(FRAME_80MS, 1)).await;
    client.end().await;
    let (events, code, reason) = client.events_then_close().await;
    assert_eq!((events, code, reason.as_str()), (vec![], 1000, "done"));
    assert_eq!(harness.log.end_inputs(), 1);
    assert_eq!(harness.log.closed(), Some(true));
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["outcome"], "done", "{line}");
    harness.clean_up().await;
}

/// `Finished` BEFORE the end of input is the provider failing: cause
/// `closed`, `error{provider}`, `1011`.
#[tokio::test]
async fn finished_without_end_is_a_provider_close_1011() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::scripted(SttScript::default().at(80, SttEvent::Finished)).await;
    let mut client = harness.ready().await;
    client.audio(pcm(FRAME_80MS, 1)).await;
    let (events, code, reason) = client.events_then_close().await;
    assert_eq!(
        (events, code, reason.as_str()),
        (vec![provider_error()], 1011, "provider error")
    );
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(
        (&line["outcome"], &line["cause"]),
        (&"provider".into(), &"closed".into()),
        "{line}"
    );
    assert_eq!(line["severity"], "WARNING", "{line}");
    harness.clean_up().await;
}

/// On the client-`end` path, a final the provider flushes once the end of
/// input returned is yielded before `Finished`, and reaches the client
/// before its `1000`.
#[tokio::test]
async fn a_final_transcript_flushed_at_end_input_arrives_before_the_close() {
    let harness = Harness::scripted(
        SttScript::default()
            .at(0, SttEvent::SpeechStart)
            .after_end(SttEvent::SpeechEnd)
            .after_end(SttEvent::EndOfTurn("The final words.".into()))
            .finish_after_end(),
    )
    .await;
    let mut client = harness.ready().await;
    assert_eq!(client.event().await, RelayEvent::SpeechStart);
    client.end().await;
    let (events, code, _) = client.events_then_close().await;
    assert_eq!(
        (events, code),
        (
            vec![
                RelayEvent::SpeechEnd,
                RelayEvent::EndOfTurn {
                    text: "The final words.".into()
                },
            ],
            1000
        )
    );
    harness.clean_up().await;
}

/// A final the provider flushes LATE — 300 ms after the end of input —
/// still arrives, before the `1000`; and the close follows the provider's
/// `Finished` (right after that final), not the end grace's end. The grace is
/// the protocol's longest here, 2 s, so the two timings are told apart with
/// room for the release's Redis round trip in between: the final arrives
/// about 300 ms after `end`, and the close comes well under 2 s after it.
#[tokio::test]
async fn a_delayed_final_inside_end_timeout_arrives_before_the_close() {
    let harness = Harness::with(Setup {
        settings: RelaySettings {
            end_timeout: Duration::from_secs(2),
            ..quick()
        },
        ..Setup::scripted(
            SttScript::default()
                .after_end_delayed(
                    Duration::from_millis(300),
                    SttEvent::EndOfTurn("Late, but in time.".into()),
                )
                .finish_after_end(),
        )
    })
    .await;
    let mut client = harness.ready().await;
    let ended = Instant::now();
    client.end().await;
    assert_eq!(
        client.event().await,
        RelayEvent::EndOfTurn {
            text: "Late, but in time.".into()
        }
    );
    let final_after = ended.elapsed();
    assert!(
        final_after >= Duration::from_millis(280) && final_after < Duration::from_millis(1_500),
        "the final arrived {final_after:?} after end"
    );
    assert_eq!(client.closed().await, (1000, "done".to_string()));
    let closed_after = ended.elapsed();
    assert!(
        closed_after < Duration::from_millis(1_800),
        "closed {closed_after:?} after end: at the grace's end (2 s), not at the provider's \
         finish"
    );
    harness.clean_up().await;
}

/// `end`, then `Finished` with nothing in between: a clean `1000`, no
/// event, no turn.
#[tokio::test]
async fn no_transcript_before_the_close_is_a_clean_done() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::scripted(SttScript::default().finish_after_end()).await;
    let mut client = harness.ready().await;
    client.audio(pcm(FRAME_80MS, 2)).await;
    client.end().await;
    assert_eq!(
        client.events_then_close().await,
        (vec![], 1000, "done".to_string())
    );
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["turns"], 0, "{line}");
    assert_eq!(line["outcome"], "done", "{line}");
    harness.clean_up().await;
}

/// The stream's end (`None`) is a drop: cause `the connection ended`,
/// `error{provider}`, `1011`.
#[tokio::test]
async fn the_stream_ending_is_a_provider_drop() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::scripted(SttScript::default().drop_at(80)).await;
    let mut client = harness.ready().await;
    client.audio(pcm(FRAME_80MS, 3)).await;
    let (events, code, _) = client.events_then_close().await;
    assert_eq!((events, code), (vec![provider_error()], 1011));
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["cause"], "the connection ended", "{line}");
    harness.clean_up().await;
}

/// The provider's own failure (`Err`): its class is the cause, then
/// `error{provider}` and `1011`; the session is over, and the events
/// scripted after the failure are never relayed.
#[tokio::test]
async fn a_provider_error_is_error_provider_and_1011() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::scripted(
        SttScript::default()
            .at(0, SttEvent::SpeechStart)
            .fail_at(80, SttError::fixed("an error event"))
            .at(80, SttEvent::SpeechEnd),
    )
    .await;
    let mut client = harness.ready().await;
    assert_eq!(client.event().await, RelayEvent::SpeechStart);
    client.audio(pcm(FRAME_80MS, 4)).await;
    let (events, code, reason) = client.events_then_close().await;
    assert_eq!(
        (events, code, reason.as_str()),
        (vec![provider_error()], 1011, "provider error")
    );
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["cause"], "an error event", "{line}");
    assert_eq!(harness.log.closed(), Some(false));
    assert_eq!(harness.lease().await, None);
    harness.clean_up().await;
}

// ── The provider's facts (§2.2) ──────────────────────────────────────────

/// `configured() == false` is the configuration `503`, after the app's auth
/// and before the `426` and the `422`s: an upgrade (with a bad rate), a
/// plain `GET`. No Redis at all is the same `503`. Nothing is opened, no
/// lease is taken, and the `503` asks no retry.
#[tokio::test]
async fn an_unconfigured_provider_is_503_before_the_426() {
    for (what, setup) in [
        (
            "an unconfigured provider",
            Setup {
                stt: ScriptedStt::unconfigured(),
                ..Setup::default()
            },
        ),
        (
            "no Redis",
            Setup {
                redis_url: Some(String::new()),
                ..Setup::default()
            },
        ),
    ] {
        let harness = Harness::with(setup).await;
        let refused = harness
            .try_open("?rate=8000&encoding=opus")
            .await
            .expect_err("refused");
        assert_eq!(
            refused.status,
            http::StatusCode::SERVICE_UNAVAILABLE,
            "{what}"
        );
        assert_eq!(
            refused.body, r#"{"detail":"voice beta not configured"}"#,
            "{what}"
        );
        assert_eq!(refused.header("retry-after"), None, "{what}");
        let plain = harness.plain(http::Method::GET, "/voice/stream").await;
        assert_eq!(
            plain.status,
            http::StatusCode::SERVICE_UNAVAILABLE,
            "{what}: 503 precedes 426"
        );
        assert!(!harness.was_opened().await, "{what}");
        assert_eq!(harness.voice.live_session_count(), 0, "{what}");
        harness.clean_up().await;
    }
}

/// `ready` advertises the provider's own facts: its rates in its order (the
/// default first), the encoding, its lead in ms; and a session without
/// `?rate=` opens at the provider's first format, not at 24 kHz.
#[tokio::test]
async fn ready_advertises_the_providers_formats_and_lead() {
    let formats = vec![
        AudioFormat::pcm_s16le(16_000),
        AudioFormat::pcm_s16le(24_000),
        AudioFormat::pcm_s16le(48_000),
    ];
    let harness = Harness::with(Setup {
        stt: ScriptedStt::new(SttScript::default())
            .with_formats(formats)
            .with_pacing_lead(Duration::from_millis(7_250)),
        ..Setup::default()
    })
    .await;
    let mut client = harness.open("").await;
    let ready = timeout(WAIT, client.ws.next())
        .await
        .expect("ready")
        .expect("a frame")
        .expect("a frame");
    assert_eq!(
        ready,
        Message::text(
            r#"{"type":"ready","rates":[16000,24000,48000],"encoding":"pcm_s16le","lead_ms":7250}"#
        ),
        "the wire form, literally"
    );
    assert_eq!(harness.log.opened(), [AudioFormat::pcm_s16le(16_000)]);
    harness.clean_up().await;
}

/// A rate among the provider's formats opens at it (48 kHz here, which the
/// protocol's defaults lack); one outside them is `422`, the body naming the
/// provider's rates in its order, before anything is opened.
#[tokio::test]
async fn a_rate_outside_the_formats_is_422() {
    let harness = Harness::with(Setup {
        stt: ScriptedStt::new(SttScript::default().finish_after_end()).with_formats(vec![
            AudioFormat::pcm_s16le(24_000),
            AudioFormat::pcm_s16le(16_000),
            AudioFormat::pcm_s16le(48_000),
        ]),
        ..Setup::default()
    })
    .await;
    for query in ["?rate=8000", "?rate=44100", "?rate=48000&rate=48000"] {
        let refused = harness.try_open(query).await.expect_err("refused");
        assert_eq!(
            refused.status,
            http::StatusCode::UNPROCESSABLE_ENTITY,
            "{query}"
        );
        assert_eq!(
            refused.body, r#"{"detail":"rate must be 24000, 16000 or 48000"}"#,
            "{query}"
        );
    }
    assert!(!harness.was_opened().await);
    assert_eq!(harness.lease().await, None);
    let mut client = harness.ready_with("?rate=48000").await;
    assert_eq!(harness.log.opened(), [AudioFormat::pcm_s16le(48_000)]);
    // 96,000 bytes a second at 48 kHz: 500 ms.
    client.audio(pcm(48_000, 1)).await;
    client.end().await;
    assert_eq!(client.closed().await.0, 1000);
    assert_eq!(harness.counters().await, (Some(500), Some(500)));
    harness.clean_up().await;
}

/// The reserved `encoding`: `pcm_s16le` (or absent) opens; anything else,
/// an empty value or a repeat, is `422` naming the provider's encodings —
/// after the rate's `422`, which a bad rate gets first.
#[tokio::test]
async fn a_bad_encoding_is_422() {
    let harness = Harness::scripted(SttScript::default().finish_after_end()).await;
    for query in [
        "?encoding=opus",
        "?encoding=",
        "?encoding=PCM_S16LE",
        "?rate=16000&encoding=pcm_s16le&encoding=pcm_s16le",
    ] {
        let refused = harness.try_open(query).await.expect_err("refused");
        assert_eq!(
            refused.status,
            http::StatusCode::UNPROCESSABLE_ENTITY,
            "{query}"
        );
        assert_eq!(
            refused.body, r#"{"detail":"encoding must be pcm_s16le"}"#,
            "{query}"
        );
    }
    let refused = harness
        .try_open("?rate=8000&encoding=opus")
        .await
        .expect_err("refused");
    assert_eq!(
        refused.body, r#"{"detail":"rate must be 24000 or 16000"}"#,
        "the rate is checked first"
    );
    assert!(!harness.was_opened().await);
    let mut client = harness.ready_with("?rate=16000&encoding=pcm_s16le").await;
    assert_eq!(harness.log.opened(), [AudioFormat::pcm_s16le(16_000)]);
    client.end().await;
    assert_eq!(client.closed().await.0, 1000);
    harness.clean_up().await;
}

/// The pacing lead is the provider's: with a 7 s lead, seven one-second
/// frames at once are accepted and the eighth is `1008 pacing` (the
/// protocol's 5 s minimum allows five: `audio_faster_than_real_time_is_1008_pacing`).
#[tokio::test]
async fn the_pacing_lead_is_the_providers() {
    let harness = Harness::with(Setup {
        stt: ScriptedStt::new(SttScript::default()).with_pacing_lead(Duration::from_secs(7)),
        ..Setup::default()
    })
    .await;
    let mut client = harness.ready().await;
    for seed in 0..8 {
        client.audio(pcm(SECOND_24K, seed)).await;
    }
    assert_eq!(client.closed().await, (1008, "pacing".to_string()));
    assert_eq!(harness.log.frames().len(), 7);
    harness.clean_up().await;
}

// ── The open ─────────────────────────────────────────────────────────────

/// An open that never completes is ended by the relay's bound, the only one:
/// cause `open_timeout: not open before the deadline`, `error{provider}`,
/// `1011`, no `ready`; the open future was dropped, the lease released.
#[tokio::test]
async fn an_open_that_hangs_is_an_open_timeout() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::with(Setup {
        stt: ScriptedStt::new(SttScript::default()).with_open(OpenScript::Hang),
        settings: RelaySettings {
            open_timeout: Duration::from_millis(300),
            ..quick()
        },
        ..Setup::default()
    })
    .await;
    let mut client = harness.open("").await;
    let started = Instant::now();
    let (events, code, _) = client.events_then_close().await;
    assert_eq!((events, code), (vec![provider_error()], 1011));
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(2),
        "{elapsed:?}"
    );
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(
        line["cause"], "open_timeout: not open before the deadline",
        "{line}"
    );
    assert_eq!(line["ready"], false, "{line}");
    assert_eq!(
        harness.log.cancelled(),
        Cancelled {
            open: 1,
            ..Cancelled::default()
        }
    );
    assert_eq!(harness.log.closed(), None, "no session to close");
    assert_eq!(harness.lease().await, None);
    harness.clean_up().await;
}

/// An open the provider refuses (or could not dial) is the provider's
/// failure: its label and class are the cause, `error{provider}`, `1011`.
#[tokio::test]
async fn a_refused_open_is_a_provider_error() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    for (label, class, cause) in [
        (
            OpenLabel::Refused,
            "an error event",
            "refused: an error event",
        ),
        (
            OpenLabel::Dial,
            "io ConnectionRefused",
            "dial: io ConnectionRefused",
        ),
    ] {
        let harness = Harness::with(Setup {
            stt: ScriptedStt::new(SttScript::default()).with_open(OpenScript::Fail(SttOpenError {
                label,
                class: ErrorClass::fixed(class),
            })),
            ..Setup::default()
        })
        .await;
        let mut client = harness.open("").await;
        let (events, code, _) = client.events_then_close().await;
        assert_eq!((events, code), (vec![provider_error()], 1011), "{cause}");
        let line = session_end_for(&capture, harness.user).await;
        assert_eq!(line["cause"], cause, "{line}");
        assert_eq!(harness.lease().await, None, "{cause}");
        harness.clean_up().await;
    }
}

/// While the provider is opening, a client that sends text and pings (all
/// ignored before `ready`) never makes the relay re-create the open: one
/// open started, none cancelled, one completed, and then `ready`.
#[tokio::test]
async fn a_client_ping_during_open_does_not_redial() {
    let harness = Harness::with(Setup {
        stt: ScriptedStt::new(SttScript::default().finish_after_end())
            .with_open(OpenScript::After(Duration::from_millis(400))),
        ..Setup::default()
    })
    .await;
    let mut client = harness.open("").await;
    for _ in 0..5 {
        client
            .ws
            .send(Message::Ping(b"are you there".to_vec().into()))
            .await
            .expect("a ping");
        client.text(r#"{"type":"noise"}"#).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(client.event().await, harness.ready_event());
    assert_eq!(harness.log.opens_started(), 1, "one open future, ever");
    assert_eq!(harness.log.cancelled(), Cancelled::default());
    assert_eq!(harness.log.opened().len(), 1);
    client.end().await;
    assert_eq!(client.closed().await.0, 1000);
    harness.clean_up().await;
}

/// A shutdown while the provider is still opening: `1001`, the open future
/// dropped (counted cancelled, never completed), no session to close, the
/// lease released, nothing live and nothing tracked.
#[tokio::test]
async fn open_cancelled_by_shutdown_leaves_nothing_behind() {
    let harness = Harness::with(Setup {
        stt: ScriptedStt::new(SttScript::default()).with_open(OpenScript::Hang),
        ..Setup::default()
    })
    .await;
    let mut client = harness.open("").await;
    harness
        .eventually("the open started", |harness| {
            harness.log.opens_started() == 1
        })
        .await;
    harness.shutdown.cancel();
    assert_eq!(client.closed().await, (1001, "shutting down".to_string()));
    assert_eq!(
        harness.log.cancelled(),
        Cancelled {
            open: 1,
            ..Cancelled::default()
        }
    );
    assert!(harness.log.opened().is_empty());
    assert_eq!(harness.log.closed(), None);
    assert_eq!(harness.lease().await, None);
    assert!(harness.drain(Duration::from_secs(2)).await);
    assert_eq!(harness.voice.live_session_count(), 0);
    harness.clean_up().await;
}

// ── Writes, and where the relay drops a future ───────────────────────────

/// The events arrive as the audio that makes them due is accepted: the
/// relay calls `send_audio` between polls of the pending stream (each
/// accepted frame wakes it), and no event is lost to the `next()` futures
/// dropped whenever another arm wins.
#[tokio::test]
async fn send_audio_interleaves_with_a_pending_poll() {
    let harness = Harness::scripted(
        SttScript::default()
            .at(80, SttEvent::Partial("one".into()))
            .at(160, SttEvent::Partial("one two".into()))
            .at(240, SttEvent::Partial("one two three".into()))
            .keepalive_every(Duration::from_millis(20))
            .finish_after_end(),
    )
    .await;
    let mut client = harness.ready().await;
    for (seed, text) in [(1, "one"), (2, "one two"), (3, "one two three")] {
        client.quiet_for(Duration::from_millis(60)).await;
        client.audio(pcm(FRAME_80MS, seed)).await;
        assert_eq!(
            client.event().await,
            RelayEvent::Partial { text: text.into() }
        );
    }
    end_and_done(&mut client).await;
    assert_eq!(harness.log.frames().len(), 3);
    harness.clean_up().await;
}

/// `end`, the provider finishes, `1000`.
async fn end_and_done(client: &mut relay_harness::Client) {
    client.end().await;
    assert_eq!(client.closed().await, (1000, "done".to_string()));
}

/// A `send_audio` that never completes (the provider stopped reading) is
/// dropped at its write bound: cause `send: timed out`, `1011`; the dropped
/// write is counted cancelled, and the session still closes — `close` is
/// called and completes.
#[tokio::test]
async fn a_send_audio_dropped_at_its_write_bound_leaves_the_session_closable() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::scripted(SttScript::default().block_writes_after(1)).await;
    let mut client = harness.ready().await;
    client.audio(pcm(FRAME_80MS, 1)).await;
    client.audio(pcm(FRAME_80MS, 2)).await;
    let (events, code, _) = client.events_then_close().await;
    assert_eq!((events, code), (vec![provider_error()], 1011));
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["cause"], "send: timed out", "{line}");
    assert_eq!(
        line["frames"], 2,
        "the blocked frame was handed over, so it counts: {line}"
    );
    assert_eq!(
        harness.log.cancelled(),
        Cancelled {
            send_audio: 1,
            ..Cancelled::default()
        }
    );
    assert_eq!(harness.log.frames(), [FRAME_80MS]);
    assert_eq!(harness.log.closed(), Some(false));
    assert_eq!(harness.lease().await, None);
    harness.clean_up().await;
}

/// An `end_input` that never completes is dropped at its write bound: cause
/// `send: timed out`, `1011`, counted cancelled; the session still closes —
/// told the end was sent, as the relay had begun to send it.
#[tokio::test]
async fn an_end_input_dropped_at_its_write_bound_leaves_the_session_closable() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::scripted(SttScript::default().hang_end_input()).await;
    let mut client = harness.ready().await;
    client.audio(pcm(FRAME_80MS, 1)).await;
    let ended = Instant::now();
    client.end().await;
    let (events, code, _) = client.events_then_close().await;
    assert_eq!((events, code), (vec![provider_error()], 1011));
    assert!(
        ended.elapsed() >= Duration::from_millis(450),
        "the write bound is 500 ms: {:?}",
        ended.elapsed()
    );
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["cause"], "send: timed out", "{line}");
    assert_eq!(line["end_received"], true, "{line}");
    assert_eq!(
        harness.log.cancelled(),
        Cancelled {
            end_input: 1,
            ..Cancelled::default()
        }
    );
    assert_eq!(harness.log.end_inputs(), 0, "it never returned");
    assert_eq!(harness.log.closed(), Some(true));
    harness.clean_up().await;
}

/// **Nothing preempts a write**: a shutdown while a `send_audio` is blocked
/// takes effect only once the write hits its bound, and the session ends as
/// that write's failure (`1011`, cause `send: timed out`), not `1001`, about
/// one write bound after the write began.
#[tokio::test]
async fn a_shutdown_during_a_blocked_write_ends_at_the_write_bound() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::scripted(SttScript::default().block_writes_after(0)).await;
    let mut client = harness.ready().await;
    let sent = Instant::now();
    client.audio(pcm(FRAME_80MS, 1)).await;
    // The relay reads the frame and begins its write within a few ms; the
    // shutdown comes 100 ms in, 400 ms before the write's bound.
    tokio::time::sleep(Duration::from_millis(100)).await;
    harness.shutdown.cancel();
    let (events, code, reason) = client.events_then_close().await;
    assert_eq!(
        (events, code, reason.as_str()),
        (vec![provider_error()], 1011, "provider error"),
        "the write's failure, not the shutdown's 1001"
    );
    let elapsed = sent.elapsed();
    assert!(
        elapsed >= Duration::from_millis(450) && elapsed < Duration::from_millis(1_500),
        "{elapsed:?}"
    );
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["cause"], "send: timed out", "{line}");
    assert_eq!(harness.log.cancelled().send_audio, 1);
    harness.clean_up().await;
}

/// A `send_audio` the provider never completes is cut off by the write
/// bound (`close_timeout`, 500 ms here): `error{provider}` and `1011` about
/// then. The frame was handed over, so it is charged (charged on hand-off:
/// `a_frame_taken_before_a_stalled_flush_is_charged`), though this provider
/// never took it.
#[tokio::test]
async fn a_blocked_send_audio_is_cut_off_by_the_close_bound() {
    let harness = Harness::scripted(SttScript::default().block_writes_after(0)).await;
    let mut client = harness.ready().await;
    let sent = Instant::now();
    client.audio(pcm(FRAME_80MS, 1)).await;
    let (events, code, _) = client.events_then_close().await;
    let elapsed = sent.elapsed();
    assert_eq!((events, code), (vec![provider_error()], 1011));
    assert!(
        elapsed >= Duration::from_millis(450) && elapsed < Duration::from_millis(1_500),
        "cut off {elapsed:?} after the frame"
    );
    assert!(harness.log.frames().is_empty());
    assert_eq!(
        harness.counters().await,
        (Some(80), Some(80)),
        "the handed-over frame was charged"
    );
    harness.clean_up().await;
}

/// **Charged on hand-off** (the S2 branch review's finding 5). A provider
/// that TAKES a frame and then stalls its flush past the write bound — the
/// Muse socket's frame accepted into tungstenite's buffer, `Pending` on the
/// flush — may still receive that frame when its close flushes. The session
/// ends `send: timed out`, `1011`, and the frame the provider holds is in
/// the session-end line, the usage record and the release's final charge:
/// never less than what the provider may receive.
#[tokio::test]
async fn a_frame_taken_before_a_stalled_flush_is_charged() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::scripted(SttScript::default().stall_flush_after(1)).await;
    let mut client = harness.ready().await;
    client.audio(pcm(FRAME_80MS, 1)).await;
    client.audio(pcm(FRAME_80MS, 2)).await;
    let (events, code, _) = client.events_then_close().await;
    assert_eq!((events, code), (vec![provider_error()], 1011));
    assert_eq!(
        harness.log.frames(),
        [FRAME_80MS, FRAME_80MS],
        "premise: the provider took both frames"
    );
    assert_eq!(
        harness.log.cancelled().send_audio,
        1,
        "premise: the second write was cut off"
    );
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["cause"], "send: timed out", "{line}");
    assert_eq!(
        (line["frames"].as_u64(), line["audio_ms"].as_u64()),
        (Some(2), Some(160)),
        "the session-end line counts the frame the provider took: {line}"
    );
    let usage: Vec<u64> = harness
        .usage
        .records()
        .into_iter()
        .map(|(_, _, amount, _)| amount)
        .collect();
    assert_eq!(
        usage,
        [160],
        "the usage record holds the frame the provider took"
    );
    assert_eq!(
        harness.counters().await,
        (Some(160), Some(160)),
        "the final charge holds the frame the provider took"
    );
    assert_eq!(harness.lease().await, None);
    harness.clean_up().await;
}

/// A write the provider fails is its failure: cause `send: <its class>`,
/// `error{provider}`, `1011`; the frames before it were accepted.
#[tokio::test]
async fn a_failed_write_is_a_provider_error_send() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::scripted(
        SttScript::default().fail_writes_after(1, SttError::fixed("io BrokenPipe")),
    )
    .await;
    let mut client = harness.ready().await;
    client.audio(pcm(FRAME_80MS, 1)).await;
    client.audio(pcm(FRAME_80MS, 2)).await;
    let (events, code, _) = client.events_then_close().await;
    assert_eq!((events, code), (vec![provider_error()], 1011));
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["cause"], "send: io BrokenPipe", "{line}");
    assert_eq!(harness.log.frames(), [FRAME_80MS]);
    harness.clean_up().await;
}

/// An adapter's keepalive is a timer it polls inside `poll_next`: the relay
/// polls the stream continuously while a session is open, so it ticks — one
/// tick per interval — with no call of the relay's own.
#[tokio::test]
async fn an_adapter_keepalive_runs_inside_poll_next() {
    let harness = Harness::scripted(
        SttScript::default()
            .keepalive_every(Duration::from_millis(50))
            .finish_after_end(),
    )
    .await;
    let mut client = harness.ready().await;
    let open = Instant::now();
    for seed in 0..10 {
        client.audio(pcm(FRAME_80MS, seed)).await;
        client.quiet_for(Duration::from_millis(80)).await;
    }
    let ticks = harness.log.keepalives();
    let intervals = usize::try_from(open.elapsed().as_millis() / 50).expect("small");
    assert!(
        ticks >= intervals / 2 && ticks <= intervals + 1,
        "{ticks} ticks in {intervals} intervals of 50 ms"
    );
    end_and_done(&mut client).await;
    harness.clean_up().await;
}

// ── The provider-run cap ─────────────────────────────────────────────────

/// How many paced 80 ms frames the flooding test sends.
const FLOOD_FRAMES: usize = 25;

/// What one flooding session saw: the frames the provider accepted, and the
/// captured lines (`stridelabs_voice`'s own, and the session-end line).
struct Flooded {
    frames: usize,
    voice_lines: Vec<serde_json::Value>,
    end: serde_json::Value,
}

/// One session against a provider that is always ready (`flood`: an
/// `Ignored` on every poll, never `Pending`): the client sends
/// [`FLOOD_FRAMES`] frames of 80 ms, paced, then `end`, and reads to the
/// close; the capture holds what the relay logged.
async fn flood_one_session(capture: &Capture) -> Flooded {
    let harness = Harness::scripted(SttScript::default().flood(SttEvent::Ignored)).await;
    let client = harness.ready().await;
    let (mut sink, mut stream) = client.ws.split();
    for seed in 0..FLOOD_FRAMES {
        sink.send(Message::Binary(
            pcm(FRAME_80MS, u8::try_from(seed).expect("small")).into(),
        ))
        .await
        .expect("send audio");
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
    sink.send(Message::text(END_FRAME)).await.expect("send end");
    let close = loop {
        match timeout(WAIT, stream.next())
            .await
            .expect("the relay closes")
        {
            Some(Ok(Message::Close(frame))) => break frame.map(|frame| u16::from(frame.code)),
            Some(Ok(_)) => {}
            other => panic!("expected a close, got {other:?}"),
        }
    };
    // The reply to the relay's close.
    let _ = timeout(Duration::from_secs(1), sink.flush()).await;
    assert_eq!(close, Some(1000), "the session ends done");
    let end = session_end_for(capture, harness.user).await;
    let frames = harness.log.frames().len();
    harness.clean_up().await;
    let voice_lines = capture
        .lines()
        .into_iter()
        .filter(|line| {
            line["logger"]
                .as_str()
                .is_some_and(|logger| logger.starts_with("stridelabs_voice"))
        })
        .collect();
    Flooded {
        frames,
        voice_lines,
        end,
    }
}

/// What every run of the flooding test asserts: every frame reached the
/// provider, the session ended `1000` with the client's `end` read, and the
/// relay logged its two lines for the session and nothing else.
fn assert_flood_survived(flooded: &Flooded) {
    assert_eq!(flooded.frames, FLOOD_FRAMES, "client frames were starved");
    let end = &flooded.end;
    assert_eq!(end["outcome"], "done", "{end}");
    assert_eq!(end["close_code"], 1000, "{end}");
    assert_eq!(end["end_received"], true, "{end}");
    assert_eq!(end["frames"], FLOOD_FRAMES, "{end}");
    let messages: Vec<&str> = flooded
        .voice_lines
        .iter()
        .map(|line| line["message"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        messages,
        [SESSION_START, SESSION_END],
        "the run cap and the budget log nothing"
    );
}

/// Run [`flood_one_session`] on the runtime `build` makes (given the
/// capture's dispatcher, for any worker threads it starts), on an OS thread
/// of its own, with THIS thread as the watchdog: a runtime the provider
/// starved cannot block a `recv_timeout` here, nor can its drop. On a
/// timeout the test fails and the stuck thread is left to the process's
/// exit.
fn flood_under_a_watchdog(build: fn(tracing::Dispatch) -> tokio::runtime::Runtime) -> Flooded {
    let (done, outcome) = mpsc::channel();
    let runner = thread::spawn(move || {
        let (capture, dispatch) = capture_dispatch(CAPPED_TRACE);
        let _guard = tracing::dispatcher::set_default(&dispatch);
        let runtime = build(dispatch);
        let joined = runtime.block_on(async move {
            tokio::spawn(async move { flood_one_session(&capture).await }).await
        });
        runtime.shutdown_timeout(Duration::from_secs(1));
        match joined {
            Ok(flooded) => {
                let _ = done.send(flooded);
            }
            Err(failed) if failed.is_panic() => std::panic::resume_unwind(failed.into_panic()),
            Err(failed) => panic!("the session's task: {failed}"),
        }
    });
    match outcome.recv_timeout(Duration::from_secs(30)) {
        Ok(flooded) => {
            runner.join().expect("the runtime's thread");
            flooded
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // The runtime's thread panicked: surface its assertion.
            if let Err(panic) = runner.join() {
                std::panic::resume_unwind(panic);
            }
            panic!("the runtime's thread ended without an outcome");
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("the flooding session did not end in 30 s: the provider starved the runtime")
        }
    }
}

/// **An always-ready provider cannot starve the client** (the design's
/// §3.3), on a CURRENT-THREAD runtime: the relay's task shares its one thread
/// with the socket's I/O and the timers, so without the cooperative budget
/// the provider's arm would keep the thread forever (the I/O driver never
/// runs, no frame is ever read, no timer fires), and without the run cap the
/// provider's arm, polled first, would always win (the session idles out
/// with no frame read). Under an external watchdog
/// ([`flood_under_a_watchdog`]).
#[test]
fn a_flooding_provider_cannot_starve_client_frames() {
    let flooded = flood_under_a_watchdog(|_| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime")
    });
    assert_flood_survived(&flooded);
}

/// The same flood on a MULTI-THREAD runtime (two workers, each logging into
/// the capture), under the same watchdog.
#[test]
fn a_flooding_provider_cannot_starve_client_frames_on_a_multi_thread_runtime() {
    let flooded = flood_under_a_watchdog(|dispatch| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .on_thread_start(move || {
                // Each worker logs into the capture for the runtime's life.
                std::mem::forget(tracing::dispatcher::set_default(&dispatch));
            })
            .build()
            .expect("a multi-thread runtime")
    });
    assert_flood_survived(&flooded);
}

// ── Close, error classes, billing ────────────────────────────────────────

/// `close(end_sent)` is told whether the end of input went out: after the
/// client's `end`, `true`; after the client's close with no `end`, `false`.
/// Either way it completes (never cancelled at its bound); `close` consumes
/// the session, so it is called once at most.
#[tokio::test]
async fn close_is_called_once_with_end_sent() {
    let ended = Harness::scripted(SttScript::default().finish_after_end()).await;
    let mut client = ended.ready().await;
    end_and_done(&mut client).await;
    assert_eq!(ended.log.closed(), Some(true));
    assert_eq!(ended.log.cancelled(), Cancelled::default());
    ended.clean_up().await;

    let closed = Harness::new().await;
    let mut client = closed.ready().await;
    client.close_first(4100, "left").await;
    assert_eq!(closed.log.closed(), Some(false));
    assert_eq!(closed.log.end_inputs(), 0);
    assert_eq!(closed.log.cancelled(), Cancelled::default());
    closed.clean_up().await;
}

/// A provider's failure reaches the log as its fixed class (the session-end
/// line's `cause`) and nothing else of the provider's does: not the
/// transcripts it sent, not the audio it was sent (as text, hex or the
/// decimal bytes `Debug` prints).
#[tokio::test]
async fn fixed_error_classes_reach_the_log_and_nothing_else() {
    const TRANSCRIPT_CANARY: &str = "leakcanarytranscript7f3a";
    const AUDIO_CANARY: &[u8] = b"leakcanaryaudio6c1e0";
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::scripted(
        SttScript::default()
            .at(0, SttEvent::Partial(format!("{TRANSCRIPT_CANARY} partial")))
            .at(0, SttEvent::EndOfTurn(format!("{TRANSCRIPT_CANARY} final")))
            .fail_at(10, SttError::fixed("http 403")),
    )
    .await;
    let mut client = harness.ready().await;
    let mut frame = AUDIO_CANARY.to_vec();
    frame.extend(pcm(480 - AUDIO_CANARY.len(), 1));
    client.audio(frame).await;
    let (events, code, _) = client.events_then_close().await;
    assert_eq!(code, 1011);
    assert_eq!(events.last(), Some(&provider_error()));
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["cause"], "http 403", "{line}");
    let logged = capture.text();
    let decimal = AUDIO_CANARY
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    for (what, canary) in [
        ("a transcript", TRANSCRIPT_CANARY.to_string()),
        ("audio", String::from_utf8_lossy(AUDIO_CANARY).into_owned()),
        ("audio as hex", relay_harness::hex(AUDIO_CANARY)),
        ("audio as decimal", decimal),
    ] {
        assert!(
            !logged.contains(&canary),
            "{what} reached a log line:\n{logged}"
        );
    }
    harness.clean_up().await;
}

/// Speech to text is billed in relay-measured audio time — the bytes the
/// client sent, at the session's rate — never in a provider's unit: a
/// provider that yields a flurry of events (here, an `Ignored` and a
/// partial per frame) changes nothing. At both protocol rates: the charge,
/// the session-end line and the usage record all agree.
#[tokio::test]
async fn audio_is_metered_from_bytes_sent_not_provider_units() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    for (rate, bytes_per_second) in [(24_000_u32, 48_000_usize), (16_000, 32_000)] {
        let mut script = SttScript::default();
        for frame in 1..=10_u64 {
            script = script
                .at(frame * 50, SttEvent::Ignored)
                .at(frame * 50, SttEvent::Partial(format!("{frame}")));
        }
        let harness = Harness::scripted(script.finish_after_end()).await;
        let mut client = harness.ready_with(&format!("?rate={rate}")).await;
        // 750 ms of audio and 6 bytes (three samples, under a millisecond):
        // 750 ms, the remainder never charged.
        let total = bytes_per_second * 3 / 4 + 6;
        for chunk in [bytes_per_second / 4, bytes_per_second / 2, 6] {
            client.audio(pcm(chunk, 1)).await;
        }
        client.end().await;
        let (_, code, _) = client.events_then_close().await;
        assert_eq!(code, 1000, "{rate}");
        let expected = audio_ms(u64::try_from(total).expect("small"), u64::from(rate) * 2);
        assert_eq!(expected, 750, "{rate}");
        let ms = i64::try_from(expected).expect("small");
        assert_eq!(harness.counters().await, (Some(ms), Some(ms)), "{rate}");
        let line = session_end_for(&capture, harness.user).await;
        assert_eq!(line["audio_ms"], expected, "{line}");
        let records = harness.usage.records();
        assert_eq!(records.len(), 1, "{rate}");
        assert_eq!(
            (records[0].0, records[0].1, records[0].2),
            (harness.user, VoiceMetric::SttMilliseconds, expected),
            "{rate}"
        );
        let charged_at = records[0].3;
        assert!(
            (Utc::now() - charged_at).num_seconds().abs() < 10,
            "on the budget's (system) clock: {charged_at}"
        );
        harness.clean_up().await;
    }
}
