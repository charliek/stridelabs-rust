//! The relay over REAL sockets (feature `live-tests`): `Voice::open_stream`
//! served on a loopback port, a tokio-tungstenite client, the scripted
//! speech-to-text provider, and the test Redis.
//!
//! Ported from tapper's `tests/voice_stream.rs` (`82be95f`) and lumen's
//! (`5b716ba`), the union of their relay cases (the design's §11.1, "C"):
//! the session and every close code, the admission's refusals, the lease
//! and the budget as a session meets them (the budget's own half of those
//! tests is `tests/lease.rs`'s), the fence at the upgrade, the failed
//! upgrade's release, and how the client left. tapper's mock Muse is the
//! scripted provider here: what a test there told the mock to send, a test
//! here scripts (`SttScript`); what the mock received, `SttLog` records.
//! The provider's own wire (its handshake, its events' names) is the
//! adapters' suites'.
//!
//! - **before the upgrade** — the configuration `503`, `426` for a plain
//!   request, `422` for a bad `rate`, `429`/`503` from the lease; nothing is
//!   opened at the provider for any of them.
//! - **the session** — `ready` once the provider opened, audio forwarded in
//!   order, the provider's events relayed, `end` → the end of input → `1000`.
//! - **every close code** — `1000`, `1001` (the shutdown token), `1008`
//!   (size, odd frame, pacing, idle, before ready, after end), `1011` (the
//!   provider fails, finishes early, drops), `4000` (the cap), `4001` (a
//!   second session), `4002` (a budget spent).
//! - **the lease and the budget** — takeover, release before the close
//!   frame, charging by audio milliseconds exactly once; the user's month and
//!   the limit's scope; a calendar crossing; a slow acquire near a reset.
//! - **the fence at the upgrade** — a lost ticket reply and a racing upgrade
//!   are retryable `503`s that write nothing.
//! - **how the client left** — the session-end line's `end_received` and
//!   `client_close_code`, never the close frame's reason.
//! - **usage** — recorded once, before any closing I/O.
//!
//! No paused clock: real sockets do real I/O, so the relay's clocks are
//! shortened through `Voice::with_relay_settings_unchecked` instead.
//!
//! The test Redis is required, never skipped (`tests/test_redis`), and every
//! test counts under prefixes of its own.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::{SinkExt as _, StreamExt as _};
use redis::AsyncCommands as _;
use stridelabs_redis::{RedisHandle, RedisOptions};
use stridelabs_voice::budget::LimitScope;
use stridelabs_voice::lease::StreamBudget;
use stridelabs_voice::protocol::{RelayEvent, MAX_FRAME_BYTES};
use stridelabs_voice::stt::{AudioFormat, SttError, SttEvent};
use stridelabs_voice::testing::{Cancelled, OpenScript, ScriptedStt, SttScript};
use stridelabs_voice::usage::{UsageSink, VoiceMetric};
use stridelabs_voice::window::{day_end, month_end, seconds_until};
use stridelabs_voice::RelaySettings;
use tokio::time::{timeout, Instant};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

#[allow(
    dead_code,
    reason = "shared with the other live suites; this one uses the lost-answer, hold, delay, \
              hold-answer and sever faults"
)]
mod redis_fault;
use redis_fault::{within_deadline, EvalFault, RedisRelay};

#[allow(
    dead_code,
    reason = "shared with the other live suites; not every one seeds every kind of key"
)]
mod test_redis;
use test_redis::{key_states, raw_redis, test_redis_url};

#[allow(dead_code, reason = "shared with tests/stt_contract.rs")]
mod log_capture;
use log_capture::{capture_logs, Capture};

#[allow(dead_code, reason = "shared with tests/stt_contract.rs")]
mod relay_harness;
use relay_harness::{
    counter_keys, counter_values, how_the_client_left, limit_event, pcm, provider_error, quick,
    rfc3339, session_end_for, settle_admission, small_budget, try_open_at, Harness, Received,
    Setup, TestClock, CAPPED_TRACE, GLOBAL_MONTHLY_MS, SECOND_24K, SMALL_DAY_MS,
    SMALL_USER_MONTH_MS, USER_DAILY_MS, WAIT,
};

/// A provider that finishes as soon as the end of input returned: a session
/// the client ends is done at once.
fn finishes() -> SttScript {
    SttScript::default().finish_after_end()
}

/// End a session that is relaying: `end`, the provider finishes, `1000`.
async fn end_done(client: &mut relay_harness::Client) {
    client.end().await;
    assert_eq!(client.closed().await, (1000, "done".to_string()));
}

// ── The session ──────────────────────────────────────────────────────────

/// The whole happy path: the provider opened at the default format, `ready`,
/// the audio forwarded in order, the provider's events relayed, `end` → the
/// end of input → the provider finishes → the client's `1000 done`; then the
/// audio charged in milliseconds and the lease gone — both BEFORE the close
/// frame reached the client, which is when they are read here.
#[tokio::test]
async fn a_session_relays_audio_and_events_and_ends_done() {
    let harness = Harness::scripted(
        SttScript::default()
            .at(160, SttEvent::SpeechStart)
            .at(160, SttEvent::Partial("what's the".into()))
            .at(160, SttEvent::SpeechEnd)
            .at(160, SttEvent::EndOfTurn("What's the weather?".into()))
            .finish_after_end(),
    )
    .await;
    let mut client = harness.ready().await;
    assert_eq!(harness.log.opened(), [AudioFormat::pcm_s16le(24_000)]);
    assert!(
        harness.lease().await.is_some(),
        "the session holds its lease"
    );

    // Two of one length, distinct in content: the payload, not its length,
    // is what is compared.
    let frames = [pcm(3_840, 1), pcm(3_840, 2), pcm(1_000, 3)];
    assert_ne!(frames[0], frames[1], "premise");
    for frame in &frames {
        client.audio(frame.clone()).await;
    }
    assert_eq!(client.event().await, RelayEvent::SpeechStart);
    assert_eq!(
        client.event().await,
        RelayEvent::Partial {
            text: "what's the".into()
        }
    );
    assert_eq!(client.event().await, RelayEvent::SpeechEnd);
    assert_eq!(
        client.event().await,
        RelayEvent::EndOfTurn {
            text: "What's the weather?".into()
        }
    );

    client.end().await;
    // Read the close frame WITHOUT replying, so the relay is still waiting
    // for the reply while Redis is read: the release must already be done.
    assert_eq!(
        client.closed_without_reply().await,
        (1000, "done".to_string())
    );
    assert_eq!(
        harness
            .log
            .frame_bytes()
            .iter()
            .map(|frame| frame.to_vec())
            .collect::<Vec<_>>(),
        frames,
        "the audio reaches the provider byte for byte, in order"
    );
    assert_eq!(harness.log.end_inputs(), 1, "the end of input was sent");
    assert_eq!(harness.log.closed(), Some(true), "closed, the end sent");
    let bytes: usize = frames.iter().map(Vec::len).sum();
    let ms = i64::try_from(bytes * 1000 / SECOND_24K).expect("small");
    assert_eq!(
        harness.lease().await,
        None,
        "released before the close frame"
    );
    assert_eq!(harness.counters().await, (Some(ms), Some(ms)));
    client.reply_to_close().await;
    harness.clean_up().await;
}

/// `?rate=16000` opens the provider at 16 kHz and is charged at 32 KB a
/// second (the core's half of the adapters' "the rate reaches the
/// handshake and the charge").
#[tokio::test]
async fn the_rate_reaches_the_open_and_the_charge() {
    let harness = Harness::scripted(finishes()).await;
    let mut client = harness.ready_with("?rate=16000").await;
    assert_eq!(harness.log.opened(), [AudioFormat::pcm_s16le(16_000)]);
    client.audio(pcm(16_000, 7)).await;
    end_done(&mut client).await;
    assert_eq!(harness.log.frame_bytes(), [pcm(16_000, 7)]);
    assert_eq!(harness.counters().await, (Some(500), Some(500)));
    harness.clean_up().await;
}

/// The provider ending the session on its own — finishing before `end`, its
/// transport closing with an error, or the stream simply ending — is
/// `error{provider}` + `1011`, and the lease is released. (Port of
/// "Muse closing or dropping unexpectedly".)
#[tokio::test]
async fn a_provider_closing_or_dropping_unexpectedly_is_1011() {
    for (how, script) in [
        (
            "finished before end",
            SttScript::default().at(0, SttEvent::Finished),
        ),
        (
            "closed with an error",
            SttScript::default().fail_at(0, SttError::fixed("closed")),
        ),
        ("dropped", SttScript::default().drop_at(0)),
    ] {
        let harness = Harness::scripted(script).await;
        let mut client = harness.ready().await;
        let (events, code, reason) = client.events_then_close().await;
        assert_eq!(events, vec![provider_error()], "{how}");
        assert_eq!((code, reason.as_str()), (1011, "provider error"), "{how}");
        assert_eq!(harness.lease().await, None, "{how}");
        assert_eq!(harness.log.closed(), Some(false), "{how}");
        harness.clean_up().await;
    }
}

/// The client closing first: the provider is closed with no end of input
/// sent (its adapter sends its own), the lease released and the audio
/// charged — both before the client's close is echoed.
#[tokio::test]
async fn the_client_closing_ends_the_provider_and_releases() {
    let harness = Harness::new().await;
    let mut client = harness.ready().await;
    client.audio(pcm(4_800, 9)).await;
    client.close_first(1000, "bye").await;
    assert_eq!(harness.log.frame_bytes(), [pcm(4_800, 9)]);
    assert_eq!(harness.log.end_inputs(), 0, "the client sent no end");
    assert_eq!(
        harness.log.closed(),
        Some(false),
        "closed, told the end was not sent"
    );
    // The release ran before the echo was flushed.
    assert_eq!(harness.lease().await, None);
    assert_eq!(harness.counters().await, (Some(100), Some(100)));
    harness.clean_up().await;
}

/// The shutdown token: every live session closes `1001`, the provider is
/// closed, the lease released — and the app's drain sees the relay finish
/// well inside its budget.
#[tokio::test]
async fn shutdown_closes_1001_and_releases() {
    let harness = Harness::new().await;
    let mut client = harness.ready().await;
    assert_eq!(
        harness.tracker.len(),
        1,
        "the session holds a tracker token"
    );
    assert_eq!(harness.voice.live_session_count(), 1);
    let started = Instant::now();
    harness.shutdown.cancel();
    assert_eq!(
        client.closed_without_reply().await,
        (1001, "shutting down".to_string())
    );
    assert_eq!(
        harness.lease().await,
        None,
        "released before the close frame"
    );
    assert_eq!(harness.log.closed(), Some(false));
    assert_eq!(harness.voice.live_session_count(), 0);
    client.reply_to_close().await;
    assert!(harness.drain(Duration::from_secs(5)).await);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert!(harness.tracker.is_empty());
    harness.clean_up().await;
}

// ── 1008: the client broke a rule ────────────────────────────────────────

/// One message over 64 KiB — binary or text — is `1008 message too big`, and
/// it never reaches the provider. Exactly 64 KiB is fine. (This is also what
/// pins the `axum` feature's tungstenite to axum's own: a different one
/// would never match the downcast, and the read error would be a drop.)
#[tokio::test]
async fn an_oversized_message_is_1008() {
    let harness = Harness::new().await;
    let mut client = harness.ready().await;
    client.audio(pcm(MAX_FRAME_BYTES, 1)).await;
    client.audio(pcm(MAX_FRAME_BYTES + 2, 2)).await;
    assert_eq!(client.closed().await, (1008, "message too big".to_string()));
    assert_eq!(harness.log.frame_bytes(), [pcm(MAX_FRAME_BYTES, 1)]);
    assert_eq!(harness.lease().await, None);
    harness.clean_up().await;

    let harness = Harness::new().await;
    let mut client = harness.ready().await;
    client.text(&"x".repeat(MAX_FRAME_BYTES + 1)).await;
    assert_eq!(client.closed().await, (1008, "message too big".to_string()));
    harness.clean_up().await;
}

/// An odd-length audio frame cannot be 16-bit samples: `1008`, and the
/// provider never sees it.
#[tokio::test]
async fn an_odd_audio_frame_is_1008() {
    let harness = Harness::new().await;
    let mut client = harness.ready().await;
    client.audio(pcm(3, 1)).await;
    assert_eq!(client.closed().await, (1008, "odd audio frame".to_string()));
    assert!(harness.log.frames().is_empty());
    harness.clean_up().await;
}

/// More than real time plus the provider's five-second lead of audio:
/// `1008 pacing`. Six one-second frames at once: five fit the lead, the
/// sixth does not, and only the five reach the provider.
#[tokio::test]
async fn audio_faster_than_real_time_is_1008_pacing() {
    let harness = Harness::new().await;
    let mut client = harness.ready().await;
    for seed in 0..6 {
        client.audio(pcm(SECOND_24K, seed)).await;
    }
    assert_eq!(client.closed().await, (1008, "pacing".to_string()));
    assert_eq!(harness.log.frames().len(), 5);
    // What was sent is what is charged.
    assert_eq!(harness.counters().await, (Some(5_000), Some(5_000)));
    harness.clean_up().await;
}

/// No audio for the idle timeout before `end`: `1008 idle`. Text, pings and
/// EMPTY binary frames keep arriving every 100 ms the whole time, and none of
/// them counts as audio (the empty ones never reach the provider): the close
/// comes one idle timeout after `ready`, not one after the last of them.
#[tokio::test]
async fn silence_from_the_client_is_1008_idle() {
    let harness = Harness::with(Setup {
        settings: RelaySettings {
            idle_timeout: Duration::from_millis(400),
            ..quick()
        },
        ..Setup::default()
    })
    .await;
    let client = harness.ready().await;
    let started = Instant::now();
    let (mut sink, mut stream) = client.ws.split();
    let chatter = async move {
        for _ in 0..10 {
            let _ = sink.send(Message::text(r#"{"type":"noise"}"#)).await;
            let _ = sink.send(Message::Binary(Vec::new().into())).await;
            let _ = sink.send(Message::Ping(Vec::new().into())).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let close = async move {
        loop {
            match timeout(WAIT, stream.next())
                .await
                .expect("the relay closes")
            {
                Some(Ok(Message::Close(frame))) => {
                    let frame = frame.expect("a close frame");
                    return (
                        u16::from(frame.code),
                        frame.reason.to_string(),
                        started.elapsed(),
                    );
                }
                Some(Ok(_)) => {}
                other => panic!("expected a close, got {other:?}"),
            }
        }
    };
    let ((), (code, reason, elapsed)) = tokio::join!(chatter, close);
    assert_eq!((code, reason.as_str()), (1008, "idle"));
    assert!(
        elapsed >= Duration::from_millis(350) && elapsed < Duration::from_millis(800),
        "the idle close came {elapsed:?} after ready"
    );
    assert!(
        harness.log.frames().is_empty(),
        "an empty frame reached the provider"
    );
    harness.clean_up().await;
}

/// A client that never goes an idle timeout without a frame, but sends
/// almost nothing — two-byte frames, each inside the idle timeout — is idle
/// all the same once its audio is an idle timeout behind real time. Scaled
/// down: a 1 s idle timeout and a frame every 900 ms (production: 10 s, so
/// a frame every 9 s is caught at about 10 s).
#[tokio::test]
async fn a_client_trickling_tiny_frames_is_1008_idle() {
    let harness = Harness::with(Setup {
        settings: RelaySettings {
            idle_timeout: Duration::from_secs(1),
            ..quick()
        },
        ..Setup::default()
    })
    .await;
    let client = harness.ready().await;
    let started = Instant::now();
    let (mut sink, mut stream) = client.ws.split();
    let trickle = async move {
        for _ in 0..4 {
            let _ = sink.send(Message::Binary(vec![0u8, 0].into())).await;
            tokio::time::sleep(Duration::from_millis(900)).await;
        }
    };
    let close = async move {
        loop {
            match timeout(WAIT, stream.next())
                .await
                .expect("the relay closes")
            {
                Some(Ok(Message::Close(frame))) => {
                    let frame = frame.expect("a close frame");
                    return (
                        u16::from(frame.code),
                        frame.reason.to_string(),
                        started.elapsed(),
                    );
                }
                Some(Ok(_)) => {}
                other => panic!("expected a close, got {other:?}"),
            }
        }
    };
    let ((), (code, reason, elapsed)) = tokio::join!(trickle, close);
    assert_eq!((code, reason.as_str()), (1008, "idle"));
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_millis(1_600),
        "the idle close came {elapsed:?} after ready; frames kept arriving every 900 ms"
    );
    harness.clean_up().await;
}

/// Audio after `end`: `1008`. (The provider is still finishing, so the
/// session is still open when it arrives.)
#[tokio::test]
async fn audio_after_end_is_1008() {
    let harness = Harness::new().await;
    let mut client = harness.ready().await;
    client.audio(pcm(480, 1)).await;
    client.end().await;
    client.audio(pcm(480, 2)).await;
    assert_eq!(client.closed().await, (1008, "audio after end".to_string()));
    assert_eq!(harness.log.frame_bytes(), [pcm(480, 1)]);
    assert_eq!(harness.log.end_inputs(), 1);
    harness.clean_up().await;
}

/// Audio before `ready` is `1008`; `end` before `ready` is a plain `1000` —
/// nothing was said. Either way the open in flight is dropped, never
/// completed.
#[tokio::test]
async fn before_ready_audio_is_1008_and_end_is_done() {
    let harness = Harness::with(Setup {
        stt: ScriptedStt::new(SttScript::default()).with_open(OpenScript::Hang),
        ..Setup::default()
    })
    .await;
    let mut client = harness.open("").await;
    client.audio(pcm(480, 1)).await;
    assert_eq!(
        client.closed().await,
        (1008, "audio before ready".to_string())
    );
    assert_eq!(harness.log.cancelled().open, 1);
    assert!(harness.log.opened().is_empty());
    harness.clean_up().await;

    let harness = Harness::with(Setup {
        stt: ScriptedStt::new(SttScript::default()).with_open(OpenScript::Hang),
        ..Setup::default()
    })
    .await;
    let mut client = harness.open("").await;
    client.end().await;
    assert_eq!(client.closed().await, (1000, "done".to_string()));
    assert_eq!(harness.lease().await, None);
    assert_eq!(harness.log.cancelled().open, 1);
    harness.clean_up().await;
}

/// After `end`, a provider that never finishes is given the end grace
/// (`end_timeout`, counted from the end of input) and the client still gets
/// `1000 done`, with every event that arrived. (Port of "a Muse that never
/// closes after end still ends done".)
#[tokio::test]
async fn a_provider_that_never_finishes_after_end_still_ends_done() {
    let harness =
        Harness::scripted(SttScript::default().after_end(SttEvent::EndOfTurn("Late.".into())))
            .await;
    let mut client = harness.ready().await;
    let ended = Instant::now();
    client.end().await;
    let (events, code, reason) = client.events_then_close().await;
    assert_eq!(
        events,
        vec![RelayEvent::EndOfTurn {
            text: "Late.".into()
        }]
    );
    assert_eq!((code, reason.as_str()), (1000, "done"));
    let elapsed = ended.elapsed();
    assert!(
        elapsed >= Duration::from_millis(450) && elapsed < Duration::from_millis(1_500),
        "the end grace is 500 ms: closed {elapsed:?} after end"
    );
    harness.clean_up().await;
}

// ── 4000 / 4001 / 4002 ───────────────────────────────────────────────────

/// The session cap: `4000 session limit` once the configured cap passes; when
/// the user's remaining day is shorter, the session ends sooner with
/// `error{limit}` + `4002 limit reached` (a new session could not continue).
#[tokio::test]
async fn the_session_cap_is_4000_and_a_spent_day_is_4002() {
    let harness = Harness::with(Setup {
        settings: RelaySettings {
            session_cap: Duration::from_millis(400),
            ..quick()
        },
        ..Setup::default()
    })
    .await;
    let mut client = harness.ready().await;
    let started = Instant::now();
    assert_eq!(client.closed().await, (4000, "session limit".to_string()));
    assert!(started.elapsed() < Duration::from_secs(2));
    harness.clean_up().await;

    let harness = Harness::new().await;
    let now = Utc::now();
    harness
        .seed(
            harness.budget.user_key(harness.user, now),
            &(USER_DAILY_MS - 300).to_string(),
        )
        .await;
    let mut client = harness.ready().await;
    let started = Instant::now();
    let (events, code, reason) = client.events_then_close().await;
    assert_eq!(
        events,
        vec![limit_event(LimitScope::UserDay, now)],
        "a spent day is a limit, announced before the close, with its scope"
    );
    assert_eq!((code, reason.as_str()), (4002, "limit reached"));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the 60 s cap did not apply"
    );
    harness.clean_up().await;
}

/// A second session for the same user, on ANOTHER instance (a second app
/// sharing the first's Redis keys), takes the lease over; the first finds
/// out at its next refresh and closes `4001 superseded` — and its release
/// leaves the NEW session's lease alone.
#[tokio::test]
async fn a_takeover_from_another_instance_is_4001_at_the_next_refresh() {
    let settings = RelaySettings {
        refresh_interval: Duration::from_millis(200),
        ..quick()
    };
    let harness = Harness::with(Setup {
        settings,
        ..Setup::scripted(finishes())
    })
    .await;
    let other_instance = Harness::with(Setup {
        settings,
        budget: Some(harness.budget.clone()),
        user: Some(harness.user),
        ..Setup::scripted(finishes())
    })
    .await;
    let mut first = harness.ready().await;
    let first_lease = harness.lease().await.expect("the first session's lease");
    first.audio(pcm(4_800, 1)).await;

    settle_admission().await;
    let mut second = other_instance.ready().await;
    let second_lease = harness.lease().await.expect("the second session's lease");
    assert_ne!(first_lease, second_lease);

    assert_eq!(first.closed().await, (4001, "superseded".to_string()));
    assert_eq!(
        harness.lease().await.as_deref(),
        Some(second_lease.as_str()),
        "the superseded session's release deleted the new lease"
    );
    // The first session's audio was still charged.
    assert_eq!(harness.counters().await.0, Some(100));

    // The second is unaffected, and ends normally.
    second.audio(pcm(4_800, 2)).await;
    end_done(&mut second).await;
    assert_eq!(other_instance.log.frame_bytes(), [pcm(4_800, 2)]);
    assert_eq!(harness.lease().await, None);
    assert_eq!(harness.counters().await, (Some(200), Some(200)));
    harness.clean_up().await;
}

/// A takeover on the SAME instance supersedes at once: the first session
/// closes `4001` within ~100 ms of the second's upgrade, with no refresh due
/// for a minute — and its release still leaves the new lease alone.
#[tokio::test]
async fn a_takeover_on_the_same_instance_is_4001_at_once() {
    let harness = Harness::scripted(finishes()).await;
    let mut first = harness.ready().await;
    settle_admission().await;
    let mut second = harness.open("").await;
    let upgraded = Instant::now();
    assert_eq!(first.closed().await, (4001, "superseded".to_string()));
    let elapsed = upgraded.elapsed();
    assert!(
        elapsed < Duration::from_millis(300),
        "the superseded session closed {elapsed:?} after the takeover (refresh is 60 s away)"
    );
    assert_eq!(second.event().await, harness.ready_event());
    assert_eq!(harness.voice.live_session_count(), 1, "the second alone");
    let lease = harness.lease().await.expect("the second session's lease");
    end_done(&mut second).await;
    assert_eq!(
        harness.lease().await,
        None,
        "the second released its own lease"
    );
    assert!(!lease.is_empty());
    harness.clean_up().await;
}

/// **Registration follows the fence, not arrival** (the S2 branch review's
/// finding 1). Two admissions for one user on ONE instance: A's acquire
/// runs (ticket 1, the lease A's) but its reply is held back at the fault
/// relay; meanwhile B takes ticket 2 and the lease, registers and reaches
/// `ready`; only then is A's reply passed on. A must not supersede B —
/// Redis holds B's token — so A is born superseded (`4001` before it dials
/// the provider, its release deleting nothing) and B runs on to `1000`,
/// releasing its own lease. Every step waits on an event, never a guess at a
/// delay: A's acquire is known to have RUN once its answer is held.
#[tokio::test]
async fn a_late_acquire_reply_does_not_supersede_the_newer_session() {
    within_deadline("a late acquire reply", async {
        let harness = Harness::scripted(finishes()).await;
        let relay = RedisRelay::start(&test_redis_url().await).await;
        // A's door: its own handle through the fault relay, patient enough
        // (20 s, inside the test's deadline) to wait out the held reply
        // rather than answer 503.
        let slow = RedisHandle::open_with(
            &relay.url,
            RedisOptions::default().with_response_timeout(Duration::from_secs(20)),
        )
        .expect("the relay's URL parses");
        let slow_door = harness.second_door(slow).await;
        // The issue (the first EVAL) passes at once; the acquire (the
        // second) runs, and its answer is held until released.
        relay.arm(EvalFault::DelayAnswer(Duration::ZERO));
        relay.arm(EvalFault::HoldAnswer);
        let late = tokio::spawn(try_open_at(slow_door, ""));
        relay
            .await_count("held acquire answers", RedisRelay::answers_held, 1)
            .await;
        let late_lease = harness
            .lease()
            .await
            .expect("premise: A's acquire ran and took the lease");
        // Past the admission interval A's acquire opened, which it opened
        // before its answer came back.
        settle_admission().await;
        let mut newer = harness.ready().await;
        let newer_lease = harness.lease().await.expect("B holds the lease");
        assert_ne!(newer_lease, late_lease, "premise: B took the lease over");
        assert!(
            !late.is_finished(),
            "premise: B registered before A's acquire reply arrived"
        );
        assert_eq!(relay.release_answers().await, 1, "A's reply, released");
        let mut late = late
            .await
            .expect("A's upgrade task")
            .expect("A's acquire succeeded: its upgrade is a 101");
        // A's first message, read whole before B is touched: its close comes
        // after its release, so A's session is over once it is read.
        let late_first = late.next().await;
        assert_eq!(
            harness.lease().await.as_deref(),
            Some(newer_lease.as_str()),
            "B's lease is intact: nothing released it"
        );
        newer.audio(pcm(SECOND_24K / 10, 1)).await;
        newer.end().await;
        assert_eq!(
            newer.closed().await,
            (1000, "done".to_string()),
            "B, the lease's rightful holder, was not superseded by A's late reply"
        );
        assert_eq!(
            late_first,
            Received::Closed(4001, "superseded".to_string()),
            "the late registration is born superseded"
        );
        assert_eq!(harness.lease().await, None, "B released its own lease");
        assert_eq!(
            harness.log.opened().len(),
            1,
            "B's session alone opened: A never dialled the provider"
        );
        assert_eq!(
            harness.log.cancelled(),
            Cancelled {
                open: 1,
                ..Cancelled::default()
            },
            "A's open future was dropped unpolled"
        );
        harness.clean_up().await;
    })
    .await;
}

/// A second upgrade by the same user inside the admission interval (the
/// production 2 s) is `429` + `Retry-After: 2`: nothing is opened at the
/// provider, and the first session is neither superseded nor disturbed.
#[tokio::test]
async fn a_second_upgrade_inside_the_admission_interval_is_429() {
    let harness = Harness::with(Setup {
        settings: RelaySettings {
            admit_interval: RelaySettings::default().admit_interval,
            ..quick()
        },
        ..Setup::scripted(finishes())
    })
    .await;
    let mut first = harness.ready().await;
    let lease = harness.lease().await;
    let refused = harness.try_open("").await.expect_err("refused");
    assert_eq!(refused.status, http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        refused.body,
        r#"{"detail":"voice stream reopened too soon"}"#
    );
    assert_eq!(refused.header("retry-after"), Some("2"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        harness.log.opens_started(),
        1,
        "the refused upgrade opened the provider"
    );
    assert_eq!(
        harness.lease().await,
        lease,
        "the refused upgrade touched the lease"
    );

    // The first session carries on and ends normally.
    first.audio(pcm(480, 1)).await;
    end_done(&mut first).await;
    assert_eq!(harness.log.frame_bytes(), [pcm(480, 1)]);
    harness.clean_up().await;
}

/// A refresh that finds the month spent: `error{limit}` with the
/// `global_month` scope, and `4002`. The month is spent AFTER admission —
/// by other sessions, as it were — so the session's up-front deadline cannot
/// see it and only the refresh finds it.
#[tokio::test]
async fn a_budget_spent_mid_session_is_4002() {
    let harness = Harness::with(Setup {
        settings: RelaySettings {
            refresh_interval: Duration::from_millis(200),
            ..quick()
        },
        ..Setup::default()
    })
    .await;
    let mut client = harness.ready().await;
    let now = Utc::now();
    harness
        .seed(
            harness.budget.global_key(now),
            &(GLOBAL_MONTHLY_MS - 100).to_string(),
        )
        .await;
    client.audio(pcm(SECOND_24K / 2, 1)).await;
    let (events, code, reason) = client.events_then_close().await;
    assert_eq!(events, vec![limit_event(LimitScope::GlobalMonth, now)]);
    assert_eq!((code, reason.as_str()), (4002, "limit reached"));
    assert_eq!(harness.lease().await, None);
    harness.clean_up().await;
}

/// The refresh charges the audio sent since the last one WHILE the session
/// runs, in whole milliseconds of audio (not wall time), and the release
/// charges only the rest.
#[tokio::test]
async fn refreshes_charge_audio_milliseconds_as_they_go() {
    let harness = Harness::with(Setup {
        settings: RelaySettings {
            refresh_interval: Duration::from_millis(150),
            ..quick()
        },
        ..Setup::scripted(finishes())
    })
    .await;
    let mut client = harness.ready().await;
    client.audio(pcm(SECOND_24K, 1)).await;
    client.audio(pcm(SECOND_24K / 2, 2)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        harness.counters().await,
        (Some(1_500), Some(1_500)),
        "charged by a refresh while the session is open"
    );
    // Ten milliseconds and 46 bytes — less than one more: the remainder is
    // rounded down, never charged twice.
    client.audio(pcm(48 * 10 + 46, 3)).await;
    end_done(&mut client).await;
    assert_eq!(harness.counters().await, (Some(1_510), Some(1_510)));
    harness.clean_up().await;
}

// ── Refused before the upgrade ───────────────────────────────────────────

/// A spent budget is `429` before the upgrade, with `Retry-After` to the end
/// of the spent window; nothing is opened and no lease is taken. The body
/// keeps its `detail` and names the spent allowance.
#[tokio::test]
async fn a_spent_budget_is_429_before_the_upgrade() {
    let harness = Harness::new().await;
    let now = Utc::now();
    harness
        .seed(
            harness.budget.user_key(harness.user, now),
            &USER_DAILY_MS.to_string(),
        )
        .await;
    let refused = harness.try_open("").await.expect_err("refused");
    assert_eq!(refused.status, http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        refused.body,
        format!(
            r#"{{"detail":"voice beta limit reached","scope":"user_day","resets_at":"{}"}}"#,
            rfc3339(day_end(now))
        )
    );
    let retry = refused.retry_after();
    let day_left = seconds_until(day_end(now), now);
    assert!((retry - day_left).abs() <= 2, "{retry} vs {day_left}");
    assert!(!harness.was_opened().await);
    assert_eq!(harness.lease().await, None);
    harness.clean_up().await;

    let harness = Harness::new().await;
    harness
        .seed(
            harness.budget.global_key(now),
            &GLOBAL_MONTHLY_MS.to_string(),
        )
        .await;
    let refused = harness.try_open("").await.expect_err("refused");
    assert_eq!(refused.status, http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        refused.body,
        format!(
            r#"{{"detail":"voice beta limit reached","scope":"global_month","resets_at":"{}"}}"#,
            rfc3339(month_end(now))
        )
    );
    let retry = refused.retry_after();
    let month_left = seconds_until(month_end(now), now);
    assert!((retry - month_left).abs() <= 2, "{retry} vs {month_left}");
    harness.clean_up().await;
}

/// A counter that is not an integer, or a Redis that is down: `503` +
/// `Retry-After: 5`, and nothing written. Admission (the ping, the ticket
/// and the acquire) FAILS CLOSED, so a Redis outage never opens a session.
/// Down, it is the `PING` before the ticket that fails.
#[tokio::test]
async fn a_poisoned_counter_or_a_dead_redis_is_a_retryable_503() {
    let harness = Harness::new().await;
    harness
        .seed(harness.budget.user_key(harness.user, Utc::now()), "1.5")
        .await;
    let refused = harness.try_open("").await.expect_err("refused");
    assert_eq!(refused.status, http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.body, r#"{"detail":"voice beta unavailable"}"#);
    assert_eq!(refused.header("retry-after"), Some("5"));
    assert_eq!(harness.lease().await, None, "nothing was written");
    harness.clean_up().await;

    let harness = Harness::with(Setup {
        redis_url: Some("redis://127.0.0.1:1".to_string()),
        ..Setup::default()
    })
    .await;
    let refused = harness.try_open("").await.expect_err("refused");
    assert_eq!(refused.status, http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.header("retry-after"), Some("5"));
    assert!(!harness.was_opened().await);
}

/// A plain `GET` (no upgrade headers): `426` with `Upgrade: websocket` — and
/// `426` comes before the rate's `422`.
#[tokio::test]
async fn a_plain_get_is_426() {
    let harness = Harness::new().await;
    for path in ["/voice/stream", "/voice/stream?rate=8000"] {
        let plain = harness.plain(http::Method::GET, path).await;
        assert_eq!(plain.status, http::StatusCode::UPGRADE_REQUIRED, "{path}");
        assert_eq!(plain.body, r#"{"detail":"expected a WebSocket upgrade"}"#);
        assert_eq!(plain.header("upgrade"), Some("websocket"));
    }
    assert!(!harness.was_opened().await);
    assert_eq!(harness.lease().await, None);
}

/// A `rate` other than the provider's: `422`, before any lease.
#[tokio::test]
async fn a_bad_rate_is_422() {
    let harness = Harness::new().await;
    for query in [
        "?rate=8000",
        "?rate=",
        "?rate=24000&rate=16000",
        "?rate=24k",
    ] {
        let refused = harness.try_open(query).await.expect_err("refused");
        assert_eq!(
            refused.status,
            http::StatusCode::UNPROCESSABLE_ENTITY,
            "{query}"
        );
        assert_eq!(refused.body, r#"{"detail":"rate must be 24000 or 16000"}"#);
    }
    assert_eq!(harness.lease().await, None);
    assert!(!harness.was_opened().await);
}

// ── The fence at the upgrade ─────────────────────────────────────────────

/// `user`'s fence hash's `next`, `None` when there is no hash (or no field).
async fn fence_next(budget: &StreamBudget, user: Uuid) -> Option<u64> {
    raw_redis()
        .await
        .hget(budget.fence_key(user), "next")
        .await
        .expect("HGET the fence")
}

/// **A lost ticket reply is a `503`, and nothing replays the increment**:
/// the admission's issue is the first `EVAL` of an upgrade (after its
/// `PING`, which leaves the connection cached), its answer is lost with the
/// connection, and — sent under `Replay::Never` — it is not re-sent: one
/// `EVAL`, `next` raised exactly ONCE, no acquire, no lease, nothing opened.
/// The client's next upgrade takes the next ticket and opens.
#[tokio::test]
async fn a_lost_ticket_reply_is_a_503_and_nothing_replays_the_increment() {
    within_deadline("a lost ticket reply", async {
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let harness = Harness::with(Setup {
            redis_url: Some(relay.url.clone()),
            ..Setup::scripted(finishes())
        })
        .await;
        relay.arm(EvalFault::LoseAnswerAndClose);
        let refused = harness.try_open("").await.expect_err("refused");
        assert_eq!(refused.status, http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(refused.body, r#"{"detail":"voice beta unavailable"}"#);
        assert_eq!(refused.header("retry-after"), Some("5"));
        assert_eq!(relay.evals(), 1, "the issue alone, sent once");
        assert_eq!(
            fence_next(&harness.budget, harness.user).await,
            Some(1),
            "the increment ran exactly once"
        );
        assert_eq!(harness.lease().await, None);
        assert!(!harness.was_opened().await);

        let mut client = harness.ready().await;
        assert_eq!(fence_next(&harness.budget, harness.user).await, Some(2));
        end_done(&mut client).await;
        harness.clean_up().await;
    })
    .await;
}

/// **A racing upgrade is a retryable `503`, and nothing is written**: the
/// admission's issue runs, and while its answer is on its way back another
/// upgrade for the same user takes a ticket. The admission's acquire then
/// carries a stale ticket: `503` + `Retry-After: 5`, no lease, no admission
/// key, nothing opened. The control: the next upgrade, racing nothing,
/// opens.
#[tokio::test]
async fn a_newer_ticket_taken_mid_upgrade_is_a_retryable_503() {
    within_deadline("a racing ticket", async {
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let harness = Harness::with(Setup {
            redis_url: Some(relay.url.clone()),
            ..Setup::scripted(finishes())
        })
        .await;
        relay.arm(EvalFault::DelayAnswer(Duration::from_millis(300)));
        let (budget, user) = (harness.budget.clone(), harness.user);
        let racer = tokio::spawn(async move {
            // The admission's issue has run once `next` is 1; then the
            // other device's.
            let deadline = Instant::now() + Duration::from_secs(5);
            while fence_next(&budget, user).await != Some(1) {
                assert!(Instant::now() < deadline, "the admission never issued");
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            let direct = RedisHandle::open(&test_redis_url().await).expect("the test URL parses");
            budget.issue_ticket(&direct, user).await.expect("a ticket")
        });
        let refused = harness.try_open("").await.expect_err("refused");
        assert_eq!(racer.await.expect("the racer"), 2);
        assert_eq!(refused.status, http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(refused.body, r#"{"detail":"voice beta unavailable"}"#);
        assert_eq!(refused.header("retry-after"), Some("5"));
        let states = key_states(&[
            harness.budget.lease_key(harness.user),
            harness.budget.admit_key(harness.user),
        ])
        .await;
        assert_eq!(states[0].kind, "none", "no lease: {states:?}");
        assert_eq!(states[1].kind, "none", "no admission: {states:?}");
        assert!(!harness.was_opened().await);

        let mut client = harness.ready().await;
        end_done(&mut client).await;
        harness.clean_up().await;
    })
    .await;
}

// ── The user's month and the limit's scope ───────────────────────────────

/// **A spent user's month is a `429` before the upgrade**, with the scope and
/// the reset in the body beside the unchanged `detail`, and `Retry-After` to
/// the first of next month; nothing is opened and no lease is taken. The
/// control: another user, whose month has room, opens a session on the same
/// app.
#[tokio::test]
async fn a_spent_users_month_is_a_429_before_the_upgrade() {
    let clock = TestClock::at("2026-10-17T12:00:00Z");
    let harness = Harness::with(Setup {
        budget: Some(small_budget(&clock)),
        ..Setup::default()
    })
    .await;
    harness
        .seed(
            harness.budget.user_month_key(harness.user, clock.now()),
            &SMALL_USER_MONTH_MS.to_string(),
        )
        .await;
    let refused = harness.try_open("").await.expect_err("refused");
    assert_eq!(refused.status, http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        refused.body,
        r#"{"detail":"voice beta limit reached","scope":"user_month","resets_at":"2026-11-01T00:00:00Z"}"#
    );
    assert_eq!(refused.retry_after(), 14 * 86_400 + 12 * 3_600);
    assert!(!harness.was_opened().await);
    assert_eq!(harness.lease().await, None);

    let other = Harness::with(Setup {
        budget: Some(harness.budget.clone()),
        ..Setup::scripted(finishes())
    })
    .await;
    let mut client = other.ready().await;
    end_done(&mut client).await;
    harness.clean_up().await;
}

/// **What admission left of the user's month ends the session, with its
/// scope**: 300 ms of the month left mid-month, and the session is closed
/// `4002` about then, after `{"type":"error","code":"limit",
/// "scope":"user_month","resets_at":…}`. The control is the calendar test
/// below: the same remainder two seconds before the month ENDS does not
/// close the session.
#[tokio::test]
async fn what_admission_left_of_the_users_month_ends_the_session_with_its_scope() {
    let clock = TestClock::at("2026-10-17T12:00:00Z");
    let harness = Harness::with(Setup {
        budget: Some(small_budget(&clock)),
        ..Setup::default()
    })
    .await;
    let [_, month, _] = counter_keys(&harness.budget, harness.user, clock.now());
    harness
        .seed(month, &(SMALL_USER_MONTH_MS - 300).to_string())
        .await;
    let mut client = harness.ready().await;
    let started = Instant::now();
    let (events, code, reason) = client.events_then_close().await;
    assert_eq!(
        events,
        vec![limit_event(LimitScope::UserMonth, clock.now())]
    );
    assert_eq!((code, reason.as_str()), (4002, "limit reached"));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the 60 s cap did not apply"
    );
    assert_eq!(harness.lease().await, None, "released");
    harness.clean_up().await;
}

/// **A user's month EXHAUSTED mid-session is `4002` with its scope**: the
/// meter charges the user's month too and answers its remainder. Admission
/// saw a whole month; then the month is all but spent elsewhere (seeded after
/// `ready`), and the first refresh charges half a second of audio to it —
/// spent: `error{limit, user_month}` and `4002`, the audio charged to all
/// three windows, the lease released. The control: the same session with the
/// month left alone is still open after that refresh.
#[tokio::test]
async fn a_users_month_exhausted_mid_session_is_4002_with_its_scope() {
    let clock = TestClock::at("2026-10-17T12:00:00Z");
    let settings = RelaySettings {
        refresh_interval: Duration::from_millis(200),
        ..quick()
    };
    // The control first: nothing spent, still open after two refreshes.
    let control = Harness::with(Setup {
        budget: Some(small_budget(&clock)),
        settings,
        ..Setup::scripted(finishes())
    })
    .await;
    let mut client = control.ready().await;
    client.audio(pcm(SECOND_24K / 2, 1)).await;
    client.quiet_for(Duration::from_millis(500)).await;
    end_done(&mut client).await;
    control.clean_up().await;

    let harness = Harness::with(Setup {
        budget: Some(small_budget(&clock)),
        settings,
        ..Setup::default()
    })
    .await;
    let keys = counter_keys(&harness.budget, harness.user, clock.now());
    let mut client = harness.ready().await;
    harness
        .seed(keys[1].clone(), &(SMALL_USER_MONTH_MS - 100).to_string())
        .await;
    client.audio(pcm(SECOND_24K / 2, 1)).await;
    let (events, code, reason) = client.events_then_close().await;
    assert_eq!(
        events,
        vec![limit_event(LimitScope::UserMonth, clock.now())]
    );
    assert_eq!((code, reason.as_str()), (4002, "limit reached"));
    assert_eq!(
        counter_values(&keys).await,
        [Some(500), Some(SMALL_USER_MONTH_MS + 400), Some(500)],
        "the half second, charged to every window"
    );
    assert_eq!(harness.lease().await, None);
    harness.clean_up().await;
}

/// **A calendar crossing never closes a session** ("monthly" means
/// EXHAUSTING a month's allowance). Admission at 23:59:59 on the month's
/// last day sees three seconds of the user's month left — and the month ENDS
/// in one, so that remainder does not bind; nor do the day and everyone's
/// month, which end with it. The clock then crosses into the new month: the
/// refreshes charge the NEW month's (and day's) counters, which have room.
/// The session is still open well past three seconds, and ends normally
/// (`1000`); the old month's counter is untouched.
///
/// The control is the test above it: the same three-second (there: 300 ms)
/// remainder mid-month DOES close the session.
#[tokio::test]
async fn a_calendar_crossing_does_not_close_the_session() {
    let clock = TestClock::at("2026-10-31T23:59:59Z");
    let harness = Harness::with(Setup {
        budget: Some(small_budget(&clock)),
        settings: RelaySettings {
            refresh_interval: Duration::from_millis(200),
            ..quick()
        },
        ..Setup::scripted(finishes())
    })
    .await;
    let october = counter_keys(&harness.budget, harness.user, clock.now());
    let near = (SMALL_USER_MONTH_MS - 3_000).to_string();
    harness.seed(october[1].clone(), &near).await;
    let mut client = harness.ready().await;
    clock.set("2026-11-01T00:00:01Z");
    let november = counter_keys(&harness.budget, harness.user, clock.now());
    // Four seconds of real time, a quarter second of audio every 400 ms:
    // in pace, never idle, and past the three seconds the old month had.
    for frame in 0..10 {
        client.audio(pcm(SECOND_24K / 4, frame)).await;
        client.quiet_for(Duration::from_millis(400)).await;
    }
    client.end().await;
    let (events, code, _) = client.events_then_close().await;
    assert_eq!((events, code), (vec![], 1000), "the session ended normally");
    assert_eq!(
        counter_values(&november).await,
        [Some(2_500), Some(2_500), Some(2_500)],
        "the audio is the new month's (and the new day's)"
    );
    let october_values = counter_values(&october).await;
    assert_eq!(
        october_values[1],
        Some(SMALL_USER_MONTH_MS - 3_000),
        "the old month is untouched"
    );
    harness.clean_up().await;
}

/// **The final charge names the window it spent**: the up-front deadline
/// ends a session when what admission left of the user's DAY runs out
/// (300 ms), but the client flushed a whole second of audio in that stretch
/// (inside its five-second lead), so the release's final charge spends the
/// user's MONTH too (400 ms were left). The `limit` event goes out after
/// that release and says `user_month`, resetting next month — not the
/// `user_day` the deadline alone saw.
///
/// The control: the same session with no audio sent; the release spends
/// nothing, and the event keeps the deadline's own `user_day`.
#[tokio::test]
async fn the_final_charge_names_the_window_it_spent_on_the_deadline_path() {
    let clock = TestClock::at("2026-10-17T12:00:00Z");
    for flushed in [false, true] {
        let harness = Harness::with(Setup {
            budget: Some(small_budget(&clock)),
            ..Setup::default()
        })
        .await;
        let keys = counter_keys(&harness.budget, harness.user, clock.now());
        harness
            .seed(keys[0].clone(), &(SMALL_DAY_MS - 300).to_string())
            .await;
        harness
            .seed(keys[1].clone(), &(SMALL_USER_MONTH_MS - 400).to_string())
            .await;
        let mut client = harness.ready().await;
        if flushed {
            client.audio(pcm(SECOND_24K, 1)).await;
        }
        let (events, code, _) = client.events_then_close().await;
        let scope = if flushed {
            LimitScope::UserMonth
        } else {
            LimitScope::UserDay
        };
        assert_eq!(
            events,
            vec![limit_event(scope, clock.now())],
            "audio flushed: {flushed}"
        );
        assert_eq!(code, 4002);
        if flushed {
            assert_eq!(
                counter_values(&keys).await[..2],
                [Some(SMALL_DAY_MS + 700), Some(SMALL_USER_MONTH_MS + 600)],
                "the second was charged to both windows"
            );
        }
        harness.clean_up().await;
    }
}

/// **A slow acquire near a reset does not close the session with a past
/// reset**. Admission at 23:59:59.700 on the month's last day sees 200 ms of
/// the user's month left, and the month ends 300 ms later; the acquire's
/// reply takes 200 ms (a delayed answer through the fault relay). Reckoned
/// from the instant the windows were read — the grant's `at` and its
/// monotonic `origin`, captured together before the acquire was sent — the
/// month resets before those 200 ms can run out, so it does not bind and the
/// session stays open; it ends normally (`1000`).
#[tokio::test]
async fn a_slow_acquire_near_a_reset_does_not_close_the_session() {
    within_deadline("a slow acquire near a reset", async {
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let clock = TestClock::at("2026-10-31T23:59:59.700Z");
        let harness = Harness::with(Setup {
            redis_url: Some(relay.url.clone()),
            budget: Some(small_budget(&clock)),
            ..Setup::scripted(finishes())
        })
        .await;
        let keys = counter_keys(&harness.budget, harness.user, clock.now());
        harness
            .seed(keys[1].clone(), &(SMALL_USER_MONTH_MS - 200).to_string())
            .await;
        // The acquire is the second EVAL through the relay (the PING before
        // it is not one; the ticket's issue is the first, and passes at once:
        // a zero delay).
        relay.arm(EvalFault::DelayAnswer(Duration::ZERO));
        relay.arm(EvalFault::DelayAnswer(Duration::from_millis(200)));
        let started = Instant::now();
        let mut client = harness.ready().await;
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "premise: the acquire took 200 ms"
        );
        assert_eq!(
            relay.evals(),
            2,
            "premise: the issue, then the acquire, delayed"
        );
        client.quiet_for(Duration::from_millis(700)).await;
        client.end().await;
        let (events, code, _) = client.events_then_close().await;
        assert_eq!((events, code), (vec![], 1000), "the session ended normally");
        harness.clean_up().await;
    })
    .await;
}

// ── A failed upgrade, and lost answers ───────────────────────────────────

/// Whether `capture` holds a line whose message is `message`.
fn logged(capture: &Capture, message: &str) -> bool {
    capture
        .lines()
        .iter()
        .any(|line| line["message"] == message)
}

/// A failed upgrade gives its lease back in a task the app's tracker
/// tracks, so its drain waits for it (the release is held at the Redis
/// relay, and the drain runs out of budget waiting); and the log line says
/// what happened — here, that the release worked.
#[tokio::test]
async fn a_failed_upgrade_is_drained_and_its_release_logged() {
    within_deadline("the failed upgrade's release", async {
        let (capture, _guard) = capture_logs("info");
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let harness = Harness::with(Setup {
            redis_url: Some(relay.url.clone()),
            ..Setup::default()
        })
        .await;
        assert_eq!(
            harness.failed_upgrade().await,
            http::StatusCode::SWITCHING_PROTOCOLS
        );
        // Armed before anything here yields, so before the cleanup task can
        // run: the release's first attempt is held; its retry (the meter's
        // `Replay::OnceOnFreshConnection`) goes through.
        relay.arm(EvalFault::Hold);
        assert!(
            !harness.drain(Duration::from_millis(300)).await,
            "the drain returned while the failed upgrade's release was still running"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !logged(
            &capture,
            "voice stream: the upgrade failed; the lease is released",
        ) {
            assert!(
                Instant::now() < deadline,
                "no release line:\n{}",
                capture.text()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // The lease was taken before the 101, and this release deleted it.
        let released = capture
            .lines()
            .into_iter()
            .find(|line| {
                line["message"] == "voice stream: the upgrade failed; the lease is released"
            })
            .expect("the release line");
        assert_eq!(released["lease_deleted"], true, "{released}");
        assert_eq!(harness.lease().await, None);
        assert!(harness.drain(Duration::from_secs(1)).await);
        assert_eq!(harness.voice.live_session_count(), 0, "deregistered");
        assert!(!harness.was_opened().await);
        harness.clean_up().await;
    })
    .await;
}

/// When that release FAILS (both the attempt and its retry are held past the
/// response timeout), the log line says so — never "released".
#[tokio::test]
async fn a_failed_upgrades_failed_release_is_logged_as_failed() {
    within_deadline("the failed upgrade's failed release", async {
        let (capture, _guard) = capture_logs("info");
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let harness = Harness::with(Setup {
            redis_url: Some(relay.url.clone()),
            ..Setup::default()
        })
        .await;
        assert_eq!(
            harness.failed_upgrade().await,
            http::StatusCode::SWITCHING_PROTOCOLS
        );
        relay.arm(EvalFault::Hold);
        relay.arm(EvalFault::Hold);
        let failed = "voice stream: the upgrade failed, and so did the lease release; it expires \
                      on its own";
        let deadline = Instant::now() + Duration::from_secs(10);
        while !logged(&capture, failed) {
            assert!(
                Instant::now() < deadline,
                "no failure line:\n{}",
                capture.text()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            !logged(
                &capture,
                "voice stream: the upgrade failed; the lease is released"
            ),
            "a failed release was logged as released:\n{}",
            capture.text()
        );
        assert!(
            harness.lease().await.is_some(),
            "the lease is left to expire"
        );
        harness.clean_up().await;
    })
    .await;
}

/// A refresh and a release whose answers were lost — the EVAL ran, then the
/// connection died before the answer arrived (the meter's one replay, on a
/// new connection) — charge the audio ONCE through a session: the totals are
/// cumulative, so the retry finds nothing left to charge. (The session half
/// of tapper's `a_meter_whose_answer_was_lost_is_charged_once`; the budget
/// half is `tests/lease.rs`'s.)
#[tokio::test]
async fn a_meter_whose_answer_was_lost_is_charged_once_in_a_session() {
    within_deadline("the lost-answer metering", async {
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let harness = Harness::with(Setup {
            redis_url: Some(relay.url.clone()),
            settings: RelaySettings {
                refresh_interval: Duration::from_millis(300),
                ..quick()
            },
            ..Setup::scripted(finishes())
        })
        .await;
        // The PING before the ticket dialled: the connection is CACHED, the
        // kind a replay retries on. Two EVALs: the ticket's issue and the
        // acquire.
        let mut client = harness.ready().await;
        assert_eq!(relay.evals(), 2);
        client.audio(pcm(SECOND_24K, 1)).await;
        relay.arm(EvalFault::LoseAnswerAndClose);
        // The first refresh: one attempt (answer lost) and its retry.
        relay
            .await_count("refresh EVALs", RedisRelay::evals, 4)
            .await;
        let deadline = Instant::now() + Duration::from_secs(5);
        while harness.counters().await != (Some(1_000), Some(1_000)) {
            assert!(
                Instant::now() < deadline,
                "the refresh charged {:?}, not 1000 ms once",
                harness.counters().await
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        client.audio(pcm(SECOND_24K / 2, 2)).await;
        // Whichever EVAL is next — another refresh, or the release — loses
        // its answer too.
        relay.arm(EvalFault::LoseAnswerAndClose);
        end_done(&mut client).await;
        assert_eq!(
            harness.counters().await,
            (Some(1_500), Some(1_500)),
            "a replayed meter charged twice"
        );
        assert_eq!(harness.lease().await, None);
        assert!(relay.evals() >= 6, "{} EVALs", relay.evals());
        assert!(
            relay.accepted() >= 3,
            "each lost answer redialled: {}",
            relay.accepted()
        );
        harness.clean_up().await;
    })
    .await;
}

/// A session after an idle spell: hosted Redis and serverless hosts drop
/// idle connections, so the cached Redis connection is dead by the next
/// upgrade, and the ticket's issue — sent at most once (`Replay::Never`) —
/// would fail on it: a 503. The admission PINGs first, under
/// `Replay::OnceOnFreshConnection`, which finds the connection dead and
/// redials, so the session opens: `101`, then `ready`, on a fresh connection.
///
/// The negative control: the upgrade's first `EVAL` alone (the ticket's
/// issue), on a handle whose cached connection was severed the same way,
/// fails (it is never re-sent) — which is what the upgrade would answer,
/// `503`, without the ping.
#[tokio::test]
async fn a_session_opens_after_the_cached_redis_connection_died_idle() {
    within_deadline("a session after an idle drop", async {
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let harness = Harness::with(Setup {
            redis_url: Some(relay.url.clone()),
            ..Setup::scripted(finishes())
        })
        .await;
        // A first session dials, so the connection is CACHED, and ends.
        let mut client = harness.ready().await;
        end_done(&mut client).await;
        let dials = relay.accepted();
        assert!(dials >= 1, "the first session dialled");

        // The idle drop, then the next session.
        relay.sever().await;
        settle_admission().await;
        let mut client = harness.ready().await;
        assert!(
            relay.accepted() > dials,
            "the dead connection was replaced by a fresh dial: {} dials",
            relay.accepted()
        );
        assert!(
            harness.lease().await.is_some(),
            "the session holds its lease"
        );
        end_done(&mut client).await;

        // The control: the upgrade's first EVAL — the ticket's issue, never
        // re-sent — with no PING before it.
        let bare = RedisHandle::open(&relay.url).expect("the relay's URL parses");
        bare.ping().await.expect("warm: the connection is cached");
        relay.sever().await;
        settle_admission().await;
        let refused = harness.budget.issue_ticket(&bare, harness.user).await;
        assert!(
            refused.is_err(),
            "the issue alone fails on the dead connection: {refused:?}"
        );
        harness.clean_up().await;
    })
    .await;
}

// ── How the client left ──────────────────────────────────────────────────

/// A client close frame's REASON: the relay records the code alone.
const CLOSE_REASON_CANARY: &str = "leakcanaryclosereason4e7a";

/// `logged`, a capture's whole text, holds no client close reason, as text
/// or as tungstenite's hex.
fn assert_no_close_reason(logged: &str) {
    assert!(
        !logged.contains(CLOSE_REASON_CANARY)
            && !logged.contains(&relay_harness::hex(CLOSE_REASON_CANARY.as_bytes())),
        "a client's close reason reached a log line:\n{logged}"
    );
}

/// After the relay has begun to end the session (its error event is out,
/// its close frame not yet read), the client answers with a close of its
/// own: `code`, and the canary reason. Returns the relay's close, which the
/// client reads after it — so, at the relay, the client's frame is the
/// reply to the relay's close, not a close that ended the session.
async fn client_answers_with_its_own_close(
    client: &mut relay_harness::Client,
    code: u16,
) -> (u16, String) {
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    client
        .ws
        .close(Some(CloseFrame {
            code: CloseCode::from(code),
            reason: CLOSE_REASON_CANARY.into(),
        }))
        .await
        .expect("the client's close");
    loop {
        match timeout(WAIT, client.ws.next())
            .await
            .expect("the relay's close")
        {
            Some(Ok(Message::Close(Some(frame)))) => {
                return (u16::from(frame.code), frame.reason.to_string())
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            other => panic!("expected the relay's close, got {other:?}"),
        }
    }
}

/// The endings the RELAY starts: what the client sends once the relay has
/// decided to end the session — after its error event, before the client
/// answers its close — is still read, on the way to the reply, and
/// recorded. The relay reads `end` there exactly as it does while relaying.
///
/// | the relay ends it | then the client | outcome | `end_received` | `client_close_code` |
/// |---|---|---|---|---|
/// | the provider fails: `error{provider}`, `1011` | sends `end`, then lets its socket answer the close | `provider` | true | 1011 (the echo) |
/// | the 400 ms session cap: `4000`, no event | lets its socket answer the close | `session_limit` | false | 4000 (the echo) |
/// | the user's day runs out: `error{limit}`, `4002` | sends `end`, then its own close, `4101` and the canary reason | `limit` | true | 4101 |
///
/// The reason on that reply reaches no log line.
#[tokio::test]
async fn the_session_end_line_records_what_the_client_sent_while_the_relay_closed() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);

    let provider =
        Harness::scripted(SttScript::default().fail_at(100, SttError::fixed("an error event")))
            .await;
    let mut client = provider.ready().await;
    client.audio(pcm(4_800, 1)).await;
    assert_eq!(client.event().await, provider_error());
    // The relay is past its relaying loop now: this `end` can only be read
    // while it closes.
    client.end().await;
    assert_eq!(
        client.closed_without_reply().await,
        (1011, "provider error".to_string())
    );
    client.reply_to_close().await;
    let line = session_end_for(&capture, provider.user).await;
    assert_eq!(
        how_the_client_left(&line),
        ("provider".to_string(), true, Some(1011)),
        "{line}"
    );
    provider.clean_up().await;

    let capped = Harness::with(Setup {
        settings: RelaySettings {
            session_cap: Duration::from_millis(400),
            ..quick()
        },
        ..Setup::default()
    })
    .await;
    let mut client = capped.ready().await;
    assert_eq!(
        client.closed_without_reply().await,
        (4000, "session limit".to_string())
    );
    client.reply_to_close().await;
    let line = session_end_for(&capture, capped.user).await;
    assert_eq!(
        how_the_client_left(&line),
        ("session_limit".to_string(), false, Some(4000)),
        "{line}"
    );
    capped.clean_up().await;

    let spent = Harness::new().await;
    let now = Utc::now();
    spent
        .seed(
            spent.budget.user_key(spent.user, now),
            &(USER_DAILY_MS - 300).to_string(),
        )
        .await;
    let mut client = spent.ready().await;
    assert_eq!(client.event().await, limit_event(LimitScope::UserDay, now));
    client.end().await;
    assert_eq!(
        client_answers_with_its_own_close(&mut client, 4101).await,
        (4002, "limit reached".to_string())
    );
    let line = session_end_for(&capture, spent.user).await;
    assert_eq!(
        how_the_client_left(&line),
        ("limit".to_string(), true, Some(4101)),
        "{line}"
    );
    // The server's own code is unchanged by the client's.
    assert_eq!(line["close_code"], 4002, "{line}");
    assert_eq!(line["limit_scope"], "user_day", "{line}");
    spent.clean_up().await;

    assert_no_close_reason(&capture.text());
}

/// Mic off (`1000` after `end`), both ways it happens:
///
/// | the client | outcome | `end_received` | `client_close_code` |
/// |---|---|---|---|
/// | `end`; the provider finishes; the client answers the relay's `1000 done` (its socket echoes the relay's code) | `done` | true | 1000 (its reply) |
/// | `end`, then closes `1000` itself before the relay does (its end wait ran out) | `client_closed` | true | 1000 |
#[tokio::test]
async fn mic_off_logs_1000_with_end_received() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);

    let done = Harness::scripted(finishes()).await;
    let mut client = done.ready().await;
    client.audio(pcm(4_800, 1)).await;
    // Reads the relay's close and sends tungstenite's reply: the echo.
    end_done(&mut client).await;
    let line = session_end_for(&capture, done.user).await;
    assert_eq!(
        how_the_client_left(&line),
        ("done".to_string(), true, Some(1000)),
        "{line}"
    );
    assert_eq!(line["close_code"], 1000, "{line}");
    done.clean_up().await;

    // A provider that does not finish within the end grace: the client
    // closes first.
    let first = Harness::new().await;
    let mut client = first.ready().await;
    client.audio(pcm(4_800, 2)).await;
    client.end().await;
    first
        .eventually("the end of input", |harness| harness.log.end_inputs() == 1)
        .await;
    client.close_first(1000, CLOSE_REASON_CANARY).await;
    let line = session_end_for(&capture, first.user).await;
    assert_eq!(
        how_the_client_left(&line),
        ("client_closed".to_string(), true, Some(1000)),
        "{line}"
    );
    first.clean_up().await;

    assert_no_close_reason(&capture.text());
}

/// An abrupt drop (no close frame at all) is `client_gone` with NO
/// `client_close_code` field: not `null`, not `1005`, not `1006`.
#[tokio::test]
async fn an_abrupt_drop_logs_no_client_close_code() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::new().await;
    let mut client = harness.ready().await;
    client.audio(pcm(4_800, 3)).await;
    harness
        .eventually("the frame reached the provider", |harness| {
            harness.log.frames() == [4_800]
        })
        .await;
    drop(client);
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(
        how_the_client_left(&line),
        ("client_gone".to_string(), false, None),
        "{line}"
    );
    assert!(line.get("client_close_code").is_none(), "{line}");
    harness.clean_up().await;
}

/// Every code a client closes with is accepted and logged as sent — the
/// server's own `4000`-range codes untouched, none of the client's a policy
/// breach — and echoed: `1000` without `end` (a client from before the
/// client table closes `1000` for every cause), then `4100` (left the
/// conversation), `4101` (paused), `4102` (idle), `4103` (disposed or
/// replaced) and `4104` (a client failure). Each close carries the canary
/// reason, which no line carries.
#[tokio::test]
async fn every_client_close_code_is_logged_as_sent_and_none_is_a_breach() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    for code in [1000, 4100, 4101, 4102, 4103, 4104] {
        let harness = Harness::new().await;
        let mut client = harness.ready().await;
        client.audio(pcm(4_800, 4)).await;
        client.close_first(code, CLOSE_REASON_CANARY).await;
        // The provider is closed as for any client close (no end of input
        // was sent), not failed as for a breach.
        assert_eq!(harness.log.frame_bytes(), [pcm(4_800, 4)], "{code}");
        assert_eq!(harness.log.closed(), Some(false), "{code}");
        let line = session_end_for(&capture, harness.user).await;
        assert_eq!(
            how_the_client_left(&line),
            ("client_closed".to_string(), false, Some(u64::from(code))),
            "{line}"
        );
        assert!(
            line.get("close_code").is_none() && line.get("cause").is_none(),
            "{line}"
        );
        assert_eq!(harness.lease().await, None, "{code}");
        harness.clean_up().await;
    }
    assert_no_close_reason(&capture.text());
}

/// A close frame with no code at all is recorded as `1005` (RFC 6455's "no
/// status received"), never as an absent field (that is a drop).
#[tokio::test]
async fn a_close_frame_without_a_code_logs_1005() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::new().await;
    let mut client = harness.ready().await;
    client.ws.close(None).await.expect("the client's close");
    let echo = timeout(WAIT, client.ws.next()).await.expect("the echo");
    assert!(matches!(echo, Some(Ok(Message::Close(_)))), "{echo:?}");
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(
        how_the_client_left(&line),
        ("client_closed".to_string(), false, Some(1005)),
        "{line}"
    );
    harness.clean_up().await;
}

/// Before `ready` (the provider never opens), both are recorded too:
///
/// | the client | outcome | `ready` | `end_received` | `client_close_code` |
/// |---|---|---|---|---|
/// | `end`, then answers the relay's `1000 done` | `done` | false | true | 1000 (its reply) |
/// | closes `4103` (transport replaced) | `client_closed` | false | false | 4103 |
#[tokio::test]
async fn end_and_a_close_before_ready_are_logged_too() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let never_opens = || Setup {
        stt: ScriptedStt::new(SttScript::default()).with_open(OpenScript::Hang),
        ..Setup::default()
    };

    let early_end = Harness::with(never_opens()).await;
    let mut client = early_end.open("").await;
    client.end().await;
    assert_eq!(client.closed().await, (1000, "done".to_string()));
    let line = session_end_for(&capture, early_end.user).await;
    assert_eq!(
        how_the_client_left(&line),
        ("done".to_string(), true, Some(1000)),
        "{line}"
    );
    assert_eq!(line["ready"], false, "{line}");
    early_end.clean_up().await;

    let early_close = Harness::with(never_opens()).await;
    let mut client = early_close.open("").await;
    client.close_first(4103, CLOSE_REASON_CANARY).await;
    let line = session_end_for(&capture, early_close.user).await;
    assert_eq!(
        how_the_client_left(&line),
        ("client_closed".to_string(), false, Some(4103)),
        "{line}"
    );
    assert_eq!(line["ready"], false, "{line}");
    early_close.clean_up().await;

    assert_no_close_reason(&capture.text());
}

// ── Usage ────────────────────────────────────────────────────────────────

/// A usage sink that stamps each record in a shared sequence — AFTER
/// holding the relay's thread for 200 ms. Were any closing write made before
/// the record, the client (running elsewhere) has read it by the time this
/// stamp is taken, and stamped its own arrival first.
struct OrderedUsage {
    sequence: Arc<AtomicU64>,
    records: Mutex<Vec<Stamped>>,
}

/// One record: its stamp in the shared sequence, then the sink's arguments
/// (the user aside).
type Stamped = (u64, VoiceMetric, u64, DateTime<Utc>);

impl OrderedUsage {
    fn records(&self) -> Vec<Stamped> {
        self.records.lock().expect("the records").clone()
    }
}

impl UsageSink for OrderedUsage {
    fn record(&self, _user: Uuid, metric: VoiceMetric, quantity: u64, at: DateTime<Utc>) {
        // A test instrument, not a sink an app may write: the contract is
        // to return at once.
        std::thread::sleep(Duration::from_millis(200));
        let stamp = self.sequence.fetch_add(1, Ordering::SeqCst);
        self.records
            .lock()
            .expect("the records")
            .push((stamp, metric, quantity, at));
    }
}

/// What the client thread of [`stt_usage_is_recorded_once_before_any_closing_io`]
/// saw: the event that arrived after its audio, and that arrival's stamp.
type Arrival = (RelayEvent, u64);

/// **The session's usage is recorded once, before any closing I/O**, by
/// order, not by timing. The provider fails, so the session's closing I/O
/// starts with a write: the `error{provider}` event to the client, then the
/// provider's close (which hangs here, to its bound) beside the release.
/// One shared sequence orders the usage record (stamped by the sink, which
/// first holds the relay's thread for 200 ms) and the event's arrival at
/// the client — a client on an OS thread and a runtime of its own, so that
/// it reads whatever reaches its socket while the relay's thread is held.
/// The record comes first. It is the session's exact audio milliseconds on
/// the budget's clock, the provider's close is still in progress when it
/// exists, and once the session is over it is still the only one.
#[tokio::test]
async fn stt_usage_is_recorded_once_before_any_closing_io() {
    let clock = TestClock::at("2026-10-17T12:00:00Z");
    let sequence = Arc::new(AtomicU64::new(0));
    let usage = Arc::new(OrderedUsage {
        sequence: Arc::clone(&sequence),
        records: Mutex::default(),
    });
    let harness = Harness::with(Setup {
        stt: ScriptedStt::new(
            SttScript::default()
                .fail_at(100, SttError::fixed("an error event"))
                .hang_close(),
        ),
        settings: RelaySettings {
            close_timeout: Duration::from_secs(2),
            ..quick()
        },
        budget: Some(small_budget(&clock)),
        usage: Some(Arc::clone(&usage) as Arc<dyn UsageSink>),
        ..Setup::default()
    })
    .await;

    // The client: `ready`, then 4,800 bytes and 46 more (100 ms and
    // 0.96 ms, recorded as 100), then the next event, stamped on arrival.
    // It then holds its socket, reading nothing more, until told to go.
    let url = format!("ws://{}/voice/stream", harness.addr);
    let ready = harness.ready_event();
    let stamps = Arc::clone(&sequence);
    let (arrivals, arrived) = std::sync::mpsc::channel::<Arrival>();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let client = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the client's runtime");
        runtime.block_on(async move {
            let (mut ws, _) = tokio_tungstenite::connect_async(url)
                .await
                .expect("the upgrade");
            let next_event = |message: Option<Result<Message, _>>| match message {
                Some(Ok(Message::Text(text))) => {
                    serde_json::from_str::<RelayEvent>(text.as_str()).expect("an event")
                }
                other => panic!("expected an event, got {other:?}"),
            };
            assert_eq!(next_event(ws.next().await), ready);
            ws.send(Message::Binary(pcm(4_846, 1).into()))
                .await
                .expect("send audio");
            let event = next_event(ws.next().await);
            let stamp = stamps.fetch_add(1, Ordering::SeqCst);
            arrivals.send((event, stamp)).expect("the test");
            // Hold the socket, unread, until the test is done with it.
            let _ = tokio::task::spawn_blocking(move || released.recv()).await;
            drop(ws);
        });
    });

    let deadline = Instant::now() + WAIT;
    let (event, arrival) = loop {
        if let Ok(arrival) = arrived.try_recv() {
            break arrival;
        }
        assert!(Instant::now() < deadline, "the client saw no event");
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert_eq!(event, provider_error(), "the first closing write");
    while usage.records().is_empty() {
        assert!(Instant::now() < deadline, "no usage record");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let records = usage.records();
    assert_eq!(
        records,
        [(records[0].0, VoiceMetric::SttMilliseconds, 100, clock.now())]
    );
    assert!(
        records[0].0 < arrival,
        "the usage record (stamp {}) came after the error event's write (its arrival's stamp \
         {arrival})",
        records[0].0
    );
    assert_eq!(
        harness.log.cancelled(),
        Cancelled::default(),
        "the provider's close is still in progress"
    );
    // The session ends at the close's bound (and its client close at
    // another: the client reads nothing more); still one record.
    harness
        .eventually("the provider's close dropped at its bound", |harness| {
            harness.log.cancelled().close == 1
        })
        .await;
    assert!(harness.drain(Duration::from_secs(5)).await);
    assert_eq!(usage.records().len(), 1);
    release.send(()).expect("the client thread");
    client.join().expect("the client thread");
    harness.clean_up().await;
}

// ── The lease's margin ───────────────────────────────────────────────────

/// The largest clocks `RelaySettings::check` allows, searched from the
/// production ones in whole seconds: the longest open (against the 2 s close
/// bound), then the longest refresh. At revision 1's bounds and the lease's
/// margin, they are the production clocks themselves.
fn largest_allowed_clocks() -> RelaySettings {
    let largest = |settings: RelaySettings, set: fn(&mut RelaySettings, Duration)| {
        (1..=60)
            .rev()
            .map(Duration::from_secs)
            .find(|value| {
                let mut tried = settings;
                set(&mut tried, *value);
                tried.check().is_ok()
            })
            .expect("some value passes")
    };
    let mut settings = RelaySettings::default();
    settings.open_timeout = largest(settings, |s, v| s.open_timeout = v);
    settings.refresh_interval = largest(settings, |s, v| s.refresh_interval = v);
    assert_eq!(settings.check(), Ok(()));
    settings
}

/// Stream real-time audio (a second of it a second) until `until`, reading
/// everything the relay sends meanwhile: a ping or a pong is fine, anything
/// else — above all a close — fails the test.
async fn keep_streaming_until(client: &mut relay_harness::Client, until: Instant) {
    let mut seed = 0_u8;
    while Instant::now() < until {
        client.audio(pcm(SECOND_24K, seed)).await;
        seed = seed.wrapping_add(1);
        let second = Instant::now() + Duration::from_secs(1);
        loop {
            match tokio::time::timeout_at(second, client.ws.next()).await {
                Err(_) => break,
                Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
                Ok(other) => panic!("the healthy session was ended: {other:?}"),
            }
        }
    }
}

/// `user`'s lease's remaining life, in ms (`-2`: there is none).
async fn lease_pttl(harness: &Harness) -> i64 {
    raw_redis()
        .await
        .pttl(harness.budget.lease_key(harness.user))
        .await
        .expect("PTTL the lease")
}

/// **A slow open at the largest clocks allowed keeps the lease.** The lease
/// is 30 s from the acquire and the first refresh comes one refresh interval
/// after `ready`; the open here takes nearly all of the largest open the
/// clocks allow. The session keeps streaming past that first refresh, which
/// renews the lease (its remaining life is a fresh lease's again, where the
/// acquire's own would have about ten seconds left), and ends `1000`.
///
/// (About 20 s of real time. With the check's earlier rule, a refresh under
/// the lease alone, the largest refresh was 29 s: the first refresh came
/// after the lease had lapsed, and the healthy session closed `4001`.)
#[tokio::test]
async fn a_slow_open_at_the_largest_allowed_clocks_keeps_the_lease() {
    let settings = largest_allowed_clocks();
    let open = settings.open_timeout - Duration::from_millis(300);
    let harness = Harness::with(Setup {
        stt: ScriptedStt::new(finishes()).with_open(OpenScript::After(open)),
        settings,
        ..Setup::default()
    })
    .await;
    let acquired = Instant::now();
    let mut client = harness.open("").await;
    client.wait = Duration::from_secs(15);
    assert_eq!(client.event().await, harness.ready_event());
    let ready = Instant::now();
    assert!(ready - acquired >= open, "premise: the open was slow");
    keep_streaming_until(
        &mut client,
        ready + settings.refresh_interval + Duration::from_millis(1_500),
    )
    .await;
    let pttl = lease_pttl(&harness).await;
    assert!(
        pttl > 20_000,
        "the first refresh renewed the lease: {pttl} ms left, {:?} after the acquire",
        acquired.elapsed()
    );
    client.wait = WAIT;
    end_done(&mut client).await;
    harness.clean_up().await;
    assert_eq!(
        (settings.open_timeout, settings.refresh_interval),
        (Duration::from_secs(8), Duration::from_secs(10)),
        "the production clocks are the largest the check allows"
    );
}

/// **One refresh that fails does not lose the lease**, at the production
/// clocks (the largest refresh the check allows): the first refresh is held
/// at the fault relay past its response bound, and its one replay too, so
/// it fails (one WARN line); the session streams on, and the next refresh,
/// one interval later and still inside the lease, renews it. The session
/// ends `1000`.
///
/// (About 22 s of real time. Without the three-refreshes-per-lease rule, the
/// largest refresh was 19 s: the next refresh came after the lease had
/// lapsed.)
#[tokio::test]
async fn a_single_failed_refresh_does_not_lose_the_lease() {
    within_deadline_of(Duration::from_secs(60), async {
        let (capture, _guard) = capture_logs("info");
        let settings = largest_allowed_clocks();
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let harness = Harness::with(Setup {
            redis_url: Some(relay.url.clone()),
            settings,
            ..Setup::scripted(finishes())
        })
        .await;
        let mut client = harness.ready().await;
        let ready = Instant::now();
        assert_eq!(relay.evals(), 2, "premise: the issue and the acquire");
        // The first refresh, and its replay on a fresh connection.
        relay.arm(EvalFault::Hold);
        relay.arm(EvalFault::Hold);
        keep_streaming_until(
            &mut client,
            ready + settings.refresh_interval * 2 + Duration::from_millis(1_500),
        )
        .await;
        let failed = capture
            .lines()
            .iter()
            .filter(|line| line["message"] == "voice stream: a lease refresh failed")
            .count();
        assert_eq!(
            failed,
            1,
            "premise: one refresh failed:\n{}",
            capture.text()
        );
        let pttl = lease_pttl(&harness).await;
        assert!(
            pttl > 20_000,
            "the next refresh renewed the lease: {pttl} ms left"
        );
        end_done(&mut client).await;
        harness.clean_up().await;
        assert_eq!(settings, RelaySettings::default(), "the production clocks");
    })
    .await;
}

/// `body` under `limit`, failing loudly if it runs over (the fault suites'
/// `within_deadline`, with a longer limit for a test that runs past a
/// lease's refreshes).
async fn within_deadline_of(limit: Duration, body: impl std::future::Future<Output = ()>) {
    if timeout(limit, body).await.is_err() {
        panic!("the test did not finish within {limit:?}: a socket stalled");
    }
}
