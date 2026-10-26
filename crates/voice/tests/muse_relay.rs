//! One relay session through the Muse adapter (features `live-tests`,
//! `muse`): `Voice::open_stream` with `MuseStt` served on a loopback port,
//! a tokio-tungstenite client, `muse::mock::MockMuse`, and the test Redis.
//!
//! Ported from tapper's `tests/voice_stream.rs` (`82be95f`) and lumen's
//! (`5b716ba`): the cases where the relay meets Muse's own wire. Every other
//! relay case runs against the scripted provider (`tests/relay.rs`,
//! `tests/stt_contract.rs`), and the adapter's own against the mock directly
//! (`tests/muse.rs`).
//!
//! - **the session** — the handshake, `ready` with Muse's facts, audio
//!   forwarded byte for byte, Muse's events normalized, `end` → `endStream`
//!   → Muse's `1000` → the client's `1000`, the audio charged and the lease
//!   released before the close frame;
//! - **the rate** — `?rate=16000` in the handshake and the charge;
//! - **Muse failing** — an error event, a close or a drop before `end`, no
//!   ack before the open deadline (cause `open_timeout`), a refusal, nothing
//!   listening: `error{provider}` and `1011`, the lease given back.
//!
//! The test Redis is required, never skipped (`tests/test_redis`), and every
//! test counts under prefixes of its own.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use chrono::Utc;
use redis::AsyncCommands as _;
use stridelabs_redis::RedisHandle;
use stridelabs_voice::budget::{TtsBudget, TtsCaps};
use stridelabs_voice::lease::StreamBudget;
use stridelabs_voice::muse::mock::{MockMuse, MuseConn, Seen};
use stridelabs_voice::muse::{handshake_body, MuseRate, MuseStt, END_STREAM};
use stridelabs_voice::protocol::RelayEvent;
use stridelabs_voice::stt::SttProvider as _;
use stridelabs_voice::testing::ScriptedTts;
use stridelabs_voice::tts::VoiceCatalog;
use stridelabs_voice::usage::NoUsage;
use stridelabs_voice::{RelaySettings, StreamContext, Voice, VoiceParts};
use tokio::time::{timeout, Instant};
use tokio_tungstenite::Connector;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use uuid::Uuid;

#[allow(
    dead_code,
    reason = "shared with the other live suites; not every one seeds every kind of key"
)]
mod test_redis;
use test_redis::{drop_keys_under, raw_redis, test_redis_url, tts_prefix};

#[allow(
    dead_code,
    reason = "shared with the relay suites; this one uses `capture_logs`"
)]
mod log_capture;
use log_capture::capture_logs;

#[allow(
    dead_code,
    reason = "shared with tests/relay.rs and tests/stt_contract.rs; this suite drives Muse, not \
              the scripted provider, so it uses the client side and the helpers only"
)]
mod relay_harness;
use relay_harness::{
    detail_envelope, pcm, private_budget, provider_error, quick, serve, session_end_for, Client,
    CAPPED_TRACE, SECOND_24K, WAIT,
};

/// The key every session opens with. Not a secret.
const TEST_KEY: &str = "test-meta-key-s2d";

/// What the route hands `open_stream`: the app's side.
struct App {
    voice: Arc<Voice<MuseStt, ScriptedTts>>,
    redis: RedisHandle,
    shutdown: CancellationToken,
    tracker: TaskTracker,
    user: Uuid,
}

/// The app's handler (the design's §5.2), its user fixed.
async fn voice_stream(
    State(app): State<Arc<App>>,
    RawQuery(query): RawQuery,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let context = StreamContext {
        redis: Some(&app.redis),
        shutdown: &app.shutdown,
        tracker: &app.tracker,
    };
    match app
        .voice
        .open_stream(context, app.user, query.as_deref(), upgrade)
        .await
    {
        Ok(switching) => switching,
        Err(refusal) => refusal.into_response_with(detail_envelope),
    }
}

/// One app relaying to Muse (its mock, unless a test points it elsewhere),
/// with a private budget and a user.
struct Harness {
    addr: SocketAddr,
    muse: MockMuse,
    voice: Arc<Voice<MuseStt, ScriptedTts>>,
    budget: StreamBudget,
    user: Uuid,
}

impl Harness {
    async fn new() -> Harness {
        Harness::with(None, quick()).await
    }

    /// `ws_url` `None`: the mock's.
    async fn with(ws_url: Option<&str>, settings: RelaySettings) -> Harness {
        let muse = MockMuse::start().await;
        let url = ws_url.map_or_else(|| muse.url(), str::to_string);
        let stt = MuseStt::new(TEST_KEY, &url, Vec::new(), Connector::Plain);
        let budget = private_budget();
        let voice = Voice::new(VoiceParts {
            stt,
            tts: ScriptedTts::new(),
            catalog: VoiceCatalog::identity(["Jason"], "Jason").expect("a catalog"),
            tts_budget: TtsBudget::new(
                tts_prefix(),
                TtsCaps::new(20_000, 300_000, 300_000).expect("valid caps"),
            ),
            stream_budget: budget.clone(),
            relay: RelaySettings::default(),
            usage: Arc::new(NoUsage),
        })
        .expect("Muse's facts pass revision 1")
        .with_relay_settings_unchecked(settings);
        let voice = Arc::new(voice);
        let user = Uuid::new_v4();
        let app = Arc::new(App {
            voice: Arc::clone(&voice),
            redis: RedisHandle::open(&test_redis_url().await).expect("the test URL parses"),
            shutdown: CancellationToken::new(),
            tracker: TaskTracker::new(),
            user,
        });
        let router = Router::new()
            .route("/voice/stream", get(voice_stream))
            .with_state(app);
        let addr = serve(router).await;
        Harness {
            addr,
            muse,
            voice,
            budget,
            user,
        }
    }

    /// An upgrade to `/voice/stream{query}`, answered `101`.
    async fn open(&self, query: &str) -> Client {
        let url = format!("ws://{}/voice/stream{query}", self.addr);
        let (ws, response) = timeout(WAIT, tokio_tungstenite::connect_async(url))
            .await
            .expect("the upgrade hung")
            .expect("the upgrade was refused");
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        Client { ws, wait: WAIT }
    }

    /// The `ready` Muse's facts advertise.
    fn ready_event(&self) -> RelayEvent {
        let stt = self.voice.stt();
        RelayEvent::ready(stt.formats(), stt.pacing_lead())
    }

    /// A session through `ready`: the client, the mock's side, and the
    /// handshake the mock read.
    async fn ready_with(&self, query: &str) -> (Client, MuseConn, String) {
        let mut client = self.open(query).await;
        let mut muse = self.muse.accept().await;
        let handshake = muse.text().await;
        assert_eq!(client.event().await, self.ready_event());
        (client, muse, handshake)
    }

    /// The user's lease token, `None` when there is none.
    async fn lease(&self) -> Option<String> {
        raw_redis()
            .await
            .get(self.budget.lease_key(self.user))
            .await
            .expect("GET the lease")
    }

    /// The user's day and the global month, in ms.
    async fn counters(&self) -> (Option<i64>, Option<i64>) {
        let now = Utc::now();
        let mut redis = raw_redis().await;
        let user: Option<i64> = redis
            .get(self.budget.user_key(self.user, now))
            .await
            .expect("GET user");
        let global: Option<i64> = redis
            .get(self.budget.global_key(now))
            .await
            .expect("GET global");
        (user, global)
    }

    async fn clean_up(&self) {
        drop_keys_under(self.budget.prefix()).await;
    }
}

/// The whole happy path: the handshake on the wire, `ready` with Muse's
/// facts (24 and 16 kHz, PCM s16le, a 5 s lead), audio forwarded byte for
/// byte and in order, Muse's events normalized, `end` → `endStream` →
/// Muse's `1000` → the client's `1000 done`; then the audio charged in
/// milliseconds and the lease gone, both BEFORE the close frame reached the
/// client, which is when they are read here.
#[tokio::test]
async fn a_session_relays_audio_and_events_and_ends_done() {
    let harness = Harness::new().await;
    assert_eq!(
        harness.ready_event().to_json(),
        r#"{"type":"ready","rates":[24000,16000],"encoding":"pcm_s16le","lead_ms":5000}"#
    );
    let (mut client, mut muse, handshake) = harness.ready_with("").await;
    assert_eq!(muse.path(), "/v1/asr/realtime");
    assert_eq!(handshake, handshake_body(TEST_KEY, MuseRate::Hz24000, &[]));
    assert!(
        harness.lease().await.is_some(),
        "the session holds its lease"
    );

    let frames = [pcm(3_840, 1), pcm(3_840, 2), pcm(1_000, 3)];
    for frame in &frames {
        client.audio(frame.clone()).await;
    }
    muse.send(r#"{"type":"speechStart","turnId":1}"#);
    muse.send(r#"{"type":"transcript","transcript":"what's the","final":false}"#);
    muse.send(r#"{"type":"speechEnd","turnId":1}"#);
    muse.send(r#"{"type":"speechComplete","turnId":1,"transcript":"What's the weather?"}"#);
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
    let (audio, after) = muse.audio_until_other().await;
    assert_eq!(
        audio, frames,
        "the audio reaches Muse byte for byte, in order"
    );
    assert_eq!(after, Seen::Text(END_STREAM.to_string()));
    muse.close(1000);
    assert_eq!(
        client.closed_without_reply().await,
        (1000, "done".to_string())
    );
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

/// `?rate=16000` names `PCM_16KHZ` in the handshake and is charged at 32 KB
/// a second.
#[tokio::test]
async fn the_rate_reaches_the_handshake_and_the_charge() {
    let harness = Harness::new().await;
    let (mut client, mut muse, handshake) = harness.ready_with("?rate=16000").await;
    assert_eq!(handshake, handshake_body(TEST_KEY, MuseRate::Hz16000, &[]));
    // A literal too: the line above would agree with a `handshake_body` that
    // ignored its rate.
    assert!(
        handshake.contains(r#""audioEncoding":"PCM_16KHZ""#),
        "{handshake}"
    );
    client.audio(pcm(16_000, 7)).await;
    client.end().await;
    let (audio, _) = muse.audio_until_other().await;
    assert_eq!(audio, vec![pcm(16_000, 7)]);
    muse.close(1000);
    assert_eq!(client.closed().await.0, 1000);
    assert_eq!(harness.counters().await, (Some(500), Some(500)));
    harness.clean_up().await;
}

/// Every Muse event the relay reads, and the ones it drops: `audioProgress`,
/// an unknown type, a frame that is not JSON, a binary frame. A final
/// `transcript` is still a partial; only `speechComplete` is a turn. Muse's
/// `error` ends the session: `error{provider}` and `1011`.
#[tokio::test]
async fn muse_events_normalize_and_an_error_event_is_1011() {
    let harness = Harness::new().await;
    let (mut client, muse, _) = harness.ready_with("").await;
    for frame in [
        r#"{"type":"speechStart","turnId":4}"#,
        r#"{"type":"audioProgress","audioMs":80}"#,
        r#"{"type":"transcript","transcript":"what's the weather","final":false}"#,
        r#"{"type":"somethingNew","x":1}"#,
        "this is not json",
    ] {
        muse.send(frame);
    }
    muse.send_binary(vec![9; 16]);
    for frame in [
        r#"{"type":"transcript","transcript":"what's the weather in","final":true}"#,
        r#"{"type":"speechEnd","turnId":4}"#,
        r#"{"type":"speechComplete","turnId":4,"transcript":"What's the weather in Chicago?"}"#,
        r#"{"type":"error","message":"the session failed"}"#,
    ] {
        muse.send(frame);
    }
    let (events, code, reason) = client.events_then_close().await;
    assert_eq!(
        events,
        vec![
            RelayEvent::SpeechStart,
            RelayEvent::Partial {
                text: "what's the weather".into()
            },
            RelayEvent::Partial {
                text: "what's the weather in".into()
            },
            RelayEvent::SpeechEnd,
            RelayEvent::EndOfTurn {
                text: "What's the weather in Chicago?".into()
            },
            provider_error(),
        ]
    );
    assert_eq!((code, reason.as_str()), (1011, "provider error"));
    assert_eq!(harness.lease().await, None);
    harness.clean_up().await;
}

/// No ack within the open deadline: `error{provider}`, `1011`, never
/// `ready`, the lease given back; the session-end line's cause is the
/// relay's own `open_timeout` (the adapter applies no deadline).
#[tokio::test]
async fn an_open_timeout_is_a_provider_error() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::with(
        None,
        RelaySettings {
            open_timeout: Duration::from_millis(300),
            ..quick()
        },
    )
    .await;
    harness.muse.never_ack();
    let mut client = harness.open("").await;
    let mut muse = harness.muse.accept().await;
    assert!(
        muse.text().await.contains("accessToken"),
        "the handshake was sent"
    );
    let started = Instant::now();
    let (events, code, _) = client.events_then_close().await;
    assert_eq!(events, vec![provider_error()]);
    assert_eq!(code, 1011);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(harness.lease().await, None);
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(
        line["cause"], "open_timeout: not open before the deadline",
        "{line}"
    );
    harness.clean_up().await;
}

/// Muse refusing the handshake (an error event instead of the ack, even one
/// carrying a `sessionId`), and a Muse nobody can reach: both
/// `error{provider}` + `1011`, the lease given back, each cause the
/// adapter's label and class.
#[tokio::test]
async fn a_refused_or_unreachable_muse_is_a_provider_error() {
    let (capture, _guard) = capture_logs(CAPPED_TRACE);
    let harness = Harness::new().await;
    harness.muse.reply_to_handshake(Some(
        r#"{"type":"error","message":"bad key","sessionId":"s1"}"#,
    ));
    let mut client = harness.open("").await;
    let (events, code, _) = client.events_then_close().await;
    assert_eq!((events, code), (vec![provider_error()], 1011));
    assert_eq!(harness.lease().await, None);
    let line = session_end_for(&capture, harness.user).await;
    assert_eq!(line["cause"], "refused: an error event", "{line}");
    harness.clean_up().await;

    // Nothing listens on port 1.
    let unreachable = Harness::with(Some("ws://127.0.0.1:1"), quick()).await;
    let mut client = unreachable.open("").await;
    let (events, code, _) = client.events_then_close().await;
    assert_eq!((events, code), (vec![provider_error()], 1011));
    assert_eq!(unreachable.lease().await, None);
    let line = session_end_for(&capture, unreachable.user).await;
    assert_eq!(line["cause"], "dial: io ConnectionRefused", "{line}");
    unreachable.clean_up().await;
}

/// Muse ending the session on its own (a close of any code before `end`,
/// even `1000`, or a dropped connection) is `error{provider}` + `1011`, and
/// the lease is given back.
#[tokio::test]
async fn muse_closing_or_dropping_unexpectedly_is_1011() {
    for how in ["close 1000", "close 1011", "drop"] {
        let harness = Harness::new().await;
        let (mut client, muse, _) = harness.ready_with("").await;
        match how {
            "close 1000" => muse.close(1000),
            "close 1011" => muse.close(1011),
            _ => muse.drop_connection(),
        }
        let (events, code, reason) = client.events_then_close().await;
        assert_eq!(events, vec![provider_error()], "{how}");
        assert_eq!((code, reason.as_str()), (1011, "provider error"), "{how}");
        assert_eq!(harness.lease().await, None, "{how}");
        harness.clean_up().await;
    }
}
