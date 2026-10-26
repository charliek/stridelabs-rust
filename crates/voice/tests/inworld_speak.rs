//! `Voice::speak` through the Inworld adapter (features `live-tests`,
//! `inworld`): the text-to-speech flow with `InworldTts` over the client an
//! app builds, against `inworld::mock::MockInworld` and the test Redis,
//! through the same minimal route `tests/tts.rs` serves.
//!
//! Ported from tapper's `tests/voice.rs` (`82be95f`) and lumen's
//! `tests/voice.rs` and `tests/voice_bounds.rs` (`5b716ba`), the cases that
//! need both the provider's wire and the charge:
//!
//! - **the success** — the request on the wire, the audio as given, the
//!   counters charged the trimmed text and their expiries;
//! - **the voices** — the default and each of the eight, sent as itself;
//! - **every failure** — each of Inworld's answers and each bound as the
//!   route's `503` + `Retry-After: 5` or `502`, and the charge that stands;
//! - **logging** — neither the key nor the text reaches a log line, with the
//!   mock echoing both in its error bodies.
//!
//! The test Redis is required, never skipped (`tests/test_redis`), and every
//! test counts under prefixes of its own.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::routing::post;
use axum::Router;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chrono::Utc;
use redis::AsyncCommands as _;
use stridelabs_inworld::{InworldClient, SYNTHESIS_PATH};
use stridelabs_redis::RedisHandle;
use stridelabs_voice::budget::{TtsBudget, TtsCaps};
use stridelabs_voice::inworld::mock::{MockInworld, Reply};
use stridelabs_voice::inworld::{InworldSpeech, InworldTts, INWORLD_VOICES};
use stridelabs_voice::lease::{StreamBudget, StreamCaps};
use stridelabs_voice::testing::{ScriptedStt, SttScript};
use stridelabs_voice::tts::VoiceCatalog;
use stridelabs_voice::usage::NoUsage;
use stridelabs_voice::window::{day_end, month_end, seconds_until};
use stridelabs_voice::{RelaySettings, Voice, VoiceParts};
use tower::ServiceExt as _;
use uuid::Uuid;

#[allow(
    dead_code,
    reason = "shared with the other live suites; not every one seeds every kind of key"
)]
mod test_redis;
use test_redis::{drop_keys_under, raw_redis, seed, stream_prefix, test_redis_url, tts_prefix};

#[allow(
    dead_code,
    reason = "shared with the relay suites; this one uses `capture_logs`"
)]
mod log_capture;
use log_capture::capture_logs;

/// The key every configured test runs with. Not a secret; the canary test
/// uses a key of its own.
const TEST_KEY: &str = "dGVzdC1pbndvcmxkLWtleQ==";

/// Nothing listens on port 1 (`tcpmux`).
const REFUSED: &str = "http://127.0.0.1:1";

/// Both apps' speech.
const SPEECH: InworldSpeech = InworldSpeech {
    model_id: "inworld-tts-2-flash",
    audio_encoding: "MP3",
    sample_rate_hertz: 24_000,
    bit_rate: 64_000,
    max_text_chars: 600,
};

/// Both apps' default caps, in characters.
const USER_DAILY_CHARS: i64 = 20_000;
const GLOBAL_MONTHLY_CHARS: i64 = 300_000;

/// What a two-character text is charged: `"hi"`.
const HI: &str = r#"{"text":"hi"}"#;

/// The client an app builds: `key` at `base`, both apps' bounds with
/// `timeout`, the MP3 check on, on a client with the client crate's
/// injected-client contract.
fn client(base: &str, key: &str, timeout: Duration) -> InworldClient {
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
        .expect("a plain HTTP client");
    InworldClient::builder(http, key)
        .base_url(base)
        .timeout(timeout)
        .max_response_bytes(4 * 1024 * 1024)
        .max_audio_bytes(2 * 1024 * 1024)
        .max_text_chars(600)
        .mp3_check(true)
        .build()
        .expect("a loopback IP literal builds")
}

/// Opens with an MPEG frame sync and is zero-padded to `len`.
fn audio(len: usize) -> Vec<u8> {
    let mut bytes = vec![0xff, 0xf3, 0x84, 0xc4];
    bytes.resize(len, 0);
    bytes
}

struct App {
    voice: Voice<ScriptedStt, InworldTts>,
    redis: RedisHandle,
    user: Uuid,
}

/// The app's handler (the design's §5.2), its user fixed.
async fn voice_tts(State(app): State<Arc<App>>, headers: HeaderMap, body: Body) -> Response {
    app.voice
        .speak(Some(&app.redis), app.user, &headers, body)
        .await
        .into_response_with(|status, body| {
            (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
        })
}

/// One app speaking through Inworld (its mock, unless a test points the
/// client elsewhere), with a private budget and a user.
struct Harness {
    router: Router,
    inworld: MockInworld,
    budget: TtsBudget,
    user: Uuid,
}

impl Harness {
    async fn new() -> Harness {
        Harness::with("", TEST_KEY, Duration::from_secs(5)).await
    }

    /// `base` empty: the mock's.
    async fn with(base: &str, key: &str, timeout: Duration) -> Harness {
        let inworld = MockInworld::start().await;
        let base = if base.is_empty() {
            inworld.base_url()
        } else {
            base.to_string()
        };
        let tts = InworldTts::new(Ok(client(&base, key, timeout)), true, SPEECH)
            .expect("both apps' parts pass");
        let budget = TtsBudget::new(
            tts_prefix(),
            TtsCaps::new(USER_DAILY_CHARS, GLOBAL_MONTHLY_CHARS, GLOBAL_MONTHLY_CHARS)
                .expect("the default caps are valid"),
        );
        let voice = Voice::new(VoiceParts {
            stt: ScriptedStt::new(SttScript::default()),
            tts,
            catalog: VoiceCatalog::identity(INWORLD_VOICES, "Jason").expect("the eight"),
            tts_budget: budget.clone(),
            stream_budget: StreamBudget::new(
                stream_prefix(),
                StreamCaps::from_minutes(120, 1_800, 1_800).expect("valid caps"),
            ),
            relay: RelaySettings::default(),
            usage: Arc::new(NoUsage),
        })
        .expect("Inworld's facts pass revision 1");
        let user = Uuid::new_v4();
        let redis = RedisHandle::open(&test_redis_url().await).expect("the test URL parses");
        let router = Router::new()
            .route("/voice/tts", post(voice_tts))
            .with_state(Arc::new(App { voice, redis, user }));
        Harness {
            router,
            inworld,
            budget,
            user,
        }
    }

    /// `POST /voice/tts`, `application/json`.
    async fn speak(&self, body: &str) -> Probe {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/voice/tts")
            .header(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("application/json"),
            )
            .body(Body::from(body.to_string()))
            .expect("a request");
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the body");
        Probe {
            status,
            headers,
            body,
        }
    }

    fn user_key(&self) -> String {
        self.budget.user_key(self.user, Utc::now())
    }

    fn global_key(&self) -> String {
        self.budget.global_key(Utc::now())
    }

    /// The user's and the global counter, `None` where absent.
    async fn counters(&self) -> (Option<i64>, Option<i64>) {
        let mut redis = raw_redis().await;
        let user: Option<i64> = redis.get(self.user_key()).await.expect("GET user");
        let global: Option<i64> = redis.get(self.global_key()).await.expect("GET global");
        (user, global)
    }

    async fn clean_up(&self) {
        drop_keys_under(self.budget.prefix()).await;
    }
}

/// A refusal's status, `{"detail"}` and `Retry-After`.
type Refusal = (StatusCode, String, Option<u64>);

struct Probe {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Probe {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .map(|value| value.to_str().expect("an ASCII header"))
    }

    /// The status, the `{"detail"}` and the `Retry-After` of a refusal.
    fn refusal(&self) -> Refusal {
        let value: serde_json::Value = serde_json::from_slice(&self.body)
            .unwrap_or_else(|error| panic!("not JSON ({error}): {:?}", self.body));
        (
            self.status,
            value["detail"].as_str().expect("a detail").to_string(),
            self.header("retry-after")
                .map(|value| value.parse().expect("integer seconds")),
        )
    }
}

fn json_body(text: &str, voice: Option<&str>) -> String {
    match voice {
        Some(voice) => serde_json::json!({"text": text, "voice": voice}).to_string(),
        None => serde_json::json!({"text": text}).to_string(),
    }
}

/// `503 voice provider unavailable` + `Retry-After: 5`.
fn provider_unavailable() -> Refusal {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "voice provider unavailable".to_string(),
        Some(5),
    )
}

/// `502 voice provider error`, no `Retry-After`.
fn provider_error() -> Refusal {
    (
        StatusCode::BAD_GATEWAY,
        "voice provider error".to_string(),
        None,
    )
}

// ── 200 ──────────────────────────────────────────────────────────────────

/// The whole success contract through Inworld: the audio passes through
/// byte for byte, as `audio/mpeg` with `Cache-Control: no-store` and an exact
/// length; the request on the wire is the pinned one (the TRIMMED text);
/// both counters are charged exactly the trimmed text's characters, and
/// expire after their window (plus its grace).
#[tokio::test]
async fn a_sentence_is_spoken_charged_and_never_cached() {
    let harness = Harness::new().await;
    let mp3 = audio(9_000);
    harness.inworld.reply_with(Reply::Audio(mp3.clone()));

    let probe = harness
        .speak(&json_body("  Hello there, Surly fan.\n", Some("Hazel")))
        .await;

    assert_eq!(probe.status, StatusCode::OK, "{:?}", probe.body);
    assert_eq!(probe.body.as_ref(), mp3.as_slice());
    assert_eq!(probe.header("content-type"), Some("audio/mpeg"));
    assert_eq!(probe.header("cache-control"), Some("no-store"));
    assert_eq!(
        probe.header("content-length"),
        Some(mp3.len().to_string().as_str())
    );
    assert_eq!(probe.header("x-voice-tts-max-chars"), Some("600"));

    let seen = harness.inworld.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, SYNTHESIS_PATH);
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some(format!("Basic {TEST_KEY}").as_str())
    );
    assert_eq!(seen[0].content_type.as_deref(), Some("application/json"));
    assert_eq!(
        seen[0].body,
        r#"{"text":"Hello there, Surly fan.","voiceId":"Hazel","modelId":"inworld-tts-2-flash","audioConfig":{"audioEncoding":"MP3","bitRate":64000,"sampleRateHertz":24000}}"#
    );

    let charged = i64::try_from("Hello there, Surly fan.".chars().count()).expect("small");
    assert_eq!(harness.counters().await, (Some(charged), Some(charged)));
    let mut redis = raw_redis().await;
    let now = Utc::now();
    let user_ttl: i64 = redis.ttl(harness.user_key()).await.expect("TTL");
    let global_ttl: i64 = redis.ttl(harness.global_key()).await.expect("TTL");
    let day_left = seconds_until(day_end(now), now);
    let month_left = seconds_until(month_end(now), now);
    assert!(
        (day_left + 3600 - 5..=day_left + 3600 + 1).contains(&user_ttl),
        "user TTL {user_ttl}, day left {day_left}"
    );
    assert!(
        (month_left + 86_400 - 5..=month_left + 86_400 + 1).contains(&global_ttl),
        "global TTL {global_ttl}, month left {month_left}"
    );
    harness.clean_up().await;
}

/// No `voice` and `"voice": null` both speak as Jason; each of the eight is
/// sent upstream as itself.
#[tokio::test]
async fn the_voice_defaults_to_jason_and_each_of_the_eight_is_itself() {
    let harness = Harness::new().await;
    // A repeated UNKNOWN key is skipped like any unknown key; only `text` and
    // `voice` may not repeat.
    for body in [
        r#"{"text":"hi"}"#,
        r#"{"text":"hi","voice":null}"#,
        r#"{"text":"hi","extra":1,"extra":2}"#,
    ] {
        let probe = harness.speak(body).await;
        assert_eq!(probe.status, StatusCode::OK, "{body}");
    }
    for voice in INWORLD_VOICES {
        let probe = harness.speak(&json_body("hi", Some(voice))).await;
        assert_eq!(probe.status, StatusCode::OK, "{voice}");
    }
    let voice_ids: Vec<String> = harness
        .inworld
        .seen()
        .iter()
        .map(|seen| {
            let body: serde_json::Value = serde_json::from_str(&seen.body).expect("JSON");
            body["voiceId"].as_str().expect("a voiceId").to_string()
        })
        .collect();
    assert_eq!(
        voice_ids,
        [
            "Jason", "Jason", "Jason", "Jason", "Hazel", "Casey", "Nadia", "Brian", "Imogen",
            "Liam", "Evan"
        ]
    );
    harness.clean_up().await;
}

// ── 502 / 503: the provider ──────────────────────────────────────────────

/// Every way Inworld can fail, and its status: `408`/`429`/`5xx`/a status
/// past `599`/a truncated body are `503` + `Retry-After: 5`; a `4xx`, a
/// redirect not followed and a malformed, oversized or non-MP3 `200` are
/// `502`. The charge stands every time: it was made before the call and is
/// never refunded.
#[tokio::test]
async fn every_provider_failure_maps_to_502_or_503_and_the_charge_stands() {
    let harness = Harness::new().await;
    let oversized_audio = format!(
        r#"{{"audioContent":"{}"}}"#,
        BASE64_STANDARD.encode(vec![0u8; 2 * 1024 * 1024 + 1])
    );
    let cases: Vec<(&str, Reply, Refusal)> = vec![
        ("408", Reply::Body(408, "{}".into()), provider_unavailable()),
        ("429", Reply::Body(429, "{}".into()), provider_unavailable()),
        ("500", Reply::Body(500, "{}".into()), provider_unavailable()),
        ("503", Reply::Body(503, "{}".into()), provider_unavailable()),
        ("600", Reply::Body(600, "{}".into()), provider_unavailable()),
        ("999", Reply::Body(999, "{}".into()), provider_unavailable()),
        ("truncated", Reply::Truncated, provider_unavailable()),
        ("400", Reply::Body(400, "{}".into()), provider_error()),
        ("401", Reply::Body(401, "{}".into()), provider_error()),
        ("422", Reply::Body(422, "{}".into()), provider_error()),
        ("a redirect", Reply::Redirect, provider_error()),
        (
            "200, not JSON",
            Reply::Body(200, "<html>".into()),
            provider_error(),
        ),
        (
            "200, no audioContent",
            Reply::Body(200, "{}".into()),
            provider_error(),
        ),
        (
            "200, audio that is not MP3",
            Reply::Body(200, r#"{"audioContent":"bm90IG1wMw=="}"#.into()),
            provider_error(),
        ),
        (
            "200, audio over 2 MiB",
            Reply::Body(200, oversized_audio),
            provider_error(),
        ),
        (
            "200, declared oversized",
            Reply::DeclaredOversized,
            provider_error(),
        ),
    ];
    let count = cases.len();
    for (label, reply, refusal) in cases {
        harness.inworld.reply_with(reply);
        let probe = harness.speak(HI).await;
        assert_eq!(probe.refusal(), refusal, "{label}");
        assert_eq!(
            probe.header("x-voice-tts-max-chars"),
            Some("600"),
            "{label}"
        );
    }
    let seen = harness.inworld.seen();
    assert_eq!(seen.len(), count, "{seen:?}");
    let charged = i64::try_from(count * 2).expect("small");
    assert_eq!(harness.counters().await, (Some(charged), Some(charged)));
    harness.clean_up().await;
}

/// A provider that hangs is a retryable `503` at the client's deadline (the
/// apps' is 15 s; this client's 300 ms), and so is one nothing listens on;
/// the charge stands.
#[tokio::test]
async fn a_hung_or_unreachable_provider_is_a_retryable_503() {
    let hung = Harness::with("", TEST_KEY, Duration::from_millis(300)).await;
    hung.inworld.reply_with(Reply::Hang(Duration::from_secs(5)));
    let started = Instant::now();
    let probe = hung.speak(HI).await;
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(probe.refusal(), provider_unavailable());
    assert_eq!(hung.counters().await, (Some(2), Some(2)));
    hung.clean_up().await;

    let unreachable = Harness::with(REFUSED, TEST_KEY, Duration::from_secs(5)).await;
    let probe = unreachable.speak(HI).await;
    assert_eq!(probe.refusal(), provider_unavailable());
    assert_eq!(unreachable.counters().await, (Some(2), Some(2)));
    unreachable.clean_up().await;
}

/// Each bound through the route: an endless body and a declared oversized
/// one are the `502` (the response bound), a body that stalls after its
/// headers and one that drips are the `503` (the total timeout); the charge
/// stands each time.
#[tokio::test]
async fn each_bound_answers_its_status_and_the_charge_stands() {
    let harness = Harness::with("", TEST_KEY, Duration::from_millis(500)).await;
    for (label, reply, refusal) in [
        ("endless", Reply::Endless, provider_error()),
        (
            "declared oversized",
            Reply::DeclaredOversized,
            provider_error(),
        ),
        (
            "stall after the headers",
            Reply::StallAfterHeaders,
            provider_unavailable(),
        ),
        ("drip", Reply::Drip, provider_unavailable()),
    ] {
        harness.inworld.reply_with(reply);
        let probe = harness.speak(HI).await;
        assert_eq!(probe.refusal(), refusal, "{label}");
    }
    harness.inworld.endless_was_dropped().await;
    assert_eq!(harness.counters().await, (Some(8), Some(8)));
    harness.clean_up().await;
}

// ── Logging ──────────────────────────────────────────────────────────────

const KEY_CANARY: &str = "leak-canary-inworld-key-3e9f1c27";
const TEXT_CANARY: &str = "leakcanarytext8d2b";

/// Neither the key nor the text reaches a log line, through a success,
/// every failure class (with the mock ECHOING both in its error bodies, so
/// a logged provider body would leak them), a refusal and a timeout, while
/// the one outcome line per spoken request IS written, with its counts.
#[tokio::test]
async fn neither_the_key_nor_the_text_reaches_a_log_line() {
    let (capture, _guard) = capture_logs("trace");
    let harness = Harness::with("", KEY_CANARY, Duration::from_millis(300)).await;
    let text = format!("Tell me about {TEXT_CANARY} in Duluth.");
    let echo = format!(r#"{{"error":"{TEXT_CANARY} {KEY_CANARY}"}}"#);
    for reply in [
        Reply::Audio(audio(2_000)),
        Reply::Body(500, echo.clone()),
        Reply::Body(400, echo.clone()),
        Reply::Body(200, echo.clone()),
        Reply::Body(200, format!("not json {TEXT_CANARY} {KEY_CANARY}")),
        Reply::Hang(Duration::from_secs(2)),
    ] {
        harness.inworld.reply_with(reply);
        let _ = harness.speak(&json_body(&text, Some("Nadia"))).await;
    }
    // A refusal that never reaches the provider, with the text in it.
    let long = format!("{TEXT_CANARY} {}", "z".repeat(600));
    let refused = harness.speak(&json_body(&long, None)).await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    seed(
        &mut raw_redis().await,
        &harness.user_key(),
        USER_DAILY_CHARS,
    )
    .await;
    let spent = harness.speak(&json_body(&text, None)).await;
    assert_eq!(spent.status, StatusCode::TOO_MANY_REQUESTS);

    // The provider really was sent the canaries, so the absence below means
    // something.
    let seen = harness.inworld.seen();
    assert!(seen.iter().all(|seen| seen.body.contains(TEXT_CANARY)));
    assert!(seen.iter().all(|seen| seen
        .authorization
        .as_deref()
        .is_some_and(|value| value.contains(KEY_CANARY))));

    let logged = capture.text();
    for (what, canary) in [("the key", KEY_CANARY), ("the text", TEXT_CANARY)] {
        assert!(
            !logged.contains(canary),
            "{what} reached a log line:\n{logged}"
        );
    }

    // One outcome line per request that reached the budget: six spoken
    // attempts and the refusal, with the counts and no text.
    let outcomes: Vec<serde_json::Value> = capture
        .lines()
        .into_iter()
        .filter(|line| {
            line["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("voice tts"))
        })
        .collect();
    assert_eq!(outcomes.len(), 7, "{outcomes:#?}");
    let chars = text.chars().count();
    let spoken = outcomes
        .iter()
        .find(|line| line["outcome"] == "spoken")
        .unwrap_or_else(|| panic!("no spoken line: {outcomes:#?}"));
    assert_eq!(spoken["chars"], chars, "{spoken}");
    assert!(spoken["latency_ms"].is_u64(), "{spoken}");
    assert_eq!(spoken["status_class"], "2xx", "{spoken}");
    harness.clean_up().await;
}

/// The control for the test above: the same capture sees a canary logged on
/// purpose, through `tracing` AND through the `log` bridge.
#[tokio::test]
async fn the_capture_sees_a_deliberate_leak() {
    let (capture, _guard) = capture_logs("trace");
    tracing::trace!(key = KEY_CANARY, "a deliberate leak");
    tracing_log::log::trace!("a deliberate leak through log: {TEXT_CANARY}");
    let logged = capture.text();
    assert!(
        logged.contains(KEY_CANARY),
        "the capture is blind: {logged}"
    );
    assert!(
        logged.contains(TEXT_CANARY),
        "the log bridge is blind: {logged}"
    );
}
