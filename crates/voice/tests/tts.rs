//! The text-to-speech flow (feature `live-tests`): `Voice::speak` against
//! the scripted provider (`testing::ScriptedTts`) and the test Redis, through
//! a minimal axum route that is what an app's handler is (the design's §5.2):
//! a fixed user, the app's Redis, `Voice::speak`, and the reply rendered
//! through a `{"detail"}` envelope.
//!
//! Ported from tapper's `tests/voice.rs` (`82be95f`) and lumen's (`5b716ba`):
//! their route half (the budget's own half is `tests/budget.rs`, the
//! provider's wire the adapters' suites), plus the flow's own contract
//! cases:
//!
//! - **configuration** — an unconfigured provider, or no Redis, is the
//!   `503` before any `4xx`;
//! - **the request** — the content type, the body bound (4 KiB at the
//!   protocol's minimum text bound, more for a larger one), the shape, the
//!   voice and its default, the trimmed text and its bound, the
//!   `Idempotency-Key`; none of them charges or speaks;
//! - **the charge** — before the provider, never refunded: a spent budget's
//!   `429` with its scope, the key's replay and its reuse, Redis down or
//!   poisoned; usage recorded for a FRESH charge only;
//! - **the provider** — what reaches it (the trimmed text and the mapped
//!   provider voice, nothing else), its two failure classes, an answer of
//!   another media type than declared;
//! - **the answer** — the audio as given, `no-store`, its exact length, and
//!   `X-Voice-Tts-Max-Chars` on every response;
//! - **logging** — one line per request that reached the charge, never the
//!   text or the key.
//!
//! The test Redis is required, never skipped (`tests/test_redis`), and every
//! test counts under prefixes of its own.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::routing::post;
use axum::Router;
use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use stridelabs_redis::RedisHandle;
use stridelabs_voice::budget::{ChargeKey, Fingerprint, LimitScope, TtsBudget, TtsCaps};
use stridelabs_voice::lease::{StreamBudget, StreamCaps};
use stridelabs_voice::protocol::TTS_MAX_CHARS_HEADER;
use stridelabs_voice::testing::{RecordingUsage, ScriptedStt, ScriptedTts, SttScript, MP3_FIXTURE};
use stridelabs_voice::tts::{TtsFailure, VoiceCatalog};
use stridelabs_voice::usage::{UsageSink, VoiceMetric};
use stridelabs_voice::{ErrorClass, RelaySettings, Voice, VoiceParts};
use tower::ServiceExt as _;
use uuid::Uuid;

#[allow(
    dead_code,
    reason = "shared with the other live suites; not every one seeds every kind of key"
)]
mod test_redis;
use test_redis::{
    assert_unchanged, drop_keys_under, key_states, raw_redis, seed, test_redis_url, tts_prefix,
};

#[allow(
    dead_code,
    reason = "shared with the relay suites; this one uses `capture_logs`"
)]
mod log_capture;
use log_capture::capture_logs;

/// Both apps' catalog: the eight, identity-mapped, `Jason` the default.
const EIGHT: [&str; 8] = [
    "Jason", "Hazel", "Casey", "Nadia", "Brian", "Imogen", "Liam", "Evan",
];

/// Both apps' default caps, in characters.
const USER_DAILY_CHARS: i64 = 20_000;
const GLOBAL_MONTHLY_CHARS: i64 = 300_000;

/// Nothing listens on port 1 (`tcpmux`).
const REFUSED: &str = "127.0.0.1:1";

/// `Content-Type: application/json`.
const JSON: (&str, &str) = ("content-type", "application/json");

/// The route's user, when a request names another (`x-test-user`): what an
/// app's extractor would have authenticated.
const USER_HEADER: &str = "x-test-user";

/// What a two-character text is charged: `"hi"`.
const HI: &str = r#"{"text":"hi"}"#;

/// The `422` a malformed `Idempotency-Key` gets.
const BAD_KEY: &str =
    "Idempotency-Key must be sent once, as 1 to 64 characters of A-Z, a-z, 0-9, _ and -";

/// The `422` a key sent with another sentence gets.
const KEY_REUSED: &str = "Idempotency-Key was already used for another sentence";

fn eight() -> VoiceCatalog {
    VoiceCatalog::identity(EIGHT, "Jason").expect("the eight")
}

fn default_caps() -> TtsCaps {
    TtsCaps::new(USER_DAILY_CHARS, GLOBAL_MONTHLY_CHARS, GLOBAL_MONTHLY_CHARS)
        .expect("the default caps are valid")
}

/// `instant` (RFC 3339), as UTC.
fn at(instant: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(instant)
        .expect("a fixed instant")
        .with_timezone(&Utc)
}

/// How a [`Harness`] is built.
struct Setup {
    tts: ScriptedTts,
    /// `None`: the test Redis. `Some("")`: no Redis at all (the app's
    /// `None` handle). `Some(url)`: that Redis (a dead port).
    redis_url: Option<String>,
    catalog: VoiceCatalog,
    caps: TtsCaps,
    /// The budget's clock, fixed at this instant; the system clock when
    /// `None`.
    at: Option<DateTime<Utc>>,
}

impl Default for Setup {
    fn default() -> Setup {
        Setup {
            tts: ScriptedTts::new(),
            redis_url: None,
            catalog: eight(),
            caps: default_caps(),
            at: None,
        }
    }
}

/// What the route hands `Voice::speak`: the app's side.
struct App {
    voice: Voice<ScriptedStt, ScriptedTts>,
    redis: Option<RedisHandle>,
    user: Uuid,
}

/// The app's handler (the design's §5.2), its user fixed unless the request
/// names another: `Voice::speak`, rendered through the `{"detail"}`
/// envelope.
async fn voice_tts(State(app): State<Arc<App>>, headers: HeaderMap, body: Body) -> Response {
    let user = headers
        .get(USER_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .unwrap_or(app.user);
    app.voice
        .speak(app.redis.as_ref(), user, &headers, body)
        .await
        .into_response_with(detail_envelope)
}

/// An app's voice `{"detail"}` writer: the status, the JSON content type,
/// the body as given.
fn detail_envelope(status: StatusCode, body: Bytes) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// One app: its `Voice` (the scripted providers, a private budget, recorded
/// usage) behind its route, and a user.
struct Harness {
    router: Router,
    tts: ScriptedTts,
    budget: TtsBudget,
    usage: RecordingUsage,
    user: Uuid,
    at: Option<DateTime<Utc>>,
}

impl Harness {
    async fn new() -> Harness {
        Harness::with(Setup::default()).await
    }

    async fn with(setup: Setup) -> Harness {
        let redis = match setup.redis_url {
            None => Some(RedisHandle::open(&test_redis_url().await).expect("the test URL parses")),
            Some(url) if url.is_empty() => None,
            Some(url) => Some(RedisHandle::open(&url).expect("the URL parses")),
        };
        let mut budget = TtsBudget::new(tts_prefix(), setup.caps);
        if let Some(at) = setup.at {
            budget = budget.with_clock(move || at);
        }
        let usage = RecordingUsage::default();
        let voice = Voice::new(VoiceParts {
            stt: ScriptedStt::new(SttScript::default()),
            tts: setup.tts.clone(),
            catalog: setup.catalog,
            tts_budget: budget.clone(),
            stream_budget: StreamBudget::new(
                test_redis::stream_prefix(),
                StreamCaps::from_minutes(120, 1_800, 1_800).expect("valid caps"),
            ),
            relay: RelaySettings::default(),
            usage: Arc::new(usage.clone()) as Arc<dyn UsageSink>,
        })
        .expect("the scripted parts pass");
        let user = Uuid::new_v4();
        let app = Arc::new(App { voice, redis, user });
        let router = Router::new()
            .route("/voice/tts", post(voice_tts))
            .with_state(app);
        Harness {
            router,
            tts: setup.tts,
            budget,
            usage,
            user,
            at: setup.at,
        }
    }

    /// `POST /voice/tts` with exactly `headers`.
    async fn post(&self, headers: &[(&str, &str)], body: impl Into<Body>) -> Probe {
        send(self.router.clone(), tts_request(headers, body.into())).await
    }

    /// `POST /voice/tts`, `application/json`.
    async fn speak(&self, body: &str) -> Probe {
        self.post(&[JSON], body.to_string()).await
    }

    /// `POST /voice/tts`, `application/json`, with `Idempotency-Key: key`.
    async fn speak_keyed(&self, body: &str, key: &str) -> Probe {
        self.post(&[JSON, ("idempotency-key", key)], body.to_string())
            .await
    }

    /// The budget's now: its fixed clock's, or the system's.
    fn now(&self) -> DateTime<Utc> {
        self.at.unwrap_or_else(Utc::now)
    }

    fn user_key(&self) -> String {
        self.budget.user_key(self.user, self.now())
    }

    fn global_key(&self) -> String {
        self.budget.global_key(self.now())
    }

    /// The user's and the global counter, `None` where absent.
    async fn counters(&self) -> (Option<i64>, Option<i64>) {
        let mut redis = raw_redis().await;
        let user: Option<i64> = redis.get(self.user_key()).await.expect("GET user");
        let global: Option<i64> = redis.get(self.global_key()).await.expect("GET global");
        (user, global)
    }

    async fn seed(&self, user: Option<i64>, global: Option<i64>) {
        let mut redis = raw_redis().await;
        for (key, value) in [(self.user_key(), user), (self.global_key(), global)] {
            if let Some(value) = value {
                seed(&mut redis, &key, value).await;
            }
        }
    }

    /// Delete every key this harness's prefix could have written.
    async fn clean_up(&self) {
        drop_keys_under(self.budget.prefix()).await;
    }
}

/// One answer, read whole.
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

    fn detail(&self) -> String {
        let value: serde_json::Value = serde_json::from_slice(&self.body)
            .unwrap_or_else(|error| panic!("not JSON ({error}): {:?}", self.body));
        value["detail"]
            .as_str()
            .unwrap_or_else(|| panic!("no string detail: {value}"))
            .to_string()
    }

    fn retry_after(&self) -> Option<u64> {
        self.header("retry-after")
            .map(|value| value.parse().expect("Retry-After is integer seconds"))
    }

    /// The status, the `{"detail"}` and the `Retry-After` of a refusal.
    fn refusal(&self) -> (StatusCode, String, Option<u64>) {
        (self.status, self.detail(), self.retry_after())
    }

    /// `X-Voice-Tts-Max-Chars`, parsed.
    fn max_chars(&self) -> Option<usize> {
        self.header(TTS_MAX_CHARS_HEADER)
            .map(|value| value.parse().expect("a decimal integer"))
    }
}

fn tts_request(headers: &[(&str, &str)], body: Body) -> Request<Body> {
    let mut builder = Request::builder().method(Method::POST).uri("/voice/tts");
    for (name, value) in headers {
        builder = builder.header(
            HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            HeaderValue::from_str(value).expect("a header value"),
        );
    }
    builder.body(body).expect("a request")
}

async fn send(router: Router, request: Request<Body>) -> Probe {
    let response = router.oneshot(request).await.expect("the router answers");
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

fn json_body(text: &str, voice: Option<&str>) -> String {
    match voice {
        Some(voice) => serde_json::json!({"text": text, "voice": voice}).to_string(),
        None => serde_json::json!({"text": text}).to_string(),
    }
}

/// `503 voice provider unavailable` + `Retry-After: 5`.
fn provider_unavailable() -> (StatusCode, String, Option<u64>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "voice provider unavailable".to_string(),
        Some(5),
    )
}

/// `502 voice provider error`, no `Retry-After`.
fn provider_error() -> (StatusCode, String, Option<u64>) {
    (
        StatusCode::BAD_GATEWAY,
        "voice provider error".to_string(),
        None,
    )
}

// ── 200 ──────────────────────────────────────────────────────────────────

/// The whole success contract: the provider's audio passes through byte for
/// byte, as its media type with `Cache-Control: no-store`, an exact length
/// and the text bound; the provider was asked for the TRIMMED text in the
/// mapped voice; both counters are charged exactly the trimmed text's
/// characters, and that fresh charge is the one usage record.
#[tokio::test]
async fn a_sentence_is_spoken_and_never_cached() {
    let audio = Bytes::from_static(b"ID3\x04\x00 some mp3 bytes");
    let harness = Harness::with(Setup {
        tts: ScriptedTts::new().then(Ok(audio.clone())),
        ..Setup::default()
    })
    .await;
    let probe = harness
        .speak(&json_body("  Hello there, Surly fan.\n", Some("Hazel")))
        .await;

    assert_eq!(probe.status, StatusCode::OK, "{:?}", probe.body);
    assert_eq!(probe.body, audio);
    assert_eq!(probe.header("content-type"), Some("audio/mpeg"));
    assert_eq!(probe.header("cache-control"), Some("no-store"));
    assert_eq!(
        probe.header("content-length"),
        Some(audio.len().to_string().as_str())
    );
    assert_eq!(probe.max_chars(), Some(600));
    assert_eq!(
        harness.tts.calls(),
        [("Hello there, Surly fan.".to_string(), "Hazel".to_string())]
    );
    let charged = i64::try_from("Hello there, Surly fan.".chars().count()).expect("small");
    assert_eq!(harness.counters().await, (Some(charged), Some(charged)));
    let records = harness.usage.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(
        (records[0].0, records[0].1, records[0].2),
        (
            harness.user,
            VoiceMetric::TtsCharacters,
            u64::try_from(charged).expect("positive")
        )
    );
    harness.clean_up().await;
}

// ── 503: the configuration ───────────────────────────────────────────────

/// An unconfigured provider, no Redis, or both: the configuration `503`,
/// with no `Retry-After`, BEFORE the request is judged (a malformed body,
/// another content type and an over-long one get the `503`, not their
/// `4xx`), and before any key is read. Nothing is spoken or recorded; the
/// text bound is still advertised.
#[tokio::test]
async fn an_unconfigured_tts_is_503_before_any_4xx_check() {
    let cases = [
        (
            "the provider unconfigured",
            Setup {
                tts: ScriptedTts::unconfigured(),
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
        (
            "neither",
            Setup {
                tts: ScriptedTts::unconfigured(),
                redis_url: Some(String::new()),
                ..Setup::default()
            },
        ),
    ];
    let long = "x".repeat(5_000);
    for (label, setup) in cases {
        let harness = Harness::with(setup).await;
        let requests: [(&[(&str, &str)], String); 6] = [
            (&[JSON], HI.to_string()),
            (&[JSON], r#"{"text":""}"#.to_string()),
            (&[JSON], "{not json".to_string()),
            (&[("content-type", "text/plain")], HI.to_string()),
            (&[JSON], long.clone()),
            (&[JSON, ("idempotency-key", "a b")], HI.to_string()),
        ];
        for (headers, body) in requests {
            let probe = harness.post(headers, body.clone()).await;
            assert_eq!(
                probe.refusal(),
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "voice beta not configured".to_string(),
                    None
                ),
                "{label}: {headers:?} {}",
                &body[..body.len().min(20)]
            );
            assert_eq!(probe.max_chars(), Some(600), "{label}");
        }
        assert!(harness.tts.calls().is_empty(), "{label}");
        assert!(harness.usage.records().is_empty(), "{label}");
        harness.clean_up().await;
    }
}

// ── 422 / 413 / 415 ──────────────────────────────────────────────────────

/// Every body check (each a `422`, with today's detail), and that none of
/// them reaches the provider or charges a character.
#[tokio::test]
async fn a_bad_request_is_refused_uncharged_and_unspoken() {
    const SHAPE: &str = "expected a JSON object with a string text and an optional voice";
    const UNKNOWN: &str =
        "unknown voice; expected one of Jason, Hazel, Casey, Nadia, Brian, Imogen, Liam, Evan";
    let harness = Harness::new().await;
    let too_long = "a".repeat(601);
    let cases: [(&str, String, &str); 15] = [
        ("unknown voice", json_body("hi", Some("Bob")), UNKNOWN),
        (
            "a voice in the wrong case",
            json_body("hi", Some("jason")),
            UNKNOWN,
        ),
        (
            "a voice that is not a string",
            r#"{"text":"hi","voice":5}"#.into(),
            SHAPE,
        ),
        ("empty text", json_body("", None), "text is empty"),
        (
            "whitespace-only text",
            json_body(" \n\t ", None),
            "text is empty",
        ),
        (
            "601 characters",
            json_body(&too_long, None),
            "text is over 600 characters",
        ),
        ("no text", r#"{"voice":"Hazel"}"#.into(), SHAPE),
        ("text that is not a string", r#"{"text":5}"#.into(), SHAPE),
        ("an array", r#"["hi"]"#.into(), SHAPE),
        ("malformed JSON", r#"{"text":"#.into(), SHAPE),
        ("an empty body", String::new(), SHAPE),
        (
            "a repeated text",
            r#"{"text":"hi","text":"bye"}"#.into(),
            SHAPE,
        ),
        (
            "a repeated voice",
            r#"{"text":"hi","voice":"Hazel","voice":"Liam"}"#.into(),
            SHAPE,
        ),
        (
            "a null voice, then a voice",
            r#"{"text":"hi","voice":null,"voice":"Liam"}"#.into(),
            SHAPE,
        ),
        (
            "a repeated text, spelled with an escape",
            r#"{"text":"hi","text":"bye"}"#.into(),
            SHAPE,
        ),
    ];
    for (label, body, detail) in cases {
        let probe = harness.speak(&body).await;
        assert_eq!(
            probe.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{label}: {:?}",
            probe.body
        );
        assert_eq!(probe.detail(), detail, "{label}");
        assert_eq!(
            probe.header("content-type"),
            Some("application/json"),
            "{label}"
        );
    }
    assert!(harness.tts.calls().is_empty(), "{:?}", harness.tts.calls());
    assert_eq!(harness.counters().await, (None, None));
    assert!(harness.usage.records().is_empty());
    harness.clean_up().await;
}

/// The text is counted in characters (Unicode scalar values), AFTER
/// trimming: 600 three-byte characters are allowed, 600 with whitespace
/// around them are allowed and spoken trimmed, and the charge is 600 either
/// way.
#[tokio::test]
async fn the_limit_counts_trimmed_characters_not_bytes() {
    let harness = Harness::new().await;
    let euros = "€".repeat(600);
    let padded = format!("  {}  \n", "a".repeat(600));
    for text in [euros.as_str(), padded.as_str()] {
        let probe = harness.speak(&json_body(text, None)).await;
        assert_eq!(probe.status, StatusCode::OK, "{:?}", probe.body);
    }
    let calls = harness.tts.calls();
    assert_eq!(calls[0].0, euros);
    assert_eq!(calls[1].0, "a".repeat(600));
    assert_eq!(harness.counters().await, (Some(1200), Some(1200)));
    harness.clean_up().await;
}

/// 4 KiB is the limit at the protocol's minimum text bound, read or
/// declared: a body of exactly 4096 bytes is read; one byte more is `413`
/// with or without a `Content-Length`; a declared length over the limit is
/// refused unread.
#[tokio::test]
async fn the_body_limit_is_four_kibibytes() {
    let harness = Harness::new().await;
    // Literals, not the crate's constants: a test that sized its body from
    // them would move with them.
    let at_limit = format!("{:<4096}", HI);
    assert_eq!(at_limit.len(), 4096);
    let over = format!("{at_limit} ");

    let ok = harness.post(&[JSON], at_limit).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.body);

    let over_length = over.len().to_string();
    for (label, headers) in [
        ("no Content-Length", vec![JSON]),
        (
            "a true Content-Length",
            vec![JSON, ("content-length", over_length.as_str())],
        ),
    ] {
        let probe = harness.post(&headers, over.clone()).await;
        assert_eq!(probe.status, StatusCode::PAYLOAD_TOO_LARGE, "{label}");
        assert_eq!(probe.detail(), "request body over 4 KiB", "{label}");
    }
    let declared = harness
        .post(&[JSON, ("content-length", "1000000")], HI)
        .await;
    assert_eq!(declared.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(declared.detail(), "request body over 4 KiB");
    assert_eq!(harness.tts.calls().len(), 1);
    assert_eq!(harness.counters().await, (Some(2), Some(2)));
    harness.clean_up().await;
}

/// **A declared length over the limit is refused UNREAD**: a
/// `Content-Length` of 1,000,000 on a body that panics if it is ever polled
/// is the `413` at once, within a short bound, and nothing is charged or
/// spoken. A check made after the read would poll the body (the panic) or
/// wait on it.
#[tokio::test]
async fn a_declared_oversized_body_is_refused_unread() {
    let harness = Harness::new().await;
    let unreadable = futures::stream::poll_fn(
        |_| -> std::task::Poll<Option<Result<Bytes, std::io::Error>>> {
            panic!("the body of a declared-oversized request was read")
        },
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri("/voice/tts")
        .header("content-type", "application/json")
        .header("content-length", "1000000")
        .body(Body::from_stream(unreadable))
        .expect("a request");
    let probe = tokio::time::timeout(
        Duration::from_secs(2),
        send(harness.router.clone(), request),
    )
    .await
    .expect("refused without waiting on the body");
    assert_eq!(
        probe.refusal(),
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body over 4 KiB".to_string(),
            None
        )
    );
    assert!(harness.tts.calls().is_empty());
    assert_eq!(harness.counters().await, (None, None));
    harness.clean_up().await;
}

/// A provider with a larger text bound gets a larger body limit,
/// `max(4096, 6 × bound + 256)`: 12,256 bytes for 2,000 characters, read in
/// full, one byte more refused with its byte count; and its text bound is
/// the `422`'s.
#[tokio::test]
async fn the_body_limit_follows_the_text_bound() {
    let harness = Harness::with(Setup {
        tts: ScriptedTts::new().with_max_text_chars(2_000),
        ..Setup::default()
    })
    .await;
    let at_limit = format!("{:<12256}", json_body(&"a".repeat(2_000), None));
    assert_eq!(at_limit.len(), 12_256);
    let ok = harness.post(&[JSON], at_limit.clone()).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.body);
    assert_eq!(ok.max_chars(), Some(2_000));
    let over = harness.post(&[JSON], format!("{at_limit} ")).await;
    assert_eq!(
        over.refusal(),
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body over 12256 bytes".to_string(),
            None
        )
    );
    let long = harness.speak(&json_body(&"a".repeat(2_001), None)).await;
    assert_eq!(
        long.refusal(),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "text is over 2000 characters".to_string(),
            None
        )
    );
    assert_eq!(harness.counters().await, (Some(2_000), Some(2_000)));
    harness.clean_up().await;
}

/// Only a JSON content type is read; its parameters do not matter. The
/// content type is judged before the body's bound: an over-long body of
/// another type is its `415`.
#[tokio::test]
async fn the_body_must_be_json() {
    let harness = Harness::new().await;
    for (label, content_type, status) in [
        ("none", None, StatusCode::UNSUPPORTED_MEDIA_TYPE),
        (
            "text/plain",
            Some("text/plain"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "a form",
            Some("application/x-www-form-urlencoded"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "json with a charset",
            Some("application/json; charset=utf-8"),
            StatusCode::OK,
        ),
        (
            "a +json type",
            Some("application/vnd.x+json"),
            StatusCode::OK,
        ),
    ] {
        let mut headers = Vec::new();
        if let Some(content_type) = content_type {
            headers.push(("content-type", content_type));
        }
        let probe = harness.post(&headers, HI).await;
        assert_eq!(probe.status, status, "{label}");
        if status != StatusCode::OK {
            assert_eq!(
                probe.detail(),
                "expected an application/json body",
                "{label}"
            );
        }
    }
    let plain_and_long = harness
        .post(&[("content-type", "text/plain")], "x".repeat(5_000))
        .await;
    assert_eq!(plain_and_long.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(harness.tts.calls().len(), 2);
    harness.clean_up().await;
}

// ── 503: Redis ───────────────────────────────────────────────────────────

/// A Redis that is configured but down is found out at the charge: after
/// the request validated (a bad body is still its `422`), a retryable `503`,
/// and the provider is never called. The charge FAILS CLOSED: the budgets
/// are the spending ceiling.
#[tokio::test]
async fn a_redis_that_is_down_is_a_retryable_503_and_nothing_is_spoken() {
    let harness = Harness::with(Setup {
        redis_url: Some(format!("redis://{REFUSED}")),
        ..Setup::default()
    })
    .await;
    let invalid = harness.speak(r#"{"text":""}"#).await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);

    let probe = harness.speak(HI).await;
    assert_eq!(
        probe.refusal(),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "voice beta unavailable".to_string(),
            Some(5)
        )
    );
    assert!(harness.tts.calls().is_empty());
    assert!(harness.usage.records().is_empty());
}

/// A counter that is not one the charge script wrote is the same retryable
/// `503`, with nothing spoken and nothing recorded.
#[tokio::test]
async fn a_poisoned_counter_is_a_503_and_nothing_is_spoken() {
    let harness = Harness::new().await;
    seed(&mut raw_redis().await, &harness.user_key(), "1.5").await;
    let probe = harness.speak(HI).await;
    assert_eq!(
        probe.refusal(),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "voice beta unavailable".to_string(),
            Some(5)
        )
    );
    assert!(harness.tts.calls().is_empty());
    assert!(harness.usage.records().is_empty());
    harness.clean_up().await;
}

// ── 429: the budget ──────────────────────────────────────────────────────

/// A spent budget is the `429`: today's `detail`, then the spent window's
/// scope and reset, and `Retry-After` to that reset; nothing is charged,
/// spoken or recorded. A charge that fits exactly is still admitted. Each
/// window, at a fixed instant an hour before the UTC day ends (and, for the
/// months, on the month's last day).
#[tokio::test]
async fn a_spent_budget_is_a_429_with_its_scope_and_nothing_is_spoken() {
    for (scope, now, resets_at, retry_after) in [
        (
            LimitScope::UserDay,
            "2026-10-17T23:00:00Z",
            "2026-10-18T00:00:00Z",
            3_600,
        ),
        (
            LimitScope::GlobalMonth,
            "2026-10-31T23:00:00Z",
            "2026-11-01T00:00:00Z",
            3_600,
        ),
    ] {
        let harness = Harness::with(Setup {
            at: Some(at(now)),
            ..Setup::default()
        })
        .await;
        match scope {
            LimitScope::UserDay => harness.seed(Some(USER_DAILY_CHARS - 10), Some(1_000)).await,
            _ => harness.seed(None, Some(GLOBAL_MONTHLY_CHARS - 10)).await,
        }
        let before = harness.counters().await;
        let refused = harness.speak(&json_body(&"b".repeat(11), None)).await;
        assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS, "{scope:?}");
        assert_eq!(
            std::str::from_utf8(&refused.body),
            Ok(format!(
                r#"{{"detail":"voice beta limit reached","scope":"{}","resets_at":"{resets_at}"}}"#,
                scope.as_str()
            )
            .as_str()),
            "{scope:?}"
        );
        assert_eq!(refused.retry_after(), Some(retry_after), "{scope:?}");
        assert_eq!(refused.max_chars(), Some(600));
        assert_eq!(
            harness.counters().await,
            before,
            "{scope:?}: nothing charged"
        );
        assert!(harness.tts.calls().is_empty(), "{scope:?}");
        assert!(harness.usage.records().is_empty(), "{scope:?}");

        let fits = harness.speak(&json_body(&"b".repeat(10), None)).await;
        assert_eq!(fits.status, StatusCode::OK, "{scope:?}: {:?}", fits.body);
        harness.clean_up().await;
    }
}

// ── The idempotency key ──────────────────────────────────────────────────

/// **The key is validated**: one header of 1 to 64 characters of `A-Z a-z
/// 0-9 _ -`. Empty, 65 characters, a space, a dot, a colon, a non-ASCII
/// value, or the header twice (even with one good value) is a `422` with
/// nothing charged and nothing spoken. The controls: a 64-character key and
/// no key at all are spoken and charged.
#[tokio::test]
async fn the_idempotency_key_is_one_header_of_safe_characters() {
    let harness = Harness::new().await;
    let long = "k".repeat(65);
    for bad in ["", long.as_str(), "a b", "a.b", "a:b", "a/b", "a+b"] {
        let probe = harness.speak_keyed(HI, bad).await;
        assert_eq!(
            probe.refusal(),
            (StatusCode::UNPROCESSABLE_ENTITY, BAD_KEY.to_string(), None),
            "{bad:?}"
        );
    }
    let twice = harness
        .post(
            &[
                JSON,
                ("idempotency-key", "sentence-1"),
                ("idempotency-key", "sentence-1"),
            ],
            HI,
        )
        .await;
    assert_eq!(
        twice.refusal(),
        (StatusCode::UNPROCESSABLE_ENTITY, BAD_KEY.to_string(), None)
    );
    let non_ascii = send(
        harness.router.clone(),
        Request::builder()
            .method(Method::POST)
            .uri("/voice/tts")
            .header("content-type", "application/json")
            .header(
                "idempotency-key",
                HeaderValue::from_bytes(b"caf\xc3\xa9").expect("an opaque header value"),
            )
            .body(Body::from(HI))
            .expect("a request"),
    )
    .await;
    assert_eq!(non_ascii.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(non_ascii.detail(), BAD_KEY);
    // The request is judged first: a bad body with a bad key is the body's.
    let both = harness.speak_keyed(r#"{"text":" "}"#, "a b").await;
    assert_eq!(both.detail(), "text is empty");
    assert_eq!(harness.counters().await, (None, None), "nothing charged");
    assert!(harness.tts.calls().is_empty(), "nothing spoken");

    let longest = harness.speak_keyed(HI, &"k".repeat(64)).await;
    assert_eq!(longest.status, StatusCode::OK, "{:?}", longest.body);
    let keyless = harness.speak(HI).await;
    assert_eq!(keyless.status, StatusCode::OK, "{:?}", keyless.body);
    assert_eq!(harness.counters().await, (Some(4), Some(4)));
    harness.clean_up().await;
}

/// **A sentence sent again under its key is charged once and spoken
/// again** (the key protects the budget, not provider spend). Both answers
/// are the audio; the counters move once; the provider is asked twice. The
/// control: the same sentence under ANOTHER key is a new charge.
#[tokio::test]
async fn a_sentence_sent_again_under_its_key_is_charged_once_and_spoken_again() {
    let harness = Harness::new().await;
    for attempt in 0..2 {
        let probe = harness.speak_keyed(HI, "sentence-1").await;
        assert_eq!(probe.status, StatusCode::OK, "attempt {attempt}");
        assert_eq!(probe.body.as_ref(), MP3_FIXTURE, "attempt {attempt}");
        assert_eq!(
            harness.counters().await,
            (Some(2), Some(2)),
            "attempt {attempt}: charged once"
        );
    }
    assert_eq!(harness.tts.calls().len(), 2, "spoken each time");
    let other = harness.speak_keyed(HI, "sentence-2").await;
    assert_eq!(other.status, StatusCode::OK);
    assert_eq!(harness.counters().await, (Some(4), Some(4)));
    harness.clean_up().await;
}

/// **A key sent with another sentence is a `422`, and charges nothing**:
/// another text, or the same text in another voice (the fingerprint covers
/// the APP voice and the trimmed text). The stored verdict keeps its value
/// and its expiry, and nothing is spoken. The controls: the key with its
/// own sentence (padded, the default voice named) replays.
#[tokio::test]
async fn a_key_sent_with_another_sentence_is_a_422_and_charges_nothing() {
    let harness = Harness::new().await;
    let key = ChargeKey::parse("sentence-1").expect("a key");
    let first = harness.speak_keyed(HI, key.as_str()).await;
    assert_eq!(first.status, StatusCode::OK);
    let verdict = [harness.budget.charge_key(harness.user, &key)];
    let before = key_states(&verdict).await;
    assert_eq!(
        before[0].value,
        Some(format!(
            "v1|0|{}|0",
            Fingerprint::of("Jason", "hi").as_str()
        ))
    );
    for body in [
        r#"{"text":"ho"}"#,
        r#"{"text":"hi","voice":"Hazel"}"#,
        r#"{"text":"hi there"}"#,
    ] {
        let probe = harness.speak_keyed(body, key.as_str()).await;
        assert_eq!(
            probe.refusal(),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                KEY_REUSED.to_string(),
                None
            ),
            "{body}"
        );
    }
    assert_unchanged(&verdict, &before, &key_states(&verdict).await, 2_000);
    assert_eq!(harness.counters().await, (Some(2), Some(2)));
    assert_eq!(harness.tts.calls().len(), 1);
    let control = harness
        .speak_keyed(r#"{"text":"  hi  ","voice":"Jason"}"#, key.as_str())
        .await;
    assert_eq!(control.status, StatusCode::OK);
    assert_eq!(harness.counters().await, (Some(2), Some(2)));
    harness.clean_up().await;
}

/// **The key is scoped by user**: two users sending the same key are two
/// charges, each to its own day (and both to everyone's month).
#[tokio::test]
async fn two_users_sending_one_key_are_two_charges() {
    let harness = Harness::new().await;
    let other = Uuid::new_v4();
    assert_eq!(
        harness.speak_keyed(HI, "shared").await.status,
        StatusCode::OK
    );
    let theirs = harness
        .post(
            &[
                JSON,
                ("idempotency-key", "shared"),
                (USER_HEADER, other.to_string().as_str()),
            ],
            HI,
        )
        .await;
    assert_eq!(theirs.status, StatusCode::OK);
    let their_day: Option<i64> = raw_redis()
        .await
        .get(harness.budget.user_key(other, harness.now()))
        .await
        .expect("GET");
    assert_eq!(harness.counters().await, (Some(2), Some(4)));
    assert_eq!(their_day, Some(2));
    harness.clean_up().await;
}

// ── The provider ─────────────────────────────────────────────────────────

/// **What reaches the provider** is the trimmed text and the catalog's
/// PROVIDER id: never the app's id, the user or the key. A mapped catalog
/// (`calm` → `provider-voice-7`, `bright` → `pv 9`), its default included;
/// the charge's fingerprint names the APP id.
#[tokio::test]
async fn the_adapter_receives_the_mapped_provider_voice_only() {
    let harness = Harness::with(Setup {
        catalog: VoiceCatalog::new([("calm", "provider-voice-7"), ("bright", "pv 9")], "calm")
            .expect("a mapped catalog"),
        ..Setup::default()
    })
    .await;
    for (body, key) in [
        (r#"{"text":" hello ","voice":"bright"}"#, "k1"),
        (r#"{"text":"hi"}"#, "k2"),
        (r#"{"text":"hey","voice":"calm"}"#, "k3"),
    ] {
        let probe = harness.speak_keyed(body, key).await;
        assert_eq!(probe.status, StatusCode::OK, "{body}");
    }
    assert_eq!(
        harness.tts.calls(),
        [
            ("hello".to_string(), "pv 9".to_string()),
            ("hi".to_string(), "provider-voice-7".to_string()),
            ("hey".to_string(), "provider-voice-7".to_string()),
        ]
    );
    // A provider id is not an app id.
    let provider_id = harness.speak(r#"{"text":"hi","voice":"pv 9"}"#).await;
    assert_eq!(
        provider_id.refusal(),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown voice; expected one of calm, bright".to_string(),
            None
        )
    );
    let key = ChargeKey::parse("k1").expect("a key");
    let verdict = key_states(&[harness.budget.charge_key(harness.user, &key)]).await;
    assert_eq!(
        verdict[0].value,
        Some(format!(
            "v1|0|{}|0",
            Fingerprint::of("bright", "hello").as_str()
        ))
    );
    harness.clean_up().await;
}

/// **The two failure classes**: `Unavailable` is the retryable `503` with
/// `Retry-After: 5`, `Permanent` the `502` without one. The charge stands
/// either way: made before the call, never refunded.
#[tokio::test]
async fn unavailable_is_503_retry_after_5_and_permanent_is_502() {
    let harness = Harness::with(Setup {
        tts: ScriptedTts::new()
            .then(Err(TtsFailure::Unavailable(ErrorClass::fixed("timed out"))))
            .then(Err(TtsFailure::Permanent(ErrorClass::fixed("http 400")))),
        ..Setup::default()
    })
    .await;
    let unavailable = harness.speak(HI).await;
    assert_eq!(unavailable.refusal(), provider_unavailable());
    assert_eq!(unavailable.max_chars(), Some(600));
    let permanent = harness.speak(HI).await;
    assert_eq!(permanent.refusal(), provider_error());
    assert_eq!(permanent.max_chars(), Some(600));
    assert_eq!(harness.tts.calls().len(), 2);
    assert_eq!(
        harness.counters().await,
        (Some(4), Some(4)),
        "the charge stands"
    );
    harness.clean_up().await;
}

/// **An answer of another media type than the provider declares** is never
/// a `200`: the `502`, logged at ERROR with outcome `provider_media_type`
/// and both types; the charge stands.
#[tokio::test]
async fn a_media_type_other_than_declared_is_502_and_logged_at_error() {
    let (capture, _guard) = capture_logs("trace");
    let harness = Harness::with(Setup {
        tts: ScriptedTts::new().answering_media_type("audio/wav"),
        ..Setup::default()
    })
    .await;
    let probe = harness.speak(HI).await;
    assert_eq!(probe.refusal(), provider_error());
    assert_eq!(probe.max_chars(), Some(600));
    assert_eq!(harness.tts.calls().len(), 1);
    assert_eq!(
        harness.counters().await,
        (Some(2), Some(2)),
        "the charge stands"
    );
    let lines = capture.lines();
    let line = lines
        .iter()
        .find(|line| line["outcome"] == "provider_media_type")
        .unwrap_or_else(|| panic!("no media-type line:\n{}", capture.text()));
    assert_eq!(line["severity"], "ERROR", "{line}");
    assert_eq!(line["declared"], "audio/mpeg", "{line}");
    assert_eq!(line["answered"], "audio/wav", "{line}");
    assert_eq!(line["status_class"], "5xx", "{line}");
    assert_eq!(line["user_id"], harness.user.to_string(), "{line}");
    harness.clean_up().await;
}

// ── The answer's header ──────────────────────────────────────────────────

/// **`X-Voice-Tts-Max-Chars` is on every response the flow answers**: the
/// `200`, the `413`, `415`, `422`s, `429`, `502` and every `503`
/// (configuration, Redis, provider), each exactly once, as the provider's
/// bound. A provider with a larger bound advertises it.
#[tokio::test]
async fn the_max_chars_header_is_on_every_tts_response() {
    for bound in [600_usize, 2_000] {
        let harness = Harness::with(Setup {
            tts: ScriptedTts::new()
                .with_max_text_chars(bound)
                .then(Ok(Bytes::from_static(MP3_FIXTURE)))
                .then(Err(TtsFailure::Permanent(ErrorClass::fixed("http 400"))))
                .then(Err(TtsFailure::Unavailable(ErrorClass::fixed("timed out")))),
            at: Some(at("2026-10-17T12:00:00Z")),
            ..Setup::default()
        })
        .await;
        let mut statuses = Vec::new();
        let mut check = |probe: Probe, what: &str| {
            assert_eq!(
                probe
                    .headers
                    .get_all(TTS_MAX_CHARS_HEADER)
                    .iter()
                    .collect::<Vec<_>>(),
                [&HeaderValue::from(bound)],
                "{what} ({bound})"
            );
            statuses.push(probe.status.as_u16());
        };
        check(harness.speak(HI).await, "200");
        check(harness.speak(HI).await, "502");
        check(harness.speak(HI).await, "503 provider");
        check(harness.post(&[JSON], "x".repeat(20_000)).await, "413");
        check(harness.post(&[], HI).await, "415");
        check(harness.speak(r#"{"text":""}"#).await, "422");
        check(harness.speak_keyed(HI, "a b").await, "422 key");
        harness.seed(Some(USER_DAILY_CHARS), None).await;
        check(harness.speak(HI).await, "429");
        let down = Harness::with(Setup {
            tts: ScriptedTts::new().with_max_text_chars(bound),
            redis_url: Some(format!("redis://{REFUSED}")),
            ..Setup::default()
        })
        .await;
        check(down.speak(HI).await, "503 Redis");
        let unconfigured = Harness::with(Setup {
            tts: ScriptedTts::unconfigured().with_max_text_chars(bound),
            ..Setup::default()
        })
        .await;
        check(unconfigured.speak(HI).await, "503 configuration");
        assert_eq!(
            statuses,
            [200, 502, 503, 413, 415, 422, 422, 429, 503, 503],
            "{bound}"
        );
        harness.clean_up().await;
    }
}

// ── Usage ────────────────────────────────────────────────────────────────

/// **Usage is recorded for a FRESH charge only**, at the instant it was
/// decided, synchronously before the provider is asked: a fresh charge is
/// one record (spoken, or failed at the provider: the charge stands); a
/// replayed one, a refusal (the budget, a reused key, a bad request) and a
/// Redis failure are none.
#[tokio::test]
async fn tts_usage_is_recorded_for_a_fresh_charge_only() {
    let now = at("2026-10-17T12:00:00Z");
    let harness = Harness::with(Setup {
        tts: ScriptedTts::new()
            .then(Ok(Bytes::from_static(MP3_FIXTURE)))
            .then(Ok(Bytes::from_static(MP3_FIXTURE)))
            .then(Err(TtsFailure::Permanent(ErrorClass::fixed("http 400")))),
        at: Some(now),
        ..Setup::default()
    })
    .await;
    let records = || harness.usage.records();
    let fresh = harness.speak_keyed(HI, "k1").await;
    assert_eq!(fresh.status, StatusCode::OK);
    assert_eq!(
        records(),
        [(harness.user, VoiceMetric::TtsCharacters, 2, now)],
        "a fresh charge"
    );
    let replay = harness.speak_keyed(HI, "k1").await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(records().len(), 1, "a replay is not recorded");
    let reused = harness.speak_keyed(r#"{"text":"ho"}"#, "k1").await;
    assert_eq!(reused.status, StatusCode::UNPROCESSABLE_ENTITY);
    let invalid = harness.speak(r#"{"text":""}"#).await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(records().len(), 1, "a refusal is not recorded");
    let failed = harness.speak_keyed(r#"{"text":"hey"}"#, "k2").await;
    assert_eq!(failed.refusal(), provider_error());
    assert_eq!(
        records(),
        [
            (harness.user, VoiceMetric::TtsCharacters, 2, now),
            (harness.user, VoiceMetric::TtsCharacters, 3, now),
        ],
        "a fresh charge the provider then failed is recorded: the charge stands"
    );
    harness.seed(Some(USER_DAILY_CHARS), None).await;
    let spent = harness.speak(HI).await;
    assert_eq!(spent.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(records().len(), 2, "a spent budget is not recorded");
    harness.clean_up().await;
}

/// **The fresh charge's record is made BEFORE the provider is asked**: with
/// the provider holding the request (a 30 s synthesis), the record already
/// exists once `synthesize` was called, while the request is still in
/// flight. A record made after the provider answered would not exist yet.
#[tokio::test]
async fn tts_usage_is_recorded_before_the_provider_is_asked() {
    let harness = Harness::with(Setup {
        tts: ScriptedTts::new().with_delay(Duration::from_secs(30)),
        ..Setup::default()
    })
    .await;
    let in_flight = tokio::spawn(send(
        harness.router.clone(),
        tts_request(&[JSON], Body::from(HI)),
    ));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while harness.tts.calls().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the provider was never asked"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let records = harness.usage.records();
    assert_eq!(
        records.len(),
        1,
        "no record while the provider holds the request"
    );
    assert_eq!(
        (records[0].0, records[0].1, records[0].2),
        (harness.user, VoiceMetric::TtsCharacters, 2)
    );
    assert!(!in_flight.is_finished(), "the provider is still holding it");
    in_flight.abort();
    harness.clean_up().await;
}

// ── Logging ──────────────────────────────────────────────────────────────

const KEY_CANARY: &str = "leakcanaryidempotencykey3e9f";
const TEXT_CANARY: &str = "leakcanarytext8d2b";

/// **One line per request that reached the charge**, with its outcome and
/// counts, and never the text or the `Idempotency-Key`: spoken (with its
/// latency and audio size, the charge fresh, then replayed), the provider's
/// two failures, the key reused, the budget spent. A request refused before
/// the charge writes no line.
#[tokio::test]
async fn one_line_per_charged_request_never_the_text_or_the_key() {
    let (capture, _guard) = capture_logs("trace");
    let harness = Harness::with(Setup {
        tts: ScriptedTts::new()
            .then(Ok(Bytes::from_static(MP3_FIXTURE)))
            .then(Ok(Bytes::from_static(MP3_FIXTURE)))
            .then(Err(TtsFailure::Unavailable(ErrorClass::fixed("timed out"))))
            .then(Err(TtsFailure::Permanent(ErrorClass::fixed("http 400")))),
        ..Setup::default()
    })
    .await;
    let text = format!("Tell me about {TEXT_CANARY} in Duluth.");
    let body = json_body(&text, Some("Nadia"));
    for key in [KEY_CANARY, KEY_CANARY, "other-1", "other-2"] {
        let _ = harness.speak_keyed(&body, key).await;
    }
    let reused = harness
        .speak_keyed(&json_body("something else", None), KEY_CANARY)
        .await;
    assert_eq!(reused.status, StatusCode::UNPROCESSABLE_ENTITY);
    let long = format!("{TEXT_CANARY} {}", "z".repeat(600));
    let refused = harness.speak(&json_body(&long, None)).await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    harness.seed(Some(USER_DAILY_CHARS), None).await;
    let spent = harness.speak(&body).await;
    assert_eq!(spent.status, StatusCode::TOO_MANY_REQUESTS);

    let calls = harness.tts.calls();
    assert!(
        calls.iter().all(|(spoken, _)| spoken.contains(TEXT_CANARY)),
        "the premise"
    );
    let logged = capture.text();
    for (what, canary) in [("the key", KEY_CANARY), ("the text", TEXT_CANARY)] {
        assert!(
            !logged.contains(canary),
            "{what} reached a log line:\n{logged}"
        );
    }
    let outcomes: Vec<(String, Option<String>)> = capture
        .lines()
        .into_iter()
        .filter(|line| {
            line["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("voice tts"))
        })
        .map(|line| {
            (
                line["outcome"].as_str().expect("an outcome").to_string(),
                line["charge"].as_str().map(str::to_string),
            )
        })
        .collect();
    let fresh = Some("fresh".to_string());
    assert_eq!(
        outcomes,
        [
            ("spoken".to_string(), fresh.clone()),
            ("spoken".to_string(), Some("replayed".to_string())),
            ("provider_unavailable".to_string(), fresh.clone()),
            ("provider_error".to_string(), fresh),
            ("key_reused".to_string(), None),
            ("budget".to_string(), None),
        ]
    );
    let chars = text.chars().count();
    let spoken = capture
        .lines()
        .into_iter()
        .find(|line| line["outcome"] == "spoken")
        .expect("a spoken line");
    assert_eq!(spoken["chars"], chars, "{spoken}");
    assert_eq!(spoken["voice"], "Nadia", "{spoken}");
    assert_eq!(spoken["status_class"], "2xx", "{spoken}");
    assert_eq!(spoken["audio_bytes"], MP3_FIXTURE.len(), "{spoken}");
    assert!(spoken["latency_ms"].is_u64(), "{spoken}");
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
