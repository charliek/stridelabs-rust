//! The relay suites' harness (`tests/relay.rs`, `tests/stt_contract.rs`): a
//! `Voice` built on the scripted adapters, served by a minimal axum router
//! on a loopback port, and a tokio-tungstenite client — REAL sockets, real
//! time, no paused clock; the relay's clocks are shortened instead
//! (`Voice::with_relay_settings_unchecked`).
//!
//! Rewritten from tapper's `tests/voice_stream.rs` harness (`82be95f`) for
//! the crate: no app, no token, no auth. The router's one route,
//! `GET /voice/stream`, is what an app's handler is (the design's §5.2): a
//! fixed user, the app's `StreamContext` (its Redis, a shutdown token and a
//! task tracker the test holds), `Voice::open_stream`, and a refusal
//! rendered through a `{"detail"}` envelope. The provider is
//! `testing::ScriptedStt`: what tapper's mock Muse was told to send, a test
//! here scripts; what the mock received, `SttLog` records.
//!
//! Lives at `tests/relay_harness/mod.rs`, so it is a module of each binary
//! that declares it, never a test binary of its own.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{RawQuery, State};
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, Utc};
use futures::{SinkExt as _, StreamExt as _};
use redis::AsyncCommands as _;
use stridelabs_redis::RedisHandle;
use stridelabs_voice::budget::{LimitScope, TtsBudget, TtsCaps};
use stridelabs_voice::lease::{StreamBudget, StreamCaps};
use stridelabs_voice::protocol::{ErrorCode, RelayEvent, END_FRAME};
use stridelabs_voice::stt::SttProvider as _;
use stridelabs_voice::testing::{RecordingUsage, ScriptedStt, ScriptedTts, SttLog, SttScript};
use stridelabs_voice::tts::VoiceCatalog;
use stridelabs_voice::usage::UsageSink;
use stridelabs_voice::{RelaySettings, StreamContext, Voice, VoiceParts};
use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower::ServiceExt as _;
use uuid::Uuid;

use crate::test_redis::{
    drop_keys_under, raw_redis, seed, stream_prefix, test_redis_url, tts_prefix,
};

/// How long any one wait on a socket may take before the test fails.
pub const WAIT: Duration = Duration::from_secs(5);

/// One second of 24 kHz s16le audio.
pub const SECOND_24K: usize = 48_000;

/// Both apps' default caps, in ms, which every harness that sets none
/// counts against.
pub const USER_DAILY_MS: i64 = 120 * 60_000;
pub const GLOBAL_MONTHLY_MS: i64 = 1_800 * 60_000;

/// The session-end line's message.
pub const SESSION_END: &str = "voice stream: session end";

/// The session-start line's message.
pub const SESSION_START: &str = "voice stream: session start";

/// Serve `router` on a fresh loopback port for the rest of the test.
pub async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("the listener's address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

/// `len` bytes of distinct-looking audio: an even length, a pattern seeded by
/// `seed` so two frames never compare equal by accident.
pub fn pcm(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add(u8::try_from(index % 251).expect("< 251")))
        .collect()
}

/// Clocks short enough for a test: a 500 ms bound on each write and close,
/// 500 ms for the provider to finish after `end`, no refresh unless a test
/// asks for one, an idle timeout no test trips by accident, and a 50 ms
/// admission interval, so a test that opens a second session for its user
/// waits for it on purpose (`settle_admission`).
pub fn quick() -> RelaySettings {
    RelaySettings {
        session_cap: Duration::from_secs(60),
        idle_timeout: Duration::from_secs(5),
        refresh_interval: Duration::from_secs(60),
        open_timeout: Duration::from_secs(3),
        ping_interval: Duration::from_secs(10),
        pong_deadline: Duration::from_secs(25),
        close_timeout: Duration::from_millis(500),
        end_timeout: Duration::from_millis(500),
        admit_interval: Duration::from_millis(50),
    }
}

/// Past [`quick`]'s admission interval: the same user may open again.
pub async fn settle_admission() {
    tokio::time::sleep(Duration::from_millis(80)).await;
}

/// Both apps' default stream caps.
pub fn default_caps() -> StreamCaps {
    StreamCaps::from_minutes(120, 1_800, 1_800).expect("the default caps are valid")
}

/// A stream budget under a prefix no other test (and no other suite)
/// counts under.
pub fn private_budget() -> StreamBudget {
    StreamBudget::new(stream_prefix(), default_caps())
}

/// What a harness is built from.
pub struct Setup {
    /// The speech-to-text provider; its log is the harness's.
    pub stt: ScriptedStt,
    /// `None`: the test Redis. `Some("")`: no Redis at all (the app's
    /// `None` handle). `Some(url)`: that Redis (a fault relay, a dead port).
    pub redis_url: Option<String>,
    pub settings: RelaySettings,
    /// `None`: a private budget. `Some`: another harness's — a second
    /// INSTANCE of the app sharing the first one's Redis keys.
    pub budget: Option<StreamBudget>,
    /// `None`: a fresh user. `Some`: the same user on that second instance.
    pub user: Option<Uuid>,
    /// `None`: the harness's `RecordingUsage`. `Some`: this sink instead.
    pub usage: Option<Arc<dyn UsageSink>>,
}

impl Default for Setup {
    fn default() -> Setup {
        Setup {
            stt: ScriptedStt::new(SttScript::default()),
            redis_url: None,
            settings: quick(),
            budget: None,
            user: None,
            usage: None,
        }
    }
}

impl Setup {
    /// The default setup with a provider whose sessions play `script`.
    pub fn scripted(script: SttScript) -> Setup {
        Setup {
            stt: ScriptedStt::new(script),
            ..Setup::default()
        }
    }
}

/// What the harness's route hands `open_stream`: the app's side.
struct App {
    voice: Arc<Voice<ScriptedStt, ScriptedTts>>,
    redis: Option<RedisHandle>,
    shutdown: CancellationToken,
    tracker: TaskTracker,
    user: Uuid,
}

/// The app's handler (the design's §5.2), its user fixed: the context, the
/// admission, and a refusal through the `{"detail"}` envelope.
async fn voice_stream(
    State(app): State<Arc<App>>,
    RawQuery(query): RawQuery,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let context = StreamContext {
        redis: app.redis.as_ref(),
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

/// An app's voice `{"detail"}` writer: the status, the JSON content type,
/// the body as given.
pub fn detail_envelope(status: StatusCode, body: bytes::Bytes) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// One app on a bound port: its `Voice` (the scripted provider, a private
/// budget, recorded usage), its shutdown token and task tracker, and a user.
pub struct Harness {
    pub addr: SocketAddr,
    pub router: Router,
    pub voice: Arc<Voice<ScriptedStt, ScriptedTts>>,
    /// What every session the provider opened saw.
    pub log: Arc<SttLog>,
    pub budget: StreamBudget,
    pub shutdown: CancellationToken,
    pub tracker: TaskTracker,
    pub usage: RecordingUsage,
    pub user: Uuid,
}

impl Harness {
    pub async fn new() -> Harness {
        Harness::with(Setup::default()).await
    }

    pub async fn scripted(script: SttScript) -> Harness {
        Harness::with(Setup::scripted(script)).await
    }

    pub async fn with(setup: Setup) -> Harness {
        let redis = match setup.redis_url {
            None => Some(RedisHandle::open(&test_redis_url().await).expect("the test URL parses")),
            Some(url) if url.is_empty() => None,
            Some(url) => Some(RedisHandle::open(&url).expect("the URL parses")),
        };
        let budget = setup.budget.unwrap_or_else(private_budget);
        let usage = RecordingUsage::default();
        let log = setup.stt.log();
        let voice = Voice::new(VoiceParts {
            stt: setup.stt,
            tts: ScriptedTts::new(),
            catalog: VoiceCatalog::identity(["Jason"], "Jason").expect("a catalog"),
            tts_budget: TtsBudget::new(
                tts_prefix(),
                TtsCaps::new(20_000, 300_000, 300_000).expect("valid caps"),
            ),
            stream_budget: budget.clone(),
            relay: RelaySettings::default(),
            usage: setup
                .usage
                .unwrap_or_else(|| Arc::new(usage.clone()) as Arc<dyn UsageSink>),
        })
        .expect("the scripted parts pass")
        .with_relay_settings_unchecked(setup.settings);
        let voice = Arc::new(voice);
        let shutdown = CancellationToken::new();
        let tracker = TaskTracker::new();
        let user = setup.user.unwrap_or_else(Uuid::new_v4);
        let app = Arc::new(App {
            voice: Arc::clone(&voice),
            redis,
            shutdown: shutdown.clone(),
            tracker: tracker.clone(),
            user,
        });
        let router = Router::new()
            .route("/voice/stream", get(voice_stream))
            .with_state(app);
        let addr = serve(router.clone()).await;
        Harness {
            addr,
            router,
            voice,
            log,
            budget,
            shutdown,
            tracker,
            usage,
            user,
        }
    }

    /// An upgrade to `/voice/stream{query}`.
    pub async fn try_open(&self, query: &str) -> Result<Client, Answer> {
        let url = format!("ws://{}/voice/stream{query}", self.addr);
        match timeout(WAIT, tokio_tungstenite::connect_async(url))
            .await
            .expect("the upgrade hung")
        {
            Ok((ws, response)) => {
                assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
                Ok(Client { ws, wait: WAIT })
            }
            Err(tungstenite::Error::Http(response)) => Err(Answer {
                status: response.status(),
                headers: response.headers().clone(),
                body: String::from_utf8_lossy(response.body().as_deref().unwrap_or_default())
                    .into_owned(),
            }),
            Err(error) => panic!("the upgrade failed below HTTP: {error}"),
        }
    }

    pub async fn open(&self, query: &str) -> Client {
        self.try_open(query)
            .await
            .unwrap_or_else(|refused| panic!("the upgrade was refused: {refused:?}"))
    }

    /// The `ready` this harness's provider advertises.
    pub fn ready_event(&self) -> RelayEvent {
        let stt = self.voice.stt();
        RelayEvent::ready(stt.formats(), stt.pacing_lead())
    }

    /// A session through `ready`.
    pub async fn ready_with(&self, query: &str) -> Client {
        let mut client = self.open(query).await;
        assert_eq!(client.event().await, self.ready_event());
        client
    }

    pub async fn ready(&self) -> Client {
        self.ready_with("").await
    }

    /// The user's lease token, `None` when there is none.
    pub async fn lease(&self) -> Option<String> {
        raw_redis()
            .await
            .get(self.budget.lease_key(self.user))
            .await
            .expect("GET the lease")
    }

    /// The user's day and the global month, in ms.
    pub async fn counters(&self) -> (Option<i64>, Option<i64>) {
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

    pub async fn seed(&self, key: String, value: &str) {
        seed(&mut raw_redis().await, &key, value).await;
    }

    /// Whether the relay began opening a provider session (after giving it a
    /// moment): what tapper's mock Muse called being dialled.
    pub async fn was_opened(&self) -> bool {
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.log.opens_started() > 0
    }

    /// A plain HTTP request through the router itself (no socket): what a
    /// non-upgrade request gets.
    pub async fn plain(&self, method: Method, path: &str) -> Answer {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .expect("a request");
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("the router is infallible");
        Answer::read(response).await
    }

    /// A real upgrade request, through the router, whose upgrade then FAILS:
    /// hyper's `OnUpgrade` for a request that has none, which resolves to an
    /// error — what a connection that dies between the `101` and the upgrade
    /// gives axum. Every check before the upgrade runs for real (the lease
    /// is taken); the answer is the `101`.
    pub async fn failed_upgrade(&self) -> StatusCode {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/voice/stream")
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Body::empty())
            .expect("a request");
        let never = hyper::upgrade::on(&mut request);
        request.extensions_mut().insert(never);
        self.router
            .clone()
            .oneshot(request)
            .await
            .expect("the router is infallible")
            .status()
    }

    /// The tracker's drain, as an app's shutdown runs it: closed, then
    /// waited on for at most `within`. `true` when every tracked task ended.
    pub async fn drain(&self, within: Duration) -> bool {
        self.tracker.close();
        timeout(within, self.tracker.wait()).await.is_ok()
    }

    /// Until `done` holds (polled every 10 ms), for at most [`WAIT`].
    pub async fn eventually(&self, what: &str, done: impl Fn(&Harness) -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done(self) {
            assert!(Instant::now() < deadline, "never: {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn clean_up(&self) {
        drop_keys_under(self.budget.prefix()).await;
    }
}

/// An HTTP answer: an upgrade the app refused, or a plain request's.
#[derive(Debug)]
pub struct Answer {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Answer {
    async fn read(response: Response) -> Answer {
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        Answer {
            status,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    pub fn retry_after(&self) -> i64 {
        self.header("retry-after")
            .and_then(|value| value.parse().ok())
            .expect("a Retry-After")
    }
}

/// What the client received next.
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    Event(RelayEvent),
    Closed(u16, String),
    Gone,
}

/// The client's side.
#[derive(Debug)]
pub struct Client {
    pub ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    pub wait: Duration,
}

impl Client {
    pub async fn next(&mut self) -> Received {
        loop {
            let message = timeout(self.wait, self.ws.next())
                .await
                .expect("nothing from the relay before the deadline");
            match message {
                Some(Ok(Message::Text(text))) => {
                    return Received::Event(
                        serde_json::from_str(text.as_str())
                            .unwrap_or_else(|error| panic!("not a relay event ({error}): {text}")),
                    )
                }
                Some(Ok(Message::Close(frame))) => {
                    // Flush the reply tungstenite queued, so the relay's wait
                    // for it ends at once.
                    let _ = timeout(Duration::from_secs(1), self.ws.flush()).await;
                    let (code, reason) = frame.map_or((1005, String::new()), |frame| {
                        (u16::from(frame.code), frame.reason.to_string())
                    });
                    return Received::Closed(code, reason);
                }
                Some(Ok(Message::Binary(_))) => panic!("the relay sent the client binary"),
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return Received::Gone,
            }
        }
    }

    pub async fn event(&mut self) -> RelayEvent {
        match self.next().await {
            Received::Event(event) => event,
            other => panic!("expected an event, got {other:?}"),
        }
    }

    /// The next message, which must be a close frame, read without sending
    /// the reply tungstenite queues for it — the relay is left waiting for
    /// it, up to its close bound. [`Client::reply_to_close`] sends it.
    pub async fn closed_without_reply(&mut self) -> (u16, String) {
        loop {
            match timeout(self.wait, self.ws.next())
                .await
                .expect("nothing from the relay before the deadline")
            {
                Some(Ok(Message::Close(frame))) => {
                    let frame = frame.expect("a close frame");
                    return (u16::from(frame.code), frame.reason.to_string());
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                other => panic!("expected a close, got {other:?}"),
            }
        }
    }

    pub async fn reply_to_close(&mut self) {
        let _ = timeout(Duration::from_secs(1), self.ws.flush()).await;
    }

    pub async fn closed(&mut self) -> (u16, String) {
        match self.next().await {
            Received::Closed(code, reason) => (code, reason),
            other => panic!("expected a close, got {other:?}"),
        }
    }

    /// Every event until the close, and the close.
    pub async fn events_then_close(&mut self) -> (Vec<RelayEvent>, u16, String) {
        let mut events = Vec::new();
        loop {
            match self.next().await {
                Received::Event(event) => events.push(event),
                Received::Closed(code, reason) => return (events, code, reason),
                Received::Gone => panic!("the relay dropped the client without a close frame"),
            }
        }
    }

    pub async fn audio(&mut self, bytes: Vec<u8>) {
        self.ws
            .send(Message::Binary(bytes.into()))
            .await
            .expect("send audio");
    }

    pub async fn text(&mut self, text: &str) {
        self.ws
            .send(Message::text(text.to_string()))
            .await
            .expect("send text");
    }

    pub async fn end(&mut self) {
        self.text(END_FRAME).await;
    }

    /// The client closes first with `code` and `reason`, then reads the
    /// relay's echo, which carries the same code.
    pub async fn close_first(&mut self, code: u16, reason: &str) {
        self.ws
            .close(Some(CloseFrame {
                code: CloseCode::from(code),
                reason: reason.to_string().into(),
            }))
            .await
            .expect("the client's close");
        let echo = timeout(WAIT, self.ws.next()).await.expect("the echo");
        assert!(
            matches!(echo, Some(Ok(Message::Close(Some(ref frame)))) if u16::from(frame.code) == code),
            "{echo:?}"
        );
    }

    /// Nothing at all arrives for `period`: no event, no close.
    pub async fn quiet_for(&mut self, period: Duration) {
        if let Ok(message) = timeout(period, self.ws.next()).await {
            panic!("expected nothing for {period:?}, got {message:?}");
        }
    }
}

pub fn provider_error() -> RelayEvent {
    RelayEvent::error(ErrorCode::Provider)
}

/// `instant` as the voice routes write it: RFC 3339, UTC, `Z`, whole seconds.
pub fn rfc3339(instant: DateTime<Utc>) -> String {
    instant.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The `limit` event the relay sends for a spent `scope`: the scope, and its
/// window's end as of `now`.
pub fn limit_event(scope: LimitScope, now: DateTime<Utc>) -> RelayEvent {
    RelayEvent::Error {
        code: ErrorCode::Limit,
        scope: Some(scope),
        resets_at: Some(scope.resets_at(now)),
    }
}

/// `instant` (RFC 3339), as UTC.
pub fn at(instant: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(instant)
        .expect("a fixed instant")
        .with_timezone(&Utc)
}

/// A clock a test moves by hand: the day- and month-boundary seam
/// (`StreamBudget::with_clock`).
#[derive(Clone)]
pub struct TestClock(Arc<Mutex<DateTime<Utc>>>);

impl TestClock {
    pub fn at(instant: &str) -> TestClock {
        TestClock(Arc::new(Mutex::new(at(instant))))
    }

    pub fn now(&self) -> DateTime<Utc> {
        *self.0.lock().expect("the clock's lock")
    }

    pub fn set(&self, instant: &str) {
        *self.0.lock().expect("the clock's lock") = at(instant);
    }

    /// `budget` on this clock.
    pub fn drive(&self, budget: StreamBudget) -> StreamBudget {
        let clock = self.clone();
        budget.with_clock(move || clock.now())
    }
}

/// Small caps, in ms, so a window is spent with a small seed: a day of 100 s,
/// a user's month of 200 s, everyone's month of 300 s.
pub const SMALL_DAY_MS: i64 = 100_000;
pub const SMALL_USER_MONTH_MS: i64 = 200_000;
pub const SMALL_GLOBAL_MONTH_MS: i64 = 300_000;

/// A private budget with the small caps, on `clock`.
pub fn small_budget(clock: &TestClock) -> StreamBudget {
    clock.drive(StreamBudget::new(
        stream_prefix(),
        StreamCaps::unchecked(SMALL_DAY_MS, SMALL_USER_MONTH_MS, SMALL_GLOBAL_MONTH_MS),
    ))
}

/// `budget`'s three counters for `user` at `now`: day, user month, global.
pub fn counter_keys(budget: &StreamBudget, user: Uuid, now: DateTime<Utc>) -> [String; 3] {
    [
        budget.user_key(user, now),
        budget.user_month_key(user, now),
        budget.global_key(now),
    ]
}

/// Their values, `None` where absent.
pub async fn counter_values(keys: &[String; 3]) -> [Option<i64>; 3] {
    let mut redis = raw_redis().await;
    let mut values = [None; 3];
    for (value, key) in values.iter_mut().zip(keys) {
        *value = redis.get(key).await.expect("GET");
    }
    values
}

/// The session-end line for `user`, once the relay has written it.
pub async fn session_end_for(
    capture: &crate::log_capture::Capture,
    user: Uuid,
) -> serde_json::Value {
    let deadline = Instant::now() + WAIT;
    loop {
        let found = capture
            .lines()
            .into_iter()
            .find(|line| line["message"] == SESSION_END && line["user_id"] == user.to_string());
        if let Some(line) = found {
            return line;
        }
        assert!(
            Instant::now() < deadline,
            "no session-end line for {user}:\n{}",
            capture.text()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A session-end line's outcome, `end_received` (always present) and
/// `client_close_code`: `None` when the field is ABSENT, which is how the
/// line says "no close frame" (a `null` fails here, as a non-number).
pub fn how_the_client_left(line: &serde_json::Value) -> (String, bool, Option<u64>) {
    let fields = line.as_object().expect("a JSON object");
    (
        line["outcome"].as_str().expect("an outcome").to_string(),
        line["end_received"]
            .as_bool()
            .unwrap_or_else(|| panic!("end_received is always present: {line}")),
        fields.get("client_close_code").map(|code| {
            code.as_u64()
                .unwrap_or_else(|| panic!("client_close_code is a number when present: {line}"))
        }),
    )
}

/// The capture filter the relay suites read their lines under: TRACE for
/// every target but the two tungstenite ones, held at `info` as an app holds
/// them (`stridelabs_voice::LOG_CAPS`; their frame dumps are what the caps
/// exist for).
pub const CAPPED_TRACE: &str = "trace,tungstenite=info,tokio_tungstenite=info";

/// `bytes` as lowercase hex — tungstenite's `Display` of a frame's payload.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
