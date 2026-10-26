# stridelabs-voice

The voice core StrideLabs apps share: what lets a client talk to an app (a
speech-to-text relay over a WebSocket) and hear it answer (text to speech,
one sentence per request) inside a spending ceiling, with the speech
providers swappable behind it. The core names no provider; a provider is an
adapter behind a feature.

Extracted from tapper (`tapper-rs/src/voice/`, at `82be95f`), which had
hardened lumen's copy; both apps run this crate's scripts and key shapes,
byte for byte, so either adopts it with no change on the wire.

**What is here** is the core every voice route stands on — the client
protocol, the provider traits, the app's voice catalog and refusals, the
checked `Voice`, and the Redis budgets — and, behind `axum`, the two flows
(the speech-to-text relay and its admission; the text-to-speech request),
and, each behind a feature of its own, the two provider adapters (Muse for
speech to text, Inworld for text to speech):

| Module | Holds |
|---|---|
| `protocol` | the client contract, revision 1 ([`PROTOCOL.md`](PROTOCOL.md) is canonical): the relay's events (`RelayEvent`, `ErrorCode`, the advertising `RelayEvent::ready`), both close-code tables (`close_code`, `client_close_code`), `END_FRAME`, `TTS_MIN_TEXT_CHARS` and its header, `IDEMPOTENCY_KEY_HEADER`, `ALLOWED_AUDIO_TYPES`, the `rate`/`encoding` parameters, `tts_body_limit`, the golden fixture and its SHA-256 |
| `stt` | the speech-to-text provider traits (`SttProvider`, `SttSession`), `SttEvent`, the fixed-class errors (`SttOpenError`, `OpenLabel`, `SttError`), `AudioFormat`, `Encoding`, and revision 1's constants (`PROTOCOL_DEFAULT_RATES`, `MIN_PACING_LEAD`, the sample-rate range, `MAX_SILENT_FRAMES_PER_POLL`); the module docs are the contract an adapter keeps |
| `tts` | the text-to-speech provider trait (`TtsProvider`, `SynthesisRequest`, `Audio`, `TtsFailure`), the app's `VoiceCatalog` (`CatalogError`), the request's strict parse (`parse_request` → `SpeakRequest`; behind `axum`, `read_request`: the `415`, the `413`s, then the parse), `charge_key`, `is_json_content_type`; the module docs are the contract |
| `usage` | the usage seam (`UsageSink`, `VoiceMetric`, `NoUsage`) |
| `refusal` | every refusal the voice routes answer (`VoiceRefusal`, `RefusalKind`): status, `{"detail"}` body, headers; the budget's `429` body (`VoiceLimitBody`) |
| the root | `Voice` (built from `VoiceParts`, checked by `Voice::new` → `VoiceSetupError`), `RelaySettings` (the relay's clocks and `RelaySettings::check`), `ErrorClass`; behind `axum`, `Voice::speak` and its `TtsReply`, and `StreamContext` (what `Voice::open_stream` needs of the app); behind `axum` or `muse`, `LOG_CAPS` |
| `window` | the UTC day and month a budget counts in: when each ends (`day_end`, `month_end`), `seconds_until` (a `Retry-After` or a TTL, rounded up, never zero), the key stamps, `key_ttls`, the `Clock` |
| `budget` | the text-to-speech character budget (`TtsBudget`, `TtsCaps`), the per-sentence idempotency key (`ChargeKey`, `Fingerprint`, `Admitted`, `Disposition`), and what both budgets share: the caps rule (`CapsError`, `CapProblem`) and the refusal (`LimitScope`, `Spent`, `LimitReached`) |
| `lease` | the speech-to-text audio budget (`StreamBudget`, `StreamCaps`): the fenced lease (`issue_ticket`, `acquire` → `Grant`), metering (`meter` → `Metered`), `audio_ms` |
| `relay` | (`axum`) one relay session: the client's audio to the provider, the provider's events back, the close machine, the session's two log lines; `PROVIDER_RUN_CAP`, the client socket's bounds, `budget_deadline` |
| `stream` | (`axum`) the upgrade's admission, `Voice::open_stream` (the configuration `503`, the `426`, the `rate`/`encoding` `422`s, the ping, the ticket and the fenced acquire, the takeover on this instance, the upgrade); `parse_rate`, `parse_encoding`, `DEFAULT_ENCODING` |
| `muse` | (`muse`) the Muse speech-to-text adapter: `MuseStt` (the app's key, URL, keywords and connector) and its `MuseSession`; `handshake_body`, `MuseEvent`, `MuseRate`, `realtime_url` (`UrlProblem`), `error_class`, `socket_config`, the endpoint constants; with `test-support` and `axum`, `mock::MockMuse` |
| `inworld` | (`inworld`) the Inworld text-to-speech adapter: `InworldTts` over the app's `InworldClient` and `InworldSpeech` (`InworldSetupError`), `INWORLD_VOICES`, `failure`; with `test-support` and `axum`, `mock::MockInworld` |
| `testing` | (`test-support`) the scripted adapters the core is tested against: `ScriptedStt` (its sessions play an `SttScript`, recording into an `SttLog`), `ScriptedTts`, `RecordingUsage`, `MP3_FIXTURE` |

## Adding the dependency

```toml
[dependencies]
stridelabs-voice = { git = "https://github.com/charliek/stridelabs-rust.git", tag = "v0.11.0" }
```

New in v0.11.0. See the workspace root README for the local `[patch]`
co-development snippet.

## Feature topology

`default = []`: the core above, with no feature at all (no HTTP server, no
provider, no client of any kind).

| Feature | For | Adds |
|---|---|---|
| `axum` | apps | the relay (`relay`) and the stream's admission (`stream`, `Voice::open_stream`, `StreamContext`) on axum's WebSocket; the text-to-speech flow (`Voice::speak`, `TtsReply`, `tts::read_request`); `VoiceRefusal::into_response_with` (a refusal rendered through the app's envelope); `LOG_CAPS` |
| `muse` | apps | the Muse adapter (`muse`), dialled through the app's `tokio_tungstenite::Connector` (tokio-tungstenite with `connect` and `rustls-tls-native-roots`, its rustls without a provider: the app's connector carries the app's); `LOG_CAPS` |
| `inworld` | apps | the Inworld adapter (`inworld`), on stridelabs-inworld (no features: the client is the app's) |
| `openapi` | apps | `utoipa::ToSchema` on `budget::LimitScope` and `refusal::VoiceLimitBody` (as `VoiceLimitReached`), for the app's OpenAPI document |
| `test-support` | tests | the `testing` module (the scripted adapters), and the test seams, none of them API without it: `TtsBudget::with_clock` / `StreamBudget::with_clock` (a fixed or moving clock, for the UTC boundaries), `TtsCaps::unchecked` / `StreamCaps::unchecked` (caps the rule refuses), `StreamBudget::acquire_under` (the real acquire under another replay policy), `Voice::with_relay_settings_unchecked` (clocks shorter than `RelaySettings::check` allows; only a zero is refused), and with `axum` `Voice::live_session_count` and each enabled adapter's mock provider (`muse::mock::MockMuse`, `inworld::mock::MockInworld`: loopback servers on axum, so `axum`'s `http1` comes on with it) |
| `live-tests` | this crate only | its real-Redis suites (`tests/budget.rs`, `tests/lease.rs`, the relay's `tests/relay.rs` and `tests/stt_contract.rs`, the text-to-speech flow's `tests/tts.rs`, and with an adapter `tests/muse_relay.rs` and `tests/inworld_speak.rs`), which turn `axum` on; never for consumers |

The features' dependencies are the narrowest that compile: tokio is `time`,
`sync` and `rt` for the core (`sync` and `rt` also come with tokio-util's
`rt`, which the shutdown token and the drain tracker need), plus `macros` and
`rt` behind `axum` (`select!`, `join!`, `spawn`, the cooperative budget) and
`net` behind `muse`; never the workspace's `full`. Nothing here selects a
crypto provider or builds a client: `muse`'s rustls and tokio-tungstenite
have no provider feature, and both adapters take what the app builds. Three
CI guards and two source scans hold that (see "Build guards" below).

## Using it

```rust,no_run
use std::time::Duration;

use stridelabs_redis::RedisHandle;
use stridelabs_voice::budget::{BudgetError, ChargeKey, Disposition, Fingerprint, TtsBudget, TtsCaps};
use stridelabs_voice::lease::{MeterMode, StreamBudget, StreamCaps};
use uuid::Uuid;

# async fn example(redis: &RedisHandle, user: Uuid) -> Result<(), Box<dyn std::error::Error>> {
// At startup: the app's prefixes and caps (its settings; the crate has no
// defaults). A `CapsError` is a startup refusal.
let tts = TtsBudget::new("myapp:voice:tts", TtsCaps::new(20_000, 300_000, 300_000)?);
let stream = StreamBudget::new(
    "myapp:voice:stream",
    StreamCaps::from_minutes(120, 1_800, 1_800)?,
);

// Per sentence: charge the trimmed text's characters BEFORE asking the
// provider, under the request's Idempotency-Key (or a minted one).
let key = ChargeKey::mint();
let fingerprint = Fingerprint::of("Jason", "Hello there.");
match tts.charge(redis, user, 12, &key, &fingerprint).await {
    Ok(admitted) => {
        // Speak. Record usage only for a fresh charge: a replay was counted.
        let _count_it = admitted.disposition == Disposition::Fresh;
    }
    // 429, with `scope`, `resets_at` and `Retry-After` from the limit.
    Err(BudgetError::Exceeded(limit)) => {
        let _ = (limit.scope, limit.resets_at, limit.retry_after_seconds);
    }
    // `KeyReused` is a 422; `Backend` (and anything newer) a 503.
    Err(_) => {}
}

// Per stream session: a PING (replaces an idle-dead connection), the
// ticket, the acquire; then a meter at each tick and a release at the end.
redis.ping().await?;
let ticket = stream.issue_ticket(redis, user).await?;
let token = Uuid::new_v4();
let grant = stream.acquire(redis, user, token, ticket, Duration::from_secs(2)).await?;
let tick = stream.meter(redis, user, token, 1_500, MeterMode::Refresh).await?;
if let Some(limit) = tick.limit_reached() {
    // The session ends, reporting `limit.scope`.
    let _ = limit;
}
stream.meter(redis, user, token, 3_000, MeterMode::Release).await?;
# let _ = grant;
# Ok(())
# }
```

## The client protocol

[`PROTOCOL.md`](PROTOCOL.md) is the wire contract between an app's voice
client (the Dart package `stridelabs_voice`) and its server (this crate,
mounted by the app): the relay's upgrade, frames, events and close codes;
the text-to-speech request, answer and refusals; the advertised facts
(`ready`'s `rates`, `encoding` and `lead_ms`; `X-Voice-Tts-Max-Chars`); the
app voice catalog rule; and the compatibility rule (additive and
presence-based; anything else is a new route). It is revision 1, and it
holds every server to what the installed clients can do: both 24 and
16 kHz, a pacing lead of at least 5 s, `ready` within 10 s, an idle timeout
of at least 10 s, a reopen admitted after at most 2 s, at most 2 s for the
provider after `end`.

`fixtures/relay_events.json` is the golden fixture: one of every event, in
the crate's canonical rendering (`RelayEvent::golden_fixture`), SHA-256
`0437bc8114b0397e3b9734e03c9cb3d72f18ba928f22a160e19fb68f6226ed15`
(`protocol::GOLDEN_FIXTURE_SHA256`). `tests/golden.rs` compares the file byte
for byte with that rendering and its hash with the one `PROTOCOL.md`
records; the client package keeps a byte copy whose test checks the same
hash. Neither repository reads the other's files: the hash is the drift
check, and a protocol revision changes `PROTOCOL.md`, the fixture and the
hash together.

## Providers

A provider is an adapter: a type implementing `stt::SttProvider` (with its
`SttSession`) or `tts::TtsProvider`, behind a feature of its own. The core
names no provider and builds no client: the adapter is handed the app's
client (or connector) and keys. The contract each trait carries (what each
event means, how a session ends, open, cancel safety, write completion,
keepalive, no starvation, close; the media type, the text bound, the voices,
the failure classes, billing) is in the `stt` and `tts` module docs.

An app assembles its `Voice` once, at startup, from its parts:

```rust,no_run
use std::sync::Arc;

use stridelabs_voice::budget::{TtsBudget, TtsCaps};
use stridelabs_voice::lease::{StreamBudget, StreamCaps};
use stridelabs_voice::stt::SttProvider;
use stridelabs_voice::tts::{TtsProvider, VoiceCatalog};
use stridelabs_voice::usage::NoUsage;
use stridelabs_voice::{RelaySettings, Voice, VoiceParts};

fn voice<S: SttProvider, T: TtsProvider>(stt: S, tts: T) -> Arc<Voice<S, T>> {
    let parts = VoiceParts {
        stt,
        tts,
        // What clients show, store and send, each mapped to a provider voice
        // (here identity-mapped), and the default.
        catalog: VoiceCatalog::identity(["Jason", "Hazel"], "Jason").expect("a valid catalog"),
        tts_budget: TtsBudget::new(
            "myapp:voice:tts",
            TtsCaps::new(20_000, 300_000, 300_000).expect("valid caps"),
        ),
        stream_budget: StreamBudget::new(
            "myapp:voice:stream",
            StreamCaps::from_minutes(120, 1_800, 1_800).expect("valid caps"),
        ),
        relay: RelaySettings::default(),
        usage: Arc::new(NoUsage),
    };
    // The checks are code facts (the adapters' constants and the catalog),
    // not deployment configuration: the app tests that its parts pass, and
    // expects at startup.
    Arc::new(Voice::new(parts).expect("revision 1 of the protocol takes these parts"))
}
```

`Voice::new` checks the relay's clocks (`RelaySettings::check`), then the
speech-to-text adapter's facts, then the text-to-speech adapter's against
the catalog, against revision 1 of the protocol (the two methods' docs list
every check, in order). An unconfigured adapter is not a startup failure: it
is the route's `503`.

## The stream's route

The route is the app's: its path, its authentication (FIRST: an
unauthenticated caller learns nothing of the configuration), its `405`s and
its documentation. Its handler is one call — the user the app
authenticated, the raw query, the upgrade taken as a `Result` (so the
configuration `503` comes before the `426`), and a `StreamContext` with the
app's Redis and shutdown — and a refusal rendered through the app's own
`{"detail"}` envelope:

```rust,no_run
# #[cfg(feature = "axum")]
# mod example {
use std::sync::Arc;

use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::WebSocketUpgrade;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse as _, Response};
use stridelabs_redis::RedisHandle;
use stridelabs_voice::stt::SttProvider;
use stridelabs_voice::tts::TtsProvider;
use stridelabs_voice::{StreamContext, Voice};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use uuid::Uuid;

/// `GET /voice/stream`, once the app's extractor authenticated `user`.
async fn voice_stream<S: SttProvider, T: TtsProvider>(
    voice: &Arc<Voice<S, T>>,
    redis: Option<&RedisHandle>,
    shutdown: &CancellationToken,
    tracker: &TaskTracker,
    user: Uuid,
    query: Option<&str>,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let context = StreamContext { redis, shutdown, tracker };
    match voice.open_stream(context, user, query, upgrade).await {
        Ok(switching) => switching,
        Err(refusal) => refusal.into_response_with(|status: StatusCode, body| {
            (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
        }),
    }
}
# }
```

- **Shutdown**: cancelling the token closes every live session `1001`, each
  after its release; an admitted session (and the lease release of an
  upgrade that failed after its `101`) holds a tracker token until it is
  done, so the app's drain (`tracker.close()`, then `tracker.wait()` under
  its deadline) waits for them.
- **The relay's clocks** (`RelaySettings`, checked by `Voice::new`):
  revision 1's bounds, and the lease's margin. The lease is 30 s
  (`LEASE_TTL`) from the acquire and the first refresh comes one
  `refresh_interval` after `ready`, so `open_timeout + close_timeout +
  refresh_interval` must stay under the lease (the first refresh lands in
  it after the slowest open) and `refresh_interval` at most a third of it
  (from the first good refresh on, one refresh that fails never costs the
  lease). The production clocks (an 8 s open, a 2 s close bound, a 10 s
  refresh) are the largest that pass.
- **One session per user**: a newer upgrade supersedes the older session
  at once on the same instance (`4001`), and at its next refresh from
  another instance (the lease).
- **Logging**: two lines per session (`voice stream: session start` and
  `voice stream: session end`, the latter WARN on a provider or internal
  failure or a failed release), a WARN per failed refresh, one line per
  admission the ping, the ticket or the acquire refused, and one for the
  lease release of an upgrade that failed, under the targets
  `stridelabs_voice::relay` and `stridelabs_voice::stream`; never a key,
  audio, a transcript, a provider's text or a close frame's reason. The
  relay's client socket is tungstenite, so the app folds `LOG_CAPS` into its
  subscriber's caps: below `INFO` tungstenite dumps every frame.
- **Usage**: each session records its audio milliseconds once, as it ends,
  before any closing I/O (`UsageSink::record` must return at once).

## The text-to-speech route

The same shape as the stream's: the app's path, authentication (FIRST),
`405`s and documentation, then one call with the user it authenticated,
the request's headers and its body, rendered through its envelope:

```rust,no_run
# #[cfg(feature = "axum")]
# mod example {
use axum::body::Body;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse as _, Response};
use stridelabs_redis::RedisHandle;
use stridelabs_voice::stt::SttProvider;
use stridelabs_voice::tts::TtsProvider;
use stridelabs_voice::Voice;
use uuid::Uuid;

/// `POST /voice/tts`, once the app's extractor authenticated `user`.
async fn voice_tts<S: SttProvider, T: TtsProvider>(
    voice: &Voice<S, T>,
    redis: Option<&RedisHandle>,
    user: Uuid,
    headers: HeaderMap,
    body: Body,
) -> Response {
    voice
        .speak(redis, user, &headers, body)
        .await
        .into_response_with(|status: StatusCode, body| {
            (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
        })
}
# }
```

- **The order** (`Voice::speak`'s docs): the configuration `503` (the
  provider unconfigured, or no Redis), then the request (`415`, `413`
  declared, `413` read, the `422`s: the shape, the voice, an empty text, a
  text over the provider's bound), the `Idempotency-Key` (`422`), the
  charge (`429`, `422` for a key that names another sentence, `503` +
  `Retry-After: 5` for Redis), then the provider: the audio (`200`, its
  media type, `Cache-Control: no-store`, its exact length), `503` +
  `Retry-After: 5` or `502`. The body is read up to
  `protocol::tts_body_limit(max_text_chars)`: 4 KiB for both apps.
- **The charge stands**: made before the provider is asked, never
  refunded; a sentence sent again under its key is charged once and spoken
  again.
- **A media type the provider did not declare** is never a `200`: the
  `502`, logged at ERROR (`outcome = "provider_media_type"`).
- **`X-Voice-Tts-Max-Chars`** (the provider's text bound) is on every
  answer `TtsReply` renders; the app's own answers on the route (its
  `401`s, its auth-outage `503`, its `405`s) need it too, so its route
  layer sets it where it is missing (`PROTOCOL.md` §5.2).
- **Logging**: one line per request that reached the charge (target
  `stridelabs_voice::voice`, message `voice tts…`): the user, the character
  count, the app voice, the status class, an outcome word (`spoken`,
  `budget`, `key_reused`, `redis`, `provider_unavailable`,
  `provider_error`, `provider_media_type`), the charge's disposition and,
  once the provider was asked, its latency. Never the text, the key or a
  body.
- **Usage**: a FRESH charge is recorded (`VoiceMetric::TtsCharacters`, at
  the charge's instant) before the provider is asked; a replayed one never.

## The adapters

Each is handed the app's keys, settings and transport; neither builds a
client, a TLS configuration or a connector, and neither selects a crypto
provider (the app installs aws-lc-rs).

```rust,no_run
# #[cfg(all(feature = "muse", feature = "inworld"))]
# mod example {
use stridelabs_inworld::InworldClient;
use stridelabs_voice::inworld::{InworldSetupError, InworldSpeech, InworldTts};
use stridelabs_voice::muse::MuseStt;

fn adapters(
    meta_api_key: &str,
    meta_ws_url: &str,
    keywords: Vec<String>,
    ws_connector: tokio_tungstenite::Connector,
    provider_client: reqwest::Client,
    inworld_api_key: &str,
    inworld_base_url: &str,
) -> Result<(MuseStt, InworldTts), InworldSetupError> {
    // Speech to text: the app's key, URL, keywords (none: the handshake's
    // field is omitted) and connector (aws-lc-rs and the platform verifier).
    let stt = MuseStt::new(meta_api_key, meta_ws_url, keywords, ws_connector);
    if let Some(problem) = stt.url_problem() {
        // The problem, never the URL, under the app's own setting name.
        tracing::warn!(%problem, "voice: META_WS_URL is refused; GET /voice/stream answers 503");
    }
    // Text to speech: the client the app built (its reqwest client, its
    // bounds, the MP3 check on), whether the key is set, and the speech.
    let client = InworldClient::builder(provider_client, inworld_api_key)
        .base_url(inworld_base_url)
        .build();
    let tts = InworldTts::new(
        client,
        !inworld_api_key.trim().is_empty(),
        InworldSpeech {
            model_id: "inworld-tts-2-flash",
            audio_encoding: "MP3",
            sample_rate_hertz: 24_000,
            bit_rate: 64_000,
            max_text_chars: 600,
        },
    )?;
    Ok((stt, tts))
}
# }
```

- **Muse** (`muse`): `wss://`, or `ws://` only to a numeric loopback
  address (`realtime_url`); the key travels in the first frame, so the app
  folds `LOG_CAPS` into its subscriber's caps (tungstenite dumps every
  frame below `INFO`). Revision 1's two rates and a 5 s lead. Muse bills
  per second of audio; the relay meters its own audio time. The open
  applies no deadline of its own; the relay's `open_timeout` is the one.
- **Inworld** (`inworld`): `InworldTts::new` refuses an encoding other
  than `MP3`, a client with the MP3 check off, and a client text bound
  under the speech's. Every `InworldError` is mapped by name (`Unavailable`
  → `503`; the rest `502`); a variant a later client crate adds is
  answered by its own `is_retryable()` and logged at ERROR. Inworld bills
  per character, which the budget counts first.
- **Mocks** (`test-support` with `axum`): `muse::mock::MockMuse` and
  `inworld::mock::MockInworld`, loopback servers an app's own route and
  log-cap tests can dial.

## Redis

### Keys

Every key is under a prefix the app passes, one per budget, with no
default (lumen: `lumen:voice:tts`, `lumen:voice:stream`; tapper:
`tapper:voice:tts`, `tapper:voice:stream`). `{user}` and `{token}` are
lowercase hyphenated uuids; `{key}` is the `Idempotency-Key` as sent (or a
minted uuid); `{day}` is `YYYY-MM-DD` and `{month}` `YYYY-MM` of the
budget clock's UTC instant, so a window rolls over by changing keys, never by
an expiry firing.

| Budget | Key after `{prefix}:` | Holds | Expiry |
|---|---|---|---|
| text | `user:{user}:{day}` | characters (a canonical integer) | the day's end + 1 h |
| text | `user-month:{user}:{month}` | characters | the month's end + 1 day |
| text | `global:{month}` | characters | the month's end + 1 day |
| text | `charge:{user}:{key}` | the verdict, `v1\|<mask>\|<fp>\|<reset>` | 600 s |
| stream | `lease:{user}` | the live session's token | 30 s (`LEASE_TTL`) |
| stream | `user:{user}:{day}` | audio ms | the day's end + 1 h |
| stream | `user-month:{user}:{month}` | audio ms | the month's end + 1 day |
| stream | `global:{month}` | audio ms | the month's end + 1 day |
| stream | `session:{token}` | the ms this session has been charged | 1 h |
| stream | `admit:{user}` | the last admitted token | the admission interval (at least 1 ms) |
| stream | `fence:{user}` | a hash; `next` is the last ticket | 1 day, refreshed at every issue and grant |

A canonical integer is `0`, or digits without a leading zero, at most 15 of
them; anything else in a counter is a poisoned counter: the call fails
(`Backend`) having written nothing.

### Scripts

Four scripts, each one `EVAL` carrying its own text. Each is byte-identical
to the extraction base, and its SHA-1 is a public constant an app may log or
assert; a unit test (`the_scripts_are_the_extraction_bases`) pins every one.

| Script | Constant | KEYS | Bytes | SHA-1 |
|---|---|---|---|---|
| the charge | `budget::CHARGE_SCRIPT_SHA1` | 4 | 2398 | `6db0a4afd52968ffb65e754d4dc48c7112016757` |
| the ticket | `lease::ISSUE_SCRIPT_SHA1` | 1 | 927 | `71b413abe08a2fe9288ecd807b0e8e8fad6cc6c0` |
| the acquire | `lease::ACQUIRE_SCRIPT_SHA1` | 6 | 2035 | `96f220b3004096553dc0fa570d43b306aa7e52d9` |
| the meter | `lease::METER_SCRIPT_SHA1` | 5 | 1926 | `b07b06c546464c457e44086bce1d96cbd5823ecb` |

Every script opens with the same Lua helpers (649 bytes, SHA-1
`882d901b042222ab1dfa60cad4981e1af84fd928`), so a counter and an argument
are validated by one rule each, and validates every counter and argument
before its first write. Each answer has one meaning: the spent-window mask
`1`–`7` (`1` the user's day, `2` everyone's month, `4` the user's month),
and the sentinels `-1` (a malformed counter, verdict, fence or argument;
nothing written), `-2` (the acquire: another token admitted inside the
admission interval), `-3` (the acquire: a stale ticket) and `-4` (the
charge: the key's stored verdict has another fingerprint).

A refusal reports ONE scope: of the spent windows, the one whose reset is
latest; a tie goes to `user_month`, then `global_month`, then `user_day`. A
replayed charge refusal keeps its original reset.

### The replay policy, per call

| Call | `Replay` | Why |
|---|---|---|
| `TtsBudget::charge` | `OnceOnFreshConnection` | a second run finds the stored verdict and writes nothing; residual: a first attempt delayed past 600 s charges again |
| `StreamBudget::issue_ticket` | `Never` | an increment is not idempotent; a lost reply is a `503`, and that ticket is never used |
| `StreamBudget::acquire` | `Never` | it IS the takeover: a second run could overwrite a session that took the lease in between, misreport `took_over`, and restart TTLs |
| `StreamBudget::meter` | `OnceOnFreshConnection` | cumulative totals: a second run charges nothing, and the lease is touched only under its own token; residual: a first attempt delayed past an hour charges again |

### Writes, ACLs and the fence's exception

Redis checks ACL permissions per command inside a script and does not roll a
script back. So every write is ONE `SET key value EX|PX ttl` (never an
`INCRBY` then an `EXPIRE`), after every check: a denied `SET` refuses before
anything changed. That is all the rule promises; it is not all-or-nothing
across commands, and these partial states are allowed:

- **The release's `DEL` comes last.** A denied `DEL` leaves the counters and
  the session meter charged and the lease to expire on its own (the state a
  failed release leaves anyway); the call is `Backend`, and a replay charges
  nothing and fails at the `DEL` again.
- **The fence is a hash**, which no one command both sets and expires. The
  ticket's script does `HINCRBY` then `EXPIRE`: a denied `EXPIRE` leaves
  `next` raised with its previous expiry (none, for a new hash) and the
  issue failed; no lease, counter or admission key is written, and a raised
  `next` only makes older tickets stale. The acquire's `EXPIRE` of the fence
  comes FIRST of its writes: denied, nothing is written; allowed, followed by
  a denied `SET`, only the fence's expiry was refreshed.

An ACL user scoped to an app's voice keys needs `EVAL` and, for the
scripts' own calls, `GET`, `SET`, `DEL`, `HGET`, `HINCRBY` and `EXPIRE` on
the two prefixes; besides those, whatever its connection sends on its own
(`PING`, for the stream's admission and a readiness probe).

## The consumer's obligations

- **The prefixes**, one per budget, with no default; two apps (or two
  environments) sharing a Redis must not share a prefix.
- **The caps**, from the app's settings: `TtsCaps::new` (characters) and
  `StreamCaps::from_minutes` (minutes, counted in ms). Each refuses with a
  `CapsError` listing every `CapProblem` (a cap not `1..=max`; a cap below
  the one it must allow at least), which the app maps to its startup
  refusals under its own setting names. The rule: each cap positive, and a
  user's day <= a user's month <= everyone's month.
- **The Redis handle**: the app's `stridelabs_redis::RedisHandle`, built
  with the bounds the replay arguments above assume — a 1 s dial and a
  500 ms response timeout (the handle's defaults). The crate cannot enforce
  them. A `rediss://` dial needs the consumer's rustls crypto provider
  (stridelabs-redis's README).
- **The PING before the ticket**: the stream's admission sends `PING` (which
  is retried on a fresh connection) before `issue_ticket` and `acquire`
  (which are never replayed), so a connection that died idle costs a redial,
  not a `503`.
- **Charge first, never refund**: the text budget is charged before the
  provider is asked, and a failed synthesis keeps its charge.
- **Usage**: count a charge only when its `Disposition` is `Fresh`.
- **Rendering**: a refusal's `scope`, `resets_at` (RFC 3339) and
  `retry_after_seconds` are the app's to put in its `429`, beside the
  `detail` its clients already parse; `Backend` details are fixed summaries,
  safe to log, never a key, a user id or Redis's own text.

## Named limits

- **A user's month that starts mid-month under-counts it**: on the deploy
  that first writes an app's user-month keys, every user's month starts at
  zero; everyone's month still bounds all.
- **Charging is per refresh**: a session can overshoot a window shared with
  other sessions by one refresh interval of audio; a crash before the first
  refresh leaves up to the pacing lead plus one interval uncharged; audio
  charged at the first refresh after a UTC boundary counts in the new
  window; a Redis outage mid-session charges late, or never if the final
  release fails too (only admission fails closed).
- **The fence's guarantee lasts the hash's life** (a day from the last issue
  or grant); a missing hash refuses every ticket, and numbering restarts.
- **One small fence hash per user may be left without an expiry** after a
  denied `EXPIRE`, until a later issue succeeds.
- **Formats and encodings**: a PCM-only core; a speech-to-text provider must
  take both 24 and 16 kHz; text to speech answers `audio/mpeg` only, in one
  body per sentence, with no context across sentences.
- **Pacing**: a provider that must be fed below real time plus the installed
  clients' 3 s pre-`ready` burst (Deepgram's 1.25×) is unsupported in
  revision 1 of the protocol; a protocol revision that lengthens the end
  grace (an advertised grace the clients honour) or drops the burst lifts it.
- **Providers**: one with no endpointing needs an adapter-side voice
  activity detector, or is unsupported; a request/response speech-to-text
  service's failed turn ends the session; a provider's billing unit can
  differ from the budgets' (characters sent; relay-measured audio).
- **Client timing**: revision 1 assumes a turn's final text within 1 s of
  the end of speech and within 2 s of the client's `end`, and a lead of at
  least 5 s (the installed clients' fixed timers); lifting any of them is a
  protocol revision.
- **A server shutdown discards late final transcripts** (the client keeps
  its last partial).
- **One-body text to speech, no context across sentences**: the trait
  returns one body per sentence; a provider's streaming and its request
  stitching or previous/next text have no place in `SynthesisRequest`, which
  carries the sentence and the voice only (no user, key or history reaches a
  provider).
- **A request/response speech-to-text adapter's obligations** (a service
  that transcribes one uploaded turn per call, such as OpenAI's file
  transcription): one call in flight per session, in turn order, each under
  a 15 s deadline; the open turn's buffer capped at 9 minutes of audio (a
  forced boundary); at most two closed turns waiting, a third makes
  `send_audio` fail with `overload`; `send_audio` never waits (append and
  voice activity detection); every event of turn n before any of turn n+1;
  `SpeechEnd` held and yielded immediately before the turn's `EndOfTurn`;
  `Finished` after the last response. The installed clients flush a segment
  1 s after `speech_end` and 10 s after `speech_start` without its
  `end_of_turn`, so a turn longer than about 10 s minus the call's latency
  still trips the 10 s timer (its late `end_of_turn` posts once).
- **Unconfirmed provider facts** (in the appendix's tables, marked
  UNCONFIRMED), each to be confirmed against a live account before an
  adapter is written: Deepgram's close code after `CloseStream`, its upgrade
  statuses and message cap; ElevenLabs' `Content-Type` per format and its
  counting rule for characters.

## Tests

Every test target and what it needs (`[[test]] required-features` in
`Cargo.toml`, so `cargo test --workspace` at default features builds exactly
the service-free ones):

| Target | Required features | Needs | Holds |
|---|---|---|---|
| `tests/golden.rs` | none | nothing | the golden fixture's bytes and SHA-256 |
| `tests/guards.rs` | none | nothing | the source scans (below) and their controls |
| `tests/voice_new.rs` | `test-support` | nothing | `Voice::new`'s refusals |
| `tests/budget.rs` | `live-tests` | Redis | the text budget's scripts, ACLs, idempotency |
| `tests/lease.rs` | `live-tests` | Redis | the lease, fence, meter, ACL cases |
| `tests/tts.rs` | `live-tests` | Redis | `Voice::speak` against `ScriptedTts` |
| `tests/relay.rs` | `live-tests` | Redis | the relay against `ScriptedStt`, over real sockets |
| `tests/stt_contract.rs` | `live-tests` | Redis | the contract's cases, the run cap |
| `tests/muse.rs` | `muse`, `axum`, `test-support` | loopback | `MuseStt` against `MockMuse` |
| `tests/muse_relay.rs` | `live-tests`, `muse` | Redis | one relay session through `MockMuse` |
| `tests/inworld.rs` | `inworld`, `axum`, `test-support` | loopback | `InworldTts` against `MockInworld` |
| `tests/inworld_speak.rs` | `live-tests`, `inworld` | Redis | `Voice::speak` through `InworldTts`: the charge that stands |

CI runs the suites per feature set as well as in the workspace's default and
all-features lanes: `--no-default-features --features axum,test-support,live-tests`
(the core's suites with no adapter compiled), `muse,axum,test-support` and
`inworld,axum,test-support` (each adapter's suites alone).

`cargo test -p stridelabs-voice` runs the unit tests (the windows, the
verdicts, the caps rule, the key shapes and the scripts' SHA-1s; the events'
wire forms; the refusal bodies, byte for byte; the request's parse, the
catalog, `RelaySettings::check`) and `tests/golden.rs` (the fixture's bytes
and hash), which need nothing. `--features test-support` adds the scripted
adapters' own tests and `tests/voice_new.rs` (`Voice::new`'s refusals),
which need nothing either.
`cargo test -p stridelabs-voice --features live-tests` (and the workspace's
`--all-features` lane) adds the real-Redis suites against the compose Redis
(`docker compose up -d redis`, `redis://localhost:6390/0`; `REDIS_URL`
overrides): every charge, ticket, acquire and meter answer, the
TTLs, the UTC boundaries, each call's replay policy through a fault relay,
and the ACL cases, each test under a prefix of its own
(`stridelabs-voice-test:<uuid>:tts` / `:stream`) and each ACL user
(`voice-test-<uuid>`) deleted when its test ends. Without a Redis they fail
loudly; they never skip.

`tests/tts.rs` (`live-tests`) drives `Voice::speak` through a minimal
route against `ScriptedTts`: every check and its order, the body bound, the
key, the charge and its usage record, the provider's answers, the
max-chars header on every response, the log line.

The adapters' suites: `tests/muse.rs` (`muse`, `axum`, `test-support`; no
Redis) drives `MuseStt` against `MockMuse` (the handshake, the open's
failures, Muse's raw frames, the close, the silent-frame bound, and the
injected connector against a `wss://` listener with a throwaway
certificate); `tests/inworld.rs` (`inworld`, `axum`, `test-support`; no
Redis) drives `InworldTts` against `MockInworld` (the setup's refusals, the
request on the wire, every failure's class, every bound);
`tests/muse_relay.rs` and `tests/inworld_speak.rs` (`live-tests` with the
adapter) run one relay session through Muse and `Voice::speak` through
Inworld, the charge included.

The relay's suites run whole sessions over real loopback sockets (the
stream served by axum, a tokio-tungstenite client) against `ScriptedStt`:
`tests/relay.rs` (every close code, the admission's refusals, the lease and
the budget as a session meets them, the fence at the upgrade, the failed
upgrade's release, how the client left, usage) and `tests/stt_contract.rs`
(the core's side of every rule in `stt`'s module docs, the provider-run cap
on a current-thread and a multi-thread runtime, each under an external
watchdog).

## Build guards

What keeps the core provider-neutral and the crate client-free is checked, not
promised:

- **The core names no provider** (`tests/guards.rs`, every lane): no source
  outside `muse.rs` and `inworld.rs` contains `muse`, `inworld` or `meta.ai`
  (any case, comments and strings included), and none uses tungstenite's
  `Message` (a `use` item that names `tungstenite` and `Message` on any
  number of lines, with comments or an alias, a `tungstenite` glob, or a
  path to it). The one exception to the names is `lib.rs`'s own lines that
  declare the two adapter modules and gate `LOG_CAPS` (and its test) on
  `any(axum, muse)`, each listed as a whole line with the number of times it
  must stand (a stale or duplicated entry fails too). The crate docs, which
  name the features, come from this README: the scan reads source files.
- **The crate builds no client of its own** (the same test, over all of
  `src/`), read as tokens, not lines (comments gone, whitespace and newlines
  collapsed), so an alias, a multi-line `use` list or an imported
  constructor is as visible as the plain call: no `ClientBuilder`,
  `ClientConfig`, `client_builder`, `connect_async` or
  `connect_async_with_config` identifier anywhere (an import, aliased or
  not, included), no `reqwest::Client` path or `use`, no `Client::new`,
  `Client::builder` or `Client::default`, no `InworldClient::builder`, no
  glob import of `reqwest` or `tokio_tungstenite`, and no `Connector`
  variant (`Plain`, `Rustls`) outside a module gated for tests (`mod`
  preceded by `#[cfg(test)]`, `feature = "test-support"` or an `any`/`all`
  of those, found by balanced braces; a module is never exempt by its
  name). That the Muse dial uses the connector it is handed is a behaviour
  test (`the_dial_uses_the_injected_connector`, `tests/muse.rs`).
- **No provider in the core build** (a CI step): `--no-default-features
  --features axum,test-support` compiles the crate with exactly those
  features, and neither `stridelabs-inworld` nor `reqwest` is compiled or in
  its graph.
- **No crypto provider selected** (a CI step): for the core, `axum`, `muse`,
  `inworld` and all of them with `openapi`, `cargo tree -e features,no-dev
  -i rustls` names no `aws_lc_rs`, `aws-lc-rs` or `ring` feature and the
  graph holds no `ring`, `aws-lc-rs` or `aws-lc-sys` package; the same query
  with dev edges (the tests' `wss://` fixture is on aws-lc-rs) does list
  `aws_lc_rs`, so the query is known to see provider features. The workspace's
  "compiles no ring" guard covers `--all-features`, dev edges included.

Each scan is a pure function over the source, with controls in the test file
that plant a violation in each form (a string, a comment, an identifier, the
allowed line in the wrong file) and watch it found.

## Appendix: a second provider, on paper

The core was checked against two providers it does not ship an adapter for,
from their public documentation alone (read 2026-10-25; no account, no request
to any provider), so that the traits and the protocol's constants do not
silently fit only Muse and Inworld. The speech-to-text side took **Deepgram**
live streaming (`wss://api.deepgram.com/v1/listen`) and, as the dissimilar
case, **OpenAI file transcription** (`POST /v1/audio/transcriptions`, model
`gpt-transcribe`, `stream=false`): no streaming input, no session, no endpointing
(the adapter's own voice activity detector makes every turn boundary, buffers
the turn's audio, wraps it as WAV and posts it once per turn) and final-only
text, so it tests that `partial` is optional, that `open`, `end_input` and
`close` assume no provider socket, and that a 15-minute session can span many
provider calls. (OpenAI's Realtime transcription and AWS Transcribe were
considered: the first stays adapter-endpointed but streams revisable deltas
and takes 24 kHz only, so it needs the adapter to resample to advertise both
rates; the second endpoints on the server and would not exercise the
endpointing contract.) Text to speech took **ElevenLabs**
(`POST /v1/text-to-speech/{voice_id}`, the one-body endpoint).

The dispositions: **maps** (the item holds as pinned), **adapter** (the
adapter's own concern), **CHANGE** (a trait or protocol change the walkthrough
made), **LIMIT** (a named limit above or here), **n/a**. A fact marked
UNCONFIRMED was not found in the documentation and is to be confirmed against
a live account before an adapter is written. Facts re-read against the pages
when this appendix was written: Deepgram's 1.25× real-time ceiling, OpenAI's
25 MB upload bound, its accepted formats (WAV, not raw PCM), `whisper-1`'s
deprecation (shutdown 2027-02-26) and that `gpt-transcribe` with `stream=true`
streams the transcript's output deltas only (the upload is still one file), and
ElevenLabs' MP3 `output_format` values (default `mp3_44100_128`) and request
fields.

### Speech to text: every server trait item and client constant

| # | Our item | Deepgram live | OpenAI file transcription | Disposition |
|---|---|---|---|---|
| 1 | `configured()` | key set (`Authorization: Token`) and the URL accepted | key set (`Authorization: Bearer`) and the base URL accepted | maps |
| 2 | `formats()`: PCM s16le mono | `encoding=linear16` with `sample_rate`; raw audio needs both | raw PCM is not accepted: the adapter prepends a 44-byte WAV header per turn | maps / adapter (the WAV wrap) |
| 3 | `formats()`: rates (revision 1: BOTH 24,000 and 16,000) | any real rate (no range documented, UNCONFIRMED beyond "set the real rate") | none documented (UNCONFIRMED); Realtime runner-up: 24 kHz only, so it needs resampling | maps; the runner-up only with adapter resampling |
| 4 | `pacing_lead()` and the provider's send rate | at most 1.25x real time; the lead is an allowance, not a rate limit, and the installed clients' 3 s pre-`ready` burst reaches the provider faster than that; a queue that paced it would complete writes on enqueue and could not drain inside the 2 s end grace | audio buffered locally, no provider pacing; 5,000 ms | **LIMIT: unsupported in revision 1** (a protocol revision that lengthens the end grace or drops the burst lifts it) |
| 5 | `open(format, deadline)` | dial the WebSocket with the query (`encoding`, `sample_rate`, `channels=1`, `model`, `interim_results`, `endpointing`, `utterance_end_ms`, `vad_events`, `smart_format`) through the app's connector; the open socket is "ready" | no dial: `open` spawns the session's poster task | maps |
| 6 | `OpenLabel::{Dial, Refused, OpenTimeout}` | a failed handshake is 4xx/5xx with a `dg-error` header: `401`/`402`/`403`/`429` are `Refused` with class `http <status>` (never the header or body); a connect error is `Dial`; the core's deadline is `OpenTimeout` | n/a at open (errors arrive per turn, row 13) | maps |
| 7 | `SpeechStart` | `SpeechStarted` (`vad_events`), or synthesised at a turn's first non-empty result | the adapter's VAD onset, held until the previous turn's `EndOfTurn` was yielded | maps / adapter |
| 8 | `Partial` (cumulative, optional) | interims replace the previous interim; finals are segments, not cumulative: cumulative = the turn's finals plus the latest interim | none (final-only) | maps; CHANGE: `partial` is explicitly optional |
| 9 | `SpeechEnd` | no such event: yielded at the turn's end | held: yielded immediately before the turn's `EndOfTurn`, so the client's 1 s flush timer starts once the text is there | maps / adapter |
| 10 | `EndOfTurn(text)` | at `speech_final`, at `UtteranceEnd` with text pending, or at the close after `CloseStream` with text pending; "do not use `speech_final` alone" is why finals are accumulated | the text of the turn's response | maps; CHANGE: the turn-order rule |
| 11 | `Ignored` | `Metadata`, the non-fatal `Error`, `ConfigureSuccess`, a duplicate final, an empty interim, an `UtteranceEnd` with nothing pending | n/a | maps |
| 12 | `Finished` | `CloseStream` flushes finals, then `Metadata`, then the close; the close code is UNCONFIRMED: a close after `CloseStream` is `Finished`, after any pending text's `EndOfTurn` | after `end_input`, the last turn's response has arrived and its events were yielded | maps / adapter |
| 13 | `Err(SttError)` | close `1008` is `data`, `1011` is `net`; a writer failure; transport errors by class | a turn's failure (`429`, `500`, `503` as `http <status>`), a call past its deadline (`timeout`), the backlog over its cap (`overload`): each ends the session (the core has no "skip a turn" event) | maps; LIMIT: a request/response provider's one failed turn ends the session (`error{provider}`, `1011`) and the client reconnects |
| 14 | `send_audio` | a binary frame, flushed (`SinkExt::send`) | append to the open turn's buffer and feed the VAD: never waits; over the backlog cap, `Err(overload)` | maps (Deepgram within row 4's limit) |
| 15 | `end_input` | `{"type":"CloseStream"}`, flushed | close the open turn and queue its call if it holds speech | maps |
| 16 | `close(end_sent)` | `CloseStream` unless sent, a normal close, read to the peer's close | drop the poster task (an in-flight call is abandoned) | maps |
| 17 | keepalive | not needed: the relay's idle rule (10 s) ends a session before Deepgram's no-audio timeout | none | maps |
| 18 | cancel-safety, interleaving, write completion | the stream half is read in `poll_next`; writes are flushed sends on the sink half | calls run in a session-owned task and `poll_next` reads results from a channel: dropping `next()` loses nothing, `send_audio` never waits on a read | maps |
| 19 | no starvation | events are bounded by audio sent | at most one response per turn | maps |
| 20 | fixed error classes | `dg-error`, `err_msg`, `description` are provider text: never carried | `error.message` is provider text: never carried | maps |
| 21 | billing unit (budget: relay-measured audio) | per second of processed audio (silence sent counts: implied, UNCONFIRMED), so close to the relay's measure | per minute of uploaded audio: only speech turns are uploaded, so the budget over-counts the bill | LIMIT: the budget is conservative for OpenAI (a cost note per adapter) |
| 22 | frames: even, up to 64 KiB | no maximum message size documented (UNCONFIRMED); a client frame is split into 100 ms chunks | n/a (buffered) | maps |
| 23 | endpointing | server-side (`endpointing`, `speech_final`, `UtteranceEnd`) | none: the adapter's VAD | maps; LIMIT: no endpointing and no adapter VAD is unsupported |
| 24 | turn order (every event of turn n before any of turn n+1) | `speech_final` precedes the next `SpeechStarted` | the adapter holds all of turn n+1's events until turn n's text is yielded | CHANGE: the turn-order rule |
| 25 | keywords / biasing | `keyterm` or `keywords`: adapter configuration from the app | `prompt` / `keywords` (some characters reject the request) | adapter |
| 26 | auth | `Authorization: Token` at the upgrade, through the app's connector | `Authorization: Bearer` on each call, through the app's `reqwest::Client` | adapter (no own client: both take the app's) |
| 27 | session length, request limits, queue bounds | no maximum documented (UNCONFIRMED) | each upload up to 25 MB (about 9 minutes at 24 kHz): a forced boundary before it; two turns waiting at most; a 15 s deadline | maps / LIMIT (the adapter's obligations, under Named limits) |
| 28 | concurrency | 150 streams on pay-as-you-go; over it, `429` at the upgrade (UNCONFIRMED where), so `Refused` | one call in flight per session; per-minute request limits are row 13 | maps |
| 29 | client: `rates` | `[24000, 16000]` | `[24000, 16000]` (Realtime runner-up: `[24000]`) | maps |
| 30 | client: `lead_ms` | 5,000 (a client lead of 4 s); the send rate is row 4's limit | 5,000 | maps (Deepgram: row 4) |
| 31 | client: `encoding` | `pcm_s16le` (other encodings unused) | `pcm_s16le`, wrapped as WAV by the adapter | maps; LIMIT: a PCM-only core (a compressed upload would extend `Encoding`, additively) |
| 32 | the end grace (`end_timeout`, the client's `endWait`) | the flush after `CloseStream` is prompt | the last turn's call after `end` can take longer than 2 s | LIMIT: `RelaySettings::check` caps `end_timeout` at 2 s because the installed clients' wait is a fixed 2 s; a provider whose final lags needs a protocol revision |
| 33 | the open latency against the client's `ready` wait | connect, TLS and the upgrade: well inside the default 8 s | instant | maps: `open_timeout + close_timeout` is at most 10 s, inside the installed clients' 12 s |
| 34 | the client's turn-assembly timers | finals arrive with `speech_final`, inside a second of the end of speech | the text arrives a call's latency after the VAD's end of speech | LIMIT: see "A request/response speech-to-text adapter's obligations" and "Client timing" under Named limits |

**Deepgram's turn logic**, pinned for the revision that lifts row 4. Every
result carries words with `start` and `end` (seconds of stream audio), and
turns are owned by time, never by "whatever text is pending". The adapter
keeps `finals` (the open turn's finalized words), `interim` (the latest
interim's words; each replaces it), `committed_until` (the audio time up to
which words belong to closed turns) and `in_speech`. An interim sets `interim`
to its words with `end > committed_until` and yields a cumulative `Partial`.
A final adds its words with `end > committed_until` and `end >` the last
final's end (a duplicate, or words already committed through an
`UtteranceEnd`, are dropped); with `speech_final`, the turn ends at the last
word's end. `UtteranceEnd{last_word_end: t}` ends the turn at `t` (ignored
for `-1` or when it owns nothing): the turn owns `finals` and the interim
words ending by `t`, and interim words after `t` are speech after the gap and
begin the next turn. A close after `CloseStream` ends a turn with pending text
before `Finished`. Ending a turn yields `SpeechEnd`, then `EndOfTurn`, and
starts the next turn if interim words remain. The adapter's required tests
are the five cases of that logic: `UtteranceEnd` committing only the words
before its gap ("what's the" then "weather" is two turns, "weather" in
exactly one), an `UtteranceEnd` ending a turn with no `speech_final`,
`speech_final` then `UtteranceEnd` being one turn, close-time finals ending
the turn before `Finished`, and committed words not being emitted again.

### Text to speech: every server trait item and client constant

| # | Our item | ElevenLabs | Disposition |
|---|---|---|---|
| 1 | `configured()` | `xi-api-key` set and the base URL accepted (regional hosts exist: the app's configuration) | maps |
| 2 | `media_type()` in the allowed set | `output_format`: default `mp3_44100_128`; MP3 variants `mp3_22050_32`, `mp3_24000_48`, `mp3_44100_32/64/96/128` (`192` needs a higher tier). The adapter asks for an MP3 format (such as `mp3_24000_48`, the closest to a 24 kHz, 64 kbit/s stream) and declares `audio/mpeg`; the response's own `Content-Type` per format is UNCONFIRMED, so it is not trusted and the MP3's shape is checked (as `stridelabs-inworld`'s `mp3_check`) | maps |
| 3 | other formats | `pcm_*`, `wav_*`, `opus_48000_*`, `ulaw_8000`, `alaw_8000` | LIMIT: revision 1's allowed set is `audio/mpeg`; another type is a protocol revision and client support first |
| 4 | `max_text_chars()` of at least 600 | per request: `eleven_flash_v2_5` 40,000, `eleven_multilingual_v2` 10,000, `eleven_v3` 5,000; the app chooses its own bound (lumen and tapper: 600) | maps; CHANGE: the body limit scales with the bound (`protocol::tts_body_limit`), so an app that raises it does not trip `413` on non-ASCII text |
| 5 | `knows_voice()` | voice ids are opaque and listed by a search endpoint; no startup call, so `None` (or `Some` against an app allowlist) | maps |
| 6 | `synthesize(SynthesisRequest { text, provider_voice })` | `POST .../{provider_voice}?output_format=...` with `text`, `model_id` and optional `voice_settings`, `language_code`; model and settings are adapter configuration | maps / adapter |
| 7 | `Audio { bytes, media_type }` | one body (the non-streaming endpoint) | maps |
| 8 | `TtsFailure::Unavailable` (`503`, `Retry-After: 5`) | `429` (`rate_limit_exceeded`, `concurrent_limit_exceeded`, `system_busy`), `503`, `500` (retryability not stated: treated as unavailable, as Inworld's `5xx`), a timeout or a broken connection | maps |
| 9 | `TtsFailure::Permanent` (`502`) | `400`, `401`, `402`, `403`, `404`, `422` (the reference documents a `detail` list, the errors page an object: the adapter reads neither into a log) | maps |
| 10 | one bounded synthesis | the adapter applies the app's bounds (time, response size, audio size) on the app's client | maps |
| 11 | streamed audio | a chunked `/stream` endpoint and WebSocket input streaming exist | LIMIT: one-body text to speech (the adapter uses the one-body endpoint, or collects `/stream` whole) |
| 12 | cross-sentence context | `previous_text`/`next_text`, `previous_request_ids` | LIMIT: `SynthesisRequest` carries the sentence and the voice only, by design |
| 13 | billing unit (budget: Unicode scalars of the trimmed text) | credits per character; whether spaces count and whether failed requests bill is UNCONFIRMED | LIMIT: the budget counts what is sent; the provider's count may differ slightly (a cost note) |
| 14 | idempotency | no idempotency key documented (UNCONFIRMED that none exists) | maps: the crate's key protects the budget, not provider spend (as for Inworld) |
| 15 | concurrency | per plan; over the limit, queued or `429` `concurrent_limit_exceeded` | maps (row 8) |
| 16 | client: allowed media types | `audio/mpeg` | maps |
| 17 | client: `TTS_MIN_TEXT_CHARS` and `X-Voice-Tts-Max-Chars` | at least 5,000 per model; the app advertises its own bound | maps |
| 18 | client: the voice catalog | app ids mapped to opaque ids in the app's configuration; stored settings unchanged by a swap | maps (the catalog rule exists for exactly this) |
| 19 | client: typed audio | `audio/mpeg` is `.mp3` | maps |

The speech-to-text client constants (`rates`, `lead_ms`, `encoding`, the end
grace) do not apply to a text-to-speech provider, and the text-to-speech
constants (allowed types, text minimum, voice catalog) do not apply to a
speech-to-text one.

### What the walkthrough changed

All additive: none touches a script, a key or an existing wire field.

1. `partial` is explicitly optional (`PROTOCOL.md`): OpenAI.
2. The turn-order rule, every event of turn n before any of turn n+1: OpenAI.
3. `MIN_PACING_LEAD` is 5 s (revision 1: the installed clients' burst and
   lead), the lead stated as an allowance, writes complete when flushed (never
   on enqueue), and the client trims its pre-`ready` buffer to its lead (a
   no-op at 5 s): Deepgram's 1.25x, which makes such a provider unsupported in
   revision 1.
4. `PROTOCOL_DEFAULT_RATES`: a provider must take BOTH 24 and 16 kHz (installed
   clients never read `ready.rates` and switch only after a microphone
   failure), with the client package's rate fallback (`PROTOCOL.md`).
5. `RelaySettings::end_timeout` is separate from `close_timeout`, and
   `RelaySettings::check` enforces revision 1's bounds: non-zero durations,
   `open_timeout + close_timeout` at most 10 s, `admit_interval` and
   `end_timeout` at most 2 s, `idle_timeout` at least 10 s, `pong_deadline`
   above `ping_interval`, and the lease's margin (`open_timeout +
   close_timeout + refresh_interval` below the lease, `3 x refresh_interval`
   within it): OpenAI's latency and the installed clients' timers.
6. `stt::MAX_SILENT_FRAMES_PER_POLL`: the adapters' absorption loops are
   bounded.
7. `protocol::tts_body_limit` scales with the text bound, with its basis stated
   in `PROTOCOL.md`: ElevenLabs' larger per-request limits.

The recorded limits are under Named limits above.

### Sources (read 2026-10-25, the load-bearing facts re-read when this appendix was written)

- Deepgram: `developers.deepgram.com/reference/speech-to-text-api/listen-streaming`
  and the pages on authenticating, endpointing and interim results, utterance
  end, start-of-speech detection, audio keep-alive, close stream, finalize,
  WebSocket errors, recovering from connection errors (the 1.25x ceiling),
  encoding, sample rate, keyterm and keywords, API rate limits, and pricing.
- OpenAI: `developers.openai.com/api/docs/guides/speech-to-text`, the
  transcription create reference, the error-codes, model (`gpt-transcribe`) and
  deprecations pages, and the realtime transcription guide.
- AWS Transcribe: the streaming partial-results page and
  `StartStreamTranscription`.
- ElevenLabs: the text-to-speech convert and stream references, the
  WebSocket guide, authentication, models, errors, voices search, pricing and
  request stitching.
