//! The Inworld adapter (features `inworld`, `axum`, `test-support`):
//! `InworldTts` driven directly, through the `TtsProvider` trait, against
//! `inworld::mock::MockInworld` on a loopback port. No Redis: the charge
//! that stands through each failure is `tests/inworld_speak.rs`'s.
//!
//! Ported from tapper's `tests/voice.rs` and `src/voice/tts.rs` (`82be95f`)
//! and lumen's `src/voice/inworld.rs` and `tests/voice_bounds.rs`
//! (`5b716ba`), at the adapter's own seam:
//!
//! - **the setup** — `InworldTts::new` refuses a non-MP3 encoding, a client
//!   with its MP3 check off, a client text bound under the speech's; a
//!   client that failed to build is unconfigured, as is an unset key; the
//!   app's client and bounds are kept as built; nothing prints the key;
//! - **the facts** — `audio/mpeg`, the speech's text bound, the eight
//!   voices known (`Some(true)`), any other `None`, and `Voice::new` takes
//!   them;
//! - **the request on the wire** — the app's model and audio, the mapped
//!   voice, `Authorization: Basic <key>`;
//! - **every failure's class** — each of Inworld's answers (`408`, `429`,
//!   `5xx`, `600`–`999`, `4xx`, a redirect not followed, every malformed
//!   `200`) as `Unavailable` (the route's `503`) or `Permanent` (its `502`),
//!   the class the client's own error text;
//! - **the bounds** — the app's, through the client it built: an endless
//!   body cut at the response bound, a stall after the headers and a drip
//!   both cut at the TOTAL timeout, a declared oversized body refused unread,
//!   audio two bytes over the bound refused before decoding, a truncated
//!   body retryable, a key or a text that cannot be sent never sent.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use stridelabs_inworld::{
    BuildError, InworldClient, InworldError, MalformedReason, UnavailableReason, SYNTHESIS_PATH,
};
use stridelabs_voice::budget::{TtsBudget, TtsCaps};
use stridelabs_voice::inworld::mock::{MockInworld, Reply, DRIP_DROPS, DRIP_EVERY};
use stridelabs_voice::inworld::{InworldSetupError, InworldSpeech, InworldTts, INWORLD_VOICES};
use stridelabs_voice::lease::{StreamBudget, StreamCaps};
use stridelabs_voice::testing::{ScriptedStt, SttScript, MP3_FIXTURE};
use stridelabs_voice::tts::{Audio, SynthesisRequest, TtsFailure, TtsProvider as _, VoiceCatalog};
use stridelabs_voice::usage::NoUsage;
use stridelabs_voice::{ErrorClass, RelaySettings, Voice, VoiceParts};

/// The key every configured test runs with. Not a secret.
const TEST_KEY: &str = "dGVzdC1pbndvcmxkLWtleQ==";

/// Nothing listens on port 1 (`tcpmux`).
const REFUSED: &str = "http://127.0.0.1:1";

/// Both apps' speech: the flash model, MP3 at 24 kHz and 64 kbit/s, 600
/// characters.
const SPEECH: InworldSpeech = InworldSpeech {
    model_id: "inworld-tts-2-flash",
    audio_encoding: "MP3",
    sample_rate_hertz: 24_000,
    bit_rate: 64_000,
    max_text_chars: 600,
};

/// Both apps' response and audio bounds: 4 MiB, 2 MiB.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_AUDIO_BYTES: usize = 2 * 1024 * 1024;

/// The HTTP client an app hands the client crate: no proxy, no redirect, no
/// retry, no body decoder (its injected-client contract). Plain `http://`
/// to the loopback mock needs no TLS.
fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
        .expect("a plain HTTP client")
}

/// The client an app builds: `key` at `base`, both apps' bounds with
/// `timeout`, the MP3 check on.
fn client(base: &str, key: &str, timeout: Duration) -> Result<InworldClient, BuildError> {
    InworldClient::builder(http(), key)
        .base_url(base)
        .timeout(timeout)
        .max_response_bytes(MAX_RESPONSE_BYTES)
        .max_audio_bytes(MAX_AUDIO_BYTES)
        .max_text_chars(600)
        .mp3_check(true)
        .build()
}

/// The provider over the mock: [`client`] with a 5 s timeout unless a test
/// shortens it, the key set.
fn provider(mock: &MockInworld, timeout: Duration) -> InworldTts {
    InworldTts::new(client(&mock.base_url(), TEST_KEY, timeout), true, SPEECH)
        .expect("both apps' parts pass")
}

/// `text` in `voice`, through the trait.
async fn speak(tts: &InworldTts, text: &str, voice: &str) -> Result<Audio, TtsFailure> {
    tts.synthesize(&SynthesisRequest::new(text, voice)).await
}

/// The route's `502`: `Permanent`, its class the error's text.
fn permanent(error: &InworldError) -> TtsFailure {
    TtsFailure::Permanent(ErrorClass::composed(error.to_string()))
}

/// Opens with an MPEG frame sync and is zero-padded to `len`.
fn audio(len: usize) -> Vec<u8> {
    let mut bytes = vec![0xff, 0xf3, 0x84, 0xc4];
    bytes.resize(len, 0);
    bytes
}

/// A failure's class, when it is `Unavailable`.
fn unavailable_class(outcome: &Result<Audio, TtsFailure>) -> String {
    match outcome {
        Err(TtsFailure::Unavailable(class)) => class.as_str().to_string(),
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

// ── The setup ────────────────────────────────────────────────────────────

/// `InworldTts::new` refuses what would break the provider's contract, in
/// order: an encoding other than `MP3` (exactly; whatever the client), then
/// for a BUILT client its MP3 check off, then its text bound under the
/// speech's. A client that failed to build is taken unchecked: it is the
/// configuration `503`. A client bound above the speech's is fine.
#[test]
fn inworld_tts_new_refuses_each_problem() {
    let built = || client("https://api.inworld.ai", TEST_KEY, Duration::from_secs(15));
    for encoding in ["mp3", "LINEAR16", "OGG_OPUS", ""] {
        let speech = InworldSpeech {
            audio_encoding: encoding,
            ..SPEECH
        };
        assert_eq!(
            InworldTts::new(built(), true, speech).err(),
            Some(InworldSetupError::UnsupportedEncoding),
            "{encoding:?}"
        );
        assert_eq!(
            InworldTts::new(Err(BuildError::ZeroTimeout), true, speech).err(),
            Some(InworldSetupError::UnsupportedEncoding),
            "{encoding:?}, no client"
        );
    }
    let unchecked = InworldClient::builder(http(), TEST_KEY)
        .mp3_check(false)
        .build();
    assert_eq!(
        InworldTts::new(unchecked, true, SPEECH).err(),
        Some(InworldSetupError::Mp3CheckOff)
    );
    let narrow = InworldClient::builder(http(), TEST_KEY)
        .max_text_chars(599)
        .build();
    assert_eq!(
        InworldTts::new(narrow, true, SPEECH).err(),
        Some(InworldSetupError::ClientTextBoundBelow {
            client: 599,
            speech: 600
        })
    );
    let wide = InworldClient::builder(http(), TEST_KEY)
        .max_text_chars(700)
        .build();
    assert!(InworldTts::new(wide, true, SPEECH).is_ok());
    assert!(InworldTts::new(built(), true, SPEECH).is_ok());
    let failed = InworldTts::new(Err(BuildError::InvalidBaseUrl("x")), true, SPEECH)
        .expect("a failed client is unconfigured, not refused");
    assert!(!failed.configured());
}

/// Configured takes a key the app says is set AND a client that was built;
/// the key alone, or the client alone, is the route's `503`.
#[test]
fn the_provider_is_configured_only_with_a_key_and_a_built_client() {
    let good = "https://api.inworld.ai";
    for (key_set, base, expected) in [
        (true, good, true),
        (false, good, false),
        (true, "http://localhost:9", false),
        (false, "http://localhost:9", false),
    ] {
        let tts = InworldTts::new(
            client(base, TEST_KEY, Duration::from_secs(15)),
            key_set,
            SPEECH,
        )
        .expect("the parts pass");
        assert_eq!(tts.configured(), expected, "{key_set} {base}");
        assert_eq!(tts.client().is_some(), expected, "{key_set} {base}");
    }
}

/// The client crate's endpoint, with a trailing slash on the base or not.
#[test]
fn the_endpoint_tolerates_a_trailing_slash_on_the_base() {
    for base in ["https://api.inworld.ai", "https://api.inworld.ai/"] {
        let tts = InworldTts::new(
            client(base, TEST_KEY, Duration::from_secs(15)),
            true,
            SPEECH,
        )
        .expect("the parts pass");
        assert_eq!(
            tts.client().expect("configured").endpoint().as_str(),
            "https://api.inworld.ai/tts/v1/voice",
            "{base}"
        );
    }
}

/// The app's client is kept as it built it: every bound it chose (none of
/// them the client crate's defaults) comes back, and the route's text bound
/// is the speech's.
#[test]
fn each_bound_is_the_callers() {
    let built = InworldClient::builder(http(), TEST_KEY)
        .base_url(REFUSED)
        .timeout(Duration::from_millis(1_234))
        .max_response_bytes(5_678)
        .max_audio_bytes(910)
        .max_text_chars(1_000)
        .build()
        .expect("a loopback IP literal");
    let bounds = built.bounds();
    let speech = InworldSpeech {
        max_text_chars: 800,
        ..SPEECH
    };
    let tts = InworldTts::new(Ok(built), true, speech).expect("the parts pass");
    assert_eq!(tts.client().map(InworldClient::bounds), Some(bounds));
    assert_eq!(bounds.timeout, Duration::from_millis(1_234));
    assert_eq!(
        (
            bounds.max_response_bytes,
            bounds.max_audio_bytes,
            bounds.max_text_chars
        ),
        (5_678, 910, 1_000)
    );
    assert_eq!(tts.max_text_chars(), 800);
    assert_eq!(tts.speech(), speech);
}

/// `Debug` names neither the key nor a refused URL's parts: whether a key
/// is set, the client's endpoint or the client crate's reason.
#[test]
fn debug_never_shows_the_key_or_a_refused_url() {
    for base in [
        "https://api.inworld.ai",
        "https://CANARY-user:CANARY-pass@api.inworld.ai/?key=CANARY#CANARY",
    ] {
        let tts = InworldTts::new(
            client(base, "CANARY-KEY", Duration::from_secs(15)),
            true,
            SPEECH,
        )
        .expect("the parts pass");
        let rendered = format!("{tts:?} {tts:#?}");
        assert!(!rendered.contains("CANARY"), "{rendered}");
        assert!(rendered.contains("api_key_configured: true"), "{rendered}");
    }
}

// ── The facts ────────────────────────────────────────────────────────────

/// The provider's facts, and `Voice::new` takes them: `audio/mpeg`, the
/// speech's bound, the eight voices known and any other id unknowable
/// (`None`, accepted: no startup call). Both apps' catalog passes, and so
/// does one mapping to a voice the adapter cannot vouch for.
#[tokio::test]
async fn the_provider_states_its_facts_and_voice_new_takes_them() {
    let mock = MockInworld::start().await;
    let tts = provider(&mock, Duration::from_secs(5));
    assert_eq!(tts.media_type(), "audio/mpeg");
    assert_eq!(tts.max_text_chars(), 600);
    for voice in INWORLD_VOICES {
        assert_eq!(tts.knows_voice(voice), Some(true), "{voice}");
    }
    for voice in ["jason", "Bob", "", " Jason"] {
        assert_eq!(tts.knows_voice(voice), None, "{voice:?}");
    }
    let voice = |tts: InworldTts, catalog: VoiceCatalog| {
        Voice::new(VoiceParts {
            stt: ScriptedStt::new(SttScript::default()),
            tts,
            catalog,
            tts_budget: TtsBudget::new(
                "test:tts",
                TtsCaps::new(20_000, 300_000, 300_000).expect("valid caps"),
            ),
            stream_budget: StreamBudget::new(
                "test:stream",
                StreamCaps::from_minutes(120, 1_800, 1_800).expect("valid caps"),
            ),
            relay: RelaySettings::default(),
            usage: std::sync::Arc::new(NoUsage),
        })
    };
    assert!(voice(
        provider(&mock, Duration::from_secs(5)),
        VoiceCatalog::identity(INWORLD_VOICES, "Jason").expect("the eight")
    )
    .is_ok());
    assert!(voice(
        tts,
        VoiceCatalog::new([("calm", "SomeOtherVoice")], "calm").expect("a mapped catalog")
    )
    .is_ok());
    assert!(mock.seen().is_empty(), "no startup call");
}

// ── The request on the wire ──────────────────────────────────────────────

/// One synthesis: `POST /tts/v1/voice` with `Authorization: Basic <key>`,
/// JSON, and exactly the app's speech (model, MP3, bit rate, sample rate;
/// no language, delivery mode or speaking rate) for the text and voice it
/// was given; the audio back byte for byte, as `audio/mpeg`.
#[tokio::test]
async fn a_sentence_is_spoken_with_the_apps_settings() {
    let mock = MockInworld::start().await;
    let mp3 = audio(9_000);
    mock.reply_with(Reply::Audio(mp3.clone()));
    let tts = provider(&mock, Duration::from_secs(5));
    let spoken = speak(&tts, "Hello there, Surly fan.", "Hazel")
        .await
        .expect("spoken");
    assert_eq!(spoken.bytes.as_ref(), mp3.as_slice());
    assert_eq!(spoken.media_type, "audio/mpeg");
    let seen = mock.seen();
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
    // The mock's default answer is the crate's own fixture.
    mock.reply_with(Reply::Audio(MP3_FIXTURE.to_vec()));
    let fixture = speak(&tts, "hi", "Jason").await.expect("spoken");
    assert_eq!(fixture.bytes.as_ref(), MP3_FIXTURE);
}

/// A key no header can carry is configured (the app said it is set) but
/// unusable: the `502`, and nothing is sent.
#[tokio::test]
async fn an_unusable_key_sends_nothing_and_is_a_502() {
    let mock = MockInworld::start().await;
    let tts = InworldTts::new(
        client(&mock.base_url(), "bad\u{1}key", Duration::from_secs(5)),
        true,
        SPEECH,
    )
    .expect("the parts pass");
    assert!(tts.configured());
    assert_eq!(
        speak(&tts, "hi", "Jason").await.err(),
        Some(permanent(&InworldError::UnusableKey))
    );
    assert!(mock.seen().is_empty());
}

/// Text over the client's bound is refused before anything is sent, a
/// `502` whose class names the counts, never the text. Characters, not
/// bytes: 600 four-byte characters are sent.
#[tokio::test]
async fn text_over_the_callers_bound_sends_nothing() {
    let mock = MockInworld::start().await;
    let tts = provider(&mock, Duration::from_secs(5));
    let over = format!("CANARY{}", "a".repeat(595));
    let refused = speak(&tts, &over, "Jason").await.err();
    assert_eq!(
        refused,
        Some(permanent(&InworldError::TextTooLong {
            chars: 601,
            max: 600
        }))
    );
    assert!(!format!("{refused:?}").contains("CANARY"), "{refused:?}");
    assert!(mock.seen().is_empty());
    let emoji = "😀".repeat(600);
    assert!(speak(&tts, &emoji, "Jason").await.is_ok());
    assert_eq!(mock.seen().len(), 1);
}

// ── Every failure's class ────────────────────────────────────────────────

/// Every way Inworld can fail, as the failure the route answers:
/// `408`/`429`/`5xx`/a status past `599` are `Unavailable` (its `503`); a
/// `4xx`, a redirect (answered, never followed) and every malformed `200`
/// (not JSON, no `audioContent`, not a string, not base64, empty, not MP3,
/// JSON over 4 MiB with or without a length, audio over 2 MiB) are
/// `Permanent` (its `502`); each class the client's own error text. The
/// caps are inclusive: exactly 4 MiB of JSON is read and spoken.
#[tokio::test]
async fn every_provider_failure_is_unavailable_or_permanent() {
    let mock = MockInworld::start().await;
    let tts = provider(&mock, Duration::from_secs(5));
    // Valid audio padded past 4 MiB by a field the client ignores, so the
    // response cap, and only it, refuses it.
    let padded_to = |length: usize| {
        let head = format!(
            r#"{{"audioContent":"{}","pad":""#,
            BASE64_STANDARD.encode(audio(2_000))
        );
        let pad = length - head.len() - r#""}"#.len();
        format!(r#"{head}{}"}}"#, "x".repeat(pad))
    };
    let at_cap = padded_to(MAX_RESPONSE_BYTES);
    assert_eq!(at_cap.len(), MAX_RESPONSE_BYTES);
    let oversized_json = padded_to(MAX_RESPONSE_BYTES + 1);
    let oversized_audio = format!(
        r#"{{"audioContent":"{}"}}"#,
        BASE64_STANDARD.encode(vec![0u8; MAX_AUDIO_BYTES + 1])
    );
    // `Unavailable` and `Rejected` are `#[non_exhaustive]`: built by the
    // client crate only, so their texts are matched instead (a status is
    // its reason, with no transport cause).
    let status = |status: u16| {
        TtsFailure::Unavailable(ErrorClass::composed(format!(
            "Inworld is unavailable: {}",
            UnavailableReason::Status(status)
        )))
    };
    let rejected = |status: u16| format!("Inworld rejected the request with HTTP {status}");
    let malformed = |reason| permanent(&InworldError::Malformed(reason));
    let cases: Vec<(&str, Reply, TtsFailure)> = vec![
        ("408", Reply::Body(408, "{}".into()), (status(408))),
        (
            "429",
            Reply::Body(429, r#"{"error":"slow down"}"#.into()),
            (status(429)),
        ),
        ("500", Reply::Body(500, "{}".into()), (status(500))),
        ("502", Reply::Body(502, "{}".into()), (status(502))),
        ("503", Reply::Body(503, "{}".into()), (status(503))),
        ("504", Reply::Body(504, "{}".into()), (status(504))),
        ("600", Reply::Body(600, "{}".into()), (status(600))),
        ("999", Reply::Body(999, "{}".into()), (status(999))),
        (
            "400",
            Reply::Body(400, r#"{"error":"bad voice"}"#.into()),
            TtsFailure::Permanent(ErrorClass::composed(rejected(400))),
        ),
        (
            "401",
            Reply::Body(401, "{}".into()),
            TtsFailure::Permanent(ErrorClass::composed(rejected(401))),
        ),
        (
            "403",
            Reply::Body(403, "{}".into()),
            TtsFailure::Permanent(ErrorClass::composed(rejected(403))),
        ),
        (
            "404",
            Reply::Body(404, "{}".into()),
            TtsFailure::Permanent(ErrorClass::composed(rejected(404))),
        ),
        (
            "422",
            Reply::Body(422, "{}".into()),
            TtsFailure::Permanent(ErrorClass::composed(rejected(422))),
        ),
        (
            "a redirect",
            Reply::Redirect,
            TtsFailure::Permanent(ErrorClass::composed(rejected(302))),
        ),
        (
            "200, not JSON",
            Reply::Body(200, "<html>".into()),
            malformed(MalformedReason::NotJsonObject),
        ),
        (
            "200, no audioContent",
            Reply::Body(200, "{}".into()),
            malformed(MalformedReason::NoAudioContent),
        ),
        (
            "200, audioContent not a string",
            Reply::Body(200, r#"{"audioContent":5}"#.into()),
            malformed(MalformedReason::NoAudioContent),
        ),
        (
            "200, audioContent not base64",
            Reply::Body(200, r#"{"audioContent":"%%%"}"#.into()),
            malformed(MalformedReason::NotBase64),
        ),
        (
            "200, empty audio",
            Reply::Body(200, r#"{"audioContent":""}"#.into()),
            malformed(MalformedReason::EmptyAudio),
        ),
        (
            "200, audio that is not MP3",
            Reply::Body(200, r#"{"audioContent":"bm90IG1wMw=="}"#.into()),
            malformed(MalformedReason::NotMp3),
        ),
        (
            "200, JSON over 4 MiB",
            Reply::Body(200, oversized_json.clone()),
            malformed(MalformedReason::BodyTooLarge),
        ),
        (
            "200, JSON over 4 MiB, chunked",
            Reply::Chunked(oversized_json),
            malformed(MalformedReason::BodyTooLarge),
        ),
        (
            "200, audio over 2 MiB",
            Reply::Body(200, oversized_audio),
            malformed(MalformedReason::AudioTooLarge),
        ),
    ];
    let count = cases.len();
    for (label, reply, expected) in cases {
        mock.reply_with(reply);
        let outcome = speak(&tts, "hi", "Jason").await;
        assert_eq!(outcome.err(), Some(expected), "{label}");
    }
    for reply in [Reply::Body(200, at_cap.clone()), Reply::Chunked(at_cap)] {
        mock.reply_with(reply);
        let spoken = speak(&tts, "hi", "Jason")
            .await
            .expect("the 4 MiB cap is inclusive");
        assert_eq!(spoken.bytes.as_ref(), audio(2_000).as_slice());
    }
    // One request per case: the redirect was answered, not followed.
    let seen = mock.seen();
    assert_eq!(seen.len(), count + 2, "{seen:?}");
    assert!(
        seen.iter().all(|seen| seen.path == SYNTHESIS_PATH),
        "{seen:?}"
    );
}

/// A provider that hangs is `Unavailable` at the client's deadline (the
/// apps' is 15 s; this client's 300 ms), and so is one nothing listens on.
#[tokio::test]
async fn a_hung_or_unreachable_provider_is_a_retryable_503() {
    let mock = MockInworld::start().await;
    mock.reply_with(Reply::Hang(Duration::from_secs(5)));
    let hung = provider(&mock, Duration::from_millis(300));
    let started = Instant::now();
    let outcome = speak(&hung, "hi", "Jason").await;
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert!(
        unavailable_class(&outcome).starts_with("Inworld is unavailable: the exchange timed out"),
        "{outcome:?}"
    );

    let unreachable = InworldTts::new(
        client(REFUSED, TEST_KEY, Duration::from_secs(5)),
        true,
        SPEECH,
    )
    .expect("the parts pass");
    let outcome = speak(&unreachable, "hi", "Jason").await;
    assert!(
        unavailable_class(&outcome).starts_with("Inworld is unavailable: the connection could not"),
        "{outcome:?}"
    );
}

// ── The bounds ───────────────────────────────────────────────────────────
//
// The apps' bounds (4 MiB of response, 2 MiB of audio), the timeout
// shortened on the client the test builds, never by waiting fifteen
// seconds. The failure's CLASS, not the wall time, tells a size refusal
// (`Permanent`) from a timeout (`Unavailable`).

/// A body with no `Content-Length` that never ends (about 32 MiB a second)
/// is CUT at the 4 MiB response bound, not buffered whole: `Permanent`,
/// `Malformed(BodyTooLarge)`, and the connection hung up (the mock's stream
/// is dropped). A client that read the body whole first could only run into
/// its 3 s timeout here, `Unavailable`.
#[tokio::test]
async fn an_endless_body_is_cut_at_the_response_bound_before_the_timeout() {
    let mock = MockInworld::start().await;
    mock.reply_with(Reply::Endless);
    let tts = provider(&mock, Duration::from_secs(3));
    assert_eq!(
        speak(&tts, "hi", "Jason").await.err(),
        Some(permanent(&InworldError::Malformed(
            MalformedReason::BodyTooLarge
        )))
    );
    mock.endless_was_dropped().await;
}

/// A `200` whose headers and first body bytes arrive and whose body then
/// does not is `Unavailable`, timed out, AT the timeout: the bound covers the
/// body, not just the headers. After the 500 ms bound and well before 2 s
/// past it.
#[tokio::test]
async fn a_body_that_stalls_after_its_headers_is_a_503_at_the_timeout() {
    let mock = MockInworld::start().await;
    mock.reply_with(Reply::StallAfterHeaders);
    let timeout = Duration::from_millis(500);
    let tts = provider(&mock, timeout);
    let started = Instant::now();
    let outcome = speak(&tts, "hi", "Jason").await;
    let elapsed = started.elapsed();
    assert!(
        unavailable_class(&outcome).starts_with("Inworld is unavailable: the exchange timed out"),
        "{outcome:?}"
    );
    assert!(
        elapsed >= timeout && elapsed < timeout + Duration::from_secs(2),
        "{elapsed:?}: not at the 500 ms bound"
    );
}

/// A body that DRIPS (a byte every 100 ms for 4 s, so never 500 ms without
/// one) is still `Unavailable`, timed out, at the 500 ms bound: the bound
/// is the whole exchange's TOTAL deadline, not a timer each read resets.
/// One that each byte reset would run to the drip's end and answer its
/// unterminated body's `Permanent` instead.
#[tokio::test]
async fn a_body_that_drips_is_cut_at_the_total_timeout_not_reset_per_read() {
    let mock = MockInworld::start().await;
    mock.reply_with(Reply::Drip);
    let timeout = Duration::from_millis(500);
    assert!(DRIP_EVERY < timeout, "the premise: no read waits the bound");
    assert!(
        DRIP_EVERY * DRIP_DROPS > timeout + Duration::from_secs(2),
        "the premise: the drip outlasts the upper bound below"
    );
    let tts = provider(&mock, timeout);
    let started = Instant::now();
    let outcome = speak(&tts, "hi", "Jason").await;
    let elapsed = started.elapsed();
    assert!(
        unavailable_class(&outcome).starts_with("Inworld is unavailable: the exchange timed out"),
        "{outcome:?}"
    );
    assert!(
        elapsed >= timeout && elapsed < timeout + Duration::from_secs(2),
        "{elapsed:?}: not at the 500 ms total deadline"
    );
}

/// A `Content-Length` one byte past the 4 MiB response bound is refused
/// UNREAD: the mock declares it and never sends a body byte, so only a
/// client that believes the declaration answers `Permanent`,
/// `Malformed(BodyTooLarge)`. One that read first would wait out its 5 s
/// timeout, `Unavailable`.
#[tokio::test]
async fn a_declared_oversized_body_is_refused_unread() {
    let mock = MockInworld::start().await;
    mock.reply_with(Reply::DeclaredOversized);
    let tts = provider(&mock, Duration::from_secs(5));
    let started = Instant::now();
    assert_eq!(
        speak(&tts, "hi", "Jason").await.err(),
        Some(permanent(&InworldError::Malformed(
            MalformedReason::BodyTooLarge
        )))
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
}

/// Audio two bytes past the 2 MiB audio bound (its body well under 4 MiB)
/// is refused BEFORE decoding, `Malformed(AudioContentTooLong)`: its base64
/// is longer than any audio within the bound encodes to. The control: ONE
/// byte past the bound encodes to exactly the bound's base64 length (2 MiB
/// is 2 mod 3), so only the post-decode check, `Malformed(AudioTooLarge)`,
/// refuses that.
#[tokio::test]
async fn audio_two_bytes_over_the_bound_is_refused_before_decoding() {
    let mock = MockInworld::start().await;
    let tts = provider(&mock, Duration::from_secs(5));
    mock.reply_with(Reply::Audio(audio(MAX_AUDIO_BYTES + 2)));
    assert_eq!(
        speak(&tts, "hi", "Jason").await.err(),
        Some(permanent(&InworldError::Malformed(
            MalformedReason::AudioContentTooLong
        )))
    );
    mock.reply_with(Reply::Audio(audio(MAX_AUDIO_BYTES + 1)));
    assert_eq!(
        speak(&tts, "hi", "Jason").await.err(),
        Some(permanent(&InworldError::Malformed(
            MalformedReason::AudioTooLarge
        )))
    );
}

/// A body that breaks off halfway through its declared length is the
/// transport failing, `Unavailable` (the route's retryable `503`), not a
/// malformed answer (lumen's `voice_bounds` case, which tapper's set
/// lacked).
#[tokio::test]
async fn a_truncated_body_is_a_retryable_503() {
    let mock = MockInworld::start().await;
    mock.reply_with(Reply::Truncated);
    let tts = provider(&mock, Duration::from_secs(5));
    let outcome = speak(&tts, "hi", "Jason").await;
    assert!(
        unavailable_class(&outcome)
            .starts_with("Inworld is unavailable: the exchange failed or the connection broke"),
        "{outcome:?}"
    );
    assert_eq!(mock.seen().len(), 1);
}
