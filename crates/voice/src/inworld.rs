//! Inworld text to speech, as a [`TtsProvider`] (feature `inworld`):
//! [`InworldTts`] speaks one sentence through stridelabs-inworld's
//! [`InworldClient`], which the APP built (on its own `reqwest::Client`,
//! with its own bounds) and hands in. Ported from lumen
//! (`lumen-rs/src/voice/inworld.rs`, `5b716ba`) and tapper's wiring
//! (`tapper-rs/src/voice/tts.rs`, `82be95f`).
//!
//! One non-streaming synthesis per sentence, as the client puts it on the
//! wire:
//!
//! ```text
//! POST {base}/tts/v1/voice
//! Authorization: Basic <key>
//! {"text":…,"voiceId":…,"modelId":…,
//!  "audioConfig":{"audioEncoding":"MP3","bitRate":…,"sampleRateHertz":…}}
//!   -> 200 {"audioContent":"<base64 MP3>","usage":{…}}
//! ```
//!
//! # What the app hands in
//!
//! - **The client** ([`InworldClient`], or the `BuildError` its configured
//!   base URL got): its HTTP client (no proxy, no redirect, no retry, no
//!   body decoder: the client crate's injected-client contract) and its
//!   bounds (the whole exchange's timeout, the response and audio bounds, the
//!   text bound). This module builds no client. A client that failed to
//!   build is the configuration `503`.
//! - **Whether the key is set**: the client crate has no "not configured"
//!   (an empty key is its `UnusableKey`, on every synthesis), so the app says
//!   it, and an unset key is the configuration `503`.
//! - **The speech** ([`InworldSpeech`]): the model, the encoding, the sample
//!   rate, the bit rate and the text bound. No defaults: both apps pass
//!   `inworld-tts-2-flash`, `MP3`, 24 kHz, 64 kbit/s and 600 characters.
//!
//! [`InworldTts::new`] refuses what would break the provider's contract:
//! an encoding other than `MP3` (revision 1's one media type is
//! `audio/mpeg`), a client with its MP3 shape check off (the adapter declares
//! `audio/mpeg` and must not take that on trust), and a client whose own
//! text bound is under the speech's (a sentence between the two would be a
//! `502` instead of the route's `422`).
//!
//! # The voices
//!
//! The catalog maps the app's ids to Inworld's `voiceId`s; [`INWORLD_VOICES`]
//! are the eight both apps verified in their accounts, which
//! [`TtsProvider::knows_voice`] answers `Some(true)` for. Any other id is
//! `None` (cannot tell without asking Inworld): accepted, and no startup
//! call is made.
//!
//! # What a failure becomes ([`failure`])
//!
//! | Inworld | `InworldError` | [`TtsFailure`] | wire |
//! |---|---|---|---|
//! | `408`, `429`, any status of `500` or more (`600`–`999` included), a timeout (a stall before or after the headers), a connection that failed or broke (a truncated body) | `Unavailable` | `Unavailable` | `503` + `Retry-After: 5` |
//! | any other non-`2xx` (a `4xx`, a `3xx` not followed) | `Rejected` | `Permanent` | `502` |
//! | a `2xx` that is not usable audio (not a JSON object, no string `audioContent`, not base64, empty, over the response or the audio bound, not MP3-shaped) | `Malformed` | `Permanent` | `502` |
//! | a key no header can carry; nothing is sent | `UnusableKey` | `Permanent` | `502` |
//! | text over the client's bound; nothing is sent (unreachable through the route, whose `422` comes first) | `TextTooLong` | `Permanent` | `502` |
//! | a NaN or infinite speaking rate; nothing is sent (unreachable: no speaking rate is sent) | `SpeakingRateNotFinite` | `Permanent` | `502` |
//! | a variant a later client crate adds (`InworldError` is `#[non_exhaustive]`) | its own `is_retryable()` decides, logged at ERROR | either | `503` or `502` |
//!
//! The class ([`crate::ErrorClass`]) is the `InworldError`'s `Display`,
//! which the client crate guarantees is fixed phrases, a status code, a
//! count or an I/O error kind: never the text, the key, a body or a URL.
//!
//! **Billing:** Inworld bills per character it processed, which the route's
//! budget counts (the trimmed text's characters) before the call.

use std::future::Future;

use stridelabs_inworld::{AudioConfig, BuildError, InworldClient, InworldError};

use crate::tts::{Audio, SynthesisRequest, TtsFailure, TtsProvider};
use crate::ErrorClass;

/// The eight voices both apps verified in their Inworld accounts: their
/// names ARE Inworld `voiceId`s.
pub const INWORLD_VOICES: [&str; 8] = [
    "Jason", "Hazel", "Casey", "Nadia", "Brian", "Imogen", "Liam", "Evan",
];

/// The one encoding revision 1 takes: MP3, answered as `audio/mpeg`.
const MP3: &str = "MP3";

/// `MP3`'s media type.
const AUDIO_MPEG: &str = "audio/mpeg";

/// How every sentence is spoken: the app's choices, with no defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InworldSpeech {
    /// The model every synthesis names (both apps: `inworld-tts-2-flash`).
    pub model_id: &'static str,
    /// The audio encoding: `MP3`, the only one revision 1 takes.
    pub audio_encoding: &'static str,
    /// The audio's sample rate (both apps: 24,000).
    pub sample_rate_hertz: u32,
    /// The audio's bit rate (both apps: 64,000).
    pub bit_rate: u32,
    /// The longest text one sentence carries, in characters: the route's
    /// bound (both apps: 600); at most the client's own.
    pub max_text_chars: usize,
}

/// Why [`InworldTts::new`] refused its parts.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum InworldSetupError {
    /// An encoding other than `MP3`: revision 1 answers `audio/mpeg` only.
    #[error("the Inworld audio encoding is not MP3, the only one the voice protocol takes")]
    UnsupportedEncoding,
    /// The client's MP3 shape check is off: the adapter declares
    /// `audio/mpeg`, and must not take it on trust.
    #[error("the Inworld client's MP3 check is off")]
    Mp3CheckOff,
    /// The client's own text bound is under the speech's: a sentence between
    /// the two would be refused by the client after it was charged.
    #[error(
        "the Inworld client's text bound ({client} characters) is under the speech's ({speech})"
    )]
    ClientTextBoundBelow {
        /// The client's bound.
        client: usize,
        /// The speech's bound.
        speech: usize,
    },
}

/// The Inworld provider: the app's client (or why it has none), whether the
/// key is set, and the speech.
pub struct InworldTts {
    api_key_configured: bool,
    client: Result<InworldClient, BuildError>,
    speech: InworldSpeech,
}

/// The key never prints: the client's own `Debug` shows its validated
/// endpoint, whether the key is usable, the bounds and the MP3 check; a
/// refused base URL shows the client crate's reason, never the URL.
impl std::fmt::Debug for InworldTts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("InworldTts");
        debug.field("api_key_configured", &self.api_key_configured);
        match &self.client {
            Ok(client) => debug.field("client", client),
            Err(refused) => debug.field("base_url_refused", refused),
        };
        debug.field("speech", &self.speech);
        debug.finish()
    }
}

impl InworldTts {
    /// The provider over the app's `client` (or the `BuildError` its base
    /// URL got: the configuration `503`, unchecked), with
    /// `api_key_configured` (the app's key is set, not blank) and `speech`.
    ///
    /// # Errors
    ///
    /// [`InworldSetupError`]: an encoding other than `MP3`; then, for a
    /// built client, its MP3 check off or its text bound under the speech's.
    pub fn new(
        client: Result<InworldClient, BuildError>,
        api_key_configured: bool,
        speech: InworldSpeech,
    ) -> Result<InworldTts, InworldSetupError> {
        if speech.audio_encoding != MP3 {
            return Err(InworldSetupError::UnsupportedEncoding);
        }
        if let Ok(built) = &client {
            if !built.checks_mp3() {
                return Err(InworldSetupError::Mp3CheckOff);
            }
            let bound = built.bounds().max_text_chars;
            if bound < speech.max_text_chars {
                return Err(InworldSetupError::ClientTextBoundBelow {
                    client: bound,
                    speech: speech.max_text_chars,
                });
            }
        }
        Ok(InworldTts {
            api_key_configured,
            client,
            speech,
        })
    }

    /// The client to speak through, when the route can speak at all: the
    /// key is set and the client was built.
    #[must_use]
    pub fn client(&self) -> Option<&InworldClient> {
        self.client
            .as_ref()
            .ok()
            .filter(|_| self.api_key_configured)
    }

    /// How every sentence is spoken.
    #[must_use]
    pub fn speech(&self) -> InworldSpeech {
        self.speech
    }
}

impl TtsProvider for InworldTts {
    fn configured(&self) -> bool {
        self.client().is_some()
    }

    fn media_type(&self) -> &'static str {
        AUDIO_MPEG
    }

    fn max_text_chars(&self) -> usize {
        self.speech.max_text_chars
    }

    fn knows_voice(&self, provider_voice: &str) -> Option<bool> {
        INWORLD_VOICES.contains(&provider_voice).then_some(true)
    }

    /// One synthesis of the request's text in its voice, with the speech's
    /// model and audio; no language, delivery mode or speaking rate (each is
    /// omitted, so Inworld's defaults apply).
    fn synthesize(
        &self,
        request: &SynthesisRequest<'_>,
    ) -> impl Future<Output = Result<Audio, TtsFailure>> + Send {
        let client = self.client().cloned();
        let speech = self.speech;
        let (text, voice) = (request.text.to_string(), request.provider_voice.to_string());
        async move {
            // Unreachable through the route, which answers an unconfigured
            // provider's 503 before it charges: a permanent failure of a
            // fixed class rather than a panic.
            let Some(client) = client else {
                return Err(TtsFailure::Permanent(ErrorClass::fixed("not configured")));
            };
            let synthesis = stridelabs_inworld::SynthesisRequest::new(
                &text,
                &voice,
                speech.model_id,
                AudioConfig::new(speech.audio_encoding)
                    .with_bit_rate(speech.bit_rate)
                    .with_sample_rate_hertz(speech.sample_rate_hertz),
            );
            match client.synthesize(&synthesis).await {
                Ok(synthesis) => Ok(Audio {
                    bytes: synthesis.audio,
                    media_type: AUDIO_MPEG,
                }),
                Err(error) => Err(failure(&error)),
            }
        }
    }
}

/// What a failed synthesis is (the module docs' table): every variant this
/// build knows, by name; one a later client crate adds by its own
/// `is_retryable()`, logged at ERROR.
#[must_use]
pub fn failure(error: &InworldError) -> TtsFailure {
    let class = ErrorClass::composed(error.to_string());
    match error {
        InworldError::Unavailable { .. } => TtsFailure::Unavailable(class),
        InworldError::Rejected { .. }
        | InworldError::Malformed(_)
        | InworldError::UnusableKey
        | InworldError::TextTooLong { .. }
        | InworldError::SpeakingRateNotFinite => TtsFailure::Permanent(class),
        // `InworldError` is `#[non_exhaustive]`, so a variant a later client
        // crate adds lands here until it is named above. Deliberately not a
        // guess (lumen's policy over tapper's silent 502): the crate's own
        // `is_retryable()` decides (a new kind of "unavailable" stays a 503
        // the client retries, anything else a 502), and ERROR says a crate
        // bump reached an arm this build never does.
        unclassified => {
            let retryable = unclassified.is_retryable();
            tracing::error!(
                error = %unclassified,
                retryable,
                "voice tts: an Inworld error this build does not classify; answered by its \
                 retryability"
            );
            if retryable {
                TtsFailure::Unavailable(class)
            } else {
                TtsFailure::Permanent(class)
            }
        }
    }
}

/// A strict HTTP server standing in for Inworld (feature `test-support`,
/// with `axum`): tapper's in-test mock (`tapper-rs/tests/voice.rs`,
/// `82be95f`) plus lumen's truncated answer, exported for an app's own
/// route tests. It records every request and answers what the test says;
/// by default a valid MP3 (`testing::MP3_FIXTURE`). It serves plain `http://`
/// on `127.0.0.1` only, which the client crate accepts as a base URL.
#[cfg(all(feature = "test-support", feature = "axum"))]
pub mod mock {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::time::Duration;

    use axum::body::{Body, Bytes};
    use axum::extract::{Request, State};
    use axum::http::header;
    use axum::response::Response;
    use axum::Router;
    use futures_util::StreamExt as _;

    /// How often [`Reply::Drip`] sends a byte.
    pub const DRIP_EVERY: Duration = Duration::from_millis(100);

    /// How many bytes [`Reply::Drip`] sends before its body ends: 4 s of
    /// them.
    pub const DRIP_DROPS: u32 = 40;

    /// How long [`Reply::Truncated`] waits after the half before it breaks
    /// the body: long enough for the server to have written the headers and
    /// the half (an error straight after them can drop them unsent, an empty
    /// reply rather than a truncated one).
    pub const TRUNCATION_PAUSE: Duration = Duration::from_millis(100);

    /// One chunk of [`Reply::Endless`]: 64 KiB of base64-looking text.
    static ENDLESS_CHUNK: [u8; 64 * 1024] = [b'A'; 64 * 1024];

    /// What the mock answers the next synthesis with.
    #[derive(Debug, Clone)]
    pub enum Reply {
        /// `200 {"audioContent": <base64 of these bytes>, "usage": …}`.
        Audio(Vec<u8>),
        /// This status and this body, `application/json`, with a length.
        Body(u16, String),
        /// `200` with this body sent CHUNKED (no `Content-Length`), in
        /// 64 KiB pieces.
        Chunked(String),
        /// `302` to `/followed` on the mock itself: a client that follows
        /// shows up as a second request.
        Redirect,
        /// Sleep this long, then the default audio.
        Hang(Duration),
        /// `200`, chunked, and it never ends: the opening of an
        /// `audioContent` string, then 64 KiB more every 2 ms (about
        /// 32 MiB a second) for as long as the client reads.
        /// [`MockInworld::endless_was_dropped`] sees the server drop it once
        /// the client hung up.
        Endless,
        /// `200`, its headers and the first bytes of a chunked body, then
        /// nothing: the body never ends and the connection stays open.
        StallAfterHeaders,
        /// `200` declaring a `Content-Length` one byte past the client
        /// crate's default response bound (4 MiB, both apps' bound), then no
        /// body byte at all.
        DeclaredOversized,
        /// `200`, chunked, and it DRIPS: the opening of an `audioContent`
        /// string, then one more byte every [`DRIP_EVERY`] for
        /// [`DRIP_DROPS`] drops (4 s), then the body ends, unterminated (not
        /// JSON). Never [`DRIP_EVERY`] without a byte: a timer each read
        /// resets never fires.
        Drip,
        /// `200` with the default audio's whole `Content-Length` declared,
        /// the first half of the body, then (after [`TRUNCATION_PAUSE`]) a
        /// broken body: the connection drops mid-body.
        Truncated,
    }

    /// One request the mock saw.
    #[derive(Clone, Debug)]
    pub struct Seen {
        /// The method.
        pub method: String,
        /// The path.
        pub path: String,
        /// The `Authorization` header, as sent.
        pub authorization: Option<String>,
        /// The `Content-Type` header, as sent.
        pub content_type: Option<String>,
        /// The body, as text.
        pub body: String,
    }

    struct MockState {
        reply: Mutex<Reply>,
        seen: Mutex<Vec<Seen>>,
        /// The last [`Reply::Endless`] stream was dropped.
        endless_dropped: Arc<AtomicBool>,
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The mock (module docs).
    pub struct MockInworld {
        addr: SocketAddr,
        state: Arc<MockState>,
    }

    impl MockInworld {
        /// A mock on a fresh `127.0.0.1` port, served for the rest of the
        /// test (a task on the caller's runtime), answering
        /// [`Reply::Audio`] of `testing::MP3_FIXTURE`.
        ///
        /// # Panics
        ///
        /// When no loopback port can be bound.
        pub async fn start() -> MockInworld {
            let state = Arc::new(MockState {
                reply: Mutex::new(Reply::Audio(crate::testing::MP3_FIXTURE.to_vec())),
                seen: Mutex::new(Vec::new()),
                endless_dropped: Arc::new(AtomicBool::new(false)),
            });
            let router = Router::new()
                .fallback(handle)
                .with_state(Arc::clone(&state));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind the mock Inworld");
            let addr = listener.local_addr().expect("the mock Inworld's address");
            tokio::spawn(async move {
                let _ = axum::serve(listener, router).await;
            });
            MockInworld { addr, state }
        }

        /// `http://127.0.0.1:<port>`: a base URL for the client.
        #[must_use]
        pub fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        /// Answer every later request with `reply`.
        pub fn reply_with(&self, reply: Reply) {
            *lock(&self.state.reply) = reply;
        }

        /// Every request so far, in order.
        #[must_use]
        pub fn seen(&self) -> Vec<Seen> {
            lock(&self.state.seen).clone()
        }

        /// Wait (up to 5 s) for the last [`Reply::Endless`] stream to be
        /// dropped (the client hung up), then re-arm the flag for the next
        /// one.
        ///
        /// # Panics
        ///
        /// When it is still being served after 5 s.
        pub async fn endless_was_dropped(&self) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while !self.state.endless_dropped.load(Ordering::SeqCst) {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the endless body is still being served: the client never hung up"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            self.state.endless_dropped.store(false, Ordering::SeqCst);
        }
    }

    /// Sets its flag when dropped: carried by [`Reply::Endless`]'s stream.
    struct SetOnDrop(Arc<AtomicBool>);

    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// `bytes` as standard, padded base64.
    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let triple = chunk.iter().enumerate().fold(0_u32, |acc, (index, byte)| {
                acc | (u32::from(*byte) << (16 - 8 * index))
            });
            for position in 0..4 {
                if position <= chunk.len() {
                    let sextet = (triple >> (18 - 6 * position)) & 0x3F;
                    encoded.push(char::from(ALPHABET[sextet as usize]));
                } else {
                    encoded.push('=');
                }
            }
        }
        encoded
    }

    /// The success body for `bytes`.
    fn audio_json(bytes: &[u8]) -> String {
        format!(
            r#"{{"audioContent":"{}","usage":{{"processedCharactersCount":12,"modelId":"inworld-tts-2-flash"}}}}"#,
            base64(bytes)
        )
    }

    fn json(status: u16, body: impl Into<Body>) -> Response {
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.into())
            .expect("a mock response")
    }

    fn streamed(body: Body) -> Response {
        json(200, body)
    }

    /// The opening of an `audioContent` string.
    fn opening() -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
        futures_util::stream::once(async {
            Ok::<_, std::io::Error>(Bytes::from_static(br#"{"audioContent":""#))
        })
    }

    async fn handle(State(state): State<Arc<MockState>>, request: Request) -> Response {
        let (parts, body) = request.into_parts();
        let header_text = |name: header::HeaderName| {
            parts
                .headers
                .get(name)
                .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        };
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap_or_default();
        lock(&state.seen).push(Seen {
            method: parts.method.to_string(),
            path: parts.uri.path().to_string(),
            authorization: header_text(header::AUTHORIZATION),
            content_type: header_text(header::CONTENT_TYPE),
            body: String::from_utf8_lossy(&body).into_owned(),
        });
        let reply = lock(&state.reply).clone();
        let default_audio = || audio_json(crate::testing::MP3_FIXTURE);
        match reply {
            Reply::Audio(bytes) => json(200, audio_json(&bytes)),
            Reply::Body(status, body) => json(status, body),
            Reply::Chunked(body) => {
                let chunks: Vec<Result<Bytes, std::io::Error>> = body
                    .into_bytes()
                    .chunks(64 * 1024)
                    .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
                    .collect();
                streamed(Body::from_stream(futures_util::stream::iter(chunks)))
            }
            Reply::Redirect => Response::builder()
                .status(302)
                .header(header::LOCATION, "/followed")
                .body(Body::empty())
                .expect("a mock response"),
            Reply::Hang(pause) => {
                tokio::time::sleep(pause).await;
                json(200, default_audio())
            }
            Reply::Endless => {
                let dropped = SetOnDrop(Arc::clone(&state.endless_dropped));
                let forever = futures_util::stream::unfold(dropped, |dropped| async move {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    Some((Ok(Bytes::from_static(&ENDLESS_CHUNK)), dropped))
                });
                streamed(Body::from_stream(opening().chain(forever)))
            }
            Reply::StallAfterHeaders => streamed(Body::from_stream(
                opening().chain(futures_util::stream::pending()),
            )),
            Reply::Drip => {
                let drip = futures_util::stream::unfold(0, |dropped| async move {
                    if dropped == DRIP_DROPS {
                        return None;
                    }
                    tokio::time::sleep(DRIP_EVERY).await;
                    Some((Ok(Bytes::from_static(b"A")), dropped + 1))
                });
                streamed(Body::from_stream(opening().chain(drip)))
            }
            Reply::DeclaredOversized => Response::builder()
                .status(200)
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::CONTENT_LENGTH,
                    stridelabs_inworld::DEFAULT_MAX_RESPONSE_BYTES + 1,
                )
                .body(Body::from_stream(futures_util::stream::pending::<
                    Result<Bytes, std::io::Error>,
                >()))
                .expect("a mock response"),
            Reply::Truncated => {
                let whole = Bytes::from(default_audio());
                let length = whole.len();
                let half = whole.slice(..length / 2);
                let chunks = futures_util::stream::iter([Ok(half)]).chain(
                    futures_util::stream::once(async {
                        tokio::time::sleep(TRUNCATION_PAUSE).await;
                        Err(std::io::Error::other(
                            "the mock Inworld's scripted truncation",
                        ))
                    }),
                );
                Response::builder()
                    .status(200)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_LENGTH, length)
                    .body(Body::from_stream(chunks))
                    .expect("a mock response")
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        /// The mock's own encoder is standard, padded base64, at every
        /// remainder.
        #[test]
        fn the_mock_encodes_standard_base64() {
            for length in 0..16_usize {
                let bytes: Vec<u8> = (0..length)
                    .map(|index| u8::try_from(index * 37 % 256).expect("a byte"))
                    .collect();
                assert_eq!(super::base64(&bytes), STANDARD.encode(&bytes), "{length}");
            }
            let all: Vec<u8> = (0..=255).collect();
            assert_eq!(super::base64(&all), STANDARD.encode(&all));
        }
    }
}

#[cfg(test)]
mod tests {
    use stridelabs_inworld::MalformedReason;

    use super::*;

    /// The variants a caller can construct, each mapped by name: every one
    /// a `502`, its class the error's own phrase. (`Unavailable` and
    /// `Rejected` only the client crate constructs: `tests/inworld.rs` maps
    /// them from real exchanges.)
    #[test]
    fn every_constructible_failure_is_a_502() {
        for error in [
            InworldError::Malformed(MalformedReason::BodyTooLarge),
            InworldError::Malformed(MalformedReason::NotJsonObject),
            InworldError::Malformed(MalformedReason::NoAudioContent),
            InworldError::Malformed(MalformedReason::AudioContentTooLong),
            InworldError::Malformed(MalformedReason::NotBase64),
            InworldError::Malformed(MalformedReason::EmptyAudio),
            InworldError::Malformed(MalformedReason::AudioTooLarge),
            InworldError::Malformed(MalformedReason::NotMp3),
            InworldError::UnusableKey,
            InworldError::TextTooLong {
                chars: 601,
                max: 600,
            },
            InworldError::SpeakingRateNotFinite,
        ] {
            assert_eq!(
                failure(&error),
                TtsFailure::Permanent(ErrorClass::composed(error.to_string())),
                "{error}"
            );
        }
    }

    /// The eight are the voices both apps verified, in their order.
    #[test]
    fn the_eight_voices_are_the_apps() {
        assert_eq!(
            INWORLD_VOICES,
            ["Jason", "Hazel", "Casey", "Nadia", "Brian", "Imogen", "Liam", "Evan"]
        );
    }
}
