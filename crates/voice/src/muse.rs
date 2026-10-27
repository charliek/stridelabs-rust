//! Meta's Muse realtime speech to text, as an [`SttProvider`] (feature
//! `muse`): [`MuseStt`] dials it, [`MuseSession`] streams one relay session
//! through it. Ported from tapper (`tapper-rs/src/voice/muse.rs`, `82be95f`)
//! and the Muse half of its relay (`relay.rs`: the open, the events, the
//! writes, the close).
//!
//! ```text
//! wss://api.meta.ai/v1/asr/realtime
//!   -> {"authorization":{"accessToken":"Bearer <key>"},"audioEncoding":"PCM_24KHZ",
//!       "model":"muse-voice-transcribe-1.0","mode":"ENDPOINTING","partialMode":"CUMULATIVE",
//!       "languageBias":["English"],"keywords":[…]}            the first text frame
//!                                                             (keywords omitted when empty)
//!   <- {"sessionId":"…"}                                       the ack (no `type`)
//!   -> binary frames: s16le mono PCM, in real time
//!   <- {"type":"speechStart"} {"type":"transcript","transcript":"…","final":false}
//!      {"type":"speechEnd"} {"type":"speechComplete","transcript":"…"}
//!      {"type":"audioProgress",…} {"type":"error","message":"…"}
//!   -> {"type":"endStream"}, then read until Muse closes 1000
//! ```
//!
//! # What the app hands in
//!
//! - **The key** (`META_API_KEY` in both apps): it goes in the FIRST FRAME,
//!   not a header. Muse has no client tokens ("route requests through a
//!   server you control"), which is why the relay exists. That frame is the
//!   most sensitive thing the relay sends anywhere: it is built here, sent
//!   once, and never logged, and the app's log caps ([`LOG_CAPS`]) hold
//!   tungstenite, whose `TRACE` output dumps every frame's payload, at
//!   `info`.
//! - **The URL** (`META_WS_URL`; [`DEFAULT_WS_URL`] is Muse's own), held to
//!   [`realtime_url`]'s rule: `wss://` anywhere, `ws://` only to a NUMERIC
//!   loopback address. A refused one leaves the provider unconfigured (the
//!   stream's `503`); [`MuseStt::url_problem`] says why, for the app's
//!   startup line under its own setting name.
//! - **The keywords**: the terms Muse biases towards, in order. No default
//!   here (tapper's are its beer and places, lumen's none); an empty list
//!   OMITS the handshake's `keywords` field rather than sending `[]`
//!   ([`handshake_body`]).
//! - **The connector**: every dial is
//!   `connect_async_tls_with_config(url, socket_config(), nodelay, connector)`
//!   with the app's `tokio_tungstenite::Connector` (both apps: aws-lc-rs and
//!   the platform verifier). This module builds no connector and no TLS
//!   configuration, and selects no crypto provider.
//!
//! # The provider's facts
//!
//! Both of revision 1's rates, 24 kHz (the default) and 16 kHz
//! ([`MuseRate`]), PCM s16le mono; a pacing lead of [`PACING_LEAD`] (5 s,
//! Muse's limit on how far ahead of real time audio may run); billed by
//! Muse per second of audio, which the relay's audio budget measures itself.
//!
//! # How the session keeps the `stt` contract
//!
//! - **Open** dials, sends the handshake and reads to the ack ([`is_ack`]) in
//!   one future, with no deadline of its own (the relay's is the only one).
//!   A dial or handshake failure is `Dial`, with [`error_class`]'s class; an
//!   error event (even one that carries a `sessionId`), a close or the
//!   connection ending before the ack is `Refused`.
//! - **Events** are parsed from Muse's RAW text frames by [`MuseEvent`]
//!   (tapper's exact serde attributes) and mapped by [`MuseEvent::into_stt`]:
//!   `speechStart`, `transcript` (cumulative, `final` not read: a final
//!   transcript is still a partial, and only `speechComplete` ends a turn),
//!   `speechEnd`, `speechComplete`; anything else with a `type`
//!   (`audioProgress`) or that does not parse is `Ignored`. Muse's `error`
//!   is the session's failure, class `an error event`.
//! - **A close frame** from Muse is `Finished` when its code is `1000`, the
//!   failure `closed` otherwise; the connection breaking is its
//!   [`error_class`], and its end without a close is the stream's end.
//! - **Ping, pong and binary frames** are absorbed, at most
//!   [`MAX_SILENT_FRAMES_PER_POLL`]
//!   in one poll, after which the session wakes itself and yields.
//! - **Writes** (`send_audio`: one binary frame; `end_input`: [`END_STREAM`])
//!   are `SinkExt::send`: written AND flushed. A failed one marks the session
//!   finished, so `close` only flushes.
//! - **Close**: still open, `endStream` (unless already sent), a normal
//!   close, then read to Muse's close reply; already finished, flush the
//!   reply to Muse's close. The relay bounds it.
//!
//! # Nothing Muse says is logged
//!
//! Not the ack, not a transcript, not an error's `message` (which
//! [`MuseEvent`] never reads), and not a `tungstenite::Error` either: its
//! `Url` variants can quote the address. [`error_class`] turns each into a
//! fixed class.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::stt::{
    AudioFormat, OpenLabel, SttError, SttEvent, SttOpenError, SttProvider, SttSession,
    MAX_SILENT_FRAMES_PER_POLL,
};
use crate::ErrorClass;
pub use crate::LOG_CAPS;

/// Muse's own endpoint: an app's `META_WS_URL` default.
pub const DEFAULT_WS_URL: &str = "wss://api.meta.ai";

/// The realtime endpoint's path, appended to the configured URL.
pub const REALTIME_PATH: &str = "/v1/asr/realtime";

/// The model every session names.
pub const MODEL: &str = "muse-voice-transcribe-1.0";

/// The ending frame: no more audio is coming.
pub const END_STREAM: &str = r#"{"type":"endStream"}"#;

/// How far ahead of real time the client's audio may run: Muse's limit, and
/// revision 1's minimum.
pub const PACING_LEAD: Duration = Duration::from_secs(5);

/// The largest message, and the largest frame, the Muse socket accepts:
/// 64 KiB. An 80 ms chunk of 24 kHz audio is 3,840 bytes, so this is over a
/// second of audio in one frame, and a bound on what one frame can make the
/// process buffer.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// The most the socket's write buffer may hold before a send fails rather
/// than queueing: four of the largest frames. Writes are eager (a write
/// buffer target of 0), so this is only reached when Muse stops reading.
pub const MAX_WRITE_BUFFER_BYTES: usize = 4 * MAX_MESSAGE_BYTES;

/// The socket's read buffer: 16 KiB, against tungstenite's 128 KiB default,
/// which it zero-fills before EVERY read. An 80 ms chunk is still one read;
/// a message up to [`MAX_MESSAGE_BYTES`] still arrives whole, over more
/// reads.
pub const READ_BUFFER_BYTES: usize = 16 * 1024;

/// The formats Muse takes, the default first: revision 1's two rates.
const FORMATS: [AudioFormat; 2] = [MuseRate::Hz24000.format(), MuseRate::Hz16000.format()];

/// A sample rate Muse takes (its `audioEncoding`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuseRate {
    /// 24 kHz: the default, and what a phone records natively.
    Hz24000,
    /// 16 kHz: the fallback for a recorder that cannot do 24.
    Hz16000,
}

impl MuseRate {
    /// Both rates, the default first.
    pub const ALL: [MuseRate; 2] = [MuseRate::Hz24000, MuseRate::Hz16000];

    /// The rate named by `value`, exactly (`"24000"` or `"16000"`).
    #[must_use]
    pub fn parse(value: &str) -> Option<MuseRate> {
        match value {
            "24000" => Some(MuseRate::Hz24000),
            "16000" => Some(MuseRate::Hz16000),
            _ => None,
        }
    }

    /// The rate `format` is, when Muse takes it (PCM s16le at 24 or 16 kHz).
    #[must_use]
    pub fn from_format(format: AudioFormat) -> Option<MuseRate> {
        MuseRate::ALL
            .into_iter()
            .find(|rate| rate.format() == format)
    }

    /// Samples per second.
    #[must_use]
    pub const fn hertz(self) -> u32 {
        match self {
            MuseRate::Hz24000 => 24_000,
            MuseRate::Hz16000 => 16_000,
        }
    }

    /// Muse's `audioEncoding` for this rate.
    #[must_use]
    pub const fn encoding(self) -> &'static str {
        match self {
            MuseRate::Hz24000 => "PCM_24KHZ",
            MuseRate::Hz16000 => "PCM_16KHZ",
        }
    }

    /// The core's format: PCM s16le mono at this rate.
    #[must_use]
    pub const fn format(self) -> AudioFormat {
        AudioFormat::pcm_s16le(self.hertz())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Handshake<'a> {
    authorization: Authorization,
    audio_encoding: &'static str,
    model: &'static str,
    mode: &'static str,
    partial_mode: &'static str,
    language_bias: [&'static str; 1],
    /// Omitted when empty (see [`handshake_body`]).
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    keywords: &'a [String],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Authorization {
    access_token: String,
}

/// The first frame of a session, in Muse's documented field order. Carries
/// the key.
///
/// **An empty `keywords` omits the field** rather than sending `[]`: tapper's
/// spike only ever sent Muse a non-empty list, and omitting is the "no bias"
/// spelling that does not depend on Muse treating an empty array as a no-op
/// (lumen, whose default is empty, confirmed it against the live Muse). A
/// term is data: it is JSON-escaped, never spliced. Capping the list is the
/// app's (its setting's startup rule).
#[must_use]
pub fn handshake_body(api_key: &str, rate: MuseRate, keywords: &[String]) -> String {
    serde_json::to_string(&Handshake {
        authorization: Authorization {
            access_token: format!("Bearer {api_key}"),
        },
        audio_encoding: rate.encoding(),
        model: MODEL,
        mode: "ENDPOINTING",
        partial_mode: "CUMULATIVE",
        language_bias: ["English"],
        keywords,
    })
    // Strings and arrays of strings always serialize.
    .expect("the Muse handshake serializes")
}

/// One event from Muse, as far as the relay reads it: tapper's exact wire
/// names. Everything not listed is [`MuseEvent::Ignored`] (`audioProgress`,
/// and any type Muse adds later). An error's `message` is not read at all, so
/// it cannot be logged.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type")]
pub enum MuseEvent {
    /// The speaker started.
    #[serde(rename = "speechStart")]
    SpeechStart,
    /// The cumulative transcript of the current utterance so far. `final`
    /// is not read: a final `transcript` is still a partial to the client,
    /// and only `speechComplete` ends a turn.
    #[serde(rename = "transcript")]
    Transcript {
        /// The text so far.
        transcript: String,
    },
    /// The speaker stopped.
    #[serde(rename = "speechEnd")]
    SpeechEnd,
    /// The utterance is complete, with its final text.
    #[serde(rename = "speechComplete")]
    SpeechComplete {
        /// The final text. Absent is empty.
        #[serde(default)]
        transcript: String,
    },
    /// Muse failed the session.
    #[serde(rename = "error")]
    Error,
    /// Anything else with a `type`.
    #[serde(other)]
    Ignored,
}

impl MuseEvent {
    /// A text frame from Muse as an event, or `None` when it is not one (not
    /// JSON, no `type`, a known type missing its field). The parse error is
    /// dropped unrendered: it can quote the frame.
    #[must_use]
    pub fn parse(text: &str) -> Option<MuseEvent> {
        serde_json::from_str(text).ok()
    }

    /// The core's event for this one: `None` for [`MuseEvent::Error`] (the
    /// session's failure, not an event) and [`MuseEvent::Ignored`] (no
    /// event: the session counts it as `SttEvent::Ignored`).
    #[must_use]
    pub fn into_stt(self) -> Option<SttEvent> {
        match self {
            MuseEvent::SpeechStart => Some(SttEvent::SpeechStart),
            MuseEvent::Transcript { transcript } => Some(SttEvent::Partial(transcript)),
            MuseEvent::SpeechEnd => Some(SttEvent::SpeechEnd),
            MuseEvent::SpeechComplete { transcript } => Some(SttEvent::EndOfTurn(transcript)),
            MuseEvent::Error | MuseEvent::Ignored => None,
        }
    }
}

/// Whether `text` is Muse's ack: a JSON object with a string `sessionId`.
#[must_use]
pub fn is_ack(text: &str) -> bool {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Ack {
        #[allow(dead_code, reason = "read only to require that it is a string")]
        session_id: String,
    }
    serde_json::from_str::<Ack>(text).is_ok()
}

/// Why a configured URL cannot be dialled. Each leaves the provider
/// unconfigured (the stream's `503`); the app logs it under its own setting
/// name, never the URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlProblem {
    /// Not a URL, or one without a host.
    Unparseable,
    /// Neither `wss://`, nor `ws://` to a numeric loopback address.
    Scheme,
    /// It carries userinfo, a query or a fragment: where a URL carries a
    /// credential, and nothing the relay would send.
    Extras,
}

impl std::fmt::Display for UrlProblem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            UrlProblem::Unparseable => "not a URL with a host",
            UrlProblem::Scheme => {
                "neither wss:// nor ws:// to a numeric loopback address (127.0.0.0/8 or ::1)"
            }
            UrlProblem::Extras => "carries userinfo, a query or a fragment",
        })
    }
}

/// `configured` with [`REALTIME_PATH`] appended (a trailing slash on it
/// tolerated): what a session dials.
///
/// `wss://` anywhere; `ws://` ONLY to a numeric loopback address (a mock in
/// a test, a developer's tunnel), because the first frame carries the key,
/// and a plaintext dial off the machine would hand it to the network. A NAME
/// is never trusted to be loopback, `localhost` included: it is whatever the
/// resolver says it is.
///
/// # Errors
///
/// A [`UrlProblem`] for a URL a session will not dial.
pub fn realtime_url(configured: &str) -> Result<String, UrlProblem> {
    let url = url::Url::parse(configured).map_err(|_| UrlProblem::Unparseable)?;
    let host = url.host_str().ok_or(UrlProblem::Unparseable)?;
    match url.scheme() {
        "wss" => {}
        "ws" if is_loopback(host) => {}
        _ => return Err(UrlProblem::Scheme),
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(UrlProblem::Extras);
    }
    Ok(format!(
        "{}{REALTIME_PATH}",
        url.as_str().trim_end_matches('/')
    ))
}

/// Whether `host`, as the URL parser left it (an IPv4 literal, already
/// normalized: `127.1` reads `127.0.0.1`; a bracketed IPv6 literal; or a
/// name), is a NUMERIC loopback address. A name is not.
fn is_loopback(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// The Muse socket's configuration: [`READ_BUFFER_BYTES`] to read into,
/// [`MAX_MESSAGE_BYTES`] for a message and a frame, eager writes, and a write
/// buffer bounded at [`MAX_WRITE_BUFFER_BYTES`].
#[must_use]
pub fn socket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(READ_BUFFER_BYTES)
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES))
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_WRITE_BUFFER_BYTES)
}

/// A `tungstenite::Error` as a fixed class: never its `Display`, which can
/// quote the URL (`UrlError::UnableToConnect`) or carry a peer's bytes.
#[must_use]
pub fn error_class(error: &tungstenite::Error) -> ErrorClass {
    use tungstenite::Error;
    match error {
        Error::ConnectionClosed | Error::AlreadyClosed => ErrorClass::fixed("closed"),
        Error::Io(io) => {
            let tls = io
                .get_ref()
                .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some());
            if tls {
                ErrorClass::fixed("tls")
            } else {
                ErrorClass::composed(format!("io {:?}", io.kind()))
            }
        }
        Error::Tls(_) => ErrorClass::fixed("tls"),
        Error::Capacity(_) => ErrorClass::fixed("capacity"),
        Error::Protocol(_) => ErrorClass::fixed("protocol"),
        Error::WriteBufferFull(_) => ErrorClass::fixed("write buffer full"),
        Error::Utf8(_) => ErrorClass::fixed("utf-8"),
        Error::AttackAttempt => ErrorClass::fixed("attack attempt"),
        Error::Url(_) => ErrorClass::fixed("url"),
        Error::Http(response) => {
            ErrorClass::composed(format!("http {}", response.status().as_u16()))
        }
        Error::HttpFormat(_) => ErrorClass::fixed("http format"),
    }
}

/// The Muse provider: the key, the realtime URL (or why the configured one
/// was refused), the keywords, and the app's connector. Built once, at
/// startup; [`SttProvider::configured`] when the key is set and the URL was
/// accepted.
pub struct MuseStt {
    api_key: String,
    url: Result<String, UrlProblem>,
    keywords: Vec<String>,
    connector: Connector,
}

/// The key never prints; the realtime URL (which [`realtime_url`] holds to
/// carry no userinfo, query or fragment) or the problem with it; the
/// keywords as their count (the terms are the operator's).
impl std::fmt::Debug for MuseStt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("MuseStt");
        debug.field("api_key_configured", &!self.api_key.trim().is_empty());
        debug.field("keywords", &self.keywords.len());
        match &self.url {
            Ok(url) => debug.field("realtime_url", url),
            Err(problem) => debug.field("realtime_url_refused", problem),
        };
        debug.finish_non_exhaustive()
    }
}

impl MuseStt {
    /// Muse with `api_key` at `ws_url` (held to [`realtime_url`]'s rule),
    /// biased towards `keywords` (empty: none, the handshake's field
    /// omitted), every dial through `connector`. Never fails: a refused URL
    /// or an empty key is an unconfigured provider, the stream's `503`.
    #[must_use]
    pub fn new(
        api_key: &str,
        ws_url: &str,
        keywords: Vec<String>,
        connector: Connector,
    ) -> MuseStt {
        MuseStt {
            api_key: api_key.to_string(),
            url: realtime_url(ws_url),
            keywords,
            connector,
        }
    }

    /// Why the configured URL was refused, for the app's startup line under
    /// its own setting name; `None` when it was accepted.
    #[must_use]
    pub fn url_problem(&self) -> Option<UrlProblem> {
        self.url.as_ref().err().copied()
    }
}

impl SttProvider for MuseStt {
    type Session = MuseSession;

    fn configured(&self) -> bool {
        !self.api_key.trim().is_empty() && self.url.is_ok()
    }

    fn formats(&self) -> &[AudioFormat] {
        &FORMATS
    }

    fn pacing_lead(&self) -> Duration {
        PACING_LEAD
    }

    /// Dial, send the handshake, read to the ack (module docs, "Open"). The
    /// relay's `deadline` is the only bound: this applies none.
    fn open(
        &self,
        format: AudioFormat,
        _deadline: tokio::time::Instant,
    ) -> impl Future<Output = Result<MuseSession, SttOpenError>> + Send {
        // Unreachable through the relay, which opens only a configured
        // provider and one of its formats: answered as a dial failure of a
        // fixed class rather than a panic.
        let target = match (&self.url, MuseRate::from_format(format)) {
            (Ok(url), Some(rate)) if self.configured() => Ok((
                url.clone(),
                handshake_body(&self.api_key, rate, &self.keywords),
                self.connector.clone(),
            )),
            (Ok(_), Some(_)) => Err(ErrorClass::fixed("not configured")),
            (Err(_), _) => Err(ErrorClass::fixed("not configured")),
            (Ok(_), None) => Err(ErrorClass::fixed("unsupported format")),
        };
        async move {
            let (url, handshake, connector) = target.map_err(dial)?;
            open_session(&url, handshake, connector).await
        }
    }
}

/// A dial failure of `class`.
fn dial(class: ErrorClass) -> SttOpenError {
    SttOpenError {
        label: OpenLabel::Dial,
        class,
    }
}

/// A refusal: Muse was reached and said no, `how`.
fn refused(how: &'static str) -> SttOpenError {
    SttOpenError {
        label: OpenLabel::Refused,
        class: ErrorClass::fixed(how),
    }
}

/// Dial `url` through `connector`, send `handshake`, and read to the ack.
/// Muse frames that arrive before the ack and are neither the ack nor an
/// error (none are documented) are skipped.
async fn open_session(
    url: &str,
    handshake: String,
    connector: Connector,
) -> Result<MuseSession, SttOpenError> {
    let (mut socket, _response) = tokio_tungstenite::connect_async_tls_with_config(
        url,
        Some(socket_config()),
        // Audio is real-time: a 3.8 KB chunk must not wait for an ACK.
        true,
        Some(connector),
    )
    .await
    .map_err(|error| dial(error_class(&error)))?;
    socket
        .send(Message::text(handshake))
        .await
        .map_err(|error| dial(error_class(&error)))?;
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                // The error first: an error event that happened to carry a
                // `sessionId` is still a refusal, not an ack.
                if MuseEvent::parse(text.as_str()) == Some(MuseEvent::Error) {
                    return Err(refused("an error event"));
                }
                if is_ack(text.as_str()) {
                    return Ok(MuseSession {
                        socket,
                        finished: false,
                    });
                }
            }
            Some(Ok(Message::Close(_))) => return Err(refused("a close")),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return Err(refused("the connection ended")),
        }
    }
}

/// The socket to Muse.
type MuseSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// One open Muse session (module docs, "How the session keeps the `stt`
/// contract").
pub struct MuseSession {
    socket: MuseSocket,
    /// Muse's side is over: it closed, the connection ended or failed, or a
    /// write failed. `close` then only flushes.
    finished: bool,
}

impl std::fmt::Debug for MuseSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MuseSession")
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl futures_core::Stream for MuseSession {
    type Item = Result<SttEvent, SttError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let session = &mut *self;
        // Frames that yield no item (ping, pong, binary) are absorbed, at most
        // this many in one poll: the read state lives in the socket, so a
        // dropped `next()` loses nothing.
        for _ in 0..MAX_SILENT_FRAMES_PER_POLL {
            let message = match Pin::new(&mut session.socket).poll_next(cx) {
                Poll::Ready(message) => message,
                Poll::Pending => return Poll::Pending,
            };
            let item = match message {
                Some(Ok(Message::Text(text))) => match MuseEvent::parse(text.as_str()) {
                    // The session is over on Muse's side, but its socket may
                    // still be open: `close` closes it.
                    Some(MuseEvent::Error) => Err(SttError::fixed("an error event")),
                    Some(event) => Ok(event.into_stt().unwrap_or(SttEvent::Ignored)),
                    None => Ok(SttEvent::Ignored),
                },
                Some(Ok(Message::Close(frame))) => {
                    session.finished = true;
                    if frame.is_some_and(|frame| frame.code == CloseCode::Normal) {
                        Ok(SttEvent::Finished)
                    } else {
                        Err(SttError::fixed("closed"))
                    }
                }
                Some(Ok(_)) => continue,
                Some(Err(error)) => {
                    session.finished = true;
                    Err(SttError {
                        class: error_class(&error),
                    })
                }
                None => {
                    session.finished = true;
                    return Poll::Ready(None);
                }
            };
            return Poll::Ready(Some(item));
        }
        // A run of silent frames: let the relay's other arms in.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl MuseSession {
    /// One write, flushed: a failure ends Muse's side.
    async fn write(&mut self, message: Message) -> Result<(), SttError> {
        match self.socket.send(message).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.finished = true;
                Err(SttError {
                    class: error_class(&error),
                })
            }
        }
    }
}

impl SttSession for MuseSession {
    fn send_audio(
        &mut self,
        frame: bytes::Bytes,
    ) -> impl Future<Output = Result<(), SttError>> + Send {
        self.write(Message::Binary(frame))
    }

    fn end_input(&mut self) -> impl Future<Output = Result<(), SttError>> + Send {
        self.write(Message::text(END_STREAM))
    }

    /// tapper's `close_muse`, without its own bound (the relay's is the one):
    /// still open, `endStream` unless `end_sent`, a normal close, then read
    /// to Muse's reply; already finished, flush the reply to Muse's close.
    async fn close(mut self, end_sent: bool) {
        if self.finished {
            let _ = self.socket.close(None).await;
            return;
        }
        if !end_sent {
            let _ = self.socket.send(Message::text(END_STREAM)).await;
        }
        let _ = self
            .socket
            .close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "".into(),
            }))
            .await;
        while let Some(Ok(message)) = self.socket.next().await {
            if message.is_close() {
                break;
            }
        }
    }
}

/// A WebSocket server standing in for Muse (feature `test-support`, with
/// `axum`): tapper's in-test mock (`tapper-rs/tests/voice_stream.rs`,
/// `82be95f`), exported because an app's own suites (its log-cap canaries,
/// its route tests) need a real Muse wire too.
///
/// It records every frame it receives and sends what the test says. By
/// default it acks the first text frame (the handshake) with
/// `{"sessionId":"mock-session"}`. It serves `ws://` on `127.0.0.1` only:
/// dial it with `tokio_tungstenite::Connector::Plain`.
#[cfg(all(feature = "test-support", feature = "axum"))]
pub mod mock {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
    use axum::extract::State;
    use axum::http::Uri;
    use axum::response::Response;
    use axum::Router;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    /// How long [`MuseConn::next`] and [`MockMuse::accept`] wait before the
    /// test fails.
    const WAIT: Duration = Duration::from_secs(5);

    /// What the mock received from the dialler.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Seen {
        /// A text frame.
        Text(String),
        /// A binary frame.
        Binary(Vec<u8>),
        /// A close frame, and its code (`None` for one with no code).
        Close(Option<u16>),
        /// The connection ended.
        Gone,
    }

    /// What a test makes the mock do.
    enum Command {
        Text(String),
        Binary(Vec<u8>),
        Close(u16),
        Drop,
    }

    /// One connection the dialler opened to the mock.
    pub struct MuseConn {
        path: String,
        seen: mpsc::UnboundedReceiver<Seen>,
        commands: mpsc::UnboundedSender<Command>,
    }

    impl MuseConn {
        /// The path the dialler asked for (`/v1/asr/realtime`, after the
        /// configured URL's own path).
        #[must_use]
        pub fn path(&self) -> &str {
            &self.path
        }

        /// The next thing the mock received; [`Seen::Gone`] once the
        /// connection ended.
        ///
        /// # Panics
        ///
        /// When nothing arrives within 5 s.
        pub async fn next(&mut self) -> Seen {
            timeout(WAIT, self.seen.recv())
                .await
                .expect("the mock Muse received nothing in 5 s")
                .unwrap_or(Seen::Gone)
        }

        /// The next text frame (the handshake first), skipping audio.
        ///
        /// # Panics
        ///
        /// On anything else, or nothing within 5 s.
        pub async fn text(&mut self) -> String {
            loop {
                match self.next().await {
                    Seen::Text(text) => return text,
                    Seen::Binary(_) => {}
                    other => panic!("expected a text frame at the mock, got {other:?}"),
                }
            }
        }

        /// Every audio frame up to the next non-audio frame, and that frame.
        pub async fn audio_until_other(&mut self) -> (Vec<Vec<u8>>, Seen) {
            let mut audio = Vec::new();
            loop {
                match self.next().await {
                    Seen::Binary(bytes) => audio.push(bytes),
                    other => return (audio, other),
                }
            }
        }

        /// Send a raw Muse frame, e.g. `{"type":"speechStart"}`.
        pub fn send(&self, text: &str) {
            self.command(Command::Text(text.to_string()));
        }

        /// Send a binary frame (Muse sends none: a frame the adapter must
        /// absorb).
        pub fn send_binary(&self, bytes: Vec<u8>) {
            self.command(Command::Binary(bytes));
        }

        /// Send a close frame with `code`.
        pub fn close(&self, code: u16) {
            self.command(Command::Close(code));
        }

        /// Drop the connection without a close frame.
        pub fn drop_connection(&self) {
            self.command(Command::Drop);
        }

        fn command(&self, command: Command) {
            // A connection that already ended takes no commands; the test
            // reads that from `next`.
            let _ = self.commands.send(command);
        }
    }

    #[derive(Clone)]
    struct MockState {
        auto_ack: Arc<AtomicBool>,
        reply_to_handshake: Arc<Mutex<Option<String>>>,
        connections: mpsc::UnboundedSender<MuseConn>,
    }

    /// The mock (module docs).
    pub struct MockMuse {
        addr: SocketAddr,
        state: MockState,
        connections: tokio::sync::Mutex<mpsc::UnboundedReceiver<MuseConn>>,
    }

    impl MockMuse {
        /// A mock on a fresh `127.0.0.1` port, served for the rest of the
        /// test (a task on the caller's runtime).
        ///
        /// # Panics
        ///
        /// When no loopback port can be bound.
        pub async fn start() -> MockMuse {
            let (connections_tx, connections_rx) = mpsc::unbounded_channel();
            let state = MockState {
                auto_ack: Arc::new(AtomicBool::new(true)),
                reply_to_handshake: Arc::new(Mutex::new(None)),
                connections: connections_tx,
            };
            let router = Router::new().fallback(upgrade).with_state(state.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind the mock Muse");
            let addr = listener.local_addr().expect("the mock Muse's address");
            tokio::spawn(async move {
                let _ = axum::serve(listener, router).await;
            });
            MockMuse {
                addr,
                state,
                connections: tokio::sync::Mutex::new(connections_rx),
            }
        }

        /// `ws://127.0.0.1:<port>`: a configured URL (the adapter appends
        /// the realtime path).
        #[must_use]
        pub fn url(&self) -> String {
            format!("ws://{}", self.addr)
        }

        /// Answer the handshake with `reply` instead of the ack (`None`:
        /// the ack again).
        pub fn reply_to_handshake(&self, reply: Option<&str>) {
            self.state.auto_ack.store(reply.is_none(), Ordering::SeqCst);
            *self
                .state
                .reply_to_handshake
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = reply.map(str::to_string);
        }

        /// Never answer the handshake at all.
        pub fn never_ack(&self) {
            self.state.auto_ack.store(false, Ordering::SeqCst);
            *self
                .state
                .reply_to_handshake
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = None;
        }

        /// The next connection the dialler opened.
        ///
        /// # Panics
        ///
        /// When none arrives within 5 s.
        pub async fn accept(&self) -> MuseConn {
            timeout(WAIT, self.connections.lock().await.recv())
                .await
                .expect("nothing dialled the mock Muse")
                .expect("the mock's channel")
        }

        /// Whether anything dialled the mock (after giving it 100 ms).
        pub async fn was_dialled(&self) -> bool {
            tokio::time::sleep(Duration::from_millis(100)).await;
            self.connections.lock().await.try_recv().is_ok()
        }
    }

    async fn upgrade(
        State(state): State<MockState>,
        uri: Uri,
        upgrade: WebSocketUpgrade,
    ) -> Response {
        let path = uri.path().to_string();
        upgrade.on_upgrade(move |socket| connection(socket, state, path))
    }

    async fn connection(mut socket: WebSocket, state: MockState, path: String) {
        let (seen_tx, seen_rx) = mpsc::unbounded_channel();
        let (commands_tx, mut commands_rx) = mpsc::unbounded_channel();
        let _ = state.connections.send(MuseConn {
            path,
            seen: seen_rx,
            commands: commands_tx,
        });
        let mut handshake_seen = false;
        let mut commands_open = true;
        loop {
            tokio::select! {
                message = socket.recv() => match message {
                    Some(Ok(Message::Text(text))) => {
                        let _ = seen_tx.send(Seen::Text(text.to_string()));
                        if !handshake_seen {
                            handshake_seen = true;
                            let reply = if state.auto_ack.load(Ordering::SeqCst) {
                                Some(r#"{"sessionId":"mock-session"}"#.to_string())
                            } else {
                                state
                                    .reply_to_handshake
                                    .lock()
                                    .unwrap_or_else(PoisonError::into_inner)
                                    .clone()
                            };
                            if let Some(reply) = reply {
                                let _ = socket.send(Message::text(reply)).await;
                            }
                        }
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        let _ = seen_tx.send(Seen::Binary(bytes.to_vec()));
                    }
                    Some(Ok(Message::Close(frame))) => {
                        let _ = seen_tx.send(Seen::Close(frame.map(|frame| frame.code)));
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => {
                        let _ = seen_tx.send(Seen::Gone);
                        return;
                    }
                },
                command = commands_rx.recv(), if commands_open => match command {
                    Some(Command::Text(text)) => {
                        let _ = socket.send(Message::text(text)).await;
                    }
                    Some(Command::Binary(bytes)) => {
                        let _ = socket.send(Message::Binary(bytes.into())).await;
                    }
                    Some(Command::Close(code)) => {
                        let _ = socket
                            .send(Message::Close(Some(CloseFrame {
                                code,
                                reason: "".into(),
                            })))
                            .await;
                    }
                    Some(Command::Drop) => return,
                    None => commands_open = false,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms(terms: &[&str]) -> Vec<String> {
        terms.iter().map(|term| (*term).to_string()).collect()
    }

    /// The documented handshake, field for field and in its order, with
    /// configured keywords (the spike's, as a fixture) and at the other
    /// rate; a term is data, escaped and never spliced.
    #[test]
    fn the_handshake_is_the_pinned_shape() {
        let keywords = terms(&["Fair State", "taproom", "tripel"]);
        assert_eq!(
            handshake_body("k3y", MuseRate::Hz24000, &keywords),
            r#"{"authorization":{"accessToken":"Bearer k3y"},"audioEncoding":"PCM_24KHZ","model":"muse-voice-transcribe-1.0","mode":"ENDPOINTING","partialMode":"CUMULATIVE","languageBias":["English"],"keywords":["Fair State","taproom","tripel"]}"#
        );
        assert!(handshake_body("k3y", MuseRate::Hz16000, &keywords)
            .contains(r#""audioEncoding":"PCM_16KHZ""#));
        assert!(
            handshake_body("k3y", MuseRate::Hz24000, &terms(&[r#"a"b"#]))
                .ends_with(r#""keywords":["a\"b"]}"#)
        );
    }

    /// No keywords omits the field; it does not send an empty array.
    #[test]
    fn no_keywords_omits_the_field() {
        let body = handshake_body("k3y", MuseRate::Hz24000, &[]);
        assert_eq!(
            body,
            r#"{"authorization":{"accessToken":"Bearer k3y"},"audioEncoding":"PCM_24KHZ","model":"muse-voice-transcribe-1.0","mode":"ENDPOINTING","partialMode":"CUMULATIVE","languageBias":["English"]}"#
        );
        assert!(!body.contains("keywords"));
    }

    /// Exactly the two rates parse; each is the core's PCM s16le format at
    /// its rate, and only those formats are Muse's.
    #[test]
    fn only_the_two_rates_parse() {
        assert_eq!(MuseRate::parse("24000"), Some(MuseRate::Hz24000));
        assert_eq!(MuseRate::parse("16000"), Some(MuseRate::Hz16000));
        for refused in [
            "", "8000", "48000", " 24000", "24000 ", "024000", "24k", "16000.0",
        ] {
            assert_eq!(MuseRate::parse(refused), None, "{refused:?}");
        }
        assert_eq!(MuseRate::Hz24000.format().bytes_per_second(), 48_000);
        assert_eq!(MuseRate::Hz16000.format().bytes_per_second(), 32_000);
        assert_eq!(MuseRate::ALL.map(MuseRate::hertz), [24_000, 16_000]);
        for rate in MuseRate::ALL {
            assert_eq!(MuseRate::from_format(rate.format()), Some(rate));
        }
        assert_eq!(MuseRate::from_format(AudioFormat::pcm_s16le(48_000)), None);
        assert_eq!(FORMATS.map(|format| format.sample_rate), [24_000, 16_000]);
    }

    #[test]
    fn the_realtime_url_appends_the_path_and_refuses_plaintext_off_loopback() {
        for (configured, expected) in [
            ("wss://api.meta.ai", "wss://api.meta.ai/v1/asr/realtime"),
            ("wss://api.meta.ai/", "wss://api.meta.ai/v1/asr/realtime"),
            (
                "wss://proxy.example:8443/muse",
                "wss://proxy.example:8443/muse/v1/asr/realtime",
            ),
            ("ws://127.0.0.1:9000", "ws://127.0.0.1:9000/v1/asr/realtime"),
            // The parser normalizes the shorthand before the check reads it.
            ("ws://127.1:9000", "ws://127.0.0.1:9000/v1/asr/realtime"),
            (
                "ws://127.8.9.10:9000/x/",
                "ws://127.8.9.10:9000/x/v1/asr/realtime",
            ),
            ("ws://[::1]:9000", "ws://[::1]:9000/v1/asr/realtime"),
        ] {
            assert_eq!(
                realtime_url(configured).as_deref(),
                Ok(expected),
                "{configured}"
            );
        }
        assert_eq!(
            realtime_url(DEFAULT_WS_URL).as_deref(),
            Ok("wss://api.meta.ai/v1/asr/realtime")
        );
        for (configured, problem) in [
            ("", UrlProblem::Unparseable),
            ("api.meta.ai", UrlProblem::Unparseable),
            ("ws://api.meta.ai", UrlProblem::Scheme),
            ("ws://10.0.0.1:9000", UrlProblem::Scheme),
            ("ws://localhost.example", UrlProblem::Scheme),
            ("ws://localhost:9000", UrlProblem::Scheme),
            ("ws://LOCALHOST:9000", UrlProblem::Scheme),
            ("ws://127.0.0.1.nip.io:9000", UrlProblem::Scheme),
            ("ws://[::ffff:127.0.0.1]:9000", UrlProblem::Scheme),
            ("https://api.meta.ai", UrlProblem::Scheme),
            ("http://127.0.0.1:9000", UrlProblem::Scheme),
            ("wss://user:pass@api.meta.ai", UrlProblem::Extras),
            ("wss://user@api.meta.ai", UrlProblem::Extras),
            ("wss://api.meta.ai?key=x", UrlProblem::Extras),
            ("wss://api.meta.ai#x", UrlProblem::Extras),
        ] {
            assert_eq!(realtime_url(configured), Err(problem), "{configured}");
        }
    }

    /// The problems' texts name no setting (each app's line does) and quote
    /// no URL.
    #[test]
    fn a_url_problem_names_no_setting() {
        assert_eq!(UrlProblem::Unparseable.to_string(), "not a URL with a host");
        assert_eq!(
            UrlProblem::Scheme.to_string(),
            "neither wss:// nor ws:// to a numeric loopback address (127.0.0.0/8 or ::1)"
        );
        assert_eq!(
            UrlProblem::Extras.to_string(),
            "carries userinfo, a query or a fragment"
        );
    }

    /// Every documented event from its raw frame, the ignored ones, and what
    /// does not parse: tapper's serde attributes, held by the wire names.
    #[test]
    fn muse_events_parse_to_what_the_relay_reads() {
        for (frame, expected) in [
            (
                r#"{"type":"speechStart","turnId":1}"#,
                Some(MuseEvent::SpeechStart),
            ),
            (
                r#"{"type":"transcript","transcript":"what is","final":false}"#,
                Some(MuseEvent::Transcript {
                    transcript: "what is".into(),
                }),
            ),
            (
                r#"{"type":"transcript","transcript":"what is it","final":true}"#,
                Some(MuseEvent::Transcript {
                    transcript: "what is it".into(),
                }),
            ),
            (
                r#"{"type":"speechEnd","turnId":1}"#,
                Some(MuseEvent::SpeechEnd),
            ),
            (
                r#"{"type":"speechComplete","turnId":1,"transcript":"what is it"}"#,
                Some(MuseEvent::SpeechComplete {
                    transcript: "what is it".into(),
                }),
            ),
            (
                r#"{"type":"speechComplete","turnId":1}"#,
                Some(MuseEvent::SpeechComplete {
                    transcript: String::new(),
                }),
            ),
            (r#"{"type":"error","message":"no"}"#, Some(MuseEvent::Error)),
            (
                r#"{"type":"audioProgress","ms":80}"#,
                Some(MuseEvent::Ignored),
            ),
            (r#"{"type":"somethingNew"}"#, Some(MuseEvent::Ignored)),
            // The core's names are not Muse's.
            (r#"{"type":"speech_start"}"#, Some(MuseEvent::Ignored)),
            (r#"{"type":"SpeechStart"}"#, Some(MuseEvent::Ignored)),
            (r#"{"sessionId":"s"}"#, None),
            (r#"{"type":"transcript"}"#, None),
            ("not json", None),
            ("[1]", None),
        ] {
            assert_eq!(MuseEvent::parse(frame), expected, "{frame}");
        }
        assert!(is_ack(r#"{"sessionId":"abc"}"#));
        assert!(is_ack(r#"{"sessionId":"abc","extra":1}"#));
        assert!(!is_ack(r#"{"sessionId":7}"#));
        assert!(!is_ack(r#"{"session_id":"abc"}"#));
        assert!(!is_ack(r#"{"type":"error"}"#));
    }

    /// Each event's core form: a final `transcript` is still a partial, only
    /// `speechComplete` ends a turn, and neither an error nor an ignored
    /// type is an event.
    #[test]
    fn muse_events_normalize() {
        assert_eq!(
            MuseEvent::SpeechStart.into_stt(),
            Some(SttEvent::SpeechStart)
        );
        assert_eq!(
            MuseEvent::Transcript {
                transcript: "a".into()
            }
            .into_stt(),
            Some(SttEvent::Partial("a".into()))
        );
        assert_eq!(MuseEvent::SpeechEnd.into_stt(), Some(SttEvent::SpeechEnd));
        assert_eq!(
            MuseEvent::SpeechComplete {
                transcript: "a.".into()
            }
            .into_stt(),
            Some(SttEvent::EndOfTurn("a.".into()))
        );
        assert_eq!(MuseEvent::Ignored.into_stt(), None);
        assert_eq!(MuseEvent::Error.into_stt(), None);
    }

    /// A refused URL's class names neither the URL nor anything in it; an
    /// HTTP refusal is its status; an I/O error its kind.
    #[test]
    fn an_error_class_never_quotes_the_url() {
        let error = tungstenite::Error::Url(tungstenite::error::UrlError::UnableToConnect(
            "wss://CANARY.example/v1/asr/realtime".to_string(),
        ));
        assert!(error.to_string().contains("CANARY"), "the premise");
        assert_eq!(error_class(&error).as_str(), "url");
        let refused = tungstenite::Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "CANARY",
        ));
        assert_eq!(error_class(&refused).as_str(), "io ConnectionRefused");
        let tls = tungstenite::Error::Io(std::io::Error::other(rustls::Error::General(
            "CANARY".into(),
        )));
        assert_eq!(error_class(&tls).as_str(), "tls");
        let http = tungstenite::Error::Http(Box::new(
            http::Response::builder()
                .status(403)
                .body(Some(b"CANARY".to_vec()))
                .expect("a response"),
        ));
        assert_eq!(error_class(&http).as_str(), "http 403");
    }

    /// Configured takes a key (not blank) AND an accepted URL; the provider
    /// states revision 1's two rates and Muse's lead.
    #[test]
    fn configured_needs_a_key_and_an_accepted_url() {
        for (key, url, configured, problem) in [
            ("k", "wss://api.meta.ai", true, None),
            ("", "wss://api.meta.ai", false, None),
            ("  ", "wss://api.meta.ai", false, None),
            ("k", "ws://api.meta.ai", false, Some(UrlProblem::Scheme)),
            (
                "k",
                "wss://api.meta.ai?x=1",
                false,
                Some(UrlProblem::Extras),
            ),
        ] {
            let muse = MuseStt::new(key, url, Vec::new(), Connector::Plain);
            assert_eq!(muse.configured(), configured, "{key:?} {url}");
            assert_eq!(muse.url_problem(), problem, "{key:?} {url}");
            assert_eq!(muse.formats(), FORMATS);
            assert_eq!(muse.pacing_lead(), PACING_LEAD);
        }
    }

    /// `Debug` names neither the key nor a refused URL's parts: whether a
    /// key is set, the keyword count, and the accepted realtime URL or the
    /// problem.
    #[test]
    fn debug_never_shows_the_key_or_a_refused_url() {
        for url in [
            "wss://api.meta.ai",
            "wss://CANARY-user:CANARY-pass@api.meta.ai/?key=CANARY#CANARY",
        ] {
            let muse = MuseStt::new(
                "CANARY-KEY",
                url,
                vec!["CANARY-TERM".into()],
                Connector::Plain,
            );
            let rendered = format!("{muse:?} {muse:#?}");
            assert!(!rendered.contains("CANARY"), "{rendered}");
            assert!(rendered.contains("api_key_configured: true"), "{rendered}");
            assert!(rendered.contains("keywords: 1"), "{rendered}");
        }
    }
}
