//! The client protocol's server side, revision 1: the events the relay sends,
//! the close codes on both sides, and the constants a client relies on.
//! `PROTOCOL.md` (beside this crate's `Cargo.toml`) is canonical; this module
//! is what the crate renders it from.
//!
//! | event | meaning |
//! |---|---|
//! | `{"type":"ready", …}` | the provider accepted the session: send audio. Advertises the session's facts: `rates`, `encoding`, `lead_ms` |
//! | `{"type":"speech_start"}` | the speaker started |
//! | `{"type":"partial","text":…}` | OPTIONAL: the current turn's text so far, cumulative |
//! | `{"type":"speech_end"}` | the speaker stopped |
//! | `{"type":"end_of_turn","text":…}` | the turn's final text |
//! | `{"type":"error","code":"provider"\|"limit"\|"internal"}` | sent just before some closes; a `limit` also carries `scope` and `resets_at` |
//!
//! **Additive, presence-based, no version handshake.** A field added later
//! is optional with a stated default when absent (an older server's bare
//! `ready` means `rates [24000, 16000]`, `pcm_s16le`, `lead_ms 5000`); a
//! receiver ignores fields it does not know and a client skips an event type
//! it does not know. Anything else is a new route.
//!
//! **The golden fixture** ([`GOLDEN_FIXTURE`], `fixtures/relay_events.json`)
//! holds one of every event in its canonical rendering
//! ([`RelayEvent::golden_fixture`]); its SHA-256 ([`GOLDEN_FIXTURE_SHA256`])
//! is recorded in `PROTOCOL.md` and checked by the client package's byte copy,
//! so the hash is the drift check between the two repositories.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::budget::{LimitReached, LimitScope};
use crate::lease::millis;
use crate::stt::{AudioFormat, Encoding};
use crate::tts::DEFAULT_BODY_BYTES;

/// The one text frame a client sends: no more audio is coming. Matched
/// exactly; any other text is ignored.
pub const END_FRAME: &str = r#"{"type":"end"}"#;

/// The text bound every text-to-speech adapter must take at least, in
/// characters (Unicode scalar values of the trimmed text). A client chunks at
/// it until a response advertises more.
pub const TTS_MIN_TEXT_CHARS: usize = 600;

/// The header on EVERY text-to-speech response, refusals included: the
/// server's text bound, a decimal integer of at least [`TTS_MIN_TEXT_CHARS`].
pub const TTS_MAX_CHARS_HEADER: &str = "x-voice-tts-max-chars";

/// The request header that names one sentence's charge: sent once, as 1 to
/// 64 characters of `A-Z a-z 0-9 _ -`; absent, the server mints one.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// The media types a text-to-speech answer may carry. Adding one is a
/// protocol revision AND client support first: a server never answers a type
/// before the clients it serves accept it.
pub const ALLOWED_AUDIO_TYPES: &[&str] = &["audio/mpeg"];

/// The upgrade's reserved `encoding` query parameter.
pub const ENCODING_PARAM: &str = "encoding";

/// The upgrade's `rate` query parameter.
pub const RATE_PARAM: &str = "rate";

/// The client socket's bound on one message and one frame.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// The golden fixture's bytes: one of every event, in `PROTOCOL.md` §11's
/// order and canonical rendering.
pub const GOLDEN_FIXTURE: &str = include_str!("../fixtures/relay_events.json");

/// The golden fixture's SHA-256, as `PROTOCOL.md` records it.
pub const GOLDEN_FIXTURE_SHA256: &str =
    "0437bc8114b0397e3b9734e03c9cb3d72f18ba928f22a160e19fb68f6226ed15";

/// The largest text-to-speech request body read for a text bound of
/// `max_text_chars`, in bytes: `max(4096, 6 × max_text_chars + 256)`,
/// saturating. A client sending raw UTF-8 spends at most 4 bytes a character
/// and 6 for a `\u`-escaped control character, plus at most 256 for the rest
/// of the object; 4 KiB at the minimum bound.
#[must_use]
pub fn tts_body_limit(max_text_chars: usize) -> usize {
    max_text_chars
        .checked_mul(6)
        .and_then(|bytes| bytes.checked_add(256))
        .unwrap_or(usize::MAX)
        .max(DEFAULT_BODY_BYTES)
}

/// The close codes the server sends.
pub mod close_code {
    /// After `end`: the provider finished, or did not within the end grace.
    pub const DONE: u16 = 1000;
    /// The server is going away; reconnect.
    pub const GOING_AWAY: u16 = 1001;
    /// The client broke a rule; the close reason names it.
    pub const POLICY: u16 = 1008;
    /// The provider, or this service, failed (after `error{provider}` or
    /// `error{internal}`).
    pub const ERROR: u16 = 1011;
    /// The session cap.
    pub const SESSION_LIMIT: u16 = 4000;
    /// A newer session for this user took over.
    pub const SUPERSEDED: u16 = 4001;
    /// A budget window is spent (after `error{limit}`).
    pub const LIMIT: u16 = 4002;
    /// What the server RECORDS for a client close frame that carries no code
    /// (RFC 6455 §7.1.5). Never sent.
    pub const NO_STATUS_RECEIVED: u16 = 1005;
}

/// The close codes a client sends: advisory. The server records the code of
/// the client's close frame and never acts on it.
pub mod client_close_code {
    /// The mic is off, after `end`.
    pub const MIC_OFF: u16 = 1000;
    /// The user left the conversation, or signed out.
    pub const LEFT: u16 = 4100;
    /// The app was paused or backgrounded.
    pub const PAUSED: u16 = 4101;
    /// Idle.
    pub const IDLE: u16 = 4102;
    /// The transport was disposed or replaced (another rate included).
    pub const REPLACED: u16 = 4103;
    /// A client-side failure: no `ready` in time, capture failed or stopped,
    /// a start failed, a recorder that would not stop, an encoding it cannot
    /// speak.
    pub const CLIENT_FAILURE: u16 = 4104;
}

/// One event to the client, as a JSON text frame (module docs' table).
/// `#[non_exhaustive]`: the protocol may add an event (an older client skips
/// it), so a match on it needs a fallback arm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RelayEvent {
    /// The provider accepted the session: send audio. The fields advertise
    /// the session's facts, each absent from an older server's `ready` (and
    /// then its default). Their order is pinned: the golden's SHA-256 depends
    /// on it.
    Ready {
        /// The sample rates the server takes, its default first (absent:
        /// `[24000, 16000]`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rates: Option<Vec<u32>>,
        /// The session's audio encoding (absent: `pcm_s16le`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        encoding: Option<Encoding>,
        /// How far ahead of real time the server lets audio run, in ms
        /// (absent: 5000).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lead_ms: Option<u64>,
    },
    /// The speaker started.
    SpeechStart,
    /// The current turn's text so far: cumulative, each replacing the last.
    /// Optional: a provider may send none.
    Partial {
        /// The text so far.
        text: String,
    },
    /// The speaker stopped (the turn may still be completing).
    SpeechEnd,
    /// The turn is complete: its final text.
    EndOfTurn {
        /// The final text.
        text: String,
    },
    /// The relay is about to close the socket, and why (the close code says
    /// the rest). Build one with [`RelayEvent::error`] or
    /// [`RelayEvent::limit`].
    Error {
        /// Which side failed.
        code: ErrorCode,
        /// A `limit`'s spent allowance; absent from every other code.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<LimitScope>,
        /// When `scope`'s allowance comes back; absent with it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resets_at: Option<DateTime<Utc>>,
    },
}

/// Why the relay is closing: the `code` of a [`RelayEvent::Error`].
/// `#[non_exhaustive]`, as [`RelayEvent`]: a code may be added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// The speech-to-text provider failed: it errored, closed unexpectedly,
    /// or did not open in time (close `1011`).
    Provider,
    /// A budget is spent: the user's day or month, or everyone's month
    /// (close `4002`); the event's `scope` says which.
    Limit,
    /// This service failed: the budget could not be charged for too long
    /// (close `1011`).
    Internal,
}

impl RelayEvent {
    /// The advertising `ready`: the provider's `formats` as `rates` (in
    /// order, the default first), their encoding (the first format's: one
    /// encoding in revision 1), and `lead` as `lead_ms`.
    #[must_use]
    pub fn ready(formats: &[AudioFormat], lead: Duration) -> RelayEvent {
        RelayEvent::Ready {
            rates: Some(formats.iter().map(|format| format.sample_rate).collect()),
            encoding: formats.first().map(|format| format.encoding),
            lead_ms: Some(millis(lead)),
        }
    }

    /// The error event of `code`, with no scope: `provider` or `internal`.
    #[must_use]
    pub fn error(code: ErrorCode) -> RelayEvent {
        RelayEvent::Error {
            code,
            scope: None,
            resets_at: None,
        }
    }

    /// The `limit` error event: the spent allowance's scope, and when it
    /// resets.
    #[must_use]
    pub fn limit(limit: &LimitReached) -> RelayEvent {
        RelayEvent::Error {
            code: ErrorCode::Limit,
            scope: Some(limit.scope),
            resets_at: Some(limit.resets_at),
        }
    }

    /// The text frame for this event: compact JSON, `type` first, then the
    /// fields in declaration order.
    ///
    /// # Panics
    ///
    /// Never: a tagged enum of strings, numbers and an instant always
    /// serializes.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a relay event serializes")
    }

    /// The golden fixture's events, `PROTOCOL.md` §11's eleven in order: the
    /// advertising `ready` (24 and 16 kHz, `pcm_s16le`, 5000 ms), one of every
    /// other variant, every error code with a `limit` of every scope, and an
    /// older server's bare `ready` last.
    ///
    /// # Panics
    ///
    /// Never: the instants are fixed, valid RFC 3339.
    #[must_use]
    pub fn golden() -> Vec<RelayEvent> {
        let at = |instant: &str| {
            DateTime::parse_from_rfc3339(instant)
                .expect("a fixed instant")
                .with_timezone(&Utc)
        };
        let limit = |scope, resets_at: &str| RelayEvent::Error {
            code: ErrorCode::Limit,
            scope: Some(scope),
            resets_at: Some(at(resets_at)),
        };
        vec![
            RelayEvent::ready(
                &[
                    AudioFormat::pcm_s16le(24_000),
                    AudioFormat::pcm_s16le(16_000),
                ],
                Duration::from_millis(5_000),
            ),
            RelayEvent::SpeechStart,
            RelayEvent::Partial {
                text: "what's the weather".to_string(),
            },
            RelayEvent::SpeechEnd,
            RelayEvent::EndOfTurn {
                text: "What's the weather in Chicago?".to_string(),
            },
            RelayEvent::error(ErrorCode::Provider),
            limit(LimitScope::UserDay, "2026-10-25T00:00:00Z"),
            limit(LimitScope::UserMonth, "2026-11-01T00:00:00Z"),
            limit(LimitScope::GlobalMonth, "2026-11-01T00:00:00Z"),
            RelayEvent::error(ErrorCode::Internal),
            RelayEvent::Ready {
                rates: None,
                encoding: None,
                lead_ms: None,
            },
        ]
    }

    /// The golden events' canonical rendering, [`GOLDEN_FIXTURE`]'s bytes: a
    /// JSON array with one compact event per line, each indented two spaces,
    /// LF line ends and a final LF.
    #[must_use]
    pub fn golden_fixture() -> String {
        let lines: Vec<String> = RelayEvent::golden()
            .iter()
            .map(|event| format!("  {}", event.to_json()))
            .collect();
        format!("[\n{}\n]\n", lines.join(",\n"))
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    /// Every golden event's wire form, literally: tapper's ten (whose `ready`
    /// now advertises the session's facts) and an older server's bare
    /// `ready`.
    #[test]
    fn each_event_has_its_pinned_wire_form() {
        let rendered: Vec<String> = RelayEvent::golden()
            .iter()
            .map(RelayEvent::to_json)
            .collect();
        assert_eq!(
            rendered,
            [
                r#"{"type":"ready","rates":[24000,16000],"encoding":"pcm_s16le","lead_ms":5000}"#,
                r#"{"type":"speech_start"}"#,
                r#"{"type":"partial","text":"what's the weather"}"#,
                r#"{"type":"speech_end"}"#,
                r#"{"type":"end_of_turn","text":"What's the weather in Chicago?"}"#,
                r#"{"type":"error","code":"provider"}"#,
                r#"{"type":"error","code":"limit","scope":"user_day","resets_at":"2026-10-25T00:00:00Z"}"#,
                r#"{"type":"error","code":"limit","scope":"user_month","resets_at":"2026-11-01T00:00:00Z"}"#,
                r#"{"type":"error","code":"limit","scope":"global_month","resets_at":"2026-11-01T00:00:00Z"}"#,
                r#"{"type":"error","code":"internal"}"#,
                r#"{"type":"ready"}"#,
            ]
        );
    }

    /// A limit event built from a refusal carries its scope and its reset
    /// (whole seconds, `Z`); the other codes carry neither; and an older
    /// server's bare `limit` still parses, scope-less.
    #[test]
    fn a_limit_event_carries_its_scope_and_reset() {
        let now = Utc
            .with_ymd_and_hms(2026, 10, 17, 12, 0, 0)
            .single()
            .expect("an instant");
        let limit = LimitReached::from_mask(4, now).expect("a spent window");
        assert_eq!(
            RelayEvent::limit(&limit).to_json(),
            r#"{"type":"error","code":"limit","scope":"user_month","resets_at":"2026-11-01T00:00:00Z"}"#
        );
        assert_eq!(
            RelayEvent::error(ErrorCode::Internal).to_json(),
            r#"{"type":"error","code":"internal"}"#
        );
        let old: RelayEvent =
            serde_json::from_str(r#"{"type":"error","code":"limit"}"#).expect("parses");
        assert_eq!(old, RelayEvent::error(ErrorCode::Limit));
    }

    /// The advertising `ready` is the provider's facts: every rate in its
    /// order (the default first), the encoding, the lead in whole ms. An
    /// older server's bare `ready` parses to all three absent, and a field
    /// this revision does not know is ignored.
    #[test]
    fn ready_advertises_the_formats_and_the_lead() {
        let formats = [
            AudioFormat::pcm_s16le(16_000),
            AudioFormat::pcm_s16le(48_000),
            AudioFormat::pcm_s16le(24_000),
        ];
        assert_eq!(
            RelayEvent::ready(&formats, Duration::from_millis(7_250)).to_json(),
            r#"{"type":"ready","rates":[16000,48000,24000],"encoding":"pcm_s16le","lead_ms":7250}"#
        );
        let bare = RelayEvent::Ready {
            rates: None,
            encoding: None,
            lead_ms: None,
        };
        for frame in [
            r#"{"type":"ready"}"#,
            r#"{"type":"ready","a_later_field":[1,2]}"#,
        ] {
            assert_eq!(
                serde_json::from_str::<RelayEvent>(frame).expect("parses"),
                bare,
                "{frame}"
            );
        }
    }

    /// The canonical rendering is the fixture file's bytes, and the
    /// constant's.
    #[test]
    fn the_golden_rendering_is_the_fixture() {
        assert_eq!(RelayEvent::golden().len(), 11);
        assert_eq!(RelayEvent::golden_fixture(), GOLDEN_FIXTURE);
    }

    /// The text body bound: 4 KiB up to a bound of 640 characters (6 × 640 +
    /// 256 = 4096), then 6 bytes a character plus 256, and no overflow.
    #[test]
    fn the_tts_body_limit_is_4_kib_or_6_bytes_a_character_plus_256() {
        assert_eq!(tts_body_limit(0), 4_096);
        assert_eq!(tts_body_limit(TTS_MIN_TEXT_CHARS), 4_096);
        assert_eq!(tts_body_limit(640), 4_096);
        assert_eq!(tts_body_limit(641), 4_102);
        assert_eq!(tts_body_limit(2_000), 12_256);
        assert_eq!(tts_body_limit(usize::MAX), usize::MAX);
        assert_eq!(tts_body_limit(usize::MAX / 6), usize::MAX);
    }

    /// The constants a client relies on, literally: they are wire facts.
    #[test]
    fn the_wire_constants_are_revision_1s() {
        assert_eq!(END_FRAME, r#"{"type":"end"}"#);
        assert_eq!(TTS_MIN_TEXT_CHARS, 600);
        assert_eq!(TTS_MAX_CHARS_HEADER, "x-voice-tts-max-chars");
        assert_eq!(IDEMPOTENCY_KEY_HEADER, "idempotency-key");
        assert_eq!(ALLOWED_AUDIO_TYPES, ["audio/mpeg"]);
        assert_eq!((RATE_PARAM, ENCODING_PARAM), ("rate", "encoding"));
        assert_eq!(MAX_FRAME_BYTES, 65_536);
        assert_eq!(
            [
                close_code::DONE,
                close_code::GOING_AWAY,
                close_code::POLICY,
                close_code::ERROR,
                close_code::SESSION_LIMIT,
                close_code::SUPERSEDED,
                close_code::LIMIT,
                close_code::NO_STATUS_RECEIVED,
            ],
            [1000, 1001, 1008, 1011, 4000, 4001, 4002, 1005]
        );
        assert_eq!(
            [
                client_close_code::MIC_OFF,
                client_close_code::LEFT,
                client_close_code::PAUSED,
                client_close_code::IDLE,
                client_close_code::REPLACED,
                client_close_code::CLIENT_FAILURE,
            ],
            [1000, 4100, 4101, 4102, 4103, 4104]
        );
    }
}
