//! Speech to text, provider side: the [`SttProvider`] a relay session dials
//! and the [`SttSession`] it streams the client's audio through.
//!
//! The core names no provider. An adapter, behind a feature of its own, maps
//! one provider's wire onto these two traits; the relay (behind `axum`) is
//! their one caller; the scripted adapter (`testing::ScriptedStt`, behind
//! `test-support`) is what the core's own suites run against. Every rule
//! below is one an adapter must keep, or one the core keeps for it, and the
//! scripted contract cases prove the core's side.
//!
//! # What the events mean
//!
//! | [`SttEvent`] | the client hears | the rule |
//! |---|---|---|
//! | `SpeechStart` | `speech_start` | the speaker started |
//! | `Partial(text)` | `partial` | OPTIONAL, and CUMULATIVE: the whole text of the current turn so far, each replacing the last. An adapter whose provider sends finalized segments plus interim results builds the cumulative text itself; one whose provider has no interim results yields none |
//! | `SpeechEnd` | `speech_end` | the speaker stopped (the turn may still be completing) |
//! | `EndOfTurn(text)` | `end_of_turn` | the turn's final text; the relay counts a turn on it |
//! | `Ignored` | nothing | one provider DATA message that maps to no event; the relay counts it |
//! | `Finished` | the close | the provider ended the session normally (below) |
//!
//! - **The core relays events in the order yielded**, none reordered or
//!   coalesced.
//! - **Endpointing is the adapter's job.** It delivers `SpeechStart`,
//!   `SpeechEnd` and `EndOfTurn` for every turn, synthesising them from the
//!   provider's finals, its end-of-speech flags, or a voice activity detector
//!   of its own when the provider has none. A provider that allows none of
//!   these is unsupported.
//! - **Turn order:** every event of turn n comes before ANY event of turn
//!   n + 1 (`EndOfTurn(n)` before `SpeechStart(n + 1)`). An adapter whose
//!   provider answers late holds all of turn n + 1's events until it has turn
//!   n's text.
//! - **Protocol-level frames** (a provider's ping, pong or binary frame) are
//!   absorbed inside the adapter and yield nothing; `Ignored` is for data
//!   messages only.
//!
//! # How a session ends
//!
//! - **`Finished`** is `1000` (done) only after the relay sent
//!   [`SttSession::end_input`]; before that it is the provider failing, cause
//!   `closed`.
//! - **Finals before `Finished`:** on the client's `end` path, every final
//!   transcript the provider flushes after `end_input` is yielded BEFORE
//!   `Finished` (or the end deadline), and the client gets it before its
//!   `1000`. Only that path: a shutdown, a takeover, a spent budget or a
//!   provider failure tears the session down, and `close` discards whatever
//!   the provider still sends (the client keeps its last partial).
//! - **The stream's end (`None`)** is a drop: `error{provider}`, `1011`.
//! - **`Err(SttError)`** is the provider's own failure: `error{provider}`,
//!   `1011`, its class the session-end line's cause. The session is over: the
//!   relay never polls the stream again.
//!
//! # The provider's facts
//!
//! - **[`SttProvider::configured`]** is "the key is set and the endpoint was
//!   accepted"; `false` is the configuration `503`, answered before the
//!   upgrade.
//! - **[`SttProvider::formats`]** is non-empty, PCM s16le only, its rates
//!   distinct, within [`MIN_SAMPLE_RATE`]..=[`MAX_SAMPLE_RATE`], and holding
//!   BOTH of [`PROTOCOL_DEFAULT_RATES`]; the first is the default `rate`. The
//!   client sees them as `ready`'s `rates`.
//! - **[`SttProvider::pacing_lead`]** is how far ahead of real time, since
//!   `ready`, the client's audio may run: the relay enforces it (`1008
//!   pacing`) and advertises it as `ready`'s `lead_ms`. At least
//!   [`MIN_PACING_LEAD`]. It is an allowance, not a send-rate limiter: a
//!   provider that must be fed slower than the installed clients' 3 s
//!   pre-`ready` burst allows is unsupported in revision 1 of the protocol.
//! - `Voice::new` refuses a provider that breaks any of these
//!   (`VoiceSetupError`).
//!
//! # The session's mechanics
//!
//! - **Frames:** the core forwards each client audio frame as received: an
//!   even number of bytes, 1 to 64 KiB (an empty frame is skipped and an odd
//!   one refused before the adapter sees it).
//! - **Open:** [`SttProvider::open`] dials, handshakes and waits for the
//!   provider's own ready, in ONE future, which the relay creates once and
//!   pins. The relay's `deadline` is the only bound: an adapter applies no
//!   deadline of its own, so an open that times out always reads
//!   `open_timeout`. A failure is [`OpenLabel::Dial`] (the provider could not
//!   be reached or handshaken) or [`OpenLabel::Refused`] (it was reached and
//!   said no), with a fixed class.
//! - **Cancel safety:** the stream is polled from a `select!` and its
//!   `next()` future is dropped whenever another arm wins; no event may be
//!   lost by that (the state lives in the session, not in the future).
//! - **Where the relay drops a future:** exactly four places: the `open`
//!   future (a shutdown, a takeover, the client's `end`, close or drop, or
//!   its deadline); a write ([`SttSession::send_audio`],
//!   [`SttSession::end_input`]) when its bound fires; [`SttSession::close`]
//!   when its bound fires; and the stream's `next()` whenever another arm
//!   wins. A dropped future leaves the session droppable, and `close` still
//!   works, without blocking. Nothing preempts a write in progress: it is
//!   awaited under its bound, so a shutdown or a deadline takes effect once
//!   the write returned or hit that bound.
//! - **Interleaving:** the relay calls `send_audio` and `end_input` only
//!   BETWEEN polls of the stream, never during one (the `&mut` borrow forbids
//!   it); an adapter holds no read state across that boundary.
//! - **Write completion:** `send_audio` and `end_input` resolve once the frame
//!   was written AND flushed to the transport. A peer that stops reading makes
//!   them wait (the transport's bounded buffer); a write never waits on the
//!   read side. An adapter may not complete a write on enqueue: the end
//!   deadline starts when `end_input` returns, and a queue would be lost at
//!   teardown. The relay bounds each write (cause `send: timed out`).
//! - **A failed write** is the provider's failure, cause `send: <class>`; the
//!   adapter marks itself finished, so `close` only flushes.
//! - **Keepalive:** an adapter whose provider needs one sends it from its own
//!   state: a timer it polls inside `poll_next` (the relay polls the stream
//!   continuously), or piggy-backed on `send_audio`. The relay calls nothing
//!   extra.
//! - **No starvation:** an adapter must not yield an unbounded run of ready
//!   items (its event rate is bounded by the audio it is sent), and its
//!   `poll_next` absorbs at most [`MAX_SILENT_FRAMES_PER_POLL`] provider
//!   frames that yield no item before it wakes itself and returns `Pending`.
//!   The relay additionally polls the client after a run of provider events,
//!   a guard an adapter's breach cannot defeat.
//! - **End of input:** `end_input` tells the provider no more audio is
//!   coming. The relay then waits for `Finished` (or a failure) until its end
//!   deadline, which starts when `end_input` RETURNED and which it treats as
//!   done.
//! - **Close:** `close(end_sent)` ends the provider side: on a transport still
//!   open, send end-of-input unless `end_sent`, a normal close, then read to
//!   the peer's close; on one already finished, flush the close reply. The
//!   relay bounds it and runs it beside the lease's release.
//! - **Fixed error classes:** [`SttError`] and [`SttOpenError`] carry an
//!   [`ErrorClass`], never a URL, a key, a frame, a transcript or the
//!   provider's own text; the class is the session-end line's cause, and
//!   nothing else of the provider's is logged.
//! - **Billing:** speech to text is charged in relay-measured audio time
//!   (`lease::audio_ms` over [`AudioFormat::bytes_per_second`]), never in a
//!   provider's unit. A provider that bills otherwise is the app's cost model.

use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ErrorClass;

/// Revision 1's minimum pacing lead. The installed clients send a 3 s burst
/// of audio buffered before `ready` and then lead real time by 4 s, both
/// fixed, against the 5 s the relay allowed before the protocol advertised a
/// lead: so no provider may advertise less.
pub const MIN_PACING_LEAD: Duration = Duration::from_millis(5_000);

/// The lowest sample rate a provider may offer, in Hz.
pub const MIN_SAMPLE_RATE: u32 = 8_000;

/// The highest sample rate a provider may offer, in Hz.
pub const MAX_SAMPLE_RATE: u32 = 48_000;

/// The rates every provider must take, revision 1 requiring BOTH. An
/// installed client opens at 24 kHz and moves to 16 kHz only when its
/// MICROPHONE refuses 24 kHz, never after the upgrade's `422`, so a server
/// missing either rate strands some installed devices.
pub const PROTOCOL_DEFAULT_RATES: [u32; 2] = [24_000, 16_000];

/// The most provider frames that yield no item (a ping, a pong, a binary
/// frame) an adapter's `poll_next` may absorb in one poll before it wakes
/// itself and returns `Pending`: what keeps a flood of such frames from
/// holding the relay's task.
pub const MAX_SILENT_FRAMES_PER_POLL: usize = 32;

/// How the client's audio is encoded: the session's, and `ready`'s
/// `encoding`. Revision 1 has one ("a PCM-only core"); another is an
/// additive protocol change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Encoding {
    /// 16-bit little-endian signed PCM, mono.
    #[serde(rename = "pcm_s16le")]
    PcmS16le,
}

impl Encoding {
    /// The wire name: `ready`'s `encoding` and the upgrade's `encoding`
    /// parameter.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Encoding::PcmS16le => "pcm_s16le",
        }
    }

    /// The encoding whose wire name is exactly `value`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Encoding> {
        [Encoding::PcmS16le]
            .into_iter()
            .find(|encoding| encoding.wire_name() == value)
    }

    /// The bytes one sample takes.
    #[must_use]
    pub const fn bytes_per_sample(self) -> u64 {
        match self {
            Encoding::PcmS16le => 2,
        }
    }
}

/// One audio format a provider takes: an encoding at a sample rate, mono.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AudioFormat {
    /// How the audio is encoded.
    pub encoding: Encoding,
    /// Samples per second, in Hz.
    pub sample_rate: u32,
}

impl AudioFormat {
    /// 16-bit little-endian signed PCM, mono, at `sample_rate` Hz.
    #[must_use]
    pub const fn pcm_s16le(sample_rate: u32) -> AudioFormat {
        AudioFormat {
            encoding: Encoding::PcmS16le,
            sample_rate,
        }
    }

    /// The bytes one second of this audio takes: what the pacing rule and
    /// the metered audio time are computed from.
    #[must_use]
    pub const fn bytes_per_second(self) -> u64 {
        self.encoding.bytes_per_sample() * self.sample_rate as u64
    }
}

/// A speech-to-text provider, as a relay session uses it (module docs: the
/// facts it states and the rules `Voice::new` holds them to).
pub trait SttProvider: Send + Sync + 'static {
    /// One open session's type.
    type Session: SttSession;

    /// Whether a session can be opened at all: the key is set and the
    /// endpoint was accepted. `false` is the configuration `503`.
    fn configured(&self) -> bool;

    /// The formats the provider takes, the default first; advertised as
    /// `ready`'s `rates`.
    fn formats(&self) -> &[AudioFormat];

    /// How far ahead of real time the client's audio may run; enforced by
    /// the relay and advertised as `ready`'s `lead_ms`. At least
    /// [`MIN_PACING_LEAD`].
    fn pacing_lead(&self) -> Duration;

    /// Dial, handshake and wait for the provider's own ready, in one future
    /// (module docs, "Open"). `deadline` is the relay's bound, which the
    /// relay applies: the adapter applies none of its own.
    fn open(
        &self,
        format: AudioFormat,
        deadline: tokio::time::Instant,
    ) -> impl Future<Output = Result<Self::Session, SttOpenError>> + Send;
}

/// One open provider session: a stream of what the provider heard, and the
/// three calls that feed and end it (module docs, "The session's
/// mechanics").
pub trait SttSession:
    futures_core::Stream<Item = Result<SttEvent, SttError>> + Unpin + Send + 'static
{
    /// Send one frame of the client's audio, as received. Resolves once it
    /// was written and flushed; never on enqueue.
    fn send_audio(
        &mut self,
        frame: bytes::Bytes,
    ) -> impl Future<Output = Result<(), SttError>> + Send;

    /// Tell the provider no more audio is coming. Resolves once that was
    /// written and flushed: the relay's end deadline starts then.
    fn end_input(&mut self) -> impl Future<Output = Result<(), SttError>> + Send;

    /// End the provider side (module docs, "Close"); `end_sent` says whether
    /// `end_input` already went out. The relay bounds it.
    fn close(self, end_sent: bool) -> impl Future<Output = ()> + Send;
}

/// What a provider heard, normalised (module docs' table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SttEvent {
    /// The speaker started.
    SpeechStart,
    /// The current turn's whole text so far (cumulative).
    Partial(String),
    /// The speaker stopped; the turn may still be completing.
    SpeechEnd,
    /// The turn's final text.
    EndOfTurn(String),
    /// One provider data message that maps to no event.
    Ignored,
    /// The provider ended the session normally.
    Finished,
}

/// Why a session did not open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SttOpenError {
    /// Which way it failed.
    pub label: OpenLabel,
    /// The provider's failure, as a fixed class.
    pub class: ErrorClass,
}

/// Which way an open failed: the first word of the session-end line's cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenLabel {
    /// Not open before the relay's deadline (the relay's own label: an
    /// adapter never returns it).
    OpenTimeout,
    /// The provider could not be reached, or the handshake failed.
    Dial,
    /// The provider was reached and refused the session.
    Refused,
}

impl OpenLabel {
    /// `open_timeout`, `dial` or `refused`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            OpenLabel::OpenTimeout => "open_timeout",
            OpenLabel::Dial => "dial",
            OpenLabel::Refused => "refused",
        }
    }
}

/// A provider's failure during a session, as a fixed class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SttError {
    /// The class: the session-end line's cause.
    pub class: ErrorClass,
}

impl SttError {
    /// A failure of the fixed class `class`.
    #[must_use]
    pub const fn fixed(class: &'static str) -> SttError {
        SttError {
            class: ErrorClass::fixed(class),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The protocol's constants are revision 1's: both default rates, the
    /// 5 s lead, the 8–48 kHz range, the silent-frame bound.
    #[test]
    fn the_revision_1_constants_are_the_protocols() {
        assert_eq!(PROTOCOL_DEFAULT_RATES, [24_000, 16_000]);
        assert_eq!(MIN_PACING_LEAD, Duration::from_secs(5));
        assert_eq!((MIN_SAMPLE_RATE, MAX_SAMPLE_RATE), (8_000, 48_000));
        assert_eq!(MAX_SILENT_FRAMES_PER_POLL, 32);
    }

    /// PCM s16le is two bytes a sample, mono: 48,000 bytes a second at
    /// 24 kHz, 32,000 at 16 kHz.
    #[test]
    fn pcm_s16le_is_two_bytes_a_sample() {
        assert_eq!(Encoding::PcmS16le.bytes_per_sample(), 2);
        assert_eq!(AudioFormat::pcm_s16le(24_000).bytes_per_second(), 48_000);
        assert_eq!(AudioFormat::pcm_s16le(16_000).bytes_per_second(), 32_000);
        assert_eq!(
            AudioFormat::pcm_s16le(16_000),
            AudioFormat {
                encoding: Encoding::PcmS16le,
                sample_rate: 16_000
            }
        );
    }

    /// The encoding's one wire name, matched exactly; serde writes the same
    /// string.
    #[test]
    fn the_encoding_parses_by_its_exact_wire_name() {
        assert_eq!(Encoding::PcmS16le.wire_name(), "pcm_s16le");
        assert_eq!(Encoding::parse("pcm_s16le"), Some(Encoding::PcmS16le));
        for other in ["", "PCM_S16LE", "pcm_s16le ", "pcm", "opus"] {
            assert_eq!(Encoding::parse(other), None, "{other:?}");
        }
        assert_eq!(
            serde_json::to_string(&Encoding::PcmS16le).expect("serializes"),
            r#""pcm_s16le""#
        );
    }

    #[test]
    fn the_open_labels_are_the_causes_first_words() {
        assert_eq!(OpenLabel::OpenTimeout.as_str(), "open_timeout");
        assert_eq!(OpenLabel::Dial.as_str(), "dial");
        assert_eq!(OpenLabel::Refused.as_str(), "refused");
        assert_eq!(SttError::fixed("closed").class.as_str(), "closed");
    }
}
