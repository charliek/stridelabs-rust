//! The usage seam: what the voice flows tell the app they consumed, for its
//! own ledger.
//!
//! The crate measures and the app records. Text to speech reports the
//! characters a FRESH charge admitted (a replayed verdict was counted by the
//! run that charged it), at the instant the charge was decided, whatever the
//! synthesis does next: the charge stands either way. Speech to text reports
//! a session's relay-measured audio when it ends, FIRST, before any closing
//! I/O, so a shutdown's drain cannot lose it.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Where the voice flows report usage: the app's ledger.
pub trait UsageSink: Send + Sync + 'static {
    /// Fire and forget: returns at once, never awaits, never blocks on I/O
    /// (an app that writes somewhere spawns the write).
    fn record(&self, user: Uuid, metric: VoiceMetric, quantity: u64, at: DateTime<Utc>);
}

/// What a quantity counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VoiceMetric {
    /// Text-to-speech characters a fresh charge admitted (Unicode scalar
    /// values of the trimmed text).
    TtsCharacters,
    /// Milliseconds of audio a speech-to-text session relayed.
    SttMilliseconds,
}

impl VoiceMetric {
    /// `tts_characters` or `stt_milliseconds`: a ledger's metric name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            VoiceMetric::TtsCharacters => "tts_characters",
            VoiceMetric::SttMilliseconds => "stt_milliseconds",
        }
    }
}

/// A sink that records nothing: for an app with no ledger.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoUsage;

impl UsageSink for NoUsage {
    fn record(&self, _: Uuid, _: VoiceMetric, _: u64, _: DateTime<Utc>) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_metric_names_are_the_ledgers() {
        assert_eq!(VoiceMetric::TtsCharacters.as_str(), "tts_characters");
        assert_eq!(VoiceMetric::SttMilliseconds.as_str(), "stt_milliseconds");
    }
}
