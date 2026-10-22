//! The synthesis request: what [`crate::InworldClient::synthesize`] sends.

use std::fmt;

use serde::Serialize;

/// One synthesis: the text, the voice, the model, and the audio wanted.
///
/// Sent as exactly
/// `{text, voiceId, modelId, language?, deliveryMode?, audioConfig}`, every
/// unset option omitted (never `null`). The strings are borrowed: nothing is
/// copied until the body is serialized.
///
/// `Debug` shows the text's length, never the text.
#[derive(Clone, Copy)]
pub struct SynthesisRequest<'a> {
    pub(crate) text: &'a str,
    pub(crate) voice_id: &'a str,
    pub(crate) model_id: &'a str,
    pub(crate) language: Option<&'a str>,
    pub(crate) delivery_mode: Option<&'a str>,
    pub(crate) audio_config: AudioConfig<'a>,
}

impl<'a> SynthesisRequest<'a> {
    /// `text` in `voice_id` by `model_id` (say `inworld-tts-2-flash`), as
    /// `audio_config` says.
    #[must_use]
    pub const fn new(
        text: &'a str,
        voice_id: &'a str,
        model_id: &'a str,
        audio_config: AudioConfig<'a>,
    ) -> SynthesisRequest<'a> {
        SynthesisRequest {
            text,
            voice_id,
            model_id,
            language: None,
            delivery_mode: None,
            audio_config,
        }
    }

    /// `language`, sent as given (a locale such as `en-US`). Unset, it is
    /// omitted.
    #[must_use]
    pub const fn with_language(mut self, language: &'a str) -> SynthesisRequest<'a> {
        self.language = Some(language);
        self
    }

    /// `deliveryMode`, sent as given (say `BALANCED`). Unset, it is omitted.
    #[must_use]
    pub const fn with_delivery_mode(mut self, delivery_mode: &'a str) -> SynthesisRequest<'a> {
        self.delivery_mode = Some(delivery_mode);
        self
    }

    /// The JSON body, in the order above.
    pub(crate) fn wire_body(&self) -> Vec<u8> {
        serde_json::to_vec(&WireRequest {
            text: self.text,
            voice_id: self.voice_id,
            model_id: self.model_id,
            language: self.language,
            delivery_mode: self.delivery_mode,
            audio_config: WireAudioConfig {
                audio_encoding: self.audio_config.audio_encoding,
                bit_rate: self.audio_config.bit_rate,
                speaking_rate: self.audio_config.speaking_rate,
                sample_rate_hertz: self.audio_config.sample_rate_hertz,
            },
        })
        // Strings, integers and a float serialize infallibly (a non-finite
        // float would be `null`, which `synthesize` refuses before this).
        .expect("a synthesis request always serializes")
    }
}

/// The text is the caller's content: only its length is shown.
impl fmt::Debug for SynthesisRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SynthesisRequest")
            .field("text_chars", &self.text.chars().count())
            .field("voice_id", &self.voice_id)
            .field("model_id", &self.model_id)
            .field("language", &self.language)
            .field("delivery_mode", &self.delivery_mode)
            .field("audio_config", &self.audio_config)
            .finish()
    }
}

/// The `audioConfig` object: the encoding, and the optional bit rate,
/// speaking rate and sample rate, each omitted when unset.
///
/// The encoding is sent as given (`MP3`, `LINEAR16`, `OGG_OPUS`, …). The
/// client's MP3 check (on by default) is blind to it: turn the check off
/// ([`crate::InworldClientBuilder::mp3_check`]) for any other encoding.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AudioConfig<'a> {
    pub(crate) audio_encoding: &'a str,
    pub(crate) bit_rate: Option<u32>,
    pub(crate) speaking_rate: Option<f64>,
    pub(crate) sample_rate_hertz: Option<u32>,
}

impl<'a> AudioConfig<'a> {
    /// `audioEncoding` alone.
    #[must_use]
    pub const fn new(audio_encoding: &'a str) -> AudioConfig<'a> {
        AudioConfig {
            audio_encoding,
            bit_rate: None,
            speaking_rate: None,
            sample_rate_hertz: None,
        }
    }

    /// `bitRate`, in bits per second.
    #[must_use]
    pub const fn with_bit_rate(mut self, bit_rate: u32) -> AudioConfig<'a> {
        self.bit_rate = Some(bit_rate);
        self
    }

    /// `speakingRate`. Not range-checked here (Inworld answers an out-of-range
    /// rate with a `4xx`); a NaN or infinite rate is
    /// [`crate::InworldError::SpeakingRateNotFinite`], and nothing is sent.
    #[must_use]
    pub const fn with_speaking_rate(mut self, speaking_rate: f64) -> AudioConfig<'a> {
        self.speaking_rate = Some(speaking_rate);
        self
    }

    /// `sampleRateHertz`.
    #[must_use]
    pub const fn with_sample_rate_hertz(mut self, sample_rate_hertz: u32) -> AudioConfig<'a> {
        self.sample_rate_hertz = Some(sample_rate_hertz);
        self
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireRequest<'a> {
    text: &'a str,
    voice_id: &'a str,
    model_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    language: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery_mode: Option<&'a str>,
    audio_config: WireAudioConfig<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireAudioConfig<'a> {
    audio_encoding: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    bit_rate: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    speaking_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sample_rate_hertz: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(request: &SynthesisRequest<'_>) -> String {
        String::from_utf8(request.wire_body()).expect("JSON is UTF-8")
    }

    #[test]
    fn every_unset_option_is_omitted() {
        let request = SynthesisRequest::new(
            "Hello there.",
            "Hazel",
            "inworld-tts-2-flash",
            AudioConfig::new("MP3"),
        );
        assert_eq!(
            body(&request),
            r#"{"text":"Hello there.","voiceId":"Hazel","modelId":"inworld-tts-2-flash","audioConfig":{"audioEncoding":"MP3"}}"#
        );
    }

    /// Every field, in the pinned order.
    #[test]
    fn every_set_option_is_sent_in_the_pinned_order() {
        let request = SynthesisRequest::new(
            "Hello there.",
            "Hazel",
            "inworld-tts-2-flash",
            AudioConfig::new("MP3")
                .with_sample_rate_hertz(24_000)
                .with_speaking_rate(1.0)
                .with_bit_rate(64_000),
        )
        .with_delivery_mode("BALANCED")
        .with_language("en-US");
        assert_eq!(
            body(&request),
            r#"{"text":"Hello there.","voiceId":"Hazel","modelId":"inworld-tts-2-flash","language":"en-US","deliveryMode":"BALANCED","audioConfig":{"audioEncoding":"MP3","bitRate":64000,"speakingRate":1.0,"sampleRateHertz":24000}}"#
        );
    }

    #[test]
    fn debug_shows_the_texts_length_not_the_text() {
        let request = SynthesisRequest::new(
            "CANARY text",
            "Hazel",
            "inworld-tts-2-flash",
            AudioConfig::new("MP3"),
        );
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("CANARY"), "{rendered}");
        assert!(rendered.contains("text_chars: 11"), "{rendered}");
    }
}
