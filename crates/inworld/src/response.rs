//! The `2xx` answer: `{"audioContent": "<base64>", "usage": {…}}`.

use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use serde_json::{Map, Value};

use crate::error::{InworldError, MalformedReason};

/// What a synthesis produced: the audio, and what Inworld reported using.
///
/// `Debug` shows the audio's length, never its bytes.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Synthesis {
    /// The decoded `audioContent`: non-empty, within
    /// [`crate::InworldBounds::max_audio_bytes`], and MP3-shaped when the
    /// client's MP3 check is on.
    pub audio: Bytes,
    /// The response's `usage`, field by field.
    pub usage: Usage,
}

impl fmt::Debug for Synthesis {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Synthesis")
            .field("audio_bytes", &self.audio.len())
            .field("usage", &self.usage)
            .finish()
    }
}

/// The response's `usage`. A field that is absent or has another type is
/// `None`, and never fails the synthesis (the audio is what was paid for);
/// so is every field when `usage` itself is absent or not an object.
///
/// `Debug` shows `model_id` as its length, never the string: it is whatever
/// the provider wrote there, and could echo the request.
#[derive(Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Usage {
    /// `usage.processedCharactersCount`, when it is a non-negative integer.
    pub processed_characters_count: Option<u64>,
    /// `usage.modelId`, when it is a non-empty string.
    pub model_id: Option<String>,
}

impl fmt::Debug for Usage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Usage")
            .field(
                "processed_characters_count",
                &self.processed_characters_count,
            )
            .field("model_id", &self.model_id.as_deref().map(Redacted))
            .finish()
    }
}

/// A provider-supplied string in a `Debug`: `<N chars>`, never its content.
struct Redacted<'a>(&'a str);

impl fmt::Debug for Redacted<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<{} chars>", self.0.chars().count())
    }
}

/// The longest `audioContent` that can decode to `max_audio_bytes`: its
/// base64 length, a whole number of 4-character quanta. Longer is refused
/// before decoding. Because it rounds up to a quantum, base64 that fits may
/// still decode to up to two bytes more than the bound (2 MiB is 2 mod 3: one
/// more), which the check after decoding refuses.
pub(crate) const fn max_audio_base64_len(max_audio_bytes: usize) -> usize {
    max_audio_bytes.div_ceil(3).saturating_mul(4)
}

/// Whether `audio` opens the way an MP3 does: an ID3v2 tag, or an MPEG audio
/// frame sync (`0xFF`, then a byte whose top three bits are set). slaudio's
/// `mp3.py` sniff, exactly. A shape check, not a decode.
pub(crate) fn opens_like_mp3(audio: &[u8]) -> bool {
    audio.starts_with(b"ID3") || (audio.len() >= 2 && audio[0] == 0xFF && (audio[1] & 0xE0) == 0xE0)
}

fn malformed(reason: MalformedReason) -> InworldError {
    InworldError::Malformed(reason)
}

/// A `2xx` body, already within the response bound, as a [`Synthesis`]. Each
/// parse error is dropped unrendered: a serde_json message can quote the body.
pub(crate) fn decode(
    body: &[u8],
    max_audio_bytes: usize,
    mp3_check: bool,
) -> Result<Synthesis, InworldError> {
    let mut object: Map<String, Value> =
        serde_json::from_slice(body).map_err(|_| malformed(MalformedReason::NotJsonObject))?;
    let Some(Value::String(audio_content)) = object.remove("audioContent") else {
        return Err(malformed(MalformedReason::NoAudioContent));
    };
    if audio_content.len() > max_audio_base64_len(max_audio_bytes) {
        return Err(malformed(MalformedReason::AudioContentTooLong));
    }
    let audio = STANDARD
        .decode(audio_content.as_bytes())
        .map_err(|_| malformed(MalformedReason::NotBase64))?;
    if audio.is_empty() {
        return Err(malformed(MalformedReason::EmptyAudio));
    }
    if audio.len() > max_audio_bytes {
        return Err(malformed(MalformedReason::AudioTooLarge));
    }
    if mp3_check && !opens_like_mp3(&audio) {
        return Err(malformed(MalformedReason::NotMp3));
    }
    Ok(Synthesis {
        audio: Bytes::from(audio),
        usage: usage(object.remove("usage")),
    })
}

fn usage(value: Option<Value>) -> Usage {
    let Some(Value::Object(mut usage)) = value else {
        return Usage::default();
    };
    Usage {
        processed_characters_count: usage
            .get("processedCharactersCount")
            .and_then(Value::as_u64),
        model_id: match usage.remove("modelId") {
            Some(Value::String(model_id)) if !model_id.is_empty() => Some(model_id),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_MAX_AUDIO_BYTES, DEFAULT_MAX_RESPONSE_BYTES};

    fn mp3(len: usize) -> Vec<u8> {
        let mut audio = vec![0u8; len];
        audio[..2].copy_from_slice(&[0xFF, 0xF3]);
        audio
    }

    fn body_of(audio: &[u8]) -> String {
        format!(r#"{{"audioContent":"{}"}}"#, STANDARD.encode(audio))
    }

    fn reason(body: &str, mp3_check: bool) -> Option<MalformedReason> {
        match decode(body.as_bytes(), DEFAULT_MAX_AUDIO_BYTES, mp3_check) {
            Ok(_) => None,
            Err(InworldError::Malformed(reason)) => Some(reason),
            Err(other) => panic!("not Malformed: {other}"),
        }
    }

    /// The two audio checks, and where each bites. 2 MiB is 2 mod 3, so the
    /// pre-decode bound (2 MiB's base64 length) admits one byte more, which
    /// the post-decode check refuses; two bytes more no longer fit the
    /// length, and are refused before decoding.
    #[test]
    fn the_audio_bound_holds_before_and_after_decoding() {
        assert_eq!(DEFAULT_MAX_AUDIO_BYTES % 3, 2, "the premise");
        let bound = max_audio_base64_len(DEFAULT_MAX_AUDIO_BYTES);
        let encoded = |len: usize| STANDARD.encode(vec![0u8; len]).len();
        assert_eq!(encoded(DEFAULT_MAX_AUDIO_BYTES), bound);
        assert_eq!(encoded(DEFAULT_MAX_AUDIO_BYTES + 1), bound);
        assert!(encoded(DEFAULT_MAX_AUDIO_BYTES + 2) > bound);
        // And the largest allowed audio's body fits the response bound.
        assert!(body_of(&mp3(DEFAULT_MAX_AUDIO_BYTES + 2)).len() < DEFAULT_MAX_RESPONSE_BYTES);

        assert_eq!(reason(&body_of(&mp3(DEFAULT_MAX_AUDIO_BYTES)), true), None);
        assert_eq!(
            reason(&body_of(&mp3(DEFAULT_MAX_AUDIO_BYTES + 1)), true),
            Some(MalformedReason::AudioTooLarge)
        );
        assert_eq!(
            reason(&body_of(&mp3(DEFAULT_MAX_AUDIO_BYTES + 2)), true),
            Some(MalformedReason::AudioContentTooLong)
        );
    }

    /// Past the pre-decode bound nothing is decoded: junk one character too
    /// long is "too long", where decoding it would say "not base64". The
    /// control: the same junk AT the bound is decoded, and is not base64.
    #[test]
    fn an_overlong_audio_content_is_refused_before_decoding() {
        let bound = max_audio_base64_len(DEFAULT_MAX_AUDIO_BYTES);
        let junk = |len: usize| format!(r#"{{"audioContent":"{}"}}"#, "!".repeat(len));
        assert_eq!(
            reason(&junk(bound + 1), true),
            Some(MalformedReason::AudioContentTooLong)
        );
        assert_eq!(reason(&junk(bound), true), Some(MalformedReason::NotBase64));
    }

    /// The pre-decode bound never overflows, whatever bound a caller sets.
    #[test]
    fn the_base64_bound_saturates() {
        assert_eq!(max_audio_base64_len(usize::MAX), usize::MAX);
        assert_eq!(max_audio_base64_len(0), 0);
        assert_eq!(max_audio_base64_len(1), 4);
        assert_eq!(max_audio_base64_len(3), 4);
        assert_eq!(max_audio_base64_len(4), 8);
    }

    #[test]
    fn the_mp3_sniff_is_slaudios() {
        for accepted in [
            &b"ID3"[..],
            b"ID3\x04\x00",
            &[0xFF, 0xF3],
            &[0xFF, 0xFB, 0x90],
            &[0xFF, 0xE0],
        ] {
            assert!(opens_like_mp3(accepted), "{accepted:02x?}");
        }
        for refused in [
            &b"not mp3"[..],
            b"{\"error\":1}",
            b"",
            &[0xFF],
            &[0xFF, 0xDF],
            &[0xFE, 0xFF],
            b"ID",
            b"RIFF\x00\x00\x00\x00WAVE",
        ] {
            assert!(!opens_like_mp3(refused), "{refused:02x?}");
        }
    }

    #[test]
    fn every_malformed_body_has_its_reason() {
        let cases = [
            ("", MalformedReason::NotJsonObject),
            ("not json", MalformedReason::NotJsonObject),
            (r#"["AAAA"]"#, MalformedReason::NotJsonObject),
            (r#""AAAA""#, MalformedReason::NotJsonObject),
            (
                r#"{"audioContent":"//OQ"} trailing"#,
                MalformedReason::NotJsonObject,
            ),
            ("{}", MalformedReason::NoAudioContent),
            (r#"{"audioContent":null}"#, MalformedReason::NoAudioContent),
            (
                r#"{"audioContent":12345678}"#,
                MalformedReason::NoAudioContent,
            ),
            (
                r#"{"audioContent":["//OQ"]}"#,
                MalformedReason::NoAudioContent,
            ),
            (r#"{"audioContent":""}"#, MalformedReason::EmptyAudio),
            // Strict: unpadded, padded wrong, whitespace, URL-safe, stray
            // trailing bits.
            (r#"{"audioContent":"//OQAA"}"#, MalformedReason::NotBase64),
            (r#"{"audioContent":"//OQAA="}"#, MalformedReason::NotBase64),
            (
                r#"{"audioContent":"//OQ\nAAAA"}"#,
                MalformedReason::NotBase64,
            ),
            (r#"{"audioContent":"__OQ"}"#, MalformedReason::NotBase64),
            (r#"{"audioContent":"//O="}"#, MalformedReason::NotBase64),
            // Base64 of "not mp3".
            (
                r#"{"audioContent":"bm90IG1wMw=="}"#,
                MalformedReason::NotMp3,
            ),
        ];
        for (body, expected) in cases {
            assert_eq!(reason(body, true), Some(expected), "{body}");
        }
        // The same well-formed non-MP3 audio passes with the check off.
        assert_eq!(reason(r#"{"audioContent":"bm90IG1wMw=="}"#, false), None);
    }

    #[test]
    fn usage_is_read_field_by_field_and_never_fails_the_synthesis() {
        let audio = STANDARD.encode(mp3(16));
        let usage_of = |usage: &str| {
            let body = format!(r#"{{"audioContent":"{audio}"{usage}}}"#);
            decode(body.as_bytes(), DEFAULT_MAX_AUDIO_BYTES, true)
                .expect("the audio is fine")
                .usage
        };
        assert_eq!(usage_of(""), Usage::default());
        assert_eq!(usage_of(r#","usage":null"#), Usage::default());
        assert_eq!(usage_of(r#","usage":[1,2]"#), Usage::default());
        assert_eq!(
            usage_of(r#","usage":{"processedCharactersCount":12,"modelId":"inworld-tts-2-flash"}"#),
            Usage {
                processed_characters_count: Some(12),
                model_id: Some("inworld-tts-2-flash".to_string()),
            }
        );
        for ill_typed in [
            r#","usage":{"processedCharactersCount":"12","modelId":5}"#,
            r#","usage":{"processedCharactersCount":-1,"modelId":""}"#,
            r#","usage":{"processedCharactersCount":1.5,"modelId":null}"#,
            r#","usage":{"processedCharactersCount":true}"#,
        ] {
            assert_eq!(usage_of(ill_typed), Usage::default(), "{ill_typed}");
        }
    }

    #[test]
    fn debug_shows_the_audios_length_not_its_bytes() {
        let synthesis = Synthesis {
            audio: Bytes::from_static(b"ID3CANARY"),
            usage: Usage::default(),
        };
        let rendered = format!("{synthesis:?}");
        assert!(!rendered.contains("CANARY"), "{rendered}");
        assert!(rendered.contains("audio_bytes: 9"), "{rendered}");
    }

    /// The model id is kept as given, and shown only as its length.
    #[test]
    fn debug_shows_the_model_ids_length_not_the_model_id() {
        let usage = Usage {
            processed_characters_count: Some(12),
            model_id: Some("CANARY-model".to_string()),
        };
        assert_eq!(usage.model_id.as_deref(), Some("CANARY-model"));
        let rendered = format!("{usage:?} {usage:#?}");
        assert!(!rendered.contains("CANARY"), "{rendered}");
        assert_eq!(
            format!("{usage:?}"),
            "Usage { processed_characters_count: Some(12), model_id: Some(<12 chars>) }"
        );
        assert_eq!(
            format!("{:?}", Usage::default()),
            "Usage { processed_characters_count: None, model_id: None }"
        );
    }
}
