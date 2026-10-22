//! The `2xx` answer: `{"audioContent": "<base64>", "usage": {…}}`.

use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

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
/// frame sync (`0xFF`, then a byte whose top three bits are set). Exactly
/// lumen 001 §6.3's expression, so a 2-byte frame sync passes (slaudio's
/// Python `mp3.py` also refuses anything under 3 bytes; this does not). A
/// shape check, not a decode.
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
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let response = WireResponse
        .deserialize(&mut deserializer)
        .and_then(|response| deserializer.end().map(|()| response))
        .map_err(|_| malformed(MalformedReason::NotJsonObject))?;
    let Some(audio_content) = response.audio_content else {
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
        usage: response.usage,
    })
}

/// What the crate reads of a `2xx` body: `audioContent`, when it is a string,
/// and `usage`, field by field.
///
/// Read by [`WireResponse`], a seed whose visitor, not a derive, decides what
/// is built, so that the response bound is also the memory bound: the top
/// level must be a JSON object (a derived struct would also take an array),
/// and every other field, and any field of another type than the one read
/// (an object where the string was, say), is skipped with [`IgnoredAny`],
/// which builds nothing. A `serde_json::Value` of the body would cost about
/// 32 bytes per JSON value: some 64 MiB for a 4 MiB array of zeros. A key
/// that repeats keeps its last value, as a `serde_json::Map` (and Python's
/// `json`) would.
struct Wire {
    audio_content: Option<String>,
    usage: Usage,
}

/// The seed that reads a [`Wire`] from the top-level object.
struct WireResponse;

impl<'de> DeserializeSeed<'de> for WireResponse {
    type Value = Wire;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Wire, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for WireResponse {
    type Value = Wire;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Wire, A::Error> {
        let mut wire = Wire {
            audio_content: None,
            usage: Usage::default(),
        };
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::AudioContent => {
                    wire.audio_content = match map.next_value_seed(Pick::String)? {
                        Picked::String(audio_content) => Some(audio_content),
                        _ => None,
                    };
                }
                Key::Usage => {
                    wire.usage = match map.next_value_seed(Pick::Usage)? {
                        Picked::Usage(usage) => usage,
                        _ => Usage::default(),
                    };
                }
                Key::ProcessedCharactersCount | Key::ModelId | Key::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(wire)
    }
}

/// A field name the crate reads, at either level; any other is [`Key::Other`].
enum Key {
    AudioContent,
    Usage,
    ProcessedCharactersCount,
    ModelId,
    Other,
}

impl<'de> de::Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Key, D::Error> {
        struct KeyVisitor;

        impl Visitor<'_> for KeyVisitor {
            type Value = Key;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a field name")
            }

            fn visit_str<E: de::Error>(self, name: &str) -> Result<Key, E> {
                Ok(match name {
                    "audioContent" => Key::AudioContent,
                    "usage" => Key::Usage,
                    "processedCharactersCount" => Key::ProcessedCharactersCount,
                    "modelId" => Key::ModelId,
                    _ => Key::Other,
                })
            }
        }

        deserializer.deserialize_identifier(KeyVisitor)
    }
}

/// What a field is read as. Any other type is drained ([`IgnoredAny`] for a
/// nested array or object) and is [`Picked::Nothing`].
#[derive(Clone, Copy)]
enum Pick {
    /// A string, kept whole.
    String,
    /// A non-negative integer.
    Count,
    /// The `usage` object.
    Usage,
}

enum Picked {
    Nothing,
    String(String),
    Count(u64),
    Usage(Usage),
}

impl<'de> DeserializeSeed<'de> for Pick {
    type Value = Picked;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Picked, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Pick {
    type Value = Picked;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Picked, E> {
        Ok(Picked::Nothing)
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Picked, E> {
        Ok(match (self, u64::try_from(value)) {
            (Pick::Count, Ok(count)) => Picked::Count(count),
            _ => Picked::Nothing,
        })
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Picked, E> {
        Ok(match self {
            Pick::Count => Picked::Count(value),
            _ => Picked::Nothing,
        })
    }

    /// A float is never a count, `5.0` included (Python's `int` check).
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Picked, E> {
        Ok(Picked::Nothing)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Picked, E> {
        Ok(match self {
            Pick::String => Picked::String(value.to_owned()),
            _ => Picked::Nothing,
        })
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Picked, E> {
        Ok(match self {
            Pick::String => Picked::String(value),
            _ => Picked::Nothing,
        })
    }

    fn visit_unit<E: de::Error>(self) -> Result<Picked, E> {
        Ok(Picked::Nothing)
    }

    fn visit_none<E: de::Error>(self) -> Result<Picked, E> {
        Ok(Picked::Nothing)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Picked, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Picked::Nothing)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Picked, A::Error> {
        let Pick::Usage = self else {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            return Ok(Picked::Nothing);
        };
        let mut usage = Usage::default();
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::ProcessedCharactersCount => {
                    usage.processed_characters_count = match map.next_value_seed(Pick::Count)? {
                        Picked::Count(count) => Some(count),
                        _ => None,
                    };
                }
                Key::ModelId => {
                    usage.model_id = match map.next_value_seed(Pick::String)? {
                        Picked::String(model_id) if !model_id.is_empty() => Some(model_id),
                        _ => None,
                    };
                }
                Key::AudioContent | Key::Usage | Key::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Picked::Usage(usage))
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

    /// Exactly §6.3's expression: a 2-byte frame sync passes (slaudio's
    /// Python `mp3.py` would refuse it, and anything else under 3 bytes);
    /// one byte, or a 2-byte `ID`, does not.
    #[test]
    fn the_mp3_sniff_is_the_specs_expression() {
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
        // Through the decode, the check on: a 2-byte frame-sync clip is
        // audio; a 1-byte `0xFF` is not MP3, and only zero bytes are empty.
        let two = decode(br#"{"audioContent":"//M="}"#, DEFAULT_MAX_AUDIO_BYTES, true)
            .expect("a 2-byte frame sync is MP3-shaped");
        assert_eq!(two.audio.as_ref(), &[0xFF, 0xF3]);
        assert_eq!(
            reason(r#"{"audioContent":"/w=="}"#, true),
            Some(MalformedReason::NotMp3)
        );
        assert_eq!(
            reason(r#"{"audioContent":""}"#, false),
            Some(MalformedReason::EmptyAudio)
        );
        assert_eq!(reason(r#"{"audioContent":"/w=="}"#, false), None);
    }

    /// Only `audioContent` and `usage` are read; everything else, however
    /// large or deep, is skipped, and a field of another type is skipped too.
    /// Escapes in keys and values are JSON's, and a repeated key keeps its
    /// last value.
    #[test]
    fn the_body_is_read_field_by_field_and_the_rest_is_skipped() {
        let decoded = |body: &str| decode(body.as_bytes(), DEFAULT_MAX_AUDIO_BYTES, true);
        let zeros = format!("[{}0]", "0,".repeat(100_000));
        let nested = r#"{"a":[1,{"b":[true,null,"xA"]}],"c":{"d":{}}}"#;
        for body in [
            format!(r#"{{"x":{zeros},"audioContent":"//OQ","y":{nested}}}"#),
            format!(r#"{{"audioContent":"//OQ","usage":{{"x":{zeros},"modelId":"m"}}}}"#),
            // An escaped key and an escaped `/` in the base64.
            r#"{"audioContent":"\/\/OQ"}"#.to_string(),
            // The last of a repeated key wins, both ways.
            r#"{"audioContent":5,"audioContent":"//OQ"}"#.to_string(),
        ] {
            let synthesis = decoded(&body).expect("audio");
            assert_eq!(synthesis.audio.as_ref(), &[0xFF, 0xF3, 0x90], "{body}");
        }
        assert_eq!(
            reason(r#"{"audioContent":"//OQ","audioContent":{"a":1}}"#, true),
            Some(MalformedReason::NoAudioContent)
        );
        assert_eq!(
            reason(r#"{"audioContent":{"audioContent":"//OQ"}}"#, true),
            Some(MalformedReason::NoAudioContent)
        );
        // `usage` that repeats, and fields of another type inside it.
        let usage = decoded(
            r#"{"audioContent":"//OQ","usage":{"modelId":"a"},"usage":{"modelId":"b","processedCharactersCount":{"n":1}}}"#,
        )
        .expect("audio")
        .usage;
        assert_eq!(usage.model_id.as_deref(), Some("b"));
        assert_eq!(usage.processed_characters_count, None);
        // serde_json skips a value iteratively, a byte of state per level of
        // nesting: a skipped field nested far past its recursion limit costs
        // no stack, and memory within the body's own size.
        let deep = format!(
            r#"{{"audioContent":"//OQ","x":{}{}}}"#,
            "[".repeat(100_000),
            "]".repeat(100_000)
        );
        assert_eq!(reason(&deep, true), None);
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
