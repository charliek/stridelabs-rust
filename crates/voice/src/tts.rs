//! Text to speech, provider side: the [`TtsProvider`] one sentence is spoken
//! through, the app's [`VoiceCatalog`], and the request rules the route
//! applies before anything is charged.
//!
//! # The provider's contract
//!
//! - **[`TtsProvider::configured`]**: the key is set and the client was
//!   built; `false` is the configuration `503`, answered before the request
//!   is read.
//! - **[`TtsProvider::media_type`]** is in `protocol::ALLOWED_AUDIO_TYPES`
//!   (revision 1: `audio/mpeg`), else `Voice::new` refuses the provider. An
//!   answer whose media type differs from the declared one is a `502`, logged
//!   at ERROR; the charge stands.
//! - **[`TtsProvider::max_text_chars`]** is at least
//!   `protocol::TTS_MIN_TEXT_CHARS` (600), else `Voice::new` refuses it. It is
//!   THE route's bound: the `422` text, the body limit
//!   (`protocol::tts_body_limit`), the unit the budget charges and the
//!   advertised `X-Voice-Tts-Max-Chars` all derive from it.
//! - **Voices:** the adapter receives the catalog's PROVIDER id only.
//!   [`TtsProvider::knows_voice`] answering `Some(false)` for a mapped id
//!   makes `Voice::new` refuse; `None` (it cannot tell without asking the
//!   provider) is accepted, and no startup call is ever made.
//! - **What reaches a provider** is a [`SynthesisRequest`]: the trimmed text
//!   and the mapped voice id. Never a user id, an idempotency key or the
//!   app's voice id.
//! - **One bounded synthesis** per admitted request, one body back; the
//!   adapter applies its own bounds (time, response, audio), which the app
//!   chose.
//! - **Failures** are [`TtsFailure::Unavailable`] (a `503` with
//!   `Retry-After: 5`: retrying shortly may work) or
//!   [`TtsFailure::Permanent`] (a `502`), each with a fixed [`ErrorClass`],
//!   the route's log line's `error` field.
//! - **Billing** is the trimmed text's Unicode scalar values, charged BEFORE
//!   the provider is called and never refunded; a replayed admission is
//!   spoken again (the key protects the budget, not provider spend). A
//!   provider that bills otherwise is the app's cost model.
//!
//! # The request
//!
//! A JSON object `{"text": <string>, "voice": <string or null>}` of at most
//! `protocol::tts_body_limit` bytes. Any other shape, or `text` or `voice`
//! given twice, is a `422`; unknown fields are ignored. `text` is trimmed and
//! must then be 1 to the provider's bound in characters; `voice` is one of
//! the catalog's APP ids, exactly, and absent or `null` is its default.
//! [`parse_request`] is that check, and [`charge_key`] the optional
//! `Idempotency-Key`'s. Behind `axum`, `read_request` runs the checks before
//! it, in order (the content type `415`, the declared and then the read
//! length `413`), and then it; `Voice::speak` is the whole flow.

use std::fmt;
use std::future::Future;

use serde::Deserialize;

use crate::budget::ChargeKey;
#[cfg(feature = "axum")]
use crate::protocol::tts_body_limit;
use crate::protocol::IDEMPOTENCY_KEY_HEADER;
use crate::refusal::VoiceRefusal;
use crate::ErrorClass;

/// The request body bound at the protocol's minimum text bound, in bytes:
/// 4 KiB (a 600-character sentence of four-byte characters is 2.4 KB of
/// JSON). `protocol::tts_body_limit` never goes below it.
pub const DEFAULT_BODY_BYTES: usize = 4 * 1024;

/// A text-to-speech provider, as the route speaks through it (module docs:
/// the contract).
pub trait TtsProvider: Send + Sync + 'static {
    /// Whether a sentence can be spoken at all: the key is set and the
    /// client was built. `false` is the configuration `503`.
    fn configured(&self) -> bool;

    /// The media type every answer carries: one of
    /// `protocol::ALLOWED_AUDIO_TYPES`.
    fn media_type(&self) -> &'static str;

    /// The longest text, in characters, this provider is asked to speak; at
    /// least `protocol::TTS_MIN_TEXT_CHARS`, and advertised to clients.
    fn max_text_chars(&self) -> usize;

    /// Whether the provider has the voice `provider_voice`: `Some(false)`
    /// refuses the catalog at startup, `None` is "cannot tell without a
    /// call" (accepted; no call is made).
    fn knows_voice(&self, provider_voice: &str) -> Option<bool>;

    /// Speak one sentence: one bounded call, one body.
    fn synthesize(
        &self,
        request: &SynthesisRequest<'_>,
    ) -> impl Future<Output = Result<Audio, TtsFailure>> + Send;
}

/// Everything that reaches a provider: the trimmed text and the mapped voice
/// id. Nothing else, so a field added later is a decision made here.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct SynthesisRequest<'a> {
    /// The trimmed text, at most the provider's bound.
    pub text: &'a str,
    /// The catalog's provider id for the requested voice.
    pub provider_voice: &'a str,
}

impl<'a> SynthesisRequest<'a> {
    /// `text` in `provider_voice`: how an adapter's own tests call
    /// [`TtsProvider::synthesize`] (the type is `#[non_exhaustive]`).
    #[must_use]
    pub fn new(text: &'a str, provider_voice: &'a str) -> SynthesisRequest<'a> {
        SynthesisRequest {
            text,
            provider_voice,
        }
    }
}

/// One spoken sentence: the whole body, and its media type.
#[derive(Debug, Clone)]
pub struct Audio {
    /// The audio, exactly as the client gets it.
    pub bytes: bytes::Bytes,
    /// Its media type; anything but the provider's declared one is a `502`.
    pub media_type: &'static str,
}

/// Why a sentence was not spoken. The charge stands either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TtsFailure {
    /// Retrying shortly may work (a timeout, an unreachable provider, its
    /// `429` or `5xx`): `503` with `Retry-After: 5`.
    Unavailable(ErrorClass),
    /// Retrying will not help (a refusal, an answer that is not audio):
    /// `502`.
    Permanent(ErrorClass),
}

/// The app's voices: the ids clients show, store and send, each mapped to a
/// provider voice, and the default. A provider swap remaps them in the app's
/// configuration, and no stored setting breaks.
///
/// App ids are 1 to 64 characters of `A-Z a-z 0-9 _ -` (so the unknown-voice
/// `422`, which lists them, needs no escaping); provider ids are 1 to 256
/// bytes with no control character. Matching is exact and case-sensitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceCatalog {
    /// `(app id, provider id)`, in the app's order.
    entries: Vec<(String, String)>,
    /// An app id among `entries`.
    default: String,
}

impl VoiceCatalog {
    /// The catalog of `entries` (app id, provider id), in order, whose
    /// default is the app id `default`.
    ///
    /// # Errors
    ///
    /// The first problem found, in `entries`' order: a [`CatalogError`].
    pub fn new<I, A, P>(entries: I, default: &str) -> Result<VoiceCatalog, CatalogError>
    where
        I: IntoIterator<Item = (A, P)>,
        A: Into<String>,
        P: Into<String>,
    {
        let mut checked: Vec<(String, String)> = Vec::new();
        for (app, provider) in entries {
            let (app, provider) = (app.into(), provider.into());
            if !is_app_id(&app) {
                return Err(CatalogError::BadAppId(app));
            }
            if !is_provider_id(&provider) {
                return Err(CatalogError::BadProviderId(provider));
            }
            if checked.iter().any(|(known, _)| *known == app) {
                return Err(CatalogError::DuplicateAppId(app));
            }
            checked.push((app, provider));
        }
        if checked.is_empty() {
            return Err(CatalogError::Empty);
        }
        if !checked.iter().any(|(app, _)| app == default) {
            return Err(CatalogError::DefaultMissing);
        }
        Ok(VoiceCatalog {
            entries: checked,
            default: default.to_string(),
        })
    }

    /// The catalog whose app ids ARE the provider's ids (both apps' today).
    ///
    /// # Errors
    ///
    /// As [`VoiceCatalog::new`].
    pub fn identity<I, A>(ids: I, default: &str) -> Result<VoiceCatalog, CatalogError>
    where
        I: IntoIterator<Item = A>,
        A: Into<String>,
    {
        VoiceCatalog::new(
            ids.into_iter().map(|id| {
                let id: String = id.into();
                (id.clone(), id)
            }),
            default,
        )
    }

    /// The app id a request without a voice speaks in.
    #[must_use]
    pub fn default_voice(&self) -> &str {
        &self.default
    }

    /// The provider id the app id `app_voice` maps to; `None` for an id not
    /// in the catalog (matched exactly, case-sensitive, untrimmed).
    #[must_use]
    pub fn provider_voice(&self, app_voice: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(app, _)| app == app_voice)
            .map(|(_, provider)| provider.as_str())
    }

    /// Every app id, in the catalog's order.
    pub fn app_voices(&self) -> impl Iterator<Item = &str> + '_ {
        self.entries.iter().map(|(app, _)| app.as_str())
    }

    /// Every `(app id, provider id)`, in the catalog's order.
    pub(crate) fn entries(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.entries
            .iter()
            .map(|(app, provider)| (app.as_str(), provider.as_str()))
    }
}

/// Why a [`VoiceCatalog`] was refused. An id is quoted escaped (`{:?}`), so
/// a control character cannot reach a log line raw.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CatalogError {
    /// No entries.
    #[error("the voice catalog is empty")]
    Empty,
    /// An app id that is not 1 to 64 characters of `A-Z a-z 0-9 _ -`.
    #[error("voice id {0:?} is not 1 to 64 characters of A-Z, a-z, 0-9, _ and -")]
    BadAppId(String),
    /// A provider id that is not 1 to 256 bytes, or holds a control
    /// character.
    #[error("provider voice id {0:?} is not 1 to 256 bytes without a control character")]
    BadProviderId(String),
    /// An app id listed twice.
    #[error("voice id {0:?} is in the catalog twice")]
    DuplicateAppId(String),
    /// The default is not one of the app ids.
    #[error("the default voice is not in the catalog")]
    DefaultMissing,
}

/// `^[A-Za-z0-9_-]{1,64}$`.
fn is_app_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// 1 to 256 bytes, no control character.
fn is_provider_id(id: &str) -> bool {
    (1..=256).contains(&id.len()) && !id.chars().any(char::is_control)
}

/// A request that passed every check of [`parse_request`]: what is charged
/// and what is spoken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeakRequest {
    /// The trimmed text.
    pub text: String,
    /// The app voice id (the catalog's default when the request named
    /// none): what the charge's fingerprint names.
    pub app_voice: String,
    /// `text`'s length in Unicode scalar values: the charge.
    pub chars: usize,
}

/// The body as parsed. `voice: null` and an absent `voice` are both `None`.
///
/// `Deserialize` is written by hand, for two refusals a derive does not make:
///
/// - **only an object.** A derived struct also accepts a SEQUENCE, so
///   `["hi"]` would be `{"text":"hi"}`, a body no client means. This visitor
///   has `visit_map` alone, so serde_json refuses anything that is not `{…}`.
/// - **no duplicate field.** serde_json hands every key to the visitor, and a
///   derive (like a `Value`) keeps the LAST of a repeated `text` or `voice`;
///   which one a proxy, a log or another parser would believe is anyone's
///   guess. A second `text` or `voice` (escaped spellings included, since keys
///   arrive decoded) is a `422`. Unknown keys are skipped, repeated or not.
struct RawRequest {
    text: String,
    voice: Option<String>,
}

impl<'de> Deserialize<'de> for RawRequest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;

        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = RawRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object with a string text and an optional voice")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<RawRequest, A::Error> {
                use serde::de::Error as _;
                let mut text: Option<String> = None;
                // `Some(None)` is a `null` voice: present, so a second one is
                // still a duplicate.
                let mut voice: Option<Option<String>> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "text" if text.is_some() => return Err(A::Error::duplicate_field("text")),
                        "text" => text = Some(map.next_value()?),
                        "voice" if voice.is_some() => {
                            return Err(A::Error::duplicate_field("voice"))
                        }
                        "voice" => voice = Some(map.next_value()?),
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(RawRequest {
                    text: text.ok_or_else(|| A::Error::missing_field("text"))?,
                    voice: voice.flatten(),
                })
            }
        }

        deserializer.deserialize_map(Fields)
    }
}

/// The request's `422` checks, in order, on a body already read within its
/// bound: the JSON shape (an object only, no repeated `text` or `voice`),
/// the voice (an app id of `catalog`, or its default), an empty text, then
/// the text over `max_text_chars` characters.
///
/// # Errors
///
/// The first check that fails, as its refusal: `InvalidBody`,
/// `UnknownVoice`, `EmptyText` or `TextTooLong`.
pub fn parse_request(
    body: &[u8],
    catalog: &VoiceCatalog,
    max_text_chars: usize,
) -> Result<SpeakRequest, VoiceRefusal> {
    let raw: RawRequest = serde_json::from_slice(body).map_err(|_| VoiceRefusal::invalid_body())?;
    let app_voice = match raw.voice {
        None => catalog.default_voice().to_string(),
        Some(name) if catalog.provider_voice(&name).is_some() => name,
        Some(_) => return Err(VoiceRefusal::unknown_voice(catalog)),
    };
    let text = raw.text.trim();
    if text.is_empty() {
        return Err(VoiceRefusal::empty_text());
    }
    let chars = text.chars().count();
    if chars > max_text_chars {
        return Err(VoiceRefusal::text_too_long(max_text_chars));
    }
    Ok(SpeakRequest {
        text: text.to_string(),
        app_voice,
        chars,
    })
}

/// Every request check before the charge but the key's, in order: the
/// content type (`415`), the declared length (`413`, refused unread), the
/// read length (`413`), then [`parse_request`]'s `422`s. The body is read
/// up to `protocol::tts_body_limit(max_text_chars)` bytes (4 KiB at the
/// protocol's minimum bound), never further.
///
/// # Errors
///
/// The first check that fails, as its refusal: `NotJson`, `BodyTooLarge`,
/// then [`parse_request`]'s.
#[cfg(feature = "axum")]
pub async fn read_request(
    headers: &http::HeaderMap,
    body: axum::body::Body,
    catalog: &VoiceCatalog,
    max_text_chars: usize,
) -> Result<SpeakRequest, VoiceRefusal> {
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !is_json_content_type(content_type) {
        return Err(VoiceRefusal::not_json());
    }
    let limit = tts_body_limit(max_text_chars);
    // A declared length over the limit is refused unread. One that lies, or
    // a body with none, is bounded by the read below.
    let declared = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > limit as u64) {
        return Err(VoiceRefusal::body_too_large(limit));
    }
    // `to_bytes` fails past the limit, and also when the client goes away
    // mid-body, which gets the same `413` that nobody is left to read.
    let bytes = axum::body::to_bytes(body, limit)
        .await
        .map_err(|_| VoiceRefusal::body_too_large(limit))?;
    parse_request(&bytes, catalog, max_text_chars)
}

/// The `Idempotency-Key` that names this request's charge: absent, a key
/// minted for it; present, exactly ONE header whose value
/// [`ChargeKey::parse`] accepts. `None` is the `422`.
#[must_use]
pub fn charge_key(headers: &http::HeaderMap) -> Option<ChargeKey> {
    let mut sent = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    match (sent.next(), sent.next()) {
        (None, _) => Some(ChargeKey::mint()),
        (Some(value), None) => value.to_str().ok().and_then(ChargeKey::parse),
        (Some(_), Some(_)) => None,
    }
}

/// Whether a request's `Content-Type` is JSON: `application/json` or any
/// `application/…+json`, parameters (`; charset=utf-8`) ignored, case
/// insensitive. An absent `Content-Type` is not JSON.
#[must_use]
pub fn is_json_content_type(content_type: Option<&str>) -> bool {
    let Some(value) = content_type else {
        return false;
    };
    let mime = value.split(';').next().unwrap_or("").trim();
    let Some((maintype, subtype)) = mime.split_once('/') else {
        return false;
    };
    maintype.eq_ignore_ascii_case("application")
        && (subtype.eq_ignore_ascii_case("json") || subtype.to_ascii_lowercase().ends_with("+json"))
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};

    use super::*;
    use crate::budget::Fingerprint;
    use crate::refusal::RefusalKind;

    /// Both apps' catalog: the eight, identity-mapped, `Jason` the default.
    const EIGHT: [&str; 8] = [
        "Jason", "Hazel", "Casey", "Nadia", "Brian", "Imogen", "Liam", "Evan",
    ];

    fn eight() -> VoiceCatalog {
        VoiceCatalog::identity(EIGHT, "Jason").expect("the eight")
    }

    fn json_body(text: &str, voice: Option<&str>) -> String {
        match voice {
            Some(voice) => serde_json::json!({ "text": text, "voice": voice }).to_string(),
            None => serde_json::json!({ "text": text }).to_string(),
        }
    }

    /// The refusal's kind and `detail`, or the request it was accepted as.
    fn refusal(body: &str) -> Result<(RefusalKind, String), SpeakRequest> {
        let refusal = match parse_request(body.as_bytes(), &eight(), 600) {
            Ok(accepted) => return Err(accepted),
            Err(refusal) => refusal,
        };
        let body: serde_json::Value = serde_json::from_slice(refusal.body()).expect("JSON");
        Ok((
            refusal.kind(),
            body["detail"].as_str().expect("a detail").to_string(),
        ))
    }

    /// The voice is an app id of the catalog, exactly: case-sensitive,
    /// untrimmed; each of the eight maps to itself.
    #[test]
    fn every_voice_parses_by_its_exact_name_only() {
        let catalog = eight();
        for voice in EIGHT {
            assert_eq!(catalog.provider_voice(voice), Some(voice));
            assert_eq!(catalog.provider_voice(&voice.to_lowercase()), None);
            assert_eq!(catalog.provider_voice(&format!(" {voice}")), None);
        }
        assert_eq!(catalog.provider_voice(""), None);
        assert_eq!(catalog.default_voice(), "Jason");
        assert_eq!(catalog.app_voices().collect::<Vec<_>>(), EIGHT);
    }

    /// The unknown-voice `422` lists the catalog's app ids in its order,
    /// `, `-joined: for the eight, today's literal byte for byte.
    #[test]
    fn the_unknown_voice_message_names_exactly_the_eight() {
        let refusal = parse_request(br#"{"text":"hi","voice":"Bob"}"#, &eight(), 600)
            .expect_err("an unknown voice");
        assert_eq!(
            std::str::from_utf8(refusal.body()),
            Ok(
                r#"{"detail":"unknown voice; expected one of Jason, Hazel, Casey, Nadia, Brian, Imogen, Liam, Evan"}"#
            )
        );
        let names = EIGHT.join(", ");
        assert_eq!(
            std::str::from_utf8(refusal.body()),
            Ok(format!(r#"{{"detail":"unknown voice; expected one of {names}"}}"#).as_str())
        );
    }

    /// Every bad request is its `422`, with today's detail: the shape (not an
    /// object, a non-string field, no text, malformed or empty JSON, a
    /// repeated `text` or `voice` however spelled), the voice, the text.
    #[test]
    fn a_bad_request_is_its_422() {
        const SHAPE: &str = "expected a JSON object with a string text and an optional voice";
        const UNKNOWN: &str =
            "unknown voice; expected one of Jason, Hazel, Casey, Nadia, Brian, Imogen, Liam, Evan";
        let too_long = "a".repeat(601);
        let cases: Vec<(&str, String, RefusalKind, &str)> = vec![
            (
                "unknown voice",
                json_body("hi", Some("Bob")),
                RefusalKind::UnknownVoice,
                UNKNOWN,
            ),
            (
                "a voice in the wrong case",
                json_body("hi", Some("jason")),
                RefusalKind::UnknownVoice,
                UNKNOWN,
            ),
            (
                "an empty voice",
                json_body("hi", Some("")),
                RefusalKind::UnknownVoice,
                UNKNOWN,
            ),
            (
                "a voice that is not a string",
                r#"{"text":"hi","voice":5}"#.into(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
            (
                "empty text",
                json_body("", None),
                RefusalKind::EmptyText,
                "text is empty",
            ),
            (
                "whitespace-only text",
                json_body(" \n\t ", None),
                RefusalKind::EmptyText,
                "text is empty",
            ),
            (
                "601 characters",
                json_body(&too_long, None),
                RefusalKind::TextTooLong,
                "text is over 600 characters",
            ),
            (
                "no text",
                r#"{"voice":"Hazel"}"#.into(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
            (
                "text that is not a string",
                r#"{"text":5}"#.into(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
            (
                "a null text",
                r#"{"text":null}"#.into(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
            (
                "an array",
                r#"["hi"]"#.into(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
            (
                "a string",
                r#""hi""#.into(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
            (
                "malformed JSON",
                r#"{"text":"#.into(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
            (
                "trailing bytes",
                r#"{"text":"hi"} x"#.into(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
            (
                "an empty body",
                String::new(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
            (
                "a repeated text",
                r#"{"text":"hi","text":"bye"}"#.into(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
            (
                "a repeated voice",
                r#"{"text":"hi","voice":"Hazel","voice":"Liam"}"#.into(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
            (
                "a null voice, then a voice",
                r#"{"text":"hi","voice":null,"voice":"Liam"}"#.into(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
            (
                "a repeated text, spelled with an escape",
                r#"{"text":"hi","\u0074ext":"bye"}"#.into(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
            (
                "a repeated voice, spelled with an escape",
                r#"{"text":"hi","voice":"Hazel","\u0076oice":"Liam"}"#.into(),
                RefusalKind::InvalidBody,
                SHAPE,
            ),
        ];
        for (label, body, kind, detail) in cases {
            assert_eq!(refusal(&body), Ok((kind, detail.to_string())), "{label}");
        }
    }

    /// The text is counted in characters (Unicode scalar values), AFTER
    /// trimming: 600 three-byte characters pass, 600 with whitespace around
    /// them pass trimmed, and the count is the charge. The bound is the
    /// caller's.
    #[test]
    fn the_bound_counts_trimmed_characters_not_bytes() {
        let catalog = eight();
        let euros = "€".repeat(600);
        let accepted = parse_request(json_body(&euros, None).as_bytes(), &catalog, 600)
            .expect("600 characters");
        assert_eq!((accepted.chars, accepted.text.len()), (600, 1_800));
        let padded = format!("  {}  \n", "a".repeat(600));
        let accepted = parse_request(json_body(&padded, None).as_bytes(), &catalog, 600)
            .expect("600 characters, padded");
        assert_eq!(accepted.text, "a".repeat(600));
        assert_eq!(accepted.chars, 600);

        let at_601 = parse_request(json_body(&"a".repeat(601), None).as_bytes(), &catalog, 601)
            .expect("the caller's bound, not 600");
        assert_eq!(at_601.chars, 601);
        let refusal = parse_request(
            json_body(&"a".repeat(1_001), None).as_bytes(),
            &catalog,
            1_000,
        )
        .expect_err("over the caller's bound");
        assert_eq!(
            std::str::from_utf8(refusal.body()),
            Ok(r#"{"detail":"text is over 1000 characters"}"#)
        );
    }

    /// An absent voice, a `null` one and the default named are one request:
    /// the default's app id, so one fingerprint (a retry that names the
    /// default where the first attempt left it out replays, not `422`s).
    /// Unknown fields are ignored; the text is what was trimmed.
    #[test]
    fn absent_null_and_default_voice_share_a_fingerprint() {
        let catalog = eight();
        let mut fingerprints = Vec::new();
        for body in [
            r#"{"text":" hi "}"#,
            r#"{"text":"hi","voice":null}"#,
            r#"{"voice":"Jason","text":"hi","other":[1,{"text":2}]}"#,
        ] {
            let request = parse_request(body.as_bytes(), &catalog, 600).expect(body);
            assert_eq!(
                request,
                SpeakRequest {
                    text: "hi".to_string(),
                    app_voice: "Jason".to_string(),
                    chars: 2
                },
                "{body}"
            );
            fingerprints.push(Fingerprint::of(&request.app_voice, &request.text));
        }
        assert!(fingerprints.windows(2).all(|pair| pair[0] == pair[1]));
        let hazel =
            parse_request(br#"{"text":"hi","voice":"Hazel"}"#, &catalog, 600).expect("Hazel");
        assert_eq!(hazel.app_voice, "Hazel");
        assert_ne!(
            Fingerprint::of(&hazel.app_voice, &hazel.text),
            fingerprints[0]
        );
    }

    /// A mapped catalog: the request names the APP id, which is what
    /// `SpeakRequest` keeps; the provider id is the catalog's.
    #[test]
    fn a_request_names_the_app_voice_and_the_catalog_maps_it() {
        let catalog = VoiceCatalog::new([("calm", "provider-voice-7"), ("bright", "pv 9")], "calm")
            .expect("a mapped catalog");
        let request =
            parse_request(br#"{"text":"hi","voice":"bright"}"#, &catalog, 600).expect("an app id");
        assert_eq!(request.app_voice, "bright");
        assert_eq!(catalog.provider_voice(&request.app_voice), Some("pv 9"));
        let refusal = parse_request(br#"{"text":"hi","voice":"pv 9"}"#, &catalog, 600)
            .expect_err("a provider id is not an app id");
        assert_eq!(
            std::str::from_utf8(refusal.body()),
            Ok(r#"{"detail":"unknown voice; expected one of calm, bright"}"#)
        );
        let default = parse_request(br#"{"text":"hi"}"#, &catalog, 600).expect("the default");
        assert_eq!(default.app_voice, "calm");
    }

    /// Each catalog problem, found in order: an app id's shape (1 to 64 of
    /// `A-Z a-z 0-9 _ -`), a provider id's (1 to 256 bytes, no control
    /// character), a repeated app id, no entries, a default not among them.
    /// A provider id may serve two app ids.
    #[test]
    fn a_catalog_is_refused_for_each_problem() {
        let long_app = "a".repeat(65);
        let long_provider = "p".repeat(257);
        for (entries, default, expected) in [
            (vec![], "Jason", CatalogError::Empty),
            (vec![("", "x")], "", CatalogError::BadAppId(String::new())),
            (
                vec![(long_app.as_str(), "x")],
                "a",
                CatalogError::BadAppId(long_app.clone()),
            ),
            (
                vec![("Jason", "x"), ("Jas on", "x")],
                "Jason",
                CatalogError::BadAppId("Jas on".to_string()),
            ),
            (
                vec![("Zoë", "x")],
                "Zoë",
                CatalogError::BadAppId("Zoë".to_string()),
            ),
            (
                vec![("a", "")],
                "a",
                CatalogError::BadProviderId(String::new()),
            ),
            (
                vec![("a", long_provider.as_str())],
                "a",
                CatalogError::BadProviderId(long_provider.clone()),
            ),
            (
                vec![("a", "line\nbreak")],
                "a",
                CatalogError::BadProviderId("line\nbreak".to_string()),
            ),
            (
                vec![("a", "x"), ("b", "y"), ("a", "z")],
                "a",
                CatalogError::DuplicateAppId("a".to_string()),
            ),
            (vec![("a", "x")], "b", CatalogError::DefaultMissing),
            (vec![("a", "x")], "A", CatalogError::DefaultMissing),
        ] {
            assert_eq!(
                VoiceCatalog::new(entries.clone(), default),
                Err(expected.clone()),
                "{entries:?} / {default:?}"
            );
        }
        let longest_app = "a".repeat(64);
        // 256 BYTES, 128 characters: the bound is bytes.
        let longest_provider = "é".repeat(128);
        assert_eq!(longest_provider.len(), 256);
        assert_eq!(
            VoiceCatalog::new([("a", format!("{longest_provider}x"))], "a"),
            Err(CatalogError::BadProviderId(format!("{longest_provider}x")))
        );
        let catalog = VoiceCatalog::new(
            [
                (longest_app.as_str(), longest_provider.as_str()),
                ("b_-9", longest_provider.as_str()),
            ],
            "b_-9",
        )
        .expect("the longest ids, one provider voice for two app ids");
        assert_eq!(
            catalog.provider_voice("b_-9"),
            Some(longest_provider.as_str())
        );
        let message = CatalogError::BadProviderId("a\u{1b}[31m".to_string()).to_string();
        assert!(!message.contains('\u{1b}'), "{message}");
    }

    /// The `Idempotency-Key`: absent mints one; one header of 1 to 64 safe
    /// characters is that key; anything else (empty, 65, another character,
    /// not ASCII, sent twice) is `None`, the `422`.
    #[test]
    fn the_idempotency_key_is_one_header_of_safe_characters() {
        let minted = charge_key(&HeaderMap::new()).expect("minted");
        assert_eq!(minted.as_str().len(), 36);
        assert_ne!(charge_key(&HeaderMap::new()), Some(minted));

        let with = |values: &[&[u8]]| {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(
                    IDEMPOTENCY_KEY_HEADER,
                    HeaderValue::from_bytes(value).expect("a header value"),
                );
            }
            charge_key(&headers).map(|key| key.as_str().to_string())
        };
        let longest = "k".repeat(64);
        assert_eq!(with(&[b"sentence-1"]), Some("sentence-1".to_string()));
        assert_eq!(with(&[longest.as_bytes()]), Some(longest.clone()));
        let long = "k".repeat(65);
        for bad in [
            &b""[..],
            long.as_bytes(),
            b"a b",
            b"a.b",
            b"a:b",
            b"a/b",
            b"a+b",
            b"caf\xc3\xa9",
        ] {
            assert_eq!(with(&[bad]), None, "{:?}", String::from_utf8_lossy(bad));
        }
        assert_eq!(with(&[b"sentence-1", b"sentence-1"]), None);
        let mut cased = HeaderMap::new();
        cased.insert(
            http::header::HeaderName::from_static("idempotency-key"),
            HeaderValue::from_static("Sentence_2"),
        );
        assert_eq!(
            charge_key(&cased).map(|key| key.as_str().to_string()),
            Some("Sentence_2".to_string())
        );
    }

    /// JSON is `application/json` or `application/…+json`, any parameters,
    /// any case; nothing else, and no header at all, is not.
    #[test]
    fn only_a_json_content_type_is_json() {
        for json in [
            "application/json",
            "application/json; charset=utf-8",
            "Application/JSON",
            "application/hal+json",
            "application/vnd.api+JSON;x=1",
        ] {
            assert!(is_json_content_type(Some(json)), "{json}");
        }
        for other in [
            "",
            "text/plain",
            "application/x-www-form-urlencoded",
            "json",
            "application/jsonx",
            "text/json",
            "application",
        ] {
            assert!(!is_json_content_type(Some(other)), "{other}");
        }
        assert!(!is_json_content_type(None));
    }
}
