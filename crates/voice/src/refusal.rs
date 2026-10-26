//! Every refusal the voice routes answer: its status, its `{"detail": …}`
//! body and its headers, as one [`VoiceRefusal`] the app renders through its
//! own envelope.
//!
//! The bodies are a contract, not a rendering: a client matches on the
//! status, and a log line or a support message on the text. So they are fixed
//! byte literals, except four that derive from the app's facts (the catalog's
//! voices, the text bound, the body bound, the provider's formats), which for
//! both apps' current facts render byte for byte as the literals did; and the
//! budget's `429`, which also names the spent allowance ([`VoiceLimitBody`]).
//!
//! | kind | status | `detail` | headers |
//! |---|---|---|---|
//! | `NotConfigured` | 503 | `voice beta not configured` | none |
//! | `Unavailable` | 503 | `voice beta unavailable` | `Retry-After: 5` |
//! | `LimitReached` | 429 | `voice beta limit reached`, then `scope` and `resets_at` | `Retry-After` to `resets_at` |
//! | `ReopenedTooSoon` | 429 | `voice stream reopened too soon` | `Retry-After`: the admission interval, rounded up |
//! | `UpgradeRequired` | 426 | `expected a WebSocket upgrade` | `Upgrade: websocket` |
//! | `BadRate` | 422 | `rate must be 24000 or 16000` (the formats' rates, in order) | none |
//! | `BadEncoding` | 422 | `encoding must be pcm_s16le` (the formats' encodings) | none |
//! | `BodyTooLarge` | 413 | `request body over 4 KiB` (else `over <n> bytes`) | none |
//! | `NotJson` | 415 | `expected an application/json body` | none |
//! | `InvalidBody` | 422 | `expected a JSON object with a string text and an optional voice` | none |
//! | `UnknownVoice` | 422 | `unknown voice; expected one of <the catalog's app ids>` | none |
//! | `EmptyText` | 422 | `text is empty` | none |
//! | `TextTooLong` | 422 | `text is over <the bound> characters` | none |
//! | `BadIdempotencyKey` | 422 | `Idempotency-Key must be sent once, as 1 to 64 characters of A-Z, a-z, 0-9, _ and -` | none |
//! | `IdempotencyKeyReused` | 422 | `Idempotency-Key was already used for another sentence` | none |
//! | `ProviderUnavailable` | 503 | `voice provider unavailable` | `Retry-After: 5` |
//! | `ProviderError` | 502 | `voice provider error` | none |
//!
//! The configuration `503` carries no `Retry-After`: waiting will not
//! configure anything. The text-to-speech route's `X-Voice-Tts-Max-Chars` is
//! added by the route's reply, not here.

use std::borrow::Cow;

use chrono::{DateTime, Utc};
use http::header::{RETRY_AFTER, UPGRADE};
use http::{HeaderMap, HeaderValue, StatusCode};
use serde::Serialize;

use crate::budget::{LimitReached, LimitScope};
use crate::stt::AudioFormat;
use crate::tts::{VoiceCatalog, DEFAULT_BODY_BYTES};

/// What a retryable `503` asks the client to wait, in seconds: a provider or
/// a Redis that is briefly unavailable. Long enough not to hammer a provider
/// that just answered `429`; short enough that the next sentence of a reply
/// is still worth speaking.
pub const RETRY_AFTER_UNAVAILABLE_SECONDS: u64 = 5;

/// The `detail` of a spent budget's `429`: a client that reads only `detail`
/// reads what it always has.
pub const LIMIT_REACHED_DETAIL: &str = "voice beta limit reached";

/// The `detail` of the stream's admission throttle (`429`).
pub const REOPENED_TOO_SOON_DETAIL: &str = "voice stream reopened too soon";

/// A refusal, ready to render: its status, body and headers (module docs'
/// table). Built by the crate's checks; the app renders it through its own
/// envelope.
#[derive(Debug, Clone)]
pub struct VoiceRefusal {
    kind: RefusalKind,
    body: Cow<'static, [u8]>,
    retry_after: Option<u64>,
    limit: Option<LimitReached>,
}

/// Which refusal (module docs' table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefusalKind {
    /// `503`: the provider is not configured, or there is no Redis.
    NotConfigured,
    /// `503` + `Retry-After: 5`: Redis did not answer, or a newer upgrade
    /// for this user won a race.
    Unavailable,
    /// `429`: a budget is spent.
    LimitReached,
    /// `429`: this user opened a stream inside the admission interval.
    ReopenedTooSoon,
    /// `426`: a plain request to the stream's WebSocket route.
    UpgradeRequired,
    /// `422`: a `rate` the provider does not take.
    BadRate,
    /// `422`: an `encoding` the provider does not take.
    BadEncoding,
    /// `413`: the body is over its bound, declared or read.
    BodyTooLarge,
    /// `415`: the body is not JSON.
    NotJson,
    /// `422`: not an object with a string `text` and an optional `voice`.
    InvalidBody,
    /// `422`: a voice not in the app's catalog.
    UnknownVoice,
    /// `422`: the trimmed text is empty.
    EmptyText,
    /// `422`: the trimmed text is over the bound.
    TextTooLong,
    /// `422`: a malformed or repeated `Idempotency-Key`.
    BadIdempotencyKey,
    /// `422`: the key's charge was made for another sentence.
    IdempotencyKeyReused,
    /// `503` + `Retry-After: 5`: the provider is briefly unavailable.
    ProviderUnavailable,
    /// `502`: the provider refused, or answered with no usable audio.
    ProviderError,
}

impl RefusalKind {
    /// The kind's one status.
    fn status(self) -> StatusCode {
        match self {
            RefusalKind::NotConfigured
            | RefusalKind::Unavailable
            | RefusalKind::ProviderUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            RefusalKind::LimitReached | RefusalKind::ReopenedTooSoon => {
                StatusCode::TOO_MANY_REQUESTS
            }
            RefusalKind::UpgradeRequired => StatusCode::UPGRADE_REQUIRED,
            RefusalKind::BadRate
            | RefusalKind::BadEncoding
            | RefusalKind::InvalidBody
            | RefusalKind::UnknownVoice
            | RefusalKind::EmptyText
            | RefusalKind::TextTooLong
            | RefusalKind::BadIdempotencyKey
            | RefusalKind::IdempotencyKeyReused => StatusCode::UNPROCESSABLE_ENTITY,
            RefusalKind::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            RefusalKind::NotJson => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            RefusalKind::ProviderError => StatusCode::BAD_GATEWAY,
        }
    }
}

impl VoiceRefusal {
    /// The status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.kind.status()
    }

    /// The JSON body: `{"detail":…}`, or the budget's [`VoiceLimitBody`].
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The `Retry-After` seconds, when retrying later may work.
    #[must_use]
    pub fn retry_after(&self) -> Option<u64> {
        self.retry_after
    }

    /// Which refusal.
    #[must_use]
    pub fn kind(&self) -> RefusalKind {
        self.kind
    }

    /// The spent budget, for a `LimitReached` (a log line's scope and
    /// windows).
    #[must_use]
    pub fn limit(&self) -> Option<&LimitReached> {
        self.limit.as_ref()
    }

    /// The headers the refusal carries besides the app's envelope's:
    /// `Retry-After` when retrying later may work, and `Upgrade: websocket`
    /// on the `426` (RFC 9110 §15.5.22).
    #[must_use]
    pub fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(seconds) = self.retry_after {
            headers.insert(RETRY_AFTER, HeaderValue::from(seconds));
        }
        if self.kind == RefusalKind::UpgradeRequired {
            headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        }
        headers
    }

    /// The response: the app's `envelope` of the status and the body (its
    /// voice `{"detail"}` writer, which sets the content type), then
    /// [`VoiceRefusal::headers`] set on it.
    #[cfg(feature = "axum")]
    pub fn into_response_with(
        self,
        envelope: impl FnOnce(StatusCode, bytes::Bytes) -> axum::response::Response,
    ) -> axum::response::Response {
        let headers = self.headers();
        let body = match self.body {
            Cow::Borrowed(body) => bytes::Bytes::from_static(body),
            Cow::Owned(body) => bytes::Bytes::from(body),
        };
        let mut response = envelope(self.kind.status(), body);
        // `extend` replaces a header the envelope set under the same name.
        response.headers_mut().extend(headers);
        response
    }

    /// A refusal whose body is a fixed literal.
    fn fixed(kind: RefusalKind, body: &'static [u8]) -> VoiceRefusal {
        VoiceRefusal {
            kind,
            body: Cow::Borrowed(body),
            retry_after: None,
            limit: None,
        }
    }

    /// A refusal whose `detail` derives from the app's facts: compact
    /// serde_json, so it is valid JSON whatever the text holds.
    fn detail(kind: RefusalKind, detail: &str) -> VoiceRefusal {
        #[derive(Serialize)]
        struct Detail<'a> {
            detail: &'a str,
        }
        // A struct of one string always serializes.
        let body = serde_json::to_vec(&Detail { detail }).expect("a detail serializes");
        VoiceRefusal {
            kind,
            body: Cow::Owned(body),
            retry_after: None,
            limit: None,
        }
    }

    pub(crate) fn invalid_body() -> VoiceRefusal {
        VoiceRefusal::fixed(
            RefusalKind::InvalidBody,
            br#"{"detail":"expected a JSON object with a string text and an optional voice"}"#,
        )
    }

    /// The catalog's app ids, in order, `, `-joined.
    pub(crate) fn unknown_voice(catalog: &VoiceCatalog) -> VoiceRefusal {
        let voices: Vec<&str> = catalog.app_voices().collect();
        VoiceRefusal::detail(
            RefusalKind::UnknownVoice,
            &format!("unknown voice; expected one of {}", voices.join(", ")),
        )
    }

    pub(crate) fn empty_text() -> VoiceRefusal {
        VoiceRefusal::fixed(RefusalKind::EmptyText, br#"{"detail":"text is empty"}"#)
    }

    pub(crate) fn text_too_long(max_text_chars: usize) -> VoiceRefusal {
        VoiceRefusal::detail(
            RefusalKind::TextTooLong,
            &format!("text is over {max_text_chars} characters"),
        )
    }
}

// The refusals the stream's admission answers (`Voice::open_stream`: the
// configuration, the upgrade, the rate and the encoding, the admission),
// which `Voice::speak` shares the first three of. Both flows are behind
// `axum`; without it only the tests build these.
#[cfg_attr(
    not(any(test, feature = "axum")),
    expect(
        dead_code,
        reason = "the voice flows, which answer these, are behind `axum`"
    )
)]
impl VoiceRefusal {
    fn retrying_after(self, seconds: u64) -> VoiceRefusal {
        VoiceRefusal {
            retry_after: Some(seconds),
            ..self
        }
    }

    /// `a`, `a or b`, `a, b or c`, …
    fn one_of(items: &[String]) -> String {
        match items {
            [] => String::new(),
            [only] => only.clone(),
            [first @ .., last] => format!("{} or {last}", first.join(", ")),
        }
    }

    pub(crate) fn not_configured() -> VoiceRefusal {
        VoiceRefusal::fixed(
            RefusalKind::NotConfigured,
            br#"{"detail":"voice beta not configured"}"#,
        )
    }

    pub(crate) fn unavailable() -> VoiceRefusal {
        VoiceRefusal::fixed(
            RefusalKind::Unavailable,
            br#"{"detail":"voice beta unavailable"}"#,
        )
        .retrying_after(RETRY_AFTER_UNAVAILABLE_SECONDS)
    }

    /// The budget's `429`: [`VoiceLimitBody`], and `Retry-After` to the
    /// reported window's end.
    pub(crate) fn limit_reached(limit: &LimitReached) -> VoiceRefusal {
        // A struct of a string, a unit enum and an instant always serializes.
        let body =
            serde_json::to_vec(&VoiceLimitBody::new(limit)).expect("a limit body serializes");
        VoiceRefusal {
            kind: RefusalKind::LimitReached,
            body: Cow::Owned(body),
            retry_after: Some(limit.retry_after_seconds),
            limit: Some(*limit),
        }
    }

    /// The admission throttle's `429`, retrying after `retry_after_seconds`
    /// (the admission interval, rounded up).
    pub(crate) fn reopened_too_soon(retry_after_seconds: u64) -> VoiceRefusal {
        VoiceRefusal::fixed(
            RefusalKind::ReopenedTooSoon,
            br#"{"detail":"voice stream reopened too soon"}"#,
        )
        .retrying_after(retry_after_seconds)
    }

    pub(crate) fn upgrade_required() -> VoiceRefusal {
        VoiceRefusal::fixed(
            RefusalKind::UpgradeRequired,
            br#"{"detail":"expected a WebSocket upgrade"}"#,
        )
    }

    /// `rate must be <the formats' rates, in order>`.
    pub(crate) fn bad_rate(formats: &[AudioFormat]) -> VoiceRefusal {
        let rates: Vec<String> = formats
            .iter()
            .map(|format| format.sample_rate.to_string())
            .collect();
        VoiceRefusal::detail(
            RefusalKind::BadRate,
            &format!("rate must be {}", VoiceRefusal::one_of(&rates)),
        )
    }

    /// `encoding must be <the formats' encodings, each once, in order>`.
    pub(crate) fn bad_encoding(formats: &[AudioFormat]) -> VoiceRefusal {
        let mut encodings: Vec<String> = Vec::new();
        for format in formats {
            let name = format.encoding.wire_name();
            if !encodings.iter().any(|known| known == name) {
                encodings.push(name.to_string());
            }
        }
        VoiceRefusal::detail(
            RefusalKind::BadEncoding,
            &format!("encoding must be {}", VoiceRefusal::one_of(&encodings)),
        )
    }
}

// The refusals only `Voice::speak` answers (the body's bound and type, the
// key, the provider). Until it lands only the tests build them, and the
// expectation fails the build once every one is used.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the text-to-speech flow answers these; until it lands, only the tests build them"
    )
)]
impl VoiceRefusal {
    /// `request body over 4 KiB` at the default bound, else `over <n>
    /// bytes`.
    pub(crate) fn body_too_large(limit: usize) -> VoiceRefusal {
        if limit == DEFAULT_BODY_BYTES {
            return VoiceRefusal::fixed(
                RefusalKind::BodyTooLarge,
                br#"{"detail":"request body over 4 KiB"}"#,
            );
        }
        VoiceRefusal::detail(
            RefusalKind::BodyTooLarge,
            &format!("request body over {limit} bytes"),
        )
    }

    pub(crate) fn not_json() -> VoiceRefusal {
        VoiceRefusal::fixed(
            RefusalKind::NotJson,
            br#"{"detail":"expected an application/json body"}"#,
        )
    }

    pub(crate) fn bad_idempotency_key() -> VoiceRefusal {
        VoiceRefusal::fixed(
            RefusalKind::BadIdempotencyKey,
            br#"{"detail":"Idempotency-Key must be sent once, as 1 to 64 characters of A-Z, a-z, 0-9, _ and -"}"#,
        )
    }

    pub(crate) fn key_reused() -> VoiceRefusal {
        VoiceRefusal::fixed(
            RefusalKind::IdempotencyKeyReused,
            br#"{"detail":"Idempotency-Key was already used for another sentence"}"#,
        )
    }

    pub(crate) fn provider_unavailable() -> VoiceRefusal {
        VoiceRefusal::fixed(
            RefusalKind::ProviderUnavailable,
            br#"{"detail":"voice provider unavailable"}"#,
        )
        .retrying_after(RETRY_AFTER_UNAVAILABLE_SECONDS)
    }

    pub(crate) fn provider_error() -> VoiceRefusal {
        VoiceRefusal::fixed(
            RefusalKind::ProviderError,
            br#"{"detail":"voice provider error"}"#,
        )
    }
}

// The `429` body when a voice budget is spent (plan 016 B-4). Not a doc
// comment: utoipa copies a `///` block into the schema's `description`; the
// line below is the API's.
/// A voice budget is spent: which allowance, and when it comes back.
#[derive(Debug, Serialize)]
pub struct VoiceLimitBody {
    /// Always `voice beta limit reached`.
    pub detail: &'static str,
    /// The spent allowance: the user's UTC day, the user's UTC calendar
    /// month, or everyone's UTC calendar month (voice is off for every user
    /// until it resets). Of several spent at once, the one that resets last.
    pub scope: LimitScope,
    /// When that allowance resets (RFC 3339, UTC): the same instant
    /// `Retry-After` counts down to.
    // chrono's serde form — `Z`, whole seconds (every window ends on one) —
    // the same one the relay's `limit` event carries.
    pub resets_at: DateTime<Utc>,
}

impl VoiceLimitBody {
    /// The body for `limit`.
    #[must_use]
    pub fn new(limit: &LimitReached) -> VoiceLimitBody {
        VoiceLimitBody {
            detail: LIMIT_REACHED_DETAIL,
            scope: limit.scope,
            resets_at: limit.resets_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stt::{Encoding, PROTOCOL_DEFAULT_RATES};

    fn limit(mask: i64, at: &str) -> LimitReached {
        LimitReached::from_mask(
            mask,
            DateTime::parse_from_rfc3339(at)
                .expect("an instant")
                .with_timezone(&Utc),
        )
        .expect("a spent window")
    }

    fn eight() -> VoiceCatalog {
        VoiceCatalog::identity(
            [
                "Jason", "Hazel", "Casey", "Nadia", "Brian", "Imogen", "Liam", "Evan",
            ],
            "Jason",
        )
        .expect("the eight")
    }

    fn protocol_formats() -> Vec<AudioFormat> {
        PROTOCOL_DEFAULT_RATES
            .into_iter()
            .map(AudioFormat::pcm_s16le)
            .collect()
    }

    /// One of every refusal, built from both apps' current facts.
    fn every_refusal() -> Vec<VoiceRefusal> {
        vec![
            VoiceRefusal::not_configured(),
            VoiceRefusal::unavailable(),
            VoiceRefusal::limit_reached(&limit(7, "2026-10-17T12:00:00Z")),
            VoiceRefusal::reopened_too_soon(2),
            VoiceRefusal::upgrade_required(),
            VoiceRefusal::bad_rate(&protocol_formats()),
            VoiceRefusal::bad_encoding(&protocol_formats()),
            VoiceRefusal::body_too_large(DEFAULT_BODY_BYTES),
            VoiceRefusal::not_json(),
            VoiceRefusal::invalid_body(),
            VoiceRefusal::unknown_voice(&eight()),
            VoiceRefusal::empty_text(),
            VoiceRefusal::text_too_long(600),
            VoiceRefusal::bad_idempotency_key(),
            VoiceRefusal::key_reused(),
            VoiceRefusal::provider_unavailable(),
            VoiceRefusal::provider_error(),
        ]
    }

    /// Every refusal body is the JSON it claims to be, with a string
    /// `detail`, and each kind has its one status.
    #[test]
    fn every_refusal_body_is_a_json_detail() {
        let refusals = every_refusal();
        assert_eq!(refusals.len(), 17, "one of every kind");
        for refusal in refusals {
            let value: serde_json::Value = serde_json::from_slice(refusal.body()).expect("JSON");
            assert!(value["detail"].is_string(), "{:?}: {value}", refusal.kind());
        }
    }

    /// Each refusal's status, kind and body, byte for byte: the literals both
    /// apps answer today, the derived ones included (rendered from today's
    /// facts: the eight voices, 600 characters, 4 KiB, 24 and 16 kHz).
    #[test]
    fn the_derived_bodies_equal_todays_literals() {
        let expected: [(RefusalKind, u16, &str); 17] = [
            (
                RefusalKind::NotConfigured,
                503,
                r#"{"detail":"voice beta not configured"}"#,
            ),
            (
                RefusalKind::Unavailable,
                503,
                r#"{"detail":"voice beta unavailable"}"#,
            ),
            (
                RefusalKind::LimitReached,
                429,
                r#"{"detail":"voice beta limit reached","scope":"user_month","resets_at":"2026-11-01T00:00:00Z"}"#,
            ),
            (
                RefusalKind::ReopenedTooSoon,
                429,
                r#"{"detail":"voice stream reopened too soon"}"#,
            ),
            (
                RefusalKind::UpgradeRequired,
                426,
                r#"{"detail":"expected a WebSocket upgrade"}"#,
            ),
            (
                RefusalKind::BadRate,
                422,
                r#"{"detail":"rate must be 24000 or 16000"}"#,
            ),
            (
                RefusalKind::BadEncoding,
                422,
                r#"{"detail":"encoding must be pcm_s16le"}"#,
            ),
            (
                RefusalKind::BodyTooLarge,
                413,
                r#"{"detail":"request body over 4 KiB"}"#,
            ),
            (
                RefusalKind::NotJson,
                415,
                r#"{"detail":"expected an application/json body"}"#,
            ),
            (
                RefusalKind::InvalidBody,
                422,
                r#"{"detail":"expected a JSON object with a string text and an optional voice"}"#,
            ),
            (
                RefusalKind::UnknownVoice,
                422,
                r#"{"detail":"unknown voice; expected one of Jason, Hazel, Casey, Nadia, Brian, Imogen, Liam, Evan"}"#,
            ),
            (RefusalKind::EmptyText, 422, r#"{"detail":"text is empty"}"#),
            (
                RefusalKind::TextTooLong,
                422,
                r#"{"detail":"text is over 600 characters"}"#,
            ),
            (
                RefusalKind::BadIdempotencyKey,
                422,
                r#"{"detail":"Idempotency-Key must be sent once, as 1 to 64 characters of A-Z, a-z, 0-9, _ and -"}"#,
            ),
            (
                RefusalKind::IdempotencyKeyReused,
                422,
                r#"{"detail":"Idempotency-Key was already used for another sentence"}"#,
            ),
            (
                RefusalKind::ProviderUnavailable,
                503,
                r#"{"detail":"voice provider unavailable"}"#,
            ),
            (
                RefusalKind::ProviderError,
                502,
                r#"{"detail":"voice provider error"}"#,
            ),
        ];
        for (refusal, (kind, status, body)) in every_refusal().into_iter().zip(expected) {
            assert_eq!(refusal.kind(), kind);
            assert_eq!(refusal.status().as_u16(), status, "{kind:?}");
            assert_eq!(std::str::from_utf8(refusal.body()), Ok(body), "{kind:?}");
        }
    }

    /// The derived bodies follow the facts: one, two and three rates (the
    /// formats' order), each encoding once, another body bound, another
    /// text bound, another catalog.
    #[test]
    fn the_derived_bodies_follow_the_apps_facts() {
        let detail = |refusal: VoiceRefusal| {
            let value: serde_json::Value = serde_json::from_slice(refusal.body()).expect("JSON");
            value["detail"].as_str().expect("a detail").to_string()
        };
        let pcm = |rates: &[u32]| -> Vec<AudioFormat> {
            rates.iter().copied().map(AudioFormat::pcm_s16le).collect()
        };
        assert_eq!(
            detail(VoiceRefusal::bad_rate(&pcm(&[16_000]))),
            "rate must be 16000"
        );
        assert_eq!(
            detail(VoiceRefusal::bad_rate(&pcm(&[48_000, 24_000, 16_000]))),
            "rate must be 48000, 24000 or 16000"
        );
        assert_eq!(
            detail(VoiceRefusal::bad_encoding(&pcm(&[48_000, 24_000, 16_000]))),
            format!("encoding must be {}", Encoding::PcmS16le.wire_name())
        );
        assert_eq!(
            detail(VoiceRefusal::body_too_large(12_256)),
            "request body over 12256 bytes"
        );
        assert_eq!(
            detail(VoiceRefusal::text_too_long(2_000)),
            "text is over 2000 characters"
        );
        let two = VoiceCatalog::identity(["calm", "bright"], "calm").expect("two voices");
        assert_eq!(
            detail(VoiceRefusal::unknown_voice(&two)),
            "unknown voice; expected one of calm, bright"
        );
    }

    /// The budget's `429`: the unchanged `detail` FIRST (a client that reads
    /// only it reads what it always has), then the scope and the reset, and
    /// `Retry-After` to that same instant; the limit itself is kept for the
    /// app's log line.
    #[test]
    fn the_limit_body_keeps_its_detail_and_adds_the_scope() {
        for (mask, at, body, retry_after) in [
            (
                1,
                "2026-10-17T23:00:00Z",
                r#"{"detail":"voice beta limit reached","scope":"user_day","resets_at":"2026-10-18T00:00:00Z"}"#,
                3_600,
            ),
            (
                5,
                "2026-10-31T23:00:00Z",
                r#"{"detail":"voice beta limit reached","scope":"user_month","resets_at":"2026-11-01T00:00:00Z"}"#,
                3_600,
            ),
            (
                2,
                "2026-12-31T23:59:59Z",
                r#"{"detail":"voice beta limit reached","scope":"global_month","resets_at":"2027-01-01T00:00:00Z"}"#,
                1,
            ),
        ] {
            let spent = limit(mask, at);
            let refusal = VoiceRefusal::limit_reached(&spent);
            assert_eq!(refusal.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(refusal.retry_after(), Some(retry_after), "{at}");
            assert_eq!(
                refusal.headers().get(RETRY_AFTER),
                Some(&HeaderValue::from(retry_after))
            );
            assert_eq!(std::str::from_utf8(refusal.body()), Ok(body));
            assert_eq!(refusal.limit(), Some(&spent));
        }
    }

    /// Only the retryable refusals carry `Retry-After` (the configuration
    /// `503` does not: waiting configures nothing), and only the `426`
    /// carries `Upgrade: websocket`. No refusal carries any other header.
    #[test]
    fn only_the_retryable_refusals_carry_retry_after() {
        for refusal in every_refusal() {
            let headers = refusal.headers();
            let expected_retry: Option<u64> = match refusal.kind() {
                RefusalKind::Unavailable | RefusalKind::ProviderUnavailable => Some(5),
                RefusalKind::ReopenedTooSoon => Some(2),
                RefusalKind::LimitReached => {
                    Some(refusal.limit().expect("a limit").retry_after_seconds)
                }
                _ => None,
            };
            assert_eq!(
                refusal.retry_after(),
                expected_retry,
                "{:?}",
                refusal.kind()
            );
            assert_eq!(
                headers.get(RETRY_AFTER),
                expected_retry.map(HeaderValue::from).as_ref(),
                "{:?}",
                refusal.kind()
            );
            let upgrade = refusal.kind() == RefusalKind::UpgradeRequired;
            assert_eq!(
                headers.get(UPGRADE),
                upgrade
                    .then(|| HeaderValue::from_static("websocket"))
                    .as_ref(),
                "{:?}",
                refusal.kind()
            );
            let expected_len = usize::from(expected_retry.is_some()) + usize::from(upgrade);
            assert_eq!(headers.len(), expected_len, "{:?}", refusal.kind());
            assert_eq!(
                refusal.limit().is_some(),
                refusal.kind() == RefusalKind::LimitReached
            );
        }
    }

    /// The app's envelope writes the status and the body (and its own
    /// headers); the refusal's headers are set on top, replacing any the
    /// envelope set under the same name.
    #[cfg(feature = "axum")]
    #[tokio::test]
    async fn the_refusal_renders_through_the_apps_envelope() {
        let envelope = |status: StatusCode, body: bytes::Bytes| {
            axum::response::Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, "application/json")
                .header(RETRY_AFTER, "999")
                .body(axum::body::Body::from(body))
                .expect("a response")
        };
        let response = VoiceRefusal::unavailable().into_response_with(envelope);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(http::header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            response
                .headers()
                .get_all(RETRY_AFTER)
                .iter()
                .collect::<Vec<_>>(),
            [&HeaderValue::from_static("5")]
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a buffered body");
        assert_eq!(&body[..], br#"{"detail":"voice beta unavailable"}"#);

        let response = VoiceRefusal::upgrade_required().into_response_with(envelope);
        assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
        assert_eq!(
            response.headers().get(UPGRADE),
            Some(&HeaderValue::from_static("websocket"))
        );
        let derived = VoiceRefusal::unknown_voice(&eight()).into_response_with(envelope);
        let body = axum::body::to_bytes(derived.into_body(), usize::MAX)
            .await
            .expect("a buffered body");
        assert_eq!(
            &body[..],
            br#"{"detail":"unknown voice; expected one of Jason, Hazel, Casey, Nadia, Brian, Imogen, Liam, Evan"}"#
        );
    }
}
