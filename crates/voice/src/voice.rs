//! [`Voice`]: one app's voice, assembled from the parts it injects and
//! checked once, at startup, against revision 1 of the protocol.
//!
//! An app builds a `Voice` from its [`VoiceParts`] (its two provider
//! adapters, its catalog, its budgets with its prefixes and caps, the relay's
//! clocks, its usage sink) and holds it for the process's life, shared as an
//! `Arc`. [`Voice::new`] is the one fallible step, and what it checks are
//! code facts (the adapters' constants and the app's catalog), not
//! deployment configuration: an app tests that its own parts pass and
//! `expect`s at startup. Built, a `Voice` is infallible; the two flows (the
//! text-to-speech request and the stream's admission, behind `axum`) are its
//! methods.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use stridelabs_redis::RedisHandle;

#[cfg(feature = "axum")]
use uuid::Uuid;

use crate::budget::TtsBudget;
#[cfg(feature = "axum")]
use crate::budget::{BudgetError, Disposition, Fingerprint};
use crate::lease::{StreamBudget, LEASE_TTL};
use crate::protocol::{ALLOWED_AUDIO_TYPES, TTS_MIN_TEXT_CHARS};
#[cfg(feature = "axum")]
use crate::refusal::VoiceRefusal;
use crate::stt::{
    SttProvider, MAX_SAMPLE_RATE, MIN_PACING_LEAD, MIN_SAMPLE_RATE, PROTOCOL_DEFAULT_RATES,
};
#[cfg(feature = "axum")]
use crate::tts::{charge_key, read_request, Audio, SynthesisRequest, TtsFailure};
use crate::tts::{TtsProvider, VoiceCatalog};
use crate::usage::UsageSink;
#[cfg(feature = "axum")]
use crate::usage::VoiceMetric;

/// The relay's clocks. [`RelaySettings::default`] is both apps' production
/// set, and [`RelaySettings::check`] holds any other to revision 1's bounds,
/// which the installed clients' fixed timers set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelaySettings {
    /// The longest a session runs, before a budget window that runs out
    /// first shortens it: 15 minutes.
    pub session_cap: Duration,
    /// The longest the client may go without an audio frame (or let its
    /// audio fall behind real time) before `end`: 10 s.
    pub idle_timeout: Duration,
    /// How often the lease is refreshed and the audio charged: 10 s.
    pub refresh_interval: Duration,
    /// The provider's dial, handshake and ready, together: 8 s.
    pub open_timeout: Duration,
    /// How often the client is pinged: 10 s.
    pub ping_interval: Duration,
    /// How long the client may go without a pong: 25 s.
    pub pong_deadline: Duration,
    /// The bound on each write and each close: 2 s.
    pub close_timeout: Duration,
    /// How long the provider has to finish after the end of input: 2 s.
    pub end_timeout: Duration,
    /// How soon after one upgrade the same user may open another: 2 s
    /// (a `429` before it). What keeps a reconnect loop from dialling the
    /// provider, and superseding itself, as fast as it can spin.
    pub admit_interval: Duration,
}

impl Default for RelaySettings {
    fn default() -> RelaySettings {
        RelaySettings {
            session_cap: Duration::from_secs(15 * 60),
            idle_timeout: Duration::from_secs(10),
            refresh_interval: Duration::from_secs(10),
            open_timeout: Duration::from_secs(8),
            ping_interval: Duration::from_secs(10),
            pong_deadline: Duration::from_secs(25),
            close_timeout: Duration::from_secs(2),
            end_timeout: Duration::from_secs(2),
            admit_interval: Duration::from_secs(2),
        }
    }
}

/// The longest `open_timeout + close_timeout` may be: `ready` is written
/// within it, and the reference client waits 12 s.
const MAX_READY_DELAY: Duration = Duration::from_secs(10);

/// The longest `admit_interval` may be: the reference client retries a
/// refused upgrade after 2.1 s.
const MAX_ADMIT_INTERVAL: Duration = Duration::from_secs(2);

/// The longest `end_timeout` may be: the reference client waits 2 s for the
/// close after `end`, then closes itself.
const MAX_END_TIMEOUT: Duration = Duration::from_secs(2);

/// The shortest `idle_timeout` may be: the protocol's idle rule, which the
/// reference client keeps by filling a capture stall over 2 s with silence.
const MIN_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

impl RelaySettings {
    /// Revision 1's bounds (`PROTOCOL.md` §2.4), each tied to a fixed timer
    /// of the installed clients, and the lease's margin, checked in this
    /// order: every duration non-zero (a zero interval panics the relay's
    /// timers); `open_timeout + close_timeout` at most 10 s; `admit_interval`
    /// at most 2 s; `end_timeout` at most 2 s; `idle_timeout` at least 10 s;
    /// `pong_deadline` over `ping_interval`; then the lease
    /// ([`LEASE_TTL`], 30 s from the acquire; the first refresh comes
    /// `refresh_interval` after `ready`):
    ///
    /// - `open_timeout + close_timeout + refresh_interval` under the lease:
    ///   the first refresh lands before the lease lapses even after the
    ///   slowest open the clocks allow (the open, then the `ready` write, each
    ///   at its bound);
    /// - `refresh_interval` at most a third of the lease: three refreshes per
    ///   lease, so from the first good refresh on, one refresh that fails
    ///   never costs the lease.
    ///
    /// # Errors
    ///
    /// [`VoiceSetupError::RelaySettingOutOfRange`] naming the first setting
    /// (or sum of settings) out of bounds: `open_timeout + close_timeout +
    /// refresh_interval` or `refresh_interval` for the lease's two.
    pub fn check(&self) -> Result<(), VoiceSetupError> {
        self.check_non_zero()?;
        let out_of_range = |setting| Err(VoiceSetupError::RelaySettingOutOfRange { setting });
        let RelaySettings {
            idle_timeout,
            refresh_interval,
            open_timeout,
            ping_interval,
            pong_deadline,
            close_timeout,
            end_timeout,
            admit_interval,
            ..
        } = *self;
        if open_timeout.saturating_add(close_timeout) > MAX_READY_DELAY {
            return out_of_range("open_timeout + close_timeout");
        }
        if admit_interval > MAX_ADMIT_INTERVAL {
            return out_of_range("admit_interval");
        }
        if end_timeout > MAX_END_TIMEOUT {
            return out_of_range("end_timeout");
        }
        if idle_timeout < MIN_IDLE_TIMEOUT {
            return out_of_range("idle_timeout");
        }
        if pong_deadline <= ping_interval {
            return out_of_range("pong_deadline");
        }
        // The lease's margin (tapper's: three refreshes per lease, and the
        // first one inside the lease after the slowest open). Before it, a 29 s
        // refresh passed: after a 5 s open its first refresh came at 34 s, past
        // the lease, and a healthy session closed `4001` with no takeover.
        if open_timeout
            .saturating_add(close_timeout)
            .saturating_add(refresh_interval)
            >= LEASE_TTL
        {
            return out_of_range("open_timeout + close_timeout + refresh_interval");
        }
        if refresh_interval.saturating_mul(3) > LEASE_TTL {
            return out_of_range("refresh_interval");
        }
        Ok(())
    }

    /// The one rule a test's clocks are held to as well: no zero duration.
    fn check_non_zero(&self) -> Result<(), VoiceSetupError> {
        let RelaySettings {
            session_cap,
            idle_timeout,
            refresh_interval,
            open_timeout,
            ping_interval,
            pong_deadline,
            close_timeout,
            end_timeout,
            admit_interval,
        } = *self;
        for (setting, value) in [
            ("session_cap", session_cap),
            ("idle_timeout", idle_timeout),
            ("refresh_interval", refresh_interval),
            ("open_timeout", open_timeout),
            ("ping_interval", ping_interval),
            ("pong_deadline", pong_deadline),
            ("close_timeout", close_timeout),
            ("end_timeout", end_timeout),
            ("admit_interval", admit_interval),
        ] {
            if value.is_zero() {
                return Err(VoiceSetupError::RelaySettingOutOfRange { setting });
            }
        }
        Ok(())
    }
}

/// Why [`Voice::new`] refused its parts: a fact of an adapter, the catalog
/// or the relay's clocks that revision 1 of the protocol does not allow.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VoiceSetupError {
    /// The text-to-speech adapter's media type is not one the protocol
    /// allows.
    #[error("text to speech: the media type {media_type:?} is not one the protocol allows")]
    MediaTypeNotAllowed {
        /// The adapter's media type.
        media_type: &'static str,
    },
    /// The text-to-speech adapter's text bound is under the protocol's
    /// minimum.
    #[error(
        "text to speech: a text bound of {max_text_chars} characters is under the protocol's \
         minimum of 600"
    )]
    TextBoundBelowMinimum {
        /// The adapter's bound.
        max_text_chars: usize,
    },
    /// The text-to-speech adapter does not have the voice the catalog maps
    /// `app_voice` to.
    #[error("text to speech: the provider has no voice for the catalog's {app_voice:?}")]
    UnknownProviderVoice {
        /// The catalog's app id.
        app_voice: String,
    },
    /// The speech-to-text adapter offers no format.
    #[error("speech to text: the provider offers no audio format")]
    NoAudioFormats,
    /// The speech-to-text adapter offers one sample rate twice.
    #[error("speech to text: {sample_rate} Hz is offered twice")]
    DuplicateAudioFormat {
        /// The repeated rate.
        sample_rate: u32,
    },
    /// A speech-to-text sample rate outside 8,000–48,000 Hz.
    #[error("speech to text: {sample_rate} Hz is outside 8000 to 48000 Hz")]
    SampleRateOutOfRange {
        /// The rate.
        sample_rate: u32,
    },
    /// The speech-to-text adapter does not take a rate revision 1 requires
    /// of every provider (24,000 and 16,000 Hz).
    #[error(
        "speech to text: the provider does not take {sample_rate} Hz, which the protocol requires"
    )]
    MissingProtocolRate {
        /// The missing rate.
        sample_rate: u32,
    },
    /// The speech-to-text adapter's pacing lead is under the protocol's
    /// minimum (5 s).
    #[error("speech to text: a pacing lead of {lead:?} is under the protocol's minimum of 5 s")]
    PacingLeadTooShort {
        /// The adapter's lead.
        lead: Duration,
    },
    /// A relay setting outside revision 1's bounds or the lease's margin
    /// ([`RelaySettings::check`]).
    #[error("relay setting {setting} is outside the protocol's bounds")]
    RelaySettingOutOfRange {
        /// The setting, or the sum of settings, out of bounds (the lease's
        /// two: `open_timeout + close_timeout + refresh_interval`, and
        /// `refresh_interval` against three per lease).
        setting: &'static str,
    },
}

/// Everything an app injects to build its [`Voice`].
pub struct VoiceParts<S, T> {
    /// The speech-to-text adapter.
    pub stt: S,
    /// The text-to-speech adapter.
    pub tts: T,
    /// The app's voices.
    pub catalog: VoiceCatalog,
    /// The character budget, under the app's prefix and caps.
    pub tts_budget: TtsBudget,
    /// The audio budget and lease, under the app's prefix and caps.
    pub stream_budget: StreamBudget,
    /// The relay's clocks.
    pub relay: RelaySettings,
    /// Where usage is reported.
    pub usage: Arc<dyn UsageSink>,
}

/// One app's voice: its adapters, catalog, budgets and clocks, checked
/// (module docs).
pub struct Voice<S: SttProvider, T: TtsProvider> {
    stt: S,
    tts: T,
    catalog: VoiceCatalog,
    tts_budget: TtsBudget,
    stream_budget: StreamBudget,
    relay: RelaySettings,
    // The flows report usage, and both are behind `axum`.
    #[cfg_attr(
        not(feature = "axum"),
        expect(
            dead_code,
            reason = "the voice flows, which report usage, are behind `axum`"
        )
    )]
    usage: Arc<dyn UsageSink>,
    /// The relay sessions live on this instance, one per user.
    #[cfg(feature = "axum")]
    live: crate::relay::LiveSessions,
}

/// What the stream's admission needs of the app besides the request
/// ([`Voice::open_stream`]): its Redis, and its shutdown.
#[cfg(feature = "axum")]
#[derive(Debug, Clone, Copy)]
pub struct StreamContext<'a> {
    /// The app's Redis handle; `None` (no Redis configured) is the
    /// configuration `503`.
    pub redis: Option<&'a RedisHandle>,
    /// Cancelled when the app begins to shut down: every live session then
    /// closes `1001`, after its release.
    pub shutdown: &'a tokio_util::sync::CancellationToken,
    /// What the app's drain waits on: an admitted session holds one of its
    /// tokens from before the upgrade until the session (or the release of
    /// an upgrade that failed) is done.
    pub tracker: &'a tokio_util::task::TaskTracker,
}

/// What [`Voice::speak`] answered: the audio or the refusal, and the text
/// bound every answer advertises. The app renders it with its own envelope
/// ([`TtsReply::into_response_with`]).
#[cfg(feature = "axum")]
#[derive(Debug)]
pub struct TtsReply {
    /// The provider's text bound: the `X-Voice-Tts-Max-Chars` value.
    pub max_text_chars: usize,
    /// The spoken sentence, or why not.
    pub outcome: Result<Audio, VoiceRefusal>,
}

#[cfg(feature = "axum")]
impl TtsReply {
    /// The response. A `200` is the audio, one body of its exact length,
    /// `Content-Type` its media type and `Cache-Control: no-store` (the bytes
    /// are one user's reply; no cache between client and server keeps
    /// them). A refusal is the app's `envelope` of its status and body, then
    /// its headers ([`VoiceRefusal::into_response_with`]). Both carry
    /// `X-Voice-Tts-Max-Chars`.
    pub fn into_response_with(
        self,
        envelope: impl FnOnce(http::StatusCode, bytes::Bytes) -> axum::response::Response,
    ) -> axum::response::Response {
        use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
        use http::HeaderValue;

        let mut response = match self.outcome {
            Ok(audio) => {
                let length = audio.bytes.len();
                let mut response =
                    axum::response::Response::new(axum::body::Body::from(audio.bytes));
                let headers = response.headers_mut();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static(audio.media_type));
                headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
                headers.insert(CONTENT_LENGTH, HeaderValue::from(length));
                response
            }
            Err(refusal) => refusal.into_response_with(envelope),
        };
        response.headers_mut().insert(
            crate::protocol::TTS_MAX_CHARS_HEADER,
            HeaderValue::from(self.max_text_chars),
        );
        response
    }
}

/// The parts' own redacting `Debug`s (an adapter's never prints its key or a
/// URL credential); the usage sink by name only.
impl<S, T> fmt::Debug for Voice<S, T>
where
    S: SttProvider + fmt::Debug,
    T: TtsProvider + fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Voice")
            .field("stt", &self.stt)
            .field("tts", &self.tts)
            .field("catalog", &self.catalog)
            .field("tts_budget", &self.tts_budget)
            .field("stream_budget", &self.stream_budget)
            .field("relay", &self.relay)
            .finish_non_exhaustive()
    }
}

impl<S: SttProvider, T: TtsProvider> Voice<S, T> {
    /// The app's voice, once its parts pass revision 1's checks, in this
    /// order: the relay's clocks ([`RelaySettings::check`]); the
    /// speech-to-text adapter's formats (at least one; each rate within
    /// 8,000–48,000 Hz and offered once; both 24,000 and 16,000 Hz among
    /// them) and its pacing lead (at least 5 s); the text-to-speech adapter's
    /// media type (an allowed one), its text bound (at least 600) and every
    /// voice the catalog maps to (none the adapter says it lacks). Whether
    /// either adapter is configured is not checked: an unconfigured one is
    /// the routes' `503`, not a startup failure.
    ///
    /// # Errors
    ///
    /// The first check that fails, as a [`VoiceSetupError`].
    pub fn new(parts: VoiceParts<S, T>) -> Result<Voice<S, T>, VoiceSetupError> {
        let VoiceParts {
            stt,
            tts,
            catalog,
            tts_budget,
            stream_budget,
            relay,
            usage,
        } = parts;
        relay.check()?;
        check_stt(&stt)?;
        check_tts(&tts, &catalog)?;
        Ok(Voice {
            stt,
            tts,
            catalog,
            tts_budget,
            stream_budget,
            relay,
            usage,
            #[cfg(feature = "axum")]
            live: crate::relay::LiveSessions::default(),
        })
    }

    /// The speech-to-text adapter.
    #[must_use]
    pub fn stt(&self) -> &S {
        &self.stt
    }

    /// The text-to-speech adapter.
    #[must_use]
    pub fn tts(&self) -> &T {
        &self.tts
    }

    /// The app's voices.
    #[must_use]
    pub fn catalog(&self) -> &VoiceCatalog {
        &self.catalog
    }

    /// The character budget the text-to-speech route charges.
    #[must_use]
    pub fn tts_budget(&self) -> &TtsBudget {
        &self.tts_budget
    }

    /// The audio budget and lease the stream charges.
    #[must_use]
    pub fn stream_budget(&self) -> &StreamBudget {
        &self.stream_budget
    }

    /// The relay's clocks.
    #[must_use]
    pub fn relay_settings(&self) -> RelaySettings {
        self.relay
    }

    /// Whether the text-to-speech route can speak at all: its adapter is
    /// configured and the app has a Redis. `false` is its `503`.
    #[must_use]
    pub fn tts_configured(&self, redis: Option<&RedisHandle>) -> bool {
        self.tts.configured() && redis.is_some()
    }

    /// Whether the stream can open a session at all: its adapter is
    /// configured and the app has a Redis. `false` is its `503`.
    #[must_use]
    pub fn stream_configured(&self, redis: Option<&RedisHandle>) -> bool {
        self.stt.configured() && redis.is_some()
    }

    /// Where usage is reported (the relay's audio, at each session's end).
    #[cfg(feature = "axum")]
    pub(crate) fn usage(&self) -> &dyn UsageSink {
        self.usage.as_ref()
    }

    /// Speak one sentence for `user`, whom the app authenticated: the
    /// text-to-speech route's whole flow after authentication, rendered by
    /// the app ([`TtsReply::into_response_with`]). In order:
    ///
    /// 1. the configuration (`503`, no `Retry-After`): the provider is not
    ///    configured, or there is no Redis; before anything about the
    ///    request;
    /// 2. the request (`tts::read_request`): `415`, `413` declared, `413`
    ///    read, then the `422`s of the shape, the voice, an empty text and a
    ///    text over the provider's bound;
    /// 3. the `Idempotency-Key` (`422`);
    /// 4. the charge, BEFORE the provider and never refunded: `429` (a
    ///    budget spent), `422` (the key names another sentence's charge) or
    ///    `503` + `Retry-After: 5` (Redis); a fresh charge is reported to the
    ///    usage sink, a replayed one is not;
    /// 5. the provider, once: the audio (`200`), `503` + `Retry-After: 5`
    ///    (unavailable) or `502` (a permanent failure, or audio of another
    ///    media type than the provider declared, logged at ERROR). The charge
    ///    stands either way, and a replayed admission is spoken again (the
    ///    key protects the budget, not provider spend).
    ///
    /// Every request that reaches the charge logs exactly one line (target
    /// `stridelabs_voice::voice`, message `voice tts…`): the user, the
    /// character count, the app voice, the status class, an outcome word, the
    /// charge's disposition and, once the provider was called, its latency.
    /// Never the text, the key or a body.
    #[cfg(feature = "axum")]
    pub async fn speak(
        &self,
        redis: Option<&RedisHandle>,
        user: Uuid,
        headers: &http::HeaderMap,
        body: axum::body::Body,
    ) -> TtsReply {
        TtsReply {
            max_text_chars: self.tts.max_text_chars(),
            outcome: self.speak_outcome(redis, user, headers, body).await,
        }
    }

    /// [`Voice::speak`]'s flow, its answer before the header.
    #[cfg(feature = "axum")]
    async fn speak_outcome(
        &self,
        redis: Option<&RedisHandle>,
        user: Uuid,
        headers: &http::HeaderMap,
        body: axum::body::Body,
    ) -> Result<Audio, VoiceRefusal> {
        // 503: the configuration, before anything about the request.
        let Some(redis) = redis.filter(|_| self.tts.configured()) else {
            return Err(VoiceRefusal::not_configured());
        };
        let max_text_chars = self.tts.max_text_chars();

        // 415 / 413 / 422: the request, then its Idempotency-Key.
        let request = read_request(headers, body, &self.catalog, max_text_chars).await?;
        let Some(key) = charge_key(headers) else {
            return Err(VoiceRefusal::bad_idempotency_key());
        };
        // The parse accepted the voice from this catalog, so it maps. A
        // catalog that did not would be this service's bug, answered as the
        // voice's 422 rather than a panic.
        let Some(provider_voice) = self.catalog.provider_voice(&request.app_voice) else {
            return Err(VoiceRefusal::unknown_voice(&self.catalog));
        };
        let chars = request.chars;
        let voice = request.app_voice.as_str();

        // 429 / 422 / 503: the budget, charged BEFORE the provider and never
        // refunded. The charge is named by the sentence's Idempotency-Key (or
        // a key minted for a request without one) and pinned to the sentence
        // by its fingerprint (the APP voice and the trimmed text): a retried
        // EVAL whose first answer was lost, and the client's retry of a
        // sentence whose answer never reached it, both replay this charge's
        // verdict rather than charging again.
        let fingerprint = Fingerprint::of(voice, &request.text);
        let disposition = match self
            .tts_budget
            .charge(redis, user, chars, &key, &fingerprint)
            .await
        {
            // The usage the app records is what a FRESH charge admitted, at
            // the instant it was decided, whatever the synthesis does next
            // (the charge stands either way). A replayed verdict never
            // counts: the run that charged it did.
            Ok(admitted) => {
                if admitted.disposition == Disposition::Fresh {
                    self.usage.record(
                        user,
                        VoiceMetric::TtsCharacters,
                        u64::try_from(chars).unwrap_or(u64::MAX),
                        admitted.at,
                    );
                }
                admitted.disposition
            }
            Err(BudgetError::KeyReused) => {
                tracing::info!(
                    user_id = %user,
                    chars,
                    voice,
                    status_class = "4xx",
                    outcome = "key_reused",
                    "voice tts: the Idempotency-Key names another sentence's charge; nothing charged"
                );
                return Err(VoiceRefusal::key_reused());
            }
            Err(BudgetError::Exceeded(limit)) => {
                tracing::info!(
                    user_id = %user,
                    chars,
                    voice,
                    status_class = "4xx",
                    outcome = "budget",
                    scope = limit.scope.as_str(),
                    user_day_spent = limit.spent.user_day,
                    user_month_spent = limit.spent.user_month,
                    global_month_spent = limit.spent.global_month,
                    retry_after_seconds = limit.retry_after_seconds,
                    "voice tts: budget spent; nothing charged"
                );
                return Err(VoiceRefusal::limit_reached(&limit));
            }
            Err(failure @ BudgetError::Backend(_)) => {
                tracing::warn!(
                    user_id = %user,
                    chars,
                    voice,
                    status_class = "5xx",
                    outcome = "redis",
                    error = %failure,
                    "voice tts: the budget could not be charged"
                );
                return Err(VoiceRefusal::unavailable());
            }
        };
        let charge = match disposition {
            Disposition::Fresh => "fresh",
            Disposition::Replayed => "replayed",
        };

        // The provider. ACCEPTED: a REPLAYED admission is spoken again; the
        // first request's audio was never kept, and a client asks again only
        // when that answer never reached it. The key protects the budget
        // (charged once), not provider spend.
        let started = std::time::Instant::now();
        let outcome = self
            .tts
            .synthesize(&SynthesisRequest::new(&request.text, provider_voice))
            .await;
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match outcome {
            Ok(audio) if audio.media_type != self.tts.media_type() => {
                // The adapter broke its contract (`TtsProvider::media_type`):
                // a client checks the type it plays, so this is never a 200.
                // Both types are the adapter's constants, safe to log.
                tracing::error!(
                    user_id = %user,
                    chars,
                    voice,
                    status_class = "5xx",
                    outcome = "provider_media_type",
                    charge,
                    latency_ms,
                    declared = self.tts.media_type(),
                    answered = audio.media_type,
                    "voice tts: the provider answered another media type than it declares; the \
                     charge stands"
                );
                Err(VoiceRefusal::provider_error())
            }
            Ok(audio) => {
                tracing::info!(
                    user_id = %user,
                    chars,
                    voice,
                    status_class = "2xx",
                    outcome = "spoken",
                    charge,
                    latency_ms,
                    audio_bytes = audio.bytes.len(),
                    "voice tts"
                );
                Ok(audio)
            }
            Err(failure) => {
                let (outcome, class, refusal) = match failure {
                    TtsFailure::Unavailable(class) => (
                        "provider_unavailable",
                        class,
                        VoiceRefusal::provider_unavailable(),
                    ),
                    TtsFailure::Permanent(class) => {
                        ("provider_error", class, VoiceRefusal::provider_error())
                    }
                };
                tracing::warn!(
                    user_id = %user,
                    chars,
                    voice,
                    status_class = "5xx",
                    outcome,
                    charge,
                    latency_ms,
                    error = %class,
                    "voice tts: the synthesis failed; the charge stands"
                );
                Err(refusal)
            }
        }
    }

    /// The relay sessions live on this instance, by user.
    #[cfg(feature = "axum")]
    pub(crate) fn live_sessions(&self) -> &crate::relay::LiveSessions {
        &self.live
    }

    /// How many relay sessions are live on this instance: a session is
    /// counted from its admission (before the upgrade) until its close
    /// began.
    #[cfg(all(feature = "test-support", feature = "axum"))]
    #[must_use]
    pub fn live_session_count(&self) -> usize {
        self.live.len()
    }

    /// The same voice on other clocks, held only to the non-zero rule (a
    /// zero duration panics the relay's timers): the test seam for clocks
    /// shorter than [`RelaySettings::check`] allows (a 300 ms idle, a
    /// one-second session cap) on real sockets.
    ///
    /// # Panics
    ///
    /// On a zero duration, naming the setting.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn with_relay_settings_unchecked(self, relay: RelaySettings) -> Voice<S, T> {
        if let Err(refusal) = relay.check_non_zero() {
            panic!("{refusal}: a test's clocks are non-zero too");
        }
        Voice { relay, ..self }
    }
}

/// The speech-to-text adapter's facts (`Voice::new`'s second step). Every
/// format is PCM s16le by construction in revision 1 (`Encoding` has no
/// other value), so the encoding needs no check of its own yet.
fn check_stt(stt: &impl SttProvider) -> Result<(), VoiceSetupError> {
    let formats = stt.formats();
    if formats.is_empty() {
        return Err(VoiceSetupError::NoAudioFormats);
    }
    for (index, format) in formats.iter().enumerate() {
        let sample_rate = format.sample_rate;
        if !(MIN_SAMPLE_RATE..=MAX_SAMPLE_RATE).contains(&sample_rate) {
            return Err(VoiceSetupError::SampleRateOutOfRange { sample_rate });
        }
        if formats[..index]
            .iter()
            .any(|earlier| earlier.sample_rate == sample_rate)
        {
            return Err(VoiceSetupError::DuplicateAudioFormat { sample_rate });
        }
    }
    for sample_rate in PROTOCOL_DEFAULT_RATES {
        if !formats
            .iter()
            .any(|format| format.sample_rate == sample_rate)
        {
            return Err(VoiceSetupError::MissingProtocolRate { sample_rate });
        }
    }
    let lead = stt.pacing_lead();
    if lead < MIN_PACING_LEAD {
        return Err(VoiceSetupError::PacingLeadTooShort { lead });
    }
    Ok(())
}

/// The text-to-speech adapter's facts against the catalog (`Voice::new`'s
/// third step).
fn check_tts(tts: &impl TtsProvider, catalog: &VoiceCatalog) -> Result<(), VoiceSetupError> {
    let media_type = tts.media_type();
    if !ALLOWED_AUDIO_TYPES.contains(&media_type) {
        return Err(VoiceSetupError::MediaTypeNotAllowed { media_type });
    }
    let max_text_chars = tts.max_text_chars();
    if max_text_chars < TTS_MIN_TEXT_CHARS {
        return Err(VoiceSetupError::TextBoundBelowMinimum { max_text_chars });
    }
    for (app_voice, provider_voice) in catalog.entries() {
        if tts.knows_voice(provider_voice) == Some(false) {
            return Err(VoiceSetupError::UnknownProviderVoice {
                app_voice: app_voice.to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The production clocks are both apps': 15 min, 10 s idle, refresh and
    /// ping, 8 s to open, 25 s for a pong, 2 s per write and close, 2 s
    /// after `end`, 2 s between upgrades; and they pass revision 1's check,
    /// the lease's margin included.
    #[test]
    fn the_production_clocks() {
        let settings = RelaySettings::default();
        assert_eq!(
            settings,
            RelaySettings {
                session_cap: Duration::from_secs(900),
                idle_timeout: Duration::from_secs(10),
                refresh_interval: Duration::from_secs(10),
                open_timeout: Duration::from_secs(8),
                ping_interval: Duration::from_secs(10),
                pong_deadline: Duration::from_secs(25),
                close_timeout: Duration::from_secs(2),
                end_timeout: Duration::from_secs(2),
                admit_interval: Duration::from_secs(2),
            }
        );
        assert_eq!(settings.check(), Ok(()));
        // Three refreshes per lease lifetime: one lost refresh never costs
        // the lease (tapper's); and the first refresh after the slowest open
        // lands inside the lease.
        assert!(LEASE_TTL >= settings.refresh_interval * 3);
        assert!(
            settings.open_timeout + settings.close_timeout + settings.refresh_interval < LEASE_TTL
        );
    }

    /// Each of revision 1's bounds, at its edge and just past it, one setting
    /// moved at a time from the production set; the first problem in
    /// `check`'s order is the one named.
    #[test]
    fn relay_settings_check_refuses_each_bound() {
        let ms = Duration::from_millis;
        let refused = |setting| Err(VoiceSetupError::RelaySettingOutOfRange { setting });
        let with = |change: fn(&mut RelaySettings, Duration), value: Duration| {
            let mut settings = RelaySettings::default();
            change(&mut settings, value);
            settings.check()
        };
        type Change = fn(&mut RelaySettings, Duration);
        let fields: [(&str, Change); 9] = [
            ("session_cap", |s, v| s.session_cap = v),
            ("idle_timeout", |s, v| s.idle_timeout = v),
            ("refresh_interval", |s, v| s.refresh_interval = v),
            ("open_timeout", |s, v| s.open_timeout = v),
            ("ping_interval", |s, v| s.ping_interval = v),
            ("pong_deadline", |s, v| s.pong_deadline = v),
            ("close_timeout", |s, v| s.close_timeout = v),
            ("end_timeout", |s, v| s.end_timeout = v),
            ("admit_interval", |s, v| s.admit_interval = v),
        ];
        for (setting, change) in fields {
            assert_eq!(
                with(change, Duration::ZERO),
                refused(setting),
                "{setting} zero"
            );
        }
        // Where zero is the only lower bound, 1 ms passes.
        for (setting, change) in fields {
            if !matches!(setting, "idle_timeout" | "pong_deadline") {
                assert_eq!(with(change, ms(1)), Ok(()), "{setting} at 1 ms");
            }
        }
        let set_open: Change = |s, v| s.open_timeout = v;
        let set_close: Change = |s, v| s.close_timeout = v;
        let set_admit: Change = |s, v| s.admit_interval = v;
        let set_end: Change = |s, v| s.end_timeout = v;
        let set_idle: Change = |s, v| s.idle_timeout = v;
        let set_pong: Change = |s, v| s.pong_deadline = v;
        let set_refresh: Change = |s, v| s.refresh_interval = v;
        for (change, edge, past, setting) in [
            // open 8 s + close 2 s is the 10 s edge.
            (
                set_open,
                ms(8_000),
                ms(8_001),
                "open_timeout + close_timeout",
            ),
            (
                set_close,
                ms(2_000),
                ms(2_001),
                "open_timeout + close_timeout",
            ),
            (set_admit, ms(2_000), ms(2_001), "admit_interval"),
            (set_end, ms(2_000), ms(2_001), "end_timeout"),
            (set_idle, ms(10_000), ms(9_999), "idle_timeout"),
            // ping is 10 s: the pong deadline must be longer.
            (set_pong, ms(10_001), ms(10_000), "pong_deadline"),
            // Three per lease: at most 10 s.
            (set_refresh, ms(10_000), ms(10_001), "refresh_interval"),
        ] {
            assert_eq!(with(change, edge), Ok(()), "{setting} at its edge");
            assert_eq!(with(change, past), refused(setting), "{setting} past it");
        }
        // The first refresh inside the lease after the slowest open: with an
        // 8 s open and a 2 s close, a 20 s refresh meets the 30 s lease and
        // is named by that rule (checked first); just under it, the
        // three-per-lease rule names it. A 29 s refresh, once accepted, is
        // refused.
        let lease_sum = "open_timeout + close_timeout + refresh_interval";
        assert_eq!(with(set_refresh, ms(20_000)), refused(lease_sum));
        assert_eq!(with(set_refresh, ms(19_999)), refused("refresh_interval"));
        assert_eq!(with(set_refresh, ms(29_000)), refused(lease_sum));
        // A fast open leaves the sum room; the third of a lease still binds.
        let fast_open = RelaySettings {
            open_timeout: ms(1_000),
            close_timeout: ms(1_000),
            ..RelaySettings::default()
        };
        assert_eq!(fast_open.check(), Ok(()));
        assert_eq!(
            RelaySettings {
                refresh_interval: ms(10_001),
                ..fast_open
            }
            .check(),
            refused("refresh_interval")
        );
        // Two problems: the first in check's order is named.
        let both = RelaySettings {
            end_timeout: ms(5_000),
            refresh_interval: ms(60_000),
            ..RelaySettings::default()
        };
        assert_eq!(both.check(), refused("end_timeout"));
        let three = RelaySettings {
            admit_interval: Duration::ZERO,
            ..both
        };
        assert_eq!(three.check(), refused("admit_interval"));
        // A sum past `Duration::MAX` is refused, not a panic.
        let huge = RelaySettings {
            open_timeout: Duration::MAX,
            ..RelaySettings::default()
        };
        assert_eq!(huge.check(), refused("open_timeout + close_timeout"));
    }
}
