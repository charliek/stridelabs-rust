//! `GET /voice/stream`'s admission (feature `axum`): every check before the
//! upgrade, then the upgrade, which hands the socket to one relay session
//! ([`crate::relay`]). Ported from tapper (`tapper-rs/src/voice/stream.rs`,
//! `82be95f`); the route itself — its path, its authentication, the `405`s,
//! its documentation — is the app's, which calls [`Voice::open_stream`]
//! with the user it authenticated.
//!
//! Every check happens BEFORE the upgrade, so a refusal is an ordinary HTTP
//! answer ([`VoiceRefusal`], rendered through the app's envelope):
//!
//! ```text
//! configuration     -> 503 {"detail":"voice beta not configured"}     the provider is not configured, or no Redis
//! not an upgrade    -> 426 {"detail":"expected a WebSocket upgrade"}  + Upgrade: websocket
//! ?rate=            -> 422 {"detail":"rate must be 24000 or 16000"}   the provider's rates; absent is its first
//! ?encoding=        -> 422 {"detail":"encoding must be pcm_s16le"}    the provider's encodings; absent is pcm_s16le
//! the lease         -> 503 + Retry-After: 5 (Redis down: a PING first, which replaces a
//!                                              cached connection that died idle)
//!                      503 + Retry-After: 5 (the ticket could not be issued: Redis down,
//!                                              or its reply lost)
//!                      503 + Retry-After: 5 (the ticket is stale: a newer upgrade for this
//!                                              user took one first)
//!                      429 {"detail":"voice beta limit reached","scope":…,"resets_at":…}
//!                          + Retry-After (a budget is spent)
//!                      429 {"detail":"voice stream reopened too soon"} + Retry-After: the
//!                          admission interval, rounded up
//!                      503 + Retry-After: 5 (Redis down)
//! ```
//!
//! Then `101`, and the session ([`crate::relay`]) owns the socket. The lease
//! is taken by the last check, so a session that is answered `101` already
//! holds it — and has superseded, at once, any session this instance was
//! running for the same user. One whose upgrade then fails releases it.
//!
//! **Admission fails closed**: a Redis error at the ping, the ticket or the
//! acquire is a `503`, because these budgets are the spending ceiling. An
//! open session does not: it keeps relaying through failed refreshes until a
//! lease's lifetime passes without a good one ([`crate::lease`]'s accepted
//! limits).

use std::sync::Arc;

use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::WebSocketUpgrade;
use axum::response::Response;
use uuid::Uuid;

use crate::lease::{MeterMode, StreamBudgetError};
use crate::protocol::{ENCODING_PARAM, MAX_FRAME_BYTES, RATE_PARAM};
use crate::refusal::VoiceRefusal;
use crate::relay::{self, Session, MAX_WRITE_BUFFER_BYTES, READ_BUFFER_BYTES};
use crate::stt::{AudioFormat, Encoding, SttProvider};
use crate::tts::TtsProvider;
use crate::{StreamContext, Voice};

/// The encoding an upgrade without `?encoding=` streams in: revision 1's
/// only one.
pub const DEFAULT_ENCODING: Encoding = Encoding::PcmS16le;

/// `?rate=`: absent is `formats[0]` (the provider's default); present
/// exactly once with one of the formats' rates, written as it is
/// (`24000`); anything else — another value, an empty one, a repeat — is
/// `None`. Other parameters are ignored, and the key is matched as written
/// (`rate`, not a percent-encoding of it).
#[must_use]
pub fn parse_rate(query: Option<&str>, formats: &[AudioFormat]) -> Option<AudioFormat> {
    match query_value(query, RATE_PARAM)? {
        None => formats.first().copied(),
        Some(value) => formats
            .iter()
            .copied()
            .find(|format| format.sample_rate.to_string() == value),
    }
}

/// `?encoding=`: absent is [`DEFAULT_ENCODING`]; present exactly once as
/// the wire name of an encoding the formats use (`pcm_s16le`); anything
/// else is `None`. The rules are [`parse_rate`]'s.
#[must_use]
pub fn parse_encoding(query: Option<&str>, formats: &[AudioFormat]) -> Option<Encoding> {
    match query_value(query, ENCODING_PARAM)? {
        None => Some(DEFAULT_ENCODING),
        Some(value) => Encoding::parse(value)
            .filter(|encoding| formats.iter().any(|format| format.encoding == *encoding)),
    }
}

/// `key`'s value in `query`: `Some(None)` when absent, `Some(Some(value))`
/// when present once (a pair without `=` has the empty value), `None` when
/// repeated. Split on `&`; the key matched as written.
fn query_value<'q>(query: Option<&'q str>, key: &str) -> Option<Option<&'q str>> {
    let mut found: Option<&str> = None;
    for pair in query.unwrap_or("").split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name != key {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(value);
    }
    Some(found)
}

impl<S: SttProvider, T: TtsProvider> Voice<S, T> {
    /// Admit one `GET /voice/stream` upgrade for `user` (module docs: the
    /// checks, in order) and, admitted, answer the `101` whose socket the
    /// relay then owns. `query` is the request's raw query string; `upgrade`
    /// the extractor's result, taken as a `Result` so that the configuration
    /// `503` comes before the `426`. The app authenticates `user` first, and
    /// renders a refusal through its own envelope
    /// ([`VoiceRefusal::into_response_with`]).
    ///
    /// The session selects on `context.shutdown` (closing `1001` when it is
    /// cancelled) and holds a `context.tracker` token from before the upgrade
    /// until it is done, as does the lease's release after an upgrade that
    /// failed, so the app's drain waits for both.
    ///
    /// # Errors
    ///
    /// The first check that refuses, as a [`VoiceRefusal`] (module docs'
    /// table).
    pub async fn open_stream(
        self: &Arc<Self>,
        context: StreamContext<'_>,
        user: Uuid,
        query: Option<&str>,
        upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    ) -> Result<Response, VoiceRefusal> {
        // 503 — the configuration.
        if !self.stream_configured(context.redis) {
            return Err(VoiceRefusal::not_configured());
        }
        let Some(redis) = context.redis else {
            return Err(VoiceRefusal::not_configured());
        };
        // 426 — not a WebSocket upgrade at all.
        let Ok(upgrade) = upgrade else {
            return Err(VoiceRefusal::upgrade_required());
        };
        // 422 — the rate, then the encoding.
        let formats = self.stt().formats();
        let Some(rated) = parse_rate(query, formats) else {
            return Err(VoiceRefusal::bad_rate(formats));
        };
        let encoding = parse_encoding(query, formats);
        let Some(format) = formats.iter().copied().find(|format| {
            format.sample_rate == rated.sample_rate && Some(format.encoding) == encoding
        }) else {
            return Err(VoiceRefusal::bad_encoding(formats));
        };
        let rate = format.sample_rate;

        // 429 / 503 — the fence, the budgets, the admission interval, and the
        // lease.
        //
        // FENCED: the acquire is sent at most once (`Replay::Never`,
        // `StreamBudget::acquire`), which stops a SECOND run of it; the ticket
        // stops a LATE first one. Each upgrade takes the user's next ticket
        // before it acquires, and the acquire is refused, writing nothing,
        // unless its ticket is still the newest. So if this request's acquire
        // is delayed in transit past its response timeout (it answers 503, no
        // session) and another upgrade B then takes a ticket and the lease,
        // the delayed original lands STALE and B keeps its session — however
        // long after B's admission interval it lands, within the fence's day
        // (`crate::lease`'s module docs: the bound).
        //
        // A PING first. The issue and the acquire below are this flow's first
        // Redis commands and neither is ever re-sent, so on a cached
        // connection that died while idle (hosted Redis and serverless hosts
        // drop idle ones) the first would fail and answer 503: the first
        // session after any quiet spell. `ping` is sent under
        // `Replay::OnceOnFreshConnection`, so it finds such a connection dead
        // and replaces it with a fresh dial, and the issue then runs on a live
        // one. One round-trip per session open. A ping that fails even on a
        // fresh dial is Redis being unavailable: the same 503 + Retry-After
        // the acquire's failure answers. RESIDUAL: the connection can still
        // die between the ping and the issue or the acquire (a 503, as
        // before).
        if let Err(failure) = redis.ping().await {
            tracing::warn!(
                user_id = %user,
                rate,
                outcome = "redis",
                error = %failure,
                "voice stream: Redis did not answer the ping before the lease; no session"
            );
            return Err(VoiceRefusal::unavailable());
        }
        // The ticket: never re-sent (`StreamBudget::issue_ticket`), so a lost
        // reply is a 503 here and the ticket it may have taken is never used.
        let ticket = match self.stream_budget().issue_ticket(redis, user).await {
            Ok(ticket) => ticket,
            Err(failure) => {
                tracing::warn!(
                    user_id = %user,
                    rate,
                    outcome = "redis",
                    error = %failure,
                    "voice stream: the lease ticket could not be issued; no session"
                );
                return Err(VoiceRefusal::unavailable());
            }
        };
        let token = Uuid::new_v4();
        let acquired = self
            .stream_budget()
            .acquire(
                redis,
                user,
                token,
                ticket,
                self.relay_settings().admit_interval,
            )
            .await;
        let grant = match acquired {
            Ok(grant) => grant,
            Err(StreamBudgetError::Stale) => {
                // A newer upgrade for this user took a ticket after this one:
                // this request lost the race (a second device, or this one's
                // own retry), and nothing was written. Retryable.
                tracing::info!(
                    user_id = %user,
                    rate,
                    outcome = "stale",
                    "voice stream: a newer upgrade took a lease ticket first; no session"
                );
                return Err(VoiceRefusal::unavailable());
            }
            Err(StreamBudgetError::Throttled {
                retry_after_seconds,
            }) => {
                tracing::info!(
                    user_id = %user,
                    rate,
                    outcome = "throttled",
                    retry_after_seconds,
                    "voice stream: another upgrade was admitted just now; no session"
                );
                return Err(VoiceRefusal::reopened_too_soon(retry_after_seconds));
            }
            Err(StreamBudgetError::Exceeded(limit)) => {
                tracing::info!(
                    user_id = %user,
                    rate,
                    outcome = "budget",
                    scope = limit.scope.as_str(),
                    user_day_spent = limit.spent.user_day,
                    user_month_spent = limit.spent.user_month,
                    global_month_spent = limit.spent.global_month,
                    retry_after_seconds = limit.retry_after_seconds,
                    "voice stream: budget spent; no session"
                );
                return Err(VoiceRefusal::limit_reached(&limit));
            }
            Err(failure @ StreamBudgetError::Backend(_)) => {
                tracing::warn!(
                    user_id = %user,
                    rate,
                    outcome = "redis",
                    error = %failure,
                    "voice stream: the lease could not be taken"
                );
                return Err(VoiceRefusal::unavailable());
            }
        };

        // The lease is this session's now: supersede, at once, any session
        // this instance is running for the same user (`relay::LiveSessions`).
        let superseded = self.live_sessions().register(user, token);
        let session = Session {
            user,
            format,
            token,
            grant,
            voice: Arc::clone(self),
            redis: redis.clone(),
            shutdown: context.shutdown.clone(),
            superseded,
        };
        // Counted from now, so a shutdown that arrives while the upgrade is
        // still completing waits for this session too.
        let tracked = context.tracker.token();
        let tracker = context.tracker.clone();
        let voice = Arc::clone(self);
        let release_redis = redis.clone();
        // The client socket's limits, set one by one: axum's upgrade takes no
        // `WebSocketConfig`.
        Ok(upgrade
            .read_buffer_size(READ_BUFFER_BYTES)
            .max_message_size(MAX_FRAME_BYTES)
            .max_frame_size(MAX_FRAME_BYTES)
            .write_buffer_size(0)
            .max_write_buffer_size(MAX_WRITE_BUFFER_BYTES)
            .on_failed_upgrade(move |_error| {
                // The 101 went out but the connection never became a
                // WebSocket: give the lease back rather than leave it to
                // expire. Nothing was streamed, so nothing is charged. Tracked
                // like a session — this runs while the session's own tracker
                // token is still held, so the count never touches zero between
                // them — so the app's drain waits for it too.
                let tracked = tracker.token();
                tokio::spawn(async move {
                    let _tracked = tracked;
                    voice.live_sessions().deregister(user, token);
                    let released =
                        relay::meter(voice, release_redis, user, token, 0, MeterMode::Release)
                            .await;
                    match released {
                        Ok(metered) => tracing::info!(
                            user_id = %user,
                            lease_deleted = metered.held,
                            "voice stream: the upgrade failed; the lease is released"
                        ),
                        Err(failure) => tracing::warn!(
                            user_id = %user,
                            error = %failure,
                            "voice stream: the upgrade failed, and so did the lease release; it \
                             expires on its own"
                        ),
                    }
                });
            })
            .on_upgrade(move |socket| async move {
                let _tracked = tracked;
                relay::run(socket, session).await;
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stt::PROTOCOL_DEFAULT_RATES;

    fn pcm(rates: &[u32]) -> Vec<AudioFormat> {
        rates.iter().copied().map(AudioFormat::pcm_s16le).collect()
    }

    /// Over the protocol's default formats (24 kHz first): absent is the
    /// first, each rate exactly as written, and nothing else — another rate,
    /// an empty or valueless one, a repeat (even of the same value), a
    /// percent-encoded one. Other parameters are ignored.
    #[test]
    fn the_rate_defaults_and_refuses_everything_else() {
        let formats = pcm(&PROTOCOL_DEFAULT_RATES);
        let (hz24, hz16) = (
            Some(AudioFormat::pcm_s16le(24_000)),
            Some(AudioFormat::pcm_s16le(16_000)),
        );
        for (query, expected) in [
            (None, hz24),
            (Some(""), hz24),
            (Some("other=1"), hz24),
            (Some("rate=24000"), hz24),
            (Some("rate=16000"), hz16),
            (Some("x=1&rate=16000&y"), hz16),
            (Some("rate="), None),
            (Some("rate"), None),
            (Some("rate=8000"), None),
            (Some("rate=024000"), None),
            (Some("rate=+24000"), None),
            (Some("rate=24000&rate=24000"), None),
            (Some("rate=24000&rate=16000"), None),
            (Some("rate=%3224000"), None),
            (Some("RATE=16000"), hz24),
        ] {
            assert_eq!(parse_rate(query, &formats), expected, "{query:?}");
        }
    }

    /// The rate follows the provider's formats: their first is the default,
    /// and only their rates parse.
    #[test]
    fn the_rate_follows_the_providers_formats() {
        let formats = pcm(&[16_000, 48_000, 24_000]);
        assert_eq!(
            parse_rate(None, &formats),
            Some(AudioFormat::pcm_s16le(16_000))
        );
        assert_eq!(
            parse_rate(Some("rate=48000"), &formats),
            Some(AudioFormat::pcm_s16le(48_000))
        );
        assert_eq!(parse_rate(Some("rate=8000"), &formats), None);
        assert_eq!(parse_rate(None, &[]), None, "no formats, no default");
    }

    /// The encoding's twin: absent is `pcm_s16le`; its exact wire name once;
    /// nothing else.
    #[test]
    fn the_encoding_defaults_and_refuses_everything_else() {
        let formats = pcm(&PROTOCOL_DEFAULT_RATES);
        let pcm16 = Some(Encoding::PcmS16le);
        for (query, expected) in [
            (None, pcm16),
            (Some(""), pcm16),
            (Some("rate=16000"), pcm16),
            (Some("encoding=pcm_s16le"), pcm16),
            (Some("rate=16000&encoding=pcm_s16le&x"), pcm16),
            (Some("encoding="), None),
            (Some("encoding"), None),
            (Some("encoding=opus"), None),
            (Some("encoding=PCM_S16LE"), None),
            (Some("encoding=pcm_s16le&encoding=pcm_s16le"), None),
            (Some("encoding=pcm%5Fs16le"), None),
        ] {
            assert_eq!(parse_encoding(query, &formats), expected, "{query:?}");
        }
        assert_eq!(DEFAULT_ENCODING, Encoding::PcmS16le);
    }
}
