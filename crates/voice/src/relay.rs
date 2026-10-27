//! One `GET /voice/stream` session (feature `axum`): the client's audio to
//! the speech-to-text provider, the provider's events back to the client,
//! and the close machine around both. Ported from tapper
//! (`tapper-rs/src/voice/relay.rs`, `82be95f`) onto the provider traits
//! ([`crate::stt`]), with one change of behaviour: the provider-run cap
//! (below).
//!
//! # The session
//!
//! ```text
//! upgrade ─▶ open the provider (dial, handshake, its ready; ≤ open_timeout) ─▶ {"type":"ready",…}
//!        ─▶ relay: client binary ─▶ the provider; the provider's events ─▶ client events
//!        ─▶ an ending ─▶ error event (some endings) ─▶ the provider closed + lease released
//!        ─▶ the client's close frame
//! ```
//!
//! One task, one `select!`, no channels: every write is awaited inline under
//! a deadline ([`RelaySettings::close_timeout`]), and the client socket's
//! write buffer is bounded ([`MAX_WRITE_BUFFER_BYTES`]), as an adapter's must
//! be, so a peer that stops reading stalls nothing for longer than that and
//! queues nothing unboundedly. The lease refresh is the one call that is not
//! inline: it runs beside the relay as an in-flight future, so a slow Redis
//! never holds a transcript back.
//!
//! # What the client may send
//!
//! - **Binary frames: audio.** In the session's format (PCM s16le mono at
//!   the session's rate), so an EVEN number of bytes; at most 64 KiB a
//!   message and a frame; never more, cumulatively, than real time plus the
//!   provider's pacing lead ([`crate::stt::SttProvider::pacing_lead`], since
//!   `ready`); none before `ready` and none after `end`; and, until `end`,
//!   never IDLE — no frame for [`RelaySettings::idle_timeout`], or the audio
//!   as a whole more than that far behind real time since `ready` (a client
//!   trickling two-byte frames is idle too).
//! - **Text: exactly `{"type":"end"}`** ([`crate::protocol::END_FRAME`]) —
//!   no more audio is coming; the provider is told
//!   ([`crate::stt::SttSession::end_input`]) and the session ends when it
//!   finishes, or [`RelaySettings::end_timeout`] after the end of input was
//!   written. Any other text is ignored.
//!
//! # The close machine
//!
//! | ending | client gets | close |
//! |---|---|---|
//! | `end`, then the provider finishes (or does not within `end_timeout`) | the last events | `1000 done` |
//! | the client closes | — | its own code, echoed |
//! | server shutdown ([`crate::StreamContext::shutdown`]) | — | `1001 shutting down` |
//! | a policy breach (size, odd frame, pacing, idle, audio before ready or after end, no pong) | — | `1008 <what>` |
//! | the provider errors, closes, drops, or does not open in time | `error{provider}` | `1011 provider error` |
//! | the budget could not be charged for a lease's lifetime | `error{internal}` | `1011 internal error` |
//! | the session cap | — | `4000 session limit` |
//! | what admission saw left in a window runs out mid-session (the cap is `min(session_cap, each binding window's remainder)`; when a window binds, retrying cannot help) | `error{limit, scope, resets_at}` | `4002 limit reached` |
//! | a newer session took the user's lease: at once on this instance, at the next refresh from another | — | `4001 superseded` |
//! | a budget is spent at a refresh | `error{limit, scope, resets_at}` | `4002 limit reached` |
//!
//! # The two budget endings
//!
//! Both carry the spent window's scope and reset to the `limit` event,
//! chosen as a refusal's is ([`crate::budget::Spent::scope`]), and both are
//! corrected by the session's final charge — the release — when it reports a
//! window spent: audio the client flushed in the last stretch can spend a
//! later window than the one that ended the session, so the event is sent
//! once the release has answered:
//!
//! - **the up-front deadline** — admission's grant says what is left in the
//!   user's day, the user's month and everyone's month. Streaming in real
//!   time from `ready`, the session exhausts a window that long after it,
//!   and is closed then, unless the session cap comes first. A window BINDS
//!   only if it would be exhausted before it ends: one that resets first (a
//!   UTC midnight, the first of the month) starts over with its whole cap, so
//!   a calendar crossing never closes a session ([`budget_deadline`]).
//! - **meter exhaustion** — a refresh charges the audio so far (to the
//!   windows of the moment it runs) and gets each window's remainder back;
//!   any at or below zero ends the session
//!   ([`crate::lease::Metered::limit_reached`]). This is what finds a window
//!   that OTHER sessions spent meanwhile, and a new window (after a crossing)
//!   spent within the same session.
//!
//! Every ending closes the provider ([`crate::stt::SttSession::close`]) and
//! RELEASES the lease — the final charge and the compare-and-delete
//! ([`crate::lease`]) — before the client is sent its close frame: a host
//! that stops a request's CPU once its connection ends may never run work
//! after the client's close. The provider's close and the release run
//! together; each step is bounded by `close_timeout` (Redis by its handle's
//! own bounds), so a session ends within a few seconds of its ending in the
//! worst case. A `limit` ending's event is the one sent AFTER the release,
//! not before it: its scope and reset are the final charge's when that
//! charge finds a window spent.
//!
//! # Writes, and where the relay drops a future
//!
//! A write — to the client, or to the provider
//! ([`crate::stt::SttSession::send_audio`],
//! [`crate::stt::SttSession::end_input`]) — is awaited inside the handler of
//! the `select!` arm that called for it, under
//! `close_timeout`; no other arm runs meanwhile, so nothing preempts a write:
//! a shutdown, a takeover or a deadline takes effect once the write returned
//! or hit its bound. The relay drops a provider future in exactly four
//! places: the `open` future (created once, pinned, and dropped when a
//! shutdown, a takeover, the client's `end`, close or drop, or its deadline
//! wins), a write at its bound, `close` at its bound, and the stream's
//! `next()` whenever another arm wins.
//!
//! **Audio is counted when it is handed over, not when the write
//! completes.** A frame counts — the session-end line's `frames` and
//! `audio_ms`, the usage record, every charge — from the moment the relay
//! calls [`crate::stt::SttSession::send_audio`] with it. A transport can take
//! a frame into its buffer and then stall on the flush; the write is dropped
//! at its bound, and the provider's close (which flushes) can still deliver
//! that frame. Counting it is what keeps the charge from ever falling short of
//! what the provider may receive; the price is at most one frame (64 KiB)
//! charged but never delivered, once per session, since a failed write ends
//! it.
//!
//! # The provider-run cap
//!
//! The provider's arm comes before the client's: a transcript is what the
//! user is waiting on, and a burst of client audio (the installed clients'
//! pre-`ready` buffer, up to three seconds of it) must not queue it behind
//! every frame. A correct adapter's events are bounded by the audio it is
//! sent. So that one that breaks that rule (always ready, never pending)
//! cannot starve the client, every provider event spends a unit of the
//! task's cooperative budget (`tokio::task::coop::consume_budget`: the task
//! yields to the runtime at the latest when the budget runs out, on a
//! current-thread runtime too), and after [`PROVIDER_RUN_CAP`] provider
//! events in a row the next `select!` polls the client before the provider.
//! Neither logs or counts anything.
//!
//! # The client's close codes
//!
//! The client closes with a code that names WHY it is leaving
//! ([`crate::protocol::client_close_code`]). The relay validates none of
//! them and acts on none of them: it records whatever code the client's close
//! frame carries, for the session-end line, and echoes it. It reads the CODE
//! only, never the close frame's reason text, which is never logged.
//!
//! # Logging
//!
//! One line when the session starts and one when it ends: the user, the rate,
//! and at the end the duration, frames, milliseconds of audio, turns, the
//! close code and an outcome word. Never a key, the audio, a transcript,
//! anything the provider sent, a raw transport error, or a close frame's
//! reason: a provider's failure is its fixed class ([`crate::ErrorClass`]).
//!
//! The session-end line also says how the CLIENT left:
//!
//! - `end_received` — whether the relay read the client's `end`: before
//!   `ready`, while relaying, or while it was closing (a client that sends
//!   `end` just as the relay ends the session — after an error event, say —
//!   still sent it, and the close reply is read past it); always present.
//! - `client_close_code` — the code of the close frame the client sent: the
//!   one that ended the session (`outcome` `client_closed`), or its reply to
//!   the relay's own close (any other outcome). `1005`
//!   ([`crate::protocol::close_code::NO_STATUS_RECEIVED`]) when that frame
//!   carried no code. **Absent** from the line (not `null`) when the relay
//!   read no close frame from the client: an abrupt drop (`client_gone`), or
//!   a client that did not answer the relay's close within the close bound.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use stridelabs_redis::RedisHandle;
use tokio::time::error::Elapsed;
use tokio::time::{sleep_until, timeout_at, Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::budget::{LimitReached, LimitScope, Spent};
use crate::lease::{
    audio_ms, millis, Grant, MeterMode, Metered, StreamBudgetError, FENCE_TTL_SECONDS, LEASE_TTL,
};
use crate::protocol::{close_code, ErrorCode, RelayEvent, END_FRAME, MAX_FRAME_BYTES};
use crate::stt::{AudioFormat, SttError, SttEvent, SttProvider, SttSession};
use crate::tts::TtsProvider;
use crate::usage::VoiceMetric;
use crate::Voice;

pub use crate::voice::RelaySettings;

/// The most provider events the relay takes in a row before it polls the
/// client first, once (module docs, "The provider-run cap"). A provider
/// bounded by its audio yields a handful of events per 80 ms client frame,
/// so a correct adapter never reaches it, and the guard changes no correct
/// session's order; a breach delays a client frame by at most this many
/// provider events.
pub const PROVIDER_RUN_CAP: u32 = 32;

/// The client socket's read buffer: 16 KiB, against tungstenite's 128 KiB
/// default, which it zero-fills before EVERY read. An 80 ms frame of 24 kHz
/// audio (3,840 bytes) is still one read; a message up to
/// [`MAX_FRAME_BYTES`] still arrives whole, over more reads.
pub const READ_BUFFER_BYTES: usize = 16 * 1024;

/// The most the client socket's write buffer may hold before a send fails
/// rather than queueing: four of the largest frames. Writes are eager (a
/// write buffer target of 0), so this is only reached when the client stops
/// reading.
pub const MAX_WRITE_BUFFER_BYTES: usize = 4 * MAX_FRAME_BYTES;

/// The session-end line's cause when the provider did not open in time: the
/// relay's own bound, the only one on an open.
const OPEN_TIMEOUT_CAUSE: &str = "open_timeout: not open before the deadline";

/// The sessions live on THIS instance, one per user, each with the handle
/// that supersedes it. [`LiveSessions::register`] is the admission's last
/// step before the upgrade: a takeover on the same instance cancels the
/// previous session AT ONCE (it closes `4001` and releases, as at a
/// refresh), instead of leaving two sessions open at the provider for up to
/// a refresh interval. A takeover from another instance is still found by
/// the refresh, through the lease ([`crate::lease`]).
///
/// **Newest ticket wins, here as in Redis.** Each session is registered with
/// the fence ticket its acquire carried ([`crate::lease`], "Fenced"): the
/// user's tickets rise with every upgrade, and Redis granted the lease to
/// whichever acquire carried the newest. Two admissions on one instance can
/// reach this registry in the other order — an acquire whose reply was slow
/// (a separate connection, a slow round trip) registers after a newer
/// upgrade took a ticket, the lease and its place here — so registration
/// order is not acquisition order. A registration therefore supersedes only
/// a session holding an OLDER ticket; one that arrives with an older ticket
/// than the session registered is itself born superseded (`4001` before it
/// dials the provider: Redis holds the newer session's token, so its
/// release deletes nothing) and leaves the newer one running.
#[derive(Debug, Default)]
pub(crate) struct LiveSessions(Mutex<HashMap<Uuid, Registered>>);

/// One user's registered session.
#[derive(Debug)]
struct Registered {
    token: Uuid,
    /// The fence ticket its acquire carried.
    ticket: u64,
    /// When it registered: a ticket is comparable only within the life of
    /// the fence that numbered it ([`FENCE_TTL`]).
    at: Instant,
    superseded: CancellationToken,
}

/// How long a user's fence hash lives after its last issue or grant
/// ([`crate::lease::FENCE_TTL_SECONDS`]): a registration at least this old
/// may hold a ticket of an expired numbering (the fence restarts at `1`),
/// so a newer registration supersedes it whatever its ticket.
const FENCE_TTL: Duration = Duration::from_secs(FENCE_TTL_SECONDS.unsigned_abs());

impl LiveSessions {
    /// Register session `token`, whose acquire carried `ticket`, as
    /// `user`'s, cancelling the session registered before it — unless that
    /// one holds a NEWER ticket (type docs): then the returned handle is
    /// already cancelled, and the registered session is untouched. The
    /// returned handle is this session's: cancelled by the next newer
    /// registration for the same user. Registering the same token again
    /// returns its existing handle.
    pub(crate) fn register(&self, user: Uuid, token: Uuid, ticket: u64) -> CancellationToken {
        self.register_at(user, token, ticket, Instant::now())
    }

    /// [`LiveSessions::register`] at `now`.
    fn register_at(&self, user: Uuid, token: Uuid, ticket: u64, now: Instant) -> CancellationToken {
        let mut live = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(registered) = live.get(&user) {
            if registered.token == token {
                return registered.superseded.clone();
            }
            if registered.ticket > ticket
                && now.saturating_duration_since(registered.at) < FENCE_TTL
            {
                let late = CancellationToken::new();
                late.cancel();
                return late;
            }
        }
        let superseded = CancellationToken::new();
        let registered = Registered {
            token,
            ticket,
            at: now,
            superseded: superseded.clone(),
        };
        if let Some(previous) = live.insert(user, registered) {
            previous.superseded.cancel();
        }
        superseded
    }

    /// Forget session `token` — only if it is still `user`'s registered one:
    /// a superseded session must not forget the session that superseded it.
    pub(crate) fn deregister(&self, user: Uuid, token: Uuid) {
        let mut live = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if live
            .get(&user)
            .is_some_and(|registered| registered.token == token)
        {
            live.remove(&user);
        }
    }

    /// How many sessions are registered.
    #[cfg_attr(
        not(any(test, feature = "test-support")),
        expect(dead_code, reason = "read by `Voice::live_session_count`, a test seam")
    )]
    pub(crate) fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).len()
    }
}

/// What the admission hands a session after every check passed and the
/// lease is taken.
pub(crate) struct Session<S: SttProvider, T: TtsProvider> {
    pub(crate) user: Uuid,
    /// The session's audio format: the upgrade's `rate` and `encoding`.
    pub(crate) format: AudioFormat,
    /// The lease's token: this session's identity in Redis.
    pub(crate) token: Uuid,
    pub(crate) grant: Grant,
    pub(crate) voice: Arc<Voice<S, T>>,
    /// The app's Redis handle (a clone shares its connection), which the
    /// lease was taken on and every refresh and the release run on.
    pub(crate) redis: RedisHandle,
    pub(crate) shutdown: CancellationToken,
    /// Cancelled when a newer session for the same user registers on this
    /// instance ([`LiveSessions`]).
    pub(crate) superseded: CancellationToken,
}

/// How a session ended (module docs' table).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ending {
    Done,
    ClientClosed,
    ClientGone,
    Shutdown,
    Policy(&'static str),
    /// Why, as a fixed class.
    Provider(String),
    Internal,
    SessionLimit,
    Superseded,
    /// A budget window is spent: which, and when it resets (both endings,
    /// module docs).
    Limit(LimitReached),
}

impl Ending {
    /// The event sent before the close frame, if any.
    fn error_event(&self) -> Option<RelayEvent> {
        match self {
            Ending::Provider(_) => Some(RelayEvent::error(ErrorCode::Provider)),
            Ending::Internal => Some(RelayEvent::error(ErrorCode::Internal)),
            Ending::Limit(limit) => Some(RelayEvent::limit(limit)),
            _ => None,
        }
    }

    /// The close frame the relay sends, if it sends one (a client that closed
    /// gets its own echoed; one that is gone gets nothing).
    fn close_frame(&self) -> Option<(u16, &'static str)> {
        match self {
            Ending::Done => Some((close_code::DONE, "done")),
            Ending::ClientClosed | Ending::ClientGone => None,
            Ending::Shutdown => Some((close_code::GOING_AWAY, "shutting down")),
            Ending::Policy(what) => Some((close_code::POLICY, what)),
            Ending::Provider(_) => Some((close_code::ERROR, "provider error")),
            Ending::Internal => Some((close_code::ERROR, "internal error")),
            Ending::SessionLimit => Some((close_code::SESSION_LIMIT, "session limit")),
            Ending::Superseded => Some((close_code::SUPERSEDED, "superseded")),
            Ending::Limit(_) => Some((close_code::LIMIT, "limit reached")),
        }
    }

    /// The log line's outcome word.
    fn outcome(&self) -> &'static str {
        match self {
            Ending::Done => "done",
            Ending::ClientClosed => "client_closed",
            Ending::ClientGone => "client_gone",
            Ending::Shutdown => "shutdown",
            Ending::Policy(_) => "policy",
            Ending::Provider(_) => "provider",
            Ending::Internal => "internal",
            Ending::SessionLimit => "session_limit",
            Ending::Superseded => "superseded",
            Ending::Limit(_) => "limit",
        }
    }
}

/// The up-front budget deadline (module docs): how long after `ready` the
/// session exhausts the first window that binds, and the limit it then ends
/// with — or `None` when no window binds.
///
/// Each of the grant's remainders is audio this session may still stream,
/// in real time, so it runs out that long after `ready`. A window binds only
/// if that comes before the window itself ends — reckoned from the grant's
/// instant ([`Grant::at`]), whose monotonic twin ([`Grant::origin`],
/// captured with it, before the acquire was sent) is `ready_delay` before
/// `ready`: the acquire's round trip, the provider's dial, handshake and
/// ready all count — so a window that resets first never ends the session.
/// Of the binding windows the earliest decides; windows that run out at the
/// same instant are reported as a refusal's are ([`Spent::scope`]).
#[must_use]
pub fn budget_deadline(grant: &Grant, ready_delay: Duration) -> Option<(Duration, LimitReached)> {
    let binding: Vec<(LimitScope, Duration)> = [
        (LimitScope::UserDay, grant.user_day_remaining_ms),
        (LimitScope::UserMonth, grant.user_month_remaining_ms),
        (LimitScope::GlobalMonth, grant.global_remaining_ms),
    ]
    .into_iter()
    .filter_map(|(scope, remaining_ms)| {
        let remaining = Duration::from_millis(u64::try_from(remaining_ms).unwrap_or(0));
        let until_reset = (scope.resets_at(grant.at) - grant.at)
            .to_std()
            .unwrap_or(Duration::ZERO);
        (ready_delay.saturating_add(remaining) < until_reset).then_some((scope, remaining))
    })
    .collect();
    let earliest = binding.iter().map(|(_, remaining)| *remaining).min()?;
    let runs_out = |scope: LimitScope| {
        binding
            .iter()
            .any(|(binds, remaining)| *binds == scope && *remaining == earliest)
    };
    let spent = Spent {
        user_day: runs_out(LimitScope::UserDay),
        user_month: runs_out(LimitScope::UserMonth),
        global_month: runs_out(LimitScope::GlobalMonth),
    };
    LimitReached::new(spent, grant.at).map(|limit| (earliest, limit))
}

/// A refresh or a release in flight ([`meter`]).
pub(crate) type MeterFuture =
    Pin<Box<dyn Future<Output = Result<Metered, StreamBudgetError>> + Send>>;

/// What one turn of `stream()`'s `select!` produced: one variant per arm
/// (module docs), so that each arm's handling is written once, after the
/// `select!`, whichever order its arms ran in.
enum Step {
    Shutdown,
    Superseded,
    Cap,
    Metered(Result<Metered, StreamBudgetError>),
    Refresh,
    Ping,
    Deadline,
    Provider(Option<Result<SttEvent, SttError>>),
    Client(Option<Result<Message, axum::Error>>),
}

/// The session's running state.
struct Relay<S: SttProvider, T: TtsProvider> {
    session: Session<S, T>,
    settings: RelaySettings,
    /// The provider's pacing lead: how far ahead of real time the client's
    /// audio may run.
    lead: Duration,
    client: WebSocket,
    provider: Option<S::Session>,
    /// The client sent `end` — the session-end line's `end_received`, with
    /// an `end` read while closing ([`Drained::end`]).
    ended: bool,
    /// The code of the client's close frame, once one is read (module docs):
    /// `1005` for a frame without one. Never its reason.
    client_close_code: Option<u16>,
    started: Instant,
    ready_at: Option<Instant>,
    audio_bytes: u64,
    frames: u64,
    turns: u64,
    /// Provider data messages that were not an event the client is told
    /// about.
    ignored: u64,
    last_audio: Instant,
    last_pong: Instant,
    /// When the budget last answered a refresh.
    last_metered: Instant,
}

/// Run one session to its end. Called by the admission's `on_upgrade`, with
/// the lease already taken.
pub(crate) async fn run<S: SttProvider, T: TtsProvider>(client: WebSocket, session: Session<S, T>) {
    let now = Instant::now();
    let settings = session.voice.relay_settings();
    let lead = session.voice.stt().pacing_lead();
    tracing::info!(
        user_id = %session.user,
        rate = session.format.sample_rate,
        took_over = session.grant.took_over,
        "voice stream: session start"
    );
    let mut relay = Relay {
        session,
        settings,
        lead,
        client,
        provider: None,
        ended: false,
        client_close_code: None,
        started: now,
        ready_at: None,
        audio_bytes: 0,
        frames: 0,
        turns: 0,
        ignored: 0,
        last_audio: now,
        last_pong: now,
        last_metered: now,
    };
    let ending = match relay.open().await {
        Ok(()) => relay.stream().await,
        Err(ending) => ending,
    };
    relay.finish(ending).await;
}

impl<S: SttProvider, T: TtsProvider> Relay<S, T> {
    /// Open the provider, watching the client and the shutdown token
    /// meanwhile; then tell the client `ready`. The open is ONE future,
    /// created once and pinned, so a client frame the loop ignores never
    /// re-creates it, and `timeout_at` is its only bound.
    async fn open(&mut self) -> Result<(), Ending> {
        let voice = Arc::clone(&self.session.voice);
        let deadline = Instant::now() + self.settings.open_timeout;
        let open = timeout_at(deadline, voice.stt().open(self.session.format, deadline));
        tokio::pin!(open);
        loop {
            tokio::select! {
                biased;
                () = self.session.shutdown.cancelled() => return Err(Ending::Shutdown),
                () = self.session.superseded.cancelled() => return Err(Ending::Superseded),
                opened = &mut open => match opened {
                    Ok(Ok(provider)) => {
                        self.provider = Some(provider);
                        break;
                    }
                    Ok(Err(failure)) => {
                        return Err(Ending::Provider(format!(
                            "{}: {}",
                            failure.label.as_str(),
                            failure.class
                        )))
                    }
                    Err(_) => return Err(Ending::Provider(OPEN_TIMEOUT_CAUSE.to_string())),
                },
                message = self.client.next() => match message {
                    Some(Ok(Message::Binary(_))) => return Err(Ending::Policy("audio before ready")),
                    // Nothing was said: done, with nothing to transcribe.
                    Some(Ok(Message::Text(text))) if text.as_str() == END_FRAME => {
                        self.ended = true;
                        return Err(Ending::Done);
                    }
                    Some(Ok(Message::Close(frame))) => {
                        self.client_close_code = Some(close_code_of(frame.as_ref()));
                        return Err(Ending::ClientClosed);
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Err(client_read_error(&error)),
                    None => return Err(Ending::ClientGone),
                },
            }
        }
        let stt = voice.stt();
        self.send_event(&RelayEvent::ready(stt.formats(), stt.pacing_lead()))
            .await?;
        let now = Instant::now();
        self.ready_at = Some(now);
        self.last_audio = now;
        self.last_pong = now;
        self.last_metered = now;
        Ok(())
    }

    /// Relay until something ends the session.
    async fn stream(&mut self) -> Ending {
        let settings = self.settings;
        let ready_at = self.ready_at.unwrap_or_else(Instant::now);
        // When a window that binds runs out before the session cap, reaching
        // the deadline means that budget is spent: a limit (4002, with its
        // scope), not the session cap (4000) a new session could continue
        // past. A window that resets first does not bind (`budget_deadline`).
        let ready_delay = ready_at.saturating_duration_since(self.session.grant.origin);
        let (cap_deadline, cap_ending) = match budget_deadline(&self.session.grant, ready_delay) {
            Some((after, limit)) if after < settings.session_cap => {
                (ready_at + after, Ending::Limit(limit))
            }
            _ => (ready_at + settings.session_cap, Ending::SessionLimit),
        };
        let mut ping =
            tokio::time::interval_at(ready_at + settings.ping_interval, settings.ping_interval);
        ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut refresh = tokio::time::interval_at(
            ready_at + settings.refresh_interval,
            settings.refresh_interval,
        );
        refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut in_flight: Option<MeterFuture> = None;
        let mut end_deadline: Option<Instant> = None;
        // Provider events taken in a row (module docs, "The provider-run cap").
        let mut provider_run: u32 = 0;
        let shutdown = self.session.shutdown.clone();
        let superseded = self.session.superseded.clone();

        loop {
            let idle_deadline = self.idle_deadline(ready_at);
            let Some(provider) = self.provider.as_mut() else {
                return Ending::Internal;
            };
            // The same arms, `biased`, in two orders: the provider before the
            // client, as always; once `PROVIDER_RUN_CAP` provider events ran
            // in a row, the client before the provider, for this one turn (a
            // ready client frame is taken; with none, the provider's arm wins
            // as usual). Two `select!`s, not two client arms in one: each
            // builds every arm's future, and the socket can be borrowed once.
            let client_first = provider_run >= PROVIDER_RUN_CAP;
            if client_first {
                provider_run = 0;
            }
            let step = if client_first {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => Step::Shutdown,
                    () = superseded.cancelled() => Step::Superseded,
                    () = sleep_until(cap_deadline) => Step::Cap,
                    metered = async { in_flight.as_mut().expect("guarded by is_some").await },
                        if in_flight.is_some() => Step::Metered(metered),
                    _ = refresh.tick() => Step::Refresh,
                    _ = ping.tick() => Step::Ping,
                    () = sleep_until(end_deadline.unwrap_or(idle_deadline)) => Step::Deadline,
                    message = self.client.next() => Step::Client(message),
                    event = provider.next() => Step::Provider(event),
                }
            } else {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => Step::Shutdown,
                    () = superseded.cancelled() => Step::Superseded,
                    () = sleep_until(cap_deadline) => Step::Cap,
                    metered = async { in_flight.as_mut().expect("guarded by is_some").await },
                        if in_flight.is_some() => Step::Metered(metered),
                    _ = refresh.tick() => Step::Refresh,
                    _ = ping.tick() => Step::Ping,
                    () = sleep_until(end_deadline.unwrap_or(idle_deadline)) => Step::Deadline,
                    // The provider before the client: a transcript is what
                    // the user is waiting on, and a burst of client audio (an
                    // installed client's pre-`ready` buffer, up to three
                    // seconds of it) must not queue it behind every frame. A
                    // correct adapter's rate is bounded by the audio it is
                    // sent; the run cap bounds an incorrect one's.
                    event = provider.next() => Step::Provider(event),
                    message = self.client.next() => Step::Client(message),
                }
            };
            if matches!(step, Step::Provider(_)) {
                provider_run += 1;
            } else {
                provider_run = 0;
            }
            match step {
                Step::Shutdown => return Ending::Shutdown,
                Step::Superseded => return Ending::Superseded,
                Step::Cap => return cap_ending,
                Step::Metered(metered) => {
                    in_flight = None;
                    if let Some(ending) = self.on_metered(metered) {
                        return ending;
                    }
                }
                Step::Refresh => {
                    if in_flight.is_none() {
                        in_flight = Some(self.meter(MeterMode::Refresh));
                    }
                }
                Step::Ping => {
                    if self.last_pong.elapsed() > settings.pong_deadline {
                        return Ending::Policy("pong timeout");
                    }
                    if !self.write_client(Message::Ping(Bytes::new())).await {
                        return Ending::ClientGone;
                    }
                }
                // Before `end`, the idle timeout; after it, the provider did
                // not finish in time after the end of input — the client
                // asked to end, and has every event that arrived.
                Step::Deadline => {
                    return if end_deadline.is_some() {
                        Ending::Done
                    } else {
                        Ending::Policy("idle")
                    };
                }
                Step::Provider(event) => {
                    if let Err(ending) = self.on_provider(event).await {
                        return ending;
                    }
                    // Every provider event spends a unit of the task's
                    // cooperative budget: `select!` only CHECKS the budget,
                    // and a pending timer or token spends none, so an
                    // always-ready provider would otherwise hold the task on
                    // its worker for good (module docs).
                    tokio::task::coop::consume_budget().await;
                }
                Step::Client(message) => match self.on_client(message).await {
                    // The end deadline starts once the end of input was
                    // written, not when `end` was read.
                    Ok(true) => end_deadline = Some(Instant::now() + settings.end_timeout),
                    Ok(false) => {}
                    Err(ending) => return ending,
                },
            }
        }
    }

    /// One client message. `Ok(true)` when it was `end`.
    async fn on_client(
        &mut self,
        message: Option<Result<Message, axum::Error>>,
    ) -> Result<bool, Ending> {
        match message {
            Some(Ok(Message::Binary(audio))) => {
                if self.ended {
                    return Err(Ending::Policy("audio after end"));
                }
                if audio.len() % 2 != 0 {
                    return Err(Ending::Policy("odd audio frame"));
                }
                if audio.is_empty() {
                    return Ok(false);
                }
                let length = u64::try_from(audio.len()).unwrap_or(u64::MAX);
                if self.audio_bytes.saturating_add(length) > self.allowed_bytes() {
                    return Err(Ending::Policy("pacing"));
                }
                // Counted — and so charged — once handed to the provider,
                // BEFORE the write is awaited (`SttSession::send_audio`'s
                // contract): a write cut off at its bound may have left the
                // frame in the transport's buffer, which the provider's close
                // can still flush to it.
                self.audio_bytes = self.audio_bytes.saturating_add(length);
                self.frames += 1;
                self.send_audio(audio).await?;
                self.last_audio = Instant::now();
                Ok(false)
            }
            Some(Ok(Message::Text(text))) => {
                if text.as_str() != END_FRAME || self.ended {
                    return Ok(false);
                }
                self.ended = true;
                self.end_input().await?;
                Ok(true)
            }
            Some(Ok(Message::Pong(_))) => {
                self.last_pong = Instant::now();
                Ok(false)
            }
            // The socket answers a ping itself.
            Some(Ok(Message::Ping(_))) => Ok(false),
            Some(Ok(Message::Close(frame))) => {
                self.client_close_code = Some(close_code_of(frame.as_ref()));
                Err(Ending::ClientClosed)
            }
            Some(Err(error)) => Err(client_read_error(&error)),
            None => Err(Ending::ClientGone),
        }
    }

    /// One provider event ([`crate::stt`]'s module docs: what each means).
    async fn on_provider(
        &mut self,
        event: Option<Result<SttEvent, SttError>>,
    ) -> Result<(), Ending> {
        let event = match event {
            Some(Ok(SttEvent::SpeechStart)) => RelayEvent::SpeechStart,
            Some(Ok(SttEvent::Partial(text))) => RelayEvent::Partial { text },
            Some(Ok(SttEvent::SpeechEnd)) => RelayEvent::SpeechEnd,
            Some(Ok(SttEvent::EndOfTurn(text))) => {
                self.turns += 1;
                RelayEvent::EndOfTurn { text }
            }
            Some(Ok(SttEvent::Ignored)) => {
                self.ignored += 1;
                return Ok(());
            }
            // The provider's normal end: done after `end`, its failure before
            // it.
            Some(Ok(SttEvent::Finished)) => {
                return Err(if self.ended {
                    Ending::Done
                } else {
                    Ending::Provider("closed".to_string())
                })
            }
            // The session is over on the provider's side; `finish` closes it
            // (the adapter knows whether its transport is still open).
            Some(Err(failure)) => return Err(Ending::Provider(failure.class.to_string())),
            None => return Err(Ending::Provider("the connection ended".to_string())),
        };
        self.send_event(&event).await
    }

    /// The most audio the client may have sent by now: real time since
    /// `ready`, plus the provider's pacing lead.
    fn allowed_bytes(&self) -> u64 {
        let elapsed = self
            .ready_at
            .map_or(Duration::ZERO, |ready| ready.elapsed());
        u64::try_from(
            (elapsed + self.lead).as_millis() * u128::from(self.session.format.bytes_per_second())
                / 1_000,
        )
        .unwrap_or(u64::MAX)
    }

    /// When the client counts as idle (module docs): one idle timeout after
    /// the LATER of two instants can be too late, so it is after the earlier
    /// — the last audio frame, and the point real time would have reached
    /// had the audio so far been streamed from `ready` without a gap. The
    /// second is what a client trickling tiny frames falls behind.
    fn idle_deadline(&self, ready_at: Instant) -> Instant {
        let caught_up_to = ready_at + Duration::from_millis(self.audio_ms());
        self.last_audio.min(caught_up_to) + self.settings.idle_timeout
    }

    /// The audio sent so far, in whole milliseconds.
    fn audio_ms(&self) -> u64 {
        audio_ms(self.audio_bytes, self.session.format.bytes_per_second())
    }

    /// A refresh or the release of this session's audio so far.
    fn meter(&self, mode: MeterMode) -> MeterFuture {
        meter(
            Arc::clone(&self.session.voice),
            self.session.redis.clone(),
            self.session.user,
            self.session.token,
            self.audio_ms(),
            mode,
        )
    }

    /// A refresh's answer: `Some` when it ends the session.
    fn on_metered(&mut self, metered: Result<Metered, StreamBudgetError>) -> Option<Ending> {
        match metered {
            Ok(metered) => {
                self.last_metered = Instant::now();
                if !metered.held {
                    return Some(Ending::Superseded);
                }
                metered.limit_reached().map(Ending::Limit)
            }
            Err(failure) => {
                // The audio since the last good refresh is still uncharged and
                // will be charged by the next one (the totals are cumulative).
                // Past a lease's lifetime the session no longer holds anything
                // a refresh could keep, and the budget is not being enforced.
                let failing = self.last_metered.elapsed();
                tracing::warn!(
                    user_id = %self.session.user,
                    error = %failure,
                    failing_ms = millis(failing),
                    "voice stream: a lease refresh failed"
                );
                (failing >= LEASE_TTL).then_some(Ending::Internal)
            }
        }
    }

    /// Send `event` to the client. A client that cannot take it is gone.
    async fn send_event(&mut self, event: &RelayEvent) -> Result<(), Ending> {
        if self.write_client(Message::text(event.to_json())).await {
            Ok(())
        } else {
            Err(Ending::ClientGone)
        }
    }

    /// One bounded write to the client: `false` when it failed or timed out.
    async fn write_client(&mut self, message: Message) -> bool {
        let deadline = Instant::now() + self.settings.close_timeout;
        matches!(
            timeout_at(deadline, self.client.send(message)).await,
            Ok(Ok(()))
        )
    }

    /// One bounded audio write to the provider: a failure is the provider's.
    async fn send_audio(&mut self, frame: Bytes) -> Result<(), Ending> {
        let deadline = Instant::now() + self.settings.close_timeout;
        let Some(provider) = self.provider.as_mut() else {
            return Err(Ending::Internal);
        };
        provider_write(timeout_at(deadline, provider.send_audio(frame)).await)
    }

    /// The bounded end of input: a failure is the provider's.
    async fn end_input(&mut self) -> Result<(), Ending> {
        let deadline = Instant::now() + self.settings.close_timeout;
        let Some(provider) = self.provider.as_mut() else {
            return Err(Ending::Internal);
        };
        provider_write(timeout_at(deadline, provider.end_input()).await)
    }

    /// The close machine's tail (module docs): the usage record, the error
    /// event, the provider closed and the lease released together, then the
    /// client's close frame, then the session's log line. Runs once per
    /// session (it consumes the relay).
    async fn finish(mut self, ending: Ending) {
        let voice = Arc::clone(&self.session.voice);
        voice
            .live_sessions()
            .deregister(self.session.user, self.session.token);
        // The usage record: the audio this session forwarded, the total the
        // release below charges, final now that the session has ended.
        // Recorded FIRST, before any of the closing I/O — the error event to a
        // client that may not read, the provider's close, the Redis release,
        // each up to `close_timeout` — so an app's shutdown drain that runs
        // out during them still finds it recorded. Recorded whether or not
        // the release lands (the record is the record; the budget is the
        // enforcement).
        voice.usage().record(
            self.session.user,
            VoiceMetric::SttMilliseconds,
            self.audio_ms(),
            voice.stream_budget().now(),
        );
        // A limit's event waits for the release: the final charge can spend
        // a LATER window than the one that ended the session — audio the
        // client flushed in the last stretch, up to its pacing lead — so its
        // scope and reset are the release's, when the release reports a
        // window spent, else the ending's own. Every other ending's event goes
        // out first.
        let limit_ending = matches!(ending, Ending::Limit(_));
        if !limit_ending {
            if let Some(event) = ending.error_event() {
                let _ = self.write_client(Message::text(event.to_json())).await;
            }
        }
        let close_provider = close_provider(
            self.provider.take(),
            self.ended,
            self.settings.close_timeout,
        );
        let release = self.meter(MeterMode::Release);
        let ((), released) = tokio::join!(close_provider, release);
        let ending = final_ending(ending, &released);
        if limit_ending {
            if let Some(event) = ending.error_event() {
                let _ = self.write_client(Message::text(event.to_json())).await;
            }
        }
        let drained = close_client(
            &mut self.client,
            &ending,
            Instant::now() + self.settings.close_timeout,
        )
        .await;
        // The client's own close when it closed first; else its reply to
        // the relay's, if it sent one in time.
        let client_close_code = self.client_close_code.or(drained.close_code);
        // An `end` the relay read while it waited for that reply counts too.
        let end_received = self.ended || drained.end;

        let duration_ms = millis(self.started.elapsed());
        let frame = ending.close_frame();
        // `release_ok`: the final charge was made. `lease_deleted`: the lease
        // was still this session's (a superseded one's is not touched).
        let (release_ok, lease_deleted) = match &released {
            Ok(metered) => (true, metered.held),
            Err(_) => (false, false),
        };
        let cause = match &ending {
            Ending::Provider(cause) => Some(cause.as_str()),
            Ending::Policy(what) => Some(*what),
            _ => None,
        };
        // A limit's scope: which window ended the session.
        let limit_scope = match &ending {
            Ending::Limit(limit) => Some(limit.scope.as_str()),
            _ => None,
        };
        let level_warn = matches!(ending, Ending::Provider(_) | Ending::Internal) || !release_ok;
        macro_rules! session_end {
            ($level:ident) => {
                tracing::$level!(
                    user_id = %self.session.user,
                    rate = self.session.format.sample_rate,
                    duration_ms,
                    ready = self.ready_at.is_some(),
                    frames = self.frames,
                    audio_ms = self.audio_ms(),
                    turns = self.turns,
                    ignored = self.ignored,
                    close_code = frame.map(|(code, _)| code),
                    outcome = ending.outcome(),
                    cause,
                    limit_scope,
                    end_received,
                    client_close_code,
                    release_ok,
                    lease_deleted,
                    "voice stream: session end"
                )
            };
        }
        if level_warn {
            session_end!(warn);
        } else {
            session_end!(info);
        }
        if let Err(failure) = released {
            tracing::warn!(
                user_id = %self.session.user,
                error = %failure,
                "voice stream: the release failed; the lease expires on its own"
            );
        }
    }
}

/// A bounded provider write's outcome: its failure, by class, or its bound.
fn provider_write(written: Result<Result<(), SttError>, Elapsed>) -> Result<(), Ending> {
    match written {
        Ok(Ok(())) => Ok(()),
        Ok(Err(failure)) => Err(Ending::Provider(format!("send: {}", failure.class))),
        Err(_) => Err(Ending::Provider("send: timed out".to_string())),
    }
}

/// The ending a session closes with, once its release has answered: a
/// limit takes the release's scope and reset when the release reports a
/// window spent (its final charge can spend a later window than the one
/// that ended the session), and keeps its own when the release failed or
/// reports nothing spent (a crossing since: the windows it charged are new).
/// Every other ending is as it was.
fn final_ending(ending: Ending, released: &Result<Metered, StreamBudgetError>) -> Ending {
    match ending {
        Ending::Limit(ended) => Ending::Limit(
            released
                .as_ref()
                .ok()
                .and_then(Metered::limit_reached)
                .unwrap_or(ended),
        ),
        other => other,
    }
}

/// Charge session `token`'s audio up to `total_ms`, then refresh or release
/// `user`'s lease — as an owned future, so the relay can run a refresh beside
/// itself, and the admission can release the lease of an upgrade that
/// failed.
pub(crate) fn meter<S: SttProvider, T: TtsProvider>(
    voice: Arc<Voice<S, T>>,
    redis: RedisHandle,
    user: Uuid,
    token: Uuid,
    total_ms: u64,
    mode: MeterMode,
) -> MeterFuture {
    Box::pin(async move {
        voice
            .stream_budget()
            .meter(&redis, user, token, total_ms, mode)
            .await
    })
}

/// End the provider side within `timeout` ([`SttSession::close`]: the
/// adapter ends what is still open, or flushes what already finished).
/// `end_sent` says whether the end of input already went out.
async fn close_provider<P: SttSession>(provider: Option<P>, end_sent: bool, timeout: Duration) {
    let Some(provider) = provider else {
        return;
    };
    let _ = tokio::time::timeout(timeout, provider.close(end_sent)).await;
}

/// What [`close_client`] read from the client while it waited for the
/// close reply — for the session-end line (module docs).
#[derive(Debug, Default)]
struct Drained {
    /// The reply's code ([`close_code_of`]), when one arrived in time.
    close_code: Option<u16>,
    /// The client's `end` was among what it still had in flight.
    end: bool,
}

/// The client's side, by `deadline`: the close frame and the client's reply
/// to it — read past whatever the client still had in flight — or, for a
/// client that closed first, the flush of the reply the socket queued.
/// Returns what the drain read ([`Drained`]): the reply's code, and whether
/// an `end` came before it — the control message only, matched exactly as
/// the relay matches it; no other text is looked at, and nothing read here
/// is logged.
async fn close_client(client: &mut WebSocket, ending: &Ending, deadline: Instant) -> Drained {
    let mut drained = Drained::default();
    let Some((code, reason)) = ending.close_frame() else {
        if *ending == Ending::ClientClosed {
            let _ = timeout_at(deadline, client.flush()).await;
        }
        return drained;
    };
    let close = Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    }));
    if !matches!(timeout_at(deadline, client.send(close)).await, Ok(Ok(()))) {
        return drained;
    }
    loop {
        match timeout_at(deadline, client.next()).await {
            Ok(Some(Ok(Message::Close(frame)))) => {
                drained.close_code = Some(close_code_of(frame.as_ref()));
                return drained;
            }
            Ok(Some(Ok(Message::Text(text)))) if text.as_str() == END_FRAME => drained.end = true,
            Ok(Some(Err(_)) | None) | Err(_) => return drained,
            Ok(Some(Ok(_))) => {}
        }
    }
}

/// A client close frame's code — `1005` (RFC 6455 §7.1.5, "no status
/// received") for a frame that carried none. Only the code: the reason is
/// never read (module docs).
fn close_code_of(frame: Option<&CloseFrame>) -> u16 {
    frame.map_or(close_code::NO_STATUS_RECEIVED, |frame| frame.code)
}

/// A failed read from the client, as an ending. An oversized message (the
/// 64 KiB limit) and a protocol breach are the client's fault and get a
/// `1008`; a connection that went away is just gone.
fn client_read_error(error: &axum::Error) -> Ending {
    use std::error::Error as _;
    use tungstenite::error::ProtocolError;
    use tungstenite::Error;
    match error
        .source()
        .and_then(|source| source.downcast_ref::<Error>())
    {
        Some(Error::Capacity(_)) => Ending::Policy("message too big"),
        Some(Error::Utf8(_)) => Ending::Policy("invalid utf-8"),
        Some(Error::Protocol(ProtocolError::ResetWithoutClosingHandshake)) => Ending::ClientGone,
        Some(Error::Protocol(_)) => Ending::Policy("protocol error"),
        _ => Ending::ClientGone,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every ending's wire: the event (if any), the code, and the reason —
    /// and its outcome word.
    #[test]
    fn the_close_machine_maps_each_ending() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-10-17T12:00:00Z")
            .expect("an instant")
            .with_timezone(&chrono::Utc);
        let limit = LimitReached::from_mask(1, at).expect("a spent window");
        for (ending, event, frame, outcome) in [
            (Ending::Done, None, Some((1000, "done")), "done"),
            (Ending::ClientClosed, None, None, "client_closed"),
            (Ending::ClientGone, None, None, "client_gone"),
            (
                Ending::Shutdown,
                None,
                Some((1001, "shutting down")),
                "shutdown",
            ),
            (
                Ending::Policy("pacing"),
                None,
                Some((1008, "pacing")),
                "policy",
            ),
            (
                Ending::Provider("closed".into()),
                Some(RelayEvent::error(ErrorCode::Provider)),
                Some((1011, "provider error")),
                "provider",
            ),
            (
                Ending::Internal,
                Some(RelayEvent::error(ErrorCode::Internal)),
                Some((1011, "internal error")),
                "internal",
            ),
            (
                Ending::SessionLimit,
                None,
                Some((4000, "session limit")),
                "session_limit",
            ),
            (
                Ending::Superseded,
                None,
                Some((4001, "superseded")),
                "superseded",
            ),
            (
                Ending::Limit(limit),
                Some(RelayEvent::limit(&limit)),
                Some((4002, "limit reached")),
                "limit",
            ),
        ] {
            assert_eq!(ending.error_event(), event, "{ending:?}");
            assert_eq!(ending.close_frame(), frame, "{ending:?}");
            assert_eq!(ending.outcome(), outcome, "{ending:?}");
        }
        assert_eq!(
            Ending::Limit(limit).error_event().map(|event| event.to_json()),
            Some(
                r#"{"type":"error","code":"limit","scope":"user_day","resets_at":"2026-10-18T00:00:00Z"}"#
                    .to_string()
            )
        );
    }

    /// A limit ending takes the release's scope when the release reports a
    /// window spent, and keeps its own when the release failed or spent
    /// nothing; no other ending changes.
    #[test]
    fn the_final_ending_is_the_releases_limit_when_it_names_one() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-10-17T12:00:00Z")
            .expect("an instant")
            .with_timezone(&chrono::Utc);
        let day = LimitReached::from_mask(1, at).expect("the day");
        let metered = |month_left: i64| Metered {
            held: true,
            user_day_remaining_ms: 5_000,
            user_month_remaining_ms: month_left,
            global_remaining_ms: 5_000,
            at,
        };
        let month = metered(0).limit_reached().expect("the month");
        assert_eq!(month.scope, LimitScope::UserMonth);
        assert_eq!(
            final_ending(Ending::Limit(day), &Ok(metered(0))),
            Ending::Limit(month)
        );
        assert_eq!(
            final_ending(Ending::Limit(day), &Ok(metered(1))),
            Ending::Limit(day)
        );
        assert_eq!(
            final_ending(
                Ending::Limit(day),
                &Err(StreamBudgetError::Backend("down".into()))
            ),
            Ending::Limit(day)
        );
        assert_eq!(
            final_ending(Ending::Done, &Ok(metered(0))),
            Ending::Done,
            "only a limit takes the release's scope"
        );
    }

    /// A grant at `at` with these remainders, in ms.
    fn grant(at: &str, day: i64, month: i64, global: i64) -> Grant {
        Grant {
            user_day_remaining_ms: day,
            user_month_remaining_ms: month,
            global_remaining_ms: global,
            took_over: false,
            at: chrono::DateTime::parse_from_rfc3339(at)
                .expect("an instant")
                .with_timezone(&chrono::Utc),
            origin: Instant::now(),
        }
    }

    const MINUTE: i64 = 60_000;
    const HOUR: i64 = 60 * MINUTE;

    /// Mid-month, the smallest remainder decides the deadline and names the
    /// scope — the user's day, the user's month or everyone's month — and
    /// remainders that run out together are reported as a refusal's are
    /// (the user's month over everyone's, a month over the day).
    #[test]
    fn the_earliest_window_to_run_out_sets_the_deadline_and_its_scope() {
        let noon = "2026-10-17T12:00:00Z";
        let zero = Duration::ZERO;
        for ((day, month, global), after, scope) in [
            ((MINUTE, HOUR, HOUR), MINUTE, LimitScope::UserDay),
            ((HOUR, MINUTE, HOUR), MINUTE, LimitScope::UserMonth),
            ((HOUR, HOUR, MINUTE), MINUTE, LimitScope::GlobalMonth),
            ((HOUR, MINUTE, MINUTE), MINUTE, LimitScope::UserMonth),
            ((MINUTE, HOUR, MINUTE), MINUTE, LimitScope::GlobalMonth),
            ((MINUTE, MINUTE, MINUTE), MINUTE, LimitScope::UserMonth),
            ((300, 400, 500), 300, LimitScope::UserDay),
        ] {
            let (deadline, limit) = budget_deadline(&grant(noon, day, month, global), zero)
                .unwrap_or_else(|| panic!("binds: {day} {month} {global}"));
            assert_eq!(
                deadline,
                Duration::from_millis(u64::try_from(after).expect("positive"))
            );
            assert_eq!(limit.scope, scope, "{day} {month} {global}");
        }
    }

    /// **A calendar crossing never closes a session**: a window whose
    /// remainder outlasts the window itself resets first, so it does not
    /// bind. Two seconds before the month ends, three seconds of the user's
    /// month (and of the day, which ends with it) do not bind; one second
    /// does. The time from the grant to `ready` counts: the same three
    /// seconds an hour before midnight bind; with two seconds left and a
    /// one-second grant-to-ready delay, one second still binds, two do not.
    /// (The negative control is the first case of each pair.)
    #[test]
    fn a_window_that_resets_before_it_runs_out_does_not_bind() {
        let late = "2026-10-31T23:59:58Z";
        let zero = Duration::ZERO;
        assert_eq!(
            budget_deadline(&grant(late, 3_000, 3_000, 3_000), zero),
            None,
            "every window resets in two seconds, before three seconds run out"
        );
        let (deadline, limit) =
            budget_deadline(&grant(late, HOUR, 1_000, HOUR), zero).expect("binds");
        assert_eq!(deadline, Duration::from_secs(1));
        assert_eq!(limit.scope, LimitScope::UserMonth);
        assert_eq!(limit.resets_at.to_rfc3339(), "2026-11-01T00:00:00+00:00");

        let hour_before = "2026-10-31T23:00:00Z";
        let (deadline, limit) =
            budget_deadline(&grant(hour_before, HOUR, 3_000, HOUR), zero).expect("binds");
        assert_eq!(deadline, Duration::from_secs(3));
        assert_eq!(limit.scope, LimitScope::UserMonth);

        let one_second = Duration::from_secs(1);
        assert!(budget_deadline(&grant(late, HOUR, 900, HOUR), one_second).is_some());
        assert_eq!(
            budget_deadline(&grant(late, HOUR, 1_000, HOUR), one_second),
            None,
            "ready one second after the grant: the month ends as one second runs out"
        );

        // A user's day that ends at midnight mid-month: only the day resets.
        let before_midnight = "2026-10-17T23:59:58Z";
        let (deadline, limit) = budget_deadline(&grant(before_midnight, 3_000, 5_000, HOUR), zero)
            .expect("the month binds");
        assert_eq!(deadline, Duration::from_secs(5), "the day does not bind");
        assert_eq!(limit.scope, LimitScope::UserMonth);
    }

    /// A newer registration cancels the older one; re-registering the same
    /// token is no takeover; another user's registration touches nothing; a
    /// superseded session's deregistration leaves the newer one registered.
    #[test]
    fn a_newer_registration_supersedes_and_only_the_owner_deregisters() {
        let live = LiveSessions::default();
        let (user, other_user) = (Uuid::new_v4(), Uuid::new_v4());
        let (first, second) = (Uuid::new_v4(), Uuid::new_v4());
        let first_cancel = live.register(user, first, 1);
        let again = live.register(user, first, 1);
        assert!(
            !first_cancel.is_cancelled(),
            "the same token is not a takeover"
        );
        let other = live.register(other_user, Uuid::new_v4(), 7);
        assert!(
            !first_cancel.is_cancelled(),
            "another user's session is not a takeover"
        );
        let second_cancel = live.register(user, second, 2);
        assert!(first_cancel.is_cancelled() && again.is_cancelled());
        assert!(!second_cancel.is_cancelled() && !other.is_cancelled());
        live.deregister(user, first);
        assert_eq!(
            live.len(),
            2,
            "the stale deregistration removed the newer session"
        );
        live.deregister(user, second);
        assert_eq!(live.len(), 1);
    }

    /// Registration follows the fence's order, not arrival order: the
    /// session that acquired on ticket 2 registers first, and the late
    /// registration of ticket 1 (its acquire's reply was slower) is born
    /// superseded and leaves ticket 2's session running and registered;
    /// ticket 3 then supersedes ticket 2 as usual.
    #[test]
    fn a_late_registration_on_an_older_ticket_is_born_superseded() {
        let live = LiveSessions::default();
        let user = Uuid::new_v4();
        let (older, newer, newest) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let newer_cancel = live.register(user, newer, 2);
        let older_cancel = live.register(user, older, 1);
        assert!(
            !newer_cancel.is_cancelled(),
            "the late registration of an older ticket superseded the newer session"
        );
        assert!(
            older_cancel.is_cancelled(),
            "the late session is superseded"
        );
        live.deregister(user, older);
        assert_eq!(live.len(), 1, "the newer session is still registered");
        let newest_cancel = live.register(user, newest, 3);
        assert!(newer_cancel.is_cancelled() && !newest_cancel.is_cancelled());
    }

    /// A ticket is comparable only within its fence's life: a registration
    /// a fence lifetime old (the user's numbering may have restarted at `1`
    /// since) is superseded by any newer one, a lower ticket included.
    #[test]
    fn a_registration_older_than_the_fence_is_superseded_by_any_ticket() {
        let live = LiveSessions::default();
        let user = Uuid::new_v4();
        let start = Instant::now();
        let stale = live.register_at(user, Uuid::new_v4(), 40, start);
        let just_inside = live.register_at(
            user,
            Uuid::new_v4(),
            1,
            start + FENCE_TTL - Duration::from_millis(1),
        );
        assert!(just_inside.is_cancelled() && !stale.is_cancelled());
        let restarted = live.register_at(user, Uuid::new_v4(), 1, start + FENCE_TTL);
        assert!(stale.is_cancelled() && !restarted.is_cancelled());
        assert_eq!(FENCE_TTL, Duration::from_secs(86_400));
    }

    /// A client close frame is recorded by its code alone — any code, the
    /// client table's or not, the server's own range included — and a frame
    /// without one as `1005`. The reason is not an input at all.
    #[test]
    fn a_client_close_frame_is_recorded_by_its_code_alone() {
        for code in [1000, 1001, 4000, 4100, 4101, 4102, 4103, 4104, 4999] {
            let frame = CloseFrame {
                code,
                reason: "a reason that is never read".into(),
            };
            assert_eq!(close_code_of(Some(&frame)), code);
        }
        assert_eq!(close_code_of(None), 1005);
    }

    /// The client socket's bounds: a 16 KiB read buffer, and four of the
    /// largest frames (64 KiB) of write buffer; the run cap is 32.
    #[test]
    fn the_socket_bounds_and_the_run_cap() {
        assert_eq!(READ_BUFFER_BYTES, 16_384);
        assert_eq!(MAX_WRITE_BUFFER_BYTES, 262_144);
        assert_eq!(PROVIDER_RUN_CAP, 32);
    }
}
