//! The speech-to-text relay's lease and audio budget: one live session per
//! user, and the audio the provider may be sent.
//!
//! Keys, under a prefix the app passes (there is no default):
//!
//! | key | holds | lifetime |
//! |---|---|---|
//! | `{prefix}:lease:{user}` | the live session's random token | [`LEASE_TTL`], refreshed every tick |
//! | `{prefix}:user:{user}:{YYYY-MM-DD}` | the user's audio today, in ms | the UTC day + an hour |
//! | `{prefix}:user-month:{user}:{YYYY-MM}` | the user's audio this month, in ms | the UTC month + a day |
//! | `{prefix}:global:{YYYY-MM}` | everyone's audio this month, in ms | the UTC month + a day |
//! | `{prefix}:session:{token}` | what this session has been charged, in ms | [`METER_TTL_SECONDS`] |
//! | `{prefix}:admit:{user}` | the token of the user's last admitted upgrade | the admission interval |
//! | `{prefix}:fence:{user}` | a hash; its field `next` is the user's last issued ticket | [`FENCE_TTL_SECONDS`] (a day), refreshed at every issue and grant |
//!
//! Caps ([`StreamCaps`]): the app's configuration, set in minutes
//! ([`StreamCaps::from_minutes`], held to the same startup rule as the text
//! budget's caps) and counted in milliseconds of audio. Everyone's month is
//! the spending ceiling; [`crate::budget`]'s module docs say what a refusal
//! reports (the scope) and why a user's month that starts mid-month
//! under-counts that month — true here too.
//!
//! # The lease: a new session takes over
//!
//! [`StreamBudget::acquire`] SETS the lease to a fresh token, whatever it held:
//! a client that dropped off Wi-Fi and reconnected on a cellular network must
//! not wait half a minute for its own dead session to expire. The superseded
//! session finds a foreign token at its next refresh and closes.
//!
//! **An acquire is sent at most once** ([`Replay::Never`]): it IS the
//! takeover, so a second run after a lost reply could overwrite a session
//! that took the lease in between (both would believe they hold it), would
//! report `took_over = false` for a real takeover (the first run already
//! wrote the token), and would restart the lease's and the admission key's
//! TTLs. A lost reply is therefore a `503` and no session; the token it may
//! have written expires within [`LEASE_TTL`], or is taken over by the
//! client's next upgrade. So that a cached connection that merely died while
//! idle does not cost the session that way, the app's admission sends a
//! `PING` first, which IS retried on a fresh connection.
//!
//! # Fenced: the newest ticket wins
//!
//! `Never` stops a SECOND run, not a LATE first one: an acquire delayed in
//! transit past its response timeout could land after the app answered
//! `503`, and SET the lease to a session that never started over one that
//! did (closing it, superseded by nobody). So every upgrade first takes a
//! TICKET ([`StreamBudget::issue_ticket`]): one script that `HINCRBY`s the
//! user's fence hash's `next` and `EXPIRE`s the hash to
//! [`FENCE_TTL_SECONDS`], sent [`Replay::Never`] after the `PING`. A lost
//! reply is the app's `503`, and nothing ever re-sends an increment: the
//! ticket it may have taken is simply never used. The acquire carries the
//! ticket, and its script refuses ([`StreamBudgetError::Stale`]) — writing
//! NOTHING — any ticket that is not the hash's current `next`. Since every
//! later upgrade takes a higher ticket first, an acquire that lands after a
//! newer upgrade took its ticket is refused, wherever it was delayed; a
//! legitimately racing second device gets the same retryable `503` and opens
//! on its retry. A grant refreshes the hash's expiry.
//!
//! **The guarantee is bounded by the hash's life:** a day, refreshed at
//! every issue and every grant. A delayed acquire is refused while the hash
//! that numbered it lives; once a user's hash has expired (no upgrade for a
//! day), numbering starts again at `1`, and an acquire delayed by more than
//! a day could carry a ticket the new numbering reissues. A day is far
//! longer than any plausible delay in transit, and the keys never accumulate.
//! A missing hash refuses every ticket (`next` is then no ticket at all).
//!
//! The fence is not the lease: a session's refresh and release still
//! compare the lease's TOKEN (below), so a ticket taken by an upgrade that
//! is then refused (throttled, a spent budget, a lost reply) never disturbs
//! the session that holds the lease.
//!
//! Every later call COMPARES the token first: a refresh extends only its own
//! lease, and a release deletes only its own — a superseded session's release
//! must never delete the session that superseded it.
//!
//! # One upgrade per user per admission interval
//!
//! A takeover is cheap for the client and not for the app: each one is a
//! provider dial, and until the superseded session notices, two sessions
//! stream. So the acquire also sets an admission key for the user — `SET NX
//! PX`, done inside the script as a read then a write, which the script's
//! atomicity makes the same thing — and a second upgrade inside the interval
//! (the relay's admission interval, 2 s by default) is refused —
//! [`StreamBudgetError::Throttled`], a `429` with `Retry-After` — before
//! anything is dialled or superseded. The key holds the token, so the same
//! token is admitted again (the script's own rule; nothing re-sends an
//! acquire, see above). A request the BUDGET refuses never reaches it: that
//! `429` is cheap already and keeps its own `Retry-After` (the script's
//! order: validate, then the fence, then the budgets, then the admission
//! interval, then the writes).
//!
//! # Charged by audio, idempotently
//!
//! The relay charges the audio it SENT the provider, in milliseconds (bytes
//! ÷ the format's bytes per second, [`audio_ms`]), not wall time and never a
//! provider's own unit. Each call carries the session's CUMULATIVE total, and
//! the script charges only the difference from the total stored under the
//! session's meter key. A second run of a call whose answer was lost (it is
//! sent under [`Replay::OnceOnFreshConnection`]: once more on a fresh
//! connection after a cached one failed) — or a later tick after a failed
//! one — therefore charges each millisecond exactly once, without a verdict
//! key per call. [`StreamBudget::meter`] says why that replay is safe.
//!
//! The day and month keys are chosen at each call, so audio after midnight
//! UTC is the new day's (and after the first of the month, the new month's).
//! Remaining budget is reported after the charge; a non-positive figure ends
//! the session (with the spent window's scope). So a cap is found spent at a
//! refresh, not the instant it is crossed — except that the relay also caps
//! a session up front at what admission saw left in each window, unless that
//! window resets first: crossing a UTC boundary only starts new counters,
//! and never ends a session by itself. What the up-front cap cannot see is
//! OTHER sessions spending a shared window meanwhile (everyone's month, or
//! the user's on another device): each live session can overshoot such a
//! window by at most one refresh interval of audio.
//!
//! # Accepted limits
//!
//! Three inaccuracies are accepted rather than paid for, each bounded and each
//! in the user's favour or neutral:
//!
//! - **A crash before the first refresh under-charges.** Audio is charged at
//!   each refresh and at the release, both run by the relay; an instance that
//!   dies (out of memory, a hard kill past the platform's grace) before its
//!   session's first refresh charges nothing for that session. At most the
//!   pacing lead plus one refresh interval of audio goes uncharged per
//!   session so lost, and the lease expires on its own ([`LEASE_TTL`]).
//! - **A UTC boundary attributes up to one interval to the new window.** The
//!   day and month are read when a charge is made, not when the audio was
//!   sent, so audio sent before midnight UTC (or the month's end) and charged
//!   at the first refresh after it counts against the new day or month — at
//!   most one refresh interval of audio per session per boundary.
//! - **Redis failing mid-session under-charges** (only ADMISSION fails
//!   closed). A refresh that cannot reach Redis does not end the session: the
//!   relay keeps forwarding audio until a failed refresh finds the last good
//!   one a whole [`LEASE_TTL`] ago, so up to that lifetime plus a refresh
//!   interval of audio streams uncharged-so-far. The totals are cumulative,
//!   so a later good refresh or the release charges it all — but if the
//!   session's final release fails too, there is no durable queue to retry
//!   it, and that audio is never charged.
//!
//! # Validated before anything is written
//!
//! As [`crate::budget`]'s script, and with its helpers: every counter is
//! read and checked, the lease, the admission key and the fence read, and
//! every argument parsed, before the first write, so a poisoned counter, a
//! key of the wrong type (a fence that is not a hash included), a fence
//! whose `next` is not a canonical integer, or a bad argument is an error
//! that wrote nothing (Redis does not roll a script back).
//!
//! **One command per key, value and expiry together**, for the reason the
//! text budget gives (Redis checks permissions per command inside a script
//! and keeps the writes before a refused one): the acquire's two writes are
//! `SET … PX`; the meter's charge is a `SET … EX` per counter and the meter,
//! and its refresh of the lease a `SET … PX` of the token it already holds —
//! never an `INCRBY`, an `EXPIRE` or a `PEXPIRE`. That keeps a denied
//! command from writing part of a charge; it is NOT all-or-nothing across
//! commands, and the partial states it allows are these:
//!
//! - **the release's `DEL` comes last.** A denied `DEL` leaves the counters
//!   and the session meter charged and the lease to expire on its own — the
//!   state a failed release leaves anyway. The call answers `Backend`, and a
//!   replay of that release charges nothing (the meter already holds the
//!   total) and fails at the `DEL` again.
//! - **The fence is a HASH**, which no single command both sets and expires,
//!   so it is the exception, ordered so a refused command costs nothing that
//!   matters. The grant's `EXPIRE` of the fence comes FIRST of its writes: a
//!   denied one leaves nothing written, and an allowed `EXPIRE` followed by a
//!   denied `SET` only refreshed the fence's expiry (one command, `SET`,
//!   writes both the admission key and the lease, so both are denied). The
//!   issue's `EXPIRE` follows its `HINCRBY`: a denied one leaves `next`
//!   raised with the hash's previous expiry (none, if the hash was new)
//!   until a later issue sets one — a raised `next` only makes older tickets
//!   stale, which is the fence's own direction — and the issue answers an
//!   error, so that ticket is never used.

use std::time::Duration;

use chrono::{DateTime, Utc};
use stridelabs_redis::{RedisError, RedisHandle, Replay};
use tokio::time::Instant;
use uuid::Uuid;

use crate::budget::{
    check_caps, global_month_key, lua_helpers, user_day_key, user_month_key, CapsError,
    LimitReached, Spent, INVALID_COUNTER,
};
use crate::window::{key_ttls, system_clock, Clock};

/// How long a lease lives unrefreshed: three of the relay's default refresh
/// ticks (10 s). A session whose process died stops holding its user's lease
/// within half a minute.
pub const LEASE_TTL: Duration = Duration::from_secs(30);

/// How long a user's fence hash lives after its last issue or grant: the
/// bound on the fencing guarantee (module docs).
pub const FENCE_TTL_SECONDS: i64 = 24 * 60 * 60;

/// How long a session's meter outlives its last charge — far past a
/// session's length, so a late retried release still finds it.
pub const METER_TTL_SECONDS: i64 = 60 * 60;

/// Milliseconds in a minute: the speech-to-text caps are set in minutes and
/// counted in milliseconds of audio.
pub const MILLIS_PER_MINUTE: i64 = 60_000;

/// The SHA-1 of the exact bytes `ISSUE_SCRIPT` sends (the extraction base's,
/// tapper `82be95f`).
pub const ISSUE_SCRIPT_SHA1: &str = "71b413abe08a2fe9288ecd807b0e8e8fad6cc6c0";

/// The SHA-1 of the exact bytes `ACQUIRE_SCRIPT` sends (the extraction
/// base's, tapper `82be95f`).
pub const ACQUIRE_SCRIPT_SHA1: &str = "96f220b3004096553dc0fa570d43b306aa7e52d9";

/// The SHA-1 of the exact bytes `METER_SCRIPT` sends (the extraction base's,
/// tapper `82be95f`).
pub const METER_SCRIPT_SHA1: &str = "b07b06c546464c457e44086bce1d96cbd5823ecb";

/// The acquire's sentinel for an upgrade inside the admission interval (a
/// sentinel beside [`INVALID_COUNTER`], so the spent-window bitmask can use
/// every value from `1` to `7`).
pub(crate) const THROTTLED: i64 = -2;

/// The acquire's sentinel for a ticket that is not the fence's current
/// `next`: a newer upgrade took a ticket since (or the hash is gone).
/// Nothing was written.
pub(crate) const STALE: i64 = -3;

/// Issue the user's next ticket.
///
/// ```text
/// KEYS = fence
/// ARGV = fence_ttl_s
/// ```
///
/// Validates first — the hash's `next` (`HGET`: a fence of another TYPE
/// fails it) must be absent or a canonical non-negative integer, and the
/// TTL a positive whole number — answering `-1` ([`INVALID_COUNTER`]) having
/// written nothing. Then `HINCRBY next 1` and `EXPIRE` (module docs on the
/// order), and answers the new `next`: the ticket, `1` or more.
pub(crate) const ISSUE_SCRIPT: &str = concat!(
    lua_helpers!(),
    "\
local current = redis.call('HGET', KEYS[1], 'next')
local fence_ttl = positive(ARGV[1])
if not fence_ttl or (current and not canonical(current)) then
  return -1
end
local ticket = redis.call('HINCRBY', KEYS[1], 'next', 1)
redis.call('EXPIRE', KEYS[1], fence_ttl)
return ticket
"
);

/// Check the fence and the three caps, admit the upgrade, then take the
/// lease.
///
/// ```text
/// KEYS = lease  user-day  user-month  global-month  admit  fence
/// ARGV = token  lease_ttl_ms  user_day_cap_ms  user_month_cap_ms  global_cap_ms  admit_ms
///        ticket  fence_ttl_s
/// ```
///
/// In this order — validate, the fence, the budgets, the admission
/// interval, the writes — it answers
/// `{verdict, user_day_remaining, user_month_remaining, global_remaining, took_over}`:
///
/// - `-1` ([`INVALID_COUNTER`]): a counter, or the fence's `next`, is not a
///   canonical non-negative integer, or an argument not what it should be;
///   nothing written;
/// - `-3` ([`STALE`]): the ticket is not the fence's current `next` (a newer
///   upgrade took one since, or the hash is gone); nothing written;
/// - `1` to `7`: a bitmask of the spent caps (`1` the user's day, `2`
///   everyone's month, `4` the user's month); nothing written;
/// - `-2` ([`THROTTLED`]): another token was admitted for this user inside
///   the admission interval; nothing written;
/// - `0`: the fence's expiry refreshed (`EXPIRE`, first: module docs), then
///   the admission key and the lease SET to the token, each one `SET … PX`;
///   the remainders are each cap less its counter, and `took_over` is `1`
///   when the lease held another token.
///
/// Every key is read before the first write.
pub(crate) const ACQUIRE_SCRIPT: &str = concat!(
    lua_helpers!(),
    "\
local day = counter(KEYS[2])
local month = counter(KEYS[3])
local global = counter(KEYS[4])
local previous = redis.call('GET', KEYS[1])
local admitted = redis.call('GET', KEYS[5])
local fence = redis.call('HGET', KEYS[6], 'next')
local lease_ttl = positive(ARGV[2])
local day_cap = whole(ARGV[3])
local month_cap = whole(ARGV[4])
local global_cap = whole(ARGV[5])
local admit_ms = positive(ARGV[6])
local ticket = positive(ARGV[7])
local fence_ttl = positive(ARGV[8])
local current = nil
if fence then
  current = canonical(fence)
end
if not (day and month and global and lease_ttl and day_cap and month_cap and global_cap
    and admit_ms and ticket and fence_ttl) or ARGV[1] == '' or (fence and not current) then
  return {-1, 0, 0, 0, 0}
end
if current ~= ticket then
  return {-3, 0, 0, 0, 0}
end
local over = 0
if day >= day_cap then
  over = over + 1
end
if global >= global_cap then
  over = over + 2
end
if month >= month_cap then
  over = over + 4
end
if over ~= 0 then
  return {over, 0, 0, 0, 0}
end
if admitted and admitted ~= ARGV[1] then
  return {-2, 0, 0, 0, 0}
end
redis.call('EXPIRE', KEYS[6], fence_ttl)
redis.call('SET', KEYS[5], ARGV[1], 'PX', admit_ms)
redis.call('SET', KEYS[1], ARGV[1], 'PX', lease_ttl)
local took_over = 0
if previous and previous ~= ARGV[1] then
  took_over = 1
end
return {0, day_cap - day, month_cap - month, global_cap - global, took_over}
"
);

/// Charge the session's audio so far, then refresh or release its lease —
/// only if it is still this session's.
///
/// ```text
/// KEYS = lease  user-day  user-month  global-month  session-meter
/// ARGV = token  total_ms  release(0|1)  lease_ttl_ms  user_day_cap_ms  user_month_cap_ms
///        global_cap_ms  day_ttl_s  month_ttl_s  meter_ttl_s
/// ```
///
/// Answers `{held, user_day_remaining, user_month_remaining, global_remaining}`
/// — `held` `1` when the lease was this token's (and was extended, or deleted
/// on release), `0` when it was not (and was not touched) — or
/// `{-1, 0, 0, 0}` having written nothing. The charge is `total_ms` minus
/// the meter, when positive: each counter is SET to its value plus it, the
/// meter to `total_ms`, each with its expiry. It is made whether or not the
/// lease is still held, because the audio was sent. Then the lease: a
/// refresh SETs it to the token it holds with a fresh `PX`; a release
/// `DEL`etes it, last (module docs).
pub(crate) const METER_SCRIPT: &str = concat!(
    lua_helpers!(),
    "\
local day = counter(KEYS[2])
local month = counter(KEYS[3])
local global = counter(KEYS[4])
local metered = counter(KEYS[5])
local held = redis.call('GET', KEYS[1]) == ARGV[1]
local total = whole(ARGV[2])
local release = ARGV[3]
local lease_ttl = positive(ARGV[4])
local day_cap = whole(ARGV[5])
local month_cap = whole(ARGV[6])
local global_cap = whole(ARGV[7])
local day_ttl = positive(ARGV[8])
local month_ttl = positive(ARGV[9])
local meter_ttl = positive(ARGV[10])
if not (day and month and global and metered and total and lease_ttl and day_cap and month_cap
    and global_cap and day_ttl and month_ttl and meter_ttl)
    or (release ~= '0' and release ~= '1') then
  return {-1, 0, 0, 0}
end
local delta = total - metered
if delta > 0 then
  day = day + delta
  month = month + delta
  global = global + delta
  redis.call('SET', KEYS[2], day, 'EX', day_ttl)
  redis.call('SET', KEYS[3], month, 'EX', month_ttl)
  redis.call('SET', KEYS[4], global, 'EX', month_ttl)
  redis.call('SET', KEYS[5], ARGV[2], 'EX', meter_ttl)
end
local answer = 0
if held then
  answer = 1
  if release == '1' then
    redis.call('DEL', KEYS[1])
  else
    redis.call('SET', KEYS[1], ARGV[1], 'PX', lease_ttl)
  end
end
return {answer, day_cap - day, month_cap - month, global_cap - global}
"
);

/// The speech-to-text caps, in milliseconds of audio: the user's UTC day,
/// the user's UTC month and everyone's UTC month. The app sets them in
/// minutes ([`StreamCaps::from_minutes`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamCaps {
    user_day_ms: i64,
    user_month_ms: i64,
    global_month_ms: i64,
}

impl StreamCaps {
    /// The largest cap, in minutes: the most whose milliseconds still fit an
    /// `i64` (the scripts' counters and remainders).
    pub const MAX_MINUTES: i64 = i64::MAX / MILLIS_PER_MINUTE;

    /// The caps, set in minutes, when each is `1..=`[`StreamCaps::MAX_MINUTES`]
    /// and they run a user's day <= a user's month <= everyone's month.
    ///
    /// # Errors
    ///
    /// [`CapsError`], naming every problem (with `max` the largest number of
    /// minutes).
    pub fn from_minutes(
        user_day: i64,
        user_month: i64,
        global_month: i64,
    ) -> Result<StreamCaps, CapsError> {
        check_caps(
            [user_day, user_month, global_month],
            StreamCaps::MAX_MINUTES,
        )?;
        // In range: each product fits an `i64` (MAX_MINUTES' definition).
        Ok(StreamCaps {
            user_day_ms: user_day * MILLIS_PER_MINUTE,
            user_month_ms: user_month * MILLIS_PER_MINUTE,
            global_month_ms: global_month * MILLIS_PER_MINUTE,
        })
    }

    /// The caps as given, in milliseconds, unchecked: a test seam, for caps
    /// smaller than a minute or refused by the startup rule.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn unchecked(
        user_day_ms: i64,
        user_month_ms: i64,
        global_month_ms: i64,
    ) -> StreamCaps {
        StreamCaps {
            user_day_ms,
            user_month_ms,
            global_month_ms,
        }
    }

    /// Audio one user may stream per UTC day, in ms.
    #[must_use]
    pub fn user_day_ms(self) -> i64 {
        self.user_day_ms
    }

    /// Audio one user may stream per UTC calendar month, in ms.
    #[must_use]
    pub fn user_month_ms(self) -> i64 {
        self.user_month_ms
    }

    /// Audio everyone together may stream per UTC calendar month, in ms: the
    /// spending ceiling.
    #[must_use]
    pub fn global_month_ms(self) -> i64 {
        self.global_month_ms
    }
}

/// A session that may start: the lease is its token's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// The user's audio left today, in ms (positive).
    pub user_day_remaining_ms: i64,
    /// The user's audio left this month, in ms (positive).
    pub user_month_remaining_ms: i64,
    /// Everyone's audio left this month, in ms (positive).
    pub global_remaining_ms: i64,
    /// Whether another session held the lease and has now been superseded.
    pub took_over: bool,
    /// The instant the windows were read at (the budget's clock): when each
    /// of them ends is reckoned from here.
    pub at: DateTime<Utc>,
    /// [`Grant::at`] on the process's monotonic clock, captured at the SAME
    /// point (before the acquire was sent), so every deadline the relay
    /// derives from the pair counts the acquire's own round trip (an origin
    /// taken after a slow acquire would bind a window that had already
    /// reset).
    pub origin: Instant,
}

/// What a refresh or release found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metered {
    /// Whether the lease was still this session's.
    pub held: bool,
    /// The user's audio left today after this charge, in ms; `<= 0` is spent.
    pub user_day_remaining_ms: i64,
    /// The user's audio left this month after this charge, in ms.
    pub user_month_remaining_ms: i64,
    /// Everyone's audio left this month after this charge, in ms.
    pub global_remaining_ms: i64,
    /// The instant the windows were read at (the budget's clock).
    pub at: DateTime<Utc>,
}

impl Metered {
    /// The windows now spent (a remainder of zero or less).
    #[must_use]
    pub fn spent(&self) -> Spent {
        Spent {
            user_day: self.user_day_remaining_ms <= 0,
            user_month: self.user_month_remaining_ms <= 0,
            global_month: self.global_remaining_ms <= 0,
        }
    }

    /// The limit a spent window ends the session with — its scope chosen as
    /// a refusal's is ([`Spent::scope`]) — or `None` while every window has
    /// audio left.
    #[must_use]
    pub fn limit_reached(&self) -> Option<LimitReached> {
        LimitReached::new(self.spent(), self.at)
    }
}

/// Refresh the lease, or release it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeterMode {
    /// Extend the lease by [`LEASE_TTL`].
    Refresh,
    /// Delete the lease. The session's last call.
    Release,
}

/// Why a session may not start, or a call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamBudgetError {
    /// A budget is spent; the lease was not taken.
    Exceeded(LimitReached),
    /// Another upgrade for this user was admitted inside the admission
    /// interval; nothing was written, nothing superseded.
    Throttled {
        /// `Retry-After`: the interval, in whole seconds, at least 1.
        retry_after_seconds: u64,
    },
    /// The acquire's ticket is no longer the user's newest: another upgrade
    /// took a ticket after it (or the fence hash is gone). Nothing was
    /// written, nothing superseded.
    Stale,
    /// Redis could not be asked, answered with an error, holds a counter
    /// that is not a non-negative integer (nothing was written), or
    /// answered something the script never answers.
    Backend(String),
}

impl std::fmt::Display for StreamBudgetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamBudgetError::Exceeded(limit) => write!(
                formatter,
                "the voice stream budget is spent ({})",
                limit.scope.as_str()
            ),
            StreamBudgetError::Throttled { .. } => {
                formatter.write_str("another voice stream was admitted for this user just now")
            }
            StreamBudgetError::Stale => formatter
                .write_str("a newer voice stream upgrade for this user took a ticket first"),
            StreamBudgetError::Backend(detail) => {
                write!(formatter, "voice stream budget: {detail}")
            }
        }
    }
}

impl std::error::Error for StreamBudgetError {}

/// Where the lease and the counters live, the caps they are held to, and the
/// clock that names the day and the month. Cloning shares the clock.
#[derive(Clone)]
pub struct StreamBudget {
    prefix: String,
    caps: StreamCaps,
    clock: Clock,
}

/// The prefix and the caps; never the clock.
impl std::fmt::Debug for StreamBudget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamBudget")
            .field("prefix", &self.prefix)
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

impl StreamBudget {
    /// The budget counting under `prefix` (the app's: there is no default),
    /// held to `caps`, on the system clock.
    #[must_use]
    pub fn new(prefix: impl Into<String>, caps: StreamCaps) -> StreamBudget {
        StreamBudget {
            prefix: prefix.into(),
            caps,
            clock: system_clock(),
        }
    }

    /// The same budget on another clock: the day- and month-boundary seam.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn with_clock(
        self,
        clock: impl Fn() -> DateTime<Utc> + Send + Sync + 'static,
    ) -> StreamBudget {
        StreamBudget {
            clock: std::sync::Arc::new(clock),
            ..self
        }
    }

    /// The key prefix this budget counts under.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The caps this budget is held to.
    #[must_use]
    pub fn caps(&self) -> StreamCaps {
        self.caps
    }

    /// `user`'s lease.
    #[must_use]
    pub fn lease_key(&self, user: Uuid) -> String {
        format!("{}:lease:{user}", self.prefix)
    }

    /// `user`'s audio counter for the UTC day `now` falls in.
    #[must_use]
    pub fn user_key(&self, user: Uuid, now: DateTime<Utc>) -> String {
        user_day_key(&self.prefix, user, now)
    }

    /// `user`'s audio counter for the UTC month `now` falls in.
    #[must_use]
    pub fn user_month_key(&self, user: Uuid, now: DateTime<Utc>) -> String {
        user_month_key(&self.prefix, user, now)
    }

    /// The global audio counter for the UTC month `now` falls in.
    #[must_use]
    pub fn global_key(&self, now: DateTime<Utc>) -> String {
        global_month_key(&self.prefix, now)
    }

    /// `user`'s admission key: the token of the upgrade last admitted.
    #[must_use]
    pub fn admit_key(&self, user: Uuid) -> String {
        format!("{}:admit:{user}", self.prefix)
    }

    /// What session `token` has been charged.
    #[must_use]
    pub fn meter_key(&self, token: Uuid) -> String {
        format!("{}:session:{token}", self.prefix)
    }

    /// `user`'s fence: a hash whose field `next` is the last ticket issued.
    #[must_use]
    pub fn fence_key(&self, user: Uuid) -> String {
        format!("{}:fence:{user}", self.prefix)
    }

    /// Take `user`'s next ticket, which the acquire must carry (module
    /// docs): every ticket issued before it is stale from now on.
    ///
    /// # Errors
    ///
    /// [`StreamBudgetError::Backend`] when Redis could not be asked, the
    /// fence is not a hash or its `next` not a canonical integer (nothing
    /// was written), or the script answered something it never answers —
    /// including a reply that was lost, after which `next` MAY have been
    /// raised: harmless, it is never re-sent and that ticket never used.
    pub async fn issue_ticket(
        &self,
        redis: &RedisHandle,
        user: Uuid,
    ) -> Result<u64, StreamBudgetError> {
        // Replay::Never — an increment is not idempotent: a second run would
        // issue a second ticket for one upgrade, and one that landed AFTER a
        // newer upgrade's issue would make that upgrade's ticket stale. So
        // it is sent at most once, after the admission's PING (which replaces
        // a cached connection that died idle); a lost reply is the app's
        // 503, and the client's next upgrade takes a new ticket.
        let answer: i64 = redis
            .eval(
                ISSUE_SCRIPT,
                &[&self.fence_key(user)],
                &[FENCE_TTL_SECONDS.into()],
                Replay::Never,
            )
            .await
            .map_err(backend)?;
        issue_verdict(answer)
    }

    /// Take `user`'s lease for session `token` — superseding whichever session
    /// held it — if `ticket` is still the user's newest
    /// ([`StreamBudget::issue_ticket`]), no budget is spent and no other
    /// upgrade for `user` was admitted in the last `admit_interval` (module
    /// docs).
    ///
    /// # Errors
    ///
    /// [`StreamBudgetError::Stale`] when a newer ticket was issued,
    /// [`StreamBudgetError::Exceeded`] when a budget is spent, and
    /// [`StreamBudgetError::Throttled`] inside the admission interval (the
    /// lease is untouched in each case); [`StreamBudgetError::Backend`] when
    /// Redis could not be asked or a counter is invalid — including a reply
    /// that was lost, after which the lease MAY hold this token (see the
    /// module docs: the acquire is never re-sent, and a LATE one is fenced).
    pub async fn acquire(
        &self,
        redis: &RedisHandle,
        user: Uuid,
        token: Uuid,
        ticket: u64,
        admit_interval: Duration,
    ) -> Result<Grant, StreamBudgetError> {
        // Replay::Never — this script is the TAKEOVER: it SETs the lease to
        // this token over whatever session held it, and the admission key. A
        // second run after a lost reply is not harmless:
        //
        // - another session B can take the lease between the two runs; the
        //   replay would overwrite B's token while B believes it holds the
        //   lease (two live sessions, both "owning" it);
        // - the first run already wrote this token, so the replay answers
        //   `took_over = 0` for a takeover that happened (the relay's log and
        //   its live sessions would miss it);
        // - it restarts the lease's and the admission key's TTLs.
        //
        // So it is sent at most once. A lost reply is `RedisError::Io`
        // (outcome unknown): the app answers 503 and starts no session;
        // whatever token the first run may have written expires within
        // LEASE_TTL or is superseded by the client's next upgrade. (`Never`
        // stops a SECOND run, not a LATE first one: the ticket does — a first
        // run that lands after a newer upgrade took its ticket is STALE and
        // writes nothing. The ticket would refuse a replay that landed after
        // such an upgrade too; `Never` still keeps a replay from restarting
        // the TTLs, or misreporting `took_over`, when no newer upgrade came.)
        self.acquire_sent(redis, user, token, ticket, admit_interval, Replay::Never)
            .await
    }

    /// [`StreamBudget::acquire`]'s script, keys and arguments sent under
    /// `replay`. **A test seam, not an API**: the acquire is sent under
    /// [`Replay::Never`] only, through [`StreamBudget::acquire`] (whose
    /// comment says why). It exists so a test can run the REAL script under
    /// the replaying policy and show what that policy would do to a takeover
    /// (`tests/lease.rs`).
    ///
    /// # Errors
    ///
    /// As [`StreamBudget::acquire`].
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub async fn acquire_under(
        &self,
        redis: &RedisHandle,
        user: Uuid,
        token: Uuid,
        ticket: u64,
        admit_interval: Duration,
        replay: Replay,
    ) -> Result<Grant, StreamBudgetError> {
        self.acquire_sent(redis, user, token, ticket, admit_interval, replay)
            .await
    }

    /// The acquire, sent under `replay`.
    async fn acquire_sent(
        &self,
        redis: &RedisHandle,
        user: Uuid,
        token: Uuid,
        ticket: u64,
        admit_interval: Duration,
        replay: Replay,
    ) -> Result<Grant, StreamBudgetError> {
        // The windows' instant and its monotonic twin, read together, once:
        // the origin every deadline of this session is derived from.
        let (now, origin) = ((self.clock)(), Instant::now());
        let (lease_key, day_key, month_key, global_key, admit_key, fence_key) = (
            self.lease_key(user),
            self.user_key(user, now),
            self.user_month_key(user, now),
            self.global_key(now),
            self.admit_key(user),
            self.fence_key(user),
        );
        let token = token.to_string();
        let answer: Vec<i64> = redis
            .eval(
                ACQUIRE_SCRIPT,
                &[
                    &lease_key,
                    &day_key,
                    &month_key,
                    &global_key,
                    &admit_key,
                    &fence_key,
                ],
                &[
                    (&token).into(),
                    millis(LEASE_TTL).into(),
                    self.caps.user_day_ms.into(),
                    self.caps.user_month_ms.into(),
                    self.caps.global_month_ms.into(),
                    // `PX 0` is an error in Redis: the shortest window is 1 ms.
                    millis(admit_interval).max(1).into(),
                    ticket.into(),
                    FENCE_TTL_SECONDS.into(),
                ],
                replay,
            )
            .await
            .map_err(backend)?;
        acquire_verdict(&answer, (now, origin), admit_interval)
    }

    /// Charge session `token`'s audio up to `total_ms` (cumulative), then
    /// refresh or release `user`'s lease if it is still `token`'s.
    ///
    /// # Errors
    ///
    /// [`StreamBudgetError::Backend`] when Redis could not be asked or a
    /// counter is invalid; nothing was written in the second case.
    pub async fn meter(
        &self,
        redis: &RedisHandle,
        user: Uuid,
        token: Uuid,
        total_ms: u64,
        mode: MeterMode,
    ) -> Result<Metered, StreamBudgetError> {
        let now = (self.clock)();
        let (day_ttl, month_ttl) = key_ttls(now);
        let (lease_key, day_key, month_key, global_key, meter_key) = (
            self.lease_key(user),
            self.user_key(user, now),
            self.user_month_key(user, now),
            self.global_key(now),
            self.meter_key(token),
        );
        let token = token.to_string();
        // Replay::OnceOnFreshConnection — a refresh or release may run twice,
        // because a second run (the retry, or a first attempt landing after
        // it) is harmless in its value AND its TTL effects:
        //
        // - the charge is `total_ms` minus this session's meter, and the
        //   meter is set to `total_ms` in the same atomic run; a second run
        //   with the same total (or a stale, smaller one) charges nothing and,
        //   charging nothing, rewrites and re-expires neither a counter nor
        //   the meter. The counters other sessions race are never
        //   double-counted; the meter key is this session's alone (its token);
        // - the lease is touched only while it holds THIS token (compared in
        //   the same atomic run) and is only ever SET to that same token: a
        //   second run cannot extend, delete or overwrite another session's
        //   lease. A second refresh restarts this session's own lease TTL,
        //   which is what a refresh is for; a second release finds the lease
        //   gone and touches nothing.
        //
        // The caller gets the retry's answer: `held` reads false for a release
        // whose first run already deleted the lease (a log field only), and
        // the remaining budgets are current. `Never` would only turn a dead
        // cached connection into a failed refresh, and a failed release into
        // a lease left to expire. (The acquire is the opposite case; above.)
        // Residual risk: a first attempt delayed past the meter key's TTL
        // (METER_TTL_SECONDS, an hour) would charge again.
        let answer: Vec<i64> = redis
            .eval(
                METER_SCRIPT,
                &[&lease_key, &day_key, &month_key, &global_key, &meter_key],
                &[
                    (&token).into(),
                    total_ms.into(),
                    match mode {
                        MeterMode::Refresh => 0_u64,
                        MeterMode::Release => 1_u64,
                    }
                    .into(),
                    millis(LEASE_TTL).into(),
                    self.caps.user_day_ms.into(),
                    self.caps.user_month_ms.into(),
                    self.caps.global_month_ms.into(),
                    day_ttl.into(),
                    month_ttl.into(),
                    METER_TTL_SECONDS.into(),
                ],
                Replay::OnceOnFreshConnection,
            )
            .await
            .map_err(backend)?;
        meter_verdict(&answer, now)
    }
}

/// `ACQUIRE_SCRIPT`'s answer, decided at `now` (with its monotonic twin).
/// Each sentinel and mask is matched on its own value — [`INVALID_COUNTER`],
/// [`THROTTLED`] and [`STALE`] are negative, the masks `1..=7` — so no reply
/// can be read as another; every answer is exactly five figures (a grant's
/// `took_over` `0` or `1`), and anything else is a reply the script never
/// makes (`Backend`).
///
/// # Errors
///
/// As [`StreamBudget::acquire`].
pub(crate) fn acquire_verdict(
    answer: &[i64],
    (now, origin): (DateTime<Utc>, Instant),
    admit_interval: Duration,
) -> Result<Grant, StreamBudgetError> {
    match answer {
        [0, day, month, global, took_over @ (0 | 1)] => Ok(Grant {
            user_day_remaining_ms: *day,
            user_month_remaining_ms: *month,
            global_remaining_ms: *global,
            took_over: *took_over == 1,
            at: now,
            origin,
        }),
        [INVALID_COUNTER, _, _, _, _] => Err(invalid_counter()),
        [STALE, _, _, _, _] => Err(StreamBudgetError::Stale),
        [THROTTLED, _, _, _, _] => Err(StreamBudgetError::Throttled {
            retry_after_seconds: u64::try_from(admit_interval.as_millis().div_ceil(1_000))
                .unwrap_or(u64::MAX)
                .max(1),
        }),
        // A mask in 1..=7 always names a window: never `unexpected`.
        [over @ 1..=7, _, _, _, _] => Err(LimitReached::from_mask(*over, now)
            .map_or_else(|| unexpected(answer), StreamBudgetError::Exceeded)),
        other => Err(unexpected(other)),
    }
}

/// `ISSUE_SCRIPT`'s answer: a ticket (`1` or more), the invalid-counter
/// sentinel, or a reply the script never makes (`Backend`).
///
/// # Errors
///
/// As [`StreamBudget::issue_ticket`].
pub(crate) fn issue_verdict(answer: i64) -> Result<u64, StreamBudgetError> {
    match answer {
        INVALID_COUNTER => Err(StreamBudgetError::Backend(
            "the stream fence is not a ticket counter; nothing was written".to_string(),
        )),
        ticket @ 1.. => Ok(ticket.unsigned_abs()),
        other => Err(unexpected(&[other])),
    }
}

/// `METER_SCRIPT`'s answer, decided at `now`: four figures, `held` `0` or
/// `1`, or the invalid-counter sentinel's; anything else is a reply the
/// script never makes (`Backend`).
///
/// # Errors
///
/// As [`StreamBudget::meter`].
pub(crate) fn meter_verdict(
    answer: &[i64],
    now: DateTime<Utc>,
) -> Result<Metered, StreamBudgetError> {
    match answer {
        [INVALID_COUNTER, _, _, _] => Err(invalid_counter()),
        [held @ (0 | 1), day, month, global] => Ok(Metered {
            held: *held == 1,
            user_day_remaining_ms: *day,
            user_month_remaining_ms: *month,
            global_remaining_ms: *global,
            at: now,
        }),
        other => Err(unexpected(other)),
    }
}

/// `bytes` of audio at `bytes_per_second`, in whole milliseconds, rounded
/// DOWN: the remainder is charged with the next call's total, never lost and
/// never charged twice. `0` for a rate of `0`.
#[must_use]
pub fn audio_ms(bytes: u64, bytes_per_second: u64) -> u64 {
    if bytes_per_second == 0 {
        return 0;
    }
    u64::try_from(u128::from(bytes) * 1_000 / u128::from(bytes_per_second)).unwrap_or(u64::MAX)
}

/// `duration` in whole milliseconds, saturating.
pub(crate) fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// A failed `eval` as `Backend`: stridelabs-redis's fixed summary, never a
/// key, a token or Redis's own text.
fn backend(failure: RedisError) -> StreamBudgetError {
    StreamBudgetError::Backend(failure.to_string())
}

fn invalid_counter() -> StreamBudgetError {
    StreamBudgetError::Backend(
        "a stream budget counter is not a non-negative integer (or an argument not a whole \
         number); nothing was written"
            .to_string(),
    )
}

fn unexpected(answer: &[i64]) -> StreamBudgetError {
    StreamBudgetError::Backend(format!("the stream budget script answered {answer:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{CapProblem, LimitScope};
    use chrono::TimeZone as _;

    fn mid_month() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 17, 12, 0, 0)
            .single()
            .expect("an instant")
    }

    fn budget(prefix: &str) -> StreamBudget {
        StreamBudget::new(
            prefix,
            StreamCaps::from_minutes(120, 1_800, 1_800).expect("valid caps"),
        )
    }

    #[test]
    fn the_keys_are_under_the_prefix() {
        let budget = budget("tapper:voice:stream");
        let user = Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("a uuid");
        let token = Uuid::parse_str("99999999-8888-7777-6666-555555555555").expect("a uuid");
        let now = Utc
            .with_ymd_and_hms(2026, 10, 17, 23, 59, 59)
            .single()
            .expect("an instant");
        assert_eq!(
            budget.lease_key(user),
            "tapper:voice:stream:lease:11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(
            budget.user_key(user, now),
            "tapper:voice:stream:user:11111111-2222-3333-4444-555555555555:2026-10-17"
        );
        assert_eq!(
            budget.user_month_key(user, now),
            "tapper:voice:stream:user-month:11111111-2222-3333-4444-555555555555:2026-10"
        );
        assert_eq!(budget.global_key(now), "tapper:voice:stream:global:2026-10");
        assert_eq!(
            budget.meter_key(token),
            "tapper:voice:stream:session:99999999-8888-7777-6666-555555555555"
        );
        assert_eq!(
            budget.admit_key(user),
            "tapper:voice:stream:admit:11111111-2222-3333-4444-555555555555"
        );
    }

    /// Bytes to milliseconds at both rates, rounded down.
    #[test]
    fn audio_is_measured_in_whole_milliseconds() {
        assert_eq!(audio_ms(48_000, 48_000), 1_000);
        assert_eq!(audio_ms(3_840, 48_000), 80);
        assert_eq!(audio_ms(47, 48_000), 0);
        assert_eq!(audio_ms(48, 48_000), 1);
        assert_eq!(audio_ms(32_000, 32_000), 1_000);
        assert_eq!(audio_ms(u64::MAX, 48_000), u64::MAX / 48);
        assert_eq!(audio_ms(10, 0), 0);
    }

    /// Every answer the acquire can get, and one meaning each: a grant of
    /// exactly five figures; the three sentinels, `-1`, `-2` (THROTTLED,
    /// once `4`: the user's month took that bit) and `-3` (STALE); every mask
    /// `1` to `7` with its windows and scope; and anything else — `8`, `-4`,
    /// the old `4`-as-throttled shape `{4,0,0,0}`, a short or long grant, a
    /// `took_over` of `2` — a `Backend` error, never a session.
    #[test]
    fn every_acquire_answer_has_one_meaning() {
        let now = mid_month();
        let origin = Instant::now();
        let admit = Duration::from_millis(2_000);
        assert_eq!(
            acquire_verdict(&[0, 10, 20, 30, 1], (now, origin), admit),
            Ok(Grant {
                user_day_remaining_ms: 10,
                user_month_remaining_ms: 20,
                global_remaining_ms: 30,
                took_over: true,
                at: now,
                origin,
            })
        );
        assert_eq!(
            acquire_verdict(&[THROTTLED, 0, 0, 0, 0], (now, origin), admit),
            Err(StreamBudgetError::Throttled {
                retry_after_seconds: 2
            })
        );
        assert_eq!(THROTTLED, -2);
        assert_eq!(
            acquire_verdict(&[STALE, 0, 0, 0, 0], (now, origin), admit),
            Err(StreamBudgetError::Stale)
        );
        assert_eq!(STALE, -3);
        assert!(matches!(
            acquire_verdict(&[INVALID_COUNTER, 0, 0, 0, 0], (now, origin), admit),
            Err(StreamBudgetError::Backend(detail)) if detail.contains("nothing was written")
        ));
        for mask in 1..=7 {
            assert_eq!(
                acquire_verdict(&[mask, 0, 0, 0, 0], (now, origin), admit),
                Err(StreamBudgetError::Exceeded(
                    LimitReached::from_mask(mask, now).expect("a mask naming a window")
                )),
                "mask {mask}"
            );
        }
        assert!(matches!(
            acquire_verdict(&[4, 0, 0, 0, 0], (now, origin), admit),
            Err(StreamBudgetError::Exceeded(limit)) if limit.scope == LimitScope::UserMonth
        ));
        for unknown in [
            &[8, 0, 0, 0, 0][..],
            &[4, 0, 0, 0][..],
            &[-4, 0, 0, 0, 0][..],
            &[-3, 0, 0, 0][..],
            &[0, 1, 2, 3][..],
            &[0, 1, 2, 3, 0, 0][..],
            &[0, 1, 2, 3, 2][..],
            &[][..],
        ] {
            assert!(
                matches!(
                    acquire_verdict(unknown, (now, origin), admit),
                    Err(StreamBudgetError::Backend(_))
                ),
                "{unknown:?}"
            );
        }
    }

    /// The issue's answers: a ticket of `1` or more, the invalid sentinel
    /// (`Backend`, nothing written), and nothing else (`0`, `-2`, `-3`).
    #[test]
    fn every_issue_answer_has_one_meaning() {
        assert_eq!(issue_verdict(1), Ok(1));
        assert_eq!(issue_verdict(42), Ok(42));
        assert!(matches!(
            issue_verdict(INVALID_COUNTER),
            Err(StreamBudgetError::Backend(detail)) if detail.contains("nothing was written")
        ));
        for unknown in [0, THROTTLED, STALE, i64::MIN] {
            assert!(
                matches!(issue_verdict(unknown), Err(StreamBudgetError::Backend(_))),
                "{unknown}"
            );
        }
        let user = Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("a uuid");
        assert_eq!(
            budget("tapper:voice:stream").fence_key(user),
            "tapper:voice:stream:fence:11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(FENCE_TTL_SECONDS, 86_400);
    }

    /// The meter's answers: four figures with `held` 0 or 1, the sentinel,
    /// and nothing else (the older three-figure shape included).
    #[test]
    fn every_meter_answer_has_one_meaning() {
        let now = mid_month();
        let metered = meter_verdict(&[1, 5, -1, 7], now).expect("four figures");
        assert_eq!(
            metered,
            Metered {
                held: true,
                user_day_remaining_ms: 5,
                user_month_remaining_ms: -1,
                global_remaining_ms: 7,
                at: now,
            }
        );
        assert_eq!(
            metered.spent(),
            Spent {
                user_day: false,
                user_month: true,
                global_month: false
            }
        );
        assert_eq!(
            metered.limit_reached().map(|limit| limit.scope),
            Some(LimitScope::UserMonth)
        );
        let fine = meter_verdict(&[0, 1, 1, 1], now).expect("four figures");
        assert_eq!(fine.limit_reached(), None, "nothing spent");
        assert!(!fine.held);
        assert!(matches!(
            meter_verdict(&[INVALID_COUNTER, 0, 0, 0], now),
            Err(StreamBudgetError::Backend(_))
        ));
        for unknown in [&[1, 5, 7][..], &[2, 1, 1, 1][..], &[1, 1, 1, 1, 1][..]] {
            assert!(
                matches!(
                    meter_verdict(unknown, now),
                    Err(StreamBudgetError::Backend(_))
                ),
                "{unknown:?}"
            );
        }
    }

    /// The stream caps' startup rule is the text caps' (`budget`'s test),
    /// over minutes, with its own range: minutes whose milliseconds fit an
    /// `i64`. In range, the caps are those minutes in milliseconds; one
    /// minute past the range is each window's own problem.
    #[test]
    fn stream_caps_are_minutes_held_to_the_rule_and_counted_in_ms() {
        use LimitScope::{GlobalMonth, UserDay, UserMonth};
        let caps = StreamCaps::from_minutes(1, 2, 2).expect("equal caps are allowed");
        assert_eq!(
            (
                caps.user_day_ms(),
                caps.user_month_ms(),
                caps.global_month_ms()
            ),
            (60_000, 120_000, 120_000)
        );
        let max = StreamCaps::MAX_MINUTES;
        assert_eq!(max, i64::MAX / 60_000);
        let largest = StreamCaps::from_minutes(max, max, max).expect("the largest is allowed");
        assert_eq!(largest.global_month_ms(), max * 60_000);
        let past = StreamCaps::from_minutes(max + 1, max + 1, max + 1).expect_err("past the range");
        assert_eq!(
            past.problems(),
            [UserDay, UserMonth, GlobalMonth].map(|window| CapProblem::Invalid { window, max })
        );
        assert_eq!(
            StreamCaps::from_minutes(120, 1_800, 1_799)
                .expect_err("below")
                .problems(),
            [CapProblem::Below {
                window: GlobalMonth,
                below: UserMonth
            }]
        );
        assert_eq!(
            StreamCaps::from_minutes(1_801, 1_800, 1_800)
                .expect_err("below")
                .problems(),
            [CapProblem::Below {
                window: UserMonth,
                below: UserDay
            }]
        );
    }
}
