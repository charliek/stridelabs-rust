//! The text-to-speech character budget, and the window scheme and refusal
//! shape both voice budgets share.
//!
//! Three counters, charged together, under a key prefix the app passes (there
//! is no default):
//!
//! | counter | cap ([`TtsCaps`]) | window | key |
//! |---|---|---|---|
//! | the user's day | `user_day` | the UTC day | `{prefix}:user:{user}:{YYYY-MM-DD}` |
//! | the user's month | `user_month` | the UTC calendar month | `{prefix}:user-month:{user}:{YYYY-MM}` |
//! | everyone's month | `global_month` | the UTC calendar month | `{prefix}:global:{YYYY-MM}` |
//!
//! The caps are the app's configuration, in characters. [`TtsCaps::new`]
//! holds them to the rule every app's startup enforces: each positive, and
//! day <= user month <= global month. Everyone's month is the spending
//! ceiling, however many users there are and however much they talk; the
//! per-user caps keep one runaway client from spending everyone's month in
//! an afternoon. A user's month equal to everyone's changes nothing until it
//! is set lower.
//!
//! # One script, all or none
//!
//! [`TtsBudget::charge`] is ONE `EVAL` of `CHARGE_SCRIPT`: read the three
//! counters, and only if the charge fits under EVERY cap add it to all
//! three. A charge that would cross any cap adds nothing to any — a request
//! refused for the global month never spends the user's day, and the
//! reverse. Lua runs atomically on the server, so two concurrent requests
//! cannot both see room for one; every key the script touches is passed in
//! `KEYS`, the form Redis (and Upstash) require of a script.
//!
//! A charge that FITS exactly is admitted: the caps are totals that may be
//! reached, never passed. Refusal is decided on "would this pass the cap",
//! not "is the cap already reached", so the ceiling above is a real bound and
//! not a bound plus one sentence.
//!
//! # Charged before the provider call, never refunded
//!
//! The app charges before it asks its text-to-speech provider, and gives
//! nothing back when the synthesis fails. A refund would make a failure loop
//! free — a provider answering `500` to every sentence would be retried by
//! the client forever at no cost to the budget — and it would need a second
//! write that can itself fail. The provider may well have billed the attempt
//! anyway.
//!
//! # Idempotent per sentence, so it may be replayed
//!
//! Each charge is named by a [`ChargeKey`]: the request's `Idempotency-Key`
//! (the client mints one per sentence and sends it again on its one retry),
//! or, without the header, a v4 uuid minted for the request. The script
//! records its verdict under `{prefix}:charge:{user}:{key}` — scoped by user,
//! so one user's key can never name another's charge — for
//! [`CHARGE_VERDICT_SECONDS`], and a second run of the same charge, in either
//! order, finds the verdict and answers it again, writing nothing
//! ([`Disposition::Replayed`]). Two runs reach it:
//!
//! - **the handle's own replay.** The `EVAL` runs on the app's
//!   stridelabs-redis handle (`RedisHandle::eval`) under
//!   [`Replay::OnceOnFreshConnection`]: after an I/O failure on a connection
//!   that was already cached (hosted Redis services and serverless platforms
//!   drop idle ones), it is sent once more on a fresh one — and a first
//!   attempt whose ANSWER was lost may already have run, or may even land
//!   after the retry;
//! - **the client's retry** of a sentence whose answer never reached it (a
//!   `503` after a lost Redis reply the handle could not replay, or the
//!   connection to the app lost), under the same key. Concurrent requests
//!   with one key are serialised by the script's atomicity: the first
//!   charges, the second replays.
//!
//! Without it, a retry charged twice — or, worse, a first attempt that took
//! the counter exactly to its cap made the retry answer `429` for a sentence
//! that had been admitted and paid for. Ten minutes is far past either
//! retry's window (the handle's: a response timeout, a dial and another
//! response timeout, 2 s with the bounds the README assumes; the client's:
//! its budget for one sentence) and short enough that the verdict keys never
//! accumulate. See [`TtsBudget::charge`] for why this script may be replayed
//! and the stream's lease acquire ([`crate::lease`]) may not.
//!
//! **The verdict is versioned and fingerprinted:** `v1|<mask>|<fp>|<reset>`
//! — the script's answer (`0` admitted, `1` to `7` the spent windows), the
//! first 16 hex characters of SHA-256 over `voice + "\n" + text`
//! ([`Fingerprint`]), and, for a refusal, when its reported window resets
//! (Unix seconds; `0` for an admission). A replay whose fingerprint differs —
//! the same key sent with another sentence, a client bug — is refused
//! ([`BudgetError::KeyReused`], a `422`), writing nothing. A refusal replays
//! with its ORIGINAL reset, not one reckoned at the replay. A stored value
//! that does not parse (another writer's, or another version's) is the
//! invalid-counter verdict: a `503`, nothing written.
//!
//! **What a replayed verdict does not do:** count as usage (an app records
//! only a [`Disposition::Fresh`] charge) — which also means a request whose
//! OWN first attempt ran, and whose answer the handle's replay then found, is
//! not recorded: usage is best-effort, and on the side of never counting a
//! sentence twice. Nor does it protect provider spend: a replayed ADMISSION
//! is spoken again, so the budget is charged once and the provider asked
//! twice.
//!
//! # Validated before anything is written
//!
//! Every counter is read and checked, and every argument parsed, before any
//! key is touched: a counter that is not a canonical non-negative integer
//! (`"1.5"`, `"-3"`, `"abc"`, `"007"`) — something other than this script
//! wrote it — a stored verdict that does not parse, or an argument that is
//! not what it should be answers an error verdict having written NOTHING,
//! the verdict included, and the app answers `503`. Redis does not roll a
//! script back when it fails part-way, so a check that could fail after the
//! first write would leave the user charged and the month not; reading first
//! is what keeps all-or-none true even for a poisoned counter. A counter of
//! another TYPE fails the `GET` itself, which is the same: an error before
//! any write.
//!
//! **One command per key, value and expiry together.** Redis checks
//! permissions (ACLs) per command INSIDE a script and keeps the writes
//! before a refused one. So every write here is ONE `SET key <value> EX
//! <ttl>` — each counter set to its validated value plus the charge, then
//! the verdict — never an `INCRBY` then an `EXPIRE`: a permission either
//! allows every write or refuses the first, before anything changed, and a
//! counter that lost its TTL gets it back on the next charge.
//!
//! # The windows are the budget's clock's
//!
//! The day and month are read off the system's UTC clock (or a test's) and
//! baked into the key ([`crate::window`]), so a window rolls over by
//! changing keys, never by an expiry firing.
//!
//! **A user's month that starts mid-month under-counts that month.** On the
//! deploy that first writes an app's user-month key, every user's month
//! counter starts at zero whatever they already spoke that month (an older
//! revision's day and global counters carry on). So for the rest of that
//! first month a user may speak up to their whole month's cap on top of what
//! they spoke before it; the global month still bounds everyone. From the
//! first of the next month the count is whole.
//!
//! # What a refusal reports (both voice budgets)
//!
//! A refusal names the windows it found spent ([`Spent`]: the script's
//! bitmask, `1` the user's day, `2` everyone's month, `4` the user's month)
//! and ONE scope ([`LimitScope`]): of the spent windows, the one whose reset
//! is LATEST — retrying before it cannot succeed. A tie (the user's month and
//! everyone's month always end together; on a month's last day, the day too)
//! goes to `user_month`, then `global_month`, then `user_day`
//! ([`Spent::scope`]). An app's `429` carries it as `"scope"` and
//! `"resets_at"` (RFC 3339) beside its `"detail"`, with `Retry-After` to the
//! same instant ([`LimitReached`]).

use std::fmt;

use chrono::{DateTime, TimeZone as _, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use stridelabs_redis::{RedisHandle, Replay};
use uuid::Uuid;

use crate::window::{
    day_end, day_stamp, key_ttls, month_end, month_stamp, seconds_until, system_clock, Clock,
};

/// How long a charge's verdict is kept, so a replay of the same charge
/// answers it again instead of charging again (module docs: ten minutes,
/// past the client's retry as well as the handle's).
pub const CHARGE_VERDICT_SECONDS: i64 = 600;

/// The longest [`ChargeKey`] a client may send, in characters.
pub const MAX_CHARGE_KEY_CHARS: usize = 64;

/// The SHA-1 of the exact bytes `CHARGE_SCRIPT` sends: the extraction
/// base's (tapper `82be95f`), so every app runs one script, byte for byte. An
/// app may log or assert which script set it runs.
pub const CHARGE_SCRIPT_SHA1: &str = "6db0a4afd52968ffb65e754d4dc48c7112016757";

/// The verdict a budget script answers when a counter is not a canonical
/// non-negative integer, a stored value does not parse, or an argument is
/// not what it should be ([`lua_helpers!`]'s `nil`): nothing was written.
/// This script's, and the stream's ([`crate::lease`]).
pub(crate) const INVALID_COUNTER: i64 = -1;

/// The charge's sentinel for a key whose stored verdict has another
/// fingerprint: the key was sent with a different sentence. Nothing was
/// written. (`-2` and `-3` are the stream's, [`crate::lease`]: each sentinel
/// has one meaning across the voice scripts.)
pub(crate) const KEY_REUSED: i64 = -4;

/// A spent-window bit: the user's UTC day.
pub(crate) const SPENT_USER_DAY: i64 = 1;
/// A spent-window bit: everyone's UTC month.
pub(crate) const SPENT_GLOBAL_MONTH: i64 = 2;
/// A spent-window bit: the user's UTC month.
pub(crate) const SPENT_USER_MONTH: i64 = 4;

/// The Lua helpers every budget script opens with. Shared by [`TtsBudget`]'s
/// script and the stream's ([`crate::lease`]), so the rules a counter and an
/// argument are validated by are one rule each:
///
/// - `canonical(value)`: a stored string that is a canonical non-negative
///   integer — `0` or a digit string without a leading zero, at most 15
///   digits (exact in Lua's doubles) — as a number, else `nil`.
/// - `counter(key)`: the integer stored at `key`, `0` when it is absent, or
///   `nil` when it is not `canonical`. A value of another TYPE fails the
///   `GET` itself.
/// - `whole(value)`: an argument that is a digit string of at most 19 digits
///   (an `i64`'s), as a number, else `nil`.
/// - `positive(value)`: `whole`, and above zero (a TTL: `EX 0`/`PX 0` is an
///   error in Redis), else `nil`.
macro_rules! lua_helpers {
    () => {
        "\
local function canonical(value)
  if type(value) == 'string' and string.len(value) <= 15
      and (value == '0' or string.match(value, '^[1-9]%d*$')) then
    return tonumber(value)
  end
  return nil
end
local function counter(key)
  local value = redis.call('GET', key)
  if not value then
    return 0
  end
  return canonical(value)
end
local function whole(value)
  if type(value) == 'string' and string.len(value) <= 19 and string.match(value, '^%d+$') then
    return tonumber(value)
  end
  return nil
end
local function positive(value)
  local number = whole(value)
  if number and number > 0 then
    return number
  end
  return nil
end
"
    };
}
pub(crate) use lua_helpers;

/// Check the three caps, then charge all three — or none — once per charge
/// key.
///
/// ```text
/// KEYS[1] = <prefix>:user:<user>:<YYYY-MM-DD>       KEYS[2] = <prefix>:user-month:<user>:<YYYY-MM>
/// KEYS[3] = <prefix>:global:<YYYY-MM>               KEYS[4] = <prefix>:charge:<user>:<charge key>
/// ARGV    = chars  user_day_cap  user_month_cap  global_cap  day_ttl  month_ttl  verdict_ttl
///           fingerprint  day_reset  month_reset
/// ```
///
/// Answers `{verdict, reset, replayed}`:
///
/// 1. The fingerprint (`ARGV[8]`, 16 lowercase hex characters) is checked,
///    and a verdict already stored under `KEYS[4]` read (another TYPE fails
///    the `GET`). A stored one is answered as it stands, `replayed` `1`:
///    this charge has run, and its answer was lost or the client sent the
///    sentence again. It must parse as `v1|<mask>|<fp>|<reset>` (mask `0` to
///    `7`, `fp` 16 lowercase hex characters, `reset` at most 15 digits), else
///    `-1`; its `fp` must be `ARGV[8]`, else `-4` ([`KEY_REUSED`]).
/// 2. Validation: the three counters are read (a missing one is zero; `GET`
///    of an absent key is `false` in Lua) and every argument parsed (the two
///    resets, Unix seconds, at most 15 digits); any that fails answers `-1`,
///    having written nothing.
/// 3. The verdict is a bitmask of the caps the charge would pass — `1` the
///    user's day, `2` everyone's month, `4` the user's month, so `1` to `7` —
///    or `0`, in which case each counter is SET to its value plus `chars`
///    with its expiry. `reset` is when the reported window ends: the month's
///    (`ARGV[10]`) when a month is spent — a month always resets last, or
///    with the day, and wins the tie ([`Spent::scope`]) — else the day's
///    (`ARGV[9]`); `0` for an admission. Either way `v1|<verdict>|<fp>|<reset>`
///    is stored under `KEYS[4]`, and `{verdict, reset, 0}` answered.
///
/// Every write comes after every check, and every write is a `SET … EX`, so
/// a failure part-way (a permission, say) can only happen before anything is
/// written (module docs).
pub(crate) const CHARGE_SCRIPT: &str = concat!(
    lua_helpers!(),
    "\
local fp = ARGV[8]
if not (type(fp) == 'string' and string.len(fp) == 16 and string.match(fp, '^[0-9a-f]+$')) then
  return {-1, 0, 0}
end
local stored = redis.call('GET', KEYS[4])
if stored then
  local mask, stored_fp, reset = string.match(stored, '^v1|([0-7])|([0-9a-f]+)|(%d+)$')
  if not (mask and string.len(stored_fp) == 16 and string.len(reset) <= 15) then
    return {-1, 0, 0}
  end
  if stored_fp ~= fp then
    return {-4, 0, 0}
  end
  return {tonumber(mask), tonumber(reset), 1}
end
local day = counter(KEYS[1])
local month = counter(KEYS[2])
local global = counter(KEYS[3])
local chars = whole(ARGV[1])
local day_cap = whole(ARGV[2])
local month_cap = whole(ARGV[3])
local global_cap = whole(ARGV[4])
local day_ttl = positive(ARGV[5])
local month_ttl = positive(ARGV[6])
local verdict_ttl = positive(ARGV[7])
local day_reset = whole(ARGV[9])
local month_reset = whole(ARGV[10])
if not (day and month and global and chars and day_cap and month_cap and global_cap
    and day_ttl and month_ttl and verdict_ttl and day_reset and month_reset)
    or string.len(ARGV[9]) > 15 or string.len(ARGV[10]) > 15 then
  return {-1, 0, 0}
end
local over = 0
if day + chars > day_cap then
  over = over + 1
end
if global + chars > global_cap then
  over = over + 2
end
if month + chars > month_cap then
  over = over + 4
end
local reset = '0'
if over == 1 then
  reset = ARGV[9]
elseif over > 1 then
  reset = ARGV[10]
end
if over == 0 then
  redis.call('SET', KEYS[1], day + chars, 'EX', day_ttl)
  redis.call('SET', KEYS[2], month + chars, 'EX', month_ttl)
  redis.call('SET', KEYS[3], global + chars, 'EX', month_ttl)
end
redis.call('SET', KEYS[4], 'v1|' .. over .. '|' .. fp .. '|' .. reset, 'EX', verdict_ttl)
return {over, tonumber(reset), 0}
"
);

/// The text-to-speech caps, in characters: the user's UTC day, the user's
/// UTC month and everyone's UTC month. The values are the app's
/// configuration; [`TtsCaps::new`] holds them to the startup rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtsCaps {
    user_day: i64,
    user_month: i64,
    global_month: i64,
}

impl TtsCaps {
    /// The largest cap: an `i64` of characters (the scripts' counters and
    /// remainders).
    pub const MAX: i64 = i64::MAX;

    /// The caps, when each is `1..=`[`TtsCaps::MAX`] and they run a user's
    /// day <= a user's month <= everyone's month.
    ///
    /// # Errors
    ///
    /// [`CapsError`], naming every problem ([`CapsError::problems`]).
    pub fn new(user_day: i64, user_month: i64, global_month: i64) -> Result<TtsCaps, CapsError> {
        check_caps([user_day, user_month, global_month], TtsCaps::MAX)?;
        Ok(TtsCaps {
            user_day,
            user_month,
            global_month,
        })
    }

    /// The caps as given, unchecked: a test seam, for caps the startup rule
    /// refuses (a user's month below their day, say).
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn unchecked(user_day: i64, user_month: i64, global_month: i64) -> TtsCaps {
        TtsCaps {
            user_day,
            user_month,
            global_month,
        }
    }

    /// Characters one user may have spoken per UTC day.
    #[must_use]
    pub fn user_day(self) -> i64 {
        self.user_day
    }

    /// Characters one user may have spoken per UTC calendar month.
    #[must_use]
    pub fn user_month(self) -> i64 {
        self.user_month
    }

    /// Characters everyone together may have spoken per UTC calendar month:
    /// the spending ceiling.
    #[must_use]
    pub fn global_month(self) -> i64 {
        self.global_month
    }
}

/// Every problem with a set of caps (one or more): the startup rule both
/// apps hold their caps to. Each cap must be `1..=max`; then a user's day <=
/// a user's month <= everyone's month, compared only between caps that are
/// each valid (an invalid cap is one problem, not also an order problem).
///
/// Its `Display` names the windows and the rule, never a configured value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the voice caps are refused: {}", describe(.problems))]
pub struct CapsError {
    problems: Vec<CapProblem>,
}

impl CapsError {
    /// The problems, in the order found: every invalid cap (day, user month,
    /// global month), then every order problem.
    #[must_use]
    pub fn problems(&self) -> &[CapProblem] {
        &self.problems
    }
}

/// One problem with a set of caps; an app maps each to its own startup
/// refusal, under its own setting names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapProblem {
    /// `window`'s cap is not a positive whole number up to `max`.
    Invalid {
        /// The window whose cap it is.
        window: LimitScope,
        /// The largest value it may take.
        max: i64,
    },
    /// `window`'s cap is below `below`'s, which it must allow at least: a
    /// user's month below their day, or everyone's month below a user's
    /// month.
    Below {
        /// The window whose cap is too small.
        window: LimitScope,
        /// The window whose cap it is below.
        below: LimitScope,
    },
}

impl fmt::Display for CapProblem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapProblem::Invalid { window, max } => write!(
                formatter,
                "the {} cap is not a positive whole number (1 to {max})",
                window.as_str()
            ),
            CapProblem::Below { window, below } => write!(
                formatter,
                "the {} cap is below the {} cap (the caps must run a user's day <= a user's \
                 month <= everyone's month)",
                window.as_str(),
                below.as_str()
            ),
        }
    }
}

fn describe(problems: &[CapProblem]) -> String {
    problems
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// The windows of a budget's three caps, in the order they must run.
const CAP_WINDOWS: [LimitScope; 3] = [
    LimitScope::UserDay,
    LimitScope::UserMonth,
    LimitScope::GlobalMonth,
];

/// `caps` (a user's day, a user's month, everyone's month, in the unit the
/// app set them in) held to the startup rule ([`CapsError`]).
pub(crate) fn check_caps(caps: [i64; 3], max: i64) -> Result<(), CapsError> {
    let valid = caps.map(|cap| (1..=max).contains(&cap));
    let mut problems: Vec<CapProblem> = CAP_WINDOWS
        .iter()
        .zip(valid)
        .filter(|(_, valid)| !valid)
        .map(|(window, _)| CapProblem::Invalid {
            window: *window,
            max,
        })
        .collect();
    for pair in [0, 1] {
        let (lower, upper) = (pair, pair + 1);
        if valid[lower] && valid[upper] && caps[upper] < caps[lower] {
            problems.push(CapProblem::Below {
                window: CAP_WINDOWS[upper],
                below: CAP_WINDOWS[lower],
            });
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(CapsError { problems })
    }
}

/// A charge [`TtsBudget::charge`] admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    /// The instant the charge was decided at: the UTC day and month it
    /// counted in, and a usage record's event time.
    pub at: DateTime<Utc>,
    /// Whether this call debited the budget or answered an earlier verdict.
    pub disposition: Disposition,
}

/// Whether an admitted charge was debited by the script run that answered.
/// An app records usage for a [`Disposition::Fresh`] one only, so a replayed
/// verdict is never counted twice (module docs: nor, then, is a request whose
/// own first run's answer the handle's replay found).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The characters were added to every counter by this run.
    Fresh,
    /// An earlier run under the same [`ChargeKey`] admitted (and charged)
    /// this sentence; this one answered its stored verdict and charged
    /// nothing.
    Replayed,
}

/// What names one charge: the request's `Idempotency-Key` — 1 to
/// [`MAX_CHARGE_KEY_CHARS`] characters of `A-Z a-z 0-9 _ -` — or a v4 uuid
/// minted for a request without one. It is stored under the user's own
/// prefix ([`TtsBudget::charge_key`]), so one user's key never meets
/// another's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChargeKey(String);

impl ChargeKey {
    /// `value`, when it is a key a client may send; `None` otherwise.
    #[must_use]
    pub fn parse(value: &str) -> Option<ChargeKey> {
        let allowed = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-';
        ((1..=MAX_CHARGE_KEY_CHARS).contains(&value.len()) && value.bytes().all(allowed))
            .then(|| ChargeKey(value.to_string()))
    }

    /// A fresh key, for a request that sent none: a v4 uuid (36 characters
    /// of the allowed set).
    #[must_use]
    pub fn mint() -> ChargeKey {
        ChargeKey(Uuid::new_v4().to_string())
    }

    /// The key as sent (or minted).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a charge's verdict is pinned to: the first 16 hex characters
/// (lowercase) of SHA-256 over `voice + "\n" + text` — the app's voice id
/// and the trimmed text, exactly what is charged and spoken. A replay under
/// the same [`ChargeKey`] must carry the same one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// `voice` speaking `text`.
    #[must_use]
    pub fn of(voice: &str, text: &str) -> Fingerprint {
        let mut digest = Sha256::new();
        digest.update(voice.as_bytes());
        digest.update(b"\n");
        digest.update(text.as_bytes());
        let hex: String = digest
            .finalize()
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Fingerprint(hex)
    }

    /// The 16 hex characters.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// The `"scope"` of a voice budget's `429` body and of the relay's `limit`
// event. Not a doc comment: utoipa copies a `///` block into the schema's
// `description`; the line below is the API's, byte for byte the extraction
// base's (an app's committed OpenAPI document pins it).
/// Which voice allowance is spent: the user's UTC day, the user's UTC
/// calendar month, or everyone's UTC calendar month.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitScope {
    /// The user's allowance for the UTC day.
    UserDay,
    /// The user's allowance for the UTC calendar month.
    UserMonth,
    /// Everyone's allowance for the UTC calendar month: voice is off for all
    /// until it resets.
    GlobalMonth,
}

impl LimitScope {
    /// The wire name, for a log line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LimitScope::UserDay => "user_day",
            LimitScope::UserMonth => "user_month",
            LimitScope::GlobalMonth => "global_month",
        }
    }

    /// When this scope's window — the one `now` falls in — ends.
    #[must_use]
    pub fn resets_at(self, now: DateTime<Utc>) -> DateTime<Utc> {
        match self {
            LimitScope::UserDay => day_end(now),
            LimitScope::UserMonth | LimitScope::GlobalMonth => month_end(now),
        }
    }

    /// The tie order among windows that reset at the same instant: higher
    /// wins (module docs).
    fn tie_rank(self) -> u8 {
        match self {
            LimitScope::UserMonth => 2,
            LimitScope::GlobalMonth => 1,
            LimitScope::UserDay => 0,
        }
    }
}

/// The windows a voice budget found spent: a script's bitmask, `1` the
/// user's day, `2` everyone's month, `4` the user's month.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Spent {
    /// The user's UTC day.
    pub user_day: bool,
    /// The user's UTC month.
    pub user_month: bool,
    /// Everyone's UTC month.
    pub global_month: bool,
}

impl Spent {
    /// A script's bitmask as the windows it names; bits outside `1 | 2 | 4`
    /// are ignored (the verdict parsers match `1..=7` first).
    #[must_use]
    pub fn from_mask(mask: i64) -> Spent {
        Spent {
            user_day: mask & SPENT_USER_DAY != 0,
            user_month: mask & SPENT_USER_MONTH != 0,
            global_month: mask & SPENT_GLOBAL_MONTH != 0,
        }
    }

    /// The scopes that are spent, in no particular order.
    fn scopes(self) -> impl Iterator<Item = LimitScope> {
        [
            (self.user_day, LimitScope::UserDay),
            (self.user_month, LimitScope::UserMonth),
            (self.global_month, LimitScope::GlobalMonth),
        ]
        .into_iter()
        .filter_map(|(spent, scope)| spent.then_some(scope))
    }

    /// The scope a refusal reports, as of `now`: of the spent windows, the
    /// one whose reset is LATEST; a tie goes to `user_month`, then
    /// `global_month`, then `user_day`. `None` when nothing is spent.
    #[must_use]
    pub fn scope(self, now: DateTime<Utc>) -> Option<LimitScope> {
        self.scopes()
            .max_by_key(|scope| (scope.resets_at(now), scope.tie_rank()))
    }
}

/// A voice budget refusal: what was found spent, the one scope reported,
/// when it resets, and the `Retry-After` to that instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitReached {
    /// Every window that is spent.
    pub spent: Spent,
    /// The one reported ([`Spent::scope`]).
    pub scope: LimitScope,
    /// When `scope`'s window ends: the earliest a retry can succeed.
    pub resets_at: DateTime<Utc>,
    /// `Retry-After`: whole seconds from the decision to `resets_at`,
    /// rounded up, at least 1.
    pub retry_after_seconds: u64,
}

impl LimitReached {
    /// `spent`, decided at `now`; `None` when nothing is spent.
    #[must_use]
    pub fn new(spent: Spent, now: DateTime<Utc>) -> Option<LimitReached> {
        let scope = spent.scope(now)?;
        Some(LimitReached::resetting(
            spent,
            scope,
            scope.resets_at(now),
            now,
        ))
    }

    /// A script's spent-windows bitmask, decided at `now` ([`Spent::from_mask`]:
    /// bits outside `1 | 2 | 4` are ignored); `None` when it names no
    /// window.
    #[must_use]
    pub fn from_mask(mask: i64, now: DateTime<Utc>) -> Option<LimitReached> {
        LimitReached::new(Spent::from_mask(mask), now)
    }

    /// A charge verdict's refusal: the spent-windows bitmask and the reset
    /// the verdict was STORED with (Unix seconds), answered at `now` — so a
    /// replayed refusal keeps its original reset, and only `Retry-After`
    /// counts down to it. The scope is the mask's: a month always resets
    /// with or after the day and wins a tie, so which window is reported
    /// never depends on the instant. `None` for a mask naming no window or a
    /// reset that is not an instant.
    #[must_use]
    pub fn from_verdict(mask: i64, reset_epoch: i64, now: DateTime<Utc>) -> Option<LimitReached> {
        let spent = Spent::from_mask(mask);
        let scope = spent.scope(now)?;
        let resets_at = Utc.timestamp_opt(reset_epoch, 0).single()?;
        Some(LimitReached::resetting(spent, scope, resets_at, now))
    }

    /// `scope` of `spent`, resetting at `resets_at`, decided at `now`.
    fn resetting(
        spent: Spent,
        scope: LimitScope,
        resets_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> LimitReached {
        LimitReached {
            spent,
            scope,
            resets_at,
            retry_after_seconds: seconds_until(resets_at, now).unsigned_abs(),
        }
    }
}

/// Why a charge was not made.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BudgetError {
    /// The charge would pass a cap; nothing was charged.
    Exceeded(LimitReached),
    /// The [`ChargeKey`] already names a charge of ANOTHER sentence (its
    /// stored [`Fingerprint`] differs); nothing was charged or written.
    KeyReused,
    /// Redis could not be asked, or answered with an error.
    Backend(String),
}

impl fmt::Display for BudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BudgetError::Exceeded(limit) => write!(
                formatter,
                "the voice TTS budget is spent ({})",
                limit.scope.as_str()
            ),
            BudgetError::KeyReused => {
                formatter.write_str("the idempotency key names a charge of another sentence")
            }
            BudgetError::Backend(detail) => write!(formatter, "voice TTS budget: {detail}"),
        }
    }
}

impl std::error::Error for BudgetError {}

/// Where the three counters live, the caps they are held to, and the clock
/// that names the day and the month. Cloning shares the clock.
#[derive(Clone)]
pub struct TtsBudget {
    prefix: String,
    caps: TtsCaps,
    clock: Clock,
}

/// The prefix and the caps; never the clock.
impl fmt::Debug for TtsBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TtsBudget")
            .field("prefix", &self.prefix)
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

impl TtsBudget {
    /// The budget counting under `prefix` (the app's: there is no default),
    /// held to `caps`, on the system clock.
    #[must_use]
    pub fn new(prefix: impl Into<String>, caps: TtsCaps) -> TtsBudget {
        TtsBudget {
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
    ) -> TtsBudget {
        TtsBudget {
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
    pub fn caps(&self) -> TtsCaps {
        self.caps
    }

    /// `user`'s day counter for the UTC day `now` falls in.
    #[must_use]
    pub fn user_key(&self, user: Uuid, now: DateTime<Utc>) -> String {
        user_day_key(&self.prefix, user, now)
    }

    /// `user`'s month counter for the UTC month `now` falls in.
    #[must_use]
    pub fn user_month_key(&self, user: Uuid, now: DateTime<Utc>) -> String {
        user_month_key(&self.prefix, user, now)
    }

    /// The global counter for the UTC month `now` falls in.
    #[must_use]
    pub fn global_key(&self, now: DateTime<Utc>) -> String {
        global_month_key(&self.prefix, now)
    }

    /// Where `user`'s charge named `key` keeps its verdict:
    /// `{prefix}:charge:{user}:{key}` (scoped by user).
    #[must_use]
    pub fn charge_key(&self, user: Uuid, key: &ChargeKey) -> String {
        format!("{}:charge:{user}:{}", self.prefix, key.as_str())
    }

    /// Charge `chars` to `user`'s day and month and to everyone's month, now
    /// — or refuse and charge nothing. `key` names this charge (the
    /// sentence's `Idempotency-Key`, or one minted for the request), and
    /// `fingerprint` pins it to its sentence: a second run under the same
    /// key answers the first verdict without charging again, and is refused
    /// if its sentence differs. See the module docs. An admitted charge
    /// answers when it was decided and its [`Disposition`].
    ///
    /// # Errors
    ///
    /// [`BudgetError::Exceeded`] when a cap would be passed (or a replayed
    /// verdict says one was, with its original reset);
    /// [`BudgetError::KeyReused`] when `key` names another sentence's charge;
    /// [`BudgetError::Backend`] when Redis could not be asked, a counter or
    /// a stored verdict is not what this script writes (nothing was
    /// written), or the script answered something it never answers. A
    /// `Backend` detail is stridelabs-redis's fixed summary or a fixed
    /// phrase: never a key, the user id or Redis's own text.
    pub async fn charge(
        &self,
        redis: &RedisHandle,
        user: Uuid,
        chars: usize,
        key: &ChargeKey,
        fingerprint: &Fingerprint,
    ) -> Result<Admitted, BudgetError> {
        let now = (self.clock)();
        let (day_ttl, month_ttl) = key_ttls(now);
        let (day_key, month_key, global_key, charge_key) = (
            self.user_key(user, now),
            self.user_month_key(user, now),
            self.global_key(now),
            self.charge_key(user, key),
        );
        // Replay::OnceOnFreshConnection — this script may run twice, because
        // a second run of the same charge is harmless in its value AND its TTL
        // effects (what stridelabs-redis requires of a replayed write):
        //
        // - every write (the three counters' SETs, the verdict SET) happens
        //   only when no verdict is stored under KEYS[4], and in the same
        //   atomic run that stores it; a second run of this charge — the
        //   retry, or a first attempt landing after it — finds the verdict
        //   and answers it, writing and re-expiring nothing;
        // - KEYS[4] is this sentence's own (`key`, under this user): the
        //   only other writer is a run of the same sentence (the client's
        //   retry), which the same rule makes a reader; the counters other
        //   requests do race are never written by a second run;
        // - the answer is the stored verdict, so the retry's answer is the
        //   first attempt's (marked replayed: the module docs say what that
        //   costs usage records).
        //
        // `Never` would be worse on both counts it exists for: a lost reply
        // would be a 503 the client must then retry, and every connection
        // that died while idle would cost the next sentence a 503. Residual
        // risk: a first attempt delayed past its own retry by more than
        // CHARGE_VERDICT_SECONDS (10 min) would charge again. (The stream's
        // lease acquire is the opposite case: `crate::lease`.)
        let answer: Vec<i64> = redis
            .eval(
                CHARGE_SCRIPT,
                &[&day_key, &month_key, &global_key, &charge_key],
                &[
                    chars.into(),
                    self.caps.user_day.into(),
                    self.caps.user_month.into(),
                    self.caps.global_month.into(),
                    day_ttl.into(),
                    month_ttl.into(),
                    CHARGE_VERDICT_SECONDS.into(),
                    fingerprint.as_str().into(),
                    day_end(now).timestamp().into(),
                    month_end(now).timestamp().into(),
                ],
                Replay::OnceOnFreshConnection,
            )
            .await
            .map_err(|failure| BudgetError::Backend(failure.to_string()))?;
        charge_verdict(&answer, now)
    }
}

/// `CHARGE_SCRIPT`'s answer `{verdict, reset, replayed}`, answered at `now`:
/// `0` admitted (fresh, or replayed), `1..=7` the spent windows with the
/// stored reset, `-1` an invalid counter, stored verdict or argument, `-4`
/// ([`KEY_REUSED`]) a key sent with another sentence; anything else — and
/// any shape but three figures with `replayed` `0` or `1` — a reply the
/// script never makes.
///
/// # Errors
///
/// As [`TtsBudget::charge`].
pub(crate) fn charge_verdict(answer: &[i64], now: DateTime<Utc>) -> Result<Admitted, BudgetError> {
    let unexpected = || BudgetError::Backend(format!("the charge script answered {answer:?}"));
    match answer {
        [0, _, replayed @ (0 | 1)] => Ok(Admitted {
            at: now,
            disposition: if *replayed == 1 {
                Disposition::Replayed
            } else {
                Disposition::Fresh
            },
        }),
        [mask @ 1..=7, reset, 0 | 1] => Err(BudgetError::Exceeded(
            LimitReached::from_verdict(*mask, *reset, now).ok_or_else(unexpected)?,
        )),
        [INVALID_COUNTER, _, _] => Err(BudgetError::Backend(
            "a budget counter is not a non-negative integer, a stored verdict does not parse, \
             or an argument is malformed; nothing was charged"
                .to_string(),
        )),
        [KEY_REUSED, _, _] => Err(BudgetError::KeyReused),
        _ => Err(unexpected()),
    }
}

// ── The window scheme both budgets share ─────────────────────────────────
//
// The stream's audio budget (`crate::lease`) counts in the same three
// windows, under keys of the same shape, validated by the same `counter`
// rule and answered with the same verdicts. So the pieces of that rule on
// the Rust side live here once, beside `lua_helpers!`.

/// `{prefix}:user:{user}:{YYYY-MM-DD}` — `user`'s counter for the UTC day
/// `now` falls in.
pub(crate) fn user_day_key(prefix: &str, user: Uuid, now: DateTime<Utc>) -> String {
    format!("{prefix}:user:{user}:{}", day_stamp(now))
}

/// `{prefix}:user-month:{user}:{YYYY-MM}` — `user`'s counter for the UTC
/// month `now` falls in.
pub(crate) fn user_month_key(prefix: &str, user: Uuid, now: DateTime<Utc>) -> String {
    format!("{prefix}:user-month:{user}:{}", month_stamp(now))
}

/// `{prefix}:global:{YYYY-MM}` — everyone's counter for the UTC month `now`
/// falls in.
pub(crate) fn global_month_key(prefix: &str, now: DateTime<Utc>) -> String {
    format!("{prefix}:global:{}", month_stamp(now))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
            .single()
            .expect("a valid instant")
    }

    fn budget(prefix: &str) -> TtsBudget {
        TtsBudget::new(
            prefix,
            TtsCaps::new(20_000, 300_000, 300_000).expect("valid caps"),
        )
    }

    fn limit(mask: i64, now: DateTime<Utc>) -> LimitReached {
        LimitReached::from_mask(mask, now).expect("a mask naming a window")
    }

    #[test]
    fn the_keys_name_the_utc_day_and_month() {
        let budget = budget("tapper:voice:tts");
        let user = Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("a uuid");
        let now = at(2026, 10, 17, 23, 59, 59);
        assert_eq!(
            budget.user_key(user, now),
            "tapper:voice:tts:user:11111111-2222-3333-4444-555555555555:2026-10-17"
        );
        assert_eq!(
            budget.user_month_key(user, now),
            "tapper:voice:tts:user-month:11111111-2222-3333-4444-555555555555:2026-10"
        );
        assert_eq!(budget.global_key(now), "tapper:voice:tts:global:2026-10");
        let next = at(2026, 11, 1, 0, 0, 0);
        assert!(budget.user_month_key(user, next).ends_with(":2026-11"));
        assert!(budget.user_key(user, next).ends_with(":2026-11-01"));
    }

    /// Every spent-window bitmask the scripts can answer, `1` to `7`, and
    /// the scope it reports mid-month (the day ends first, the two months
    /// together): the latest reset, ties to `user_month` then
    /// `global_month`. A mask naming no window (`0`, or only bits outside
    /// `1 | 2 | 4`) is no refusal.
    #[test]
    fn each_mask_names_its_windows_and_reports_the_latest_reset() {
        use LimitScope::{GlobalMonth, UserDay, UserMonth};
        let now = at(2026, 10, 17, 12, 0, 0);
        for (mask, (day, global, month), scope) in [
            (1, (true, false, false), UserDay),
            (2, (false, true, false), GlobalMonth),
            (3, (true, true, false), GlobalMonth),
            (4, (false, false, true), UserMonth),
            (5, (true, false, true), UserMonth),
            (6, (false, true, true), UserMonth),
            (7, (true, true, true), UserMonth),
        ] {
            let limit = limit(mask, now);
            assert_eq!(
                limit.spent,
                Spent {
                    user_day: day,
                    user_month: month,
                    global_month: global
                },
                "mask {mask}"
            );
            assert_eq!(limit.scope, scope, "mask {mask}");
            assert_eq!(limit.resets_at, scope.resets_at(now), "mask {mask}");
            let expected = if scope == UserDay {
                12 * 3_600
            } else {
                15 * 86_400 - 12 * 3_600
            };
            assert_eq!(limit.retry_after_seconds, expected, "mask {mask}");
        }
        assert_eq!(Spent::from_mask(0).scope(now), None);
        assert_eq!(LimitReached::new(Spent::default(), now), None);
        assert_eq!(LimitReached::from_mask(0, now), None);
        assert_eq!(LimitReached::from_mask(8, now), None);
    }

    /// On a month's LAST day the day and both months end at the same
    /// midnight: every spent set ties, and the tie order decides —
    /// `user_month`, then `global_month`, then `user_day`. (The negative
    /// control is the mid-month test above: there the day ends first, so a
    /// month always wins on its reset alone.)
    #[test]
    fn on_a_months_last_day_the_tie_goes_to_the_users_month_then_the_global_one() {
        use LimitScope::{GlobalMonth, UserDay, UserMonth};
        let now = at(2026, 10, 31, 18, 0, 0);
        assert_eq!(day_end(now), month_end(now), "premise: one midnight");
        for (mask, scope) in [
            (1, UserDay),
            (2, GlobalMonth),
            (3, GlobalMonth),
            (4, UserMonth),
            (5, UserMonth),
            (6, UserMonth),
            (7, UserMonth),
        ] {
            let limit = limit(mask, now);
            assert_eq!(limit.scope, scope, "mask {mask}");
            assert_eq!(limit.resets_at, at(2026, 11, 1, 0, 0, 0), "mask {mask}");
            assert_eq!(limit.retry_after_seconds, 6 * 3_600, "mask {mask}");
        }
    }

    /// The charge script's every answer: `0` admitted, fresh or replayed
    /// (and when); `1..=7` refused with its windows and the STORED reset
    /// (fresh: the reported window's end; replayed: the original one, even
    /// after it passed — `Retry-After` is then 1); `-1` an invalid counter
    /// or stored verdict; `-4` a reused key; anything else a reply it never
    /// makes (`8`, `-2`, `-3`, a large number, an older bare integer, a
    /// `replayed` of `2`, a reset that is no instant) — each `Backend`, never
    /// an admission.
    #[test]
    fn every_charge_answer_has_one_meaning() {
        let now = at(2026, 10, 17, 12, 0, 0);
        assert_eq!(
            charge_verdict(&[0, 0, 0], now),
            Ok(Admitted {
                at: now,
                disposition: Disposition::Fresh
            })
        );
        assert_eq!(
            charge_verdict(&[0, 0, 1], now),
            Ok(Admitted {
                at: now,
                disposition: Disposition::Replayed
            })
        );
        for mask in 1..=7 {
            let fresh = limit(mask, now);
            for replayed in [0, 1] {
                assert_eq!(
                    charge_verdict(&[mask, fresh.resets_at.timestamp(), replayed], now),
                    Err(BudgetError::Exceeded(fresh)),
                    "mask {mask}"
                );
            }
        }
        // A replayed refusal keeps the reset it was stored with: yesterday's
        // day, answered today, still says yesterday's midnight.
        let original = at(2026, 10, 17, 0, 0, 0);
        assert_eq!(
            charge_verdict(&[1, original.timestamp(), 1], now),
            Err(BudgetError::Exceeded(LimitReached {
                spent: Spent::from_mask(1),
                scope: LimitScope::UserDay,
                resets_at: original,
                retry_after_seconds: 1,
            }))
        );
        assert!(matches!(
            charge_verdict(&[INVALID_COUNTER, 0, 0], now),
            Err(BudgetError::Backend(detail)) if detail.contains("nothing was charged")
        ));
        assert_eq!(
            charge_verdict(&[KEY_REUSED, 0, 0], now),
            Err(BudgetError::KeyReused)
        );
        for unknown in [
            &[8, 0, 0][..],
            &[15, 0, 0][..],
            &[-2, 0, 0][..],
            &[-3, 0, 0][..],
            &[i64::MAX, 0, 0][..],
            &[i64::MIN, 0, 0][..],
            &[0][..],
            &[0, 0][..],
            &[0, 0, 0, 0][..],
            &[0, 0, 2][..],
            &[1, 0, 2][..],
            &[1, i64::MAX, 0][..],
            &[][..],
        ] {
            assert_eq!(
                charge_verdict(unknown, now),
                Err(BudgetError::Backend(format!(
                    "the charge script answered {unknown:?}"
                ))),
                "{unknown:?}"
            );
        }
    }

    /// A key a client may send: 1 to 64 characters of `A-Z a-z 0-9 _ -`,
    /// nothing else (no space, dot, slash, colon, non-ASCII); a minted one
    /// is a uuid, which parses.
    #[test]
    fn a_charge_key_is_one_to_sixty_four_safe_characters() {
        for good in [
            "a",
            "A-z_09",
            &"k".repeat(64),
            "550e8400-e29b-41d4-a716-446655440000",
        ] {
            assert_eq!(
                ChargeKey::parse(good).map(|key| key.as_str().to_string()),
                Some(good.to_string()),
                "{good}"
            );
        }
        for bad in [
            "",
            &"k".repeat(65),
            "a b",
            "a.b",
            "a/b",
            "a:b",
            "a\tb",
            "é",
            "a+b",
            "*",
        ] {
            assert_eq!(ChargeKey::parse(bad), None, "{bad:?}");
        }
        let minted = ChargeKey::mint();
        assert_eq!(ChargeKey::parse(minted.as_str()), Some(minted.clone()));
        assert_ne!(minted, ChargeKey::mint());
    }

    /// The fingerprint is the first 16 hex characters of SHA-256 over
    /// `voice + "\n" + text` (vectors from `sha256sum`), and tells voices and
    /// texts apart.
    #[test]
    fn the_fingerprint_is_sha256_of_voice_newline_text_cut_to_16_hex() {
        assert_eq!(Fingerprint::of("Jason", "hi").as_str(), "0189888111b3955a");
        assert_eq!(Fingerprint::of("Hazel", "hi").as_str(), "eee74b70571a7144");
        assert_eq!(
            Fingerprint::of("Jason", "hi there").as_str(),
            "622a4e06adc89cf1"
        );
    }

    /// The verdict key is under the user: two users' same key are two keys.
    #[test]
    fn the_charge_key_is_scoped_by_user() {
        let budget = budget("tapper:voice:tts");
        let key = ChargeKey::parse("sentence-1").expect("a key");
        let user = Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("a uuid");
        let other = Uuid::parse_str("66666666-2222-3333-4444-555555555555").expect("a uuid");
        assert_eq!(
            budget.charge_key(user, &key),
            "tapper:voice:tts:charge:11111111-2222-3333-4444-555555555555:sentence-1"
        );
        assert_ne!(
            budget.charge_key(user, &key),
            budget.charge_key(other, &key)
        );
    }

    /// The scopes' wire names.
    #[test]
    fn the_scopes_serialize_in_snake_case() {
        for (scope, wire) in [
            (LimitScope::UserDay, "user_day"),
            (LimitScope::UserMonth, "user_month"),
            (LimitScope::GlobalMonth, "global_month"),
        ] {
            assert_eq!(scope.as_str(), wire);
            assert_eq!(
                serde_json::to_string(&scope).expect("JSON"),
                format!("\"{wire}\"")
            );
        }
    }

    /// The startup rule's every row, as [`CapProblem`]s: each cap
    /// `1..=MAX` (zero, negative and `MAX` itself; `MAX` is allowed), then
    /// day <= user month <= global month between valid caps (equal is
    /// allowed; an invalid cap is not also compared), every problem at once
    /// in order; and the message names windows and the rule, never a value.
    #[test]
    fn caps_new_refuses_each_problem_and_names_its_window() {
        use LimitScope::{GlobalMonth, UserDay, UserMonth};
        let max = TtsCaps::MAX;
        let invalid = |window| CapProblem::Invalid { window, max };
        let refused = |caps: [i64; 3]| {
            TtsCaps::new(caps[0], caps[1], caps[2])
                .expect_err("refused")
                .problems()
                .to_vec()
        };
        assert_eq!(
            TtsCaps::new(10, 10, 30).map(|caps| (
                caps.user_day(),
                caps.user_month(),
                caps.global_month()
            )),
            Ok((10, 10, 30)),
            "equal caps are allowed"
        );
        assert!(
            TtsCaps::new(max, max, max).is_ok(),
            "the largest is allowed"
        );
        for (index, window) in [UserDay, UserMonth, GlobalMonth].into_iter().enumerate() {
            for bad in [0, -1, i64::MIN] {
                let mut caps = [5, 5, 5];
                caps[index] = bad;
                assert_eq!(refused(caps), [invalid(window)], "{window:?} = {bad}");
            }
        }
        assert_eq!(
            refused([7, 6, 30]),
            [CapProblem::Below {
                window: UserMonth,
                below: UserDay
            }]
        );
        assert_eq!(
            refused([20_000, 300_001, 300_000]),
            [CapProblem::Below {
                window: GlobalMonth,
                below: UserMonth
            }]
        );
        assert_eq!(
            refused([9, 8, 7]),
            [
                CapProblem::Below {
                    window: UserMonth,
                    below: UserDay
                },
                CapProblem::Below {
                    window: GlobalMonth,
                    below: UserMonth
                }
            ]
        );
        // An invalid cap is not also compared: one problem, not two.
        assert_eq!(refused([7, 0, 300_000]), [invalid(UserMonth)]);
        // Every problem, invalid ones first.
        assert_eq!(
            refused([0, 9, 8]),
            [
                invalid(UserDay),
                CapProblem::Below {
                    window: GlobalMonth,
                    below: UserMonth
                }
            ]
        );
        let error = TtsCaps::new(-987_654_321, 6, 5).expect_err("refused");
        assert_eq!(
            error.to_string(),
            format!(
                "the voice caps are refused: the user_day cap is not a positive whole number (1 \
                 to {max}); the global_month cap is below the user_month cap (the caps must run \
                 a user's day <= a user's month <= everyone's month)"
            )
        );
        assert!(!error.to_string().contains("987654321"));
    }
}
