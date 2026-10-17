//! The commands [`RedisHandle`] sends, each under its replay policy.

use crate::handle::Replay;
use crate::{RedisError, RedisHandle};

/// `INCR` the window's counter and, only when that created it (`count == 1`),
/// set its TTL — one server-side script, so the two steps are atomic. A plain
/// `INCR` then `EXPIRE` could be cut between the calls (a crash, a cancelled
/// future, a dropped connection) and leave a counter with no TTL, rate
/// limiting its subject forever; Redis runs a script without interleaving
/// any other client's command, so that cannot happen.
///
/// Byte-for-byte the script of Python `stridelabs-mcp`'s `limits.py`
/// (`_INCR_WITH_EXPIRE_LUA`), so both implementations share one key's
/// semantics. It touches one key, passed as `KEYS[1]`, which keeps it within
/// what Upstash's scripting supports.
const FIXED_WINDOW_SCRIPT: &str = "
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
";

/// The longest window or TTL either command accepts: ten years of 365 days,
/// in seconds.
///
/// **Checked before anything is sent**, because an `EXPIRE` that Redis
/// refuses runs AFTER the script's `INCR`, and a script is not rolled back
/// when a later call in it errors: the counter would be left at 1 with no
/// TTL, and every later hit (count > 1) skips the `EXPIRE` — a window that
/// never ends. Redis refuses a seconds TTL it cannot represent: `expire.c`'s
/// `expireGenericCommand` rejects one above `LLONG_MAX / 1000` (the
/// conversion to milliseconds would overflow) or whose absolute deadline,
/// `basetime + when`, would pass `LLONG_MAX` ("invalid expire time"); a value
/// above `i64::MAX` does not even parse as an integer; and `t_string.c`'s
/// `getExpireMillisecondsOrReply` makes the same two checks for `SET … EX`.
/// Ten years is about 3·10^8 s against a ceiling near 9.2·10^15 s, so no
/// clock and no server version brings it close — and no rate-limit window
/// or cache entry has a reason to be longer.
pub const MAX_TTL_SECS: u64 = 10 * 365 * 24 * 60 * 60;

/// `1..=MAX_TTL_SECS`, or the given refusal.
fn check_ttl(secs: u64, refusal: &'static str) -> Result<(), RedisError> {
    if (1..=MAX_TTL_SECS).contains(&secs) {
        Ok(())
    } else {
        Err(RedisError::InvalidArgument(refusal))
    }
}

impl RedisHandle {
    /// Count one hit in the fixed window `key` and return the window's count,
    /// this hit included. The first hit in a window (count 1) sets the key's
    /// TTL to `window_secs`; later hits leave it alone, so the window ends
    /// `window_secs` after its first hit however many follow.
    ///
    /// The caller builds the key, window number included (Python's shape is
    /// `{prefix}:{subject}:{class}:{unix_secs / window}`), and compares the
    /// count against its limit — this is the counter, not the policy.
    ///
    /// **The key namespace must be the counter's alone.** The TTL is set only
    /// when the `INCR` creates the key, so a key that already holds an
    /// integer with no TTL — written by something else, or left by a script
    /// run that failed after its `INCR` — is counted up forever and never
    /// repaired. Give the windows a prefix nothing else writes under.
    ///
    /// Sent as a raw `EVAL` (redis-rs's `script` feature, which exists for
    /// `EVALSHA` caching, stays off).
    ///
    /// **Never replayed.** If the reply is lost — the connection drops, or
    /// the response timeout elapses — Redis may already have run the `INCR`,
    /// so sending it again could count one hit twice. The error goes to the
    /// caller as [`RedisError::Io`] and the connection is dropped; whether to
    /// allow the request anyway (fail open, as a rate limiter should) is the
    /// caller's decision.
    ///
    /// # Errors
    ///
    /// [`RedisError::InvalidArgument`], before any I/O, for `window_secs`
    /// outside `1..=`[`MAX_TTL_SECS`] (an `EXPIRE` of 0 deletes the key, so
    /// the count would never pass 1; one Redis refuses would leave the key
    /// without a TTL — see [`MAX_TTL_SECS`]); [`RedisError::Connect`] if no
    /// connection could be made; [`RedisError::Io`] if the outcome is
    /// unknown; [`RedisError::Command`] if Redis refused the script (the key
    /// holds something other than an integer counter, say).
    pub async fn fixed_window_hit(&self, key: &str, window_secs: u64) -> Result<u64, RedisError> {
        check_ttl(
            window_secs,
            "a fixed window must be from 1 second to MAX_TTL_SECS (ten years) long",
        )?;
        let mut eval = redis::cmd("EVAL");
        eval.arg(FIXED_WINDOW_SCRIPT)
            .arg(1)
            .arg(key)
            .arg(window_secs);
        self.query(&eval, Replay::Never).await
    }

    /// `GET key`: the value, or `None` when the key does not exist (or has
    /// expired).
    ///
    /// Idempotent, so if it fails at the I/O level on a connection that was
    /// already cached — one that may have died while idle — it is sent
    /// **once** more, on a fresh connection.
    ///
    /// # Errors
    ///
    /// [`RedisError::Connect`] / [`RedisError::Io`] if the command (and its
    /// one retry, where it earned one) failed; [`RedisError::Command`] if the
    /// key holds a non-string value (`WRONGTYPE`) or bytes that are not UTF-8.
    pub async fn get(&self, key: &str) -> Result<Option<String>, RedisError> {
        let mut get = redis::cmd("GET");
        get.arg(key);
        self.query(&get, Replay::OnceOnFreshConnection).await
    }

    /// `SET key value EX ttl_secs`: store `value` under `key`, expiring after
    /// `ttl_secs` seconds, replacing any value (and TTL) already there.
    ///
    /// Idempotent — a second identical `SET` leaves the key as one would — so
    /// it gets the same one retry as [`RedisHandle::get`]. "Idempotent" is in
    /// the cache sense, not a conditional write: the retry, or a first attempt
    /// that lands late, **restarts the TTL** and **overwrites whatever another
    /// writer stored in between**. Right for a TTL cache whose writers all
    /// store the same answer; wrong for anything that needs compare-and-set.
    ///
    /// # Errors
    ///
    /// [`RedisError::InvalidArgument`], before any I/O, for `ttl_secs`
    /// outside `1..=`[`MAX_TTL_SECS`] (Redis refuses an `EX` of 0, and any it
    /// cannot represent); otherwise as [`RedisHandle::get`].
    pub async fn set_ex(&self, key: &str, value: &str, ttl_secs: u64) -> Result<(), RedisError> {
        check_ttl(
            ttl_secs,
            "a TTL must be from 1 second to MAX_TTL_SECS (ten years) long",
        )?;
        let mut set = redis::cmd("SET");
        set.arg(key).arg(value).arg("EX").arg(ttl_secs);
        self.query(&set, Replay::OnceOnFreshConnection).await
    }
}
