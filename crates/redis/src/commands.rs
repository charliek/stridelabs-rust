//! The commands [`RedisHandle`] sends, each under its replay policy.

use std::fmt;

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

/// One `ARGV` entry for [`RedisHandle::eval`]: text or an integer, made with
/// `From` (`token.as_str().into()`, `ttl_ms.into()`).
///
/// Redis hands a script every argument as a string, so an integer arrives as
/// its decimal digits for the script to `tonumber` — exactly what
/// redis-rs's own `arg(n)` sends. Lua numbers are doubles: an integer
/// beyond ±2^53 does not survive `tonumber` exactly.
///
/// Its own type, rather than redis-rs's `ToRedisArgs`, so that no redis-rs
/// type is part of this crate's API.
///
/// Its `Debug` names the kind of argument, never its value
/// (`EvalArg(<text, 12 bytes>)`, `EvalArg(<integer>)`): arguments carry lease
/// tokens and user ids, and an `args` slice is exactly what a consumer's
/// `{:?}` or `#[instrument]` would otherwise print.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EvalArg<'a>(Arg<'a>);

impl fmt::Debug for EvalArg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Arg::Text(text) => write!(f, "EvalArg(<text, {} bytes>)", text.len()),
            Arg::Signed(_) | Arg::Unsigned(_) => f.write_str("EvalArg(<integer>)"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Arg<'a> {
    Text(&'a str),
    Signed(i64),
    Unsigned(u64),
}

impl<'a> From<&'a str> for EvalArg<'a> {
    fn from(text: &'a str) -> Self {
        EvalArg(Arg::Text(text))
    }
}

impl<'a> From<&'a String> for EvalArg<'a> {
    fn from(text: &'a String) -> Self {
        EvalArg(Arg::Text(text))
    }
}

impl From<i64> for EvalArg<'_> {
    fn from(number: i64) -> Self {
        EvalArg(Arg::Signed(number))
    }
}

impl From<i32> for EvalArg<'_> {
    fn from(number: i32) -> Self {
        EvalArg(Arg::Signed(number.into()))
    }
}

impl From<u64> for EvalArg<'_> {
    fn from(number: u64) -> Self {
        EvalArg(Arg::Unsigned(number))
    }
}

impl From<u32> for EvalArg<'_> {
    fn from(number: u32) -> Self {
        EvalArg(Arg::Unsigned(number.into()))
    }
}

impl From<usize> for EvalArg<'_> {
    fn from(number: usize) -> Self {
        // Lossless: no target this builds for has a usize wider than 64 bits.
        EvalArg(Arg::Unsigned(number as u64))
    }
}

/// A type [`RedisHandle::eval`] can read a script's reply as: `i64` (the
/// script returned a number) or `Vec<i64>` (a table of numbers).
///
/// Lua's conversion to a reply applies first: a number is truncated to an
/// integer, `true` becomes 1, and `false` becomes nil — as the reply, or as
/// an element of a table: `{1, false, 3}` arrives as `[1, nil, 3]`. Only a
/// Lua `nil` ends a table, so `{1, nil, 3}` arrives as `[1]`. The decoding is
/// strict: `i64` takes only an integer reply and `Vec<i64>` only an array of
/// integers (an empty table included, a nil reply or a nil element not —
/// `{1, false, 3}` is an error), and anything else is
/// [`RedisError::Command`] naming the reply's shape, never its contents. A
/// script that wrote before returning a reply that does not decode still
/// wrote: the error says Redis ran it.
///
/// Sealed — implemented here and nowhere else — so that no redis-rs type is
/// part of this crate's API (redis-rs's own conversions would also put the
/// reply's value in their error). More reply types can be added without a
/// breaking change.
pub trait EvalReply: sealed::Sealed {}

mod sealed {
    /// The decoding behind [`super::EvalReply`]. `pub` inside a private
    /// module: nameable here, unnameable (so unimplementable) outside.
    pub trait Sealed: Sized {
        fn from_reply(reply: redis::Value) -> Result<Self, crate::RedisError>;
    }
}

impl EvalReply for i64 {}

impl sealed::Sealed for i64 {
    fn from_reply(reply: redis::Value) -> Result<i64, RedisError> {
        match reply {
            redis::Value::Int(number) => Ok(number),
            other => Err(RedisError::Command(format!(
                "the script answered {}, not an integer",
                shape(&other)
            ))),
        }
    }
}

impl EvalReply for Vec<i64> {}

impl sealed::Sealed for Vec<i64> {
    fn from_reply(reply: redis::Value) -> Result<Vec<i64>, RedisError> {
        let redis::Value::Array(items) = reply else {
            return Err(RedisError::Command(format!(
                "the script answered {}, not an array of integers",
                shape(&reply)
            )));
        };
        items
            .iter()
            .enumerate()
            .map(|(index, item)| match item {
                redis::Value::Int(number) => Ok(*number),
                other => Err(RedisError::Command(format!(
                    "the script's array holds {} at index {index}, not an integer",
                    shape(other)
                ))),
            })
            .collect()
    }
}

/// `EVAL script numkeys keys… args…`.
fn eval_command(script: &str, keys: &[&str], args: &[EvalArg<'_>]) -> redis::Cmd {
    let mut eval = redis::cmd("EVAL");
    eval.arg(script).arg(keys.len());
    for key in keys {
        eval.arg(*key);
    }
    for arg in args {
        match arg.0 {
            Arg::Text(text) => eval.arg(text),
            Arg::Signed(number) => eval.arg(number),
            Arg::Unsigned(number) => eval.arg(number),
        };
    }
    eval
}

/// What kind of reply `value` is — for an error message that must not carry
/// the value itself (a script's reply can hold a user id or a token).
fn shape(value: &redis::Value) -> &'static str {
    match value {
        redis::Value::Nil => "nil",
        redis::Value::Int(_) => "an integer",
        redis::Value::BulkString(_) => "a string",
        redis::Value::SimpleString(_) | redis::Value::Okay => "a status",
        redis::Value::Array(_) => "an array",
        redis::Value::Double(_) => "a double",
        redis::Value::Boolean(_) => "a boolean",
        _ => "another kind of reply",
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
    /// one retry, where it earned one) failed — and `Io`, the first
    /// attempt's, when the retry could not even connect, since the first may
    /// have run; [`RedisError::Command`] if the key holds a non-string value
    /// (`WRONGTYPE`) or bytes that are not UTF-8.
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

    /// `EVAL script numkeys keys… args…`: run a Lua script, with `keys` as
    /// its `KEYS` and `args` as its `ARGV`, both in order, and read its reply
    /// as `T` — `i64` or `Vec<i64>` (see [`EvalReply`]).
    ///
    /// ```no_run
    /// # async fn example(redis: &stridelabs_redis::RedisHandle, token: &str) -> Result<(), stridelabs_redis::RedisError> {
    /// use stridelabs_redis::Replay;
    ///
    /// // Read-only: a second run changes nothing, so a lost reply may be
    /// // retried on a fresh connection.
    /// const SPENT: &str = "return {tonumber(redis.call('GET', KEYS[1]) or 0), redis.call('PTTL', KEYS[1])}";
    /// let spent_and_ttl: Vec<i64> = redis
    ///     .eval(SPENT, &["budget:alice:2026-10-20"], &[], Replay::OnceOnFreshConnection)
    ///     .await?;
    ///
    /// // Takes the lease over: it writes, so it is sent at most once. Had its
    /// // reply been lost and the script re-sent, the second run could
    /// // overwrite a holder that took the lease in between — and would
    /// // restart the TTL either way.
    /// const TAKE_OVER: &str = "
    /// local previous = redis.call('GET', KEYS[1])
    /// redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
    /// if previous and previous ~= ARGV[1] then return 1 end
    /// return 0
    /// ";
    /// let took_over: i64 = redis
    ///     .eval(TAKE_OVER, &["lease:alice"], &[token.into(), 30_000_u64.into()], Replay::Never)
    ///     .await?;
    /// // An `Io` error here (`is_outcome_unknown()`): the takeover may have
    /// // run, may not, or may still run — the request can be delayed on the
    /// // dropped connection. Reading the lease back shows who holds it NOW,
    /// // not what became of this attempt, and is no licence to retry. Treat
    /// // the session as not owning the lease until a later read shows its
    /// // own token, or end the session.
    /// # let _ = (spent_and_ttl, took_over);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// **`replay` is the caller's call, and it is the important argument**:
    /// [`Replay::Never`] for any script that writes — it counts, it acquires
    /// or takes something over — and [`Replay::OnceOnFreshConnection`] only
    /// for one whose second execution is harmless: a read, or a write that
    /// is idempotent in its value and its TTL effects on a key no other
    /// writer races. Under `OnceOnFreshConnection` a script whose reply was
    /// lost after it ran **is** run again. See [`Replay`].
    ///
    /// Pass every key the script touches in `keys` rather than building it
    /// inside the script: that is Redis's scripting contract.
    ///
    /// Sent as a raw `EVAL` — the script travels with every call — rather
    /// than `EVALSHA` with a `SCRIPT LOAD` cache: no script cache to go
    /// missing after a server restart or failover, and none of redis-rs's
    /// `script` feature (and its `sha1_smol`) in the graph.
    ///
    /// # Errors
    ///
    /// [`RedisError::Connect`] if no connection could be made;
    /// [`RedisError::Io`] if no valid reply was read (and, under
    /// `OnceOnFreshConnection`, its one retry where it earned one failed
    /// too) — the script may have run; [`RedisError::Command`] if Redis
    /// answered with an error (a Lua runtime or compile error, a
    /// `redis.error_reply`, an error from a `redis.call`; the connection stays
    /// cached and nothing is retried) or with a reply that is not a `T`.
    ///
    /// A `Command` error names only the error's code (when Redis defines it)
    /// and its class, or the reply's shape — never the script, a key, an
    /// argument or the reply. Redis's own text can quote all of those (a
    /// compile error quotes the source, an `error('…' .. ARGV[1])` or
    /// `redis.error_reply(…)` says whatever the script put in it, an unknown
    /// command echoes its arguments), so it is not carried at all: to see it
    /// while debugging a script, run the script with `redis-cli`.
    pub async fn eval<T: EvalReply>(
        &self,
        script: &str,
        keys: &[&str],
        args: &[EvalArg<'_>],
        replay: Replay,
    ) -> Result<T, RedisError> {
        let reply: redis::Value = self
            .query(&eval_command(script, keys, args), replay)
            .await?;
        T::from_reply(reply)
    }

    /// `PING`: `Ok(())` when Redis answers `PONG` — a readiness probe.
    ///
    /// Idempotent, so it gets [`RedisHandle::get`]'s one retry on a fresh
    /// connection after an I/O failure on a cached one: a probe that finds
    /// the idle connection dead reports whether Redis can be reached NOW,
    /// not that a socket went stale. Bounded by the handle's timeouts — at
    /// most a dial and a response timeout, or response + dial + response
    /// when it retries (1.5 s and 2 s with the defaults), which a readiness
    /// endpoint's own deadline should allow for.
    ///
    /// # Errors
    ///
    /// [`RedisError::Connect`] if no connection could be made;
    /// [`RedisError::Io`] if no valid reply was read; [`RedisError::Command`]
    /// if Redis answered with an error (`NOAUTH`, `LOADING`, …) or with
    /// something other than `PONG`.
    pub async fn ping(&self) -> Result<(), RedisError> {
        let reply: redis::Value = self
            .query(&redis::cmd("PING"), Replay::OnceOnFreshConnection)
            .await?;
        match reply {
            redis::Value::SimpleString(pong) if pong == "PONG" => Ok(()),
            other => Err(RedisError::Command(format!(
                "PING was answered with {}, not PONG",
                shape(&other)
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sealed::Sealed as _;
    use super::*;

    /// A reply value no error message may echo: it stands in for a user id.
    const SECRET: &str = "user_01SECRETVALUE";

    fn words(command: &redis::Cmd) -> Vec<String> {
        command
            .args_iter()
            .map(|arg| match arg {
                redis::Arg::Simple(bytes) => String::from_utf8(bytes.to_vec()).expect("UTF-8"),
                _ => panic!("EVAL's arguments are all simple"),
            })
            .collect()
    }

    /// `numkeys` is the number of keys, the keys come before the arguments,
    /// each list keeps its order, and every integer type is sent as its
    /// decimal digits.
    #[test]
    fn eval_sends_numkeys_then_the_keys_then_the_arguments_in_order() {
        let owned = String::from("owned");
        let command = eval_command(
            "return 1",
            &["k:1", "k:2", "k:3"],
            &[
                "text".into(),
                (&owned).into(),
                (-3_i64).into(),
                i64::MIN.into(),
                u64::MAX.into(),
                7_i32.into(),
                8_u32.into(),
                9_usize.into(),
            ],
        );
        assert_eq!(
            words(&command),
            [
                "EVAL",
                "return 1",
                "3",
                "k:1",
                "k:2",
                "k:3",
                "text",
                "owned",
                "-3",
                "-9223372036854775808",
                "18446744073709551615",
                "7",
                "8",
                "9",
            ]
        );

        let command = eval_command("return 0", &[], &[]);
        assert_eq!(words(&command), ["EVAL", "return 0", "0"]);
    }

    /// `{:?}` of an argument list — what a consumer's log line or
    /// `#[instrument]` prints — names each argument's kind, never its value:
    /// a token, and the numbers too (an integer can be a user's id).
    #[test]
    fn eval_arg_debug_never_prints_the_value() {
        let owned = String::from(SECRET);
        let args: [EvalArg<'_>; 4] = [
            SECRET.into(),
            (&owned).into(),
            9_876_543_210_i64.into(),
            1_234_567_u64.into(),
        ];
        let rendered = format!("{args:?} {args:#?}");
        for value in [SECRET, "9876543210", "1234567"] {
            assert!(!rendered.contains(value), "{value} in {rendered}");
        }
        assert_eq!(format!("{:?}", args[0]), "EvalArg(<text, 18 bytes>)");
        assert_eq!(format!("{:?}", args[2]), "EvalArg(<integer>)");
        assert_eq!(format!("{:?}", args[3]), "EvalArg(<integer>)");
    }

    #[test]
    fn integer_replies_decode() {
        assert_eq!(i64::from_reply(redis::Value::Int(-7)).unwrap(), -7);
        assert_eq!(
            Vec::<i64>::from_reply(redis::Value::Array(vec![
                redis::Value::Int(0),
                redis::Value::Int(i64::MAX),
                redis::Value::Int(-1),
            ]))
            .unwrap(),
            [0, i64::MAX, -1]
        );
        assert_eq!(
            Vec::<i64>::from_reply(redis::Value::Array(Vec::new())).unwrap(),
            Vec::<i64>::new(),
            "an empty table is an empty array"
        );
    }

    /// A reply of another shape is `Command` (Redis answered), and the
    /// message names the shape — never the value, which may be a user id.
    #[test]
    fn a_reply_of_another_shape_names_the_shape_never_the_value() {
        let secret = || redis::Value::BulkString(SECRET.as_bytes().to_vec());
        let cases: Vec<(Result<(), RedisError>, &str)> = vec![
            (i64::from_reply(secret()).map(drop), "a string"),
            (i64::from_reply(redis::Value::Nil).map(drop), "nil"),
            (
                i64::from_reply(redis::Value::Array(vec![secret()])).map(drop),
                "an array",
            ),
            (Vec::<i64>::from_reply(secret()).map(drop), "a string"),
            (
                Vec::<i64>::from_reply(redis::Value::Nil).map(drop),
                "nil, not an array",
            ),
            (
                Vec::<i64>::from_reply(redis::Value::Int(1)).map(drop),
                "an integer, not an array",
            ),
            (
                Vec::<i64>::from_reply(redis::Value::Array(vec![redis::Value::Int(1), secret()]))
                    .map(drop),
                "a string at index 1",
            ),
            (
                Vec::<i64>::from_reply(redis::Value::Array(vec![redis::Value::Nil])).map(drop),
                "nil at index 0",
            ),
        ];
        for (result, shape) in cases {
            let error = result.expect_err(shape);
            assert!(matches!(error, RedisError::Command(_)), "{error:?}");
            assert!(!error.is_outcome_unknown());
            let rendered = error.to_string();
            assert!(rendered.contains(shape), "{shape}: {rendered}");
            for rendered in [rendered, format!("{error:?}")] {
                assert!(!rendered.contains(SECRET), "{rendered}");
            }
        }
    }
}
