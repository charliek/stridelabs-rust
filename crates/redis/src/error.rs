//! [`RedisError`] — what a [`RedisHandle`](crate::RedisHandle) call can fail
//! with, classified by what the caller can conclude about the command.
//!
//! The variants are not redis-rs's error kinds. They answer the one question
//! a caller's policy turns on — **did the command run?** — because that is
//! what decides whether anything may be retried:
//!
//! | Variant | Command sent? | Ran? |
//! |---|---|---|
//! | [`InvalidUrl`](RedisError::InvalidUrl), [`InvalidArgument`](RedisError::InvalidArgument) | no | no |
//! | [`Connect`](RedisError::Connect) | no — no connection was established | no |
//! | [`Io`](RedisError::Io) | maybe | **unknown** — no valid reply was read |
//! | [`Command`](RedisError::Command) | yes | Redis answered, with an error or an unexpected reply |
//!
//! # Classified by where the failure happened, not by redis-rs's kind
//!
//! A command's failure is `Io` whenever no complete, well-formed reply was
//! read for it — whatever redis-rs's `ErrorKind` says — and `Command` only
//! once one was. The kind cannot draw that line: in redis-rs 1.7.1
//! `ErrorKind::Parse` covers both a malformed reply off the wire (the codec's
//! failure, after which the command may well have run) and a well-formed reply
//! of the wrong type (`FromRedisValue`'s), and the other kinds a round-trip
//! can fail with (`Io`, `Client`, `Extension`, …) say nothing reliable about
//! whether a reply was read. So the handle reads the raw `redis::Value`
//! first: any failure to get one is `Io`; a server error reply in it, or a
//! value that does not convert to the expected type, is `Command`.
//!
//! # Never the URL
//!
//! A Redis URL carries its password in the userinfo (`redis://:secret@host`),
//! so no variant holds the URL or any part of it. The payloads are redis-rs's
//! own rendering of the failure, which names the kind of failure ("Redis URL
//! did not parse", "Connection refused", "timed out", a server error reply)
//! and never the connection info; the crate's tests pin that for each
//! variant built from a `redis://:secret@…` URL.

/// Why a [`RedisHandle`](crate::RedisHandle) call failed. See the module docs
/// for what each variant says about whether the command ran.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RedisError {
    /// [`RedisHandle::open`](crate::RedisHandle::open) refused the URL: it does
    /// not parse as a Redis URL, names a scheme this build cannot dial, or
    /// asks for `#insecure` TLS. The payload is the reason, never the URL.
    #[error("invalid Redis URL: {0}")]
    InvalidUrl(String),
    /// The caller passed a value no Redis command should be sent with (a
    /// window or TTL of zero or above [`MAX_TTL_SECS`](crate::MAX_TTL_SECS), a
    /// zero timeout). Nothing was sent.
    #[error("invalid Redis command argument: {0}")]
    InvalidArgument(&'static str),
    /// No connection could be established — refused, unresolvable, a TLS or
    /// `AUTH` failure, or the dial timeout elapsed. The command was never
    /// sent. Every caller that was waiting on the same dial gets this same
    /// error, and the next call dials afresh.
    #[error("could not connect to Redis: {0}")]
    Connect(String),
    /// No valid reply was read, with the command possibly already on the
    /// wire: the connection failed, the response timeout elapsed, or what came
    /// back was not well-formed RESP. **Whether Redis ran it is unknown**: it
    /// may have executed and only the reply been lost or mangled. The
    /// connection is dropped and the next call redials.
    #[error("no valid reply from Redis; the command's outcome is unknown: {0}")]
    Io(String),
    /// Redis answered with a well-formed reply that was not what was
    /// expected: an error reply (`WRONGTYPE`, a script error, `OOM`, …), or a
    /// value of the wrong type. The connection is known to work and stays
    /// cached.
    #[error("Redis command failed: {0}")]
    Command(String),
}

impl RedisError {
    /// `true` for [`RedisError::Io`]: the command may or may not have run.
    ///
    /// A caller deciding whether to send a non-idempotent command again must
    /// treat this as "it may have counted already".
    #[must_use]
    pub fn is_outcome_unknown(&self) -> bool {
        matches!(self, RedisError::Io(_))
    }

    /// A round-trip that produced no valid reply — whatever redis-rs's kind
    /// for it (see the module docs).
    pub(crate) fn no_valid_reply(error: &redis::RedisError) -> RedisError {
        RedisError::Io(error.to_string())
    }
}
