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
//! # What a payload carries: a fixed summary, never anyone's text
//!
//! Every payload is a summary this crate composes from fixed strings — it
//! never copies redis-rs's text or the server's, because both can carry what
//! they were sent. A Redis URL holds its password in the userinfo; a server
//! refusing a handshake echoes it (`unknown command 'HELLO', with args
//! beginning with: '3' 'AUTH' '<user>' '<password>'`); an unknown command
//! echoes its arguments (`… 'EVAL', with args beginning with: '<script>' '1'
//! '<key>' '<token>'`); a script's compile error quotes its source, and
//! `error(…)` / `redis.error_reply(…)` say whatever the script put in them —
//! the first word, the error's "code", included; redis-rs's account of a
//! reply that is not RESP quotes its bytes, and of a reply that does not
//! convert, its value; and a URL check can quote the URL's query.
//!
//! | Variant | Its payload |
//! |---|---|
//! | [`InvalidUrl`](RedisError::InvalidUrl) | which URL check failed, from a fixed list ("Invalid database number", "Missing hostname", …), or that the URL is not one redis-rs accepts |
//! | [`InvalidArgument`](RedisError::InvalidArgument) | which of this crate's checks failed |
//! | [`Connect`](RedisError::Connect), [`Io`](RedisError::Io) | what happened, by class: "timed out", "connection refused", "the connection was closed or reset", an I/O error's kind, "the reply was not well-formed RESP", "authentication failed", or an error reply as below |
//! | [`Command`](RedisError::Command) | an error reply's code when it is one Redis itself defines (`ERR`, `WRONGTYPE`, `NOSCRIPT`, `BUSY`, `READONLY`, `OOM`, …; any other is reported as undefined, never echoed) with a fixed description of its class; or that a reply did not convert to the command's type; or the shape of a reply `eval` or `ping` did not expect |
//!
//! So `Display`, `Debug` and the payload itself — logged, stored, or wrapped
//! by a consumer — carry none of it. The server's own words are not kept at
//! all: to see them, reproduce the command with `redis-cli`.

/// Why a [`RedisHandle`](crate::RedisHandle) call failed. See the module docs
/// for what each variant says about whether the command ran, and for what
/// each payload carries — a fixed summary, never redis-rs's or the server's
/// text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RedisError {
    /// [`RedisHandle::open`](crate::RedisHandle::open) refused the URL: it does
    /// not parse as a Redis URL, names a scheme this build cannot dial, or
    /// asks for `#insecure` TLS. The payload is which check failed, never the
    /// URL or any part of it.
    #[error("invalid Redis URL: {0}")]
    InvalidUrl(String),
    /// The caller passed a value no Redis command should be sent with (a
    /// window or TTL of zero or above [`MAX_TTL_SECS`](crate::MAX_TTL_SECS), a
    /// zero timeout). Nothing was sent.
    #[error("invalid Redis command argument: {0}")]
    InvalidArgument(&'static str),
    /// No connection could be established — refused, unresolvable, a TLS or
    /// `AUTH` failure, the server refusing the handshake, or the dial timeout
    /// elapsed. The command was never sent. Every caller that was waiting on
    /// the same dial gets this same error, and the next call dials afresh.
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
    /// cached. The payload names the error's code (when Redis defines it)
    /// and its class, or the reply's shape — never the server's text.
    #[error("Redis command failed: {0}")]
    Command(String),
}

/// The error codes Redis itself answers with, and what each means: all a
/// summary says about an error reply. A code not listed here is reported as
/// undefined, never echoed — the code is only the reply's first word, and a
/// script chooses its own (`redis.error_reply(ARGV[1])` answers with
/// whatever `ARGV[1]` starts with).
///
/// Each description states what happened to the command, because that is
/// what a caller acts on: Redis raises most of these BEFORE running it
/// (`processCommand`'s checks, a command's own type or key check), so they
/// say it was refused; only `ERR` can also come from a script that had
/// already written. Inside a script, "the command" is the `redis.call` that
/// failed — the script's earlier calls stand.
const SERVER_ERROR_CODES: &[(&str, &str)] = &[
    (
        "ERR",
        "a generic error: an unknown command or a refused argument (nothing ran), \
         or a script's error (the script may have written first)",
    ),
    (
        "WRONGTYPE",
        "the key holds another kind of value; the command was refused",
    ),
    ("NOSCRIPT", "no cached script has that SHA-1; nothing ran"),
    (
        "BUSY",
        "a script or function is running past its time limit; the command was refused",
    ),
    (
        "UNKILLABLE",
        "the running script has written, so it cannot be killed",
    ),
    (
        "NOTBUSY",
        "no script is running, so there is nothing to kill",
    ),
    (
        "READONLY",
        "the server is a read-only replica; the write was refused",
    ),
    (
        "OOM",
        "the server is at its memory limit; the command was refused",
    ),
    ("MISCONF", "the server cannot persist; writes are refused"),
    ("NOREPLICAS", "too few healthy replicas; writes are refused"),
    (
        "MASTERDOWN",
        "the replica has lost its primary; the command was refused",
    ),
    (
        "LOADING",
        "the server is loading its dataset; the command was refused",
    ),
    (
        "NOAUTH",
        "the connection is not authenticated; the command was refused",
    ),
    ("WRONGPASS", "the credentials were refused"),
    (
        "NOPERM",
        "the user lacks the ACL permission; the command was refused",
    ),
    ("NOPROTO", "the protocol version is not supported"),
    (
        "EXECABORT",
        "the transaction was discarded after an earlier error; none of it ran",
    ),
    (
        "BUSYKEY",
        "the target key already exists; the command was refused",
    ),
    (
        "NOGROUP",
        "no such stream consumer group; the command was refused",
    ),
    ("BUSYGROUP", "the consumer group already exists"),
    (
        "UNBLOCKED",
        "the blocked command was unblocked before it completed",
    ),
    (
        "MOVED",
        "a cluster redirect: this node did not run the command",
    ),
    (
        "ASK",
        "a cluster redirect: this node did not run the command",
    ),
    (
        "TRYAGAIN",
        "a cluster slot is being migrated; the command was refused",
    ),
    (
        "CROSSSLOT",
        "the keys hash to different cluster slots; the command was refused",
    ),
    (
        "CLUSTERDOWN",
        "the cluster is down; the command was refused",
    ),
];

/// redis-rs 1.7.1's URL checks (`connection.rs`), each a fixed description
/// that leads its rendering. Only these are ever repeated: one of them
/// ("Invalid protocol version") appends the URL's own `protocol` value.
const URL_REFUSALS: &[&str] = &[
    "Redis URL did not parse",
    "URL provided is not a redis URL",
    "Missing hostname",
    "Missing path",
    "Invalid database number",
    "Invalid protocol version",
    "Username is not valid UTF-8 string",
    "Password is not valid UTF-8 string",
    "Cannot connect to a wildcard address (0.0.0.0 or ::)",
    "only #insecure is supported as URL fragment",
    "can't connect with TLS, the feature is not enabled",
    "Unix sockets are not available on this platform.",
];

impl RedisError {
    /// `true` for [`RedisError::Io`]: the command may or may not have run.
    ///
    /// A caller deciding whether to send a non-idempotent command again must
    /// treat this as "it may have counted already".
    #[must_use]
    pub fn is_outcome_unknown(&self) -> bool {
        matches!(self, RedisError::Io(_))
    }

    /// redis-rs refused the URL.
    pub(crate) fn invalid_url(error: &redis::RedisError) -> RedisError {
        let rendered = error.to_string();
        let refusal = URL_REFUSALS
            .iter()
            .find(|refusal| rendered.starts_with(**refusal))
            .copied()
            .unwrap_or("not a URL redis-rs accepts");
        RedisError::InvalidUrl(refusal.to_owned())
    }

    /// The dial — TCP, TLS, or the connection-setup commands — failed.
    pub(crate) fn connect(error: &redis::RedisError) -> RedisError {
        RedisError::Connect(describe(error))
    }

    /// A round-trip that produced no valid reply — whatever redis-rs's kind
    /// for it (see the module docs).
    pub(crate) fn no_valid_reply(error: &redis::RedisError) -> RedisError {
        RedisError::Io(describe(error))
    }

    /// Redis answered with `error`, a well-formed error reply (at the top
    /// level or inside an array).
    pub(crate) fn error_reply(error: &redis::RedisError) -> RedisError {
        RedisError::Command(describe(error))
    }

    /// A well-formed reply that does not convert to the type the command
    /// reads. redis-rs's account of it quotes the reply.
    pub(crate) fn unconvertible(_error: &redis::ParsingError) -> RedisError {
        RedisError::Command(
            "the reply is not of the type the command reads (redis-rs: incompatible type)"
                .to_owned(),
        )
    }
}

/// What `error` was, told from redis-rs's classification alone — an error
/// reply's code if Redis defines it, the error's kind, an I/O error's kind —
/// and never from its text (see the module docs for what that can quote).
/// Also what this crate's own log lines say about a redis-rs error.
pub(crate) fn describe(error: &redis::RedisError) -> String {
    // An error reply, or redis-rs's verdict on one (a refused `SELECT`):
    // `code` is redis-rs's fixed string for a code it knows, else the
    // reply's first word, which only the table may repeat.
    if let Some(code) = error.code() {
        return match SERVER_ERROR_CODES.iter().find(|(known, _)| *known == code) {
            Some((code, meaning)) => format!("the server answered {code} ({meaning})"),
            None => "the server answered an error whose code Redis does not define \
                     (a script can raise any)"
                .to_owned(),
        };
    }
    match error.kind() {
        redis::ErrorKind::Io => describe_io(error),
        redis::ErrorKind::Parse => "the reply was not well-formed RESP".to_owned(),
        redis::ErrorKind::AuthenticationFailed => "authentication failed".to_owned(),
        redis::ErrorKind::InvalidClientConfig => "invalid client configuration".to_owned(),
        redis::ErrorKind::RESP3NotSupported => "the server does not support RESP3".to_owned(),
        redis::ErrorKind::UnexpectedReturnType => "a reply of an unexpected type".to_owned(),
        // `ErrorKind`'s `Debug` is its variant's name.
        kind => format!("a redis-rs error ({kind:?})"),
    }
}

/// An I/O failure by its class. redis-rs keeps the `io::Error` behind an
/// `Arc` that its `source()` exposes; its kind's `Debug` is a variant name.
fn describe_io(error: &redis::RedisError) -> String {
    use std::error::Error as _;
    use std::sync::Arc;

    if error.is_timeout() {
        return "timed out".to_owned();
    }
    if error.is_connection_refusal() {
        return "connection refused".to_owned();
    }
    if error.is_connection_dropped() {
        return "the connection was closed or reset".to_owned();
    }
    let kind = error
        .source()
        .and_then(|source| source.downcast_ref::<Arc<dyn std::error::Error + Send + Sync>>())
        .and_then(|inner| inner.downcast_ref::<std::io::Error>())
        .map(std::io::Error::kind);
    match kind {
        Some(kind) => format!("an I/O error ({kind:?})"),
        None => "an I/O error".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    /// Stands in for a password, a token or a user id that a request carried.
    const CANARY: &str = "user_01CANARYVALUE";

    /// Every way a consumer could render `error`: `Display`, `Debug` (plain
    /// and alternate), and the payload itself, plain and quoted.
    fn renderings(error: &RedisError) -> Vec<String> {
        let mut all = vec![
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
        ];
        match error {
            RedisError::InvalidUrl(payload)
            | RedisError::Connect(payload)
            | RedisError::Io(payload)
            | RedisError::Command(payload) => {
                all.push(payload.clone());
                all.push(format!("{payload:?}"));
            }
            RedisError::InvalidArgument(reason) => all.push((*reason).to_owned()),
        }
        all
    }

    fn assert_nowhere(error: &RedisError, canary: &str) {
        for rendered in renderings(error) {
            assert!(!rendered.contains(canary), "{canary} in {rendered}");
        }
    }

    /// `bytes` — one RESP error reply, possibly inside an array — as the
    /// redis-rs error `decode` extracts from it.
    fn server_error(bytes: &[u8]) -> redis::RedisError {
        let reply = redis::parse_redis_value(bytes).expect("well-formed RESP");
        reply.extract_error().expect_err("an error reply")
    }

    /// Redis's own diagnostics quote what they were sent; the summary keeps
    /// the code (when Redis defines it) and its class, and nothing else.
    #[test]
    fn an_error_reply_shows_only_its_code_and_class() {
        let cases: [(String, &str); 4] = [
            (
                format!("-ERR unknown command 'EVAL', with args beginning with: 'return 1' '1' '{CANARY}'\r\n"),
                "the server answered ERR (a generic error",
            ),
            (
                format!("-WRONGTYPE {CANARY}\r\n"),
                "the server answered WRONGTYPE (the key holds another kind of value; \
                 the command was refused)",
            ),
            (format!("-NOSCRIPT {CANARY}\r\n"), "the server answered NOSCRIPT"),
            (format!("*2\r\n:1\r\n-BUSY {CANARY}\r\n"), "the server answered BUSY"),
        ];
        for (reply, expected) in &cases {
            let redis_rs = server_error(reply.as_bytes());
            assert!(
                redis_rs.to_string().contains(CANARY),
                "the hazard: {redis_rs}"
            );
            let error = RedisError::error_reply(&redis_rs);
            assert!(matches!(error, RedisError::Command(_)), "{error:?}");
            assert!(!error.is_outcome_unknown());
            assert_nowhere(&error, CANARY);
            for rendered in renderings(&error) {
                assert!(rendered.contains(expected), "{expected}: {rendered}");
            }
        }
    }

    /// A summary must not misstate whether the command ran. Every code
    /// Redis raises BEFORE running the command says it was refused (or that
    /// nothing ran); none speaks of a write that happened.
    #[test]
    fn a_refusal_before_execution_says_the_command_did_not_run() {
        for code in [
            "WRONGTYPE",
            "NOSCRIPT",
            "BUSY",
            "READONLY",
            "OOM",
            "MISCONF",
            "NOREPLICAS",
            "MASTERDOWN",
            "LOADING",
            "NOAUTH",
            "NOPERM",
            "EXECABORT",
            "BUSYKEY",
            "NOGROUP",
            "MOVED",
            "ASK",
            "TRYAGAIN",
            "CROSSSLOT",
            "CLUSTERDOWN",
        ] {
            let error =
                RedisError::error_reply(&server_error(format!("-{code} detail\r\n").as_bytes()));
            let summary = error.to_string();
            assert!(summary.contains(&format!("answered {code} (")), "{summary}");
            assert!(
                ["refused", "nothing ran", "none of it ran", "did not run"]
                    .iter()
                    .any(|said| summary.contains(said)),
                "{code} must say the command did not run: {summary}"
            );
            assert!(!summary.contains("acknowledged"), "{code}: {summary}");
        }
    }

    /// A script picks its error's first word (`redis.error_reply(ARGV[1])`),
    /// so a code Redis does not define is user data: never echoed — whatever
    /// its case or punctuation, or when it is all there is.
    #[test]
    fn an_error_code_redis_does_not_define_is_never_echoed() {
        for (reply, canary) in [
            (format!("-{CANARY}\r\n"), CANARY),
            (format!("-{CANARY} and more\r\n"), CANARY),
            ("-CANARYCODE detail\r\n".to_owned(), "CANARYCODE"),
            ("-err lowercase is not ERR\r\n".to_owned(), "lowercase"),
            ("-ERR, punctuated\r\n".to_owned(), "punctuated"),
        ] {
            let error = RedisError::error_reply(&server_error(reply.as_bytes()));
            assert_nowhere(&error, canary);
            assert!(
                error
                    .to_string()
                    .contains("whose code Redis does not define"),
                "{reply:?}: {error}"
            );
        }
    }

    /// A reply that does not convert: redis-rs's error quotes it.
    #[test]
    fn an_unconvertible_reply_is_never_quoted() {
        let reply = redis::Value::BulkString(CANARY.as_bytes().to_vec());
        let parsing = <u64 as redis::FromRedisValue>::from_redis_value(reply)
            .expect_err("text is not a count");
        assert!(
            parsing.to_string().contains(CANARY),
            "the hazard: {parsing}"
        );

        let error = RedisError::unconvertible(&parsing);
        assert_nowhere(&error, CANARY);
        assert!(error.to_string().contains("incompatible type"), "{error}");
    }

    /// A dial or a round-trip that failed below the reply: its class, from
    /// redis-rs's kinds and predicates, never its text — not an I/O error's
    /// message, not a `General` error's detail, not a malformed reply's
    /// bytes.
    #[test]
    fn a_failure_below_the_reply_is_described_by_its_class() {
        let cases: Vec<(redis::RedisError, &str)> = vec![
            (io::Error::from(io::ErrorKind::TimedOut).into(), "timed out"),
            (
                io::Error::new(io::ErrorKind::TimedOut, CANARY).into(),
                "timed out",
            ),
            (
                io::Error::new(io::ErrorKind::ConnectionRefused, CANARY).into(),
                "connection refused",
            ),
            (
                io::Error::new(io::ErrorKind::BrokenPipe, CANARY).into(),
                "the connection was closed or reset",
            ),
            (
                io::Error::new(io::ErrorKind::InvalidData, CANARY).into(),
                "an I/O error (InvalidData)",
            ),
            (io::Error::other(CANARY).into(), "an I/O error (Other)"),
            (
                (
                    redis::ErrorKind::AuthenticationFailed,
                    "Password authentication failed",
                )
                    .into(),
                "authentication failed",
            ),
            (
                (
                    redis::ErrorKind::InvalidClientConfig,
                    "some check",
                    CANARY.to_owned(),
                )
                    .into(),
                "invalid client configuration",
            ),
            (
                (redis::ErrorKind::Client, "some check", CANARY.to_owned()).into(),
                "a redis-rs error (Client)",
            ),
            (
                redis::parse_redis_value(format!("?{CANARY}\r\n").as_bytes())
                    .expect_err("not RESP"),
                "the reply was not well-formed RESP",
            ),
        ];
        for (redis_rs, expected) in &cases {
            for error in [
                RedisError::connect(redis_rs),
                RedisError::no_valid_reply(redis_rs),
            ] {
                assert_nowhere(&error, CANARY);
                assert!(error.to_string().ends_with(expected), "{expected}: {error}");
            }
        }
    }

    /// A handshake's failures. A server refusing `HELLO` echoes it,
    /// credentials included — the `Connect` names only the code; redis-rs's
    /// refused `SELECT` keeps the server's detail — dropped too.
    #[test]
    fn a_refused_handshake_never_carries_what_it_sent() {
        let hello = server_error(
            format!("-ERR unknown command 'HELLO', with args beginning with: '3' 'AUTH' 'alice' '{CANARY}' \r\n")
                .as_bytes(),
        );
        let select: redis::RedisError = (
            redis::ErrorKind::Server(redis::ServerErrorKind::ResponseError),
            "Redis server refused to switch database",
            CANARY.to_owned(),
        )
            .into();
        for redis_rs in [hello, select] {
            assert!(
                redis_rs.to_string().contains(CANARY),
                "the hazard: {redis_rs}"
            );
            let error = RedisError::connect(&redis_rs);
            assert!(matches!(error, RedisError::Connect(_)), "{error:?}");
            assert_nowhere(&error, CANARY);
            assert!(
                error.to_string().contains("the server answered ERR"),
                "{error}"
            );
        }
    }
}
