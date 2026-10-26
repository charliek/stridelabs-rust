//! A fail-loud real-Redis probe for integration tests (feature `redis`).
//!
//! The Redis twin of `require_postgres` (feature `postgres`): a test that needs
//! a real server calls [`require_redis`], which **panics** — naming the URL it
//! tried (password redacted), the `REDIS_URL` env var, and the command that
//! starts the server — when no server answers. It never returns `None` for a
//! test to shrug off, so a green run means the Redis-backed behaviour ran.
//!
//! It probes, and hands back what a test needs to run against the server it
//! found: the URL (to build the code under test from, e.g. a
//! `stridelabs_redis::RedisHandle`) and a connection of its own (to inspect
//! or prepare keys independently of that code). It flushes nothing and
//! selects nothing beyond what the URL says: keys are shared by every test
//! that uses the same server, so tests isolate themselves with unique keys.
//!
//! **No TLS of its own.** This crate's `redis` is built without a TLS
//! feature, as its Postgres driver is: the probe talks to a local or CI
//! server in the clear, and adds no rustls to a consumer's test graph. (A
//! `rediss://` URL works only where something else in the build — a
//! consumer's `stridelabs-redis`, say — turns redis-rs's TLS on.)

use std::fmt;
use std::time::Duration;

use ::redis::aio::MultiplexedConnection;
use ::redis::AsyncConnectionConfig;

use crate::redact::{redact_password, UrlShape};

/// The env var [`require_redis`] checks before falling back to its
/// `default_url` argument.
const REDIS_URL_VAR: &str = "REDIS_URL";

/// What a URL must look like to be rendered (password masked) in a panic
/// message or `Debug`: a TCP Redis URL with a host. Anything else — a
/// Unix-socket URL included — is shown as a placeholder.
const REDIS_URL_SHAPE: UrlShape = UrlShape {
    env_var: REDIS_URL_VAR,
    schemes: &["redis", "rediss", "valkey", "valkeys"],
};

/// How long the probe waits — for the connection, then for `PING` — before it
/// gives up. Short on purpose, as `require_postgres`'s is: a local or CI
/// Redis that is up answers in milliseconds.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// The Redis server [`require_redis`] reached.
///
/// `Debug` shows the URL with its password redacted.
#[derive(Clone)]
pub struct RedisServer {
    url: String,
    connection: MultiplexedConnection,
}

impl RedisServer {
    /// The URL that answered — `REDIS_URL` if it was set, otherwise the
    /// default the test passed. Build the code under test from this, so it
    /// talks to the same server the probe did.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// A connection to the server that is independent of the code under
    /// test: for setting up keys, or reading back what that code wrote
    /// (`TTL`, `GET`, …). Cheap to call — a clone of one multiplexed
    /// connection. It belongs to the Tokio runtime [`require_redis`] ran on.
    pub fn connection(&self) -> MultiplexedConnection {
        self.connection.clone()
    }
}

impl fmt::Debug for RedisServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisServer")
            .field("url", &redact_password(&self.url, &REDIS_URL_SHAPE))
            .finish_non_exhaustive()
    }
}

/// Which database number a test Redis URL may select, for
/// [`require_local_redis_url`].
///
/// Allowing database 0 is the default: a suite that isolates itself by key
/// prefix (slaudio's does) can share it with a dev stack safely.
/// [`RedisDbPolicy::RefuseZero`] is for a suite that seeds state the code
/// under test reads back by fixed key shape (a full rate-limit window, a
/// spent budget): in database 0, which a running dev stack counts into, that
/// would refuse a developer's real requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedisDbPolicy {
    /// Any database, 0 included.
    #[default]
    AllowZero,
    /// Database 0 is refused, whether the URL selects it explicitly
    /// (`/0`) or by naming no database at all.
    RefuseZero,
}

/// The Redis URL in `var`, which must be set, name a server on this machine
/// ([`require_local_url`](crate::require_local_url)'s rule), be one redis-rs
/// can open, and select a database `policy` allows; or a panic saying what
/// to fix. No connection is made: build the code under test from the URL,
/// and probe it however the suite does.
///
/// The database is the one redis-rs itself parses out of the URL, whatever
/// form selects it.
///
/// # Panics
///
/// On every refusal of [`require_local_url`](crate::require_local_url), on a
/// URL redis-rs refuses (a `rediss://` URL needs a redis-rs TLS feature this
/// crate does not turn on), and under [`RedisDbPolicy::RefuseZero`] on a URL
/// that selects database 0. The message never shows the value.
///
/// ```no_run
/// use stridelabs_testing::{require_local_redis_url, RedisDbPolicy};
///
/// // e.g. `export MYAPP_TEST_REDIS_URL=redis://localhost:6379/1`
/// let url = require_local_redis_url("MYAPP_TEST_REDIS_URL", RedisDbPolicy::RefuseZero);
/// # let _ = url;
/// ```
pub fn require_local_redis_url(var: &str, policy: RedisDbPolicy) -> String {
    require_local_redis_url_from(var, policy, |name| std::env::var(name).ok())
}

/// [`require_local_redis_url`], whose refusals that suggest a URL suggest the
/// consumer's own `example_url` (`redis://localhost:56379/1`, the port and
/// database its compose file and Makefile use) instead of a fixed
/// `redis://localhost:6379/1`.
///
/// The rule is exactly [`require_local_redis_url`]'s. Two messages carry the
/// example: for an unset or empty `var`, ``<var> is not set. Set it to a local
/// Redis URL such as `<example_url>`.``; and, under
/// [`RedisDbPolicy::RefuseZero`], the refusal of database 0. `example_url` is
/// printed verbatim, so keep it free of secrets; it is not checked against
/// the rule (a wrong example only misleads the reader).
///
/// # Panics
///
/// As [`require_local_redis_url`].
///
/// ```no_run
/// use stridelabs_testing::{require_local_redis_url_with_example, RedisDbPolicy};
///
/// let url = require_local_redis_url_with_example(
///     "MYAPP_TEST_REDIS_URL",
///     RedisDbPolicy::RefuseZero,
///     "redis://localhost:56379/1",
/// );
/// # let _ = url;
/// ```
pub fn require_local_redis_url_with_example(
    var: &str,
    policy: RedisDbPolicy,
    example_url: &str,
) -> String {
    require_local_redis_url_with_example_from(var, policy, example_url, |name| {
        std::env::var(name).ok()
    })
}

/// The example [`require_local_redis_url`] has always suggested.
const DEFAULT_EXAMPLE_URL: &str = "redis://localhost:6379/1";

/// The env-injectable seam behind [`require_local_redis_url`].
fn require_local_redis_url_from(
    var: &str,
    policy: RedisDbPolicy,
    get: impl Fn(&str) -> Option<String>,
) -> String {
    checked_local_redis_url(var, get(var).as_deref(), policy)
        .unwrap_or_else(|refusal| panic!("{refusal}"))
}

/// The env-injectable seam behind [`require_local_redis_url_with_example`].
fn require_local_redis_url_with_example_from(
    var: &str,
    policy: RedisDbPolicy,
    example_url: &str,
    get: impl Fn(&str) -> Option<String>,
) -> String {
    checked_local_redis_url_with_example(var, get(var).as_deref(), policy, example_url)
        .unwrap_or_else(|refusal| panic!("{refusal}"))
}

fn checked_local_redis_url(
    var: &str,
    value: Option<&str>,
    policy: RedisDbPolicy,
) -> Result<String, String> {
    checked_redis_url(var, value, policy, DEFAULT_EXAMPLE_URL, None)
}

fn checked_local_redis_url_with_example(
    var: &str,
    value: Option<&str>,
    policy: RedisDbPolicy,
    example_url: &str,
) -> Result<String, String> {
    let hint = format!("Set it to a local Redis URL such as `{example_url}`.");
    checked_redis_url(var, value, policy, example_url, Some(&hint))
}

fn checked_redis_url(
    var: &str,
    value: Option<&str>,
    policy: RedisDbPolicy,
    example_url: &str,
    unset_hint: Option<&str>,
) -> Result<String, String> {
    let url = crate::local::checked_local_url_hinted(var, value, unset_hint)?;
    let Ok(client) = ::redis::Client::open(url.as_str()) else {
        return Err(crate::local::refusal(
            var,
            "is not a Redis URL this build of redis-rs can open",
        ));
    };
    if policy == RedisDbPolicy::RefuseZero
        && client.get_connection_info().redis_settings().db() == 0
    {
        return Err(crate::local::refusal(
            var,
            &format!(
                "selects database 0, explicitly or by naming no database; this suite must \
                 never share the database a running dev stack counts into, so select another \
                 (`{example_url}`)"
            ),
        ));
    }
    Ok(url)
}

/// Connect to Redis for a test, or panic with an actionable message.
///
/// Reads `REDIS_URL` from the environment; if it is unset (or empty),
/// connects to `default_url` instead — pass your compose or CI server's URL
/// there. The server must answer `PING`.
///
/// # Panics
///
/// If no connection is established, or `PING` is not answered, within 2
/// seconds each, this panics with a message naming:
///
/// - the URL it tried, with the password replaced by `***`,
/// - what failed, by redis-rs's error kind and, for an I/O failure, its
///   class (`Io (connection refused)`), never redis-rs's message, which can
///   quote the credentials the handshake sent,
/// - the `REDIS_URL` env var, so a misconfigured environment is obvious,
/// - the command to start the local server (`docker compose up -d redis`, or
///   `make up` in a repo with that Makefile target).
///
/// It never returns `None` or skips silently — see the module docs for why.
pub async fn require_redis(default_url: &str) -> RedisServer {
    require_redis_from(default_url, |var| std::env::var(var).ok()).await
}

/// The env-injectable seam behind [`require_redis`], so unit tests can
/// exercise its precedence without mutating the real process environment
/// (`std::env::set_var` in a test races every other test in the binary — the
/// workspace convention, see `stridelabs-config`).
async fn require_redis_from(
    default_url: &str,
    get: impl Fn(&str) -> Option<String>,
) -> RedisServer {
    require_redis_at(&resolve_url(default_url, get)).await
}

/// `REDIS_URL` when set and non-empty, else `default_url`. Empty counts as
/// unset, as it does for `stridelabs-config`'s `env_or`: that is how a
/// variable someone left unfilled arrives from compose or CI.
fn resolve_url(default_url: &str, get: impl Fn(&str) -> Option<String>) -> String {
    get(REDIS_URL_VAR)
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| default_url.to_string())
}

/// The env-free seam: probe exactly `url`.
async fn require_redis_at(url: &str) -> RedisServer {
    match connect(url).await {
        Ok(connection) => RedisServer {
            url: url.to_string(),
            connection,
        },
        Err(err) => panic!("{}", connection_failure_message(url, &err)),
    }
}

async fn connect(url: &str) -> ::redis::RedisResult<MultiplexedConnection> {
    let client = ::redis::Client::open(url)?;
    let config = AsyncConnectionConfig::new()
        .set_connection_timeout(Some(CONNECT_TIMEOUT))
        .set_response_timeout(Some(CONNECT_TIMEOUT));
    let mut connection = client
        .get_multiplexed_async_connection_with_config(&config)
        .await?;
    ::redis::cmd("PING")
        .query_async::<()>(&mut connection)
        .await?;
    Ok(connection)
}

fn connection_failure_message(url: &str, err: &::redis::RedisError) -> String {
    format!(
        "\n\
        could not connect to Redis at {redacted}\n\
        \n\
        error: {summary} (redis-rs's message is withheld: it can quote the \
        credentials the handshake sent)\n\
        \n\
        stridelabs-testing::require_redis never skips a test for a missing \
        Redis — fix the connection instead of ignoring this panic:\n\
        \n\
        - start the local Redis: `docker compose up -d redis` (or `make up`)\n\
        - or point {var} at a Redis server that is actually reachable\n",
        redacted = redact_password(url, &REDIS_URL_SHAPE),
        summary = failure_summary(err),
        var = REDIS_URL_VAR,
    )
}

/// What failed, from the error's kind alone and never its text: a Redis
/// older than 6 answers `HELLO 3 AUTH <user> <password>` with an error that
/// quotes those arguments, and redis-rs passes that text on. The server is
/// the redacted URL the message already names. `ErrorKind`'s `Debug` is a
/// variant name.
fn failure_summary(err: &::redis::RedisError) -> String {
    let class = if err.is_timeout() {
        "timed out"
    } else if err.is_connection_refusal() {
        "connection refused"
    } else if err.is_connection_dropped() {
        "the connection was closed or reset"
    } else {
        return format!("{:?}", err.kind());
    };
    format!("{:?} ({class})", err.kind())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lookup;

    /// The URL `docker-compose.yml`'s `redis` service serves (host port
    /// 6390, no password). CI exports the same string as `REDIS_URL`, so the
    /// happy path below goes through the public, env-reading entry point.
    const COMPOSE_URL: &str = "redis://localhost:6390/0";

    #[tokio::test]
    async fn require_redis_connects_to_the_compose_redis() {
        let server = require_redis(COMPOSE_URL).await;

        let pong: String = ::redis::cmd("PING")
            .query_async(&mut server.connection())
            .await
            .expect("PING the compose Redis");
        assert_eq!(pong, "PONG");

        // The URL it hands back is the one that answered: dialling it again
        // reaches the same server.
        let again = require_redis_at(server.url()).await;
        let _: () = ::redis::cmd("PING")
            .query_async(&mut again.connection())
            .await
            .expect("PING through the returned URL");
    }

    #[test]
    fn redis_url_takes_precedence_over_the_default() {
        let url = resolve_url(
            COMPOSE_URL,
            lookup(&[("REDIS_URL", "redis://ci-redis:6379/2")]),
        );
        assert_eq!(url, "redis://ci-redis:6379/2");
    }

    #[test]
    fn an_unset_or_empty_redis_url_falls_back_to_the_default() {
        assert_eq!(resolve_url(COMPOSE_URL, lookup(&[])), COMPOSE_URL);
        assert_eq!(
            resolve_url(COMPOSE_URL, lookup(&[("REDIS_URL", "")])),
            COMPOSE_URL
        );
    }

    /// The seam is wired to the lookup it is handed: a fake `REDIS_URL`
    /// pointing at a dead port wins over a default that would answer.
    #[tokio::test]
    #[should_panic(expected = "could not connect to Redis at redis://127.0.0.1:1/0")]
    async fn the_lookup_seam_decides_which_url_is_probed() {
        let _ = require_redis_from(
            COMPOSE_URL,
            lookup(&[("REDIS_URL", "redis://127.0.0.1:1/0")]),
        )
        .await;
    }

    #[tokio::test]
    #[should_panic(expected = "could not connect to Redis")]
    async fn an_unreachable_redis_panics_with_an_actionable_message() {
        // Port 1 on loopback: nothing listens, and the attempt fails fast.
        let _ = require_redis_at("redis://:hunter2@127.0.0.1:1/0").await;
    }

    #[tokio::test]
    #[should_panic(expected = "<a REDIS_URL that is not a well-formed URL (not shown)>")]
    async fn a_malformed_url_panics_without_echoing_it() {
        let _ = require_redis_at("not a redis url").await;
    }

    #[test]
    fn the_panic_message_names_the_env_var_and_the_command_and_no_password() {
        let err =
            ::redis::RedisError::from(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        let message = connection_failure_message("redis://:hunter2@127.0.0.1:1/0", &err);

        assert!(!message.contains("hunter2"), "{message}");
        assert!(message.contains("redis://:***@127.0.0.1:1/0"), "{message}");
        assert!(
            message.contains("error: Io (connection refused)"),
            "{message}"
        );
        assert!(message.contains("REDIS_URL"), "{message}");
        assert!(message.contains("docker compose up -d redis"), "{message}");
        assert!(message.contains("make up"), "{message}");
    }

    /// The live panic payload of a real failed connection, not a simulated
    /// error, so a change that bypassed `connection_failure_message` would
    /// still be caught.
    fn panic_message_for(url: &str) -> String {
        let result = std::panic::catch_unwind(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build a runtime for this sync test");
            rt.block_on(require_redis_at(url))
        });
        let payload = result.expect_err("the probe must fail");
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "<non-string panic payload>".to_string())
    }

    /// What a Redis older than 6 answers a `HELLO` with: an error that
    /// quotes the command's arguments, credentials included. redis-rs
    /// recognises only the newer, backquoted form of it, and passes this one
    /// on as the server's error, text and all.
    const PRE_HELLO_REPLY: &[u8] = b"-ERR unknown command 'HELLO', with args beginning with: \
                                     '3' 'AUTH' 'default' 'hunter2' \r\n";

    /// A server on loopback that answers the first thing it is sent (the
    /// handshake pipeline: `HELLO` and two ignored `CLIENT SETINFO`s) with
    /// [`PRE_HELLO_REPLY`] and two `+OK`s, then holds the connection until
    /// the client drops it. Its `host:port`.
    fn pre_hello_redis() -> String {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a fake Redis");
        let address = listener.local_addr().expect("fake Redis address");
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 4096];
            if !matches!(stream.read(&mut buf), Ok(n) if n > 0) {
                return;
            }
            let mut reply = PRE_HELLO_REPLY.to_vec();
            reply.extend_from_slice(b"+OK\r\n+OK\r\n");
            if stream.write_all(&reply).is_err() {
                return;
            }
            while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
        });
        address.to_string()
    }

    /// The kind, and an I/O failure's class, whatever text the error holds.
    #[test]
    fn the_summary_is_the_kind_and_the_io_class_never_the_text() {
        use std::io;

        let io_error =
            |kind: io::ErrorKind| ::redis::RedisError::from(io::Error::new(kind, "hunter2"));
        let server_error = ::redis::parse_redis_value(PRE_HELLO_REPLY)
            .expect("well-formed RESP")
            .extract_error()
            .expect_err("an error reply");
        let cases = [
            (
                io_error(io::ErrorKind::ConnectionRefused),
                "Io (connection refused)",
            ),
            (io_error(io::ErrorKind::TimedOut), "Io (timed out)"),
            (
                io_error(io::ErrorKind::ConnectionReset),
                "Io (the connection was closed or reset)",
            ),
            (io_error(io::ErrorKind::Other), "Io"),
            (server_error, "Server(ResponseError)"),
        ];
        for (error, expected) in cases {
            assert!(error.to_string().contains("hunter2"), "the raw text has it");
            assert_eq!(failure_summary(&error), expected);
        }
    }

    /// The panic names what failed by its kind, never by redis-rs's text:
    /// a refused RESP3 handshake whose error reply quotes the password must
    /// not put it in the panic, and the URL it tried stays redacted.
    #[test]
    fn a_handshake_error_quoting_the_password_is_summarized_not_echoed() {
        let address = pre_hello_redis();
        let message = panic_message_for(&format!(
            "redis://default:hunter2@{address}/0?protocol=resp3"
        ));

        assert!(!message.contains("hunter2"), "{message}");
        assert!(!message.contains("unknown command"), "{message}");
        assert!(
            message.contains(&format!(
                "could not connect to Redis at redis://default:***@{address}/0"
            )),
            "{message}"
        );
        assert!(
            message.contains("error: Server(ResponseError)"),
            "{message}"
        );
    }

    #[test]
    fn an_unreachable_redis_panic_carries_no_password_end_to_end() {
        let message = panic_message_for("redis://:hunter2@127.0.0.1:1/0");
        assert!(!message.contains("hunter2"), "{message}");
        assert!(message.contains("could not connect to Redis"), "{message}");
    }

    /// A typo'd URL that still parses — one slash short, so the credentials
    /// land in a generic URL's PATH, where no userinfo mask looks — is not
    /// echoed into the panic.
    #[test]
    fn a_malformed_url_with_credentials_in_its_path_is_not_echoed() {
        for url in [
            "rediss:/default:hunter2@example.upstash.io:6379",
            "redis:default:hunter2@localhost:6390",
            "redis:///:hunter2@localhost:6390",
        ] {
            let message = panic_message_for(url);
            assert!(!message.contains("hunter2"), "{url}: {message}");
            assert!(
                message.contains("<a REDIS_URL that is not a well-formed URL (not shown)>"),
                "{url}: {message}"
            );
        }
    }

    const VAR: &str = "STRIDELABS_TESTING_REDIS_URL";

    /// `RefuseZero` refuses database 0 in every form redis-rs reads as 0
    /// (explicit, or no database named); a non-zero database passes it, and
    /// the default policy allows 0 (slaudio's prefix-isolated suites).
    #[test]
    fn refuse_zero_refuses_database_zero_in_every_form() {
        for url in [
            "redis://localhost:6390/0",
            "redis://localhost:6390",
            "redis://localhost:6390/",
            "redis://:hunter2@127.0.0.1:6390/0",
        ] {
            let message =
                checked_local_redis_url(VAR, Some(url), RedisDbPolicy::RefuseZero).expect_err(url);
            assert!(
                message.contains(&format!("{VAR} selects database 0")),
                "{url}: {message}"
            );
            assert!(!message.contains("hunter2"), "{url}: {message}");
            assert_eq!(
                checked_local_redis_url(VAR, Some(url), RedisDbPolicy::default()).as_deref(),
                Ok(url),
                "the default allows database 0"
            );
        }
        for url in ["redis://localhost:6390/1", "redis://:hunter2@[::1]:6390/15"] {
            assert_eq!(
                checked_local_redis_url(VAR, Some(url), RedisDbPolicy::RefuseZero).as_deref(),
                Ok(url)
            );
        }
        assert_eq!(RedisDbPolicy::default(), RedisDbPolicy::AllowZero);
    }

    /// The local rule comes first (a remote server is refused whatever its
    /// database), and a URL redis-rs cannot open is refused without being
    /// shown.
    #[test]
    fn a_remote_or_unopenable_url_is_refused_before_the_database_is_read() {
        for (url, problem) in [
            (
                "redis://:hunter2@cache.example.com:6379/1",
                "names a host that is not loopback",
            ),
            // (Not `rediss://`: whether redis-rs opens one depends on a TLS
            // feature some other crate in the build may turn on.)
            (
                "http://hunter2@localhost:6390/1",
                "is not a Redis URL this build of redis-rs can open",
            ),
        ] {
            for policy in [RedisDbPolicy::AllowZero, RedisDbPolicy::RefuseZero] {
                let message = checked_local_redis_url(VAR, Some(url), policy).expect_err(url);
                assert!(
                    message.contains(&format!("{VAR} {problem}")),
                    "{url}: {message}"
                );
                assert!(!message.contains("hunter2"), "{url}: {message}");
            }
        }
    }

    #[test]
    #[should_panic(expected = "STRIDELABS_TESTING_REDIS_URL selects database 0")]
    fn require_local_redis_url_panics_with_the_refusal() {
        let _ = require_local_redis_url_from(
            VAR,
            RedisDbPolicy::RefuseZero,
            lookup(&[(VAR, "redis://localhost:6390")]),
        );
    }

    const EXAMPLE: &str = "redis://localhost:56379/1";

    /// The tail every refusal carries (see `local`'s tests), for the redis
    /// variable.
    const TAIL: &str =
        "stridelabs-testing never skips a test for a missing server, and never lets a \
        suite write to a server on another machine: set STRIDELABS_TESTING_REDIS_URL to a URL \
        whose host is this machine (`localhost`, `127.0.0.1` or `::1`), such as the server \
        `docker compose up -d` starts. The value is not shown: a URL can carry a password.\n";

    /// The existing function's two example-bearing refusals are byte-for-byte
    /// what they were: the unset one carries none, the database-0 one the
    /// fixed `6379` example.
    #[test]
    fn the_default_example_refusals_are_byte_unchanged() {
        assert_eq!(
            checked_local_redis_url(VAR, None, RedisDbPolicy::RefuseZero),
            Err(format!(
                "\nSTRIDELABS_TESTING_REDIS_URL is not set.\n\n{TAIL}"
            ))
        );
        assert_eq!(
            checked_local_redis_url(
                VAR,
                Some("redis://localhost:6390/0"),
                RedisDbPolicy::RefuseZero
            ),
            Err(format!(
                "\nSTRIDELABS_TESTING_REDIS_URL selects database 0, explicitly or by naming no \
                 database; this suite must never share the database a running dev stack counts \
                 into, so select another (`redis://localhost:6379/1`).\n\n{TAIL}"
            ))
        );
    }

    /// The variant's unset refusal suggests the consumer's own example, in
    /// place of no example at all.
    #[test]
    fn the_unset_refusal_suggests_the_consumers_example() {
        for value in [None, Some("")] {
            for policy in [RedisDbPolicy::AllowZero, RedisDbPolicy::RefuseZero] {
                assert_eq!(
                    checked_local_redis_url_with_example(VAR, value, policy, EXAMPLE),
                    Err(format!(
                        "\nSTRIDELABS_TESTING_REDIS_URL is not set. Set it to a local Redis URL \
                         such as `redis://localhost:56379/1`.\n\n{TAIL}"
                    ))
                );
            }
        }
    }

    /// The database-0 refusal names the consumer's example, not `6379`.
    #[test]
    fn the_database_zero_refusal_suggests_the_consumers_example() {
        let message = checked_local_redis_url_with_example(
            VAR,
            Some("redis://localhost:6390/0"),
            RedisDbPolicy::RefuseZero,
            EXAMPLE,
        )
        .expect_err("database 0");
        assert_eq!(
            message,
            format!(
                "\nSTRIDELABS_TESTING_REDIS_URL selects database 0, explicitly or by naming no \
                 database; this suite must never share the database a running dev stack counts \
                 into, so select another (`redis://localhost:56379/1`).\n\n{TAIL}"
            )
        );
        assert!(
            !message.contains("6379/1`") || message.contains("56379/1`"),
            "{message}"
        );
        assert!(!message.contains("redis://localhost:6379"), "{message}");
    }

    /// Every refusal but the two that carry the example is the existing
    /// function's, whatever example is given, and the default example makes
    /// the variant the existing function outright.
    #[test]
    fn the_example_changes_no_other_outcome() {
        for url in [
            "redis://:hunter2@cache.example.com:6379/1",
            "http://hunter2@localhost:6390/1",
            "redis://localhost:6390/1",
        ] {
            for policy in [RedisDbPolicy::AllowZero, RedisDbPolicy::RefuseZero] {
                let plain = checked_local_redis_url(VAR, Some(url), policy);
                for example in [EXAMPLE, DEFAULT_EXAMPLE_URL] {
                    assert_eq!(
                        checked_local_redis_url_with_example(VAR, Some(url), policy, example),
                        plain,
                        "{url}"
                    );
                }
            }
        }
        assert_eq!(
            checked_local_redis_url_with_example(
                VAR,
                Some("redis://localhost:6390/0"),
                RedisDbPolicy::RefuseZero,
                DEFAULT_EXAMPLE_URL
            ),
            checked_local_redis_url(
                VAR,
                Some("redis://localhost:6390/0"),
                RedisDbPolicy::RefuseZero
            )
        );
    }

    /// The public variant panics with the consumer's example, and returns a
    /// good URL as given.
    #[test]
    #[should_panic(expected = "(`redis://localhost:56379/1`)")]
    fn require_local_redis_url_with_example_panics_with_the_example() {
        let _ = require_local_redis_url_with_example_from(
            VAR,
            RedisDbPolicy::RefuseZero,
            EXAMPLE,
            lookup(&[(VAR, "redis://localhost:6390")]),
        );
    }

    #[test]
    fn require_local_redis_url_with_example_returns_a_good_url() {
        assert_eq!(
            require_local_redis_url_with_example_from(
                VAR,
                RedisDbPolicy::RefuseZero,
                EXAMPLE,
                lookup(&[(VAR, "redis://localhost:6390/2")]),
            ),
            "redis://localhost:6390/2"
        );
    }

    #[tokio::test]
    async fn debug_redacts_the_password() {
        let reachable = require_redis(COMPOSE_URL).await;
        let server = RedisServer {
            url: "redis://default:hunter2@localhost:6390/0".to_string(),
            connection: reachable.connection(),
        };

        let rendered = format!("{server:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(
            rendered.contains("redis://default:***@localhost:6390/0"),
            "{rendered}"
        );
    }
}
