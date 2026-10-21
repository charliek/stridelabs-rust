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
    use std::collections::HashMap;

    use super::*;

    /// The URL `docker-compose.yml`'s `redis` service serves (host port
    /// 6390, no password). CI exports the same string as `REDIS_URL`, so the
    /// happy path below goes through the public, env-reading entry point.
    const COMPOSE_URL: &str = "redis://localhost:6390/0";

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: HashMap<&str, &str> = pairs.iter().copied().collect();
        move |key| map.get(key).map(|value| value.to_string())
    }

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
