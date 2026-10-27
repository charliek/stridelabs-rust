//! The test Redis, for both live suites (`tests/budget.rs`, `tests/lease.rs`):
//! tapper's `tests/test_redis/` (`82be95f`) on this workspace's wiring.
//!
//! Lives at `tests/test_redis/mod.rs`, not `tests/test_redis.rs`, so it is a
//! module of each binary that declares it and never a test binary of its own
//! (`tests/redis_fault/mod.rs` says the same).
//!
//! **Required, never skipped.** stridelabs-testing's `require_redis`, with the
//! compose Redis as the default and `REDIS_URL` overriding it, as
//! stridelabs-redis's live suite does: no server is a failure with
//! instructions. That Redis is the workspace's own (compose's, or CI's
//! service), shared with every other live suite and with no running app, so
//! isolation is by PREFIX: each test counts under prefixes of its own
//! ([`tts_prefix`], [`stream_prefix`]), deletes its keys when it is done, and
//! every "nothing else was written" check scans its own prefix only.
//!
//! Every key a test seeds itself (outside the code under test) is given
//! [`SEEDED_KEY_TTL_SECS`] as it is created, so a test that panics before its
//! cleanup leaves nothing behind for long.

use std::sync::OnceLock;

use redis::AsyncCommands as _;
use stridelabs_redis::RedisHandle;
use stridelabs_testing::require_redis;
use uuid::Uuid;

/// `docker-compose.yml`'s `redis` service. CI sets `REDIS_URL` to the same.
pub const COMPOSE_URL: &str = "redis://localhost:6390/0";

/// The TTL every key a test seeds gets as it is created: far past any test's
/// run, short enough that a panic before the cleanup costs nothing.
pub const SEEDED_KEY_TTL_SECS: u64 = 120;

/// The URL that answered the probe, once this binary has probed.
static PROBED_URL: OnceLock<String> = OnceLock::new();

/// The test Redis's URL: `REDIS_URL`, else [`COMPOSE_URL`], probed by
/// `require_redis` (a panic with instructions when it does not answer) the
/// first time a test of this binary asks. Probed once, not per call: every
/// helper below opens a connection of its own, and a probe per call doubled
/// a run's connections (a suite run churns through local ports).
pub async fn test_redis_url() -> String {
    if let Some(url) = PROBED_URL.get() {
        return url.clone();
    }
    let url = require_redis(COMPOSE_URL).await.url().to_string();
    PROBED_URL.get_or_init(|| url).clone()
}

/// A stridelabs-redis handle on the test Redis: the code under test's.
pub async fn test_handle() -> RedisHandle {
    RedisHandle::open(&test_redis_url().await).expect("the test URL parses")
}

/// A direct connection to the test Redis, for seeding and reading back —
/// never the code under test. (A connection belongs to the runtime it was
/// opened on, and each test has its own, so one is opened per call.)
pub async fn raw_redis() -> redis::aio::MultiplexedConnection {
    redis::Client::open(test_redis_url().await.as_str())
        .expect("the probed URL opens")
        .get_multiplexed_async_connection()
        .await
        // The kind only: redis-rs's message can quote the handshake's
        // credentials (stridelabs-testing's probe withholds it too).
        .unwrap_or_else(|failure| panic!("connect to the test Redis: {:?}", failure.kind()))
}

/// A text budget prefix no other test (and no other suite) shares.
pub fn tts_prefix() -> String {
    format!("stridelabs-voice-test:{}:tts", Uuid::new_v4())
}

/// A stream budget prefix no other test (and no other suite) shares.
pub fn stream_prefix() -> String {
    format!("stridelabs-voice-test:{}:stream", Uuid::new_v4())
}

/// `SET key value EX` [`SEEDED_KEY_TTL_SECS`]: a seeded value that cleans
/// itself up.
pub async fn seed<V>(redis: &mut redis::aio::MultiplexedConnection, key: &str, value: V)
where
    V: redis::ToSingleRedisArg + redis::ToRedisArgs + Send + Sync,
{
    let () = redis
        .set_ex(key, value, SEEDED_KEY_TTL_SECS)
        .await
        .expect("SET … EX");
}

/// `EXPIRE key` [`SEEDED_KEY_TTL_SECS`], for a key a test just created some
/// other way (a hash, a list).
pub async fn expire_soon(redis: &mut redis::aio::MultiplexedConnection, key: &str) {
    let set: bool = redis
        .expire(key, i64::try_from(SEEDED_KEY_TTL_SECS).expect("small"))
        .await
        .expect("EXPIRE");
    assert!(set, "the seeded key exists");
}

/// Delete every key matching `pattern` (a `KEYS` glob): a test's cleanup.
pub async fn drop_keys(pattern: &str) {
    let mut redis = raw_redis().await;
    let keys: Vec<String> = redis.keys(pattern).await.expect("KEYS");
    if !keys.is_empty() {
        let _: i64 = redis.del(keys).await.expect("DEL");
    }
}

/// Delete every key under `prefix` (`<prefix>:*`): a test's own prefix.
pub async fn drop_keys_under(prefix: &str) {
    drop_keys(&format!("{prefix}:*")).await;
}

/// Deletes every key under a test's prefix when it is dropped — on a panic
/// too. For a test that leaves keys with NO expiry (a fence hash whose
/// `EXPIRE` was denied, an older script's counter) or a long one (a fixed
/// clock's month), which an assertion failing before the test's own cleanup
/// would otherwise leave behind for good. Create it before that state.
pub struct KeysUnder {
    pattern: String,
    /// The test Redis's own URL (the default user's), to delete them with.
    admin_url: String,
}

impl KeysUnder {
    /// A guard over `<prefix>:*`.
    pub async fn guard(prefix: &str) -> KeysUnder {
        KeysUnder {
            pattern: format!("{prefix}:*"),
            admin_url: test_redis_url().await,
        }
    }
}

impl Drop for KeysUnder {
    fn drop(&mut self) {
        let deleted = redis::Client::open(self.admin_url.as_str())
            .and_then(|client| client.get_connection())
            .and_then(|mut connection| {
                let keys: Vec<String> = redis::cmd("KEYS")
                    .arg(&self.pattern)
                    .query(&mut connection)?;
                if keys.is_empty() {
                    return Ok(());
                }
                redis::cmd("DEL").arg(keys).query::<i64>(&mut connection)?;
                Ok(())
            });
        if let Err(failure) = deleted {
            eprintln!(
                "could not delete the test keys {}: {:?}",
                self.pattern,
                failure.kind()
            );
        }
    }
}

/// Every key under `prefix` (`<prefix>:*`), sorted: what a test wrote under
/// a prefix of its own, ALL of it.
pub async fn keys_under(prefix: &str) -> Vec<String> {
    let mut keys: Vec<String> = raw_redis()
        .await
        .keys(format!("{prefix}:*"))
        .await
        .expect("KEYS");
    keys.sort();
    keys
}

/// `url` with `user` and `password` as its credentials (the database kept).
pub fn with_credentials(url: &str, user: &str, password: &str) -> String {
    let mut parsed = redis::parse_redis_url(url).expect("the test Redis URL is a URL");
    parsed.set_username(user).expect("a user");
    parsed.set_password(Some(password)).expect("a password");
    parsed.into()
}

/// What one key holds, for the "nothing changed" checks: its type, its
/// value (a string's; a list's items joined by `,`; a hash's `field=value`
/// pairs, sorted, joined by `,`; `None` for anything else or an absent key)
/// and its PTTL (`-2` absent, `-1` no expiry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyState {
    pub kind: String,
    pub value: Option<String>,
    pub pttl: i64,
}

/// `key`'s [`KeyState`].
pub async fn key_state(redis: &mut redis::aio::MultiplexedConnection, key: &str) -> KeyState {
    let kind: String = redis::cmd("TYPE")
        .arg(key)
        .query_async(redis)
        .await
        .expect("TYPE");
    let value = match kind.as_str() {
        "string" => redis.get(key).await.expect("GET"),
        "list" => {
            let items: Vec<String> = redis.lrange(key, 0, -1).await.expect("LRANGE");
            Some(items.join(","))
        }
        // A hash (the stream's fence): its fields, sorted.
        "hash" => {
            let mut fields: Vec<(String, String)> = redis.hgetall(key).await.expect("HGETALL");
            fields.sort();
            Some(
                fields
                    .into_iter()
                    .map(|(field, value)| format!("{field}={value}"))
                    .collect::<Vec<_>>()
                    .join(","),
            )
        }
        _ => None,
    };
    let pttl: i64 = redis.pttl(key).await.expect("PTTL");
    KeyState { kind, value, pttl }
}

/// Every key's [`KeyState`], in order.
pub async fn key_states(keys: &[String]) -> Vec<KeyState> {
    let mut redis = raw_redis().await;
    let mut states = Vec::with_capacity(keys.len());
    for key in keys {
        states.push(key_state(&mut redis, key).await);
    }
    states
}

/// `after` is `before` with nothing written: every type and value the same,
/// and every TTL the same or LOWER by no more than the time that passed
/// (`slack_ms`) — an expiry a script refreshed would have gone UP.
pub fn assert_unchanged(keys: &[String], before: &[KeyState], after: &[KeyState], slack_ms: i64) {
    for ((key, before), after) in keys.iter().zip(before).zip(after) {
        assert_eq!(
            (&after.kind, &after.value),
            (&before.kind, &before.value),
            "{key} was written"
        );
        if before.pttl < 0 {
            assert_eq!(after.pttl, before.pttl, "{key}'s expiry changed");
        } else {
            assert!(
                after.pttl <= before.pttl && after.pttl >= before.pttl - slack_ms,
                "{key}'s expiry moved: {} ms, then {} ms",
                before.pttl,
                after.pttl
            );
        }
    }
}

/// `pttl` is `seconds` as set a moment ago.
pub fn assert_fresh_ttl(pttl: i64, seconds: i64, what: &str) {
    assert!(
        (seconds * 1_000 - 2_000..=seconds * 1_000).contains(&pttl),
        "{what}: PTTL {pttl} ms, expected about {seconds} s"
    );
}

/// A Redis ACL user a test made, deleted again when it is dropped (on a
/// panic too). Users are server-wide, so each is `voice-test-<uuid>`, may
/// touch only keys under the test's own prefix, and is never the default
/// user.
pub struct AclUser {
    pub name: String,
    pub url: String,
    /// The test Redis's own URL (the default user's), to delete the user with.
    admin_url: String,
}

impl AclUser {
    /// `ACL SETUSER voice-test-<uuid> reset on ><password> ~<prefix>:* -@all
    /// +ping +select +client|setinfo <rules…>`: no command but the
    /// connection's own and those `rules` grant, on no key outside `prefix`.
    /// Its URL is the test Redis's, database included, with these
    /// credentials.
    pub async fn create(prefix: &str, rules: &[&str]) -> AclUser {
        let name = format!("voice-test-{}", Uuid::new_v4());
        let password = Uuid::new_v4().simple().to_string();
        let mut setuser = redis::cmd("ACL");
        setuser
            .arg("SETUSER")
            .arg(&name)
            .arg("reset")
            .arg("on")
            .arg(format!(">{password}"))
            .arg(format!("~{prefix}:*"))
            .arg("-@all")
            .arg("+ping")
            .arg("+select")
            .arg("+client|setinfo");
        for rule in rules {
            setuser.arg(*rule);
        }
        let admin_url = test_redis_url().await;
        let user = AclUser {
            url: with_credentials(&admin_url, &name, &password),
            name,
            admin_url,
        };
        let () = setuser
            .query_async(&mut raw_redis().await)
            .await
            .expect("ACL SETUSER (the test Redis's default user may manage ACLs)");
        user
    }

    /// A stridelabs-redis handle that authenticates as this user.
    pub fn handle(&self) -> RedisHandle {
        RedisHandle::open(&self.url).expect("the ACL user's URL opens")
    }
}

impl Drop for AclUser {
    fn drop(&mut self) {
        let deleted = redis::Client::open(self.admin_url.as_str())
            .and_then(|client| client.get_connection())
            .and_then(|mut connection| {
                redis::cmd("ACL")
                    .arg("DELUSER")
                    .arg(&self.name)
                    .query::<i64>(&mut connection)
            });
        if let Err(failure) = deleted {
            eprintln!(
                "could not delete the test ACL user {}: {failure}",
                self.name
            );
        }
    }
}
