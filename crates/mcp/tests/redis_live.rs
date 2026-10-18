//! `RedisRateLimiter` and `RedisPatCache` against a real Redis (feature
//! `live-tests`; CI's all-features lane). `require_redis` panics when there
//! is no server — `docker compose up -d redis` — so this suite never passes
//! by skipping.
//!
//! Every test works under a key prefix of its own, and pins the limiter's
//! clock, so a run that straddles a minute boundary counts into one window.

mod support;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use redis::aio::MultiplexedConnection;
use serde_json::json;
use stridelabs_auth::{PatValidator, SLAUTH_PAT_PREFIX};
use stridelabs_mcp::{
    pat_cache_key, CachedPat, CredentialVerifier, PatCache, RateClass, RateLimit, RateLimiter,
    RedisPatCache, RedisRateLimiter, SlauthPatCredential, Window, RATE_LIMIT_LOG_TARGET,
};
use stridelabs_redis::RedisHandle;
use stridelabs_testing::{require_redis, RedisServer};
use support::Capture;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// `docker-compose.yml`'s `redis` service. CI sets `REDIS_URL` to the same.
const COMPOSE_URL: &str = "redis://localhost:6390/0";

const GENERATE: RateClass = RateClass("generate");
const IDENTITY: &str = "6f1c1b7e-2d4f-4c55-9a51-0d7e2b1f3a10";

/// 20 s into its minute, so a refusal says "Retry in 40 seconds"; 32 000 s
/// into its UTC day (day 20 370), so a day refusal says "in 15 h 7 min".
const NOW: u64 = 1_760_000_000;
const DAY: u64 = 86_400;

async fn server() -> RedisServer {
    require_redis(COMPOSE_URL).await
}

fn unique_prefix(test: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_nanos();
    format!("stridelabs-mcp-test:{test}:{}:{nanos}", std::process::id())
}

async fn raw<T: redis::FromRedisValue>(server: &RedisServer, args: &[&str]) -> T {
    let mut connection: MultiplexedConnection = server.connection();
    let mut command = redis::cmd(args[0]);
    for arg in &args[1..] {
        command.arg(*arg);
    }
    command
        .query_async(&mut connection)
        .await
        .unwrap_or_else(|error| panic!("{args:?}: {error}"))
}

fn limiter(server: &RedisServer, prefix: &str, limit: u32) -> RedisRateLimiter {
    let handle = RedisHandle::open(server.url()).expect("the probed URL");
    RedisRateLimiter::new(handle, [(GENERATE, limit)], prefix).with_clock(|| NOW)
}

// --- the limiter ----------------------------------------------------------------

#[tokio::test]
async fn the_window_key_and_its_ttl_are_pythons() {
    let server = server().await;
    let prefix = unique_prefix("key");
    let limiter = limiter(&server, &prefix, 5);

    limiter
        .check("alice", GENERATE)
        .await
        .expect("under the limit");

    let key = format!("{prefix}:alice:generate:{}", NOW / 60);
    assert_eq!(
        raw::<Option<String>>(&server, &["GET", &key])
            .await
            .as_deref(),
        Some("1")
    );
    let ttl: i64 = raw(&server, &["PTTL", &key]).await;
    // Generous below (a stalled scheduler), exact above: a TTL is never longer.
    assert!((50_000..=60_000).contains(&ttl), "a 60 s window: {ttl} ms");

    // A later hit counts without moving the window's end.
    raw::<()>(&server, &["PEXPIRE", &key, "30000"]).await;
    limiter
        .check("alice", GENERATE)
        .await
        .expect("under the limit");
    let ttl: i64 = raw(&server, &["PTTL", &key]).await;
    assert!(
        ttl <= 30_000,
        "the TTL is set on the first hit only: {ttl} ms"
    );
}

#[tokio::test]
async fn the_limit_trips_with_pythons_text() {
    let server = server().await;
    let limiter = limiter(&server, &unique_prefix("trip"), 2);

    limiter.check("alice", GENERATE).await.expect("first");
    limiter.check("alice", GENERATE).await.expect("second");
    let refused = limiter.check("alice", GENERATE).await.unwrap_err();

    assert_eq!(
        refused.to_string(),
        "Rate limit exceeded for generate operations (2 per minute). Retry in 40 seconds."
    );
    // Bob, and Alice's other classes, have windows of their own.
    limiter.check("bob", GENERATE).await.expect("bob's first");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_hits_are_counted_atomically() {
    let server = server().await;
    let prefix = unique_prefix("atomic");
    let limiter = Arc::new(limiter(&server, &prefix, 50));

    let hits: Vec<_> = (0..200)
        .map(|_| {
            let limiter = Arc::clone(&limiter);
            tokio::spawn(async move { limiter.check("alice", GENERATE).await.is_ok() })
        })
        .collect();
    let mut admitted = 0;
    for hit in hits {
        if hit.await.expect("no panic") {
            admitted += 1;
        }
    }

    assert_eq!(admitted, 50);
    let key = format!("{prefix}:alice:generate:{}", NOW / 60);
    assert_eq!(
        raw::<Option<String>>(&server, &["GET", &key])
            .await
            .as_deref(),
        Some("200")
    );
}

#[tokio::test]
async fn a_new_minute_is_a_new_window() {
    let server = server().await;
    let prefix = unique_prefix("rollover");
    let handle = RedisHandle::open(server.url()).expect("the probed URL");
    let now = Arc::new(std::sync::atomic::AtomicU64::new(NOW));
    let clock = Arc::clone(&now);
    let limiter = RedisRateLimiter::new(handle, [(GENERATE, 1)], prefix.as_str())
        .with_clock(move || clock.load(std::sync::atomic::Ordering::SeqCst));

    limiter.check("alice", GENERATE).await.expect("first");
    assert!(limiter.check("alice", GENERATE).await.is_err());
    now.fetch_add(60, std::sync::atomic::Ordering::SeqCst);
    limiter
        .check("alice", GENERATE)
        .await
        .expect("the next minute");
}

#[tokio::test]
async fn prefixes_isolate_limiters() {
    let server = server().await;
    let one = limiter(&server, &unique_prefix("app-a"), 1);
    let other = limiter(&server, &unique_prefix("app-b"), 1);

    one.check("alice", GENERATE).await.expect("app a's first");
    other.check("alice", GENERATE).await.expect("app b's first");
    assert!(one.check("alice", GENERATE).await.is_err());
}

#[tokio::test]
async fn a_limit_of_zero_writes_nothing() {
    let server = server().await;
    let prefix = unique_prefix("zero");
    let limiter = limiter(&server, &prefix, 0);

    for _ in 0..10 {
        limiter.check("alice", GENERATE).await.expect("unlimited");
    }

    let keys: Vec<String> = raw(&server, &["KEYS", &format!("{prefix}:*")]).await;
    assert!(keys.is_empty(), "{keys:?}");
}

// --- the day window ---------------------------------------------------------

/// A limiter with `per_minute` and `per_day` ceilings for `generate` (0:
/// that window off), on its own handle, at `NOW`.
fn windowed(server: &RedisServer, prefix: &str, per_minute: u32, per_day: u32) -> RedisRateLimiter {
    let handle = RedisHandle::open(server.url()).expect("the probed URL");
    RedisRateLimiter::from_limits(
        handle,
        [
            RateLimit::per_minute(GENERATE, per_minute),
            RateLimit::per_day(GENERATE, per_day),
        ],
        prefix,
    )
    .with_clock(|| NOW)
}

fn minute_key(prefix: &str, subject: &str, now: u64) -> String {
    format!("{prefix}:{subject}:generate:{}", now / 60)
}

fn day_key(prefix: &str, subject: &str, now: u64) -> String {
    format!("{prefix}:{subject}:generate:day:{}", now / DAY)
}

async fn value(server: &RedisServer, key: &str) -> Option<String> {
    raw::<Option<String>>(server, &["GET", key]).await
}

async fn keys(server: &RedisServer, prefix: &str) -> Vec<String> {
    let mut keys: Vec<String> = raw(server, &["KEYS", &format!("{prefix}:*")]).await;
    keys.sort();
    keys
}

#[tokio::test]
async fn the_day_key_is_its_own_and_its_ttl_a_day_set_on_the_first_hit_only() {
    let server = server().await;
    let prefix = unique_prefix("day-key");
    let limiter = windowed(&server, &prefix, 5, 30);

    limiter.check("alice", GENERATE).await.expect("under both");

    let (minute, day) = (
        minute_key(&prefix, "alice", NOW),
        day_key(&prefix, "alice", NOW),
    );
    assert_eq!(day, format!("{prefix}:alice:generate:day:20370"));
    assert_eq!(keys(&server, &prefix).await, [minute.clone(), day.clone()]);
    assert_eq!(value(&server, &minute).await.as_deref(), Some("1"));
    assert_eq!(value(&server, &day).await.as_deref(), Some("1"));
    let ttl: i64 = raw(&server, &["PTTL", &minute]).await;
    assert!(
        (50_000..=60_000).contains(&ttl),
        "the minute's 60 s, unchanged: {ttl} ms"
    );
    let ttl: i64 = raw(&server, &["PTTL", &day]).await;
    // Generous below (a stalled scheduler), exact above: never longer.
    assert!(
        (86_390_000..=86_400_000).contains(&ttl),
        "a day's 86 400 s: {ttl} ms"
    );

    // A later hit counts without moving the day key's expiry.
    raw::<()>(&server, &["PEXPIRE", &day, "30000"]).await;
    limiter.check("alice", GENERATE).await.expect("under both");
    assert_eq!(value(&server, &day).await.as_deref(), Some("2"));
    let ttl: i64 = raw(&server, &["PTTL", &day]).await;
    assert!(
        (1..=30_000).contains(&ttl),
        "the TTL is set on the first hit only: {ttl} ms"
    );
}

#[tokio::test]
async fn the_day_limit_trips_with_the_day_text_and_writes_no_minute_key_when_that_is_off() {
    let server = server().await;
    let prefix = unique_prefix("day-trip");
    let limiter = windowed(&server, &prefix, 0, 2);

    limiter.check("alice", GENERATE).await.expect("first");
    limiter.check("alice", GENERATE).await.expect("second");
    let refused = limiter.check("alice", GENERATE).await.unwrap_err();

    assert_eq!(refused.window, Window::Day);
    assert_eq!(
        refused.to_string(),
        "Rate limit exceeded for generate operations (2 per day). \
         The limit resets at 00:00 UTC, in 15 h 7 min."
    );
    assert_eq!(
        keys(&server, &prefix).await,
        [day_key(&prefix, "alice", NOW)]
    );
    // Bob has a day of his own.
    limiter.check("bob", GENERATE).await.expect("bob's first");
}

#[tokio::test]
async fn a_minute_refusal_does_not_spend_the_day_but_a_day_refusal_counts_in_the_minute() {
    let server = server().await;
    let prefix = unique_prefix("day-order");

    // A burst against a minute ceiling of 1: one admitted, two refused per
    // minute, and only the admitted one reached the day.
    let limiter = windowed(&server, &prefix, 1, 5);
    let verdicts = [
        limiter.check("alice", GENERATE).await,
        limiter.check("alice", GENERATE).await,
        limiter.check("alice", GENERATE).await,
    ];
    assert!(verdicts[0].is_ok());
    for refused in &verdicts[1..] {
        assert_eq!(refused.as_ref().unwrap_err().window, Window::Minute);
    }
    assert_eq!(
        value(&server, &minute_key(&prefix, "alice", NOW))
            .await
            .as_deref(),
        Some("3")
    );
    assert_eq!(
        value(&server, &day_key(&prefix, "alice", NOW))
            .await
            .as_deref(),
        Some("1")
    );

    // A day ceiling of 1: the second call passes the minute (counted there)
    // and is refused by the day.
    let limiter = windowed(&server, &prefix, 10, 1);
    limiter.check("bob", GENERATE).await.expect("the day's one");
    assert_eq!(
        limiter.check("bob", GENERATE).await.unwrap_err().window,
        Window::Day
    );
    assert_eq!(
        value(&server, &minute_key(&prefix, "bob", NOW))
            .await
            .as_deref(),
        Some("2")
    );
    assert_eq!(
        value(&server, &day_key(&prefix, "bob", NOW))
            .await
            .as_deref(),
        Some("2")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_limiters_sharing_one_redis_never_admit_more_than_the_day_cap() {
    let server = server().await;
    let prefix = unique_prefix("day-shared");
    // Two instances of a service: separate handles (separate connections),
    // one prefix, one Redis.
    let instances = [
        Arc::new(windowed(&server, &prefix, 0, 25)),
        Arc::new(windowed(&server, &prefix, 0, 25)),
    ];

    let hits: Vec<_> = (0..200)
        .map(|n| {
            let limiter = Arc::clone(&instances[n % 2]);
            tokio::spawn(async move { limiter.check("alice", GENERATE).await.is_ok() })
        })
        .collect();
    let mut admitted = 0;
    for hit in hits {
        if hit.await.expect("no panic") {
            admitted += 1;
        }
    }

    assert_eq!(admitted, 25);
    assert_eq!(
        value(&server, &day_key(&prefix, "alice", NOW))
            .await
            .as_deref(),
        Some("200")
    );
}

#[tokio::test]
async fn the_next_utc_day_is_a_new_window() {
    let server = server().await;
    let prefix = unique_prefix("day-rollover");
    let handle = RedisHandle::open(server.url()).expect("the probed URL");
    let now = Arc::new(AtomicU64::new(NOW));
    let clock = Arc::clone(&now);
    let limiter =
        RedisRateLimiter::from_limits(handle, [RateLimit::per_day(GENERATE, 1)], prefix.as_str())
            .with_clock(move || clock.load(Ordering::SeqCst));

    limiter.check("alice", GENERATE).await.expect("first");
    assert!(limiter.check("alice", GENERATE).await.is_err());
    // 00:00 UTC.
    now.store((NOW / DAY + 1) * DAY, Ordering::SeqCst);
    limiter
        .check("alice", GENERATE)
        .await
        .expect("the next day");

    assert_eq!(
        value(&server, &day_key(&prefix, "alice", (NOW / DAY + 1) * DAY))
            .await
            .as_deref(),
        Some("1")
    );
}

#[tokio::test]
async fn one_clock_reading_names_every_key_of_a_check() {
    let server = server().await;
    let prefix = unique_prefix("day-one-reading");
    let handle = RedisHandle::open(server.url()).expect("the probed URL");
    // The day's last second, then the next day's first: a second reading
    // within the check would put the day hit in the next day.
    let last_second = (NOW / DAY + 1) * DAY - 1;
    let readings = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&readings);
    let limiter = RedisRateLimiter::from_limits(
        handle,
        [
            RateLimit::per_minute(GENERATE, 5),
            RateLimit::per_day(GENERATE, 5),
        ],
        prefix.as_str(),
    )
    .with_clock(move || last_second + counted.fetch_add(1, Ordering::SeqCst));

    limiter.check("alice", GENERATE).await.expect("under both");

    assert_eq!(readings.load(Ordering::SeqCst), 1);
    assert_eq!(
        keys(&server, &prefix).await,
        [
            minute_key(&prefix, "alice", last_second),
            day_key(&prefix, "alice", last_second)
        ]
    );
}

/// A real partial failure: the day key holds something `INCR` refuses, so
/// the minute hit succeeds and the day hit errors. The check fails open
/// with one warning (on the day), and the minute keeps its count.
#[tokio::test]
async fn a_failing_day_after_a_counted_minute_fails_open_and_keeps_the_minute() {
    let (capture, _guard) = Capture::install();
    let server = server().await;
    let prefix = unique_prefix("day-fail-open");
    let day = day_key(&prefix, "alice", NOW);
    raw::<()>(&server, &["SET", &day, "not-a-counter", "EX", "600"]).await;
    let limiter = windowed(&server, &prefix, 5, 1);

    for _ in 0..3 {
        limiter
            .check("alice", GENERATE)
            .await
            .expect("allowed, though a day of 1 would refuse the second");
    }

    assert_eq!(
        value(&server, &minute_key(&prefix, "alice", NOW))
            .await
            .as_deref(),
        Some("3")
    );
    assert_eq!(value(&server, &day).await.as_deref(), Some("not-a-counter"));
    let warnings = capture.take(RATE_LIMIT_LOG_TARGET);
    assert_eq!(warnings.len(), 3, "one per check: {warnings:?}");
    for line in &warnings {
        assert_eq!(line.field("window"), Some("day"));
        assert_eq!(line.field("class"), Some("generate"));
    }
}

/// The minute fails: the check fails open there and never hits the day.
#[tokio::test]
async fn a_failing_minute_fails_open_and_skips_the_day() {
    let (capture, _guard) = Capture::install();
    let server = server().await;
    let prefix = unique_prefix("minute-fail-open");
    let minute = minute_key(&prefix, "alice", NOW);
    raw::<()>(&server, &["SET", &minute, "not-a-counter", "EX", "600"]).await;
    let limiter = windowed(&server, &prefix, 1, 1);

    for _ in 0..3 {
        limiter.check("alice", GENERATE).await.expect("fails open");
    }

    assert_eq!(
        keys(&server, &prefix).await,
        [minute],
        "the day was never hit"
    );
    let warnings = capture.take(RATE_LIMIT_LOG_TARGET);
    assert_eq!(warnings.len(), 3, "{warnings:?}");
    for line in &warnings {
        assert_eq!(line.field("window"), Some("minute"));
    }
}

// --- the PAT cache --------------------------------------------------------------

fn pat() -> String {
    format!("{SLAUTH_PAT_PREFIX}{}", "g".repeat(43))
}

async fn slauth() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/pat/validate"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"valid": true, "identity_id": IDENTITY})),
        )
        .mount(&server)
        .await;
    server
}

fn credential(slauth: &MockServer, cache: RedisPatCache) -> SlauthPatCredential {
    SlauthPatCredential::new(
        PatValidator::new(
            format!("{}/api/v1/pat/validate", slauth.uri()),
            reqwest::Client::new(),
        ),
        ["image:generate"],
    )
    .with_cache(cache)
}

async fn validations(slauth: &MockServer) -> usize {
    slauth.received_requests().await.expect("recording").len()
}

fn cache(server: &RedisServer, prefix: &str) -> RedisPatCache {
    RedisPatCache::new(
        RedisHandle::open(server.url()).expect("the probed URL"),
        prefix,
    )
}

#[tokio::test]
async fn an_identity_round_trips_under_the_prefixed_digest_with_its_ttl() {
    let server = server().await;
    let prefix = unique_prefix("pat-roundtrip");
    let cache = cache(&server, &prefix);
    let identity = Uuid::parse_str(IDENTITY).unwrap();
    let key = pat_cache_key(&pat());

    assert_eq!(cache.get(&key).await.expect("a miss is not an error"), None);
    cache
        .set(
            &key,
            CachedPat::new(identity, 1_760_000_120),
            Duration::from_secs(120),
        )
        .await
        .expect("stored");
    assert_eq!(
        cache.get(&key).await.expect("a hit"),
        Some(CachedPat::new(identity, 1_760_000_120))
    );

    let stored = format!("{prefix}:{key}");
    assert_eq!(
        raw::<Option<String>>(&server, &["GET", &stored])
            .await
            .as_deref(),
        Some(format!("{IDENTITY}:1760000120").as_str()),
        "{{uuid}}:{{expires_at}}, under {{prefix}}:{{digest}}"
    );
    let ttl: i64 = raw(&server, &["PTTL", &stored]).await;
    assert!((110_000..=120_000).contains(&ttl), "{ttl} ms");
}

#[tokio::test]
async fn a_ttl_is_whole_seconds_rounded_down_and_at_most_a_day() {
    let server = server().await;
    let prefix = unique_prefix("pat-ttl");
    let cache = cache(&server, &prefix);
    let identity = Uuid::parse_str(IDENTITY).unwrap();

    for (key, ttl, longest_ms, shortest_ms) in [
        // `Duration::MAX` must not overflow, nor become a key that never expires.
        ("max", Duration::MAX, 86_400_000, 86_000_000),
        ("fraction", Duration::from_millis(2_900), 2_000, 1),
        ("zero", Duration::ZERO, 1_000, 1),
    ] {
        cache
            .set(key, CachedPat::new(identity, 1_760_000_120), ttl)
            .await
            .expect("stored");
        let ttl_ms: i64 = raw(&server, &["PTTL", &format!("{prefix}:{key}")]).await;
        assert!(
            (shortest_ms..=longest_ms).contains(&ttl_ms),
            "{key}: {ttl_ms} ms"
        );
    }
}

#[tokio::test]
async fn the_credential_validates_once_and_a_hit_does_not_refresh_the_ttl() {
    let server = server().await;
    let slauth = slauth().await;
    let prefix = unique_prefix("pat-hit");
    let credential = credential(&slauth, cache(&server, &prefix));
    let stored = format!("{prefix}:{}", pat_cache_key(&pat()));

    credential.verify(&pat()).await.expect("valid");
    raw::<()>(&server, &["PEXPIRE", &stored, "30000"]).await;
    let principal = credential.verify(&pat()).await.expect("a hit");

    assert_eq!(principal.subject, IDENTITY);
    assert_eq!(validations(&slauth).await, 1);
    let ttl: i64 = raw(&server, &["PTTL", &stored]).await;
    assert!(
        (1..=30_000).contains(&ttl),
        "the hit left the TTL alone: {ttl} ms"
    );
}

#[tokio::test]
async fn a_malformed_cached_value_falls_through_to_slauth() {
    let server = server().await;
    let slauth = slauth().await;
    let prefix = unique_prefix("pat-malformed");
    let stored = format!("{prefix}:{}", pat_cache_key(&pat()));
    let cache = cache(&server, &prefix);
    let credential = credential(&slauth, cache.clone());

    // Garbage, the old bare-UUID form, and a non-numeric expiry.
    let values = ["not-a-uuid", IDENTITY, &format!("{IDENTITY}:soon")];
    for (attempt, value) in values.into_iter().enumerate() {
        raw::<()>(&server, &["SET", &stored, value, "EX", "120"]).await;
        assert!(cache.get(&pat_cache_key(&pat())).await.is_err(), "{value}");

        let principal = credential.verify(&pat()).await.expect("slauth decided");

        assert_eq!(principal.subject, IDENTITY);
        assert_eq!(validations(&slauth).await, attempt + 1, "{value}");
        assert_eq!(
            raw::<Option<String>>(&server, &["GET", &stored])
                .await
                .as_deref(),
            Some(value),
            "nothing is written after a failed read"
        );
    }
}

#[tokio::test]
async fn an_expired_entry_is_a_miss_and_the_fresh_one_carries_its_expiry() {
    let server = server().await;
    let slauth = slauth().await;
    let prefix = unique_prefix("pat-expired");
    let stored = format!("{prefix}:{}", pat_cache_key(&pat()));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs();
    // Expired a second ago, though Redis would keep it two more minutes.
    let expired = format!("{IDENTITY}:{}", now - 1);
    raw::<()>(&server, &["SET", &stored, &expired, "EX", "120"]).await;

    credential(&slauth, cache(&server, &prefix))
        .verify(&pat())
        .await
        .expect("validated again");

    assert_eq!(validations(&slauth).await, 1);
    let fresh: String = raw::<Option<String>>(&server, &["GET", &stored])
        .await
        .expect("rewritten");
    let (identity, expires_at) = fresh.split_once(':').expect("{uuid}:{expires_at}");
    let expires_at: u64 = expires_at.parse().expect("Unix seconds");
    assert_eq!(identity, IDENTITY);
    // Stamped from a clock read between `now` and `after`, so the bound is
    // exact whatever the scheduler did in between.
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs();
    assert!(
        (now + 120..=after + 120).contains(&expires_at),
        "validation time + 120: {expires_at} not in {}..={}",
        now + 120,
        after + 120
    );
}

#[tokio::test]
async fn cache_prefixes_isolate_verifiers() {
    let server = server().await;
    let slauth = slauth().await;
    let one = credential(&slauth, cache(&server, &unique_prefix("pat-app-a")));
    let other = credential(&slauth, cache(&server, &unique_prefix("pat-app-b")));

    one.verify(&pat()).await.expect("valid");
    other.verify(&pat()).await.expect("valid");
    one.verify(&pat()).await.expect("valid");

    assert_eq!(
        validations(&slauth).await,
        2,
        "the second verifier never saw the first one's result"
    );
}
