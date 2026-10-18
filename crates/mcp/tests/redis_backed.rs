//! The Redis-backed limiter and PAT cache against a Redis that is not there
//! (feature `redis`; no server needed): the limiter fails open with one
//! warning per check, on whichever window it tried first, an unlimited class
//! never touches Redis, and the PAT credential falls through to slauth.
//! `tests/redis_live.rs` covers a real server.

mod support;

use serde_json::json;
use stridelabs_auth::{PatValidator, SLAUTH_PAT_PREFIX};
use stridelabs_mcp::{
    CredentialVerifier, PatCache, RateClass, RateLimit, RateLimiter, RedisPatCache,
    RedisRateLimiter, SlauthPatCredential, DEFAULT_RATE_LIMIT_PREFIX, RATE_LIMIT_LOG_TARGET,
};
use stridelabs_redis::RedisHandle;
use support::Capture;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const GENERATE: RateClass = RateClass("generate");

/// Nothing listens on port 1: every dial is refused at once.
fn dead_redis() -> RedisHandle {
    RedisHandle::open("redis://:hunter2@127.0.0.1:1/0").expect("the URL parses")
}

#[tokio::test]
async fn a_dead_redis_fails_open_with_a_warning() {
    let (capture, _guard) = Capture::install();
    let limiter = RedisRateLimiter::new(dead_redis(), [(GENERATE, 1)], DEFAULT_RATE_LIMIT_PREFIX);

    for _ in 0..5 {
        limiter
            .check("alice", GENERATE)
            .await
            .expect("fails open: allowed despite a limit of 1");
    }

    let warnings = capture.take(RATE_LIMIT_LOG_TARGET);
    assert_eq!(
        warnings.len(),
        5,
        "one warning per failed hit: {warnings:?}"
    );
    for line in &warnings {
        assert_eq!(line.level, tracing::Level::WARN);
        assert_eq!(line.field("class"), Some("generate"));
        assert_eq!(line.field("window"), Some("minute"));
    }
    assert!(!capture.everything().contains("hunter2"), "never the URL");
}

/// Both windows on, Redis down: each check fails open at the minute (its
/// first window), with ONE warning, and never tries the day after it.
#[tokio::test]
async fn a_dead_redis_fails_open_once_per_check_on_both_windows() {
    let (capture, _guard) = Capture::install();
    let limiter = RedisRateLimiter::from_limits(
        dead_redis(),
        [
            RateLimit::per_day(GENERATE, 1),
            RateLimit::per_minute(GENERATE, 1),
        ],
        DEFAULT_RATE_LIMIT_PREFIX,
    );

    for _ in 0..4 {
        limiter
            .check("alice", GENERATE)
            .await
            .expect("fails open: allowed despite a limit of 1 a minute and 1 a day");
    }

    let warnings = capture.take(RATE_LIMIT_LOG_TARGET);
    assert_eq!(
        warnings.len(),
        4,
        "one warning per check, not per window: {warnings:?}"
    );
    for line in &warnings {
        assert_eq!(line.field("window"), Some("minute"), "the first window");
    }
    assert!(!capture.everything().contains("hunter2"), "never the URL");
}

/// A TCP endpoint that accepts every connection and drops it at once: the
/// dial succeeds and the handshake fails, a different failure from a
/// refused port. The URL carries a password, which must never be logged.
async fn dropping_redis() -> RedisHandle {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback port");
    let address = listener.local_addr().expect("local address");
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            drop(socket);
        }
    });
    RedisHandle::open(&format!("redis://:hunter2@{address}/0")).expect("the URL parses")
}

#[tokio::test]
async fn an_endpoint_that_drops_every_connection_fails_open_on_both_windows() {
    let (capture, _guard) = Capture::install();
    let limiter = RedisRateLimiter::from_limits(
        dropping_redis().await,
        [
            RateLimit::per_minute(GENERATE, 1),
            RateLimit::per_day(GENERATE, 1),
        ],
        DEFAULT_RATE_LIMIT_PREFIX,
    );

    for _ in 0..3 {
        limiter
            .check("alice", GENERATE)
            .await
            .expect("fails open: allowed despite a limit of 1 a minute and 1 a day");
    }

    let warnings = capture.take(RATE_LIMIT_LOG_TARGET);
    assert_eq!(warnings.len(), 3, "one warning per check: {warnings:?}");
    for line in &warnings {
        assert_eq!(line.level, tracing::Level::WARN);
        assert_eq!(line.field("window"), Some("minute"), "the first window");
    }
    assert!(!capture.everything().contains("hunter2"), "never the URL");
}

/// A class limited only per day fails open on the day.
#[tokio::test]
async fn a_day_only_class_fails_open_on_the_day() {
    let (capture, _guard) = Capture::install();
    let limiter = RedisRateLimiter::from_limits(
        dead_redis(),
        [
            RateLimit::per_minute(GENERATE, 0),
            RateLimit::per_day(GENERATE, 1),
        ],
        DEFAULT_RATE_LIMIT_PREFIX,
    );

    for _ in 0..3 {
        limiter.check("alice", GENERATE).await.expect("fails open");
    }

    let warnings = capture.take(RATE_LIMIT_LOG_TARGET);
    assert_eq!(warnings.len(), 3, "{warnings:?}");
    for line in &warnings {
        assert_eq!(line.field("window"), Some("day"));
    }
}

#[tokio::test]
async fn an_unlimited_class_never_touches_redis() {
    let (capture, _guard) = Capture::install();
    let per_minute =
        RedisRateLimiter::new(dead_redis(), [(GENERATE, 0)], DEFAULT_RATE_LIMIT_PREFIX);
    let both_windows_off = RedisRateLimiter::from_limits(
        dead_redis(),
        [
            RateLimit::per_minute(GENERATE, 0),
            RateLimit::per_day(GENERATE, 0),
        ],
        DEFAULT_RATE_LIMIT_PREFIX,
    );

    for limiter in [per_minute, both_windows_off] {
        for class in [GENERATE, RateClass::READ] {
            limiter.check("alice", class).await.expect("unlimited");
        }
    }

    assert!(
        capture.take(RATE_LIMIT_LOG_TARGET).is_empty(),
        "no hit was attempted"
    );
}

#[tokio::test]
async fn a_dead_cache_is_an_error_and_the_credential_falls_through() {
    let cache = RedisPatCache::new(dead_redis(), "imgmcp:pat:validate");
    let key = stridelabs_mcp::pat_cache_key("anything");
    assert!(cache.get(&key).await.is_err());

    let slauth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/pat/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"valid": true, "identity_id": "6f1c1b7e-2d4f-4c55-9a51-0d7e2b1f3a10"}),
        ))
        .mount(&slauth)
        .await;
    let credential = SlauthPatCredential::new(
        PatValidator::new(
            format!("{}/api/v1/pat/validate", slauth.uri()),
            reqwest::Client::new(),
        ),
        ["image:generate"],
    )
    .with_cache(cache);

    let token = format!("{SLAUTH_PAT_PREFIX}{}", "g".repeat(43));
    let principal = credential.verify(&token).await.expect("slauth decided");

    assert_eq!(principal.subject, "6f1c1b7e-2d4f-4c55-9a51-0d7e2b1f3a10");
    assert_eq!(
        slauth.received_requests().await.expect("recording").len(),
        1
    );
}
