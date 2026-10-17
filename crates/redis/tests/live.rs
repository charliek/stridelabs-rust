//! `RedisHandle` against a real Redis (feature `live-tests`; CI's
//! all-features lane). `require_redis` panics when there is no server —
//! `docker compose up -d redis` — so this suite never passes by skipping.
//!
//! Most tests put [`support::Proxy`] between the handle and the server, to
//! count dials and to lose replies or connections on demand.

mod support;

use std::time::{Duration, Instant};

use redis::aio::MultiplexedConnection;
use stridelabs_redis::{RedisError, RedisHandle, MAX_TTL_SECS};
use stridelabs_testing::{require_redis, RedisServer};
use support::{unique_key, Proxy, Replies};

/// `docker-compose.yml`'s `redis` service. CI sets `REDIS_URL` to the same.
const COMPOSE_URL: &str = "redis://localhost:6390/0";

async fn server() -> RedisServer {
    require_redis(COMPOSE_URL).await
}

async fn raw_get(server: &RedisServer, key: &str) -> Option<String> {
    redis::cmd("GET")
        .arg(key)
        .query_async(&mut server.connection())
        .await
        .expect("GET through the probe's own connection")
}

async fn pttl(server: &RedisServer, key: &str) -> i64 {
    redis::cmd("PTTL")
        .arg(key)
        .query_async(&mut server.connection())
        .await
        .expect("PTTL through the probe's own connection")
}

async fn raw(server: &RedisServer, args: &[&str]) {
    let mut connection: MultiplexedConnection = server.connection();
    let mut command = redis::cmd(args[0]);
    for arg in &args[1..] {
        command.arg(*arg);
    }
    command
        .query_async::<()>(&mut connection)
        .await
        .unwrap_or_else(|error| panic!("{args:?}: {error}"));
}

/// A handle through a fresh proxy, its connection already dialled and cached
/// (one `GET`), so the next command runs on a CACHED connection.
async fn warm_handle(server: &RedisServer) -> (Proxy, RedisHandle) {
    let proxy = Proxy::start(server.url()).await;
    let handle = RedisHandle::open(&proxy.url()).expect("the proxy URL");
    handle
        .get(&unique_key("warm-up"))
        .await
        .expect("the warm-up GET");
    proxy.assert_accepted(1).await;
    (proxy, handle)
}

// ── The fixed window ────────────────────────────────────────────────────────

#[tokio::test]
async fn the_first_hit_counts_one_and_sets_the_window_ttl() {
    let server = server().await;
    let handle = RedisHandle::open(server.url()).unwrap();
    let key = unique_key("first-hit");

    assert_eq!(handle.fixed_window_hit(&key, 60).await.unwrap(), 1);

    let ttl = pttl(&server, &key).await;
    assert!(
        (59_000..=60_000).contains(&ttl),
        "a 60 s window's TTL starts at 60 s: {ttl} ms"
    );
}

/// The TTL is set on the FIRST hit only: a later hit must not push the
/// window's end out. `PEXPIRE` stands in for 30 s passing.
#[tokio::test]
async fn later_hits_count_up_and_never_reset_the_ttl() {
    let server = server().await;
    let handle = RedisHandle::open(server.url()).unwrap();
    let key = unique_key("later-hits");

    assert_eq!(handle.fixed_window_hit(&key, 60).await.unwrap(), 1);
    raw(&server, &["PEXPIRE", &key, "30000"]).await;

    assert_eq!(handle.fixed_window_hit(&key, 60).await.unwrap(), 2);
    assert_eq!(handle.fixed_window_hit(&key, 60).await.unwrap(), 3);

    let ttl = pttl(&server, &key).await;
    assert!(
        (0..=30_000).contains(&ttl),
        "a later hit reset the window's TTL: {ttl} ms"
    );
}

/// 100 concurrent hits over four handles (four connections): every count
/// from 1 to 100 handed out exactly once, none lost, and the key has a TTL.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_hits_are_atomic() {
    let server = server().await;
    let key = unique_key("concurrent");
    let handles: Vec<RedisHandle> = (0..4)
        .map(|_| RedisHandle::open(server.url()).unwrap())
        .collect();

    let hits: Vec<_> = (0..100)
        .map(|i| {
            let handle = handles[i % handles.len()].clone();
            let key = key.clone();
            tokio::spawn(async move { handle.fixed_window_hit(&key, 60).await })
        })
        .collect();
    let mut counts = Vec::new();
    for hit in hits {
        counts.push(hit.await.unwrap().expect("a hit"));
    }
    counts.sort_unstable();

    assert_eq!(counts, (1..=100).collect::<Vec<u64>>());
    assert_eq!(raw_get(&server, &key).await.as_deref(), Some("100"));
    assert!(pttl(&server, &key).await > 0, "the window has its TTL");
}

#[tokio::test]
async fn windows_are_isolated_by_key() {
    let server = server().await;
    let handle = RedisHandle::open(server.url()).unwrap();
    let (a, b) = (unique_key("isolated-a"), unique_key("isolated-b"));

    for expected in 1..=3 {
        assert_eq!(handle.fixed_window_hit(&a, 60).await.unwrap(), expected);
    }
    assert_eq!(handle.fixed_window_hit(&b, 60).await.unwrap(), 1);
    assert_eq!(raw_get(&server, &a).await.as_deref(), Some("3"));
    assert_eq!(raw_get(&server, &b).await.as_deref(), Some("1"));
}

/// The bound is inside what Redis accepts: a window and a TTL of exactly
/// `MAX_TTL_SECS` are set as asked.
#[tokio::test]
async fn the_longest_window_and_ttl_are_accepted() {
    let server = server().await;
    let handle = RedisHandle::open(server.url()).unwrap();
    let (window, cached) = (unique_key("max-window"), unique_key("max-ttl"));
    let max_ms = i64::try_from(MAX_TTL_SECS * 1000).unwrap();

    assert_eq!(
        handle
            .fixed_window_hit(&window, MAX_TTL_SECS)
            .await
            .unwrap(),
        1
    );
    handle.set_ex(&cached, "v", MAX_TTL_SECS).await.unwrap();
    for key in [&window, &cached] {
        let ttl = pttl(&server, key).await;
        assert!((max_ms - 5_000..=max_ms).contains(&ttl), "{key}: {ttl} ms");
    }
}

/// Above the bound nothing is sent: in particular no `INCR`, which a refused
/// `EXPIRE` inside the script would have left behind without a TTL.
#[tokio::test]
async fn an_out_of_range_window_leaves_no_counter_behind() {
    let server = server().await;
    let handle = RedisHandle::open(server.url()).unwrap();
    let key = unique_key("out-of-range");

    for secs in [MAX_TTL_SECS + 1, u64::MAX] {
        let error = handle
            .fixed_window_hit(&key, secs)
            .await
            .expect_err("too long");
        assert!(
            matches!(error, RedisError::InvalidArgument(_)),
            "{secs}: {error:?}"
        );
        let error = handle.set_ex(&key, "v", secs).await.expect_err("too long");
        assert!(
            matches!(error, RedisError::InvalidArgument(_)),
            "{secs}: {error:?}"
        );
    }
    assert_eq!(raw_get(&server, &key).await, None, "nothing reached Redis");
}

/// Redis refusing the script (the key is not a counter) is a `Command`
/// error: final, not retried, and the connection it came over stays cached.
#[tokio::test]
async fn a_server_error_reply_is_a_command_error_and_keeps_the_connection() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("not-a-counter");
    raw(&server, &["SET", &key, "not a number"]).await;

    let error = handle
        .fixed_window_hit(&key, 60)
        .await
        .expect_err("INCR on text");
    assert!(matches!(error, RedisError::Command(_)), "{error:?}");
    assert!(!error.is_outcome_unknown());

    let list = unique_key("a-list");
    raw(&server, &["RPUSH", &list, "x"]).await;
    let error = handle.get(&list).await.expect_err("GET on a list");
    assert!(matches!(error, RedisError::Command(_)), "{error:?}");

    let fine = unique_key("fine");
    assert_eq!(handle.fixed_window_hit(&fine, 60).await.unwrap(), 1);
    assert_eq!(proxy.accepted(), 1, "a server error is no reason to redial");
}

// ── No replay after a lost reply ────────────────────────────────────────────

/// **The hit ran; its reply never came back** (the response timeout ends the
/// wait). The call fails with an unknown outcome and is NOT sent again, so
/// the counter in Redis is exactly 1 — and the next hit, on a fresh
/// connection, makes it 2.
#[tokio::test]
async fn a_lost_reply_is_never_replayed() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("lost-reply");

    proxy.set_replies(Replies::LoseNext);
    let started = Instant::now();
    let error = handle
        .fixed_window_hit(&key, 60)
        .await
        .expect_err("the reply was lost");
    assert!(matches!(error, RedisError::Io(_)), "{error:?}");
    assert!(error.is_outcome_unknown());
    assert!(
        started.elapsed() >= Duration::from_millis(500),
        "the response timeout ended it"
    );

    assert_eq!(
        raw_get(&server, &key).await.as_deref(),
        Some("1"),
        "Redis ran the INCR exactly once: it was not replayed"
    );
    assert_eq!(proxy.accepted(), 1, "no redial was made to replay it");

    assert_eq!(handle.fixed_window_hit(&key, 60).await.unwrap(), 2);
    proxy.assert_accepted(2).await;
}

/// **The hit ran; the connection died with its reply.** Same verdict: an
/// unknown outcome, never replayed, counter exactly 1.
#[tokio::test]
async fn a_connection_lost_with_the_reply_is_never_replayed() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("lost-connection");

    proxy.set_replies(Replies::CloseOnNext);
    let error = handle
        .fixed_window_hit(&key, 60)
        .await
        .expect_err("the connection closed with the reply");
    assert!(matches!(error, RedisError::Io(_)), "{error:?}");

    assert_eq!(
        raw_get(&server, &key).await.as_deref(),
        Some("1"),
        "Redis ran the INCR exactly once: it was not replayed"
    );
    assert_eq!(proxy.accepted(), 1, "no redial was made to replay it");

    assert_eq!(handle.fixed_window_hit(&key, 60).await.unwrap(), 2);
    proxy.assert_accepted(2).await;
}

/// **The hit ran; what came back was not RESP.** No valid reply was read, so
/// the outcome is unknown — the same verdict as a lost reply, not a `Command`
/// error — and the hit is not replayed: the counter is exactly 1. The
/// unparseable stream condemns the connection, so the next hit redials.
#[tokio::test]
async fn a_malformed_reply_is_outcome_unknown_and_never_replayed() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("malformed");

    proxy.set_replies(Replies::CorruptNext);
    let error = handle
        .fixed_window_hit(&key, 60)
        .await
        .expect_err("the reply was not RESP");
    assert!(matches!(error, RedisError::Io(_)), "{error:?}");
    assert!(error.is_outcome_unknown());

    assert_eq!(
        raw_get(&server, &key).await.as_deref(),
        Some("1"),
        "Redis ran the INCR exactly once: it was not replayed"
    );
    assert_eq!(proxy.accepted(), 1, "no redial was made to replay it");

    assert_eq!(handle.fixed_window_hit(&key, 60).await.unwrap(), 2);
    proxy.assert_accepted(2).await;
}

/// The idempotent retry is for a connection that died while idle — an I/O
/// failure — and does not widen to a malformed reply: that `GET` fails
/// outcome-unknown, unretried, and the next one redials.
#[tokio::test]
async fn a_malformed_reply_to_get_is_not_retried() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("malformed-get");
    raw(&server, &["SET", &key, "value"]).await;

    proxy.set_replies(Replies::CorruptNext);
    let error = handle.get(&key).await.expect_err("the reply was not RESP");
    assert!(error.is_outcome_unknown(), "{error:?}");
    assert_eq!(proxy.accepted(), 1, "not retried on a fresh connection");

    assert_eq!(handle.get(&key).await.unwrap().as_deref(), Some("value"));
    proxy.assert_accepted(2).await;
}

/// A caller that gives up on a hit (its future dropped mid-round-trip) does
/// not condemn the connection, and nothing replays the hit: it landed once.
#[tokio::test]
async fn a_cancelled_hit_keeps_the_connection_and_is_not_replayed() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("cancelled");

    proxy.set_replies(Replies::Delay(Duration::from_millis(300)));
    let cancelled =
        tokio::time::timeout(Duration::from_millis(50), handle.fixed_window_hit(&key, 60)).await;
    assert!(cancelled.is_err(), "the caller gave up first");
    proxy.set_replies(Replies::Forward);
    // Let the delayed reply drain into the connection that is still open.
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert_eq!(
        handle.fixed_window_hit(&key, 60).await.unwrap(),
        2,
        "the cancelled hit landed exactly once"
    );
    assert_eq!(proxy.accepted(), 1, "the same connection carried on");
}

// ── Reconnecting ────────────────────────────────────────────────────────────

/// The cached connection is gone (a server restart, an idle timeout): a hit
/// on it fails — and is not replayed — and the NEXT hit redials and lands.
#[tokio::test]
async fn after_the_connection_dies_the_next_hit_redials() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("redial");

    proxy.kill_connections().await;
    let error = handle
        .fixed_window_hit(&key, 60)
        .await
        .expect_err("the cached connection is dead");
    assert!(matches!(error, RedisError::Io(_)), "{error:?}");
    assert_eq!(
        proxy.accepted(),
        1,
        "a hit is never retried on a fresh connection"
    );

    assert_eq!(
        handle.fixed_window_hit(&key, 60).await.unwrap(),
        1,
        "the failed hit never reached Redis; the next one did"
    );
    proxy.assert_accepted(2).await;
}

/// `GET` and `SET EX` are idempotent: after the cached connection died, or
/// lost a reply, each is sent once more on a fresh connection and the caller
/// sees only the answer.
#[tokio::test]
async fn an_idempotent_command_is_retried_once_on_a_fresh_connection() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("retried");

    handle.set_ex(&key, "first", 120).await.unwrap();

    proxy.kill_connections().await;
    assert_eq!(handle.get(&key).await.unwrap().as_deref(), Some("first"));
    proxy.assert_accepted(2).await;

    proxy.kill_connections().await;
    handle.set_ex(&key, "second", 120).await.unwrap();
    proxy.assert_accepted(3).await;
    assert_eq!(raw_get(&server, &key).await.as_deref(), Some("second"));

    proxy.set_replies(Replies::LoseNext);
    assert_eq!(handle.get(&key).await.unwrap().as_deref(), Some("second"));
    proxy.assert_accepted(4).await;
}

/// A `SET` whose reply was lost on a cached connection, when the retry
/// cannot reconnect: the caller learns the outcome is unknown (the first
/// attempt's `Io`), not "never sent" (the dial's `Connect`) — and the `SET`
/// did run.
#[tokio::test]
async fn a_failed_reconnect_for_the_retry_keeps_the_outcome_unknown() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("retry-cannot-reconnect");

    proxy.set_refusing(true);
    proxy.set_replies(Replies::CloseOnNext);
    let error = handle
        .set_ex(&key, "maybe", 120)
        .await
        .expect_err("no reply, and no fresh connection");

    assert!(matches!(error, RedisError::Io(_)), "{error:?}");
    assert!(error.is_outcome_unknown());
    assert_eq!(
        raw_get(&server, &key).await.as_deref(),
        Some("maybe"),
        "the first attempt ran: \"unknown\" was the truth"
    );
    proxy.assert_accepted(2).await;
}

/// Many calls failing together on one dead connection share ONE redial.
///
/// Overlap is forced, not hoped for: on this single-threaded runtime each
/// `GET`, polled once, fails on the dead connection and then waits on the
/// redial — a spawned task that cannot run, let alone finish, before the
/// test yields — so all twenty are waiting on it at once.
#[tokio::test]
async fn concurrent_failures_on_a_dead_connection_share_one_redial() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("shared-redial");
    handle.set_ex(&key, "value", 120).await.unwrap();

    proxy.kill_connections().await;
    let mut gets: Vec<_> = (0..20).map(|_| Box::pin(handle.get(&key))).collect();
    for get in &mut gets {
        assert!(futures::poll!(get).is_pending(), "waiting on the redial");
    }
    for got in futures::future::join_all(gets).await {
        assert_eq!(got.unwrap().as_deref(), Some("value"));
    }
    proxy.assert_accepted(2).await;
}

/// A server that goes away and comes back: while it is down every call
/// fails — a failed dial is not cached, so each call dials afresh — and once
/// it is back the next call reconnects.
#[tokio::test]
async fn a_restarted_server_is_reconnected_to() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("restart");

    proxy.set_refusing(true);
    proxy.kill_connections().await;
    let error = handle.fixed_window_hit(&key, 60).await.expect_err("down");
    assert!(
        matches!(error, RedisError::Io(_)),
        "the cached connection: {error:?}"
    );
    for attempt in 2..=3 {
        let error = handle
            .fixed_window_hit(&key, 60)
            .await
            .expect_err("still down");
        assert!(matches!(error, RedisError::Connect(_)), "{error:?}");
        proxy.assert_accepted(attempt).await;
    }

    proxy.set_refusing(false);
    assert_eq!(
        handle.fixed_window_hit(&key, 60).await.unwrap(),
        1,
        "no hit reached Redis while it was down"
    );
    proxy.assert_accepted(4).await;
}

// ── Single flight and the generation guard ─────────────────────────────────

/// Fifty concurrent first commands on a fresh handle: one dial between them.
///
/// Overlap is forced, not hoped for: on this single-threaded runtime each
/// hit, polled once, finds the dial in flight (a spawned task that cannot
/// run before the test yields) and joins it, so all fifty are waiting on the
/// one dial when it completes.
#[tokio::test]
async fn concurrent_first_commands_share_one_dial() {
    let server = server().await;
    let proxy = Proxy::start(server.url()).await;
    let handle = RedisHandle::open(&proxy.url()).unwrap();
    let key = unique_key("single-flight");

    let mut hits: Vec<_> = (0..50)
        .map(|_| Box::pin(handle.fixed_window_hit(&key, 60)))
        .collect();
    for hit in &mut hits {
        assert!(futures::poll!(hit).is_pending(), "waiting on the dial");
    }
    let mut counts: Vec<u64> = futures::future::join_all(hits)
        .await
        .into_iter()
        .map(|hit| hit.expect("a hit"))
        .collect();
    counts.sort_unstable();

    assert_eq!(counts, (1..=50).collect::<Vec<u64>>());
    proxy.assert_accepted(1).await;
}

/// **A stale failure after a reconnect keeps the new connection.** A hit is
/// put on the wire on connection 1 and left unpolled; connection 1 dies;
/// another call notices and a third reconnects (connection 2). Only then is
/// the old hit polled again, and its failure — reported against connection
/// 1 — must leave connection 2 cached: the next hit makes no third dial.
#[tokio::test]
async fn a_stale_failure_after_a_reconnect_keeps_the_new_connection() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let (old_key, key) = (unique_key("stale-old"), unique_key("stale-new"));

    // On the wire on connection 1, its reply lost so it cannot complete.
    proxy.set_replies(Replies::LoseNext);
    let mut stale = Box::pin(handle.fixed_window_hit(&old_key, 60));
    assert!(futures::poll!(&mut stale).is_pending());

    proxy.kill_connections().await;
    proxy.set_replies(Replies::Forward);
    let error = handle
        .fixed_window_hit(&key, 60)
        .await
        .expect_err("connection 1 is dead");
    assert!(matches!(error, RedisError::Io(_)), "{error:?}");
    assert_eq!(handle.fixed_window_hit(&key, 60).await.unwrap(), 1);
    proxy.assert_accepted(2).await;

    // The old hit's failure arrives now, after the reconnect.
    let error = stale.await.expect_err("connection 1 died under it");
    assert!(matches!(error, RedisError::Io(_)), "{error:?}");

    assert_eq!(handle.fixed_window_hit(&key, 60).await.unwrap(), 2);
    assert_eq!(
        proxy.accepted(),
        2,
        "the stale failure discarded connection 2 and forced a third dial"
    );
}

// ── GET / SET EX ────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_and_set_ex_round_trip_with_their_ttl() {
    let server = server().await;
    let handle = RedisHandle::open(server.url()).unwrap();
    let key = unique_key("round-trip");

    assert_eq!(handle.get(&key).await.unwrap(), None, "no such key yet");

    handle.set_ex(&key, "{\"sub\":\"ü\"}", 120).await.unwrap();
    assert_eq!(
        handle.get(&key).await.unwrap().as_deref(),
        Some("{\"sub\":\"ü\"}")
    );
    let ttl = pttl(&server, &key).await;
    assert!((119_000..=120_000).contains(&ttl), "{ttl} ms");

    handle.set_ex(&key, "replaced", 30).await.unwrap();
    assert_eq!(handle.get(&key).await.unwrap().as_deref(), Some("replaced"));
    let ttl = pttl(&server, &key).await;
    assert!(
        (29_000..=30_000).contains(&ttl),
        "the TTL was replaced too: {ttl} ms"
    );
}

#[tokio::test]
async fn a_set_ex_value_expires() {
    let server = server().await;
    let handle = RedisHandle::open(server.url()).unwrap();
    let key = unique_key("expires");

    handle.set_ex(&key, "short-lived", 1).await.unwrap();
    assert!(handle.get(&key).await.unwrap().is_some());
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(handle.get(&key).await.unwrap(), None);
}
