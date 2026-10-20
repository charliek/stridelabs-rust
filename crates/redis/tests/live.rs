//! `RedisHandle` against a real Redis (feature `live-tests`; CI's
//! all-features lane). `require_redis` panics when there is no server —
//! `docker compose up -d redis` — so this suite never passes by skipping.
//!
//! Most tests put [`support::Proxy`] between the handle and the server, to
//! count dials and to lose replies or connections on demand.

mod support;

use std::time::{Duration, Instant};

use redis::aio::MultiplexedConnection;
use stridelabs_redis::{RedisError, RedisHandle, Replay, MAX_TTL_SECS};
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

/// Every way a consumer could render `error`: `Display`, `Debug` (plain and
/// alternate), and the payload itself, plain and quoted.
fn renderings(error: &RedisError) -> Vec<String> {
    let payload = match error {
        RedisError::InvalidUrl(payload)
        | RedisError::Connect(payload)
        | RedisError::Io(payload)
        | RedisError::Command(payload) => payload.clone(),
        RedisError::InvalidArgument(reason) => (*reason).to_owned(),
        other => panic!("a variant this suite does not know: {other:?}"),
    };
    vec![
        error.to_string(),
        format!("{error:?}"),
        format!("{error:#?}"),
        format!("{payload:?}"),
        payload,
    ]
}

/// Redis's own error text for `command`, as redis-rs reports it on the
/// probe's own connection — unfiltered: what proves a diagnostic really
/// quotes its input before a test shows the handle's error does not.
async fn raw_error_text(server: &RedisServer, command: &redis::Cmd) -> String {
    match command
        .query_async::<redis::Value>(&mut server.connection())
        .await
    {
        Err(error) => error.to_string(),
        Ok(redis::Value::ServerError(error)) => error.to_string(),
        Ok(other) => panic!("not an error reply: {other:?}"),
    }
}

/// `EVAL script 0 arg` on the probe's own connection.
fn raw_eval(script: &str, arg: &str) -> redis::Cmd {
    let mut eval = redis::cmd("EVAL");
    eval.arg(script).arg(0).arg(arg);
    eval
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

// ── EVAL and PING ───────────────────────────────────────────────────────────

/// Writes `ARGV[i]` to `KEYS[i]` for every key, so the keys' order can be
/// read back, and answers `{#KEYS, #ARGV, tonumber(ARGV[#KEYS + 1]), …}`.
const ECHO_SCRIPT: &str = "
for i = 1, #KEYS do
    redis.call('SET', KEYS[i], ARGV[i], 'EX', 60)
end
local answer = {#KEYS, #ARGV}
for i = #KEYS + 1, #ARGV do
    answer[#answer + 1] = tonumber(ARGV[i])
end
return answer
";

/// One run, counted: `INCR KEYS[1]` (expiring in a minute) and the count —
/// the shape of a script a second run would change.
const COUNT_SCRIPT: &str = "
local count = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], 60)
return count
";

/// Keys and arguments arrive in order, text and integers alike, and the
/// reply reads as an array of integers or a single one.
#[tokio::test]
async fn eval_passes_keys_and_args_in_order_and_reads_integers() {
    let server = server().await;
    let handle = RedisHandle::open(server.url()).unwrap();
    let prefix = unique_key("eval-order");
    let keys = ["a", "b", "c"].map(|name| format!("{prefix}:{name}"));
    let key_refs = keys.each_ref().map(String::as_str);

    let answer: Vec<i64> = handle
        .eval(
            ECHO_SCRIPT,
            &key_refs,
            &[
                "first".into(),
                "second".into(),
                "third".into(),
                7_i64.into(),
                (-3_i64).into(),
                (1_u64 << 40).into(),
            ],
            Replay::Never,
        )
        .await
        .expect("the echo script");
    assert_eq!(answer, [3, 6, 7, -3, 1 << 40]);
    for (key, value) in keys.iter().zip(["first", "second", "third"]) {
        assert_eq!(raw_get(&server, key).await.as_deref(), Some(value), "{key}");
    }

    let doubled: i64 = handle
        .eval(
            "return tonumber(ARGV[1]) * 2",
            &[],
            &[21_u32.into()],
            Replay::OnceOnFreshConnection,
        )
        .await
        .expect("a single integer");
    assert_eq!(doubled, 42);

    let empty: Vec<i64> = handle
        .eval("return {}", &[], &[], Replay::Never)
        .await
        .expect("an empty table");
    assert!(empty.is_empty(), "{empty:?}");

    raw(&server, &["DEL", &keys[0], &keys[1], &keys[2]]).await;
}

/// A script's error — its own `error_reply`, a Lua runtime error, an error
/// from a `redis.call` — and a reply of the wrong shape are `Command` errors
/// (Redis answered): final, not retried even under `OnceOnFreshConnection`,
/// the connection kept. The error names the code (`ERR`) and carries
/// neither the script, its key, its argument, nor Redis's own text — in no
/// rendering, the payload included.
#[tokio::test]
async fn a_script_error_is_a_command_error_without_the_script_or_its_values() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("eval-error");
    raw(&server, &["SET", &key, "not a number", "EX", "60"]).await;
    let secret = "user_01SECRETARGUMENT";

    let marked = |body: &str| format!("local marker = 'SCRIPT-BODY-MARKER'\n{body}");
    let failures = [
        (
            marked("return redis.error_reply('ERR refused by the script')"),
            "refused by the script",
        ),
        (
            marked("return tonumber(ARGV[2]) + 1"),
            "arithmetic on a nil",
        ),
        (
            marked("return redis.call('INCR', KEYS[1])"),
            "not an integer",
        ),
    ];
    for (script, expected) in &failures {
        let error = handle
            .eval::<i64>(
                script,
                &[&key],
                &[secret.into()],
                Replay::OnceOnFreshConnection,
            )
            .await
            .expect_err(expected);
        assert!(matches!(error, RedisError::Command(_)), "{error:?}");
        assert!(!error.is_outcome_unknown());
        for rendered in renderings(&error) {
            assert!(rendered.contains("the server answered ERR"), "{rendered}");
            for leaked in ["SCRIPT-BODY-MARKER", secret, key.as_str(), expected] {
                assert!(!rendered.contains(leaked), "{leaked} in {rendered}");
            }
        }
    }

    let error = handle
        .eval::<Vec<i64>>(
            &marked("return ARGV[1]"),
            &[],
            &[secret.into()],
            Replay::Never,
        )
        .await
        .expect_err("a string is not an array");
    assert!(matches!(error, RedisError::Command(_)), "{error:?}");
    for rendered in renderings(&error) {
        assert!(!rendered.contains(secret), "{rendered}");
    }

    let one: i64 = handle
        .eval("return 1", &[], &[], Replay::Never)
        .await
        .expect("the connection still works");
    assert_eq!(one, 1);
    assert_eq!(proxy.accepted(), 1, "a script error is no reason to redial");
    raw(&server, &["DEL", &key]).await;
}

/// **Redis's diagnostics that quote their input never reach the error.**
/// Each script below makes Redis's own error text carry a canary — shown
/// first on the probe's own connection: an argument raised as the error's
/// code, after a code Redis defines, in a Lua runtime error, inside an
/// array; and the script's own source, which a compile error quotes. The
/// handle's error carries none of it, in any rendering or its payload.
#[tokio::test]
async fn server_diagnostics_quoting_the_input_are_withheld() {
    let server = server().await;
    let handle = RedisHandle::open(server.url()).unwrap();
    let canary = "user_01CANARYARGUMENT";
    let body = "SOURCE_CANARY";
    let raised = format!("{canary} raised by the script");

    let cases: [(String, &str, &str, &str); 5] = [
        (
            "return redis.error_reply(ARGV[1])".to_owned(),
            raised.as_str(),
            canary,
            "whose code Redis does not define",
        ),
        (
            "return redis.error_reply('ERR ' .. ARGV[1])".to_owned(),
            canary,
            canary,
            "the server answered ERR",
        ),
        (
            "error(ARGV[1])".to_owned(),
            canary,
            canary,
            "the server answered ERR",
        ),
        (
            "return {1, redis.error_reply('WRONGTYPE ' .. ARGV[1])}".to_owned(),
            canary,
            canary,
            "the server answered WRONGTYPE",
        ),
        (
            format!("return {body} {body}_TWO"),
            canary,
            body,
            "the server answered ERR",
        ),
    ];
    for (script, arg, leaked, summary) in &cases {
        let error = handle
            .eval::<Vec<i64>>(script, &[], &[(*arg).into()], Replay::Never)
            .await
            .expect_err(script);
        assert!(matches!(error, RedisError::Command(_)), "{error:?}");
        let text = raw_error_text(&server, &raw_eval(script, arg)).await;
        assert!(text.contains(leaked), "{script}: Redis quoted it: {text}");
        for rendered in renderings(&error) {
            assert!(!rendered.contains(leaked), "{script}: {rendered}");
            assert!(rendered.contains(summary), "{script}: {rendered}");
        }
    }
}

/// **A server with `EVAL` renamed or disabled echoes the whole command** —
/// `unknown command 'EVAX', with args beginning with: '<script>' '1' '<key>'
/// '<token>'` — and none of it reaches the error, in any rendering or its
/// payload. The proxy renames this one request on its way in, so the
/// shared server is untouched; nothing ran, and the connection stays
/// cached. (Redis echoes about 128 characters of arguments, so the canaries
/// are short.)
#[tokio::test]
async fn a_renamed_eval_echoing_its_arguments_is_withheld() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("K-CANARY");
    let token = "T-CANARY";
    let script = "return 1 --S-CANARY";

    proxy.rewrite_next_request(b"$4\r\nEVAL\r\n", b"$4\r\nEVAX\r\n");
    let error = handle
        .eval::<i64>(script, &[&key], &[token.into()], Replay::Never)
        .await
        .expect_err("EVAX is not a command");
    assert!(matches!(error, RedisError::Command(_)), "{error:?}");
    assert!(!error.is_outcome_unknown());

    let mut renamed = redis::cmd("EVAX");
    renamed.arg(script).arg(1).arg(&key).arg(token);
    let text = raw_error_text(&server, &renamed).await;
    assert!(text.contains("unknown command 'EVAX'"), "{text}");
    for leaked in ["S-CANARY", "K-CANARY", token] {
        assert!(text.contains(leaked), "Redis echoed {leaked}: {text}");
        for rendered in renderings(&error) {
            assert!(!rendered.contains(leaked), "{leaked} in {rendered}");
            assert!(rendered.contains("the server answered ERR"), "{rendered}");
        }
    }

    let one: i64 = handle
        .eval(script, &[&key], &[token.into()], Replay::Never)
        .await
        .expect("the rename was one-shot");
    assert_eq!(one, 1);
    assert_eq!(proxy.accepted(), 1, "an error reply is no reason to redial");
}

/// **A server refusing the handshake echoes the credentials.** Under
/// `?protocol=resp3` redis-rs dials with `HELLO 3 AUTH <user> <password>`;
/// a server with `HELLO` renamed or disabled answers `unknown command …,
/// with args beginning with: '3' 'AUTH' 'alice' '<password>'` (shown first
/// on the probe's own connection). The dial fails as `Connect` carrying
/// none of it, in any rendering or its payload. The proxy renames the
/// handshake's `HELLO` on its way in, so the shared server is untouched.
#[tokio::test]
async fn a_refused_handshake_echoing_the_password_is_withheld() {
    let server = server().await;
    let proxy = Proxy::start(server.url()).await;
    let password = "P-CANARY";
    let mut url = url::Url::parse(&proxy.url()).expect("the proxy URL");
    url.set_username("alice").expect("a user");
    url.set_password(Some(password)).expect("a password");
    url.set_query(Some("protocol=resp3"));

    let mut renamed = redis::cmd("HELXO");
    renamed.arg(3).arg("AUTH").arg("alice").arg(password);
    let text = raw_error_text(&server, &renamed).await;
    assert!(text.contains(password), "Redis echoes the password: {text}");

    proxy.rewrite_next_request(b"$5\r\nHELLO\r\n", b"$5\r\nHELXO\r\n");
    let handle = RedisHandle::open(url.as_str()).expect("a RESP3 URL");
    let error = handle.ping().await.expect_err("the handshake is refused");
    assert!(matches!(error, RedisError::Connect(_)), "{error:?}");
    assert!(!error.is_outcome_unknown());
    for rendered in renderings(&error) {
        assert!(!rendered.contains(password), "{rendered}");
        assert!(rendered.contains("the server answered ERR"), "{rendered}");
    }
    proxy.assert_accepted(1).await;
}

/// Only a Lua `nil` ends a table: `{1, nil, 3}` arrives as `[1]`. A `false`
/// is a nil ELEMENT — `{1, false, 3}` arrives as `[1, nil, 3]` — which
/// `Vec<i64>` refuses, naming where.
#[tokio::test]
async fn a_false_in_a_table_is_a_nil_element_and_only_nil_ends_it() {
    let server = server().await;
    let handle = RedisHandle::open(server.url()).unwrap();

    let error = handle
        .eval::<Vec<i64>>("return {1, false, 3}", &[], &[], Replay::Never)
        .await
        .expect_err("a nil element is not an integer");
    assert!(matches!(error, RedisError::Command(_)), "{error:?}");
    assert!(error.to_string().contains("nil at index 1"), "{error}");

    let ended: Vec<i64> = handle
        .eval("return {1, nil, 3}", &[], &[], Replay::Never)
        .await
        .expect("nil ends the table");
    assert_eq!(ended, [1]);
}

/// **`Replay::Never` on a dead cached connection**: the script is not sent
/// again — the call fails, and the counter shows it never ran — and the
/// next call redials.
#[tokio::test]
async fn eval_under_replay_never_is_not_resent_on_a_fresh_connection() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("eval-never");

    proxy.kill_connections().await;
    let error = handle
        .eval::<i64>(COUNT_SCRIPT, &[&key], &[], Replay::Never)
        .await
        .expect_err("the cached connection is dead");
    assert!(matches!(error, RedisError::Io(_)), "{error:?}");
    assert!(error.is_outcome_unknown());
    assert_eq!(proxy.accepted(), 1, "no fresh connection to re-send it on");
    assert_eq!(raw_get(&server, &key).await, None, "so it never ran");

    let count: i64 = handle
        .eval(COUNT_SCRIPT, &[&key], &[], Replay::Never)
        .await
        .expect("the next call redials");
    assert_eq!(count, 1);
    proxy.assert_accepted(2).await;
    raw(&server, &["DEL", &key]).await;
}

/// **`Replay::OnceOnFreshConnection` on a dead cached connection**: sent once
/// more on a fresh connection, and the caller sees only the answer.
#[tokio::test]
async fn eval_under_replay_once_is_retried_on_a_fresh_connection() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let key = unique_key("eval-once");

    proxy.kill_connections().await;
    let count: i64 = handle
        .eval(COUNT_SCRIPT, &[&key], &[], Replay::OnceOnFreshConnection)
        .await
        .expect("retried on a fresh connection");
    assert_eq!(count, 1);
    proxy.assert_accepted(2).await;
    assert_eq!(
        raw_get(&server, &key).await.as_deref(),
        Some("1"),
        "the attempt on the dead connection never ran; the retry did"
    );
    raw(&server, &["DEL", &key]).await;
}

/// **Why the choice is the caller's.** The script RUNS and its reply is lost:
/// under `Never` it ran once and the caller is told the outcome is unknown;
/// under `OnceOnFreshConnection` it runs a second time, and the caller gets
/// the retry's answer — harmless only for a script written to be replayed,
/// which this counter is not.
#[tokio::test]
async fn a_lost_reply_leaves_one_run_under_never_and_two_under_once() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;
    let (never, once) = (unique_key("lost-never"), unique_key("lost-once"));

    proxy.set_replies(Replies::LoseNext);
    let error = handle
        .eval::<i64>(COUNT_SCRIPT, &[&never], &[], Replay::Never)
        .await
        .expect_err("the reply was lost");
    assert!(error.is_outcome_unknown(), "{error:?}");
    assert_eq!(
        raw_get(&server, &never).await.as_deref(),
        Some("1"),
        "it ran, once"
    );
    assert_eq!(proxy.accepted(), 1, "and was not sent again");

    // The lost reply cost that connection; cache a fresh one.
    handle.ping().await.expect("PONG on a fresh connection");
    proxy.assert_accepted(2).await;

    proxy.set_replies(Replies::LoseNext);
    let count: i64 = handle
        .eval(COUNT_SCRIPT, &[&once], &[], Replay::OnceOnFreshConnection)
        .await
        .expect("answered by the retry");
    assert_eq!(count, 2, "the retry's answer: the script's second run");
    assert_eq!(
        raw_get(&server, &once).await.as_deref(),
        Some("2"),
        "it ran twice"
    );
    proxy.assert_accepted(3).await;
    raw(&server, &["DEL", &never, &once]).await;
}

/// `PING` is `Ok(())` on `PONG`; after the cached connection died it is
/// retried once on a fresh one, so a readiness probe reports whether Redis
/// can be reached now — and while Redis is down, it fails.
#[tokio::test]
async fn ping_answers_and_is_retried_on_a_fresh_connection() {
    let server = server().await;
    let (proxy, handle) = warm_handle(&server).await;

    handle.ping().await.expect("PONG");
    assert_eq!(proxy.accepted(), 1, "on the cached connection");

    proxy.kill_connections().await;
    handle.ping().await.expect("retried on a fresh connection");
    proxy.assert_accepted(2).await;

    proxy.set_refusing(true);
    proxy.kill_connections().await;
    let error = handle.ping().await.expect_err("Redis is down");
    assert!(
        matches!(error, RedisError::Io(_)),
        "the cached connection: {error:?}"
    );
    let error = handle.ping().await.expect_err("still down");
    assert!(matches!(error, RedisError::Connect(_)), "{error:?}");
}
