//! The speech-to-text audio budget against a real Redis (feature
//! `live-tests`): the ticket, the lease, the fence and the meter, their
//! scripts driven directly through `StreamBudget`.
//!
//! Moved from tapper's `tests/voice_stream.rs` (`82be95f`): its lease, fence
//! and meter tests as they were, and the budget half of its relay tests (the
//! upgrade's statuses and the session's close codes are the relay's, tested
//! with it) — every expectation held at the budget's own answer, keys and
//! TTLs:
//!
//! - **the lease** — a takeover is reported; a stale session's refresh and
//!   release never touch the newer lease; charges are cumulative and charged
//!   once; the owner's release deletes; the admission interval;
//! - **the fence** — a ticket issued once before every acquire; a lost ticket
//!   reply, a delayed issue, a delayed acquire, a racing upgrade, the hash's
//!   day, a poisoned fence, each held to "the newest ticket wins, and a stale
//!   one writes nothing";
//! - **the caps** — every spent mask before the admission interval; a user's
//!   month spent by a meter; a calendar crossing charging the new windows;
//! - **the replay policy** — the ticket and the acquire `Never`, the meter
//!   `OnceOnFreshConnection`, each through the fault relay
//!   (`tests/redis_fault`); a grant's origin taken before its round trip;
//! - **validation and writes** — a poisoned key at the acquire or the meter
//!   writes nothing; the ACL cases, including the fence's two-write exception
//!   and the partial states it allows (the README, "Writes, ACLs and the
//!   fence's exception");
//! - **the keys** — exactly the ones the module docs name, and nothing else
//!   under the test's prefix (an app's literal keys are the crate's unit
//!   test, `the_key_shapes_are_tappers_under_tappers_prefixes`).
//!
//! Every test writes only under prefixes of its own (`tests/test_redis`), so
//! two runs of these suites can share one Redis.
//!
//! `require_redis` panics when there is no server — `docker compose up -d
//! redis` — so this suite never passes by skipping (`tests/test_redis`).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use stridelabs_redis::{RedisHandle, RedisOptions, Replay};
use stridelabs_voice::budget::{LimitScope, Spent};
use stridelabs_voice::lease::{
    Grant, MeterMode, StreamBudget, StreamBudgetError, StreamCaps, FENCE_TTL_SECONDS,
    METER_TTL_SECONDS,
};
use tokio::time::Instant;
use uuid::Uuid;

#[allow(
    dead_code,
    reason = "shared with tests/budget.rs; this suite uses the lost-answer, hold, delay and gate \
              faults"
)]
mod redis_fault;
use redis_fault::{within_deadline, EvalFault, RedisRelay};

#[allow(
    dead_code,
    reason = "shared with tests/budget.rs; not every suite seeds every kind of key"
)]
mod test_redis;
use test_redis::{
    assert_fresh_ttl, assert_unchanged, drop_keys_under, expire_soon, key_states, keys_under,
    raw_redis, seed, stream_prefix, test_handle, test_redis_url, AclUser, KeysUnder,
};

/// The caps a test that sets none counts against: both apps' defaults (two
/// hours a user a day; thirty hours a month, the user's and everyone's).
const USER_DAILY_MS: i64 = 120 * 60_000;
const GLOBAL_MONTHLY_MS: i64 = 1_800 * 60_000;

fn default_caps() -> StreamCaps {
    StreamCaps::from_minutes(120, 1_800, 1_800).expect("the default caps are valid")
}

/// A budget under a prefix no other test (and no other suite) counts under.
fn private_budget() -> StreamBudget {
    StreamBudget::new(stream_prefix(), default_caps())
}

/// An acquire as the app's admission makes it: `user`'s next ticket, then
/// the acquire carrying it.
async fn acquire_now(
    budget: &StreamBudget,
    redis: &RedisHandle,
    user: Uuid,
    token: Uuid,
    admit: Duration,
) -> Result<Grant, StreamBudgetError> {
    let ticket = budget.issue_ticket(redis, user).await?;
    budget.acquire(redis, user, token, ticket, admit).await
}

/// Delete every key under `budget`'s prefix.
async fn clean_up(budget: &StreamBudget) {
    drop_keys_under(budget.prefix()).await;
}

/// `user`'s lease token, `None` when there is none.
async fn lease(budget: &StreamBudget, user: Uuid) -> Option<String> {
    raw_redis()
        .await
        .get(budget.lease_key(user))
        .await
        .expect("GET the lease")
}

// ── The lease, directly ──────────────────────────────────────────────────

/// Against the scripts themselves: a takeover is reported; an acquire with
/// the same token again is not a takeover; a stale session's refresh and
/// release never touch the newer lease; charges are cumulative and charged
/// once however often a total is replayed; and the owner's release deletes.
#[tokio::test]
async fn the_lease_compares_before_it_extends_or_deletes() {
    let redis = test_handle().await;
    let budget = private_budget();
    let user = Uuid::new_v4();
    let (stale, fresh) = (Uuid::new_v4(), Uuid::new_v4());
    let lease = |budget: &StreamBudget| budget.lease_key(user);
    let mut raw = raw_redis().await;
    // The admission interval is the next test's; here it is out of the way.
    let admit = Duration::from_millis(1);

    let first = acquire_now(&budget, &redis, user, stale, admit)
        .await
        .expect("acquire");
    assert!(!first.took_over);
    assert_eq!(first.user_day_remaining_ms, USER_DAILY_MS);
    assert_eq!(first.global_remaining_ms, GLOBAL_MONTHLY_MS);
    assert!(
        !acquire_now(&budget, &redis, user, stale, admit)
            .await
            .expect("again")
            .took_over
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(
        acquire_now(&budget, &redis, user, fresh, admit)
            .await
            .expect("takeover")
            .took_over
    );

    // The stale session charges its audio, but extends nothing.
    let pttl_before: i64 = raw.pttl(lease(&budget)).await.expect("PTTL");
    // Far past PTTL's millisecond rounding, so an extension cannot hide in it.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let refreshed = budget
        .meter(&redis, user, stale, 1_500, MeterMode::Refresh)
        .await
        .expect("refresh");
    assert!(!refreshed.held);
    assert_eq!(refreshed.user_day_remaining_ms, USER_DAILY_MS - 1_500);
    let pttl_after: i64 = raw.pttl(lease(&budget)).await.expect("PTTL");
    assert!(
        pttl_after <= pttl_before - 200,
        "the stale refresh extended the new lease: {pttl_before} ms, then {pttl_after} ms"
    );
    let released = budget
        .meter(&redis, user, stale, 1_500, MeterMode::Release)
        .await
        .expect("release");
    assert!(!released.held);
    let held: Option<String> = raw.get(lease(&budget)).await.expect("GET");
    assert_eq!(
        held,
        Some(fresh.to_string()),
        "a stale release deleted the newer lease"
    );

    // Replays charge nothing; a larger total charges the difference.
    for total in [1_500, 1_000, 1_500] {
        let metered = budget
            .meter(&redis, user, stale, total, MeterMode::Refresh)
            .await
            .expect("replay");
        assert_eq!(
            metered.user_day_remaining_ms,
            USER_DAILY_MS - 1_500,
            "{total}"
        );
    }
    let metered = budget
        .meter(&redis, user, fresh, 700, MeterMode::Refresh)
        .await
        .expect("the owner's refresh");
    assert!(metered.held);
    assert_eq!(metered.user_day_remaining_ms, USER_DAILY_MS - 2_200);
    assert_eq!(metered.global_remaining_ms, GLOBAL_MONTHLY_MS - 2_200);
    let pttl: i64 = raw.pttl(lease(&budget)).await.expect("PTTL");
    assert!(
        pttl > 29_000,
        "the owner's refresh extends the lease: {pttl}"
    );

    let released = budget
        .meter(&redis, user, fresh, 700, MeterMode::Release)
        .await
        .expect("the owner's release");
    assert!(released.held);
    let gone: Option<String> = raw.get(lease(&budget)).await.expect("GET");
    assert_eq!(gone, None);
    clean_up(&budget).await;
}

/// The admission interval, against the script: a second TOKEN inside it is
/// [`StreamBudgetError::Throttled`] and writes nothing (the lease stays the
/// first's); the SAME token again — the replay of an acquire whose answer
/// was lost — is admitted; and a spent budget is refused as spent, with its
/// own `Retry-After`, before the interval is consulted.
#[tokio::test]
async fn the_admission_interval_refuses_a_second_token_but_admits_a_replay() {
    let redis = test_handle().await;
    let budget = private_budget();
    let user = Uuid::new_v4();
    let (first, second) = (Uuid::new_v4(), Uuid::new_v4());
    let interval = Duration::from_secs(2);
    let mut raw = raw_redis().await;

    let ticket = budget.issue_ticket(&redis, user).await.expect("a ticket");
    budget
        .acquire(&redis, user, first, ticket, interval)
        .await
        .expect("the first upgrade");
    budget
        .acquire(&redis, user, first, ticket, interval)
        .await
        .expect("a replay of the same acquire (its ticket too) is admitted");
    assert_eq!(
        acquire_now(&budget, &redis, user, second, interval).await,
        Err(StreamBudgetError::Throttled {
            retry_after_seconds: 2
        })
    );
    let held: Option<String> = raw.get(budget.lease_key(user)).await.expect("GET");
    assert_eq!(
        held,
        Some(first.to_string()),
        "a throttled acquire took the lease"
    );

    seed(&mut raw, &budget.user_key(user, Utc::now()), USER_DAILY_MS).await;
    assert!(matches!(
        acquire_now(&budget, &redis, user, second, interval).await,
        Err(StreamBudgetError::Exceeded(limit)) if limit.spent.user_day
    ));
    clean_up(&budget).await;
}

// ── A lost acquire reply is not replayed ─────────────────────────────────

/// What [`race_a_takeover_against_a_lost_reply`] saw.
#[derive(Debug)]
struct LostReplyRace {
    /// The lease's token at the end.
    lease: Option<String>,
    /// How many `EVAL`s session A's handle sent through the relay.
    evals: usize,
    /// How many connections session A's handle opened: one per dial.
    accepted: usize,
    /// Session A's acquire: its `took_over`, or its error rendered.
    outcome: Result<bool, String>,
}

/// The admission interval both sessions acquire with in the race: long
/// enough that waiting it out is a real step of the choreography, short
/// enough to keep the test fast.
const RACE_ADMIT: Duration = Duration::from_millis(50);

/// Wait (up to five seconds) until `user`'s admission key is gone — expired
/// on its own, the way an admission interval ends.
async fn admission_expires(budget: &StreamBudget, user: Uuid) {
    let mut raw = raw_redis().await;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let present: bool = raw.exists(budget.admit_key(user)).await.expect("EXISTS");
        if !present {
            return;
        }
        assert!(Instant::now() < deadline, "the admission key never expired");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The finding the `Replay` choice exists for: session A's acquire writes
/// `user`'s lease, its reply is lost with its CACHED connection, and session
/// B takes the lease over before anything could re-send A's acquire. A
/// replay would then overwrite B — unless the fence refuses it.
///
/// Choreography: A takes its ticket (on a handle of its own, so the fault
/// below meets the acquire), then A's acquire goes through a
/// [`RedisRelay`], warmed so its connection is cached (the only kind a
/// replay retries on); the relay loses the reply to A's next `EVAL` with
/// the connection, and HOLDS every new connection at its gate, so a replay
/// — which must redial — cannot run yet. A's first run lands (the lease is
/// A's). A's admission key is waited out, B takes a ticket and the lease
/// over on a connection of its own, and B's admission key is waited out
/// too — so the real script's admission guard cannot refuse a replay of A,
/// and only the replay policy and the fence decide. Then the gate opens and
/// A's call is awaited: a replay, if there is one, has run. The dial
/// timeout is long so a gated redial waits for the gate rather than failing
/// first.
async fn race_a_takeover_against_a_lost_reply<F, Fut>(
    budget: &StreamBudget,
    user: Uuid,
    a: Uuid,
    attempt: F,
) -> LostReplyRace
where
    F: FnOnce(RedisHandle, u64) -> Fut,
    Fut: std::future::Future<Output = Result<bool, String>> + Send + 'static,
{
    let direct = test_handle().await;
    let ticket = budget
        .issue_ticket(&direct, user)
        .await
        .expect("A's ticket");
    let relay = RedisRelay::start(&test_redis_url().await).await;
    let through_relay = RedisHandle::open_with(
        &relay.url,
        RedisOptions::default().with_dial_timeout(Duration::from_secs(10)),
    )
    .expect("the relay's URL parses");
    through_relay.ping().await.expect("warm A's connection");
    assert_eq!(relay.accepted(), 1, "one warm connection, now cached");

    relay.arm(EvalFault::LoseAnswerAndClose);
    relay.gate();
    let session_a = tokio::spawn(attempt(through_relay.clone(), ticket));

    // A's EVAL has run when the lease is A's (the relay delivers it, reads
    // its reply, and drops the reply with the connection).
    let mut raw = raw_redis().await;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let held: Option<String> = raw.get(budget.lease_key(user)).await.expect("GET");
        if held == Some(a.to_string()) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "A's write never landed: {held:?}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // B takes the lease over on its own connection, once A's admission
    // interval has ended (inside it, B would be refused as throttled).
    admission_expires(budget, user).await;
    let b = Uuid::new_v4();
    let grant = acquire_now(budget, &direct, user, b, RACE_ADMIT)
        .await
        .expect("B takes the lease over");
    assert!(grant.took_over, "B superseded A");
    let admitted: Option<String> = raw.get(budget.admit_key(user)).await.expect("GET");
    assert_eq!(admitted, Some(b.to_string()), "B's admission key is set");
    // ...and B's admission interval ends too, so a replay of A's acquire
    // would pass the script's admission guard rather than be throttled.
    admission_expires(budget, user).await;

    relay.open_gate();
    let outcome = session_a.await.expect("session A's task");
    let lease: Option<String> = raw.get(budget.lease_key(user)).await.expect("GET");
    LostReplyRace {
        lease,
        evals: relay.evals(),
        accepted: relay.accepted(),
        outcome,
    }
}

/// **A lease acquire whose reply was lost is NOT replayed**:
/// `StreamBudget::acquire` is sent under `Replay::Never`, so when its reply
/// is lost with a cached connection, the call fails (the app's `503`) and
/// nothing re-sends it — the script ran ONCE (one `EVAL`, no redial, and A's
/// token was written), and B's takeover after it stands.
///
/// The control is the next test: the same choreography with the same, real
/// acquire sent under `Replay::OnceOnFreshConnection` IS replayed (two
/// `EVAL`s, a redial), so what this one counts is the policy, not the setup.
#[tokio::test]
async fn a_lease_acquire_whose_reply_was_lost_is_not_replayed() {
    within_deadline("the lost-acquire race", async {
        let budget = private_budget();
        let user = Uuid::new_v4();
        let a = Uuid::new_v4();
        let raced = race_a_takeover_against_a_lost_reply(&budget, user, a, {
            let budget = budget.clone();
            move |redis, ticket| async move {
                budget
                    .acquire(&redis, user, a, ticket, RACE_ADMIT)
                    .await
                    .map(|grant| grant.took_over)
                    .map_err(|error| error.to_string())
            }
        })
        .await;

        let error = raced
            .outcome
            .clone()
            .expect_err("a lost reply fails the acquire");
        assert!(
            error.contains("no valid reply from Redis") && error.contains("outcome is unknown"),
            "{error}"
        );
        assert_eq!(raced.evals, 1, "the acquire was sent once: {raced:?}");
        assert_eq!(raced.accepted, 1, "and never redialled for: {raced:?}");
        assert_ne!(
            raced.lease.as_deref(),
            Some(a.to_string().as_str()),
            "A's acquire was replayed over B's takeover: {raced:?}"
        );
        assert!(raced.lease.is_some(), "B holds the lease: {raced:?}");
        clean_up(&budget).await;
    })
    .await;
}

/// The control for [`a_lease_acquire_whose_reply_was_lost_is_not_replayed`]:
/// the same race with the REAL acquire — `ACQUIRE_SCRIPT`, its keys and
/// arguments, through `StreamBudget::acquire_under` — sent under the
/// alternative policy, `Replay::OnceOnFreshConnection`. The replay redials
/// once the gate opens and runs the script a SECOND time, past B's waited-
/// out admission guard.
///
/// Without the fence that replay would overwrite B's lease (and A's call
/// would even report a takeover): why the acquire is sent under `Never`. The
/// replay carries A's ticket, which B's issue made stale: the fence refuses
/// it, writing nothing, and B keeps the lease — the fence covers a replay as
/// well as a late first run. (The negative control: with the fence check
/// removed from the script, this test sees B overwritten.)
#[tokio::test]
async fn the_real_acquire_under_a_replaying_policy_is_refused_by_the_fence() {
    within_deadline("the replayed-acquire race", async {
        let budget = private_budget();
        let user = Uuid::new_v4();
        let a = Uuid::new_v4();
        let raced = race_a_takeover_against_a_lost_reply(&budget, user, a, {
            let budget = budget.clone();
            move |redis, ticket| async move {
                budget
                    .acquire_under(
                        &redis,
                        user,
                        a,
                        ticket,
                        RACE_ADMIT,
                        Replay::OnceOnFreshConnection,
                    )
                    .await
                    .map(|grant| grant.took_over)
                    .map_err(|error| error.to_string())
            }
        })
        .await;

        assert_eq!(
            raced.outcome,
            Err(StreamBudgetError::Stale.to_string()),
            "the replay was refused as stale: {raced:?}"
        );
        assert_eq!(raced.evals, 2, "sent, then replayed: {raced:?}");
        assert_eq!(raced.accepted, 2, "the replay redialled: {raced:?}");
        assert_ne!(
            raced.lease.as_deref(),
            Some(a.to_string().as_str()),
            "the replay overwrote B's takeover: {raced:?}"
        );
        assert!(raced.lease.is_some(), "B holds the lease: {raced:?}");
        clean_up(&budget).await;
    })
    .await;
}

// ── The fence ────────────────────────────────────────────────────────────

/// `user`'s fence hash's `next`, `None` when there is no hash (or no field).
async fn fence_next(budget: &StreamBudget, user: Uuid) -> Option<u64> {
    let mut raw = raw_redis().await;
    raw.hget(budget.fence_key(user), "next")
        .await
        .expect("HGET the fence")
}

/// `user`'s lease, admission and fence keys: what an acquire may write.
fn lease_keys(budget: &StreamBudget, user: Uuid) -> [String; 3] {
    [
        budget.lease_key(user),
        budget.admit_key(user),
        budget.fence_key(user),
    ]
}

/// `budget`'s three counters for `user` at `now`: day, user month, global.
fn counter_keys(budget: &StreamBudget, user: Uuid, now: DateTime<Utc>) -> [String; 3] {
    [
        budget.user_key(user, now),
        budget.user_month_key(user, now),
        budget.global_key(now),
    ]
}

/// Their values, `None` where absent.
async fn counter_values(keys: &[String; 3]) -> [Option<i64>; 3] {
    let mut redis = raw_redis().await;
    let mut values = [None; 3];
    for (value, key) in values.iter_mut().zip(keys) {
        *value = redis.get(key).await.expect("GET");
    }
    values
}

/// **A lost ticket reply is an error, and nothing replays the increment**:
/// the issue (after the admission's `PING`, which leaves the connection
/// cached) has its answer lost with the connection, and — sent under
/// `Replay::Never` — it is not re-sent: one `EVAL`, `next` raised exactly
/// ONCE, no lease. The client's next upgrade takes the next ticket.
///
/// (The negative control: the issue sent under `OnceOnFreshConnection`
/// re-runs it on a fresh dial — two `EVAL`s, `next` raised twice — and,
/// the replay answering, succeeds; this test fails on its first
/// assertions.)
#[tokio::test]
async fn a_lost_ticket_reply_is_an_error_and_nothing_replays_the_increment() {
    within_deadline("a lost ticket reply", async {
        let budget = private_budget();
        let user = Uuid::new_v4();
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let through_relay = RedisHandle::open(&relay.url).expect("the relay's URL parses");
        through_relay.ping().await.expect("the admission's PING");
        relay.arm(EvalFault::LoseAnswerAndClose);
        let issued = budget.issue_ticket(&through_relay, user).await;
        assert!(
            matches!(&issued, Err(StreamBudgetError::Backend(detail)) if detail.contains("outcome is unknown")),
            "{issued:?}"
        );
        assert_eq!(relay.evals(), 1, "the issue alone, sent once");
        assert_eq!(
            fence_next(&budget, user).await,
            Some(1),
            "the increment ran exactly once"
        );
        assert_eq!(lease(&budget, user).await, None);

        let grant = acquire_now(
            &budget,
            &through_relay,
            user,
            Uuid::new_v4(),
            Duration::from_secs(2),
        )
        .await
        .expect("the next upgrade");
        assert!(!grant.took_over);
        assert_eq!(fence_next(&budget, user).await, Some(2));
        clean_up(&budget).await;
    })
    .await;
}

/// **A newer ticket taken mid-upgrade makes the acquire stale, and nothing is
/// written**: an upgrade's issue runs, and before its acquire another
/// upgrade for the same user takes a ticket. The acquire then carries a
/// stale ticket: [`StreamBudgetError::Stale`] (the app's retryable `503`),
/// no lease, no admission key, the fence untouched. The control: the next
/// upgrade, racing nothing, is granted.
#[tokio::test]
async fn a_newer_ticket_taken_mid_upgrade_is_stale_and_writes_nothing() {
    let redis = test_handle().await;
    let budget = private_budget();
    let user = Uuid::new_v4();
    let ticket = budget.issue_ticket(&redis, user).await.expect("a ticket");
    assert_eq!(
        budget.issue_ticket(&redis, user).await,
        Ok(2),
        "the other device"
    );
    let keys = lease_keys(&budget, user);
    let before = key_states(&keys).await;
    assert_eq!(
        budget
            .acquire(&redis, user, Uuid::new_v4(), ticket, Duration::from_secs(2))
            .await,
        Err(StreamBudgetError::Stale)
    );
    assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);
    assert_eq!(before[0].kind, "none", "no lease");
    assert_eq!(before[1].kind, "none", "no admission");

    let token = Uuid::new_v4();
    acquire_now(&budget, &redis, user, token, Duration::from_secs(2))
        .await
        .expect("the next upgrade is granted");
    assert_eq!(lease(&budget, user).await, Some(token.to_string()));
    clean_up(&budget).await;
}

/// **A delayed ISSUE leaves the session it raced alone, and fences the
/// acquire it overtook**. A's issue is held in transit (its call gives up:
/// a `503`), then lands late:
///
/// 1. after B took its ticket but before B's acquire: B's ticket is stale,
///    and B's acquire is refused, writing nothing — B's retry (a new
///    ticket) is granted;
/// 2. after B's grant: only `next` moves. B's session is untouched — its
///    refresh still holds the lease (a session is the lease's TOKEN, not
///    the fence) — and the next upgrade takes the next ticket.
///
/// (The negative control for 1: with the fence check removed from the
/// script, B's stale acquire is granted.)
#[tokio::test]
async fn a_delayed_issue_fences_the_acquire_it_overtook_and_no_session() {
    within_deadline("a delayed issue", async {
        let budget = private_budget();
        let user = Uuid::new_v4();
        let direct = test_handle().await;
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let late = RedisHandle::open(&relay.url).expect("the relay's URL parses");
        late.ping().await.expect("warm");

        // 1. A's issue lands between B's issue and B's acquire.
        relay.arm(EvalFault::Hold);
        let issue_a = tokio::spawn({
            let (budget, late) = (budget.clone(), late.clone());
            async move { budget.issue_ticket(&late, user).await }
        });
        assert!(
            issue_a.await.expect("A's task").is_err(),
            "A's issue gave up: a 503"
        );
        let b = Uuid::new_v4();
        let ticket_b = budget
            .issue_ticket(&direct, user)
            .await
            .expect("B's ticket");
        assert_eq!(ticket_b, 1, "A's issue has not landed yet");
        assert_eq!(relay.release_held().await, 1, "A's issue lands, late");
        assert_eq!(fence_next(&budget, user).await, Some(2));
        let keys = lease_keys(&budget, user);
        let before = key_states(&keys).await;
        assert_eq!(
            budget.acquire(&direct, user, b, ticket_b, RACE_ADMIT).await,
            Err(StreamBudgetError::Stale)
        );
        assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);
        let grant = acquire_now(&budget, &direct, user, b, RACE_ADMIT)
            .await
            .expect("B's retry, with a new ticket");
        assert!(!grant.took_over);

        // 2. Another issue held, landing after B's grant.
        relay.arm(EvalFault::Hold);
        let issue_c = tokio::spawn({
            let (budget, late) = (budget.clone(), late.clone());
            async move { budget.issue_ticket(&late, user).await }
        });
        assert!(issue_c.await.expect("C's task").is_err());
        assert_eq!(relay.release_held().await, 1);
        assert_eq!(fence_next(&budget, user).await, Some(4));
        let refreshed = budget
            .meter(&direct, user, b, 1_000, MeterMode::Refresh)
            .await
            .expect("B's refresh");
        assert!(refreshed.held, "B's session still holds its lease");
        admission_expires(&budget, user).await;
        let next = acquire_now(&budget, &direct, user, Uuid::new_v4(), RACE_ADMIT)
            .await
            .expect("the next upgrade");
        assert!(next.took_over);
        assert_eq!(fence_next(&budget, user).await, Some(5));
        clean_up(&budget).await;
    })
    .await;
}

/// **A delayed ACQUIRE lands stale, and the newer session stands.** The
/// race above with A's acquire HELD in transit instead of answered: A's call
/// gives up (the app's `503`, no session), B takes a ticket and the lease,
/// B's admission interval ends, and only then does A's acquire land —
/// carrying A's ticket, which B's issue made stale. It writes NOTHING: the
/// lease, the admission key and the fence keep their values and expiries,
/// and B's refresh still holds.
///
/// The control, in the same test: the same held acquire with no newer
/// upgrade in between lands and takes the lease — what refused it above is
/// the newer ticket, not the choreography. (The negative control: with the
/// fence check removed from the script, A's late acquire overwrites B.)
#[tokio::test]
async fn a_delayed_acquire_lands_stale_and_the_newer_session_stands() {
    within_deadline("a delayed acquire", async {
        let budget = private_budget();
        let user = Uuid::new_v4();
        let direct = test_handle().await;
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let late = RedisHandle::open(&relay.url).expect("the relay's URL parses");
        late.ping().await.expect("warm");

        let a = Uuid::new_v4();
        let ticket_a = budget
            .issue_ticket(&direct, user)
            .await
            .expect("A's ticket");
        relay.arm(EvalFault::Hold);
        let acquire_a = tokio::spawn({
            let (budget, late) = (budget.clone(), late.clone());
            async move { budget.acquire(&late, user, a, ticket_a, RACE_ADMIT).await }
        });
        assert!(
            matches!(
                acquire_a.await.expect("A's task"),
                Err(StreamBudgetError::Backend(_))
            ),
            "A's acquire gave up: a 503"
        );
        let b = Uuid::new_v4();
        acquire_now(&budget, &direct, user, b, RACE_ADMIT)
            .await
            .expect("B takes the lease");
        admission_expires(&budget, user).await;
        let keys = lease_keys(&budget, user);
        let before = key_states(&keys).await;
        assert_eq!(relay.release_held().await, 1, "A's acquire lands, late");
        assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);
        assert_eq!(before[0].value, Some(b.to_string()), "B's lease");
        let refreshed = budget
            .meter(&direct, user, b, 0, MeterMode::Refresh)
            .await
            .expect("B's refresh");
        assert!(refreshed.held, "B still holds its lease");

        // The control: held, with nobody newer — it lands and takes over.
        admission_expires(&budget, user).await;
        let c = Uuid::new_v4();
        let ticket_c = budget
            .issue_ticket(&direct, user)
            .await
            .expect("C's ticket");
        relay.arm(EvalFault::Hold);
        let acquire_c = tokio::spawn({
            let (budget, late) = (budget.clone(), late.clone());
            async move { budget.acquire(&late, user, c, ticket_c, RACE_ADMIT).await }
        });
        assert!(acquire_c.await.expect("C's task").is_err());
        assert_eq!(relay.release_held().await, 1);
        assert_eq!(
            lease(&budget, user).await,
            Some(c.to_string()),
            "an unfenced late landing"
        );
        clean_up(&budget).await;
    })
    .await;
}

/// **The fence hash's life bounds the guarantee** (one hash, one TTL: a
/// day). An issue sets the day; a GRANT refreshes it; a refusal (here,
/// throttled) does not. Once the hash is gone, an acquire with any ticket
/// is stale and writes nothing — not even a new hash — and the numbering
/// starts again at `1`: an acquire delayed past the hash's life could carry
/// a ticket the new numbering reissues, which the module docs accept (a day
/// is far past any delay in transit).
#[tokio::test]
async fn the_fence_lives_a_day_from_its_last_issue_or_grant() {
    let budget = private_budget();
    let user = Uuid::new_v4();
    let redis = test_handle().await;
    let mut raw = raw_redis().await;
    let fence = budget.fence_key(user);
    let day_ms = FENCE_TTL_SECONDS * 1_000;

    let ticket = budget.issue_ticket(&redis, user).await.expect("a ticket");
    assert_eq!(ticket, 1);
    let pttl: i64 = raw.pttl(&fence).await.expect("PTTL");
    assert!((day_ms - 2_000..=day_ms).contains(&pttl), "{pttl}");

    // A grant refreshes the day.
    let _: bool = raw.pexpire(&fence, 60_000).await.expect("PEXPIRE");
    let a = Uuid::new_v4();
    budget
        .acquire(&redis, user, a, ticket, Duration::from_secs(2))
        .await
        .expect("granted");
    let pttl: i64 = raw.pttl(&fence).await.expect("PTTL");
    assert!(
        (day_ms - 2_000..=day_ms).contains(&pttl),
        "refreshed: {pttl}"
    );

    // A refusal does not (the issue before it does: lowered after it).
    let ticket = budget.issue_ticket(&redis, user).await.expect("a ticket");
    let _: bool = raw.pexpire(&fence, 60_000).await.expect("PEXPIRE");
    let keys = lease_keys(&budget, user);
    let before = key_states(&keys).await;
    assert_eq!(
        budget
            .acquire(&redis, user, Uuid::new_v4(), ticket, Duration::from_secs(2))
            .await,
        Err(StreamBudgetError::Throttled {
            retry_after_seconds: 2
        })
    );
    assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);

    // The hash expires: every ticket is stale, and nothing is created.
    let _: bool = raw.pexpire(&fence, 1).await.expect("PEXPIRE");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let _: i64 = raw.del(budget.admit_key(user)).await.expect("DEL");
    let before = key_states(&keys).await;
    assert_eq!(before[2].kind, "none", "the hash expired");
    for stale in [1, ticket] {
        assert_eq!(
            budget
                .acquire(
                    &redis,
                    user,
                    Uuid::new_v4(),
                    stale,
                    Duration::from_millis(1)
                )
                .await,
            Err(StreamBudgetError::Stale),
            "{stale}"
        );
    }
    assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);

    // The bound: numbering restarts, so a ticket from before the expiry is
    // current again once reissued.
    assert_eq!(budget.issue_ticket(&redis, user).await, Ok(1));
    let late = Uuid::new_v4();
    budget
        .acquire(&redis, user, late, 1, Duration::from_millis(1))
        .await
        .expect("a pre-expiry ticket matches the restarted numbering");
    clean_up(&budget).await;
}

/// **A poisoned fence changes nothing, value or expiry** (validation before
/// any write): a fence that is a STRING or a LIST (the wrong type for
/// `HGET`), or a hash whose `next` is not a canonical integer (`abc`,
/// `007`, `1.5`, `-1`, 16 digits). The issue and the acquire are each a
/// `Backend` error, and every key the acquire reads — the lease, the
/// counters, the admission key and the fence — keeps its type, value and
/// expiry.
///
/// The control: a clean hash at `next = 5` issues `6` with the day's
/// expiry, and an acquire with `6` is granted.
#[tokio::test]
async fn a_poisoned_fence_changes_no_value_and_no_expiry() {
    let budget = private_budget();
    let redis = test_handle().await;
    let mut raw = raw_redis().await;
    for poison in [
        "string",
        "list",
        "abc",
        "007",
        "1.5",
        "-1",
        "1234567890123456",
    ] {
        let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
        let now = Utc::now();
        let fence = budget.fence_key(user);
        match poison {
            "string" => seed(&mut raw, &fence, "5").await,
            "list" => {
                let _: i64 = raw.rpush(&fence, "5").await.expect("RPUSH");
                expire_soon(&mut raw, &fence).await;
            }
            next => {
                let _: i64 = raw.hset(&fence, "next", next).await.expect("HSET");
                expire_soon(&mut raw, &fence).await;
            }
        }
        seed(
            &mut raw,
            &budget.lease_key(user),
            Uuid::new_v4().to_string(),
        )
        .await;
        for counter in counter_keys(&budget, user, now) {
            seed(&mut raw, &counter, 7).await;
        }
        let keys = [
            budget.lease_key(user),
            budget.user_key(user, now),
            budget.user_month_key(user, now),
            budget.global_key(now),
            budget.admit_key(user),
            fence,
        ];
        let before = key_states(&keys).await;
        let issued = budget.issue_ticket(&redis, user).await;
        assert!(
            matches!(issued, Err(StreamBudgetError::Backend(_))),
            "{poison}: {issued:?}"
        );
        assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);
        let acquired = budget
            .acquire(&redis, user, token, 5, Duration::from_millis(1))
            .await;
        assert!(
            matches!(acquired, Err(StreamBudgetError::Backend(_))),
            "{poison}: {acquired:?}"
        );
        assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);
    }

    let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
    let fence = budget.fence_key(user);
    let _: i64 = raw.hset(&fence, "next", "5").await.expect("HSET");
    expire_soon(&mut raw, &fence).await;
    assert_eq!(budget.issue_ticket(&redis, user).await, Ok(6));
    let pttl: i64 = raw.pttl(&fence).await.expect("PTTL");
    assert!(pttl > 120_000, "the day's expiry: {pttl}");
    budget
        .acquire(&redis, user, token, 6, Duration::from_millis(1))
        .await
        .expect("the current ticket is granted");
    clean_up(&budget).await;
}

// ── The user's month and the limit's scope ───────────────────────────────

/// `instant` (RFC 3339), as UTC.
fn at(instant: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(instant)
        .expect("a fixed instant")
        .with_timezone(&Utc)
}

/// A clock a test moves by hand: the day- and month-boundary seam
/// (`StreamBudget::with_clock`).
#[derive(Clone)]
struct TestClock(Arc<Mutex<DateTime<Utc>>>);

impl TestClock {
    fn at(instant: &str) -> TestClock {
        TestClock(Arc::new(Mutex::new(at(instant))))
    }

    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().expect("the clock's lock")
    }

    fn set(&self, instant: &str) {
        *self.0.lock().expect("the clock's lock") = at(instant);
    }

    /// `budget` on this clock.
    fn drive(&self, budget: StreamBudget) -> StreamBudget {
        let clock = self.clone();
        budget.with_clock(move || clock.now())
    }
}

/// Small caps, in ms, so a window is spent with a small seed: a day of 100 s,
/// a user's month of 200 s, everyone's month of 300 s.
const SMALL_CAPS: StreamCaps = StreamCaps::unchecked(100_000, 200_000, 300_000);

/// A private budget with [`SMALL_CAPS`] on `clock`.
fn small_budget(clock: &TestClock) -> StreamBudget {
    clock.drive(StreamBudget::new(stream_prefix(), SMALL_CAPS))
}

/// **Every spent-window mask the acquire can answer, `1` to `7`** (the user's
/// month is bit `4`, and THROTTLED is the sentinel `-2`), against the real
/// script, mid-month and on a month's last day: each window in the mask is
/// at its cap, the others not, and the acquire is refused with exactly those
/// windows and the table's scope — whether or not ANOTHER upgrade was
/// admitted just now (the budgets come before the admission interval:
/// throttle precedence) — and writes nothing: the lease (another
/// session's), the admission key, the counters and the fence, values and
/// expiries alike.
///
/// The controls: mask `0` with no other admission is a grant — the lease
/// and the admission key are this token's, the fence's expiry refreshed,
/// each window's remainder is its cap less its counter, and the takeover is
/// reported; mask `0` with another admission is THROTTLED, writing nothing.
#[tokio::test]
async fn every_spent_mask_is_refused_at_the_acquire_before_the_admission_interval() {
    use LimitScope::{GlobalMonth, UserDay, UserMonth};
    let redis = test_handle().await;
    let scopes = [
        UserDay,
        GlobalMonth,
        GlobalMonth,
        UserMonth,
        UserMonth,
        UserMonth,
        UserMonth,
    ];
    let admit = Duration::from_secs(2);
    for (when, day_resets, month_resets) in [
        (
            "2026-10-17T12:00:00Z",
            "2026-10-18T00:00:00Z",
            "2026-11-01T00:00:00Z",
        ),
        (
            "2026-10-31T18:00:00Z",
            "2026-11-01T00:00:00Z",
            "2026-11-01T00:00:00Z",
        ),
    ] {
        let clock = TestClock::at(when);
        let now = clock.now();
        for admitted_elsewhere in [false, true] {
            for mask in 0..=7_i64 {
                let budget = small_budget(&clock);
                let (user, token, other) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
                let [day, month, global] = counter_keys(&budget, user, now);
                let keys = [
                    budget.lease_key(user),
                    day.clone(),
                    month.clone(),
                    global.clone(),
                    budget.admit_key(user),
                    budget.fence_key(user),
                ];
                let mut raw = raw_redis().await;
                seed(&mut raw, &keys[0], other.to_string()).await;
                if admitted_elsewhere {
                    seed(&mut raw, &keys[4], other.to_string()).await;
                }
                for (key, bit, cap) in [
                    (&day, 1, SMALL_CAPS.user_day_ms()),
                    (&month, 4, SMALL_CAPS.user_month_ms()),
                    (&global, 2, SMALL_CAPS.global_month_ms()),
                ] {
                    if mask & bit != 0 {
                        seed(&mut raw, key, cap).await;
                    } else {
                        seed(&mut raw, key, 1_000).await;
                    }
                }
                // The ticket first, so the refusals below are held to the
                // fence too (a refusal writes nothing there either; only a
                // grant refreshes its expiry).
                let ticket = budget.issue_ticket(&redis, user).await.expect("a ticket");
                let _: bool = raw.expire(&keys[5], 600).await.expect("EXPIRE");
                let before = key_states(&keys).await;
                let acquired = budget.acquire(&redis, user, token, ticket, admit).await;
                let case = format!("{when}, mask {mask}, admitted elsewhere {admitted_elsewhere}");
                match (mask, admitted_elsewhere) {
                    (0, false) => {
                        let grant =
                            acquired.unwrap_or_else(|refused| panic!("{case}: {refused:?}"));
                        assert_eq!(
                            grant,
                            Grant {
                                user_day_remaining_ms: 99_000,
                                user_month_remaining_ms: 199_000,
                                global_remaining_ms: 299_000,
                                took_over: true,
                                at: now,
                                origin: grant.origin,
                            },
                            "{case}"
                        );
                        let after = key_states(&keys).await;
                        assert_eq!(after[0].value, Some(token.to_string()), "{case}");
                        assert_eq!(after[4].value, Some(token.to_string()), "{case}");
                        assert!(
                            after[5].pttl > 600_000,
                            "{case}: the grant refreshed the fence: {:?}",
                            after[5]
                        );
                    }
                    (0, true) => {
                        assert_eq!(
                            acquired,
                            Err(StreamBudgetError::Throttled {
                                retry_after_seconds: 2
                            }),
                            "{case}"
                        );
                        assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);
                    }
                    _ => {
                        let scope = scopes[usize::try_from(mask - 1).expect("1..=7")];
                        let Err(StreamBudgetError::Exceeded(limit)) = acquired else {
                            panic!("{case}: {acquired:?}");
                        };
                        assert_eq!(
                            limit.spent,
                            Spent {
                                user_day: mask & 1 != 0,
                                user_month: mask & 4 != 0,
                                global_month: mask & 2 != 0,
                            },
                            "{case}"
                        );
                        assert_eq!(limit.scope, scope, "{case}");
                        let resets = if scope == UserDay {
                            day_resets
                        } else {
                            month_resets
                        };
                        assert_eq!(limit.resets_at, at(resets), "{case}");
                        assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);
                    }
                }
                clean_up(&budget).await;
            }
        }
    }
}

/// **A user's month exhausted mid-session is reported with its scope**: the
/// meter charges the user's month too and answers its remainder. The grant
/// saw a whole month; then the month is all but spent elsewhere (seeded
/// after the grant), and a refresh charging half a second of audio spends
/// it: `held`, the user's month's remainder negative, `limit_reached` scoped
/// `user_month`, resetting at the first of next month, and the half second
/// charged to all three windows. (The relay's `error{limit}` and `4002` are
/// its own tests.) The control: the same refresh with the month left alone
/// spends nothing.
#[tokio::test]
async fn a_users_month_spent_by_a_meter_is_reported_with_its_scope() {
    let redis = test_handle().await;
    let clock = TestClock::at("2026-10-17T12:00:00Z");
    let now = clock.now();
    let budget = small_budget(&clock);
    let admit = Duration::from_millis(1);

    let (control_user, control_token) = (Uuid::new_v4(), Uuid::new_v4());
    acquire_now(&budget, &redis, control_user, control_token, admit)
        .await
        .expect("the control's grant");
    let control = budget
        .meter(&redis, control_user, control_token, 500, MeterMode::Refresh)
        .await
        .expect("the control's refresh");
    assert_eq!(control.limit_reached(), None, "nothing spent");

    let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
    let keys = counter_keys(&budget, user, now);
    let grant = acquire_now(&budget, &redis, user, token, admit)
        .await
        .expect("a grant");
    assert_eq!(grant.user_month_remaining_ms, SMALL_CAPS.user_month_ms());
    seed(
        &mut raw_redis().await,
        &keys[1],
        SMALL_CAPS.user_month_ms() - 100,
    )
    .await;
    let metered = budget
        .meter(&redis, user, token, 500, MeterMode::Refresh)
        .await
        .expect("a refresh");
    assert!(metered.held);
    assert_eq!(metered.user_month_remaining_ms, -400);
    let limit = metered.limit_reached().expect("the month is spent");
    assert_eq!(
        limit.spent,
        Spent {
            user_month: true,
            ..Spent::default()
        }
    );
    assert_eq!(limit.scope, LimitScope::UserMonth);
    assert_eq!(limit.resets_at, at("2026-11-01T00:00:00Z"));
    assert_eq!(
        counter_values(&keys).await,
        [
            Some(500),
            Some(SMALL_CAPS.user_month_ms() + 400),
            Some(1_000)
        ],
        "the half second, charged to every window (everyone's month holds the control's too)"
    );
    clean_up(&budget).await;
}

/// **A calendar crossing charges the new windows and leaves the old ones**
/// ("monthly" means EXHAUSTING a month's allowance, never crossing it). A
/// grant at 23:59:59 on the month's last day sees three seconds of the
/// user's month left; the clock then crosses into the new month, and the
/// refresh charges the NEW month's (and day's) counters, which have room:
/// nothing is spent. The old month's counter is untouched, and the release
/// charges only what is new.
#[tokio::test]
async fn a_calendar_crossing_charges_the_new_windows_and_leaves_the_old_ones() {
    let redis = test_handle().await;
    let clock = TestClock::at("2026-10-31T23:59:59Z");
    let budget = small_budget(&clock);
    let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
    let october = counter_keys(&budget, user, clock.now());
    seed(
        &mut raw_redis().await,
        &october[1],
        SMALL_CAPS.user_month_ms() - 3_000,
    )
    .await;
    let grant = acquire_now(&budget, &redis, user, token, Duration::from_millis(1))
        .await
        .expect("a grant");
    assert_eq!(grant.user_month_remaining_ms, 3_000);

    clock.set("2026-11-01T00:00:01Z");
    let november = counter_keys(&budget, user, clock.now());
    let metered = budget
        .meter(&redis, user, token, 2_500, MeterMode::Refresh)
        .await
        .expect("a refresh");
    assert_eq!(metered.limit_reached(), None, "the new month has room");
    assert_eq!(
        metered.user_month_remaining_ms,
        SMALL_CAPS.user_month_ms() - 2_500
    );
    let released = budget
        .meter(&redis, user, token, 2_500, MeterMode::Release)
        .await
        .expect("the release");
    assert!(released.held);
    assert_eq!(
        counter_values(&november).await,
        [Some(2_500), Some(2_500), Some(2_500)],
        "the audio is the new month's (and the new day's), charged once"
    );
    assert_eq!(
        counter_values(&october).await,
        [None, Some(SMALL_CAPS.user_month_ms() - 3_000), None],
        "the old month is untouched"
    );
    clean_up(&budget).await;
}

/// **A grant's origin is taken before its acquire is sent**: the windows'
/// instant (`at`, the budget's clock) and its monotonic twin (`origin`) are
/// read together, BEFORE the round trip, so a deadline the relay derives
/// from them counts the acquire's own time (a slow acquire near a reset must
/// not bind a window that has already reset). Through the fault relay the
/// acquire's answer takes 200 ms: the origin is from before it.
///
/// The control (a mutation, run): an origin captured after the acquire
/// answered is under 200 ms old here, and the assertion fails.
#[tokio::test]
async fn a_grants_origin_is_taken_before_its_acquire_is_sent() {
    within_deadline("a slow acquire", async {
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let through_relay = RedisHandle::open(&relay.url).expect("the relay's URL parses");
        let clock = TestClock::at("2026-10-31T23:59:59.700Z");
        let budget = small_budget(&clock);
        let user = Uuid::new_v4();
        let ticket = budget
            .issue_ticket(&through_relay, user)
            .await
            .expect("a ticket");
        relay.arm(EvalFault::DelayAnswer(Duration::from_millis(200)));
        let sent = Instant::now();
        let grant = budget
            .acquire(
                &through_relay,
                user,
                Uuid::new_v4(),
                ticket,
                Duration::from_millis(1),
            )
            .await
            .expect("a grant");
        let answered = Instant::now();
        assert!(
            answered.duration_since(sent) >= Duration::from_millis(200),
            "premise: the acquire took 200 ms"
        );
        assert_eq!(grant.at, clock.now(), "the budget clock's instant");
        assert!(grant.origin >= sent, "{:?} before {sent:?}", grant.origin);
        assert!(
            answered.duration_since(grant.origin) >= Duration::from_millis(200),
            "the origin is from before the round trip: {:?}",
            answered.duration_since(grant.origin)
        );
        clean_up(&budget).await;
    })
    .await;
}

// ── Validation before any write ──────────────────────────────────────────

/// **A poisoned key changes nothing, value or expiry, at the acquire or the
/// meter** (both scripts read three counters, and validate every key and
/// argument before any write). Each key a script reads is made a LIST (the
/// wrong type) — the lease, each counter, the admission key or the session
/// meter — and each counter also a non-integer, while the rest hold clean
/// values with the seeded two-minute expiry. Every call is a `Backend` error
/// and EVERY key keeps its type, value and expiry, for a refresh and a
/// release alike.
///
/// The control: the same keys clean, the acquire writes the lease and the
/// admission key, and the meter writes the counters, the meter and the
/// lease's expiry — what the check above would have caught.
#[tokio::test]
async fn a_poisoned_key_at_the_acquire_or_the_meter_changes_no_value_and_no_expiry() {
    let redis = test_handle().await;
    let clock = TestClock::at("2026-10-17T12:00:00Z");
    let now = clock.now();
    let budget = small_budget(&clock);
    let admit = Duration::from_millis(50);
    let mut raw = raw_redis().await;
    for poisoned in 0..5 {
        for poison in ["list", "1.5", "007"] {
            // The lease, the admission key and the meter: their TYPE is what
            // the scripts validate (the lease and admission key hold tokens).
            let counter = (1..=3).contains(&poisoned);
            if !counter && poison != "list" {
                continue;
            }
            let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
            let [day, month, global] = counter_keys(&budget, user, now);
            let acquire_keys = [
                budget.lease_key(user),
                day.clone(),
                month.clone(),
                global.clone(),
                budget.admit_key(user),
            ];
            let meter_keys = [
                budget.lease_key(user),
                day,
                month,
                global,
                budget.meter_key(token),
            ];
            for (script, keys) in [("acquire", &acquire_keys), ("meter", &meter_keys)] {
                for mode in [MeterMode::Refresh, MeterMode::Release] {
                    for (index, key) in keys.iter().enumerate() {
                        let _: i64 = raw.del(key).await.expect("DEL");
                        if index == poisoned {
                            if poison == "list" {
                                let _: i64 = raw.rpush(key, "not a counter").await.expect("RPUSH");
                                expire_soon(&mut raw, key).await;
                            } else {
                                seed(&mut raw, key, poison).await;
                            }
                        } else if index == 0 {
                            // The lease: this session's, so a meter would
                            // touch it.
                            seed(&mut raw, key, token.to_string()).await;
                        } else if index < 4 {
                            seed(&mut raw, key, 7).await;
                        } else if script == "meter" {
                            seed(&mut raw, key, 5).await;
                        }
                    }
                    let before = key_states(keys).await;
                    let answered = if script == "acquire" {
                        acquire_now(&budget, &redis, user, token, admit)
                            .await
                            .map(|_| ())
                    } else {
                        budget
                            .meter(&redis, user, token, 1_000, mode)
                            .await
                            .map(|_| ())
                    };
                    let case = format!("{script} {mode:?}: key {poisoned} = {poison}");
                    assert!(
                        matches!(answered, Err(StreamBudgetError::Backend(_))),
                        "{case}: {answered:?}"
                    );
                    assert_unchanged(keys, &before, &key_states(keys).await, 2_000);
                }
            }
        }
    }

    // The controls: clean keys, and each script writes.
    let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
    let [day, month, global] = counter_keys(&budget, user, now);
    for key in [&day, &month, &global] {
        let _: i64 = raw.del(key).await.expect("DEL");
        seed(&mut raw, key, 7).await;
    }
    acquire_now(&budget, &redis, user, token, admit)
        .await
        .expect("clean keys: a grant");
    let lease = key_states(&[budget.lease_key(user), budget.admit_key(user)]).await;
    assert_eq!(lease[0].value, Some(token.to_string()));
    assert_eq!(lease[1].value, Some(token.to_string()));
    let metered = budget
        .meter(&redis, user, token, 1_000, MeterMode::Refresh)
        .await
        .expect("clean keys: charged");
    assert!(metered.held);
    let after = key_states(&[day, month, global, budget.meter_key(token)]).await;
    for (state, value) in after.iter().zip(["1007", "1007", "1007", "1000"]) {
        assert_eq!(state.value.as_deref(), Some(value), "{state:?}");
        assert!(state.pttl > 120_000, "the expiry was set: {state:?}");
    }
    clean_up(&budget).await;
}

/// A Redis that is down is found out at every call: the ticket, the acquire
/// and the meter are each `Backend` (the app's retryable `503`, or a failed
/// refresh), naming the failure's class only. Admission FAILS CLOSED.
#[tokio::test]
async fn a_redis_that_is_down_is_a_backend_error_at_every_call() {
    let down = RedisHandle::open("redis://127.0.0.1:1").expect("the URL parses");
    let budget = private_budget();
    let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
    let refusals = [
        budget.issue_ticket(&down, user).await.map(|_| ()),
        budget
            .acquire(&down, user, token, 1, Duration::from_secs(2))
            .await
            .map(|_| ()),
        budget
            .meter(&down, user, token, 1_000, MeterMode::Refresh)
            .await
            .map(|_| ()),
        budget
            .meter(&down, user, token, 1_000, MeterMode::Release)
            .await
            .map(|_| ()),
    ];
    for refused in refusals {
        let Err(StreamBudgetError::Backend(detail)) = &refused else {
            panic!("{refused:?}");
        };
        assert!(detail.starts_with("could not connect to Redis"), "{detail}");
        assert!(!detail.contains(&user.to_string()), "{detail}");
    }
}

/// **The keys a session writes, and nothing else**: an acquire, a refresh
/// and a release under a prefix of this test's own, on a fixed clock, write
/// exactly the lease, the admission key, the fence (a hash, `next` = the
/// ticket), the user's day, the user's month, everyone's month and the
/// session meter — named as the module docs say — and the prefix holds NO
/// other key (the whole prefix is compared, so any extra write fails it); the
/// release leaves all but the lease. (The literal key strings under tapper's
/// and lumen's own prefixes are the unit test
/// `the_key_shapes_are_tappers_under_tappers_prefixes`, which needs no
/// Redis: a live test never writes under an app's prefix.) The admission
/// interval is long enough that its key outlives the test.
#[tokio::test]
async fn the_stream_keys_are_dated_and_nothing_else_is_written() {
    let redis = test_handle().await;
    let clock = TestClock::at("2031-03-15T12:00:00Z");
    let prefix = stream_prefix();
    // The fence lives a day and the month's keys weeks, on this clock.
    let _keys = KeysUnder::guard(&prefix).await;
    let budget = clock.drive(StreamBudget::new(prefix.clone(), default_caps()));
    let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
    acquire_now(&budget, &redis, user, token, Duration::from_secs(30))
        .await
        .expect("a grant");
    budget
        .meter(&redis, user, token, 1_000, MeterMode::Refresh)
        .await
        .expect("a refresh");
    let mut expected = vec![
        format!("{prefix}:admit:{user}"),
        format!("{prefix}:fence:{user}"),
        format!("{prefix}:global:2031-03"),
        format!("{prefix}:lease:{user}"),
        format!("{prefix}:session:{token}"),
        format!("{prefix}:user-month:{user}:2031-03"),
        format!("{prefix}:user:{user}:2031-03-15"),
    ];
    expected.sort();
    assert_eq!(keys_under(&prefix).await, expected);
    let fence = key_states(&[budget.fence_key(user)]).await;
    assert_eq!(fence[0].kind, "hash");
    assert_eq!(fence[0].value.as_deref(), Some("next=1"));
    assert!(fence[0].pttl > (FENCE_TTL_SECONDS - 2) * 1_000, "{fence:?}");
    let meter = key_states(&[budget.meter_key(token)]).await;
    assert_eq!(meter[0].value.as_deref(), Some("1000"));
    assert_fresh_ttl(meter[0].pttl, METER_TTL_SECONDS, "the session meter");
    budget
        .meter(&redis, user, token, 1_000, MeterMode::Release)
        .await
        .expect("a release");
    expected.retain(|key| !key.contains(":lease:"));
    assert_eq!(keys_under(&prefix).await, expected);
}

// ── Write permissions (ACLs) and the fence's two writes ─────────────────

/// The meter as it was before the user's month (tapper `f92e3e5`), verbatim:
/// two counters, `INCRBY` then `EXPIRE`, the lease's `PEXPIRE`; `KEYS = lease
/// user-day global-month session-meter`, `ARGV = token total_ms release
/// lease_ttl_ms user_cap_ms global_cap_ms user_ttl_s global_ttl_s
/// meter_ttl_s`. The write-permission test's control: what one command per
/// key prevents.
const OLD_METER_SCRIPT: &str = "\
local function counter(key)
  local value = redis.call('GET', key)
  if not value then
    return 0
  end
  if string.len(value) <= 15 and (value == '0' or string.match(value, '^[1-9]%d*$')) then
    return tonumber(value)
  end
  return nil
end
local user = counter(KEYS[2])
local global = counter(KEYS[3])
local metered = counter(KEYS[4])
if not user or not global or not metered then
  return {-1, 0, 0}
end
local held = redis.call('GET', KEYS[1]) == ARGV[1]
local delta = tonumber(ARGV[2]) - metered
if delta > 0 then
  user = redis.call('INCRBY', KEYS[2], delta)
  redis.call('EXPIRE', KEYS[2], ARGV[7])
  global = redis.call('INCRBY', KEYS[3], delta)
  redis.call('EXPIRE', KEYS[3], ARGV[8])
  redis.call('SET', KEYS[4], ARGV[2], 'EX', ARGV[9])
end
local answer = 0
if held then
  answer = 1
  if ARGV[3] == '1' then
    redis.call('DEL', KEYS[1])
  else
    redis.call('PEXPIRE', KEYS[1], ARGV[4])
  end
end
return {answer, tonumber(ARGV[5]) - user, tonumber(ARGV[6]) - global}
";

/// The old meter's refresh (or release) of session `token`'s audio up to
/// `total_ms`: its reply.
async fn old_meter(
    redis: &RedisHandle,
    budget: &StreamBudget,
    (user, token): (Uuid, Uuid),
    total_ms: u64,
    release: bool,
    now: DateTime<Utc>,
) -> Result<Vec<i64>, stridelabs_redis::RedisError> {
    let token_text = token.to_string();
    redis
        .eval(
            OLD_METER_SCRIPT,
            &[
                &budget.lease_key(user),
                &budget.user_key(user, now),
                &budget.global_key(now),
                &budget.meter_key(token),
            ],
            &[
                (&token_text).into(),
                total_ms.into(),
                u64::from(release).into(),
                30_000_i64.into(),
                USER_DAILY_MS.into(),
                GLOBAL_MONTHLY_MS.into(),
                43_200_i64.into(),
                1_296_000_i64.into(),
                3_600_i64.into(),
            ],
            Replay::OnceOnFreshConnection,
        )
        .await
}

/// **A denied write permission charges everything or nothing at the meter.**
/// The meter's writes are `SET … EX` per counter and the meter, `SET … PX` to
/// refresh the lease (never `INCRBY`, `EXPIRE` or `PEXPIRE`), and the
/// release's `DEL` LAST:
///
/// - a user allowed `SET` but not `EXPIRE`/`PEXPIRE` (nor `INCRBY`) has its
///   refresh charged to all three windows, each with its expiry, and its
///   lease extended;
/// - a user allowed no `SET` is refused with NOTHING written;
/// - a user allowed `SET` but not `DEL` has its release CHARGED and the
///   lease left to expire — the state a failed release leaves anyway.
///
/// The control: the meter as it was before (`INCRBY` then `EXPIRE`), under
/// the first user, leaves a partial charge: the day charged with NO expiry,
/// everyone's month untouched.
#[tokio::test]
async fn a_write_permission_allows_every_meter_write_or_refuses_before_any() {
    let clock = TestClock::at("2026-10-17T12:00:00Z");
    let now = clock.now();
    let budget = small_budget(&clock);
    let prefix = budget.prefix().to_string();
    // The control's day counter has no expiry: deleted however the test ends.
    let _keys = KeysUnder::guard(&prefix).await;
    let no_expire = AclUser::create(&prefix, &["+eval", "+get", "+set", "+incrby", "+del"]).await;
    let no_set = AclUser::create(&prefix, &["+eval", "+get", "+del"]).await;
    let no_del = AclUser::create(&prefix, &["+eval", "+get", "+set"]).await;
    let mut raw = raw_redis().await;
    let day_ttl = 12 * 3_600 + 3_600;
    let month_ttl = 14 * 86_400 + 12 * 3_600 + 86_400;

    // Allowed SET: the refresh charges all three and extends the lease.
    let handle = no_expire.handle();
    let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
    seed(&mut raw, &budget.lease_key(user), token.to_string()).await;
    let metered = budget
        .meter(&handle, user, token, 1_000, MeterMode::Refresh)
        .await
        .expect("SET is allowed");
    assert!(metered.held);
    let keys = counter_keys(&budget, user, now);
    let states = key_states(&keys).await;
    for (state, ttl) in states.iter().zip([day_ttl, month_ttl, month_ttl]) {
        assert_eq!(state.value.as_deref(), Some("1000"), "{state:?}");
        assert_fresh_ttl(state.pttl, ttl, "an expiry with every write");
    }
    let lease = key_states(&[budget.lease_key(user)]).await;
    assert!(lease[0].pttl > 25_000, "the lease extended: {lease:?}");

    // Denied SET: nothing written.
    let handle = no_set.handle();
    let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
    seed(&mut raw, &budget.lease_key(user), token.to_string()).await;
    let mut all = counter_keys(&budget, user, now).to_vec();
    all.extend([budget.meter_key(token), budget.lease_key(user)]);
    let before = key_states(&all).await;
    let refused = budget
        .meter(&handle, user, token, 1_000, MeterMode::Refresh)
        .await;
    assert!(
        matches!(refused, Err(StreamBudgetError::Backend(_))),
        "{refused:?}"
    );
    assert_unchanged(&all, &before, &key_states(&all).await, 2_000);

    // Denied DEL: the release is charged; the lease is left to expire.
    // (Everyone's month is shared with the users above: the release adds
    // its second to what is there.)
    let handle = no_del.handle();
    let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
    seed(&mut raw, &budget.lease_key(user), token.to_string()).await;
    let keys = counter_keys(&budget, user, now);
    let global_before = counter_values(&keys).await[2].unwrap_or(0);
    let refused = budget
        .meter(&handle, user, token, 1_000, MeterMode::Release)
        .await;
    assert!(refused.is_err(), "DEL is denied: {refused:?}");
    assert_eq!(
        counter_values(&keys).await,
        [Some(1_000), Some(1_000), Some(global_before + 1_000)],
        "the audio was charged"
    );
    let lease = key_states(&[budget.lease_key(user)]).await;
    assert_eq!(lease[0].value, Some(token.to_string()));
    assert!(lease[0].pttl > 0, "it still expires: {lease:?}");

    // The control: the older meter under the user denied EXPIRE.
    let handle = no_expire.handle();
    let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
    seed(&mut raw, &budget.lease_key(user), token.to_string()).await;
    let global_before = key_states(&[budget.global_key(now)]).await;
    let refused = old_meter(&handle, &budget, (user, token), 1_000, false, now).await;
    assert!(refused.is_err(), "EXPIRE is denied: {refused:?}");
    let states = key_states(&[budget.user_key(user, now), budget.global_key(now)]).await;
    assert_eq!(
        states[0].value.as_deref(),
        Some("1000"),
        "the old meter charged the day anyway"
    );
    assert_eq!(states[0].pttl, -1, "with no expiry");
    assert_eq!(
        states[1].value, global_before[0].value,
        "and never reached everyone's month"
    );
}

/// **A denied `EXPIRE` grants nothing at the acquire** (the fence's expiry
/// refresh is the grant's FIRST write). A user allowed every other command
/// the acquire sends but not `EXPIRE` is refused with the lease, the
/// admission key, the counters and the fence untouched. The issue under the
/// same user raises `next` and then fails: the accepted partial write — the
/// ticket is never answered, so never used, and a raised `next` only makes
/// older tickets stale.
///
/// The control: allowed `EXPIRE`, the same acquire is granted.
#[tokio::test]
async fn a_denied_fence_expiry_grants_nothing() {
    let budget = private_budget();
    let prefix = budget.prefix().to_string();
    // A denied issue leaves the fence raised: deleted however the test ends.
    let _keys = KeysUnder::guard(&prefix).await;
    let no_expire = AclUser::create(&prefix, &["+eval", "+get", "+set", "+hget", "+hincrby"]).await;
    let allowed = AclUser::create(
        &prefix,
        &["+eval", "+get", "+set", "+hget", "+hincrby", "+expire"],
    )
    .await;
    let direct = test_handle().await;
    let denied = no_expire.handle();
    let user = Uuid::new_v4();
    let ticket = budget.issue_ticket(&direct, user).await.expect("a ticket");
    let mut keys = lease_keys(&budget, user).to_vec();
    keys.extend(counter_keys(&budget, user, Utc::now()));
    let before = key_states(&keys).await;
    let refused = budget
        .acquire(
            &denied,
            user,
            Uuid::new_v4(),
            ticket,
            Duration::from_millis(1),
        )
        .await;
    assert!(
        matches!(refused, Err(StreamBudgetError::Backend(_))),
        "{refused:?}"
    );
    assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);

    let issued = budget.issue_ticket(&denied, user).await;
    assert!(issued.is_err(), "EXPIRE is denied: {issued:?}");
    assert_eq!(
        fence_next(&budget, user).await,
        Some(2),
        "raised, unanswered"
    );

    acquire_now(
        &budget,
        &allowed.handle(),
        user,
        Uuid::new_v4(),
        Duration::from_millis(1),
    )
    .await
    .expect("allowed EXPIRE: granted");
}

/// **The fence's `EXPIRE` denied at the ISSUE raises `next` and writes
/// nothing else** (the fence's documented two-write exception: `HINCRBY`
/// then `EXPIRE`). Under a user denied `EXPIRE`:
///
/// - a NEW hash: the issue is `Backend` (the app's `503`), `next` is `1`
///   with NO expiry, and no lease, admission key, counter or session meter
///   exists;
/// - an EXISTING hash (its expiry lowered to ten minutes, so a refresh would
///   show): `next` is raised by one and keeps its expiry.
///
/// Then with `EXPIRE` allowed again, the next issue answers `next + 1` and
/// restores the day's expiry. (The negative control is the allowed issue
/// itself: it does refresh the expiry, which the denied one did not.)
#[tokio::test]
async fn the_fence_expire_denial_at_issue_raises_next_and_writes_nothing_else() {
    let budget = private_budget();
    let prefix = budget.prefix().to_string();
    // The denied issue leaves a fence hash with NO expiry: deleted however
    // the test ends, before that state exists.
    let _keys = KeysUnder::guard(&prefix).await;
    let no_expire = AclUser::create(
        &prefix,
        &["+eval", "+get", "+set", "+hget", "+hincrby", "+del"],
    )
    .await;
    let denied = no_expire.handle();
    let direct = test_handle().await;
    let mut raw = raw_redis().await;
    let token = Uuid::new_v4();
    let day_ms = FENCE_TTL_SECONDS * 1_000;

    // A new hash.
    let user = Uuid::new_v4();
    let fence = budget.fence_key(user);
    let issued = budget.issue_ticket(&denied, user).await;
    assert!(
        matches!(issued, Err(StreamBudgetError::Backend(_))),
        "{issued:?}"
    );
    assert_eq!(fence_next(&budget, user).await, Some(1), "next is raised");
    let pttl: i64 = raw.pttl(&fence).await.expect("PTTL");
    assert_eq!(pttl, -1, "a new hash keeps no expiry");
    let mut others = vec![
        budget.lease_key(user),
        budget.admit_key(user),
        budget.meter_key(token),
    ];
    others.extend(counter_keys(&budget, user, Utc::now()));
    for state in key_states(&others).await {
        assert_eq!(state.kind, "none", "nothing else was written: {state:?}");
    }
    assert_eq!(
        budget.issue_ticket(&direct, user).await,
        Ok(2),
        "allowed again: next + 1"
    );
    let pttl: i64 = raw.pttl(&fence).await.expect("PTTL");
    assert!(
        (day_ms - 2_000..=day_ms).contains(&pttl),
        "restored: {pttl}"
    );

    // An existing hash.
    let user = Uuid::new_v4();
    let fence = budget.fence_key(user);
    assert_eq!(budget.issue_ticket(&direct, user).await, Ok(1));
    let _: bool = raw.pexpire(&fence, 600_000).await.expect("PEXPIRE");
    let before: i64 = raw.pttl(&fence).await.expect("PTTL");
    let issued = budget.issue_ticket(&denied, user).await;
    assert!(
        matches!(issued, Err(StreamBudgetError::Backend(_))),
        "{issued:?}"
    );
    assert_eq!(fence_next(&budget, user).await, Some(2), "next is raised");
    let after: i64 = raw.pttl(&fence).await.expect("PTTL");
    assert!(
        after <= before && after >= before - 2_000,
        "the expiry was kept: {before} ms, then {after} ms"
    );
    for state in key_states(&[budget.lease_key(user), budget.admit_key(user)]).await {
        assert_eq!(state.kind, "none", "nothing else was written: {state:?}");
    }
    assert_eq!(budget.issue_ticket(&direct, user).await, Ok(3));
    let pttl: i64 = raw.pttl(&fence).await.expect("PTTL");
    assert!(
        (day_ms - 2_000..=day_ms).contains(&pttl),
        "restored: {pttl}"
    );
}

/// **An allowed fence `EXPIRE` then a denied `SET` writes no lease**: the
/// acquire's first write (the fence's expiry) is allowed and runs, its next
/// (`SET` of the admission key) is denied, and the script stops there. The
/// only change is the fence's refreshed expiry (harmless: a grant would have
/// made it); `next` is unchanged, and there is no admission key and no lease
/// — one command, `SET`, writes both. The control: the same acquire allowed
/// `SET` is granted.
#[tokio::test]
async fn an_allowed_fence_expire_then_a_denied_set_writes_no_lease() {
    let budget = private_budget();
    let prefix = budget.prefix().to_string();
    let no_set = AclUser::create(&prefix, &["+eval", "+get", "+hget", "+expire"]).await;
    let allowed = AclUser::create(&prefix, &["+eval", "+get", "+hget", "+expire", "+set"]).await;
    let direct = test_handle().await;
    let mut raw = raw_redis().await;
    let user = Uuid::new_v4();
    let fence = budget.fence_key(user);
    let ticket = budget.issue_ticket(&direct, user).await.expect("a ticket");
    let _: bool = raw.pexpire(&fence, 600_000).await.expect("PEXPIRE");
    let mut untouched = vec![budget.lease_key(user), budget.admit_key(user)];
    untouched.extend(counter_keys(&budget, user, Utc::now()));
    let before = key_states(&untouched).await;

    let refused = budget
        .acquire(
            &no_set.handle(),
            user,
            Uuid::new_v4(),
            ticket,
            Duration::from_millis(1),
        )
        .await;
    assert!(
        matches!(refused, Err(StreamBudgetError::Backend(_))),
        "{refused:?}"
    );
    assert_unchanged(&untouched, &before, &key_states(&untouched).await, 2_000);
    assert_eq!(before[0].kind, "none", "no lease");
    assert_eq!(before[1].kind, "none", "no admission key");
    assert_eq!(
        fence_next(&budget, user).await,
        Some(ticket),
        "next unchanged"
    );
    let pttl: i64 = raw.pttl(&fence).await.expect("PTTL");
    assert!(
        pttl > 600_000,
        "the allowed EXPIRE ran first and refreshed the fence: {pttl}"
    );

    let token = Uuid::new_v4();
    budget
        .acquire(
            &allowed.handle(),
            user,
            token,
            ticket,
            Duration::from_millis(1),
        )
        .await
        .expect("SET allowed: granted");
    assert_eq!(lease(&budget, user).await, Some(token.to_string()));
    clean_up(&budget).await;
}

/// **A denied release `DEL` keeps the charge, and the lease expires on its
/// own** — the release's one partial state (its `DEL` comes LAST): under a
/// user denied `DEL`, the release is `Backend`, every counter and the
/// session meter hold the charge with their expiries, and the lease still
/// holds this session's token with its expiry untouched (not refreshed:
/// a release never re-`SET`s it). The control: the same release allowed
/// `DEL` deletes the lease.
#[tokio::test]
async fn a_denied_release_del_keeps_the_charge_and_the_lease_expires() {
    let clock = TestClock::at("2026-10-17T12:00:00Z");
    let now = clock.now();
    let budget = small_budget(&clock);
    let prefix = budget.prefix().to_string();
    let no_del = AclUser::create(&prefix, &["+eval", "+get", "+set"]).await;
    let allowed = AclUser::create(&prefix, &["+eval", "+get", "+set", "+del"]).await;
    let mut raw = raw_redis().await;
    let (day_ttl, month_ttl) = (12 * 3_600 + 3_600, 14 * 86_400 + 12 * 3_600 + 86_400);

    let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
    seed(&mut raw, &budget.lease_key(user), token.to_string()).await;
    let lease_before = key_states(&[budget.lease_key(user)]).await;
    let refused = budget
        .meter(&no_del.handle(), user, token, 1_000, MeterMode::Release)
        .await;
    assert!(
        matches!(&refused, Err(StreamBudgetError::Backend(detail)) if detail.starts_with("Redis command failed")),
        "{refused:?}"
    );
    let charged = key_states(&counter_keys(&budget, user, now)).await;
    for (state, ttl) in charged.iter().zip([day_ttl, month_ttl, month_ttl]) {
        assert_eq!(state.value.as_deref(), Some("1000"), "{state:?}");
        assert_fresh_ttl(state.pttl, ttl, "charged, with its expiry");
    }
    let meter = key_states(&[budget.meter_key(token)]).await;
    assert_eq!(meter[0].value.as_deref(), Some("1000"));
    assert_fresh_ttl(meter[0].pttl, METER_TTL_SECONDS, "the session meter");
    let lease_after = key_states(&[budget.lease_key(user)]).await;
    assert_unchanged(
        &[budget.lease_key(user)],
        &lease_before,
        &lease_after,
        2_000,
    );
    assert!(lease_after[0].pttl > 0, "it expires on its own");

    let released = budget
        .meter(&allowed.handle(), user, token, 1_000, MeterMode::Release)
        .await
        .expect("DEL allowed: released");
    assert!(released.held);
    assert_eq!(lease(&budget, user).await, None);
    clean_up(&budget).await;
}

/// **A replayed release after a denied `DEL` charges nothing**: the meter
/// already holds the release's total, so the same release sent again (the
/// handle's replay, or the caller's retry) adds nothing to any counter and
/// fails at the `DEL` again. The control: a release carrying MORE audio
/// charges exactly the difference, and fails at the `DEL` too.
#[tokio::test]
async fn a_replayed_release_after_a_denied_del_charges_nothing() {
    let clock = TestClock::at("2026-10-17T12:00:00Z");
    let now = clock.now();
    let budget = small_budget(&clock);
    let prefix = budget.prefix().to_string();
    let no_del = AclUser::create(&prefix, &["+eval", "+get", "+set"]).await;
    let denied = no_del.handle();
    let mut raw = raw_redis().await;
    let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
    seed(&mut raw, &budget.lease_key(user), token.to_string()).await;
    let keys = counter_keys(&budget, user, now);

    for attempt in ["the release", "its replay"] {
        let refused = budget
            .meter(&denied, user, token, 1_000, MeterMode::Release)
            .await;
        assert!(
            matches!(refused, Err(StreamBudgetError::Backend(_))),
            "{attempt}: {refused:?}"
        );
        assert_eq!(
            counter_values(&keys).await,
            [Some(1_000), Some(1_000), Some(1_000)],
            "{attempt}: charged once"
        );
    }
    let meter = key_states(&[budget.meter_key(token)]).await;
    assert_eq!(meter[0].value.as_deref(), Some("1000"));

    let refused = budget
        .meter(&denied, user, token, 1_500, MeterMode::Release)
        .await;
    assert!(
        matches!(refused, Err(StreamBudgetError::Backend(_))),
        "{refused:?}"
    );
    assert_eq!(
        counter_values(&keys).await,
        [Some(1_500), Some(1_500), Some(1_500)],
        "more audio charges the difference"
    );
    assert_eq!(lease(&budget, user).await, Some(token.to_string()));
    clean_up(&budget).await;
}

// ── The meter's replay policy ────────────────────────────────────────────

/// **A refresh and a release whose answers were lost charge the audio
/// ONCE**: the `EVAL` ran, then the connection died before the answer
/// arrived, and the meter's one replay (`OnceOnFreshConnection`, on a new
/// connection) finds nothing left to charge — the totals are cumulative.
#[tokio::test]
async fn a_meter_whose_answer_was_lost_is_charged_once() {
    within_deadline("the lost-answer metering", async {
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let through_relay = RedisHandle::open(&relay.url).expect("the relay's URL parses");
        let budget = private_budget();
        let (user, token) = (Uuid::new_v4(), Uuid::new_v4());
        through_relay.ping().await.expect("the admission's PING");
        acquire_now(
            &budget,
            &through_relay,
            user,
            token,
            Duration::from_millis(1),
        )
        .await
        .expect("a grant");
        // The connection is CACHED, the kind a replay retries on. Two EVALs:
        // the ticket's issue and the acquire.
        assert_eq!(relay.evals(), 2);
        let now = Utc::now();
        let keys = counter_keys(&budget, user, now);

        relay.arm(EvalFault::LoseAnswerAndClose);
        let refreshed = budget
            .meter(&through_relay, user, token, 1_000, MeterMode::Refresh)
            .await
            .expect("the refresh, replayed");
        assert!(refreshed.held);
        assert_eq!(relay.evals(), 4, "one attempt (answer lost) and its retry");
        assert_eq!(
            counter_values(&keys).await,
            [Some(1_000), Some(1_000), Some(1_000)],
            "a replayed refresh charged twice"
        );

        relay.arm(EvalFault::LoseAnswerAndClose);
        budget
            .meter(&through_relay, user, token, 1_500, MeterMode::Release)
            .await
            .expect("the release, replayed");
        assert_eq!(relay.evals(), 6);
        assert_eq!(
            counter_values(&keys).await,
            [Some(1_500), Some(1_500), Some(1_500)],
            "a replayed release charged twice"
        );
        assert_eq!(lease(&budget, user).await, None);
        assert!(
            relay.accepted() >= 3,
            "each lost answer redialled: {}",
            relay.accepted()
        );
        clean_up(&budget).await;
    })
    .await;
}
