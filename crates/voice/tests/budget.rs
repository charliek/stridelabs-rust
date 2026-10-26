//! The text-to-speech character budget against a real Redis (feature
//! `live-tests`): `TtsBudget::charge` and its script, driven directly.
//!
//! Moved from tapper's `tests/voice.rs` (`82be95f`): its budget tests as they
//! were, and the budget half of its route tests (the route's status, body and
//! provider call are the app's flow, tested with it) — every expectation held
//! at the budget's own answer, counters and keys:
//!
//! - **the caps** — the user's day, the user's month and everyone's month,
//!   charged all-or-none by one script; a charge that fits exactly is
//!   admitted, one that would pass a cap charges nothing; every spent mask
//!   and the scope it reports, mid-month and on a month's last day;
//! - **the idempotency key** — a sentence charged again under its key
//!   replays its verdict (also after a lost reply, and concurrently); a key
//!   sent with another sentence is refused; scoped by user; a replayed
//!   refusal keeps its original reset across midnight;
//! - **validation and writes** — a poisoned counter, a key of the wrong type
//!   and a malformed stored verdict each write nothing, value or expiry; a
//!   denied write permission allows every write or refuses before any;
//! - **the replay policy** — `OnceOnFreshConnection`, through the fault
//!   relay (`tests/redis_fault`): a lost answer is replayed and charged once;
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

use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use stridelabs_redis::{RedisHandle, Replay};
use stridelabs_voice::budget::{
    Admitted, BudgetError, ChargeKey, Disposition, Fingerprint, LimitScope, Spent, TtsBudget,
    TtsCaps, CHARGE_VERDICT_SECONDS,
};
use stridelabs_voice::window::{day_end, month_end, seconds_until};
use uuid::Uuid;

#[allow(
    dead_code,
    reason = "shared with tests/lease.rs; this suite uses the lost-answer fault only"
)]
mod redis_fault;
use redis_fault::{within_deadline, EvalFault, RedisRelay};

#[allow(
    dead_code,
    reason = "shared with tests/lease.rs; not every suite seeds every kind of key"
)]
mod test_redis;
use test_redis::{
    assert_fresh_ttl, assert_unchanged, drop_keys_under, expire_soon, key_states, keys_under,
    raw_redis, seed, test_handle, test_redis_url, tts_prefix, AclUser, KeysUnder,
};

/// The caps a test that sets none counts against: both apps' defaults (the
/// user's day 20,000 characters; the user's month and everyone's month
/// 300,000).
const USER_DAILY_CHARS: i64 = 20_000;
const GLOBAL_MONTHLY_CHARS: i64 = 300_000;

fn default_caps() -> TtsCaps {
    TtsCaps::new(USER_DAILY_CHARS, GLOBAL_MONTHLY_CHARS, GLOBAL_MONTHLY_CHARS)
        .expect("the default caps are valid")
}

/// `instant` (RFC 3339), as UTC.
fn at(instant: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(instant)
        .expect("a fixed instant")
        .with_timezone(&Utc)
}

/// The fingerprint of a sentence no test cares about: a charge under a
/// fresh key ([`ChargeKey::mint`]) is the only one carrying it.
fn any_sentence() -> Fingerprint {
    Fingerprint::of("Jason", "any sentence")
}

/// The day key's and the month keys' expiries, in seconds, for a write at
/// `now`: each window's end plus its grace (an hour; a day).
fn window_ttls(now: DateTime<Utc>) -> (i64, i64) {
    (
        seconds_until(day_end(now), now) + 3_600,
        seconds_until(month_end(now), now) + 86_400,
    )
}

/// One user's budget under a prefix of its own, on a fixed clock, charged
/// through `redis` — the budget half of tapper's route harness.
struct Charging {
    redis: RedisHandle,
    budget: TtsBudget,
    user: Uuid,
    now: DateTime<Utc>,
}

impl Charging {
    /// The default caps, mid-month.
    async fn new() -> Charging {
        Charging::with(
            default_caps(),
            at("2026-10-17T12:00:00Z"),
            test_handle().await,
        )
    }

    fn with(caps: TtsCaps, now: DateTime<Utc>, redis: RedisHandle) -> Charging {
        Charging {
            redis,
            budget: TtsBudget::new(tts_prefix(), caps).with_clock(move || now),
            user: Uuid::new_v4(),
            now,
        }
    }

    fn user_key(&self) -> String {
        self.budget.user_key(self.user, self.now)
    }

    fn user_month_key(&self) -> String {
        self.budget.user_month_key(self.user, self.now)
    }

    fn global_key(&self) -> String {
        self.budget.global_key(self.now)
    }

    /// `chars` of a sentence nobody else sends, under a fresh key.
    async fn charge(&self, chars: usize) -> Result<Admitted, BudgetError> {
        self.charge_keyed(chars, &ChargeKey::mint(), &any_sentence())
            .await
    }

    async fn charge_keyed(
        &self,
        chars: usize,
        key: &ChargeKey,
        fingerprint: &Fingerprint,
    ) -> Result<Admitted, BudgetError> {
        self.budget
            .charge(&self.redis, self.user, chars, key, fingerprint)
            .await
    }

    /// The user's day, the user's month and the global month, `None` where
    /// absent.
    async fn all_counters(&self) -> (Option<i64>, Option<i64>, Option<i64>) {
        let mut redis = raw_redis().await;
        let day: Option<i64> = redis.get(self.user_key()).await.expect("GET day");
        let month: Option<i64> = redis.get(self.user_month_key()).await.expect("GET month");
        let global: Option<i64> = redis.get(self.global_key()).await.expect("GET global");
        (day, month, global)
    }

    /// The user's day and the global month, `None` where absent.
    async fn counters(&self) -> (Option<i64>, Option<i64>) {
        let (day, _, global) = self.all_counters().await;
        (day, global)
    }

    async fn seed(&self, user: Option<i64>, global: Option<i64>) {
        let mut redis = raw_redis().await;
        for (key, value) in [(self.user_key(), user), (self.global_key(), global)] {
            if let Some(value) = value {
                seed(&mut redis, &key, value).await;
            }
        }
    }

    /// Delete every key this budget's prefix could have written.
    async fn clean_up(&self) {
        drop_keys_under(self.budget.prefix()).await;
    }
}

/// `charged` is a refusal with exactly `spent`'s windows, reporting `scope`,
/// resetting at that window's end as of `now`.
fn assert_refused(
    charged: &Result<Admitted, BudgetError>,
    spent: Spent,
    scope: LimitScope,
    now: DateTime<Utc>,
) {
    let Err(BudgetError::Exceeded(limit)) = charged else {
        panic!("expected a refusal: {charged:?}");
    };
    assert_eq!(limit.spent, spent);
    assert_eq!(limit.scope, scope);
    assert_eq!(limit.resets_at, scope.resets_at(now));
    assert_eq!(
        i64::try_from(limit.retry_after_seconds).expect("small"),
        seconds_until(scope.resets_at(now), now)
    );
}

// ── The caps ─────────────────────────────────────────────────────────────

/// The user's day: a charge that FITS exactly is admitted (the cap may be
/// reached), one that would pass it is refused with the day's scope and
/// reset — and charges NEITHER counter.
#[tokio::test]
async fn the_users_day_is_capped_and_a_refusal_charges_nothing() {
    let charging = Charging::new().await;
    charging
        .seed(Some(USER_DAILY_CHARS - 10), Some(1_000))
        .await;

    let refused = charging.charge(11).await;
    assert_refused(
        &refused,
        Spent {
            user_day: true,
            ..Spent::default()
        },
        LimitScope::UserDay,
        charging.now,
    );
    assert_eq!(
        charging.counters().await,
        (Some(USER_DAILY_CHARS - 10), Some(1_000)),
        "both-or-neither: the refusal charged a counter"
    );

    let fits = charging.charge(10).await.expect("an exact fit is admitted");
    assert_eq!(fits.disposition, Disposition::Fresh);
    assert_eq!(
        charging.counters().await,
        (Some(USER_DAILY_CHARS), Some(1_010))
    );
    assert!(matches!(
        charging.charge(1).await,
        Err(BudgetError::Exceeded(_))
    ));
    charging.clean_up().await;
}

/// The global month: a charge that would pass it is refused, resetting at
/// the first of next month, and the USER's day is not charged — the half of
/// both-or-neither a two-step charge would get wrong.
#[tokio::test]
async fn the_global_month_is_capped_and_never_spends_the_users_day() {
    let charging = Charging::new().await;
    charging.seed(None, Some(GLOBAL_MONTHLY_CHARS - 5)).await;

    let refused = charging.charge(6).await;
    assert_refused(
        &refused,
        Spent {
            global_month: true,
            ..Spent::default()
        },
        LimitScope::GlobalMonth,
        charging.now,
    );
    assert_eq!(
        charging.counters().await,
        (None, Some(GLOBAL_MONTHLY_CHARS - 5)),
        "both-or-neither: a global refusal charged the user"
    );

    charging.charge(5).await.expect("an exact fit is admitted");
    assert_eq!(
        charging.counters().await,
        (Some(5), Some(GLOBAL_MONTHLY_CHARS))
    );
    charging.clean_up().await;
}

/// Both spent: the refusal reports the LATER window (everyone's month),
/// because retrying at midnight would still be refused.
#[tokio::test]
async fn with_both_spent_retry_after_is_the_months_end() {
    let charging = Charging::new().await;
    charging
        .seed(Some(USER_DAILY_CHARS), Some(GLOBAL_MONTHLY_CHARS))
        .await;
    let refused = charging.charge(2).await;
    assert_refused(
        &refused,
        Spent {
            user_day: true,
            global_month: true,
            ..Spent::default()
        },
        LimitScope::GlobalMonth,
        charging.now,
    );
    assert_eq!(
        charging.counters().await,
        (Some(USER_DAILY_CHARS), Some(GLOBAL_MONTHLY_CHARS))
    );
    charging.clean_up().await;
}

/// The charge is ONE atomic script: ten concurrent 100-character charges
/// against a day with room for exactly five admit exactly five, and the
/// counters land exactly on the cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_charges_cannot_pass_the_cap() {
    let charging = Charging::new().await;
    charging.seed(Some(USER_DAILY_CHARS - 500), Some(0)).await;
    let answers = futures::future::join_all((0..10).map(|_| charging.charge(100))).await;
    let admitted = answers.iter().filter(|answer| answer.is_ok()).count();
    let refused = answers
        .iter()
        .filter(|answer| matches!(answer, Err(BudgetError::Exceeded(_))))
        .count();
    assert_eq!((admitted, refused), (5, 5), "{answers:?}");
    assert_eq!(
        charging.counters().await,
        (Some(USER_DAILY_CHARS), Some(500))
    );
    charging.clean_up().await;
}

/// A Redis that is down is found out at the charge: `Backend` (the app's
/// retryable `503`), naming the failure's class only. Admission FAILS
/// CLOSED: the budgets are the spending cap.
#[tokio::test]
async fn a_redis_that_is_down_is_a_backend_error() {
    let down = RedisHandle::open("redis://127.0.0.1:1").expect("the URL parses");
    let charging = Charging::with(default_caps(), at("2026-10-17T12:00:00Z"), down);
    let charged = charging.charge(2).await;
    let Err(BudgetError::Backend(detail)) = &charged else {
        panic!("{charged:?}");
    };
    assert!(detail.starts_with("could not connect to Redis"), "{detail}");
    assert!(!detail.contains(&charging.user.to_string()), "{detail}");
}

/// **Every spent-window mask the charge can answer, `1` to `7`**, against the
/// real script: each window in the mask is five characters short of its cap,
/// the others empty, and a ten-character charge is refused with exactly
/// those windows and the scope the table names — the latest reset; the two
/// months tie (to `user_month`), and on a month's LAST day, when all three
/// windows end at one midnight, the tie order alone decides — and NOTHING is
/// written: no counter's value or expiry moves.
///
/// The control is mask `0`: the same charge is admitted and all three
/// counters count it, each with its window's expiry.
#[tokio::test]
async fn every_spent_mask_is_refused_at_the_charge_with_its_scope_and_charges_nothing() {
    use LimitScope::{GlobalMonth, UserDay, UserMonth};
    let redis = test_handle().await;
    let caps = TtsCaps::new(100, 200, 300).expect("valid caps");
    // Mask 1 to 7: day, global, day+global, month, day+month,
    // global+month, all three.
    let scopes = [
        UserDay,
        GlobalMonth,
        GlobalMonth,
        UserMonth,
        UserMonth,
        UserMonth,
        UserMonth,
    ];
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
        let now = at(when);
        for mask in 0..=7_i64 {
            let prefix = tts_prefix();
            let budget = TtsBudget::new(prefix.clone(), caps).with_clock(move || now);
            let user = Uuid::new_v4();
            let keys = [
                budget.user_key(user, now),
                budget.user_month_key(user, now),
                budget.global_key(now),
            ];
            let mut raw = raw_redis().await;
            for (key, bit, near) in [(&keys[0], 1, 95), (&keys[1], 4, 195), (&keys[2], 2, 295)] {
                if mask & bit != 0 {
                    seed(&mut raw, key, near).await;
                }
            }
            let before = key_states(&keys).await;
            let charged = budget
                .charge(&redis, user, 10, &ChargeKey::mint(), &any_sentence())
                .await;
            if mask == 0 {
                assert_eq!(charged.expect("room in every window").at, now);
                let after = key_states(&keys).await;
                let (day_ttl, month_ttl) = window_ttls(now);
                for (state, ttl) in after.iter().zip([day_ttl, month_ttl, month_ttl]) {
                    assert_eq!(state.value.as_deref(), Some("10"), "{when}: {state:?}");
                    assert_fresh_ttl(state.pttl, ttl, when);
                }
            } else {
                let scope = scopes[usize::try_from(mask - 1).expect("1..=7")];
                let Err(BudgetError::Exceeded(limit)) = charged else {
                    panic!("{when}, mask {mask}: {charged:?}");
                };
                assert_eq!(
                    limit.spent,
                    Spent {
                        user_day: mask & 1 != 0,
                        user_month: mask & 4 != 0,
                        global_month: mask & 2 != 0,
                    },
                    "{when}, mask {mask}"
                );
                assert_eq!(limit.scope, scope, "{when}, mask {mask}");
                let resets = if scope == UserDay {
                    day_resets
                } else {
                    month_resets
                };
                assert_eq!(limit.resets_at, at(resets), "{when}, mask {mask}");
                assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);
            }
            drop_keys_under(&prefix).await;
        }
    }
}

/// **A spent user's month is refused with its scope and reset**: nothing is
/// charged, the scope is `user_month`, and it resets at the first of next
/// month, `Retry-After` counting to that same instant. A charge that fits
/// the month exactly is then admitted — the cap may be reached, never
/// passed — and counts in all three windows. (The app's `429` body and its
/// compatibility with clients that parse only `detail` are the app flow's
/// tests.)
///
/// The control: before the month is spent, the same charge is admitted.
#[tokio::test]
async fn a_spent_users_month_is_refused_with_its_scope_and_reset() {
    let now = at("2026-10-17T12:00:00Z");
    let charging = Charging::with(
        TtsCaps::unchecked(1_000, 50, 1_000),
        now,
        test_handle().await,
    );
    charging.charge(40).await.expect("the control is admitted");
    assert_eq!(
        charging.all_counters().await,
        (Some(40), Some(40), Some(40))
    );

    let refused = charging.charge(11).await;
    let Err(BudgetError::Exceeded(limit)) = refused else {
        panic!("{refused:?}");
    };
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
        limit.retry_after_seconds,
        14 * 86_400 + 12 * 3_600,
        "to the first of next month"
    );
    assert_eq!(
        charging.all_counters().await,
        (Some(40), Some(40), Some(40)),
        "a refusal charged a counter"
    );

    charging.charge(10).await.expect("an exact fit is admitted");
    assert_eq!(
        charging.all_counters().await,
        (Some(50), Some(50), Some(50))
    );
    charging.clean_up().await;
}

// ── Validation before any write ──────────────────────────────────────────

/// A counter that is not a canonical non-negative integer — something other
/// than the charge script wrote it — is `Backend` with NOTHING written: not
/// the other counter, not the poisoned one, not a verdict. A counter of
/// another TYPE is the same.
#[tokio::test]
async fn a_poisoned_counter_is_a_backend_error_and_nothing_is_written() {
    let charging = Charging::new().await;
    let mut redis = raw_redis().await;
    for (label, key, other) in [
        (
            "the global counter",
            charging.global_key(),
            charging.user_key(),
        ),
        (
            "the user's counter",
            charging.user_key(),
            charging.global_key(),
        ),
    ] {
        for poison in ["1.5", "-3", "abc", "007", "", " 5", "1e3"] {
            seed(&mut redis, &key, poison).await;
            let charged = charging.charge(2).await;
            assert!(
                matches!(&charged, Err(BudgetError::Backend(detail)) if detail.contains("nothing was charged")),
                "{label} = {poison:?}: {charged:?}"
            );
            let stored: Option<String> = redis.get(&key).await.expect("GET");
            assert_eq!(stored.as_deref(), Some(poison), "{label} = {poison:?}");
            let charged: Option<String> = redis.get(&other).await.expect("GET");
            assert_eq!(
                charged, None,
                "{label} = {poison:?}: the other counter was charged"
            );
        }
        let _: i64 = redis.del(&key).await.expect("DEL");
        let _: i64 = redis.rpush(&key, "not a counter").await.expect("RPUSH");
        expire_soon(&mut redis, &key).await;
        let charged = charging.charge(2).await;
        assert!(
            matches!(charged, Err(BudgetError::Backend(_))),
            "{label} is a list: {charged:?}"
        );
        let charged: Option<String> = redis.get(&other).await.expect("GET");
        assert_eq!(
            charged, None,
            "{label} is a list: the other counter was charged"
        );
        let _: i64 = redis.del(&key).await.expect("DEL");
    }
    let verdicts: Vec<String> = redis
        .keys(format!("{}:charge:*", charging.budget.prefix()))
        .await
        .expect("KEYS");
    assert!(
        verdicts.is_empty(),
        "a refused-as-invalid charge stored a verdict: {verdicts:?}"
    );
    charging.clean_up().await;
}

/// **A poisoned key changes nothing, value or expiry.** Each key the charge
/// reads — the user's day, the user's month, everyone's month, the verdict —
/// is made a LIST (the wrong type), and each counter also a non-integer; the
/// others hold clean counters with the seeded two-minute expiry. Every such
/// charge is a `Backend` error, and EVERY key keeps its type, its value and
/// its expiry (no expiry went up).
///
/// The control: the same keys all clean, the charge is admitted and every
/// counter's value and expiry DO change — which is what the check above
/// would have caught.
#[tokio::test]
async fn a_poisoned_key_at_the_charge_changes_no_value_and_no_expiry() {
    let redis = test_handle().await;
    let now = at("2026-10-17T12:00:00Z");
    let prefix = tts_prefix();
    let budget = TtsBudget::new(prefix.clone(), default_caps()).with_clock(move || now);
    let charge_id = ChargeKey::mint();
    let mut raw = raw_redis().await;
    for poisoned in 0..4 {
        for poison in ["list", "1.5", "007"] {
            if poisoned == 3 && poison != "list" {
                // The verdict is the charge's own key: here its type; its
                // value's version and shape are the next test's.
                continue;
            }
            let user = Uuid::new_v4();
            let keys = [
                budget.user_key(user, now),
                budget.user_month_key(user, now),
                budget.global_key(now),
                budget.charge_key(user, &charge_id),
            ];
            for (index, key) in keys.iter().enumerate() {
                let _: i64 = raw.del(key).await.expect("DEL");
                if index == poisoned {
                    if poison == "list" {
                        let _: i64 = raw.rpush(key, "not a counter").await.expect("RPUSH");
                        expire_soon(&mut raw, key).await;
                    } else {
                        seed(&mut raw, key, poison).await;
                    }
                } else if index < 3 {
                    seed(&mut raw, key, 7).await;
                }
            }
            let before = key_states(&keys).await;
            let charged = budget
                .charge(&redis, user, 10, &charge_id, &any_sentence())
                .await;
            assert!(
                matches!(charged, Err(BudgetError::Backend(_))),
                "key {poisoned} = {poison}: {charged:?}"
            );
            assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);
        }
    }

    // The control: clean keys, and the charge writes every counter.
    let user = Uuid::new_v4();
    let keys = [
        budget.user_key(user, now),
        budget.user_month_key(user, now),
        budget.global_key(now),
    ];
    let _: i64 = raw.del(&keys[2]).await.expect("DEL");
    for key in &keys {
        seed(&mut raw, key, 7).await;
    }
    budget
        .charge(&redis, user, 10, &ChargeKey::mint(), &any_sentence())
        .await
        .expect("clean keys: admitted");
    let after = key_states(&keys).await;
    for state in &after {
        assert_eq!(state.value.as_deref(), Some("17"));
        assert!(state.pttl > 120_000, "the expiry was set: {state:?}");
    }
    drop_keys_under(&prefix).await;
}

/// **A stored verdict that does not parse writes nothing** (the replay path
/// parses `v1|<mask>|<fp>|<reset>` with `string.match`, where an older script
/// once read a bare number): the bare verdicts `0` and `3`, another version,
/// a mask past `7`, a fingerprint that is upper case or short, a reset of 16
/// digits or negative, a field too many or too few, an empty value. Each
/// charge is `Backend` (the app's `503`), and every key — the counters and
/// the verdict — keeps its value and its expiry.
///
/// The controls: the well-formed verdict for this sentence REPLAYS (and
/// still writes nothing), and the same verdict for another sentence is
/// [`BudgetError::KeyReused`].
#[tokio::test]
async fn a_malformed_stored_verdict_is_a_503_and_changes_nothing() {
    let redis = test_handle().await;
    let now = at("2026-10-17T12:00:00Z");
    let prefix = tts_prefix();
    let budget = TtsBudget::new(prefix.clone(), default_caps()).with_clock(move || now);
    let fingerprint = Fingerprint::of("Jason", "hi");
    let fp = fingerprint.as_str();
    let mut raw = raw_redis().await;
    let poisons = [
        "0".to_string(),
        "3".to_string(),
        format!("v2|0|{fp}|0"),
        format!("v1|8|{fp}|0"),
        format!("v1|0|{}|0", fp.to_uppercase()),
        format!("v1|0|{}|0", &fp[..15]),
        format!("v1|1|{fp}|1234567890123456"),
        format!("v1|1|{fp}|-1"),
        format!("v1|0|{fp}|0|0"),
        format!("v1|0|{fp}"),
        String::new(),
    ];
    let user = Uuid::new_v4();
    let key = ChargeKey::mint();
    let keys = [
        budget.user_key(user, now),
        budget.user_month_key(user, now),
        budget.global_key(now),
        budget.charge_key(user, &key),
    ];
    for key_name in &keys[..3] {
        seed(&mut raw, key_name, 7).await;
    }
    for poison in &poisons {
        seed(&mut raw, &keys[3], poison.as_str()).await;
        let before = key_states(&keys).await;
        let charged = budget.charge(&redis, user, 10, &key, &fingerprint).await;
        assert!(
            matches!(&charged, Err(BudgetError::Backend(detail)) if detail.contains("nothing was charged")),
            "{poison:?}: {charged:?}"
        );
        assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);
    }

    seed(&mut raw, &keys[3], format!("v1|0|{fp}|0").as_str()).await;
    let before = key_states(&keys).await;
    let replayed = budget
        .charge(&redis, user, 10, &key, &fingerprint)
        .await
        .expect("a well-formed admission replays");
    assert_eq!(replayed.disposition, Disposition::Replayed);
    assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);
    assert_eq!(
        budget
            .charge(&redis, user, 10, &key, &Fingerprint::of("Jason", "ho"))
            .await,
        Err(BudgetError::KeyReused)
    );
    assert_unchanged(&keys, &before, &key_states(&keys).await, 2_000);
    drop_keys_under(&prefix).await;
}

/// The charge script as it was before the user's month (tapper `f92e3e5`),
/// verbatim: two counters, the user's day and everyone's month; `INCRBY` then
/// `EXPIRE`; `KEYS = user-day global-month verdict`, `ARGV = chars user_cap
/// global_cap user_ttl global_ttl verdict_ttl`. The write-permission test's
/// control: what one command per key prevents.
const OLD_CHARGE_SCRIPT: &str = "\
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
local stored = redis.call('GET', KEYS[3])
if stored then
  return tonumber(stored)
end
local user = counter(KEYS[1])
local global = counter(KEYS[2])
if not user or not global then
  return -1
end
local chars = tonumber(ARGV[1])
local over = 0
if user + chars > tonumber(ARGV[2]) then
  over = over + 1
end
if global + chars > tonumber(ARGV[3]) then
  over = over + 2
end
if over == 0 then
  redis.call('INCRBY', KEYS[1], chars)
  redis.call('EXPIRE', KEYS[1], ARGV[4])
  redis.call('INCRBY', KEYS[2], chars)
  redis.call('EXPIRE', KEYS[2], ARGV[5])
end
redis.call('SET', KEYS[3], over, 'EX', ARGV[6])
return over
";

/// The old script's charge of `chars` to `user`, at `now`, with constant caps
/// (20,000 and 300,000): its verdict.
async fn old_charge(
    redis: &RedisHandle,
    budget: &TtsBudget,
    user: Uuid,
    chars: u32,
    now: DateTime<Utc>,
) -> Result<i64, stridelabs_redis::RedisError> {
    let (day_ttl, month_ttl) = window_ttls(now);
    redis
        .eval(
            OLD_CHARGE_SCRIPT,
            &[
                &budget.user_key(user, now),
                &budget.global_key(now),
                &format!("{}:charge:{}", budget.prefix(), Uuid::new_v4()),
            ],
            &[
                chars.into(),
                20_000_i64.into(),
                300_000_i64.into(),
                day_ttl.into(),
                month_ttl.into(),
                120_i64.into(),
            ],
            Replay::Never,
        )
        .await
}

/// **A denied write permission charges nothing, or everything.** Redis
/// checks permissions per command inside a script and keeps the writes
/// before a refused one; the charge's only write is `SET … EX`:
///
/// - a user allowed `SET` (and `INCRBY`) but NOT `EXPIRE` is admitted, and
///   all three counters are written with their expiries;
/// - a user allowed no `SET` is refused, and NOTHING is written — no
///   counter, no verdict.
///
/// The control: under the first user, the charge script as it was before
/// (`INCRBY` then `EXPIRE`) fails part-way and leaves exactly the partial
/// charge one command per key prevents: the day charged with NO expiry, the
/// month untouched.
#[tokio::test]
async fn a_write_permission_allows_every_charge_write_or_refuses_before_any() {
    let now = at("2026-10-17T12:00:00Z");
    let prefix = tts_prefix();
    // The control's day counter has no expiry: deleted however the test ends.
    let _keys = KeysUnder::guard(&prefix).await;
    let budget = TtsBudget::new(prefix.clone(), default_caps()).with_clock(move || now);
    let no_expire = AclUser::create(&prefix, &["+eval", "+get", "+set", "+incrby"]).await;
    let no_set = AclUser::create(&prefix, &["+eval", "+get"]).await;
    let (day_ttl, month_ttl) = window_ttls(now);

    let allowed = no_expire.handle();
    let user = Uuid::new_v4();
    let keys = [
        budget.user_key(user, now),
        budget.user_month_key(user, now),
        budget.global_key(now),
    ];
    budget
        .charge(&allowed, user, 10, &ChargeKey::mint(), &any_sentence())
        .await
        .expect("SET is allowed: admitted");
    let after = key_states(&keys).await;
    for (state, ttl) in after.iter().zip([day_ttl, month_ttl, month_ttl]) {
        assert_eq!(state.value.as_deref(), Some("10"), "{state:?}");
        assert_fresh_ttl(state.pttl, ttl, "an expiry with every write");
    }
    drop_keys_under(&prefix).await;

    let denied = no_set.handle();
    let user = Uuid::new_v4();
    let charge_id = ChargeKey::mint();
    let keys = [
        budget.user_key(user, now),
        budget.user_month_key(user, now),
        budget.global_key(now),
        budget.charge_key(user, &charge_id),
    ];
    let refused = budget
        .charge(&denied, user, 10, &charge_id, &any_sentence())
        .await;
    assert!(
        matches!(refused, Err(BudgetError::Backend(_))),
        "{refused:?}"
    );
    for state in key_states(&keys).await {
        assert_eq!(state.kind, "none", "nothing was written: {state:?}");
    }

    // The control: the older script under the user denied EXPIRE.
    let user = Uuid::new_v4();
    let refused = old_charge(&allowed, &budget, user, 10, now).await;
    assert!(refused.is_err(), "EXPIRE is denied: {refused:?}");
    let day = key_states(&[budget.user_key(user, now), budget.global_key(now)]).await;
    assert_eq!(
        day[0].value.as_deref(),
        Some("10"),
        "the old script charged the day anyway"
    );
    assert_eq!(day[0].pttl, -1, "with no expiry: it never resets");
    assert_eq!(day[1].kind, "none", "and never reached the month");
}

/// **The keys a charge writes, and nothing else**: a charge under a prefix of
/// this test's own, on a fixed clock, writes exactly the user's day, the
/// user's month, everyone's month and the charge's verdict — named as the
/// module docs say — and the prefix holds NO other key (the whole prefix is
/// compared, so any extra write fails it); the verdict is versioned and
/// fingerprinted and lives ten minutes. (The literal key strings under
/// tapper's and lumen's own prefixes are the unit test
/// `the_key_shapes_are_tappers_under_tappers_prefixes`, which needs no
/// Redis: a live test never writes under an app's prefix.)
#[tokio::test]
async fn the_tts_keys_are_dated_and_nothing_else_is_written() {
    let redis = test_handle().await;
    let now = at("2031-03-15T12:00:00Z");
    let prefix = tts_prefix();
    // The month's keys outlive their month by a day: weeks, on this clock.
    let _keys = KeysUnder::guard(&prefix).await;
    let budget = TtsBudget::new(prefix.clone(), default_caps()).with_clock(move || now);
    let (user, charge_id) = (Uuid::new_v4(), ChargeKey::mint());
    budget
        .charge(&redis, user, 12, &charge_id, &any_sentence())
        .await
        .expect("admitted");
    assert_eq!(
        keys_under(&prefix).await,
        [
            format!("{prefix}:charge:{user}:{}", charge_id.as_str()),
            format!("{prefix}:global:2031-03"),
            format!("{prefix}:user-month:{user}:2031-03"),
            format!("{prefix}:user:{user}:2031-03-15"),
        ]
    );
    let verdict = key_states(&[budget.charge_key(user, &charge_id)]).await;
    assert_eq!(
        verdict[0].value,
        Some(format!("v1|0|{}|0", any_sentence().as_str()))
    );
    assert_fresh_ttl(verdict[0].pttl, CHARGE_VERDICT_SECONDS, "the verdict");
}

// ── The idempotency key ──────────────────────────────────────────────────

/// **A sentence charged again under its key is charged once**: the second
/// charge replays the first's verdict ([`Disposition::Replayed`]) and the
/// counters move once. (Speaking it again is the app flow's: the key protects
/// the budget, not provider spend.) The control: the same sentence under
/// ANOTHER key is a new, fresh charge.
#[tokio::test]
async fn a_sentence_charged_again_under_its_key_is_charged_once() {
    let charging = Charging::new().await;
    let key = ChargeKey::parse("sentence-1").expect("a key");
    let hi = Fingerprint::of("Jason", "hi");
    for (attempt, disposition) in [Disposition::Fresh, Disposition::Replayed]
        .into_iter()
        .enumerate()
    {
        let admitted = charging.charge_keyed(2, &key, &hi).await.expect("admitted");
        assert_eq!(admitted.disposition, disposition, "attempt {attempt}");
        assert_eq!(
            charging.counters().await,
            (Some(2), Some(2)),
            "attempt {attempt}: charged once"
        );
    }
    let other = ChargeKey::parse("sentence-2").expect("a key");
    let admitted = charging
        .charge_keyed(2, &other, &hi)
        .await
        .expect("admitted");
    assert_eq!(admitted.disposition, Disposition::Fresh);
    assert_eq!(charging.counters().await, (Some(4), Some(4)));
    charging.clean_up().await;
}

/// **A charge whose ANSWER was lost is charged once and keeps its first
/// verdict**: the `EVAL` ran, then the CACHED connection died before the
/// reply arrived, so the handle's one replay (`OnceOnFreshConnection`) sends
/// it again on a fresh dial — and the replay finds the verdict the first
/// attempt stored under its charge key ([`Disposition::Replayed`]).
///
/// Two rounds, because a replay that re-ran the script would fail them
/// differently: with room left it would charge twice; with the first attempt
/// taking the day exactly to its cap it would answer a refusal for a sentence
/// that was admitted and paid for.
#[tokio::test]
async fn a_charge_whose_answer_was_lost_is_charged_once_with_its_first_verdict() {
    within_deadline("the lost-answer replay", async {
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let through_relay = RedisHandle::open(&relay.url).expect("the relay's URL parses");
        let charging = Charging::with(default_caps(), at("2026-10-17T12:00:00Z"), through_relay);
        // Warm: the connection is now CACHED, the only kind a replay retries on.
        let warm = charging.charge(2).await.expect("the warm-up");
        assert_eq!(warm.disposition, Disposition::Fresh);
        assert_eq!(charging.counters().await, (Some(2), Some(2)));

        relay.arm(EvalFault::LoseAnswerAndClose);
        let with_room = charging.charge(2).await.expect("replayed: admitted");
        assert_eq!(with_room.disposition, Disposition::Replayed);
        assert_eq!(
            charging.counters().await,
            (Some(4), Some(4)),
            "a replayed charge was charged twice"
        );

        charging.seed(Some(USER_DAILY_CHARS - 2), None).await;
        relay.arm(EvalFault::LoseAnswerAndClose);
        let at_the_cap = charging
            .charge(2)
            .await
            .expect("the replay must answer the first attempt's admission, not judge again");
        assert_eq!(at_the_cap.disposition, Disposition::Replayed);
        assert_eq!(charging.counters().await, (Some(USER_DAILY_CHARS), Some(6)));

        // Each faulted charge really was sent twice, on two connections.
        assert_eq!(
            relay.evals(),
            5,
            "the warm-up, then two attempts per faulted charge"
        );
        assert!(
            relay.accepted() >= 3,
            "each retry redialled: {}",
            relay.accepted()
        );
        charging.clean_up().await;
    })
    .await;
}

/// **The client's retry after a reply the handle could not replay is
/// charged once.** The first charge RUNS but its answer is lost on a
/// connection the handle had just dialled (no replay on a fresh connection):
/// `Backend` (the app's `503`), with the sentence charged. The client sends
/// it again under the same key: the stored verdict answers, nothing more is
/// charged.
///
/// The control, in the same test: the same loss followed by a retry under a
/// NEW key (what every retry was before the key) charges the sentence twice.
#[tokio::test]
async fn a_retry_after_a_lost_reply_is_charged_once_under_its_key() {
    within_deadline("the keyed retry", async {
        let relay = RedisRelay::start(&test_redis_url().await).await;
        let through_relay = RedisHandle::open(&relay.url).expect("the relay's URL parses");
        let charging = Charging::with(default_caps(), at("2026-10-17T12:00:00Z"), through_relay);
        let hi = Fingerprint::of("Jason", "hi");
        let key = |name: &str| ChargeKey::parse(name).expect("a key");

        // No warm-up: the first EVAL goes out on a fresh dial, so the
        // handle has nothing to replay it on.
        relay.arm(EvalFault::LoseAnswerAndClose);
        let lost = charging.charge_keyed(2, &key("sentence-1"), &hi).await;
        assert!(
            matches!(&lost, Err(BudgetError::Backend(detail)) if detail.contains("outcome is unknown")),
            "{lost:?}"
        );
        assert_eq!(relay.evals(), 1, "not replayed by the handle");
        assert_eq!(charging.counters().await, (Some(2), Some(2)), "it ran");
        let retried = charging
            .charge_keyed(2, &key("sentence-1"), &hi)
            .await
            .expect("the retry is admitted");
        assert_eq!(retried.disposition, Disposition::Replayed);
        assert_eq!(
            charging.counters().await,
            (Some(2), Some(2)),
            "the retry replayed the verdict"
        );

        // The control: the retry under a new key is a second charge.
        relay.arm(EvalFault::LoseAnswerAndClose);
        // A cached connection now: the handle WOULD replay it, so lose the
        // replay's answer too.
        relay.arm(EvalFault::LoseAnswerAndClose);
        let lost = charging.charge_keyed(2, &key("sentence-2"), &hi).await;
        assert!(matches!(lost, Err(BudgetError::Backend(_))), "{lost:?}");
        assert_eq!(charging.counters().await, (Some(4), Some(4)));
        let new_key = charging
            .charge_keyed(2, &key("sentence-3"), &hi)
            .await
            .expect("admitted");
        assert_eq!(new_key.disposition, Disposition::Fresh);
        assert_eq!(
            charging.counters().await,
            (Some(6), Some(6)),
            "a new key charges the same sentence again"
        );
        charging.clean_up().await;
    })
    .await;
}

/// **A key sent with another sentence is refused, and charges nothing**:
/// another text, or the same text in another voice (the fingerprint covers
/// both), is [`BudgetError::KeyReused`] (the app's `422`). Nothing is
/// written — the stored verdict keeps its value and its expiry. The control:
/// the key with its own sentence replays.
#[tokio::test]
async fn a_key_sent_with_another_sentence_is_refused_and_charges_nothing() {
    let charging = Charging::new().await;
    let key = ChargeKey::parse("sentence-1").expect("a key");
    let hi = Fingerprint::of("Jason", "hi");
    charging
        .charge_keyed(2, &key, &hi)
        .await
        .expect("the first charge");
    let verdict = [charging.budget.charge_key(charging.user, &key)];
    let before = key_states(&verdict).await;
    assert_eq!(before[0].value, Some(format!("v1|0|{}|0", hi.as_str())));
    for (voice, text) in [("Jason", "ho"), ("Hazel", "hi"), ("Jason", "hi there")] {
        let chars = text.chars().count();
        assert_eq!(
            charging
                .charge_keyed(chars, &key, &Fingerprint::of(voice, text))
                .await,
            Err(BudgetError::KeyReused),
            "{voice}: {text}"
        );
    }
    assert_unchanged(&verdict, &before, &key_states(&verdict).await, 2_000);
    assert_eq!(charging.counters().await, (Some(2), Some(2)));
    let control = charging
        .charge_keyed(2, &key, &hi)
        .await
        .expect("its own sentence replays");
    assert_eq!(control.disposition, Disposition::Replayed);
    assert_eq!(charging.counters().await, (Some(2), Some(2)));
    charging.clean_up().await;
}

/// **The key is scoped by user**: two users charging under the same key are
/// two charges, each to its own day (and both to everyone's month).
#[tokio::test]
async fn two_users_sending_one_key_are_two_charges() {
    let charging = Charging::new().await;
    let other = Uuid::new_v4();
    let key = ChargeKey::parse("shared").expect("a key");
    let hi = Fingerprint::of("Jason", "hi");
    let mine = charging.charge_keyed(2, &key, &hi).await.expect("admitted");
    let theirs = charging
        .budget
        .charge(&charging.redis, other, 2, &key, &hi)
        .await
        .expect("admitted");
    assert_eq!(
        (mine.disposition, theirs.disposition),
        (Disposition::Fresh, Disposition::Fresh)
    );
    let mut raw = raw_redis().await;
    let their_day: Option<i64> = raw
        .get(charging.budget.user_key(other, charging.now))
        .await
        .expect("GET");
    assert_eq!(charging.counters().await, (Some(2), Some(4)));
    assert_eq!(their_day, Some(2));
    charging.clean_up().await;
}

/// **Concurrent charges under one key are serialised by the script**: of ten
/// charges of one sentence sent at once, exactly one is fresh and nine
/// replay its verdict, and the counters move once. The control: ten keys,
/// ten fresh charges.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_charges_under_one_key_charge_once() {
    let redis = test_handle().await;
    let prefix = tts_prefix();
    let budget = TtsBudget::new(prefix.clone(), default_caps());
    let user = Uuid::new_v4();
    let key = ChargeKey::mint();
    let fingerprint = Fingerprint::of("Jason", "hello");
    let now = Utc::now();
    let charges = (0..10).map(|_| budget.charge(&redis, user, 5, &key, &fingerprint));
    let answers: Vec<Admitted> = futures::future::join_all(charges)
        .await
        .into_iter()
        .map(|answer| answer.expect("admitted"))
        .collect();
    let fresh = answers
        .iter()
        .filter(|admitted| admitted.disposition == Disposition::Fresh)
        .count();
    assert_eq!(fresh, 1, "{answers:?}");
    let day = key_states(&[budget.user_key(user, now)]).await;
    assert_eq!(day[0].value.as_deref(), Some("5"));

    let keys: Vec<ChargeKey> = (0..10).map(|_| ChargeKey::mint()).collect();
    let charges = keys
        .iter()
        .map(|key| budget.charge(&redis, user, 5, key, &fingerprint));
    let fresh = futures::future::join_all(charges)
        .await
        .into_iter()
        .filter(
            |answer| matches!(answer, Ok(admitted) if admitted.disposition == Disposition::Fresh),
        )
        .count();
    assert_eq!(fresh, 10);
    let day = key_states(&[budget.user_key(user, now)]).await;
    assert_eq!(day[0].value.as_deref(), Some("55"));
    drop_keys_under(&prefix).await;
}

/// **A replayed refusal keeps its ORIGINAL reset**: a sentence refused for
/// the user's day just before midnight, sent again under its key just
/// after, is refused again with the first answer's day end (now past:
/// `Retry-After` 1) — the stored verdict, not a new judgement. The control:
/// a NEW key just after midnight is admitted (the new day has room).
#[tokio::test]
async fn a_replayed_refusal_keeps_its_original_reset() {
    let redis = test_handle().await;
    let prefix = tts_prefix();
    let clock = Arc::new(Mutex::new(at("2026-10-17T23:59:58Z")));
    let budget = TtsBudget::new(
        prefix.clone(),
        TtsCaps::new(10, 1_000, 1_000).expect("valid caps"),
    )
    .with_clock({
        let clock = Arc::clone(&clock);
        move || *clock.lock().expect("the clock")
    });
    let user = Uuid::new_v4();
    let key = ChargeKey::mint();
    let fingerprint = Fingerprint::of("Jason", "too long");
    let first = budget.charge(&redis, user, 11, &key, &fingerprint).await;
    let Err(BudgetError::Exceeded(refused)) = first else {
        panic!("{first:?}");
    };
    assert_eq!(refused.scope, LimitScope::UserDay);
    assert_eq!(refused.resets_at, at("2026-10-18T00:00:00Z"));
    assert_eq!(refused.retry_after_seconds, 2);

    *clock.lock().expect("the clock") = at("2026-10-18T00:00:30Z");
    let replayed = budget.charge(&redis, user, 11, &key, &fingerprint).await;
    let Err(BudgetError::Exceeded(again)) = replayed else {
        panic!("{replayed:?}");
    };
    assert_eq!(again.scope, LimitScope::UserDay);
    assert_eq!(again.resets_at, at("2026-10-18T00:00:00Z"), "the original");
    assert_eq!(again.retry_after_seconds, 1);

    let fresh = ChargeKey::mint();
    let tomorrow = Fingerprint::of("Jason", "short");
    let admitted = budget
        .charge(&redis, user, 5, &fresh, &tomorrow)
        .await
        .expect("a new day");
    assert_eq!(admitted.disposition, Disposition::Fresh);
    drop_keys_under(&prefix).await;
}
