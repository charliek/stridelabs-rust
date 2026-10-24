//! The cache contract, made deterministic.
//!
//! Under `cfg(test)` the cache's clock is frozen at construction and moves
//! only by [`JwksCache::advance_for_test`], so every gate edge is asserted to
//! the nanosecond and no scheduler pause can open a gate early. A test that
//! needs an attempt to end later than it started advances the clock while
//! the attempt is in flight. [`JwksCache::settle`] waits for the attempt in
//! flight, so a test asserts on the state after spawned work, not during it.
//! A cancellation is a lookup polled once and dropped, never a race against
//! a timer. The real clock is left only to what is real time by nature: a
//! fetch's network timeout, a lookup's bound on its wait (a timer on the
//! lookup's own runtime), and a fresh hit's latency. Those tests keep at least a 5× margin
//! between what they assert and what they wait for.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wiremock::{MockServer, ResponseTemplate};

use futures_util::future::FutureExt as _;

use super::*;
use crate::mock_issuer::{
    issuer, issuer_then, jwks_body, jwks_url_of, primary_body, primary_issuer, requests,
};
use crate::test_support::{test_jwks_json, TestKey, PRIMARY_KID, SECONDARY_KID};

const fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

const fn millis(n: u64) -> Duration {
    Duration::from_millis(n)
}

const NANO: Duration = Duration::from_nanos(1);

/// Every rate limit off: each miss dials.
const NO_THROTTLE: Tuning = Tuning::new(JWKS_TTL, Duration::ZERO);

/// Caches nothing; fetches at most once a second.
const ZERO_TTL: Tuning = Tuning::new(Duration::ZERO, MIN_REFETCH_INTERVAL);

const TTL: Duration = secs(60);
/// TTL 60 s, interval 30 s: floor 30 s, and no refresh-ahead (60 < 3 × 30),
/// so expiry is reached directly.
const BOUNDED: Tuning = Tuning::new(TTL, MIN_REFETCH_INTERVAL);
/// TTL 120 s, interval 30 s: floor 30 s, refresh window 60 s, so a lookup
/// the set answers refreshes it from 60 s on.
const BLIP: Tuning = Tuning::new(secs(120), MIN_REFETCH_INTERVAL);

/// Port 1 on loopback: nothing listens, and no request escapes the host.
const NOTHING_LISTENS: &str = "http://127.0.0.1:1/jwks";

fn cache(server: &MockServer, tuning: Tuning) -> JwksCache {
    cache_at(jwks_url_of(server), tuning)
}

/// Through the public builders, so every test below exercises them; the two
/// fetch-side bounds have no public builder.
fn cache_at(jwks_url: impl Into<String>, tuning: Tuning) -> JwksCache {
    let mut cache = JwksCache::new(jwks_url, reqwest::Client::new())
        .with_ttl(tuning.ttl)
        .with_min_refetch_interval(tuning.min_refetch_interval);
    cache.tuning.fetch_timeout = tuning.fetch_timeout;
    cache.tuning.first_join_wait = tuning.first_join_wait;
    cache.tuning.retry_join_wait = tuning.retry_join_wait;
    cache
}

/// A lookup polled once (so it has started or joined its attempt) and then
/// dropped: a cancelled caller, with no timer to race.
fn cancel_a_lookup(cache: &JwksCache, context: &str) {
    let mut lookup = Box::pin(cache.jwks_for_kid(PRIMARY_KID));
    assert!(
        (&mut lookup).now_or_never().is_none(),
        "{context}: the lookup was waiting on its attempt"
    );
}

/// One attempt that takes `flight` on the cache's clock: the lookup starts
/// it, the clock moves while it is in flight, and the lookup then gets its
/// outcome. On a current-thread runtime the fetch runs only once the test
/// yields, so the start and the end are stamped exactly `flight` apart.
async fn an_attempt_taking(cache: &JwksCache, flight: Duration) -> Result<Arc<JwkSet>, AuthError> {
    let mut lookup = Box::pin(cache.jwks_for_kid(PRIMARY_KID));
    assert!(
        (&mut lookup).now_or_never().is_none(),
        "the lookup started an attempt"
    );
    cache.advance_for_test(flight);
    lookup.await
}

fn multi_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a multi-thread runtime builds")
}

impl JwksCache {
    /// The primary test key set, fetched successfully just now by an attempt
    /// that started just now.
    fn seed(&self) {
        let mut state = self.inner.state();
        let now = self.inner.now();
        let set = TestKey::primary().jwks();
        let mut seen = Seen::default();
        seen.record(&set);
        *state = State {
            cached: Some(Fetched {
                set: Arc::new(set),
                unusable: Arc::default(),
                fetched_at: now,
                id: u64::MAX,
            }),
            last_start: Some(now),
            last_end: Some(now),
            seen,
            ..State::default()
        };
    }

    /// An attempt that started and failed just now, the `failures`-th in a
    /// row.
    fn failed_just_now(&self, failures: u32) {
        let mut state = self.inner.state();
        let now = self.inner.now();
        state.last_start = Some(now);
        state.last_end = Some(now);
        state.failures = failures;
    }

    fn in_flight(&self) -> bool {
        self.inner.state().in_flight.is_some()
    }

    fn failures(&self) -> u32 {
        self.inner.state().failures
    }

    fn attempts_reserved(&self) -> u64 {
        self.inner.state().next_id
    }

    fn fetched_at(&self) -> Option<Instant> {
        self.inner.state().cached.as_ref().map(|c| c.fetched_at)
    }

    fn last_start(&self) -> Option<Instant> {
        self.inner.state().last_start
    }

    /// One attempt ended, as a failure: the slot clear, the end stamped and
    /// one failure counted.
    #[track_caller]
    fn assert_one_failed_attempt(&self, context: &str) {
        let state = self.inner.state();
        assert!(state.in_flight.is_none(), "{context}: the slot is clear");
        assert_eq!(state.failures, 1, "{context}: one failure counted");
        assert!(state.last_end.is_some(), "{context}: the end is stamped");
    }
}

/// `Jwks` whose message contains `fragment`.
#[track_caller]
fn assert_jwks(result: Result<Arc<JwkSet>, AuthError>, fragment: &str, context: &str) {
    match result {
        Err(AuthError::Jwks(message)) => assert!(
            message.contains(fragment),
            "{context}: expected Jwks containing {fragment:?}, got {message:?}"
        ),
        Ok(_) => panic!("{context}: served a set; expected Jwks containing {fragment:?}"),
        Err(other) => panic!("{context}: expected Jwks containing {fragment:?}, got {other}"),
    }
}

#[track_caller]
fn assert_unknown(result: Result<Arc<JwkSet>, AuthError>, context: &str) {
    match result {
        Err(AuthError::UnknownKid) => {}
        Ok(_) => panic!("{context}: served a set; expected UnknownKid"),
        Err(other) => panic!("{context}: expected UnknownKid, got {other}"),
    }
}

#[track_caller]
fn assert_unseen(result: Result<Arc<JwkSet>, AuthError>, context: &str) {
    match result {
        Err(AuthError::UnseenKid) => {}
        Ok(_) => panic!("{context}: served a set; expected UnseenKid"),
        Err(other) => panic!("{context}: expected UnseenKid, got {other}"),
    }
}

/// Spawn one lookup per kid, every one before awaiting any, and collect each
/// result with how long its lookup took.
async fn concurrent_lookups(
    cache: &Arc<JwksCache>,
    kids: impl IntoIterator<Item = String>,
) -> Vec<(Result<Arc<JwkSet>, AuthError>, Duration)> {
    let tasks: Vec<_> = kids
        .into_iter()
        .map(|kid| {
            let cache = Arc::clone(cache);
            tokio::spawn(async move {
                let started = Instant::now();
                (cache.jwks_for_kid(&kid).await, started.elapsed())
            })
        })
        .collect();
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.expect("lookup task"));
    }
    results
}

/// `count` concurrent lookups of the primary kid.
async fn herd(
    cache: &Arc<JwksCache>,
    count: usize,
) -> Vec<(Result<Arc<JwkSet>, AuthError>, Duration)> {
    concurrent_lookups(cache, std::iter::repeat_n(PRIMARY_KID.to_owned(), count)).await
}

fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime builds")
}

/// How long [`until`] waits for a condition before failing the test.
const POLL_LIMIT: Duration = secs(10);

async fn until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + POLL_LIMIT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(millis(5)).await;
    }
}

/// An issuer that accepts every connection and never answers, counting the
/// connections: each is one fetch attempt reaching it. Runs on the test's
/// runtime, and dies with it.
struct SilentIssuer {
    url: String,
    accepted: Arc<AtomicUsize>,
}

impl SilentIssuer {
    async fn start() -> SilentIssuer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a silent issuer");
        let url = format!(
            "http://{}/jwks",
            listener.local_addr().expect("listener address")
        );
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                // Held open and never read from or written to.
                held.push(stream);
            }
        });
        SilentIssuer { url, accepted }
    }

    fn dials(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

// --- the derived durations ------------------------------------------------

#[test]
fn the_floor_is_the_interval_clamped_to_the_ttl_and_to_one_second() {
    let floor = |ttl, interval| Tuning::new(ttl, interval).floor();

    assert_eq!(floor(JWKS_TTL, MIN_REFETCH_INTERVAL), secs(30), "defaults");
    assert_eq!(
        floor(secs(10), MIN_REFETCH_INTERVAL),
        secs(10),
        "a TTL below the interval"
    );
    assert_eq!(floor(secs(30), MIN_REFETCH_INTERVAL), secs(30));
    assert_eq!(
        floor(millis(500), MIN_REFETCH_INTERVAL),
        secs(1),
        "a sub-second TTL"
    );
    assert_eq!(
        floor(Duration::ZERO, MIN_REFETCH_INTERVAL),
        secs(1),
        "a zero TTL is still limited"
    );
    assert_eq!(
        floor(JWKS_TTL, Duration::ZERO),
        Duration::ZERO,
        "the test-only off switch"
    );
    assert_eq!(
        floor(JWKS_TTL, millis(500)),
        millis(500),
        "an explicit sub-second interval"
    );
    assert_eq!(floor(Duration::ZERO, millis(500)), millis(500));
    assert_eq!(floor(Duration::MAX, MIN_REFETCH_INTERVAL), secs(30));
    assert_eq!(floor(Duration::MAX, Duration::MAX), Duration::MAX);
}

#[test]
fn the_refresh_window_is_a_tenth_of_the_ttl_clamped_and_needs_three_floors() {
    let window = |ttl, interval| {
        let tuning = Tuning::new(ttl, interval);
        (tuning.refresh_window(), tuning.refresh_at())
    };

    assert_eq!(
        window(JWKS_TTL, MIN_REFETCH_INTERVAL),
        (secs(360), secs(3240)),
        "defaults"
    );
    assert_eq!(
        window(secs(120), MIN_REFETCH_INTERVAL),
        (secs(60), secs(60)),
        "at least 60 s"
    );
    assert_eq!(
        window(secs(36_000), MIN_REFETCH_INTERVAL),
        (secs(600), secs(35_400)),
        "at most 10 min"
    );
    assert_eq!(
        window(secs(90), MIN_REFETCH_INTERVAL),
        (secs(60), secs(30)),
        "exactly three floors: W stops one floor short of the TTL"
    );
    assert_eq!(
        window(secs(90) - NANO, MIN_REFETCH_INTERVAL),
        (Duration::ZERO, secs(90) - NANO),
        "under three floors: no refresh-ahead"
    );
    assert_eq!(window(TTL, MIN_REFETCH_INTERVAL), (Duration::ZERO, TTL));
    assert_eq!(
        window(Duration::ZERO, MIN_REFETCH_INTERVAL),
        (Duration::ZERO, Duration::ZERO)
    );
    assert_eq!(
        window(Duration::MAX, Duration::MAX),
        (Duration::ZERO, Duration::MAX),
        "3F overflows: no refresh-ahead, and no panic"
    );
    assert_eq!(window(Duration::MAX, MIN_REFETCH_INTERVAL).0, secs(600));
    assert_eq!(window(JWKS_TTL, Duration::ZERO), (secs(360), secs(3240)));
}

#[test]
fn the_backoff_doubles_from_one_second_to_eight_and_the_floor() {
    let defaults = Tuning::default();
    let schedule: Vec<u64> = (0..=8).map(|n| defaults.backoff(n).as_secs()).collect();
    assert_eq!(
        schedule,
        [30, 1, 2, 4, 8, 8, 8, 8, 8],
        "the floor after a success, then 1 s doubling to 8 s"
    );
    for n in [31, 32, 33, 64, u32::MAX] {
        assert_eq!(defaults.backoff(n), secs(8), "B({n})");
    }

    // Never past the floor either.
    let short = Tuning::new(secs(4), MIN_REFETCH_INTERVAL); // floor 4 s
    assert_eq!(short.backoff(3), secs(4));
    assert_eq!(short.backoff(4), secs(4));
    // A zero TTL's floor is 1 s; the off switch's is zero.
    assert_eq!(ZERO_TTL.backoff(0), secs(1));
    assert_eq!(ZERO_TTL.backoff(3), secs(1));
    assert_eq!(NO_THROTTLE.backoff(0), Duration::ZERO);
    assert_eq!(NO_THROTTLE.backoff(u32::MAX), Duration::ZERO);
    // A huge floor keeps the 8 s cap.
    let unbounded = Tuning::new(Duration::MAX, Duration::MAX);
    assert_eq!(unbounded.backoff(0), Duration::MAX);
    assert_eq!(unbounded.backoff(u32::MAX), secs(8));
}

// --- decide(), at the exact edges -------------------------------------------

/// One row of the `decide` table: the state's shape at `now`, and the
/// expected decision.
struct Row {
    tuning: Tuning,
    /// The cached set's age, if there is one (the primary key set).
    age: Option<Duration>,
    kid: &'static str,
    in_flight: bool,
    since_start: Option<Duration>,
    since_end: Option<Duration>,
    failures: u32,
    /// The kids earlier fetched sets held.
    seen: &'static [&'static str],
    /// The cached set holds the primary kid with no usable key.
    unusable: bool,
    /// The cache reports unusable keys ([`JwksCache::report_unusable_keys`]).
    report: bool,
    expect: &'static str,
}

const ROW: Row = Row {
    tuning: Tuning::new(JWKS_TTL, MIN_REFETCH_INTERVAL),
    age: None,
    kid: PRIMARY_KID,
    in_flight: false,
    since_start: None,
    since_end: None,
    failures: 0,
    seen: &[],
    unusable: false,
    report: true,
    expect: "",
};

fn kind(decision: &Decision<'_>) -> &'static str {
    match decision {
        Decision::Serve(_) => "serve",
        Decision::ServeAndRefresh(_) => "serve+refresh",
        Decision::Join(_) => "join",
        Decision::Start => "start",
        Decision::UnknownKid => "unknown-kid",
        Decision::UnseenKid => "unseen-kid",
        Decision::Unusable(_) => "unusable",
        Decision::Suppressed => "suppressed",
        Decision::TooSoon => "too-soon",
    }
}

/// `now` is a fixed instant far enough past `base` that every age below is
/// formed by addition: no instant is ever subtracted, so a freshly booted
/// machine's monotonic clock cannot underflow.
fn run_row(row: &Row) -> &'static str {
    let base = Instant::now();
    let now = base + secs(100_000);
    let ago = |by: Duration| base + (secs(100_000) - by);
    let (_sender, attempt) = attempt_channel();
    let state = State {
        cached: row.age.map(|age| Fetched {
            set: Arc::new(TestKey::primary().jwks()),
            unusable: Arc::new(
                row.unusable
                    .then(|| (PRIMARY_KID.to_owned(), UnusableReason::Use))
                    .into_iter()
                    .collect(),
            ),
            fetched_at: ago(age),
            id: 0,
        }),
        in_flight: row.in_flight.then(|| InFlight {
            id: 1,
            retry: false,
            attempt,
        }),
        last_start: row.since_start.map(ago),
        last_end: row.since_end.map(ago),
        failures: row.failures,
        seen: Seen(row.seen.iter().map(|kid| (*kid).to_owned()).collect()),
        ..State::default()
    };
    kind(&decide(&state, row.kid, now, &row.tuning, row.report))
}

#[test]
fn decide_follows_its_table_at_every_edge() {
    let r = secs(3240); // R at the defaults
    let t = JWKS_TTL;
    let f = secs(30);
    let long_ago = Some(secs(50_000));
    let sub_second_ttl = Tuning::new(millis(500), MIN_REFETCH_INTERVAL);
    // The review's case: F = min(250 ms, max(100 ms, 1 s)) = 250 ms.
    let sub_second_both = Tuning::new(millis(100), millis(250));

    #[rustfmt::skip]
    let rows = [
        // A set inside its TTL that holds the kid: served; refreshed ahead
        // from R, while nothing is in flight and the window gate is open.
        Row { age: Some(r - NANO), since_end: Some(r - NANO), expect: "serve", ..ROW },
        Row { age: Some(r), since_end: Some(r), expect: "serve+refresh", ..ROW },
        Row { age: Some(t - NANO), since_end: Some(t - NANO), expect: "serve+refresh", ..ROW },
        Row { age: Some(r), since_end: Some(r), in_flight: true, expect: "serve", ..ROW },
        // The window gate after a success is the floor, from the last end.
        Row { age: Some(r), since_end: Some(f - NANO), expect: "serve", ..ROW },
        Row { age: Some(r), since_end: Some(f), expect: "serve+refresh", ..ROW },
        // After failures, B(n) from the last end: 1 s, doubling to 8 s.
        Row { age: Some(r), since_end: Some(secs(1) - NANO), failures: 1, expect: "serve", ..ROW },
        Row { age: Some(r), since_end: Some(secs(1)), failures: 1, expect: "serve+refresh", ..ROW },
        Row { age: Some(r), since_end: Some(secs(8) - NANO), failures: 4, expect: "serve", ..ROW },
        Row { age: Some(r), since_end: Some(secs(8)), failures: 4, expect: "serve+refresh", ..ROW },
        Row { age: Some(r), since_end: Some(secs(8) - NANO), failures: 6, expect: "serve", ..ROW },
        Row { age: Some(r), since_end: Some(secs(8)), failures: u32::MAX, expect: "serve+refresh", ..ROW },
        // Measured from the end, never the start.
        Row { age: Some(r), since_start: long_ago, since_end: Some(secs(1) - NANO), failures: 1, expect: "serve", ..ROW },
        // A set inside its TTL without the kid: join, or the start-to-start
        // kid gate, which ignores the end and the failures. Closed, a kid an
        // earlier set held is unknown (retired), and one never seen is
        // unseen.
        Row { age: Some(secs(1)), kid: "other", in_flight: true, expect: "join", ..ROW },
        Row { age: Some(t - NANO), kid: "other", since_start: Some(f - NANO), seen: &["other"], expect: "unknown-kid", ..ROW },
        Row { age: Some(t - NANO), kid: "other", since_start: Some(f - NANO), seen: &[PRIMARY_KID], expect: "unseen-kid", ..ROW },
        Row { age: Some(t - NANO), kid: "other", since_start: Some(f - NANO), expect: "unseen-kid", ..ROW },
        Row { age: Some(t - NANO), kid: "other", since_start: Some(f), expect: "start", ..ROW },
        Row { age: Some(t - NANO), kid: "other", since_start: Some(f), seen: &["other"], expect: "start", ..ROW },
        Row { age: Some(secs(1)), kid: "other", since_start: Some(f), since_end: Some(Duration::ZERO), failures: 3, expect: "start", ..ROW },
        Row { age: Some(secs(1)), kid: "other", since_start: Some(f - NANO), since_end: long_ago, failures: 3, expect: "unseen-kid", ..ROW },
        Row { age: Some(secs(1)), kid: "other", since_start: Some(f - NANO), since_end: long_ago, failures: 3, seen: &["other"], expect: "unknown-kid", ..ROW },
        // At the TTL, never the set: join, or the expiry gate.
        Row { age: Some(t), in_flight: true, expect: "join", ..ROW },
        Row { age: None, in_flight: true, expect: "join", ..ROW },
        Row { age: Some(t), since_start: Some(t), since_end: Some(t), expect: "start", ..ROW },
        Row { age: Some(t), kid: "other", since_start: Some(t), since_end: Some(t), expect: "start", ..ROW },
        Row { age: None, expect: "start", ..ROW },
        Row { age: Some(t), since_end: Some(secs(1) - NANO), failures: 1, expect: "suppressed", ..ROW },
        Row { age: Some(t), since_end: Some(secs(1)), failures: 1, expect: "start", ..ROW },
        Row { age: None, since_end: Some(secs(2) - NANO), failures: 2, expect: "suppressed", ..ROW },
        Row { age: None, since_end: Some(secs(2)), failures: 2, expect: "start", ..ROW },
        Row { age: Some(t), since_end: Some(secs(8) - NANO), failures: 4, expect: "suppressed", ..ROW },
        Row { age: Some(t), since_end: Some(secs(8)), failures: 4, expect: "start", ..ROW },
        Row { age: Some(t), since_end: Some(secs(8) - NANO), failures: 5, expect: "suppressed", ..ROW },
        Row { age: Some(t), since_end: Some(secs(8)), failures: u32::MAX, expect: "start", ..ROW },
        Row { age: Some(t), kid: "other", since_end: Some(secs(8) - NANO), failures: 9, expect: "suppressed", ..ROW },
        Row { age: Some(t), since_start: long_ago, since_end: Some(secs(1) - NANO), failures: 1, expect: "suppressed", ..ROW },
        // A zero TTL: nothing is ever valid; the spacing is the 1 s floor.
        Row { tuning: ZERO_TTL, age: Some(Duration::ZERO), since_end: Some(Duration::ZERO), expect: "too-soon", ..ROW },
        Row { tuning: ZERO_TTL, since_end: Some(secs(1) - NANO), expect: "too-soon", ..ROW },
        Row { tuning: ZERO_TTL, since_end: Some(secs(1)), expect: "start", ..ROW },
        Row { tuning: ZERO_TTL, since_end: Some(secs(1) - NANO), failures: 1, expect: "suppressed", ..ROW },
        // A sub-second TTL: valid to 500 ms, then the 1 s spacing.
        Row { tuning: sub_second_ttl, age: Some(millis(500) - NANO), since_end: Some(millis(500) - NANO), expect: "serve", ..ROW },
        Row { tuning: sub_second_ttl, age: Some(millis(500)), since_end: Some(millis(500)), expect: "too-soon", ..ROW },
        Row { tuning: sub_second_ttl, age: Some(secs(1)), since_end: Some(secs(1)), expect: "start", ..ROW },
        // A sub-second TTL under a sub-second interval: the spacing is F, the interval.
        Row { tuning: sub_second_both, age: Some(millis(250) - NANO), since_end: Some(millis(250) - NANO), expect: "too-soon", ..ROW },
        Row { tuning: sub_second_both, age: Some(millis(250)), since_end: Some(millis(250)), expect: "start", ..ROW },
        // A TTL under three floors: no refresh-ahead up to the TTL.
        Row { tuning: BOUNDED, age: Some(TTL - NANO), since_end: Some(TTL - NANO), expect: "serve", ..ROW },
        Row { tuning: BOUNDED, age: Some(TTL), since_end: Some(TTL), expect: "start", ..ROW },
        // The test-only off switch: every gate open at once.
        Row { tuning: NO_THROTTLE, since_end: Some(Duration::ZERO), failures: 3, expect: "start", ..ROW },
        Row { tuning: NO_THROTTLE, age: Some(secs(1)), kid: "other", since_start: Some(Duration::ZERO), expect: "start", ..ROW },
        // No attempt behind a gate: it is open.
        Row { age: Some(secs(1)), kid: "other", expect: "start", ..ROW },
        Row { age: Some(r), expect: "serve+refresh", ..ROW },
        // A kid the set holds with no usable key (a cache that reports
        // unusable keys): never served, refreshed ahead or not; the kid gate
        // as for a kid the set lacks, and closed, `unusable` from memory,
        // though the kid is seen; past the TTL, the expiry gate, as ever.
        Row { age: Some(secs(1)), unusable: true, in_flight: true, expect: "join", ..ROW },
        Row { age: Some(r), since_end: Some(r), unusable: true, since_start: Some(f), expect: "start", ..ROW },
        Row { age: Some(t - NANO), unusable: true, since_start: Some(f), expect: "start", ..ROW },
        Row { age: Some(t - NANO), unusable: true, since_start: Some(f - NANO), seen: &[PRIMARY_KID], expect: "unusable", ..ROW },
        Row { age: Some(secs(1)), unusable: true, since_start: Some(f - NANO), expect: "unusable", ..ROW },
        Row { tuning: NO_THROTTLE, age: Some(secs(1)), unusable: true, since_start: Some(Duration::ZERO), expect: "start", ..ROW },
        Row { age: Some(t), unusable: true, since_end: Some(secs(1) - NANO), failures: 1, expect: "suppressed", ..ROW },
        Row { age: Some(t), unusable: true, since_start: Some(t), since_end: Some(t), expect: "start", ..ROW },
        // Reporting off: the same set serves the kid, refreshed ahead as any.
        Row { age: Some(secs(1)), unusable: true, report: false, since_start: Some(f - NANO), expect: "serve", ..ROW },
        Row { age: Some(r), since_end: Some(r), unusable: true, report: false, expect: "serve+refresh", ..ROW },
        // Only the kid it records: a kid the set lacks is still unseen or
        // unknown.
        Row { age: Some(secs(1)), unusable: true, kid: "other", since_start: Some(f - NANO), expect: "unseen-kid", ..ROW },
        Row { age: Some(secs(1)), unusable: true, kid: "other", since_start: Some(f - NANO), seen: &["other"], expect: "unknown-kid", ..ROW },
    ];

    let mut wrong = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let got = run_row(row);
        if got != row.expect {
            wrong.push(format!("row {index}: expected {}, got {got}", row.expect));
        }
    }
    assert!(
        wrong.is_empty(),
        "decide disagrees with its table:\n{}",
        wrong.join("\n")
    );
}

// --- lookups ---------------------------------------------------------------

#[tokio::test]
async fn a_fresh_hit_costs_no_request() {
    let server = primary_issuer(1).await;
    let cache = cache(&server, Tuning::default());

    for _ in 0..5 {
        cache.jwks_for_kid(PRIMARY_KID).await.expect("cached");
    }
}

#[tokio::test]
async fn an_expired_entry_is_refetched() {
    let server = primary_issuer(2).await;
    // Zero TTL and zero interval: every lookup finds nothing valid, and may
    // dial at once.
    let cache = cache(&server, Tuning::new(Duration::ZERO, Duration::ZERO));

    cache.jwks_for_kid(PRIMARY_KID).await.expect("first");
    cache.jwks_for_kid(PRIMARY_KID).await.expect("after expiry");
}

#[tokio::test]
async fn an_unknown_kid_refetches_and_picks_up_a_rotated_key() {
    // First response has only key 1; the second has only key 2, i.e. the
    // issuer rotated between the two lookups.
    let server = issuer_then(primary_body(), jwks_body(TestKey::secondary().jwks_json())).await;
    let cache = cache(&server, NO_THROTTLE);

    let before = cache.jwks_for_kid(PRIMARY_KID).await.expect("first key");
    assert!(before.find(SECONDARY_KID).is_none());

    let after = cache
        .jwks_for_kid(SECONDARY_KID)
        .await
        .expect("rotated key");

    assert!(after.find(SECONDARY_KID).is_some());
    assert!(
        after.find(PRIMARY_KID).is_none(),
        "the refetched set replaces the old one; a retired key stays retired"
    );
}

#[tokio::test]
async fn a_kid_still_missing_after_a_refetch_is_unknown() {
    let server = primary_issuer(2).await;
    let cache = cache(&server, NO_THROTTLE);

    cache.jwks_for_kid(PRIMARY_KID).await.expect("known key");
    assert_unknown(cache.jwks_for_kid("no-such-kid").await, "after the refetch");
}

/// The first fetch ever succeeds but lacks the kid: the issuer's verdict,
/// not an outage. Inside the floor that fetch opened, the same kid, never
/// seen in a fetched set, is answered from memory as a suppressed refetch,
/// without a second request.
#[tokio::test]
async fn a_cold_fetch_without_the_kid_is_unknown_and_opens_the_floor() {
    let server = primary_issuer(1).await;
    let cache = cache(&server, BOUNDED);

    assert_unknown(
        cache.jwks_for_kid("attacker-supplied-kid").await,
        "cold fetch",
    );
    assert_eq!(requests(&server).await, 1, "the cold lookup dials once");

    assert_unseen(
        cache.jwks_for_kid("attacker-supplied-kid").await,
        "inside the floor",
    );
    assert_eq!(requests(&server).await, 1, "answered from memory");
}

/// A set younger than the TTL, an unknown kid, and the last attempt a full
/// floor ago: a rotation, picked up by one refetch rather than after the
/// rest of the TTL.
#[tokio::test]
async fn an_unknown_kid_outside_the_floor_refetches_and_picks_up_a_rotated_key() {
    let server = issuer(jwks_body(TestKey::secondary().jwks_json()), 1).await;
    let cache = cache(&server, BOUNDED);
    // Fetched 45 s ago by the attempt then: inside the 60 s TTL, outside the
    // 30 s floor.
    cache.seed();
    cache.advance_for_test(secs(45));

    let after = cache
        .jwks_for_kid(SECONDARY_KID)
        .await
        .expect("the rotated key, refetched");
    assert!(after.find(SECONDARY_KID).is_some());
    assert_eq!(requests(&server).await, 1, "one refetch");

    // The refetch replaced the set and opened a new floor: the retired key
    // is unknown now, and that is answered from memory.
    assert_unknown(cache.jwks_for_kid(PRIMARY_KID).await, "the retired key");
    assert_eq!(requests(&server).await, 1, "answered from memory");
}

#[tokio::test]
async fn a_never_seen_kid_inside_the_floor_does_not_refetch() {
    // One request total: the lookup for the known key. The ones that follow
    // are answered from memory, without touching the issuer.
    let server = primary_issuer(1).await;
    let cache = cache(&server, BOUNDED);

    cache.jwks_for_kid(PRIMARY_KID).await.expect("known key");
    for _ in 0..2 {
        assert_unseen(
            cache.jwks_for_kid("attacker-supplied-kid").await,
            "inside the floor",
        );
    }

    // Past the TTL the set is no longer the issuer's word on which keys
    // exist: with a failure too recent to retry, that is an outage, not a
    // verdict on the kid. (v0.8.0 answered UnknownKid here.)
    cache.advance_for_test(secs(75));
    cache.failed_just_now(1);
    assert_jwks(
        cache.jwks_for_kid("attacker-supplied-kid").await,
        SUPPRESSED,
        "past the TTL",
    );
    assert_eq!(requests(&server).await, 1);
}

/// v0.8.0 served a set up to one interval past its TTL when a refetch was
/// suppressed; no set past its TTL answers a lookup now, and the lookup that
/// finds one inside a backoff step does not dial either.
#[tokio::test]
async fn an_expired_entry_is_not_served_when_a_refetch_is_suppressed() {
    let server = primary_issuer(0).await;
    let cache = cache(&server, BOUNDED);
    cache.seed();
    cache.advance_for_test(secs(75)); // 15 s past the TTL, inside v0.8.0's 90 s bound
    cache.failed_just_now(1);
    let attempt = cache.last_start();

    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        SUPPRESSED,
        "15 s past the TTL",
    );
    assert_eq!(cache.last_start(), attempt, "not dialed");
}

#[tokio::test]
async fn a_suppressed_refetch_after_a_failure_reports_the_outage() {
    let server = issuer(ResponseTemplate::new(503), 1).await;
    let cache = cache(&server, BOUNDED);

    // With nothing ever cached, the caller's token can't be blamed.
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        "503",
        "the failing fetch",
    );
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        SUPPRESSED,
        "nothing ever cached",
    );

    // Nor with a set that has the kid but is past the TTL: inside the
    // backoff a failure opened, it is no usable set at all.
    cache.seed();
    cache.advance_for_test(secs(105));
    cache.failed_just_now(1);
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        SUPPRESSED,
        "a set past the TTL",
    );
}

/// The suppressed rows through the public entry point. Every lookup sits
/// inside a backoff step a failed attempt opened, so none may dial.
#[tokio::test]
async fn a_suppressed_lookup_past_the_ttl_is_an_outage_not_a_verdict() {
    let server = primary_issuer(0).await;
    let cache = cache(&server, BOUNDED);

    // Past the TTL: an outage whether or not the set has the kid, however
    // far past it.
    for age in [secs(75), secs(105)] {
        cache.seed();
        cache.advance_for_test(age);
        cache.failed_just_now(1);
        let attempt = cache.last_start();
        for kid in [PRIMARY_KID, "attacker-supplied-kid"] {
            assert_jwks(cache.jwks_for_kid(kid).await, SUPPRESSED, kid);
        }
        assert_eq!(cache.last_start(), attempt, "not dialed");
    }

    // Inside the TTL: still the issuer's word, the known key served, and
    // the never-seen one a suppressed refetch.
    cache.seed();
    cache.advance_for_test(secs(45));
    cache.failed_just_now(1);
    let attempt = cache.last_start();
    cache
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("inside the TTL, and holds the key");
    assert_unseen(
        cache.jwks_for_kid("attacker-supplied-kid").await,
        "inside the TTL",
    );
    assert_eq!(cache.last_start(), attempt, "not dialed");
}

/// The outage timeline v0.8.0 got wrong (t counts from the last success).
/// Every attempt fails; the set is past its TTL throughout, and no run of
/// failures serves it.
#[tokio::test]
async fn failed_attempts_never_revive_an_expired_set() {
    let server = issuer(ResponseTemplate::new(503), 3).await;
    let cache = cache(&server, BOUNDED);
    cache.seed();
    cache.advance_for_test(secs(90));
    let last_success = cache.fetched_at();

    assert_jwks(cache.jwks_for_kid(PRIMARY_KID).await, "503", "attempt 1");
    assert_eq!(
        cache.fetched_at(),
        last_success,
        "a failed attempt is not a success"
    );
    // Inside attempt 1's backoff: v0.8.0 served the set here.
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        SUPPRESSED,
        "after attempt 1",
    );

    cache.advance_for_test(secs(1));
    assert_jwks(cache.jwks_for_kid(PRIMARY_KID).await, "503", "attempt 2");
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        SUPPRESSED,
        "after attempt 2",
    );

    // Much later, the gate is open again, and the set is still not served.
    cache.advance_for_test(secs(45));
    assert_jwks(cache.jwks_for_kid(PRIMARY_KID).await, "503", "attempt 3");
    assert_eq!(cache.fetched_at(), last_success);
    assert_eq!(requests(&server).await, 3);
}

/// The defect report's repro, to the letter: a set 1 s past its TTL, a
/// refetch that fails, and a second lookup right after. v0.8.0 answered the
/// second one with the expired set.
#[tokio::test]
async fn an_expired_set_is_not_served_after_a_failed_refetch() {
    let server = issuer(ResponseTemplate::new(500), 1).await;
    let cache = cache(&server, BOUNDED);
    cache.seed();
    cache.advance_for_test(secs(61));

    // 1st lookup: the TTL has expired, the refetch runs and fails.
    assert_jwks(cache.jwks_for_kid(PRIMARY_KID).await, "500", "1st lookup");
    // 2nd lookup, inside the backoff: an error too, and no dial.
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        SUPPRESSED,
        "2nd lookup",
    );
    assert_eq!(requests(&server).await, 1, "one attempt, not two");
}

/// A TTL below the interval: v0.8.0 served the expired set with no fetch
/// attempt at all, because the warm fetch still held the interval. The floor
/// is the TTL then, so expiry refetches, and a healthy issuer gets a fresh
/// set rather than a refusal.
#[tokio::test]
async fn a_ttl_below_the_interval_refetches_at_expiry() {
    let server = primary_issuer(2).await;
    let cache = cache(&server, Tuning::new(secs(10), MIN_REFETCH_INTERVAL));

    cache.jwks_for_kid(PRIMARY_KID).await.expect("warm");
    cache.advance_for_test(secs(25)); // past the TTL, inside the 30 s interval
    cache
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("expired, so refetched; the issuer is healthy");
    assert_eq!(requests(&server).await, 2);

    // And the refetch renewed the set: the next lookup is a plain hit.
    cache.jwks_for_kid(PRIMARY_KID).await.expect("fresh hit");
    assert_eq!(requests(&server).await, 2);
}

/// The same shape with the issuer down at expiry: the TTL is still a bound,
/// and the backoff still spaces the attempts.
#[tokio::test]
async fn a_ttl_below_the_interval_is_still_a_bound_when_the_refetch_fails() {
    let server = issuer(ResponseTemplate::new(503), 2).await;
    let cache = cache(&server, Tuning::new(secs(10), MIN_REFETCH_INTERVAL));
    cache.seed();
    cache.advance_for_test(secs(25));

    assert_jwks(cache.jwks_for_kid(PRIMARY_KID).await, "503", "attempt 1");
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        SUPPRESSED,
        "inside the backoff",
    );

    // 1 s on: past the first backoff step, still inside the 10 s floor.
    cache.advance_for_test(secs(1));
    assert_jwks(cache.jwks_for_kid(PRIMARY_KID).await, "503", "attempt 2");
    assert_eq!(requests(&server).await, 2);
}

/// A herd that meets an expired set and a dead issuer: one attempt, and
/// every caller is refused. (v0.8.0 refused the one that dialed and served
/// the expired set to the rest.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_herd_after_expiry_with_a_failing_issuer_dials_once_and_all_fail() {
    let server = issuer(
        // Slow, so every other task piles up behind the first one's fetch.
        ResponseTemplate::new(503).set_delay(millis(100)),
        1,
    )
    .await;
    let cache = Arc::new(cache(&server, BOUNDED));
    cache.seed();
    cache.advance_for_test(secs(75));

    for (result, _) in herd(&cache, 16).await {
        assert!(
            matches!(result, Err(AuthError::Jwks(_))),
            "an expired set must not answer anyone: {result:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_misses_make_one_request() {
    let server = issuer(
        // A slow response widens the window in which every other task
        // piles up behind the first one's fetch.
        primary_body().set_delay(millis(100)),
        1,
    )
    .await;
    let cache = Arc::new(cache(&server, Tuning::default()));

    for (result, _) in herd(&cache, 16).await {
        result.expect("jwks");
    }
}

// --- refresh-ahead ---------------------------------------------------------

/// (a) One transient failure near expiry, then a healthy issuer, at TTL 120 s
/// (refresh-ahead from 60 s): lookups at 75, 110, 125, 125 and 140 s. The
/// refresh at 75 s fails and the set answers; the one at 110 s renews it.
/// v0.8.0 refused one of these lookups, and a TTL bound without
/// refresh-ahead refused three.
#[tokio::test]
async fn one_blip_near_expiry_refuses_nothing() {
    let server = issuer_then(ResponseTemplate::new(503), primary_body()).await;
    let cache = cache(&server, BLIP);
    cache.seed();

    let mut refused = Vec::new();
    for (at, by) in [(75, 75), (110, 35), (125, 15), (125, 0), (140, 15)] {
        cache.advance_for_test(secs(by));
        if let Err(err) = cache.jwks_for_kid(PRIMARY_KID).await {
            refused.push(format!("t={at}: {err}"));
        }
        cache.settle().await;
    }
    assert!(refused.is_empty(), "refused around one blip: {refused:?}");
    assert_eq!(requests(&server).await, 2);
    assert_eq!(cache.failures(), 0, "the second refresh succeeded");
}

/// (b) A refresh-ahead that keeps failing: the set answers every lookup
/// until its TTL, and from the TTL on it answers none.
#[tokio::test]
async fn a_failing_refresh_ahead_serves_until_the_ttl_and_refuses_at_it() {
    let server = issuer(ResponseTemplate::new(503), 3).await;
    let cache = cache(&server, BLIP);
    cache.seed();

    for (at, by) in [(60, 60), (90, 30), (119, 29)] {
        cache.advance_for_test(secs(by));
        cache
            .jwks_for_kid(PRIMARY_KID)
            .await
            .unwrap_or_else(|err| panic!("t={at}: the set is inside its TTL: {err}"));
        cache.settle().await;
    }
    assert_eq!(cache.failures(), 3, "three refreshes ran and failed");
    assert_eq!(requests(&server).await, 3);

    cache.advance_for_test(secs(1)); // t = 120: the TTL
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        SUPPRESSED,
        "t=120, 1 s after a third failure (Bx(3) = 4 s)",
    );
    assert_eq!(requests(&server).await, 3);
}

/// (j) A TTL under three floors leaves no room to refresh ahead: the set is
/// served to its TTL and refetched at it.
#[tokio::test]
async fn a_ttl_under_three_floors_never_refreshes_ahead() {
    let server = primary_issuer(1).await;
    let cache = cache(&server, BOUNDED);
    cache.seed();

    cache.advance_for_test(TTL - secs(1));
    cache
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("inside the TTL");
    assert!(!cache.in_flight(), "no refresh started");
    assert_eq!(requests(&server).await, 0);

    cache.advance_for_test(secs(1));
    cache
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("refetched at the TTL");
    assert_eq!(requests(&server).await, 1);
}

// --- cancellation and recovery -----------------------------------------------

/// A caller cancelled mid-fetch (its request timed out, its client went
/// away) does not cancel the fetch: the attempt runs to completion as a
/// failure on its own task, a second lookup joins it rather than dialing,
/// and the end is stamped at the completion. (v0.8.0 ran the fetch in the
/// caller's future, so the cancel dropped it.) The clock moves 5 s while the
/// attempt is in flight, so "stamped at completion" is exact.
#[tokio::test]
async fn a_cancelled_caller_never_cancels_the_fetch() {
    let silent = SilentIssuer::start().await;
    let cache = cache_at(
        silent.url.clone(),
        Tuning {
            fetch_timeout: millis(300),
            ..BOUNDED
        },
    );
    cache.seed();
    cache.advance_for_test(secs(105));
    let last_success = cache.fetched_at();

    cancel_a_lookup(&cache, "the caller");
    assert!(cache.in_flight(), "the fetch outlived its caller");
    let started = cache.last_start();
    cache.advance_for_test(secs(5));

    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        "fetch failed",
        "a second lookup joins the same attempt",
    );
    assert_eq!(silent.dials(), 1, "joined, not dialed");
    {
        let state = cache.inner.state();
        assert!(state.in_flight.is_none());
        assert_eq!(state.failures, 1, "the attempt counted once, as a failure");
        assert_eq!(state.cached.as_ref().map(|c| c.fetched_at), last_success);
        assert_eq!(state.last_start, started, "one attempt");
        assert_eq!(
            state.last_end,
            started.map(|at| at + secs(5)),
            "the end is stamped at completion, not at the cancel"
        );
    }

    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        SUPPRESSED,
        "then backed off",
    );
    assert_eq!(silent.dials(), 1);
}

/// (c) A caller cancelled while a healthy issuer is still answering leaves
/// the fetch to complete: one request, and the next lookup is a fresh hit.
#[tokio::test]
async fn a_cancelled_caller_leaves_a_healthy_fetch_to_complete() {
    let server = issuer(primary_body().set_delay(millis(300)), 1).await;
    let cache = cache(&server, BOUNDED);

    cancel_a_lookup(&cache, "the caller");
    cache.settle().await;

    assert_eq!(requests(&server).await, 1);
    cache.jwks_for_kid(PRIMARY_KID).await.expect("a fresh hit");
    assert_eq!(requests(&server).await, 1, "from memory");
}

/// (d) The cancel lands at expiry, the issuer is healthy: nothing after it is
/// refused, the lookup that arrives mid-fetch included.
#[tokio::test]
async fn a_cancel_at_expiry_with_a_healthy_issuer_refuses_nothing_later() {
    let server = issuer(primary_body().set_delay(millis(300)), 1).await;
    let cache = cache(&server, BOUNDED);
    cache.seed();
    cache.advance_for_test(secs(61));

    cancel_a_lookup(&cache, "the caller");
    cache
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("joined the cancelled caller's fetch");
    for _ in 0..3 {
        cache.jwks_for_kid(PRIMARY_KID).await.expect("fresh hit");
    }
    assert_eq!(requests(&server).await, 1);
}

/// (e) An expired set and an issuer that fails once, then recovers: one
/// dial, retries suppressed up to the nanosecond before 1 s after the failure
/// completed, and recovery at that second.
#[tokio::test]
async fn recovery_after_expiry_comes_one_second_after_the_failure() {
    let server = issuer_then(ResponseTemplate::new(503), primary_body()).await;
    let cache = cache(&server, BOUNDED);
    cache.seed();
    cache.advance_for_test(secs(61));

    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        "503",
        "the failing attempt",
    );
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        SUPPRESSED,
        "an immediate retry",
    );
    cache.advance_for_test(secs(1) - NANO);
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        SUPPRESSED,
        "1 ns before 1 s on",
    );
    assert_eq!(requests(&server).await, 1);

    cache.advance_for_test(NANO);
    cache
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("recovered 1 s after the failure");
    assert_eq!(requests(&server).await, 2);
}

/// (f) Under a permanent failure after expiry, attempts are spaced 1, 2, 4,
/// 8, 8 s apart, each measured from the previous attempt's completion, and
/// checked at the nanosecond either side. Every attempt takes 500 ms on the
/// cache's clock: had a step been measured from the start, the probe 1 ns
/// before it ends would already be 500 ms past it and would dial.
#[tokio::test]
async fn the_backoff_after_expiry_runs_from_completion_and_caps_at_eight_seconds() {
    let flight = millis(500);
    let server = issuer(ResponseTemplate::new(503), 6).await;
    let cache = cache(&server, BOUNDED);
    cache.seed();
    cache.advance_for_test(secs(61));

    assert_jwks(an_attempt_taking(&cache, flight).await, "503", "attempt 1");
    for (attempt, step) in [(2, 1), (3, 2), (4, 4), (5, 8), (6, 8)] {
        cache.advance_for_test(secs(step) - NANO);
        assert_jwks(
            cache.jwks_for_kid(PRIMARY_KID).await,
            SUPPRESSED,
            &format!("1 ns before step {step} s ends"),
        );
        cache.advance_for_test(NANO);
        assert_jwks(
            an_attempt_taking(&cache, flight).await,
            "503",
            &format!("attempt {attempt}, {step} s after the last one completed"),
        );
    }
    assert_eq!(requests(&server).await, 6);
}

/// (g) A black-holed issuer: it accepts and never answers. The first
/// attempt's joiners wait for its fetch timeout, and no longer than their
/// own bound. A retry's joiners give up after the join wait, with the fetch
/// still running, and later lookups join it rather than dialing. One fetch
/// at a time, and as many as the backoff schedule allows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_black_holed_issuer_holds_a_retrys_joiners_only_for_the_join_wait() {
    let silent = SilentIssuer::start().await;
    let fetch_timeout = secs(2);
    let join_wait = millis(200);
    let tuning = Tuning {
        fetch_timeout,
        retry_join_wait: join_wait,
        ..BOUNDED
    };
    let cache = Arc::new(cache_at(silent.url.clone(), tuning));
    cache.seed();
    cache.advance_for_test(secs(61));

    // Attempt 1, a first attempt: everyone waits for the fetch timeout.
    for (result, waited) in herd(&cache, 8).await {
        assert_jwks(result, "fetch failed", "attempt 1's joiner");
        assert!(
            waited >= fetch_timeout * 4 / 5,
            "a first attempt is waited for: {waited:?}"
        );
        assert!(
            waited < tuning.first_join_wait,
            "and no longer than the joiner's own bound: {waited:?}"
        );
    }
    assert_eq!(silent.dials(), 1);
    assert_eq!(cache.failures(), 1);

    // Inside Bx(1): refused at once.
    cache.advance_for_test(secs(1) - NANO);
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        SUPPRESSED,
        "inside Bx(1)",
    );

    // Attempt 2, a retry: everyone gives up after the join wait.
    cache.advance_for_test(NANO);
    for (result, waited) in herd(&cache, 8).await {
        assert_jwks(result, STILL_IN_PROGRESS, "attempt 2's joiner");
        assert!(
            waited >= join_wait * 4 / 5 && waited < join_wait * 5,
            "a retry's joiner waits the join wait: {waited:?}"
        );
    }
    assert!(
        cache.in_flight(),
        "the retry carries on without its joiners"
    );
    for (result, _) in herd(&cache, 4).await {
        assert_jwks(result, STILL_IN_PROGRESS, "a later joiner of attempt 2");
    }
    assert_eq!(silent.dials(), 2, "one dial for the whole retry");
    assert_eq!(cache.attempts_reserved(), 2);

    cache.settle().await;
    assert_eq!(cache.failures(), 2);

    // The schedule: Bx(2) = 2 s.
    cache.advance_for_test(secs(2) - NANO);
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        SUPPRESSED,
        "1 ns inside Bx(2)",
    );
    cache.advance_for_test(NANO);
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        STILL_IN_PROGRESS,
        "attempt 3",
    );
    cache.settle().await;

    assert_eq!(silent.dials(), 3, "one dial per attempt");
    assert_eq!(
        cache.attempts_reserved(),
        3,
        "three attempts, as the schedule allows"
    );
    assert_eq!(cache.failures(), 3);
}

/// (h) A flood of random kids. Against a fresh set, one request for the
/// lot; against an expired set inside a backoff step, none; and after a
/// failed refresh-ahead, the kid gate still holds for the rest of its floor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kid_flood_cannot_turn_lookups_into_fetches() {
    async fn flood(cache: &Arc<JwksCache>) -> Vec<(Result<Arc<JwkSet>, AuthError>, Duration)> {
        concurrent_lookups(cache, (0..100).map(|i| format!("attacker-kid-{i}"))).await
    }

    // A fresh set, last fetched more than a floor ago.
    let server = issuer(primary_body().set_delay(millis(100)), 1).await;
    let fresh = Arc::new(cache(&server, BOUNDED));
    fresh.seed();
    fresh.advance_for_test(secs(31));
    for (result, _) in flood(&fresh).await {
        assert_unknown(result, "against a fresh set");
    }
    assert_eq!(
        requests(&server).await,
        1,
        "one refetch for the whole flood"
    );

    // An expired set, a failure just now.
    let server = issuer(ResponseTemplate::new(503), 0).await;
    let expired = Arc::new(cache(&server, BOUNDED));
    expired.seed();
    expired.advance_for_test(secs(61));
    expired.failed_just_now(1);
    for (result, _) in flood(&expired).await {
        assert_jwks(result, SUPPRESSED, "inside a backoff step");
    }
    assert_eq!(requests(&server).await, 0);

    // A failed refresh-ahead: the set answers its own kid, and the flood is
    // answered from memory for the rest of the floor.
    let server = issuer(ResponseTemplate::new(503), 1).await;
    let refreshing = Arc::new(cache(&server, BLIP));
    refreshing.seed();
    refreshing.advance_for_test(secs(75));
    refreshing
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("served, refresh started");
    refreshing.settle().await;
    assert_eq!(refreshing.failures(), 1);
    for (result, _) in flood(&refreshing).await {
        assert_unseen(result, "just after the failed refresh");
    }
    refreshing.advance_for_test(secs(29));
    for (result, _) in flood(&refreshing).await {
        assert_unseen(result, "29 s after it");
    }
    assert_eq!(requests(&server).await, 1, "only the refresh dialed");
    // Only fetched sets add to the seen kids: the flood added none.
    assert!(refreshing
        .inner
        .state()
        .seen
        .0
        .iter()
        .all(|kid| !kid.starts_with("attacker-kid-")));
}

/// The two verdicts inside the floor, through the public entry point: a kid
/// an earlier fetched set held and the current one lacks (a retired key) is
/// `UnknownKid`, one no fetched set held is `UnseenKid`, and neither dials.
/// Once the floor has passed, a never-seen kid refetches, and still absent
/// after that refetch it is `UnknownKid`.
#[tokio::test]
async fn inside_the_floor_a_retired_kid_is_unknown_and_a_never_seen_one_unseen() {
    // The issuer rotates from the primary key to the secondary, and serves
    // that for the last two fetches.
    let server = MockServer::start().await;
    for (body, times) in [
        (primary_body(), 1),
        (jwks_body(TestKey::secondary().jwks_json()), 2),
    ] {
        wiremock::Mock::given(wiremock::matchers::path("/jwks"))
            .respond_with(body)
            .up_to_n_times(times)
            .expect(times)
            .mount(&server)
            .await;
    }
    let cache = cache(&server, BOUNDED);

    cache
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("the first key");
    cache.advance_for_test(secs(31));
    cache
        .jwks_for_kid(SECONDARY_KID)
        .await
        .expect("the rotated key, refetched");
    assert_eq!(requests(&server).await, 2);

    // Inside the floor that refetch opened.
    assert_unknown(cache.jwks_for_kid(PRIMARY_KID).await, "the retired key");
    assert_unseen(cache.jwks_for_kid("never-seen").await, "a never-seen kid");
    assert_eq!(requests(&server).await, 2, "both from memory");

    // Past the floor, inside the TTL: a refetch, and the issuer's verdict.
    cache.advance_for_test(secs(30));
    assert_unknown(
        cache.jwks_for_kid("never-seen").await,
        "absent after a refetch",
    );
    assert_eq!(requests(&server).await, 3, "one refetch");
    // That refetch added nothing: still never seen, inside the new floor.
    assert_unseen(cache.jwks_for_kid("never-seen").await, "the new floor");
    assert_unknown(cache.jwks_for_kid(PRIMARY_KID).await, "still retired");
    assert_eq!(requests(&server).await, 3);
}

// --- report_unusable_keys (rule 5) ----------------------------------------

/// The primary key's JWKS with its `use` set to `enc`: the kid is held, and
/// no key under it can verify RS256.
fn primary_for_encryption() -> String {
    let mut set: serde_json::Value =
        serde_json::from_str(test_jwks_json()).expect("the committed JWKS");
    set["keys"][0]["use"] = serde_json::json!("enc");
    set.to_string()
}

#[track_caller]
fn assert_unusable(
    result: Result<Arc<JwkSet>, AuthError>,
    expected: UnusableReason,
    context: &str,
) {
    match result {
        Err(AuthError::UnusableKey(reason)) => assert_eq!(reason, expected, "{context}"),
        Ok(_) => panic!("{context}: served a set; expected UnusableKey({expected})"),
        Err(other) => panic!("{context}: expected UnusableKey({expected}), got {other}"),
    }
}

/// An issuer that answers its first `unusable` requests with the primary
/// key labelled for encryption, and every one after that with the usable
/// primary key: a broken key, then the issuer's fix.
async fn unusable_then_fixed(unusable: u64, fixed: u64) -> MockServer {
    let server = MockServer::start().await;
    for (body, times) in [
        (jwks_body(&primary_for_encryption()), unusable),
        (primary_body(), fixed),
    ] {
        wiremock::Mock::given(wiremock::matchers::path("/jwks"))
            .respond_with(body)
            .up_to_n_times(times)
            .expect(times)
            .mount(&server)
            .await;
    }
    server
}

/// Rule 5: a kid the set holds with no usable key is `UnusableKey`, with
/// the reason, from the fetch that found it and then from memory inside the
/// floor; each floor buys one refetch, and the refetch that finds a usable
/// key under the kid serves it.
#[tokio::test]
async fn an_unusable_kid_refetches_once_per_floor_and_picks_up_a_fixed_key() {
    let server = unusable_then_fixed(2, 1).await;
    let cache = cache(&server, BOUNDED).report_unusable_keys(true);
    assert!(cache.reports_unusable_keys());

    assert_unusable(
        cache.jwks_for_kid(PRIMARY_KID).await,
        UnusableReason::Use,
        "the cold fetch",
    );
    assert_eq!(requests(&server).await, 1);
    cache.advance_for_test(secs(30) - NANO);
    for _ in 0..3 {
        assert_unusable(
            cache.jwks_for_kid(PRIMARY_KID).await,
            UnusableReason::Use,
            "inside the floor",
        );
    }
    assert_eq!(requests(&server).await, 1, "answered from memory");

    cache.advance_for_test(NANO);
    assert_unusable(
        cache.jwks_for_kid(PRIMARY_KID).await,
        UnusableReason::Use,
        "the floor's one refetch, still unusable",
    );
    assert_eq!(requests(&server).await, 2);
    assert_unusable(
        cache.jwks_for_kid(PRIMARY_KID).await,
        UnusableReason::Use,
        "inside the floor that refetch opened",
    );
    assert_eq!(requests(&server).await, 2, "answered from memory");

    // 60 s on the clock: the refetched set (30 s old) is inside its TTL.
    cache.advance_for_test(secs(30));
    cache
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("the next floor's refetch finds the fixed key");
    assert_eq!(requests(&server).await, 3);
    cache
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("served from memory");
    assert_eq!(requests(&server).await, 3);
}

/// The control: off (the default), the same set is served for the kid it
/// holds, as through v0.9.0, and never refetched for it.
#[tokio::test]
async fn without_report_unusable_keys_a_held_kid_is_served_whatever_its_key() {
    let server = issuer(jwks_body(&primary_for_encryption()), 1).await;
    let cache = cache(&server, BOUNDED);
    assert!(!cache.reports_unusable_keys());

    for _ in 0..3 {
        let set = cache
            .jwks_for_kid(PRIMARY_KID)
            .await
            .expect("a set holding the kid");
        assert!(set.find(PRIMARY_KID).is_some());
    }
}

/// A herd for an unusable kid inside the TTL, its floor open, shares the one
/// refetch the floor allows, and every lookup gets the reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_herd_for_an_unusable_kid_makes_one_refetch() {
    let server = MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::path("/jwks"))
        .respond_with(jwks_body(&primary_for_encryption()).set_delay(millis(100)))
        .expect(2)
        .mount(&server)
        .await;
    let cache = Arc::new(cache(&server, BOUNDED).report_unusable_keys(true));
    assert_unusable(
        cache.jwks_for_kid(PRIMARY_KID).await,
        UnusableReason::Use,
        "the cold fetch",
    );
    cache.advance_for_test(secs(30));

    for (result, _) in herd(&cache, 16).await {
        assert_unusable(result, UnusableReason::Use, "a herd member");
    }
    assert_eq!(requests(&server).await, 2, "one refetch for the herd");
}

/// A set of `count` copies of the primary key, kids `{prefix}0` and up.
fn set_of(prefix: &str, count: usize) -> JwkSet {
    let key = TestKey::primary().jwks().keys.remove(0);
    JwkSet {
        keys: (0..count)
            .map(|i| {
                let mut key = key.clone();
                key.common.key_id = Some(format!("{prefix}{i}"));
                key
            })
            .collect(),
    }
}

/// The seen kids are bounded: the newest fetched sets' kids are kept, the
/// oldest forgotten past the cap, a kid fetched again becomes the newest,
/// and a set larger than the cap keeps its last kids.
#[test]
fn the_seen_kids_are_bounded_and_newest_last() {
    let mut seen = Seen::default();
    seen.record(&set_of("a", 3));
    assert!(seen.contains("a0") && seen.contains("a2"));
    assert!(!seen.contains("b0"));

    // Re-recording a kid moves it to the newest end, with no duplicate.
    seen.record(&set_of("a", 1));
    assert_eq!(seen.0.len(), 3);
    assert_eq!(seen.0.back().map(String::as_str), Some("a0"));

    // Sixty-two more: the cap is reached and the oldest go first.
    seen.record(&set_of("b", 62));
    assert_eq!(seen.0.len(), SEEN_KIDS);
    assert!(!seen.contains("a1"), "the oldest is forgotten");
    assert!(seen.contains("a2") && seen.contains("a0") && seen.contains("b61"));

    // A set past the cap on its own: its last kids, and the cap holds.
    seen.record(&set_of("c", 1000));
    assert_eq!(seen.0.len(), SEEN_KIDS);
    assert!(seen.contains("c999") && seen.contains("c936"));
    assert!(!seen.contains("c935") && !seen.contains("b61"));

    // A key with no kid adds nothing.
    let mut no_kid = set_of("x", 1);
    no_kid.keys[0].common.key_id = None;
    let before = seen.0.clone();
    seen.record(&no_kid);
    assert_eq!(seen.0, before);
}

/// (i) A zero TTL caches nothing: two lookups that waited on one fetch both
/// get its set, a lookup 1 ns short of a second after it is refused with
/// the spacing message, and one at the second fetches.
#[tokio::test]
async fn a_zero_ttl_serves_only_its_joiners_and_fetches_at_most_once_a_second() {
    let server = issuer(primary_body().set_delay(millis(50)), 2).await;
    let cache = cache(&server, ZERO_TTL);

    let (first, second) = tokio::join!(
        cache.jwks_for_kid(PRIMARY_KID),
        cache.jwks_for_kid(PRIMARY_KID)
    );
    first.expect("the lookup that started the fetch");
    second.expect("the lookup that joined it");
    assert_eq!(requests(&server).await, 1);
    assert!(cache.inner.state().cached.is_none(), "nothing is cached");

    cache.advance_for_test(secs(1) - NANO);
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        TOO_SOON,
        "1 ns short of 1 s on",
    );
    cache.advance_for_test(NANO);
    cache.jwks_for_kid(PRIMARY_KID).await.expect("1 s on");
    assert_eq!(requests(&server).await, 2);
}

/// (k) Rule J: a lookup that waited on a fetch and resumes only after the
/// set crossed its TTL is refused, not handed the set.
#[tokio::test]
async fn a_joiner_resuming_after_the_ttl_is_refused() {
    let server = primary_issuer(1).await;
    let cache = cache(&server, BOUNDED);

    let mut lookup = Box::pin(cache.jwks_for_kid(PRIMARY_KID));
    assert!(
        (&mut lookup).now_or_never().is_none(),
        "waiting on its fetch"
    );
    cache.settle().await;
    cache.advance_for_test(TTL);

    assert_jwks(lookup.await, EXPIRED_BEFORE_USE, "resumed at the TTL");
}

/// (l) A fresh hit never waits behind a fetch: no lock is held across one.
/// Checked twice, with a refresh-ahead in flight and with an unknown-kid
/// fetch in flight. Both fetches are held at a silent issuer, which accepts
/// and never answers, under a 60 s fetch timeout, so each is provably still
/// in flight when the hit is made and when `in_flight()` is asserted: only
/// that timeout could end it. The proof is that the hit completes on its
/// first poll (it never awaits anything); the 500 ms wall-clock bound beside
/// it is 120× under the fetch it must not wait for. Neither fetch is waited
/// for: both end with the test's runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_hit_never_waits_behind_a_fetch() {
    const HELD: Duration = secs(60);

    #[track_caller]
    fn assert_answers_at_once(cache: &JwksCache, silent: &SilentIssuer, context: &str) {
        assert_eq!(
            silent.dials(),
            1,
            "{context}: the fetch is held at the issuer"
        );
        let started = Instant::now();
        match cache.jwks_for_kid(PRIMARY_KID).now_or_never() {
            Some(Ok(_)) => {}
            Some(Err(err)) => panic!("{context}: {err}"),
            None => panic!("{context}: the hit waited behind the fetch"),
        }
        let waited = started.elapsed();
        assert!(
            waited < millis(500),
            "{context}: took {waited:?} with the fetch held for up to {HELD:?}"
        );
        assert!(
            cache.in_flight(),
            "{context}: the held fetch was in flight throughout"
        );
    }

    // A refresh-ahead in flight.
    let silent = SilentIssuer::start().await;
    let cache = cache_at(
        silent.url.clone(),
        Tuning {
            fetch_timeout: HELD,
            ..BLIP
        },
    );
    cache.seed();
    cache.advance_for_test(secs(75));
    cache
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("served, refresh started");
    until("the refresh to reach the issuer", || silent.dials() == 1).await;
    assert_answers_at_once(&cache, &silent, "behind a refresh-ahead");

    // An unknown-kid fetch in flight, with a lookup waiting on it.
    let silent = SilentIssuer::start().await;
    let cache = Arc::new(cache_at(
        silent.url.clone(),
        Tuning {
            fetch_timeout: HELD,
            ..BOUNDED
        },
    ));
    cache.seed();
    cache.advance_for_test(secs(31));
    let rotation = tokio::spawn({
        let cache = Arc::clone(&cache);
        async move { cache.jwks_for_kid("rotated-kid").await }
    });
    until("the unknown-kid fetch to reach the issuer", || {
        silent.dials() == 1
    })
    .await;
    assert_answers_at_once(&cache, &silent, "behind an unknown-kid fetch");
    assert!(
        !rotation.is_finished(),
        "the rotation lookup is still waiting"
    );
    rotation.abort();
}

// --- the single-flight slot: gcp's sequence and its races -------------------

/// (m) A fetch that panics answers each of its waiters "refetch aborted",
/// clears its slot, counts as one failure, and the next lookup past the
/// backoff dials again.
#[tokio::test]
async fn a_panicking_fetch_aborts_its_waiters_and_counts_as_a_failure() {
    let server = primary_issuer(1).await;
    let cache = cache(&server, BOUNDED);
    cache.inner.panics_left.store(1, Ordering::SeqCst);

    let mut first = Box::pin(cache.jwks_for_kid(PRIMARY_KID));
    let mut second = Box::pin(cache.jwks_for_kid(PRIMARY_KID));
    assert!((&mut first).now_or_never().is_none());
    assert!((&mut second).now_or_never().is_none());

    for waiter in [first.await, second.await] {
        assert_jwks(waiter, ABORTED, "a waiter of the panicked attempt");
    }
    cache.assert_one_failed_attempt("the panicked attempt");
    assert_eq!(requests(&server).await, 0, "it panicked before any request");

    cache.advance_for_test(secs(1));
    cache
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("the next attempt");
    assert_eq!(requests(&server).await, 1);
}

/// (m) A fetch task the runtime drops before it is ever polled (a
/// current-thread runtime dropped right after the lookup that spawned it)
/// still clears its slot and counts as a failure: its guard existed before
/// the task did.
#[test]
fn a_fetch_dropped_before_its_first_poll_aborts_its_attempt() {
    // Nothing listens: had the task run, it would fail with "fetch failed",
    // never "refetch aborted".
    let cache = cache_at(NOTHING_LISTENS, BOUNDED);
    let mut lookup = Box::pin(cache.jwks_for_kid(PRIMARY_KID));

    let doomed = current_thread_runtime();
    doomed.block_on(async {
        // One poll reserves the slot and spawns the fetch; a current-thread
        // runtime runs it only once this future yields, which it never does.
        assert!((&mut lookup).now_or_never().is_none());
    });
    assert!(cache.in_flight(), "the unpolled attempt holds its slot");
    drop(doomed);

    cache.assert_one_failed_attempt("the dropped task");
    assert_jwks(
        current_thread_runtime().block_on(lookup),
        ABORTED,
        "its waiter",
    );
}

/// (m) A runtime shut down mid-fetch drops the task; the attempt counts as
/// a failure and its waiter gets "refetch aborted".
#[test]
fn a_runtime_shutdown_mid_fetch_aborts_its_attempt() {
    // Accepts the connection (the kernel backlog does) and never answers.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a silent listener");
    let url = format!(
        "http://{}/jwks",
        silent.local_addr().expect("listener address")
    );
    let cache = cache_at(url, BOUNDED);
    let mut lookup = Box::pin(cache.jwks_for_kid(PRIMARY_KID));

    let doomed = current_thread_runtime();
    doomed.block_on(async {
        assert!((&mut lookup).now_or_never().is_none());
        // Let the fetch run and reach the silent issuer.
        tokio::time::sleep(millis(100)).await;
    });
    assert!(cache.in_flight(), "mid-fetch");
    drop(doomed);

    cache.assert_one_failed_attempt("the shutdown");
    assert_jwks(
        current_thread_runtime().block_on(lookup),
        ABORTED,
        "its waiter",
    );
    drop(silent);
}

/// (m) A waiter that is slow to come back for its result still gets its own
/// attempt's set, after a newer attempt has replaced the cached one.
#[tokio::test]
async fn a_delayed_waiter_gets_its_own_attempts_set() {
    let server = issuer_then(primary_body(), jwks_body(TestKey::secondary().jwks_json())).await;
    let cache = cache(&server, NO_THROTTLE);

    let mut delayed = Box::pin(cache.jwks_for_kid(PRIMARY_KID));
    assert!(
        (&mut delayed).now_or_never().is_none(),
        "waiting on attempt A"
    );
    cache.settle().await;
    cache
        .jwks_for_kid(SECONDARY_KID)
        .await
        .expect("attempt B replaces the set");
    assert!(cache
        .inner
        .state()
        .cached
        .as_ref()
        .is_some_and(|c| c.set.find(PRIMARY_KID).is_none()));

    let set = delayed.await.expect("A's set, still inside its TTL");
    assert!(set.find(PRIMARY_KID).is_some(), "A's waiter gets A's set");
}

/// (m) A completion racing a new reservation. The slot only ever holds one
/// attempt, and a guard touches the state only while it holds that guard's
/// id: one that completes or drops after its slot was taken over neither
/// clears the newer reservation nor charges it a failure, and a normal
/// failure is counted exactly once.
#[tokio::test]
async fn a_stale_guard_never_clears_or_charges_a_newer_reservation() {
    let cache = cache_at(NOTHING_LISTENS, BOUNDED);
    let reserve = || {
        let mut state = cache.inner.state();
        let now = cache.inner.now();
        cache.reserve(&mut state, now)
    };
    let guard = |id: u64, sender| SlotGuard {
        inner: Arc::clone(&cache.inner),
        id,
        sender: Some(sender),
        cache_success: true,
        purpose: Purpose::Needed,
    };
    // A guard for attempt 0 whose waiters are long gone.
    let stale = || guard(0, oneshot::channel().0);

    // Attempt 0 fails: once.
    let first = reserve();
    assert_eq!(first.id, 0);
    guard(0, first.sender).complete(Err(AuthError::Jwks("boom".into())));
    let ended = {
        let state = cache.inner.state();
        assert!(state.in_flight.is_none());
        assert_eq!(
            state.failures, 1,
            "counted once, by complete, not again by drop"
        );
        state.last_end
    };

    // Attempt 1 holds the slot now. Attempt 0's guard, again, is stale.
    let second = reserve();
    assert_eq!(second.id, 1);
    cache.advance_for_test(secs(5));
    stale().complete(Err(AuthError::Jwks("late".into())));
    drop(stale());
    {
        let state = cache.inner.state();
        assert!(state.holds(1), "the stale guard left the newer slot alone");
        assert_eq!(state.failures, 1, "and charged it nothing");
        assert_eq!(state.last_end, ended, "nor stamped its end");
        assert!(state.cached.is_none(), "nor cached anything");
    }
    stale().complete(Ok((TestKey::primary().jwks(), HashMap::new())));
    assert!(
        cache.inner.state().cached.is_none(),
        "a stale success caches nothing"
    );

    // Attempt 1's own guard finishes it.
    guard(1, second.sender).complete(Ok((TestKey::primary().jwks(), HashMap::new())));
    let state = cache.inner.state();
    assert!(state.in_flight.is_none());
    assert_eq!(state.failures, 0);
    assert!(state.cached.is_some());
}

/// (n) A fresh hit needs no runtime at all: it is answered from memory.
/// (Starting or joining a fetch needs one, as reqwest does.)
#[test]
fn outside_a_runtime_a_fresh_hit_still_answers() {
    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "no runtime here"
    );
    let cache = cache_at(NOTHING_LISTENS, BLIP);
    cache.seed();
    cache.advance_for_test(secs(30));

    match cache.jwks_for_kid(PRIMARY_KID).now_or_never() {
        Some(Ok(set)) => assert!(set.find(PRIMARY_KID).is_some()),
        Some(Err(err)) => panic!("a fresh hit: {err}"),
        None => panic!("a fresh hit does not wait"),
    }
    assert_eq!(cache.attempts_reserved(), 0, "nothing reserved");
}

/// Fix for the review's second P2, in its own sequence: current-thread
/// runtime A starts a first fetch inside a caller's 50 ms timeout, and its
/// `block_on` returns, leaving A alive but undriven and the fetch frozen in
/// it (its own timeout included). A lookup in runtime B joins that fetch and
/// gives up at its own bound, a timer on B, instead of waiting for A
/// forever. The slot
/// stays taken while A lives (the documented requirement on the host
/// runtime); dropping A ends the attempt, and B then fetches for itself.
#[test]
fn a_lookup_never_hangs_on_a_fetch_frozen_in_another_runtime() {
    use wiremock::matchers::{method, path};
    use wiremock::Mock;

    let setup = multi_thread_runtime();
    let server = setup.block_on(async {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(primary_body().set_delay(millis(500)))
            // A's request may or may not have left before A stopped; B's
            // own fetch is the other.
            .expect(1..=2)
            .mount(&server)
            .await;
        server
    });
    let first_join_wait = millis(500);
    let cache = cache(
        &server,
        Tuning {
            first_join_wait,
            ..BOUNDED
        },
    );

    let a = current_thread_runtime();
    let cancelled = a.block_on(async {
        tokio::time::timeout(millis(50), cache.jwks_for_kid(PRIMARY_KID)).await
    });
    assert!(cancelled.is_err(), "the caller in A timed out");
    assert!(cache.in_flight(), "A's fetch is frozen in A");

    let b = current_thread_runtime();
    let started = Instant::now();
    let joined = b
        .block_on(async { tokio::time::timeout(secs(10), cache.jwks_for_kid(PRIMARY_KID)).await })
        .expect("the lookup in B hung on the fetch frozen in A");
    let waited = started.elapsed();
    assert_jwks(joined, STILL_IN_PROGRESS, "B's lookup");
    assert!(
        waited >= first_join_wait * 4 / 5,
        "B waited its bound: {waited:?}"
    );
    assert!(cache.in_flight(), "the slot stays taken while A lives");

    drop(a);
    cache.assert_one_failed_attempt("A's dropped fetch");
    cache.advance_for_test(secs(1));
    b.block_on(cache.jwks_for_kid(PRIMARY_KID))
        .expect("B's own fetch, once A is gone");
    // The mock's `expect(1..=2)` is checked when `server` drops.
}

/// (o) What a consumer's state and handlers need.
#[test]
fn the_cache_is_send_and_sync_and_its_lookup_is_send() {
    fn send_and_sync<T: Send + Sync>() {}
    fn send<T: Send>(_: &T) {}
    send_and_sync::<JwksCache>();
    let cache = cache_at(NOTHING_LISTENS, BOUNDED);
    let lookup = cache.jwks_for_kid(PRIMARY_KID);
    send(&lookup);
}

/// `Debug` never blocks on, or deadlocks over, the state: contended, it
/// prints `<locked>`.
#[test]
fn debug_prints_locked_rather_than_waiting() {
    let cache = cache_at(NOTHING_LISTENS, BOUNDED);
    cache.seed();
    assert!(format!("{cache:?}").contains("in_flight: false"));
    let held = cache.inner.state();
    assert!(format!("{cache:?}").contains("<locked>"));
    drop(held);
}

// --- fetch failures ----------------------------------------------------------

#[tokio::test]
async fn a_non_2xx_response_is_a_jwks_error() {
    let server = issuer(ResponseTemplate::new(500), 1).await;
    let cache = cache(&server, Tuning::default());

    assert_jwks(cache.jwks_for_kid(PRIMARY_KID).await, "500", "a 500");
}

#[tokio::test]
async fn a_malformed_body_is_a_jwks_error() {
    let server = issuer(jwks_body("{\"keys\": \"not a list\"}"), 1).await;
    let cache = cache(&server, Tuning::default());

    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        "not a valid JWKS",
        "a malformed body",
    );
}

#[tokio::test]
async fn an_unreachable_endpoint_is_a_jwks_error() {
    let cache = JwksCache::new(NOTHING_LISTENS, reqwest::Client::new());

    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        "fetch failed",
        "port 1",
    );
}

// --- the body cap -------------------------------------------------------------

const OVER_THE_CAP: &str = "response body is over 1048576 bytes";

/// The primary test key's JWKS, padded with trailing whitespace (still one
/// valid JSON document) to exactly `len` bytes.
fn jwks_padded_to(len: usize) -> Vec<u8> {
    let mut body = test_jwks_json().as_bytes().to_vec();
    assert!(body.len() <= len, "the test JWKS fits in {len} bytes");
    body.resize(len, b' ');
    body
}

/// An issuer that answers every `GET` with a chunked `200` (no
/// `Content-Length`, so no up-front size to refuse), writing one HTTP chunk
/// per piece, `gap` apart. When the pieces run out it ends the body; an
/// endless iterator keeps writing until the client hangs up.
async fn drip_issuer(
    pieces: impl Iterator<Item = Vec<u8>> + Send + 'static,
    gap: Duration,
) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a drip issuer");
    let url = format!(
        "http://{}/jwks",
        listener.local_addr().expect("listener address")
    );
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => request.extend_from_slice(&buf[..n]),
            }
        }
        let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                    transfer-encoding: chunked\r\n\r\n";
        if stream.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        for piece in pieces {
            let mut chunk = format!("{:x}\r\n", piece.len()).into_bytes();
            chunk.extend_from_slice(&piece);
            chunk.extend_from_slice(b"\r\n");
            // The client hanging up is the end of an endless body.
            if stream.write_all(&chunk).await.is_err() {
                return;
            }
            tokio::time::sleep(gap).await;
        }
        let _ = stream.write_all(b"0\r\n\r\n").await;
    });
    url
}

/// The cap is on the whole body: exactly `MAX_JWKS_BYTES` is a set, one
/// byte more is a failed fetch, as any other failed refresh is.
#[tokio::test]
async fn a_body_of_exactly_the_cap_is_read_and_one_byte_more_is_refused() {
    let at_cap = issuer(
        ResponseTemplate::new(200).set_body_raw(jwks_padded_to(MAX_JWKS_BYTES), "application/json"),
        1,
    )
    .await;
    let set = cache(&at_cap, Tuning::default())
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("a body of exactly the cap is a set");
    assert!(set.find(PRIMARY_KID).is_some());

    let over = issuer(
        ResponseTemplate::new(200)
            .set_body_raw(jwks_padded_to(MAX_JWKS_BYTES + 1), "application/json"),
        1,
    )
    .await;
    let cache = cache(&over, Tuning::default());
    assert_jwks(
        cache.jwks_for_kid(PRIMARY_KID).await,
        OVER_THE_CAP,
        "one byte over the cap",
    );
    cache.assert_one_failed_attempt("one byte over the cap");
}

/// A body that arrives slowly, in many chunks, is read whole as long as it
/// stays under the cap and inside the fetch timeout: the cap counts every
/// chunk, and only the timeout bounds the time.
#[tokio::test]
async fn a_slow_drip_under_the_cap_is_read_whole_inside_the_fetch_timeout() {
    // 16 chunks of 64 KiB, 20 ms apart: about 0.3 s, against a 10 s timeout.
    let body = jwks_padded_to(MAX_JWKS_BYTES);
    let pieces: Vec<Vec<u8>> = body.chunks(64 * 1024).map(<[u8]>::to_vec).collect();
    assert_eq!(pieces.len(), 16);
    let url = drip_issuer(pieces.into_iter(), millis(20)).await;

    let set = cache_at(url, Tuning::default())
        .jwks_for_kid(PRIMARY_KID)
        .await
        .expect("a dripped body under the cap is a set");
    assert!(set.find(PRIMARY_KID).is_some());
}

/// A body that never ends is refused once it passes the cap, not read until
/// the fetch timeout: the read stops at the chunk that would cross it, so
/// the attempt ends with the cap's error, long before the timeout's.
#[tokio::test]
async fn an_endless_drip_is_refused_at_the_cap_not_at_the_timeout() {
    // 64 KiB every 10 ms: the cap is passed after about 0.17 s.
    let opening = std::iter::once(b"{\"keys\": [".to_vec());
    let spaces = std::iter::repeat_with(|| vec![b' '; 64 * 1024]);
    let url = drip_issuer(opening.chain(spaces), millis(10)).await;
    let fetch_timeout = secs(5);
    let cache = cache_at(
        url,
        Tuning {
            fetch_timeout,
            first_join_wait: fetch_timeout + secs(1),
            ..Tuning::default()
        },
    );

    let started = Instant::now();
    let result = cache.jwks_for_kid(PRIMARY_KID).await;
    let took = started.elapsed();

    assert_jwks(result, OVER_THE_CAP, "an endless body");
    assert!(
        took < fetch_timeout,
        "refused at the cap in {took:?}, before the {fetch_timeout:?} timeout"
    );
    cache.assert_one_failed_attempt("an endless body");
}

// --- the URL canary ----------------------------------------------------------
//
// A JWKS URL is configuration, and configuration can carry a credential:
// userinfo in the authority, a token in the query. Each marker stands for
// one of them, and any of them in a rendered `AuthError` — or in the line
// the `http` feature logs for it — is the leak `fetch`'s `without_url()`
// closes; in the `Debug` of a type holding the URL, the leak the
// redacting `Debug` impls close.

const CANARY_MARKERS: &[&str] = &["CANARY-user", "CANARY-pass", "CANARY-token"];

/// A JWKS URL at `authority` (`host:port`) carrying every marker.
fn canary_url(authority: impl std::fmt::Display) -> String {
    format!("http://CANARY-user:CANARY-pass@{authority}/jwks?token=CANARY-token")
}

#[track_caller]
fn assert_no_canary(haystack: &str, what: &str) {
    for marker in CANARY_MARKERS {
        assert!(
            !haystack.contains(marker),
            "{what} leaked JWKS URL material ({marker:?}): {haystack}"
        );
    }
}

/// What the naive fetch — `send()`, then `json()` — fails with, unredacted.
async fn naive_fetch_error(url: &str) -> reqwest::Error {
    match reqwest::Client::new().get(url).send().await {
        Err(err) => err,
        Ok(response) => response
            .json::<JwkSet>()
            .await
            .expect_err("no fixture here serves a JWKS"),
    }
}

/// One failure per arm of `fetch`: `send()` (nothing listens on port 1),
/// the status check (a 503) and `json()` (a 200 that is not a JWKS).
#[tokio::test]
async fn a_jwks_failure_never_renders_url_material() {
    // Two requests each: the naive fetch's, then the cache's.
    let unavailable = issuer(ResponseTemplate::new(503), 2).await;
    let not_a_jwks = issuer(jwks_body("{\"keys\": \"not a list\"}"), 2).await;
    let cases = [
        ("send", canary_url("127.0.0.1:1")),
        ("status", canary_url(unavailable.address())),
        ("decode", canary_url(not_a_jwks.address())),
    ];

    for (name, url) in cases {
        // The control: reqwest renders the query (it moves userinfo into
        // an `Authorization` header itself). Without this, a fixture
        // whose URL never reached the error would pass everything below.
        let naive = naive_fetch_error(&url).await;
        assert!(
            naive.to_string().contains("CANARY-token"),
            "{name}: reqwest no longer renders the URL, so this test is vacuous: {naive}"
        );

        let err = cache_at(url, NO_THROTTLE)
            .jwks_for_kid(PRIMARY_KID)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Jwks(_)), "{name}: {err}");
        assert_no_canary(&format!("{err} / {err:?}"), name);
        #[cfg(feature = "http")]
        assert_no_canary(&http_log::logged_as_500(err), name);
    }
}

/// The other road from configuration to a log: `?config`, `?verifier`.
/// None of the three types holding the JWKS URL may print its userinfo or
/// query, and each must still name the endpoint — redacted, not dropped.
#[test]
fn debug_never_renders_url_material() {
    let url = canary_url("jwks.example:8443");
    let config = crate::SlauthConfig {
        issuer: "https://issuer.example".into(),
        jwks_url: url.clone(),
        audience: "svc".into(),
        pat_validate_url: Some(url.clone()),
    };
    // An injected client with a default credential header that nobody
    // marked sensitive: reqwest::Client's own Debug would print it.
    let client = || {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_static("Bearer CANARY-header"),
        );
        reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("a plain client builds")
    };
    let cache = JwksCache::new(url, client());
    let verifier = crate::Verifier::new(config.clone(), client());

    for (name, debug) in [
        ("SlauthConfig", format!("{config:?}")),
        ("JwksCache", format!("{cache:?}")),
        ("Verifier", format!("{verifier:?}")),
    ] {
        assert!(
            !debug.contains("CANARY"),
            "{name}'s Debug leaked URL or client-header material: {debug}"
        );
        assert!(
            debug.contains(r#""http://jwks.example:8443/jwks""#),
            "{name}'s Debug no longer names the JWKS endpoint: {debug}"
        );
    }
}

/// The `http` feature's log line: `From<AuthError> for AppError` makes a
/// JWKS failure `AppError::Internal`, whose `IntoResponse` logs it in full.
#[cfg(feature = "http")]
mod http_log {
    use std::sync::{Arc, Mutex};

    use axum::response::IntoResponse as _;
    use tracing_subscriber::fmt::MakeWriter;

    use crate::AuthError;

    /// A `MakeWriter` that keeps every byte the fmt subscriber writes —
    /// the same capture `stridelabs-http`'s upstream leak tests use.
    #[derive(Clone, Default)]
    struct LogSink(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log sink").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for LogSink {
        type Writer = LogSink;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Everything logged while `err` is rendered as the 500 it becomes.
    /// A thread-local subscriber (`with_default`), so tests running in
    /// parallel never write into each other's capture.
    pub(super) fn logged_as_500(err: AuthError) -> String {
        let app: stridelabs_http::AppError = err.into();
        // `AppError::Internal` is `#[error(transparent)]`, so this is the
        // JWKS detail exactly as the line carries it.
        let expected = app.to_string();
        let sink = LogSink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || drop(app.into_response()));

        let logs =
            String::from_utf8(sink.0.lock().expect("log sink").clone()).expect("utf-8 log output");
        // Absence proves nothing unless the line was captured, detail and
        // all. (Any `err` but a JWKS failure becomes a 401, logs nothing,
        // and fails here too.)
        assert!(
            logs.contains("internal error") && logs.contains(&expected),
            "the 500's log line was not captured with its detail: {logs}"
        );
        logs
    }
}
