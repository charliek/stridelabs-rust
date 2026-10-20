//! Per-attempt single-flight, made deterministic. The token endpoint answers
//! only when a test releases it, and a test releases it only once the callers
//! it means to queue are provably waiting on the attempt
//! ([`TokenProvider::waiters`] counts the clones of the attempt's shared
//! future). No sleeps stand in for ordering.
//!
//! Wall-clock bounds exist only to turn a broken test into a failure rather
//! than a hang, and they nest: the polling helper gives up after
//! [`POLL_LIMIT`], the gate after [`GATE_LIMIT`], and the provider's own
//! metadata timeout ([`REQUEST_LIMIT`]) is longer than both, so no request
//! times out while a test is still arranging its callers.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::task::JoinSet;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use super::*;

#[path = "../../tests/common/log_capture.rs"]
mod log_capture;
use log_capture::LogCapture;

const TOKEN_PATH: &str = "/computeMetadata/v1/instance/service-accounts/default/token";

/// How long [`until`] waits for a condition.
const POLL_LIMIT: Duration = Duration::from_secs(30);
/// How long a gated request waits to be released.
const GATE_LIMIT: Duration = Duration::from_secs(60);
/// The provider's metadata timeout: longer than either, so the gate, not the
/// request, decides when a response comes.
const REQUEST_LIMIT: Duration = Duration::from_secs(120);

/// A metadata token endpoint whose n-th request answers `answers[n]`, each
/// only after one [`Endpoint::release`].
struct Gated {
    answers: Vec<ResponseTemplate>,
    seen: Arc<AtomicUsize>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl Respond for Gated {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let n = self.seen.fetch_add(1, Ordering::SeqCst);
        // Blocks this mock server's own thread (wiremock runs each server on
        // one) until released. Bounded, so a broken test fails, not hangs.
        let _ = self.release.lock().unwrap().recv_timeout(GATE_LIMIT);
        self.answers
            .get(n)
            .cloned()
            .unwrap_or_else(|| ResponseTemplate::new(599))
    }
}

struct Endpoint {
    server: MockServer,
    seen: Arc<AtomicUsize>,
    release: mpsc::Sender<()>,
}

impl Endpoint {
    async fn start(answers: Vec<ResponseTemplate>) -> Endpoint {
        let server = MockServer::start().await;
        let seen = Arc::new(AtomicUsize::new(0));
        let (release, gate) = mpsc::channel();
        Mock::given(method("GET"))
            .and(path(TOKEN_PATH))
            .respond_with(Gated {
                answers,
                seen: Arc::clone(&seen),
                release: Mutex::new(gate),
            })
            .mount(&server)
            .await;
        Endpoint {
            server,
            seen,
            release,
        }
    }

    fn provider(&self) -> TokenProvider {
        TokenProvider::metadata_server(reqwest::Client::new(), &["scope"]).with_options(
            TokenOptions::default()
                .metadata_base_url(self.server.uri())
                .metadata_timeout(REQUEST_LIMIT),
        )
    }

    /// Let one request through.
    fn release(&self) {
        self.release.send(()).unwrap();
    }

    fn requests(&self) -> usize {
        self.seen.load(Ordering::SeqCst)
    }
}

fn token(name: &str, expires_in: u64) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(json!({"access_token": name, "expires_in": expires_in}))
}

/// Wait (bounded) until `condition` holds.
async fn until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + POLL_LIMIT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

fn spawn_callers(
    provider: &TokenProvider,
    count: usize,
) -> JoinSet<Result<AccessToken, GcpAuthError>> {
    let mut calls = JoinSet::new();
    for _ in 0..count {
        let provider = provider.clone();
        calls.spawn(async move { provider.token().await });
    }
    calls
}

fn idle(provider: &TokenProvider) -> bool {
    provider.inner.cache().in_flight.is_none()
}

/// 30 s of life is inside the refresh margin: never cached. All 32 callers
/// still share the one attempt they found in flight, and get its token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_callers_share_one_attempt_even_when_its_token_is_too_short_to_cache() {
    let endpoint = Endpoint::start(vec![token("short", 30), token("next", 30)]).await;
    let provider = endpoint.provider();

    let mut calls = spawn_callers(&provider, 32);
    until("32 waiters on one attempt", || provider.waiters() == 32).await;
    until("the attempt's request", || endpoint.requests() == 1).await;
    endpoint.release();

    while let Some(result) = calls.join_next().await {
        assert_eq!(result.unwrap().unwrap().token, "short");
    }
    assert_eq!(endpoint.requests(), 1, "one attempt, one request");

    // Too short-lived to cache: a call after the attempt starts another.
    endpoint.release();
    assert_eq!(provider.token().await.unwrap().token, "next");
    assert_eq!(endpoint.requests(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_the_initiator_cancels_nothing() {
    let endpoint = Endpoint::start(vec![token("kept", 3600)]).await;
    let provider = endpoint.provider();

    let initiator = {
        let provider = provider.clone();
        tokio::spawn(async move { provider.token().await })
    };
    until("the attempt's request", || endpoint.requests() == 1).await;
    let mut waiters = spawn_callers(&provider, 5);
    until("the initiator and 5 waiters", || provider.waiters() == 6).await;

    initiator.abort();
    assert!(initiator.await.unwrap_err().is_cancelled());
    until("the initiator gone", || provider.waiters() == 5).await;
    endpoint.release();

    while let Some(result) = waiters.join_next().await {
        assert_eq!(result.unwrap().unwrap().token, "kept");
    }
    assert_eq!(endpoint.requests(), 1);
    assert_eq!(
        provider.token().await.unwrap().token,
        "kept",
        "and it was cached"
    );
    assert_eq!(endpoint.requests(), 1);
}

/// With every caller gone the refresh still finishes, and its token is
/// cached for the next one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refresh_outlives_every_caller() {
    let endpoint = Endpoint::start(vec![token("orphan", 3600)]).await;
    let provider = endpoint.provider();

    let only = {
        let provider = provider.clone();
        tokio::spawn(async move { provider.token().await })
    };
    until("the attempt's request", || endpoint.requests() == 1).await;
    only.abort();
    assert!(only.await.unwrap_err().is_cancelled());
    assert_eq!(provider.waiters(), 0);
    endpoint.release();

    until("the orphaned attempt to finish", || idle(&provider)).await;
    assert_eq!(provider.token().await.unwrap().token, "orphan");
    assert_eq!(endpoint.requests(), 1, "served from the cache");
}

/// The interleaving a counter-based design gets wrong: attempt A fails;
/// attempt B starts, its initiator is cancelled, a waiter remains. That
/// waiter gets B's outcome — never A's failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_waiter_gets_its_own_attempts_outcome_never_an_older_failure() {
    let endpoint = Endpoint::start(vec![ResponseTemplate::new(503), token("b", 3600)]).await;
    let provider = endpoint.provider();

    let mut first = spawn_callers(&provider, 1);
    until("attempt A's waiter", || provider.waiters() == 1).await;
    endpoint.release();
    assert!(matches!(
        first.join_next().await.unwrap().unwrap(),
        Err(GcpAuthError::Status { status: 503, .. })
    ));
    assert!(idle(&provider), "a failed attempt leaves nothing behind");

    let b_initiator = {
        let provider = provider.clone();
        tokio::spawn(async move { provider.token().await })
    };
    until("attempt B's request", || endpoint.requests() == 2).await;
    let mut b_waiter = spawn_callers(&provider, 1);
    until("B's initiator and waiter", || provider.waiters() == 2).await;
    b_initiator.abort();
    assert!(b_initiator.await.unwrap_err().is_cancelled());
    until("B's initiator gone", || provider.waiters() == 1).await;
    endpoint.release();

    assert_eq!(
        b_waiter.join_next().await.unwrap().unwrap().unwrap().token,
        "b"
    );
    assert_eq!(endpoint.requests(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_waiters_of_a_failed_attempt_share_its_error_and_a_later_call_retries() {
    let endpoint =
        Endpoint::start(vec![ResponseTemplate::new(503), token("recovered", 3600)]).await;
    let provider = endpoint.provider();

    let mut calls = spawn_callers(&provider, 16);
    until("16 waiters on one attempt", || provider.waiters() == 16).await;
    endpoint.release();
    while let Some(result) = calls.join_next().await {
        assert!(matches!(
            result.unwrap(),
            Err(GcpAuthError::Status { status: 503, .. })
        ));
    }
    assert_eq!(endpoint.requests(), 1, "one attempt, one request");

    endpoint.release();
    assert_eq!(provider.token().await.unwrap().token, "recovered");
    assert_eq!(endpoint.requests(), 2, "the failure was not cached");
}

/// A refresh task the runtime drops before it is ever polled — here, a
/// current-thread runtime dropped right after the call that spawned it —
/// still clears its slot: its guard existed before the task did. The next
/// call, on another runtime, refreshes instead of inheriting a dead attempt.
#[test]
fn a_refresh_dropped_before_its_first_poll_leaves_nothing_behind() {
    let setup = tokio::runtime::Runtime::new().unwrap();
    let endpoint = setup.block_on(Endpoint::start(vec![token("fresh", 3600)]));
    let provider = endpoint.provider();
    let current_thread = || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    };

    let doomed = current_thread();
    doomed.block_on(async {
        let call = provider.token();
        tokio::pin!(call);
        // One poll reserves the slot and spawns the refresh; a current-thread
        // runtime runs it only once this future yields, which it never does.
        assert!(futures::poll!(&mut call).is_pending());
        assert_eq!(provider.waiters(), 1);
    });
    assert!(
        !idle(&provider),
        "the unpolled attempt still holds its slot"
    );
    drop(doomed);

    assert!(
        idle(&provider),
        "dropping the unpolled task cleared its slot"
    );
    assert_eq!(endpoint.requests(), 0, "the refresh never ran");
    endpoint.release();
    assert_eq!(
        current_thread().block_on(provider.token()).unwrap().token,
        "fresh"
    );
    assert_eq!(endpoint.requests(), 1);
}

/// A refresh that panics answers every waiter of that attempt with
/// `RefreshAborted`, clears its slot, and the next call refreshes. On a
/// current-thread runtime the task runs only when the test yields, so both
/// waiters are provably queued before it panics.
#[tokio::test]
async fn a_panicking_refresh_aborts_its_waiters_and_the_next_call_retries() {
    let endpoint = Endpoint::start(vec![token("after-panic", 3600)]).await;
    let provider = endpoint.provider();
    provider.panic_next_refreshes(1);

    let first = provider.token();
    let second = provider.token();
    tokio::pin!(first, second);
    assert!(futures::poll!(&mut first).is_pending());
    assert!(futures::poll!(&mut second).is_pending());
    assert_eq!(provider.waiters(), 2);

    for waiter in [first.await, second.await] {
        assert!(
            matches!(waiter, Err(GcpAuthError::RefreshAborted)),
            "{waiter:?}"
        );
    }
    assert!(idle(&provider), "the panicked attempt cleared its slot");
    assert_eq!(endpoint.requests(), 0, "it panicked before any request");

    endpoint.release();
    assert_eq!(provider.token().await.unwrap().token, "after-panic");
    assert_eq!(endpoint.requests(), 1);
}

/// A waiter that is slow to come back for its result still gets its own
/// attempt's — even after a newer attempt has started and finished.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delayed_waiter_gets_its_own_attempts_result_after_a_newer_attempt_finished() {
    // 30 s of life: never cached, so the second call makes a new attempt.
    let endpoint = Endpoint::start(vec![token("a", 30), token("b", 30)]).await;
    let provider = endpoint.provider();

    let delayed = provider.token();
    tokio::pin!(delayed);
    assert!(
        futures::poll!(&mut delayed).is_pending(),
        "waiting on attempt A"
    );
    until("attempt A's request", || endpoint.requests() == 1).await;
    endpoint.release();
    until("attempt A to finish", || idle(&provider)).await;

    endpoint.release();
    assert_eq!(provider.token().await.unwrap().token, "b", "attempt B");
    assert_eq!(endpoint.requests(), 2);

    assert_eq!(
        delayed.await.unwrap().token,
        "a",
        "A's waiter gets A's token"
    );
}

/// A cached token is served until its refresh deadline (expiry minus the
/// 60 s margin) and, once the clock crosses it, refreshed exactly once
/// however many callers arrive together. The clock is the provider's test
/// seam, so nothing waits an hour.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_crossing_its_refresh_deadline_is_refreshed_exactly_once() {
    let endpoint = Endpoint::start(vec![token("first", 3600), token("second", 3600)]).await;
    let provider = endpoint.provider();

    endpoint.release();
    assert_eq!(provider.token().await.unwrap().token, "first");
    // Well inside the deadline (3600 - 60 = 3540 s): served from the cache.
    provider.advance_clock(Duration::from_secs(3500));
    assert_eq!(provider.token().await.unwrap().token, "first");
    assert_eq!(endpoint.requests(), 1);

    // Past it: one refresh for all of them.
    provider.advance_clock(Duration::from_secs(100));
    let mut calls = spawn_callers(&provider, 16);
    until("16 waiters on the refresh", || provider.waiters() == 16).await;
    endpoint.release();
    while let Some(result) = calls.join_next().await {
        assert_eq!(result.unwrap().unwrap().token, "second");
    }
    assert_eq!(endpoint.requests(), 2, "exactly one refresh");
    assert_eq!(
        provider.token().await.unwrap().token,
        "second",
        "now cached"
    );
    assert_eq!(endpoint.requests(), 2);
}

// --- invalidate -----------------------------------------------------------

/// A token this provider never handed out, whatever its string.
fn foreign(bearer: &str) -> AccessToken {
    AccessToken {
        token: bearer.to_owned(),
        quota_project: None,
    }
}

fn cached_bearer(provider: &TokenProvider) -> Option<String> {
    provider
        .inner
        .cache()
        .token
        .as_ref()
        .map(|cached| cached.token.token.clone())
}

/// The wave a revoked credential produces: 16 calls each holding the same
/// rejected bearer, each running `invalidate` then `token`. Whatever the
/// interleaving, one evicts, one refresh runs, and every call ends with the
/// new token. The endpoint answers only once all 16 are waiting, so they
/// share one attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wave_of_rejections_of_one_token_costs_exactly_one_refresh() {
    let endpoint = Endpoint::start(vec![token("t1", 3600), token("t2", 3600)]).await;
    let provider = endpoint.provider();
    endpoint.release();
    let rejected = provider.token().await.unwrap();
    assert_eq!(rejected.token, "t1");

    let mut calls = JoinSet::new();
    for _ in 0..16 {
        let (provider, rejected) = (provider.clone(), rejected.clone());
        calls.spawn(async move {
            let evicted = provider.invalidate(&rejected);
            (evicted, provider.token().await)
        });
    }
    until("16 waiters on one forced refresh", || {
        provider.waiters() == 16
    })
    .await;
    endpoint.release();

    let mut evictions = 0;
    while let Some(result) = calls.join_next().await {
        let (evicted, token) = result.unwrap();
        evictions += usize::from(evicted);
        assert_eq!(token.unwrap().token, "t2");
    }
    assert_eq!(evictions, 1, "exactly one call found the token to evict");
    assert_eq!(endpoint.requests(), 2, "one forced refresh");
    assert_eq!(provider.token().await.unwrap().token, "t2", "and cached");
    assert_eq!(endpoint.requests(), 2);
}

/// A token its refresh deadline already replaced is stale: a 401 that comes
/// back for it now must not throw away its successor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalidating_a_token_its_deadline_replaced_is_a_no_op() {
    let endpoint = Endpoint::start(vec![token("t1", 3600), token("t2", 3600)]).await;
    let provider = endpoint.provider();
    endpoint.release();
    let stale = provider.token().await.unwrap();

    provider.advance_clock(Duration::from_secs(3600));
    endpoint.release();
    assert_eq!(provider.token().await.unwrap().token, "t2", "refreshed");

    assert!(!provider.invalidate(&stale), "t1 is gone: nothing to evict");
    assert_eq!(cached_bearer(&provider).as_deref(), Some("t2"));
    assert_eq!(provider.token().await.unwrap().token, "t2", "still cached");
    assert_eq!(endpoint.requests(), 2, "no third refresh");
}

/// Two callers rejected on one bearer, the second only after the first's
/// refresh completed: the second finds the new token cached, so its
/// invalidation is a no-op and its `token()` refreshes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_staggered_rejecter_finds_the_new_token_and_refreshes_nothing() {
    let endpoint = Endpoint::start(vec![token("t1", 3600), token("t2", 3600)]).await;
    let provider = endpoint.provider();
    endpoint.release();
    let first = provider.token().await.unwrap();
    let second = provider.clone().token().await.unwrap();
    assert_eq!((first.token.as_str(), second.token.as_str()), ("t1", "t1"));

    assert!(provider.invalidate(&first), "the first rejecter evicts");
    endpoint.release();
    assert_eq!(provider.token().await.unwrap().token, "t2");
    assert!(idle(&provider));

    assert!(!provider.invalidate(&second), "the second finds t2, not t1");
    assert_eq!(provider.token().await.unwrap().token, "t2");
    assert_eq!(endpoint.requests(), 2, "one refresh for both");
}

#[tokio::test]
async fn invalidating_a_token_the_cache_never_held_is_a_no_op() {
    let endpoint = Endpoint::start(vec![token("t1", 3600)]).await;
    let provider = endpoint.provider();
    assert!(!provider.invalidate(&foreign("t1")), "empty cache");
    assert_eq!(endpoint.requests(), 0, "and it starts nothing");
    assert!(idle(&provider));

    endpoint.release();
    assert_eq!(provider.token().await.unwrap().token, "t1");
    assert!(!provider.invalidate(&foreign("other")));
    assert!(
        !provider.invalidate(&foreign("t1 ")),
        "the whole bearer, exactly"
    );
    assert_eq!(provider.token().await.unwrap().token, "t1");
    assert_eq!(endpoint.requests(), 1);

    // Matched by bearer, not by provenance: the same bearer from anywhere
    // (another metadata-server provider holds the same one) evicts it.
    assert!(provider.invalidate(&foreign("t1")));
    assert_eq!(cached_bearer(&provider), None);
}

/// A refresh already in flight is the refresh the rejected caller wants:
/// invalidating neither cancels it nor starts a second one, and a refresh
/// that returns a *different* bearer is cached as usual.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalidating_during_a_refresh_joins_it() {
    let endpoint = Endpoint::start(vec![token("t1", 3600), token("t2", 3600)]).await;
    let provider = endpoint.provider();
    endpoint.release();
    let rejected = provider.token().await.unwrap();

    // Past the refresh deadline: the cache still holds t1, but a call
    // refreshes. Park one on the attempt.
    provider.advance_clock(Duration::from_secs(3600));
    let mut first = spawn_callers(&provider, 1);
    until("the refresh's request", || endpoint.requests() == 2).await;
    until("its waiter", || provider.waiters() == 1).await;

    assert!(provider.invalidate(&rejected), "t1 was still cached");
    let mut second = spawn_callers(&provider, 1);
    until("both on the one attempt", || provider.waiters() == 2).await;
    endpoint.release();

    for calls in [&mut first, &mut second] {
        assert_eq!(
            calls.join_next().await.unwrap().unwrap().unwrap().token,
            "t2"
        );
    }
    assert_eq!(endpoint.requests(), 2, "no extra attempt");
    assert_eq!(cached_bearer(&provider).as_deref(), Some("t2"), "cached");
    assert_eq!(provider.token().await.unwrap().token, "t2");
    assert_eq!(endpoint.requests(), 2);
}

/// The evicted token is never served again, not even as a fallback: a
/// refresh that fails surfaces its error, and the next call tries again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_refresh_after_invalidation_does_not_revive_the_evicted_token() {
    let endpoint = Endpoint::start(vec![
        token("t1", 3600),
        ResponseTemplate::new(503),
        token("t3", 3600),
    ])
    .await;
    let provider = endpoint.provider();
    endpoint.release();
    let rejected = provider.token().await.unwrap();

    assert!(provider.invalidate(&rejected));
    endpoint.release();
    assert!(matches!(
        provider.token().await,
        Err(GcpAuthError::Status { status: 503, .. })
    ));
    assert_eq!(cached_bearer(&provider), None, "nothing revived");
    endpoint.release();
    assert_eq!(provider.token().await.unwrap().token, "t3");
    assert_eq!(endpoint.requests(), 3);
}

/// The metadata server re-serves its cached bearer, so a refresh that
/// *starts after* the eviction can return the very bearer just rejected.
/// That one is cached (it is all the source has), and can be evicted again:
/// each round costs one refresh, which is what bounds a consumer's replays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refresh_that_returns_the_same_bearer_can_be_evicted_again() {
    let endpoint = Endpoint::start(vec![token("t1", 3600), token("t1", 3600)]).await;
    let provider = endpoint.provider();
    endpoint.release();
    let first = provider.token().await.unwrap();

    assert!(provider.invalidate(&first));
    endpoint.release();
    let again = provider.token().await.unwrap();
    assert_eq!(again.token, "t1", "the same bearer");
    assert_eq!(endpoint.requests(), 2);
    assert_eq!(cached_bearer(&provider).as_deref(), Some("t1"), "cached");

    assert!(provider.invalidate(&again), "and evictable again");
    assert_eq!(cached_bearer(&provider), None);
}

/// Panel 5(a). A refresh that was already in flight when `invalidate`
/// evicted t1, and that returns t1 (the metadata server re-serving it),
/// hands t1 to its waiters but never caches it: the next call asks the
/// source again. Then the same shape with a refresh that returns a new
/// bearer: that one is cached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refresh_in_flight_at_an_eviction_never_reinstalls_the_rejected_bearer() {
    let endpoint = Endpoint::start(vec![
        token("t1", 3600),
        token("t1", 3600),
        token("t2", 3600),
        token("t3", 3600),
    ])
    .await;
    let provider = endpoint.provider();
    endpoint.release();
    let rejected = provider.token().await.unwrap();

    // An attempt in flight (the deadline passed), then the eviction.
    provider.advance_clock(Duration::from_secs(3600));
    let mut before = spawn_callers(&provider, 1);
    until("the refresh's request", || endpoint.requests() == 2).await;
    until("its waiter", || provider.waiters() == 1).await;
    assert!(provider.invalidate(&rejected), "t1 was still cached");
    let mut after = spawn_callers(&provider, 1);
    until("a caller after the eviction joins it", || {
        provider.waiters() == 2
    })
    .await;
    endpoint.release();

    for calls in [&mut before, &mut after] {
        assert_eq!(
            calls.join_next().await.unwrap().unwrap().unwrap().token,
            "t1",
            "its waiters get what the source returned"
        );
    }
    assert!(idle(&provider));
    assert_eq!(cached_bearer(&provider), None, "but t1 is not re-cached");

    endpoint.release();
    assert_eq!(
        provider.token().await.unwrap().token,
        "t2",
        "the next call asked the source again"
    );
    assert_eq!(endpoint.requests(), 3);

    // The same race, answered with a different bearer: installed as usual.
    let rejected = provider.token().await.unwrap();
    provider.advance_clock(Duration::from_secs(3600));
    let mut in_flight = spawn_callers(&provider, 1);
    until("the second refresh's request", || endpoint.requests() == 4).await;
    until("its waiter", || provider.waiters() == 1).await;
    assert!(provider.invalidate(&rejected), "t2 was still cached");
    endpoint.release();
    assert_eq!(
        in_flight.join_next().await.unwrap().unwrap().unwrap().token,
        "t3"
    );
    assert_eq!(cached_bearer(&provider).as_deref(), Some("t3"), "cached");
    assert_eq!(provider.token().await.unwrap().token, "t3");
    assert_eq!(endpoint.requests(), 4);
}

/// Every log line `invalidate` and the no-re-install path write names the
/// source and kind and never the bearer. A current-thread runtime, so the
/// refresh task logs on this thread, into this test's capture.
#[tokio::test]
async fn invalidation_never_logs_a_bearer() {
    let capture = LogCapture::default();
    let _guard = capture.install();
    let endpoint = Endpoint::start(vec![
        token("CANARY-T1", 3600),
        token("CANARY-T1", 3600),
        token("CANARY-T2", 3600),
    ])
    .await;
    let provider = endpoint.provider();
    endpoint.release();
    let rejected = provider.token().await.unwrap();

    provider.advance_clock(Duration::from_secs(3600));
    let in_flight = provider.token();
    tokio::pin!(in_flight);
    assert!(futures::poll!(&mut in_flight).is_pending());
    until("the refresh's request", || endpoint.requests() == 2).await;
    assert!(provider.invalidate(&rejected));
    endpoint.release();
    assert_eq!(in_flight.await.unwrap().token, "CANARY-T1");
    endpoint.release();
    assert_eq!(provider.token().await.unwrap().token, "CANARY-T2");

    let logs = capture.text();
    for expected in [
        "evicted a rejected GCP access token",
        "a refresh returned the token evicted while it ran; not cached",
        "refreshed GCP access token",
        "source=metadata server",
        "kind=metadata_server",
    ] {
        assert!(logs.contains(expected), "{expected:?} not logged: {logs}");
    }
    assert!(!logs.contains("CANARY"), "a bearer was logged: {logs}");
}
