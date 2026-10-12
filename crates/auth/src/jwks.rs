//! The issuer's key set, cached.
//!
//! # Contract
//!
//! [`JwksCache::jwks_for_kid`] returns a [`JwkSet`] that **contains** the
//! requested `kid`, or an error. It never returns a set the caller then has to
//! re-check.
//!
//! Three rules decide whether that costs a network call:
//!
//! 1. **Fresh hit.** The cached set is younger than [`JWKS_TTL`] *and*
//!    contains the kid → served from memory.
//! 2. **Miss → refetch.** Either condition failing is a miss, and a miss
//!    refetches. Refetching on an unknown kid (rather than only on age) is
//!    what makes a key rotation take effect in seconds instead of an hour.
//! 3. **…but at most one refetch per [`MIN_REFETCH_INTERVAL`].** This is the
//!    hardening that rule 2 needs. Without it, anyone can mint a syntactically
//!    valid token carrying a random `kid` and turn every request into an
//!    outbound HTTPS call to the issuer — a request amplifier pointed at the
//!    single service every other service depends on. Inside the interval the
//!    answer comes from memory, and only from a set within the *stale bound*
//!    (below): that set if it contains the kid (a stale key beats a spurious
//!    401 — the interval exists to protect the issuer), otherwise
//!    [`AuthError::UnknownKid`]. With no set within the bound — nothing ever
//!    cached, or a set past it — the last fetch failed and the error is
//!    [`AuthError::Jwks`]. Saying "unknown key" there would blame the
//!    caller's token for this service's outage.
//!
//!    The stale bound is `ttl + min_refetch_interval` (3630 s at the
//!    defaults), measured from the set's last **successful** fetch, never
//!    from an attempt. Every failed attempt opens a fresh interval, so a set
//!    bounded by the interval alone outlives any issuer outage: a key the
//!    issuer retired — say, because it leaked — would keep verifying for as
//!    long as the outage lasted. Bounded this way it stops verifying at most
//!    one interval past the TTL, however many attempts fail after the last
//!    success. With a zero interval the bound is the TTL itself: nothing is
//!    served stale, and nothing is suppressed either.
//!
//! The cost of rule 3 is bounded and worth naming: a key rotation that lands
//! within [`MIN_REFETCH_INTERVAL`] of the last fetch is invisible for the
//! remainder of that interval, so tokens signed by the new key are rejected
//! for up to 30 seconds. Issuers roll keys on the order of days.
//!
//! A fetch *attempt* starts the interval, successful or not. A failing issuer
//! is precisely when hammering it is least helpful. The attempt that fails
//! answers [`AuthError::Jwks`] itself; it never falls back to the cached set.
//!
//! # Concurrency
//!
//! The refetch happens while holding the write half of the lock, and the
//! hit-check is repeated after acquiring it (double-checked locking). So a
//! thundering herd of concurrent misses — the shape a restart or a rotation
//! actually produces — makes **one** request; the rest wake up to a populated
//! cache. Holding a lock across an await is usually a smell; here it is the
//! mechanism.
//!
//! # Departures from the original implementation this crate replaced
//!
//! The cache is an *instance*, not a `static OnceLock`, and it holds an
//! injected `reqwest::Client` instead of calling `reqwest::get` (which builds
//! and throws away a whole client, TLS setup included, per fetch). A global
//! meant two verifiers in one process — the shape every test that wanted an
//! isolated cache needs — silently shared one key set.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use tokio::sync::RwLock;

use crate::config::redact_url;
use crate::error::AuthError;

/// How long a fetched key set is considered fresh.
pub const JWKS_TTL: Duration = Duration::from_secs(3600);

/// The floor between two JWKS fetches, whatever the reason for the second.
pub const MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(30);

/// Hard bound on a single JWKS fetch. The fetch can run under the cache's
/// write lock, so this is the longest a hanging issuer can stall the
/// process's verification before the attempt fails with [`AuthError::Jwks`].
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// A JWKS endpoint plus the last thing it said.
///
/// Cheap to share (`&self` methods only); a [`crate::Verifier`] owns one
/// inside its `Arc`, which is the intended way to hold it.
///
/// `Debug` prints the JWKS URL without its userinfo, query or fragment, as
/// [`crate::SlauthConfig`]'s does.
pub struct JwksCache {
    jwks_url: String,
    http: reqwest::Client,
    tuning: Tuning,
    state: RwLock<State>,
}

impl fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwksCache")
            .field("jwks_url", &redact_url(&self.jwks_url))
            // Never the client itself: reqwest::Client's Debug prints its
            // default headers, and an injected client may carry credentials.
            .field("http", &format_args!("reqwest::Client {{ .. }}"))
            .field("tuning", &self.tuning)
            .field("state", &self.state)
            .finish()
    }
}

/// The two durations of the cache contract: [`JWKS_TTL`] and
/// [`MIN_REFETCH_INTERVAL`] unless [`JwksCache::with_ttl`] or
/// [`JwksCache::with_min_refetch_interval`] replaced them.
///
/// Private so that consumers reach the durations through those builders,
/// never a struct literal, and a third one can join without a breaking
/// change.
#[derive(Debug, Clone, Copy)]
struct Tuning {
    ttl: Duration,
    min_refetch_interval: Duration,
}

impl Default for Tuning {
    fn default() -> Tuning {
        Tuning {
            ttl: JWKS_TTL,
            min_refetch_interval: MIN_REFETCH_INTERVAL,
        }
    }
}

impl Tuning {
    /// The oldest a set may be, counted from its last successful fetch, and
    /// still answer a lookup inside the refetch interval (module docs, rule
    /// 3). Saturating: [`JwksCache::with_ttl`] takes any `Duration`, and
    /// `Duration + Duration` panics on overflow.
    fn stale_bound(&self) -> Duration {
        self.ttl.saturating_add(self.min_refetch_interval)
    }
}

#[derive(Debug, Default)]
struct State {
    cached: Option<CachedJwks>,
    /// When a fetch was last *attempted* — including one that failed.
    last_fetch: Option<Instant>,
}

/// The set is behind an `Arc` so that handing it to a caller is a refcount
/// bump rather than a deep copy of every key — this happens on the fresh-hit
/// path, i.e. on essentially every authenticated request.
#[derive(Debug)]
struct CachedJwks {
    set: Arc<JwkSet>,
    /// When the last SUCCESSFUL fetch completed: both the TTL and the stale
    /// bound are measured from here. Only a successful fetch writes
    /// `State::cached`, so no failed or cancelled attempt can move it.
    fetched: Instant,
}

impl State {
    /// The cached set, if it is within `ttl` and has the key.
    fn fresh_with_kid(&self, kid: &str, ttl: Duration) -> Option<&Arc<JwkSet>> {
        let cached = self.cached.as_ref()?;
        (cached.fetched.elapsed() < ttl && cached.set.find(kid).is_some()).then_some(&cached.set)
    }

    /// The cached set, if at `now` its last successful fetch is younger than
    /// `bound`. Deliberately blind to `last_fetch`: attempts open intervals,
    /// and an interval must never extend the bound.
    ///
    /// `now` is a parameter so that the suppression arm's two checks read one
    /// instant, and so that the bound's test can pin it to the second without
    /// racing the clock.
    fn within_bound(&self, bound: Duration, now: Instant) -> Option<&CachedJwks> {
        self.cached
            .as_ref()
            .filter(|cached| now.saturating_duration_since(cached.fetched) < bound)
    }

    /// The cached set, if it has the key and is within `bound` at `now`.
    fn any_with_kid(&self, kid: &str, bound: Duration, now: Instant) -> Option<&Arc<JwkSet>> {
        self.within_bound(bound, now)
            .filter(|cached| cached.set.find(kid).is_some())
            .map(|cached| &cached.set)
    }
}

impl JwksCache {
    /// Build a cache over `jwks_url`, fetching with `http`.
    ///
    /// The client is injected and **shared** — pass the same one the rest of
    /// the service uses, so JWKS fetches reuse its connection pool and inherit
    /// its timeouts and proxy settings.
    pub fn new(jwks_url: impl Into<String>, http: reqwest::Client) -> JwksCache {
        JwksCache {
            jwks_url: jwks_url.into(),
            http,
            tuning: Tuning::default(),
            state: RwLock::new(State::default()),
        }
    }

    /// Replace the TTL ([`JWKS_TTL`] by default): how long a fetched set is
    /// served from memory before a lookup refetches it. It moves the stale
    /// bound too, which is `ttl + min_refetch_interval` (module docs, rule 3).
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> JwksCache {
        self.tuning.ttl = ttl;
        self
    }

    /// Replace the refetch floor ([`MIN_REFETCH_INTERVAL`] by default).
    ///
    /// For tests: the 30-second default is the contract. Zero turns the floor
    /// off (every miss dials the issuer, and nothing is served stale); a short
    /// interval lets a test watch the window open and close without a 30 s
    /// sleep. A production service that lowers it reopens the request
    /// amplifier rule 3 of the module docs exists to close.
    #[must_use]
    pub fn with_min_refetch_interval(mut self, interval: Duration) -> JwksCache {
        self.tuning.min_refetch_interval = interval;
        self
    }

    /// The endpoint this cache reads from.
    pub fn jwks_url(&self) -> &str {
        &self.jwks_url
    }

    /// A key set containing `kid`, from memory or from the issuer.
    ///
    /// See the module docs for when this makes a network call. Errors are
    /// [`AuthError::UnknownKid`] (the issuer doesn't publish that key, or
    /// hasn't within the refetch interval) or [`AuthError::Jwks`] (the
    /// endpoint could not be reached, answered non-2xx, answered with
    /// something that isn't a JWKS, or — inside the refetch interval — has
    /// not answered successfully within the stale bound; see the module
    /// docs, rule 3).
    ///
    /// Returned behind an `Arc`: a cache hit costs a refcount bump, not a
    /// copy of the key set.
    pub async fn jwks_for_kid(&self, kid: &str) -> Result<Arc<JwkSet>, AuthError> {
        {
            let state = self.state.read().await;
            if let Some(set) = state.fresh_with_kid(kid, self.tuning.ttl) {
                return Ok(Arc::clone(set));
            }
        }

        let mut state = self.state.write().await;

        // Re-check under the write lock: another task may have refetched
        // while this one waited for it.
        if let Some(set) = state.fresh_with_kid(kid, self.tuning.ttl) {
            return Ok(Arc::clone(set));
        }

        if state
            .last_fetch
            .is_some_and(|last| last.elapsed() < self.tuning.min_refetch_interval)
        {
            // Bounded by the last SUCCESS, not by this interval: a run of
            // failed attempts opens interval after interval, and none of them
            // may keep a retired key verifying (module docs, rule 3).
            let bound = self.tuning.stale_bound();
            let now = Instant::now();
            if let Some(set) = state.any_with_kid(kid, bound, now) {
                tracing::debug!("serving a stale JWKS: refetch is within the minimum interval");
                return Ok(Arc::clone(set));
            }
            tracing::debug!("suppressing JWKS refetch");
            return Err(match state.within_bound(bound, now) {
                Some(_) => AuthError::UnknownKid,
                // Nothing cached, or a set past the bound — which inside the
                // interval only a failed or cancelled attempt leaves behind
                // (a success would have refreshed it). Either way the last
                // attempt failed, and "unknown key" would blame the caller.
                None => AuthError::Jwks("recent fetch failed; refetch suppressed".into()),
            });
        }

        // The attempt timestamp is recorded BEFORE the await, for two
        // reasons: a caller canceling the verification future mid-fetch
        // (request timeout, task abort) must still burn the suppression
        // window — otherwise repeated cancellation defeats the rate limit —
        // and the documented "an attempt starts the interval" reading stays
        // true rather than measuring from completion.
        state.last_fetch = Some(Instant::now());
        let set = Arc::new(self.fetch().await?);

        // Replace rather than merge: a rotation that *retires* a key must
        // actually retire it here too.
        state.cached = Some(CachedJwks {
            set: Arc::clone(&set),
            fetched: Instant::now(),
        });

        match set.find(kid) {
            Some(_) => Ok(set),
            None => Err(AuthError::UnknownKid),
        }
    }

    async fn fetch(&self) -> Result<JwkSet, AuthError> {
        // Per-request timeout, because this fetch can run while the cache's
        // write lock is held: without a bound, a hanging issuer would block
        // every verification in the process until the socket died on its own.
        // reqwest::Client has NO default timeout, and we can't assume the
        // injected client configured one.
        //
        // Every `reqwest::Error` is rendered `without_url()`: its `Display`
        // otherwise ends " for url (…)", query string included (reqwest moves
        // only userinfo out, into an `Authorization` header), and
        // `AuthError::Jwks` lands in logs — the `http` feature's 500 logs it
        // in full. A JWKS URL is configuration, and configuration can carry a
        // token. The operator knows which issuer they configured.
        let response = self
            .http
            .get(&self.jwks_url)
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|err| AuthError::Jwks(format!("fetch failed: {}", err.without_url())))?;

        let status = response.status();
        if !status.is_success() {
            return Err(AuthError::Jwks(format!("endpoint returned {status}")));
        }

        response.json::<JwkSet>().await.map_err(|err| {
            AuthError::Jwks(format!(
                "response was not a valid JWKS: {}",
                err.without_url()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::mock_issuer::{issuer, jwks_body, jwks_url_of, primary_issuer};
    use crate::test_support::{TestKey, PRIMARY_KID, SECONDARY_KID};

    fn cache(server: &MockServer, tuning: Tuning) -> JwksCache {
        cache_at(jwks_url_of(server), tuning)
    }

    /// Through the public builders, so every test below exercises them.
    fn cache_at(jwks_url: String, tuning: Tuning) -> JwksCache {
        JwksCache::new(jwks_url, reqwest::Client::new())
            .with_ttl(tuning.ttl)
            .with_min_refetch_interval(tuning.min_refetch_interval)
    }

    const NO_THROTTLE: Tuning = Tuning {
        ttl: JWKS_TTL,
        min_refetch_interval: Duration::ZERO,
    };

    /// Small on purpose. The stale-bound tests fabricate instants under three
    /// minutes old, and an age near the 3600 s default could exceed the
    /// monotonic clock of a freshly booted CI VM (`earlier`'s `checked_sub`).
    ///
    /// Every test that reads the real clock keeps its fabricated ages at
    /// least 15 s from each edge it asserts (TTL, interval, bound), so a
    /// scheduler or VM pause between seeding and the lookup cannot flip the
    /// answer. Only the pure `State` test, which passes its own `now`, checks
    /// the bound to the second.
    const TTL: Duration = Duration::from_secs(60);
    const WINDOW: Duration = Duration::from_secs(30);
    /// Stale bound: 90 s.
    const BOUNDED: Tuning = Tuning {
        ttl: TTL,
        min_refetch_interval: WINDOW,
    };
    /// Under [`BOUNDED`]: 15 s past the TTL and 15 s inside the bound.
    const INSIDE_THE_BOUND: Duration = Duration::from_secs(75);
    /// Under [`BOUNDED`]: 15 s past the bound.
    const PAST_THE_BOUND: Duration = Duration::from_secs(105);

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// `by` before `at`. Fabricated rather than slept for, so the bound is
    /// checked to the second without minutes of waiting.
    fn earlier(at: Instant, by: Duration) -> Instant {
        at.checked_sub(by)
            .expect("the monotonic clock is further along than a test's fabricated age")
    }

    fn ago(age: Duration) -> Instant {
        earlier(Instant::now(), age)
    }

    /// A state holding the primary key set, last fetched successfully at
    /// `fetched`, whose most recent attempt was at `last_fetch`.
    fn fetched_at(fetched: Instant, last_fetch: Option<Instant>) -> State {
        State {
            cached: Some(CachedJwks {
                set: Arc::new(TestKey::primary().jwks()),
                fetched,
            }),
            last_fetch,
        }
    }

    async fn seed(cache: &JwksCache, age: Duration, last_fetch: Option<Instant>) {
        *cache.state.write().await = fetched_at(ago(age), last_fetch);
    }

    /// Time passing, without sleeping: every instant the cache holds becomes
    /// `by` older — including any the code under test wrote, which a re-seed
    /// would overwrite.
    async fn advance(cache: &JwksCache, by: Duration) {
        let mut state = cache.state.write().await;
        if let Some(cached) = state.cached.as_mut() {
            cached.fetched = earlier(cached.fetched, by);
        }
        state.last_fetch = state.last_fetch.map(|at| earlier(at, by));
    }

    /// The outage answer: `Jwks`, from the suppression arm.
    fn assert_suppressed_outage(result: Result<Arc<JwkSet>, AuthError>, context: &str) {
        let Err(err) = result else {
            panic!("{context}: served a set; expected the suppressed outage");
        };
        assert!(matches!(err, AuthError::Jwks(_)), "{context}: {err}");
        assert!(err.to_string().contains("suppressed"), "{context}: {err}");
    }

    /// Requests the mock issuer has answered so far — checked mid-test, where
    /// `expect(n)` only checks the total when the server drops.
    async fn requests(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .expect("wiremock records requests by default")
            .len()
    }

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
        let cache = cache(
            &server,
            Tuning {
                // Zero TTL: every lookup finds the entry already stale.
                ttl: Duration::ZERO,
                min_refetch_interval: Duration::ZERO,
            },
        );

        cache.jwks_for_kid(PRIMARY_KID).await.expect("first");
        cache.jwks_for_kid(PRIMARY_KID).await.expect("after expiry");
    }

    #[tokio::test]
    async fn an_unknown_kid_refetches_and_picks_up_a_rotated_key() {
        let server = MockServer::start().await;
        // First response has only key 1; the second has only key 2, i.e. the
        // issuer rotated between the two lookups.
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(jwks_body(TestKey::primary().jwks_json()))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(jwks_body(TestKey::secondary().jwks_json()))
            .expect(1)
            .mount(&server)
            .await;
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
        let err = cache.jwks_for_kid("no-such-kid").await.unwrap_err();

        assert!(matches!(err, AuthError::UnknownKid), "{err}");
    }

    /// The first fetch ever succeeds but lacks the kid: the issuer's verdict,
    /// not an outage. The set it brought back answers the same kid inside the
    /// interval that fetch opened, without a second request.
    #[tokio::test]
    async fn a_cold_fetch_without_the_kid_is_unknown_and_opens_the_interval() {
        let server = primary_issuer(1).await;
        let cache = cache(&server, BOUNDED);

        let err = cache
            .jwks_for_kid("attacker-supplied-kid")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::UnknownKid), "cold fetch: {err}");
        assert_eq!(requests(&server).await, 1, "the cold lookup dials once");

        let err = cache
            .jwks_for_kid("attacker-supplied-kid")
            .await
            .unwrap_err();
        assert!(
            matches!(err, AuthError::UnknownKid),
            "inside the interval: {err}"
        );
        assert_eq!(requests(&server).await, 1, "answered from memory");
    }

    /// A set younger than the TTL, an unknown kid, and the last attempt a
    /// full interval ago: a rotation, picked up by one refetch rather than
    /// after the rest of the TTL.
    #[tokio::test]
    async fn an_unknown_kid_outside_the_interval_refetches_and_picks_up_a_rotated_key() {
        let server = issuer(jwks_body(TestKey::secondary().jwks_json()), 1).await;
        let cache = cache(&server, BOUNDED);
        // Fetched 45 s ago by the attempt then: 15 s inside the 60 s TTL, and
        // 15 s outside the 30 s interval.
        seed(&cache, secs(45), Some(ago(secs(45)))).await;

        let after = cache
            .jwks_for_kid(SECONDARY_KID)
            .await
            .expect("the rotated key, refetched");
        assert!(after.find(SECONDARY_KID).is_some());
        assert_eq!(requests(&server).await, 1, "one refetch");

        // The refetch replaced the set and opened a new interval: the retired
        // key is unknown now, and that is answered from memory.
        let err = cache.jwks_for_kid(PRIMARY_KID).await.unwrap_err();
        assert!(matches!(err, AuthError::UnknownKid), "{err}");
        assert_eq!(requests(&server).await, 1, "answered from memory");
    }

    #[tokio::test]
    async fn an_unknown_kid_inside_the_interval_does_not_refetch() {
        // One request total: the lookup for the known key. The ones that
        // follow are answered from memory, without touching the issuer.
        let server = primary_issuer(1).await;
        let cache = cache(&server, BOUNDED);

        cache.jwks_for_kid(PRIMARY_KID).await.expect("known key");

        for _ in 0..2 {
            let err = cache
                .jwks_for_kid("attacker-supplied-kid")
                .await
                .unwrap_err();
            assert!(matches!(err, AuthError::UnknownKid), "{err}");
        }

        // Past the TTL but within the stale bound, the set is still the
        // issuer's word on which keys exist: unknown, not an outage.
        let attempt = cache.state.read().await.last_fetch;
        seed(&cache, INSIDE_THE_BOUND, attempt).await;
        let err = cache
            .jwks_for_kid("attacker-supplied-kid")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::UnknownKid), "{err}");
    }

    #[tokio::test]
    async fn a_stale_entry_is_served_when_a_refetch_is_suppressed() {
        let server = primary_issuer(1).await;
        let cache = cache(
            &server,
            Tuning {
                // Stale immediately, but the interval forbids refetching —
                // the key is still the issuer's key, so serve it.
                ttl: Duration::ZERO,
                min_refetch_interval: MIN_REFETCH_INTERVAL,
            },
        );

        cache.jwks_for_kid(PRIMARY_KID).await.expect("first");
        cache
            .jwks_for_kid(PRIMARY_KID)
            .await
            .expect("stale but usable");

        // ...but only within the stale bound (ttl 0 + the interval). The same
        // set 15 s past it, with the interval still open — which only a
        // failed attempt leaves behind — is an outage, not a key.
        let attempt = cache.state.read().await.last_fetch;
        seed(&cache, MIN_REFETCH_INTERVAL + secs(15), attempt).await;
        assert_suppressed_outage(cache.jwks_for_kid(PRIMARY_KID).await, "past the bound");
    }

    #[tokio::test]
    async fn a_suppressed_refetch_after_a_failure_reports_the_outage() {
        let server = issuer(ResponseTemplate::new(503), 1).await;
        let cache = cache(&server, BOUNDED);

        let first = cache.jwks_for_kid(PRIMARY_KID).await.unwrap_err();
        let second = cache.jwks_for_kid(PRIMARY_KID).await;

        // With nothing ever cached, the caller's token can't be blamed.
        assert!(matches!(first, AuthError::Jwks(_)), "{first}");
        assert_suppressed_outage(second, "nothing ever cached");

        // Nor with a set that has the kid but is past the stale bound: inside
        // the interval the failure opened, it is no usable set at all.
        let attempt = cache.state.read().await.last_fetch;
        seed(&cache, PAST_THE_BOUND, attempt).await;
        assert_suppressed_outage(
            cache.jwks_for_kid(PRIMARY_KID).await,
            "a set past the bound",
        );
    }

    /// The bound is `ttl + interval`, read off the last SUCCESS whatever
    /// `last_fetch` says: every state here has an attempt stamped at `now`,
    /// i.e. sits inside an interval a failure opened. One fixed `now`, so the
    /// edges are checked to the second with no clock to race.
    #[test]
    fn the_stale_bound_is_ttl_plus_one_window_past_the_last_success() {
        let now = Instant::now();
        let just_failed = |age| fetched_at(earlier(now, age), Some(now));
        let served = |state: &State, tuning: Tuning| {
            let bound = tuning.stale_bound();
            let served = state.within_bound(bound, now).is_some();
            assert_eq!(
                state.any_with_kid(PRIMARY_KID, bound, now).is_some(),
                served,
                "the kid lookup obeys the same bound"
            );
            served
        };

        assert!(served(&just_failed(secs(89)), BOUNDED), "inside the bound");
        assert!(
            !served(&just_failed(secs(90)), BOUNDED),
            "the bound itself is past it"
        );
        assert!(
            !served(&just_failed(secs(91)), BOUNDED),
            "fetched 91 s ago: a fresh attempt stamp must not stretch the bound"
        );

        // A zero interval: the bound is the TTL — nothing is served stale.
        let unthrottled = Tuning {
            ttl: TTL,
            min_refetch_interval: Duration::ZERO,
        };
        assert!(served(&just_failed(secs(59)), unthrottled));
        assert!(!served(&just_failed(secs(61)), unthrottled));

        // `with_ttl` takes any `Duration`; the bound saturates, not panics.
        let forever = Tuning {
            ttl: Duration::MAX,
            min_refetch_interval: WINDOW,
        };
        assert_eq!(forever.stale_bound(), Duration::MAX);
        assert!(served(&just_failed(secs(91)), forever));

        // Never fetched successfully: nothing to serve, whatever the interval.
        assert!(!served(&State::default(), BOUNDED));
    }

    /// The suppressed rows of the behaviour table through the public entry
    /// point. Every lookup sits inside an interval a failed attempt opened,
    /// so none may dial (`expect(0)`, and `last_fetch` must not move).
    #[tokio::test]
    async fn a_suppressed_lookup_past_the_bound_is_an_outage_not_a_verdict() {
        let server = primary_issuer(0).await;
        let cache = cache(&server, BOUNDED);
        let attempt = Some(Instant::now());

        // Past the bound: an outage whether or not the set has the kid.
        seed(&cache, PAST_THE_BOUND, attempt).await;
        for kid in [PRIMARY_KID, "attacker-supplied-kid"] {
            assert_suppressed_outage(cache.jwks_for_kid(kid).await, kid);
        }
        assert_eq!(cache.state.read().await.last_fetch, attempt, "not dialed");

        // Past the TTL but within the bound: still the issuer's word.
        seed(&cache, INSIDE_THE_BOUND, attempt).await;
        cache
            .jwks_for_kid(PRIMARY_KID)
            .await
            .expect("stale but bounded");
        let err = cache
            .jwks_for_kid("attacker-supplied-kid")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::UnknownKid), "{err}");
        assert_eq!(cache.state.read().await.last_fetch, attempt, "not dialed");
    }

    /// The module's claim that a caller cancelling mid-fetch still burns the
    /// interval — and that the cancelled attempt, not being a success, leaves
    /// the bound where the last success put it.
    #[tokio::test]
    async fn a_cancelled_fetch_burns_the_window_and_does_not_move_the_bound() {
        // Accepts the connection (the kernel backlog does) and never answers,
        // so the fetch hangs until it is dropped.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a silent listener");
        let url = format!(
            "http://{}/jwks",
            silent.local_addr().expect("listener address")
        );
        let cache = cache_at(url, BOUNDED);
        // Past the TTL, so the lookup dials; no attempt yet, so it may.
        seed(&cache, PAST_THE_BOUND, None).await;
        let last_success = cache.state.read().await.cached.as_ref().map(|c| c.fetched);

        let cancelled =
            tokio::time::timeout(Duration::from_millis(200), cache.jwks_for_kid(PRIMARY_KID)).await;
        assert!(cancelled.is_err(), "the fetch hung and was cancelled");

        let state = cache.state.read().await;
        assert!(
            state.last_fetch.is_some_and(|at| at.elapsed() < WINDOW),
            "the cancelled attempt opened an interval"
        );
        assert_eq!(
            state.cached.as_ref().map(|c| c.fetched),
            last_success,
            "a cancelled attempt is not a success"
        );
        drop(state);

        assert_suppressed_outage(
            cache.jwks_for_kid(PRIMARY_KID).await,
            "inside that interval, past the bound",
        );
        drop(silent);
    }

    /// The outage timeline the bound exists for, compressed with `advance`
    /// (t counts from the last success). Two attempts reach the issuer and
    /// both fail; no run of them revives the set.
    ///
    /// The interval here is 60 s (TTL 60 s, bound 120 s), not 30 s: one
    /// interval must hold a lookup inside the bound and one past it, each
    /// 15 s from the bound and from the interval's own end, which takes an
    /// interval of at least 45 s.
    #[tokio::test]
    async fn failed_attempts_never_extend_the_stale_bound() {
        let server = issuer(ResponseTemplate::new(503), 2).await;
        let cache = cache(
            &server,
            Tuning {
                ttl: TTL,
                min_refetch_interval: secs(60),
            },
        );
        // t = 90: 30 s past the TTL, and the last attempt — the success
        // itself — 30 s outside the interval.
        seed(&cache, secs(90), Some(ago(secs(90)))).await;
        let last_success = cache.state.read().await.cached.as_ref().map(|c| c.fetched);

        let err = cache.jwks_for_kid(PRIMARY_KID).await.unwrap_err();
        assert!(
            matches!(&err, AuthError::Jwks(detail) if detail.contains("503")),
            "attempt 1 dials, and the failure is its own answer: {err}"
        );
        assert_eq!(
            cache.state.read().await.cached.as_ref().map(|c| c.fetched),
            last_success,
            "a failed attempt is not a success"
        );
        // Inside attempt 1's interval, and 30 s inside the bound.
        cache
            .jwks_for_kid(PRIMARY_KID)
            .await
            .expect("inside attempt 1's interval and the bound: stale but served");

        // t = 135: the same interval (15 s before it ends), now 15 s past the
        // bound.
        advance(&cache, secs(45)).await;
        assert_suppressed_outage(cache.jwks_for_kid(PRIMARY_KID).await, "t = 135");

        // t = 165: the interval closed 15 s ago, so attempt 2 dials — and
        // fails.
        advance(&cache, secs(30)).await;
        let err = cache.jwks_for_kid(PRIMARY_KID).await.unwrap_err();
        assert!(
            matches!(&err, AuthError::Jwks(detail) if detail.contains("503")),
            "attempt 2 dials, and the failure is its own answer: {err}"
        );
        assert_suppressed_outage(
            cache.jwks_for_kid(PRIMARY_KID).await,
            "inside attempt 2's interval",
        );
    }

    #[tokio::test]
    async fn a_non_2xx_response_is_a_jwks_error() {
        let server = issuer(ResponseTemplate::new(500), 1).await;
        let cache = cache(&server, Tuning::default());

        let err = cache.jwks_for_kid(PRIMARY_KID).await.unwrap_err();

        assert!(matches!(err, AuthError::Jwks(_)), "{err}");
        assert!(err.to_string().contains("500"));
    }

    #[tokio::test]
    async fn a_malformed_body_is_a_jwks_error() {
        let server = issuer(jwks_body("{\"keys\": \"not a list\"}"), 1).await;
        let cache = cache(&server, Tuning::default());

        let err = cache.jwks_for_kid(PRIMARY_KID).await.unwrap_err();

        assert!(matches!(err, AuthError::Jwks(_)), "{err}");
        assert!(err.to_string().contains("not a valid JWKS"));
    }

    #[tokio::test]
    async fn an_unreachable_endpoint_is_a_jwks_error() {
        // Port 1 on loopback: nothing listens, and no request escapes the host.
        let cache = JwksCache::new("http://127.0.0.1:1/jwks", reqwest::Client::new());

        let err = cache.jwks_for_kid(PRIMARY_KID).await.unwrap_err();

        assert!(matches!(err, AuthError::Jwks(_)), "{err}");
    }

    // --- the URL canary ----------------------------------------------------
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

            let logs = String::from_utf8(sink.0.lock().expect("log sink").clone())
                .expect("utf-8 log output");
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_misses_make_one_request() {
        let server = issuer(
            // A slow response widens the window in which every other task
            // piles up behind the first one's fetch.
            jwks_body(TestKey::primary().jwks_json()).set_delay(Duration::from_millis(100)),
            1,
        )
        .await;
        let cache = Arc::new(cache(&server, Tuning::default()));

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            tasks.push(tokio::spawn(async move {
                cache.jwks_for_kid(PRIMARY_KID).await
            }));
        }

        for task in tasks {
            task.await.expect("task").expect("jwks");
        }
    }
}
