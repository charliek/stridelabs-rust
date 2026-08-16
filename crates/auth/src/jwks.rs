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
//!    answer comes from memory: the cached set if it happens to contain the
//!    kid (a stale key beats a spurious 401 — the interval exists to protect
//!    the issuer, not to expire keys), otherwise [`AuthError::UnknownKid`] —
//!    unless nothing has ever been cached, in which case the *last fetch*
//!    failed and the error is [`AuthError::Jwks`]. Saying "unknown key" there
//!    would blame the caller's token for this service's outage.
//!
//! The cost of rule 3 is bounded and worth naming: a key rotation that lands
//! within [`MIN_REFETCH_INTERVAL`] of the last fetch is invisible for the
//! remainder of that interval, so tokens signed by the new key are rejected
//! for up to 30 seconds. Issuers roll keys on the order of days.
//!
//! A fetch *attempt* starts the interval, successful or not. A failing issuer
//! is precisely when hammering it is least helpful.
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

use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use tokio::sync::RwLock;

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
#[derive(Debug)]
pub struct JwksCache {
    jwks_url: String,
    http: reqwest::Client,
    tuning: Tuning,
    state: RwLock<State>,
}

/// The two durations of the cache contract, injectable so the tests can
/// exercise TTL expiry and interval suppression without sleeping.
///
/// Crate-private on purpose: the semantics are the crate's contract, not a
/// consumer's dial. A service that wants different numbers wants a different
/// argument, made once here.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tuning {
    pub ttl: Duration,
    pub min_refetch_interval: Duration,
}

impl Default for Tuning {
    fn default() -> Tuning {
        Tuning {
            ttl: JWKS_TTL,
            min_refetch_interval: MIN_REFETCH_INTERVAL,
        }
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
    fetched: Instant,
}

impl State {
    /// The cached set, if it is within `ttl` and has the key.
    fn fresh_with_kid(&self, kid: &str, ttl: Duration) -> Option<&Arc<JwkSet>> {
        let cached = self.cached.as_ref()?;
        (cached.fetched.elapsed() < ttl && cached.set.find(kid).is_some()).then_some(&cached.set)
    }

    /// The cached set if it has the key, however old it is.
    fn any_with_kid(&self, kid: &str) -> Option<&Arc<JwkSet>> {
        let cached = self.cached.as_ref()?;
        cached.set.find(kid).is_some().then_some(&cached.set)
    }
}

impl JwksCache {
    /// Build a cache over `jwks_url`, fetching with `http`.
    ///
    /// The client is injected and **shared** — pass the same one the rest of
    /// the service uses, so JWKS fetches reuse its connection pool and inherit
    /// its timeouts and proxy settings.
    pub fn new(jwks_url: impl Into<String>, http: reqwest::Client) -> JwksCache {
        JwksCache::with_tuning(jwks_url, http, Tuning::default())
    }

    pub(crate) fn with_tuning(
        jwks_url: impl Into<String>,
        http: reqwest::Client,
        tuning: Tuning,
    ) -> JwksCache {
        JwksCache {
            jwks_url: jwks_url.into(),
            http,
            tuning,
            state: RwLock::new(State::default()),
        }
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
    /// something that isn't a JWKS, or has never yet been reached at all —
    /// see the module docs on the suppression window).
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
            if let Some(set) = state.any_with_kid(kid) {
                tracing::debug!("serving a stale JWKS: refetch is within the minimum interval");
                return Ok(Arc::clone(set));
            }
            tracing::debug!("suppressing JWKS refetch for an unknown key id");
            return Err(match state.cached {
                Some(_) => AuthError::UnknownKid,
                // Nothing cached at all means the last attempt failed, and
                // saying "unknown key" would blame the caller for it.
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
        let response = self
            .http
            .get(&self.jwks_url)
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|err| AuthError::Jwks(format!("fetch failed: {err}")))?;

        let status = response.status();
        if !status.is_success() {
            return Err(AuthError::Jwks(format!("endpoint returned {status}")));
        }

        response
            .json::<JwkSet>()
            .await
            .map_err(|err| AuthError::Jwks(format!("response was not a valid JWKS: {err}")))
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
        JwksCache::with_tuning(jwks_url_of(server), reqwest::Client::new(), tuning)
    }

    const NO_THROTTLE: Tuning = Tuning {
        ttl: JWKS_TTL,
        min_refetch_interval: Duration::ZERO,
    };

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

    #[tokio::test]
    async fn an_unknown_kid_inside_the_interval_does_not_refetch() {
        // One request total: the lookup for the known key. The two that
        // follow are answered from memory, without touching the issuer.
        let server = primary_issuer(1).await;
        let cache = cache(&server, Tuning::default());

        cache.jwks_for_kid(PRIMARY_KID).await.expect("known key");

        for _ in 0..2 {
            let err = cache
                .jwks_for_kid("attacker-supplied-kid")
                .await
                .unwrap_err();
            assert!(matches!(err, AuthError::UnknownKid), "{err}");
        }
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
    }

    #[tokio::test]
    async fn a_suppressed_refetch_after_a_failure_reports_the_outage() {
        let server = issuer(ResponseTemplate::new(503), 1).await;
        let cache = cache(&server, Tuning::default());

        let first = cache.jwks_for_kid(PRIMARY_KID).await.unwrap_err();
        let second = cache.jwks_for_kid(PRIMARY_KID).await.unwrap_err();

        // With nothing ever cached, the caller's token can't be blamed.
        assert!(matches!(first, AuthError::Jwks(_)), "{first}");
        assert!(matches!(second, AuthError::Jwks(_)), "{second}");
        assert!(second.to_string().contains("suppressed"));
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
