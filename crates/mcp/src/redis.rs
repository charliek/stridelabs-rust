//! Redis-backed [`RateLimiter`] and [`PatCache`] (feature `redis`), on
//! stridelabs-redis's lazy, single-flight [`RedisHandle`].
//!
//! Both share one handle with the rest of the app (`RedisHandle` is an `Arc`
//! bump to clone), and both are built for a store that can fail:
//!
//! - [`RedisRateLimiter`] **fails open**: a check's first Redis error is a
//!   `warn` line on [`RATE_LIMIT_LOG_TARGET`] and an allowed call. Its hit,
//!   one per window, is stridelabs-redis's atomic `fixed_window_hit`, which
//!   is **never replayed** after a lost reply (a retry could count one hit
//!   twice).
//! - [`RedisPatCache`] reports every failure as a [`PatCacheError`], and
//!   [`SlauthPatCredential`](crate::SlauthPatCredential) falls through to
//!   slauth on it.
//!
//! A malformed `REDIS_URL` is refused by [`RedisHandle::open`] at boot, not
//! per command: a fail-open limiter on a URL that could never connect would
//! otherwise run unlimited with nothing but warnings to show for it.

use std::fmt;
use std::future::Future;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::time::Duration;

use stridelabs_redis::{RedisError, RedisHandle};
use uuid::Uuid;

use crate::limits::{
    refusal, Clock, LimitFuture, Limits, RateClass, RateLimit, RateLimited, RateLimiter, Window,
    RATE_LIMIT_LOG_TARGET,
};
use crate::pat::{cache_ttl_secs, CachedPat, PatCache, PatCacheError, PatCacheFuture};

/// The key prefix Python's `enforce_rate_limit` uses (`key_prefix="mcp:rl"`).
/// Give each service its own when several share one Redis.
pub const DEFAULT_RATE_LIMIT_PREFIX: &str = "mcp:rl";

/// Python `enforce_rate_limit` over Redis: fixed windows per
/// `(subject, class)` — Python's minute, and optionally a UTC day — shared
/// by every instance of the service.
///
/// - The minute key is `{prefix}:{subject}:{class}:{unix_seconds / 60}`,
///   Python's exactly, so a Rust and a Python service on one Redis would
///   count into the same windows. The day key is
///   `{prefix}:{subject}:{class}:day:{unix_seconds / 86400}` (no Python
///   ancestor). Each window is its own key, hit by stridelabs-redis's
///   single-key `fixed_window_hit`, whose first hit sets the key's TTL to
///   the window's length in the same atomic script: one script per window,
///   never a multi-key one, so what Upstash or a cluster supports is
///   unchanged. The TTL is cleanup; the window's end is the key changing
///   (at the next minute, at 00:00 UTC), and a later hit never extends it.
/// - One check reads the clock once and hits a class's windows **shortest
///   first**, stopping at the first refusal, so a call refused per minute is
///   not counted in the day ([the `limits` module docs](crate::limits#windows)).
/// - A class with no limit, or a limit of 0, is not limited in that window
///   and never touches Redis for it.
/// - **Fails open, per check.** The first Redis error (down, slow, refusing
///   the script) allows the call, logs one warning, and stops: a minute hit
///   that succeeded keeps its count (there is no rollback), and a minute
///   that failed is not followed by the day. The limit is a cost bound, not
///   an authorization check, and a Redis blip must not lock every user out.
///   A hit is never replayed. Each takes at most a dial plus a response
///   timeout (1.5 s by default, stridelabs-redis's `RedisOptions`), inside
///   the tool's own deadline; a deadline or a cancellation that ends the call
///   meanwhile ends it as `ToolCall` says, never as an allowed call.
pub struct RedisRateLimiter {
    handle: RedisHandle,
    limits: Limits,
    prefix: String,
    clock: Clock,
}

// The handle recovers from a failed or abandoned command by itself (its slot
// is poison-tolerant and generation-guarded; stridelabs-redis's handle docs),
// and the rest is read-only configuration (the clock is unwind-safe by its
// own bound), so a panic mid-check leaves nothing half-updated for a later
// check to observe. Only the handle needs asserting: it holds boxed futures.
impl UnwindSafe for RedisRateLimiter {}
impl RefUnwindSafe for RedisRateLimiter {}

impl RedisRateLimiter {
    /// A limiter counting in `handle`'s Redis under `prefix` (e.g.
    /// [`DEFAULT_RATE_LIMIT_PREFIX`]), with these per-class ceilings in calls
    /// per minute (0 or an absent class: unlimited): the same limiter as
    /// [`RedisRateLimiter::from_limits`] with [`RateLimit::per_minute`]
    /// entries.
    ///
    /// The prefix must be a namespace nothing else writes under:
    /// `fixed_window_hit` sets a key's TTL only when it creates it.
    pub fn new<I>(handle: RedisHandle, limits: I, prefix: impl Into<String>) -> RedisRateLimiter
    where
        I: IntoIterator<Item = (RateClass, u32)>,
    {
        RedisRateLimiter::with_limits(handle, Limits::per_minute(limits), prefix.into())
    }

    /// A limiter counting in `handle`'s Redis under `prefix`, with these
    /// ceilings, each in its own window. For a repeated `(class, window)`,
    /// the last entry wins; a limit of 0 (the last one included) turns that
    /// window off for the class. The prefix rule is [`RedisRateLimiter::new`]'s.
    pub fn from_limits<I>(
        handle: RedisHandle,
        limits: I,
        prefix: impl Into<String>,
    ) -> RedisRateLimiter
    where
        I: IntoIterator<Item = RateLimit>,
    {
        RedisRateLimiter::with_limits(handle, Limits::new(limits), prefix.into())
    }

    fn with_limits(handle: RedisHandle, limits: Limits, prefix: String) -> RedisRateLimiter {
        RedisRateLimiter {
            handle,
            limits,
            prefix,
            clock: Clock::system(),
        }
    }

    /// Replace the clock (Unix seconds), so a test can pin calls to one
    /// window. Like `MemoryLimiter::with_clock`, the closure must itself be
    /// `UnwindSafe + RefUnwindSafe`:
    ///
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stridelabs_mcp::RedisRateLimiter;
    /// use stridelabs_redis::RedisHandle;
    ///
    /// let handle = RedisHandle::open("redis://localhost:6390/0").unwrap();
    /// let erased: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 0);
    /// let _ = RedisRateLimiter::new(handle, [], "mcp:rl").with_clock(move || erased());
    /// ```
    #[must_use]
    pub fn with_clock(
        mut self,
        now: impl Fn() -> u64 + Send + Sync + UnwindSafe + RefUnwindSafe + 'static,
    ) -> RedisRateLimiter {
        self.clock = Clock::from_fn(now);
        self
    }

    /// The key of `(subject, class)`'s `window` at `now`.
    fn key(&self, subject: &str, class: RateClass, window: Window, now: u64) -> String {
        let index = now / window.secs();
        match window {
            // Python's key, unchanged.
            Window::Minute => format!("{}:{subject}:{class}:{index}", self.prefix),
            Window::Day => format!("{}:{subject}:{class}:day:{index}", self.prefix),
        }
    }
}

impl RateLimiter for RedisRateLimiter {
    fn check<'a>(&'a self, subject: &'a str, class: RateClass) -> LimitFuture<'a> {
        Box::pin(async move {
            let limits = self.limits.of(class);
            if limits.is_empty() {
                return Ok(());
            }
            let now = self.clock.now();
            check_windows(limits, class, now, |window| {
                let key = self.key(subject, class, window, now);
                async move { self.handle.fixed_window_hit(&key, window.secs()).await }
            })
            .await
        })
    }
}

/// The multi-window policy, apart from Redis so a test can script each
/// window's outcome: hit `limits`' windows in order (shortest first) through
/// `hit`, refuse at the first count over its ceiling, and fail open — warn
/// once, allow, stop — at the first error.
async fn check_windows<F, Fut>(
    limits: &[(Window, u32)],
    class: RateClass,
    now: u64,
    mut hit: F,
) -> Result<(), RateLimited>
where
    F: FnMut(Window) -> Fut,
    Fut: Future<Output = Result<u64, RedisError>>,
{
    for &(window, limit) in limits {
        match hit(window).await {
            Ok(count) if count > u64::from(limit) => {
                return Err(refusal(class, window, limit, now))
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    target: RATE_LIMIT_LOG_TARGET,
                    class = class.as_str(),
                    window = window.as_str(),
                    %error,
                    "MCP rate limiter: Redis unavailable, failing open"
                );
                return Ok(());
            }
        }
    }
    Ok(())
}

impl fmt::Debug for RedisRateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisRateLimiter")
            // The handle's `Debug` never prints the URL.
            .field("handle", &self.handle)
            .field("limits", &self.limits)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

/// A [`PatCache`] in Redis: `GET` / `SET … EX` of `{uuid}:{expires_at}`
/// (the identity, hyphenated, and the entry's absolute expiry in Unix
/// seconds) under `{prefix}:{key}` (`key` is
/// [`pat_cache_key`](crate::pat_cache_key)'s digest). Anything else stored
/// there — a bare UUID included — is malformed: a cache error, and the
/// credential falls through to slauth.
///
/// The prefix is **required**, and should name the service (imgmcp uses
/// `imgmcp:pat:validate`): two verifiers on one Redis with one prefix would
/// share each other's positive results, whatever audience or ceiling each
/// enforces. It is used as given — not checked, even for being empty — so
/// keeping it unique among everything that shares the Redis is the
/// caller's job.
///
/// `SET … EX` is housekeeping: the key's TTL is the one given, in whole
/// seconds, rounded down, from 1 s to
/// [`PAT_CACHE_MAX_TTL`](crate::PAT_CACHE_MAX_TTL) (one day), the rule
/// [`SlauthPatCredential::with_cache_ttl`](crate::SlauthPatCredential::with_cache_ttl)
/// applies — a `Duration::MAX` from another caller is a day, never a key
/// that does not expire. Validity is the stored expiry, which the credential
/// enforces: a `SET` Redis runs late (after the credential gave up on it)
/// restarts the key's TTL but not the entry's validity.
#[derive(Debug, Clone)]
pub struct RedisPatCache {
    handle: RedisHandle,
    prefix: String,
}

impl RedisPatCache {
    /// A cache in `handle`'s Redis, under `prefix` (used as given; see the
    /// type docs).
    pub fn new(handle: RedisHandle, prefix: impl Into<String>) -> RedisPatCache {
        RedisPatCache {
            handle,
            prefix: prefix.into(),
        }
    }

    fn key(&self, key: &str) -> String {
        format!("{}:{key}", self.prefix)
    }
}

impl PatCache for RedisPatCache {
    fn get<'a>(&'a self, key: &'a str) -> PatCacheFuture<'a, Option<CachedPat>> {
        Box::pin(async move {
            let Some(value) = self.handle.get(&self.key(key)).await.map_err(cache_error)? else {
                return Ok(None);
            };
            decode(&value).map(Some)
        })
    }

    fn set<'a>(&'a self, key: &'a str, entry: CachedPat, ttl: Duration) -> PatCacheFuture<'a, ()> {
        Box::pin(async move {
            // The credential's TTL rule (whole seconds, rounded down, 1 s to
            // a day), applied again for a caller of the trait that is not the
            // credential: `SET … EX` takes whole seconds, refuses 0, and a
            // `Duration::MAX` must not become a key that never expires.
            self.handle
                .set_ex(&self.key(key), &encode(entry), cache_ttl_secs(ttl))
                .await
                .map_err(cache_error)
        })
    }
}

/// The stored form of an entry: `{uuid}:{expires_at}`.
fn encode(entry: CachedPat) -> String {
    format!("{}:{}", entry.identity.hyphenated(), entry.expires_at)
}

/// [`encode`]'s inverse; anything else is malformed. Strict: a hyphenated
/// UUID and a plain decimal expiry, nothing more.
fn decode(value: &str) -> Result<CachedPat, PatCacheError> {
    let malformed = || PatCacheError::new("the cached value is malformed");
    let (identity, expires_at) = value.split_once(':').ok_or_else(malformed)?;
    if identity.len() != 36
        || expires_at.is_empty()
        || !expires_at.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(malformed());
    }
    let identity = Uuid::try_parse(identity).map_err(|_| malformed())?;
    let expires_at = expires_at.parse().map_err(|_| malformed())?;
    Ok(CachedPat::new(identity, expires_at))
}

/// `RedisError`'s rendering never includes the URL (or its password).
fn cache_error(error: RedisError) -> PatCacheError {
    PatCacheError::new(error.to_string())
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    #[test]
    fn the_redis_limiter_is_a_rate_limiter_and_the_cache_a_pat_cache() {
        fn limiter<T: RateLimiter>() {}
        fn cache<T: PatCache>() {}
        limiter::<RedisRateLimiter>();
        cache::<RedisPatCache>();
    }

    #[test]
    fn an_entry_is_stored_as_uuid_colon_expiry_and_nothing_else_reads_back() {
        let identity = Uuid::parse_str("6f1c1b7e-2d4f-4c55-9a51-0d7e2b1f3a10").unwrap();
        let entry = CachedPat::new(identity, 1_760_000_120);

        assert_eq!(
            encode(entry),
            "6f1c1b7e-2d4f-4c55-9a51-0d7e2b1f3a10:1760000120"
        );
        assert_eq!(decode(&encode(entry)), Ok(entry));
        for malformed in [
            "6f1c1b7e-2d4f-4c55-9a51-0d7e2b1f3a10", // a bare UUID (the old form)
            "6f1c1b7e-2d4f-4c55-9a51-0d7e2b1f3a10:",
            "6f1c1b7e-2d4f-4c55-9a51-0d7e2b1f3a10:12x",
            "6f1c1b7e-2d4f-4c55-9a51-0d7e2b1f3a10:-1",
            "6f1c1b7e-2d4f-4c55-9a51-0d7e2b1f3a10:+1",
            "6f1c1b7e-2d4f-4c55-9a51-0d7e2b1f3a10:1:2",
            "6f1c1b7e-2d4f-4c55-9a51-0d7e2b1f3a10:99999999999999999999",
            "6f1c1b7e2d4f4c559a510d7e2b1f3a10:1760000120", // not hyphenated
            "not-a-uuid:1760000120",
            "",
        ] {
            assert_eq!(
                decode(malformed),
                Err(PatCacheError::new("the cached value is malformed")),
                "{malformed:?}"
            );
        }
    }

    // --- the multi-window policy, each window's outcome scripted ------------

    const GENERATE: RateClass = RateClass("generate");
    /// 20 s into its minute, 32 000 s into its UTC day.
    const NOW: u64 = 1_760_000_000;
    const BOTH: [(Window, u32); 2] = [(Window::Minute, 2), (Window::Day, 30)];

    /// `check_windows` over `limits` with each window's hit answered by
    /// `outcome`: the verdict, the windows hit in order, and the `window`
    /// field of every fail-open warning.
    fn run(
        limits: &[(Window, u32)],
        outcome: impl Fn(Window) -> Result<u64, RedisError>,
    ) -> (Result<(), RateLimited>, Vec<Window>, Vec<String>) {
        let warnings = Warnings::default();
        let subscriber = tracing_subscriber::registry().with(warnings.clone());
        let hits = std::cell::RefCell::new(Vec::new());
        let verdict = tracing::subscriber::with_default(subscriber, || {
            futures::executor::block_on(check_windows(limits, GENERATE, NOW, |window| {
                hits.borrow_mut().push(window);
                std::future::ready(outcome(window))
            }))
        });
        let warnings = warnings.0.lock().unwrap().clone();
        (verdict, hits.into_inner(), warnings)
    }

    #[test]
    fn under_every_ceiling_both_windows_count_and_the_call_is_allowed() {
        let (verdict, hits, warnings) = run(&BOTH, |_| Ok(1));
        assert_eq!(verdict, Ok(()));
        assert_eq!(hits, [Window::Minute, Window::Day], "shortest first");
        assert!(warnings.is_empty());
    }

    #[test]
    fn a_minute_refusal_never_reaches_the_day() {
        let (verdict, hits, _) = run(&BOTH, |window| match window {
            Window::Minute => Ok(3),
            Window::Day => panic!("the day must not be hit"),
        });
        assert_eq!(verdict, Err(RateLimited::new(GENERATE, 2, 40)));
        assert_eq!(hits, [Window::Minute]);
    }

    #[test]
    fn a_day_refusal_comes_after_the_minute_counted() {
        let (verdict, hits, _) = run(&BOTH, |window| match window {
            Window::Minute => Ok(2),
            Window::Day => Ok(31),
        });
        assert_eq!(
            verdict,
            Err(RateLimited::in_window(GENERATE, Window::Day, 30, 54_400))
        );
        assert_eq!(hits, [Window::Minute, Window::Day]);
    }

    #[test]
    fn a_day_error_after_a_counted_minute_fails_open_with_one_warning() {
        // The minute's INCR stands (no rollback, no replay); the day's
        // failure allows the call.
        let (verdict, hits, warnings) = run(&BOTH, |window| match window {
            Window::Minute => Ok(1),
            Window::Day => Err(RedisError::Io("the reply was lost".to_owned())),
        });
        assert_eq!(verdict, Ok(()));
        assert_eq!(hits, [Window::Minute, Window::Day]);
        assert_eq!(warnings, ["day"]);
    }

    #[test]
    fn a_minute_error_fails_open_and_skips_the_day() {
        let (verdict, hits, warnings) = run(&BOTH, |window| match window {
            Window::Minute => Err(RedisError::Connect("refused".to_owned())),
            Window::Day => panic!("the day must not be hit after a minute error"),
        });
        assert_eq!(verdict, Ok(()));
        assert_eq!(hits, [Window::Minute]);
        assert_eq!(warnings, ["minute"]);
    }

    #[test]
    fn a_minute_error_allows_even_a_call_the_day_would_refuse() {
        // Negative control for the one above: with the minute healthy, the
        // same day answer refuses.
        let day_over = |window| match window {
            Window::Minute => Ok(1),
            Window::Day => Ok(99),
        };
        assert!(run(&BOTH, day_over).0.is_err());
        let minute_down = |window| match window {
            Window::Minute => Err(RedisError::Command("ERR".to_owned())),
            Window::Day => Ok(99),
        };
        assert_eq!(run(&BOTH, minute_down).0, Ok(()));
    }

    #[test]
    fn keys_are_pythons_minute_and_a_day_of_their_own() {
        let handle = RedisHandle::open("redis://localhost:6390/0").expect("parses");
        let limiter = RedisRateLimiter::new(handle, [], "imgmcp:rl");
        assert_eq!(
            limiter.key("alice", GENERATE, Window::Minute, NOW),
            format!("imgmcp:rl:alice:generate:{}", NOW / 60)
        );
        assert_eq!(
            limiter.key("alice", GENERATE, Window::Day, NOW),
            "imgmcp:rl:alice:generate:day:20370"
        );
    }

    #[test]
    fn new_is_from_limits_with_per_minute_entries() {
        let handle = RedisHandle::open("redis://localhost:6390/0").expect("parses");
        let pairs = [(GENERATE, 6), (RateClass::READ, 0)];
        assert_eq!(
            RedisRateLimiter::new(handle.clone(), pairs, "p").limits,
            RedisRateLimiter::from_limits(
                handle,
                pairs.map(|(class, limit)| RateLimit::per_minute(class, limit)),
                "p"
            )
            .limits
        );
    }

    /// The `window` field of each warning on the limiter's target.
    #[derive(Clone, Default)]
    struct Warnings(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warnings {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Window<'a>(&'a mut Option<String>);
            impl tracing::field::Visit for Window<'_> {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    if field.name() == "window" {
                        *self.0 = Some(value.to_owned());
                    }
                }
                fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn fmt::Debug) {}
            }
            if event.metadata().target() == RATE_LIMIT_LOG_TARGET
                && *event.metadata().level() == tracing::Level::WARN
            {
                let mut window = None;
                event.record(&mut Window(&mut window));
                self.0.lock().unwrap().push(window.expect("a window field"));
            }
        }
    }

    #[test]
    fn debug_never_prints_the_url() {
        let handle = RedisHandle::open("redis://:hunter2@localhost:6390/0").expect("parses");
        let limiter = RedisRateLimiter::new(
            handle.clone(),
            [(RateClass("generate"), 6)],
            DEFAULT_RATE_LIMIT_PREFIX,
        );
        let cache = RedisPatCache::new(handle, "imgmcp:pat:validate");

        for debug in [format!("{limiter:?}"), format!("{cache:?}")] {
            assert!(!debug.contains("hunter2"), "{debug}");
        }
        assert!(format!("{limiter:?}").contains("mcp:rl"));
    }
}
