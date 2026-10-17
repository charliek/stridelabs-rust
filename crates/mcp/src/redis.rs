//! Redis-backed [`RateLimiter`] and [`PatCache`] (feature `redis`), on
//! stridelabs-redis's lazy, single-flight [`RedisHandle`].
//!
//! Both share one handle with the rest of the app (`RedisHandle` is an `Arc`
//! bump to clone), and both are built for a store that can fail:
//!
//! - [`RedisRateLimiter`] **fails open**: any Redis error is a `warn` line
//!   on [`RATE_LIMIT_LOG_TARGET`] and an allowed call. Its hit is
//!   stridelabs-redis's atomic `fixed_window_hit`, which is **never
//!   replayed** after a lost reply (a retry could count one hit twice).
//! - [`RedisPatCache`] reports every failure as a [`PatCacheError`], and
//!   [`SlauthPatCredential`](crate::SlauthPatCredential) falls through to
//!   slauth on it.
//!
//! A malformed `REDIS_URL` is refused by [`RedisHandle::open`] at boot, not
//! per command: a fail-open limiter on a URL that could never connect would
//! otherwise run unlimited with nothing but warnings to show for it.

use std::fmt;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::time::Duration;

use stridelabs_redis::{RedisError, RedisHandle};
use uuid::Uuid;

use crate::limits::{
    refusal, Clock, LimitFuture, Limits, RateClass, RateLimiter, RATE_LIMIT_LOG_TARGET, WINDOW_SECS,
};
use crate::pat::{cache_ttl_secs, CachedPat, PatCache, PatCacheError, PatCacheFuture};

/// The key prefix Python's `enforce_rate_limit` uses (`key_prefix="mcp:rl"`).
/// Give each service its own when several share one Redis.
pub const DEFAULT_RATE_LIMIT_PREFIX: &str = "mcp:rl";

/// Python `enforce_rate_limit` over Redis: a fixed one-minute window per
/// `(subject, class)`, shared by every instance of the service.
///
/// - The key is `{prefix}:{subject}:{class}:{unix_seconds / 60}`, Python's
///   exactly, so a Rust and a Python service on one Redis would count into
///   the same windows. The first hit of a window sets its 60 s TTL, in the
///   same atomic script.
/// - A class with no limit, or a limit of 0, is not limited and never
///   touches Redis.
/// - **Fails open.** A Redis error (down, slow, refusing the script) allows
///   the call and logs a warning; the limit is a cost bound, not an
///   authorization check, and a Redis blip must not lock every user out.
///   One hit takes at most a dial plus a response timeout (1.5 s by default,
///   stridelabs-redis's `RedisOptions`), inside the tool's own deadline.
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
    /// per minute (0 or an absent class: unlimited).
    ///
    /// The prefix must be a namespace nothing else writes under:
    /// `fixed_window_hit` sets a key's TTL only when it creates it.
    pub fn new<I>(handle: RedisHandle, limits: I, prefix: impl Into<String>) -> RedisRateLimiter
    where
        I: IntoIterator<Item = (RateClass, u32)>,
    {
        RedisRateLimiter {
            handle,
            limits: Limits::new(limits),
            prefix: prefix.into(),
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
}

impl RateLimiter for RedisRateLimiter {
    fn check<'a>(&'a self, subject: &'a str, class: RateClass) -> LimitFuture<'a> {
        Box::pin(async move {
            let limit = self.limits.of(class);
            if limit == 0 {
                return Ok(());
            }
            let now = self.clock.now();
            let key = format!("{}:{subject}:{class}:{}", self.prefix, now / WINDOW_SECS);
            match self.handle.fixed_window_hit(&key, WINDOW_SECS).await {
                Ok(count) if count > u64::from(limit) => Err(refusal(class, limit, now)),
                Ok(_) => Ok(()),
                Err(error) => {
                    tracing::warn!(
                        target: RATE_LIMIT_LOG_TARGET,
                        class = class.as_str(),
                        %error,
                        "MCP rate limiter: Redis unavailable, failing open"
                    );
                    Ok(())
                }
            }
        })
    }
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
