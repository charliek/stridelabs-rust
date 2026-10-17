//! slauth personal access tokens at the MCP boundary: [`SlauthPatCredential`],
//! a [`CredentialVerifier`] for `slp_live_…` tokens, with an optional
//! [`PatCache`] in front of slauth.
//!
//! slauth resolves a PAT to an identity and nothing else — a PAT carries no
//! scopes — so the credential grants exactly the app's **ceiling** scopes on
//! every success. Wire it under slauth's prefix:
//!
//! ```no_run
//! # fn wire(resource: &stridelabs_mcp::ProtectedResource, http: reqwest::Client) {
//! use stridelabs_auth::{PatValidator, SLAUTH_PAT_PREFIX};
//! use stridelabs_mcp::{McpVerifier, SlauthPatCredential};
//!
//! // The validator's client must follow no redirects (see below).
//! let no_redirects = reqwest::Client::builder()
//!     .redirect(reqwest::redirect::Policy::none())
//!     .build()
//!     .expect("a client builds");
//! let pats = SlauthPatCredential::new(
//!     PatValidator::new("https://auth.stridelabs.ai/api/v1/pat/validate", no_redirects),
//!     ["image:generate"],
//! );
//! let verifier = McpVerifier::new(resource, "https://auth.stridelabs.ai/.well-known/jwks.json", http)
//!     .with_credential(SLAUTH_PAT_PREFIX, pats);
//! # }
//! ```
//!
//! # Outcomes
//!
//! | slauth's answer ([`PatValidator::validate`]) | Result |
//! |---|---|
//! | the identity | a [`Principal`]: subject = the identity UUID (hyphenated, lowercase), scopes = the ceiling, [`AuthMethod::Token`], no email, name or client id |
//! | `Rejected(reason)` (malformed, unknown, revoked, expired) | [`VerifyError::Invalid`]`(reason)` → `401 invalid_token` |
//! | `Unavailable(reason)` (slauth down, slow, or answering nonsense) | [`VerifyError::Unavailable`]`(reason)` → `503`; the client keeps its token |
//!
//! The reasons are [`PatValidationError`]'s fixed messages (or one of
//! slauth's four reason codes), never the token or the URL.
//!
//! # The cache: fail-through, successes only
//!
//! [`SlauthPatCredential::with_cache`] puts a [`PatCache`] in front of the
//! validation, so a client making many calls costs slauth one round trip per
//! [`PAT_CACHE_TTL`] instead of one per call:
//!
//! - **The key is a digest, never the token**: the first 32 lowercase hex
//!   characters of the token's SHA-256 ([`pat_cache_key`]), which the cache
//!   namespaces under its own prefix (Python's `pat:validate:{digest}`;
//!   `RedisPatCache` requires the prefix so verifiers sharing a Redis never
//!   share each other's positive results).
//! - **Only the identity is stored, with an absolute expiry**, and only a
//!   success's: a [`CachedPat`] of the identity UUID and the moment the
//!   verdict stops being trusted (the validation's start plus the TTL, Unix
//!   seconds). The ceiling scopes are applied afresh on every hit, so
//!   changing them takes effect at once; a rejection or an outage is never
//!   cached.
//! - **Fail-through.** A cache that errors, times out (every operation is
//!   bounded by [`PAT_CACHE_TIMEOUT`]) or holds something malformed is
//!   skipped with a warning, and the token is validated against slauth
//!   directly: a cache blip never breaks authentication. After a failed
//!   read nothing is written back (as in Python); a failed write still
//!   returns the success it was caching, without validating again.
//! - **The expiry is absolute, and the credential enforces it.** An entry
//!   read at or after its `expires_at` is a miss, whatever the store's own
//!   TTL says, so nothing can stretch it: not a hit (which never writes),
//!   and not a write that lands late — a `SET` that Redis runs after the
//!   credential gave up on it at the 250 ms bound still carries the original
//!   expiry, though its own housekeeping TTL starts when it lands.
//!
//! **Staleness.** A cached success is trusted until its expiry, so a PAT
//! revoked in slauth keeps working here for up to the TTL (120 s by
//! default) after the validation that cached it — exactly Python's
//! trade-off, now a bound that holds against late writes too (with the
//! clocks of the instances sharing a cache in step: an expiry is a
//! wall-clock time). Shorten it with [`SlauthPatCredential::with_cache_ttl`]
//! if that window matters more than slauth's load.
//!
//! **The validator's client must not follow redirects**
//! (`reqwest::redirect::Policy::none()`): with a following client, a
//! redirect back to the validate URL is indistinguishable from slauth's
//! answer, and whatever answers it would be taken as the verdict — and
//! cached. See [`PatValidator`].
//!
//! A token that is not shaped like a slauth PAT ([`is_slauth_pat`]) is refused
//! by the validator without a call, and skips the cache too: only a
//! validated success is ever stored, so no such key can exist.

use std::borrow::Cow;
use std::fmt;
use std::future::Future;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use stridelabs_auth::{is_slauth_pat, PatValidationError, PatValidator};
use uuid::Uuid;

use crate::auth::AUTH_LOG_TARGET;
use crate::limits::Clock;
use crate::principal::{AuthMethod, Principal};
use crate::verifier::{CredentialVerifier, VerifyError, VerifyFuture};

/// How long a cached validation stays valid: Python's
/// `PAT_CACHE_TTL_SECONDS`. Also the longest a revoked PAT keeps working
/// here.
pub const PAT_CACHE_TTL: Duration = Duration::from_secs(120);

/// The longest TTL [`SlauthPatCredential::with_cache_ttl`] accepts (a
/// longer one is cut to it): one day, and so the most a revocation can lag.
pub const PAT_CACHE_MAX_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// A cache TTL as whole seconds: rounded **down** (so the configured TTL is
/// a true upper bound on staleness), at least 1 s (a cache cannot store for
/// less, and Redis refuses `EX 0`), at most [`PAT_CACHE_MAX_TTL`].
pub(crate) fn cache_ttl_secs(ttl: Duration) -> u64 {
    ttl.as_secs().clamp(1, PAT_CACHE_MAX_TTL.as_secs())
}

/// The bound on every cache operation. A cache slower than this is treated
/// as failed and skipped: slauth, which answers within its own 5 s bound,
/// decides instead.
pub const PAT_CACHE_TIMEOUT: Duration = Duration::from_millis(250);

/// A [`PatCache`] operation that failed.
///
/// The reason is for the log line the credential writes when it skips the
/// cache; it must never carry the token, and should not carry the key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("PAT cache unavailable: {0}")]
pub struct PatCacheError(Cow<'static, str>);

impl PatCacheError {
    /// A cache failure, for `reason`.
    pub fn new(reason: impl Into<Cow<'static, str>>) -> PatCacheError {
        PatCacheError(reason.into())
    }

    /// Why the operation failed.
    pub fn reason(&self) -> &str {
        &self.0
    }
}

/// What a [`PatCache`] holds for one token: the identity slauth resolved it
/// to, and when that verdict stops being trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CachedPat {
    /// The slauth identity the token belongs to.
    pub identity: Uuid,
    /// Unix seconds: the validation's start plus the TTL. Read at or after
    /// it, the entry is a miss.
    pub expires_at: u64,
}

impl CachedPat {
    /// An entry for `identity`, trusted until `expires_at` (Unix seconds).
    pub fn new(identity: Uuid, expires_at: u64) -> CachedPat {
        CachedPat {
            identity,
            expires_at,
        }
    }
}

/// The future a [`PatCache`] operation returns.
pub type PatCacheFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, PatCacheError>> + Send + 'a>>;

/// Where [`SlauthPatCredential`] keeps validated identities.
///
/// `key` is [`pat_cache_key`] of the token: 32 lowercase hex characters,
/// never the token itself. A cache that shares a store with anything else
/// namespaces it (`RedisPatCache` prefixes it).
///
/// Any `Err` (including from a `get` whose stored value is malformed) makes
/// the credential skip the cache and ask slauth; so does an operation slower
/// than [`PAT_CACHE_TIMEOUT`]. The cache need not judge expiry: the
/// credential treats an entry past its [`CachedPat::expires_at`] as a miss.
pub trait PatCache: Send + Sync + 'static {
    /// The entry cached under `key`, or `None` on a miss. A stored value
    /// that is not an entry is an `Err`.
    fn get<'a>(&'a self, key: &'a str) -> PatCacheFuture<'a, Option<CachedPat>>;

    /// Cache `entry` under `key`, replacing whatever is there, and let the
    /// store drop it after `ttl` — housekeeping only: validity is
    /// `entry.expires_at`, which the credential enforces on every read.
    ///
    /// From [`SlauthPatCredential`], `ttl` is always whole seconds from 1 s
    /// to [`PAT_CACHE_MAX_TTL`] (see [`SlauthPatCredential::with_cache_ttl`]).
    fn set<'a>(&'a self, key: &'a str, entry: CachedPat, ttl: Duration) -> PatCacheFuture<'a, ()>;
}

/// The cache key for `token`: the first 32 lowercase hex characters (128
/// bits) of its SHA-256 — Python's `hashlib.sha256(token).hexdigest()[:32]`.
pub fn pat_cache_key(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut key = String::with_capacity(32);
    for byte in &digest[..16] {
        key.push(char::from(HEX[usize::from(byte >> 4)]));
        key.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    key
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// A [`CredentialVerifier`] for slauth PATs (see the [module docs](self)):
/// slauth's verdict through a [`PatValidator`], the app's ceiling scopes on
/// success, and an optional fail-through [`PatCache`].
#[derive(Clone)]
pub struct SlauthPatCredential {
    validator: PatValidator,
    ceiling: Arc<[String]>,
    cache: Option<Arc<dyn PatCache>>,
    cache_ttl: Duration,
    clock: Clock,
}

impl SlauthPatCredential {
    /// A credential validating with `validator`, and granting exactly
    /// `ceiling_scopes` to every valid PAT.
    pub fn new<I, S>(validator: PatValidator, ceiling_scopes: I) -> SlauthPatCredential
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        SlauthPatCredential {
            validator,
            ceiling: ceiling_scopes.into_iter().map(Into::into).collect(),
            cache: None,
            cache_ttl: PAT_CACHE_TTL,
            clock: Clock::system(),
        }
    }

    /// Consult `cache` before slauth, and store successes in it for
    /// [`PAT_CACHE_TTL`] (see the [module docs](self) for the fail-through
    /// rules).
    #[must_use]
    pub fn with_cache(mut self, cache: impl PatCache) -> SlauthPatCredential {
        self.cache = Some(Arc::new(cache));
        self
    }

    /// Replace the cached entries' TTL ([`PAT_CACHE_TTL`] by default): the
    /// longest a revoked PAT keeps working.
    ///
    /// Whole seconds, **rounded down**, so the TTL given is a true upper
    /// bound on how stale a cached success can be: `2.9 s` stores for 2 s.
    /// At least 1 s (a cache cannot store for less: `0` and `0.5 s` store
    /// for 1 s), and at most [`PAT_CACHE_MAX_TTL`], one day (`Duration::MAX`
    /// stores for a day).
    #[must_use]
    pub fn with_cache_ttl(mut self, ttl: Duration) -> SlauthPatCredential {
        self.cache_ttl = Duration::from_secs(cache_ttl_secs(ttl));
        self
    }

    /// Replace the clock (Unix seconds) that stamps and judges cache
    /// entries' expiry, so a test can move time without sleeping. Like the
    /// limiters', the closure must itself be `UnwindSafe + RefUnwindSafe`.
    #[must_use]
    pub fn with_clock(
        mut self,
        now: impl Fn() -> u64 + Send + Sync + UnwindSafe + RefUnwindSafe + 'static,
    ) -> SlauthPatCredential {
        self.clock = Clock::from_fn(now);
        self
    }

    /// The identity `token` belongs to: from the cache, or from slauth.
    async fn identity(&self, token: &str) -> Result<Uuid, PatValidationError> {
        // A token not shaped like a PAT is refused by the validator without a
        // call, and can have no cache entry (only successes are stored).
        let cache = match self.cache.as_deref() {
            Some(cache) if is_slauth_pat(token) => cache,
            _ => return self.validator.validate(token).await,
        };
        let key = pat_cache_key(token);
        match bounded(cache.get(&key)).await {
            // Judged after the read returns, so a slow read cannot carry an
            // entry past its expiry.
            Ok(Some(entry)) if entry.expires_at > self.clock.now() => return Ok(entry.identity),
            // Expired: a miss, whatever the store's own TTL kept it for.
            Ok(Some(_)) | Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    target: AUTH_LOG_TARGET,
                    %error,
                    "PAT cache read failed; validating directly against slauth"
                );
                return self.validator.validate(token).await;
            }
        }
        // Stamped before slauth is asked: the verdict may be that old by the
        // time it is stored, never older.
        let expires_at = self.clock.now().saturating_add(self.cache_ttl.as_secs());
        let identity = self.validator.validate(token).await?;
        let entry = CachedPat::new(identity, expires_at);
        if let Err(error) = bounded(cache.set(&key, entry, self.cache_ttl)).await {
            tracing::warn!(target: AUTH_LOG_TARGET, %error, "PAT cache write failed; continuing");
        }
        Ok(identity)
    }
}

/// `op`, bounded by [`PAT_CACHE_TIMEOUT`]; running out is a cache failure.
async fn bounded<T>(op: PatCacheFuture<'_, T>) -> Result<T, PatCacheError> {
    tokio::time::timeout(PAT_CACHE_TIMEOUT, op)
        .await
        .unwrap_or_else(|_elapsed| Err(PatCacheError::new("timed out")))
}

impl CredentialVerifier for SlauthPatCredential {
    fn verify<'a>(&'a self, token: &'a str) -> VerifyFuture<'a> {
        Box::pin(async move {
            match self.identity(token).await {
                Ok(identity) => Ok(Principal::new(
                    identity.to_string(),
                    self.ceiling.iter().cloned(),
                    AuthMethod::Token,
                )),
                Err(PatValidationError::Rejected { reason }) => Err(VerifyError::invalid(reason)),
                Err(PatValidationError::Unavailable { reason }) => {
                    Err(VerifyError::unavailable(reason))
                }
            }
        })
    }
}

impl fmt::Debug for SlauthPatCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlauthPatCredential")
            // PatValidator's `Debug` redacts the validate URL.
            .field("validator", &self.validator)
            .field("ceiling", &self.ceiling)
            .field("cached", &self.cache.is_some())
            .field("cache_ttl", &self.cache_ttl)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_pythons_truncated_sha256_hex() {
        // hashlib.sha256(b"slp_live_" + b"a" * 43).hexdigest()[:32]
        let token = format!("slp_live_{}", "a".repeat(43));
        assert_eq!(pat_cache_key(&token), "161ae6aec93c7cc3df7ac7d1e7a59008");
        // `…8f 01 cf…`: a byte below 0x10 keeps its leading zero.
        assert_eq!(pat_cache_key("abc"), "ba7816bf8f01cfea414140de5dae2223");
        assert_eq!(pat_cache_key("").len(), 32);
        assert!(!pat_cache_key(&token).contains("slp_live_"));
    }

    #[test]
    fn debug_shows_the_ceiling_and_never_the_validate_url_secrets() {
        let credential = SlauthPatCredential::new(
            PatValidator::new(
                "https://auth.example/api/v1/pat/validate?key=SECRET",
                reqwest::Client::new(),
            ),
            ["image:generate"],
        );

        let debug = format!("{credential:?}");

        assert!(debug.contains("image:generate"), "{debug}");
        assert!(debug.contains("cached: false"), "{debug}");
        assert!(!debug.contains("SECRET"), "{debug}");
    }

    #[test]
    fn a_ttl_is_whole_seconds_rounded_down_from_one_second_to_a_day() {
        for (given, stored) in [
            (Duration::ZERO, 1),
            (Duration::from_millis(500), 1),
            (Duration::from_millis(2_900), 2),
            (Duration::from_secs(120), 120),
            (Duration::from_millis(120_500), 120),
            (PAT_CACHE_MAX_TTL, 86_400),
            (PAT_CACHE_MAX_TTL + Duration::from_secs(1), 86_400),
            (Duration::MAX, 86_400),
        ] {
            assert_eq!(cache_ttl_secs(given), stored, "{given:?}");
            let credential = SlauthPatCredential::new(
                PatValidator::new("http://127.0.0.1:1", reqwest::Client::new()),
                ["a"],
            )
            .with_cache_ttl(given);
            assert_eq!(
                credential.cache_ttl,
                Duration::from_secs(stored),
                "{given:?}"
            );
        }
    }

    #[test]
    fn cache_errors_render_their_reason() {
        let error = PatCacheError::new("connection refused");
        assert_eq!(error.reason(), "connection refused");
        assert_eq!(
            error.to_string(),
            "PAT cache unavailable: connection refused"
        );
    }
}
