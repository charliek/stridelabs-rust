//! The issuer's key set, cached.
//!
//! # Contract
//!
//! [`JwksCache::jwks_for_kid`] returns a [`JwkSet`] that **contains** the
//! requested `kid`, or an error. It never returns a set the caller then has to
//! re-check, and **it never returns a set past its TTL**.
//!
//! A set's *age* is the time since its last **successful** fetch. Every bound
//! below is per cache instance and read off that instance's monotonic clock.
//!
//! 1. **Fresh hit.** A set younger than its TTL ([`JWKS_TTL`], an hour) that
//!    contains the kid is served from memory.
//! 2. **Refresh ahead.** In the last tenth of the TTL (at least 60 s, at most
//!    10 min: the last 6 min at the defaults), a lookup the set answers is
//!    still served at once, and it also starts a background refresh that
//!    nobody waits on. A failed refresh is retried 1 s after it *completed*,
//!    doubling, at most the refetch floor (below), and the set keeps
//!    answering until its TTL. So an issuer blip near the hour costs nothing.
//!    Refresh-ahead needs traffic in that window, and it is off for a TTL
//!    under three floors. Without it, the first lookup at or after the TTL
//!    fetches.
//! 3. **Never past the TTL.** From the TTL on, the set answers nothing: a
//!    lookup waits for the fetch in flight, or starts one, and is refused
//!    with [`AuthError::Jwks`] if that fails. There is no stale fallback. A
//!    key the issuer retired (say, because it leaked) stops passing this
//!    cache no later than one TTL after the last successful fetch that still
//!    published it, whatever the issuer is doing. (Through v0.8.0 that bound
//!    was `ttl + min_refetch_interval`.) After a failure, the next fetch of a
//!    needed set is allowed 1 s after that failure completed, doubling to
//!    8 s; a lookup in between is refused at once, from memory ("recent fetch
//!    failed; refetch suppressed"). So once the issuer is back, recovery
//!    takes at most what is left of an attempt still failing at that moment
//!    (up to [`FETCH_TIMEOUT`]), then the backoff (up to 8 s), then one
//!    successful fetch (up to [`FETCH_TIMEOUT`]): about 28 s at the
//!    defaults, and only once a lookup arrives to start that fetch.
//! 4. **Unknown kids are rate-limited.** A set inside its TTL that lacks the
//!    kid refetches (what makes a key rotation take effect in seconds rather
//!    than an hour), but at most once per refetch floor, counted from the
//!    *start* of the last attempt of any kind. Without that floor, anyone
//!    could mint a syntactically valid token carrying a random `kid` and turn
//!    every request into an outbound HTTPS call to the issuer: a request
//!    amplifier pointed at the one service every other service depends on.
//!    Inside the floor the answer is [`AuthError::UnknownKid`] from memory, the
//!    issuer's word on which keys exist. Only a set inside its TTL gives that
//!    verdict: without one the answer is `Jwks`, because "unknown key" would
//!    blame the caller's token for this service's outage.
//!
//! The **refetch floor** `F` is `min(min_refetch_interval, max(ttl, 1 s))`:
//! [`MIN_REFETCH_INTERVAL`] (30 s) at the defaults; the TTL, when that is
//! shorter, so that a TTL of 1 s or more refetches at expiry instead of
//! waiting out an interval longer than the set lives; and never under 1 s
//! unless the interval itself is, so a zero TTL is still rate-limited. A TTL
//! under 1 s outlives nothing: from its expiry until `F` after the last
//! completed attempt, a lookup is refused ("key set expired inside the
//! minimum refetch spacing; refetch suppressed"). A zero TTL caches nothing:
//! a fetched set answers only the lookups that waited on that fetch, and
//! fetches start at most once per `F`, which is 1 s while the interval is at
//! least 1 s and the interval itself when it is shorter (zero: no limit).
//!
//! The cost of rule 4 is bounded and worth naming: a key rotation that lands
//! within the floor of the last attempt is invisible for the rest of it, so
//! tokens signed by the new key are rejected for up to 30 seconds. A failed
//! attempt counts, so a rotation that coincides with an issuer blip waits out
//! both. Issuers roll keys on the order of days.
//!
//! # Load on the issuer
//!
//! With a zero-latency failing issuer and steady traffic, one cache makes at
//! most: one unknown-kid fetch per floor against a valid set (2 a minute);
//! refresh-ahead attempts at the window's start plus 0, 1, 3, 7, 15 and 31 s,
//! then one per floor (16 in the 6-minute window at the defaults); and after
//! expiry, attempts 1, 2, 4, 8, 8 … s apart (7.5 a minute). Nobody can make
//! the two age-driven kinds happen early. Fetch latency lowers each rate,
//! because spacing runs from completion. v0.8.0 made 2 a minute;
//! stridelabs-python refetches on every request once its set has expired.
//! Replicas of one service expire, and so retry, in lockstep.
//!
//! # Concurrency
//!
//! A fetch is single-flight and runs on a tokio task of its own, so
//! cancelling the lookup that started it (a client disconnect, a request
//! timeout, a task abort) never cancels it, and no lock is held across it: a
//! fresh hit never waits behind a fetch. A lookup that needs the fetch in
//! flight joins it, with a bound of its own: [`FETCH_TIMEOUT`] plus 1 s for
//! a *first* attempt (one made with no failure since the last success),
//! which the fetch's own timeout normally ends first; 2 s for a *retry*, so
//! a black-holed issuer cannot hold every request for a whole fetch timeout
//! over and over. A joiner that reaches its bound gets `Jwks` ("JWKS refetch
//! still in progress") while the fetch carries on. A joiner checks the
//! result's age again when it resumes: a set that crossed its TTL while the
//! lookup was waiting is refused, not served (a zero TTL excepted, whose
//! whole point is serving the joiners). A herd of concurrent misses, the
//! shape a restart or a rotation produces, makes one request.
//!
//! Each bound is a timer on the joining lookup's own runtime, never on the
//! runtime hosting the fetch: it holds whatever that one is doing, including
//! when it is no longer being driven.
//!
//! **Lookups require a Tokio runtime with the time driver enabled, as
//! reqwest does** (its timeouts need it, and so do the bounds above). The
//! fetch is spawned on the runtime of the lookup that starts it, which
//! therefore needs IO and time, and which **must keep being driven until the
//! fetch ends**: a fetch on a current-thread runtime whose `block_on` has
//! returned is frozen with it, and while it is, every lookup that needs it
//! joins it and gives up at its bound, because the slot stays taken until
//! that runtime finishes the fetch or is dropped. A runtime that shuts down
//! mid-fetch drops the fetch's task; the attempt counts as a failure and its
//! waiters get `Jwks` ("refetch aborted"). Outside any tokio runtime the
//! cache does not panic: a refresh-ahead is skipped (the set answers), and a
//! lookup that would start or join a fetch is `Jwks` ("no tokio runtime to
//! fetch the JWKS on").
//!
//! # Departures from the original implementation this crate replaced
//!
//! The cache is an *instance*, not a `static OnceLock`, and it holds an
//! injected `reqwest::Client` instead of calling `reqwest::get` (which builds
//! and throws away a whole client, TLS setup included, per fetch). A global
//! meant two verifiers in one process — the shape every test that wanted an
//! isolated cache needs — silently shared one key set.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use futures_util::future::{BoxFuture, FutureExt as _, Shared};
use jsonwebtoken::jwk::JwkSet;
use tokio::sync::oneshot;
use tracing::Instrument as _;

use crate::config::redact_url;
use crate::error::AuthError;

/// How long a fetched key set is served: the most it is ever served for,
/// counted from its last successful fetch (module docs, rule 3).
pub const JWKS_TTL: Duration = Duration::from_secs(3600);

/// The floor between two fetch attempts made for an unknown kid against a
/// set inside its TTL, and the cap on the retry spacing after a failure
/// (module docs). Never longer than the TTL, and never under 1 s unless this
/// interval is: [`JwksCache::with_ttl`].
pub const MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(30);

/// Hard bound on a single JWKS fetch, connect to the end of the body. A
/// lookup that joins a first attempt waits at most this plus 1 s, so a
/// hanging issuer holds such a lookup until the attempt fails with
/// [`AuthError::Jwks`] and no longer. A lookup that joins a retry waits at
/// most 2 s (module docs, "Concurrency").
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a lookup waits on a retry, an attempt made after a failure,
/// before giving up on it while it carries on.
const RETRY_JOIN_WAIT: Duration = Duration::from_secs(2);

/// How much longer than the fetch timeout a lookup waits on a first attempt:
/// room for the fetch's own timeout to end the attempt first, so that the
/// lookup gets the attempt's real outcome, and an end to the wait if the
/// runtime hosting the fetch has stopped running it.
const FIRST_JOIN_MARGIN: Duration = Duration::from_secs(1);

/// The floor's own floor: below it only an explicitly sub-second interval
/// takes the floor (module docs).
const FLOOR_MIN: Duration = Duration::from_secs(1);

/// The refresh window is a tenth of the TTL, clamped to these.
const WINDOW_MIN: Duration = Duration::from_secs(60);
const WINDOW_MAX: Duration = Duration::from_secs(600);

/// The first retry spacing after a failure, doubling from there. Whole
/// seconds, which `Tuning::backoff` relies on.
const BACKOFF_START: Duration = Duration::from_secs(1);
const _: () = assert!(BACKOFF_START.subsec_nanos() == 0);

/// The cap on the retry spacing once the set has expired: what bounds
/// recovery after the issuer returns.
const EXPIRED_BACKOFF_MAX: Duration = Duration::from_secs(8);

/// v0.8.0's text, kept: no usable set, and a failure too recent to retry.
const SUPPRESSED: &str = "recent fetch failed; refetch suppressed";
/// No usable set and no failure: only a TTL under 1 s, whose set expires
/// inside the floor, gets here.
const TOO_SOON: &str = "key set expired inside the minimum refetch spacing; refetch suppressed";
const STILL_IN_PROGRESS: &str = "JWKS refetch still in progress";
const EXPIRED_BEFORE_USE: &str = "key set expired before the lookup could use it";
const ABORTED: &str = "refetch aborted";
const NO_RUNTIME: &str = "no tokio runtime to fetch the JWKS on";

/// A JWKS endpoint plus the last thing it said.
///
/// Cheap to share (`&self` methods only); a [`crate::Verifier`] owns one
/// inside its `Arc`, which is the intended way to hold it.
///
/// `Debug` prints the JWKS URL without its userinfo, query or fragment, as
/// [`crate::SlauthConfig`]'s does, then the tuning and the cache state (or
/// `<locked>` if another thread holds it at that instant).
pub struct JwksCache {
    tuning: Tuning,
    inner: Arc<Inner>,
}

/// What a fetch task shares with the cache, and so outlives a lookup.
struct Inner {
    jwks_url: String,
    http: reqwest::Client,
    state: Mutex<State>,
    /// Test seam: the clock is frozen at this cache's construction and moves
    /// only when a test advances it, so no scheduler pause can carry a gate
    /// past its edge, and a test carries a set through its TTL without
    /// waiting an hour. The network timeouts stay on the real clock.
    #[cfg(test)]
    clock: Mutex<Instant>,
    /// Test seam: how many upcoming fetches panic instead of fetching.
    #[cfg(test)]
    panics_left: std::sync::atomic::AtomicUsize,
}

impl fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("JwksCache");
        debug
            .field("jwks_url", &redact_url(&self.inner.jwks_url))
            // Never the client itself: reqwest::Client's Debug prints its
            // default headers, and an injected client may carry credentials.
            .field("http", &format_args!("reqwest::Client {{ .. }}"))
            .field("tuning", &self.tuning);
        // `try_lock`: a `Debug` reached while this thread holds the state (a
        // log line formatting the cache) must not deadlock on it.
        match self.inner.state.try_lock() {
            Ok(state) => debug.field("state", &*state),
            Err(TryLockError::Poisoned(poisoned)) => debug.field("state", &*poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => debug.field("state", &format_args!("<locked>")),
        };
        debug.finish()
    }
}

/// The durations of the cache contract: [`JWKS_TTL`] and
/// [`MIN_REFETCH_INTERVAL`] unless [`JwksCache::with_ttl`] or
/// [`JwksCache::with_min_refetch_interval`] replaced them, and the two
/// fetch-side bounds, which only the crate's tests replace.
///
/// Private so that consumers reach the durations through those builders,
/// never a struct literal, and another one can join without a breaking
/// change. Everything derived from them saturates or is checked, because the
/// builders take any `Duration`.
#[derive(Debug, Clone, Copy)]
struct Tuning {
    ttl: Duration,
    min_refetch_interval: Duration,
    fetch_timeout: Duration,
    /// How long a lookup waits on a first attempt: [`FETCH_TIMEOUT`] plus
    /// [`FIRST_JOIN_MARGIN`], unless a test replaced it.
    first_join_wait: Duration,
    retry_join_wait: Duration,
}

impl Default for Tuning {
    fn default() -> Tuning {
        Tuning::new(JWKS_TTL, MIN_REFETCH_INTERVAL)
    }
}

impl Tuning {
    const fn new(ttl: Duration, min_refetch_interval: Duration) -> Tuning {
        Tuning {
            ttl,
            min_refetch_interval,
            fetch_timeout: FETCH_TIMEOUT,
            first_join_wait: FETCH_TIMEOUT.saturating_add(FIRST_JOIN_MARGIN),
            retry_join_wait: RETRY_JOIN_WAIT,
        }
    }

    /// `F = min(interval, max(ttl, 1 s))` (module docs). Never longer than a
    /// TTL of 1 s or more, or the cache could not refetch a healthy issuer's
    /// set between its expiry and the floor's end. Never shorter than 1 s for
    /// a shorter TTL, or a zero TTL would turn the rate limit off.
    fn floor(&self) -> Duration {
        self.min_refetch_interval.min(self.ttl.max(FLOOR_MIN))
    }

    /// `W`: a tenth of the TTL clamped to [60 s, 10 min], and at most
    /// `ttl - floor` so that one floor of the TTL is outside it. Zero, so no
    /// refresh-ahead, unless the TTL holds three floors: a shorter TTL leaves
    /// no room for a refresh and its retry before expiry, so the first lookup
    /// after expiry fetches instead.
    fn refresh_window(&self) -> Duration {
        let floor = self.floor();
        match floor.checked_mul(3) {
            Some(three_floors) if self.ttl >= three_floors => (self.ttl / 10)
                .clamp(WINDOW_MIN, WINDOW_MAX)
                .min(self.ttl.saturating_sub(floor)),
            _ => Duration::ZERO,
        }
    }

    /// `R = ttl - W`: the age from which a lookup the set answers also
    /// starts a background refresh.
    fn refresh_at(&self) -> Duration {
        self.ttl.saturating_sub(self.refresh_window())
    }

    /// The spacing after `failures` consecutive failed or aborted attempts,
    /// from the last one's completion, while the set still answers:
    /// `min(1 s × 2^(n-1), floor)`, and the floor itself after a success.
    fn window_backoff(&self, failures: u32) -> Duration {
        self.backoff(failures, self.floor())
    }

    /// The same once the set has expired, capped at 8 s as well: the cap is
    /// what bounds recovery after the issuer returns.
    fn expired_backoff(&self, failures: u32) -> Duration {
        self.backoff(failures, self.floor().min(EXPIRED_BACKOFF_MAX))
    }

    fn backoff(&self, failures: u32, cap: Duration) -> Duration {
        let Some(doublings) = failures.checked_sub(1) else {
            return self.floor();
        };
        // 2^(n-1) whole seconds, in u64 seconds so that any cap a `Duration`
        // holds is reached exactly; only a step beyond `Duration::MAX`
        // (2^64 s and up) saturates.
        let step = 1u64
            .checked_shl(doublings)
            .and_then(|factor| BACKOFF_START.as_secs().checked_mul(factor))
            .map_or(Duration::MAX, Duration::from_secs);
        step.min(cap)
    }
}

#[derive(Default)]
struct State {
    /// The last successful fetch's set, written only by a success (never
    /// under a zero TTL), so no failed or cancelled attempt can move its age.
    cached: Option<Fetched>,
    /// The attempt in flight, if any. Cleared only by that attempt's own
    /// [`SlotGuard`], when it finishes, panics or is dropped.
    in_flight: Option<InFlight>,
    /// When the last attempt of any kind started: the unknown-kid gate.
    last_start: Option<Instant>,
    /// When the last attempt ended, success or failure: the retry gates.
    last_end: Option<Instant>,
    /// Consecutive failed or aborted attempts since the last success.
    failures: u32,
    next_id: u64,
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("State")
            .field("cached", &self.cached)
            .field("in_flight", &self.in_flight.is_some())
            .field("last_start", &self.last_start)
            .field("last_end", &self.last_end)
            .field("failures", &self.failures)
            .finish_non_exhaustive()
    }
}

impl State {
    fn holds(&self, id: u64) -> bool {
        self.in_flight.as_ref().is_some_and(|slot| slot.id == id)
    }

    /// Attempt `id` ended at `now`: clear its slot, stamp the end and count
    /// the outcome, but only while the slot still holds it, so that a stale
    /// guard can never clear or charge a newer reservation. False, with
    /// nothing changed, otherwise. The one transition out of an attempt:
    /// [`SlotGuard::complete`] and the guard's `Drop` both end here.
    fn finish(&mut self, id: u64, now: Instant, succeeded: bool) -> bool {
        if !self.holds(id) {
            return false;
        }
        self.in_flight = None;
        self.last_end = Some(now);
        self.failures = if succeeded {
            0
        } else {
            self.failures.saturating_add(1)
        };
        true
    }
}

/// One successful fetch: its set and when it completed, which is what a
/// joiner re-checks the set's age against (module docs, "Concurrency").
///
/// The set is behind an `Arc` so that handing it to a caller is a refcount
/// bump rather than a deep copy of every key — this happens on the fresh-hit
/// path, i.e. on essentially every authenticated request.
#[derive(Debug, Clone)]
struct Fetched {
    set: Arc<JwkSet>,
    fetched_at: Instant,
    /// The attempt that fetched it.
    id: u64,
}

/// One fetch attempt as every waiter sees it: the outcome its task sends,
/// shareable. A failure is its [`AuthError::Jwks`] message. A sender dropped
/// unsent (a task that panicked, or was dropped before or while running)
/// resolves it to "refetch aborted".
type Attempt = Shared<BoxFuture<'static, Result<Fetched, String>>>;

/// A new attempt's sender, and the [`Attempt`] its waiters share.
fn attempt_channel() -> (oneshot::Sender<Result<Fetched, String>>, Attempt) {
    let (sender, receiver) = oneshot::channel();
    let attempt = receiver
        .map(|sent| sent.unwrap_or_else(|_| Err(ABORTED.to_owned())))
        .boxed()
        .shared();
    (sender, attempt)
}

struct InFlight {
    id: u64,
    /// Made after a failure, so its joiners wait at most `retry_join_wait`.
    retry: bool,
    attempt: Attempt,
}

/// What a lookup does, decided under the lock from the state and the clock
/// alone (`decide`). The module docs' rules, as a table:
///
/// | the set | in flight | has the kid | gate | decision |
/// |---|---|---|---|---|
/// | `age < R` | any | yes | — | `Serve` |
/// | `R ≤ age < T` | any | yes | none in flight and `last_end + Bw(n)` | open: `ServeAndRefresh`; closed: `Serve` |
/// | `age < T` | yes | no | — | `Join` |
/// | `age < T` | no | no | `last_start + F` | open: `Start`; closed: `UnknownKid` |
/// | none, or `age ≥ T` | yes | any | — | `Join` (never the expired set) |
/// | none, or `age ≥ T` | no | any | `last_end + Bx(n)` | open: `Start`; closed: `Suppressed`, or `TooSoon` with no failure |
///
/// `T` is the TTL, `R` the age the refresh window opens at, `F` the refetch
/// floor, `Bw(n)` and `Bx(n)` the backoffs in the window and after expiry
/// ([`Tuning`]), and `n` the failure count; `Bw(0) = Bx(0) = F`.
enum Decision<'a> {
    Serve(&'a Arc<JwkSet>),
    ServeAndRefresh(&'a Arc<JwkSet>),
    Join(&'a InFlight),
    Start,
    UnknownKid,
    Suppressed,
    TooSoon,
}

/// Pure: the state, the kid, one reading of the clock and the tuning in, a
/// [`Decision`] out. Every gate is `elapsed >= spacing` on a saturating
/// `elapsed`, so no instant arithmetic can overflow, and a gate with no
/// attempt behind it is open.
fn decide<'a>(state: &'a State, kid: &str, now: Instant, tuning: &Tuning) -> Decision<'a> {
    let since =
        |at: Option<Instant>| at.map_or(Duration::MAX, |at| now.saturating_duration_since(at));
    let valid = state
        .cached
        .as_ref()
        .map(|cached| (cached, now.saturating_duration_since(cached.fetched_at)))
        .filter(|&(_, age)| age < tuning.ttl);
    match (valid, &state.in_flight) {
        (Some((cached, age)), in_flight) if cached.set.find(kid).is_some() => {
            let refresh = age >= tuning.refresh_at()
                && in_flight.is_none()
                && since(state.last_end) >= tuning.window_backoff(state.failures);
            if refresh {
                Decision::ServeAndRefresh(&cached.set)
            } else {
                Decision::Serve(&cached.set)
            }
        }
        (_, Some(in_flight)) => Decision::Join(in_flight),
        (Some(_), None) if since(state.last_start) >= tuning.floor() => Decision::Start,
        (Some(_), None) => Decision::UnknownKid,
        (None, None) if since(state.last_end) >= tuning.expired_backoff(state.failures) => {
            Decision::Start
        }
        (None, None) if state.failures == 0 => Decision::TooSoon,
        (None, None) => Decision::Suppressed,
    }
}

/// Why an attempt was started: a refresh-ahead nobody waits on, or a fetch a
/// lookup needs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    RefreshAhead,
    Needed,
}

/// A reserved attempt, not yet spawned. Built under the lock and spawned
/// only after it is released (`start`).
struct Reservation {
    handle: tokio::runtime::Handle,
    id: u64,
    retry: bool,
    attempt: Attempt,
    sender: oneshot::Sender<Result<Fetched, String>>,
}

impl JwksCache {
    /// Build a cache over `jwks_url`, fetching with `http`.
    ///
    /// The client is injected and **shared** — pass the same one the rest of
    /// the service uses, so JWKS fetches reuse its connection pool and inherit
    /// its timeouts and proxy settings.
    pub fn new(jwks_url: impl Into<String>, http: reqwest::Client) -> JwksCache {
        JwksCache {
            tuning: Tuning::default(),
            inner: Arc::new(Inner {
                jwks_url: jwks_url.into(),
                http,
                state: Mutex::new(State::default()),
                #[cfg(test)]
                clock: Mutex::new(Instant::now()),
                #[cfg(test)]
                panics_left: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    /// Replace the TTL ([`JWKS_TTL`] by default): how long a fetched set is
    /// served from memory, and the most it is ever served for, whatever the
    /// issuer is doing (module docs, rule 3).
    ///
    /// A TTL below the refetch interval lowers the refetch floor `F` with
    /// it: `F = min(interval, max(ttl, 1 s))` (module docs). A TTL of 1 s or
    /// more is refetched at expiry rather than refused for the rest of an
    /// interval it no longer lives through. A lookup on a sub-second TTL is
    /// refused from its expiry until `F` after the last completed attempt:
    /// 1 s while the interval is at least 1 s, the interval itself when it
    /// is shorter (a 100 ms TTL under a 250 ms interval: 250 ms). A zero TTL
    /// caches nothing: each fetch serves only the lookups that waited on it,
    /// and fetches start at most once per `F`.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> JwksCache {
        self.tuning.ttl = ttl;
        self
    }

    /// Replace the refetch interval ([`MIN_REFETCH_INTERVAL`] by default),
    /// which the refetch floor is derived from (module docs).
    ///
    /// For tests: the 30-second default is the contract. Zero turns all rate
    /// limiting off (every miss dials the issuer, and a failure is retried at
    /// once); a sub-second interval gives a sub-second floor; a short
    /// interval lets a test watch a floor open and close without a 30 s
    /// sleep. A production service that lowers it reopens the request
    /// amplifier rule 4 of the module docs exists to close.
    #[must_use]
    pub fn with_min_refetch_interval(mut self, interval: Duration) -> JwksCache {
        self.tuning.min_refetch_interval = interval;
        self
    }

    /// The endpoint this cache reads from.
    pub fn jwks_url(&self) -> &str {
        &self.inner.jwks_url
    }

    /// A key set containing `kid`, from memory or from the issuer, and never
    /// one past its TTL.
    ///
    /// See the module docs for when this makes a network call, and for when
    /// it waits on one. Errors are [`AuthError::UnknownKid`] (a set inside its
    /// TTL lacks the kid: just refetched, or within the refetch floor of the
    /// last attempt) or [`AuthError::Jwks`]: the endpoint could not be
    /// reached, answered non-2xx or answered with something that isn't a
    /// JWKS; or, with no set inside its TTL, a refetch is not allowed yet,
    /// the fetch this lookup joined outlasted its wait (2 s on a retry,
    /// [`FETCH_TIMEOUT`] plus 1 s on a first attempt), the set it waited for
    /// aged past its TTL first, the attempt was aborted, or there is no tokio
    /// runtime to start or wait on a fetch on.
    ///
    /// Returned behind an `Arc`: a cache hit costs a refcount bump, not a
    /// copy of the key set.
    ///
    /// # Panics
    ///
    /// Requires a Tokio runtime with the time driver enabled, as reqwest
    /// does: a lookup that has to wait on a fetch, polled on a runtime built
    /// without `enable_time`, panics in tokio's timer. Outside any runtime it
    /// never panics (module docs, "Concurrency").
    pub async fn jwks_for_kid(&self, kid: &str) -> Result<Arc<JwkSet>, AuthError> {
        let (attempt, retry) = {
            let state = self.inner.state();
            let now = self.inner.now();
            match decide(&state, kid, now, &self.tuning) {
                Decision::Serve(set) => return Ok(Arc::clone(set)),
                Decision::ServeAndRefresh(set) => {
                    let set = Arc::clone(set);
                    // No runtime: the set still answers, and the refresh
                    // waits for a lookup that has one.
                    let _nobody_waits = self.start(state, now, Purpose::RefreshAhead);
                    return Ok(set);
                }
                // A wait, like a start, needs a runtime: outside one, the
                // lookup is refused at once (module docs, "Concurrency").
                Decision::Join(_) if tokio::runtime::Handle::try_current().is_err() => {
                    return Err(AuthError::Jwks(NO_RUNTIME.into()));
                }
                Decision::Join(in_flight) => (in_flight.attempt.clone(), in_flight.retry),
                Decision::Start => {
                    let Some(joined) = self.start(state, now, Purpose::Needed) else {
                        return Err(AuthError::Jwks(NO_RUNTIME.into()));
                    };
                    joined
                }
                Decision::UnknownKid => {
                    tracing::debug!(
                        "unknown JWKS kid inside the refetch floor; refetch suppressed"
                    );
                    return Err(AuthError::UnknownKid);
                }
                Decision::Suppressed => {
                    tracing::debug!("suppressing JWKS refetch after a recent failure");
                    return Err(AuthError::Jwks(SUPPRESSED.into()));
                }
                Decision::TooSoon => {
                    tracing::debug!("suppressing JWKS refetch inside the minimum spacing");
                    return Err(AuthError::Jwks(TOO_SOON.into()));
                }
            }
        };

        // Every wait has a bound of its own, on this lookup's runtime (it has
        // one: both arms above that reach here checked). Not the fetch's own
        // timeout alone: that fires only while the runtime hosting the fetch
        // is being driven, and this lookup may be on another runtime.
        let wait = if retry {
            self.tuning.retry_join_wait
        } else {
            self.tuning.first_join_wait
        };
        match tokio::time::timeout(wait, attempt).await {
            Ok(outcome) => self.resolve(outcome, kid),
            Err(_) => {
                tracing::debug!("JWKS fetch still in flight; this lookup stops waiting on it");
                Err(AuthError::Jwks(STILL_IN_PROGRESS.into()))
            }
        }
    }

    /// What a lookup that waited on an attempt gets from it (module docs,
    /// "Concurrency").
    fn resolve(
        &self,
        outcome: Result<Fetched, String>,
        kid: &str,
    ) -> Result<Arc<JwkSet>, AuthError> {
        let fetched = outcome.map_err(AuthError::Jwks)?;
        // The clock is read again, under the lock like every reading the
        // gates use: the set may have crossed its TTL while this lookup was
        // waiting (or before a slow caller polled it again), and rule 3 is
        // about the moment the set is handed out. A zero TTL serves its
        // joiners by definition.
        let usable = {
            let _state = self.inner.state();
            let age = self
                .inner
                .now()
                .saturating_duration_since(fetched.fetched_at);
            self.tuning.ttl.is_zero() || age < self.tuning.ttl
        };
        if !usable {
            tracing::debug!(
                attempt = fetched.id,
                "JWKS set expired before the lookup that waited for it could use it"
            );
            return Err(AuthError::Jwks(EXPIRED_BEFORE_USE.into()));
        }
        match fetched.set.find(kid) {
            Some(_) => Ok(fetched.set),
            None => Err(AuthError::UnknownKid),
        }
    }

    /// Reserve the slot for a new attempt, under the lock. `None`, with
    /// nothing changed, outside a tokio runtime.
    fn reserve(&self, state: &mut State, now: Instant) -> Option<Reservation> {
        let handle = tokio::runtime::Handle::try_current().ok()?;
        let id = state.next_id;
        state.next_id = id.wrapping_add(1);
        let retry = state.failures > 0;
        let (sender, attempt) = attempt_channel();
        state.in_flight = Some(InFlight {
            id,
            retry,
            attempt: attempt.clone(),
        });
        state.last_start = Some(now);
        Some(Reservation {
            handle,
            id,
            retry,
            attempt,
            sender,
        })
    }

    /// Start an attempt: reserve the slot, release the lock, spawn the
    /// fetch, and return what a lookup joins (the attempt, and whether it is
    /// a retry). `None`, with nothing changed, outside a tokio runtime.
    ///
    /// The lock is taken by value so that it is always released before the
    /// spawn: nothing that runs a guard's drop — a runtime that drops the
    /// task on the spot because it is shutting down — can then do so while
    /// this thread holds the lock the guard takes. There is no await between
    /// the reservation and the spawn, so no cancellation can strand a slot.
    fn start(
        &self,
        mut state: MutexGuard<'_, State>,
        now: Instant,
        purpose: Purpose,
    ) -> Option<(Attempt, bool)> {
        let Reservation {
            handle,
            id,
            retry,
            attempt,
            sender,
        } = self.reserve(&mut state, now)?;
        drop(state);
        // The guard exists before the task does, so even a task dropped
        // before its first poll clears the slot it reserved.
        let guard = SlotGuard {
            inner: Arc::clone(&self.inner),
            id,
            sender: Some(sender),
            cache_success: !self.tuning.ttl.is_zero(),
            purpose,
        };
        // A needed fetch logs inside the request that waits on it. A
        // refresh-ahead belongs to no request: the one that triggered it has
        // already been answered.
        let span = match purpose {
            Purpose::Needed => tracing::Span::current(),
            Purpose::RefreshAhead => tracing::Span::none(),
        };
        drop(handle.spawn(run(guard, self.tuning.fetch_timeout).instrument(span)));
        Some((attempt, retry))
    }

    /// Test seam: move this cache's clock forward.
    #[cfg(test)]
    pub(crate) fn advance_for_test(&self, by: Duration) {
        *self
            .inner
            .clock
            .lock()
            .unwrap_or_else(PoisonError::into_inner) += by;
    }

    /// Test seam: wait for the attempt in flight, if any, to finish, so that
    /// a test asserts on the state after spawned work and not during it. The
    /// state is final when its outcome arrives: a guard updates the state
    /// before it sends, and clears the slot before an abort is seen.
    #[cfg(test)]
    pub(crate) async fn settle(&self) {
        let attempt = self
            .inner
            .state()
            .in_flight
            .as_ref()
            .map(|in_flight| in_flight.attempt.clone());
        if let Some(attempt) = attempt {
            let _outcome = attempt.await;
        }
    }
}

/// Attempt `guard.id`, on its own task: no caller's cancellation reaches it.
async fn run(guard: SlotGuard, timeout: Duration) {
    #[cfg(test)]
    guard.inner.panic_if_asked();
    let result = guard.inner.fetch(timeout).await;
    guard.complete(result);
}

/// Attempt `id`'s claim on the in-flight slot, and the only way its outcome
/// reaches the waiters.
///
/// Created before the task is spawned and moved into it, so it is dropped
/// however the task ends — completed, panicked, or dropped by the runtime
/// before its first poll or at shutdown. It touches the state only while the
/// slot still holds attempt `id`, so a stale guard can never clear or charge
/// a newer reservation. It is never dropped while this thread holds the
/// state lock: [`JwksCache::start`] spawns only after releasing it, and
/// [`SlotGuard::complete`] releases it before returning.
struct SlotGuard {
    inner: Arc<Inner>,
    id: u64,
    /// `None` once [`SlotGuard::complete`] has sent the outcome.
    sender: Option<oneshot::Sender<Result<Fetched, String>>>,
    /// False under a zero TTL, which caches nothing.
    cache_success: bool,
    purpose: Purpose,
}

impl SlotGuard {
    /// Record the outcome and clear the slot in one critical section, then
    /// hand the outcome to the waiters.
    fn complete(mut self, result: Result<JwkSet, AuthError>) {
        let outcome = {
            let mut state = self.inner.state();
            let now = self.inner.now();
            let outcome = match result {
                Ok(set) => Ok(Fetched {
                    set: Arc::new(set),
                    fetched_at: now,
                    id: self.id,
                }),
                Err(AuthError::Jwks(message)) => Err(message),
                Err(other) => Err(other.to_string()),
            };
            if state.finish(self.id, now, outcome.is_ok()) && self.cache_success {
                if let Ok(fetched) = &outcome {
                    // Replace rather than merge: a rotation that *retires* a
                    // key must actually retire it here too.
                    state.cached = Some(fetched.clone());
                }
            }
            outcome
        };
        if self.purpose == Purpose::RefreshAhead {
            if let Err(message) = &outcome {
                // The message is URL-free (`fetch` renders every error
                // `without_url()`), and nothing here names a kid or a token.
                tracing::warn!(
                    error = %message,
                    "JWKS refresh-ahead failed; the cached set answers until its TTL"
                );
            }
        }
        if let Some(sender) = self.sender.take() {
            // Every waiter may be gone; the state is updated either way.
            let _ = sender.send(outcome);
        }
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        // A no-op after `complete`; otherwise the attempt was aborted (a
        // panic, a task dropped before or while running) and counts as a
        // failure, stamped now, so the retry gates still apply.
        if self.sender.is_none() {
            return;
        }
        {
            let mut state = self.inner.state();
            let now = self.inner.now();
            state.finish(self.id, now, false);
        }
        tracing::debug!("JWKS fetch attempt aborted");
        // Dropped only now, with the slot clear: a waiter woken by it finds
        // the state final.
        drop(self.sender.take());
    }
}

impl Inner {
    /// The cache state. A std mutex: it is never held across an await, and a
    /// panic while holding it cannot leave the state half-written.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The clock every gate reads. Called with the state lock held, so that
    /// the instants a lookup compares and the ones a completion writes are
    /// ordered by the lock.
    fn now(&self) -> Instant {
        #[cfg(test)]
        {
            *self.clock.lock().unwrap_or_else(PoisonError::into_inner)
        }
        #[cfg(not(test))]
        {
            Instant::now()
        }
    }

    #[cfg(test)]
    fn panic_if_asked(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        if self
            .panics_left
            .fetch_update(SeqCst, SeqCst, |left| left.checked_sub(1))
            .is_ok()
        {
            panic!("injected JWKS fetch panic");
        }
    }

    async fn fetch(&self, timeout: Duration) -> Result<JwkSet, AuthError> {
        // Per-request timeout, because a lookup that joined a first attempt
        // waits for it: without a bound, a hanging issuer would hold those
        // lookups until the socket died on its own. reqwest::Client has NO
        // default timeout, and we can't assume the injected client configured
        // one.
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
            .timeout(timeout)
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
mod tests;
