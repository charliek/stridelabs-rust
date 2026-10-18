//! Per-caller rate limiting: the seam [`ToolCall`](crate::ToolCall) calls,
//! and the implementations that need no infrastructure.
//!
//! A tool opts in with [`ToolCall::rate_limit`](crate::ToolCall::rate_limit),
//! naming a [`RateLimiter`] and its [`RateClass`]. The boundary calls
//! [`RateLimiter::check`] with the principal's subject and that class **after**
//! the scope check (a call refused for its scopes consumes nothing, as in
//! Python) and **inside** the call's cancellation, timeout and panic capture,
//! together with the body: a limiter that hangs is bounded by the tool's
//! deadline, one that panics is an internal error, and a cancelled request
//! stops waiting for it. (Python's timeout covered the body alone; this is a
//! deliberate broadening.)
//!
//! Classes are the app's vocabulary — imgmcp's `generate`, Python's `read` /
//! `write` / `cover` — so [`RateClass`] is an open newtype, not an enum.
//!
//! - [`NoLimit`] never limits.
//! - [`MemoryLimiter`] is Python `enforce_rate_limit`'s fixed one-minute
//!   window held in process memory — plus, through
//!   [`MemoryLimiter::from_limits`], a fixed UTC-day window: right for tests,
//!   and for a service that runs as one instance.
//! - `RedisRateLimiter` (feature `redis`) shares the same windows across
//!   instances through Redis, and fails open when Redis does.
//!
//! # Windows
//!
//! A limit is a ceiling per [`Window`]: a [`RateLimit`] names the class, the
//! window and the ceiling. Every window is **fixed and aligned to the Unix
//! epoch** — [`Window::Minute`] is `unix_seconds / 60` (Python's), and
//! [`Window::Day`] is `unix_seconds / 86_400`, the UTC day, which resets at
//! 00:00 UTC (Unix time has no leap seconds, so every day is 86 400 s). A
//! class may have both: imgmcp's `generate` is 6 a minute and 30 a day.
//!
//! One check of a class with several windows reads the clock **once** (no
//! call is counted in one day's minute and the next day's day), then counts
//! the call in each window, **shortest first**, and stops at the first one it
//! exceeds. So a call counts in every window up to and including the one
//! that refused it, and in no longer one: a burst refused by the minute
//! window does not spend the day, while a call the day refuses still counts
//! in the minute (it got that far). Within one window the behaviour is
//! Python's: every call counts, a refused one included, as Redis's `INCR`
//! does.
//!
//! # Refusal versus failure
//!
//! Every `Err` a limiter returns is a refusal, shown to the model as the
//! [`RateLimited`] text: the boundary never second-guesses one. What a
//! limiter does when its own store fails is the implementation's policy, so
//! it is decided there, not here — `RedisRateLimiter` logs a warning and
//! allows the call (a limiter blip must not take the whole MCP surface down).

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

/// The `tracing` target of the limiters' own log lines (a fail-open warning).
pub const RATE_LIMIT_LOG_TARGET: &str = "stridelabs.mcp.ratelimit";

/// A rate-limit bucket, named by the app.
///
/// The name appears in the refusal ("Rate limit exceeded for {class}
/// operations …") and in a Redis key, so keep it a plain lowercase word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RateClass(pub &'static str);

impl RateClass {
    /// Python's bucket for cheap, read-only tools.
    pub const READ: RateClass = RateClass("read");
    /// Python's bucket for tools that change state.
    pub const WRITE: RateClass = RateClass("write");

    /// The class's name.
    pub fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for RateClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// The fixed window a [`RateLimit`] counts in, aligned to the Unix epoch
/// (see [the module docs](self#windows)).
///
/// `#[non_exhaustive]`: a longer or shorter window may be added. The
/// variants are declared, and ordered, shortest first; the limiters sort a
/// class's windows by [`Window::secs`] whatever order they were given in.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Window {
    /// `unix_seconds / 60`: Python `enforce_rate_limit`'s window.
    Minute,
    /// `unix_seconds / 86_400`: the UTC day, from 00:00 UTC to 00:00 UTC.
    /// It has no Python ancestor.
    Day,
}

impl Window {
    /// The window's length in seconds: 60, or 86 400.
    pub const fn secs(self) -> u64 {
        match self {
            Window::Minute => 60,
            Window::Day => 86_400,
        }
    }

    /// The window's name, `minute` or `day`: what a refusal says ("per
    /// day") and a fail-open warning's `window` field.
    pub const fn as_str(self) -> &'static str {
        match self {
            Window::Minute => "minute",
            Window::Day => "day",
        }
    }
}

impl fmt::Display for Window {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// At most `limit` calls per subject in `class` per `window`. A limit of 0
/// turns that window off for the class (it is not counted).
///
/// Built with [`RateLimit::per_minute`] or [`RateLimit::per_day`];
/// `#[non_exhaustive]` so a later field (a window offset, say) is not a
/// breaking change. The fields stay readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateLimit {
    /// The bucket.
    pub class: RateClass,
    /// The window the ceiling applies to.
    pub window: Window,
    /// The ceiling; 0 is off.
    pub limit: u32,
}

impl RateLimit {
    /// `limit` calls per minute in `class`.
    pub const fn per_minute(class: RateClass, limit: u32) -> RateLimit {
        RateLimit {
            class,
            window: Window::Minute,
            limit,
        }
    }

    /// `limit` calls per UTC day in `class`.
    pub const fn per_day(class: RateClass, limit: u32) -> RateLimit {
        RateLimit {
            class,
            window: Window::Day,
            limit,
        }
    }
}

/// A caller exceeded its limit for a class in one window.
///
/// `Display` is the text the tool boundary returns to the model as the
/// call's error:
///
/// - [`Window::Minute`] — Python's text, byte for byte: "Rate limit exceeded
///   for {class} operations ({limit} per minute). Retry in
///   {retry_after_secs} seconds."
/// - [`Window::Day`] — "Rate limit exceeded for {class} operations ({limit}
///   per day). The limit resets at 00:00 UTC, in {H} h {M} min.", where the
///   time left, `retry_after_secs`, is rounded **up** to whole minutes (one
///   second left reads "0 h 1 min", a whole day "24 h 0 min"), so the
///   reset is never sooner than it says.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateLimited {
    /// The class whose limit was exceeded.
    pub class: RateClass,
    /// That class's ceiling in [`RateLimited::window`].
    pub limit: u32,
    /// Seconds until the current window ends (for a day: until 00:00 UTC).
    pub retry_after_secs: u64,
    /// The window whose ceiling was exceeded.
    pub window: Window,
}

impl RateLimited {
    /// A per-minute refusal for `class`, whose ceiling is `limit` calls per
    /// minute, with `retry_after_secs` left in the window.
    pub fn new(class: RateClass, limit: u32, retry_after_secs: u64) -> RateLimited {
        RateLimited::in_window(class, Window::Minute, limit, retry_after_secs)
    }

    /// A refusal for `class`, whose ceiling is `limit` calls per `window`,
    /// with `retry_after_secs` left in the window.
    ///
    /// The day text names 00:00 UTC as the reset, because [`Window::Day`]
    /// *is* the UTC day (`unix_seconds / 86_400`): pass the seconds left until
    /// then.
    pub fn in_window(
        class: RateClass,
        window: Window,
        limit: u32,
        retry_after_secs: u64,
    ) -> RateLimited {
        RateLimited {
            class,
            limit,
            retry_after_secs,
            window,
        }
    }
}

impl fmt::Display for RateLimited {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let RateLimited {
            class,
            limit,
            retry_after_secs,
            window,
        } = self;
        match window {
            Window::Minute => write!(
                f,
                "Rate limit exceeded for {class} operations ({limit} per minute). \
                 Retry in {retry_after_secs} seconds."
            ),
            Window::Day => {
                // Rounded up: "0 h 0 min" would tell the caller to retry now.
                let minutes = retry_after_secs.div_ceil(60);
                write!(
                    f,
                    "Rate limit exceeded for {class} operations ({limit} per day). \
                     The limit resets at 00:00 UTC, in {} h {} min.",
                    minutes / 60,
                    minutes % 60
                )
            }
        }
    }
}

impl std::error::Error for RateLimited {}

/// The future a [`RateLimiter`] returns.
pub type LimitFuture<'a> = Pin<Box<dyn Future<Output = Result<(), RateLimited>> + Send + 'a>>;

/// Counts a call against `(subject, class)` and refuses it once the class's
/// limit is exceeded. Object-safe, like [`CredentialVerifier`](crate::CredentialVerifier):
/// a [`ToolCall`](crate::ToolCall) holds one as `Arc<dyn RateLimiter>`.
///
/// Return `Err` only for a definite refusal: the boundary shows every `Err`
/// to the model as the [`RateLimited`] text. A limiter backed by a store
/// that can fail decides itself what a failure means; failing open (allow,
/// and log a warning) is the house policy, so that a store blip cannot lock
/// every user out.
///
/// `UnwindSafe + RefUnwindSafe` because a [`ToolCall`](crate::ToolCall)
/// holding one stays both (its auto traits are part of its API). A limiter
/// whose state a panic cannot leave half-updated — a counter behind a
/// `Mutex`, a handle that recovers from a failed command — can assert so
/// with `impl UnwindSafe`/`impl RefUnwindSafe`, as `RedisRateLimiter` does.
pub trait RateLimiter: Send + Sync + UnwindSafe + RefUnwindSafe + 'static {
    /// Count one call by `subject` in `class`, and refuse it if that takes
    /// the class over its limit.
    fn check<'a>(&'a self, subject: &'a str, class: RateClass) -> LimitFuture<'a>;
}

/// Never limits.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoLimit;

impl RateLimiter for NoLimit {
    fn check<'a>(&'a self, _subject: &'a str, _class: RateClass) -> LimitFuture<'a> {
        Box::pin(std::future::ready(Ok(())))
    }
}

/// The ceilings a limiter enforces: per class, its windows that are on,
/// shortest first. A class with no entry, or only entries of 0, is not
/// limited — and not counted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Limits(BTreeMap<RateClass, Vec<(Window, u32)>>);

impl Limits {
    /// `limits` as given; for a repeated `(class, window)`, the last entry
    /// wins — a final 0 included, which turns that window off.
    pub(crate) fn new<I>(limits: I) -> Limits
    where
        I: IntoIterator<Item = RateLimit>,
    {
        let mut latest = BTreeMap::new();
        for limit in limits {
            latest.insert((limit.class, limit.window), limit.limit);
        }
        let mut by_class: BTreeMap<RateClass, Vec<(Window, u32)>> = BTreeMap::new();
        for ((class, window), limit) in latest {
            if limit > 0 {
                by_class.entry(class).or_default().push((window, limit));
            }
        }
        for windows in by_class.values_mut() {
            windows.sort_by_key(|&(window, _)| window.secs());
        }
        Limits(by_class)
    }

    /// Per-minute ceilings, as the `new` constructors take them.
    pub(crate) fn per_minute<I>(limits: I) -> Limits
    where
        I: IntoIterator<Item = (RateClass, u32)>,
    {
        Limits::new(
            limits
                .into_iter()
                .map(|(class, limit)| RateLimit::per_minute(class, limit)),
        )
    }

    /// `class`'s windows that are on, shortest first, with their ceilings;
    /// empty when the class is not limited.
    pub(crate) fn of(&self, class: RateClass) -> &[(Window, u32)] {
        self.0.get(&class).map_or(&[], Vec::as_slice)
    }
}

/// Unix seconds, from the system clock or a test's. The closure must be
/// unwind-safe itself (it is held by a limiter that is), rather than asserted
/// to be: a clock that shares state with something else says so in its type.
#[derive(Clone)]
pub(crate) struct Clock(Arc<dyn Fn() -> u64 + Send + Sync + UnwindSafe + RefUnwindSafe>);

impl Clock {
    pub(crate) fn system() -> Clock {
        Clock(Arc::new(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs())
        }))
    }

    pub(crate) fn from_fn(
        now: impl Fn() -> u64 + Send + Sync + UnwindSafe + RefUnwindSafe + 'static,
    ) -> Clock {
        Clock(Arc::new(now))
    }

    pub(crate) fn now(&self) -> u64 {
        (self.0)()
    }
}

/// The refusal for a hit that took `class`'s count in `window` over
/// `limit`, at `now`: the retry hint is what is left of that window.
pub(crate) fn refusal(class: RateClass, window: Window, limit: u32, now: u64) -> RateLimited {
    let secs = window.secs();
    RateLimited::in_window(class, window, limit, secs - now % secs)
}

/// An in-process fixed-window limiter: at most `limit` calls per
/// `(subject, class)` per window — Python `enforce_rate_limit`'s minute,
/// held in memory instead of Redis, and optionally a UTC day.
///
/// - [`MemoryLimiter::new`] takes per-minute ceilings, as before;
///   [`MemoryLimiter::from_limits`] takes [`RateLimit`]s in any window.
/// - A class with no configured limit, or a limit of 0, is not limited (and
///   not counted) in that window.
/// - A class's windows are checked shortest first, from **one** clock
///   reading, and the check stops at the first refusal (see
///   [the module docs](self#windows)). Within a window every call counts, a
///   refused one included, as Redis's `INCR` does.
/// - Windows are fixed, not sliding: two calls a second apart across a
///   boundary are in different windows, and a refusal's `retry_after_secs`
///   is what is left of the current one.
/// - **Windows only move forward**, each on its own. The clock is read
///   inside the one `Mutex`, and a reading from an earlier window than the
///   newest one of that length seen (a clock stepped backwards, or a check
///   that was delayed) counts against the newest window: it never reopens an
///   old one, and never resets the current one's counts.
/// - **A window's counts are dropped when it moves forward** — the minute's
///   every minute, the day's at 00:00 UTC — so memory is bounded by the
///   subjects active within one window of the longest length configured.
/// - Every check is one short critical section covering all of the class's
///   windows, so concurrent calls never over-admit in any of them. Counts are
///   `u64`, so even a limit of `u32::MAX` refuses the call after it.
///
/// Its state lives in the limiter, so share **one** across a service's
/// stateless handler instances (an `Arc<dyn RateLimiter>` in the app state,
/// cloned into each).
pub struct MemoryLimiter {
    limits: Limits,
    clock: Clock,
    windows: Mutex<HashMap<Window, Counts>>,
}

/// One window length's state.
#[derive(Default)]
struct Counts {
    /// The newest window of this length any check has read the clock in.
    index: u64,
    counts: HashMap<(String, RateClass), u64>,
}

impl MemoryLimiter {
    /// A limiter with these per-class ceilings, in calls per minute; 0 or an
    /// absent class is unlimited: the same limiter as
    /// [`MemoryLimiter::from_limits`] with [`RateLimit::per_minute`]
    /// entries.
    pub fn new<I>(limits: I) -> MemoryLimiter
    where
        I: IntoIterator<Item = (RateClass, u32)>,
    {
        MemoryLimiter::with_limits(Limits::per_minute(limits))
    }

    /// A limiter with these ceilings, each in its own window:
    ///
    /// ```
    /// use stridelabs_mcp::{MemoryLimiter, RateClass, RateLimit};
    ///
    /// const GENERATE: RateClass = RateClass("generate");
    /// let _ = MemoryLimiter::from_limits([
    ///     RateLimit::per_minute(RateClass::READ, 60),
    ///     RateLimit::per_minute(GENERATE, 6),
    ///     RateLimit::per_day(GENERATE, 30),
    /// ]);
    /// ```
    ///
    /// For a repeated `(class, window)`, the last entry wins; a limit of 0
    /// (the last one included) turns that window off for the class.
    pub fn from_limits<I>(limits: I) -> MemoryLimiter
    where
        I: IntoIterator<Item = RateLimit>,
    {
        MemoryLimiter::with_limits(Limits::new(limits))
    }

    fn with_limits(limits: Limits) -> MemoryLimiter {
        MemoryLimiter {
            limits,
            clock: Clock::system(),
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Replace the clock (Unix seconds), so a test can place calls in a
    /// window and roll it over without sleeping.
    ///
    /// The closure must be `UnwindSafe + RefUnwindSafe` (the limiter is, and
    /// a [`ToolCall`](crate::ToolCall) holding it must stay so): a closure
    /// over an atomic, a `Mutex` or plain data is; one over a type-erased
    /// `dyn Fn` is not, and does not compile:
    ///
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stridelabs_mcp::MemoryLimiter;
    ///
    /// let erased: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 0);
    /// let _ = MemoryLimiter::new([]).with_clock(move || erased());
    /// ```
    ///
    /// ```
    /// use std::sync::atomic::{AtomicU64, Ordering};
    /// use std::sync::Arc;
    /// use stridelabs_mcp::MemoryLimiter;
    ///
    /// let now = Arc::new(AtomicU64::new(1_760_000_000));
    /// let read = Arc::clone(&now);
    /// let _ = MemoryLimiter::new([]).with_clock(move || read.load(Ordering::SeqCst));
    /// ```
    #[must_use]
    pub fn with_clock(
        mut self,
        now: impl Fn() -> u64 + Send + Sync + UnwindSafe + RefUnwindSafe + 'static,
    ) -> MemoryLimiter {
        self.clock = Clock::from_fn(now);
        self
    }

    fn hit(&self, subject: &str, class: RateClass) -> Result<(), RateLimited> {
        let limits = self.limits.of(class);
        if limits.is_empty() {
            return Ok(());
        }
        // A panic elsewhere while holding the lock cannot have left a count
        // half-updated (each update is one `+= 1`), so poison says nothing
        // about them.
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        // Read once, inside the lock: readings are applied in the order they
        // were taken, and every window of this check sees the same instant.
        let now = self.clock.now();
        for &(window, limit) in limits {
            let state = windows.entry(window).or_default();
            let index = now / window.secs();
            if index > state.index {
                state.index = index;
                state.counts.clear();
            }
            // An older reading (a backwards clock) counts against the newest
            // window, and its retry hint runs to that window's end.
            let now = now.max(state.index * window.secs());
            let count = state.counts.entry((subject.to_owned(), class)).or_insert(0);
            *count = count.saturating_add(1);
            if *count > u64::from(limit) {
                // Not counted in any longer window.
                return Err(refusal(class, window, limit, now));
            }
        }
        Ok(())
    }
}

impl RateLimiter for MemoryLimiter {
    fn check<'a>(&'a self, subject: &'a str, class: RateClass) -> LimitFuture<'a> {
        Box::pin(std::future::ready(self.hit(subject, class)))
    }
}

impl fmt::Debug for MemoryLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryLimiter")
            .field("limits", &self.limits.0)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    const GENERATE: RateClass = RateClass("generate");

    /// 1_760_000_000 is 32 000 s into its UTC day (and 20 s into its
    /// minute): 54 400 s, rounded up 15 h 7 min, are left of the day.
    const NOW: u64 = 1_760_000_000;
    const DAY: u64 = 86_400;

    /// A clock the test moves.
    fn clock(start: u64) -> (Arc<AtomicU64>, impl Fn() -> u64 + Send + Sync + 'static) {
        let now = Arc::new(AtomicU64::new(start));
        let read = Arc::clone(&now);
        (now, move || read.load(Ordering::SeqCst))
    }

    /// `(subject, class)`'s count in `window`, if it has one.
    fn count(
        limiter: &MemoryLimiter,
        window: Window,
        subject: &str,
        class: RateClass,
    ) -> Option<u64> {
        let windows = limiter.windows.lock().unwrap();
        windows
            .get(&window)
            .and_then(|state| state.counts.get(&(subject.to_owned(), class)))
            .copied()
    }

    /// The `(subject, class)` entries counted in `window`, sorted.
    fn entries(limiter: &MemoryLimiter, window: Window) -> Vec<(String, RateClass)> {
        let windows = limiter.windows.lock().unwrap();
        let mut keys: Vec<_> = windows
            .get(&window)
            .map(|state| state.counts.keys().cloned().collect())
            .unwrap_or_default();
        keys.sort();
        keys
    }

    /// The newest index `window` has seen.
    fn index(limiter: &MemoryLimiter, window: Window) -> Option<u64> {
        let windows = limiter.windows.lock().unwrap();
        windows.get(&window).map(|state| state.index)
    }

    fn block_on_check(
        limiter: &MemoryLimiter,
        subject: &str,
        class: RateClass,
    ) -> Result<(), RateLimited> {
        futures::executor::block_on(limiter.check(subject, class))
    }

    #[tokio::test]
    async fn trips_after_the_limit_with_pythons_text_and_retry_hint() {
        // 100_040 is 20 s into its minute, so 40 s remain.
        let (_, now) = clock(100_040);
        let limiter = MemoryLimiter::new([(GENERATE, 2)]).with_clock(now);

        limiter.check("a", GENERATE).await.expect("first");
        limiter.check("a", GENERATE).await.expect("second");
        let refused = limiter.check("a", GENERATE).await.unwrap_err();

        assert_eq!(refused, RateLimited::new(GENERATE, 2, 40));
        assert_eq!(refused.window, Window::Minute);
        assert_eq!(
            refused.to_string(),
            "Rate limit exceeded for generate operations (2 per minute). Retry in 40 seconds."
        );
    }

    #[tokio::test]
    async fn buckets_are_per_subject_and_per_class() {
        let limiter = MemoryLimiter::new([(RateClass::READ, 1), (RateClass::WRITE, 1)]);

        limiter.check("a", RateClass::READ).await.expect("a's read");
        assert!(limiter.check("a", RateClass::READ).await.is_err());
        // B is untouched by A's overage, and A's write bucket by its reads.
        limiter.check("b", RateClass::READ).await.expect("b's read");
        limiter
            .check("a", RateClass::WRITE)
            .await
            .expect("a's write");
    }

    #[tokio::test]
    async fn the_window_resets_when_the_minute_rolls_over() {
        let (now, read) = clock(100_000);
        let limiter = MemoryLimiter::new([(RateClass::READ, 1)]).with_clock(read);
        limiter.check("a", RateClass::READ).await.expect("first");
        assert!(limiter.check("a", RateClass::READ).await.is_err());

        now.fetch_add(61, Ordering::SeqCst);
        limiter
            .check("a", RateClass::READ)
            .await
            .expect("a new window");
    }

    #[tokio::test]
    async fn the_window_is_the_wall_clock_minute_not_a_sliding_one() {
        // Two calls a second apart across a minute boundary are in different
        // windows (Python's `now // 60`), and a refusal right at a window's
        // start waits the whole minute.
        let (now, read) = clock(119);
        let limiter = MemoryLimiter::new([(RateClass::READ, 1)]).with_clock(read);
        limiter.check("a", RateClass::READ).await.expect("window 1");
        now.store(120, Ordering::SeqCst);
        limiter.check("a", RateClass::READ).await.expect("window 2");

        let refused = limiter.check("a", RateClass::READ).await.unwrap_err();
        assert_eq!(refused.retry_after_secs, 60);
    }

    #[tokio::test]
    async fn refused_calls_count_too() {
        let (now, read) = clock(600);
        let limiter = MemoryLimiter::new([(RateClass::READ, 1)]).with_clock(read);
        for _ in 0..3 {
            let _ = limiter.check("a", RateClass::READ).await;
        }
        assert_eq!(
            count(&limiter, Window::Minute, "a", RateClass::READ),
            Some(3)
        );
        now.fetch_add(60, Ordering::SeqCst);
        limiter
            .check("a", RateClass::READ)
            .await
            .expect("next window");
    }

    #[tokio::test]
    async fn expired_entries_are_dropped_when_the_window_rolls_over() {
        let (now, read) = clock(6_000);
        let limiter = MemoryLimiter::new([(RateClass::READ, 5)]).with_clock(read);
        for subject in ["a", "b", "c"] {
            limiter
                .check(subject, RateClass::READ)
                .await
                .expect("under");
        }
        assert_eq!(entries(&limiter, Window::Minute).len(), 3);

        now.fetch_add(60, Ordering::SeqCst);
        limiter.check("d", RateClass::READ).await.expect("under");

        assert_eq!(
            entries(&limiter, Window::Minute),
            [("d".to_owned(), RateClass::READ)]
        );
    }

    #[tokio::test]
    async fn a_zero_or_absent_limit_never_limits_and_counts_nothing() {
        let limiter = MemoryLimiter::new([(GENERATE, 0)]);
        for _ in 0..50 {
            limiter.check("a", GENERATE).await.expect("0 is unlimited");
            limiter
                .check("a", RateClass::READ)
                .await
                .expect("absent is unlimited");
        }
        assert!(
            limiter.windows.lock().unwrap().is_empty(),
            "unlimited classes are not counted"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_calls_never_over_admit() {
        let (_, read) = clock(1_000_020);
        let limiter = Arc::new(MemoryLimiter::new([(GENERATE, 50)]).with_clock(read));

        let calls: Vec<_> = (0..400)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                tokio::spawn(async move { limiter.check("a", GENERATE).await.is_ok() })
            })
            .collect();
        let mut admitted = 0;
        for call in calls {
            if call.await.expect("no panic") {
                admitted += 1;
            }
        }

        assert_eq!(admitted, 50);
        assert_eq!(count(&limiter, Window::Minute, "a", GENERATE), Some(400));
    }

    /// A clock answering `readings` in the order it is called.
    fn scripted<const N: usize>(
        readings: [u64; N],
    ) -> impl Fn() -> u64 + Send + Sync + UnwindSafe + RefUnwindSafe {
        let calls = AtomicU64::new(0);
        move || {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            readings[usize::try_from(call).expect("a small count")]
        }
    }

    #[test]
    fn a_check_stalled_reading_the_clock_cannot_reopen_the_previous_minute() {
        use std::sync::atomic::AtomicBool;
        use std::sync::mpsc;

        // The reviewer's interleaving: A reads 119 (minute 1) and stalls; B
        // reads 120 (minute 2); A resumes; C reads 120. The clock's first
        // call (A's) waits until the test releases it.
        let (entered, a_is_reading) = mpsc::channel::<()>();
        let (release, released) = mpsc::channel::<()>();
        let gate = Mutex::new((entered, released));
        let readings = scripted([119, 120, 120]);
        let first = AtomicBool::new(true);
        let clock = move || {
            if first.swap(false, Ordering::SeqCst) {
                let gate = gate.lock().unwrap();
                gate.0.send(()).unwrap();
                gate.1.recv().unwrap();
            }
            readings()
        };
        let limiter = Arc::new(MemoryLimiter::new([(RateClass::READ, 1)]).with_clock(clock));
        let check = |limiter: &MemoryLimiter| block_on_check(limiter, "s", RateClass::READ);

        let a = std::thread::spawn({
            let limiter = Arc::clone(&limiter);
            move || check(&limiter)
        });
        a_is_reading.recv().expect("A reads the clock");
        let b_done = Arc::new(AtomicBool::new(false));
        let b = std::thread::spawn({
            let (limiter, done) = (Arc::clone(&limiter), Arc::clone(&b_done));
            move || {
                let verdict = check(&limiter);
                done.store(true, Ordering::SeqCst);
                verdict
            }
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            !b_done.load(Ordering::SeqCst),
            "B must wait while A is between reading the clock and counting"
        );
        release.send(()).expect("release A");

        assert_eq!(a.join().unwrap(), Ok(()), "A: minute 1's first call");
        assert_eq!(b.join().unwrap(), Ok(()), "B: minute 2's first call");
        assert_eq!(
            check(&limiter),
            Err(RateLimited::new(RateClass::READ, 1, 60)),
            "C: minute 2's second call, over a limit of 1"
        );
    }

    #[tokio::test]
    async fn a_clock_stepped_backwards_counts_against_the_newest_window() {
        let limiter =
            MemoryLimiter::new([(RateClass::READ, 2)]).with_clock(scripted([600, 590, 300, 605]));

        limiter
            .check("s", RateClass::READ)
            .await
            .expect("600: first");
        limiter
            .check("s", RateClass::READ)
            .await
            .expect("590: second, in the newest window");
        // 300 is five minutes back: it neither reopens that window nor
        // resets the current one, and waits for the current one's end.
        assert_eq!(
            limiter.check("s", RateClass::READ).await,
            Err(RateLimited::new(RateClass::READ, 2, 60))
        );
        assert_eq!(
            limiter.check("s", RateClass::READ).await,
            Err(RateLimited::new(RateClass::READ, 2, 55))
        );
        assert_eq!(
            count(&limiter, Window::Minute, "s", RateClass::READ),
            Some(4)
        );
    }

    #[tokio::test]
    async fn even_a_limit_of_u32_max_refuses_the_call_after_it() {
        let limiter = MemoryLimiter::new([(RateClass::READ, u32::MAX)]).with_clock(|| 600);
        limiter.check("s", RateClass::READ).await.expect("first");
        // Stand in for the u32::MAX - 1 calls in between.
        limiter
            .windows
            .lock()
            .unwrap()
            .get_mut(&Window::Minute)
            .expect("counted")
            .counts
            .insert(("s".to_owned(), RateClass::READ), u64::from(u32::MAX));

        assert_eq!(
            limiter.check("s", RateClass::READ).await,
            Err(RateLimited::new(RateClass::READ, u32::MAX, 60))
        );
    }

    #[tokio::test]
    async fn no_limit_never_limits() {
        for _ in 0..50 {
            NoLimit.check("a", RateClass::READ).await.expect("never");
        }
    }

    // --- windows ------------------------------------------------------------

    #[test]
    fn windows_have_a_length_and_a_name_and_sort_shortest_first() {
        assert_eq!((Window::Minute.secs(), Window::Day.secs()), (60, 86_400));
        assert_eq!(
            (Window::Minute.as_str(), Window::Day.to_string().as_str()),
            ("minute", "day")
        );
        assert!(Window::Minute < Window::Day);
        assert_eq!(
            RateLimit::per_day(GENERATE, 30),
            RateLimit {
                class: GENERATE,
                window: Window::Day,
                limit: 30
            }
        );
        assert_eq!(RateLimit::per_minute(GENERATE, 6).window, Window::Minute);
    }

    #[test]
    fn new_is_from_limits_with_per_minute_entries() {
        let pairs = [(RateClass::READ, 60), (GENERATE, 6), (RateClass::WRITE, 0)];
        assert_eq!(
            MemoryLimiter::new(pairs).limits,
            MemoryLimiter::from_limits(
                pairs.map(|(class, limit)| RateLimit::per_minute(class, limit))
            )
            .limits
        );
        assert_eq!(
            MemoryLimiter::new(pairs).limits.of(GENERATE),
            [(Window::Minute, 6)]
        );
    }

    #[test]
    fn a_repeated_entry_is_the_last_one_and_a_final_zero_turns_the_window_off() {
        let limits = Limits::new([
            RateLimit::per_day(GENERATE, 2),
            RateLimit::per_minute(GENERATE, 1),
            RateLimit::per_minute(GENERATE, 3),
            RateLimit::per_day(GENERATE, 0),
            RateLimit::per_minute(RateClass::READ, 0),
            RateLimit::per_minute(RateClass::READ, 5),
        ]);
        assert_eq!(limits.of(GENERATE), [(Window::Minute, 3)]);
        assert_eq!(limits.of(RateClass::READ), [(Window::Minute, 5)]);

        let limiter = MemoryLimiter::from_limits([
            RateLimit::per_minute(GENERATE, 1),
            RateLimit::per_minute(GENERATE, 3),
            RateLimit::per_day(GENERATE, 2),
            RateLimit::per_day(GENERATE, 0),
        ])
        .with_clock(|| NOW);
        for call in 1..=3 {
            assert_eq!(
                block_on_check(&limiter, "a", GENERATE),
                Ok(()),
                "call {call}"
            );
        }
        assert_eq!(
            block_on_check(&limiter, "a", GENERATE),
            Err(RateLimited::new(GENERATE, 3, 40)),
            "the later minute ceiling, 3"
        );
        assert_eq!(
            count(&limiter, Window::Day, "a", GENERATE),
            None,
            "the day is off"
        );
    }

    #[test]
    fn windows_are_ordered_shortest_first_whatever_order_they_are_given_in() {
        let limits = Limits::new([
            RateLimit::per_day(GENERATE, 30),
            RateLimit::per_minute(GENERATE, 6),
        ]);
        assert_eq!(
            limits.of(GENERATE),
            [(Window::Minute, 6), (Window::Day, 30)]
        );
        assert_eq!(limits.of(RateClass::READ), []);
    }

    #[test]
    fn the_day_refusal_says_when_00_00_utc_is_rounded_up_to_the_minute() {
        for (retry, left) in [
            (1, "0 h 1 min"),
            (59, "0 h 1 min"),
            (60, "0 h 1 min"),
            (61, "0 h 2 min"),
            (3_599, "1 h 0 min"),
            (3_600, "1 h 0 min"),
            (3_601, "1 h 1 min"),
            (54_400, "15 h 7 min"),
            (86_399, "24 h 0 min"),
            (86_400, "24 h 0 min"),
        ] {
            assert_eq!(
                RateLimited::in_window(GENERATE, Window::Day, 30, retry).to_string(),
                format!(
                    "Rate limit exceeded for generate operations (30 per day). \
                     The limit resets at 00:00 UTC, in {left}."
                ),
                "{retry} s"
            );
        }
        // The minute text is Python's, whichever constructor built it.
        assert_eq!(
            RateLimited::in_window(GENERATE, Window::Minute, 6, 40),
            RateLimited::new(GENERATE, 6, 40)
        );
        assert_eq!(
            RateLimited::in_window(GENERATE, Window::Minute, 6, 40).to_string(),
            "Rate limit exceeded for generate operations (6 per minute). Retry in 40 seconds."
        );
    }

    #[tokio::test]
    async fn a_day_limit_trips_with_the_day_text_and_the_time_to_midnight() {
        let limiter =
            MemoryLimiter::from_limits([RateLimit::per_day(GENERATE, 2)]).with_clock(|| NOW);

        limiter.check("a", GENERATE).await.expect("first");
        limiter.check("a", GENERATE).await.expect("second");
        let refused = limiter.check("a", GENERATE).await.unwrap_err();

        assert_eq!(
            refused,
            RateLimited::in_window(GENERATE, Window::Day, 2, 54_400)
        );
        assert_eq!(
            refused.to_string(),
            "Rate limit exceeded for generate operations (2 per day). \
             The limit resets at 00:00 UTC, in 15 h 7 min."
        );
        // A day-only class is not counted per minute.
        assert_eq!(count(&limiter, Window::Minute, "a", GENERATE), None);
        assert_eq!(count(&limiter, Window::Day, "a", GENERATE), Some(3));
    }

    #[tokio::test]
    async fn the_minute_alone_never_counts_a_day() {
        let (now, read) = clock(NOW);
        let limiter = MemoryLimiter::from_limits([
            RateLimit::per_minute(GENERATE, 2),
            RateLimit::per_day(GENERATE, 0),
        ])
        .with_clock(read);
        for _ in 0..30 {
            limiter.check("a", GENERATE).await.expect("one");
            limiter.check("a", GENERATE).await.expect("two");
            assert!(limiter.check("a", GENERATE).await.is_err());
            now.fetch_add(60, Ordering::SeqCst);
        }
        assert!(entries(&limiter, Window::Day).is_empty());
    }

    #[tokio::test]
    async fn a_minute_refusal_is_not_counted_in_the_day() {
        let (now, read) = clock(NOW);
        let limiter = MemoryLimiter::from_limits([
            RateLimit::per_day(GENERATE, 5),
            RateLimit::per_minute(GENERATE, 2),
        ])
        .with_clock(read);

        // A burst of 10 in one minute: 2 admitted, 8 refused per minute.
        let mut admitted = 0;
        for _ in 0..10 {
            match limiter.check("a", GENERATE).await {
                Ok(()) => admitted += 1,
                Err(refused) => assert_eq!(refused, RateLimited::new(GENERATE, 2, 40)),
            }
        }
        assert_eq!(admitted, 2);
        assert_eq!(count(&limiter, Window::Minute, "a", GENERATE), Some(10));
        assert_eq!(
            count(&limiter, Window::Day, "a", GENERATE),
            Some(2),
            "the refused burst did not spend the day"
        );

        // So the day still has 3 to give, across later minutes.
        for _ in 0..3 {
            now.fetch_add(60, Ordering::SeqCst);
            limiter
                .check("a", GENERATE)
                .await
                .expect("the day's 3, 4, 5");
        }
        now.fetch_add(60, Ordering::SeqCst);
        let refused = limiter.check("a", GENERATE).await.unwrap_err();
        assert_eq!(refused.window, Window::Day);
    }

    #[tokio::test]
    async fn a_day_refusal_still_counts_in_the_minute() {
        let limiter = MemoryLimiter::from_limits([
            RateLimit::per_minute(GENERATE, 3),
            RateLimit::per_day(GENERATE, 1),
        ])
        .with_clock(|| NOW);

        limiter.check("a", GENERATE).await.expect("the day's one");
        for _ in 0..2 {
            assert_eq!(
                limiter.check("a", GENERATE).await.unwrap_err().window,
                Window::Day
            );
        }
        // The day refusals reached the day, so they counted in the minute:
        // the next call is the minute's fourth, refused per minute.
        assert_eq!(count(&limiter, Window::Minute, "a", GENERATE), Some(3));
        assert_eq!(
            limiter.check("a", GENERATE).await,
            Err(RateLimited::new(GENERATE, 3, 40))
        );
        assert_eq!(count(&limiter, Window::Day, "a", GENERATE), Some(3));
    }

    #[tokio::test]
    async fn each_window_rolls_over_on_its_own() {
        // 10 s into a UTC day.
        let start = 20_370 * DAY + 10;
        let (now, read) = clock(start);
        let limiter = MemoryLimiter::from_limits([
            RateLimit::per_minute(GENERATE, 1),
            RateLimit::per_day(GENERATE, 3),
        ])
        .with_clock(read);

        for minute in 0..3 {
            limiter.check("a", GENERATE).await.expect("one a minute");
            assert_eq!(
                limiter.check("a", GENERATE).await.unwrap_err().window,
                Window::Minute,
                "minute {minute}"
            );
            assert_eq!(
                count(&limiter, Window::Minute, "a", GENERATE),
                Some(2),
                "the minute's counts are new every minute"
            );
            assert_eq!(
                count(&limiter, Window::Day, "a", GENERATE),
                Some(minute + 1),
                "the day's carry across minutes"
            );
            now.fetch_add(60, Ordering::SeqCst);
        }
        assert_eq!(
            limiter.check("a", GENERATE).await,
            Err(RateLimited::in_window(GENERATE, Window::Day, 3, DAY - 190))
        );

        // 00:00 UTC: both windows are new.
        now.store(start - 10 + DAY, Ordering::SeqCst);
        limiter
            .check("a", GENERATE)
            .await
            .expect("the next UTC day");
        assert_eq!(count(&limiter, Window::Day, "a", GENERATE), Some(1));
        assert_eq!(index(&limiter, Window::Day), Some(20_371));
    }

    #[tokio::test]
    async fn day_counts_are_dropped_when_the_day_rolls_over() {
        let (now, read) = clock(NOW);
        let limiter =
            MemoryLimiter::from_limits([RateLimit::per_day(GENERATE, 5)]).with_clock(read);
        for subject in ["a", "b", "c"] {
            limiter.check(subject, GENERATE).await.expect("under");
        }
        assert_eq!(entries(&limiter, Window::Day).len(), 3);

        now.fetch_add(DAY, Ordering::SeqCst);
        limiter.check("d", GENERATE).await.expect("under");

        assert_eq!(entries(&limiter, Window::Day), [("d".to_owned(), GENERATE)]);
    }

    #[tokio::test]
    async fn the_day_window_only_moves_forward_too() {
        // Day 2, then two readings from day 1.
        let limiter = MemoryLimiter::from_limits([RateLimit::per_day(GENERATE, 2)])
            .with_clock(scripted([2 * DAY + 5, DAY + 100, DAY + 200]));

        limiter.check("s", GENERATE).await.expect("day 2: first");
        limiter
            .check("s", GENERATE)
            .await
            .expect("a day-1 reading: day 2's second");
        // Waits for the end of day 2, the newest day, not of day 1.
        assert_eq!(
            limiter.check("s", GENERATE).await,
            Err(RateLimited::in_window(GENERATE, Window::Day, 2, DAY))
        );
        assert_eq!(index(&limiter, Window::Day), Some(2));
        assert_eq!(count(&limiter, Window::Day, "s", GENERATE), Some(3));
    }

    #[test]
    fn one_clock_reading_covers_every_window_of_a_check() {
        // The first check's reading is the last second of day 0; a second
        // reading (one per window) would put its day count in day 1.
        let limiter = MemoryLimiter::from_limits([
            RateLimit::per_minute(GENERATE, 5),
            RateLimit::per_day(GENERATE, 5),
        ])
        .with_clock(scripted([DAY - 1, DAY]));

        assert_eq!(block_on_check(&limiter, "a", GENERATE), Ok(()));

        assert_eq!(index(&limiter, Window::Minute), Some(DAY / 60 - 1));
        assert_eq!(index(&limiter, Window::Day), Some(0), "the same instant");

        // And exactly one reading per check, whatever the number of windows.
        let readings = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&readings);
        let limiter = MemoryLimiter::from_limits([
            RateLimit::per_minute(GENERATE, 2),
            RateLimit::per_day(GENERATE, 3),
        ])
        .with_clock(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            NOW
        });
        for _ in 0..7 {
            let _ = block_on_check(&limiter, "a", GENERATE);
        }
        assert_eq!(readings.load(Ordering::SeqCst), 7);
        // An unlimited class does not read it at all.
        block_on_check(&limiter, "a", RateClass::READ).expect("unlimited");
        assert_eq!(readings.load(Ordering::SeqCst), 7);
    }

    #[test]
    fn concurrent_threads_never_exceed_the_day_limit() {
        let limiter = MemoryLimiter::from_limits([
            RateLimit::per_minute(GENERATE, 10_000),
            RateLimit::per_day(GENERATE, 50),
        ])
        .with_clock(|| NOW);

        let admitted: usize = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        (0..100)
                            .filter(|_| block_on_check(&limiter, "a", GENERATE).is_ok())
                            .count()
                    })
                })
                .collect();
            threads
                .into_iter()
                .map(|thread| thread.join().expect("no panic"))
                .sum()
        });

        assert_eq!(admitted, 50);
        assert_eq!(count(&limiter, Window::Day, "a", GENERATE), Some(800));
        assert_eq!(count(&limiter, Window::Minute, "a", GENERATE), Some(800));
    }

    // --- the rest ------------------------------------------------------------

    #[test]
    fn classes_render_their_name() {
        assert_eq!(RateClass::READ.to_string(), "read");
        assert_eq!(RateClass::WRITE.as_str(), "write");
        assert_eq!(GENERATE.as_str(), "generate");
    }

    #[test]
    fn the_limiters_are_object_safe_and_unwind_safe() {
        fn limiter<T: RateLimiter>() {}
        fn unwind_safe<T: UnwindSafe + RefUnwindSafe + Send + Sync>() {}
        limiter::<NoLimit>();
        limiter::<MemoryLimiter>();
        unwind_safe::<Arc<dyn RateLimiter>>();
        let _: Arc<dyn RateLimiter> = Arc::new(MemoryLimiter::new([]));
    }

    #[test]
    fn the_refusal_is_an_error() {
        fn error<T: std::error::Error + Send + Sync + 'static>() {}
        error::<RateLimited>();
    }

    #[test]
    fn debug_names_the_limits() {
        let debug = format!("{:?}", MemoryLimiter::new([(GENERATE, 6)]));
        assert!(debug.contains("generate") && debug.contains('6'), "{debug}");
        let debug = format!(
            "{:?}",
            MemoryLimiter::from_limits([RateLimit::per_day(GENERATE, 30)])
        );
        assert!(debug.contains("Day") && debug.contains("30"), "{debug}");
    }
}
