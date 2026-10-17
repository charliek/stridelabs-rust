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
//!   window held in process memory: right for tests, and for a service that
//!   runs as one instance.
//! - `RedisRateLimiter` (feature `redis`) shares the same window across
//!   instances through Redis, and fails open when Redis does.
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

/// The fixed window every limiter here counts in: one wall-clock minute
/// (`unix_seconds / 60`), as in Python.
pub(crate) const WINDOW_SECS: u64 = 60;

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

/// A caller exceeded its per-minute limit for a class.
///
/// `Display` is Python's text, byte for byte, and the tool boundary returns
/// it to the model as the call's error: "Rate limit exceeded for {class}
/// operations ({limit} per minute). Retry in {retry_after_secs} seconds."
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "Rate limit exceeded for {class} operations ({limit} per minute). \
     Retry in {retry_after_secs} seconds."
)]
#[non_exhaustive]
pub struct RateLimited {
    /// The class whose limit was exceeded.
    pub class: RateClass,
    /// That class's per-minute ceiling.
    pub limit: u32,
    /// Seconds until the current window ends.
    pub retry_after_secs: u64,
}

impl RateLimited {
    /// A refusal for `class`, whose ceiling is `limit` calls per minute, with
    /// `retry_after_secs` left in the window.
    pub fn new(class: RateClass, limit: u32, retry_after_secs: u64) -> RateLimited {
        RateLimited {
            class,
            limit,
            retry_after_secs,
        }
    }
}

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

/// The per-class ceilings a limiter enforces. A class with no entry, or an
/// entry of 0, is not limited — and not counted.
#[derive(Debug, Clone, Default)]
pub(crate) struct Limits(BTreeMap<RateClass, u32>);

impl Limits {
    pub(crate) fn new<I>(limits: I) -> Limits
    where
        I: IntoIterator<Item = (RateClass, u32)>,
    {
        Limits(limits.into_iter().collect())
    }

    /// The ceiling for `class`; 0 means unlimited.
    pub(crate) fn of(&self, class: RateClass) -> u32 {
        self.0.get(&class).copied().unwrap_or(0)
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

/// The refusal for a hit that took `class`'s count over `limit`, at `now`.
pub(crate) fn refusal(class: RateClass, limit: u32, now: u64) -> RateLimited {
    RateLimited::new(class, limit, WINDOW_SECS - now % WINDOW_SECS)
}

/// An in-process fixed-window limiter: at most `limit` calls per
/// `(subject, class)` per wall-clock minute — Python `enforce_rate_limit`'s
/// window, held in memory instead of Redis.
///
/// - A class with no configured limit, or a limit of 0, is not limited (and
///   not counted).
/// - Every call in a limited class counts, a refused one included, as
///   Redis's `INCR` does.
/// - The window is `unix_seconds / 60`, not a sliding minute: two calls a
///   second apart across a minute boundary are in different windows, and a
///   refusal's `retry_after_secs` is what is left of the current one.
/// - **Windows only move forward.** The clock is read inside the one
///   `Mutex`, and a reading from an earlier window than the newest one seen
///   (a clock stepped backwards, or a check that was delayed) counts against
///   the newest window: it never reopens an old one, and never resets the
///   current one's counts.
/// - **Counts are dropped when the window moves forward**, so memory is
///   bounded by the subjects active within one minute.
/// - Every check is one short critical section, so concurrent calls never
///   over-admit. Counts are `u64`, so even a limit of `u32::MAX` refuses
///   the call after it.
///
/// Its state lives in the limiter, so share **one** across a service's
/// stateless handler instances (an `Arc<dyn RateLimiter>` in the app state,
/// cloned into each).
pub struct MemoryLimiter {
    limits: Limits,
    clock: Clock,
    window: Mutex<Window>,
}

#[derive(Default)]
struct Window {
    /// The newest window any check has read the clock in.
    index: u64,
    counts: HashMap<(String, RateClass), u64>,
}

impl MemoryLimiter {
    /// A limiter with these per-class ceilings, in calls per minute; 0 or an
    /// absent class is unlimited.
    pub fn new<I>(limits: I) -> MemoryLimiter
    where
        I: IntoIterator<Item = (RateClass, u32)>,
    {
        MemoryLimiter {
            limits: Limits::new(limits),
            clock: Clock::system(),
            window: Mutex::new(Window::default()),
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
        let limit = self.limits.of(class);
        if limit == 0 {
            return Ok(());
        }
        // A panic elsewhere while holding the lock cannot have left the
        // counts half-updated (each update is one `+= 1`), so poison says
        // nothing about them.
        let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
        // Read inside the lock, so readings are applied in the order they
        // were taken.
        let now = self.clock.now();
        let index = now / WINDOW_SECS;
        if index > window.index {
            window.index = index;
            window.counts.clear();
        }
        // An older reading (a backwards clock) counts against the newest
        // window, and its retry hint runs to that window's end.
        let now = now.max(window.index * WINDOW_SECS);
        let count = window
            .counts
            .entry((subject.to_owned(), class))
            .or_insert(0);
        *count = count.saturating_add(1);
        if *count > u64::from(limit) {
            Err(refusal(class, limit, now))
        } else {
            Ok(())
        }
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

    /// A clock the test moves.
    fn clock(start: u64) -> (Arc<AtomicU64>, impl Fn() -> u64 + Send + Sync + 'static) {
        let now = Arc::new(AtomicU64::new(start));
        let read = Arc::clone(&now);
        (now, move || read.load(Ordering::SeqCst))
    }

    fn entries(limiter: &MemoryLimiter) -> Vec<(String, RateClass)> {
        let window = limiter.window.lock().unwrap();
        let mut keys: Vec<_> = window.counts.keys().cloned().collect();
        keys.sort();
        keys
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
            limiter.window.lock().unwrap().counts[&("a".to_owned(), RateClass::READ)],
            3
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
        assert_eq!(entries(&limiter).len(), 3);

        now.fetch_add(60, Ordering::SeqCst);
        limiter.check("d", RateClass::READ).await.expect("under");

        assert_eq!(entries(&limiter), [("d".to_owned(), RateClass::READ)]);
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
            entries(&limiter).is_empty(),
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
        assert_eq!(
            limiter.window.lock().unwrap().counts[&("a".to_owned(), GENERATE)],
            400
        );
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
        let check = |limiter: &MemoryLimiter| {
            futures::executor::block_on(limiter.check("s", RateClass::READ))
        };

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
            limiter.window.lock().unwrap().counts[&("s".to_owned(), RateClass::READ)],
            4
        );
    }

    #[tokio::test]
    async fn even_a_limit_of_u32_max_refuses_the_call_after_it() {
        let limiter = MemoryLimiter::new([(RateClass::READ, u32::MAX)]).with_clock(|| 600);
        limiter.check("s", RateClass::READ).await.expect("first");
        // Stand in for the u32::MAX - 1 calls in between.
        limiter
            .window
            .lock()
            .unwrap()
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
    fn debug_names_the_limits() {
        let debug = format!("{:?}", MemoryLimiter::new([(GENERATE, 6)]));
        assert!(debug.contains("generate") && debug.contains('6'), "{debug}");
    }
}
