//! An opt-in retry for transient failures: [`RetryPolicy`], which
//! [`GcsClient::with_retry`](crate::storage::GcsClient::with_retry) takes.
//!
//! The policy is Cloud Storage's documented retry strategy: capped
//! exponential backoff with full jitter, bounded by a deadline, and
//! optionally by a number of attempts. After a transient failure the wait is
//! a uniform draw under a ceiling; the first ceiling is
//! `min(initial_delay, max_delay)`, and each next one the last times
//! `multiplier`, capped at `max_delay`. The operation gives up, returning
//! that attempt's error unchanged, when the attempt cap is reached or the
//! wait would end past `deadline` from the first attempt's start. An attempt
//! already running is never cut off. Every wait is at least 1 ms, so the
//! clock always moves and a nonzero deadline always ends the loop.
//!
//! **What is transient** is decided where each failure happens, never by
//! reading an error's text back:
//!
//! - a `408`, a `429`, and the `5xx` that report a transient server
//!   condition: `500`, `502`, `503` and `504`;
//! - a transport failure before any response that timed out, failed to
//!   connect, or broke in flight;
//! - any failure reading a body after the headers (an interrupted transfer);
//! - an attempt cut off by the client's timeout, unless that attempt had
//!   already received an error status that is not transient (a `412` whose
//!   error body stalls is still a `412`'s attempt);
//! - the same classes on the way to the access token.
//!
//! Never: a `404` (an answer), any other status (`401`, `403`, `412`, `501`
//! and `505` included), a refused redirect, a request that cannot be built,
//! a body over a cap, a refusal before anything was sent, any other token
//! error.
//!
//! ```
//! use std::time::Duration;
//! use stridelabs_gcp::retry::RetryPolicy;
//!
//! // 1 s, doubling, at most 60 s a wait, for 120 s.
//! let policy = RetryPolicy::google_default();
//! assert_eq!(policy.deadline, Duration::from_secs(120));
//! // A shorter budget for a call on a request path.
//! let quick = RetryPolicy::google_default()
//!     .with_deadline(Duration::from_secs(10))
//!     .with_max_attempts(3);
//! assert_eq!(quick.max_attempts, Some(3));
//! ```

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

use crate::auth::GcpAuthError;
use crate::storage::StorageError;
use crate::util::Failed;

/// When, and how often, a failed operation is tried again.
/// [`RetryPolicy::disabled`] (the default) retries nothing.
///
/// See [the module docs](self) for the schedule and for what is transient.
/// The fields are public and readable; nothing validates them, and every
/// value means something (normalized when used):
///
/// - a zero `deadline` retries nothing: exactly one attempt;
/// - a `max_attempts` of `Some(0)` or `Some(1)` is one attempt too, and
///   `None` caps nothing but the deadline;
/// - a `multiplier` that is NaN or below `1.0` is `1.0`; `+∞`, or a product
///   past `max_delay`, is `max_delay`;
/// - `initial_delay > max_delay` starts at `max_delay`;
/// - zero delays are allowed, and every wait is still at least 1 ms, so the
///   loop always ends by the deadline: at most `deadline / 1 ms + 1`
///   attempts that fail instantly;
/// - a `Duration::MAX` deadline with no attempt cap retries until the
///   operation succeeds or meets a failure that is not transient.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct RetryPolicy {
    /// The first wait's ceiling.
    pub initial_delay: Duration,
    /// How much each ceiling grows.
    pub multiplier: f64,
    /// The largest ceiling.
    pub max_delay: Duration,
    /// How long after the first attempt starts the operation may still
    /// wait for another. Zero is no retry.
    pub deadline: Duration,
    /// The most attempts an operation makes, the first included; `None`
    /// (the default) leaves the deadline as the only bound.
    pub max_attempts: Option<u32>,
}

impl Default for RetryPolicy {
    /// [`RetryPolicy::disabled`].
    fn default() -> RetryPolicy {
        RetryPolicy::disabled()
    }
}

impl RetryPolicy {
    /// No retry: one attempt per operation, as without a policy. It is
    /// [`RetryPolicy::google_default`]'s schedule with a zero deadline, so
    /// `disabled().with_deadline(d)` is that schedule for `d`.
    pub const fn disabled() -> RetryPolicy {
        RetryPolicy::google_default().with_deadline(Duration::ZERO)
    }

    /// The defaults Google's Cloud Storage client libraries document: 1 s
    /// initial, ×2, 60 s at most, a 120 s deadline, no attempt cap.
    pub const fn google_default() -> RetryPolicy {
        RetryPolicy {
            initial_delay: Duration::from_secs(1),
            multiplier: 2.0,
            max_delay: Duration::from_secs(60),
            deadline: Duration::from_secs(120),
            max_attempts: None,
        }
    }

    /// Set [`RetryPolicy::initial_delay`].
    #[must_use]
    pub const fn with_initial_delay(mut self, delay: Duration) -> RetryPolicy {
        self.initial_delay = delay;
        self
    }

    /// Set [`RetryPolicy::multiplier`].
    #[must_use]
    pub const fn with_multiplier(mut self, multiplier: f64) -> RetryPolicy {
        self.multiplier = multiplier;
        self
    }

    /// Set [`RetryPolicy::max_delay`].
    #[must_use]
    pub const fn with_max_delay(mut self, delay: Duration) -> RetryPolicy {
        self.max_delay = delay;
        self
    }

    /// Set [`RetryPolicy::deadline`].
    #[must_use]
    pub const fn with_deadline(mut self, deadline: Duration) -> RetryPolicy {
        self.deadline = deadline;
        self
    }

    /// Cap the attempts an operation makes at `attempts`, the first
    /// included ([`RetryPolicy::max_attempts`]); the deadline still applies.
    #[must_use]
    pub const fn with_max_attempts(mut self, attempts: u32) -> RetryPolicy {
        self.max_attempts = Some(attempts);
        self
    }
}

/// The shortest wait between two attempts, whatever the policy says: zero
/// delays still advance the clock, so `deadline / 1 ms + 1` bounds the
/// attempts a run of instant failures can make.
pub(crate) const MIN_RETRY_WAIT: Duration = Duration::from_millis(1);

/// A [`RetryPolicy`] normalized for use.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Schedule {
    /// The first wait's ceiling: `min(initial_delay, max_delay)`, so an
    /// inverted pair starts at `max_delay`.
    first: Duration,
    /// At least 1.0: NaN, anything below 1 and `-∞` become 1.0. `+∞` stays,
    /// and saturates the next ceiling at `max_delay`.
    multiplier: f64,
    max_delay: Duration,
    /// Nonzero: a zero deadline is no schedule at all.
    deadline: Duration,
    /// At least 2 when set: a cap of one attempt or none is no schedule.
    max_attempts: Option<u32>,
}

impl Schedule {
    /// `policy`'s schedule, or `None` when it retries nothing (a zero
    /// deadline, or an attempt cap of at most one: exactly one attempt).
    pub(crate) fn of(policy: RetryPolicy) -> Option<Schedule> {
        if policy.deadline.is_zero() || policy.max_attempts.is_some_and(|max| max <= 1) {
            return None;
        }
        // `>=` is false for NaN, so NaN lands on 1.0 too.
        let multiplier = if policy.multiplier >= 1.0 {
            policy.multiplier
        } else {
            1.0
        };
        Some(Schedule {
            first: policy.initial_delay.min(policy.max_delay),
            multiplier,
            max_delay: policy.max_delay,
            deadline: policy.deadline,
            max_attempts: policy.max_attempts,
        })
    }

    /// The ceiling after `ceiling`: `min(ceiling × multiplier, max_delay)`,
    /// without a panic. A product past `Duration`'s range, or not finite
    /// (`+∞`, `0 × ∞`), is past any `max_delay`.
    fn next(&self, ceiling: Duration) -> Duration {
        Duration::try_from_secs_f64(ceiling.as_secs_f64() * self.multiplier)
            .map_or(self.max_delay, |next| next.min(self.max_delay))
    }

    /// The wait for a draw `unit` (meant to lie in `[0, 1)`) under
    /// `ceiling`: `ceiling × unit`, clamped to `[MIN_RETRY_WAIT, ceiling]`
    /// (`MIN_RETRY_WAIT` when the ceiling is lower). A draw outside `[0, 1]`
    /// is clamped into it, and NaN is 0.
    fn wait(ceiling: Duration, unit: f64) -> Duration {
        let unit = if unit > 0.0 { unit.min(1.0) } else { 0.0 };
        Duration::try_from_secs_f64(ceiling.as_secs_f64() * unit)
            .map_or(ceiling, |wait| wait.min(ceiling))
            .max(MIN_RETRY_WAIT)
    }

    /// Whether attempt `made` (from 1) was the last the cap allows.
    fn capped(&self, made: u64) -> bool {
        self.max_attempts.is_some_and(|max| made >= u64::from(max))
    }

    /// Whether waiting `wait` more, `elapsed` into the run, would pass the
    /// deadline. Saturating: a `Duration::MAX` deadline is never passed.
    fn exhausted(&self, elapsed: Duration, wait: Duration) -> bool {
        elapsed.saturating_add(wait) > self.deadline
    }
}

/// A production draw for the jitter: uniform in `[0, 1)`.
pub(crate) fn uniform() -> f64 {
    rand::random::<f64>()
}

/// Run `attempt` under `policy` for `operation`: once when the policy
/// retries nothing; otherwise again after each transient failure, on the
/// schedule, until a success, a permanent failure, the attempt cap, or a
/// wait that would pass the deadline, each of which returns that attempt's
/// outcome unchanged. `unit` is the jitter's draw (see [`uniform`]).
pub(crate) async fn run<T, F>(
    policy: RetryPolicy,
    operation: &'static str,
    mut unit: impl FnMut() -> f64,
    mut attempt: impl FnMut() -> F,
) -> Result<T, StorageError>
where
    F: Future<Output = Result<T, Failed<StorageError>>>,
{
    let Some(schedule) = Schedule::of(policy) else {
        return attempt().await.map_err(|failed| failed.error);
    };
    let started = Instant::now();
    let mut ceiling = schedule.first;
    let mut number: u64 = 1;
    loop {
        // The failure is not held through the wait.
        let wait = match attempt().await {
            Ok(value) => return Ok(value),
            Err(failed) if !failed.transient || schedule.capped(number) => return Err(failed.error),
            Err(failed) => {
                let wait = Schedule::wait(ceiling, unit());
                if schedule.exhausted(started.elapsed(), wait) {
                    return Err(failed.error);
                }
                log_retry(operation, number, wait, &failed.error);
                wait
            }
        };
        tokio::time::sleep(wait).await;
        ceiling = schedule.next(ceiling);
        number = number.saturating_add(1);
    }
}

/// A retry's one `debug` line. Not generic, so every operation shares it.
fn log_retry(operation: &'static str, attempt: u64, wait: Duration, error: &StorageError) {
    let (status, category, token) = cause(error);
    tracing::debug!(
        operation,
        attempt,
        wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
        status,
        category,
        token,
        "a GCS request failed transiently; retrying"
    );
}

/// What a retry's log line may say about the failure it retries: the HTTP
/// status, or the transport category (a fixed label), and whether it was
/// the access token that failed. Never a name, a message or a URL.
fn cause(error: &StorageError) -> (Option<u16>, &str, bool) {
    match error {
        StorageError::Status { status, .. } => (Some(*status), "status", false),
        StorageError::Request { reason, .. } => (None, reason, false),
        StorageError::Timeout { .. } => (None, "operation timeout", false),
        StorageError::Auth { source, .. } => match source {
            GcpAuthError::Status { status, .. } => (Some(*status), "status", true),
            GcpAuthError::Request { reason, .. } => (None, reason, true),
            _ => (None, "other", true),
        },
        _ => (None, "other", false),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    const SECOND: Duration = Duration::from_secs(1);

    fn ceilings(policy: RetryPolicy, count: usize) -> Vec<Duration> {
        let schedule = Schedule::of(policy).expect("a schedule");
        let mut ceiling = schedule.first;
        let mut out = Vec::new();
        for _ in 0..count {
            out.push(ceiling);
            ceiling = schedule.next(ceiling);
        }
        out
    }

    fn secs(values: &[u64]) -> Vec<Duration> {
        values.iter().map(|&s| Duration::from_secs(s)).collect()
    }

    #[test]
    fn google_default_doubles_from_one_second_to_sixty() {
        assert_eq!(
            ceilings(RetryPolicy::google_default(), 9),
            secs(&[1, 2, 4, 8, 16, 32, 60, 60, 60])
        );
    }

    /// Invalid values are normalized, never rejected and never a panic.
    #[test]
    fn invalid_policies_have_defined_schedules() {
        let base = RetryPolicy::google_default();
        // A multiplier that is NaN, below 1 or -inf is 1: a flat schedule.
        for multiplier in [
            f64::NAN,
            0.5,
            0.0,
            -2.0,
            f64::NEG_INFINITY,
            f64::MIN_POSITIVE,
        ] {
            assert_eq!(
                ceilings(base.with_multiplier(multiplier), 4),
                secs(&[1, 1, 1, 1]),
                "{multiplier}"
            );
        }
        // +inf saturates at max_delay from the second ceiling on.
        assert_eq!(
            ceilings(base.with_multiplier(f64::INFINITY), 4),
            secs(&[1, 60, 60, 60])
        );
        // So does a product past Duration's range.
        assert_eq!(
            ceilings(
                base.with_multiplier(f64::MAX).with_max_delay(Duration::MAX),
                3
            ),
            [SECOND, Duration::MAX, Duration::MAX]
        );
        // An inverted pair starts at max_delay.
        assert_eq!(
            ceilings(
                base.with_initial_delay(Duration::from_secs(90))
                    .with_max_delay(Duration::from_secs(10)),
                3
            ),
            secs(&[10, 10, 10])
        );
        // Zero delays with a 50 ms deadline: zero ceilings, 1 ms waits.
        let zero = base
            .with_initial_delay(Duration::ZERO)
            .with_max_delay(Duration::ZERO)
            .with_deadline(Duration::from_millis(50));
        assert_eq!(ceilings(zero, 3), [Duration::ZERO; 3]);
        assert_eq!(
            ceilings(zero.with_multiplier(f64::INFINITY), 3),
            [Duration::ZERO; 3],
            "0 × ∞ saturates at a max_delay of zero"
        );
        for unit in [0.0, 0.5, 1.0] {
            assert_eq!(Schedule::wait(Duration::ZERO, unit), MIN_RETRY_WAIT);
        }
        // A zero deadline, or a cap of at most one attempt, is no schedule.
        assert_eq!(Schedule::of(RetryPolicy::disabled()), None);
        assert_eq!(Schedule::of(base.with_deadline(Duration::ZERO)), None);
        assert_eq!(Schedule::of(base.with_max_attempts(0)), None);
        assert_eq!(Schedule::of(base.with_max_attempts(1)), None);
        assert!(Schedule::of(base.with_max_attempts(2)).is_some());
        // Duration::MAX: the deadline is never passed, and the largest
        // delays draw without a panic.
        let forever = base
            .with_deadline(Duration::MAX)
            .with_initial_delay(Duration::MAX)
            .with_max_delay(Duration::MAX);
        let schedule = Schedule::of(forever).unwrap();
        assert!(!schedule.exhausted(Duration::MAX, Duration::MAX));
        assert_eq!(Schedule::wait(Duration::MAX, 1.0), Duration::MAX);
        assert_eq!(schedule.next(Duration::MAX), Duration::MAX);
        // And at a finite deadline the comparison is strict.
        let schedule = Schedule::of(base).unwrap();
        assert!(!schedule.exhausted(Duration::from_secs(60), Duration::from_secs(60)));
        assert!(schedule.exhausted(Duration::from_secs(60), Duration::from_secs(61)));
    }

    #[test]
    fn a_draw_is_clamped_under_its_ceiling_and_floored() {
        let ceiling = Duration::from_secs(8);
        assert_eq!(Schedule::wait(ceiling, 1.0), ceiling);
        assert_eq!(Schedule::wait(ceiling, 0.5), Duration::from_secs(4));
        assert_eq!(Schedule::wait(ceiling, 2.0), ceiling);
        for unit in [0.0, -1.0, f64::NAN, f64::NEG_INFINITY] {
            assert_eq!(Schedule::wait(ceiling, unit), MIN_RETRY_WAIT, "{unit}");
        }
        assert_eq!(Schedule::wait(ceiling, f64::INFINITY), ceiling);
        for _ in 0..1000 {
            let unit = uniform();
            assert!((0.0..1.0).contains(&unit), "{unit}");
        }
    }

    // --- the driver, on tokio's paused clock, with synthetic attempts ---------

    /// An attempt's scripted outcome.
    #[derive(Clone, Copy)]
    enum Outcome {
        Ok,
        Transient(u16),
        Permanent(u16),
    }

    /// What a run did: the attempts made, when each started (since the run
    /// began), and the result.
    struct Run {
        starts: Vec<Duration>,
        result: Result<u32, StorageError>,
    }

    /// Drive `policy` with the jitter fixed at `unit`; attempt `n` (from 1)
    /// takes `latency` and ends as `script(n)`. A watchdog fails the test if
    /// the loop does not end within `max_attempts`.
    async fn drive(
        policy: RetryPolicy,
        unit: f64,
        latency: Duration,
        max_attempts: usize,
        script: impl Fn(u32) -> Outcome,
    ) -> Run {
        let started = Instant::now();
        let starts = RefCell::new(Vec::new());
        let result = run(
            policy,
            "download",
            || unit,
            || {
                starts.borrow_mut().push(started.elapsed());
                let made = starts.borrow().len();
                assert!(
                    made <= max_attempts,
                    "watchdog: more than {max_attempts} attempts; the loop does not end"
                );
                let n = u32::try_from(made).unwrap();
                let outcome = script(n);
                async move {
                    tokio::time::sleep(latency).await;
                    let status = |status| StorageError::Status {
                        operation: "download",
                        status,
                        // Which attempt it was, so the last one is visible.
                        google_status: Some(format!("attempt-{n}")),
                        message: None,
                    };
                    match outcome {
                        Outcome::Ok => Ok(n),
                        Outcome::Transient(code) => Err(Failed::transient(status(code))),
                        Outcome::Permanent(code) => Err(Failed::permanent(status(code))),
                    }
                }
            },
        )
        .await;
        Run {
            starts: starts.into_inner(),
            result,
        }
    }

    fn attempt_of(result: &Result<u32, StorageError>) -> Option<&str> {
        match result {
            Err(StorageError::Status { google_status, .. }) => google_status.as_deref(),
            _ => None,
        }
    }

    /// Every draw at its ceiling, zero latency: waits 1, 2, 4, 8, 16 and
    /// 32 s (63 s in all), then 60 s would pass 120 s. Seven attempts, the
    /// fewest google_default can make at zero latency, and the seventh's
    /// error comes back unchanged.
    #[tokio::test(start_paused = true)]
    async fn a_permanent_503_at_full_jitter_is_seven_attempts_and_the_last_error() {
        let run = drive(
            RetryPolicy::google_default(),
            1.0,
            Duration::ZERO,
            100,
            |_| Outcome::Transient(503),
        )
        .await;
        assert_eq!(run.starts, secs(&[0, 1, 3, 7, 15, 31, 63]));
        assert_eq!(attempt_of(&run.result), Some("attempt-7"));
        assert!(matches!(
            run.result,
            Err(StorageError::Status { status: 503, .. })
        ));
    }

    /// The attempt cap ends the loop before the deadline does, and the
    /// capped attempt's error comes back unchanged, with no wait after it.
    #[tokio::test(start_paused = true)]
    async fn the_attempt_cap_ends_the_loop_at_its_count() {
        for (cap, starts) in [
            (2u32, &[0, 1][..]),
            (3, &[0, 1, 3][..]),
            (7, &[0, 1, 3, 7, 15, 31, 63][..]),
        ] {
            let started = Instant::now();
            let policy = RetryPolicy::google_default().with_max_attempts(cap);
            let run = drive(policy, 1.0, Duration::ZERO, 100, |_| {
                Outcome::Transient(503)
            })
            .await;
            assert_eq!(run.starts, secs(starts), "cap {cap}");
            assert_eq!(
                attempt_of(&run.result).map(str::to_owned),
                Some(format!("attempt-{cap}"))
            );
            assert_eq!(
                started.elapsed(),
                *run.starts.last().unwrap(),
                "cap {cap}: no wait after the last attempt"
            );
        }
        // A cap the deadline reaches first changes nothing.
        let run = drive(
            RetryPolicy::google_default().with_max_attempts(50),
            1.0,
            Duration::ZERO,
            100,
            |_| Outcome::Transient(503),
        )
        .await;
        assert_eq!(run.starts.len(), 7);
        // And a success inside the cap is a success.
        let run = drive(
            RetryPolicy::google_default().with_max_attempts(3),
            1.0,
            Duration::ZERO,
            100,
            |n| {
                if n < 3 {
                    Outcome::Transient(503)
                } else {
                    Outcome::Ok
                }
            },
        )
        .await;
        assert_eq!(run.result.unwrap(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_is_exactly_one_attempt_even_with_zero_jitter() {
        for policy in [
            RetryPolicy::disabled(),
            RetryPolicy::default(),
            RetryPolicy::google_default().with_deadline(Duration::ZERO),
            RetryPolicy::google_default().with_max_attempts(1),
            RetryPolicy::google_default().with_max_attempts(0),
        ] {
            let run = drive(policy, 0.0, Duration::ZERO, 2, |_| Outcome::Transient(503)).await;
            assert_eq!(run.starts, [Duration::ZERO], "{policy:?}");
            assert_eq!(attempt_of(&run.result), Some("attempt-1"));
        }
    }

    /// Zero delays, zero jitter and instant failures: only the 1 ms floor
    /// moves the clock, so a 50 ms deadline allows exactly 50 / 1 + 1
    /// attempts. Without the floor the loop would spin forever; the watchdog
    /// turns that into a failure.
    #[tokio::test(start_paused = true)]
    async fn zero_delays_end_within_the_one_millisecond_floor_bound() {
        let policy = RetryPolicy::google_default()
            .with_initial_delay(Duration::ZERO)
            .with_max_delay(Duration::ZERO)
            .with_deadline(Duration::from_millis(50));
        let run = drive(policy, 0.0, Duration::ZERO, 1_000, |_| {
            Outcome::Transient(503)
        })
        .await;
        assert_eq!(run.starts.len(), 51);
        assert_eq!(run.starts.last(), Some(&Duration::from_millis(50)));
        assert_eq!(attempt_of(&run.result), Some("attempt-51"));
    }

    #[tokio::test(start_paused = true)]
    async fn success_on_the_third_attempt() {
        let run = drive(
            RetryPolicy::google_default(),
            0.5,
            Duration::ZERO,
            100,
            |n| {
                if n < 3 {
                    Outcome::Transient(503)
                } else {
                    Outcome::Ok
                }
            },
        )
        .await;
        assert_eq!(run.result.unwrap(), 3);
        // Half of each ceiling: 0.5 s, then 1 s.
        assert_eq!(
            run.starts,
            [
                Duration::ZERO,
                Duration::from_millis(500),
                Duration::from_millis(1500)
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_permanent_error_returns_at_once() {
        let started = Instant::now();
        let run = drive(
            RetryPolicy::google_default(),
            1.0,
            Duration::ZERO,
            100,
            |n| {
                if n == 1 {
                    Outcome::Permanent(412)
                } else {
                    Outcome::Ok
                }
            },
        )
        .await;
        assert_eq!(run.starts, [Duration::ZERO]);
        assert!(matches!(
            run.result,
            Err(StorageError::Status { status: 412, .. })
        ));
        assert_eq!(started.elapsed(), Duration::ZERO, "no wait");
    }

    /// Real attempts make fewer: two 60 s attempts around one 1 s wait end
    /// at 121 s, past the deadline, and the second attempt, started at 61 s,
    /// was never cut off.
    #[tokio::test(start_paused = true)]
    async fn slow_attempts_end_the_loop_sooner_and_are_never_cut_off() {
        let started = Instant::now();
        let run = drive(
            RetryPolicy::google_default(),
            1.0,
            Duration::from_secs(60),
            100,
            |_| Outcome::Transient(504),
        )
        .await;
        assert_eq!(run.starts, secs(&[0, 61]));
        assert_eq!(attempt_of(&run.result), Some("attempt-2"));
        assert_eq!(started.elapsed(), Duration::from_secs(121));
    }

    /// `Duration::MAX`: the deadline is the only bound, so the loop retries
    /// until a success.
    #[tokio::test(start_paused = true)]
    async fn a_max_deadline_retries_until_success() {
        let run = drive(
            RetryPolicy::google_default().with_deadline(Duration::MAX),
            1.0,
            Duration::ZERO,
            100,
            |n| {
                if n < 40 {
                    Outcome::Transient(500)
                } else {
                    Outcome::Ok
                }
            },
        )
        .await;
        assert_eq!(run.result.unwrap(), 40);
    }

    #[test]
    fn a_retry_log_says_a_status_or_a_category_only() {
        let status = StorageError::Status {
            operation: "upload",
            status: 503,
            google_status: Some("UNAVAILABLE".to_owned()),
            message: None,
        };
        assert_eq!(cause(&status), (Some(503), "status", false));
        let request = StorageError::Request {
            operation: "download",
            reason: "decode error".to_owned(),
        };
        assert_eq!(cause(&request), (None, "decode error", false));
        let token = StorageError::Auth {
            operation: "delete",
            source: GcpAuthError::Status {
                endpoint: "http://metadata/token".to_owned(),
                status: 503,
                detail: String::new(),
            },
        };
        assert_eq!(cause(&token), (Some(503), "status", true));
    }
}
