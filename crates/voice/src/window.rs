//! The UTC calendar both voice budgets count in: the day and the month an
//! instant falls in, when each ends, how a key names it, and how long a key
//! that counts in it lives.
//!
//! The day and the month are read off the budget's clock (the system's, or a
//! test's) and baked into each key, so a window rolls over by changing keys,
//! never by an expiry firing. The expiry is only garbage collection: each key
//! lives until its window ends plus a grace ([`DAY_KEY_GRACE_SECONDS`],
//! [`MONTH_KEY_GRACE_SECONDS`]), enough that a clock a little behind another
//! instance's still finds its counter.

use std::sync::Arc;

use chrono::{DateTime, Datelike as _, NaiveDate, NaiveTime, Utc};

/// The clock a budget names its windows by: the system's
/// ([`system_clock`]), or a test's.
pub type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// The system's UTC clock.
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(Utc::now)
}

/// The midnight (UTC) that ends `now`'s day.
///
/// # Panics
///
/// On the last day chrono can represent, which has no successor.
#[must_use]
pub fn day_end(now: DateTime<Utc>) -> DateTime<Utc> {
    let tomorrow = now
        .date_naive()
        .succ_opt()
        .expect("a UTC date this process can read has a successor");
    tomorrow.and_time(NaiveTime::MIN).and_utc()
}

/// The first instant (UTC) of the month after `now`'s.
///
/// # Panics
///
/// In the last month chrono can represent, which has no successor.
#[must_use]
pub fn month_end(now: DateTime<Utc>) -> DateTime<Utc> {
    let (year, month) = match now.month() {
        12 => (now.year() + 1, 1),
        month => (now.year(), month + 1),
    };
    NaiveDate::from_ymd_opt(year, month, 1)
        .expect("the first of a month always exists")
        .and_time(NaiveTime::MIN)
        .and_utc()
}

/// Whole seconds from `now` until `end`, rounded UP and at least 1 — a
/// `Retry-After` (or a TTL) that is never early and never zero.
#[must_use]
pub fn seconds_until(end: DateTime<Utc>, now: DateTime<Utc>) -> i64 {
    let millis = (end - now).num_milliseconds();
    millis
        .div_euclid(1000)
        .saturating_add(i64::from(millis.rem_euclid(1000) != 0))
        .max(1)
}

/// How long a day key (a user's day) outlives its day.
pub const DAY_KEY_GRACE_SECONDS: i64 = 60 * 60;

/// How long a month key (a user's month, everyone's month) outlives its
/// month.
pub const MONTH_KEY_GRACE_SECONDS: i64 = 24 * 60 * 60;

/// The expiries (`EX`, seconds) of a day key and of a month key written at
/// `now`: each window's remainder plus its grace.
#[must_use]
pub fn key_ttls(now: DateTime<Utc>) -> (i64, i64) {
    (
        seconds_until(day_end(now), now).saturating_add(DAY_KEY_GRACE_SECONDS),
        seconds_until(month_end(now), now).saturating_add(MONTH_KEY_GRACE_SECONDS),
    )
}

/// `now`'s UTC day as a key names it: `YYYY-MM-DD`.
#[must_use]
pub fn day_stamp(now: DateTime<Utc>) -> String {
    now.format("%Y-%m-%d").to_string()
}

/// `now`'s UTC month as a key names it: `YYYY-MM`.
#[must_use]
pub fn month_stamp(now: DateTime<Utc>) -> String {
    now.format("%Y-%m").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    fn at(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
            .single()
            .expect("a valid instant")
    }

    /// The windows end at the next UTC midnight and the next first-of-month,
    /// across a year boundary and a leap day.
    #[test]
    fn the_windows_end_where_the_calendar_does() {
        assert_eq!(
            day_end(at(2026, 10, 17, 12, 0, 0)),
            at(2026, 10, 18, 0, 0, 0)
        );
        assert_eq!(
            day_end(at(2026, 12, 31, 23, 59, 59)),
            at(2027, 1, 1, 0, 0, 0)
        );
        assert_eq!(day_end(at(2028, 2, 28, 0, 0, 0)), at(2028, 2, 29, 0, 0, 0));
        assert_eq!(
            month_end(at(2026, 10, 17, 12, 0, 0)),
            at(2026, 11, 1, 0, 0, 0)
        );
        assert_eq!(month_end(at(2026, 12, 1, 0, 0, 0)), at(2027, 1, 1, 0, 0, 0));
        assert_eq!(
            month_end(at(2028, 2, 29, 23, 0, 0)),
            at(2028, 3, 1, 0, 0, 0)
        );
        // Midnight itself belongs to the day it starts.
        assert_eq!(
            day_end(at(2026, 10, 18, 0, 0, 0)),
            at(2026, 10, 19, 0, 0, 0)
        );
    }

    /// Rounded up, never zero: a client waiting exactly this long finds the
    /// window gone.
    #[test]
    fn retry_after_rounds_up_and_is_never_zero() {
        let now = at(2026, 10, 17, 23, 59, 59);
        assert_eq!(seconds_until(day_end(now), now), 1);
        let almost = now + chrono::Duration::milliseconds(999);
        assert_eq!(seconds_until(day_end(now), almost), 1);
        let early = now - chrono::Duration::milliseconds(1);
        assert_eq!(seconds_until(day_end(now), early), 2);
        assert_eq!(seconds_until(now, now), 1);
        assert_eq!(
            seconds_until(
                day_end(at(2026, 10, 17, 0, 0, 0)),
                at(2026, 10, 17, 0, 0, 0)
            ),
            86_400
        );
    }

    /// Every key lives until its window's end plus its grace: the day an
    /// hour, both months a day.
    #[test]
    fn the_ttls_are_each_windows_end_plus_its_grace() {
        assert_eq!(
            key_ttls(at(2026, 10, 31, 23, 0, 0)),
            (3_600 + 3_600, 3_600 + 86_400)
        );
        assert_eq!(
            key_ttls(at(2026, 2, 1, 0, 0, 0)),
            (86_400 + 3_600, 28 * 86_400 + 86_400)
        );
    }

    /// A key names the UTC date and month of its instant, zero-padded, on
    /// either side of a month's last midnight.
    #[test]
    fn the_stamps_are_the_utc_day_and_month() {
        let last = at(2026, 10, 31, 23, 59, 59);
        assert_eq!(day_stamp(last), "2026-10-31");
        assert_eq!(month_stamp(last), "2026-10");
        let first = at(2026, 11, 1, 0, 0, 0);
        assert_eq!(day_stamp(first), "2026-11-01");
        assert_eq!(month_stamp(first), "2026-11");
        assert_eq!(day_stamp(at(2031, 3, 5, 12, 0, 0)), "2031-03-05");
    }
}
