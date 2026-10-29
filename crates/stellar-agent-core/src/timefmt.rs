//! Shared timestamp formatting helpers.
//!
//! Provides [`crate::timefmt::current_iso8601_utc`],
//! [`crate::timefmt::epoch_to_datetime`], and [`crate::timefmt::now_unix_ms`]
//! for use by audit logging, observability, wallet lifecycle, and MCP expiry
//! checks.
//!
//! # Why not use `chrono` or `time`?
//!
//! Neither crate is in the workspace.  The functionality needed here is a
//! simple decomposition of a Unix epoch second into calendar fields — nothing
//! that justifies a heavyweight dependency.  The implementation is valid for
//! years 1970–2099, which covers all plausible audit-log timestamps.

use std::sync::Arc;

use crate::wallet::WalletLifecycleError;

// ── Public API ────────────────────────────────────────────────────────────────

/// Wall-clock source for wallet lifecycle and approval-expiry checks.
///
/// The trait exists because `std::time::SystemTime::now()` is not mockable and
/// Tokio's paused time controls runtime timers, not host wall-clock reads.
///
/// # Errors
///
/// Returns [`WalletLifecycleError::ClockError`] when the underlying wall-clock
/// read or conversion fails.
pub trait Clock: Send + Sync {
    /// Return the current Unix timestamp in milliseconds.
    ///
    /// # Errors
    ///
    /// Returns [`WalletLifecycleError::ClockError`] when the clock cannot be read
    /// or converted to milliseconds.
    fn now_unix_ms(&self) -> Result<u64, WalletLifecycleError>;
}

/// Default [`Clock`] implementation backed by [`std::time::SystemTime`].
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> Result<u64, WalletLifecycleError> {
        now_unix_ms()
    }
}

/// Returns the default system wall-clock implementation.
#[must_use]
pub fn default_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// Test helper clock with caller-controlled output.
#[cfg(any(test, feature = "test-helpers"))]
pub struct MockClock {
    now_unix_ms: Box<dyn Fn() -> Result<u64, WalletLifecycleError> + Send + Sync>,
}

#[cfg(any(test, feature = "test-helpers"))]
impl MockClock {
    /// Creates a mock clock from a closure.
    #[must_use]
    pub fn new(
        now_unix_ms: impl Fn() -> Result<u64, WalletLifecycleError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            now_unix_ms: Box::new(now_unix_ms),
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl Clock for MockClock {
    fn now_unix_ms(&self) -> Result<u64, WalletLifecycleError> {
        (self.now_unix_ms)()
    }
}

/// Formats a [`std::time::SystemTime`] as an RFC 3339 UTC string with second
/// precision: `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Subsecond resolution is truncated.  Returns the Unix epoch string
/// (`1970-01-01T00:00:00Z`) on underflow (cannot happen post-2026).
///
/// # Examples
///
/// ```
/// use std::time::{Duration, UNIX_EPOCH};
/// use stellar_agent_core::timefmt::format_rfc3339_utc;
///
/// // 2026-04-30T12:34:56Z = 1_777_552_496 seconds since epoch.
/// let t = UNIX_EPOCH + Duration::from_secs(1_777_552_496);
/// assert_eq!(format_rfc3339_utc(t), "2026-04-30T12:34:56Z");
/// ```
///
/// # Panics
///
/// Never panics.
#[must_use]
pub fn format_rfc3339_utc(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (year, month, day, hour, min, sec) = epoch_to_datetime(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Parses exactly `YYYY-MM-DDTHH:MM:SSZ` as Unix seconds.
///
/// Accepts valid Gregorian dates with four-digit years from 1970, and seconds
/// from 00 through 59. Other forms and invalid calendar fields return `None`.
///
/// # Examples
///
/// ```
/// use std::time::{Duration, UNIX_EPOCH};
/// use stellar_agent_core::timefmt::{format_rfc3339_utc, parse_rfc3339_utc};
///
/// let seconds = 1_777_552_496;
/// let text = format_rfc3339_utc(UNIX_EPOCH + Duration::from_secs(seconds));
/// assert_eq!(parse_rfc3339_utc(&text), Some(seconds));
/// ```
#[must_use]
pub fn parse_rfc3339_utc(text: &str) -> Option<u64> {
    if text.len() != 20 {
        return None;
    }
    for (i, byte) in text.bytes().enumerate() {
        let valid = match i {
            4 | 7 => byte == b'-',
            10 => byte == b'T',
            13 | 16 => byte == b':',
            19 => byte == b'Z',
            _ => byte.is_ascii_digit(),
        };
        if !valid {
            return None;
        }
    }
    let year: u32 = text.get(0..4)?.parse().ok()?;
    let month: usize = text.get(5..7)?.parse().ok()?;
    let day: u32 = text.get(8..10)?.parse().ok()?;
    let hour: u64 = text.get(11..13)?.parse().ok()?;
    let minute: u64 = text.get(14..16)?.parse().ok()?;
    let second: u64 = text.get(17..19)?.parse().ok()?;
    if year < 1970 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days_in_month = [
        31,
        if is_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > days_in_month[month - 1] {
        return None;
    }
    let prior_year_days: u64 = (1970..year)
        .map(|y| if is_leap_year(y) { 366 } else { 365 })
        .sum();
    let prior_month_days: u32 = days_in_month[..month - 1].iter().sum();
    let days = prior_year_days + u64::from(prior_month_days + day - 1);
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Returns the current UTC time as an ISO-8601 string with millisecond
/// precision: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
///
/// Uses [`std::time::SystemTime`] to avoid requiring a `chrono` or `time`
/// dependency (neither is in the workspace).
///
/// # Examples
///
/// ```
/// use stellar_agent_core::timefmt::current_iso8601_utc;
///
/// let ts = current_iso8601_utc();
/// assert!(ts.ends_with('Z'), "timestamp must end with Z: {ts}");
/// assert_eq!(ts.len(), 24, "length must be 24: {ts}");
/// ```
#[must_use]
pub fn current_iso8601_utc() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (year, month, day, hour, min, sec) = epoch_to_datetime(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// Returns the current Unix timestamp in milliseconds.
///
/// # Errors
///
/// Returns [`WalletLifecycleError::ClockError`] when the system clock is before
/// the Unix epoch or when the millisecond count overflows `u64`.
///
/// # Notes
///
/// Returns wall-clock milliseconds. Not monotonic — successive calls may return
/// decreasing values across NTP steps or manual clock changes. Code that needs
/// monotonic timing (e.g. duration measurement, deadline tracking) should use
/// `std::time::Instant::now()` instead. Approval-GC TTL comparison
/// (`crates/stellar-agent-cli/src/commands/approve/gc.rs`) uses wall-clock here
/// because the persisted approval expiry is itself a wall-clock timestamp.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::timefmt::now_unix_ms;
///
/// let now = now_unix_ms().expect("system clock should be valid");
/// assert!(now > 0);
/// ```
pub fn now_unix_ms() -> Result<u64, WalletLifecycleError> {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|e| WalletLifecycleError::ClockError {
            detail: "system clock is before UNIX_EPOCH".to_owned(),
            source: Some(e),
        })
        .and_then(|d| {
            u64::try_from(d.as_millis()).map_err(|_| WalletLifecycleError::ClockError {
                detail: "system clock milliseconds overflow u64".to_owned(),
                source: None,
            })
        })
}

/// Convert Unix epoch seconds to `(year, month, day, hour, min, sec)`.
///
/// Simple implementation valid for years 1970–2099.  Not intended for
/// arbitrary-precision calendar arithmetic.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::timefmt::epoch_to_datetime;
///
/// // 2026-04-29T00:00:00 UTC
/// // Verified via calendar.timegm((2026,4,29,0,0,0,0,0,0)) in Python 3.
/// let (y, mo, d, h, mi, s) = epoch_to_datetime(1_777_420_800);
/// assert_eq!(y, 2026);
/// assert_eq!(mo, 4);
/// assert_eq!(d, 29);
/// assert_eq!(h, 0);
/// assert_eq!(mi, 0);
/// assert_eq!(s, 0);
/// ```
#[must_use]
pub fn epoch_to_datetime(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let sec = (secs % 60) as u32;
    let mins = secs / 60;
    let min = (mins % 60) as u32;
    let hours = mins / 60;
    let hour = (hours % 24) as u32;
    let mut days = (hours / 24) as u32;

    let mut year = 1970u32;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let leap = is_leap_year(year);
    let days_in_month: [u32; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0u32;
    for &dim in &days_in_month {
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    (year, month + 1, days + 1, hour, min, sec)
}

/// Returns `true` if `year` is a Gregorian leap year.
#[must_use]
pub(crate) fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    use super::*;

    #[test]
    fn parse_rfc3339_utc_inverts_format() {
        use std::time::{Duration, UNIX_EPOCH};
        for (seconds, text) in [
            (0, "1970-01-01T00:00:00Z"),
            (1_709_251_199, "2024-02-29T23:59:59Z"),
            (1_777_552_496, "2026-04-30T12:34:56Z"),
            (4_107_542_400, "2100-03-01T00:00:00Z"),
            (13_574_563_200, "2400-02-29T00:00:00Z"),
        ] {
            assert_eq!(
                format_rfc3339_utc(UNIX_EPOCH + Duration::from_secs(seconds)),
                text
            );
            assert_eq!(parse_rfc3339_utc(text), Some(seconds));
        }
    }

    #[test]
    fn parse_rfc3339_utc_refuses_other_forms() {
        for text in [
            "2026-04-30T12:34:56.000Z",
            "2026-04-30T12:34:56+00:00",
            "2026-04-30t12:34:56Z",
            "2026-04-30T12:34:56z",
            "2026-13-30T12:34:56Z",
            "2026-00-30T12:34:56Z",
            "2024-02-30T12:34:56Z",
            "2026-02-29T12:34:56Z",
            "2100-02-29T12:34:56Z",
            "2026-04-00T12:34:56Z",
            "2026-04-31T12:34:56Z",
            "2026-04-30T24:34:56Z",
            "2026-04-30T12:60:56Z",
            "2026-04-30T12:34:60Z",
            "1969-12-31T23:59:59Z",
            "2026-04-30T12:34:56Z trailing",
            "2026/04-30T12:34:56Z",
            "2026-04-30T12:34:5é",
            "",
        ] {
            assert_eq!(parse_rfc3339_utc(text), None, "{text}");
        }
    }

    #[test]
    fn format_rfc3339_utc_known_timestamp() {
        use std::time::{Duration, UNIX_EPOCH};
        // 2026-04-30T12:34:56Z = 1_777_552_496 s since epoch.
        let t = UNIX_EPOCH + Duration::from_secs(1_777_552_496);
        assert_eq!(format_rfc3339_utc(t), "2026-04-30T12:34:56Z");
    }

    #[test]
    fn format_rfc3339_utc_epoch() {
        use std::time::UNIX_EPOCH;
        assert_eq!(format_rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_format() {
        let ts = current_iso8601_utc();
        assert!(ts.ends_with('Z'), "timestamp must end with Z: {ts}");
        assert_eq!(ts.len(), 24, "length must be 24: {ts}");
    }

    #[test]
    fn now_unix_ms_returns_positive_current_time() {
        let now = now_unix_ms().unwrap();
        assert!(now > 1_700_000_000_000, "now looks implausible: {now}");
    }

    #[test]
    fn epoch_to_datetime_known_value() {
        // 2026-04-29T00:00:00 UTC
        // Verified independently via `calendar.timegm((2026,4,29,0,0,0,0,0,0))`
        // in Python 3 (UTC, no DST): 1_777_420_800.
        let ts = 1_777_420_800u64;
        let (y, mo, d, h, mi, s) = epoch_to_datetime(ts);
        assert_eq!(y, 2026);
        assert_eq!(mo, 4);
        assert_eq!(d, 29);
        assert_eq!(h, 0);
        assert_eq!(mi, 0);
        assert_eq!(s, 0);
    }

    #[test]
    fn epoch_to_datetime_known_value_2025() {
        // 2025-04-29T00:00:00 UTC
        // Verified independently via `calendar.timegm((2025,4,29,0,0,0,0,0,0))`
        // in Python 3 (UTC, no DST): 1_745_884_800.
        let ts = 1_745_884_800u64;
        let (y, mo, d, h, mi, s) = epoch_to_datetime(ts);
        assert_eq!(y, 2025);
        assert_eq!(mo, 4);
        assert_eq!(d, 29);
        assert_eq!(h, 0);
        assert_eq!(mi, 0);
        assert_eq!(s, 0);
    }

    #[test]
    fn epoch_to_datetime_unix_zero() {
        let (y, mo, d, h, mi, s) = epoch_to_datetime(0);
        assert_eq!(y, 1970);
        assert_eq!(mo, 1);
        assert_eq!(d, 1);
        assert_eq!(h, 0);
        assert_eq!(mi, 0);
        assert_eq!(s, 0);
    }

    #[test]
    fn is_leap_year_2000() {
        assert!(is_leap_year(2000));
    }

    #[test]
    fn is_leap_year_1900_not_leap() {
        assert!(!is_leap_year(1900));
    }

    #[test]
    fn is_leap_year_2024() {
        assert!(is_leap_year(2024));
    }
}
