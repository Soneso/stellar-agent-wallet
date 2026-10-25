//! The one clock mainnet authorization reads.
//!
//! The authorization ledger in the window store, the signing points, and the
//! submit gate decide freshness against [`now_ms`], so an authorization's
//! issue time, its expiry, and the moment it is used are all measured on the
//! same clock. A caller never supplies the time a transition is checked
//! against.
//!
//! Under the `test-hooks` feature, and in this crate's own tests,
//! [`set_now_ms_for_test`] fixes the clock for every caller in the process
//! until its guard drops; tests that use it run serially.

use stellar_agent_core::error::{WalletError, WalletStateError};

/// The current Unix time in milliseconds.
///
/// # Errors
///
/// `wallet.clock_error` when the system clock is before the Unix epoch or
/// its milliseconds do not fit a `u64`.
pub fn now_ms() -> Result<u64, WalletError> {
    #[cfg(any(test, feature = "test-hooks"))]
    if let Some(now) = *test_override::lock() {
        return Ok(now);
    }
    stellar_agent_core::timefmt::now_unix_ms().map_err(|error| {
        WalletError::WalletState(WalletStateError::ClockError {
            detail: error.to_string(),
        })
    })
}

#[cfg(any(test, feature = "test-hooks"))]
mod test_override {
    use std::sync::{Mutex, MutexGuard, PoisonError};

    static OVERRIDE: Mutex<Option<u64>> = Mutex::new(None);

    pub(super) fn lock() -> MutexGuard<'static, Option<u64>> {
        OVERRIDE.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Holds the clock override set by [`set_now_ms_for_test`]; dropping it
/// restores the system clock.
///
/// Only compiled with the `test-hooks` feature or in this crate's tests.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
#[derive(Debug)]
#[must_use = "the override lasts only while the guard lives"]
pub struct TestClockGuard(());

#[cfg(any(test, feature = "test-hooks"))]
impl TestClockGuard {
    /// Moves the overridden clock to `now_ms`.
    pub fn set(&self, now_ms: u64) {
        *test_override::lock() = Some(now_ms);
    }
}

#[cfg(any(test, feature = "test-hooks"))]
impl Drop for TestClockGuard {
    fn drop(&mut self) {
        *test_override::lock() = None;
    }
}

/// Fixes [`now_ms`] at `now_ms` for every caller until the guard drops.
///
/// Only compiled with the `test-hooks` feature or in this crate's tests.
/// Never include `test-hooks` in production or release builds.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub fn set_now_ms_for_test(now_ms: u64) -> TestClockGuard {
    *test_override::lock() = Some(now_ms);
    TestClockGuard(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use super::*;
    use serial_test::serial;

    /// The override holds while its guard lives, moves with it, and the
    /// system clock returns when it drops.
    #[test]
    #[serial]
    fn the_override_lasts_while_its_guard_lives() {
        let guard = set_now_ms_for_test(5);
        assert_eq!(now_ms().unwrap(), 5);
        guard.set(9);
        assert_eq!(now_ms().unwrap(), 9);
        drop(guard);
        assert!(now_ms().unwrap() > 1_700_000_000_000);
    }
}
