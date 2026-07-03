//! Error taxonomy for the wallet lifecycle.
//!
//! Provides [`WalletLifecycleError`] — the typed error surface for every
//! failure mode that can occur during wallet unlock, memory locking, TTL
//! enforcement, and dispose.  No error variant surfaces secret material.

use thiserror::Error;

/// Errors from the wallet lifecycle (unlock, mlock, TTL, dispose).
///
/// Every variant carries only non-secret context (reasons, errno values,
/// profile names).  Seed material is never present in any variant.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WalletLifecycleError {
    /// `mlock` (or `VirtualLock` on Windows) was requested but the operating
    /// system refused the call.
    ///
    /// Triggered when `MlockRequired::True` is in effect and `region::lock`
    /// returns an error.  Callers must raise `RLIMIT_MEMLOCK` or set the
    /// profile field `wallet.mlock_required = "warn"` to opt out of the
    /// fail-closed behaviour.
    #[error("mlock unavailable: {reason} (errno {errno})")]
    MlockUnavailable {
        /// Human-readable reason string from the OS error.
        reason: String,
        /// `errno` value from the failed `mlock` / `VirtualLock` syscall.
        errno: i32,
    },

    /// The wallet has already been disposed and the signing seed is no longer
    /// available.
    ///
    /// Returned by [`super::lifecycle::Wallet::seed`] when called after
    /// `dispose()` or after the TTL has expired.
    #[error("wallet has been disposed; re-unlock to obtain a new signing window")]
    Disposed,

    /// The TTL value is outside the permitted range `(0, 600]` seconds.
    ///
    /// Zero-second TTLs are prohibited (a zero-TTL window is immediately
    /// disposed and would be a programming error at the call site).  TTLs
    /// greater than 600 seconds (10 minutes) are prohibited to limit the
    /// maximum window during which signing materials reside in memory.
    #[error("invalid TTL {ttl_seconds}s: {reason}")]
    TtlInvalid {
        /// The rejected TTL value supplied by the caller.
        ttl_seconds: u32,
        /// Human-readable reason explaining why the value is rejected.
        reason: String,
    },

    /// A dispose operation was attempted on a wallet that has already been
    /// disposed.
    ///
    /// `dispose()` is idempotent — callers may ignore this error or use it
    /// to detect accidental double-dispose at a higher layer.
    #[error("wallet was already disposed")]
    AlreadyDisposed,

    /// The system clock is unavailable or returned an invalid value.
    ///
    /// Returned when `SystemTime::now().duration_since(UNIX_EPOCH)` fails
    /// (system clock is before the Unix epoch) or when the millisecond
    /// count overflows `u64`.  Both cases are essentially impossible on
    /// production hardware but must be handled explicitly — silently falling
    /// back to epoch 0 would make an expiry check treat every wallet as
    /// immediately TTL-expired.
    ///
    /// `is_disposed()` returns `true` (fails closed) when this error occurs
    /// internally.  `seed()` and `unlock()` propagate the typed error.
    #[error("wallet clock error: {detail}")]
    ClockError {
        /// Non-secret diagnostic detail.
        detail: String,
        /// Optional underlying system-clock error.
        #[source]
        source: Option<std::time::SystemTimeError>,
    },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, reason = "test-only fixture construction")]

    use std::error::Error as _;
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    fn system_time_error_fixture() -> std::time::SystemTimeError {
        match UNIX_EPOCH.duration_since(UNIX_EPOCH + Duration::from_secs(1)) {
            Err(e) => e,
            Ok(_) => panic!("fixture must produce SystemTimeError"),
        }
    }

    #[test]
    fn mlock_unavailable_display() {
        let e = WalletLifecycleError::MlockUnavailable {
            reason: "ENOMEM".to_owned(),
            errno: 12,
        };
        let s = format!("{e}");
        assert!(s.contains("mlock unavailable"), "got: {s}");
        assert!(s.contains("ENOMEM"), "got: {s}");
        assert!(s.contains("12"), "got: {s}");
    }

    #[test]
    fn disposed_display() {
        let e = WalletLifecycleError::Disposed;
        let s = format!("{e}");
        assert!(s.contains("disposed"), "got: {s}");
    }

    #[test]
    fn ttl_invalid_display() {
        let e = WalletLifecycleError::TtlInvalid {
            ttl_seconds: 0,
            reason: "must be > 0".to_owned(),
        };
        let s = format!("{e}");
        assert!(s.contains("0s"), "got: {s}");
        assert!(s.contains("must be > 0"), "got: {s}");
    }

    #[test]
    fn already_disposed_display() {
        let e = WalletLifecycleError::AlreadyDisposed;
        let s = format!("{e}");
        assert!(s.contains("already disposed"), "got: {s}");
    }

    #[test]
    fn clock_error_display() {
        let e = WalletLifecycleError::ClockError {
            detail: "system clock is before UNIX_EPOCH".to_owned(),
            source: None,
        };
        let s = format!("{e}");
        assert!(s.contains("clock"), "got: {s}");
        assert!(s.contains("UNIX_EPOCH"), "got: {s}");
    }

    #[test]
    fn clock_error_preserves_systemtime_source() {
        let source = system_time_error_fixture();
        let e = WalletLifecycleError::ClockError {
            detail: "system clock is before UNIX_EPOCH".to_owned(),
            source: Some(source),
        };

        assert!(e.source().is_some());
    }

    #[test]
    fn clock_error_constructs_with_none_source() {
        let e = WalletLifecycleError::ClockError {
            detail: "system clock milliseconds overflow u64".to_owned(),
            source: None,
        };

        assert!(e.source().is_none());
    }

    #[test]
    fn clock_error_display_does_not_include_source_drift() {
        let source = system_time_error_fixture();
        let source_display = source.to_string();
        let e = WalletLifecycleError::ClockError {
            detail: "system clock is before UNIX_EPOCH".to_owned(),
            source: Some(source),
        };
        let display = format!("{e}");

        assert!(
            !display.contains(&source_display),
            "parent Display must not include source drift detail: {display}"
        );
        assert!(e.source().is_some());
    }

    #[test]
    fn error_variants_are_debug() {
        let variants: &[WalletLifecycleError] = &[
            WalletLifecycleError::MlockUnavailable {
                reason: "test".to_owned(),
                errno: 1,
            },
            WalletLifecycleError::Disposed,
            WalletLifecycleError::TtlInvalid {
                ttl_seconds: 0,
                reason: "zero".to_owned(),
            },
            WalletLifecycleError::AlreadyDisposed,
            WalletLifecycleError::ClockError {
                detail: "test clock error".to_owned(),
                source: None,
            },
        ];
        for v in variants {
            // Debug must not expose secret material — just verify it compiles
            // and produces a non-empty string.
            assert!(!format!("{v:?}").is_empty());
        }
    }

    #[test]
    fn no_secret_material_in_display() {
        // No variant carries seed material. Format every variant and assert
        // that neither the word "seed" nor a 32-byte-seed-shaped run (64 hex
        // characters) ever appears, so a future variant that formatted raw key
        // bytes would fail this guard.
        let variants: &[WalletLifecycleError] = &[
            WalletLifecycleError::MlockUnavailable {
                reason: "kernel refused".to_owned(),
                errno: 12,
            },
            WalletLifecycleError::Disposed,
            WalletLifecycleError::TtlInvalid {
                ttl_seconds: 0,
                reason: "must be > 0".to_owned(),
            },
            WalletLifecycleError::AlreadyDisposed,
            WalletLifecycleError::ClockError {
                detail: "system clock is before UNIX_EPOCH".to_owned(),
                source: None,
            },
        ];
        for v in variants {
            let display = format!("{v}");
            assert!(
                !display.contains("seed"),
                "seed must not appear in error: {display}"
            );
            let has_seed_shaped_hex_run = display
                .as_bytes()
                .windows(64)
                .any(|w| w.iter().all(u8::is_ascii_hexdigit));
            assert!(
                !has_seed_shaped_hex_run,
                "no 32-byte-seed-shaped hex run may appear in error: {display}"
            );
        }
    }
}
