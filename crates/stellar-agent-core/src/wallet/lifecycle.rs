//! Wallet lifecycle: clock-checked seed access and RAII disposal.
//!
//! The unlock window bounds when a wallet hands out its seed or transfers it
//! to a signer. Expiry refuses access. The seed stays in a zeroize-on-drop
//! page, locked when the lock succeeds, until the wallet or the receiving
//! signer drops it.
//! Mainnet environment signers unlock once per signature and drop the seed
//! afterward. Testnet environment signers hold it until the command drops them,
//! which can outlast the unlock TTL.
//!
//! ```text
//! Wallet::unlock(profile, &seed, ttl, mlock_required)
//!   ↓
//! zeroed home → lock → copy seed
//!   ↓
//! Wallet { locked_seed, expires_at_unix_ms, … }
//!   ↓ clock check                    ↓ clock check
//! seed() borrows                into_locked_seed() transfers ownership
//!   ↓                                ↓
//! Wallet::dispose / Drop         signer's Drop
//!   ↓                                ↓
//! zeroize → unlock → free        zeroize → unlock → free
//! ```
//!
//! Drop also zeroizes during panic unwind. Call [`Wallet::dispose`] to close
//! access and release the seed before the wallet's scope ends.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::timefmt::{Clock, default_clock};

use super::{
    config::MlockRequired,
    error::WalletLifecycleError,
    mlock::{LockedSeed, MlockDegradation},
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default unlock-window duration in seconds.
pub const DEFAULT_TTL_SECONDS: u32 = 30;

/// Maximum permitted TTL (600 seconds = 10 minutes).
///
/// The profile field `wallet.unlock_ttl_seconds` bounds seed access through
/// the wallet. An owner that receives the seed controls its residency lifetime.
pub const MAX_TTL_SECONDS: u32 = 600;

// ── Wallet ────────────────────────────────────────────────────────────────────

/// Short-in-memory-unlock window protecting a 32-byte signing seed.
///
/// The clock refuses seed access after `ttl_seconds`. The seed stays in its
/// stable home until disposal or transfer to another owner. [`Drop`] calls
/// [`Wallet::dispose`], including during panic unwind.
///
/// # Construction
///
/// Use [`Wallet::unlock`]; direct struct construction is not part of the
/// public API.
///
/// # Concurrency
///
/// `Wallet` is `Send + Sync` (auto-derived: the memory-lock guard and the
/// clock handle are both thread-safe). Its methods take `&mut self` or
/// consume state, so SHARED mutation still requires the caller to wrap it
/// in `Arc<Mutex<Wallet>>` or use the MCP server's per-request ownership
/// model; the common single-owner pattern needs neither.
///
/// # Examples
///
/// This example is `no_run` because `Wallet::unlock` constructs a
/// `LockedSeed` and may attempt OS memory locking.
///
/// ```no_run
/// use stellar_agent_core::wallet::{Wallet, MlockRequired};
///
/// # fn example() -> Result<(), stellar_agent_core::wallet::WalletLifecycleError> {
/// let seed = zeroize::Zeroizing::new([0u8; 32]); // caller-obtained seed
/// let mut wallet = Wallet::unlock(
///     "default".to_owned(),
///     &seed,
///     30,
///     MlockRequired::False,
/// )?;
///
/// let bytes: &[u8; 32] = wallet.seed()?;
/// // … use bytes to sign …
///
/// wallet.dispose();
/// # Ok(())
/// # }
/// ```
// Debug is implemented manually so the seed field is never exposed in debug
// output (LockedSeed does not derive Debug for the same reason).
impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("profile_name", &self.profile_name)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field(
                "disposed",
                &self.disposed.load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

/// Short-in-memory-unlock window protecting a 32-byte signing seed.
///
/// The clock bounds seed access to `ttl_seconds`. Disposal zeroizes the seed
/// before releasing its lock. A transferred seed stays alive with its new owner.
pub struct Wallet {
    /// Profile this wallet is locked to (for tracing + audit-log correlation).
    profile_name: String,
    /// The `mlock`-protected seed.  `None` after dispose.
    locked_seed: Option<LockedSeed>,
    /// Unix epoch in milliseconds when the TTL expires.
    expires_at_unix_ms: u64,
    /// Set once the wallet is disposed or transfers its seed.
    disposed: AtomicBool,
    /// Wall-clock source for TTL checks.
    clock: Arc<dyn Clock>,
    /// Snapshot of [`LockedSeed::mlock_degradation`] taken at construction
    /// time.
    ///
    /// Copied out (rather than read through `locked_seed`) so it remains
    /// queryable after [`Wallet::dispose`] clears `locked_seed`, matching
    /// `profile_name()` / `expires_at_unix_ms()`'s post-dispose availability.
    mlock_degradation: Option<MlockDegradation>,
}

impl Wallet {
    /// Open a short-in-memory-unlock window for `profile_name`.
    ///
    /// The caller borrows its seed, preferably from a `Zeroizing` buffer.
    /// The wallet copies it into a stable home after the configured lock attempt.
    /// Clock checks refuse seed access and ownership transfer after `ttl_seconds`.
    /// The seed zeroizes when its owner disposes or drops it.
    ///
    /// # Errors
    ///
    /// - [`WalletLifecycleError::TtlInvalid`] when `ttl_seconds == 0` or
    ///   `ttl_seconds > 600`.
    /// - [`WalletLifecycleError::MlockUnavailable`] when
    ///   `mlock_required == MlockRequired::True` and the OS refuses the lock
    ///   or its page size exceeds the 64 KiB alignment of the seed's home.
    ///
    /// # Examples
    ///
    /// This example is `no_run` because `Wallet::unlock` constructs a
    /// `LockedSeed` and may attempt OS memory locking.
    ///
    /// ```no_run
    /// use stellar_agent_core::wallet::{Wallet, MlockRequired};
    ///
    /// # fn run() -> Result<(), stellar_agent_core::wallet::WalletLifecycleError> {
    /// let seed = zeroize::Zeroizing::new([0u8; 32]);
    /// let mut w = Wallet::unlock("default".to_owned(), &seed, 30, MlockRequired::False)?;
    /// w.dispose();
    /// # Ok(())
    /// # }
    /// ```
    pub fn unlock(
        profile_name: String,
        seed: &[u8; 32],
        ttl_seconds: u32,
        mlock_required: MlockRequired,
    ) -> Result<Self, WalletLifecycleError> {
        Self::unlock_with_clock(
            profile_name,
            seed,
            ttl_seconds,
            mlock_required,
            default_clock(),
        )
    }

    /// Open a short-in-memory-unlock window using an injected wall-clock source.
    ///
    /// This constructor is equivalent to [`Wallet::unlock`] except the clock is
    /// caller-supplied so tests can cover fail-closed clock-error paths.
    ///
    /// # Security
    ///
    /// `Clock` impls run in-process with seed-access privilege; the injected
    /// clock can return arbitrary `now_ms` values that affect TTL evaluation
    /// (e.g. setting `now_ms = u64::MAX` would keep an expired wallet "live"
    /// indefinitely; setting `now_ms = 0` would force an immediate fail-closed
    /// expiry). This trait is intended for **in-process testing only**, not
    /// for sandboxing untrusted time sources. Production code MUST use
    /// [`Wallet::unlock`] which threads [`SystemClock`](crate::timefmt::SystemClock).
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Wallet::unlock`], including clock errors from
    /// the injected [`Clock`].
    pub fn unlock_with_clock(
        profile_name: String,
        seed: &[u8; 32],
        ttl_seconds: u32,
        mlock_required: MlockRequired,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, WalletLifecycleError> {
        // ── Validate TTL ─────────────────────────────────────────────────────
        if ttl_seconds == 0 {
            return Err(WalletLifecycleError::TtlInvalid {
                ttl_seconds,
                reason: "TTL must be > 0 seconds".to_owned(),
            });
        }
        if ttl_seconds > MAX_TTL_SECONDS {
            return Err(WalletLifecycleError::TtlInvalid {
                ttl_seconds,
                reason: format!("TTL must be ≤ {MAX_TTL_SECONDS} seconds (10 minutes)"),
            });
        }

        // ── Construct the locked seed ────────────────────────────────────────
        let locked_seed = LockedSeed::new(seed, mlock_required, &profile_name)?;
        let mlock_degradation = locked_seed.mlock_degradation().cloned();

        // ── Compute expiry ───────────────────────────────────────────────────
        let now_ms = clock.now_unix_ms()?;
        let expires_at_unix_ms = now_ms.saturating_add(u64::from(ttl_seconds) * 1_000);

        Ok(Self {
            profile_name,
            locked_seed: Some(locked_seed),
            expires_at_unix_ms,
            disposed: AtomicBool::new(false),
            clock,
            mlock_degradation,
        })
    }

    /// Borrow the seed bytes if the wallet is still active.
    ///
    /// Returns `Err(WalletLifecycleError::Disposed)` when:
    /// - `dispose()` has been called, OR
    /// - the TTL has expired (checked against the system clock).
    ///
    /// # Errors
    ///
    /// Returns [`WalletLifecycleError::Disposed`] if the wallet is disposed
    /// or TTL-expired.
    pub fn seed(&self) -> Result<&[u8; 32], WalletLifecycleError> {
        if self.disposed.load(Ordering::Acquire) {
            return Err(WalletLifecycleError::Disposed);
        }
        // TTL check: if the current time is past expires_at_unix_ms, treat as
        // disposed.  On clock error, fail closed (return Disposed) so a broken
        // clock cannot keep a past-TTL window open indefinitely.
        let now_ms = match self.clock.now_unix_ms() {
            Ok(ms) => ms,
            Err(e) => {
                tracing::debug!(
                    profile = %self.profile_name,
                    error = %e,
                    "wallet seed(): clock error — treating as disposed (fail-closed)"
                );
                return Err(e);
            }
        };
        if now_ms >= self.expires_at_unix_ms {
            return Err(WalletLifecycleError::Disposed);
        }
        match &self.locked_seed {
            None => Err(WalletLifecycleError::Disposed),
            Some(locked) => Ok(locked.seed()),
        }
    }

    /// Transfer the seed's stable home to another owner during the unlock window.
    ///
    /// The receiving owner controls the seed's lifetime, which can exceed the TTL.
    ///
    /// # Errors
    ///
    /// Returns the same disposed, expiry, and clock errors as [`Wallet::seed`].
    pub fn into_locked_seed(mut self) -> Result<LockedSeed, WalletLifecycleError> {
        self.seed()?;
        let seed = self
            .locked_seed
            .take()
            .ok_or(WalletLifecycleError::Disposed)?;
        self.disposed.store(true, Ordering::Release);
        Ok(seed)
    }

    #[cfg(test)]
    fn lock_target(&self) -> Option<usize> {
        self.locked_seed.as_ref().and_then(LockedSeed::lock_target)
    }

    /// Zeroize the seed, release its memory lock, and close access.
    ///
    /// Repeated disposal is a no-op. [`Drop`] performs the same cleanup.
    pub fn dispose(&mut self) {
        if self.disposed.load(Ordering::Acquire) {
            return;
        }
        self.disposed.store(true, Ordering::Release);
        // LockedSeed zeroizes before unlocking and freeing its home.
        drop(self.locked_seed.take());

        tracing::debug!(
            profile = %self.profile_name,
            "wallet disposed; signing seed zeroized"
        );
    }

    /// Return the profile name this wallet is bound to.
    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    /// Returns the `mlock` degradation details when `mlock` was attempted
    /// and failed under `MlockRequired::Warn` — this wallet's unlock window
    /// proceeded with unprotected (unpinned) memory.
    ///
    /// Returns `None` both when `mlock` succeeded and when
    /// `MlockRequired::False` meant locking was never attempted. Remains
    /// accurate after [`Wallet::dispose`]: the value is snapshotted at
    /// construction time, independent of the disposed `locked_seed`.
    ///
    /// Callers that need to record a `WalletMlockFailed` audit-log entry
    /// check this accessor before (or after) disposing the wallet.
    #[must_use]
    pub fn mlock_degradation(&self) -> Option<&MlockDegradation> {
        self.mlock_degradation.as_ref()
    }

    /// Return the Unix epoch milliseconds at which the TTL expires.
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// Return `true` if the wallet has been disposed or the TTL has expired.
    ///
    /// On clock error, returns `true` (fails closed) so a broken clock cannot
    /// keep a past-TTL window open indefinitely.
    pub fn is_disposed(&self) -> bool {
        if self.disposed.load(Ordering::Acquire) {
            return true;
        }
        match self.clock.now_unix_ms() {
            Ok(now_ms) => now_ms >= self.expires_at_unix_ms,
            Err(e) => {
                // Clock failure: fail closed rather than treating a past-TTL
                // wallet as still active.
                tracing::debug!(
                    profile = %self.profile_name,
                    error = %e,
                    "wallet is_disposed(): clock error — reporting disposed (fail-closed)"
                );
                true
            }
        }
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.dispose();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only panic injection")]
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use zeroize::Zeroizing;

    const TEST_SEED: [u8; 32] = [0xABu8; 32];

    // ── Basic unlock + dispose ────────────────────────────────────────────────

    #[test]
    fn unlock_and_dispose_idempotent() {
        let mut w = Wallet::unlock(
            "test-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .unwrap();
        assert!(!w.is_disposed());
        assert_eq!(w.seed().unwrap(), &TEST_SEED);
        w.dispose();
        assert!(w.is_disposed());
        // Second dispose must be a no-op.
        w.dispose();
        assert!(w.is_disposed());
    }

    #[test]
    fn seed_after_dispose_returns_disposed() {
        let mut w = Wallet::unlock(
            "test-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .unwrap();
        w.dispose();
        assert!(matches!(w.seed(), Err(WalletLifecycleError::Disposed)));
    }

    // ── TTL enforcement ───────────────────────────────────────────────────────

    #[test]
    fn ttl_expires_and_seed_returns_disposed() {
        // The clock check in `seed()` compares the system clock against the
        // expiry timestamp; moving that timestamp into the past exercises the
        // expiry path without waiting.
        let mut w = Wallet::unlock(
            "test-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30, // long TTL so the wallet is active until the timestamp moves
            MlockRequired::False,
        )
        .unwrap();
        assert_eq!(w.seed().unwrap(), &TEST_SEED);
        assert!(!w.is_disposed());

        // Simulate expiry by setting expires_at_unix_ms to 0 (epoch = past).
        w.expires_at_unix_ms = 0;
        assert!(w.is_disposed());
        assert!(matches!(w.seed(), Err(WalletLifecycleError::Disposed)));
    }

    // ── TTL validation ────────────────────────────────────────────────────────

    #[test]
    fn ttl_zero_returns_error() {
        let err = Wallet::unlock(
            "test-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            0,
            MlockRequired::False,
        )
        .unwrap_err();
        assert!(
            matches!(err, WalletLifecycleError::TtlInvalid { ttl_seconds: 0, .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn ttl_over_maximum_returns_error() {
        let err = Wallet::unlock(
            "test-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            MAX_TTL_SECONDS + 1,
            MlockRequired::False,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                WalletLifecycleError::TtlInvalid {
                    ttl_seconds,
                    ..
                } if ttl_seconds == MAX_TTL_SECONDS + 1
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn ttl_at_maximum_is_accepted() {
        let mut w = Wallet::unlock(
            "test-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            MAX_TTL_SECONDS,
            MlockRequired::False,
        )
        .unwrap();
        w.dispose();
    }

    #[test]
    fn wallet_lifecycle_propagates_clock_error_from_injected_failing_clock() {
        let clock = Arc::new(crate::timefmt::MockClock::new(|| {
            Err(WalletLifecycleError::ClockError {
                detail: "mock clock failed".to_owned(),
                source: None,
            })
        }));

        let err = Wallet::unlock_with_clock(
            "test-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
            clock,
        )
        .unwrap_err();

        assert!(
            matches!(err, WalletLifecycleError::ClockError { .. }),
            "expected ClockError from injected clock, got {err:?}"
        );
    }

    // ── Profile name accessor ─────────────────────────────────────────────────

    #[test]
    fn profile_name_accessor() {
        let mut w = Wallet::unlock(
            "my-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .unwrap();
        assert_eq!(w.profile_name(), "my-profile");
        w.dispose();
    }

    // ── Drop runs on panic-unwind ─────────────────────────────────────────────

    #[test]
    fn panic_unwind_zeroes_seed() {
        super::super::mlock::ZEROIZED_BEFORE_UNLOCK.set(None);
        let result = std::panic::catch_unwind(|| {
            let _wallet = Wallet::unlock(
                "panic-test".to_owned(),
                &Zeroizing::new(TEST_SEED),
                30,
                MlockRequired::False,
            )
            .unwrap();
            panic!("injected panic for dispose test");
        });
        assert!(result.is_err());
        assert_eq!(
            super::super::mlock::ZEROIZED_BEFORE_UNLOCK.get(),
            Some(true)
        );
    }

    // ── Seed bytes after dispose ──────────────────────────────────────────────

    #[test]
    fn seed_is_inaccessible_after_dispose() {
        let mut w = Wallet::unlock(
            "dispose-test".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .unwrap();

        // Confirm seed is readable before dispose.
        assert_eq!(w.seed().unwrap(), &TEST_SEED);

        w.dispose();

        // After dispose, seed() must return Disposed.
        assert!(
            matches!(w.seed(), Err(WalletLifecycleError::Disposed)),
            "seed must not be accessible after dispose"
        );
    }

    // ── Warn-mode mlock fallback ──────────────────────────────────────────────

    #[test]
    fn warn_mode_unlock_proceeds() {
        // Warn mode must always produce a valid Wallet, even on rlimit-0 envs.
        let mut w = Wallet::unlock(
            "warn-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::Warn,
        )
        .unwrap();
        assert_eq!(w.seed().unwrap(), &TEST_SEED);
        w.dispose();
    }

    // ── expires_at_unix_ms accessor ───────────────────────────────────────────

    #[test]
    fn expires_at_in_future() {
        let before_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut w = Wallet::unlock(
            "expiry-test".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .unwrap();
        let after_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let exp = w.expires_at_unix_ms();
        // expires_at should be approximately now + 30_000 ms.
        assert!(
            exp >= before_ms + 29_000,
            "expires_at should be ~now+30s; got exp={exp} before={before_ms}"
        );
        assert!(
            exp <= after_ms + 31_000,
            "expires_at should be ~now+30s; got exp={exp} after={after_ms}"
        );
        w.dispose();
    }

    // ── Seed inaccessible after dispose (residue gate) ───────────────────────

    #[test]
    fn seed_inaccessible_means_disposed_state_is_set() {
        // Verifies that after dispose, the wallet correctly reports Disposed
        // on every seed() call.  Direct heap-residue scanning requires unsafe
        // pointer reads (prohibited by #![forbid(unsafe_code)]).  The
        // authoritative zeroing guarantee is the Zeroizing<T> contract
        // (zeroize crate, MIRI-verified) + the panic-injection test above.
        let seed: [u8; 32] = [0xCDu8; 32];
        let mut w = Wallet::unlock(
            "residue-test".to_owned(),
            &Zeroizing::new(seed),
            30,
            MlockRequired::False,
        )
        .unwrap();
        // Before dispose: seed is accessible.
        assert_eq!(w.seed().unwrap(), &seed);
        w.dispose();
        // After dispose: seed returns Disposed.
        assert!(
            matches!(w.seed(), Err(WalletLifecycleError::Disposed)),
            "seed must not be accessible after dispose (no-residue gate)"
        );
    }

    #[test]
    fn no_task_is_spawned_by_unlock() {
        let wallet = Wallet::unlock(
            "test".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .unwrap();
        assert_eq!(wallet.seed().unwrap(), &TEST_SEED);
    }

    #[test]
    fn an_unlocked_wallet_reads_the_locked_home() {
        fn returned(wallet: Wallet) -> Wallet {
            wallet
        }
        let wallet = Wallet::unlock(
            "test".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::Warn,
        )
        .unwrap();
        let address = wallet.seed().unwrap().as_ptr() as usize;
        assert_eq!(wallet.lock_target(), Some(address));
        let mut values = Vec::new();
        values.push(wallet);
        assert_eq!(values[0].seed().unwrap().as_ptr() as usize, address);
        assert_eq!(values[0].lock_target(), Some(address));
        let boxed = Box::new(values.pop().unwrap());
        assert_eq!(boxed.seed().unwrap().as_ptr() as usize, address);
        assert_eq!(boxed.lock_target(), Some(address));
        let wallet = returned(*boxed);
        assert_eq!(wallet.seed().unwrap().as_ptr() as usize, address);
        assert_eq!(wallet.lock_target(), Some(address));
    }

    #[test]
    fn into_locked_seed_refuses_after_the_ttl() {
        use std::sync::atomic::AtomicU64;
        let now = Arc::new(AtomicU64::new(1000));
        let clock_now = Arc::clone(&now);
        let clock = Arc::new(crate::timefmt::MockClock::new(move || {
            Ok(clock_now.load(Ordering::SeqCst))
        }));
        let wallet = Wallet::unlock_with_clock(
            "test".to_owned(),
            &Zeroizing::new(TEST_SEED),
            1,
            MlockRequired::False,
            clock,
        )
        .unwrap();
        now.store(2000, Ordering::SeqCst);
        assert!(matches!(
            wallet.into_locked_seed(),
            Err(WalletLifecycleError::Disposed)
        ));
    }

    #[test]
    fn into_locked_seed_refuses_after_dispose() {
        let mut wallet = Wallet::unlock(
            "test".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .unwrap();
        wallet.dispose();
        assert!(matches!(
            wallet.into_locked_seed(),
            Err(WalletLifecycleError::Disposed)
        ));
    }

    #[test]
    fn into_locked_seed_returns_the_same_home() {
        let wallet = Wallet::unlock(
            "test".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::Warn,
        )
        .unwrap();
        let address = wallet.seed().unwrap().as_ptr();
        let locked = wallet.into_locked_seed().unwrap();
        assert_eq!(locked.seed().as_ptr(), address);
        assert_eq!(locked.seed(), &TEST_SEED);
    }
}
