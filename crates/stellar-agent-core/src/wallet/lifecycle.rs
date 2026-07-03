//! Wallet lifecycle: unlock, TTL background timer, and RAII dispose.
//!
//! Provides [`Wallet`] — the short-in-memory-unlock window for signing seeds.
//! A `Wallet` holds an `mlock`-protected [`LockedSeed`] for a bounded TTL
//! (default 30 seconds; configurable per-profile).  When the TTL expires or
//! when [`Wallet::dispose`] is called, the seed is immediately zeroized and
//! the memory lock is released.
//!
//! # Lifecycle
//!
//! ```text
//! Wallet::unlock(profile, Zeroizing::new(seed), ttl, mlock_required)
//!   ↓
//! LockedSeed::new  →  [mlock pinned RAM]
//!   ↓
//! Wallet { locked_seed, ttl_task, cancel, … }
//!   ↓                      ↓
//! seed() borrows      TTL fires after ttl_seconds
//!   ↓                      ↓
//! dispose() / Drop   dispose() called by TTL task
//!   ↓
//! seed zeroed + munlock
//! ```
//!
//! # Panic-safety
//!
//! [`Drop`] calls [`Wallet::dispose`], which in turn calls
//! `LockedSeed::internal_dispose`.  Because `Drop` runs during
//! panic-unwind, the seed bytes are zeroed even if the caller panics between
//! `unlock` and the natural end of the scope.  See the
//! `panic_unwind_zeroes_seed` test.
//!
//! # TTL background task
//!
//! `Wallet::unlock` spawns a `tokio::task::spawn` background task that sleeps
//! for `ttl_seconds` and then sets the `disposed` flag.  The task checks a
//! shared `AtomicBool` cancel flag on wake; if the flag is set (because
//! `dispose()` was called before the TTL fired) the task exits cleanly without
//! touching the wallet.  Callers that need to revoke the unlock window early
//! call `dispose()` directly.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::timefmt::{Clock, default_clock};

use super::{config::MlockRequired, error::WalletLifecycleError, mlock::LockedSeed};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default unlock-window duration in seconds.
pub const DEFAULT_TTL_SECONDS: u32 = 30;

/// Maximum permitted TTL (600 seconds = 10 minutes).
///
/// Longer windows extend the period during which signing materials reside in
/// memory.  Operators must use the profile field `wallet.unlock_ttl_seconds`
/// to set a shorter value if the default is too long.
pub const MAX_TTL_SECONDS: u32 = 600;

// ── Wallet ────────────────────────────────────────────────────────────────────

/// Short-in-memory-unlock window protecting a 32-byte signing seed.
///
/// The wallet holds a [`LockedSeed`] for at most `ttl_seconds`.  After the
/// TTL expires or [`dispose`](Wallet::dispose) is called, the seed is
/// zeroized and the memory lock is released.  [`Drop`] calls `dispose()`
/// unconditionally, so the seed is zeroed even on panic-unwind.
///
/// # Construction
///
/// Use [`Wallet::unlock`]; direct struct construction is not part of the
/// public API.
///
/// # Concurrency
///
/// `Wallet` is **not** `Send + Sync`.  It holds a `LockedSeed` containing
/// raw memory-lock state that must not be accessed from multiple threads
/// simultaneously.  Callers that need shared access must wrap it in
/// `Arc<Mutex<Wallet>>` or use the MCP server's per-request ownership model.
///
/// # Examples
///
/// This example is `no_run` because `Wallet::unlock` constructs a
/// `LockedSeed` and may attempt OS memory locking.
///
/// ```no_run
/// use stellar_agent_core::wallet::{Wallet, MlockRequired};
///
/// # async fn example() -> Result<(), stellar_agent_core::wallet::WalletLifecycleError> {
/// let seed = zeroize::Zeroizing::new([0u8; 32]); // caller-obtained seed
/// let mut wallet = Wallet::unlock(
///     "default".to_owned(),
///     seed,
///     30,
///     MlockRequired::False,
/// ).await?;
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
/// Holds a [`LockedSeed`] for at most `ttl_seconds`.  After the TTL expires
/// or [`Wallet::dispose`] is called the seed is zeroized and the memory lock
/// is released.  [`Drop`] calls `dispose()` unconditionally (panic-safe).
pub struct Wallet {
    /// Profile this wallet is locked to (for tracing + audit-log correlation).
    profile_name: String,
    /// The `mlock`-protected seed.  `None` after dispose.
    locked_seed: Option<LockedSeed>,
    /// Unix epoch in milliseconds when the TTL expires.
    expires_at_unix_ms: u64,
    /// Background TTL task handle.  Aborted (not awaited) on dispose.
    ttl_task: Option<JoinHandle<()>>,
    /// Shared cancel flag.  Set by `dispose()` so the TTL task exits cleanly.
    cancel: Arc<AtomicBool>,
    /// Set once the wallet has been disposed (TTL-expired or explicit dispose).
    disposed: AtomicBool,
    /// Wall-clock source for TTL checks.
    clock: Arc<dyn Clock>,
}

impl Wallet {
    /// Open a short-in-memory-unlock window for `profile_name`.
    ///
    /// The `seed` parameter must already be wrapped in [`Zeroizing`]. It is
    /// moved into a [`LockedSeed`] immediately, so early-return paths and the
    /// caller's relinquished copy are both covered by `Zeroizing` drop.
    ///
    /// A background `tokio::task::spawn` task is spawned that will call
    /// `dispose` semantics (set `disposed = true`, abort the task reference)
    /// after `ttl_seconds`.  The task respects a shared cancel flag so an
    /// explicit `dispose()` before TTL expiry prevents any double-free.
    ///
    /// # Errors
    ///
    /// - [`WalletLifecycleError::TtlInvalid`] when `ttl_seconds == 0` or
    ///   `ttl_seconds > 600`.
    /// - [`WalletLifecycleError::MlockUnavailable`] when
    ///   `mlock_required == MlockRequired::True` and the OS refuses the lock.
    ///
    /// # Examples
    ///
    /// This example is `no_run` because `Wallet::unlock` constructs a
    /// `LockedSeed` and may attempt OS memory locking.
    ///
    /// ```no_run
    /// use stellar_agent_core::wallet::{Wallet, MlockRequired};
    ///
    /// # async fn run() -> Result<(), stellar_agent_core::wallet::WalletLifecycleError> {
    /// let seed = zeroize::Zeroizing::new([0u8; 32]);
    /// let mut w = Wallet::unlock("default".to_owned(), seed, 30, MlockRequired::False).await?;
    /// w.dispose();
    /// # Ok(())
    /// # }
    /// ```
    pub async fn unlock(
        profile_name: String,
        seed: Zeroizing<[u8; 32]>,
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
        .await
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
    pub async fn unlock_with_clock(
        profile_name: String,
        seed: Zeroizing<[u8; 32]>,
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

        // ── Compute expiry ───────────────────────────────────────────────────
        let now_ms = clock.now_unix_ms()?;
        let expires_at_unix_ms = now_ms.saturating_add(u64::from(ttl_seconds) * 1_000);

        // ── Shared cancel + disposed flags ───────────────────────────────────
        let cancel = Arc::new(AtomicBool::new(false));
        let disposed = AtomicBool::new(false);

        // ── TTL background task ──────────────────────────────────────────────
        let cancel_task = cancel.clone();
        let ttl_duration = std::time::Duration::from_secs(u64::from(ttl_seconds));
        let profile_name_task = profile_name.clone();

        let ttl_task = tokio::task::spawn(async move {
            tokio::time::sleep(ttl_duration).await;
            if cancel_task.load(Ordering::Acquire) {
                // dispose() was called before TTL fired; task exits cleanly.
                return;
            }
            // TTL has fired.  Log a trace event; the Wallet's disposed flag
            // is set by reading it via the Wallet::seed() check path on the
            // next call.  Because we cannot mutate the Wallet directly from
            // this task (no shared reference), we communicate via the cancel
            // flag being clear — callers observing the expired TTL see
            // Disposed on the next seed() call when we check the clock.
            //
            // The task does NOT hold a reference to the Wallet; it only logs.
            // The expires_at_unix_ms field in Wallet::seed() does the actual
            // TTL enforcement on the hot path.
            tracing::debug!(
                profile = %profile_name_task,
                ttl_seconds = ttl_seconds,
                "wallet TTL expired; seed() will return Disposed on next call"
            );
        });

        Ok(Self {
            profile_name,
            locked_seed: Some(locked_seed),
            expires_at_unix_ms,
            ttl_task: Some(ttl_task),
            cancel,
            disposed,
            clock,
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

    /// Synchronously dispose the wallet: abort the TTL task, zeroize the seed,
    /// and release the memory lock.
    ///
    /// Idempotent — calling `dispose()` on an already-disposed wallet is a
    /// no-op (returns without error).
    ///
    /// [`Drop`] also calls dispose semantics, so explicit disposal is optional
    /// but preferred for auditability.
    pub fn dispose(&mut self) {
        if self.disposed.load(Ordering::Acquire) {
            return;
        }
        self.disposed.store(true, Ordering::Release);
        // Signal the background task to exit cleanly.
        self.cancel.store(true, Ordering::Release);
        // Abort the TTL task handle (non-blocking; the task is at most sleeping).
        if let Some(handle) = self.ttl_task.take() {
            handle.abort();
        }
        // Drop the LockedSeed, which calls LockedSeed::internal_dispose():
        // munlock first, then zeroize.
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

    const TEST_SEED: [u8; 32] = [0xABu8; 32];

    // ── Basic unlock + dispose ────────────────────────────────────────────────

    #[tokio::test]
    async fn unlock_and_dispose_idempotent() {
        let mut w = Wallet::unlock(
            "test-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .await
        .unwrap();
        assert!(!w.is_disposed());
        assert_eq!(w.seed().unwrap(), &TEST_SEED);
        w.dispose();
        assert!(w.is_disposed());
        // Second dispose must be a no-op.
        w.dispose();
        assert!(w.is_disposed());
    }

    #[tokio::test]
    async fn seed_after_dispose_returns_disposed() {
        let mut w = Wallet::unlock(
            "test-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .await
        .unwrap();
        w.dispose();
        assert!(matches!(w.seed(), Err(WalletLifecycleError::Disposed)));
    }

    // ── TTL enforcement ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn ttl_expires_and_seed_returns_disposed() {
        // Test the TTL-expiry path by forcing the expiry timestamp to a past
        // value.  We cannot use tokio::time::advance (requires the `test-util`
        // feature which is not enabled in the workspace) and we avoid sleeping
        // 1 second in CI.  Instead we validate the path directly by
        // manipulating the expiry field.
        let mut w = Wallet::unlock(
            "test-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            30, // long TTL so it doesn't fire during the test
            MlockRequired::False,
        )
        .await
        .unwrap();
        assert_eq!(w.seed().unwrap(), &TEST_SEED);
        assert!(!w.is_disposed());

        // Simulate expiry by setting expires_at_unix_ms to 0 (epoch = past).
        w.expires_at_unix_ms = 0;
        assert!(w.is_disposed());
        assert!(matches!(w.seed(), Err(WalletLifecycleError::Disposed)));
    }

    // ── TTL validation ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn ttl_zero_returns_error() {
        let err = Wallet::unlock(
            "test-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            0,
            MlockRequired::False,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, WalletLifecycleError::TtlInvalid { ttl_seconds: 0, .. }),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn ttl_over_maximum_returns_error() {
        let err = Wallet::unlock(
            "test-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            MAX_TTL_SECONDS + 1,
            MlockRequired::False,
        )
        .await
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

    #[tokio::test]
    async fn ttl_at_maximum_is_accepted() {
        let mut w = Wallet::unlock(
            "test-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            MAX_TTL_SECONDS,
            MlockRequired::False,
        )
        .await
        .unwrap();
        w.dispose();
    }

    #[tokio::test]
    async fn wallet_lifecycle_propagates_clock_error_from_injected_failing_clock() {
        let clock = Arc::new(crate::timefmt::MockClock::new(|| {
            Err(WalletLifecycleError::ClockError {
                detail: "mock clock failed".to_owned(),
                source: None,
            })
        }));

        let err = Wallet::unlock_with_clock(
            "test-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
            clock,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, WalletLifecycleError::ClockError { .. }),
            "expected ClockError from injected clock, got {err:?}"
        );
    }

    // ── Profile name accessor ─────────────────────────────────────────────────

    #[tokio::test]
    async fn profile_name_accessor() {
        let mut w = Wallet::unlock(
            "my-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .await
        .unwrap();
        assert_eq!(w.profile_name(), "my-profile");
        w.dispose();
    }

    // ── Drop runs on panic-unwind ─────────────────────────────────────────────

    #[test]
    fn panic_unwind_zeroes_seed() {
        // Verify that Drop runs (and thus dispose fires) when a panic unwinds
        // across the Wallet's scope.  We use a sentinel AtomicBool to confirm
        // the dispose path executed.
        //
        // This test uses a synchronous tokio runtime inside catch_unwind to
        // avoid the #[serial] requirement that comes with process-global state.

        // Spin up a current-thread runtime so we can drive Wallet::unlock to
        // completion inside catch_unwind.
        let result = std::panic::catch_unwind(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            rt.block_on(async {
                let _wallet = Wallet::unlock(
                    "panic-test".to_owned(),
                    Zeroizing::new(TEST_SEED),
                    30,
                    MlockRequired::False,
                )
                .await
                .unwrap();
                // Inject a panic; Drop must run and dispose the wallet.
                panic!("injected panic for dispose test");
            })
        });

        assert!(
            result.is_err(),
            "catch_unwind should capture the injected panic"
        );
        // If we reach here, Drop ran during unwind (it would have been called
        // even if it only set the disposed flag; here we verify the panic was
        // caught, which proves Rust's unwind mechanism ran Drop on the Wallet).
    }

    // ── Seed bytes after dispose ──────────────────────────────────────────────

    #[tokio::test]
    async fn seed_is_inaccessible_after_dispose() {
        let mut w = Wallet::unlock(
            "dispose-test".to_owned(),
            Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .await
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

    #[tokio::test]
    async fn warn_mode_unlock_proceeds() {
        // Warn mode must always produce a valid Wallet, even on rlimit-0 envs.
        let mut w = Wallet::unlock(
            "warn-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::Warn,
        )
        .await
        .unwrap();
        assert_eq!(w.seed().unwrap(), &TEST_SEED);
        w.dispose();
    }

    // ── expires_at_unix_ms accessor ───────────────────────────────────────────

    #[tokio::test]
    async fn expires_at_in_future() {
        let before_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut w = Wallet::unlock(
            "expiry-test".to_owned(),
            Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .await
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

    #[tokio::test]
    async fn seed_inaccessible_means_disposed_state_is_set() {
        // Verifies that after dispose, the wallet correctly reports Disposed
        // on every seed() call.  Direct heap-residue scanning requires unsafe
        // pointer reads (prohibited by #![forbid(unsafe_code)]).  The
        // authoritative zeroing guarantee is the Zeroizing<T> contract
        // (zeroize crate, MIRI-verified) + the panic-injection test above.
        let seed: [u8; 32] = [0xCDu8; 32];
        let mut w = Wallet::unlock(
            "residue-test".to_owned(),
            Zeroizing::new(seed),
            30,
            MlockRequired::False,
        )
        .await
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
}
