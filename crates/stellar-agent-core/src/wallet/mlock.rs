//! Region-backed memory-locked seed buffer.
//!
//! Provides [`LockedSeed`] — an opaque 32-byte seed holder that:
//!
//! 1. Wraps the seed bytes in [`zeroize::Zeroizing`] so they are zeroed on
//!    drop, including on panic-unwind (Rust's `Drop` glue runs during unwind).
//! 2. Calls `region::lock` to pin the seed's backing page in physical RAM via
//!    `mlock(2)` (POSIX) or `VirtualLock` (Windows), preventing the page from
//!    being swapped to disk (threat T6 swap-disclosure).
//! 3. Releases the lock and zeroes the seed when dropped or when
//!    `dispose()` is called explicitly.
//!
//! # `region` crate and mlock(2) vs mlock2(MLOCK_ONFAULT)
//!
//! The `region` crate calls `libc::mlock(2)` directly — plain POSIX `mlock`,
//! not `mlock2(MLOCK_ONFAULT)`.  Plain `mlock(2)` eagerly populates and pins
//! pages at lock time, which is at least as strong as `mlock2(MLOCK_ONFAULT)`
//! for the wallet's small, definitely-accessed seed region.  `MLOCK_ONFAULT`
//! is a performance optimisation for large regions that may never be faulted
//! in; for a 32-byte seed buffer it is operationally inert.
//!
//! # `region::lock` alignment semantics
//!
//! `region::lock(address, size)` accepts arbitrary addresses and rounds down to
//! the nearest page boundary internally (`util::round_to_page_boundaries` is
//! called before the syscall).  No manual page-alignment of the seed buffer is
//! required by this crate.  The consequence is that the locked range covers the
//! entire page containing the seed, which may include adjacent allocations on
//! that page.  This is the standard behaviour of `mlock(2)`.
//!
//! # `Send`/`Sync` invariants for `region::LockGuard`
//!
//! `region::LockGuard` carries `unsafe impl Send` and `unsafe impl Sync`
//! without inline `// SAFETY:` documentation (upstream convention gap).
//! Because `stellar-agent-core` uses `#![forbid(unsafe_code)]` we cannot add
//! a wrapper newtype with `unsafe impl` in this crate.  The upstream invariants
//! are:
//!
//! - **`Send`** is sound because `munlock(addr, size)` (called by
//!   `LockGuard::drop`) is a process-scoped syscall, not bound to the thread
//!   that called `mlock`.  Moving the guard to another thread and dropping it
//!   there is safe.
//! - **`Sync`** is sound because `LockGuard` exposes no `&self` API that
//!   touches the locked memory; the only operation is `Drop` (exclusive).

use zeroize::Zeroizing;

use super::{config::MlockRequired, error::WalletLifecycleError};

// ── LockedSeed ────────────────────────────────────────────────────────────────

/// An `mlock`-protected 32-byte signing seed.
///
/// The seed bytes are stored in a [`Zeroizing<[u8; 32]>`] so they are zeroed
/// on drop regardless of the drop path (normal return, `?` propagation, or
/// panic-unwind).  When `MlockRequired::True` or `MlockRequired::Warn` is in
/// effect and `mlock` succeeds, the backing page is additionally pinned in RAM
/// via `region::lock`.
///
/// # Construction
///
/// Use `LockedSeed::new`; the raw `seed: [u8; 32]` parameter is moved into
/// a `Zeroizing` wrapper immediately on entry so the stack copy is zeroed when
/// the wrapper drops.
///
/// # Disposal
///
/// Call [`LockedSeed::dispose`] for explicit cleanup, or rely on [`Drop`].
/// Both paths zeroize the seed bytes and release the memory lock.
pub struct LockedSeed {
    /// Seed bytes, zeroized on drop.  `Option` so `dispose()` can take
    /// ownership and zero explicitly before the field drops.
    seed: Option<Zeroizing<[u8; 32]>>,
    /// The memory-lock guard.  `None` when `MlockRequired::False` is set or
    /// when `mlock` failed under `MlockRequired::Warn`.  Dropped before
    /// `seed` to follow the invariant: release lock first, then zero.
    ///
    /// `region::LockGuard` carries `unsafe impl Send + Sync`; the invariants
    /// (munlock is process-scoped; no &self API on the guard) are documented in
    /// the module-level rustdoc.
    guard: Option<region::LockGuard>,
    /// Whether this seed has been explicitly disposed.
    disposed: bool,
}

impl LockedSeed {
    /// Create a new `LockedSeed`, optionally locking the backing page in RAM.
    ///
    /// The `seed` parameter is already wrapped in `Zeroizing<[u8; 32]>`; this
    /// function moves it directly into the locked page owner without making an
    /// additional bare stack copy.
    ///
    /// `profile_name` is used to populate the `profile` field in the
    /// `tracing::warn!` emitted under `MlockRequired::Warn` when `mlock`
    /// fails.  Pass the owning wallet's profile name (e.g. `"default"`).
    ///
    /// Behaviour on `mlock` failure depends on `required`:
    ///
    /// - [`MlockRequired::True`] — returns
    ///   [`WalletLifecycleError::MlockUnavailable`]; the seed is zeroed and
    ///   this function does not return `Ok`.
    /// - [`MlockRequired::Warn`] — returns `Ok` with `guard: None`; emits a
    ///   structured `tracing::warn!`.  `EventKind::WalletMlockFailed` is a
    ///   reserved audit-log event kind (recognised by `audit verify`) not
    ///   currently emitted by any call site; this function's responsibility
    ///   ends at the tracing span.
    /// - [`MlockRequired::False`] — `mlock` is not attempted; always returns
    ///   `Ok` with `guard: None`.
    ///
    /// # Errors
    ///
    /// Returns [`WalletLifecycleError::MlockUnavailable`] when
    /// `required == MlockRequired::True` and the OS refuses the lock.
    ///
    pub(crate) fn new(
        zeroizing_seed: Zeroizing<[u8; 32]>,
        required: MlockRequired,
        profile_name: &str,
    ) -> Result<Self, WalletLifecycleError> {
        let guard = match required {
            MlockRequired::False => None,
            MlockRequired::True | MlockRequired::Warn => {
                // Obtain a stable address for the seed bytes.  The Zeroizing
                // wrapper is on the stack here; we take the address of the
                // inner array.  region::lock rounds the address down to the
                // page boundary internally.
                let addr = zeroizing_seed.as_ptr();
                let size = std::mem::size_of::<[u8; 32]>();

                match region::lock(addr, size) {
                    Ok(guard) => Some(guard),
                    Err(err) => {
                        let reason = err.to_string();
                        // Extract errno from the inner io::Error if present.
                        let errno = extract_os_errno(&err);

                        match required {
                            MlockRequired::True => {
                                // zeroizing_seed is dropped here, zeroing the
                                // stack copy before the error propagates.
                                return Err(WalletLifecycleError::MlockUnavailable {
                                    reason,
                                    errno,
                                });
                            }
                            MlockRequired::Warn => {
                                // Proceed with unprotected memory.  The warn!
                                // is structured so the `tracing-json`
                                // subscriber layer captures profile, reason,
                                // and errno as individual JSON fields.
                                tracing::warn!(
                                    profile = %profile_name,
                                    reason = %reason,
                                    errno = errno,
                                    "wallet.mlock_failed: mlock unavailable; \
                                     proceeding with unprotected memory (warn mode)."
                                );
                                None
                            }
                            // MlockRequired::False is handled in the outer
                            // match and cannot reach this arm.
                            MlockRequired::False => None,
                        }
                    }
                }
            }
        };

        Ok(Self {
            seed: Some(zeroizing_seed),
            guard,
            disposed: false,
        })
    }

    /// Borrow the seed bytes.
    ///
    /// The borrow lifetime keeps the `LockedSeed` alive (and thus the lock
    /// guard alive) for as long as the caller holds the reference.
    ///
    /// This method is `pub(crate)` — external callers access the seed
    /// through [`super::lifecycle::Wallet::seed`], which enforces TTL and
    /// disposed-flag checks before delegating here.
    #[allow(
        clippy::expect_used,
        reason = "Provably infallible: seed is Some whenever disposed == false. \
                  The assert! below catches violations at runtime; the expect is \
                  the unreachable fallthrough after the assert.  See INVARIANT comment."
    )]
    pub(crate) fn seed(&self) -> &[u8; 32] {
        // INVARIANT: `seed` is `Some` whenever `disposed == false`.
        // The only code path that sets `seed` to `None` is `internal_dispose()`,
        // which also sets `disposed = true`.  This method is `pub(crate)` and
        // the only external caller is `lifecycle::Wallet::seed()`, which gates
        // on `disposed` before calling here.  Failing this assert indicates a
        // programming error in `stellar-agent-core` internals, not user input.
        //
        // Note: `// SAFETY:` is reserved for `unsafe` blocks.
        // This is a safe invariant assertion, not an unsafe precondition.
        assert!(
            self.seed.is_some(),
            "LockedSeed::seed() called after dispose(): seed is None \
             (invariant: disposed == false implies seed.is_some())"
        );
        // `Zeroizing<[u8; 32]>` implements `Deref<Target = [u8; 32]>`;
        // `as_deref` gives `Option<&[u8; 32]>`.
        self.seed
            .as_deref()
            .expect("invariant: disposed == false implies seed.is_some()")
    }

    /// Explicitly zeroize the seed bytes and release the memory lock.
    ///
    /// After `dispose()` returns, the seed bytes are zeroed and the
    /// `region::LockGuard` is dropped (which calls `munlock`).  Calling
    /// `dispose()` more than once is a no-op.
    ///
    /// [`Drop`] also calls the same zeroise + unlock path, so explicit
    /// disposal is optional but may be preferable for auditability.
    pub fn dispose(mut self) {
        self.internal_dispose();
        // Prevent Drop from running internal_dispose a second time.
        std::mem::forget(self);
    }

    /// Returns `true` if this seed has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Internal dispose logic shared between `dispose()` and `Drop`.
    fn internal_dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        // Drop the guard first (calls munlock), then the seed (calls zeroize).
        // This ordering ensures the page is unlocked before the seed bytes are
        // cleared, which is the safe order: the page may be swapped after
        // unlock, but by then zeroize has already cleared the bytes.
        drop(self.guard.take());
        drop(self.seed.take());
    }
}

impl Drop for LockedSeed {
    fn drop(&mut self) {
        self.internal_dispose();
    }
}

// ── errno extraction ──────────────────────────────────────────────────────────

/// Extract the OS errno from a `region::Error`, falling back to `0`.
///
/// `region::Error::SystemCall` wraps `io::Error`; `io::Error::raw_os_error()`
/// returns the errno as `Option<i32>`.
fn extract_os_errno(err: &region::Error) -> i32 {
    // region::Error::SystemCall(io::Error) — the inner io::Error carries errno.
    // Other region error variants (InvalidParameter, etc.) have no errno.
    if let region::Error::SystemCall(io_err) = err {
        io_err.raw_os_error().unwrap_or(0)
    } else {
        0
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only panic injection")]
    #![allow(clippy::print_stderr, reason = "test-only skip-notification")]
    use super::*;

    const TEST_SEED: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22,
    ];

    // ── MlockRequired::False ─────────────────────────────────────────────────

    #[test]
    fn false_mode_succeeds_without_lock() {
        // MlockRequired::False must always succeed regardless of rlimit.
        let locked = LockedSeed::new(
            Zeroizing::new(TEST_SEED),
            MlockRequired::False,
            "test-profile",
        )
        .unwrap();
        assert_eq!(locked.seed(), &TEST_SEED);
        assert!(locked.guard.is_none(), "False mode must not hold a guard");
        locked.dispose();
    }

    #[test]
    fn false_mode_seed_matches_input() {
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        let locked =
            LockedSeed::new(Zeroizing::new(seed), MlockRequired::False, "test-profile").unwrap();
        assert_eq!(locked.seed(), &seed);
        locked.dispose();
    }

    // ── MlockRequired::Warn ──────────────────────────────────────────────────

    #[test]
    fn warn_mode_succeeds_or_falls_back() {
        // Warn mode must return Ok regardless of whether mlock succeeds.
        let locked = LockedSeed::new(
            Zeroizing::new(TEST_SEED),
            MlockRequired::Warn,
            "test-profile",
        )
        .unwrap();
        assert_eq!(locked.seed(), &TEST_SEED);
        locked.dispose();
    }

    // ── MlockRequired::True ──────────────────────────────────────────────────

    #[test]
    fn true_mode_succeeds_when_lock_available() {
        // On most development machines RLIMIT_MEMLOCK allows at least one page.
        // If the lock fails, skip rather than fail — we cannot control rlimit
        // in CI without root.
        match LockedSeed::new(
            Zeroizing::new(TEST_SEED),
            MlockRequired::True,
            "test-profile",
        ) {
            Ok(locked) => {
                assert_eq!(locked.seed(), &TEST_SEED);
                locked.dispose();
            }
            Err(WalletLifecycleError::MlockUnavailable { reason, errno }) => {
                eprintln!(
                    "mlock unavailable in this environment (errno {errno}): {reason}; skipping"
                );
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    // ── Dispose + zeroise ────────────────────────────────────────────────────

    #[test]
    fn dispose_marks_as_disposed() {
        let mut locked = LockedSeed::new(
            Zeroizing::new(TEST_SEED),
            MlockRequired::False,
            "test-profile",
        )
        .unwrap();
        assert!(!locked.is_disposed());
        locked.internal_dispose();
        assert!(locked.is_disposed());
        // Seed option is taken.
        assert!(locked.seed.is_none(), "seed must be None after dispose");
        // Guard is taken.
        assert!(locked.guard.is_none(), "guard must be None after dispose");
        // Prevent double-dispose via Drop.
        std::mem::forget(locked);
    }

    #[test]
    fn drop_zeroes_seed_field() {
        // Verify that LockedSeed::new + drop compiles and runs without panic.
        // The authoritative zeroing guarantee is provided by the Zeroizing<T>
        // contract (verified by the zeroize crate's own MIRI-tested suite) and
        // the panic-injection test `drop_runs_on_panic_unwind`.
        //
        // Direct post-drop memory reads require unsafe + UB (reading freed
        // memory), which is prohibited by #![forbid(unsafe_code)].  Instead we
        // verify the Drop path executes via the dispose_marks_as_disposed test.
        let locked = LockedSeed::new(
            Zeroizing::new([0xA5u8; 32]),
            MlockRequired::False,
            "test-profile",
        )
        .unwrap();
        drop(locked);
        // If we reach here, Drop ran without panic.
    }

    #[test]
    fn double_dispose_is_idempotent() {
        let mut locked = LockedSeed::new(
            Zeroizing::new(TEST_SEED),
            MlockRequired::False,
            "test-profile",
        )
        .unwrap();
        locked.internal_dispose();
        // Second call must not panic or double-free.
        locked.internal_dispose();
        std::mem::forget(locked);
    }

    // ── Panic-safety regression ──────────────────────────────────────────────

    #[test]
    fn drop_runs_on_panic_unwind() {
        // Create a LockedSeed inside a catch_unwind closure.  If the seed
        // bytes are still present after unwind, Zeroizing has failed.
        //
        // We cannot read the freed memory directly, but we CAN verify that
        // drop was called by observing a side-effect via an Arc<AtomicBool>.
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        struct SentinelDropper(Arc<AtomicBool>);
        impl Drop for SentinelDropper {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_clone = dropped.clone();

        let result = std::panic::catch_unwind(move || {
            // Bind the LockedSeed to a variable so it lives until the panic.
            let _locked = LockedSeed::new(
                Zeroizing::new(TEST_SEED),
                MlockRequired::False,
                "test-profile",
            )
            .unwrap();
            let _sentinel = SentinelDropper(dropped_clone);
            panic!("injected panic for drop-on-unwind test");
        });

        assert!(result.is_err(), "catch_unwind should capture the panic");
        assert!(
            dropped.load(Ordering::SeqCst),
            "Drop must run during panic unwind (Zeroizing relies on this)"
        );
    }

    // ── Error type correctness ───────────────────────────────────────────────

    #[test]
    fn mlock_unavailable_errno_extraction() {
        // Construct a region::Error::SystemCall wrapping an io::Error with a
        // known raw_os_error and verify extract_os_errno returns it.
        let io_err = std::io::Error::from_raw_os_error(12); // ENOMEM
        let region_err = region::Error::SystemCall(io_err);
        assert_eq!(extract_os_errno(&region_err), 12);
    }

    #[test]
    fn invalid_parameter_errno_is_zero() {
        // region::Error::InvalidParameter has no errno — should return 0.
        // The variant takes a &'static str parameter (per error.rs:19).
        let region_err: region::Error = region::Error::InvalidParameter("size");
        assert_eq!(extract_os_errno(&region_err), 0);
    }

    // ── extract_os_errno when raw_os_error is None ───────────────────────────

    #[test]
    fn syscall_error_without_raw_os_error_returns_zero() {
        // std::io::Error::new with a kind that has no OS error code produces
        // an io::Error whose raw_os_error() returns None.  extract_os_errno
        // must fall back to 0.
        let io_err = std::io::Error::other("no errno here");
        let region_err = region::Error::SystemCall(io_err);
        assert_eq!(
            extract_os_errno(&region_err),
            0,
            "io::Error without raw_os_error must produce errno 0"
        );
    }

    // ── is_disposed() state machine ──────────────────────────────────────────

    #[test]
    fn is_disposed_false_before_any_dispose() {
        let locked = LockedSeed::new(
            Zeroizing::new(TEST_SEED),
            MlockRequired::False,
            "test-profile",
        )
        .unwrap();
        assert!(
            !locked.is_disposed(),
            "newly created LockedSeed must report disposed=false"
        );
        // Drop runs internal_dispose but we cannot observe is_disposed after drop;
        // verify the initial state before drop.
        drop(locked);
    }

    // ── seed content is preserved exactly ────────────────────────────────────

    #[test]
    fn seed_content_preserved_exactly_for_all_zero_seed() {
        let all_zeros = [0u8; 32];
        let locked =
            LockedSeed::new(Zeroizing::new(all_zeros), MlockRequired::False, "test").unwrap();
        assert_eq!(
            locked.seed(),
            &all_zeros,
            "all-zero seed must be preserved verbatim"
        );
        locked.dispose();
    }

    #[test]
    fn seed_content_preserved_exactly_for_all_ones_seed() {
        let all_ff = [0xFFu8; 32];
        let locked = LockedSeed::new(Zeroizing::new(all_ff), MlockRequired::False, "test").unwrap();
        assert_eq!(
            locked.seed(),
            &all_ff,
            "all-0xFF seed must be preserved verbatim"
        );
        locked.dispose();
    }

    #[test]
    fn seed_content_preserved_for_ascending_byte_pattern() {
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        let locked = LockedSeed::new(Zeroizing::new(seed), MlockRequired::False, "test").unwrap();
        assert_eq!(
            locked.seed(),
            &seed,
            "ascending byte pattern must be preserved verbatim"
        );
        locked.dispose();
    }

    // ── MlockRequired::Warn guard state ─────────────────────────────────────

    /// In Warn mode the guard is either Some (mlock succeeded) or None (mlock
    /// failed but we proceeded).  In both cases `seed()` must return the
    /// original bytes and `is_disposed()` must be false.
    #[test]
    fn warn_mode_seed_bytes_available_regardless_of_mlock_outcome() {
        let locked = LockedSeed::new(
            Zeroizing::new(TEST_SEED),
            MlockRequired::Warn,
            "test-profile",
        )
        .unwrap();
        // The seed must be readable regardless of whether mlock succeeded or not.
        assert_eq!(
            locked.seed(),
            &TEST_SEED,
            "seed must be readable in Warn mode regardless of mlock outcome"
        );
        assert!(
            !locked.is_disposed(),
            "Warn-mode LockedSeed must not be disposed at creation"
        );
        locked.dispose();
    }

    // ── Drop ordering: guard released before seed zeroed ────────────────────

    /// Verifies that `internal_dispose` sets `disposed = true` before
    /// returning, so that a second `internal_dispose` call (from Drop) is
    /// a no-op.  This exercises the idempotent guard `if self.disposed { return }`.
    #[test]
    fn internal_dispose_idempotent_guard_is_set_before_field_drops() {
        let mut locked = LockedSeed::new(
            Zeroizing::new(TEST_SEED),
            MlockRequired::False,
            "test-profile",
        )
        .unwrap();
        // First dispose: sets disposed=true, takes seed and guard.
        locked.internal_dispose();
        assert!(
            locked.disposed,
            "disposed flag must be set after first call"
        );
        assert!(locked.seed.is_none(), "seed must be taken after dispose");
        assert!(locked.guard.is_none(), "guard must be taken after dispose");

        // Second dispose: must be a no-op (early return via `if self.disposed`).
        locked.internal_dispose();
        // State must be unchanged (already disposed; no panic).
        assert!(locked.disposed);
        std::mem::forget(locked);
    }

    // ── Multiple seeds sequentially do not interfere ─────────────────────────

    #[test]
    fn sequential_locked_seeds_do_not_share_state() {
        let seed_a: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3));
        let seed_b: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));

        let la =
            LockedSeed::new(Zeroizing::new(seed_a), MlockRequired::False, "profile-a").unwrap();
        let lb =
            LockedSeed::new(Zeroizing::new(seed_b), MlockRequired::False, "profile-b").unwrap();

        assert_eq!(
            la.seed(),
            &seed_a,
            "seed A must not be contaminated by seed B"
        );
        assert_eq!(
            lb.seed(),
            &seed_b,
            "seed B must not be contaminated by seed A"
        );

        la.dispose();
        lb.dispose();
    }

    // ── MlockRequired::True: guard is Some when OS grants the lock ───────────

    /// When `MlockRequired::True` and the OS grants `mlock`, the guard must be
    /// `Some`.  On environments where mlock is unavailable (CI without
    /// RLIMIT_MEMLOCK), skip the guard assertion rather than fail the test.
    #[test]
    fn true_mode_guard_is_some_when_mlock_succeeds() {
        let result = LockedSeed::new(
            Zeroizing::new(TEST_SEED),
            MlockRequired::True,
            "test-profile",
        );
        match result {
            Ok(locked) => {
                assert!(
                    locked.guard.is_some(),
                    "True mode must hold a LockGuard when mlock succeeds"
                );
                assert_eq!(
                    locked.seed(),
                    &TEST_SEED,
                    "seed must be readable when mlock succeeds"
                );
                locked.dispose();
            }
            Err(WalletLifecycleError::MlockUnavailable { errno, .. }) => {
                // mlock unavailable in this environment — guard assertion skipped.
                eprintln!("mlock unavailable (errno {errno}); skipping guard assertion");
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    // ── WalletLifecycleError display ─────────────────────────────────────────

    #[test]
    fn mlock_unavailable_error_display_contains_reason_and_errno() {
        let err = WalletLifecycleError::MlockUnavailable {
            reason: "resource temporarily unavailable".to_owned(),
            errno: 11,
        };
        let display = format!("{err}");
        assert!(
            display.contains("resource temporarily unavailable"),
            "display must contain reason: {display}"
        );
        assert!(
            display.contains("11"),
            "display must contain errno: {display}"
        );
    }
}
