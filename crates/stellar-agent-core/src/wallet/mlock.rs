//! Region-backed memory-locked seed buffer.
//!
//! [`LockedSeed`] allocates an isolated home, locks it before copying the seed,
//! and keeps that address stable through ownership transfers. Drop zeroizes the
//! seed before unlocking and freeing its home, including during panic unwind.
//!
//! `region::lock` uses `mlock(2)` on POSIX and `VirtualLock` on Windows.
//! It rounds the range to whole pages. Locks do not nest, so each seed owns
//! a separate aligned allocation to keep another seed's drop from unlocking it.
//!
//! `region::LockGuard` is `Send + Sync`: unlocking is process-scoped, and the
//! guard exposes no shared-reference operation that touches the locked memory.

use zeroize::{Zeroize, Zeroizing};

use super::{config::MlockRequired, error::WalletLifecycleError};

// Memory locks do not nest. A separate 64 KiB-aligned allocation isolates each
// seed on supported 4 KiB, 16 KiB, and 64 KiB pages, including at unlock time.
const SEED_PAGE_ALIGN: usize = 65536;

#[repr(C, align(65536))]
struct SeedPage([u8; 32]);

const _: () = assert!(std::mem::align_of::<SeedPage>() == SEED_PAGE_ALIGN);

impl Zeroize for SeedPage {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

fn seed_page_isolates(page_size: usize) -> bool {
    page_size <= SEED_PAGE_ALIGN
}

#[cfg(test)]
thread_local! {
    pub(super) static ZEROIZED_BEFORE_UNLOCK: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// A 32-byte signing seed with a stable, isolated, zeroize-on-drop home.
///
/// When the configured posture requires or attempts locking, the home is locked
/// before the seed enters it. A tolerated lock failure is available to callers
/// through the wallet's degradation accessor.
///
/// [`Drop`] and [`LockedSeed::dispose`] zeroize the seed, unlock, then free it.
pub struct LockedSeed {
    /// Drop zeroizes this home, releases the guard, then frees the box.
    home: Box<Zeroizing<SeedPage>>,
    /// Absent when locking is disabled or a failure is tolerated.
    guard: Option<region::LockGuard>,
    mlock_degradation: Option<MlockDegradation>,
    #[cfg(test)]
    lock_target: Option<usize>,
}

/// Details of an `mlock` failure tolerated under `MlockRequired::Warn`.
#[derive(Debug, Clone)]
pub struct MlockDegradation {
    /// Human-readable reason for the lock failure.
    pub reason: String,
    /// OS error number, when the failure exposes one.
    pub errno: Option<i32>,
}

impl LockedSeed {
    /// Allocate a zeroed home, attempt its lock, then copy the borrowed seed.
    ///
    /// `True` refuses a lock failure before copying any seed bytes. `Warn`
    /// records the failure and proceeds. `False` skips the lock attempt.
    /// The caller keeps responsibility for zeroizing the borrowed input.
    ///
    /// # Errors
    ///
    /// Returns [`WalletLifecycleError::MlockUnavailable`] under `True` when
    /// the OS refuses the lock or its page size exceeds the home's alignment.
    pub(crate) fn new(
        seed: &[u8; 32],
        required: MlockRequired,
        profile_name: &str,
    ) -> Result<Self, WalletLifecycleError> {
        Self::with_page_size(seed, required, profile_name, region::page::size())
    }

    /// Build the home as [`LockedSeed::new`] does, checking isolation against
    /// `page_size` instead of the host's page size.
    fn with_page_size(
        seed: &[u8; 32],
        required: MlockRequired,
        profile_name: &str,
        page_size: usize,
    ) -> Result<Self, WalletLifecycleError> {
        let mut home = Box::new(Zeroizing::new(SeedPage([0u8; 32])));
        let mut mlock_degradation = None;
        #[cfg(test)]
        let mut lock_target = None;
        let guard = match required {
            MlockRequired::False => None,
            MlockRequired::True | MlockRequired::Warn => {
                let addr = home.0.as_ptr();
                #[cfg(test)]
                {
                    lock_target = Some(addr as usize);
                }
                let result = if seed_page_isolates(page_size) {
                    region::lock(addr, 32)
                } else {
                    Err(region::Error::InvalidParameter(
                        "page size exceeds seed alignment",
                    ))
                };
                match result {
                    Ok(guard) => Some(guard),
                    Err(err) => {
                        let reason = err.to_string();
                        let errno = extract_os_errno(&err);
                        if required == MlockRequired::True {
                            return Err(WalletLifecycleError::MlockUnavailable { reason, errno });
                        }
                        tracing::warn!(
                            profile = %profile_name,
                            reason = %reason,
                            errno = errno,
                            "wallet.mlock_failed: mlock unavailable; proceeding with unprotected memory (warn mode)."
                        );
                        mlock_degradation = Some(MlockDegradation {
                            reason,
                            errno: if errno == 0 { None } else { Some(errno) },
                        });
                        None
                    }
                }
            }
        };
        home.0.copy_from_slice(seed);
        Ok(Self {
            home,
            guard,
            mlock_degradation,
            #[cfg(test)]
            lock_target,
        })
    }

    /// Return details of a tolerated lock failure, if any.
    pub(crate) fn mlock_degradation(&self) -> Option<&MlockDegradation> {
        self.mlock_degradation.as_ref()
    }

    /// Borrow the seed from its stable home for this owner's lifetime.
    pub fn seed(&self) -> &[u8; 32] {
        &self.home.0
    }

    /// Zeroize the seed, unlock its page, and free its home.
    pub fn dispose(self) {
        drop(self);
    }

    #[cfg(test)]
    pub(super) fn lock_target(&self) -> Option<usize> {
        self.lock_target
    }

    /// Release the memory lock on the home. The caller zeroizes the home first.
    fn release_lock(&mut self) {
        #[cfg(test)]
        ZEROIZED_BEFORE_UNLOCK.set(Some(self.home.0.iter().all(|byte| *byte == 0)));
        drop(self.guard.take());
    }
}

impl Drop for LockedSeed {
    fn drop(&mut self) {
        self.home.zeroize();
        self.release_lock();
    }
}

/// Extract the OS errno from a `region::Error`, falling back to `0`.
fn extract_os_errno(err: &region::Error) -> i32 {
    if let region::Error::SystemCall(io_err) = err {
        io_err.raw_os_error().unwrap_or(0)
    } else {
        0
    }
}

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
        let locked = LockedSeed::new(&TEST_SEED, MlockRequired::False, "test-profile").unwrap();
        assert_eq!(locked.seed(), &TEST_SEED);
        assert!(locked.guard.is_none(), "False mode must not hold a guard");
        locked.dispose();
    }

    #[test]
    fn false_mode_seed_matches_input() {
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        let locked = LockedSeed::new(&seed, MlockRequired::False, "test-profile").unwrap();
        assert_eq!(locked.seed(), &seed);
        locked.dispose();
    }

    // ── MlockRequired::Warn ──────────────────────────────────────────────────

    #[test]
    fn warn_mode_succeeds_or_falls_back() {
        // Warn mode must return Ok regardless of whether mlock succeeds.
        let locked = LockedSeed::new(&TEST_SEED, MlockRequired::Warn, "test-profile").unwrap();
        assert_eq!(locked.seed(), &TEST_SEED);
        locked.dispose();
    }

    // ── MlockRequired::True ──────────────────────────────────────────────────

    #[test]
    fn true_mode_succeeds_when_lock_available() {
        // On most development machines RLIMIT_MEMLOCK allows at least one page.
        // If the lock fails, skip rather than fail — we cannot control rlimit
        // in CI without root.
        match LockedSeed::new(&TEST_SEED, MlockRequired::True, "test-profile") {
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

    // ── Panic-safety regression ──────────────────────────────────────────────

    #[test]
    fn drop_runs_on_panic_unwind() {
        ZEROIZED_BEFORE_UNLOCK.set(None);
        let result = std::panic::catch_unwind(|| {
            let _locked = LockedSeed::new(&TEST_SEED, MlockRequired::False, "test").unwrap();
            panic!("injected panic for drop-on-unwind test");
        });
        assert!(result.is_err());
        assert_eq!(ZEROIZED_BEFORE_UNLOCK.get(), Some(true));
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

    // ── seed content is preserved exactly ────────────────────────────────────

    #[test]
    fn seed_content_preserved_exactly_for_all_zero_seed() {
        let all_zeros = [0u8; 32];
        let locked = LockedSeed::new(&all_zeros, MlockRequired::False, "test").unwrap();
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
        let locked = LockedSeed::new(&all_ff, MlockRequired::False, "test").unwrap();
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
        let locked = LockedSeed::new(&seed, MlockRequired::False, "test").unwrap();
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
    /// original bytes.
    #[test]
    fn warn_mode_seed_bytes_available_regardless_of_mlock_outcome() {
        let locked = LockedSeed::new(&TEST_SEED, MlockRequired::Warn, "test-profile").unwrap();
        // The seed must be readable regardless of whether mlock succeeded or not.
        assert_eq!(
            locked.seed(),
            &TEST_SEED,
            "seed must be readable in Warn mode regardless of mlock outcome"
        );
        locked.dispose();
    }

    // ── Multiple seeds sequentially do not interfere ─────────────────────────

    #[test]
    fn sequential_locked_seeds_do_not_share_state() {
        let seed_a: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3));
        let seed_b: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));

        let la = LockedSeed::new(&seed_a, MlockRequired::False, "profile-a").unwrap();
        let lb = LockedSeed::new(&seed_b, MlockRequired::False, "profile-b").unwrap();

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
        let result = LockedSeed::new(&TEST_SEED, MlockRequired::True, "test-profile");
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

    #[test]
    fn the_lock_target_is_the_address_seed_returns() {
        fn returned(seed: LockedSeed) -> LockedSeed {
            seed
        }
        let locked = LockedSeed::new(&TEST_SEED, MlockRequired::Warn, "test").unwrap();
        let address = locked.seed().as_ptr() as usize;
        assert_eq!(locked.lock_target(), Some(address));
        let mut values = Vec::new();
        values.push(locked);
        assert_eq!(values[0].seed().as_ptr() as usize, address);
        assert_eq!(values[0].lock_target(), Some(address));
        let boxed = Box::new(values.pop().unwrap());
        assert_eq!(boxed.seed().as_ptr() as usize, address);
        assert_eq!(boxed.lock_target(), Some(address));
        let returned = returned(*boxed);
        assert_eq!(returned.seed().as_ptr() as usize, address);
        assert_eq!(returned.lock_target(), Some(address));
    }

    #[test]
    fn drop_zeroizes_before_it_unlocks() {
        ZEROIZED_BEFORE_UNLOCK.set(None);
        let locked = LockedSeed::new(&TEST_SEED, MlockRequired::Warn, "test").unwrap();
        drop(locked);
        assert_eq!(ZEROIZED_BEFORE_UNLOCK.get(), Some(true));
    }

    #[test]
    fn dispose_zeroizes_before_it_unlocks() {
        ZEROIZED_BEFORE_UNLOCK.set(None);
        LockedSeed::new(&TEST_SEED, MlockRequired::False, "test")
            .unwrap()
            .dispose();
        assert_eq!(ZEROIZED_BEFORE_UNLOCK.get(), Some(true));
    }

    #[test]
    fn seed_pages_do_not_share_a_page() {
        let a = LockedSeed::new(&TEST_SEED, MlockRequired::False, "a").unwrap();
        let b = LockedSeed::new(&TEST_SEED, MlockRequired::False, "b").unwrap();
        let a = a.seed().as_ptr() as usize;
        let b = b.seed().as_ptr() as usize;
        assert_eq!(SEED_PAGE_ALIGN, 65536);
        assert_eq!(a % SEED_PAGE_ALIGN, 0);
        assert_eq!(b % SEED_PAGE_ALIGN, 0);
        assert!(a.abs_diff(b) >= SEED_PAGE_ALIGN);
    }

    #[test]
    fn seed_page_isolates_up_to_its_alignment() {
        for size in [4096, 16384, 65536] {
            assert!(seed_page_isolates(size));
        }
        assert!(!seed_page_isolates(131072));
    }

    #[test]
    fn a_page_larger_than_the_home_refuses_or_degrades() {
        let oversized = SEED_PAGE_ALIGN * 2;
        match LockedSeed::with_page_size(&TEST_SEED, MlockRequired::True, "test", oversized) {
            Err(WalletLifecycleError::MlockUnavailable { reason, errno }) => {
                assert_eq!(
                    reason,
                    "Invalid parameter value: page size exceeds seed alignment"
                );
                assert_eq!(errno, 0);
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
            Ok(_) => panic!("True mode must refuse a page larger than the home"),
        }

        let warned =
            LockedSeed::with_page_size(&TEST_SEED, MlockRequired::Warn, "test", oversized).unwrap();
        let degradation = warned.mlock_degradation().unwrap();
        assert_eq!(
            degradation.reason,
            "Invalid parameter value: page size exceeds seed alignment"
        );
        assert_eq!(degradation.errno, None);
        assert!(warned.guard.is_none(), "an unisolated home stays unlocked");
        assert_eq!(warned.seed(), &TEST_SEED);
    }
}
