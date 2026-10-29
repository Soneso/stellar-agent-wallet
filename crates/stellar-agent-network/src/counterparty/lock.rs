//! Single-writer OFD-advisory flock substrate for the per-profile counterparty cache.
//!
//! # What this module does
//!
//! Provides [`CacheLock`] — a thin wrapper around a [`std::fs::File`] whose
//! [`std::fs::File::try_lock`] (Rust 1.89 stable) holds an OFD-advisory exclusive lock
//! for the duration of a counterparty cache write.  The lock file lives at
//! `<cache_dir>/.lock`.
//!
//! # Single-writer invariant
//!
//! At most one wallet process (or one task within a process) may write the
//! cache directory at a time.  `CacheLock::acquire` fails immediately with
//! [`CounterpartyError::WriterLocked`] if another holder owns the lock — there
//! is no retry or spin.  `cache::StellarTomlResolver::refresh` returns
//! `WriterLocked` to its caller, the CLI `counterparty refresh` or
//! `counterparty warm-up`.  The listing that feeds the policy criteria takes
//! no lock, so a held lock does not block criterion evaluation.
//!
//! # Drop discipline
//!
//! Dropping the [`CacheLock`] explicitly releases the advisory lock before
//! closing the file descriptor.
//!
//! Enforces the single-writer flock invariant for the per-profile counterparty
//! cache directory.

use std::fs::OpenOptions;
use std::path::Path;

use stellar_agent_core::file_lock::HeldFileLock;

use crate::counterparty::CounterpartyError;

// ─────────────────────────────────────────────────────────────────────────────
// CacheLock
// ─────────────────────────────────────────────────────────────────────────────

/// An exclusive OFD-advisory lock over the counterparty cache directory.
///
/// Acquired via [`CacheLock::acquire`]; explicitly unlocked when the guard drops.
///
/// Visibility: `pub(crate)` in production; `pub` under `test-helpers` feature
/// so integration tests can hold the lock manually to simulate race conditions.
pub struct CacheLock {
    /// The guard explicitly releases the lock on drop.
    _file: HeldFileLock,
}

impl std::fmt::Debug for CacheLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheLock").finish_non_exhaustive()
    }
}

impl CacheLock {
    /// Acquires the exclusive OFD lock for the given lock-file path.
    ///
    /// Opens (or creates) the file at `path` with mode `0o600`, then calls
    /// `File::try_lock()`.  If another holder already owns the lock,
    /// `try_lock` returns `WouldBlock` which is mapped to
    /// [`CounterpartyError::WriterLocked`].
    ///
    /// # Errors
    ///
    /// - [`CounterpartyError::WriterLocked`] — another process or task holds
    ///   the exclusive lock; the caller should not wait and should fall back
    ///   to the cached value.
    /// - [`CounterpartyError::Io`] — the lock file could not be created or
    ///   opened (permissions, non-existent parent directory, etc.).
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn acquire(path: &Path) -> Result<Self, CounterpartyError> {
        // Open or create the lock file.  Mode 0o600 matches the cache files so
        // the lock file itself does not widen the cache directory's ACL.
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .create(true)
                .write(true)
                // Do NOT truncate: the lock file is only used as an flock
                // carrier; its content is irrelevant.  Truncating would be
                // a no-op but clippy::suspicious_open_options demands we be
                // explicit about intent.
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(|e| CounterpartyError::Io { kind: e.kind() })?
        };
        #[cfg(not(unix))]
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            // Do NOT truncate: the lock file is only used as an flock carrier.
            .truncate(false)
            .open(path)
            .map_err(|e| CounterpartyError::Io { kind: e.kind() })?;

        // Acquire the exclusive lock FIRST, then assert the file is empty.
        // Checking metadata before acquiring the lock is a TOCTOU race — a
        // concurrent writer could plant content between the check and the lock.
        // Acquiring the lock first serialises the check.
        //
        // `try_lock()` is stabilised in Rust 1.89.  It acquires an exclusive
        // advisory lock without blocking.  `TryLockError::WouldBlock` maps to
        // `WriterLocked`; `TryLockError::Error(io_err)` maps to `Io`.
        let file = HeldFileLock::try_lock(file).map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => CounterpartyError::WriterLocked,
            std::fs::TryLockError::Error(io_err) => CounterpartyError::Io {
                kind: io_err.kind(),
            },
        })?;

        // Post-lock integrity check: assert the file is empty.
        // A pre-planted lock file with content indicates tampering — the lock
        // file must always be an empty advisory-flock carrier.  Checking here
        // (after lock acquisition) is race-free; we own the lock.
        let file_len = file
            .metadata()
            .map_err(|e| CounterpartyError::Io { kind: e.kind() })?
            .len();
        if file_len != 0 {
            tracing::warn!(
                path = %path.display(),
                file_len,
                "counterparty lock file has unexpected content — possible tampering; \
                 treating as WriterLocked"
            );
            return Err(CounterpartyError::WriterLocked);
        }

        Ok(Self { _file: file })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn dropping_cache_unlocks_with_a_duplicate_descriptor_alive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.lock");
        let guard = CacheLock::acquire(&path).unwrap();
        let duplicate = guard._file.try_clone_file().unwrap();
        assert!(matches!(
            CacheLock::acquire(&path),
            Err(CounterpartyError::WriterLocked)
        ));
        drop(guard);
        let _next = CacheLock::acquire(&path).unwrap();
        drop(duplicate);
        assert!(matches!(
            CacheLock::acquire(&path),
            Err(CounterpartyError::WriterLocked)
        ));
    }

    #[test]
    fn acquire_creates_lock_file() {
        let dir = TempDir::new().expect("tmpdir");
        let lock_path = dir.path().join(".lock");

        let _lock = CacheLock::acquire(&lock_path).expect("first acquire must succeed");
        assert!(lock_path.exists(), "lock file must be created on acquire");
    }

    #[test]
    fn second_acquire_returns_writer_locked() {
        let dir = TempDir::new().expect("tmpdir");
        let lock_path = dir.path().join(".lock");

        let _lock1 = CacheLock::acquire(&lock_path).expect("first acquire must succeed");
        let result = CacheLock::acquire(&lock_path);

        assert!(
            matches!(result, Err(CounterpartyError::WriterLocked)),
            "second acquire on the same lock must return WriterLocked, got: {result:?}",
        );
    }

    #[test]
    fn lock_released_on_drop() {
        let dir = TempDir::new().expect("tmpdir");
        let lock_path = dir.path().join(".lock");

        {
            let _lock = CacheLock::acquire(&lock_path).expect("first acquire must succeed");
        }
        // After the first lock drops, a second acquire must succeed.
        let result = CacheLock::acquire(&lock_path);
        assert!(
            result.is_ok(),
            "acquire after drop must succeed, got: {result:?}",
        );
    }

    /// A lock file with pre-planted content (non-zero length)
    /// must be treated as `WriterLocked` rather than proceeding.
    #[test]
    fn non_empty_lock_file_returns_writer_locked() {
        let dir = TempDir::new().expect("tmpdir");
        let lock_path = dir.path().join(".lock");

        // Plant content in the lock file.
        std::fs::write(&lock_path, b"attacker-planted-content").expect("write");

        let result = CacheLock::acquire(&lock_path);
        assert!(
            matches!(result, Err(CounterpartyError::WriterLocked)),
            "non-empty lock file must return WriterLocked, got: {result:?}"
        );
    }
}
