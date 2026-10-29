//! Sidecar advisory-lock substrate for the audit-log writer.
//!
//! Mirrors `stellar_agent_network::policy_state::lock::WindowStoreLock` and
//! `stellar_agent_network::counterparty::lock::CacheLock`: an exclusive
//! `File::try_lock` held on a small sidecar file next to the resource it
//! protects, rather than on the resource itself.
//!
//! # Why the log file itself is never locked
//!
//! `File::try_lock()` maps to `LockFileEx` on Windows, whose exclusivity is
//! enforced against ALL I/O issued through any OTHER handle to the SAME file
//! — including reads, and including a second handle opened by the SAME
//! process. POSIX advisory locks (OFD/flock) never restrict I/O through a
//! different descriptor, only other lock requests. Locking the audit log file
//! directly would therefore make every concurrent reader fail on Windows
//! (`ERROR_LOCK_VIOLATION`) while a writer was alive. Locking a sidecar file
//! instead preserves cross-process single-writer exclusivity without ever
//! placing an OS lock on the data readers need to touch, on any platform.
//!
//! # Lifetime across rotation
//!
//! The sidecar lock's path is derived from the active log path's stem (see
//! [`crate::audit_log::writer::lock_sidecar_path`]) and never changes when the
//! active file is renamed to a rotated archive. [`AuditWriterLock`] is
//! acquired once in `AuditWriter::open` and held for the writer's entire
//! lifetime, including across every rotation — rotation never releases or
//! re-acquires it. This is what guarantees the archive rename in
//! `AuditWriter::rotate` is safe against a concurrent second writer: no other
//! process can ever hold the writer role while the current one is rotating.

use std::fs::OpenOptions;
use std::path::Path;

use super::writer::WriterError;
use crate::file_lock::HeldFileLock;

/// An exclusive OFD/handle advisory lock over an audit-log writer's sidecar
/// lock file.
///
/// Acquired via [`AuditWriterLock::acquire`]; explicitly unlocked when the guard drops.
pub struct AuditWriterLock {
    /// The guard explicitly releases the lock on drop.
    _file: HeldFileLock,
}

impl std::fmt::Debug for AuditWriterLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditWriterLock").finish_non_exhaustive()
    }
}

impl AuditWriterLock {
    /// Acquires the exclusive advisory lock for the given lock-file path.
    ///
    /// Opens (or creates) the file at `path` with mode `0o600`, then calls
    /// `File::try_lock()`. If another holder already owns the lock,
    /// `try_lock` returns `WouldBlock`, mapped to [`WriterError::FileLocked`].
    ///
    /// # Errors
    ///
    /// - [`WriterError::FileLocked`] — another process or task holds the
    ///   exclusive lock.
    /// - [`WriterError::Io`] — the lock file could not be created, opened, or
    ///   locked for a reason other than contention.
    pub fn acquire(path: &Path) -> Result<Self, WriterError> {
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .create(true)
                .write(true)
                // Do NOT truncate: the lock file is only an advisory-lock
                // carrier; its content is irrelevant.
                .truncate(false)
                .mode(0o600)
                .open(path)?
        };
        #[cfg(not(unix))]
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)?;

        // Acquire the lock BEFORE any content check — a pre-lock check is a
        // TOCTOU race (see CacheLock::acquire / WindowStoreLock::acquire for
        // the identical rationale).
        let file = HeldFileLock::try_lock(file).map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => WriterError::FileLocked,
            std::fs::TryLockError::Error(io_err) => WriterError::Io(io_err),
        })?;

        Ok(Self { _file: file })
    }
}

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
    fn dropping_audit_writer_unlocks_with_a_duplicate_descriptor_alive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.lock");
        let guard = AuditWriterLock::acquire(&path).unwrap();
        let duplicate = guard._file.try_clone_file().unwrap();
        assert!(matches!(
            AuditWriterLock::acquire(&path),
            Err(WriterError::FileLocked)
        ));
        drop(guard);
        let _next = AuditWriterLock::acquire(&path).unwrap();
        drop(duplicate);
        assert!(matches!(
            AuditWriterLock::acquire(&path),
            Err(WriterError::FileLocked)
        ));
    }

    #[test]
    fn acquire_creates_lock_file() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("audit.jsonl.lock");
        let _lock = AuditWriterLock::acquire(&lock_path).unwrap();
        assert!(lock_path.exists());
    }

    #[test]
    fn second_acquire_returns_file_locked() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("audit.jsonl.lock");
        let _lock1 = AuditWriterLock::acquire(&lock_path).unwrap();
        let result = AuditWriterLock::acquire(&lock_path);
        assert!(matches!(result, Err(WriterError::FileLocked)));
    }

    #[test]
    fn lock_released_on_drop() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("audit.jsonl.lock");
        {
            let _lock = AuditWriterLock::acquire(&lock_path).unwrap();
        }
        let result = AuditWriterLock::acquire(&lock_path);
        assert!(result.is_ok());
    }
}
