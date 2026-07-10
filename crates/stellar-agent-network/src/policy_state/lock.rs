//! Single-writer OFD-advisory flock substrate for the persisted policy
//! window-state store.
//!
//! Mirrors [`crate::counterparty::lock::CacheLock`]: an exclusive
//! `File::try_lock` held for the duration of a window-state read-modify-write.
//! The lock file lives at `<window-state-file>.lock`, a sibling of the store
//! file itself.

use std::fs::{File, OpenOptions};
use std::path::Path;

use crate::policy_state::WindowStoreError;

/// An exclusive OFD-advisory lock over a profile's policy window-state store.
///
/// Acquired via [`WindowStoreLock::acquire`]; held until dropped. The
/// underlying lock file is kept open — the kernel releases the advisory lock
/// when the file descriptor closes (i.e. when [`WindowStoreLock`] drops).
pub struct WindowStoreLock {
    /// The open lock file. Closing it (on drop) releases the OFD lock.
    _file: File,
}

impl std::fmt::Debug for WindowStoreLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowStoreLock").finish_non_exhaustive()
    }
}

impl WindowStoreLock {
    /// Acquires the exclusive OFD lock for the given lock-file path.
    ///
    /// Opens (or creates) the file at `path` with mode `0o600`, then calls
    /// `File::try_lock()`. If another holder already owns the lock,
    /// `try_lock` returns `WouldBlock`, mapped to
    /// [`WindowStoreError::WriterLocked`].
    ///
    /// # Errors
    ///
    /// - [`WindowStoreError::WriterLocked`] — another process or task holds
    ///   the exclusive lock.
    /// - [`WindowStoreError::Io`] — the lock file could not be created or
    ///   opened.
    pub fn acquire(path: &Path) -> Result<Self, WindowStoreError> {
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(|e| WindowStoreError::Io { kind: e.kind() })?
        };
        #[cfg(not(unix))]
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|e| WindowStoreError::Io { kind: e.kind() })?;

        // Acquire the lock BEFORE any content check — a pre-lock check is a
        // TOCTOU race (see CacheLock::acquire for the identical rationale).
        file.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => WindowStoreError::WriterLocked,
            std::fs::TryLockError::Error(io_err) => WindowStoreError::Io {
                kind: io_err.kind(),
            },
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

    #[test]
    fn acquire_creates_lock_file() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join(".window.lock");
        let _lock = WindowStoreLock::acquire(&lock_path).unwrap();
        assert!(lock_path.exists());
    }

    #[test]
    fn second_acquire_returns_writer_locked() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join(".window.lock");
        let _lock1 = WindowStoreLock::acquire(&lock_path).unwrap();
        let result = WindowStoreLock::acquire(&lock_path);
        assert!(matches!(result, Err(WindowStoreError::WriterLocked)));
    }

    #[test]
    fn lock_released_on_drop() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join(".window.lock");
        {
            let _lock = WindowStoreLock::acquire(&lock_path).unwrap();
        }
        let result = WindowStoreLock::acquire(&lock_path);
        assert!(result.is_ok());
    }
}
