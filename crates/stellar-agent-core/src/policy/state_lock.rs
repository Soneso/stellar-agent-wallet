//! The exclusive lock over one profile's policy window-state store.
//!
//! The window store, its authorization ledger, and the policy pin share one
//! OFD-advisory exclusive lock on a sibling file of the store,
//! `<window-state-file>.lock`. Holding the guard is what makes a
//! read-verify-write sequence over any of them atomic with respect to every
//! other process on the host: the store's own transitions take it, and a
//! caller that reads, compares, and writes the pin holds one guard across all
//! three steps.
//!
//! The guard is not reentrant. A second acquisition of the same lock, in the
//! same process or another, answers
//! [`StateLockError::WriterLocked`](crate::policy::state_lock::StateLockError::WriterLocked)
//! at once,
//! so a holder never calls an operation that acquires the lock itself.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::profile::schema::KeyringEntryRef;

/// Why the window-state lock could not be taken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StateLockError {
    /// Another process or task holds the exclusive lock.
    #[error("policy window-state store writer is locked by another process")]
    WriterLocked,

    /// The lock file could not be created, opened, or locked.
    #[error("policy window-state store I/O error: {kind:?}")]
    Io {
        /// The underlying I/O error kind.
        kind: std::io::ErrorKind,
    },
}

/// Derives the lock file of a window-state file: its sibling named
/// `<file name>.lock`.
///
/// A path without a UTF-8 file name falls back to `policy.window.lock` in the
/// same directory.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use stellar_agent_core::policy::state_lock::window_lock_path;
///
/// assert_eq!(
///     window_lock_path(Path::new("/state/policy/main.window")),
///     Path::new("/state/policy/main.window.lock"),
/// );
/// ```
#[must_use]
pub fn window_lock_path(window_path: &Path) -> PathBuf {
    let mut path = window_path.to_path_buf();
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("policy.window")
        .to_owned();
    path.set_file_name(format!("{name}.lock"));
    path
}

/// An exclusive OFD-advisory lock over a profile's policy window-state store.
///
/// Acquired with [`WindowStoreLock::acquire`] or
/// [`WindowStoreLock::acquire_for`]; held until dropped. The kernel releases
/// the lock when the file descriptor closes, which is when the guard drops.
///
/// The guard retains the lock file it holds and, when acquired for a store,
/// the store's keyring coordinate. Operations that require the guard check
/// both against the scope they are asked to act on, so a guard over one
/// profile's store never authorizes a write to another's.
pub struct WindowStoreLock {
    /// The open lock file. Closing it on drop releases the OFD lock.
    _file: File,
    /// The lock file this guard holds.
    path: PathBuf,
    /// The window-state key coordinate the guard was acquired for, when it
    /// was acquired for a store rather than for a bare lock path.
    window_key: Option<KeyringEntryRef>,
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
    /// `File::try_lock()`. The lock is acquired before any content check: a
    /// check made before the lock is a time-of-check race.
    ///
    /// A guard acquired this way carries no store coordinate, so the policy
    /// pin operations refuse it.
    ///
    /// # Errors
    ///
    /// - [`StateLockError::WriterLocked`] when another process or task holds
    ///   the exclusive lock.
    /// - [`StateLockError::Io`] when the lock file could not be created or
    ///   opened.
    pub fn acquire(path: &Path) -> Result<Self, StateLockError> {
        Self::acquire_inner(path, None)
    }

    /// Acquires the lock of the window-state store at `window_path`, whose
    /// HMAC key lives at `window_key`.
    ///
    /// The guard records both, and the policy pin operations accept it only
    /// for that store and that coordinate.
    ///
    /// # Errors
    ///
    /// The errors of [`WindowStoreLock::acquire`].
    pub fn acquire_for(
        window_path: &Path,
        window_key: &KeyringEntryRef,
    ) -> Result<Self, StateLockError> {
        Self::acquire_inner(&window_lock_path(window_path), Some(window_key.clone()))
    }

    fn acquire_inner(
        path: &Path,
        window_key: Option<KeyringEntryRef>,
    ) -> Result<Self, StateLockError> {
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(|e| StateLockError::Io { kind: e.kind() })?
        };
        #[cfg(not(unix))]
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|e| StateLockError::Io { kind: e.kind() })?;

        file.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => StateLockError::WriterLocked,
            std::fs::TryLockError::Error(io_err) => StateLockError::Io {
                kind: io_err.kind(),
            },
        })?;

        Ok(Self {
            _file: file,
            path: path.to_path_buf(),
            window_key,
        })
    }

    /// The lock file this guard holds.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this guard holds the lock of the store at `window_path` whose
    /// key lives at `window_key`.
    #[must_use]
    pub fn guards(&self, window_path: &Path, window_key: &KeyringEntryRef) -> bool {
        self.path == window_lock_path(window_path) && self.window_key.as_ref() == Some(window_key)
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
        assert!(matches!(result, Err(StateLockError::WriterLocked)));
    }

    #[test]
    fn lock_released_on_drop() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join(".window.lock");
        {
            let _lock = WindowStoreLock::acquire(&lock_path).unwrap();
        }
        assert!(WindowStoreLock::acquire(&lock_path).is_ok());
    }

    /// The sibling name appends `.lock` to the store's file name, and a path
    /// without a file name falls back to the fixed name.
    #[test]
    fn lock_path_is_the_sibling_name() {
        assert_eq!(
            window_lock_path(Path::new("/a/b/main.window")),
            PathBuf::from("/a/b/main.window.lock")
        );
        assert_eq!(
            window_lock_path(Path::new("/")),
            PathBuf::from("/policy.window.lock")
        );
    }

    /// A store-scoped guard and a bare-path guard of one file exclude each
    /// other, and only the store-scoped guard answers for its own store and
    /// coordinate.
    #[test]
    fn a_scoped_guard_guards_only_its_store_and_coordinate() {
        let dir = TempDir::new().unwrap();
        let window = dir.path().join("main.window");
        let key = KeyringEntryRef::new("stellar-agent-policy-window-main", "default");
        let other_key = KeyringEntryRef::new("stellar-agent-policy-window-other", "default");
        let scoped = WindowStoreLock::acquire_for(&window, &key).unwrap();
        assert!(matches!(
            WindowStoreLock::acquire(&window_lock_path(&window)),
            Err(StateLockError::WriterLocked)
        ));
        assert!(scoped.guards(&window, &key));
        assert!(!scoped.guards(&window, &other_key));
        assert!(!scoped.guards(&dir.path().join("other.window"), &key));
        drop(scoped);
        let bare = WindowStoreLock::acquire(&window_lock_path(&window)).unwrap();
        assert!(!bare.guards(&window, &key));
    }
}
