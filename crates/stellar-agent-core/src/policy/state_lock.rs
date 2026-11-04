//! The exclusive lock over one window-state keyring entry.
//!
//! The HMAC key, the generation commitment, and the policy pin that the
//! window store, its authorization ledger, and the pin operations read and
//! write are named by a profile's window-state keyring entry, not by a file
//! path. They therefore share one OFD-advisory exclusive lock named by that
//! entry: `policy-state-<digest>.lock` in the directory of the window-state
//! file, which gives one lock file per entry in the policy-state directory
//! whatever store path a handle names. Holding the guard is what makes a
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

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::file_lock::HeldFileLock;
use crate::profile::schema::{KeyringEntryRef, keyring_entry_alias};

/// Why the window-state lock could not be taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
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

/// The domain separator of the lock file digest.
const LOCK_NAME_DOMAIN: &[u8] = b"stellar-agent-policy-state-lock:v1";

/// Derives the lock file of the window-state keyring entry `window_key`:
/// `policy-state-<64 lowercase hex>.lock` in the directory of `window_path`.
///
/// The hex is the SHA-256 of a domain separator and the case-folded name a
/// joining keyring store answers for the entry, so every spelling one keyring
/// entry answers shares the lock. The name carries no path component beyond
/// the directory, so every store path in one directory, and every alias of
/// that directory, opens one file. A path without a parent component resolves
/// in the current directory.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use stellar_agent_core::policy::state_lock::window_lock_path;
/// use stellar_agent_core::profile::schema::KeyringEntryRef;
///
/// let key = KeyringEntryRef::new("stellar-agent-policy-window-main", "default");
/// let lock = window_lock_path(Path::new("/state/policy/main.window"), &key);
///
/// assert_eq!(
///     lock,
///     window_lock_path(Path::new("/state/policy/copy.window"), &key),
/// );
/// assert_eq!(lock.parent(), Some(Path::new("/state/policy")));
/// ```
#[must_use]
pub fn window_lock_path(window_path: &Path, window_key: &KeyringEntryRef) -> PathBuf {
    let digest = Sha256::new()
        .chain_update(LOCK_NAME_DOMAIN)
        .chain_update(keyring_entry_alias(window_key).as_bytes())
        .finalize();
    let name = format!("policy-state-{}.lock", crate::hex::encode(&digest));
    window_path
        .parent()
        .map_or_else(|| PathBuf::from(&name), |directory| directory.join(&name))
}

/// An exclusive OFD-advisory lock over one window-state keyring entry.
///
/// Acquired with [`WindowStoreLock::acquire_for`]; explicitly unlocked when
/// the guard drops.
///
/// The guard retains the lock file it holds and the keyring coordinate it was
/// acquired for. Operations that require the guard check both against the
/// scope they are asked to act on, so a guard over one entry never authorizes
/// a write to another's.
pub struct WindowStoreLock {
    /// The guard explicitly releases the lock on drop.
    _file: HeldFileLock,
    /// The lock file this guard holds.
    path: PathBuf,
    /// The window-state key coordinate the guard was acquired for; a test
    /// fixture's bare lock has none.
    window_key: Option<KeyringEntryRef>,
}

impl std::fmt::Debug for WindowStoreLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowStoreLock").finish_non_exhaustive()
    }
}

/// Attempts a retried lock acquisition makes before it reports contention.
pub const LOCK_ATTEMPTS: u32 = 3;

/// The pause between two attempts of a retried lock acquisition.
pub const LOCK_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// Runs `attempt` up to [`LOCK_ATTEMPTS`] times, sleeping
/// [`LOCK_RETRY_DELAY`] after each [`StateLockError::WriterLocked`] but the
/// last. Any other result, success or I/O error, returns at once: only
/// contention is transient.
fn with_retry<T>(
    mut attempt: impl FnMut() -> Result<T, StateLockError>,
) -> Result<T, StateLockError> {
    let mut made = 0;
    loop {
        made += 1;
        match attempt() {
            Err(StateLockError::WriterLocked) if made < LOCK_ATTEMPTS => {
                std::thread::sleep(LOCK_RETRY_DELAY);
            }
            result => return result,
        }
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
    /// pin operations refuse it. Test fixtures only; production code uses
    /// [`Self::acquire_for`].
    ///
    /// # Errors
    ///
    /// The errors of [`Self::acquire_for`].
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn acquire(path: &Path) -> Result<Self, StateLockError> {
        Self::acquire_inner(path, None)
    }

    /// Acquires the lock of the keyring entry `window_key` in the directory
    /// of `window_path`, the file [`window_lock_path`] names.
    ///
    /// Opens (or creates) the lock file with mode `0o600`, then calls
    /// `File::try_lock()`. The lock is acquired before any content check: a
    /// check made before the lock is a time-of-check race.
    ///
    /// The guard records the lock file and the coordinate, and the policy pin
    /// operations accept it only for that lock file and that coordinate.
    ///
    /// # Errors
    ///
    /// - [`StateLockError::WriterLocked`] when another process or task holds
    ///   the exclusive lock.
    /// - [`StateLockError::Io`] when the lock file could not be created or
    ///   opened.
    pub fn acquire_for(
        window_path: &Path,
        window_key: &KeyringEntryRef,
    ) -> Result<Self, StateLockError> {
        Self::acquire_inner(
            &window_lock_path(window_path, window_key),
            Some(window_key.clone()),
        )
    }

    /// Acquires the scoped lock of [`WindowStoreLock::acquire_for`], retrying
    /// contention with [`LOCK_ATTEMPTS`] attempts [`LOCK_RETRY_DELAY`] apart.
    ///
    /// # Errors
    ///
    /// The first I/O error, or [`StateLockError::WriterLocked`] when the lock
    /// stays held through the final attempt.
    pub fn acquire_for_with_retry(
        window_path: &Path,
        window_key: &KeyringEntryRef,
    ) -> Result<Self, StateLockError> {
        with_retry(|| Self::acquire_for(window_path, window_key))
    }

    /// Acquires the scoped lock of [`WindowStoreLock::acquire_for`] only when
    /// its lock file exists, retrying contention like
    /// [`WindowStoreLock::acquire_for_with_retry`].
    ///
    /// A reader that writes nothing uses this acquisition, so it creates
    /// neither the lock file nor its directory. An absent lock file returns
    /// `Ok(None)` without inspecting the keyring. An advancing load recreates
    /// the lock and checks any existing pin.
    ///
    /// # Errors
    ///
    /// The errors of [`WindowStoreLock::acquire_for_with_retry`], except that
    /// a missing lock file or directory is `Ok(None)`.
    pub fn acquire_existing_for_with_retry(
        window_path: &Path,
        window_key: &KeyringEntryRef,
    ) -> Result<Option<Self>, StateLockError> {
        let path = window_lock_path(window_path, window_key);
        match with_retry(|| Self::open_and_lock(&path, Some(window_key.clone()), false)) {
            Ok(lock) => Ok(Some(lock)),
            Err(StateLockError::Io {
                kind: std::io::ErrorKind::NotFound,
            }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn acquire_inner(
        path: &Path,
        window_key: Option<KeyringEntryRef>,
    ) -> Result<Self, StateLockError> {
        Self::open_and_lock(path, window_key, true)
    }

    /// Opens the lock file, creating it when `create` is set, and takes the
    /// exclusive lock without blocking.
    fn open_and_lock(
        path: &Path,
        window_key: Option<KeyringEntryRef>,
        create: bool,
    ) -> Result<Self, StateLockError> {
        let mut options = OpenOptions::new();
        options.create(create).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|e| StateLockError::Io { kind: e.kind() })?;

        let file = HeldFileLock::try_lock(file).map_err(|e| match e {
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

    /// Whether this guard holds the lock that [`window_lock_path`] names for
    /// `window_path` and `window_key`, acquired for that coordinate.
    #[must_use]
    pub fn guards(&self, window_path: &Path, window_key: &KeyringEntryRef) -> bool {
        self.path == window_lock_path(window_path, window_key)
            && self.window_key.as_ref() == Some(window_key)
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
    fn dropping_window_store_unlocks_with_a_duplicate_descriptor_alive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.lock");
        let guard = WindowStoreLock::acquire(&path).unwrap();
        let duplicate = guard._file.try_clone_file().unwrap();
        assert!(matches!(
            WindowStoreLock::acquire(&path),
            Err(StateLockError::WriterLocked)
        ));
        drop(guard);
        let _next = WindowStoreLock::acquire(&path).unwrap();
        drop(duplicate);
        assert!(matches!(
            WindowStoreLock::acquire(&path),
            Err(StateLockError::WriterLocked)
        ));
    }

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

    /// The lock file is a digest of the keyring entry: two store paths in one
    /// directory over one entry share it, two entries do not, the spellings
    /// one entry answers share it, and its name is fixed by the entry alone.
    #[test]
    fn the_lock_is_named_by_the_entry() {
        let key = KeyringEntryRef::new("stellar-agent-policy-window-main", "default");
        assert_eq!(
            window_lock_path(Path::new("/a/b/main.window"), &key),
            window_lock_path(Path::new("/a/b/copy.window"), &key),
        );

        let other = KeyringEntryRef::new("stellar-agent-policy-window-other", "default");
        assert_ne!(
            window_lock_path(Path::new("/a/b/main.window"), &key),
            window_lock_path(Path::new("/a/b/main.window"), &other),
        );

        let folded = KeyringEntryRef::new("Stellar-Agent-Policy-Window-MAIN", "Default");
        assert_ne!(key, folded);
        assert_eq!(
            window_lock_path(Path::new("/a/b/main.window"), &key),
            window_lock_path(Path::new("/a/b/main.window"), &folded),
        );
        assert_eq!(
            window_lock_path(Path::new("/a/b/main.window"), &key),
            PathBuf::from(
                "/a/b/policy-state-8244f0262157c5bedebaac761613a388ffbd0630ac029bb3b01ae0bcd420927e.lock"
            )
        );
    }

    /// A path without a parent component resolves in the current directory,
    /// as the store's own temporary file does.
    #[test]
    fn a_path_without_a_parent_resolves_in_the_current_directory() {
        let key = KeyringEntryRef::new("stellar-agent-policy-window-main", "default");
        let bare = window_lock_path(Path::new("main.window"), &key);
        assert_eq!(bare.parent(), Some(Path::new("")));
        assert_eq!(bare, window_lock_path(Path::new("/"), &key));
    }

    /// A guard taken through one spelling of the directory excludes an
    /// acquisition through another, whatever store file each names.
    #[cfg(unix)]
    #[test]
    fn an_aliased_directory_shares_the_lock() {
        let root = TempDir::new().unwrap();
        let dir = root.path().join("dir");
        std::fs::create_dir(&dir).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let key = KeyringEntryRef::new("stellar-agent-policy-window-main", "default");

        let held = WindowStoreLock::acquire_for(&dir.join("x.window"), &key).unwrap();
        assert!(matches!(
            WindowStoreLock::acquire_for(&link.join("y.window"), &key),
            Err(StateLockError::WriterLocked)
        ));
        drop(held);
        assert!(WindowStoreLock::acquire_for(&link.join("y.window"), &key).is_ok());
    }

    /// A store-scoped guard and a bare-path guard of one file exclude each
    /// other, and only the store-scoped guard answers, for its own coordinate
    /// in its own directory, whichever store file there is named.
    #[test]
    fn a_scoped_guard_guards_only_its_lock_file_and_coordinate() {
        let dir = TempDir::new().unwrap();
        let elsewhere = TempDir::new().unwrap();
        let window = dir.path().join("main.window");
        let key = KeyringEntryRef::new("stellar-agent-policy-window-main", "default");
        let other_key = KeyringEntryRef::new("stellar-agent-policy-window-other", "default");
        let scoped = WindowStoreLock::acquire_for(&window, &key).unwrap();
        assert!(matches!(
            WindowStoreLock::acquire(&window_lock_path(&window, &key)),
            Err(StateLockError::WriterLocked)
        ));
        assert!(scoped.guards(&window, &key));
        assert!(scoped.guards(&dir.path().join("other.window"), &key));
        assert!(!scoped.guards(&window, &other_key));
        assert!(!scoped.guards(&elsewhere.path().join("main.window"), &key));
        drop(scoped);
        let bare = WindowStoreLock::acquire(&window_lock_path(&window, &key)).unwrap();
        assert!(!bare.guards(&window, &key));
    }
}
