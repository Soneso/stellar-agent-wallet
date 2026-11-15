//! The exclusive and shared locks over a toolsets directory.
//!
//! Install and uninstall change a toolset's directory and its pin record.
//! Each runs under one exclusive advisory lock on
//! `<toolsets_root>/.toolsets.lock`, so processes never interleave those steps.
//! A reader that must see one installation unchanged holds a shared lock on
//! the same file, which excludes the exclusive lock.
//! The CLI holds a separate installation-wide lock while reading or minting
//! the pin key. The lock order is the toolsets-root lock first, then the
//! installation pin-key lock.
//! The guard unlocks before closing its handle, so a descriptor copy
//! inherited by a spawned child cannot keep the lock held.
//!
//! The lock file is a regular file, and the runtime's toolset listing skips
//! it by name.  Nothing reads the lock file's bytes while the lock is held:
//! on Windows a held lock blocks every other handle's reads of the file.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use stellar_agent_core::file_lock::HeldFileLock;
use stellar_agent_core::policy::state_lock::{LOCK_ATTEMPTS, LOCK_RETRY_DELAY};

use crate::ToolsetInstallError;
pub use stellar_agent_core::profile::schema::TOOLSET_PIN_KEY_LOCK_FILE_NAME;

/// File name of the lock file inside the toolsets root.
pub const TOOLSETS_LOCK_FILE_NAME: &str = ".toolsets.lock";

/// An exclusive advisory lock over one toolsets directory.
///
/// Acquired with [`lock_toolsets`] and released when dropped. The guard records
/// the root it was taken on, and [`crate::install_toolset`] and
/// [`crate::uninstall_toolset`] refuse a guard of another root.
pub struct ToolsetsLock {
    /// The guard releases the lock before closing the file handle.
    _file: HeldFileLock,
    /// The toolsets root the lock was taken on.
    root: PathBuf,
}

impl std::fmt::Debug for ToolsetsLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolsetsLock").finish_non_exhaustive()
    }
}

impl ToolsetsLock {
    /// The toolsets root this lock was taken on.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Refuses unless this lock was taken on `toolsets_root`.
    pub(crate) fn check_root(&self, toolsets_root: &Path) -> Result<(), ToolsetInstallError> {
        if self.root == toolsets_root {
            Ok(())
        } else {
            Err(ToolsetInstallError::ToolsetsRootInvalid {
                detail: "the toolsets lock was taken on another toolsets directory".to_owned(),
            })
        }
    }
}

/// Takes the exclusive lock of `toolsets_root`, creating the directory and
/// the lock file when absent.
///
/// A lock held by another process or handle is retried
/// [`LOCK_ATTEMPTS`] times, [`LOCK_RETRY_DELAY`] apart, the bound the
/// policy window-state lock uses; a lock still held after the last attempt
/// refuses with [`ToolsetInstallError::Busy`].
///
/// # Errors
///
/// - [`ToolsetInstallError::Busy`]: the lock stays held through the last
///   attempt.
/// - [`ToolsetInstallError::Io`]: the directory or the lock file cannot be
///   created or opened, or the lock call fails for another reason.
pub fn lock_toolsets(toolsets_root: &Path) -> Result<ToolsetsLock, ToolsetInstallError> {
    std::fs::create_dir_all(toolsets_root).map_err(ToolsetInstallError::from_io)?;

    let file = lock_file(
        &toolsets_root.join(TOOLSETS_LOCK_FILE_NAME),
        ToolsetInstallError::Busy,
    )?;
    Ok(ToolsetsLock {
        _file: file,
        root: toolsets_root.to_path_buf(),
    })
}

/// A shared advisory lock over one toolsets directory, released when dropped.
///
/// Shared locks coexist; while one lives, [`lock_toolsets`] cannot take the
/// exclusive lock, so no install, forced reinstall, or uninstall changes the
/// root. This guard cannot stand in for a [`ToolsetsLock`].
pub struct ToolsetsReadLock {
    /// The guard releases the lock before closing the file handle.
    _file: HeldFileLock,
}

impl std::fmt::Debug for ToolsetsReadLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolsetsReadLock").finish_non_exhaustive()
    }
}

/// Takes the shared lock of an existing `toolsets_root` without blocking,
/// creating the lock file when absent. The root itself is never created.
///
/// Returns `Ok(None)` when `toolsets_root` does not exist.
///
/// # Errors
///
/// - [`ToolsetInstallError::Busy`]: the exclusive lock is held.
/// - [`ToolsetInstallError::Io`]: the lock file cannot be opened or locked.
pub fn lock_toolsets_shared(
    toolsets_root: &Path,
) -> Result<Option<ToolsetsReadLock>, ToolsetInstallError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    shared_lock(toolsets_root, &options)
}

/// Takes the shared lock of `toolsets_root` without blocking, opening only
/// an existing lock file. Creates nothing.
///
/// Returns `Ok(None)` when the root or its lock file does not exist.
///
/// # Errors
///
/// As [`lock_toolsets_shared`].
pub fn lock_existing_toolsets_shared(
    toolsets_root: &Path,
) -> Result<Option<ToolsetsReadLock>, ToolsetInstallError> {
    shared_lock(toolsets_root, OpenOptions::new().read(true))
}

fn shared_lock(
    toolsets_root: &Path,
    options: &OpenOptions,
) -> Result<Option<ToolsetsReadLock>, ToolsetInstallError> {
    let file = match options.open(toolsets_root.join(TOOLSETS_LOCK_FILE_NAME)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ToolsetInstallError::from_io(e)),
    };
    match HeldFileLock::try_lock_shared(file) {
        Ok(guard) => Ok(Some(ToolsetsReadLock { _file: guard })),
        Err(std::fs::TryLockError::WouldBlock) => Err(ToolsetInstallError::Busy),
        Err(std::fs::TryLockError::Error(e)) => Err(ToolsetInstallError::from_io(e)),
    }
}

/// An exclusive installation pin-key lock, held until dropped.
#[derive(Debug)]
pub struct InstallationPinKeyLock {
    _file: HeldFileLock,
}

/// Locks the installation pin-key read-or-mint at `lock_path`.
///
/// The caller holds the toolsets-root lock before taking this lock.
/// Contention uses the same retry bound as [`lock_toolsets`].
///
/// # Errors
///
/// - [`ToolsetInstallError::PinKeyBusy`] if every attempt finds the lock held.
/// - [`ToolsetInstallError::Io`] if the lock file cannot be opened.
pub fn lock_installation_pin_key(
    lock_path: &Path,
) -> Result<InstallationPinKeyLock, ToolsetInstallError> {
    let file = lock_file(lock_path, ToolsetInstallError::PinKeyBusy)?;
    Ok(InstallationPinKeyLock { _file: file })
}

fn lock_file(path: &Path, busy: ToolsetInstallError) -> Result<HeldFileLock, ToolsetInstallError> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut made = 0;
    loop {
        made += 1;
        let file = options.open(path).map_err(ToolsetInstallError::from_io)?;
        match HeldFileLock::try_lock(file) {
            Ok(guard) => return Ok(guard),
            Err(std::fs::TryLockError::WouldBlock) if made < LOCK_ATTEMPTS => {
                std::thread::sleep(LOCK_RETRY_DELAY);
            }
            Err(std::fs::TryLockError::WouldBlock) => return Err(busy),
            Err(std::fs::TryLockError::Error(e)) => return Err(ToolsetInstallError::from_io(e)),
        }
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

    #[cfg(unix)]
    #[test]
    fn dropping_the_guard_unlocks_while_a_duplicate_descriptor_lives() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let second = file.reopen().unwrap();
        let guard = lock_file(file.path(), ToolsetInstallError::Busy).unwrap();
        let duplicate = guard.try_clone_file().unwrap();
        assert!(matches!(
            second.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(guard);
        let next = HeldFileLock::try_lock(second).unwrap();
        drop(duplicate);
        assert!(matches!(
            HeldFileLock::try_lock(file.reopen().unwrap()),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(next);
    }

    #[test]
    fn a_second_lock_on_the_same_root_waits_and_refuses() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("toolsets");
        let held = lock_toolsets(&root).unwrap();
        assert!(
            root.join(TOOLSETS_LOCK_FILE_NAME).is_file(),
            "the first lock must create the lock file"
        );

        let started = std::time::Instant::now();
        let err = lock_toolsets(&root).unwrap_err();
        let waited = started.elapsed();
        assert!(
            matches!(err, ToolsetInstallError::Busy),
            "a second lock while the first is held must refuse with Busy, got: {err:?}"
        );
        let bound = LOCK_RETRY_DELAY * (LOCK_ATTEMPTS - 1);
        assert!(
            waited >= bound,
            "the Busy refusal must come after the retries the held lock forces \
             ({waited:?} < {bound:?})"
        );

        drop(held);
        lock_toolsets(&root).expect("the lock is free once the first guard drops");
    }

    #[test]
    fn shared_locks_coexist_and_exclude_the_exclusive_lock() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("toolsets");
        drop(lock_toolsets(&root).unwrap());
        let first = lock_existing_toolsets_shared(&root).unwrap().unwrap();
        let second = lock_toolsets_shared(&root).unwrap().unwrap();
        let err = lock_toolsets(&root).unwrap_err();
        assert!(matches!(err, ToolsetInstallError::Busy), "{err:?}");
        drop(first);
        let err = lock_toolsets(&root).unwrap_err();
        assert!(matches!(err, ToolsetInstallError::Busy), "{err:?}");
        drop(second);
        let exclusive = lock_toolsets(&root).expect("free once every shared guard drops");
        for shared in [lock_toolsets_shared, lock_existing_toolsets_shared] {
            let err = shared(&root).unwrap_err();
            assert!(matches!(err, ToolsetInstallError::Busy), "{err:?}");
        }
        drop(exclusive);
    }

    #[test]
    fn shared_locks_never_create_the_root() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("toolsets");
        assert!(lock_toolsets_shared(&root).unwrap().is_none());
        assert!(lock_existing_toolsets_shared(&root).unwrap().is_none());
        assert!(!root.exists(), "no shared lock creates the root");

        std::fs::create_dir(&root).unwrap();
        assert!(lock_existing_toolsets_shared(&root).unwrap().is_none());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        drop(lock_toolsets_shared(&root).unwrap().unwrap());
        assert!(root.join(TOOLSETS_LOCK_FILE_NAME).is_file());
        assert!(lock_existing_toolsets_shared(&root).unwrap().is_some());
    }

    #[test]
    fn a_lock_on_another_root_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let lock = lock_toolsets(&dir.path().join("a")).unwrap();
        assert_eq!(lock.root(), dir.path().join("a"));
        lock.check_root(&dir.path().join("a")).unwrap();
        let err = lock.check_root(&dir.path().join("b")).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ToolsetsRootInvalid { .. }),
            "got: {err:?}"
        );
    }
}
