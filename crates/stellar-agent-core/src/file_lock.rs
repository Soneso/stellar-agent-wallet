//! An exclusive file lock ends when its guard drops.
//!
//! A `flock` belongs to the open file description, so closing one descriptor
//! ends it only when the last copy of that descriptor closes. A spawned child
//! can hold such a copy, and the guard therefore unlocks explicitly when it
//! drops.

use std::fs::{File, Metadata, TryLockError};

/// An exclusive advisory file lock released on drop.
#[must_use]
pub struct HeldFileLock {
    file: File,
}

impl HeldFileLock {
    /// Takes an exclusive advisory lock without blocking.
    ///
    /// # Errors
    ///
    /// Returns [`TryLockError::WouldBlock`] on contention, or the underlying I/O error.
    pub fn try_lock(file: File) -> Result<Self, TryLockError> {
        file.try_lock()?;
        Ok(Self { file })
    }

    /// Reads metadata from the locked file descriptor.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if metadata cannot be read.
    pub fn metadata(&self) -> std::io::Result<Metadata> {
        self.file.metadata()
    }

    /// Duplicates the file descriptor for tests of lock lifetime.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if the descriptor cannot be duplicated.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn try_clone_file(&self) -> std::io::Result<File> {
        self.file.try_clone()
    }
}

impl Drop for HeldFileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl std::fmt::Debug for HeldFileLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldFileLock").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only assertions")]

    use super::*;

    #[test]
    fn a_held_lock_excludes_a_second_opener() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let _guard = HeldFileLock::try_lock(file.reopen().unwrap()).unwrap();
        assert!(matches!(
            HeldFileLock::try_lock(file.reopen().unwrap()),
            Err(TryLockError::WouldBlock)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn dropping_the_guard_unlocks_while_a_duplicate_descriptor_lives() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let guard = HeldFileLock::try_lock(file.reopen().unwrap()).unwrap();
        let duplicate = guard.try_clone_file().unwrap();
        assert!(matches!(
            HeldFileLock::try_lock(file.reopen().unwrap()),
            Err(TryLockError::WouldBlock)
        ));
        drop(guard);
        let _next = HeldFileLock::try_lock(file.reopen().unwrap()).unwrap();
        drop(duplicate);
        assert!(matches!(
            HeldFileLock::try_lock(file.reopen().unwrap()),
            Err(TryLockError::WouldBlock)
        ));
    }
}
