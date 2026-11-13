//! An exclusive or shared file lock ends when its guard drops.
//!
//! A `flock` belongs to the open file description, so closing one descriptor
//! ends it only when the last copy of that descriptor closes. A spawned child
//! can hold such a copy, and the guard therefore unlocks explicitly when it
//! drops.

use std::fs::{File, Metadata, TryLockError};

/// Stable identity of an open file on a supported platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileIdentity {
    /// Unix device and inode.
    Unix {
        /// Device number.
        dev: u64,
        /// Inode number.
        ino: u64,
    },
    /// Windows volume serial and file index.
    Windows {
        /// Volume serial number.
        volume_serial: u32,
        /// File index within the volume.
        file_index: u64,
    },
}

impl FileIdentity {
    /// Canonical protected-store representation.
    #[must_use]
    pub fn wire(&self) -> String {
        match self {
            Self::Unix { dev, ino } => format!("unix:{dev}:{ino}"),
            Self::Windows {
                volume_serial,
                file_index,
            } => format!("windows:{volume_serial:08x}:{file_index:016x}"),
        }
    }

    /// Parses a canonical file identity.
    ///
    /// # Errors
    /// Returns an invalid-data error for any noncanonical representation.
    pub fn parse(value: &str) -> std::io::Result<Self> {
        let invalid =
            || std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid file identity");
        let parts: Vec<_> = value.split(':').collect();
        let identity = match parts.as_slice() {
            ["unix", dev, ino] => Self::Unix {
                dev: dev.parse().map_err(|_| invalid())?,
                ino: ino.parse().map_err(|_| invalid())?,
            },
            ["windows", volume, index] => Self::Windows {
                volume_serial: u32::from_str_radix(volume, 16).map_err(|_| invalid())?,
                file_index: u64::from_str_radix(index, 16).map_err(|_| invalid())?,
            },
            _ => return Err(invalid()),
        };
        if identity.wire() != value {
            return Err(invalid());
        }
        Ok(identity)
    }
}

impl serde::Serialize for FileIdentity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.wire())
    }
}

impl<'de> serde::Deserialize<'de> for FileIdentity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// An exclusive or shared advisory file lock released on drop.
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

    /// Takes a shared advisory lock without blocking. Shared locks on one
    /// file coexist, and an exclusive lock excludes them.
    ///
    /// # Errors
    ///
    /// Returns [`TryLockError::WouldBlock`] while an exclusive lock is held,
    /// or the underlying I/O error.
    pub fn try_lock_shared(file: File) -> Result<Self, TryLockError> {
        file.try_lock_shared()?;
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

    /// Syncs the locked file's data and metadata to storage.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if the sync fails.
    pub fn sync_all(&self) -> std::io::Result<()> {
        self.file.sync_all()
    }

    /// Reads identity from the held handle, independently of its path.
    ///
    /// # Errors
    /// Returns an error when the platform cannot identify the file.
    pub fn identity(&self) -> std::io::Result<FileIdentity> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let metadata = self.file.metadata()?;
            Ok(FileIdentity::Unix {
                dev: metadata.dev(),
                ino: metadata.ino(),
            })
        }
        #[cfg(windows)]
        {
            let (volume_serial, file_index) =
                stellar_agent_windows_identity::file_identity(&self.file)
                    .map_err(std::io::Error::other)?;
            Ok(FileIdentity::Windows {
                volume_serial,
                file_index,
            })
        }
        #[cfg(not(any(unix, windows)))]
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "file identity unavailable",
        ))
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
    fn file_identity_wire_form_round_trips() {
        for (identity, wire) in [
            (FileIdentity::Unix { dev: 12, ino: 34 }, "unix:12:34"),
            (
                FileIdentity::Windows {
                    volume_serial: 0xabc,
                    file_index: 0x1234,
                },
                "windows:00000abc:0000000000001234",
            ),
        ] {
            assert_eq!(identity.wire(), wire);
            assert_eq!(FileIdentity::parse(wire).unwrap(), identity);
        }
        for invalid in [
            "unix:01:2",
            "unix:+1:2",
            "unix:1:2:3",
            "windows:abc:1234",
            "windows:00000ABC:0000000000001234",
            "other:1:2",
        ] {
            assert!(FileIdentity::parse(invalid).is_err());
        }
    }

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
