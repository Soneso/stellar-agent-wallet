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
//! `lock_sidecar_path`) and never changes when the
//! active file is renamed to a rotated archive. [`AuditWriterLock`] is
//! acquired once in `AuditWriter::open` and held for the writer's entire
//! lifetime, including across every rotation — rotation never releases or
//! re-acquires it. This is what guarantees the archive rename in
//! `AuditWriter::rotate` is safe against a concurrent second writer: no other
//! process can ever hold the writer role while the current one is rotating.
//!
//! # Carrier identity
//!
//! A keyed log has three carriers: the writer sidecar `<log>.lock`, the drain
//! lock `<log>.drain.lock` and the outbox lock `<log>.outbox.lock`. The
//! protected audit state records the file identity of each in a
//! [`CarrierRecord`]. [`AuditWriterLock::acquire_bound`] opens a carrier,
//! locks that handle, and only then reads the record and compares the
//! identity of the locked handle with it. The identity comes from the handle,
//! never from the path, so a lock file renamed or replaced after the record
//! was written refuses with `audit.carrier_replaced` instead of admitting a
//! second holder of the same role.

use std::fs::OpenOptions;
use std::path::Path;

use super::outbox::{OutboxLoss, OutboxState};
use super::tip_anchor::{CarrierRecord, TipAnchorStore};
use super::writer::WriterError;
use crate::file_lock::{FileIdentity, HeldFileLock};

/// The protected coordination role of a lock file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// The writer role.
    Writer,
    /// The drain role.
    Drain,
    /// The outbox role.
    Outbox,
}

impl std::fmt::Display for Carrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Writer => "writer",
            Self::Drain => "drain",
            Self::Outbox => "outbox",
        })
    }
}

/// A held carrier whose identity matched the protected record under the lock.
///
/// The record read under the lock is stable while the lock is held.
/// Enrollment and binding store carrier identities while holding all three
/// carriers. Acknowledgement holds all three while updating only the retired
/// watch. The guard keeps the generation that record named, so the holder
/// reads and writes the outbox commitment of that generation only.
#[derive(Debug)]
pub struct BoundCarrierLock {
    lock: AuditWriterLock,
    generation: u64,
}

impl BoundCarrierLock {
    /// The outbox generation the record named when the lock was taken.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Checks that the record still names the generation of this guard.
    ///
    /// A binding can retire the generation between the acquisition and the
    /// open of the outbox data file. A holder calls this after it opens the
    /// data file: a matching generation then fixes which file the handle holds.
    ///
    /// # Errors
    ///
    /// - [`WriterError::CarriersUnbound`] when the record is gone.
    /// - [`WriterError::CarrierGenerationChanged`] when the record names
    ///   another generation.
    /// - [`WriterError::TipAnchorStore`] when the record cannot be read.
    pub(crate) fn check_generation(&self, store: &dyn TipAnchorStore) -> Result<(), WriterError> {
        let record = store
            .load_carrier_record()?
            .ok_or(WriterError::CarriersUnbound)?;
        if record.generation != self.generation {
            return Err(WriterError::CarrierGenerationChanged {
                held: self.generation,
                current: record.generation,
            });
        }
        Ok(())
    }

    /// Releases the identity check and keeps the held lock.
    pub(crate) fn into_lock(self) -> AuditWriterLock {
        self.lock
    }

    /// A carrier whose identity the caller just recorded under the record of
    /// `generation` while holding `lock`.
    pub(crate) fn enrolled(lock: AuditWriterLock, generation: u64) -> Self {
        Self { lock, generation }
    }
}

/// An exclusive OFD/handle advisory lock over an audit-log writer's sidecar
/// lock file.
///
/// Acquired via [`AuditWriterLock::acquire`]; explicitly unlocked when the guard drops.
pub struct AuditWriterLock {
    /// The locked handle. Its identity is read for the carrier record, and
    /// the guard releases the lock on drop.
    file: HeldFileLock,
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
    /// The file opens for reading and writing on every platform: Windows reads
    /// the identity through `GetFileInformationByHandle`, which needs a handle
    /// with read access. On Windows the share mode omits delete sharing, so a
    /// held carrier cannot be renamed or deleted.
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
                .read(true)
                .write(true)
                // Do NOT truncate: the lock file is only an advisory-lock
                // carrier; its content is irrelevant.
                .truncate(false)
                .mode(0o600)
                .open(path)?
        };
        #[cfg(windows)]
        let file = {
            use std::os::windows::fs::OpenOptionsExt as _;
            const FILE_SHARE_READ: u32 = 1;
            const FILE_SHARE_WRITE: u32 = 2;
            OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .open(path)?
        };
        #[cfg(not(any(unix, windows)))]
        let file = OpenOptions::new()
            .create(true)
            .read(true)
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

        Ok(Self { file })
    }

    /// Identifies the locked handle.
    ///
    /// # Errors
    ///
    /// [`WriterError::CarrierIdentityUnavailable`] when the platform cannot
    /// identify the file. The underlying error is logged at `warn`.
    pub fn identity(&self) -> Result<FileIdentity, WriterError> {
        self.file.identity().map_err(|error| {
            tracing::warn!(%error, "audit carrier identity unavailable");
            WriterError::CarrierIdentityUnavailable
        })
    }

    /// Syncs the lock file, so its creation is durable before its identity is
    /// recorded.
    ///
    /// # Errors
    ///
    /// [`WriterError::Io`] when the sync fails.
    pub(crate) fn sync_all(&self) -> Result<(), WriterError> {
        Ok(self.file.sync_all()?)
    }

    /// Locks a carrier and checks its identity under that lock.
    ///
    /// Opens and try-locks the path first, then loads the record and compares
    /// the identity of the locked handle with the record's identity for
    /// `carrier`. An outbox acquisition also runs the retired watch.
    ///
    /// # Errors
    ///
    /// - [`WriterError::FileLocked`] and [`WriterError::Io`] as
    ///   [`AuditWriterLock::acquire`] returns them.
    /// - [`WriterError::CarriersUnbound`] when no record exists.
    /// - [`WriterError::CarrierReplaced`] when the locked file is not the
    ///   recorded one.
    /// - [`WriterError::CarrierIdentityUnavailable`] when the platform cannot
    ///   identify the locked file.
    /// - [`WriterError::RetiredOutboxChanged`] when an outbox acquisition finds
    ///   the retired generation's commitment changed.
    /// - [`WriterError::TipAnchorStore`] when the record or a commitment cannot
    ///   be read.
    pub fn acquire_bound(
        path: &Path,
        carrier: Carrier,
        store: &dyn TipAnchorStore,
    ) -> Result<BoundCarrierLock, WriterError> {
        Self::acquire_checked(path, carrier, store, carrier == Carrier::Outbox)
    }

    /// Locks the outbox carrier for a keyed queue append and checks its
    /// identity under that lock, without the retired watch.
    ///
    /// A keyed append reads and writes no commitment, so the retired watch
    /// belongs to the drain, which runs it on every acquisition.
    ///
    /// # Errors
    ///
    /// The errors of [`AuditWriterLock::acquire_bound`] except
    /// [`WriterError::RetiredOutboxChanged`].
    pub(crate) fn acquire_queue_bound(
        path: &Path,
        store: &dyn TipAnchorStore,
    ) -> Result<BoundCarrierLock, WriterError> {
        Self::acquire_checked(path, Carrier::Outbox, store, false)
    }

    fn acquire_checked(
        path: &Path,
        carrier: Carrier,
        store: &dyn TipAnchorStore,
        watch_retired: bool,
    ) -> Result<BoundCarrierLock, WriterError> {
        let lock = Self::acquire(path)?;
        let record = store
            .load_carrier_record()?
            .ok_or(WriterError::CarriersUnbound)?;
        lock.check_identity(carrier, &record)?;
        if watch_retired {
            check_retired(store, &record)?;
        }
        Ok(BoundCarrierLock {
            lock,
            generation: record.generation,
        })
    }

    /// Compares the identity of the locked handle with the record's identity
    /// for `carrier`.
    ///
    /// # Errors
    ///
    /// [`WriterError::CarrierReplaced`] on a mismatch, and
    /// [`WriterError::CarrierIdentityUnavailable`] when the platform cannot
    /// identify the locked file.
    pub(crate) fn check_identity(
        &self,
        carrier: Carrier,
        record: &CarrierRecord,
    ) -> Result<(), WriterError> {
        let expected = match carrier {
            Carrier::Writer => &record.writer,
            Carrier::Drain => &record.drain,
            Carrier::Outbox => &record.outbox_lock,
        };
        if &self.identity()? != expected {
            return Err(WriterError::CarrierReplaced { carrier });
        }
        Ok(())
    }
}

/// A retired generation whose commitment differs from the value the record
/// captured when the generation was retired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetiredChange {
    /// The retired generation.
    pub(crate) generation: u64,
    /// The commitment the store holds now, in its keyring form, or the empty
    /// string for an absent entry.
    pub(crate) observed: String,
    /// Rows the commitment counted at retirement.
    pub(crate) recorded_rows: u64,
    /// Rows the commitment counts now.
    pub(crate) observed_rows: u64,
}

impl RetiredChange {
    /// The change as a loss of queued rows: the rows counted at retirement
    /// against the rows counted now.
    pub(crate) fn loss(&self) -> OutboxLoss {
        OutboxLoss {
            expected_rows: self.recorded_rows,
            found_rows: self.observed_rows,
        }
    }
}

/// Reads the commitment of the record's retired generation and returns the
/// change when it differs from the value captured at retirement.
///
/// A holder of a retired generation writes only that generation's commitment
/// and the retired file, so any write it makes after the binding surfaces
/// here.
///
/// # Errors
///
/// [`WriterError::TipAnchorStore`] when a commitment cannot be read or the
/// captured value is not a commitment.
pub(crate) fn retired_changed(
    store: &dyn TipAnchorStore,
    record: &CarrierRecord,
) -> Result<Option<RetiredChange>, WriterError> {
    let Some(retired) = &record.retired else {
        return Ok(None);
    };
    let observed = store.load_outbox_state(retired.generation)?;
    let observed_value = observed
        .as_ref()
        .map(OutboxState::to_keyring_value)
        .unwrap_or_default();
    if observed_value == retired.state {
        return Ok(None);
    }
    let recorded_rows = if retired.state.is_empty() {
        0
    } else {
        OutboxState::parse(&retired.state)?.pending
    };
    Ok(Some(RetiredChange {
        generation: retired.generation,
        observed: observed_value,
        recorded_rows,
        observed_rows: observed.map_or(0, |state| state.pending),
    }))
}

/// Refuses when the record's retired generation changed after the binding.
///
/// # Errors
///
/// [`WriterError::RetiredOutboxChanged`] on a change, and the errors of
/// [`retired_changed`].
pub(crate) fn check_retired(
    store: &dyn TipAnchorStore,
    record: &CarrierRecord,
) -> Result<(), WriterError> {
    match retired_changed(store, record)? {
        Some(change) => Err(WriterError::RetiredOutboxChanged {
            generation: change.generation,
        }),
        None => Ok(()),
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
        let duplicate = guard.file.try_clone_file().unwrap();
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

    #[cfg(windows)]
    #[test]
    fn a_held_carrier_cannot_be_renamed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.lock");
        let _held = AuditWriterLock::acquire(&path).unwrap();
        assert!(std::fs::rename(&path, dir.path().join("moved.lock")).is_err());
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
