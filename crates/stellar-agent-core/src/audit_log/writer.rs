//! Hash-chained audit log writer with file locking, O_APPEND, and per-line fsync.
//!
//! Provides [`AuditWriter`] — the single-process writer that appends
//! [`AuditEntry`] records to the profile's audit log file.  Each write:
//! 1. Truncates arg_keys if needed to stay within the 4096-byte limit.
//! 2. Computes the current entry hash via `SHA-256(canonical_body || prev_hash)`.
//! 3. Serialises the full entry to JSON + newline.
//! 4. Writes via `O_APPEND` (kernel-enforced append-only).
//! 5. Calls `fsync(2)` so a crash truncates at most one entry.
//! 6. Signs the chain root (first entry per file) with HMAC-SHA256 only after
//!    the first entry has been written and fsynced.
//!
//! # Single-writer invariant
//!
//! An exclusive advisory lock is held on a **sidecar** lock file
//! (`<log>.lock`, next to the log — see [`lock_sidecar_path`] and
//! [`crate::audit_log::lock::AuditWriterLock`]) using
//! [`std::fs::File::lock`] (stable since Rust 1.89; exclusive by default).
//! The log file itself is NEVER locked.  The lock is held for the entire
//! lifetime of the [`AuditWriter`], including across every rotation — it is
//! acquired once in [`AuditWriter::open`] and never re-acquired or released
//! until the writer drops.  A second process attempting to open the same
//! profile receives [`WriterError::FileLocked`] immediately (non-blocking
//! `try_lock`).
//!
//! Within a process, callers must share one `AuditWriter` instance via
//! `Arc<Mutex<AuditWriter>>`.
//!
//! # Why the sidecar, not the log file
//!
//! `File::try_lock()` maps to `LockFileEx` on Windows, whose exclusivity is
//! enforced against ALL I/O issued through any OTHER handle to the SAME file
//! — including reads, and including a second handle opened by the SAME
//! process for the SAME path (documented Win32 behaviour, "Locking and
//! Unlocking Byte Ranges in Files", Microsoft Learn).  POSIX advisory locks
//! (OFD/flock) never restrict I/O through a different descriptor, only other
//! lock requests.  Locking the log file directly therefore made every
//! concurrent reader — `AuditReader`, `verify_log`, a second in-process
//! `File::open` — fail on Windows with a lock-violation error while a writer
//! was alive, even though the same code was harmless on POSIX.  Locking a
//! sidecar file instead preserves the single-writer invariant without ever
//! placing an OS lock on data any reader needs to touch, on every platform.
//!
//! # File-lock implementation note
//!
//! `std::fs::File::lock()` acquires an exclusive OFD (open-file-description)
//! advisory lock on POSIX (Linux `OFD_SETLK`, macOS `flock`).
//! `std::fs::File::try_lock()` is the non-blocking variant; returns
//! `Err(WouldBlock)` when the lock is held by another OFD.  The lock is
//! released when the sidecar lock file's handle is dropped (OFD/handle
//! closed).
//!
//! The stable standard-library `File::try_lock` API is used in preference to
//! the `fd-lock` crate.
//!
//! # Single-handle I/O against the active log file
//!
//! `AuditWriter::file` is the SAME `std::fs::File` used for every read and
//! write against the active log file (the initial chain-recovery scan, the
//! partial-rotation detection scan, and every subsequent `write_entry`).
//! The log file carries no OS lock (the writer's lock lives on the sidecar),
//! so this is purely a consistency invariant: a single handle guarantees the
//! writer's in-memory state (`last_hash`, `is_new_file`) is always derived
//! from exactly the bytes it will next append after, with no possibility of
//! a second handle observing a different buffered view of the same file.
//!
//! # Per-file HMAC sidecar
//!
//! Each log file has its own `<file>.root_hmac` sidecar written on the first
//! entry of that file.  On rotation the sidecar is renamed alongside the log
//! file: `audit.jsonl` → `audit.jsonl.<ts>` AND
//! `audit.jsonl.root_hmac` → `audit.jsonl.<ts>.root_hmac`.
//!
//! Durability invariant: the on-disk sidecar's chain-root tag is always either
//! (a) absent, or (b) covers a prefix of entries that has been fsynced to the
//! log file.  In the current sidecar format the prefix is the first entry's
//! canonical body.  A crash after entry fsync but before sidecar write can
//! therefore leave the sidecar absent; it must never leave a sidecar tag for an
//! entry that was not first written and fsynced to the log.  Conceptually, a
//! verifier would treat `chain-root-tag covers a strict superset of log entries`
//! as the impossible `ChainRootAhead` state.
//!
//! # Rotation
//!
//! When the file exceeds [`ROTATION_THRESHOLD_BYTES`] (10 MiB), the writer:
//! 1. Writes an [`AuditRotationHandoff`](crate::audit_log::entry::AuditEntry::new_rotation_handoff)
//!    entry naming the new active filename.
//! 2. Renames the active file to `<stem>.<compact-ts>`.
//! 3. Renames the active file's `.root_hmac` sidecar (if present) to
//!    `<stem>.<compact-ts>.root_hmac`.
//! 4. Opens a fresh active file; its first entry uses the rotation handoff's
//!    hash as `previous_entry_hash` (cross-file chain bridge).
//! 5. Retains at most [`MAX_ROTATED_FILES`] (10) rotated copies.
//!
//! See [`crate::audit_log`] module-level rustdoc § First-entry-per-file rule
//! for the canonical statement of which hash a new file's first entry chains
//! from (zero-block hash for the very first file; handoff entry hash for all
//! subsequent files).
//!
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    chain::{ZERO_BLOCK_HASH, decode_hash, sign_chain_root},
    entry::AuditEntry,
};
use crate::timefmt::current_iso8601_utc;

// Re-export rotation constants at the writer module level for crate-internal
// consumers and tests that currently import from this module.
pub use super::rotation::{MAX_ROTATED_FILES, ROTATION_THRESHOLD_BYTES};

#[cfg(test)]
static FORCE_NEXT_ROTATION_CREATE_FAILURE_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

static LAST_ROTATION_TIMESTAMP_MS: AtomicU64 = AtomicU64::new(0);
static ROTATION_COLLISION_COUNTER: AtomicU64 = AtomicU64::new(0);

// ── AuditWriter ───────────────────────────────────────────────────────────────

/// Single-writer append-only audit log with hash-chained entries.
///
/// Holds an exclusive `std::fs::File::lock()` advisory lock on the log file
/// for its entire lifetime.  Drop to release the lock and close the file.
///
/// Obtain via [`AuditWriter::open`]; then call [`AuditWriter::write_entry`]
/// to append entries.
///
/// # Examples
///
/// ```no_run
/// use std::path::PathBuf;
/// use stellar_agent_core::audit_log::entry::{AuditEntry, NewToolInvocation};
/// use stellar_agent_core::audit_log::schema::PolicyDecision;
/// use stellar_agent_core::audit_log::writer::AuditWriter;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut writer = AuditWriter::open(PathBuf::from("/tmp/audit/test.jsonl"), None)?;
/// let entry = AuditEntry::new_tool_invocation(NewToolInvocation::new(
///     "stellar_pay_commit",
///     "stellar:testnet",
///     vec!["destination".to_owned()],
///     PolicyDecision::Allow,
///     uuid::Uuid::new_v4().to_string(),
/// ));
/// // previous_entry_hash is set by write_entry from writer.last_entry_hash().
/// writer.write_entry(entry)?;
/// # Ok(())
/// # }
/// ```
pub struct AuditWriter {
    /// Path to the active log file.
    path: PathBuf,
    /// Exclusive advisory lock on the sidecar `<path>.lock` file.
    ///
    /// Held for the entire `AuditWriter` lifetime, including across every
    /// rotation — never released or re-acquired until the writer drops.  The
    /// log file at `path` itself carries no lock; see the module-level
    /// "Single-writer invariant" and "Why the sidecar, not the log file"
    /// sections.  This field is never read; its only purpose is to hold the
    /// lock for as long as the `AuditWriter` lives.
    _lock: crate::audit_log::lock::AuditWriterLock,
    /// The single OS handle used for every read and write against the active
    /// log file.
    ///
    /// Held for the entire `AuditWriter` lifetime; dropping it closes the
    /// file.  See the module-level "Single-handle I/O against the active log
    /// file" section for why one handle is used rather than a fresh handle
    /// per operation.
    file: File,
    /// SHA-256 hash of the last entry written to the current file.
    ///
    /// In `Debug` output this is truncated to first-8 + last-8 characters of
    /// the hex portion to avoid full-hash exposure in debug traces.
    last_hash: String,
    /// Whether the active file is empty (determines chain root signing).
    is_new_file: bool,
    /// Optional 32-byte HMAC key for chain-root signing (Zeroizing on drop).
    ///
    /// `Zeroizing<[u8; 32]>` ensures the key material is zeroed when the
    /// `AuditWriter` is dropped.
    hmac_key: Option<Zeroizing<[u8; 32]>>,
    /// Test-only fault seam for the write-entry durability invariant.
    #[cfg(test)]
    fail_after_entry_before_sidecar: bool,
    /// Archive name produced by a failed mid-rotation active-lock acquisition.
    ///
    /// Once set, the writer refuses all future writes. The caller must discard
    /// the instance and reopen after operator inspection.
    partial_rotation_archive: Option<PathBuf>,
}

impl std::fmt::Debug for AuditWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Truncate last_hash to first-8-last-8 of the hex portion.
        let hash_display = if self.last_hash.starts_with("sha256:") && self.last_hash.len() > 22 {
            let hex = &self.last_hash[7..];
            if hex.len() >= 16 {
                format!("sha256:{}...{}", &hex[..8], &hex[hex.len() - 8..])
            } else {
                self.last_hash.clone()
            }
        } else {
            self.last_hash.clone()
        };

        f.debug_struct("AuditWriter")
            .field("path", &self.path)
            .field("last_hash", &hash_display)
            .field("is_new_file", &self.is_new_file)
            .finish_non_exhaustive()
    }
}

impl AuditWriter {
    /// Opens the audit log file at `path` and acquires an exclusive advisory
    /// lock via [`std::fs::File::try_lock`].
    ///
    /// Creates parent directories if they do not exist.  On Unix, the parent
    /// directory is created with mode `0700` (owner-only read-write-execute) so
    /// rotation siblings are not listable by other local users.  On non-Unix
    /// platforms the default OS permissions are used.  Sets file mode `0600`
    /// (owner-read-write only) on POSIX.  Opens in `O_APPEND` mode so all
    /// writes are kernel-enforced appends.
    ///
    /// The log path **must** have an explicit parent directory component.  A
    /// bare filename (e.g. `audit.jsonl` with no directory prefix) is rejected
    /// with [`WriterError::PathContract`] because the rotated-sibling placement
    /// and directory-mode invariants require a known parent directory.
    ///
    /// The lock is acquired BEFORE reading the existing file for chain recovery
    /// so that no other process can append entries between the read and the
    /// first write.
    ///
    /// If the file is already locked by another process,
    /// [`WriterError::FileLocked`] is returned immediately (non-blocking).
    ///
    /// `hmac_key` is the optional 32-byte chain-root HMAC key wrapped in a
    /// [`Zeroizing`] guard.  If `None`, the chain root is not HMAC-signed (the
    /// hash chain is still intact).
    ///
    /// # Errors
    ///
    /// - [`WriterError::PathContract`] if `path` has no parent directory
    ///   component (bare filename).
    /// - [`WriterError::Io`] on I/O failure.
    /// - [`WriterError::FileLocked`] if another process holds the exclusive
    ///   lock on the log file.
    pub fn open(path: PathBuf, hmac_key: Option<Zeroizing<[u8; 32]>>) -> Result<Self, WriterError> {
        // Enforce parent-component contract: a bare filename has no known
        // parent directory, making rotated-sibling placement and directory-mode
        // enforcement impossible.  Callers must supply an explicit parent, e.g.
        // `~/.local/state/stellar-agent/audit/default.jsonl`.
        let parent = path.parent().ok_or_else(|| WriterError::PathContract {
            detail: "audit log path must have a parent directory component \
                     (e.g. /path/to/audit/default.jsonl, not a bare filename)"
                .to_owned(),
        })?;

        // Create parent directories with restricted permissions on Unix so
        // rotation siblings are not listable by other local users.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(parent)?;
        }

        // Acquire the exclusive sidecar lock BEFORE touching the data file at
        // all, so no other process can append between the chain-recovery read
        // and the first write, and a losing opener never even creates the
        // data file.  The log file itself is never locked — see the
        // module-level "Single-writer invariant" and "Why the sidecar, not
        // the log file" sections.
        let lock_path = lock_sidecar_path(&path);
        let lock = crate::audit_log::lock::AuditWriterLock::acquire(&lock_path)?;

        // Open the data file. No lock is placed on it; see above. This is the
        // single handle used for every subsequent read and write against the
        // active log file — see the module-level "Single-handle I/O against
        // the active log file" section.
        let file = open_append_0600(&path)?;

        // Detect partial-rotation state after acquiring the lock, before reading
        // the chain.  Returns IntegrityViolation(VerifyError::PartialRotation)
        // on any anomaly; Ok(()) when the directory is clean.
        // No auto-recovery — silent recovery could mask a tamper attempt.
        detect_partial_rotation(&path, &file)?;

        // Check if the file is empty (determines chain root vs continuation).
        let is_new_file = file.metadata()?.len() == 0;

        // Determine initial last_hash.
        let last_hash = if is_new_file {
            ZERO_BLOCK_HASH.to_owned()
        } else {
            read_and_verify_entry_chain_at_open(&file)?
        };

        Ok(Self {
            path,
            _lock: lock,
            file,
            last_hash,
            is_new_file,
            hmac_key,
            #[cfg(test)]
            fail_after_entry_before_sidecar: false,
            partial_rotation_archive: None,
        })
    }

    /// Returns the SHA-256 hash of the last entry written to the current file.
    ///
    /// Callers constructing a new [`AuditEntry`] should use this value as the
    /// `previous_entry_hash`.
    #[must_use]
    pub fn last_entry_hash(&self) -> &str {
        &self.last_hash
    }

    /// Returns the in-memory chain-tip hash as a raw 32-byte array.
    ///
    /// The chain tip is the SHA-256 of the most-recently-written entry. It is
    /// sourced from the writer's in-memory state (not re-read from disk), so
    /// it is always consistent with the most-recent `write_entry` call.
    ///
    /// # Use for `SaSignerSetBaselined.prev_chain_tip_hash`
    ///
    /// The `prev_chain_tip_hash` field of `SaSignerSetBaselined` MUST be
    /// sourced from this method inside the same write critical section (while
    /// the `Arc<Mutex<AuditWriter>>` is held), never re-read from disk after
    /// lock release.
    ///
    /// # Returns
    ///
    /// A 32-byte raw SHA-256 digest. Returns `[0u8; 32]` when no entry has
    /// been written yet (the writer's initial hash is the zero-block hash
    /// `SHA-256([0u8; 32])`; decoding it to bytes and returning that would be
    /// equivalent, but returning `[0u8; 32]` directly is a more explicit
    /// "no prior entry" sentinel at the call site).
    #[must_use]
    pub fn current_chain_tip(&self) -> [u8; 32] {
        use super::chain::decode_hash;
        decode_hash(&self.last_hash).unwrap_or([0u8; 32])
    }

    /// Appends `entry` to the audit log.
    ///
    /// Steps:
    /// 1. Rotate if needed (file size exceeds [`ROTATION_THRESHOLD_BYTES`]).
    /// 2. Truncate arg_keys if needed to stay within the 4096-byte limit.
    /// 3. Set `entry.previous_entry_hash` to the writer's `last_hash`.
    /// 4. Compute `current_hash = SHA-256(canonical_body || prev_hash)`.
    /// 5. Serialise to JSON + `\n`.
    /// 6. Write via `O_APPEND`.
    /// 7. `fsync(2)`.
    /// 8. If first entry in the file and `hmac_key` is set, sign the chain root
    ///    and write the `.root_hmac` sidecar.
    ///
    /// Durability invariant: the on-disk sidecar's chain-root tag is always
    /// either (a) absent, or (b) covers a prefix of entries that has been
    /// fsynced to the log file.  The sidecar write therefore occurs strictly
    /// after the first log entry write and `sync_data()`.
    ///
    /// # Errors
    ///
    /// - [`WriterError::Io`] on I/O failure.
    /// - [`WriterError::Serialise`] if the entry cannot be serialised.
    /// - [`WriterError::Hash`] if the hash computation fails.
    pub fn write_entry(&mut self, mut entry: AuditEntry) -> Result<(), WriterError> {
        if let Some(archive_name) = &self.partial_rotation_archive {
            return Err(WriterError::PartialRotation {
                archive_name: archive_name.clone(),
                active_locked_by: None,
            });
        }

        // Rotate if needed before writing.
        if self.needs_rotation()? {
            self.rotate()?;
        }

        // Truncate arg_keys if needed.
        entry.truncate_arg_keys_if_needed()?;

        // Set the previous hash on the entry.
        entry.previous_entry_hash = self.last_hash.clone();

        // Compute the new entry hash without allocating the canonical body.
        let current_hash = compute_entry_hash_streamed(&entry, &self.last_hash)?;

        // Serialise the entry (with the correct previous_entry_hash set above).
        let json = serde_json::to_vec(&entry).map_err(WriterError::Serialise)?;
        let mut line = json;
        line.push(b'\n');

        // O_APPEND write + fsync.
        self.file.write_all(&line)?;
        self.file.flush()?;
        self.file.sync_data()?;

        #[cfg(test)]
        if self.fail_after_entry_before_sidecar {
            return Err(WriterError::Io(io::Error::other(
                "test fault after entry fsync before root_hmac sidecar",
            )));
        }

        // For the chain root (first entry per file), optionally sign with HMAC
        // and write the sidecar AFTER the log entry has been flushed.
        if self.is_new_file {
            if let Some(ref key) = self.hmac_key {
                let body = entry
                    .canonical_json_body()
                    .map_err(WriterError::Serialise)?;
                let tag = sign_chain_root(key.as_ref(), &body).map_err(|e| {
                    WriterError::Io(io::Error::other(format!("HMAC sign failed: {e}")))
                })?;
                self.write_root_hmac_sidecar(&tag)?;
            }
            self.is_new_file = false;
        }

        // Advance the chain.
        self.last_hash = current_hash;
        Ok(())
    }

    /// Enables a test-only fault seam immediately after log-entry fsync and
    /// immediately before the chain-root sidecar write.
    #[cfg(test)]
    pub(crate) fn set_fail_after_entry_before_sidecar(&mut self, enabled: bool) {
        self.fail_after_entry_before_sidecar = enabled;
    }

    /// Forces a log rotation without waiting for the size threshold.
    ///
    /// `pub(crate)` and `#[cfg(test)]` — only for unit tests that need to
    /// trigger rotation without writing 10 MiB of filler data.
    ///
    /// Directly invokes the internal `rotate()` logic.
    ///
    /// # Errors
    ///
    /// Returns `WriterError` on I/O or serialisation failure.
    #[cfg(test)]
    pub(crate) fn force_rotate_for_test(&mut self) -> Result<(), WriterError> {
        self.rotate()
    }

    /// Returns the path to the active log file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Returns `true` if the file size exceeds the rotation threshold.
    ///
    /// # Errors
    ///
    /// Returns [`WriterError::Io`] if file metadata cannot be read.
    fn needs_rotation(&self) -> Result<bool, WriterError> {
        let meta = self.file.metadata()?;
        Ok(meta.len() >= ROTATION_THRESHOLD_BYTES)
    }

    /// Rotates the active log file.
    ///
    /// Writes a handoff entry, renames the current file + its HMAC sidecar,
    /// prunes excess rotated files, and opens a fresh active file.
    ///
    /// # Errors
    ///
    /// Returns [`WriterError::Io`] / [`WriterError::Serialise`] /
    /// [`WriterError::Hash`] on failure.
    ///
    /// # Failure modes
    ///
    /// Two intermediate states can occur if the process crashes mid-rotation:
    ///
    /// **Recoverable — handoff written but `fs::rename` failed:**
    /// The active file ends with an `AuditRotationHandoff` entry, but the file
    /// has not been renamed.  On the next `AuditWriter::open` the writer resumes
    /// appending to the still-active file.  `audit verify` will not see a gap
    /// because the rotated archive does not exist yet; however the handoff entry
    /// is "orphaned" — it names an archive file that does not exist at that point.
    /// Recovery: the next successful rotation produces a correctly-named archive.
    ///
    /// **Potentially unrecoverable — `fs::rename` succeeded but
    /// `create_new_active_file_after_rotation` failed:**
    /// The active file has been archived but the new active path could not be
    /// created.  The writer is left in an inconsistent state (`self.file`
    /// still refers to the now-archived file, though it holds no lock on it —
    /// any reader may open it freely) and the current `AuditWriter` instance
    /// cannot be used again.  The next `AuditWriter::open` on the same path
    /// will create a fresh chain, losing the cross-file chain bridge.
    fn rotate(&mut self) -> Result<(), WriterError> {
        let stem = self
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("audit.jsonl");
        let ts = compact_timestamp();
        let rotated_name = format!("{stem}.{ts}");
        let rotated_path = self
            .path
            .parent()
            .map(|p| p.join(&rotated_name))
            .unwrap_or_else(|| PathBuf::from(&rotated_name));

        // Write the rotation handoff entry to the current file.
        let mut handoff = AuditEntry::new_rotation_handoff(
            // NOTE: handoff names the *rotated* file — i.e. the archive file,
            // not the new active file.  `verify_log` uses this to locate the
            // archived file by name.  The name here must match the basename
            // of `rotated_path`.
            &rotated_name,
            uuid::Uuid::new_v4().to_string(),
        );
        handoff.previous_entry_hash = self.last_hash.clone();
        // Defensive: truncate arg_keys even though handoff entries always have
        // an empty arg_keys list — ensures consistency if future code paths
        // populate arg_keys on handoff entries.
        handoff
            .truncate_arg_keys_if_needed()
            .map_err(WriterError::Serialise)?;
        let handoff_hash = compute_entry_hash_streamed(&handoff, &self.last_hash)?;

        let json = serde_json::to_vec(&handoff).map_err(WriterError::Serialise)?;
        let mut line = json;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.flush()?;
        self.file.sync_data()?;

        // Rename the HMAC sidecar before renaming the log file so both
        // renames are co-located in time.
        let active_hmac_sidecar = hmac_sidecar_path(&self.path);
        let rotated_hmac_sidecar = hmac_sidecar_path(&rotated_path);
        if active_hmac_sidecar.exists() {
            fs::rename(&active_hmac_sidecar, &rotated_hmac_sidecar)?;
        }

        // Rename the current log file to the rotated name.
        fs::rename(&self.path, &rotated_path)?;

        // Prune excess rotated files.
        self.prune_rotated_files()?;

        // Open the new active file BEFORE swapping the writer state.
        //
        // Unlike a per-file lock scheme, no race window opens up here: the
        // sidecar lock acquired in `AuditWriter::open` is held continuously
        // across the whole rotation (never released, never re-acquired), so
        // no other process can ever hold the writer role while we are
        // between `fs::rename` and this `create_new` call — the active path
        // being briefly absent from the directory is a filesystem-visible
        // detail, not a lock-ownership race. A concurrent READER observing
        // this brief absence is expected and handled — see
        // `reader::collect_files_newest_first`'s rotation-window tolerance.
        //
        // Use create_new (O_CREAT|O_EXCL) to defend against a race where an
        // attacker pre-creates the new active path between our fs::rename and
        // this open.  AlreadyExists from a crash-recovery scenario (stale
        // partial file) is surfaced as Io so the caller can intervene;
        // the stale file MUST NOT be reused because its chain state is unknown.
        let new_file = match create_new_active_file_after_rotation(&self.path) {
            Ok(file) => file,
            Err(_) => {
                let archive_name = PathBuf::from(&rotated_name);
                self.partial_rotation_archive = Some(archive_name.clone());
                return Err(WriterError::PartialRotation {
                    archive_name,
                    active_locked_by: None,
                });
            }
        };

        // Atomic swap: the old handle is dropped here.
        self.file = new_file;
        self.last_hash = handoff_hash;
        self.is_new_file = true;

        Ok(())
    }

    /// Removes the oldest rotated files, keeping at most [`MAX_ROTATED_FILES`].
    ///
    /// Only deletes files whose names match the strict rotated-sibling pattern
    /// (via [`is_rotated_sibling`]) to avoid accidentally removing sidecars.
    ///
    /// # Errors
    ///
    /// Returns [`WriterError::Io`] if the directory cannot be read.
    fn prune_rotated_files(&self) -> Result<(), WriterError> {
        let dir = match self.path.parent() {
            Some(d) => d,
            None => return Ok(()),
        };
        let stem = self
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("audit.jsonl");

        let mut rotated: Vec<PathBuf> = fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|s| s.to_str())
                    .map(|name| is_rotated_sibling(stem, name))
                    .unwrap_or(false)
            })
            .collect();

        if rotated.len() <= MAX_ROTATED_FILES {
            return Ok(());
        }

        rotated.sort();
        let excess = rotated.len() - MAX_ROTATED_FILES;
        for path in rotated.iter().take(excess) {
            let _ = fs::remove_file(path);
            // Also remove the matching HMAC sidecar if present.
            let sidecar = hmac_sidecar_path(path);
            if sidecar.exists() {
                let _ = fs::remove_file(&sidecar);
            }
        }
        Ok(())
    }

    /// Writes the chain-root HMAC tag to a `<file>.root_hmac` sidecar file.
    ///
    /// File is created with mode `0600` on POSIX.
    ///
    /// # Errors
    ///
    /// Returns [`WriterError::Io`] on I/O failure.
    fn write_root_hmac_sidecar(&self, tag: &str) -> Result<(), WriterError> {
        let sidecar = hmac_sidecar_path(&self.path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&sidecar)?;
            f.write_all(tag.as_bytes())?;
            f.write_all(b"\n")?;
            f.sync_data()?;
        }
        #[cfg(not(unix))]
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&sidecar)?;
            f.write_all(tag.as_bytes())?;
            f.write_all(b"\n")?;
            f.sync_data()?;
        }
        Ok(())
    }
}

// ── Rotated-sibling classification ───────────────────────────────────────────

/// Returns `true` iff `name` is a rotated sibling of the active file named
/// `stem`.
///
/// A valid rotated sibling has the form `<stem>.<compact-ts>` where
/// `<compact-ts>` is exactly one of:
/// - `YYYYMMDDTHHMMSS` — 8 date digits + `T` + 6 time digits (second precision).
/// - `YYYYMMDDTHHMMSSmmm` — 8 date digits + `T` + 9 time digits (millisecond
///   precision, as produced by [`compact_timestamp`]).
/// - `YYYYMMDDTHHMMSSmmm-N` - millisecond precision plus a decimal collision
///   counter for multiple rotations in the same millisecond.
///
/// Requiring an exact digit count prevents future-format collisions (e.g. a
/// nanosecond-precision suffix starting with the same 15 characters) and
/// avoids false positives on files with long numeric tails.
///
/// This strict check prevents the glob from matching:
/// - `.lock` sidecars  (`audit.jsonl.lock`)
/// - `.root_hmac` sidecars  (`audit.jsonl.root_hmac`)
/// - Unrelated-prefix files  (`other.jsonl.20260428T123456`)
/// - The active file itself
///
/// The implementation is a simple two-part string split and a digit/`T` scan —
/// no regex dependency warranted.
///
/// For stem `audit.jsonl`: `audit.jsonl.20260428T123456` (second precision),
/// `audit.jsonl.20260428T123456789` (millisecond precision), and
/// `audit.jsonl.20260428T123456789-1` (same-ms collision suffix) match.
/// `audit.jsonl.lock`, `audit.jsonl.root_hmac`, `other.jsonl.20260428T123456`,
/// and any suffix with the wrong digit count do not.
pub(crate) fn is_rotated_sibling(stem: &str, name: &str) -> bool {
    // Must start with exactly "<stem>."
    let prefix = format!("{stem}.");
    let Some(suffix) = name.strip_prefix(&prefix) else {
        return false;
    };
    let (base_suffix, collision_suffix) = match suffix.split_once('-') {
        Some((base, collision)) => {
            if collision.is_empty() || !collision.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            (base, Some(collision))
        }
        None => (suffix, None),
    };
    if collision_suffix.is_some() && base_suffix.len() != 18 {
        return false;
    }
    // suffix must be exactly 15 chars (8+T+6, second precision) or
    // exactly 18 chars (8+T+9, millisecond precision).
    // Any other length is rejected to prevent future-prefix collisions.
    match base_suffix.len() {
        15 | 18 => {}
        _ => return false,
    }
    // First 8 chars must be decimal digits (YYYYMMDD).
    if !base_suffix[..8].bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // Ninth char must be 'T'.
    if base_suffix.as_bytes()[8] != b'T' {
        return false;
    }
    // Remaining chars after 'T' must all be decimal digits.
    // Length constraint guarantees either 6 or 9 digits here.
    base_suffix[9..].bytes().all(|b| b.is_ascii_digit())
}

// ── Rotation create-failure test seam ────────────────────────────────────────
//
// The sidecar lock (see `lock.rs`) is acquired once in `AuditWriter::open` and
// held for the writer's entire lifetime, including across rotation — rotation
// never acquires or releases any lock. The only failure `rotate()` can hit
// when establishing the new active file is the CREATE itself (e.g. a stale
// leftover file from a previous crash). This seam lets a test force that
// create to fail deterministically, without needing to engineer a real
// pre-existing file collision.

/// Returns `Err(WriterError::Io)` if a test has armed the forced
/// rotation-create failure seam for `path`, consuming the arm.  A no-op
/// outside `#[cfg(test)]`.
fn check_forced_rotation_create_failure(path: &Path) -> Result<(), WriterError> {
    #[cfg(test)]
    if let Ok(mut force_path) = FORCE_NEXT_ROTATION_CREATE_FAILURE_PATH.lock()
        && force_path.as_deref() == Some(path)
    {
        *force_path = None;
        return Err(WriterError::Io(io::Error::other(
            "test fault: forced rotation create failure",
        )));
    }
    #[cfg(not(test))]
    let _ = path;
    Ok(())
}

/// Creates the new active file after a rotation (`O_CREAT | O_EXCL`, mode
/// 0600 on POSIX). No lock is acquired here — the sidecar lock acquired in
/// `AuditWriter::open` already excludes every other writer for the entire
/// rotation, so there is no race window for a second lock acquisition to
/// close.
///
/// # Errors
///
/// - [`WriterError::Io`] on create failure (including `AlreadyExists` from a
///   stale leftover file), or if a test has armed the forced-failure seam for
///   `path`.
fn create_new_active_file_after_rotation(path: &Path) -> Result<File, WriterError> {
    check_forced_rotation_create_failure(path)?;
    open_create_new_0600(path).map_err(WriterError::Io)
}

// ── Path helpers ──────────────────────────────────────────────────────────────

/// Returns the `.root_hmac` sidecar path for `log_path`.
///
/// For `audit.jsonl` → `audit.jsonl.root_hmac`.
/// For `audit.jsonl.20260428T123456` → `audit.jsonl.20260428T123456.root_hmac`.
///
/// Uses `set_extension` via push onto the OsString so the existing extension
/// (`.jsonl`) is preserved.
pub(super) fn hmac_sidecar_path(log_path: &Path) -> PathBuf {
    // `with_extension` replaces the last extension; we want to APPEND.
    // Build the sidecar name by appending ".root_hmac" to the full filename.
    let mut sidecar = log_path.to_path_buf();
    let existing = sidecar
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_owned();
    sidecar.set_file_name(format!("{existing}.root_hmac"));
    sidecar
}

/// Returns the sidecar lock-file path for `log_path`.
///
/// For `audit.jsonl` → `audit.jsonl.lock`.
///
/// This path is derived from the ACTIVE log path's stem and is never
/// recomputed against a rotated archive name — the sidecar lock stays fixed
/// at this path for the writer's entire lifetime, including across rotation
/// (see the module-level "Single-writer invariant" section).  `.lock` is
/// already excluded from [`is_rotated_sibling`]'s pattern (see
/// `is_rotated_sibling_rejects_lock_sidecar`), so rotation's directory scan
/// and pruning never touch it.
pub(super) fn lock_sidecar_path(log_path: &Path) -> PathBuf {
    let mut sidecar = log_path.to_path_buf();
    let existing = sidecar
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_owned();
    sidecar.set_file_name(format!("{existing}.lock"));
    sidecar
}

/// Returns `true` if the sidecar lock for `log_path` is currently held by a
/// live writer (in this process or another).
///
/// Performs a non-blocking probe: attempts to acquire the lock itself and
/// immediately releases it (drop) if that succeeds. Used by
/// `reader::collect_files_newest_first` to distinguish a genuinely
/// out-of-band-deleted active file from the microsecond-scale window between
/// `rotate()`'s archive rename and its new active file's `create_new`, during
/// which a live writer still holds this lock throughout.
///
/// Returns `false` on any I/O error other than contention (e.g. the parent
/// directory does not exist) — an ambiguous probe result must never be
/// treated as "a writer is live", or a genuine integrity violation could be
/// silently retried away.
///
/// Two accepted side effects, both confined to the anomalous
/// active-file-absent path this probe serves:
///
/// - The probe CREATES the sidecar file when absent (acquisition opens with
///   create), so `verify` against a copied-off audit directory is not
///   strictly non-mutating on this path. On a read-only filesystem the
///   acquisition fails, which degrades to `false` — the correct give-up
///   direction.
/// - While a successful probe momentarily holds the lock, a concurrently
///   STARTING writer's `open()` can observe spurious contention and refuse
///   with `FileLocked`. The window is microseconds, the refusal is
///   fail-closed and indistinguishable from genuine contention, and every
///   opener already treats `FileLocked` as retryable; a live writer is never
///   affected (the probe cannot acquire a held lock).
///
/// On the reader path this probe is vacuous-by-construction: `AuditReader`
/// keeps its writer alive, so the lock is always held and the fast give-up
/// branch is reachable only through writer-independent entry points
/// (`verify::verify_log`).
pub(super) fn sidecar_lock_is_held(log_path: &Path) -> bool {
    matches!(
        crate::audit_log::lock::AuditWriterLock::acquire(&lock_sidecar_path(log_path)),
        Err(WriterError::FileLocked)
    )
}

/// Bounded number of re-scan attempts tolerated for the rotation window (see
/// the `audit_log` module's "Reader consistency posture" docs).
pub(super) const ROTATION_WINDOW_RETRY_ATTEMPTS: u32 = 20;

/// Delay between re-scan attempts. Small enough that the total bound
/// (`ROTATION_WINDOW_RETRY_ATTEMPTS * ROTATION_WINDOW_RETRY_DELAY` = a
/// nominal 20ms; coarser OS sleep granularity — Windows timers tick at
/// ~15.6ms by default — stretches the real elapsed bound accordingly, still
/// finite and small) is imperceptible to any caller, large enough to give a
/// concurrent writer's rotation a realistic chance to complete. The waits
/// are synchronous `thread::sleep`s: callers on an async executor should
/// reach these reader/verify APIs through `spawn_blocking` (as with any of
/// this module's file I/O).
pub(super) const ROTATION_WINDOW_RETRY_DELAY: std::time::Duration =
    std::time::Duration::from_millis(1);

/// Shared bounded-retry primitive for the rotation-window tolerance used by
/// both `reader::collect_files_newest_first` and `verify::collect_file_chain`.
///
/// Re-invokes `rescan` up to [`ROTATION_WINDOW_RETRY_ATTEMPTS`] times while
/// `is_still_absent` reports the active file is still missing from the most
/// recent scan AND the writer's sidecar lock for `log_path` is observably
/// held by a live writer. Returns as soon as `is_still_absent` reports the
/// file has reappeared, or once the bound is exhausted, or immediately if no
/// writer holds the lock (an unheld lock means the absence is not a live
/// rotation in progress, so waiting would only delay a genuine integrity
/// error for no benefit). Never turns a genuine gap into success — it only
/// ever delays, by at most `ROTATION_WINDOW_RETRY_ATTEMPTS *
/// ROTATION_WINDOW_RETRY_DELAY`, the point at which a still-missing file is
/// reported as one.
pub(super) fn wait_out_transient_rotation_window<T, E>(
    log_path: &Path,
    mut latest: T,
    is_still_absent: impl Fn(&T) -> bool,
    mut rescan: impl FnMut() -> Result<T, E>,
) -> Result<T, E> {
    for _ in 0..ROTATION_WINDOW_RETRY_ATTEMPTS {
        if !is_still_absent(&latest) {
            return Ok(latest);
        }
        if !sidecar_lock_is_held(log_path) {
            break;
        }
        std::thread::sleep(ROTATION_WINDOW_RETRY_DELAY);
        latest = rescan()?;
    }
    Ok(latest)
}

struct Sha256Writer<'a>(&'a mut Sha256);

impl Write for Sha256Writer<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn compute_entry_hash_streamed(
    entry: &AuditEntry,
    previous_entry_hash: &str,
) -> Result<String, WriterError> {
    let prev_bytes = decode_hash(previous_entry_hash).map_err(WriterError::Hash)?;
    let mut hasher = Sha256::new();
    {
        let mut writer = Sha256Writer(&mut hasher);
        entry
            .canonical_json_write(&mut writer)
            .map_err(WriterError::Serialise)?;
    }
    hasher.update(prev_bytes);
    Ok(format!("sha256:{}", crate::hex::encode(&hasher.finalize())))
}

// ── Platform-specific file open ───────────────────────────────────────────────

/// Opens (or creates) the file at `path` in `O_APPEND | O_RDWR | O_CREAT`
/// mode with permissions `0600` on POSIX.
///
/// Read access is included (not just append) because this handle also
/// performs the partial-rotation scan and the chain-recovery read at open
/// time — see the module-level "Single-handle requirement (Windows)" section
/// for why those reads must go through this SAME handle rather than a second
/// open of the same path.
fn open_append_0600(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
    }
}

/// Creates the file at `path` exclusively (`O_CREAT | O_EXCL | O_APPEND`) with
/// permissions `0600` on POSIX.
///
/// Returns `Err(io::ErrorKind::AlreadyExists)` if the file already exists.
/// Used when opening the new active file after a rotation to defend against a
/// race where an attacker pre-creates the path between `fs::rename` and the
/// writer's `try_lock`.
///
/// # Recovery note
///
/// If `AlreadyExists` is returned from a legitimate crash-recovery scenario
/// (e.g. a partial new active file was left from a previous run), the operator
/// should remove the stale file and retry.  The existing file MUST NOT be
/// silently reused because its chain state is unknown.
fn open_create_new_0600(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .create_new(true)
            .append(true)
            .read(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create_new(true)
            .append(true)
            .read(true)
            .open(path)
    }
}

/// Returns a compact ISO-8601-like timestamp for rotation file naming.
///
/// Format: `YYYYMMDDTHHMMSSmmm`, with `-N` appended for additional calls that
/// land in the same millisecond.
fn compact_timestamp() -> String {
    let ts = current_iso8601_utc();
    // "2026-04-28T12:34:56.123Z" → "20260428T123456123"
    let compact = ts
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .replace('Z', "");
    let timestamp_ms = compact
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse::<u64>()
        .unwrap_or(0);

    loop {
        let previous = LAST_ROTATION_TIMESTAMP_MS.load(Ordering::Acquire);
        if timestamp_ms > previous {
            if LAST_ROTATION_TIMESTAMP_MS
                .compare_exchange(previous, timestamp_ms, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return compact;
            }
            continue;
        }

        let suffix = ROTATION_COLLISION_COUNTER.fetch_add(1, Ordering::AcqRel) + 1;
        return format!("{compact}-{suffix}");
    }
}

// ── Recover chain hash from existing file ────────────────────────────────────

/// Reads the last JSON line from `path` and re-derives the hash of that entry.
///
/// Used when re-opening an existing log file to recover the chain state.
/// The lock MUST be held before calling this function.
///
/// Uses a reverse 4-KiB chunk scan so startup recovery reads only the trailing
/// line in the normal case. If the trailing line is malformed, falls back to
/// the legacy full-file scan so mid-line truncation can still recover the last
/// complete JSON line.
///
/// # Errors
///
/// Returns [`WriterError::Io`] or [`WriterError::Serialise`] on failure.
#[cfg(test)]
fn read_last_entry_hash(path: &Path) -> Result<String, WriterError> {
    match read_last_entry_hash_rev(path) {
        Ok(hash) => Ok(hash),
        Err(WriterError::Serialise(_)) | Err(WriterError::Hash(_)) => {
            read_last_entry_hash_full_scan(path)
        }
        Err(err) => Err(err),
    }
}

fn read_and_verify_entry_chain_at_open(file: &File) -> Result<String, WriterError> {
    // Reuse the caller's already-open (and already-locked) handle rather than
    // opening a second one — see the module-level "Single-handle requirement
    // (Windows)" section.
    let mut cursor = file;
    cursor.seek(SeekFrom::Start(0))?;
    let reader = BufReader::new(cursor);

    let mut expected_previous_hash = ZERO_BLOCK_HASH.to_owned();
    let mut last_hash = ZERO_BLOCK_HASH.to_owned();
    let mut entry_idx = 0usize;

    for line_result in reader.lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        entry_idx += 1;
        let entry: AuditEntry = serde_json::from_str(&line).map_err(WriterError::Serialise)?;
        if entry.previous_entry_hash != expected_previous_hash {
            return Err(WriterError::ChainBrokenAtOpen {
                entry_idx,
                expected_hex: expected_previous_hash,
                got_hex: entry.previous_entry_hash,
            });
        }

        let hash = compute_entry_hash_streamed(&entry, &entry.previous_entry_hash)?;
        expected_previous_hash = hash.clone();
        last_hash = hash;
    }

    Ok(last_hash)
}

#[cfg(test)]
fn read_last_entry_hash_rev(path: &Path) -> Result<String, WriterError> {
    const REV_CHUNK: usize = 4096;

    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(ZERO_BLOCK_HASH.to_owned());
    }

    let mut pos = len;
    let mut tail = Vec::new();
    while pos > 0 {
        let chunk_size = usize::try_from(std::cmp::min(REV_CHUNK as u64, pos))
            .map_err(|_| io::Error::other("audit log chunk size overflow"))?;
        pos -= chunk_size as u64;
        file.seek(SeekFrom::Start(pos))?;

        let mut chunk = vec![0u8; chunk_size];
        file.read_exact(&mut chunk)?;
        chunk.append(&mut tail);
        tail = chunk;

        while tail.last() == Some(&b'\n') {
            tail.pop();
        }
        if tail.is_empty() {
            continue;
        }
        if let Some(idx) = tail.iter().rposition(|&byte| byte == b'\n') {
            return parse_entry_hash_from_line(&tail[idx + 1..]);
        }
    }

    parse_entry_hash_from_line(&tail)
}

#[cfg(test)]
fn read_last_entry_hash_full_scan(path: &Path) -> Result<String, WriterError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut last_hash = ZERO_BLOCK_HASH.to_owned();
    let mut last_error = None;
    for line_result in reader.lines() {
        let line = line_result?;
        if !line.trim().is_empty() {
            match parse_entry_hash_from_line(line.as_bytes()) {
                Ok(hash) => {
                    last_hash = hash;
                    last_error = None;
                }
                Err(err) => {
                    last_error = Some(err);
                }
            }
        }
    }

    if last_hash == ZERO_BLOCK_HASH
        && let Some(err) = last_error
    {
        return Err(err);
    }
    Ok(last_hash)
}

#[cfg(test)]
fn parse_entry_hash_from_line(line: &[u8]) -> Result<String, WriterError> {
    if line.is_empty() {
        return Ok(ZERO_BLOCK_HASH.to_owned());
    }

    let entry: AuditEntry = serde_json::from_slice(line).map_err(WriterError::Serialise)?;
    let hash = compute_entry_hash_streamed(&entry, &entry.previous_entry_hash)?;
    Ok(hash)
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors that can occur during audit log writing.
#[derive(Debug, thiserror::Error)]
pub enum WriterError {
    /// An I/O error occurred.
    #[error("audit log I/O error: {0}")]
    Io(#[from] io::Error),

    /// The audit log's sidecar lock (`<log>.lock`) is held by another process.
    ///
    /// Only one `AuditWriter` per log file is permitted across all processes.
    /// Use `Arc<Mutex<AuditWriter>>` to share within a process. The log file
    /// itself is never locked; readers are unaffected by this condition.
    #[error("audit log file is locked by another process (audit.writer_locked)")]
    FileLocked,

    /// The supplied path violates a structural contract.
    ///
    /// Currently raised when the audit log path has no parent directory
    /// component (i.e. is a bare filename resolved against CWD, which makes
    /// rotated-sibling placement and directory-mode enforcement impossible).
    /// Always supply a path with an explicit parent directory, e.g.
    /// `~/.local/state/stellar-agent/audit/default.jsonl`.
    #[error("audit log path contract violated: {detail}")]
    PathContract {
        /// Human-readable description of the contract violation.
        detail: String,
    },

    /// An entry could not be serialised.
    #[error("audit log serialisation error: {0}")]
    Serialise(#[from] serde_json::Error),

    /// The hash chain computation failed.
    #[error("audit log hash chain error: {0}")]
    Hash(#[source] super::chain::HashError),

    /// Rotation archived the old file but could not create the new active
    /// file.
    ///
    /// The caller must discard the current writer. Reusing it could append a
    /// second handoff entry to the archived file and corrupt the rotation tail.
    /// The writer's sidecar lock (see `lock.rs`) remains held throughout —
    /// this variant is never caused by a lock conflict, since no lock is
    /// acquired when establishing the new active file.
    #[error(
        "audit log partial rotation: archived {archive_name:?}, new active file could not be created (lock holder if known: {active_locked_by:?})"
    )]
    PartialRotation {
        /// Basename of the archive created before the new active file could
        /// be created.
        archive_name: PathBuf,
        /// Reserved for future PID-based holder identification against the
        /// writer's own sidecar lock; always `None` today, since this
        /// variant is never caused by a lock conflict (see the variant docs).
        active_locked_by: Option<u32>,
    },

    /// The existing active file's in-file hash chain is broken at open.
    #[error(
        "audit log hash chain broken at open entry {entry_idx}: expected previous hash {expected_hex}, got {got_hex}"
    )]
    ChainBrokenAtOpen {
        /// One-based non-empty entry index in the active log file.
        entry_idx: usize,
        /// Expected previous-entry hash for this entry.
        expected_hex: String,
        /// Actual previous-entry hash stored in this entry.
        got_hex: String,
    },

    /// A second caller passed a different `log_path` for the same profile name.
    ///
    /// The registry enforces a single canonical path per profile name.  If two
    /// callers supply different paths for the same profile the registry cannot
    /// serve both consistently.  Callers must ensure all usages of the same
    /// profile name supply the same `log_path`.
    #[error(
        "audit writer registry path mismatch for profile '{profile_name}': \
         cached path {cached_path:?} does not match requested path {requested_path:?} \
         (audit.registry_path_mismatch)"
    )]
    PathMismatch {
        /// Profile name for which the mismatch was detected.
        profile_name: String,
        /// Path held in the registry (first-open wins).
        cached_path: PathBuf,
        /// Path supplied by the second caller.
        requested_path: PathBuf,
    },

    /// A second caller passed a different HMAC key for the same profile name.
    ///
    /// The registry enforces a single HMAC key per profile per process.  Key
    /// material for the chain root can only be set on the first open; a
    /// conflicting key on a subsequent call is rejected to avoid silently
    /// discarding HMAC key material or writing chain-root signatures with the
    /// wrong key.
    #[error(
        "audit writer registry HMAC key mismatch for profile '{profile_name}': \
         the cached writer was opened with a different HMAC key \
         (audit.registry_hmac_key_mismatch)"
    )]
    HmacKeyMismatch {
        /// Profile name for which the mismatch was detected.
        profile_name: String,
    },

    /// An audit-log integrity violation was detected before the writer could be
    /// opened.
    ///
    /// The inner [`VerifyError`](super::verify::VerifyError) carries the
    /// specific integrity state (use
    /// [`VerifyError::PartialRotation`](super::verify::VerifyError::PartialRotation)
    /// for partial-rotation detection).
    ///
    /// No auto-recovery is performed.  The operator must inspect the audit-log
    /// directory, follow the audit-log recovery runbook, and then retry the open.
    #[error("audit log integrity violation on open: {0}")]
    IntegrityViolation(#[from] super::verify::VerifyError),
}

// ── Partial-rotation detection ────────────────────────────────────────────────

/// Returns the basename (file-name component) of `path` as a `String`.
///
/// Used by recovery-hint formatting to avoid leaking full filesystem paths into
/// operator-visible error messages.  Structured fields in
/// [`super::verify::PartialRotationState`] retain the full `PathBuf` for
/// programmatic recovery.
///
/// Falls back to `"<non-utf8>"` when the basename contains non-UTF-8 bytes.
fn basename_lossy_path(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("<non-utf8>")
        .to_owned()
}

/// Inspects the audit-log directory for evidence of a crash mid-rotation.
///
/// Called from [`AuditWriter::open`] after the exclusive advisory lock is
/// acquired, before the chain-hash recovery scan.  Detection is conservative:
/// any suspicious intermediate-state file causes an error rather than silent
/// continuation.
///
/// `active_file` is the SAME locked handle `AuditWriter::open` just acquired
/// for `log_path`; the active-file scan (rule 3) reads through it instead of
/// opening a second handle — see the module-level "Single-handle requirement
/// (Windows)" section.
///
/// # Detection rules (in precedence order)
///
/// 1. **[`PartialRotationState::OrphanSidecar`]** — a `.root_hmac` sidecar
///    for a rotated archive exists (matching the `<stem>.<ts>.root_hmac`
///    pattern) but the corresponding `<stem>.<ts>` log file does not.  Caused
///    by the process crashing after the HMAC sidecar rename (step 2) but
///    before the log file rename (step 3) in `rotate()`.
///
/// 2. **[`PartialRotationState::MidRename`]** — a file with the `.tmp` suffix
///    exists in the audit-log directory.  Any such file indicates that a
///    write-to-tmp then rename-to-final pattern was interrupted and the `.tmp`
///    file was not cleaned up.
///
/// 3. **[`PartialRotationState::PartialHandoffWrite`]** — the active log file
///    is non-empty and its last line fails JSON parsing.  Caused by the process
///    being killed after writing a partial entry byte sequence (before fsync
///    completed).
///
/// # Errors
///
/// Returns `Err(`[`WriterError::IntegrityViolation`]`)` wrapping a
/// [`VerifyError::PartialRotation`](super::verify::VerifyError::PartialRotation)
/// when any anomaly is detected.  Returns `Ok(())` when the directory is clean.
///
/// Returns [`WriterError::Io`] on filesystem read failures unrelated to the
/// detection logic.
///
fn detect_partial_rotation(log_path: &Path, active_file: &File) -> Result<(), WriterError> {
    use super::verify::{PartialRotationState, VerifyError};

    let parent = match log_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        // No parent means a bare filename: the PathContract check in open()
        // already rejects this before we are called.
        _ => return Ok(()),
    };
    let stem = match log_path.file_name().and_then(|s| s.to_str()) {
        Some(s) => s,
        None => return Ok(()),
    };

    // Walk the directory once; classify every entry.
    let read_dir = match fs::read_dir(parent) {
        Ok(rd) => rd,
        Err(_) => return Ok(()), // directory doesn't exist yet; nothing to detect
    };

    for dir_entry in read_dir.filter_map(|e| e.ok()) {
        let entry_path = dir_entry.path();
        let entry_name = match entry_path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n.to_owned(),
            None => continue,
        };

        // ── Rule 1: orphan sidecar ──────────────────────────────────────────
        // Pattern: `<stem>.<ts>.root_hmac` where `<stem>.<ts>` does not exist.
        if let Some(log_name) = entry_name.strip_suffix(".root_hmac") {
            // Only check rotated-archive sidecars (i.e. `<stem>.<ts>.root_hmac`),
            // not the active file's own sidecar (`<stem>.root_hmac`).
            if is_rotated_sibling(stem, log_name) {
                let expected_log = parent.join(log_name);
                // Use symlink_metadata + is_file() instead of exists() so
                // a symlink pointing at /dev/zero (or a directory) is treated
                // as absent.  A symlink is not a regular file, so `is_file()`
                // returns false for symlinks on all platforms.
                let expected_log_is_regular_file = fs::symlink_metadata(&expected_log)
                    .map(|m| m.is_file())
                    .unwrap_or(false);
                if !expected_log_is_regular_file {
                    // Emit basename only in the operator-visible recovery
                    // hint; full paths remain in the structured fields for
                    // programmatic recovery.
                    let sidecar_name = basename_lossy_path(&entry_path);
                    let log_name_display = basename_lossy_path(&expected_log);
                    let recovery = format!(
                        "orphan sidecar detected — see docs/runbooks/audit-log-recovery.md §2.1. \
                         Sidecar: {sidecar_name}. Expected log: {log_name_display}.",
                    );
                    return Err(WriterError::IntegrityViolation(
                        VerifyError::PartialRotation {
                            state: PartialRotationState::OrphanSidecar {
                                sidecar_path: entry_path,
                                expected_log_path: expected_log,
                            },
                            recovery_hint: recovery,
                        },
                    ));
                }
            }
        }

        // ── Rule 2: mid-rename tmp file ─────────────────────────────────────
        // Pattern: any regular file with `.tmp` extension in the audit directory.
        if entry_name.ends_with(".tmp") {
            // Use symlink_metadata so an attacker-planted symlink (e.g. pointing
            // at /dev/zero or a sparse 16-EiB file) does not provide an
            // attacker-controlled size_bytes.  Only emit size for regular files;
            // symlinks/dirs use 0.
            let meta = fs::symlink_metadata(&entry_path);
            let is_regular = meta.as_ref().map(|m| m.is_file()).unwrap_or(false);
            let size_bytes = if is_regular {
                meta.map(|m| m.len()).unwrap_or(0)
            } else {
                0
            };
            // Basename only in the human-readable hint; full path in structured fields.
            let tmp_name = basename_lossy_path(&entry_path);
            let recovery = format!(
                "tmp file found — see docs/runbooks/audit-log-recovery.md §2.2. \
                 Tmp file: {tmp_name} ({size_bytes} bytes).",
            );
            return Err(WriterError::IntegrityViolation(
                VerifyError::PartialRotation {
                    state: PartialRotationState::MidRename {
                        tmp_path: entry_path,
                        size_bytes,
                    },
                    recovery_hint: recovery,
                },
            ));
        }
    }

    // ── Rule 3: partial handoff write in active file ─────────────────────────
    // Check if the active log file has a non-empty last line that is not valid
    // JSON.  This indicates a truncated write (process killed mid-append).
    // Use symlink_metadata + is_file() to avoid following a symlink planted at
    // the active log path.
    let log_is_regular_file = fs::symlink_metadata(log_path)
        .map(|m| m.is_file())
        .unwrap_or(false);
    if log_is_regular_file && let Some(state) = detect_partial_last_entry(active_file, log_path)? {
        // Basename only in the human-readable hint; full path in structured fields.
        let log_name = basename_lossy_path(log_path);
        let recovery = format!(
            "truncated entry detected — see docs/runbooks/audit-log-recovery.md §2.3. \
             Log: {log_name}.",
        );
        return Err(WriterError::IntegrityViolation(
            VerifyError::PartialRotation {
                state,
                recovery_hint: recovery,
            },
        ));
    }

    Ok(())
}

/// Scans the active log file for a truncated last entry.
///
/// Returns `Ok(Some(PartialRotationState::PartialHandoffWrite { .. }))` if the
/// file is non-empty and the last non-empty line fails JSON parsing.
/// Returns `Ok(None)` if the file is empty or all lines parse cleanly.
/// Returns `Err(WriterError::Io)` on I/O failure.
///
/// # Large-entry correctness
///
/// A single audit entry may legally exceed 4096 bytes (arg_keys alone can
/// be up to 4096 bytes; the JSON envelope adds further overhead).  A fixed
/// 4 KiB tail window would set `last_line_start_in_tail = 0` when the final
/// complete entry spans the window boundary, treating the front-partial of
/// that legitimate entry as the "last line" — JSON parse fails — producing a
/// false-positive `PartialHandoffWrite` that blocks `AuditWriter::open` on a
/// clean log.
///
/// Walks backward in 4096-byte chunks until a newline preceding the last
/// non-empty content is found, or the file start is reached.  At the file
/// start the entire accumulated buffer IS the last line, so no newline is
/// needed.
fn detect_partial_last_entry(
    file: &File,
    log_path: &Path,
) -> Result<Option<super::verify::PartialRotationState>, WriterError> {
    // Chunk size for the backward scan.  Large enough to hold one typical
    // entry; small enough to avoid reading the whole file on the hot path.
    const SCAN_CHUNK: u64 = 4096;

    // Reuse the caller's already-open (and already-locked) handle rather than
    // opening a second one — see the module-level "Single-handle requirement
    // (Windows)" section.
    let mut file = file;
    let file_size = file.metadata()?.len();
    if file_size == 0 {
        return Ok(None);
    }

    // Walk backward through the file in SCAN_CHUNK-sized windows, prepending
    // each chunk to an accumulation buffer, until we find a newline that
    // precedes the last non-empty line.
    let mut buf: Vec<u8> = Vec::new();
    let mut scan_end = file_size; // exclusive upper bound of bytes scanned so far

    loop {
        let chunk_size = std::cmp::min(SCAN_CHUNK, scan_end);
        let chunk_start = scan_end - chunk_size;

        file.seek(SeekFrom::Start(chunk_start))?;
        let mut chunk = vec![0u8; chunk_size as usize];
        file.read_exact(&mut chunk)?;

        // Prepend chunk to buf (new data is before previously-read data).
        chunk.extend_from_slice(&buf);
        buf = chunk;

        // Strip trailing newlines from the accumulated window.
        while buf.last() == Some(&b'\n') {
            buf.pop();
        }
        if buf.is_empty() {
            // File contains only newlines.
            return Ok(None);
        }

        // Look for a newline that precedes the last non-empty content.
        if let Some(nl_idx) = buf.iter().rposition(|&b| b == b'\n') {
            // Found a preceding newline.  The last line begins at nl_idx + 1
            // within buf.  The absolute file offset of that position is:
            //   chunk_start + nl_idx + 1
            // (chunk_start is the offset of the first byte currently in buf).
            let last_line = &buf[nl_idx + 1..];
            if last_line.is_empty() {
                return Ok(None);
            }
            let partial_entry_offset = chunk_start + (nl_idx as u64) + 1;
            return classify_last_line(last_line, partial_entry_offset, file_size, log_path);
        }

        // No newline found yet.
        if chunk_start == 0 {
            // Reached the file start: the entire buf IS the last (and only)
            // line.
            return classify_last_line(&buf, 0, file_size, log_path);
        }

        // Continue scanning further back.
        scan_end = chunk_start;
    }
}

/// Classifies the last non-empty line extracted by [`detect_partial_last_entry`].
///
/// Returns `Ok(None)` if the line parses as valid JSON (no partial write).
/// Returns `Ok(Some(PartialHandoffWrite { .. }))` if the line is not valid JSON.
#[inline]
fn classify_last_line(
    last_line: &[u8],
    partial_entry_offset: u64,
    file_size: u64,
    log_path: &Path,
) -> Result<Option<super::verify::PartialRotationState>, WriterError> {
    use super::verify::PartialRotationState;
    if serde_json::from_slice::<serde_json::Value>(last_line).is_ok() {
        Ok(None)
    } else {
        Ok(Some(PartialRotationState::PartialHandoffWrite {
            log_path: log_path.to_path_buf(),
            file_size_bytes: file_size,
            partial_entry_offset,
        }))
    }
}

// ── AuditWriterRegistry ───────────────────────────────────────────────────────

/// Process-global registry ensuring at most one [`AuditWriter`] per profile
/// name per process.
///
/// # Rationale
///
/// Multiple call sites in the same process may independently open the same
/// audit log file, which triggers [`WriterError::FileLocked`] on the second
/// open attempt.  The registry serialises open requests by profile name so the
/// file is opened exactly once.
///
/// # Singleton invariant
///
/// `get_or_open(profile_name, log_path, hmac_key)` always returns the same
/// `Arc<Mutex<AuditWriter>>` for the same `profile_name` within a process.
/// The underlying file is opened on the first call and the handle is reused on
/// subsequent calls.  Different profile names produce independent writers.
///
/// # Mismatch detection
///
/// A second caller that passes a different `log_path` for the same
/// `profile_name` receives [`WriterError::PathMismatch`].  A second caller
/// that passes a different `hmac_key` fingerprint receives
/// [`WriterError::HmacKeyMismatch`].  These errors guard against accidental
/// profile-name reuse across different log files or credential sets within the
/// same process.
///
/// # Process scope
///
/// The registry is process-global (backed by a `OnceLock`).  It intentionally
/// does NOT use thread-local storage, because a thread-local registry cannot
/// enforce the "at most one writer per profile per *process*" invariant — two
/// threads would each open their own writer for the same file, racing on the
/// advisory lock.
///
/// # I/O outside the registry lock (double-checked insert)
///
/// `AuditWriter::open` performs synchronous filesystem I/O (directory
/// creation, advisory lock acquisition via `flock`, file open, chain-hash
/// recovery scan).  Holding the registry mutex across that I/O would serialise
/// all profile lookups behind one file's I/O latency.  Instead, the
/// implementation uses a double-checked insert pattern:
///
/// 1. Acquire registry lock; check cache.  Return cached handle on hit.
/// 2. Release lock; call `AuditWriter::open` without holding the registry.
/// 3. Re-acquire lock; check cache again to handle the race where a second
///    thread opened the same profile concurrently.  If a concurrent winner is
///    found, the freshly-opened writer is discarded (its `Drop` releases the
///    advisory lock) and the winner's handle is returned.  Otherwise insert.
///
/// This means the advisory-lock acquisition can race: two threads may both
/// call `AuditWriter::open` concurrently for the same profile.  The loser
/// receives [`WriterError::FileLocked`] from the OS and its error is
/// propagated to the caller — which is the correct behaviour because the
/// registry does not know *a priori* which thread's open will succeed.
///
/// Consequently, callers that need guaranteed deduplication under high
/// concurrency must not rely on racing the registry; they should acquire the
/// `Arc<Mutex<AuditWriter>>` once and share it.
///
/// # Mutex panic-poison policy
///
/// Two `Mutex` layers are involved:
///
/// 1. **Registry lock** (`Mutex<HashMap<…>>`): held only for the cache lookup
///    and insert steps.  `AuditWriter::open` runs outside this lock.
///    If a thread panics while holding this lock, the next call to
///    `get_or_open` returns [`WriterError::Io`] wrapping the poison context
///    rather than propagating an unexpected `PoisonError` across an API
///    boundary.  The registry is considered permanently degraded after a poison
///    — callers must treat the error as fatal for audit-log operations.
///
/// 2. **Writer lock** (`Mutex<AuditWriter>`): held only by the *caller* while
///    it writes a log entry.  The registry itself never holds this inner lock.
///    A panic inside a `write_entry` call poisons this mutex; the
///    `SignersManager::emit_baseline` and similar helpers already handle
///    inner-mutex poison by marking the audit writer degraded and logging a
///    warning instead of propagating the panic.
///
/// `AuditWriterRegistry` is a wallet-side observability primitive.  On-chain
/// smart-account contracts have no audit-log surface.
pub struct AuditWriterRegistry;

/// Metadata stored alongside each `Arc<Mutex<AuditWriter>>` in the registry.
///
/// Used to detect path/HMAC-key mismatches on subsequent `get_or_open` calls
/// for the same profile name.
struct RegistryEntry {
    /// Canonical path the writer was opened at.
    log_path: PathBuf,
    /// SHA-256 fingerprint of the HMAC key passed on first open, or `None` if
    /// no key was supplied.  Stored instead of the raw key so the key is not
    /// retained in memory after the `AuditWriter` has taken ownership of it.
    hmac_key_fingerprint: Option<[u8; 32]>,
    /// The cached writer handle.
    handle: Arc<Mutex<AuditWriter>>,
}

/// The process-global backing store.
static REGISTRY: OnceLock<Mutex<HashMap<String, RegistryEntry>>> = OnceLock::new();

/// Computes a SHA-256 fingerprint of an HMAC key.
///
/// Used to compare HMAC keys across `get_or_open` calls without retaining the
/// raw key material in the registry.
fn hmac_key_fingerprint(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.finalize().into()
}

impl AuditWriterRegistry {
    /// Returns the shared `Arc<Mutex<AuditWriter>>` for `profile_name`,
    /// opening it the first time it is requested.
    ///
    /// On the first call for a given `profile_name` the writer is opened at
    /// `log_path` with the supplied `hmac_key`.  On subsequent calls the
    /// existing handle is returned after validating that `log_path` and the
    /// HMAC key fingerprint match the first-open values.
    ///
    /// # Double-checked insert
    ///
    /// `AuditWriter::open` runs **outside** the registry lock to avoid
    /// holding the mutex across synchronous filesystem I/O (directory creation,
    /// advisory lock, chain recovery scan).  See the struct-level docs for the
    /// full concurrency rationale and the race-loser behaviour.
    ///
    /// The `log_path` parameter carries the full path to the log file (e.g.
    /// `~/.local/state/stellar-agent/audit/default.jsonl`).  The profile name
    /// is used only as the registry cache key; path construction — including
    /// any sanitisation of the profile name into a safe file-stem — is the
    /// caller's responsibility.  See
    /// `stellar_agent_core::profile::schema::default_audit_log_path_for` for
    /// the canonical path derivation.
    ///
    /// # Errors
    ///
    /// - [`WriterError::FileLocked`] if another *process* holds the exclusive
    ///   advisory lock on the log file.  (Within a process, the registry
    ///   prevents this by reusing the same handle.)
    /// - [`WriterError::PathMismatch`] if a subsequent caller supplies a
    ///   different `log_path` for the same `profile_name`.
    /// - [`WriterError::HmacKeyMismatch`] if a subsequent caller supplies a
    ///   different `hmac_key` for the same `profile_name`.
    /// - [`WriterError::PathContract`] if `log_path` has no parent directory
    ///   component.
    /// - [`WriterError::Io`] on I/O failure during `AuditWriter::open`, or if
    ///   the process-global registry mutex is poisoned.
    /// - Other [`WriterError`] variants propagated from [`AuditWriter::open`].
    ///
    /// # Panics
    ///
    /// Does not panic.  Registry-mutex poison is converted to
    /// [`WriterError::Io`] so the caller receives a typed error rather than an
    /// unwound panic.
    pub fn get_or_open(
        profile_name: &str,
        log_path: &Path,
        hmac_key: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<Arc<Mutex<AuditWriter>>, WriterError> {
        let incoming_fingerprint = hmac_key.as_deref().map(hmac_key_fingerprint);

        // ── Phase 1: cache lookup under lock ────────────────────────────────
        let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
        {
            let map = registry.lock().map_err(|_| {
                WriterError::Io(io::Error::other(
                    "audit writer registry mutex poisoned; cannot open writer",
                ))
            })?;

            if let Some(entry) = map.get(profile_name) {
                // Validate log_path matches the cached entry.
                if entry.log_path != log_path {
                    return Err(WriterError::PathMismatch {
                        profile_name: profile_name.to_owned(),
                        cached_path: entry.log_path.clone(),
                        requested_path: log_path.to_path_buf(),
                    });
                }
                // Validate HMAC key fingerprint matches the cached entry.
                if entry.hmac_key_fingerprint != incoming_fingerprint {
                    return Err(WriterError::HmacKeyMismatch {
                        profile_name: profile_name.to_owned(),
                    });
                }
                return Ok(Arc::clone(&entry.handle));
            }
            // Cache miss — release the lock before doing I/O.
        }

        // ── Phase 2: open writer outside the lock ───────────────────────────
        // Perform the I/O (directory creation, advisory lock, chain recovery)
        // without holding the registry lock so concurrent opens for different
        // profiles do not serialise behind each other's I/O.
        let writer = AuditWriter::open(log_path.to_path_buf(), hmac_key)?;
        let handle = Arc::new(Mutex::new(writer));

        // ── Phase 3: re-acquire lock and insert (double-checked) ────────────
        // A concurrent thread may have won the race and inserted while we were
        // in Phase 2.  Check again; if a winner exists, discard the freshly-
        // opened writer (its Drop releases the advisory lock) and return the
        // winner's handle — but only after validating path + key consistency.
        let mut map = registry.lock().map_err(|_| {
            WriterError::Io(io::Error::other(
                "audit writer registry mutex poisoned; cannot open writer",
            ))
        })?;

        if let Some(entry) = map.get(profile_name) {
            // A concurrent thread inserted while we held no lock.
            // Validate consistency before returning the winner's handle.
            if entry.log_path != log_path {
                return Err(WriterError::PathMismatch {
                    profile_name: profile_name.to_owned(),
                    cached_path: entry.log_path.clone(),
                    requested_path: log_path.to_path_buf(),
                });
            }
            if entry.hmac_key_fingerprint != incoming_fingerprint {
                return Err(WriterError::HmacKeyMismatch {
                    profile_name: profile_name.to_owned(),
                });
            }
            // `handle` (our freshly-opened writer) is dropped here, releasing
            // the advisory lock we held as the race loser.
            return Ok(Arc::clone(&entry.handle));
        }

        // We are the first (or the only) opener for this profile — insert.
        map.insert(
            profile_name.to_owned(),
            RegistryEntry {
                log_path: log_path.to_path_buf(),
                hmac_key_fingerprint: incoming_fingerprint,
                handle: Arc::clone(&handle),
            },
        );
        Ok(handle)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]
    use super::*;
    use crate::audit_log::entry::NewToolInvocation;
    use crate::audit_log::schema::PolicyDecision;
    use std::{
        collections::HashSet,
        sync::{Arc, Barrier, Mutex},
    };
    use tempfile::TempDir;

    fn make_entry(_prev_hash: &str) -> AuditEntry {
        AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "stellar_pay_commit",
            "stellar:testnet",
            vec!["destination".to_owned(), "amount".to_owned()],
            PolicyDecision::Allow,
            uuid::Uuid::new_v4().to_string(),
        ))
    }

    fn serialised_entry_line(previous_hash: &str) -> (Vec<u8>, String) {
        let mut entry = make_entry(previous_hash);
        entry.previous_entry_hash = previous_hash.to_owned();
        let hash = compute_entry_hash_streamed(&entry, previous_hash).unwrap();
        let mut line = serde_json::to_vec(&entry).unwrap();
        line.push(b'\n');
        (line, hash)
    }

    fn open_no_key(path: PathBuf) -> AuditWriter {
        AuditWriter::open(path, None).unwrap()
    }

    #[test]
    fn open_creates_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let writer = open_no_key(path.clone());
        assert!(path.exists());
        drop(writer);
    }

    #[test]
    fn write_entry_produces_valid_json_line() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let mut writer = open_no_key(path.clone());
        let entry = make_entry(writer.last_entry_hash());
        writer.write_entry(entry).unwrap();
        drop(writer);

        let contents = fs::read_to_string(&path).unwrap();
        let trimmed = contents.trim();
        assert!(!trimmed.is_empty());
        let _v: serde_json::Value = serde_json::from_str(trimmed).unwrap();
    }

    #[test]
    fn write_multiple_entries_all_parseable() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let mut writer = open_no_key(path.clone());

        for _ in 0..5 {
            let entry = make_entry(writer.last_entry_hash());
            writer.write_entry(entry).unwrap();
        }
        drop(writer);

        let contents = fs::read_to_string(&path).unwrap();
        let count = contents.lines().filter(|l| !l.trim().is_empty()).count();
        assert_eq!(count, 5);
    }

    #[test]
    fn last_hash_advances_on_write() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let mut writer = open_no_key(path);

        let h0 = writer.last_entry_hash().to_owned();
        let entry = make_entry(&h0);
        writer.write_entry(entry).unwrap();
        let h1 = writer.last_entry_hash().to_owned();
        assert_ne!(h0, h1);
    }

    #[test]
    fn reopen_recovers_chain() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");

        let mut writer = open_no_key(path.clone());
        let entry = make_entry(writer.last_entry_hash());
        writer.write_entry(entry).unwrap();
        let hash_after_first = writer.last_entry_hash().to_owned();
        drop(writer);

        let writer2 = open_no_key(path);
        assert_eq!(writer2.last_entry_hash(), hash_after_first);
    }

    /// Re-opening a NON-EMPTY audit log and then writing a further entry must
    /// succeed through a SINGLE handle.
    ///
    /// `AuditWriter::open` exercises the partial-rotation last-entry scan and
    /// the chain-recovery read only when the file already has entries —
    /// exactly the case here. Both reads (and the following write) go through
    /// the same handle that holds the exclusive lock. On Windows,
    /// `LockFileEx`'s exclusive lock blocks I/O issued through any OTHER
    /// handle to the same file, including a second handle opened by the SAME
    /// process, so a two-handle design would fail this exact sequence with
    /// `ERROR_ACCESS_DENIED` (raw os error 5). POSIX advisory locks never
    /// block a second handle's I/O, so this test cannot distinguish a
    /// single-handle design from a two-handle one on this platform; the
    /// `windows-storage` CI job runs it on `windows-latest`, where the
    /// distinction is observable.
    #[test]
    fn reopen_nonempty_log_then_write_succeeds() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let mut writer = open_no_key(path.clone());
            writer
                .write_entry(make_entry(writer.last_entry_hash()))
                .unwrap();
        } // Lock released, handle closed.

        // Re-open against the now non-empty file: exercises the
        // partial-rotation last-entry scan and the chain-recovery read.
        let mut writer = open_no_key(path.clone());
        writer
            .write_entry(make_entry(writer.last_entry_hash()))
            .unwrap();
        drop(writer);

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents.lines().filter(|l| !l.trim().is_empty()).count(),
            2,
            "both entries (pre- and post-reopen) must be present"
        );
    }

    #[test]
    fn open_rejects_broken_in_file_chain() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");

        let mut writer = open_no_key(path.clone());
        for _ in 0..3 {
            let entry = make_entry(writer.last_entry_hash());
            writer.write_entry(entry).unwrap();
        }
        drop(writer);

        let contents = fs::read_to_string(&path).unwrap();
        let mut entries: Vec<serde_json::Value> = contents
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let original_previous = entries[1]["previous_entry_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut tampered_previous = original_previous.clone().into_bytes();
        tampered_previous[0] = if tampered_previous[0] == b'0' {
            b'1'
        } else {
            b'0'
        };
        entries[1]["previous_entry_hash"] =
            serde_json::Value::String(String::from_utf8(tampered_previous).unwrap());

        let mut tampered_contents = entries
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\n");
        tampered_contents.push('\n');
        fs::write(&path, tampered_contents).unwrap();

        let err = AuditWriter::open(path, None).expect_err("open must reject broken in-file chain");
        match err {
            WriterError::ChainBrokenAtOpen {
                entry_idx,
                expected_hex,
                got_hex,
            } => {
                assert_eq!(entry_idx, 2);
                assert_eq!(expected_hex, original_previous);
                assert_ne!(got_hex, expected_hex);
            }
            other => assert!(
                matches!(other, WriterError::ChainBrokenAtOpen { .. }),
                "expected ChainBrokenAtOpen"
            ),
        }
    }

    #[test]
    fn read_last_entry_hash_empty_file_returns_zero_block_hash() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        File::create(&path).unwrap();

        assert_eq!(read_last_entry_hash(&path).unwrap(), ZERO_BLOCK_HASH);
    }

    #[test]
    fn read_last_entry_hash_single_line_without_trailing_newline() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let (mut line, expected_hash) = serialised_entry_line(ZERO_BLOCK_HASH);
        line.pop();
        fs::write(&path, line).unwrap();

        assert_eq!(read_last_entry_hash(&path).unwrap(), expected_hash);
    }

    #[test]
    fn read_last_entry_hash_multi_line_uses_final_entry() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let (first, first_hash) = serialised_entry_line(ZERO_BLOCK_HASH);
        let (second, second_hash) = serialised_entry_line(&first_hash);
        let mut contents = first;
        contents.extend_from_slice(&second);
        fs::write(&path, contents).unwrap();

        assert_eq!(read_last_entry_hash(&path).unwrap(), second_hash);
    }

    #[test]
    fn read_last_entry_hash_large_file_reads_trailing_entry() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let (line, expected_hash) = serialised_entry_line(ZERO_BLOCK_HASH);
        let mut contents = vec![b'\n'; 10 * 1024 * 1024];
        contents.extend_from_slice(&line);
        fs::write(&path, contents).unwrap();

        assert_eq!(read_last_entry_hash(&path).unwrap(), expected_hash);
    }

    #[test]
    fn read_last_entry_hash_ignores_trailing_newline_padding() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let (line, expected_hash) = serialised_entry_line(ZERO_BLOCK_HASH);
        let mut contents = line;
        contents.extend_from_slice(b"\n\n\n");
        fs::write(&path, contents).unwrap();

        assert_eq!(read_last_entry_hash(&path).unwrap(), expected_hash);
    }

    #[test]
    fn read_last_entry_hash_falls_back_after_truncated_trailing_line() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let (line, expected_hash) = serialised_entry_line(ZERO_BLOCK_HASH);
        let mut contents = line;
        contents.extend_from_slice(br#"{"truncated":"#);
        fs::write(&path, contents).unwrap();

        assert_eq!(read_last_entry_hash(&path).unwrap(), expected_hash);
    }

    #[test]
    fn hmac_root_sidecar_created() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let key = Zeroizing::new([0x42u8; 32]);
        let mut writer = AuditWriter::open(path.clone(), Some(key)).unwrap();
        let entry = make_entry(writer.last_entry_hash());
        writer.write_entry(entry).unwrap();
        drop(writer);

        let sidecar = hmac_sidecar_path(&path);
        assert!(sidecar.exists(), "root_hmac sidecar must exist");
        let contents = fs::read_to_string(&sidecar).unwrap();
        assert!(
            contents.trim().starts_with("sha256:"),
            "sidecar must contain sha256 tag: {contents}"
        );
    }

    #[test]
    fn crash_after_entry_fsync_before_sidecar_leaves_no_ahead_root() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let key = [0x42u8; 32];
        let mut writer = AuditWriter::open(path.clone(), Some(Zeroizing::new(key))).unwrap();
        writer.set_fail_after_entry_before_sidecar(true);
        let entry = make_entry(writer.last_entry_hash());

        let error = writer
            .write_entry(entry)
            .expect_err("fault injection must fail");
        assert!(
            matches!(error, WriterError::Io(ref io_error) if io_error.kind() == io::ErrorKind::Other),
            "fault injection must return an I/O error after entry fsync"
        );
        drop(writer);

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "entry must be fsynced before the crash seam"
        );

        let sidecar = hmac_sidecar_path(&path);
        assert!(
            !sidecar.exists(),
            "sidecar must be absent at the after-entry-before-sidecar crash seam"
        );

        let reopened = AuditWriter::open(path, Some(Zeroizing::new(key))).unwrap();
        assert!(
            !reopened.is_new_file,
            "reopen must recover the fsynced entry rather than starting a new file"
        );
        assert_ne!(reopened.last_entry_hash(), ZERO_BLOCK_HASH);
    }

    // ── concurrent_open_returns_filelocked ───────────────────────────────────

    #[test]
    fn concurrent_open_returns_filelocked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("locked.jsonl");

        // Open writer 1 — acquires the lock.
        let _writer1 = open_no_key(path.clone());

        // Attempt writer 2 — must get FileLocked.
        let result = AuditWriter::open(path.clone(), None);
        assert!(
            matches!(result, Err(WriterError::FileLocked)),
            "second open must return FileLocked, got: {result:?}"
        );
    }

    // ── sidecar lock: mechanism + cross-process exclusion ────────────────────

    /// The sidecar lock file exists at `<path>.lock` (never at `path` itself)
    /// once a writer is open, and a raw second acquire against that exact
    /// sidecar path — bypassing `AuditWriter` entirely — is excluded while the
    /// writer is alive and succeeds once it drops. This exercises the
    /// exclusion mechanism directly rather than only through `AuditWriter`,
    /// simulating two independent processes racing for the same sidecar file.
    #[test]
    fn sidecar_lock_file_excludes_second_raw_acquire_and_releases_on_drop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let writer = open_no_key(path.clone());

        let lock_path = lock_sidecar_path(&path);
        assert!(
            lock_path.exists(),
            "sidecar lock file must exist: {lock_path:?}"
        );
        assert_ne!(
            lock_path, path,
            "the log file itself must never be the lock path"
        );

        let second = crate::audit_log::lock::AuditWriterLock::acquire(&lock_path);
        assert!(
            matches!(second, Err(WriterError::FileLocked)),
            "a second raw acquire of the same sidecar path must be excluded, got: {second:?}"
        );

        drop(writer);

        let third = crate::audit_log::lock::AuditWriterLock::acquire(&lock_path);
        assert!(
            third.is_ok(),
            "acquire after the writer drops must succeed, got: {third:?}"
        );
    }

    /// Pins the invariant this campaign establishes: a reader with its own,
    /// completely independent file handle completes successfully while a live
    /// writer holds its lock — on every platform. This passed on POSIX before
    /// the sidecar redesign (advisory locks never block a second handle's
    /// I/O) and is the exact case that failed on Windows under the old
    /// data-file-locking scheme (`ERROR_LOCK_VIOLATION`/`ERROR_ACCESS_DENIED`
    /// on any second handle to the locked log file).
    #[test]
    fn reader_completes_while_live_writer_holds_lock() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut writer = open_no_key(path.clone());
        writer
            .write_entry(make_entry(writer.last_entry_hash()))
            .unwrap();

        // `writer` (and its sidecar lock) stays alive for the whole call
        // below. `verify_log` opens its own independent handles on the log
        // file — the same code path a separate `audit verify` process would
        // use against a log a different process's writer is actively holding.
        let result = crate::audit_log::verify::verify_log(&path, None);
        assert!(
            result.is_ok(),
            "reader must complete while the writer is alive, got: {result:?}"
        );

        drop(writer);
    }

    // ── hmac_sidecar_renamed_on_rotation ────────────────────────────────────

    #[test]
    fn hmac_sidecar_renamed_on_rotation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let key = Zeroizing::new([0x11u8; 32]);
        let mut writer = AuditWriter::open(path.clone(), Some(key)).unwrap();

        // Write the first entry — this creates the root_hmac sidecar.
        let entry = make_entry(writer.last_entry_hash());
        writer.write_entry(entry).unwrap();

        // Read the original sidecar tag before rotation.
        let active_sidecar = hmac_sidecar_path(&path);
        assert!(
            active_sidecar.exists(),
            "active sidecar must exist before rotation"
        );
        let original_tag = fs::read_to_string(&active_sidecar).unwrap();
        assert!(
            original_tag.trim().starts_with("sha256:"),
            "sidecar tag format: {original_tag}"
        );

        // Force rotation by padding the file to exceed the threshold.
        // We do this by writing a large entry that exceeds ROTATION_THRESHOLD_BYTES.
        // Simpler: directly rename/truncate to simulate a large file.
        // Actually, we write enough bytes.  Use a helper that inflates with big arg_keys.
        let large_content = vec![0u8; ROTATION_THRESHOLD_BYTES as usize];
        fs::write(&path, &large_content).unwrap();

        // Write one more entry to trigger rotation.
        let entry2 = make_entry(writer.last_entry_hash());
        writer.write_entry(entry2).unwrap();

        // After rotation:
        // 1. A rotated file `audit.jsonl.<ts>` must exist.
        // 2. Its sidecar `audit.jsonl.<ts>.root_hmac` must exist with original tag.
        // 3. The active sidecar `audit.jsonl.root_hmac` must NOT exist yet
        //    (no new chain root written to the new file yet).

        // Find the rotated file.
        let stem = "audit.jsonl";
        let rotated_files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|s| s.to_str())
                    .map(|name| is_rotated_sibling(stem, name))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(
            rotated_files.len(),
            1,
            "exactly one rotated file expected: {rotated_files:?}"
        );

        let rotated_path = &rotated_files[0];
        let rotated_sidecar = hmac_sidecar_path(rotated_path);
        assert!(
            rotated_sidecar.exists(),
            "rotated sidecar must exist at {rotated_sidecar:?}"
        );
        let rotated_tag = fs::read_to_string(&rotated_sidecar).unwrap();
        assert_eq!(
            original_tag.trim(),
            rotated_tag.trim(),
            "rotated sidecar must contain original chain-root tag"
        );
    }

    // ── is_rotated_sibling unit tests ────────────────────────────────────────

    /// Accept: 8-digit date + T + 6-digit time (second precision).
    #[test]
    fn is_rotated_sibling_accepts_second_precision() {
        assert!(is_rotated_sibling(
            "audit.jsonl",
            "audit.jsonl.20260428T123456"
        ));
    }

    /// Accept: 8-digit date + T + 9-digit time (millisecond precision,
    /// as produced by compact_timestamp()).
    #[test]
    fn is_rotated_sibling_accepts_ms_precision() {
        assert!(is_rotated_sibling(
            "audit.jsonl",
            "audit.jsonl.20260428T123456789"
        ));
    }

    #[test]
    fn is_rotated_sibling_accepts_ms_collision_suffix() {
        assert!(is_rotated_sibling(
            "audit.jsonl",
            "audit.jsonl.20260428T123456789-1"
        ));
    }

    #[test]
    fn is_rotated_sibling_rejects_second_precision_collision_suffix() {
        assert!(!is_rotated_sibling(
            "audit.jsonl",
            "audit.jsonl.20260428T123456-1"
        ));
    }

    #[test]
    fn is_rotated_sibling_rejects_nonnumeric_collision_suffix() {
        assert!(!is_rotated_sibling(
            "audit.jsonl",
            "audit.jsonl.20260428T123456789-a"
        ));
    }

    #[test]
    fn compact_timestamp_keeps_same_ms_calls_distinct() {
        const CALLS: usize = 100;
        const ATTEMPTS: usize = 10;

        let mut observed_same_ms_prefix = false;
        for _ in 0..ATTEMPTS {
            let barrier = Arc::new(Barrier::new(CALLS + 1));
            let timestamps = Arc::new(Mutex::new(Vec::with_capacity(CALLS)));
            let handles: Vec<_> = (0..CALLS)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let timestamps = Arc::clone(&timestamps);
                    std::thread::spawn(move || {
                        barrier.wait();
                        let timestamp = compact_timestamp();
                        timestamps.lock().unwrap().push(timestamp);
                    })
                })
                .collect();

            barrier.wait();
            for handle in handles {
                handle.join().unwrap();
            }

            let timestamps = timestamps.lock().unwrap().clone();
            let distinct: HashSet<_> = timestamps.iter().cloned().collect();
            assert_eq!(
                distinct.len(),
                CALLS,
                "rotation timestamps must be unique: {timestamps:?}"
            );

            let has_same_ms_prefix = timestamps.iter().any(|timestamp| {
                let prefix = timestamp
                    .split_once('-')
                    .map_or(timestamp.as_str(), |(prefix, _)| prefix);
                timestamps
                    .iter()
                    .filter(|other| {
                        other
                            .split_once('-')
                            .map_or(other.as_str(), |(other_prefix, _)| other_prefix)
                            == prefix
                    })
                    .count()
                    > 1
            });
            if has_same_ms_prefix {
                observed_same_ms_prefix = true;
                break;
            }
        }

        assert!(
            observed_same_ms_prefix,
            "expected at least one shared millisecond prefix across {CALLS} calls"
        );
    }

    /// Reject: only 1 digit after T — too short.
    #[test]
    fn is_rotated_sibling_rejects_too_few_suffix_digits() {
        assert!(!is_rotated_sibling("audit.jsonl", "audit.jsonl.20260428T1"));
    }

    /// Reject: 14 digits after T — too long (would collide with future ns precision).
    #[test]
    fn is_rotated_sibling_rejects_too_many_suffix_digits() {
        assert!(!is_rotated_sibling(
            "audit.jsonl",
            "audit.jsonl.20260428T12345678901234"
        ));
    }

    #[test]
    fn is_rotated_sibling_rejects_lock_sidecar() {
        assert!(!is_rotated_sibling("audit.jsonl", "audit.jsonl.lock"));
    }

    #[test]
    fn is_rotated_sibling_rejects_root_hmac_sidecar() {
        assert!(!is_rotated_sibling("audit.jsonl", "audit.jsonl.root_hmac"));
    }

    #[test]
    fn is_rotated_sibling_rejects_unrelated_prefix() {
        assert!(!is_rotated_sibling(
            "audit.jsonl",
            "other.jsonl.20260428T123456"
        ));
    }

    #[test]
    fn is_rotated_sibling_rejects_active_file() {
        assert!(!is_rotated_sibling("audit.jsonl", "audit.jsonl"));
    }

    #[test]
    fn is_rotated_sibling_rejects_no_extension() {
        assert!(!is_rotated_sibling("audit.jsonl", "audit"));
    }

    #[test]
    fn is_rotated_sibling_rejects_short_suffix() {
        // Only 7 digits after stem — need 8 + 'T' + 6 or 9 digits.
        assert!(!is_rotated_sibling("audit.jsonl", "audit.jsonl.2026042"));
    }

    #[test]
    fn is_rotated_sibling_rejects_no_t_separator() {
        // 8 digits but no 'T'.
        assert!(!is_rotated_sibling("audit.jsonl", "audit.jsonl.20260428"));
    }

    /// Reject: 7 digits after T (not 6 or 9).
    #[test]
    fn is_rotated_sibling_rejects_7_digit_time() {
        assert!(!is_rotated_sibling(
            "audit.jsonl",
            "audit.jsonl.20260428T1234567"
        ));
    }

    // ── post-rotation single-writer enforcement ───────────────────────────────

    /// After rotation completes, a second `AuditWriter::open` on the same
    /// active path must still return `FileLocked`.
    ///
    /// Validates that the new active path is locked before the old lock is
    /// dropped.  The test cannot deterministically trigger the exact
    /// interleaving, but it validates the post-rotation state invariant: only
    /// one writer may hold the lock on the active path at any time.
    #[test]
    fn post_rotation_active_path_is_locked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Open writer 1.
        let mut writer1 = open_no_key(path.clone());

        // Force rotation by padding the file size above the threshold.
        let large_content = vec![0u8; ROTATION_THRESHOLD_BYTES as usize];
        fs::write(&path, &large_content).unwrap();

        // Trigger rotation.
        let entry = make_entry(writer1.last_entry_hash());
        writer1.write_entry(entry).unwrap();

        // After rotation, the new active file at `path` must be locked by writer1.
        // A second open attempt must return FileLocked.
        let result = AuditWriter::open(path.clone(), None);
        assert!(
            matches!(result, Err(WriterError::FileLocked)),
            "active path must remain locked after rotation; got: {result:?}"
        );

        // Writer1 is still functional — write one more entry.
        let entry2 = make_entry(writer1.last_entry_hash());
        writer1.write_entry(entry2).unwrap();
    }

    /// A path with no parent directory component must be rejected.
    ///
    /// On all POSIX + Windows platforms `PathBuf::from("/").parent()` returns
    /// `None`, so `"/"` is the canonical path-without-parent.  The
    /// `PathContract` error fires before any I/O attempt.
    #[test]
    fn open_bare_filename_returns_path_contract() {
        // PathBuf::from("/") has parent() == None on all supported platforms.
        let result = AuditWriter::open(PathBuf::from("/"), None);
        assert!(
            matches!(result, Err(WriterError::PathContract { .. })),
            "path with no parent must return PathContract, got: {result:?}"
        );
    }

    /// `open_create_new_0600` must fail when the target path already exists,
    /// proving the race-defence helper works as intended.
    ///
    /// The race window (rename → create_new) cannot be triggered deterministically
    /// in a unit test; this test directly validates the underlying helper.
    #[test]
    fn pre_created_active_path_fails_on_rotation() {
        let dir = TempDir::new().unwrap();
        // Create a pre-existing file to simulate the "stale active path" scenario.
        let stale = dir.path().join("stale.jsonl");
        fs::write(&stale, b"stale\n").unwrap();

        // open_create_new_0600 must return AlreadyExists, not silently succeed.
        let result = open_create_new_0600(&stale);
        assert!(
            result.is_err(),
            "open_create_new_0600 must fail when file already exists"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::AlreadyExists,
            "expected AlreadyExists, got: {err:?}"
        );
    }

    #[test]
    fn rotation_create_failure_returns_partial_rotation_and_poisons_writer() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = open_no_key(path.clone());
        writer
            .write_entry(make_entry(writer.last_entry_hash()))
            .unwrap();

        // Force rotation by padding the file to exceed the threshold. The log
        // file carries no lock, so a plain second-handle write is fine on
        // every platform; the garbage content is archived away untouched by
        // the rotation this test triggers below.
        let large_content = vec![0u8; ROTATION_THRESHOLD_BYTES as usize];
        fs::write(&path, &large_content).unwrap();

        if let Ok(mut force_path) = FORCE_NEXT_ROTATION_CREATE_FAILURE_PATH.lock() {
            *force_path = Some(path.clone());
        }
        let err = writer
            .write_entry(make_entry(writer.last_entry_hash()))
            .expect_err("forced post-rename create failure must be surfaced");
        assert!(
            matches!(
                err,
                WriterError::PartialRotation {
                    active_locked_by: None,
                    ..
                }
            ),
            "expected PartialRotation with no known lock holder, got {err:?}"
        );
        let archive_name = match err {
            WriterError::PartialRotation {
                archive_name,
                active_locked_by: None,
            } => archive_name,
            _ => PathBuf::new(),
        };

        let second_err = writer
            .write_entry(make_entry(writer.last_entry_hash()))
            .expect_err("poisoned writer must refuse future writes");
        assert!(matches!(second_err, WriterError::PartialRotation { .. }));

        let archive_path = dir.path().join(&archive_name);
        let contents = fs::read_to_string(&archive_path).unwrap();
        let handoff_count = contents
            .lines()
            .filter(|line| line.contains(r#""kind":"audit_rotation_handoff""#))
            .count();
        assert_eq!(
            handoff_count, 1,
            "poisoned writer must not append a second handoff to {archive_path:?}"
        );
    }

    // ── AuditWriterRegistry tests ─────────────────────────────────────────────
    //
    // The registry is backed by a process-global `OnceLock<Mutex<HashMap<…>>>`.
    // Each test uses a unique profile name (UUIDs) so distinct tests in the
    // same binary cannot interfere through the shared map.

    /// Same profile name returns the same `Arc` pointer (singleton invariant).
    #[test]
    fn registry_same_profile_returns_same_arc() {
        let dir = TempDir::new().unwrap();
        let profile = format!("reg-same-{}", uuid::Uuid::new_v4().simple());
        let log_path = dir.path().join(format!("{profile}.jsonl"));
        let a = AuditWriterRegistry::get_or_open(&profile, &log_path, None).unwrap();
        let b = AuditWriterRegistry::get_or_open(&profile, &log_path, None).unwrap();
        assert!(
            Arc::ptr_eq(&a, &b),
            "same profile must return the same Arc pointer"
        );
    }

    /// Different profile names return different `Arc` pointers.
    #[test]
    fn registry_different_profiles_return_different_arcs() {
        let dir = TempDir::new().unwrap();
        let p1 = format!("reg-diff-1-{}", uuid::Uuid::new_v4().simple());
        let p2 = format!("reg-diff-2-{}", uuid::Uuid::new_v4().simple());
        let path1 = dir.path().join(format!("{p1}.jsonl"));
        let path2 = dir.path().join(format!("{p2}.jsonl"));
        let a = AuditWriterRegistry::get_or_open(&p1, &path1, None).unwrap();
        let b = AuditWriterRegistry::get_or_open(&p2, &path2, None).unwrap();
        assert!(
            !Arc::ptr_eq(&a, &b),
            "different profiles must return different Arc pointers"
        );
    }

    /// Concurrent callers for the same profile all receive the same `Arc`
    /// from the cache-hit path (no warmup before the race).
    ///
    /// Eight threads race on a profile name that has never been opened.  The
    /// first thread to complete its open wins; all threads must return the same
    /// `Arc` pointer regardless of which thread won.  This exercises the
    /// double-checked insert path (MINOR C5 fix: removed pre-race warmup so
    /// threads actually exercise the cache-miss race, not just cache-hit).
    #[test]
    fn registry_concurrent_cache_miss_race_all_return_same_arc() {
        use std::{sync::Barrier, thread};
        let dir = TempDir::new().unwrap();
        // Use a profile name not previously opened in this test binary.
        let profile = format!("reg-conc-miss-{}", uuid::Uuid::new_v4().simple());
        let log_path = dir.path().join(format!("{profile}.jsonl"));

        // No warmup: all threads race on a cold cache entry.
        // Because the advisory file lock prevents two threads from
        // simultaneously holding the open writer, all but one thread will
        // receive FileLocked from AuditWriter::open and propagate it — OR the
        // double-checked insert logic returns the winner's Arc.  In practice
        // threads that see FileLocked are the losers; we allow that outcome and
        // assert that any successful opener returns the same Arc.
        const THREADS: usize = 8;
        let barrier = Arc::new(Barrier::new(THREADS));
        // Collect raw Arc pointers (usize) from successful openers — avoids a
        // clippy::type_complexity violation on the result accumulator type.
        let ptrs: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::with_capacity(THREADS)));

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let ptrs = Arc::clone(&ptrs);
                let profile = profile.clone();
                let log_path = log_path.clone();
                thread::spawn(move || {
                    barrier.wait();
                    if let Ok(arc) = AuditWriterRegistry::get_or_open(&profile, &log_path, None) {
                        // Safety: the pointer value is only compared, never dereferenced.
                        ptrs.lock().unwrap().push(Arc::as_ptr(&arc) as usize);
                    }
                    // FileLocked losers contribute nothing to `ptrs`.
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread must not panic");
        }

        let collected = ptrs.lock().unwrap().clone();
        assert!(
            !collected.is_empty(),
            "at least one thread must succeed in opening the registry entry"
        );
        // All successful callers must return the same Arc pointer.
        let first_ptr = collected[0];
        for ptr in &collected[1..] {
            assert_eq!(
                *ptr, first_ptr,
                "all successful concurrent openers must return the same Arc"
            );
        }
    }

    /// Concurrent callers for the same profile all receive the same `Arc`
    /// from the cache-hit path (warmup before the race).
    ///
    /// Eight threads simultaneously call `get_or_open` for a profile that was
    /// opened once before the barrier.  Every returned pointer must equal the
    /// pre-barrier handle pointer (cache-hit path only).
    #[test]
    fn registry_concurrent_cache_hit_all_return_same_arc() {
        use std::{sync::Barrier, thread};
        let dir = TempDir::new().unwrap();
        let profile = format!("reg-conc-hit-{}", uuid::Uuid::new_v4().simple());
        let log_path = dir.path().join(format!("{profile}.jsonl"));

        // Warm up: open once before the threads start so the cache is populated.
        let first = AuditWriterRegistry::get_or_open(&profile, &log_path, None).unwrap();
        let first_ptr = Arc::as_ptr(&first);

        const THREADS: usize = 8;
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let profile = profile.clone();
                let log_path = log_path.clone();
                thread::spawn(move || {
                    barrier.wait();
                    AuditWriterRegistry::get_or_open(&profile, &log_path, None).unwrap()
                })
            })
            .collect();

        for handle in handles {
            let arc = handle.join().expect("thread must not panic");
            assert_eq!(
                Arc::as_ptr(&arc),
                first_ptr,
                "concurrent cache-hit call must return the same Arc as the initial open"
            );
        }
    }

    /// A second process attempting to open the same log file receives
    /// `FileLocked`.
    ///
    /// Simulated in-process by holding a raw `AuditWriter::open` handle on the
    /// log file path before calling `get_or_open` for the same profile (using a
    /// distinct profile name that is not yet in the registry cache, so the
    /// registry attempts `AuditWriter::open` and hits the advisory lock).
    #[test]
    fn registry_file_locked_by_external_process_returns_error() {
        let dir = TempDir::new().unwrap();
        let profile = format!("reg-lock-{}", uuid::Uuid::new_v4().simple());
        let log_path = dir.path().join(format!("{profile}.jsonl"));

        // Hold the lock via a direct AuditWriter::open (simulates another process).
        let _direct_writer = AuditWriter::open(log_path.clone(), None).unwrap();

        // The registry must surface FileLocked.
        let result = AuditWriterRegistry::get_or_open(&profile, &log_path, None);
        assert!(
            matches!(result, Err(WriterError::FileLocked)),
            "registry must propagate FileLocked when file is held by another opener, got: {result:?}"
        );
    }

    /// A second `get_or_open` call for the same profile with a different path
    /// returns `WriterError::PathMismatch`.
    #[test]
    fn registry_path_mismatch_returns_error() {
        let dir = TempDir::new().unwrap();
        let profile = format!("reg-pathmm-{}", uuid::Uuid::new_v4().simple());
        let path1 = dir.path().join(format!("{profile}.jsonl"));
        let path2 = dir.path().join(format!("{profile}-other.jsonl"));

        // First open succeeds.
        let _a = AuditWriterRegistry::get_or_open(&profile, &path1, None).unwrap();

        // Second open with a different path must return PathMismatch.
        let result = AuditWriterRegistry::get_or_open(&profile, &path2, None);
        assert!(
            matches!(result, Err(WriterError::PathMismatch { .. })),
            "registry must return PathMismatch when a different path is supplied, got: {result:?}"
        );
    }

    /// A second `get_or_open` call for the same profile with a different HMAC
    /// key returns `WriterError::HmacKeyMismatch`.
    #[test]
    fn registry_hmac_key_mismatch_returns_error() {
        let dir = TempDir::new().unwrap();
        let profile = format!("reg-keymmatch-{}", uuid::Uuid::new_v4().simple());
        let log_path = dir.path().join(format!("{profile}.jsonl"));

        let key_a = Zeroizing::new([0x11u8; 32]);
        let key_b = Zeroizing::new([0x22u8; 32]);

        // First open with key_a.
        let _a = AuditWriterRegistry::get_or_open(&profile, &log_path, Some(key_a)).unwrap();

        // Second open with key_b must return HmacKeyMismatch.
        let result = AuditWriterRegistry::get_or_open(&profile, &log_path, Some(key_b));
        assert!(
            matches!(result, Err(WriterError::HmacKeyMismatch { .. })),
            "registry must return HmacKeyMismatch when a different HMAC key is supplied, got: {result:?}"
        );
    }

    /// A second `get_or_open` call for the same profile supplying `None` where
    /// the first open supplied `Some(key)` returns `HmacKeyMismatch`.
    #[test]
    fn registry_hmac_key_mismatch_some_vs_none_returns_error() {
        let dir = TempDir::new().unwrap();
        let profile = format!("reg-keymmatch2-{}", uuid::Uuid::new_v4().simple());
        let log_path = dir.path().join(format!("{profile}.jsonl"));

        let key = Zeroizing::new([0xAAu8; 32]);

        // First open with a key.
        let _a = AuditWriterRegistry::get_or_open(&profile, &log_path, Some(key)).unwrap();

        // Second open with no key must return HmacKeyMismatch.
        let result = AuditWriterRegistry::get_or_open(&profile, &log_path, None);
        assert!(
            matches!(result, Err(WriterError::HmacKeyMismatch { .. })),
            "registry must return HmacKeyMismatch when None supplied after Some(key), got: {result:?}"
        );
    }

    // ── Partial-rotation detection tests ─────────────────────────────────────
    //
    // Each test simulates one specific intermediate-state on disk and asserts
    // that `AuditWriter::open` returns `WriterError::IntegrityViolation` wrapping
    // the correct `VerifyError::PartialRotation` variant.  The happy-path test
    // asserts that a clean directory opens without error.

    /// Happy path: a clean audit-log directory opens without error.
    #[test]
    fn detect_partial_rotation_clean_directory_opens_ok() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        // Fresh open on an empty directory must succeed.
        let writer = AuditWriter::open(path, None);
        assert!(
            writer.is_ok(),
            "clean directory must open without error; got: {writer:?}"
        );
    }

    /// Happy path: existing log with entries (no rotation artefacts) opens.
    #[test]
    fn detect_partial_rotation_existing_log_with_entries_opens_ok() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let mut writer = AuditWriter::open(path.clone(), None).unwrap();
            writer
                .write_entry(make_entry(writer.last_entry_hash()))
                .unwrap();
        }
        // Re-open on a clean file with one entry must succeed.
        let writer2 = AuditWriter::open(path, None);
        assert!(
            writer2.is_ok(),
            "clean file with entries must reopen without error; got: {writer2:?}"
        );
    }

    /// Orphan sidecar: a `.root_hmac` sidecar for a rotated archive exists but
    /// the corresponding rotated log file is absent.
    ///
    /// Simulates crash after step 2 (sidecar rename) but before step 3 (log
    /// rename) in `rotate()`.
    #[test]
    fn detect_partial_rotation_orphan_sidecar_detected() {
        use crate::audit_log::verify::{PartialRotationState, VerifyError};

        let dir = TempDir::new().unwrap();
        let stem = "audit.jsonl";
        let path = dir.path().join(stem);

        // Create the active log file (it must exist for the lock to be
        // acquired successfully, and it is clean so chain recovery proceeds).
        fs::write(&path, b"").unwrap();

        // Plant an orphan sidecar: `audit.jsonl.20260101T000000000.root_hmac`
        // without the matching rotated log `audit.jsonl.20260101T000000000`.
        let ts = "20260101T000000000";
        let orphan_sidecar = dir.path().join(format!("{stem}.{ts}.root_hmac"));
        fs::write(&orphan_sidecar, b"hmac-tag\n").unwrap();

        // The corresponding log file is deliberately absent.
        let result = AuditWriter::open(path.clone(), None);
        match result {
            Err(WriterError::IntegrityViolation(VerifyError::PartialRotation {
                state:
                    PartialRotationState::OrphanSidecar {
                        sidecar_path,
                        expected_log_path,
                    },
                ..
            })) => {
                assert_eq!(
                    sidecar_path, orphan_sidecar,
                    "sidecar_path must be the planted orphan sidecar"
                );
                assert_eq!(
                    expected_log_path,
                    dir.path().join(format!("{stem}.{ts}")),
                    "expected_log_path must be the missing rotated log"
                );
            }
            other => panic!(
                "expected WriterError::IntegrityViolation(VerifyError::PartialRotation \
                 {{ OrphanSidecar }}) but got: {other:?}"
            ),
        }
    }

    /// Mid-rename: a `.tmp` file in the audit directory is detected.
    ///
    /// Simulates a write-to-tmp pattern that was interrupted before the final
    /// rename.
    #[test]
    fn detect_partial_rotation_mid_rename_tmp_file_detected() {
        use crate::audit_log::verify::{PartialRotationState, VerifyError};

        let dir = TempDir::new().unwrap();
        let stem = "audit.jsonl";
        let path = dir.path().join(stem);

        // Create a clean active log file.
        fs::write(&path, b"").unwrap();

        // Plant a `.tmp` file (simulating an interrupted atomic write).
        let tmp_path = dir.path().join("audit.jsonl.tmp");
        let tmp_content = b"partial data";
        fs::write(&tmp_path, tmp_content).unwrap();

        let result = AuditWriter::open(path.clone(), None);
        match result {
            Err(WriterError::IntegrityViolation(VerifyError::PartialRotation {
                state:
                    PartialRotationState::MidRename {
                        tmp_path: detected_tmp,
                        size_bytes,
                    },
                ..
            })) => {
                assert_eq!(
                    detected_tmp, tmp_path,
                    "detected tmp_path must match the planted file"
                );
                assert_eq!(
                    size_bytes,
                    tmp_content.len() as u64,
                    "size_bytes must reflect the file size"
                );
            }
            other => panic!(
                "expected WriterError::IntegrityViolation(VerifyError::PartialRotation \
                 {{ MidRename }}) but got: {other:?}"
            ),
        }
    }

    /// Partial handoff write: the active log file has a truncated (non-JSON)
    /// last line.
    ///
    /// Simulates a write that was interrupted after writing a partial JSON byte
    /// sequence (e.g. the process was killed mid-`write_all`).
    #[test]
    fn detect_partial_rotation_partial_handoff_write_detected() {
        use crate::audit_log::verify::{PartialRotationState, VerifyError};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Write one complete JSON entry to the log, then append a truncated line.
        {
            let mut writer = AuditWriter::open(path.clone(), None).unwrap();
            writer
                .write_entry(make_entry(writer.last_entry_hash()))
                .unwrap();
            drop(writer); // release lock before writing corruption below
        }
        {
            let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
            // Write an incomplete JSON fragment (missing closing brace/bracket).
            f.write_all(b"{\"truncated_entry\":true, incomplete...")
                .unwrap();
            f.sync_data().unwrap();
        }

        let result = AuditWriter::open(path.clone(), None);
        match result {
            Err(WriterError::IntegrityViolation(VerifyError::PartialRotation {
                state:
                    PartialRotationState::PartialHandoffWrite {
                        log_path: detected_path,
                        file_size_bytes,
                        ..
                    },
                ..
            })) => {
                assert_eq!(
                    detected_path, path,
                    "detected log_path must match the opened path"
                );
                assert!(file_size_bytes > 0, "file_size_bytes must be non-zero");
            }
            other => panic!(
                "expected WriterError::IntegrityViolation(VerifyError::PartialRotation \
                 {{ PartialHandoffWrite }}) but got: {other:?}"
            ),
        }
    }

    /// Large-entry happy path: a log whose last complete entry serialises to more
    /// than 4096 bytes must open without error (no false-positive
    /// `PartialHandoffWrite`).
    ///
    /// Validates the backward-scan-by-chunks algorithm in
    /// `detect_partial_last_entry`: a fixed 4 KiB tail window would fail to
    /// locate a preceding newline when the final complete entry spans the window
    /// boundary, misclassifying the entry's front-partial as a truncated last
    /// line.
    #[test]
    fn detect_partial_rotation_large_entry_no_false_positive() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Write a valid complete entry, then append a second entry whose JSON
        // is larger than 4096 bytes.  We bypass `write_entry`'s arg_keys
        // truncation by directly constructing and serialising the oversized
        // line — this mimics a log written by a previous wallet version with
        // different limits, or a log with a very long `tool_name` / `network_id`.
        {
            let mut writer = AuditWriter::open(path.clone(), None).unwrap();
            writer
                .write_entry(make_entry(writer.last_entry_hash()))
                .unwrap();
            drop(writer);
        }

        // Build a valid-JSON line > 6000 bytes so it definitely crosses the
        // 4096-byte scan chunk boundary.
        {
            use crate::audit_log::{entry::NewToolInvocation, schema::PolicyDecision};

            // 64 arg_keys each ~100 bytes long produces a line >> 4 KiB.
            let large_arg_keys: Vec<String> = (0..64)
                .map(|i| format!("arg_key_{i:02}_{}", "x".repeat(90)))
                .collect();

            let invocation = NewToolInvocation::new(
                "stellar_pay_commit",
                "stellar:testnet",
                large_arg_keys,
                PolicyDecision::Allow,
                uuid::Uuid::new_v4().to_string(),
            );
            let mut entry = AuditEntry::new_tool_invocation(invocation);
            entry.previous_entry_hash = ZERO_BLOCK_HASH.to_owned();

            let mut json = serde_json::to_vec(&entry).unwrap();
            json.push(b'\n');
            assert!(
                json.len() > 4096,
                "test requires serialised entry > 4096 bytes, got {} bytes",
                json.len()
            );

            let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&json).unwrap();
            f.sync_data().unwrap();
        }

        // The open must succeed: a complete JSON line spanning > 4 KiB is NOT
        // a partial write, and the backward-scan fix must correctly identify it
        // as parseable.
        //
        // Note: chain verification at open will fail because the large entry's
        // `previous_entry_hash` does not match the preceding entry's hash.
        // We therefore call `detect_partial_last_entry` directly to isolate
        // the detection logic from chain-hash verification.
        let scan_file = fs::File::open(&path).unwrap();
        let result = detect_partial_last_entry(&scan_file, &path);
        assert!(
            matches!(result, Ok(None)),
            "large complete JSON entry must not trigger PartialHandoffWrite; got: {result:?}"
        );
    }

    /// Debug output truncated hash must match `sha256:XXXXXXXX...XXXXXXXX`
    #[test]
    fn debug_output_truncates_last_hash() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let mut writer = open_no_key(path);
        let entry = make_entry(writer.last_entry_hash());
        writer.write_entry(entry).unwrap();

        let debug_str = format!("{writer:?}");
        // Verify the truncated form: `sha256:XXXXXXXX...XXXXXXXX` where
        // - prefix is exactly `sha256:` followed by 8 hex chars
        // - then `...`
        // - then 8 hex chars at the tail
        let truncated_pattern_present = {
            // Find `sha256:` inside last_hash field.
            if let Some(hash_start) = debug_str.find("sha256:") {
                let rest = &debug_str[hash_start..];
                // Must have sha256: + 8 hex + ... + 8 hex
                if rest.len() >= 7 + 8 + 3 + 8 {
                    let hex_head = &rest[7..15]; // 8 chars after "sha256:"
                    let ellipsis = &rest[15..18]; // "..."
                    let hex_tail = &rest[18..26]; // 8 chars after "..."
                    hex_head.bytes().all(|b| b.is_ascii_hexdigit())
                        && ellipsis == "..."
                        && hex_tail.bytes().all(|b| b.is_ascii_hexdigit())
                } else {
                    false
                }
            } else {
                false
            }
        };
        assert!(
            truncated_pattern_present,
            "debug output must contain `sha256:XXXXXXXX...XXXXXXXX` pattern: {debug_str}"
        );
    }
}
