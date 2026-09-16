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
    chain::{ZERO_BLOCK_HASH, decode_hash, sign_chain_root, verify_chain_root},
    entry::AuditEntry,
    schema::TipAnchorReason,
    tip_anchor::{KeyedAuditAccess, TipAnchor, TipAnchorStore, TipAnchorStoreError},
};
use crate::timefmt::current_iso8601_utc;

// Re-export rotation constants at the writer module level for crate-internal
// consumers and tests that currently import from this module.
pub use super::rotation::{MAX_ROTATED_FILES, ROTATION_THRESHOLD_BYTES};

#[cfg(test)]
static FORCE_NEXT_ROTATION_CREATE_FAILURE_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

static LAST_ROTATION_TIMESTAMP_MS: AtomicU64 = AtomicU64::new(0);
static ROTATION_COLLISION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Reason carried by the tip-anchor refusal for a log replaced underneath the
/// writer's own handle.
///
/// The registry keys its eviction on this exact value: a cached writer that
/// holds a file the path no longer resolves to can never be brought back into
/// agreement by re-checking it, so the entry has to be dropped rather than
/// re-checked. Every other mismatch describes the file at the path, which the
/// cached writer still holds and an operator repairs in place.
const LOG_REPLACED_REASON: &str = "the log at the path was replaced underneath the writer";

/// Reason for a log that shrank below where this writer last appended.
///
/// An in-place truncation keeps the file's identity, so only the length says it
/// happened. Appending anyway would chain the new row off a tip the file no
/// longer holds and then anchor over the splice.
const LOG_TRUNCATED_REASON: &str = "the log is shorter than the writer's last append";

/// Reason for a log whose last entry is no longer the one this writer wrote.
///
/// An in-place overwrite that keeps the length passes both the identity and the
/// length check; the entry at the writer's own end offset is what discriminates.
const LOG_TIP_REWRITTEN_REASON: &str =
    "the entry at the writer's last append is not the one it wrote";

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
    /// Number of entries in the active file.
    ///
    /// Tracked whether or not an anchor store is attached, so attaching one to
    /// an already-open writer needs no rescan.
    entry_count: u64,
    /// Byte offset just past the active file's last entry — the file length
    /// when the file ends on an entry boundary, which it always does after a
    /// successful [`AuditWriter::write_entry`].
    end_offset: u64,
    /// Set when a tip-anchor write failed, cleared when one succeeds.
    ///
    /// The append path writes the anchor best-effort, because the entry is
    /// already durable and a keyring failure must not be reported as a failed
    /// append. Left alone, one transient failure would leave the anchor behind
    /// the file for every subsequent append, widening the window in which a
    /// rollback to a state at or ahead of the stale anchor is absorbed. The next
    /// append therefore re-writes the anchor for the writer's CURRENT state
    /// before it appends anything, which repairs any number of missed writes in
    /// one go.
    anchor_behind: bool,
    /// Keyring-held tip anchor for the active PATH, when the opener supplied
    /// one.
    ///
    /// `None` leaves every anchor behaviour off: the writer neither checks nor
    /// advances an anchor, and its appends are not gated on the file's identity
    /// either. Unkeyed writers (the startup advisory, the zero-config
    /// best-effort path, read-only smart-account verbs) are opened this way, so
    /// their appends land ahead of the anchor and the next keyed acquisition
    /// absorbs them.
    tip_anchor: Option<Arc<dyn TipAnchorStore>>,
    /// Test-only fault seam for the write-entry durability invariant.
    #[cfg(test)]
    fail_after_entry_before_sidecar: bool,
    /// Test-only fault seam that skips the anchor write while still appending
    /// and fsyncing the entry — the crash window between the entry's
    /// `sync_data` and the anchor write.
    #[cfg(test)]
    skip_tip_anchor_write: bool,
    /// Archive name produced by a failed mid-rotation active-lock acquisition.
    ///
    /// Once set, the writer refuses all future writes. The caller must discard
    /// the instance and reopen after operator inspection.
    partial_rotation_archive: Option<PathBuf>,
    /// Latched, with the reason, when the file at the path stopped being the
    /// file this writer holds or stopped ending where this writer left it.
    ///
    /// Once set, every acquisition and every append through this instance
    /// refuses, whatever the path holds afterwards. A writer that has been lied
    /// to about its own file can never be brought back into agreement on its
    /// own: the rows it would append are unreachable or would chain over a
    /// splice, and a caller still holding it from an earlier acquisition must
    /// not get to write one. Recovery is an operator's, through
    /// `audit reanchor`; the registry's part is to stop handing this writer out.
    log_diverged: Option<&'static str>,
    /// Set once the anchor names a row a refused append was obliged to write.
    ///
    /// One such anchor is enough: it already puts every file at this path short
    /// of the anchor, and a second would describe a chain of rows none of which
    /// exist. Left unset when the keyring rejected the write, so the next
    /// refused append retries it.
    owed_row_anchored: bool,
}

/// How [`AuditWriter::open`] treats an attached tip-anchor store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TipAnchorOpenMode {
    /// Run the check, adopting an absent anchor and absorbing appends made
    /// ahead of it. A rolled-back or truncated file is refused.
    Check,
    /// Skip the check so a refused file can be opened for repair. Only
    /// [`AuditWriter::open_for_reanchor`] uses this; the caller must follow it
    /// with [`AuditWriter::reanchor`].
    Repair,
}

/// What reconciling the anchor against the active file did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorOutcome {
    /// No anchor store is attached; nothing was checked.
    NotAnchored,
    /// No anchor existed and the active file holds no entries. The store is
    /// left empty, which says exactly that; the first append writes the first
    /// anchor. No row is emitted — there is no tip to record.
    AdoptedEmpty,
    /// No anchor existed and the active file carried entries; its tip was
    /// adopted. The caller emits the `audit_tip_anchored` row.
    AdoptedExisting,
    /// The anchor already named the file's tip exactly.
    Current,
    /// The file had moved forward past the anchor with the anchored entry
    /// intact; the anchor was advanced to the new tip.
    Advanced,
    /// The anchor named the newest archive's rotation handoff and the path held
    /// the file that rotation created; the anchor was moved onto that file.
    RotationCompleted,
}

/// What the anchor store holds for a path, from the repair verb's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoredTipAnchor {
    /// Nothing has ever been anchored at this path.
    Absent,
    /// A usable anchor.
    Usable(TipAnchor),
    /// A value is stored and cannot be parsed. Every ordinary caller refuses on
    /// it; the repair verb replaces it.
    Unusable {
        /// Structural description of the stored bytes, carrying no digest.
        shape: String,
        /// Why the value could not be parsed.
        reason: String,
    },
}

impl StoredTipAnchor {
    /// Renders the stored value for an operator-facing report.
    ///
    /// A usable anchor gives its `<entry count>:<end offset>` coordinates; the
    /// other two say what they are. No digest appears in any of them.
    #[must_use]
    pub fn coordinates(&self) -> Option<String> {
        match self {
            Self::Absent => None,
            Self::Usable(anchor) => Some(anchor.coordinates()),
            Self::Unusable { shape, .. } => Some(format!("unusable ({shape})")),
        }
    }
}

/// Describes a stored anchor value structurally, without echoing it.
///
/// A value that failed to parse is of unknown provenance, so it is reported by
/// field count and length rather than quoted back to the operator.
fn describe_anchor_shape(raw: Option<&str>) -> String {
    match raw {
        None => "the value disappeared between the two reads".to_owned(),
        Some(raw) => format!(
            "{} colon-separated fields, {} bytes",
            raw.split(':').count(),
            raw.len()
        ),
    }
}

/// The outcome of an operator-acknowledged re-anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReanchorReport {
    /// The anchor that was replaced.
    pub previous: StoredTipAnchor,
    /// The anchor now in force, or `None` when the repair left the file with no
    /// entries to anchor.
    pub current: Option<TipAnchor>,
    /// Value of the path's monotonic re-anchor counter after this repair.
    pub reanchor_count: u64,
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
    /// `access` pairs the 32-byte chain-root HMAC key with the anchor store for
    /// this path, and the two cannot be separated: a keyed writer's rows are the
    /// ones `audit verify` covers and the ones worth removing, so a key with no
    /// anchor store would leave exactly those rows unguarded. `None` opens
    /// unkeyed — the chain root is not HMAC-signed (the hash chain is still
    /// intact) and no anchor is checked or advanced. There is no third shape.
    ///
    /// # Errors
    ///
    /// - [`WriterError::PathContract`] if `path` has no parent directory
    ///   component (bare filename).
    /// - [`WriterError::Io`] on I/O failure.
    /// - [`WriterError::FileLocked`] if another process holds the exclusive
    ///   lock on the log file.
    /// - [`WriterError::TipAnchorMismatch`] / [`WriterError::TipAnchorStore`]
    ///   from the anchor reconciliation when `access` is supplied; see
    ///   [`AuditWriter::open_with_tip_anchor`].
    pub fn open(path: PathBuf, access: Option<KeyedAuditAccess>) -> Result<Self, WriterError> {
        let (hmac_key, tip_anchor) = match access {
            Some(access) => {
                let (key, store) = access.into_parts();
                (Some(key), Some(store))
            }
            None => (None, None),
        };
        Self::open_inner(path, hmac_key, tip_anchor, TipAnchorOpenMode::Check)
    }

    /// Opens a KEYED writer with no anchor store — the shape a production
    /// caller cannot construct.
    ///
    /// Reproduces a log written by a build whose keyed writers maintained no
    /// anchor, which is what the adoption path has to handle on first keyed use.
    /// Feature-gated: never reachable from a shipped binary.
    ///
    /// # Errors
    ///
    /// Everything [`AuditWriter::open`] returns for an unkeyed open.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn open_keyed_unanchored_for_test(
        path: PathBuf,
        hmac_key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, WriterError> {
        Self::open_inner(path, Some(hmac_key), None, TipAnchorOpenMode::Check)
    }

    /// Opens the audit log as [`AuditWriter::open`] does and binds it to
    /// `tip_anchor`, the keyring-held high-water mark for this PATH, with the
    /// chain-root key optional.
    ///
    /// The anchor is independent of the chain-root key, so a profile that has
    /// not minted one yet still anchors. This is the constructor for that case;
    /// [`AuditWriter::open`] is the one every keyed caller uses, and it takes
    /// the key and the store as one inseparable value.
    ///
    /// The anchor is reconciled against the file before the writer is returned:
    /// an absent anchor is adopted (writing an `audit_tip_anchored` row when the
    /// file already carried entries), a file that moved forward past the anchor
    /// with the anchored entry intact is absorbed and the anchor advanced, and a
    /// file that was rolled back, truncated, or replaced is refused with
    /// [`WriterError::TipAnchorMismatch`]. From then on every
    /// [`AuditWriter::write_entry`] advances the anchor.
    ///
    /// Supply a store only for writers whose appends should move the anchor.
    /// See [`crate::audit_log::tip_anchor`] for the full check semantics and for
    /// what the anchor does not protect.
    ///
    /// # Errors
    ///
    /// Everything [`AuditWriter::open`] returns, plus:
    /// - [`WriterError::TipAnchorMismatch`] when the file no longer contains the
    ///   anchored tip.
    /// - [`WriterError::TipAnchorStore`] when the anchor cannot be read or
    ///   written.
    pub fn open_with_tip_anchor(
        path: PathBuf,
        hmac_key: Option<Zeroizing<[u8; 32]>>,
        tip_anchor: Arc<dyn TipAnchorStore>,
    ) -> Result<Self, WriterError> {
        Self::open_inner(path, hmac_key, Some(tip_anchor), TipAnchorOpenMode::Check)
    }

    /// Opens the audit log for anchor repair, skipping the tip-anchor check so
    /// a refused file can be inspected and re-anchored.
    ///
    /// The only caller is the `audit reanchor` verb, which follows this with
    /// [`AuditWriter::reanchor`]. Opening this way does not by itself change the
    /// anchor.
    ///
    /// # Errors
    ///
    /// Everything [`AuditWriter::open`] returns.
    pub fn open_for_reanchor(
        path: PathBuf,
        hmac_key: Option<Zeroizing<[u8; 32]>>,
        tip_anchor: Arc<dyn TipAnchorStore>,
    ) -> Result<Self, WriterError> {
        Self::open_inner(path, hmac_key, Some(tip_anchor), TipAnchorOpenMode::Repair)
    }

    fn open_inner(
        path: PathBuf,
        hmac_key: Option<Zeroizing<[u8; 32]>>,
        tip_anchor: Option<Arc<dyn TipAnchorStore>>,
        anchor_mode: TipAnchorOpenMode,
    ) -> Result<Self, WriterError> {
        // Enforce parent-component contract: a bare filename has no known
        // parent directory, making rotated-sibling placement and directory-mode
        // enforcement impossible.  Callers must supply an explicit parent, e.g.
        // `~/.local/share/stellar-agent/audit/default.jsonl`.
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
        let len = file.metadata()?.len();
        let is_new_file = len == 0;

        // Determine initial last_hash, entry count, and end offset by replaying
        // the whole active file.  The counters are tracked whether or not an
        // anchor store is attached, so the anchor check costs no rescan of its
        // own on a writer opened unkeyed.
        //
        // The replay seeds from the cross-file bridge, not unconditionally from
        // the zero block: the first entry of a file created by a rotation chains
        // off the outgoing file's handoff entry (see the module-level
        // "First-entry-per-file rule"), so a zero-block seed would read every
        // post-rotation active file as a broken chain.
        let seed = initial_chain_seed(&path)?;
        let scan = if is_new_file {
            ChainScan::empty(seed)
        } else {
            read_and_verify_entry_chain(&file, 0, &seed)?
        };

        let mut writer = Self {
            path,
            _lock: lock,
            file,
            last_hash: scan.last_hash,
            is_new_file,
            hmac_key,
            entry_count: scan.entry_count,
            end_offset: scan.end_offset,
            anchor_behind: false,
            log_diverged: None,
            owed_row_anchored: false,
            tip_anchor,
            #[cfg(test)]
            fail_after_entry_before_sidecar: false,
            #[cfg(test)]
            skip_tip_anchor_write: false,
            partial_rotation_archive: None,
        };

        if writer.tip_anchor.is_some() && anchor_mode == TipAnchorOpenMode::Check {
            let outcome = writer.reconcile_tip_anchor()?;
            writer.emit_adoption_row_if_needed(outcome);
        }

        Ok(writer)
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

        // The log this writer holds must still be the log at its path, and must
        // still end on the entry this writer last wrote. A caller acquires the
        // writer, signs, submits, and only then appends, so the check at
        // acquisition covers none of that span: a replacement or a rollback
        // landing inside it would take the row proving a committed action, or
        // splice it onto a chain the file no longer holds. The check runs BEFORE
        // the rotation decision, which is the one moment the handle and the path
        // are legitimately allowed to diverge.
        //
        // A refusal here is durable, not just in-process: the row the wallet owed
        // is anchored in the keyring, so no file at this path satisfies the
        // anchor again until an operator acknowledges what happened.
        if let Err(e) = self.refuse_if_log_moved_on_append() {
            if !self.owed_row_anchored {
                self.anchor_the_refused_row(&mut entry);
            }
            return Err(e);
        }

        // Repair an anchor left behind by an earlier failed write, before this
        // append moves the tip again. The value written names the entry most
        // recently fsynced, so it is safe at any point and subsumes however many
        // writes were missed.
        self.retry_tip_anchor_if_behind();

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

        // Advance the keyring-held tip anchor to the entry just fsynced, before
        // the in-memory tip moves.  Best-effort by contract: the entry is
        // already durable, so failing the append here would tell the caller the
        // row was not written when it was.  A missed advance leaves the anchor
        // behind the file, which the next reconciliation absorbs as an
        // ahead-of-anchor file.
        let advanced_count = self.entry_count.saturating_add(1);
        let advanced_end = self.entry_end_offset()?;
        self.store_tip_anchor_best_effort(&TipAnchor::new(
            advanced_count,
            current_hash.clone(),
            advanced_end,
        ));

        // Advance the chain.
        self.entry_count = advanced_count;
        self.end_offset = advanced_end;
        self.last_hash = current_hash;
        Ok(())
    }

    /// Enables a test-only fault seam immediately after log-entry fsync and
    /// immediately before the chain-root sidecar write.
    #[cfg(test)]
    pub(crate) fn set_fail_after_entry_before_sidecar(&mut self, enabled: bool) {
        self.fail_after_entry_before_sidecar = enabled;
    }

    /// Enables a test-only fault seam in the crash window between an entry's
    /// `sync_data` and the tip-anchor write: the entry lands durably, the
    /// anchor does not move.
    #[cfg(test)]
    pub(crate) fn set_skip_tip_anchor_write(&mut self, enabled: bool) {
        self.skip_tip_anchor_write = enabled;
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

    /// Performs only the first half of a rotation: appends the handoff entry to
    /// the outgoing file and advances the anchor onto it, stopping before the
    /// renames.
    ///
    /// `pub(crate)` and `#[cfg(test)]` — lets a test observe the rotation
    /// window, where the path still holds the whole outgoing file and the
    /// rollback guard must still be armed. The writer is left mid-rotation and
    /// must be discarded afterwards.
    #[cfg(test)]
    pub(crate) fn write_rotation_handoff_for_test(&mut self) -> Result<String, WriterError> {
        let stem = self
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("audit.jsonl");
        let rotated_name = format!("{stem}.{}", compact_timestamp());
        self.append_rotation_handoff(&rotated_name)
    }

    /// Returns the path to the active log file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    // ── Tip anchor ───────────────────────────────────────────────────────────

    /// Returns `true` when this writer maintains a tip anchor.
    #[must_use]
    pub fn has_tip_anchor(&self) -> bool {
        self.tip_anchor.is_some()
    }

    /// Reconciles the anchor against the active file — the check
    /// [`AuditWriterRegistry::get_or_open_keyed`] runs on EVERY acquisition of a
    /// keyed writer.
    ///
    /// The writer registry caches writers for the process lifetime, so a check
    /// performed only at open would miss a file replaced underneath a live
    /// writer. This re-reads the file each time: cheap when the anchor is
    /// current (one file-identity comparison, one seek and one entry hash), a
    /// replay of the appended tail when the file has moved forward.
    ///
    /// A writer with no anchor store returns `Ok(())` unchanged.
    ///
    /// # Errors
    ///
    /// - [`WriterError::TipAnchorMismatch`] when the file no longer contains the
    ///   anchored tip — it was rolled back, truncated, or replaced.
    /// - [`WriterError::TipAnchorStore`] when the anchor cannot be read or
    ///   written.
    /// - [`WriterError::Io`] / [`WriterError::Serialise`] /
    ///   [`WriterError::ChainBrokenAtOpen`] when the file cannot be replayed.
    pub fn verify_tip_anchor(&mut self) -> Result<(), WriterError> {
        let outcome = self.reconcile_tip_anchor()?;
        self.emit_adoption_row_if_needed(outcome);
        Ok(())
    }

    /// Moves the anchor to the active file's current tip and records the
    /// repair — the operator-acknowledged way out of a
    /// [`WriterError::TipAnchorMismatch`].
    ///
    /// Replays the whole active file first, so a file whose internal chain is
    /// broken is refused rather than blessed. On success the path's monotonic
    /// re-anchor counter is incremented and an `audit_tip_anchored` row naming
    /// the superseded anchor is appended, which advances the anchor once more
    /// to cover that row.
    ///
    /// Open the writer with [`AuditWriter::open_for_reanchor`]: an ordinary open
    /// would refuse before reaching this method.
    ///
    /// # Errors
    ///
    /// - [`WriterError::TipAnchorUnavailable`] when no anchor store is attached.
    /// - [`WriterError::TipAnchorStore`] when the anchor or the counter cannot be
    ///   read or written.
    /// - [`WriterError::ChainBrokenAtOpen`] when the file's own chain does not
    ///   verify.
    /// - [`WriterError::Io`] / [`WriterError::Serialise`] on failure to append
    ///   the row.
    pub fn reanchor(&mut self) -> Result<ReanchorReport, WriterError> {
        let store = self
            .tip_anchor
            .clone()
            .ok_or(WriterError::TipAnchorUnavailable)?;
        let previous = self.stored_tip_anchor()?;

        let scan = self.replay_active_file()?;
        self.adopt_scan_state(&scan);
        let repaired_count = scan.entry_count;
        if scan.entry_count > 0 {
            let repaired =
                TipAnchor::new(scan.entry_count, scan.last_hash.clone(), scan.end_offset);
            store
                .store_anchor(&repaired)
                .map_err(WriterError::TipAnchorStore)?;
        }
        let reanchor_count = store
            .bump_reanchor_count()
            .map_err(WriterError::TipAnchorStore)?;

        // The row itself advances the anchor past `repaired`; the report names
        // the anchor the operator asked for, which is what the refusal was
        // about.
        self.write_entry(AuditEntry::new_audit_tip_anchored(
            TipAnchorReason::RollbackAcknowledged,
            repaired_count,
            previous.coordinates(),
            Some(reanchor_count),
            uuid::Uuid::new_v4().to_string(),
        ))?;

        // The row itself advanced the anchor past the repaired tip; report the
        // anchor as it now stands rather than the intermediate value.
        let current = store.load_anchor().map_err(WriterError::TipAnchorStore)?;
        Ok(ReanchorReport {
            previous,
            current,
            reanchor_count,
        })
    }

    /// Returns the anchor currently held in the store, without comparing it
    /// against the file.
    ///
    /// Used by the repair verb to report what it is about to replace. A value
    /// that is present but does not parse is reported as
    /// [`StoredTipAnchor::Unusable`] rather than failing, so the repair can
    /// replace it; every other caller goes through
    /// [`TipAnchorStore::load_anchor`] and refuses on it.
    ///
    /// # Errors
    ///
    /// - [`WriterError::TipAnchorUnavailable`] when no anchor store is attached.
    /// - [`WriterError::TipAnchorStore`] when the backend is unavailable.
    pub fn stored_tip_anchor(&self) -> Result<StoredTipAnchor, WriterError> {
        let store = self
            .tip_anchor
            .as_ref()
            .ok_or(WriterError::TipAnchorUnavailable)?;
        match store.load_anchor() {
            Ok(Some(anchor)) => Ok(StoredTipAnchor::Usable(anchor)),
            Ok(None) => Ok(StoredTipAnchor::Absent),
            Err(parse_error) => {
                // The value is there and cannot be read. Ordinary opens refuse on
                // it, which is what keeps a corrupted anchor from reading as
                // "nothing anchored"; the repair verb is the one caller that has
                // to be able to replace it, so it needs to see the shape.
                let raw = store.load_raw().map_err(WriterError::TipAnchorStore)?;
                Ok(StoredTipAnchor::Unusable {
                    shape: describe_anchor_shape(raw.as_deref()),
                    reason: parse_error.detail,
                })
            }
        }
    }

    /// Replays the active file and returns the anchor that describes its
    /// current tip, WITHOUT storing it.
    ///
    /// Used by the repair verb to report what it would write before the
    /// operator acknowledges it. `None` when the file has no entries, so there
    /// is nothing to anchor.
    ///
    /// # Errors
    ///
    /// [`WriterError::Io`] / [`WriterError::Serialise`] /
    /// [`WriterError::ChainBrokenAtOpen`] when the file cannot be replayed.
    pub fn current_tip_anchor(&self) -> Result<Option<TipAnchor>, WriterError> {
        let scan = self.replay_active_file()?;
        if scan.entry_count == 0 {
            return Ok(None);
        }
        Ok(Some(TipAnchor::new(
            scan.entry_count,
            scan.last_hash,
            scan.end_offset,
        )))
    }

    /// Returns the hash the active file's FIRST entry must chain from.
    ///
    /// The single source of the replay seed for this writer: every full-file
    /// replay, and the tail replay whose anchor names an empty file, goes
    /// through here rather than naming [`ZERO_BLOCK_HASH`] directly. The zero
    /// block is correct only for the first file of a chain; a file a rotation
    /// created chains off the outgoing file's handoff entry, so a hardcoded
    /// zero-block seed reads every post-rotation active file as a broken chain.
    fn chain_seed(&self) -> Result<String, WriterError> {
        initial_chain_seed(&self.path)
    }

    /// Replays the whole active file from its chain seed.
    ///
    /// Validates linkage end to end and yields the file's entry count, tip hash,
    /// and end offset — the three values a [`TipAnchor`] records.
    fn replay_active_file(&self) -> Result<ChainScan, WriterError> {
        let seed = self.chain_seed()?;
        read_and_verify_entry_chain(&self.file, 0, &seed)
    }

    /// Compares the anchor with the active file and brings the two into
    /// agreement, or refuses.
    ///
    /// Proves first that the file at the path IS the file this writer holds,
    /// then reads the length through the path rather than the held handle. Every
    /// other read here goes through the handle, which is the right source for
    /// the bytes this writer will append after; the anchor, though, guards the
    /// file every other process and every operator sees at the path, and the two
    /// are one file only for as long as the identity comparison says so.
    fn reconcile_tip_anchor(&mut self) -> Result<AnchorOutcome, WriterError> {
        let Some(store) = self.tip_anchor.clone() else {
            return Ok(AnchorOutcome::NotAnchored);
        };
        // A rotation that failed between the rename and the new file's creation
        // leaves this writer's handle on the archive with nothing, or something
        // stale, at the path. That is a partial rotation, which has its own code
        // and its own runbook section; reporting it as a replacement would send
        // the operator to `audit reanchor` for a directory state the repair verb
        // refuses anyway.
        if let Some(archive_name) = &self.partial_rotation_archive {
            return Err(WriterError::PartialRotation {
                archive_name: archive_name.clone(),
                active_locked_by: None,
            });
        }
        let anchor = store.load_anchor().map_err(WriterError::TipAnchorStore)?;
        self.refuse_if_replaced(anchor.as_ref())?;
        let len = fs::metadata(&self.path)?.len();

        let Some(anchor) = anchor else {
            return self.adopt_tip_anchor(store.as_ref(), len);
        };

        // Cheap path first: prove the anchored entry is still the entry ending
        // at the anchored offset, without replaying the file and without
        // touching the audit directory.
        let intact = self.entry_is_intact_at(anchor.end_offset, &anchor.tip_hash)?;
        if intact && len == anchor.end_offset {
            self.entry_count = anchor.entry_count;
            self.end_offset = anchor.end_offset;
            self.is_new_file = false;
            self.last_hash.clone_from(&anchor.tip_hash);
            return Ok(AnchorOutcome::Current);
        }

        // The anchor may name the PREVIOUS file generation: a rotation leaves it
        // on the outgoing file's handoff entry, and it stays there until the new
        // file's first append advances it. That state is provable, not guessed —
        // the anchored tip must equal the hash of the newest archive's last
        // entry, which `chain_seed` already reads and already requires to be a
        // rotation handoff naming that archive. An attacker cannot manufacture
        // the match: appending a handoff to a copy of the log produces a NEW tip
        // hash, which the anchor does not name.
        //
        // Checked before the length comparison because such an anchor's count
        // and offset describe the ARCHIVE, so comparing them against the file
        // now at the path is meaningless in either direction.
        if self.anchor_names_the_rotation_handoff(&anchor)? {
            return self.adopt_rotated_file(store.as_ref());
        }

        if len < anchor.end_offset {
            return Err(self.tip_anchor_mismatch(&anchor, len, "file is shorter than the anchor"));
        }
        if !intact {
            return Err(self.tip_anchor_mismatch(
                &anchor,
                len,
                "the entry at the anchored offset is not the anchored entry",
            ));
        }

        // The file moved forward past the anchor. Replay only the appended tail,
        // which validates that it chains off the anchored tip.
        let tail = read_and_verify_entry_chain(&self.file, anchor.end_offset, &anchor.tip_hash)?;
        let advanced = TipAnchor::new(
            anchor.entry_count.saturating_add(tail.entry_count),
            tail.last_hash.clone(),
            tail.end_offset,
        );
        self.entry_count = advanced.entry_count;
        self.end_offset = advanced.end_offset;
        self.is_new_file = false;
        self.last_hash.clone_from(&advanced.tip_hash);
        store
            .store_anchor(&advanced)
            .map_err(WriterError::TipAnchorStore)?;
        Ok(AnchorOutcome::Advanced)
    }

    /// Returns `true` when the anchor names exactly the newest rotated
    /// archive's handoff entry — the fingerprint of a rotation whose renames
    /// completed while the new file's anchor write was lost.
    ///
    /// Compares hashes, not counts or offsets: the hash identifies one entry,
    /// and the counts in such an anchor describe the archive rather than the
    /// file now at the path. A log that has never rotated has no archive, so
    /// [`AuditWriter::chain_seed`] returns the zero block, which is never an
    /// entry hash and therefore never matches an anchor with entries.
    fn anchor_names_the_rotation_handoff(&self, anchor: &TipAnchor) -> Result<bool, WriterError> {
        Ok(self.chain_seed()? == anchor.tip_hash)
    }

    /// Re-derives the anchor from the file a completed rotation left at this
    /// path.
    ///
    /// No `audit_tip_anchored` row is written: the rotation handoff entry in the
    /// archive is already the durable record that the rotation happened, and the
    /// anchor is being moved onto the same chain it already covered rather than
    /// forgiving a divergence.
    fn adopt_rotated_file(
        &mut self,
        store: &dyn TipAnchorStore,
    ) -> Result<AnchorOutcome, WriterError> {
        let scan = self.replay_active_file()?;
        self.adopt_scan_state(&scan);
        if scan.entry_count > 0 {
            let rotated = TipAnchor::new(scan.entry_count, scan.last_hash.clone(), scan.end_offset);
            store
                .store_anchor(&rotated)
                .map_err(WriterError::TipAnchorStore)?;
        }
        // A file the rotation created but nothing has appended to yet stays
        // unanchored in its own right: the anchor keeps naming the archive's
        // handoff, which is what proves this generation on the next open.
        Ok(AnchorOutcome::RotationCompleted)
    }

    /// Takes an unanchored file under anchor protection at its current tip.
    ///
    /// The whole file is replayed first, so a broken chain is refused rather
    /// than adopted. When the writer is keyed AND the file carries a chain-root
    /// sidecar, that sidecar must verify: a log whose root signature is wrong is
    /// not a log worth anchoring. A keyed writer facing a file with NO sidecar
    /// still adopts — that is a log written only by unkeyed writers, which is
    /// exactly the state the zero-config quickstart leaves behind, and refusing
    /// it would make minting an audit key a one-way door.
    fn adopt_tip_anchor(
        &mut self,
        store: &dyn TipAnchorStore,
        len: u64,
    ) -> Result<AnchorOutcome, WriterError> {
        if len == 0 {
            // Nothing to anchor. Leaving the store empty says exactly that, and
            // the first append writes the first real anchor.
            self.entry_count = 0;
            self.end_offset = 0;
            return Ok(AnchorOutcome::AdoptedEmpty);
        }

        let scan = self.replay_active_file()?;
        self.verify_chain_root_for_adoption()?;
        let adopted = TipAnchor::new(scan.entry_count, scan.last_hash.clone(), scan.end_offset);
        self.adopt_scan_state(&scan);
        store
            .store_anchor(&adopted)
            .map_err(WriterError::TipAnchorStore)?;
        Ok(if adopted.entry_count == 0 {
            AnchorOutcome::AdoptedEmpty
        } else {
            AnchorOutcome::AdoptedExisting
        })
    }

    /// Verifies the active file's chain-root sidecar before adoption.
    ///
    /// A missing sidecar is accepted; see [`AuditWriter::adopt_tip_anchor`].
    fn verify_chain_root_for_adoption(&self) -> Result<(), WriterError> {
        let Some(key) = self.hmac_key.as_ref() else {
            return Ok(());
        };
        let sidecar = hmac_sidecar_path(&self.path);
        if !sidecar.exists() {
            return Ok(());
        }
        let tag = fs::read_to_string(&sidecar)?;
        let first = read_first_entry_of(&self.file)?;
        let body = first
            .canonical_json_body()
            .map_err(WriterError::Serialise)?;
        verify_chain_root(key.as_ref(), &body, tag.trim()).map_err(|_| {
            WriterError::IntegrityViolation(super::verify::VerifyError::HmacMismatch {
                file: basename_lossy_path(&self.path),
            })
        })
    }

    /// Returns `true` when the last entry ending at or before `end_offset` still
    /// hashes to `tip_hash`.
    ///
    /// At a zero entry count there is no entry to hash; the offset comparison in
    /// the caller is the whole check. The anchor check passes the anchor's
    /// coordinates, the append check passes the writer's own.
    fn entry_is_intact_at(&mut self, end_offset: u64, tip_hash: &str) -> Result<bool, WriterError> {
        let Some(line) = read_last_line_before(&self.file, end_offset)? else {
            return Ok(false);
        };
        let Ok(entry) = serde_json::from_slice::<AuditEntry>(&line) else {
            return Ok(false);
        };
        let hash = compute_entry_hash_streamed(&entry, &entry.previous_entry_hash)?;
        Ok(hash == tip_hash)
    }

    /// Adopts a full-file replay result as the writer's in-memory state.
    fn adopt_scan_state(&mut self, scan: &ChainScan) {
        self.entry_count = scan.entry_count;
        self.end_offset = scan.end_offset;
        self.is_new_file = scan.entry_count == 0;
        if scan.entry_count > 0 {
            self.last_hash.clone_from(&scan.last_hash);
        }
    }

    /// Refuses when the file now at the path is not the file this writer holds.
    ///
    /// The writer keeps ONE handle for its whole lifetime, and every other read
    /// in the anchor check goes through it. A rename over the log path leaves
    /// that handle on the previous inode, whose tail is exactly the anchored
    /// one: the check would pass, the rows would be appended to a file no path
    /// names any more and would be gone when the process exits, and the log an
    /// operator reads would stay behind the anchor with nothing refused. File
    /// identity is therefore resolved from the PATH and compared against the
    /// handle, which is the only comparison a rename cannot satisfy. A path
    /// holding no file at all is the same finding: the log this writer guards is
    /// not there.
    ///
    /// Recovery is an operator's, not the writer's: the registry drops the
    /// cached writer so the next acquisition opens the file at the path and
    /// checks THAT file against the anchor, which refuses an older copy and
    /// accepts the same file put back. The new file is never adopted silently.
    fn refuse_if_replaced(&mut self, anchor: Option<&TipAnchor>) -> Result<(), WriterError> {
        if let Some(reason) = self.log_diverged {
            return Err(self.diverged_error(anchor, reason));
        }
        let held = same_file::Handle::from_file(self.file.try_clone()?)?;
        let replaced = match same_file::Handle::from_path(&self.path) {
            Ok(at_path) => at_path != held,
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Err(e) => return Err(WriterError::Io(e)),
        };
        if !replaced {
            return Ok(());
        }
        Err(self.latch(anchor, LOG_REPLACED_REASON))
    }

    /// Proves, on the append path, that the file at the path is still the file
    /// this writer holds AND still ends on the entry this writer last wrote.
    ///
    /// An unkeyed writer has no anchor to protect and no rows worth removing, so
    /// it pays nothing. For an anchored writer this is one identity comparison,
    /// one `stat` of the path, and — only when the file carries entries — a read
    /// of its last line and one hash. No keyring round trip: the refusal reports
    /// the writer's own counters rather than reloading the anchor to name them.
    ///
    /// The three findings are distinct because the file diverged in three ways.
    /// A rename leaves the identity behind; an in-place truncation keeps the
    /// identity and moves the end; an in-place overwrite of the same length
    /// keeps both and changes the bytes. All three would otherwise let this
    /// writer chain a row off a tip the file at the path does not hold and then
    /// anchor over the result.
    fn refuse_if_log_moved_on_append(&mut self) -> Result<(), WriterError> {
        if self.tip_anchor.is_none() {
            return Ok(());
        }
        self.refuse_if_replaced(None)?;
        // Identity is proven, so the held handle and the path are one file and
        // the reads below can go through the handle.
        if fs::metadata(&self.path)?.len() < self.end_offset {
            return Err(self.latch(None, LOG_TRUNCATED_REASON));
        }
        let tip = self.last_hash.clone();
        if self.entry_count > 0 && !self.entry_is_intact_at(self.end_offset, &tip)? {
            return Err(self.latch(None, LOG_TIP_REWRITTEN_REASON));
        }
        Ok(())
    }

    /// Latches `reason` and returns the refusal it names.
    ///
    /// Once latched the writer refuses everything, because the condition is not
    /// one it can re-test its way out of: the caller it refused has already been
    /// told the row was not written, and a file that looks right again afterwards
    /// would only hide that.
    fn latch(&mut self, anchor: Option<&TipAnchor>, reason: &'static str) -> WriterError {
        self.log_diverged = Some(reason);
        self.diverged_error(anchor, reason)
    }

    /// Builds the refusal for a log that stopped being the one this writer
    /// holds.
    ///
    /// The anchor's coordinates name what the log was expected to hold. On a
    /// path nothing has anchored yet the writer's own counters say the same
    /// thing about the file it holds, which is what the divergence departed
    /// from. The length is the one at the path now; a path holding no file
    /// reports zero, and the reason names which of the three it was.
    fn diverged_error(&self, anchor: Option<&TipAnchor>, reason: &'static str) -> WriterError {
        let (expected_count, expected_offset) = anchor
            .map_or((self.entry_count, self.end_offset), |anchor| {
                (anchor.entry_count, anchor.end_offset)
            });
        let actual_len = fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        tracing::warn!(
            log = %basename_lossy_path(&self.path),
            expected_count,
            expected_offset,
            actual_len,
            reason,
            "audit tip anchor mismatch; refusing"
        );
        WriterError::TipAnchorMismatch {
            expected_count,
            expected_offset,
            actual_len,
            reason,
        }
    }

    /// Builds the refusal for a file that no longer contains the anchored tip.
    fn tip_anchor_mismatch(
        &self,
        anchor: &TipAnchor,
        actual_len: u64,
        reason: &'static str,
    ) -> WriterError {
        tracing::warn!(
            log = %basename_lossy_path(&self.path),
            expected_count = anchor.entry_count,
            expected_offset = anchor.end_offset,
            actual_len,
            reason,
            "audit tip anchor mismatch; refusing"
        );
        WriterError::TipAnchorMismatch {
            expected_count: anchor.entry_count,
            expected_offset: anchor.end_offset,
            actual_len,
            reason,
        }
    }

    /// Writes `anchor` without failing the caller.
    ///
    /// Used on the append and rotation paths, where the log entry is already
    /// durable and an anchor-write failure must not be reported as a failed
    /// append. A failure latches [`AuditWriter::anchor_behind`] so the next
    /// append retries before it appends.
    fn store_tip_anchor_best_effort(&mut self, anchor: &TipAnchor) {
        #[cfg(test)]
        if self.skip_tip_anchor_write {
            return;
        }
        let Some(store) = self.tip_anchor.clone() else {
            return;
        };
        match store.store_anchor(anchor) {
            Ok(()) => self.anchor_behind = false,
            Err(e) => {
                self.anchor_behind = true;
                tracing::warn!(
                    log = %basename_lossy_path(&self.path),
                    error = %e,
                    "audit tip anchor write failed; the next append retries it, and \
                     the next acquisition absorbs whatever gap remains"
                );
            }
        }
    }

    /// Anchors the row this append was refused on, so the refusal outlives the
    /// process.
    ///
    /// The action the row was going to prove has already committed. A refusal
    /// that lives only in this writer's memory is erased by a restart, and the
    /// file at the path — an attacker's byte-identical copy included — would
    /// then satisfy the anchor and be accepted, leaving a committed action with
    /// no row, no refusal and no record anywhere but a log line. Anchoring the
    /// row that was owed puts the obligation in the one store filesystem access
    /// cannot rewind: every file at this path is short of the anchor by exactly
    /// that row, so every later open refuses until an operator runs
    /// `audit reanchor --acknowledge-rollback`, whose report shows one more
    /// anchored entry than the file holds and whose row records it permanently.
    ///
    /// Best-effort, like every other anchor write. If the keyring rejects it the
    /// refusal still stands for this writer and for every caller still holding
    /// it, but it does not survive the process — which is the state this exists
    /// to improve on, not one it can guarantee away.
    fn anchor_the_refused_row(&mut self, entry: &mut AuditEntry) {
        if entry.truncate_arg_keys_if_needed().is_err() {
            return;
        }
        entry.previous_entry_hash.clone_from(&self.last_hash);
        let Ok(hash) = compute_entry_hash_streamed(entry, &self.last_hash) else {
            return;
        };
        let Ok(json) = serde_json::to_vec(entry) else {
            return;
        };
        // The serialised row plus its newline: where the file would have ended
        // had the append been allowed to happen.
        let owed_end = self
            .end_offset
            .saturating_add(json.len() as u64)
            .saturating_add(1);
        let owed = TipAnchor::new(self.entry_count.saturating_add(1), hash, owed_end);
        self.store_tip_anchor_best_effort(&owed);
        self.owed_row_anchored = !self.anchor_behind;
    }

    /// Returns the byte offset just past the entry this writer has only now
    /// appended and fsynced.
    ///
    /// Read from the file rather than computed as "previous offset plus the
    /// bytes written". The writer's idea of where the previous entry ended can
    /// be short of where it actually ended: every reader in this subsystem
    /// tolerates blank lines between entries and at end of file, so a log that
    /// picked any up outside this writer has more bytes than the writer
    /// accounted for. An arithmetic offset then names a position inside an
    /// entry, and the next open reports a rollback on an untouched log.
    ///
    /// The file is opened `O_APPEND` and the writer holds the exclusive lock, so
    /// after `sync_data` the entry just written ends at end of file, which is
    /// also where the reader's replay ends: the entry is the last one and its
    /// trailing newline is the file's last byte.
    fn entry_end_offset(&self) -> Result<u64, WriterError> {
        Ok(self.file.metadata()?.len())
    }

    /// Re-writes the anchor for the writer's current state when an earlier
    /// write failed.
    ///
    /// A no-op when no write has failed, so the ordinary append pays nothing.
    fn retry_tip_anchor_if_behind(&mut self) {
        if !self.anchor_behind || self.entry_count == 0 {
            return;
        }
        let current = TipAnchor::new(self.entry_count, self.last_hash.clone(), self.end_offset);
        self.store_tip_anchor_best_effort(&current);
    }

    /// Appends the adoption row when reconciliation adopted a non-empty file.
    ///
    /// Non-fatal: the anchor is already in force, and refusing the acquisition
    /// because a forensic row could not be appended would take the log offline
    /// for a reason the anchor itself has already handled.
    fn emit_adoption_row_if_needed(&mut self, outcome: AnchorOutcome) {
        if outcome != AnchorOutcome::AdoptedExisting {
            return;
        }
        let entry_count = self.entry_count;
        if let Err(e) = self.write_entry(AuditEntry::new_audit_tip_anchored(
            TipAnchorReason::Adopted,
            entry_count,
            None,
            None,
            uuid::Uuid::new_v4().to_string(),
        )) {
            tracing::warn!(
                log = %basename_lossy_path(&self.path),
                error = %e,
                "audit tip anchor adopted but the adoption row could not be appended"
            );
        }
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

        let handoff_hash = self.append_rotation_handoff(&rotated_name)?;

        // Rename the HMAC sidecar before renaming the log file so both
        // renames are co-located in time.
        let active_hmac_sidecar = hmac_sidecar_path(&self.path);
        let rotated_hmac_sidecar = hmac_sidecar_path(&rotated_path);
        if active_hmac_sidecar.exists() {
            fs::rename(&active_hmac_sidecar, &rotated_hmac_sidecar)?;
        }

        self.finish_rotation(&rotated_path, &rotated_name, handoff_hash)
    }

    /// Appends the rotation handoff entry to the outgoing file and advances the
    /// anchor onto it.
    ///
    /// The first half of [`AuditWriter::rotate`], split out so a test can stop
    /// inside the rotation window and observe that the rollback guard is still
    /// armed there. Returns the handoff entry's hash, which the new file's first
    /// entry chains from.
    fn append_rotation_handoff(&mut self, rotated_name: &str) -> Result<String, WriterError> {
        // Write the rotation handoff entry to the current file.
        let mut handoff = AuditEntry::new_rotation_handoff(
            // NOTE: handoff names the *rotated* file — i.e. the archive file,
            // not the new active file.  `verify_log` uses this to locate the
            // archived file by name.  The name here must match the basename
            // of `rotated_path`.
            rotated_name,
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
        self.entry_count = self.entry_count.saturating_add(1);
        self.end_offset = self.entry_end_offset()?;

        // Advance the anchor onto the handoff entry — the outgoing file's true
        // tip — BEFORE the renames.
        //
        // Ordering is load-bearing, and the empty-file anchor is deliberately
        // NOT written here.  The empty-file anchor is offset 0, which is a
        // prefix of every file, so while it stands every file reads as
        // ahead-of-anchor and a rollback is absorbed instead of refused.
        // Writing it before the renames would leave that window open across the
        // whole rotation, with the path still holding the full outgoing file.
        // Holding the outgoing tip instead keeps the rollback guard armed
        // throughout, and the crash window it opens — the renames complete but
        // the new file's anchor write does not — is closed on the next open by
        // the rotation-completed rule in `reconcile_tip_anchor`, which
        // recognises an anchor naming exactly the newest archive's handoff.
        self.store_tip_anchor_best_effort(&TipAnchor::new(
            self.entry_count,
            handoff_hash.clone(),
            self.end_offset,
        ));
        Ok(handoff_hash)
    }

    /// Performs the renames, the prune, and the new-file create — the second
    /// half of [`AuditWriter::rotate`].
    fn finish_rotation(
        &mut self,
        rotated_path: &Path,
        rotated_name: &str,
        handoff_hash: String,
    ) -> Result<(), WriterError> {
        // Rename the current log file to the rotated name.
        fs::rename(&self.path, rotated_path)?;

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
        self.entry_count = 0;
        self.end_offset = 0;

        // The anchor is deliberately left naming the archive's handoff entry.
        // There is no anchor value for a file with no entries: offset 0 is a
        // prefix of every file, so such an anchor classifies every file at this
        // path as ahead of it and a directory-level restore would be absorbed
        // instead of refused.  Until this file's first append advances the
        // anchor, `reconcile_tip_anchor`'s rotation-completed rule carries every
        // open and pre-flight, and it proves the generation by hash.
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

// Test-only observation point fired once per rotation-window retry iteration,
// after the sidecar-lock probe and before the sleep + rescan, receiving the
// 0-based attempt index. It exists so in-crate tests can drive the transient
// active-file window deterministically on the scanning thread — restoring the
// file from inside the retry loop rather than racing an external restorer
// thread against the wall clock. Installed only via
// `install_rotation_window_retry_observer`, which returns an RAII guard that
// clears it on drop; a leaked observer would otherwise fire in an unrelated
// test when libtest runs on a single thread. The whole hook is compiled out of
// every non-test build.
#[cfg(test)]
type RotationWindowRetryObserver = Box<dyn FnMut(u32)>;

#[cfg(test)]
thread_local! {
    static ROTATION_WINDOW_RETRY_OBSERVER: std::cell::RefCell<Option<RotationWindowRetryObserver>> =
        const { std::cell::RefCell::new(None) };
}

/// RAII handle for the thread-local rotation-window retry observer. Clearing
/// the observer on drop is load-bearing, not hygiene: under
/// `cargo test -- --test-threads=1` libtest runs every test on one thread, so
/// an observer left installed past its test would fire in the next one.
#[cfg(test)]
pub(super) struct RotationWindowRetryObserverGuard;

#[cfg(test)]
impl Drop for RotationWindowRetryObserverGuard {
    fn drop(&mut self) {
        ROTATION_WINDOW_RETRY_OBSERVER.with(|cell| *cell.borrow_mut() = None);
    }
}

/// Installs `observer` as the thread-local rotation-window retry observer for
/// the current thread and returns a guard that uninstalls it on drop.
///
/// The observer runs on the scanning thread, once per retry iteration of
/// [`wait_out_transient_rotation_window`], with the 0-based attempt index. The
/// returned guard MUST be bound for the observed scope — dropping it
/// immediately uninstalls the observer before any scan can run.
///
/// One observer per thread-scope: the guard's drop CLEARS the slot rather
/// than restoring a previously installed observer, so installs do not nest.
/// The observer is invoked while the slot's `RefCell` is mutably borrowed —
/// an observer that re-enters a reader/verify scan (and thereby this wait)
/// panics with a `BorrowMutError` rather than recursing.
#[cfg(test)]
#[must_use = "the observer is uninstalled as soon as the returned guard drops; bind it for the observed scope"]
pub(super) fn install_rotation_window_retry_observer(
    observer: impl FnMut(u32) + 'static,
) -> RotationWindowRetryObserverGuard {
    ROTATION_WINDOW_RETRY_OBSERVER.with(|cell| *cell.borrow_mut() = Some(Box::new(observer)));
    RotationWindowRetryObserverGuard
}

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
    #[cfg(test)]
    let mut attempt: u32 = 0;
    // The `attempt` counter is a `#[cfg(test)]` companion to the production
    // range loop; it feeds only the test-only observer below, so clippy's
    // manual-counter lint applies to the test build alone.
    #[cfg_attr(test, allow(clippy::explicit_counter_loop))]
    for _ in 0..ROTATION_WINDOW_RETRY_ATTEMPTS {
        if !is_still_absent(&latest) {
            return Ok(latest);
        }
        if !sidecar_lock_is_held(log_path) {
            break;
        }
        // Test-only deterministic observation point; see
        // `install_rotation_window_retry_observer`. Placed after the lock probe
        // (so an unheld lock never reaches it) and before the sleep + rescan.
        // Compiled out entirely in shipped builds, leaving the loop above
        // byte-identical to production.
        #[cfg(test)]
        {
            ROTATION_WINDOW_RETRY_OBSERVER.with(|cell| {
                if let Some(observer) = cell.borrow_mut().as_mut() {
                    observer(attempt);
                }
            });
            attempt += 1;
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

/// The result of replaying a byte range of the active log file.
struct ChainScan {
    /// Entry hash of the last entry in the replayed range, or the seed hash
    /// when the range held no entries.
    last_hash: String,
    /// Number of entries in the replayed range.
    entry_count: u64,
    /// Byte offset just past the replayed range — the file length when the
    /// range ran to end of file.
    end_offset: u64,
}

impl ChainScan {
    /// The result of replaying an empty range.
    fn empty(seed: String) -> Self {
        Self {
            last_hash: seed,
            entry_count: 0,
            end_offset: 0,
        }
    }
}

/// Replays the log file from `start_offset`, verifying that each entry chains
/// off the previous one and that the first chains off `seed_hash`.
///
/// Reads through `read_until` rather than `BufRead::lines` so the byte offset
/// stays exact: the tip anchor records where the chain ends, and a line-based
/// reader cannot report that. Entry indices in
/// [`WriterError::ChainBrokenAtOpen`] count non-empty entries from the start of
/// the replayed range.
fn read_and_verify_entry_chain(
    file: &File,
    start_offset: u64,
    seed_hash: &str,
) -> Result<ChainScan, WriterError> {
    // Reuse the caller's already-open (and already-locked) handle rather than
    // opening a second one — see the module-level "Single-handle requirement
    // (Windows)" section.
    let mut cursor = file;
    cursor.seek(SeekFrom::Start(start_offset))?;
    let mut reader = BufReader::new(cursor);

    let mut expected_previous_hash = seed_hash.to_owned();
    let mut last_hash = seed_hash.to_owned();
    let mut entry_idx = 0usize;
    let mut consumed = start_offset;
    // Offset just past the last ENTRY, which is what the anchor records: bytes
    // after it that hold no entry (trailing blank lines) are not part of the
    // verified prefix.
    let mut end_offset = start_offset;
    let mut raw = Vec::new();

    loop {
        raw.clear();
        let read = reader.read_until(b'\n', &mut raw)?;
        if read == 0 {
            break;
        }
        consumed = consumed.saturating_add(read as u64);

        let line = strip_line_terminator(&raw);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }

        entry_idx += 1;
        let entry: AuditEntry = serde_json::from_slice(line).map_err(WriterError::Serialise)?;
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
        end_offset = consumed;
    }

    Ok(ChainScan {
        last_hash,
        entry_count: entry_idx as u64,
        end_offset,
    })
}

/// Returns the hash the active file's first entry must chain from.
///
/// [`ZERO_BLOCK_HASH`] for the very first file of a chain; the hash of the
/// newest rotated sibling's last entry — the rotation handoff — once the log has
/// rotated at least once. This is the writer-side counterpart of the cross-file
/// bridge `verify_log` validates when it walks from one file into the next.
///
/// Only the newest archive's LAST line is read, so the cost is one seek and one
/// entry hash rather than a walk of every retained archive.
///
/// # What this does and does not establish
///
/// The line is required to BE a rotation handoff naming this archive — the
/// shape [`AuditWriter::rotate`] always writes last, and the only shape whose
/// hash a following file legitimately chains from. Anything else is refused
/// with [`WriterError::RotationBridgeUnusable`] rather than silently used as a
/// seed, so a file dropped into the audit directory under a later timestamp
/// cannot redirect the bridge by looking vaguely like a log.
///
/// That check is structural, not cryptographic. It does not walk the archive's
/// chain and does not verify its root signature, so it establishes only that the
/// seed came from a well-formed handoff for this stem. The bridge's integrity is
/// established by `audit verify`, which walks every file, threads the tip from
/// one into the next, and requires each file's chain-root signature under the
/// profile's key. Open-time failure here is fail-closed: the writer refuses.
///
/// An archive with no readable last entry falls back to the zero block, so the
/// caller's replay reports the bridge failure against the active file's own
/// first entry, which is the more useful diagnostic.
pub(super) fn initial_chain_seed(log_path: &Path) -> Result<String, WriterError> {
    let chain = super::verify::collect_file_chain(log_path)?;
    // `collect_file_chain` returns rotated siblings oldest-first with the active
    // path last, so the newest archive is the second-to-last element.
    let Some(newest_archive) = chain.len().checked_sub(2).and_then(|idx| chain.get(idx)) else {
        return Ok(ZERO_BLOCK_HASH.to_owned());
    };
    let archive_name = basename_lossy_path(newest_archive);
    let file = match File::open(newest_archive) {
        Ok(file) => file,
        Err(_) => return Ok(ZERO_BLOCK_HASH.to_owned()),
    };
    let len = file.metadata()?.len();
    let Some(line) = read_last_line_before(&file, len)? else {
        return Ok(ZERO_BLOCK_HASH.to_owned());
    };
    let entry: AuditEntry =
        serde_json::from_slice(&line).map_err(|_| WriterError::RotationBridgeUnusable {
            archive_name: archive_name.clone(),
            reason: "the archive's last line is not a parseable audit entry",
        })?;
    match &entry.event_kind {
        super::schema::EventKind::AuditRotationHandoff { next_file_name }
            if *next_file_name == archive_name => {}
        super::schema::EventKind::AuditRotationHandoff { .. } => {
            return Err(WriterError::RotationBridgeUnusable {
                archive_name,
                reason: "the archive's handoff entry names a different archive",
            });
        }
        _ => {
            return Err(WriterError::RotationBridgeUnusable {
                archive_name,
                reason: "the archive does not end with a rotation handoff entry",
            });
        }
    }
    compute_entry_hash_streamed(&entry, &entry.previous_entry_hash)
}

/// Strips a trailing `\n`, and a `\r` before it, from a raw line.
fn strip_line_terminator(raw: &[u8]) -> &[u8] {
    let mut line = raw;
    if line.last() == Some(&b'\n') {
        line = &line[..line.len() - 1];
    }
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    line
}

/// Reads the last non-empty line that ends at or before `end_offset`.
///
/// Walks backward in 4 KiB windows so the common case touches only the tail of
/// the file, matching [`detect_partial_last_entry`]'s scan discipline: a single
/// audit entry may legally exceed one window, so the scan keeps accumulating
/// until it finds the newline that starts the last line, or reaches the file
/// start.
///
/// Returns `Ok(None)` when the range holds nothing but whitespace.
///
/// `pub(super)` so the verifier proves the anchored entry intact with the same
/// scan the writer uses, rather than a second implementation that could drift
/// from it.
pub(super) fn read_last_line_before(file: &File, end_offset: u64) -> io::Result<Option<Vec<u8>>> {
    const SCAN_CHUNK: u64 = 4096;

    let mut cursor = file;
    let file_len = cursor.metadata()?.len();
    let mut scan_end = std::cmp::min(end_offset, file_len);
    if scan_end == 0 {
        return Ok(None);
    }

    let mut buf: Vec<u8> = Vec::new();
    loop {
        let chunk_size = std::cmp::min(SCAN_CHUNK, scan_end);
        let chunk_start = scan_end - chunk_size;
        cursor.seek(SeekFrom::Start(chunk_start))?;
        let mut chunk = vec![
            0u8;
            usize::try_from(chunk_size)
                .map_err(|_| io::Error::other("audit log chunk size overflow"))?
        ];
        cursor.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&buf);
        buf = chunk;

        while buf.last().is_some_and(u8::is_ascii_whitespace) {
            buf.pop();
        }
        if buf.is_empty() {
            if chunk_start == 0 {
                return Ok(None);
            }
            scan_end = chunk_start;
            continue;
        }
        if let Some(idx) = buf.iter().rposition(|&byte| byte == b'\n') {
            return Ok(Some(strip_line_terminator(&buf[idx + 1..]).to_vec()));
        }
        if chunk_start == 0 {
            return Ok(Some(strip_line_terminator(&buf).to_vec()));
        }
        scan_end = chunk_start;
    }
}

/// Reads and parses the first entry of the active file through the writer's own
/// handle.
fn read_first_entry_of(file: &File) -> Result<AuditEntry, WriterError> {
    let mut cursor = file;
    cursor.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(cursor);
    let mut raw = Vec::new();
    loop {
        raw.clear();
        let read = reader.read_until(b'\n', &mut raw)?;
        if read == 0 {
            return Err(WriterError::Io(io::Error::other(
                "audit log has no first entry to verify the chain root against",
            )));
        }
        let line = strip_line_terminator(&raw);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        return serde_json::from_slice(line).map_err(WriterError::Serialise);
    }
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
    /// `~/.local/share/stellar-agent/audit/default.jsonl`.
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

    /// The active log file no longer contains the anchored chain tip.
    ///
    /// The keyring-held anchor names an entry count, a tip hash, and a byte
    /// offset for this log PATH. This variant means the file at that path is
    /// shorter than the anchor, or the entry ending at the anchored offset is
    /// not the anchored entry: the file was rolled back to an older copy,
    /// truncated, or replaced.
    ///
    /// No digest appears in the message. Counts and offsets are enough to tell
    /// an operator how far the file moved, and repeating a chain hash in a
    /// refusal only widens where it can be observed.
    ///
    /// Wire code: `audit.tip_anchor_mismatch`. Recovery:
    /// `stellar-agent audit reanchor --profile <name> --acknowledge-rollback`
    /// after establishing why the file changed. See
    /// `docs/maintainers/audit-log-recovery.md`.
    #[error(
        "audit.tip_anchor_mismatch: {reason}; anchored at {expected_count} entries / \
         {expected_offset} bytes, file is {actual_len} bytes"
    )]
    TipAnchorMismatch {
        /// Entry count the anchor names.
        expected_count: u64,
        /// Byte offset the anchor names.
        expected_offset: u64,
        /// Current length of the log file.
        actual_len: u64,
        /// Stable diagnostic for which half of the check failed.
        reason: &'static str,
    },

    /// The tip anchor could not be read from, or written to, its backing store.
    ///
    /// The anchor lives in the platform keyring. An unreadable anchor cannot be
    /// distinguished from a rolled-back one, so every caller that requires the
    /// anchor treats this as fail-closed.
    #[error("audit log tip anchor unavailable: {0}")]
    TipAnchorStore(#[from] TipAnchorStoreError),

    /// A tip-anchor operation was requested on a writer that has no anchor
    /// store attached.
    ///
    /// Produced only by [`AuditWriter::reanchor`], whose caller is expected to
    /// have opened the writer through [`AuditWriter::open_for_reanchor`].
    #[error("audit log tip anchor repair requested on a writer with no anchor store")]
    TipAnchorUnavailable,

    /// The newest rotated archive cannot supply the cross-file chain seed.
    ///
    /// A file created by a rotation chains its first entry off the outgoing
    /// file's rotation-handoff entry, so opening the active file means reading
    /// that handoff out of the newest archive. This variant means the archive's
    /// last entry is not a handoff naming that archive: the file was truncated
    /// mid-entry, or something that is not a rotated sibling of this log was
    /// placed in the audit directory under a rotated sibling's name.
    ///
    /// Fail-closed: the writer refuses rather than seeding the replay from an
    /// unverified hash. Recovery is to move the offending file out of the audit
    /// directory; see `docs/maintainers/audit-log-recovery.md`.
    #[error("audit.rotation_bridge_unusable: {reason} (archive {archive_name})")]
    RotationBridgeUnusable {
        /// Basename of the archive that cannot supply the seed.
        archive_name: String,
        /// Stable diagnostic for which structural check failed.
        reason: &'static str,
    },
}

/// Returns the condition an audit-writer acquisition failure describes, led by
/// its `audit.*` sub-code, for callers that surface it to an operator.
///
/// `None` means the failure is a registry path or key registration conflict,
/// which the caller's own "writer open failed" wording already covers. Every
/// other variant names a condition about the LOG, whose remedy is neither
/// minting a key nor resolving a registration, so the caller must not tell the
/// operator to do either.
///
/// The sub-codes are the ones already documented for these conditions; the
/// detail-carried convention matches `approval.writer_locked`.
#[must_use]
pub fn audit_log_unusable_detail(e: &WriterError) -> Option<String> {
    match e {
        WriterError::FileLocked => Some(
            "audit.writer_locked: the audit log's writer lock is held by another process; \
             stop the running stellar-agent-mcp server and retry"
                .to_owned(),
        ),
        // These carry their own `audit.*` code at the head of their Display.
        WriterError::RotationBridgeUnusable { .. } | WriterError::IntegrityViolation(_) => {
            Some(e.to_string())
        }
        WriterError::ChainBrokenAtOpen { entry_idx, .. } => Some(format!(
            "audit.chain_broken: the log's own hash chain is broken at entry {entry_idx}; \
             the file was modified outside the writer"
        )),
        WriterError::TipAnchorStore(detail) => Some(format!(
            "audit.tip_anchor_unavailable: the tip anchor could not be read or written \
             ({detail}); the keyring must be reachable before a value-moving verb can prove \
             the log has not been rolled back"
        )),
        WriterError::PathContract { detail } => Some(format!("audit.path_contract: {detail}")),
        WriterError::Io(err) => Some(format!(
            "audit.io_error: the audit log could not be read or written ({})",
            err.kind()
        )),
        WriterError::Serialise(_) | WriterError::Hash(_) => Some(
            "audit.parse_error: the audit log could not be parsed or hashed; the file was \
             modified outside the writer"
                .to_owned(),
        ),
        WriterError::PartialRotation { .. } => Some(
            "audit.partial_rotation: the audit directory holds evidence of a crash \
             mid-rotation and needs operator inspection"
                .to_owned(),
        ),
        WriterError::TipAnchorUnavailable => None,
        WriterError::TipAnchorMismatch { .. }
        | WriterError::PathMismatch { .. }
        | WriterError::HmacKeyMismatch { .. } => None,
    }
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
                        "orphan sidecar detected — see docs/maintainers/audit-log-recovery.md §2.1. \
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
                "tmp file found — see docs/maintainers/audit-log-recovery.md §2.2. \
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
            "truncated entry detected — see docs/maintainers/audit-log-recovery.md §2.3. \
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
    /// Set when the log at `log_path` was found replaced underneath `handle`.
    ///
    /// The entry stays in the map as a tombstone rather than being removed
    /// outright, because the evicted writer keeps the sidecar lock until its
    /// last holder drops it: opening the path in that window answers
    /// [`WriterError::FileLocked`], whose remedy is to stop a server that is
    /// this one. While a holder remains, the tombstone answers the replacement
    /// instead; once it is the only holder left, it is dropped and the next
    /// acquisition opens the file at the path.
    evicted: Option<EvictedWriter>,
}

/// What a tombstoned [`RegistryEntry`] answers with.
///
/// Carries the anchor coordinates the refusal was made against; the length is
/// read fresh, since the file at the path can keep changing while a holder
/// keeps the evicted writer alive.
struct EvictedWriter {
    /// Entry count the anchor named when the replacement was found.
    expected_count: u64,
    /// Byte offset the anchor named when the replacement was found.
    expected_offset: u64,
}

impl EvictedWriter {
    /// Rebuilds the replaced-underneath refusal for `log_path`.
    fn refusal(&self, log_path: &Path) -> WriterError {
        WriterError::TipAnchorMismatch {
            expected_count: self.expected_count,
            expected_offset: self.expected_offset,
            actual_len: fs::metadata(log_path).map(|m| m.len()).unwrap_or(0),
            reason: LOG_REPLACED_REASON,
        }
    }
}

/// The process-global backing store.
static REGISTRY: OnceLock<Mutex<HashMap<String, RegistryEntry>>> = OnceLock::new();

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
    /// `~/.local/share/stellar-agent/audit/default.jsonl`).  The profile name
    /// is used only as the registry cache key; path construction — including
    /// any sanitisation of the profile name into a safe file-stem — is the
    /// caller's responsibility.  See
    /// `stellar_agent_core::profile::schema::default_audit_log_path_for` for
    /// the canonical path derivation.
    ///
    /// A keyed writer is opened through
    /// [`AuditWriterRegistry::get_or_open_keyed`] instead: a key without an
    /// anchor store would write rows the anchor never covers.
    ///
    /// # Errors
    ///
    /// - [`WriterError::FileLocked`] if another *process* holds the exclusive
    ///   advisory lock on the log file.  (Within a process, the registry
    ///   prevents this by reusing the same handle.)
    /// - [`WriterError::PathMismatch`] if a subsequent caller supplies a
    ///   different `log_path` for the same `profile_name`.
    /// - [`WriterError::HmacKeyMismatch`] if a subsequent caller presents a key
    ///   for the same `profile_name` this writer was not opened with.
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
    pub fn get_or_open_unkeyed(
        profile_name: &str,
        log_path: &Path,
    ) -> Result<Arc<Mutex<AuditWriter>>, WriterError> {
        Self::get_or_open_inner(profile_name, log_path, None).map(|(handle, _opened)| handle)
    }

    /// Returns the shared writer for `profile_name`, opened KEYED and bound to
    /// the anchor store `access` carries.
    ///
    /// # The anchor is reconciled on EVERY call
    ///
    /// A cache hit is reconciled before the handle is returned; a cache miss is
    /// reconciled by [`AuditWriter::open`] and is not checked twice, since the
    /// open just proved it. The check belongs here rather than in each caller
    /// because the registry is the only way a keyed writer is reached: a caller
    /// that forgot the check would append to a log this process has not proved
    /// still contains the tip it anchored, and the row that proves an
    /// authorization would be the row a rollback silently swallowed.
    ///
    /// A refusal naming a log replaced underneath the writer's own handle also
    /// evicts the cached entry, because no re-check can bring that writer back
    /// into agreement — the file it holds is not the file at the path any more.
    /// The entry becomes a tombstone that answers the replacement until every
    /// holder has dropped the writer, at which point the next acquisition opens
    /// the file now at the path and checks THAT file against the anchor: an
    /// older copy refuses, the same file put back is accepted.
    ///
    /// # Errors
    ///
    /// Everything [`AuditWriterRegistry::get_or_open_unkeyed`] returns, plus the
    /// tip-anchor failures of [`AuditWriter::open_with_tip_anchor`] and of
    /// [`AuditWriter::verify_tip_anchor`].
    pub fn get_or_open_keyed(
        profile_name: &str,
        log_path: &Path,
        access: KeyedAuditAccess,
    ) -> Result<Arc<Mutex<AuditWriter>>, WriterError> {
        let (handle, opened) = Self::get_or_open_inner(profile_name, log_path, Some(access))?;
        if opened {
            return Ok(handle);
        }
        if let Err(e) = reconcile_cached_tip_anchor(&handle) {
            if let WriterError::TipAnchorMismatch {
                expected_count,
                expected_offset,
                reason,
                ..
            } = &e
                && *reason == LOG_REPLACED_REASON
            {
                Self::evict(
                    profile_name,
                    EvictedWriter {
                        expected_count: *expected_count,
                        expected_offset: *expected_offset,
                    },
                );
            }
            return Err(e);
        }
        Ok(handle)
    }

    /// Marks the cached entry for `profile_name` as evicted.
    ///
    /// The entry is kept rather than removed: its writer still holds the sidecar
    /// lock for as long as any caller references it, and a fresh open in that
    /// window would answer [`WriterError::FileLocked`] and tell the operator to
    /// stop a server that is the one asking. The tombstone answers the
    /// replacement until the writer is unreferenced. A poisoned or uninitialised
    /// registry is left alone — the acquisition is refused either way, and this
    /// is the recovery path, not the guard.
    fn evict(profile_name: &str, evicted: EvictedWriter) {
        let Some(registry) = REGISTRY.get() else {
            return;
        };
        let Ok(mut map) = registry.lock() else {
            return;
        };
        if let Some(entry) = map.get_mut(profile_name) {
            entry.evicted = Some(evicted);
        }
    }

    /// Returns the cached writer for `profile_name`, opening it on a miss, and
    /// says which of the two happened.
    ///
    /// `true` means this call opened the writer, so the anchor was reconciled by
    /// the open and the caller need not repeat it.
    ///
    /// `access` carries the chain-root key and the anchor store together or
    /// neither: it is the same value the public entry points take, threaded
    /// through unsplit so the key-with-no-anchor shape has no expression here
    /// either.
    fn get_or_open_inner(
        profile_name: &str,
        log_path: &Path,
        access: Option<KeyedAuditAccess>,
    ) -> Result<(Arc<Mutex<AuditWriter>>, bool), WriterError> {
        let incoming_fingerprint = access.as_ref().map(KeyedAuditAccess::key_fingerprint);

        // ── Phase 1: cache lookup under lock ────────────────────────────────
        let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
        {
            let mut map = registry.lock().map_err(|_| {
                WriterError::Io(io::Error::other(
                    "audit writer registry mutex poisoned; cannot open writer",
                ))
            })?;

            let mut drop_tombstone = false;
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
                match entry.evicted.as_ref() {
                    // A holder still references the evicted writer, so the
                    // sidecar lock is still held and opening the path would
                    // report the wrong condition. Answer the replacement.
                    Some(evicted) if Arc::strong_count(&entry.handle) > 1 => {
                        let refusal = evicted.refusal(log_path);
                        drop(map);
                        return Err(refusal);
                    }
                    // The tombstone is the last holder; drop it so the open
                    // below gets the lock.
                    Some(_) => drop_tombstone = true,
                    None => {
                        let handle = Arc::clone(&entry.handle);
                        drop(map);
                        return Ok((handle, false));
                    }
                }
            }
            if drop_tombstone {
                map.remove(profile_name);
            }
            // Cache miss — release the lock before doing I/O.
        }

        // ── Phase 2: open writer outside the lock ───────────────────────────
        // Perform the I/O (directory creation, advisory lock, chain recovery)
        // without holding the registry lock so concurrent opens for different
        // profiles do not serialise behind each other's I/O.
        let handle = Arc::new(Mutex::new(AuditWriter::open(
            log_path.to_path_buf(),
            access,
        )?));

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
            // A tombstone left by a concurrent eviction is superseded: this
            // open took the sidecar lock, which proves the evicted writer is
            // gone. Anything else is a live winner, and our freshly-opened
            // writer is dropped here, releasing the advisory lock we held as
            // the race loser.
            if entry.evicted.is_none() {
                let winner = Arc::clone(&entry.handle);
                drop(map);
                drop(handle);
                return Ok((winner, false));
            }
        }

        // We are the first (or the only) opener for this profile — insert.
        map.insert(
            profile_name.to_owned(),
            RegistryEntry {
                log_path: log_path.to_path_buf(),
                hmac_key_fingerprint: incoming_fingerprint,
                handle: Arc::clone(&handle),
                evicted: None,
            },
        );
        Ok((handle, true))
    }
}

/// Runs the anchor check on a writer the registry is about to hand out.
///
/// A poisoned writer mutex is surfaced as an I/O error rather than unwound, the
/// same discipline [`AuditWriterRegistry::get_or_open_keyed`] applies to the
/// registry mutex, and it is fail-closed for the same reason: a writer whose
/// state cannot be read is a writer whose log cannot be proved current.
fn reconcile_cached_tip_anchor(handle: &Arc<Mutex<AuditWriter>>) -> Result<(), WriterError> {
    let mut writer = handle.lock().map_err(|_| {
        WriterError::Io(io::Error::other(
            "audit writer mutex poisoned; cannot reconcile the tip anchor",
        ))
    })?;
    writer.verify_tip_anchor()
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
        let mut writer = AuditWriter::open_keyed_unanchored_for_test(path.clone(), key).unwrap();
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
        let mut writer =
            AuditWriter::open_keyed_unanchored_for_test(path.clone(), Zeroizing::new(key)).unwrap();
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

        let reopened =
            AuditWriter::open_keyed_unanchored_for_test(path, Zeroizing::new(key)).unwrap();
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

    // ── wait_out_transient_rotation_window: closure semantics ─────────────────

    /// A present file (`is_still_absent` reports false on the first check)
    /// returns immediately without probing the lock or rescanning.
    #[test]
    fn wait_out_rotation_window_returns_immediately_when_not_absent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut rescan_calls = 0u32;
        let out: Result<u32, std::convert::Infallible> = wait_out_transient_rotation_window(
            &path,
            7u32,
            |_latest: &u32| false,
            || {
                rescan_calls += 1;
                Ok(7u32)
            },
        );

        assert_eq!(out.unwrap(), 7);
        assert_eq!(
            rescan_calls, 0,
            "a present file must not trigger any rescan"
        );
    }

    /// An unheld sidecar lock (no live writer) means the absence is not a live
    /// rotation, so the loop gives up on its first iteration: it returns the
    /// latest scan unchanged and never rescans. This is the give-up posture the
    /// `sidecar_lock_is_held` break enforces.
    #[test]
    fn wait_out_rotation_window_gives_up_immediately_when_lock_unheld() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut rescan_calls = 0u32;
        let out: Result<u32, std::convert::Infallible> = wait_out_transient_rotation_window(
            &path,
            1u32,
            |_latest: &u32| true,
            || {
                rescan_calls += 1;
                Ok(2u32)
            },
        );

        assert_eq!(out.unwrap(), 1, "the latest scan is returned unchanged");
        assert_eq!(
            rescan_calls, 0,
            "an unheld lock must not trigger any rescan"
        );
    }

    /// A rescan error propagates through the primitive's `?`. The sidecar lock
    /// is held so the loop reaches the rescan call rather than giving up first.
    #[test]
    fn wait_out_rotation_window_propagates_rescan_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let _held =
            crate::audit_log::lock::AuditWriterLock::acquire(&lock_sidecar_path(&path)).unwrap();

        let out: Result<u32, &'static str> = wait_out_transient_rotation_window(
            &path,
            0u32,
            |_latest: &u32| true,
            || Err("rescan failed"),
        );

        assert_eq!(out, Err("rescan failed"));
    }

    /// When the file reappears before the retry bound is exhausted, the loop
    /// returns the reappeared scan at that iteration and does not run the full
    /// bound. The sidecar lock is held so each iteration proceeds to a rescan.
    #[test]
    fn wait_out_rotation_window_stops_when_scan_reappears_before_bound() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let _held =
            crate::audit_log::lock::AuditWriterLock::acquire(&lock_sidecar_path(&path)).unwrap();

        let mut rescan_calls = 0u32;
        let out: Result<u32, std::convert::Infallible> = wait_out_transient_rotation_window(
            &path,
            0u32,
            |latest: &u32| *latest == 0,
            || {
                rescan_calls += 1;
                Ok(if rescan_calls >= 3 { 1u32 } else { 0u32 })
            },
        );

        assert_eq!(out.unwrap(), 1, "the reappeared scan result is returned");
        assert_eq!(
            rescan_calls, 3,
            "must stop at the reappearing rescan, not exhaust the bound"
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
        let mut writer = AuditWriter::open_keyed_unanchored_for_test(path.clone(), key).unwrap();

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
        let a = AuditWriterRegistry::get_or_open_unkeyed(&profile, &log_path).unwrap();
        let b = AuditWriterRegistry::get_or_open_unkeyed(&profile, &log_path).unwrap();
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
        let a = AuditWriterRegistry::get_or_open_unkeyed(&p1, &path1).unwrap();
        let b = AuditWriterRegistry::get_or_open_unkeyed(&p2, &path2).unwrap();
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
                    if let Ok(arc) = AuditWriterRegistry::get_or_open_unkeyed(&profile, &log_path) {
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
        let first = AuditWriterRegistry::get_or_open_unkeyed(&profile, &log_path).unwrap();
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
                    AuditWriterRegistry::get_or_open_unkeyed(&profile, &log_path).unwrap()
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
        let result = AuditWriterRegistry::get_or_open_unkeyed(&profile, &log_path);
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
        let _a = AuditWriterRegistry::get_or_open_unkeyed(&profile, &path1).unwrap();

        // Second open with a different path must return PathMismatch.
        let result = AuditWriterRegistry::get_or_open_unkeyed(&profile, &path2);
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
        let _a =
            AuditWriterRegistry::get_or_open_keyed(&profile, &log_path, test_keyed_access(key_a))
                .unwrap();

        // Second open with key_b must return HmacKeyMismatch.
        let result =
            AuditWriterRegistry::get_or_open_keyed(&profile, &log_path, test_keyed_access(key_b));
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
        let _a =
            AuditWriterRegistry::get_or_open_keyed(&profile, &log_path, test_keyed_access(key))
                .unwrap();

        // Second open with no key must return HmacKeyMismatch.
        let result = AuditWriterRegistry::get_or_open_unkeyed(&profile, &log_path);
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

    // ── Tip anchor ───────────────────────────────────────────────────────────

    use crate::audit_log::tip_anchor::InMemoryTipAnchorStore;

    /// Pairs a test key with a throwaway in-memory anchor store, so a keyed
    /// registry open in a test carries a handle exactly as production does.
    fn test_keyed_access(key: Zeroizing<[u8; 32]>) -> KeyedAuditAccess {
        KeyedAuditAccess::new(
            key,
            Arc::new(InMemoryTipAnchorStore::new()) as Arc<dyn TipAnchorStore>,
        )
    }

    /// Opens an anchored writer over a shared in-memory store.
    fn open_anchored(
        path: &Path,
        store: &Arc<InMemoryTipAnchorStore>,
    ) -> Result<AuditWriter, WriterError> {
        AuditWriter::open_with_tip_anchor(
            path.to_path_buf(),
            None,
            Arc::clone(store) as Arc<dyn TipAnchorStore>,
        )
    }

    /// Reads back the anchor as the string the keyring would hold, so the
    /// assertions pin the stored VALUE rather than an in-memory struct the
    /// writer could have left stale.
    fn stored_value(store: &Arc<InMemoryTipAnchorStore>) -> String {
        store
            .peek()
            .expect("an anchor must be stored")
            .to_keyring_value()
    }

    /// The anchor that describes `path` exactly as it stands on disk.
    ///
    /// Computed independently of the writer's own replay — it counts lines and
    /// hashes the last one — so it is an oracle rather than a restatement of
    /// the code under test, and it holds for a rotation-created file whose
    /// chain seeds from the handoff hash rather than the zero block.
    fn tip_of(path: &Path) -> TipAnchor {
        let content = fs::read(path).unwrap();
        let mut entry_count = 0u64;
        let mut end_offset = 0u64;
        let mut last_line: Option<Vec<u8>> = None;
        let mut consumed = 0u64;
        for raw in content.split_inclusive(|&b| b == b'\n') {
            consumed += raw.len() as u64;
            let line = strip_line_terminator(raw);
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            entry_count += 1;
            end_offset = consumed;
            last_line = Some(line.to_vec());
        }
        match last_line {
            None => panic!("tip_of called on a file with no entries"),
            Some(line) => {
                let entry: AuditEntry = serde_json::from_slice(&line).unwrap();
                let hash = compute_entry_hash_streamed(&entry, &entry.previous_entry_hash).unwrap();
                TipAnchor::new(entry_count, hash, end_offset)
            }
        }
    }

    /// Counts `audit_tip_anchored` rows carrying `reason` in the log at `path`.
    fn count_tip_anchored_rows(path: &Path, reason: &str) -> usize {
        let content = fs::read_to_string(path).unwrap();
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter(|line| {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                value["kind"] == "audit_tip_anchored" && value["reason"] == reason
            })
            .count()
    }

    #[test]
    fn append_advances_the_anchor_to_the_new_tip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let mut writer = open_anchored(&path, &store).unwrap();
        assert!(
            store.peek().is_none(),
            "an empty log is left unanchored: there is no entry to name"
        );

        for expected_count in 1..=3u64 {
            writer.write_entry(make_entry("")).unwrap();
            let anchor = store.peek().unwrap();
            assert_eq!(
                anchor.entry_count, expected_count,
                "the anchor must count every appended entry"
            );
            assert_eq!(
                stored_value(&store),
                tip_of(&path).to_keyring_value(),
                "the stored anchor value must name the file's current tip"
            );
        }
        drop(writer);

        assert_eq!(
            stored_value(&store),
            tip_of(&path).to_keyring_value(),
            "the anchor survives the writer"
        );
    }

    #[test]
    fn reopen_absorbs_appends_made_without_the_anchor() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }
        let anchored_after_first = store.peek().unwrap();

        // An unanchored writer appends two entries; the anchor does not move.
        {
            let mut writer = open_no_key(path.clone());
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }
        assert_eq!(
            store.peek().unwrap(),
            anchored_after_first,
            "an unanchored writer must not move the anchor"
        );

        // The next anchored open absorbs them and re-anchors on the new tip.
        let writer = open_anchored(&path, &store).unwrap();
        drop(writer);
        assert_eq!(
            stored_value(&store),
            tip_of(&path).to_keyring_value(),
            "reopening must re-anchor on the tip the unkeyed appends left"
        );
        assert_eq!(store.peek().unwrap().entry_count, 3);
        assert_eq!(
            count_tip_anchored_rows(&path, "adopted"),
            0,
            "absorbing appends ahead of the anchor is not an adoption"
        );
    }

    #[test]
    fn crash_between_entry_fsync_and_anchor_write_self_heals_on_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let anchor_before = {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            let anchor_before = store.peek().unwrap();

            // The crash window: the entry is appended and fsynced, the anchor
            // write never happens.
            writer.set_skip_tip_anchor_write(true);
            writer.write_entry(make_entry("")).unwrap();
            anchor_before
        };
        assert_eq!(
            store.peek().unwrap(),
            anchor_before,
            "the failpoint must leave the anchor one entry behind the file"
        );
        assert_eq!(tip_of(&path).entry_count, 2, "the entry is on disk");

        let writer = open_anchored(&path, &store).unwrap();
        drop(writer);
        assert_eq!(
            stored_value(&store),
            tip_of(&path).to_keyring_value(),
            "reopening must advance the anchor onto the fsynced entry"
        );
    }

    #[test]
    fn truncating_one_entry_refuses_with_a_tip_anchor_mismatch() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let truncate_to = {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            let after_two = store.peek().unwrap();
            writer.write_entry(make_entry("")).unwrap();
            after_two.end_offset
        };
        let anchored = store.peek().unwrap();
        assert_eq!(anchored.entry_count, 3);

        // Drop the last entry, leaving a log whose chain and root signature are
        // both still intact — exactly what the anchor exists to catch.
        let content = fs::read(&path).unwrap();
        fs::write(&path, &content[..truncate_to as usize]).unwrap();
        assert!(
            verify_log_is_clean(&path),
            "the truncated log must still pass the chain walk"
        );

        let err = open_anchored(&path, &store).unwrap_err();
        assert!(
            matches!(
                err,
                WriterError::TipAnchorMismatch {
                    expected_count: 3,
                    actual_len,
                    ..
                } if actual_len == truncate_to
            ),
            "expected a tip-anchor mismatch naming the anchored count, got {err:?}"
        );
        assert_eq!(
            store.peek().unwrap(),
            anchored,
            "a refusal must not move the anchor"
        );
    }

    #[test]
    fn restoring_an_older_copy_refuses() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let older_copy = {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            let snapshot = fs::read(&path).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            snapshot
        };

        fs::write(&path, &older_copy).unwrap();
        assert!(
            verify_log_is_clean(&path),
            "the restored copy must still pass the chain walk"
        );

        let err = open_anchored(&path, &store).unwrap_err();
        assert!(
            matches!(
                err,
                WriterError::TipAnchorMismatch {
                    expected_count: 4,
                    ..
                }
            ),
            "expected a tip-anchor mismatch against the four-entry anchor, got {err:?}"
        );
    }

    #[test]
    fn rotation_anchors_the_new_file_then_its_first_entry() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        writer.force_rotate_for_test().unwrap();

        let archive_handoff = tip_of(&newest_archive(&path));
        assert_eq!(
            store.peek().unwrap(),
            archive_handoff,
            "rotation leaves the anchor on the outgoing file's handoff, never on \
             an empty-file value that would classify every file as ahead"
        );

        writer.write_entry(make_entry("")).unwrap();
        let anchor = store.peek().unwrap();
        assert_eq!(
            anchor.entry_count, 1,
            "the anchor names the NEW file's first entry, not the archive's tip"
        );
        assert_eq!(stored_value(&store), tip_of(&path).to_keyring_value());
        drop(writer);

        // Reopening the rotation-created active file must not read as a
        // rollback: its chain seed is the handoff hash, not the zero block.
        let writer = open_anchored(&path, &store).unwrap();
        drop(writer);
        assert_eq!(stored_value(&store), tip_of(&path).to_keyring_value());
    }

    #[test]
    fn reopening_an_empty_rotation_created_file_is_not_a_rollback() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.force_rotate_for_test().unwrap();
        }
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);

        let mut writer =
            open_anchored(&path, &store).expect("an empty post-rotation file must open cleanly");
        writer.write_entry(make_entry("")).unwrap();
        assert_eq!(store.peek().unwrap().entry_count, 1);
    }

    #[test]
    fn a_log_with_no_anchor_is_adopted_and_records_the_adoption() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");

        // A log written with no anchor at all — the state every profile is in
        // before the anchor exists.
        {
            let mut writer = open_no_key(path.clone());
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }
        let tip_before_adoption = tip_of(&path);

        let store = Arc::new(InMemoryTipAnchorStore::new());
        let writer = open_anchored(&path, &store).expect("adoption needs no operator action");
        drop(writer);

        assert_eq!(
            count_tip_anchored_rows(&path, "adopted"),
            1,
            "adoption must leave exactly one adopted row in the log"
        );
        let anchor = store.peek().unwrap();
        assert_eq!(
            anchor.entry_count,
            tip_before_adoption.entry_count + 1,
            "the adoption row itself advances the anchor"
        );
        assert_eq!(stored_value(&store), tip_of(&path).to_keyring_value());
    }

    #[test]
    fn an_anchored_open_refuses_a_broken_chain_instead_of_adopting_it() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");

        {
            let mut writer = open_no_key(path.clone());
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }
        // Break the second entry's link to the first.
        let content = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_owned).collect();
        lines[1] = lines[1].replace(
            "\"previous_entry_hash\":\"sha256:",
            "\"previous_entry_hash\":\"sha256:0",
        );
        let corrupted = format!("{}\n", lines.join("\n"));
        fs::write(&path, corrupted).unwrap();

        let store = Arc::new(InMemoryTipAnchorStore::new());
        let err = open_anchored(&path, &store).unwrap_err();
        assert!(
            matches!(err, WriterError::ChainBrokenAtOpen { .. }),
            "a broken chain must be refused, not adopted: {err:?}"
        );
        assert!(
            store.peek().is_none(),
            "a refused adoption must not write an anchor"
        );
    }

    #[test]
    fn a_replaced_file_is_refused_on_the_next_acquisition_of_a_live_writer() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        let snapshot = fs::read(&path).unwrap();
        writer.write_entry(make_entry("")).unwrap();

        writer
            .verify_tip_anchor()
            .expect("an untouched file passes the per-acquisition check");

        // Replace the file underneath the live writer with an older copy.
        fs::write(&path, &snapshot).unwrap();

        let err = writer.verify_tip_anchor().unwrap_err();
        assert!(
            matches!(
                err,
                WriterError::TipAnchorMismatch {
                    expected_count: 3,
                    ..
                }
            ),
            "the per-acquisition check must catch a file replaced underneath a \
             live writer: {err:?}"
        );
    }

    #[test]
    fn reanchor_recovers_a_refused_log_and_records_the_repair() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let snapshot = {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            let snapshot = fs::read(&path).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            snapshot
        };
        let superseded = store.peek().unwrap();
        fs::write(&path, &snapshot).unwrap();
        assert!(
            open_anchored(&path, &store).is_err(),
            "the rolled-back log must refuse before the repair"
        );
        assert_eq!(store.reanchor_count().unwrap(), None);

        let report = {
            let mut writer = AuditWriter::open_for_reanchor(
                path.clone(),
                None,
                Arc::clone(&store) as Arc<dyn TipAnchorStore>,
            )
            .expect("repair opens a log an ordinary open refuses");
            writer.reanchor().expect("repair must succeed")
        };

        assert_eq!(report.previous, StoredTipAnchor::Usable(superseded.clone()));
        assert_eq!(report.reanchor_count, 1);
        assert_eq!(store.reanchor_count().unwrap(), Some(1));
        assert_eq!(
            count_tip_anchored_rows(&path, "rollback_acknowledged"),
            1,
            "the repair must leave a permanent record in the log"
        );
        assert_eq!(
            stored_value(&store),
            tip_of(&path).to_keyring_value(),
            "the repair row itself advances the anchor"
        );

        open_anchored(&path, &store).expect("the repaired log must open cleanly");
    }

    #[test]
    fn reanchor_refuses_a_log_whose_chain_is_broken() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }
        let content = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_owned).collect();
        lines[1] = lines[1].replace(
            "\"previous_entry_hash\":\"sha256:",
            "\"previous_entry_hash\":\"sha256:0",
        );
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        // Repair skips the ANCHOR check, never the chain replay: a log whose own
        // linkage is broken has no tip worth anchoring, so it is refused before
        // the repair path is reachable at all.
        let err = AuditWriter::open_for_reanchor(
            path.clone(),
            None,
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        )
        .unwrap_err();
        assert!(
            matches!(err, WriterError::ChainBrokenAtOpen { .. }),
            "repair must not bless a log whose own chain is broken: {err:?}"
        );
        assert_eq!(
            store.reanchor_count().unwrap(),
            None,
            "a refused repair must not touch the counter"
        );
    }

    #[test]
    fn adoption_refuses_a_chain_root_signed_by_another_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let one = Zeroizing::new([7u8; 32]);
        let other = Zeroizing::new([9u8; 32]);

        // A log whose chain root is signed under one key.
        {
            let mut writer =
                AuditWriter::open_keyed_unanchored_for_test(path.clone(), one).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }

        // Adoption under a different key must refuse: a log whose root signature
        // does not verify is not a log worth taking under anchor protection.
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let err = AuditWriter::open_with_tip_anchor(
            path.clone(),
            Some(other.clone()),
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                WriterError::IntegrityViolation(
                    super::super::verify::VerifyError::HmacMismatch { .. }
                )
            ),
            "adoption must refuse a chain root signed by another key: {err:?}"
        );
        assert!(
            store.peek().is_none(),
            "a refused adoption must not write an anchor"
        );
    }

    #[test]
    fn adoption_accepts_a_log_with_no_chain_root_sidecar() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");

        // A log written entirely by unkeyed writers has no `.root_hmac`
        // sidecar. Minting an audit key later must not be a one-way door.
        {
            let mut writer = open_no_key(path.clone());
            writer.write_entry(make_entry("")).unwrap();
        }
        assert!(!hmac_sidecar_path(&path).exists());

        let store = Arc::new(InMemoryTipAnchorStore::new());
        let writer = AuditWriter::open_with_tip_anchor(
            path.clone(),
            Some(Zeroizing::new([3u8; 32])),
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        )
        .expect("a sidecar-less log must still adopt");
        drop(writer);
        assert_eq!(count_tip_anchored_rows(&path, "adopted"), 1);
    }

    #[test]
    fn repair_replaces_a_stored_anchor_that_cannot_be_parsed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }

        // A value an earlier build of this code could have written, and which
        // `load_anchor` now refuses. Failing closed is right; being unable to
        // clear it through the repair verb is not, because the only remedy left
        // would be deleting the keyring entry by hand.
        store.set_raw("0:0000000000000000000000000000000000000000000000000000000000000000:0");

        // An ordinary open still refuses: the guard must not read a corrupted
        // value as "nothing anchored".
        let err = open_anchored(&path, &store).unwrap_err();
        assert!(
            matches!(err, WriterError::TipAnchorStore(_)),
            "an unparseable anchor must fail an ordinary open: {err:?}"
        );

        let mut writer = AuditWriter::open_for_reanchor(
            path.clone(),
            None,
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        )
        .expect("repair opens regardless of the anchor's state");

        // The repair reports it as present-but-unusable, by shape, without
        // echoing the value.
        let stored = writer.stored_tip_anchor().expect("repair can read it");
        let StoredTipAnchor::Unusable { shape, reason } = &stored else {
            panic!("expected an unusable stored anchor, got {stored:?}");
        };
        assert!(shape.contains("3 colon-separated fields"), "shape: {shape}");
        assert!(!reason.is_empty());
        assert!(
            stored
                .coordinates()
                .is_some_and(|c| c.starts_with("unusable (")),
            "the report names it as unusable: {:?}",
            stored.coordinates()
        );

        let report = writer.reanchor().expect("repair must replace it");
        assert_eq!(report.previous, stored);
        assert_eq!(report.reanchor_count, 1);
        drop(writer);

        // And the log opens cleanly afterwards.
        open_anchored(&path, &store).expect("the repaired log must open cleanly");
        assert_eq!(stored_value(&store), tip_of(&path).to_keyring_value());
    }

    #[test]
    fn an_unreadable_anchor_fails_closed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }

        store.set_failing(true);
        let err = open_anchored(&path, &store).unwrap_err();
        assert!(
            matches!(err, WriterError::TipAnchorStore(_)),
            "an anchor that cannot be read must refuse, not adopt: {err:?}"
        );
    }

    #[test]
    fn a_writer_with_no_anchor_store_neither_checks_nor_writes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }
        let anchored = store.peek().unwrap();

        // Truncate to nothing, then open unanchored: the unkeyed paths keep
        // their existing behaviour and are not gated on the anchor.
        fs::write(&path, b"").unwrap();
        let mut writer = open_no_key(path.clone());
        assert!(!writer.has_tip_anchor());
        writer
            .verify_tip_anchor()
            .expect("a writer with no anchor store checks nothing");
        writer.write_entry(make_entry("")).unwrap();
        assert_eq!(
            store.peek().unwrap(),
            anchored,
            "an unanchored writer must not move the anchor"
        );
    }

    #[test]
    fn reopening_a_rotation_created_active_file_resumes_the_chain() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");

        {
            let mut writer = open_no_key(path.clone());
            writer.write_entry(make_entry("")).unwrap();
            writer.force_rotate_for_test().unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }

        // The active file's first entry chains off the archive's handoff entry,
        // not the zero block. Reopening must seed from that bridge.
        let mut writer = open_no_key(path.clone());
        writer.write_entry(make_entry("")).unwrap();
        drop(writer);

        crate::audit_log::verify::verify_log(&path, None)
            .expect("the whole chain must verify across the reopen");
    }

    #[test]
    fn writing_into_an_empty_rotation_created_file_after_a_restart_bridges() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");

        {
            let mut writer = open_no_key(path.clone());
            writer.write_entry(make_entry("")).unwrap();
            writer.force_rotate_for_test().unwrap();
        }
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);

        // A restart between the rotation and the first append must still write
        // an entry that chains off the handoff.
        let mut writer = open_no_key(path.clone());
        writer.write_entry(make_entry("")).unwrap();
        drop(writer);

        crate::audit_log::verify::verify_log(&path, None)
            .expect("the first entry after a restart must bridge to the archive");
    }

    // ── Tip anchor across a rotation ─────────────────────────────────────────
    //
    // A file a rotation created chains its first entry off the outgoing file's
    // handoff entry, not off the zero block. Every replay the anchor performs —
    // full-file and tail alike — has to seed from that bridge. These four pin
    // the branches that a log which has rotated at least once actually reaches;
    // the anchor-current tests above never leave the first file of a chain.

    /// Builds an alpha.6-shaped log: entries, one rotation, more entries, and
    /// no anchor. Returns nothing in the store.
    fn rotated_log_without_anchor(path: &Path) {
        let mut writer = open_no_key(path.to_path_buf());
        writer.write_entry(make_entry("")).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        writer.force_rotate_for_test().unwrap();
        writer.write_entry(make_entry("")).unwrap();
        writer.write_entry(make_entry("")).unwrap();
    }

    #[test]
    fn adoption_succeeds_on_a_rotation_created_active_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        rotated_log_without_anchor(&path);
        let tip_before = tip_of(&path);
        assert_eq!(
            tip_before.entry_count, 2,
            "the active file is post-rotation"
        );

        let store = Arc::new(InMemoryTipAnchorStore::new());
        let writer = open_anchored(&path, &store)
            .expect("the upgrade path must adopt a log that has rotated");
        drop(writer);

        assert_eq!(
            count_tip_anchored_rows(&path, "adopted"),
            1,
            "adoption must record itself even on a rotated log"
        );
        assert_eq!(
            stored_value(&store),
            tip_of(&path).to_keyring_value(),
            "the anchor must name the post-rotation file's tip"
        );
        assert_eq!(
            store.peek().unwrap().entry_count,
            tip_before.entry_count + 1
        );
    }

    #[test]
    fn crash_after_the_first_post_rotation_append_self_heals_on_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.force_rotate_for_test().unwrap();
            // The rotation left the anchor on the archive's handoff. The first
            // append into the new file lands in the crash window: entry fsynced,
            // anchor not written, so the anchor still names the PREVIOUS
            // generation while the file holds one entry.
            writer.set_skip_tip_anchor_write(true);
            writer.write_entry(make_entry("")).unwrap();
        }
        assert_eq!(
            store.peek().unwrap(),
            tip_of(&newest_archive(&path)),
            "the failpoint must leave the anchor on the archive's handoff"
        );
        assert_eq!(tip_of(&path).entry_count, 1, "the entry is on disk");

        let writer = open_anchored(&path, &store)
            .expect("a post-rotation file must open, not read as a rollback");
        drop(writer);
        assert_eq!(
            stored_value(&store),
            tip_of(&path).to_keyring_value(),
            "reopening must advance the anchor onto the fsynced entry"
        );
        assert_eq!(
            count_tip_anchored_rows(&path, "adopted"),
            0,
            "absorbing an append ahead of the anchor is not an adoption"
        );
    }

    #[test]
    fn repair_works_on_a_rotation_created_active_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let snapshot = {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.force_rotate_for_test().unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            let snapshot = fs::read(&path).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            snapshot
        };
        fs::write(&path, &snapshot).unwrap();
        assert!(
            open_anchored(&path, &store).is_err(),
            "the rolled-back post-rotation log must refuse before the repair"
        );

        let mut writer = AuditWriter::open_for_reanchor(
            path.clone(),
            None,
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        )
        .expect("repair must open a rotated log");
        let proposed = writer
            .current_tip_anchor()
            .expect("the repair verb reports the tip before the acknowledgement");
        assert_eq!(
            proposed
                .expect("a post-rotation file with entries has a tip")
                .entry_count,
            2
        );
        let report = writer
            .reanchor()
            .expect("repair must succeed on a rotated log");
        assert_eq!(report.reanchor_count, 1);
        drop(writer);

        assert_eq!(count_tip_anchored_rows(&path, "rollback_acknowledged"), 1);
        open_anchored(&path, &store).expect("the repaired rotated log must open cleanly");
    }

    #[test]
    fn a_truncation_is_a_tip_anchor_mismatch_and_a_broken_chain_is_a_chain_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        drop(writer);
        let anchored = store.peek().unwrap();
        assert_eq!(anchored.entry_count, 2);

        // Roll the file back to empty. The anchor names two entries at a
        // non-zero offset, so this is a truncation, and the operator must get
        // the code whose runbook covers it rather than a chain-break code that
        // would send them to the wrong section.
        //
        // Scope: this pins the code the two conditions produce, nothing about
        // the rotation window. The rotation-window claims are pinned by
        // `a_rollback_during_the_rotation_window_is_refused` and its siblings.
        fs::write(&path, b"").unwrap();
        let err = open_anchored(&path, &store).unwrap_err();
        assert!(
            matches!(
                err,
                WriterError::TipAnchorMismatch {
                    expected_count: 2,
                    actual_len: 0,
                    ..
                }
            ),
            "a rollback must report the tip-anchor code, not a chain break: {err:?}"
        );

        // The mirror case: the file is replaced by one whose own linkage is
        // broken, which is a chain error rather than a rollback.
        store.set(None);
        let mut foreign = Vec::new();
        {
            let other = dir.path().join("other.jsonl");
            let mut w = open_no_key(other.clone());
            w.write_entry(make_entry("")).unwrap();
            drop(w);
            let content = fs::read(&other).unwrap();
            // Break the first entry's link so the file cannot chain from any
            // seed this path could produce.
            let text = String::from_utf8(content).unwrap();
            foreign.extend_from_slice(
                text.replace(
                    "\"previous_entry_hash\":\"sha256:",
                    "\"previous_entry_hash\":\"sha256:0",
                )
                .as_bytes(),
            );
        }
        fs::write(&path, &foreign).unwrap();
        let err = open_anchored(&path, &store).unwrap_err();
        assert!(
            matches!(err, WriterError::ChainBrokenAtOpen { .. }),
            "a file whose own linkage is broken is a chain break, not a rollback: {err:?}"
        );
    }

    #[test]
    fn rotation_bridge_refuses_an_archive_that_is_not_a_handoff() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        rotated_log_without_anchor(&path);

        // Replace the archive's trailing handoff with an ordinary entry: the
        // shape a planted sibling would have.
        let archive = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| is_rotated_sibling("test.jsonl", n))
            })
            .expect("one archive exists");
        let content = fs::read_to_string(&archive).unwrap();
        let kept: Vec<&str> = content
            .lines()
            .filter(|l| !l.contains("audit_rotation_handoff"))
            .collect();
        fs::write(&archive, format!("{}\n", kept.join("\n"))).unwrap();

        let err = open_no_key_result(path.clone()).unwrap_err();
        assert!(
            matches!(
                err,
                WriterError::RotationBridgeUnusable {
                    reason: "the archive does not end with a rotation handoff entry",
                    ..
                }
            ),
            "an archive that cannot supply the bridge must refuse: {err:?}"
        );
    }

    fn open_no_key_result(path: PathBuf) -> Result<AuditWriter, WriterError> {
        AuditWriter::open(path, None)
    }

    // ── The rotation window ──────────────────────────────────────────────────
    //
    // The empty-file anchor is offset 0, a prefix of every file, so while it
    // stands every file classifies as ahead-of-anchor and a rollback is
    // absorbed rather than refused. Rotation therefore never leaves it standing
    // while the path holds entries: the anchor is advanced onto the outgoing
    // file's handoff before the renames and handed to the new file only after
    // them. These pin both halves of that window.

    #[test]
    fn a_rollback_during_the_rotation_window_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        let one_entry = fs::read(&path).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        writer.write_entry(make_entry("")).unwrap();

        // The instant before the renames: the handoff is appended and the
        // anchor names it. The rollback guard has to be armed here, not
        // suspended, because the path still holds the whole outgoing file.
        writer.write_rotation_handoff_for_test().unwrap();
        let during_rotation = store.peek().unwrap();
        assert_eq!(
            during_rotation.entry_count, 4,
            "the anchor must name the outgoing file's tip during the rotation, \
             not the empty-file value: {during_rotation:?}"
        );
        drop(writer);

        fs::write(&path, &one_entry).unwrap();
        let err = open_anchored(&path, &store).unwrap_err();
        assert!(
            matches!(
                err,
                WriterError::TipAnchorMismatch {
                    expected_count: 4,
                    ..
                }
            ),
            "a rollback inside the rotation window must be refused, not absorbed: {err:?}"
        );
    }

    /// Returns the newest rotated sibling of `path`.
    fn newest_archive(path: &Path) -> PathBuf {
        let stem = path.file_name().and_then(|s| s.to_str()).unwrap();
        let mut archives: Vec<PathBuf> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| is_rotated_sibling(stem, n))
            })
            .collect();
        archives.sort();
        archives.pop().expect("at least one archive")
    }

    #[test]
    fn a_rotation_whose_new_file_anchor_write_was_lost_opens_and_re_anchors() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.force_rotate_for_test().unwrap();
        }

        // Simulate the post-rename anchor write being lost: put the anchor back
        // to the value the rotation left just before the renames, which names
        // the archive's handoff entry.
        let stranded = tip_of(&newest_archive(&path));
        assert_eq!(
            stranded.entry_count, 3,
            "the stranded anchor names the archive's handoff: {stranded:?}"
        );
        let stranded_check = stranded.clone();
        store.set(Some(stranded));
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            0,
            "the new file is empty"
        );

        // Shorter than the anchor, but provably a completed rotation: the
        // anchored tip IS the newest archive's handoff.
        let writer =
            open_anchored(&path, &store).expect("a completed rotation must not read as a rollback");
        drop(writer);
        assert_eq!(
            store.peek().unwrap(),
            stranded_check,
            "an empty post-rotation file stays on the archive's handoff: there is \
             no entry of its own to anchor yet"
        );
        assert_eq!(
            count_tip_anchored_rows(&path, "adopted"),
            0,
            "a rotation handover is not an adoption"
        );

        // The first append moves the anchor onto this file's own first entry.
        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        assert_eq!(store.peek().unwrap().entry_count, 1);
        assert_eq!(stored_value(&store), tip_of(&path).to_keyring_value());
    }

    #[test]
    fn a_rollback_onto_a_foreign_shorter_file_is_still_refused_after_a_rotation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let one_entry = {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            let one_entry = fs::read(&path).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.force_rotate_for_test().unwrap();
            one_entry
        };
        // The anchor names the archive's handoff, so the rotation-completed rule
        // is live — but the path holds a rolled-back prefix of the OLD file, not
        // the file the rotation created. The rule re-derives the anchor from the
        // file, and the file's first entry does not chain from the archive's
        // handoff, so the replay refuses.
        store.set(Some(tip_of(&newest_archive(&path))));
        fs::write(&path, &one_entry).unwrap();
        let err = open_anchored(&path, &store).unwrap_err();
        assert!(
            matches!(err, WriterError::ChainBrokenAtOpen { .. }),
            "a rolled-back prefix of the pre-rotation file must not be blessed \
             by the rotation-completed rule: {err:?}"
        );
    }
    #[test]
    fn restoring_the_pre_rotation_directory_state_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let pre_rotation = {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            let pre_rotation = fs::read(&path).unwrap();
            // Rotate and stop. Nothing has appended to the new file, which is
            // the moment an anchor meaning "this file is empty" would leave the
            // guard disarmed: offset 0 is a prefix of every file.
            writer.force_rotate_for_test().unwrap();
            pre_rotation
        };
        let archive = newest_archive(&path);

        // Roll the whole directory back to before the rotation: the archive is
        // gone and the path holds the file as it was. Every entry in it is
        // genuine and its chain verifies, which is exactly why the chain walk
        // cannot catch this.
        fs::remove_file(&archive).unwrap();
        fs::write(&path, &pre_rotation).unwrap();
        assert!(
            verify_log_is_clean(&path),
            "the restored state chains cleanly"
        );

        let err = open_anchored(&path, &store).unwrap_err();
        assert!(
            matches!(err, WriterError::TipAnchorMismatch { .. }),
            "a directory-level rollback to before the rotation must be refused: {err:?}"
        );
    }

    #[test]
    fn restoring_an_older_archive_and_active_pair_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        // Rotate twice. The snapshot is the directory as it stood right after
        // the FIRST rotation: one archive and an empty active file.
        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        writer.force_rotate_for_test().unwrap();
        let first_archive = newest_archive(&path);
        let first_archive_bytes = fs::read(&first_archive).unwrap();
        let empty_active = fs::read(&path).unwrap();

        writer.write_entry(make_entry("")).unwrap();
        writer.force_rotate_for_test().unwrap();
        drop(writer);
        let second_archive = newest_archive(&path);
        assert_ne!(first_archive, second_archive, "two archives exist");

        // Restore the pair to its earlier state. Both files are internally
        // consistent and bridge to each other; only the anchor knows the pair is
        // stale.
        fs::remove_file(&second_archive).unwrap();
        fs::write(&first_archive, &first_archive_bytes).unwrap();
        fs::write(&path, &empty_active).unwrap();
        assert!(
            verify_log_is_clean(&path),
            "the restored pair chains cleanly"
        );

        let err = open_anchored(&path, &store).unwrap_err();
        assert!(
            matches!(err, WriterError::TipAnchorMismatch { .. }),
            "restoring an older archive-and-active pair must be refused: {err:?}"
        );
    }

    #[test]
    fn trailing_blank_lines_do_not_make_an_untouched_log_read_as_rolled_back() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }

        // Bytes every reader in this subsystem tolerates but no writer here
        // produces: the replay, `verify_log` and the partial-entry scan all skip
        // blank lines. The anchor has to tolerate them identically, or an
        // untouched log reports a rollback the operator would have to
        // acknowledge.
        {
            use std::io::Write as _;
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"\n\n").unwrap();
            f.sync_data().unwrap();
        }

        let mut writer =
            open_anchored(&path, &store).expect("trailing blank lines are not a rollback");
        writer
            .verify_tip_anchor()
            .expect("nor do they fail the per-acquisition check");

        // The next append lands after the blanks, and the anchor names where it
        // actually ends rather than where arithmetic on the writer's own bytes
        // would have put it.
        writer.write_entry(make_entry("")).unwrap();
        let anchored = store.peek().unwrap();
        assert_eq!(anchored.entry_count, 3);
        assert_eq!(
            anchored.end_offset,
            fs::metadata(&path).unwrap().len(),
            "the anchored offset must be the real end of the appended entry"
        );
        drop(writer);

        open_anchored(&path, &store).expect("and the reopen agrees");
        assert!(verify_log_is_clean(&path));
    }

    #[test]
    fn a_failed_anchor_write_is_retried_on_the_next_append() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let mut writer = open_anchored(&path, &store).unwrap();
        let writes_at_open = store.writes().len();

        // The first append's anchor write fails: the entry is durable, the
        // anchor is not moved.
        store.set_failing(true);
        writer.write_entry(make_entry("")).unwrap();
        assert_eq!(
            store.writes().len(),
            writes_at_open,
            "a failed write must record nothing"
        );
        assert!(store.peek().is_none(), "the anchor is left behind the file");

        // The next append repairs it BEFORE appending, then records its own.
        store.set_failing(false);
        writer.write_entry(make_entry("")).unwrap();

        let recorded: Vec<u64> = store
            .writes()
            .into_iter()
            .skip(writes_at_open)
            .map(|a| a.entry_count)
            .collect();
        assert_eq!(
            recorded,
            vec![1, 2],
            "the append must first re-write the anchor for the entry already on \
             disk, then write its own; without the repair only the second \
             would appear"
        );
        assert_eq!(stored_value(&store), tip_of(&path).to_keyring_value());
    }

    /// A log replaced by RENAME under a live keyed writer is refused, the
    /// registry drops the writer, and nothing lands in the file the rename
    /// unlinked.
    ///
    /// The writer holds one handle for its whole lifetime, and a rename leaves
    /// that handle on the previous inode — whose tail is exactly the anchored
    /// one, so every content check passes. Rows would then be appended to a file
    /// no path names, lost when the process exits, while the log an operator
    /// reads stayed behind the anchor with nothing refused. The replacement here
    /// carries the SAME bytes as the file it displaces, so file identity is the
    /// only thing that can tell the two apart.
    #[test]
    fn a_rename_over_the_log_under_a_live_writer_is_refused_and_evicts_the_writer() {
        let dir = TempDir::new().unwrap();
        let profile = format!("reg-rename-{}", uuid::Uuid::new_v4().simple());
        let path = dir.path().join(format!("{profile}.jsonl"));
        let store: Arc<dyn TipAnchorStore> = Arc::new(InMemoryTipAnchorStore::new());
        let key = Zeroizing::new([0x5a_u8; 32]);
        let acquire = || {
            AuditWriterRegistry::get_or_open_keyed(
                &profile,
                &path,
                KeyedAuditAccess::new(key.clone(), Arc::clone(&store)),
            )
        };

        let held = acquire().unwrap();
        held.lock().unwrap().write_entry(make_entry("")).unwrap();
        let after_one_entry = fs::read(&path).unwrap();
        held.lock().unwrap().write_entry(make_entry("")).unwrap();
        let anchored_bytes = fs::read(&path).unwrap();
        acquire().expect("an untouched log must still acquire");

        // A second handle on the file the rename is about to unlink, so the
        // inode stays observable after it has no name.
        let unlinked_inode = File::open(&path).unwrap();
        let replacement = dir.path().join("replacement.jsonl");
        fs::write(&replacement, &anchored_bytes).unwrap();
        fs::rename(&replacement, &path).unwrap();

        let err = acquire().expect_err("a log replaced under a live writer must refuse");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. } if *reason == LOG_REPLACED_REASON
            ),
            "expected the replaced-underneath-the-writer refusal, got {err:?}"
        );
        assert_eq!(
            unlinked_inode.metadata().unwrap().len(),
            anchored_bytes.len() as u64,
            "no row may be appended to the inode the rename unlinked"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            anchored_bytes.len() as u64,
            "no row may be appended to the file now at the path"
        );

        // The refusal evicted the cached writer, so the next acquisition opens
        // the file at the path and checks THAT file against the anchor. The
        // evicted writer still holds the sidecar lock until every caller has
        // dropped it.
        drop(held);

        fs::write(&path, &after_one_entry).unwrap();
        let err = acquire().expect_err("an older copy at the path must refuse");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. }
                    if *reason == "file is shorter than the anchor"
            ),
            "the reopened path must be checked against the anchor on its own \
             terms, got {err:?}"
        );

        fs::write(&path, &anchored_bytes).unwrap();
        acquire().expect("the anchored file put back at the path must acquire");
    }

    /// Unlinking the log reads as a replacement, not as an empty log the writer
    /// may carry on appending to.
    ///
    /// Unix only, because it is the unlink itself that is under test: a delete
    /// there removes the name at once while the writer's handle keeps the file
    /// alive. The same branch — nothing at the path — is covered on every
    /// platform by the rename-away pins.
    #[cfg(unix)]
    #[test]
    fn a_deleted_log_under_a_live_writer_is_refused() {
        let dir = TempDir::new().unwrap();
        let profile = format!("reg-unlink-{}", uuid::Uuid::new_v4().simple());
        let path = dir.path().join(format!("{profile}.jsonl"));
        let store: Arc<dyn TipAnchorStore> = Arc::new(InMemoryTipAnchorStore::new());
        let key = Zeroizing::new([0x5b_u8; 32]);
        let acquire = || {
            AuditWriterRegistry::get_or_open_keyed(
                &profile,
                &path,
                KeyedAuditAccess::new(key.clone(), Arc::clone(&store)),
            )
        };

        let held = acquire().unwrap();
        held.lock().unwrap().write_entry(make_entry("")).unwrap();
        fs::remove_file(&path).unwrap();

        let err = acquire().expect_err("a removed log must refuse");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. } if *reason == LOG_REPLACED_REASON
            ),
            "expected the replaced-underneath-the-writer refusal, got {err:?}"
        );
        drop(held);
    }

    /// The production half of this file, with line endings normalized.
    ///
    /// `include_str!` yields the bytes as checked out, and a Windows checkout
    /// is CRLF, so every scan below matches against `\n`-only text and stops
    /// at the test module marker rather than reading its own assertions.
    fn production_source() -> String {
        let source = include_str!("writer.rs").replace("\r\n", "\n");
        source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("the production half precedes the test module")
            .to_owned()
    }

    /// A keyed writer cannot be opened without an anchor store.
    ///
    /// The registry's keyed entry point takes [`KeyedAuditAccess`], which cannot
    /// be built without both halves, so the guarantee is structural rather than
    /// a convention. This pins that no second keyed entry point grows back: a
    /// registry function that accepts a bare key would let a caller open a keyed
    /// writer whose rows the anchor never covers, which is exactly the class of
    /// rows an attacker wants to remove.
    #[test]
    fn the_registry_has_no_keyed_entry_point_that_takes_a_bare_key() {
        let production = production_source();
        assert!(
            production.contains("pub fn get_or_open_keyed"),
            "the scan must see the production half of this file"
        );

        let keyed_entry_points = production.matches("pub fn get_or_open").count();
        assert_eq!(
            keyed_entry_points, 2,
            "the registry exposes exactly two entry points, `get_or_open_unkeyed` \\
             and `get_or_open_keyed`; a third would need its own argument for the \\
             anchor store and is how a bare-key open grows back"
        );
        assert!(
            !production.contains(
                "hmac_key: Option<Zeroizing<[u8; 32]>>,\n    ) -> Result<Arc<Mutex<AuditWriter>>"
            ),
            "no public registry entry point may take a bare optional key"
        );
    }

    /// An append refuses when the log at the path stopped being the file the
    /// writer holds, and the writer refuses everything afterwards.
    ///
    /// A caller acquires the writer, signs, submits, and only then appends, so
    /// the check at acquisition covers none of that span. Without a check on the
    /// append itself, the row proving a committed action lands in a file no path
    /// names and is gone when the process exits. The latch is what makes the
    /// refusal stick: the same file put back at the path afterwards must not
    /// quietly re-enable a writer whose caller has already been told the append
    /// failed.
    #[test]
    fn an_append_after_the_log_is_replaced_refuses_and_latches_the_writer() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        let anchored_len = fs::metadata(&path).unwrap().len();

        // Move the log out from under the writer. The handle still names this
        // file; the path names nothing.
        let moved = dir.path().join("moved.jsonl");
        fs::rename(&path, &moved).unwrap();

        let err = writer
            .write_entry(make_entry(""))
            .expect_err("an append onto a path the writer no longer holds must refuse");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. } if *reason == LOG_REPLACED_REASON
            ),
            "expected the replaced-underneath-the-writer refusal, got {err:?}"
        );
        assert_eq!(
            fs::metadata(&moved).unwrap().len(),
            anchored_len,
            "the refused append must write nothing"
        );

        // The refusal is durable: the anchor now names the row the wallet owed,
        // so the file at the path is short of it by exactly that row.
        let owed = store.peek().expect("the refused row must be anchored");
        assert_eq!(
            owed.entry_count, 2,
            "the anchor must name the row that was refused, not the one on disk"
        );
        assert!(
            owed.end_offset > anchored_len,
            "the anchored offset must lie past the end of the file on disk"
        );

        // The very same file back at the path does not revive the writer: its
        // caller was already told the append failed, and a row written now would
        // sit after a gap nothing accounts for.
        fs::rename(&moved, &path).unwrap();
        let err = writer
            .write_entry(make_entry(""))
            .expect_err("a latched writer must refuse every later append");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. } if *reason == LOG_REPLACED_REASON
            ),
            "expected the latched refusal, got {err:?}"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            anchored_len,
            "a latched writer must write nothing either"
        );
        drop(writer);

        // A fresh writer on the same file refuses too: the refusal outlives the
        // process that made it.
        let err = open_anchored(&path, &store)
            .expect_err("the file the anchor is ahead of must not open cleanly");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. }
                    if *reason == "file is shorter than the anchor"
            ),
            "expected a rollback refusal against the owed anchor, got {err:?}"
        );

        // Only the operator-acknowledged repair clears it, and its report names
        // one more anchored entry than the file holds.
        let mut repair = AuditWriter::open_for_reanchor(
            path.clone(),
            None,
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        )
        .unwrap();
        let report = repair.reanchor().expect("the repair verb must recover it");
        assert_eq!(
            report.previous.coordinates(),
            Some(owed.coordinates()),
            "the repair must record the anchor that named the missing row"
        );
        assert_eq!(report.reanchor_count, 1);
    }

    /// An unanchored writer is not gated on the file's identity.
    ///
    /// The identity check exists to protect the anchor, and an unkeyed writer
    /// has neither. Gating it too would make the startup advisory and the
    /// zero-config path fail on states they are explicitly allowed to write
    /// through.
    #[test]
    fn an_unanchored_writer_appends_through_a_replacement() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");

        let mut writer = open_no_key(path.clone());
        writer.write_entry(make_entry("")).unwrap();
        let moved = dir.path().join("moved.jsonl");
        fs::rename(&path, &moved).unwrap();

        writer
            .write_entry(make_entry(""))
            .expect("an unanchored writer has no anchor to protect");
    }

    /// The writer's own rotation is not a replacement.
    ///
    /// Rotation renames the active file away and creates a new one at the same
    /// path, which is exactly the shape the identity check refuses — so the
    /// check has to run before the rotation decision and never inside the
    /// rotation itself, and the handle has to be on the new file before anything
    /// checks again.
    #[test]
    fn a_rotation_under_a_live_anchored_writer_is_not_a_replacement() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        writer.force_rotate_for_test().unwrap();

        writer
            .write_entry(make_entry(""))
            .expect("the file a rotation created is the file at the path");
        writer
            .verify_tip_anchor()
            .expect("and the acquisition check agrees");
        assert_eq!(stored_value(&store), tip_of(&path).to_keyring_value());
    }

    /// A rotation that failed after the rename reports the partial rotation, not
    /// a replacement.
    ///
    /// Both leave the handle on a file the path no longer names, and they need
    /// different things looked at: a partial rotation is a directory state an
    /// operator repairs by hand, and `audit reanchor` refuses it anyway.
    #[test]
    fn a_failed_rotation_reports_the_partial_rotation_not_a_replacement() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();

        // Pad the file past the rotation threshold through a second handle,
        // APPENDING blank lines: the log carries no lock, every reader here
        // tolerates blanks, and the entry the writer last wrote stays where it
        // is, so the rotation this triggers is the writer's own rather than a
        // rewrite of its tip.
        {
            let mut padding = OpenOptions::new().append(true).open(&path).unwrap();
            padding
                .write_all(&vec![b'\n'; ROTATION_THRESHOLD_BYTES as usize])
                .unwrap();
            padding.sync_data().unwrap();
        }
        if let Ok(mut force_path) = FORCE_NEXT_ROTATION_CREATE_FAILURE_PATH.lock() {
            *force_path = Some(path.clone());
        }
        let err = writer
            .write_entry(make_entry(""))
            .expect_err("the forced post-rename create failure must be surfaced");
        assert!(
            matches!(err, WriterError::PartialRotation { .. }),
            "expected PartialRotation, got {err:?}"
        );

        let err = writer
            .verify_tip_anchor()
            .expect_err("the acquisition check must refuse too");
        assert!(
            matches!(err, WriterError::PartialRotation { .. }),
            "a half-finished rotation is not a replacement, got {err:?}"
        );
    }

    /// While an evicted writer is still referenced, the registry answers the
    /// replacement rather than the sidecar lock the evicted writer still holds,
    /// and the holder's own next append refuses.
    ///
    /// Removing the entry outright would make the next acquisition open the path
    /// and collide with a lock this very process holds, which reports
    /// `audit.writer_locked` and tells the operator to stop a server that is the
    /// one asking — the wrong instruction at the moment a log has been replaced.
    #[test]
    fn an_evicted_writer_still_referenced_answers_the_replacement_not_the_lock() {
        let dir = TempDir::new().unwrap();
        let profile = format!("reg-tombstone-{}", uuid::Uuid::new_v4().simple());
        let path = dir.path().join(format!("{profile}.jsonl"));
        let store: Arc<dyn TipAnchorStore> = Arc::new(InMemoryTipAnchorStore::new());
        let key = Zeroizing::new([0x5c_u8; 32]);
        let acquire = || {
            AuditWriterRegistry::get_or_open_keyed(
                &profile,
                &path,
                KeyedAuditAccess::new(key.clone(), Arc::clone(&store)),
            )
        };

        let held = acquire().unwrap();
        held.lock().unwrap().write_entry(make_entry("")).unwrap();
        let anchored_bytes = fs::read(&path).unwrap();

        let replacement = dir.path().join("replacement.jsonl");
        fs::write(&replacement, &anchored_bytes).unwrap();
        fs::rename(&replacement, &path).unwrap();

        let err = acquire().expect_err("the replacement must refuse and evict");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. } if *reason == LOG_REPLACED_REASON
            ),
            "expected the replaced-underneath-the-writer refusal, got {err:?}"
        );

        // `held` is still alive, so the evicted writer's sidecar lock is too.
        let err = acquire().expect_err("a later acquisition must still refuse");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. } if *reason == LOG_REPLACED_REASON
            ),
            "the tombstone must answer the replacement, not the lock, got {err:?}"
        );

        let err = held
            .lock()
            .unwrap()
            .write_entry(make_entry(""))
            .expect_err("the holder's own append must refuse");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. } if *reason == LOG_REPLACED_REASON
            ),
            "an evicted writer must be latched for its holder too, got {err:?}"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            anchored_bytes.len() as u64,
            "nothing may be appended at the path"
        );

        // Once nothing references the evicted writer the path is opened again —
        // and refused, because the refused append anchored the row the wallet
        // owed and no file at this path holds it.
        drop(held);
        let err = acquire().expect_err("the owed row must outlive the evicted writer");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. }
                    if *reason == "file is shorter than the anchor"
            ),
            "expected a rollback refusal against the owed anchor, got {err:?}"
        );
    }

    /// An in-place truncation landing between an acquisition and its append is
    /// refused, durably, rather than appended onto.
    ///
    /// The file keeps its identity, so only its length says what happened. The
    /// row would otherwise be written at the shortened end, chained off a tip the
    /// file no longer holds, and the anchor would advance over the splice.
    #[test]
    fn an_append_after_the_log_is_truncated_in_place_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        let two_rows = fs::metadata(&path).unwrap().len();

        // Same inode, fewer bytes.
        let one_row = fs::read(&path).unwrap();
        let first_line_end = one_row.iter().position(|&b| b == b'\n').unwrap() + 1;
        fs::write(&path, &one_row[..first_line_end]).unwrap();

        let err = writer
            .write_entry(make_entry(""))
            .expect_err("an append onto a truncated log must refuse");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. }
                    if *reason == LOG_TRUNCATED_REASON
            ),
            "expected the truncated-under-the-writer refusal, got {err:?}"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            first_line_end as u64,
            "the refused append must write nothing"
        );

        let owed = store.peek().expect("the refused row must be anchored");
        assert_eq!(owed.entry_count, 3, "the anchor must name the refused row");
        assert!(
            owed.end_offset > two_rows,
            "the anchored offset must lie past where the untruncated file ended"
        );
        drop(writer);
        assert!(
            open_anchored(&path, &store).is_err(),
            "the refusal must outlive the writer that made it"
        );
    }

    /// An in-place overwrite that keeps the file's length is refused too.
    ///
    /// Identity and length both still agree; the entry at the writer's own end
    /// offset is the only thing left that can tell the file apart from the one it
    /// wrote.
    #[test]
    fn an_append_after_the_log_is_overwritten_at_the_same_length_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        let original = fs::read(&path).unwrap();

        // A different chain of the same byte length at the same inode: the
        // writer's own bytes with one character of the request id changed.
        let mut forged = original.clone();
        let idx = forged
            .windows(2)
            .position(|w| w == b"\"r")
            .expect("the row carries a quoted field to alter");
        forged[idx + 1] = b'R';
        assert_eq!(forged.len(), original.len());
        fs::write(&path, &forged).unwrap();

        let err = writer
            .write_entry(make_entry(""))
            .expect_err("an append onto an overwritten log must refuse");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. }
                    if *reason == LOG_TIP_REWRITTEN_REASON
            ),
            "expected the rewritten-tip refusal, got {err:?}"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            forged,
            "the refused append must write nothing"
        );
        assert_eq!(
            store
                .peek()
                .expect("the refused row must be anchored")
                .entry_count,
            2,
            "the anchor must name the refused row"
        );
    }

    /// Every `fn open*` declaration in `source` that takes a chain-root key
    /// without an anchor handle, excluding the ones a `cfg` gate keeps out of
    /// every shipped binary.
    ///
    /// Visibility is not part of the predicate: a `pub(crate)` constructor
    /// reachable from anywhere in this crate opens exactly the same hole as a
    /// `pub` one.
    /// Returns `true` when `signature` takes an anchor store the caller cannot
    /// omit.
    ///
    /// An optional store is not an exemption: a keyed writer constructed with
    /// `None` writes rows no anchor covers, which is the whole condition this
    /// scan exists to prevent. The check looks for an `Option<` within the
    /// parameter that names the store, so `Option<Arc<dyn TipAnchorStore>>`
    /// and `Option<&dyn TipAnchorStore>` both read as optional.
    fn takes_a_required_anchor_store(signature: &str) -> bool {
        let mut required = false;
        for (idx, _) in signature.match_indices("TipAnchorStore") {
            let window_start = signature[..idx]
                .rfind([',', '('])
                .map_or(0, |offset| offset + 1);
            if signature[window_start..idx].contains("Option<") {
                continue;
            }
            required = true;
        }
        required
    }

    fn keyed_constructors_without_an_anchor(source: &str) -> Vec<String> {
        let mut offenders = Vec::new();
        for (idx, _) in source.match_indices("fn open") {
            let line_start = source[..idx].rfind('\n').map_or(0, |nl| nl + 1);
            // Only a declaration at the head of its line, so call sites and
            // prose mentioning `fn open` are not scanned. A declaration with no
            // visibility keyword is the shared private implementation every
            // public entry point funnels through; it cannot be reached by a
            // caller holding `AuditWriter`, which is the reach this scan is
            // about.
            let prefix: Vec<&str> = source[line_start..idx].split_whitespace().collect();
            let visible = prefix
                .iter()
                .any(|word| matches!(*word, "pub" | "pub(crate)" | "pub(super)"));
            let well_formed = prefix.iter().all(|word| {
                matches!(
                    *word,
                    "pub" | "pub(crate)" | "pub(super)" | "const" | "async" | "unsafe"
                )
            });
            if !visible || !well_formed {
                continue;
            }
            let end = source[idx..]
                .find('{')
                .map_or(source.len(), |offset| idx + offset);
            let signature = &source[idx..end];
            if !signature.contains("Zeroizing<[u8; 32]>")
                || signature.contains("KeyedAuditAccess")
                || takes_a_required_anchor_store(signature)
            {
                continue;
            }
            if source[..line_start]
                .trim_end()
                .ends_with("#[cfg(any(test, feature = \"test-helpers\"))]")
            {
                continue;
            }
            offenders.push(format!(
                "line {}: {}",
                source[..idx].lines().count(),
                signature.replace('\n', " ")
            ));
        }
        offenders
    }

    /// No writer CONSTRUCTOR takes a chain-root key without an anchor store.
    ///
    /// Closing the registry's entry points alone leaves the hole open one level
    /// down: a caller that reaches `AuditWriter` directly could still open a
    /// keyed writer whose rows the anchor never covers, which is exactly the
    /// class of rows an attacker wants to remove. [`KeyedAuditAccess`] pairs the
    /// key and the store inseparably, and the anchored constructors take the
    /// store as a required argument. The one exemption is the test seam, which
    /// carries a `cfg` gate that keeps it out of every shipped binary.
    ///
    /// The scan is exercised against a synthetic offender first, so a predicate
    /// that stopped recognising the shape fails here rather than passing
    /// vacuously over a production half that grew one.
    #[test]
    fn no_writer_constructor_takes_a_key_without_an_anchor_handle() {
        let public_offender = "    pub fn open(\n        path: PathBuf,\n        \
             hmac_key: Option<Zeroizing<[u8; 32]>>,\n    ) -> Result<Self, WriterError> {";
        assert_eq!(
            keyed_constructors_without_an_anchor(public_offender).len(),
            1,
            "the scan must flag a public constructor taking a bare key"
        );
        let crate_visible_offender = "    pub(crate) fn open_keyed(\n        path: PathBuf,\n        \
             hmac_key: Zeroizing<[u8; 32]>,\n    ) -> Result<Self, WriterError> {";
        assert_eq!(
            keyed_constructors_without_an_anchor(crate_visible_offender).len(),
            1,
            "visibility must not exempt a constructor from the scan"
        );
        let optional_store_offender = "    pub fn open_keyed(\n        path: PathBuf,\n        \
             hmac_key: Zeroizing<[u8; 32]>,\n        anchor: Option<Arc<dyn TipAnchorStore>>,\n\
                 ) -> Result<Self, WriterError> {";
        assert_eq!(
            keyed_constructors_without_an_anchor(optional_store_offender).len(),
            1,
            "an anchor store the caller may omit is not an exemption: a keyed writer \
             constructed with None writes rows no anchor covers"
        );
        let private_helper = "    fn open_inner(\n        path: PathBuf,\n        \
             hmac_key: Option<Zeroizing<[u8; 32]>>,\n        anchor: Option<Arc<dyn TipAnchorStore>>,\n\
                 ) -> Result<Self, WriterError> {";
        assert!(
            keyed_constructors_without_an_anchor(private_helper).is_empty(),
            "the shared private implementation every public entry point funnels through is \
             not reachable by a caller holding AuditWriter"
        );
        let required_store = "    pub fn open_keyed(\n        path: PathBuf,\n        \
             hmac_key: Zeroizing<[u8; 32]>,\n        anchor: &dyn TipAnchorStore,\n\
                 ) -> Result<Self, WriterError> {";
        assert!(
            keyed_constructors_without_an_anchor(required_store).is_empty(),
            "a required anchor store is the exemption the scan is written around"
        );

        let gated = format!("    #[cfg(any(test, feature = \"test-helpers\"))]\n{public_offender}");
        assert!(
            keyed_constructors_without_an_anchor(&gated).is_empty(),
            "a cfg-gated test seam is the one exemption"
        );

        let production = production_source();
        assert!(
            production.contains("pub fn open("),
            "the scan must see the production half of this file"
        );
        let offenders = keyed_constructors_without_an_anchor(&production);
        assert!(
            offenders.is_empty(),
            "a keyed writer must not be constructible without an anchor \
             handle:\n{}",
            offenders.join("\n")
        );
    }

    /// No replay site may hardcode the zero block as its seed.
    ///
    /// The zero block is correct only for the first file of a chain. Every
    /// replay goes through `AuditWriter::chain_seed` / `initial_chain_seed`,
    /// which is the one place that decides between the zero block and the
    /// cross-file bridge; a call that names `ZERO_BLOCK_HASH` directly is the
    /// defect this pins, and it is invisible to any test that never rotates.
    #[test]
    fn no_replay_site_hardcodes_the_zero_block_seed() {
        let production = production_source();
        assert!(
            production.contains("fn initial_chain_seed"),
            "the scan must see the production half of this file"
        );

        let mut offenders = Vec::new();
        for (idx, _) in production.match_indices("read_and_verify_entry_chain(") {
            let call = &production[idx..];
            let end = call.find(")?").unwrap_or(call.len().min(240));
            let call = &call[..end];
            if call.contains("ZERO_BLOCK_HASH") {
                let line = production[..idx].lines().count();
                offenders.push(format!("line {line}: {}", call.replace('\n', " ")));
            }
        }
        assert!(
            offenders.is_empty(),
            "replay sites must seed through chain_seed()/initial_chain_seed, \
             never the zero block directly:\n{}",
            offenders.join("\n")
        );
    }

    /// Runs the verifier's chain walk and reports whether it passes.
    fn verify_log_is_clean(path: &Path) -> bool {
        crate::audit_log::verify::verify_log(path, None).is_ok()
    }

    /// A log replaced underneath the writer AND grown past the rotation
    /// threshold refuses, and archives nothing.
    ///
    /// The identity check runs before the rotation decision, which is the one
    /// moment the handle and the path are legitimately allowed to diverge.
    /// Reversing the two would rename a file the writer never verified into an
    /// archive and start a fresh chain on top of it, turning a substituted log
    /// into a rotation the chain walk accepts.
    #[test]
    fn a_replaced_log_over_the_rotation_threshold_refuses_and_archives_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());

        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        let anchored_bytes = fs::read(&path).unwrap();

        // A replacement that is both a different file and over the threshold.
        let replacement = dir.path().join("replacement.jsonl");
        let mut padded = anchored_bytes.clone();
        padded.resize(
            usize::try_from(crate::audit_log::rotation::ROTATION_THRESHOLD_BYTES).unwrap() + 1,
            b'\n',
        );
        fs::write(&replacement, &padded).unwrap();
        fs::rename(&replacement, &path).unwrap();

        let err = writer
            .write_entry(make_entry(""))
            .expect_err("a replaced log must refuse before anything is archived");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. } if *reason == LOG_REPLACED_REASON
            ),
            "the refusal must name the replacement, not the size: {err:?}"
        );

        let archives: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| is_rotated_sibling("audit.jsonl", name))
            .collect();
        assert!(
            archives.is_empty(),
            "a refused append must archive nothing: {archives:?}"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            padded.len() as u64,
            "the file at the path is untouched by the refusal"
        );
    }
}
