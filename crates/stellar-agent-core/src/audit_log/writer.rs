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
//! (`<log>.lock`, next to the log — see `lock_sidecar_path` and
//! `crate::audit_log::lock::AuditWriterLock`) using
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
//! The sidecar lock is `std::fs::File::try_lock`, which is `flock` on Linux
//! and macOS and `LockFileEx` on Windows.  It is non-blocking and returns
//! `Err(WouldBlock)` when another open file description or handle holds the
//! lock.  The lock is released when the writer's `AuditWriterLock` drops;
//! the guard unlocks before it closes the handle.
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
//! entry that was not first written and fsynced to the log.  The sidecar is
//! replaced atomically, through a temp file and a rename, so a crash never
//! leaves a torn tag.  A keyed writer that opens a file with entries and no
//! sidecar writes the tag only when it can prove the file is its lineage's:
//! the anchor check proved the file from byte 0 (the anchored prefix is
//! current, advanced past, or the file a completed rotation created; see
//! `AnchorOutcome::proved_the_file`), and the replayed chain root starts at
//! offset 0.  It writes it before its first append.  An adopted or otherwise
//! unproved file, or one whose first entry does not start at byte 0, keeps no
//! tag; `audit reanchor`, the operator's acknowledgement of the file as it
//! stands, writes it for a chain root at offset 0, and `profile
//! rotate-audit-key` re-signs every file.  Conceptually, a
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
//! The handoff is always its file's last entry. A rotation whose renames fail
//! leaves it pending, and so does any replay that finds the active file ending
//! on one: the next append of any row first completes the rename under the
//! handoff's archive name, and a writer whose handoff write, flush, or fsync
//! failed rebuilds its state from the file before that append. Neither rename
//! replaces an existing file. Each archive name sorts after every existing
//! archive of the log, so the name order is the creation order whatever the
//! clock says.
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
    sync::{Arc, Mutex, OnceLock},
};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    binding::BindingHistory,
    chain::{ZERO_BLOCK_HASH, decode_hash, encode_hash, sign_chain_root},
    entry::AuditEntry,
    rotation::{
        MarkerNamesNoBoundary, PruneMarker, PruneMarkerData, PruneSeed, oldest_retained_seed,
        read_prune_marker,
    },
    schema::{EventKind, TipAnchorReason},
    tip_anchor::{
        KeyedAuditAccess, PriorAnchoring, TipAnchor, TipAnchorStore, TipAnchorStoreError,
    },
};
use crate::timefmt::current_iso8601_utc;

// Re-export rotation constants at the writer module level for crate-internal
// consumers and tests that currently import from this module.
pub use super::rotation::{MAX_ROTATED_FILES, ROTATION_THRESHOLD_BYTES};

#[cfg(test)]
static FORCE_NEXT_ROTATION_CREATE_FAILURE_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

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

/// Reason for a log that extends past where this writer last appended.
///
/// Extra bytes have no place in the writer's cached chain. The next append
/// must refuse before it can join a foreign row or a torn prefix.
const LOG_GREW_REASON: &str = "the log is longer than the writer's last append";

/// A test hook run on the just-rotated archive's path right after the rename.
#[cfg(test)]
type RotationRenameHook = Box<dyn FnOnce(&Path) + Send + Sync>;

/// Longest row the writer appends, newline included.
///
/// An honest row stays within a few kilobytes: [`super::entry::MAX_ENTRY_BYTES`]
/// (4096) bounds the argument keys and every recorded string is capped. The cap
/// is 256 times that, so no row the wallet builds reaches it, and an append
/// over it refuses with [`WriterError::RowTooLarge`] and never writes the row.
/// The prune reads archives within the same bound, so every row the writer
/// appends stays readable to it.
pub const MAX_ROW_BYTES: u64 = 1024 * 1024;

/// Reason for a file whose replay reaches the anchored tip at the anchored
/// offset through a different number of entries.
///
/// The tip hash and the offset fix only where the anchored prefix ends. The
/// count is what fixes where it starts: blank lines that replace a removed
/// prefix keep the offset and the tip, and change only the count.
const LOG_COUNT_REASON: &str = "the entries up to the anchored offset are not the anchored count";

/// Reason for a file whose anchored entry does not end exactly at the
/// anchored offset.
///
/// The writer ends every row with one `\n` right after its JSON, so the anchored
/// entry's line ends on the byte before the anchored offset. A reader that skips
/// whitespace still finds the entry when bytes around it changed, for example a
/// carriage return inserted before its newline, and such a file proves nothing
/// about where the anchored prefix ends.
const LOG_ENTRY_END_REASON: &str = "the anchored entry does not end at the anchored offset";

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
    /// The drain lock `<path>.drain.lock`, held for the writer's whole life
    /// when the writer drains the audit outbox, and `None` otherwise.
    ///
    /// Taken only after the sidecar lock, so a writer that lost the sidecar
    /// never holds it. Another process that finds the sidecar lock held reads
    /// this lock to learn whether the holder drains. Declared before `_lock`
    /// because fields drop in declaration order: the drain lock is released
    /// first, so a held drain lock never outlives the sidecar lock it vouches
    /// for.
    _drain_lock: Option<crate::audit_log::lock::AuditWriterLock>,
    /// Exclusive advisory lock on the sidecar `<path>.lock` file.
    ///
    /// Held for the entire `AuditWriter` lifetime, including across every
    /// rotation — never released or re-acquired until the writer drops.  The
    /// log file at `path` itself carries no lock; see the module-level
    /// "Single-writer invariant" and "Why the sidecar, not the log file"
    /// sections.  This field is never read; its only purpose is to hold the
    /// lock for as long as the `AuditWriter` lives.
    _lock: crate::audit_log::lock::AuditWriterLock,
    /// `true` for checked and acknowledgement writers with a tip-anchor store.
    ///
    /// A draining writer drains the outbox at open after anchor
    /// reconciliation, in every [`AuditWriter::verify_tip_anchor`] (which
    /// every registry cache hit runs), and at the start of every
    /// [`AuditWriter::write_entry`] and [`AuditWriter::write_built`]. A queued
    /// row therefore precedes the writer's own next row.
    drains: bool,
    /// `true` for a writer opened for an outbox-loss acknowledgement, until
    /// [`AuditWriter::acknowledge_outbox_loss`] succeeds.
    ///
    /// While it is set, the drain at open and in
    /// [`AuditWriter::verify_tip_anchor`] is deferred, and only such a writer
    /// acknowledges a loss.
    acknowledge_outbox: bool,
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
    /// The chain hash the active segment's first entry links to.
    segment_start_hash: [u8; 32],
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
    /// Length established by the latest replay or successful append. A replay
    /// can include trailing blank lines beyond the last entry's anchor offset.
    checked_len: u64,
    /// An anchor write that failed and is still outstanding.
    ///
    /// The value can name a durable tip (an append's new entry), a rotation's
    /// handoff in the next file generation, or a row not yet written (the row
    /// a refused append owed). The append path writes the anchor best-effort,
    /// because the entry is already durable and a keyring failure must not be
    /// reported as a failed append. A later anchor write replaces the value,
    /// and a successful write clears it. The next append retries the value
    /// before it appends anything, which repairs any number of missed writes
    /// in one go, and a rotation's handoff survives the swap to an empty
    /// active file, where the writer has no entry of its own to rebuild it
    /// from. Value actions call [`AuditWriter::require_anchor_current`] before
    /// and after their pre-action row, so they never proceed while an anchor
    /// write is outstanding.
    pending_tip_anchor: Option<TipAnchor>,
    /// Whether the writer was opened with an anchor store in the checked mode,
    /// the only shape whose tip facts [`AuditWriter::verified_tip_facts`]
    /// reports. A writer opened for repair, or with no anchor store, never is.
    checked_open: bool,
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
    /// Whether the profile's audit binding was recorded before this writer was
    /// opened, as the opener established it.
    ///
    /// One of the facts [`PriorAnchoring::find`] weighs when no anchor is
    /// stored: a recorded binding means a keyed use reached this log before,
    /// so its anchor should be there.
    binding: BindingHistory,
    /// Test-only fault seam for the write-entry durability invariant.
    #[cfg(test)]
    fail_after_entry_before_sidecar: bool,
    /// Test-only fault seam that skips the anchor write while still appending
    /// and fsyncing the entry — the crash window between the entry's
    /// `sync_data` and the anchor write.
    #[cfg(test)]
    skip_tip_anchor_write: bool,
    /// Test-only fault seam: the number of further appends allowed to succeed
    /// before the next one fails, or `None` for no fault.
    #[cfg(test)]
    appends_before_fault: Option<usize>,
    /// Test-only fault seam for a crash between a drain's appends and the
    /// outbox truncation: the drain appends and returns without truncating.
    #[cfg(test)]
    skip_outbox_truncate: bool,
    /// Test-only fault seam that stops a prune after its durable marker write,
    /// modelling a crash before the archive's deletion.
    #[cfg(test)]
    skip_prune_removal: bool,
    /// Test-only fault seam: the append's `write_all` completes and its
    /// `sync_data` reports failure, leaving a full line the writer's state does
    /// not account for.
    #[cfg(test)]
    fail_sync_after_entry_write: bool,
    /// Test-only fault seam: the rotation handoff's `write_all` completes and
    /// its `sync_data` reports failure, leaving the handoff in the file and
    /// unaccounted for in the writer's state.
    #[cfg(test)]
    fail_sync_after_handoff_write: bool,
    /// Test-only fault seam run on the archive path right after a rotation's
    /// rename and before the new active file exists, modelling a file swapped
    /// in under the just-rotated archive's name.
    #[cfg(test)]
    after_rotation_rename: Option<RotationRenameHook>,
    /// Test-only fault seam: the number of further rotation attempts whose
    /// renames fail after the handoff is in place.
    #[cfg(test)]
    rotation_renames_to_fail: u32,
    /// Test-only seam: the current time, in archive-name form, that every
    /// later rotation names its archive from.
    #[cfg(test)]
    archive_clock: Option<String>,
    /// The rotation handoff the active file ends on, when its rotation has
    /// not completed: the renames failed, or the process stopped before them.
    ///
    /// The next rotation attempt renames the file under this handoff's archive
    /// name and appends no second handoff, so every archive holds exactly one
    /// handoff, its last entry. Any appended entry clears it.
    pending_handoff: Option<PendingHandoff>,
    /// Set while a rotation handoff is being written, and cleared once the
    /// writer's state accounts for it.
    ///
    /// A failed write, flush, or fsync leaves it set with none, part, or all
    /// of the handoff in the file. The next append then rebuilds the state
    /// from the file, or refuses, before it rotates or chains a row; see
    /// [`AuditWriter::append_rotation_handoff`].
    handoff_unsettled: bool,
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

/// Counts of permissions revoked before acknowledging an outbox loss.
#[derive(Debug, Clone, Copy, Default)]
pub struct RevokedCounts {
    /// Decided, unexpired, unconsumed approvals removed.
    pub approvals: usize,
    /// Toolset grants removed.
    pub grants: usize,
}

/// The result of acknowledging an outbox loss.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OutboxLossReport {
    /// Committed rows before acknowledgement.
    pub expected_rows: u64,
    /// Complete rows found in the outbox.
    pub found_rows: u64,
    /// Remaining rows appended after the acknowledgement.
    pub drained: usize,
    /// Approvals revoked by the caller.
    pub revoked_approvals: usize,
    /// Grants revoked by the caller.
    pub revoked_grants: usize,
}

/// How [`AuditWriter::open`] treats an attached tip-anchor store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TipAnchorOpenMode {
    /// Run the check, adopting an absent anchor that nothing shows was ever
    /// written and absorbing appends made ahead of it. A rolled-back or
    /// truncated file is refused, and so is an absent anchor that
    /// [`PriorAnchoring`] shows was written before.
    Check,
    /// Check the anchor and hold the drain lock, deferring the initial drain.
    Acknowledge,
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

impl AnchorOutcome {
    /// Whether the check proved the active file from byte 0 against an anchor
    /// this writer's lineage stored.
    ///
    /// [`Self::Current`] and [`Self::Advanced`] replayed the file from byte 0
    /// and reached the anchored tip at the anchored offset through exactly the
    /// anchored count; an advance also chained every later entry from that
    /// tip. [`Self::RotationCompleted`] found the anchor on the handoff the
    /// file's first entry chains from, so the anchored prefix of this file is
    /// empty and all of it chains from the anchored tip. An adoption had no
    /// anchor to prove anything against.
    fn proved_the_file(&self) -> bool {
        matches!(
            self,
            Self::Current | Self::Advanced | Self::RotationCompleted
        )
    }
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
    /// Classifies a raw stored anchor value read from a store.
    ///
    /// `None` is [`Self::Absent`]. A value that does not parse is
    /// [`Self::Unusable`], described by its shape and never echoed.
    #[must_use]
    pub fn from_raw(raw: Option<&str>) -> Self {
        let Some(raw) = raw else {
            return Self::Absent;
        };
        match TipAnchor::parse(raw.trim()) {
            Ok(anchor) => Self::Usable(anchor),
            Err(e) => Self::Unusable {
                shape: describe_anchor_shape(Some(raw)),
                reason: e.to_string(),
            },
        }
    }

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

/// One condition an operator acknowledged in a re-anchor, in the order its
/// `audit_tip_anchored` row is appended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReanchorAcknowledgement {
    /// The current path's stored anchor disagreed with its log. The row has
    /// reason `rollback_acknowledged` and names this path's superseded anchor.
    Rollback,
    /// The profile's audit binding changed. The row has reason
    /// `binding_changed` and names `previous_anchor`.
    BindingChange {
        /// The anchor of the log path the previous binding named, as
        /// `<entry count>:<end offset>`. `None` when nothing was anchored there
        /// or the previous binding was unreadable.
        previous_anchor: Option<String>,
    },
}

/// Why an append refused before its row was written.
#[derive(Debug)]
enum AppendRefusal {
    /// The log at the path stopped being the log the writer holds. The caller
    /// anchors the row it owed, so the refusal outlives the process.
    LogMoved(WriterError),
    /// Every other refusal. Nothing is anchored.
    Other(WriterError),
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
    /// Number of queued outbox rows the repair appended after its own rows, or
    /// `None` when the drain refused.
    ///
    /// A refused drain leaves every queued row in the outbox, and the next
    /// drain appends again the rows it appended before the refusal.
    pub outbox_drained: Option<usize>,
    /// Why the outbox could not be drained after a successful repair, led by
    /// its `audit.*` sub-code, or `None` when the drain succeeded.
    ///
    /// The sub-code is `audit.outbox_unusable`, `audit.outbox_busy`,
    /// `audit.outbox_rows_missing`, or the
    /// condition an append of the drain refused on, such as `audit.io_error`.
    /// The repair itself stands either way; the rows stay queued for the next
    /// drain.
    pub outbox_refusal: Option<String>,
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

/// What [`AuditWriter::verified_tip_facts`] established about a checked,
/// anchored writer after verification and draining.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedTipFacts {
    /// The chain hash the active file's first entry links to.
    pub segment_start_hash: [u8; 32],
    /// Entries in the active file after the drain. A rotation resets it.
    pub entry_count: u64,
    /// The active file's tip: the hash of its last entry, or, for an empty
    /// file, the hash its first entry chains from.
    pub tip_hash: [u8; 32],
    /// [`super::tip_anchor::log_path_sha256`] of the active log path.
    pub log_path_sha256: [u8; 32],
    /// Whether the durable anchor names exactly this tip and no anchor write
    /// is still owed.
    pub anchor_covers_tip: bool,
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
    /// A writer opened with an anchor store takes `<log>.drain.lock` and
    /// drains the audit outbox after reconciliation. The adoption row is
    /// appended even when the drain refuses.
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
    /// - Every error of [`AuditWriter::drain_outbox`], when `access` is
    ///   supplied.
    pub fn open(path: PathBuf, access: Option<KeyedAuditAccess>) -> Result<Self, WriterError> {
        let (hmac_key, tip_anchor, binding) = match access {
            Some(access) => {
                let binding = access.binding_history();
                let (key, store) = access.into_parts();
                (Some(key), Some(store), binding)
            }
            None => (None, None, BindingHistory::NotRecorded),
        };
        Self::open_inner(
            path,
            hmac_key,
            tip_anchor,
            binding,
            TipAnchorOpenMode::Check,
        )
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
        Self::open_inner(
            path,
            Some(hmac_key),
            None,
            BindingHistory::NotRecorded,
            TipAnchorOpenMode::Check,
        )
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
    /// [`WriterError::TipAnchorMismatch`]. An absent anchor that
    /// [`PriorAnchoring`] shows was written before is refused with
    /// [`WriterError::TipAnchorMissing`]; `binding` says whether the profile's
    /// audit binding was recorded before this open, which is one such fact.
    /// From then on every [`AuditWriter::write_entry`] advances the anchor.
    ///
    /// The writer takes `<log>.drain.lock` and drains the audit outbox after
    /// reconciliation. The adoption row is appended even when the drain
    /// refuses.
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
    /// - [`WriterError::TipAnchorMissing`] when no anchor is stored and the log
    ///   shows it was anchored before.
    /// - [`WriterError::TipAnchorStore`] when the anchor cannot be read or
    ///   written.
    /// - Every error of [`AuditWriter::drain_outbox`].
    pub fn open_with_tip_anchor(
        path: PathBuf,
        hmac_key: Option<Zeroizing<[u8; 32]>>,
        tip_anchor: Arc<dyn TipAnchorStore>,
        binding: BindingHistory,
    ) -> Result<Self, WriterError> {
        Self::open_inner(
            path,
            hmac_key,
            Some(tip_anchor),
            binding,
            TipAnchorOpenMode::Check,
        )
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
        Self::open_inner(
            path,
            hmac_key,
            Some(tip_anchor),
            BindingHistory::NotRecorded,
            TipAnchorOpenMode::Repair,
        )
    }

    /// Opens for outbox-loss acknowledgement while enforcing the tip anchor.
    /// The drain lock is held, and the initial outbox drain is deferred.
    ///
    /// # Errors
    /// Returns the errors of a checked writer open, except outbox drain errors.
    pub fn open_for_outbox_acknowledgement(
        path: PathBuf,
        hmac_key: Option<Zeroizing<[u8; 32]>>,
        tip_anchor: Arc<dyn TipAnchorStore>,
        binding: BindingHistory,
    ) -> Result<Self, WriterError> {
        Self::open_inner(
            path,
            hmac_key,
            Some(tip_anchor),
            binding,
            TipAnchorOpenMode::Acknowledge,
        )
    }

    fn open_inner(
        path: PathBuf,
        hmac_key: Option<Zeroizing<[u8; 32]>>,
        tip_anchor: Option<Arc<dyn TipAnchorStore>>,
        binding: BindingHistory,
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

        // A draining writer takes the drain lock here, while it holds the
        // sidecar lock. An opener that lost the sidecar never holds it, so a
        // held drain lock always means a draining writer owns the log. The
        // repair writer and writers without an anchor store do not drain and
        // do not take it.
        let drains = tip_anchor.is_some() && anchor_mode != TipAnchorOpenMode::Repair;
        let drain_lock = if drains {
            Some(super::outbox::acquire_drain_lock(&path)?)
        } else {
            None
        };

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
        let segment_start_hash = decode_hash(&seed).map_err(WriterError::Hash)?;
        let mut scan = if is_new_file {
            ChainScan::empty(seed)
        } else {
            read_and_verify_entry_chain(&file, 0, &seed)?
        };
        let root = scan.first_entry.take();
        let pending_handoff = PendingHandoff::from_scan(&path, &scan)?;

        let mut writer = Self {
            path,
            _drain_lock: drain_lock,
            _lock: lock,
            drains,
            acknowledge_outbox: anchor_mode == TipAnchorOpenMode::Acknowledge,
            file,
            last_hash: scan.last_hash,
            segment_start_hash,
            is_new_file,
            hmac_key,
            entry_count: scan.entry_count,
            end_offset: scan.end_offset,
            checked_len: scan.checked_len,
            pending_tip_anchor: None,
            log_diverged: None,
            owed_row_anchored: false,
            checked_open: tip_anchor.is_some() && anchor_mode != TipAnchorOpenMode::Repair,
            tip_anchor,
            binding,
            #[cfg(test)]
            fail_after_entry_before_sidecar: false,
            #[cfg(test)]
            skip_tip_anchor_write: false,
            #[cfg(test)]
            appends_before_fault: None,
            #[cfg(test)]
            skip_outbox_truncate: false,
            #[cfg(test)]
            skip_prune_removal: false,
            #[cfg(test)]
            fail_sync_after_entry_write: false,
            #[cfg(test)]
            fail_sync_after_handoff_write: false,
            #[cfg(test)]
            after_rotation_rename: None,
            #[cfg(test)]
            rotation_renames_to_fail: 0,
            #[cfg(test)]
            archive_clock: None,
            pending_handoff,
            handoff_unsettled: false,
            partial_rotation_archive: None,
        };

        if writer.tip_anchor.is_some() && anchor_mode != TipAnchorOpenMode::Repair {
            let outcome = writer.reconcile_tip_anchor()?;
            // Only an outcome that proved the file from byte 0 against the
            // anchor, and before any append, which may rotate it.
            if outcome.proved_the_file() {
                writer.repair_root_sidecar(root.as_ref())?;
            }
            let anchored_count = writer.entry_count;
            // Drain point: at open, after anchor reconciliation and before
            // any row of the writer's own, so a queued consent row enters
            // the log before the opener can act on the approval it records.
            writer.drain_then_record_adoption(outcome, anchored_count)?;
        }

        Ok(writer)
    }

    /// Writes the active file's chain-root sidecar when a keyed writer finds a
    /// file with entries and none beside it.
    ///
    /// A keyed writer writes the tag after the first entry is durable, so a
    /// crash or a failed sidecar write in between leaves a keyed file with no
    /// tag. A tag binds where a file starts, so it is minted only for content
    /// this writer's lineage provably wrote: `root` comes from a replay of the
    /// whole file that the caller accepted, the open's after an anchor check
    /// that proved the file from byte 0 (see [`AnchorOutcome::proved_the_file`]),
    /// or a re-anchor's after the operator acknowledged the file. The root
    /// entry must also start at byte 0: an honest writer writes no blank line
    /// and no indentation, so any byte before it is foreign and nothing is
    /// written. The tag covers exactly that entry, as the first append would
    /// have written it, and is written before the writer's first append can
    /// rotate the file into an archive. A sidecar that exists is left as it is,
    /// whatever it holds.
    fn repair_root_sidecar(&self, root: Option<&ChainRoot>) -> Result<(), WriterError> {
        let (Some(key), Some(root)) = (&self.hmac_key, root) else {
            return Ok(());
        };
        if root.offset != 0 {
            tracing::warn!(
                log = %basename_lossy_path(&self.path),
                offset = root.offset,
                "audit log chain-root sidecar is missing and the first entry does not \
                 start the file; no tag is written"
            );
            return Ok(());
        }
        match fs::symlink_metadata(hmac_sidecar_path(&self.path)) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(WriterError::Io(e)),
        }
        let body = root
            .entry
            .canonical_json_body()
            .map_err(WriterError::Serialise)?;
        let tag = sign_chain_root(key.as_ref(), &body)
            .map_err(|e| WriterError::Io(io::Error::other(format!("HMAC sign failed: {e}"))))?;
        self.write_root_hmac_sidecar(&tag)?;
        tracing::warn!(
            log = %basename_lossy_path(&self.path),
            "audit log chain-root sidecar was missing; written from the verified first entry"
        );
        Ok(())
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
    /// lock release. Build the row in the `build` closure of
    /// [`AuditWriter::write_built`], which drains the outbox and completes any
    /// rotation before the tip is read.
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
    /// A draining writer first drains the audit outbox, so every queued
    /// consent row precedes this entry. A writer that does not drain appends
    /// directly.
    ///
    /// Steps of the append itself:
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
    /// - Every error of [`AuditWriter::drain_outbox`], for a draining writer.
    ///   The entry is then not appended.
    /// - [`WriterError::Io`] on I/O failure.
    /// - [`WriterError::Serialise`] if the entry cannot be serialised.
    /// - [`WriterError::Hash`] if the hash computation fails.
    /// - [`WriterError::RowTooLarge`] if the serialized row is longer than
    ///   [`MAX_ROW_BYTES`]. Nothing is written.
    ///
    /// An anchor-write failure after fsync retries once and leaves the append
    /// successful. Value actions call [`Self::require_anchor_current`] around
    /// their pre-action row to withhold the action while repair is owed.
    pub fn write_entry(&mut self, mut entry: AuditEntry) -> Result<(), WriterError> {
        refuse_oversized_row(&mut entry)?;
        if self.drains {
            self.drain_outbox()?;
        }
        self.append_checked(entry)
    }

    /// Drains the audit outbox, then builds an entry from the writer's current
    /// state and appends it, with nothing appended in between.
    ///
    /// `build` reads the tip it needs from the writer, for example
    /// [`AuditWriter::current_chain_tip`]. The drain runs first. Every check the
    /// append makes, and any rotation it needs, runs next, so a rotation's
    /// handoff entry is in place before `build` reads the tip. The append then
    /// follows `build` directly, so the tip `build` reads is the predecessor of
    /// the entry it builds. A caller that reads the tip before
    /// [`AuditWriter::write_entry`] gets no such guarantee. That call's own drain
    /// and rotation can land rows in between.
    ///
    /// A writer that does not drain builds and appends without draining.
    ///
    /// # Errors
    ///
    /// Every error of [`AuditWriter::write_entry`].
    pub fn write_built<F>(&mut self, build: F) -> Result<(), WriterError>
    where
        F: FnOnce(&Self) -> AuditEntry,
    {
        if self.drains {
            self.drain_outbox()?;
        }
        if let Err(refusal) = self.prepare_append() {
            // When the log moved under the writer, the row this call owed is
            // built only to anchor it.
            return Err(match refusal {
                AppendRefusal::LogMoved(e) => {
                    self.anchor_owed_row(build);
                    e
                }
                AppendRefusal::Other(e) => e,
            });
        }
        let entry = build(self);
        self.commit_append(entry)
    }

    /// Returns `true` when this writer drains the audit outbox.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn drains_outbox(&self) -> bool {
        self.drains
    }

    /// Appends every row queued in the audit outbox to the log, then empties
    /// the outbox.
    ///
    /// Requires an attached tip-anchor store, which holds the outbox
    /// commitment. Under the outbox lock it reads the file and the
    /// commitment, checks the committed prefix, discards a final segment with
    /// no terminating newline (an append that never returned `Ok`) with a
    /// `warn`, and parses every complete line before appending any. Each entry
    /// keeps the consent timestamp it was queued with. Only after every entry
    /// is appended is the commitment reset to zero, and only then is the
    /// outbox truncated to zero.
    ///
    /// Delivery is at least once. A refusal leaves the outbox unchanged, and
    /// the entries appended before the refusal are appended again by the next
    /// drain, with the same `request_id`. Queued rows are committed in the
    /// keyring until they are drained.
    ///
    /// Returns the number of rows appended.
    ///
    /// # Errors
    ///
    /// - [`WriterError::TipAnchorUnavailable`] without an attached store.
    /// - [`WriterError::OutboxBusy`] when the outbox lock stays held.
    /// - [`WriterError::TipAnchorStore`] when the commitment cannot be read or
    ///   reset.
    /// - [`WriterError::OutboxRowsMissing`] when committed rows are missing,
    ///   changed, or reordered. Nothing is appended and the outbox is left
    ///   unchanged.
    /// - [`WriterError::OutboxUnusable`] when a complete line does not parse.
    ///   Nothing is appended and the outbox is left unchanged.
    /// - Every error of the append, for example
    ///   [`WriterError::TipAnchorMismatch`]. The outbox is left unchanged.
    /// - [`WriterError::Io`] when the outbox cannot be read or truncated.
    pub fn drain_outbox(&mut self) -> Result<usize, WriterError> {
        let store = self
            .tip_anchor
            .clone()
            .ok_or(WriterError::TipAnchorUnavailable)?;
        let Some(batch) = super::outbox::OutboxBatch::take(&self.path, store.as_ref())? else {
            return Ok(0);
        };
        if batch.is_empty() {
            return Ok(0);
        }
        let entries = batch.parse_entries()?;
        let drained = entries.len();
        for entry in entries {
            self.append_checked(entry)?;
        }
        store
            .store_outbox_state(&super::outbox::OutboxState::default())
            .map_err(WriterError::TipAnchorStore)?;
        #[cfg(test)]
        if self.skip_outbox_truncate {
            return Ok(drained);
        }
        batch.clear()?;
        if drained > 0 {
            tracing::debug!(
                log = %basename_lossy_path(&self.path),
                drained,
                "audit outbox drained into the log"
            );
        }
        Ok(drained)
    }

    /// Reports a loss of committed outbox rows, checked under the outbox lock
    /// and released before it returns.
    ///
    /// `Ok(None)` means the outbox holds its committed prefix unchanged and in
    /// order. When it does not, every complete line that remains is parsed
    /// too, so a loss whose acknowledgement would refuse on an unusable line
    /// refuses here, before the caller revokes anything.
    ///
    /// # Errors
    ///
    /// - [`WriterError::TipAnchorUnavailable`] without an attached store.
    /// - [`WriterError::OutboxBusy`] when the outbox lock stays held.
    /// - [`WriterError::TipAnchorStore`] when the commitment cannot be read.
    /// - [`WriterError::OutboxUnusable`] when a loss exists and a remaining
    ///   complete line does not parse.
    /// - [`WriterError::Io`] when the outbox cannot be read.
    pub fn outbox_loss(&self) -> Result<Option<super::outbox::OutboxLoss>, WriterError> {
        let store = self
            .tip_anchor
            .as_ref()
            .ok_or(WriterError::TipAnchorUnavailable)?;
        let batch = super::outbox::OutboxBatch::read_locked(&self.path, store.as_ref())?;
        let Some(loss) = batch.loss() else {
            return Ok(None);
        };
        batch.parse_entries()?;
        Ok(Some(loss))
    }

    /// Records a loss of committed outbox rows, then drains the complete rows
    /// that remain, all under the outbox lock.
    ///
    /// Only a writer from [`AuditWriter::open_for_outbox_acknowledgement`]
    /// acknowledges, because only that open checks the tip anchor and defers
    /// the drain the loss refuses. The caller revokes the profile's decided
    /// approvals and grants first and passes their counts in `revoked`.
    ///
    /// Every remaining line is parsed before the
    /// `audit_outbox_loss_acknowledged` row is appended, so an unusable line
    /// refuses with nothing written. After the row, the remaining entries are
    /// appended in queue order, the commitment is reset to zero, and the
    /// outbox is truncated. A refusal after the row leaves the commitment and
    /// the outbox in place, so the loss still holds and a rerun records it
    /// again.
    ///
    /// # Errors
    ///
    /// - [`WriterError::Io`] of kind `InvalidInput` on a writer opened any
    ///   other way, before anything is read or written.
    /// - [`WriterError::TipAnchorUnavailable`] without an attached store.
    /// - [`WriterError::OutboxBusy`] when the outbox lock stays held.
    /// - [`WriterError::TipAnchorStore`] when the commitment cannot be read or
    ///   reset.
    /// - [`WriterError::OutboxLossNotFound`] when the outbox holds its
    ///   committed prefix. Nothing is written.
    /// - [`WriterError::OutboxUnusable`] when a remaining complete line does
    ///   not parse. Nothing is written.
    /// - Every error of the appends, and [`WriterError::Io`] when the outbox
    ///   cannot be truncated.
    pub fn acknowledge_outbox_loss(
        &mut self,
        reason: &str,
        revoked: RevokedCounts,
    ) -> Result<OutboxLossReport, WriterError> {
        if !self.acknowledge_outbox {
            return Err(WriterError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an outbox loss is acknowledged only through a writer opened for the \
                 acknowledgement",
            )));
        }
        let store = self
            .tip_anchor
            .clone()
            .ok_or(WriterError::TipAnchorUnavailable)?;
        let batch = super::outbox::OutboxBatch::read_locked(&self.path, store.as_ref())?;
        let loss = batch.loss().ok_or(WriterError::OutboxLossNotFound)?;
        let entries = batch.parse_entries()?;
        self.append_checked(AuditEntry::new_audit_outbox_loss_acknowledged(
            loss.expected_rows,
            loss.found_rows,
            reason,
            revoked.approvals,
            revoked.grants,
        ))?;
        let drained = entries.len();
        for entry in entries {
            self.append_checked(entry)?;
        }
        store
            .store_outbox_state(&super::outbox::OutboxState::default())
            .map_err(WriterError::TipAnchorStore)?;
        batch.clear()?;
        self.acknowledge_outbox = false;
        Ok(OutboxLossReport {
            expected_rows: loss.expected_rows,
            found_rows: loss.found_rows,
            drained,
            revoked_approvals: revoked.approvals,
            revoked_grants: revoked.grants,
        })
    }

    /// Appends `entry` with every check an append makes, without draining.
    ///
    /// The divergence check, the anchor retry, rotation, the hash, the write,
    /// the fsync, the chain-root sidecar, and the anchor advance all run here,
    /// through [`Self::prepare_append`] and [`Self::commit_append`].
    /// [`AuditWriter::write_entry`], [`AuditWriter::write_built`], and
    /// [`AuditWriter::drain_outbox`] append only through these two methods.
    fn append_checked(&mut self, mut entry: AuditEntry) -> Result<(), WriterError> {
        refuse_oversized_row(&mut entry)?;
        if let Err(refusal) = self.prepare_append() {
            return Err(match refusal {
                AppendRefusal::LogMoved(e) => {
                    self.anchor_owed_row(|_| entry);
                    e
                }
                AppendRefusal::Other(e) => e,
            });
        }
        self.commit_append(entry)
    }

    /// Anchors the row an append owed when the log moved under the writer,
    /// once per writer. `owed` builds that row and runs only while no owed
    /// row is anchored.
    fn anchor_owed_row(&mut self, owed: impl FnOnce(&Self) -> AuditEntry) {
        if !self.owed_row_anchored {
            let mut entry = owed(self);
            self.anchor_the_refused_row(&mut entry);
        }
    }

    /// Runs every check an append makes before its row exists, and completes
    /// any rotation the append needs.
    ///
    /// After `Ok`, the writer's tip is the predecessor of the next row
    /// [`Self::commit_append`] writes, so a row built from that tip names its
    /// predecessor correctly.
    ///
    /// # Errors
    ///
    /// [`AppendRefusal::LogMoved`] when the log at the path stopped being the
    /// log this writer holds, and [`AppendRefusal::Other`] for every other
    /// refusal, including a failed rotation. An anchor-write failure remains
    /// best-effort, so post-action rows can still land.
    fn prepare_append(&mut self) -> Result<(), AppendRefusal> {
        #[cfg(test)]
        if let Some(remaining) = self.appends_before_fault.as_mut() {
            if *remaining == 0 {
                return Err(AppendRefusal::Other(WriterError::Io(io::Error::other(
                    "test fault: append refused",
                ))));
            }
            *remaining -= 1;
        }
        if let Some(archive_name) = &self.partial_rotation_archive {
            return Err(AppendRefusal::Other(WriterError::PartialRotation {
                archive_name: archive_name.clone(),
                active_locked_by: None,
            }));
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
        // A refusal here is durable, not just in-process: the caller anchors
        // the row the wallet owed in the keyring. No file at this path then
        // satisfies the anchor until an operator acknowledges what happened.
        self.refuse_if_log_moved_on_append()
            .map_err(AppendRefusal::LogMoved)?;

        // A rotation handoff whose write, flush, or fsync failed can sit in the
        // file unaccounted for. The state is rebuilt from the file first, so the
        // rotation below renames under that handoff rather than appending a
        // second one chained from the entry before it.
        self.settle_unsettled_handoff()
            .map_err(AppendRefusal::Other)?;

        // Repair an anchor left behind by an earlier failed write, before this
        // append moves the tip again. The value written names the entry most
        // recently fsynced, so it is safe at any point and subsumes however many
        // writes were missed.
        let _ = self.retry_tip_anchor_if_behind();

        // Rotate if needed before the row is built and written, so the
        // rotation's handoff entry is the row's predecessor. A file that ends on
        // a pending handoff takes no row before its rotation completes, whatever
        // its size: the handoff is always its file's last entry.
        if self.pending_handoff.is_some() || self.needs_rotation().map_err(AppendRefusal::Other)? {
            self.rotate().map_err(AppendRefusal::Other)?;
        }
        Ok(())
    }

    /// Writes `entry` after [`Self::prepare_append`] returned `Ok`, with
    /// nothing appended in between: the hash, the write, the fsync, the
    /// chain-root sidecar, and the anchor advance.
    ///
    /// # Errors
    ///
    /// [`WriterError::Io`], [`WriterError::Serialise`], or
    /// [`WriterError::Hash`] when the row cannot be hashed, serialised, or
    /// written. [`WriterError::RowTooLarge`] when the serialized row is longer
    /// than [`MAX_ROW_BYTES`]; nothing is written. Anchor writes retry once and
    /// remain best-effort after the row is durable. Call
    /// [`Self::require_anchor_current`] to gate a value action.
    fn commit_append(&mut self, mut entry: AuditEntry) -> Result<(), WriterError> {
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
        let bytes = line.len() as u64;
        if bytes > MAX_ROW_BYTES {
            return Err(WriterError::RowTooLarge {
                bytes,
                cap: MAX_ROW_BYTES,
            });
        }

        // O_APPEND write + fsync.
        self.file.write_all(&line)?;
        self.file.flush()?;
        #[cfg(test)]
        if self.fail_sync_after_entry_write {
            return Err(WriterError::Io(io::Error::other(
                "test fault: sync_data failed after a full write",
            )));
        }
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

        // Commit the durable chain state before either anchor-write attempt.
        // An anchor outage must leave the next append on this row's hash.
        self.entry_count = self.entry_count.saturating_add(1);
        self.end_offset = self.entry_end_offset()?;
        self.checked_len = self.end_offset;
        self.last_hash = current_hash;
        self.pending_handoff = None;
        let current = TipAnchor::new(self.entry_count, self.last_hash.clone(), self.end_offset);
        self.store_tip_anchor_best_effort(&current);
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

    /// Enables a test-only fault seam: `allowed` further appends succeed and
    /// the next one fails with an I/O error. `None` disables it.
    #[cfg(test)]
    pub(crate) fn set_appends_before_fault(&mut self, allowed: Option<usize>) {
        self.appends_before_fault = allowed;
    }

    /// Enables a test-only fault seam for a crash between a drain's appends
    /// and the outbox truncation.
    #[cfg(test)]
    pub(crate) fn set_skip_outbox_truncate(&mut self, enabled: bool) {
        self.skip_outbox_truncate = enabled;
    }

    /// Enables a test-only fault seam that fails an append's `sync_data` after
    /// its `write_all` completed.
    #[cfg(test)]
    pub(crate) fn set_fail_sync_after_entry_write(&mut self, enabled: bool) {
        self.fail_sync_after_entry_write = enabled;
    }

    /// Enables a test-only fault seam that fails a rotation handoff's
    /// `sync_data` after its `write_all` completed.
    #[cfg(test)]
    pub(crate) fn set_fail_sync_after_handoff_write(&mut self, enabled: bool) {
        self.fail_sync_after_handoff_write = enabled;
    }

    /// Makes the renames of the next `attempts` rotation attempts fail after
    /// the handoff is in place, as a directory that refuses renames would.
    #[cfg(test)]
    pub(crate) fn set_rotation_renames_to_fail(&mut self, attempts: u32) {
        self.rotation_renames_to_fail = attempts;
    }

    /// Makes every later rotation of this writer name its archive as if the
    /// current time were `now`, a `YYYYMMDDTHHMMSSmmm` timestamp.
    #[cfg(test)]
    pub(crate) fn set_archive_clock_for_test(&mut self, now: &str) {
        self.archive_clock = Some(now.to_owned());
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
        let rotated_name = self.next_archive_name(stem)?;
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

    /// Writes the anchor value a failed write left owed, or refuses while it
    /// cannot be written. Writes no audit row.
    ///
    /// A value action calls this before its pre-action row and, under the
    /// guard that appended the row, right after it. The first call refuses a
    /// behind anchor before the row exists. The second catches a failed anchor
    /// write of the row itself, or of a row the outbox drain appended ahead of
    /// it, so the action never proceeds on a row the anchor does not cover.
    /// Plain appends do not call it: a row recording an action that already
    /// committed must land whether or not its anchor does.
    ///
    /// # Errors
    ///
    /// [`WriterError::TipAnchorStore`] when the owed anchor cannot be written,
    /// and the refusal an append reports when the log at the path moved or
    /// changed under the writer.
    pub fn require_anchor_current(&mut self) -> Result<(), WriterError> {
        self.refuse_if_log_moved_on_append()?;
        self.retry_tip_anchor_if_behind()
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
    /// A draining writer then drains the audit outbox, so this is a drain point
    /// of every registry cache hit. When reconciliation adopted the file, the
    /// adoption row follows the drained rows, and it is appended even when the
    /// drain refuses.
    ///
    /// # Errors
    ///
    /// - [`WriterError::TipAnchorMismatch`] when the file no longer contains the
    ///   anchored tip — it was rolled back, truncated, or replaced.
    /// - [`WriterError::TipAnchorStore`] when the anchor cannot be read or
    ///   written.
    /// - [`WriterError::Io`] / [`WriterError::Serialise`] /
    ///   [`WriterError::ChainBrokenAtOpen`] when the file cannot be replayed.
    /// - Every error of [`AuditWriter::drain_outbox`], for a draining writer.
    pub fn verify_tip_anchor(&mut self) -> Result<(), WriterError> {
        let outcome = self.reconcile_tip_anchor()?;
        let anchored_count = self.entry_count;
        self.drain_then_record_adoption(outcome, anchored_count)
    }

    /// The anchor store attached to this writer.
    #[must_use]
    pub fn tip_anchor_store(&self) -> Option<&Arc<dyn TipAnchorStore>> {
        self.tip_anchor.as_ref()
    }

    /// Verifies the log against its anchor, drains the outbox, and reports the
    /// facts of the final tip.
    ///
    /// Requires a writer opened with an anchor store in the checked mode.
    /// Runs [`AuditWriter::verify_tip_anchor`] (reconciliation, which first
    /// repairs an owed anchor write, then the drain), re-writes an anchor the
    /// drain's appends left owed, and only then compares the durable anchor
    /// with the tip. The facts report a lag only when the anchor still does
    /// not name the tip after that re-write. `entry_count` is taken after the
    /// drain. A verified empty log with no anchor written yet is covered at
    /// count zero, and so is an empty file a rotation created whose anchor
    /// names the archive's handoff.
    ///
    /// # Errors
    ///
    /// - [`WriterError::TipAnchorUnavailable`] for a writer opened without an
    ///   anchor store or for repair.
    /// - Every error of [`AuditWriter::verify_tip_anchor`], including an
    ///   anchor that cannot be read or an owed write that cannot be repaired.
    /// - [`WriterError::TipAnchorStore`] when the anchor cannot be read back.
    /// - [`WriterError::Hash`] when the tip hash does not decode.
    pub fn verified_tip_facts(&mut self) -> Result<VerifiedTipFacts, WriterError> {
        if !self.checked_open {
            return Err(WriterError::TipAnchorUnavailable);
        }
        self.verify_tip_anchor()?;
        // A drained row whose anchor write failed is owed; one more write is
        // attempted before the lag is reported. Its failure is the lag itself.
        if self.retry_tip_anchor_if_behind().is_err() {
            tracing::debug!(
                log = %basename_lossy_path(&self.path),
                "audit tip anchor still behind after the drain"
            );
        }
        let store = self
            .tip_anchor
            .clone()
            .ok_or(WriterError::TipAnchorUnavailable)?;
        let stored = store.load_anchor().map_err(WriterError::TipAnchorStore)?;
        let anchor_covers_tip = !self.anchor_behind()
            && match stored {
                None => self.entry_count == 0,
                Some(anchor) => {
                    anchor.tip_hash == self.last_hash
                        && (self.entry_count == 0
                            || (anchor.entry_count == self.entry_count
                                && anchor.end_offset == self.end_offset))
                }
            };
        Ok(VerifiedTipFacts {
            segment_start_hash: self.segment_start_hash,
            entry_count: self.entry_count,
            tip_hash: decode_hash(&self.last_hash).map_err(WriterError::Hash)?,
            log_path_sha256: super::tip_anchor::log_path_sha256(&self.path),
            anchor_covers_tip,
        })
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
    /// After its own row, the repair drains the audit outbox, so the queued
    /// rows follow the `audit_tip_anchored` row. A drain refusal does not undo
    /// the repair: it is reported in [`ReanchorReport::outbox_refusal`] and the
    /// rows stay queued.
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
        self.reanchor_acknowledging(&[ReanchorAcknowledgement::Rollback])
    }

    /// Moves the anchor to the active file's current tip and appends one
    /// `audit_tip_anchored` row per acknowledged condition, in order.
    ///
    /// [`AuditWriter::reanchor`] is this method with a single
    /// [`ReanchorAcknowledgement::Rollback`]. The whole active file is replayed
    /// first, the current tip is anchored, and the path's re-anchor counter is
    /// incremented once, so every row of one run carries the same count. A
    /// rollback row names this path's superseded anchor; a binding-change row
    /// names the anchor the caller supplies for the previous binding's path.
    /// Queued consent rows drain after every acknowledgement row is appended.
    /// A drain refusal leaves the repair in force and is reported in
    /// [`ReanchorReport::outbox_refusal`].
    ///
    /// # Errors
    ///
    /// The errors of [`AuditWriter::reanchor`]. An empty `acknowledged` list
    /// refuses with a [`WriterError::Io`] of kind `InvalidInput` before any
    /// write; every anchor move carries a row naming its reason.
    pub fn reanchor_acknowledging(
        &mut self,
        acknowledged: &[ReanchorAcknowledgement],
    ) -> Result<ReanchorReport, WriterError> {
        let store = self
            .tip_anchor
            .clone()
            .ok_or(WriterError::TipAnchorUnavailable)?;
        if acknowledged.is_empty() {
            return Err(WriterError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a re-anchor needs at least one acknowledged condition",
            )));
        }
        let previous = self.stored_tip_anchor()?;

        let scan = self.replay_active_file()?;
        self.adopt_scan_state(&scan)?;
        let repaired_count = scan.entry_count;
        if scan.entry_count > 0 {
            let repaired =
                TipAnchor::new(scan.entry_count, scan.last_hash.clone(), scan.end_offset);
            store
                .store_anchor(&repaired)
                .map_err(WriterError::TipAnchorStore)?;
        }
        // The operator acknowledged this file as it stands.
        self.repair_root_sidecar(scan.first_entry.as_ref())?;
        let reanchor_count = store
            .bump_reanchor_count()
            .map_err(WriterError::TipAnchorStore)?;

        // Each row advances the anchor past the one before; the report names
        // the anchor the operator asked for, which is what the refusal was
        // about. Every repair row records the entry count of the repaired tip.
        for acknowledgement in acknowledged {
            let (reason, previous_anchor) = match acknowledgement {
                ReanchorAcknowledgement::Rollback => (
                    TipAnchorReason::RollbackAcknowledged,
                    previous.coordinates(),
                ),
                ReanchorAcknowledgement::BindingChange { previous_anchor } => {
                    (TipAnchorReason::BindingChanged, previous_anchor.clone())
                }
            };
            self.append_checked(AuditEntry::new_audit_tip_anchored(
                reason,
                repaired_count,
                previous_anchor,
                Some(reanchor_count),
                uuid::Uuid::new_v4().to_string(),
            ))?;
        }

        // Queued rows follow the repair rows. A drain refusal leaves them
        // queued and the repair in force.
        let (outbox_drained, outbox_refusal) = match self.drain_outbox() {
            Ok(drained) => (Some(drained), None),
            Err(e) => {
                let detail = audit_log_unusable_detail(&e).unwrap_or_else(|| e.to_string());
                tracing::warn!(
                    log = %basename_lossy_path(&self.path),
                    error = %e,
                    "audit reanchor: the repair stands, and the audit outbox could not be drained"
                );
                (None, Some(detail))
            }
        };

        // The rows advanced the anchor past the repaired tip; report the
        // anchor as it now stands rather than the intermediate value.
        let current = store.load_anchor().map_err(WriterError::TipAnchorStore)?;
        Ok(ReanchorReport {
            previous,
            current,
            reanchor_count,
            outbox_drained,
            outbox_refusal,
        })
    }

    /// Whether the stored anchor disagrees with the active file, decided under
    /// this writer's lock.
    ///
    /// Both cases read a replay of the active file. An absent anchor disagrees
    /// when [`PriorAnchoring::find`] finds evidence of prior anchoring for
    /// `binding` and that replay's entry count and anchoring rows: the facts the
    /// writer's own missing-anchor refusal reads, so a rotated archive that no
    /// longer verifies cannot hide them. A present anchor is judged by
    /// [`super::verify::stored_anchor_disagrees_with_walk`]. It reads the
    /// store, the file, and the sidecar's metadata only: nothing is adopted,
    /// advanced, or written.
    ///
    /// # Errors
    ///
    /// - [`WriterError::TipAnchorUnavailable`] when no anchor store is attached.
    /// - [`WriterError::TipAnchorStore`] when the backend is unavailable.
    /// - [`WriterError::Io`] / [`WriterError::Serialise`] /
    ///   [`WriterError::ChainBrokenAtOpen`] when the file cannot be replayed.
    /// - [`WriterError::IntegrityViolation`] when the anchored entry cannot be
    ///   read.
    pub fn stored_anchor_disagrees(&self, binding: BindingHistory) -> Result<bool, WriterError> {
        let stored = self.stored_tip_anchor()?;
        let scan = self.replay_active_file()?;
        if stored == StoredTipAnchor::Absent {
            return Ok(PriorAnchoring::find(
                binding,
                &self.path,
                scan.entry_count,
                scan.holds_anchoring_row,
            )
            .is_some());
        }
        let tip = super::verify::VerifiedTip {
            entry_count: scan.entry_count,
            tip_hash: scan.last_hash,
            end_offset: scan.end_offset,
            holds_anchoring_row: scan.holds_anchoring_row,
        };
        Ok(super::verify::stored_anchor_disagrees_with_walk(
            &self.path,
            &stored,
            Some(&tip),
        )?)
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
        let mut anchor = store.load_anchor().map_err(WriterError::TipAnchorStore)?;
        self.refuse_if_replaced(anchor.as_ref())?;
        if self.anchor_behind() {
            self.require_anchor_current()?;
            anchor = store.load_anchor().map_err(WriterError::TipAnchorStore)?;
        }
        let len = fs::metadata(&self.path)?.len();

        let Some(anchor) = anchor else {
            return self.adopt_tip_anchor(store.as_ref(), len);
        };

        // Cheap path first: prove the anchored entry is still the entry ending
        // at the anchored offset, without replaying the file and without
        // touching the audit directory.
        let intact = self.entry_is_intact_at(anchor.end_offset, &anchor.tip_hash)?;
        if intact && len == anchor.end_offset {
            // The writer's counters come from replaying this file from byte 0
            // at open, or from its own appends since: they must reach the
            // anchored offset through exactly the anchored entries.
            if self.end_offset != anchor.end_offset || self.entry_count != anchor.entry_count {
                return Err(self.tip_anchor_mismatch(&anchor, len, LOG_COUNT_REASON));
            }
            self.checked_len = len;
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
        if !self.entry_ends_exactly_at(anchor.end_offset, &anchor.tip_hash)? {
            return Err(self.tip_anchor_mismatch(&anchor, len, LOG_ENTRY_END_REASON));
        }

        // The file moved forward past the anchor. Replay only the appended tail,
        // which validates that it chains off the anchored tip.
        let tail = read_and_verify_entry_chain(&self.file, anchor.end_offset, &anchor.tip_hash)?;
        // The prefix up to the anchored offset must hold exactly the anchored
        // entries. The writer's counters reach either the anchored offset
        // itself or, after the open's replay, the tail's end.
        let prefix_count = if self.end_offset == anchor.end_offset {
            Some(self.entry_count)
        } else if self.end_offset == tail.end_offset {
            self.entry_count.checked_sub(tail.entry_count)
        } else {
            None
        };
        if prefix_count != Some(anchor.entry_count) {
            return Err(self.tip_anchor_mismatch(&anchor, len, LOG_COUNT_REASON));
        }
        let advanced = TipAnchor::new(
            anchor.entry_count.saturating_add(tail.entry_count),
            tail.last_hash.clone(),
            tail.end_offset,
        );
        // The tail's last entry decides whether the file ends on a pending
        // handoff, for example one whose fsync failed after its bytes landed.
        if tail.entry_count > 0 {
            self.pending_handoff = PendingHandoff::from_scan(&self.path, &tail)?;
        }
        self.entry_count = advanced.entry_count;
        self.end_offset = advanced.end_offset;
        self.checked_len = tail.checked_len;
        self.is_new_file = false;
        self.last_hash.clone_from(&advanced.tip_hash);
        self.handoff_unsettled = false;
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
        self.adopt_scan_state(&scan)?;
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

    /// Takes an unanchored file under anchor protection at its current tip,
    /// unless the log shows it was anchored before.
    ///
    /// The whole file is replayed first, so a broken chain is refused rather
    /// than adopted. A log that [`PriorAnchoring::find`] shows was anchored
    /// before is refused with [`WriterError::TipAnchorMissing`]: its anchor was
    /// deleted, and adopting the file as it stands would accept whatever was
    /// removed from it alongside. A log with none of that evidence was written
    /// only by unkeyed writers, which is the state the zero-config quickstart
    /// leaves behind, and it is adopted; refusing it would make minting an
    /// audit key a one-way door. A file with a chain-root sidecar never reaches
    /// adoption, because the sidecar is itself such evidence.
    fn adopt_tip_anchor(
        &mut self,
        store: &dyn TipAnchorStore,
        len: u64,
    ) -> Result<AnchorOutcome, WriterError> {
        if len == 0 {
            self.refuse_if_anchored_before(0, false, len)?;
            // Nothing to anchor. Leaving the store empty says exactly that, and
            // the first append writes the first real anchor.
            self.entry_count = 0;
            self.end_offset = 0;
            self.checked_len = 0;
            return Ok(AnchorOutcome::AdoptedEmpty);
        }

        let scan = self.replay_active_file()?;
        self.refuse_if_anchored_before(scan.entry_count, scan.holds_anchoring_row, len)?;
        let adopted = TipAnchor::new(scan.entry_count, scan.last_hash.clone(), scan.end_offset);
        self.adopt_scan_state(&scan)?;
        store
            .store_anchor(&adopted)
            .map_err(WriterError::TipAnchorStore)?;
        Ok(if adopted.entry_count == 0 {
            AnchorOutcome::AdoptedEmpty
        } else {
            AnchorOutcome::AdoptedExisting
        })
    }

    /// Refuses an absent anchor that the log shows was written before.
    ///
    /// `entry_count` and `holds_anchoring_row` come from a full replay of the
    /// active file; `len` is its length. See [`PriorAnchoring::find`] for the
    /// evidence and its order.
    fn refuse_if_anchored_before(
        &self,
        entry_count: u64,
        holds_anchoring_row: bool,
        len: u64,
    ) -> Result<(), WriterError> {
        match PriorAnchoring::find(self.binding, &self.path, entry_count, holds_anchoring_row) {
            None => Ok(()),
            Some(evidence) => Err(WriterError::TipAnchorMissing {
                evidence,
                entry_count,
                actual_len: len,
            }),
        }
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

    /// Returns `true` when the line that ends exactly at `end_offset` is the
    /// entry hashing to `tip_hash`, written as the writer writes a row: its
    /// newline is the byte before `end_offset`, and no whitespace opens or
    /// closes its JSON.
    fn entry_ends_exactly_at(&self, end_offset: u64, tip_hash: &str) -> Result<bool, WriterError> {
        let Some(line) = read_line_ending_at(&self.file, end_offset)? else {
            return Ok(false);
        };
        let (Some(first), Some(last)) = (line.first(), line.last()) else {
            return Ok(false);
        };
        if first.is_ascii_whitespace() || last.is_ascii_whitespace() {
            return Ok(false);
        }
        let Ok(entry) = serde_json::from_slice::<AuditEntry>(&line) else {
            return Ok(false);
        };
        Ok(compute_entry_hash_streamed(&entry, &entry.previous_entry_hash)? == tip_hash)
    }

    /// Adopts a full-file replay result as the writer's in-memory state,
    /// including the handoff the file ends on when its rotation is pending.
    ///
    /// # Errors
    ///
    /// Every error of [`PendingHandoff::from_scan`]; the state is unchanged.
    fn adopt_scan_state(&mut self, scan: &ChainScan) -> Result<(), WriterError> {
        let pending_handoff = PendingHandoff::from_scan(&self.path, scan)?;
        self.entry_count = scan.entry_count;
        self.end_offset = scan.end_offset;
        self.checked_len = scan.checked_len;
        self.is_new_file = scan.entry_count == 0;
        if scan.entry_count > 0 {
            self.last_hash.clone_from(&scan.last_hash);
        }
        self.pending_handoff = pending_handoff;
        self.handoff_unsettled = false;
        Ok(())
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
    /// The exact length includes any blank tail validated during replay. The
    /// anchored offset still names the last entry, so reopen and acquisition
    /// retain their blank-line tolerance.
    ///
    /// Four shapes diverge from the writer's cached state. A rename changes
    /// identity; truncation shortens the file; growth extends it; an overwrite
    /// keeps identity and length but changes the tip. Each refuses before a row
    /// can chain from the stale tip and anchor over the result.
    fn refuse_if_log_moved_on_append(&mut self) -> Result<(), WriterError> {
        if self.tip_anchor.is_none() {
            return Ok(());
        }
        self.refuse_if_replaced(None)?;
        // Identity is proven, so the held handle and the path are one file and
        // the reads below can go through the handle.
        let len = fs::metadata(&self.path)?.len();
        if len != self.checked_len {
            let reason = if len < self.checked_len {
                LOG_TRUNCATED_REASON
            } else {
                LOG_GREW_REASON
            };
            return Err(self.latch(None, reason));
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
    /// reports zero, and the reason names the shape it was.
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

    /// Writes `anchor` with one immediate retry, without failing the caller.
    ///
    /// Used where an anchor-write failure must not fail the caller: the append
    /// and rotation paths, whose entry is already durable, and the owed-row
    /// anchor of a refused append. Appends commit their chain state before this
    /// call, so a failure leaves the next append on the row just written. Both
    /// attempts run under the sidecar lock the writer holds. A second failure
    /// keeps `anchor` owed in `pending_tip_anchor` for the next retry.
    fn store_tip_anchor_best_effort(&mut self, anchor: &TipAnchor) {
        #[cfg(test)]
        if self.skip_tip_anchor_write {
            return;
        }
        let Some(store) = self.tip_anchor.clone() else {
            return;
        };
        match store
            .store_anchor(anchor)
            .or_else(|_| store.store_anchor(anchor))
        {
            Ok(()) => self.pending_tip_anchor = None,
            Err(e) => {
                self.pending_tip_anchor = Some(anchor.clone());
                tracing::warn!(
                    log = %basename_lossy_path(&self.path),
                    error = %e,
                    "audit tip anchor write failed twice; repair is owed"
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
    /// row that was owed puts the obligation in the keyring, outside the log
    /// file. Every file at this path is then short of the anchor by exactly
    /// that row, so every later open refuses until an operator runs
    /// `audit reanchor --acknowledge-rollback`. Its report shows one more
    /// anchored entry than the file holds, and its row records that
    /// permanently.
    /// Anyone who can restore the keyring's own storage together with the log
    /// can restore an older state, and with a headless keyring backend the
    /// anchor is kept in a file on the same host.
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
        self.owed_row_anchored = !self.anchor_behind();
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

    /// Whether an anchor write failed and its repair is still owed.
    fn anchor_behind(&self) -> bool {
        self.pending_tip_anchor.is_some()
    }

    /// Writes the anchor value a failed write left owed, including a rotation
    /// handoff's value on a file that has no entry yet.
    ///
    /// A no-op while nothing is owed. A failed retry keeps the value owed and
    /// returns the store's error; the append path ignores it so that rows
    /// written after an action committed still land.
    ///
    /// # Errors
    ///
    /// [`WriterError::TipAnchorStore`] when the store rejects the write.
    fn retry_tip_anchor_if_behind(&mut self) -> Result<(), WriterError> {
        let Some(anchor) = self.pending_tip_anchor.clone() else {
            return Ok(());
        };
        let store = self
            .tip_anchor
            .clone()
            .ok_or(WriterError::TipAnchorUnavailable)?;
        store
            .store_anchor(&anchor)
            .map_err(WriterError::TipAnchorStore)?;
        self.pending_tip_anchor = None;
        Ok(())
    }

    /// Drains the outbox of a draining writer, then appends the adoption row
    /// when reconciliation adopted a non-empty file.
    ///
    /// `entry_count` is the count the adoption anchored, read before the
    /// drain. The adoption is in force in the keyring once reconciliation
    /// returns, and the next reconciliation finds the anchor current, so this
    /// call is the only one that can append the adoption row. When the drain
    /// refuses, the row is still appended and the refusal is returned; the
    /// refused rows stay queued behind it.
    ///
    /// # Errors
    ///
    /// Every error of [`AuditWriter::drain_outbox`], for a draining writer.
    fn drain_then_record_adoption(
        &mut self,
        outcome: AnchorOutcome,
        entry_count: u64,
    ) -> Result<(), WriterError> {
        if self.drains
            && !self.acknowledge_outbox
            && let Err(refusal) = self.drain_outbox()
        {
            self.record_adoption(outcome, entry_count);
            return Err(refusal);
        }
        self.record_adoption(outcome, entry_count);
        Ok(())
    }

    /// Appends the adoption row, with [`Self::append_checked`], when
    /// reconciliation adopted a non-empty file.
    ///
    /// Non-fatal: the anchor is already in force, and refusing the acquisition
    /// because a forensic row could not be appended would take the log offline
    /// for a reason the anchor itself has already handled.
    fn record_adoption(&mut self, outcome: AnchorOutcome, entry_count: u64) {
        if outcome != AnchorOutcome::AdoptedExisting {
            return;
        }
        if let Err(e) = self.append_checked(adoption_row(entry_count)) {
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
        #[cfg(any(test, feature = "test-helpers"))]
        let threshold = super::rotation::test_seam::rotation_threshold_for(&self.path)
            .unwrap_or(ROTATION_THRESHOLD_BYTES);
        #[cfg(not(any(test, feature = "test-helpers")))]
        let threshold = ROTATION_THRESHOLD_BYTES;
        Ok(meta.len() >= threshold)
    }

    /// Rotates the active log file.
    ///
    /// Writes a handoff entry, renames the current file + its HMAC sidecar,
    /// opens a fresh active file, and then prunes excess rotated files. A
    /// prune that stops is logged and never fails the rotation.
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
    /// has not been renamed.  `audit verify` will not see a gap because the
    /// rotated archive does not exist yet; the handoff names an archive file
    /// that does not exist at that point.  The writer, or the next
    /// `AuditWriter::open`, holds it as the pending handoff, and the next
    /// rotation attempt renames the file under that handoff's name without
    /// appending another, so the archive ends on its one handoff.
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
        // A handoff whose rotation did not complete already names the archive
        // and carries the anchor; appending another would put two in one file.
        let (rotated_name, handoff_hash) = match &self.pending_handoff {
            Some(pending) => (pending.archive_name.clone(), pending.hash.clone()),
            None => {
                let rotated_name = self.next_archive_name(stem)?;
                let handoff_hash = self.append_rotation_handoff(&rotated_name)?;
                (rotated_name, handoff_hash)
            }
        };
        let rotated_path = self.path.with_file_name(&rotated_name);
        let active_hmac_sidecar = hmac_sidecar_path(&self.path);
        let rotated_hmac_sidecar = hmac_sidecar_path(&rotated_path);
        refuse_taken_rotation_target(&rotated_path, &rotated_name)?;
        let moves_sidecar = active_hmac_sidecar.exists();
        if moves_sidecar {
            refuse_taken_rotation_target(&rotated_hmac_sidecar, &rotated_name)?;
        }

        #[cfg(test)]
        if self.rotation_renames_to_fail > 0 {
            self.rotation_renames_to_fail -= 1;
            return Err(WriterError::Io(io::Error::other(
                "test fault: rotation rename failed",
            )));
        }

        // Rename the HMAC sidecar before renaming the log file so both
        // renames are co-located in time.
        if moves_sidecar {
            fs::rename(&active_hmac_sidecar, &rotated_hmac_sidecar)?;
        }

        self.finish_rotation(&rotated_path, &rotated_name, handoff_hash)
    }

    /// The name of the archive the next rotation creates, which sorts after
    /// every existing archive of this log.
    ///
    /// The newest archive is the last rotated sibling in the order the prune,
    /// [`initial_chain_seed`], and `audit verify` read the chain in, so the
    /// archive created here is always the chain's last archive, whatever the
    /// clock says; see [`next_archive_suffix`]. Neither the archive nor its
    /// chain-root sidecar may exist under the name, since a rename replaces its
    /// destination.
    ///
    /// # Errors
    ///
    /// [`WriterError::RotationBridgeUnusable`] when a file exists under the
    /// name, or, with [`ARCHIVE_NAMES_EXHAUSTED_REASON`], when no name sorts
    /// after the newest archive. [`WriterError::IntegrityViolation`] when the
    /// sibling listing fails, and [`WriterError::Io`] when a name cannot be
    /// checked.
    fn next_archive_name(&self, stem: &str) -> Result<String, WriterError> {
        let chain = super::verify::collect_file_chain(&self.path)?;
        // The listing holds the rotated siblings oldest first, then the active path.
        let newest = chain
            .len()
            .checked_sub(2)
            .and_then(|idx| chain.get(idx))
            .map(|archive| basename_lossy_path(archive));
        let newest_suffix = newest
            .as_deref()
            .and_then(|name| name.strip_prefix(stem))
            .and_then(|rest| rest.strip_prefix('.'));
        let Some(suffix) = next_archive_suffix(&self.archive_clock(), newest_suffix) else {
            return Err(WriterError::RotationBridgeUnusable {
                archive_name: newest.unwrap_or_default(),
                reason: ARCHIVE_NAMES_EXHAUSTED_REASON,
            });
        };
        let name = format!("{stem}.{suffix}");
        let archive = self.path.with_file_name(&name);
        refuse_taken_rotation_target(&archive, &name)?;
        refuse_taken_rotation_target(&hmac_sidecar_path(&archive), &name)?;
        Ok(name)
    }

    /// The current time in archive-name form, or the time a test set.
    fn archive_clock(&self) -> String {
        #[cfg(test)]
        if let Some(now) = &self.archive_clock {
            return now.clone();
        }
        compact_timestamp()
    }

    /// Appends the rotation handoff entry to the outgoing file and advances the
    /// anchor onto it.
    ///
    /// The first half of [`AuditWriter::rotate`], split out so a test can stop
    /// inside the rotation window and observe that the rollback guard is still
    /// armed there. Returns the handoff entry's hash, which the new file's first
    /// entry chains from.
    ///
    /// Once the handoff's bytes can have reached the file, the writer must not
    /// append from its earlier state: a row chained from the entry before the
    /// handoff, or a second handoff, would leave the handoff inside its file.
    /// `handoff_unsettled` is therefore set before the write and cleared only
    /// once the state accounts for the handoff: here after its fsync, or in
    /// [`AuditWriter::settle_unsettled_handoff`], which the next append runs
    /// before anything else touches the file. That replay adopts the file as it
    /// stands past the writer's last entry and holds a handoff the file ends on
    /// as pending, or refuses. An anchored writer adopts the handoff in the
    /// anchor check of its next acquisition; an append without that check
    /// refuses the grown file earlier, in the append's log check, and latches.
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
        self.handoff_unsettled = true;
        self.file.write_all(&line)?;
        self.file.flush()?;
        #[cfg(test)]
        if self.fail_sync_after_handoff_write {
            return Err(WriterError::Io(io::Error::other(
                "test fault: sync_data failed after a full handoff write",
            )));
        }
        self.file.sync_data()?;
        self.entry_count = self.entry_count.saturating_add(1);
        self.end_offset = self.entry_end_offset()?;
        self.checked_len = self.end_offset;
        // The handoff is now the file's tip and stays pending until the
        // rotation completes, so a failed rename is retried under its name.
        self.last_hash.clone_from(&handoff_hash);
        self.pending_handoff = Some(PendingHandoff {
            archive_name: rotated_name.to_owned(),
            hash: handoff_hash.clone(),
        });
        self.handoff_unsettled = false;

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

    /// Rebuilds the writer's state from the file after a rotation handoff
    /// whose write, flush, or fsync failed, or refuses.
    ///
    /// Replays the file from the writer's last entry, which proves that what
    /// follows chains from it, and adopts the result as the anchor
    /// reconciliation adopts an advanced tail: a file ending on the handoff
    /// holds it as pending, so the next rotation renames under it. A file with
    /// nothing past that entry leaves the state as it is. A tail that does not
    /// replay refuses, and the next append replays it again.
    ///
    /// # Errors
    ///
    /// Every error of the replay and of [`PendingHandoff::from_scan`]; the
    /// state is unchanged.
    fn settle_unsettled_handoff(&mut self) -> Result<(), WriterError> {
        if !self.handoff_unsettled {
            return Ok(());
        }
        let tail = read_and_verify_entry_chain(&self.file, self.end_offset, &self.last_hash)?;
        if tail.entry_count > 0 {
            let pending_handoff = PendingHandoff::from_scan(&self.path, &tail)?;
            self.entry_count = self.entry_count.saturating_add(tail.entry_count);
            self.end_offset = tail.end_offset;
            self.checked_len = tail.checked_len;
            self.is_new_file = false;
            self.last_hash.clone_from(&tail.last_hash);
            self.pending_handoff = pending_handoff;
        }
        self.handoff_unsettled = false;
        Ok(())
    }

    /// Performs the rename, the new-file create, the state swap, and the
    /// prune: the second half of [`AuditWriter::rotate`].
    ///
    /// The prune runs last, once the new active file exists and the writer
    /// holds it. A prune error is logged and the rotation still returns `Ok`,
    /// so retention can never leave the active path missing.
    fn finish_rotation(
        &mut self,
        rotated_path: &Path,
        rotated_name: &str,
        handoff_hash: String,
    ) -> Result<(), WriterError> {
        // The new segment starts at the handoff hash. It is decoded before any
        // rename or state change, so a decode error leaves the writer whole.
        let segment_start_hash = decode_hash(&handoff_hash).map_err(WriterError::Hash)?;
        // The just-rotated archive's boundaries as this writer holds them, taken
        // before the swap replaces them: the prune proves the archive against
        // these and never against what the file at its name says.
        let rotated = RotatedArchive {
            path: rotated_path,
            seed: encode_hash(&self.segment_start_hash),
            handoff: handoff_hash.clone(),
        };

        // Rename the current log file to the rotated name.
        fs::rename(&self.path, rotated_path)?;
        #[cfg(test)]
        if let Some(hook) = self.after_rotation_rename.take() {
            hook(rotated_path);
        }

        // Open the new active file BEFORE swapping the writer state.
        //
        // Unlike a per-file lock scheme, no race window opens up here: the
        // sidecar lock acquired in `AuditWriter::open` is held continuously
        // across the whole rotation (never released, never re-acquired), so
        // no other process can ever hold the writer role while we are
        // between `fs::rename` and this `create_new` call. The active path
        // being briefly absent from the directory is a filesystem-visible
        // detail, not a lock-ownership race. A concurrent READER observing
        // this brief absence is expected and handled; see
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
        self.segment_start_hash = segment_start_hash;
        self.last_hash = handoff_hash;
        self.pending_handoff = None;
        self.is_new_file = true;
        self.entry_count = 0;
        self.end_offset = 0;
        self.checked_len = 0;

        // The anchor is deliberately left naming the archive's handoff entry.
        // There is no anchor value for a file with no entries: offset 0 is a
        // prefix of every file, so such an anchor classifies every file at this
        // path as ahead of it and a directory-level restore would be absorbed
        // instead of refused.  Until this file's first append advances the
        // anchor, `reconcile_tip_anchor`'s rotation-completed rule carries every
        // open and pre-flight, and it proves the generation by hash.

        // Retention is best effort: an error stops the prune with every
        // remaining archive kept, and the rotation stands.
        if let Err(e) = self.prune_rotated_files(&rotated) {
            tracing::warn!(
                log = %basename_lossy_path(&self.path),
                error = %e,
                "audit log prune stopped; the remaining archives are kept"
            );
        }
        Ok(())
    }

    /// Removes the oldest archives of the proven chain, keeping at most
    /// [`MAX_ROTATED_FILES`].
    ///
    /// The chain runs from the oldest rotated sibling (by the strict pattern of
    /// [`is_rotated_sibling`]) to `rotated`, the archive this rotation created.
    /// [`prove_prune_chain`] validates every archive in it in full before any
    /// deletion, its chain-root tag included for a keyed writer, and one
    /// failure stops the prune with nothing deleted. A sibling that sorts after
    /// `rotated` is outside the chain, so it is never deleted and never counted
    /// toward the excess.
    ///
    /// The oldest archive must start at the seed the `<log>.pruned` marker
    /// records for it, or at the zero seed when no marker exists; the archive
    /// never supplies its own start, so archives or a marker removed outside the
    /// prune stall it. A durable marker covers each deletion. A marker that
    /// names neither boundary for the oldest archive and a failed removal also
    /// stop the prune. Every stop keeps the remaining archives and logs a warning
    /// naming the file and the cause.
    ///
    /// # Errors
    ///
    /// Returns [`WriterError`] when the sibling listing fails, when the marker
    /// does not parse or does not authenticate under the writer's key, or when
    /// a marker write fails. [`AuditWriter::finish_rotation`] logs the error
    /// and completes the rotation.
    fn prune_rotated_files(&self, rotated: &RotatedArchive<'_>) -> Result<(), WriterError> {
        let mut siblings = super::verify::collect_file_chain(&self.path)?;
        // The listing holds the rotated siblings oldest first, then the active path.
        siblings.pop();
        let Some(newest) = siblings
            .iter()
            .position(|path| path.file_name() == rotated.path.file_name())
        else {
            self.warn_prune_stopped(&PruneStop::new(
                rotated.path.to_path_buf(),
                PruneStopCause::NotListed,
            ));
            return Ok(());
        };
        let chain = &siblings[..=newest];
        let excess = chain.len().saturating_sub(MAX_ROTATED_FILES);
        if excess == 0 {
            return Ok(());
        }

        let mut marker = read_prune_marker(&self.path)?;
        if let (Some(marker), Some(key)) = (&marker, &self.hmac_key)
            && !marker.verify_tag(key)
        {
            return Err(super::verify::VerifyError::HmacMismatch {
                file: basename_lossy_path(&prune_marker_path(&self.path)),
            }
            .into());
        }
        // The retained history starts where the marker says the oldest archive
        // starts, or at the zero seed when nothing was ever pruned. The oldest
        // archive never supplies its own start: a log missing its oldest
        // archives, its marker, or both, stalls here.
        let start_seed =
            match oldest_retained_seed(marker.as_ref(), &basename_lossy_path(&chain[0])) {
                Ok(seed) => seed.to_owned(),
                Err(MarkerNamesNoBoundary) => {
                    self.warn_prune_stopped(&PruneStop::new(
                        chain[0].clone(),
                        PruneStopCause::MarkerBoundary,
                    ));
                    return Ok(());
                }
            };
        let handoffs =
            match prove_prune_chain(chain, &start_seed, rotated, self.hmac_key.as_deref()) {
                Ok(handoffs) => handoffs,
                Err(stop) => {
                    self.warn_prune_stopped(&stop);
                    return Ok(());
                }
            };

        let deletions = chain.iter().zip(&chain[1..]).zip(handoffs).take(excess);
        for ((archive, successor), hash) in deletions {
            let file = basename_lossy_path(archive);
            let seed = match oldest_retained_seed(marker.as_ref(), &file) {
                Ok(seed) => seed.to_owned(),
                Err(MarkerNamesNoBoundary) => {
                    self.warn_prune_stopped(&PruneStop::new(
                        archive.clone(),
                        PruneStopCause::MarkerBoundary,
                    ));
                    return Ok(());
                }
            };
            // A retained previous file retries the same recorded deletion.
            let retry = marker.as_ref().is_some_and(|m| {
                m.data
                    .previous
                    .as_ref()
                    .is_some_and(|previous| previous.file == file)
            });
            let count = marker.as_ref().map_or(0, |m| m.data.pruned_files);
            let mut next = PruneMarker {
                data: PruneMarkerData {
                    version: 1,
                    oldest: PruneSeed {
                        file: basename_lossy_path(successor),
                        initial_prev_hash: hash,
                    },
                    previous: Some(PruneSeed {
                        file,
                        initial_prev_hash: seed,
                    }),
                    pruned_files: count.saturating_add(u64::from(!retry)),
                },
                tag: None,
            };
            next.write(&self.path, self.hmac_key.as_deref())
                .map_err(io::Error::other)?;
            #[cfg(test)]
            if self.skip_prune_removal {
                return Ok(());
            }
            if let Err(e) = fs::remove_file(archive) {
                self.warn_prune_stopped(&PruneStop::new(
                    archive.clone(),
                    PruneStopCause::Removal(e),
                ));
                return Ok(());
            }
            let _ = fs::remove_file(hmac_sidecar_path(archive));
            marker = Some(next);
        }
        Ok(())
    }

    /// Logs a prune that stopped at a file, which it keeps with every other
    /// remaining archive.
    fn warn_prune_stopped(&self, stop: &PruneStop) {
        tracing::warn!(
            log = %basename_lossy_path(&self.path),
            file = %basename_lossy_path(&stop.file),
            cause = %stop.cause,
            "audit log prune stopped; the remaining archives are kept"
        );
    }

    /// Writes the chain-root HMAC tag to a `<file>.root_hmac` sidecar file.
    ///
    /// The sidecar is replaced atomically through a temp file and a rename, so
    /// a crash leaves either no tag or the whole tag, and a symlink at either
    /// path is replaced rather than followed. The file is created with mode
    /// `0600` on POSIX.
    ///
    /// # Errors
    ///
    /// Returns [`WriterError::Io`] on I/O failure.
    fn write_root_hmac_sidecar(&self, tag: &str) -> Result<(), WriterError> {
        super::rotation::write_sidecar_atomic(&hmac_sidecar_path(&self.path), tag.as_bytes())
            .map_err(|detail| WriterError::Io(io::Error::other(detail)))
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
/// - `YYYYMMDDTHHMMSSmmm-N` - millisecond precision plus a decimal counter,
///   which the writer adds when the clock does not place a rotation after the
///   newest archive (see [`next_archive_suffix`]). The writer writes six
///   digits; any count is read.
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
/// `audit.jsonl.20260428T123456789-000001` (counter) match.
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
    // The checks below run on bytes, never on `str` slices: a directory entry
    // name is attacker-placeable, and a byte index inside a multi-byte
    // character would panic a `str` slice. Any non-ASCII byte fails the digit
    // or `T` test, so such a name is never a sibling.
    let bytes = base_suffix.as_bytes();
    let (Some(date), Some(separator), Some(time)) = (bytes.get(..8), bytes.get(8), bytes.get(9..))
    else {
        return false;
    };
    // First 8 bytes must be decimal digits (YYYYMMDD), the ninth `T`, and the
    // rest decimal digits. The length constraint gives either 6 or 9 of them.
    date.iter().all(u8::is_ascii_digit) && *separator == b'T' && time.iter().all(u8::is_ascii_digit)
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

/// The `audit_tip_anchored` row that records the adoption of an existing log
/// holding `entry_count` entries.
fn adoption_row(entry_count: u64) -> AuditEntry {
    AuditEntry::new_audit_tip_anchored(
        TipAnchorReason::Adopted,
        entry_count,
        None,
        None,
        uuid::Uuid::new_v4().to_string(),
    )
}

/// Returns the `.root_hmac` sidecar path for `log_path`.
///
/// For `audit.jsonl` → `audit.jsonl.root_hmac`.
/// For `audit.jsonl.20260428T123456` → `audit.jsonl.20260428T123456.root_hmac`.
pub(super) fn hmac_sidecar_path(log_path: &Path) -> PathBuf {
    sidecar_path(log_path, ".root_hmac")
}

/// Returns the retention marker path beside the active log.
pub(crate) fn prune_marker_path(log_path: &Path) -> PathBuf {
    sidecar_path(log_path, ".pruned")
}

/// Returns the path beside `log_path` whose file name is the log's full file
/// name followed by `suffix`.
///
/// For `audit.jsonl` and `.lock` → `audit.jsonl.lock`. The log's own
/// extension is kept: `suffix` is appended, never substituted.
pub(super) fn sidecar_path(log_path: &Path, suffix: &str) -> PathBuf {
    let mut sidecar = log_path.to_path_buf();
    let existing = sidecar
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_owned();
    sidecar.set_file_name(format!("{existing}{suffix}"));
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
    sidecar_path(log_path, ".lock")
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

/// Returns the current UTC time in archive-name form, `YYYYMMDDTHHMMSSmmm`.
fn compact_timestamp() -> String {
    // "2026-04-28T12:34:56.123Z" → "20260428T123456123"
    current_iso8601_utc()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() && *c != 'Z')
        .collect()
}

/// Length of a second-precision archive suffix, `YYYYMMDDTHHMMSS`.
const SECOND_SUFFIX_LEN: usize = 15;

/// Digits of the counter an archive suffix carries when the clock does not
/// place a rotation after the newest archive.
///
/// The width is fixed, so the counters' lexical order is their numeric order.
const ARCHIVE_COUNTER_WIDTH: usize = 6;

/// Reason for a rotation that finds no archive name after the newest archive.
const ARCHIVE_NAMES_EXHAUSTED_REASON: &str =
    "the archive names after the newest archive are exhausted";

/// The archive suffix, the part of the name after `<stem>.`, of the next
/// rotation: the smallest one the writer produces that sorts strictly after
/// `newest`, the suffix of the newest existing archive, or `now` itself.
///
/// `now` is the current time as [`compact_timestamp`] gives it, used whenever
/// it sorts after `newest`. A clock that stands still or was set back
/// continues from `newest` instead: a second-precision suffix takes its
/// millisecond form, a millisecond suffix takes the counter `-000001`, and a
/// suffix with a counter takes the next counter of [`ARCHIVE_COUNTER_WIDTH`]
/// digits. A counter shorter than that width is padded with zeros on the
/// right, so `-9` continues as `-900000`. Returns
/// `None` when no counter of that width sorts after `newest`'s, which only a
/// counter opening with that many nines leaves.
///
/// Archive names sort, and are read as a chain, by their bytes. Taking the
/// next name from the newest archive rather than from the clock alone keeps
/// that order the order the archives were created in.
fn next_archive_suffix(now: &str, newest: Option<&str>) -> Option<String> {
    let Some(newest) = newest else {
        return Some(now.to_owned());
    };
    if now > newest {
        return Some(now.to_owned());
    }
    let (base, counter) = match newest.split_once('-') {
        Some((base, counter)) => (base, Some(counter)),
        None => (newest, None),
    };
    let counter = match counter {
        None if base.len() == SECOND_SUFFIX_LEN => return Some(format!("{base}000")),
        None => 1,
        Some(counter) if counter.len() < ARCHIVE_COUNTER_WIDTH => {
            return Some(format!("{base}-{counter:0<ARCHIVE_COUNTER_WIDTH$}"));
        }
        Some(counter) => counter
            .get(..ARCHIVE_COUNTER_WIDTH)?
            .parse::<u32>()
            .ok()?
            .checked_add(1)?,
    };
    let next = format!("{counter:0ARCHIVE_COUNTER_WIDTH$}");
    (next.len() == ARCHIVE_COUNTER_WIDTH).then(|| format!("{base}-{next}"))
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
    /// Byte offset just past the last entry in the replayed range.
    end_offset: u64,
    /// Byte offset just past all replayed bytes, including trailing blank lines.
    checked_len: u64,
    /// Whether the replayed range holds an `audit_tip_anchored` row, which only
    /// a writer with an anchor store appends.
    holds_anchoring_row: bool,
    /// The file name the last entry hands off to, when that entry is a
    /// rotation handoff.
    last_handoff: Option<String>,
    /// The first entry of the replayed range, which a replay from offset 0
    /// makes the file's chain root.
    first_entry: Option<ChainRoot>,
}

/// Refuses `entry` with [`WriterError::RowTooLarge`] when its serialized line,
/// newline included, would be longer than [`MAX_ROW_BYTES`].
///
/// Applies the append's argument-key truncation first, which the append would
/// apply anyway and which leaves an already truncated entry unchanged, and
/// measures with a placeholder predecessor hash: every entry hash serializes
/// to the same length, so the measure is the length the append writes. It
/// runs before the append's checks, rotation, or drain, so an oversized row
/// changes nothing. Bytes are counted, not buffered.
fn refuse_oversized_row(entry: &mut AuditEntry) -> Result<(), WriterError> {
    /// Counts the bytes serialized into it.
    struct ByteCount(u64);
    impl Write for ByteCount {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0 = self.0.saturating_add(buf.len() as u64);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    entry.truncate_arg_keys_if_needed()?;
    let previous = std::mem::replace(&mut entry.previous_entry_hash, ZERO_BLOCK_HASH.to_owned());
    let mut count = ByteCount(0);
    let measured = serde_json::to_writer(&mut count, &*entry);
    entry.previous_entry_hash = previous;
    measured?;
    let bytes = count.0.saturating_add(1);
    if bytes > MAX_ROW_BYTES {
        return Err(WriterError::RowTooLarge {
            bytes,
            cap: MAX_ROW_BYTES,
        });
    }
    Ok(())
}

/// A rotation handoff the active file ends on whose rotation has not completed.
struct PendingHandoff {
    /// The archive name the handoff names.
    archive_name: String,
    /// The handoff's entry hash, which the anchor and the next file chain from.
    hash: String,
}

impl PendingHandoff {
    /// The handoff a replay of the active file at `log_path` ends on, when it
    /// names a rotated sibling of that file. A handoff naming anything else is
    /// never a rename target.
    ///
    /// # Errors
    ///
    /// [`WriterError::RotationBridgeUnusable`] when a file already exists under
    /// the handoff's archive name: the rename would replace it, and no honest
    /// rotation leaves its handoff pending over an existing archive.
    /// [`WriterError::Io`] when that name cannot be checked.
    fn from_scan(log_path: &Path, scan: &ChainScan) -> Result<Option<Self>, WriterError> {
        let Some(stem) = log_path.file_name().and_then(|name| name.to_str()) else {
            return Ok(None);
        };
        let Some(archive_name) = scan.last_handoff.as_ref() else {
            return Ok(None);
        };
        if !is_rotated_sibling(stem, archive_name) {
            return Ok(None);
        }
        refuse_taken_rotation_target(&log_path.with_file_name(archive_name), archive_name)?;
        Ok(Some(Self {
            archive_name: archive_name.clone(),
            hash: scan.last_hash.clone(),
        }))
    }
}

/// Reason for a rotation whose archive name is already taken.
const ROTATION_TARGET_TAKEN_REASON: &str =
    "a file already exists under the rotation's archive name";

/// Refuses a rotation rename onto `target`, the archive `archive_name` or its
/// chain-root sidecar, when anything already exists there.
///
/// A rename replaces its destination, and an existing file under an archive
/// name is never the writer's to overwrite. The check runs right before the
/// renames; a concurrent writer of the audit directory between the check and
/// the rename is outside its guarantee.
fn refuse_taken_rotation_target(target: &Path, archive_name: &str) -> Result<(), WriterError> {
    match fs::symlink_metadata(target) {
        Ok(_) => Err(WriterError::RotationBridgeUnusable {
            archive_name: archive_name.to_owned(),
            reason: ROTATION_TARGET_TAKEN_REASON,
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(WriterError::Io(e)),
    }
}

/// The first entry of a replayed range and where its JSON starts.
struct ChainRoot {
    entry: AuditEntry,
    /// Byte offset of the entry's first byte in the file, past any blank lines
    /// before it and any whitespace that opens its own line.
    offset: u64,
}

impl ChainScan {
    /// The result of replaying an empty range.
    fn empty(seed: String) -> Self {
        Self {
            last_hash: seed,
            entry_count: 0,
            end_offset: 0,
            checked_len: 0,
            holds_anchoring_row: false,
            last_handoff: None,
            first_entry: None,
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
    scan_entry_chain(file, start_offset, Some(seed_hash), None)
}

/// The chain replay behind [`read_and_verify_entry_chain`], over `file` from
/// `start_offset`.
///
/// With `seed_hash` `None` the first entry's own `previous_entry_hash` starts
/// the chain, and every later entry must chain from the one before it. With a
/// `budget`, a line or a file past its limit fails with an
/// [`io::ErrorKind::InvalidData`] error carrying [`ReadBudgetExceeded`]; see
/// [`scan_entry_reader`] for how the reads are bounded.
fn scan_entry_chain(
    file: &File,
    start_offset: u64,
    seed_hash: Option<&str>,
    budget: Option<ScanBudget>,
) -> Result<ChainScan, WriterError> {
    // Reuse the caller's already-open (and already-locked) handle rather than
    // opening a second one; see the module-level "Single-handle requirement
    // (Windows)" section.
    let mut cursor = file;
    cursor.seek(SeekFrom::Start(start_offset))?;
    scan_entry_reader(cursor, start_offset, seed_hash, budget)
}

/// Replays the entries `source` yields, `start_offset` being the file offset
/// of its first byte.
///
/// With a `budget`, the file limit sits below the buffer: at most the file
/// limit plus one byte is ever read from `source`, however fast the file grows,
/// so a line read never passes what remains of the file limit by more than that
/// one byte. Each line read is bounded by the line limit plus one byte above
/// the buffer.
fn scan_entry_reader(
    source: impl Read,
    start_offset: u64,
    seed_hash: Option<&str>,
    budget: Option<ScanBudget>,
) -> Result<ChainScan, WriterError> {
    let source_limit = budget.map_or(u64::MAX, |budget| budget.file.saturating_add(1));
    let mut reader = BufReader::new(source.take(source_limit));

    let mut expected_previous_hash = seed_hash.map(str::to_owned);
    let mut last_hash = seed_hash.unwrap_or_default().to_owned();
    let mut last_handoff = None;
    let mut first_entry = None;
    let mut entry_idx = 0usize;
    let mut consumed = start_offset;
    // Offset just past the last ENTRY, which is what the anchor records: bytes
    // after it that hold no entry (trailing blank lines) are not part of the
    // verified prefix.
    let mut end_offset = start_offset;
    let mut holds_anchoring_row = false;
    let mut raw = Vec::new();

    loop {
        raw.clear();
        let read = match budget {
            Some(budget) => {
                let file_left = budget
                    .file
                    .saturating_sub(consumed.saturating_sub(start_offset));
                let read = (&mut reader)
                    .take(budget.line.saturating_add(1))
                    .read_until(b'\n', &mut raw)?;
                if read as u64 > budget.line {
                    return Err(budget_exceeded("line", budget.line));
                }
                if read as u64 > file_left {
                    return Err(budget_exceeded("file", budget.file));
                }
                read
            }
            None => reader.read_until(b'\n', &mut raw)?,
        };
        if read == 0 {
            break;
        }
        let line_start = consumed;
        consumed = consumed.saturating_add(read as u64);

        let line = strip_line_terminator(&raw);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }

        entry_idx += 1;
        let entry: AuditEntry = serde_json::from_slice(line).map_err(WriterError::Serialise)?;
        let expected =
            expected_previous_hash.get_or_insert_with(|| entry.previous_entry_hash.clone());
        if entry.previous_entry_hash != *expected {
            return Err(WriterError::ChainBrokenAtOpen {
                entry_idx,
                expected_hex: expected.clone(),
                got_hex: entry.previous_entry_hash,
            });
        }

        let hash = compute_entry_hash_streamed(&entry, &entry.previous_entry_hash)?;
        expected_previous_hash = Some(hash.clone());
        last_hash = hash;
        end_offset = consumed;
        holds_anchoring_row |= matches!(entry.event_kind, EventKind::AuditTipAnchored { .. });
        if first_entry.is_none() {
            let indent = line.iter().take_while(|b| b.is_ascii_whitespace()).count();
            first_entry = Some(ChainRoot {
                entry: entry.clone(),
                offset: line_start.saturating_add(indent as u64),
            });
        }
        last_handoff = match entry.event_kind {
            EventKind::AuditRotationHandoff { next_file_name } => Some(next_file_name),
            _ => None,
        };
    }

    Ok(ChainScan {
        last_hash,
        entry_count: entry_idx as u64,
        end_offset,
        checked_len: consumed,
        holds_anchoring_row,
        last_handoff,
        first_entry,
    })
}

/// The error a budgeted scan returns at a read limit.
fn budget_exceeded(limit: &'static str, bytes: u64) -> WriterError {
    WriterError::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        ReadBudgetExceeded { limit, bytes },
    ))
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
    Ok(read_archive_handoff_hash(newest_archive)?.unwrap_or_else(|| ZERO_BLOCK_HASH.to_owned()))
}

/// Hashes an archive's handoff entry, or returns `None` when the archive cannot
/// be opened or holds no non-blank line.
///
/// [`initial_chain_seed`] seeds the successor of such an archive with the zero
/// block, so the replay reports the bridge at the active file's own first entry.
///
/// A last line that is not a handoff naming this archive refuses with
/// [`WriterError::RotationBridgeUnusable`].
fn read_archive_handoff_hash(archive: &Path) -> Result<Option<String>, WriterError> {
    let archive_name = basename_lossy_path(archive);
    let Ok(file) = super::verify::open_regular_file(archive) else {
        return Ok(None);
    };
    let len = file.metadata()?.len();
    let Some(line) = read_last_line_before(&file, len)? else {
        return Ok(None);
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
    compute_entry_hash_streamed(&entry, &entry.previous_entry_hash).map(Some)
}

// ── Retention proof ──────────────────────────────────────────────────────────

/// Longest line the prune reads from an archive, terminator included.
///
/// The writer refuses any row longer than [`MAX_ROW_BYTES`], so no archive it
/// wrote holds a longer line, and the prune refuses one rather than buffer it.
const PRUNE_LINE_CAP: u64 = MAX_ROW_BYTES;

/// Largest archive the prune reads.
///
/// Every append checks the threshold before it writes, so an archive holds
/// less than [`ROTATION_THRESHOLD_BYTES`] before its last row, then that row
/// and the rotation handoff, each within [`MAX_ROW_BYTES`]. There is one
/// handoff: a rotation attempt whose renames fail leaves its handoff pending,
/// and the next attempt renames the file under it and appends no second
/// handoff, so retries never grow an archive.
const PRUNE_FILE_CAP: u64 = ROTATION_THRESHOLD_BYTES + 2 * MAX_ROW_BYTES;

/// The archive a rotation just created, with the boundaries the writer holds
/// for it in memory.
struct RotatedArchive<'a> {
    /// The archive's path.
    path: &'a Path,
    /// The hash its first entry chains from: the outgoing segment's start.
    seed: String,
    /// The hash of the rotation handoff the writer appended to it.
    handoff: String,
}

/// The file a prune stopped at, and why. A stop deletes nothing further.
///
/// The cause is boxed: it can carry a [`super::verify::VerifyError`], and the
/// stop is the error type of every proof step.
#[derive(Debug)]
struct PruneStop {
    file: PathBuf,
    cause: Box<PruneStopCause>,
}

impl PruneStop {
    fn new(file: PathBuf, cause: PruneStopCause) -> Self {
        Self {
            file,
            cause: Box::new(cause),
        }
    }

    /// Reclassifies a stop at the oldest archive whose first entry does not
    /// chain from the start seed as [`PruneStopCause::StartBoundary`]; every
    /// other stop is returned unchanged.
    fn at_start(self) -> Self {
        match *self.cause {
            PruneStopCause::Chain(e @ WriterError::ChainBrokenAtOpen { entry_idx: 1, .. }) => {
                Self::new(self.file, PruneStopCause::StartBoundary(e))
            }
            cause => Self::new(self.file, cause),
        }
    }
}

/// Why a prune stopped.
#[derive(Debug)]
enum PruneStopCause {
    /// The archive this rotation created is missing from the sibling listing.
    NotListed,
    /// The file cannot be opened as a regular file.
    Open(super::verify::VerifyError),
    /// The file, or one of its lines, is larger than an honest writer produces.
    OverBudget(ReadBudgetExceeded),
    /// A read of the file failed.
    Read(io::Error),
    /// The file's entries do not chain from its predecessor's handoff through
    /// to its own last entry, or a line is not an audit entry.
    Chain(WriterError),
    /// The file does not end with a rotation handoff naming it.
    NoHandoff,
    /// A keyed writer cannot verify the file's chain-root tag over its first
    /// entry: the `.root_hmac` sidecar is missing, unreadable, or holds a tag
    /// that does not verify under the writer's key.
    RootTag(super::verify::VerifyError),
    /// The just-rotated archive does not end on the handoff this writer
    /// appended to it.
    NotTheRotatedArchive,
    /// The prune marker names neither boundary for the oldest archive.
    MarkerBoundary,
    /// The archive's removal failed.
    Removal(io::Error),
    /// The oldest archive does not chain from the start of the retained
    /// history: the seed the prune marker records for it, or the zero seed
    /// when no marker exists. Archives or the marker were removed outside the
    /// prune.
    StartBoundary(WriterError),
}

impl PruneStopCause {
    /// Classifies an archive scan's error, keeping the read-budget, I/O and
    /// parse or link cases apart.
    fn from_scan_error(e: WriterError) -> Self {
        match e {
            WriterError::Io(io) => {
                let exceeded = io
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<ReadBudgetExceeded>())
                    .copied();
                match exceeded {
                    Some(exceeded) => Self::OverBudget(exceeded),
                    None => Self::Read(io),
                }
            }
            e => Self::Chain(e),
        }
    }
}

impl std::fmt::Display for PruneStopCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotListed => f.write_str("not in the sibling listing"),
            Self::Open(e) => write!(f, "open: {e}"),
            Self::OverBudget(e) => write!(f, "read budget: {e}"),
            Self::Read(e) => write!(f, "read: {e}"),
            Self::Chain(e) => write!(f, "chain: {e}"),
            Self::NoHandoff => f.write_str("no rotation handoff naming the file"),
            Self::RootTag(e) => write!(f, "chain-root tag: {e}"),
            Self::NotTheRotatedArchive => {
                f.write_str("the file does not end on the handoff this writer appended")
            }
            Self::MarkerBoundary => f.write_str(
                "the prune marker names neither boundary for the oldest archive; see \
                 docs/maintainers/audit-log-recovery.md section 11",
            ),
            Self::Removal(e) => write!(f, "removal: {e}"),
            Self::StartBoundary(e) => write!(
                f,
                "chain: the oldest archive does not chain from the authenticated start \
                 of the retained history ({e}); see \
                 docs/maintainers/audit-log-recovery.md section 11"
            ),
        }
    }
}

/// A read of a file the writer does not hold passed one of its limits.
#[derive(Debug, Clone, Copy)]
struct ReadBudgetExceeded {
    /// `"line"` or `"file"`.
    limit: &'static str,
    /// The limit in bytes.
    bytes: u64,
}

impl std::fmt::Display for ReadBudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the {} exceeds {} bytes", self.limit, self.bytes)
    }
}

impl std::error::Error for ReadBudgetExceeded {}

/// Read limits for a scan of a file the writer does not hold.
#[derive(Clone, Copy)]
struct ScanBudget {
    /// Longest line, terminator included.
    line: u64,
    /// Most bytes read from the file.
    file: u64,
}

/// The read limits of every archive the prune scans.
const PRUNE_BUDGET: ScanBudget = ScanBudget {
    line: PRUNE_LINE_CAP,
    file: PRUNE_FILE_CAP,
};

/// Validates `chain`, oldest first and ending at `rotated`, the archive this
/// rotation created, and returns each archive's handoff hash in order.
///
/// Every archive is replayed in full: each entry chains from the entry before
/// it, the first from the predecessor's handoff, and the last is a rotation
/// handoff naming the archive. The oldest archive's first entry chains from
/// `start_seed`, the start of the retained history the caller derives from the
/// prune marker or the zero seed, so no link is taken from an archive's own
/// file. The just-rotated archive's boundaries come from the writer's memory: its first entry must chain from `rotated.seed`, the
/// predecessor's handoff must equal that seed, and the file must end on
/// `rotated.handoff`. With `key`, every archive's first entry must also carry
/// a chain-root tag that verifies under it, so each counted file starts where
/// a keyed writer started one.
///
/// The links bind the entries into one sequence, and the tags bind where that
/// sequence divides into files: a file split at an interior rotation handoff
/// keeps valid links, but the part after the split starts on an entry no
/// keyed writer signed. An unkeyed writer has only the links, so a sequence
/// re-divided at such a handoff passes its proof.
fn prove_prune_chain(
    chain: &[PathBuf],
    start_seed: &str,
    rotated: &RotatedArchive<'_>,
    key: Option<&[u8; 32]>,
) -> Result<Vec<String>, PruneStop> {
    let Some((newest, older)) = chain.split_last() else {
        return Ok(Vec::new());
    };
    let mut handoffs: Vec<String> = Vec::with_capacity(chain.len());
    for archive in older {
        let handoff = match handoffs.last() {
            Some(predecessor) => scan_archive(archive, predecessor, key)?,
            None => scan_archive(archive, start_seed, key).map_err(PruneStop::at_start)?,
        };
        handoffs.push(handoff);
    }
    let predecessor = handoffs.last().map_or(start_seed, String::as_str);
    if predecessor != rotated.seed {
        let stop = PruneStop::new(
            newest.clone(),
            PruneStopCause::Chain(WriterError::ChainBrokenAtOpen {
                entry_idx: 1,
                expected_hex: predecessor.to_owned(),
                got_hex: rotated.seed.clone(),
            }),
        );
        return Err(if older.is_empty() {
            stop.at_start()
        } else {
            stop
        });
    }
    let handoff = scan_archive(newest, &rotated.seed, key)?;
    if handoff != rotated.handoff {
        return Err(PruneStop::new(
            newest.clone(),
            PruneStopCause::NotTheRotatedArchive,
        ));
    }
    handoffs.push(handoff);
    Ok(handoffs)
}

/// Replays one archive within [`PRUNE_BUDGET`] from `seed`, checks its
/// chain-root tag under `key` when one is given, and returns its handoff hash.
fn scan_archive(archive: &Path, seed: &str, key: Option<&[u8; 32]>) -> Result<String, PruneStop> {
    let stop = |cause| PruneStop::new(archive.to_path_buf(), cause);
    let file =
        super::verify::open_regular_file(archive).map_err(|e| stop(PruneStopCause::Open(e)))?;
    let len = file
        .metadata()
        .map_err(|e| stop(PruneStopCause::Open(super::verify::VerifyError::Io(e))))?
        .len();
    if len > PRUNE_BUDGET.file {
        return Err(stop(PruneStopCause::OverBudget(ReadBudgetExceeded {
            limit: "file",
            bytes: PRUNE_BUDGET.file,
        })));
    }
    let scan = scan_entry_chain(&file, 0, Some(seed), Some(PRUNE_BUDGET))
        .map_err(|e| stop(PruneStopCause::from_scan_error(e)))?;
    if scan.last_handoff.as_deref() != Some(basename_lossy_path(archive).as_str()) {
        return Err(stop(PruneStopCause::NoHandoff));
    }
    if let (Some(key), Some(first_entry)) = (key, &scan.first_entry) {
        let body = first_entry
            .entry
            .canonical_json_body()
            .map_err(|e| stop(PruneStopCause::Chain(WriterError::Serialise(e))))?;
        super::verify::verify_root_sidecar(archive, key, &body)
            .map_err(|e| stop(PruneStopCause::RootTag(e)))?;
    }
    Ok(scan.last_hash)
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

/// Reads the line whose `\n` is the byte just before `end_offset`, without
/// that newline.
///
/// Returns `Ok(None)` when `end_offset` is zero or past the end of the file,
/// when the byte before it is not a newline, or when the line, newline
/// included, is longer than [`MAX_ROW_BYTES`], which no row the writer appends
/// is. Reads backward in
/// 4 KiB windows, as [`read_last_line_before`] does.
fn read_line_ending_at(file: &File, end_offset: u64) -> io::Result<Option<Vec<u8>>> {
    const SCAN_CHUNK: u64 = 4096;

    let mut cursor = file;
    if end_offset == 0 || cursor.metadata()?.len() < end_offset {
        return Ok(None);
    }
    let line_end = end_offset - 1;
    let mut terminator = [0u8; 1];
    cursor.seek(SeekFrom::Start(line_end))?;
    cursor.read_exact(&mut terminator)?;
    if terminator[0] != b'\n' {
        return Ok(None);
    }

    let mut line: Vec<u8> = Vec::new();
    let mut scan_end = line_end;
    while scan_end > 0 {
        let chunk_size = std::cmp::min(SCAN_CHUNK, scan_end);
        let chunk_start = scan_end - chunk_size;
        cursor.seek(SeekFrom::Start(chunk_start))?;
        let mut chunk = vec![
            0u8;
            usize::try_from(chunk_size)
                .map_err(|_| io::Error::other("audit log chunk size overflow"))?
        ];
        cursor.read_exact(&mut chunk)?;
        if let Some(idx) = chunk.iter().rposition(|&byte| byte == b'\n') {
            chunk.drain(..=idx);
            chunk.extend_from_slice(&line);
            line = chunk;
            break;
        }
        chunk.extend_from_slice(&line);
        line = chunk;
        if line.len() as u64 >= MAX_ROW_BYTES {
            return Ok(None);
        }
        scan_end = chunk_start;
    }
    if line.len() as u64 >= MAX_ROW_BYTES {
        return Ok(None);
    }
    Ok(Some(line))
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

    /// No anchor is stored for the log path, and the log shows one was.
    ///
    /// The evidence is a fact that outlives the anchor itself: an audit binding
    /// recorded before this open, a chain-root sidecar on the active file, or
    /// an `audit_tip_anchored` row in it. Deleting the anchor and truncating
    /// the log would otherwise be adopted as a fresh log, and the removed rows
    /// would leave no trace.
    ///
    /// Wire code: `audit.tip_anchor_missing`. Recovery:
    /// `stellar-agent audit reanchor --profile <name> --acknowledge-rollback`
    /// after establishing why the anchor is gone. See
    /// `docs/maintainers/audit-log-recovery.md`.
    #[error(
        "audit.tip_anchor_missing: no tip anchor is stored for this log path, although \
         {evidence}; the file holds {entry_count} entries / {actual_len} bytes"
    )]
    TipAnchorMissing {
        /// What shows the log was anchored before.
        evidence: PriorAnchoring,
        /// Number of entries in the active file.
        entry_count: u64,
        /// Current length of the log file.
        actual_len: u64,
    },

    /// The tip anchor could not be read from, or written to, its backing store.
    ///
    /// The anchor lives in the keyring. An unreadable anchor cannot be
    /// distinguished from a rolled-back one, so every caller that requires the
    /// anchor treats this as fail-closed.
    #[error("audit.tip_anchor_unavailable: audit log tip anchor unavailable: {0}")]
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

    /// The audit outbox lock stayed held for the whole wait.
    ///
    /// Another process is appending to or draining the outbox. Distinct from
    /// [`WriterError::FileLocked`], which names the writer's sidecar lock. See
    /// [`crate::audit_log::outbox`].
    #[error(
        "audit.outbox_busy: the audit outbox lock stayed held for {} ms; another \
         process is appending to or draining the outbox",
        super::outbox::OUTBOX_LOCK_WAIT.as_millis()
    )]
    OutboxBusy,

    /// A complete line of the audit outbox does not parse as an audit entry.
    ///
    /// The drain refused and left the outbox unchanged. The variant names the
    /// line, the column, and the class of the parse failure, never the line's
    /// content. Anyone who can write the audit directory can plant that
    /// content, and this error reaches agent and CLI envelopes. Recovery is in
    /// `docs/maintainers/audit-log-recovery.md`.
    #[error(
        "audit.outbox_unusable: line {line} of the audit outbox does not parse as an \
         audit entry ({reason} at column {column}); the outbox is left unchanged"
    )]
    OutboxUnusable {
        /// One-based number of the first line that does not parse.
        line: usize,
        /// One-based column of that line at which parsing stopped.
        column: usize,
        /// Class of the parse failure, from a closed set: `invalid JSON`,
        /// `JSON that is not an audit entry`, or `truncated JSON`.
        reason: &'static str,
    },

    /// The serialized row is longer than [`MAX_ROW_BYTES`].
    ///
    /// [`AuditWriter::write_entry`] and the outbox drain measure the row before
    /// the append's checks, drain, or rotation, so the file, the chain, the
    /// anchor, and the audit directory are unchanged. A row
    /// [`AuditWriter::write_built`] builds exists only after the append's
    /// rotation, by that method's contract, so a rotation the file was due for
    /// may precede the refusal; the row itself is never written.
    #[error(
        "audit.row_too_large: the serialized row is {bytes} bytes, over the {cap}-byte \
         cap; the row was not written"
    )]
    RowTooLarge {
        /// Length of the serialized row, newline included.
        bytes: u64,
        /// The cap, [`MAX_ROW_BYTES`].
        cap: u64,
    },
    /// The outbox does not contain its committed prefix unchanged and in order.
    #[error(
        "audit.outbox_rows_missing: the audit outbox does not hold the {recorded} queued rows the keyring records, unchanged and in order ({found} complete lines found); queued consent rows were removed or changed outside the wallet; see `stellar-agent audit acknowledge-outbox-loss`"
    )]
    OutboxRowsMissing {
        /// Number of rows committed in the keyring.
        recorded: u64,
        /// Number of complete lines found.
        found: u64,
    },
    /// No committed outbox loss remains to acknowledge.
    #[error(
        "audit.outbox_loss_not_found: no committed outbox loss was found; nothing was acknowledged"
    )]
    OutboxLossNotFound,
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
/// Each sub-code identifies the documented recovery procedure for its condition.
#[must_use]
pub fn audit_log_unusable_detail(e: &WriterError) -> Option<String> {
    match e {
        WriterError::FileLocked => Some(
            "audit.writer_locked: an active audit writer holds this profile's lock \
             (for example, a running stellar-agent-mcp server); stop the process using \
             this profile, retry the command, then restart the server if needed"
                .to_owned(),
        ),
        // These carry their own `audit.*` code at the head of their Display.
        WriterError::RotationBridgeUnusable { .. }
        | WriterError::IntegrityViolation(_)
        | WriterError::OutboxBusy
        | WriterError::OutboxUnusable { .. }
        | WriterError::RowTooLarge { .. }
        | WriterError::OutboxRowsMissing { .. }
        | WriterError::OutboxLossNotFound => Some(e.to_string()),
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
        | WriterError::TipAnchorMissing { .. }
        | WriterError::PathMismatch { .. }
        | WriterError::HmacKeyMismatch { .. } => None,
    }
}

/// Maps an audit-writer failure to the [`WalletError`] that names its
/// condition, for a caller that refuses because a required audit row cannot
/// be written.
///
/// Three outcomes, because three different things are wrong and three
/// different things fix them:
///
/// - A tip-anchor mismatch is [`ValidationError::AuditTipAnchorMismatch`], and
///   an absent anchor the log shows was written is
///   [`ValidationError::AuditTipAnchorMissing`]: the log may have been rolled
///   back or truncated, and only `audit reanchor` addresses that.
/// - A condition about the log, as [`audit_log_unusable_detail`] names it, is
///   [`ValidationError::AuditLogUnusable`], led by its `audit.*` sub-code.
/// - Everything left is a registry path or key registration conflict, which
///   is what [`ValidationError::AuditWriterOpenFailed`] describes.
///
/// [`WalletError`]: crate::error::WalletError
/// [`ValidationError::AuditTipAnchorMismatch`]: crate::error::ValidationError::AuditTipAnchorMismatch
/// [`ValidationError::AuditTipAnchorMissing`]: crate::error::ValidationError::AuditTipAnchorMissing
/// [`ValidationError::AuditLogUnusable`]: crate::error::ValidationError::AuditLogUnusable
/// [`ValidationError::AuditWriterOpenFailed`]: crate::error::ValidationError::AuditWriterOpenFailed
#[must_use]
pub fn audit_writer_refusal(profile: &str, e: &WriterError) -> crate::error::WalletError {
    use crate::error::{ValidationError, WalletError};

    if let WriterError::TipAnchorMismatch { reason, .. } = e {
        return WalletError::Validation(ValidationError::AuditTipAnchorMismatch {
            profile: profile.to_owned(),
            reason: (*reason).to_owned(),
        });
    }
    if let WriterError::TipAnchorMissing { evidence, .. } = e {
        return WalletError::Validation(ValidationError::AuditTipAnchorMissing {
            profile: profile.to_owned(),
            evidence: evidence.describe().to_owned(),
        });
    }
    if let Some(detail) = audit_log_unusable_detail(e) {
        return WalletError::Validation(ValidationError::AuditLogUnusable {
            profile: profile.to_owned(),
            detail,
        });
    }
    WalletError::Validation(ValidationError::AuditWriterOpenFailed {
        profile: profile.to_owned(),
    })
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
pub(super) fn basename_lossy_path(path: &Path) -> String {
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
    /// Removes one registry entry so tests can observe ownership by a proof alone.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn remove_for_test(profile_name: &str) {
        if let Some(registry) = REGISTRY.get()
            && let Ok(mut registry) = registry.lock()
        {
            registry.remove(profile_name);
        }
    }

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
    /// # The outbox is drained on EVERY call
    ///
    /// A keyed writer drains the audit outbox. A cache miss drains at open,
    /// after anchor reconciliation. A cache hit drains after its anchor check,
    /// under the same writer-mutex guard. Either way, a consent row queued
    /// before this call is in the log when the handle is returned.
    ///
    /// # Errors
    ///
    /// Everything [`AuditWriterRegistry::get_or_open_unkeyed`] returns, plus the
    /// tip-anchor failures of [`AuditWriter::open_with_tip_anchor`] and of
    /// [`AuditWriter::verify_tip_anchor`], plus every error of
    /// [`AuditWriter::drain_outbox`]: [`WriterError::OutboxBusy`],
    /// [`WriterError::OutboxUnusable`], and the errors of the drain's appends.
    pub fn get_or_open_keyed(
        profile_name: &str,
        log_path: &Path,
        access: KeyedAuditAccess,
    ) -> Result<Arc<Mutex<AuditWriter>>, WriterError> {
        let binding = access.binding_history();
        let (handle, opened) = Self::get_or_open_inner(profile_name, log_path, Some(access))?;
        if opened {
            return Ok(handle);
        }
        if let Err(e) = reconcile_cached_tip_anchor(&handle, binding) {
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
        // winner's handle, but only after validating path + key consistency.
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

        // We are the first (or the only) opener for this profile: insert.
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

/// Runs the anchor check on a writer the registry is about to hand out, which
/// for a draining writer also drains the audit outbox, under one guard.
///
/// The drain is a drain point of every keyed acquisition: a caller that read
/// an approval and then acquires the writer gets it back only after any
/// queued consent row is in the log. Holding one guard for both steps keeps
/// another holder of the handle from appending between them.
///
/// A poisoned writer mutex is surfaced as an I/O error rather than unwound, the
/// same discipline [`AuditWriterRegistry::get_or_open_keyed`] applies to the
/// registry mutex, and it is fail-closed for the same reason: a writer whose
/// state cannot be read is a writer whose log cannot be proved current.
fn reconcile_cached_tip_anchor(
    handle: &Arc<Mutex<AuditWriter>>,
    binding: BindingHistory,
) -> Result<(), WriterError> {
    let mut writer = handle.lock().map_err(|_| {
        WriterError::Io(io::Error::other(
            "audit writer mutex poisoned; cannot reconcile the tip anchor",
        ))
    })?;
    // Evidence learned by any acquisition survives later accesses that lack it.
    if binding == BindingHistory::Recorded {
        writer.binding = BindingHistory::Recorded;
    }
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
    use crate::audit_log::test_helpers::rotated_archives_newest_first;
    use std::sync::{Arc, Mutex};
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

    const PRUNE_TEST_KEY: [u8; 32] = [0x63; 32];

    /// Hashes an archive's final entry, which must be a handoff naming it.
    fn archive_handoff_hash(archive: &Path) -> Result<String, WriterError> {
        read_archive_handoff_hash(archive)?.ok_or_else(|| WriterError::RotationBridgeUnusable {
            archive_name: basename_lossy_path(archive),
            reason: "the archive has no readable last entry",
        })
    }

    fn rotate_pruning_fixture(writer: &mut AuditWriter) {
        writer.write_entry(make_entry("")).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        let _threshold = super::super::rotation::test_seam::set_rotation_threshold(&writer.path, 1);
        writer.write_entry(make_entry("")).unwrap();
    }

    fn pruning_fixture(path: &Path, keyed: bool, rotations: usize) -> AuditWriter {
        let mut writer = if keyed {
            AuditWriter::open_keyed_unanchored_for_test(
                path.to_path_buf(),
                Zeroizing::new(PRUNE_TEST_KEY),
            )
            .unwrap()
        } else {
            open_no_key(path.to_path_buf())
        };
        writer.write_entry(make_entry("")).unwrap();
        for _ in 0..rotations {
            rotate_pruning_fixture(&mut writer);
        }
        writer
    }

    #[test]
    fn verify_passes_after_twelve_rotations() {
        use super::super::verify::{VerifyWarning, collect_file_chain, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let _writer = pruning_fixture(&path, true, 12);
        let chain = collect_file_chain(&path).unwrap();
        let ok = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        assert!(ok.hmac_verified);
        assert_eq!(ok.files_walked, 11);
        assert_eq!(
            ok.warnings,
            vec![VerifyWarning::PrunedPrefix {
                first_file: basename_lossy_path(&chain[0]),
                pruned_files: 2,
            }]
        );
        assert_eq!(
            serde_json::to_value(&ok.warnings[0]).unwrap()["kind"],
            "pruned_prefix"
        );
        assert!(!is_rotated_sibling("audit.jsonl", "audit.jsonl.pruned"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(prune_marker_path(&path))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn verify_detects_an_interior_edit_after_pruning() {
        use super::super::verify::{VerifyError, collect_file_chain, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let _writer = pruning_fixture(&path, true, 12);
        let archive = collect_file_chain(&path).unwrap()[4].clone();
        let content = fs::read_to_string(&archive).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_owned).collect();
        let mut entry: AuditEntry = serde_json::from_str(&lines[1]).unwrap();
        entry.request_id = "edited-interior-row".to_owned();
        lines[1] = serde_json::to_string(&entry).unwrap();
        fs::write(&archive, format!("{}\n", lines.join("\n"))).unwrap();
        assert!(matches!(verify_log(&path, Some(&PRUNE_TEST_KEY)),
            Err(VerifyError::ChainBroken { file, line: 3, .. })
                if file == basename_lossy_path(&archive)));
    }

    #[test]
    fn verify_refuses_an_archive_deleted_beyond_the_marker() {
        use super::super::verify::{VerifyError, collect_file_chain, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, true, 12);
        let chain = collect_file_chain(&path).unwrap();
        fs::remove_file(&chain[0]).unwrap();
        let marker = fs::read(prune_marker_path(&path)).unwrap();
        assert!(matches!(verify_log(&path, Some(&PRUNE_TEST_KEY)),
            Err(VerifyError::ChainBroken { file, line: 1, .. })
                if file == basename_lossy_path(&chain[1])));
        rotate_pruning_fixture(&mut writer);
        rotate_pruning_fixture(&mut writer);
        assert_eq!(
            fs::read(prune_marker_path(&path)).unwrap(),
            marker,
            "pruning cannot adopt a boundary beyond the authenticated marker"
        );
        assert!(matches!(verify_log(&path, Some(&PRUNE_TEST_KEY)),
            Err(VerifyError::ChainBroken { file, line: 1, .. })
                if file == basename_lossy_path(&chain[1])));
    }

    #[test]
    fn verify_refuses_a_forged_marker() {
        use super::super::verify::{VerifyError, collect_file_chain, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let _writer = pruning_fixture(&path, true, 12);
        let chain = collect_file_chain(&path).unwrap();
        let seed = archive_handoff_hash(&chain[0]).unwrap();
        fs::remove_file(&chain[0]).unwrap();
        let marker_path = prune_marker_path(&path);
        let mut marker = read_prune_marker(&path).unwrap().unwrap();
        marker.data.oldest = PruneSeed {
            file: basename_lossy_path(&chain[1]),
            initial_prev_hash: seed,
        };
        for tag in [None, Some(ZERO_BLOCK_HASH.to_owned())] {
            marker.tag = tag;
            fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();
            assert!(matches!(verify_log(&path, Some(&PRUNE_TEST_KEY)),
                Err(VerifyError::HmacMismatch { file }) if file == "audit.jsonl.pruned"));
        }
    }

    #[test]
    fn a_crash_between_marker_and_removal_still_verifies() {
        use super::super::verify::{VerifyWarning, collect_file_chain, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, true, 10);
        let oldest = collect_file_chain(&path).unwrap()[0].clone();
        writer.skip_prune_removal = true;
        rotate_pruning_fixture(&mut writer);
        assert!(oldest.exists(), "the deletion waits for the durable marker");
        assert!(hmac_sidecar_path(&oldest).exists());
        let marker = read_prune_marker(&path).unwrap().unwrap();
        assert_eq!(
            marker.data.previous.as_ref().unwrap().file,
            basename_lossy_path(&oldest)
        );
        assert_eq!(marker.data.pruned_files, 1);
        let ok = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        assert!(ok.hmac_verified);
        assert_eq!(ok.files_walked, 12);
        assert!(
            ok.warnings.is_empty(),
            "the complete prefix is still present"
        );
        writer.skip_prune_removal = false;
        let chain = collect_file_chain(&path).unwrap();
        writer
            .prune_rotated_files(&rotated_archive_from_file(&chain[chain.len() - 2]))
            .unwrap();
        assert!(!oldest.exists());
        assert!(!hmac_sidecar_path(&oldest).exists());
        assert_eq!(
            read_prune_marker(&path).unwrap().unwrap().data.pruned_files,
            1,
            "retrying the recorded deletion counts it once"
        );
        assert_eq!(
            verify_log(&path, Some(&PRUNE_TEST_KEY))
                .unwrap()
                .files_walked,
            11
        );
        rotate_pruning_fixture(&mut writer);
        let ok = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        assert!(ok.hmac_verified);
        assert_eq!(ok.files_walked, 11);
        assert!(matches!(
            &ok.warnings[..],
            [VerifyWarning::PrunedPrefix {
                pruned_files: 2,
                ..
            }]
        ));
    }

    #[test]
    fn a_crash_at_a_later_prune_verifies_from_the_previous_seed() {
        use super::super::verify::{VerifyWarning, collect_file_chain, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, true, 11);
        assert_eq!(
            read_prune_marker(&path).unwrap().unwrap().data.pruned_files,
            1,
            "the first prune has run"
        );
        let unremoved = collect_file_chain(&path).unwrap()[0].clone();
        writer.skip_prune_removal = true;
        rotate_pruning_fixture(&mut writer);
        assert!(
            unremoved.exists(),
            "the deletion waits for the durable marker"
        );
        let marker = read_prune_marker(&path).unwrap().unwrap();
        let previous = marker.data.previous.as_ref().unwrap();
        assert_eq!(previous.file, basename_lossy_path(&unremoved));
        assert_ne!(
            previous.initial_prev_hash, ZERO_BLOCK_HASH,
            "the unremoved file chains from the handoff of an archive already pruned"
        );
        assert_eq!(marker.data.pruned_files, 2);
        let ok = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        assert!(ok.hmac_verified);
        // Eleven archives, the unremoved one included, plus the active file.
        assert_eq!(ok.files_walked, 12);
        assert_eq!(
            ok.warnings,
            vec![VerifyWarning::PrunedPrefix {
                first_file: basename_lossy_path(&unremoved),
                pruned_files: 2,
            }]
        );

        writer.skip_prune_removal = false;
        rotate_pruning_fixture(&mut writer);
        assert!(!unremoved.exists());
        let chain = collect_file_chain(&path).unwrap();
        let ok = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        assert!(ok.hmac_verified);
        assert_eq!(ok.files_walked, 11);
        assert_eq!(
            ok.warnings,
            vec![VerifyWarning::PrunedPrefix {
                first_file: basename_lossy_path(&chain[0]),
                pruned_files: 3,
            }]
        );
    }

    /// A keyed writer with an anchor store, rotated as [`pruning_fixture`]
    /// rotates, so the tip-anchor checks run on every append.
    fn anchored_pruning_fixture(
        path: &Path,
        rotations: usize,
    ) -> (AuditWriter, Arc<InMemoryTipAnchorStore>) {
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let access = KeyedAuditAccess::new(
            Zeroizing::new(PRUNE_TEST_KEY),
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        );
        let mut writer = AuditWriter::open(path.to_path_buf(), Some(access)).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        for _ in 0..rotations {
            rotate_pruning_fixture(&mut writer);
        }
        (writer, store)
    }

    /// Rotates once more and asserts that the prune failed without touching
    /// the rotation: the new active file exists, the next append lands and the
    /// anchor names it, no archive is removed, and the marker bytes are
    /// unchanged.
    fn assert_prune_failure_keeps_the_rotation(
        writer: &mut AuditWriter,
        store: &Arc<InMemoryTipAnchorStore>,
        marker: Option<&[u8]>,
    ) {
        use super::super::verify::collect_file_chain;
        let path = writer.path.clone();
        let mut archives = collect_file_chain(&path).unwrap();
        archives.pop();
        rotate_pruning_fixture(writer);
        assert!(path.exists(), "the rotation created the new active file");
        writer.write_entry(make_entry("")).unwrap();
        writer.require_anchor_current().unwrap();
        assert_eq!(
            stored_value(store),
            TipAnchor::new(
                writer.entry_count,
                writer.last_hash.clone(),
                writer.end_offset
            )
            .to_keyring_value(),
            "the anchor names the append after the failed prune"
        );
        let mut after = collect_file_chain(&path).unwrap();
        after.pop();
        assert_eq!(after.len(), archives.len() + 1, "no archive was removed");
        assert!(archives.iter().all(|archive| after.contains(archive)));
        let on_disk = fs::read(prune_marker_path(&path)).ok();
        assert_eq!(on_disk.as_deref(), marker, "the marker is unchanged");
    }

    #[test]
    fn a_garbled_prune_marker_never_fails_the_rotation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let (mut writer, store) = anchored_pruning_fixture(&path, 11);
        fs::write(prune_marker_path(&path), b"not JSON").unwrap();
        assert_prune_failure_keeps_the_rotation(&mut writer, &store, Some(b"not JSON".as_slice()));
    }

    #[test]
    fn a_forged_prune_marker_never_fails_the_rotation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let (mut writer, store) = anchored_pruning_fixture(&path, 11);
        let mut marker = read_prune_marker(&path).unwrap().unwrap();
        marker.tag = Some(ZERO_BLOCK_HASH.to_owned());
        let forged = serde_json::to_vec(&marker).unwrap();
        fs::write(prune_marker_path(&path), &forged).unwrap();
        assert_prune_failure_keeps_the_rotation(&mut writer, &store, Some(forged.as_slice()));
    }

    #[test]
    fn a_failed_prune_marker_write_never_fails_the_rotation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let (mut writer, store) = anchored_pruning_fixture(&path, 11);
        let marker = fs::read(prune_marker_path(&path)).unwrap();
        // A directory at the temp path makes the atomic marker write fail.
        fs::create_dir(dir.path().join("audit.jsonl.pruned.tmp")).unwrap();
        assert_prune_failure_keeps_the_rotation(&mut writer, &store, Some(marker.as_slice()));
    }

    /// The real archives, oldest first, without the active file.
    fn real_archives(path: &Path) -> Vec<PathBuf> {
        let mut archives = super::super::verify::collect_file_chain(path).unwrap();
        archives.pop();
        archives
    }

    /// Sibling names that sort right after `archive` and before any archive a
    /// later millisecond creates.
    fn sibling_names_after(archive: &Path, count: usize) -> Vec<PathBuf> {
        let name = basename_lossy_path(archive);
        let base = name.split_once('-').map_or(name.as_str(), |(base, _)| base);
        (1..=count)
            .map(|n| archive.with_file_name(format!("{base}-9999999{n}")))
            .inspect(|file| {
                assert!(is_rotated_sibling(
                    "audit.jsonl",
                    &basename_lossy_path(file)
                ));
            })
            .collect()
    }

    /// Plants three sibling-named files right after `archive`, each holding one
    /// rotation handoff naming itself and chained from the previous one, the
    /// first from `archive`'s handoff. Every planted file is internally
    /// consistent and the run bridges from `archive`. Returns the planted files
    /// and the last planted handoff hash.
    fn plant_handoff_run_after(archive: &Path) -> (Vec<PathBuf>, String) {
        let planted = sibling_names_after(archive, 3);
        let mut previous = archive_handoff_hash(archive).unwrap();
        for file in &planted {
            let mut handoff =
                AuditEntry::new_rotation_handoff(basename_lossy_path(file), "planted");
            handoff.previous_entry_hash = previous.clone();
            previous = compute_entry_hash_streamed(&handoff, &previous).unwrap();
            let mut line = serde_json::to_vec(&handoff).unwrap();
            line.push(b'\n');
            fs::write(file, line).unwrap();
            assert_eq!(archive_handoff_hash(file).unwrap(), previous);
        }
        (planted, previous)
    }

    /// Lets the clock pass the newest archive's millisecond, so the next
    /// archive is named from the clock rather than from a counter after the
    /// names [`sibling_names_after`] produced.
    fn wait_for_a_later_archive_name() {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    /// Replaces `file`'s first entry's `previous_entry_hash` in place. Hashes
    /// share one length, so the file keeps its length.
    fn edit_first_previous_hash(file: &Path, previous: &str) {
        let content = fs::read_to_string(file).unwrap();
        let first = content.lines().next().unwrap();
        let entry: AuditEntry = serde_json::from_str(first).unwrap();
        let edited = content.replacen(&entry.previous_entry_hash, previous, 1);
        assert_eq!(edited.len(), content.len());
        assert_ne!(edited, content);
        fs::write(file, edited).unwrap();
    }

    /// Asserts that every real archive survived, nothing planted was removed,
    /// and the prune wrote no marker.
    fn assert_nothing_pruned(path: &Path, real: &[PathBuf], planted: &[PathBuf]) {
        assert!(
            real.iter().all(|archive| archive.exists()),
            "no real archive was removed"
        );
        assert!(
            planted
                .iter()
                .all(|file| fs::symlink_metadata(file).is_ok())
        );
        assert!(!prune_marker_path(path).exists(), "no marker was written");
    }

    /// The key a pruning fixture runs under, for a verify of its log.
    fn fixture_key(keyed: bool) -> Option<&'static [u8; 32]> {
        keyed.then_some(&PRUNE_TEST_KEY)
    }

    /// Planted runs are refused by the link proof alone, so each such case
    /// runs unkeyed, where the links are the whole proof, and keyed.
    #[test]
    fn planted_siblings_never_raise_the_prune_excess() {
        for keyed in [false, true] {
            planted_siblings_never_raise_the_prune_excess_case(keyed);
        }
    }

    fn planted_siblings_never_raise_the_prune_excess_case(keyed: bool) {
        use super::super::verify::{collect_file_chain, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, keyed, 10);
        let real = real_archives(&path);
        let (planted, _) = plant_handoff_run_after(&real[real.len() - 1]);
        wait_for_a_later_archive_name();
        rotate_pruning_fixture(&mut writer);
        assert_nothing_pruned(&path, &real, &planted);
        let chain = collect_file_chain(&path).unwrap();
        assert_eq!(
            &chain[real.len()..real.len() + planted.len()],
            &planted[..],
            "the planted files sort between the real archives"
        );
        for file in &planted {
            fs::remove_file(file).unwrap();
        }
        let ok = verify_log(&path, fixture_key(keyed)).unwrap();
        assert_eq!(ok.hmac_verified, keyed);
        assert_eq!(ok.files_walked, real.len() + 2);
        assert!(ok.warnings.is_empty(), "no prefix was pruned");
    }

    /// An archive edited to bridge a planted run, the run itself consistent and
    /// chained from the real predecessor, stops the prune at the edited file.
    #[test]
    fn an_edited_archive_never_bridges_a_planted_run() {
        for keyed in [false, true] {
            an_edited_archive_never_bridges_a_planted_run_case(keyed);
        }
    }

    fn an_edited_archive_never_bridges_a_planted_run_case(keyed: bool) {
        use super::super::verify::{collect_file_chain, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, keyed, 9);
        wait_for_a_later_archive_name();
        rotate_pruning_fixture(&mut writer);
        let real = real_archives(&path);
        assert_eq!(real.len(), 10);
        let (planted, last_planted) = plant_handoff_run_after(&real[8]);
        let edited = &real[9];
        let original = fs::read(edited).unwrap();
        edit_first_previous_hash(edited, &last_planted);
        wait_for_a_later_archive_name();
        rotate_pruning_fixture(&mut writer);
        assert_nothing_pruned(&path, &real, &planted);
        let chain = collect_file_chain(&path).unwrap();
        assert_eq!(
            &chain[9..12],
            &planted[..],
            "the planted run sorts before the edit"
        );

        fs::write(edited, original).unwrap();
        for file in &planted {
            fs::remove_file(file).unwrap();
        }
        let ok = verify_log(&path, fixture_key(keyed)).unwrap();
        assert_eq!(ok.hmac_verified, keyed);
        assert_eq!(ok.files_walked, real.len() + 2);
        assert!(ok.warnings.is_empty(), "no prefix was pruned");
    }

    /// The active file edited before the rotating append to bridge a planted
    /// run never lets the prune count that run.
    #[test]
    fn an_edited_active_file_never_bridges_a_planted_run() {
        for keyed in [false, true] {
            an_edited_active_file_never_bridges_a_planted_run_case(keyed);
        }
    }

    fn an_edited_active_file_never_bridges_a_planted_run_case(keyed: bool) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, keyed, 10);
        let real = real_archives(&path);
        let (planted, last_planted) = plant_handoff_run_after(&real[real.len() - 1]);
        writer.write_entry(make_entry("")).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        edit_first_previous_hash(&path, &last_planted);
        wait_for_a_later_archive_name();
        let _threshold = super::super::rotation::test_seam::set_rotation_threshold(&path, 1);
        writer.write_entry(make_entry("")).unwrap();
        assert_nothing_pruned(&path, &real, &planted);
    }

    /// A file swapped in under the just-rotated archive's name, internally
    /// consistent and chained from a planted run, is not the archive this
    /// writer rotated: the prune proves that archive from memory.
    #[test]
    fn a_file_swapped_in_after_the_rename_is_not_the_rotated_archive() {
        for keyed in [false, true] {
            a_file_swapped_in_after_the_rename_is_not_the_rotated_archive_case(keyed);
        }
    }

    fn a_file_swapped_in_after_the_rename_is_not_the_rotated_archive_case(keyed: bool) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, keyed, 10);
        let real = real_archives(&path);
        let (planted, last_planted) = plant_handoff_run_after(&real[real.len() - 1]);
        wait_for_a_later_archive_name();
        writer.after_rotation_rename = Some(Box::new(move |archive: &Path| {
            let mut row = make_entry("");
            row.previous_entry_hash = last_planted.clone();
            let row_hash = compute_entry_hash_streamed(&row, &last_planted).unwrap();
            let mut handoff =
                AuditEntry::new_rotation_handoff(basename_lossy_path(archive), "swapped");
            handoff.previous_entry_hash = row_hash.clone();
            let mut bytes = serde_json::to_vec(&row).unwrap();
            bytes.push(b'\n');
            bytes.extend(serde_json::to_vec(&handoff).unwrap());
            bytes.push(b'\n');
            fs::write(archive, bytes).unwrap();
        }));
        rotate_pruning_fixture(&mut writer);
        assert_nothing_pruned(&path, &real, &planted);
    }

    /// Plants `make` at a sibling name between the newest archive and the next,
    /// rotates on a thread, and asserts that the rotation returns within a few
    /// seconds and prunes nothing.
    fn assert_a_planted_sibling_stalls_the_prune(make: impl FnOnce(&Path, &Path)) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, true, 10);
        let real = real_archives(&path);
        let planted = sibling_names_after(&real[real.len() - 1], 1);
        make(&planted[0], &real[real.len() - 1]);
        wait_for_a_later_archive_name();
        let (done, rotated) = std::sync::mpsc::channel();
        let rotation = std::thread::spawn(move || {
            rotate_pruning_fixture(&mut writer);
            let _ = done.send(());
            writer
        });
        match rotated.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(()) => drop(rotation.join().unwrap()),
            // The thread dropped its sender without sending: it panicked.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => match rotation.join() {
                Err(panic) => std::panic::resume_unwind(panic),
                Ok(_) => panic!("the rotation thread ended without reporting"),
            },
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Releases a rotation blocked on a FIFO; never blocks itself.
                #[cfg(unix)]
                crate::audit_log::test_fifo::release_fifo(&planted[0]);
                panic!("the rotation did not return while pruning a planted sibling");
            }
        }
        assert_nothing_pruned(&path, &real, &planted);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_sibling_never_blocks_the_rotation() {
        assert_a_planted_sibling_stalls_the_prune(|fifo, _| {
            crate::audit_log::test_fifo::make_fifo(fifo);
        });
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_sibling_stalls_the_prune() {
        assert_a_planted_sibling_stalls_the_prune(|link, archive| {
            std::os::unix::fs::symlink(archive, link).unwrap();
        });
    }

    #[test]
    fn a_directory_sibling_stalls_the_prune() {
        assert_a_planted_sibling_stalls_the_prune(|directory, _| {
            fs::create_dir(directory).unwrap();
        });
    }

    /// The just-rotated archive's boundaries as its file states them, for a
    /// prune run outside a rotation over an honest log.
    fn rotated_archive_from_file(archive: &Path) -> RotatedArchive<'_> {
        let content = fs::read_to_string(archive).unwrap();
        let first: AuditEntry = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        RotatedArchive {
            path: archive,
            seed: first.previous_entry_hash,
            handoff: archive_handoff_hash(archive).unwrap(),
        }
    }

    #[test]
    fn an_oversized_sibling_stops_the_prune_at_the_read_budget() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, true, 10);
        let real = real_archives(&path);
        let planted = sibling_names_after(&real[real.len() - 1], 1);
        // One line past the line cap, sparse and without a newline.
        fs::File::create(&planted[0])
            .unwrap()
            .set_len(PRUNE_LINE_CAP + 1)
            .unwrap();
        wait_for_a_later_archive_name();
        rotate_pruning_fixture(&mut writer);
        assert_nothing_pruned(&path, &real, &planted);

        let mut chain = real_archives(&path);
        let rotated = chain.pop().unwrap();
        chain.push(rotated.clone());
        let boundaries = rotated_archive_from_file(&rotated);
        let stop = prove_prune_chain(&chain, ZERO_BLOCK_HASH, &boundaries, Some(&PRUNE_TEST_KEY))
            .unwrap_err();
        assert_eq!(stop.file, planted[0]);
        assert!(
            matches!(
                *stop.cause,
                PruneStopCause::OverBudget(ReadBudgetExceeded { limit: "line", .. })
            ),
            "{:?}",
            stop.cause
        );

        // A file past the file cap stops before any byte of it is read.
        fs::File::options()
            .write(true)
            .open(&planted[0])
            .unwrap()
            .set_len(PRUNE_FILE_CAP + 1)
            .unwrap();
        let stop = prove_prune_chain(&chain, ZERO_BLOCK_HASH, &boundaries, Some(&PRUNE_TEST_KEY))
            .unwrap_err();
        assert!(
            matches!(
                *stop.cause,
                PruneStopCause::OverBudget(ReadBudgetExceeded { limit: "file", .. })
            ),
            "{:?}",
            stop.cause
        );
    }

    /// A line under the line budget but past what remains of the file budget
    /// stops at the file budget: the read is bounded by both.
    #[test]
    fn a_budgeted_scan_stops_at_the_remaining_file_budget() {
        let dir = TempDir::new().unwrap();
        let long_line = dir.path().join("long-line");
        fs::write(&long_line, vec![b'x'; 2000]).unwrap();
        let file = File::open(&long_line).unwrap();
        let budget = ScanBudget {
            line: 1500,
            file: 1000,
        };
        let Err(err) = scan_entry_chain(&file, 0, None, Some(budget)) else {
            panic!("the scan must stop at a budget");
        };
        let cause = PruneStopCause::from_scan_error(err);
        assert!(
            matches!(
                cause,
                PruneStopCause::OverBudget(ReadBudgetExceeded {
                    limit: "file",
                    bytes: 1000
                })
            ),
            "{cause:?}"
        );
    }

    /// A copy of the archive the last prune deleted, planted back under its own
    /// name, sorts oldest and is the one deleted; the real archives the honest
    /// prune keeps all survive.
    #[test]
    fn a_planted_copy_of_a_pruned_archive_is_deleted_first() {
        use super::super::verify::{VerifyWarning, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, true, 10);
        let real = real_archives(&path);
        let pruned_bytes = fs::read(&real[0]).unwrap();
        let pruned_tag = fs::read(hmac_sidecar_path(&real[0])).unwrap();
        rotate_pruning_fixture(&mut writer);
        assert!(
            !real[0].exists(),
            "the first prune removes the oldest archive"
        );
        // The copy comes back with its own valid chain-root tag.
        fs::write(&real[0], &pruned_bytes).unwrap();
        fs::write(hmac_sidecar_path(&real[0]), &pruned_tag).unwrap();
        rotate_pruning_fixture(&mut writer);
        let kept = real_archives(&path);
        assert!(!real[0].exists(), "the planted copy is deleted");
        assert!(!real[1].exists(), "the honest prune removes its archive");
        assert_eq!(kept.len(), 10);
        assert_eq!(
            &kept[..8],
            &real[2..],
            "every archive the honest prune keeps survives"
        );
        assert_eq!(
            read_prune_marker(&path).unwrap().unwrap().data.pruned_files,
            2,
            "the copy retries the recorded deletion"
        );
        let ok = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        assert!(ok.hmac_verified);
        assert_eq!(ok.files_walked, 11);
        assert_eq!(
            ok.warnings,
            vec![VerifyWarning::PrunedPrefix {
                first_file: basename_lossy_path(&real[2]),
                pruned_files: 2,
            }]
        );
    }

    /// Siblings planted under names that sort after every archive come before
    /// the next archive, which is named after them. The prune stops at the
    /// first of them with every archive kept; once they are removed, the next
    /// prune proves the chain and the log verifies.
    #[test]
    fn siblings_planted_after_the_newest_archive_stop_the_prune_until_removed() {
        use super::super::verify::{VerifyWarning, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, true, 10);
        let real = real_archives(&path);
        let planted: Vec<PathBuf> = (1..=3)
            .map(|n| path.with_file_name(format!("audit.jsonl.20991231T23595999{n}")))
            .collect();
        for file in &planted {
            fs::write(file, b"{\"planted\":true}\n").unwrap();
        }
        rotate_pruning_fixture(&mut writer);
        let rotated = real_archives(&path).pop().unwrap();
        assert_eq!(
            basename_lossy_path(&rotated),
            "audit.jsonl.20991231T235959993-000001",
            "the new archive sorts after the planted siblings"
        );
        assert_nothing_pruned(&path, &real, &planted);

        for file in &planted {
            fs::remove_file(file).unwrap();
        }
        rotate_pruning_fixture(&mut writer);
        assert!(!real[0].exists() && !real[1].exists(), "the prune resumed");
        assert!(real[2..].iter().all(|archive| archive.exists()));
        assert!(rotated.exists());
        let ok = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        assert!(ok.hmac_verified);
        assert_eq!(ok.files_walked, 11);
        assert_eq!(
            ok.warnings,
            vec![VerifyWarning::PrunedPrefix {
                first_file: basename_lossy_path(&real[2]),
                pruned_files: 2,
            }]
        );
    }

    #[test]
    fn a_prune_stops_on_an_unusable_handoff() {
        use super::super::verify::{VerifyError, collect_file_chain, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, true, 10);
        let oldest = collect_file_chain(&path).unwrap()[0].clone();
        let content = fs::read_to_string(&oldest).unwrap();
        let mut lines: Vec<&str> = content.lines().collect();
        lines.pop();
        let edited = format!("{}\n", lines.join("\n"));
        fs::write(&oldest, &edited).unwrap();
        rotate_pruning_fixture(&mut writer);
        assert_eq!(fs::read_to_string(&oldest).unwrap(), edited);
        assert!(hmac_sidecar_path(&oldest).exists());
        assert!(!prune_marker_path(&path).exists());
        assert_eq!(collect_file_chain(&path).unwrap().len(), 12);
        assert!(matches!(
            verify_log(&path, Some(&PRUNE_TEST_KEY)),
            Err(VerifyError::ChainBroken { .. } | VerifyError::RotationGap { .. })
        ));
    }

    #[test]
    fn resign_covers_the_prune_marker() {
        use super::super::rotation::resign_chain_root_sidecars;
        use super::super::verify::{VerifyError, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = pruning_fixture(&path, true, 12);
        drop(writer);
        let new_key = [0x64; 32];
        assert_eq!(resign_chain_root_sidecars(&path, &new_key).unwrap(), 12);
        assert!(verify_log(&path, Some(&new_key)).unwrap().hmac_verified);
        assert!(matches!(verify_log(&path, Some(&PRUNE_TEST_KEY)),
            Err(VerifyError::HmacMismatch { file }) if file == "audit.jsonl.pruned"));
    }

    #[test]
    fn an_unkeyed_writer_writes_an_untagged_marker() {
        use super::super::verify::{VerifyWarning, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let _writer = pruning_fixture(&path, false, 12);
        assert!(read_prune_marker(&path).unwrap().unwrap().tag.is_none());
        let ok = verify_log(&path, None).unwrap();
        assert!(!ok.hmac_verified);
        assert_eq!(ok.files_walked, 11);
        assert!(matches!(
            &ok.warnings[..],
            [VerifyWarning::PrunedPrefix {
                pruned_files: 2,
                ..
            }]
        ));
    }

    #[test]
    fn verify_refuses_a_malformed_prune_marker() {
        use super::super::verify::{VerifyError, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let _writer = pruning_fixture(&path, true, 12);
        let mut marker = read_prune_marker(&path).unwrap().unwrap();
        marker.data.version = 2;
        for bytes in [
            b"not JSON".to_vec(),
            vec![0xff],
            serde_json::to_vec(&marker).unwrap(),
        ] {
            fs::write(prune_marker_path(&path), bytes).unwrap();
            assert!(matches!(verify_log(&path, Some(&PRUNE_TEST_KEY)),
                Err(VerifyError::ParseError { detail, .. }) if detail.contains("audit.jsonl.pruned")));
        }
    }

    /// An archive holding a rotation handoff before its last entry links
    /// across that handoff. Split there into a prefix under the handoff's name
    /// with the archive's own tag and a suffix under the archive's name, the
    /// sequence still links, but the suffix starts on an entry no keyed writer
    /// signed, so a keyed prune counts neither part and deletes nothing.
    ///
    /// The writer completes a pending handoff's rotation before any further
    /// row, so it never writes such an archive; the fixture builds one by
    /// dropping the pending handoff and appending past it.
    #[test]
    fn an_archive_split_at_an_interior_handoff_never_raises_the_prune_excess() {
        use super::super::verify::{collect_file_chain, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, true, 4);
        wait_for_a_later_archive_name();
        writer.write_rotation_handoff_for_test().unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let last: AuditEntry = serde_json::from_str(content.lines().last().unwrap()).unwrap();
        let EventKind::AuditRotationHandoff {
            next_file_name: interior_name,
        } = last.event_kind
        else {
            panic!("the interrupted rotation ends on its handoff");
        };
        writer.pending_handoff = None;
        for _ in 0..6 {
            wait_for_a_later_archive_name();
            rotate_pruning_fixture(&mut writer);
        }
        let real = real_archives(&path);
        assert_eq!(real.len(), 10);
        let split = real[4].clone();
        let original = fs::read_to_string(&split).unwrap();
        let lines: Vec<&str> = original.lines().collect();
        let at = lines
            .iter()
            .position(|line| line.contains(interior_name.as_str()))
            .unwrap();
        assert!(
            at + 1 < lines.len(),
            "the handoff is interior to the archive"
        );
        let prefix = split.with_file_name(&interior_name);
        fs::write(&prefix, format!("{}\n", lines[..=at].join("\n"))).unwrap();
        fs::copy(hmac_sidecar_path(&split), hmac_sidecar_path(&prefix)).unwrap();
        fs::write(&split, format!("{}\n", lines[at + 1..].join("\n"))).unwrap();
        let chain = collect_file_chain(&path).unwrap();
        assert_eq!(chain[4], prefix, "the prefix sorts right before the suffix");
        assert_eq!(chain[5], split);

        wait_for_a_later_archive_name();
        rotate_pruning_fixture(&mut writer);
        assert_nothing_pruned(&path, &real, std::slice::from_ref(&prefix));

        fs::write(&split, &original).unwrap();
        fs::remove_file(&prefix).unwrap();
        fs::remove_file(hmac_sidecar_path(&prefix)).unwrap();
        let ok = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        assert!(ok.hmac_verified);
        assert_eq!(ok.files_walked, real.len() + 2);
        assert!(ok.warnings.is_empty(), "no prefix was pruned");
    }

    #[test]
    fn an_archive_without_its_root_tag_stalls_a_keyed_prune() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, true, 10);
        let real = real_archives(&path);
        fs::remove_file(hmac_sidecar_path(&real[3])).unwrap();
        rotate_pruning_fixture(&mut writer);
        assert_nothing_pruned(&path, &real, &[]);

        let mut chain = real_archives(&path);
        let rotated = chain.pop().unwrap();
        chain.push(rotated.clone());
        let boundaries = rotated_archive_from_file(&rotated);
        let stop = prove_prune_chain(&chain, ZERO_BLOCK_HASH, &boundaries, Some(&PRUNE_TEST_KEY))
            .unwrap_err();
        assert_eq!(stop.file, real[3]);
        assert!(
            matches!(
                &*stop.cause,
                PruneStopCause::RootTag(super::super::verify::VerifyError::HmacSidecarMissing { file })
                    if *file == basename_lossy_path(&real[3])
            ),
            "{:?}",
            stop.cause
        );
    }

    /// Opens a keyed writer with an anchor store on `path`.
    fn open_keyed_anchored(path: &Path, store: &Arc<InMemoryTipAnchorStore>) -> AuditWriter {
        let access = KeyedAuditAccess::new(
            Zeroizing::new(PRUNE_TEST_KEY),
            Arc::clone(store) as Arc<dyn TipAnchorStore>,
        );
        AuditWriter::open(path.to_path_buf(), Some(access)).unwrap()
    }

    /// Fails the first entry's sidecar write on a fresh keyed log, so the file
    /// holds a durable first entry and no chain-root tag.
    fn first_entry_without_its_root_tag(path: &Path, store: &Arc<InMemoryTipAnchorStore>) {
        let mut writer = open_keyed_anchored(path, store);
        writer.set_fail_after_entry_before_sidecar(true);
        writer.write_entry(make_entry("")).unwrap_err();
        drop(writer);
        assert!(!hmac_sidecar_path(path).exists());
        assert!(!fs::read(path).unwrap().is_empty());
    }

    #[test]
    fn a_keyed_open_writes_a_missing_root_tag_before_any_rotation() {
        use super::super::verify::verify_log;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        // The first entry of the file a rotation created lands without its tag;
        // the anchor still names the archive's handoff.
        let mut writer = open_keyed_anchored(&path, &store);
        writer.write_entry(make_entry("")).unwrap();
        writer.force_rotate_for_test().unwrap();
        writer.set_fail_after_entry_before_sidecar(true);
        writer.write_entry(make_entry("")).unwrap_err();
        drop(writer);
        assert!(!hmac_sidecar_path(&path).exists());

        let mut writer = open_keyed_anchored(&path, &store);
        assert!(
            hmac_sidecar_path(&path).exists(),
            "the open wrote the missing tag"
        );
        assert!(
            verify_log(&path, Some(&PRUNE_TEST_KEY))
                .unwrap()
                .hmac_verified
        );

        rotate_pruning_fixture(&mut writer);
        let archives = real_archives(&path);
        assert_eq!(archives.len(), 2);
        assert!(hmac_sidecar_path(&archives[1]).exists());
        assert!(
            verify_log(&path, Some(&PRUNE_TEST_KEY))
                .unwrap()
                .hmac_verified
        );
    }

    /// An adopted file had no anchor to be proved against, so the open mints
    /// no tag for it.
    #[test]
    fn an_adopted_file_gets_no_root_tag_at_open() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        first_entry_without_its_root_tag(&path, &store);
        assert!(store.peek().is_none(), "the failed append anchored nothing");
        let _writer = open_keyed_anchored(&path, &store);
        assert!(store.peek().is_some(), "the open adopted the file");
        assert!(!hmac_sidecar_path(&path).exists());
    }

    /// The active file holds handoffs P and Q, the anchor on Q. The writer
    /// completes a pending handoff's rotation before it writes anything else,
    /// so the fixture appends Q past P through the seam that writes a bare
    /// handoff. The prefix through P moves to an archive under P's name with
    /// the active file's tag, blank lines of equal length replace it, and the
    /// active tag is removed: the tip and its offset still match.
    /// The open proves the count from byte 0, refuses, and mints no tag.
    #[test]
    fn a_padded_split_of_the_active_file_refuses_and_gets_no_root_tag() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let (mut writer, store) = anchored_pruning_fixture(&path, 10);
        writer.write_entry(make_entry("")).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        wait_for_a_later_archive_name();
        writer.write_rotation_handoff_for_test().unwrap();
        drop(writer);
        let mut writer = open_keyed_anchored(&path, &store);
        wait_for_a_later_archive_name();
        writer.write_rotation_handoff_for_test().unwrap();
        drop(writer);
        let real = real_archives(&path);
        assert_eq!(real.len(), 10);

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let handoffs: Vec<(usize, String)> = lines
            .iter()
            .enumerate()
            .filter_map(|(at, line)| {
                match serde_json::from_str::<AuditEntry>(line).unwrap().event_kind {
                    EventKind::AuditRotationHandoff { next_file_name } => {
                        Some((at, next_file_name))
                    }
                    _ => None,
                }
            })
            .collect();
        assert_eq!(handoffs.len(), 2);
        let (at_p, p_name) = &handoffs[0];
        let prefix = format!("{}\n", lines[..=*at_p].join("\n"));
        let planted = path.with_file_name(p_name);
        fs::write(&planted, &prefix).unwrap();
        fs::copy(hmac_sidecar_path(&path), hmac_sidecar_path(&planted)).unwrap();
        let padded = format!(
            "{}{}\n",
            "\n".repeat(prefix.len()),
            lines[at_p + 1..].join("\n")
        );
        assert_eq!(padded.len(), content.len());
        fs::write(&path, padded).unwrap();
        fs::remove_file(hmac_sidecar_path(&path)).unwrap();

        let access = KeyedAuditAccess::new(
            Zeroizing::new(PRUNE_TEST_KEY),
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        );
        let err = AuditWriter::open(path.clone(), Some(access)).unwrap_err();
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. } if *reason == LOG_COUNT_REASON
            ),
            "{err:?}"
        );
        assert!(!hmac_sidecar_path(&path).exists(), "no tag was minted");
        assert_nothing_pruned(&path, &real, std::slice::from_ref(&planted));
    }

    /// A blank line before an otherwise intact anchored first entry is a byte
    /// no honest writer writes, so the open mints no tag for that entry.
    #[test]
    fn a_leading_blank_line_leaves_a_missing_root_tag_unwritten() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let (line, hash) = serialised_entry_line(ZERO_BLOCK_HASH);
        let mut content = b"\n".to_vec();
        content.extend_from_slice(&line);
        fs::write(&path, &content).unwrap();
        let store = Arc::new(InMemoryTipAnchorStore::new());
        store
            .store_anchor(&TipAnchor::new(1, hash, content.len() as u64))
            .unwrap();

        let writer = open_keyed_anchored(&path, &store);
        assert_eq!(writer.entry_count, 1, "the anchor check accepted the file");
        assert!(!hmac_sidecar_path(&path).exists(), "no tag was minted");
    }

    /// Counts the handoffs in `file`.
    fn handoff_count(file: &Path) -> usize {
        fs::read_to_string(file)
            .unwrap()
            .lines()
            .filter(|line| {
                matches!(
                    serde_json::from_str::<AuditEntry>(line).unwrap().event_kind,
                    EventKind::AuditRotationHandoff { .. }
                )
            })
            .count()
    }

    /// Three rotation attempts whose renames fail, two in one process and one
    /// after a reopen, leave one handoff; the rotation that then succeeds
    /// archives the file under that handoff's name within the prune's budget,
    /// and the prunes prove it as the newest archive and as an older one.
    #[test]
    fn a_failed_rotation_rename_is_retried_under_its_one_handoff() {
        use super::super::verify::verify_log;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let (mut writer, store) = anchored_pruning_fixture(&path, 10);
        let real = real_archives(&path);
        writer.write_entry(make_entry("")).unwrap();
        wait_for_a_later_archive_name();
        let _threshold = super::super::rotation::test_seam::set_rotation_threshold(&path, 1);
        writer.set_rotation_renames_to_fail(2);
        writer.write_entry(make_entry("")).unwrap_err();
        writer.write_entry(make_entry("")).unwrap_err();
        assert_eq!(handoff_count(&path), 1);
        drop(writer);
        let mut writer = open_keyed_anchored(&path, &store);
        writer.set_rotation_renames_to_fail(1);
        writer.write_entry(make_entry("")).unwrap_err();
        assert_eq!(handoff_count(&path), 1, "every attempt reused the handoff");
        let content = fs::read_to_string(&path).unwrap();
        let last: AuditEntry = serde_json::from_str(content.lines().last().unwrap()).unwrap();
        let EventKind::AuditRotationHandoff {
            next_file_name: pending_name,
        } = last.event_kind
        else {
            panic!("the file ends on its handoff");
        };

        writer.write_entry(make_entry("")).unwrap();
        let archive = path.with_file_name(&pending_name);
        assert!(archive.exists(), "the archive carries the pending name");
        assert_eq!(handoff_count(&archive), 1);
        assert!(fs::metadata(&archive).unwrap().len() <= PRUNE_FILE_CAP);
        assert!(!real[0].exists(), "the prune proved the new archive");

        wait_for_a_later_archive_name();
        writer.write_entry(make_entry("")).unwrap();
        assert!(
            !real[1].exists(),
            "the next prune proved it as an older one"
        );
        assert!(archive.exists());
        drop(writer);
        assert!(
            verify_log(&path, Some(&PRUNE_TEST_KEY))
                .unwrap()
                .hmac_verified
        );
    }

    /// What [`directory_snapshot`] records of one file.
    #[derive(Debug, PartialEq, Eq)]
    enum SnapshotFile {
        /// The file's bytes.
        Bytes(Vec<u8>),
        /// The length of a lock file the live writer holds.
        HeldLock(u64),
    }

    /// Every file in the directory of the log at `log` with its bytes, in name
    /// order, except the lock sidecar and the drain lock the live writer
    /// holds, which are recorded by their length.
    ///
    /// Windows refuses reads of a file locked with `LockFileEx` through any
    /// other handle, so the held locks are compared by name and length.
    fn directory_snapshot(log: &Path) -> Vec<(String, SnapshotFile)> {
        let held_locks = [
            lock_sidecar_path(log),
            super::super::outbox::drain_lock_path(log),
        ];
        let mut files: Vec<(String, SnapshotFile)> = fs::read_dir(log.parent().unwrap())
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let path = entry.path();
                let state = if held_locks.contains(&path) {
                    SnapshotFile::HeldLock(entry.metadata().unwrap().len())
                } else {
                    SnapshotFile::Bytes(fs::read(&path).unwrap())
                };
                (entry.file_name().to_string_lossy().into_owned(), state)
            })
            .collect();
        files.sort_by(|a, b| a.0.cmp(&b.0));
        files
    }

    /// With the active file at the rotation threshold and the retention cap
    /// reached, an oversized row refuses before the rotation, its handoff, the
    /// anchor move, or the prune.
    #[test]
    fn a_row_over_the_cap_at_the_rotation_threshold_changes_nothing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let (mut writer, store) = anchored_pruning_fixture(&path, 10);
        writer.write_entry(make_entry("")).unwrap();
        let _threshold = super::super::rotation::test_seam::set_rotation_threshold(&path, 1);
        let before = directory_snapshot(&path);
        let anchor = stored_value(&store);

        let row = row_of_len(&writer, MAX_ROW_BYTES + 1);
        let err = writer.write_entry(row).unwrap_err();
        assert!(matches!(err, WriterError::RowTooLarge { .. }), "{err:?}");
        assert_eq!(stored_value(&store), anchor, "the anchor is unchanged");
        assert_eq!(
            directory_snapshot(&path),
            before,
            "no file in the audit directory changed"
        );
    }

    /// Serves an endless line of `x` and counts the bytes read from it.
    struct EndlessLine {
        served: u64,
    }

    impl io::Read for EndlessLine {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            buf.fill(b'x');
            self.served += buf.len() as u64;
            Ok(buf.len())
        }
    }

    /// The file budget bounds the reads below the buffer: a source that never
    /// ends is read for at most the budget and one byte, where a buffer above
    /// the limit would read a whole buffer.
    #[test]
    fn a_budgeted_scan_reads_at_most_one_byte_past_the_file_budget() {
        let mut source = EndlessLine { served: 0 };
        let budget = ScanBudget {
            line: MAX_ROW_BYTES,
            file: 1000,
        };
        let result = scan_entry_reader(&mut source, 0, None, Some(budget));
        assert_eq!(source.served, 1001, "bytes read from the source");
        let Err(err) = result else {
            panic!("the scan must stop at a budget");
        };
        assert!(matches!(
            PruneStopCause::from_scan_error(err),
            PruneStopCause::OverBudget(ReadBudgetExceeded { limit: "file", .. })
        ));
    }

    /// Asserts that the prune proof of `path`'s archives, which no marker
    /// covers, stops at `oldest` because it does not chain from the zero seed.
    fn assert_start_boundary_stall(path: &Path, keyed: bool, oldest: &Path) {
        let chain = real_archives(path);
        assert_eq!(chain[0], oldest);
        let boundaries = rotated_archive_from_file(chain.last().unwrap());
        let stop = prove_prune_chain(&chain, ZERO_BLOCK_HASH, &boundaries, fixture_key(keyed))
            .unwrap_err();
        assert_eq!(stop.file, oldest);
        assert!(
            matches!(
                &*stop.cause,
                PruneStopCause::StartBoundary(WriterError::ChainBrokenAtOpen { entry_idx: 1, .. })
            ),
            "{:?}",
            stop.cause
        );
    }

    /// A log that was never pruned starts at the zero seed. Its oldest archive
    /// deleted outside the prune leaves the next one starting on a handoff no
    /// marker records, so the prune stalls with every archive kept and
    /// verification fails.
    #[test]
    fn a_log_missing_its_oldest_archive_stalls_the_prune() {
        for keyed in [false, true] {
            a_log_missing_its_oldest_archive_stalls_the_prune_case(keyed);
        }
    }

    fn a_log_missing_its_oldest_archive_stalls_the_prune_case(keyed: bool) {
        use super::super::verify::verify_log;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, keyed, 10);
        let real = real_archives(&path);
        fs::remove_file(&real[0]).unwrap();
        if keyed {
            fs::remove_file(hmac_sidecar_path(&real[0])).unwrap();
        }
        rotate_pruning_fixture(&mut writer);
        rotate_pruning_fixture(&mut writer);
        assert_eq!(real_archives(&path).len(), 11, "the prune kept the excess");
        assert_nothing_pruned(&path, &real[1..], &[]);
        assert_start_boundary_stall(&path, keyed, &real[1]);
        assert!(verify_log(&path, fixture_key(keyed)).is_err());
    }

    /// After a prune, the marker is what authenticates the start of the
    /// retained history. With the marker deleted the oldest archive does not
    /// chain from the zero seed, so the next prune stalls with every archive
    /// kept and verification fails.
    #[test]
    fn a_log_missing_its_prune_marker_stalls_the_prune() {
        for keyed in [false, true] {
            a_log_missing_its_prune_marker_stalls_the_prune_case(keyed);
        }
    }

    fn a_log_missing_its_prune_marker_stalls_the_prune_case(keyed: bool) {
        use super::super::verify::verify_log;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, keyed, 11);
        let real = real_archives(&path);
        assert_eq!(real.len(), 10, "one honest prune ran");
        fs::remove_file(prune_marker_path(&path)).unwrap();
        rotate_pruning_fixture(&mut writer);
        assert_eq!(real_archives(&path).len(), 11, "the prune kept the excess");
        assert_nothing_pruned(&path, &real, &[]);
        assert_start_boundary_stall(&path, keyed, &real[0]);
        assert!(verify_log(&path, fixture_key(keyed)).is_err());
    }

    /// A carriage return before the anchored entry's newline moves that
    /// entry's end one byte past the anchored offset, while a reader that
    /// skips whitespace still finds the entry before it. With a chained entry
    /// appended and the root tag removed, the open refuses and mints no tag.
    #[test]
    fn an_anchored_entry_ending_past_its_offset_refuses_and_gets_no_root_tag() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = open_keyed_anchored(&path, &store);
        writer.write_entry(make_entry("")).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        drop(writer);
        let anchor = store.peek().unwrap();
        let mut content = fs::read(&path).unwrap();
        assert_eq!(content.len() as u64, anchor.end_offset);
        content.insert(content.len() - 1, b'\r');
        let (line, _) = serialised_entry_line(&anchor.tip_hash);
        content.extend_from_slice(&line);
        fs::write(&path, &content).unwrap();
        fs::remove_file(hmac_sidecar_path(&path)).unwrap();

        let access = KeyedAuditAccess::new(
            Zeroizing::new(PRUNE_TEST_KEY),
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        );
        let Err(err) = AuditWriter::open(path.clone(), Some(access)) else {
            panic!("the open accepted an anchored entry that ends past the anchored offset");
        };
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. }
                    if *reason == LOG_ENTRY_END_REASON || *reason == LOG_COUNT_REASON
            ),
            "{err:?}"
        );
        assert!(!hmac_sidecar_path(&path).exists(), "no tag was minted");
        assert_eq!(store.peek(), Some(anchor), "the anchor is unchanged");
    }

    /// The archive name the last entry of `file`, a rotation handoff, names.
    fn last_handoff_name(file: &Path) -> String {
        let content = fs::read_to_string(file).unwrap();
        let last: AuditEntry = serde_json::from_str(content.lines().last().unwrap()).unwrap();
        let EventKind::AuditRotationHandoff { next_file_name } = last.event_kind else {
            panic!("the file ends on a rotation handoff");
        };
        next_file_name
    }

    /// A rotation handoff whose fsync failed after its bytes landed is the
    /// file's last entry. The next acquisition reconciles the file and holds
    /// that handoff as pending, so the next append renames the file under it
    /// and the archive ends on its one handoff.
    #[test]
    fn a_handoff_whose_fsync_failed_is_completed_under_its_one_handoff() {
        use super::super::verify::verify_log;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = open_keyed_anchored(&path, &store);
        writer.write_entry(make_entry("")).unwrap();
        let _threshold = super::super::rotation::test_seam::set_rotation_threshold(&path, 1);
        writer.set_fail_sync_after_handoff_write(true);
        writer.write_entry(make_entry("")).unwrap_err();
        writer.set_fail_sync_after_handoff_write(false);
        assert_eq!(handoff_count(&path), 1, "the handoff's bytes landed");
        let pending_name = last_handoff_name(&path);
        assert!(real_archives(&path).is_empty());

        writer.verify_tip_anchor().unwrap();
        writer.write_entry(make_entry("")).unwrap();
        let archives = real_archives(&path);
        assert_eq!(archives, vec![path.with_file_name(&pending_name)]);
        assert_eq!(
            handoff_count(&archives[0]),
            1,
            "the archive holds one handoff"
        );
        archive_handoff_hash(&archives[0]).unwrap();
        assert_eq!(handoff_count(&path), 0);
        verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
    }

    /// A small unanchored file that ends on a rotation handoff is adopted by a
    /// keyed open. The adoption row would be the first row after that handoff,
    /// so the open completes the rotation under the handoff's name first and
    /// the row starts the new file; the next rotation archives that file with
    /// its own one handoff.
    #[test]
    fn an_adopted_file_ending_on_a_handoff_completes_its_rotation_first() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut unkeyed = open_no_key(path.clone());
        unkeyed.write_entry(make_entry("")).unwrap();
        let handoff = unkeyed.write_rotation_handoff_for_test().unwrap();
        drop(unkeyed);
        let pending_name = last_handoff_name(&path);

        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = open_keyed_anchored(&path, &store);
        let archives = real_archives(&path);
        assert_eq!(archives, vec![path.with_file_name(&pending_name)]);
        assert_eq!(archive_handoff_hash(&archives[0]).unwrap(), handoff);
        assert_eq!(handoff_count(&archives[0]), 1);
        let content = fs::read_to_string(&path).unwrap();
        let first: AuditEntry = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(
            first.previous_entry_hash, handoff,
            "the adoption row starts the new file"
        );
        assert!(matches!(
            first.event_kind,
            EventKind::AuditTipAnchored { .. }
        ));

        wait_for_a_later_archive_name();
        writer.force_rotate_for_test().unwrap();
        let archives = real_archives(&path);
        assert_eq!(archives.len(), 2);
        for archive in &archives {
            assert_eq!(handoff_count(archive), 1);
            archive_handoff_hash(archive).unwrap();
        }
    }

    /// A correctly chained handoff naming an existing older archive, appended
    /// to a threshold-sized active file, would rename the active file over
    /// that archive. The reopen refuses and the archive stays as it was.
    #[test]
    fn a_pending_handoff_naming_an_existing_archive_refuses_at_open() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = pruning_fixture(&path, true, 3);
        let tip = writer.last_hash.clone();
        drop(writer);
        let real = real_archives(&path);
        let target = real[0].clone();
        let target_bytes = fs::read(&target).unwrap();
        let target_tag = fs::read(hmac_sidecar_path(&target)).unwrap();

        let mut handoff = AuditEntry::new_rotation_handoff(basename_lossy_path(&target), "planted");
        handoff.previous_entry_hash = tip;
        let mut line = serde_json::to_vec(&handoff).unwrap();
        line.push(b'\n');
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&line)
            .unwrap();
        let _threshold = super::super::rotation::test_seam::set_rotation_threshold(&path, 1);

        let Err(err) = AuditWriter::open_keyed_unanchored_for_test(
            path.clone(),
            Zeroizing::new(PRUNE_TEST_KEY),
        ) else {
            panic!("the open accepted a pending rename over an existing archive");
        };
        assert!(
            matches!(
                &err,
                WriterError::RotationBridgeUnusable { archive_name, reason }
                    if *archive_name == basename_lossy_path(&target)
                        && *reason == ROTATION_TARGET_TAKEN_REASON
            ),
            "{err:?}"
        );
        assert_eq!(fs::read(&target).unwrap(), target_bytes);
        assert_eq!(fs::read(hmac_sidecar_path(&target)).unwrap(), target_tag);
    }

    /// A file planted under a pending handoff's archive name after a failed
    /// rename is never replaced: the retried rotation refuses, and the planted
    /// file and the active file keep their bytes.
    #[test]
    fn a_rotation_rename_never_replaces_an_existing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, true, 2);
        let _threshold = super::super::rotation::test_seam::set_rotation_threshold(&path, 1);
        writer.set_rotation_renames_to_fail(1);
        writer.write_entry(make_entry("")).unwrap_err();
        let pending = path.with_file_name(last_handoff_name(&path));
        fs::write(&pending, b"planted").unwrap();
        let active = fs::read(&path).unwrap();

        let err = writer.write_entry(make_entry("")).unwrap_err();
        assert!(
            matches!(
                &err,
                WriterError::RotationBridgeUnusable { reason, .. }
                    if *reason == ROTATION_TARGET_TAKEN_REASON
            ),
            "{err:?}"
        );
        assert_eq!(fs::read(&pending).unwrap(), b"planted");
        assert_eq!(fs::read(&path).unwrap(), active);
    }

    /// An unkeyed writer whose rotation handoff failed its fsync after the
    /// bytes landed rebuilds its state from the file on the next append: the
    /// archive holds that one handoff, and the new file chains from it.
    #[test]
    fn an_unkeyed_handoff_whose_fsync_failed_is_completed_under_its_one_handoff() {
        use super::super::verify::verify_log;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = open_no_key(path.clone());
        writer.write_entry(make_entry("")).unwrap();
        let _threshold = super::super::rotation::test_seam::set_rotation_threshold(&path, 1);
        writer.set_fail_sync_after_handoff_write(true);
        writer.write_entry(make_entry("")).unwrap_err();
        writer.set_fail_sync_after_handoff_write(false);
        assert_eq!(handoff_count(&path), 1, "the handoff's bytes landed");
        let pending_name = last_handoff_name(&path);
        assert!(real_archives(&path).is_empty());

        writer.write_entry(make_entry("")).unwrap();
        let archives = real_archives(&path);
        assert_eq!(archives, vec![path.with_file_name(&pending_name)]);
        assert_eq!(
            handoff_count(&archives[0]),
            1,
            "the archive holds one handoff"
        );
        let handoff = archive_handoff_hash(&archives[0]).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let first: AuditEntry = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(
            first.previous_entry_hash, handoff,
            "the new file chains from the handoff"
        );
        assert_eq!(handoff_count(&path), 0);
        let ok = verify_log(&path, None).unwrap();
        assert_eq!(ok.files_walked, 2);
    }

    /// A restart under a clock set back before the newest archive still names
    /// the next archive after it: the archive is the chain's last, keyed
    /// verification passes, and a later prune proves the chain and removes the
    /// oldest archive.
    #[test]
    fn an_archive_named_under_a_clock_set_back_sorts_after_the_newest() {
        use super::super::verify::verify_log;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        drop(pruning_fixture(&path, true, 9));
        let before = real_archives(&path);
        let mut writer = AuditWriter::open_keyed_unanchored_for_test(
            path.clone(),
            Zeroizing::new(PRUNE_TEST_KEY),
        )
        .unwrap();
        writer.set_archive_clock_for_test("20000101T000000000");
        assert!(basename_lossy_path(&before[8]).as_str() > "audit.jsonl.20000101T000000000");

        rotate_pruning_fixture(&mut writer);
        let after = real_archives(&path);
        assert_eq!(after.len(), 10);
        assert_eq!(&after[..9], &before[..], "the new archive sorts last");
        assert_eq!(handoff_count(&after[9]), 1);
        archive_handoff_hash(&after[9]).unwrap();
        let ok = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        assert!(ok.hmac_verified);
        assert_eq!(ok.files_walked, 11);

        rotate_pruning_fixture(&mut writer);
        let pruned = real_archives(&path);
        assert!(!before[0].exists(), "the prune proved the chain");
        assert_eq!(pruned.len(), 10);
        assert_eq!(&pruned[..9], &after[1..]);
        assert!(prune_marker_path(&path).exists());
        let ok = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        assert!(ok.hmac_verified);
        assert_eq!(ok.files_walked, 11);
    }

    /// Twelve rotations inside one timestamp name their archives in creation
    /// order, past the point where the counter gains a digit, and the log
    /// verifies after the prunes they cause.
    #[test]
    fn rotations_inside_one_timestamp_name_archives_in_creation_order() {
        use super::super::verify::verify_log;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = AuditWriter::open_keyed_unanchored_for_test(
            path.clone(),
            Zeroizing::new(PRUNE_TEST_KEY),
        )
        .unwrap();
        writer.set_archive_clock_for_test("20260101T120000500");
        writer.write_entry(make_entry("")).unwrap();
        let mut created = Vec::new();
        for _ in 0..12 {
            rotate_pruning_fixture(&mut writer);
            created.push(real_archives(&path).pop().unwrap());
        }
        let mut sorted = created.clone();
        sorted.sort();
        assert_eq!(sorted, created, "names sort in creation order");
        assert_eq!(
            basename_lossy_path(&created[11]),
            "audit.jsonl.20260101T120000500-000011"
        );
        assert_eq!(real_archives(&path), created[2..]);
        let ok = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        assert!(ok.hmac_verified);
        assert_eq!(ok.files_walked, 11);
    }

    /// A zero-rooted keyed log beside a valid marker under the same key that
    /// names other boundaries has no recorded start for its oldest archive.
    /// Verification fails naming the marker boundary and that archive, the
    /// prune stops with every archive kept, and with the marker moved aside
    /// both pass from the zero seed.
    #[test]
    fn a_marker_naming_other_boundaries_stops_verify_and_the_prune_alike() {
        use super::super::verify::{MARKER_NAMES_NO_BOUNDARY_REASON, VerifyError, verify_log};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, true, 10);
        let real = real_archives(&path);
        verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        let mut stale = PruneMarker {
            data: PruneMarkerData {
                version: 1,
                oldest: PruneSeed {
                    file: "audit.jsonl.20000101T000000000".to_owned(),
                    initial_prev_hash: archive_handoff_hash(&real[0]).unwrap(),
                },
                previous: Some(PruneSeed {
                    file: "audit.jsonl.19991231T235959999".to_owned(),
                    initial_prev_hash: ZERO_BLOCK_HASH.to_owned(),
                }),
                pruned_files: 1,
            },
            tag: None,
        };
        stale.write(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        let marker = read_prune_marker(&path).unwrap().unwrap();
        assert!(marker.verify_tag(&PRUNE_TEST_KEY), "the marker is valid");
        let marker_bytes = fs::read(prune_marker_path(&path)).unwrap();

        let err = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap_err();
        assert!(
            matches!(
                &err,
                VerifyError::ChainBroken { line: 1, file, reason }
                    if *file == basename_lossy_path(&real[0])
                        && *reason == MARKER_NAMES_NO_BOUNDARY_REASON
            ),
            "{err:?}"
        );
        assert_eq!(
            oldest_retained_seed(Some(&marker), &basename_lossy_path(&real[0])),
            Err(MarkerNamesNoBoundary),
            "the prune reads the same start"
        );
        rotate_pruning_fixture(&mut writer);
        assert_eq!(real_archives(&path).len(), 11, "the prune kept the excess");
        assert!(real.iter().all(|archive| archive.exists()));
        assert_eq!(fs::read(prune_marker_path(&path)).unwrap(), marker_bytes);

        let aside = dir.path().join("stale.pruned");
        fs::rename(prune_marker_path(&path), &aside).unwrap();
        let ok = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        assert!(ok.hmac_verified);
        assert!(
            ok.warnings.is_empty(),
            "the log verifies from the zero seed"
        );
        rotate_pruning_fixture(&mut writer);
        assert!(!real[0].exists() && !real[1].exists(), "the prune resumed");
        assert_eq!(real_archives(&path).len(), 10);
        let ok = verify_log(&path, Some(&PRUNE_TEST_KEY)).unwrap();
        assert!(ok.hmac_verified);
    }

    /// Writes `content` to a fresh file in `dir` and opens it for reading.
    fn file_holding(dir: &TempDir, content: &[u8]) -> File {
        let path = dir.path().join("lines");
        fs::write(&path, content).unwrap();
        File::open(&path).unwrap()
    }

    /// `line` after a two-byte first line, with its newline, and the offset
    /// just past that newline.
    fn after_a_short_line(line: &[u8]) -> (Vec<u8>, u64) {
        let mut content = b"a\n".to_vec();
        content.extend_from_slice(line);
        content.push(b'\n');
        let end = content.len() as u64;
        (content, end)
    }

    /// Lines whose start or end meets a 4 KiB read window, or that span two
    /// windows, are read whole.
    #[test]
    fn the_boundary_reader_reads_lines_across_its_read_windows() {
        let dir = TempDir::new().unwrap();
        for len in [4095, 4096, 4097, 8192] {
            let line = vec![b'x'; len];
            let (content, end) = after_a_short_line(&line);
            let file = file_holding(&dir, &content);
            assert_eq!(
                read_line_ending_at(&file, end).unwrap(),
                Some(line),
                "a line of {len} bytes"
            );
        }

        let mut content = vec![b'x'; 4095];
        content.extend_from_slice(b"\nnext\n");
        let file = file_holding(&dir, &content);
        assert_eq!(
            read_line_ending_at(&file, 4096).unwrap(),
            Some(vec![b'x'; 4095]),
            "the file's first line, ending at the window edge"
        );
    }

    /// A line of exactly [`MAX_ROW_BYTES`] with its newline is read; one byte
    /// more is not.
    #[test]
    fn the_boundary_reader_reads_up_to_the_row_cap() {
        let dir = TempDir::new().unwrap();
        let cap = usize::try_from(MAX_ROW_BYTES).unwrap();
        let line = vec![b'x'; cap - 1];
        let (content, end) = after_a_short_line(&line);
        let file = file_holding(&dir, &content);
        assert_eq!(read_line_ending_at(&file, end).unwrap(), Some(line));

        let (content, end) = after_a_short_line(&vec![b'x'; cap]);
        let file = file_holding(&dir, &content);
        assert_eq!(read_line_ending_at(&file, end).unwrap(), None);
    }

    /// An offset whose preceding byte is not a newline, an offset of zero,
    /// and an offset past the end of the file name no line.
    #[test]
    fn the_boundary_reader_needs_a_newline_right_before_the_offset() {
        let dir = TempDir::new().unwrap();
        let content = b"first\nsecond\n";
        let file = file_holding(&dir, content);
        let len = content.len() as u64;
        assert_eq!(
            read_line_ending_at(&file, len).unwrap(),
            Some(b"second".to_vec())
        );
        assert_eq!(
            read_line_ending_at(&file, 6).unwrap(),
            Some(b"first".to_vec())
        );
        for offset in [len - 1, 5, 7, 0, len + 1] {
            assert_eq!(
                read_line_ending_at(&file, offset).unwrap(),
                None,
                "offset {offset}"
            );
        }
    }

    /// Whitespace that opens or closes a line comes back with it, so the
    /// caller can refuse a line the writer would not have written.
    #[test]
    fn the_boundary_reader_keeps_whitespace_around_the_line() {
        let dir = TempDir::new().unwrap();
        let (content, end) = after_a_short_line(b" \t{}\r");
        let file = file_holding(&dir, &content);
        assert_eq!(
            read_line_ending_at(&file, end).unwrap(),
            Some(b" \t{}\r".to_vec())
        );
    }

    #[test]
    fn a_reanchor_writes_a_missing_root_tag_and_its_open_does_not() {
        use super::super::verify::verify_log;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        first_entry_without_its_root_tag(&path, &store);

        let mut writer = AuditWriter::open_for_reanchor(
            path.clone(),
            Some(Zeroizing::new(PRUNE_TEST_KEY)),
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        )
        .unwrap();
        assert!(
            !hmac_sidecar_path(&path).exists(),
            "opening for a re-anchor changes nothing"
        );
        writer.reanchor().unwrap();
        assert!(hmac_sidecar_path(&path).exists(), "the re-anchor wrote it");
        drop(writer);
        assert!(
            verify_log(&path, Some(&PRUNE_TEST_KEY))
                .unwrap()
                .hmac_verified
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_root_sidecar_never_redirects_the_tag_write() {
        use super::super::verify::verify_log;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let elsewhere = dir.path().join("elsewhere");
        fs::write(&elsewhere, b"untouched").unwrap();
        std::os::unix::fs::symlink(&elsewhere, hmac_sidecar_path(&path)).unwrap();
        // Unanchored: an anchored open reads any sidecar entry as evidence of a
        // prior anchor and refuses before the first append.
        let mut writer = AuditWriter::open_keyed_unanchored_for_test(
            path.clone(),
            Zeroizing::new(PRUNE_TEST_KEY),
        )
        .unwrap();
        writer.write_entry(make_entry("")).unwrap();
        assert_eq!(fs::read(&elsewhere).unwrap(), b"untouched");
        assert!(
            fs::symlink_metadata(hmac_sidecar_path(&path))
                .unwrap()
                .is_file()
        );
        assert!(
            verify_log(&path, Some(&PRUNE_TEST_KEY))
                .unwrap()
                .hmac_verified
        );
    }

    /// Builds a row whose serialized line, newline included, is `len` bytes
    /// once `writer` appends it.
    fn row_of_len(writer: &AuditWriter, len: u64) -> AuditEntry {
        let mut entry = make_entry("");
        // No argument keys and the oversize flag already set: the append's
        // truncation pass then leaves the row as it is.
        entry.arg_keys.clear();
        entry.truncated = true;
        entry.chain_id = Some(String::new());
        entry.previous_entry_hash = writer.last_entry_hash().to_owned();
        let base = serde_json::to_vec(&entry).unwrap().len() as u64 + 1;
        let pad = usize::try_from(len - base).unwrap();
        entry.chain_id = Some("x".repeat(pad));
        assert_eq!(serde_json::to_vec(&entry).unwrap().len() as u64 + 1, len);
        entry
    }

    #[test]
    fn a_row_over_the_cap_refuses_and_writes_nothing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = open_keyed_anchored(&path, &store);
        writer.write_entry(make_entry("")).unwrap();
        let bytes = fs::read(&path).unwrap();
        let anchor = stored_value(&store);
        let tip = writer.last_entry_hash().to_owned();

        let row = row_of_len(&writer, MAX_ROW_BYTES + 1);
        let err = writer.write_entry(row).unwrap_err();
        assert!(
            matches!(
                err,
                WriterError::RowTooLarge { bytes, cap: MAX_ROW_BYTES } if bytes == MAX_ROW_BYTES + 1
            ),
            "{err:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), bytes, "the file is unchanged");
        assert_eq!(stored_value(&store), anchor, "the anchor is unchanged");
        assert_eq!(writer.last_entry_hash(), tip);

        writer.write_entry(make_entry("")).unwrap();
        writer.require_anchor_current().unwrap();
    }

    /// A row at the cap appends, and the archive it ends up in stays within
    /// the prune's read budget.
    #[test]
    fn a_row_at_the_cap_appends_and_its_archive_prunes() {
        use super::super::verify::verify_log;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = pruning_fixture(&path, true, 0);
        let row = row_of_len(&writer, MAX_ROW_BYTES);
        let before = fs::metadata(&path).unwrap().len();
        writer.write_entry(row).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), before + MAX_ROW_BYTES);
        for _ in 0..10 {
            rotate_pruning_fixture(&mut writer);
        }
        let oldest = real_archives(&path)[0].clone();
        rotate_pruning_fixture(&mut writer);
        assert!(!oldest.exists(), "the archive holding the row was pruned");
        assert_eq!(real_archives(&path).len(), MAX_ROTATED_FILES);
        assert!(
            verify_log(&path, Some(&PRUNE_TEST_KEY))
                .unwrap()
                .hmac_verified
        );
    }

    /// A valid marker padded past the read cap is refused as malformed without
    /// being parsed, which stops the prune. Read whole, the padded marker would
    /// parse and the prune would proceed.
    #[test]
    fn an_oversized_prune_marker_stops_the_prune() {
        use super::super::verify::SIDECAR_READ_CAP;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let (mut writer, store) = anchored_pruning_fixture(&path, 11);
        let mut padded = fs::read(prune_marker_path(&path)).unwrap();
        padded.resize(usize::try_from(SIDECAR_READ_CAP).unwrap() + 1, b' ');
        assert!(serde_json::from_slice::<PruneMarker>(&padded).is_ok());
        fs::write(prune_marker_path(&path), &padded).unwrap();
        assert_prune_failure_keeps_the_rotation(&mut writer, &store, Some(padded.as_slice()));
        assert!(matches!(
            read_prune_marker(&path),
            Err(super::super::verify::VerifyError::ParseError { detail, .. })
                if detail.contains("exceeds")
        ));
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
    /// `windows-storage` CI job runs it on `windows-2025`, where the
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

    /// The next archive suffix sorts strictly after the newest archive's and
    /// is a rotated-sibling suffix, whether the clock moved past the newest
    /// archive, stood still, or was set back, and whatever counter the newest
    /// archive carries.
    #[test]
    fn the_next_archive_suffix_sorts_after_the_newest() {
        let now = "20260101T120000500";
        let cases = [
            (None, Some(now)),
            (Some("20260101T120000499"), Some(now)),
            (Some("20260101T115959"), Some(now)),
            (Some(now), Some("20260101T120000500-000001")),
            (
                Some("20260101T130000000"),
                Some("20260101T130000000-000001"),
            ),
            (
                Some("20260101T130000000-000009"),
                Some("20260101T130000000-000010"),
            ),
            (Some("20260101T130000"), Some("20260101T130000000")),
            (
                Some("20260101T130000000-9"),
                Some("20260101T130000000-900000"),
            ),
            (
                Some("20260101T130000000-10"),
                Some("20260101T130000000-100000"),
            ),
            (
                Some("20260101T130000000-1234567"),
                Some("20260101T130000000-123457"),
            ),
            (Some("20260101T130000000-999999"), None),
            (Some("20260101T130000000-99999993"), None),
        ];
        for (newest, expected) in cases {
            let next = next_archive_suffix(now, newest);
            assert_eq!(next.as_deref(), expected, "after {newest:?}");
            let Some(next) = next else { continue };
            if let Some(newest) = newest {
                assert!(next.as_str() > newest, "{next} sorts after {newest}");
            }
            assert!(is_rotated_sibling(
                "audit.jsonl",
                &format!("audit.jsonl.{next}")
            ));
        }
    }

    /// Successive suffixes inside one millisecond sort in the order they were
    /// taken, past the point where a counter gains a digit.
    #[test]
    fn same_millisecond_archive_suffixes_sort_in_creation_order() {
        let now = "20260101T120000500";
        let mut newest: Option<String> = None;
        let mut taken = Vec::new();
        for _ in 0..12 {
            let next = next_archive_suffix(now, newest.as_deref()).unwrap();
            taken.push(next.clone());
            newest = Some(next);
        }
        let mut sorted = taken.clone();
        sorted.sort();
        assert_eq!(sorted, taken);
        assert_eq!(taken[11], "20260101T120000500-000011");
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

    /// A 15-byte and an 18-byte suffix whose byte 8 falls inside a two-byte
    /// character. Byte length passes the first check, so these names reach
    /// the digit and `T` tests.
    const MULTIBYTE_AT_BYTE_8_NAMES: [&str; 2] = [
        "audit.jsonl.1234567\u{e9}123456",
        "audit.jsonl.1234567\u{e9}123456789",
    ];

    #[test]
    fn is_rotated_sibling_rejects_a_multibyte_character_at_byte_8_without_panicking() {
        for name in MULTIBYTE_AT_BYTE_8_NAMES {
            let suffix = name.strip_prefix("audit.jsonl.").unwrap();
            assert!(matches!(suffix.len(), 15 | 18), "{name}");
            assert!(!suffix.is_char_boundary(8), "{name}");
            assert!(!is_rotated_sibling("audit.jsonl", name), "{name}");
        }
        assert!(!is_rotated_sibling(
            "audit.jsonl",
            "audit.jsonl.1234567\u{e9}123456789-1"
        ));
    }

    #[test]
    fn pruning_skips_a_multibyte_name_in_the_audit_directory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = open_no_key(path.clone());
        for name in MULTIBYTE_AT_BYTE_8_NAMES {
            fs::write(dir.path().join(name), b"not an archive\n").unwrap();
        }
        writer
            .prune_rotated_files(&RotatedArchive {
                path: &dir.path().join("audit.jsonl.20260101T000000000"),
                seed: ZERO_BLOCK_HASH.to_owned(),
                handoff: ZERO_BLOCK_HASH.to_owned(),
            })
            .unwrap();
        for name in MULTIBYTE_AT_BYTE_8_NAMES {
            assert!(dir.path().join(name).exists(), "{name} must be left alone");
        }
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
            crate::audit_log::BindingHistory::NotRecorded,
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

    /// The adoption is in force in the keyring once reconciliation returns,
    /// and the next open finds the anchor current. An open whose drain then
    /// refuses still appends the adoption row, exactly once.
    #[test]
    fn an_open_whose_drain_refuses_still_records_the_adoption() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        {
            let mut writer = open_no_key(path.clone());
            writer.write_entry(make_entry("")).unwrap();
        }
        let outbox = super::super::outbox::outbox_path(&path);
        fs::write(&outbox, b"not an audit entry\n").unwrap();

        let store = Arc::new(InMemoryTipAnchorStore::new());
        let err = open_anchored(&path, &store).unwrap_err();
        assert!(matches!(err, WriterError::OutboxUnusable { .. }), "{err:?}");
        assert_eq!(
            count_tip_anchored_rows(&path, "adopted"),
            1,
            "the refused drain leaves the adoption row"
        );
        assert_eq!(
            stored_value(&store),
            tip_of(&path).to_keyring_value(),
            "the adoption row advanced the anchor"
        );

        fs::remove_file(&outbox).unwrap();
        drop(open_anchored(&path, &store).expect("the outbox was moved aside"));
        assert_eq!(
            count_tip_anchored_rows(&path, "adopted"),
            1,
            "the adoption is recorded once"
        );
    }

    /// The cache-hit twin: while a keyed writer is cached, the anchor and the
    /// chain-root sidecar both disappear, and the opener records no binding.
    /// Nothing then shows the log was anchored, so the next acquisition adopts
    /// it. Its drain refuses, and the adoption row is still appended, exactly
    /// once.
    #[test]
    fn a_cache_hit_whose_drain_refuses_still_records_the_adoption() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let key = Zeroizing::new([0x5a_u8; 32]);
        let access =
            || KeyedAuditAccess::new(key.clone(), Arc::clone(&store) as Arc<dyn TipAnchorStore>);
        let profile = "cache-hit-adoption-drain-refused";

        let handle = AuditWriterRegistry::get_or_open_keyed(profile, &path, access()).unwrap();
        handle.lock().unwrap().write_entry(make_entry("")).unwrap();
        store.set(None);
        fs::remove_file(hmac_sidecar_path(&path)).unwrap();
        let outbox = super::super::outbox::outbox_path(&path);
        fs::write(&outbox, b"not an audit entry\n").unwrap();

        let err = AuditWriterRegistry::get_or_open_keyed(profile, &path, access()).unwrap_err();
        assert!(matches!(err, WriterError::OutboxUnusable { .. }), "{err:?}");
        assert_eq!(
            count_tip_anchored_rows(&path, "adopted"),
            1,
            "the refused drain leaves the adoption row"
        );
        assert_eq!(
            stored_value(&store),
            tip_of(&path).to_keyring_value(),
            "the adoption row advanced the anchor"
        );

        fs::remove_file(&outbox).unwrap();
        drop(AuditWriterRegistry::get_or_open_keyed(profile, &path, access()).unwrap());
        assert_eq!(
            count_tip_anchored_rows(&path, "adopted"),
            1,
            "the adoption is recorded once"
        );
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
        assert_eq!(report.outbox_drained, Some(0), "an empty outbox drains");
        assert_eq!(report.outbox_refusal, None);
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

    /// A drain that refuses part way after the repair reports no count: the
    /// rows it appended stay queued and are appended again by the next drain,
    /// so no number of drained rows is true.
    #[test]
    fn a_drain_refused_part_way_after_a_repair_reports_no_drained_count() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let snapshot = {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            let snapshot = fs::read(&path).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            snapshot
        };
        fs::write(&path, &snapshot).unwrap();
        let outbox = super::super::outbox::AuditOutbox::for_log(&path, store.clone());
        for request_id in ["queued-1", "queued-2", "queued-3"] {
            outbox
                .append(&AuditEntry::new_approval_attested(
                    "PaymentSimulated",
                    "stellar_pay_commit",
                    None,
                    "ABCDEFGHIJKLMNOPQRSTUV",
                    "cli",
                    request_id,
                ))
                .unwrap();
        }
        let queued = fs::read(outbox.path()).unwrap();

        let mut writer = AuditWriter::open_for_reanchor(
            path.clone(),
            None,
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        )
        .unwrap();
        // The repair row and the first queued row land; the second refuses.
        writer.set_appends_before_fault(Some(2));
        let report = writer.reanchor().expect("the repair stands");
        drop(writer);

        assert_eq!(report.outbox_drained, None);
        let refusal = report.outbox_refusal.expect("the drain refused");
        assert!(refusal.starts_with("audit.io_error"), "{refusal}");
        assert_eq!(
            fs::read(outbox.path()).unwrap(),
            queued,
            "every row stays queued"
        );
        let log = fs::read_to_string(&path).unwrap();
        assert!(
            log.contains(r#""request_id":"queued-1""#),
            "the partial drain"
        );
        assert!(!log.contains(r#""request_id":"queued-2""#));
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

    /// Keeps the first `entries` lines of the log at `path` and drops the rest,
    /// as an attacker who removes the newest rows would.
    fn truncate_to_entries(path: &Path, entries: usize) {
        let content = fs::read_to_string(path).unwrap();
        let kept: String = content.split_inclusive('\n').take(entries).collect();
        fs::write(path, kept).unwrap();
    }

    /// Opens a keyed writer the way production does, through
    /// [`KeyedAuditAccess`], with the binding history the opener established.
    fn open_keyed_with_binding(
        path: &Path,
        store: &Arc<InMemoryTipAnchorStore>,
        binding: BindingHistory,
    ) -> Result<AuditWriter, WriterError> {
        let access = KeyedAuditAccess::new(
            Zeroizing::new([0x2c_u8; 32]),
            Arc::clone(store) as Arc<dyn TipAnchorStore>,
        )
        .with_binding_history(binding);
        AuditWriter::open(path.to_path_buf(), Some(access))
    }

    /// Asserts a refusal names `evidence` and that it left the store and the
    /// file exactly as they were: no adoption row and no anchor.
    fn assert_missing_anchor_refused(
        result: Result<AuditWriter, WriterError>,
        evidence: PriorAnchoring,
        path: &Path,
        store: &Arc<InMemoryTipAnchorStore>,
        bytes_before: &[u8],
    ) {
        let err = result.expect_err("an absent anchor with evidence must be refused");
        match &err {
            WriterError::TipAnchorMissing {
                evidence: found,
                actual_len,
                ..
            } => {
                assert_eq!(*found, evidence, "{err}");
                assert_eq!(*actual_len, bytes_before.len() as u64, "{err}");
            }
            other => panic!("expected TipAnchorMissing, got {other:?}"),
        }
        assert!(
            err.to_string().starts_with("audit.tip_anchor_missing: "),
            "{err}"
        );
        assert!(store.peek().is_none(), "a refusal must not write an anchor");
        assert_eq!(
            fs::read(path).unwrap(),
            bytes_before,
            "a refusal must not append an adoption row"
        );
    }

    /// The anchor is deleted and the log truncated, and the profile's audit
    /// binding is recorded: a keyed use reached this log before, so the anchor
    /// it left is gone. Nothing else points to it here (the rows were written
    /// by an unkeyed anchored writer from an empty file, so there is neither a
    /// sidecar nor an adoption row), and the binding alone refuses the open.
    #[test]
    fn a_recorded_binding_refuses_to_adopt_a_truncated_log_whose_anchor_was_deleted() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        {
            let mut writer = open_anchored(&path, &store).unwrap();
            for _ in 0..3 {
                writer.write_entry(make_entry("")).unwrap();
            }
        }
        assert_eq!(store.peek().unwrap().entry_count, 3);
        store.set(None);
        truncate_to_entries(&path, 1);
        assert!(!hmac_sidecar_path(&path).exists());
        assert_eq!(count_tip_anchored_rows(&path, "adopted"), 0);
        let bytes_before = fs::read(&path).unwrap();

        assert_missing_anchor_refused(
            open_keyed_with_binding(&path, &store, BindingHistory::Recorded),
            PriorAnchoring::BindingRecorded,
            &path,
            &store,
            &bytes_before,
        );
    }

    /// Only the chain-root sidecar shows a keyed writer wrote this file: no
    /// binding is recorded and the file holds no adoption row. The truncated
    /// file is refused, and so is the file truncated to nothing.
    #[test]
    fn a_chain_root_sidecar_refuses_to_adopt_a_truncated_log_whose_anchor_was_deleted() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        {
            let mut writer = AuditWriter::open_keyed_unanchored_for_test(
                path.clone(),
                Zeroizing::new([0x2c_u8; 32]),
            )
            .unwrap();
            for _ in 0..3 {
                writer.write_entry(make_entry("")).unwrap();
            }
        }
        assert!(hmac_sidecar_path(&path).exists());
        let store = Arc::new(InMemoryTipAnchorStore::new());

        truncate_to_entries(&path, 1);
        let bytes_before = fs::read(&path).unwrap();
        assert_missing_anchor_refused(
            open_keyed_with_binding(&path, &store, BindingHistory::NotRecorded),
            PriorAnchoring::ChainRootSidecar,
            &path,
            &store,
            &bytes_before,
        );

        truncate_to_entries(&path, 0);
        assert_missing_anchor_refused(
            open_keyed_with_binding(&path, &store, BindingHistory::NotRecorded),
            PriorAnchoring::ChainRootSidecar,
            &path,
            &store,
            &[],
        );
    }

    /// Only an earlier adoption row shows the log was anchored: no binding is
    /// recorded and an unkeyed writer left no sidecar. The anchor is deleted
    /// and the rows after the adoption row are removed; the open is refused.
    #[test]
    fn an_earlier_adoption_row_refuses_to_adopt_a_truncated_log_whose_anchor_was_deleted() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        open_no_key(path.clone())
            .write_entry(make_entry(""))
            .unwrap();
        let store = Arc::new(InMemoryTipAnchorStore::new());
        {
            let mut writer = open_anchored(&path, &store).unwrap();
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }
        assert_eq!(count_tip_anchored_rows(&path, "adopted"), 1);
        store.set(None);
        truncate_to_entries(&path, 2);
        assert!(!hmac_sidecar_path(&path).exists());
        assert_eq!(
            count_tip_anchored_rows(&path, "adopted"),
            1,
            "the kept prefix ends on the adoption row"
        );
        let bytes_before = fs::read(&path).unwrap();

        assert_missing_anchor_refused(
            open_keyed_with_binding(&path, &store, BindingHistory::NotRecorded),
            PriorAnchoring::AnchoringRow,
            &path,
            &store,
            &bytes_before,
        );
    }

    fn assert_anchoring_row_alone_refuses_adoption(reason: TipAnchorReason) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        {
            let mut writer = open_no_key(path.clone());
            writer
                .write_entry(AuditEntry::new_audit_tip_anchored(
                    reason,
                    0,
                    None,
                    Some(1),
                    uuid::Uuid::new_v4().to_string(),
                ))
                .unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }
        truncate_to_entries(&path, 1);
        assert!(!hmac_sidecar_path(&path).exists());
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let bytes = fs::read(&path).unwrap();
        assert_missing_anchor_refused(
            open_keyed_with_binding(&path, &store, BindingHistory::NotRecorded),
            PriorAnchoring::AnchoringRow,
            &path,
            &store,
            &bytes,
        );
    }

    #[test]
    fn a_rollback_acknowledged_row_alone_refuses_adoption() {
        assert_anchoring_row_alone_refuses_adoption(TipAnchorReason::RollbackAcknowledged);
    }

    #[test]
    fn a_binding_changed_row_alone_refuses_adoption() {
        assert_anchoring_row_alone_refuses_adoption(TipAnchorReason::BindingChanged);
    }

    /// The cache-hit twin of the sidecar refusal: the anchor disappears from
    /// the keyring while a keyed writer is cached. The next acquisition refuses
    /// instead of adopting the log as it stands.
    #[test]
    fn a_cache_hit_refuses_a_deleted_anchor_the_sidecar_shows_was_written() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let key = Zeroizing::new([0x5b_u8; 32]);
        let access =
            || KeyedAuditAccess::new(key.clone(), Arc::clone(&store) as Arc<dyn TipAnchorStore>);
        let profile = "cache-hit-anchor-deleted";

        let handle = AuditWriterRegistry::get_or_open_keyed(profile, &path, access()).unwrap();
        handle.lock().unwrap().write_entry(make_entry("")).unwrap();
        drop(handle);
        store.set(None);
        let len_before = fs::metadata(&path).unwrap().len();

        let err = AuditWriterRegistry::get_or_open_keyed(profile, &path, access()).unwrap_err();
        assert!(
            matches!(
                err,
                WriterError::TipAnchorMissing {
                    evidence: PriorAnchoring::ChainRootSidecar,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(store.peek().is_none(), "a refusal must not write an anchor");
        assert_eq!(fs::metadata(&path).unwrap().len(), len_before);
    }

    #[test]
    fn a_cache_hit_preserves_incoming_recorded_binding_as_the_only_evidence() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let access = |binding| {
            KeyedAuditAccess::new(
                Zeroizing::new([0x5b_u8; 32]),
                Arc::clone(&store) as Arc<dyn TipAnchorStore>,
            )
            .with_binding_history(binding)
        };
        let profile = "cache-hit-new-binding-evidence";
        let handle = AuditWriterRegistry::get_or_open_keyed(
            profile,
            &path,
            access(BindingHistory::NotRecorded),
        )
        .unwrap();
        for _ in 0..3 {
            handle.lock().unwrap().write_entry(make_entry("")).unwrap();
        }
        store.set(None);
        fs::remove_file(hmac_sidecar_path(&path)).unwrap();
        truncate_to_entries(&path, 1);
        assert_eq!(count_tip_anchored_rows(&path, "adopted"), 0);
        let bytes = fs::read(&path).unwrap();

        for binding in [BindingHistory::Recorded, BindingHistory::NotRecorded] {
            let err = AuditWriterRegistry::get_or_open_keyed(profile, &path, access(binding))
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    WriterError::TipAnchorMissing {
                        evidence: PriorAnchoring::BindingRecorded,
                        ..
                    }
                ),
                "{err:?}"
            );
            assert!(store.peek().is_none());
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert!(!hmac_sidecar_path(&path).exists());
        }
    }

    /// Regression guard: a log written only by unkeyed writers, with no
    /// recorded binding, no sidecar and no adoption row, is the quickstart
    /// state, and the first keyed open adopts it.
    #[test]
    fn a_quickstart_log_adopts_on_its_first_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        {
            let mut writer = open_no_key(path.clone());
            writer.write_entry(make_entry("")).unwrap();
            writer.write_entry(make_entry("")).unwrap();
        }
        let store = Arc::new(InMemoryTipAnchorStore::new());
        assert_eq!(
            PriorAnchoring::find(BindingHistory::NotRecorded, &path, 2, false),
            None,
            "a quickstart log carries no evidence of an earlier anchor"
        );

        drop(
            open_keyed_with_binding(&path, &store, BindingHistory::NotRecorded)
                .expect("a quickstart log adopts on its first key"),
        );
        assert_eq!(count_tip_anchored_rows(&path, "adopted"), 1);
        assert_eq!(stored_value(&store), tip_of(&path).to_keyring_value());
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
            crate::audit_log::BindingHistory::NotRecorded,
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

    fn keyed_anchor_writer(path: &Path, store: &Arc<InMemoryTipAnchorStore>) -> AuditWriter {
        AuditWriter::open(
            path.to_path_buf(),
            Some(KeyedAuditAccess::new(
                Zeroizing::new([0x5a; 32]),
                Arc::clone(store) as Arc<dyn TipAnchorStore>,
            )),
        )
        .unwrap()
    }

    #[test]
    fn one_failed_anchor_write_is_retried_immediately() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        store.fail_next_writes(1);
        writer.write_entry(make_entry("")).unwrap();
        assert!(!writer.anchor_behind());
        assert_eq!(store.peek(), Some(tip_of(&path)));
    }

    #[test]
    fn a_persistent_anchor_failure_keeps_the_durable_chain_state() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        store.set_failing(true);
        writer.write_entry(make_entry("")).unwrap();
        assert!(writer.anchor_behind());
        let durable = tip_of(&path);
        assert_eq!(writer.entry_count, durable.entry_count);
        assert_eq!(writer.end_offset, durable.end_offset);
        assert_eq!(writer.last_hash, durable.tip_hash);
        writer.write_entry(make_entry("")).unwrap();
        assert_eq!(tip_of(&path).entry_count, 2, "plain appends still land");
        assert!(verify_log_is_clean(&path));
    }

    #[test]
    fn require_anchor_current_refuses_without_writing_a_row() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        store.set_failing(true);
        writer.write_entry(make_entry("")).unwrap();
        let bytes = fs::read(&path).unwrap();
        let count = writer.entry_count;
        let error = writer.require_anchor_current().unwrap_err();
        assert!(matches!(error, WriterError::TipAnchorStore(_)));
        assert!(error.to_string().contains("audit.tip_anchor_unavailable"));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(writer.entry_count, count);
        store.set_failing(false);
        writer.require_anchor_current().unwrap();
        assert!(!writer.anchor_behind());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(store.peek(), Some(tip_of(&path)));
    }

    #[test]
    fn a_failed_anchor_write_is_retried_on_the_next_append() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        store.set_failing(true);
        writer.write_entry(make_entry("")).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(writer.require_anchor_current().is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        let repair = tip_of(&path);
        store.set_failing(false);
        writer.write_entry(make_entry("")).unwrap();
        assert_eq!(store.writes(), vec![repair, tip_of(&path)]);
        assert!(!writer.anchor_behind());
    }

    #[test]
    fn an_empty_post_rotation_file_repairs_the_failed_handoff() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        writer.write_entry(make_entry("")).unwrap();
        store.set_failing(true);
        writer.force_rotate_for_test().unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        assert!(writer.require_anchor_current().is_err());
        let archive = rotated_archives_newest_first(&path).remove(0);
        let handoff = tip_of(&archive);
        let writes = store.writes().len();
        store.set_failing(false);
        writer.write_entry(make_entry("")).unwrap();
        assert_eq!(store.writes()[writes], handoff);
        assert_eq!(store.peek(), Some(tip_of(&path)));
        writer.verify_tip_anchor().unwrap();
    }

    #[test]
    fn a_cached_empty_post_rotation_file_repairs_the_handoff() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        writer.write_entry(make_entry("")).unwrap();
        store.fail_next_writes(2);
        writer.force_rotate_for_test().unwrap();
        assert!(writer.anchor_behind());
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        writer.verify_tip_anchor().unwrap();
        assert!(!writer.anchor_behind());
        let archive = rotated_archives_newest_first(&path).remove(0);
        assert_eq!(store.peek(), Some(tip_of(&archive)));
    }

    #[test]
    fn a_cached_one_entry_file_repairs_before_reconciling_the_handoff() {
        use crate::audit_log::rotation::test_seam::set_rotation_threshold;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let profile = format!("handoff-{}", uuid::Uuid::new_v4());
        let acquire = || {
            AuditWriterRegistry::get_or_open_keyed(
                &profile,
                &path,
                KeyedAuditAccess::new(
                    Zeroizing::new([0x5a; 32]),
                    Arc::clone(&store) as Arc<dyn TipAnchorStore>,
                ),
            )
        };
        let writer = acquire().unwrap();
        writer.lock().unwrap().write_entry(make_entry("")).unwrap();
        let threshold = set_rotation_threshold(&path, 1);
        store.fail_next_writes(4);
        writer.lock().unwrap().write_entry(make_entry("")).unwrap();
        drop(threshold);
        assert_eq!(tip_of(&path).entry_count, 1);
        store.fail_next_writes(1);
        assert!(matches!(acquire(), Err(WriterError::TipAnchorStore(_))));
        acquire().unwrap();
        assert!(!writer.lock().unwrap().anchor_behind());
        assert_eq!(store.peek(), Some(tip_of(&path)));
    }

    #[test]
    fn chain_state_commits_before_the_anchor_store_is_called() {
        use std::sync::atomic::{AtomicBool, Ordering};
        #[derive(Debug)]
        struct InterruptedStore {
            inner: InMemoryTipAnchorStore,
            armed: AtomicBool,
        }
        impl TipAnchorStore for InterruptedStore {
            fn load_outbox_state(
                &self,
            ) -> Result<Option<super::super::outbox::OutboxState>, TipAnchorStoreError>
            {
                self.inner.load_outbox_state()
            }
            fn store_outbox_state(
                &self,
                state: &super::super::outbox::OutboxState,
            ) -> Result<(), TipAnchorStoreError> {
                self.inner.store_outbox_state(state)
            }

            fn load_anchor(&self) -> Result<Option<TipAnchor>, TipAnchorStoreError> {
                self.inner.load_anchor()
            }
            fn load_raw(&self) -> Result<Option<String>, TipAnchorStoreError> {
                self.inner.load_raw()
            }
            fn reanchor_count(&self) -> Result<Option<u64>, TipAnchorStoreError> {
                self.inner.reanchor_count()
            }
            fn store_anchor(&self, anchor: &TipAnchor) -> Result<(), TipAnchorStoreError> {
                assert!(!self.armed.load(Ordering::SeqCst), "interrupt anchor write");
                self.inner.store_anchor(anchor)
            }
            fn bump_reanchor_count(&self) -> Result<u64, TipAnchorStoreError> {
                self.inner.bump_reanchor_count()
            }
        }
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InterruptedStore {
            inner: InMemoryTipAnchorStore::new(),
            armed: AtomicBool::new(false),
        });
        let mut writer = AuditWriter::open(
            path.clone(),
            Some(KeyedAuditAccess::new(
                Zeroizing::new([0x5a; 32]),
                store.clone(),
            )),
        )
        .unwrap();
        store.armed.store(true, Ordering::SeqCst);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                writer.write_entry(make_entry("")).unwrap();
            }))
            .is_err()
        );
        let durable = tip_of(&path);
        assert_eq!(writer.entry_count, durable.entry_count);
        assert_eq!(writer.end_offset, durable.end_offset);
        assert_eq!(writer.last_hash, durable.tip_hash);
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

    /// `write_built` on a log moved under the writer refuses, builds the row it
    /// owed once, and anchors that row once.
    #[test]
    fn write_built_after_the_log_is_replaced_anchors_the_owed_row_once() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        let anchored_len = fs::metadata(&path).unwrap().len();
        fs::rename(&path, dir.path().join("moved.jsonl")).unwrap();

        let builds = std::cell::Cell::new(0_u32);
        let err = writer
            .write_built(|_| {
                builds.set(builds.get() + 1);
                make_entry("")
            })
            .expect_err("an append onto a path the writer no longer holds must refuse");
        assert!(
            matches!(
                &err,
                WriterError::TipAnchorMismatch { reason, .. } if *reason == LOG_REPLACED_REASON
            ),
            "{err:?}"
        );
        assert_eq!(builds.get(), 1, "the owed row is built once");
        let owed = store.peek().expect("the refused row must be anchored");
        assert_eq!(owed.entry_count, 2, "the anchor names the refused row");
        assert!(owed.end_offset > anchored_len);

        let later_builds = std::cell::Cell::new(0_u32);
        writer
            .write_built(|_| {
                later_builds.set(later_builds.get() + 1);
                make_entry("")
            })
            .expect_err("a latched writer refuses");
        assert_eq!(later_builds.get(), 0, "a latched writer builds no row");
        assert_eq!(store.peek(), Some(owed), "the owed row is anchored once");
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

        let _threshold = super::super::rotation::test_seam::set_rotation_threshold(&path, 1);
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

    fn assert_append_after_foreign_bytes_refuses(bytes: &[u8]) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        let original = fs::read(&path).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        let grown = fs::read(&path).unwrap();
        assert_eq!(grown.len(), original.len() + bytes.len());
        for _ in 0..2 {
            let err = writer.write_entry(make_entry("")).unwrap_err();
            assert!(matches!(err, WriterError::TipAnchorMismatch { reason, .. }
                if reason == LOG_GREW_REASON));
            assert_eq!(writer.log_diverged, Some(LOG_GREW_REASON));
            assert_eq!(
                fs::read(&path).unwrap(),
                grown,
                "the refused row writes no bytes"
            );
        }
    }

    #[test]
    fn an_append_after_foreign_growth_refuses() {
        let (line, _) = serialised_entry_line(ZERO_BLOCK_HASH);
        assert_append_after_foreign_bytes_refuses(&line);
    }

    #[test]
    fn an_append_after_a_foreign_torn_prefix_refuses() {
        assert_append_after_foreign_bytes_refuses(b"{\"foreign\":");
    }

    /// A full `write_all` whose `sync_data` fails leaves a line the writer's
    /// state does not account for; the next append refuses on the growth.
    #[test]
    fn an_append_after_a_failed_sync_refuses() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        let before = fs::read(&path).unwrap();
        writer.set_fail_sync_after_entry_write(true);
        assert!(writer.write_entry(make_entry("")).is_err());
        writer.set_fail_sync_after_entry_write(false);
        let written = fs::read(&path).unwrap();
        assert!(written.len() > before.len() && written.ends_with(b"\n"));
        let err = writer.write_entry(make_entry("")).unwrap_err();
        assert!(matches!(err, WriterError::TipAnchorMismatch { reason, .. }
            if reason == LOG_GREW_REASON));
        assert_eq!(writer.log_diverged, Some(LOG_GREW_REASON));
        assert_eq!(
            fs::read(&path).unwrap(),
            written,
            "the refused row writes no bytes"
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

    // ── verified tip facts ──────────────────────────────────────────────

    fn tip_hash_bytes(anchor: &TipAnchor) -> [u8; 32] {
        decode_hash(&anchor.tip_hash).unwrap()
    }

    #[test]
    fn the_facts_of_a_current_anchor_name_the_tip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        writer.write_entry(make_entry("")).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        let facts = writer.verified_tip_facts().unwrap();
        let tip = tip_of(&path);
        assert_eq!(
            facts,
            VerifiedTipFacts {
                segment_start_hash: decode_hash(ZERO_BLOCK_HASH).unwrap(),
                entry_count: 2,
                tip_hash: tip_hash_bytes(&tip),
                log_path_sha256: super::super::tip_anchor::log_path_sha256(&path),
                anchor_covers_tip: true,
            }
        );
    }

    #[test]
    fn an_empty_genesis_is_covered_at_count_zero() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        let facts = writer.verified_tip_facts().unwrap();
        assert_eq!(facts.entry_count, 0);
        assert!(facts.anchor_covers_tip);
        assert_eq!(facts.tip_hash, decode_hash(&writer.last_hash).unwrap());
    }

    #[test]
    fn an_empty_rotation_file_is_covered_by_its_handoff() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = open_anchored(&path, &store).unwrap();
        writer.write_entry(make_entry("")).unwrap();
        writer.force_rotate_for_test().unwrap();
        let handoff = tip_of(&newest_archive(&path));
        let facts = writer.verified_tip_facts().unwrap();
        assert_eq!(facts.entry_count, 0, "a rotation resets the count");
        assert!(facts.anchor_covers_tip);
        assert_eq!(facts.tip_hash, tip_hash_bytes(&handoff));
    }

    #[test]
    fn an_owed_anchor_write_is_repaired_before_the_facts() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        store.fail_next_writes(2);
        writer.write_entry(make_entry("")).unwrap();
        assert!(writer.anchor_behind());
        let facts = writer.verified_tip_facts().unwrap();
        assert!(facts.anchor_covers_tip);
        assert_eq!(facts.entry_count, 1);
        assert_eq!(store.peek(), Some(tip_of(&path)));
    }

    #[test]
    fn a_persistent_anchor_write_failure_refuses_the_facts() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        writer.write_entry(make_entry("")).unwrap();
        store.fail_next_writes(usize::MAX);
        writer.write_entry(make_entry("")).unwrap();
        assert!(matches!(
            writer.verified_tip_facts(),
            Err(WriterError::TipAnchorStore(_))
        ));
        store.fail_next_writes(0);
        let facts = writer.verified_tip_facts().unwrap();
        assert!(facts.anchor_covers_tip);
        assert_eq!(facts.entry_count, 2);
    }

    #[test]
    fn a_drained_row_whose_anchor_write_failed_is_retried_before_the_facts() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        writer.write_entry(make_entry("")).unwrap();
        super::super::outbox::AuditOutbox::for_log(&path, store.clone())
            .append(&AuditEntry::new_approval_attested(
                "PaymentSimulated",
                "stellar_pay_commit",
                None,
                "ABCDEFGHIJKLMNOPQRSTUV",
                "cli",
                "queued",
            ))
            .unwrap();
        // The drained append and its immediate retry both fail; the write the
        // facts owe the anchor succeeds.
        store.fail_next_writes(2);
        let facts = writer.verified_tip_facts().unwrap();
        assert!(facts.anchor_covers_tip);
        assert_eq!(facts.entry_count, 2);
        assert_eq!(store.peek(), Some(tip_of(&path)));
    }

    #[test]
    fn a_drain_whose_anchor_stays_behind_is_reported_as_a_lag() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        writer.write_entry(make_entry("")).unwrap();
        super::super::outbox::AuditOutbox::for_log(&path, store.clone())
            .append(&AuditEntry::new_approval_attested(
                "PaymentSimulated",
                "stellar_pay_commit",
                None,
                "ABCDEFGHIJKLMNOPQRSTUV",
                "cli",
                "queued",
            ))
            .unwrap();
        store.fail_next_writes(usize::MAX);
        let facts = writer.verified_tip_facts().unwrap();
        assert!(
            !facts.anchor_covers_tip,
            "the durable anchor names the first entry"
        );
        assert_eq!(facts.entry_count, 2);
        store.fail_next_writes(0);
        assert!(writer.verified_tip_facts().unwrap().anchor_covers_tip);
    }

    #[test]
    fn an_unreadable_anchor_refuses_the_facts() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        writer.write_entry(make_entry("")).unwrap();
        store.set_failing(true);
        assert!(writer.verified_tip_facts().is_err());
        store.set_failing(false);
        assert!(writer.verified_tip_facts().unwrap().anchor_covers_tip);
    }

    #[test]
    fn the_count_is_taken_after_the_outbox_drains() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        writer.write_entry(make_entry("")).unwrap();
        let outbox = super::super::outbox::AuditOutbox::for_log(&path, store.clone());
        for request_id in ["queued-1", "queued-2"] {
            outbox
                .append(&AuditEntry::new_approval_attested(
                    "PaymentSimulated",
                    "stellar_pay_commit",
                    None,
                    "ABCDEFGHIJKLMNOPQRSTUV",
                    "cli",
                    request_id,
                ))
                .unwrap();
        }
        let facts = writer.verified_tip_facts().unwrap();
        assert_eq!(facts.entry_count, 3);
        assert!(facts.anchor_covers_tip);
        assert_eq!(facts.tip_hash, tip_hash_bytes(&tip_of(&path)));
        assert_eq!(fs::metadata(outbox.path()).unwrap().len(), 0);
    }

    #[test]
    fn a_writer_without_a_checked_anchor_has_no_facts() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let mut unanchored = open_no_key(path.clone());
        assert!(matches!(
            unanchored.verified_tip_facts(),
            Err(WriterError::TipAnchorUnavailable)
        ));
        drop(unanchored);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut repair = AuditWriter::open_for_reanchor(
            path,
            None,
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        )
        .unwrap();
        assert!(matches!(
            repair.verified_tip_facts(),
            Err(WriterError::TipAnchorUnavailable)
        ));
    }

    #[test]
    fn the_writer_carries_its_anchor_store() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let writer = keyed_anchor_writer(&path, &store);
        let anchor = Arc::clone(&store) as Arc<dyn TipAnchorStore>;
        assert!(Arc::ptr_eq(writer.tip_anchor_store().unwrap(), &anchor));
    }

    #[test]
    fn rotation_changes_the_verified_segment_and_reopen_preserves_it() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = keyed_anchor_writer(&path, &store);
        let genesis = writer.verified_tip_facts().unwrap();
        writer.write_entry(make_entry("")).unwrap();
        let before = writer.verified_tip_facts().unwrap();
        assert_eq!(genesis.segment_start_hash, before.segment_start_hash);
        writer.force_rotate_for_test().unwrap();
        let rotated = writer.verified_tip_facts().unwrap();
        assert_ne!(rotated.segment_start_hash, before.segment_start_hash);
        assert_eq!(rotated.segment_start_hash, rotated.tip_hash);
        assert_eq!(rotated.entry_count, 0);
        writer.write_entry(make_entry("")).unwrap();
        assert_eq!(
            writer.verified_tip_facts().unwrap().segment_start_hash,
            rotated.segment_start_hash
        );
        drop(writer);
        let mut reopened = keyed_anchor_writer(&path, &store);
        assert_eq!(
            reopened.verified_tip_facts().unwrap().segment_start_hash,
            rotated.segment_start_hash
        );
    }
}
