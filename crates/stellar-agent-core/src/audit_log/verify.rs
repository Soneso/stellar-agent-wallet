//! Chain-walk verification algorithm for the hash-chained audit log.
//!
//! Provides [`verify_log`] — walks the chain of log files (oldest rotated
//! first, then the active file) and verifies that:
//!
//! 1. Every entry's `previous_entry_hash` matches the hash computed from the
//!    prior entry's canonical body.
//! 2. The cross-file chain bridge: the first entry of each non-first file must
//!    chain off the last entry of the preceding file.
//! 3. The `AuditRotationHandoff.next_file_name` of each rotated file's last
//!    entry matches the basename of the next file in the chain (validates
//!    that no file was substituted in the chain).
//! 4. The chain-root HMAC tag (in the `<file>.root_hmac` sidecar) verifies
//!    against the chain root entry (if an HMAC key is supplied).
//!    If `hmac_key` is `Some` and the sidecar is missing,
//!    [`VerifyError::HmacSidecarMissing`] is returned. The root tag covers
//!    each file's first entry only.
//! 5. With a key, the entry-tag walk: once tags are in force, every entry
//!    carries a valid entry tag, or is covered by a valid keyed start or a
//!    valid quarantine row after it. A failure is
//!    [`VerifyError::EntryTagInvalid`].
//!
//! Without a `<log>.pruned` marker the first file starts from
//! [`ZERO_BLOCK_HASH`]. With one, the first file starts from the seed the marker
//! records for it as either boundary, the rule the prune applies too; a marker
//! that names neither boundary fails with [`VerifyError::ChainBroken`] at line
//! 1 of that file. A nonzero marker seed produces
//! [`VerifyWarning::PrunedPrefix`]. With a key,
//! the marker's tag must verify before the walk. Without a key it is untrusted
//! bookkeeping. Every subsequent bridge, entry, sidecar, and anchor check holds.
//!
//! Each acknowledged outbox loss produces [`VerifyWarning::OutboxLossAcknowledged`].
//! The warning records the file, line, and counts without changing the chain verdict.
//!
//! # Wire codes (closed set)
//!
//! Error variant wire codes use a closed set: `audit.chain_broken`,
//! `audit.rotation_gap`, `audit.hmac_mismatch`, `audit.hmac_sidecar_missing`,
//! `audit.too_many_rotated_files`, `audit.non_regular_file_log_path`,
//! `audit.parse_error`, `audit.path_contract`, `audit.io_error`,
//! `audit.signer_set_canonical_body`, `audit.tip_anchor_mismatch`,
//! `audit.tip_anchor_missing`, `audit.entry_tag_invalid`.  The line
//! number / file basename is in
//! the envelope `detail` field, not the wire code itself, ensuring cardinality
//! stays bounded.
//!
//! # Wire guarantees
//!
//! Every error produced by [`verify_log`] carries a wire code from the closed
//! set above.  The `audit verify` CLI emits these codes in a deterministic JSON
//! envelope.

use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::{
    binding::BindingHistory,
    chain::{
        EntryTagCheck, EntryTagKey, ZERO_BLOCK_HASH, check_entry_tag, compute_entry_hash,
        derive_entry_tag_key, verify_chain_root,
    },
    entry::AuditEntry,
    rotation::{MarkerNamesNoBoundary, oldest_retained_seed, read_prune_marker},
    schema::{EntryTagsRekeyCause, EventKind},
    tip_anchor::{PriorAnchoring, TipAnchor},
    writer::{
        MAX_ROTATED_FILES, hmac_sidecar_path, is_rotated_sibling, prune_marker_path,
        wait_out_transient_rotation_window,
    },
};

// ── Public API ────────────────────────────────────────────────────────────────

/// Backward timestamp drift threshold for [`VerifyWarning::BackwardTimestampJump`].
///
/// Wall-clock audit timestamps can move backward under NTP corrections or manual
/// clock changes. Drift up to 60 seconds is treated as ordinary clock skew; a
/// larger jump is suspicious enough to report without making verification fail.
pub const BACKWARD_TS_WARN_THRESHOLD_MS: u64 = 60_000;

/// Maximum number of rotated siblings `audit verify` will collect before
/// rejecting the directory as polluted.
const ROTATED_FILE_CHAIN_CAP: usize = MAX_ROTATED_FILES * 2 + 1;

/// [`VerifyError::ChainBroken`] reason for a log whose oldest file is neither
/// boundary its prune marker records, so nothing records what that file's
/// first entry chains from. The prune stops at the same file.
pub(super) const MARKER_NAMES_NO_BOUNDARY_REASON: &str = "prune_marker_names_neither_boundary";

/// The outcome of a successful log verification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyOk {
    /// Total number of entries verified across all files.
    pub entries_verified: usize,
    /// Number of files (including rotated files) walked.
    pub files_walked: usize,
    /// Per-file verification results, in verification order.
    pub per_file: Vec<FileVerifyResult>,
    /// Informational warnings discovered during verification.
    pub warnings: Vec<VerifyWarning>,
    /// Whether every file's chain-root HMAC sidecar was verified.
    ///
    /// `true` only when the caller supplied an HMAC key and each file in the
    /// walked chain had a sidecar that verified successfully.
    pub hmac_verified: bool,
    /// Coordinates of the last file's chain tip, for comparison against a
    /// keyring-held [`TipAnchor`].
    ///
    /// `None` only when no file was walked at all.
    pub active_tip: Option<VerifiedTip>,
    /// Whether the entry tags verified: a key was supplied, tags are in force
    /// in the walked chain, and every entry the rules require a tag of
    /// carries a valid one.
    pub entry_tags_verified: bool,
    /// The newest keyed start with a valid tag in the walked chain, or `None`
    /// when no such row was walked, for example because a prune removed it.
    pub entry_tags_boundary: Option<EntryTagsBoundary>,
}

/// Where the newest keyed start with a valid entry tag sits in the walked
/// chain: an `audit_entry_tags_started` or `audit_entry_tags_rekeyed` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryTagsBoundary {
    /// Basename of the file holding the row.
    pub file: String,
    /// One-based line of the row in that file.
    pub line: usize,
    /// The row's event kind.
    pub kind: String,
}

/// The verified chain tip of the last file in a walk.
///
/// The three values a [`TipAnchor`] records, computed from the file rather than
/// read from the keyring, so the two can be compared.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedTip {
    /// Number of entries in the active file.
    pub entry_count: u64,
    /// Entry hash of the active file's last entry, or the hash the file chains
    /// from when it is empty.
    pub tip_hash: String,
    /// Byte offset just past the active file's last entry.
    pub end_offset: u64,
    /// Whether the active file shows prior anchoring: it holds an
    /// `audit_tip_anchored` row, an entry-tag row, or a row with an entry tag,
    /// or the handoff it chains from carries `entry_tags`.
    pub holds_anchoring_row: bool,
}

/// Verification metadata for one walked audit-log file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FileVerifyResult {
    /// Path to the verified file, either active or rotated.
    pub path: PathBuf,
    /// Number of entries successfully verified in this file.
    pub entries_verified: u64,
    /// Whether this file's chain-root HMAC tag verified against the supplied
    /// audit key.
    ///
    /// `None` means no audit key was supplied and verification performed a
    /// structural chain walk only.
    pub hmac_verified: Option<bool>,
}

/// Informational warnings produced by [`verify_log`] and by the audit-outbox
/// inspection `audit verify` runs beside it.
///
/// Warnings do not invalidate the hash chain and do not cause verification to
/// fail. They are surfaced for operator investigation in deterministic CLI JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VerifyWarning {
    /// Retention removes a prefix whose boundary the prune marker records.
    PrunedPrefix {
        /// Basename of the first retained file in the walk.
        first_file: String,
        /// Number of archives the marker records as pruned.
        pruned_files: u64,
    },
    /// An entry timestamp moved backward beyond [`BACKWARD_TS_WARN_THRESHOLD_MS`].
    BackwardTimestampJump {
        /// Previous entry timestamp as it appeared in the log.
        previous_ts: String,
        /// Current entry timestamp as it appeared in the log.
        current_ts: String,
        /// Backward drift in milliseconds.
        drift_ms: u64,
        /// Zero-based file index in verification order.
        file_index: usize,
        /// Zero-based non-empty entry index within the file.
        entry_index: usize,
    },
    /// The audit outbox ends in a segment with no terminating newline: an
    /// append that never returned `Ok`. The next append or drain discards it.
    OutboxTornTail {
        /// Size of the torn segment in bytes.
        torn_bytes: usize,
    },
    /// Complete lines of the audit outbox do not parse as audit entries. Every
    /// drain refuses with `audit.outbox_unusable` until an operator moves the
    /// file aside; see `docs/maintainers/audit-log-recovery.md`.
    OutboxUnparseable {
        /// One-based numbers of the lines that do not parse.
        lines: Vec<usize>,
    },
    /// The audit outbox exists and could not be read.
    OutboxUnreadable {
        /// The I/O error kind.
        error_kind: String,
    },
    /// An operator acknowledges missing or changed queued consent rows.
    OutboxLossAcknowledged {
        /// Basename of the file containing the acknowledgement.
        file: String,
        /// One-based line of the acknowledgement.
        line: usize,
        /// Number of rows committed in the keyring.
        expected_rows: u64,
        /// Number of complete lines found.
        found_rows: u64,
    },
    /// The entry-tag boundary took in entries past the stored anchor without
    /// tags, once, when the log first came under entry tags.
    EntryTagsAbsorbed {
        /// Basename of the file holding the boundary row.
        file: String,
        /// One-based line of the boundary row.
        line: usize,
        /// Entry count of the stored anchor the boundary found.
        anchored_count: u64,
        /// Entries the boundary took in without tags.
        absorbed_count: u64,
    },
    /// An operator quarantined entries that carry no valid entry tag.
    ///
    /// Reported for a quarantine row that takes effect: under a key, one
    /// whose own tag is valid, and in every walk one that no later quarantine
    /// row of its file covers. A covered row reports nothing.
    EntriesQuarantined {
        /// Basename of the file holding the quarantine row.
        file: String,
        /// One-based line of the quarantine row.
        line: usize,
        /// Number of entries directly before the row that it covers.
        quarantined_count: u64,
    },
    /// A keyed open re-keyed entry tags because entries after the newest
    /// keyed start did not verify under the current key.
    EntryTagsRekeyedAtOpen {
        /// Basename of the file holding the rekey row.
        file: String,
        /// One-based line of the rekey row.
        line: usize,
    },
}

/// Verify a hash-chained audit log starting at `log_path`.
///
/// Walks the active log file and all rotated siblings in the same directory,
/// verifying the complete chain including cross-file bridges.
/// Returns [`VerifyOk`] on success.
///
/// # Arguments
///
/// - `log_path` — path to the active log file (e.g.
///   `~/.local/share/stellar-agent/audit/default.jsonl`).
/// - `hmac_key` — optional 32-byte key for verifying the chain-root HMAC tag
///   on each file and the entry tags.  If `None`, HMAC verification is skipped
///   (the hash chain is still verified) and no entry tag is checked.  If
///   `Some` and the sidecar is missing, returns
///   [`VerifyError::HmacSidecarMissing`].
///
/// With a key, the entry-tag walk runs over every walked entry; see
/// [`VerifyError::EntryTagInvalid`] for when it fails.
///
/// # Errors
///
/// Returns a [`VerifyError`] on path validation failure or on the first
/// integrity violation found.
///
/// # Examples
///
/// ```no_run
/// use std::path::PathBuf;
/// use stellar_agent_core::audit_log::verify::verify_log;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let ok = verify_log(&PathBuf::from("/tmp/test.jsonl"), None)?;
/// println!("verified {} entries across {} files", ok.entries_verified, ok.files_walked);
/// # Ok(())
/// # }
/// ```
pub fn verify_log(log_path: &Path, hmac_key: Option<&[u8; 32]>) -> Result<VerifyOk, VerifyError> {
    verify_walk(log_path, hmac_key, hmac_key.map(derive_entry_tag_key), None)
}

/// [`verify_log`] with the active file read only up to `active_end_offset`,
/// the offset just past the last entry a writer holding the log verified.
///
/// Bytes past that offset are not part of the log the writer holds and do
/// not change the result: every chain, sidecar, handoff and entry-tag check
/// runs over the bounded log. A reader calls this under the writer's guard,
/// with [`super::writer::AuditWriter::end_offset`].
///
/// # Errors
///
/// Every error of [`verify_log`] over the bounded log.
pub(super) fn verify_log_within(
    log_path: &Path,
    hmac_key: Option<&[u8; 32]>,
    active_end_offset: u64,
) -> Result<VerifyOk, VerifyError> {
    verify_walk(
        log_path,
        hmac_key,
        hmac_key.map(derive_entry_tag_key),
        Some(active_end_offset),
    )
}

/// Verifies the chain and the entry tags of the log at `log_path` under
/// `key`, without the chain-root sidecar and prune-marker tag checks.
///
/// The walk is [`verify_log`]'s. `profile rotate-audit-key` runs it under the
/// old key before it replaces that key, while the sidecars may still be signed
/// by a key an interrupted earlier run already replaced. The result's
/// `hmac_verified` is `false`.
///
/// # Errors
///
/// Every error of [`verify_log`] except the sidecar and marker tag failures.
pub fn verify_entry_tags(log_path: &Path, key: &[u8; 32]) -> Result<VerifyOk, VerifyError> {
    verify_walk(log_path, None, Some(derive_entry_tag_key(key)), None)
}

/// The walk behind [`verify_log`], [`verify_log_within`] and
/// [`verify_entry_tags`]: `sidecar_key` checks the chain-root sidecars and
/// the prune marker, `tag_key` the entry tags, and `active_limit`, when
/// given, is where the walk stops reading the active file.
fn verify_walk(
    log_path: &Path,
    sidecar_key: Option<&[u8; 32]>,
    tag_key: Option<EntryTagKey>,
    active_limit: Option<u64>,
) -> Result<VerifyOk, VerifyError> {
    let hmac_key = sidecar_key;
    let mut tag_walk = EntryTagWalk::new(tag_key);
    let mut total_entries = 0usize;
    let mut files_walked = 0usize;

    // Collect the ordered list of files: oldest rotated first, then active.
    //
    // Rotation-window tolerance: `AuditWriter::rotate` renames the active
    // file to its archive name and creates the new active file as two
    // separate filesystem operations, so a concurrent reader can observe the
    // active path (the LAST element here) transiently absent even though the
    // log is not actually empty. When that happens and rotated siblings are
    // present, re-scan a small bounded number of times while the writer's
    // sidecar lock is observably held by a live writer before concluding the
    // file is genuinely missing — see `reader`'s "Reader consistency
    // posture" docs, which this mirrors for the writer-independent
    // entrypoint.
    let file_chain = collect_file_chain(log_path)?;
    let file_chain = if file_chain.len() > 1 && !file_chain.last().is_some_and(|p| p.exists()) {
        wait_out_transient_rotation_window(
            log_path,
            file_chain,
            |chain: &Vec<PathBuf>| !chain.last().is_some_and(|p| p.exists()),
            || collect_file_chain(log_path),
        )?
    } else {
        file_chain
    };
    let active_stem = log_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| VerifyError::PathContract {
            detail: "log path has no UTF-8 file name".to_owned(),
        })?;

    let marker = read_prune_marker(log_path)?;
    if let (Some(marker), Some(key)) = (&marker, hmac_key)
        && !marker.verify_tag(key)
    {
        return Err(VerifyError::HmacMismatch {
            file: basename_lossy(&prune_marker_path(log_path)),
        });
    }
    let first_file = file_chain.first().map(|path| basename_lossy(path));
    // The first file chains from the start the prune reads too; every later
    // bridge uses the walk's tip. A first file that does not exist is reported
    // by the walk.
    let mut expected_prev_hash = match first_file
        .as_deref()
        .map(|file| oldest_retained_seed(marker.as_ref(), file))
    {
        Some(Ok(seed)) => Some(seed.to_owned()),
        Some(Err(MarkerNamesNoBoundary)) if file_chain.first().is_some_and(|p| p.exists()) => {
            return Err(VerifyError::ChainBroken {
                line: 1,
                file: first_file.unwrap_or_default(),
                reason: MARKER_NAMES_NO_BOUNDARY_REASON,
            });
        }
        Some(Err(MarkerNamesNoBoundary)) | None => None,
    };
    let mut previous_timestamp: Option<(String, u64)> = None;
    let mut warnings = Vec::new();
    if expected_prev_hash
        .as_deref()
        .is_some_and(|seed| seed != ZERO_BLOCK_HASH)
        && let (Some(marker), Some(first_file)) = (&marker, first_file)
    {
        warnings.push(VerifyWarning::PrunedPrefix {
            first_file,
            pruned_files: marker.data.pruned_files,
        });
    }
    let mut per_file = Vec::new();
    // Tracks whether every per-file `SingleFileResult.sidecar_verified` was
    // true. AND-combined into `VerifyOk.hmac_verified` on success.
    let mut all_sidecars_verified = true;
    // Chain tip of the last file walked, for tip-anchor comparison.
    let mut active_tip: Option<VerifiedTip> = None;
    // Whether the handoff the next file chains from carries `entry_tags`.
    let mut seed_handoff_entry_tags = false;

    for (file_idx, path) in file_chain.iter().enumerate() {
        if !path.exists() {
            if file_idx == 0 {
                // The primary (oldest / only) file must exist. A missing primary
                // log is a user-actionable condition (nothing logged yet, or a
                // wrong path), not an ambient I/O failure — surface it via the
                // dedicated `LogNotFound` variant so it classifies distinctly.
                return Err(VerifyError::LogNotFound {
                    path: path.display().to_string(),
                });
            }
            // A rotated file referenced by the chain does not exist.
            let basename = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_owned();
            return Err(VerifyError::RotationGap { file: basename });
        }

        // For rotated files (not the last/active file), pass the current file's
        // basename for handoff validation.  The handoff entry records the archive
        // name of the file it is written into (not the new active file).  For the
        // active (last) file, no handoff is expected, so pass `None`.
        let current_file_basename: Option<&str> = if file_idx + 1 < file_chain.len() {
            // This is a rotated file; pass its own basename for handoff check.
            path.file_name().and_then(|s| s.to_str())
        } else {
            // This is the active (last) file; no handoff expected.
            None
        };

        let is_last_file = file_idx + 1 == file_chain.len();
        let result = verify_single_file(
            VerifySingleFileContext {
                path,
                hmac_key,
                expected_initial_prev_hash: expected_prev_hash.as_deref(),
                next_file_basename: current_file_basename,
                is_last_file,
                active_stem,
                file_index: file_idx,
                previous_timestamp: previous_timestamp.as_ref(),
                byte_limit: if is_last_file { active_limit } else { None },
            },
            &mut tag_walk,
        )?;

        let SingleFileResult {
            entries,
            last_hash,
            last_timestamp,
            warnings: file_warnings,
            sidecar_verified,
            end_offset,
            holds_anchoring_row,
            handoff_entry_tags,
        } = result;

        if is_last_file {
            active_tip = Some(VerifiedTip {
                entry_count: entries as u64,
                tip_hash: last_hash.clone(),
                end_offset,
                holds_anchoring_row: holds_anchoring_row || seed_handoff_entry_tags,
            });
        }
        seed_handoff_entry_tags = handoff_entry_tags;

        total_entries += entries;
        files_walked += 1;
        warnings.extend(file_warnings);
        per_file.push(FileVerifyResult {
            path: path.clone(),
            entries_verified: entries as u64,
            hmac_verified: hmac_key.map(|_| sidecar_verified),
        });
        // AND-combine: every per-file `sidecar_verified` must be true for the
        // top-level `hmac_verified` to be true. Reaching here at all already
        // implies success (sidecar failures return `Err` early), but threading
        // the boolean explicitly documents the invariant against future drift.
        all_sidecars_verified &= sidecar_verified;

        // Thread the last_hash into the next file's expected initial hash.
        expected_prev_hash = Some(last_hash);
        previous_timestamp = last_timestamp;
    }

    tag_walk.finish();
    if tag_walk.checks_tags()
        && tag_walk.in_force()
        && let Some(failure) = tag_walk.failure()
    {
        return Err(VerifyError::EntryTagInvalid {
            file: failure.file.clone(),
            line: failure.line,
            reason: failure.reason,
        });
    }

    Ok(VerifyOk {
        entries_verified: total_entries,
        files_walked,
        per_file,
        warnings,
        hmac_verified: hmac_key.is_some() && all_sidecars_verified,
        active_tip,
        entry_tags_verified: tag_walk.checks_tags() && tag_walk.in_force(),
        entry_tags_boundary: tag_walk.boundary().cloned(),
    })
}

/// Verify a hash-chained audit log and additionally report the session-level
/// audit-writer health.
///
/// This is an additive variant of [`verify_log`] — it calls `verify_log`
/// unchanged and extends the result with `audit_writer_degraded: bool` from
/// the supplied health handle.
///
/// Callers that do NOT need the health field should continue using
/// [`verify_log`] directly; this function's signature must not change
/// `verify_log`'s signature.
///
/// # Arguments
///
/// - `log_path` — same as [`verify_log`].
/// - `hmac_key` — same as [`verify_log`].
/// - `anchor` — the keyring-held [`TipAnchor`] for this log PATH, when the
///   caller could establish that the path it was asked to verify is the one the
///   anchor names. `Some` applies [`check_anchor_against_walk`]: the walk fails
///   with [`VerifyError::TipAnchorMismatch`] unless the anchored entry is
///   intact at the anchored offset and the active file ends at or past it,
///   which is what catches a restored older copy or a truncation that the
///   chain walk alone accepts. Entries past the anchor are decided by the
///   entry-tag walk. `None` verifies the chain and the tags only.
/// - `health` — a live handle to the session-level
///   [`crate::audit_log::health::AuditWriterHealthHandle`].
///
/// # Errors
///
/// Returns the same errors as [`verify_log`].
///
/// # Examples
///
/// ```no_run
/// use std::path::PathBuf;
/// use stellar_agent_core::audit_log::{
///     health::AuditWriterHealth,
///     verify::verify_log_with_health,
/// };
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let health = AuditWriterHealth::new();
/// let handle = health.handle();
/// let ok = verify_log_with_health(&PathBuf::from("/tmp/test.jsonl"), None, None, &handle)?;
/// println!(
///     "verified {} entries; degraded: {}",
///     ok.verify_ok.entries_verified, ok.audit_writer_degraded
/// );
/// # Ok(())
/// # }
/// ```
pub fn verify_log_with_health(
    log_path: &Path,
    hmac_key: Option<&[u8; 32]>,
    anchor: Option<&TipAnchor>,
    health: &crate::audit_log::health::AuditWriterHealthHandle,
) -> Result<VerifyOkWithHealth, VerifyError> {
    let verify_ok = verify_log(log_path, hmac_key)?;
    if let Some(anchor) = anchor {
        check_anchor_against_walk(log_path, anchor, verify_ok.active_tip.as_ref())?;
    }
    let audit_writer_degraded = health.is_degraded();
    Ok(VerifyOkWithHealth {
        verify_ok,
        audit_writer_degraded,
    })
}

/// Compares the keyring-held anchor with the tip the walk actually found.
///
/// Applies the same three-way rule the writer applies, and in the same order, so
/// the two surfaces cannot disagree about a given file:
///
/// 1. A verified prefix shorter than the anchor is a rollback or a truncation.
/// 2. The entry ending at the anchored offset must still hash to the anchored
///    tip. Length alone proves nothing: a longer, internally consistent chain
///    that does not contain the anchored entry is a wholesale substitution, and
///    it passes the chain walk exactly as an honest log does.
/// 3. At the anchored offset the counts and the tip must match as well, which
///    catches a prefix rewritten to a different entry count.
///
/// Before any of that, an anchor naming the newest archive's rotation handoff is
/// accepted: it describes the generation this file succeeded, not this file.
///
/// A file that moved FORWARD past an intact anchored entry is not an error
/// here. Once entry tags are in force, the entry-tag walk of [`verify_log`]
/// decides the entries past the anchor: each needs a valid tag. Before that,
/// the next keyed acquisition absorbs the gap once and counts it in its
/// `audit_entry_tags_started` row.
///
/// The function reads the log at `log_path` and never reads or writes the
/// keyring, so it neither adopts nor advances an anchor.
///
/// # Errors
///
/// [`VerifyError::TipAnchorMismatch`] when the anchor disagrees with the walk,
/// and [`VerifyError`] I/O variants when the anchored entry cannot be read.
pub fn check_anchor_against_walk(
    log_path: &Path,
    anchor: &TipAnchor,
    active_tip: Option<&VerifiedTip>,
) -> Result<(), VerifyError> {
    let Some(tip) = active_tip else {
        return Err(VerifyError::TipAnchorMismatch {
            expected_count: anchor.entry_count,
            expected_offset: anchor.end_offset,
            actual_count: 0,
            actual_offset: 0,
            reason: "no active file was walked",
        });
    };

    let mismatch = |reason: &'static str| VerifyError::TipAnchorMismatch {
        expected_count: anchor.entry_count,
        expected_offset: anchor.end_offset,
        actual_count: tip.entry_count,
        actual_offset: tip.end_offset,
        reason,
    };

    if anchor.matches_tip(tip.entry_count, &tip.tip_hash, tip.end_offset) {
        return Ok(());
    }

    // The anchor may name the PREVIOUS file generation. A rotation leaves it on
    // the outgoing file's handoff entry and it stays there until the new file's
    // first append advances it, so its count and offset describe the archive,
    // not the file the walk just ended on. The same proof the writer applies:
    // the anchored tip must be the hash of the newest archive's last entry.
    if anchor_names_the_rotation_handoff(log_path, anchor) {
        return Ok(());
    }

    if tip.end_offset < anchor.end_offset {
        return Err(mismatch(
            "the active file's verified prefix is shorter than the anchor",
        ));
    }
    if !anchored_entry_is_intact(log_path, anchor)? {
        return Err(mismatch(
            "the entry at the anchored offset is not the anchored entry",
        ));
    }
    if tip.end_offset == anchor.end_offset {
        return Err(mismatch("the active file's tip is not the anchored tip"));
    }
    Ok(())
}

/// Refuses a log with no stored anchor that shows it was anchored before.
///
/// The verifier's half of the writer's adoption rule, decided by the same
/// [`PriorAnchoring::find`]: an audit binding recorded for the profile, a
/// chain-root sidecar on the active file, or an `audit_tip_anchored` row in
/// it, for a file with entries; the sidecar alone for an empty file. `binding`
/// is what the caller read from the keyring without writing it. A log none of
/// these facts describe was never anchored and passes, so a log written only by
/// unkeyed writers verifies before its first keyed use.
///
/// Call this only when no anchor is stored for the path the walk verified.
///
/// # Errors
///
/// [`VerifyError::TipAnchorMissing`] naming the evidence.
pub fn check_missing_anchor(
    log_path: &Path,
    binding: BindingHistory,
    active_tip: Option<&VerifiedTip>,
) -> Result<(), VerifyError> {
    let (entry_count, holds_anchoring_row) =
        active_tip.map_or((0, false), |tip| (tip.entry_count, tip.holds_anchoring_row));
    match PriorAnchoring::find(binding, log_path, entry_count, holds_anchoring_row) {
        None => Ok(()),
        Some(evidence) => Err(VerifyError::TipAnchorMissing {
            evidence,
            actual_count: entry_count,
            actual_offset: active_tip.map_or(0, |tip| tip.end_offset),
        }),
    }
}

/// Whether a stored anchor disagrees with the walked tip of the log at
/// `log_path`.
///
/// An absent anchor agrees, an unusable one disagrees, and a usable one
/// disagrees exactly when [`check_anchor_against_walk`] refuses it. A file that
/// moved forward past an intact anchored entry agrees. Like that rule, this
/// reads only the log.
///
/// # Errors
///
/// [`VerifyError`] when the anchored entry cannot be read for a reason other
/// than a disagreement.
pub fn stored_anchor_disagrees_with_walk(
    log_path: &Path,
    stored: &crate::audit_log::writer::StoredTipAnchor,
    active_tip: Option<&VerifiedTip>,
) -> Result<bool, VerifyError> {
    use crate::audit_log::writer::StoredTipAnchor;
    match stored {
        StoredTipAnchor::Absent => Ok(false),
        StoredTipAnchor::Unusable { .. } => Ok(true),
        StoredTipAnchor::Usable(anchor) => {
            match check_anchor_against_walk(log_path, anchor, active_tip) {
                Ok(()) => Ok(false),
                Err(VerifyError::TipAnchorMismatch { .. }) => Ok(true),
                Err(e) => Err(e),
            }
        }
    }
}

/// Returns `true` when the anchor names exactly the newest rotated archive's
/// handoff entry.
///
/// The verifier's half of the writer's rotation-completed rule, computed from
/// the same helper so the two cannot disagree about which archive is newest or
/// what its handoff hashes to. A failure to derive the seed returns `false`,
/// which leaves the caller's remaining checks to refuse: the walk has already
/// validated the cross-file bridge by this point, so a seed that cannot be read
/// here is a reason to distrust the file, not to accept it.
fn anchor_names_the_rotation_handoff(log_path: &Path, anchor: &TipAnchor) -> bool {
    crate::audit_log::writer::initial_chain_seed(log_path)
        .is_ok_and(|seed| seed.hash == anchor.tip_hash)
}

/// Returns `true` when the last entry ending at or before the anchored offset
/// still hashes to the anchored tip.
///
/// Reads through the writer's own backward scan, so the verifier and the writer
/// prove intactness from the same bytes in the same way.
fn anchored_entry_is_intact(log_path: &Path, anchor: &TipAnchor) -> Result<bool, VerifyError> {
    let file = open_regular_file(log_path)?;
    let Some(line) = crate::audit_log::writer::read_last_line_before(&file, anchor.end_offset)
        .map_err(VerifyError::Io)?
    else {
        return Ok(false);
    };
    let Ok(entry) = serde_json::from_slice::<AuditEntry>(&line) else {
        return Ok(false);
    };
    let Ok(body) = entry.canonical_json_body() else {
        return Ok(false);
    };
    match compute_entry_hash(&body, &entry.previous_entry_hash) {
        Ok(hash) => Ok(hash == anchor.tip_hash),
        Err(_) => Ok(false),
    }
}

/// The outcome of a successful [`verify_log_with_health`] call.
///
/// Wraps [`VerifyOk`] and adds the session-level health state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyOkWithHealth {
    /// The verification result (same as `verify_log` output).
    pub verify_ok: VerifyOk,
    /// Whether the audit-writer mutex was poisoned at any point during this
    /// MCP server session.  A degraded writer means at least one audit row
    /// was dropped since server start.
    ///
    /// This field is informational — it does NOT cause verification to fail
    /// because the health state is a session property, not a log-file property.
    /// When `true`, the operator should restart the server and investigate the
    /// poison cause.
    pub audit_writer_degraded: bool,
}

// ── Internal structures ───────────────────────────────────────────────────────

struct SingleFileResult {
    entries: usize,
    /// Whether this file holds an `audit_tip_anchored` row, an entry-tag row,
    /// or a row with an entry tag.
    holds_anchoring_row: bool,
    /// Whether this file's rotation handoff carries `entry_tags`.
    handoff_entry_tags: bool,
    /// Hash of the last entry in this file (used for cross-file chain bridging).
    last_hash: String,
    /// Byte offset just past the last entry in this file — the length of the
    /// verified prefix, which the tip anchor records.
    end_offset: u64,
    /// Last parsed timestamp in this file, if the file contained any entries.
    last_timestamp: Option<(String, u64)>,
    warnings: Vec<VerifyWarning>,
    /// `true` iff this file had its HMAC sidecar successfully verified end-to-end.
    /// `false` when no HMAC key was supplied (sidecar verification skipped).
    /// On sidecar mismatch or missing-sidecar, `verify_single_file` returns an
    /// error rather than `false`, so this field documents only the
    /// supplied-key-and-verified case explicitly.
    sidecar_verified: bool,
}

#[derive(Clone, Copy)]
struct VerifySingleFileContext<'a> {
    path: &'a Path,
    hmac_key: Option<&'a [u8; 32]>,
    expected_initial_prev_hash: Option<&'a str>,
    next_file_basename: Option<&'a str>,
    is_last_file: bool,
    active_stem: &'a str,
    file_index: usize,
    previous_timestamp: Option<&'a (String, u64)>,
    /// Where reading the file stops, when given; bytes past it are not read.
    byte_limit: Option<u64>,
}

/// Collects the ordered list of files to verify.
///
/// Uses [`is_rotated_sibling`] for strict glob matching — prevents `.lock`
/// and `.root_hmac` sidecars from being included as log files.
///
/// The active file is placed last; rotated files are sorted oldest-first by
/// filename (lexicographic compact-timestamp order).
///
/// # Errors
///
/// Returns [`VerifyError::PathContract`] if `log_path` has no parent directory
/// component (bare filename).  Supply an explicit parent directory, e.g.
/// `~/.local/share/stellar-agent/audit/default.jsonl`.  This shares the wire
/// code `audit.path_contract` with the non-UTF-8 file-name rejection so that
/// operators see one error class for "the supplied path is structurally
/// unusable", rather than conflating it into `audit.io_error`
/// (which covers permission-denied, ENOSPC, etc.).
pub(super) fn collect_file_chain(log_path: &Path) -> Result<Vec<PathBuf>, VerifyError> {
    let dir = log_path.parent().ok_or_else(|| VerifyError::PathContract {
        detail: "audit log path must have a parent directory component \
                 (e.g. /path/to/audit/default.jsonl, not a bare filename)"
            .to_owned(),
    })?;
    let stem = log_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("audit.jsonl");

    let mut rotated = Vec::new();
    if dir.exists() {
        for entry in fs::read_dir(dir).map_err(VerifyError::Io)? {
            let Ok(path) = entry.map(|entry| entry.path()) else {
                continue;
            };
            let is_rotated = path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|name| is_rotated_sibling(stem, name))
                .unwrap_or(false);
            if !is_rotated {
                continue;
            }

            rotated.push(path);
            if rotated.len() > ROTATED_FILE_CHAIN_CAP {
                return Err(VerifyError::TooManyRotatedFiles {
                    found: rotated.len(),
                    cap: ROTATED_FILE_CHAIN_CAP,
                });
            }
        }
    }

    // Sort rotated files oldest-first (lexicographic timestamp order).
    rotated.sort();

    // Verification order: rotated files (oldest first), then active.
    let mut chain = rotated;
    chain.push(log_path.to_path_buf());
    Ok(chain)
}

/// Verifies a single log file.
///
/// # Arguments
///
/// - `path` — path to the log file.
/// - `hmac_key` — optional HMAC key for chain-root verification.
/// - `expected_initial_prev_hash` — the expected `previous_entry_hash` of the
///   first entry in this file.  `None` means this is the very first file in
///   the chain — use [`ZERO_BLOCK_HASH`].
/// - `next_file_basename` — if `Some`, the expected value of the
///   `AuditRotationHandoff.next_file_name` in this file's last handoff entry.
///   The handoff entry names the **rotated archive name** of the current file
///   (i.e. what this file will be / has been renamed to), NOT the new active
///   file that follows.  We verify that the basename in the handoff matches the
///   actual current file's basename — this detects substitution (renaming the
///   rotated file to a different timestamp).  `None` for the last (active) file
///   in the chain.
/// - `is_last_file` — whether this file is the active file. Active files must
///   not contain rotation handoff entries.
///
/// # Errors
///
/// Returns a [`VerifyError`] on the first integrity violation.
fn verify_single_file(
    ctx: VerifySingleFileContext<'_>,
    tag_walk: &mut EntryTagWalk,
) -> Result<SingleFileResult, VerifyError> {
    let path = ctx.path;
    let file_basename = basename_lossy(path);
    let file = open_regular_file(path)?;
    let mut reader = BufReader::new(file.take(ctx.byte_limit.unwrap_or(u64::MAX)));

    // For the very first file, the initial expected prev hash is ZERO_BLOCK_HASH.
    // For subsequent files, it is the last_hash of the preceding file.
    let initial_prev_hash = ctx.expected_initial_prev_hash.unwrap_or(ZERO_BLOCK_HASH);
    let mut prev_hash = initial_prev_hash.to_owned();

    let mut entries = 0usize;
    let mut end_offset = 0u64;
    let mut holds_anchoring_row = false;
    let mut handoff_entry_tags = false;
    let mut is_first_entry = true;
    let mut last_handoff_next_file: Option<String> = None;
    let mut previous_timestamp = ctx.previous_timestamp.cloned();
    let mut warnings = Vec::new();
    // Each row's quarantine directive, when it is one that can take effect,
    // and the warning each such directive reports with the position it takes
    // in `warnings`; only a directive no later one covers reports it.
    let mut directives: Vec<Option<u64>> = Vec::new();
    let mut quarantine_warnings: Vec<(usize, usize, VerifyWarning)> = Vec::new();

    // Read through `read_until` rather than `BufRead::lines` so the byte offset
    // of the verified prefix stays exact: the tip anchor records where the chain
    // ends, and a line-based reader cannot report that.
    let mut raw = Vec::new();
    let mut consumed = 0u64;
    let mut line_index = 0usize;
    loop {
        raw.clear();
        let read = reader
            .read_until(b'\n', &mut raw)
            .map_err(VerifyError::Io)?;
        if read == 0 {
            break;
        }
        consumed = consumed.saturating_add(read as u64);
        let line_number = line_index + 1;
        line_index += 1;

        let line = std::str::from_utf8(strip_line_terminator(&raw)).map_err(|e| {
            VerifyError::ParseError {
                line: line_number,
                detail: format!("line is not valid UTF-8: {e}"),
            }
        })?;

        if line.trim().is_empty() {
            continue;
        }

        // Parse the entry.
        let entry: AuditEntry =
            serde_json::from_str(line).map_err(|e| VerifyError::ParseError {
                line: line_number,
                detail: e.to_string(),
            })?;

        let current_ts_ms =
            parse_audit_timestamp_ms(&entry.ts).map_err(|detail| VerifyError::ParseError {
                line: line_number,
                detail,
            })?;
        if let Some((previous_ts, previous_ts_ms)) = &previous_timestamp
            && *previous_ts_ms > current_ts_ms
        {
            let drift_ms = *previous_ts_ms - current_ts_ms;
            if drift_ms > BACKWARD_TS_WARN_THRESHOLD_MS {
                warnings.push(VerifyWarning::BackwardTimestampJump {
                    previous_ts: previous_ts.clone(),
                    current_ts: entry.ts.clone(),
                    drift_ms,
                    file_index: ctx.file_index,
                    entry_index: entries,
                });
            }
        }
        previous_timestamp = Some((entry.ts.clone(), current_ts_ms));

        // Verify the previous_entry_hash matches what we expect.
        if entry.previous_entry_hash != prev_hash {
            return Err(VerifyError::ChainBroken {
                line: line_number,
                file: path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_owned(),
                reason: "previous_entry_hash_mismatch",
            });
        }

        // Compute canonical body and hash.
        let body = entry
            .canonical_json_body()
            .map_err(|e| VerifyError::ParseError {
                line: line_number,
                detail: e.to_string(),
            })?;

        let current_hash =
            compute_entry_hash(&body, &prev_hash).map_err(|e| VerifyError::ParseError {
                line: line_number,
                detail: e.to_string(),
            })?;

        // Verify chain-root HMAC on the first entry of each file.
        if is_first_entry {
            if let Some(key) = ctx.hmac_key {
                verify_root_sidecar(path, key, &body)?;
            }
            is_first_entry = false;
        }

        holds_anchoring_row |= shows_anchoring(&entry);
        let check = tag_walk.observe(&file_basename, line_number, &entry, &current_hash);
        // A quarantine row takes part in coverage when it can take effect:
        // with a key, only one whose own tag is valid.
        let directive = match &entry.event_kind {
            EventKind::AuditEntriesQuarantined { quarantined_count }
                if check.is_none_or(|check| check == EntryTagCheck::Valid) =>
            {
                Some(*quarantined_count)
            }
            _ => None,
        };
        let row = directives.len();
        directives.push(directive);

        // Track rotation handoff entries for cross-file validation.
        // `EventKind` is `#[non_exhaustive]` but we are in the same crate, so
        // this match IS exhaustive without a wildcard arm.  If a new variant is
        // added to `EventKind`, the compiler will force this match to be updated,
        // ensuring `verify_single_file` is always aware of every event kind.
        match &entry.event_kind {
            EventKind::ToolInvocation => {}
            EventKind::PluginInvoked { .. } => {}
            EventKind::WalletMlockFailed { .. } => {}
            EventKind::SaRawInvocation { .. } => {
                // No rotation-handoff tracking needed for this variant.
            }
            EventKind::SmartAccountDeployed { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaContextRuleCreated { .. }
            | EventKind::SaContextRuleCreatedV2 { .. }
            | EventKind::SaContextRulePinsUpdated { .. }
            | EventKind::SaContextRulePinsUpdatedV2 { .. }
            | EventKind::SaContextRuleDeleted { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaContextRuleNameUpdated { .. }
            | EventKind::SaContextRuleValidUntilUpdated { .. } => {
                // Metadata-update forensic rows emitted alongside SaRawInvocation.
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::PasskeyRegistered { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::PasskeyAssertion { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaSignerAdded { .. }
            | EventKind::SaSignerRemoved { .. }
            | EventKind::SaThresholdChanged { .. }
            | EventKind::SaSignerSetDiverged { .. }
            | EventKind::SaSignerSetBaselined { .. }
            | EventKind::SaSignerSetBaselinedV2 { .. }
            | EventKind::SaSignerAddedV2 { .. }
            | EventKind::SaSignerRemovedV2 { .. }
            | EventKind::SaThresholdChangedV2 { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaVerifierHashDrift { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaPolicyHashDrift { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaMutableContractOverride { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaUnknownContractOverride { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaVerifierMigrated { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaVerifierDiversificationOverride { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaVerifierAllowlistAdvisory { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaPolicyAdded { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaPolicyRemoved { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaSpendingLimitRetuned { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaWeightedThresholdChanged { .. }
            | EventKind::SaSignerWeightChanged { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaMulticallBundleSubmitted { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaMulticallInnerExecuted { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaMulticallBundleDenied { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaMulticallRegistered { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaMulticallRegistrationRefused { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaMulticallUnregistered { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaMulticallUnregisteredForce { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaTimelockScheduled { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaTimelockCancelled { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaTimelockExecuted { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaTimelockDivergencePostSubmit { .. } => {
                // Timelock cross-RPC divergence post-submit event.
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaExternalExecuteSubmitted { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::ChannelPoolInitialised { .. }
            | EventKind::ChannelAcquired { .. }
            | EventKind::ChannelReleased { .. } => {
                // Channel-account pool events.
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SubmissionAuthMismatch { .. } => {
                // Simulation-audit mismatch event.
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::ApprovalAttested { .. }
            | EventKind::ApprovalRejected { .. }
            | EventKind::ApprovalAttestedRemote { .. }
            | EventKind::ApprovalRejectedRemote { .. } => {
                // Approval lifecycle events. No rotation-handoff tracking
                // needed; the hash-chain is maintained by the surrounding
                // hash check.
            }
            EventKind::ValueActionSubmitted { .. }
            | EventKind::ValueActionPending { .. }
            | EventKind::ValueActionFailed { .. }
            | EventKind::SubmissionReceiptCleared { .. }
            | EventKind::X402PaymentAuthorized { .. }
            | EventKind::X402AuthorizationWithheld { .. }
            | EventKind::OpaquePayloadSigned { .. }
            | EventKind::MppChargeAuthorized { .. }
            | EventKind::MppAuthorizationWithheld { .. }
            | EventKind::MppReceiptObserved { .. }
            | EventKind::MppSettlementReconciled { .. }
            | EventKind::KeyringKeyWritten { .. }
            | EventKind::SignerIdentityEnrolled { .. }
            | EventKind::MainnetEnablementMinted { .. }
            | EventKind::MppStateAdopted { .. }
            | EventKind::MppStateReset { .. }
            | EventKind::PolicyWindowStateReset { .. }
            | EventKind::AuditTipAnchored { .. } => {
                // Value-action, key-write, window-state-reset, and tip-anchor
                // forensic rows. No rotation-handoff tracking needed; the
                // hash-chain is maintained by the surrounding hash check.
            }
            EventKind::AuditOutboxLossAcknowledged {
                expected_rows,
                found_rows,
                ..
            } => {
                warnings.push(VerifyWarning::OutboxLossAcknowledged {
                    file: path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    line: line_number,
                    expected_rows: *expected_rows,
                    found_rows: *found_rows,
                });
            }
            EventKind::AuditEntryTagsStarted {
                anchored_count,
                absorbed_count,
            } => {
                if *absorbed_count > 0 {
                    warnings.push(VerifyWarning::EntryTagsAbsorbed {
                        file: file_basename.clone(),
                        line: line_number,
                        anchored_count: *anchored_count,
                        absorbed_count: *absorbed_count,
                    });
                }
            }
            EventKind::AuditEntryTagsRekeyed { cause } => {
                if *cause == EntryTagsRekeyCause::OpenRepair {
                    warnings.push(VerifyWarning::EntryTagsRekeyedAtOpen {
                        file: file_basename.clone(),
                        line: line_number,
                    });
                }
            }
            EventKind::AuditEntriesQuarantined { quarantined_count } => {
                if directive.is_some() {
                    quarantine_warnings.push((
                        row,
                        warnings.len(),
                        VerifyWarning::EntriesQuarantined {
                            file: file_basename.clone(),
                            line: line_number,
                            quarantined_count: *quarantined_count,
                        },
                    ));
                }
            }
            EventKind::AuditRotationHandoff {
                next_file_name,
                entry_tags,
            } => {
                handoff_entry_tags = *entry_tags;
                if ctx.is_last_file {
                    return Err(VerifyError::ChainBroken {
                        line: line_number,
                        file: path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_owned(),
                        reason: "rotation_handoff_in_active_file",
                    });
                }
                last_handoff_next_file = Some(next_file_name.clone());
            }
        }

        prev_hash = current_hash;
        entries += 1;
        end_offset = consumed;
    }

    // A quarantine is reported only for a directive that takes effect: one
    // that no later directive of the file covers. Inserted from the last so
    // every earlier position stays where it was recorded.
    let covered = quarantine_coverage(&directives);
    for (row, at, warning) in quarantine_warnings.into_iter().rev() {
        if !covered[row] {
            warnings.insert(at, warning);
        }
    }

    // Validate the rotation handoff's `next_file_name` against the current
    // file's actual basename.
    //
    // The handoff entry records the archive name that this file was renamed to
    // (e.g. `audit.jsonl.20260429T123456789`).  By verifying that this matches
    // the actual filename of the file we just read, we detect substitution attacks
    // where an attacker swaps one rotated file for another.
    //
    if let Some(this_file_basename) = ctx.next_file_basename {
        match last_handoff_next_file {
            Some(ref actual) if actual == this_file_basename => {}
            Some(ref actual) => {
                let actual = sanitize_handoff_next_file_name(ctx.active_stem, actual);
                return Err(VerifyError::RotationGap {
                    file: format!("handoff names '{actual}' but file is '{this_file_basename}'"),
                });
            }
            None => {
                // No handoff entry found but this is a rotated file — it must
                // have a handoff entry or the chain integrity cannot be confirmed.
                return Err(VerifyError::RotationGap {
                    file: format!(
                        "no handoff entry in '{}' (expected archive name '{this_file_basename}')",
                        path.file_name().and_then(|s| s.to_str()).unwrap_or("")
                    ),
                });
            }
        }
    }

    Ok(SingleFileResult {
        entries,
        holds_anchoring_row,
        handoff_entry_tags,
        last_hash: prev_hash,
        end_offset,
        last_timestamp: previous_timestamp,
        warnings,
        // Reaching this point with `ctx.hmac_key.is_some()` implies every
        // chunk's sidecar verified successfully — the only paths that produce
        // a sidecar failure return `Err` early (HmacSidecarMissing /
        // HmacMismatch upstream). Capture the boolean explicitly so callers
        // don't have to re-derive it from `hmac_key.is_some()` (avoids a class
        // of drift if a future change introduces a non-fatal sidecar-skip path).
        sidecar_verified: ctx.hmac_key.is_some(),
    })
}

/// Whether `entry` shows that a keyed writer or an anchored writer reached the
/// log: an `audit_tip_anchored` row, one of the entry-tag rows, or any row that
/// carries an entry tag.
pub(super) fn shows_anchoring(entry: &AuditEntry) -> bool {
    entry.entry_tag.is_some()
        || matches!(
            entry.event_kind,
            EventKind::AuditTipAnchored { .. }
                | EventKind::AuditEntryTagsStarted { .. }
                | EventKind::AuditEntryTagsRekeyed { .. }
                | EventKind::AuditEntriesQuarantined { .. }
        )
}

/// What a row means to the entry-tag walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TagRowClass {
    /// `audit_entry_tags_started` or `audit_entry_tags_rekeyed`.
    KeyedStart {
        /// The row's event kind.
        kind: &'static str,
    },
    /// A rotation handoff, with its `entry_tags` flag.
    Handoff {
        /// The handoff's `entry_tags` flag.
        entry_tags: bool,
    },
    /// `audit_entries_quarantined`, with its count.
    Quarantine {
        /// The number of entries directly before the row it covers.
        quarantined_count: u64,
    },
    /// Every other row.
    Other,
}

impl TagRowClass {
    /// The class of a row of kind `kind`.
    pub(super) fn of(kind: &EventKind) -> Self {
        match kind {
            EventKind::AuditEntryTagsStarted { .. } => Self::KeyedStart {
                kind: "audit_entry_tags_started",
            },
            EventKind::AuditEntryTagsRekeyed { .. } => Self::KeyedStart {
                kind: "audit_entry_tags_rekeyed",
            },
            EventKind::AuditRotationHandoff { entry_tags, .. } => Self::Handoff {
                entry_tags: *entry_tags,
            },
            EventKind::AuditEntriesQuarantined { quarantined_count } => Self::Quarantine {
                quarantined_count: *quarantined_count,
            },
            _ => Self::Other,
        }
    }

    /// Whether a row of this class puts entry tags in force for itself and
    /// every row after it: a keyed start, or a handoff with `entry_tags`.
    pub(super) fn starts_entry_tags(self) -> bool {
        matches!(
            self,
            Self::KeyedStart { .. } | Self::Handoff { entry_tags: true }
        )
    }
}

/// Which rows of one file the quarantine rows in it cover, oldest first.
///
/// `quarantine[i]` is `Some(n)` when row `i` is an
/// `audit_entries_quarantined { quarantined_count: n }` row that may take
/// effect, and `None` for every other row. The walk runs from the last row to
/// the first: a quarantine row that no later quarantine row covers takes
/// effect and covers the `n` rows directly before it, and a covered row, a
/// covered quarantine row included, starts no coverage. A quarantine row thus
/// takes effect only when no later quarantine row that takes effect covers
/// it, so a planted quarantine row that a genuine one covers hides nothing.
///
/// The bounded reader and the entry-tag walk both decide coverage here, so a
/// row `audit verify` accepts as quarantined is the row every scan drops.
pub(super) fn quarantine_coverage(quarantine: &[Option<u64>]) -> Vec<bool> {
    let mut covered = vec![false; quarantine.len()];
    let mut remaining = 0u64;
    for (flag, count) in covered.iter_mut().zip(quarantine).rev() {
        if remaining > 0 {
            *flag = true;
            remaining -= 1;
        } else if let Some(count) = count {
            remaining = *count;
        }
    }
    covered
}

/// A row the entry-tag walk holds against the log: the first row of a run of
/// rows whose tags failed and that nothing after them covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TagFailure {
    /// Basename of the file holding the row.
    pub(super) file: String,
    /// One-based line of the row in that file.
    pub(super) line: usize,
    /// `missing` or `mismatch`.
    pub(super) reason: &'static str,
}

/// One row the entry-tag walk has checked and not yet applied.
#[derive(Debug, Clone, Copy)]
struct CheckedRow {
    line: usize,
    class: TagRowClass,
    check: EntryTagCheck,
}

/// The entry-tag walk over a chain of entries, oldest first.
///
/// A valid tag on an entry covers that entry and, through its chain hash,
/// every entry before it. The walk keeps the first row of the run of failing
/// rows that is still open, and the first failure that nothing covered.
///
/// The rows of one file are held until the walk moves to the next file or
/// finishes. [`quarantine_coverage`] then decides which of them a valid
/// `audit_entries_quarantined` row covers; a covered row opens and closes no
/// run, and a covered keyed start or flagged handoff still puts tags in
/// force. Every other row is applied in order:
///
/// - A keyed start (`audit_entry_tags_started`, `audit_entry_tags_rekeyed`)
///   with a valid tag puts tags in force and clears the open run and the
///   recorded failure; it is recorded as the boundary. With a failing tag it
///   puts tags in force and opens a run.
/// - A handoff with `entry_tags` puts tags in force from the start of the
///   walk, and then counts as a row under the rules below.
/// - Any other row with a valid tag, a quarantine row included, turns an open
///   run into the recorded failure, keeping the first one recorded.
/// - A row with a missing or mismatched tag opens a run unless one is open.
/// - At the end of the walk an open run becomes the recorded failure.
///
/// The verdict belongs to the caller: a failure counts only while tags are in
/// force. Without a key the walk checks nothing.
pub(super) struct EntryTagWalk {
    key: Option<EntryTagKey>,
    in_force: bool,
    open_run: Option<TagFailure>,
    recorded: Option<TagFailure>,
    boundary: Option<EntryTagsBoundary>,
    /// The file whose rows `held` holds.
    held_file: String,
    /// The checked rows of `held_file` not yet applied, oldest first.
    held: Vec<CheckedRow>,
}

impl EntryTagWalk {
    /// A walk checking tags under `key`, or checking nothing when `None`.
    pub(super) fn new(key: Option<EntryTagKey>) -> Self {
        Self {
            key,
            in_force: false,
            open_run: None,
            recorded: None,
            boundary: None,
            held_file: String::new(),
            held: Vec::new(),
        }
    }

    /// Whether the walk holds a key and so checks tags.
    pub(super) fn checks_tags(&self) -> bool {
        self.key.is_some()
    }

    /// Whether tags are in force in the walked entries, once
    /// [`Self::finish`] has applied every row.
    pub(super) fn in_force(&self) -> bool {
        self.in_force
    }

    /// The recorded failure, once [`Self::finish`] has closed the open run.
    pub(super) fn failure(&self) -> Option<&TagFailure> {
        self.recorded.as_ref()
    }

    /// The newest keyed start with a valid tag, once [`Self::finish`] has
    /// applied every row.
    pub(super) fn boundary(&self) -> Option<&EntryTagsBoundary> {
        self.boundary.as_ref()
    }

    /// Feeds one entry whose chain hash is `hash`, at `line` of `file`.
    /// Returns the tag check, or `None` without a key.
    pub(super) fn observe(
        &mut self,
        file: &str,
        line: usize,
        entry: &AuditEntry,
        hash: &str,
    ) -> Option<EntryTagCheck> {
        let key = self.key.as_ref()?;
        let check = check_entry_tag(key, hash, entry.entry_tag.as_deref());
        self.observe_check(file, line, TagRowClass::of(&entry.event_kind), check);
        Some(check)
    }

    /// Feeds one row of `file` whose tag was already checked as `check`.
    /// Rows of one file arrive consecutively, oldest first.
    pub(super) fn observe_check(
        &mut self,
        file: &str,
        line: usize,
        class: TagRowClass,
        check: EntryTagCheck,
    ) {
        if self.held_file != file {
            self.apply_held();
            file.clone_into(&mut self.held_file);
        }
        self.held.push(CheckedRow { line, class, check });
    }

    /// Applies every held row and closes an open run at the end of the walk.
    pub(super) fn finish(&mut self) {
        self.apply_held();
        self.close_run();
    }

    /// Applies the held rows of one file, skipping the rows a valid
    /// quarantine row covers.
    fn apply_held(&mut self) {
        let held = std::mem::take(&mut self.held);
        let quarantine: Vec<Option<u64>> = held
            .iter()
            .map(|row| match row.class {
                TagRowClass::Quarantine { quarantined_count }
                    if row.check == EntryTagCheck::Valid =>
                {
                    Some(quarantined_count)
                }
                _ => None,
            })
            .collect();
        let covered = quarantine_coverage(&quarantine);
        for (row, covered) in held.into_iter().zip(covered) {
            if covered {
                self.in_force |= row.class.starts_entry_tags();
            } else {
                self.apply(row);
            }
        }
    }

    /// Applies one row no quarantine row covers.
    fn apply(&mut self, row: CheckedRow) {
        match row.class {
            TagRowClass::KeyedStart { kind } => {
                self.in_force = true;
                if row.check == EntryTagCheck::Valid {
                    self.open_run = None;
                    self.recorded = None;
                    self.boundary = Some(EntryTagsBoundary {
                        file: self.held_file.clone(),
                        line: row.line,
                        kind: kind.to_owned(),
                    });
                } else {
                    self.open(row);
                }
                return;
            }
            TagRowClass::Handoff { entry_tags: true } => self.in_force = true,
            TagRowClass::Handoff { entry_tags: false }
            | TagRowClass::Quarantine { .. }
            | TagRowClass::Other => {}
        }
        if row.check == EntryTagCheck::Valid {
            self.close_run();
        } else {
            self.open(row);
        }
    }

    fn open(&mut self, row: CheckedRow) {
        if self.open_run.is_none() {
            self.open_run = Some(TagFailure {
                file: self.held_file.clone(),
                line: row.line,
                reason: row.check.failure_reason().unwrap_or("missing"),
            });
        }
    }

    fn close_run(&mut self) {
        if let Some(run) = self.open_run.take()
            && self.recorded.is_none()
        {
            self.recorded = Some(run);
        }
    }
}

/// Verifies the chain-root tag in `log_file`'s `.root_hmac` sidecar over
/// `first_body`, the canonical body of the file's first entry, under `key`.
///
/// The sidecar is opened with [`open_regular_file`] and read within
/// [`SIDECAR_READ_CAP`]. An absent sidecar is
/// [`VerifyError::HmacSidecarMissing`]. A tag that does not verify is
/// [`VerifyError::HmacMismatch`], and so is a sidecar too long to hold one.
pub(super) fn verify_root_sidecar(
    log_file: &Path,
    key: &[u8; 32],
    first_body: &[u8],
) -> Result<(), VerifyError> {
    let file = || {
        log_file
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_owned()
    };
    let tag = match read_small_regular_file(&hmac_sidecar_path(log_file), SIDECAR_READ_CAP) {
        Ok(Some(bytes)) => String::from_utf8(bytes).map_err(|e| {
            VerifyError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?,
        Ok(None) => return Err(VerifyError::HmacMismatch { file: file() }),
        Err(VerifyError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(VerifyError::HmacSidecarMissing { file: file() });
        }
        Err(e) => return Err(e),
    };
    verify_chain_root(key, first_body, tag.trim())
        .map_err(|_| VerifyError::HmacMismatch { file: file() })
}

/// Most bytes read from a sidecar: a `.root_hmac` tag or the `<log>.pruned`
/// marker.
///
/// A tag is under a hundred bytes and a marker, which names two files of at
/// most 255 bytes each with their seeds and a tag, under one kilobyte. The cap
/// keeps a planted sidecar from making a reader allocate more than this.
pub(super) const SIDECAR_READ_CAP: u64 = 16 * 1024;

/// Reads the regular file at `path` whole when it holds at most `cap` bytes.
///
/// `Ok(None)` means the file is longer than `cap`; at most `cap + 1` bytes are
/// read to find that out. The open is [`open_regular_file`].
pub(super) fn read_small_regular_file(
    path: &Path,
    cap: u64,
) -> Result<Option<Vec<u8>>, VerifyError> {
    read_bounded(open_regular_file(path)?, cap).map_err(VerifyError::Io)
}

/// Reads `reader` to its end when it yields at most `cap` bytes, and returns
/// `None` after reading `cap + 1` bytes otherwise.
fn read_bounded(reader: impl Read, cap: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    reader.take(cap.saturating_add(1)).read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= cap).then_some(bytes))
}

/// Opens `path` for reading only when it is a regular file.
///
/// On Unix the open itself refuses a symlink (`O_NOFOLLOW`) and never waits
/// (`O_NONBLOCK`), so a FIFO or device at the path cannot stall the caller. On
/// Windows the open names the reparse point itself rather than its target
/// (`FILE_FLAG_OPEN_REPARSE_POINT`), and a handle that carries the
/// reparse-point attribute is refused. A `symlink_metadata` pre-check there
/// refuses a non-regular file before the open, so a directory gets this
/// refusal rather than the access error its open would return. On every
/// platform the opened handle must then be a regular file. A refusal is
/// [`VerifyError::NonRegularFileLogPath`].
pub(super) fn open_regular_file(path: &Path) -> Result<File, VerifyError> {
    let non_regular = || VerifyError::NonRegularFileLogPath {
        path: path.to_path_buf(),
    };
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt as _;
        match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(_) if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) => {
                return Err(non_regular());
            }
            Err(e) => return Err(VerifyError::Io(e)),
        }
    };
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        let reparse_point = |metadata: &fs::Metadata| {
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        };
        let metadata = fs::symlink_metadata(path).map_err(VerifyError::Io)?;
        if !metadata.file_type().is_file() || reparse_point(&metadata) {
            return Err(non_regular());
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(VerifyError::Io)?;
        if reparse_point(&file.metadata().map_err(VerifyError::Io)?) {
            return Err(non_regular());
        }
        file
    };
    #[cfg(not(any(unix, windows)))]
    let file = {
        if !fs::symlink_metadata(path)
            .map_err(VerifyError::Io)?
            .file_type()
            .is_file()
        {
            return Err(non_regular());
        }
        File::open(path).map_err(VerifyError::Io)?
    };
    if !file.metadata().map_err(VerifyError::Io)?.is_file() {
        return Err(non_regular());
    }
    Ok(file)
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

fn basename_lossy(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("<non-utf8>")
        .to_owned()
}

fn parse_audit_timestamp_ms(ts: &str) -> Result<u64, String> {
    if ts.len() != 24
        || ts.as_bytes().get(4) != Some(&b'-')
        || ts.as_bytes().get(7) != Some(&b'-')
        || ts.as_bytes().get(10) != Some(&b'T')
        || ts.as_bytes().get(13) != Some(&b':')
        || ts.as_bytes().get(16) != Some(&b':')
        || ts.as_bytes().get(19) != Some(&b'.')
        || ts.as_bytes().get(23) != Some(&b'Z')
    {
        return Err("timestamp must match YYYY-MM-DDTHH:MM:SS.mmmZ".to_owned());
    }

    let year = parse_decimal_u32(ts, 0, 4, "year")?;
    let month = parse_decimal_u32(ts, 5, 7, "month")?;
    let day = parse_decimal_u32(ts, 8, 10, "day")?;
    let hour = parse_decimal_u32(ts, 11, 13, "hour")?;
    let minute = parse_decimal_u32(ts, 14, 16, "minute")?;
    let second = parse_decimal_u32(ts, 17, 19, "second")?;
    let millis = parse_decimal_u32(ts, 20, 23, "millisecond")?;

    if !(1970..=2099).contains(&year)
        || !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 59
        || millis > 999
    {
        return Err("timestamp component out of supported range".to_owned());
    }
    let month_days = days_in_month(year, month);
    if day == 0 || day > month_days {
        return Err("timestamp day out of range for month".to_owned());
    }

    let mut days = 0u64;
    for y in 1970..year {
        days += u64::from(if is_leap_year_u32(y) { 366u32 } else { 365u32 });
    }
    for m in 1..month {
        days += u64::from(days_in_month(year, m));
    }
    days += u64::from(day - 1);

    let seconds =
        days * 86_400 + u64::from(hour) * 3_600 + u64::from(minute) * 60 + u64::from(second);
    Ok(seconds * 1_000 + u64::from(millis))
}

fn parse_decimal_u32(ts: &str, start: usize, end: usize, field: &str) -> Result<u32, String> {
    let s = &ts[start..end];
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("timestamp {field} contains non-decimal digits"));
    }
    s.parse::<u32>()
        .map_err(|_| format!("timestamp {field} is out of range"))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year_u32(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year_u32(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn sanitize_handoff_next_file_name(active_stem: &str, next_file_name: &str) -> String {
    if is_rotated_sibling(active_stem, next_file_name) {
        next_file_name.to_owned()
    } else {
        format!("<invalid: {} bytes>", next_file_name.len())
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Discriminant for the detected partial-rotation intermediate state.
///
/// Produced by [`crate::audit_log::writer::AuditWriter::open`] when the audit-log directory contains
/// evidence of a crash mid-rotation.  Carried inside
/// [`VerifyError::PartialRotation`] (aliased as
/// [`crate::audit_log::AuditLogIntegrityError::PartialRotation`]).
///
/// The writer surfaces this as an error and requires operator intervention;
/// it does NOT auto-recover.  Silent recovery could mask a tamper attempt
/// that manufactured the same directory state.
///
/// # Recovery
///
/// The writer surfaces this as an error and requires operator intervention;
/// it does NOT auto-recover.  Silent recovery could mask a tamper attempt.
/// See the audit-log recovery runbook for per-variant guidance.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PartialRotationState {
    /// A `.root_hmac` sidecar for a rotated archive exists on disk but the
    /// corresponding rotated log file does not.
    ///
    /// Possible cause: the HMAC sidecar rename completed but the log file
    /// rename did not complete before the process crashed or was killed.
    ///
    /// Recovery: see the audit-log recovery runbook, orphan-sidecar section.
    ///
    /// Display emits only the file basename to avoid leaking full filesystem
    /// paths into operator-visible messages.
    /// Full paths are retained in the structured fields for programmatic recovery.
    #[error(
        "orphan sidecar: {} exists without matching log file {}",
        basename_lossy(sidecar_path),
        basename_lossy(expected_log_path)
    )]
    OrphanSidecar {
        /// Path to the orphaned `.root_hmac` sidecar file.
        sidecar_path: std::path::PathBuf,
        /// Log file path that the sidecar was expected to accompany.
        expected_log_path: std::path::PathBuf,
    },

    /// A temporary file (`.tmp` suffix) was found in the audit-log directory.
    ///
    /// Possible cause: an atomic-write pattern using a `.tmp` file was
    /// interrupted before the final rename.  Any `.tmp` file in the audit
    /// directory is unexpected in steady state and indicates a partial
    /// operation left behind on crash.
    ///
    /// Recovery: see the audit-log recovery runbook, mid-rename section.
    ///
    /// Display emits only the file basename to avoid leaking full filesystem
    /// paths into operator-visible messages.
    /// Full paths are retained in the structured fields for programmatic recovery.
    #[error(
        "mid-rename tmp file: {} (size {size_bytes} bytes)",
        basename_lossy(tmp_path)
    )]
    MidRename {
        /// Path to the unexpected `.tmp` file.
        tmp_path: std::path::PathBuf,
        /// Observed size of the `.tmp` file in bytes.
        size_bytes: u64,
    },

    /// The active log file's last entry could not be parsed as valid JSON.
    ///
    /// Possible cause: the process was killed after writing a partial entry
    /// byte sequence to the log file (before `fsync` completed).  The log
    /// file contains at least one complete prior entry, so the chain up to
    /// the truncation point may be intact.
    ///
    /// Recovery: see the audit-log recovery runbook, partial-handoff section.
    ///
    /// Display emits only the file basename to avoid leaking full filesystem
    /// paths into operator-visible messages.
    /// Full paths are retained in the structured fields for programmatic recovery.
    #[error(
        "partial handoff write: last entry in {} is unparseable \
         (file size {file_size_bytes} bytes, partial entry starts at byte {partial_entry_offset})",
        basename_lossy(log_path)
    )]
    PartialHandoffWrite {
        /// Path to the active log file containing the truncated entry.
        log_path: std::path::PathBuf,
        /// Total file size at detection time.
        file_size_bytes: u64,
        /// Byte offset where the last (truncated) line begins.
        partial_entry_offset: u64,
    },
}

/// Errors returned by [`verify_log`].
///
/// Each variant maps to a closed-set typed wire code.  Line numbers and file
/// basenames are in the `detail` field of the error envelope, not embedded in
/// the wire code itself, keeping wire-code cardinality bounded.
///
/// All integrity violations (`ChainBroken`, `RotationGap`, `HmacMismatch`,
/// `HmacSidecarMissing`) indicate that the tamper-evidence substrate itself
/// has been compromised, not an auth-flow error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The hash chain is broken at the given line.
    ///
    /// Wire code: `audit.chain_broken`.  Detail: line number + file basename.
    #[error("audit.chain_broken: {reason} at line {line} in {file}")]
    ChainBroken {
        /// Line number where the chain break was detected.
        line: usize,
        /// Basename of the file containing the broken chain.
        file: String,
        /// Stable diagnostic reason for the chain break.
        reason: &'static str,
    },

    /// A rotated file is missing or the rotation handoff is invalid.
    ///
    /// Wire code: `audit.rotation_gap`.  Detail: file basename or description.
    #[error("audit.rotation_gap: {file}")]
    RotationGap {
        /// File basename or description of the gap.
        file: String,
    },

    /// A chain-root or prune-marker HMAC tag did not verify.
    ///
    /// Wire code: `audit.hmac_mismatch`.  Detail: file basename.
    #[error("audit.hmac_mismatch: chain-root HMAC verification failed for {file}")]
    HmacMismatch {
        /// Basename of the file whose HMAC did not verify.
        file: String,
    },

    /// An HMAC key was provided but the sidecar file is missing.
    ///
    /// Wire code: `audit.hmac_sidecar_missing`.  Detail: file basename.
    ///
    /// This is an integrity violation: if a key is configured, a sidecar
    /// MUST exist for every file in the chain.
    #[error("audit.hmac_sidecar_missing: .root_hmac sidecar missing for {file}")]
    HmacSidecarMissing {
        /// Basename of the file whose sidecar is absent.
        file: String,
    },

    /// More rotated files were found than [`MAX_ROTATED_FILES`] retention plus
    /// a bounded grace window allows; likely a DoS or directory-pollution
    /// scenario.
    ///
    /// Wire code: `audit.too_many_rotated_files`.  Detail: found count + cap.
    #[error("audit.too_many_rotated_files: found {found} rotated files, cap {cap}")]
    TooManyRotatedFiles {
        /// Number of rotated sibling files observed before verification stopped.
        found: usize,
        /// Maximum allowed rotated sibling count.
        cap: usize,
    },

    /// The supplied log path or HMAC sidecar path is not a regular file.
    ///
    /// Rejecting directories and symlinks before open closes the symlink-redirect
    /// attack surface where `audit verify` could be pointed at an arbitrary file.
    /// Display emits the basename only to avoid leaking full filesystem paths.
    #[error("audit.non_regular_file_log_path: {}", basename_lossy(path))]
    NonRegularFileLogPath {
        /// Rejected path. Display uses only the basename.
        path: PathBuf,
    },

    /// A JSON line could not be parsed.
    ///
    /// Wire code: `audit.parse_error`.  Detail: line number + description.
    #[error("audit.parse_error: line {line}: {detail}")]
    ParseError {
        /// Line number where the parse error occurred.
        line: usize,
        /// Human-readable parse error description.
        detail: String,
    },

    /// The supplied log path violates a structural contract.
    ///
    /// Wire code: `audit.path_contract`.  This variant is deliberately
    /// separate from [`VerifyError::Io`] so agents and operators can
    /// distinguish deterministic path-shape rejection (such as a log path with
    /// no UTF-8 file name) from ambient filesystem failures, while preserving
    /// the closed-set wire-code model.
    #[error("audit.path_contract: {detail}")]
    PathContract {
        /// Human-readable structural path failure.
        detail: String,
    },

    /// The primary (oldest / only) audit-log file does not exist.
    ///
    /// Distinct from [`VerifyError::Io`]: a missing primary log is not an
    /// ambient I/O failure but a user-actionable condition — either nothing has
    /// been written to the audit log yet, or the supplied path is wrong. The
    /// dedicated variant lets callers classify it as validation-class rather
    /// than an internal invariant violation.
    ///
    /// Wire code: `audit.log_not_found`.
    #[error("audit.log_not_found: audit log not found at {path}")]
    LogNotFound {
        /// Display path of the missing primary audit-log file.
        path: String,
    },

    /// An I/O error occurred while reading the log.
    ///
    /// Wire code: `audit.io_error`.
    #[error("audit.io_error: {0}")]
    Io(#[from] std::io::Error),

    /// Malformed canonical-body computation on signer-set state.
    ///
    /// Wraps a [`super::signer_set::SignerSetCanonicalBodyError`] from the
    /// signer-set primitive (`compute_signer_set_digest` / `canonical_scaddress`).
    ///
    /// Distinct from [`VerifyError::ParseError`], which signals JSON decode
    /// failure on an audit-log file row.  This variant signals malformed
    /// canonical-body computation on signer-set state that can fire from a code
    /// path with no associated audit-log line number.  Using a dedicated variant
    /// rather than routing through `ParseError { line: 0, ... }` prevents the
    /// two integrity classes from being indistinguishable in wire logs.
    ///
    /// Wire code: `audit.signer_set_canonical_body`.
    #[error("audit.signer_set_canonical_body: {0}")]
    SignerSetCanonicalBody(#[from] super::signer_set::SignerSetCanonicalBodyError),

    /// A partial-rotation intermediate state was detected when opening the
    /// audit-log writer.
    ///
    /// The writer detected that the audit-log directory contains evidence of a
    /// process crash mid-rotation.  The specific cause is encoded in
    /// [`PartialRotationState`].
    ///
    /// No auto-recovery is performed.  Silent recovery could mask a tamper
    /// attempt that manufactured the same directory state.  The operator must
    /// inspect the audit-log directory and follow the audit-log recovery runbook
    /// before re-opening the writer.
    ///
    /// Wire code: `audit.partial_rotation`.
    ///
    /// # Producers
    ///
    /// This variant is produced by two distinct code paths:
    ///
    /// 1. [`crate::audit_log::writer::AuditWriter::open`] — detects the state
    ///    at writer-open time via `detect_partial_rotation` and returns
    ///    [`crate::audit_log::writer::WriterError::IntegrityViolation`] wrapping
    ///    this variant.
    ///
    /// 2. [`verify_log`] — detects the same state when verifying an audit log
    ///    from a writer interrupted mid-rotation.
    ///
    /// Callers that match on `VerifyError::PartialRotation` receive the same
    /// typed state regardless of which path produced it; the `recovery_hint`
    /// field always points to the same runbook section.
    #[error(
        "audit.partial_rotation: {state}; \
         recovery runbook: docs/maintainers/audit-log-recovery.md"
    )]
    PartialRotation {
        /// Detected partial-rotation state with associated file metadata.
        state: PartialRotationState,
        /// Human-readable hint pointing to the recovery runbook.
        recovery_hint: String,
    },

    /// The active log file's chain tip is not the one the keyring-held anchor
    /// names.
    ///
    /// The chain walk itself succeeded: linkage, per-entry hashes, and the
    /// chain-root signatures are all intact. They verify a PREFIX, so an older
    /// copy of the active file, or a truncated one, passes them. The anchor is
    /// what pins the END of the chain, and it does not agree with the file.
    ///
    /// Counts and offsets only: no digest appears in the message.
    ///
    /// Wire code: `audit.tip_anchor_mismatch`. Recovery:
    /// `stellar-agent audit reanchor --profile <name> --acknowledge-rollback`
    /// after establishing why the file changed. See
    /// `docs/maintainers/audit-log-recovery.md`.
    #[error(
        "audit.tip_anchor_mismatch: {reason}; anchored at {expected_count} entries / \
         {expected_offset} bytes, file holds {actual_count} entries / {actual_offset} bytes"
    )]
    TipAnchorMismatch {
        /// Entry count the anchor names for the active file.
        expected_count: u64,
        /// Byte offset the anchor names for the active file.
        expected_offset: u64,
        /// Entry count the walk found in the active file.
        actual_count: u64,
        /// Byte offset the walk found for the active file's last entry.
        actual_offset: u64,
        /// Stable diagnostic for which half of the check failed.
        reason: &'static str,
    },

    /// No anchor is stored for the log path, and the log shows one was.
    ///
    /// The chain walk succeeded, and it verifies a prefix only. The evidence
    /// is a fact that outlives the anchor: an audit binding recorded for the
    /// profile, a chain-root sidecar on the active file, or an
    /// `audit_tip_anchored` row in it. A log with its anchor deleted and its
    /// tail truncated would otherwise verify as a log that was never anchored.
    ///
    /// Counts and offsets only: no digest appears in the message.
    ///
    /// Wire code: `audit.tip_anchor_missing`. Recovery:
    /// `stellar-agent audit reanchor --profile <name> --acknowledge-rollback`
    /// after establishing why the anchor is gone. See
    /// `docs/maintainers/audit-log-recovery.md`.
    #[error(
        "audit.tip_anchor_missing: anchor: missing; no tip anchor is stored for this log path, \
         although {evidence}; file holds {actual_count} entries / {actual_offset} bytes"
    )]
    TipAnchorMissing {
        /// What shows the log was anchored before.
        evidence: PriorAnchoring,
        /// Entry count the walk found in the active file.
        actual_count: u64,
        /// Byte offset the walk found for the active file's last entry.
        actual_offset: u64,
    },

    /// Entry tags are in force and an entry carries no valid tag while no
    /// valid keyed start or quarantine row after it covers it.
    ///
    /// Without the audit key, anyone who can write the log can append an
    /// entry that chains correctly; the tag is what such an entry lacks. The
    /// reason is `missing` or `mismatch`, and the message carries no digest.
    ///
    /// Wire code: `audit.entry_tag_invalid`. Recovery:
    /// `stellar-agent audit reanchor --profile <name>
    /// --acknowledge-unauthenticated-tail` after establishing where the
    /// entries came from. See `docs/maintainers/audit-log-recovery.md`.
    #[error("audit.entry_tag_invalid: entry tag {reason} at line {line} in {file}")]
    EntryTagInvalid {
        /// Basename of the file holding the entry.
        file: String,
        /// One-based line of the entry.
        line: usize,
        /// `missing` or `mismatch`.
        reason: &'static str,
    },
}

impl VerifyError {
    /// Returns the closed-set wire code for this error.
    ///
    /// Used by the CLI to emit a structured JSON error envelope.
    #[must_use]
    pub fn wire_code(&self) -> &'static str {
        match self {
            Self::ChainBroken { .. } => "audit.chain_broken",
            Self::RotationGap { .. } => "audit.rotation_gap",
            Self::HmacMismatch { .. } => "audit.hmac_mismatch",
            Self::HmacSidecarMissing { .. } => "audit.hmac_sidecar_missing",
            Self::TooManyRotatedFiles { .. } => "audit.too_many_rotated_files",
            Self::NonRegularFileLogPath { .. } => "audit.non_regular_file_log_path",
            Self::ParseError { .. } => "audit.parse_error",
            Self::PathContract { .. } => "audit.path_contract",
            Self::LogNotFound { .. } => "audit.log_not_found",
            Self::Io(_) => "audit.io_error",
            Self::SignerSetCanonicalBody(_) => "audit.signer_set_canonical_body",
            Self::PartialRotation { .. } => "audit.partial_rotation",
            Self::TipAnchorMismatch { .. } => "audit.tip_anchor_mismatch",
            Self::TipAnchorMissing { .. } => "audit.tip_anchor_missing",
            Self::EntryTagInvalid { .. } => "audit.entry_tag_invalid",
        }
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
    use crate::audit_log::{
        entry::{AuditEntry, IntoOptionalChainId, NewToolInvocation},
        schema::{
            ContractKind, EVENT_KIND_VARIANT_COUNT, KeyPurpose, PinsUpdateReason, PolicyDecision,
            TipAnchorReason, ValueActionKind, ValueLegRecord, VerifierAdvisoryKind, WasmHashPin,
        },
        writer::{
            AuditWriter, ROTATION_THRESHOLD_BYTES, ROTATION_WINDOW_RETRY_ATTEMPTS,
            install_rotation_window_retry_observer,
        },
    };
    use crate::observability::RedactedStrkey;
    use std::cell::RefCell;
    use std::fs;
    use std::rc::Rc;
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    fn verify_event_kind_explicit_arm_for_test(event_kind: &EventKind) -> &'static str {
        match event_kind {
            EventKind::MainnetEnablementMinted { .. } => "mainnet_enablement_minted",
            EventKind::ToolInvocation => "tool_invocation",
            EventKind::PluginInvoked { .. } => "plugin_invoked",
            EventKind::WalletMlockFailed { .. } => "wallet_mlock_failed",
            EventKind::SaRawInvocation { .. } => "sa_raw_invocation",
            EventKind::SmartAccountDeployed { .. } => "smart_account_deployed",
            EventKind::SaContextRuleCreated { .. } => "sa_context_rule_created",
            EventKind::SaContextRulePinsUpdated { .. } => "sa_context_rule_pins_updated",
            EventKind::SaContextRuleCreatedV2 { .. } => "sa_context_rule_created_v2",
            EventKind::SaContextRulePinsUpdatedV2 { .. } => "sa_context_rule_pins_updated_v2",
            EventKind::SaContextRuleDeleted { .. } => "sa_context_rule_deleted",
            EventKind::PasskeyRegistered { .. } => "passkey_registered",
            EventKind::PasskeyAssertion { .. } => "passkey_assertion",
            EventKind::SaSignerAdded { .. } => "sa_signer_added",
            EventKind::SaSignerRemoved { .. } => "sa_signer_removed",
            EventKind::SaThresholdChanged { .. } => "sa_threshold_changed",
            EventKind::SaSignerSetDiverged { .. } => "sa_signer_set_diverged",
            EventKind::SaSignerSetBaselined { .. } => "sa_signer_set_baselined",
            EventKind::SaSignerSetBaselinedV2 { .. } => "sa_signer_set_baselined_v2",
            EventKind::SaSignerAddedV2 { .. } => "sa_signer_added_v2",
            EventKind::SaSignerRemovedV2 { .. } => "sa_signer_removed_v2",
            EventKind::SaThresholdChangedV2 { .. } => "sa_threshold_changed_v2",
            EventKind::SaVerifierHashDrift { .. } => "sa_verifier_hash_drift",
            EventKind::SaPolicyHashDrift { .. } => "sa_policy_hash_drift",
            EventKind::SaMutableContractOverride { .. } => "sa_mutable_contract_override",
            EventKind::SaUnknownContractOverride { .. } => "sa_unknown_contract_override",
            EventKind::AuditRotationHandoff { .. } => "audit_rotation_handoff",
            EventKind::SaVerifierMigrated { .. } => "sa_verifier_migrated",
            EventKind::SaVerifierDiversificationOverride { .. } => {
                "sa_verifier_diversification_override"
            }
            EventKind::SaVerifierAllowlistAdvisory { .. } => "sa_verifier_allowlist_advisory",
            EventKind::SaPolicyAdded { .. } => "sa_policy_added",
            EventKind::SaPolicyRemoved { .. } => "sa_policy_removed",
            EventKind::SaSpendingLimitRetuned { .. } => "sa_spending_limit_retuned",
            EventKind::SaWeightedThresholdChanged { .. } => "sa_weighted_threshold_changed",
            EventKind::SaSignerWeightChanged { .. } => "sa_signer_weight_changed",
            EventKind::SaMulticallBundleSubmitted { .. } => "sa_multicall_bundle_submitted",
            EventKind::SaMulticallInnerExecuted { .. } => "sa_multicall_inner_executed",
            EventKind::SaMulticallBundleDenied { .. } => "sa_multicall_bundle_denied",
            EventKind::SaMulticallRegistered { .. } => "sa_multicall_registered",
            EventKind::SaMulticallRegistrationRefused { .. } => "sa_multicall_registration_refused",
            EventKind::SaMulticallUnregistered { .. } => "sa_multicall_unregistered",
            EventKind::SaMulticallUnregisteredForce { .. } => "sa_multicall_unregistered_force",
            EventKind::SaTimelockScheduled { .. } => "sa_timelock_scheduled",
            EventKind::SaTimelockCancelled { .. } => "sa_timelock_cancelled",
            EventKind::SaTimelockExecuted { .. } => "sa_timelock_executed",
            EventKind::SaTimelockDivergencePostSubmit { .. } => {
                "sa_timelock_divergence_post_submit"
            }
            EventKind::SaExternalExecuteSubmitted { .. } => "sa_external_execute_submitted",
            EventKind::SaContextRuleNameUpdated { .. } => "sa_context_rule_name_updated",
            EventKind::SaContextRuleValidUntilUpdated { .. } => {
                "sa_context_rule_valid_until_updated"
            }
            EventKind::ChannelPoolInitialised { .. } => "channel_pool_initialised",
            EventKind::ChannelAcquired { .. } => "channel_acquired",
            EventKind::ChannelReleased { .. } => "channel_released",
            EventKind::SubmissionAuthMismatch { .. } => "submission_auth_mismatch",
            EventKind::ApprovalAttested { .. } => "approval_attested",
            EventKind::ApprovalRejected { .. } => "approval_rejected",
            EventKind::ApprovalAttestedRemote { .. } => "approval_attested_remote",
            EventKind::ApprovalRejectedRemote { .. } => "approval_rejected_remote",
            EventKind::ValueActionSubmitted { .. } => "value_action_submitted",
            EventKind::ValueActionPending { .. } => "value_action_pending",
            EventKind::ValueActionFailed { .. } => "value_action_failed",
            EventKind::SubmissionReceiptCleared { .. } => "submission_receipt_cleared",
            EventKind::X402PaymentAuthorized { .. } => "x402_payment_authorized",
            EventKind::X402AuthorizationWithheld { .. } => "x402_authorization_withheld",
            EventKind::OpaquePayloadSigned { .. } => "opaque_payload_signed",
            EventKind::MppChargeAuthorized { .. } => "mpp_charge_authorized",
            EventKind::MppAuthorizationWithheld { .. } => "mpp_authorization_withheld",
            EventKind::MppReceiptObserved { .. } => "mpp_receipt_observed",
            EventKind::MppSettlementReconciled { .. } => "mpp_settlement_reconciled",
            EventKind::KeyringKeyWritten { .. } => "keyring_key_written",
            EventKind::SignerIdentityEnrolled { .. } => "signer_identity_enrolled",
            EventKind::PolicyWindowStateReset { .. } => "policy_window_state_reset",
            EventKind::MppStateAdopted { .. } => "mpp_state_adopted",
            EventKind::MppStateReset { .. } => "mpp_state_reset",
            EventKind::AuditTipAnchored { .. } => "audit_tip_anchored",
            EventKind::AuditOutboxLossAcknowledged { .. } => "audit_outbox_loss_acknowledged",
            EventKind::AuditEntryTagsStarted { .. } => "audit_entry_tags_started",
            EventKind::AuditEntryTagsRekeyed { .. } => "audit_entry_tags_rekeyed",
            EventKind::AuditEntriesQuarantined { .. } => "audit_entries_quarantined",
        }
    }

    fn v2_snapshot_fixture() -> crate::audit_log::signer_set::SignerSetSnapshotV2 {
        use crate::audit_log::signer_set::{
            SignerEntryV2, SignerIdentityV2, SignerSetSnapshotV2, ThresholdObservation,
        };
        SignerSetSnapshotV2 {
            signers: vec![SignerEntryV2 {
                id: 0,
                identity: SignerIdentityV2::Ed25519 { pubkey: [0u8; 32] },
            }],
            threshold: Some(ThresholdObservation {
                policy: [0x22u8; 32],
                threshold: 1,
            }),
        }
    }

    fn current_event_kind_fixtures() -> Vec<EventKind> {
        vec![
            EventKind::ToolInvocation,
            EventKind::PluginInvoked {
                plugin_name: "plugin".to_owned(),
                exit_code: 0,
                decision: PolicyDecision::Allow,
                duration_ms: 1,
            },
            EventKind::WalletMlockFailed {
                profile: "default".to_owned(),
                reason: "mlock unavailable".to_owned(),
                errno: None,
            },
            EventKind::SaRawInvocation {
                smart_account: "CDABC...12345".to_owned(),
                wire_code: "sa.ok".to_owned(),
                auth_digest_prefix: Some("12345678".to_owned()),
                context_rule_ids_count: 0,
                result: crate::audit_log::schema::SaInvocationResult::Success,
            },
            EventKind::SmartAccountDeployed {
                smart_account: "CDABC...12345".to_owned(),
                deployer: "GDABC...12345".to_owned(),
                wasm_hash_prefix: "12345678...90abcdef".to_owned(),
                wasm_uploaded: false,
                tx_hash_redacted: "abcdef12...34567890".to_owned(),
                ledger: 1,
            },
            EventKind::SaContextRuleCreated {
                smart_account: "CDABC...12345".to_owned(),
                rule_id: 1,
                context_type: "default".to_owned(),
                signers_count: 1,
                policies_count: 1,
                valid_until: None,
                pinned_verifier_wasm_hashes_first8: vec![],
                pinned_policy_wasm_hashes_first8: vec![],
                mutable_override: false,
                unknown_override: false,
                pinned_verifier_executable_refs: vec![],
                pinned_policy_executable_refs: vec![],
            },
            EventKind::SaContextRulePinsUpdated {
                smart_account: "CDABC...12345".to_owned(),
                rule_id: 1,
                pinned_verifier_wasm_hashes_first8: vec!["aabbccdd00112233".to_owned()],
                pinned_policy_wasm_hashes_first8: vec![],
                mutable_override: false,
                unknown_override: false,
                pinned_verifier_executable_refs: vec![],
                pinned_policy_executable_refs: vec![],
                reason: PinsUpdateReason::SignerAdded,
            },
            EventKind::SaContextRuleCreatedV2 {
                smart_account: "CDABC...12345".to_owned(),
                rule_id: 1,
                context_type: "default".to_owned(),
                signers_count: 1,
                policies_count: 1,
                valid_until: None,
                pinned_verifier_wasm_hashes: vec![WasmHashPin::new([0xaa; 32])],
                pinned_policy_wasm_hashes: vec![],
                mutable_override: false,
                unknown_override: false,
                pinned_verifier_executable_refs: vec![],
                pinned_policy_executable_refs: vec![],
            },
            EventKind::SaContextRulePinsUpdatedV2 {
                smart_account: "CDABC...12345".to_owned(),
                rule_id: 1,
                pinned_verifier_wasm_hashes: vec![WasmHashPin::new([0xaa; 32])],
                pinned_policy_wasm_hashes: vec![],
                mutable_override: false,
                unknown_override: false,
                pinned_verifier_executable_refs: vec![],
                pinned_policy_executable_refs: vec![],
                reason: PinsUpdateReason::SignerAdded,
            },
            EventKind::SaContextRuleDeleted {
                smart_account: "CDABC...12345".to_owned(),
                rule_id: 1,
            },
            EventKind::PasskeyRegistered {
                credential_name: "test-passkey".to_owned(),
                credential_id_redacted: "AABBC...IJJKK".to_owned(),
                rp_id: "127.0.0.1".to_owned(),
                status: "registered".to_owned(),
            },
            EventKind::PasskeyAssertion {
                credential_name: "test-passkey".to_owned(),
                credential_id_redacted: "AABBC...IJJKK".to_owned(),
                rp_id: "localhost".to_owned(),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDEPL...MNO56"),
                auth_digest_redacted: "abcde...vwxyz".to_owned(),
                signed_at_unix_ms: 1_747_000_000_000,
                result: "success".to_owned(),
            },
            EventKind::SaSignerAdded {
                rule_id: 1,
                signer_id: 0,
                resulting_signer_count: 1,
                resulting_threshold: 1,
                resulting_signer_ids: vec![0],
                resulting_signer_pubkeys: vec![
                    crate::audit_log::signer_set::SignerPubkey::Ed25519 { pubkey: [0u8; 32] },
                ],
                resulting_signer_pubkeys_first8: vec!["00000000".to_owned()],
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            },
            EventKind::SaSignerRemoved {
                rule_id: 1,
                signer_id: 0,
                resulting_signer_count: 0,
                resulting_threshold: 0,
                resulting_signer_ids: vec![],
                resulting_signer_pubkeys: vec![],
                resulting_signer_pubkeys_first8: vec![],
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            },
            EventKind::SaThresholdChanged {
                rule_id: 1,
                old_threshold: 1,
                new_threshold: 2,
                resulting_threshold: 2,
                resulting_signer_count: 2,
                resulting_signer_ids: vec![0, 1],
                resulting_signer_pubkeys: vec![
                    crate::audit_log::signer_set::SignerPubkey::Ed25519 { pubkey: [0u8; 32] },
                    crate::audit_log::signer_set::SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
                ],
                resulting_signer_pubkeys_first8: vec!["00000000".to_owned(), "01010101".to_owned()],
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            },
            EventKind::SaSignerSetDiverged {
                rule_id: 1,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                expected_signer_count: 2,
                observed_signer_count: 1,
                expected_threshold: Some(2),
                observed_threshold: Some(2),
                expected_signer_set_digest: "abcdef12...34567890".to_owned(),
                observed_signer_set_digest: "12345678...abcdef90".to_owned(),
                snapshot_version: None,
            },
            EventKind::SaSignerSetBaselined {
                rule_id: 1,
                observed_signer_count: 1,
                observed_threshold: 1,
                observed_signer_ids: vec![0],
                observed_signer_pubkeys: vec![
                    crate::audit_log::signer_set::SignerPubkey::Ed25519 { pubkey: [0u8; 32] },
                ],
                observed_signer_pubkeys_first8: vec!["00000000".to_owned()],
                observed_at_ledger_seq: 1_000,
                observed_at_unix_ms: 1_700_000_000_000,
                baseline_reason: crate::audit_log::signer_set::BaselineReason::FirstObservation,
                prev_chain_tip_hash: [0u8; 32],
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            },
            EventKind::SaSignerSetBaselinedV2 {
                rule_id: 1,
                snapshot: v2_snapshot_fixture(),
                observed_at_ledger_seq: 1_000,
                observed_at_unix_ms: 1_700_000_000_000,
                baseline_reason: crate::audit_log::signer_set::BaselineReason::ConfirmedInstall,
                prev_chain_tip_hash: [0u8; 32],
                account_digest: [0x11u8; 32],
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            },
            EventKind::SaSignerAddedV2 {
                rule_id: 1,
                signer_id: 1,
                snapshot: v2_snapshot_fixture(),
                account_digest: [0x11u8; 32],
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            },
            EventKind::SaSignerRemovedV2 {
                rule_id: 1,
                signer_id: 2,
                snapshot: v2_snapshot_fixture(),
                account_digest: [0x11u8; 32],
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            },
            EventKind::SaThresholdChangedV2 {
                rule_id: 1,
                previous_threshold: None,
                snapshot: v2_snapshot_fixture(),
                account_digest: [0x11u8; 32],
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            },
            EventKind::SaVerifierHashDrift {
                rule_id: 1,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                deploy_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...67890"),
                pinned_hash_first8: "aabbccdd".to_owned(),
                observed_hash_first8: "11223344".to_owned(),
                observed_executable: None,
            },
            EventKind::SaPolicyHashDrift {
                rule_id: 2,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                deploy_address_redacted: RedactedStrkey::from_already_redacted("CCCCC...99999"),
                pinned_hash_first8: "eeff0011".to_owned(),
                observed_hash_first8: "22334455".to_owned(),
                observed_executable: None,
            },
            EventKind::SaMutableContractOverride {
                rule_id: Some(3),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                contract_address_redacted: RedactedStrkey::from_already_redacted("CDABC...99999"),
                contract_kind: ContractKind::Verifier,
                override_acknowledged_at: "2026-05-19T10:00:00Z".to_owned(),
                executable_owner_redacted: None,
                executable_tag: None,
            },
            EventKind::SaUnknownContractOverride {
                rule_id: Some(4),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                contract_address_redacted: RedactedStrkey::from_already_redacted("CEEEE...88888"),
                contract_kind: ContractKind::Policy,
                override_acknowledged_at: "2026-05-19T11:00:00Z".to_owned(),
                observed_hash_first8: "aabbccdd".to_owned(),
            },
            EventKind::AuditRotationHandoff {
                next_file_name: "audit.jsonl.20260428T010203004".to_owned(),
                entry_tags: false,
            },
            EventKind::SaVerifierMigrated {
                rule_id: 5,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                from_hash_first8: "deadbeef".to_owned(),
                to_hash_first8: "cafebabe".to_owned(),
                tx_hash_redacted: "aabb1122...ccdd3344".to_owned(),
            },
            EventKind::SaVerifierDiversificationOverride {
                rule_id: 6,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                verifier_hash_first8: "11223344".to_owned(),
                observed_value_threshold_stroops: 100_000_000_000,
                override_acknowledged_at: "2026-05-20T12:34:56.000Z".to_owned(),
            },
            EventKind::SaVerifierAllowlistAdvisory {
                rule_id: 7,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                revoked_hash_first8: "aabbccdd".to_owned(),
                advised_status: VerifierAdvisoryKind::Revoked,
            },
            EventKind::SaPolicyAdded {
                rule_id: 8,
                policy_id: 1,
                policy_address_redacted: RedactedStrkey::from_already_redacted("CPOLI...YYYYY"),
                transaction_hash_redacted: "aabb1122...ccdd3344".to_owned(),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            },
            EventKind::SaPolicyRemoved {
                rule_id: 9,
                policy_id: 0,
                transaction_hash_redacted: "aabb1122...ccdd3344".to_owned(),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            },
            EventKind::SaSpendingLimitRetuned {
                rule_id: 11,
                old_limit: 10_000_000,
                new_limit: 20_000_000,
                period_ledgers: 17_280,
                policy_address_redacted: RedactedStrkey::from_already_redacted("CPOLI...YYYYY"),
                transaction_hash_redacted: "aabb1122...ccdd3344".to_owned(),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            },
            EventKind::SaWeightedThresholdChanged {
                rule_id: 12,
                old_threshold: 1,
                new_threshold: 2,
                policy_address_redacted: RedactedStrkey::from_already_redacted("CPOLI...YYYYY"),
                transaction_hash_redacted: "aabb1122...ccdd3344".to_owned(),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            },
            EventKind::SaSignerWeightChanged {
                rule_id: 13,
                signer_identity_redacted: "delegated:GAAAA...BBBBB".to_owned(),
                old_weight: 1,
                new_weight: 2,
                policy_address_redacted: RedactedStrkey::from_already_redacted("CPOLI...YYYYY"),
                transaction_hash_redacted: "aabb1122...ccdd3344".to_owned(),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            },
            EventKind::SaMulticallBundleSubmitted {
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                rule_id: 10,
                bundle_tx_hash_redacted: "aabbccdd...11223344".to_owned(),
                inner_count: 3,
            },
            EventKind::SaMulticallInnerExecuted {
                bundle_tx_hash_redacted: "aabbccdd...11223344".to_owned(),
                inner_index: 0,
                target_contract_redacted: RedactedStrkey::from_already_redacted("CSAC1...ZZZZ1"),
                fn_name: "transfer".to_owned(),
                return_scval_b64_prefix: None,
            },
            EventKind::SaMulticallBundleDenied {
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                rule_id: 10,
                inner_count: 3,
                denied_inner_index: Some(1),
                observed_inner_count: None,
                deny_wire_code: "multicall.policy_gate".to_owned(),
                refusal_phase: "policy_gate".to_owned(),
                bundle_tx_hash_redacted: None,
            },
            EventKind::SaMulticallRegistered {
                network_safename: "test-sdf-network---september-2015".to_owned(),
                address_redacted: RedactedStrkey::from_already_redacted("CMCAL...ROUTE"),
                wasm_sha256: "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4"
                    .to_owned(),
            },
            EventKind::SaMulticallRegistrationRefused {
                network_safename: "test-sdf-network---september-2015".to_owned(),
                address_redacted: RedactedStrkey::from_already_redacted("CMCAL...ROUTE"),
                attempted_wasm_sha256:
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                existing_wasm_sha256: None,
                refusal_reason: "sha256_mismatch".to_owned(),
            },
            EventKind::SaMulticallUnregistered {
                network_safename: "test-sdf-network---september-2015".to_owned(),
                prior_address_redacted: RedactedStrkey::from_already_redacted("CMCAL...ROUTE"),
                prior_wasm_sha256:
                    "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4".to_owned(),
            },
            EventKind::SaMulticallUnregisteredForce {
                network_safename: "test-sdf-network---september-2015".to_owned(),
                prior_address_raw: "INVALID_ADDRESS".to_owned(),
                prior_address_raw_truncated: false,
                prior_wasm_sha256_raw: "not-hex".to_owned(),
                prior_wasm_sha256_raw_truncated: false,
                load_warnings: vec!["invalid C-strkey address: INVALID_ADDRESS".to_owned()],
                load_warnings_truncated: false,
            },
            EventKind::SaTimelockScheduled {
                operation_id_redacted: "abcdef12...34567890".to_owned(),
                operation_id_full_hex:
                    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_owned(),
                timelock_contract_redacted: RedactedStrkey::from_already_redacted("CTLCK...ABCDE"),
                target_redacted: RedactedStrkey::from_already_redacted("CTARG...12345"),
                function: "upgrade".to_owned(),
                delay_ledgers: 1_440,
                proposer_redacted: RedactedStrkey::from_already_redacted("GPROP...ABCDE"),
                schedule_tx_hash_redacted: "aabb1122...ccdd3344".to_owned(),
                audit_request_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            },
            EventKind::SaTimelockCancelled {
                operation_id_redacted: "abcdef12...34567890".to_owned(),
                operation_id_full_hex:
                    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_owned(),
                timelock_contract_redacted: RedactedStrkey::from_already_redacted("CTLCK...ABCDE"),
                canceller_redacted: RedactedStrkey::from_already_redacted("GCNLR...ABCDE"),
                cancel_tx_hash_redacted: "bbcc2233...ddee4455".to_owned(),
                audit_request_id: "00000000-0000-0000-0000-000000000002".to_owned(),
            },
            EventKind::SaTimelockExecuted {
                operation_id_redacted: "abcdef12...34567890".to_owned(),
                operation_id_full_hex:
                    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_owned(),
                timelock_contract_redacted: RedactedStrkey::from_already_redacted("CTLCK...ABCDE"),
                executor_redacted: Some(RedactedStrkey::from_already_redacted("GEXEC...ABCDE")),
                execute_tx_hash_redacted: "ccdd3344...eeff5566".to_owned(),
                audit_request_id: "00000000-0000-0000-0000-000000000003".to_owned(),
            },
            EventKind::SaTimelockDivergencePostSubmit {
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                operation_id_redacted: "abcdef12...34567890".to_owned(),
                tx_hash_redacted: "aabb1122...ccdd3344".to_owned(),
                path: "schedule".to_owned(),
                primary_present: true,
                secondary_present: false,
                audit_request_id: "00000000-0000-0000-0000-000000000004".to_owned(),
            },
            EventKind::SaExternalExecuteSubmitted {
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                target_contract: "CTOKE...ZZZZZ".to_owned(),
                function: "transfer".to_owned(),
                arg_count: 3,
                auth_rule_ids: vec![1],
                rule_signer_pubkey_first8: "aabb1122".to_owned(),
                verifier_address: "CVERI...WWWWW".to_owned(),
                transaction_hash_redacted: "aabb1122...ccdd3344".to_owned(),
            },
            EventKind::SubmissionAuthMismatch {
                smart_account: "CDABC...12345".to_owned(),
                expected_count: 2,
                actual_count: 3,
                reason: "entry_count_mismatch".to_owned(),
            },
            EventKind::SaContextRuleNameUpdated {
                smart_account: "CDABC...12345".to_owned(),
                rule_id: 7,
                new_name_redacted: "new len=8".to_owned(),
                audit_request_id: "00000000-0000-0000-0000-000000000004".to_owned(),
            },
            EventKind::SaContextRuleValidUntilUpdated {
                smart_account: "CDABC...12345".to_owned(),
                rule_id: 7,
                new_valid_until: Some(123_456),
                audit_request_id: "00000000-0000-0000-0000-000000000005".to_owned(),
            },
            EventKind::ApprovalAttested {
                approval_kind: "PaymentSimulated".to_owned(),
                gated_tool: "stellar_pay_commit".to_owned(),
                envelope_sha256_hex: Some("a".repeat(64)),
                nonce_prefix: "AAAAAAAA".to_owned(),
                origin: "cli".to_owned(),
                mainnet_presence: None,
            },
            EventKind::ApprovalRejected {
                approval_kind: "PaymentSimulated".to_owned(),
                nonce_prefix: "BBBBBBBB".to_owned(),
                origin: "cli".to_owned(),
            },
            EventKind::ApprovalAttestedRemote {
                approval_kind: "PaymentSimulated".to_owned(),
                gated_tool: "stellar_pay_commit".to_owned(),
                envelope_sha256_hex: Some("a".repeat(64)),
                nonce_prefix: "CCCCCCCC".to_owned(),
                operator_credential_id_redacted: "deadbeef".to_owned(),
            },
            EventKind::ApprovalRejectedRemote {
                approval_kind: "PaymentSimulated".to_owned(),
                nonce_prefix: "DDDDDDDD".to_owned(),
                operator_credential_id_redacted: "cafebabe".to_owned(),
            },
            EventKind::ValueActionSubmitted {
                witness: None,
                approval_nonce: None,
                legs: vec![ValueLegRecord {
                    action: ValueActionKind::Payment,
                    amount: Some(1_000_000),
                    asset: Some("native".to_owned()),
                    destination_redacted: Some("GAAAA...ZZZZZ".to_owned()),
                }],
                opaque_reason: None,
                transaction_hash_redacted: "abcd1234...5678efgh".to_owned(),
                ledger: 42,
            },
            EventKind::ValueActionPending {
                witness: None,
                approval_nonce: None,
                legs: vec![ValueLegRecord {
                    action: ValueActionKind::Payment,
                    amount: Some(1_000_000),
                    asset: Some("native".to_owned()),
                    destination_redacted: Some("GAAAA...ZZZZZ".to_owned()),
                }],
                transaction_hash_redacted: "abcd1234...5678efgh".to_owned(),
                source_redacted: "GAAAA...ZZZZZ".to_owned(),
                sequence: 7,
            },
            EventKind::ValueActionFailed {
                approval_nonce: None,
                legs: vec![ValueLegRecord {
                    action: ValueActionKind::Payment,
                    amount: Some(1_000_000),
                    asset: Some("native".to_owned()),
                    destination_redacted: Some("GAAAA...ZZZZZ".to_owned()),
                }],
                transaction_hash_redacted: "abcd1234...5678efgh".to_owned(),
                code: "ledger.insufficient_balance".to_owned(),
            },
            EventKind::SubmissionReceiptCleared {
                transaction_hash_redacted: "abcd1234...5678efgh".to_owned(),
                cleared_from: "ambiguous".to_owned(),
                reservation_released: true,
                evidence: Some("submission.sequence_consumed".to_owned()),
            },
            EventKind::X402PaymentAuthorized {
                witness: None,
                signature_expiration_ledger: None,
                legs: vec![ValueLegRecord {
                    action: ValueActionKind::X402Payment,
                    amount: Some(2_500_000),
                    asset: Some(
                        "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA".to_owned(),
                    ),
                    destination_redacted: Some("GBPXX...WIVL".to_owned()),
                }],
                network: "stellar:testnet".to_owned(),
                scheme: "exact".to_owned(),
            },
            EventKind::X402AuthorizationWithheld {
                network: "stellar:testnet".to_owned(),
                scheme: "exact".to_owned(),
                failure_stage: "resimulation".to_owned(),
            },
            EventKind::OpaquePayloadSigned {
                payload_sha256_redacted: "dfe78222...9d11baf1".to_owned(),
                signer_redacted: crate::observability::RedactedStrkey::from_already_redacted(
                    "GBPXX...WIVL",
                ),
            },
            EventKind::MppChargeAuthorized {
                authorization_id_hash: "a".repeat(64),
                fingerprint_hash: "b".repeat(64),
                legs: vec![ValueLegRecord {
                    action: ValueActionKind::MppCharge,
                    amount: Some(10_000_000),
                    asset: Some(
                        "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA".to_owned(),
                    ),
                    destination_redacted: Some("GAAAA...AAAWHF".to_owned()),
                }],
                network: "stellar:testnet".to_owned(),
                payer_redacted: RedactedStrkey::from_already_redacted("GABCD...VWXYZ"),
                sponsorship_mode: "sponsored_pull".to_owned(),
                approval_present: true,
            },
            EventKind::MppAuthorizationWithheld {
                authorization_id_hash: "c".repeat(64),
                fingerprint_hash: "d".repeat(64),
                failure_stage: "authorization_audit".to_owned(),
                key_access_began: true,
                policy_budget_consumed: true,
            },
            EventKind::MppReceiptObserved {
                authorization_id_hash: "e".repeat(64),
                receipt_digest: "f".repeat(64),
                transaction_reference_redacted: "aaaaaaaa...aaaaaaaa".to_owned(),
                source_transport: "mcp".to_owned(),
                claimed_status: "success".to_owned(),
            },
            EventKind::MppSettlementReconciled {
                authorization_id_hash: "1".repeat(64),
                transaction_reference_redacted: "bbbbbbbb...bbbbbbbb".to_owned(),
                ledger: 42,
                verified_outcome: "settled".to_owned(),
            },
            EventKind::KeyringKeyWritten {
                key_purpose: KeyPurpose::AuditHashChainHmac,
                keyring_service: "stellar-agent-audit".to_owned(),
                keyring_entry: "default".to_owned(),
                public_address: None,
            },
            EventKind::SignerIdentityEnrolled {
                keyring_service: "stellar-agent-signer-default".to_owned(),
                keyring_entry: "enrolled-identity".to_owned(),
                public_address: RedactedStrkey::from_already_redacted("GABCD...VWXYZ"),
                role: "agent".to_owned(),
            },
            EventKind::ChannelPoolInitialised {
                funder_redacted: "GABCD...12345".to_owned(),
                channel_count: 4,
                tx_hash_redacted: "abcd1234...5678wxyz".to_owned(),
                ledger: 7,
            },
            EventKind::ChannelAcquired {
                channel_redacted: "GCHAN...00001".to_owned(),
                index: 0,
            },
            EventKind::ChannelReleased {
                channel_redacted: "GCHAN...00001".to_owned(),
                index: 0,
                outcome: "success".to_owned(),
            },
            EventKind::MainnetEnablementMinted {
                profile: "operator".to_owned(),
                endpoint_host: "rpc.example.invalid".to_owned(),
                installation_nonce_sha256: "00".repeat(32),
                rotated: false,
            },
            EventKind::MppStateAdopted {
                profile: "default".to_owned(),
                generation: 1,
            },
            EventKind::MppStateReset {
                profile: "default".to_owned(),
                discarded_generation: Some(7),
                carried_generation: Some(6),
                stale_carry: true,
                reason: "recovery".to_owned(),
            },
            EventKind::PolicyWindowStateReset {
                owner_authorization: None,
                wiped: None,
                profile: "default".to_owned(),
                reason: "corrupt-file recovery".to_owned(),
            },
            EventKind::AuditOutboxLossAcknowledged {
                expected_rows: 2,
                found_rows: 1,
                reason: "inspection".to_owned(),
                revoked_approvals: 1,
                revoked_grants: 1,
            },
            EventKind::AuditTipAnchored {
                reason: TipAnchorReason::Adopted,
                entry_count: 12,
                previous_anchor: None,
                reanchor_count: None,
            },
            EventKind::AuditEntryTagsStarted {
                anchored_count: 3,
                absorbed_count: 2,
            },
            EventKind::AuditEntryTagsRekeyed {
                cause: crate::audit_log::schema::EntryTagsRekeyCause::Rotation,
            },
            EventKind::AuditEntriesQuarantined {
                quarantined_count: 2,
            },
        ]
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "test adapter for fixture readability"
    )]
    fn new_tool_invocation(
        tool: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        arg_keys: Vec<String>,
        envelope_hash: Option<String>,
        nonce_id: Option<String>,
        policy_decision: PolicyDecision,
        decision_reason: Option<String>,
        request_id: impl Into<String>,
    ) -> AuditEntry {
        let mut params =
            NewToolInvocation::new(tool, chain_id, arg_keys, policy_decision, request_id);
        params.envelope_hash = envelope_hash;
        params.nonce_id = nonce_id;
        params.decision_reason = decision_reason;
        AuditEntry::new_tool_invocation(params)
    }

    fn tool_entry() -> AuditEntry {
        new_tool_invocation(
            "stellar_pay_commit",
            "stellar:testnet",
            vec!["destination".to_owned()],
            None,
            None,
            PolicyDecision::Allow,
            None,
            uuid::Uuid::new_v4().to_string(),
        )
    }
    fn write_entries(path: &Path, count: usize) {
        let mut writer = AuditWriter::open(path.to_path_buf(), None).unwrap();
        for _ in 0..count {
            writer.write_entry(tool_entry()).unwrap();
        }
    }

    fn write_entries_with_timestamps(path: &Path, timestamps: &[&str]) {
        let mut writer = AuditWriter::open(path.to_path_buf(), None).unwrap();
        for ts in timestamps {
            let mut entry = new_tool_invocation(
                "stellar_pay_commit",
                "stellar:testnet",
                vec!["destination".to_owned()],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            );
            entry.ts = (*ts).to_owned();
            writer.write_entry(entry).unwrap();
        }
    }

    /// A payment row that records the signature expiration ledger and one
    /// that does not both chain and verify; the field is written only when
    /// present.
    #[test]
    fn x402_rows_with_and_without_the_expiration_ledger_verify() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        for ledger in [Some(1_060), None] {
            writer
                .write_entry(AuditEntry::new_x402_payment_authorized(
                    "stellar_x402_create_payment",
                    "stellar:mainnet",
                    vec![],
                    "stellar:mainnet",
                    "exact",
                    PolicyDecision::Allow,
                    uuid::Uuid::new_v4().to_string(),
                    None,
                    ledger,
                ))
                .unwrap();
        }
        drop(writer);

        assert_eq!(verify_log(&path, None).unwrap().entries_verified, 2);
        let text = std::fs::read_to_string(&path).unwrap();
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["kind"], "x402_payment_authorized");
        assert_eq!(rows[0]["signature_expiration_ledger"], 1_060);
        assert_eq!(rows[1]["kind"], "x402_payment_authorized");
        assert!(
            rows[1]
                .as_object()
                .unwrap()
                .get("signature_expiration_ledger")
                .is_none(),
            "{}",
            rows[1]
        );
    }

    /// The signature expiration ledger is part of a row's hash input: a
    /// payment row whose ledger changes after a following row was written
    /// breaks the chain.
    #[test]
    fn a_changed_expiration_ledger_breaks_the_chain() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        writer
            .write_entry(AuditEntry::new_x402_payment_authorized(
                "stellar_x402_create_payment",
                "stellar:mainnet",
                vec![],
                "stellar:mainnet",
                "exact",
                PolicyDecision::Allow,
                uuid::Uuid::new_v4().to_string(),
                None,
                Some(1_060),
            ))
            .unwrap();
        writer.write_entry(tool_entry()).unwrap();
        drop(writer);
        verify_log(&path, None).unwrap();
        let original = fs::read_to_string(&path).unwrap();
        let mut rows: Vec<serde_json::Value> = original
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        rows[0]["signature_expiration_ledger"] = serde_json::json!(1_061);
        let tampered = rows
            .iter()
            .map(|row| serde_json::to_string(row).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, tampered + "\n").unwrap();
        assert!(matches!(
            verify_log(&path, None),
            Err(VerifyError::ChainBroken { .. })
        ));
    }

    #[test]
    fn verify_empty_log_ok() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        // Create an empty file.
        std::fs::File::create(&path).unwrap();

        let ok = verify_log(&path, None).unwrap();
        assert_eq!(ok.entries_verified, 0);
        assert_eq!(ok.files_walked, 1);
    }

    #[cfg(unix)]
    #[test]
    fn verify_log_rejects_non_utf8_filename() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let dir = TempDir::new().unwrap();
        let bad_name = OsString::from_vec(vec![b'a', 0xFF, b'.', b'j', b's', b'o', b'n']);
        let path = dir.path().join(PathBuf::from(bad_name));

        let result = verify_log(&path, None);

        assert!(
            matches!(
                result,
                Err(VerifyError::PathContract { ref detail })
                    if detail == "log path has no UTF-8 file name"
            ),
            "expected PathContract for non-UTF8 filename, got {result:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn verify_log_rejects_non_utf16_filename() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt as _;

        let dir = TempDir::new().unwrap();
        let bad_name = OsString::from_wide(&[
            0x0061, // 'a'
            0xD800, // unpaired surrogate
            0x002E, // '.'
            0x006A, // 'j'
            0x0073, // 's'
            0x006F, // 'o'
            0x006E, // 'n'
        ]);
        let path = dir.path().join(PathBuf::from(bad_name));

        let result = verify_log(&path, None);

        assert!(
            matches!(
                result,
                Err(VerifyError::PathContract { ref detail })
                    if detail == "log path has no UTF-8 file name"
            ),
            "expected PathContract for non-UTF16 filename, got {result:?}"
        );
    }

    /// A path with no parent component (e.g. the filesystem root `/`) is a
    /// path-shape contract violation and must surface `audit.path_contract`
    /// rather than `audit.io_error` so operators see one error class for
    /// "the supplied path is structurally unusable".
    #[test]
    fn verify_log_rejects_path_without_parent_as_path_contract() {
        // `Path::parent()` returns `None` for the root-only path `/` (and the
        // empty path); these are the only inputs that hit `parent.is_none()`
        // in `collect_file_chain`.
        let result = verify_log(Path::new("/"), None);

        assert!(
            matches!(
                result,
                Err(VerifyError::PathContract { ref detail })
                    if detail.contains("must have a parent directory component")
            ),
            "expected PathContract for parent-less path, got {result:?}"
        );
    }

    #[test]
    fn verify_valid_chain_ok() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 5);

        let ok = verify_log(&path, None).unwrap();
        assert_eq!(ok.entries_verified, 5);
    }

    #[test]
    fn collect_file_chain_rejects_rotated_file_flood() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        for i in 0..(ROTATED_FILE_CHAIN_CAP + 1) {
            let rotated = dir.path().join(format!("test.jsonl.20260513T{i:09}"));
            fs::write(rotated, b"{}\n").unwrap();
        }

        let err = collect_file_chain(&path).unwrap_err();

        assert!(
            matches!(
                err,
                VerifyError::TooManyRotatedFiles {
                    found,
                    cap: ROTATED_FILE_CHAIN_CAP,
                } if found == ROTATED_FILE_CHAIN_CAP + 1
            ),
            "expected TooManyRotatedFiles for rotated-file flood, got {err:?}"
        );
    }

    #[test]
    fn verify_event_kind_policy_covers_all_current_variants() {
        let labels: Vec<&'static str> = current_event_kind_fixtures()
            .iter()
            .map(verify_event_kind_explicit_arm_for_test)
            .collect();

        assert_eq!(
            labels,
            vec![
                "tool_invocation",
                "plugin_invoked",
                "wallet_mlock_failed",
                "sa_raw_invocation",
                "smart_account_deployed",
                "sa_context_rule_created",
                "sa_context_rule_pins_updated",
                "sa_context_rule_created_v2",
                "sa_context_rule_pins_updated_v2",
                "sa_context_rule_deleted",
                "passkey_registered",
                "passkey_assertion",
                "sa_signer_added",
                "sa_signer_removed",
                "sa_threshold_changed",
                "sa_signer_set_diverged",
                "sa_signer_set_baselined",
                "sa_signer_set_baselined_v2",
                "sa_signer_added_v2",
                "sa_signer_removed_v2",
                "sa_threshold_changed_v2",
                "sa_verifier_hash_drift",
                "sa_policy_hash_drift",
                "sa_mutable_contract_override",
                "sa_unknown_contract_override",
                "audit_rotation_handoff",
                "sa_verifier_migrated",
                "sa_verifier_diversification_override",
                "sa_verifier_allowlist_advisory",
                "sa_policy_added",
                "sa_policy_removed",
                "sa_spending_limit_retuned",
                "sa_weighted_threshold_changed",
                "sa_signer_weight_changed",
                "sa_multicall_bundle_submitted",
                "sa_multicall_inner_executed",
                "sa_multicall_bundle_denied",
                "sa_multicall_registered",
                "sa_multicall_registration_refused",
                "sa_multicall_unregistered",
                "sa_multicall_unregistered_force",
                "sa_timelock_scheduled",
                "sa_timelock_cancelled",
                "sa_timelock_executed",
                "sa_timelock_divergence_post_submit",
                "sa_external_execute_submitted",
                "submission_auth_mismatch",
                "sa_context_rule_name_updated",
                "sa_context_rule_valid_until_updated",
                "approval_attested",
                "approval_rejected",
                "approval_attested_remote",
                "approval_rejected_remote",
                "value_action_submitted",
                "value_action_pending",
                "value_action_failed",
                "submission_receipt_cleared",
                "x402_payment_authorized",
                "x402_authorization_withheld",
                "opaque_payload_signed",
                "mpp_charge_authorized",
                "mpp_authorization_withheld",
                "mpp_receipt_observed",
                "mpp_settlement_reconciled",
                "keyring_key_written",
                "signer_identity_enrolled",
                "channel_pool_initialised",
                "channel_acquired",
                "channel_released",
                "mainnet_enablement_minted",
                "mpp_state_adopted",
                "mpp_state_reset",
                "policy_window_state_reset",
                "audit_outbox_loss_acknowledged",
                "audit_tip_anchored",
                "audit_entry_tags_started",
                "audit_entry_tags_rekeyed",
                "audit_entries_quarantined",
            ]
        );
        assert_eq!(
            labels.len(),
            EVENT_KIND_VARIANT_COUNT,
            "every EventKind variant needs a fixture here; adding one without a \
             fixture, or bumping EVENT_KIND_VARIANT_COUNT without adding one, \
             leaves the wire-tag list incomplete"
        );
        let mut unique: Vec<&'static str> = labels.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            labels.len(),
            "each variant must map to a distinct wire tag"
        );
    }

    /// Builds the anchor that describes `path`'s active file as the writer
    /// would have left it.
    fn anchor_for(path: &std::path::Path) -> TipAnchor {
        let ok = verify_log(path, None).unwrap();
        let tip = ok.active_tip.unwrap();
        TipAnchor::new(tip.entry_count, tip.tip_hash, tip.end_offset)
    }

    #[test]
    fn verify_with_an_anchor_passes_on_the_anchored_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 3);
        let anchor = anchor_for(&path);

        let health = crate::audit_log::health::AuditWriterHealth::new();
        let ok = verify_log_with_health(&path, None, Some(&anchor), &health.handle()).unwrap();
        assert_eq!(ok.verify_ok.entries_verified, 3);
    }

    #[test]
    fn verify_with_an_anchor_fails_on_a_truncated_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 3);
        let anchor = anchor_for(&path);

        // Drop the last entry. The chain walk alone still passes, because it
        // verifies a prefix; the anchor is the only thing that pins the end.
        let content = fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = content.lines().take(2).collect();
        fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();
        verify_log(&path, None).expect("the truncated log still passes the chain walk");

        let health = crate::audit_log::health::AuditWriterHealth::new();
        let err = verify_log_with_health(&path, None, Some(&anchor), &health.handle()).unwrap_err();
        assert!(
            matches!(
                err,
                VerifyError::TipAnchorMismatch {
                    expected_count: 3,
                    actual_count: 2,
                    ..
                }
            ),
            "expected a tip-anchor mismatch naming both counts, got {err:?}"
        );
        assert_eq!(err.wire_code(), "audit.tip_anchor_mismatch");
        assert!(
            !err.to_string().contains("sha256:"),
            "the refusal must not carry a digest: {err}"
        );
    }

    /// Once tags are in force, entries ahead of the anchor pass only with
    /// valid tags: two tagged rows pass with the tags verified, two forged
    /// untagged rows fail with `missing`.
    #[test]
    fn verify_with_an_anchor_passes_on_a_file_ahead_of_it_only_with_valid_tags() {
        let health = crate::audit_log::health::AuditWriterHealth::new();
        for forged in [false, true] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("test.jsonl");
            let mut writer = keyed_writer(&path);
            writer.write_entry(tool_entry()).unwrap();
            let anchor = anchor_for(&path);
            if forged {
                drop(writer);
                forge_untagged(&path);
                forge_untagged(&path);
            } else {
                writer.write_entry(tool_entry()).unwrap();
                writer.write_entry(tool_entry()).unwrap();
                drop(writer);
            }
            let result =
                verify_log_with_health(&path, Some(&TAG_TEST_KEY), Some(&anchor), &health.handle());
            if forged {
                let err = result.unwrap_err();
                assert!(
                    matches!(
                        err,
                        VerifyError::EntryTagInvalid {
                            reason: "missing",
                            line: 3,
                            ..
                        }
                    ),
                    "{err:?}"
                );
            } else {
                let ok = result.unwrap();
                assert_eq!(ok.verify_ok.entries_verified, 4);
                assert!(ok.verify_ok.entry_tags_verified);
            }
        }
    }

    #[test]
    fn verify_with_an_anchor_fails_on_a_same_length_substitution() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 3);
        let anchor = anchor_for(&path);

        // A different log of the same entry count and byte length: the chain
        // walk passes, the anchored tip hash does not match.
        let other = dir.path().join("other.jsonl");
        write_entries(&other, 3);
        fs::copy(&other, &path).unwrap();
        fs::remove_file(&other).unwrap();
        verify_log(&path, None).expect("the substituted log still passes the chain walk");

        let health = crate::audit_log::health::AuditWriterHealth::new();
        let err = verify_log_with_health(&path, None, Some(&anchor), &health.handle()).unwrap_err();
        assert!(
            matches!(err, VerifyError::TipAnchorMismatch { .. }),
            "expected a tip-anchor mismatch for a substituted file, got {err:?}"
        );
    }

    #[test]
    fn verify_with_an_anchor_fails_on_a_longer_substitution() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 3);
        let anchor = anchor_for(&path);

        // A different log that is LONGER than the anchor in both entry count and
        // byte offset, and internally consistent end to end. Entry count and
        // length alone cannot tell it from an honest log that simply had more
        // rows appended; only the anchored entry can.
        let other = dir.path().join("other.jsonl");
        write_entries(&other, 6);
        fs::copy(&other, &path).unwrap();
        fs::remove_file(&other).unwrap();
        verify_log(&path, None).expect("the substituted log still passes the chain walk");

        let tip = verify_log(&path, None).unwrap().active_tip.unwrap();
        assert!(
            tip.entry_count > anchor.entry_count && tip.end_offset > anchor.end_offset,
            "the substitution must be ahead of the anchor on both axes, or the \
             test is not exercising the ahead rule"
        );

        let health = crate::audit_log::health::AuditWriterHealth::new();
        let err = verify_log_with_health(&path, None, Some(&anchor), &health.handle()).unwrap_err();
        assert!(
            matches!(err, VerifyError::TipAnchorMismatch { .. }),
            "a longer substitution that does not contain the anchored entry must \
             refuse, got {err:?}"
        );
        assert_eq!(err.wire_code(), "audit.tip_anchor_mismatch");
    }

    /// Keeps the first `entries` lines of the log at `path`.
    fn truncate_to_entries(path: &Path, entries: usize) {
        let content = fs::read_to_string(path).unwrap();
        let kept: String = content.split_inclusive('\n').take(entries).collect();
        fs::write(path, kept).unwrap();
    }

    /// Walks the log and applies the missing-anchor check, as `audit verify`
    /// does for a profile whose anchor is absent.
    fn verify_without_anchor(path: &Path, binding: BindingHistory) -> Result<(), VerifyError> {
        let ok = verify_log(path, None).expect("the truncated log still passes the chain walk");
        check_missing_anchor(path, binding, ok.active_tip.as_ref())
    }

    fn assert_anchor_missing(err: &VerifyError, evidence: PriorAnchoring, count: u64) {
        assert!(
            matches!(
                err,
                VerifyError::TipAnchorMissing {
                    evidence: found,
                    actual_count,
                    ..
                } if *found == evidence && *actual_count == count
            ),
            "expected a missing anchor naming {evidence:?} at {count} entries, got {err:?}"
        );
        assert_eq!(err.wire_code(), "audit.tip_anchor_missing");
        assert!(err.to_string().contains("anchor: missing"), "{err}");
        assert!(
            !err.to_string().contains("sha256:"),
            "the refusal must not carry a digest: {err}"
        );
    }

    #[test]
    fn verify_reports_anchor_missing_under_a_recorded_binding() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 3);
        truncate_to_entries(&path, 2);

        let err = verify_without_anchor(&path, BindingHistory::Recorded).unwrap_err();
        assert_anchor_missing(&err, PriorAnchoring::BindingRecorded, 2);
    }

    #[test]
    fn verify_reports_anchor_missing_when_a_chain_root_sidecar_exists() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        {
            let mut writer = AuditWriter::open_keyed_unanchored_for_test(
                path.clone(),
                Zeroizing::new([0x3d_u8; 32]),
            )
            .unwrap();
            for _ in 0..3 {
                writer.write_entry(tool_entry()).unwrap();
            }
        }
        truncate_to_entries(&path, 1);

        let err = verify_without_anchor(&path, BindingHistory::NotRecorded).unwrap_err();
        assert_anchor_missing(&err, PriorAnchoring::ChainRootSidecar, 1);
    }

    #[test]
    fn verify_reports_anchor_missing_when_the_log_holds_an_adoption_row() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 1);
        let store =
            std::sync::Arc::new(crate::audit_log::tip_anchor::InMemoryTipAnchorStore::new());
        {
            let mut writer = AuditWriter::open_with_tip_anchor(
                path.clone(),
                None,
                std::sync::Arc::clone(&store)
                    as std::sync::Arc<dyn crate::audit_log::tip_anchor::TipAnchorStore>,
                BindingHistory::NotRecorded,
            )
            .unwrap();
            writer.write_entry(tool_entry()).unwrap();
        }
        // The kept prefix is the first entry and the adoption row after it.
        truncate_to_entries(&path, 2);

        let err = verify_without_anchor(&path, BindingHistory::NotRecorded).unwrap_err();
        assert_anchor_missing(&err, PriorAnchoring::AnchoringRow, 2);
    }

    fn assert_anchoring_row_alone_reports_missing(
        reason: crate::audit_log::schema::TipAnchorReason,
    ) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        {
            let mut writer = AuditWriter::open(path.clone(), None).unwrap();
            writer
                .write_entry(AuditEntry::new_audit_tip_anchored(
                    reason,
                    0,
                    None,
                    Some(1),
                    uuid::Uuid::new_v4().to_string(),
                ))
                .unwrap();
            writer.write_entry(tool_entry()).unwrap();
        }
        truncate_to_entries(&path, 1);
        assert!(!crate::audit_log::writer::hmac_sidecar_path(&path).exists());
        let err = verify_without_anchor(&path, BindingHistory::NotRecorded).unwrap_err();
        assert_anchor_missing(&err, PriorAnchoring::AnchoringRow, 1);
    }

    #[test]
    fn verify_reports_missing_anchor_from_a_rollback_acknowledged_row_alone() {
        assert_anchoring_row_alone_reports_missing(
            crate::audit_log::schema::TipAnchorReason::RollbackAcknowledged,
        );
    }

    #[test]
    fn verify_reports_missing_anchor_from_a_binding_changed_row_alone() {
        assert_anchoring_row_alone_reports_missing(
            crate::audit_log::schema::TipAnchorReason::BindingChanged,
        );
    }

    /// Regression guard: a log written only by unkeyed writers, with no
    /// recorded binding, verifies without an anchor.
    #[test]
    fn verify_passes_an_unanchored_quickstart_log() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 3);

        verify_without_anchor(&path, BindingHistory::NotRecorded)
            .expect("a log that was never anchored verifies without an anchor");
    }

    /// Runs the walk with an anchor through the same entry point
    /// `audit verify --profile` uses.
    fn verify_with_anchor(
        path: &std::path::Path,
        anchor: &TipAnchor,
    ) -> Result<VerifyOkWithHealth, VerifyError> {
        let health = crate::audit_log::health::AuditWriterHealth::new();
        verify_log_with_health(path, None, Some(anchor), &health.handle())
    }

    /// Builds a log that has rotated once, leaving the anchor on the archive's
    /// handoff entry — the state every completed rotation leaves behind until
    /// the new file's first append.
    fn rotated_log(dir: &std::path::Path) -> (std::path::PathBuf, TipAnchor) {
        let path = dir.join("test.jsonl");
        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        writer.write_entry(sample_tool_entry()).unwrap();
        writer.write_entry(sample_tool_entry()).unwrap();
        writer.force_rotate_for_test().unwrap();
        drop(writer);
        let handoff = last_entry_anchor(&newest_archive_of(dir));
        (path, handoff)
    }

    /// Returns the newest rotated sibling of `test.jsonl` in `dir`.
    ///
    /// Matches through `is_rotated_sibling` so the `.lock` and `.root_hmac`
    /// sidecars, which share the prefix, are not mistaken for archives.
    fn newest_archive_of(dir: &std::path::Path) -> std::path::PathBuf {
        let mut archives: Vec<std::path::PathBuf> = fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| is_rotated_sibling("test.jsonl", n))
            })
            .collect();
        archives.sort();
        archives.pop().expect("one archive")
    }

    fn sample_tool_entry() -> AuditEntry {
        new_tool_invocation(
            "stellar_pay_commit",
            "stellar:testnet",
            vec!["destination".to_owned()],
            None,
            None,
            PolicyDecision::Allow,
            None,
            uuid::Uuid::new_v4().to_string(),
        )
    }

    /// The anchor describing `file`'s last entry, computed independently of the
    /// code under test.
    fn last_entry_anchor(file: &std::path::Path) -> TipAnchor {
        let content = fs::read_to_string(file).unwrap();
        let mut count = 0u64;
        let mut end = 0u64;
        let mut last = String::new();
        let mut consumed = 0u64;
        for raw in content.split_inclusive('\n') {
            consumed += raw.len() as u64;
            let line = raw.trim_end_matches(['\n', '\r']);
            if line.trim().is_empty() {
                continue;
            }
            count += 1;
            end = consumed;
            last = line.to_owned();
        }
        let entry: AuditEntry = serde_json::from_str(&last).unwrap();
        let body = entry.canonical_json_body().unwrap();
        let hash = compute_entry_hash(&body, &entry.previous_entry_hash).unwrap();
        TipAnchor::new(count, hash, end)
    }

    #[test]
    fn verify_accepts_an_anchor_naming_the_archive_handoff_after_a_rotation() {
        let dir = TempDir::new().unwrap();
        let (path, handoff) = rotated_log(dir.path());

        // The active file is empty and the anchor names the previous
        // generation. Refusing here would make `audit verify --profile` report a
        // rollback on every freshly rotated log.
        let ok = verify_with_anchor(&path, &handoff).expect("a rotated log verifies");
        assert_eq!(ok.verify_ok.files_walked, 2);
    }

    #[test]
    fn verify_refuses_a_restore_of_the_pre_rotation_directory_state() {
        let dir = TempDir::new().unwrap();
        let (path, handoff) = rotated_log(dir.path());
        let archive = newest_archive_of(dir.path());
        let pre_rotation: String = fs::read_to_string(&archive)
            .unwrap()
            .lines()
            .filter(|l| !l.contains("audit_rotation_handoff"))
            .map(|l| format!("{l}\n"))
            .collect();

        // Roll the directory back to before the rotation.
        fs::remove_file(&archive).unwrap();
        fs::write(&path, pre_rotation).unwrap();
        verify_log(&path, None).expect("the restored state still passes the chain walk");

        let err = verify_with_anchor(&path, &handoff).unwrap_err();
        assert!(
            matches!(err, VerifyError::TipAnchorMismatch { .. }),
            "a directory-level rollback must be refused: {err:?}"
        );
    }

    #[test]
    fn verify_refuses_a_restore_of_an_older_archive_and_active_pair() {
        let dir = TempDir::new().unwrap();
        let (path, handoff) = rotated_log(dir.path());

        // Append to the post-rotation file so the anchor legitimately moves onto
        // it, then restore the pair to the moment the rotation finished.
        let empty_active = fs::read(&path).unwrap();
        {
            let mut writer = AuditWriter::open(path.clone(), None).unwrap();
            writer.write_entry(sample_tool_entry()).unwrap();
            writer.write_entry(sample_tool_entry()).unwrap();
        }
        let current = last_entry_anchor(&path);
        assert!(verify_with_anchor(&path, &current).is_ok());

        fs::write(&path, &empty_active).unwrap();
        verify_log(&path, None).expect("the restored pair still passes the chain walk");

        let err = verify_with_anchor(&path, &current).unwrap_err();
        assert!(
            matches!(err, VerifyError::TipAnchorMismatch { .. }),
            "restoring the pair to an earlier moment must be refused: {err:?}"
        );
        // And the pre-rotation-generation anchor is not a way back in either:
        // it names the archive's handoff, which is the legitimate freshly
        // rotated state, so it is accepted — the guard that matters is that the
        // anchor cannot go BACKWARD once it has moved on.
        assert!(verify_with_anchor(&path, &handoff).is_ok());
    }

    #[test]
    fn verify_tolerates_trailing_blank_lines() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 2);
        let anchor = anchor_for(&path);
        fs::write(&path, [fs::read(&path).unwrap(), b"\n\n".to_vec()].concat()).unwrap();

        verify_with_anchor(&path, &anchor)
            .expect("blank lines after the tip entry are not a rollback");
    }

    #[test]
    fn verify_reports_the_active_file_tip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 2);

        let ok = verify_log(&path, None).unwrap();
        let tip = ok.active_tip.expect("a walked file must report a tip");
        assert_eq!(tip.entry_count, 2);
        assert_eq!(
            tip.end_offset,
            fs::metadata(&path).unwrap().len(),
            "the tip offset must be the end of the last entry"
        );
    }

    #[test]
    fn verify_accepts_regular_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 1);

        let ok = verify_log(&path, None).unwrap();

        assert_eq!(ok.entries_verified, 1);
        assert!(ok.warnings.is_empty());
    }

    #[test]
    fn verify_rejects_directory_path() {
        let dir = TempDir::new().unwrap();

        let result = verify_log(dir.path(), None);

        assert!(
            matches!(result, Err(VerifyError::NonRegularFileLogPath { .. })),
            "expected NonRegularFileLogPath for directory, got {result:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn verify_rejects_symlinked_log_path() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.jsonl");
        let link = dir.path().join("linked.jsonl");
        write_entries(&target, 1);
        symlink(&target, &link).unwrap();

        let result = verify_log(&link, None);

        assert!(
            matches!(result, Err(VerifyError::NonRegularFileLogPath { .. })),
            "expected NonRegularFileLogPath for symlink, got {result:?}"
        );
    }

    #[test]
    fn verify_log_emits_backward_jump_warning_for_60s_drift() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries_with_timestamps(
            &path,
            &[
                "2026-05-06T00:00:00.000Z",
                "2026-05-06T00:00:10.000Z",
                "2026-05-05T23:58:20.000Z",
            ],
        );

        let ok = verify_log(&path, None).unwrap();

        assert_eq!(ok.warnings.len(), 1);
        assert_eq!(
            ok.warnings[0],
            VerifyWarning::BackwardTimestampJump {
                previous_ts: "2026-05-06T00:00:10.000Z".to_owned(),
                current_ts: "2026-05-05T23:58:20.000Z".to_owned(),
                drift_ms: 110_000,
                file_index: 0,
                entry_index: 2,
            }
        );
    }

    #[test]
    fn verify_log_does_not_warn_on_30s_jitter() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries_with_timestamps(
            &path,
            &[
                "2026-05-06T00:00:00.000Z",
                "2026-05-06T00:00:10.000Z",
                "2026-05-05T23:59:40.000Z",
            ],
        );

        let ok = verify_log(&path, None).unwrap();

        assert!(
            ok.warnings.is_empty(),
            "unexpected warnings: {:?}",
            ok.warnings
        );
    }

    #[test]
    fn verify_log_warning_does_not_cause_hard_failure() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries_with_timestamps(
            &path,
            &[
                "2026-05-06T00:00:00.000Z",
                "2026-05-06T00:00:10.000Z",
                "2026-05-05T23:58:20.000Z",
            ],
        );

        let ok = verify_log(&path, None).unwrap();

        assert_eq!(ok.entries_verified, 3);
        assert!(matches!(
            ok.warnings.as_slice(),
            [VerifyWarning::BackwardTimestampJump { .. }]
        ));
    }

    #[test]
    fn verify_tampered_entry_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 3);

        // Tamper: read file, change the tool name in the second line.
        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert!(lines.len() >= 2);

        let mut tampered: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
        let mut entry: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        entry["tool"] = serde_json::Value::String("tampered".to_owned());
        tampered[1] = serde_json::to_string(&entry).unwrap();

        fs::write(&path, tampered.join("\n") + "\n").unwrap();

        let err = verify_log(&path, None).unwrap_err();
        assert!(
            matches!(err, VerifyError::ChainBroken { .. }),
            "expected ChainBroken, got {err:?}"
        );
    }

    #[test]
    fn verify_tampered_release_evidence_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("evidence.jsonl");
        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        for evidence in [None, Some("submission.sequence_consumed".to_owned()), None] {
            writer
                .write_entry(AuditEntry::new_submission_receipt_cleared(
                    "tx receipt clear",
                    "stellar:testnet",
                    "abcd1234...5678efgh",
                    "ambiguous",
                    true,
                    evidence,
                    None,
                    "evidence-request",
                ))
                .unwrap();
        }
        drop(writer);
        verify_log(&path, None).unwrap();
        let original = fs::read_to_string(&path).unwrap();
        let mut rows: Vec<serde_json::Value> = original
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        rows[1]["evidence"] = serde_json::json!("submission.time_bound_passed");
        let tampered = rows
            .iter()
            .map(|row| serde_json::to_string(row).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, tampered + "\n").unwrap();
        assert!(matches!(
            verify_log(&path, None),
            Err(VerifyError::ChainBroken { .. })
        ));
    }

    #[test]
    fn verify_deleted_entry_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 4);

        let contents = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = contents.lines().map(|l| l.to_string()).collect();
        assert!(lines.len() >= 3);
        lines.remove(1);
        fs::write(&path, lines.join("\n") + "\n").unwrap();

        let err = verify_log(&path, None).unwrap_err();
        assert!(
            matches!(err, VerifyError::ChainBroken { .. }),
            "expected ChainBroken, got {err:?}"
        );
    }

    #[test]
    fn verify_reordered_entries_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 4);

        let contents = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = contents.lines().map(|l| l.to_string()).collect();
        assert!(lines.len() >= 2);
        lines.swap(0, 1);
        fs::write(&path, lines.join("\n") + "\n").unwrap();

        let err = verify_log(&path, None).unwrap_err();
        assert!(
            matches!(err, VerifyError::ChainBroken { .. }),
            "expected ChainBroken, got {err:?}"
        );
    }

    #[test]
    fn verify_error_wire_codes() {
        assert_eq!(
            VerifyError::ChainBroken {
                line: 5,
                file: "f.jsonl".to_owned(),
                reason: "previous_entry_hash_mismatch",
            }
            .wire_code(),
            "audit.chain_broken"
        );
        assert_eq!(
            VerifyError::RotationGap {
                file: "missing.jsonl.20260428T123456".to_owned()
            }
            .wire_code(),
            "audit.rotation_gap"
        );
        assert_eq!(
            VerifyError::HmacMismatch {
                file: "f.jsonl".to_owned()
            }
            .wire_code(),
            "audit.hmac_mismatch"
        );
        assert_eq!(
            VerifyError::HmacSidecarMissing {
                file: "f.jsonl".to_owned()
            }
            .wire_code(),
            "audit.hmac_sidecar_missing"
        );
        assert_eq!(
            VerifyError::TooManyRotatedFiles { found: 22, cap: 21 }.wire_code(),
            "audit.too_many_rotated_files"
        );
        assert_eq!(
            VerifyError::NonRegularFileLogPath {
                path: PathBuf::from("/tmp/f.jsonl")
            }
            .wire_code(),
            "audit.non_regular_file_log_path"
        );
        assert_eq!(
            VerifyError::ParseError {
                line: 1,
                detail: "bad json".to_owned()
            }
            .wire_code(),
            "audit.parse_error"
        );
        assert_eq!(
            VerifyError::PathContract {
                detail: "log path has no UTF-8 file name".to_owned()
            }
            .wire_code(),
            "audit.path_contract"
        );
        assert_eq!(
            VerifyError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found"
            ))
            .wire_code(),
            "audit.io_error"
        );
    }

    #[test]
    fn verify_with_hmac_key_ok() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let key = Zeroizing::new([0x42u8; 32]);
        let mut writer = AuditWriter::open_keyed_unanchored_for_test(path.clone(), key).unwrap();
        let entry = new_tool_invocation(
            "test",
            "stellar:testnet",
            vec![],
            None,
            None,
            PolicyDecision::Allow,
            None,
            uuid::Uuid::new_v4().to_string(),
        );
        writer.write_entry(entry).unwrap();
        drop(writer);

        let ok = verify_log(&path, Some(&[0x42u8; 32])).unwrap();
        assert_eq!(ok.entries_verified, 1);
        assert!(ok.hmac_verified);
    }

    #[test]
    fn verify_without_hmac_key_reports_hmac_unverified() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 1);

        let ok = verify_log(&path, None).unwrap();

        assert_eq!(ok.entries_verified, 1);
        assert!(!ok.hmac_verified);
    }

    #[test]
    fn verify_hmac_sidecar_missing_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        // Write without HMAC key (no sidecar created).
        write_entries(&path, 1);

        // Now verify WITH a key — sidecar is absent → HmacSidecarMissing.
        let result = verify_log(&path, Some(&[0x42u8; 32]));
        assert!(
            matches!(result, Err(VerifyError::HmacSidecarMissing { .. })),
            "expected HmacSidecarMissing, got {result:?}"
        );
    }

    // ── Cross-file rotation chain tests ──────────────────────────────────────

    /// Helper: write `count` entries to a fresh writer then force rotation by
    /// inflating the file to ROTATION_THRESHOLD_BYTES before the next write.
    fn write_with_forced_rotation(dir: &std::path::Path, name: &str, entries_before: usize) {
        let path = dir.join(name);
        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        for _ in 0..entries_before {
            let entry = new_tool_invocation(
                "test",
                "stellar:testnet",
                vec![],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            );
            writer.write_entry(entry).unwrap();
        }
        drop(writer);

        // Inflate file to trigger rotation on next write.
        let large_content = vec![b'\n'; ROTATION_THRESHOLD_BYTES as usize];
        fs::write(&path, &large_content).unwrap();

        let mut writer2 = AuditWriter::open(path.clone(), None).unwrap();
        // Write one more entry to trigger rotation and start new file.
        let entry = new_tool_invocation(
            "post_rotation",
            "stellar:testnet",
            vec![],
            None,
            None,
            PolicyDecision::Allow,
            None,
            uuid::Uuid::new_v4().to_string(),
        );
        writer2.write_entry(entry).unwrap();
        // Write one more entry in the new active file.
        let entry2 = new_tool_invocation(
            "post_rotation_2",
            "stellar:testnet",
            vec![],
            None,
            None,
            PolicyDecision::Allow,
            None,
            uuid::Uuid::new_v4().to_string(),
        );
        writer2.write_entry(entry2).unwrap();
    }

    fn rotated_files(dir: &std::path::Path, stem: &str) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|s| s.to_str())
                    .map(|name| is_rotated_sibling(stem, name))
                    .unwrap_or(false)
            })
            .collect()
    }

    fn corrupt_handoff_next_file_name(rotated_path: &Path, next_file_name: &str) {
        let contents = fs::read_to_string(rotated_path).unwrap();
        let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
        assert!(!lines.is_empty());

        let mut new_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
        for line in new_lines.iter_mut() {
            if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(line)
                && v["kind"].as_str() == Some("audit_rotation_handoff")
            {
                v["next_file_name"] = serde_json::Value::String(next_file_name.to_owned());
                *line = serde_json::to_string(&v).unwrap();
                break;
            }
        }
        fs::write(rotated_path, new_lines.join("\n") + "\n").unwrap();
    }

    fn rotation_gap_for_corrupt_handoff_name(next_file_name: &str) -> String {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        write_with_forced_rotation(dir.path(), "audit.jsonl", 2);

        let rotated_files = rotated_files(dir.path(), "audit.jsonl");
        assert!(!rotated_files.is_empty());
        corrupt_handoff_next_file_name(&rotated_files[0], next_file_name);

        verify_log(&path, None).unwrap_err().to_string()
    }

    #[test]
    fn verify_chain_across_rotation_ok() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Write 2 entries, then force rotation, write 2 more.
        write_with_forced_rotation(dir.path(), "audit.jsonl", 2);

        // verify_log should succeed and walk both files.
        let ok = verify_log(&path, None).unwrap();
        assert!(
            ok.files_walked >= 2,
            "must walk at least 2 files, got {}",
            ok.files_walked
        );
    }

    #[test]
    fn verify_log_reports_per_file_entries_across_rotation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        {
            let mut writer = AuditWriter::open(path.clone(), None).unwrap();
            let entry = new_tool_invocation(
                "pre_rotation",
                "stellar:testnet",
                vec![],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            );
            writer.write_entry(entry).unwrap();
        }

        {
            use std::io::Write as _;

            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            let padding = vec![b'\n'; ROTATION_THRESHOLD_BYTES as usize];
            f.write_all(&padding).unwrap();
        }

        {
            let mut writer = AuditWriter::open(path.clone(), None).unwrap();
            let entry = new_tool_invocation(
                "post_rotation",
                "stellar:testnet",
                vec![],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            );
            writer.write_entry(entry).unwrap();
        }

        let ok = verify_log(&path, None).unwrap();
        assert_eq!(ok.files_walked, 2);
        assert_eq!(ok.entries_verified, 3);
        assert_eq!(ok.per_file.len(), 2);
        assert_ne!(ok.per_file[0].path, path);
        assert_eq!(ok.per_file[0].entries_verified, 2);
        assert_eq!(ok.per_file[0].hmac_verified, None);
        assert_eq!(ok.per_file[1].path, path);
        assert_eq!(ok.per_file[1].entries_verified, 1);
        assert_eq!(ok.per_file[1].hmac_verified, None);
    }

    /// With rotated siblings present, an absent active file and NO live
    /// writer (sidecar lock unheld) is a genuine integrity gap: the
    /// rotation-window tolerance gives up on its first probe and `verify_log`
    /// reports `RotationGap`. The elapsed ceiling is a hang guard only, far
    /// above the retry budget — immediacy is the probe's documented contract,
    /// not something a wall-clock assertion can pin without flaking.
    #[test]
    fn verify_missing_active_no_writer_reports_rotation_gap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        {
            let mut writer = AuditWriter::open(path.clone(), None).unwrap();
            writer
                .write_entry(new_tool_invocation(
                    "pre_rotation",
                    "stellar:testnet",
                    vec![],
                    None,
                    None,
                    PolicyDecision::Allow,
                    None,
                    uuid::Uuid::new_v4().to_string(),
                ))
                .unwrap();
            writer.force_rotate_for_test().unwrap();
            writer
                .write_entry(new_tool_invocation(
                    "post_rotation",
                    "stellar:testnet",
                    vec![],
                    None,
                    None,
                    PolicyDecision::Allow,
                    None,
                    uuid::Uuid::new_v4().to_string(),
                ))
                .unwrap();
        } // writer dropped: sidecar lock released.

        fs::remove_file(&path).unwrap();

        let started = std::time::Instant::now();
        let err = verify_log(&path, None)
            .expect_err("an absent active file with no live writer is a gap");
        assert!(
            matches!(err, VerifyError::RotationGap { .. }),
            "expected RotationGap, got {err:?}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "gap reporting must never hang"
        );
    }

    /// The transient active-file absence during a live writer's rotation is
    /// waited out by `verify_log` too (the writer-independent entry point):
    /// with the sidecar lock held and the file reappearing inside the retry
    /// budget, verification succeeds over the full chain.
    ///
    /// The file is restored from inside the retry loop, on the verifying
    /// thread, via the test-only retry observer (restore at attempt index 1,
    /// exit on attempt index 2's absence check). This makes the recovery
    /// deterministic and immune to scheduling load rather than racing an
    /// external restorer thread against the wall clock.
    #[test]
    fn verify_active_transient_absence_while_writer_alive_recovers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        writer
            .write_entry(new_tool_invocation(
                "pre_rotation",
                "stellar:testnet",
                vec![],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            ))
            .unwrap();
        writer.force_rotate_for_test().unwrap();
        writer
            .write_entry(new_tool_invocation(
                "post_rotation",
                "stellar:testnet",
                vec![],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            ))
            .unwrap();

        let saved_active_contents = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();

        let observed_attempts = Rc::new(RefCell::new(Vec::<u32>::new()));
        let observed_for_hook = Rc::clone(&observed_attempts);
        let restore_path = path.clone();
        let _observer_guard = install_rotation_window_retry_observer(move |attempt| {
            observed_for_hook.borrow_mut().push(attempt);
            if attempt == 1 {
                fs::write(&restore_path, &saved_active_contents).unwrap();
            }
        });

        // The writer stays alive (lock held) across the verification.
        let result = verify_log(&path, None);
        drop(writer);

        let ok = result.expect("transient rotation-window absence must not surface as RotationGap");
        assert_eq!(ok.files_walked, 2);
        // pre_rotation + the rotation-handoff row in the archive + post_rotation.
        assert_eq!(ok.entries_verified, 3);
        assert_eq!(
            *observed_attempts.borrow(),
            vec![0, 1],
            "attempt 0 observes the still-absent file, attempt 1 restores it, \
             attempt 2's absence check exits before reaching the observer"
        );
    }

    /// A lock-held active-file absence that never reappears exhausts the retry
    /// bound and is then reported as a `RotationGap` — `verify_log` never turns
    /// a genuine gap into success. The observer never restores the file, so it
    /// fires on every iteration; the recorded sequence pins that the loop
    /// probes exactly the full bound (indices 0..ROTATION_WINDOW_RETRY_ATTEMPTS)
    /// before giving up.
    #[test]
    fn verify_active_absence_lock_held_exhausts_bound_then_reports_gap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        writer
            .write_entry(new_tool_invocation(
                "pre_rotation",
                "stellar:testnet",
                vec![],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            ))
            .unwrap();
        writer.force_rotate_for_test().unwrap();
        writer
            .write_entry(new_tool_invocation(
                "post_rotation",
                "stellar:testnet",
                vec![],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            ))
            .unwrap();

        // Active file absent, rotated sibling present, writer (and its sidecar
        // lock) still alive — the loop retries the full bound before giving up.
        fs::remove_file(&path).unwrap();

        let observed_attempts = Rc::new(RefCell::new(Vec::<u32>::new()));
        let observed_for_hook = Rc::clone(&observed_attempts);
        let _observer_guard = install_rotation_window_retry_observer(move |attempt| {
            observed_for_hook.borrow_mut().push(attempt);
        });

        let err = verify_log(&path, None)
            .expect_err("a lock-held active-file absence that never reappears is a gap");
        drop(writer);

        assert!(
            matches!(err, VerifyError::RotationGap { .. }),
            "expected RotationGap, got {err:?}"
        );
        assert_eq!(
            *observed_attempts.borrow(),
            (0..ROTATION_WINDOW_RETRY_ATTEMPTS).collect::<Vec<u32>>(),
            "a lock-held, never-reappearing active file must probe exactly the full retry bound"
        );
    }

    #[test]
    fn verify_rejects_rotation_handoff_in_active_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        writer
            .write_entry(new_tool_invocation(
                "stellar_pay_commit",
                "stellar:testnet",
                vec![],
                None,
                None,
                PolicyDecision::Allow,
                None,
                "req-1",
            ))
            .unwrap();

        let mut handoff =
            AuditEntry::new_rotation_handoff("audit.jsonl.20260428T010203004", "req", false);
        handoff.previous_entry_hash = writer.last_entry_hash().to_owned();
        let json = serde_json::to_string(&handoff).unwrap();
        drop(writer);

        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "{json}").unwrap();

        let err = verify_log(&path, None).unwrap_err();

        assert!(
            matches!(
                err,
                VerifyError::ChainBroken {
                    reason: "rotation_handoff_in_active_file",
                    ..
                }
            ),
            "expected active-file handoff ChainBroken, got {err:?}"
        );
    }

    #[test]
    fn verify_substitute_rotated_file_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        write_with_forced_rotation(dir.path(), "audit.jsonl", 2);

        // Find the rotated file and replace it with a fresh chain
        // (started from ZERO_BLOCK_HASH — simulates substitution).
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
        assert!(
            !rotated_files.is_empty(),
            "must have at least one rotated file"
        );

        // Write a fresh single-entry chain to the rotated file's path.
        let rotated_path = &rotated_files[0];
        {
            // Overwrite the rotated file to simulate substitution.
            fs::remove_file(rotated_path).unwrap();
            let mut fresh_writer = AuditWriter::open(rotated_path.clone(), None).unwrap();
            let entry = new_tool_invocation(
                "substitute",
                "stellar:testnet",
                vec![],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            );
            fresh_writer.write_entry(entry).unwrap();
        }

        // Verification must fail because the cross-file chain is broken.
        let result = verify_log(&path, None);
        assert!(
            matches!(
                result,
                Err(VerifyError::ChainBroken { .. } | VerifyError::RotationGap { .. })
            ),
            "expected ChainBroken or RotationGap for substituted file, got {result:?}"
        );
    }

    #[test]
    fn verify_dropped_handoff_entry_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        write_with_forced_rotation(dir.path(), "audit.jsonl", 2);

        // Find the rotated file and remove its last entry (the handoff entry).
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
        assert!(!rotated_files.is_empty());

        let rotated_path = &rotated_files[0];
        let contents = fs::read_to_string(rotated_path).unwrap();
        let mut lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
        assert!(!lines.is_empty());
        // Remove the last line (rotation handoff).
        lines.pop();
        fs::write(rotated_path, lines.join("\n") + "\n").unwrap();

        // Verification should fail because the handoff is missing.
        let result = verify_log(&path, None);
        assert!(
            result.is_err(),
            "expected error when handoff entry is dropped, got Ok"
        );
    }

    /// Verifies that `verify_log` with an HMAC key succeeds and reports
    /// `hmac_verified = true` after a rotation when sidecars are present for
    /// both the rotated file and the new active file.
    #[test]
    fn verify_chain_across_rotation_with_hmac_ok() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let key: [u8; 32] = [0xABu8; 32];

        // Write entries with the HMAC key, force rotation.
        {
            let mut writer =
                AuditWriter::open_keyed_unanchored_for_test(path.clone(), Zeroizing::new(key))
                    .unwrap();
            // Write a first entry — this creates the root_hmac sidecar.
            let entry = new_tool_invocation(
                "pre_rotation",
                "stellar:testnet",
                vec![],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            );
            writer.write_entry(entry).unwrap();
            drop(writer);

            // Pad the file via append (not overwrite) so the first entry is
            // preserved.  The HMAC sidecar was signed for the first entry's
            // canonical body; overwriting would corrupt the archive's HMAC.
            {
                use std::io::Write as _;
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap();
                let padding = vec![b'\n'; ROTATION_THRESHOLD_BYTES as usize];
                f.write_all(&padding).unwrap();
            }

            let mut writer2 =
                AuditWriter::open_keyed_unanchored_for_test(path.clone(), Zeroizing::new(key))
                    .unwrap();
            // Rotation happens here; a new active file + sidecar are created.
            let entry2 = new_tool_invocation(
                "post_rotation",
                "stellar:testnet",
                vec![],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            );
            writer2.write_entry(entry2).unwrap();
        }

        // Verify the full chain with the HMAC key.
        let ok = verify_log(&path, Some(&key))
            .expect("verify_chain_across_rotation_with_hmac_ok: verify_log failed");

        assert!(
            ok.files_walked >= 2,
            "must walk at least 2 files across rotation; walked {}",
            ok.files_walked
        );
        assert!(
            ok.entries_verified >= 1,
            "must verify at least 1 entry; got {}",
            ok.entries_verified
        );
        assert!(
            ok.per_file
                .iter()
                .all(|file| file.hmac_verified == Some(true))
        );
    }

    #[test]
    fn verify_handoff_next_file_name_mismatch_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        write_with_forced_rotation(dir.path(), "audit.jsonl", 2);

        // Find the rotated file and corrupt the handoff's next_file_name.
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
        assert!(!rotated_files.is_empty());

        let rotated_path = &rotated_files[0];
        let contents = fs::read_to_string(rotated_path).unwrap();
        let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
        assert!(!lines.is_empty());

        // Find the handoff line and corrupt its next_file_name.
        let mut new_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
        for line in new_lines.iter_mut() {
            if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(line)
                && v["kind"].as_str() == Some("audit_rotation_handoff")
            {
                v["next_file_name"] = serde_json::Value::String("wrong_file.jsonl".to_owned());
                *line = serde_json::to_string(&v).unwrap();
                break;
            }
        }
        fs::write(rotated_path, new_lines.join("\n") + "\n").unwrap();

        let result = verify_log(&path, None);
        assert!(
            result.is_err(),
            "expected error on handoff next_file_name mismatch, got Ok"
        );
    }

    #[test]
    fn verify_handoff_next_file_name_mismatch_sanitizes_invalid_name() {
        let malicious_name = "audit.jsonl.\u{1b}[31mBAD\nnext";
        let rendered = rotation_gap_for_corrupt_handoff_name(malicious_name);

        assert!(
            rendered.contains("<invalid: "),
            "invalid handoff name must be summarized: {rendered:?}"
        );
        assert!(
            !rendered.contains('\u{1b}') && !rendered.contains('\n'),
            "terminal-control characters must not be rendered: {rendered:?}"
        );
        assert!(
            !rendered.contains("BAD") && !rendered.contains("next"),
            "attacker-controlled filename bytes must not be rendered: {rendered:?}"
        );
    }

    #[test]
    fn verify_handoff_next_file_name_mismatch_sanitizes_null_byte_name() {
        let malicious_name = "audit.jsonl.\u{0}injected";
        let rendered = rotation_gap_for_corrupt_handoff_name(malicious_name);

        assert!(
            rendered.contains(&format!("<invalid: {} bytes>", malicious_name.len())),
            "invalid handoff name must be summarized: {rendered:?}"
        );
        assert!(
            !rendered.contains('\u{0}') && !rendered.contains("injected"),
            "null byte and attacker text must not be rendered: {rendered:?}"
        );
    }

    #[test]
    fn verify_handoff_next_file_name_mismatch_sanitizes_oversized_name() {
        let raw_suffix = "a".repeat(8 * 1024);
        let malicious_name = format!("audit.jsonl.{raw_suffix}");
        let rendered = rotation_gap_for_corrupt_handoff_name(&malicious_name);

        assert!(
            rendered.contains(&format!("<invalid: {} bytes>", malicious_name.len())),
            "oversized handoff name must be summarized: {rendered:?}"
        );
        assert!(
            !rendered.contains(&raw_suffix),
            "oversized attacker-controlled bytes must not be rendered"
        );
    }

    // ── verify_log_with_health tests ──────────────────────────────────────────

    #[test]
    fn verify_log_with_health_delegates_to_verify_log_and_reports_non_degraded() {
        use crate::audit_log::health::AuditWriterHealth;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 3);

        let health = AuditWriterHealth::new();
        let handle = health.handle();

        let result = super::verify_log_with_health(&path, None, None, &handle)
            .expect("verify_log_with_health failed");

        // The verify_ok sub-field must agree with a plain verify_log call.
        assert_eq!(result.verify_ok.entries_verified, 3);
        assert_eq!(result.verify_ok.files_walked, 1);
        // Health flag was never set — must report non-degraded.
        assert!(!result.audit_writer_degraded);
    }

    #[test]
    fn verify_log_with_health_reports_degraded_when_health_poisoned() {
        use crate::audit_log::health::AuditWriterHealth;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 1);

        let health = AuditWriterHealth::new();
        let handle = health.handle();
        handle.mark_degraded();

        let result = super::verify_log_with_health(&path, None, None, &handle)
            .expect("verify_log_with_health failed");

        assert_eq!(result.verify_ok.entries_verified, 1);
        // Health flag was set before the call — must be visible in the result.
        assert!(result.audit_writer_degraded);
    }

    #[test]
    fn verify_log_with_health_propagates_verify_log_errors() {
        use crate::audit_log::health::AuditWriterHealth;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 2);

        // Tamper with the log so verify_log returns ChainBroken.
        let contents = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = contents.lines().map(|l| l.to_string()).collect();
        lines.remove(0);
        fs::write(&path, lines.join("\n") + "\n").unwrap();

        let health = AuditWriterHealth::new();
        let handle = health.handle();

        let result = super::verify_log_with_health(&path, None, None, &handle);
        assert!(
            matches!(result, Err(VerifyError::ChainBroken { .. })),
            "expected ChainBroken propagated through verify_log_with_health, got {result:?}"
        );
    }

    #[test]
    fn verify_ok_with_health_equality() {
        use super::VerifyOkWithHealth;

        let v1 = VerifyOkWithHealth {
            verify_ok: VerifyOk {
                entries_verified: 5,
                files_walked: 2,
                per_file: vec![],
                warnings: vec![],
                hmac_verified: false,
                active_tip: None,
                entry_tags_verified: false,
                entry_tags_boundary: None,
            },
            audit_writer_degraded: false,
        };
        let v2 = v1.clone();
        assert_eq!(v1, v2);
        assert_eq!(v1.verify_ok.entries_verified, 5);
    }

    // ── parse_audit_timestamp_ms boundary tests ───────────────────────────────

    #[test]
    fn parse_timestamp_rejects_wrong_length() {
        // Too short — 23 chars instead of 24.
        let err = parse_audit_timestamp_ms("2026-05-06T12:00:00.00Z");
        assert!(err.is_err(), "expected error for too-short timestamp");
        assert!(
            err.unwrap_err().contains("YYYY-MM-DDTHH"),
            "error should mention format"
        );
    }

    #[test]
    fn parse_timestamp_rejects_wrong_separator_positions() {
        // 'T' in wrong position (position 10 replaced with space).
        let err = parse_audit_timestamp_ms("2026-05-06 12:00:00.000Z");
        assert!(err.is_err());
    }

    #[test]
    fn parse_timestamp_rejects_year_1969() {
        // Year before 1970 is out of supported range.
        let err = parse_audit_timestamp_ms("1969-01-01T00:00:00.000Z");
        assert!(err.is_err(), "expected error for year 1969");
        assert!(
            err.unwrap_err().contains("out of supported range"),
            "error should mention out of range"
        );
    }

    #[test]
    fn parse_timestamp_rejects_year_2100() {
        // Year 2100 is beyond the supported ceiling.
        let err = parse_audit_timestamp_ms("2100-01-01T00:00:00.000Z");
        assert!(err.is_err(), "expected error for year 2100");
    }

    #[test]
    fn parse_timestamp_rejects_month_zero() {
        let err = parse_audit_timestamp_ms("2026-00-01T00:00:00.000Z");
        assert!(err.is_err(), "expected error for month 0");
        assert!(
            err.unwrap_err().contains("out of supported range"),
            "error must cite out-of-range"
        );
    }

    #[test]
    fn parse_timestamp_rejects_month_13() {
        let err = parse_audit_timestamp_ms("2026-13-01T00:00:00.000Z");
        assert!(err.is_err(), "expected error for month 13");
    }

    #[test]
    fn parse_timestamp_rejects_day_zero() {
        let err = parse_audit_timestamp_ms("2026-01-00T00:00:00.000Z");
        assert!(err.is_err(), "expected error for day 0");
        assert!(
            err.unwrap_err().contains("day out of range"),
            "error must cite day out of range"
        );
    }

    #[test]
    fn parse_timestamp_rejects_day_beyond_month_max() {
        // April has 30 days; day 31 is invalid.
        let err = parse_audit_timestamp_ms("2026-04-31T00:00:00.000Z");
        assert!(err.is_err(), "expected error for April 31");
        assert!(
            err.unwrap_err().contains("day out of range"),
            "error must cite day out of range for month"
        );
    }

    #[test]
    fn parse_timestamp_rejects_feb_29_in_non_leap_year() {
        // 2026 is not a leap year; Feb 29 is invalid.
        let err = parse_audit_timestamp_ms("2026-02-29T00:00:00.000Z");
        assert!(err.is_err(), "expected error for Feb 29 in 2026");
        assert!(
            err.unwrap_err().contains("day out of range"),
            "error must cite day out of range for month"
        );
    }

    #[test]
    fn parse_timestamp_accepts_feb_29_in_leap_year() {
        // 2024 is divisible by 4 but not 100 → leap year.
        let result = parse_audit_timestamp_ms("2024-02-29T00:00:00.000Z");
        assert!(
            result.is_ok(),
            "Feb 29 2024 must be accepted as valid: {result:?}"
        );
    }

    #[test]
    fn parse_timestamp_rejects_feb_29_in_century_non_leap() {
        // 2100 is divisible by 100 but not 400 → not a leap year, but also
        // year > 2099 is rejected first (out of range). Use 1900 instead —
        // but 1900 < 1970, also out of range. 2100 > 2099, out of range too.
        // The only accessible century-non-leap year inside [1970,2099] would
        // require century 1900 or 2100 which are both out of range for the
        // parser. This test documents the constraint: the parser's [1970,2099]
        // range excludes all century-non-leap years, so no additional test case
        // is possible for this specific path.  Coverage of `is_leap_year_u32`
        // for year % 400 is provided by the 2000 test below.
        // The 2100 case is captured by the rejects_year_2100 test above.
        let result = parse_audit_timestamp_ms("2100-02-29T00:00:00.000Z");
        assert!(result.is_err(), "2100 must be rejected (out of range year)");
    }

    #[test]
    fn parse_timestamp_accepts_feb_29_in_year_2000() {
        // 2000 is divisible by 400 → leap year.
        let result = parse_audit_timestamp_ms("2000-02-29T00:00:00.000Z");
        assert!(result.is_ok(), "Feb 29 2000 must be accepted: {result:?}");
    }

    #[test]
    fn parse_timestamp_rejects_hour_24() {
        let err = parse_audit_timestamp_ms("2026-05-06T24:00:00.000Z");
        assert!(err.is_err(), "expected error for hour 24");
        assert!(
            err.unwrap_err().contains("out of supported range"),
            "error must cite out of range"
        );
    }

    #[test]
    fn parse_timestamp_rejects_minute_60() {
        let err = parse_audit_timestamp_ms("2026-05-06T00:60:00.000Z");
        assert!(err.is_err(), "expected error for minute 60");
    }

    #[test]
    fn parse_timestamp_rejects_second_60() {
        let err = parse_audit_timestamp_ms("2026-05-06T00:00:60.000Z");
        assert!(err.is_err(), "expected error for second 60");
    }

    #[test]
    fn parse_timestamp_rejects_non_decimal_digits() {
        // Non-decimal character in the year field.
        let err = parse_audit_timestamp_ms("202X-05-06T00:00:00.000Z");
        assert!(err.is_err(), "expected error for non-decimal year");
        assert!(
            err.unwrap_err().contains("non-decimal"),
            "error must mention non-decimal"
        );
    }

    #[test]
    fn parse_timestamp_epoch_is_zero_ms() {
        // 1970-01-01T00:00:00.000Z is Unix epoch — must produce exactly 0.
        let ms = parse_audit_timestamp_ms("1970-01-01T00:00:00.000Z").unwrap();
        assert_eq!(ms, 0, "Unix epoch must map to 0 ms");
    }

    #[test]
    fn parse_timestamp_known_value_2026_05_06_correct() {
        // 2026-05-06T00:00:00.000Z: compute expected ms from first principles.
        // Days from 1970-01-01 to 2026-01-01: sum over years 1970..=2025.
        // Then add days for Jan (31) + Feb (28, non-leap) + Mar (31) + Apr (30) = 120 days.
        // Plus 5 more days for May 1-5.
        // Full calculation via known reference: 2026-05-06 = 20579 days since epoch.
        let ms = parse_audit_timestamp_ms("2026-05-06T00:00:00.000Z").unwrap();
        let expected_days: u64 = 20579;
        assert_eq!(
            ms,
            expected_days * 86_400 * 1_000,
            "2026-05-06T00:00:00.000Z must map to {expected} ms",
            expected = expected_days * 86_400 * 1_000
        );
    }

    #[test]
    fn parse_timestamp_millisecond_precision_preserved() {
        // Same date/time as above but with millisecond = 999.
        let ms_000 = parse_audit_timestamp_ms("2026-05-06T00:00:00.000Z").unwrap();
        let ms_999 = parse_audit_timestamp_ms("2026-05-06T00:00:00.999Z").unwrap();
        assert_eq!(
            ms_999 - ms_000,
            999,
            "millisecond component must be added verbatim"
        );
    }

    // ── days_in_month coverage ────────────────────────────────────────────────

    #[test]
    fn days_in_month_31_day_months() {
        for m in [1u32, 3, 5, 7, 8, 10, 12] {
            assert_eq!(days_in_month(2026, m), 31, "month {m} should have 31 days");
        }
    }

    #[test]
    fn days_in_month_30_day_months() {
        for m in [4u32, 6, 9, 11] {
            assert_eq!(days_in_month(2026, m), 30, "month {m} should have 30 days");
        }
    }

    #[test]
    fn days_in_month_february_non_leap() {
        // 2026 is not a leap year.
        assert_eq!(days_in_month(2026, 2), 28);
    }

    #[test]
    fn days_in_month_february_leap() {
        // 2024 is divisible by 4 and not 100 → leap.
        assert_eq!(days_in_month(2024, 2), 29);
    }

    #[test]
    fn days_in_month_invalid_month_returns_zero() {
        // The wildcard arm returns 0 for invalid month values.
        assert_eq!(days_in_month(2026, 0), 0);
        assert_eq!(days_in_month(2026, 13), 0);
    }

    // ── is_leap_year_u32 coverage ─────────────────────────────────────────────

    #[test]
    fn is_leap_year_divisible_by_4_not_100() {
        assert!(is_leap_year_u32(2024));
        assert!(is_leap_year_u32(1984));
    }

    #[test]
    fn is_leap_year_divisible_by_400() {
        // 2000 is divisible by 400 → leap year.
        assert!(is_leap_year_u32(2000));
        assert!(is_leap_year_u32(1600));
    }

    #[test]
    fn is_not_leap_year_divisible_by_100_not_400() {
        // 1900 is divisible by 100 but not 400 → not leap.
        assert!(!is_leap_year_u32(1900));
    }

    #[test]
    fn is_not_leap_year_odd_year() {
        assert!(!is_leap_year_u32(2025));
        assert!(!is_leap_year_u32(2027));
    }

    // ── PartialRotationState Display / Error ──────────────────────────────────

    #[test]
    fn partial_rotation_state_orphan_sidecar_display_contains_basename_only() {
        let state = PartialRotationState::OrphanSidecar {
            sidecar_path: PathBuf::from(
                "/home/user/audit/audit.jsonl.20260506T120000000.root_hmac",
            ),
            expected_log_path: PathBuf::from("/home/user/audit/audit.jsonl.20260506T120000000"),
        };
        let display = state.to_string();
        // Must contain the basename of the sidecar file.
        assert!(
            display.contains("audit.jsonl.20260506T120000000.root_hmac"),
            "display must contain sidecar basename: {display}"
        );
        // Must NOT leak the full filesystem path.
        assert!(
            !display.contains("/home/user/audit"),
            "display must not leak full path: {display}"
        );
    }

    #[test]
    fn partial_rotation_state_mid_rename_display_contains_size() {
        let state = PartialRotationState::MidRename {
            tmp_path: PathBuf::from("/home/user/audit/audit.jsonl.tmp"),
            size_bytes: 4096,
        };
        let display = state.to_string();
        assert!(
            display.contains("4096 bytes"),
            "display must include size: {display}"
        );
        assert!(
            display.contains("audit.jsonl.tmp"),
            "display must include tmp file basename: {display}"
        );
        assert!(
            !display.contains("/home/user"),
            "display must not leak directory: {display}"
        );
    }

    #[test]
    fn partial_rotation_state_partial_handoff_write_display_contains_offset_and_size() {
        let state = PartialRotationState::PartialHandoffWrite {
            log_path: PathBuf::from("/home/user/audit/audit.jsonl"),
            file_size_bytes: 10240,
            partial_entry_offset: 9999,
        };
        let display = state.to_string();
        assert!(
            display.contains("10240 bytes"),
            "display must include file size: {display}"
        );
        assert!(
            display.contains("9999"),
            "display must include partial entry offset: {display}"
        );
        assert!(
            display.contains("audit.jsonl"),
            "display must include log basename: {display}"
        );
    }

    // ── VerifyError::PartialRotation wire_code and Display ────────────────────

    #[test]
    fn verify_error_partial_rotation_wire_code() {
        let err = VerifyError::PartialRotation {
            state: PartialRotationState::MidRename {
                tmp_path: PathBuf::from("/tmp/audit.jsonl.tmp"),
                size_bytes: 0,
            },
            recovery_hint: "see runbook".to_owned(),
        };
        assert_eq!(err.wire_code(), "audit.partial_rotation");
    }

    #[test]
    fn verify_error_partial_rotation_display_contains_recovery_hint() {
        let err = VerifyError::PartialRotation {
            state: PartialRotationState::OrphanSidecar {
                sidecar_path: PathBuf::from("/tmp/audit.jsonl.root_hmac"),
                expected_log_path: PathBuf::from("/tmp/audit.jsonl"),
            },
            recovery_hint: "docs/maintainers/audit-log-recovery.md".to_owned(),
        };
        let display = err.to_string();
        assert!(
            display.contains("audit.partial_rotation"),
            "display must include wire code prefix: {display}"
        );
        assert!(
            display.contains("docs/maintainers/audit-log-recovery.md"),
            "display must include recovery hint: {display}"
        );
    }

    // ── VerifyError::SignerSetCanonicalBody wire_code ─────────────────────────

    #[test]
    fn verify_error_signer_set_canonical_body_wire_code() {
        use crate::audit_log::signer_set::SignerSetCanonicalBodyError;

        let inner = SignerSetCanonicalBodyError::MalformedObservedSignerSet {
            reason: "signer_ids length mismatch",
        };
        let err = VerifyError::SignerSetCanonicalBody(inner);
        assert_eq!(err.wire_code(), "audit.signer_set_canonical_body");
    }

    // ── VerifyError Display format coverage ───────────────────────────────────

    #[test]
    fn verify_error_chain_broken_display_contains_reason_line_and_file() {
        let err = VerifyError::ChainBroken {
            line: 7,
            file: "audit.jsonl".to_owned(),
            reason: "previous_entry_hash_mismatch",
        };
        let s = err.to_string();
        assert!(
            s.contains("audit.chain_broken"),
            "must contain wire code: {s}"
        );
        assert!(
            s.contains("previous_entry_hash_mismatch"),
            "must contain reason: {s}"
        );
        assert!(s.contains('7'), "must contain line number: {s}");
        assert!(s.contains("audit.jsonl"), "must contain file name: {s}");
    }

    #[test]
    fn verify_error_hmac_mismatch_display() {
        let err = VerifyError::HmacMismatch {
            file: "mylog.jsonl".to_owned(),
        };
        let s = err.to_string();
        assert!(
            s.contains("audit.hmac_mismatch"),
            "must contain wire code: {s}"
        );
        assert!(s.contains("mylog.jsonl"), "must contain filename: {s}");
    }

    #[test]
    fn verify_error_non_regular_file_log_path_display_basename_only() {
        // Display must emit only the basename, not the full path.
        let err = VerifyError::NonRegularFileLogPath {
            path: PathBuf::from("/home/user/very/secret/path/audit.jsonl"),
        };
        let s = err.to_string();
        assert!(s.contains("audit.jsonl"), "must contain basename: {s}");
        assert!(
            !s.contains("/home/user/very"),
            "must NOT contain full path: {s}"
        );
    }

    // ── basename_lossy non-UTF-8 path ─────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn basename_lossy_non_utf8_returns_sentinel() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        // A path whose filename component is not valid UTF-8.
        let bad = OsString::from_vec(vec![0xFF, 0xFE]);
        let path = PathBuf::from(bad);
        let result = basename_lossy(&path);
        assert_eq!(
            result, "<non-utf8>",
            "non-UTF-8 basename must return sentinel"
        );
    }

    // ── sanitize_handoff_next_file_name: valid rotated sibling passes through ──

    #[test]
    fn sanitize_handoff_returns_name_unchanged_for_valid_rotated_sibling() {
        // A correctly-formed rotated sibling should NOT be redacted.
        let stem = "audit.jsonl";
        let valid_name = "audit.jsonl.20260506T120000000";
        let result = sanitize_handoff_next_file_name(stem, valid_name);
        assert_eq!(
            result, valid_name,
            "valid rotated sibling name must be returned unchanged"
        );
    }

    #[test]
    fn sanitize_handoff_redacts_non_sibling_name() {
        let stem = "audit.jsonl";
        let bad_name = "completely_unrelated_file.txt";
        let result = sanitize_handoff_next_file_name(stem, bad_name);
        assert!(
            result.starts_with("<invalid:"),
            "non-sibling name must be sanitized: {result}"
        );
        assert!(
            !result.contains("completely_unrelated_file"),
            "attacker-controlled text must not appear: {result}"
        );
    }

    // ── VerifyWarning threshold boundary ─────────────────────────────────────

    #[test]
    fn verify_log_does_not_warn_at_exactly_threshold() {
        // Drift of exactly BACKWARD_TS_WARN_THRESHOLD_MS (60_000 ms) must NOT
        // emit a warning — the condition is `drift_ms > THRESHOLD`.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        // t1 = 00:01:00.000, t2 = 00:00:00.000 → drift = 60_000 ms exactly.
        write_entries_with_timestamps(
            &path,
            &["2026-05-06T00:01:00.000Z", "2026-05-06T00:00:00.000Z"],
        );

        let ok = verify_log(&path, None).unwrap();
        assert!(
            ok.warnings.is_empty(),
            "drift at exactly BACKWARD_TS_WARN_THRESHOLD_MS must not warn: {:?}",
            ok.warnings
        );
    }

    #[test]
    fn verify_log_warns_at_one_ms_above_threshold() {
        // Drift of BACKWARD_TS_WARN_THRESHOLD_MS + 1 (60_001 ms) MUST emit a warning.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        // t1 = 00:01:00.001, t2 = 00:00:00.000 → drift = 60_001 ms.
        write_entries_with_timestamps(
            &path,
            &["2026-05-06T00:01:00.001Z", "2026-05-06T00:00:00.000Z"],
        );

        let ok = verify_log(&path, None).unwrap();
        assert_eq!(
            ok.warnings.len(),
            1,
            "drift of 60_001 ms must produce exactly one warning"
        );
        let VerifyWarning::BackwardTimestampJump { drift_ms, .. } = &ok.warnings[0] else {
            panic!(
                "expected a backward timestamp jump, got {:?}",
                ok.warnings[0]
            );
        };
        assert_eq!(*drift_ms, 60_001);
    }

    // ── verify_log: missing primary log file returns LogNotFound ──────────────

    #[test]
    fn verify_log_missing_primary_file_returns_log_not_found() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.jsonl");
        // No file created — the primary (only) log is absent.

        let result = verify_log(&path, None);
        assert!(
            matches!(result, Err(VerifyError::LogNotFound { .. })),
            "missing primary log file must return LogNotFound, got {result:?}"
        );
        assert_eq!(
            result.unwrap_err().wire_code(),
            "audit.log_not_found",
            "missing primary log must carry the audit.log_not_found wire code"
        );
    }

    // ── verify_log: blank lines in log are ignored ─────────────────────────────

    #[test]
    fn verify_log_blank_lines_are_skipped() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 2);

        // Insert blank lines between the entries.
        let contents = fs::read_to_string(&path).unwrap();
        let with_blanks = contents.replace('\n', "\n\n");
        fs::write(&path, with_blanks).unwrap();

        let ok = verify_log(&path, None).unwrap();
        assert_eq!(
            ok.entries_verified, 2,
            "blank lines must be skipped; expected 2 entries verified"
        );
    }

    // ── verify_log: invalid JSON line returns ParseError ─────────────────────

    #[test]
    fn verify_log_invalid_json_returns_parse_error_with_line_number() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        // Write one valid entry, then append a malformed JSON line.
        write_entries(&path, 1);
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, "{{NOT VALID JSON}}").unwrap();

        let result = verify_log(&path, None);
        assert!(
            matches!(result, Err(VerifyError::ParseError { line: 2, .. })),
            "invalid JSON on line 2 must return ParseError at line 2, got {result:?}"
        );
    }

    // ── verify_log: invalid timestamp in entry ────────────────────────────────

    #[test]
    fn verify_log_invalid_timestamp_in_entry_returns_parse_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        let mut entry = new_tool_invocation(
            "test_tool",
            "stellar:testnet",
            vec![],
            None,
            None,
            PolicyDecision::Allow,
            None,
            uuid::Uuid::new_v4().to_string(),
        );
        // Set a deliberately invalid timestamp that will fail parse_audit_timestamp_ms.
        // Exactly 24 bytes but wrong separator positions so the format check rejects it.
        entry.ts = "NOTAVALIDTIMESTAMP123456".to_owned();
        writer.write_entry(entry).unwrap();
        drop(writer);

        let result = verify_log(&path, None);
        assert!(
            matches!(result, Err(VerifyError::ParseError { .. })),
            "invalid timestamp must return ParseError, got {result:?}"
        );
    }

    // ── per_file hmac_verified field ──────────────────────────────────────────

    #[test]
    fn per_file_hmac_verified_is_some_true_when_hmac_key_provided() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let key = [0x99u8; 32];
        let mut writer =
            AuditWriter::open_keyed_unanchored_for_test(path.clone(), zeroize::Zeroizing::new(key))
                .unwrap();
        writer
            .write_entry(new_tool_invocation(
                "test",
                "stellar:testnet",
                vec![],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            ))
            .unwrap();
        drop(writer);

        let ok = verify_log(&path, Some(&key)).unwrap();
        assert_eq!(ok.per_file.len(), 1);
        assert_eq!(
            ok.per_file[0].hmac_verified,
            Some(true),
            "per_file.hmac_verified must be Some(true) when HMAC key was supplied and verified"
        );
    }

    #[test]
    fn per_file_hmac_verified_is_none_when_no_key_provided() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        write_entries(&path, 1);

        let ok = verify_log(&path, None).unwrap();
        assert_eq!(ok.per_file.len(), 1);
        assert_eq!(
            ok.per_file[0].hmac_verified, None,
            "per_file.hmac_verified must be None when no HMAC key supplied"
        );
    }

    // ── verify_hmac_wrong_key_returns_mismatch ─────────────────────────────────

    #[test]
    fn verify_hmac_wrong_key_returns_hmac_mismatch() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        // Write with key A.
        let key_a = [0xAAu8; 32];
        let key_b = [0xBBu8; 32];
        let mut writer = AuditWriter::open_keyed_unanchored_for_test(
            path.clone(),
            zeroize::Zeroizing::new(key_a),
        )
        .unwrap();
        writer
            .write_entry(new_tool_invocation(
                "test",
                "stellar:testnet",
                vec![],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            ))
            .unwrap();
        drop(writer);

        // Verify with key B — must fail with HmacMismatch.
        let result = verify_log(&path, Some(&key_b));
        assert!(
            matches!(result, Err(VerifyError::HmacMismatch { .. })),
            "verifying with wrong key must return HmacMismatch, got {result:?}"
        );
    }

    // ── collect_file_chain: non-existent directory is handled gracefully ───────

    #[test]
    fn collect_file_chain_non_existent_dir_returns_only_active_file() {
        let dir = TempDir::new().unwrap();
        let non_existent_dir = dir.path().join("subdir_that_does_not_exist");
        let path = non_existent_dir.join("audit.jsonl");

        // collect_file_chain does not require the directory to exist (dir.exists()
        // guard skips read_dir); it returns a chain with only the active file.
        let chain = collect_file_chain(&path).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], path);
    }

    // ── FileVerifyResult serialisation round-trip ────────────────────────────

    #[test]
    fn file_verify_result_serde_round_trip() {
        let original = FileVerifyResult {
            path: PathBuf::from("/tmp/audit.jsonl"),
            entries_verified: 42,
            hmac_verified: Some(true),
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: FileVerifyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn file_verify_result_serde_round_trip_no_hmac() {
        let original = FileVerifyResult {
            path: PathBuf::from("/tmp/audit.jsonl"),
            entries_verified: 0,
            hmac_verified: None,
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: FileVerifyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    // ── VerifyWarning serialisation round-trip ────────────────────────────────

    #[test]
    fn verify_warning_backward_timestamp_jump_serde_round_trip() {
        let warning = VerifyWarning::BackwardTimestampJump {
            previous_ts: "2026-05-06T00:01:00.000Z".to_owned(),
            current_ts: "2026-05-05T23:58:00.000Z".to_owned(),
            drift_ms: 180_000,
            file_index: 0,
            entry_index: 5,
        };
        let json = serde_json::to_string(&warning).unwrap();
        let decoded: VerifyWarning = serde_json::from_str(&json).unwrap();
        assert_eq!(warning, decoded);

        // Also verify the serde tag field is present.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "backward_timestamp_jump");
        assert_eq!(v["drift_ms"], 180_000_u64);
    }

    // ── Regular-file open ─────────────────────────────────────────────────────

    fn assert_refused_as_non_regular(result: Result<File, VerifyError>, path: &Path) {
        match result {
            Err(VerifyError::NonRegularFileLogPath { path: refused }) => {
                assert_eq!(refused, path);
            }
            other => panic!("expected a non-regular-file refusal, got {other:?}"),
        }
    }

    #[test]
    fn open_regular_file_opens_a_regular_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("regular");
        fs::write(&path, b"bytes").unwrap();
        let mut contents = String::new();
        open_regular_file(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "bytes");
    }

    #[test]
    fn open_regular_file_refuses_a_directory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("directory");
        fs::create_dir(&path).unwrap();
        assert_refused_as_non_regular(open_regular_file(&path), &path);
    }

    #[cfg(unix)]
    #[test]
    fn open_regular_file_refuses_a_symlink_to_a_regular_file() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"bytes").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_refused_as_non_regular(open_regular_file(&link), &link);
    }

    /// The refusal comes from the open, which never waits for a writer; a
    /// blocking open would hang until the timeout releases it.
    #[cfg(unix)]
    #[test]
    fn open_regular_file_refuses_a_fifo_without_waiting() {
        use crate::audit_log::test_fifo::{make_fifo, release_fifo};
        use std::sync::mpsc::{RecvTimeoutError, channel};
        let dir = TempDir::new().unwrap();
        let fifo = dir.path().join("fifo");
        make_fifo(&fifo);
        let (done, opened) = channel();
        let opener = {
            let fifo = fifo.clone();
            std::thread::spawn(move || {
                let _ = done.send(open_regular_file(&fifo));
            })
        };
        match opened.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(result) => assert_refused_as_non_regular(result, &fifo),
            Err(RecvTimeoutError::Disconnected) => match opener.join() {
                Err(panic) => std::panic::resume_unwind(panic),
                Ok(()) => panic!("the open thread ended without reporting"),
            },
            Err(RecvTimeoutError::Timeout) => {
                release_fifo(&fifo);
                panic!("opening a FIFO waited for a writer");
            }
        }
        opener.join().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn open_regular_file_refuses_a_file_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"bytes").unwrap();
        let link = dir.path().join("link");
        std::os::windows::fs::symlink_file(&target, &link).unwrap();
        assert_refused_as_non_regular(open_regular_file(&link), &link);
    }

    /// Serves `len` bytes and counts how many a reader asked for.
    struct CountingReader {
        len: u64,
        served: u64,
    }

    impl Read for CountingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let left = self.len - self.served;
            let n = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
            buf[..n].fill(b' ');
            self.served += n as u64;
            Ok(n)
        }
    }

    #[test]
    fn a_bounded_read_stops_one_byte_past_the_cap() {
        let mut reader = CountingReader {
            len: 10 * SIDECAR_READ_CAP,
            served: 0,
        };
        assert!(
            read_bounded(&mut reader, SIDECAR_READ_CAP)
                .unwrap()
                .is_none()
        );
        assert_eq!(reader.served, SIDECAR_READ_CAP + 1);

        let mut reader = CountingReader {
            len: SIDECAR_READ_CAP,
            served: 0,
        };
        let bytes = read_bounded(&mut reader, SIDECAR_READ_CAP)
            .unwrap()
            .unwrap();
        assert_eq!(bytes.len() as u64, SIDECAR_READ_CAP);
    }
    #[test]
    fn verify_warns_for_an_acknowledged_loss() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        writer
            .write_entry(AuditEntry::new_audit_outbox_loss_acknowledged(
                2,
                1,
                "inspection",
                1,
                1,
            ))
            .unwrap();
        drop(writer);
        let result = verify_log(&path, None).unwrap();
        assert_eq!(
            result.warnings,
            vec![VerifyWarning::OutboxLossAcknowledged {
                file: "audit.jsonl".to_owned(),
                line: 1,
                expected_rows: 2,
                found_rows: 1,
            }]
        );
    }

    // ── entry tags ──────────────────────────────────────────────────────

    /// The audit key the entry-tag tests write under.
    const TAG_TEST_KEY: [u8; 32] = [0x2c; 32];

    /// A key the log was not written under.
    const OTHER_TAG_KEY: [u8; 32] = [0x3d; 32];

    /// A keyed writer with an anchor store; its open appends the boundary row.
    fn keyed_writer_with(path: &Path, key: [u8; 32]) -> AuditWriter {
        let store: std::sync::Arc<dyn crate::audit_log::tip_anchor::TipAnchorStore> =
            std::sync::Arc::new(crate::audit_log::tip_anchor::InMemoryTipAnchorStore::new());
        AuditWriter::open(
            path.to_path_buf(),
            Some(crate::audit_log::tip_anchor::KeyedAuditAccess::new(
                Zeroizing::new(key),
                store,
            )),
        )
        .unwrap()
    }

    fn keyed_writer(path: &Path) -> AuditWriter {
        keyed_writer_with(path, TAG_TEST_KEY)
    }

    /// Appends an untagged row chained from the tip of `path`.
    fn forge_untagged(path: &Path) -> String {
        crate::audit_log::test_helpers::append_forged_entry(path, tool_entry(), |_| None)
    }

    #[test]
    fn a_forged_untagged_suffix_fails_keyed_verify() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = keyed_writer(&path);
        writer.write_entry(tool_entry()).unwrap();
        writer.write_entry(tool_entry()).unwrap();
        drop(writer);
        verify_log(&path, Some(&TAG_TEST_KEY)).unwrap();
        forge_untagged(&path);

        let err = verify_log(&path, Some(&TAG_TEST_KEY)).unwrap_err();
        assert!(
            matches!(
                &err,
                VerifyError::EntryTagInvalid { file, line: 4, reason: "missing" }
                    if file == "audit.jsonl"
            ),
            "{err:?}"
        );
        assert_eq!(err.wire_code(), "audit.entry_tag_invalid");
        assert_eq!(
            err.to_string(),
            "audit.entry_tag_invalid: entry tag missing at line 4 in audit.jsonl"
        );
        assert!(!err.to_string().contains("sha256:"));

        let keyless = verify_log(&path, None).unwrap();
        assert!(!keyless.entry_tags_verified);
        assert_eq!(keyless.entries_verified, 4);
    }

    #[test]
    fn a_forged_suffix_after_tagged_rows_fails_verify() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = keyed_writer(&path);
        writer.write_entry(tool_entry()).unwrap();
        writer.force_rotate_for_test().unwrap();
        writer.write_entry(tool_entry()).unwrap();
        writer.write_entry(tool_entry()).unwrap();
        drop(writer);
        assert!(
            verify_log(&path, Some(&TAG_TEST_KEY))
                .unwrap()
                .entry_tags_verified
        );
        forge_untagged(&path);
        let err = verify_log(&path, Some(&TAG_TEST_KEY)).unwrap_err();
        assert!(
            matches!(
                &err,
                VerifyError::EntryTagInvalid { file, line: 3, reason: "missing" }
                    if file == "audit.jsonl"
            ),
            "{err:?}"
        );

        let random = dir.path().join("random").join("audit.jsonl");
        let mut writer = keyed_writer(&random);
        writer.write_entry(tool_entry()).unwrap();
        drop(writer);
        crate::audit_log::test_helpers::append_forged_entry(&random, tool_entry(), |_| {
            Some(format!("sha256:{}", "ab".repeat(32)))
        });
        let err = verify_log(&random, Some(&TAG_TEST_KEY)).unwrap_err();
        assert!(
            matches!(
                err,
                VerifyError::EntryTagInvalid {
                    line: 3,
                    reason: "mismatch",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn an_old_key_tag_after_the_rekey_row_refuses() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = keyed_writer(&path);
        writer.write_entry(tool_entry()).unwrap();
        writer
            .switch_entry_tag_key(Zeroizing::new(OTHER_TAG_KEY), "rotation")
            .unwrap();
        drop(writer);
        crate::audit_log::resign_chain_root_sidecars(&path, &OTHER_TAG_KEY).unwrap();
        assert!(
            verify_log(&path, Some(&OTHER_TAG_KEY))
                .unwrap()
                .entry_tags_verified
        );
        crate::audit_log::test_helpers::append_forged_entry(&path, tool_entry(), |hash| {
            Some(crate::audit_log::test_helpers::entry_tag_under(
                &TAG_TEST_KEY,
                hash,
            ))
        });
        let err = verify_log(&path, Some(&OTHER_TAG_KEY)).unwrap_err();
        assert!(
            matches!(
                err,
                VerifyError::EntryTagInvalid {
                    line: 4,
                    reason: "mismatch",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    /// A quarantine row covers exactly its count of entries directly before
    /// it: covering one of two forged rows fails at the first, covering both
    /// passes.
    #[test]
    fn a_quarantine_row_covers_only_its_count() {
        for count in [1_u64, 2] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("audit.jsonl");
            let mut writer = keyed_writer(&path);
            writer.write_entry(tool_entry()).unwrap();
            drop(writer);
            forge_untagged(&path);
            forge_untagged(&path);
            crate::audit_log::test_helpers::append_forged_entry(
                &path,
                AuditEntry::new_audit_entries_quarantined(count, "quarantine"),
                |hash| {
                    Some(crate::audit_log::test_helpers::entry_tag_under(
                        &TAG_TEST_KEY,
                        hash,
                    ))
                },
            );
            let result = verify_log(&path, Some(&TAG_TEST_KEY));
            if count == 1 {
                let err = result.unwrap_err();
                assert!(
                    matches!(
                        err,
                        VerifyError::EntryTagInvalid {
                            line: 3,
                            reason: "missing",
                            ..
                        }
                    ),
                    "{err:?}"
                );
            } else {
                let ok = result.unwrap();
                assert!(ok.entry_tags_verified);
                assert!(ok.warnings.contains(&VerifyWarning::EntriesQuarantined {
                    file: "audit.jsonl".to_owned(),
                    line: 5,
                    quarantined_count: 2,
                }));
            }
        }
    }

    #[test]
    fn verify_reports_the_boundary_position() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = keyed_writer(&path);
        writer.write_entry(tool_entry()).unwrap();
        let ok = verify_log(&path, Some(&TAG_TEST_KEY)).unwrap();
        assert_eq!(
            ok.entry_tags_boundary,
            Some(EntryTagsBoundary {
                file: "audit.jsonl".to_owned(),
                line: 1,
                kind: "audit_entry_tags_started".to_owned(),
            })
        );
        writer
            .switch_entry_tag_key(Zeroizing::new(OTHER_TAG_KEY), "rotation")
            .unwrap();
        drop(writer);
        crate::audit_log::resign_chain_root_sidecars(&path, &OTHER_TAG_KEY).unwrap();
        let ok = verify_log(&path, Some(&OTHER_TAG_KEY)).unwrap();
        assert_eq!(
            ok.entry_tags_boundary,
            Some(EntryTagsBoundary {
                file: "audit.jsonl".to_owned(),
                line: 3,
                kind: "audit_entry_tags_rekeyed".to_owned(),
            })
        );
        assert!(ok.entry_tags_verified);
    }
}
