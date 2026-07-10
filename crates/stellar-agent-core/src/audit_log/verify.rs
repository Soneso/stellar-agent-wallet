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
//!    [`VerifyError::HmacSidecarMissing`] is returned.
//!
//! # Wire codes (closed set)
//!
//! Error variant wire codes use a closed set: `audit.chain_broken`,
//! `audit.rotation_gap`, `audit.hmac_mismatch`, `audit.hmac_sidecar_missing`,
//! `audit.too_many_rotated_files`, `audit.non_regular_file_log_path`,
//! `audit.parse_error`, `audit.path_contract`, `audit.io_error`,
//! `audit.signer_set_canonical_body`.  The line number / file basename is in
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
    chain::{ZERO_BLOCK_HASH, compute_entry_hash, verify_chain_root},
    entry::AuditEntry,
    schema::EventKind,
    writer::{MAX_ROTATED_FILES, hmac_sidecar_path, is_rotated_sibling},
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

/// Informational warnings produced by [`verify_log`].
///
/// Warnings do not invalidate the hash chain and do not cause verification to
/// fail. They are surfaced for operator investigation in deterministic CLI JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VerifyWarning {
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
///   `~/.local/state/stellar-agent/audit/default.jsonl`).
/// - `hmac_key` — optional 32-byte key for verifying the chain-root HMAC tag
///   on each file.  If `None`, HMAC verification is skipped (the hash chain
///   is still verified).  If `Some` and the sidecar is missing, returns
///   [`VerifyError::HmacSidecarMissing`].
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
    let mut total_entries = 0usize;
    let mut files_walked = 0usize;

    // Collect the ordered list of files: oldest rotated first, then active.
    let file_chain = collect_file_chain(log_path)?;
    let active_stem = log_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| VerifyError::PathContract {
            detail: "log path has no UTF-8 file name".to_owned(),
        })?;

    // `expected_prev_hash` threads the last_hash from one file into the next
    // to verify the cross-file chain bridge.
    // None means "this is the very first file — use ZERO_BLOCK_HASH internally".
    let mut expected_prev_hash: Option<String> = None;
    let mut previous_timestamp: Option<(String, u64)> = None;
    let mut warnings = Vec::new();
    let mut per_file = Vec::new();
    // Tracks whether every per-file `SingleFileResult.sidecar_verified` was
    // true. AND-combined into `VerifyOk.hmac_verified` on success.
    let mut all_sidecars_verified = true;

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
        let result = verify_single_file(VerifySingleFileContext {
            path,
            hmac_key,
            expected_initial_prev_hash: expected_prev_hash.as_deref(),
            next_file_basename: current_file_basename,
            is_last_file,
            active_stem,
            file_index: file_idx,
            previous_timestamp: previous_timestamp.as_ref(),
        })?;

        let SingleFileResult {
            entries,
            last_hash,
            last_timestamp,
            warnings: file_warnings,
            sidecar_verified,
        } = result;

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

    Ok(VerifyOk {
        entries_verified: total_entries,
        files_walked,
        per_file,
        warnings,
        hmac_verified: hmac_key.is_some() && all_sidecars_verified,
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
/// let ok = verify_log_with_health(&PathBuf::from("/tmp/test.jsonl"), None, &handle)?;
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
    health: &crate::audit_log::health::AuditWriterHealthHandle,
) -> Result<VerifyOkWithHealth, VerifyError> {
    let verify_ok = verify_log(log_path, hmac_key)?;
    let audit_writer_degraded = health.is_degraded();
    Ok(VerifyOkWithHealth {
        verify_ok,
        audit_writer_degraded,
    })
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
    /// Hash of the last entry in this file (used for cross-file chain bridging).
    last_hash: String,
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
/// `~/.local/state/stellar-agent/audit/default.jsonl`.  This shares the wire
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
fn verify_single_file(ctx: VerifySingleFileContext<'_>) -> Result<SingleFileResult, VerifyError> {
    let path = ctx.path;
    let file = open_regular_file(path)?;
    let reader = BufReader::new(file);

    // For the very first file, the initial expected prev hash is ZERO_BLOCK_HASH.
    // For subsequent files, it is the last_hash of the preceding file.
    let initial_prev_hash = ctx.expected_initial_prev_hash.unwrap_or(ZERO_BLOCK_HASH);
    let mut prev_hash = initial_prev_hash.to_owned();

    let mut entries = 0usize;
    let mut is_first_entry = true;
    let mut last_handoff_next_file: Option<String> = None;
    let mut previous_timestamp = ctx.previous_timestamp.cloned();
    let mut warnings = Vec::new();

    for (line_index, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(VerifyError::Io)?;
        let line_number = line_index + 1;

        if line.trim().is_empty() {
            continue;
        }

        // Parse the entry.
        let entry: AuditEntry =
            serde_json::from_str(&line).map_err(|e| VerifyError::ParseError {
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
                let sidecar = hmac_sidecar_path(path);
                if sidecar.exists() {
                    let tag = read_regular_file_to_string(&sidecar)?;
                    let tag = tag.trim();
                    verify_chain_root(key, &body, tag).map_err(|_| VerifyError::HmacMismatch {
                        file: path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_owned(),
                    })?;
                } else {
                    // HMAC key provided but sidecar missing — integrity violation.
                    return Err(VerifyError::HmacSidecarMissing {
                        file: path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_owned(),
                    });
                }
            }
            is_first_entry = false;
        }

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
            EventKind::SaContextRuleCreated { .. } | EventKind::SaContextRuleDeleted { .. } => {
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
            EventKind::SaSignerAdded { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaSignerRemoved { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaThresholdChanged { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaSignerSetDiverged { .. } => {
                // No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::SaSignerSetBaselined { .. } => {
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
            | EventKind::X402PaymentAuthorized { .. }
            | EventKind::KeyringKeyWritten { .. }
            | EventKind::PolicyWindowStateReset { .. } => {
                // Value-action, key-write, and window-state-reset forensic
                // rows. No rotation-handoff tracking needed; the hash-chain is
                // maintained by the surrounding hash check.
            }
            EventKind::AuditRotationHandoff { next_file_name } => {
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
        last_hash: prev_hash,
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

fn open_regular_file(path: &Path) -> Result<File, VerifyError> {
    let metadata = fs::symlink_metadata(path).map_err(VerifyError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(VerifyError::NonRegularFileLogPath {
            path: path.to_path_buf(),
        });
    }
    File::open(path).map_err(VerifyError::Io)
}

fn read_regular_file_to_string(path: &Path) -> Result<String, VerifyError> {
    let mut file = open_regular_file(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(VerifyError::Io)?;
    Ok(contents)
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

    /// The chain-root HMAC tag did not verify.
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
         recovery runbook: docs/runbooks/audit-log-recovery.md"
    )]
    PartialRotation {
        /// Detected partial-rotation state with associated file metadata.
        state: PartialRotationState,
        /// Human-readable hint pointing to the recovery runbook.
        recovery_hint: String,
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
            ContractKind, KeyPurpose, PolicyDecision, ValueActionKind, ValueLegRecord,
            VerifierAdvisoryKind,
        },
        writer::{AuditWriter, ROTATION_THRESHOLD_BYTES},
    };
    use crate::observability::RedactedStrkey;
    use std::fs;
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    fn verify_event_kind_explicit_arm_for_test(event_kind: &EventKind) -> &'static str {
        match event_kind {
            EventKind::ToolInvocation => "tool_invocation",
            EventKind::PluginInvoked { .. } => "plugin_invoked",
            EventKind::WalletMlockFailed { .. } => "wallet_mlock_failed",
            EventKind::SaRawInvocation { .. } => "sa_raw_invocation",
            EventKind::SmartAccountDeployed { .. } => "smart_account_deployed",
            EventKind::SaContextRuleCreated { .. } => "sa_context_rule_created",
            EventKind::SaContextRuleDeleted { .. } => "sa_context_rule_deleted",
            EventKind::PasskeyRegistered { .. } => "passkey_registered",
            EventKind::PasskeyAssertion { .. } => "passkey_assertion",
            EventKind::SaSignerAdded { .. } => "sa_signer_added",
            EventKind::SaSignerRemoved { .. } => "sa_signer_removed",
            EventKind::SaThresholdChanged { .. } => "sa_threshold_changed",
            EventKind::SaSignerSetDiverged { .. } => "sa_signer_set_diverged",
            EventKind::SaSignerSetBaselined { .. } => "sa_signer_set_baselined",
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
            EventKind::X402PaymentAuthorized { .. } => "x402_payment_authorized",
            EventKind::KeyringKeyWritten { .. } => "keyring_key_written",
            EventKind::PolicyWindowStateReset { .. } => "policy_window_state_reset",
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
                expected_threshold: 2,
                observed_threshold: 2,
                expected_signer_set_digest: "abcdef12...34567890".to_owned(),
                observed_signer_set_digest: "12345678...abcdef90".to_owned(),
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
            EventKind::SaVerifierHashDrift {
                rule_id: 1,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                deploy_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...67890"),
                pinned_hash_first8: "aabbccdd".to_owned(),
                observed_hash_first8: "11223344".to_owned(),
            },
            EventKind::SaPolicyHashDrift {
                rule_id: 2,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                deploy_address_redacted: RedactedStrkey::from_already_redacted("CCCCC...99999"),
                pinned_hash_first8: "eeff0011".to_owned(),
                observed_hash_first8: "22334455".to_owned(),
            },
            EventKind::SaMutableContractOverride {
                rule_id: 3,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                contract_address_redacted: RedactedStrkey::from_already_redacted("CDABC...99999"),
                contract_kind: ContractKind::Verifier,
                override_acknowledged_at: "2026-05-19T10:00:00Z".to_owned(),
            },
            EventKind::SaUnknownContractOverride {
                rule_id: 4,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                contract_address_redacted: RedactedStrkey::from_already_redacted("CEEEE...88888"),
                contract_kind: ContractKind::Policy,
                override_acknowledged_at: "2026-05-19T11:00:00Z".to_owned(),
                observed_hash_first8: "aabbccdd".to_owned(),
            },
            EventKind::AuditRotationHandoff {
                next_file_name: "audit.jsonl.20260428T010203004".to_owned(),
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
            EventKind::X402PaymentAuthorized {
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
            EventKind::KeyringKeyWritten {
                key_purpose: KeyPurpose::AuditHashChainHmac,
                keyring_service: "stellar-agent-audit".to_owned(),
                keyring_entry: "default".to_owned(),
                public_address: None,
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

    fn write_entries(path: &Path, count: usize) {
        let mut writer = AuditWriter::open(path.to_path_buf(), None).unwrap();
        for _ in 0..count {
            let entry = new_tool_invocation(
                "stellar_pay_commit",
                "stellar:testnet",
                vec!["destination".to_owned()],
                None,
                None,
                PolicyDecision::Allow,
                None,
                uuid::Uuid::new_v4().to_string(),
            );
            writer.write_entry(entry).unwrap();
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
                "sa_context_rule_deleted",
                "passkey_registered",
                "passkey_assertion",
                "sa_signer_added",
                "sa_signer_removed",
                "sa_threshold_changed",
                "sa_signer_set_diverged",
                "sa_signer_set_baselined",
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
                "x402_payment_authorized",
                "keyring_key_written",
            ]
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
        let mut writer = AuditWriter::open(path.clone(), Some(key)).unwrap();
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

        let mut handoff = AuditEntry::new_rotation_handoff("audit.jsonl.20260428T010203004", "req");
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
            let mut writer = AuditWriter::open(path.clone(), Some(Zeroizing::new(key))).unwrap();
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

            let mut writer2 = AuditWriter::open(path.clone(), Some(Zeroizing::new(key))).unwrap();
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

        let result = super::verify_log_with_health(&path, None, &handle)
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

        let result = super::verify_log_with_health(&path, None, &handle)
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

        let result = super::verify_log_with_health(&path, None, &handle);
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
            recovery_hint: "docs/runbooks/audit-log-recovery.md".to_owned(),
        };
        let display = err.to_string();
        assert!(
            display.contains("audit.partial_rotation"),
            "display must include wire code prefix: {display}"
        );
        assert!(
            display.contains("docs/runbooks/audit-log-recovery.md"),
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
        let VerifyWarning::BackwardTimestampJump { drift_ms, .. } = &ok.warnings[0];
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
            AuditWriter::open(path.clone(), Some(zeroize::Zeroizing::new(key))).unwrap();
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
        let mut writer =
            AuditWriter::open(path.clone(), Some(zeroize::Zeroizing::new(key_a))).unwrap();
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
}
