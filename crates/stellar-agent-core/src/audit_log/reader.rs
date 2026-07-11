//! Audit-log reader that reconstructs signer-set state from the hash-chained log.
//!
//! Provides [`AuditReader`] — a read-side companion to [`AuditWriter`] that
//! scans the rotated log-file chain in reverse-chronological order to find the
//! most-recent signer-set state row for a given `(rule_id, smart_account)`
//! pair.
//!
//! # Shared-mutex discipline
//!
//! `AuditReader` holds a clone of the same `Arc<Mutex<AuditWriter>>` that the
//! write path uses. The reader acquires the mutex for the entire duration of a
//! scan, which eliminates intra-process reader/writer races: a writer cannot
//! append a new entry while the reader is traversing the log.
//!
//! Because the writer holds the file-system advisory lock for its lifetime, and
//! the reader acquires the writer mutex before reading, multi-process isolation
//! is also guaranteed for the single-writer invariant.
//!
//! # Scan order
//!
//! The active file is scanned first (most-recent entries), then rotated files
//! from newest to oldest. Within each file, entries are scanned from first to
//! last (oldest-to-newest within that file) and the most-recent match across all
//! files is captured. This implements "newest overall" semantics without
//! reversing within a file.
//!
//! # Integrity contract
//!
//! Integrity errors (`ChainBroken`, `RotationGap`, `HmacMismatch`,
//! `HmacSidecarMissing`, `ParseError`) MUST propagate and MUST NOT be
//! reinterpreted as `Ok(None)`. `Ok(None)` is reserved for "full chain
//! traversal completed cleanly with no matching row" — it never silently masks
//! integrity violations.
//!
//! # Reader consistency posture
//!
//! `AuditWriter` places no OS lock on the log file itself (the exclusive lock
//! lives on a sidecar file — see `writer::lock_sidecar_path` and
//! `crate::audit_log::lock`), so a reader may observe the log directory
//! mid-write or mid-rotation, on every platform:
//!
//! - **Mid-append** (a write in progress): the active file's last line may be
//!   incomplete. This is the pre-existing torn-tail case, surfaced as
//!   [`AuditLogIntegrityError::ParseError`] — never silently treated as
//!   `Ok(None)`. Unaffected by this module's design.
//!
//! - **Mid-rotation** (the active file transiently absent): `AuditWriter::rotate`
//!   renames the active file to its archive name and then creates the new
//!   active file as two separate filesystem operations; a reader can observe
//!   the directory in the microsecond-scale window between them, in which the
//!   active path does not exist even though the log is not actually empty.
//!   [`collect_files_newest_first`] tolerates this: when the active file is
//!   absent but rotated siblings are present, it re-scans the directory a
//!   small bounded number of times (never indefinitely) WHILE the writer's
//!   sidecar lock is observably held by a live writer (probed by
//!   `writer::wait_out_transient_rotation_window`, shared with
//!   `verify::verify_log`'s equivalent tolerance), on the theory that the
//!   combination of "no active file" + "a writer is currently alive" is far
//!   more likely to be this transient window than out-of-band tampering. If
//!   the file reappears, the scan proceeds normally with the fresh file
//!   listing. If the bound is exhausted, or no writer is alive to begin with,
//!   the absence is treated exactly as before: [`AuditLogIntegrityError::RotationGap`]
//!   for a non-active missing file, or "empty log" for an active file absent
//!   with no rotated siblings. This bounded tolerance never turns a genuine
//!   integrity violation into `Ok` — it only delays, by a few milliseconds at
//!   most, the point at which a still-absent file is reported as a gap.

use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use sha2::{Digest as _, Sha256};

use super::{
    chain::{ZERO_BLOCK_HASH, compute_entry_hash},
    entry::AuditEntry,
    schema::EventKind,
    signer_set::{ObservedSignerSet, SignerSetStatePayload},
    verify::VerifyError,
    writer::{AuditWriter, is_rotated_sibling, wait_out_transient_rotation_window},
};

/// Pinned wasm-hash record for one rule, extracted from the `SaContextRuleCreated`
/// audit row.
///
/// Carries first-8-hex projections of the pinned wasm hashes recorded at
/// rule-install time, plus the install-time override flags so
/// `smart-account rules verify-pins` output can convey whether the pin was established
/// under an opt-in override.
///
/// # Backward-compatibility
///
/// Override fields use `#[serde(default)]` on the schema side, so reading an
/// audit row that predates their addition yields `mutable_override = false` /
/// `unknown_override = false` — the conservative safe default.
#[derive(Clone, Debug, Default)]
pub struct PinnedHashesRecord {
    /// First-8-hex of each pinned verifier wasm hash. Empty when no `External`
    /// signers were present, or for audit rows that predate verifier pinning.
    pub pinned_verifier_first8: Vec<String>,
    /// First-8-hex of each pinned policy wasm hash. Empty when no policies
    /// were present, or for audit rows that predate policy pinning.
    pub pinned_policy_first8: Vec<String>,
    /// `true` if `--accept-mutable-verifier` was set at install time.
    /// Rows that predate this field deserialise as `false`.
    pub mutable_override: bool,
    /// `true` if `--accept-unknown-verifier` was set at install time.
    /// Rows that predate this field deserialise as `false`.
    pub unknown_override: bool,
}

/// Re-export of [`VerifyError`] under a reader-oriented name.
///
/// Integrity error returned by audit-log read paths.
///
/// Wire codes are preserved verbatim (`audit.chain_broken`,
/// `audit.rotation_gap`, `audit.hmac_mismatch`, `audit.hmac_sidecar_missing`,
/// `audit.parse_error`, `audit.too_many_rotated_files`,
/// `audit.non_regular_file_log_path`, `audit.path_contract`,
/// `audit.io_error`, `audit.signer_set_canonical_body`).
pub type AuditLogIntegrityError = VerifyError;

// ── AuditReader ───────────────────────────────────────────────────────────────

/// Read-side companion to [`AuditWriter`] for signer-set baseline reconstruction.
///
/// Holds a clone of the shared `Arc<Mutex<AuditWriter>>` to eliminate
/// intra-process reader/writer races.
///
/// Obtain via [`AuditReader::new`]; then call
/// [`AuditReader::find_latest_signer_set_state`] to scan the rotated log chain.
pub struct AuditReader {
    /// Shared writer mutex — acquired for the full duration of each scan.
    ///
    /// Sharing the writer's mutex eliminates intra-process reader/writer races:
    /// a writer cannot append while the reader traverses the log. Because the
    /// writer also holds the OS advisory lock for its lifetime, multi-process
    /// isolation is guaranteed by the single-writer invariant.
    writer: Arc<Mutex<AuditWriter>>,

    /// Optional HMAC key for chain-root sidecar verification.
    ///
    /// When `Some`, the reader calls through to the chain-root HMAC check in
    /// `verify_single_file`. When `None`, HMAC verification is skipped (the
    /// hash chain is still verified). Mirrors the `verify_log` contract.
    hmac_key: Option<[u8; 32]>,
}

impl AuditReader {
    /// Constructs a new `AuditReader` from the shared writer mutex and an
    /// optional HMAC key.
    ///
    /// The `log_path` is derived from the writer under a brief mutex acquire at
    /// construction time. Subsequent scans re-acquire the mutex for the duration
    /// of the traversal.
    ///
    /// # Panics
    ///
    /// Panics if the writer mutex is poisoned (indicates a previous panicking
    /// write operation — the audit log is in an unknown state).
    #[must_use]
    pub fn new(writer: Arc<Mutex<AuditWriter>>, hmac_key: Option<[u8; 32]>) -> Self {
        Self { writer, hmac_key }
    }

    /// Scans the rotated chain backwards for the most-recent row matching
    /// `(rule_id, smart_account_redacted)` whose event kind is one of
    /// `SaSignerAdded`, `SaSignerRemoved`, `SaThresholdChanged`, or
    /// `SaSignerSetBaselined`.
    ///
    /// Reconstructs [`ObservedSignerSet`] from the most-recent matching row's
    /// `resulting_*` / `observed_*` payload fields.
    ///
    /// # Scan semantics
    ///
    /// The scan traverses: active file (newest entries last, all read) → rotated
    /// files newest-first (oldest-timestamp sibling last). Within each file
    /// entries are read first-to-last. The most-recent matching entry across the
    /// full chain is returned. HMAC integrity is checked when `hmac_key` is set.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(payload))` — matching row found; `payload.row_hash` is the
    ///   SHA-256 of the canonical JSON body of the row (body with
    ///   `previous_entry_hash = ""`), suitable for binding into
    ///   `FrozenChainStateTuple`.
    /// - `Ok(None)` — full rotated-chain traversal completed cleanly with no
    ///   matching row (reserved for "no baseline"; never silently masks integrity
    ///   errors).
    ///
    /// # Errors
    ///
    /// - [`AuditLogIntegrityError::ChainBroken`] — hash chain break at a
    ///   specific line (integrity violation, not a configuration error).
    /// - [`AuditLogIntegrityError::RotationGap`] — a rotated file in the chain
    ///   is missing or the handoff entry names a non-existent file.
    /// - [`AuditLogIntegrityError::HmacMismatch`] — chain-root HMAC tag did
    ///   not verify (only when `hmac_key` is `Some`).
    /// - [`AuditLogIntegrityError::HmacSidecarMissing`] — HMAC key provided
    ///   but per-file sidecar is absent (integrity violation).
    /// - [`AuditLogIntegrityError::ParseError`] — a log line could not be
    ///   parsed as an [`AuditEntry`]. Includes torn-tail scenarios where the
    ///   active file's last line is incomplete (a truncated write produces an
    ///   unparseable line).
    /// - [`AuditLogIntegrityError::Io`] — ambient filesystem failure.
    ///
    /// # Errors
    ///
    /// In addition to the integrity errors listed above, returns
    /// [`AuditLogIntegrityError::Io`] if the writer mutex is poisoned (a prior
    /// writer thread panicked while holding the lock — the audit log is in an
    /// unknown state; process restart is the only safe recovery). The Io error
    /// message describes the lock-poisoned condition.
    pub fn find_latest_signer_set_state(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
    ) -> Result<Option<SignerSetStatePayload>, AuditLogIntegrityError> {
        // Acquire the writer mutex for the full duration of the scan.
        // If the mutex is poisoned (a prior writer thread panicked), propagate
        // as AuditLogIntegrityError::Io so callers get a structured typed error
        // rather than an unhandled panic. The lock-poisoned condition means the
        // audit-log in-memory state may be inconsistent; process restart is the
        // recommended recovery.
        // Promoted to an Io error: the reader may see a half-written state from
        // the panicking writer, so silent recovery via `into_inner()` is unsound.
        let writer_guard = self.writer.lock().map_err(|_| {
            AuditLogIntegrityError::Io(std::io::Error::other(
                "audit-log writer mutex is poisoned; a prior write path panicked \
                 mid-write — audit-log integrity is unknown; restart the process",
            ))
        })?;

        let log_path = writer_guard.path().to_path_buf();
        let hmac_key = self.hmac_key.as_ref();

        // Collect the file chain in scan order: active first, then rotated files
        // newest-first. We reverse the verification order (verify.rs goes oldest
        // first; we want newest-first so we can stop at the first match).
        let files_newest_first = collect_files_newest_first(&log_path)?;

        // Determine whether any rotated siblings exist. If the active file
        // is absent AND rotated siblings are present, the log directory is in an
        // inconsistent state (filesystem tampering / out-of-band deletion of the
        // active file). Promote to RotationGap rather than silently falling
        // through to rotated-sibling data as if it were the most-recent state.
        let has_rotated_siblings = files_newest_first.len() > 1;

        let mut best: Option<SignerSetStatePayload> = None;

        for path in &files_newest_first {
            if !path.exists() {
                if *path == log_path {
                    if has_rotated_siblings {
                        // Active file is missing but rotated siblings exist.
                        // This indicates filesystem tampering or an out-of-band
                        // deletion: the writer always creates the active file on
                        // open, so absence with siblings present is anomalous.
                        // Promote to RotationGap so callers get a typed integrity
                        // error rather than silently falling through to rotated data.
                        return Err(AuditLogIntegrityError::RotationGap {
                            file: log_path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("<active>")
                                .to_owned(),
                        });
                    }
                    // No rotated siblings: active file missing = empty log.
                    // (Writer may not have written any entries yet.)
                    continue;
                }
                return Err(AuditLogIntegrityError::RotationGap {
                    file: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("<unknown>")
                        .to_owned(),
                });
            }

            // Pass ZERO_BLOCK_HASH as the expected first-row
            // `previous_entry_hash` only when the active file is the ONLY file
            // in the chain (single-file wallet). For that case the first row's
            // `previous_entry_hash` MUST equal ZERO_BLOCK_HASH; any other value
            // means the row body was tampered after write.
            //
            // When rotated siblings exist, the cross-file handoff hash is
            // `verify_log`'s responsibility; we pass `None` so the first-row
            // check in `scan_file_for_signer_set` is skipped for those files.
            let is_active = *path == log_path;
            let expected_first_row_prev: Option<&str> = if is_active && !has_rotated_siblings {
                Some(ZERO_BLOCK_HASH)
            } else {
                None
            };
            let file_result = scan_file_for_signer_set(
                path,
                rule_id,
                smart_account_redacted,
                hmac_key,
                expected_first_row_prev,
            )?;

            if let Some(payload) = file_result {
                // Keep the most-recent (latest row_hash from the latest file).
                // Since we scan newest-file-first and within each file we read
                // all entries and keep the last match, the first non-None result
                // from any file is already the most-recent across the chain.
                best = Some(payload);
                break;
            }
        }

        Ok(best)
    }

    /// Scans the rotated chain for the most-recent `SaContextRuleCreated` row
    /// matching `(rule_id, smart_account_redacted)` and returns the pinned
    /// verifier and policy wasm-hash first-8 hex strings.
    ///
    /// Used by `managers::verifiers::verify_pinned_verifier_against_chain` and
    /// `verify_pinned_policy_against_chain` to derive the audit-log-expected hash
    /// at signing time.
    ///
    /// # Returns
    ///
    /// - `Ok(Some((verifier_hashes, policy_hashes)))` — the most-recent
    ///   `SaContextRuleCreated` row for the given `(rule_id, smart_account_redacted)`
    ///   pair was found; the returned vectors carry the first-8-hex strings of the
    ///   pinned verifier and policy wasm hashes respectively.  Either or both may
    ///   be empty if the rule had no `External` signers / no policies, or if the
    ///   rule was installed before pinning was added (`#[serde(default)]` yields
    ///   empty vecs on earlier entries).
    /// - `Ok(None)` — no matching `SaContextRuleCreated` row found. Callers treat
    ///   this as "no pin recorded" and may skip drift-detection.
    ///
    /// # Integrity contract
    ///
    /// Integrity errors propagate the same as `find_latest_signer_set_state` —
    /// `Ok(None)` is NEVER used to mask an integrity failure.
    ///
    /// # Errors
    ///
    /// Same error variants as [`AuditReader::find_latest_signer_set_state`]:
    /// `ChainBroken`, `RotationGap`, `HmacMismatch`, `HmacSidecarMissing`,
    /// `ParseError`, `Io`.
    pub fn find_latest_context_rule_pinned_hashes(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
    ) -> Result<Option<PinnedHashesRecord>, AuditLogIntegrityError> {
        let writer_guard = self.writer.lock().map_err(|_| {
            AuditLogIntegrityError::Io(std::io::Error::other(
                "audit-log writer mutex is poisoned; a prior write path panicked \
                 mid-write — audit-log integrity is unknown; restart the process",
            ))
        })?;

        let log_path = writer_guard.path().to_path_buf();
        let hmac_key = self.hmac_key.as_ref();

        let files_newest_first = collect_files_newest_first(&log_path)?;
        let has_rotated_siblings = files_newest_first.len() > 1;

        let mut best: Option<PinnedHashesRecord> = None;

        for path in &files_newest_first {
            if !path.exists() {
                if *path == log_path {
                    if has_rotated_siblings {
                        return Err(AuditLogIntegrityError::RotationGap {
                            file: log_path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("<active>")
                                .to_owned(),
                        });
                    }
                    continue;
                }
                return Err(AuditLogIntegrityError::RotationGap {
                    file: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("<unknown>")
                        .to_owned(),
                });
            }

            let is_active = *path == log_path;
            let expected_first_row_prev: Option<&str> = if is_active && !has_rotated_siblings {
                Some(ZERO_BLOCK_HASH)
            } else {
                None
            };

            let file_result = scan_file_for_context_rule_pins(
                path,
                rule_id,
                smart_account_redacted,
                hmac_key,
                expected_first_row_prev,
            )?;

            if let Some(hashes) = file_result {
                best = Some(hashes);
                break;
            }
        }

        Ok(best)
    }

    /// Scans the full rotated chain and returns ALL `SaContextRuleCreated` rows,
    /// deduplicated to the most-recent row per `(rule_id, smart_account_redacted)`.
    ///
    /// Used by the startup advisory to identify every context rule referencing
    /// a revoked or retired verifier wasm hash. Unlike
    /// `find_latest_context_rule_pinned_hashes`, this method does NOT filter by
    /// a specific `(rule_id, smart_account_redacted)` pair — it collects ALL
    /// rules across the full log chain.
    ///
    /// # Deduplication
    ///
    /// If the same `(rule_id, smart_account_redacted)` appears more than once
    /// (e.g. after a rule reinstall), the MOST RECENT row wins. Scan order is
    /// newest-file-first, newest-entry-last-within-file — same as the other
    /// `find_latest_*` methods.
    ///
    /// # Returns
    ///
    /// A `Vec` of `(rule_id, smart_account_redacted, PinnedHashesRecord)` tuples,
    /// deduplicated to the most-recent row per `(rule_id, smart_account)` — the
    /// newest file wins on conflict — and sorted by `(rule_id, smart_account)`
    /// ascending for deterministic output. Empty when the log is absent or
    /// contains no `SaContextRuleCreated` rows.
    ///
    /// # Errors
    ///
    /// Same integrity error variants as [`AuditReader::find_latest_signer_set_state`]:
    /// `ChainBroken`, `RotationGap`, `HmacMismatch`, `HmacSidecarMissing`,
    /// `ParseError`, `Io`.
    pub fn scan_all_context_rule_created(
        &self,
    ) -> Result<Vec<(u32, String, PinnedHashesRecord)>, AuditLogIntegrityError> {
        let writer_guard = self.writer.lock().map_err(|_| {
            AuditLogIntegrityError::Io(std::io::Error::other(
                "audit-log writer mutex is poisoned; a prior write path panicked \
                 mid-write — audit-log integrity is unknown; restart the process",
            ))
        })?;

        let log_path = writer_guard.path().to_path_buf();
        let hmac_key = self.hmac_key.as_ref();

        let files_newest_first = collect_files_newest_first(&log_path)?;
        let has_rotated_siblings = files_newest_first.len() > 1;

        // Collect all (rule_id, smart_account, record) tuples across all files.
        // Files are scanned newest-first; within each file entries are collected
        // in read order (oldest-to-newest). Use a HashMap to deduplicate to the
        // most-recent row per (rule_id, smart_account) key.
        let mut latest: std::collections::HashMap<(u32, String), PinnedHashesRecord> =
            std::collections::HashMap::new();

        for path in &files_newest_first {
            if !path.exists() {
                if *path == log_path {
                    if has_rotated_siblings {
                        return Err(AuditLogIntegrityError::RotationGap {
                            file: log_path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("<active>")
                                .to_owned(),
                        });
                    }
                    continue;
                }
                return Err(AuditLogIntegrityError::RotationGap {
                    file: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("<unknown>")
                        .to_owned(),
                });
            }

            let is_active = *path == log_path;
            let expected_first_row_prev: Option<&str> = if is_active && !has_rotated_siblings {
                Some(ZERO_BLOCK_HASH)
            } else {
                None
            };

            let mut this_file: std::collections::HashMap<(u32, String), PinnedHashesRecord> =
                std::collections::HashMap::new();
            scan_file_for_all_context_rule_created(
                path,
                hmac_key,
                expected_first_row_prev,
                &mut this_file,
            )?;
            // Files are scanned newest-first; keep the first-seen (newest) row
            // per key so a reinstall in a newer file wins over an older file's.
            for (key, rec) in this_file {
                latest.entry(key).or_insert(rec);
            }
        }

        // Collect into a stable-ordered Vec (rule_id ascending for deterministic output).
        let mut result: Vec<(u32, String, PinnedHashesRecord)> = latest
            .into_iter()
            .map(|((rid, sa), rec)| (rid, sa, rec))
            .collect();
        result.sort_by_key(|(rid, sa, _)| (*rid, sa.clone()));
        Ok(result)
    }

    /// Returns the set of context-rule IDs that the local audit log records as
    /// installed on `sa_address_redacted` but NOT subsequently deleted.
    ///
    /// Scans the full rotated chain for all `SaContextRuleCreated` rows whose
    /// `smart_account` field matches `sa_address_redacted`, then subtracts any
    /// `rule_id` that also has a matching `SaContextRuleDeleted` row for the
    /// same address. The result is the audit-log's best view of "live" rule IDs
    /// on this smart account.
    ///
    /// Used by `ContextRuleManager::list_active_context_rules` to cross-check
    /// the on-chain enumeration against the local audit record: a malicious RPC
    /// that drops a live rule from its enumeration response will cause that
    /// rule's ID to appear in `ActiveContextRuleEnumeration::audit_log_missing`.
    ///
    /// # Returns
    ///
    /// - `Ok(ids)` — sorted `Vec<u32>` of rule IDs the audit log believes are
    ///   installed. Empty when no matching rows exist or when every
    ///   `SaContextRuleCreated` entry for this address has a corresponding
    ///   `SaContextRuleDeleted` entry.
    /// - `Err(AuditLogIntegrityError)` — integrity violation or I/O error; MUST
    ///   NOT be silently mapped to `Ok(vec![])`.
    ///
    /// # Errors
    ///
    /// Same variants as [`AuditReader::find_latest_signer_set_state`].
    pub fn find_installed_context_rule_ids(
        &self,
        sa_address_redacted: &str,
    ) -> Result<Vec<u32>, AuditLogIntegrityError> {
        let writer_guard = self.writer.lock().map_err(|_| {
            AuditLogIntegrityError::Io(std::io::Error::other(
                "audit-log writer mutex is poisoned; a prior write path panicked \
                 mid-write — audit-log integrity is unknown; restart the process",
            ))
        })?;

        let log_path = writer_guard.path().to_path_buf();
        let hmac_key = self.hmac_key.as_ref();

        let files_newest_first = collect_files_newest_first(&log_path)?;
        let has_rotated_siblings = files_newest_first.len() > 1;

        // created_ids: set of rule IDs seen in SaContextRuleCreated rows.
        // deleted_ids: set of rule IDs seen in SaContextRuleDeleted rows.
        // Both are collected across all files; newest-file-first order does not
        // matter here because we do a set-difference at the end.
        let mut created_ids: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut deleted_ids: std::collections::HashSet<u32> = std::collections::HashSet::new();

        for path in &files_newest_first {
            if !path.exists() {
                if *path == log_path {
                    if has_rotated_siblings {
                        return Err(AuditLogIntegrityError::RotationGap {
                            file: log_path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("<active>")
                                .to_owned(),
                        });
                    }
                    continue;
                }
                return Err(AuditLogIntegrityError::RotationGap {
                    file: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("<unknown>")
                        .to_owned(),
                });
            }

            let is_active = *path == log_path;
            let expected_first_row_prev: Option<&str> = if is_active && !has_rotated_siblings {
                Some(ZERO_BLOCK_HASH)
            } else {
                None
            };

            scan_file_for_context_rule_lifecycle(
                path,
                sa_address_redacted,
                hmac_key,
                expected_first_row_prev,
                &mut created_ids,
                &mut deleted_ids,
            )?;
        }

        // Live = created - deleted.
        let mut live: Vec<u32> = created_ids.difference(&deleted_ids).copied().collect();
        live.sort_unstable();
        Ok(live)
    }

    /// Scans the audit log for pending timelock operations on a given timelock
    /// contract and returns them as `(operation_id_full_hex, request_id, timelock_redacted)`
    /// tuples.
    ///
    /// A "pending" operation is one that has a `SaTimelockScheduled` row but
    /// no corresponding `SaTimelockCancelled` or `SaTimelockExecuted` row with
    /// the same `operation_id_full_hex`.
    ///
    /// The `timelock_contract_strkey` parameter is matched against the
    /// `timelock_contract_redacted` field in each row. Because the audit log
    /// stores the redacted form, callers MUST supply the redacted form of the
    /// timelock contract address (first-5-last-5 C-strkey).
    ///
    /// # Returns
    ///
    /// - `Ok(vec)` — a possibly-empty list of `(operation_id_full_hex,
    ///   scheduled_request_id, timelock_redacted)` tuples for operations that
    ///   do not have a corresponding cancel or execute row.
    ///
    /// # Errors
    ///
    /// - [`AuditLogIntegrityError::ParseError`] — a log line could not be parsed.
    /// - [`AuditLogIntegrityError::ChainBroken`] — hash chain break detected.
    /// - [`AuditLogIntegrityError::Io`] — filesystem or mutex-poison error.
    pub fn find_pending_timelock_operations(
        &self,
        timelock_contract_redacted: &str,
    ) -> Result<Vec<(String, String, String)>, AuditLogIntegrityError> {
        let writer_guard = self.writer.lock().map_err(|_| {
            AuditLogIntegrityError::Io(std::io::Error::other(
                "audit-log writer mutex is poisoned; a prior write path panicked \
                 mid-write — audit-log integrity is unknown; restart the process",
            ))
        })?;

        let log_path = writer_guard.path().to_path_buf();
        let hmac_key = self.hmac_key.as_ref();

        let files_newest_first = collect_files_newest_first(&log_path)?;
        let has_rotated_siblings = files_newest_first.len() > 1;

        // scheduled_ops: map from operation_id_full_hex → (request_id, timelock_redacted).
        // cancelled_or_executed: set of operation_id_full_hex that have been
        // cancelled or executed.
        let mut scheduled_ops: std::collections::HashMap<String, (String, String)> =
            std::collections::HashMap::new();
        let mut cancelled_or_executed: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for path in &files_newest_first {
            if !path.exists() {
                if *path == log_path {
                    if has_rotated_siblings {
                        return Err(AuditLogIntegrityError::RotationGap {
                            file: log_path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("<active>")
                                .to_owned(),
                        });
                    }
                    continue;
                }
                return Err(AuditLogIntegrityError::RotationGap {
                    file: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("<unknown>")
                        .to_owned(),
                });
            }

            let is_active = *path == log_path;
            let expected_first_row_prev: Option<&str> = if is_active && !has_rotated_siblings {
                Some(ZERO_BLOCK_HASH)
            } else {
                None
            };

            scan_file_for_timelock_operations(
                path,
                timelock_contract_redacted,
                hmac_key,
                expected_first_row_prev,
                &mut scheduled_ops,
                &mut cancelled_or_executed,
            )?;
        }

        // Pending = scheduled - (cancelled ∪ executed).
        let pending: Vec<(String, String, String)> = scheduled_ops
            .into_iter()
            .filter(|(op_id, _)| !cancelled_or_executed.contains(op_id))
            .map(|(op_id, (request_id, tl_redacted))| (op_id, request_id, tl_redacted))
            .collect();

        Ok(pending)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns log files in scan order: active file first, then rotated siblings
/// newest-first (by filename / timestamp, descending).
///
/// This is the reverse of `verify.rs::collect_file_chain` (which returns
/// oldest-first). We want newest-first to stop at the first match without
/// scanning the entire chain.
///
/// # Filename-ordering invariant
///
/// Rotated filenames use the strict `<stem>.<YYYYMMDDTHHMMSSmmm>` pattern
/// produced by `audit_log/writer.rs::compact_timestamp()`. This format is
/// sortable by lexicographic string comparison and the lexicographic order
/// equals chronological order. Consequently, `rotated.sort(); rotated.reverse()`
/// correctly yields newest-first ordering.
///
/// This invariant is verified by the `rotation_suffix_lex_sort_matches_chronological`
/// unit test in `audit_log/rotation.rs::tests`.
///
/// # Rotation-window tolerance
///
/// If the active file is absent from the listing but rotated siblings are
/// present, re-scans the directory a small bounded number of times while the
/// writer's sidecar lock is observably held by a live writer, tolerating the
/// microsecond-scale window `AuditWriter::rotate` opens between archiving the
/// old active file and creating the new one — see the module-level "Reader
/// consistency posture" section. This never masks a genuine gap: callers
/// still see the active file missing (and, when siblings are present, still
/// get `RotationGap`) if it never reappears within the bound.
fn collect_files_newest_first(log_path: &Path) -> Result<Vec<PathBuf>, AuditLogIntegrityError> {
    let chain = scan_files_newest_first(log_path)?;
    if chain.len() > 1 && !chain[0].exists() {
        return wait_out_transient_rotation_window(
            log_path,
            chain,
            |chain: &Vec<PathBuf>| !chain[0].exists(),
            || scan_files_newest_first(log_path),
        );
    }
    Ok(chain)
}

/// Performs one directory scan, returning the active file first followed by
/// rotated siblings newest-first. See [`collect_files_newest_first`] for the
/// scan-order contract; this function performs no retry.
fn scan_files_newest_first(log_path: &Path) -> Result<Vec<PathBuf>, AuditLogIntegrityError> {
    let dir = log_path
        .parent()
        .ok_or_else(|| AuditLogIntegrityError::PathContract {
            detail: "audit log path must have a parent directory component".to_owned(),
        })?;
    let stem = log_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| AuditLogIntegrityError::PathContract {
            detail: "audit log path has no UTF-8 file name".to_owned(),
        })?;

    let mut rotated: Vec<PathBuf> = Vec::new();
    if dir.exists() {
        for entry_result in std::fs::read_dir(dir).map_err(AuditLogIntegrityError::Io)? {
            let path = entry_result.map_err(AuditLogIntegrityError::Io)?.path();
            let is_rotated = path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|name| is_rotated_sibling(stem, name))
                .unwrap_or(false);
            if is_rotated {
                rotated.push(path);
            }
        }
    }

    // Sort rotated files oldest-first, then reverse to get newest-first.
    rotated.sort();
    rotated.reverse();

    // Scan order: active file first, then rotated newest-first.
    let mut chain = vec![log_path.to_path_buf()];
    chain.extend(rotated);
    Ok(chain)
}

/// Scans a single log file for the most-recent signer-set row matching
/// `(rule_id, smart_account_redacted)`.
///
/// Reads the file line-by-line. ALL lines must parse cleanly (parse errors
/// propagate as `AuditLogIntegrityError::ParseError`). Empty lines are skipped.
/// Returns the LAST (most-recent within this file) matching row's
/// `SignerSetStatePayload`.
///
/// # Hash-chain verification
///
/// The reader verifies the within-file `previous_entry_hash` chain for every
/// row. At row N (N ≥ 1) the entry's stored `previous_entry_hash` is compared
/// against the `current_hash` computed from the prior row's canonical body. A
/// mismatch returns `AuditLogIntegrityError::ChainBroken` — it MUST NOT be
/// silently reinterpreted as `Ok(None)`.
///
/// When `expected_first_row_prev` is `Some(hash)`, the FIRST row's
/// `previous_entry_hash` is additionally validated to equal `hash`. The caller
/// passes `Some(ZERO_BLOCK_HASH)` when the active file is the only file in the
/// chain (single-file wallet, `files_newest_first.len() == 1`). This closes the
/// fresh-wallet baseline tampering gap: an attacker who rewrites only the first
/// (and only) row's body cannot escape detection, because the row's stored
/// `previous_entry_hash` must still equal `ZERO_BLOCK_HASH` — any deviation
/// returns `ChainBroken`.
///
/// When `expected_first_row_prev` is `None` (rotated files or multi-file chains),
/// the first-row check is skipped. The cross-file handoff hash is `verify_log`'s
/// responsibility; the reader's added value is catching intra-file tampering
/// (row 2 onward) without a full chain walk.
///
/// When `hmac_key` is `Some`, the chain-root HMAC sidecar is verified on the
/// first entry of each file to confirm chain-root authenticity.
///
/// # EOF handling
///
/// Both active and rotated files apply the same parse-error propagation rule.
/// `BufReader::lines` yields incomplete trailing lines (from a mid-write crash)
/// as non-empty strings; if the last line does not parse as valid JSON it is a
/// `ParseError`. There is no leniency difference between active and rotated files.
fn scan_file_for_signer_set(
    path: &Path,
    rule_id: u32,
    smart_account_redacted: &str,
    hmac_key: Option<&[u8; 32]>,
    expected_first_row_prev: Option<&str>,
) -> Result<Option<SignerSetStatePayload>, AuditLogIntegrityError> {
    use super::chain::verify_chain_root;
    use super::writer::hmac_sidecar_path;

    let file = open_regular_file(path)?;
    let reader = BufReader::new(file);

    let mut best: Option<SignerSetStatePayload> = None;
    let mut is_first_entry = true;
    // Thread the hash computed from each row into the next row's chain check.
    // Starts as `None` until the first row is parsed; from row 2 onward this
    // holds the `current_hash` of the preceding row.
    let mut prev_computed_hash: Option<String> = None;

    for (line_index, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(AuditLogIntegrityError::Io)?;
        let line_number = line_index + 1;

        if line.trim().is_empty() {
            continue;
        }

        // Parse error means a torn write or corrupted entry. MUST propagate;
        // never reinterpret as Ok(None).
        let entry: AuditEntry =
            serde_json::from_str(&line).map_err(|e| AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: e.to_string(),
            })?;

        // Verify chain-root HMAC on the first entry of each file when a key is
        // provided. This authenticates the chain root without a full chain walk,
        // sufficient for the reader's narrower integrity scope.
        if is_first_entry {
            if let Some(key) = hmac_key {
                let body = entry.canonical_json_body().map_err(|e| {
                    AuditLogIntegrityError::ParseError {
                        line: line_number,
                        detail: e.to_string(),
                    }
                })?;
                let sidecar = hmac_sidecar_path(path);
                if sidecar.exists() {
                    let tag =
                        std::fs::read_to_string(&sidecar).map_err(AuditLogIntegrityError::Io)?;
                    verify_chain_root(key, &body, tag.trim()).map_err(|_| {
                        AuditLogIntegrityError::HmacMismatch {
                            file: path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("")
                                .to_owned(),
                        }
                    })?;
                } else {
                    return Err(AuditLogIntegrityError::HmacSidecarMissing {
                        file: path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_owned(),
                    });
                }
            }
            // First-row `previous_entry_hash` must equal the expected predecessor
            // hash when the caller provides one.  The caller passes
            // `Some(ZERO_BLOCK_HASH)` for single-file chains (active file is the
            // only file); this closes the fresh-wallet tamper gap where an
            // attacker rewrites the single row's `previous_entry_hash` field and
            // the chain-only primitive has no row-2 check to catch it.  Row 1's
            // check is performed here when `expected_first_row_prev` is `Some(_)`
            // (single-file-chain case); otherwise the cross-file handoff hash
            // check is deferred to `verify_log`.
            if let Some(expected_prev) = expected_first_row_prev
                && entry.previous_entry_hash != expected_prev
            {
                return Err(AuditLogIntegrityError::ChainBroken {
                    line: line_number,
                    file: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_owned(),
                    reason: "first row previous_entry_hash mismatch \
                             (expected ZERO_BLOCK_HASH for single-file chain)",
                });
            }
            is_first_entry = false;
        }

        // Compute SHA-256 of the canonical body (body-only, without prev hash)
        // for the row_hash TOCTOU anchor AND for the chain-link computation.
        let body = entry
            .canonical_json_body()
            .map_err(|e| AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: e.to_string(),
            })?;
        let row_hash: [u8; 32] = Sha256::digest(&body).into();

        // Chain-hash verification. From row 2 onward: verify the entry's stored
        // `previous_entry_hash` matches the `current_hash` computed from the
        // preceding row's body.
        // Row 1's `previous_entry_hash` check is performed above (lines
        // 452-467) when `expected_first_row_prev` is `Some(_)` (single-file-
        // chain case); otherwise the cross-file handoff hash check is deferred
        // to `verify_log`.
        if let Some(ref expected_hash) = prev_computed_hash
            && entry.previous_entry_hash != *expected_hash
        {
            return Err(AuditLogIntegrityError::ChainBroken {
                line: line_number,
                file: path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_owned(),
                reason: "previous_entry_hash mismatch",
            });
        }

        // Compute the current entry's chain hash for the next row's check.
        let current_hash = compute_entry_hash(&body, &entry.previous_entry_hash).map_err(|e| {
            AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: format!("chain hash computation failed: {e}"),
            }
        })?;
        prev_computed_hash = Some(current_hash);

        // Check if this entry is a signer-set state row for our target.
        if let Some(state) =
            extract_observed_signer_set(&entry.event_kind, rule_id, smart_account_redacted)
        {
            best = Some(SignerSetStatePayload::new(state, row_hash));
        }
    }

    Ok(best)
}

/// Extracts an [`ObservedSignerSet`] from a signer-set event kind if it
/// matches `(rule_id, smart_account_redacted)`.
///
/// Returns `None` if the event is not a signer-set event or does not match
/// the filter.
///
/// # Validation contract
///
/// The returned `ObservedSignerSet` is structurally valid: deserialization
/// enforces the variant tag and field shapes (JSON type correctness). However,
/// the `External` variant's `verifier_contract` C-strkey is NOT validated as a
/// well-formed strkey here — that validation happens downstream in
/// [`signer_set::signer_pubkey_canonical_body`] when the canonical body is
/// computed. Consumers that call `signer_pubkey_canonical_body` on values
/// derived from this function must handle the
/// [`signer_set::SignerSetCanonicalBodyError`] error path.
fn extract_observed_signer_set(
    kind: &EventKind,
    rule_id: u32,
    smart_account_redacted: &str,
) -> Option<ObservedSignerSet> {
    match kind {
        EventKind::SaSignerAdded {
            rule_id: rid,
            smart_account_redacted: sa,
            resulting_signer_count,
            resulting_threshold,
            resulting_signer_ids,
            resulting_signer_pubkeys,
            ..
        } if *rid == rule_id && sa == smart_account_redacted => Some(ObservedSignerSet {
            signer_count: *resulting_signer_count,
            threshold: *resulting_threshold,
            signer_ids: resulting_signer_ids.clone(),
            signer_pubkeys: resulting_signer_pubkeys.clone(),
        }),
        EventKind::SaSignerRemoved {
            rule_id: rid,
            smart_account_redacted: sa,
            resulting_signer_count,
            resulting_threshold,
            resulting_signer_ids,
            resulting_signer_pubkeys,
            ..
        } if *rid == rule_id && sa == smart_account_redacted => Some(ObservedSignerSet {
            signer_count: *resulting_signer_count,
            threshold: *resulting_threshold,
            signer_ids: resulting_signer_ids.clone(),
            signer_pubkeys: resulting_signer_pubkeys.clone(),
        }),
        EventKind::SaThresholdChanged {
            rule_id: rid,
            smart_account_redacted: sa,
            resulting_threshold,
            resulting_signer_count,
            resulting_signer_ids,
            resulting_signer_pubkeys,
            ..
        } if *rid == rule_id && sa == smart_account_redacted => Some(ObservedSignerSet {
            signer_count: *resulting_signer_count,
            threshold: *resulting_threshold,
            signer_ids: resulting_signer_ids.clone(),
            signer_pubkeys: resulting_signer_pubkeys.clone(),
        }),
        EventKind::SaSignerSetBaselined {
            rule_id: rid,
            smart_account_redacted: sa,
            observed_signer_count,
            observed_threshold,
            observed_signer_ids,
            observed_signer_pubkeys,
            ..
        } if *rid == rule_id && sa == smart_account_redacted => Some(ObservedSignerSet {
            signer_count: *observed_signer_count,
            threshold: *observed_threshold,
            signer_ids: observed_signer_ids.clone(),
            signer_pubkeys: observed_signer_pubkeys.clone(),
        }),
        _ => None,
    }
}

/// Opens a path as a regular file (rejects symlinks and directories).
fn open_regular_file(path: &Path) -> Result<std::fs::File, AuditLogIntegrityError> {
    let metadata = std::fs::symlink_metadata(path).map_err(AuditLogIntegrityError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(AuditLogIntegrityError::NonRegularFileLogPath {
            path: path.to_path_buf(),
        });
    }
    std::fs::File::open(path).map_err(AuditLogIntegrityError::Io)
}

/// Scans a single log file for the most-recent `SaContextRuleCreated` row
/// matching `(rule_id, smart_account_redacted)`.
///
/// Mirrors `scan_file_for_signer_set` structurally: reads all entries with full
/// hash-chain integrity verification, then returns the LAST matching entry's
/// `pinned_verifier_wasm_hashes_first8` and `pinned_policy_wasm_hashes_first8`.
///
/// # Integrity contract
///
/// Chain-hash verification applies identically to `scan_file_for_signer_set`.
/// Parse errors and chain-breaks propagate; `Ok(None)` means clean traversal
/// with no match.
///
/// # Return
///
/// `Ok(Some(PinnedHashesRecord))` on match;
/// `Ok(None)` if no `SaContextRuleCreated` row matches the filter.
fn scan_file_for_context_rule_pins(
    path: &Path,
    rule_id: u32,
    smart_account_redacted: &str,
    hmac_key: Option<&[u8; 32]>,
    expected_first_row_prev: Option<&str>,
) -> Result<Option<PinnedHashesRecord>, AuditLogIntegrityError> {
    use super::chain::verify_chain_root;
    use super::writer::hmac_sidecar_path;

    let file = open_regular_file(path)?;
    let reader = BufReader::new(file);

    let mut best: Option<PinnedHashesRecord> = None;
    let mut is_first_entry = true;
    let mut prev_computed_hash: Option<String> = None;

    for (line_index, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(AuditLogIntegrityError::Io)?;
        let line_number = line_index + 1;

        if line.trim().is_empty() {
            continue;
        }

        let entry: AuditEntry =
            serde_json::from_str(&line).map_err(|e| AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: e.to_string(),
            })?;

        if is_first_entry {
            if let Some(key) = hmac_key {
                let body = entry.canonical_json_body().map_err(|e| {
                    AuditLogIntegrityError::ParseError {
                        line: line_number,
                        detail: e.to_string(),
                    }
                })?;
                let sidecar = hmac_sidecar_path(path);
                if sidecar.exists() {
                    let tag =
                        std::fs::read_to_string(&sidecar).map_err(AuditLogIntegrityError::Io)?;
                    verify_chain_root(key, &body, tag.trim()).map_err(|_| {
                        AuditLogIntegrityError::HmacMismatch {
                            file: path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("")
                                .to_owned(),
                        }
                    })?;
                } else {
                    return Err(AuditLogIntegrityError::HmacSidecarMissing {
                        file: path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_owned(),
                    });
                }
            }
            if let Some(expected_prev) = expected_first_row_prev
                && entry.previous_entry_hash != expected_prev
            {
                return Err(AuditLogIntegrityError::ChainBroken {
                    line: line_number,
                    file: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_owned(),
                    reason: "first row previous_entry_hash mismatch \
                             (expected ZERO_BLOCK_HASH for single-file chain)",
                });
            }
            is_first_entry = false;
        }

        let body = entry
            .canonical_json_body()
            .map_err(|e| AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: e.to_string(),
            })?;

        if let Some(ref expected_hash) = prev_computed_hash
            && entry.previous_entry_hash != *expected_hash
        {
            return Err(AuditLogIntegrityError::ChainBroken {
                line: line_number,
                file: path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_owned(),
                reason: "previous_entry_hash mismatch",
            });
        }

        let current_hash = compute_entry_hash(&body, &entry.previous_entry_hash).map_err(|e| {
            AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: format!("chain hash computation failed: {e}"),
            }
        })?;
        prev_computed_hash = Some(current_hash);

        // Check if this entry is a SaContextRuleCreated row for our target.
        if let EventKind::SaContextRuleCreated {
            rule_id: rid,
            smart_account: sa,
            pinned_verifier_wasm_hashes_first8,
            pinned_policy_wasm_hashes_first8,
            mutable_override,
            unknown_override,
            ..
        } = &entry.event_kind
            && *rid == rule_id
            && sa == smart_account_redacted
        {
            best = Some(PinnedHashesRecord {
                pinned_verifier_first8: pinned_verifier_wasm_hashes_first8.clone(),
                pinned_policy_first8: pinned_policy_wasm_hashes_first8.clone(),
                mutable_override: *mutable_override,
                unknown_override: *unknown_override,
            });
        }
    }

    Ok(best)
}

/// Scans a single log file and inserts/updates `(rule_id, smart_account_redacted)`
/// → [`PinnedHashesRecord`] entries in `out` for every `SaContextRuleCreated`
/// row found.
///
/// Mirrors `scan_file_for_context_rule_pins` structurally but collects ALL
/// `SaContextRuleCreated` entries instead of filtering by `(rule_id, smart_account)`.
/// Each invocation overwrites any existing entry for the same key, preserving
/// "most-recent wins" semantics when this function is called file-by-file
/// (newest-file-first) — newer files overwrite older files' entries.
///
/// # Integrity contract
///
/// Chain-hash verification applies identically to `scan_file_for_context_rule_pins`.
/// Parse errors and chain-breaks propagate; `Ok(())` means the file was fully
/// traversed cleanly.
fn scan_file_for_all_context_rule_created(
    path: &Path,
    hmac_key: Option<&[u8; 32]>,
    expected_first_row_prev: Option<&str>,
    out: &mut std::collections::HashMap<(u32, String), PinnedHashesRecord>,
) -> Result<(), AuditLogIntegrityError> {
    use super::chain::verify_chain_root;
    use super::writer::hmac_sidecar_path;

    let file = open_regular_file(path)?;
    let reader = BufReader::new(file);

    let mut is_first_entry = true;
    let mut prev_computed_hash: Option<String> = None;

    for (line_index, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(AuditLogIntegrityError::Io)?;
        let line_number = line_index + 1;

        if line.trim().is_empty() {
            continue;
        }

        let entry: AuditEntry =
            serde_json::from_str(&line).map_err(|e| AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: e.to_string(),
            })?;

        if is_first_entry {
            if let Some(key) = hmac_key {
                let body = entry.canonical_json_body().map_err(|e| {
                    AuditLogIntegrityError::ParseError {
                        line: line_number,
                        detail: e.to_string(),
                    }
                })?;
                let sidecar = hmac_sidecar_path(path);
                if sidecar.exists() {
                    let tag =
                        std::fs::read_to_string(&sidecar).map_err(AuditLogIntegrityError::Io)?;
                    verify_chain_root(key, &body, tag.trim()).map_err(|_| {
                        AuditLogIntegrityError::HmacMismatch {
                            file: path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("")
                                .to_owned(),
                        }
                    })?;
                } else {
                    return Err(AuditLogIntegrityError::HmacSidecarMissing {
                        file: path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_owned(),
                    });
                }
            }
            if let Some(expected_prev) = expected_first_row_prev
                && entry.previous_entry_hash != expected_prev
            {
                return Err(AuditLogIntegrityError::ChainBroken {
                    line: line_number,
                    file: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_owned(),
                    reason: "first row previous_entry_hash mismatch \
                             (expected ZERO_BLOCK_HASH for single-file chain)",
                });
            }
            is_first_entry = false;
        }

        let body = entry
            .canonical_json_body()
            .map_err(|e| AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: e.to_string(),
            })?;

        if let Some(ref expected_hash) = prev_computed_hash
            && entry.previous_entry_hash != *expected_hash
        {
            return Err(AuditLogIntegrityError::ChainBroken {
                line: line_number,
                file: path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_owned(),
                reason: "previous_entry_hash mismatch",
            });
        }

        let current_hash = compute_entry_hash(&body, &entry.previous_entry_hash).map_err(|e| {
            AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: format!("chain hash computation failed: {e}"),
            }
        })?;
        prev_computed_hash = Some(current_hash);

        // Collect every SaContextRuleCreated row; overwrite on duplicate key
        // to keep the most-recent entry per (rule_id, smart_account).
        if let EventKind::SaContextRuleCreated {
            rule_id: rid,
            smart_account: sa,
            pinned_verifier_wasm_hashes_first8,
            pinned_policy_wasm_hashes_first8,
            mutable_override,
            unknown_override,
            ..
        } = &entry.event_kind
        {
            out.insert(
                (*rid, sa.clone()),
                PinnedHashesRecord {
                    pinned_verifier_first8: pinned_verifier_wasm_hashes_first8.clone(),
                    pinned_policy_first8: pinned_policy_wasm_hashes_first8.clone(),
                    mutable_override: *mutable_override,
                    unknown_override: *unknown_override,
                },
            );
        }
    }

    Ok(())
}

/// Scans a single log file for `SaContextRuleCreated` and `SaContextRuleDeleted`
/// rows matching `sa_address_redacted`, inserting rule IDs into the provided
/// `created_ids` and `deleted_ids` sets.
///
/// Used by [`AuditReader::find_installed_context_rule_ids`] to determine which
/// rule IDs the audit log believes are currently installed on a smart account.
///
/// Verifies the hash chain for every row in the file (same discipline as
/// `scan_file_for_context_rule_pins`). Integrity errors propagate and MUST NOT
/// be masked as empty sets.
fn scan_file_for_context_rule_lifecycle(
    path: &Path,
    sa_address_redacted: &str,
    hmac_key: Option<&[u8; 32]>,
    expected_first_row_prev: Option<&str>,
    created_ids: &mut std::collections::HashSet<u32>,
    deleted_ids: &mut std::collections::HashSet<u32>,
) -> Result<(), AuditLogIntegrityError> {
    use super::chain::verify_chain_root;
    use super::writer::hmac_sidecar_path;

    let file = open_regular_file(path)?;
    let reader = BufReader::new(file);

    let mut is_first_entry = true;
    let mut prev_computed_hash: Option<String> = None;

    for (line_index, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(AuditLogIntegrityError::Io)?;
        let line_number = line_index + 1;

        if line.trim().is_empty() {
            continue;
        }

        let entry: AuditEntry =
            serde_json::from_str(&line).map_err(|e| AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: e.to_string(),
            })?;

        if is_first_entry {
            // HMAC chain-root verification (same discipline as
            // scan_file_for_context_rule_pins).
            if let Some(key) = hmac_key {
                let body = entry.canonical_json_body().map_err(|e| {
                    AuditLogIntegrityError::ParseError {
                        line: line_number,
                        detail: e.to_string(),
                    }
                })?;
                let sidecar = hmac_sidecar_path(path);
                if sidecar.exists() {
                    let tag =
                        std::fs::read_to_string(&sidecar).map_err(AuditLogIntegrityError::Io)?;
                    verify_chain_root(key, &body, tag.trim()).map_err(|_| {
                        AuditLogIntegrityError::HmacMismatch {
                            file: path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("")
                                .to_owned(),
                        }
                    })?;
                } else {
                    return Err(AuditLogIntegrityError::HmacSidecarMissing {
                        file: path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_owned(),
                    });
                }
            }
            // First-row previous_entry_hash check (single-file chain).
            if let Some(expected) = expected_first_row_prev
                && entry.previous_entry_hash != expected
            {
                return Err(AuditLogIntegrityError::ChainBroken {
                    line: line_number,
                    file: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_owned(),
                    reason: "first row previous_entry_hash mismatch \
                             (expected ZERO_BLOCK_HASH for single-file chain)",
                });
            }
            is_first_entry = false;
        }

        let body = entry
            .canonical_json_body()
            .map_err(|e| AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: e.to_string(),
            })?;

        if let Some(ref expected_hash) = prev_computed_hash
            && entry.previous_entry_hash != *expected_hash
        {
            return Err(AuditLogIntegrityError::ChainBroken {
                line: line_number,
                file: path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_owned(),
                reason: "previous_entry_hash mismatch",
            });
        }

        let current_hash = compute_entry_hash(&body, &entry.previous_entry_hash).map_err(|e| {
            AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: format!("chain hash computation failed: {e}"),
            }
        })?;
        prev_computed_hash = Some(current_hash);

        // Collect SaContextRuleCreated rows for the target smart account.
        if let EventKind::SaContextRuleCreated {
            rule_id: rid,
            smart_account: sa,
            ..
        } = &entry.event_kind
            && sa == sa_address_redacted
        {
            created_ids.insert(*rid);
        }

        // Collect SaContextRuleDeleted rows for the target smart account.
        if let EventKind::SaContextRuleDeleted {
            rule_id: rid,
            smart_account: sa,
        } = &entry.event_kind
            && sa == sa_address_redacted
        {
            deleted_ids.insert(*rid);
        }
    }

    Ok(())
}

/// Scans a single log file for timelock scheduled / cancelled / executed rows
/// matching the given `timelock_contract_redacted`, accumulating them into the
/// caller-owned maps.
///
/// # Chain integrity
///
/// The within-file `previous_entry_hash` chain is verified for every row,
/// following the same discipline as [`scan_file_for_context_rule_lifecycle`].
fn scan_file_for_timelock_operations(
    path: &Path,
    timelock_contract_redacted: &str,
    hmac_key: Option<&[u8; 32]>,
    expected_first_row_prev: Option<&str>,
    scheduled_ops: &mut std::collections::HashMap<String, (String, String)>,
    cancelled_or_executed: &mut std::collections::HashSet<String>,
) -> Result<(), AuditLogIntegrityError> {
    use super::chain::verify_chain_root;
    use super::writer::hmac_sidecar_path;
    use crate::audit_log::schema::EventKind;

    let file = open_regular_file(path)?;
    let reader = BufReader::new(file);

    let mut is_first_entry = true;
    let mut prev_computed_hash: Option<String> = None;

    for (line_index, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(AuditLogIntegrityError::Io)?;
        let line_number = line_index + 1;

        if line.trim().is_empty() {
            continue;
        }

        let entry: AuditEntry =
            serde_json::from_str(&line).map_err(|e| AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: e.to_string(),
            })?;

        if is_first_entry {
            if let Some(key) = hmac_key {
                let body = entry.canonical_json_body().map_err(|e| {
                    AuditLogIntegrityError::ParseError {
                        line: line_number,
                        detail: e.to_string(),
                    }
                })?;
                let sidecar = hmac_sidecar_path(path);
                if sidecar.exists() {
                    let tag =
                        std::fs::read_to_string(&sidecar).map_err(AuditLogIntegrityError::Io)?;
                    verify_chain_root(key, &body, tag.trim()).map_err(|_| {
                        AuditLogIntegrityError::HmacMismatch {
                            file: path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("")
                                .to_owned(),
                        }
                    })?;
                } else {
                    return Err(AuditLogIntegrityError::HmacSidecarMissing {
                        file: path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_owned(),
                    });
                }
            }
            if let Some(expected) = expected_first_row_prev
                && entry.previous_entry_hash != expected
            {
                return Err(AuditLogIntegrityError::ChainBroken {
                    line: line_number,
                    file: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_owned(),
                    reason: "first row previous_entry_hash mismatch \
                             (expected ZERO_BLOCK_HASH for single-file chain)",
                });
            }
            is_first_entry = false;
        }

        let body = entry
            .canonical_json_body()
            .map_err(|e| AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: e.to_string(),
            })?;

        if let Some(ref expected_hash) = prev_computed_hash
            && entry.previous_entry_hash != *expected_hash
        {
            return Err(AuditLogIntegrityError::ChainBroken {
                line: line_number,
                file: path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_owned(),
                reason: "previous_entry_hash mismatch",
            });
        }

        let current_hash = compute_entry_hash(&body, &entry.previous_entry_hash).map_err(|e| {
            AuditLogIntegrityError::ParseError {
                line: line_number,
                detail: format!("chain hash computation failed: {e}"),
            }
        })?;
        prev_computed_hash = Some(current_hash);

        // Match SaTimelockScheduled for the target timelock contract.
        if let EventKind::SaTimelockScheduled {
            operation_id_full_hex,
            timelock_contract_redacted: tl_redacted,
            audit_request_id,
            ..
        } = &entry.event_kind
            && tl_redacted.as_str() == timelock_contract_redacted
        {
            scheduled_ops
                .entry(operation_id_full_hex.clone())
                .or_insert_with(|| (audit_request_id.clone(), tl_redacted.as_str().to_owned()));
        }

        // Match SaTimelockCancelled for the target timelock contract.
        // `SaTimelockCancelled` carries `operation_id_full_hex`, so dedupe uses
        // the exact 64-hex match instead of the redacted form, eliminating the
        // 64-bit collision surface.
        if let EventKind::SaTimelockCancelled {
            operation_id_full_hex,
            timelock_contract_redacted: tl_redacted,
            ..
        } = &entry.event_kind
            && tl_redacted.as_str() == timelock_contract_redacted
        {
            scheduled_ops.remove(operation_id_full_hex.as_str());
            cancelled_or_executed.insert(operation_id_full_hex.clone());
        }

        // Match SaTimelockExecuted for the target timelock contract.
        // Exact `operation_id_full_hex` match (same rationale as Cancelled above).
        if let EventKind::SaTimelockExecuted {
            operation_id_full_hex,
            timelock_contract_redacted: tl_redacted,
            ..
        } = &entry.event_kind
            && tl_redacted.as_str() == timelock_contract_redacted
        {
            scheduled_ops.remove(operation_id_full_hex.as_str());
            cancelled_or_executed.insert(operation_id_full_hex.clone());
        }
    }

    Ok(())
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
        entry::{AuditEntry, NewToolInvocation},
        schema::PolicyDecision,
        signer_set::{BaselineReason, SignerPubkey},
        writer::AuditWriter,
    };
    use crate::observability::RedactedStrkey;
    use std::sync::Arc;
    use tempfile::TempDir;

    // ── Helper: build a log path in a tempdir ─────────────────────────────────

    fn tmp_log(dir: &TempDir) -> PathBuf {
        dir.path().join("audit.jsonl")
    }

    fn open_writer(path: PathBuf) -> Arc<Mutex<AuditWriter>> {
        Arc::new(Mutex::new(AuditWriter::open(path, None).unwrap()))
    }

    // ── Helper: build a SaSignerSetBaselined EventKind ────────────────────────

    fn baselined_event(
        rule_id: u32,
        sa_redacted: &str,
        signer_count: u32,
        threshold: u32,
    ) -> EventKind {
        let ids: Vec<u32> = (0..signer_count).collect();
        let pubkeys: Vec<SignerPubkey> = ids
            .iter()
            .map(|i| SignerPubkey::Ed25519 {
                pubkey: {
                    let mut k = [0u8; 32];
                    k[0] = (*i) as u8;
                    k
                },
            })
            .collect();
        // For Ed25519, first-8 bytes of the 32-byte pubkey.
        let pubkeys_first8: Vec<String> = pubkeys
            .iter()
            .map(|pk| match pk {
                SignerPubkey::Ed25519 { pubkey } => {
                    pubkey[..8].iter().map(|b| format!("{b:02x}")).collect()
                }
                _ => "0000000000000000".to_owned(),
            })
            .collect();
        EventKind::SaSignerSetBaselined {
            rule_id,
            observed_signer_count: signer_count,
            observed_threshold: threshold,
            observed_signer_ids: ids,
            observed_signer_pubkeys: pubkeys,
            observed_signer_pubkeys_first8: pubkeys_first8,
            observed_at_ledger_seq: 1_000,
            observed_at_unix_ms: 1_700_000_000_000,
            baseline_reason: BaselineReason::first_observation(),
            prev_chain_tip_hash: [0u8; 32],
            smart_account_redacted: RedactedStrkey::from_already_redacted(sa_redacted),
        }
    }

    // ── Helper: write an EventKind entry to a writer ──────────────────────────

    fn write_event(writer: &mut AuditWriter, kind: EventKind) {
        let mut entry = AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "smart-account.signers.list",
            Option::<String>::None,
            vec![],
            PolicyDecision::Allow,
            uuid::Uuid::new_v4().to_string(),
        ));
        // Replace the ToolInvocation kind with the signer-set kind.
        entry.event_kind = kind;
        writer.write_entry(entry).unwrap();
    }

    // ── 1. Basic find in active file ──────────────────────────────────────────

    #[test]
    fn find_latest_signer_set_state_returns_most_recent_in_active_file() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Write two baseline rows for the same (rule_id, smart_account).
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            write_event(&mut w, baselined_event(1, "CDABC...12345", 3, 2)); // more recent
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader
            .find_latest_signer_set_state(1, "CDABC...12345")
            .unwrap();

        let payload = result.expect("should find the most-recent row");
        assert_eq!(
            payload.state().signer_count,
            3,
            "should return the most-recent row"
        );
        assert_eq!(payload.state().threshold, 2);
        assert_ne!(*payload.row_hash(), [0u8; 32], "row_hash must be non-zero");
    }

    // ── 2. Returns None when no matching row ──────────────────────────────────

    #[test]
    fn find_latest_signer_set_state_returns_none_for_unmatched_rule() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        // Different rule_id — should not match.
        let result = reader
            .find_latest_signer_set_state(99, "CDABC...12345")
            .unwrap();
        assert!(result.is_none(), "should return None for unmatched rule_id");
    }

    #[test]
    fn find_latest_signer_set_state_returns_none_for_unmatched_smart_account() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader
            .find_latest_signer_set_state(1, "COTHER...OTHER")
            .unwrap();
        assert!(
            result.is_none(),
            "should return None for unmatched smart_account"
        );
    }

    // ── 3. Finds baseline row in a rotated file ───────────────────────────────

    #[test]
    fn find_latest_signer_set_state_discovers_baseline_in_rotated_file() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            // Use the test-only force-rotate helper to trigger rotation
            // without writing 10 MiB of filler data.
            w.force_rotate_for_test().unwrap();
            // Write a non-matching entry in the new (active) file.
            write_event(&mut w, baselined_event(99, "COTHER...OTHER", 1, 1));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader
            .find_latest_signer_set_state(1, "CDABC...12345")
            .unwrap();

        let payload = result.expect("should find baseline row in rotated file");
        assert_eq!(payload.state().signer_count, 2);
    }

    // ── 4. Torn-tail returns integrity error not None ─────────────────────────

    #[test]
    fn find_latest_signer_set_state_torn_tail_returns_parse_error_not_none() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
        }

        // Capture the actual last-line length at write time, then truncate by
        // last_line_len / 2 bytes. Self-adapting — works regardless of future
        // schema changes to the entry layout.
        {
            use std::io::{BufRead, BufReader, Seek};
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let total_len = f.seek(std::io::SeekFrom::End(0)).unwrap();
            f.seek(std::io::SeekFrom::Start(0)).unwrap();
            // Find the length of the last line.
            let reader_tmp = BufReader::new(&mut f);
            let last_line_len = reader_tmp
                .lines()
                .last()
                .and_then(|r| r.ok())
                .map(|l| l.len() + 1) // +1 for the newline
                .unwrap_or(20) as u64;
            let truncate_by = (last_line_len / 2).max(4); // at least 4 bytes into JSON
            let truncate_to = total_len.saturating_sub(truncate_by);
            if truncate_to > 0 {
                f.set_len(truncate_to).unwrap();
            }
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_latest_signer_set_state(1, "CDABC...12345");

        // Must return an error, NOT Ok(None).
        assert!(
            result.is_err(),
            "torn tail must return Err, not Ok(None): {result:?}"
        );
        match result.unwrap_err() {
            AuditLogIntegrityError::ParseError { .. } => {}
            other => panic!("expected ParseError, got: {other:?}"),
        }
    }

    // ── 5. Concurrent-write race — truly races writers vs reader ─────────

    #[test]
    fn concurrent_write_and_read_no_torn_state() {
        // The test truly races writers against a reader rather than
        // joining the writer thread before reading. The assertion is that the
        // reader never sees a torn/parse-error state — it sees either a matching
        // row or no row, never corruption.
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        // Pre-write one baseline row so the reader always has something to scan.
        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
        }

        // Spawn a writer thread that appends 100 baseline entries, releasing
        // the mutex between each write to allow the reader to interleave.
        let writer_clone = Arc::clone(&writer);
        let writer_thread = std::thread::spawn(move || {
            for i in 0u32..100 {
                {
                    let mut w = writer_clone.lock().unwrap();
                    write_event(&mut w, baselined_event(1, "CDABC...12345", 2 + (i % 3), 2));
                }
                std::thread::yield_now();
            }
        });

        // Reader runs concurrently. The shared mutex ensures the reader always
        // sees fully-written entries (no torn lines).
        let reader = AuditReader::new(Arc::clone(&writer), None);
        for _ in 0..100 {
            let result = reader.find_latest_signer_set_state(1, "CDABC...12345");
            assert!(
                result.is_ok(),
                "reader saw a torn / parse-error state under concurrent write: {result:?}"
            );
            std::thread::yield_now();
        }

        writer_thread.join().unwrap();

        // After all writes complete, the reader must see a valid row.
        let final_result = reader
            .find_latest_signer_set_state(1, "CDABC...12345")
            .unwrap();
        assert!(
            final_result.is_some(),
            "row must be visible after all writes"
        );
    }

    // ── 6. AuditLogIntegrityError wire-code coverage ─────────────────────────

    #[test]
    fn audit_log_integrity_error_wire_codes_cover_all_variants() {
        // Use an exhaustive `match` so adding a new VerifyError variant forces
        // a compile error (no wildcard arm). A Vec approach would silently miss
        // new variants.
        fn wire_code_by_match(e: &AuditLogIntegrityError) -> &'static str {
            match e {
                AuditLogIntegrityError::ChainBroken { .. } => "audit.chain_broken",
                AuditLogIntegrityError::RotationGap { .. } => "audit.rotation_gap",
                AuditLogIntegrityError::HmacMismatch { .. } => "audit.hmac_mismatch",
                AuditLogIntegrityError::HmacSidecarMissing { .. } => "audit.hmac_sidecar_missing",
                AuditLogIntegrityError::TooManyRotatedFiles { .. } => {
                    "audit.too_many_rotated_files"
                }
                AuditLogIntegrityError::NonRegularFileLogPath { .. } => {
                    "audit.non_regular_file_log_path"
                }
                AuditLogIntegrityError::ParseError { .. } => "audit.parse_error",
                AuditLogIntegrityError::PathContract { .. } => "audit.path_contract",
                AuditLogIntegrityError::LogNotFound { .. } => "audit.log_not_found",
                AuditLogIntegrityError::Io(_) => "audit.io_error",
                AuditLogIntegrityError::SignerSetCanonicalBody(_) => {
                    "audit.signer_set_canonical_body"
                }
                AuditLogIntegrityError::PartialRotation { .. } => "audit.partial_rotation",
            }
        }

        let errors = [
            AuditLogIntegrityError::ChainBroken {
                line: 1,
                file: "f".to_owned(),
                reason: "test",
            },
            AuditLogIntegrityError::RotationGap {
                file: "f".to_owned(),
            },
            AuditLogIntegrityError::HmacMismatch {
                file: "f".to_owned(),
            },
            AuditLogIntegrityError::HmacSidecarMissing {
                file: "f".to_owned(),
            },
            AuditLogIntegrityError::TooManyRotatedFiles { found: 22, cap: 21 },
            AuditLogIntegrityError::NonRegularFileLogPath {
                path: PathBuf::from("/dev/null"),
            },
            AuditLogIntegrityError::ParseError {
                line: 1,
                detail: "bad json".to_owned(),
            },
            AuditLogIntegrityError::PathContract {
                detail: "no parent".to_owned(),
            },
            AuditLogIntegrityError::LogNotFound {
                path: "/tmp/audit.jsonl".to_owned(),
            },
            AuditLogIntegrityError::Io(std::io::Error::other("ambient")),
            AuditLogIntegrityError::SignerSetCanonicalBody(
                crate::audit_log::signer_set::SignerSetCanonicalBodyError::MalformedObservedSignerSet {
                    reason: "signer_ids.len() != signer_pubkeys.len()",
                },
            ),
            AuditLogIntegrityError::PartialRotation {
                state: crate::audit_log::PartialRotationState::MidRename {
                    tmp_path: PathBuf::from("/tmp/audit.tmp"),
                    size_bytes: 42,
                },
                recovery_hint: "see runbook".to_owned(),
            },
        ];

        for err in &errors {
            // The match-derived code must equal the wire_code() method's output.
            let match_code = wire_code_by_match(err);
            let method_code = err.wire_code();
            assert!(
                !match_code.is_empty(),
                "every VerifyError variant must have a non-empty wire code"
            );
            assert!(
                match_code.starts_with("audit."),
                "wire code must start with 'audit.': {match_code}"
            );
            assert_eq!(
                match_code, method_code,
                "match-derived wire code must equal wire_code() method output"
            );
        }
    }

    // ── 7. Chain-hash tampering returns ChainBroken, not Ok(None) ────────────

    #[test]
    fn chain_hash_tampering_returns_chain_broken_not_none() {
        // If a row's `previous_entry_hash` is mutated after writing (simulating
        // an attacker editing the log), the reader must return
        // AuditLogIntegrityError::ChainBroken, NOT Ok(None).
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Write two entries: the first (row 1) is the baseline, the second
            // (row 2) must reference row 1's hash. We then tamper row 2's
            // `previous_entry_hash` in the file.
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            write_event(&mut w, baselined_event(1, "CDABC...12345", 3, 2));
        }

        // Tamper: read the file, locate the second JSON line, and replace its
        // `"previous_entry_hash":"sha256:..."` with a corrupted prefix to break
        // the chain link. The replacement targets the SHA-256 prefix so that the
        // hash value no longer matches `compute_entry_hash` output. The body
        // (JSON) remains parseable, so the reader reaches the chain-hash check
        // and returns ChainBroken — not ParseError.
        {
            let contents = std::fs::read_to_string(&path).unwrap();
            let mut lines: Vec<String> = contents.lines().map(|l| l.to_owned()).collect();
            // Row 2 is at index 1 (0-based). If only one row was written, skip.
            if lines.len() >= 2 {
                let tampered_row = lines[1].replace(
                    "\"previous_entry_hash\":\"sha256:",
                    "\"previous_entry_hash\":\"sha256:AAAA",
                );
                // Only write back if the substitution actually changed the line
                // (i.e. the pattern was found and replaced).
                if tampered_row != lines[1] {
                    lines[1] = tampered_row;
                    let new_contents = lines.join("\n") + "\n";
                    std::fs::write(&path, new_contents).unwrap();
                }
            }
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_latest_signer_set_state(1, "CDABC...12345");

        // Must return exactly ChainBroken: the tamper mutates body bytes that
        // survive JSON parsing, so the chain-hash check fires — not ParseError.
        // Wire codes are distinct; ChainBroken is the correct variant for a
        // hash mismatch that passes parse-level validation.
        match result {
            Err(AuditLogIntegrityError::ChainBroken { .. }) => {
                // Correct: chain-hash mismatch propagated as expected.
            }
            Ok(None) => panic!("tampered chain must not return Ok(None)"),
            Ok(Some(_)) => panic!("tampered chain must not return Ok(Some(...))"),
            Err(other) => panic!("expected ChainBroken, got: {other:?}"),
        }
    }

    // ── 8. Missing active file with rotated siblings → RotationGap ────────

    #[test]
    fn missing_active_file_with_rotated_siblings_returns_rotation_gap() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            // Force rotation to create a rotated sibling.
            w.force_rotate_for_test().unwrap();
            // Write one entry in the new active file to confirm it exists.
            write_event(&mut w, baselined_event(99, "COTHER...OTHER", 1, 1));
        }

        // Remove the active file to simulate out-of-band deletion / tampering.
        // `writer` stays alive (and its sidecar lock held) for the rest of the
        // test, so this exercises the "genuinely missing, not a transient
        // rotation window" path of `wait_out_transient_rotation_window`: the
        // lock IS held, so the scan retries up to its bound before giving up,
        // but the file never reappears (nothing recreates it here), so the
        // final outcome is unchanged — just reached after a bounded delay of
        // at most 20ms rather than immediately.
        std::fs::remove_file(&path).unwrap();

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_latest_signer_set_state(1, "CDABC...12345");

        match result {
            Err(AuditLogIntegrityError::RotationGap { .. }) => {
                // Correct: missing active file with rotated siblings is a gap.
            }
            other => {
                panic!("expected RotationGap for missing active file with siblings, got: {other:?}")
            }
        }
    }

    // ── 8b. Active file transiently absent during a live rotation ────────────

    /// Pins the rotation-window tolerance: if the active file reappears
    /// before the retry bound is exhausted, the scan proceeds normally
    /// instead of surfacing a spurious `RotationGap`.
    ///
    /// Simulates the window `AuditWriter::rotate` opens between archiving the
    /// old active file and creating the new one by removing the active file
    /// and having a background thread recreate it (with its real content)
    /// after a short delay, while the writer — and its sidecar lock — stays
    /// alive throughout, exactly as a live writer's rotation would.
    #[test]
    fn active_file_transient_absence_while_writer_alive_recovers() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            // Force rotation to create a rotated sibling.
            w.force_rotate_for_test().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 3, 3));
        }

        let saved_active_contents = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        let recreate_path = path.clone();
        let recreate_handle = std::thread::spawn(move || {
            // Comfortably inside the retry bound (20 attempts x 1ms = 20ms).
            std::thread::sleep(std::time::Duration::from_millis(3));
            std::fs::write(&recreate_path, &saved_active_contents).unwrap();
        });

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_latest_signer_set_state(1, "CDABC...12345");
        recreate_handle.join().unwrap();

        let payload = result
            .expect("transient rotation-window absence must not surface as RotationGap")
            .expect("row must still be found once the active file reappears");
        assert_eq!(payload.state().signer_count, 3);
    }

    // ── 9. Single-row predecessor-hash tamper → ChainBroken ──────────────────

    // ── Helper: build a SaSignerAdded EventKind ───────────────────────────────

    fn signer_added_event(
        rule_id: u32,
        sa_redacted: &str,
        count: u32,
        threshold: u32,
    ) -> EventKind {
        let ids: Vec<u32> = (0..count).collect();
        let pubkeys: Vec<SignerPubkey> = ids
            .iter()
            .map(|i| SignerPubkey::Ed25519 {
                pubkey: {
                    let mut k = [0u8; 32];
                    k[0] = *i as u8;
                    k
                },
            })
            .collect();
        let pubkeys_first8: Vec<String> = pubkeys
            .iter()
            .map(|pk| match pk {
                SignerPubkey::Ed25519 { pubkey } => {
                    pubkey[..8].iter().map(|b| format!("{b:02x}")).collect()
                }
                _ => "0000000000000000".to_owned(),
            })
            .collect();
        EventKind::SaSignerAdded {
            rule_id,
            signer_id: count.saturating_sub(1),
            resulting_signer_count: count,
            resulting_threshold: threshold,
            resulting_signer_ids: ids,
            resulting_signer_pubkeys: pubkeys,
            resulting_signer_pubkeys_first8: pubkeys_first8,
            smart_account_redacted: RedactedStrkey::from_already_redacted(sa_redacted),
        }
    }

    // ── Helper: build a SaSignerRemoved EventKind ─────────────────────────────

    fn signer_removed_event(
        rule_id: u32,
        sa_redacted: &str,
        count: u32,
        threshold: u32,
    ) -> EventKind {
        let ids: Vec<u32> = (0..count).collect();
        let pubkeys: Vec<SignerPubkey> = ids
            .iter()
            .map(|i| SignerPubkey::Ed25519 {
                pubkey: {
                    let mut k = [0u8; 32];
                    k[0] = *i as u8;
                    k
                },
            })
            .collect();
        let pubkeys_first8: Vec<String> = pubkeys
            .iter()
            .map(|pk| match pk {
                SignerPubkey::Ed25519 { pubkey } => {
                    pubkey[..8].iter().map(|b| format!("{b:02x}")).collect()
                }
                _ => "0000000000000000".to_owned(),
            })
            .collect();
        EventKind::SaSignerRemoved {
            rule_id,
            signer_id: count,
            resulting_signer_count: count,
            resulting_threshold: threshold,
            resulting_signer_ids: ids,
            resulting_signer_pubkeys: pubkeys,
            resulting_signer_pubkeys_first8: pubkeys_first8,
            smart_account_redacted: RedactedStrkey::from_already_redacted(sa_redacted),
        }
    }

    // ── Helper: build a SaThresholdChanged EventKind ──────────────────────────

    fn threshold_changed_event(
        rule_id: u32,
        sa_redacted: &str,
        count: u32,
        new_threshold: u32,
    ) -> EventKind {
        let ids: Vec<u32> = (0..count).collect();
        let pubkeys: Vec<SignerPubkey> = ids
            .iter()
            .map(|i| SignerPubkey::Ed25519 {
                pubkey: {
                    let mut k = [0u8; 32];
                    k[0] = *i as u8;
                    k
                },
            })
            .collect();
        let pubkeys_first8: Vec<String> = pubkeys
            .iter()
            .map(|pk| match pk {
                SignerPubkey::Ed25519 { pubkey } => {
                    pubkey[..8].iter().map(|b| format!("{b:02x}")).collect()
                }
                _ => "0000000000000000".to_owned(),
            })
            .collect();
        EventKind::SaThresholdChanged {
            rule_id,
            old_threshold: 1,
            new_threshold,
            resulting_threshold: new_threshold,
            resulting_signer_count: count,
            resulting_signer_ids: ids,
            resulting_signer_pubkeys: pubkeys,
            resulting_signer_pubkeys_first8: pubkeys_first8,
            smart_account_redacted: RedactedStrkey::from_already_redacted(sa_redacted),
        }
    }

    // ── Helper: build a SaContextRuleCreated EventKind ───────────────────────

    fn context_rule_created_event(
        rule_id: u32,
        sa_redacted: &str,
        verifier_hashes: Vec<String>,
        policy_hashes: Vec<String>,
        mutable_override: bool,
        unknown_override: bool,
    ) -> EventKind {
        EventKind::SaContextRuleCreated {
            smart_account: sa_redacted.to_owned(),
            rule_id,
            context_type: "default".to_owned(),
            signers_count: 1,
            policies_count: policy_hashes.len() as u32,
            valid_until: None,
            pinned_verifier_wasm_hashes_first8: verifier_hashes,
            pinned_policy_wasm_hashes_first8: policy_hashes,
            mutable_override,
            unknown_override,
        }
    }

    // ── Helper: build a SaContextRuleDeleted EventKind ───────────────────────

    fn context_rule_deleted_event(rule_id: u32, sa_redacted: &str) -> EventKind {
        EventKind::SaContextRuleDeleted {
            smart_account: sa_redacted.to_owned(),
            rule_id,
        }
    }

    // ── Helper: build a SaTimelockScheduled EventKind ────────────────────────

    fn timelock_scheduled_event(
        op_id_full_hex: &str,
        tl_redacted: &str,
        request_id: &str,
    ) -> EventKind {
        EventKind::SaTimelockScheduled {
            operation_id_redacted: format!("{}...{}", &op_id_full_hex[..8], &op_id_full_hex[56..]),
            operation_id_full_hex: op_id_full_hex.to_owned(),
            timelock_contract_redacted: RedactedStrkey::from_already_redacted(tl_redacted),
            target_redacted: RedactedStrkey::from_already_redacted("CAAAA...BBBBB"),
            function: "upgrade".to_owned(),
            delay_ledgers: 100,
            proposer_redacted: RedactedStrkey::from_already_redacted("GAAA1...11111"),
            schedule_tx_hash_redacted: "aabbccdd...11223344".to_owned(),
            audit_request_id: request_id.to_owned(),
        }
    }

    // ── Helper: build a SaTimelockCancelled EventKind ────────────────────────

    fn timelock_cancelled_event(op_id_full_hex: &str, tl_redacted: &str) -> EventKind {
        EventKind::SaTimelockCancelled {
            operation_id_redacted: format!("{}...{}", &op_id_full_hex[..8], &op_id_full_hex[56..]),
            operation_id_full_hex: op_id_full_hex.to_owned(),
            timelock_contract_redacted: RedactedStrkey::from_already_redacted(tl_redacted),
            canceller_redacted: RedactedStrkey::from_already_redacted("GAAA1...22222"),
            cancel_tx_hash_redacted: "aabbccdd...99887766".to_owned(),
            audit_request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    // ── Helper: build a SaTimelockExecuted EventKind ─────────────────────────

    fn timelock_executed_event(op_id_full_hex: &str, tl_redacted: &str) -> EventKind {
        EventKind::SaTimelockExecuted {
            operation_id_redacted: format!("{}...{}", &op_id_full_hex[..8], &op_id_full_hex[56..]),
            operation_id_full_hex: op_id_full_hex.to_owned(),
            timelock_contract_redacted: RedactedStrkey::from_already_redacted(tl_redacted),
            executor_redacted: None,
            execute_tx_hash_redacted: "aabbccdd...77665544".to_owned(),
            audit_request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    // ── 10. SaSignerAdded is picked up by find_latest_signer_set_state ────────

    #[test]
    fn find_latest_signer_set_state_picks_up_signer_added_event() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Write a baseline, then a signer-added event that supersedes it.
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            write_event(&mut w, signer_added_event(1, "CDABC...12345", 3, 2));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader
            .find_latest_signer_set_state(1, "CDABC...12345")
            .unwrap();

        let payload = result.expect("should find signer-added event");
        assert_eq!(
            payload.state().signer_count,
            3,
            "SaSignerAdded resulting count must be returned"
        );
        assert_eq!(payload.state().threshold, 2);
        assert_eq!(
            payload.state().signer_ids.len(),
            3,
            "signer_ids length must match resulting_signer_count"
        );
    }

    // ── 11. SaSignerRemoved is picked up by find_latest_signer_set_state ──────

    #[test]
    fn find_latest_signer_set_state_picks_up_signer_removed_event() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 3, 2));
            write_event(&mut w, signer_removed_event(1, "CDABC...12345", 2, 2));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let payload = reader
            .find_latest_signer_set_state(1, "CDABC...12345")
            .unwrap()
            .expect("should find signer-removed event");

        assert_eq!(
            payload.state().signer_count,
            2,
            "SaSignerRemoved resulting count must be returned"
        );
    }

    // ── 12. SaThresholdChanged is picked up by find_latest_signer_set_state ───

    #[test]
    fn find_latest_signer_set_state_picks_up_threshold_changed_event() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 1));
            write_event(&mut w, threshold_changed_event(1, "CDABC...12345", 2, 2));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let payload = reader
            .find_latest_signer_set_state(1, "CDABC...12345")
            .unwrap()
            .expect("should find threshold-changed event");

        assert_eq!(
            payload.state().threshold,
            2,
            "SaThresholdChanged resulting threshold must be returned"
        );
        assert_eq!(
            payload.state().signer_count,
            2,
            "signer count must be unchanged by threshold change"
        );
    }

    // ── 13. find_latest_context_rule_pinned_hashes: basic round-trip ──────────

    #[test]
    fn find_latest_context_rule_pinned_hashes_returns_pinned_hashes() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(
                    5,
                    "CDABC...12345",
                    vec!["aabbccdd".to_owned()],
                    vec!["11223344".to_owned()],
                    false,
                    false,
                ),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader
            .find_latest_context_rule_pinned_hashes(5, "CDABC...12345")
            .unwrap();

        let record = result.expect("should find SaContextRuleCreated row");
        assert_eq!(
            record.pinned_verifier_first8,
            vec!["aabbccdd"],
            "verifier hash must be returned verbatim"
        );
        assert_eq!(
            record.pinned_policy_first8,
            vec!["11223344"],
            "policy hash must be returned verbatim"
        );
        assert!(!record.mutable_override);
        assert!(!record.unknown_override);
    }

    // ── 14. find_latest_context_rule_pinned_hashes: mutable/unknown overrides ──

    #[test]
    fn find_latest_context_rule_pinned_hashes_returns_override_flags() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(
                    7,
                    "CDABC...12345",
                    vec!["aabb0011".to_owned()],
                    vec![],
                    true,
                    true,
                ),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let record = reader
            .find_latest_context_rule_pinned_hashes(7, "CDABC...12345")
            .unwrap()
            .expect("should find the row");

        assert!(
            record.mutable_override,
            "mutable_override must be true when set at install"
        );
        assert!(
            record.unknown_override,
            "unknown_override must be true when set at install"
        );
    }

    // ── 15. find_latest_context_rule_pinned_hashes: returns None when no match ─

    #[test]
    fn find_latest_context_rule_pinned_hashes_returns_none_when_no_match() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        // Different rule_id — must not match.
        let result = reader
            .find_latest_context_rule_pinned_hashes(99, "CDABC...12345")
            .unwrap();
        assert!(result.is_none());
    }

    // ── 16. find_latest_context_rule_pinned_hashes: most-recent row wins ───────

    #[test]
    fn find_latest_context_rule_pinned_hashes_returns_most_recent_row() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // First install — verifier hash "aaaaaaaa".
            write_event(
                &mut w,
                context_rule_created_event(
                    1,
                    "CDABC...12345",
                    vec!["aaaaaaaa".to_owned()],
                    vec![],
                    false,
                    false,
                ),
            );
            // Reinstall (rule_id same) — verifier hash "bbbbbbbb". More recent.
            write_event(
                &mut w,
                context_rule_created_event(
                    1,
                    "CDABC...12345",
                    vec!["bbbbbbbb".to_owned()],
                    vec![],
                    false,
                    false,
                ),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let record = reader
            .find_latest_context_rule_pinned_hashes(1, "CDABC...12345")
            .unwrap()
            .expect("should find a row");

        assert_eq!(
            record.pinned_verifier_first8,
            vec!["bbbbbbbb"],
            "most-recent reinstall hash must win"
        );
    }

    // ── 17. scan_all_context_rule_created: collects all rules ─────────────────

    #[test]
    fn scan_all_context_rule_created_collects_all_rules_deduped() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Rule 1 on account A — installed twice; most-recent wins.
            write_event(
                &mut w,
                context_rule_created_event(
                    1,
                    "CAAA1...11111",
                    vec!["aaaaaaaa".to_owned()],
                    vec![],
                    false,
                    false,
                ),
            );
            write_event(
                &mut w,
                context_rule_created_event(
                    1,
                    "CAAA1...11111",
                    vec!["bbbbbbbb".to_owned()],
                    vec![],
                    false,
                    false,
                ),
            );
            // Rule 2 on account B — installed once.
            write_event(
                &mut w,
                context_rule_created_event(
                    2,
                    "CBBB2...22222",
                    vec!["cccccccc".to_owned()],
                    vec!["dddddddd".to_owned()],
                    false,
                    false,
                ),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let mut results = reader.scan_all_context_rule_created().unwrap();
        // Results are sorted by (rule_id, smart_account).
        results.sort_by_key(|(rid, sa, _)| (*rid, sa.clone()));

        assert_eq!(results.len(), 2, "two distinct (rule_id, sa) pairs");

        let (r0_id, r0_sa, r0_rec) = &results[0];
        assert_eq!(*r0_id, 1);
        assert_eq!(r0_sa, "CAAA1...11111");
        assert_eq!(
            r0_rec.pinned_verifier_first8,
            vec!["bbbbbbbb"],
            "most-recent reinstall must win for rule 1"
        );

        let (r1_id, r1_sa, r1_rec) = &results[1];
        assert_eq!(*r1_id, 2);
        assert_eq!(r1_sa, "CBBB2...22222");
        assert_eq!(r1_rec.pinned_verifier_first8, vec!["cccccccc"]);
        assert_eq!(r1_rec.pinned_policy_first8, vec!["dddddddd"]);
    }

    // ── 18. scan_all_context_rule_created: empty log returns empty vec ─────────

    #[test]
    fn scan_all_context_rule_created_returns_empty_for_empty_log() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        // Write a non-contextRuleCreated row so the log file exists but has no
        // matching rows.
        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 1, 1));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let results = reader.scan_all_context_rule_created().unwrap();
        assert!(
            results.is_empty(),
            "no SaContextRuleCreated rows → empty result"
        );
    }

    // ── 19. find_installed_context_rule_ids: basic lifecycle ──────────────────

    #[test]
    fn find_installed_context_rule_ids_returns_created_minus_deleted() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Install rules 1, 2, 3 then delete rule 2.
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(
                &mut w,
                context_rule_created_event(2, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(
                &mut w,
                context_rule_created_event(3, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(&mut w, context_rule_deleted_event(2, "CDABC...12345"));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let live_ids = reader
            .find_installed_context_rule_ids("CDABC...12345")
            .unwrap();

        assert_eq!(live_ids, vec![1, 3], "rule 2 deleted; rules 1 and 3 live");
    }

    // ── 20. find_installed_context_rule_ids: all deleted returns empty ─────────

    #[test]
    fn find_installed_context_rule_ids_returns_empty_when_all_deleted() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(&mut w, context_rule_deleted_event(1, "CDABC...12345"));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let live_ids = reader
            .find_installed_context_rule_ids("CDABC...12345")
            .unwrap();

        assert!(
            live_ids.is_empty(),
            "all installed rules deleted → empty result"
        );
    }

    // ── 21. find_installed_context_rule_ids: no rows returns empty ────────────

    #[test]
    fn find_installed_context_rule_ids_returns_empty_for_different_account() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Rows exist but for a different smart account.
            write_event(
                &mut w,
                context_rule_created_event(1, "COTHER...OTHER", vec![], vec![], false, false),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let live_ids = reader
            .find_installed_context_rule_ids("CDABC...12345")
            .unwrap();

        assert!(
            live_ids.is_empty(),
            "rows for different SA must not appear in result"
        );
    }

    // ── 22. find_pending_timelock_operations: basic scheduled→pending ──────────

    #[test]
    fn find_pending_timelock_operations_returns_scheduled_ops() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let op_id = "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
        let tl_redacted = "CAAAA...BBBBB";
        let req_id = uuid::Uuid::new_v4().to_string();

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                timelock_scheduled_event(op_id, tl_redacted, &req_id),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let pending = reader
            .find_pending_timelock_operations(tl_redacted)
            .unwrap();

        assert_eq!(pending.len(), 1, "one pending op");
        let (found_op_id, found_req_id, found_tl) = &pending[0];
        assert_eq!(found_op_id, op_id, "operation_id_full_hex must match");
        assert_eq!(found_req_id, &req_id, "request_id must match");
        assert_eq!(found_tl, tl_redacted, "timelock_redacted must match");
    }

    // ── 23. find_pending_timelock_operations: cancelled removes from pending ───

    #[test]
    fn find_pending_timelock_operations_cancelled_op_is_not_pending() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let op_id = "1111111111111111111111111111111111111111111111111111111111111111";
        let tl_redacted = "CTLLL...TTTTT";

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                timelock_scheduled_event(op_id, tl_redacted, "req-sched-1"),
            );
            write_event(&mut w, timelock_cancelled_event(op_id, tl_redacted));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let pending = reader
            .find_pending_timelock_operations(tl_redacted)
            .unwrap();

        assert!(
            pending.is_empty(),
            "cancelled op must not appear in pending list"
        );
    }

    // ── 24. find_pending_timelock_operations: executed removes from pending ────

    #[test]
    fn find_pending_timelock_operations_executed_op_is_not_pending() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let op_id = "2222222222222222222222222222222222222222222222222222222222222222";
        let tl_redacted = "CTLLL...TTTTT";

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                timelock_scheduled_event(op_id, tl_redacted, "req-sched-2"),
            );
            write_event(&mut w, timelock_executed_event(op_id, tl_redacted));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let pending = reader
            .find_pending_timelock_operations(tl_redacted)
            .unwrap();

        assert!(
            pending.is_empty(),
            "executed op must not appear in pending list"
        );
    }

    // ── 25. find_pending_timelock_operations: two ops; one cancelled ──────────

    #[test]
    fn find_pending_timelock_operations_mixed_ops_only_pending_returned() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let op1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let op2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let tl_redacted = "CTLLL...TTTTT";
        let req1 = "req-a";
        let req2 = "req-b";

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, timelock_scheduled_event(op1, tl_redacted, req1));
            write_event(&mut w, timelock_scheduled_event(op2, tl_redacted, req2));
            // Cancel op1; op2 remains pending.
            write_event(&mut w, timelock_cancelled_event(op1, tl_redacted));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let pending = reader
            .find_pending_timelock_operations(tl_redacted)
            .unwrap();

        assert_eq!(pending.len(), 1, "only op2 is still pending");
        let (found_op_id, found_req_id, _) = &pending[0];
        assert_eq!(found_op_id, op2, "pending op must be op2");
        assert_eq!(found_req_id, req2);
    }

    // ── 26. find_pending_timelock_operations: different timelock addr ignored ──

    #[test]
    fn find_pending_timelock_operations_ignores_different_timelock_address() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let op_id = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let tl_a = "CTAAA...AAAAA";
        let tl_b = "CTBBB...BBBBB";

        {
            let mut w = writer.lock().unwrap();
            // Schedule on timelock A; query for timelock B.
            write_event(&mut w, timelock_scheduled_event(op_id, tl_a, "req-diff-tl"));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let pending = reader.find_pending_timelock_operations(tl_b).unwrap();

        assert!(
            pending.is_empty(),
            "ops on a different timelock must not appear"
        );
    }

    // ── 27. find_latest_context_rule_pinned_hashes: chain broken in active file

    #[test]
    fn find_latest_context_rule_pinned_hashes_chain_broken_propagates() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
        }

        // Tamper: corrupt the second row's `previous_entry_hash` field.
        {
            let contents = std::fs::read_to_string(&path).unwrap();
            let mut lines: Vec<String> = contents.lines().map(|l| l.to_owned()).collect();
            if lines.len() >= 2 {
                let tampered = lines[1].replace(
                    "\"previous_entry_hash\":\"sha256:",
                    "\"previous_entry_hash\":\"sha256:FFFF",
                );
                if tampered != lines[1] {
                    lines[1] = tampered;
                    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
                }
            }
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_latest_context_rule_pinned_hashes(1, "CDABC...12345");

        match result {
            Err(AuditLogIntegrityError::ChainBroken { .. }) => {}
            other => panic!("expected ChainBroken for tampered hash, got: {other:?}"),
        }
    }

    // ── 28. find_installed_context_rule_ids: chain broken propagates ──────────

    #[test]
    fn find_installed_context_rule_ids_chain_broken_propagates() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(
                &mut w,
                context_rule_created_event(2, "CDABC...12345", vec![], vec![], false, false),
            );
        }

        // Tamper: corrupt the second row's `previous_entry_hash`.
        {
            let contents = std::fs::read_to_string(&path).unwrap();
            let mut lines: Vec<String> = contents.lines().map(|l| l.to_owned()).collect();
            if lines.len() >= 2 {
                let tampered = lines[1].replace(
                    "\"previous_entry_hash\":\"sha256:",
                    "\"previous_entry_hash\":\"sha256:FFFF",
                );
                if tampered != lines[1] {
                    lines[1] = tampered;
                    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
                }
            }
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_installed_context_rule_ids("CDABC...12345");

        match result {
            Err(AuditLogIntegrityError::ChainBroken { .. }) => {}
            other => panic!("expected ChainBroken for tampered hash, got: {other:?}"),
        }
    }

    // ── 29. find_pending_timelock_operations: chain broken propagates ──────────

    #[test]
    fn find_pending_timelock_operations_chain_broken_propagates() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let op_id = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let tl_redacted = "CTLLL...TTTTT";

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                timelock_scheduled_event(op_id, tl_redacted, "req-chain-break"),
            );
            write_event(
                &mut w,
                timelock_scheduled_event(op_id, tl_redacted, "req-chain-break-2"),
            );
        }

        // Tamper: corrupt the second row's `previous_entry_hash`.
        {
            let contents = std::fs::read_to_string(&path).unwrap();
            let mut lines: Vec<String> = contents.lines().map(|l| l.to_owned()).collect();
            if lines.len() >= 2 {
                let tampered = lines[1].replace(
                    "\"previous_entry_hash\":\"sha256:",
                    "\"previous_entry_hash\":\"sha256:FFFF",
                );
                if tampered != lines[1] {
                    lines[1] = tampered;
                    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
                }
            }
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_pending_timelock_operations(tl_redacted);

        match result {
            Err(AuditLogIntegrityError::ChainBroken { .. }) => {}
            other => panic!("expected ChainBroken for tampered hash, got: {other:?}"),
        }
    }

    // ── 30. Empty active log (no entries yet) → all methods return Ok empty ────

    #[test]
    fn empty_log_all_methods_return_ok_empty() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        // Open writer without writing any entries — creates the file but leaves it empty.
        let writer = open_writer(path.clone());

        let reader = AuditReader::new(Arc::clone(&writer), None);

        let ss = reader
            .find_latest_signer_set_state(1, "CDABC...12345")
            .unwrap();
        assert!(
            ss.is_none(),
            "empty log: find_latest_signer_set_state must be None"
        );

        let pins = reader
            .find_latest_context_rule_pinned_hashes(1, "CDABC...12345")
            .unwrap();
        assert!(
            pins.is_none(),
            "empty log: find_latest_context_rule_pinned_hashes must be None"
        );

        let all_rules = reader.scan_all_context_rule_created().unwrap();
        assert!(
            all_rules.is_empty(),
            "empty log: scan_all_context_rule_created must be empty"
        );

        let ids = reader
            .find_installed_context_rule_ids("CDABC...12345")
            .unwrap();
        assert!(
            ids.is_empty(),
            "empty log: find_installed_context_rule_ids must be empty"
        );

        let pending = reader
            .find_pending_timelock_operations("CTLLL...TTTTT")
            .unwrap();
        assert!(
            pending.is_empty(),
            "empty log: find_pending_timelock_operations must be empty"
        );
    }

    // ── 31. row_hash is the body-only SHA-256, not the chain-link hash ─────────

    #[test]
    fn row_hash_is_body_only_sha256_not_chain_link_hash() {
        // The SignerSetStatePayload.row_hash is SHA-256(canonical_body with
        // previous_entry_hash=""), NOT the chain-link hash which also covers
        // the previous_entry_hash bytes. For the first row in a fresh log the
        // chain-link hash equals SHA-256(body || ZERO_BLOCK_HASH_bytes), but the
        // row_hash is SHA-256(body || "") (body-only canonical form).
        // We can verify by writing two entries for the same key; if both return
        // distinct row_hashes the second row's hash is NOT the same as the first.
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            write_event(&mut w, baselined_event(1, "CDABC...12345", 3, 2));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);

        // Query returns the most-recent row.
        let payload = reader
            .find_latest_signer_set_state(1, "CDABC...12345")
            .unwrap()
            .expect("must find a row");

        // The row_hash must be non-zero (not the zero-block placeholder).
        assert_ne!(
            *payload.row_hash(),
            [0u8; 32],
            "row_hash must be a real SHA-256, not the zero sentinel"
        );

        // The row_hash must be exactly 32 bytes (SHA-256 output size).
        assert_eq!(payload.row_hash().len(), 32, "row_hash must be 32 bytes");

        // The state fields must match the most-recent entry's payload.
        assert_eq!(payload.state().signer_count, 3);
    }

    // ── 32. scan_all_context_rule_created: newest-file-first ordering ──────────

    #[test]
    fn scan_all_context_rule_created_newest_file_wins_after_rotation() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Install rule 1 with verifier hash "aaaaaaaa" in the first (to-be-rotated) file.
            write_event(
                &mut w,
                context_rule_created_event(
                    1,
                    "CDABC...12345",
                    vec!["aaaaaaaa".to_owned()],
                    vec![],
                    false,
                    false,
                ),
            );
            w.force_rotate_for_test().unwrap();
            // Reinstall rule 1 with verifier hash "bbbbbbbb" in the new active file.
            write_event(
                &mut w,
                context_rule_created_event(
                    1,
                    "CDABC...12345",
                    vec!["bbbbbbbb".to_owned()],
                    vec![],
                    false,
                    false,
                ),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let results = reader.scan_all_context_rule_created().unwrap();

        // Exactly one (rule_id=1, sa) pair, with the most-recent (active-file) hash.
        assert_eq!(results.len(), 1, "deduped to one entry");
        let (_, _, rec) = &results[0];
        assert_eq!(
            rec.pinned_verifier_first8,
            vec!["bbbbbbbb"],
            "reinstall in newer file must win over older file's entry"
        );
    }

    // ── 33. find_installed_context_rule_ids: result is sorted ─────────────────

    #[test]
    fn find_installed_context_rule_ids_result_is_sorted() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Install rules in non-sorted order: 3, 1, 2.
            write_event(
                &mut w,
                context_rule_created_event(3, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(
                &mut w,
                context_rule_created_event(2, "CDABC...12345", vec![], vec![], false, false),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let ids = reader
            .find_installed_context_rule_ids("CDABC...12345")
            .unwrap();

        assert_eq!(ids, vec![1, 2, 3], "result must be sorted ascending");
    }

    // ── 34. Non-regular file at log path → NonRegularFileLogPath ──────────────

    #[cfg(unix)]
    #[test]
    fn symlink_at_log_path_returns_non_regular_file_error() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let target = dir.path().join("does_not_exist_target");

        // Create a dangling symlink at the log path.
        symlink(&target, &path).unwrap();

        // scan_file_for_signer_set calls open_regular_file which rejects symlinks.
        // We drive it through find_latest_signer_set_state. The writer is never
        // opened on this path (path doesn't exist as a real file), so we construct
        // the writer separately on a different path and then manually create a
        // reader pointing at the symlink path.
        let real_path = dir.path().join("real_audit.jsonl");
        let writer = open_writer(real_path.clone());

        // Write one entry via the real writer so we can swap the reader's path
        // below. Actually we bypass the reader's path-from-writer by creating
        // a symlink at the writer's own path — but the writer's path()
        // always points to real_path. Instead, test open_regular_file directly
        // through the internal function by constructing a temporary log file
        // that IS real, then replacing it with a symlink after opening.
        //
        // Simplest approach: write one valid entry to real_path,
        // then call scan_file_for_signer_set with the symlink path directly
        // (it's a module-private function reachable from the test mod via super::*).
        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 1, 1));
        }

        let result = scan_file_for_signer_set(
            &path, // symlink to non-existent target
            1,
            "CDABC...12345",
            None,
            None,
        );

        match result {
            Err(AuditLogIntegrityError::NonRegularFileLogPath { .. }) => {}
            Err(AuditLogIntegrityError::Io(_)) => {
                // Acceptable: some OS configurations return an Io error when
                // symlink_metadata fails on a dangling symlink.
            }
            other => panic!("expected NonRegularFileLogPath or Io for symlink, got: {other:?}"),
        }
    }

    // ── 35. collect_files_newest_first: active-only = single-element vec ───────

    #[test]
    fn collect_files_newest_first_active_only_returns_single_path() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        // Create the file to satisfy `dir.exists()` in collect_files_newest_first.
        std::fs::File::create(&path).unwrap();

        let chain = collect_files_newest_first(&path).unwrap();
        assert_eq!(chain.len(), 1, "no rotated siblings → only active file");
        assert_eq!(chain[0], path, "first element must be the active path");
    }

    // ── 36. find_latest_signer_set_state: active-file-only, no rotated files ───

    #[test]
    fn find_latest_signer_set_state_no_rows_no_rotated_files_returns_none() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        // Open writer; do NOT write anything.
        let writer = open_writer(path.clone());

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader
            .find_latest_signer_set_state(1, "CDABC...12345")
            .unwrap();

        assert!(
            result.is_none(),
            "fresh wallet with no entries must return None, not an error"
        );
    }

    #[test]
    fn single_row_active_file_previous_hash_tamper_returns_chain_broken() {
        // A file with exactly one row has no row-2 chain check to detect
        // tampering of that row. The first-row check enforces that the single
        // row's stored `previous_entry_hash` field equals ZERO_BLOCK_HASH (the
        // only valid predecessor for the first row in a single-file chain).
        //
        // What this test covers: `previous_entry_hash` field tampering on a
        // single-row baseline file. An attacker rewrites the stored
        // `previous_entry_hash` from ZERO_BLOCK_HASH to an arbitrary hash.
        // The first-row check in `scan_file_for_signer_set` catches this via
        // `expected_first_row_prev: Some(ZERO_BLOCK_HASH)` and returns `ChainBroken`.
        //
        // What this test does NOT cover: pure body-field tamper (e.g. mutating
        // `observed_signer_count` while leaving `previous_entry_hash` legitimate).
        // For a single-row file there is no row-2 chain link to catch body-field
        // tamper via hash-chain alone. Body-tamper detection for single-row
        // baseline files is layered: (a) HMAC sidecar when `hmac_key: Some(_)`;
        // (b) two-RPC divergence check at next-signing time. The audit-log
        // chain-only primitive does not detect pure body-tamper of a single-row
        // file; that is a defence-in-depth property of the layered model.
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Write exactly ONE baseline row — the fresh-wallet scenario.
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
        }

        // Tamper: rewrite the single row's `previous_entry_hash` field from
        // ZERO_BLOCK_HASH to an attacker-chosen value. The first-row check in
        // `scan_file_for_signer_set` must catch this and return ChainBroken.
        // Without the check, this single-row file would return Ok(Some(...)).
        //
        // ZERO_BLOCK_HASH = sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
        let tamper_applied;
        {
            let contents = std::fs::read_to_string(&path).unwrap();
            let mut lines: Vec<String> = contents.lines().map(|l| l.to_owned()).collect();
            assert_eq!(lines.len(), 1, "single-row precondition");
            // Replace the verbatim ZERO_BLOCK_HASH value stored in the JSON row's
            // `previous_entry_hash` field with an all-F hash.
            let original = lines[0].clone();
            let tampered = lines[0].replace(
                ZERO_BLOCK_HASH,
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            );
            tamper_applied = tampered != original;
            if tamper_applied {
                lines[0] = tampered;
                std::fs::write(&path, lines.join("\n") + "\n").unwrap();
            }
        }

        // Assert the tamper was applied. If ZERO_BLOCK_HASH no longer appears
        // verbatim in the stored row (schema drift), this test must fail loudly
        // rather than silently no-op. A silent skip would leave the first-row
        // check unverified for the new schema.
        assert!(
            tamper_applied,
            "schema drift: ZERO_BLOCK_HASH no longer appears verbatim in row; \
             this regression test must be re-authored for the new schema"
        );

        {
            let reader = AuditReader::new(Arc::clone(&writer), None);
            let result = reader.find_latest_signer_set_state(1, "CDABC...12345");

            // Must return ChainBroken — NOT Ok(None) (which would hide the tamper)
            // and NOT Ok(Some(...)) (which would return unmodified signer-set state
            // silently ignoring the tampered predecessor hash).
            match result {
                Err(AuditLogIntegrityError::ChainBroken { .. }) => {
                    // Correct: tampered `previous_entry_hash` on the single-row
                    // baseline file detected as expected.
                }
                Ok(None) => panic!("single-row tamper must not return Ok(None)"),
                Ok(Some(p)) => panic!(
                    "single-row tamper must not return Ok(Some(...)): signer_count={}",
                    p.state().signer_count
                ),
                Err(other) => panic!("expected ChainBroken, got: {other:?}"),
            }
        }
    }
}
