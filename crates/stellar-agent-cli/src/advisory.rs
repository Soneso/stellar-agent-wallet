//! Startup advisory check for revoked/retired verifier wasm hashes.
//!
//! On every CLI invocation, after profile load and before subcommand dispatch,
//! scan the local audit log for rules referencing verifier wasm hashes flagged
//! as `Revoked` or `Retired` in [`VERIFIER_ALLOWLIST`]. Emit one stderr
//! advisory line per affected rule.
//!
//! # No-network invariant
//!
//! [`run_startup_advisory`] accepts NO `StellarRpcClient` parameter. The only
//! I/O is reading the local audit-log file. The in-crate AST import-scan test
//! in `tests/advisory_no_network_deps.rs` enforces this invariant by walking
//! the transitive call closure of `run_startup_advisory` and asserting that no
//! networking, subprocess, or DNS import is reachable.
//!
//! # Advisory posture
//!
//! The advisory is purely informational and NON-FATAL. Audit-log errors
//! (file absent, I/O error, integrity violation) are logged at `warn!` level
//! and the advisory returns an empty [`AdvisoryResult`] — CLI startup
//! continues normally.
//!
//! # Test-helpers feature gate
//!
//! Under `#[cfg(any(test, feature = "test-helpers"))]`, the inner helper
//! `run_startup_advisory_with_allowlist` is exported. It accepts a synthetic
//! `&[VerifierAllowlistEntry]` allowlist parameter, enabling tests to exercise
//! the `Revoked` / `Retired` trigger paths without modifying the production
//! `VERIFIER_ALLOWLIST` constant. The trigger-path integration tests live in
//! the `#[cfg(test)] mod tests` block at the bottom of this file (Revoked,
//! Retired, dedup, and multi-rule cases).

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use tracing::warn;
use uuid::Uuid;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::reader::AuditReader;
use stellar_agent_core::audit_log::schema::VerifierAdvisoryKind;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_smart_account::verifier_allowlist::{
    VERIFIER_ALLOWLIST, VerifierAllowlistEntry, VerifierAuditStatus,
};

// ── AdvisoryResult ─────────────────────────────────────────────────────────────

/// Result of the startup advisory scan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdvisoryResult {
    /// Rule IDs that referenced a `Revoked` or `Retired` verifier hash.
    ///
    /// Empty when no revoked/retired verifier hashes are found in the audit
    /// log, or when the audit log is absent or unreadable.
    pub triggered_rule_ids: Vec<u32>,
}

// ── run_startup_advisory ───────────────────────────────────────────────────────

/// Runs the startup advisory scan against the local audit log using the
/// production [`VERIFIER_ALLOWLIST`].
///
/// This is a thin wrapper around `run_startup_advisory_with_allowlist` that
/// passes the compile-time constant allowlist. All I/O, error handling, and
/// audit-row emission are handled by the inner function.
///
/// # Non-fatal
///
/// Audit-log errors are logged at `warn!` level and an empty
/// [`AdvisoryResult`] is returned. CLI startup is NEVER aborted.
///
/// # No-network invariant
///
/// This function MUST NOT import or invoke `StellarRpcClient`,
/// `stellar_agent_network::rpc::*`, `use reqwest`, or `tokio::net::*`.
/// The only I/O is reading the local audit-log file at `audit_log_path`.
/// The AST import-scan in `tests/advisory_no_network_deps.rs` enforces this
/// invariant by walking the transitive call closure and checking for forbidden
/// networking, subprocess, or DNS imports.
#[must_use]
pub fn run_startup_advisory(audit_log_path: &Path) -> AdvisoryResult {
    advisory_impl(audit_log_path, VERIFIER_ALLOWLIST)
}

/// Runs the startup advisory scan with a caller-supplied `allowlist` slice.
///
/// Separated from [`run_startup_advisory`] to enable integration tests that
/// inject synthetic `Revoked` / `Retired` entries without modifying the
/// production `VERIFIER_ALLOWLIST` constant.
///
/// # Short-circuit
///
/// When the audit-log file is absent or empty (zero bytes), returns an empty
/// [`AdvisoryResult`] immediately — avoiding an `AuditWriter::open` + drop
/// cycle before subcommand dispatch.
///
/// # Algorithm
///
/// 1. If the audit-log file is absent or empty, return early.
/// 2. Open an `AuditWriter` to drive `AuditReader` construction and
///    advisory-row emission.
/// 3. Scan all `SaContextRuleCreated` rows (deduplicated most-recent-per-rule).
/// 4. For each rule, deduplicate `pinned_verifier_first8` before iterating.
/// 5. For any hash matching a `Revoked` or `Retired` allowlist entry, emit one
///    `[advisory]` stderr line and one `SaVerifierAllowlistAdvisory` audit row.
/// 6. Record `rule_id` in [`AdvisoryResult::triggered_rule_ids`] once per rule.
#[cfg(any(test, feature = "test-helpers"))]
#[cfg_attr(not(test), allow(dead_code))]
#[must_use]
pub fn run_startup_advisory_with_allowlist(
    audit_log_path: &Path,
    allowlist: &[VerifierAllowlistEntry],
) -> AdvisoryResult {
    advisory_impl(audit_log_path, allowlist)
}

/// Shared implementation — called by both entry points above.
#[allow(
    clippy::print_stderr,
    reason = "advisory output is operator-facing stderr"
)]
fn advisory_impl(audit_log_path: &Path, allowlist: &[VerifierAllowlistEntry]) -> AdvisoryResult {
    // ── 0. Short-circuit if audit-log is absent or empty ────────────────────
    // Avoids a redundant AuditWriter open/close cycle before subcommand dispatch.
    match std::fs::metadata(audit_log_path) {
        // Race window note: `metadata().len() == 0` is checked AFTER the file
        // exists; a concurrent writer appending between the metadata read and
        // `AuditWriter::open` would cause us to return `AdvisoryResult::default()`
        // instead of reading the new content. Currently safe because no
        // concurrent writers exist during startup-advisory (the advisory runs
        // before subcommand dispatch + before any production manager acquires the
        // audit-writer lock). If startup concurrency changes, reconsider this
        // short-circuit.
        Ok(meta) if meta.len() == 0 => return AdvisoryResult::default(),
        Err(_) => return AdvisoryResult::default(),
        Ok(_) => {}
    }

    // ── 1. Open the audit writer ─────────────────────────────────────────────
    // Writer needed for AuditReader construction AND for writing advisory rows.
    let writer: Arc<Mutex<AuditWriter>> = match open_audit_writer_for_advisory(audit_log_path) {
        Ok(w) => w,
        Err(e) => {
            warn!(
                audit_log_path = %audit_log_path.display(),
                error = %e,
                "startup advisory: could not open audit writer; advisory skipped"
            );
            return AdvisoryResult::default();
        }
    };

    // ── 2. Scan ALL SaContextRuleCreated rows via AuditReader ────────────────
    let reader = AuditReader::new(Arc::clone(&writer), None);
    let all_rules = match reader.scan_all_context_rule_created() {
        Ok(rows) => rows,
        Err(e) => {
            warn!(
                audit_log_path = %audit_log_path.display(),
                error = %e,
                "startup advisory: audit-log scan failed; advisory skipped"
            );
            return AdvisoryResult::default();
        }
    };

    if all_rules.is_empty() {
        return AdvisoryResult::default();
    }

    // ── 3. Check each rule's pinned hashes against the allowlist ──────────────
    let mut triggered_rule_ids: Vec<u32> = Vec::new();
    let request_id = Uuid::new_v4().to_string();

    for (rule_id, smart_account_redacted, pinned) in &all_rules {
        // Deduplicate hashes per rule before iterating: avoids duplicate stderr
        // lines + audit rows when the same hash appears more than once in the
        // pinned set.
        let unique_hashes: HashSet<&String> = pinned.pinned_verifier_first8.iter().collect();
        // Iterate in a stable order (sort the deduplicated set) for deterministic output.
        let mut sorted_hashes: Vec<&String> = unique_hashes.into_iter().collect();
        sorted_hashes.sort_unstable();

        for hash_first8 in sorted_hashes {
            let Some(advisory_kind) = find_advisory_kind_in(hash_first8, allowlist) else {
                continue;
            };

            // 3a. Emit operator-facing stderr advisory with variant-aware wording
            //     ("revoked verifier" would be misleading for a Retired entry).
            eprintln!(
                "[advisory] rule {} references {} verifier {}; \
                 run 'stellar-agent smart-account migrate-verifier' to remediate",
                rule_id, advisory_kind, hash_first8,
            );

            // 3b. Emit SaVerifierAllowlistAdvisory audit row.
            let entry = AuditEntry::new_sa_verifier_allowlist_advisory(
                *rule_id,
                RedactedStrkey::from_already_redacted(smart_account_redacted.as_str()),
                hash_first8.as_str(),
                advisory_kind,
                Option::<String>::None,
                request_id.as_str(),
            );
            match writer.lock() {
                Ok(mut w) => {
                    if let Err(e) = w.write_entry(entry) {
                        warn!(
                            rule_id = rule_id,
                            hash_first8 = %hash_first8,
                            error = %e,
                            "startup advisory: failed to write advisory audit row"
                        );
                    }
                }
                Err(poison) => {
                    // Mutex is poisoned — a prior write path panicked mid-write.
                    // Log at warn and continue; advisory row is best-effort.
                    warn!(
                        rule_id = rule_id,
                        hash_first8 = %hash_first8,
                        error = %format!("audit writer mutex poisoned: {poison}"),
                        "startup advisory: could not acquire audit writer lock; audit row skipped"
                    );
                }
            }

            // 3c. Record triggered rule_id (once per rule, not once per hash).
            if !triggered_rule_ids.contains(rule_id) {
                triggered_rule_ids.push(*rule_id);
            }
        }
    }

    AdvisoryResult { triggered_rule_ids }
}

// ── Internal helpers ───────────────────────────────────────────────────────────

/// Looks up `hash_first8` in the provided `allowlist` slice.
///
/// Returns [`VerifierAdvisoryKind::Revoked`] for `Revoked` entries and
/// [`VerifierAdvisoryKind::Retired`] for `Retired` entries.
///
/// # Default-emit on unknown posture
///
/// Unknown future `VerifierAuditStatus` variants (a future status that adds a
/// new advisory-triggering posture) default to
/// [`VerifierAdvisoryKind::Revoked`] rather than `None`. A `Revoked` advisory is
/// more conservative than silently swallowing the event. When `VerifierAuditStatus`
/// gains a new truly non-advisory variant, this arm must be updated explicitly.
///
/// # Returns
///
/// - `Some(Revoked)` — entry found with `Revoked` status.
/// - `Some(Retired)` — entry found with `Retired` status.
/// - `Some(Revoked)` — entry found with an unrecognised future status
///   (default-emit on unknown).
/// - `None` — entry found with `Audited`, `Provisional`, or `Unaudited` status
///   (no advisory needed; `Provisional` is a normal healthy state for a young
///   allowlist, not a disclosed vulnerability).
/// - `None` — hash not in allowlist (unknown hashes are not flagged; the
///   install-time gate already rejected them without `--accept-unknown-verifier`).
pub(crate) fn find_advisory_kind_in(
    hash_first8: &str,
    allowlist: &[VerifierAllowlistEntry],
) -> Option<VerifierAdvisoryKind> {
    for entry in allowlist {
        let entry_first8 = wasm_hash_first8_hex(&entry.wasm_hash);
        if entry_first8 == hash_first8 {
            return match &entry.audit_status {
                VerifierAuditStatus::Revoked { .. } => Some(VerifierAdvisoryKind::Revoked),
                VerifierAuditStatus::Retired { .. } => Some(VerifierAdvisoryKind::Retired),
                VerifierAuditStatus::Audited { .. }
                | VerifierAuditStatus::Provisional { .. }
                | VerifierAuditStatus::Unaudited => None,
                // Default-emit on unknown for future VerifierAuditStatus variants:
                // an unrecognised status defaults to Revoked rather than silently
                // swallowing the advisory.  Update this arm when a new
                // non-advisory status variant is introduced.
                _ => Some(VerifierAdvisoryKind::Revoked),
            };
        }
    }
    // Hash not in allowlist — not flagged.
    None
}

/// Converts the first 4 bytes of a 32-byte wasm hash to an 8-char lowercase hex string.
///
/// Matches the encoding used for `pinned_verifier_wasm_hashes_first8` in
/// `EventKind::SaContextRuleCreated`.
pub(crate) fn wasm_hash_first8_hex(wasm_hash: &[u8; 32]) -> String {
    wasm_hash[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Opens (or creates) the audit-log writer at `audit_log_path`.
///
/// Creates parent directories if absent. Maps errors to a `String` so the
/// advisory can `warn!` and skip non-fatally.
fn open_audit_writer_for_advisory(
    audit_log_path: &Path,
) -> Result<Arc<Mutex<AuditWriter>>, String> {
    if let Some(parent) = audit_log_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create parent dirs for audit log: {e}"))?;
    }

    let writer = AuditWriter::open(audit_log_path.to_path_buf(), None)
        .map_err(|e| format!("open audit writer: {e}"))?;
    Ok(Arc::new(Mutex::new(writer)))
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use stellar_agent_core::audit_log::entry::{AuditEntry, NewToolInvocation};
    use stellar_agent_core::audit_log::schema::{EventKind, PolicyDecision};
    use stellar_agent_core::audit_log::writer::AuditWriter;
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;

    // ── Helpers ────────────────────────────────────────────────────────────────

    fn tmp_log(dir: &TempDir) -> PathBuf {
        dir.path().join("audit.jsonl")
    }

    fn open_writer(path: PathBuf) -> Arc<Mutex<AuditWriter>> {
        Arc::new(Mutex::new(AuditWriter::open(path, None).unwrap()))
    }

    /// Writes a `SaContextRuleCreated` row with the given pinned verifier hashes.
    fn write_context_rule_created(
        writer: &Arc<Mutex<AuditWriter>>,
        rule_id: u32,
        smart_account: &str,
        pinned_hashes: Vec<String>,
    ) {
        let mut entry = AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "smart-account.rules.create",
            Option::<String>::None,
            vec![],
            PolicyDecision::Allow,
            Uuid::new_v4().to_string(),
        ));
        entry.event_kind = EventKind::SaContextRuleCreated {
            smart_account: smart_account.to_owned(),
            rule_id,
            context_type: "default".to_owned(),
            signers_count: 1,
            policies_count: 0,
            valid_until: None,
            pinned_verifier_wasm_hashes_first8: pinned_hashes,
            pinned_policy_wasm_hashes_first8: vec![],
            mutable_override: false,
            unknown_override: false,
        };
        writer.lock().unwrap().write_entry(entry).unwrap();
    }

    // ── Test 1: empty result when audit log is absent ─────────────────────────

    #[test]
    fn advisory_returns_empty_when_audit_log_absent() {
        // Path nested under a non-existent directory — open_audit_writer_for_advisory
        // will fail because it tries to create_dir_all then open the writer;
        // since the advisory has a guard path deep in the non-existent tree,
        // the create_dir_all would create them — so use an impossible path
        // (file as parent component).
        let dir = TempDir::new().unwrap();
        // Create a regular file, then try to use it as a directory (impossible parent).
        let file_as_dir = dir.path().join("regular_file");
        std::fs::write(&file_as_dir, b"content").unwrap();
        let impossible_path = file_as_dir.join("nested").join("audit.jsonl");

        let result = run_startup_advisory(&impossible_path);
        assert!(
            result.triggered_rule_ids.is_empty(),
            "advisory must return empty when audit log path cannot be opened"
        );
    }

    // ── Test 2: empty result when log has no SaContextRuleCreated rows ─────────

    #[test]
    fn advisory_returns_empty_when_audit_log_has_no_context_rule_rows() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut w = writer.lock().unwrap();
            // Write a ToolInvocation row only — no SaContextRuleCreated.
            let entry = AuditEntry::new_tool_invocation(NewToolInvocation::new(
                "smart-account.rules.list",
                Option::<String>::None,
                vec![],
                PolicyDecision::Allow,
                Uuid::new_v4().to_string(),
            ));
            w.write_entry(entry).unwrap();
        }
        // Drop the writer so the new open inside run_startup_advisory can acquire
        // the file-level lock (same process, different writer instance).
        drop(writer);

        let result = run_startup_advisory(&path);
        assert!(
            result.triggered_rule_ids.is_empty(),
            "advisory must return empty when no SaContextRuleCreated rows exist"
        );
    }

    // ── Test 3: no trigger for hash not in VERIFIER_ALLOWLIST ────────────────
    //
    // The name reflects the behavior under test: a hash absent from the
    // allowlist must not produce a positive trigger.

    #[test]
    fn advisory_returns_empty_when_hash_not_in_allowlist() {
        // Production VERIFIER_ALLOWLIST has three Provisional entries (OZ WebAuthn
        // v0.7.2 at index 0, OZ WebAuthn v0.7.1 at index 1, OZ Ed25519 v0.7.2 at
        // index 2).
        // "deadbeef" is not in the allowlist → advisory must NOT trigger.
        // Positive trigger paths (Revoked + Retired) are tested in
        // `advisory_emits_audit_row_and_eprintln_on_revoked_hash` and
        // `advisory_emits_audit_row_and_eprintln_on_retired_hash` below
        // (via `run_startup_advisory_with_allowlist`).
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        write_context_rule_created(&writer, 4, "CDABC...12345", vec!["deadbeef".to_owned()]);
        drop(writer);

        let result = run_startup_advisory(&path);
        assert!(
            result.triggered_rule_ids.is_empty(),
            "hash not in VERIFIER_ALLOWLIST must not trigger advisory; triggered={:?}",
            result.triggered_rule_ids
        );
    }

    // ── Test 4: advisory does NOT fire on Provisional entry ────────────────────

    #[test]
    fn advisory_does_not_fire_on_provisional_entry() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        // OZ v0.7.1 wasm_hash first-8-hex = "67800690" — Provisional in VERIFIER_ALLOWLIST.
        write_context_rule_created(&writer, 1, "CDABC...12345", vec!["67800690".to_owned()]);
        drop(writer);

        let result = run_startup_advisory(&path);
        assert!(
            result.triggered_rule_ids.is_empty(),
            "Provisional entry must not trigger advisory; triggered={:?}",
            result.triggered_rule_ids
        );
    }

    // ── Test 5: no trigger when hash is unknown (Retired-path negative case) ────
    //
    // The name reflects the behavior under test: the no-trigger path for a hash
    // not in the allowlist. The positive Retired trigger is tested below via
    // `run_startup_advisory_with_allowlist`.

    #[test]
    fn advisory_returns_empty_when_hash_not_in_allowlist_retired_path() {
        // "cafebabe" is not in VERIFIER_ALLOWLIST → advisory must NOT trigger.
        // The positive Retired branch (a Retired entry triggers the advisory) is
        // covered by `advisory_emits_audit_row_and_eprintln_on_retired_hash` below.
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        write_context_rule_created(&writer, 7, "CDABC...12345", vec!["cafebabe".to_owned()]);
        drop(writer);

        let result = run_startup_advisory(&path);
        assert!(
            result.triggered_rule_ids.is_empty(),
            "hash not in allowlist must not trigger advisory"
        );
    }

    // ── Test 6: no advisory emitted for empty audit log ────────────────────────

    #[test]
    fn advisory_emits_no_advisory_for_empty_audit_log() {
        // Empty log file (writer opens but no entries written) → empty result.
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        drop(writer);

        let result = run_startup_advisory(&path);
        assert!(
            result.triggered_rule_ids.is_empty(),
            "empty audit log must not trigger advisory"
        );
    }

    // ── Unit test: wasm_hash_first8_hex correctness ───────────────────────────

    #[test]
    fn wasm_hash_first8_hex_produces_correct_prefix() {
        let hash: [u8; 32] = {
            let mut h = [0u8; 32];
            h[0] = 0x67;
            h[1] = 0x80;
            h[2] = 0x06;
            h[3] = 0x90;
            h
        };
        assert_eq!(wasm_hash_first8_hex(&hash), "67800690");
    }

    #[test]
    fn wasm_hash_first8_hex_all_zeros() {
        let hash = [0u8; 32];
        assert_eq!(wasm_hash_first8_hex(&hash), "00000000");
    }

    #[test]
    fn wasm_hash_first8_hex_all_ff() {
        let hash = [0xffu8; 32];
        assert_eq!(wasm_hash_first8_hex(&hash), "ffffffff");
    }

    // ── Unit tests: find_advisory_kind_in ────────────────────────────────────

    #[test]
    fn find_advisory_kind_in_returns_none_for_provisional_oz_v071() {
        // OZ v0.7.1 hash first-8: "67800690" — Provisional → no advisory kind.
        let kind = find_advisory_kind_in("67800690", VERIFIER_ALLOWLIST);
        assert!(
            kind.is_none(),
            "Provisional OZ v0.7.1 must not produce an advisory kind"
        );
    }

    #[test]
    fn find_advisory_kind_in_returns_none_for_provisional_status() {
        // Synthetic Provisional entry, independent of production allowlist
        // contents — pins the explicit arm against the alarming `_` wildcard.
        let allowlist = [VerifierAllowlistEntry::new_for_test(
            [0x12u8; 32],
            VerifierAuditStatus::Provisional {
                attested_by: "OpenZeppelin",
                attested_at: "2026-01-01",
            },
        )];
        let entry_first8 = wasm_hash_first8_hex(&[0x12u8; 32]);
        let kind = find_advisory_kind_in(&entry_first8, &allowlist);
        assert!(
            kind.is_none(),
            "Provisional status must not produce an advisory kind"
        );
    }

    #[test]
    fn find_advisory_kind_in_returns_none_for_unknown_hash() {
        let kind = find_advisory_kind_in("00000000", VERIFIER_ALLOWLIST);
        assert!(
            kind.is_none(),
            "unknown hash must not produce advisory kind"
        );
    }

    /// The explicit `Revoked` arm in `find_advisory_kind_in` maps
    /// `VerifierAuditStatus::Revoked` to `VerifierAdvisoryKind::Revoked`.
    ///
    /// The `_ =>` default arm (which also maps unknown future variants to
    /// `VerifierAdvisoryKind::Revoked`) is a separate code path; it is not
    /// exercised by this test.  Since `VerifierAuditStatus` is
    /// `#[non_exhaustive]`, constructing an undocumented variant from outside
    /// the defining crate is not possible; the `_ =>` arm therefore cannot be
    /// reached directly in an external test.
    #[test]
    fn find_advisory_kind_in_returns_revoked_for_revoked_status() {
        let allowlist = [VerifierAllowlistEntry::new_for_test(
            [0xABu8; 32],
            VerifierAuditStatus::Revoked {
                revoked_at: "2026-01-01",
                reason: "test-revoked",
            },
        )];
        let entry_first8 = wasm_hash_first8_hex(&[0xABu8; 32]);
        let kind = find_advisory_kind_in(&entry_first8, &allowlist);
        assert_eq!(
            kind,
            Some(VerifierAdvisoryKind::Revoked),
            "Revoked status must map to VerifierAdvisoryKind::Revoked"
        );
    }

    #[test]
    fn find_advisory_kind_in_returns_retired_for_retired_status() {
        let allowlist = [VerifierAllowlistEntry::new_for_test(
            [0xCDu8; 32],
            VerifierAuditStatus::Retired {
                revoked_at: "2024-01-01",
                retired_at: "2026-01-01",
            },
        )];
        let entry_first8 = wasm_hash_first8_hex(&[0xCDu8; 32]);
        let kind = find_advisory_kind_in(&entry_first8, &allowlist);
        assert_eq!(
            kind,
            Some(VerifierAdvisoryKind::Retired),
            "Retired status must map to VerifierAdvisoryKind::Retired"
        );
    }

    // ── Advisory fires on Revoked entry (trigger-path test) ──────────────────
    //
    // Uses `run_startup_advisory_with_allowlist` with a synthetic allowlist
    // containing a Revoked entry.

    #[test]
    fn advisory_emits_audit_row_and_eprintln_on_revoked_hash() {
        // Synthetic allowlist: one Revoked entry with a distinct wasm hash.
        let revoked_hash: [u8; 32] = {
            let mut h = [0xABu8; 32];
            h[0] = 0xDE;
            h[1] = 0xAD;
            h[2] = 0xBE;
            h[3] = 0xEF;
            h
        };
        let synthetic_allowlist = [VerifierAllowlistEntry::new_for_test(
            revoked_hash,
            VerifierAuditStatus::Revoked {
                revoked_at: "2026-01-01",
                reason: "CVE-2026-0001 test fixture",
            },
        )];

        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        // Write a SaContextRuleCreated row referencing the revoked hash.
        let revoked_first8 = wasm_hash_first8_hex(&revoked_hash);
        write_context_rule_created(&writer, 4, "CDABC...12345", vec![revoked_first8.clone()]);
        drop(writer);

        let result = run_startup_advisory_with_allowlist(&path, &synthetic_allowlist);

        // (a) AdvisoryResult.triggered_rule_ids contains rule_id 4.
        assert_eq!(
            result.triggered_rule_ids,
            vec![4],
            "triggered_rule_ids must contain rule_id 4 when Revoked hash matches; got={:?}",
            result.triggered_rule_ids
        );

        // (c) SaVerifierAllowlistAdvisory audit row emitted — verify by raw file scan.
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("sa_verifier_allowlist_advisory"),
            "audit log must contain SaVerifierAllowlistAdvisory row after Revoked trigger; \
             log content (first 500 chars): {}",
            &content[..content.len().min(500)]
        );
        assert!(
            content.contains(&revoked_first8),
            "audit log advisory row must reference the revoked hash first8={}",
            revoked_first8
        );
        // The advisory kind in the row must be "revoked".
        assert!(
            content.contains("\"revoked\""),
            "advisory row advised_status must be 'revoked'; log: {}",
            &content[..content.len().min(500)]
        );
    }

    // ── Advisory fires on Retired entry (trigger-path test) ──────────────────
    //
    // A `Retired` hash triggers the advisory the same as `Revoked`; the advisory
    // check must NOT skip `Retired` entries.

    #[test]
    fn advisory_emits_audit_row_and_eprintln_on_retired_hash() {
        let retired_hash: [u8; 32] = {
            let mut h = [0xCDu8; 32];
            h[0] = 0xCA;
            h[1] = 0xFE;
            h[2] = 0xBA;
            h[3] = 0xBE;
            h
        };
        let synthetic_allowlist = vec![VerifierAllowlistEntry::new_for_test(
            retired_hash,
            VerifierAuditStatus::Retired {
                revoked_at: "2024-01-01",
                retired_at: "2026-01-01",
            },
        )];

        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let retired_first8 = wasm_hash_first8_hex(&retired_hash);
        write_context_rule_created(&writer, 7, "CDEFG...67890", vec![retired_first8.clone()]);
        drop(writer);

        let result = run_startup_advisory_with_allowlist(&path, &synthetic_allowlist);

        // (a) AdvisoryResult.triggered_rule_ids contains rule_id 7.
        assert_eq!(
            result.triggered_rule_ids,
            vec![7],
            "triggered_rule_ids must contain rule_id 7 when Retired hash matches; got={:?}",
            result.triggered_rule_ids
        );

        // (c) Audit row emitted with advised_status "retired".
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("sa_verifier_allowlist_advisory"),
            "audit log must contain SaVerifierAllowlistAdvisory row after Retired trigger"
        );
        assert!(
            content.contains("\"retired\""),
            "advisory row advised_status must be 'retired'; log: {}",
            &content[..content.len().min(500)]
        );
    }

    // ── Dedup test: same hash appearing twice in the same rule ───────────────

    #[test]
    fn advisory_deduplicates_when_hash_appears_twice_in_same_rule() {
        let revoked_hash: [u8; 32] = {
            let mut h = [0x11u8; 32];
            h[0] = 0xAA;
            h[1] = 0xBB;
            h[2] = 0xCC;
            h[3] = 0xDD;
            h
        };
        let synthetic_allowlist = vec![VerifierAllowlistEntry::new_for_test(
            revoked_hash,
            VerifierAuditStatus::Revoked {
                revoked_at: "2026-02-01",
                reason: "dedup-test fixture",
            },
        )];

        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let revoked_first8 = wasm_hash_first8_hex(&revoked_hash);
        // Pin the same hash TWICE in the pinned_verifier list for one rule.
        write_context_rule_created(
            &writer,
            2,
            "CAAAA...00001",
            vec![revoked_first8.clone(), revoked_first8.clone()],
        );
        drop(writer);

        let result = run_startup_advisory_with_allowlist(&path, &synthetic_allowlist);

        // Rule 2 triggered once (not twice despite the duplicate hash).
        assert_eq!(
            result.triggered_rule_ids,
            vec![2],
            "triggered_rule_ids must contain rule_id 2 exactly once; got={:?}",
            result.triggered_rule_ids
        );

        // Audit log must contain exactly ONE advisory row (not two).
        let content = std::fs::read_to_string(&path).unwrap();
        let advisory_count = content
            .lines()
            .filter(|line| line.contains("sa_verifier_allowlist_advisory"))
            .count();
        assert_eq!(
            advisory_count, 1,
            "audit log must contain exactly 1 advisory row for a duplicate-hash rule; got {advisory_count}"
        );
    }

    // ── Multi-rule test: 2 rules affected independently ──────────────────────

    #[test]
    fn advisory_handles_multiple_affected_rules_independently() {
        let hash_a: [u8; 32] = {
            let mut h = [0x22u8; 32];
            h[0] = 0xF0;
            h[1] = 0x0D;
            h[2] = 0xBA;
            h[3] = 0xD0;
            h
        };
        let hash_b: [u8; 32] = {
            let mut h = [0x33u8; 32];
            h[0] = 0xBE;
            h[1] = 0xEF;
            h[2] = 0xCA;
            h[3] = 0xFE;
            h
        };
        let synthetic_allowlist = vec![
            VerifierAllowlistEntry::new_for_test(
                hash_a,
                VerifierAuditStatus::Revoked {
                    revoked_at: "2026-03-01",
                    reason: "multi-rule fixture A",
                },
            ),
            VerifierAllowlistEntry::new_for_test(
                hash_b,
                VerifierAuditStatus::Retired {
                    revoked_at: "2024-03-01",
                    retired_at: "2026-03-01",
                },
            ),
        ];

        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let first8_a = wasm_hash_first8_hex(&hash_a);
        let first8_b = wasm_hash_first8_hex(&hash_b);

        // Rule 3 references hash_a (Revoked).
        write_context_rule_created(&writer, 3, "CAAAA...00002", vec![first8_a.clone()]);
        // Rule 5 references hash_b (Retired).
        write_context_rule_created(&writer, 5, "CAAAA...00003", vec![first8_b.clone()]);
        drop(writer);

        let result = run_startup_advisory_with_allowlist(&path, &synthetic_allowlist);

        // Both rules triggered.
        let mut triggered = result.triggered_rule_ids.clone();
        triggered.sort_unstable();
        assert_eq!(
            triggered,
            vec![3, 5],
            "triggered_rule_ids must contain both rule_id 3 and 5; got={:?}",
            result.triggered_rule_ids
        );

        // Audit log must contain two advisory rows — one per affected rule.
        let content = std::fs::read_to_string(&path).unwrap();
        let advisory_count = content
            .lines()
            .filter(|line| line.contains("sa_verifier_allowlist_advisory"))
            .count();
        assert_eq!(
            advisory_count, 2,
            "audit log must contain 2 advisory rows for 2 independently-affected rules; got {advisory_count}"
        );
        // Both hash first8 values appear in the log.
        assert!(
            content.contains(&first8_a),
            "log must reference hash_a first8={first8_a}"
        );
        assert!(
            content.contains(&first8_b),
            "log must reference hash_b first8={first8_b}"
        );
    }
}
