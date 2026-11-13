//! Startup advisory check for revoked/retired verifier wasm hashes.
//!
//! On every CLI invocation, after profile load and before subcommand dispatch,
//! scan the local audit log for rules referencing verifier wasm hashes flagged
//! as `Revoked` or `Retired` in [`VERIFIER_ALLOWLIST`]. Emit one stderr
//! advisory line per affected rule. A pin is matched against an allowlist
//! entry in all 32 bytes, so a hash sharing only a prefix with a revoked or
//! retired entry is never assigned that entry's status. A rule whose pin
//! record holds eight-byte hash prefixes gets an advisory naming
//! `sa.wasm_pin_incomplete` and its recovery instead: a prefix cannot name
//! an allowlist entry.
//!
//! # No-network invariant
//!
//! [`run_startup_advisory`] accepts NO `StellarRpcClient` parameter. The only
//! I/O is local: the scan reads the audit log, and the injected opener accesses
//! the keyring, checks the profile binding, and handles the tip anchor and
//! outbox for a keyed append. The writer appends local audit rows. The AST test
//! in `tests/cli/advisory_no_network_deps.rs` enforces this invariant by walking
//! the transitive call closure of `run_startup_advisory` and asserting that no
//! networking, subprocess, or DNS import is reachable.
//!
//! # Advisory posture
//!
//! The advisory is informational and non-fatal. An absent or empty log
//! returns an empty [`AdvisoryResult`] silently. A scan failure logs a warning
//! and returns an empty result. CLI startup continues normally.
//!
//! The scan reads without a writer or its verified-tip bound. A finding
//! opens the caller-supplied writer once and appends an advisory row. The
//! caller supplies the profile's audit key when available. A failed open or
//! append leaves the stderr advisory intact. A scan without findings opens
//! no writer and logs nothing.
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

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use tracing::warn;
use uuid::Uuid;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::reader::{
    ContextRulePinRecord, scan_all_context_rule_pin_records_unanchored,
};
use stellar_agent_core::audit_log::schema::{VerifierAdvisoryKind, WasmHashPin};
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
    /// Rule IDs whose pin record holds eight-byte hash prefixes, which
    /// signing refuses with `sa.wasm_pin_incomplete`. No allowlist status is
    /// looked up for them.
    pub incomplete_pin_rule_ids: Vec<u32>,
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
/// A scan failure logs a warning and returns an empty [`AdvisoryResult`].
/// A writer acquisition or append failure logs a warning and preserves the
/// findings. An absent or empty log returns silently. CLI startup continues.
///
/// # No-network invariant
///
/// This function MUST NOT import or invoke `StellarRpcClient`,
/// `stellar_agent_network::rpc::*`, `use reqwest`, or `tokio::net::*`.
/// The scan reads the local audit-log file at `audit_log_path`. A finding
/// calls `open_writer` at most once to append rows through a local writer.
/// The AST import-scan in `tests/cli/advisory_no_network_deps.rs` enforces this
/// invariant by walking the transitive call closure and checking for forbidden
/// networking, subprocess, or DNS imports.
#[must_use]
pub fn run_startup_advisory(
    audit_log_path: &Path,
    open_writer: impl FnOnce() -> Result<Arc<Mutex<AuditWriter>>, String>,
) -> AdvisoryResult {
    advisory_impl(audit_log_path, VERIFIER_ALLOWLIST, open_writer)
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
/// [`AdvisoryResult`] immediately without calling `open_writer`.
///
/// # Algorithm
///
/// 1. If the audit-log file is absent or empty, return early.
/// 2. Scan every rule's newest pin record without a writer through
///    `scan_all_context_rule_pin_records_unanchored`.
/// 3. Keep `open_writer` for the first finding that needs an audit row.
/// 4. For a record of eight-byte hash prefixes, emit one `[advisory]` stderr
///    line naming `sa.wasm_pin_incomplete` and the recovery, record the rule
///    in [`AdvisoryResult::incomplete_pin_rule_ids`], and look up no status.
/// 5. For a complete record, deduplicate the full verifier hashes, and for
///    any hash equal in all 32 bytes to a `Revoked` or `Retired` allowlist
///    entry, emit one `[advisory]` stderr line. Call `open_writer` once on
///    the first finding and reuse its writer for each advisory audit row.
///    A failed open logs one warning and leaves the stderr lines intact.
/// 6. Record `rule_id` in [`AdvisoryResult::triggered_rule_ids`] once per rule.
#[cfg(any(test, feature = "test-helpers"))]
#[cfg_attr(not(test), allow(dead_code))]
#[must_use]
pub fn run_startup_advisory_with_allowlist(
    audit_log_path: &Path,
    allowlist: &[VerifierAllowlistEntry],
    open_writer: impl FnOnce() -> Result<Arc<Mutex<AuditWriter>>, String>,
) -> AdvisoryResult {
    advisory_impl(audit_log_path, allowlist, open_writer)
}

/// Shared implementation called by both entry points above.
#[allow(
    clippy::print_stderr,
    reason = "advisory output is operator-facing stderr"
)]
fn advisory_impl(
    audit_log_path: &Path,
    allowlist: &[VerifierAllowlistEntry],
    open_writer: impl FnOnce() -> Result<Arc<Mutex<AuditWriter>>, String>,
) -> AdvisoryResult {
    // ── 0. Short-circuit if audit-log is absent or empty ────────────────────
    // No pin records exist to scan in an absent or empty log.
    match std::fs::metadata(audit_log_path) {
        // A concurrent append after this metadata read is seen on the next
        // invocation. The advisory is informational and runs before dispatch.
        Ok(meta) if meta.len() == 0 => return AdvisoryResult::default(),
        Err(_) => return AdvisoryResult::default(),
        Ok(_) => {}
    }

    // ── 1. Read pin records without a writer or keyring access ─────────────
    let all_rules = match scan_all_context_rule_pin_records_unanchored(audit_log_path) {
        Ok(rows) => rows,
        Err(e) => {
            warn!(
                error = %e,
                "startup advisory: audit-log scan failed; advisory skipped"
            );
            return AdvisoryResult::default();
        }
    };

    if all_rules.is_empty() {
        return AdvisoryResult::default();
    }

    // ── 2. Check each rule's pinned hashes against the allowlist ──────────────
    let mut triggered_rule_ids: Vec<u32> = Vec::new();
    let mut incomplete_pin_rule_ids: Vec<u32> = Vec::new();
    let request_id = Uuid::new_v4().to_string();
    let mut open_writer = Some(open_writer);
    let mut writer = None;

    for (rule_id, smart_account_redacted, record) in &all_rules {
        let pinned = match record {
            ContextRulePinRecord::Complete(pinned) => pinned,
            ContextRulePinRecord::Incomplete(_) => {
                // A prefix cannot name an allowlist entry: report the
                // incomplete record and its recovery, and look up no status.
                eprintln!(
                    "[advisory] rule {rule_id} has a pin record of eight-byte hash prefixes \
                     (sa.wasm_pin_incomplete); signing under it is refused until the rule is \
                     reinstalled through an independently authorized rule such as rule 0"
                );
                if !incomplete_pin_rule_ids.contains(rule_id) {
                    incomplete_pin_rule_ids.push(*rule_id);
                }
                continue;
            }
            _ => continue,
        };
        // Deduplicate hashes per rule, in a stable order, before iterating:
        // avoids duplicate stderr lines and audit rows when the same hash
        // appears more than once in the pinned set.
        let sorted_hashes: BTreeSet<&WasmHashPin> = pinned.pinned_verifier_hashes.iter().collect();

        for hash in sorted_hashes {
            let Some(advisory_kind) = find_advisory_kind_in(hash, allowlist) else {
                continue;
            };

            // 2a. Emit operator-facing stderr advisory with variant-aware wording
            //     ("revoked verifier" would be misleading for a Retired entry).
            eprintln!(
                "[advisory] rule {} references {} verifier {}; \
                 run 'stellar-agent smart-account migrate-verifier' to remediate",
                rule_id, advisory_kind, hash,
            );

            // 2b. Emit SaVerifierAllowlistAdvisory audit row; its hash field
            //     is the labeled first-8 display projection of the full hash.
            //     Without a writer the stderr line is the whole advisory.
            if let Some(open_writer) = open_writer.take() {
                writer = match open_writer() {
                    Ok(writer) => Some(writer),
                    Err(error) => {
                        warn!(
                            error = %error,
                            "startup advisory: audit writer open failed; \
                             stderr advisory stands and the command proceeds; advisory rows skipped"
                        );
                        None
                    }
                };
            }
            let hash_first8 = hash.first8_display();
            if let Some(writer) = &writer {
                write_advisory_row(
                    writer,
                    *rule_id,
                    smart_account_redacted,
                    &hash_first8,
                    advisory_kind,
                    &request_id,
                );
            }

            // 2c. Record triggered rule_id (once per rule, not once per hash).
            if !triggered_rule_ids.contains(rule_id) {
                triggered_rule_ids.push(*rule_id);
            }
        }
    }

    AdvisoryResult {
        triggered_rule_ids,
        incomplete_pin_rule_ids,
    }
}

/// Writes one `SaVerifierAllowlistAdvisory` row through `writer`, logging a
/// failed append or a poisoned writer mutex at `warn!`: the row is
/// best-effort.
fn write_advisory_row(
    writer: &Arc<Mutex<AuditWriter>>,
    rule_id: u32,
    smart_account_redacted: &str,
    hash_first8: &str,
    advisory_kind: VerifierAdvisoryKind,
    request_id: &str,
) {
    let entry = AuditEntry::new_sa_verifier_allowlist_advisory(
        rule_id,
        RedactedStrkey::from_already_redacted(smart_account_redacted),
        hash_first8,
        advisory_kind,
        Option::<String>::None,
        request_id,
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
            // A prior write path panicked mid-write. Log at warn and
            // continue; the advisory row is best-effort.
            warn!(
                rule_id = rule_id,
                hash_first8 = %hash_first8,
                error = %format!("audit writer mutex poisoned: {poison}"),
                "startup advisory: could not acquire audit writer lock; audit row skipped"
            );
        }
    }
}

// ── Internal helpers ───────────────────────────────────────────────────────────

/// Looks up the full pinned `hash` in the provided `allowlist` slice.
///
/// An entry matches only when its hash equals the pin in all 32 bytes, so a
/// hash that shares a prefix with an entry is never assigned that entry's
/// status.
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
    hash: &WasmHashPin,
    allowlist: &[VerifierAllowlistEntry],
) -> Option<VerifierAdvisoryKind> {
    for entry in allowlist {
        if hash.matches(&entry.wasm_hash) {
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
    use stellar_agent_core::audit_log::tip_anchor::{
        InMemoryTipAnchorStore, KeyedAuditAccess, TipAnchorStore,
    };
    use stellar_agent_core::audit_log::verify::verify_log;
    use stellar_agent_core::audit_log::writer::AuditWriter;
    use stellar_agent_test_support::log_capture::{CaptureWriter, inert_dispatcher};
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

    /// Writes a `SaContextRuleCreatedV2` row with the given pinned verifier
    /// hashes.
    fn write_context_rule_created(
        writer: &Arc<Mutex<AuditWriter>>,
        rule_id: u32,
        smart_account: &str,
        pinned_hashes: Vec<WasmHashPin>,
    ) {
        let mut entry = AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "smart-account.rules.create",
            Option::<String>::None,
            vec![],
            PolicyDecision::Allow,
            Uuid::new_v4().to_string(),
        ));
        entry.event_kind = EventKind::SaContextRuleCreatedV2 {
            smart_account: smart_account.to_owned(),
            rule_id,
            context_type: "default".to_owned(),
            signers_count: 1,
            policies_count: 0,
            valid_until: None,
            pinned_verifier_wasm_hashes: pinned_hashes,
            pinned_policy_wasm_hashes: vec![],
            mutable_override: false,
            unknown_override: false,
            pinned_verifier_executable_refs: vec![],
            pinned_policy_executable_refs: vec![],
        };
        writer.lock().unwrap().write_entry(entry).unwrap();
    }

    /// Writes a version-1 `SaContextRuleCreated` row of eight-byte prefixes.
    fn write_prefix_context_rule_created(
        writer: &Arc<Mutex<AuditWriter>>,
        rule_id: u32,
        smart_account: &str,
        pinned_first8: Vec<String>,
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
            pinned_verifier_wasm_hashes_first8: pinned_first8,
            pinned_policy_wasm_hashes_first8: vec![],
            mutable_override: false,
            unknown_override: false,
            pinned_verifier_executable_refs: vec![],
            pinned_policy_executable_refs: vec![],
        };
        writer.lock().unwrap().write_entry(entry).unwrap();
    }

    /// A full hash whose bytes all equal `byte`.
    fn h(byte: u8) -> WasmHashPin {
        WasmHashPin::new([byte; 32])
    }

    #[test]
    #[serial_test::serial]
    fn startup_scans_the_loaded_profiles_configured_audit_log() {
        use stellar_agent_core::profile::{loader, schema::Profile};
        use stellar_agent_test_support::StellarAgentHomeGuard;

        let dir = TempDir::new().unwrap();
        let _home = StellarAgentHomeGuard::new(dir.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let path = dir.path().join("custom-audit.jsonl");
        let profile =
            Profile::builder_testnet_named("configured", "signer", "test", "nonce", "test")
                .audit_log_path(&path)
                .build();
        loader::save("configured", &profile).unwrap();
        let default_path =
            stellar_agent_core::profile::schema::default_audit_log_path_for("configured");
        std::fs::create_dir_all(default_path.parent().unwrap()).unwrap();
        let default_writer = open_writer(default_path.clone());
        write_context_rule_created(&default_writer, 99, "CDABC...12345", vec![h(0xab)]);
        drop(default_writer);
        let default_bytes = std::fs::read(&default_path).unwrap();

        let writer = open_writer(path.clone());
        write_context_rule_created(&writer, 4, "CDABC...12345", vec![h(0xab)]);
        drop(writer);
        let allowlist = [VerifierAllowlistEntry::new_for_test(
            [0xAB; 32],
            VerifierAuditStatus::Revoked {
                revoked_at: "2026-01-01",
                reason: "test fixture",
            },
        )];
        let result = crate::run_profile_startup_advisory(
            Some("configured"),
            |selected_path, open_writer| {
                run_startup_advisory_with_allowlist(selected_path, &allowlist, open_writer)
            },
        );

        assert_eq!(result.triggered_rule_ids, vec![4]);
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("sa_verifier_allowlist_advisory")
        );
        assert_eq!(std::fs::read(&default_path).unwrap(), default_bytes);
    }

    /// `profile init` and `profile enable-mainnet` skip the startup scan. No
    /// startup advisory precedes the spending preview, and no advisory row
    /// precedes their first write. Every other command still scans.
    #[test]
    #[serial_test::serial]
    fn startup_advisory_skips_preview_commands() {
        use clap::Parser as _;
        use stellar_agent_core::profile::{loader, schema::Profile};
        use stellar_agent_test_support::StellarAgentHomeGuard;

        let dir = TempDir::new().unwrap();
        let _home = StellarAgentHomeGuard::new(dir.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let path = dir.path().join("operator-audit.jsonl");
        let profile = Profile::builder_testnet_named("operator", "signer", "test", "nonce", "test")
            .audit_log_path(&path)
            .build();
        loader::save("operator", &profile).unwrap();
        let writer = open_writer(path.clone());
        write_context_rule_created(&writer, 4, "CDABC...12345", vec![h(0xee)]);
        drop(writer);
        let before = std::fs::read(&path).unwrap();

        let run = |args: &[&str]| {
            let cli = crate::Cli::try_parse_from(
                std::iter::once("stellar-agent").chain(args.iter().copied()),
            )
            .unwrap_or_else(|error| panic!("{args:?} parses: {error}"));
            crate::startup_advisory_for(&cli.command, |path, open_writer| {
                run_startup_advisory(path, open_writer)
            })
        };
        for args in [
            &[
                "profile",
                "enable-mainnet",
                "--profile",
                "operator",
                "--check",
            ][..],
            &["profile", "enable-mainnet", "--profile", "operator"][..],
            &["profile", "init", "--profile", "operator"][..],
            &[
                "profile",
                "policy",
                "add-counterparty",
                "--profile",
                "operator",
                "--recipient",
                "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
            ][..],
        ] {
            let result = run(args);
            assert!(result.triggered_rule_ids.is_empty(), "{args:?}");
            assert_eq!(std::fs::read(&path).unwrap(), before, "{args:?}");
        }

        let result = run(&["profile", "show", "operator"]);
        assert_eq!(result.triggered_rule_ids, vec![4]);
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("sa_verifier_allowlist_advisory")
        );
    }

    /// A finding acquires the profile's keyed writer and records its binding.
    /// A changed binding refuses the row while the scan still reports findings.
    #[test]
    #[serial_test::serial]
    fn the_advisory_records_and_checks_the_profile_binding() {
        use stellar_agent_core::profile::{loader, schema::Profile};
        use stellar_agent_network::keyring::KeyringAuditBindingStore;
        use stellar_agent_test_support::StellarAgentHomeGuard;

        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let _home = StellarAgentHomeGuard::new(dir.path());
        let name = "advisory-binding";
        let path = dir.path().join("advisory-audit.jsonl");
        let profile = Profile::builder_testnet_named(name, "signer", "test", "nonce", "test")
            .audit_log_path(&path)
            .build();
        loader::save(name, &profile).unwrap();
        let allowlist = [VerifierAllowlistEntry::new_for_test(
            [0xAB; 32],
            VerifierAuditStatus::Revoked {
                revoked_at: "2026-01-01",
                reason: "test fixture",
            },
        )];
        let binding = || {
            KeyringAuditBindingStore::for_profile(name)
                .load_raw()
                .unwrap()
        };
        let run = || {
            crate::run_profile_startup_advisory(Some(name), |selected_path, open_writer| {
                run_startup_advisory_with_allowlist(selected_path, &allowlist, open_writer)
            })
        };

        let writer = open_writer(path.clone());
        write_context_rule_created(&writer, 4, "CDABC...12345", vec![h(0xab)]);
        drop(writer);
        let coord = &profile.audit_log_hash_chain_key_id;
        stellar_agent_network::keyring::rotate_keyring_secret_32(&coord.service, &coord.account)
            .unwrap();
        assert!(binding().is_none());
        assert_eq!(run().triggered_rule_ids, vec![4]);
        assert!(
            binding().is_some(),
            "the keyed advisory records its binding"
        );
        let key = stellar_agent_network::keyring::load_hmac_key_32(coord).unwrap();
        let verified = verify_log(&path, Some(&key)).unwrap();
        assert!(verified.hmac_verified);
        assert!(verified.entry_tags_verified);
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.matches("sa_verifier_allowlist_advisory").count(), 1);
        let writer =
            crate::commands::value_audit::require_value_audit_writer(&profile, name).unwrap();
        write_context_rule_created(&writer, 5, "CDABC...12345", vec![h(0xab)]);
        drop(writer);

        let mut elsewhere = profile.clone();
        elsewhere.audit_log_path = dir.path().join("elsewhere.jsonl");
        KeyringAuditBindingStore::for_profile(name)
            .store(&stellar_agent_core::audit_log::AuditBinding::for_profile(
                &elsewhere,
            ))
            .unwrap();
        let recorded = binding();
        let before = std::fs::read(&path).unwrap();
        assert!(
            run().triggered_rule_ids.contains(&5),
            "the advisory still runs"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "a binding refusal writes no row"
        );
        assert!(
            binding() == recorded,
            "the advisory preserves the refused binding"
        );
    }

    /// Persists a profile and one revoked pin, with an optional seeded audit key.
    fn startup_profile_with_finding(
        dir: &TempDir,
        name: &str,
        keyed: bool,
    ) -> stellar_agent_core::profile::schema::Profile {
        use stellar_agent_core::audit_log::BindingCheck;
        use stellar_agent_core::profile::{loader, schema::Profile};
        use stellar_agent_network::keyring::{keyed_audit_access, rotate_keyring_secret_32};

        let path = dir.path().join("audit.jsonl");
        let profile = Profile::builder_testnet_named(name, "signer", "test", "nonce", "test")
            .audit_log_path(&path)
            .build();
        loader::save(name, &profile).unwrap();
        let access = keyed.then(|| {
            let coord = &profile.audit_log_hash_chain_key_id;
            rotate_keyring_secret_32(&coord.service, &coord.account).unwrap();
            keyed_audit_access(&profile, name, BindingCheck::Enforce).unwrap()
        });
        let writer = Arc::new(Mutex::new(AuditWriter::open(path, access).unwrap()));
        write_context_rule_created(&writer, 4, "CDABC...12345", vec![h(0xab)]);
        profile
    }

    fn run_profile_with_revoked_pin(name: &str) -> AdvisoryResult {
        let allowlist = [VerifierAllowlistEntry::new_for_test(
            [0xab; 32],
            VerifierAuditStatus::Revoked {
                revoked_at: "2026-01-01",
                reason: "test fixture",
            },
        )];
        crate::run_profile_startup_advisory(Some(name), |path, open_writer| {
            run_startup_advisory_with_allowlist(path, &allowlist, open_writer)
        })
    }

    #[test]
    #[serial_test::serial]
    fn startup_advisory_releases_keyed_writer_for_rotation() {
        use stellar_agent_core::audit_log::BindingCheck;
        use stellar_agent_network::keyring::keyed_audit_access;

        let dir = TempDir::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let name = "advisory-release-keyed";
        let profile = startup_profile_with_finding(&dir, name, true);
        assert_eq!(
            run_profile_with_revoked_pin(name).triggered_rule_ids,
            vec![4]
        );
        let content = std::fs::read_to_string(&profile.audit_log_path).unwrap();
        assert_eq!(content.matches("sa_verifier_allowlist_advisory").count(), 1);
        let access = keyed_audit_access(&profile, name, BindingCheck::Enforce).unwrap();
        let binding = access.binding_history();
        let (key, store) = access.into_parts();
        let _rotation = AuditWriter::open_for_key_rotation(
            profile.audit_log_path.clone(),
            Some(key),
            store,
            binding,
        )
        .expect("the advisory releases the sidecar lock before rotation");
    }

    #[test]
    #[serial_test::serial]
    fn startup_advisory_releases_unkeyed_writer_for_first_key() {
        use stellar_agent_core::audit_log::BindingCheck;
        use stellar_agent_network::keyring::{
            keyed_audit_access, load_hmac_key_32, rotate_keyring_secret_32,
        };

        let dir = TempDir::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let name = "advisory-release-unkeyed";
        let profile = startup_profile_with_finding(&dir, name, false);
        let coord = &profile.audit_log_hash_chain_key_id;
        assert!(load_hmac_key_32(coord).is_err());
        assert_eq!(
            run_profile_with_revoked_pin(name).triggered_rule_ids,
            vec![4]
        );
        let content = std::fs::read_to_string(&profile.audit_log_path).unwrap();
        assert_eq!(content.matches("sa_verifier_allowlist_advisory").count(), 1);
        rotate_keyring_secret_32(&coord.service, &coord.account).unwrap();
        let access = keyed_audit_access(&profile, name, BindingCheck::Enforce).unwrap();
        let writer = AuditWriter::open(profile.audit_log_path.clone(), Some(access))
            .expect("the first keyed open succeeds after the unkeyed advisory");
        drop(writer);
        let key = load_hmac_key_32(coord).unwrap();
        let verified = verify_log(&profile.audit_log_path, Some(&key)).unwrap();
        assert!(verified.hmac_verified);
        assert!(verified.entry_tags_verified);
    }

    #[test]
    #[serial_test::serial]
    fn startup_advisory_production_open_failure_warns_once_and_keeps_findings() {
        use stellar_agent_core::profile::{loader, schema::Profile};
        use stellar_agent_network::keyring::load_hmac_key_32;

        let dir = TempDir::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let name = "advisory-missing-key";
        let path = tmp_log(&dir);
        let profile = Profile::builder_testnet_named(name, "signer", "test", "nonce", "test")
            .audit_log_path(&path)
            .build();
        loader::save(name, &profile).unwrap();
        let access = KeyedAuditAccess::new(
            zeroize::Zeroizing::new([0x4e; 32]),
            Arc::new(InMemoryTipAnchorStore::new()),
        );
        let writer = Arc::new(Mutex::new(
            AuditWriter::open(path.clone(), Some(access)).unwrap(),
        ));
        write_context_rule_created(&writer, 4, "CDABC...12345", vec![h(0xab)]);
        drop(writer);
        assert!(load_hmac_key_32(&profile.audit_log_hash_chain_key_id).is_err());
        let before = std::fs::read(&path).unwrap();
        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let _inert = inert_dispatcher();
        let result = tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            run_profile_with_revoked_pin(name)
        });
        assert_eq!(result.triggered_rule_ids, vec![4]);
        let logs = capture.captured_str();
        assert_eq!(
            logs.lines().filter(|line| line.contains("WARN")).count(),
            1,
            "{logs}"
        );
        assert!(logs.contains("audit.chain_key_unavailable"), "{logs}");
        assert!(
            logs.contains("stderr advisory stands and the command proceeds"),
            "{logs}"
        );
        assert!(!logs.contains("refuses to proceed unaudited"), "{logs}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    /// A keyed finding appends one advisory row authenticated by the same key.
    #[test]
    fn the_advisory_on_a_keyed_log_prints_and_writes_a_keyed_row() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let key = [0x4e; 32];
        let anchor: Arc<dyn TipAnchorStore> = Arc::new(InMemoryTipAnchorStore::new());
        let access = || KeyedAuditAccess::new(zeroize::Zeroizing::new(key), Arc::clone(&anchor));
        let writer = Arc::new(Mutex::new(
            AuditWriter::open(path.clone(), Some(access())).unwrap(),
        ));
        write_context_rule_created(&writer, 4, "CDABC...12345", vec![h(0xab)]);
        drop(writer);
        let before = verify_log(&path, Some(&key)).unwrap();
        let allowlist = [VerifierAllowlistEntry::new_for_test(
            [0xAB; 32],
            VerifierAuditStatus::Revoked {
                revoked_at: "2026-01-01",
                reason: "test fixture",
            },
        )];
        let mut opens = 0;
        let result = run_startup_advisory_with_allowlist(&path, &allowlist, || {
            opens += 1;
            AuditWriter::open(path.clone(), Some(access()))
                .map(|writer| Arc::new(Mutex::new(writer)))
                .map_err(|error| error.to_string())
        });

        assert_eq!(opens, 1);
        assert_eq!(result.triggered_rule_ids, vec![4]);
        let content = std::fs::read_to_string(&path).unwrap();
        let rows: Vec<AuditEntry> = content
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .filter(|entry: &AuditEntry| {
                matches!(
                    entry.event_kind,
                    EventKind::SaVerifierAllowlistAdvisory { .. }
                )
            })
            .collect();
        assert_eq!(rows.len(), 1);
        assert!(matches!(
            rows[0].event_kind,
            EventKind::SaVerifierAllowlistAdvisory {
                rule_id: 4,
                advised_status: VerifierAdvisoryKind::Revoked,
                ..
            }
        ));
        let verified = verify_log(&path, Some(&key)).unwrap();
        assert_eq!(verified.entries_verified, before.entries_verified + 1);
        assert!(verified.hmac_verified);
        assert!(verified.entry_tags_verified);
    }

    #[test]
    #[serial_test::serial]
    fn advisory_on_a_keyed_log_without_findings_never_opens_or_warns() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let access = KeyedAuditAccess::new(
            zeroize::Zeroizing::new([0x4e; 32]),
            Arc::new(InMemoryTipAnchorStore::new()) as Arc<dyn TipAnchorStore>,
        );
        let writer = Arc::new(Mutex::new(
            AuditWriter::open(path.clone(), Some(access)).unwrap(),
        ));
        write_context_rule_created(&writer, 4, "CDABC...12345", vec![h(0xab)]);
        let before = std::fs::read(&path).unwrap();
        let allowlist = [VerifierAllowlistEntry::new_for_test(
            [0xab; 32],
            VerifierAuditStatus::Unaudited,
        )];
        let capture = CaptureWriter::new();
        let _inert = inert_dispatcher();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let mut opens = 0;
        let result = tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            run_startup_advisory_with_allowlist(&path, &allowlist, || {
                opens += 1;
                Err("no finding needs a writer".to_owned())
            })
        });
        assert_eq!(result, AdvisoryResult::default());
        assert_eq!(opens, 0);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let logs = capture.captured_str();
        assert!(!logs.contains("WARN"), "{logs}");
        assert!(logs.is_empty(), "{logs}");
    }

    /// Two findings on one rule keep both stderr lines when the single open fails.
    /// The startup test in main captures those lines from this test's process.
    #[test]
    #[serial_test::serial]
    fn advisory_writer_open_failure_warns_once_and_keeps_findings() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        write_context_rule_created(&writer, 4, "CDABC...12345", vec![h(0xab), h(0xcd)]);
        drop(writer);
        let before = std::fs::read(&path).unwrap();
        let allowlist = [0xab, 0xcd].map(|byte| {
            VerifierAllowlistEntry::new_for_test(
                [byte; 32],
                VerifierAuditStatus::Revoked {
                    revoked_at: "2026-01-01",
                    reason: "test fixture",
                },
            )
        });
        let capture = CaptureWriter::new();
        let _inert = inert_dispatcher();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let mut opens = 0;
        let result = tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            run_startup_advisory_with_allowlist(&path, &allowlist, || {
                opens += 1;
                Err("fixture writer unavailable".to_owned())
            })
        });
        assert_eq!(opens, 1);
        assert_eq!(result.triggered_rule_ids, vec![4]);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let logs = capture.captured_str();
        assert_eq!(
            logs.lines().filter(|line| line.contains("WARN")).count(),
            1,
            "{logs}"
        );
        assert!(logs.contains("fixture writer unavailable"), "{logs}");
        assert!(
            logs.contains("startup advisory: audit writer open failed"),
            "{logs}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn startup_profile_load_failures_are_nonfatal_and_do_not_scan() {
        use stellar_agent_core::profile::{loader, schema::Profile};
        use stellar_agent_test_support::StellarAgentHomeGuard;

        let dir = TempDir::new().unwrap();
        let _home = StellarAgentHomeGuard::new(dir.path());
        let profile =
            Profile::builder_testnet_named("owner", "signer", "test", "nonce", "test").build();
        let malformed = loader::save("malformed", &profile).unwrap();
        std::fs::write(malformed, "invalid = [").unwrap();
        loader::save("mismatched", &profile).unwrap();

        for name in ["missing", "malformed", "mismatched"] {
            let result = crate::run_profile_startup_advisory(Some(name), |_, _| {
                panic!("a profile load failure must not scan an audit log")
            });
            assert_eq!(result, AdvisoryResult::default());
        }
    }

    // ── Test 1: empty result when audit log is absent ─────────────────────────

    #[test]
    fn advisory_returns_empty_when_audit_log_absent() {
        let dir = TempDir::new().unwrap();
        // Create a regular file, then try to use it as a directory (impossible parent).
        let file_as_dir = dir.path().join("regular_file");
        std::fs::write(&file_as_dir, b"content").unwrap();
        let impossible_path = file_as_dir.join("nested").join("audit.jsonl");

        let result =
            run_startup_advisory(&impossible_path, || panic!("an absent log needs no writer"));
        assert!(
            result.triggered_rule_ids.is_empty(),
            "advisory must return empty when audit log path cannot be opened"
        );
    }

    // ── Test 2: empty result when log has no pin rows ─────────────────────────

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
        drop(writer);

        let result = run_startup_advisory(&path, || panic!("no finding needs a writer"));
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
        // A 0xde hash is not in the allowlist → advisory must NOT trigger.
        // Positive trigger paths (Revoked + Retired) are tested in
        // `advisory_emits_audit_row_and_eprintln_on_revoked_hash` and
        // `advisory_emits_audit_row_and_eprintln_on_retired_hash` below
        // (via `run_startup_advisory_with_allowlist`).
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        write_context_rule_created(&writer, 4, "CDABC...12345", vec![h(0xde)]);
        drop(writer);

        let result = run_startup_advisory(&path, || panic!("no finding needs a writer"));
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
        // OZ v0.7.1 wasm_hash, Provisional in VERIFIER_ALLOWLIST.
        write_context_rule_created(
            &writer,
            1,
            "CDABC...12345",
            vec![WasmHashPin::new(VERIFIER_ALLOWLIST[1].wasm_hash)],
        );
        drop(writer);

        let result = run_startup_advisory(&path, || panic!("no finding needs a writer"));
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
        // A 0xca hash is not in VERIFIER_ALLOWLIST → advisory must NOT trigger.
        // The positive Retired branch (a Retired entry triggers the advisory) is
        // covered by `advisory_emits_audit_row_and_eprintln_on_retired_hash` below.
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        write_context_rule_created(&writer, 7, "CDABC...12345", vec![h(0xca)]);
        drop(writer);

        let result = run_startup_advisory(&path, || panic!("no finding needs a writer"));
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

        let result = run_startup_advisory(&path, || panic!("no finding needs a writer"));
        assert!(
            result.triggered_rule_ids.is_empty(),
            "empty audit log must not trigger advisory"
        );
    }

    // ── Unit tests: find_advisory_kind_in ────────────────────────────────────

    #[test]
    fn find_advisory_kind_in_returns_none_for_provisional_oz_v071() {
        // OZ v0.7.1 hash, Provisional: no advisory kind.
        let kind = find_advisory_kind_in(
            &WasmHashPin::new(VERIFIER_ALLOWLIST[1].wasm_hash),
            VERIFIER_ALLOWLIST,
        );
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
        let kind = find_advisory_kind_in(&h(0x12), &allowlist);
        assert!(
            kind.is_none(),
            "Provisional status must not produce an advisory kind"
        );
    }

    #[test]
    fn find_advisory_kind_in_returns_none_for_unknown_hash() {
        let kind = find_advisory_kind_in(&h(0x00), VERIFIER_ALLOWLIST);
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
        let kind = find_advisory_kind_in(&h(0xab), &allowlist);
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
        let kind = find_advisory_kind_in(&h(0xcd), &allowlist);
        assert_eq!(
            kind,
            Some(VerifierAdvisoryKind::Retired),
            "Retired status must map to VerifierAdvisoryKind::Retired"
        );
    }

    // ── Pin width: full matches, prefix twins and incomplete records ──────────

    /// A full pin of a revoked hash triggers the advisory for its rule, and
    /// the advisory row names the rule, the labeled first-8 projection of the
    /// pinned hash and the revoked status.
    #[test]
    fn advisory_fires_for_a_full_pin_of_a_revoked_hash() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        write_context_rule_created(&writer, 4, "CDABC...12345", vec![h(0xab)]);
        drop(writer);
        let allowlist = [VerifierAllowlistEntry::new_for_test(
            [0xAB; 32],
            VerifierAuditStatus::Revoked {
                revoked_at: "2026-01-01",
                reason: "encoding fixture",
            },
        )];

        let result = run_startup_advisory_with_allowlist(&path, &allowlist, || {
            Ok(open_writer(path.clone()))
        });

        assert_eq!(result.triggered_rule_ids, vec![4]);
        assert!(result.incomplete_pin_rule_ids.is_empty());
        let advisories: Vec<(u32, String, VerifierAdvisoryKind)> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<AuditEntry>(line).unwrap())
            .filter_map(|entry| match entry.event_kind {
                EventKind::SaVerifierAllowlistAdvisory {
                    rule_id,
                    revoked_hash_first8,
                    advised_status,
                    ..
                } => Some((rule_id, revoked_hash_first8, advised_status)),
                _ => None,
            })
            .collect();
        assert_eq!(
            advisories,
            vec![(
                4,
                "abababababababab".to_owned(),
                VerifierAdvisoryKind::Revoked
            )]
        );
    }

    /// A pinned hash that shares the first eight bytes of a revoked or
    /// retired entry and differs after them is assigned no status: the
    /// lookup compares all 32 bytes, and the exact hashes still match.
    #[test]
    fn advisory_does_not_assign_a_status_to_an_equal_prefix_twin() {
        let revoked = [0x42u8; 32];
        let retired = [0x52u8; 32];
        let twin = |hash: [u8; 32]| {
            let mut twin = hash;
            twin[8..].fill(0x43);
            WasmHashPin::new(twin)
        };
        let allowlist = [
            VerifierAllowlistEntry::new_for_test(
                revoked,
                VerifierAuditStatus::Revoked {
                    revoked_at: "2026-01-01",
                    reason: "twin fixture",
                },
            ),
            VerifierAllowlistEntry::new_for_test(
                retired,
                VerifierAuditStatus::Retired {
                    revoked_at: "2024-01-01",
                    retired_at: "2026-01-01",
                },
            ),
        ];
        assert_eq!(find_advisory_kind_in(&twin(revoked), &allowlist), None);
        assert_eq!(find_advisory_kind_in(&twin(retired), &allowlist), None);
        assert_eq!(
            find_advisory_kind_in(&WasmHashPin::new(revoked), &allowlist),
            Some(VerifierAdvisoryKind::Revoked)
        );
        assert_eq!(
            find_advisory_kind_in(&WasmHashPin::new(retired), &allowlist),
            Some(VerifierAdvisoryKind::Retired)
        );

        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        write_context_rule_created(&writer, 4, "CDABC...12345", vec![twin(revoked)]);
        write_context_rule_created(&writer, 5, "CDABC...12345", vec![twin(retired)]);
        drop(writer);
        let result = run_startup_advisory_with_allowlist(&path, &allowlist, || {
            Ok(open_writer(path.clone()))
        });
        assert!(result.triggered_rule_ids.is_empty(), "{result:?}");
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains("sa_verifier_allowlist_advisory")
        );
    }

    /// A pin record of eight-byte prefixes is reported as incomplete, and no
    /// allowlist status is looked up for its prefix, even one that equals a
    /// revoked entry's first eight bytes.
    #[test]
    fn advisory_reports_an_incomplete_pin_record_without_a_status_lookup() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        write_prefix_context_rule_created(
            &writer,
            4,
            "CDABC...12345",
            vec!["abababababababab".to_owned()],
        );
        drop(writer);
        let allowlist = [VerifierAllowlistEntry::new_for_test(
            [0xAB; 32],
            VerifierAuditStatus::Revoked {
                revoked_at: "2026-01-01",
                reason: "prefix fixture",
            },
        )];

        let result = run_startup_advisory_with_allowlist(&path, &allowlist, || {
            Ok(open_writer(path.clone()))
        });

        assert!(result.triggered_rule_ids.is_empty(), "{result:?}");
        assert_eq!(result.incomplete_pin_rule_ids, vec![4]);
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains("sa_verifier_allowlist_advisory"),
            "an incomplete record writes no advisory row"
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

        // Write a SaContextRuleCreatedV2 row referencing the revoked hash.
        let revoked_first8 = WasmHashPin::new(revoked_hash).first8_display();
        write_context_rule_created(
            &writer,
            4,
            "CDABC...12345",
            vec![WasmHashPin::new(revoked_hash)],
        );
        drop(writer);

        let result = run_startup_advisory_with_allowlist(&path, &synthetic_allowlist, || {
            Ok(open_writer(path.clone()))
        });

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

        write_context_rule_created(
            &writer,
            7,
            "CDEFG...67890",
            vec![WasmHashPin::new(retired_hash)],
        );
        drop(writer);

        let result = run_startup_advisory_with_allowlist(&path, &synthetic_allowlist, || {
            Ok(open_writer(path.clone()))
        });

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

        // Pin the same hash TWICE in the pinned_verifier list for one rule.
        write_context_rule_created(
            &writer,
            2,
            "CAAAA...00001",
            vec![
                WasmHashPin::new(revoked_hash),
                WasmHashPin::new(revoked_hash),
            ],
        );
        drop(writer);

        let result = run_startup_advisory_with_allowlist(&path, &synthetic_allowlist, || {
            Ok(open_writer(path.clone()))
        });

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

    /// Deduplication compares all 32 bytes: two revoked hashes that share
    /// their first eight bytes are two pins, each reported with its own
    /// stderr line and audit row, although both rows carry the same labeled
    /// first-8 display.
    #[test]
    fn advisory_keeps_equal_prefix_pins_distinct_when_deduplicating() {
        let pinned = [0x42u8; 32];
        let mut twin = pinned;
        twin[8..].fill(0x43);
        let revoked = |hash: [u8; 32]| {
            VerifierAllowlistEntry::new_for_test(
                hash,
                VerifierAuditStatus::Revoked {
                    revoked_at: "2026-02-01",
                    reason: "equal-prefix dedup fixture",
                },
            )
        };
        let synthetic_allowlist = vec![revoked(pinned), revoked(twin)];

        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        write_context_rule_created(
            &writer,
            4,
            "CAAAA...00004",
            vec![
                WasmHashPin::new(pinned),
                WasmHashPin::new(twin),
                WasmHashPin::new(pinned),
            ],
        );
        drop(writer);

        let result = run_startup_advisory_with_allowlist(&path, &synthetic_allowlist, || {
            Ok(open_writer(path.clone()))
        });
        assert_eq!(result.triggered_rule_ids, vec![4]);

        let content = std::fs::read_to_string(&path).unwrap();
        let advisory_rows: Vec<&str> = content
            .lines()
            .filter(|line| line.contains("sa_verifier_allowlist_advisory"))
            .collect();
        assert_eq!(
            advisory_rows.len(),
            2,
            "one advisory row per distinct full hash: {advisory_rows:?}"
        );
        let display = WasmHashPin::new(pinned).first8_display();
        assert_eq!(display, WasmHashPin::new(twin).first8_display());
        assert!(
            advisory_rows.iter().all(|row| row.contains(&display)),
            "{advisory_rows:?}"
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

        let first8_a = WasmHashPin::new(hash_a).first8_display();
        let first8_b = WasmHashPin::new(hash_b).first8_display();

        // Rule 3 references hash_a (Revoked).
        write_context_rule_created(&writer, 3, "CAAAA...00002", vec![WasmHashPin::new(hash_a)]);
        // Rule 5 references hash_b (Retired).
        write_context_rule_created(&writer, 5, "CAAAA...00003", vec![WasmHashPin::new(hash_b)]);
        drop(writer);

        let mut opens = 0;
        let result = run_startup_advisory_with_allowlist(&path, &synthetic_allowlist, || {
            opens += 1;
            Ok(open_writer(path.clone()))
        });
        assert_eq!(opens, 1);

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
