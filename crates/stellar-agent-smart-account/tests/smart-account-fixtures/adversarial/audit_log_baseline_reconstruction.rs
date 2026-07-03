//! Adversarial fixture: audit log baseline reconstruction.
//!
//! Authors a sequence of audit rows (`SaSignerSetBaselined` → `SaSignerAdded` →
//! `SaThresholdChanged` → `SaSignerRemoved`) for a rule and asserts that
//! `AuditReader::find_latest_signer_set_state` returns the `ObservedSignerSet`
//! reconstructed from the MOST-RECENT row only (not the baseline row).
//!
//! Property check: regardless of row insertion order (baseline first, then
//! modifications), the most-recent row dictates the reconstruction.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::reader::AuditReader;
use stellar_agent_core::audit_log::signer_set::{BaselineReason, ObservedSignerSet, SignerPubkey};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::RedactedStrkey;
use tempfile::TempDir;
use uuid::Uuid;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn tmp_audit_writer() -> (Arc<Mutex<AuditWriter>>, PathBuf, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter::open must succeed");
    (Arc::new(Mutex::new(writer)), path, dir)
}

const SMART_ACCOUNT_REDACTED: &str = "CAAAA...AAD2KM";
const RULE_ID: u32 = 1;
const CHAIN_ID: &str = "stellar:testnet";

fn pubkeys_first8(observed: &ObservedSignerSet) -> Vec<String> {
    observed
        .signer_pubkeys
        .iter()
        .map(|_| "0101010101010101".to_owned())
        .collect()
}

fn write_baseline(writer: &Arc<Mutex<AuditWriter>>, rule_id: u32, observed: &ObservedSignerSet) {
    let prev_tip = writer.lock().unwrap().current_chain_tip();
    let entry = AuditEntry::new_sa_signer_set_baselined(
        rule_id,
        observed,
        pubkeys_first8(observed),
        0,
        BaselineReason::first_observation(),
        prev_tip,
        RedactedStrkey::from_already_redacted(SMART_ACCOUNT_REDACTED),
        CHAIN_ID,
        Uuid::new_v4().to_string(),
    );
    writer.lock().unwrap().write_entry(entry).unwrap();
}

fn write_signer_added(
    writer: &Arc<Mutex<AuditWriter>>,
    rule_id: u32,
    new_signer_id: u32,
    resulting: &ObservedSignerSet,
) {
    let entry = AuditEntry::new_sa_signer_added(
        rule_id,
        new_signer_id,
        resulting,
        pubkeys_first8(resulting),
        RedactedStrkey::from_already_redacted(SMART_ACCOUNT_REDACTED),
        CHAIN_ID,
        Uuid::new_v4().to_string(),
    );
    writer.lock().unwrap().write_entry(entry).unwrap();
}

fn write_threshold_changed(
    writer: &Arc<Mutex<AuditWriter>>,
    rule_id: u32,
    old_threshold: u32,
    new_threshold: u32,
    resulting: &ObservedSignerSet,
) {
    let entry = AuditEntry::new_sa_threshold_changed(
        rule_id,
        old_threshold,
        new_threshold,
        resulting,
        pubkeys_first8(resulting),
        RedactedStrkey::from_already_redacted(SMART_ACCOUNT_REDACTED),
        CHAIN_ID,
        Uuid::new_v4().to_string(),
    );
    writer.lock().unwrap().write_entry(entry).unwrap();
}

fn write_signer_removed(
    writer: &Arc<Mutex<AuditWriter>>,
    rule_id: u32,
    removed_signer_id: u32,
    resulting: &ObservedSignerSet,
) {
    let entry = AuditEntry::new_sa_signer_removed(
        rule_id,
        removed_signer_id,
        resulting,
        pubkeys_first8(resulting),
        RedactedStrkey::from_already_redacted(SMART_ACCOUNT_REDACTED),
        CHAIN_ID,
        Uuid::new_v4().to_string(),
    );
    writer.lock().unwrap().write_entry(entry).unwrap();
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Baseline only — returned state matches baseline row exactly.
#[test]
fn baseline_only_returns_baseline_state() {
    let (writer, _, _dir) = tmp_audit_writer();

    let observed = ObservedSignerSet {
        signer_count: 1,
        threshold: 1,
        signer_ids: vec![0],
        signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [1u8; 32] }],
    };
    write_baseline(&writer, RULE_ID, &observed);

    let reader = AuditReader::new(Arc::clone(&writer), None);
    let payload = reader
        .find_latest_signer_set_state(RULE_ID, SMART_ACCOUNT_REDACTED)
        .unwrap()
        .unwrap();

    assert_eq!(payload.state().signer_count, 1);
    assert_eq!(payload.state().threshold, 1);
}

/// After `SaSignerAdded`, the `SaSignerAdded` row dictates (signer_count=2).
#[test]
fn most_recent_row_dictates_after_add() {
    let (writer, _, _dir) = tmp_audit_writer();

    let baseline = ObservedSignerSet {
        signer_count: 1,
        threshold: 1,
        signer_ids: vec![0],
        signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [1u8; 32] }],
    };
    write_baseline(&writer, RULE_ID, &baseline);

    let post_add = ObservedSignerSet {
        signer_count: 2,
        threshold: 1,
        signer_ids: vec![0, 1],
        signer_pubkeys: vec![
            SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
            SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
        ],
    };
    write_signer_added(&writer, RULE_ID, 1, &post_add);

    let reader = AuditReader::new(Arc::clone(&writer), None);
    let payload = reader
        .find_latest_signer_set_state(RULE_ID, SMART_ACCOUNT_REDACTED)
        .unwrap()
        .unwrap();

    assert_eq!(
        payload.state().signer_count,
        2,
        "signer_count must reflect SaSignerAdded"
    );
    assert_eq!(payload.state().threshold, 1);
    assert_eq!(payload.state().signer_ids, vec![0, 1]);
}

/// After baseline → SaSignerAdded → SaThresholdChanged, threshold change dictates.
#[test]
fn most_recent_row_dictates_after_threshold_change() {
    let (writer, _, _dir) = tmp_audit_writer();

    let baseline = ObservedSignerSet {
        signer_count: 1,
        threshold: 1,
        signer_ids: vec![0],
        signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [1u8; 32] }],
    };
    write_baseline(&writer, RULE_ID, &baseline);

    let after_add = ObservedSignerSet {
        signer_count: 2,
        threshold: 1,
        signer_ids: vec![0, 1],
        signer_pubkeys: vec![
            SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
            SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
        ],
    };
    write_signer_added(&writer, RULE_ID, 1, &after_add);

    let after_threshold = ObservedSignerSet {
        signer_count: 2,
        threshold: 2,
        signer_ids: vec![0, 1],
        signer_pubkeys: after_add.signer_pubkeys.clone(),
    };
    write_threshold_changed(&writer, RULE_ID, 1, 2, &after_threshold);

    let reader = AuditReader::new(Arc::clone(&writer), None);
    let payload = reader
        .find_latest_signer_set_state(RULE_ID, SMART_ACCOUNT_REDACTED)
        .unwrap()
        .unwrap();

    assert_eq!(
        payload.state().threshold,
        2,
        "threshold must reflect SaThresholdChanged"
    );
    assert_eq!(payload.state().signer_count, 2);
}

/// Full sequence: baseline → add → threshold-change → remove.
/// The `SaSignerRemoved` row dictates (signer_count=1 again).
#[test]
fn most_recent_row_dictates_after_remove() {
    let (writer, _, _dir) = tmp_audit_writer();

    let baseline = ObservedSignerSet {
        signer_count: 1,
        threshold: 1,
        signer_ids: vec![0],
        signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [1u8; 32] }],
    };
    write_baseline(&writer, RULE_ID, &baseline);

    let after_add = ObservedSignerSet {
        signer_count: 2,
        threshold: 1,
        signer_ids: vec![0, 1],
        signer_pubkeys: vec![
            SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
            SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
        ],
    };
    write_signer_added(&writer, RULE_ID, 1, &after_add);

    let after_threshold = ObservedSignerSet {
        signer_count: 2,
        threshold: 2,
        signer_ids: after_add.signer_ids.clone(),
        signer_pubkeys: after_add.signer_pubkeys.clone(),
    };
    write_threshold_changed(&writer, RULE_ID, 1, 2, &after_threshold);

    // Lower threshold first (safe ordering), then remove.
    let pre_remove_threshold = ObservedSignerSet {
        signer_count: 2,
        threshold: 1,
        signer_ids: after_add.signer_ids.clone(),
        signer_pubkeys: after_add.signer_pubkeys.clone(),
    };
    write_threshold_changed(&writer, RULE_ID, 2, 1, &pre_remove_threshold);

    let after_remove = ObservedSignerSet {
        signer_count: 1,
        threshold: 1,
        signer_ids: vec![0],
        signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [1u8; 32] }],
    };
    write_signer_removed(&writer, RULE_ID, 1, &after_remove);

    let reader = AuditReader::new(Arc::clone(&writer), None);
    let payload = reader
        .find_latest_signer_set_state(RULE_ID, SMART_ACCOUNT_REDACTED)
        .unwrap()
        .unwrap();

    assert_eq!(
        payload.state().signer_count,
        1,
        "signer_count must reflect remove"
    );
    assert_eq!(payload.state().threshold, 1);
    assert_eq!(payload.state().signer_ids, vec![0]);
}

/// `find_latest_signer_set_state` returns `None` for a rule ID that has no rows,
/// even when other rules have rows in the same log.
#[test]
fn missing_rule_returns_none_not_wrong_state() {
    let (writer, _, _dir) = tmp_audit_writer();

    let baseline = ObservedSignerSet {
        signer_count: 1,
        threshold: 1,
        signer_ids: vec![0],
        signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [1u8; 32] }],
    };
    write_baseline(&writer, 1, &baseline);

    let reader = AuditReader::new(Arc::clone(&writer), None);
    let payload = reader
        .find_latest_signer_set_state(42, SMART_ACCOUNT_REDACTED)
        .unwrap();

    assert!(
        payload.is_none(),
        "missing rule ID must return None, not rule 1's state"
    );
}

/// Two rules in the same log — reader returns the state for the queried rule only.
#[test]
fn per_rule_isolation_in_same_log() {
    let (writer, _, _dir) = tmp_audit_writer();

    let rule1_observed = ObservedSignerSet {
        signer_count: 1,
        threshold: 1,
        signer_ids: vec![0],
        signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [1u8; 32] }],
    };
    write_baseline(&writer, 1, &rule1_observed);

    let rule2_observed = ObservedSignerSet {
        signer_count: 3,
        threshold: 2,
        signer_ids: vec![0, 1, 2],
        signer_pubkeys: vec![
            SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
            SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
            SignerPubkey::Ed25519 { pubkey: [3u8; 32] },
        ],
    };
    write_baseline(&writer, 2, &rule2_observed);

    let reader = AuditReader::new(Arc::clone(&writer), None);

    let r1 = reader
        .find_latest_signer_set_state(1, SMART_ACCOUNT_REDACTED)
        .unwrap()
        .unwrap();
    assert_eq!(r1.state().signer_count, 1, "rule 1 must return 1-of-1");

    let r2 = reader
        .find_latest_signer_set_state(2, SMART_ACCOUNT_REDACTED)
        .unwrap()
        .unwrap();
    assert_eq!(r2.state().signer_count, 3, "rule 2 must return 3-of-2");
    assert_eq!(r2.state().threshold, 2);
}
