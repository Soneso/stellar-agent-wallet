//! Adversarial fixture: audit-log wholesale replacement detection.
//!
//! Replaces the wallet's audit-log file wholesale with a different but valid
//! hash chain (an audit log from a different rule / smart account, integrity-clean
//! per its own chain check). Asserts that the divergence-check path refuses because
//! the most-recent state row in the replacement log was written for a DIFFERENT
//! `smart_account_redacted` value, so `find_latest_signer_set_state` returns `None`
//! for the queried `(rule_id, smart_account_redacted)` pair → `SignerSetMissingBaseline`.
//!
//! Note: the full HMAC-sidecar binding (binding the chain's HMAC root to a
//! per-profile keyring entry) is a keyring-integration concern. Without a keyring
//! in unit tests, this fixture validates the orthogonal property: a wholesale
//! replacement with a log written for a DIFFERENT smart account is detected
//! because the `smart_account_redacted` filter does not match — producing
//! `SignerSetMissingBaseline` rather than a false-positive approval.
//!
//! # Property verified
//!
//! Atomic signer-threshold update: a wholesale-replaced audit log for a different
//! smart account does not satisfy the divergence check for the victim account.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::signer_set::{BaselineReason, ObservedSignerSet, SignerPubkey};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
use stellar_xdr::{ContractId, Hash, ScAddress};
use uuid::Uuid;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn tmp_audit_writer_at(path: &std::path::Path) -> Arc<Mutex<AuditWriter>> {
    let writer =
        AuditWriter::open(path.to_path_buf(), None).expect("AuditWriter::open must succeed");
    Arc::new(Mutex::new(writer))
}

fn manager_with_url(
    rpc_url: &str,
    audit_writer: Arc<Mutex<AuditWriter>>,
    audit_log_path: PathBuf,
) -> SignersManager {
    let config = SignersManagerConfig::new(
        rpc_url.to_owned(),
        rpc_url.to_owned(),
        audit_writer,
        audit_log_path,
        "Test SDF Network ; September 2015".to_owned(),
        "test-profile".to_owned(),
        Duration::from_secs(5),
        "stellar:testnet".to_owned(),
    );
    SignersManager::new(config).expect("SignersManager::new must succeed")
}

fn zero_sc_address() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0u8; 32])))
}

fn write_baseline(
    writer: &Arc<Mutex<AuditWriter>>,
    rule_id: u32,
    smart_account_redacted: &str,
    observed: &ObservedSignerSet,
) {
    let prev_tip = writer.lock().unwrap().current_chain_tip();
    let first8: Vec<String> = observed
        .signer_pubkeys
        .iter()
        .map(|_| "0101010101010101".to_owned())
        .collect();
    let entry = AuditEntry::new_sa_signer_set_baselined(
        rule_id,
        observed,
        first8,
        0,
        BaselineReason::first_observation(),
        prev_tip,
        RedactedStrkey::from_already_redacted(smart_account_redacted),
        "stellar:testnet",
        Uuid::new_v4().to_string(),
    );
    writer.lock().unwrap().write_entry(entry).unwrap();
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// A wholesale-replaced log written for a DIFFERENT smart account is not matched
/// by `find_latest_signer_set_state` for the victim account → `SignerSetMissingBaseline`.
///
/// This validates the `smart_account_redacted` filter in `find_latest_signer_set_state`:
/// even if the replacement chain is integrity-clean, the reader returns `None` for
/// the victim's `(rule_id, smart_account_redacted)` pair because it does not appear
/// in the attacker's log.
#[tokio::test]
async fn wholesale_replacement_with_wrong_account_returns_missing_baseline() {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let log_path = dir.path().join("audit.jsonl");

    // Write an integrity-clean log for a DIFFERENT smart account.
    let attacker_account_redacted = "CATTK...KATTK";
    {
        let attacker_writer = tmp_audit_writer_at(&log_path);
        let observed = ObservedSignerSet {
            signer_count: 2,
            threshold: 2,
            signer_ids: vec![0, 1],
            signer_pubkeys: vec![
                SignerPubkey::Ed25519 {
                    pubkey: [0xaau8; 32],
                },
                SignerPubkey::Ed25519 {
                    pubkey: [0xbbu8; 32],
                },
            ],
        };
        write_baseline(&attacker_writer, 1, attacker_account_redacted, &observed);
        // Log is dropped here, file handle released.
    }

    // Open the manager pointing at the replaced log.
    // The VICTIM's smart_account_redacted is NOT the attacker's account.
    let victim_writer = tmp_audit_writer_at(&log_path);
    let manager = manager_with_url(
        "http://127.0.0.1:1", // unreachable; step 1 fires before any RPC
        Arc::clone(&victim_writer),
        log_path,
    );

    // The victim queries for rule 1, ZERO_CONTRACT ("CAAAA...AD2KM") —
    // not present in the attacker's log → returns SignerSetMissingBaseline.
    let result = manager
        .verify_signer_set_against_chain(
            zero_sc_address(),
            1,
            Some(stellar_agent_core::constants::SIMULATE_SENTINEL_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SaError::SignerSetMissingBaseline { rule_id: 1, .. })
        ),
        "wholesale replacement for wrong account must return SignerSetMissingBaseline; got: {result:?}"
    );
}

/// A wholesale-replaced log written for a DIFFERENT rule_id is not matched →
/// `SignerSetMissingBaseline` for the queried rule_id.
#[tokio::test]
async fn wholesale_replacement_with_wrong_rule_id_returns_missing_baseline() {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let log_path = dir.path().join("audit.jsonl");

    let account_redacted = "CAAAA...AAD2KM";

    // Write a log for rule_id 99 (not the rule the victim queries).
    {
        let attacker_writer = tmp_audit_writer_at(&log_path);
        let observed = ObservedSignerSet {
            signer_count: 1,
            threshold: 1,
            signer_ids: vec![0],
            signer_pubkeys: vec![SignerPubkey::Ed25519 {
                pubkey: [0xaau8; 32],
            }],
        };
        write_baseline(&attacker_writer, 99, account_redacted, &observed);
    }

    let victim_writer = tmp_audit_writer_at(&log_path);
    let manager = manager_with_url("http://127.0.0.1:1", Arc::clone(&victim_writer), log_path);

    // Victim queries rule_id 1 — not present in the attacker's log.
    let result = manager
        .verify_signer_set_against_chain(
            zero_sc_address(),
            1,
            Some(stellar_agent_core::constants::SIMULATE_SENTINEL_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SaError::SignerSetMissingBaseline { rule_id: 1, .. })
        ),
        "wholesale replacement for wrong rule must return SignerSetMissingBaseline; got: {result:?}"
    );
}
