//! Adversarial fixture: the order and the deadline of the passkey signing
//! checks.
//!
//! `sign_with_passkey_rule` runs, for every rule other than rule 0 and before
//! any ceremony: the verifier diversification gate (audit log only), then
//! under one deadline the rule locks, the signer-set baseline read, the
//! pinned-hash drift check and the signer-set comparison, each step for
//! every rule before the next starts.
//!
//! # Invariants
//!
//! - A rule without a signer-set state row refuses with
//!   `CredentialsError::SignerSetDivergence` wrapping
//!   `SaError::SignerSetMissingBaseline` before any RPC, although its
//!   verifier has drifted from the pin record: the drift check, which would
//!   find the drift, runs after the baseline read and never starts.
//! - A deadline that has passed when the baseline read returns refuses with
//!   `CredentialsError::SignerSetDivergence` wrapping
//!   `SaError::AuthEntryConstructionFailed` at stage `baseline_read`.
//! - A chain whose signer set differs from the state row refuses with
//!   `CredentialsError::SignerSetDivergence` wrapping
//!   `SaError::SignerSetDiverged`, after the drift check passed. The
//!   comparison writes the diverged row under the request id the
//!   `PasskeyAssertion` row carries.

#![cfg(feature = "test-helpers")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::credentials::{CredentialsError, CredentialsManager};
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
use stellar_xdr::{ContractId, Hash, ScAddress};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer};

use super::rpc_mock_helpers::{
    KNOWN_WASM_HASH, SorobanRpcDispatcher, UNKNOWN_WASM_HASH,
    build_context_rule_external_signers_xdr, build_context_rule_scval_xdr,
    build_ledger_entries_contract_instance, build_simulate_response, build_threshold_scval_xdr,
    policy_sc_address, signer_set_n_of_n, tmp_audit_writer, write_baseline,
};

const RULE_ID: u32 = 1;

/// The first-8 the pin record holds for the rule's verifier; the live
/// verifier runs another executable.
const PINNED_VERIFIER_FIRST8: &str = "4242424242424242";

fn verifier() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x2a; 32])))
}

fn read_audit_entries(log_path: &Path) -> Vec<AuditEntry> {
    std::fs::read_to_string(log_path)
        .expect("audit log must be readable")
        .lines()
        .filter_map(|line| serde_json::from_str::<AuditEntry>(line).ok())
        .collect()
}

/// A signers manager over `rpc_url` on both endpoints with `timeout`.
fn signers_manager(
    rpc_url: &str,
    audit_writer: Arc<Mutex<AuditWriter>>,
    audit_log_path: PathBuf,
    timeout: Duration,
) -> Arc<SignersManager> {
    Arc::new(
        SignersManager::new(SignersManagerConfig::new(
            rpc_url.to_owned(),
            rpc_url.to_owned(),
            audit_writer,
            audit_log_path,
            "Test SDF Network ; September 2015".to_owned(),
            "test-profile".to_owned(),
            timeout,
            "stellar:testnet".to_owned(),
        ))
        .expect("SignersManager::new must succeed"),
    )
}

/// A rule whose verifier drifted from its pin record and which has no
/// signer-set state row refuses at the baseline read, before any RPC: no
/// drift row is written and the endpoint is never contacted.
#[tokio::test]
async fn a_missing_baseline_refuses_before_the_drift_check_reads_the_chain() {
    let (audit_writer, audit_log_path, dir) = tmp_audit_writer();
    let smart_account_strkey = format!("{}", stellar_strkey::Contract([0u8; 32]));
    let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
    audit_writer
        .lock()
        .expect("audit writer poisoned")
        .write_entry(AuditEntry::new_sa_context_rule_created(
            &smart_account_redacted,
            RULE_ID,
            "default",
            1,
            0,
            None,
            "stellar:testnet",
            uuid::Uuid::new_v4().to_string(),
            vec![PINNED_VERIFIER_FIRST8.to_owned()],
            vec![],
            false,
            false,
            vec![],
            vec![],
        ))
        .expect("context-rule-created row must write");

    // The chain the drift check would read: the rule's one External signer
    // on the verifier, whose executable is not the pinned one.
    let server = MockServer::start().await;
    let rule_xdr = build_context_rule_external_signers_xdr(RULE_ID, &[0], &verifier(), &[0x11; 32]);
    Mock::given(method("POST"))
        .respond_with(SorobanRpcDispatcher::new(
            build_ledger_entries_contract_instance(&verifier(), UNKNOWN_WASM_HASH),
            build_simulate_response(&rule_xdr),
        ))
        .mount(&server)
        .await;
    let manager = signers_manager(
        &server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
        Duration::from_secs(5),
    );
    let credentials =
        CredentialsManager::new(dir.path().join("passkeys"), "default", "localhost", None);
    let ceremony_started = AtomicBool::new(false);

    let result = credentials
        .sign_with_passkey_rule(
            "laptop-passkey",
            &smart_account_strkey,
            &[0u8; 32],
            vec![RULE_ID],
            manager,
            "127.0.0.1:0".parse().expect("socket addr parses"),
            Duration::from_millis(10),
            |_| ceremony_started.store(true, Ordering::SeqCst),
            // The one pinned verifier passes the diversification gate.
            true,
        )
        .await;

    match &result {
        Err(CredentialsError::SignerSetDivergence { source }) => assert!(
            matches!(
                source.as_ref(),
                SaError::SignerSetMissingBaseline {
                    rule_id: RULE_ID,
                    ..
                }
            ),
            "the baseline read refuses first: {source:?}"
        ),
        other => panic!("expected SignerSetDivergence; got {other:?}"),
    }
    assert!(!ceremony_started.load(Ordering::SeqCst));
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "no RPC precedes the baseline read"
    );
    let entries = read_audit_entries(&audit_log_path);
    assert!(
        !entries.iter().any(|entry| matches!(
            entry.event_kind,
            EventKind::SaVerifierHashDrift { .. } | EventKind::SaPolicyHashDrift { .. }
        )),
        "the drift check never ran"
    );
    assert!(
        entries.iter().any(|entry| matches!(
            &entry.event_kind,
            EventKind::PasskeyAssertion { result, .. } if result == "failure:signer_set_diverged"
        )),
        "PasskeyAssertion(failure:signer_set_diverged) row must be emitted"
    );
}

/// A deadline of zero passes during the baseline read, and the refusal is
/// the read's elapse, wrapped as a signer-set refusal.
#[tokio::test]
async fn a_spent_deadline_refuses_at_the_baseline_read() {
    let (audit_writer, audit_log_path, dir) = tmp_audit_writer();
    let smart_account_strkey = format!("{}", stellar_strkey::Contract([0u8; 32]));
    let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
    write_baseline(
        &audit_writer,
        RULE_ID,
        &smart_account_redacted,
        &signer_set_n_of_n(1),
    );
    // The deadline is spent before any RPC; an unreachable endpoint makes
    // any network call fail differently.
    let manager = signers_manager(
        "http://127.0.0.1:1",
        Arc::clone(&audit_writer),
        audit_log_path,
        Duration::ZERO,
    );
    let credentials =
        CredentialsManager::new(dir.path().join("passkeys"), "default", "localhost", None);

    let result = credentials
        .sign_with_passkey_rule(
            "laptop-passkey",
            &smart_account_strkey,
            &[0u8; 32],
            vec![RULE_ID],
            manager,
            "127.0.0.1:0".parse().expect("socket addr parses"),
            Duration::from_millis(10),
            |_| {},
            // The diversification gate, which reads the log only, passes.
            true,
        )
        .await;

    match &result {
        Err(CredentialsError::SignerSetDivergence { source }) => match source.as_ref() {
            SaError::AuthEntryConstructionFailed {
                stage,
                redacted_reason,
            } => {
                assert_eq!(*stage, "baseline_read");
                assert_eq!(
                    redacted_reason,
                    "baseline_read exceeded collective pre-submit budget of 0s"
                );
            }
            other => panic!("expected the baseline_read elapse; got {other:?}"),
        },
        other => panic!("expected SignerSetDivergence; got {other:?}"),
    }
}

/// A rule whose state row records one signer while the chain holds two
/// refuses at the comparison, the drift check before it having passed: the
/// diverged row and the `PasskeyAssertion` row share the request id, and no
/// ceremony starts.
#[tokio::test]
async fn a_changed_signer_set_refuses_at_the_comparison() {
    let (audit_writer, audit_log_path, dir) = tmp_audit_writer();
    let smart_account_strkey = format!("{}", stellar_strkey::Contract([0u8; 32]));
    let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
    write_baseline(
        &audit_writer,
        RULE_ID,
        &smart_account_redacted,
        &signer_set_n_of_n(1),
    );

    // The rule holds two signers and the simple-threshold policy at
    // threshold 2. One endpoint serves both roles: the drift check's rule
    // read, then each comparison endpoint's rule read, then each one's
    // threshold read.
    let policy = policy_sc_address();
    let rule_xdr = build_context_rule_scval_xdr(
        RULE_ID,
        &signer_set_n_of_n(2),
        std::slice::from_ref(&policy),
    );
    let rule_response = build_simulate_response(&rule_xdr);
    let threshold_response = build_simulate_response(&build_threshold_scval_xdr(2));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            build_ledger_entries_contract_instance(&policy, KNOWN_WASM_HASH),
            vec![
                rule_response.clone(),
                rule_response.clone(),
                rule_response,
                threshold_response,
            ],
        ))
        .mount(&server)
        .await;
    let manager = signers_manager(
        &server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
        Duration::from_secs(5),
    );
    let credentials =
        CredentialsManager::new(dir.path().join("passkeys"), "default", "localhost", None);
    let ceremony_started = AtomicBool::new(false);

    let result = credentials
        .sign_with_passkey_rule(
            "laptop-passkey",
            &smart_account_strkey,
            &[0u8; 32],
            vec![RULE_ID],
            manager,
            "127.0.0.1:0".parse().expect("socket addr parses"),
            Duration::from_millis(10),
            |_| ceremony_started.store(true, Ordering::SeqCst),
            // The diversification gate, which reads the log only, passes.
            true,
        )
        .await;

    match &result {
        Err(CredentialsError::SignerSetDivergence { source }) => assert!(
            matches!(
                source.as_ref(),
                SaError::SignerSetDiverged {
                    rule_id: RULE_ID,
                    tx_hash: None,
                    ..
                }
            ),
            "the comparison refuses: {source:?}"
        ),
        other => panic!("expected SignerSetDivergence; got {other:?}"),
    }
    assert!(!ceremony_started.load(Ordering::SeqCst));
    let entries = read_audit_entries(&audit_log_path);
    let diverged: Vec<&AuditEntry> = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.event_kind,
                EventKind::SaSignerSetDiverged {
                    rule_id: RULE_ID,
                    ..
                }
            )
        })
        .collect();
    assert_eq!(diverged.len(), 1, "one diverged row");
    let assertion: Vec<&AuditEntry> = entries
        .iter()
        .filter(|entry| {
            matches!(
                &entry.event_kind,
                EventKind::PasskeyAssertion { result, .. } if result == "failure:signer_set_diverged"
            )
        })
        .collect();
    assert_eq!(
        assertion.len(),
        1,
        "one PasskeyAssertion(failure:signer_set_diverged) row"
    );
    assert_eq!(
        diverged[0].request_id, assertion[0].request_id,
        "the two rows share the request id"
    );
    assert!(
        !entries.iter().any(|entry| matches!(
            entry.event_kind,
            EventKind::SaVerifierHashDrift { .. } | EventKind::SaPolicyHashDrift { .. }
        )),
        "the drift check found no drift"
    );
}
