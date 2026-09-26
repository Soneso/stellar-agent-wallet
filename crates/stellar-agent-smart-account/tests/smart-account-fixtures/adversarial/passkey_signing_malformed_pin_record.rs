//! Adversarial fixture: passkey signing with a malformed pin record.
//!
//! Scenario: the `SaContextRuleCreated` row for the signing rule carries
//! executable-reference pins that the install path never writes: a pin whose
//! tag exceeds the bounded rendering, a pin list misaligned with its first-8
//! list, or a pin whose resolved first-8 disagrees with the aligned first-8
//! entry. The audit reader refuses such a record as an integrity error.
//!
//! # Invariant
//!
//! `sign_with_passkey_rule` MUST abort before any signing ceremony with
//! `CredentialsError::DriftCheckUnavailable` whose source is
//! `SaError::AuditLog(ParseError)`, with or without
//! `accept_single_verifier`, and the outer `PasskeyAssertion` row MUST record
//! `failure:drift_check_unavailable`. An integrity failure is neither an
//! absent baseline nor an overridable diversification decision.

#![cfg(feature = "test-helpers")]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use stellar_agent_core::audit_log::AuditLogIntegrityError;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{EventKind, ExecutableRefPin};
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::credentials::{CredentialsError, CredentialsManager};
use stellar_xdr::{ContractId, Hash, ScAddress, ScString};

use super::rpc_mock_helpers::{manager_one_url, tmp_audit_writer};

const RULE_ID: u32 = 1;
const PINNED_FIRST8: &str = "4242424242424242";

fn pin() -> ExecutableRefPin {
    ExecutableRefPin::new(
        &ScAddress::Contract(ContractId(Hash([0x0cu8; 32]))),
        &ScString(b"policy-v1".to_vec().try_into().expect("tag fits")),
        &[0x42u8; 32],
    )
    .expect("pin builds")
}

fn read_audit_entries(log_path: &Path) -> Vec<AuditEntry> {
    std::fs::read_to_string(log_path)
        .expect("audit log must be readable")
        .lines()
        .filter_map(|line| serde_json::from_str::<AuditEntry>(line).ok())
        .collect()
}

/// Each malformed pin record aborts passkey signing with the typed integrity
/// error routed to `DriftCheckUnavailable`, before any ceremony, whether or
/// not the single-verifier override is set.
#[tokio::test]
async fn malformed_pin_record_routes_to_drift_check_unavailable() {
    let mut long_tag = pin();
    long_tag.tag = "t".repeat(65);
    let mut disagreeing = pin();
    disagreeing.resolved_hash_first8 = "1111111111111111".to_owned();
    // Each case pins one policy with first-8 `PINNED_FIRST8`.
    let cases: [(&str, Vec<Option<ExecutableRefPin>>); 3] = [
        ("malformed pin shape", vec![Some(long_tag)]),
        // The pin at position 0 matches the aligned first-8; only the
        // extra entry makes the list longer than the first-8 list.
        ("misaligned list", vec![Some(pin()), None]),
        ("first-8 disagreement", vec![Some(disagreeing)]),
    ];

    for (case, policy_refs) in cases {
        for accept_single_verifier in [false, true] {
            let (audit_writer, audit_log_path, dir) = tmp_audit_writer();
            let smart_account_strkey = format!("{}", stellar_strkey::Contract([0u8; 32]));
            let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
            let created = AuditEntry::new_sa_context_rule_created(
                &smart_account_redacted,
                RULE_ID,
                "default",
                1,
                1,
                None,
                "stellar:testnet",
                uuid::Uuid::new_v4().to_string(),
                vec![],
                vec![PINNED_FIRST8.to_owned()],
                true,
                false,
                vec![],
                policy_refs.clone(),
            );
            audit_writer
                .lock()
                .expect("audit writer poisoned")
                .write_entry(created)
                .expect("context-rule-created row must write");

            // The integrity failure precedes every RPC; an unreachable
            // endpoint makes any network call fail differently.
            let signers_manager = Arc::new(manager_one_url(
                "http://127.0.0.1:1",
                Arc::clone(&audit_writer),
                audit_log_path.clone(),
            ));
            let manager =
                CredentialsManager::new(dir.path().join("passkeys"), "default", "localhost", None);
            let ceremony_started = AtomicBool::new(false);

            let result = manager
                .sign_with_passkey_rule(
                    "laptop-passkey",
                    &smart_account_strkey,
                    &[0u8; 32],
                    vec![RULE_ID],
                    Some(signers_manager),
                    "127.0.0.1:0".parse().expect("socket addr parses"),
                    Duration::from_millis(10),
                    |_| ceremony_started.store(true, Ordering::SeqCst),
                    accept_single_verifier,
                )
                .await;

            let label = format!("{case}, accept_single_verifier={accept_single_verifier}");
            match &result {
                Err(CredentialsError::DriftCheckUnavailable { source }) => assert!(
                    matches!(
                        source.as_ref(),
                        SaError::AuditLog(AuditLogIntegrityError::ParseError { .. })
                    ),
                    "{label}: source must be the audit integrity error; got {source:?}"
                ),
                other => panic!("{label}: expected DriftCheckUnavailable; got {other:?}"),
            }
            assert!(
                !ceremony_started.load(Ordering::SeqCst),
                "{label}: no signing ceremony may start"
            );

            let entries = read_audit_entries(&audit_log_path);
            assert!(
                entries.iter().any(|entry| matches!(
                    &entry.event_kind,
                    EventKind::PasskeyAssertion { result, .. }
                        if result == "failure:drift_check_unavailable"
                )),
                "{label}: PasskeyAssertion(failure:drift_check_unavailable) row must be emitted"
            );
            assert!(
                !entries.iter().any(|entry| matches!(
                    entry.event_kind,
                    EventKind::SaVerifierDiversificationOverride { .. }
                )),
                "{label}: no diversification override row may be written"
            );
        }
    }
}
