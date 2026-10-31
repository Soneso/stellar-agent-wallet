//! Adversarial fixture: passkey signing with a malformed pin record.
//!
//! Scenario: the `SaContextRuleCreatedV2` row for the signing rule carries
//! executable-reference pins that the install path never writes: a pin whose
//! tag exceeds the bounded rendering, a pin list misaligned with its hash
//! list, or a pin whose resolved hash disagrees with the aligned hash, also
//! in bytes after the first eight. The audit reader refuses such a record as
//! an integrity error.
//!
//! A version-1 row of eight-byte prefixes is a well-formed but incomplete
//! record: signing refuses it with `SaError::WasmPinIncomplete`, routed to
//! `CredentialsError::DriftCheckUnavailable`, before any ceremony.
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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use stellar_agent_core::audit_log::AuditLogIntegrityError;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{
    EventKind, ExecutableRefPin, ExecutableRefPinFirst8, WasmHashPin,
};
use stellar_agent_core::audit_log::test_helpers::verified_audit_entries;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::auth_entry::PartialSorobanAuthorizationEntry;
use stellar_agent_smart_account::managers::auth_entry::test_helpers::partial_authorization_entry;
use stellar_agent_smart_account::managers::credentials::{CredentialsError, CredentialsManager};
use stellar_xdr::{ContractId, Hash, ScAddress, ScString};

use super::rpc_mock_helpers::{manager_one_url, tmp_audit_writer};

const RULE_ID: u32 = 1;

/// A valid testnet auth entry for the zero smart account over [`RULE_ID`].
fn testnet_entry() -> PartialSorobanAuthorizationEntry {
    partial_authorization_entry(
        ScAddress::Contract(ContractId(Hash([0u8; 32]))),
        TESTNET_PASSPHRASE,
        vec![ContextRuleId::new(RULE_ID)],
    )
    .expect("fixture auth entry builds")
}
const PINNED_HASH: WasmHashPin = WasmHashPin::new([0x42; 32]);

fn pin() -> ExecutableRefPin {
    ExecutableRefPin::new(
        &ScAddress::Contract(ContractId(Hash([0x0cu8; 32]))),
        &ScString(b"policy-v1".to_vec().try_into().expect("tag fits")),
        &[0x42u8; 32],
    )
    .expect("pin builds")
}

/// Each malformed pin record aborts passkey signing with the typed integrity
/// error routed to `DriftCheckUnavailable`, before any ceremony, whether or
/// not the single-verifier override is set.
#[tokio::test]
async fn malformed_pin_record_routes_to_drift_check_unavailable() {
    let mut long_tag = pin();
    long_tag.tag = "t".repeat(65);
    let mut disagreeing = pin();
    disagreeing.resolved_hash = WasmHashPin::new([0x11; 32]);
    let mut twin = [0x42u8; 32];
    twin[8..].fill(0x43);
    let mut twin_disagreeing = pin();
    twin_disagreeing.resolved_hash = WasmHashPin::new(twin);
    // Each case pins one policy with the hash `PINNED_HASH`.
    let cases: [(&str, Vec<Option<ExecutableRefPin>>); 4] = [
        ("malformed pin shape", vec![Some(long_tag)]),
        // The pin at position 0 matches the aligned hash; only the extra
        // entry makes the list longer than the hash list.
        ("misaligned list", vec![Some(pin()), None]),
        ("resolved hash disagreement", vec![Some(disagreeing)]),
        ("equal-prefix resolved hash", vec![Some(twin_disagreeing)]),
    ];

    for (case, policy_refs) in cases {
        for accept_single_verifier in [false, true] {
            let (audit_writer, audit_log_path, dir) = tmp_audit_writer();
            let smart_account_strkey = format!("{}", stellar_strkey::Contract([0u8; 32]));
            let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
            let created = AuditEntry::new_sa_context_rule_created_v2(
                &smart_account_redacted,
                RULE_ID,
                "default",
                1,
                1,
                None,
                "stellar:testnet",
                uuid::Uuid::new_v4().to_string(),
                vec![],
                vec![PINNED_HASH],
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
                audit_log_path,
            ));
            let manager =
                CredentialsManager::new(dir.path().join("passkeys"), "default", "localhost", None);
            let ceremony_started = AtomicBool::new(false);

            let result = manager
                .sign_with_passkey_rule(
                    "laptop-passkey",
                    &testnet_entry(),
                    signers_manager,
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

            let entries = verified_audit_entries(&audit_writer);
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

/// A version-1 pin record of eight-byte prefixes aborts passkey signing with
/// `SaError::WasmPinIncomplete` routed to `DriftCheckUnavailable`, before any
/// ceremony and any RPC, whether or not the single-verifier override is set.
/// No override admits an incomplete record.
#[tokio::test]
async fn an_incomplete_pin_record_refuses_passkey_signing_before_any_ceremony() {
    for accept_single_verifier in [false, true] {
        let (audit_writer, audit_log_path, dir) = tmp_audit_writer();
        let smart_account_strkey = format!("{}", stellar_strkey::Contract([0u8; 32]));
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
        let first8_pin = ExecutableRefPinFirst8::new(
            &ScAddress::Contract(ContractId(Hash([0x0cu8; 32]))),
            &ScString(b"policy-v1".to_vec().try_into().expect("tag fits")),
            &[0x42u8; 32],
        )
        .expect("pin builds");
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
            vec!["4242424242424242".to_owned()],
            true,
            true,
            vec![],
            vec![Some(first8_pin)],
        );
        audit_writer
            .lock()
            .expect("audit writer poisoned")
            .write_entry(created)
            .expect("context-rule-created row must write");

        let signers_manager = Arc::new(manager_one_url(
            "http://127.0.0.1:1",
            Arc::clone(&audit_writer),
            audit_log_path,
        ));
        let manager =
            CredentialsManager::new(dir.path().join("passkeys"), "default", "localhost", None);
        let ceremony_started = AtomicBool::new(false);
        let result = manager
            .sign_with_passkey_rule(
                "laptop-passkey",
                &testnet_entry(),
                signers_manager,
                "127.0.0.1:0".parse().expect("socket addr parses"),
                Duration::from_millis(10),
                |_| ceremony_started.store(true, Ordering::SeqCst),
                accept_single_verifier,
            )
            .await;

        let label = format!("accept_single_verifier={accept_single_verifier}");
        match &result {
            Err(CredentialsError::DriftCheckUnavailable { source }) => {
                assert!(
                    matches!(
                        source.as_ref(),
                        SaError::WasmPinIncomplete {
                            rule_id: RULE_ID,
                            ..
                        }
                    ),
                    "{label}: source must be the incomplete-pin refusal; got {source:?}"
                );
                assert_eq!(source.wire_code(), "sa.wasm_pin_incomplete", "{label}");
            }
            other => panic!("{label}: expected DriftCheckUnavailable; got {other:?}"),
        }
        assert!(
            !ceremony_started.load(Ordering::SeqCst),
            "{label}: no signing ceremony may start"
        );
        let entries = verified_audit_entries(&audit_writer);
        assert!(
            !entries.iter().any(|entry| matches!(
                entry.event_kind,
                EventKind::SaVerifierDiversificationOverride { .. }
            )),
            "{label}: no diversification override row may be written"
        );
    }
}
