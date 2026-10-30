//! Adversarial fixture: `verifier_wasm_not_in_allowlist`.
//!
//! Scenario: the verifier contract has a wasm hash that is NOT in
//! `VERIFIER_ALLOWLIST` (the compile-time allowlist).  `pin_referenced_contracts`
//! MUST return `SaError::VerifierWasmNotInAllowlist` with
//! `wire_code = "sa.verifier_wasm_not_in_allowlist"` when
//! `accept_unknown_verifier = false`.
//!
//! Verifier pinning is fail-closed for unknown verifier wasm by default;
//! the operator may opt in via `--accept-unknown-verifier`.
//!
//! # Implements
//!
//! Verifier wasm pinning: enforces that only allowlisted verifier wasm hashes
//! are accepted at rule-install time.

use std::sync::Arc;

use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::rules::RuleContext;
use stellar_agent_smart_account::managers::rules::{ContextRuleDefinition, ContextRuleSignerInput};
use stellar_agent_smart_account::managers::verifiers::pin_referenced_contracts;
use stellar_xdr::{ContractId, Hash, ScAddress};
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::combined_rpc_responder::JsonRpcResultResponder;
use super::rpc_mock_helpers::{
    SOURCE_G, UNKNOWN_WASM_HASH, ZERO_CONTRACT_REDACTED, build_ledger_entries_contract_instance,
    manager_one_url, tmp_audit_writer,
};

// ── Address helpers ───────────────────────────────────────────────────────────

/// Verifier contract address (`[0x30; 32]`), distinct from other fixture addresses.
fn verifier_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x30u8; 32])))
}

/// Smart-account address (`[0x31; 32]`).
fn smart_account_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x31u8; 32])))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Without `--accept-unknown-verifier`, installing a rule whose verifier has
/// an unknown wasm hash (not in `VERIFIER_ALLOWLIST`) must return
/// `SaError::VerifierWasmNotInAllowlist` with
/// `wire_code = "sa.verifier_wasm_not_in_allowlist"`.
#[tokio::test]
async fn verifier_unknown_wasm_hash_rejected_without_override() {
    let verifier = verifier_addr();
    let smart_account = smart_account_addr();

    // RPC returns UNKNOWN_WASM_HASH — not in VERIFIER_ALLOWLIST.
    let ledger_entries = build_ledger_entries_contract_instance(&verifier, UNKNOWN_WASM_HASH);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(JsonRpcResultResponder(ledger_entries))
        .mount(&server)
        .await;

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(&server.uri(), Arc::clone(&audit_writer), audit_log_path);

    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "unknown-wasm-test".to_owned(),
        None,
        vec![ContextRuleSignerInput::External {
            verifier: verifier.clone(),
            pubkey_data: vec![0xeeu8; 32],
        }],
        vec![],
    );

    let result = pin_referenced_contracts(
        &manager,
        smart_account,
        ZERO_CONTRACT_REDACTED,
        &definition,
        None,
        SOURCE_G,
        false, // accept_mutable_verifier
        false, // accept_unknown_verifier — MUST refuse unknown hash
        Uuid::new_v4().to_string(),
    )
    .await;

    assert!(
        matches!(result, Err(SaError::VerifierWasmNotInAllowlist { .. })),
        "unknown-wasm verifier must be refused without accept_unknown_verifier; got: {result:?}"
    );
    let error = result.unwrap_err();
    assert_eq!(
        error.wire_code(),
        "sa.verifier_wasm_not_in_allowlist",
        "wire_code must be 'sa.verifier_wasm_not_in_allowlist'"
    );
    // The rule has no on-chain id before install, so the refusal names none.
    assert!(
        matches!(
            error,
            SaError::VerifierWasmNotInAllowlist { rule_id: None, .. }
        ),
        "a pre-install refusal carries no rule id: {error:?}"
    );
    assert!(
        error
            .to_string()
            .starts_with("verifier wasm hash not in VERIFIER_ALLOWLIST: "),
        "{error}"
    );
}

/// Wire-code consistency: `SaError::VerifierWasmNotInAllowlist` carries
/// `"sa.verifier_wasm_not_in_allowlist"` regardless of construction path.
///
/// Type-level check (no RPC required).
#[test]
fn verifier_wasm_not_in_allowlist_wire_code_is_consistent() {
    let err = SaError::VerifierWasmNotInAllowlist {
        rule_id: None,
        smart_account_redacted: RedactedStrkey::from_already_redacted(ZERO_CONTRACT_REDACTED),
        observed_hash_first8: "dddddddd".to_owned(),
        request_id: Uuid::new_v4().to_string(),
    };
    assert_eq!(
        err.wire_code(),
        "sa.verifier_wasm_not_in_allowlist",
        "VerifierWasmNotInAllowlist wire_code must be 'sa.verifier_wasm_not_in_allowlist'"
    );
}

#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn a_revoked_verifier_is_refused_with_both_overrides() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(JsonRpcResultResponder(
            build_ledger_entries_contract_instance(&verifier_addr(), [0xee; 32]),
        ))
        .mount(&server)
        .await;
    let (audit, path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(&server.uri(), audit, path);
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "revoked".to_owned(),
        None,
        vec![ContextRuleSignerInput::External {
            verifier: verifier_addr(),
            pubkey_data: vec![0x11; 32],
        }],
        vec![],
    );
    let error = pin_referenced_contracts(
        &manager,
        smart_account_addr(),
        ZERO_CONTRACT_REDACTED,
        &definition,
        None,
        SOURCE_G,
        true,
        true,
        "revoked-install".to_owned(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, SaError::VerifierWasmRevoked { rule_id: None, .. }),
        "{error:?}"
    );
    assert_eq!(error.wire_code(), "sa.verifier_wasm_revoked");
    assert!(!error.to_string().contains("for rule"));
}

#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn identify_verifier_refuses_a_revoked_verifier() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(JsonRpcResultResponder(
            build_ledger_entries_contract_instance(&verifier_addr(), [0xee; 32]),
        ))
        .mount(&server)
        .await;
    let (audit, path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(&server.uri(), audit, path);
    let error = manager
        .identify_verifier(
            smart_account_addr(),
            verifier_addr(),
            7,
            SOURCE_G,
            "revoked-identify".to_owned(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            SaError::VerifierWasmRevoked {
                rule_id: Some(7),
                ..
            }
        ),
        "{error:?}"
    );
}
