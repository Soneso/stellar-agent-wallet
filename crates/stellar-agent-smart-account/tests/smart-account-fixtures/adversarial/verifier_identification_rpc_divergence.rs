//! Adversarial fixture: `verifier_identification_rpc_divergence`.
//!
//! Scenario: primary and secondary RPCs return different wasm hashes for the
//! same verifier contract during `identify_verifier`. The primary returns the
//! allowlisted OZ WebAuthn-verifier hash; the secondary returns an unknown hash
//! → `NetworkRpcDivergence` fires before any allowlist check runs.
//!
//! This is the verifier-path mirror of
//! `threshold_policy_identification_rpc_divergence.rs` and validates that the
//! two-RPC agreement check in `identify_verifier` fires even within the
//! identification step — before the signer-set comparison — when the verifier
//! contract's wasm hash is inconsistent across RPCs.

use std::sync::Arc;

use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_smart_account::VERIFIER_ALLOWLIST;
use stellar_agent_smart_account::error::SaError;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::rpc_mock_helpers::SorobanRpcDispatcher;
use super::rpc_mock_helpers::{
    SOURCE_G, UNKNOWN_WASM_HASH, ZERO_CONTRACT_REDACTED, build_ledger_entries_contract_instance,
    build_simulate_response, build_threshold_scval_xdr, manager_two_url, signer_set_n_of_n,
    tmp_audit_writer, write_baseline,
};

/// Verifier address used throughout this fixture (`[0x03; 32]` hash bytes —
/// distinct from the policy address `[0x01; 32]` and policy2 `[0x02; 32]`).
fn verifier_sc_address() -> stellar_xdr::ScAddress {
    use stellar_xdr::{ContractId, Hash, ScAddress};
    ScAddress::Contract(ContractId(Hash([0x03u8; 32])))
}

/// Smart-account address used as the forensic `smart_account` argument
/// (`[0x04; 32]` hash bytes — distinct from verifier, policy, and zero addresses).
fn smart_account_sc_address() -> stellar_xdr::ScAddress {
    use stellar_xdr::{ContractId, Hash, ScAddress};
    ScAddress::Contract(ContractId(Hash([0x04u8; 32])))
}

// ── Test ──────────────────────────────────────────────────────────────────────

/// Primary returns `VERIFIER_ALLOWLIST[0].wasm_hash` for the verifier; secondary
/// returns `UNKNOWN_WASM_HASH`.
///
/// The two-RPC agreement check in `identify_verifier` detects the hash
/// disagreement and returns `NetworkRpcDivergence` before the allowlist check.
#[tokio::test]
async fn verifier_hash_rpc_disagreement_returns_rpc_divergence() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    // Write a valid baseline so rule_id=1 is not missing-baseline.
    let baseline = signer_set_n_of_n(1);
    write_baseline(&audit_writer, 1, ZERO_CONTRACT_REDACTED, &baseline);

    let smart_account = smart_account_sc_address();
    let verifier = verifier_sc_address();

    // Context rule simulate response — not exercised by identify_verifier (no rule fetch),
    // but required by the SorobanRpcDispatcher which expects a simulate response.
    let sim_threshold = build_simulate_response(&build_threshold_scval_xdr(1));

    // Primary: serves VERIFIER_ALLOWLIST[0].wasm_hash for the verifier contract instance.
    let primary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(
            build_ledger_entries_contract_instance(&verifier, VERIFIER_ALLOWLIST[0].wasm_hash),
            sim_threshold.clone(),
        ))
        .mount(&primary_server)
        .await;

    // Secondary: serves UNKNOWN_WASM_HASH for the verifier contract instance.
    let secondary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(
            build_ledger_entries_contract_instance(&verifier, UNKNOWN_WASM_HASH),
            sim_threshold,
        ))
        .mount(&secondary_server)
        .await;

    let manager = manager_two_url(
        &primary_server.uri(),
        &secondary_server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path,
    );

    let result = manager
        .identify_verifier(
            smart_account,
            verifier,
            1,
            SOURCE_G,
            Uuid::new_v4().to_string(),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SaError::NetworkRpcDivergence { rule_id: 1, .. })
        ),
        "verifier hash disagreement must return NetworkRpcDivergence; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "network.rpc_divergence",
        "wire_code must be 'network.rpc_divergence'"
    );
}

/// Type-level: `NetworkRpcDivergence` from verifier-identification carries the
/// same wire code as `NetworkRpcDivergence` from policy-identification.
///
/// The error variant is the same regardless of which identify-* path triggered it.
#[test]
fn verifier_identification_rpc_divergence_wire_code_is_consistent() {
    let verifier_id_divergence = SaError::NetworkRpcDivergence {
        rule_id: 1,
        smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
        primary_view_digest_first8: "aabb0011".to_owned(),
        secondary_view_digest_first8: "ccdd9922".to_owned(),
        request_id: Uuid::new_v4().to_string(),
    };
    assert_eq!(
        verifier_id_divergence.wire_code(),
        "network.rpc_divergence",
        "NetworkRpcDivergence wire code must be 'network.rpc_divergence'"
    );
}
