//! Adversarial fixture: RPC divergence detection before signer-set baseline comparison.
//!
//! Scenario: primary and secondary RPC endpoints disagree on the on-chain signer
//! set (primary sees 1-of-1, secondary sees 2-of-2). The audit-log baseline is
//! also 1-of-1. Even though the baseline matches the primary view, the two-RPC
//! disagreement is detected FIRST (Step 2b) and returns `NetworkRpcDivergence`.
//!
//! This validates the ordering guarantee: `NetworkRpcDivergence` fires before
//! `SignerSetDiverged` when the two RPCs disagree — even if the primary view
//! matches the local baseline.
//!
//! Verifies the atomic signer-threshold-update invariant: `NetworkRpcDivergence`
//! is returned before `SignerSetDiverged` when the two RPC endpoints disagree.

use std::sync::Arc;

use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_smart_account::error::SaError;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::combined_rpc_responder::{CombinedRpcResponder, SequencedSimulate};
use super::rpc_mock_helpers::{
    KNOWN_WASM_HASH, SOURCE_G, ZERO_CONTRACT_REDACTED, build_context_rule_scval_xdr,
    build_simulate_response, build_threshold_scval_xdr, manager_two_url, policy_sc_address,
    signer_set_n_of_n, tmp_audit_writer, write_baseline, zero_sc_address,
};

// ── Test ──────────────────────────────────────────────────────────────────────

/// Primary sees 1-of-1; secondary sees 2-of-2; baseline is 1-of-1.
///
/// The two-RPC agreement check fires at Step 2b and returns `NetworkRpcDivergence`
/// rather than `SignerSetDiverged`, even though the primary view matches the baseline.
#[tokio::test]
async fn primary_secondary_disagree_returns_rpc_divergence() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    // Write a 1-of-1 baseline.
    let baseline = signer_set_n_of_n(1);
    write_baseline(&audit_writer, 1, ZERO_CONTRACT_REDACTED, &baseline);

    let policy = policy_sc_address();

    // Primary mock: returns 1-of-1 on-chain.
    let cr_1of1 =
        build_context_rule_scval_xdr(1, &signer_set_n_of_n(1), std::slice::from_ref(&policy));
    let th_1 = build_threshold_scval_xdr(1);
    let sim_cr_1 = build_simulate_response(&cr_1of1);
    let sim_th_1 = build_simulate_response(&th_1);

    // Secondary mock: returns 2-of-2 on-chain.
    let cr_2of2 =
        build_context_rule_scval_xdr(1, &signer_set_n_of_n(2), std::slice::from_ref(&policy));
    let th_2 = build_threshold_scval_xdr(2);
    let sim_cr_2 = build_simulate_response(&cr_2of2);
    let sim_th_2 = build_simulate_response(&th_2);

    // Primary mock server: simulate sequence for primary.
    // Primary receives:
    //   1. identify_threshold_policy: get_context_rule (primary)
    //   2. fetch_signer_set(primary): get_context_rule
    //   3. fetch_signer_set(primary): get_threshold
    let primary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new(
            SOURCE_G,
            &policy,
            KNOWN_WASM_HASH,
            SequencedSimulate::new(vec![sim_cr_1.clone(), sim_cr_1.clone(), sim_th_1.clone()]),
        ))
        .mount(&primary_server)
        .await;

    // Secondary mock server: simulate sequence for secondary.
    // Secondary receives:
    //   1. fetch_contract_wasm_hashes secondary: getLedgerEntries (contract instance)
    //   2. fetch_signer_set(secondary): get_context_rule
    //   3. fetch_signer_set(secondary): get_threshold
    let secondary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new(
            SOURCE_G,
            &policy,
            KNOWN_WASM_HASH,
            SequencedSimulate::new(vec![sim_cr_2.clone(), sim_th_2.clone()]),
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
        .verify_signer_set_against_chain(
            zero_sc_address(),
            1,
            Some(SOURCE_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SaError::NetworkRpcDivergence { rule_id: 1, .. })
        ),
        "primary/secondary disagreement must return NetworkRpcDivergence; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "network.rpc_divergence",
        "wire_code must be 'network.rpc_divergence'"
    );
}

/// The `NetworkRpcDivergence` wire code is `"network.rpc_divergence"` (not `"sa.*"`).
///
/// This variant-level assertion ensures the error is not confused with
/// `sa.signer_set_diverged` in wire output — they have different response shapes.
#[tokio::test]
async fn rpc_divergence_wire_code_is_not_signer_set_diverged() {
    // Construct the error type directly without RPC — validates the wire code
    // at the type level without needing a full mock stack.
    let err = SaError::NetworkRpcDivergence {
        rule_id: 1,
        smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
        primary_view_digest_first8: "aabbccdd".to_owned(),
        secondary_view_digest_first8: "11223344".to_owned(),
        request_id: Uuid::new_v4().to_string(),
    };
    assert_eq!(
        err.wire_code(),
        "network.rpc_divergence",
        "NetworkRpcDivergence wire code must be 'network.rpc_divergence'"
    );
    assert_ne!(
        err.wire_code(),
        "sa.signer_set_diverged",
        "NetworkRpcDivergence must not be confused with SignerSetDiverged in wire output"
    );
}
