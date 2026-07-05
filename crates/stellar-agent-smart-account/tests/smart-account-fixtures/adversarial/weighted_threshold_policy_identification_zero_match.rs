//! Adversarial fixture: weighted-threshold policy identification — zero-match
//! rejection.
//!
//! Scenario: the `ContextRule` lists one policy address, but the policy
//! contract's wasm hash does NOT match `WEIGHTED_THRESHOLD_POLICY_WASM_HASHES[0]`
//! (the single-entry allowlist). The match count is zero →
//! `WeightedThresholdNotInstalled` (fail-closed).
//!
//! This validates that a policy contract with an unrecognised wasm hash (e.g. an
//! attacker-controlled contract that mimics the weighted-threshold-policy
//! interface, or an unrelated policy such as the simple-threshold policy) is
//! rejected before any `get_threshold` / `get_signer_weights` read.

use std::sync::Arc;

use stellar_agent_smart_account::error::SaError;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::combined_rpc_responder::{CombinedRpcResponder, SequencedSimulate};
use super::rpc_mock_helpers::{
    SOURCE_G, UNKNOWN_WASM_HASH, build_context_rule_scval_xdr, build_simulate_response,
    manager_one_url, policy_sc_address, signer_set_n_of_n, tmp_audit_writer, zero_sc_address,
};

// ── Test ──────────────────────────────────────────────────────────────────────

/// One policy address present but its wasm hash is not in the allowlist →
/// `WeightedThresholdNotInstalled` (zero-match, fail-closed).
#[tokio::test]
async fn unknown_wasm_hash_returns_weighted_threshold_not_installed() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    let policy = policy_sc_address();

    let cr_xdr =
        build_context_rule_scval_xdr(1, &signer_set_n_of_n(1), std::slice::from_ref(&policy));
    let sim_cr = build_simulate_response(&cr_xdr);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new_unknown_hash(
            SOURCE_G,
            &policy,
            UNKNOWN_WASM_HASH,
            SequencedSimulate::new(vec![sim_cr]),
        ))
        .mount(&mock_server)
        .await;

    let manager = manager_one_url(
        &mock_server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path,
    );

    let result = manager
        .identify_weighted_threshold_policy(
            zero_sc_address(),
            1,
            Some(SOURCE_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SaError::WeightedThresholdNotInstalled { rule_id: 1, .. })
        ),
        "unknown wasm hash must return WeightedThresholdNotInstalled; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "sa.weighted_threshold_not_installed",
        "wire_code must be 'sa.weighted_threshold_not_installed'"
    );
}

/// An empty `policies` list also returns `WeightedThresholdNotInstalled` —
/// there is nothing to check, and the operator action is identical to the
/// zero-match case.
#[tokio::test]
async fn empty_policies_list_returns_weighted_threshold_not_installed() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    let cr_xdr = build_context_rule_scval_xdr(1, &signer_set_n_of_n(1), &[]);
    let sim_cr = build_simulate_response(&cr_xdr);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new_no_policies(
            SOURCE_G,
            SequencedSimulate::new(vec![sim_cr]),
        ))
        .mount(&mock_server)
        .await;

    let manager = manager_one_url(
        &mock_server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path,
    );

    let result = manager
        .identify_weighted_threshold_policy(
            zero_sc_address(),
            1,
            Some(SOURCE_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SaError::WeightedThresholdNotInstalled { rule_id: 1, .. })
        ),
        "empty policies list must return WeightedThresholdNotInstalled; got: {result:?}"
    );
}
