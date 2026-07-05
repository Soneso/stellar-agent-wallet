//! Adversarial fixture: weighted-threshold policy identification — multi-match
//! rejection.
//!
//! Scenario: the `ContextRule` lists TWO policy addresses, and BOTH have wasm
//! hashes that match `WEIGHTED_THRESHOLD_POLICY_WASM_HASHES[0]`. Multi-match is
//! ambiguous — the wallet cannot safely determine which policy to read/retune →
//! `WeightedThresholdPolicyIdentificationFailed` (fail-closed, match_count = 2).

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
    KNOWN_WEIGHTED_THRESHOLD_WASM_HASH, SOURCE_G, build_context_rule_scval_xdr,
    build_simulate_response, manager_one_url, policy_sc_address, policy2_sc_address,
    signer_set_n_of_n, tmp_audit_writer, zero_sc_address,
};

// ── Test ──────────────────────────────────────────────────────────────────────

/// Two policy addresses, both with the allowlisted weighted-threshold wasm
/// hash → multi-match → `WeightedThresholdPolicyIdentificationFailed`.
#[tokio::test]
async fn two_allowlisted_policies_returns_identification_failed_multi_match() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    let policy_a = policy_sc_address();
    let policy_b = policy2_sc_address();

    let cr_xdr = build_context_rule_scval_xdr(
        1,
        &signer_set_n_of_n(1),
        &[policy_a.clone(), policy_b.clone()],
    );
    let sim_cr = build_simulate_response(&cr_xdr);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new_two_policies(
            SOURCE_G,
            &policy_a,
            KNOWN_WEIGHTED_THRESHOLD_WASM_HASH,
            &policy_b,
            KNOWN_WEIGHTED_THRESHOLD_WASM_HASH, // both match — multi-match
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
            Err(SaError::WeightedThresholdPolicyIdentificationFailed { rule_id: 1, .. })
        ),
        "two allowlisted policies must return WeightedThresholdPolicyIdentificationFailed; \
         got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "sa.weighted_threshold_policy_identification_failed",
        "wire_code must be 'sa.weighted_threshold_policy_identification_failed'"
    );
}

/// Type-level: verify the `WeightedThresholdPolicyIdentificationFailed`
/// multi-match shape.
#[test]
fn identification_failed_multi_match_wire_code() {
    use stellar_agent_smart_account::signers::types::WasmHashSummary;

    let err = SaError::WeightedThresholdPolicyIdentificationFailed {
        rule_id: 1,
        smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
        observed_wasm_hashes_summary: WasmHashSummary::new(
            2,
            Some([0xe3, 0xd8, 0xcc, 0x5a, 0xb9, 0x66, 0x85, 0x26]),
        )
        .expect("count=2 + Some is valid"),
        request_id: Uuid::new_v4().to_string(),
    };
    assert_eq!(
        err.wire_code(),
        "sa.weighted_threshold_policy_identification_failed"
    );
}
