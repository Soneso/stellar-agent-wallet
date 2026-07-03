//! Adversarial fixture: threshold policy identification — multi-match rejection.
//!
//! Scenario: the `ContextRule` lists TWO policy addresses, and BOTH have wasm
//! hashes that match the `THRESHOLD_POLICY_WASM_HASHES` allowlist. Multi-match
//! is ambiguous — the wallet cannot safely determine which policy to use →
//! `ThresholdPolicyIdentificationFailed` (fail-closed, match_count = 2).
//!
//! This validates the single-match requirement: exactly ONE policy must match
//! the allowlist; zero or two-or-more is rejected.

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
    build_simulate_response, manager_one_url, policy_sc_address, policy2_sc_address,
    signer_set_n_of_n, tmp_audit_writer, write_baseline, zero_sc_address,
};

// ── Test ──────────────────────────────────────────────────────────────────────

/// Two policy addresses, both with the allowlisted wasm hash → multi-match →
/// `ThresholdPolicyIdentificationFailed`.
///
/// An on-chain configuration that lists two identical threshold-policy contracts
/// (duplicates, or two upgrades) must be rejected — the wallet cannot safely
/// choose between them without operator intervention.
#[tokio::test]
async fn two_allowlisted_policies_returns_identification_failed_multi_match() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    // Write a valid baseline so Step 1 passes.
    let baseline = signer_set_n_of_n(1);
    write_baseline(&audit_writer, 1, ZERO_CONTRACT_REDACTED, &baseline);

    let policy_a = policy_sc_address();
    let policy_b = policy2_sc_address();

    // ContextRule lists BOTH policy_a and policy_b.
    let cr_xdr = build_context_rule_scval_xdr(1, &baseline, &[policy_a.clone(), policy_b.clone()]);
    let sim_cr = build_simulate_response(&cr_xdr);

    // Mock: both policy_a and policy_b return KNOWN_WASM_HASH (both in allowlist).
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new_two_policies(
            SOURCE_G,
            &policy_a,
            KNOWN_WASM_HASH,
            &policy_b,
            KNOWN_WASM_HASH, // both match — multi-match
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
            Err(SaError::ThresholdPolicyIdentificationFailed { rule_id: 1, .. })
        ),
        "two allowlisted policies must return ThresholdPolicyIdentificationFailed; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "sa.threshold_policy_identification_failed",
        "wire_code must be 'sa.threshold_policy_identification_failed'"
    );
}

/// Type-level: verify the `ThresholdPolicyIdentificationFailed` multi-match shape.
///
/// The `observed_wasm_hashes_summary.count` carries the number of observed policies
/// (not the number of matches), allowing operators to diagnose the configuration.
#[test]
fn identification_failed_multi_match_wire_code() {
    use stellar_agent_smart_account::signers::types::WasmHashSummary;

    // count=2 (two policies observed), first_first8=Some([...]) from the first hash.
    let err = SaError::ThresholdPolicyIdentificationFailed {
        rule_id: 1,
        smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
        observed_wasm_hashes_summary: WasmHashSummary::new(
            2,
            Some([0x43, 0xc4, 0x87, 0x90, 0xb8, 0x3f, 0xbe, 0x28]),
        )
        .expect("count=2 + Some is valid"),
        request_id: Uuid::new_v4().to_string(),
    };
    assert_eq!(err.wire_code(), "sa.threshold_policy_identification_failed");
}
