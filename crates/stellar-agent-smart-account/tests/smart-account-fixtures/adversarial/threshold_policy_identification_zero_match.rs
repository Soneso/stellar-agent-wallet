//! Adversarial fixture: threshold policy identification — zero-match rejection.
//!
//! Scenario: the `ContextRule` lists one policy address, but the policy contract's
//! wasm hash does NOT match any entry in `THRESHOLD_POLICY_WASM_HASHES`. The
//! match count is zero → `ThresholdPolicyIdentificationFailed` (fail-closed).
//!
//! This validates that a policy contract with an unrecognised wasm hash (e.g. an
//! attacker-controlled contract that mimics the threshold-policy interface) is
//! rejected before any threshold read.

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
    SOURCE_G, UNKNOWN_WASM_HASH, ZERO_CONTRACT_REDACTED, build_context_rule_scval_xdr,
    build_simulate_response, manager_one_url, policy_sc_address, signer_set_n_of_n,
    tmp_audit_writer, write_baseline, zero_sc_address,
};

// ── Test ──────────────────────────────────────────────────────────────────────

/// One policy address present but its wasm hash is not in the allowlist →
/// `ThresholdPolicyIdentificationFailed` with zero-match count.
///
/// The attacker provides a contract that implements the threshold-policy interface
/// but was built from an unrecognised binary — the wasm-hash allowlist gate rejects it.
#[tokio::test]
async fn unknown_wasm_hash_returns_identification_failed_zero_match() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    // Write a valid baseline so Step 1 passes.
    let baseline = signer_set_n_of_n(1);
    write_baseline(&audit_writer, 1, ZERO_CONTRACT_REDACTED, &baseline);

    let policy = policy_sc_address();

    // ContextRule has one policy address (the attacker-controlled contract).
    let cr_xdr = build_context_rule_scval_xdr(1, &baseline, std::slice::from_ref(&policy));
    let sim_cr = build_simulate_response(&cr_xdr);

    // The mock serves UNKNOWN_WASM_HASH for the policy contract instance.
    // `identify_threshold_policy` will see this hash, find no allowlist match,
    // and return ThresholdPolicyIdentificationFailed with match_count = 0.
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new_unknown_hash(
            SOURCE_G,
            &policy,
            UNKNOWN_WASM_HASH,
            // Only one simulateTransaction call: fetch_context_rule_primary.
            // After that, getLedgerEntries fetches happen for wasm-hash check.
            // No further simulateTransaction needed (hash mismatch fires before simulate).
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
        "unknown wasm hash must return ThresholdPolicyIdentificationFailed; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "sa.threshold_policy_identification_failed",
        "wire_code must be 'sa.threshold_policy_identification_failed'"
    );
}

/// Type-level: `ThresholdPolicyIdentificationFailed` carries `observed_wasm_hashes_summary.count`.
#[test]
fn identification_failed_zero_match_count_field() {
    use stellar_agent_smart_account::signers::types::WasmHashSummary;

    // count=1, first_first8=Some([...]) — one policy was observed but its hash
    // is not in the allowlist. The `first_first8` carries the first 8 bytes of the
    // observed hash for diagnostics (invariant: count > 0 implies Some).
    let err = SaError::ThresholdPolicyIdentificationFailed {
        rule_id: 1,
        smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
        observed_wasm_hashes_summary: WasmHashSummary::new(
            1,
            Some([0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd]),
        )
        .expect("count=1 + Some is valid"),
        request_id: Uuid::new_v4().to_string(),
    };
    assert_eq!(err.wire_code(), "sa.threshold_policy_identification_failed");
}
