//! Adversarial fixture: threshold policy identification — zero-match rejection.
//!
//! Scenario: the `ContextRule` lists one policy address, but the policy contract's
//! wasm hash does NOT match any entry in `THRESHOLD_POLICY_WASM_HASHES`, and the
//! audit log holds a version-1 baseline. The version-2 observation records no
//! threshold; the version-1 comparison needs one, and the rule's policies
//! include none that is a simple-threshold policy →
//! `ThresholdPolicyIdentificationFailed` (fail closed).
//!
//! This validates that a policy contract with an unrecognised wasm hash (e.g. an
//! attacker-controlled contract that mimics the threshold-policy interface) is
//! never read as the threshold policy: no threshold read happens.

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
    SOURCE_G, UNKNOWN_WASM_HASH, ZERO_CONTRACT_REDACTED, assert_refusal_holds_no_marker,
    build_context_rule_scval_xdr, build_simulate_response, manager_one_url, mcp_error_envelope,
    policy_sc_address, signer_set_n_of_n, tmp_audit_writer, wallet_traced, write_baseline,
    zero_sc_address,
};

// ── Test ──────────────────────────────────────────────────────────────────────

/// One policy address present but its wasm hash is not in the allowlist →
/// `ThresholdPolicyIdentificationFailed` with the attached-policy count.
///
/// The attacker provides a contract that implements the threshold-policy interface
/// but was built from an unrecognised binary — the wasm-hash allowlist gate rejects it.
/// The refusal states the check and the count; the observed hash, which
/// failed the allowlist, appears in no form in the error's Display, Debug
/// and source chain, its serialized form, the MCP error envelope or the
/// wallet's logs, which hold the observation event.
#[test]
fn unknown_wasm_hash_returns_identification_failed_zero_match() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    // Write a valid baseline so Step 1 passes.
    let baseline = signer_set_n_of_n(1);
    write_baseline(&audit_writer, 1, ZERO_CONTRACT_REDACTED, &baseline);

    let policy = policy_sc_address();

    // ContextRule has one policy address (the attacker-controlled contract).
    let cr_xdr = build_context_rule_scval_xdr(1, &baseline, std::slice::from_ref(&policy));
    let sim_cr = build_simulate_response(&cr_xdr);

    let (result, logs) = wallet_traced(async move {
        // The mock serves UNKNOWN_WASM_HASH for the policy contract instance.
        // The observation finds no allowlist match and records no threshold;
        // the version-1 comparison returns ThresholdPolicyIdentificationFailed.
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(CombinedRpcResponder::new_unknown_hash(
                SOURCE_G,
                &policy,
                UNKNOWN_WASM_HASH,
                // Only get_context_rule simulations (one per endpoint, both on
                // this server); the policy's instance read follows, and no
                // threshold read is made for a policy that is not allowlisted.
                SequencedSimulate::new(vec![sim_cr]),
            ))
            .mount(&mock_server)
            .await;

        let manager = manager_one_url(
            &mock_server.uri(),
            Arc::clone(&audit_writer),
            audit_log_path,
        );

        manager
            .verify_signer_set_against_chain(
                zero_sc_address(),
                1,
                Some(SOURCE_G),
                "req-zero-match".to_owned(),
            )
            .await
    });

    let err = match result {
        Err(
            err @ SaError::ThresholdPolicyIdentificationFailed {
                rule_id: 1,
                observed_policy_count: 1,
                ..
            },
        ) => err,
        other => panic!(
            "unknown wasm hash must return ThresholdPolicyIdentificationFailed with one \
             attached policy; got: {other:?}"
        ),
    };
    assert_eq!(
        err.wire_code(),
        "sa.threshold_policy_identification_failed",
        "wire_code must be 'sa.threshold_policy_identification_failed'"
    );
    assert_eq!(
        err.to_string(),
        "threshold-policy identification failed on rule 1: rule must identify exactly one \
         supported threshold policy (attached policies: 1)"
    );
    assert!(
        logs.contains("observe_contract: observed contract executable"),
        "{logs}"
    );
    assert!(
        mcp_error_envelope(&err).contains("\"sa.threshold_policy_identification_failed\""),
        "the MCP envelope carries the wire code"
    );
    let observed_full = hex::encode(UNKNOWN_WASM_HASH);
    let observed_first8 = hex::encode(&UNKNOWN_WASM_HASH[..8]);
    assert_refusal_holds_no_marker(&err, &logs, &[&observed_full, &observed_first8], &["wasm"]);
}

/// Type-level: `ThresholdPolicyIdentificationFailed` carries the number of
/// attached policies as `observed_policy_count`.
#[test]
fn identification_failed_zero_match_count_field() {
    let err = SaError::ThresholdPolicyIdentificationFailed {
        rule_id: 1,
        smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
        observed_policy_count: 1,
        request_id: Uuid::new_v4().to_string(),
    };
    assert_eq!(err.wire_code(), "sa.threshold_policy_identification_failed");
    let value = serde_json::to_value(&err).unwrap();
    assert_eq!(value["context"]["observed_policy_count"], 1);
}
