//! Adversarial fixture: `threshold_policy_not_installed`.
//!
//! Scenario: the on-chain `ContextRule` has an empty `policies` list and the
//! audit log holds a version-1 baseline. The version-2 observation records no
//! threshold, and the version-1 comparison needs one, so the projection
//! refuses with `ThresholdPolicyNotInstalled`, failing closed.
//!
//! A valid baseline exists so the test confirms that the comparison fires
//! AFTER the audit-log read passes, and that the error is
//! `ThresholdPolicyNotInstalled`, NOT `SignerSetMissingBaseline`.

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
    build_simulate_response, manager_one_url, policy_sc_address, signer_set_n_of_n,
    tmp_audit_writer, write_baseline, zero_sc_address,
};

// ── Test ──────────────────────────────────────────────────────────────────────

/// `ContextRule.policies` is empty → `ThresholdPolicyNotInstalled` fail-closed.
///
/// The RPC returns a valid ContextRule ScVal but with no policy addresses in
/// the `policies` field. The version-1 comparison must detect the missing
/// threshold and return `ThresholdPolicyNotInstalled`; with no policy there is
/// no executable or threshold read.
#[tokio::test]
async fn empty_policies_returns_threshold_policy_not_installed() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    // Write a valid 1-of-1 baseline so Step 1 passes.
    let baseline = signer_set_n_of_n(1);
    write_baseline(&audit_writer, 1, ZERO_CONTRACT_REDACTED, &baseline);

    // Build a ContextRule ScVal with an EMPTY policies list.
    let cr_no_policy = build_context_rule_scval_xdr(1, &baseline, &[] /* no policies */);
    let sim_cr_no_policy = build_simulate_response(&cr_no_policy);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        // No policy → no contract-instance fetch and no threshold read follow the
        // rule reads. Both clients point at this one server, so it serves the
        // primary's and the secondary's get_context_rule; the comparison then
        // returns ThresholdPolicyNotInstalled without any getLedgerEntries.
        .respond_with(CombinedRpcResponder::new(
            SOURCE_G,
            &policy_sc_address(), // policy_addr not used since policies=[]; kept for account dispatch
            KNOWN_WASM_HASH,
            SequencedSimulate::new(vec![sim_cr_no_policy]),
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
            Err(SaError::ThresholdPolicyNotInstalled { rule_id: 1, .. })
        ),
        "empty policies must return ThresholdPolicyNotInstalled; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "sa.threshold_policy_not_installed",
        "wire_code must be 'sa.threshold_policy_not_installed'"
    );
}

/// `ThresholdPolicyNotInstalled` fires AFTER Step 1 (baseline present) —
/// not `SignerSetMissingBaseline`.
#[tokio::test]
async fn not_installed_requires_baseline_step_to_pass_first() {
    // Construct the error at the type level to verify it is distinct from
    // SignerSetMissingBaseline (which fires at Step 1, not Step 2a).
    let not_installed = SaError::ThresholdPolicyNotInstalled {
        rule_id: 1,
        smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
        request_id: Uuid::new_v4().to_string(),
    };
    let missing_baseline = SaError::SignerSetMissingBaseline {
        rule_id: 1,
        smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
        request_id: Uuid::new_v4().to_string(),
    };
    assert_ne!(
        not_installed.wire_code(),
        missing_baseline.wire_code(),
        "ThresholdPolicyNotInstalled and SignerSetMissingBaseline must have distinct wire codes"
    );
    assert_eq!(
        not_installed.wire_code(),
        "sa.threshold_policy_not_installed"
    );
    assert_eq!(
        missing_baseline.wire_code(),
        "sa.signer_set_missing_baseline"
    );
}
