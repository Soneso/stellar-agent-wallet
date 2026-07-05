//! Adversarial fixture: weighted-threshold policy identification — RPC hash
//! disagreement.
//!
//! Scenario: primary and secondary RPCs return different wasm hashes for the
//! same policy contract during `identify_weighted_threshold_policy`. Both
//! hashes are individually plausible allowlist candidates, but the two RPCs
//! disagree on which hash is current → `NetworkRpcDivergence`.
//!
//! This validates that the two-RPC agreement check in
//! `identify_weighted_threshold_policy` fires before the single-entry
//! allowlist match — a compromised or lagging RPC cannot silently substitute
//! a policy contract identity.

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
    KNOWN_WEIGHTED_THRESHOLD_WASM_HASH, SOURCE_G, UNKNOWN_WASM_HASH, build_context_rule_scval_xdr,
    build_simulate_response, manager_two_url, policy_sc_address, signer_set_n_of_n,
    tmp_audit_writer, zero_sc_address,
};

// ── Test ──────────────────────────────────────────────────────────────────────

/// Primary returns `KNOWN_WEIGHTED_THRESHOLD_WASM_HASH` for the policy;
/// secondary returns `UNKNOWN_WASM_HASH`.
#[tokio::test]
async fn policy_hash_rpc_disagreement_returns_rpc_divergence() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    let policy = policy_sc_address();

    let cr_xdr =
        build_context_rule_scval_xdr(1, &signer_set_n_of_n(1), std::slice::from_ref(&policy));
    let sim_cr = build_simulate_response(&cr_xdr);

    let primary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new(
            SOURCE_G,
            &policy,
            KNOWN_WEIGHTED_THRESHOLD_WASM_HASH,
            SequencedSimulate::new(vec![sim_cr.clone()]),
        ))
        .mount(&primary_server)
        .await;

    let secondary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new_unknown_hash(
            SOURCE_G,
            &policy,
            UNKNOWN_WASM_HASH,
            SequencedSimulate::new(vec![sim_cr.clone()]),
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
            Err(SaError::NetworkRpcDivergence { rule_id: 1, .. })
        ),
        "policy hash disagreement must return NetworkRpcDivergence; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "network.rpc_divergence",
        "wire_code must be 'network.rpc_divergence'"
    );
}

/// Type-level: `NetworkRpcDivergence` from weighted-threshold-policy
/// identification carries the same wire code as `NetworkRpcDivergence` from
/// any other consumer.
#[test]
fn network_rpc_divergence_wire_code_is_consistent() {
    let policy_id_divergence = SaError::NetworkRpcDivergence {
        rule_id: 1,
        smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
        primary_view_digest_first8: "aabb0011".to_owned(),
        secondary_view_digest_first8: "ccdd9922".to_owned(),
        request_id: Uuid::new_v4().to_string(),
    };
    assert_eq!(policy_id_divergence.wire_code(), "network.rpc_divergence");
}
