//! Adversarial fixture: signer-set divergence suppression via compromised primary RPC.
//!
//! Scenario: primary RPC returns a stale signer set (1-of-1), but secondary
//! returns the current signer set (2-of-2). The two-RPC agreement check
//! detects the divergence and returns `NetworkRpcDivergence` — even though the
//! primary view happens to match the audit-log baseline.
//!
//! This validates that a compromised or lagging primary RPC cannot suppress a
//! `SignerSetDiverged` error by returning a stale view that matches the baseline:
//! the secondary RPC disagrees, so `NetworkRpcDivergence` fires first.

use std::sync::Arc;

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

/// Primary RPC is stale (returns 1-of-1 matching baseline); secondary is current (2-of-2).
///
/// `verify_signer_set_against_chain` must return `NetworkRpcDivergence`, NOT
/// `SignerSetDiverged`. The two-RPC agreement check prevents a compromised
/// primary from suppressing the divergence signal.
#[tokio::test]
async fn stale_primary_current_secondary_returns_rpc_divergence() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    // Write a 1-of-1 baseline (matches the stale primary view — this is the "suppression" attempt).
    let baseline = signer_set_n_of_n(1);
    write_baseline(&audit_writer, 1, ZERO_CONTRACT_REDACTED, &baseline);

    let policy = policy_sc_address();

    // Primary: stale 1-of-1 (matches baseline, but is wrong).
    let cr_1of1 =
        build_context_rule_scval_xdr(1, &signer_set_n_of_n(1), std::slice::from_ref(&policy));
    let th_1 = build_threshold_scval_xdr(1);
    let sim_cr_1 = build_simulate_response(&cr_1of1);
    let sim_th_1 = build_simulate_response(&th_1);

    // Secondary: current 2-of-2 (the real on-chain state).
    let cr_2of2 =
        build_context_rule_scval_xdr(1, &signer_set_n_of_n(2), std::slice::from_ref(&policy));
    let th_2 = build_threshold_scval_xdr(2);
    let sim_cr_2 = build_simulate_response(&cr_2of2);
    let sim_th_2 = build_simulate_response(&th_2);

    // Primary server: serves stale 1-of-1.
    // Primary receives:
    //   1. identify_threshold_policy: get_context_rule (primary only)
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

    // Secondary server: serves current 2-of-2.
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

    // The stale primary cannot suppress the divergence — secondary disagrees.
    assert!(
        matches!(
            result,
            Err(SaError::NetworkRpcDivergence { rule_id: 1, .. })
        ),
        "stale primary matching baseline must still return NetworkRpcDivergence; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "network.rpc_divergence",
        "wire_code must be 'network.rpc_divergence'"
    );
}
