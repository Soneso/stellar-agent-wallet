//! Adversarial fixture: signer-set divergence via out-of-band key rotation.
//!
//! Scenario: both primary and secondary RPC endpoints agree on the current on-chain
//! signer set (2 signers, 2-of-2), but the audit-log baseline has only 1 signer
//! (recorded before an out-of-band key rotation happened).
//!
//! Expected: `verify_signer_set_against_chain` returns `SaError::SignerSetDiverged`
//! (not `NetworkRpcDivergence` — the two RPCs agree, so the divergence is detected
//! at the expected-vs-observed comparison step).

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

/// Both RPCs report 2-of-2 on-chain; baseline has 1-of-1 (stale after out-of-band add).
///
/// `verify_signer_set_against_chain` must return `SaError::SignerSetDiverged`
/// with `wire_code = "sa.signer_set_diverged"`.
///
/// Uses separate primary and secondary mock servers so that the interleaved
/// `tokio::join!` calls within `verify_signer_set_against_chain` do not race on
/// a shared `SequencedSimulate` counter.  Each server sees its own ordered
/// sequence: get_context_rule (Step 2a) then get_context_rule + get_threshold
/// (Step 2b).
#[tokio::test]
async fn out_of_band_rotation_returns_signer_set_diverged() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    // Write a 1-of-1 baseline (stale — an out-of-band add happened since).
    let baseline = signer_set_n_of_n(1);
    write_baseline(&audit_writer, 1, ZERO_CONTRACT_REDACTED, &baseline);

    // Both RPCs agree on 2-of-2.
    let policy = policy_sc_address();
    let on_chain = signer_set_n_of_n(2);
    let cr_xdr = build_context_rule_scval_xdr(1, &on_chain, std::slice::from_ref(&policy));
    let th_xdr = build_threshold_scval_xdr(2);
    let sim_cr = build_simulate_response(&cr_xdr);
    let sim_th = build_simulate_response(&th_xdr);

    // Primary server: sees 3 simulate calls in sequence:
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
            SequencedSimulate::new(vec![sim_cr.clone(), sim_cr.clone(), sim_th.clone()]),
        ))
        .mount(&primary_server)
        .await;

    // Secondary server: sees 2 simulate calls:
    //   1. fetch_signer_set(secondary): get_context_rule
    //   2. fetch_signer_set(secondary): get_threshold
    // Also serves the two-RPC getLedgerEntries for identify_threshold_policy.
    let secondary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new(
            SOURCE_G,
            &policy,
            KNOWN_WASM_HASH,
            SequencedSimulate::new(vec![sim_cr.clone(), sim_th.clone()]),
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
        matches!(result, Err(SaError::SignerSetDiverged { rule_id: 1, .. })),
        "stale baseline with both RPCs agreeing must return SignerSetDiverged; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "sa.signer_set_diverged",
        "wire_code must be 'sa.signer_set_diverged'"
    );
}
