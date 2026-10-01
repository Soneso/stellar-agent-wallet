//! Adversarial fixture: a rule holding a signer the wallet cannot decode.
//!
//! Scenario: the primary RPC serves a context rule with two decodable
//! `Delegated` signers and a third signer whose `Signer` tag is unknown. Both
//! RPCs would agree on it, and the audit log holds no baseline for the rule.
//!
//! Expected: `list_signers` refuses with `sa.deployment_failed` naming the
//! undecodable signer's index. The refusal comes out of the signer-set
//! observation's rule reads, which run on both endpoints before any other
//! read, so each endpoint sees one `get_context_rule` simulation and nothing
//! more. No `SaSignerSetBaselinedV2` (or version 1) row is written for the two
//! signers the wallet can read, and no `SaSignerSetDiverged` row either.
//!
//! # Invariant
//!
//! An observed signer set describes every signer the rule holds; a signer the
//! wallet cannot represent refuses the observation.

use std::sync::Arc;

use stellar_agent_smart_account::error::SaError;
use stellar_xdr::ScAddress;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::combined_rpc_responder::{CombinedRpcResponder, SequencedSimulate};
use super::rpc_mock_helpers::{
    KNOWN_WASM_HASH, SOURCE_G, append_signer_to_rule_xdr, build_context_rule_scval_xdr,
    build_simulate_response, build_threshold_scval_xdr, manager_two_url, policy_sc_address,
    signer_set_n_of_n, tmp_audit_writer, unknown_tag_signer_scval, zero_sc_address,
};

/// Builds the `ContextRule` XDR for rule `1`: the two `Delegated` signers of
/// `signer_set_n_of_n(2)` (ids `0` and `1`) plus a signer with id `2` whose
/// tag is `Future`, a variant the wallet does not know.
fn rule_with_an_unknown_third_signer_xdr(policy: &ScAddress) -> String {
    append_signer_to_rule_xdr(
        &build_context_rule_scval_xdr(1, &signer_set_n_of_n(2), std::slice::from_ref(policy)),
        2,
        &unknown_tag_signer_scval(),
    )
}

/// Number of `simulateTransaction` requests `server` received.
async fn simulate_count(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("request recording is on")
        .iter()
        .filter(|request| {
            serde_json::from_slice::<serde_json::Value>(&request.body)
                .map(|body| body["method"] == "simulateTransaction")
                .unwrap_or(false)
        })
        .count()
}

/// `list_signers` on a fresh log refuses a rule with an undecodable third
/// signer and writes neither a baseline nor a divergence row.
///
/// Both servers serve the full observation sequence (the rule, then the
/// threshold), so the refusal is the decoder's and not a missing response.
#[tokio::test]
async fn list_signers_refuses_a_rule_with_an_undecodable_signer() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    let policy = policy_sc_address();
    let sim_cr = build_simulate_response(&rule_with_an_unknown_third_signer_xdr(&policy));
    let sim_th = build_simulate_response(&build_threshold_scval_xdr(2));

    let primary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new(
            SOURCE_G,
            &policy,
            KNOWN_WASM_HASH,
            SequencedSimulate::new(vec![sim_cr.clone(), sim_th.clone()]),
        ))
        .mount(&primary_server)
        .await;

    let secondary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new(
            SOURCE_G,
            &policy,
            KNOWN_WASM_HASH,
            SequencedSimulate::new(vec![sim_cr, sim_th]),
        ))
        .mount(&secondary_server)
        .await;

    let manager = manager_two_url(
        &primary_server.uri(),
        &secondary_server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );

    let result = manager
        .list_signers(
            zero_sc_address(),
            1,
            Some(SOURCE_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    let audit_log = std::fs::read_to_string(&audit_log_path).unwrap_or_default();
    let signer_set_rows: Vec<&str> = audit_log
        .lines()
        .filter(|line| {
            serde_json::from_str::<serde_json::Value>(line).is_ok_and(|row| {
                row["kind"] == "sa_signer_set_baselined"
                    || row["kind"] == "sa_signer_set_baselined_v2"
                    || row["kind"] == "sa_signer_set_diverged"
            })
        })
        .collect();
    assert!(
        signer_set_rows.is_empty(),
        "no baseline or divergence row may be written for a partly decoded rule: \
         {signer_set_rows:?}"
    );

    let err = match result {
        Err(err) => err,
        Ok(observed) => panic!("the rule must be refused; observed {observed:?}"),
    };
    assert_eq!(err.wire_code(), "sa.deployment_failed", "got: {err:?}");
    let SaError::DeploymentFailed {
        phase,
        redacted_reason,
    } = &err
    else {
        panic!("expected DeploymentFailed, got {err:?}");
    };
    assert_eq!(*phase, "simulate");
    assert_eq!(
        redacted_reason,
        "get_context_rule: signer at index 2 (id 2) is not a recognised Signer: \
         unknown signer tag \"Future\""
    );

    assert_eq!(
        simulate_count(&primary_server).await,
        1,
        "the refusal comes from the primary's rule read; no threshold read follows"
    );
    assert_eq!(
        simulate_count(&secondary_server).await,
        1,
        "the secondary reads the rule once, concurrently with the primary, and \
         nothing more"
    );
}
