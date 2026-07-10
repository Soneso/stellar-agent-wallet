//! Adversarial fixture: `check_divergence_for_auth_rule_ids` collective budget (#46).
//!
//! Scenario: a write path is called with TWO `auth_rule_ids`, each individually
//! baselined and matching on-chain (no divergence would ever fire). Every RPC
//! response is delayed enough that ONE rule's full `verify_signer_set_against_chain`
//! round-trip consumes most of the manager's configured `timeout`, and a SECOND
//! rule's check needs the same amount again. A per-call-fresh timeout would let
//! both succeed; the collective budget derived once from `self.timeout` and
//! shared across every `auth_rule_id` in the loop must instead cut the second
//! check off using only the REMAINING budget, proving the deadline is collective
//! rather than re-armed per iteration.
//!
//! # Invariant
//!
//! `check_divergence_for_auth_rule_ids` computes ONE `SequentialRpcBudget` from
//! `self.timeout` before the loop and wraps every `auth_rule_id`'s
//! `verify_signer_set_against_chain` call against that SAME deadline.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::signing::{Signer, SoftwareSigningKey};
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::rules::{ContextRuleManager, ContextRuleManagerConfig};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

use super::combined_rpc_responder::{CombinedRpcResponder, SequencedSimulate};
use super::rpc_mock_helpers::{
    KNOWN_WASM_HASH, ZERO_CONTRACT_REDACTED, build_context_rule_scval_xdr, build_simulate_response,
    build_threshold_scval_xdr, manager_two_url, policy_sc_address, signer_set_n_of_n,
    tmp_audit_writer, write_baseline, zero_sc_address,
};

const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";
const RULE_ID_A: u32 = 1;
const RULE_ID_B: u32 = 2;

/// Every RPC round-trip (simulate or getLedgerEntries) is delayed by this much.
/// One `verify_signer_set_against_chain` call needs 4 sequential hops on its
/// critical path (identify_threshold_policy: cr-fetch + wasm-pin-check;
/// then fetch_signer_set primary/secondary in parallel: cr-fetch + threshold-fetch
/// each) — roughly `4 * PER_HOP_DELAY` wall time per rule_id.
const PER_HOP_DELAY: Duration = Duration::from_millis(200);

/// The manager's configured RPC timeout — the SHARED collective-budget total.
/// Comfortably covers one rule_id's ~800ms critical path (with margin) but
/// leaves too little remaining for a second full ~800ms check.
const MANAGER_TIMEOUT: Duration = Duration::from_millis(1200);

/// Wraps any `Respond` implementation and adds a fixed delay to every response,
/// so the mock server's real wall-clock latency drives the collective budget.
struct DelayedResponder<R> {
    inner: R,
    delay: Duration,
}

impl<R: Respond> Respond for DelayedResponder<R> {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.inner.respond(request).set_delay(self.delay)
    }
}

async fn build_manager() -> (
    ContextRuleManager,
    PathBuf,
    tempfile::TempDir,
    MockServer,
    MockServer,
) {
    let (audit_writer, audit_log_path, dir) = tmp_audit_writer();

    // Both rule_ids are baselined with a 2-of-2 signer set that MATCHES the
    // on-chain response below — divergence never fires; the only refusal
    // reachable is the collective budget elapsing.
    let on_chain = signer_set_n_of_n(2);
    write_baseline(&audit_writer, RULE_ID_A, ZERO_CONTRACT_REDACTED, &on_chain);
    write_baseline(&audit_writer, RULE_ID_B, ZERO_CONTRACT_REDACTED, &on_chain);

    let signer = SoftwareSigningKey::new_from_bytes([0x31; 32]);
    let signer_g = signer
        .public_key()
        .await
        .expect("fixture signer public key must derive")
        .to_string();

    let policy = policy_sc_address();
    let cr_xdr = build_context_rule_scval_xdr(RULE_ID_A, &on_chain, std::slice::from_ref(&policy));
    let th_xdr = build_threshold_scval_xdr(2);
    let sim_cr = build_simulate_response(&cr_xdr);
    let sim_th = build_simulate_response(&th_xdr);

    // Primary sees, per rule_id: identify's cr-fetch, fetch_signer_set's
    // cr-fetch, fetch_signer_set's threshold-fetch — [cr, cr, th] x 2 rule_ids.
    let primary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(DelayedResponder {
            inner: CombinedRpcResponder::new(
                &signer_g,
                &policy,
                KNOWN_WASM_HASH,
                SequencedSimulate::new(vec![
                    sim_cr.clone(),
                    sim_cr.clone(),
                    sim_th.clone(),
                    sim_cr.clone(),
                    sim_cr.clone(),
                    sim_th.clone(),
                ]),
            ),
            delay: PER_HOP_DELAY,
        })
        .mount(&primary_server)
        .await;

    // Secondary only runs fetch_signer_set: [cr, th] x 2 rule_ids.
    let secondary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(DelayedResponder {
            inner: CombinedRpcResponder::new(
                &signer_g,
                &policy,
                KNOWN_WASM_HASH,
                SequencedSimulate::new(vec![sim_cr.clone(), sim_th.clone(), sim_cr, sim_th]),
            ),
            delay: PER_HOP_DELAY,
        })
        .mount(&secondary_server)
        .await;

    let signers_manager = Arc::new(manager_two_url(
        &primary_server.uri(),
        &secondary_server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    ));
    let manager = ContextRuleManager::new(
        ContextRuleManagerConfig::new(
            primary_server.uri(),
            NETWORK_PASSPHRASE.to_owned(),
            MANAGER_TIMEOUT,
            CHAIN_ID.to_owned(),
        )
        .with_signers_manager(signers_manager)
        .with_audit_writer(audit_writer),
    )
    .expect("ContextRuleManager::new must succeed");

    (
        manager,
        audit_log_path,
        dir,
        primary_server,
        secondary_server,
    )
}

/// A collective budget derived from `self.timeout` is shared across ALL
/// `auth_rule_ids`: the first rule_id's check consumes most of the budget
/// (well inside it), and the second rule_id's check — which on its own would
/// also fit inside a FRESH `self.timeout` window — is cut off by the
/// REMAINING budget instead, proving the deadline is collective, not
/// re-armed per iteration.
#[tokio::test]
async fn update_valid_until_divergence_check_budget_is_collective_across_auth_rule_ids() {
    let (manager, _audit_log_path, _dir, _primary, _secondary) = build_manager().await;

    let signer = SoftwareSigningKey::new_from_bytes([0x31; 32]);
    let auth_rule_ids = vec![ContextRuleId::new(RULE_ID_A), ContextRuleId::new(RULE_ID_B)];

    let result = manager
        .update_valid_until(
            zero_sc_address(),
            7,
            Some(123_456),
            auth_rule_ids,
            &signer,
            None,
            "req-collective-budget".to_owned(),
        )
        .await;

    let err = result.expect_err(
        "the second auth_rule_id's divergence check must be cut off by the \
         collective budget, not silently complete on a fresh per-call timeout",
    );
    assert!(
        matches!(
            err,
            SaError::DeploymentFailed {
                phase: "simulate",
                ..
            }
        ),
        "expected DeploymentFailed{{phase: \"simulate\"}} (collective budget elapsed), got {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("collective budget") && msg.contains("verify_signer_set_against_chain"),
        "error must name the collective budget and the stage it elapsed during; got: {msg}"
    );
}
