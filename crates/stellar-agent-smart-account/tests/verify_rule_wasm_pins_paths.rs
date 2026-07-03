//! Mock-driven path tests for `ContextRuleManager::verify_rule_wasm_pins`.
//!
//! Both tests are `#[serial]`. The async RPC client built by `ContextRuleManager`
//! resolves system proxies through a process-global cache (reqwest `SYS_PROXIES`),
//! and the HTTP-proxy env vars it reads are process-global state. Running the two
//! `#[tokio::test]` cases concurrently on the harness's worker threads lets that
//! shared state race, which intermittently misroutes a simulate response and flips
//! the expected `PinStatus` (observed on CI under full-workspace load: a `NoContracts`
//! rule resolved to `NoPin`). Serialising both cases removes the intra-binary
//! concurrency. Same discipline as `list_rules_no_indexer_call_mock.rs` and
//! `feedback_global_static_test_serialization`.

use std::sync::Arc;
use std::time::Duration;

use serial_test::serial;

use stellar_agent_smart_account::managers::rules::{
    ContextRuleManager, ContextRuleManagerConfig, PinStatus,
};
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

#[path = "smart-account-fixtures/adversarial/combined_rpc_responder.rs"]
mod combined_rpc_responder;
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "shared adversarial fixture helpers assert setup invariants"
)]
#[path = "smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
mod rpc_mock_helpers;

use combined_rpc_responder::{CombinedRpcResponder, SequencedSimulate};
use rpc_mock_helpers::{
    SOURCE_G, build_context_rule_scval_xdr, build_simulate_response, manager_two_url,
    policy_sc_address, signer_set_n_of_n, tmp_audit_writer, zero_sc_address,
};

const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";

#[allow(
    clippy::expect_used,
    reason = "test helper asserts fixture construction invariants"
)]
async fn manager_with_rule(
    rule_id: u32,
    policies: Vec<stellar_xdr::ScAddress>,
) -> (ContextRuleManager, tempfile::TempDir) {
    let (audit_writer, audit_log_path, tmp_dir) = tmp_audit_writer();
    let signers = signer_set_n_of_n(0);
    let rule_xdr = build_context_rule_scval_xdr(rule_id, &signers, &policies);
    let simulate = SequencedSimulate::new(vec![build_simulate_response(&rule_xdr)]);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new_no_policies(SOURCE_G, simulate))
        .mount(&server)
        .await;

    let signers_manager = Arc::new(manager_two_url(
        &server.uri(),
        &server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path,
    ));

    let manager = ContextRuleManager::new(
        ContextRuleManagerConfig::new(
            server.uri(),
            NETWORK_PASSPHRASE.to_owned(),
            Duration::from_secs(5),
            CHAIN_ID.to_owned(),
        )
        .with_signers_manager(signers_manager)
        .with_audit_writer(audit_writer),
    )
    .expect("ContextRuleManager::new must succeed");
    // Return `tmp_dir` so the caller keeps it in scope for the test's lifetime;
    // when the test scope ends, `TempDir::Drop` cleans the directory naturally
    // (avoids the previous `std::mem::forget` leak).
    (manager, tmp_dir)
}

#[tokio::test]
#[serial]
#[allow(clippy::expect_used, reason = "test asserts successful fixture path")]
async fn verify_rule_wasm_pins_returns_no_contracts_when_rule_has_no_external_contracts() {
    let rule_id = 31;
    let (manager, _tmp_dir) = manager_with_rule(rule_id, vec![]).await;

    let result = manager
        .verify_rule_wasm_pins(zero_sc_address(), rule_id, SOURCE_G, "req-no-contracts")
        .await
        .expect("verify_rule_wasm_pins must return a result");

    assert_eq!(result.verifier_pin_status, PinStatus::NoContracts);
    assert_eq!(result.policy_pin_status, PinStatus::NoContracts);
    assert!(result.pinned_verifier_first8.is_empty());
    assert!(result.pinned_policy_first8.is_empty());
}

#[tokio::test]
#[serial]
#[allow(clippy::expect_used, reason = "test asserts successful fixture path")]
async fn verify_rule_wasm_pins_returns_no_pin_when_contracts_exist_without_audit_pin() {
    let rule_id = 32;
    let (manager, _tmp_dir) = manager_with_rule(rule_id, vec![policy_sc_address()]).await;

    let result = manager
        .verify_rule_wasm_pins(zero_sc_address(), rule_id, SOURCE_G, "req-no-pin")
        .await
        .expect("verify_rule_wasm_pins must return a result");

    assert_eq!(result.verifier_pin_status, PinStatus::NoPin);
    assert_eq!(result.policy_pin_status, PinStatus::NoPin);
    assert!(result.pinned_verifier_first8.is_empty());
    assert!(result.pinned_policy_first8.is_empty());
}
