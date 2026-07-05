//! Mock-substrate unit tests for `ContextRuleManager::simulate_install_rule`
//! (Package D, GH issue #8 — the propose-time simulation seam for
//! agent-proposed context rules).
//!
//! # Coverage map
//!
//! | Test | Mechanism | Coverage |
//! |------|-----------|----------|
//! | [`success_shape_returns_pin_result_and_latest_ledger`] | wiremock | happy path: `Ok(SimulateInstallRuleOutput)` with `latest_ledger` from the mock response and an empty (skipped) `pin_result` when `signers_manager` is `None` |
//! | [`simulate_error_propagates_as_deployment_failed`] | wiremock | a `simulateTransaction` error response propagates as `SaError::DeploymentFailed { phase: "simulate" }` |
//! | [`does_not_modify_install_rule_path_no_extra_simulate_calls`] | wiremock | exactly ONE `simulateTransaction` call — no signing/submission side-effects |
//!
//! # Gating
//!
//! No feature flags required; compiles under default `cargo test` via a
//! wiremock HTTP server, mirroring `list_active_context_rules_mock.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; adversarial fixtures assert invariants via panic-on-failure"
)]

use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRuleSignerInput,
    RuleContext, parse_g_strkey_to_signer_address,
};
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

#[path = "smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
mod rpc_mock_helpers;

use rpc_mock_helpers::{SOURCE_G, SorobanRpcDispatcher, build_ledger_entries_account};

const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";

fn manager_for_server(server: &MockServer) -> ContextRuleManager {
    let config = ContextRuleManagerConfig::new(
        server.uri(),
        NETWORK_PASSPHRASE.to_owned(),
        std::time::Duration::from_secs(5),
        CHAIN_ID.to_owned(),
    );
    // No `.with_signers_manager(...)`: exercises the documented test-only
    // escape hatch (pin check skipped with a `warn!` log), matching
    // `list_active_context_rules_mock.rs::manager_for_server`.
    ContextRuleManager::new(config).expect("ContextRuleManager::new must succeed")
}

fn simple_rule_definition() -> ContextRuleDefinition {
    let signer_address = parse_g_strkey_to_signer_address(SOURCE_G).expect("valid G-strkey");
    ContextRuleDefinition::new(
        RuleContext::Default,
        "spend-daily".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_address,
        }],
        vec![],
    )
}

/// Builds a `simulateTransaction` JSON-RPC result body — mirrors
/// `rpc_mock_helpers::build_simulate_response`, duplicated here only because
/// that helper is `pub(crate)`-scoped-by-convention to the adversarial
/// fixture directory's own call sites; the shape is identical.
fn simulate_ok_response(return_xdr: &str, latest_ledger: u64) -> serde_json::Value {
    serde_json::json!({
        "transactionData": "AAAAAAAAAAIAAAAGAAAAAcwD/nT9D7Dc2LxRdab+2vEUF8B+XoN7mQW21oxPT8ALAAAAFAAAAAEAAAAHy8vNUZ8vyZ2ybPHW0XbSrRtP7gEWsJ6zDzcfY9P8z88AAAABAAAABgAAAAHMA/50/Q+w3Ni8UXWm/trxFBfAfl6De5kFttaMT0/ACwAAABAAAAABAAAAAgAAAA8AAAAHQ291bnRlcgAAAAASAAAAAAAAAAAg4dbAxsGAGICfBG3iT2cKGYQ6hK4sJWzZ6or1C5v6GAAAAAEAHfKyAAAFiAAAAIgAAAAAAAAAAw==",
        "minResourceFee": "1000",
        "results": [
            {
                "auth": [],
                "xdr": return_xdr
            }
        ],
        "latestLedger": latest_ledger
    })
}

fn simulate_error_response(error_msg: &str) -> serde_json::Value {
    serde_json::json!({
        "error": error_msg,
        "latestLedger": 1000
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Success shape
// ─────────────────────────────────────────────────────────────────────────────

/// `simulate_install_rule` returns `Ok(SimulateInstallRuleOutput)` carrying
/// the RPC-observed `latest_ledger` and an empty `pin_result` (the
/// `signers_manager = None` escape hatch skips the pin check).
#[tokio::test]
async fn success_shape_returns_pin_result_and_latest_ledger() {
    use stellar_xdr::{Limits, ScVal, WriteXdr};

    use stellar_xdr::{ContractId, Hash, ScAddress};

    let server = MockServer::start().await;
    let smart_account = ScAddress::Contract(ContractId(Hash([0x42u8; 32])));

    let ledger_resp = build_ledger_entries_account(SOURCE_G);
    let return_xdr = ScVal::U32(7)
        .to_xdr_base64(Limits::none())
        .expect("ScVal::U32 must encode");
    let simulate_resp = simulate_ok_response(&return_xdr, 12_345);

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(ledger_resp, simulate_resp))
        .mount(&server)
        .await;

    let manager = manager_for_server(&server);
    let output = manager
        .simulate_install_rule(
            smart_account,
            simple_rule_definition(),
            SOURCE_G,
            false,
            false,
            "req-simulate-success".to_owned(),
        )
        .await
        .expect("simulate_install_rule must succeed against a well-formed mock");

    assert_eq!(
        output.latest_ledger, 12_345,
        "latest_ledger must come from the mocked simulateTransaction response"
    );
    assert!(
        output.pin_result.pinned_verifier_wasm_hashes.is_empty(),
        "no External signers in the fixture → no pinned verifiers"
    );
    assert!(
        output.pin_result.pinned_policy_wasm_hashes.is_empty(),
        "no policies in the fixture → no pinned policies"
    );
    assert!(!output.pin_result.mutable_override);
    assert!(!output.pin_result.unknown_override);
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulate-error propagation
// ─────────────────────────────────────────────────────────────────────────────

/// A `simulateTransaction` error response propagates as
/// `SaError::DeploymentFailed { phase: "simulate", .. }` — `simulate_install_rule`
/// does not swallow or misclassify the RPC-reported simulate failure.
#[tokio::test]
async fn simulate_error_propagates_as_deployment_failed() {
    use stellar_xdr::{ContractId, Hash, ScAddress};

    let server = MockServer::start().await;
    let smart_account = ScAddress::Contract(ContractId(Hash([0x43u8; 32])));

    let ledger_resp = build_ledger_entries_account(SOURCE_G);
    let simulate_resp = simulate_error_response("Error(Contract, #9999)");

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(ledger_resp, simulate_resp))
        .mount(&server)
        .await;

    let manager = manager_for_server(&server);
    let err = manager
        .simulate_install_rule(
            smart_account,
            simple_rule_definition(),
            SOURCE_G,
            false,
            false,
            "req-simulate-error".to_owned(),
        )
        .await
        .expect_err("a simulateTransaction error response must propagate as an error");

    assert_eq!(
        err.wire_code(),
        "sa.deployment_failed",
        "wire_code must be 'sa.deployment_failed'; got: {}",
        err.wire_code()
    );
    assert!(
        err.to_string().contains("9999"),
        "error message must surface the underlying simulate error; got: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// No extra RPC calls
// ─────────────────────────────────────────────────────────────────────────────

/// `simulate_install_rule` issues exactly ONE `simulateTransaction` call
/// (plus the `getLedgerEntries` account fetch) — it does not sign or submit,
/// and does not re-simulate.
#[tokio::test]
async fn does_not_modify_install_rule_path_no_extra_simulate_calls() {
    use stellar_xdr::{ContractId, Hash, Limits, ScAddress, ScVal, WriteXdr};

    let server = MockServer::start().await;
    let smart_account = ScAddress::Contract(ContractId(Hash([0x44u8; 32])));

    let ledger_resp = build_ledger_entries_account(SOURCE_G);
    let return_xdr = ScVal::U32(1)
        .to_xdr_base64(Limits::none())
        .expect("ScVal::U32 must encode");
    let simulate_resp = simulate_ok_response(&return_xdr, 999);

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(ledger_resp, simulate_resp))
        .expect(2) // 1 getLedgerEntries (fetch_account) + 1 simulateTransaction
        .mount(&server)
        .await;

    let manager = manager_for_server(&server);
    manager
        .simulate_install_rule(
            smart_account,
            simple_rule_definition(),
            SOURCE_G,
            false,
            false,
            "req-no-extra-calls".to_owned(),
        )
        .await
        .expect("simulate_install_rule must succeed");

    // `.expect(2)` above is verified when `server` (and its underlying
    // wiremock `MockServer`) is dropped at end of scope; wiremock panics on
    // a call-count mismatch at that point.
}
