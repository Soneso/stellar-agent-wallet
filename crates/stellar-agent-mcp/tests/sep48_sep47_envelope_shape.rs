//! Envelope-shape regression guards for the RPC-dependent SEP-48/SEP-47 arms.
//!
//! `stellar_sep48_preview_invocation` and `stellar_sep47_discover` both call
//! into `stellar-agent-sep48`'s RPC fetch path
//! (`fetch_contract_spec`/`discover_claimed_seps`, which share the same
//! `fetch_wasm_bytes` two-step `getLedgerEntries` flow). These tests mock that
//! RPC to force each documented business-error arm and assert the full
//! envelope shape (`ok:false`, the documented wire code, a non-empty
//! `request_id`, `is_error == Some(true)`), mirroring the offline RPC-path
//! coverage already established at the `stellar-agent-sep48` crate level in
//! `spec_rpc_coverage.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use serde_json::json;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{Sep47DiscoverArgs, Sep48PreviewInvocationArgs, WalletServer};
use stellar_agent_test_support::EchoIdResponder;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

mod common;

// The SEP-41 token fixture WASM, already committed for `stellar-agent-sep48`'s
// own offline RPC-path coverage; has a valid `contractspecv0` section with an
// `approve` function.
const WASM_BYTES: &[u8] =
    include_bytes!("../../stellar-agent-sep48/tests/fixtures/sep41_token.wasm");

/// A valid, fixed C-strkey used as the target contract for every test in this
/// file. Each test mounts its own isolated `MockServer`, so cross-test
/// `SPEC_CACHE` collisions (the process-global cache in `spec.rs`, keyed on
/// contract strkey) are avoided by using a distinct seed per test instead.
fn contract_strkey(seed: u8) -> String {
    stellar_strkey::Contract([seed; 32])
        .to_string()
        .as_str()
        .to_owned()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// Builds the base64-encoded `LedgerEntryData::ContractCode` XDR containing
/// `wasm_bytes`.
fn build_code_xdr(wasm_bytes: &[u8]) -> String {
    use stellar_xdr::{
        BytesM, ContractCodeCostInputs, ContractCodeEntry, ContractCodeEntryExt,
        ContractCodeEntryV1, ExtensionPoint, Hash, LedgerEntryData, Limits, WriteXdr,
    };
    let hash = Hash(sha256(wasm_bytes));
    let code: BytesM = wasm_bytes.try_into().unwrap();
    let entry = LedgerEntryData::ContractCode(ContractCodeEntry {
        ext: ContractCodeEntryExt::V1(ContractCodeEntryV1 {
            ext: ExtensionPoint::V0,
            cost_inputs: ContractCodeCostInputs {
                ext: ExtensionPoint::V0,
                n_instructions: 0,
                n_functions: 0,
                n_globals: 0,
                n_table_entries: 0,
                n_types: 0,
                n_data_segments: 0,
                n_elem_segments: 0,
                n_imports: 0,
                n_exports: 0,
                n_data_segment_bytes: 0,
            },
        }),
        hash,
        code,
    });
    entry.to_xdr_base64(Limits::none()).unwrap()
}

/// Builds a contract-instance `LedgerEntryData::ContractData` XDR for the
/// given contract strkey.
fn build_instance_xdr_for(wasm_hash: [u8; 32], contract: &str) -> String {
    use stellar_xdr::{
        ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint,
        Hash, LedgerEntryData, Limits, ScAddress, ScContractInstance, ScVal, WriteXdr,
    };
    let instance = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: ScAddress::Contract(ContractId(Hash(
            stellar_strkey::Contract::from_string(contract)
                .expect("valid strkey")
                .0,
        ))),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(Hash(wasm_hash)),
            storage: None,
        }),
    });
    instance.to_xdr_base64(Limits::none()).unwrap()
}

/// Wraps a single XDR string into a `getLedgerEntries` JSON-RPC result.
fn ledger_entries_result(xdr: &str) -> serde_json::Value {
    json!({
        "entries": [{"xdr": xdr, "key": "dummy", "lastModifiedLedgerSeq": 1}],
        "latestLedger": 100
    })
}

fn testnet_profile_with_rpc(rpc_url: &str) -> Profile {
    let mut p = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    p.rpc_url = rpc_url.to_owned();
    p
}

// ─────────────────────────────────────────────────────────────────────────────
// sep48.spec_fetch_failed
// ─────────────────────────────────────────────────────────────────────────────

/// `stellar_sep48_preview_invocation` returns the full business-error envelope
/// with wire code `sep48.spec_fetch_failed` when the on-chain instance lookup
/// comes back with an empty `entries` list — the cheapest honest way to force
/// `fetch_contract_spec`'s RPC-fetch failure without a live network.
#[tokio::test]
async fn preview_invocation_empty_instance_entries_returns_spec_fetch_failed_envelope() {
    let contract = contract_strkey(20);
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [],
            "latestLedger": 100
        })))
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let args = Sep48PreviewInvocationArgs {
        transaction_xdr: None,
        contract_id: Some(contract),
        function: Some("approve".to_owned()),
        chain_id: "stellar:testnet".to_owned(),
    };
    let result = server
        .call_stellar_sep48_preview_invocation(args)
        .await
        .expect("handler must return a business-error result, not a protocol error");

    let (code, _message, _text) = common::assert_business_envelope(&result);
    assert_eq!(
        code, "sep48.spec_fetch_failed",
        "an empty instance-entries RPC response must surface sep48.spec_fetch_failed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// sep48.render_failed
// ─────────────────────────────────────────────────────────────────────────────

/// `stellar_sep48_preview_invocation` returns the full business-error envelope
/// with wire code `sep48.render_failed` when the spec fetch succeeds but the
/// requested function is absent from the contract's spec.
#[tokio::test]
async fn preview_invocation_unknown_function_returns_render_failed_envelope() {
    let contract = contract_strkey(21);
    let wasm_hash = sha256(WASM_BYTES);
    let instance_xdr = build_instance_xdr_for(wasm_hash, &contract);
    let code_xdr = build_code_xdr(WASM_BYTES);

    let mock_server = MockServer::start().await;

    // First call: getLedgerEntries(instance) → ContractData with WASM hash.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&instance_xdr)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Second call: getLedgerEntries(code) → ContractCode with WASM bytes.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&code_xdr)))
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let args = Sep48PreviewInvocationArgs {
        transaction_xdr: None,
        contract_id: Some(contract),
        // The SEP-41 fixture's spec has no such function.
        function: Some("this_function_does_not_exist".to_owned()),
        chain_id: "stellar:testnet".to_owned(),
    };
    let result = server
        .call_stellar_sep48_preview_invocation(args)
        .await
        .expect("handler must return a business-error result, not a protocol error");

    let (code, _message, _text) = common::assert_business_envelope(&result);
    assert_eq!(
        code, "sep48.render_failed",
        "a successfully-fetched spec with an unknown function name must surface \
         sep48.render_failed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// sep47.discovery_failed
// ─────────────────────────────────────────────────────────────────────────────

/// `stellar_sep47_discover` returns the full business-error envelope with wire
/// code `sep47.discovery_failed` when the on-chain instance lookup comes back
/// empty. `discover_claimed_seps` delegates to the same `fetch_wasm_bytes` as
/// `fetch_contract_spec`, so the identical empty-entries mock forces the same
/// underlying `Sep48Error::RpcFetchFailure`.
#[tokio::test]
async fn discover_empty_instance_entries_returns_discovery_failed_envelope() {
    let contract = contract_strkey(22);
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [],
            "latestLedger": 100
        })))
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let args = Sep47DiscoverArgs {
        contract_id: contract,
        chain_id: "stellar:testnet".to_owned(),
    };
    let result = server
        .call_stellar_sep47_discover(args)
        .await
        .expect("handler must return a business-error result, not a protocol error");

    let (code, _message, _text) = common::assert_business_envelope(&result);
    assert_eq!(
        code, "sep47.discovery_failed",
        "an empty instance-entries RPC response must surface sep47.discovery_failed"
    );
}
