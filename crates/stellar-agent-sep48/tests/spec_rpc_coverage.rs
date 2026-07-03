//! Offline RPC-path coverage tests for `spec.rs` and `discovery.rs`.
//!
//! Uses `wiremock` to mock the two-step `getLedgerEntries` JSON-RPC flow that
//! `fetch_contract_spec` and `fetch_wasm_bytes` perform, covering branches in
//! the RPC fetch path that cannot be exercised without a live network.
//!
//! Mock strategy: the mock server returns pre-built XDR responses for both
//! the contract-instance key (step 1) and the contract-code key (step 2).
//! The fixture WASM is the SEP-41 token contract already committed in
//! `tests/fixtures/sep41_token.wasm`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use serde_json::json;
use stellar_agent_sep48::{Sep48Error, fetch_contract_spec};
use stellar_agent_test_support::EchoIdResponder;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

// The WASM fixture bytes used as the mock "on-chain" WASM.
const WASM_BYTES: &[u8] = include_bytes!("fixtures/sep41_token.wasm");

/// Returns a unique, valid contract C-strkey seeded by `seed`.
///
/// Each test fetches under a distinct contract id so the process-global
/// `SPEC_CACHE` in `spec.rs` (keyed on the contract strkey) cannot be populated
/// by one test and then observed by another, which would make results depend on
/// test execution order. Seed 1 is reserved for `CONTRACT_CACHE_HIT`.
fn unique_contract(seed: u8) -> String {
    // `stellar_strkey::Contract::to_string` is an inherent method returning a
    // no_std `heapless` string; convert it to an owned `std` String.
    stellar_strkey::Contract([seed; 32])
        .to_string()
        .as_str()
        .to_owned()
}

/// Builds a SHA-256 hash of `data` and returns it as a `[u8; 32]`.
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

/// Wraps a single XDR string into a `getLedgerEntries` JSON-RPC result.
///
/// `stellar-rpc-client` requires both `entries` and `latestLedger` fields to
/// be present in a `getLedgerEntries` response.
fn ledger_entries_result(xdr: &str) -> serde_json::Value {
    json!({
        "entries": [{"xdr": xdr, "key": "dummy", "lastModifiedLedgerSeq": 1}],
        "latestLedger": 100
    })
}

/// Verifies that `fetch_contract_spec` returns non-empty spec entries when both
/// the instance lookup and code lookup succeed with valid mocked XDR.
///
/// Covers:
/// - `fetch_wasm_bytes` happy path (both RPC calls succeed)
/// - `Spec::from_wasm` parse path
/// - `SPEC_CACHE` insertion (first call — cache miss)
/// - `fetch_contract_spec` happy path
#[tokio::test]
async fn fetch_contract_spec_happy_path_with_mocked_rpc() {
    let contract = unique_contract(2);
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

    let result = fetch_contract_spec(&mock_server.uri(), &contract).await;

    assert!(
        result.is_ok(),
        "fetch_contract_spec must succeed with valid mocked RPC, got: {result:?}"
    );
    let entries = result.unwrap();
    assert!(
        !entries.is_empty(),
        "spec entries must be non-empty for the SEP-41 token fixture WASM"
    );

    // Verify the approve function is present in the parsed spec.
    let spec = soroban_spec_tools::Spec::new(&entries);
    assert!(
        spec.find_function("approve").is_ok(),
        "approve function must be present in the parsed spec"
    );
}

/// Verifies that `fetch_contract_spec` returns `Sep48Error::RpcFetchFailure`
/// when the instance lookup returns an empty entries list.
///
/// Covers the `empty instance ledger entries` branch in
/// `extract_wasm_hash_from_instance_response`.
#[tokio::test]
async fn fetch_contract_spec_empty_instance_response_returns_rpc_failure() {
    let contract = unique_contract(3);
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [],
            "ledger": 100
        })))
        .mount(&mock_server)
        .await;

    let result = fetch_contract_spec(&mock_server.uri(), &contract).await;

    assert!(
        matches!(result, Err(Sep48Error::RpcFetchFailure { .. })),
        "empty entries must return RpcFetchFailure, got: {result:?}"
    );
}

/// Verifies that `fetch_contract_spec` returns `Sep48Error::RpcFetchFailure`
/// when the instance lookup returns null `entries`.
///
/// Covers the `no instance ledger entry` branch.
#[tokio::test]
async fn fetch_contract_spec_null_instance_entries_returns_rpc_failure() {
    let contract = unique_contract(4);
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": null,
            "ledger": 100
        })))
        .mount(&mock_server)
        .await;

    let result = fetch_contract_spec(&mock_server.uri(), &contract).await;

    assert!(
        matches!(result, Err(Sep48Error::RpcFetchFailure { .. })),
        "null entries must return RpcFetchFailure, got: {result:?}"
    );
}

/// Verifies that `fetch_contract_spec` returns `Sep48Error::RpcFetchFailure`
/// when the instance XDR is malformed.
///
/// Covers the `parse_ledger_entry_xdr` error branch.
#[tokio::test]
async fn fetch_contract_spec_malformed_instance_xdr_returns_rpc_failure() {
    let contract = unique_contract(5);
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result("not-valid-xdr")))
        .mount(&mock_server)
        .await;

    let result = fetch_contract_spec(&mock_server.uri(), &contract).await;

    assert!(
        matches!(result, Err(Sep48Error::RpcFetchFailure { .. })),
        "malformed XDR must return RpcFetchFailure, got: {result:?}"
    );
}

/// Verifies that `fetch_contract_spec` returns `Sep48Error::RpcFetchFailure`
/// when the instance entry is a `StellarAsset` executable.
///
/// Covers the SAC-detection branch and verifies the error reason string.
#[tokio::test]
async fn fetch_contract_spec_sac_instance_returns_rpc_failure_with_sac_reason() {
    use stellar_xdr::{
        ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint,
        Hash, LedgerEntryData, Limits, ScAddress, ScContractInstance, ScVal, WriteXdr,
    };
    let contract = unique_contract(6);
    let sac_instance = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: ScAddress::Contract(ContractId(Hash(
            stellar_strkey::Contract::from_string(&contract)
                .expect("valid strkey")
                .0,
        ))),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::StellarAsset,
            storage: None,
        }),
    });
    let xdr = sac_instance.to_xdr_base64(Limits::none()).unwrap();

    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&xdr)))
        .mount(&mock_server)
        .await;

    let result = fetch_contract_spec(&mock_server.uri(), &contract).await;

    match &result {
        Err(Sep48Error::RpcFetchFailure { reason }) => {
            assert!(
                reason.contains("Stellar Asset Contract"),
                "SAC error must mention 'Stellar Asset Contract', got: {reason}"
            );
        }
        other => panic!("SAC instance must return RpcFetchFailure with SAC reason, got: {other:?}"),
    }
}

/// Verifies that `fetch_contract_spec` returns `Sep48Error::RpcFetchFailure`
/// when the code lookup returns empty entries.
///
/// Covers the `empty code ledger entries` branch.
#[tokio::test]
async fn fetch_contract_spec_empty_code_entries_returns_rpc_failure() {
    let contract = unique_contract(7);
    let wasm_hash = sha256(WASM_BYTES);
    let instance_xdr = build_instance_xdr_for(wasm_hash, &contract);

    let mock_server = MockServer::start().await;

    // First call: instance lookup succeeds.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&instance_xdr)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Second call: code lookup returns empty entries.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [],
            "ledger": 100
        })))
        .mount(&mock_server)
        .await;

    let result = fetch_contract_spec(&mock_server.uri(), &contract).await;

    assert!(
        matches!(result, Err(Sep48Error::RpcFetchFailure { .. })),
        "empty code entries must return RpcFetchFailure, got: {result:?}"
    );
}

/// Verifies that `fetch_contract_spec` returns `Sep48Error::SpecSectionMissing`
/// or `WasmParseFailure` when the WASM has no `contractspecv0` section.
///
/// Covers the `SpecSectionMissing` error path.
#[tokio::test]
async fn fetch_contract_spec_wasm_without_spec_section_returns_spec_missing() {
    let contract = unique_contract(8);
    // Minimal valid WASM (magic + version) — has no custom sections.
    let minimal_wasm = b"\x00asm\x01\x00\x00\x00";
    let wasm_hash = sha256(minimal_wasm);
    let instance_xdr = build_instance_xdr_for(wasm_hash, &contract);
    let code_xdr = build_code_xdr(minimal_wasm);

    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&instance_xdr)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&code_xdr)))
        .mount(&mock_server)
        .await;

    let result = fetch_contract_spec(&mock_server.uri(), &contract).await;

    assert!(
        matches!(
            result,
            Err(Sep48Error::SpecSectionMissing) | Err(Sep48Error::WasmParseFailure { .. })
        ),
        "minimal WASM must return SpecSectionMissing or WasmParseFailure, got: {result:?}"
    );
}

/// Verifies that `fetch_contract_spec` returns `Sep48Error::InvalidContractAddress`
/// for an invalid C-strkey.
///
/// Covers the `parse_contract_id` error branch.
#[tokio::test]
async fn fetch_contract_spec_invalid_contract_strkey_returns_error() {
    let mock_server = MockServer::start().await;

    // No mock responses needed — the error fires before any RPC call.
    let result = fetch_contract_spec(&mock_server.uri(), "not-a-strkey").await;

    assert!(
        matches!(result, Err(Sep48Error::InvalidContractAddress { .. })),
        "invalid strkey must return InvalidContractAddress, got: {result:?}"
    );
}

/// Verifies that `discover_claimed_seps` returns an empty list for a WASM
/// that has no `contractmetav0` section.
///
/// Covers the `fetch_wasm_bytes` + `extract_seps_from_wasm` path via mocked RPC.
#[tokio::test]
async fn discover_claimed_seps_wasm_without_meta_section_returns_empty() {
    use stellar_agent_sep48::discover_claimed_seps;

    let contract = unique_contract(9);
    // Minimal WASM (magic + version) — has no contractmetav0 section.
    let minimal_wasm = b"\x00asm\x01\x00\x00\x00";
    let wasm_hash = sha256(minimal_wasm);
    let instance_xdr = build_instance_xdr_for(wasm_hash, &contract);
    let code_xdr = build_code_xdr(minimal_wasm);

    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&instance_xdr)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&code_xdr)))
        .mount(&mock_server)
        .await;

    let result = discover_claimed_seps(&mock_server.uri(), &contract).await;

    assert!(
        result.is_ok(),
        "discover_claimed_seps must succeed for valid WASM, got: {result:?}"
    );
    assert!(
        result.unwrap().is_empty(),
        "WASM without contractmetav0 must return empty SEP list"
    );
}

/// Verifies that `fetch_contract_spec` returns `Sep48Error::RpcFetchFailure`
/// when the RPC URL is not parseable as a URI.
///
/// `StellarRpcClient::new` calls `stellar_rpc_client::Client::new` which
/// parses the URL via `base_url.parse::<Uri>()`; an unparseable URL returns
/// `Err(Error::InvalidRpcUrl(...))` before any network activity. This covers
/// the `map_err` closure for client construction failure in `fetch_wasm_bytes`.
#[tokio::test]
async fn fetch_contract_spec_invalid_rpc_url_returns_rpc_failure() {
    let contract = unique_contract(10);
    // "not a url" fails URI parse — `Client::new` returns Err immediately,
    // no network connection is attempted.
    let result = fetch_contract_spec("://not-a-valid-url", &contract).await;
    assert!(
        matches!(result, Err(Sep48Error::RpcFetchFailure { .. })),
        "unparseable RPC URL must return RpcFetchFailure, got: {result:?}"
    );
}

/// Verifies that `fetch_contract_spec` returns `RpcFetchFailure` when the RPC
/// server is down.
///
/// Covers the `getLedgerEntries` network-error path via `StellarRpcClient`.
#[tokio::test]
async fn fetch_contract_spec_server_down_returns_rpc_failure() {
    let contract = unique_contract(11);
    // Bind to an ephemeral port and immediately drop the listener so the port
    // is closed before we call fetch_contract_spec.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to ephemeral port");
        listener.local_addr().expect("local_addr").port()
    };
    let url = format!("http://127.0.0.1:{port}");

    let result = fetch_contract_spec(&url, &contract).await;

    assert!(
        matches!(result, Err(Sep48Error::RpcFetchFailure { .. })),
        "server down must return RpcFetchFailure, got: {result:?}"
    );
}

/// Verifies the in-process spec cache hit path.
///
/// Uses a unique C-strkey (`CONTRACT_CACHE_HIT`) not shared with any other test
/// to avoid cross-test SPEC_CACHE collisions. The first call populates the cache
/// from a mock RPC; the second call is made against a closed-port server — if the
/// cache is hit the result is `Ok`, if it were a cache miss the closed port would
/// produce `RpcFetchFailure`.
///
/// Covers the cache-hit fast path in `fetch_contract_spec`.
// CONTRACT_CACHE_HIT is stellar_strkey::Contract([1u8; 32]).to_string()
const CONTRACT_CACHE_HIT: &str = "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526";

#[tokio::test]
async fn fetch_contract_spec_second_call_hits_cache() {
    let wasm_hash = sha256(WASM_BYTES);
    let instance_xdr = build_instance_xdr_for(wasm_hash, CONTRACT_CACHE_HIT);
    let code_xdr = build_code_xdr(WASM_BYTES);

    let mock_server = MockServer::start().await;

    // Register BOTH RPC steps once each; any further requests → 404 (unmatched).
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&instance_xdr)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&code_xdr)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // First call — cache miss, two RPC requests are served.
    let first = fetch_contract_spec(&mock_server.uri(), CONTRACT_CACHE_HIT).await;
    assert!(
        first.is_ok(),
        "first call must succeed with valid mocked RPC, got: {first:?}"
    );

    // Second call — same strkey, but now we point at a closed port. If the cache
    // is bypassed, the TCP connection fails and `RpcFetchFailure` is returned.
    // A cache hit returns `Ok` without touching the network.
    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    };
    let dead_url = format!("http://127.0.0.1:{dead_port}");

    let second = fetch_contract_spec(&dead_url, CONTRACT_CACHE_HIT).await;
    let first_entries = first.unwrap();
    let second_entries = second.expect(
        "second call for same contract must return Ok from cache, not hit the (dead) network",
    );
    assert_eq!(
        first_entries.len(),
        second_entries.len(),
        "cached entries must match the first-call entries"
    );
}

/// Builds a contract-instance `LedgerEntryData::ContractData` XDR for the
/// given contract strkey.
fn build_instance_xdr_for(wasm_hash: [u8; 32], contract_strkey: &str) -> String {
    use stellar_xdr::{
        ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint,
        Hash, LedgerEntryData, Limits, ScAddress, ScContractInstance, ScVal, WriteXdr,
    };
    let instance = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: ScAddress::Contract(ContractId(Hash(
            stellar_strkey::Contract::from_string(contract_strkey)
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

/// Verifies that `fetch_contract_spec` returns `Sep48Error::WasmParseFailure`
/// when the code entry contains garbage bytes that `wasmparser` cannot parse.
///
/// `soroban_spec::read::raw_from_wasm` calls `wasmparser::Parser::parse_all`;
/// on invalid input it returns `BinaryReaderError` which becomes
/// `FromWasmError::Read("reading wasm")`. That string does NOT contain
/// "not found" so it maps to `WasmParseFailure` (not `SpecSectionMissing`).
///
/// Covers the `Sep48Error::WasmParseFailure` branch in `fetch_contract_spec`.
#[tokio::test]
async fn fetch_contract_spec_garbage_wasm_returns_wasm_parse_failure() {
    let contract = unique_contract(12);
    // Bytes that are not valid WASM at all (no magic header).
    let garbage_wasm = b"\xff\xfe\xfd\xfc\x00\x01\x02\x03garbage_content";
    let wasm_hash = sha256(garbage_wasm);
    let instance_xdr = build_instance_xdr_for(wasm_hash, &contract);
    let code_xdr = build_code_xdr(garbage_wasm);

    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&instance_xdr)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&code_xdr)))
        .mount(&mock_server)
        .await;

    let result = fetch_contract_spec(&mock_server.uri(), &contract).await;

    match &result {
        Err(Sep48Error::WasmParseFailure { reason }) => {
            assert!(
                reason.contains("reading wasm"),
                "garbage WASM must produce 'reading wasm' parse-failure reason, got: {reason}"
            );
        }
        other => panic!("garbage WASM must return WasmParseFailure, got: {other:?}"),
    }
}

/// Verifies that `fetch_contract_spec` returns `Sep48Error::SpecSectionMissing`
/// when the WASM contains an empty `contractspecv0` custom section (zero spec
/// entries). This is distinct from the missing-section case: the section exists
/// but carries no entries, so `Spec::from_wasm` returns `Ok([])` and the
/// `if entries.is_empty()` guard fires.
///
/// WASM layout:
///   magic+version | custom-section-id=0 | size=0x0f | name-len=0x0e |
///   b"contractspecv0" | (no data)
///
/// Covers the `SpecSectionMissing` branch when `entries.is_empty()` in `fetch_contract_spec`.
#[tokio::test]
async fn fetch_contract_spec_empty_spec_section_returns_spec_missing() {
    let contract = unique_contract(13);
    // Build a minimal WASM with an empty contractspecv0 custom section.
    // WASM custom section format: id=0x00, size (LEB128), name_len (LEB128), name, data.
    let section_name = b"contractspecv0"; // 14 bytes
    // section body = 1 byte (name_len) + 14 bytes (name) + 0 bytes (data) = 15 = 0x0f
    let section_body_len: u8 = 1 + section_name.len() as u8;
    let mut empty_spec_wasm = b"\x00asm\x01\x00\x00\x00".to_vec();
    empty_spec_wasm.push(0x00); // custom section id
    empty_spec_wasm.push(section_body_len); // section size (LEB128, fits in 1 byte)
    empty_spec_wasm.push(section_name.len() as u8); // name length
    empty_spec_wasm.extend_from_slice(section_name);
    // No data bytes — the spec section is empty.

    let wasm_hash = sha256(&empty_spec_wasm);
    let instance_xdr = build_instance_xdr_for(wasm_hash, &contract);
    let code_xdr = build_code_xdr(&empty_spec_wasm);

    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&instance_xdr)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(ledger_entries_result(&code_xdr)))
        .mount(&mock_server)
        .await;

    let result = fetch_contract_spec(&mock_server.uri(), &contract).await;

    assert!(
        matches!(result, Err(Sep48Error::SpecSectionMissing)),
        "empty contractspecv0 section must return SpecSectionMissing, got: {result:?}"
    );
}
