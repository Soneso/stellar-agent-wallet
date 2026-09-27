//! Offline RPC-path coverage tests for `spec.rs` and `discovery.rs`.
//!
//! Uses `wiremock` with a keyed `getLedgerEntries` responder to serve the
//! contract instance, the owner's executable-tag entry (for an external
//! reference) and the contract code, each under its real ledger key, the way
//! a live endpoint answers.
//!
//! The base fixture Wasm is the SEP-41 token contract committed in
//! `tests/fixtures/sep41_token.wasm`.
//!
//! The spec cache in `spec.rs` is process-global and keyed by Wasm hash, so a
//! spec cached by one test would be observed by any other test in this binary
//! that fetches code with the same hash, making results depend on execution
//! order. Every test that fetches code therefore appends a custom section
//! carrying its own seed string to the fixture Wasm (see [`seeded`]), which
//! gives each test code with a hash no other test uses. Seeds carry a
//! `spec_rpc_coverage/` prefix so they are also distinct from the seeds in the
//! MCP envelope-shape tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use serde_json::Value;
use stellar_agent_sep48::{Sep48Error, discover_claimed_seps, fetch_contract_spec};
use stellar_agent_test_support::{KeyedLedgerEntriesResponder, xdr_fixtures};
use stellar_xdr::{Hash, LedgerKey, LedgerKeyContractCode, Limits, WriteXdr};
use wiremock::MockServer;

/// The SEP-41 token fixture; its spec has an `approve` function.
const BASE_WASM: &[u8] = include_bytes!("fixtures/sep41_token.wasm");

/// Minimal valid Wasm (magic + version) with no sections.
const MINIMAL_WASM: &[u8] = b"\x00asm\x01\x00\x00\x00";

/// Executable owner used by the external-reference fixtures.
const OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/// Returns a valid contract C-strkey seeded by `seed`.
fn contract(seed: u8) -> String {
    // `stellar_strkey::Contract::to_string` is an inherent method returning a
    // no_std `heapless` string; convert it to an owned `std` String.
    stellar_strkey::Contract([seed; 32])
        .to_string()
        .as_str()
        .to_owned()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// Appends the unsigned LEB128 encoding of `n` to `out`.
fn push_leb128(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Encodes a Wasm custom section named `name` carrying `data`.
fn custom_section(name: &str, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    push_leb128(name.len(), &mut body);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(data);
    let mut section = vec![0x00];
    push_leb128(body.len(), &mut section);
    section.extend_from_slice(&body);
    section
}

/// Returns `wasm` with a trailing custom section carrying `seed`, so the
/// result has a hash unique to `seed` and parses to the same spec and meta.
fn seeded(wasm: &[u8], seed: &str) -> Vec<u8> {
    let mut out = wasm.to_vec();
    out.extend(custom_section(
        "test_seed",
        format!("spec_rpc_coverage/{seed}").as_bytes(),
    ));
    out
}

/// Returns a Wasm whose `contractspecv0` section holds one function named
/// `function`, seeded by `seed`.
fn wasm_with_spec_function(function: &str, seed: &str) -> Vec<u8> {
    use stellar_xdr::{ScSpecEntry, ScSpecFunctionV0};
    let entry = ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
        doc: "".try_into().unwrap(),
        name: function.try_into().unwrap(),
        inputs: vec![].try_into().unwrap(),
        outputs: vec![].try_into().unwrap(),
    });
    let mut wasm = MINIMAL_WASM.to_vec();
    wasm.extend(custom_section(
        "contractspecv0",
        &entry.to_xdr(Limits::none()).unwrap(),
    ));
    seeded(&wasm, seed)
}

/// Returns a Wasm whose `contractmetav0` section claims `seps`, seeded by
/// `seed`.
fn wasm_with_sep_claim(seps: &str, seed: &str) -> Vec<u8> {
    use stellar_xdr::{ScMetaEntry, ScMetaV0};
    let entry = ScMetaEntry::ScMetaV0(ScMetaV0 {
        key: "sep".try_into().unwrap(),
        val: seps.try_into().unwrap(),
    });
    let mut wasm = MINIMAL_WASM.to_vec();
    wasm.extend(custom_section(
        "contractmetav0",
        &entry.to_xdr(Limits::none()).unwrap(),
    ));
    seeded(&wasm, seed)
}

fn entry(response_json: &str) -> Value {
    xdr_fixtures::ledger_entry_from_response_json(response_json)
}

/// The Wasm instance entry of `contract` pointing at `wasm_hash`.
fn wasm_instance(contract: &str, wasm_hash: [u8; 32]) -> Value {
    entry(&xdr_fixtures::contract_instance_ledger_entries_json(
        contract, wasm_hash,
    ))
}

/// The external-reference instance entry of `contract`, owned by [`OWNER`].
fn external_ref_instance(contract: &str, tag: &[u8]) -> Value {
    entry(&xdr_fixtures::external_ref_instance_ledger_entries_json(
        contract, OWNER, tag,
    ))
}

/// [`OWNER`]'s executable-tag entry for `tag`, holding `wasm_hash`.
fn tag_entry(tag: &[u8], wasm_hash: [u8; 32]) -> Value {
    entry(&xdr_fixtures::executable_tag_ledger_entries_json(
        OWNER, tag, wasm_hash,
    ))
}

/// The well-formed code entry for `code`, under the key of its own hash.
fn code_entry(code: &[u8]) -> Value {
    entry(&xdr_fixtures::contract_code_ledger_entries_json(
        sha256(code),
        code,
    ))
}

/// The base64 `LedgerKey::ContractCode` for `wasm_hash`.
fn code_key_b64(wasm_hash: [u8; 32]) -> String {
    LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: Hash(wasm_hash),
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

async fn serve(entries: impl IntoIterator<Item = Value>) -> MockServer {
    entries
        .into_iter()
        .fold(KeyedLedgerEntriesResponder::new(), |responder, e| {
            responder.with_entry(e)
        })
        .serve()
        .await
}

/// Counts the requests `server` received that ask for the code entry of
/// `wasm_hash`.
async fn code_fetch_count(server: &MockServer, wasm_hash: [u8; 32]) -> usize {
    let key = code_key_b64(wasm_hash);
    server
        .received_requests()
        .await
        .expect("request recording is enabled")
        .iter()
        .filter(|request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap_or_default();
            body["params"]["keys"]
                .as_array()
                .is_some_and(|keys| keys.iter().any(|k| k.as_str() == Some(key.as_str())))
        })
        .count()
}

fn function_names(entries: &[stellar_xdr::ScSpecEntry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|e| match e {
            stellar_xdr::ScSpecEntry::FunctionV0(f) => Some(f.name.to_utf8_string_lossy()),
            _ => None,
        })
        .collect()
}

fn expect_rpc_failure<T>(result: Result<T, Sep48Error>) -> String {
    match result {
        Err(Sep48Error::RpcFetchFailure { reason }) => reason,
        Err(other) => panic!("expected RpcFetchFailure, got: {other:?}"),
        Ok(_) => panic!("expected RpcFetchFailure, got: Ok"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wasm contracts
// ─────────────────────────────────────────────────────────────────────────────

/// A Wasm contract's instance and code resolve to the parsed spec.
#[tokio::test]
async fn fetch_contract_spec_happy_path_with_mocked_rpc() {
    let contract = contract(2);
    let wasm = seeded(BASE_WASM, "happy_path");
    let server = serve([wasm_instance(&contract, sha256(&wasm)), code_entry(&wasm)]).await;

    let entries = fetch_contract_spec(&server.uri(), &contract)
        .await
        .expect("fetch_contract_spec must succeed with valid mocked RPC");

    let spec = soroban_spec_tools::Spec::new(&entries);
    assert!(
        spec.find_function("approve").is_ok(),
        "approve function must be present in the parsed spec"
    );
}

/// A contract with no instance entry is refused with the absent reason.
#[tokio::test]
async fn fetch_contract_spec_absent_instance_returns_rpc_failure() {
    let contract = contract(3);
    let server = serve([]).await;

    let reason = expect_rpc_failure(fetch_contract_spec(&server.uri(), &contract).await);

    assert_eq!(
        reason,
        format!(
            "no instance ledger entry for contract {}",
            redact(&contract)
        )
    );
}

/// An instance entry that does not decode is refused as malformed.
#[tokio::test]
async fn fetch_contract_spec_malformed_instance_xdr_returns_rpc_failure() {
    let contract = contract(5);
    let mut instance = wasm_instance(&contract, [5u8; 32]);
    instance["xdr"] = Value::String("not-valid-xdr".to_owned());
    let server = serve([instance]).await;

    let reason = expect_rpc_failure(fetch_contract_spec(&server.uri(), &contract).await);

    assert!(
        reason.contains("contract instance entry does not decode"),
        "malformed instance XDR must be reported as malformed, got: {reason}"
    );
}

/// A Stellar Asset Contract keeps its SAC reason.
#[tokio::test]
async fn fetch_contract_spec_sac_instance_returns_rpc_failure_with_sac_reason() {
    let contract = contract(6);
    let server = serve([entry(&xdr_fixtures::sac_instance_ledger_entries_json(
        &contract,
    ))])
    .await;

    let reason = expect_rpc_failure(fetch_contract_spec(&server.uri(), &contract).await);

    assert_eq!(
        reason,
        format!(
            "contract {} is a Stellar Asset Contract (SAC), not a Wasm contract",
            redact(&contract)
        )
    );
}

/// An instance whose code entry is not served is refused naming the hash.
#[tokio::test]
async fn fetch_contract_spec_missing_code_entry_returns_rpc_failure() {
    let contract = contract(7);
    let wasm = seeded(BASE_WASM, "missing_code_entry");
    let server = serve([wasm_instance(&contract, sha256(&wasm))]).await;

    let reason = expect_rpc_failure(fetch_contract_spec(&server.uri(), &contract).await);

    assert!(
        reason.starts_with("no code ledger entry for Wasm hash "),
        "got: {reason}"
    );
}

/// Wasm without a `contractspecv0` section is `SpecSectionMissing`.
#[tokio::test]
async fn fetch_contract_spec_wasm_without_spec_section_returns_spec_missing() {
    let contract = contract(8);
    let wasm = seeded(MINIMAL_WASM, "without_spec_section");
    let server = serve([wasm_instance(&contract, sha256(&wasm)), code_entry(&wasm)]).await;

    let result = fetch_contract_spec(&server.uri(), &contract).await;

    assert!(
        matches!(result, Err(Sep48Error::SpecSectionMissing)),
        "Wasm without a spec section must return SpecSectionMissing, got: {result:?}"
    );
}

/// An invalid address keeps `InvalidContractAddress`, redacted, before any
/// RPC request.
#[tokio::test]
async fn fetch_contract_spec_invalid_contract_strkey_returns_error() {
    let server = serve([]).await;

    let result = fetch_contract_spec(&server.uri(), "not-a-strkey").await;

    match result {
        Err(Sep48Error::InvalidContractAddress { addr }) => assert_eq!(addr, "not-a...trkey"),
        other => panic!("invalid strkey must return InvalidContractAddress, got: {other:?}"),
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("recording")
            .is_empty(),
        "an invalid address must be refused before any RPC request"
    );
}

/// An unparseable RPC URL is refused before any network activity.
#[tokio::test]
async fn fetch_contract_spec_invalid_rpc_url_returns_rpc_failure() {
    let contract = contract(10);
    let result = fetch_contract_spec("://not-a-valid-url", &contract).await;
    assert!(
        matches!(result, Err(Sep48Error::RpcFetchFailure { .. })),
        "unparseable RPC URL must return RpcFetchFailure, got: {result:?}"
    );
}

/// An unreachable endpoint's error reaches the reason only through
/// `redact_rpc_error`: no scheme, userinfo credentials, path or query of the
/// URL survives.
#[tokio::test]
async fn fetch_contract_spec_server_down_reason_is_redacted() {
    let contract = contract(11);
    // Bind to an ephemeral port and immediately drop the listener so the port
    // is closed before the fetch.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to ephemeral port");
        listener.local_addr().expect("local_addr").port()
    };
    let url = format!("http://admin:s3cr3t@127.0.0.1:{port}/private-path?key=SECRET");

    let reason = expect_rpc_failure(fetch_contract_spec(&url, &contract).await);

    assert!(
        !reason.to_ascii_lowercase().contains("http://"),
        "the URL scheme must be stripped from the reason: {reason}"
    );
    assert!(
        !reason.contains("admin") && !reason.contains("s3cr3t"),
        "userinfo credentials must be stripped from the reason: {reason}"
    );
    assert!(
        !reason.contains("private-path") && !reason.contains("SECRET"),
        "the URL path and query must be stripped from the reason: {reason}"
    );
}

/// Every call resolves the instance, and a hash already parsed is served
/// from the cache without a code fetch: the second call is answered by an
/// endpoint that serves the instance but no code.
#[tokio::test]
async fn fetch_contract_spec_second_call_resolves_instance_and_hits_cache() {
    let contract = contract(1);
    let wasm = seeded(BASE_WASM, "second_call_hits_cache");
    let hash = sha256(&wasm);

    let first_server = serve([wasm_instance(&contract, hash), code_entry(&wasm)]).await;
    let first = fetch_contract_spec(&first_server.uri(), &contract)
        .await
        .expect("first call must succeed");

    let instance_only = serve([wasm_instance(&contract, hash)]).await;
    let second = fetch_contract_spec(&instance_only.uri(), &contract)
        .await
        .expect("second call must be served from the cache");

    assert_eq!(first, second, "cached entries must match the first call");
    assert_eq!(code_fetch_count(&instance_only, hash).await, 0);
    assert_eq!(
        instance_only
            .received_requests()
            .await
            .expect("recording")
            .len(),
        1,
        "the second call must resolve the instance with one request"
    );
}

/// Garbage code bytes are `WasmParseFailure`.
#[tokio::test]
async fn fetch_contract_spec_garbage_wasm_returns_wasm_parse_failure() {
    let contract = contract(12);
    let garbage = seeded(
        b"\xff\xfe\xfd\xfc\x00\x01\x02\x03garbage_content",
        "garbage",
    );
    let server = serve([
        wasm_instance(&contract, sha256(&garbage)),
        code_entry(&garbage),
    ])
    .await;

    match fetch_contract_spec(&server.uri(), &contract).await {
        Err(Sep48Error::WasmParseFailure { reason }) => assert!(
            reason.contains("reading wasm"),
            "garbage Wasm must produce 'reading wasm' parse-failure reason, got: {reason}"
        ),
        other => panic!("garbage Wasm must return WasmParseFailure, got: {other:?}"),
    }
}

/// An empty `contractspecv0` section (zero entries) is `SpecSectionMissing`.
#[tokio::test]
async fn fetch_contract_spec_empty_spec_section_returns_spec_missing() {
    let contract = contract(13);
    let mut wasm = MINIMAL_WASM.to_vec();
    wasm.extend(custom_section("contractspecv0", &[]));
    let wasm = seeded(&wasm, "empty_spec_section");
    let server = serve([wasm_instance(&contract, sha256(&wasm)), code_entry(&wasm)]).await;

    let result = fetch_contract_spec(&server.uri(), &contract).await;

    assert!(
        matches!(result, Err(Sep48Error::SpecSectionMissing)),
        "empty contractspecv0 section must return SpecSectionMissing, got: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache keyed by Wasm hash
// ─────────────────────────────────────────────────────────────────────────────

/// Two contracts running the same Wasm share one cached spec: the second
/// contract's call resolves its instance and fetches no code.
#[tokio::test]
async fn contracts_sharing_a_wasm_hash_cause_one_code_fetch() {
    let first = contract(30);
    let second = contract(31);
    let wasm = seeded(BASE_WASM, "shared_hash");
    let hash = sha256(&wasm);
    let server = serve([
        wasm_instance(&first, hash),
        wasm_instance(&second, hash),
        code_entry(&wasm),
    ])
    .await;

    let a = fetch_contract_spec(&server.uri(), &first)
        .await
        .expect("first contract");
    let b = fetch_contract_spec(&server.uri(), &second)
        .await
        .expect("second contract");

    assert_eq!(a, b);
    assert_eq!(
        code_fetch_count(&server, hash).await,
        1,
        "contracts on the same code must share one code fetch"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// External references
// ─────────────────────────────────────────────────────────────────────────────

/// An external-reference contract resolves through the owner's tag entry and
/// returns the spec of the code the tag points at.
#[tokio::test]
async fn external_reference_resolves_through_tag_entry() {
    let contract = contract(40);
    let wasm = seeded(BASE_WASM, "external_ref_resolves");
    let server = serve([
        external_ref_instance(&contract, b"token"),
        tag_entry(b"token", sha256(&wasm)),
        code_entry(&wasm),
    ])
    .await;

    let entries = fetch_contract_spec(&server.uri(), &contract)
        .await
        .expect("an external reference with a live tag entry must resolve");

    let spec = soroban_spec_tools::Spec::new(&entries);
    assert!(spec.find_function("approve").is_ok());
}

/// After the owner repoints the tag at different code, the next call returns
/// the spec of the new code.
#[tokio::test]
async fn external_reference_repointed_tag_returns_new_spec() {
    let contract = contract(41);
    let old_code = wasm_with_spec_function("alpha", "repoint_old");
    let new_code = wasm_with_spec_function("beta", "repoint_new");

    let before = serve([
        external_ref_instance(&contract, b"app"),
        tag_entry(b"app", sha256(&old_code)),
        code_entry(&old_code),
    ])
    .await;
    let first = fetch_contract_spec(&before.uri(), &contract)
        .await
        .expect("spec before the repoint");
    assert_eq!(function_names(&first), ["alpha"]);

    let after = serve([
        external_ref_instance(&contract, b"app"),
        tag_entry(b"app", sha256(&new_code)),
        code_entry(&new_code),
    ])
    .await;
    let second = fetch_contract_spec(&after.uri(), &contract)
        .await
        .expect("spec after the repoint");
    assert_eq!(
        function_names(&second),
        ["beta"],
        "the spec must follow the code the tag points at now"
    );
}

/// An external reference with no live tag entry is refused naming the owner
/// and the tag, and no code is fetched.
#[tokio::test]
async fn external_reference_without_tag_entry_is_refused() {
    let contract = contract(42);
    let server = serve([external_ref_instance(&contract, b"token\n")]).await;

    let reason = expect_rpc_failure(fetch_contract_spec(&server.uri(), &contract).await);

    assert_eq!(
        reason,
        format!(
            "contract {} executable is an external reference managed by GAAAA...AAWHF under \
             tag \"token\\n\" with no live tag entry",
            redact(&contract)
        )
    );
    assert_eq!(
        server.received_requests().await.expect("recording").len(),
        2,
        "only the instance and the tag entry are requested"
    );
}

/// Discovery of an external-reference contract reads the claim from the code
/// the tag points at.
#[tokio::test]
async fn discover_external_reference_resolves_through_tag_entry() {
    let contract = contract(43);
    let wasm = wasm_with_sep_claim("41,40", "discover_external_ref");
    let server = serve([
        external_ref_instance(&contract, b"token"),
        tag_entry(b"token", sha256(&wasm)),
        code_entry(&wasm),
    ])
    .await;

    let seps = discover_claimed_seps(&server.uri(), &contract)
        .await
        .expect("discovery of an external reference must resolve");

    assert_eq!(seps, ["40", "41"]);
}

/// Discovery refuses an external reference with no live tag entry.
#[tokio::test]
async fn discover_external_reference_without_tag_entry_is_refused() {
    let contract = contract(44);
    let server = serve([external_ref_instance(&contract, b"token")]).await;

    let reason = expect_rpc_failure(discover_claimed_seps(&server.uri(), &contract).await);

    assert!(reason.ends_with("with no live tag entry"), "got: {reason}");
}

/// Discovery returns an empty list for Wasm with no `contractmetav0` section.
#[tokio::test]
async fn discover_claimed_seps_wasm_without_meta_section_returns_empty() {
    let contract = contract(9);
    let wasm = seeded(MINIMAL_WASM, "discover_without_meta");
    let server = serve([wasm_instance(&contract, sha256(&wasm)), code_entry(&wasm)]).await;

    let seps = discover_claimed_seps(&server.uri(), &contract)
        .await
        .expect("discovery must succeed for valid Wasm");

    assert!(
        seps.is_empty(),
        "Wasm without contractmetav0 must return no SEPs"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Code entry verification
// ─────────────────────────────────────────────────────────────────────────────

/// A code entry returned under a key other than the requested one is ignored
/// and the fetch refuses, even when its bytes hash to the requested hash.
#[tokio::test]
async fn code_entry_under_another_key_is_ignored() {
    let contract = contract(50);
    let wasm = seeded(BASE_WASM, "code_under_other_key");
    let hash = sha256(&wasm);
    let foreign = entry(&xdr_fixtures::contract_code_ledger_entries_json(
        [0xee; 32], &wasm,
    ));
    let server = KeyedLedgerEntriesResponder::new()
        .with_entry(wasm_instance(&contract, hash))
        .with_entry_for_key(code_key_b64(hash), foreign)
        .serve()
        .await;

    let reason = expect_rpc_failure(fetch_contract_spec(&server.uri(), &contract).await);

    assert!(
        reason.starts_with("no code ledger entry for Wasm hash "),
        "an entry under another key must be ignored, got: {reason}"
    );
}

/// A code entry whose bytes do not hash to the requested key is refused and
/// nothing is cached: a later call for the same hash fetches code again.
#[tokio::test]
async fn code_entry_with_mismatched_hash_is_refused_and_not_cached() {
    let contract = contract(51);
    let expected = seeded(BASE_WASM, "hash_mismatch_expected");
    let substituted = seeded(BASE_WASM, "hash_mismatch_substituted");
    let hash = sha256(&expected);
    let server = serve([
        wasm_instance(&contract, hash),
        entry(&xdr_fixtures::contract_code_ledger_entries_json(
            hash,
            &substituted,
        )),
    ])
    .await;

    let reason = expect_rpc_failure(fetch_contract_spec(&server.uri(), &contract).await);
    assert!(
        reason.starts_with("code hash mismatch: "),
        "bytes that do not hash to the key must be refused, got: {reason}"
    );

    let instance_only = serve([wasm_instance(&contract, hash)]).await;
    let reason = expect_rpc_failure(fetch_contract_spec(&instance_only.uri(), &contract).await);
    assert!(
        reason.starts_with("no code ledger entry for Wasm hash "),
        "a refused fetch must not populate the cache, got: {reason}"
    );
    assert_eq!(code_fetch_count(&instance_only, hash).await, 1);
}

/// First-5-last-5 redaction as `spec.rs` renders contract strkeys.
fn redact(strkey: &str) -> String {
    format!("{}...{}", &strkey[..5], &strkey[strkey.len() - 5..])
}
