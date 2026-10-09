//! Envelope-shape regression guards for the RPC-dependent SEP-48/SEP-47 arms.
//!
//! `stellar_sep48_preview_invocation` and `stellar_sep47_discover` both call
//! into `stellar-agent-sep48`'s RPC fetch path
//! (`fetch_contract_spec`/`discover_claimed_seps`, which share the same
//! resolve-then-fetch-code `getLedgerEntries` flow). These tests serve that
//! RPC through a keyed responder, each entry under its real ledger key, to
//! force each documented business-error arm and assert the full envelope
//! shape (`ok:false`, the documented wire code, a non-empty `request_id`,
//! `is_error == Some(true)`), mirroring the offline RPC-path coverage at the
//! `stellar-agent-sep48` crate level in `spec_rpc_coverage.rs`.
//!
//! The SEP-48 spec cache is process-global and keyed by Wasm hash, so a spec
//! cached by one test would be observed by any other test in this binary
//! that fetches code with the same hash. Every test that fetches code
//! therefore appends a custom section carrying its own seed string to the
//! fixture Wasm, which gives it code with a hash no other test uses. Seeds
//! carry a `sep48_sep47_envelope_shape/` prefix so they are also distinct
//! from the seeds in the sep48 crate's own tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{Sep47DiscoverArgs, Sep48PreviewInvocationArgs, WalletServer};
use stellar_agent_test_support::{KeyedLedgerEntriesResponder, xdr_fixtures};

// The SEP-41 token fixture Wasm, committed for `stellar-agent-sep48`'s own
// offline RPC-path coverage; has a valid `contractspecv0` section with an
// `approve` function.
const WASM_BYTES: &[u8] =
    include_bytes!("../../../stellar-agent-sep48/tests/fixtures/sep41_token.wasm");

/// A valid contract C-strkey seeded by `seed`.
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

/// Returns `wasm` with a trailing custom section carrying `seed`, so the
/// result has a hash unique to `seed` and parses to the same spec.
fn seeded(wasm: &[u8], seed: &str) -> Vec<u8> {
    let name = b"test_seed";
    let data = format!("sep48_sep47_envelope_shape/{seed}");
    let body_len = 1 + name.len() + data.len();
    assert!(
        body_len < 0x80,
        "seed section must fit one-byte LEB128 sizes"
    );
    let mut out = wasm.to_vec();
    out.push(0x00);
    out.push(u8::try_from(body_len).unwrap());
    out.push(u8::try_from(name.len()).unwrap());
    out.extend_from_slice(name);
    out.extend_from_slice(data.as_bytes());
    out
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
/// with wire code `sep48.spec_fetch_failed` when the endpoint returns no
/// instance entry for the contract, the cheapest honest way to force
/// `fetch_contract_spec`'s RPC-fetch failure without a live network.
#[tokio::test]
async fn preview_invocation_empty_instance_entries_returns_spec_fetch_failed_envelope() {
    let contract = contract_strkey(20);
    let mock_server = KeyedLedgerEntriesResponder::new().serve().await;

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

    let (code, _message, _text) = crate::common::assert_business_envelope(&result);
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
    let wasm = seeded(WASM_BYTES, "unknown_function");
    let wasm_hash = sha256(&wasm);

    let mock_server = KeyedLedgerEntriesResponder::new()
        .with_entry(xdr_fixtures::ledger_entry_from_response_json(
            &xdr_fixtures::contract_instance_ledger_entries_json(&contract, wasm_hash),
        ))
        .with_entry(xdr_fixtures::ledger_entry_from_response_json(
            &xdr_fixtures::contract_code_ledger_entries_json(wasm_hash, &wasm),
        ))
        .serve()
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

    let (code, _message, _text) = crate::common::assert_business_envelope(&result);
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
/// code `sep47.discovery_failed` when the endpoint returns no instance entry.
/// `discover_claimed_seps` resolves the Wasm hash through the same step as
/// `fetch_contract_spec`, so the identical empty responder forces the same
/// underlying `Sep48Error::RpcFetchFailure`.
#[tokio::test]
async fn discover_empty_instance_entries_returns_discovery_failed_envelope() {
    let contract = contract_strkey(22);
    let mock_server = KeyedLedgerEntriesResponder::new().serve().await;

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

    let (code, _message, _text) = crate::common::assert_business_envelope(&result);
    assert_eq!(
        code, "sep47.discovery_failed",
        "an empty instance-entries RPC response must surface sep47.discovery_failed"
    );
}
