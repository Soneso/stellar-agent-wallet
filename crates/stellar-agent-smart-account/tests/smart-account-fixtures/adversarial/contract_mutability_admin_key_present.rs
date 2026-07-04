//! Adversarial fixture: contract mutability detection when admin key is present.
//!
//! Scenario: both RPCs return a contract instance whose instance storage
//! contains an `Admin` key with a non-zero `ScVal::Address`.
//! `detect_contract_mutability` must return `MutabilityStatus::Mutable` with
//! `admin_or_owner_key = "Admin"`.
//!
//! This validates the happy-path admin-key detection without any RPC
//! disagreement.  The companion test for RPC divergence is embedded in
//! `managers/verifiers.rs::tests::mutability_status_rpc_divergence`.
//!
//! # OZ survey citation
//!
//! `AccessControlStorageKey::Admin` encodes on-wire as
//! `ScVal::Vec(Some(ScVec([ScVal::Symbol("Admin")])))` — not a bare `ScVal::Symbol`.
//! A `#[contracttype]` unit variant `Foo` maps to a one-element `ScVec([Symbol("Foo")])`
//! via `map_empty_variant` `into_xdr` (`soroban-sdk-macros` `derive_enum.rs`),
//! then wrapped in `ScVal::Vec` by `TryFrom<Enum> for ScVal` (same file).
//! Keys are stored in instance storage (`e.storage().instance()`),
//! which embeds in `ScContractInstance.storage: Option<ScMap>`.
//! Source: `packages/access/src/access_control/storage.rs:20-29` (OZ SHA `a9c4216`).
//!
//! # Property verified
//!
//! Verifier pinning: `detect_contract_mutability` correctly identifies a mutable
//! contract when its instance storage contains a recognised admin or owner key.

use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_smart_account::error::{AdminOrOwnerKey, SaError};
use stellar_agent_smart_account::managers::verifiers::{
    MutabilityStatus, detect_contract_mutability,
};
use stellar_xdr::{
    ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint,
    Hash, LedgerKeyContractData, ScAddress, ScContractInstance, ScMap, ScMapEntry, ScSymbol, ScVal,
    ScVec,
};
use stellar_xdr::{LedgerEntryData, LedgerKey, Limits, WriteXdr};
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

// ── Address helpers ───────────────────────────────────────────────────────────

/// Contract under test: distinct from smart account, policy, and zero addresses.
fn contract_under_test() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x07u8; 32])))
}

/// Admin holder address (Ed25519 account, all 0xaa bytes).
fn admin_holder_address() -> stellar_xdr::ScAddress {
    stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([0xaau8; 32])),
    ))
}

// ── XDR builders ─────────────────────────────────────────────────────────────

/// Encodes `LedgerKey::ContractData(LedgerKeyContractInstance)` to XDR base64.
fn contract_instance_key_xdr(addr: &ScAddress) -> String {
    LedgerKey::ContractData(LedgerKeyContractData {
        contract: addr.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    })
    .to_xdr_base64(Limits::none())
    .expect("LedgerKey XDR must encode")
}

/// Encodes a `LedgerEntryData::ContractData(ContractInstance)` to XDR base64,
/// with `ScContractInstance.storage` containing `{ Admin: admin_addr }`.
///
/// # Byte-layout citation
///
/// `ScContractInstance.storage: Option<ScMap>` — `xdr/curr/Stellar-contract.x`
/// `SCContractInstance` (stellar-xdr v26.0.0).
/// `stellar-rpc-client` (rs-stellar-rpc-client) confirms the response
/// `.xdr` field contains `LedgerEntryData` (not `LedgerEntry`).
fn contract_instance_entry_xdr_with_admin(
    contract: &ScAddress,
    admin_addr: &stellar_xdr::ScAddress,
) -> String {
    // `#[contracttype]` unit variant `Admin` → `ScVal::Vec([Symbol("Admin")])`.
    // See `soroban-sdk-macros` `derive_enum.rs` (`map_empty_variant` + `TryFrom<&Enum> for ScVal`).
    let symbol = ScVal::Symbol(ScSymbol(b"Admin".to_vec().try_into().expect("Admin fits")));
    let entry = ScMapEntry {
        key: ScVal::Vec(Some(ScVec(
            vec![symbol].try_into().expect("single-element ScVec fits"),
        ))),
        val: ScVal::Address(admin_addr.clone()),
    };
    let storage_map: ScMap = vec![entry].try_into().expect("one ScMapEntry fits");
    let instance = ScContractInstance {
        executable: ContractExecutable::Wasm(Hash([0x42u8; 32])),
        storage: Some(storage_map),
    };
    LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: contract.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: stellar_xdr::ScVal::ContractInstance(instance),
    })
    .to_xdr_base64(Limits::none())
    .expect("ContractInstance XDR must encode")
}

/// Builds a `getLedgerEntries` JSON-RPC result with a single contract-instance
/// entry containing instance storage.
fn ledger_entries_with_admin(contract: &ScAddress) -> serde_json::Value {
    let key_xdr = contract_instance_key_xdr(contract);
    let entry_xdr = contract_instance_entry_xdr_with_admin(contract, &admin_holder_address());
    serde_json::json!({
        "entries": [{
            "key": key_xdr,
            "xdr": entry_xdr,
            "lastModifiedLedgerSeq": 100
        }],
        "latestLedger": 1000
    })
}

// ── RPC responder ─────────────────────────────────────────────────────────────

/// A `wiremock::Respond` implementation that returns a canned
/// `getLedgerEntries` result for every POST.
struct CannedLedgerEntriesResponder(serde_json::Value);

impl wiremock::Respond for CannedLedgerEntriesResponder {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).unwrap_or(serde_json::json!({}));
        let req_id = body.get("id").cloned().unwrap_or(serde_json::json!(1));
        wiremock::ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": self.0
            }))
            .insert_header("content-type", "application/json")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Both RPCs agree: contract has an `Admin` instance-storage key with a non-zero
/// `ScVal::Address`.  `detect_contract_mutability` returns `Mutable { admin_or_owner_key: AdminOrOwnerKey::Admin }`.
///
/// This is the primary "admin key present → Mutable" adversarial case for
/// `detect_contract_mutability`.
#[tokio::test]
async fn admin_key_present_returns_mutable() {
    let contract = contract_under_test();
    let entries = ledger_entries_with_admin(&contract);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CannedLedgerEntriesResponder(entries))
        .mount(&server)
        .await;

    let rpc = StellarRpcClient::new(&server.uri()).expect("RPC client must construct");

    let result = detect_contract_mutability(
        &rpc,
        &rpc,
        &contract,
        42,
        "CAAAA...ABSC4",
        "fixture-request-id",
    )
    .await;

    let status = result.expect("detect_contract_mutability must succeed");

    assert!(
        matches!(
            &status,
            MutabilityStatus::Mutable {
                admin_or_owner_key: AdminOrOwnerKey::Admin,
                ..
            }
        ),
        "contract with Admin key must yield Mutable {{ admin_or_owner_key: \"Admin\" }}; got {status:?}"
    );

    // Verify the holder is redacted (first-5-last-5 of the G-strkey for [0xaa; 32]).
    if let MutabilityStatus::Mutable {
        holder_redacted, ..
    } = &status
    {
        assert!(
            holder_redacted.contains("..."),
            "holder_redacted must be first-5-last-5 redacted; got {holder_redacted}"
        );
        assert_eq!(
            holder_redacted.len(),
            // "GAAAA...AAAAA" style: 5 + "..." + 5 = 13 chars
            13,
            "holder_redacted must be 13 chars (first-5 + '...' + last-5); got {holder_redacted}"
        );
    }
}

/// Wire code produced by `SaError::NetworkRpcDivergence` is `"network.rpc_divergence"`.
///
/// Type-level check verifying the wire code is consistent from this fixture's
/// perspective (mirrors the parallel check in `verifier_identification_rpc_divergence.rs`).
#[test]
fn contract_mutability_rpc_divergence_wire_code_is_consistent() {
    let err = SaError::NetworkRpcDivergence {
        rule_id: 42,
        smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ABSC4"),
        primary_view_digest_first8: "aabbccdd".to_owned(),
        secondary_view_digest_first8: "11223344".to_owned(),
        request_id: "fixture-request-id".to_owned(),
    };
    assert_eq!(
        err.wire_code(),
        "network.rpc_divergence",
        "NetworkRpcDivergence wire code must be 'network.rpc_divergence'"
    );
}
