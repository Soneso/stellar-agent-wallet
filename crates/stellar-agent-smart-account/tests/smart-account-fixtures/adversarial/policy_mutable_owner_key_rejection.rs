//! Adversarial fixture: `policy_mutable_owner_key_rejection`.
//!
//! Scenario: the policy contract's instance storage contains an `Owner` key
//! with a non-zero `ScVal::Address`.  `pin_referenced_contracts` MUST return
//! `SaError::PolicyMutable` with `wire_code = "sa.policy_mutable"` when
//! `accept_mutable_verifier = false`.
//!
//! This is the "mutable policy → install refused" adversarial case
//! (refusal path).
//!
//! Verifies the verifier-pinning requirement: mutable policies are rejected
//! when `accept_mutable_verifier` is false.

use std::sync::Arc;

use stellar_agent_smart_account::bindings::ContextRuleType;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRulePolicy, ContextRuleSignerInput,
};
use stellar_agent_smart_account::managers::verifiers::pin_referenced_contracts;
use stellar_agent_smart_account::signers::policy_identification::THRESHOLD_POLICY_WASM_HASHES;
use stellar_xdr::{
    ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint,
    Hash, ScAddress, ScContractInstance, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec,
};
use stellar_xdr::{LedgerEntryData, Limits, WriteXdr};
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::combined_rpc_responder::JsonRpcResultResponder;
use super::rpc_mock_helpers::{
    SOURCE_G, ZERO_CONTRACT_REDACTED, contract_instance_key_xdr, manager_one_url, tmp_audit_writer,
};

// ── Address helpers ───────────────────────────────────────────────────────────

/// Policy contract address (`[0x11; 32]`), distinct from zero and verifier addresses.
fn policy_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x11u8; 32])))
}

/// Smart-account address (`[0x12; 32]`).
fn smart_account_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x12u8; 32])))
}

/// Owner holder address (Ed25519 account, all `0xbb` bytes).
fn owner_holder_xdr_address() -> stellar_xdr::ScAddress {
    stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([0xbbu8; 32])),
    ))
}

// ── XDR builder ──────────────────────────────────────────────────────────────

/// Encodes a contract instance whose instance storage contains `{ Owner: owner_addr }`.
///
/// The contract WASM hash is `THRESHOLD_POLICY_WASM_HASHES[0]` so the allowlist
/// check passes; only the mutability check should fire.
///
/// # Byte-layout citation
///
/// `ScContractInstance.storage: Option<ScMap>` — `xdr/curr/Stellar-contract.x`
/// `SCContractInstance` (stellar-xdr v26.0.0).  Owner key encoding:
/// `OwnableStorageKey::Owner` encodes on-wire as
/// `ScVal::Vec([Symbol("Owner")])`.
/// `soroban-sdk-macros` `derive_enum.rs` (`map_empty_variant` + `TryFrom<&Enum> for ScVal`).
fn mutable_policy_instance_xdr(contract: &ScAddress) -> String {
    let symbol = ScVal::Symbol(ScSymbol(b"Owner".to_vec().try_into().expect("Owner fits")));
    let entry = ScMapEntry {
        key: ScVal::Vec(Some(ScVec(
            vec![symbol].try_into().expect("single-element ScVec fits"),
        ))),
        val: ScVal::Address(owner_holder_xdr_address()),
    };
    let storage_map: ScMap = vec![entry].try_into().expect("one ScMapEntry fits");
    let instance = ScContractInstance {
        executable: ContractExecutable::Wasm(Hash(THRESHOLD_POLICY_WASM_HASHES[0])),
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
    .expect("mutable policy ContractInstance XDR must encode")
}

fn mutable_policy_ledger_entries(policy: &ScAddress) -> serde_json::Value {
    let key_xdr = contract_instance_key_xdr(policy);
    let entry_xdr = mutable_policy_instance_xdr(policy);
    serde_json::json!({
        "entries": [{
            "key": key_xdr,
            "xdr": entry_xdr,
            "lastModifiedLedgerSeq": 100
        }],
        "latestLedger": 1000
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Without `--accept-mutable-verifier`, installing a rule whose policy has a
/// non-zero `Owner` storage key must return `SaError::PolicyMutable` with
/// `wire_code = "sa.policy_mutable"`.
///
/// Verifies the refusal path: a mutable policy is rejected when
/// `accept_mutable_verifier` is not set.
#[tokio::test]
async fn policy_with_owner_key_rejected_without_override() {
    let policy = policy_addr();
    let smart_account = smart_account_addr();
    let ledger_entries = mutable_policy_ledger_entries(&policy);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(JsonRpcResultResponder(ledger_entries))
        .mount(&server)
        .await;

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(&server.uri(), Arc::clone(&audit_writer), audit_log_path);

    // Rule with one Delegated signer (no verifier) and one mutable policy.
    let definition = ContextRuleDefinition::new(
        ContextRuleType::Default,
        "mutable-policy-test".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
                stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([0x11u8; 32])),
            )),
        }],
        vec![ContextRulePolicy::new(
            policy.clone(),
            ScVal::Void, // placeholder params — not decoded by pin_referenced_contracts
        )],
    );

    let result = pin_referenced_contracts(
        &manager,
        Some(&audit_writer),
        smart_account,
        ZERO_CONTRACT_REDACTED,
        &definition,
        0,
        SOURCE_G,
        false, // accept_mutable_verifier — MUST refuse
        false, // accept_unknown_verifier
        "stellar:testnet",
        Uuid::new_v4().to_string(),
    )
    .await;

    assert!(
        matches!(result, Err(SaError::PolicyMutable { .. })),
        "mutable policy must be refused without accept_mutable_verifier; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "sa.policy_mutable",
        "wire_code must be 'sa.policy_mutable'"
    );
}
