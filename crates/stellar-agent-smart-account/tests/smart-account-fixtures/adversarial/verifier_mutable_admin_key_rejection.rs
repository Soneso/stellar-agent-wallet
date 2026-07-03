//! Adversarial fixture: `verifier_mutable_admin_key_rejection`.
//!
//! Scenario: the verifier contract's instance storage contains an `Admin` key
//! with a non-zero `ScVal::Address`.  `pin_referenced_contracts` MUST return
//! `SaError::VerifierMutable` with `wire_code = "sa.verifier_mutable"` when
//! `accept_mutable_verifier = false`.
//!
//! This is the primary "mutable verifier → install refused" adversarial case.
//!
//! # Implements
//!
//! Verifier-pinning refusal path: a mutable verifier (admin key present) must be rejected.

use std::sync::Arc;

use stellar_agent_smart_account::VERIFIER_ALLOWLIST;
use stellar_agent_smart_account::bindings::ContextRuleType;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::rules::{ContextRuleDefinition, ContextRuleSignerInput};
use stellar_agent_smart_account::managers::verifiers::pin_referenced_contracts;
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

/// Verifier contract address (`[0x07; 32]`), distinct from zero and policy addresses.
fn verifier_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x07u8; 32])))
}

/// Smart-account address (`[0x08; 32]`).
fn smart_account_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x08u8; 32])))
}

/// Admin holder address (Ed25519 account, all `0xaa` bytes).
fn admin_holder_xdr_address() -> stellar_xdr::ScAddress {
    stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([0xaau8; 32])),
    ))
}

// ── XDR builder ──────────────────────────────────────────────────────────────

/// Encodes a contract instance whose instance storage contains `{ Admin: admin_addr }`.
///
/// The contract WASM hash is `VERIFIER_ALLOWLIST[0].wasm_hash` so the allowlist
/// check passes; only the mutability check should fire.
///
/// # Byte-layout citation
///
/// `ScContractInstance.storage: Option<ScMap>` — `xdr/curr/Stellar-contract.x`
/// `SCContractInstance` (stellar-xdr v26.0.0).  Admin key encoding:
/// `AccessControlStorageKey::Admin` encodes on-wire as
/// `ScVal::Vec([Symbol("Admin")])`.
/// `soroban-sdk-macros` `derive_enum.rs` (`map_empty_variant` + `TryFrom<&Enum> for ScVal`).
fn mutable_verifier_instance_xdr(contract: &ScAddress) -> String {
    let symbol = ScVal::Symbol(ScSymbol(b"Admin".to_vec().try_into().expect("Admin fits")));
    let entry = ScMapEntry {
        key: ScVal::Vec(Some(ScVec(
            vec![symbol].try_into().expect("single-element ScVec fits"),
        ))),
        val: ScVal::Address(admin_holder_xdr_address()),
    };
    let storage_map: ScMap = vec![entry].try_into().expect("one ScMapEntry fits");
    let instance = ScContractInstance {
        executable: ContractExecutable::Wasm(Hash(VERIFIER_ALLOWLIST[0].wasm_hash)),
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
    .expect("mutable verifier ContractInstance XDR must encode")
}

fn mutable_verifier_ledger_entries(verifier: &ScAddress) -> serde_json::Value {
    let key_xdr = contract_instance_key_xdr(verifier);
    let entry_xdr = mutable_verifier_instance_xdr(verifier);
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

/// Without `--accept-mutable-verifier`, installing a rule whose verifier has a
/// non-zero `Admin` storage key must return `SaError::VerifierMutable` with
/// `wire_code = "sa.verifier_mutable"`.
#[tokio::test]
async fn verifier_with_admin_key_rejected_without_override() {
    let verifier = verifier_addr();
    let smart_account = smart_account_addr();
    let ledger_entries = mutable_verifier_ledger_entries(&verifier);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(JsonRpcResultResponder(ledger_entries))
        .mount(&server)
        .await;

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(&server.uri(), Arc::clone(&audit_writer), audit_log_path);

    // Build a rule definition with one External signer referencing the mutable verifier.
    let definition = ContextRuleDefinition::new(
        ContextRuleType::Default,
        "mutable-verifier-test".to_owned(),
        None,
        vec![ContextRuleSignerInput::External {
            verifier: verifier.clone(),
            pubkey_data: vec![0xbbu8; 32],
        }],
        vec![],
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
        matches!(result, Err(SaError::VerifierMutable { .. })),
        "mutable verifier must be refused without accept_mutable_verifier; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "sa.verifier_mutable",
        "wire_code must be 'sa.verifier_mutable'"
    );
}
