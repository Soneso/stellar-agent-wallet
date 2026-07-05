//! Adversarial fixture: `accept_mutable_verifier_override_audit_row`.
//!
//! Scenario: the verifier contract has a non-zero `Admin` storage key (mutable),
//! but `accept_mutable_verifier = true` is set.  `pin_referenced_contracts` MUST:
//! 1. Succeed (return `Ok(PinResult)` with `mutable_override = true`).
//! 2. Emit a `SaMutableContractOverride` audit row BEFORE returning.
//! 3. The override row's `request_id` matches the caller-supplied UUID.
//!
//! This validates the "accept-mutable-verifier override emits audit row" path
//! (override path with operator-supplied flag).

use std::io::{BufRead, BufReader};
use std::sync::Arc;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{ContractKind, EventKind};
use stellar_agent_smart_account::VERIFIER_ALLOWLIST;
use stellar_agent_smart_account::managers::rules::RuleContext;
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

/// Verifier contract address (`[0x40; 32]`), distinct from all other fixture addresses.
fn verifier_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x40u8; 32])))
}

/// Smart-account address (`[0x41; 32]`).
fn smart_account_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x41u8; 32])))
}

fn admin_holder_xdr_address() -> stellar_xdr::ScAddress {
    stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([0xccu8; 32])),
    ))
}

// ── XDR builder ──────────────────────────────────────────────────────────────

/// Contract instance with `Admin` storage key (mutable) and the allowlisted
/// `VERIFIER_ALLOWLIST[0].wasm_hash` WASM hash.
///
/// # Byte-layout citation
///
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
    .expect("mutable verifier instance XDR must encode")
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

// ── Helpers ───────────────────────────────────────────────────────────────────

fn read_audit_entries(log_path: &std::path::Path) -> Vec<AuditEntry> {
    let file = std::fs::File::open(log_path).expect("audit log must be readable");
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(trimmed) {
            entries.push(entry);
        }
    }
    entries
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// With `accept_mutable_verifier = true`, installing a rule whose verifier has
/// a non-zero `Admin` storage key must succeed, return `PinResult { mutable_override: true }`,
/// AND emit a `SaMutableContractOverride` audit row with the same `request_id`.
#[tokio::test]
async fn accept_mutable_verifier_succeeds_and_emits_override_audit_row() {
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
    let manager = manager_one_url(
        &server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );

    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "accept-mutable-verifier-test".to_owned(),
        None,
        vec![ContextRuleSignerInput::External {
            verifier: verifier.clone(),
            pubkey_data: vec![0xddu8; 32],
        }],
        vec![],
    );

    let request_id = Uuid::new_v4().to_string();

    let result = pin_referenced_contracts(
        &manager,
        Some(&audit_writer),
        smart_account,
        ZERO_CONTRACT_REDACTED,
        &definition,
        0,
        SOURCE_G,
        true,  // accept_mutable_verifier — MUST succeed
        false, // accept_unknown_verifier
        "stellar:testnet",
        request_id.clone(),
    )
    .await;

    let pin_result = result.expect(
        "pin_referenced_contracts must succeed when accept_mutable_verifier = true; got error",
    );

    // mutable_override must be set.
    assert!(
        pin_result.mutable_override,
        "PinResult::mutable_override must be true when Admin key present and override accepted"
    );

    // The verifier hash must be pinned (non-empty).
    assert!(
        !pin_result.pinned_verifier_wasm_hashes.is_empty(),
        "pinned_verifier_wasm_hashes must be non-empty after successful pin"
    );

    // SaMutableContractOverride audit row must be emitted.
    let entries = read_audit_entries(&audit_log_path);
    let override_row = entries.iter().find(|e| {
        matches!(
            &e.event_kind,
            EventKind::SaMutableContractOverride { contract_kind, .. }
                if *contract_kind == ContractKind::Verifier
        )
    });
    assert!(
        override_row.is_some(),
        "SaMutableContractOverride audit row (contract_kind='verifier') must be emitted"
    );

    // Verify request_id correlation.
    let override_entry = override_row.unwrap();
    assert_eq!(
        override_entry.request_id, request_id,
        "SaMutableContractOverride row must carry the same request_id"
    );
}
