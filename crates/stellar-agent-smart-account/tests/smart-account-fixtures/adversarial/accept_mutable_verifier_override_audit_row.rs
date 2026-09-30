//! Adversarial fixture: `accept_mutable_verifier_override_audit_row`.
//!
//! Scenario: the verifier contract has a non-zero `Admin` storage key (mutable),
//! but `accept_mutable_verifier = true` is set.  `pin_referenced_contracts` MUST:
//! 1. Succeed (return `Ok(PinResult)` with `mutable_override = true`).
//! 2. Return one pending mutable override naming the verifier, which the
//!    install writes as its `SaMutableContractOverride` row after it
//!    confirms.
//! 3. Write no audit row itself, although the signers manager holds a
//!    writer: a refused install leaves no override row.

use std::sync::Arc;

use stellar_agent_core::audit_log::schema::ContractKind;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_smart_account::VERIFIER_ALLOWLIST;
use stellar_agent_smart_account::managers::rules::RuleContext;
use stellar_agent_smart_account::managers::rules::{ContextRuleDefinition, ContextRuleSignerInput};
use stellar_agent_smart_account::managers::verifiers::{
    PendingOverride, PendingOverrideKind, pin_referenced_contracts,
};
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

// ── Tests ─────────────────────────────────────────────────────────────────────

/// With `accept_mutable_verifier = true`, pinning a rule whose verifier has a
/// non-zero `Admin` storage key succeeds with `mutable_override: true` and one
/// pending mutable override naming the verifier, and writes no audit row.
#[tokio::test]
async fn accept_mutable_verifier_succeeds_with_a_pending_override_and_writes_no_row() {
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

    let result = pin_referenced_contracts(
        &manager,
        smart_account,
        ZERO_CONTRACT_REDACTED,
        &definition,
        None,
        SOURCE_G,
        true,  // accept_mutable_verifier — MUST succeed
        false, // accept_unknown_verifier
        Uuid::new_v4().to_string(),
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

    // The override is pending: one mutable entry naming the verifier, with
    // no external reference for an admin storage key.
    let verifier_redacted = redact_strkey_first5_last5(
        &stellar_agent_core::sc_address::scaddress_to_strkey(&verifier).expect("verifier strkey"),
    );
    assert!(
        matches!(
            pin_result.pending_overrides.as_slice(),
            [PendingOverride {
                kind: PendingOverrideKind::Mutable {
                    executable_ref: None,
                },
                contract_redacted,
                contract_kind: ContractKind::Verifier,
                ..
            }] if contract_redacted.as_str() == verifier_redacted
        ),
        "one pending mutable override for the verifier: {:?}",
        pin_result.pending_overrides
    );

    // Pinning writes nothing; the install writes the row after it confirms.
    let audit_log = std::fs::read_to_string(&audit_log_path).unwrap_or_default();
    assert!(
        audit_log.is_empty(),
        "pinning writes no audit row: {audit_log}"
    );
}
