//! Adversarial fixture: `contract_instance_unsupported_rejection`.
//!
//! Scenario: a verifier or policy contract's instance entry exists but does
//! not decode as contract-instance data, its executable is not Wasm, or its
//! executable is a CAP-85 external reference.  Such a contract has no Wasm
//! hash the wallet can pin: the signing-time drift check cannot observe a
//! change to its code, and an external reference's owner can repoint it at
//! any time.  `pin_referenced_contracts` MUST return
//! `SaError::ContractInstanceUnsupported` with
//! `wire_code = "sa.contract_instance_unsupported"` whatever override flags
//! are set, and MUST NOT emit a `SaMutableContractOverride` audit row.
//!
//! Where the refusal happens decides which override rows can exist:
//!
//! - A Stellar Asset Contract instance has no Wasm hash, so identification
//!   reports an allowlist miss; with `accept_unknown_verifier` the install
//!   records the unknown-hash override and the mutability probe then refuses.
//! - An undecodable instance and an external reference are refused by the
//!   identification fetch itself, before either override flag is consulted,
//!   so no override row of either kind is written.

use std::io::{BufRead, BufReader};
use std::sync::Arc;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{ContractKind, EventKind};
use stellar_agent_smart_account::error::{AdminOrOwnerKey, SaError};
use stellar_agent_smart_account::managers::rules::RuleContext;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRulePolicy, ContextRuleSignerInput,
};
use stellar_agent_smart_account::managers::verifiers::pin_referenced_contracts;
use stellar_xdr::{
    ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint,
    Hash, ScAddress, ScContractInstance, ScVal,
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

/// Referenced contract address (`[0x51; 32]`), distinct from all other fixture addresses.
fn contract_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x51u8; 32])))
}

/// Smart-account address (`[0x52; 32]`).
fn smart_account_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x52u8; 32])))
}

// ── XDR builders ──────────────────────────────────────────────────────────────

/// Encodes a contract instance whose executable is the built-in Stellar Asset
/// contract (`ContractExecutable::StellarAsset`), which carries no Wasm hash.
///
/// # Byte-layout citation
///
/// `ContractExecutableType` discriminants in stellar-xdr v26.0.1
/// `src/curr/generated.rs:11504-11505`: `Wasm = 0`, `StellarAsset = 1`.
fn non_wasm_instance_xdr(contract: &ScAddress) -> String {
    LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: contract.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::StellarAsset,
            storage: None,
        }),
    })
    .to_xdr_base64(Limits::none())
    .expect("non-Wasm ContractInstance XDR must encode")
}

/// Base64 of `"notvalidxdr"`: valid base64 that does not decode as `LedgerEntryData`.
const UNDECODABLE_ENTRY_XDR: &str = "bm90dmFsaWR4ZHI=";

fn ledger_entries(contract: &ScAddress, entry_xdr: &str) -> serde_json::Value {
    serde_json::json!({
        "entries": [{
            "key": contract_instance_key_xdr(contract),
            "xdr": entry_xdr,
            "lastModifiedLedgerSeq": 100
        }],
        "latestLedger": 1000
    })
}

fn read_audit_entries(log_path: &std::path::Path) -> Vec<AuditEntry> {
    let file = std::fs::File::open(log_path).expect("audit log must be readable");
    BufReader::new(file)
        .lines()
        .map(|line| line.expect("audit log line must be readable"))
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<AuditEntry>(line.trim()).expect("audit row must parse"))
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Both instance shapes, for both contract kinds, with and without
/// `accept_mutable_verifier`, are refused with
/// `sa.contract_instance_unsupported` and write no mutable-override row.
/// The SAC instance reaches the mutability probe through the unknown-hash
/// override; the undecodable instance is refused at identification, before
/// any override row.
#[tokio::test]
async fn unpinnable_instance_rejected_regardless_of_mutable_override() {
    let contract = contract_addr();
    for (entry_xdr, reason, expect_unknown_override_row) in [
        (
            UNDECODABLE_ENTRY_XDR.to_owned(),
            AdminOrOwnerKey::UndecodableInstance,
            false,
        ),
        (
            non_wasm_instance_xdr(&contract),
            AdminOrOwnerKey::NonWasmExecutable,
            true,
        ),
    ] {
        for contract_kind in [ContractKind::Verifier, ContractKind::Policy] {
            for accept_mutable_verifier in [false, true] {
                let server = MockServer::start().await;
                Mock::given(method("POST"))
                    .and(path("/"))
                    .respond_with(JsonRpcResultResponder(ledger_entries(
                        &contract, &entry_xdr,
                    )))
                    .mount(&server)
                    .await;

                let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
                let manager = manager_one_url(
                    &server.uri(),
                    Arc::clone(&audit_writer),
                    audit_log_path.clone(),
                );

                let (signers, policies) = if contract_kind == ContractKind::Policy {
                    (
                        vec![ContextRuleSignerInput::Delegated {
                            address: ScAddress::Account(stellar_xdr::AccountId(
                                stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(
                                    [0x11u8; 32],
                                )),
                            )),
                        }],
                        vec![ContextRulePolicy::new(contract.clone(), ScVal::Void)],
                    )
                } else {
                    (
                        vec![ContextRuleSignerInput::External {
                            verifier: contract.clone(),
                            pubkey_data: vec![0xbbu8; 32],
                        }],
                        vec![],
                    )
                };
                let definition = ContextRuleDefinition::new(
                    RuleContext::Default,
                    "unsupported-instance".to_owned(),
                    None,
                    signers,
                    policies,
                );

                let result = pin_referenced_contracts(
                    &manager,
                    Some(&audit_writer),
                    smart_account_addr(),
                    ZERO_CONTRACT_REDACTED,
                    &definition,
                    0,
                    SOURCE_G,
                    accept_mutable_verifier,
                    true, // accept_unknown_verifier: reach the mutability step
                    "stellar:testnet",
                    Uuid::new_v4().to_string(),
                )
                .await;

                let case = format!(
                    "reason={reason}, kind={contract_kind}, \
                     accept_mutable_verifier={accept_mutable_verifier}"
                );
                let error = result.expect_err(&case);
                assert_eq!(
                    error.wire_code(),
                    "sa.contract_instance_unsupported",
                    "{case}: {error:?}"
                );
                assert!(
                    matches!(
                        &error,
                        SaError::ContractInstanceUnsupported {
                            contract_kind: actual_kind,
                            reason: actual_reason,
                            ..
                        } if *actual_kind == contract_kind && *actual_reason == reason
                    ),
                    "{case}: {error:?}"
                );

                let entries = read_audit_entries(&audit_log_path);
                assert_eq!(
                    entries.iter().any(|e| matches!(
                        e.event_kind,
                        EventKind::SaUnknownContractOverride { .. }
                    )),
                    expect_unknown_override_row,
                    "{case}: unknown-hash override row presence"
                );
                assert!(
                    !entries.iter().any(|e| matches!(
                        e.event_kind,
                        EventKind::SaMutableContractOverride { .. }
                    )),
                    "{case}: no mutable-override row may be written"
                );
            }
        }
    }
}

/// A verifier or policy whose instance executable is an external reference is
/// refused with `ContractInstanceUnsupported { reason: ExternalRefExecutable }`
/// even with `accept_mutable_verifier` and `accept_unknown_verifier` both set,
/// and even though the owner's tag entry currently resolves to an allowlisted
/// hash. The refusal comes from identification, before either override
/// branch, so no override row of either kind is written.
#[tokio::test]
async fn external_ref_instance_rejected_before_any_override() {
    use stellar_agent_test_support::{KeyedLedgerEntriesResponder, xdr_fixtures};

    const OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    let contract = contract_addr();
    let contract_strkey =
        stellar_agent_core::sc_address::scaddress_to_strkey(&contract).expect("contract strkey");

    for contract_kind in [ContractKind::Verifier, ContractKind::Policy] {
        let allowlisted = if contract_kind == ContractKind::Verifier {
            stellar_agent_smart_account::VERIFIER_ALLOWLIST[0].wasm_hash
        } else {
            super::rpc_mock_helpers::KNOWN_WASM_HASH
        };
        let responder = KeyedLedgerEntriesResponder::new()
            .with_entry(xdr_fixtures::ledger_entry_from_response_json(
                &xdr_fixtures::external_ref_instance_ledger_entries_json(
                    &contract_strkey,
                    OWNER,
                    b"verifier-v1",
                ),
            ))
            .with_entry(xdr_fixtures::ledger_entry_from_response_json(
                &xdr_fixtures::executable_tag_ledger_entries_json(
                    OWNER,
                    b"verifier-v1",
                    allowlisted,
                ),
            ));
        let server = responder.serve().await;

        let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
        let manager = manager_one_url(
            &server.uri(),
            Arc::clone(&audit_writer),
            audit_log_path.clone(),
        );

        let (signers, policies) = if contract_kind == ContractKind::Policy {
            (
                vec![ContextRuleSignerInput::Delegated {
                    address: ScAddress::Account(stellar_xdr::AccountId(
                        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(
                            [0x11u8; 32],
                        )),
                    )),
                }],
                vec![ContextRulePolicy::new(contract.clone(), ScVal::Void)],
            )
        } else {
            (
                vec![ContextRuleSignerInput::External {
                    verifier: contract.clone(),
                    pubkey_data: vec![0xbbu8; 32],
                }],
                vec![],
            )
        };
        let definition = ContextRuleDefinition::new(
            RuleContext::Default,
            "external-ref-instance".to_owned(),
            None,
            signers,
            policies,
        );

        let result = pin_referenced_contracts(
            &manager,
            Some(&audit_writer),
            smart_account_addr(),
            ZERO_CONTRACT_REDACTED,
            &definition,
            0,
            SOURCE_G,
            true, // accept_mutable_verifier
            true, // accept_unknown_verifier
            "stellar:testnet",
            Uuid::new_v4().to_string(),
        )
        .await;

        let case = format!("kind={contract_kind}");
        let error = result.expect_err(&case);
        assert_eq!(
            error.wire_code(),
            "sa.contract_instance_unsupported",
            "{case}: {error:?}"
        );
        assert!(
            matches!(
                &error,
                SaError::ContractInstanceUnsupported {
                    contract_kind: actual_kind,
                    reason: AdminOrOwnerKey::ExternalRefExecutable,
                    ..
                } if *actual_kind == contract_kind
            ),
            "{case}: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("owner-managed external reference"),
            "{case}: {error}"
        );

        let entries = read_audit_entries(&audit_log_path);
        assert!(
            !entries.iter().any(|e| matches!(
                e.event_kind,
                EventKind::SaUnknownContractOverride { .. }
                    | EventKind::SaMutableContractOverride { .. }
            )),
            "{case}: no override row of either kind may be written"
        );
    }
}
