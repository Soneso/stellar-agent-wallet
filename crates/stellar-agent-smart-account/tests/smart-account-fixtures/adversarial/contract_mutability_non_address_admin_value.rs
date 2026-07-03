//! Adversarial fixture: `Admin` storage key with a non-address value fails closed.

use stellar_agent_network::StellarRpcClient;
use stellar_agent_smart_account::error::AdminOrOwnerKey;
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

fn contract_under_test() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x17u8; 32])))
}

fn contract_instance_key_xdr(addr: &ScAddress) -> String {
    LedgerKey::ContractData(LedgerKeyContractData {
        contract: addr.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    })
    .to_xdr_base64(Limits::none())
    .expect("LedgerKey XDR must encode")
}

fn contract_instance_entry_xdr_with_non_address_admin(contract: &ScAddress) -> String {
    // `#[contracttype]` unit variant `Admin` → `ScVal::Vec([Symbol("Admin")])`.
    // See `soroban-sdk-macros` `derive_enum.rs` (`map_empty_variant` + `TryFrom<&Enum> for ScVal`).
    let symbol = ScVal::Symbol(ScSymbol(b"Admin".to_vec().try_into().expect("Admin fits")));
    let entry = ScMapEntry {
        key: ScVal::Vec(Some(ScVec(
            vec![symbol].try_into().expect("single-element ScVec fits"),
        ))),
        val: ScVal::U32(0),
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
        val: ScVal::ContractInstance(instance),
    })
    .to_xdr_base64(Limits::none())
    .expect("ContractInstance XDR must encode")
}

fn ledger_entries_with_non_address_admin(contract: &ScAddress) -> serde_json::Value {
    serde_json::json!({
        "entries": [{
            "key": contract_instance_key_xdr(contract),
            "xdr": contract_instance_entry_xdr_with_non_address_admin(contract),
            "lastModifiedLedgerSeq": 100
        }],
        "latestLedger": 1000
    })
}

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

#[tokio::test]
async fn non_address_admin_value_returns_mutable() {
    let contract = contract_under_test();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CannedLedgerEntriesResponder(
            ledger_entries_with_non_address_admin(&contract),
        ))
        .mount(&server)
        .await;

    let rpc = StellarRpcClient::new(&server.uri()).expect("RPC client must construct");
    let status = detect_contract_mutability(
        &rpc,
        &rpc,
        &contract,
        42,
        "CAAAA...ABSC4",
        "fixture-request-id",
    )
    .await
    .expect("detect_contract_mutability must succeed");

    assert_eq!(
        status,
        MutabilityStatus::Mutable {
            admin_or_owner_key: AdminOrOwnerKey::Admin,
            holder_redacted: "[non-address-admin-value]".to_owned(),
        }
    );
}
