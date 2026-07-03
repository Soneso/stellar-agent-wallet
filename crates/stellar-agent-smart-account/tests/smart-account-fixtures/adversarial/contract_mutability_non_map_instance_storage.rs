//! Adversarial fixture: malformed instance storage decodes as a non-map ScVal.

use stellar_agent_network::StellarRpcClient;
use stellar_agent_smart_account::error::AdminOrOwnerKey;
use stellar_agent_smart_account::managers::verifiers::{
    MutabilityStatus, detect_contract_mutability,
};
use stellar_xdr::{
    ContractDataDurability, ContractDataEntry, ContractId, ExtensionPoint, Hash,
    LedgerKeyContractData, ScAddress, ScBytes, ScVal,
};
use stellar_xdr::{LedgerEntryData, LedgerKey, Limits, WriteXdr};
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

fn contract_under_test() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x18u8; 32])))
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

fn malformed_contract_instance_entry_xdr(contract: &ScAddress) -> String {
    LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: contract.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::Bytes(ScBytes(vec![0xde, 0xad].try_into().expect("bytes fit"))),
    })
    .to_xdr_base64(Limits::none())
    .expect("ContractData XDR must encode")
}

fn ledger_entries_with_non_map_storage(contract: &ScAddress) -> serde_json::Value {
    serde_json::json!({
        "entries": [{
            "key": contract_instance_key_xdr(contract),
            "xdr": malformed_contract_instance_entry_xdr(contract),
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
async fn non_map_instance_storage_returns_mutable() {
    let contract = contract_under_test();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CannedLedgerEntriesResponder(
            ledger_entries_with_non_map_storage(&contract),
        ))
        .mount(&server)
        .await;

    let rpc = StellarRpcClient::new(&server.uri()).expect("RPC client must construct");
    let status = detect_contract_mutability(
        &rpc,
        &rpc,
        &contract,
        43,
        "CAAAA...ABSC4",
        "fixture-request-id",
    )
    .await
    .expect("detect_contract_mutability must succeed");

    assert_eq!(
        status,
        MutabilityStatus::Mutable {
            admin_or_owner_key: AdminOrOwnerKey::Admin,
            holder_redacted: "[non-map-instance-storage]".to_owned(),
        }
    );
}
