//! Exact transaction status wire text, including key order and absent fields.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]
use serde_json::{Value, json};
use stellar_agent_core::policy::v1::criteria::state_store::{StateKey, WindowEntry, WindowLimit};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_mcp::server::{StellarTransactionStatusArgs, WalletServer};
use stellar_agent_network::policy_state::{PersistedWindowStore, SubmissionHold};
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::transaction_status_integration::{
    ENVELOPE_HASH, SOURCE, TX_HASH, seed_receipt, status_profile,
};

/// The wallet state and chain answer a guard case runs against.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    /// A settled receipt with its open reservation and a `NOT_FOUND` answer.
    Settled,
    /// An open reservation whose receipt is missing.
    Orphan,
    /// No wallet state and a failing chain query.
    Failure,
    /// A receipt whose reservation reconciliation releases.
    Released,
}

impl Case {
    fn expected(self) -> &'static str {
        match self {
            Self::Settled => include_str!("transaction_status_wire_guard/settled.json"),
            Self::Orphan => include_str!("transaction_status_wire_guard/orphan.json"),
            Self::Failure => include_str!("transaction_status_wire_guard/failure.json"),
            Self::Released => include_str!("transaction_status_wire_guard/released.json"),
        }
    }
}

async fn endpoint(fail: bool) -> MockServer {
    let server = MockServer::start().await;
    for (name, result) in [
        (
            "getNetwork",
            stellar_agent_test_support::signed_envelope::get_network_result(
                stellar_agent_test_support::signed_envelope::TESTNET_PASSPHRASE,
            ),
        ),
        (
            "getTransaction",
            json!({"status":"NOT_FOUND","latestLedger":2000,"oldestLedger":1}),
        ),
        (
            "getHealth",
            json!({"status":"healthy","latestLedger":2000,"oldestLedger":1,"ledgerRetentionWindow":1999}),
        ),
        (
            "getLedgers",
            json!({"latestLedger":2000,"oldestLedger":1,"latestLedgerCloseTime":"1","oldestLedgerCloseTime":1,"cursor":"2000","ledgers":[]}),
        ),
        (
            "getLedgerEntries",
            stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[
                "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
            ]),
        ),
    ] {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":name})))
            .respond_with(stellar_agent_test_support::EchoIdResponder::new(result))
            .mount(&server)
            .await;
    }
    if fail {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":"getTransaction"})))
            .respond_with(|request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc":"2.0", "id":body["id"],
                    "error":{"code":-32600,"message":"wire guard failure"}
                }))
            })
            .with_priority(1)
            .mount(&server)
            .await;
    }
    server
}

// Only the generated correlation identifier varies between invocations.
fn normalize(text: &str) -> String {
    let value: Value = serde_json::from_str(text).unwrap();
    let id = value["request_id"].as_str().unwrap();
    assert!(uuid::Uuid::parse_str(id).unwrap().get_version_num() == 4);
    text.replace(id, "REQUEST_ID")
}

async fn check(case: Case) {
    let _root = crate::common::isolated_data_root();
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let rpc = endpoint(case == Case::Failure).await;
    let profile = status_profile(&rpc.uri(), "status-wire");
    let server = WalletServer::new(profile.clone()).unwrap();
    let name = server.profile_name_for_approval();
    let max_time = if case == Case::Released { 1 } else { 0 };
    let receipts = ReceiptStore::open(&name).unwrap();
    if matches!(case, Case::Settled | Case::Released) {
        seed_receipt(&name, 7, max_time);
        receipts
            .finalize(
                ENVELOPE_HASH,
                ReceiptStatus::Failed {
                    code: "ledger.failed".to_owned(),
                },
                Some(1500),
            )
            .unwrap();
    }
    if case != Case::Failure {
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        let window = PersistedWindowStore::for_profile(&name);
        window
            .record_pending(
                &profile,
                &[WindowEntry::new(
                    StateKey::new(&name, 1, "native", 86400),
                    now,
                    75,
                    WindowLimit::Amount {
                        asset: "native".to_owned(),
                        window: "1d".to_owned(),
                        max_stroops: 1000000,
                    },
                )],
                &SubmissionHold {
                    chain_scope: stellar_agent_network::policy_state::ChainScope::for_chain(
                        profile.chain_id,
                    ),
                    id: ENVELOPE_HASH.to_owned(),
                    tx_hash: TX_HASH.to_owned(),
                    source: SOURCE.to_owned(),
                    sequence: 7,
                    max_time,
                    pending_since_ms: now,
                    submission_ledger: 1000,
                    submission_anchor: None,
                    operator_required: false,
                },
            )
            .unwrap();
    }
    let result = server
        .call_stellar_transaction_status(StellarTransactionStatusArgs {
            chain_id: "stellar:testnet".to_owned(),
            tx_hash: TX_HASH.to_owned(),
        })
        .await
        .unwrap();
    assert_eq!(result.is_error == Some(true), case == Case::Failure);
    let mut actual =
        normalize(&result.content[0].as_text().unwrap().text).replace(&rpc.uri(), "RPC_URL");
    if case == Case::Released {
        let record = receipts.get(ENVELOPE_HASH).unwrap().unwrap();
        actual = actual.replace(
            record.settlement_decision_id.as_deref().unwrap(),
            "DECISION_ID",
        );
    }
    assert_eq!(actual, case.expected());
}

#[tokio::test]
#[serial_test::serial]
async fn settled_receipt_and_open_reservation() {
    check(Case::Settled).await;
}
#[tokio::test]
#[serial_test::serial]
async fn orphan_hold_without_receipt() {
    check(Case::Orphan).await;
}
#[tokio::test]
#[serial_test::serial]
async fn chain_query_failure() {
    check(Case::Failure).await;
}
#[tokio::test]
#[serial_test::serial]
async fn reconciliation_releases_the_hold() {
    check(Case::Released).await;
}
