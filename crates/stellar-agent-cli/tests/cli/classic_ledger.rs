//! A loopback Stellar RPC for the classic verbs: it answers the reads, the
//! send, and the confirmation for the ledger entries it holds, quotes one
//! inclusion fee in every fee-statistics percentile, and counts the sends.
//!
//! Every server it starts shares its entries and its send counter, so a
//! primary and an oracle served from one ledger read the same state and
//! their sends add up. A method outside the classic verbs' set panics the
//! responder, so a test never passes on an RPC call it did not expect.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test fixture; panics and unwraps are acceptable"
)]

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use stellar_agent_test_support::signed_envelope::{
    TESTNET_PASSPHRASE, get_network_result, send_transaction_hash_hex,
};
use stellar_agent_test_support::xdr_fixtures::{account_entry_xdr, account_ledger_key_xdr};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The native balance of every account the ledger funds: 10 000 XLM.
pub const ACCOUNT_BALANCE: i64 = 100_000_000_000;

/// The inclusion fee a new ledger quotes, in stroops.
const DEFAULT_INCLUSION_FEE: u32 = 100;

/// A testnet ledger of funded accounts and extra entries.
#[derive(Clone)]
pub struct ClassicLedger {
    entries: Arc<Vec<(String, String)>>,
    inclusion_fee: u32,
    sends: Arc<Mutex<usize>>,
}

impl ClassicLedger {
    /// `accounts` funded with [`ACCOUNT_BALANCE`], each signed by its own
    /// master key, plus the `extra` `(key, entry)` pairs, quoting a
    /// 100-stroop inclusion fee.
    pub fn new(accounts: &[&str], extra: &[(String, String)]) -> Self {
        let mut entries: Vec<(String, String)> = accounts
            .iter()
            .map(|account| {
                (
                    account_ledger_key_xdr(account),
                    account_entry_xdr(account, ACCOUNT_BALANCE, 0),
                )
            })
            .collect();
        entries.extend(extra.iter().cloned());
        Self {
            entries: Arc::new(entries),
            inclusion_fee: DEFAULT_INCLUSION_FEE,
            sends: Arc::new(Mutex::new(0)),
        }
    }

    /// The same ledger quoting `stroops` as the inclusion fee in every
    /// percentile, so `--fee auto` builds one operation at `stroops`.
    pub fn with_inclusion_fee(mut self, stroops: u32) -> Self {
        self.inclusion_fee = stroops;
        self
    }

    /// Starts a server answering every POST from this ledger.
    pub async fn serve(&self) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(self.clone())
            .mount(&server)
            .await;
        server
    }

    /// The number of `sendTransaction` calls every server of this ledger
    /// answered.
    pub fn sends(&self) -> usize {
        *self.sends.lock().unwrap()
    }

    /// The `getFeeStats` distribution quoting the inclusion fee everywhere.
    fn fee_distribution(&self) -> Value {
        let fee = self.inclusion_fee.to_string();
        json!({
            "max": fee, "min": fee, "mode": fee, "p10": fee, "p20": fee,
            "p30": fee, "p40": fee, "p50": fee, "p60": fee, "p70": fee,
            "p80": fee, "p90": fee, "p95": fee, "p99": fee,
            "transactionCount": "10", "ledgerCount": 5
        })
    }
}

impl Respond for ClassicLedger {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let result = match body["method"].as_str().unwrap() {
            "getNetwork" => get_network_result(TESTNET_PASSPHRASE),
            "getLedgerEntries" => {
                let keys: Vec<&str> = body["params"]["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                let entries: Vec<Value> = self
                    .entries
                    .iter()
                    .filter(|(key, _)| keys.contains(&key.as_str()))
                    .map(
                        |(key, xdr)| json!({"key": key, "xdr": xdr, "lastModifiedLedgerSeq": 1000}),
                    )
                    .collect();
                json!({"entries": entries, "latestLedger": 1001})
            }
            "getFeeStats" => {
                let fees = self.fee_distribution();
                json!({
                    "sorobanInclusionFee": fees, "inclusionFee": fees, "latestLedger": 1001
                })
            }
            "sendTransaction" => {
                *self.sends.lock().unwrap() += 1;
                json!({
                    "hash": send_transaction_hash_hex(&body, TESTNET_PASSPHRASE),
                    "status": "PENDING", "latestLedger": 1001,
                    "latestLedgerCloseTime": "1700000000"
                })
            }
            "getTransaction" => json!({
                "status": "SUCCESS", "txHash": body["params"]["hash"], "ledger": 1005,
                "createdAt": "1700000005", "latestLedger": 1006, "oldestLedger": 1
            }),
            "getHealth" => json!({
                "status": "healthy", "latestLedger": 2000, "oldestLedger": 1,
                "ledgerRetentionWindow": 1999
            }),
            "getLedgers" => json!({
                "latestLedger": 2000, "oldestLedger": 1, "latestLedgerCloseTime": "100",
                "oldestLedgerCloseTime": 1, "cursor": "2000", "ledgers": []
            }),
            other => panic!("unexpected RPC method {other}"),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
    }
}
