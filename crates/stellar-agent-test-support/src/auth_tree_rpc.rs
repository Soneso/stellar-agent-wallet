//! A mocked Stellar RPC endpoint whose simulation hands an authorizing
//! address an invocation tree the test chooses.
//!
//! Available only when the `test-helpers` cargo feature is enabled.
//!
//! Adapter-level submit tests drive a whole flow (contract pin reads, quote
//! simulations, the authorized simulation, the signed re-simulation and the
//! send) against one endpoint. [`AuthTreeRpc`] answers each step:
//!
//! - `getLedgerEntries` reports the configured accounts and contract
//!   instances, each only when its key is requested.
//! - `simulateTransaction` without authorization entries returns the
//!   configured return value and, when the tree function yields one, an
//!   Address-credential entry for the authorizing address over that tree.
//!   With authorization entries (the signed re-simulation) it echoes them.
//! - `sendTransaction` records the envelope and reports it pending;
//!   `getTransaction` reports it applied.
//!
//! [`AuthTreeEndpoint`] exposes what the flow did: the number of
//! simulations, the number of simulations that carried signed entries, and
//! every sent envelope.

#![allow(
    clippy::panic,
    reason = "test-helper fixture constructors expose documented panic paths"
)]

use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicUsize, Ordering},
};

use serde_json::{Value, json};
use stellar_xdr::{
    ContractDataDurability, ContractDataEntry, ExtensionPoint, HostFunction, InvokeContractArgs,
    LedgerEntryData, LedgerFootprint, LedgerKey, Limits, OperationBody, PublicKey, ReadXdr,
    ScAddress, ScContractInstance, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanResources, SorobanTransactionData,
    SorobanTransactionDataExt, TransactionEnvelope, Uint256, VecM, WriteXdr,
};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

use crate::send_transaction_hash_hex;
use crate::signed_envelope::{get_network_result, ledger_entries_result_for};

/// The ledger sequence the endpoint reports as latest.
const LATEST_LEDGER: u32 = 1000;

/// The nonce of every authorization entry the endpoint hands out.
pub const AUTH_ENTRY_NONCE: i64 = 7;

/// Builds the simulated root invocation for a host function, or `None` when
/// the call needs no authorization from the authorizing address.
pub type TreeFn = dyn Fn(&InvokeContractArgs) -> Option<SorobanAuthorizedInvocation> + Send + Sync;

/// Builds the simulated return value for a host function.
pub type ReturnFn = dyn Fn(&InvokeContractArgs) -> ScVal + Send + Sync;

/// Configuration of a mocked endpoint; [`Self::start`] mounts it.
pub struct AuthTreeRpc {
    passphrase: String,
    authorizer: ScAddress,
    accounts: Vec<(String, [u8; 32])>,
    instances: Vec<(ScAddress, ScContractInstance)>,
    tree: Arc<TreeFn>,
    returns: Arc<ReturnFn>,
}

impl AuthTreeRpc {
    /// An endpoint for `passphrase` whose authorization entries name
    /// `authorizer`. Without further configuration no call needs
    /// authorization and every call returns `ScVal::Void`.
    #[must_use]
    pub fn new(passphrase: &str, authorizer: ScAddress) -> Self {
        Self {
            passphrase: passphrase.to_owned(),
            authorizer,
            accounts: Vec::new(),
            instances: Vec::new(),
            tree: Arc::new(|_| None),
            returns: Arc::new(|_| ScVal::Void),
        }
    }

    /// Reports the classic account `account_id` (a G-strkey) with its own
    /// master key as its only signer.
    ///
    /// # Panics
    ///
    /// Panics if `account_id` is not a valid G-strkey.
    #[must_use]
    pub fn account(mut self, account_id: &str) -> Self {
        let key = stellar_strkey::ed25519::PublicKey::from_string(account_id)
            .unwrap_or_else(|err| panic!("invalid account id: {err}"))
            .0;
        self.accounts.push((account_id.to_owned(), key));
        self
    }

    /// Reports `instance` as the persistent instance entry of `contract`.
    #[must_use]
    pub fn instance(mut self, contract: ScAddress, instance: ScContractInstance) -> Self {
        self.instances.push((contract, instance));
        self
    }

    /// Sets the function that builds the simulated tree of a host function.
    #[must_use]
    pub fn tree(
        mut self,
        tree: impl Fn(&InvokeContractArgs) -> Option<SorobanAuthorizedInvocation>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.tree = Arc::new(tree);
        self
    }

    /// Sets the function that builds the simulated return value of a host
    /// function.
    #[must_use]
    pub fn returns(
        mut self,
        returns: impl Fn(&InvokeContractArgs) -> ScVal + Send + Sync + 'static,
    ) -> Self {
        self.returns = Arc::new(returns);
        self
    }

    /// Starts a mock server answering every JSON-RPC request with this
    /// configuration.
    pub async fn start(self) -> AuthTreeEndpoint {
        let server = MockServer::start().await;
        let record = Arc::new(Record::default());
        Mock::given(method("POST"))
            .respond_with(Responder {
                config: Arc::new(self),
                record: Arc::clone(&record),
            })
            .mount(&server)
            .await;
        AuthTreeEndpoint { server, record }
    }
}

/// What the mocked endpoint observed.
#[derive(Default)]
struct Record {
    simulations: AtomicUsize,
    signed_simulations: AtomicUsize,
    sent: Mutex<Vec<String>>,
}

/// A running mocked endpoint.
pub struct AuthTreeEndpoint {
    server: MockServer,
    record: Arc<Record>,
}

impl AuthTreeEndpoint {
    /// The endpoint URL.
    #[must_use]
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// The number of `simulateTransaction` requests answered.
    #[must_use]
    pub fn simulations(&self) -> usize {
        self.record.simulations.load(Ordering::SeqCst)
    }

    /// The number of `simulateTransaction` requests that carried
    /// authorization entries (signed re-simulations).
    #[must_use]
    pub fn signed_simulations(&self) -> usize {
        self.record.signed_simulations.load(Ordering::SeqCst)
    }

    /// Every envelope sent through `sendTransaction`, in order.
    ///
    /// # Panics
    ///
    /// Panics if a recorded envelope is not valid base64 XDR.
    #[must_use]
    pub fn sent(&self) -> Vec<TransactionEnvelope> {
        self.record
            .sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|xdr| {
                TransactionEnvelope::from_xdr_base64(xdr, Limits::none())
                    .unwrap_or_else(|err| panic!("sent envelope XDR: {err}"))
            })
            .collect()
    }
}

struct Responder {
    config: Arc<AuthTreeRpc>,
    record: Arc<Record>,
}

impl Respond for Responder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let result = match body["method"].as_str().unwrap_or_default() {
            "getNetwork" => get_network_result(&self.config.passphrase),
            "getLatestLedger" => json!({
                "id": "ab".repeat(32),
                "sequence": LATEST_LEDGER,
                "protocolVersion": 27
            }),
            "getLedgerEntries" => self.ledger_entries(&body),
            "simulateTransaction" => self.simulate(&body),
            "sendTransaction" => {
                if let Some(xdr) = body["params"]["transaction"].as_str() {
                    self.record
                        .sent
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(xdr.to_owned());
                }
                json!({
                    "status": "PENDING",
                    "hash": send_transaction_hash_hex(&body, &self.config.passphrase),
                    "latestLedger": LATEST_LEDGER,
                    "latestLedgerCloseTime": "1234567890"
                })
            }
            "getTransaction" => json!({
                "status": "SUCCESS",
                "ledger": LATEST_LEDGER + 1,
                "latestLedger": LATEST_LEDGER + 1,
                "oldestLedger": 1
            }),
            other => {
                return ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": -32601, "message": format!("method not mocked: {other}")}
                }));
            }
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
    }
}

impl Responder {
    /// Answers each requested key the configuration knows, in request order.
    fn ledger_entries(&self, body: &Value) -> Value {
        let entries: Vec<Value> = body["params"]["keys"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|key_xdr| {
                let key = LedgerKey::from_xdr_base64(key_xdr, Limits::none()).ok()?;
                match key {
                    LedgerKey::Account(account) => {
                        let PublicKey::PublicKeyTypeEd25519(Uint256(bytes)) = account.account_id.0;
                        let (account_id, _) =
                            self.config.accounts.iter().find(|(_, key)| *key == bytes)?;
                        ledger_entries_result_for(&[account_id.as_str()])["entries"]
                            .get(0)
                            .cloned()
                    }
                    LedgerKey::ContractData(data)
                        if data.key == ScVal::LedgerKeyContractInstance =>
                    {
                        let (contract, instance) = self
                            .config
                            .instances
                            .iter()
                            .find(|(contract, _)| *contract == data.contract)?;
                        let entry = LedgerEntryData::ContractData(ContractDataEntry {
                            ext: ExtensionPoint::V0,
                            contract: contract.clone(),
                            key: ScVal::LedgerKeyContractInstance,
                            durability: ContractDataDurability::Persistent,
                            val: ScVal::ContractInstance(instance.clone()),
                        });
                        Some(json!({
                            "key": key_xdr,
                            "xdr": entry.to_xdr_base64(Limits::none()).ok()?,
                            "lastModifiedLedgerSeq": 100,
                            "liveUntilLedgerSeq": 999_999
                        }))
                    }
                    _ => None,
                }
            })
            .collect();
        json!({"entries": entries, "latestLedger": LATEST_LEDGER})
    }

    /// Answers a simulation of the envelope's one `InvokeContract` operation.
    fn simulate(&self, body: &Value) -> Value {
        self.record.simulations.fetch_add(1, Ordering::SeqCst);
        let Some((invoke, signed_auth)) =
            body["params"]["transaction"].as_str().and_then(invoke_of)
        else {
            return json!({"error": "not an InvokeContract envelope", "latestLedger": LATEST_LEDGER});
        };
        let auth = if signed_auth.is_empty() {
            (self.config.tree)(&invoke)
                .map(|root_invocation| SorobanAuthorizationEntry {
                    credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                        address: self.config.authorizer.clone(),
                        nonce: AUTH_ENTRY_NONCE,
                        signature_expiration_ledger: 0,
                        signature: ScVal::Void,
                    }),
                    root_invocation,
                })
                .into_iter()
                .collect()
        } else {
            self.record
                .signed_simulations
                .fetch_add(1, Ordering::SeqCst);
            signed_auth
        };
        let auth_xdr: Vec<String> = auth
            .iter()
            .filter_map(|entry| entry.to_xdr_base64(Limits::none()).ok())
            .collect();
        json!({
            "transactionData": minimal_transaction_data(),
            "minResourceFee": "1000",
            "results": [{
                "auth": auth_xdr,
                "xdr": (self.config.returns)(&invoke)
                    .to_xdr_base64(Limits::none())
                    .unwrap_or_default()
            }],
            "latestLedger": LATEST_LEDGER
        })
    }
}

/// The contract call and the authorization entries of a v1 envelope whose
/// first operation invokes a contract.
fn invoke_of(envelope_xdr: &str) -> Option<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>)> {
    let TransactionEnvelope::Tx(tx) =
        TransactionEnvelope::from_xdr_base64(envelope_xdr, Limits::none()).ok()?
    else {
        return None;
    };
    let OperationBody::InvokeHostFunction(op) = &tx.tx.operations.first()?.body else {
        return None;
    };
    let HostFunction::InvokeContract(invoke) = &op.host_function else {
        return None;
    };
    Some((invoke.clone(), op.auth.to_vec()))
}

/// A `SorobanTransactionData` with an empty footprint and zero resources.
fn minimal_transaction_data() -> String {
    SorobanTransactionData {
        ext: SorobanTransactionDataExt::V0,
        resources: SorobanResources {
            footprint: LedgerFootprint {
                read_only: VecM::default(),
                read_write: VecM::default(),
            },
            instructions: 0,
            disk_read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee: 0,
    }
    .to_xdr_base64(Limits::none())
    .unwrap_or_default()
}
