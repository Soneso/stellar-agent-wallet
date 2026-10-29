//! `create_payment` signs only the SAC `transfer` it built, through one
//! identified client, within its ledger and fee bounds.
//!
//! A mock RPC on loopback answers every method the flow sends, routed by
//! method: `getNetwork` for the endpoint identity check, `getHealth` for the
//! ledger consistency read, and `simulateTransaction` for both simulations.
//! Any other method panics. The unsigned first simulation answers with
//! authorization entries shaped from the honest entry: the payer's unsigned
//! `Address` entry for exactly the transfer the requirements describe, built
//! here from the test's own values. The signed re-simulation answers with
//! entries derived from the signed entry it received. A counting signer
//! records every signing primitive the flow calls and the digest it signs,
//! and a counting transmit gate records whether the flow reached the send.
//!
//! Every hostile case gives otherwise valid answers to every later request,
//! so a check that fails to refuse yields a payment.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::cross_check::{CrossCheckValue, WitnessEntry, WitnessField};
use stellar_agent_core::error::{NetworkError, WalletError, WitnessUnavailableReason};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::NetworkContext;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::client::constructions_on_this_thread;
use stellar_agent_network::cross_check::{CrossCheckOutcome, CrossCheckWitness, SorobanCrossCheck};
use stellar_agent_network::signing::{Signer, SoftwareSigningKey, WebAuthnAssertion};
use stellar_agent_test_support::rpc_request_count;
use stellar_agent_x402::X402Error;
use stellar_agent_x402::constants::X402_STELLAR_TESTNET;
use stellar_agent_x402::exact::create_payment;
use stellar_agent_x402::wire::{PaymentPayload, PaymentRequirements};
use stellar_xdr::{
    AccountId, ContractExecutable, ContractId, ContractIdPreimage, ContractIdPreimageFromAddress,
    CreateContractArgs, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, HostFunction,
    Int128Parts, InvokeContractArgs, LedgerFootprint, Limits, OperationBody, PublicKey, ReadXdr,
    ScAddress, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
    SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanResources, SorobanResourcesExtV0,
    SorobanTransactionData, SorobanTransactionDataExt, TransactionEnvelope, TransactionExt,
    Uint256, VecM, WriteXdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
use zeroize::Zeroizing;

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";

/// SAC contract of the payment asset.
const ASSET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// Another contract, never the payment asset.
const OTHER_CONTRACT: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

const PAYER_SEED: [u8; 32] = [0x5a; 32];
const PAY_TO_SEED: [u8; 32] = [0x6b; 32];
const OTHER_ACCOUNT_SEED: [u8; 32] = [0x7c; 32];

const AMOUNT: u64 = 10_000_000;

/// An amount a hostile answer substitutes.
const FORGED_AMOUNT: u64 = 987_654_321_987;

/// The nonce the first simulation answers with.
const NONCE: i64 = 4_242_424_242;

const LATEST_LEDGER: u32 = 1000;
const MAX_TIMEOUT_SECONDS: u32 = 300;

/// `LATEST_LEDGER + ceil(MAX_TIMEOUT_SECONDS / 5)`.
const EXPECTED_EXPIRATION: u32 = 1060;

/// The resource fee ceiling the wallet applies to both simulations.
const FEE_CEILING: u64 = 10_000_000;

/// The minimum resource fee and embedded resource fee of an honest answer.
const HONEST_RESOURCE_FEE: u64 = 1000;

/// Deadline of the identity check and the health read in an honest payment.
const GENEROUS_DEADLINE: Duration = Duration::from_secs(60);

/// Deadline of a payment whose identity check or health read is meant to
/// fail after its retries.
const SHORT_DEADLINE: Duration = Duration::from_millis(700);

// ── Values ───────────────────────────────────────────────────────────────────

fn account_strkey(seed: [u8; 32]) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes())
        .to_string()
        .as_str()
        .to_owned()
}

fn account_address(seed: [u8; 32]) -> ScAddress {
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        key.verifying_key().to_bytes(),
    ))))
}

fn contract_address(strkey: &str) -> ScAddress {
    let contract = stellar_strkey::Contract::from_string(strkey).expect("contract strkey");
    ScAddress::Contract(ContractId(Hash(contract.0)))
}

/// A non-negative `i128` below 2^64 as its XDR high and low halves.
fn amount_scval(amount: u64) -> ScVal {
    ScVal::I128(Int128Parts { hi: 0, lo: amount })
}

fn requirements() -> PaymentRequirements {
    PaymentRequirements {
        scheme: "exact".to_owned(),
        network: X402_STELLAR_TESTNET.to_owned(),
        asset: ASSET.to_owned(),
        amount: AMOUNT.to_string(),
        pay_to: account_strkey(PAY_TO_SEED),
        max_timeout_seconds: MAX_TIMEOUT_SECONDS,
        extra: serde_json::json!({ "areFeesSponsored": true }),
    }
}

/// `transfer(payer, payTo, amount)` on the payment asset.
fn built_transfer() -> InvokeContractArgs {
    InvokeContractArgs {
        contract_address: contract_address(ASSET),
        function_name: ScSymbol("transfer".try_into().unwrap()),
        args: vec![
            ScVal::Address(account_address(PAYER_SEED)),
            ScVal::Address(account_address(PAY_TO_SEED)),
            amount_scval(AMOUNT),
        ]
        .try_into()
        .unwrap(),
    }
}

/// A root invocation of `function` without nested calls.
fn invocation_of(function: InvokeContractArgs) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(function),
        sub_invocations: VecM::default(),
    }
}

/// The entry an honest recording simulation returns for the built transfer.
fn honest_entry() -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: account_address(PAYER_SEED),
            nonce: NONCE,
            signature_expiration_ledger: 0,
            signature: ScVal::Void,
        }),
        root_invocation: invocation_of(built_transfer()),
    }
}

/// `entry`'s address credentials.
fn address_credentials(entry: &mut SorobanAuthorizationEntry) -> &mut SorobanAddressCredentials {
    let SorobanCredentials::Address(credentials) = &mut entry.credentials else {
        panic!("the entry carries Address credentials");
    };
    credentials
}

/// `entry` with its address credentials moved into another arm.
fn with_credentials_arm(
    mut entry: SorobanAuthorizationEntry,
    arm: impl FnOnce(SorobanAddressCredentials) -> SorobanCredentials,
) -> SorobanAuthorizationEntry {
    let credentials = address_credentials(&mut entry).clone();
    entry.credentials = arm(credentials);
    entry
}

/// `entry` with the arguments of its root contract call edited.
fn with_root_args(
    mut entry: SorobanAuthorizationEntry,
    edit: impl FnOnce(&mut Vec<ScVal>),
) -> SorobanAuthorizationEntry {
    let SorobanAuthorizedFunction::ContractFn(function) = &mut entry.root_invocation.function
    else {
        panic!("the entry's root invocation is a contract call");
    };
    let mut args = function.args.to_vec();
    edit(&mut args);
    function.args = args.try_into().unwrap();
    entry
}

/// The honest entry with its root contract call edited.
fn honest_entry_with_transfer(
    edit: impl FnOnce(&mut InvokeContractArgs),
) -> SorobanAuthorizationEntry {
    let mut transfer = built_transfer();
    edit(&mut transfer);
    let mut entry = honest_entry();
    entry.root_invocation = invocation_of(transfer);
    entry
}

/// `entry` with one nested call to another contract.
fn with_sub_invocation(mut entry: SorobanAuthorizationEntry) -> SorobanAuthorizationEntry {
    let mut nested = built_transfer();
    nested.contract_address = contract_address(OTHER_CONTRACT);
    entry.root_invocation.sub_invocations = vec![invocation_of(nested)].try_into().unwrap();
    entry
}

/// The payer's entry credentialed for another account.
fn foreign_entry() -> SorobanAuthorizationEntry {
    let mut entry = honest_entry();
    address_credentials(&mut entry).address = account_address(OTHER_ACCOUNT_SEED);
    entry
}

/// The honest entry's invocation with `SourceAccount` credentials.
fn source_account_entry() -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: invocation_of(built_transfer()),
    }
}

/// The preimage digest the payer must sign, built from the test's own values.
fn expected_digest() -> [u8; 32] {
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into()),
        nonce: NONCE,
        signature_expiration_ledger: EXPECTED_EXPIRATION,
        invocation: invocation_of(built_transfer()),
    });
    Sha256::digest(preimage.to_xdr(Limits::none()).unwrap()).into()
}

// ── Mock RPC ─────────────────────────────────────────────────────────────────

/// Transaction data with `ext` and an embedded resource fee of `resource_fee`.
fn transaction_data_with(
    ext: SorobanTransactionDataExt,
    resource_fee: i64,
) -> SorobanTransactionData {
    SorobanTransactionData {
        ext,
        resources: SorobanResources {
            footprint: LedgerFootprint {
                read_only: VecM::default(),
                read_write: VecM::default(),
            },
            instructions: 1_000,
            disk_read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee,
    }
}

fn transaction_data_xdr() -> String {
    transaction_data_with(SorobanTransactionDataExt::V0, 1_000)
        .to_xdr_base64(Limits::none())
        .unwrap()
}

/// Transaction data whose extension lists one archived entry to restore.
fn archived_transaction_data_xdr() -> String {
    transaction_data_with(
        SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
            archived_soroban_entries: vec![0].try_into().unwrap(),
        }),
        1_000,
    )
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// Transaction data embedding `resource_fee`.
fn transaction_data_xdr_with_fee(resource_fee: i64) -> String {
    transaction_data_with(SorobanTransactionDataExt::V0, resource_fee)
        .to_xdr_base64(Limits::none())
        .unwrap()
}

fn void_xdr() -> String {
    ScVal::Void.to_xdr_base64(Limits::none()).unwrap()
}

/// A successful simulation answer with `results` as its result list.
fn answer_with_results(results: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "transactionData": transaction_data_xdr(),
        "minResourceFee": "1000",
        "results": results,
        "latestLedger": LATEST_LEDGER,
    })
}

/// A successful simulation answer whose one result carries `auth`.
fn answer(auth: &[SorobanAuthorizationEntry]) -> serde_json::Value {
    let auth: Vec<String> = auth
        .iter()
        .map(|entry| entry.to_xdr_base64(Limits::none()).unwrap())
        .collect();
    answer_with_results(&serde_json::json!([{ "auth": auth, "xdr": void_xdr() }]))
}

/// `answer(auth)` reporting `ledger` as its latest ledger.
fn answer_at(auth: &[SorobanAuthorizationEntry], ledger: u32) -> serde_json::Value {
    let mut answer = answer(auth);
    answer["latestLedger"] = serde_json::json!(ledger);
    answer
}

/// `answer(auth)` with `field` set to `value`.
fn answer_with(
    auth: &[SorobanAuthorizationEntry],
    field: &str,
    value: serde_json::Value,
) -> serde_json::Value {
    let mut answer = answer(auth);
    answer[field] = value;
    answer
}

/// A `getNetwork` result reporting `passphrase` at a supported protocol.
fn network_result(passphrase: &str) -> serde_json::Value {
    serde_json::json!({
        "friendbotUrl": "https://friendbot.stellar.org",
        "passphrase": passphrase,
        "protocolVersion": 29,
    })
}

/// A complete `getHealth` result at `ledger` with `status`.
fn health_result(status: &str, ledger: u32) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "latestLedger": ledger,
        "oldestLedger": 1,
        "ledgerRetentionWindow": 17_280,
    })
}

/// A JSON-RPC success answer to the request with `id`.
fn rpc_result(id: &serde_json::Value, result: &serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }))
        .insert_header("content-type", "application/json")
}

/// A JSON-RPC error object answering the request with `id`.
fn rpc_error_object(id: &serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32603, "message": "backend unavailable"},
        }))
        .insert_header("content-type", "application/json")
}

/// How the mock answers `getNetwork` or `getHealth`.
#[derive(Clone)]
enum MethodAnswer {
    /// This result.
    Result(serde_json::Value),
    /// This result, after a delay.
    Delayed(serde_json::Value, Duration),
    /// A JSON-RPC error object.
    ErrorObject,
    /// An HTTP error status with no JSON-RPC body: a transport failure.
    HttpStatus(u16),
    /// A JSON-RPC error object for the first request, this result afterwards.
    ErrorObjectOnceThen(serde_json::Value),
}

impl MethodAnswer {
    fn respond(&self, id: &serde_json::Value, seen_before: usize) -> ResponseTemplate {
        match self {
            Self::Result(result) => rpc_result(id, result),
            Self::Delayed(result, delay) => rpc_result(id, result).set_delay(*delay),
            Self::ErrorObject => rpc_error_object(id),
            Self::HttpStatus(status) => ResponseTemplate::new(*status),
            Self::ErrorObjectOnceThen(result) => {
                if seen_before == 0 {
                    rpc_error_object(id)
                } else {
                    rpc_result(id, result)
                }
            }
        }
    }
}

/// The re-simulation answer derived from the signed entries it received.
type Resimulation = Box<dyn Fn(&[SorobanAuthorizationEntry]) -> serde_json::Value + Send + Sync>;

/// The endpoint of one payment.
///
/// A `simulateTransaction` request without authorization entries is the first
/// simulation, and one with entries is the signed re-simulation.
struct PaymentRpc {
    network: MethodAnswer,
    health: MethodAnswer,
    first: serde_json::Value,
    resimulation: Resimulation,
    /// How long the endpoint takes to answer a simulation.
    simulate_delay: Duration,
    /// `getNetwork` requests answered so far.
    network_requests: AtomicUsize,
    /// `getHealth` requests answered so far.
    health_requests: AtomicUsize,
    /// The entries each re-simulation request carried.
    received_signed: Arc<Mutex<Vec<Vec<SorobanAuthorizationEntry>>>>,
}

impl PaymentRpc {
    fn simulate(&self, body: &serde_json::Value) -> ResponseTemplate {
        let envelope = body["params"]["transaction"]
            .as_str()
            .expect("simulateTransaction carries a transaction envelope");
        let TransactionEnvelope::Tx(transaction) =
            TransactionEnvelope::from_xdr_base64(envelope, Limits::none())
                .expect("a decodable envelope")
        else {
            panic!("the x402 flow builds a v1 envelope");
        };
        let OperationBody::InvokeHostFunction(host) = &transaction.tx.operations[0].body else {
            panic!("the x402 flow builds an InvokeHostFunction operation");
        };
        let result = if host.auth.is_empty() {
            self.first.clone()
        } else {
            let signed = host.auth.to_vec();
            self.received_signed.lock().unwrap().push(signed.clone());
            (self.resimulation)(&signed)
        };
        rpc_result(&body["id"], &result).set_delay(self.simulate_delay)
    }
}

impl Respond for PaymentRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("a JSON-RPC request body");
        match body["method"].as_str() {
            Some("getNetwork") => {
                let seen = self.network_requests.fetch_add(1, Ordering::SeqCst);
                self.network.respond(&body["id"], seen)
            }
            Some("getHealth") => {
                let seen = self.health_requests.fetch_add(1, Ordering::SeqCst);
                self.health.respond(&body["id"], seen)
            }
            Some("simulateTransaction") => self.simulate(&body),
            other => panic!("the x402 flow sends no {other:?} request"),
        }
    }
}

// ── Signer ───────────────────────────────────────────────────────────────────

/// The payer's key, recording every signing primitive call.
struct CountingSigner {
    inner: SoftwareSigningKey,
    /// Digests passed to `sign_soroban_address_auth_payload`.
    address_auth_digests: Mutex<Vec<[u8; 32]>>,
    /// Calls to every other signing primitive.
    other_signing_calls: AtomicUsize,
}

impl CountingSigner {
    fn new() -> Self {
        Self {
            inner: SoftwareSigningKey::new_from_zeroizing(Zeroizing::new(PAYER_SEED)),
            address_auth_digests: Mutex::new(Vec::new()),
            other_signing_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl Signer for CountingSigner {
    async fn sign_tx_payload(
        &self,
        payload: &stellar_agent_network::signing::TxSigningPayload,
    ) -> Result<[u8; 64], WalletError> {
        self.other_signing_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_tx_payload(payload).await
    }

    async fn sign_auth_digest(
        &self,
        digest: &stellar_agent_network::signing::SmartAccountAuthDigest,
    ) -> Result<[u8; 64], WalletError> {
        self.other_signing_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_auth_digest(digest).await
    }

    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &stellar_agent_network::signing::SorobanAuthPayload,
    ) -> Result<[u8; 64], WalletError> {
        self.address_auth_digests
            .lock()
            .unwrap()
            .push(*payload.as_bytes());
        self.inner.sign_soroban_address_auth_payload(payload).await
    }

    async fn sign_message(
        &self,
        payload: &stellar_agent_network::signing::MessagePayload,
    ) -> Result<[u8; 64], WalletError> {
        self.other_signing_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_message(payload).await
    }

    async fn sign_webauthn_assertion(
        &self,
        auth_digest: &stellar_agent_network::signing::SmartAccountAuthDigest,
        credential_id: &[u8],
    ) -> Result<WebAuthnAssertion, WalletError> {
        self.other_signing_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .sign_webauthn_assertion(auth_digest, credential_id)
            .await
    }

    async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
        self.inner.public_key().await
    }
}

// ── One payment ──────────────────────────────────────────────────────────────

/// What the oracle answers when the payment requires the cross-check
/// witness.
struct OracleScenario {
    /// The oracle's answer to the unsigned simulation.
    simulation: serde_json::Value,
    simulate_delay: Duration,
}

/// Everything one payment's endpoint answers and the caller passes.
struct Scenario {
    requirements: PaymentRequirements,
    network: MethodAnswer,
    health: MethodAnswer,
    first: serde_json::Value,
    resimulation: Resimulation,
    deadline: Duration,
    /// The oracle of a required witness; `None` passes a cross-check that is
    /// not required.
    oracle: Option<OracleScenario>,
}

impl Scenario {
    /// An honest endpoint: the testnet identity, a healthy endpoint at the
    /// simulation's ledger, an honest first simulation, and a re-simulation
    /// that returns no authorization.
    fn honest() -> Self {
        Self {
            requirements: requirements(),
            network: MethodAnswer::Result(network_result(TESTNET_PASSPHRASE)),
            health: MethodAnswer::Result(health_result("healthy", LATEST_LEDGER)),
            first: answer(&[honest_entry()]),
            resimulation: Box::new(|_| answer(&[])),
            deadline: GENEROUS_DEADLINE,
            oracle: None,
        }
    }

    /// Requires the witness from an oracle answering the unsigned simulation
    /// with `simulation`.
    fn with_oracle(mut self, simulation: serde_json::Value) -> Self {
        self.oracle = Some(OracleScenario {
            simulation,
            simulate_delay: Duration::ZERO,
        });
        self
    }

    fn with_oracle_delay(mut self, delay: Duration) -> Self {
        self.oracle
            .as_mut()
            .expect("an oracle is configured")
            .simulate_delay = delay;
        self
    }

    fn with_first(mut self, first: serde_json::Value) -> Self {
        self.first = first;
        self
    }

    fn with_resimulation(
        mut self,
        resimulation: impl Fn(&[SorobanAuthorizationEntry]) -> serde_json::Value + Send + Sync + 'static,
    ) -> Self {
        self.resimulation = Box::new(resimulation);
        self
    }

    fn with_network(mut self, network: MethodAnswer) -> Self {
        self.network = network;
        self
    }

    fn with_health(mut self, health: MethodAnswer) -> Self {
        self.health = health;
        self
    }

    fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    fn with_max_timeout_seconds(mut self, seconds: u32) -> Self {
        self.requirements.max_timeout_seconds = seconds;
        self
    }
}

/// What one `create_payment` call returned and caused.
struct Outcome {
    result: Result<PaymentPayload, X402Error>,
    /// The cross-check outcome of a built payment.
    cross_check: Option<CrossCheckOutcome>,
    /// The JSON-RPC request bodies the primary endpoint received, in order.
    bodies: Vec<serde_json::Value>,
    /// The JSON-RPC request bodies the oracle received, in order.
    oracle_bodies: Vec<serde_json::Value>,
    /// The entries each re-simulation request to the oracle carried.
    oracle_received_signed: Vec<Vec<SorobanAuthorizationEntry>>,
    /// The oracle's authority, as the witness names it.
    oracle_uri: String,
    /// The witness the transmit gate saw, per gate call.
    gate_witnesses: Vec<Option<CrossCheckWitness>>,
    address_auth_digests: Vec<[u8; 32]>,
    signing_calls: usize,
    gate_calls: usize,
    simulate_requests: usize,
    requests: usize,
    /// The method of every request, in the order the endpoint received them.
    methods: Vec<String>,
    /// `StellarRpcClient` constructions inside `create_payment`.
    constructions: usize,
    elapsed: Duration,
    received_signed: Vec<Vec<SorobanAuthorizationEntry>>,
}

/// The JSON-RPC request bodies `server` received, in order.
async fn request_bodies(server: &MockServer) -> Vec<serde_json::Value> {
    server
        .received_requests()
        .await
        .expect("request recording is enabled")
        .iter()
        .map(|request| serde_json::from_slice(&request.body).unwrap())
        .collect()
}

/// Prepares the cross-check of a profile whose oracle is `oracle`: an
/// unvalued payment with an oracle configured requires the witness.
fn prepared_cross_check(primary: &MockServer, oracle: &MockServer) -> SorobanCrossCheck {
    let profile = Profile::builder_testnet("x402-signer", "payer", "x402-nonce", "nonce")
        .rpc_url(primary.uri())
        .oracle_provider_url(Some(oracle.uri().parse().expect("the loopback URL parses")))
        .build();
    let prepared = SorobanCrossCheck::prepare(
        &profile,
        &NetworkContext::from_profile(&profile),
        CrossCheckValue::Unvalued,
        "x402_test",
    )
    .expect("the oracle client builds");
    assert!(matches!(prepared, SorobanCrossCheck::Required { .. }));
    prepared
}

/// Runs `create_payment` for `scenario` on a client built before the call.
async fn run(scenario: Scenario) -> Outcome {
    let received_signed = Arc::new(Mutex::new(Vec::new()));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(PaymentRpc {
            network: scenario.network,
            health: scenario.health,
            first: scenario.first,
            resimulation: scenario.resimulation,
            simulate_delay: Duration::ZERO,
            network_requests: AtomicUsize::new(0),
            health_requests: AtomicUsize::new(0),
            received_signed: Arc::clone(&received_signed),
        })
        .mount(&server)
        .await;
    let oracle_received_signed = Arc::new(Mutex::new(Vec::new()));
    let oracle_server = MockServer::start().await;
    let cross_check = match scenario.oracle {
        Some(oracle) => {
            Mock::given(method("POST"))
                .respond_with(PaymentRpc {
                    network: MethodAnswer::Result(network_result(TESTNET_PASSPHRASE)),
                    health: MethodAnswer::Result(health_result("healthy", LATEST_LEDGER)),
                    first: oracle.simulation,
                    resimulation: Box::new(|_| answer(&[])),
                    simulate_delay: oracle.simulate_delay,
                    network_requests: AtomicUsize::new(0),
                    health_requests: AtomicUsize::new(0),
                    received_signed: Arc::clone(&oracle_received_signed),
                })
                .mount(&oracle_server)
                .await;
            prepared_cross_check(&server, &oracle_server)
        }
        None => SorobanCrossCheck::NotRequired,
    };
    let client = StellarRpcClient::new(&server.uri()).expect("the loopback URL parses");
    let signer = CountingSigner::new();
    let gate_calls = AtomicUsize::new(0);
    let gate_witnesses = Mutex::new(Vec::new());
    let constructions_before = constructions_on_this_thread();
    let started = tokio::time::Instant::now();
    let created = create_payment(
        &scenario.requirements,
        &signer,
        &client,
        &cross_check,
        TESTNET_PASSPHRASE,
        started + scenario.deadline,
        |authorization| {
            gate_calls.fetch_add(1, Ordering::SeqCst);
            gate_witnesses
                .lock()
                .unwrap()
                .push(authorization.cross_check.cloned());
            Ok(())
        },
    )
    .await;
    let (result, cross_check) = match created {
        Ok(created) => (Ok(created.payload), Some(created.cross_check)),
        Err(error) => (Err(error), None),
    };
    let elapsed = started.elapsed();
    let constructions = constructions_on_this_thread() - constructions_before;
    let address_auth_digests = signer.address_auth_digests.lock().unwrap().clone();
    let signing_calls =
        address_auth_digests.len() + signer.other_signing_calls.load(Ordering::SeqCst);
    let received = server
        .received_requests()
        .await
        .expect("request recording is enabled");
    let methods = received
        .iter()
        .map(|request| {
            serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["method"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    let received_signed = received_signed.lock().unwrap().clone();
    let oracle_received_signed = oracle_received_signed.lock().unwrap().clone();
    Outcome {
        result,
        cross_check,
        bodies: request_bodies(&server).await,
        oracle_bodies: request_bodies(&oracle_server).await,
        oracle_received_signed,
        oracle_uri: oracle_server.uri(),
        gate_witnesses: gate_witnesses.into_inner().unwrap(),
        address_auth_digests,
        signing_calls,
        gate_calls: gate_calls.load(Ordering::SeqCst),
        simulate_requests: rpc_request_count(&server, "simulateTransaction").await,
        requests: received.len(),
        methods,
        constructions,
        elapsed,
        received_signed,
    }
}

/// Runs `create_payment` against a mock answering the first simulation with
/// `first` and the re-simulation with `resimulation`.
async fn pay(
    first: serde_json::Value,
    resimulation: impl Fn(&[SorobanAuthorizationEntry]) -> serde_json::Value + Send + Sync + 'static,
) -> Outcome {
    run(Scenario::honest()
        .with_first(first)
        .with_resimulation(resimulation))
    .await
}

/// Runs `create_payment` with `first_auth` as the first simulation's entries.
/// The re-simulation answers honestly, so a check that fails to refuse yields
/// a payment.
async fn pay_with_first_auth(first_auth: &[SorobanAuthorizationEntry]) -> Outcome {
    pay(answer(first_auth), |_| answer(&[])).await
}

/// Runs `create_payment` against an honest first simulation and a
/// re-simulation answered by `resimulation`.
async fn pay_with_resimulation(
    resimulation: impl Fn(&[SorobanAuthorizationEntry]) -> serde_json::Value + Send + Sync + 'static,
) -> Outcome {
    pay(answer(&[honest_entry()]), resimulation).await
}

/// The signed entry a re-simulation received, edited.
fn signed_entry_with(
    signed: &[SorobanAuthorizationEntry],
    edit: impl FnOnce(SorobanAuthorizationEntry) -> SorobanAuthorizationEntry,
) -> serde_json::Value {
    let [entry] = signed else {
        panic!("the re-simulation carries one signed entry");
    };
    answer(&[edit(entry.clone())])
}

// ── Assertions ───────────────────────────────────────────────────────────────

/// Asserts that `result` is a refusal with wire code `code` and exactly
/// `expected` as its detail. The detail is a fixed sentence, so equality also
/// shows that it carries no value from the answer.
fn assert_refusal(result: &Result<PaymentPayload, X402Error>, code: &str, expected: &str) {
    let Err(error) = result else {
        panic!("expected a {code} refusal {expected:?}, got a payment payload");
    };
    assert_eq!(error.wire_code(), code, "the refusal's wire code: {error}");
    let (X402Error::UnexpectedAuthEntries { detail } | X402Error::RpcSimulateFailed { detail }) =
        error
    else {
        panic!("expected a refusal carrying a detail, got {error:?}");
    };
    assert_eq!(detail, expected, "the refusal detail");
}

/// Asserts that the first simulation was refused before anything was signed,
/// with exactly `expected` as the detail.
fn assert_refused_before_signing(outcome: &Outcome, expected: &str) {
    assert_refusal(&outcome.result, "x402.unexpected_auth_entries", expected);
    assert_eq!(
        outcome.signing_calls, 0,
        "no signing primitive may run on a refused simulation"
    );
    assert_eq!(
        outcome.gate_calls, 0,
        "the transmit gate must not run on a refused simulation"
    );
    assert_eq!(
        outcome.simulate_requests, 1,
        "only the unsigned simulation is sent"
    );
    assert_eq!(outcome.requests, 2, "no other request is sent");
}

/// Asserts that the payer signed once, the gate ran once, and both
/// simulations were sent.
fn assert_signed_and_sent_once(outcome: &Outcome) {
    assert_eq!(
        outcome.address_auth_digests.len(),
        1,
        "the payer signs one authorization"
    );
    assert_eq!(outcome.signing_calls, 1, "no other signing primitive runs");
    assert_eq!(outcome.gate_calls, 1, "the transmit gate runs once");
    assert_eq!(outcome.simulate_requests, 2, "both simulations are sent");
    assert_eq!(outcome.requests, 4, "no other request is sent");
}

/// Asserts that the re-simulation answer was refused with `code` and exactly
/// `expected` as the detail, after one signature and one send.
fn assert_refused_after_resimulation(outcome: &Outcome, code: &str, expected: &str) {
    assert_refusal(&outcome.result, code, expected);
    assert_signed_and_sent_once(outcome);
}

/// Asserts that the payment was built, and that its transaction carries
/// exactly the entries the re-simulation received.
fn assert_paid(outcome: &Outcome) {
    let payload = outcome
        .result
        .as_ref()
        .unwrap_or_else(|error| panic!("expected a payment payload, got {error:?}"));
    assert_signed_and_sent_once(outcome);
    let TransactionEnvelope::Tx(transaction) =
        TransactionEnvelope::from_xdr_base64(&payload.payload.transaction, Limits::none())
            .expect("the payload carries a decodable envelope")
    else {
        panic!("the payload carries a v1 envelope");
    };
    let OperationBody::InvokeHostFunction(host) = &transaction.tx.operations[0].body else {
        panic!("the payload carries an InvokeHostFunction operation");
    };
    assert_eq!(
        host.host_function,
        HostFunction::InvokeContract(built_transfer())
    );
    assert_eq!(
        outcome.received_signed,
        vec![host.auth.to_vec()],
        "the payload carries the entries the re-simulation received"
    );
}

// The refusal details `create_payment` writes, one fixed sentence per check.

const COUNT_DETAIL: &str =
    "the simulation must return exactly one authorization entry, the payer's";
const SOURCE_ACCOUNT_DETAIL: &str = "the simulated authorization entry has source-account \
     credentials, not the payer's address credentials";
const ADDRESS_V2_DETAIL: &str = "the simulated authorization entry has AddressV2 credentials; \
     this flow signs legacy address credentials only";
const DELEGATED_DETAIL: &str = "the simulated authorization entry has delegated address \
     credentials; this flow signs legacy address credentials only";
const OTHER_ACCOUNT_DETAIL: &str =
    "the simulated authorization entry is for an account other than the payer";
const EXPIRATION_DETAIL: &str =
    "the simulated authorization entry has a non-zero signature expiration ledger";
const SIGNATURE_DETAIL: &str = "the simulated authorization entry already carries a signature";
const NOT_A_CONTRACT_CALL_DETAIL: &str = "the simulated root invocation is not a contract call";
const OTHER_CONTRACT_DETAIL: &str =
    "the simulated root invocation calls a contract other than the payment asset";
const OTHER_FUNCTION_DETAIL: &str =
    "the simulated root invocation calls a function other than transfer";
const ARGUMENT_COUNT_DETAIL: &str = "the simulated root invocation passes a different number \
     of arguments than transfer(from, to, amount)";
const FROM_DETAIL: &str =
    "the simulated root invocation passes a from argument other than the payer";
const TO_DETAIL: &str = "the simulated root invocation passes a to argument other than payTo";
const AMOUNT_DETAIL: &str =
    "the simulated root invocation passes an amount other than the required amount";
const NESTED_CALLS_DETAIL: &str = "the simulated root invocation carries nested calls";
const RESIMULATION_AUTH_DETAIL: &str =
    "the re-simulation returned authorization entries other than the signed entry";
const RESIMULATION_NO_RESULT_DETAIL: &str = "the re-simulation returned no result";
const RESIMULATION_DECODE_DETAIL: &str = "the re-simulation results do not decode";

// ── (a) The honest answer ────────────────────────────────────────────────────

/// One payer entry for exactly the built transfer: the payer signs the
/// preimage of the built transfer, under the simulated nonce and the computed
/// expiration, once.
#[tokio::test]
async fn an_honest_simulation_signs_the_built_transfer_once() {
    let outcome = pay_with_resimulation(|_| answer(&[])).await;
    assert_paid(&outcome);
    assert_eq!(
        outcome.address_auth_digests,
        vec![expected_digest()],
        "the signed digest is SHA-256 of the built transfer's preimage"
    );
    let [signed] = outcome.received_signed[0].as_slice() else {
        panic!("one signed entry");
    };
    let SorobanCredentials::Address(credentials) = &signed.credentials else {
        panic!("the signed entry carries Address credentials");
    };
    assert_eq!(credentials.address, account_address(PAYER_SEED));
    assert_eq!(credentials.nonce, NONCE);
    assert_eq!(credentials.signature_expiration_ledger, EXPECTED_EXPIRATION);
    assert_ne!(credentials.signature, ScVal::Void);
    assert_eq!(signed.root_invocation, invocation_of(built_transfer()));
}

// ── (b) Refused first simulations ────────────────────────────────────────────

#[tokio::test]
async fn a_root_invocation_of_another_contract_is_refused_before_signing() {
    let entry = honest_entry_with_transfer(|transfer| {
        transfer.contract_address = contract_address(OTHER_CONTRACT);
    });
    let outcome = pay_with_first_auth(&[entry]).await;
    assert_refused_before_signing(&outcome, OTHER_CONTRACT_DETAIL);
}

#[tokio::test]
async fn a_root_invocation_that_is_not_a_contract_call_is_refused_before_signing() {
    let mut entry = honest_entry();
    entry.root_invocation.function =
        SorobanAuthorizedFunction::CreateContractHostFn(CreateContractArgs {
            contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
                address: account_address(PAYER_SEED),
                salt: Uint256([0x11; 32]),
            }),
            executable: ContractExecutable::StellarAsset,
        });
    let outcome = pay_with_first_auth(&[entry]).await;
    assert_refused_before_signing(&outcome, NOT_A_CONTRACT_CALL_DETAIL);
}

#[tokio::test]
async fn a_root_invocation_of_another_function_is_refused_before_signing() {
    let entry = honest_entry_with_transfer(|transfer| {
        transfer.function_name = ScSymbol("approve".try_into().unwrap());
    });
    let outcome = pay_with_first_auth(&[entry]).await;
    assert_refused_before_signing(&outcome, OTHER_FUNCTION_DETAIL);
}

#[tokio::test]
async fn a_transfer_from_another_account_is_refused_before_signing() {
    let entry = with_root_args(honest_entry(), |args| {
        args[0] = ScVal::Address(account_address(OTHER_ACCOUNT_SEED));
    });
    let outcome = pay_with_first_auth(&[entry]).await;
    assert_refused_before_signing(&outcome, FROM_DETAIL);
}

#[tokio::test]
async fn a_transfer_to_another_recipient_is_refused_before_signing() {
    let entry = with_root_args(honest_entry(), |args| {
        args[1] = ScVal::Address(account_address(OTHER_ACCOUNT_SEED));
    });
    let outcome = pay_with_first_auth(&[entry]).await;
    assert_refused_before_signing(&outcome, TO_DETAIL);
}

#[tokio::test]
async fn a_transfer_of_another_amount_is_refused_before_signing() {
    let entry = with_root_args(honest_entry(), |args| {
        args[2] = amount_scval(FORGED_AMOUNT);
    });
    let outcome = pay_with_first_auth(&[entry]).await;
    assert_refused_before_signing(&outcome, AMOUNT_DETAIL);
}

#[tokio::test]
async fn a_transfer_with_an_extra_argument_is_refused_before_signing() {
    let entry = with_root_args(honest_entry(), |args| {
        args.push(amount_scval(AMOUNT));
    });
    let outcome = pay_with_first_auth(&[entry]).await;
    assert_refused_before_signing(&outcome, ARGUMENT_COUNT_DETAIL);
}

#[tokio::test]
async fn a_transfer_with_a_missing_argument_is_refused_before_signing() {
    let entry = with_root_args(honest_entry(), |args| {
        args.pop();
    });
    let outcome = pay_with_first_auth(&[entry]).await;
    assert_refused_before_signing(&outcome, ARGUMENT_COUNT_DETAIL);
}

#[tokio::test]
async fn a_root_invocation_with_a_nested_call_is_refused_before_signing() {
    let outcome = pay_with_first_auth(&[with_sub_invocation(honest_entry())]).await;
    assert_refused_before_signing(&outcome, NESTED_CALLS_DETAIL);
}

#[tokio::test]
async fn an_empty_authorization_is_refused_before_signing() {
    let outcome = pay_with_first_auth(&[]).await;
    assert_refused_before_signing(&outcome, COUNT_DETAIL);
}

#[tokio::test]
async fn a_sole_entry_for_another_account_is_refused_before_signing() {
    let outcome = pay_with_first_auth(&[foreign_entry()]).await;
    assert_refused_before_signing(&outcome, OTHER_ACCOUNT_DETAIL);
}

#[tokio::test]
async fn an_entry_for_another_account_beside_the_payers_is_refused_before_signing() {
    let outcome = pay_with_first_auth(&[honest_entry(), foreign_entry()]).await;
    assert_refused_before_signing(&outcome, COUNT_DETAIL);
}

#[tokio::test]
async fn a_duplicate_payer_entry_is_refused_before_signing() {
    let outcome = pay_with_first_auth(&[honest_entry(), honest_entry()]).await;
    assert_refused_before_signing(&outcome, COUNT_DETAIL);
}

#[tokio::test]
async fn a_source_account_entry_beside_the_payers_is_refused_before_signing() {
    let outcome = pay_with_first_auth(&[honest_entry(), source_account_entry()]).await;
    assert_refused_before_signing(&outcome, COUNT_DETAIL);
}

#[tokio::test]
async fn a_sole_source_account_entry_is_refused_before_signing() {
    let outcome = pay_with_first_auth(&[source_account_entry()]).await;
    assert_refused_before_signing(&outcome, SOURCE_ACCOUNT_DETAIL);
}

#[tokio::test]
async fn a_payer_entry_with_address_v2_credentials_is_refused_before_signing() {
    let entry = with_credentials_arm(honest_entry(), SorobanCredentials::AddressV2);
    let outcome = pay_with_first_auth(&[entry]).await;
    assert_refused_before_signing(&outcome, ADDRESS_V2_DETAIL);
}

#[tokio::test]
async fn a_payer_entry_with_delegated_credentials_is_refused_before_signing() {
    let entry = with_credentials_arm(honest_entry(), |address_credentials| {
        SorobanCredentials::AddressWithDelegates(SorobanAddressCredentialsWithDelegates {
            address_credentials,
            delegates: VecM::default(),
        })
    });
    let outcome = pay_with_first_auth(&[entry]).await;
    assert_refused_before_signing(&outcome, DELEGATED_DETAIL);
}

#[tokio::test]
async fn a_payer_entry_with_a_non_zero_expiration_is_refused_before_signing() {
    let mut entry = honest_entry();
    address_credentials(&mut entry).signature_expiration_ledger = 5_000;
    let outcome = pay_with_first_auth(&[entry]).await;
    assert_refused_before_signing(&outcome, EXPIRATION_DETAIL);
}

#[tokio::test]
async fn a_payer_entry_that_already_carries_a_signature_is_refused_before_signing() {
    let mut entry = honest_entry();
    address_credentials(&mut entry).signature = ScVal::Vec(Some(ScVec(VecM::default())));
    let outcome = pay_with_first_auth(&[entry]).await;
    assert_refused_before_signing(&outcome, SIGNATURE_DETAIL);
}

// ── (c) Re-simulation answers ────────────────────────────────────────────────

#[tokio::test]
async fn a_resimulation_with_an_empty_authorization_is_accepted() {
    let outcome = pay_with_resimulation(|_| answer(&[])).await;
    assert_paid(&outcome);
}

#[tokio::test]
async fn a_resimulation_echoing_the_signed_entry_is_accepted() {
    let outcome = pay_with_resimulation(answer).await;
    assert_paid(&outcome);
}

#[tokio::test]
async fn a_resimulation_entry_for_another_address_is_refused() {
    let outcome = pay_with_resimulation(|signed| {
        signed_entry_with(signed, |mut entry| {
            address_credentials(&mut entry).address = account_address(OTHER_ACCOUNT_SEED);
            entry
        })
    })
    .await;
    assert_refused_after_resimulation(
        &outcome,
        "x402.unexpected_auth_entries",
        RESIMULATION_AUTH_DETAIL,
    );
}

#[tokio::test]
async fn a_resimulation_entry_with_another_credential_arm_is_refused() {
    let outcome = pay_with_resimulation(|signed| {
        signed_entry_with(signed, |entry| {
            with_credentials_arm(entry, SorobanCredentials::AddressV2)
        })
    })
    .await;
    assert_refused_after_resimulation(
        &outcome,
        "x402.unexpected_auth_entries",
        RESIMULATION_AUTH_DETAIL,
    );
}

#[tokio::test]
async fn a_resimulation_entry_with_another_nonce_is_refused() {
    let outcome = pay_with_resimulation(|signed| {
        signed_entry_with(signed, |mut entry| {
            let credentials = address_credentials(&mut entry);
            credentials.nonce = credentials.nonce.wrapping_add(1);
            entry
        })
    })
    .await;
    assert_refused_after_resimulation(
        &outcome,
        "x402.unexpected_auth_entries",
        RESIMULATION_AUTH_DETAIL,
    );
}

#[tokio::test]
async fn a_resimulation_entry_with_another_expiration_is_refused() {
    let outcome = pay_with_resimulation(|signed| {
        signed_entry_with(signed, |mut entry| {
            let credentials = address_credentials(&mut entry);
            credentials.signature_expiration_ledger += 1;
            entry
        })
    })
    .await;
    assert_refused_after_resimulation(
        &outcome,
        "x402.unexpected_auth_entries",
        RESIMULATION_AUTH_DETAIL,
    );
}

#[tokio::test]
async fn a_resimulation_entry_with_another_signature_is_refused() {
    let outcome = pay_with_resimulation(|signed| {
        signed_entry_with(signed, |mut entry| {
            address_credentials(&mut entry).signature = ScVal::Void;
            entry
        })
    })
    .await;
    assert_refused_after_resimulation(
        &outcome,
        "x402.unexpected_auth_entries",
        RESIMULATION_AUTH_DETAIL,
    );
}

#[tokio::test]
async fn a_resimulation_entry_with_another_root_invocation_is_refused() {
    let outcome = pay_with_resimulation(|signed| {
        signed_entry_with(signed, |entry| {
            with_root_args(entry, |args| args[2] = amount_scval(FORGED_AMOUNT))
        })
    })
    .await;
    assert_refused_after_resimulation(
        &outcome,
        "x402.unexpected_auth_entries",
        RESIMULATION_AUTH_DETAIL,
    );
}

#[tokio::test]
async fn a_resimulation_entry_with_a_nested_call_is_refused() {
    let outcome =
        pay_with_resimulation(|signed| signed_entry_with(signed, with_sub_invocation)).await;
    assert_refused_after_resimulation(
        &outcome,
        "x402.unexpected_auth_entries",
        RESIMULATION_AUTH_DETAIL,
    );
}

#[tokio::test]
async fn a_resimulation_with_an_extra_entry_is_refused() {
    let outcome = pay_with_resimulation(|signed| {
        let mut entries = signed.to_vec();
        entries.extend_from_slice(signed);
        answer(&entries)
    })
    .await;
    assert_refused_after_resimulation(
        &outcome,
        "x402.unexpected_auth_entries",
        RESIMULATION_AUTH_DETAIL,
    );
}

#[tokio::test]
async fn a_resimulation_without_a_result_is_a_failed_simulation() {
    let outcome = pay_with_resimulation(|_| answer_with_results(&serde_json::json!([]))).await;
    assert_refused_after_resimulation(
        &outcome,
        "x402.rpc_simulate_failed",
        RESIMULATION_NO_RESULT_DETAIL,
    );
}

#[tokio::test]
async fn a_resimulation_with_undecodable_authorization_is_a_failed_simulation() {
    let outcome = pay_with_resimulation(|_| {
        answer_with_results(&serde_json::json!([{ "auth": ["AAAA"], "xdr": void_xdr() }]))
    })
    .await;
    assert_refused_after_resimulation(
        &outcome,
        "x402.rpc_simulate_failed",
        RESIMULATION_DECODE_DETAIL,
    );
}

#[tokio::test]
async fn a_resimulation_with_an_undecodable_result_value_is_a_failed_simulation() {
    let outcome = pay_with_resimulation(|_| {
        answer_with_results(&serde_json::json!([{ "auth": [], "xdr": "AAAA" }]))
    })
    .await;
    assert_refused_after_resimulation(
        &outcome,
        "x402.rpc_simulate_failed",
        RESIMULATION_DECODE_DETAIL,
    );
}

// ── Shared assertions of the bounds tests ────────────────────────────────────

/// The successful primary sequence of one payment.
const PAYMENT_METHODS: [&str; 4] = [
    "getNetwork",
    "simulateTransaction",
    "getHealth",
    "simulateTransaction",
];

/// Asserts that `result` is an `RpcSimulateFailed` refusal with exactly
/// `expected` as its detail.
fn assert_simulate_failed(result: &Result<PaymentPayload, X402Error>, expected: &str) {
    assert_refusal(result, "x402.rpc_simulate_failed", expected);
}

/// Asserts that nothing was signed or gated and that the endpoint received
/// exactly `methods`, in order.
fn assert_nothing_signed_after(outcome: &Outcome, methods: &[&str]) {
    assert_eq!(outcome.signing_calls, 0, "no signing primitive may run");
    assert_eq!(outcome.gate_calls, 0, "the transmit gate must not run");
    assert_eq!(
        outcome.methods, methods,
        "the requests the endpoint received"
    );
}

/// Asserts that a refusal came after one signature, one gate call, and the
/// full primary sequence.
fn assert_refused_after_the_send(outcome: &Outcome, expected: &str) {
    assert_simulate_failed(&outcome.result, expected);
    assert_signed_and_sent_once(outcome);
    assert_eq!(outcome.methods, PAYMENT_METHODS);
}

/// The signature expiration ledger of the one signed entry the re-simulation
/// received.
fn signed_expiration(outcome: &Outcome) -> u32 {
    let [signed] = outcome.received_signed[0].as_slice() else {
        panic!("one signed entry");
    };
    let SorobanCredentials::Address(credentials) = &signed.credentials else {
        panic!("the signed entry carries Address credentials");
    };
    credentials.signature_expiration_ledger
}

/// The transaction envelope of a built payment.
fn payment_transaction(outcome: &Outcome) -> stellar_xdr::TransactionV1Envelope {
    let payload = outcome
        .result
        .as_ref()
        .unwrap_or_else(|error| panic!("expected a payment payload, got {error:?}"));
    let TransactionEnvelope::Tx(transaction) =
        TransactionEnvelope::from_xdr_base64(&payload.payload.transaction, Limits::none())
            .expect("the payload carries a decodable envelope")
    else {
        panic!("the payload carries a v1 envelope");
    };
    transaction
}

// ── Endpoint identity on the caller's client ─────────────────────────────────

/// The endpoint identity check is the client's first request, both
/// simulations and the health read use the same client, and `create_payment`
/// builds no client of its own.
#[tokio::test]
async fn x402_identifies_one_client_before_both_simulations() {
    let outcome = run(Scenario::honest()).await;
    assert_paid(&outcome);
    assert_eq!(outcome.methods, PAYMENT_METHODS);
    assert_eq!(
        outcome.constructions, 0,
        "create_payment uses the caller's client and builds none"
    );
}

/// An identity attempt that fails is retried, and no simulation is sent
/// before the identity is established.
#[tokio::test]
async fn an_identity_retry_precedes_the_first_simulation() {
    let outcome = run(
        Scenario::honest().with_network(MethodAnswer::ErrorObjectOnceThen(network_result(
            TESTNET_PASSPHRASE,
        ))),
    )
    .await;
    assert!(outcome.result.is_ok(), "{:?}", outcome.result.err());
    assert_eq!(outcome.signing_calls, 1, "the payer signs once");
    assert_eq!(outcome.gate_calls, 1, "the transmit gate runs once");
    assert_eq!(
        outcome.methods,
        [
            "getNetwork",
            "getNetwork",
            "simulateTransaction",
            "getHealth",
            "simulateTransaction",
        ]
    );
}

/// Every identity refusal returns the check's own network code before any
/// simulation, signature, or gate call.
#[tokio::test]
async fn x402_identity_refusals_precede_simulation() {
    let cases = [
        (
            "an endpoint reporting mainnet",
            MethodAnswer::Result(network_result(MAINNET_PASSPHRASE)),
            "network.mainnet_write_forbidden",
        ),
        (
            "an endpoint serving another network",
            MethodAnswer::Result(network_result(FUTURENET_PASSPHRASE)),
            "network.endpoint_network_mismatch",
        ),
        (
            "an answer without protocolVersion",
            MethodAnswer::Result(serde_json::json!({ "passphrase": TESTNET_PASSPHRASE })),
            "network.endpoint_identity_unavailable",
        ),
        (
            "an endpoint answering only error objects",
            MethodAnswer::ErrorObject,
            "network.endpoint_identity_unavailable",
        ),
        (
            "an endpoint failing at the transport",
            MethodAnswer::HttpStatus(503),
            "network.endpoint_identity_unavailable",
        ),
    ];
    for (case, network, code) in cases {
        let outcome = run(Scenario::honest()
            .with_network(network)
            .with_deadline(SHORT_DEADLINE))
        .await;
        let Err(error) = &outcome.result else {
            panic!("{case}: expected an identity refusal, got a payment");
        };
        assert!(
            matches!(error, X402Error::EndpointIdentity(_)),
            "{case}: {error:?}"
        );
        assert_eq!(error.wire_code(), code, "{case}");
        assert!(
            !outcome.methods.is_empty() && outcome.methods.iter().all(|m| m == "getNetwork"),
            "{case}: only identity requests are sent: {:?}",
            outcome.methods
        );
        assert_eq!(outcome.signing_calls, 0, "{case}: nothing is signed");
        assert_eq!(outcome.gate_calls, 0, "{case}: the gate does not run");
    }
}

/// An identity answer that arrives after the caller's deadline refuses: the
/// check runs under the supplied deadline, not a budget of its own.
#[tokio::test]
async fn x402_identity_obeys_the_supplied_deadline() {
    let outcome = run(Scenario::honest()
        .with_network(MethodAnswer::Delayed(
            network_result(TESTNET_PASSPHRASE),
            Duration::from_secs(3),
        ))
        .with_deadline(Duration::from_millis(500)))
    .await;
    let Err(error) = &outcome.result else {
        panic!("expected an identity refusal, got a payment");
    };
    assert_eq!(error.wire_code(), "network.endpoint_identity_unavailable");
    assert!(
        outcome.elapsed < Duration::from_millis(2_500),
        "the check stops at the deadline, took {:?}",
        outcome.elapsed
    );
    assert_eq!(outcome.simulate_requests, 0, "no simulation is sent");
    assert_eq!(outcome.signing_calls, 0, "nothing is signed");
}

/// No production source of the crate builds an RPC client: `create_payment`
/// sends every request through the client its caller passes, and the
/// witness's oracle client is the one the caller prepared.
#[test]
fn x402_has_no_raw_rpc_client_construction() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    let mut pending = vec![src];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    assert!(
        files.iter().any(|path| path.ends_with("exact.rs")),
        "the scan reaches the payment flow: {files:?}"
    );
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap();
        let production = stellar_agent_test_support::source_order::production_half(&source);
        for banned in [
            "Client::new",
            "StellarRpcClient::new",
            "::with_credential(",
            "profile_rpc_client(",
            "from_profile(",
            "::prepare(",
        ] {
            assert!(
                !production.contains(banned),
                "{}: production code calls {banned}",
                path.display()
            );
        }
    }
}

// ── Expiration bound ─────────────────────────────────────────────────────────

/// `maxTimeoutSeconds` of zero refuses before any request; one and 300
/// seconds sign windows of one and sixty ledgers.
#[tokio::test]
async fn timeout_range_is_validated_before_rpc() {
    let outcome = run(Scenario::honest().with_max_timeout_seconds(0)).await;
    let Err(X402Error::InvalidPaymentRequired { detail }) = &outcome.result else {
        panic!("expected InvalidPaymentRequired, got {:?}", outcome.result);
    };
    assert_eq!(detail, "maxTimeoutSeconds must be at least 1");
    assert_nothing_signed_after(&outcome, &[]);

    for (seconds, window) in [(1, 1), (300, 60)] {
        let outcome = run(Scenario::honest().with_max_timeout_seconds(seconds)).await;
        assert_paid(&outcome);
        assert_eq!(
            signed_expiration(&outcome),
            LATEST_LEDGER + window,
            "{seconds} s"
        );
    }
}

/// The window rounds up to whole ledgers of five seconds.
#[tokio::test]
async fn expiration_rounds_up_within_sixty_ledgers() {
    for (seconds, window) in [(1, 1), (5, 1), (6, 2), (300, 60)] {
        let outcome = run(Scenario::honest().with_max_timeout_seconds(seconds)).await;
        assert_paid(&outcome);
        assert_eq!(
            signed_expiration(&outcome),
            LATEST_LEDGER + window,
            "{seconds} s"
        );
    }
}

/// A requirement above 300 seconds signs the sixty-ledger window of 300
/// seconds.
#[tokio::test]
async fn timeouts_above_the_maximum_sign_a_sixty_ledger_window() {
    for seconds in [301, u32::MAX] {
        let outcome = run(Scenario::honest().with_max_timeout_seconds(seconds)).await;
        assert_paid(&outcome);
        assert_eq!(
            signed_expiration(&outcome),
            EXPECTED_EXPIRATION,
            "{seconds} s"
        );
    }
}

/// The simulation's ledger is above zero and at most one ledger ahead of the
/// health ledger, and the health ledger lies before the expiration ledger.
#[tokio::test]
async fn simulation_ledger_must_bracket_health_and_expiration() {
    // One ledger of skew between backends is tolerated.
    let outcome = run(
        Scenario::honest().with_health(MethodAnswer::Result(health_result(
            "healthy",
            LATEST_LEDGER - 1,
        ))),
    )
    .await;
    assert_paid(&outcome);

    // `(first simulation ledger, health ledger, re-simulation ledger,
    // detail)`. The re-simulation ledger lets the payment complete if the
    // first-phase check fails to refuse.
    let cases = [
        (
            LATEST_LEDGER,
            LATEST_LEDGER - 2,
            LATEST_LEDGER,
            "the simulation reports a ledger more than one ahead of the endpoint's health",
        ),
        (0, 0, 0, "the simulation reports ledger zero"),
        (
            LATEST_LEDGER,
            EXPECTED_EXPIRATION,
            EXPECTED_EXPIRATION - 1,
            "the endpoint's health ledger has reached the signature expiration ledger",
        ),
        (
            LATEST_LEDGER,
            u32::MAX,
            EXPECTED_EXPIRATION - 1,
            "the endpoint's health ledger has reached the signature expiration ledger",
        ),
    ];
    for (simulation, health, resimulation, detail) in cases {
        let outcome = run(Scenario::honest()
            .with_first(answer_at(&[honest_entry()], simulation))
            .with_health(MethodAnswer::Result(health_result("healthy", health)))
            .with_resimulation(move |_| answer_at(&[], resimulation)))
        .await;
        assert_simulate_failed(&outcome.result, detail);
        assert_nothing_signed_after(
            &outcome,
            &["getNetwork", "simulateTransaction", "getHealth"],
        );
    }
}

/// A simulation ledger without room for the window refuses before the
/// health read and before signing.
#[tokio::test]
async fn expiration_overflow_refuses_before_signing() {
    let ledger = u32::MAX - 10;
    let outcome = run(Scenario::honest()
        .with_first(answer_at(&[honest_entry()], ledger))
        .with_health(MethodAnswer::Result(health_result("healthy", ledger)))
        .with_resimulation(move |_| answer_at(&[], ledger)))
    .await;
    assert_simulate_failed(
        &outcome.result,
        "the simulation's latest ledger leaves no room for the signature expiration window",
    );
    assert_nothing_signed_after(&outcome, &["getNetwork", "simulateTransaction"]);
}

/// The re-simulation's ledger is at most one ledger behind the health ledger
/// and lies before the expiration ledger.
#[tokio::test]
async fn resimulation_must_remain_before_expiration() {
    // One ledger of skew between backends is tolerated.
    let outcome =
        run(Scenario::honest().with_resimulation(|_| answer_at(&[], LATEST_LEDGER - 1))).await;
    assert_paid(&outcome);

    let cases = [
        (
            LATEST_LEDGER - 2,
            "the re-simulation reports a ledger more than one behind the endpoint's health",
        ),
        (
            EXPECTED_EXPIRATION,
            "the re-simulation reports a ledger at or past the signature expiration ledger",
        ),
        (
            u32::MAX,
            "the re-simulation reports a ledger at or past the signature expiration ledger",
        ),
    ];
    for (resimulation, detail) in cases {
        let outcome =
            run(Scenario::honest().with_resimulation(move |_| answer_at(&[], resimulation))).await;
        assert_refused_after_the_send(&outcome, detail);
    }
}

/// Asserts that a payment whose health read answered `health` refuses with
/// `detail` before signing, after the first simulation and at least one
/// health read.
async fn assert_health_refused(health: MethodAnswer, detail: &str) {
    let outcome = run(Scenario::honest()
        .with_health(health)
        .with_deadline(SHORT_DEADLINE))
    .await;
    assert_simulate_failed(&outcome.result, detail);
    assert_eq!(outcome.signing_calls, 0, "nothing is signed");
    assert_eq!(outcome.gate_calls, 0, "the gate does not run");
    assert_eq!(outcome.simulate_requests, 1, "only the first simulation");
    assert!(
        outcome
            .methods
            .starts_with(&["getNetwork".to_owned(), "simulateTransaction".to_owned()])
            && outcome.methods[2..].iter().all(|m| m == "getHealth")
            && outcome.methods.len() > 2,
        "{:?}",
        outcome.methods
    );
}

/// A health read that reports a status other than `healthy` refuses before
/// signing.
#[tokio::test]
async fn an_unhealthy_status_refuses_before_signing() {
    assert_health_refused(
        MethodAnswer::Result(health_result("unhealthy", LATEST_LEDGER)),
        "the endpoint reports a health status other than healthy",
    )
    .await;
}

/// A health read answered only with JSON-RPC error objects refuses before
/// signing once its deadline ends the retries.
#[tokio::test]
async fn a_health_error_object_refuses_before_signing() {
    assert_health_refused(
        MethodAnswer::ErrorObject,
        "the endpoint's health could not be read",
    )
    .await;
}

/// A health answer without `ledgerRetentionWindow` does not deserialize and
/// refuses before signing.
#[tokio::test]
async fn a_health_answer_without_a_field_refuses_before_signing() {
    assert_health_refused(
        MethodAnswer::Result(serde_json::json!({
            "status": "healthy",
            "latestLedger": LATEST_LEDGER,
            "oldestLedger": 1,
        })),
        "the endpoint's health could not be read",
    )
    .await;
}

/// A health read that fails at the transport refuses before signing once its
/// deadline ends the retries.
#[tokio::test]
async fn a_health_transport_failure_refuses_before_signing() {
    assert_health_refused(
        MethodAnswer::HttpStatus(503),
        "the endpoint's health could not be read",
    )
    .await;
}

// ── Resource fee ceiling ─────────────────────────────────────────────────────

/// Both simulations' minimum resource fee lies in `1..=10_000_000` stroops.
#[tokio::test]
async fn resource_fee_ceiling_applies_to_both_simulations() {
    for (fee, first_detail, resimulation_detail) in [
        (
            0,
            "simulate returned no min_resource_fee / transaction_data",
            "re-simulate returned no min_resource_fee / transaction_data",
        ),
        (
            FEE_CEILING + 1,
            "the simulation's minimum resource fee exceeds the wallet's ceiling of 10000000 \
             stroops",
            "the re-simulation's minimum resource fee exceeds the wallet's ceiling of 10000000 \
             stroops",
        ),
        (
            u64::MAX,
            "the simulation's minimum resource fee exceeds the wallet's ceiling of 10000000 \
             stroops",
            "the re-simulation's minimum resource fee exceeds the wallet's ceiling of 10000000 \
             stroops",
        ),
    ] {
        let fee_value = serde_json::json!(fee.to_string());
        let outcome = run(Scenario::honest().with_first(answer_with(
            &[honest_entry()],
            "minResourceFee",
            fee_value.clone(),
        )))
        .await;
        assert_simulate_failed(&outcome.result, first_detail);
        assert_nothing_signed_after(&outcome, &["getNetwork", "simulateTransaction"]);

        let outcome = run(Scenario::honest()
            .with_resimulation(move |_| answer_with(&[], "minResourceFee", fee_value.clone())))
        .await;
        assert_refused_after_the_send(&outcome, resimulation_detail);
    }
}

/// A first simulation with a positive minimum resource fee and empty
/// transaction data refuses before signing.
#[tokio::test]
async fn empty_transaction_data_in_first_simulation_refuses_before_signing() {
    let first = answer_with(&[honest_entry()], "transactionData", serde_json::json!(""));
    let outcome = run(Scenario::honest().with_first(first)).await;
    assert_simulate_failed(
        &outcome.result,
        "simulate returned no min_resource_fee / transaction_data",
    );
    assert_nothing_signed_after(&outcome, &["getNetwork", "simulateTransaction"]);
}

/// A re-simulation with a positive minimum resource fee and empty transaction
/// data is a failed simulation after the send, and no payload is returned.
#[tokio::test]
async fn empty_transaction_data_in_resimulation_withholds_payload() {
    let outcome = run(Scenario::honest()
        .with_resimulation(|_| answer_with(&[], "transactionData", serde_json::json!(""))))
    .await;
    assert_refused_after_the_send(
        &outcome,
        "re-simulate returned no min_resource_fee / transaction_data",
    );
}

/// The resource fee embedded in both simulations' transaction data lies in
/// `0..=min_resource_fee`.
#[tokio::test]
async fn embedded_resource_fee_is_bounded_and_covered() {
    let first_detail = "the simulation's transaction data embeds a resource fee outside zero to \
                        its minimum resource fee";
    let resimulation_detail = "the re-simulation's transaction data embeds a resource fee \
                               outside zero to its minimum resource fee";
    let ceiling = i64::try_from(FEE_CEILING).unwrap();
    // `(embedded fee, minimum resource fee)`.
    let cases = [
        (-1, HONEST_RESOURCE_FEE),
        (ceiling + 1, FEE_CEILING),
        (1001, HONEST_RESOURCE_FEE),
    ];
    for (embedded, minimum) in cases {
        let data = serde_json::json!(transaction_data_xdr_with_fee(embedded));
        let minimum = serde_json::json!(minimum.to_string());
        let mut first = answer_with(&[honest_entry()], "transactionData", data.clone());
        first["minResourceFee"] = minimum.clone();
        let outcome = run(Scenario::honest().with_first(first)).await;
        assert_simulate_failed(&outcome.result, first_detail);
        assert_nothing_signed_after(&outcome, &["getNetwork", "simulateTransaction"]);

        let outcome = run(Scenario::honest().with_resimulation(move |_| {
            let mut answer = answer_with(&[], "transactionData", data.clone());
            answer["minResourceFee"] = minimum.clone();
            answer
        }))
        .await;
        assert_refused_after_the_send(&outcome, resimulation_detail);
    }
}

/// A minimum resource fee at the ceiling builds a payment whose fee is the
/// ceiling plus the 100-stroop base fee.
#[tokio::test]
async fn resource_fee_boundary_builds_exact_total() {
    let at_ceiling = |auth: &[SorobanAuthorizationEntry]| {
        let mut answer = answer_with(
            auth,
            "transactionData",
            serde_json::json!(transaction_data_xdr_with_fee(
                i64::try_from(FEE_CEILING).unwrap()
            )),
        );
        answer["minResourceFee"] = serde_json::json!(FEE_CEILING.to_string());
        answer
    };
    let outcome = run(Scenario::honest()
        .with_first(at_ceiling(&[honest_entry()]))
        .with_resimulation(move |_| at_ceiling(&[])))
    .await;
    assert_paid(&outcome);
    let transaction = payment_transaction(&outcome);
    assert_eq!(transaction.tx.fee, 10_000_100);
    let TransactionExt::V1(data) = &transaction.tx.ext else {
        panic!("the payment carries Soroban transaction data");
    };
    assert_eq!(data.resource_fee, i64::try_from(FEE_CEILING).unwrap());
}

// ── Restoration ──────────────────────────────────────────────────────────────

/// A restore preamble in the first simulation refuses before signing, a
/// zero-fee preamble included.
#[tokio::test]
async fn restore_in_first_simulation_refuses_before_signing() {
    for preamble_fee in ["0", "5000"] {
        let first = answer_with(
            &[honest_entry()],
            "restorePreamble",
            serde_json::json!({
                "transactionData": transaction_data_xdr(),
                "minResourceFee": preamble_fee,
            }),
        );
        let outcome = run(Scenario::honest().with_first(first)).await;
        assert_simulate_failed(
            &outcome.result,
            "the simulation returned a restore preamble; this wallet does not restore archived \
             ledger entries",
        );
        assert_nothing_signed_after(&outcome, &["getNetwork", "simulateTransaction"]);
    }
}

/// A restore preamble in the re-simulation refuses after the send: one
/// signature, one signed request, and no payload.
#[tokio::test]
async fn restore_in_resimulation_withholds_payload() {
    let outcome = run(Scenario::honest().with_resimulation(|_| {
        answer_with(
            &[],
            "restorePreamble",
            serde_json::json!({
                "transactionData": transaction_data_xdr(),
                "minResourceFee": "5000",
            }),
        )
    }))
    .await;
    assert_refused_after_the_send(
        &outcome,
        "the re-simulation returned a restore preamble; this wallet does not restore archived \
         ledger entries",
    );
    assert_eq!(outcome.received_signed.len(), 1, "one signed request");
}

/// Transaction data of the first simulation that restores archived entries
/// inside the simulation refuses before signing.
#[tokio::test]
async fn archived_entries_in_first_simulation_refuse_before_signing() {
    let first = answer_with(
        &[honest_entry()],
        "transactionData",
        serde_json::json!(archived_transaction_data_xdr()),
    );
    let outcome = run(Scenario::honest().with_first(first)).await;
    assert_simulate_failed(
        &outcome.result,
        "the simulation's transaction data restores archived ledger entries; this wallet does \
         not restore them",
    );
    assert_nothing_signed_after(&outcome, &["getNetwork", "simulateTransaction"]);
}

/// Transaction data of the re-simulation that restores archived entries
/// refuses after the send, and no payload is returned.
#[tokio::test]
async fn archived_entries_in_resimulation_withhold_payload() {
    let outcome = run(Scenario::honest().with_resimulation(|_| {
        answer_with(
            &[],
            "transactionData",
            serde_json::json!(archived_transaction_data_xdr()),
        )
    }))
    .await;
    assert_refused_after_the_send(
        &outcome,
        "the re-simulation's transaction data restores archived ledger entries; this wallet \
         does not restore them",
    );
}

// ── Simulation request failures and malformed data ───────────────────────────

/// First-phase transaction data that does not decode refuses before signing
/// with a fixed detail.
#[tokio::test]
async fn an_undecodable_first_transaction_data_is_refused_before_signing() {
    let first = answer_with(
        &[honest_entry()],
        "transactionData",
        serde_json::json!("AAAA"),
    );
    let outcome = run(Scenario::honest().with_first(first)).await;
    assert_simulate_failed(
        &outcome.result,
        "the simulation's transaction data does not decode",
    );
    assert_nothing_signed_after(&outcome, &["getNetwork", "simulateTransaction"]);
}

/// A simulation request that fails carries a phase prefix and the scrubbed
/// network error: the echoed credential never reaches the detail.
#[tokio::test]
async fn a_failed_simulation_request_carries_a_phase_prefix_and_no_credentials() {
    /// Answers `simulateTransaction` with an error object that echoes a
    /// credential-bearing URL, from the request `fail_from` on.
    struct EchoingFailure {
        fail_from: usize,
        simulations: AtomicUsize,
        inner: PaymentRpc,
    }
    impl Respond for EchoingFailure {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            if body["method"] == "simulateTransaction"
                && self.simulations.fetch_add(1, Ordering::SeqCst) >= self.fail_from
            {
                return ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {
                        "code": -32000,
                        "message": "upstream https://user:SECRET@archive.example.com:8443/rpc?token=SECRET failed",
                    },
                }));
            }
            self.inner.respond(request)
        }
    }

    for (fail_from, prefix, signatures) in [
        (0, "first simulation request failed: ", 0),
        (1, "re-simulation request failed: ", 1),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(EchoingFailure {
                fail_from,
                simulations: AtomicUsize::new(0),
                inner: PaymentRpc {
                    network: MethodAnswer::Result(network_result(TESTNET_PASSPHRASE)),
                    health: MethodAnswer::Result(health_result("healthy", LATEST_LEDGER)),
                    first: answer(&[honest_entry()]),
                    resimulation: Box::new(|_| answer(&[])),
                    simulate_delay: Duration::ZERO,
                    network_requests: AtomicUsize::new(0),
                    health_requests: AtomicUsize::new(0),
                    received_signed: Arc::new(Mutex::new(Vec::new())),
                },
            })
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let signer = CountingSigner::new();
        let result = create_payment(
            &requirements(),
            &signer,
            &client,
            &SorobanCrossCheck::NotRequired,
            TESTNET_PASSPHRASE,
            tokio::time::Instant::now() + GENEROUS_DEADLINE,
            |_| Ok(()),
        )
        .await;
        let Err(X402Error::RpcSimulateFailed { detail }) = result else {
            panic!("expected RpcSimulateFailed, got {result:?}");
        };
        assert!(detail.starts_with(prefix), "{detail}");
        assert!(
            detail.contains("simulateTransaction failed: "),
            "the network error follows the prefix: {detail}"
        );
        assert!(
            detail.contains("archive.example.com:8443"),
            "the echoed host stays: {detail}"
        );
        for leaked in ["SECRET", "token=", "user:", "https://"] {
            assert!(!detail.contains(leaked), "{leaked} survived: {detail}");
        }
        assert_eq!(
            signer.address_auth_digests.lock().unwrap().len(),
            signatures,
            "{prefix}"
        );
    }
}

/// A simulation answer's `error` string reaches the refusal detail of both
/// phases scrubbed: the echoed URL as host and port, the control character
/// and the quotes escaped, quoted, and cut at the bound.
#[tokio::test]
async fn a_simulation_answer_error_reaches_the_detail_scrubbed() {
    fn hostile() -> String {
        format!(
            "host https://user:PWSECRET@leak.example/rpc?k=QSECRET said \"no\"\u{1b}[2J {}",
            "e".repeat(1000)
        )
    }
    let expected_body = format!(
        "{}{}",
        r#"host leak.example said \"no\"\u{001b}[2J "#,
        "e".repeat(stellar_agent_network::MAX_SERVER_TEXT_CHARS - 41)
    );
    assert_eq!(
        expected_body.chars().count(),
        stellar_agent_network::MAX_SERVER_TEXT_CHARS
    );
    let quoted = format!("\"{expected_body}\"...");

    let first = run(Scenario::honest().with_first(answer_with(
        &[honest_entry()],
        "error",
        serde_json::json!(hostile()),
    )))
    .await;
    assert_refusal(
        &first.result,
        "x402.rpc_simulate_failed",
        &format!("simulate returned error: {quoted}"),
    );
    assert_eq!(
        first.signing_calls, 0,
        "nothing is signed on a refused simulation"
    );

    let second =
        pay_with_resimulation(|_| answer_with(&[], "error", serde_json::json!(hostile()))).await;
    assert_refusal(
        &second.result,
        "x402.rpc_simulate_failed",
        &format!("re-simulate returned error: {quoted}"),
    );
}

// ── Cross-check witness ──────────────────────────────────────────────────────

/// The methods of `bodies`, in order.
fn methods_of(bodies: &[serde_json::Value]) -> Vec<&str> {
    bodies
        .iter()
        .map(|body| body["method"].as_str().unwrap())
        .collect()
}

/// Asserts that the witness refused before anything was signed: the primary
/// received exactly its identity check and its simulation, and the oracle its
/// identity check and the unsigned simulation.
fn assert_witness_refused_before_signing(outcome: &Outcome) {
    assert_eq!(outcome.signing_calls, 0, "nothing is signed");
    assert_eq!(outcome.gate_calls, 0, "the transmit gate does not run");
    assert_eq!(outcome.requests, 2, "the primary's identity and simulation");
    assert_eq!(
        outcome.methods,
        ["getNetwork", "simulateTransaction"],
        "the primary's requests"
    );
    assert_eq!(
        methods_of(&outcome.oracle_bodies),
        ["getNetwork", "simulateTransaction"],
        "the oracle's requests"
    );
}

/// The wallet error a witness refusal carries.
fn witness_error(outcome: &Outcome) -> &WalletError {
    let Err(X402Error::CrossCheck(error)) = &outcome.result else {
        panic!("expected a cross-check refusal, got {:?}", outcome.result);
    };
    error
}

/// Asserts a `simulation.divergence` refusal on `field` before signing.
fn assert_witness_divergence(outcome: &Outcome, field: WitnessField) {
    let error = witness_error(outcome);
    assert!(
        matches!(
            error,
            WalletError::Network(NetworkError::WitnessDivergence {
                entry: WitnessEntry::SorobanSimulation,
                field: got,
                sequence_delta: None,
            }) if *got == field
        ),
        "expected a divergence on {field}, got {error:?}"
    );
    let refusal = outcome.result.as_ref().unwrap_err();
    assert_eq!(refusal.wire_code(), "simulation.divergence");
    assert_eq!(
        refusal.to_string(),
        format!(
            "cross-check refused: the primary RPC and the oracle disagree on the soroban \
             simulation {field}; the wallet did not sign or send. Retry the action; if the \
             disagreement persists, investigate both endpoints"
        )
    );
    assert_witness_refused_before_signing(outcome);
}

/// Runs a payment whose oracle answers the unsigned simulation with
/// `simulation`, and asserts the divergence on `field`.
async fn oracle_diverges(simulation: serde_json::Value, field: WitnessField) {
    let outcome = run(Scenario::honest().with_oracle(simulation)).await;
    assert_witness_divergence(&outcome, field);
}

/// Asserts that a payment with a required witness was built, and that the
/// witness names the oracle and the ledger it reported.
fn assert_paid_with_witness(outcome: &Outcome, oracle_ledger: u32) {
    assert_paid(outcome);
    let cross_check = outcome.cross_check.as_ref().expect("a built payment");
    let witness = cross_check.witness().expect("the witness passed");
    assert_eq!(witness.authority(), outcome.oracle_uri);
    assert_eq!(witness.oracle_ledger(), oracle_ledger);
    assert_eq!(witness.kinds(), &[WitnessEntry::SorobanSimulation]);
    let view = cross_check.view();
    assert_eq!(view.status, "passed");
    assert_eq!(view.provider.as_deref(), Some(outcome.oracle_uri.as_str()));
    assert_eq!(view.ledger, Some(oracle_ledger));
    assert_eq!(
        outcome.gate_witnesses,
        vec![Some(witness.clone())],
        "the transmit gate sees the witness"
    );
    assert_eq!(
        methods_of(&outcome.oracle_bodies),
        ["getNetwork", "simulateTransaction"],
        "the oracle answers the identity check and the unsigned simulation"
    );
    assert!(
        outcome.oracle_received_signed.is_empty(),
        "the signed authorization never reaches the oracle"
    );
}

/// A passing witness reports the oracle's authority and ledger, which differ
/// from the primary's, in the outcome and to the transmit gate, and the crate
/// builds no client of its own.
#[tokio::test]
async fn a_passing_witness_reports_the_oracle_and_its_ledger() {
    let outcome = run(Scenario::honest().with_oracle(answer_at(&[honest_entry()], 1001))).await;
    assert_paid_with_witness(&outcome, 1001);
    assert_eq!(outcome.methods, PAYMENT_METHODS);
    assert_eq!(
        outcome.constructions, 0,
        "create_payment uses the prepared oracle client and builds none"
    );
}

/// A payment whose cross-check is not required sends nothing to an oracle and
/// reports the outcome it was given.
#[tokio::test]
async fn a_witness_that_is_not_required_reports_not_required() {
    let outcome = run(Scenario::honest()).await;
    assert_paid(&outcome);
    assert_eq!(
        outcome.cross_check.as_ref().unwrap().view().status,
        "not_required"
    );
    assert_eq!(outcome.gate_witnesses, vec![None]);
    assert!(outcome.oracle_bodies.is_empty());
}

#[tokio::test]
async fn witness_oracle_error_diverges_on_the_result() {
    oracle_diverges(
        answer_with(
            &[honest_entry()],
            "error",
            serde_json::json!("host invocation failed"),
        ),
        WitnessField::SimulationResult,
    )
    .await;
}

#[tokio::test]
async fn witness_oracle_restore_preamble_diverges_on_the_result() {
    oracle_diverges(
        answer_with(
            &[honest_entry()],
            "restorePreamble",
            serde_json::json!({
                "transactionData": transaction_data_xdr(),
                "minResourceFee": "5000",
            }),
        ),
        WitnessField::SimulationResult,
    )
    .await;
}

#[tokio::test]
async fn witness_second_oracle_result_diverges_on_the_authorization_count() {
    let auth = vec![honest_entry().to_xdr_base64(Limits::none()).unwrap()];
    let result = serde_json::json!({ "auth": auth, "xdr": void_xdr() });
    oracle_diverges(
        answer_with_results(&serde_json::json!([result.clone(), result])),
        WitnessField::AuthorizationCount,
    )
    .await;
}

#[tokio::test]
async fn witness_zero_oracle_results_diverge_on_the_authorization_count() {
    oracle_diverges(
        answer_with_results(&serde_json::json!([])),
        WitnessField::AuthorizationCount,
    )
    .await;
}

#[tokio::test]
async fn witness_other_oracle_entry_count_diverges_on_the_authorization_count() {
    oracle_diverges(
        answer(&[honest_entry(), honest_entry()]),
        WitnessField::AuthorizationCount,
    )
    .await;
    oracle_diverges(answer(&[]), WitnessField::AuthorizationCount).await;
}

#[tokio::test]
async fn witness_source_account_credentials_diverge_on_the_credentials() {
    oracle_diverges(answer(&[source_account_entry()]), WitnessField::Credentials).await;
}

#[tokio::test]
async fn witness_address_v2_credentials_diverge_on_the_credentials() {
    oracle_diverges(
        answer(&[with_credentials_arm(
            honest_entry(),
            SorobanCredentials::AddressV2,
        )]),
        WitnessField::Credentials,
    )
    .await;
}

/// The refusal precedes the payer's signature: the witness runs before
/// `sign_soroban_auth_entry`.
#[tokio::test]
async fn witness_other_address_diverges_on_the_address() {
    oracle_diverges(answer(&[foreign_entry()]), WitnessField::Address).await;
}

#[tokio::test]
async fn witness_signed_oracle_entry_diverges_on_the_signature() {
    let mut entry = honest_entry();
    address_credentials(&mut entry).signature = ScVal::U32(1);
    oracle_diverges(answer(&[entry]), WitnessField::Signature).await;
}

#[tokio::test]
async fn witness_other_invocation_diverges_on_the_invocation() {
    let entry = with_root_args(honest_entry(), |args| args[2] = amount_scval(FORGED_AMOUNT));
    oracle_diverges(answer(&[entry]), WitnessField::Invocation).await;
}

#[tokio::test]
async fn witness_zero_resource_fee_diverges_on_the_resource_fee() {
    oracle_diverges(
        answer_with(&[honest_entry()], "minResourceFee", serde_json::json!("0")),
        WitnessField::ResourceFee,
    )
    .await;
}

#[tokio::test]
async fn witness_resource_fee_above_the_ceiling_diverges_on_the_resource_fee() {
    oracle_diverges(
        answer_with(
            &[honest_entry()],
            "minResourceFee",
            serde_json::json!((FEE_CEILING + 1).to_string()),
        ),
        WitnessField::ResourceFee,
    )
    .await;
}

/// The oracle's resource fee may be anything from one stroop to the ceiling.
#[tokio::test]
async fn witness_resource_fee_bounds_pass() {
    for fee in [1, FEE_CEILING] {
        let outcome = run(Scenario::honest().with_oracle(answer_with(
            &[honest_entry()],
            "minResourceFee",
            serde_json::json!(fee.to_string()),
        )))
        .await;
        assert_paid_with_witness(&outcome, LATEST_LEDGER);
    }
}

/// An oracle three ledgers behind the primary cannot vouch for the primary's
/// ledger.
#[tokio::test]
async fn witness_oracle_three_ledgers_behind_diverges_on_the_ledger_skew() {
    oracle_diverges(
        answer_at(&[honest_entry()], LATEST_LEDGER - 3),
        WitnessField::LedgerSkew,
    )
    .await;
}

/// An oracle two ledgers behind passes, and so does one four ledgers ahead
/// while the signature window allows it.
#[tokio::test]
async fn witness_oracle_ledger_within_the_bounds_passes() {
    for ledger in [LATEST_LEDGER - 2, LATEST_LEDGER + 4] {
        let outcome =
            run(Scenario::honest().with_oracle(answer_at(&[honest_entry()], ledger))).await;
        assert_paid_with_witness(&outcome, ledger);
    }
}

/// With the primary at ledger 1000 and a one-second timeout the expiration
/// ledger is 1001: an oracle at 1001 or 1002 refuses and one at 1000 passes.
/// An oracle at `u32::MAX` refuses on the expiration without an overflow.
#[tokio::test]
async fn witness_oracle_at_or_past_the_expiration_diverges_on_the_expiration() {
    for ledger in [LATEST_LEDGER + 1, LATEST_LEDGER + 2, u32::MAX] {
        let outcome = run(Scenario::honest()
            .with_max_timeout_seconds(1)
            .with_oracle(answer_at(&[honest_entry()], ledger)))
        .await;
        assert_witness_divergence(&outcome, WitnessField::Expiration);
    }
    let outcome = run(Scenario::honest()
        .with_max_timeout_seconds(1)
        .with_oracle(answer_at(&[honest_entry()], LATEST_LEDGER)))
    .await;
    assert_paid_with_witness(&outcome, LATEST_LEDGER);
}

/// The oracle's nonce and signature expiration ledger are not compared.
#[tokio::test]
async fn witness_ignores_the_oracle_nonce_and_expiration() {
    let mut entry = honest_entry();
    let credentials = address_credentials(&mut entry);
    credentials.nonce = NONCE + 1;
    credentials.signature_expiration_ledger = EXPECTED_EXPIRATION;
    let outcome = run(Scenario::honest().with_oracle(answer(&[entry]))).await;
    assert_paid_with_witness(&outcome, LATEST_LEDGER);
}

/// An oracle answer whose authorization entry or result value does not
/// decode is an unusable answer, refused after one attempt.
#[tokio::test]
async fn witness_undecodable_oracle_answer_is_witness_unavailable() {
    let mut bad_auth = answer(&[honest_entry()]);
    bad_auth["results"][0]["auth"][0] = serde_json::json!("AAAA");
    let mut bad_value = answer(&[honest_entry()]);
    bad_value["results"][0]["xdr"] = serde_json::json!("not-xdr");
    for simulation in [bad_auth, bad_value] {
        let outcome = run(Scenario::honest().with_oracle(simulation)).await;
        let error = witness_error(&outcome);
        assert!(
            matches!(
                error,
                WalletError::Network(NetworkError::WitnessUnavailable {
                    reason: WitnessUnavailableReason::InvalidAnswer { .. }
                })
            ),
            "{error:?}"
        );
        assert_eq!(
            outcome.result.as_ref().unwrap_err().wire_code(),
            "network.witness_unavailable"
        );
        assert_witness_refused_before_signing(&outcome);
    }
}

/// The oracle receives the transaction bytes the primary simulated, with no
/// `authMode`.
#[tokio::test]
async fn witness_oracle_simulates_the_primary_envelope() {
    let outcome = run(Scenario::honest().with_oracle(answer(&[honest_entry()]))).await;
    assert_paid_with_witness(&outcome, LATEST_LEDGER);
    let primary = &outcome.bodies[1];
    let oracle = &outcome.oracle_bodies[1];
    assert_eq!(primary["method"], "simulateTransaction");
    assert_eq!(oracle["method"], "simulateTransaction");
    assert_eq!(
        oracle["params"]["transaction"],
        primary["params"]["transaction"]
    );
    assert!(
        oracle["params"].get("authMode").is_none(),
        "{}",
        oracle["params"]
    );
}

/// The oracle's answer is never used: the signed entry carries the primary's
/// nonce, and the payload the primary re-simulation's resource data.
#[tokio::test]
async fn witness_payload_keeps_the_primary_nonce_and_resource_data() {
    let mut entry = honest_entry();
    address_credentials(&mut entry).nonce = NONCE + 7;
    let mut simulation = answer(&[entry]);
    simulation["transactionData"] = serde_json::json!(transaction_data_xdr_with_fee(999));
    let outcome = run(Scenario::honest()
        .with_oracle(simulation)
        .with_resimulation(|_| {
            let mut answer = answer(&[]);
            answer["transactionData"] = serde_json::json!(transaction_data_xdr_with_fee(998));
            answer
        }))
    .await;
    assert_paid_with_witness(&outcome, LATEST_LEDGER);
    let [signed] = outcome.received_signed[0].as_slice() else {
        panic!("one signed entry");
    };
    let SorobanCredentials::Address(credentials) = &signed.credentials else {
        panic!("the signed entry carries Address credentials");
    };
    assert_eq!(credentials.nonce, NONCE, "the primary's nonce is signed");
    let TransactionExt::V1(data) = payment_transaction(&outcome).tx.ext else {
        panic!("the payment carries resource data");
    };
    assert_eq!(
        data,
        transaction_data_with(SorobanTransactionDataExt::V0, 998),
        "the payload carries the primary re-simulation's resource data"
    );
}

/// A primary answer with a second result refuses before the witness, so the
/// oracle receives nothing.
#[tokio::test]
async fn a_second_primary_result_refuses_before_the_witness() {
    let auth = vec![honest_entry().to_xdr_base64(Limits::none()).unwrap()];
    let result = serde_json::json!({ "auth": auth, "xdr": void_xdr() });
    let outcome = run(Scenario::honest()
        .with_first(answer_with_results(&serde_json::json!([
            result.clone(),
            result
        ])))
        .with_oracle(answer(&[honest_entry()])))
    .await;
    assert_simulate_failed(&outcome.result, "simulation returned more than one result");
    assert_nothing_signed_after(&outcome, &["getNetwork", "simulateTransaction"]);
    assert!(outcome.oracle_bodies.is_empty(), "no oracle request");
}

/// A witness that outlasts the caller's deadline refuses at the health read,
/// which keeps the absolute deadline, before anything is signed.
#[tokio::test]
async fn a_witness_slower_than_the_deadline_refuses_at_the_health_read() {
    let outcome = run(Scenario::honest()
        .with_deadline(Duration::from_millis(1_000))
        .with_oracle(answer(&[honest_entry()]))
        .with_oracle_delay(Duration::from_millis(1_500)))
    .await;
    assert_simulate_failed(&outcome.result, "the endpoint's health could not be read");
    assert_eq!(outcome.signing_calls, 0, "nothing is signed");
    assert_eq!(outcome.gate_calls, 0, "the transmit gate does not run");
    assert_eq!(
        outcome
            .methods
            .iter()
            .filter(|method| *method == "simulateTransaction")
            .count(),
        1,
        "the signed re-simulation is never sent"
    );
    assert_eq!(
        methods_of(&outcome.oracle_bodies),
        ["getNetwork", "simulateTransaction"]
    );
}
