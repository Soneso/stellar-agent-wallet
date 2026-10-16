//! `create_payment` signs only the SAC `transfer` it built.
//!
//! A mock RPC on loopback answers both simulations. The unsigned first
//! simulation answers with authorization entries shaped from the honest entry:
//! the payer's unsigned `Address` entry for exactly the transfer the
//! requirements describe, built here from the test's own values. The signed
//! re-simulation answers with entries derived from the signed entry it
//! received. A counting signer records every signing primitive the flow calls
//! and the digest it signs, and a counting transmit gate records whether the
//! flow reached the send.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::error::WalletError;
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
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanResources, SorobanTransactionData,
    SorobanTransactionDataExt, TransactionEnvelope, Uint256, VecM, WriteXdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
use zeroize::Zeroizing;

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

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

fn transaction_data_xdr() -> String {
    SorobanTransactionData {
        ext: SorobanTransactionDataExt::V0,
        resources: SorobanResources {
            footprint: LedgerFootprint {
                read_only: VecM::default(),
                read_write: VecM::default(),
            },
            instructions: 1_000,
            disk_read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee: 1_000,
    }
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

/// The re-simulation answer derived from the signed entries it received.
type Resimulation = Box<dyn Fn(&[SorobanAuthorizationEntry]) -> serde_json::Value + Send + Sync>;

/// Simulate endpoint for both simulations of one payment.
///
/// A request without authorization entries is the first simulation, and one
/// with entries is the signed re-simulation.
struct SimulateRpc {
    first: serde_json::Value,
    resimulation: Resimulation,
    /// The entries each re-simulation request carried.
    received_signed: Arc<Mutex<Vec<Vec<SorobanAuthorizationEntry>>>>,
}

impl Respond for SimulateRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("a JSON-RPC request body");
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
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": result,
            }))
            .insert_header("content-type", "application/json")
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
    async fn sign_tx_payload(&self, payload: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        self.other_signing_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_tx_payload(payload).await
    }

    async fn sign_auth_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        self.other_signing_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_auth_digest(digest).await
    }

    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &[u8; 32],
    ) -> Result<[u8; 64], WalletError> {
        self.address_auth_digests.lock().unwrap().push(*payload);
        self.inner.sign_soroban_address_auth_payload(payload).await
    }

    async fn sign_webauthn_assertion(
        &self,
        auth_digest: &[u8; 32],
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

/// What one `create_payment` call returned and caused.
struct Outcome {
    result: Result<PaymentPayload, X402Error>,
    address_auth_digests: Vec<[u8; 32]>,
    signing_calls: usize,
    gate_calls: usize,
    simulate_requests: usize,
    requests: usize,
    received_signed: Vec<Vec<SorobanAuthorizationEntry>>,
}

/// Runs `create_payment` against a mock answering the first simulation with
/// `first` and the re-simulation with `resimulation`.
async fn pay(
    first: serde_json::Value,
    resimulation: impl Fn(&[SorobanAuthorizationEntry]) -> serde_json::Value + Send + Sync + 'static,
) -> Outcome {
    let received_signed = Arc::new(Mutex::new(Vec::new()));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(SimulateRpc {
            first,
            resimulation: Box::new(resimulation),
            received_signed: Arc::clone(&received_signed),
        })
        .mount(&server)
        .await;
    let signer = CountingSigner::new();
    let gate_calls = AtomicUsize::new(0);
    let result = create_payment(
        &requirements(),
        &signer,
        &server.uri(),
        TESTNET_PASSPHRASE,
        |_| {
            gate_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .await;
    let address_auth_digests = signer.address_auth_digests.lock().unwrap().clone();
    let signing_calls =
        address_auth_digests.len() + signer.other_signing_calls.load(Ordering::SeqCst);
    let requests = server
        .received_requests()
        .await
        .expect("request recording is enabled")
        .len();
    let received_signed = received_signed.lock().unwrap().clone();
    Outcome {
        result,
        address_auth_digests,
        signing_calls,
        gate_calls: gate_calls.load(Ordering::SeqCst),
        simulate_requests: rpc_request_count(&server, "simulateTransaction").await,
        requests,
        received_signed,
    }
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
    assert_eq!(outcome.requests, 1, "no other request is sent");
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
    assert_eq!(outcome.requests, 2, "no other request is sent");
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
