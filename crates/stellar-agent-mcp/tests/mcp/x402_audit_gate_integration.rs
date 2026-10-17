//! The x402 payment tools write `x402_payment_authorized` before the signed
//! authorization leaves the wallet.
//!
//! `create_payment` sends the signed authorization to the profile's RPC in the
//! re-simulation request. The mock RPC here answers every method the payment
//! sends, routed by method: `getNetwork` for the endpoint identity check,
//! `getHealth` for the ledger consistency read, and `simulateTransaction` for
//! both simulations; any other method panics. It inspects every simulate
//! request: the unsigned first simulate carries no authorization entry, and
//! the signed re-simulation carries the payer's signed entry. Its handler for
//! the signed request counts the `x402_payment_authorized` rows already in the
//! log, so a row written after the send, or not at all, fails the test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{
    WalletServer, X402AuthenticatedPaymentArgs, X402CreatePaymentArgs,
};
use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};
use stellar_xdr::{
    AccountId, ContractId, Hash, HostFunction, InvokeContractArgs, Limits, OperationBody,
    PublicKey, ReadXdr, ScAddress, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
    TransactionEnvelope, Uint256, VecM, WriteXdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// SAC token contract the payment transfers.
const ASSET: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

/// Payment recipient.
const PAY_TO: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/// A real `SorobanTransactionData` body the re-simulation answers with.
const TRANSACTION_DATA: &str = "AAAAAAAAAAIAAAAGAAAAAcwD/nT9D7Dc2LxRdab+2vEUF8B+XoN7mQW21oxPT8ALAAAAFAAAAAEAAAAHy8vNUZ8vyZ2ybPHW0XbSrRtP7gEWsJ6zDzcfY9P8z88AAAABAAAABgAAAAHMA/50/Q+w3Ni8UXWm/trxFBfAfl6De5kFttaMT0/ACwAAABAAAAABAAAAAgAAAA8AAAAHQ291bnRlcgAAAAASAAAAAAAAAAAg4dbAxsGAGICfBG3iT2cKGYQ6hK4sJWzZ6or1C5v6GAAAAAEAHfKyAAAFiAAAAIgAAAAAAAAAAw==";

/// Keyring service holding the payer's secret.
const SIGNER_SERVICE: &str = "x402-gate-svc";

/// How the mock answers the first, unsigned simulate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FirstSimulate {
    /// The authorization entry the host would require.
    Ok,
    /// An RPC error: `create_payment` fails before any signature exists.
    Error,
    /// An RPC error whose text is [`hostile_simulation_error`].
    HostileError,
    /// The payer's entry for a transfer of another amount than the one the
    /// wallet built.
    OtherAmount,
    /// The honest entry with a minimum resource fee above the wallet's
    /// ceiling.
    FeeAboveCeiling,
}

/// How the mock answers the signed re-simulation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Resimulation {
    /// Resource data and a fee: the payment completes.
    Ok,
    /// An RPC error in the response.
    RpcError,
    /// A fee and resource data that does not decode.
    UndecodableTransactionData,
    /// The signed entry with another nonce: authorization other than the
    /// signed entry.
    OtherAuthorization,
    /// A minimum resource fee above the wallet's ceiling.
    FeeAboveCeiling,
    /// A restore preamble beside otherwise valid resource data.
    RestorePreamble,
    /// A latest ledger at the signature expiration ledger.
    LedgerAtExpiration,
    /// A positive minimum resource fee and empty transaction data.
    EmptyTransactionData,
}

/// How the mock answers `getNetwork`.
#[derive(Clone, PartialEq, Eq)]
enum NetworkAnswer {
    /// This passphrase at a supported protocol version.
    Passphrase(&'static str),
    /// This passphrase after a delay.
    Delayed(&'static str, std::time::Duration),
    /// A JSON-RPC error object.
    ErrorObject,
}

/// What the mock observed, shared with the test.
#[derive(Default)]
struct Observed {
    /// `x402_payment_authorized` rows in the log when each signed
    /// re-simulation arrived.
    authorized_rows_at_resimulation: Vec<usize>,
    /// Per simulate request, whether it carried an authorization entry.
    signed: Vec<bool>,
    /// Per signed request, the expiration ledger, the address, and the
    /// invocation of the signed authorization entry it carried.
    transmitted: Vec<(u32, ScAddress, InvokeContractArgs)>,
    /// The method of every request, in the order they arrived.
    methods: Vec<String>,
}

/// Simulate endpoint for the x402 Exact flow.
#[derive(Clone)]
struct X402Rpc {
    payer: ScAddress,
    log_path: PathBuf,
    first: FirstSimulate,
    resimulation: Resimulation,
    network: NetworkAnswer,
    /// Bytes the unsigned simulate writes over the log, once: a rollback that
    /// lands after the audit pre-flight and before the transmit gate.
    roll_back_to: Arc<Mutex<Option<Vec<u8>>>>,
    /// The keyring entry the unsigned simulate deletes: the signer loaded
    /// before it then fails at the sign call.
    forget_on_first: Option<(String, String)>,
    observed: Arc<Mutex<Observed>>,
}

impl X402Rpc {
    fn new(payer: &str, log_path: PathBuf) -> Self {
        Self {
            payer: payer_sc_address(payer),
            log_path,
            first: FirstSimulate::Ok,
            resimulation: Resimulation::Ok,
            network: NetworkAnswer::Passphrase(TESTNET_PASSPHRASE),
            roll_back_to: Arc::new(Mutex::new(None)),
            forget_on_first: None,
            observed: Arc::new(Mutex::new(Observed::default())),
        }
    }

    fn authorized_rows_in_log(&self) -> usize {
        std::fs::read_to_string(&self.log_path)
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains(r#""kind":"x402_payment_authorized""#))
            .count()
    }
}

fn simulate_result(req_id: serde_json::Value, result: serde_json::Value) -> ResponseTemplate {
    let mut body = serde_json::Map::new();
    body.insert("jsonrpc".to_owned(), serde_json::Value::from("2.0"));
    body.insert("id".to_owned(), req_id);
    body.insert("result".to_owned(), result);
    ResponseTemplate::new(200)
        .set_body_json(serde_json::Value::Object(body))
        .insert_header("content-type", "application/json")
}

fn void_xdr() -> String {
    ScVal::Void
        .to_xdr_base64(Limits::none())
        .expect("ScVal::Void encodes")
}

/// Testnet passphrase the profiles here serve.
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Mainnet passphrase.
const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// A network that is neither testnet nor mainnet.
const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";

/// Latest ledger of every answer, and the health ledger.
const LEDGER: u32 = 1000;

/// A minimum resource fee one stroop above the wallet's ceiling.
const FEE_ABOVE_CEILING: &str = "10000001";

impl X402Rpc {
    fn network_answer(&self, req_id: &serde_json::Value) -> ResponseTemplate {
        let answer = |passphrase: &str| {
            simulate_result(
                req_id.clone(),
                serde_json::json!({
                    "friendbotUrl": "https://friendbot.stellar.org",
                    "passphrase": passphrase,
                    "protocolVersion": 29,
                }),
            )
        };
        match &self.network {
            NetworkAnswer::Passphrase(passphrase) => answer(passphrase),
            NetworkAnswer::Delayed(passphrase, delay) => answer(passphrase).set_delay(*delay),
            NetworkAnswer::ErrorObject => ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32603, "message": "backend unavailable"},
                }))
                .insert_header("content-type", "application/json"),
        }
    }
}

impl Respond for X402Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body)
            .unwrap_or_else(|_| serde_json::json!({}));
        let req_id = body
            .get("id")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(1));
        let method = body
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        self.observed.lock().unwrap().methods.push(method.clone());
        match method.as_str() {
            "getNetwork" => return self.network_answer(&req_id),
            "getHealth" => {
                return simulate_result(
                    req_id,
                    serde_json::json!({
                        "status": "healthy",
                        "latestLedger": LEDGER,
                        "oldestLedger": 1,
                        "ledgerRetentionWindow": 17_280,
                    }),
                );
            }
            "simulateTransaction" => {}
            other => panic!("the x402 flow sends no {other:?} request"),
        }
        let envelope_b64 = body
            .get("params")
            .and_then(|params| params.get("transaction"))
            .and_then(serde_json::Value::as_str)
            .expect("simulateTransaction carries a transaction envelope");
        let envelope = TransactionEnvelope::from_xdr_base64(envelope_b64, Limits::none())
            .expect("the tool must send a decodable envelope");
        let TransactionEnvelope::Tx(transaction) = envelope else {
            panic!("the x402 flow builds a v1 envelope");
        };
        let operation = transaction
            .tx
            .operations
            .first()
            .expect("one operation")
            .clone();
        let OperationBody::InvokeHostFunction(host) = operation.body else {
            panic!("the x402 flow builds an InvokeHostFunction operation");
        };
        let HostFunction::InvokeContract(invoke) = host.host_function else {
            panic!("the x402 flow invokes a contract");
        };
        let signed_entries = host.auth.to_vec();
        let signed = !signed_entries.is_empty();
        self.observed.lock().unwrap().signed.push(signed);
        if let Some(entry) = host.auth.first()
            && let SorobanCredentials::Address(credentials) = &entry.credentials
            && let SorobanAuthorizedFunction::ContractFn(function) = &entry.root_invocation.function
        {
            self.observed.lock().unwrap().transmitted.push((
                credentials.signature_expiration_ledger,
                credentials.address.clone(),
                function.clone(),
            ));
        }

        if !signed {
            if let Some(bytes) = self.roll_back_to.lock().unwrap().take() {
                std::fs::write(&self.log_path, bytes).expect("roll the audit log back");
            }
            if let Some((service, account)) = &self.forget_on_first {
                keyring_core::Entry::new(service, account)
                    .expect("Entry::new")
                    .delete_credential()
                    .expect("delete the signer's secret");
            }
            if self.first == FirstSimulate::Error {
                return simulate_result(
                    req_id,
                    serde_json::json!({"error": "host invocation failed", "latestLedger": 1000}),
                );
            }
            if self.first == FirstSimulate::HostileError {
                return simulate_result(
                    req_id,
                    serde_json::json!({"error": hostile_simulation_error(), "latestLedger": 1000}),
                );
            }
            let mut invoke = invoke;
            if self.first == FirstSimulate::OtherAmount {
                let mut args = invoke.args.to_vec();
                args[2] = ScVal::from(1_i128 << 62);
                invoke.args = args.try_into().expect("three arguments");
            }
            let entry = SorobanAuthorizationEntry {
                credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                    address: self.payer.clone(),
                    nonce: 7,
                    signature_expiration_ledger: 0,
                    signature: ScVal::Void,
                }),
                root_invocation: SorobanAuthorizedInvocation {
                    function: SorobanAuthorizedFunction::ContractFn(invoke),
                    sub_invocations: VecM::default(),
                },
            };
            let min_resource_fee = if self.first == FirstSimulate::FeeAboveCeiling {
                FEE_ABOVE_CEILING
            } else {
                "1000"
            };
            return simulate_result(
                req_id,
                serde_json::json!({
                    "transactionData": TRANSACTION_DATA,
                    "minResourceFee": min_resource_fee,
                    "results": [{
                        "auth": [entry.to_xdr_base64(Limits::none()).expect("entry encodes")],
                        "xdr": void_xdr(),
                    }],
                    "latestLedger": 1000,
                }),
            );
        }

        // The signed authorization has arrived: the row recording it must
        // already be durable.
        let rows = self.authorized_rows_in_log();
        self.observed
            .lock()
            .unwrap()
            .authorized_rows_at_resimulation
            .push(rows);
        if rows != 1 {
            return simulate_result(
                req_id,
                serde_json::json!({"error": "no authorization row", "latestLedger": 1000}),
            );
        }
        match self.resimulation {
            Resimulation::Ok => simulate_result(
                req_id,
                serde_json::json!({
                    "transactionData": TRANSACTION_DATA,
                    "minResourceFee": "1000",
                    "results": [{"auth": [], "xdr": void_xdr()}],
                    "latestLedger": 1000,
                }),
            ),
            Resimulation::RpcError => simulate_result(
                req_id,
                serde_json::json!({"error": "re-simulation trapped", "latestLedger": 1000}),
            ),
            Resimulation::UndecodableTransactionData => simulate_result(
                req_id,
                serde_json::json!({
                    "transactionData": "AAAA",
                    "minResourceFee": "1000",
                    "results": [{"auth": [], "xdr": void_xdr()}],
                    "latestLedger": 1000,
                }),
            ),
            Resimulation::OtherAuthorization => {
                let mut entry = signed_entries[0].clone();
                let SorobanCredentials::Address(credentials) = &mut entry.credentials else {
                    panic!("the signed entry carries Address credentials");
                };
                credentials.nonce += 1;
                simulate_result(
                    req_id,
                    serde_json::json!({
                        "transactionData": TRANSACTION_DATA,
                        "minResourceFee": "1000",
                        "results": [{
                            "auth": [entry.to_xdr_base64(Limits::none()).expect("entry encodes")],
                            "xdr": void_xdr(),
                        }],
                        "latestLedger": 1000,
                    }),
                )
            }
            Resimulation::FeeAboveCeiling => simulate_result(
                req_id,
                serde_json::json!({
                    "transactionData": TRANSACTION_DATA,
                    "minResourceFee": FEE_ABOVE_CEILING,
                    "results": [{"auth": [], "xdr": void_xdr()}],
                    "latestLedger": 1000,
                }),
            ),
            Resimulation::RestorePreamble => simulate_result(
                req_id,
                serde_json::json!({
                    "transactionData": TRANSACTION_DATA,
                    "minResourceFee": "1000",
                    "results": [{"auth": [], "xdr": void_xdr()}],
                    "restorePreamble": {
                        "transactionData": TRANSACTION_DATA,
                        "minResourceFee": "5000",
                    },
                    "latestLedger": 1000,
                }),
            ),
            Resimulation::LedgerAtExpiration => simulate_result(
                req_id,
                serde_json::json!({
                    "transactionData": TRANSACTION_DATA,
                    "minResourceFee": "1000",
                    "results": [{"auth": [], "xdr": void_xdr()}],
                    "latestLedger": 1060,
                }),
            ),
            Resimulation::EmptyTransactionData => simulate_result(
                req_id,
                serde_json::json!({
                    "transactionData": "",
                    "minResourceFee": "1000",
                    "results": [{"auth": [], "xdr": void_xdr()}],
                    "latestLedger": 1000,
                }),
            ),
        }
    }
}

/// Derives the G-strkey for a 32-byte ed25519 seed.
fn gstrkey_for_seed(seed: [u8; 32]) -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
        .to_string()
        .to_string()
}

/// Derives the S-strkey for a 32-byte ed25519 seed.
fn sstrkey_for_seed(seed: [u8; 32]) -> String {
    stellar_strkey::ed25519::PrivateKey(seed)
        .as_unredacted()
        .to_string()
        .to_string()
}

fn payer_sc_address(payer: &str) -> ScAddress {
    let key = stellar_strkey::ed25519::PublicKey::from_string(payer).expect("payer G-strkey");
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key.0))))
}

/// Which x402 tool a case drives.
#[derive(Clone, Copy, Debug)]
enum Tool {
    CreatePayment,
    AuthenticatedPayment,
}

impl Tool {
    fn name(self) -> &'static str {
        match self {
            Self::CreatePayment => "stellar_x402_create_payment",
            Self::AuthenticatedPayment => "stellar_x402_authenticated_payment",
        }
    }
}

/// One isolated payer, profile, mock RPC, and server.
///
/// The payer seed names the payer account, and the shared test audit log is
/// named after that account. A seed therefore belongs to one profile name in
/// the whole test binary: the tests here use seeds no other suite uses.
struct Fixture {
    _home: tempfile::TempDir,
    _home_guard: StellarAgentHomeGuard,
    profile: Profile,
    server: WalletServer,
    mock: MockServer,
    rpc: X402Rpc,
}

async fn fixture(
    profile_name: &str,
    seed: [u8; 32],
    configure: impl FnOnce(&mut X402Rpc),
) -> Fixture {
    fixture_with_profile(profile_name, seed, configure, |_| {}).await
}

/// [`fixture`] with `configure_profile` applied to the profile before the
/// server is built.
async fn fixture_with_profile(
    profile_name: &str,
    seed: [u8; 32],
    configure: impl FnOnce(&mut X402Rpc),
    configure_profile: impl FnOnce(&mut Profile),
) -> Fixture {
    let home = tempfile::tempdir().expect("temp home");
    let home_guard = StellarAgentHomeGuard::new(home.path());
    keyring_mock::install().expect("mock keyring");
    let payer = gstrkey_for_seed(seed);
    keyring_core::Entry::new(SIGNER_SERVICE, &payer)
        .expect("Entry::new")
        .set_password(&sstrkey_for_seed(seed))
        .expect("set_password");
    let mut profile =
        Profile::builder_testnet_named(profile_name, SIGNER_SERVICE, &payer, "n-svc", "n-acct")
            .with_noop_engine()
            .build();
    crate::common::install_test_audit_key(&mut profile);
    let _ = std::fs::remove_file(&profile.audit_log_path);
    let mut rpc = X402Rpc::new(&payer, profile.audit_log_path.clone());
    configure(&mut rpc);
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(rpc.clone())
        .mount(&mock)
        .await;
    profile.rpc_url = mock.uri();
    configure_profile(&mut profile);
    let mut server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    server.set_x402_identity_session_for_test(
        "header.payload.signature".to_owned(),
        gstrkey_for_seed([0x01; 32]),
        Vec::new(),
    );
    Fixture {
        _home: home,
        _home_guard: home_guard,
        profile,
        server,
        mock,
        rpc,
    }
}

fn payment_required() -> String {
    serde_json::json!({
        "scheme": "exact", "network": "stellar:testnet", "asset": ASSET,
        "amount": "10000000", "payTo": PAY_TO, "maxTimeoutSeconds": 300,
        "extra": { "areFeesSponsored": true }
    })
    .to_string()
}

async fn call(fixture: &Fixture, tool: Tool) -> rmcp::model::CallToolResult {
    match tool {
        Tool::CreatePayment => fixture
            .server
            .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                chain_id: "stellar:testnet".into(),
                address: None,
                payment_required: payment_required(),
            })
            .await
            .expect("no protocol error"),
        Tool::AuthenticatedPayment => fixture
            .server
            .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
                chain_id: "stellar:testnet".into(),
                address: None,
                home_domain: "merchant.example".into(),
                payment_required: payment_required(),
            })
            .await
            .expect("no protocol error"),
    }
}

fn result_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .iter()
        .filter_map(|content| content.as_text().map(|text| text.text.clone()))
        .collect::<Vec<_>>()
        .join("");
    serde_json::from_str(&text).expect("tool results carry a JSON envelope")
}

fn x402_rows(profile: &Profile) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    let rows = crate::common::audit_rows(profile);
    let authorized = crate::common::rows_of_kind(&rows, "x402_payment_authorized")
        .into_iter()
        .cloned()
        .collect();
    let withheld = crate::common::rows_of_kind(&rows, "x402_authorization_withheld")
        .into_iter()
        .cloned()
        .collect();
    (authorized, withheld)
}

/// The success path: the authorized row is in the log when the signed
/// re-simulation arrives, and it is the only x402 row afterwards.
async fn the_row_precedes_the_signed_resimulation(tool: Tool, profile_name: &str, seed: u8) {
    let fixture = fixture(profile_name, [seed; 32], |_| {}).await;
    let result = call(&fixture, tool).await;
    let envelope = result_json(&result);
    assert_ne!(result.is_error, Some(true), "{tool:?}: {envelope}");
    assert!(
        envelope["data"]["paymentSignature"].is_string(),
        "{tool:?}: {envelope}"
    );
    let observed = fixture.rpc.observed.lock().unwrap();
    assert_eq!(
        observed.authorized_rows_at_resimulation,
        vec![1],
        "{tool:?}: exactly one x402_payment_authorized row must be durable when the \
         signed authorization reaches the RPC"
    );
    drop(observed);
    let (authorized, withheld) = x402_rows(&fixture.profile);
    assert_eq!(
        authorized.len(),
        1,
        "{tool:?}: one authorized row: {authorized:?}"
    );
    assert!(
        withheld.is_empty(),
        "{tool:?}: no withheld row: {withheld:?}"
    );
    assert_eq!(authorized[0]["tool"], tool.name());
    assert_eq!(authorized[0]["network"], "stellar:testnet");
    assert_eq!(authorized[0]["scheme"], "exact");
}

#[tokio::test]
#[serial]
async fn create_payment_writes_its_row_before_the_signed_resimulation() {
    the_row_precedes_the_signed_resimulation(Tool::CreatePayment, "x402-gate-ok-cp", 0x31).await;
}

#[tokio::test]
#[serial]
async fn authenticated_payment_writes_its_row_before_the_signed_resimulation() {
    the_row_precedes_the_signed_resimulation(Tool::AuthenticatedPayment, "x402-gate-ok-ap", 0x32)
        .await;
}

/// A refusing strict write at the gate: the log is rolled back after the
/// pre-flight passed, so the gate's write refuses. Only the unsigned simulate
/// reaches the RPC, and no signature is returned.
async fn a_refused_gate_write_sends_nothing_signed(tool: Tool, profile_name: &str, seed: u8) {
    let fixture = fixture(profile_name, [seed; 32], |_| {}).await;
    // First payment: anchors a non-empty log.
    let first = call(&fixture, tool).await;
    assert_ne!(first.is_error, Some(true), "{}", result_json(&first));
    fixture.mock.reset().await;
    Mock::given(method("POST"))
        .respond_with(fixture.rpc.clone())
        .mount(&fixture.mock)
        .await;
    fixture.rpc.observed.lock().unwrap().signed.clear();
    *fixture.rpc.roll_back_to.lock().unwrap() = Some(Vec::new());
    let log_rows_before = crate::common::audit_rows(&fixture.profile).len();
    assert!(log_rows_before > 0);

    let second = call(&fixture, tool).await;
    let (code, _message, text) = crate::common::assert_business_envelope(&second);
    assert_eq!(
        code, "audit.tip_anchor_mismatch",
        "{tool:?}: the gate's refusal answers its own audit code"
    );
    assert!(
        !text.contains("paymentSignature"),
        "{tool:?}: no signature may be returned: {text}"
    );
    let signed = fixture.rpc.observed.lock().unwrap().signed.clone();
    assert_eq!(
        signed,
        vec![false],
        "{tool:?}: exactly one RPC request, carrying no signature"
    );
    let (authorized, withheld) = x402_rows(&fixture.profile);
    assert!(
        authorized.is_empty() && withheld.is_empty(),
        "{tool:?}: the rolled-back log takes no row"
    );
}

#[tokio::test]
#[serial]
async fn create_payment_withholds_when_the_gate_write_refuses() {
    a_refused_gate_write_sends_nothing_signed(Tool::CreatePayment, "x402-gate-refuse-cp", 0x33)
        .await;
}

#[tokio::test]
#[serial]
async fn authenticated_payment_withholds_when_the_gate_write_refuses() {
    a_refused_gate_write_sends_nothing_signed(
        Tool::AuthenticatedPayment,
        "x402-gate-refuse-ap",
        0x34,
    )
    .await;
}

/// A failure after the gate writes a withheld row paired with the authorized
/// row by `request_id`.
async fn a_failure_after_the_gate_is_paired(
    tool: Tool,
    profile_name: &str,
    seed: u8,
    resimulation: Resimulation,
    expected_stage: &str,
    expected_code: &str,
) {
    let fixture = fixture(profile_name, [seed; 32], |rpc| {
        rpc.resimulation = resimulation;
    })
    .await;
    let result = call(&fixture, tool).await;
    let (code, _message, text) = crate::common::assert_business_envelope(&result);
    assert_eq!(
        code, expected_code,
        "{tool:?}: the primary error is returned"
    );
    assert!(!text.contains("paymentSignature"), "{text}");
    let (authorized, withheld) = x402_rows(&fixture.profile);
    assert_eq!(authorized.len(), 1, "{tool:?}: {authorized:?}");
    assert_eq!(withheld.len(), 1, "{tool:?}: {withheld:?}");
    assert_eq!(withheld[0]["failure_stage"], expected_stage);
    assert_eq!(withheld[0]["tool"], tool.name());
    assert_eq!(
        withheld[0]["request_id"], authorized[0]["request_id"],
        "{tool:?}: the two rows share one request id"
    );
    let rows = crate::common::audit_rows(&fixture.profile);
    let authorized_at = rows
        .iter()
        .position(|row| row["kind"] == "x402_payment_authorized")
        .unwrap();
    let withheld_at = rows
        .iter()
        .position(|row| row["kind"] == "x402_authorization_withheld")
        .unwrap();
    assert!(
        authorized_at < withheld_at,
        "the authorized row comes first"
    );
}

#[tokio::test]
#[serial]
async fn create_payment_resimulation_error_writes_a_paired_withheld_row() {
    a_failure_after_the_gate_is_paired(
        Tool::CreatePayment,
        "x402-gate-resim-cp",
        0x35,
        Resimulation::RpcError,
        "resimulation",
        "x402.rpc_simulate_failed",
    )
    .await;
}

#[tokio::test]
#[serial]
async fn authenticated_payment_resimulation_error_writes_a_paired_withheld_row() {
    a_failure_after_the_gate_is_paired(
        Tool::AuthenticatedPayment,
        "x402-gate-resim-ap",
        0x36,
        Resimulation::RpcError,
        "resimulation",
        "x402.payment_build_failed",
    )
    .await;
}

#[tokio::test]
#[serial]
async fn create_payment_undecodable_resimulation_data_is_response_processing() {
    a_failure_after_the_gate_is_paired(
        Tool::CreatePayment,
        "x402-gate-data-cp",
        0x37,
        Resimulation::UndecodableTransactionData,
        "response_processing",
        "x402.transaction_build_failed",
    )
    .await;
}

#[tokio::test]
#[serial]
async fn authenticated_payment_undecodable_resimulation_data_is_response_processing() {
    a_failure_after_the_gate_is_paired(
        Tool::AuthenticatedPayment,
        "x402-gate-data-ap",
        0x38,
        Resimulation::UndecodableTransactionData,
        "response_processing",
        "x402.payment_build_failed",
    )
    .await;
}

#[tokio::test]
#[serial]
async fn create_payment_resimulated_other_authorization_writes_a_paired_withheld_row() {
    a_failure_after_the_gate_is_paired(
        Tool::CreatePayment,
        "x402-gate-auth-cp",
        0x3c,
        Resimulation::OtherAuthorization,
        "response_processing",
        "x402.unexpected_auth_entries",
    )
    .await;
}

#[tokio::test]
#[serial]
async fn authenticated_payment_resimulated_other_authorization_writes_a_paired_withheld_row() {
    a_failure_after_the_gate_is_paired(
        Tool::AuthenticatedPayment,
        "x402-gate-auth-ap",
        0x3d,
        Resimulation::OtherAuthorization,
        "response_processing",
        "x402.payment_build_failed",
    )
    .await;
}

/// An error before the gate ran: nothing was signed or sent signed, and no x402
/// row is written.
async fn an_error_before_the_gate_writes_no_row(tool: Tool, profile_name: &str, seed: u8) {
    let fixture = fixture(profile_name, [seed; 32], |rpc| {
        rpc.first = FirstSimulate::Error;
    })
    .await;
    let result = call(&fixture, tool).await;
    let _ = crate::common::assert_business_envelope(&result);
    let (authorized, withheld) = x402_rows(&fixture.profile);
    assert!(authorized.is_empty(), "{tool:?}: {authorized:?}");
    assert!(withheld.is_empty(), "{tool:?}: {withheld:?}");
    assert_eq!(
        fixture.rpc.observed.lock().unwrap().signed,
        vec![false],
        "{tool:?}: only the unsigned simulate was sent"
    );
}

/// A simulation `error` a hostile endpoint could send: a credential-bearing
/// URL, quotes, a terminal escape, and a thousand characters.
fn hostile_simulation_error() -> String {
    format!(
        "host https://user:PWSECRET@leak.example/rpc?k=QSECRET said \"no\"\u{1b}[2J {}",
        "e".repeat(1000)
    )
}

/// The simulation `error` reaches the tool result scrubbed: the URL as host
/// and port, the quotes and the escape escaped, quoted, and cut at the bound.
async fn a_simulation_error_reaches_the_tool_result_scrubbed(
    tool: Tool,
    profile_name: &str,
    seed: u8,
    expected_code: &str,
) {
    let fixture = fixture(profile_name, [seed; 32], |rpc| {
        rpc.first = FirstSimulate::HostileError;
    })
    .await;
    let result = call(&fixture, tool).await;
    let (code, message, text) = crate::common::assert_business_envelope(&result);
    assert_eq!(code, expected_code, "{tool:?}: {text}");
    let quoted = format!(
        "\"{}{}\"...",
        r#"host leak.example said \"no\"\u{001b}[2J "#,
        "e".repeat(stellar_agent_network::MAX_SERVER_TEXT_CHARS - 41)
    );
    assert!(
        message.ends_with(&format!("simulate returned error: {quoted}")),
        "{tool:?}: {message}"
    );
    for leaked in ["PWSECRET", "QSECRET", "https:", "/rpc", "\u{1b}"] {
        assert!(
            !text.contains(leaked),
            "{tool:?}: {leaked:?} survived: {text}"
        );
    }
    assert!(!message.contains(&"e".repeat(300)), "{tool:?}: {message}");
}

#[tokio::test]
#[serial]
async fn create_payment_simulation_error_reaches_the_tool_result_scrubbed() {
    a_simulation_error_reaches_the_tool_result_scrubbed(
        Tool::CreatePayment,
        "x402-gate-scrub-cp",
        0x4a,
        "x402.rpc_simulate_failed",
    )
    .await;
}

#[tokio::test]
#[serial]
async fn authenticated_payment_simulation_error_reaches_the_tool_result_scrubbed() {
    a_simulation_error_reaches_the_tool_result_scrubbed(
        Tool::AuthenticatedPayment,
        "x402-gate-scrub-ap",
        0x4b,
        "x402.payment_build_failed",
    )
    .await;
}

#[tokio::test]
#[serial]
async fn create_payment_error_before_the_gate_writes_no_row() {
    an_error_before_the_gate_writes_no_row(Tool::CreatePayment, "x402-gate-early-cp", 0x39).await;
}

#[tokio::test]
#[serial]
async fn authenticated_payment_error_before_the_gate_writes_no_row() {
    an_error_before_the_gate_writes_no_row(Tool::AuthenticatedPayment, "x402-gate-early-ap", 0x3a)
        .await;
}

/// A simulated authorization for another transfer than the one the wallet
/// built is refused before signing: the gate never runs, no x402 row is
/// written, and only the unsigned simulate reaches the RPC.
async fn a_simulated_authorization_for_another_transfer_is_not_signed(
    tool: Tool,
    profile_name: &str,
    seed: u8,
    expected_code: &str,
) {
    let fixture = fixture(profile_name, [seed; 32], |rpc| {
        rpc.first = FirstSimulate::OtherAmount;
    })
    .await;
    let result = call(&fixture, tool).await;
    let (code, _message, text) = crate::common::assert_business_envelope(&result);
    assert_eq!(code, expected_code, "{tool:?}: the tool's wire code");
    assert!(
        !text.contains("paymentSignature"),
        "{tool:?}: no signature may be returned: {text}"
    );
    let (authorized, withheld) = x402_rows(&fixture.profile);
    assert!(authorized.is_empty(), "{tool:?}: {authorized:?}");
    assert!(withheld.is_empty(), "{tool:?}: {withheld:?}");
    assert_eq!(
        fixture.rpc.observed.lock().unwrap().signed,
        vec![false],
        "{tool:?}: one simulate request, carrying no signature"
    );
}

#[tokio::test]
#[serial]
async fn create_payment_refuses_a_simulated_authorization_for_another_transfer() {
    a_simulated_authorization_for_another_transfer_is_not_signed(
        Tool::CreatePayment,
        "x402-gate-other-cp",
        0x3e,
        "x402.unexpected_auth_entries",
    )
    .await;
}

#[tokio::test]
#[serial]
async fn authenticated_payment_refuses_a_simulated_authorization_for_another_transfer() {
    a_simulated_authorization_for_another_transfer_is_not_signed(
        Tool::AuthenticatedPayment,
        "x402-gate-other-ap",
        0x3f,
        "x402.payment_build_failed",
    )
    .await;
}

/// The transmit gate sees the authorization that then leaves the wallet. Its
/// payer, recipient, asset, amount, and expiration ledger are those of the
/// signed entry the re-simulation carries to the RPC.
#[tokio::test]
#[serial]
async fn the_transmit_gate_sees_the_authorization_the_resimulation_carries() {
    let seed = [0x3b_u8; 32];
    let fixture = fixture("x402-gate-values", seed, |_| {}).await;
    let requirements: stellar_agent_x402::wire::PaymentRequirements =
        serde_json::from_str(&payment_required()).expect("payment requirements parse");
    let signer = stellar_agent_network::signing::SoftwareSigningKey::new_from_zeroizing(
        zeroize::Zeroizing::new(seed),
    );

    let mut seen = None;
    // No row is written here, so the mock answers the signed request with an
    // error after recording it; the result does not matter to this test.
    let client = stellar_agent_network::StellarRpcClient::new(&fixture.mock.uri())
        .expect("the loopback URL parses");
    let _ = stellar_agent_x402::exact::create_payment(
        &requirements,
        &signer,
        &client,
        &fixture.profile.network_passphrase,
        tokio::time::Instant::now() + std::time::Duration::from_secs(60),
        |authorization| {
            seen = Some((
                authorization.network.to_owned(),
                authorization.scheme.to_owned(),
                authorization.payer.to_owned(),
                authorization.pay_to.to_owned(),
                authorization.asset.to_owned(),
                authorization.amount,
                authorization.signature_expiration_ledger,
            ));
            Ok(())
        },
    )
    .await;

    let (network, scheme, payer, pay_to, asset, amount, expiration) =
        seen.expect("the transmit gate ran");
    assert_eq!(network, "stellar:testnet");
    assert_eq!(scheme, "exact");
    assert_eq!(payer, gstrkey_for_seed(seed));
    assert_eq!(pay_to, PAY_TO);
    assert_eq!(asset, ASSET);
    assert_eq!(amount, 10_000_000);
    assert_eq!(
        expiration, 1060,
        "latest ledger 1000 plus ceil(300 s / 5 s) ledgers"
    );

    let observed = fixture.rpc.observed.lock().unwrap();
    let [(sent_expiration, sent_address, sent_function)] = observed.transmitted.as_slice() else {
        panic!("one signed request: {:?}", observed.signed);
    };
    assert_eq!(*sent_expiration, expiration);
    assert_eq!(*sent_address, payer_sc_address(&payer));
    let asset_id = stellar_strkey::Contract::from_string(&asset).expect("asset C-strkey");
    assert_eq!(
        sent_function.contract_address,
        ScAddress::Contract(ContractId(Hash(asset_id.0)))
    );
    assert_eq!(
        sent_function.args[0],
        ScVal::Address(payer_sc_address(&payer))
    );
    assert_eq!(
        sent_function.args[1],
        ScVal::Address(payer_sc_address(&pay_to))
    );
    assert_eq!(sent_function.args[2], ScVal::from(amount));
}

// ── Endpoint identity through both tools ─────────────────────────────────────

/// The successful primary sequence of one payment.
const PAYMENT_METHODS: [&str; 4] = [
    "getNetwork",
    "simulateTransaction",
    "getHealth",
    "simulateTransaction",
];

/// Both tools build exactly one client per payment under a Noop policy, and
/// every request of the payment goes to it: the identity check first, then
/// the simulations and the health read.
async fn the_primary_client_serves_the_whole_payment(tool: Tool, profile_name: &str, seed: u8) {
    let fixture = fixture(profile_name, [seed; 32], |_| {}).await;
    let (result, built) = crate::common::clients_built_by(call(&fixture, tool)).await;
    let envelope = result_json(&result);
    assert_ne!(result.is_error, Some(true), "{tool:?}: {envelope}");
    assert!(
        envelope["data"]["paymentSignature"].is_string(),
        "{tool:?}: {envelope}"
    );
    assert_eq!(built, 1, "{tool:?}: one client per payment");
    assert_eq!(
        fixture.rpc.observed.lock().unwrap().methods,
        PAYMENT_METHODS,
        "{tool:?}: the identity check is the client's first request"
    );
}

#[tokio::test]
#[serial]
async fn mcp_x402_tools_share_the_primary_client() {
    the_primary_client_serves_the_whole_payment(Tool::CreatePayment, "x402-client-cp", 0xc6).await;
    the_primary_client_serves_the_whole_payment(Tool::AuthenticatedPayment, "x402-client-ap", 0xc7)
        .await;
}

/// An endpoint that fails the identity check answers its own network code
/// through both tools: an error result, no payload, no simulation, and no
/// x402 audit row. The authenticated tool does not collapse it into
/// `x402.payment_build_failed`.
#[tokio::test]
#[serial]
async fn mcp_x402_identity_errors_keep_network_codes() {
    let cases = [
        (
            NetworkAnswer::Passphrase(FUTURENET_PASSPHRASE),
            "network.endpoint_network_mismatch",
        ),
        (
            NetworkAnswer::Passphrase(MAINNET_PASSPHRASE),
            "network.mainnet_write_forbidden",
        ),
        (
            NetworkAnswer::ErrorObject,
            "network.endpoint_identity_unavailable",
        ),
    ];
    let mut seed = 0xc7;
    for (network, code) in cases {
        for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
            seed += 1;
            let profile_name = format!("x402-identity-{seed:x}");
            let answer = network.clone();
            let fixture = fixture_with_profile(
                &profile_name,
                [seed; 32],
                |rpc| rpc.network = answer,
                |profile| profile.submit_timeout_seconds = Some(1),
            )
            .await;
            let result = call(&fixture, tool).await;
            let (got, _message, text) = crate::common::assert_business_envelope(&result);
            assert_eq!(got, code, "{tool:?}");
            assert!(!text.contains("paymentSignature"), "{tool:?}: {text}");
            let observed = fixture.rpc.observed.lock().unwrap();
            assert!(
                observed.signed.is_empty(),
                "{tool:?}: no simulation is sent"
            );
            assert!(
                observed.methods.iter().all(|method| method == "getNetwork"),
                "{tool:?}: {:?}",
                observed.methods
            );
            drop(observed);
            let (authorized, withheld) = x402_rows(&fixture.profile);
            assert!(
                authorized.is_empty() && withheld.is_empty(),
                "{tool:?}: no x402 row"
            );
        }
    }
}

/// A profile URL the transport cannot parse refuses through both tools with
/// `network.rpc_unreachable` before any request.
#[tokio::test]
#[serial]
async fn mcp_x402_client_construction_failure_is_rpc_unreachable() {
    for (tool, profile_name, seed) in [
        (Tool::CreatePayment, "x402-construct-cp", 0xce),
        (Tool::AuthenticatedPayment, "x402-construct-ap", 0xcf),
    ] {
        let fixture = fixture_with_profile(
            profile_name,
            [seed; 32],
            |_| {},
            |profile| {
                profile.rpc_url = "http://archive example.com/rpc".to_owned();
            },
        )
        .await;
        let result = call(&fixture, tool).await;
        let (code, _message, text) = crate::common::assert_business_envelope(&result);
        assert_eq!(code, "network.rpc_unreachable", "{tool:?}");
        assert!(!text.contains("paymentSignature"), "{tool:?}: {text}");
        assert!(
            fixture.rpc.observed.lock().unwrap().methods.is_empty(),
            "{tool:?}: no request"
        );
    }
}

/// The identity check runs under the profile's submit timeout. A configured
/// one second refuses an answer that takes three, whatever the requirement's
/// `maxTimeoutSeconds`. The default of sixty seconds waits for it, even under
/// a one-second `maxTimeoutSeconds`.
#[tokio::test]
#[serial]
async fn mcp_x402_identity_uses_profile_timeout() {
    let slow = NetworkAnswer::Delayed(TESTNET_PASSPHRASE, std::time::Duration::from_secs(3));
    let mut seed = 0xd5;
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        seed += 1;
        let answer = slow.clone();
        let configured = fixture_with_profile(
            &format!("x402-timeout-set-{seed:x}"),
            [seed; 32],
            |rpc| rpc.network = answer,
            |profile| profile.submit_timeout_seconds = Some(1),
        )
        .await;
        let started = std::time::Instant::now();
        let result = call_with(&configured, tool, &payment_required_with(|_| {})).await;
        let (code, _message, _text) = crate::common::assert_business_envelope(&result);
        assert_eq!(code, "network.endpoint_identity_unavailable", "{tool:?}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "{tool:?}: the configured timeout ends the check"
        );

        seed += 1;
        let answer = slow.clone();
        let default = fixture_with_profile(
            &format!("x402-timeout-default-{seed:x}"),
            [seed; 32],
            |rpc| rpc.network = answer,
            |profile| profile.submit_timeout_seconds = None,
        )
        .await;
        let result = call_with(
            &default,
            tool,
            &payment_required_with(|requirements| {
                requirements["maxTimeoutSeconds"] = serde_json::json!(1);
            }),
        )
        .await;
        let envelope = result_json(&result);
        assert_ne!(result.is_error, Some(true), "{tool:?}: {envelope}");
        assert!(
            envelope["data"]["paymentSignature"].is_string(),
            "{tool:?}: {envelope}"
        );
    }
}

/// `payment_required()` edited by `edit`.
fn payment_required_with(edit: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut requirements: serde_json::Value =
        serde_json::from_str(&payment_required()).expect("the fixture parses");
    edit(&mut requirements);
    requirements.to_string()
}

/// Calls `tool` with `payment_required` on the testnet chain.
async fn call_with(
    fixture: &Fixture,
    tool: Tool,
    payment_required: &str,
) -> rmcp::model::CallToolResult {
    call_on_chain(fixture, tool, payment_required, "stellar:testnet")
        .await
        .expect("no protocol error")
}

/// Calls `tool` with `payment_required` and `chain_id`.
async fn call_on_chain(
    fixture: &Fixture,
    tool: Tool,
    payment_required: &str,
    chain_id: &str,
) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
    match tool {
        Tool::CreatePayment => {
            fixture
                .server
                .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                    chain_id: chain_id.into(),
                    address: None,
                    payment_required: payment_required.to_owned(),
                })
                .await
        }
        Tool::AuthenticatedPayment => {
            fixture
                .server
                .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
                    chain_id: chain_id.into(),
                    address: None,
                    home_domain: "merchant.example".into(),
                    payment_required: payment_required.to_owned(),
                })
                .await
        }
    }
}

// ── Bounds after the gate keep their audit stages ────────────────────────────

/// A first simulation above the fee ceiling refuses before the gate: no x402
/// row. The authenticated tool answers `x402.payment_build_failed`.
#[tokio::test]
#[serial]
async fn mcp_resource_refusals_preserve_audit_stages() {
    for (tool, profile_name, seed, code) in [
        (
            Tool::CreatePayment,
            "x402-fee-first-cp",
            0xda,
            "x402.rpc_simulate_failed",
        ),
        (
            Tool::AuthenticatedPayment,
            "x402-fee-first-ap",
            0xdb,
            "x402.payment_build_failed",
        ),
    ] {
        let fixture = fixture(profile_name, [seed; 32], |rpc| {
            rpc.first = FirstSimulate::FeeAboveCeiling;
        })
        .await;
        let result = call(&fixture, tool).await;
        let (got, _message, text) = crate::common::assert_business_envelope(&result);
        assert_eq!(got, code, "{tool:?}");
        assert!(!text.contains("paymentSignature"), "{tool:?}: {text}");
        let (authorized, withheld) = x402_rows(&fixture.profile);
        assert!(
            authorized.is_empty() && withheld.is_empty(),
            "{tool:?}: nothing was signed, so no x402 row"
        );
        assert_eq!(
            fixture.rpc.observed.lock().unwrap().signed,
            vec![false],
            "{tool:?}: only the unsigned simulate was sent"
        );
    }
    a_failure_after_the_gate_is_paired(
        Tool::CreatePayment,
        "x402-fee-resim-cp",
        0xdc,
        Resimulation::FeeAboveCeiling,
        "resimulation",
        "x402.rpc_simulate_failed",
    )
    .await;
    a_failure_after_the_gate_is_paired(
        Tool::AuthenticatedPayment,
        "x402-fee-resim-ap",
        0xdd,
        Resimulation::FeeAboveCeiling,
        "resimulation",
        "x402.payment_build_failed",
    )
    .await;
}

/// A restore preamble in the re-simulation withholds the payload, and the
/// withheld row pairs with the authorized row at stage `resimulation`.
#[tokio::test]
#[serial]
async fn mcp_restore_refusal_records_paired_withheld_row() {
    a_failure_after_the_gate_is_paired(
        Tool::CreatePayment,
        "x402-restore-cp",
        0xde,
        Resimulation::RestorePreamble,
        "resimulation",
        "x402.rpc_simulate_failed",
    )
    .await;
    a_failure_after_the_gate_is_paired(
        Tool::AuthenticatedPayment,
        "x402-restore-ap",
        0xdf,
        Resimulation::RestorePreamble,
        "resimulation",
        "x402.payment_build_failed",
    )
    .await;
}

/// A re-simulation ledger at the expiration ledger withholds the payload, and
/// the withheld row pairs with the authorized row at stage `resimulation`.
#[tokio::test]
#[serial]
async fn mcp_resimulation_past_expiration_records_paired_withheld_row() {
    a_failure_after_the_gate_is_paired(
        Tool::CreatePayment,
        "x402-expiry-cp",
        0xe0,
        Resimulation::LedgerAtExpiration,
        "resimulation",
        "x402.rpc_simulate_failed",
    )
    .await;
    a_failure_after_the_gate_is_paired(
        Tool::AuthenticatedPayment,
        "x402-expiry-ap",
        0xe1,
        Resimulation::LedgerAtExpiration,
        "resimulation",
        "x402.payment_build_failed",
    )
    .await;
}

/// A re-simulation with a positive minimum resource fee and empty transaction
/// data withholds the payload, and the withheld row pairs with the authorized
/// row at stage `resimulation`.
#[tokio::test]
#[serial]
async fn mcp_empty_resimulation_data_records_paired_withheld_row() {
    a_failure_after_the_gate_is_paired(
        Tool::CreatePayment,
        "x402-empty-data-cp",
        0xf8,
        Resimulation::EmptyTransactionData,
        "resimulation",
        "x402.rpc_simulate_failed",
    )
    .await;
    a_failure_after_the_gate_is_paired(
        Tool::AuthenticatedPayment,
        "x402-empty-data-ap",
        0xf9,
        Resimulation::EmptyTransactionData,
        "resimulation",
        "x402.payment_build_failed",
    )
    .await;
}

// ── Validation before admission ──────────────────────────────────────────────

/// A V1 engine whose only rule caps the payment asset at `cap` per day.
fn cap_engine(profile_name: &str, cap: i128) -> stellar_agent_core::PolicyEngineV1 {
    use stellar_agent_core::policy::Decision;
    use stellar_agent_core::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
    use stellar_agent_core::{PolicyDocument, PolicyEngineV1, PolicyRule, RuleMatch, ScopeId};
    PolicyEngineV1::new(
        PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            signature: None,
            rules: vec![PolicyRule {
                r#match: RuleMatch {
                    tool: "*".into(),
                    chain: "*".into(),
                },
                criteria: vec![Box::new(PerPeriodCapCriterion::new(
                    ASSET.into(),
                    Window::parse("1d").expect("window"),
                    cap,
                ))],
                decision: Decision::Allow,
                allow_opaque_signing: false,
            }],
        },
        profile_name.into(),
    )
}

/// The persisted spending window of the payment asset: the summed amount and
/// the count of authorizations.
fn window_state(profile: &Profile, profile_name: &str) -> (i128, u32) {
    use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
    let state = PolicyStateStore::new();
    stellar_agent_network::policy_state::PersistedWindowStore::for_profile(profile_name)
        .load_into(profile_name, profile, &state)
        .expect("the persisted window loads");
    state
        .query_window(
            &StateKey::new(
                profile_name,
                1,
                &stellar_agent_core::policy::v1::value::asset_normalise(ASSET),
                86_400,
            ),
            stellar_agent_core::timefmt::now_unix_ms().expect("clock"),
        )
        .expect("the window reads")
}

/// Every invalid requirement field answers its own `x402.*` code through both
/// tools before any request, and the spending window stays empty.
#[tokio::test]
#[serial]
async fn invalid_requirements_do_not_consume_window() {
    type Edit = fn(&mut serde_json::Value);
    let cases: [(Edit, &str); 8] = [
        (|r| r["scheme"] = "upto".into(), "x402.unsupported_scheme"),
        (
            |r| r["network"] = "stellar:pubnet".into(),
            "x402.network_passphrase_mismatch",
        ),
        (|r| r["asset"] = PAY_TO.into(), "x402.invalid_asset_address"),
        (
            |r| r["extra"] = serde_json::json!({ "areFeesSponsored": false }),
            "x402.fees_not_sponsored",
        ),
        (|r| r["amount"] = "0".into(), "x402.amount_conversion"),
        (
            |r| r["payTo"] = "not-a-strkey".into(),
            "x402.invalid_recipient_address",
        ),
        (
            |r| r["payTo"] = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            "x402.invalid_recipient_address",
        ),
        (
            |r| r["maxTimeoutSeconds"] = 0.into(),
            "x402.invalid_payment_required",
        ),
    ];
    let mut seed = 0xe1;
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        seed += 1;
        let profile_name = format!("x402-invalid-{seed:x}");
        let mut fixture = fixture(&profile_name, [seed; 32], |_| {}).await;
        fixture
            .server
            .set_policy_engine_for_test(Arc::new(cap_engine(&profile_name, 100_000_000)));
        for (edit, code) in cases {
            let result = call_with(&fixture, tool, &payment_required_with(edit)).await;
            let (got, _message, text) = crate::common::assert_business_envelope(&result);
            assert_eq!(got, code, "{tool:?}");
            assert!(!text.contains("paymentSignature"), "{tool:?}: {text}");
        }
        assert!(
            fixture.rpc.observed.lock().unwrap().methods.is_empty(),
            "{tool:?}: invalid requirements send no request"
        );
        assert_eq!(
            window_state(&fixture.profile, &profile_name),
            (0, 0),
            "{tool:?}: invalid requirements consume no headroom"
        );
    }
}

/// The admitted leg is the transfer the payer signs, for a G, a C, and an M
/// recipient. The window holds its amount and asset, and the authorized row
/// its asset and redacted recipient. The signed invocation calls the contract
/// of the admitted asset and carries the same recipient and amount.
#[tokio::test]
#[serial]
async fn valid_requirements_preserve_window_leg() {
    let muxed =
        stellar_strkey::Strkey::MuxedAccountEd25519(stellar_strkey::ed25519::MuxedAccount {
            ed25519: [0x2c; 32],
            id: 77,
        })
        .to_string()
        .as_str()
        .to_owned();
    let recipients = [
        PAY_TO.to_owned(),
        "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".to_owned(),
        muxed,
    ];
    let mut seed = 0xe3;
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        for recipient in &recipients {
            seed += 1;
            let profile_name = format!("x402-leg-{seed:x}");
            let mut fixture = fixture(&profile_name, [seed; 32], |_| {}).await;
            fixture
                .server
                .set_policy_engine_for_test(Arc::new(cap_engine(&profile_name, 100_000_000)));
            let result = call_with(
                &fixture,
                tool,
                &payment_required_with(|r| r["payTo"] = recipient.as_str().into()),
            )
            .await;
            let envelope = result_json(&result);
            assert_ne!(
                result.is_error,
                Some(true),
                "{tool:?} {recipient}: {envelope}"
            );
            assert_eq!(
                window_state(&fixture.profile, &profile_name),
                (10_000_000, 1),
                "{tool:?} {recipient}"
            );
            let (authorized, _) = x402_rows(&fixture.profile);
            let leg = &authorized[0]["legs"][0];
            assert_eq!(leg["amount"], "10000000", "{tool:?} {recipient}");
            assert_eq!(leg["asset"], ASSET, "{tool:?} {recipient}");
            assert_eq!(
                leg["destination_redacted"],
                stellar_agent_core::observability::redact_strkey_first5_last5(recipient),
                "{tool:?} {recipient}"
            );
            let observed = fixture.rpc.observed.lock().unwrap();
            let [(_, _, function)] = observed.transmitted.as_slice() else {
                panic!("{tool:?} {recipient}: one signed request");
            };
            let recipient_address = match stellar_strkey::Strkey::from_string(recipient).unwrap() {
                stellar_strkey::Strkey::PublicKeyEd25519(key) => {
                    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key.0))))
                }
                stellar_strkey::Strkey::Contract(contract) => {
                    ScAddress::Contract(ContractId(Hash(contract.0)))
                }
                stellar_strkey::Strkey::MuxedAccountEd25519(account) => {
                    ScAddress::MuxedAccount(stellar_xdr::MuxedEd25519Account {
                        id: account.id,
                        ed25519: Uint256(account.ed25519),
                    })
                }
                other => panic!("unexpected recipient {other:?}"),
            };
            let admitted_asset = leg["asset"].as_str().expect("the leg names its asset");
            let admitted_contract = stellar_strkey::Contract::from_string(admitted_asset)
                .expect("the admitted asset is a contract strkey");
            assert_eq!(
                function.contract_address,
                ScAddress::Contract(ContractId(Hash(admitted_contract.0))),
                "{tool:?} {recipient}: the signed transfer calls the admitted asset"
            );
            assert_eq!(function.args[1], ScVal::Address(recipient_address));
            assert_eq!(function.args[2], ScVal::from(10_000_000_i128));
        }
    }
}

/// A sibling authorization reserves after evaluation and before accounting.
#[derive(Debug)]
struct CompetingAuthorization(
    stellar_agent_core::policy::v1::criteria::per_period_cap::PerPeriodCapCriterion,
);

impl stellar_agent_core::policy::v1::criteria::Criterion for CompetingAuthorization {
    fn kind(&self) -> &'static str {
        "per_period_cap"
    }

    fn evaluate(
        &self,
        ctx: &stellar_agent_core::policy::v1::EvalContext<'_>,
    ) -> Result<
        Option<stellar_agent_core::policy::DenyReason>,
        stellar_agent_core::policy::PolicyError,
    > {
        self.0.evaluate(ctx)
    }

    fn record_confirmed(
        &self,
        ctx: &stellar_agent_core::policy::v1::EvalContext<'_>,
    ) -> Result<
        Vec<stellar_agent_core::policy::v1::criteria::state_store::WindowEntry>,
        stellar_agent_core::policy::PolicyError,
    > {
        let entries = self.0.record_confirmed(ctx)?;
        stellar_agent_network::policy_state::PersistedWindowStore::for_profile(ctx.profile_name)
            .record_authorized(ctx.profile, &entries)
            .expect("the sibling authorization fits alone");
        Ok(entries)
    }
}

/// An authorization that loses the atomic admission to a sibling refuses
/// through both tools before any request, so nothing is signed or sent, and
/// the window holds only the sibling's spend.
#[tokio::test]
#[serial]
async fn window_admission_refusal_precedes_signing() {
    use stellar_agent_core::policy::Decision;
    use stellar_agent_core::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
    use stellar_agent_core::{PolicyDocument, PolicyEngineV1, PolicyRule, RuleMatch, ScopeId};
    for (tool, profile_name, seed) in [
        (Tool::CreatePayment, "x402-compete-cp", 0xea),
        (Tool::AuthenticatedPayment, "x402-compete-ap", 0xeb),
    ] {
        let mut fixture = fixture(profile_name, [seed; 32], |_| {}).await;
        fixture
            .server
            .set_policy_engine_for_test(Arc::new(PolicyEngineV1::new(
                PolicyDocument {
                    version: 1,
                    scope: ScopeId::AllProfiles,
                    signature: None,
                    rules: vec![PolicyRule {
                        r#match: RuleMatch {
                            tool: "*".into(),
                            chain: "*".into(),
                        },
                        criteria: vec![Box::new(CompetingAuthorization(
                            PerPeriodCapCriterion::new(
                                ASSET.into(),
                                Window::parse("1d").expect("window"),
                                15_000_000,
                            ),
                        ))],
                        decision: Decision::Allow,
                        allow_opaque_signing: false,
                    }],
                },
                profile_name.into(),
            )));
        let result = call(&fixture, tool).await;
        let (code, _message, text) = crate::common::assert_business_envelope(&result);
        assert_eq!(code, "policy.deny.per_period_cap_exceeded", "{tool:?}");
        assert!(!text.contains("paymentSignature"), "{tool:?}: {text}");
        assert!(
            fixture.rpc.observed.lock().unwrap().methods.is_empty(),
            "{tool:?}: admission refuses before any request"
        );
        let (authorized, withheld) = x402_rows(&fixture.profile);
        assert!(authorized.is_empty() && withheld.is_empty(), "{tool:?}");
        assert_eq!(
            window_state(&fixture.profile, profile_name),
            (10_000_000, 1),
            "{tool:?}: only the sibling's spend"
        );
    }
}

/// A failure after admission keeps the admitted spend: the endpoint identity
/// check, the first simulation, the sign call, the transmit gate, and the
/// re-simulation, through both tools.
#[tokio::test]
#[serial]
async fn post_admission_failure_keeps_spend() {
    #[derive(Clone, Copy, Debug)]
    enum Failure {
        Identity,
        Simulation,
        Signing,
        TransmitGate,
        Resimulation,
    }
    let mut seed = 0xeb;
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        for failure in [
            Failure::Identity,
            Failure::Simulation,
            Failure::Signing,
            Failure::TransmitGate,
            Failure::Resimulation,
        ] {
            seed += 1;
            let profile_name = format!("x402-keep-{seed:x}");
            let payer = gstrkey_for_seed([seed; 32]);
            let mut fixture = fixture(&profile_name, [seed; 32], |rpc| match failure {
                Failure::Identity => {
                    rpc.network = NetworkAnswer::Passphrase(FUTURENET_PASSPHRASE);
                }
                Failure::Simulation => rpc.first = FirstSimulate::Error,
                Failure::Signing => {
                    rpc.forget_on_first = Some((SIGNER_SERVICE.to_owned(), payer.clone()));
                }
                Failure::Resimulation => rpc.resimulation = Resimulation::RpcError,
                Failure::TransmitGate => {}
            })
            .await;
            fixture
                .server
                .set_policy_engine_for_test(Arc::new(cap_engine(&profile_name, 100_000_000)));
            let expected = if let Failure::TransmitGate = failure {
                // A first payment anchors a non-empty log; the second payment's
                // unsigned simulate then rolls the log back, so the gate's
                // strict write refuses.
                let first = call(&fixture, tool).await;
                assert_ne!(first.is_error, Some(true), "{}", result_json(&first));
                *fixture.rpc.roll_back_to.lock().unwrap() = Some(Vec::new());
                (20_000_000, 2)
            } else {
                (10_000_000, 1)
            };
            let result = call(&fixture, tool).await;
            let (code, _message, text) = crate::common::assert_business_envelope(&result);
            assert!(
                !text.contains("paymentSignature"),
                "{tool:?} {failure:?}: {text}"
            );
            assert_eq!(
                window_state(&fixture.profile, &profile_name),
                expected,
                "{tool:?} {failure:?} ({code}): the admitted spend stays: {text}"
            );
        }
    }
}

// ── chain_id ─────────────────────────────────────────────────────────────────

/// The generated `chain_id` description of both tools names the wallet's
/// spellings, `stellar:testnet` and `stellar:mainnet`.
#[test]
fn x402_chain_id_schema_uses_mainnet() {
    let expected = concat!(
        "The wallet's CAIP-2 chain identifier: `\"stellar:testnet\"` or\n",
        "`\"stellar:mainnet\"`. The x402 requirement `network` spells mainnet\n",
        "`\"stellar:pubnet\"`; this argument does not.\n",
        "\n",
        "Validated against the active profile after the payment requirements:\n",
        "invalid requirements answer their own `x402.*` code first. A mismatch\n",
        "returns a JSON-RPC `ErrorData` from the `dispatch_gate` preamble.",
    );
    for name in [
        "stellar_x402_create_payment",
        "stellar_x402_authenticated_payment",
    ] {
        let tool = WalletServer::all_registered_tools()
            .into_iter()
            .find(|tool| tool.name == name)
            .unwrap_or_else(|| panic!("{name} is registered"));
        let schema = serde_json::Value::Object((*tool.input_schema).clone());
        assert_eq!(
            schema["properties"]["chain_id"]["description"], expected,
            "{name}"
        );
    }
}

/// Valid requirements with the x402 spelling as `chain_id` reach the
/// dispatch gate, which answers invalid params. Invalid requirements answer
/// their own code before the gate, whatever the `chain_id`. A mainnet profile
/// refuses structurally before both.
#[tokio::test]
#[serial]
async fn x402_chain_arguments_preserve_refusal_order() {
    for (tool, profile_name, seed) in [
        (Tool::CreatePayment, "x402-chain-cp", 0xf6),
        (Tool::AuthenticatedPayment, "x402-chain-ap", 0xf7),
    ] {
        let fixture = fixture(profile_name, [seed; 32], |_| {}).await;
        let error = call_on_chain(&fixture, tool, &payment_required(), "stellar:pubnet")
            .await
            .expect_err("the dispatch gate refuses the chain");
        assert_eq!(
            error.code,
            rmcp::model::ErrorCode::INVALID_PARAMS,
            "{tool:?}"
        );

        let invalid = payment_required_with(|r| r["scheme"] = "upto".into());
        let result = call_on_chain(&fixture, tool, &invalid, "stellar:pubnet")
            .await
            .expect("invalid requirements answer before the gate");
        let (code, _message, _text) = crate::common::assert_business_envelope(&result);
        assert_eq!(code, "x402.unsupported_scheme", "{tool:?}");
        assert!(
            fixture.rpc.observed.lock().unwrap().methods.is_empty(),
            "{tool:?}: no request"
        );
    }

    let mainnet = WalletServer::new(
        Profile::builder_mainnet(
            "https://rpc.example.invalid",
            "svc",
            "acct",
            "n-svc",
            "n-acct",
        )
        .with_noop_engine()
        .build(),
    )
    .expect("WalletServer::new");
    let invalid = payment_required_with(|r| r["scheme"] = "upto".into());
    let created = mainnet
        .call_stellar_x402_create_payment(X402CreatePaymentArgs {
            chain_id: "stellar:pubnet".into(),
            address: None,
            payment_required: invalid.clone(),
        })
        .await
        .expect("the structural refusal is a business envelope");
    assert_eq!(
        crate::common::assert_business_envelope(&created).0,
        "network.mainnet_write_forbidden"
    );
    let authenticated = mainnet
        .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
            chain_id: "stellar:pubnet".into(),
            address: None,
            home_domain: "merchant.example".into(),
            payment_required: invalid,
        })
        .await
        .expect("the structural refusal is a business envelope");
    assert_eq!(
        crate::common::assert_business_envelope(&authenticated).0,
        "network.mainnet_write_forbidden"
    );
}

/// Both x402 tools send the profile's primary credential on every request,
/// the identity request first; without it the endpoint refuses that request
/// with HTTP 401 and the tool ends there with the credential code.
#[tokio::test]
#[serial]
async fn x402_tools_send_the_primary_credential() {
    use stellar_agent_core::profile::schema::ProviderRole;
    for (tool, name, seed, bare_name, bare_seed) in [
        (
            Tool::CreatePayment,
            "x402-credential-cp",
            0x85,
            "x402-credential-cp-bare",
            0x86,
        ),
        (
            Tool::AuthenticatedPayment,
            "x402-credential-ap",
            0x87,
            "x402-credential-ap-bare",
            0x88,
        ),
    ] {
        let keyed = fixture_with_profile(
            name,
            [seed; 32],
            |_| {},
            |profile| {
                crate::common::bind_rpc_credential(profile, ProviderRole::Primary, true);
            },
        )
        .await;
        crate::common::require_rpc_credential(&keyed.mock).await;
        let result = call(&keyed, tool).await;
        let envelope = result_json(&result);
        assert_ne!(result.is_error, Some(true), "{tool:?}: {envelope}");
        let trace = crate::common::credential_trace(&keyed.mock).await;
        assert_eq!(
            trace.first().map(|(method, _)| method.as_str()),
            Some("getNetwork"),
            "{tool:?}: {trace:?}"
        );
        assert!(trace.iter().all(|(_, keyed)| *keyed), "{tool:?}: {trace:?}");

        let bare = fixture(bare_name, [bare_seed; 32], |_| {}).await;
        crate::common::require_rpc_credential(&bare.mock).await;
        let result = call(&bare, tool).await;
        let (code, _message, text) = crate::common::assert_business_envelope(&result);
        assert_eq!(code, "network.rpc_credential_refused", "{tool:?}: {text}");
        assert_eq!(
            crate::common::credential_trace(&bare.mock).await,
            [("getNetwork".to_owned(), false)],
            "{tool:?}"
        );
    }
}
