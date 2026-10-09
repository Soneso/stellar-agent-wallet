//! The x402 payment tools write `x402_payment_authorized` before the signed
//! authorization leaves the wallet.
//!
//! `create_payment` sends the signed authorization to the profile's RPC in the
//! re-simulation request. The mock RPC here inspects every simulate request: the
//! unsigned first simulate carries no authorization entry, and the signed
//! re-simulation carries the payer's signed entry. Its handler for the signed
//! request counts the `x402_payment_authorized` rows already in the log, so a
//! row written after the send, or not at all, fails the test.

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
}

/// What the mock observed, shared with the test.
#[derive(Default)]
struct Observed {
    /// `x402_payment_authorized` rows in the log when each signed
    /// re-simulation arrived.
    authorized_rows_at_resimulation: Vec<usize>,
    /// Per request, whether it carried an authorization entry.
    signed: Vec<bool>,
    /// Per signed request, the expiration ledger, the address, and the
    /// invocation of the signed authorization entry it carried.
    transmitted: Vec<(u32, ScAddress, InvokeContractArgs)>,
}

/// Simulate endpoint for the x402 Exact flow.
#[derive(Clone)]
struct X402Rpc {
    payer: ScAddress,
    log_path: PathBuf,
    first: FirstSimulate,
    resimulation: Resimulation,
    /// Bytes the unsigned simulate writes over the log, once: a rollback that
    /// lands after the audit pre-flight and before the transmit gate.
    roll_back_to: Arc<Mutex<Option<Vec<u8>>>>,
    observed: Arc<Mutex<Observed>>,
}

impl X402Rpc {
    fn new(payer: &str, log_path: PathBuf) -> Self {
        Self {
            payer: payer_sc_address(payer),
            log_path,
            first: FirstSimulate::Ok,
            resimulation: Resimulation::Ok,
            roll_back_to: Arc::new(Mutex::new(None)),
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

impl Respond for X402Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body)
            .unwrap_or_else(|_| serde_json::json!({}));
        let req_id = body
            .get("id")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(1));
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
        let signed = !host.auth.is_empty();
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
            if self.first == FirstSimulate::Error {
                return simulate_result(
                    req_id,
                    serde_json::json!({"error": "host invocation failed", "latestLedger": 1000}),
                );
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
            return simulate_result(
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
    let _ = stellar_agent_x402::exact::create_payment(
        &requirements,
        &signer,
        &fixture.mock.uri(),
        &fixture.profile.network_passphrase,
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
