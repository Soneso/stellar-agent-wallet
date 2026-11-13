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
    /// Testnet protocols in request order, retaining the final value.
    Protocols(Vec<u32>),
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
    signed_entries_sha256: Vec<[u8; 32]>,
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
    simulation_ledger: u32,
    health_ledger: u32,
    resimulation: Resimulation,
    network: NetworkAnswer,
    /// Bytes the unsigned simulate writes over the log, once: a rollback that
    /// lands after the audit pre-flight and before the transmit gate.
    roll_back_to: Arc<Mutex<Option<Vec<u8>>>>,
    /// The keyring entry the unsigned simulate deletes: the signer loaded
    /// before it then fails at the sign call.
    forget_on_first: Option<(String, String)>,
    /// A row the unsigned simulate queues in the audit outbox, once: a consent
    /// row that arrives after the audit pre-flight and before the transmit
    /// gate, so the gate's own acquisition drains it.
    queue_on_first: Arc<Mutex<Option<stellar_agent_core::audit_log::AuditEntry>>>,
    outbox_store: Arc<Mutex<Option<Arc<dyn stellar_agent_core::audit_log::TipAnchorStore>>>>,
    observed: Arc<Mutex<Observed>>,
}

impl X402Rpc {
    fn new(payer: &str, log_path: PathBuf) -> Self {
        Self {
            payer: payer_sc_address(payer),
            log_path,
            first: FirstSimulate::Ok,
            simulation_ledger: LEDGER,
            health_ledger: LEDGER,
            resimulation: Resimulation::Ok,
            network: NetworkAnswer::Passphrase(TESTNET_PASSPHRASE),
            roll_back_to: Arc::new(Mutex::new(None)),
            forget_on_first: None,
            queue_on_first: Arc::new(Mutex::new(None)),
            outbox_store: Arc::new(Mutex::new(None)),
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

/// The primary's simulation and health ledger.
const LEDGER: u32 = 1000;

/// The oracle's simulation ledger, within the witness bounds.
const ORACLE_LEDGER: u32 = LEDGER + 1;

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
            NetworkAnswer::Protocols(protocols) => {
                let count = self
                    .observed
                    .lock()
                    .unwrap()
                    .methods
                    .iter()
                    .filter(|method| *method == "getNetwork")
                    .count();
                let protocol = protocols[count.saturating_sub(1).min(protocols.len() - 1)];
                simulate_result(
                    req_id.clone(),
                    serde_json::json!({"passphrase": TESTNET_PASSPHRASE, "protocolVersion": protocol}),
                )
            }
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
                        "latestLedger": self.health_ledger,
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
        if signed {
            use sha2::{Digest, Sha256};
            self.observed
                .lock()
                .unwrap()
                .signed_entries_sha256
                .push(Sha256::digest(host.auth.to_xdr(Limits::none()).unwrap()).into());
        }
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
            if let Some(row) = self.queue_on_first.lock().unwrap().take() {
                stellar_agent_core::audit_log::AuditOutbox::for_log(
                    &self.log_path,
                    self.outbox_store
                        .lock()
                        .unwrap()
                        .clone()
                        .expect("queued row store"),
                )
                .append(&row)
                .expect("queue the consent row");
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
                    "latestLedger": self.simulation_ledger,
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
                    "latestLedger": self.health_ledger,
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
    build_fixture(profile_name, seed, configure, configure_profile, |_| {
        keyring_mock::install().expect("mock keyring");
    })
    .await
}

/// [`fixture_with_profile`] with the keyring store `install_keyring` installs
/// for the payer's address.
async fn build_fixture(
    profile_name: &str,
    seed: [u8; 32],
    configure: impl FnOnce(&mut X402Rpc),
    configure_profile: impl FnOnce(&mut Profile),
    install_keyring: impl FnOnce(&str),
) -> Fixture {
    let home = tempfile::tempdir().expect("temp home");
    let home_guard = StellarAgentHomeGuard::new(home.path());
    let payer = gstrkey_for_seed(seed);
    install_keyring(&payer);
    keyring_core::Entry::new(SIGNER_SERVICE, &payer)
        .expect("Entry::new")
        .set_password(&sstrkey_for_seed(seed))
        .expect("set_password");
    crate::common::store_named_signer_identity(profile_name, SIGNER_SERVICE, &payer, seed);
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
                approval_nonce: None,
                approval_attestation: None,
                chain_id: "stellar:testnet".into(),
                address: None,
                payment_required: payment_required(),
                business_id: None,
            })
            .await
            .expect("no protocol error"),
        Tool::AuthenticatedPayment => fixture
            .server
            .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
                chain_id: "stellar:testnet".into(),
                address: None,
                approval_nonce: None,
                approval_attestation: None,
                home_domain: "merchant.example".into(),
                payment_required: payment_required(),
                business_id: None,
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

type PayerBarrier = Arc<(Mutex<usize>, std::sync::Condvar)>;

struct ApprovedFixture {
    fixture: Fixture,
    nonce: String,
    attestation: String,
    store_path: PathBuf,
    signer_reads: Arc<std::sync::atomic::AtomicUsize>,
    signer_barrier: Arc<Mutex<Option<PayerBarrier>>>,
    requirements: String,
}

async fn approval_fixture(tool: Tool, configure: impl FnOnce(&mut X402Rpc)) -> ApprovedFixture {
    approval_fixture_with_terms(tool, payment_required(), configure).await
}

async fn approval_fixture_with_terms(
    tool: Tool,
    requirements: String,
    configure: impl FnOnce(&mut X402Rpc),
) -> ApprovedFixture {
    let name = format!("approval-{}", uuid::Uuid::new_v4().simple());
    let signer_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reads = signer_reads.clone();
    let signer_barrier = Arc::new(Mutex::new(None::<PayerBarrier>));
    let rendezvous = signer_barrier.clone();
    let mut fixture = build_fixture(
        &name,
        [0x91; 32],
        configure,
        |_| {},
        move |payer| {
            keyring_mock::install_with_read_hooks(vec![keyring_mock::ReadHook::new(
                SIGNER_SERVICE,
                payer,
                Arc::new(move || {
                    let index = reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let barrier = rendezvous.lock().unwrap().clone();
                    if let Some(barrier) = barrier
                        && index < 2
                    {
                        let mut arrived = barrier.0.lock().unwrap();
                        *arrived += 1;
                        barrier.1.notify_all();
                        let (arrived, timeout) = barrier
                            .1
                            .wait_timeout_while(
                                arrived,
                                std::time::Duration::from_secs(60),
                                |arrived| *arrived < 2,
                            )
                            .unwrap();
                        assert!(
                            !timeout.timed_out() && *arrived == 2,
                            "both proofs verify before either payer read completes"
                        );
                    }
                }),
            )])
            .unwrap();
        },
    )
    .await;
    let directory = fixture._home.path().join("approvals");
    fixture.server.set_approval_dir_for_test(directory.clone());
    fixture.server.set_policy_engine_for_test(Arc::new(
        crate::common::policy_mock::MockPolicyEngine::require_approval(),
    ));
    let queued = proof_call(
        &fixture,
        tool,
        (None, None),
        requirements.clone(),
        None,
        "merchant.example",
    )
    .await;
    let value = result_json(&queued);
    assert_ne!(queued.is_error, Some(true), "{value}");
    assert!(fixture.rpc.observed.lock().unwrap().transmitted.is_empty());
    assert!(x402_rows(&fixture.profile).0.is_empty());
    let nonce = value["data"]["approval"]["approval_nonce"]
        .as_str()
        .unwrap()
        .to_owned();
    let store_path = directory.join(format!("{name}.toml"));
    let attestation = attest_pending(&fixture, &store_path, &nonce);
    ApprovedFixture {
        fixture,
        nonce,
        attestation,
        store_path,
        signer_reads,
        signer_barrier,
        requirements,
    }
}

fn attest_pending(fixture: &Fixture, store_path: &std::path::Path, nonce: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use stellar_agent_core::approval::{
        AttestationBinding, AttestedApprover, ConsentAuthorization, PendingApprovalStore,
        attest::{ConsentAudit, Surface, attest_and_persist},
    };
    let name = stellar_agent_core::profile::name::profile_name_for_approval(&fixture.profile);
    let key = [0x5a; 32];
    keyring_core::Entry::new(
        &fixture.profile.attestation_key_id.service,
        &fixture.profile.attestation_key_id.account,
    )
    .unwrap()
    .set_password(&URL_SAFE_NO_PAD.encode(key))
    .unwrap();
    let mut store = PendingApprovalStore::open(store_path.to_path_buf()).unwrap();
    let entry = store.get(nonce).unwrap().clone();
    let outbox = stellar_agent_core::audit_log::AuditOutbox::for_log(
        &fixture.profile.audit_log_path,
        stellar_agent_network::keyring::KeyringTipAnchorStore::shared(
            &fixture.profile.audit_log_hash_chain_key_id,
            &fixture.profile.audit_log_path,
        ),
    );
    let access = stellar_agent_network::keyring::keyed_audit_access(
        &fixture.profile,
        &name,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    )
    .unwrap();
    let _writer = stellar_agent_core::audit_log::AuditWriterRegistry::get_or_open_keyed(
        &name,
        &fixture.profile.audit_log_path,
        access,
    )
    .unwrap();
    attest_and_persist(
        &mut store,
        &entry,
        &key,
        &AttestationBinding::new(&name, "stellar:testnet"),
        Surface::Cli,
        ConsentAudit::Outbox(&outbox),
        ConsentAuthorization::Standard(&AttestedApprover::Local),
        |_, _| Err("no grant".to_owned()),
    )
    .unwrap();
    let attestation = store
        .get(nonce)
        .unwrap()
        .attestation_blob_b64
        .clone()
        .unwrap();
    drop(store);
    attestation
}

async fn proof_call(
    fixture: &Fixture,
    tool: Tool,
    proof: (Option<&str>, Option<&str>),
    requirements: String,
    address: Option<String>,
    domain: &str,
) -> rmcp::model::CallToolResult {
    proof_call_server(&fixture.server, tool, proof, requirements, address, domain).await
}

async fn proof_call_server(
    server: &WalletServer,
    tool: Tool,
    proof: (Option<&str>, Option<&str>),
    requirements: String,
    address: Option<String>,
    domain: &str,
) -> rmcp::model::CallToolResult {
    match tool {
        Tool::CreatePayment => server
            .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                approval_nonce: proof.0.map(str::to_owned),
                approval_attestation: proof.1.map(str::to_owned),
                chain_id: "stellar:testnet".to_owned(),
                payment_required: requirements,
                address,
                business_id: None,
            })
            .await
            .unwrap(),
        Tool::AuthenticatedPayment => server
            .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
                approval_nonce: proof.0.map(str::to_owned),
                approval_attestation: proof.1.map(str::to_owned),
                chain_id: "stellar:testnet".to_owned(),
                payment_required: requirements,
                address,
                business_id: None,
                home_domain: domain.to_owned(),
            })
            .await
            .unwrap(),
    }
}

impl ApprovedFixture {
    fn pair(&self) -> (Option<&str>, Option<&str>) {
        (Some(&self.nonce), Some(&self.attestation))
    }

    fn entry(&self) -> stellar_agent_core::approval::PendingApproval {
        stellar_agent_core::approval::PendingApprovalStore::open(self.store_path.clone())
            .unwrap()
            .get(&self.nonce)
            .unwrap()
            .clone()
    }

    async fn pay(&self, tool: Tool) -> rmcp::model::CallToolResult {
        proof_call(
            &self.fixture,
            tool,
            self.pair(),
            self.requirements.clone(),
            None,
            "merchant.example",
        )
        .await
    }
}

fn assert_same_refusal(left: &serde_json::Value, right: &serde_json::Value) {
    let mut left = left.clone();
    let mut right = right.clone();
    for value in [&mut left, &mut right] {
        let id = value["request_id"].as_str().unwrap();
        assert_eq!(uuid::Uuid::parse_str(id).unwrap().get_version_num(), 4);
        value["request_id"] = serde_json::Value::Null;
    }
    assert_eq!(left, right);
}

fn assert_approval_refusal(result: &rmcp::model::CallToolResult) {
    let value = result_json(result);
    assert_eq!(
        value["error"]["code"], "policy.approval_required",
        "{value}"
    );
    assert!(value["data"].get("paymentSignature").is_none());
}

#[tokio::test]
#[serial]
async fn approved_payment_pays_and_records_the_approval() {
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        for payee in [
            PAY_TO.to_owned(),
            stellar_strkey::Contract([3; 32]).to_string().to_string(),
            stellar_strkey::ed25519::MuxedAccount {
                ed25519: [0x41; 32],
                id: 19,
            }
            .to_string()
            .to_string(),
            stellar_strkey::MuxedContract {
                contract_id: [3; 32],
                id: 19,
            }
            .to_string()
            .to_string(),
        ] {
            let terms = payment_required_with(|r| r["payTo"] = payee.into());
            let approved = approval_fixture_with_terms(tool, terms, |rpc| {
                rpc.network = NetworkAnswer::Protocols(vec![30])
            })
            .await;
            let entry = approved.entry();
            let result = approved.pay(tool).await;
            let value = result_json(&result);
            assert_ne!(result.is_error, Some(true), "{value}");
            assert!(value["data"]["paymentSignature"].is_string(), "{value}");
            let observed = approved.fixture.rpc.observed.lock().unwrap();
            assert_eq!(observed.transmitted.len(), 1);
            assert_eq!(observed.authorized_rows_at_resimulation, vec![1]);
            let stellar_agent_core::approval::ApprovalKind::X402Payment {
                root_invocation_xdr,
                ..
            } = entry.kind
            else {
                panic!("x402 intent");
            };
            let root =
                SorobanAuthorizedInvocation::from_xdr_base64(root_invocation_xdr, Limits::none())
                    .unwrap();
            assert_eq!(
                root.function,
                SorobanAuthorizedFunction::ContractFn(observed.transmitted[0].2.clone())
            );
            assert_eq!(
                x402_rows(&approved.fixture.profile).0[0]["policy_decision"],
                "require_approval"
            );
        }
    }
}

#[tokio::test]
#[serial]
async fn spent_approval_pays_nothing_again() {
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        for resimulation in [Resimulation::Ok, Resimulation::RpcError] {
            let approved = approval_fixture(tool, |rpc| rpc.resimulation = resimulation).await;
            let result = approved.pay(tool).await;
            assert_eq!(
                result.is_error == Some(true),
                resimulation != Resimulation::Ok,
                "{}",
                result_json(&result)
            );
            let stellar_agent_core::approval::ApprovalKind::Consumed { tx_hash, .. } =
                approved.entry().kind
            else {
                panic!("signed transmission must spend the approval");
            };
            assert_eq!(
                tx_hash,
                stellar_agent_core::hex::encode(
                    &approved
                        .fixture
                        .rpc
                        .observed
                        .lock()
                        .unwrap()
                        .signed_entries_sha256[0],
                )
            );
            let retry = approved.pay(tool).await;
            assert_eq!(
                result_json(&retry)["error"]["code"],
                "policy.approval_consumed"
            );
            assert_eq!(
                approved
                    .fixture
                    .rpc
                    .observed
                    .lock()
                    .unwrap()
                    .transmitted
                    .len(),
                1
            );
        }
    }
}

#[tokio::test]
#[serial]
async fn approved_payment_audit_row_records_require_approval() {
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        let approved = approval_fixture(tool, |_| {}).await;
        let result = approved.pay(tool).await;
        assert_ne!(result.is_error, Some(true), "{}", result_json(&result));
        assert_eq!(
            x402_rows(&approved.fixture.profile).0[0]["policy_decision"],
            "require_approval"
        );
    }
}

#[tokio::test]
#[serial]
async fn unverified_proof_signs_nothing() {
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        let mut approved =
            approval_fixture(tool, |rpc| rpc.network = NetworkAnswer::Protocols(vec![30])).await;
        let original = format!("{:?}", approved.entry());
        for (field, changed) in [
            ("amount", "20000000".to_owned()),
            ("payTo", gstrkey_for_seed([0x92; 32])),
            (
                "payTo",
                stellar_strkey::Contract([4; 32]).to_string().to_string(),
            ),
            (
                "asset",
                stellar_strkey::Contract([0x93; 32]).to_string().to_string(),
            ),
            (
                "payTo",
                stellar_strkey::ed25519::MuxedAccount {
                    ed25519: [0; 32],
                    id: 42,
                }
                .to_string()
                .to_string(),
            ),
        ] {
            let mut requirements: serde_json::Value =
                serde_json::from_str(&payment_required()).unwrap();
            requirements[field] = changed.into();
            assert_approval_refusal(
                &proof_call(
                    &approved.fixture,
                    tool,
                    approved.pair(),
                    requirements.to_string(),
                    None,
                    "merchant.example",
                )
                .await,
            );
        }
        let queued = call(&approved.fixture, tool).await;
        let queued = result_json(&queued);
        let other_nonce = queued["data"]["approval"]["approval_nonce"]
            .as_str()
            .unwrap();
        let other_attestation =
            attest_pending(&approved.fixture, &approved.store_path, other_nonce);
        for pair in [
            (
                Some(approved.nonce.as_str()),
                Some(other_attestation.as_str()),
            ),
            (Some(approved.nonce.as_str()), Some("forged")),
            (Some("absent"), Some(approved.attestation.as_str())),
            (Some(approved.nonce.as_str()), None),
            (None, Some(approved.attestation.as_str())),
        ] {
            assert_approval_refusal(
                &proof_call(
                    &approved.fixture,
                    tool,
                    pair,
                    payment_required(),
                    None,
                    "merchant.example",
                )
                .await,
            );
        }
        if matches!(tool, Tool::AuthenticatedPayment) {
            assert_approval_refusal(
                &proof_call(
                    &approved.fixture,
                    tool,
                    approved.pair(),
                    payment_required(),
                    None,
                    "another.example",
                )
                .await,
            );
        }
        let original_profile = approved.fixture.profile.clone();
        let mut changed = original_profile.clone();
        changed.mcp_signer_default.account = gstrkey_for_seed([0x92; 32]);
        let mut changed_server = WalletServer::new(changed).unwrap();
        changed_server.set_approval_dir_for_test(approved.store_path.parent().unwrap().to_owned());
        changed_server.set_policy_engine_for_test(Arc::new(
            crate::common::policy_mock::MockPolicyEngine::require_approval(),
        ));
        let original_server = std::mem::replace(&mut approved.fixture.server, changed_server);
        assert_approval_refusal(&approved.pay(tool).await);
        approved.fixture.server = original_server;
        assert!(
            approved
                .fixture
                .rpc
                .observed
                .lock()
                .unwrap()
                .methods
                .is_empty()
        );
        assert!(x402_rows(&approved.fixture.profile).0.is_empty());
        assert_eq!(format!("{:?}", approved.entry()), original);
        assert_eq!(
            approved
                .signer_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "refused proof reads no payer key"
        );
        let w = stellar_strkey::MuxedContract {
            contract_id: [5; 32],
            id: 42,
        }
        .to_string()
        .to_string();
        let result = proof_call(
            &approved.fixture,
            tool,
            approved.pair(),
            payment_required_with(|r| r["payTo"] = w.into()),
            None,
            "merchant.example",
        )
        .await;
        assert_approval_refusal(&result);
        assert_eq!(
            approved.fixture.rpc.observed.lock().unwrap().methods,
            vec!["getNetwork"]
        );
        assert_eq!(
            approved
                .signer_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        let result = approved.pay(tool).await;
        assert_ne!(result.is_error, Some(true), "{}", result_json(&result));
    }
}

#[tokio::test]
#[serial]
async fn failure_before_the_transmit_gate_keeps_the_approval() {
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        for fault in 0..3 {
            let approved = approval_fixture(tool, |rpc| match fault {
                0 => rpc.first = FirstSimulate::Error,
                1 => rpc.network = NetworkAnswer::Passphrase(FUTURENET_PASSPHRASE),
                _ => {}
            })
            .await;
            let coordinate = &approved.fixture.profile.mcp_signer_default;
            if fault == 2 {
                keyring_core::Entry::new(&coordinate.service, &coordinate.account)
                    .unwrap()
                    .set_password(&sstrkey_for_seed([0x92; 32]))
                    .unwrap();
            }
            let result = approved.pay(tool).await;
            assert_eq!(result.is_error, Some(true));
            assert!(matches!(
                approved.entry().kind,
                stellar_agent_core::approval::ApprovalKind::X402Payment { .. }
            ));
            assert!(
                approved
                    .fixture
                    .rpc
                    .observed
                    .lock()
                    .unwrap()
                    .transmitted
                    .is_empty()
            );
            approved.fixture.mock.reset().await;
            let mut rpc = approved.fixture.rpc.clone();
            rpc.first = FirstSimulate::Ok;
            rpc.network = NetworkAnswer::Protocols(vec![30]);
            keyring_core::Entry::new(&coordinate.service, &coordinate.account)
                .unwrap()
                .set_password(&sstrkey_for_seed([0x91; 32]))
                .unwrap();
            Mock::given(method("POST"))
                .respond_with(rpc)
                .mount(&approved.fixture.mock)
                .await;
            let result = approved.pay(tool).await;
            assert_ne!(result.is_error, Some(true), "{}", result_json(&result));
        }
    }
}

#[tokio::test]
#[serial]
async fn approved_cross_check_failure_keeps_the_approval() {
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        let mut approved = approval_fixture(tool, |_| {}).await;
        let oracle = MockServer::start().await;
        let mut rpc = approved.fixture.rpc.clone();
        rpc.first = FirstSimulate::OtherAmount;
        Mock::given(method("POST"))
            .respond_with(rpc)
            .mount(&oracle)
            .await;
        let mut profile = approved.fixture.profile.clone();
        profile.oracle_provider_url = Some(oracle.uri().parse().unwrap());
        profile.cross_check_thresholds =
            stellar_agent_core::cross_check::CrossCheckThresholds::new(
                [(
                    stellar_agent_core::asset_id::CanonicalAsset::contract(ASSET).unwrap(),
                    PAYMENT_AMOUNT,
                )]
                .into_iter()
                .collect(),
            )
            .unwrap();
        let mut server = WalletServer::new(profile).unwrap();
        server.set_approval_dir_for_test(approved.store_path.parent().unwrap().to_owned());
        server.set_policy_engine_for_test(Arc::new(
            crate::common::policy_mock::MockPolicyEngine::require_approval(),
        ));
        server.set_x402_identity_session_for_test("jwt".into(), gstrkey_for_seed([1; 32]), vec![]);
        approved.fixture.server = server;
        let result = approved.pay(tool).await;
        assert_eq!(
            result_json(&result)["error"]["code"],
            "simulation.divergence",
            "{}",
            result_json(&result)
        );
        assert!(matches!(
            approved.entry().kind,
            stellar_agent_core::approval::ApprovalKind::X402Payment { .. }
        ));
        assert!(
            approved
                .fixture
                .rpc
                .observed
                .lock()
                .unwrap()
                .transmitted
                .is_empty()
        );
        assert!(x402_rows(&approved.fixture.profile).0.is_empty());
    }
}

#[tokio::test]
#[serial]
async fn x402_audit_failure_after_spend_prevents_retry_release() {
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        let approved = approval_fixture(tool, |_| {}).await;
        *approved.fixture.rpc.roll_back_to.lock().unwrap() = Some(Vec::new());
        let result = approved.pay(tool).await;
        assert_eq!(result.is_error, Some(true));
        assert!(matches!(
            approved.entry().kind,
            stellar_agent_core::approval::ApprovalKind::Consumed { .. }
        ));
        assert!(
            approved
                .fixture
                .rpc
                .observed
                .lock()
                .unwrap()
                .transmitted
                .is_empty()
        );
        let result = approved.pay(tool).await;
        assert_eq!(
            result_json(&result)["error"]["code"],
            "policy.approval_consumed"
        );
        assert!(
            approved
                .fixture
                .rpc
                .observed
                .lock()
                .unwrap()
                .transmitted
                .is_empty()
        );
    }
}

#[tokio::test]
#[serial]
async fn proof_with_a_foreign_network_answers_approval_required() {
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        let mut approved = approval_fixture(tool, |_| {}).await;
        for allow in [false, true] {
            if allow {
                approved.fixture.server.set_policy_engine_for_test(Arc::new(
                    crate::common::policy_mock::MockPolicyEngine::allow(),
                ));
            }
            for (field, value) in [
                ("network", "stellar:pubnet"),
                ("asset", "invalid"),
                ("amount", "0"),
                ("amount", "9999999999999999999999999999999999999999"),
                ("payTo", "invalid"),
            ] {
                let mut requirements: serde_json::Value =
                    serde_json::from_str(&payment_required()).unwrap();
                requirements[field] = value.into();
                if field == "network" {
                    requirements["scheme"] = "invalid".into();
                    requirements["extra"]["areFeesSponsored"] = false.into();
                    requirements["maxTimeoutSeconds"] = 0.into();
                }
                let stored = proof_call(
                    &approved.fixture,
                    tool,
                    approved.pair(),
                    requirements.to_string(),
                    None,
                    "merchant.example",
                )
                .await;
                let absent = proof_call(
                    &approved.fixture,
                    tool,
                    (Some("absent"), Some(&approved.attestation)),
                    requirements.to_string(),
                    None,
                    "merchant.example",
                )
                .await;
                assert_approval_refusal(&stored);
                assert_same_refusal(&result_json(&stored), &result_json(&absent));
            }
        }
        assert!(
            approved
                .fixture
                .rpc
                .observed
                .lock()
                .unwrap()
                .methods
                .is_empty()
        );
        assert_eq!(
            approved
                .signer_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        for (field, value, code) in [
            (
                "scheme",
                serde_json::json!("invalid"),
                "x402.unsupported_scheme",
            ),
            (
                "extra",
                serde_json::json!({"areFeesSponsored":false}),
                "x402.fees_not_sponsored",
            ),
            (
                "maxTimeoutSeconds",
                serde_json::json!(0),
                "x402.invalid_payment_required",
            ),
        ] {
            let result = proof_call(
                &approved.fixture,
                tool,
                approved.pair(),
                payment_required_with(|r| r[field] = value),
                None,
                "merchant.example",
            )
            .await;
            assert_eq!(
                result_json(&result)["error"]["code"],
                code,
                "{}",
                result_json(&result)
            );
        }
        assert!(matches!(
            approved.entry().kind,
            stellar_agent_core::approval::ApprovalKind::X402Payment { .. }
        ));
        let valid = payment_required_with(|r| {
            r["maxTimeoutSeconds"] = 17.into();
            r["extra"]["retained"] = true.into();
        });
        let result = proof_call(
            &approved.fixture,
            tool,
            (Some("arbitrary"), Some("arbitrary")),
            valid.clone(),
            None,
            "merchant.example",
        )
        .await;
        assert_ne!(result.is_error, Some(true), "{}", result_json(&result));
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::STANDARD
            .decode(
                result_json(&result)["data"]["paymentSignature"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            payload["accepted"],
            serde_json::from_str::<serde_json::Value>(&valid).unwrap()
        );
        assert!(matches!(
            approved.entry().kind,
            stellar_agent_core::approval::ApprovalKind::X402Payment { .. }
        ));
    }
}

#[tokio::test]
#[serial]
async fn proof_with_a_foreign_payer_address_answers_approval_required() {
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        let approved = approval_fixture(tool, |_| {}).await;
        let mut envelopes = Vec::new();
        for nonce in [&approved.nonce, &"absent".to_owned()] {
            let result = proof_call(
                &approved.fixture,
                tool,
                (Some(nonce), Some(&approved.attestation)),
                payment_required(),
                Some(gstrkey_for_seed([0x94; 32])),
                "merchant.example",
            )
            .await;
            assert_approval_refusal(&result);
            envelopes.push(result_json(&result));
        }
        assert_same_refusal(&envelopes[0], &envelopes[1]);
        assert!(
            approved
                .fixture
                .rpc
                .observed
                .lock()
                .unwrap()
                .methods
                .is_empty()
        );
        assert!(matches!(
            approved.entry().kind,
            stellar_agent_core::approval::ApprovalKind::X402Payment { .. }
        ));
    }
}

#[tokio::test]
#[serial]
async fn proof_with_an_invalid_home_domain_answers_approval_required() {
    let approved = approval_fixture(Tool::AuthenticatedPayment, |_| {}).await;
    let mut envelopes = Vec::new();
    for nonce in [&approved.nonce, &"absent".to_owned()] {
        let result = proof_call(
            &approved.fixture,
            Tool::AuthenticatedPayment,
            (Some(nonce), Some(&approved.attestation)),
            payment_required(),
            None,
            "INVALID.example",
        )
        .await;
        assert_approval_refusal(&result);
        envelopes.push(result_json(&result));
    }
    assert_same_refusal(&envelopes[0], &envelopes[1]);
    assert!(
        approved
            .fixture
            .rpc
            .observed
            .lock()
            .unwrap()
            .methods
            .is_empty()
    );
    assert!(matches!(
        approved.entry().kind,
        stellar_agent_core::approval::ApprovalKind::X402Payment { .. }
    ));
}

#[tokio::test]
#[serial]
async fn proof_with_unsupported_w_payee_answers_approval_required() {
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        let approved =
            approval_fixture(tool, |rpc| rpc.network = NetworkAnswer::Protocols(vec![29])).await;
        let mut requirements: serde_json::Value =
            serde_json::from_str(&payment_required()).unwrap();
        requirements["payTo"] = stellar_strkey::MuxedContract {
            contract_id: [0x55; 32],
            id: 42,
        }
        .to_string()
        .to_string()
        .into();
        let result = proof_call(
            &approved.fixture,
            tool,
            approved.pair(),
            requirements.to_string(),
            None,
            "merchant.example",
        )
        .await;
        assert_approval_refusal(&result);
        for pair in [
            (None, None),
            (Some(approved.nonce.as_str()), None),
            (None, Some(approved.attestation.as_str())),
        ] {
            let result = proof_call(
                &approved.fixture,
                tool,
                pair,
                requirements.to_string(),
                None,
                "merchant.example",
            )
            .await;
            assert_eq!(
                result_json(&result)["error"]["code"],
                "x402.muxed_contract_protocol_unsupported"
            );
        }
        assert!(
            approved
                .fixture
                .rpc
                .observed
                .lock()
                .unwrap()
                .transmitted
                .is_empty()
        );
        assert!(x402_rows(&approved.fixture.profile).0.is_empty());
        assert!(matches!(
            approved.entry().kind,
            stellar_agent_core::approval::ApprovalKind::X402Payment { .. }
        ));
    }
}

#[tokio::test]
#[serial]
async fn x402_wait_uses_the_paying_calls_ledger() {
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        let approved = approval_fixture(tool, |_| {}).await;
        let mut requirements: serde_json::Value =
            serde_json::from_str(&payment_required()).unwrap();
        requirements["maxTimeoutSeconds"] = 0.into();
        let result = proof_call(
            &approved.fixture,
            tool,
            approved.pair(),
            requirements.to_string(),
            None,
            "merchant.example",
        )
        .await;
        assert_eq!(result.is_error, Some(true));
        requirements["maxTimeoutSeconds"] = 45.into();
        requirements["extra"]["areFeesSponsored"] = false.into();
        assert_eq!(
            proof_call(
                &approved.fixture,
                tool,
                approved.pair(),
                requirements.to_string(),
                None,
                "merchant.example"
            )
            .await
            .is_error,
            Some(true)
        );
        assert!(matches!(
            approved.entry().kind,
            stellar_agent_core::approval::ApprovalKind::X402Payment { .. }
        ));
        approved.fixture.mock.reset().await;
        let mut rpc = approved.fixture.rpc.clone();
        rpc.simulation_ledger = 2000;
        rpc.health_ledger = 2000;
        Mock::given(method("POST"))
            .respond_with(rpc)
            .mount(&approved.fixture.mock)
            .await;
        requirements["extra"]["areFeesSponsored"] = true.into();
        let result = proof_call(
            &approved.fixture,
            tool,
            approved.pair(),
            requirements.to_string(),
            None,
            "merchant.example",
        )
        .await;
        assert_ne!(result.is_error, Some(true), "{}", result_json(&result));
        assert_eq!(
            approved.fixture.rpc.observed.lock().unwrap().transmitted[0].0,
            2009
        );
    }
}

#[tokio::test]
#[serial]
async fn proof_absent_wrong_terms_keep_their_errors() {
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        for allow in [false, true] {
            let mut approved = approval_fixture(tool, |_| {}).await;
            if allow {
                approved.fixture.server.set_policy_engine_for_test(Arc::new(
                    crate::common::policy_mock::MockPolicyEngine::allow(),
                ));
            }
            let mut terms: serde_json::Value = serde_json::from_str(&payment_required()).unwrap();
            terms["network"] = "stellar:pubnet".into();
            let result = proof_call(
                &approved.fixture,
                tool,
                (None, None),
                terms.to_string(),
                None,
                "merchant.example",
            )
            .await;
            assert_eq!(
                result_json(&result)["error"]["code"],
                "x402.network_passphrase_mismatch"
            );
            let result = proof_call(
                &approved.fixture,
                tool,
                (None, None),
                payment_required(),
                Some(gstrkey_for_seed([0x95; 32])),
                "merchant.example",
            )
            .await;
            assert_eq!(
                result_json(&result)["error"]["code"],
                if allow {
                    "x402.invalid_payment_required"
                } else {
                    "policy.approval_required_unsupported"
                }
            );
            if matches!(tool, Tool::AuthenticatedPayment) {
                let mut server = WalletServer::new(approved.fixture.profile.clone()).unwrap();
                server
                    .set_approval_dir_for_test(approved.store_path.parent().unwrap().to_path_buf());
                server.set_policy_engine_for_test(if allow {
                    Arc::new(crate::common::policy_mock::MockPolicyEngine::allow())
                } else {
                    Arc::new(crate::common::policy_mock::MockPolicyEngine::require_approval())
                });
                let result = server
                    .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
                        approval_nonce: None,
                        approval_attestation: None,
                        chain_id: "stellar:testnet".into(),
                        payment_required: payment_required(),
                        address: None,
                        home_domain: "INVALID.example".into(),
                        business_id: None,
                    })
                    .await
                    .unwrap();
                assert_eq!(
                    result_json(&result)["error"]["code"],
                    "identity.home_domain_invalid"
                );
            }
            assert!(
                approved
                    .fixture
                    .rpc
                    .observed
                    .lock()
                    .unwrap()
                    .transmitted
                    .is_empty()
            );
        }
    }
}

#[test]
fn x402_approval_docs_match_the_tool_contract() {
    for schema in [
        serde_json::to_value(schemars::schema_for!(X402CreatePaymentArgs)).unwrap(),
        serde_json::to_value(schemars::schema_for!(X402AuthenticatedPaymentArgs)).unwrap(),
    ] {
        let properties = &schema["properties"];
        assert!(
            properties["approval_nonce"]["description"]
                .as_str()
                .unwrap()
                .contains("when the policy requires approval, on either network."),
            "approval nonce schema covers both networks"
        );
        assert!(
            properties["approval_attestation"]["description"]
                .as_str()
                .unwrap()
                .contains("Required alongside `approval_nonce` when the policy requires approval."),
            "approval attestation schema follows policy"
        );
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for path in [
        "docs/mcp.md",
        "docs/protocols.md",
        "docs/getting-started.md",
        "docs/agents.md",
        "docs/cli-reference/profile-and-governance.md",
        "docs/maintainers/security-internals.md",
        "skills/stellar-agent-wallet/references/mcp-tools.md",
        "skills/stellar-agent-wallet/references/protocols.md",
        "skills/stellar-agent-wallet/references/troubleshooting.md",
        "skills/stellar-agent-wallet/references/approvals-and-audit.md",
        "skills/stellar-agent-wallet/references/cli-reference.md",
    ] {
        let doc = std::fs::read_to_string(root.join(path)).unwrap();
        let text = doc.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            text.contains("Supply `approval_nonce` with `approval_attestation` when the policy requires approval, on either network."),
            "{path}: approval arguments follow policy on either network"
        );
        assert!(
            text.contains("approval_nonce") && text.contains("approval_attestation"),
            "{path}"
        );
        assert!(
            text.contains("Allow without") && text.contains("one call"),
            "{path}"
        );
        assert!(
            !text.contains("payment tools also require approval under an Allow rule"),
            "{path}"
        );
        assert!(
            !text.contains("Testnet approval escalation returns"),
            "{path}"
        );
        assert!(
            !text.contains("x402 payments use two calls with mandatory approval"),
            "{path}"
        );
    }
}

async fn approved_protocol_change(tool: Tool) {
    let mut terms: serde_json::Value = serde_json::from_str(&payment_required()).unwrap();
    terms["payTo"] = stellar_strkey::MuxedContract {
        contract_id: [0x55; 32],
        id: 42,
    }
    .to_string()
    .to_string()
    .into();
    let approved = approval_fixture_with_terms(tool, terms.to_string(), |rpc| {
        rpc.network = NetworkAnswer::Protocols(vec![30, 30, 29]);
    })
    .await;
    let result = proof_call(
        &approved.fixture,
        tool,
        approved.pair(),
        terms.to_string(),
        None,
        "merchant.example",
    )
    .await;
    assert_eq!(
        result_json(&result)["error"]["code"],
        "x402.muxed_contract_protocol_unsupported",
        "post-dispatch protocol refusal retains its x402 code"
    );
    let observed = approved.fixture.rpc.observed.lock().unwrap();
    assert!(observed.transmitted.is_empty());
    assert_eq!(observed.methods, ["getNetwork", "getNetwork", "getNetwork"]);
    assert!(x402_rows(&approved.fixture.profile).1.is_empty());
    assert!(matches!(
        approved.entry().kind,
        stellar_agent_core::approval::ApprovalKind::X402Payment { .. }
    ));
}

#[tokio::test]
#[serial]
async fn approved_create_protocol_change_keeps_x402_error() {
    approved_protocol_change(Tool::CreatePayment).await;
}

#[tokio::test]
#[serial]
async fn approved_authenticated_protocol_change_keeps_x402_error() {
    approved_protocol_change(Tool::AuthenticatedPayment).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn concurrent_approved_calls_release_one_payment() {
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        let mut approved = approval_fixture(tool, |_| {}).await;
        let replacement = WalletServer::new(approved.fixture.profile.clone()).unwrap();
        let server = Arc::new(std::mem::replace(&mut approved.fixture.server, replacement));
        approved
            .signer_reads
            .store(0, std::sync::atomic::Ordering::SeqCst);
        *approved.signer_barrier.lock().unwrap() =
            Some(Arc::new((Mutex::new(0), std::sync::Condvar::new())));
        let pay = |server: Arc<WalletServer>| {
            let nonce = approved.nonce.clone();
            let attestation = approved.attestation.clone();
            async move {
                proof_call_server(
                    &server,
                    tool,
                    (Some(&nonce), Some(&attestation)),
                    payment_required(),
                    None,
                    "merchant.example",
                )
                .await
            }
        };
        let (first, second) =
            tokio::join!(tokio::spawn(pay(server.clone())), tokio::spawn(pay(server)));
        let (first, second) = (first.unwrap(), second.unwrap());
        assert_eq!(
            [&first, &second]
                .iter()
                .filter(|result| result.is_error != Some(true))
                .count(),
            1
        );
        assert_eq!(
            approved
                .fixture
                .rpc
                .observed
                .lock()
                .unwrap()
                .transmitted
                .len(),
            1
        );
    }
}

struct RecipientRecorder {
    inner: stellar_agent_core::PolicyEngineV1,
    classes: Arc<Mutex<Vec<Option<stellar_agent_core::policy::v1::criteria::counterparty_allowlist::RecipientClass>>>>,
}

impl stellar_agent_core::PolicyEngine for RecipientRecorder {
    fn window_state_store(
        &self,
    ) -> Option<&stellar_agent_core::policy::v1::criteria::state_store::PolicyStateStore> {
        self.inner.window_state_store()
    }
    fn evaluate(
        &self,
        tool: &stellar_agent_core::policy::ToolDescriptor,
        args: &serde_json::Value,
        profile: &Profile,
        account: Option<&dyn stellar_agent_core::policy::v1::AccountReservesView>,
        identity: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView>,
        counterparty: Option<&dyn stellar_agent_core::policy::v1::CounterpartyCacheView>,
        sep10: Option<&dyn stellar_agent_core::policy::v1::Sep10SessionView>,
        sep45: Option<&dyn stellar_agent_core::policy::v1::Sep45SessionView>,
        now: u64,
    ) -> Result<stellar_agent_core::policy::Decision, stellar_agent_core::policy::PolicyError> {
        self.inner.evaluate(
            tool,
            args,
            profile,
            account,
            identity,
            counterparty,
            sep10,
            sep45,
            now,
        )
    }

    fn evaluate_with_value_full(
        &self,
        tool: &stellar_agent_core::policy::ToolDescriptor,
        args: &serde_json::Value,
        profile: &Profile,
        value: stellar_agent_core::policy::v1::ValueClass,
        account: Option<&dyn stellar_agent_core::policy::v1::AccountReservesView>,
        identity: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView>,
        counterparty: Option<&dyn stellar_agent_core::policy::v1::CounterpartyCacheView>,
        sep10: Option<&dyn stellar_agent_core::policy::v1::Sep10SessionView>,
        sep45: Option<&dyn stellar_agent_core::policy::v1::Sep45SessionView>,
        now: u64,
    ) -> Result<stellar_agent_core::policy::Evaluation, stellar_agent_core::policy::PolicyError>
    {
        self.inner.evaluate_with_value_full(
            tool,
            args,
            profile,
            value,
            account,
            identity,
            counterparty,
            sep10,
            sep45,
            now,
        )
    }

    fn record_confirmed(
        &self,
        tool: &stellar_agent_core::policy::ToolDescriptor,
        profile: &Profile,
        value: &stellar_agent_core::policy::v1::ValueClass,
    ) -> Result<
        Vec<stellar_agent_core::policy::v1::criteria::state_store::WindowEntry>,
        stellar_agent_core::policy::PolicyError,
    > {
        let stellar_agent_core::policy::v1::ValueClass::Value(effects) = value else {
            panic!("payment value");
        };
        self.classes.lock().unwrap().push(effects.recipient_class());
        self.inner.record_confirmed(tool, profile, value)
    }
}

#[tokio::test]
#[serial]
async fn approved_x402_records_governing_value_effects() {
    use stellar_agent_core::policy::v1::criteria::counterparty_allowlist::{
        CounterpartyAllowlistCriterion, CounterpartyKind, RecipientClass,
    };
    use stellar_agent_core::policy::{ApprovalRequest, Decision};
    use stellar_agent_core::{PolicyDocument, PolicyEngineV1, PolicyRule, RuleMatch, ScopeId};
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        let mut approved = approval_fixture(tool, |rpc| rpc.first = FirstSimulate::Error).await;
        let classes = Arc::new(Mutex::new(Vec::new()));
        let name =
            stellar_agent_core::profile::name::profile_name_for_approval(&approved.fixture.profile);
        let inner = PolicyEngineV1::new(
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                signature: None,
                rules: vec![PolicyRule {
                    r#match: RuleMatch {
                        tool: "*".into(),
                        chain: "*".into(),
                    },
                    criteria: vec![Box::new(CounterpartyAllowlistCriterion::new(
                        vec![CounterpartyKind::GAccount],
                        vec![PAY_TO.into()],
                    )), Box::new(stellar_agent_core::policy::v1::criteria::per_period_cap::PerPeriodCapCriterion::new(
                        ASSET.into(), stellar_agent_core::policy::v1::criteria::per_period_cap::Window::parse("1d").unwrap(), 100_000_000,
                    ))],
                    decision: Decision::RequireApproval(ApprovalRequest::new("reason".into(), 120)),
                    allow_opaque_signing: false,
                }],
            },
            name.clone(),
        );
        approved
            .fixture
            .server
            .set_policy_engine_for_test(Arc::new(RecipientRecorder {
                inner,
                classes: classes.clone(),
            }));
        let queued = call(&approved.fixture, tool).await;
        assert_ne!(queued.is_error, Some(true));
        assert!(
            classes.lock().unwrap().is_empty(),
            "queueing records no spend"
        );
        let result = approved.pay(tool).await;
        assert_eq!(result.is_error, Some(true), "{}", result_json(&result));
        assert_eq!(*classes.lock().unwrap(), vec![Some(RecipientClass::Listed)]);
        assert_eq!(
            window_state(&approved.fixture.profile, &name),
            (10_000_000, 1)
        );
        assert!(matches!(
            approved.entry().kind,
            stellar_agent_core::approval::ApprovalKind::X402Payment { .. }
        ));
        approved.fixture.mock.reset().await;
        let mut rpc = approved.fixture.rpc.clone();
        rpc.first = FirstSimulate::Ok;
        Mock::given(method("POST"))
            .respond_with(rpc)
            .mount(&approved.fixture.mock)
            .await;
        let result = approved.pay(tool).await;
        assert_ne!(result.is_error, Some(true), "{}", result_json(&result));
        assert_eq!(
            *classes.lock().unwrap(),
            vec![Some(RecipientClass::Listed); 2]
        );
        assert_eq!(
            window_state(&approved.fixture.profile, &name),
            (20_000_000, 2)
        );
    }
}

/// A signer-load failure a case puts at the payer's signer coordinate.
#[derive(Clone, Copy, Debug)]
enum SignerFault {
    /// No entry at the coordinate.
    Missing,
    /// The entry holds the seed of another account.
    OtherKey,
    /// The credential store fails the read with backend text of its own.
    StoreFailure,
}

/// Backend text the injected store failure carries; no envelope may echo it.
const BACKEND_TEXT: &str = "backend-sentinel-never-render";

/// The seed of the account whose secret the `OtherKey` fault stores.
const OTHER_SEED: [u8; 32] = [0x2f; 32];

/// A signer-load auth error reaches the tool result with its own code and
/// message, before any payment request or x402 row.
async fn signer_load_auth_error(tool: Tool, profile_name: &str, seed: u8, fault: SignerFault) {
    let fixture = fixture(profile_name, [seed; 32], |_| {}).await;
    let account = &fixture.profile.mcp_signer_default.account;
    let entry = keyring_core::Entry::new(SIGNER_SERVICE, account).expect("Entry::new");
    let (expected_code, expected_message) = match fault {
        SignerFault::Missing => {
            entry.delete_credential().expect("remove only the signer");
            (
                "auth.keyring_not_found",
                "the configured keyring entry must exist; provision or select the required \
                 entry."
                    .to_owned(),
            )
        }
        SignerFault::OtherKey => {
            entry
                .set_password(&sstrkey_for_seed(OTHER_SEED))
                .expect("store another account's seed");
            (
                "auth.signer_key_mismatch",
                format!(
                    "signing key public key '{}' does not match the expected signing account '{account}'",
                    gstrkey_for_seed(OTHER_SEED)
                ),
            )
        }
        SignerFault::StoreFailure => {
            keyring_mock::inject_error(
                SIGNER_SERVICE,
                account,
                keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other(BACKEND_TEXT))),
            )
            .expect("inject the store failure");
            (
                "auth.keyring_platform_error",
                "keyring operation failed: read unknown credential store: \
                 credential store operation failed"
                    .to_owned(),
            )
        }
    };

    let result = call(&fixture, tool).await;
    let (code, message, text) = crate::common::assert_business_envelope(&result);
    assert_eq!(code, expected_code, "{tool:?}: {text}");
    assert_eq!(message, expected_message, "{tool:?}: {text}");
    assert!(
        result_json(&result)["error"].get("details").is_none(),
        "{text}"
    );
    if !matches!(fault, SignerFault::OtherKey) {
        assert!(!text.contains(account), "{text}");
    }
    assert!(!text.contains(&sstrkey_for_seed([seed; 32])), "{text}");
    assert!(!text.contains(&sstrkey_for_seed(OTHER_SEED)), "{text}");
    assert!(!text.contains(BACKEND_TEXT), "{text}");
    assert!(!text.contains("paymentSignature"), "{text}");
    assert!(
        fixture.rpc.observed.lock().unwrap().methods.is_empty(),
        "{tool:?}: no payment request"
    );
    let (authorized, withheld) = x402_rows(&fixture.profile);
    assert!(authorized.is_empty() && withheld.is_empty(), "{tool:?}");
}

#[tokio::test]
#[serial]
async fn create_payment_preserves_missing_signer_auth_error() {
    signer_load_auth_error(
        Tool::CreatePayment,
        "x402-missing-signer-cp",
        0xfa,
        SignerFault::Missing,
    )
    .await;
}

#[tokio::test]
#[serial]
async fn authenticated_payment_preserves_missing_signer_auth_error() {
    signer_load_auth_error(
        Tool::AuthenticatedPayment,
        "x402-missing-signer-ap",
        0xfb,
        SignerFault::Missing,
    )
    .await;
}

#[tokio::test]
#[serial]
async fn create_payment_signer_key_mismatch_reports_auth_code() {
    signer_load_auth_error(
        Tool::CreatePayment,
        "x402-key-mismatch-cp",
        0xfc,
        SignerFault::OtherKey,
    )
    .await;
}

#[tokio::test]
#[serial]
async fn authenticated_payment_signer_key_mismatch_reports_auth_code() {
    signer_load_auth_error(
        Tool::AuthenticatedPayment,
        "x402-key-mismatch-ap",
        0xfd,
        SignerFault::OtherKey,
    )
    .await;
}

#[tokio::test]
#[serial]
async fn create_payment_keyring_platform_error_reports_auth_code() {
    signer_load_auth_error(
        Tool::CreatePayment,
        "x402-store-failure-cp",
        0xfe,
        SignerFault::StoreFailure,
    )
    .await;
}

#[tokio::test]
#[serial]
async fn authenticated_payment_keyring_platform_error_reports_auth_code() {
    signer_load_auth_error(
        Tool::AuthenticatedPayment,
        "x402-store-failure-ap",
        0xff,
        SignerFault::StoreFailure,
    )
    .await;
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

/// The testnet payment's ledger trace carries the protocol version its
/// endpoint identity check established.
#[tokio::test(flavor = "current_thread")]
#[serial]
async fn testnet_create_payment_traces_the_endpoint_protocol_version() {
    use stellar_agent_core::observability::{FormatChoice, SubscriberConfig, subscriber_for_tests};
    use tracing::instrument::WithSubscriber as _;
    let fixture = fixture("x402-protocol-trace", [0xb4; 32], |_| {}).await;
    let capture = stellar_agent_test_support::CaptureWriter::new();
    let writer = capture.clone();
    let subscriber = subscriber_for_tests(
        SubscriberConfig::default()
            .with_filter_override(Some(tracing_subscriber::EnvFilter::new("debug")))
            .with_format_override(Some(FormatChoice::Pretty))
            .with_writer_factory(Some(Box::new(move || Box::new(writer.clone())))),
    )
    .expect("the wallet subscriber builds");
    let inert = stellar_agent_test_support::inert_dispatcher();
    let dispatch = tracing::Dispatch::new(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let result = call(&fixture, Tool::CreatePayment)
        .with_subscriber(dispatch)
        .await;
    drop(inert);
    assert_ne!(result.is_error, Some(true), "{}", result_json(&result));
    let logs = capture.captured_str();
    let trace = logs
        .split("x402 payment ledgers checked")
        .nth(1)
        .unwrap_or_else(|| panic!("the ledger trace is written: {logs}"));
    let fields = trace.split("\n\n").next().unwrap_or(trace);
    assert!(fields.contains("protocol_version"), "{fields}");
}

/// On testnet the create-payment tool ignores the approval arguments under an
/// allowing policy: absent, either half alone, or both, the payment is signed
/// and returned as without them.
#[tokio::test]
#[serial]
async fn testnet_create_payment_ignores_supplied_approval_arguments() {
    for (seed, nonce, attestation) in [
        (0xb0, None, None),
        (0xb1, Some("approval-nonce"), None),
        (0xb2, None, Some("approval-attestation")),
        (0xb3, Some("approval-nonce"), Some("approval-attestation")),
    ] {
        let fixture = fixture(&format!("x402-approval-args-{seed:x}"), [seed; 32], |_| {}).await;
        let result = fixture
            .server
            .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                approval_nonce: nonce.map(str::to_owned),
                approval_attestation: attestation.map(str::to_owned),
                chain_id: "stellar:testnet".into(),
                address: None,
                payment_required: payment_required(),
                business_id: None,
            })
            .await
            .expect("no protocol error");
        let envelope = result_json(&result);
        assert_ne!(
            result.is_error,
            Some(true),
            "{nonce:?} {attestation:?}: {envelope}"
        );
        assert!(
            envelope["data"]["paymentSignature"].is_string(),
            "{nonce:?} {attestation:?}: {envelope}"
        );
        let (authorized, _) = x402_rows(&fixture.profile);
        assert_eq!(authorized.len(), 1, "{nonce:?} {attestation:?}");
        assert_eq!(authorized[0]["policy_decision"], "allow");
    }
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
        &stellar_agent_network::cross_check::SorobanCrossCheck::NotRequired,
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
                    approval_nonce: None,
                    approval_attestation: None,
                    chain_id: chain_id.into(),
                    address: None,
                    payment_required: payment_required.to_owned(),
                    business_id: None,
                })
                .await
        }
        Tool::AuthenticatedPayment => {
            fixture
                .server
                .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
                    chain_id: chain_id.into(),
                    address: None,
                    approval_nonce: None,
                    approval_attestation: None,
                    home_domain: "merchant.example".into(),
                    payment_required: payment_required.to_owned(),
                    business_id: None,
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
    cap_engine_with_recipient(profile_name, cap, None)
}

fn cap_engine_with_recipient(
    profile_name: &str,
    cap: i128,
    recipient: Option<&str>,
) -> stellar_agent_core::PolicyEngineV1 {
    use stellar_agent_core::policy::Decision;
    use stellar_agent_core::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
    use stellar_agent_core::policy::v1::criteria::{
        Criterion,
        counterparty_allowlist::{CounterpartyAllowlistCriterion, CounterpartyKind},
    };
    use stellar_agent_core::{PolicyDocument, PolicyEngineV1, PolicyRule, RuleMatch, ScopeId};
    let mut criteria: Vec<Box<dyn Criterion>> = vec![Box::new(PerPeriodCapCriterion::new(
        ASSET.into(),
        Window::parse("1d").expect("window"),
        cap,
    ))];
    if let Some(recipient) = recipient {
        criteria.push(Box::new(CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::GAccount, CounterpartyKind::CAccount],
            vec![recipient.to_owned()],
        )));
    }
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
                criteria,
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

#[tokio::test]
#[serial]
async fn muxed_unlisted_budget_preserves_destination_and_amount() {
    use stellar_agent_core::policy::Decision;
    use stellar_agent_core::policy::v1::criteria::{
        Criterion,
        counterparty_allowlist::{
            CounterpartyAllowlistCriterion, CounterpartyKind, UnlistedBudget, UnlistedMode,
        },
        per_period_cap::{PerPeriodCapCriterion, Window},
    };
    use stellar_agent_core::{PolicyDocument, PolicyEngineV1, PolicyRule, RuleMatch, ScopeId};
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        for contract in [false, true] {
            let expected = if contract {
                ScAddress::MuxedContract(stellar_xdr::MuxedContract {
                    id: 7,
                    contract_id: ContractId(Hash([6; 32])),
                })
            } else {
                ScAddress::MuxedAccount(stellar_xdr::MuxedEd25519Account {
                    id: 7,
                    ed25519: Uint256([6; 32]),
                })
            };
            let payee =
                stellar_agent_core::sc_address::scaddress_destination_strkey(&expected).unwrap();
            let profile_name = "muxed-budget";
            let mut fixture = fixture(profile_name, [0x47; 32], |rpc| {
                rpc.network = NetworkAnswer::Protocols(vec![30])
            })
            .await;
            let criteria: Vec<Box<dyn Criterion>> = vec![
                Box::new(PerPeriodCapCriterion::new(
                    ASSET.into(),
                    Window::parse("1d").unwrap(),
                    100_000_000,
                )),
                Box::new(
                    CounterpartyAllowlistCriterion::new(
                        vec![CounterpartyKind::GAccount, CounterpartyKind::CAccount],
                        vec![],
                    )
                    .with_unlisted(UnlistedMode::Budget(UnlistedBudget::new(
                        ASSET.into(),
                        10_000_000,
                        10_000_000,
                        Window::parse("1d").unwrap(),
                    ))),
                ),
            ];
            let engine = PolicyEngineV1::new(
                PolicyDocument {
                    version: 1,
                    scope: ScopeId::AllProfiles,
                    signature: None,
                    rules: vec![PolicyRule {
                        r#match: RuleMatch {
                            tool: "*".into(),
                            chain: "*".into(),
                        },
                        criteria,
                        decision: Decision::Allow,
                        allow_opaque_signing: false,
                    }],
                },
                profile_name.into(),
            );
            fixture.server.set_policy_engine_for_test(Arc::new(engine));
            let requirements = payment_required_with(|r| r["payTo"] = payee.as_str().into());
            let result = result_json(&call_with(&fixture, tool, &requirements).await);
            assert_eq!(result["ok"], true, "{result}");
            assert_eq!(result["data"]["payTo"], payee);
            assert_eq!(
                window_state(&fixture.profile, profile_name),
                (10_000_000, 1)
            );
            let (rows, _) = x402_rows(&fixture.profile);
            assert_eq!(
                rows[0]["legs"][0]["destination_redacted"],
                stellar_agent_core::observability::redact_strkey_first5_last5(&payee)
            );
            assert_eq!(rows[0]["legs"][0]["amount"], "10000000");
            {
                let observed = fixture.rpc.observed.lock().unwrap();
                assert_eq!(observed.transmitted.len(), 1);
                assert_eq!(observed.transmitted[0].2.args[1], ScVal::Address(expected));
                assert_eq!(
                    observed.transmitted[0].2.args[2],
                    ScVal::from(10_000_000_i128)
                );
            }
            let denied = result_json(&call_with(&fixture, tool, &requirements).await);
            assert_eq!(
                denied["error"]["code"], "policy.deny.unlisted_budget_exceeded",
                "{denied}"
            );
            assert_eq!(
                window_state(&fixture.profile, profile_name),
                (10_000_000, 1)
            );
        }
    }
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
        (PAY_TO.to_owned(), PAY_TO.to_owned()),
        (
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".to_owned(),
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".to_owned(),
        ),
        (muxed.clone(), muxed.clone()),
        (
            muxed,
            format!("{}", stellar_strkey::ed25519::PublicKey([0x2c; 32])),
        ),
        (
            stellar_strkey::MuxedContract {
                contract_id: [3; 32],
                id: 7,
            }
            .to_string()
            .as_str()
            .to_owned(),
            stellar_strkey::Contract([3; 32])
                .to_string()
                .as_str()
                .to_owned(),
        ),
        (
            stellar_strkey::MuxedContract {
                contract_id: [3; 32],
                id: 7,
            }
            .to_string()
            .as_str()
            .to_owned(),
            stellar_strkey::MuxedContract {
                contract_id: [3; 32],
                id: 7,
            }
            .to_string()
            .as_str()
            .to_owned(),
        ),
    ];
    let mut seed = 0xe3;
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        for (recipient, entry) in &recipients {
            seed += 1;
            let profile_name = format!("x402-leg-{seed:x}");
            let mut fixture = fixture(&profile_name, [seed; 32], |rpc| {
                rpc.network = NetworkAnswer::Protocols(vec![30])
            })
            .await;
            fixture
                .server
                .set_policy_engine_for_test(Arc::new(cap_engine_with_recipient(
                    &profile_name,
                    100_000_000,
                    Some(entry),
                )));
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
            assert_eq!(authorized[0]["policy_decision"], "allow");
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
                stellar_strkey::Strkey::MuxedContract(contract) => {
                    ScAddress::MuxedContract(stellar_xdr::MuxedContract {
                        id: contract.id,
                        contract_id: ContractId(Hash(contract.contract_id)),
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

#[tokio::test]
#[serial]
async fn muxed_contract_protocol_table_and_library_mapping() {
    let payee = stellar_strkey::MuxedContract {
        contract_id: [3; 32],
        id: 7,
    }
    .to_string();
    for tool in [Tool::CreatePayment, Tool::AuthenticatedPayment] {
        for protocols in [vec![28], vec![29], vec![30], vec![31], vec![30, 29]] {
            let schedule = protocols.clone();
            let fixture = fixture("muxed-protocol", [0x46; 32], |rpc| {
                rpc.network = NetworkAnswer::Protocols(schedule)
            })
            .await;
            let result = call_with(
                &fixture,
                tool,
                &payment_required_with(|r| r["payTo"] = payee.as_str().into()),
            )
            .await;
            let result = result_json(&result);
            if *protocols.last().unwrap() < 30 {
                assert_eq!(
                    result["error"]["code"], "x402.muxed_contract_protocol_unsupported",
                    "{tool:?}: {result}"
                );
                assert!(fixture.rpc.observed.lock().unwrap().signed.is_empty());
                let observed = fixture.rpc.observed.lock().unwrap();
                assert_eq!(observed.methods.len(), protocols.len());
                assert_eq!(
                    observed
                        .methods
                        .iter()
                        .filter(|method| *method == "simulateTransaction")
                        .count(),
                    0
                );
                assert_eq!(window_state(&fixture.profile, "muxed-protocol"), (0, 0));
            } else {
                assert_eq!(result["ok"], true, "{tool:?}: {result}");
                assert_eq!(result["data"]["payTo"], payee.as_str());
            }
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
            approval_nonce: None,
            approval_attestation: None,
            chain_id: "stellar:pubnet".into(),
            address: None,
            payment_required: invalid.clone(),
            business_id: None,
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
            approval_nonce: None,
            approval_attestation: None,
            home_domain: "merchant.example".into(),
            payment_required: invalid,
            business_id: None,
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

// ── Cross-check witness through both tools ───────────────────────────────────

/// The payment amount `payment_required` names, in the asset's atomic units.
const PAYMENT_AMOUNT: i128 = 10_000_000;

/// A payment whose profile names an oracle and a threshold for the payment
/// asset, with the reads of the payer's signer entry counted.
struct WitnessFixture {
    fixture: Fixture,
    oracle: MockServer,
    oracle_rpc: X402Rpc,
    signer_reads: Arc<std::sync::atomic::AtomicUsize>,
}

impl WitnessFixture {
    fn signer_reads(&self) -> usize {
        self.signer_reads.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The methods the oracle received, in order.
    async fn oracle_methods(&self) -> Vec<String> {
        crate::common::received_methods(&self.oracle).await
    }
}

/// Builds a [`WitnessFixture`]: the oracle answers as `configure_oracle` sets
/// its mock, the profile's threshold for the payment asset is `threshold`,
/// and `oracle_url` replaces the oracle's URL in the profile when set.
async fn witness_fixture(
    profile_name: &str,
    seed: u8,
    threshold: i128,
    oracle_url: Option<&str>,
    configure_oracle: impl FnOnce(&mut X402Rpc),
) -> WitnessFixture {
    let payer = gstrkey_for_seed([seed; 32]);
    let oracle = MockServer::start().await;
    let mut oracle_rpc = X402Rpc::new(&payer, PathBuf::from("oracle-writes-no-row"));
    oracle_rpc.simulation_ledger = ORACLE_LEDGER;
    configure_oracle(&mut oracle_rpc);
    Mock::given(method("POST"))
        .respond_with(oracle_rpc.clone())
        .mount(&oracle)
        .await;
    let oracle_url = oracle_url.map_or_else(|| oracle.uri(), str::to_owned);
    let signer_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = Arc::clone(&signer_reads);
    let fixture = build_fixture(
        profile_name,
        [seed; 32],
        |_| {},
        |profile| {
            profile.oracle_provider_url = Some(oracle_url.parse().expect("an oracle URL"));
            profile.cross_check_thresholds =
                stellar_agent_core::cross_check::CrossCheckThresholds::new(
                    [(
                        stellar_agent_core::asset_id::CanonicalAsset::contract(ASSET)
                            .expect("the payment asset is a contract"),
                        threshold,
                    )]
                    .into_iter()
                    .collect(),
                )
                .expect("a valid threshold table");
        },
        move |payer| {
            keyring_mock::install_with_read_hooks(vec![keyring_mock::ReadHook::new(
                SIGNER_SERVICE,
                payer,
                Arc::new(move || {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }),
            )])
            .expect("mock keyring with a read hook");
        },
    )
    .await;
    WitnessFixture {
        fixture,
        oracle,
        oracle_rpc,
        signer_reads,
    }
}

/// The x402 rows of the verified audit chain: `x402_payment_authorized` and
/// `x402_authorization_withheld`. A payment that wrote no row leaves no log.
fn verified_x402_rows(profile: &Profile) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    if !profile.audit_log_path.exists() {
        return (Vec::new(), Vec::new());
    }
    let rows: Vec<serde_json::Value> =
        stellar_agent_core::audit_log::test_helpers::verified_audit_entries_from_path(
            &profile.audit_log_path,
        )
        .iter()
        .map(|entry| serde_json::to_value(entry).expect("an audit entry serializes"))
        .collect();
    let of_kind = |kind: &str| {
        crate::common::rows_of_kind(&rows, kind)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>()
    };
    (
        of_kind("x402_payment_authorized"),
        of_kind("x402_authorization_withheld"),
    )
}

/// The `cross_check` of a passed witness on the oracle at `oracle_uri`.
fn passed_view(oracle_uri: &str) -> serde_json::Value {
    serde_json::json!({"status": "passed", "provider": oracle_uri, "ledger": ORACLE_LEDGER})
}

/// Drives `tool` through a payment below the asset's threshold and one at it:
/// below, the witness is not required, no oracle client is built, and the
/// oracle receives nothing; at the threshold, the oracle client is built
/// beside the primary and simulates once.
async fn value_wiring(tool: Tool, seeds: [u8; 2]) {
    let below = witness_fixture(
        &format!("x402-witness-below-{}", tool.name()),
        seeds[0],
        PAYMENT_AMOUNT + 1,
        None,
        |_| {},
    )
    .await;
    let (result, built) = crate::common::clients_built_by(call(&below.fixture, tool)).await;
    let envelope = result_json(&result);
    assert_ne!(result.is_error, Some(true), "{tool:?}: {envelope}");
    assert_eq!(
        envelope["data"]["cross_check"],
        serde_json::json!({"status": "not_required", "reason": "below_threshold"}),
        "{tool:?}"
    );
    assert_eq!(built, 1, "{tool:?}: no oracle client below the threshold");
    assert!(below.oracle_methods().await.is_empty(), "{tool:?}");

    let at = witness_fixture(
        &format!("x402-witness-at-{}", tool.name()),
        seeds[1],
        PAYMENT_AMOUNT,
        None,
        |_| {},
    )
    .await;
    let (result, built) = crate::common::clients_built_by(call(&at.fixture, tool)).await;
    let envelope = result_json(&result);
    assert_ne!(result.is_error, Some(true), "{tool:?}: {envelope}");
    assert_eq!(
        envelope["data"]["cross_check"],
        passed_view(&at.oracle.uri()),
        "{tool:?}"
    );
    assert_eq!(built, 2, "{tool:?}: the primary and the oracle client");
    assert_eq!(
        at.oracle_methods().await,
        ["getNetwork", "simulateTransaction"],
        "{tool:?}"
    );
}

#[tokio::test]
#[serial]
async fn x402_value_wiring_create_payment() {
    value_wiring(Tool::CreatePayment, [0x12, 0x13]).await;
}

#[tokio::test]
#[serial]
async fn x402_value_wiring_authenticated_payment() {
    value_wiring(Tool::AuthenticatedPayment, [0x14, 0x15]).await;
}

/// A passed witness reaches the tool result and the `x402_payment_authorized`
/// row, and the signed authorization reaches only the primary.
#[tokio::test]
#[serial]
async fn x402_authorized_row_carries_witness() {
    for (tool, seed) in [
        (Tool::CreatePayment, 0x16),
        (Tool::AuthenticatedPayment, 0x17),
    ] {
        let witness = witness_fixture(
            &format!("x402-witness-row-{}", tool.name()),
            seed,
            PAYMENT_AMOUNT,
            None,
            |_| {},
        )
        .await;
        let result = call(&witness.fixture, tool).await;
        let envelope = result_json(&result);
        assert_ne!(result.is_error, Some(true), "{tool:?}: {envelope}");
        assert!(envelope["data"]["paymentSignature"].is_string());
        assert_eq!(
            envelope["data"]["cross_check"],
            passed_view(&witness.oracle.uri())
        );
        let (authorized, withheld) = verified_x402_rows(&witness.fixture.profile);
        assert!(withheld.is_empty(), "{tool:?}: {withheld:?}");
        let [row] = authorized.as_slice() else {
            panic!("{tool:?}: one authorized row: {authorized:?}");
        };
        assert_eq!(row["tool"], tool.name());
        assert_eq!(row["witness"]["provider"], witness.oracle.uri());
        assert_eq!(row["witness"]["ledger"], ORACLE_LEDGER);
        assert_eq!(
            row["witness"]["kinds"],
            serde_json::json!(["soroban_simulation"])
        );
        let digest = row["witness"]["inputs_digest"].as_str().unwrap();
        assert_eq!(digest.len(), 64, "{digest}");
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(
            witness.oracle_rpc.observed.lock().unwrap().signed,
            [false],
            "{tool:?}: the oracle simulates the unsigned transfer only"
        );
        assert_eq!(
            witness.fixture.rpc.observed.lock().unwrap().signed,
            [false, true],
            "{tool:?}"
        );
    }
}

/// Asserts that a witness refusal reached the tool result as `code` and
/// `message` and nothing else, before the payer signed: one read of the
/// signer entry (its load), the primary's unsigned simulation only, and no
/// x402 row.
async fn assert_witness_refusal(
    witness: &WitnessFixture,
    tool: Tool,
    result: &rmcp::model::CallToolResult,
    code: &str,
    message: &str,
) {
    let (got_code, got_message, text) = crate::common::assert_business_envelope(result);
    assert_eq!(got_code, code, "{tool:?}: {text}");
    assert_eq!(got_message, message, "{tool:?}: {text}");
    let mut envelope = result_json(result);
    envelope
        .as_object_mut()
        .expect("an envelope object")
        .remove("request_id");
    assert_eq!(
        envelope,
        serde_json::json!({"ok": false, "error": {"code": code, "message": message}}),
        "{tool:?}"
    );
    assert_eq!(witness.signer_reads(), 1, "{tool:?}: the signer load only");
    let observed = witness.fixture.rpc.observed.lock().unwrap();
    assert_eq!(observed.signed, [false], "{tool:?}: nothing signed is sent");
    assert_eq!(
        observed.methods,
        ["getNetwork", "simulateTransaction"],
        "{tool:?}: the refusal precedes the health read"
    );
    drop(observed);
    let (authorized, withheld) = verified_x402_rows(&witness.fixture.profile);
    assert!(
        authorized.is_empty() && withheld.is_empty(),
        "{tool:?}: no x402 row: {authorized:?} {withheld:?}"
    );
}

/// An oracle whose simulation disagrees with the primary's refuses through
/// both tools with `simulation.divergence`, before signing and without a row.
#[tokio::test]
#[serial]
async fn x402_cross_check_refusal_writes_no_authorized_row() {
    for (tool, seed) in [
        (Tool::CreatePayment, 0x18),
        (Tool::AuthenticatedPayment, 0x19),
    ] {
        let witness = witness_fixture(
            &format!("x402-witness-diverges-{}", tool.name()),
            seed,
            PAYMENT_AMOUNT,
            None,
            |oracle| oracle.first = FirstSimulate::OtherAmount,
        )
        .await;
        let result = call(&witness.fixture, tool).await;
        assert_witness_refusal(
            &witness,
            tool,
            &result,
            "simulation.divergence",
            "cross-check refused: the primary RPC and the oracle disagree on the soroban \
             simulation invocation; the wallet did not sign or send. Retry the action; if the \
             disagreement persists, investigate both endpoints",
        )
        .await;
    }
}

/// An oracle that serves another network refuses through both tools with
/// `network.witness_unavailable`, before signing and without a row.
#[tokio::test]
#[serial]
async fn x402_witness_unavailable_writes_no_authorized_row() {
    for (tool, seed) in [
        (Tool::CreatePayment, 0x1a),
        (Tool::AuthenticatedPayment, 0x1b),
    ] {
        let witness = witness_fixture(
            &format!("x402-witness-unavailable-{}", tool.name()),
            seed,
            PAYMENT_AMOUNT,
            None,
            |oracle| oracle.network = NetworkAnswer::Passphrase(FUTURENET_PASSPHRASE),
        )
        .await;
        let result = call(&witness.fixture, tool).await;
        let expected = stellar_agent_core::error::WalletError::from(
            stellar_agent_core::error::NetworkError::WitnessUnavailable {
                reason:
                    stellar_agent_core::error::WitnessUnavailableReason::IdentityNetworkMismatch {
                        authority: witness.oracle.uri(),
                    },
            },
        )
        .to_string();
        assert_witness_refusal(
            &witness,
            tool,
            &result,
            "network.witness_unavailable",
            &expected,
        )
        .await;
        assert_eq!(witness.oracle_methods().await, ["getNetwork"], "{tool:?}");
    }
}

/// An oracle that refuses the credential refuses through both tools with
/// `network.rpc_credential_refused`, before signing and without a row.
#[tokio::test]
#[serial]
async fn x402_oracle_credential_refusal_writes_no_authorized_row() {
    for (tool, seed) in [
        (Tool::CreatePayment, 0x1c),
        (Tool::AuthenticatedPayment, 0x1d),
    ] {
        let witness = witness_fixture(
            &format!("x402-witness-credential-{}", tool.name()),
            seed,
            PAYMENT_AMOUNT,
            None,
            |_| {},
        )
        .await;
        Mock::given(method("POST"))
            .and(wiremock::matchers::body_partial_json(
                serde_json::json!({"method": "simulateTransaction"}),
            ))
            .respond_with(ResponseTemplate::new(401))
            .with_priority(1)
            .mount(&witness.oracle)
            .await;
        let result = call(&witness.fixture, tool).await;
        assert_witness_refusal(
            &witness,
            tool,
            &result,
            "network.rpc_credential_refused",
            &format!(
                "RPC endpoint '{}' answered a request with HTTP 401; check the credential \
                 the profile configures for this endpoint",
                witness.oracle.uri()
            ),
        )
        .await;
        assert_eq!(
            witness.oracle_methods().await,
            ["getNetwork", "simulateTransaction"],
            "{tool:?}: no retry after a credential refusal"
        );
    }
}

/// An oracle client that cannot be built refuses through both tools before
/// the signer entry is read and before any payment request.
#[tokio::test]
#[serial]
async fn x402_oracle_client_construction_refuses_before_the_signer() {
    for (tool, seed) in [
        (Tool::CreatePayment, 0x1e),
        (Tool::AuthenticatedPayment, 0x1f),
    ] {
        let witness = witness_fixture(
            &format!("x402-witness-construction-{}", tool.name()),
            seed,
            PAYMENT_AMOUNT,
            Some("ftp://oracle.example/private-path"),
            |_| {},
        )
        .await;
        let (result, built) = crate::common::clients_built_by(call(&witness.fixture, tool)).await;
        let (code, message, text) = crate::common::assert_business_envelope(&result);
        assert_eq!(code, "network.witness_unavailable", "{tool:?}: {text}");
        assert_eq!(
            message,
            "cross-check unavailable: the client for oracle 'ftp://oracle.example' could not \
             be built; correct oracle_provider_url in the profile file",
            "{tool:?}"
        );
        assert_eq!(
            built, 1,
            "{tool:?}: the failed oracle construction only; the primary client is never built"
        );
        assert_eq!(witness.signer_reads(), 0, "{tool:?}: no signer read");
        assert!(
            witness
                .fixture
                .rpc
                .observed
                .lock()
                .unwrap()
                .methods
                .is_empty(),
            "{tool:?}: no payment request"
        );
        let (authorized, withheld) = verified_x402_rows(&witness.fixture.profile);
        assert!(authorized.is_empty() && withheld.is_empty(), "{tool:?}");
    }
}

/// With a required witness both tools build the primary client and the
/// oracle client, and every payment request goes to the primary.
#[tokio::test]
#[serial]
async fn mcp_x402_tools_build_the_oracle_client_beside_the_primary() {
    for (tool, seed) in [
        (Tool::CreatePayment, 0x20),
        (Tool::AuthenticatedPayment, 0x21),
    ] {
        let witness = witness_fixture(
            &format!("x402-witness-clients-{}", tool.name()),
            seed,
            PAYMENT_AMOUNT,
            None,
            |_| {},
        )
        .await;
        let (result, built) = crate::common::clients_built_by(call(&witness.fixture, tool)).await;
        let envelope = result_json(&result);
        assert_ne!(result.is_error, Some(true), "{tool:?}: {envelope}");
        assert_eq!(built, 2, "{tool:?}: the primary and the oracle");
        assert_eq!(
            witness.fixture.rpc.observed.lock().unwrap().methods,
            PAYMENT_METHODS,
            "{tool:?}"
        );
    }
}

/// The oracle's simulation error text and a JSON-RPC error text reach neither
/// the tool result nor the wallet's log.
#[tokio::test(flavor = "current_thread")]
#[serial]
async fn x402_oracle_texts_reach_no_tool_result_or_log() {
    use stellar_agent_core::observability::{FormatChoice, SubscriberConfig, subscriber_for_tests};
    use tracing::instrument::WithSubscriber as _;
    let cases = [
        (Tool::CreatePayment, 0x23, false, "simulation.divergence"),
        (
            Tool::AuthenticatedPayment,
            0x24,
            false,
            "simulation.divergence",
        ),
        (
            Tool::CreatePayment,
            0x25,
            true,
            "network.witness_unavailable",
        ),
        (
            Tool::AuthenticatedPayment,
            0x26,
            true,
            "network.witness_unavailable",
        ),
    ];
    for (tool, seed, rpc_error, code) in cases {
        let witness = witness_fixture(
            &format!("x402-witness-texts-{seed:x}"),
            seed,
            PAYMENT_AMOUNT,
            None,
            |oracle| oracle.first = FirstSimulate::HostileError,
        )
        .await;
        if rpc_error {
            Mock::given(method("POST"))
                .and(wiremock::matchers::body_partial_json(
                    serde_json::json!({"method": "simulateTransaction"}),
                ))
                .respond_with(|request: &Request| {
                    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "jsonrpc": "2.0", "id": body["id"],
                        "error": {"code": -32603, "message": hostile_simulation_error()},
                    }))
                })
                .with_priority(1)
                .mount(&witness.oracle)
                .await;
        }
        let capture = stellar_agent_test_support::CaptureWriter::new();
        let writer = capture.clone();
        let subscriber = subscriber_for_tests(
            SubscriberConfig::default()
                .with_filter_override(Some(tracing_subscriber::EnvFilter::new("trace")))
                .with_format_override(Some(FormatChoice::Pretty))
                .with_writer_factory(Some(Box::new(move || Box::new(writer.clone())))),
        )
        .expect("the wallet subscriber builds");
        let inert = stellar_agent_test_support::inert_dispatcher();
        let dispatch = tracing::Dispatch::new(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let result = call(&witness.fixture, tool).with_subscriber(dispatch).await;
        drop(inert);
        let logs = capture.captured_str();
        let (got, _message, text) = crate::common::assert_business_envelope(&result);
        assert_eq!(got, code, "{tool:?}: {text}");
        for forbidden in ["PWSECRET", "QSECRET", "leak.example", "eeeeeeeeee"] {
            assert!(!text.contains(forbidden), "{tool:?}: {text}");
            assert!(!logs.contains(forbidden), "{tool:?}: {logs}");
        }
        assert!(
            logs.contains("x402"),
            "{tool:?}: the capture holds the tool's own events: {logs}"
        );
    }
}

/// Caches the fixture's keyed audit writer over an in-memory tip-anchor store
/// the test scripts to fail. The tools' later acquisitions hit the cache and
/// keep that store.
fn cache_writer_over_scripted_anchor(
    fixture: &Fixture,
) -> (
    Arc<Mutex<stellar_agent_core::audit_log::AuditWriter>>,
    Arc<stellar_agent_core::audit_log::tip_anchor::InMemoryTipAnchorStore>,
) {
    use stellar_agent_core::audit_log::tip_anchor::InMemoryTipAnchorStore;
    use stellar_agent_core::audit_log::{AuditWriterRegistry, KeyedAuditAccess};
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let writer = AuditWriterRegistry::get_or_open_keyed(
        &fixture.server.profile_name_for_approval(),
        &fixture.profile.audit_log_path,
        KeyedAuditAccess::new(zeroize::Zeroizing::new([0x37; 32]), store.clone()),
    )
    .unwrap();
    (writer, store)
}

/// A consent row as `approve --id` queues it beside a running server.
fn queued_consent_row() -> stellar_agent_core::audit_log::AuditEntry {
    stellar_agent_core::audit_log::AuditEntry::new_approval_attested(
        "PaymentSimulated",
        "stellar_pay_commit",
        None,
        "queued-consent-nonce",
        "cli",
        "queued-consent",
    )
}

/// Asserts that `result` is the gate's anchor refusal and that the payment
/// left nothing behind: no signature returned, no signed request sent, and
/// neither x402 row written.
fn assert_withheld_before_the_authorized_row(
    tool: Tool,
    fixture: &Fixture,
    result: &rmcp::model::CallToolResult,
) {
    let (code, message, text) = crate::common::assert_business_envelope(result);
    assert_eq!(code, "audit.chain_key_unavailable", "{tool:?}: {text}");
    assert!(
        message.contains("audit.tip_anchor_unavailable"),
        "{tool:?}: {text}"
    );
    assert!(!text.contains("paymentSignature"), "{tool:?}: {text}");
    assert_eq!(
        fixture.rpc.observed.lock().unwrap().signed,
        [false],
        "{tool:?}: only the unsigned simulation reached the RPC"
    );
    let rows = crate::common::audit_rows(&fixture.profile);
    assert_eq!(
        crate::common::rows_of_kind(&rows, "approval_attested").len(),
        1,
        "{tool:?}: the queued consent row was drained: {rows:?}"
    );
    let (authorized, withheld) = verified_x402_rows(&fixture.profile);
    assert!(
        authorized.is_empty() && withheld.is_empty(),
        "{tool:?}: a refusal before the authorized row writes no x402 row: \
         {authorized:?} {withheld:?}"
    );
}

/// Both transmit gates withhold the signature while the authorization anchor
/// fails after the authorized row, and pair that row with an
/// `anchor_unavailable` withheld row.
///
/// Three anchor writes fail: the authorized row's two attempts and the gate's
/// repair after the row. The withheld row's own retry then lands.
#[tokio::test]
#[serial]
async fn an_unavailable_anchor_withholds_both_x402_transmissions() {
    for (tool, seed) in [
        (Tool::CreatePayment, 0x61),
        (Tool::AuthenticatedPayment, 0x62),
    ] {
        let name = format!("x402-anchor-{}", tool.name());
        let fixture = fixture(&name, [seed; 32], |_| {}).await;
        let (_writer, store) = cache_writer_over_scripted_anchor(&fixture);
        store.fail_next_writes(3);
        let result = call(&fixture, tool).await;
        let (code, message, text) = crate::common::assert_business_envelope(&result);
        assert_eq!(code, "audit.chain_key_unavailable", "{text}");
        assert!(message.contains("audit.tip_anchor_unavailable"), "{text}");
        assert!(!text.contains("paymentSignature"));
        assert_eq!(fixture.rpc.observed.lock().unwrap().signed, [false]);
        let (authorized, withheld) = verified_x402_rows(&fixture.profile);
        assert_eq!(authorized.len(), 1);
        assert_eq!(withheld.len(), 1);
        assert_eq!(withheld[0]["failure_stage"], "anchor_unavailable");
        assert_eq!(authorized[0]["request_id"], withheld[0]["request_id"]);
    }
}

/// A tip anchor that falls behind before the authorized row is written
/// refuses both payments at the gate's first anchor check: nothing signed is
/// sent and neither x402 row is written.
///
/// The consent row the unsigned simulation queues is drained by the gate's
/// own acquisition, after that acquisition's anchor check. The drained row's
/// two anchor attempts fail, and the gate's repair before the row is the third
/// failure.
#[tokio::test]
#[serial]
async fn an_anchor_behind_before_the_authorized_row_withholds_both_x402_transmissions() {
    for (tool, seed) in [
        (Tool::CreatePayment, 0x81),
        (Tool::AuthenticatedPayment, 0x82),
    ] {
        let name = format!("x402-anchor-before-{}", tool.name());
        let fixture = fixture(&name, [seed; 32], |_| {}).await;
        *fixture.rpc.queue_on_first.lock().unwrap() = Some(queued_consent_row());
        let (_writer, store) = cache_writer_over_scripted_anchor(&fixture);
        *fixture.rpc.outbox_store.lock().unwrap() = Some(store.clone());
        store.fail_next_writes(3);
        let result = call(&fixture, tool).await;
        assert_withheld_before_the_authorized_row(tool, &fixture, &result);
    }
}

/// A row the audit pre-flight drains whose anchor cannot be written refuses
/// both payments when the transmit gate acquires the writer: nothing signed is
/// sent and neither x402 row is written.
///
/// The consent row is queued before the call, so the tool's pre-flight
/// acquisition drains it. Its two anchor attempts fail, and the gate's
/// acquisition repairs before it reconciles: that third failure refuses the
/// acquisition.
#[tokio::test]
#[serial]
async fn an_anchor_left_behind_by_the_pre_flight_drain_withholds_both_x402_transmissions() {
    for (tool, seed) in [
        (Tool::CreatePayment, 0x83),
        (Tool::AuthenticatedPayment, 0x84),
    ] {
        let name = format!("x402-anchor-drain-{}", tool.name());
        let fixture = fixture(&name, [seed; 32], |_| {}).await;
        let (_writer, store) = cache_writer_over_scripted_anchor(&fixture);
        stellar_agent_core::audit_log::AuditOutbox::for_log(
            &fixture.profile.audit_log_path,
            store.clone(),
        )
        .append(&queued_consent_row())
        .expect("queue the consent row");
        store.fail_next_writes(3);
        let result = call(&fixture, tool).await;
        assert_withheld_before_the_authorized_row(tool, &fixture, &result);
    }
}

/// An authorized row whose two anchor attempts fail is repaired by the gate's
/// check after the row, and the payment then completes.
#[tokio::test]
#[serial]
async fn the_repair_after_the_authorized_row_lets_both_x402_payments_complete() {
    for (tool, seed) in [
        (Tool::CreatePayment, 0x8b),
        (Tool::AuthenticatedPayment, 0x8c),
    ] {
        let name = format!("x402-anchor-repair-{}", tool.name());
        let fixture = fixture(&name, [seed; 32], |_| {}).await;
        let (_writer, store) = cache_writer_over_scripted_anchor(&fixture);
        store.fail_next_writes(2);
        let result = call(&fixture, tool).await;
        let envelope = result_json(&result);
        assert_ne!(result.is_error, Some(true), "{tool:?}: {envelope}");
        assert!(envelope["data"]["paymentSignature"].is_string(), "{tool:?}");
        assert_eq!(fixture.rpc.observed.lock().unwrap().signed, [false, true]);
        let (authorized, withheld) = verified_x402_rows(&fixture.profile);
        assert_eq!(authorized.len(), 1, "{tool:?}");
        assert!(withheld.is_empty(), "{tool:?}: {withheld:?}");
        let rows = crate::common::audit_rows(&fixture.profile);
        assert_eq!(
            store.peek().map(|anchor| anchor.entry_count),
            Some(rows.len() as u64),
            "{tool:?}: the repair anchored the authorized row"
        );
    }
}
