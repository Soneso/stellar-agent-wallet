//! Release proof matrix cells whose rows span both surfaces, on testnet.
//!
//! Each test iterates the rows of one or more cells. An MCP row runs its
//! tool handlers on an in-process server, or on a `stellar-agent mcp serve`
//! child that the test drives over standard input and output. A CLI row runs
//! its verb in a child of the `stellar-agent` executable. Every profile is
//! provisioned with the signed V1 policy ceremony of [`crate::v1_ceremony`]
//! on the headless keyring of an isolated data root. Most rules allow every
//! testnet tool under a call-count window, so a sent call holds a
//! spending-window reservation beside its receipt.
//!
//! An in-process server and an in-process store read share the child's root
//! and keyring: the test installs the root as the data root and the root's
//! headless store as the default keyring store, as `approval_split_commit`
//! does. The writer, cap, reserve and hold tests also remove keyring entries
//! between the ceremony and a run, as `audit_binding_cli` does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration assertions"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{StellarTransactionStatusArgs, WalletServer};
use stellar_agent_test_support::StellarAgentHomeGuard;
use stellar_agent_test_support::keyring_mock::DefaultStoreGuard;
use stellar_agent_test_support::signed_envelope::{
    TESTNET_PASSPHRASE, get_network_result, send_transaction_hash_hex,
};
use stellar_agent_test_support::xdr_fixtures::{account_entry_xdr, account_ledger_key_xdr};
use stellar_xdr::{
    AccountId, HostFunction, Limits, OperationBody, PublicKey, ReadXdr as _, ScAddress, ScVal,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, TransactionEnvelope, Uint256, VecM,
    WriteXdr as _,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use crate::classic_ledger::{ACCOUNT_BALANCE, ClassicLedger, readiness_result};
use crate::fee_reserve_boundary::claimable_entry;
use crate::proof_rows::{CLI_PROOF_ROWS, CliProofRow, row_tool};
use crate::v1_ceremony::{CliRun, IsolatedHome, Keypair, policy_document, policy_rule};

/// The seed of the signer every row signs with.
const SIGNER_SEED: [u8; 32] = [0x5b; 32];

/// The seed of the policy owner.
const OWNER_SEED: [u8; 32] = [0x6b; 32];

/// The seed of the issuer of the `USD` asset the sizing and hold rows trust.
const ISSUER_SEED: [u8; 32] = [0x33; 32];

/// The variable a CLI row reads the signer secret from.
const SIGNER_ENV: &str = "PROOF_ROW_CLAIMS_SIGNER_SECRET";

/// The payment destination. The ledger funds it.
const DESTINATION: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// The account a create-account row creates. The ledger does not hold it.
const NEW_ACCOUNT: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

/// The pinned testnet USDC issuer a trustline row trusts. The ledger funds
/// it, so the issuer-flag read answers.
const USDC_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

/// The hash of the claimable balance a claim row claims, the one
/// [`claimable_entry`] holds.
const BALANCE_ID_HEX64: &str = "abababababababababababababababababababababababababababababababab";

/// The SAC token contract an x402 row pays in.
const X402_ASSET: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

/// The x402 payee.
const X402_PAY_TO: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/// A `SorobanTransactionData` body the x402 simulations answer with.
const X402_TRANSACTION_DATA: &str = "AAAAAAAAAAIAAAAGAAAAAcwD/nT9D7Dc2LxRdab+2vEUF8B+XoN7mQW21oxPT8ALAAAAFAAAAAEAAAAHy8vNUZ8vyZ2ybPHW0XbSrRtP7gEWsJ6zDzcfY9P8z88AAAABAAAABgAAAAHMA/50/Q+w3Ni8UXWm/trxFBfAfl6De5kFttaMT0/ACwAAABAAAAABAAAAAgAAAA8AAAAHQ291bnRlcgAAAAASAAAAAAAAAAAg4dbAxsGAGICfBG3iT2cKGYQ6hK4sJWzZ6or1C5v6GAAAAAEAHfKyAAAFiAAAAIgAAAAAAAAAAw==";

/// The ledger the x402 endpoint reports.
const X402_LEDGER: u32 = 1000;

/// The value audit row kinds a call can write.
const VALUE_ROW_KINDS: &[&str] = &[
    "value_action_pending",
    "value_action_submitted",
    "value_action_failed",
    "x402_payment_authorized",
    "x402_authorization_withheld",
];

/// One value row of the proof matrix: an MCP commit or single-call tool, or
/// a CLI verb.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Row {
    McpPayCommit,
    McpCreateAccountCommit,
    McpClaimCommit,
    McpTrustlineCommit,
    McpX402CreatePayment,
    McpX402AuthenticatedPayment,
    CliPay,
    CliClaim,
    CliTrustline,
    CliAccountsCreate,
}

impl Row {
    /// The row id the matrix names.
    fn id(self) -> &'static str {
        match self {
            Self::McpPayCommit => "mcp.pay_commit",
            Self::McpCreateAccountCommit => "mcp.create_account_commit",
            Self::McpClaimCommit => "mcp.claim_commit",
            Self::McpTrustlineCommit => "mcp.trustline_commit",
            Self::McpX402CreatePayment => "mcp.x402_create_payment",
            Self::McpX402AuthenticatedPayment => "mcp.x402_authenticated_payment",
            Self::CliPay => "cli.pay",
            Self::CliClaim => "cli.claim",
            Self::CliTrustline => "cli.trustline",
            Self::CliAccountsCreate => "cli.accounts_create",
        }
    }

    /// Whether the row sends a classic transaction.
    fn is_classic(self) -> bool {
        !matches!(
            self,
            Self::McpX402CreatePayment | Self::McpX402AuthenticatedPayment
        )
    }

    /// Whether the row runs on the CLI.
    fn is_cli(self) -> bool {
        matches!(
            self,
            Self::CliPay | Self::CliClaim | Self::CliTrustline | Self::CliAccountsCreate
        )
    }

    /// A profile name unique to this row and `case`.
    fn profile(self, case: &str) -> String {
        format!("{}-{case}", self.id().replace(['.', '_'], "-"))
    }
}

/// The rows of `audit.outcome_row`.
const OUTCOME_ROWS: &[Row] = &[
    Row::McpPayCommit,
    Row::McpCreateAccountCommit,
    Row::McpClaimCommit,
    Row::McpTrustlineCommit,
    Row::McpX402CreatePayment,
    Row::McpX402AuthenticatedPayment,
    Row::CliPay,
    Row::CliClaim,
    Row::CliTrustline,
    Row::CliAccountsCreate,
];

/// The rows of the pending `status.transaction_reconciles` cell.
const RECONCILE_ROWS: &[Row] = &[
    Row::McpCreateAccountCommit,
    Row::McpClaimCommit,
    Row::McpTrustlineCommit,
    Row::CliClaim,
    Row::CliTrustline,
    Row::CliAccountsCreate,
];

fn signer() -> Keypair {
    Keypair::from_seed(SIGNER_SEED)
}

fn owner() -> Keypair {
    Keypair::from_seed(OWNER_SEED)
}

fn account_id(g: &str) -> AccountId {
    AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        stellar_strkey::ed25519::PublicKey::from_string(g)
            .unwrap()
            .0,
    )))
}

// ─────────────────────────────────────────────────────────────────────────────
// Endpoints
// ─────────────────────────────────────────────────────────────────────────────

/// What the endpoint answers for a sent transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    /// The send is accepted and the transaction is never found.
    Missing,
    /// The send is accepted and the transaction applied.
    Applied,
    /// The send is accepted and the transaction failed on chain.
    Failed,
    /// The send is refused with a definitive `ERROR` status.
    Refused,
}

/// The base64 `TransactionResult` of a `txBAD_SEQ` failure.
fn bad_sequence_result() -> String {
    stellar_xdr::TransactionResult {
        fee_charged: 100,
        result: stellar_xdr::TransactionResultResult::TxBadSeq,
        ext: stellar_xdr::TransactionResultExt::V0,
    }
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// A testnet ledger for the classic rows. It funds the signer, the payment
/// destination and the USDC issuer, holds the signer's claimable balance,
/// and answers every send with its [`Answer`], which
/// [`ClassicRows::confirm`] changes to [`Answer::Applied`].
#[derive(Clone)]
struct ClassicRows {
    entries: Arc<Vec<(String, String)>>,
    answer: Arc<std::sync::Mutex<Answer>>,
    sends: Arc<AtomicUsize>,
}

impl ClassicRows {
    fn new(answer: Answer) -> Self {
        let signer = signer();
        let mut entries: Vec<(String, String)> = [signer.public(), DESTINATION, USDC_ISSUER]
            .iter()
            .map(|account| {
                (
                    account_ledger_key_xdr(account),
                    account_entry_xdr(account, ACCOUNT_BALANCE, 0),
                )
            })
            .collect();
        entries.push(claimable_entry(signer.public()));
        Self {
            entries: Arc::new(entries),
            answer: Arc::new(std::sync::Mutex::new(answer)),
            sends: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// From now on every `getTransaction` reports the transaction applied.
    fn confirm(&self) {
        *self.answer.lock().unwrap() = Answer::Applied;
    }

    fn sends(&self) -> usize {
        self.sends.load(Ordering::SeqCst)
    }

    async fn serve(&self) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(self.clone())
            .mount(&server)
            .await;
        server
    }
}

impl Respond for ClassicRows {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let fee = json!({
            "max": "100", "min": "100", "mode": "100", "p10": "100", "p20": "100",
            "p30": "100", "p40": "100", "p50": "100", "p60": "100", "p70": "100",
            "p80": "100", "p90": "100", "p95": "100", "p99": "100",
            "transactionCount": "10", "ledgerCount": 5
        });
        let answer = *self.answer.lock().unwrap();
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
                json!({"sorobanInclusionFee": fee, "inclusionFee": fee, "latestLedger": 1001})
            }
            "sendTransaction" => {
                self.sends.fetch_add(1, Ordering::SeqCst);
                let hash = send_transaction_hash_hex(&body, TESTNET_PASSPHRASE);
                if answer == Answer::Refused {
                    json!({
                        "hash": hash, "status": "ERROR", "errorResultXdr": bad_sequence_result(),
                        "latestLedger": 1001, "latestLedgerCloseTime": "1700000000"
                    })
                } else {
                    json!({
                        "hash": hash, "status": "PENDING", "latestLedger": 1001,
                        "latestLedgerCloseTime": "1700000000"
                    })
                }
            }
            "getTransaction" => match answer {
                Answer::Applied => json!({
                    "status": "SUCCESS", "txHash": body["params"]["hash"], "ledger": 1005,
                    "createdAt": crate::classic_ledger::now_unix().to_string(),
                    "latestLedger": 1006, "oldestLedger": 1
                }),
                Answer::Failed => json!({
                    "status": "FAILED", "txHash": body["params"]["hash"], "ledger": 1005,
                    "createdAt": crate::classic_ledger::now_unix().to_string(),
                    "resultXdr": bad_sequence_result(), "latestLedger": 1006, "oldestLedger": 1
                }),
                Answer::Missing | Answer::Refused => json!({
                    "status": "NOT_FOUND", "latestLedger": 1006, "oldestLedger": 1
                }),
            },
            readiness @ ("getHealth" | "getLedgers") => readiness_result(readiness).unwrap(),
            other => panic!("unexpected RPC method {other}"),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
    }
}

/// The testnet endpoint of an x402 payment: the identity and health reads,
/// the unsigned simulation that returns the payer's authorization entry, and
/// the signed re-simulation, which answers with resource data or, when
/// `fail_resimulation` is set, with an error.
#[derive(Clone)]
struct X402Endpoint {
    payer: ScAddress,
    fail_resimulation: bool,
}

impl X402Endpoint {
    fn new(payer: &str, fail_resimulation: bool) -> Self {
        Self {
            payer: ScAddress::Account(account_id(payer)),
            fail_resimulation,
        }
    }

    async fn serve(&self) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(self.clone())
            .mount(&server)
            .await;
        server
    }
}

impl Respond for X402Endpoint {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let void = ScVal::Void.to_xdr_base64(Limits::none()).unwrap();
        let result = match body["method"].as_str().unwrap() {
            "getNetwork" => get_network_result(TESTNET_PASSPHRASE),
            "getHealth" => json!({
                "status": "healthy", "latestLedger": X402_LEDGER, "oldestLedger": 1,
                "ledgerRetentionWindow": 17_280
            }),
            "simulateTransaction" => {
                let envelope = TransactionEnvelope::from_xdr_base64(
                    body["params"]["transaction"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap();
                let TransactionEnvelope::Tx(transaction) = envelope else {
                    panic!("the x402 flow builds a v1 envelope");
                };
                let OperationBody::InvokeHostFunction(host) =
                    transaction.tx.operations[0].body.clone()
                else {
                    panic!("the x402 flow invokes a host function");
                };
                let HostFunction::InvokeContract(invoke) = host.host_function else {
                    panic!("the x402 flow invokes a contract");
                };
                if host.auth.is_empty() {
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
                    json!({
                        "transactionData": X402_TRANSACTION_DATA, "minResourceFee": "1000",
                        "results": [{
                            "auth": [entry.to_xdr_base64(Limits::none()).unwrap()],
                            "xdr": void,
                        }],
                        "latestLedger": X402_LEDGER,
                    })
                } else if self.fail_resimulation {
                    json!({"error": "re-simulation trapped", "latestLedger": X402_LEDGER})
                } else {
                    json!({
                        "transactionData": X402_TRANSACTION_DATA, "minResourceFee": "1000",
                        "results": [{"auth": [], "xdr": void}],
                        "latestLedger": X402_LEDGER,
                    })
                }
            }
            other => panic!("the x402 flow sends no {other} request"),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Homes
// ─────────────────────────────────────────────────────────────────────────────

/// The rule that allows every testnet tool under a call-count window of
/// `window`, which is the accounting window of every hold it sizes.
fn allow_all(window: &str) -> String {
    policy_rule(
        "*",
        "stellar:testnet",
        &format!("[{{ kind = \"rate_limit\", window = \"{window}\", max_calls = 100 }}]"),
        "allow",
    )
}

/// One row's isolated home: a testnet V1 profile named `name`, reading
/// through `rpc_url`, under a signed policy of `rules`.
struct RowHome {
    home: IsolatedHome,
    name: String,
}

impl RowHome {
    /// A home whose policy allows every testnet tool under a call-count
    /// window of 100 calls a day.
    fn provision(name: &str, rpc_url: &str) -> Self {
        Self::provision_with(name, rpc_url, &[allow_all("1d")])
    }

    fn provision_with(name: &str, rpc_url: &str, rules: &[String]) -> Self {
        let home = IsolatedHome::new();
        home.provision_v1_profile(
            name,
            &["--rpc-url", rpc_url],
            &signer(),
            &owner(),
            &policy_document(name, rules),
        );
        Self {
            home,
            name: name.to_owned(),
        }
    }

    /// Runs `args` with the profile and the signer's secret in the child's
    /// environment.
    fn run(&self, args: &[&str]) -> CliRun {
        let signer = signer();
        let mut all: Vec<&str> = args.to_vec();
        all.extend_from_slice(&["--profile", &self.name]);
        self.home.run(&all, &[(SIGNER_ENV, signer.secret())])
    }

    /// The value audit rows of the profile, by kind, in log order.
    fn value_rows(&self) -> Vec<String> {
        let profile = self.home.load_profile(&self.name);
        std::fs::read_to_string(&profile.audit_log_path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter_map(|row| row["kind"].as_str().map(str::to_owned))
            .filter(|kind| VALUE_ROW_KINDS.contains(&kind.as_str()))
            .collect()
    }

    /// Opens the home in this process: the home as the data root and its
    /// headless store as the default keyring store, until the guard drops.
    fn enter(&self) -> InProcess {
        let store: Arc<keyring_core::CredentialStore> =
            Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
                self.home.keyring_path(),
                stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                    zeroize::Zeroizing::new(self.home.headless_key()),
                )),
            ));
        InProcess {
            _store: DefaultStoreGuard::install(store),
            _home: StellarAgentHomeGuard::new(self.home.path()),
        }
    }

    /// The MCP server of the profile, with a one-second submission timeout.
    /// The caller holds the guard of [`Self::enter`].
    fn server(&self) -> WalletServer {
        let mut profile: Profile = self.home.load_profile(&self.name);
        profile.submit_timeout_seconds = Some(1);
        let mut server =
            WalletServer::new_with_policy_dir_for_test(profile, &self.home.path().join("policies"))
                .unwrap();
        server.set_approval_dir_for_test(self.home.path().join("approvals"));
        server.set_x402_identity_session_for_test(
            "header.payload.signature".to_owned(),
            stellar_agent_test_support::signed_envelope::account_id_for_seed([0x01; 32]),
            Vec::new(),
        );
        server
    }
}

/// The data root and the default keyring store of an in-process server.
struct InProcess {
    _store: DefaultStoreGuard,
    _home: StellarAgentHomeGuard,
}

// ─────────────────────────────────────────────────────────────────────────────
// Row invocations
// ─────────────────────────────────────────────────────────────────────────────

/// The JSON envelope a tool result carries as the text of its first content
/// item.
fn result_json(result: &impl serde::Serialize) -> Value {
    let wire = serde_json::to_value(result).unwrap();
    serde_json::from_str(wire["content"][0]["text"].as_str().unwrap()).unwrap()
}

/// Calls the MCP preparation tool `tool` on `server` with `args` and, with
/// its prepared envelope, the tool's commit handler; returns both envelopes.
/// A refused preparation reaches no commit handler, and its commit envelope
/// is `null`.
async fn prepare_and_commit(server: &WalletServer, tool: &str, args: Value) -> (Value, Value) {
    fn from<T: serde::de::DeserializeOwned>(value: &Value) -> T {
        serde_json::from_value(value.clone()).unwrap()
    }
    let prepared = result_json(
        &match tool {
            "stellar_pay" => server.call_stellar_pay(from(&args)).await,
            "stellar_create_account" => server.call_stellar_create_account(from(&args)).await,
            "stellar_claim" => server.call_stellar_claim(from(&args)).await,
            "stellar_trustline" => server.call_stellar_trustline(from(&args)).await,
            other => panic!("{other} has no commit handler"),
        }
        .unwrap(),
    );
    if prepared["ok"] != true {
        return (prepared, Value::Null);
    }
    let mut commit = args;
    for field in ["nonce", "expires_at_unix_ms", "envelope_xdr"] {
        commit[field] = prepared["data"][field].clone();
    }
    let committed = result_json(
        &match tool {
            "stellar_pay" => server.call_stellar_pay_commit(from(&commit)).await,
            "stellar_create_account" => {
                server
                    .call_stellar_create_account_commit(from(&commit))
                    .await
            }
            "stellar_claim" => server.call_stellar_claim_commit(from(&commit)).await,
            _ => server.call_stellar_trustline_commit(from(&commit)).await,
        }
        .unwrap(),
    );
    (prepared, committed)
}

/// The preparation arguments of a classic MCP row.
fn prepare_args(row: Row, source: &str) -> Value {
    let chain = "stellar:testnet";
    match row {
        Row::McpPayCommit => json!({
            "chain_id": chain, "source": source, "destination": DESTINATION,
            "asset": "native", "amount_in_stroops": "10000000",
        }),
        Row::McpCreateAccountCommit => json!({
            "chain_id": chain, "source": source, "destination": NEW_ACCOUNT,
            "starting_balance": "2 XLM",
        }),
        Row::McpClaimCommit => json!({
            "chain_id": chain, "balance_id": BALANCE_ID_HEX64, "source_account": source,
        }),
        Row::McpTrustlineCommit => json!({
            "chain_id": chain, "from": source, "asset": "USDC", "limit_stroops": "1000000000",
        }),
        other => panic!("{other:?} has no preparation"),
    }
}

/// The preparation tool of a classic MCP row, from [`MCP_COMMIT_ROWS`].
fn preparation_tool(row: Row) -> &'static str {
    MCP_COMMIT_ROWS
        .iter()
        .find(|(id, _)| *id == row.id())
        .map(|(_, tool)| *tool)
        .unwrap_or_else(|| panic!("{row:?} has no preparation"))
}

/// Prepares and commits a classic MCP row and returns the commit envelope.
async fn mcp_commit(server: &WalletServer, row: Row, source: &str) -> Value {
    let (prepared, committed) =
        prepare_and_commit(server, preparation_tool(row), prepare_args(row, source)).await;
    assert_eq!(prepared["ok"], true, "{}: {prepared}", row.id());
    committed
}

/// Calls an x402 MCP row and returns its envelope.
async fn mcp_x402(server: &WalletServer, row: Row) -> Value {
    let requirements = json!({
        "scheme": "exact", "network": "stellar:testnet", "asset": X402_ASSET,
        "amount": "10000000", "payTo": X402_PAY_TO, "maxTimeoutSeconds": 300,
        "extra": { "areFeesSponsored": true }
    })
    .to_string();
    let result = match row {
        Row::McpX402CreatePayment => {
            server
                .call_stellar_x402_create_payment(
                    serde_json::from_value(json!({
                        "chain_id": "stellar:testnet", "payment_required": requirements,
                    }))
                    .unwrap(),
                )
                .await
        }
        Row::McpX402AuthenticatedPayment => {
            server
                .call_stellar_x402_authenticated_payment(
                    serde_json::from_value(json!({
                        "chain_id": "stellar:testnet", "payment_required": requirements,
                        "home_domain": "merchant.example",
                    }))
                    .unwrap(),
                )
                .await
        }
        other => panic!("{other:?} is not an x402 row"),
    }
    .unwrap();
    result_json(&result)
}

/// The argv of a CLI row, without the profile, with a one-second submission
/// timeout.
fn cli_args(row: Row, source: &str) -> Vec<String> {
    let issued = format!("USDC:{USDC_ISSUER}");
    let args: Vec<&str> = match row {
        Row::CliPay => vec![
            "pay",
            DESTINATION,
            "1 XLM",
            "--source",
            source,
            "--secret-env",
            SIGNER_ENV,
        ],
        Row::CliClaim => vec![
            "claim",
            BALANCE_ID_HEX64,
            "--source",
            source,
            "--secret-env",
            SIGNER_ENV,
        ],
        Row::CliTrustline => vec!["trustline", "--from", source, "--asset", &issued],
        Row::CliAccountsCreate => vec![
            "accounts",
            "create",
            NEW_ACCOUNT,
            "--sponsor",
            source,
            "--secret-env",
            SIGNER_ENV,
            "--starting-balance",
            "2 XLM",
        ],
        other => panic!("{other:?} is not a CLI row"),
    };
    args.into_iter()
        .chain(["--timeout-seconds", "1"])
        .map(str::to_owned)
        .collect()
}

/// Sends one classic row's call through the home's endpoint and returns its
/// envelope: the commit tool's for an MCP row, the verb's for a CLI row.
async fn send_classic(home: &RowHome, row: Row) -> Value {
    let source = signer().public().to_owned();
    if row.is_cli() {
        let args = cli_args(row, &source);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        home.run(&args).envelope
    } else {
        let _in_process = home.enter();
        let server = home.server();
        mcp_commit(&server, row, &source).await
    }
}

/// The status view of `tx_hash` through the row's surface: the
/// `stellar_transaction_status` tool for an MCP row and `tx status` for a CLI
/// row.
async fn status_view(home: &RowHome, row: Row, tx_hash: &str) -> Value {
    if row.is_cli() {
        let run = home.run(&["tx", "status", tx_hash]);
        assert_eq!(run.code, 0, "{}: {} {}", row.id(), run.envelope, run.stderr);
        run.envelope
    } else {
        let _in_process = home.enter();
        let server = home.server();
        let result = server
            .call_stellar_transaction_status(StellarTransactionStatusArgs {
                chain_id: "stellar:testnet".to_owned(),
                tx_hash: Some(tx_hash.to_owned()),
                business_id: None,
                retry_recovery: false,
            })
            .await
            .unwrap();
        result_json(&result)
    }
}

/// The transaction and envelope hashes a timed-out call reports.
fn timeout_hashes(row: Row, sent: &Value) -> Result<(String, String), String> {
    let details = &sent["error"]["details"];
    match (
        sent["error"]["code"].as_str(),
        details["tx_hash"].as_str(),
        details["envelope_hash"].as_str(),
    ) {
        (Some("submission.tx_timeout"), Some(tx), Some(envelope)) => {
            Ok((tx.to_owned(), envelope.to_owned()))
        }
        _ => Err(format!("{}: not a reported timeout: {sent}", row.id())),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// status.transaction_reconciles
// ─────────────────────────────────────────────────────────────────────────────

/// Checks that `view` reports the receipt of `envelope_hash` with
/// `receipt_status` beside its open hold.
fn reconciled(view: &Value, receipt_status: &str, envelope_hash: &str) -> Result<(), String> {
    let data = &view["data"];
    let holds = data["record"]["envelope_hash"] == envelope_hash
        && data["record"]["status"] == receipt_status
        && data["record"]["reservation_open"] == true
        && data["reservation"]["envelope_hash"] == envelope_hash
        && data["reservation"]["operator_required"] == false;
    if view["ok"] == true && holds {
        Ok(())
    } else {
        Err(format!(
            "expected a {receipt_status} receipt beside its hold: {view}"
        ))
    }
}

/// Checks that `view` reports the receipt of `envelope_hash` released at its
/// accounting horizon: the record names the expiry and its decision, and no
/// hold remains.
fn released(view: &Value, envelope_hash: &str) -> Result<(), String> {
    let data = &view["data"];
    let holds = data["chain_status"] == "NOT_FOUND"
        && data["record"]["envelope_hash"] == envelope_hash
        && data["record"]["reservation_open"] == false
        && data["record"]["release_code"] == "submission.accounting_expired"
        && data["record"]["settlement_decision_id"].is_string()
        && data["reservation"].is_null();
    if view["ok"] == true && holds {
        Ok(())
    } else {
        Err(format!(
            "expected the hold released at its accounting horizon: {view}"
        ))
    }
}

/// Seeds in `home`, as `tx_status_wire_guard`'s `Case::Released` does, a sent
/// receipt and its hold for a submission from the signer whose time bound
/// and one-day window have passed, and returns its transaction and envelope
/// hashes. A testnet call of these rows sends no time bound, so its own hold
/// has no accounting horizon.
fn seed_expired_hold(home: &RowHome, index: usize) -> (String, String) {
    use stellar_agent_core::policy::v1::criteria::state_store::{
        StateKey, WindowEntry, WindowLimit,
    };
    use stellar_agent_network::policy_state::{ChainScope, PersistedWindowStore, SubmissionHold};
    let envelope_hash = format!("{:02x}", 0xa0 + index).repeat(32);
    let tx_hash = format!("{:02x}", 0xb0 + index).repeat(32);
    let _in_process = home.enter();
    let profile = home.home.load_profile(&home.name);
    let source = signer().public().to_owned();
    let receipts = stellar_agent_core::profile::receipt::ReceiptStore::open(&home.name).unwrap();
    receipts
        .begin_submission(&envelope_hash, &tx_hash, &source, 7, 1, 1_000)
        .unwrap();
    receipts.mark_submitted(&envelope_hash).unwrap();
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    PersistedWindowStore::for_profile(&home.name)
        .record_pending(
            &profile,
            &[WindowEntry::new(
                StateKey::new(&home.name, 1, "native", 86_400),
                now,
                75,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000_000,
                },
            )],
            &SubmissionHold {
                destinations: Default::default(),
                chain_scope: ChainScope::for_chain(profile.chain_id),
                id: envelope_hash.clone(),
                tx_hash: tx_hash.clone(),
                source,
                sequence: 7,
                max_time: 1,
                pending_since_ms: now,
                submission_ledger: 1_000,
                submission_anchor: None,
                operator_required: false,
            },
        )
        .unwrap();
    (tx_hash, envelope_hash)
}

/// For each commit and verb of the cell, a sent call that times out leaves a
/// pending receipt and a held reservation. The transaction status of its
/// hash, through the row's own surface, reports both; once the endpoint
/// reports the transaction applied, the status records the success on the
/// receipt and keeps the hold, which a reported success does not release.
/// In a second home, a sent receipt and its hold whose time bound and window
/// have passed are seeded as the wire guard's released case seeds them, and
/// the endpoint never finds the transaction. The status through the row's
/// surface releases the hold: the record carries
/// `submission.accounting_expired` and its decision, and no hold remains.
/// No status call sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn every_sent_row_reconciles_its_receipt_and_hold() {
    let mut failures = Vec::new();
    for &row in RECONCILE_ROWS {
        let ledger = ClassicRows::new(Answer::Missing);
        let rpc = ledger.serve().await;
        let home = RowHome::provision(&row.profile("reconcile"), &rpc.uri());
        let sent = send_classic(&home, row).await;
        let (tx_hash, envelope_hash) = match timeout_hashes(row, &sent) {
            Ok(hashes) => hashes,
            Err(failure) => {
                failures.push(failure);
                continue;
            }
        };
        let sends = ledger.sends();

        let before = status_view(&home, row, &tx_hash).await;
        if let Err(failure) = reconciled(&before, "pending", &envelope_hash) {
            failures.push(format!("{} before the report: {failure}", row.id()));
        }
        ledger.confirm();
        let after = status_view(&home, row, &tx_hash).await;
        if after["data"]["chain_status"] != "SUCCESS" {
            failures.push(format!("{}: no applied report: {after}", row.id()));
        }
        if let Err(failure) = reconciled(&after, "success", &envelope_hash) {
            failures.push(format!("{} after the report: {failure}", row.id()));
        }
        if ledger.sends() != sends {
            failures.push(format!("{}: a status call sent", row.id()));
        }
    }

    for (index, &row) in RECONCILE_ROWS.iter().enumerate() {
        let ledger = ClassicRows::new(Answer::Missing);
        let rpc = ledger.serve().await;
        let home = RowHome::provision(&row.profile("release"), &rpc.uri());
        let (tx_hash, envelope_hash) = seed_expired_hold(&home, index);
        let view = status_view(&home, row, &tx_hash).await;
        if let Err(failure) = released(&view, &envelope_hash) {
            failures.push(format!("{} past its horizon: {failure}", row.id()));
        }
        if ledger.sends() != 0 {
            failures.push(format!("{}: a status call sent", row.id()));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ─────────────────────────────────────────────────────────────────────────────
// audit.outcome_row
// ─────────────────────────────────────────────────────────────────────────────

/// One terminal outcome a row reaches against the offline endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// A classic call the endpoint reports applied.
    Applied,
    /// A classic call sent and never reported, so its outcome is unknown.
    TimedOut,
    /// A classic call the endpoint reports failed on chain.
    Failed,
    /// A classic call whose send the endpoint refuses.
    SendRefused,
    /// An x402 payment whose signed authorization is returned.
    Paid,
    /// An x402 payment withheld after its authorization passed the gate.
    Withheld,
}

impl Outcome {
    fn of(row: Row) -> &'static [Self] {
        if row.is_classic() {
            &[
                Self::Applied,
                Self::TimedOut,
                Self::Failed,
                Self::SendRefused,
            ]
        } else {
            &[Self::Paid, Self::Withheld]
        }
    }

    /// The value rows the call leaves: the one row that records the outcome
    /// and, for a withheld payment, the authorization row the transmit gate
    /// wrote before the failure, which the outcome row pairs with. Every sent
    /// classic outcome keeps the pending row the recorder wrote before the
    /// send and writes no other value row.
    fn rows(self) -> &'static [&'static str] {
        match self {
            Self::Applied | Self::TimedOut | Self::Failed | Self::SendRefused => {
                &["value_action_pending"]
            }
            Self::Paid => &["x402_payment_authorized"],
            Self::Withheld => &["x402_payment_authorized", "x402_authorization_withheld"],
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::TimedOut => "timed-out",
            Self::Failed => "failed",
            Self::SendRefused => "refused",
            Self::Paid => "paid",
            Self::Withheld => "withheld",
        }
    }
}

/// Runs `row` to `outcome` in a fresh home and returns the call's envelope
/// and the home.
async fn reach(row: Row, outcome: Outcome) -> (Value, RowHome) {
    let profile = row.profile(outcome.name());
    if row.is_classic() {
        let ledger = ClassicRows::new(match outcome {
            Outcome::Applied => Answer::Applied,
            Outcome::Failed => Answer::Failed,
            Outcome::SendRefused => Answer::Refused,
            _ => Answer::Missing,
        });
        let rpc = ledger.serve().await;
        let home = RowHome::provision(&profile, &rpc.uri());
        let sent = send_classic(&home, row).await;
        drop(rpc);
        (sent, home)
    } else {
        let endpoint = X402Endpoint::new(signer().public(), outcome == Outcome::Withheld);
        let rpc = endpoint.serve().await;
        let home = RowHome::provision(&profile, &rpc.uri());
        let paid = {
            let _in_process = home.enter();
            mcp_x402(&home.server(), row).await
        };
        drop(rpc);
        (paid, home)
    }
}

/// Whether `envelope` reports `outcome` for `row`. The fixture's failure and
/// refusal both carry a `txBAD_SEQ` result; `trustline` renders every send
/// failure under its own code.
fn reports(row: Row, outcome: Outcome, envelope: &Value) -> bool {
    let failure = |code: &str| {
        let expected = if row == Row::CliTrustline {
            "trustline.submit_failed"
        } else {
            code
        };
        envelope["ok"] == false && envelope["error"]["code"] == expected
    };
    match outcome {
        Outcome::Applied => envelope["ok"] == true,
        Outcome::TimedOut => envelope["error"]["code"] == "submission.tx_timeout",
        Outcome::Failed => failure("submission.sequence_number_stale"),
        Outcome::SendRefused => failure("submission.tx_malformed"),
        Outcome::Paid => envelope["ok"] == true && envelope["data"]["paymentSignature"].is_string(),
        Outcome::Withheld => {
            envelope["ok"] == false
                && envelope
                    .get("data")
                    .is_none_or(|data| data.get("paymentSignature").is_none())
        }
    }
}

/// For each value row, every terminal outcome it reaches offline writes one
/// audit row that records it. A classic call that is applied, times out,
/// fails on chain or has its send refused leaves exactly one
/// `value_action_pending` row and no other value row: no answer after the
/// send writes a further row. A paid x402 payment leaves exactly
/// one `x402_payment_authorized` row, and a payment withheld after the
/// transmit gate leaves exactly one `x402_authorization_withheld` row,
/// paired with the gate's authorization row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn every_terminal_outcome_writes_one_audit_row() {
    let mut failures = Vec::new();
    for &row in OUTCOME_ROWS {
        for &outcome in Outcome::of(row) {
            let (envelope, home) = reach(row, outcome).await;
            if !reports(row, outcome, &envelope) {
                failures.push(format!(
                    "{} {}: unexpected answer: {envelope}",
                    row.id(),
                    outcome.name()
                ));
                continue;
            }
            let rows = home.value_rows();
            if rows != outcome.rows() {
                failures.push(format!(
                    "{} {}: value rows {rows:?}, expected {:?}",
                    row.id(),
                    outcome.name(),
                    outcome.rows()
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ─────────────────────────────────────────────────────────────────────────────
// The MCP server process: status.approval_view and audit.outbox_at_shutdown
// ─────────────────────────────────────────────────────────────────────────────
//
// Each row's signed policy lists, in this order, one `require_approval` rule
// for each of the row's tools (the preparation and the commit of a classic
// row, the payment tool of an x402 row), then the rule that allows every
// other testnet tool under a call-count window. `approval_rules` builds that
// order, and the engine applies the first rule that matches a tool.

/// The MCP rows of the approval and outbox cells.
const APPROVAL_ROWS: &[Row] = &[
    Row::McpPayCommit,
    Row::McpCreateAccountCommit,
    Row::McpClaimCommit,
    Row::McpTrustlineCommit,
    Row::McpX402CreatePayment,
    Row::McpX402AuthenticatedPayment,
];

impl Row {
    /// The tool whose call stores the row's approval and its arguments.
    fn preparation(self, source: &str) -> (&'static str, Value) {
        let requirements = json!({
            "scheme": "exact", "network": "stellar:testnet", "asset": X402_ASSET,
            "amount": "10000000", "payTo": X402_PAY_TO, "maxTimeoutSeconds": 300,
            "extra": { "areFeesSponsored": true }
        })
        .to_string();
        match self {
            Self::McpPayCommit => ("stellar_pay", prepare_args(self, source)),
            Self::McpCreateAccountCommit => ("stellar_create_account", prepare_args(self, source)),
            Self::McpClaimCommit => ("stellar_claim", prepare_args(self, source)),
            Self::McpTrustlineCommit => ("stellar_trustline", prepare_args(self, source)),
            Self::McpX402CreatePayment => (
                "stellar_x402_create_payment",
                json!({"chain_id": "stellar:testnet", "payment_required": requirements}),
            ),
            Self::McpX402AuthenticatedPayment => (
                "stellar_x402_authenticated_payment",
                json!({
                    "chain_id": "stellar:testnet", "payment_required": requirements,
                    "home_domain": "merchant.example",
                }),
            ),
            other => panic!("{other:?} is not an MCP row"),
        }
    }

    /// The rules that require approval for the row's tools, ahead of the rule
    /// that allows every other testnet tool.
    fn approval_rules(self) -> Vec<String> {
        let tools: &[&str] = match self {
            Self::McpPayCommit => &["stellar_pay", "stellar_pay_commit"],
            Self::McpCreateAccountCommit => {
                &["stellar_create_account", "stellar_create_account_commit"]
            }
            Self::McpClaimCommit => &["stellar_claim", "stellar_claim_commit"],
            Self::McpTrustlineCommit => &["stellar_trustline", "stellar_trustline_commit"],
            Self::McpX402CreatePayment => &["stellar_x402_create_payment"],
            Self::McpX402AuthenticatedPayment => &["stellar_x402_authenticated_payment"],
            other => panic!("{other:?} is not an MCP row"),
        };
        tools
            .iter()
            .map(|tool| {
                policy_rule(tool, "stellar:testnet", "[]", "require_approval")
                    + "ttl_secs = 600\nreason = \"operator review\"\n"
            })
            .chain(std::iter::once(allow_all("1d")))
            .collect()
    }
}

/// A `stellar-agent mcp serve` child of a row's home, driven over its
/// standard input and output.
struct ServerChild {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    lines: std::sync::mpsc::Receiver<String>,
    stderr: Arc<std::sync::Mutex<String>>,
    next_id: u64,
}

impl ServerChild {
    /// Starts the server for `home`'s profile and completes the MCP
    /// initialization handshake.
    fn start(home: &RowHome) -> Self {
        use std::io::BufRead as _;
        use std::process::Stdio;
        let mut child = home
            .home
            .command(&["mcp", "serve", "--profile", &home.name])
            .env("STELLAR_AGENT_LOG", "error")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (sender, lines) = std::sync::mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr = Arc::new(std::sync::Mutex::new(String::new()));
        let sink = Arc::clone(&stderr);
        let mut pipe = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = std::io::Read::read_to_string(&mut pipe, &mut text);
            sink.lock().unwrap().push_str(&text);
        });
        let stdin = child.stdin.take();
        let mut server = Self {
            child,
            stdin,
            lines,
            stderr,
            next_id: 1,
        };
        let init = server.request(
            "initialize",
            &json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "proof-row-claims", "version": "0" },
            }),
        );
        assert!(init.get("result").is_some(), "initialize failed: {init}");
        server.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        server
    }

    fn send(&mut self, message: &Value) {
        use std::io::Write as _;
        let stdin = self.stdin.as_mut().unwrap();
        let mut line = serde_json::to_vec(message).unwrap();
        line.push(b'\n');
        stdin.write_all(&line).unwrap();
        stdin.flush().unwrap();
    }

    /// Sends one request and returns its response, skipping notifications.
    fn request(&mut self, method: &str, params: &Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        loop {
            let line = self
                .lines
                .recv_timeout(std::time::Duration::from_secs(60))
                .unwrap_or_else(|_| {
                    panic!(
                        "no answer to {method}; stderr: {}",
                        self.stderr.lock().unwrap()
                    )
                });
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["id"] == json!(id) {
                return message;
            }
        }
    }

    /// Calls `tool` with `arguments` and returns the tool's JSON envelope.
    fn call(&mut self, tool: &str, arguments: &Value) -> Value {
        let response = self.request(
            "tools/call",
            &json!({ "name": tool, "arguments": arguments }),
        );
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("{tool}: no text content: {response}"));
        serde_json::from_str(text).unwrap()
    }

    /// Closes the server's standard input, the shutdown a client's exit
    /// gives it, and returns its exit status and standard error.
    fn shut_down(mut self) -> (std::process::ExitStatus, String) {
        drop(self.stdin.take());
        let started = std::time::Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(60),
                "the server exits within a minute"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        std::thread::sleep(std::time::Duration::from_millis(100));
        let stderr = self.stderr.lock().unwrap().clone();
        (status, stderr)
    }
}

/// One MCP row's approval, stored by its preparation through a server child
/// that holds the profile's audit writer.
struct StoredApproval {
    home: RowHome,
    server: Option<ServerChild>,
    nonce: String,
    _rpc: MockServer,
}

impl StoredApproval {
    /// Provisions `row`'s home under `case`, starts its server, caches the
    /// server's audit writer with a message signature, and runs the row's
    /// preparation, which stores a pending approval.
    async fn new(row: Row, case: &str) -> Self {
        let rpc = if row.is_classic() {
            ClassicRows::new(Answer::Missing).serve().await
        } else {
            X402Endpoint::new(signer().public(), false).serve().await
        };
        let home = RowHome::provision_with(&row.profile(case), &rpc.uri(), &row.approval_rules());
        let mut server = ServerChild::start(&home);
        let signed = server.call(
            "stellar_sep43_sign_message",
            &json!({"chain_id": "stellar:testnet", "message": "hello"}),
        );
        assert_eq!(signed["ok"], true, "{}: {signed}", row.id());
        let (tool, args) = row.preparation(signer().public());
        let prepared = server.call(tool, &args);
        let nonce = prepared["data"]["approval"]["approval_nonce"]
            .as_str()
            .unwrap_or_else(|| panic!("{}: no approval: {prepared}", row.id()))
            .to_owned();
        Self {
            home,
            server: Some(server),
            nonce,
            _rpc: rpc,
        }
    }

    /// `stellar_approval_status` of the approval, through the server.
    fn status(&mut self) -> Value {
        let nonce = self.nonce.clone();
        self.server
            .as_mut()
            .unwrap()
            .call("stellar_approval_status", &json!({"approval_id": nonce}))
    }

    /// Shuts the server down; see [`ServerChild::shut_down`].
    fn shut_down(&mut self) -> (std::process::ExitStatus, String) {
        self.server.take().unwrap().shut_down()
    }

    /// The bytes of the profile's approval inbox.
    fn inbox(&self) -> Vec<u8> {
        std::fs::read(
            self.home
                .home
                .path()
                .join("approvals")
                .join(format!("{}.toml", self.home.name)),
        )
        .unwrap()
    }

    /// Approves the approval through `stellar-agent approve`, the operator's
    /// entry, while the server holds the audit writer.
    fn approve(&self) -> CliRun {
        self.home.home.run(
            &[
                "approve",
                "--id",
                &self.nonce,
                "--profile",
                &self.home.name,
                "--yes",
            ],
            &[],
        )
    }

    /// The audit log of the profile.
    fn log_path(&self) -> std::path::PathBuf {
        self.home.home.load_profile(&self.home.name).audit_log_path
    }

    /// The number of rows queued beside the profile's audit log.
    fn queued(&self) -> usize {
        stellar_agent_core::audit_log::inspect_outbox(&self.log_path())
            .unwrap()
            .pending
    }

    /// The `approval_attested` rows of the profile's log for this approval.
    fn attested_rows(&self) -> usize {
        let prefix = &self.nonce[..8];
        std::fs::read_to_string(self.log_path())
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|row| {
                row["kind"] == "approval_attested"
                    && row
                        .as_object()
                        .is_some_and(|fields| fields.values().any(|v| v == prefix))
            })
            .count()
    }
}

/// `view` without its per-call request id.
fn without_request_id(mut view: Value) -> Value {
    view["request_id"] = Value::Null;
    view
}

/// The approval kind the inbox stores for an MCP approval row.
fn inbox_kind(row: Row) -> &'static str {
    match row {
        Row::McpPayCommit | Row::McpCreateAccountCommit => "PaymentSimulated",
        Row::McpClaimCommit => "ClaimSimulated",
        Row::McpTrustlineCommit => "TrustlineSimulated",
        Row::McpX402CreatePayment | Row::McpX402AuthenticatedPayment => "X402Payment",
        other => panic!("{other:?} is not an MCP row"),
    }
}

/// For each MCP value row on testnet, the server process answers
/// `stellar_approval_status` from the approval inbox, with the row's
/// approval kind. Before consent it reports the stored approval `pending`,
/// with an expiry ahead, no reuse and a supported verification that is not
/// valid; after `stellar-agent approve` it reports it `attested`, with the
/// verification `{"supported":true,"valid":true,"reason":"ok"}`. Two status
/// calls in each state answer the same view and leave the inbox byte for
/// byte as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn every_mcp_row_reports_its_inbox_approval_without_consuming_it() {
    let mut failures = Vec::new();
    for &row in APPROVAL_ROWS {
        let mut approval = StoredApproval::new(row, "inbox-view").await;
        for (state, approve, verification) in [
            (
                "pending",
                false,
                json!({"supported": true, "valid": false, "reason": "attestation_invalid"}),
            ),
            (
                "attested",
                true,
                json!({"supported": true, "valid": true, "reason": "ok"}),
            ),
        ] {
            if approve {
                let approved = approval.approve();
                if approved.code != 0 {
                    failures.push(format!("{}: approve: {}", row.id(), approved.envelope));
                    break;
                }
            }
            let before = approval.inbox();
            let first = approval.status();
            let second = approval.status();
            let data = &first["data"];
            let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
            let holds = first["ok"] == true
                && data["state"] == state
                && data["reusable"] == false
                && data["expires_at_ms"].as_u64().is_some_and(|at| at > now);
            if !holds {
                failures.push(format!("{} {state}: {first}", row.id()));
            }
            if data["kind"] != inbox_kind(row) {
                failures.push(format!(
                    "{} {state}: kind {}, expected {}",
                    row.id(),
                    data["kind"],
                    inbox_kind(row)
                ));
            }
            if data["verification"] != verification {
                failures.push(format!(
                    "{} {state}: verification {}, expected {verification}",
                    row.id(),
                    data["verification"]
                ));
            }
            if without_request_id(first.clone()) != without_request_id(second) {
                failures.push(format!(
                    "{} {state}: a second call answers another view",
                    row.id()
                ));
            }
            if approval.inbox() != before {
                failures.push(format!(
                    "{} {state}: the status calls changed the inbox",
                    row.id()
                ));
            }
        }
        let _ = approval.shut_down();
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// For each MCP value row on testnet, `stellar-agent approve` run while the
/// server process holds the profile's audit writer queues its consent row in
/// the outbox, and the log lacks it. Closing the server's standard input
/// shuts it down: it exits 0, and its exit drain delivers the row and
/// empties the outbox.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn every_mcp_row_queues_its_approval_row_until_the_server_exit_drain() {
    let mut failures = Vec::new();
    for &row in APPROVAL_ROWS {
        let mut approval = StoredApproval::new(row, "exit-drain").await;
        let approved = approval.approve();
        if approved.code != 0 {
            failures.push(format!("{}: approve: {}", row.id(), approved.envelope));
            let _ = approval.shut_down();
            continue;
        }
        let (queued, attested) = (approval.queued(), approval.attested_rows());
        if (queued, attested) != (1, 0) {
            failures.push(format!(
                "{}: after approve, queued {queued} and logged {attested}",
                row.id()
            ));
        }
        let (status, stderr) = approval.shut_down();
        let (queued, attested) = (approval.queued(), approval.attested_rows());
        if !status.success() || (queued, attested) != (0, 1) {
            failures.push(format!(
                "{}: after the exit, {status}, queued {queued} and logged {attested}; {stderr}",
                row.id()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ─────────────────────────────────────────────────────────────────────────────
// One root, many profiles: audit.writer_before_signer, the sizing claims and
// sizing.hold_follows_evidence
// ─────────────────────────────────────────────────────────────────────────────
//
// Every row of a test runs under its own profile of one data root. A CLI row
// runs its verb through the `stellar-agent` binary, as a child process of
// `IsolatedHome::run`. An MCP commit row runs its preparation and commit on
// an in-process `WalletServer` built over the same profile.

/// The MCP classic commit rows, each with its preparation tool.
const MCP_COMMIT_ROWS: [(&str, &str); 4] = [
    ("mcp.pay_commit", "stellar_pay"),
    ("mcp.create_account_commit", "stellar_create_account"),
    ("mcp.claim_commit", "stellar_claim"),
    ("mcp.trustline_commit", "stellar_trustline"),
];

/// The rows of the proven `sizing.caps_refuse` cell: the debit rows.
const CAP_ROWS: [&str; 4] = [
    "mcp.pay_commit",
    "mcp.create_account_commit",
    "cli.pay",
    "cli.accounts_create",
];

/// The rows of the `sizing.reserve_refuses` cell this file proves.
const RESERVE_ROWS: [&str; 1] = ["cli.accounts_create"];

/// The [`ClassicLedger`] with a switchable transaction answer: while
/// `failed` is set every `getTransaction` reports `FAILED` with a bad-sequence
/// result; otherwise, while `confirmed` is false, it reports `NOT_FOUND`, and
/// then the ledger's own `SUCCESS` answers. While `consumed` is set the
/// ledger reads come from `consumed_ledger`, whose signer account is at
/// sequence 101, the sequence every row's first envelope uses.
#[derive(Clone)]
struct OutcomeLedger {
    ledger: ClassicLedger,
    consumed_ledger: ClassicLedger,
    confirmed: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    consumed: Arc<AtomicBool>,
}

impl Respond for OutcomeLedger {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let result = match body["method"].as_str() {
            Some("getTransaction") if self.failed.load(Ordering::SeqCst) => json!({
                "status": "FAILED", "txHash": body["params"]["hash"], "ledger": 1005,
                "createdAt": "1700000005", "latestLedger": 1006, "oldestLedger": 1,
                "resultXdr": bad_sequence_result()
            }),
            Some("getTransaction") if !self.confirmed.load(Ordering::SeqCst) => {
                json!({"status": "NOT_FOUND", "latestLedger": 1006, "oldestLedger": 1})
            }
            Some("getLedgerEntries") if self.consumed.load(Ordering::SeqCst) => {
                return self.consumed_ledger.respond(request);
            }
            _ => return self.ledger.respond(request),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
    }
}

/// One isolated root, its ledger and the rows' profiles.
struct Rows {
    home: IsolatedHome,
    ledger: ClassicLedger,
    confirmed: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    consumed: Arc<AtomicBool>,
    rpc: MockServer,
    signer: Keypair,
    issuer: Keypair,
}

impl Rows {
    async fn new() -> Self {
        use stellar_agent_test_support::xdr_fixtures::account_entry_xdr_with_seq;
        let signer = signer();
        let issuer = Keypair::from_seed(ISSUER_SEED);
        let ledger = ClassicLedger::new(
            &[signer.public(), DESTINATION, issuer.public()],
            &[claimable_entry(signer.public())],
        );
        let consumed_ledger = ClassicLedger::new(
            &[DESTINATION, issuer.public()],
            &[
                claimable_entry(signer.public()),
                (
                    account_ledger_key_xdr(signer.public()),
                    account_entry_xdr_with_seq(signer.public(), ACCOUNT_BALANCE, 0, 101),
                ),
            ],
        );
        let confirmed = Arc::new(AtomicBool::new(true));
        let failed = Arc::new(AtomicBool::new(false));
        let consumed = Arc::new(AtomicBool::new(false));
        let rpc = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(OutcomeLedger {
                ledger: ledger.clone(),
                consumed_ledger,
                confirmed: Arc::clone(&confirmed),
                failed: Arc::clone(&failed),
                consumed: Arc::clone(&consumed),
            })
            .mount(&rpc)
            .await;
        Self {
            home: IsolatedHome::new(),
            ledger,
            confirmed,
            failed,
            consumed,
            rpc,
            signer,
            issuer,
        }
    }

    /// Provisions `profile` with one rule for `row`'s tool whose criteria are
    /// the TOML array `criteria`.
    fn provision(&self, profile: &str, row: &CliProofRow, criteria: &str) {
        self.provision_rules(
            profile,
            &[policy_rule(
                row_tool(row),
                "stellar:testnet",
                criteria,
                "allow",
            )],
        );
    }

    /// Provisions `profile` with `rules`.
    fn provision_rules(&self, profile: &str, rules: &[String]) {
        self.home.provision_v1_profile(
            profile,
            &["--rpc-url", &self.rpc.uri()],
            &self.signer,
            &owner(),
            &policy_document(profile, rules),
        );
    }

    /// Stores `seconds` as the submit timeout of `profile`'s file, which the
    /// binary and an in-process server both read.
    fn set_submit_timeout(&self, profile: &str, seconds: u64) {
        let mut loaded: Profile = self.home.load_profile(profile);
        loaded.submit_timeout_seconds = Some(seconds);
        stellar_agent_core::profile::loader::save_to_dir(
            profile,
            &loaded,
            &self.home.path().join("profiles"),
        )
        .unwrap();
    }

    /// Opens the root's headless keyring in this process.
    fn open_keyring(&self) {
        let store: Arc<keyring_core::CredentialStore> =
            Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
                self.home.keyring_path(),
                stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                    zeroize::Zeroizing::new(self.home.headless_key()),
                )),
            ));
        keyring_core::set_default_store(store);
    }

    /// Deletes the keyring entry at `coordinate`.
    fn delete_entry(&self, coordinate: &stellar_agent_core::profile::schema::KeyringEntryRef) {
        self.open_keyring();
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .delete_credential()
            .unwrap();
    }

    /// Runs `row`'s verb on `profile` through [`IsolatedHome::run`]. With
    /// `secret`, the signer variable holds the signer's secret; without it,
    /// the variable is unset.
    fn run(&self, row: &CliProofRow, profile: &str, secret: bool) -> CliRun {
        let asset = format!("USD:{}", self.issuer.public());
        let signer = self.signer.public();
        let mut args: Vec<&str> = match row.verb {
            "pay" => vec![
                "pay",
                DESTINATION,
                "1 XLM",
                "--source",
                signer,
                "--secret-env",
                SIGNER_ENV,
                "--output",
                "json",
            ],
            "claim" => vec![
                "claim",
                BALANCE_ID_HEX64,
                "--source",
                signer,
                "--secret-env",
                SIGNER_ENV,
                "--output",
                "json",
            ],
            "trustline" => vec!["trustline", "--from", signer, "--asset", &asset],
            "accounts create" => vec![
                "accounts",
                "create",
                NEW_ACCOUNT,
                "--sponsor",
                signer,
                "--secret-env",
                SIGNER_ENV,
                "--starting-balance",
                "1 XLM",
                "--output",
                "json",
            ],
            other => panic!("no invocation for {other}"),
        };
        args.extend_from_slice(&["--profile", profile]);
        let envs: &[(&str, &str)] = if secret {
            &[(SIGNER_ENV, self.signer.secret())]
        } else {
            &[]
        };
        self.home.run(&args, envs)
    }

    /// Withholds the signing key of row `id` on `profile`. A run without
    /// its secret leaves the signer variable of a `--secret-env` verb unset.
    /// An MCP commit and the trustline verb sign with the enrolled keyring
    /// signer, whose seed this deletes.
    fn withhold_signer(&self, id: &str, profile: &str) {
        if id.starts_with("mcp.") || id == "cli.trustline" {
            let loaded = self.home.load_profile(profile);
            self.delete_entry(&loaded.mcp_signer_default);
        }
    }

    /// The pending reservations of `profile`'s window store.
    fn holds(&self, profile: &str) -> Vec<stellar_agent_network::policy_state::SubmissionHold> {
        self.open_keyring();
        stellar_agent_network::policy_state::PersistedWindowStore::for_profile(profile)
            .pending_reservations(&self.home.load_profile(profile))
            .unwrap()
    }

    /// The statuses of `profile`'s window records that carry a submission:
    /// for each submission id, in id order, the status of every record of
    /// it, in bucket order. The store's own decoder is private to its crate,
    /// so this reads the JSON body that follows the store's authentication
    /// tag; the body starts at the first offset whose rest parses as JSON.
    fn hold_statuses(&self, profile: &str) -> Vec<Vec<String>> {
        let path =
            stellar_agent_core::profile::schema::default_policy_window_state_path_for(profile);
        let bytes = std::fs::read(path).unwrap();
        let body: Value = (0..bytes.len())
            .filter(|&at| bytes[at] == b'{')
            .find_map(|at| serde_json::from_slice(&bytes[at..]).ok())
            .unwrap();
        let mut statuses: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for record in body["entries"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|bucket| bucket["records"].as_array().unwrap())
        {
            let Some(id) = record["id"].as_str().filter(|id| !id.is_empty()) else {
                continue;
            };
            statuses
                .entry(id.to_owned())
                .or_default()
                .push(record["status"].as_str().unwrap().to_owned());
        }
        statuses.into_values().collect()
    }

    /// The preparation arguments of the MCP `tool`.
    fn mcp_args(&self, tool: &str) -> Value {
        let source = self.signer.public();
        let chain = "stellar:testnet";
        match tool {
            "stellar_pay" => json!({"chain_id": chain, "source": source,
                "destination": DESTINATION, "amount": "1 XLM", "asset": "native"}),
            "stellar_create_account" => json!({"chain_id": chain, "source": source,
                "destination": NEW_ACCOUNT, "starting_balance": "1 XLM"}),
            "stellar_claim" => json!({"chain_id": chain, "balance_id": BALANCE_ID_HEX64,
                "source_account": source}),
            "stellar_trustline" => json!({"chain_id": chain, "from": source,
                "asset": format!("USD:{}", self.issuer.public())}),
            other => panic!("no MCP row for {other}"),
        }
    }

    /// Prepares `tool` on `server` and commits the prepared envelope through
    /// the tool's commit handler; returns both results.
    async fn mcp_commit(&self, server: &WalletServer, tool: &str) -> (Value, Value) {
        prepare_and_commit(server, tool, self.mcp_args(tool)).await
    }

    /// Reconciles the transaction `hash` of `profile` through the row's
    /// status entry: `stellar_transaction_status` on `server`, or
    /// `tx status` through the binary.
    async fn reconcile(&self, server: Option<&WalletServer>, profile: &str, hash: &str) -> Value {
        match server {
            Some(server) => result_json(
                &server
                    .call_stellar_transaction_status(StellarTransactionStatusArgs {
                        chain_id: "stellar:testnet".to_owned(),
                        tx_hash: Some(hash.to_owned()),
                        business_id: None,
                        retry_recovery: false,
                    })
                    .await
                    .unwrap(),
            ),
            None => {
                self.home
                    .run(&["tx", "status", hash, "--profile", profile], &[])
                    .envelope
            }
        }
    }

    /// The rules of `id`'s profile: an MCP row admits its preparation
    /// without criteria and gives its commit `criteria`; a CLI row gives its
    /// verb's tool `criteria`.
    fn rules_for(id: &str, criteria: &str) -> Vec<String> {
        let chain = "stellar:testnet";
        match MCP_COMMIT_ROWS.iter().find(|(row, _)| *row == id) {
            Some((_, tool)) => vec![
                policy_rule(tool, chain, "[]", "allow"),
                policy_rule(&format!("{tool}_commit"), chain, criteria, "allow"),
            ],
            None => {
                let row = CLI_PROOF_ROWS.iter().find(|row| row.id == id).unwrap();
                vec![policy_rule(row_tool(row), chain, criteria, "allow")]
            }
        }
    }

    /// Runs `id`'s production entry once on `profile`: the MCP preparation
    /// and commit handlers on a server built in this process, or the CLI verb
    /// through the binary, with the signer's secret when `secret` is set. An
    /// MCP row's result is its commit's: a preparation that refuses answers
    /// `{"preparation_refused": <envelope>}`, which no expected answer
    /// matches.
    async fn call_row(&self, id: &str, profile: &str, secret: bool) -> Value {
        match MCP_COMMIT_ROWS.iter().find(|(row, _)| *row == id) {
            Some((_, tool)) => {
                self.open_keyring();
                let server = WalletServer::new(self.home.load_profile(profile)).unwrap();
                let (prepared, committed) = self.mcp_commit(&server, tool).await;
                if prepared["ok"] == true {
                    committed
                } else {
                    json!({ "preparation_refused": prepared })
                }
            }
            None => {
                let row = CLI_PROOF_ROWS.iter().find(|row| row.id == id).unwrap();
                self.run(row, profile, secret).envelope
            }
        }
    }
}

/// The refusal code of row `id` with its signing key withheld, as a run of
/// the row answers it: a `--secret-env` verb meets its unset signer
/// variable, and the trustline verb signs with the enrolled keyring signer,
/// whose seed [`Rows::withhold_signer`] deletes.
fn withheld_signer_code(id: &str) -> &'static str {
    if id == "cli.trustline" {
        "auth.keyring_not_found"
    } else {
        "validation.secret_env_not_set"
    }
}

/// The audit writer of every CLI value verb is acquired before its signing
/// key loads.
///
/// For each row, three profiles run the verb. With the signer present the
/// verb sends once, so the run reaches the end. With the signing key
/// withheld the verb refuses with the signer's own code, which
/// [`withheld_signer_code`] names, and sends nothing, so
/// the signer load follows the policy gate. With the signing key withheld
/// and the audit chain key removed, the verb refuses with the writer's
/// `audit.chain_key_unavailable` refusal instead: the writer acquisition
/// runs, and refuses, before the signer load.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn every_cli_value_verb_acquires_the_audit_writer_before_the_signing_key() {
    let rows = Rows::new().await;
    let mut failures = Vec::new();
    for row in CLI_PROOF_ROWS {
        let stem = row.verb.replace(' ', "-");

        let sent = format!("writer-{stem}-sent");
        rows.provision(&sent, row, "[]");
        let before = rows.ledger.sends();
        let run = rows.run(row, &sent, true);
        if run.code != 0 || rows.ledger.sends() != before + 1 {
            failures.push(format!(
                "{}: signer present: {} stderr={}",
                row.id, run.envelope, run.stderr
            ));
        }

        let signer = format!("writer-{stem}-signer");
        rows.provision(&signer, row, "[]");
        rows.withhold_signer(row.id, &signer);
        let before = rows.ledger.sends();
        let unsigned = rows.run(row, &signer, false);
        let signer_code = unsigned.error_code().to_owned();
        if unsigned.code != 1 || signer_code != withheld_signer_code(row.id) {
            failures.push(format!(
                "{}: signer withheld: {} stderr={}",
                row.id, unsigned.envelope, unsigned.stderr
            ));
        }

        let audit = format!("writer-{stem}-audit");
        rows.provision(&audit, row, "[]");
        rows.withhold_signer(row.id, &audit);
        let loaded = rows.home.load_profile(&audit);
        rows.delete_entry(&loaded.audit_log_hash_chain_key_id);
        let refused = rows.run(row, &audit, false);
        if refused.code != 1 || refused.error_code() != "audit.chain_key_unavailable" {
            failures.push(format!(
                "{}: audit key removed (signer refusal {signer_code}): {} stderr={}",
                row.id, refused.envelope, refused.stderr
            ));
        }
        if rows.ledger.sends() != before {
            failures.push(format!("{}: a refused run sent", row.id));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The submit timeout of each profile of
/// [`every_commit_row_settles_its_hold_only_on_outcome_evidence`]. A few
/// seconds keep each row short, and the margin above one second keeps the
/// build and send of a row clear of the timeout.
const HOLD_SUBMIT_TIMEOUT_SECONDS: u64 = 5;

/// A sent call's hold is never released without evidence, on every commit
/// row: a reported success turns it into an exposure, and a failed or
/// not-found answer keeps it.
///
/// Each row runs on its own profile, whose rate-limit rule makes every call
/// take a hold, through its production entry: the MCP preparation and commit
/// handlers in this process, or the CLI verb through the binary. The ledger
/// answers `NOT_FOUND` until the profile's submit timeout of
/// [`HOLD_SUBMIT_TIMEOUT_SECONDS`] ends the wait, so the send ends as
/// `submission.tx_timeout` with one pending hold.
/// Reconciliations through the row's status entry then meet, in order,
/// `NOT_FOUND` with the source sequence unconsumed, `FAILED`, and
/// `NOT_FOUND` with the source sequence consumed; each keeps every record
/// of the hold pending. After the ledger confirms the transaction with
/// `SUCCESS`, the same reconciliation turns every record into an exposure,
/// which the window counts through its accounting horizon.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn every_commit_row_settles_its_hold_only_on_outcome_evidence() {
    let rows = Rows::new().await;
    let _home = StellarAgentHomeGuard::new(rows.home.path());
    let rule = allow_all("1d");
    let ids = MCP_COMMIT_ROWS
        .iter()
        .map(|(id, _)| *id)
        .chain(CLI_PROOF_ROWS.iter().map(|row| row.id));
    let one = |status: &str| vec![vec![status.to_owned()]];
    let mut failures = Vec::new();
    for id in ids {
        let profile = format!("hold-{}", id.replace(['.', '_'], "-"));
        rows.provision_rules(&profile, std::slice::from_ref(&rule));
        rows.set_submit_timeout(&profile, HOLD_SUBMIT_TIMEOUT_SECONDS);
        rows.open_keyring();
        rows.confirmed.store(false, Ordering::SeqCst);
        let before = rows.ledger.sends();
        let mcp = MCP_COMMIT_ROWS.iter().find(|(row, _)| *row == id);
        let server = mcp.map(|_| WalletServer::new(rows.home.load_profile(&profile)).unwrap());
        let envelope = match (mcp, &server) {
            (Some((_, tool)), Some(server)) => {
                let (prepared, committed) = rows.mcp_commit(server, tool).await;
                json!({"prepared": prepared, "committed": committed["error"]})
            }
            _ => {
                let row = CLI_PROOF_ROWS.iter().find(|row| row.id == id).unwrap();
                json!({"committed": rows.run(row, &profile, true).envelope["error"]})
            }
        };
        let sent = rows.ledger.sends() - before;
        let held = rows.holds(&profile);
        if envelope["committed"]["code"] != "submission.tx_timeout"
            || sent != 1
            || held.len() != 1
            || rows.hold_statuses(&profile) != one("pending")
        {
            failures.push(format!(
                "{id}: unconfirmed send: {sent} sent, {} held: {envelope}",
                held.len()
            ));
            continue;
        }
        let hash = held[0].tx_hash.clone();
        let kept = rows.reconcile(server.as_ref(), &profile, &hash).await;
        let after_absence = rows.hold_statuses(&profile);
        rows.failed.store(true, Ordering::SeqCst);
        let failed = rows.reconcile(server.as_ref(), &profile, &hash).await;
        rows.failed.store(false, Ordering::SeqCst);
        let after_failure = rows.hold_statuses(&profile);
        rows.consumed.store(true, Ordering::SeqCst);
        let consumed = rows.reconcile(server.as_ref(), &profile, &hash).await;
        rows.consumed.store(false, Ordering::SeqCst);
        let after_consumed = rows.hold_statuses(&profile);
        rows.confirmed.store(true, Ordering::SeqCst);
        let confirmed = rows.reconcile(server.as_ref(), &profile, &hash).await;
        let after_success = rows.hold_statuses(&profile);
        if after_absence != one("pending")
            || after_failure != one("pending")
            || after_consumed != one("pending")
            || after_success != one("exposure")
            || rows.holds(&profile).len() != 1
            || rows.ledger.sends() - before != 1
        {
            failures.push(format!(
                "{id}: hold after NOT_FOUND {after_absence:?}, after FAILED \
                 {after_failure:?}, after NOT_FOUND with the sequence consumed \
                 {after_consumed:?}, after SUCCESS {after_success:?}: {kept} then {failed} \
                 then {consumed} then {confirmed}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The total fee of every classic envelope built against [`Rows`]: one
/// operation at the 100 stroops the ledger quotes in every percentile.
const ENVELOPE_FEE: i64 = 100;

/// The protocol reserve of an account without subentries.
const RESERVE: i64 = 10_000_000;

/// The 1 XLM a payment or a sponsored creation of [`Rows`] debits.
const ONE_XLM: i64 = 10_000_000;

/// A per-transaction or per-period cap refuses, before signing, a call of
/// every debit row whose amount alone or with its window's spend exceeds
/// the cap.
///
/// Each row runs through its production entry on two profiles. Under a
/// 1-stroop `per_tx_cap`, the 1 XLM call refuses with
/// `policy.deny.per_tx_cap_exceeded` and sends nothing. Under a 1.5 XLM
/// `per_period_cap`, the first 1 XLM call sends and confirms, and the second
/// refuses with `policy.deny.per_period_cap_exceeded` and sends nothing.
/// Every refused call runs with its signing key withheld, so a refusal that
/// came after the signer load would answer the signer's code instead of the
/// cap's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn every_debit_row_refuses_a_call_over_its_cap_before_signing() {
    let rows = Rows::new().await;
    let _home = StellarAgentHomeGuard::new(rows.home.path());
    let mut failures = Vec::new();
    for id in CAP_ROWS {
        let stem = id.replace(['.', '_'], "-");

        let profile = format!("cap-tx-{stem}");
        let criteria = "[{ kind = \"per_tx_cap\", asset = \"native\", max_stroops = \"1\" }]";
        rows.provision_rules(&profile, &Rows::rules_for(id, criteria));
        rows.withhold_signer(id, &profile);
        let before = rows.ledger.sends();
        let refused = rows.call_row(id, &profile, false).await;
        if refused["error"]["code"] != "policy.deny.per_tx_cap_exceeded"
            || rows.ledger.sends() != before
        {
            failures.push(format!("{id}: per-transaction cap: {refused}"));
        }

        let profile = format!("cap-period-{stem}");
        let criteria = format!(
            "[{{ kind = \"per_period_cap\", window = \"1d\", asset = \"native\", \
             max_stroops = \"{}\" }}]",
            ONE_XLM + ONE_XLM / 2
        );
        rows.provision_rules(&profile, &Rows::rules_for(id, &criteria));
        let before = rows.ledger.sends();
        let first = rows.call_row(id, &profile, true).await;
        let after_first = rows.ledger.sends();
        rows.withhold_signer(id, &profile);
        let second = rows.call_row(id, &profile, false).await;
        if first["ok"] != true
            || after_first != before + 1
            || second["error"]["code"] != "policy.deny.per_period_cap_exceeded"
            || rows.ledger.sends() != after_first
        {
            failures.push(format!("{id}: per-period cap: {first} then {second}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// On the create-account row, the minimum reserve criterion refuses, before
/// signing, a call that would leave the source balance below its reserve
/// plus the margin, and admits the call that leaves exactly that much.
///
/// The boundary margin is the funded balance less the 1 XLM sponsored
/// creation, the envelope fee and the protocol reserve. The row runs through
/// its production entry on a profile at that margin, where the call sends,
/// and on one at the margin plus one stroop, where it refuses with
/// `policy.deny.minimum_reserve_breached` and sends nothing. The refused call
/// runs with its signing key withheld, so a refusal after the signer load
/// would answer the signer's code instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn the_create_account_row_refuses_below_reserve_and_admits_the_boundary() {
    let rows = Rows::new().await;
    let _home = StellarAgentHomeGuard::new(rows.home.path());
    let mut failures = Vec::new();
    let boundary = ACCOUNT_BALANCE - ONE_XLM - ENVELOPE_FEE - RESERVE;
    for id in RESERVE_ROWS {
        let stem = id.replace(['.', '_'], "-");
        for (case, margin, admitted) in
            [("boundary", boundary, true), ("over", boundary + 1, false)]
        {
            let profile = format!("reserve-{case}-{stem}");
            let criteria = format!("[{{ kind = \"minimum_reserve\", margin_stroops = {margin} }}]");
            rows.provision_rules(&profile, &Rows::rules_for(id, &criteria));
            if !admitted {
                rows.withhold_signer(id, &profile);
            }
            let before = rows.ledger.sends();
            let envelope = rows.call_row(id, &profile, admitted).await;
            let sent = rows.ledger.sends() - before;
            let held = if admitted {
                envelope["ok"] == true && sent == 1
            } else {
                envelope["error"]["code"] == "policy.deny.minimum_reserve_breached" && sent == 0
            };
            if !held {
                failures.push(format!(
                    "{id} {case} margin {margin}: {sent} sent: {envelope}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ─────────────────────────────────────────────────────────────────────────────
// sizing.accounting_inputs
// ─────────────────────────────────────────────────────────────────────────────
//
// Off mainnet the three inputs refuse as follows. An unlisted payment beyond
// a budget bound is denied `policy.deny.unlisted_budget_exceeded`, since only
// a mainnet profile escalates the excess to an approval. A debit beyond the
// total budget of the policy's epoch is denied
// `policy.deny.total_budget_exhausted`. The balance floor reads no observed
// account off mainnet, so it refuses every call `account.unread` before any
// send.

/// One accounting input of `sizing.accounting_inputs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccountingInput {
    /// The unlisted-recipient budget of `counterparty_allowlist`.
    Unlisted,
    /// The `total_budget` of the policy's epoch.
    Total,
    /// The `balance_floor`.
    Floor,
}

impl AccountingInput {
    fn name(self) -> &'static str {
        match self {
            Self::Unlisted => "unlisted",
            Self::Total => "total",
            Self::Floor => "floor",
        }
    }

    /// The criteria array of the input for a call that debits `amount`
    /// stroops of `asset`: each bound admits one such call and refuses a
    /// second.
    fn criteria(self, asset: &str, amount: i64) -> String {
        match self {
            Self::Unlisted => format!(
                "[{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [], \
                 unlisted = {{ mode = \"budget\", asset = \"{asset}\", per_tx_stroops = {amount}, \
                 per_period_stroops = {amount}, window = \"1d\" }} }}]"
            ),
            Self::Total => {
                format!(
                    "[{{ kind = \"total_budget\", asset = \"{asset}\", max_stroops = {amount} }}]"
                )
            }
            Self::Floor => "[{ kind = \"balance_floor\", min_stroops = \"1\" }]".to_owned(),
        }
    }

    /// The refusal of a call over the input off mainnet.
    fn refusal(self) -> &'static str {
        match self {
            Self::Unlisted => "policy.deny.unlisted_budget_exceeded",
            Self::Total => "policy.deny.total_budget_exhausted",
            Self::Floor => "account.unread",
        }
    }

    /// The prefix of the window bucket the input counts in.
    fn bucket(self) -> &'static str {
        match self {
            Self::Unlisted => "unlisted:",
            Self::Total => "total:",
            Self::Floor => "",
        }
    }

    /// The inputs that can refuse a call of `row`. A claim and a trustline
    /// debit nothing, so neither the unlisted budget nor the total budget
    /// can be exceeded by them; the floor counts their fee.
    fn of(row: Row) -> &'static [Self] {
        match row {
            Row::McpClaimCommit | Row::McpTrustlineCommit | Row::CliClaim | Row::CliTrustline => {
                &[Self::Floor]
            }
            _ => &[Self::Unlisted, Self::Total, Self::Floor],
        }
    }
}

/// The rows of `sizing.accounting_inputs`.
const ACCOUNTING_ROWS: &[Row] = &[
    Row::McpPayCommit,
    Row::McpCreateAccountCommit,
    Row::McpClaimCommit,
    Row::McpTrustlineCommit,
    Row::McpX402CreatePayment,
    Row::McpX402AuthenticatedPayment,
    Row::CliPay,
    Row::CliClaim,
    Row::CliTrustline,
    Row::CliAccountsCreate,
];

/// The 1 XLM a classic accounting row debits, and the 1 unit of
/// [`X402_ASSET`] an x402 row pays.
const ACCOUNTING_AMOUNT: i64 = 10_000_000;

/// `rules` in a version 2 policy document scoped to `profile`, the version
/// the three accounting criteria require.
fn accounting_document(profile: &str, rules: &[String]) -> String {
    policy_document(profile, rules).replacen("version = 1", "version = 2", 1)
}

/// The number of records of each bucket of the window store at `path`,
/// read as [`Rows::hold_statuses`] reads the store; empty without a file.
fn bucket_rows(path: &std::path::Path) -> std::collections::BTreeMap<String, usize> {
    let Ok(bytes) = std::fs::read(path) else {
        return std::collections::BTreeMap::new();
    };
    let body: Value = (0..bytes.len())
        .filter(|&at| bytes[at] == b'{')
        .find_map(|at| serde_json::from_slice(&bytes[at..]).ok())
        .unwrap();
    body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|bucket| {
            (
                bucket["bucket"].as_str().unwrap().to_owned(),
                bucket["records"].as_array().unwrap().len(),
            )
        })
        .collect()
}

/// The refusal code of a call's envelope, or of the preparation that
/// refused in its place.
fn refusal_code(envelope: &Value) -> &str {
    envelope["error"]["code"]
        .as_str()
        .or_else(|| envelope["preparation_refused"]["error"]["code"].as_str())
        .unwrap_or("")
}

/// Checks the window of a row after its first call was sent and after its
/// second call over `input` refused: every bucket holds the one record of
/// the sent call, the input's own bucket among them, and the refusal added
/// none.
fn one_row_per_bucket(
    input: AccountingInput,
    sent: &std::collections::BTreeMap<String, usize>,
    refused: &std::collections::BTreeMap<String, usize>,
) -> Result<(), String> {
    let counted = sent.keys().any(|bucket| bucket.starts_with(input.bucket()));
    if !counted || sent.values().any(|rows| *rows != 1) || refused != sent {
        Err(format!(
            "window after the sent call {sent:?}, after the refused call {refused:?}"
        ))
    } else {
        Ok(())
    }
}

/// The window store path of `profile` under the data root installed now.
fn window_path(profile: &str) -> std::path::PathBuf {
    stellar_agent_core::profile::schema::default_policy_window_state_path_for(profile)
}

/// Prepares the classic MCP `tool` on `server` with `args` and returns the
/// commit arguments of the prepared envelope, or the refused preparation.
async fn prepare_commit_args(
    server: &WalletServer,
    tool: &str,
    args: Value,
) -> Result<Value, Value> {
    fn from<T: serde::de::DeserializeOwned>(value: &Value) -> T {
        serde_json::from_value(value.clone()).unwrap()
    }
    let prepared = result_json(
        &match tool {
            "stellar_pay" => server.call_stellar_pay(from(&args)).await,
            "stellar_create_account" => server.call_stellar_create_account(from(&args)).await,
            "stellar_claim" => server.call_stellar_claim(from(&args)).await,
            "stellar_trustline" => server.call_stellar_trustline(from(&args)).await,
            other => panic!("{other} has no commit handler"),
        }
        .unwrap(),
    );
    if prepared["ok"] != true {
        return Err(json!({ "preparation_refused": prepared }));
    }
    let mut commit = args;
    for field in ["nonce", "expires_at_unix_ms", "envelope_xdr"] {
        commit[field] = prepared["data"][field].clone();
    }
    Ok(commit)
}

/// Commits the prepared classic MCP `tool` on `server`.
async fn commit_prepared(server: &WalletServer, tool: &str, commit: Value) -> Value {
    fn from<T: serde::de::DeserializeOwned>(value: &Value) -> T {
        serde_json::from_value(value.clone()).unwrap()
    }
    result_json(
        &match tool {
            "stellar_pay" => server.call_stellar_pay_commit(from(&commit)).await,
            "stellar_create_account" => {
                server
                    .call_stellar_create_account_commit(from(&commit))
                    .await
            }
            "stellar_claim" => server.call_stellar_claim_commit(from(&commit)).await,
            _ => server.call_stellar_trustline_commit(from(&commit)).await,
        }
        .unwrap(),
    )
}

/// Runs a classic row of `rows` under `input` on its own profile and
/// returns the failures. An MCP row prepares both calls on one server,
/// commits the first, and commits the second on a server started in its
/// place; a CLI row runs its verb twice, each run a new process. Under the
/// unlisted and total budgets the first call sends and the second refuses
/// with the input's code and sends nothing, with one window record in each
/// bucket. Under the floor both calls refuse `account.unread`, nothing is
/// sent, and the window holds no record.
async fn classic_accounting_case(rows: &Rows, row: Row, input: AccountingInput) -> Vec<String> {
    let id = row.id();
    let profile = format!(
        "accounting-{}-{}",
        input.name(),
        id.replace(['.', '_'], "-")
    );
    let rules = Rows::rules_for(id, &input.criteria("native", ACCOUNTING_AMOUNT));
    rows.home.provision_v1_profile(
        &profile,
        &["--rpc-url", &rows.rpc.uri()],
        &rows.signer,
        &owner(),
        &accounting_document(&profile, &rules),
    );
    rows.open_keyring();
    let mcp = MCP_COMMIT_ROWS
        .iter()
        .find(|(row, _)| *row == id)
        .map(|(_, tool)| *tool);
    let before = rows.ledger.sends();
    let (first, second) = match mcp {
        Some(tool) => {
            let server = WalletServer::new(rows.home.load_profile(&profile)).unwrap();
            let first = prepare_commit_args(&server, tool, rows.mcp_args(tool)).await;
            let second = prepare_commit_args(&server, tool, rows.mcp_args(tool)).await;
            match (first, second) {
                (Ok(first), Ok(second)) => {
                    let first = commit_prepared(&server, tool, first).await;
                    drop(server);
                    let restarted = WalletServer::new(rows.home.load_profile(&profile)).unwrap();
                    let sent = bucket_rows(&window_path(&profile));
                    let second = commit_prepared(&restarted, tool, second).await;
                    return finish(rows, id, input, before, &first, &second, &sent, &profile);
                }
                (first, second) => (
                    first.unwrap_or_else(|refused| refused),
                    second.unwrap_or_else(|refused| refused),
                ),
            }
        }
        None => {
            let row = CLI_PROOF_ROWS.iter().find(|row| row.id == id).unwrap();
            let first = rows.run(row, &profile, true).envelope;
            let sent = bucket_rows(&window_path(&profile));
            let second = rows.run(row, &profile, true).envelope;
            return finish(rows, id, input, before, &first, &second, &sent, &profile);
        }
    };
    // Both preparations refused: only the floor refuses before a send.
    finish(
        rows,
        id,
        input,
        before,
        &first,
        &second,
        &Default::default(),
        &profile,
    )
}

/// Checks the two calls of a classic accounting case.
#[allow(clippy::too_many_arguments, reason = "the two calls and their facts")]
fn finish(
    rows: &Rows,
    id: &str,
    input: AccountingInput,
    before: usize,
    first: &Value,
    second: &Value,
    sent: &std::collections::BTreeMap<String, usize>,
    profile: &str,
) -> Vec<String> {
    let mut failures = Vec::new();
    let sends = rows.ledger.sends() - before;
    let refused = bucket_rows(&window_path(profile));
    if input == AccountingInput::Floor {
        if refusal_code(first) != "account.unread"
            || refusal_code(second) != "account.unread"
            || sends != 0
            || !refused.values().all(|rows| *rows == 0)
        {
            failures.push(format!(
                "{id} floor: {sends} sent, window {refused:?}: {first} then {second}"
            ));
        }
        return failures;
    }
    if first["ok"] != true || sends != 1 {
        failures.push(format!(
            "{id} {}: first call, {sends} sent: {first}",
            input.name()
        ));
    }
    if refusal_code(second) != input.refusal() {
        failures.push(format!(
            "{id} {}: second call after the restart: {second}",
            input.name()
        ));
    }
    if let Err(failure) = one_row_per_bucket(input, sent, &refused) {
        failures.push(format!("{id} {}: {failure}", input.name()));
    }
    failures
}

/// Runs an x402 row under `input` in its own home and returns the
/// failures. The first payment is authorized on one server and the second
/// is called on a server started in its place. Under the unlisted and total
/// budgets the first is paid and the second refuses with the input's code,
/// with one window record in each bucket. Under the floor both refuse
/// `account.unread` and the window holds no record.
async fn x402_accounting_case(row: Row, input: AccountingInput) -> Vec<String> {
    let id = row.id();
    let endpoint = X402Endpoint::new(signer().public(), false);
    let rpc = endpoint.serve().await;
    let tool = match row {
        Row::McpX402CreatePayment => "stellar_x402_create_payment",
        _ => "stellar_x402_authenticated_payment",
    };
    let name = row.profile(&format!("accounting-{}", input.name()));
    let rules = [policy_rule(
        tool,
        "stellar:testnet",
        &input.criteria(X402_ASSET, ACCOUNTING_AMOUNT),
        "allow",
    )];
    let home = IsolatedHome::new();
    home.provision_v1_profile(
        &name,
        &["--rpc-url", &rpc.uri()],
        &signer(),
        &owner(),
        &accounting_document(&name, &rules),
    );
    let home = RowHome { home, name };
    let _in_process = home.enter();
    let first = mcp_x402(&home.server(), row).await;
    let sent = bucket_rows(&window_path(&home.name));
    let second = mcp_x402(&home.server(), row).await;
    let refused = bucket_rows(&window_path(&home.name));
    let mut failures = Vec::new();
    if input == AccountingInput::Floor {
        if refusal_code(&first) != "account.unread"
            || refusal_code(&second) != "account.unread"
            || !refused.values().all(|rows| *rows == 0)
        {
            failures.push(format!(
                "{id} floor: window {refused:?}: {first} then {second}"
            ));
        }
        return failures;
    }
    if first["ok"] != true {
        failures.push(format!("{id} {}: first call: {first}", input.name()));
    }
    if refusal_code(&second) != input.refusal() {
        failures.push(format!(
            "{id} {}: second call after the restart: {second}",
            input.name()
        ));
    }
    if let Err(failure) = one_row_per_bucket(input, &sent, &refused) {
        failures.push(format!("{id} {}: {failure}", input.name()));
    }
    failures
}

/// The unlisted counter, the budget epoch and the balance floor size every
/// value row's call from persisted accounting, on testnet.
///
/// Each row runs under each input that can refuse it, on its own profile
/// whose signed version 2 policy holds that input alone. After one call is
/// sent and the wallet restarts, a second call over the unlisted budget or
/// the total budget refuses with that input's code and sends nothing, and
/// the window keeps the one record of the sent call in each bucket. The
/// floor reads no observed account off mainnet, so under it every call
/// refuses `account.unread` before any send and the window holds no record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn every_row_sizes_its_second_call_from_persisted_accounting() {
    let mut failures = Vec::new();
    for &row in ACCOUNTING_ROWS.iter().filter(|row| !row.is_classic()) {
        for &input in AccountingInput::of(row) {
            failures.extend(x402_accounting_case(row, input).await);
        }
    }
    let rows = Rows::new().await;
    let _home = StellarAgentHomeGuard::new(rows.home.path());
    for &row in ACCOUNTING_ROWS.iter().filter(|row| row.is_classic()) {
        for &input in AccountingInput::of(row) {
            failures.extend(classic_accounting_case(&rows, row, input).await);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// For every test of this file that a matrix cell names, the rows of all the
/// cells that name it are exactly the rows of the test's table, and the table
/// lists exactly the tests of this file that a cell names.
#[test]
fn the_row_tables_match_their_matrix_cells() {
    const MODULE: &str = "proof_row_claims::";
    let matrix: toml::Table = toml::from_str(include_str!(
        "../../../../.github/scripts/proof-matrix.toml"
    ))
    .unwrap();
    let sorted = |mut rows: Vec<String>| {
        rows.sort();
        rows
    };
    let ids = |rows: &[Row]| sorted(rows.iter().map(|row| row.id().to_owned()).collect());
    let cli_ids: Vec<String> = CLI_PROOF_ROWS.iter().map(|row| row.id.to_owned()).collect();
    let commit_ids = sorted(
        MCP_COMMIT_ROWS
            .iter()
            .map(|(id, _)| (*id).to_owned())
            .chain(cli_ids.iter().cloned())
            .collect(),
    );
    let owned = |rows: &[&str]| sorted(rows.iter().map(|row| (*row).to_owned()).collect());
    let tables: Vec<(&str, Vec<String>)> = vec![
        (
            "every_terminal_outcome_writes_one_audit_row",
            ids(OUTCOME_ROWS),
        ),
        (
            "every_sent_row_reconciles_its_receipt_and_hold",
            ids(RECONCILE_ROWS),
        ),
        (
            "every_mcp_row_reports_its_inbox_approval_without_consuming_it",
            ids(APPROVAL_ROWS),
        ),
        (
            "every_mcp_row_queues_its_approval_row_until_the_server_exit_drain",
            ids(APPROVAL_ROWS),
        ),
        (
            "every_commit_row_settles_its_hold_only_on_outcome_evidence",
            commit_ids,
        ),
        (
            "every_debit_row_refuses_a_call_over_its_cap_before_signing",
            owned(&CAP_ROWS),
        ),
        (
            "the_create_account_row_refuses_below_reserve_and_admits_the_boundary",
            owned(&RESERVE_ROWS),
        ),
        (
            "every_cli_value_verb_acquires_the_audit_writer_before_the_signing_key",
            sorted(cli_ids.clone()),
        ),
    ];
    let mut named: std::collections::BTreeMap<&str, Vec<String>> =
        std::collections::BTreeMap::new();
    for cell in matrix["cell"].as_array().unwrap() {
        let cell = cell.as_table().unwrap();
        let Some(tests) = cell.get("tests").and_then(toml::Value::as_array) else {
            continue;
        };
        for test in tests {
            let Some(test) = test["name"].as_str().unwrap().strip_prefix(MODULE) else {
                continue;
            };
            named.entry(test).or_default().extend(
                cell["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| row.as_str().unwrap().to_owned()),
            );
        }
    }
    let named: std::collections::BTreeMap<&str, Vec<String>> = named
        .into_iter()
        .map(|(test, rows)| (test, sorted(rows)))
        .collect();
    let tables: std::collections::BTreeMap<&str, Vec<String>> = tables.into_iter().collect();
    assert_eq!(named, tables);
}
