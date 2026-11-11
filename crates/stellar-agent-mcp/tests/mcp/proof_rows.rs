//! The MCP rows of the release proof matrix and the fixtures that reach them.
//!
//! [`MCP_PROOF_ROWS`] names every mainnet-admitted value tool with its phase,
//! and [`invocation`] gives each row one testnet call whose arguments pass
//! parsing. A commit row carries a well-formed envelope and a nonce. The rows
//! run through a protocol client over a duplex stream, so a call takes the
//! path a client's call takes, against a mock endpoint that answers the
//! network, readiness, fee and ledger reads of every row.
//!
//! The guard below proves each row reaches the policy gate offline; tests of
//! a matrix claim build on the same rows, invocations and environment.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use rmcp::ServiceExt as _;
use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_mcp::server::WalletServer;
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_seq, account_ledger_key_xdr,
};
use stellar_xdr::{
    AccountId, AlphaNum4, AssetCode4, ChangeTrustAsset, ChangeTrustOp, ClaimClaimableBalanceOp,
    ClaimableBalanceId, CreateAccountOp, Hash, LedgerKey, LedgerKeyClaimableBalance, Limits, Memo,
    MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions, PublicKey, SequenceNumber,
    Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM,
    WriteXdr,
};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use crate::common::policy_mock::{MockPolicyEngine, testnet_server_with_engine_and_rpc};

/// The phase of a value tool: the simulate step, the commit step, or a
/// single call that signs in one step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Prepare,
    Commit,
    Single,
}

impl Phase {
    /// The phase name the matrix uses.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Commit => "commit",
            Self::Single => "single",
        }
    }
}

/// One MCP row of the proof matrix.
#[derive(Clone, Copy, Debug)]
pub(crate) struct McpProofRow {
    /// The row id the matrix names.
    pub(crate) id: &'static str,
    /// The registered tool name.
    pub(crate) tool: &'static str,
    /// The tool's phase.
    pub(crate) phase: Phase,
}

/// Every mainnet-admitted value tool on MCP.
pub(crate) const MCP_PROOF_ROWS: &[McpProofRow] = &[
    McpProofRow {
        id: "mcp.pay",
        tool: "stellar_pay",
        phase: Phase::Prepare,
    },
    McpProofRow {
        id: "mcp.pay_commit",
        tool: "stellar_pay_commit",
        phase: Phase::Commit,
    },
    McpProofRow {
        id: "mcp.create_account",
        tool: "stellar_create_account",
        phase: Phase::Prepare,
    },
    McpProofRow {
        id: "mcp.create_account_commit",
        tool: "stellar_create_account_commit",
        phase: Phase::Commit,
    },
    McpProofRow {
        id: "mcp.claim",
        tool: "stellar_claim",
        phase: Phase::Prepare,
    },
    McpProofRow {
        id: "mcp.claim_commit",
        tool: "stellar_claim_commit",
        phase: Phase::Commit,
    },
    McpProofRow {
        id: "mcp.trustline",
        tool: "stellar_trustline",
        phase: Phase::Prepare,
    },
    McpProofRow {
        id: "mcp.trustline_commit",
        tool: "stellar_trustline_commit",
        phase: Phase::Commit,
    },
    McpProofRow {
        id: "mcp.x402_create_payment",
        tool: "stellar_x402_create_payment",
        phase: Phase::Single,
    },
    McpProofRow {
        id: "mcp.x402_authenticated_payment",
        tool: "stellar_x402_authenticated_payment",
        phase: Phase::Single,
    },
];

/// The source account of every row. The mock endpoint holds it funded.
pub(crate) const SOURCE_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

/// The payment destination. The mock endpoint holds it funded.
pub(crate) const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// The pinned testnet USDC issuer a trustline row trusts. The mock endpoint
/// holds it funded.
const USDC_TESTNET_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

/// The account a create-account row creates. The mock endpoint does not
/// hold it.
pub(crate) const NEW_ACCOUNT_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

/// The hash of the claimable balance a claim row claims.
const BALANCE_HASH: [u8; 32] = [0xab; 32];

/// The sequence number of the funded accounts; commit envelopes use the next.
const ACCOUNT_SEQ: i64 = 100;

/// The balance of the funded accounts: 10,000 XLM.
const ACCOUNT_BALANCE_STROOPS: i64 = 100_000_000_000;

/// The amount of the claimable balance: 5 XLM.
const CLAIM_AMOUNT_STROOPS: i64 = 50_000_000;

/// The testnet arguments of `row`'s one invocation.
///
/// # Panics
///
/// Panics if `row` names a tool without an invocation.
pub(crate) fn invocation(row: &McpProofRow) -> Value {
    let chain_id = "stellar:testnet";
    match row.tool {
        "stellar_pay" => json!({
            "chain_id": chain_id,
            "source": SOURCE_G,
            "destination": DEST_G,
            "amount": "10 XLM",
            "asset": "native",
        }),
        "stellar_pay_commit" => json!({
            "chain_id": chain_id,
            "source": SOURCE_G,
            "destination": DEST_G,
            "amount": "10 XLM",
            "asset": "native",
            "nonce": "dGVzdA",
            "expires_at_unix_ms": u64::MAX,
            "envelope_xdr": envelope(OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(g_bytes(DEST_G))),
                asset: stellar_xdr::Asset::Native,
                amount: 100_000_000,
            })),
        }),
        "stellar_create_account" => json!({
            "chain_id": chain_id,
            "source": SOURCE_G,
            "destination": NEW_ACCOUNT_G,
            "starting_balance": "1 XLM",
        }),
        "stellar_create_account_commit" => json!({
            "chain_id": chain_id,
            "source": SOURCE_G,
            "destination": NEW_ACCOUNT_G,
            "starting_balance": "1 XLM",
            "nonce": "dGVzdA",
            "expires_at_unix_ms": u64::MAX,
            "envelope_xdr": envelope(OperationBody::CreateAccount(CreateAccountOp {
                destination: account_id(NEW_ACCOUNT_G),
                starting_balance: 10_000_000,
            })),
        }),
        "stellar_claim" => json!({
            "chain_id": chain_id,
            "balance_id": stellar_agent_core::hex::encode(&BALANCE_HASH),
            "source_account": SOURCE_G,
        }),
        "stellar_claim_commit" => json!({
            "chain_id": chain_id,
            "balance_id": stellar_agent_core::hex::encode(&BALANCE_HASH),
            "source_account": SOURCE_G,
            "nonce": "dGVzdA",
            "expires_at_unix_ms": u64::MAX,
            "envelope_xdr": envelope(OperationBody::ClaimClaimableBalance(
                ClaimClaimableBalanceOp {
                    balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(BALANCE_HASH)),
                },
            )),
        }),
        "stellar_trustline" => json!({
            "chain_id": chain_id,
            "from": SOURCE_G,
            "asset": "USDC",
        }),
        "stellar_trustline_commit" => json!({
            "chain_id": chain_id,
            "from": SOURCE_G,
            "nonce": "dGVzdA",
            "expires_at_unix_ms": u64::MAX,
            "envelope_xdr": envelope(OperationBody::ChangeTrust(ChangeTrustOp {
                line: ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(*b"USDC"),
                    issuer: account_id(USDC_TESTNET_ISSUER),
                }),
                limit: i64::MAX,
            })),
        }),
        "stellar_x402_create_payment" => json!({
            "chain_id": chain_id,
            "payment_required": x402_requirements(),
        }),
        "stellar_x402_authenticated_payment" => json!({
            "chain_id": chain_id,
            "home_domain": "example.com",
            "payment_required": x402_requirements(),
        }),
        other => panic!("no invocation for {other}"),
    }
}

/// A testnet x402 payment requirement for a SAC transfer.
fn x402_requirements() -> String {
    json!({
        "scheme": "exact",
        "network": "stellar:testnet",
        "asset": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
        "amount": "1000000",
        "payTo": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        "maxTimeoutSeconds": 300,
        "extra": { "areFeesSponsored": true }
    })
    .to_string()
}

fn g_bytes(g: &str) -> [u8; 32] {
    stellar_strkey::ed25519::PublicKey::from_string(g)
        .unwrap()
        .0
}

fn account_id(g: &str) -> AccountId {
    AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(g_bytes(g))))
}

/// A single-operation V1 envelope from [`SOURCE_G`] at the sequence after
/// [`ACCOUNT_SEQ`], base64 encoded.
fn envelope(body: OperationBody) -> String {
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(g_bytes(SOURCE_G))),
        fee: 100,
        seq_num: SequenceNumber(ACCOUNT_SEQ + 1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body,
        }]
        .try_into()
        .unwrap(),
        ext: TransactionExt::V0,
    };
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// The ledger entry XDR of the claimable balance a claim row claims: native
/// XLM, claimable by [`SOURCE_G`] without condition.
fn claimable_balance_entry_xdr() -> String {
    use stellar_xdr::{
        ClaimPredicate, ClaimableBalanceEntry, ClaimableBalanceEntryExt, Claimant, ClaimantV0,
        LedgerEntryData,
    };
    LedgerEntryData::ClaimableBalance(ClaimableBalanceEntry {
        balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(BALANCE_HASH)),
        claimants: VecM::try_from(vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: account_id(SOURCE_G),
            predicate: ClaimPredicate::Unconditional,
        })])
        .unwrap(),
        asset: stellar_xdr::Asset::Native,
        amount: CLAIM_AMOUNT_STROOPS,
        ext: ClaimableBalanceEntryExt::V0,
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

fn claimable_balance_key_xdr() -> String {
    LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
        balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(BALANCE_HASH)),
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// One fee distribution of a `getFeeStats` answer whose every percentile is
/// the base fee.
fn fee_distribution() -> Value {
    let mut distribution = serde_json::Map::new();
    for field in [
        "max", "min", "mode", "p10", "p20", "p30", "p40", "p50", "p60", "p70", "p80", "p90", "p95",
        "p99",
    ] {
        distribution.insert(field.to_owned(), json!("100"));
    }
    distribution.insert("transactionCount".to_owned(), json!("12"));
    distribution.insert("ledgerCount".to_owned(), json!("5"));
    Value::Object(distribution)
}

/// Answers the reads every row makes: the testnet identity, the fee
/// statistics, and the ledger entries of the funded accounts and the
/// claimable balance. A key the endpoint does not hold is absent from the
/// answer, and every other read gets its operational answer.
struct ProofEndpoint {
    entries: Vec<(String, String)>,
}

impl ProofEndpoint {
    fn new() -> Self {
        Self {
            entries: vec![
                (
                    account_ledger_key_xdr(SOURCE_G),
                    account_entry_xdr_with_seq(SOURCE_G, ACCOUNT_BALANCE_STROOPS, 0, ACCOUNT_SEQ),
                ),
                (
                    account_ledger_key_xdr(DEST_G),
                    account_entry_xdr_with_seq(DEST_G, ACCOUNT_BALANCE_STROOPS, 0, ACCOUNT_SEQ),
                ),
                (
                    account_ledger_key_xdr(USDC_TESTNET_ISSUER),
                    account_entry_xdr_with_seq(
                        USDC_TESTNET_ISSUER,
                        ACCOUNT_BALANCE_STROOPS,
                        0,
                        ACCOUNT_SEQ,
                    ),
                ),
                (claimable_balance_key_xdr(), claimable_balance_entry_xdr()),
            ],
        }
    }
}

impl Respond for ProofEndpoint {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or_else(|_| json!({}));
        let id = body.get("id").cloned().unwrap_or_else(|| json!(1));
        let method = body["method"].as_str().unwrap_or_default();
        let result = match method {
            "getNetwork" => crate::common::EndpointNetwork::testnet().result(),
            "getFeeStats" => json!({
                "sorobanInclusionFee": fee_distribution(),
                "inclusionFee": fee_distribution(),
                "latestLedger": crate::common::OPERATIONAL_LATEST_LEDGER,
            }),
            "getLedgerEntries" => {
                let requested: Vec<&str> = body["params"]["keys"]
                    .as_array()
                    .map(|keys| keys.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let entries: Vec<Value> = self
                    .entries
                    .iter()
                    .filter(|(key, _)| requested.contains(&key.as_str()))
                    .map(|(key, xdr)| {
                        json!({
                            "key": key,
                            "xdr": xdr,
                            "lastModifiedLedgerSeq": crate::common::OPERATIONAL_LATEST_LEDGER - 1,
                        })
                    })
                    .collect();
                json!({
                    "entries": entries,
                    "latestLedger": crate::common::OPERATIONAL_LATEST_LEDGER,
                })
            }
            other => crate::common::operational_result(other).unwrap_or_else(|| json!({})),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
            .insert_header("content-type", "application/json")
    }
}

/// The testnet environment a row runs in: an isolated data root and the mock
/// endpoint. Dropping it restores the data root.
pub(crate) struct ProofEnvironment {
    _data_root: crate::common::IsolatedDataRoot,
    endpoint: MockServer,
}

impl ProofEnvironment {
    /// Starts the mock endpoint under a fresh data root.
    pub(crate) async fn start() -> Self {
        let data_root = crate::common::isolated_data_root();
        let endpoint = MockServer::start().await;
        crate::common::mount_ready_endpoint(&endpoint).await;
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(ProofEndpoint::new())
            .mount(&endpoint)
            .await;
        Self {
            _data_root: data_root,
            endpoint,
        }
    }

    /// The URL of the mock endpoint.
    pub(crate) fn rpc_url(&self) -> String {
        self.endpoint.uri()
    }
}

/// A JSON-RPC client over the client half of a duplex stream.
pub(crate) struct ProofClient {
    write: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    lines: tokio::io::Lines<BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
    next_id: u64,
}

impl ProofClient {
    /// Serves `server` on a fresh duplex stream and completes the MCP
    /// initialization handshake.
    pub(crate) async fn connect(server: WalletServer) -> Self {
        let (client_side, server_side) = tokio::io::duplex(1 << 20);
        let (server_read, server_write) = tokio::io::split(server_side);
        tokio::spawn(async move {
            let service = server
                .serve((server_read, server_write))
                .await
                .expect("server initializes");
            let _ = service.waiting().await;
        });
        let (read, write) = tokio::io::split(client_side);
        let mut client = Self {
            write,
            lines: BufReader::new(read).lines(),
            next_id: 1,
        };
        let init = client
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": { "name": "proof-rows", "version": "0" },
                }),
            )
            .await;
        assert!(init.get("result").is_some(), "initialize failed: {init}");
        client
            .send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
            .await;
        client
    }

    async fn send(&mut self, message: &Value) {
        let mut line = serde_json::to_vec(message).unwrap();
        line.push(b'\n');
        self.write.write_all(&line).await.unwrap();
        self.write.flush().await.unwrap();
    }

    /// Sends one request and returns its response, skipping notifications.
    pub(crate) async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
            .await;
        loop {
            let line =
                tokio::time::timeout(std::time::Duration::from_secs(30), self.lines.next_line())
                    .await
                    .expect("the server answers within the timeout")
                    .unwrap()
                    .expect("the server keeps the stream open");
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["id"] == json!(id) {
                return message;
            }
        }
    }

    /// Calls `row`'s tool with its invocation and returns the JSON-RPC
    /// response.
    pub(crate) async fn call_row(&mut self, row: &McpProofRow) -> Value {
        self.request(
            "tools/call",
            json!({ "name": row.tool, "arguments": invocation(row) }),
        )
        .await
    }
}

/// The business-envelope error code of a `tools/call` response, or a
/// description of the response when it is not a business error.
pub(crate) fn business_code(response: &Value) -> Result<String, String> {
    let result = response
        .get("result")
        .ok_or_else(|| format!("no result: {response}"))?;
    if result["isError"] != json!(true) {
        return Err(format!("not an error: {response}"));
    }
    let text = result["content"][0]["text"]
        .as_str()
        .ok_or_else(|| format!("no text content: {response}"))?;
    let envelope: Value = serde_json::from_str(text).map_err(|error| format!("{error}: {text}"))?;
    envelope["error"]["code"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("no error code: {text}"))
}

/// Each row's invocation reaches the policy gate: under an engine that
/// matches no rule, every row answers `policy.deny.no_matching_rule`.
#[tokio::test]
#[serial]
async fn every_mcp_proof_row_reaches_the_policy_gate() {
    let mut failures = Vec::new();
    for row in MCP_PROOF_ROWS {
        let environment = ProofEnvironment::start().await;
        let server = testnet_server_with_engine_and_rpc(
            MockPolicyEngine::deny_no_matching_rule(),
            &environment.rpc_url(),
        );
        let mut client = ProofClient::connect(server).await;
        let response = client.call_row(row).await;
        match business_code(&response) {
            Ok(code) if code == "policy.deny.no_matching_rule" => {}
            Ok(code) => failures.push(format!("{} ({}): {code}", row.id, row.tool)),
            Err(description) => failures.push(format!("{} ({}): {description}", row.id, row.tool)),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// In a build without mainnet writes, each single-call row refuses a mainnet
/// profile with `network.mainnet_write_forbidden` before any request: the
/// answer carries no payment signature and the endpoint receives nothing.
/// No keyring is installed, so a call that reached a key would answer with a
/// keyring failure instead.
#[cfg(not(feature = "mainnet-write"))]
#[tokio::test]
#[serial]
async fn every_single_call_row_refuses_mainnet_before_any_request() {
    use stellar_agent_core::profile::schema::Profile;

    let mut failures = Vec::new();
    for row in MCP_PROOF_ROWS
        .iter()
        .filter(|row| row.phase == Phase::Single)
    {
        let environment = ProofEnvironment::start().await;
        let profile =
            Profile::builder_mainnet(environment.rpc_url(), "svc", "acct", "n-svc", "n-acct")
                .with_noop_engine()
                .build();
        let server = WalletServer::new(profile).expect("the mainnet server starts");
        let mut client = ProofClient::connect(server).await;
        let mut arguments = invocation(row);
        arguments["chain_id"] = json!("stellar:mainnet");
        let response = client
            .request(
                "tools/call",
                json!({ "name": row.tool, "arguments": arguments }),
            )
            .await;
        let requests = environment
            .endpoint
            .received_requests()
            .await
            .expect("the mock endpoint records requests")
            .len();
        let code = business_code(&response);
        if code.as_deref() != Ok("network.mainnet_write_forbidden")
            || response.to_string().contains("paymentSignature")
            || requests != 0
        {
            failures.push(format!(
                "{} ({}): {code:?}, {requests} request(s): {response}",
                row.id, row.tool
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The release proof matrix, read from beside its checker.
const MATRIX: &str = include_str!("../../../../.github/scripts/proof-matrix.toml");

/// Every entry of the matrix table `table` whose surface is `mcp`.
fn matrix_mcp_entries<'a>(
    document: &'a toml_edit::DocumentMut,
    table: &str,
) -> Vec<&'a toml_edit::Table> {
    document[table]
        .as_array_of_tables()
        .unwrap_or_else(|| panic!("the matrix holds [[{table}]] entries"))
        .iter()
        .filter(|entry| entry["surface"].as_str() == Some("mcp"))
        .collect()
}

fn text(entry: &toml_edit::Table, field: &str) -> String {
    entry[field]
        .as_str()
        .unwrap_or_else(|| panic!("matrix entry without {field}: {entry}"))
        .to_owned()
}

/// [`MCP_PROOF_ROWS`] equals the MCP rows of the matrix, and the rows and the
/// excluded MCP entries together are the registered value-moving tools,
/// disjoint, each name registered.
#[test]
fn mcp_proof_rows_match_the_matrix_and_the_value_registry() {
    use std::collections::BTreeSet;
    use stellar_agent_core::policy::{McpToolRegistration, ToolValueKind};

    let document: toml_edit::DocumentMut = MATRIX.parse().expect("the matrix parses");
    let matrix_rows: BTreeSet<(String, String, String)> = matrix_mcp_entries(&document, "row")
        .into_iter()
        .map(|row| (text(row, "id"), text(row, "name"), text(row, "phase")))
        .collect();
    let table_rows: BTreeSet<(String, String, String)> = MCP_PROOF_ROWS
        .iter()
        .map(|row| {
            (
                row.id.to_owned(),
                row.tool.to_owned(),
                row.phase.as_str().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        table_rows.len(),
        MCP_PROOF_ROWS.len(),
        "the table names a row twice"
    );
    assert_eq!(
        table_rows, matrix_rows,
        "the table and the matrix rows differ"
    );

    let row_tools: BTreeSet<String> = MCP_PROOF_ROWS
        .iter()
        .map(|row| row.tool.to_owned())
        .collect();
    let excluded: BTreeSet<String> = matrix_mcp_entries(&document, "excluded")
        .into_iter()
        .map(|entry| text(entry, "name"))
        .collect();
    let both: Vec<&String> = row_tools.intersection(&excluded).collect();
    assert!(both.is_empty(), "rows that are also excluded: {both:?}");

    let registered: BTreeSet<&str> = inventory::iter::<McpToolRegistration>
        .into_iter()
        .map(|registration| registration.name)
        .collect();
    let named: BTreeSet<String> = row_tools.union(&excluded).cloned().collect();
    let unregistered: Vec<&String> = named
        .iter()
        .filter(|name| !registered.contains(name.as_str()))
        .collect();
    assert!(
        unregistered.is_empty(),
        "matrix names that no tool registers: {unregistered:?}"
    );
    let moves_value: BTreeSet<String> = inventory::iter::<McpToolRegistration>
        .into_iter()
        .filter(|registration| registration.value_kind == ToolValueKind::MovesValue)
        .map(|registration| registration.name.to_owned())
        .collect();
    assert_eq!(
        named, moves_value,
        "the rows and the excluded entries differ from the value-moving tools"
    );
}
