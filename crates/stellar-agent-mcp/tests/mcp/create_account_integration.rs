//! Integration tests for the `stellar_create_account` and
//! `stellar_create_account_commit` MCP tools.
//!
//! These tests exercise the handlers directly via `WalletServer`, bypassing
//! the stdio transport.  A wiremock server provides deterministic RPC responses
//! without a live Stellar network connection.
//!
//! # Test coverage
//!
//! ## Simulate step (`stellar_create_account`)
//!
//! 1. Happy path — wiremock RPC returns a funded source account; response
//!    contains `envelope_xdr`, `nonce`, `expires_at_unix_ms`, `simulation`.
//! 2. Invalid source G-strkey — returns `invalid_params`.
//! 3. Invalid destination G-strkey — returns `invalid_params`.
//! 4. `chain_id` mismatch: returns `invalid_params` once the endpoint check
//!    and the source read pass.
//! 5. An endpoint serving another network, or mainnet, refuses the simulate
//!    before any read, as an `is_error` envelope.
//!
//! ## Commit step (`stellar_create_account_commit`)
//!
//! 6. Mainnet profile rejects commit with `network.mainnet_write_forbidden`.
//! 7. Replayed nonce returns `nonce.replayed`.
//! 8. Expired nonce returns `nonce.expired`.
//! 9. Envelope divergence returns `simulation.divergence`.
//! 10. HMAC mismatch (one corrupted byte) returns `nonce.expired`.
//!
//! # Keyring isolation
//!
//! Tests that exercise the keyring path call `keyring_mock::install` before
//! constructing `WalletServer`.  The mock store is process-global so tests that
//! touch the keyring are serialised via `#[serial]`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use std::sync::Arc;

use crate::common::policy_mock::{MockPolicyEngine, testnet_server_with_engine_and_rpc};
use async_trait::async_trait;
use helpers::AnyTool;
use serial_test::serial;
use stellar_agent_core::policy::DenyReason;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{
    StellarCreateAccountArgs, StellarCreateAccountCommitArgs, WalletServer,
};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_balance, account_entry_xdr_with_seq, account_ledger_key_xdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A valid testnet G-strkey for the source account (funded).
const SOURCE_G: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

/// A valid testnet G-strkey for the destination (new) account.
/// Uses `stellar-agent-test-support::testnet_strkeys` for a deterministic valid strkey.
/// Using a second well-known strkey verified valid by stellar-strkey.
const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// Testnet profile with `engine = Noop` and the given RPC URL for test isolation.
///
/// Explicitly sets `Noop` so `WalletServer::new` succeeds without a signed
/// policy file on disk: `PolicyEngineKind::default()` is `V1`, which requires
/// a signed policy file and a keyring owner-key entry.
///
/// Seeds the audit chain-root key via [`common::install_test_audit_key`]: the
/// audit pre-flight runs BEFORE nonce-commit consumption on every `*_commit`
/// tool, so any test reaching a commit-phase gate needs this seeded to reach
/// the gate under test rather than refusing `audit.chain_key_unavailable`
/// first. Tests that specifically exercise the unminted-audit-key refusal use
/// a distinct profile/coordinate instead of this helper.
fn testnet_profile_with_rpc(rpc_url: &str) -> Profile {
    let mut p = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    p.rpc_url = rpc_url.to_owned();
    crate::common::install_test_audit_key(&mut p);
    p
}

/// Builds a mainnet profile with `engine = Noop` and a caller-supplied
/// `rpc_url`.
///
/// Because `PolicyEngineKind::default()` is `V1`, `Noop` is set explicitly so
/// `WalletServer::new` succeeds without a signed policy file on disk. The
/// mainnet simulate test and Property A point `rpc_url` at a local wiremock
/// server and assert which requests it receives.
fn mainnet_profile_with_rpc(rpc_url: &str) -> Profile {
    Profile::builder_mainnet(rpc_url, "svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build()
}

struct CreateAccountFeeRpcResponder {
    account_key_xdr: String,
    account_xdr: String,
    fee_stats: Arc<serde_json::Value>,
}

impl CreateAccountFeeRpcResponder {
    fn new(account_key_xdr: String, account_xdr: String, fee_stats: serde_json::Value) -> Self {
        Self {
            account_key_xdr,
            account_xdr,
            fee_stats: Arc::new(fee_stats),
        }
    }
}

#[async_trait]
impl Respond for CreateAccountFeeRpcResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let request_value = serde_json::from_slice::<serde_json::Value>(&request.body)
            .unwrap_or_else(|_| serde_json::json!({}));
        let req_id = request_value
            .get("id")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(1));
        let method = request_value
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let result = match method {
            "getNetwork" => crate::common::EndpointNetwork::testnet().result(),
            "getFeeStats" => (*self.fee_stats).clone(),
            "getLedgerEntries" => {
                let body = String::from_utf8_lossy(&request.body);
                if body.contains(&self.account_key_xdr) {
                    serde_json::json!({
                        "entries": [{
                            "key": self.account_key_xdr,
                            "xdr": self.account_xdr,
                            "lastModifiedLedgerSeq": 1000
                        }],
                        "latestLedger": 1001
                    })
                } else {
                    serde_json::json!({
                        "entries": [],
                        "latestLedger": 1001
                    })
                }
            }
            _ => serde_json::json!({}),
        };

        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }))
            .insert_header("content-type", "application/json")
    }
}

/// Starts a local endpoint that reports what `network` reports and answers
/// for the funded `SOURCE_G` account. A call passes the endpoint check and
/// the source read and reaches the step a test is about.
async fn funded_source_endpoint(network: crate::common::EndpointNetwork) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            crate::common::TimeoutRpc::new(vec![(
                account_ledger_key_xdr(SOURCE_G),
                account_entry_xdr_with_seq(SOURCE_G, 100_000_000_000_000, 0, 100),
            )])
            .with_network(network),
        )
        .mount(&server)
        .await;
    server
}

fn fee_stat_json(p95: &str, p99: &str) -> serde_json::Value {
    serde_json::json!({
        "max": "1000",
        "min": "100",
        "mode": "100",
        "p10": "100",
        "p20": "110",
        "p30": "120",
        "p40": "130",
        "p50": "140",
        "p60": "150",
        "p70": "160",
        "p80": "170",
        "p90": "180",
        "p95": p95,
        "p99": p99,
        "transactionCount": "12",
        "ledgerCount": "5"
    })
}

fn fee_stats_result(p95: &str, p99: &str) -> serde_json::Value {
    serde_json::json!({
        "sorobanInclusionFee": fee_stat_json("300", "400"),
        "inclusionFee": fee_stat_json(p95, p99),
        "latestLedger": "12345"
    })
}

fn call_result_text(result: &rmcp::model::CallToolResult) -> &str {
    result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.as_str())
        .unwrap_or("")
}

fn call_result_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    serde_json::from_str(call_result_text(result)).expect("tool result must be JSON")
}

fn install_test_nonce_key(byte: u8) {
    let profile = testnet_profile_with_rpc("https://soroban-testnet.stellar.org");
    helpers::setup_nonce_key(&profile, byte);
}

fn tx_fee_from_envelope_xdr(envelope_xdr: &str) -> u32 {
    use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};

    match TransactionEnvelope::from_xdr_base64(envelope_xdr, Limits::none())
        .expect("valid transaction envelope")
    {
        TransactionEnvelope::Tx(env) => env.tx.fee,
        other => panic!(
            "expected v1 transaction envelope, got {:?}",
            other.discriminant()
        ),
    }
}

/// Builds a minimal but structurally valid `TransactionV1Envelope` base64 string
/// containing a single `CreateAccount` operation from `SOURCE_G` to `DEST_G`.
///
/// The commit handler decodes `envelope_xdr` as the first gate.  Tests that
/// exercise downstream gates (policy, nonce) must supply valid XDR so the
/// re-derivation step succeeds.
fn valid_create_account_envelope_b64() -> String {
    use stellar_xdr::{
        AccountId, CreateAccountOp, Limits, Memo, MuxedAccount, Operation, OperationBody,
        Preconditions, PublicKey, SequenceNumber, Transaction, TransactionEnvelope, TransactionExt,
        TransactionV1Envelope, Uint256, VecM, WriteXdr,
    };
    fn g_bytes(g: &str) -> [u8; 32] {
        stellar_strkey::ed25519::PublicKey::from_string(g)
            .expect("valid G-strkey")
            .0
    }
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(g_bytes(SOURCE_G))),
        fee: 100,
        seq_num: SequenceNumber(101),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(g_bytes(DEST_G)))),
                starting_balance: 10_000_000,
            }),
        }]
        .try_into()
        .expect("single-op vec"),
        ext: TransactionExt::V0,
    };
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    })
    .to_xdr_base64(Limits::none())
    .expect("XDR encode must succeed")
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulate step: input validation (no network required)
// ─────────────────────────────────────────────────────────────────────────────

/// Simulate step rejects an invalid source G-strkey.
///
/// The validation happens before any RPC call, so no mock server is needed.
#[tokio::test]
#[serial]
async fn simulate_rejects_invalid_source_strkey() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let profile = testnet_profile_with_rpc("https://soroban-testnet.stellar.org");
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let args = StellarCreateAccountArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: "NOT_A_VALID_STRKEY".to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        classic_base: None,
    };
    let result = server.call_stellar_create_account(args).await;
    // Should be Err(invalid_params)
    assert!(result.is_err(), "invalid source must return Err");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("invalid source"),
        "error must mention invalid source, got: {err}"
    );
}

/// Simulate step rejects an invalid destination G-strkey.
#[tokio::test]
#[serial]
async fn simulate_rejects_invalid_destination_strkey() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(AccountOnlyResponder {
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000),
        })
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let args = StellarCreateAccountArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: "NOT_A_VALID_STRKEY".to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        classic_base: None,
    };
    let result = server.call_stellar_create_account(args).await;
    assert!(result.is_err(), "invalid destination must return Err");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("invalid destination"),
        "error must mention invalid destination, got: {err}"
    );
}

/// Simulate step rejects a chain_id that does not match the profile.
#[tokio::test]
#[serial]
async fn simulate_rejects_chain_id_mismatch() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let endpoint = funded_source_endpoint(crate::common::EndpointNetwork::testnet()).await;
    let profile = testnet_profile_with_rpc(&endpoint.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let args = StellarCreateAccountArgs {
        chain_id: "stellar:mainnet".to_owned(), // mismatch: profile is testnet
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        classic_base: None,
    };
    let result = server.call_stellar_create_account(args).await;
    assert!(result.is_err(), "chain_id mismatch must return Err");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("chain_id mismatch"),
        "error must mention chain_id mismatch, got: {err}"
    );
    assert_eq!(
        crate::common::received_methods(&endpoint).await,
        ["getNetwork", "getLedgerEntries"],
        "the chain check runs after the endpoint check and the source read"
    );
}

/// The simulate arguments for a 1 XLM account creation by `SOURCE_G` on
/// `chain_id`, with `classic_base` as the fee choice.
fn simulate_args_on(chain_id: &str, classic_base: Option<&str>) -> StellarCreateAccountArgs {
    StellarCreateAccountArgs {
        chain_id: chain_id.to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        classic_base: classic_base.map(str::to_owned),
    }
}

/// A simulate whose endpoint serves another network is refused before any
/// read, with the fixed fee and with the automatic fee, as an `is_error`
/// envelope rather than a protocol error. A `chain_id` that does not match
/// the profile, which otherwise ends in an `invalid_params` protocol error
/// after the source read, is refused the same way.
#[tokio::test]
#[serial]
async fn simulate_refuses_an_endpoint_serving_another_network_before_any_read() {
    for args in [
        simulate_args_on("stellar:testnet", None),
        simulate_args_on("stellar:testnet", Some("auto")),
        simulate_args_on("stellar:mainnet", None),
    ] {
        let _data_root = crate::common::isolated_data_root();
        keyring_mock::install().expect("mock keyring store init");
        let endpoint = funded_source_endpoint(crate::common::EndpointNetwork::reporting(
            crate::common::FUTURENET_PASSPHRASE,
        ))
        .await;
        let server = WalletServer::new(testnet_profile_with_rpc(&endpoint.uri()))
            .expect("WalletServer::new");
        let label = format!("{} fee {:?}", args.chain_id, args.classic_base);

        let (result, built) =
            crate::common::clients_built_by(server.call_stellar_create_account(args)).await;
        let result = result.expect("the refusal is a tool result, not a protocol error");
        let (code, _message, text) = crate::common::assert_business_envelope(&result);
        assert_eq!(code, "network.endpoint_network_mismatch", "{label}: {text}");
        assert_eq!(
            crate::common::received_methods(&endpoint).await,
            ["getNetwork"],
            "{label}: the endpoint check precedes every read"
        );
        assert_eq!(built, 1, "{label}: one client for the simulate");
    }
}

/// A simulate on a mainnet profile whose endpoint reports mainnet is refused
/// with `network.mainnet_write_forbidden` before any read, as an `is_error`
/// envelope: the simulate step reads the values its commit signs.
#[tokio::test]
#[serial]
async fn simulate_refuses_an_endpoint_reporting_mainnet() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let endpoint = funded_source_endpoint(crate::common::EndpointNetwork::reporting(
        stellar_agent_test_support::signed_envelope::MAINNET_PASSPHRASE,
    ))
    .await;
    let server =
        WalletServer::new(mainnet_profile_with_rpc(&endpoint.uri())).expect("WalletServer::new");

    let result = server
        .call_stellar_create_account(simulate_args_on("stellar:mainnet", None))
        .await
        .expect("the refusal is a tool result, not a protocol error");
    let (code, _message, text) = crate::common::assert_business_envelope(&result);
    assert_eq!(code, "network.mainnet_write_forbidden", "{text}");
    assert_eq!(
        crate::common::received_methods(&endpoint).await,
        ["getNetwork"],
        "the endpoint check precedes every read"
    );
}

#[tokio::test]
#[serial]
async fn simulate_create_account_fee_auto_selects_p95_and_binds_envelope_fee() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(11);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(CreateAccountFeeRpcResponder::new(
            account_ledger_key_xdr(SOURCE_G),
            account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000),
            fee_stats_result("333", "999"),
        ))
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let args = StellarCreateAccountArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        classic_base: Some("auto".to_owned()),
    };
    let result = server
        .call_stellar_create_account(args)
        .await
        .expect("auto fee create-account simulate should succeed");
    assert_ne!(result.is_error, Some(true));

    let json = call_result_json(&result);
    let data = json.get("data").expect("success envelope has data");
    assert_eq!(
        data.pointer("/simulation/selected_fee_per_op_stroops"),
        Some(&serde_json::json!("333"))
    );
    assert_eq!(
        data.pointer("/simulation/selected_fee_percentile"),
        Some(&serde_json::json!("p95"))
    );
    let envelope_xdr = data
        .get("envelope_xdr")
        .and_then(serde_json::Value::as_str)
        .expect("envelope_xdr present");
    assert_eq!(tx_fee_from_envelope_xdr(envelope_xdr), 333);
}

#[tokio::test]
#[serial]
async fn simulate_create_account_fee_auto_p99_selects_p99() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(12);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(CreateAccountFeeRpcResponder::new(
            account_ledger_key_xdr(SOURCE_G),
            account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000),
            fee_stats_result("333", "999"),
        ))
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let args = StellarCreateAccountArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        classic_base: Some("auto:p99".to_owned()),
    };
    let result = server
        .call_stellar_create_account(args)
        .await
        .expect("auto:p99 fee create-account simulate should succeed");
    let json = call_result_json(&result);
    let data = json.get("data").expect("success envelope has data");
    assert_eq!(
        data.pointer("/simulation/selected_fee_per_op_stroops"),
        Some(&serde_json::json!("999"))
    );
    assert_eq!(
        data.pointer("/simulation/selected_fee_percentile"),
        Some(&serde_json::json!("p99"))
    );
    let envelope_xdr = data
        .get("envelope_xdr")
        .and_then(serde_json::Value::as_str)
        .expect("envelope_xdr present");
    assert_eq!(tx_fee_from_envelope_xdr(envelope_xdr), 999);
}

#[tokio::test]
#[serial]
async fn simulate_create_account_fee_explicit_above_profile_cap_fails() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(13);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(CreateAccountFeeRpcResponder::new(
            account_ledger_key_xdr(SOURCE_G),
            account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000),
            fee_stats_result("333", "999"),
        ))
        .mount(&mock_server)
        .await;

    let mut profile = testnet_profile_with_rpc(&mock_server.uri());
    profile.classic_max_fee_per_op_stroops = Some(100);
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let args = StellarCreateAccountArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        classic_base: Some("500".to_owned()),
    };
    let result = server
        .call_stellar_create_account(args)
        .await
        .expect("fee above cap must return Ok(is_error) envelope");
    let (code, message, _text) = crate::common::assert_business_envelope(&result);
    assert_eq!(
        code, "fees.percentile_exceeds_cap",
        "expected fees.percentile_exceeds_cap, got: {code}"
    );
    assert_eq!(
        message,
        "the explicit per-operation fee 500 stroops exceeds the profile cap of 100 stroops; \
         lower the fee or raise classic_max_fee_per_op_stroops",
        "cap-exceeded detail must carry the explicit fee and the cap; got: {message}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Commit step: mainnet refusal and policy gate (four-property suite)
//
// Property A: a mainnet profile is refused at entry with
//   network.mainnet_write_forbidden, before the policy gate and any request.
// Property B: V1 engine + matching allow rule → commit proceeds past the gate.
// Property C: V1 engine + no matching rule → policy.deny.no_matching_rule.
// Property D: V1 engine + explicit deny rule → policy.deny.explicit_rule_deny.
// Properties B, C, and D run on testnet, where the commit reaches the gate.
// ─────────────────────────────────────────────────────────────────────────────

/// Property A: on a mainnet profile with the Noop engine, the commit step
/// answers `network.mainnet_write_forbidden` and sends no request.
///
/// The Noop engine's own mainnet verdict (`policy.engine_required`) stays
/// pinned in core and through the friendbot tool; the commit refusal precedes
/// it.
#[tokio::test]
#[serial]
async fn mainnet_profile_commit_refuses_with_mainnet_write_forbidden() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(CreateAccountFeeRpcResponder::new(
            account_ledger_key_xdr(SOURCE_G),
            account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000_000),
            fee_stats_result("100", "100"),
        ))
        .mount(&mock_server)
        .await;
    let profile = mainnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    // Valid CreateAccount XDR, so nothing but the mainnet refusal stops the
    // call before the policy gate.
    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:mainnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: "dGVzdA".to_owned(), // arbitrary base64
        expires_at_unix_ms: u64::MAX,
        envelope_xdr: valid_create_account_envelope_b64(),
        approval_nonce: None,
        approval_attestation: None,
    };
    let result = server
        .call_stellar_create_account_commit(args)
        .await
        .expect("mainnet commit must return Ok(is_error) envelope");
    let (code, _message, _text) = crate::common::assert_business_envelope(&result);
    assert_eq!(
        code, "network.mainnet_write_forbidden",
        "error must be network.mainnet_write_forbidden, got: {code}"
    );
    let received = mock_server
        .received_requests()
        .await
        .expect("request recording is enabled");
    assert!(
        received.is_empty(),
        "a refused mainnet commit must send no request; got {}",
        received.len()
    );
}

/// Property B: when `policy.engine = "v1"` AND the engine returns
/// `Decision::Allow`, `dispatch_gate` returns `Ok(DispatchOutcome::Allow)`
/// and the commit step proceeds past the policy gate.
///
/// The commit step is expected to fail at the nonce gate — the nonce `"dGVzdA"`
/// is too short to verify as a valid HMAC-minted 48-byte blob, so `nonce.expired`
/// is the expected post-policy-gate error.  The key assertion is the absence of
/// `policy.engine_required`, which proves the V1 engine was consulted and
/// returned Allow before the nonce gate was reached.
#[tokio::test]
#[serial]
async fn policy_v1_engine_allow_rule_passes_gate() {
    let _data_root = crate::common::isolated_data_root();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(CreateAccountFeeRpcResponder::new(
            account_ledger_key_xdr(SOURCE_G),
            account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000_000),
            fee_stats_result("100", "100"),
        ))
        .mount(&mock_server)
        .await;
    let server = testnet_server_with_engine_and_rpc(MockPolicyEngine::allow(), &mock_server.uri());

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: "dGVzdA".to_owned(),
        expires_at_unix_ms: u64::MAX,
        envelope_xdr: valid_create_account_envelope_b64(),
        approval_nonce: None,
        approval_attestation: None,
    };
    let result = server
        .call_stellar_create_account_commit(args)
        .await
        .expect("commit reaches the nonce gate, surfaced as Ok(is_error) envelope");
    let (code, _message, _text) = crate::common::assert_business_envelope(&result);
    assert_ne!(
        code, "policy.engine_required",
        "V1 Allow path must NOT emit policy.engine_required"
    );
    assert_eq!(
        code, "nonce.expired",
        "V1 Allow path must reach the nonce gate (proof of gate-pass)"
    );
}

/// Property C: when `policy.engine = "v1"` AND the engine returns
/// `Decision::Deny(NoMatchingRule)`, `dispatch_gate` emits
/// `policy.deny.no_matching_rule`.
#[tokio::test]
#[serial]
async fn policy_v1_engine_no_matching_rule_emits_wire_code() {
    let _data_root = crate::common::isolated_data_root();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(CreateAccountFeeRpcResponder::new(
            account_ledger_key_xdr(SOURCE_G),
            account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000_000),
            fee_stats_result("100", "100"),
        ))
        .mount(&mock_server)
        .await;
    let server = testnet_server_with_engine_and_rpc(
        MockPolicyEngine::deny_no_matching_rule(),
        &mock_server.uri(),
    );

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: "dGVzdA".to_owned(),
        expires_at_unix_ms: u64::MAX,
        envelope_xdr: valid_create_account_envelope_b64(),
        approval_nonce: None,
        approval_attestation: None,
    };
    let result = server
        .call_stellar_create_account_commit(args)
        .await
        .expect("V1 engine with NoMatchingRule must return Ok(is_error) envelope");
    let (code, _message, _text) = crate::common::assert_business_envelope(&result);
    let expected_wire_code = format!("policy.deny.{}", DenyReason::NoMatchingRule.code());
    assert_eq!(
        code, expected_wire_code,
        "V1 engine NoMatchingRule must emit policy.deny.no_matching_rule; got: {code}"
    );
}

/// Property D: when `policy.engine = "v1"` AND the engine returns
/// `Decision::Deny(DenyReason::ExplicitRuleDeny)`, `dispatch_gate` emits
/// `policy.deny.explicit_rule_deny`.
#[tokio::test]
#[serial]
async fn policy_v1_engine_explicit_deny_emits_wire_code() {
    let _data_root = crate::common::isolated_data_root();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(CreateAccountFeeRpcResponder::new(
            account_ledger_key_xdr(SOURCE_G),
            account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000_000),
            fee_stats_result("100", "100"),
        ))
        .mount(&mock_server)
        .await;
    let server = testnet_server_with_engine_and_rpc(
        MockPolicyEngine::deny_explicit_rule(),
        &mock_server.uri(),
    );

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: "dGVzdA".to_owned(),
        expires_at_unix_ms: u64::MAX,
        envelope_xdr: valid_create_account_envelope_b64(),
        approval_nonce: None,
        approval_attestation: None,
    };
    let result = server
        .call_stellar_create_account_commit(args)
        .await
        .expect("V1 engine with ExplicitRuleDeny must return Ok(is_error) envelope");
    let (code, _message, _text) = crate::common::assert_business_envelope(&result);
    let expected_wire_code = format!("policy.deny.{}", DenyReason::ExplicitRuleDeny.code());
    assert_eq!(
        code, expected_wire_code,
        "V1 engine ExplicitRuleDeny must emit policy.deny.explicit_rule_deny; got: {code}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Commit step: nonce error paths
// ─────────────────────────────────────────────────────────────────────────────

/// Commit step with a malformed nonce (not valid base64-48-bytes) returns
/// `nonce.expired` (agent should re-simulate).
#[tokio::test]
#[serial]
async fn commit_returns_nonce_expired_on_bad_nonce() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let endpoint = funded_source_endpoint(crate::common::EndpointNetwork::testnet()).await;
    let profile = testnet_profile_with_rpc(&endpoint.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    // Supply valid CreateAccount XDR so the re-derivation step succeeds
    // and the call reaches the nonce parse gate (which rejects the bad nonce).
    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: "!!invalid-base64!!".to_owned(),
        expires_at_unix_ms: u64::MAX,
        envelope_xdr: valid_create_account_envelope_b64(),
        approval_nonce: None,
        approval_attestation: None,
    };
    let result = server
        .call_stellar_create_account_commit(args)
        .await
        .expect("bad nonce is surfaced as Ok(is_error) envelope");
    let (code, _message, _text) = crate::common::assert_business_envelope(&result);
    assert_eq!(
        code, "nonce.expired",
        "bad nonce must carry wire code nonce.expired"
    );
}

/// Commit step with a validly-encoded but wrong-length nonce (not 48 bytes
/// decoded) also returns `nonce.expired`.
#[tokio::test]
#[serial]
async fn commit_returns_nonce_expired_on_wrong_length_nonce() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let endpoint = funded_source_endpoint(crate::common::EndpointNetwork::testnet()).await;
    let profile = testnet_profile_with_rpc(&endpoint.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    // 20 bytes of base64 decodes to fewer than 48 bytes.
    use base64::Engine;
    let short_nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 20]);

    // Supply valid CreateAccount XDR so the re-derivation step succeeds
    // and the call reaches the nonce parse gate (which rejects the short nonce).
    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: short_nonce,
        expires_at_unix_ms: u64::MAX,
        envelope_xdr: valid_create_account_envelope_b64(),
        approval_nonce: None,
        approval_attestation: None,
    };
    let result = server
        .call_stellar_create_account_commit(args)
        .await
        .expect("wrong-length nonce is surfaced as Ok(is_error) envelope");
    let (code, _message, _text) = crate::common::assert_business_envelope(&result);
    assert_eq!(
        code, "nonce.expired",
        "wrong-length nonce must carry wire code nonce.expired"
    );
}

/// Commit step rejects a replay: the same nonce cannot be used twice.
///
/// This test uses a mock RPC that returns a simulated account, mints a real
/// nonce via the simulate step, then attempts to commit twice.  The second
/// commit must return `nonce.replayed`.
///
/// Because `stellar_create_account` calls `fetch_account` (RPC), we need a
/// mock server that returns a plausible RPC response.  For this test we use
/// an approach where the mock returns a JSON-RPC error (account not found)
/// so the simulate step fails with a tool-level error, which lets us test
/// the nonce-replay path independently via direct nonce manipulation.
///
/// The nonce replay test that requires a successful simulate step is covered
/// by the end-to-end binary smoke test; here we exercise the replay-window
/// logic directly using the nonce crate test helpers.
///
/// This test does NOT call `server.call_stellar_create_account_commit`; it
/// exercises `NonceMint::verify` / `mint` directly.
#[tokio::test]
#[serial]
async fn nonce_mint_verify_returns_replayed() {
    let _data_root = crate::common::isolated_data_root();
    use stellar_agent_nonce::{NonceVerifyRequest, ReplayWindow};
    keyring_mock::install().expect("mock keyring store init");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(AccountOnlyResponder {
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000),
        })
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    helpers::setup_nonce_key(&profile, 0);
    let mint = helpers::mint_for(&profile);

    // A fixed past timestamp avoids the SystemTime::now() pattern (silent
    // u128→u64 truncation + 1970-epoch on anomaly).  This test exercises
    // NonceMint::verify directly; both mint() and verify() receive the same
    // fixed now_ms, so there is no real-clock dependency.  1_000_000_000_000 ms
    // = 2001-09-09 (past epoch, stable).
    let now_ms: u64 = 1_000_000_000_000;
    let expiry_ms = now_ms + 120_000;
    let envelope_xdr = "AAAABW=="; // placeholder

    let nonce = mint
        .mint(
            &AnyTool,
            envelope_xdr.as_bytes(),
            now_ms,
            expiry_ms,
            "stellar_create_account_commit",
            "stellar:testnet",
        )
        .expect("mint");

    let mut window = ReplayWindow::new();
    // First verify: succeeds.
    mint.verify(NonceVerifyRequest {
        replay_window: &mut window,
        nonce: &nonce,
        envelope_xdr: envelope_xdr.as_bytes(),
        expiry_unix_ms: expiry_ms,
        tool_name: "stellar_create_account_commit",
        chain_id: "stellar:testnet",
        now_unix_ms: now_ms,
    })
    .expect("first verify should succeed");

    // Second verify: must return Replayed.
    let result = mint.verify(NonceVerifyRequest {
        replay_window: &mut window,
        nonce: &nonce,
        envelope_xdr: envelope_xdr.as_bytes(),
        expiry_unix_ms: expiry_ms,
        tool_name: "stellar_create_account_commit",
        chain_id: "stellar:testnet",
        now_unix_ms: now_ms,
    });
    assert!(
        matches!(result, Err(stellar_agent_nonce::NonceError::Replayed)),
        "second verify must return Replayed, got: {result:?}"
    );
}

/// Expired nonce returns `nonce.expired`.
///
/// Verified via the nonce crate directly (the `expired` path fires when
/// `now_unix_ms >= expiry_unix_ms`).
///
/// This test does NOT call `server.call_stellar_create_account_commit`; it
/// exercises `NonceMint::verify` directly.
#[tokio::test]
#[serial]
async fn nonce_mint_verify_returns_expired_on_expiry() {
    let _data_root = crate::common::isolated_data_root();
    use stellar_agent_nonce::{NonceVerifyRequest, ReplayWindow};
    keyring_mock::install().expect("mock keyring store init");

    let profile = testnet_profile_with_rpc("https://soroban-testnet.stellar.org");
    helpers::setup_nonce_key(&profile, 1);
    let mint = helpers::mint_for(&profile);

    let now_ms: u64 = 1_000_000_000_000; // fixed past timestamp
    let expiry_ms = now_ms + 120_000;
    let envelope_xdr = "BBBBBW=="; // placeholder

    let nonce = mint
        .mint(
            &AnyTool,
            envelope_xdr.as_bytes(),
            now_ms,
            expiry_ms,
            "stellar_create_account_commit",
            "stellar:testnet",
        )
        .expect("mint");

    let mut window = ReplayWindow::new();
    // now_ms >> expiry_ms → expired
    let future_now = expiry_ms + 1;
    let result = mint.verify(NonceVerifyRequest {
        replay_window: &mut window,
        nonce: &nonce,
        envelope_xdr: envelope_xdr.as_bytes(),
        expiry_unix_ms: expiry_ms,
        tool_name: "stellar_create_account_commit",
        chain_id: "stellar:testnet",
        now_unix_ms: future_now,
    });
    assert!(
        matches!(result, Err(stellar_agent_nonce::NonceError::Expired)),
        "verify after expiry must return Expired, got: {result:?}"
    );
}

/// Corrupted HMAC tag (one byte flipped) returns `HmacMismatch`.
///
/// The MCP layer maps `HmacMismatch` to `nonce.expired` so the two cases are
/// indistinguishable to the agent.
///
/// This test does NOT call `server.call_stellar_create_account_commit`; it
/// exercises `NonceMint::verify` directly via the nonce crate.
#[tokio::test]
#[serial]
async fn nonce_mint_hmac_mismatch_via_corrupted_nonce() {
    let _data_root = crate::common::isolated_data_root();
    use stellar_agent_nonce::mint::Nonce;
    use stellar_agent_nonce::{NonceVerifyRequest, ReplayWindow};
    keyring_mock::install().expect("mock keyring store init");

    use base64::Engine;
    let profile = testnet_profile_with_rpc("https://soroban-testnet.stellar.org");
    helpers::setup_nonce_key(&profile, 2);
    let mint = helpers::mint_for(&profile);

    let now_ms: u64 = 2_000_000_000_000;
    let expiry_ms = now_ms + 120_000;
    let envelope_xdr = "CCCCCW==";

    let nonce = mint
        .mint(
            &AnyTool,
            envelope_xdr.as_bytes(),
            now_ms,
            expiry_ms,
            "stellar_create_account_commit",
            "stellar:testnet",
        )
        .expect("mint");

    // Corrupt one byte of the HMAC tag (bytes 16..48 of the 48-byte nonce).
    let mut raw: [u8; 48] = {
        // Re-encode to bytes via base64 then decode.
        let b64 = nonce.to_base64();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&b64)
            .expect("decode");
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&decoded);
        arr
    };
    raw[16] ^= 0xFF; // flip all bits of the first tag byte
    let corrupted = Nonce::from_raw(raw);

    let mut window = ReplayWindow::new();
    let result = mint.verify(NonceVerifyRequest {
        replay_window: &mut window,
        nonce: &corrupted,
        envelope_xdr: envelope_xdr.as_bytes(),
        expiry_unix_ms: expiry_ms,
        tool_name: "stellar_create_account_commit",
        chain_id: "stellar:testnet",
        now_unix_ms: now_ms,
    });
    assert!(
        matches!(result, Err(stellar_agent_nonce::NonceError::HmacMismatch)),
        "corrupted HMAC must return HmacMismatch, got: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Commit step: envelope divergence
// ─────────────────────────────────────────────────────────────────────────────

/// An RPC error during the commit's rebuild ends the commit as the account
/// fetch's own refusal, and nothing is sent.
///
/// The endpoint reports testnet and answers every other method with a
/// JSON-RPC error. The commit carries a valid create-account envelope, so it
/// passes the decode and the endpoint check. Its source read then fails.
#[tokio::test]
#[serial]
async fn commit_handles_rpc_error_during_rebuild() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(|request: &Request| {
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).unwrap_or(serde_json::json!({}));
            let reply = if body["method"] == "getNetwork" {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": crate::common::EndpointNetwork::testnet().result(),
                })
            } else {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": { "code": -32600, "message": "account not found" }
                })
            };
            ResponseTemplate::new(200).set_body_json(reply)
        })
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    // A validly encoded 48-byte nonce; the commit ends before it is parsed.
    use base64::Engine;
    let zero_nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 48]);

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: zero_nonce,
        expires_at_unix_ms: 3_000_000_000_000,
        envelope_xdr: valid_create_account_envelope_b64(),
        approval_nonce: None,
        approval_attestation: None,
    };
    let result = server
        .call_stellar_create_account_commit(args)
        .await
        .expect("the account-fetch failure is a tool result, not a protocol error");
    let (code, _message, text) = crate::common::assert_business_envelope(&result);
    assert_eq!(
        code, "network.rpc_unreachable",
        "the RPC error during the rebuild's account fetch must surface: {text}"
    );
    assert_eq!(
        crate::common::received_methods(&mock_server).await,
        ["getNetwork", "getLedgerEntries"],
        "the account fetch follows the endpoint check and ends the commit"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Indistinguishability integration test
// ─────────────────────────────────────────────────────────────────────────────

/// Indistinguishability invariant: agent-visible JSON error string is
/// byte-identical for `Expired` and `HmacMismatch`.
///
/// This test locks the invariant against future refactor regressions.  The
/// wire-code unit tests in the `stellar-agent-nonce` crate verify
/// Rust-level equality (both map to `"nonce.expired"`); this integration test
/// verifies the MCP commit handler emits the same full JSON-RPC error message
/// for both paths.  The agent-visible message is the observable surface.
#[tokio::test]
#[serial]
async fn commit_indistinguishability_expired_vs_hmac_mismatch() {
    let _data_root = crate::common::isolated_data_root();
    use base64::Engine;
    use stellar_agent_nonce::mint::Nonce;

    keyring_mock::install().expect("mock keyring store init");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(AccountOnlyResponder {
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000),
        })
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    helpers::setup_nonce_key(&profile, 0xAA);
    let server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    let mint = helpers::mint_for(&profile);

    // Valid XDR for both paths: re-derivation must succeed before reaching the
    // expiry/HMAC gate.  The nonce HMAC is over the envelope_xdr bytes (the
    // base64 string), so minting and committing with the same string produces a
    // matching HMAC pre-corruption.
    let envelope_a = valid_create_account_envelope_b64();

    // ── Path A: Expired ───────────────────────────────────────────────────────
    // Mint a valid nonce, then submit with expires_at_unix_ms = 1 (far past).
    // The commit handler's expiry check fires first: now_unix_ms > 1 → Expired.
    let now_a: u64 = 3_000_000_000_000; // far future for mint
    let expiry_a: u64 = now_a + 120_000;
    let nonce_a = mint
        .mint(
            &AnyTool,
            envelope_a.as_bytes(),
            now_a,
            expiry_a,
            "stellar_create_account_commit",
            "stellar:testnet",
        )
        .expect("mint nonce_a");

    let args_a = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: nonce_a.to_base64(),
        expires_at_unix_ms: 1, // far past → Expired
        envelope_xdr: envelope_a.clone(),
        approval_nonce: None,
        approval_attestation: None,
    };
    let result_a = server
        .call_stellar_create_account_commit(args_a)
        .await
        .expect("Expired path must return Ok(is_error) envelope");
    let (code_a, message_a, _text_a) = crate::common::assert_business_envelope(&result_a);

    // ── Path B: HmacMismatch ──────────────────────────────────────────────────
    // Mint a nonce with valid far-future expiry; corrupt one HMAC byte so the
    // expiry check passes but HMAC compare fails → HmacMismatch.
    let now_b: u64 = 3_000_000_000_000;
    let expiry_b: u64 = now_b + 120_000;
    // Use the same XDR as path A — the HMAC corruption (below) ensures path B
    // reaches HmacMismatch, not Expired.
    let envelope_b = valid_create_account_envelope_b64();
    let nonce_b = mint
        .mint(
            &AnyTool,
            envelope_b.as_bytes(),
            now_b,
            expiry_b,
            "stellar_create_account_commit",
            "stellar:testnet",
        )
        .expect("mint nonce_b");

    // Corrupt byte 16 of the 48-byte nonce (first byte of the HMAC tag).
    let mut raw_b: [u8; 48] = {
        let b64 = nonce_b.to_base64();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&b64)
            .expect("decode nonce_b");
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&decoded);
        arr
    };
    raw_b[16] ^= 0xFF;
    let corrupted_b = Nonce::from_raw(raw_b);

    let args_b = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: corrupted_b.to_base64(),
        expires_at_unix_ms: expiry_b, // valid (far future) so expiry passes
        envelope_xdr: envelope_b.to_owned(),
        approval_nonce: None,
        approval_attestation: None,
    };
    let result_b = server
        .call_stellar_create_account_commit(args_b)
        .await
        .expect("HmacMismatch path must return Ok(is_error) envelope");
    let (code_b, message_b, _text_b) = crate::common::assert_business_envelope(&result_b);

    // ── Path C: malformed nonce (parse failure) ───────────────────────────────
    // A nonce string that fails `Nonce::from_base64` reaches the commit handler's
    // parse arm, which collapses to the same Expired envelope. Valid envelope +
    // testnet Allow so the call reaches the nonce-parse gate before any verify.
    let args_c = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: "!!! not a valid nonce !!!".to_owned(),
        expires_at_unix_ms: expiry_b, // valid; parse fails before expiry is read
        envelope_xdr: envelope_a.clone(),
        approval_nonce: None,
        approval_attestation: None,
    };
    let result_c = server
        .call_stellar_create_account_commit(args_c)
        .await
        .expect("parse-failure path must return Ok(is_error) envelope");
    let (code_c, message_c, _text_c) = crate::common::assert_business_envelope(&result_c);

    // ── Indistinguishability assertion ────────────────────────────────────────
    for (label, code) in [
        ("Expired", &code_a),
        ("HmacMismatch", &code_b),
        ("ParseFailure", &code_c),
    ] {
        assert_eq!(
            code, "nonce.expired",
            "{label} path must carry wire code nonce.expired; got: {code}"
        );
    }
    // `details` is part of the comparison: an object present on one refusal
    // and absent on another tells the caller which refusal it got.
    let pair_a = (
        code_a,
        message_a,
        crate::common::business_envelope_details(&result_a),
    );
    let pair_b = (
        code_b,
        message_b,
        crate::common::business_envelope_details(&result_b),
    );
    let pair_c = (
        code_c,
        message_c,
        crate::common::business_envelope_details(&result_c),
    );
    assert!(
        pair_a.2.is_none(),
        "an approval refusal carries no structured detail: {:?}",
        pair_a.2
    );
    assert_eq!(
        pair_a, pair_b,
        "indistinguishability violated: Expired and HmacMismatch must produce \
         byte-identical agent-visible (code, message) pairs.\n  a: {pair_a:?}\n  b: {pair_b:?}"
    );
    assert_eq!(
        pair_a, pair_c,
        "indistinguishability violated: a malformed-nonce parse failure must produce \
         the same (code, message) as Expired.\n  a: {pair_a:?}\n  c: {pair_c:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-check integration tests
// ─────────────────────────────────────────────────────────────────────────────

/// Wiremock responder serving the account state and the endpoint's network
/// identity, and nothing else.
///
/// The reported identity is testnet, matching the profile every consumer
/// builds, so a commit reaching the endpoint probe passes it and is refused,
/// if at all, by the gate the test is about.
struct AccountOnlyResponder {
    account_key_xdr: String,
    account_xdr: String,
}

#[async_trait::async_trait]
impl wiremock::Respond for AccountOnlyResponder {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        let request_value = serde_json::from_slice::<serde_json::Value>(&request.body)
            .unwrap_or_else(|_| serde_json::json!({}));
        let req_id = request_value
            .get("id")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(1));
        let method = request_value
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let result = match method {
            "getNetwork" => crate::common::EndpointNetwork::testnet().result(),
            "getLedgerEntries" => {
                let body = String::from_utf8_lossy(&request.body);
                if body.contains(&self.account_key_xdr) {
                    serde_json::json!({
                        "entries": [{
                            "key": &self.account_key_xdr,
                            "xdr": &self.account_xdr,
                            "lastModifiedLedgerSeq": 1000
                        }],
                        "latestLedger": 1001
                    })
                } else {
                    serde_json::json!({ "entries": [], "latestLedger": 1001 })
                }
            }
            _ => serde_json::json!({}),
        };

        wiremock::ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }))
            .insert_header("content-type", "application/json")
    }
}

/// Derives the G-strkey for a 32-byte ed25519 seed.
fn gstrkey_for_seed(seed: [u8; 32]) -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = signing_key.verifying_key();
    stellar_strkey::ed25519::PublicKey(vk.to_bytes())
        .to_string()
        .to_string()
}

/// Derives the S-strkey (seed strkey) for a 32-byte ed25519 seed.
fn sstrkey_for_seed(seed: [u8; 32]) -> String {
    stellar_strkey::ed25519::PrivateKey(seed)
        .as_unredacted()
        .to_string()
        .to_string()
}

/// RPC responder for a full simulate → commit → submit round trip.
///
/// Serves the SAME funded-account `getLedgerEntries` response on the simulate
/// fetch, the commit re-fetch, and the submit-path signer fetch, so the
/// rebuilt envelope is byte-identical to the presented one (the divergence
/// check passes) and the source account reports the signing key as its own
/// master key. `getNetwork` answers the endpoint-identity probe, then
/// `sendTransaction` (PENDING) is followed by `getTransaction` (SUCCESS).
struct CreateAccountSubmitSuccessRpcResponder {
    account_key_xdr: String,
    account_xdr: String,
    network: crate::common::EndpointNetwork,
}

#[async_trait]
impl Respond for CreateAccountSubmitSuccessRpcResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let request_value = serde_json::from_slice::<serde_json::Value>(&request.body)
            .unwrap_or_else(|_| serde_json::json!({}));
        let req_id = request_value
            .get("id")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(1));
        let method = request_value
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let result = match method {
            "getNetwork" => self.network.result(),
            "getLedgerEntries" => {
                let body = String::from_utf8_lossy(&request.body);
                if body.contains(&self.account_key_xdr) {
                    serde_json::json!({
                        "entries": [
                            {
                                "key": self.account_key_xdr,
                                "xdr": self.account_xdr,
                                "lastModifiedLedgerSeq": 1000
                            }
                        ],
                        "latestLedger": 1001
                    })
                } else {
                    serde_json::json!({ "entries": [], "latestLedger": 1001 })
                }
            }
            // The endpoint answers with the hash of the transaction it was
            // handed, the way a real one does: the wallet polls and records
            // the hash it computed from the bytes it signed, and reports a
            // disagreement as `submission.hash_mismatch`.
            "sendTransaction" => serde_json::json!({
                "hash": crate::common::submitted_tx_hash(request),
                "status": "PENDING",
                "latestLedger": 1001,
                "latestLedgerCloseTime": "1234567890"
            }),
            "getTransaction" => serde_json::json!({
                "status": "SUCCESS",
                "ledger": 1005,
                "txHash": crate::common::polled_tx_hash(request),
            }),
            _ => serde_json::json!({}),
        };

        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }))
            .insert_header("content-type", "application/json")
    }
}

/// End-to-end success path: `stellar_create_account` (simulate) mints a
/// nonce; `stellar_create_account_commit` reuses the exact `(nonce,
/// expires_at_unix_ms, envelope_xdr)` triple, re-derives the decimal-string
/// `starting_balance_stroops` from the HMAC-bound envelope, signs via a
/// keyring-backed signer, and submits. Asserts the committed values, not just
/// that each phase in isolation accepts the new wire shape.
#[tokio::test]
#[serial]
async fn create_account_commit_full_round_trip_succeeds_with_string_encoded_amounts() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(201);

    // Fresh signer keypair; populates the mock keyring's default signer entry
    // ("svc", "acct" — matching `testnet_profile_with_rpc`'s
    // `Profile::builder_testnet("svc", "acct", ...)`) with its S-strkey.
    let seed = [0x43_u8; 32];
    let source_g = gstrkey_for_seed(seed);
    keyring_core::Entry::new("svc", "acct")
        .expect("Entry::new")
        .set_password(&sstrkey_for_seed(seed))
        .expect("set_password");

    let account_key_xdr = account_ledger_key_xdr(&source_g);
    // 10_000_000 XLM: comfortably covers the starting balance, base reserve, and fee.
    let account_xdr = account_entry_xdr_with_balance(&source_g, 100_000_000_000_000);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(CreateAccountSubmitSuccessRpcResponder {
            account_key_xdr,
            account_xdr,
            network: crate::common::EndpointNetwork::testnet(),
        })
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    // ── Simulate ───────────────────────────────────────────────────────────
    let simulate_args = StellarCreateAccountArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: source_g.clone(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""100 XLM""#).expect("parse amount"),
        classic_base: None,
    };
    let (sim_result, simulate_clients) =
        crate::common::clients_built_by(server.call_stellar_create_account(simulate_args.clone()))
            .await;
    let sim_result = sim_result.expect("simulate must not error");
    assert_ne!(sim_result.is_error, Some(true), "simulate must succeed");
    let simulate_methods = crate::common::received_methods(&mock_server).await;
    let sim_json = call_result_json(&sim_result);
    let sim_data = sim_json.get("data").expect("simulate success carries data");

    assert_eq!(
        sim_data.pointer("/simulation/operation/starting_balance_stroops"),
        Some(&serde_json::json!("1000000000")),
        "simulate must report starting_balance_stroops as a decimal string: {sim_data}"
    );

    let nonce = sim_data
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .expect("nonce present")
        .to_owned();
    let expires_at_unix_ms = sim_data
        .get("expires_at_unix_ms")
        .and_then(serde_json::Value::as_u64)
        .expect("expires_at_unix_ms present");
    let envelope_xdr = sim_data
        .get("envelope_xdr")
        .and_then(serde_json::Value::as_str)
        .expect("envelope_xdr present")
        .to_owned();

    // ── Commit ─────────────────────────────────────────────────────────────
    let commit_args = StellarCreateAccountCommitArgs {
        chain_id: simulate_args.chain_id.clone(),
        source: simulate_args.source.clone(),
        destination: simulate_args.destination.clone(),
        starting_balance: simulate_args.starting_balance.clone(),
        nonce,
        expires_at_unix_ms,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    };
    let (commit_result, commit_clients) =
        crate::common::clients_built_by(server.call_stellar_create_account_commit(commit_args))
            .await;
    let commit_result = commit_result.expect("commit must not error");
    let commit_json = call_result_json(&commit_result);
    assert_ne!(
        commit_result.is_error,
        Some(true),
        "commit must succeed, got: {commit_json}"
    );
    let commit_data = commit_json
        .get("data")
        .expect("commit success carries data");
    assert!(
        commit_data
            .get("tx_hash")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "committed response must carry tx_hash: {commit_data}"
    );
    assert_eq!(
        commit_data
            .get("ledger")
            .and_then(serde_json::Value::as_u64),
        Some(1005),
        "committed response must carry the submitted ledger: {commit_data}"
    );

    // The simulate and the commit each check their endpoint before their
    // first read, on the one client each builds; the submit layer checks the
    // commit's client again. The `Noop` engine builds no reconcile client and
    // no oracle is configured.
    let all_methods = crate::common::received_methods(&mock_server).await;
    let commit_methods = &all_methods[simulate_methods.len()..];
    let network_checks = |methods: &[String]| {
        methods
            .iter()
            .filter(|m| m.as_str() == "getNetwork")
            .count()
    };
    assert_eq!(
        simulate_methods.first().map(String::as_str),
        Some("getNetwork")
    );
    assert_eq!(
        commit_methods.first().map(String::as_str),
        Some("getNetwork")
    );
    assert_eq!(network_checks(&simulate_methods), 1, "{simulate_methods:?}");
    assert_eq!(network_checks(commit_methods), 2, "{commit_methods:?}");
    assert_eq!(simulate_clients, 1, "the simulate reads through one client");
    assert_eq!(
        commit_clients, 1,
        "the commit reads and sends through one client"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Commit-phase gate view wiring (#48): minimum_reserve under a real V1 engine
// ─────────────────────────────────────────────────────────────────────────────

/// Full simulate → commit round trip succeeds under a `minimum_reserve` rule
/// covering BOTH `stellar_create_account` and `stellar_create_account_commit`,
/// evaluated by a real `PolicyEngineV1` (not `MockPolicyEngine`, which ignores
/// `account_view`).
///
/// `MinimumReserveCriterion::evaluate` fails closed whenever `ctx.account_view`
/// is `None`; both phases reaching `Ok` (rather than
/// `policy.criterion_evaluation_failed` at commit) is direct proof that
/// `stellar_create_account_commit`'s dispatch site now supplies the same kind
/// of real `account_view` its simulate phase always has.
#[tokio::test]
#[serial]
async fn create_account_two_phase_round_trip_succeeds_under_satisfied_minimum_reserve_rule() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(202);

    let seed = [0x44_u8; 32];
    let source_g = gstrkey_for_seed(seed);
    keyring_core::Entry::new("svc", "acct")
        .expect("Entry::new")
        .set_password(&sstrkey_for_seed(seed))
        .expect("set_password");

    let account_key_xdr = account_ledger_key_xdr(&source_g);
    // 10_000_000 XLM: comfortably covers the starting balance, base reserve,
    // fee, AND the minimum_reserve margin below.
    let account_xdr = account_entry_xdr_with_balance(&source_g, 100_000_000_000_000);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(CreateAccountSubmitSuccessRpcResponder {
            account_key_xdr,
            account_xdr,
            network: crate::common::EndpointNetwork::testnet(),
        })
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    server.set_policy_engine_for_test(std::sync::Arc::new(
        crate::common::v1_engine_mock::minimum_reserve_engine(
            &["stellar_create_account", "stellar_create_account_commit"],
            5_0000000, // 5 XLM margin — comfortably satisfied by the funded account.
        ),
    ));

    // ── Simulate ───────────────────────────────────────────────────────────
    let simulate_args = StellarCreateAccountArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: source_g.clone(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""100 XLM""#).expect("parse amount"),
        classic_base: None,
    };
    let sim_result = server
        .call_stellar_create_account(simulate_args.clone())
        .await
        .expect("simulate must not error");
    assert_ne!(
        sim_result.is_error,
        Some(true),
        "simulate under a satisfied minimum_reserve rule must succeed: {}",
        call_result_json(&sim_result)
    );
    let sim_json = call_result_json(&sim_result);
    let sim_data = sim_json.get("data").expect("simulate success carries data");
    let nonce = sim_data
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .expect("nonce present")
        .to_owned();
    let expires_at_unix_ms = sim_data
        .get("expires_at_unix_ms")
        .and_then(serde_json::Value::as_u64)
        .expect("expires_at_unix_ms present");
    let envelope_xdr = sim_data
        .get("envelope_xdr")
        .and_then(serde_json::Value::as_str)
        .expect("envelope_xdr present")
        .to_owned();

    // ── Commit ─────────────────────────────────────────────────────────────
    let commit_args = StellarCreateAccountCommitArgs {
        chain_id: simulate_args.chain_id.clone(),
        source: simulate_args.source.clone(),
        destination: simulate_args.destination.clone(),
        starting_balance: simulate_args.starting_balance.clone(),
        nonce,
        expires_at_unix_ms,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    };
    let commit_result = server
        .call_stellar_create_account_commit(commit_args)
        .await
        .expect("commit must not error");
    let commit_json = call_result_json(&commit_result);
    assert_ne!(
        commit_result.is_error,
        Some(true),
        "commit under a satisfied minimum_reserve rule must succeed \
         (account_view must be supplied at the commit dispatch site); got: {commit_json}"
    );
    assert!(
        commit_json
            .get("data")
            .and_then(|d| d.get("tx_hash"))
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "committed response must carry tx_hash: {commit_json}"
    );
}

/// `stellar_create_account_commit` denies under a `minimum_reserve` rule when
/// the source account's real (mocked, low) on-chain balance breaches the
/// reserve floor — `policy.deny.minimum_reserve_breached`, not
/// `policy.criterion_evaluation_failed` (which would indicate a missing
/// `account_view`) and not any RPC-error envelope.
#[tokio::test]
#[serial]
async fn create_account_commit_denies_under_unsatisfied_minimum_reserve_rule() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");

    let account_key_xdr = account_ledger_key_xdr(SOURCE_G);
    // 2 XLM: below the ~1.5 XLM base reserve plus the 5 XLM margin configured
    // below — the rule must deny, not fail closed on a missing view.
    let account_xdr = account_entry_xdr_with_balance(SOURCE_G, 20_000_000);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(CreateAccountSubmitSuccessRpcResponder {
            account_key_xdr,
            account_xdr,
            network: crate::common::EndpointNetwork::testnet(),
        })
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    server.set_policy_engine_for_test(std::sync::Arc::new(
        crate::common::v1_engine_mock::minimum_reserve_engine(
            &["stellar_create_account", "stellar_create_account_commit"],
            5_0000000, // 5 XLM margin — the mocked 2 XLM balance cannot satisfy it.
        ),
    ));

    // Commit is reached directly: the gate denies before nonce parsing, so an
    // arbitrary nonce/envelope pair (not minted by a prior simulate call) is
    // sufficient — nonce verification is never reached.
    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: "dGVzdA".to_owned(),
        expires_at_unix_ms: u64::MAX,
        envelope_xdr: valid_create_account_envelope_b64(),
        approval_nonce: None,
        approval_attestation: None,
    };
    let result = server
        .call_stellar_create_account_commit(args)
        .await
        .expect("unsatisfied minimum_reserve rule must return Ok(is_error) envelope");
    let (code, _message, _text) = crate::common::assert_business_envelope(&result);
    assert_eq!(
        code, "policy.deny.minimum_reserve_breached",
        "commit under an unsatisfied minimum_reserve rule must deny with \
         minimum_reserve_breached, not fail closed on a missing account_view; got: {code}"
    );
}

// ── Envelope-shape regression guard: nonce.mint_failed ───────────────────────

/// `stellar_create_account` returns the full documented business-error
/// envelope (`ok:false`, `error.code == "nonce.mint_failed"`, non-empty
/// `request_id`, `is_error == Some(true)`) when the nonce-key keyring entry
/// is absent.
///
/// Forces the failure the cheapest honest way: a fresh mock keyring store
/// with NO key written at the profile's nonce coordinate — every RPC call
/// (fee stats, account fetch) succeeds normally, so the only failure is
/// `NonceMint::mint`'s keyring load inside the handler's own simulate path.
#[tokio::test]
#[serial]
async fn simulate_nonce_mint_failed_envelope_shape() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    // Deliberately no nonce-key seeding call — the mock store stays empty
    // at the nonce coordinate.

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(CreateAccountFeeRpcResponder::new(
            account_ledger_key_xdr(SOURCE_G),
            account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000),
            fee_stats_result("333", "999"),
        ))
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let args = StellarCreateAccountArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        classic_base: Some("auto".to_owned()),
    };
    let result = server
        .call_stellar_create_account(args)
        .await
        .expect("handler must return a business-error result, not a protocol error");

    let (code, _message, _text) = crate::common::assert_business_envelope(&result);
    assert_eq!(
        code, "nonce.mint_failed",
        "an absent nonce-key keyring entry must surface nonce.mint_failed"
    );
}

mod helpers {
    use base64::Engine;
    use keyring_core::Entry;
    use stellar_agent_core::profile::schema::Profile;
    use stellar_agent_nonce::{NonceMint, ToolCatalogue};

    pub(super) struct AnyTool;

    impl ToolCatalogue for AnyTool {
        fn is_registered(&self, _: &str) -> bool {
            true
        }
    }

    pub(super) fn setup_nonce_key(profile: &Profile, byte: u8) {
        let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32]);
        Entry::new(
            &profile.mcp_nonce_key_alias.service,
            &profile.mcp_nonce_key_alias.account,
        )
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password");
    }

    pub(super) fn mint_for(profile: &Profile) -> NonceMint {
        NonceMint::from_profile(profile, "nonce-test").expect("NonceMint::from_profile")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Endpoint-identity probe at the commit boundary
// ─────────────────────────────────────────────────────────────────────────────

/// `stellar_create_account_commit` refuses with
/// `network.endpoint_network_mismatch` when the endpoint serves a network
/// other than the profile's, before any other request, and the nonce it was
/// handed survives that refusal.
///
/// The simulate runs while the endpoint reports testnet, since the simulate
/// checks the endpoint too. The endpoint then reports a third network for the
/// refused commit, whose only request is the endpoint check.
///
/// The survival proof is the second commit: the endpoint's reported identity
/// is swapped back to the profile's network and the SAME nonce is committed
/// again, which submits. A nonce recorded in the replay window by the first
/// call would instead return `nonce.replayed` there. Repeating the refused
/// call and asserting the mismatch code again would discriminate nothing,
/// because the check precedes the nonce gate and answers identically whether
/// or not the nonce was consumed.
#[tokio::test]
#[serial]
async fn commit_endpoint_network_mismatch_refuses_without_burning_nonce() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(202);

    let seed = [0x58_u8; 32];
    let source_g = gstrkey_for_seed(seed);
    keyring_core::Entry::new("svc", "acct")
        .expect("Entry::new")
        .set_password(&sstrkey_for_seed(seed))
        .expect("set_password");

    let account_key_xdr = account_ledger_key_xdr(&source_g);
    let account_xdr = account_entry_xdr_with_balance(&source_g, 100_000_000_000_000);

    // The endpoint serves the profile's testnet for the simulate.
    let network = crate::common::EndpointNetwork::testnet();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(CreateAccountSubmitSuccessRpcResponder {
            account_key_xdr,
            account_xdr,
            network: network.clone(),
        })
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    // ── Simulate: mints a real nonce over a real envelope ──────────────────
    let simulate_args = StellarCreateAccountArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: source_g.clone(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""100 XLM""#).expect("parse amount"),
        classic_base: None,
    };
    let sim_result = server
        .call_stellar_create_account(simulate_args.clone())
        .await
        .expect("simulate must not error");
    assert_ne!(
        sim_result.is_error,
        Some(true),
        "simulate must succeed: {}",
        call_result_text(&sim_result)
    );
    let sim_json = call_result_json(&sim_result);
    let sim_data = sim_json.get("data").expect("simulate success carries data");
    let nonce = sim_data
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .expect("nonce present")
        .to_owned();
    let expires_at_unix_ms = sim_data
        .get("expires_at_unix_ms")
        .and_then(serde_json::Value::as_u64)
        .expect("expires_at_unix_ms present");
    let envelope_xdr = sim_data
        .get("envelope_xdr")
        .and_then(serde_json::Value::as_str)
        .expect("envelope_xdr present")
        .to_owned();

    let commit_args = StellarCreateAccountCommitArgs {
        chain_id: simulate_args.chain_id.clone(),
        source: simulate_args.source.clone(),
        destination: simulate_args.destination.clone(),
        starting_balance: simulate_args.starting_balance.clone(),
        nonce,
        expires_at_unix_ms,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    };

    // ── Commit against the wrong network ───────────────────────────────────
    network.set(crate::common::FUTURENET_PASSPHRASE);
    let before_commit = crate::common::received_methods(&mock_server).await.len();
    let refused = server
        .call_stellar_create_account_commit(commit_args.clone())
        .await
        .expect("the refusal must surface as an is_error envelope, not a protocol error");
    let (code, _message, _text) = crate::common::assert_business_envelope(&refused);
    assert_eq!(
        code, "network.endpoint_network_mismatch",
        "a commit whose endpoint serves a different network must carry the \
         mismatch code, got: {code}"
    );
    assert_eq!(
        crate::common::received_methods(&mock_server).await[before_commit..],
        ["getNetwork"],
        "the refused commit's endpoint check is its first and only request"
    );

    // ── Commit again once the endpoint serves the profile's network ────────
    network.set(stellar_agent_test_support::signed_envelope::TESTNET_PASSPHRASE);
    let committed = server
        .call_stellar_create_account_commit(commit_args)
        .await
        .expect("the retry must not error");
    let committed_json = call_result_json(&committed);
    assert_ne!(
        committed.is_error,
        Some(true),
        "the same nonce must still commit after the endpoint is corrected, \
         which it can only do if the refused call left the replay window \
         empty; got: {committed_json}"
    );
    assert!(
        committed_json["data"]["tx_hash"].as_str().is_some(),
        "the retry must report an on-chain tx_hash: {committed_json}"
    );
}

/// The prepare and the commit send the profile's primary credential on
/// every request, and the creation submits; without the credential each
/// tool ends on the endpoint's 401 with the credential code.
#[tokio::test]
#[serial]
async fn prepare_and_commit_send_the_primary_credential() {
    use stellar_agent_core::profile::schema::ProviderRole;
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(203);
    let seed = [0x5c_u8; 32];
    let source_g = gstrkey_for_seed(seed);
    keyring_core::Entry::new("svc", "acct")
        .expect("Entry::new")
        .set_password(&sstrkey_for_seed(seed))
        .expect("set_password");
    let mock_server = MockServer::start().await;
    crate::common::require_rpc_credential(&mock_server).await;
    Mock::given(method("POST"))
        .respond_with(CreateAccountSubmitSuccessRpcResponder {
            account_key_xdr: account_ledger_key_xdr(&source_g),
            account_xdr: account_entry_xdr_with_balance(&source_g, 100_000_000_000_000),
            network: crate::common::EndpointNetwork::testnet(),
        })
        .mount(&mock_server)
        .await;
    let mut profile = testnet_profile_with_rpc(&mock_server.uri());
    crate::common::bind_rpc_credential(&mut profile, ProviderRole::Primary, true);
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let simulate_args = StellarCreateAccountArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: source_g.clone(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""100 XLM""#).expect("parse amount"),
        classic_base: None,
    };
    let sim_result = server
        .call_stellar_create_account(simulate_args.clone())
        .await
        .expect("simulate must not error");
    assert_ne!(
        sim_result.is_error,
        Some(true),
        "{}",
        call_result_text(&sim_result)
    );
    let sim_data = call_result_json(&sim_result)["data"].clone();
    let commit_args = StellarCreateAccountCommitArgs {
        chain_id: simulate_args.chain_id.clone(),
        source: simulate_args.source.clone(),
        destination: simulate_args.destination.clone(),
        starting_balance: simulate_args.starting_balance.clone(),
        nonce: sim_data["nonce"].as_str().expect("nonce").to_owned(),
        expires_at_unix_ms: sim_data["expires_at_unix_ms"].as_u64().expect("expiry"),
        envelope_xdr: sim_data["envelope_xdr"]
            .as_str()
            .expect("envelope")
            .to_owned(),
        approval_nonce: None,
        approval_attestation: None,
    };
    let committed = server
        .call_stellar_create_account_commit(commit_args.clone())
        .await
        .expect("the commit must not error");
    let committed_json = call_result_json(&committed);
    assert!(
        committed_json["data"]["tx_hash"].is_string(),
        "{committed_json}"
    );
    crate::common::assert_every_request_carried_the_credential(&mock_server).await;

    let bare =
        WalletServer::new(testnet_profile_with_rpc(&mock_server.uri())).expect("WalletServer::new");
    crate::common::assert_credential_refusals(
        &mock_server,
        vec![
            bare.call_stellar_create_account(simulate_args).await,
            bare.call_stellar_create_account_commit(commit_args).await,
        ],
    )
    .await;
}

async fn witness_create_case(amount: &str, mode: &str, expected: &str) {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let _data_root = crate::common::isolated_data_root();
    // The profile's own signer account gives it an audit log no other test
    // writes, so the row counts below are the rows this commit appended.
    let account = crate::common::own_signer_account("witness-create");
    let reads = Arc::new(AtomicUsize::new(0));
    let count = reads.clone();
    keyring_mock::install_with_read_hooks(vec![keyring_mock::ReadHook::new(
        "svc",
        &account,
        Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
        }),
    )])
    .unwrap();
    install_test_nonce_key(245);
    let seed = [0x75; 32];
    let source = gstrkey_for_seed(seed);
    keyring_core::Entry::new("svc", &account)
        .unwrap()
        .set_password(&sstrkey_for_seed(seed))
        .unwrap();
    let primary = MockServer::start().await;
    let oracle = MockServer::start().await;
    for (endpoint, sequence) in [
        (&primary, 100),
        (&oracle, if mode == "source" { 999 } else { 100 }),
    ] {
        let identity = if mode == "identity" && endpoint.uri() == oracle.uri() {
            crate::common::EndpointNetwork::reporting("hostile-identity-marker")
        } else {
            crate::common::EndpointNetwork::testnet()
        };
        Mock::given(method("POST"))
            .respond_with(
                crate::common::TimeoutRpc::new(vec![(
                    account_ledger_key_xdr(&source),
                    account_entry_xdr_with_seq(&source, 100_000_000_000_000, 0, sequence),
                )])
                .confirming_in(1005)
                .with_network(identity),
            )
            .mount(endpoint)
            .await;
    }
    let mut profile = crate::common::testnet_profile_for_account(&primary.uri(), &account);
    profile.oracle_provider_url = (mode != "none").then(|| url::Url::parse(&oracle.uri()).unwrap());
    let server = WalletServer::new(profile.clone()).unwrap();
    let args = StellarCreateAccountArgs {
        source,
        starting_balance: serde_json::from_value(serde_json::json!(amount)).unwrap(),
        ..simulate_args_on("stellar:testnet", None)
    };
    let simulated = server
        .call_stellar_create_account(args.clone())
        .await
        .unwrap();
    assert_ne!(
        simulated.is_error,
        Some(true),
        "{:?}",
        call_result_json(&simulated)
    );
    let data = call_result_json(&simulated)["data"].clone();
    let commit = StellarCreateAccountCommitArgs {
        chain_id: args.chain_id,
        source: args.source,
        destination: args.destination,
        starting_balance: args.starting_balance,
        nonce: data["nonce"].as_str().unwrap().into(),
        expires_at_unix_ms: data["expires_at_unix_ms"].as_u64().unwrap(),
        envelope_xdr: data["envelope_xdr"].as_str().unwrap().into(),
        approval_nonce: None,
        approval_attestation: None,
    };
    assert!(crate::common::received_methods(&oracle).await.is_empty());
    // The prepare ran without a cap; the commit runs on a server whose
    // profile caps the per-operation fee below the envelope's.
    let server = if mode == "cap" {
        let mut capped = profile.clone();
        capped.classic_max_fee_per_op_stroops = Some(50);
        WalletServer::new(capped).unwrap()
    } else {
        server
    };
    let before = reads.load(Ordering::SeqCst);
    let result = server
        .call_stellar_create_account_commit(commit)
        .await
        .unwrap();
    let body = call_result_json(&result);
    if expected.contains('.') {
        let (code, text, _) = crate::common::assert_business_envelope(&result);
        assert_eq!(code, expected, "{body}");
        assert_eq!(reads.load(Ordering::SeqCst), before);
        assert!(
            !crate::common::received_methods(&primary)
                .await
                .iter()
                .any(|m| m == "sendTransaction")
        );
        assert!(!text.contains("hostile-identity-marker"));
        if mode == "identity" {
            assert!(text.contains("serves a network other than the profile's"));
            assert_eq!(
                crate::common::received_methods(&oracle).await,
                ["getNetwork"]
            );
        }
        if mode == "cap" {
            assert_eq!(
                text,
                "the envelope's per-operation fee 100 stroops exceeds the profile cap of 50 \
                 stroops; prepare the transaction again with a fee within the cap"
            );
            assert!(
                crate::common::received_methods(&oracle).await.is_empty(),
                "the cap precedes the witness"
            );
        }
        return;
    }
    assert_ne!(result.is_error, Some(true), "{body}");
    assert_eq!(body["data"]["cross_check"]["status"], expected);
    assert!(
        crate::common::received_methods(&primary)
            .await
            .iter()
            .any(|m| m == "sendTransaction")
    );
    let rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let mut witnesses = Vec::new();
    for kind in ["value_action_pending", "value_action_submitted"] {
        let rows: Vec<_> = rows.iter().filter(|row| row["kind"] == kind).collect();
        assert_eq!(rows.len(), 1, "{kind}: {rows:?}");
        if expected == "passed" {
            assert_eq!(rows[0]["witness"]["provider"], oracle.uri());
            assert_eq!(rows[0]["witness"]["ledger"], 1001);
            assert_eq!(
                rows[0]["witness"]["inputs_digest"].as_str().unwrap().len(),
                64
            );
            assert_eq!(
                rows[0]["witness"]["kinds"],
                serde_json::json!(["source_account"])
            );
            witnesses.push(rows[0]["witness"].clone());
        } else {
            assert!(rows[0].get("witness").is_none());
        }
    }
    if expected == "passed" {
        assert_eq!(witnesses[0], witnesses[1]);
        assert_eq!(body["data"]["cross_check"]["provider"], oracle.uri());
        assert_eq!(body["data"]["cross_check"]["ledger"], 1001);
        assert_eq!(
            crate::common::received_methods(&oracle).await,
            ["getNetwork", "getLedgerEntries"]
        );
    } else {
        assert!(crate::common::received_methods(&oracle).await.is_empty());
        assert_eq!(
            body["data"]["cross_check"]["reason"],
            if expected == "not_required" {
                "below_threshold"
            } else {
                "oracle_not_configured"
            }
        );
    }
}

#[tokio::test]
#[serial]
async fn create_account_commit_rows_carry_witness() {
    witness_create_case("2000 XLM", "match", "passed").await;
}

#[tokio::test]
#[serial]
async fn create_account_commit_source_disagreement_refuses_simulation_divergence() {
    witness_create_case("2000 XLM", "source", "simulation.divergence").await;
}

#[tokio::test]
#[serial]
async fn create_account_commit_oracle_identity_refusal_is_witness_unavailable() {
    witness_create_case("2000 XLM", "identity", "network.witness_unavailable").await;
}

#[tokio::test]
#[serial]
async fn create_account_commit_without_oracle_skips_on_testnet() {
    witness_create_case("2000 XLM", "none", "skipped").await;
}

#[tokio::test]
#[serial]
async fn create_account_commit_below_threshold_is_not_required() {
    witness_create_case("999 XLM", "match", "not_required").await;
}

#[tokio::test]
#[serial]
async fn create_commit_fee_above_cap_refuses_before_the_witness() {
    witness_create_case("2000 XLM", "cap", "fees.percentile_exceeds_cap").await;
}
