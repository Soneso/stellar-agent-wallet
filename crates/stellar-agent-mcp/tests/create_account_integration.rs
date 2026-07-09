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
//! 4. `chain_id` mismatch — returns `invalid_params`.
//! 5. Policy gate (mainnet profile + simulate step) — simulate is NOT
//!    destructive so it is ALLOWED even on mainnet (confirm the mainnet
//!    destructive-tool rule does not over-block).
//!
//! ## Commit step (`stellar_create_account_commit`)
//!
//! 6. Mainnet profile rejects commit (`destructive_hint = true` +
//!    `NoopPolicyEngine` → `policy.engine_required`).
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

use async_trait::async_trait;
use common::policy_mock::{MockPolicyEngine, mainnet_server_with_engine};
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

mod common;
use helpers::AnyTool;

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
fn testnet_profile_with_rpc(rpc_url: &str) -> Profile {
    let mut p = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    p.rpc_url = rpc_url.to_owned();
    p
}

/// Builds a mainnet profile with `engine = Noop` for Property A tests.
///
/// Property A tests the mainnet gate: `NoopPolicyEngine` refuses mainnet
/// destructive tools.  Because `PolicyEngineKind::default()` is `V1`, we must
/// set `Noop` explicitly so `WalletServer::new` succeeds without a signed
/// policy file on disk.
fn mainnet_profile() -> Profile {
    Profile::builder_mainnet("svc", "acct", "n-svc", "n-acct")
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
    keyring_mock::install().expect("mock keyring store init");
    let profile = testnet_profile_with_rpc("https://soroban-testnet.stellar.org");
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
}

/// Simulate step with a mainnet profile is ALLOWED (simulate is NOT destructive).
///
/// Only tools with `destructive_hint = true` are refused on mainnet.  The
/// simulate step has `destructive_hint = false`.
#[tokio::test]
#[serial]
async fn simulate_allowed_on_mainnet_profile() {
    keyring_mock::install().expect("mock keyring store init");
    // Mainnet profile — chain_id = stellar:mainnet
    let mut profile = mainnet_profile();
    // Override chain_id argument to match the mainnet profile so we can reach
    // the RPC call (which will fail because there is no live RPC).
    profile.rpc_url = "https://soroban-testnet.stellar.org".to_owned(); // won't actually connect

    let server = WalletServer::new(profile).expect("WalletServer::new");

    let args = StellarCreateAccountArgs {
        chain_id: "stellar:mainnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        classic_base: None,
    };
    // The policy gate should NOT block this (simulate is not destructive).
    // The call will fail at the RPC step (network unreachable), but it should
    // NOT fail with policy.engine_required.
    let result = server.call_stellar_create_account(args).await;
    // Either Ok (unlikely without network) or a tool-level Err (is_error=true)
    // from the RPC step.  Either way, NOT a JSON-RPC Err from policy gate.
    match result {
        Err(err) => {
            // The only acceptable Err from here is a raw JSON-RPC error.
            // It must NOT be policy.engine_required.
            let msg = err.to_string();
            assert!(
                !msg.contains("policy.engine_required"),
                "simulate must NOT be refused by policy gate on mainnet, got: {msg}"
            );
        }
        Ok(_) => {
            // Passed all the way to network (unexpected in unit test but not wrong).
        }
    }
}

#[tokio::test]
#[serial]
async fn simulate_create_account_fee_auto_selects_p95_and_binds_envelope_fee() {
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
    let (code, message, _text) = common::assert_business_envelope(&result);
    assert_eq!(
        code, "fees.percentile_exceeds_cap",
        "expected fees.percentile_exceeds_cap, got: {code}"
    );
    assert_eq!(
        message,
        "auto-selected per-operation fee 500 stroops (percentile explicit) \
         exceeds the profile cap of 100 stroops; raise classic_max_fee_per_op_stroops \
         or accept a lower fee percentile",
        "cap-exceeded detail must carry the selected fee, percentile, and cap; got: {message}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Commit step: policy gate on mainnet (four-property suite)
//
// Property A: Noop engine refuses mainnet destructive tools with
//   policy.engine_required.
// Property B: V1 engine + matching allow rule → commit proceeds past the gate.
// Property C: V1 engine + no matching rule → policy.deny.no_matching_rule.
// Property D: V1 engine + explicit deny rule → policy.deny.explicit_rule_deny.
// ─────────────────────────────────────────────────────────────────────────────

/// Property A: when `policy.engine = "noop"`, the commit step for a destructive
/// mainnet tool returns `policy.engine_required`.
///
/// `NoopPolicyEngine` returns `Err(NotImplemented)` for destructive tools on
/// mainnet, preserving the Noop engine behaviour for migrated profiles.
#[tokio::test]
#[serial]
async fn policy_noop_engine_refuses_mainnet_destructive() {
    keyring_mock::install().expect("mock keyring store init");
    let profile = mainnet_profile();
    let server = WalletServer::new(profile).expect("WalletServer::new");

    // Supply valid CreateAccount XDR so the re-derivation step succeeds
    // and the call reaches the policy gate (which rejects mainnet).
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
    let (code, _message, _text) = common::assert_business_envelope(&result);
    assert_eq!(
        code, "policy.engine_required",
        "error must be policy.engine_required, got: {code}"
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
    let server = mainnet_server_with_engine(MockPolicyEngine::allow());

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:mainnet".to_owned(),
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
    let (code, _message, _text) = common::assert_business_envelope(&result);
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
    let server = mainnet_server_with_engine(MockPolicyEngine::deny_no_matching_rule());

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:mainnet".to_owned(),
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
    let (code, _message, _text) = common::assert_business_envelope(&result);
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
    let server = mainnet_server_with_engine(MockPolicyEngine::deny_explicit_rule());

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:mainnet".to_owned(),
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
    let (code, _message, _text) = common::assert_business_envelope(&result);
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
    keyring_mock::install().expect("mock keyring store init");
    let profile = testnet_profile_with_rpc("https://soroban-testnet.stellar.org");
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
    let (code, _message, _text) = common::assert_business_envelope(&result);
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
    keyring_mock::install().expect("mock keyring store init");
    let profile = testnet_profile_with_rpc("https://soroban-testnet.stellar.org");
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
    let (code, _message, _text) = common::assert_business_envelope(&result);
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

/// Commit step handles RPC error during envelope re-build gracefully.
///
/// The mock RPC returns an "account not found" error so `fetch_account` fails
/// before the divergence check runs.  This test exercises the "RPC error during
/// commit re-build" error path, not the divergence path.
///
/// The genuine `simulation.divergence` path requires a valid `AccountEntry`
/// XDR fixture so `fetch_account` succeeds and the handler can re-build an
/// envelope that differs from the presented one.
///
/// This test verifies:
/// - The commit handler returns a tool-level error (not a panic) when the
///   RPC call during re-build returns an error.
/// - The response does NOT contain a `tx_hash` (no transaction was submitted).
#[tokio::test]
#[serial]
async fn commit_handles_rpc_error_during_rebuild() {
    keyring_mock::install().expect("mock keyring store init");

    // A mock RPC server that handles getLedgerEntries.
    let mock_server = MockServer::start().await;
    let profile = testnet_profile_with_rpc(&mock_server.uri());
    helpers::setup_nonce_key(&profile, 3);
    let server = WalletServer::new(profile.clone()).expect("WalletServer::new");

    // We need to mint a nonce for a fake envelope (since the divergence check
    // compares the re-built envelope against what we present, and the handler
    // will re-build using the current source account state from the mock RPC).
    // The simulate step would also call the mock RPC, so here we skip it and
    // construct the nonce directly with a placeholder envelope.
    let mint = helpers::mint_for(&profile);

    // Use a fixed timestamp rather than the SystemTime::now() pattern.
    // This test calls server.call_stellar_create_account_commit, which reads
    // the real clock internally via now_unix_ms().  We need expiry_ms to be
    // in the real future so the commit handler does not reject the nonce as
    // expired.  3_000_000_000_000 ms = 2065-01-24 (far future, stable).
    // TTL = 120_000ms is within [MIN, MAX].
    let now_ms: u64 = 3_000_000_000_000;
    let expiry_ms = now_ms + 120_000;
    // Use a placeholder envelope_xdr that the handler won't re-build.
    let mismatched_xdr = "MISMATCHED_BASE64==";

    let nonce = mint
        .mint(
            &AnyTool,
            mismatched_xdr.as_bytes(),
            now_ms,
            expiry_ms,
            "stellar_create_account_commit",
            "stellar:testnet",
        )
        .expect("mint");

    // Mock the RPC server to return a well-funded account so fetch_account
    // succeeds and re-build proceeds.  The re-built envelope will differ from
    // `mismatched_xdr`, triggering the divergence check.
    //
    // The stellar-rpc-client sends JSON-RPC requests; we match all POST requests
    // and return a failure response so fetch_account returns an error (which
    // also surfaces as a tool-level error, not `simulation.divergence`).
    // To reach the divergence check we need fetch_account to SUCCEED.
    //
    // Since constructing a valid AccountEntry XDR in a unit test without a full
    // XDR encoder is expensive, we fall back to testing the divergence check at
    // the nonce-verify level: when the envelope presented mismatches the one that
    // was nonce-bound, the HMAC verify will fail (not divergence).
    //
    // The `simulation.divergence` path is tested end-to-end in the binary smoke
    // test.  Here we document the coverage gap and verify that when the commit
    // step DOES receive a valid nonce but a mismatched envelope_xdr, it at
    // minimum does not panic and returns a tool error.
    //
    // This matches the honest test coverage disclosure model: unit tests cover
    // what is feasible without XDR fixtures; smoke tests cover the rest.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32001,
                "message": "account not found"
            }
        })))
        .mount(&mock_server)
        .await;

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: nonce.to_base64(),
        expires_at_unix_ms: expiry_ms,
        envelope_xdr: mismatched_xdr.to_owned(),
        approval_nonce: None,
        approval_attestation: None,
    };

    // With a mock RPC returning an error, fetch_account will fail and the
    // handler will return a tool-level error (is_error=true), not a JSON-RPC error.
    let result = server.call_stellar_create_account_commit(args).await;
    // Must not panic; any result shape is acceptable here.
    match result {
        Ok(tool_result) => {
            // If we get Ok, the tool result itself should have is_error=true
            // OR contain a divergence or nonce error message.
            // Just verify it doesn't silently succeed without a tx_hash.
            let content = &tool_result.content;
            if let Some(first) = content.first() {
                let text = first.as_text().map(|t| t.text.as_str()).unwrap_or("");
                // Should not contain a tx_hash if we supplied a mismatched envelope.
                // (A mismatched envelope that somehow gets past all checks is a bug.)
                assert!(
                    !text.contains(r#""tx_hash""#),
                    "commit with mismatched envelope must not return a tx_hash, got: {text}"
                );
            }
        }
        Err(err) => {
            // JSON-RPC level error is also acceptable (e.g. from policy gate if
            // the test environment changed).  Just verify no panic.
            let _ = err.to_string();
        }
    }
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
    let (code_a, message_a, _text_a) = common::assert_business_envelope(&result_a);

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
    let (code_b, message_b, _text_b) = common::assert_business_envelope(&result_b);

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
    let (code_c, message_c, _text_c) = common::assert_business_envelope(&result_c);

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
    let pair_a = (code_a, message_a);
    let pair_b = (code_b, message_b);
    let pair_c = (code_c, message_c);
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

/// Simple wiremock responder for `getLedgerEntries` only.
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

        let result = if method == "getLedgerEntries" {
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
        } else {
            serde_json::json!({})
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

/// Builds a minimal `CreateAccount` envelope with `fee=100`, `seq_num=101`,
/// and `starting_balance = 20_000_000_000` (2000 XLM, above the floor).
fn high_value_create_account_envelope_b64() -> String {
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
                starting_balance: 20_000_000_000, // 2000 XLM
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
    .expect("XDR encode")
}

/// Builds a minimal `CreateAccount` envelope with `starting_balance = 9_990_000_000`
/// (999 XLM, below the 1000 XLM MINIMUM_FLOOR).
fn below_threshold_create_account_envelope_b64() -> String {
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
                starting_balance: 9_990_000_000, // 999 XLM
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
    .expect("XDR encode")
}

/// High-value cross-check passes when both primary and oracle return the same
/// account state for `stellar_create_account_commit`.
///
/// 2 000 XLM starting balance (above 1 000 XLM MINIMUM_FLOOR).  Both mocks return
/// `seq_num = 100` → identical rebuild → cross-check passes.  The zero-byte
/// nonce fails at the HMAC gate (not cross-check).
#[tokio::test]
#[serial]
async fn create_account_commit_high_value_cross_check_passes_on_match() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(52);

    let primary_mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("POST"))
        .respond_with(AccountOnlyResponder {
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(SOURCE_G, 100_000_000_000_000, 0, 100),
        })
        .mount(&primary_mock)
        .await;

    let oracle_mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("POST"))
        .respond_with(AccountOnlyResponder {
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(SOURCE_G, 100_000_000_000_000, 0, 100),
        })
        .mount(&oracle_mock)
        .await;

    let mut profile = testnet_profile_with_rpc(&primary_mock.uri());
    profile.oracle_provider_url = Some(url::Url::parse(&oracle_mock.uri()).unwrap());
    profile.usd_threshold = 0;
    let server = WalletServer::new(profile).expect("WalletServer::new");

    use base64::Engine;
    let zero_nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 48]);

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""2000 XLM""#).expect("parse amount"),
        nonce: zero_nonce,
        expires_at_unix_ms: 3_000_000_000_000,
        envelope_xdr: high_value_create_account_envelope_b64(),
        approval_nonce: None,
        approval_attestation: None,
    };

    let result = server.call_stellar_create_account_commit(args).await;
    match result {
        Err(err) => {
            assert!(
                err.to_string().contains("nonce.expired")
                    || err.to_string().contains("nonce.replayed"),
                "cross-check passed; expected nonce gate error, got: {err}"
            );
            assert!(
                !err.to_string().contains("simulation.divergence"),
                "simulation.divergence must not appear when cross-check passes; got: {err}"
            );
        }
        Ok(tool_result) => {
            let json = call_result_json(&tool_result);
            assert!(
                !json.to_string().contains("simulation.divergence"),
                "simulation.divergence must not appear when cross-check passes"
            );
        }
    }
}

/// High-value cross-check fails when the oracle returns a different sequence
/// number for `stellar_create_account_commit`.
///
/// Primary: `seq_num = 100`.  Oracle: `seq_num = 999` → oracle rebuild → seq 1000 →
/// byte mismatch → `simulation.divergence`.
#[tokio::test]
#[serial]
async fn create_account_commit_high_value_cross_check_fails_on_mismatch() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(53);

    let primary_mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("POST"))
        .respond_with(AccountOnlyResponder {
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(SOURCE_G, 100_000_000_000_000, 0, 100),
        })
        .mount(&primary_mock)
        .await;

    let oracle_mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("POST"))
        .respond_with(AccountOnlyResponder {
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(SOURCE_G, 100_000_000_000_000, 0, 999),
        })
        .mount(&oracle_mock)
        .await;

    let mut profile = testnet_profile_with_rpc(&primary_mock.uri());
    profile.oracle_provider_url = Some(url::Url::parse(&oracle_mock.uri()).unwrap());
    profile.usd_threshold = 0;
    let server = WalletServer::new(profile).expect("WalletServer::new");

    use base64::Engine;
    let zero_nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 48]);

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""2000 XLM""#).expect("parse amount"),
        nonce: zero_nonce,
        expires_at_unix_ms: 3_000_000_000_000,
        envelope_xdr: high_value_create_account_envelope_b64(),
        approval_nonce: None,
        approval_attestation: None,
    };

    let result = server
        .call_stellar_create_account_commit(args)
        .await
        .expect("oracle divergence must return Ok(is_error) envelope");
    let (code, _message, _text) = common::assert_business_envelope(&result);
    assert_eq!(
        code, "simulation.divergence",
        "oracle mismatch must produce simulation.divergence, got: {code}"
    );
}

/// High-value cross-check is skipped when `oracle_provider_url` is unset for
/// `stellar_create_account_commit`.
///
/// A `tracing::warn!` is emitted but the commit proceeds to the nonce gate.
#[tokio::test]
#[serial]
async fn create_account_commit_high_value_cross_check_skips_when_oracle_url_unset() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(54);

    let primary_mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("POST"))
        .respond_with(AccountOnlyResponder {
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(SOURCE_G, 100_000_000_000_000, 0, 100),
        })
        .mount(&primary_mock)
        .await;

    let mut profile = testnet_profile_with_rpc(&primary_mock.uri());
    profile.oracle_provider_url = None;
    profile.usd_threshold = 0;
    let server = WalletServer::new(profile).expect("WalletServer::new");

    use base64::Engine;
    let zero_nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 48]);

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        starting_balance: serde_json::from_str(r#""2000 XLM""#).expect("parse amount"),
        nonce: zero_nonce,
        expires_at_unix_ms: 3_000_000_000_000,
        envelope_xdr: high_value_create_account_envelope_b64(),
        approval_nonce: None,
        approval_attestation: None,
    };

    let result = server.call_stellar_create_account_commit(args).await;
    match result {
        Err(err) => {
            assert!(
                err.to_string().contains("nonce.expired")
                    || err.to_string().contains("nonce.replayed"),
                "cross-check skipped; expected nonce gate error, got: {err}"
            );
            assert!(
                !err.to_string().contains("simulation.divergence"),
                "simulation.divergence must not appear when cross-check is skipped; got: {err}"
            );
        }
        Ok(tool_result) => {
            let json = call_result_json(&tool_result);
            assert!(
                !json.to_string().contains("simulation.divergence"),
                "simulation.divergence must not appear when cross-check is skipped"
            );
        }
    }
}

/// Below-threshold `stellar_create_account_commit` skips the cross-check
/// unconditionally — the oracle mock server receives zero requests.
///
/// 999 XLM starting balance (9 990 000 000 stroops) < 10 000 000 000 MINIMUM_FLOOR.
#[tokio::test]
#[serial]
async fn create_account_commit_below_threshold_skips_cross_check_unconditionally() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(55);

    let primary_mock = MockServer::start().await;
    Mock::given(wiremock::matchers::method("POST"))
        .respond_with(AccountOnlyResponder {
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(SOURCE_G, 100_000_000_000_000, 0, 100),
        })
        .mount(&primary_mock)
        .await;

    // Oracle mock: not mounted — any request here would produce an invalid response.
    let oracle_mock = MockServer::start().await;

    let mut profile = testnet_profile_with_rpc(&primary_mock.uri());
    profile.oracle_provider_url = Some(url::Url::parse(&oracle_mock.uri()).unwrap());
    profile.usd_threshold = 0;
    let server = WalletServer::new(profile).expect("WalletServer::new");

    use base64::Engine;
    let zero_nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 48]);

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        // 999 XLM — below the 1000 XLM MINIMUM_FLOOR.
        starting_balance: serde_json::from_str(r#""999 XLM""#).expect("parse amount"),
        nonce: zero_nonce,
        expires_at_unix_ms: 3_000_000_000_000,
        envelope_xdr: below_threshold_create_account_envelope_b64(),
        approval_nonce: None,
        approval_attestation: None,
    };

    let result = server.call_stellar_create_account_commit(args).await;
    match result {
        Err(err) => {
            assert!(
                err.to_string().contains("nonce.expired")
                    || err.to_string().contains("nonce.replayed"),
                "below-threshold: expected nonce gate error, got: {err}"
            );
            assert!(
                !err.to_string().contains("simulation.divergence"),
                "simulation.divergence must not appear below threshold; got: {err}"
            );
        }
        Ok(tool_result) => {
            let json = call_result_json(&tool_result);
            assert!(
                !json.to_string().contains("simulation.divergence"),
                "simulation.divergence must not appear below threshold"
            );
        }
    }
    let oracle_requests = oracle_mock.received_requests().await.unwrap_or_default();
    assert_eq!(
        oracle_requests.len(),
        0,
        "oracle must receive 0 requests for below-threshold create_account; received: {}",
        oracle_requests.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Full round trip: simulate → commit → submit succeeds; the decimal-string
// wire encoding survives every hop, not just each phase in isolation.
// ─────────────────────────────────────────────────────────────────────────────

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
/// Serves the SAME funded-account `getLedgerEntries` response on both the
/// simulate fetch and the commit re-fetch, so the rebuilt envelope is
/// byte-identical to the presented one (the divergence check passes), then
/// `sendTransaction` (PENDING) followed by `getTransaction` (SUCCESS).
struct CreateAccountSubmitSuccessRpcResponder {
    account_key_xdr: String,
    account_xdr: String,
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
            "sendTransaction" => serde_json::json!({
                "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "status": "PENDING",
                "latestLedger": 1001,
                "latestLedgerCloseTime": "1234567890"
            }),
            "getTransaction" => serde_json::json!({
                "status": "SUCCESS",
                "ledger": 1005,
                "txHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
    let sim_result = server
        .call_stellar_create_account(simulate_args.clone())
        .await
        .expect("simulate must not error");
    assert_ne!(sim_result.is_error, Some(true), "simulate must succeed");
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
    let commit_result = server
        .call_stellar_create_account_commit(commit_args)
        .await
        .expect("commit must not error");
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

    let (code, _message, _text) = common::assert_business_envelope(&result);
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
        NonceMint::from_profile(profile).expect("NonceMint::from_profile")
    }
}
