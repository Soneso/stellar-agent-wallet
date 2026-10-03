//! The commit tools, the rule-commit tool, and the SEP-43 sign-and-submit tool
//! refuse a mainnet context at entry.
//!
//! Each case runs on the Noop engine and, as a separate test, on an engine
//! that allows every call, so the refusal is shown to precede the policy gate
//! whatever its verdict. The profile endpoint is a mock server that must
//! receive no request. No keyring mock is installed: the refusal precedes
//! every key access. The envelopes are well formed, so a call that passed the
//! refusal would reach the policy gate and beyond.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only fixture construction and assertions"
)]

use std::sync::Arc;

use rmcp::model::CallToolResult;
use stellar_agent_core::profile::Profile;
use stellar_xdr::{
    AccountId, AlphaNum4, AssetCode4, ChangeTrustAsset, ChangeTrustOp, ClaimClaimableBalanceOp,
    ClaimableBalanceId, CreateAccountOp, Hash, Limits, Memo, MuxedAccount, Operation,
    OperationBody, PaymentOp, Preconditions, PublicKey, SequenceNumber, Transaction,
    TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

use crate::server::WalletServer;
use crate::tools::common::{AllowAllPolicyEngine, assert_mainnet_write_forbidden};

const SOURCE_G: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// A mainnet server on the Noop engine whose endpoint is `rpc`, or on an
/// allow-all engine when `allow_all` holds.
fn mainnet_server(rpc: &str, allow_all: bool) -> WalletServer {
    let profile = Profile::builder_mainnet_named("refusal", rpc, "s", "default", "n", "a")
        .with_noop_engine()
        .build();
    let mut server = WalletServer::new(profile).unwrap();
    if allow_all {
        server.policy_engine = Arc::new(AllowAllPolicyEngine);
    }
    server
}

fn g_bytes(g: &str) -> [u8; 32] {
    stellar_strkey::ed25519::PublicKey::from_string(g)
        .unwrap()
        .0
}

/// A single-operation V1 envelope from [`SOURCE_G`], base64 encoded.
fn envelope(body: OperationBody) -> String {
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(g_bytes(SOURCE_G))),
        fee: 100,
        seq_num: SequenceNumber(101),
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

fn payment_envelope() -> String {
    envelope(OperationBody::Payment(PaymentOp {
        destination: MuxedAccount::Ed25519(Uint256(g_bytes(DEST_G))),
        asset: stellar_xdr::Asset::Native,
        amount: 100_000_000,
    }))
}

/// Asserts the canonical refusal and that `rpc` received no request.
async fn assert_refused_without_requests(
    rpc: &wiremock::MockServer,
    result: Result<CallToolResult, rmcp::ErrorData>,
) {
    let result =
        result.unwrap_or_else(|e| panic!("the mainnet refusal is a business envelope, got {e:?}"));
    assert_mainnet_write_forbidden(&result);
    let received = rpc.received_requests().await.unwrap();
    assert!(
        received.is_empty(),
        "a refused mainnet call must send no request; got {}",
        received.len()
    );
}

async fn pay_commit_case(allow_all: bool) {
    let rpc = wiremock::MockServer::start().await;
    let server = mainnet_server(&rpc.uri(), allow_all);
    let args = serde_json::from_value(serde_json::json!({
        "chain_id": "stellar:mainnet",
        "source": SOURCE_G,
        "destination": DEST_G,
        "amount": "10 XLM",
        "asset": "native",
        "nonce": "dGVzdA",
        "expires_at_unix_ms": u64::MAX,
        "envelope_xdr": payment_envelope()
    }))
    .unwrap();
    let result = server.call_stellar_pay_commit(args).await;
    assert_refused_without_requests(&rpc, result).await;
}

#[tokio::test]
async fn pay_commit_refuses_mainnet_at_entry_on_noop_engine() {
    pay_commit_case(false).await;
}

#[tokio::test]
async fn pay_commit_refuses_mainnet_at_entry_under_allow_all_engine() {
    pay_commit_case(true).await;
}

async fn create_account_commit_case(allow_all: bool) {
    let rpc = wiremock::MockServer::start().await;
    let server = mainnet_server(&rpc.uri(), allow_all);
    let envelope_xdr = envelope(OperationBody::CreateAccount(CreateAccountOp {
        destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(g_bytes(DEST_G)))),
        starting_balance: 10_000_000,
    }));
    let args = serde_json::from_value(serde_json::json!({
        "chain_id": "stellar:mainnet",
        "source": SOURCE_G,
        "destination": DEST_G,
        "starting_balance": "1 XLM",
        "nonce": "dGVzdA",
        "expires_at_unix_ms": u64::MAX,
        "envelope_xdr": envelope_xdr
    }))
    .unwrap();
    let result = server.call_stellar_create_account_commit(args).await;
    assert_refused_without_requests(&rpc, result).await;
}

#[tokio::test]
async fn create_account_commit_refuses_mainnet_at_entry_on_noop_engine() {
    create_account_commit_case(false).await;
}

#[tokio::test]
async fn create_account_commit_refuses_mainnet_at_entry_under_allow_all_engine() {
    create_account_commit_case(true).await;
}

async fn trustline_commit_case(allow_all: bool) {
    let rpc = wiremock::MockServer::start().await;
    let server = mainnet_server(&rpc.uri(), allow_all);
    let envelope_xdr = envelope(OperationBody::ChangeTrust(ChangeTrustOp {
        line: ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USDC"),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(g_bytes(DEST_G)))),
        }),
        limit: i64::MAX,
    }));
    let args = serde_json::from_value(serde_json::json!({
        "chain_id": "stellar:mainnet",
        "from": SOURCE_G,
        "nonce": "dGVzdA",
        "expires_at_unix_ms": u64::MAX,
        "envelope_xdr": envelope_xdr
    }))
    .unwrap();
    let result = server.call_stellar_trustline_commit(args).await;
    assert_refused_without_requests(&rpc, result).await;
}

#[tokio::test]
async fn trustline_commit_refuses_mainnet_at_entry_on_noop_engine() {
    trustline_commit_case(false).await;
}

#[tokio::test]
async fn trustline_commit_refuses_mainnet_at_entry_under_allow_all_engine() {
    trustline_commit_case(true).await;
}

async fn claim_commit_case(allow_all: bool) {
    let rpc = wiremock::MockServer::start().await;
    let server = mainnet_server(&rpc.uri(), allow_all);
    let envelope_xdr = envelope(OperationBody::ClaimClaimableBalance(
        ClaimClaimableBalanceOp {
            balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([7u8; 32])),
        },
    ));
    let args = serde_json::from_value(serde_json::json!({
        "chain_id": "stellar:mainnet",
        "balance_id": format!("00000000{}", "07".repeat(32)),
        "nonce": "dGVzdA",
        "expires_at_unix_ms": u64::MAX,
        "envelope_xdr": envelope_xdr
    }))
    .unwrap();
    let result = server.call_stellar_claim_commit(args).await;
    assert_refused_without_requests(&rpc, result).await;
}

#[tokio::test]
async fn claim_commit_refuses_mainnet_at_entry_on_noop_engine() {
    claim_commit_case(false).await;
}

#[tokio::test]
async fn claim_commit_refuses_mainnet_at_entry_under_allow_all_engine() {
    claim_commit_case(true).await;
}

async fn rule_create_commit_case(allow_all: bool) {
    let rpc = wiremock::MockServer::start().await;
    let server = mainnet_server(&rpc.uri(), allow_all);
    let args = serde_json::from_value(serde_json::json!({
        "chain_id": "stellar:mainnet",
        "approval_nonce": "any-nonce"
    }))
    .unwrap();
    let result = server.call_stellar_rule_create_commit(args).await;
    assert_refused_without_requests(&rpc, result).await;
}

/// A mainnet context over a testnet profile and a testnet `chain_id`
/// argument refuses with the canonical code. The argument check that follows
/// the entry refusal keys on the caller's `chain_id` and passes here, so this
/// case pins the refusal that keys on the context.
#[tokio::test]
async fn rule_create_commit_refuses_a_mainnet_context_over_a_testnet_argument() {
    let rpc = wiremock::MockServer::start().await;
    let profile = Profile::builder_testnet_named("refusal", "s", "default", "n", "a")
        .rpc_url(rpc.uri())
        .with_noop_engine()
        .build();
    let mut server = WalletServer::new(profile).unwrap();
    server.context = stellar_agent_network::NetworkContext::new(
        stellar_agent_core::profile::caip2::Caip2::Mainnet,
        rpc.uri(),
    );
    let args = serde_json::from_value(serde_json::json!({
        "chain_id": "stellar:testnet",
        "approval_nonce": "any-nonce"
    }))
    .unwrap();
    let result = server.call_stellar_rule_create_commit(args).await;
    assert_refused_without_requests(&rpc, result).await;
}

#[tokio::test]
async fn rule_create_commit_refuses_mainnet_at_entry_on_noop_engine() {
    rule_create_commit_case(false).await;
}

#[tokio::test]
async fn rule_create_commit_refuses_mainnet_at_entry_under_allow_all_engine() {
    rule_create_commit_case(true).await;
}

async fn sep43_sign_and_submit_case(allow_all: bool) {
    let rpc = wiremock::MockServer::start().await;
    let server = mainnet_server(&rpc.uri(), allow_all);
    let args = serde_json::from_value(serde_json::json!({
        "chain_id": "stellar:mainnet",
        "transaction_xdr": payment_envelope()
    }))
    .unwrap();
    let result = server
        .call_stellar_sep43_sign_and_submit_transaction(args)
        .await;
    assert_refused_without_requests(&rpc, result).await;
}

#[tokio::test]
async fn sep43_sign_and_submit_refuses_mainnet_at_entry_on_noop_engine() {
    sep43_sign_and_submit_case(false).await;
}

#[tokio::test]
async fn sep43_sign_and_submit_refuses_mainnet_at_entry_under_allow_all_engine() {
    sep43_sign_and_submit_case(true).await;
}
