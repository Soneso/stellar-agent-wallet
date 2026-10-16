//! Integration tests for `stellar_create_account_commit` authoritative-args
//! re-derivation.
//!
//! Verifies that the commit handler decodes the HMAC-bound `envelope_xdr` and
//! passes those authoritative values to the policy engine, not the
//! caller-supplied args.  This enforces policy-evaluation order: the policy
//! engine evaluates the XDR-authoritative values, never the caller-supplied
//! fields.
//!
//! # Test coverage
//!
//! 1. `envelope_xdr` that encodes a `Payment` op presented to
//!    `stellar_create_account_commit` → `simulation.divergence` (op-kind
//!    mismatch before the policy engine even sees args).
//!
//! 2. `envelope_xdr` that is valid XDR but encodes a `CreateAccount` to
//!    `G_REAL_DEST` while caller args supply `destination = G_ATTACKER` →
//!    the policy engine sees `G_REAL_DEST` from the XDR, not `G_ATTACKER`.
//!    An engine that records what it evaluates shows the destination it saw,
//!    and the call proceeds to the nonce step, which fails with
//!    `nonce.expired` because the nonce ("dGVzdA") is a trivially-invalid
//!    stub.
//!
//! 3. Caller supplies `starting_balance = "999 XLM"` while the XDR encodes
//!    `starting_balance = 1 XLM` (10_000_000 stroops) → the policy engine
//!    receives the XDR-authoritative `starting_balance_stroops = 10_000_000`,
//!    not the attacker-inflated caller value. The recording engine shows the
//!    balance it saw; the outcome is again `nonce.expired`.
//!
//! # Keyring isolation
//!
//! All tests install the mock keyring store before constructing `WalletServer`
//! and are serialised via `#[serial]`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{StellarCreateAccountCommitArgs, WalletServer};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_seq, account_ledger_key_xdr,
};
use stellar_xdr::{
    AccountId, Asset, CreateAccountOp, Limits, Memo, MuxedAccount, Operation, OperationBody,
    PaymentOp, Preconditions, PublicKey, SequenceNumber, Transaction, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer};

// ─────────────────────────────────────────────────────────────────────────────
// Fixture constants
// ─────────────────────────────────────────────────────────────────────────────

/// Source account G-strkey (seed [1u8;32] canonical test vector).
const SOURCE_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

/// The destination G-strkey encoded in the XDR envelope (the allowed one).
const G_REAL_DEST: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

/// An attacker-controlled destination G-strkey supplied in caller args.
/// Must differ from `G_REAL_DEST` to prove the divergence.
const G_ATTACKER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

// ─────────────────────────────────────────────────────────────────────────────
// XDR fixture helpers
// ─────────────────────────────────────────────────────────────────────────────

fn g_to_bytes(g: &str) -> [u8; 32] {
    stellar_strkey::ed25519::PublicKey::from_string(g)
        .expect("valid G-strkey")
        .0
}

fn g_to_muxed(g: &str) -> MuxedAccount {
    MuxedAccount::Ed25519(Uint256(g_to_bytes(g)))
}

fn g_to_account_id(g: &str) -> AccountId {
    AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(g_to_bytes(g))))
}

/// Builds a `TransactionV1Envelope` with a single `CreateAccount` operation,
/// serialised to base64.
fn create_account_envelope_b64(dest: &str, starting_balance: i64) -> String {
    let tx = Transaction {
        source_account: g_to_muxed(SOURCE_G),
        fee: 100,
        seq_num: SequenceNumber(101),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: g_to_account_id(dest),
                starting_balance,
            }),
        }]
        .try_into()
        .expect("single-op vec"),
        ext: TransactionExt::V0,
    };
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });
    env.to_xdr_base64(Limits::none())
        .expect("XDR encode must succeed")
}

/// Builds a `TransactionV1Envelope` with a single `Payment` operation,
/// serialised to base64.
fn payment_envelope_b64(dest: &str, amount: i64) -> String {
    let tx = Transaction {
        source_account: g_to_muxed(SOURCE_G),
        fee: 100,
        seq_num: SequenceNumber(101),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: g_to_muxed(dest),
                asset: Asset::Native,
                amount,
            }),
        }]
        .try_into()
        .expect("single-op vec"),
        ext: TransactionExt::V0,
    };
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });
    env.to_xdr_base64(Limits::none())
        .expect("XDR encode must succeed")
}

// ─────────────────────────────────────────────────────────────────────────────
// Profile helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Testnet profile with `engine = Noop` for test isolation.
///
/// Explicitly sets `Noop` so `WalletServer::new` succeeds without a signed
/// policy file on disk (`PolicyEngineKind::default()` is `V1`, which requires
/// a signed policy file and a keyring owner-key entry).
fn testnet_profile() -> Profile {
    Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build()
}

/// A server on a local endpoint that reports testnet and answers for the
/// funded `SOURCE_G` account, with an engine that allows and records what it
/// evaluates. Returns the endpoint too, which must outlive the calls.
async fn recording_server() -> (
    WalletServer,
    crate::common::policy_mock::CapturingPolicyEngine,
    MockServer,
) {
    let endpoint = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(crate::common::TimeoutRpc::new(vec![(
            account_ledger_key_xdr(SOURCE_G),
            account_entry_xdr_with_seq(SOURCE_G, 100_000_000_000_000, 0, 100),
        )]))
        .mount(&endpoint)
        .await;
    let mut profile = testnet_profile();
    profile.rpc_url = endpoint.uri();
    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    let engine = crate::common::policy_mock::CapturingPolicyEngine::new();
    server.set_policy_engine_for_test(std::sync::Arc::new(engine.clone()));
    (server, engine, endpoint)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Payment XDR presented to stellar_create_account_commit →
// simulation.divergence
//
// The commit handler re-derives args from the XDR first.  A Payment op in a
// stellar_create_account_commit call is an OperationKindMismatch →
// simulation.divergence.  This fires before the nonce is touched.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn create_account_commit_with_payment_xdr_returns_simulation_divergence() {
    keyring_mock::install().expect("mock keyring store init");
    let server = WalletServer::new(testnet_profile()).expect("WalletServer::new");

    // envelope_xdr encodes a Payment op.
    let envelope_xdr = payment_envelope_b64(G_REAL_DEST, 10_000_000);

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: G_REAL_DEST.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: "dGVzdA".to_owned(),
        expires_at_unix_ms: u64::MAX,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    };

    let result = server
        .call_stellar_create_account_commit(args)
        .await
        .expect("Payment XDR must return Ok(is_error) envelope");
    let (code, _message, _text) = crate::common::assert_business_envelope(&result);
    assert_eq!(
        code, "simulation.divergence",
        "error must be simulation.divergence (op-kind mismatch); got: {code}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: Caller supplies attacker destination; XDR encodes real destination
//
// With authoritative args re-derivation, the policy engine receives the XDR-
// encoded `G_REAL_DEST` as `destination`, not the caller-supplied `G_ATTACKER`.
// The testnet `NoopPolicyEngine` returns Allow for non-mainnet destructive
// tools.  The call proceeds past the policy gate to the nonce verification
// step, which fails with `nonce.expired` because the nonce ("dGVzdA") is a
// trivially-invalid stub — NOT `policy.engine_required` or a `policy.deny`.
//
// This confirms the args flow through re-derivation (if they weren't, the
// behaviour might differ on mainnet where the policy engine rejects).
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn create_account_commit_policy_engine_sees_xdr_destination_not_caller_destination() {
    keyring_mock::install().expect("mock keyring store init");
    let (server, engine, _endpoint) = recording_server().await;

    // envelope_xdr encodes G_REAL_DEST; caller args claim G_ATTACKER.
    let envelope_xdr = create_account_envelope_b64(G_REAL_DEST, 10_000_000);

    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: G_ATTACKER.to_owned(), // attacker-controlled field
        starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
        nonce: "dGVzdA".to_owned(), // invalid stub → nonce.expired after policy gate
        expires_at_unix_ms: u64::MAX,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    };

    let result = server
        .call_stellar_create_account_commit(args)
        .await
        .expect("the nonce refusal is a tool result, not a protocol error");
    let (code, _message, text) = crate::common::assert_business_envelope(&result);
    assert_eq!(
        code, "nonce.expired",
        "the call passes the gate and fails at the nonce step: {text}"
    );
    let evaluated = engine.arguments_for("stellar_create_account_commit");
    assert_eq!(
        evaluated.len(),
        1,
        "the gate evaluates the commit once: {evaluated:?}"
    );
    assert_eq!(
        evaluated[0]["destination"], G_REAL_DEST,
        "the gate evaluates the destination the envelope encodes, not the caller's: {evaluated:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: Caller supplies inflated starting_balance; XDR encodes real balance
//
// The attacker submits `starting_balance = "999 XLM"` in caller args while the
// XDR encodes 1 XLM (10_000_000 stroops).  With authoritative re-derivation,
// the policy engine receives `starting_balance_stroops = 10_000_000` (the
// XDR-encoded value), not the attacker-inflated 9_990_000_000.
//
// The testnet NoopPolicyEngine allows any amount on testnet, so the call
// proceeds to nonce verification and fails with `nonce.expired` — NOT a policy
// cap denial or `simulation.divergence`.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn create_account_commit_policy_engine_sees_xdr_balance_not_caller_balance() {
    keyring_mock::install().expect("mock keyring store init");
    let (server, engine, _endpoint) = recording_server().await;

    // XDR encodes 1 XLM (10_000_000 stroops) as the starting balance.
    let envelope_xdr = create_account_envelope_b64(G_REAL_DEST, 10_000_000);

    // Caller supplies an attacker-controlled inflated starting_balance.
    let args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: G_REAL_DEST.to_owned(),
        starting_balance: serde_json::from_str(r#""999 XLM""#).unwrap(), // attacker-inflated
        nonce: "dGVzdA".to_owned(), // invalid stub → nonce.expired after policy gate
        expires_at_unix_ms: u64::MAX,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    };

    let result = server
        .call_stellar_create_account_commit(args)
        .await
        .expect("the nonce refusal is a tool result, not a protocol error");
    let (code, _message, text) = crate::common::assert_business_envelope(&result);
    assert_eq!(
        code, "nonce.expired",
        "the call passes the gate and fails at the nonce step: {text}"
    );
    let evaluated = engine.arguments_for("stellar_create_account_commit");
    assert_eq!(
        evaluated.len(),
        1,
        "the gate evaluates the commit once: {evaluated:?}"
    );
    assert_eq!(
        evaluated[0]["starting_balance_stroops"], "10000000",
        "the gate evaluates the balance the envelope encodes, not the caller's: {evaluated:?}"
    );
}
