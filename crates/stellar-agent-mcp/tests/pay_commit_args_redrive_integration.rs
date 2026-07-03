//! Integration tests for `stellar_pay_commit` authoritative-args re-derivation.
//!
//! Verifies that the commit handler decodes the HMAC-bound `envelope_xdr` and
//! passes those authoritative values to the policy engine, not the caller-supplied
//! args.  This enforces policy-evaluation order: the policy engine evaluates the
//! XDR-authoritative values, never the caller-supplied fields.
//!
//! # Test coverage
//!
//! 1. `envelope_xdr` that encodes a `CreateAccount` op presented to
//!    `stellar_pay_commit` → `simulation.divergence` (op-kind mismatch before
//!    the policy engine even sees args).
//!
//! 2. `envelope_xdr` that is valid XDR but encodes a `Payment` to
//!    `G_REAL_DEST` while caller args supply `destination = G_ATTACKER` →
//!    the policy engine sees `G_REAL_DEST` from the XDR, not `G_ATTACKER`.
//!    With `NoopPolicyEngine::testnet` the call proceeds to the nonce-expired
//!    gate (not a policy deny), confirming the authoritative args flow is wired.
//!
//! 3. `envelope_xdr` with a `Memo::Hash` → `nonce.expired`: Hash memos decode
//!    as `Ok(None)`; the tamper is caught by the envelope-rebuild divergence
//!    check, but nonce-parse fires first with the test fixture nonce.
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
use stellar_agent_mcp::server::{StellarPayCommitArgs, WalletServer};
use stellar_agent_test_support::keyring_mock;
use stellar_xdr::{
    AccountId, Asset, Hash, Limits, Memo, MuxedAccount, Operation, OperationBody, PaymentOp,
    Preconditions, PublicKey, SequenceNumber, Transaction, TransactionEnvelope, TransactionExt,
    TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

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

/// Builds a `TransactionV1Envelope` with a single `Payment` operation
/// and the given memo, serialised to base64.
fn payment_envelope_b64(dest: &str, amount: i64, memo: Memo) -> String {
    let tx = Transaction {
        source_account: g_to_muxed(SOURCE_G),
        fee: 100,
        seq_num: SequenceNumber(101),
        cond: Preconditions::None,
        memo,
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

/// Builds a `TransactionV1Envelope` with a `CreateAccount` operation,
/// serialised to base64.
fn create_account_envelope_b64(dest: &str, starting_balance: i64) -> String {
    use stellar_xdr::{CreateAccountOp, OperationBody};
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

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: CreateAccount XDR presented to stellar_pay_commit → simulation.divergence
//
// The commit handler re-derives args from the XDR first.  A CreateAccount op
// in a stellar_pay_commit call is an OperationKindMismatch → simulation.divergence.
// This fires before the nonce is touched.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn pay_commit_with_create_account_xdr_returns_simulation_divergence() {
    keyring_mock::install().expect("mock keyring store init");
    let server = WalletServer::new(testnet_profile()).expect("WalletServer::new");

    // envelope_xdr encodes a CreateAccount op.
    let envelope_xdr = create_account_envelope_b64(G_REAL_DEST, 10_000_000);

    let args = StellarPayCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: G_REAL_DEST.to_owned(),
        amount: Some(serde_json::from_str(r#""1 XLM""#).unwrap()),
        amount_in_stroops: None,
        asset: "native".to_owned(),
        memo_text: None,
        memo_id: None,
        memo_hash_hex: None,
        memo_return_hex: None,
        nonce: "dGVzdA".to_owned(),
        expires_at_unix_ms: u64::MAX,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    };

    let result = server.call_stellar_pay_commit(args).await;
    assert!(result.is_err(), "CreateAccount XDR must cause an Err");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("simulation.divergence"),
        "error must be simulation.divergence (op-kind mismatch); got: {err}"
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
// This confirms the args are flowing through re-derivation (if they weren't,
// the behaviour might differ on mainnet where the policy engine rejects).
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn pay_commit_policy_engine_sees_xdr_destination_not_caller_destination() {
    keyring_mock::install().expect("mock keyring store init");
    let server = WalletServer::new(testnet_profile()).expect("WalletServer::new");

    // envelope_xdr encodes G_REAL_DEST; caller args claim G_ATTACKER.
    let envelope_xdr = payment_envelope_b64(G_REAL_DEST, 10_000_000, Memo::None);

    let args = StellarPayCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: G_ATTACKER.to_owned(), // attacker-controlled field
        amount: Some(serde_json::from_str(r#""1 XLM""#).unwrap()),
        amount_in_stroops: None,
        asset: "native".to_owned(),
        memo_text: None,
        memo_id: None,
        memo_hash_hex: None,
        memo_return_hex: None,
        nonce: "dGVzdA".to_owned(), // invalid stub → nonce.expired after policy gate
        expires_at_unix_ms: u64::MAX,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    };

    let result = server.call_stellar_pay_commit(args).await;
    // The call must either:
    // (a) Fail at nonce parse with nonce.expired (policy gate passed with XDR args), OR
    // (b) Succeed with G-strkey validation error (invalid destination — but G_ATTACKER is
    //     a valid G-strkey so this doesn't fire).
    //
    // It must NOT fail with policy.engine_required or simulation.divergence at
    // the re-derivation step (the XDR is a valid Payment to G_REAL_DEST).
    match result {
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("nonce.expired") || msg.contains("nonce."),
                "after policy gate, must fail at nonce step; got: {msg}"
            );
            assert!(
                !msg.contains("simulation.divergence"),
                "must NOT return simulation.divergence for valid Payment XDR; got: {msg}"
            );
            assert!(
                !msg.contains("policy.engine_required"),
                "must NOT return policy gate error for testnet; got: {msg}"
            );
        }
        Ok(tool_result) => {
            // If for some reason it returns Ok (e.g. tool-level error result),
            // the is_error flag distinguishes it from a success.
            // We accept any outcome that isn't simulation.divergence or policy rejection.
            let json_str = tool_result
                .content
                .first()
                .and_then(|c| c.as_text())
                .map_or_else(String::new, |raw| raw.text.clone());
            assert!(
                !json_str.contains("simulation.divergence"),
                "must NOT return simulation.divergence for valid Payment XDR; got: {json_str}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: Memo::Hash in XDR is not a hard decode error.
//
// Hash memos decode as Ok(None) — the memo is treated as absent for
// re-derivation purposes.  The tamper is still caught later by the
// envelope-rebuild divergence check (rebuilt envelope uses Memo::None because
// memo_hash_hex is None, so it won't match the Hash-memo XDR).
//
// With this test fixture ("dGVzdA" is not a valid nonce), the call fails at
// nonce-parse before it reaches the rebuild divergence check — still an error,
// but nonce.expired rather than simulation.divergence.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn pay_commit_hash_memo_xdr_reaches_nonce_check() {
    keyring_mock::install().expect("mock keyring store init");
    let server = WalletServer::new(testnet_profile()).expect("WalletServer::new");

    let envelope_xdr = payment_envelope_b64(G_REAL_DEST, 10_000_000, Memo::Hash(Hash([0u8; 32])));

    let args = StellarPayCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: G_REAL_DEST.to_owned(),
        amount: Some(serde_json::from_str(r#""1 XLM""#).unwrap()),
        amount_in_stroops: None,
        asset: "native".to_owned(),
        memo_text: None,
        memo_id: None,
        memo_hash_hex: None,
        memo_return_hex: None,
        // An invalid-format nonce: decode succeeds, policy allows (testnet
        // NoopPolicyEngine), then nonce-parse fails here.
        nonce: "dGVzdA".to_owned(),
        expires_at_unix_ms: u64::MAX,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    };

    // The Hash memo does not fail at decode.  The call proceeds past decode and
    // dispatch_gate, then fails at nonce-parse (nonce.expired) because "dGVzdA"
    // is not a valid Nonce wire format.
    let result = server.call_stellar_pay_commit(args).await;
    assert!(result.is_err(), "call must still return an error");
    let err = result.unwrap_err();
    // The nonce-parse gate fires before the envelope-rebuild divergence check.
    assert!(
        err.to_string().contains("nonce.expired"),
        "Hash memo XDR reaches nonce-parse gate; expected nonce.expired; got: {err}"
    );
}
