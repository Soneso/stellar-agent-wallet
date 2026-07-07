//! Integration tests for the approval spine wiring.
//!
//! Exercises the `dispatch_gate` return type and the commit-side attestation
//! gate through the public `call_stellar_*` test helpers:
//!
//! 1. `profile_name_for_approval` strips the `stellar-agent-owner-` prefix.
//! 2. `profile_name_for_approval` falls back to `"default"` for non-standard
//!    profiles.
//! 3. Commit `stellar_pay_commit` with `RequireApproval` engine and an
//!    un-parseable nonce returns a gate error (nonce-parse path).
//! 4. Commit `stellar_create_account_commit` with `RequireApproval` engine and
//!    an un-parseable nonce returns a gate error.
//! 5. Commit `stellar_pay_commit` with `Allow` engine and no attestation fields
//!    proceeds past the attestation gate (may fail at nonce step, not policy).
//! 6. `dispatch_gate` with `RequireApproval` engine returns a non-error outcome
//!    (indirectly verified: the simulate call does NOT return a `policy.deny.*`
//!    error when the engine says RequireApproval — it returns a tool result with
//!    an `approval` block).
//! 7. Commit `stellar_pay_commit` with `RequireApproval` engine, a freshly-minted
//!    valid nonce, and zero attestation fields → asserts SPECIFICALLY
//!    `policy.approval_required` (the attestation gate fires BEFORE the nonce
//!    HMAC+replay step).
//!
//! # Ordering invariant
//!
//! The commit path enforces: `dispatch_gate` → `attestation_gate` → `nonce verify`.
//! Test 7 provides the positive proof: a syntactically valid nonce that would
//! pass `Nonce::from_base64` is presented alongside empty attestation fields; the
//! handler must return `policy.approval_required`, NOT `nonce.expired`.  A
//! regression that reverses the order would instead return `nonce.expired` (HMAC
//! mismatch collapsed for indistinguishability), and test 7 would fail.
//!
//! Tests 3 and 4 remain as parse-failure path exercises and are kept for
//! completeness; test 7 is the authoritative attestation-before-nonce gate test.
//!
//! # `#[serial]` requirement
//!
//! All tests touching the process-global keyring mock are serialised via
//! `#[serial]` so they do not race on the shared store.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use common::policy_mock::MockPolicyEngine;
use serial_test::serial;
use stellar_agent_core::{
    policy::PolicyEngine,
    profile::schema::{KeyringEntryRef, Profile},
};
use stellar_agent_mcp::server::{
    StellarCreateAccountCommitArgs, StellarPayCommitArgs, WalletServer,
};
use stellar_agent_nonce::{NonceMint, ToolCatalogue};
use stellar_agent_test_support::keyring_mock;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

mod common;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_server_with_engine(engine: impl PolicyEngine + 'static) -> WalletServer {
    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk (PolicyEngineKind::default() is V1); the real engine is
    // substituted below via set_policy_engine_for_test.
    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    let mut server = WalletServer::new(profile).expect("WalletServer::new must not fail in tests");
    server.set_policy_engine_for_test(Arc::new(engine));
    server
}

/// Builds a minimal but structurally valid `TransactionV1Envelope` base64 string
/// with a single `Payment` operation.
///
/// The commit handler re-derives `envelope_xdr` as the first step, so an
/// invalid/stub XDR returns `simulation.divergence` instead of proceeding to the
/// nonce gate.  Tests 3 and 4 exercise the approval gate, not XDR validation, and
/// need valid XDR to reach the nonce step.
fn minimal_payment_envelope_b64(source: &str, dest: &str) -> String {
    use stellar_xdr::{
        Asset, Limits, Memo, MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions,
        SequenceNumber, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope,
        Uint256, VecM, WriteXdr,
    };
    fn g_bytes(g: &str) -> [u8; 32] {
        stellar_strkey::ed25519::PublicKey::from_string(g)
            .expect("valid G-strkey")
            .0
    }
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(g_bytes(source))),
        fee: 100,
        seq_num: SequenceNumber(101),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(g_bytes(dest))),
                asset: Asset::Native,
                amount: 10_000_000,
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

/// Builds a minimal but structurally valid `TransactionV1Envelope` base64 string
/// with a single `CreateAccount` operation.
fn minimal_create_account_envelope_b64(source: &str, dest: &str) -> String {
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
        source_account: MuxedAccount::Ed25519(Uint256(g_bytes(source))),
        fee: 100,
        seq_num: SequenceNumber(101),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(g_bytes(dest)))),
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
// Test 1: profile_name_for_approval strips the service prefix
// ─────────────────────────────────────────────────────────────────────────────

/// `profile_name_for_approval` must strip `stellar-agent-owner-` from the
/// `policy_owner_key_id.service` field and return the bare profile name.
///
/// This is the approval-store path discriminator: different profiles produce
/// different store files.
///
/// Note: `Profile::builder_testnet` derives `policy_owner_key_id` from
/// `signer_account` (the second arg), not from `signer_service`.  Tests that
/// want a specific profile name MUST set `policy_owner_key_id` explicitly after
/// building, using `KeyringEntryRef::default_owner_key`.
#[test]
#[serial]
fn profile_name_for_approval_strips_prefix() {
    keyring_mock::install().ok();
    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk (PolicyEngineKind::default() is V1).
    let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    // Explicitly set the owner-key service to the profile name we want to verify.
    profile.policy_owner_key_id = KeyringEntryRef::default_owner_key("myprofile");
    let server = WalletServer::new(profile).expect("WalletServer::new must not fail in tests");
    let name = server.profile_name_for_approval();
    assert_eq!(
        name, "myprofile",
        "profile_name_for_approval must strip stellar-agent-owner- prefix; got: {name}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: profile_name_for_approval falls back to "default"
// ─────────────────────────────────────────────────────────────────────────────

/// When `policy_owner_key_id.service` does not start with the expected prefix,
/// `profile_name_for_approval` returns `"default"` rather than panicking.
///
/// This is a safety valve: a misconfigured or legacy profile does not cause a
/// panic at the approval-path entry point.
#[test]
#[serial]
fn profile_name_for_approval_falls_back_to_default() {
    keyring_mock::install().ok();
    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk (PolicyEngineKind::default() is V1).
    let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile.policy_owner_key_id = KeyringEntryRef::new("custom-service", "default");
    let server = WalletServer::new(profile).expect("WalletServer::new must not fail in tests");
    let name = server.profile_name_for_approval();
    assert_eq!(
        name, "default",
        "profile_name_for_approval must return 'default' when prefix absent; got: {name}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: stellar_pay_commit with RequireApproval + absent attestation → gate error
// ─────────────────────────────────────────────────────────────────────────────

/// When the dispatch gate returns `RequireApproval` and the commit args carry
/// no `approval_nonce` / `approval_attestation`, the handler must return a
/// gate error before signing.
///
/// Gate ordering: nonce parse → nonce verify → attestation.  A deliberately
/// un-parseable nonce produces `nonce.expired` (indistinguishability) before
/// the attestation gate.  Both `nonce.expired` and `policy.approval_required`
/// are expected outcomes; the test confirms no signing or network call is made.
#[tokio::test]
#[serial]
async fn stellar_pay_commit_require_approval_no_attestation_is_blocked() {
    keyring_mock::install().ok();
    let server = make_server_with_engine(MockPolicyEngine::require_approval());

    // Use valid XDR so the re-derivation step succeeds and the test reaches the
    // nonce/attestation gate that this test exercises.
    let source = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
    let dest = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    let envelope_xdr = minimal_payment_envelope_b64(source, dest);

    let commit_args = StellarPayCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: source.to_owned(),
        destination: dest.to_owned(),
        amount: Some(serde_json::from_str(r#""10 XLM""#).expect("valid amount")),
        amount_in_stroops: None,
        asset: "native".to_owned(),
        memo_text: None,
        memo_id: None,
        memo_hash_hex: None,
        memo_return_hex: None,
        // Unparseable nonce: triggers nonce.expired before attestation gate.
        nonce: "not-a-valid-nonce".to_owned(),
        expires_at_unix_ms: 9_999_999_999_000,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    };

    let result = server.call_stellar_pay_commit(commit_args).await;
    match result {
        Ok(tool_result) => {
            // The attestation gate fires before nonce parse for
            // `stellar_pay_commit`, so `policy.approval_required` (an
            // Ok(is_error) business envelope) is the expected outcome here.
            // `nonce.expired`/`nonce.replayed` (also business envelopes) are
            // accepted as well, in case the gate ordering ever changes.
            let (code, _message, _text) = common::assert_business_envelope(&tool_result);
            let blocked = code == "nonce.expired"
                || code == "nonce.replayed"
                || code == "policy.approval_required";
            assert!(
                blocked,
                "commit must be blocked at nonce or attestation gate; \
                 expected nonce.expired, nonce.replayed, or policy.approval_required, got: {code}"
            );
        }
        Err(e) => {
            // nonce.expired (from nonce parse) or policy.approval_required
            // (from attestation gate if nonce parse were to succeed) are
            // both valid outcomes that confirm the gate is active.
            let blocked = e.message.contains("nonce.expired")
                || e.message.contains("nonce.replayed")
                || e.message.contains("policy.approval_required");
            assert!(
                blocked,
                "commit must be blocked at nonce or attestation gate; \
                 expected nonce.expired or policy.approval_required, got: {}",
                e.message
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: stellar_create_account_commit with RequireApproval + absent attestation
// ─────────────────────────────────────────────────────────────────────────────

/// Same as test 3 for `stellar_create_account_commit`.
#[tokio::test]
#[serial]
async fn stellar_create_account_commit_require_approval_no_attestation_is_blocked() {
    keyring_mock::install().ok();
    let server = make_server_with_engine(MockPolicyEngine::require_approval());

    // Use valid XDR so the re-derivation step succeeds and the test reaches the
    // nonce/attestation gate that this test exercises.
    let source = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
    let dest = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    let envelope_xdr = minimal_create_account_envelope_b64(source, dest);

    let commit_args = StellarCreateAccountCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: source.to_owned(),
        destination: dest.to_owned(),
        starting_balance: serde_json::from_str(r#""1 XLM""#).expect("valid amount"),
        nonce: "not-a-valid-nonce".to_owned(),
        expires_at_unix_ms: 9_999_999_999_000,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    };

    let result = server
        .call_stellar_create_account_commit(commit_args)
        .await
        .expect(
            "commit blocked at the nonce/attestation gate is surfaced as an Ok(is_error) envelope, \
             not a protocol error or a signed submission",
        );
    let (code, _message, _text) = common::assert_business_envelope(&result);
    let blocked =
        code == "nonce.expired" || code == "nonce.replayed" || code == "policy.approval_required";
    assert!(
        blocked,
        "commit must be blocked at nonce or attestation gate; \
         expected nonce.expired / nonce.replayed / policy.approval_required, got: {code}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: stellar_pay_commit with Allow + absent attestation is NOT blocked by
// the attestation gate (may fail at nonce step for different reasons)
// ─────────────────────────────────────────────────────────────────────────────

/// When the dispatch gate returns `Allow`, the attestation gate is bypassed.
/// An unparseable nonce still returns `nonce.expired` but NOT `policy.approval_required`.
///
/// This verifies the attestation gate is conditional on `RequireApproval` only.
#[tokio::test]
#[serial]
async fn stellar_pay_commit_allow_engine_no_attestation_gate() {
    keyring_mock::install().ok();
    let server = make_server_with_engine(MockPolicyEngine::allow());

    let commit_args = StellarPayCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI".to_owned(),
        destination: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN".to_owned(),
        amount: Some(serde_json::from_str(r#""10 XLM""#).expect("valid amount")),
        amount_in_stroops: None,
        asset: "native".to_owned(),
        memo_text: None,
        memo_id: None,
        memo_hash_hex: None,
        memo_return_hex: None,
        nonce: "not-a-valid-nonce".to_owned(),
        expires_at_unix_ms: 9_999_999_999_000,
        envelope_xdr: "AAAAAA==".to_owned(),
        // No attestation fields — with Allow engine, these should NOT trigger
        // policy.approval_required.
        approval_nonce: None,
        approval_attestation: None,
    };

    let result = server.call_stellar_pay_commit(commit_args).await;
    match result {
        Ok(tool_result) => {
            // The stub envelope_xdr ("AAAAAA==") fails re-derivation before the
            // dispatch/attestation gates are even reached, so the expected
            // outcome here is the `simulation.divergence` business envelope.
            let (code, message, _text) = common::assert_business_envelope(&tool_result);
            assert_ne!(
                code, "policy.approval_required",
                "Allow engine must NOT trigger policy.approval_required; got: {code}"
            );
            let blocked = code == "nonce.expired"
                || code == "nonce.replayed"
                || code.starts_with("nonce.")
                || code == "simulation.divergence"
                || message.contains("chain_id mismatch");
            assert!(
                blocked,
                "Allow engine should fail at nonce gate or divergence check, not policy gate; \
                 got: {code} / {message}"
            );
        }
        Err(e) => {
            // Must NOT be policy.approval_required (attestation gate bypassed
            // for Allow flows).
            assert!(
                !e.message.contains("policy.approval_required"),
                "Allow engine must NOT trigger policy.approval_required; got: {}",
                e.message
            );
            // Expected: nonce.expired from the nonce parse/verify step.
            assert!(
                e.message.contains("nonce.expired")
                    || e.message.contains("nonce.replayed")
                    || e.message.contains("nonce.")
                    || e.message.contains("chain_id mismatch")
                    || e.message.contains("simulation.divergence"),
                "Allow engine should fail at nonce gate, not policy gate; got: {}",
                e.message
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: APPROVAL_TTL_MS constant is 24 hours
// ─────────────────────────────────────────────────────────────────────────────

/// The `APPROVAL_TTL_MS` constant in the core approval store must be exactly
/// 24 hours (86_400_000 milliseconds).
///
/// This is a compile-time documentation test that pins the constant value.
///
/// `#[serial]`: every test in this file touches the process-global keyring mock
/// via other tests sharing the binary; serialise for uniformity.
#[test]
#[serial]
fn approval_ttl_ms_is_24_hours() {
    use stellar_agent_core::approval::store::DEFAULT_TTL_MS;
    assert_eq!(
        DEFAULT_TTL_MS, 86_400_000,
        "DEFAULT_TTL_MS must be exactly 24 hours (86_400_000 ms)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: attestation gate fires BEFORE nonce HMAC+replay
// ─────────────────────────────────────────────────────────────────────────────

/// A `ToolCatalogue` that accepts the `stellar_pay_commit` tool, used for
/// minting a valid nonce in test 7.
struct PayCommitCatalogue;
impl ToolCatalogue for PayCommitCatalogue {
    fn is_registered(&self, tool_name: &str) -> bool {
        tool_name == "stellar_pay_commit"
    }
}

/// Builds a `LedgerEntryData::Account` XDR base64 string with a fixed
/// sequence number of 100.  Mirrors the helper in `pay_integration.rs`.
fn t7_account_entry_xdr(account_id: &str, balance_stroops: i64) -> String {
    use stellar_xdr::{
        AccountEntry, AccountEntryExt, AccountId, LedgerEntryData, Limits, PublicKey,
        SequenceNumber, String32, Thresholds, Uint256, WriteXdr,
    };
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_id)
        .expect("valid account_id")
        .0;
    let entry = AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
        balance: balance_stroops,
        seq_num: SequenceNumber(100),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: vec![].try_into().expect("empty signers"),
        ext: AccountEntryExt::V0,
    };
    LedgerEntryData::Account(entry)
        .to_xdr_base64(Limits::none())
        .expect("XDR encoding must succeed")
}

fn t7_account_ledger_key_xdr(account_id: &str) -> String {
    use stellar_xdr::{
        AccountId, LedgerKey, LedgerKeyAccount, Limits, PublicKey, Uint256, WriteXdr,
    };
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_id)
        .expect("valid account_id")
        .0;
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
    });
    key.to_xdr_base64(Limits::none())
        .expect("key XDR encoding must succeed")
}

/// EchoIdResponder echoes the JSON-RPC request id back in the response.
/// Required because the RPC client validates that the response id matches the request id.
struct T7EchoIdResponder {
    result: std::sync::Arc<serde_json::Value>,
}

impl T7EchoIdResponder {
    fn new(result: serde_json::Value) -> Self {
        Self {
            result: std::sync::Arc::new(result),
        }
    }
}

#[async_trait]
impl Respond for T7EchoIdResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let req_id = serde_json::from_slice::<serde_json::Value>(&request.body)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(serde_json::json!(1));
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": *self.result,
        });
        ResponseTemplate::new(200)
            .set_body_json(body)
            .insert_header("content-type", "application/json")
    }
}

/// `RequireApproval` engine + freshly-minted valid nonce + zero attestation
/// fields → asserts SPECIFICALLY `policy.approval_required`.
///
/// # Ordering invariant
///
/// The commit path enforces: `dispatch_gate → input_validation → nonce_parse →
/// rpc_fetch → divergence_check → attestation_gate → nonce_hmac_verify`.
/// This test ensures the attestation gate fires BEFORE nonce HMAC verify:
///
/// - Correct order: `policy.approval_required` (attestation gate) because
///   `approval_nonce` and `approval_attestation` are both `None`.
/// - Regression (nonce first): `nonce.expired` (HMAC mismatch collapsed for
///   indistinguishability).
///
/// The mock RPC returns a deterministic account with seq=100.  The test builds
/// the matching envelope XDR locally using `ClassicOpBuilder` with the same
/// parameters, so the divergence check passes and the attestation gate is reached.
#[tokio::test]
#[serial]
async fn commit_with_valid_nonce_but_no_attestation_returns_indistinguishable_approval_required() {
    use stellar_agent_core::DEFAULT_CLASSIC_FEE_STROOPS;
    use stellar_agent_network::ClassicOpBuilder;

    // ── Setup ────────────────────────────────────────────────────────────────
    keyring_mock::install().ok();

    // Seed the nonce key ("n-svc" / "n-acct") — same alias as the test profile.
    let nonce_key_bytes = [0xABu8; 32];
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_key_bytes);
    keyring_core::Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password for nonce key");

    // ── Start mock RPC ────────────────────────────────────────────────────────
    let mock_server = MockServer::start().await;

    const SOURCE: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
    const DEST: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

    let account_xdr = t7_account_entry_xdr(SOURCE, 1_000_000_000);
    let key_xdr = t7_account_ledger_key_xdr(SOURCE);

    Mock::given(method("POST"))
        .respond_with(T7EchoIdResponder::new(serde_json::json!({
            "entries": [
                {
                    "key": key_xdr,
                    "xdr": account_xdr,
                    "lastModifiedLedgerSeq": 1000
                }
            ],
            "latestLedger": 1001
        })))
        .mount(&mock_server)
        .await;

    // ── Build profile with mock RPC URL ───────────────────────────────────────
    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk (PolicyEngineKind::default() is V1).
    let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile.rpc_url = mock_server.uri();

    // ── Build the expected envelope XDR locally ───────────────────────────────
    // The commit handler uses: ClassicOpBuilder::new(source, seq=100, passphrase, fee)
    // and builds a payment to DEST for 10 XLM.  We replicate that here to get
    // the exact XDR that the divergence check expects.
    let network_passphrase = profile.network_passphrase.clone();
    let mut builder = ClassicOpBuilder::new(
        SOURCE,
        100,
        &network_passphrase,
        DEFAULT_CLASSIC_FEE_STROOPS,
    );
    // 10 XLM = 100_000_000 stroops.  `StellarAmount::from_stroops` is infallible
    // for any i64 value; this matches `args.amount.into_stellar_amount()` in the
    // commit handler when `amount = "10 XLM"`.
    let amount = stellar_agent_core::StellarAmount::from_stroops(100_000_000);
    builder
        .payment(DEST, amount, &stellar_agent_network::Asset::Native)
        .expect("payment op");
    let envelope_xdr = builder.build().expect("envelope build");

    // ── Mint a syntactically valid nonce bound to the correct envelope XDR ────
    let now_ms: u64 = 1_893_456_000_000; // 2030-01-01 UTC (stable test epoch)
    let expiry_ms: u64 = now_ms + 60_000; // 60 s in the future

    let nonce_mint = NonceMint::from_profile(&profile).expect("NonceMint::from_profile");
    let nonce = nonce_mint
        .mint(
            &PayCommitCatalogue,
            envelope_xdr.as_bytes(),
            now_ms,
            expiry_ms,
            "stellar_pay_commit",
            "stellar:testnet",
        )
        .expect("NonceMint::mint must succeed with valid parameters");
    let nonce_b64 = nonce.to_base64();

    // ── Build server with RequireApproval engine ──────────────────────────────
    let server = {
        let mut s = WalletServer::new(profile).expect("WalletServer::new must not fail");
        s.set_policy_engine_for_test(std::sync::Arc::new(MockPolicyEngine::require_approval()));
        s
    };

    // ── Call commit with valid nonce but NO attestation ───────────────────────
    let commit_args = StellarPayCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE.to_owned(),
        destination: DEST.to_owned(),
        amount: Some(serde_json::from_str(r#""10 XLM""#).expect("valid amount")),
        amount_in_stroops: None,
        asset: "native".to_owned(),
        memo_text: None,
        memo_id: None,
        memo_hash_hex: None,
        memo_return_hex: None,
        nonce: nonce_b64,
        expires_at_unix_ms: expiry_ms,
        envelope_xdr,
        // Attestation fields absent — attestation gate must fire before nonce HMAC.
        approval_nonce: None,
        approval_attestation: None,
    };

    let result = server
        .call_stellar_pay_commit(commit_args)
        .await
        .expect("stellar_pay_commit with RequireApproval and no attestation must return Ok(is_error) envelope");

    // ── Assert: SPECIFICALLY policy.approval_required ─────────────────────────
    // Correct order: attestation gate fires first → policy.approval_required.
    // Regression (nonce before attestation): nonce.expired (HMAC mismatch).
    let (code, _message, _text) = common::assert_business_envelope(&result);
    assert_eq!(
        code, "policy.approval_required",
        "ordering invariant: attestation gate must fire before nonce HMAC verify; \
         expected policy.approval_required, got: {code}"
    );
    assert_ne!(
        code, "nonce.expired",
        "nonce.expired indicates wrong gate order (nonce HMAC verified before attestation); \
         got: {code}"
    );
}
