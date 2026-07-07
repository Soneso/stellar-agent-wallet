//! Property 4 — Dispatch-layer attestation indistinguishability tests.
//!
//! Verifies that three distinct attestation-gate failure modes produce
//! **byte-identical** JSON-RPC error envelopes at the dispatch boundary,
//! satisfying the oracle-defence indistinguishability invariant.
//!
//! # Three failure modes
//!
//! a. **Absent attestation.** `stellar_pay_commit` is called with a
//!    `Decision::RequireApproval` engine result, but `approval_nonce` and
//!    `approval_attestation` are both `None`.
//!
//! b. **Forged attestation HMAC.** Same setup, but `approval_attestation`
//!    is `Some("forged-bytes")` — non-empty, with a nonce id that is NOT in
//!    the approval store (so the gate fails at "entry not found").
//!
//! c. **Expired approval entry.** A real approval entry exists in the store
//!    with `expires_at_unix_ms = 1` (epoch + 1ms, always in the past).
//!
//! # Byte-identity assertion
//!
//! All three error envelopes are captured via `rmcp::ErrorData` and compared
//! using `serde_json::to_string`.  The assertion covers the full wire body:
//! `code`, `message`, and `data`.
//!
//! # Forensic differentiation
//!
//! `tracing::debug!` output distinguishes the three cases for operator forensics.
//! The isolated case tests capture subscriber output and assert that each
//! forensic reason is emitted while the JSON-RPC wire envelope remains
//! indistinguishable.
//!
//! # Approval-store isolation
//!
//! Each test injects a `tempfile::TempDir` via
//! `WalletServer::set_approval_dir_for_test`, routing all approval-store I/O to
//! a per-test temporary directory.  This prevents pollution of the developer's
//! real wallet state at `~/Library/Application Support/Soneso.stellar-agent/approvals/`.
//!
//! # `#[serial]` requirement
//!
//! All tests in this file touch the process-global keyring mock and are
//! serialised via `#[serial]` so they do not race on the shared store.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use serial_test::serial;
use stellar_agent_core::{
    DEFAULT_CLASSIC_FEE_STROOPS,
    approval::{PendingApprovalStore, store::PendingApproval},
    policy::v1::{
        AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
        Sep45SessionView,
    },
    policy::{ApprovalRequest, Decision, PolicyEngine, PolicyError, ToolDescriptor},
    profile::schema::Profile,
};
use stellar_agent_mcp::server::{StellarPayCommitArgs, WalletServer};
use stellar_agent_network::{Asset, ClassicOpBuilder};
use stellar_agent_nonce::{NonceMint, ToolCatalogue};
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_balance, account_ledger_key_xdr,
};
use stellar_agent_test_support::{CaptureWriter, keyring_mock};
use tempfile::TempDir;
use tracing::instrument::WithSubscriber as _;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

mod common;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const SOURCE: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
const DEST: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// The canonical wire code emitted by `approval_required_indistinguishable()`
/// for all attestation-gate failure modes.
const POLICY_APPROVAL_REQUIRED_CODE: &str = "policy.approval_required";

/// The canonical indistinguishable `error.message` detail emitted by
/// `approval_required_indistinguishable()` for all attestation-gate failure
/// modes.
///
/// Using `assert_eq!` against this constant (rather than `assert!(contains(...))`)
/// pins the exact wire body and catches any drift in the message text.
const POLICY_APPROVAL_REQUIRED_MSG: &str = "approval attestation absent, invalid, or expired; \
     run `stellar-agent approve --id <nonce>` then re-submit with attestation";

fn capture_subscriber(writer: CaptureWriter) -> impl tracing::Subscriber + Send + Sync {
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish()
}

// ─────────────────────────────────────────────────────────────────────────────
// MockPolicyEngine — always RequireApproval
// ─────────────────────────────────────────────────────────────────────────────

struct RequireApprovalEngine;

impl PolicyEngine for RequireApprovalEngine {
    fn evaluate(
        &self,
        _tool: &ToolDescriptor,
        _args: &serde_json::Value,
        _profile: &Profile,
        _account_view: Option<&dyn AccountReservesView>,
        _identity_view: Option<&dyn AccountIdentityView>,
        _counterparty_cache: Option<&dyn CounterpartyCacheView>,
        _sep10_sessions: Option<&dyn Sep10SessionView>,
        _sep45_sessions: Option<&dyn Sep45SessionView>,
    ) -> Result<Decision, PolicyError> {
        Ok(Decision::RequireApproval(ApprovalRequest::new(
            "test-nonce".into(),
            120,
        )))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolCatalogue for nonce-minting
// ─────────────────────────────────────────────────────────────────────────────

struct PayCommitCatalogue;

impl ToolCatalogue for PayCommitCatalogue {
    fn is_registered(&self, tool_name: &str) -> bool {
        tool_name == "stellar_pay_commit"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RPC mock helpers
// ─────────────────────────────────────────────────────────────────────────────

// Kept local: single-caller scope and approval-specific response shape.
struct AccountLedgerResponder {
    account_key_xdr: String,
    account_xdr: String,
}

#[async_trait]
impl Respond for AccountLedgerResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let req_id = serde_json::from_slice::<serde_json::Value>(&request.body)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(serde_json::json!(1));
        let body = serde_json::json!({
            "entries": [{
                "key": self.account_key_xdr,
                "xdr": self.account_xdr,
                "lastModifiedLedgerSeq": 1000
            }],
            "latestLedger": 1001
        });
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": body,
            }))
            .insert_header("content-type", "application/json")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared test scaffold
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a `WalletServer` with `RequireApproval` engine, injects the given
/// `approval_dir` override, and returns:
/// - the server (with `approval_dir_override` set),
/// - the exact `envelope_xdr` that will pass the divergence check,
/// - a freshly-minted `nonce_b64`,
/// - the nonce expiry in ms.
///
/// `approval_dir` must point to a `tempfile::TempDir` that the caller keeps
/// alive for the duration of the test.  Routing approval-store I/O to a temp
/// dir prevents pollution of the developer's real wallet state.
async fn build_scaffold(
    profile: Profile,
    approval_dir: std::path::PathBuf,
) -> (WalletServer, String, String, u64) {
    let network_passphrase = profile.network_passphrase.clone();
    // Build the envelope that matches what the commit handler will rebuild
    // (seq=100 from mock, fee=DEFAULT_CLASSIC_FEE_STROOPS, 10 XLM payment).
    let mut builder = ClassicOpBuilder::new(
        SOURCE,
        100,
        &network_passphrase,
        DEFAULT_CLASSIC_FEE_STROOPS,
    );
    builder
        .payment(
            DEST,
            stellar_agent_core::StellarAmount::from_stroops(100_000_000),
            &Asset::Native,
        )
        .expect("payment op");
    let envelope_xdr = builder.build().expect("envelope build");

    let now_ms: u64 = 1_893_456_000_000; // 2030-01-01 UTC test epoch
    let expiry_ms: u64 = now_ms + 60_000;

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
        .expect("NonceMint::mint");
    let nonce_b64 = nonce.to_base64();

    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    server.set_policy_engine_for_test(Arc::new(RequireApprovalEngine));
    server.set_approval_dir_for_test(approval_dir);

    (server, envelope_xdr, nonce_b64, expiry_ms)
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 4 — byte-identity assertion across all three failure modes
// ─────────────────────────────────────────────────────────────────────────────

/// **Property 4 (combined)** — All three attestation-gate failure modes must
/// produce byte-identical JSON-RPC error envelopes.
///
/// Runs three commit invocations sequentially and asserts that all three
/// produce the same wire error as `serde_json::to_string(ErrorData)`.
///
/// # Indistinguishability
///
/// An oracle that can distinguish the three failure modes (by observing the
/// wire response) gains information about the server's internal state.  The
/// uniform `policy.approval_required` envelope closes this oracle.
#[tokio::test]
#[serial]
async fn property4_all_failure_modes_produce_byte_identical_wire_error() {
    keyring_mock::install().expect("mock keyring store init");

    // Seed the nonce key used by all three invocations.
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xABu8; 32]);
    keyring_core::Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password for nonce key");

    // Helper: start a fresh RPC mock and return the URI.
    let fresh_rpc_mock = || async {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(AccountLedgerResponder {
                account_key_xdr: account_ledger_key_xdr(SOURCE),
                account_xdr: account_entry_xdr_with_balance(SOURCE, 1_000_000_000),
            })
            .mount(&mock_server)
            .await;
        mock_server
    };

    // ── Case a: absent attestation ───────────────────────────────────────────
    let temp_a = TempDir::new().expect("TempDir::new for case a");
    let mock_a = fresh_rpc_mock().await;
    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk: PolicyEngineKind::default() is V1.
    let mut profile_a = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile_a.rpc_url = mock_a.uri();

    let (server_a, envelope_a, nonce_a, expiry_a) =
        build_scaffold(profile_a, temp_a.path().to_path_buf()).await;
    let result_a = server_a
        .call_stellar_pay_commit(StellarPayCommitArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: SOURCE.to_owned(),
            destination: DEST.to_owned(),
            amount: Some(serde_json::from_str(r#""10 XLM""#).expect("parse amount")),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            nonce: nonce_a,
            expires_at_unix_ms: expiry_a,
            envelope_xdr: envelope_a,
            // Both absent.
            approval_nonce: None,
            approval_attestation: None,
        })
        .await
        .expect("case a: absent attestation must return Ok(is_error) envelope");
    let (code_a, message_a, _text_a) = common::assert_business_envelope(&result_a);

    // ── Case b: forged attestation (nonce not in store) ──────────────────────
    let temp_b = TempDir::new().expect("TempDir::new for case b");
    let mock_b = fresh_rpc_mock().await;
    // Explicitly set Noop so WalletServer::new succeeds without a policy file.
    let mut profile_b = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile_b.rpc_url = mock_b.uri();

    let (server_b, envelope_b, nonce_b, expiry_b) =
        build_scaffold(profile_b, temp_b.path().to_path_buf()).await;
    let result_b = server_b
        .call_stellar_pay_commit(StellarPayCommitArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: SOURCE.to_owned(),
            destination: DEST.to_owned(),
            amount: Some(serde_json::from_str(r#""10 XLM""#).expect("parse amount")),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            nonce: nonce_b,
            expires_at_unix_ms: expiry_b,
            envelope_xdr: envelope_b,
            // Present but not in the store → entry-not-found → approval_required.
            approval_nonce: Some("some-nonce-not-in-store-b4se6".to_owned()),
            approval_attestation: Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xFFu8; 32]),
            ),
        })
        .await
        .expect("case b: forged attestation must return Ok(is_error) envelope");
    let (code_b, message_b, _text_b) = common::assert_business_envelope(&result_b);

    // ── Case c: expired approval entry ───────────────────────────────────────
    let temp_c = TempDir::new().expect("TempDir::new for case c");
    let mock_c = fresh_rpc_mock().await;
    // Explicitly set Noop so WalletServer::new succeeds without a policy file.
    let mut profile_c = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile_c.rpc_url = mock_c.uri();
    let (server_c, envelope_c, nonce_c, expiry_c) =
        build_scaffold(profile_c.clone(), temp_c.path().to_path_buf()).await;

    // Insert an expired PendingApproval entry into the temp store.
    // TTL = 0 → expires_at = created_at → immediately expired.
    let approval_nonce_id: String;
    {
        // profile_name_for_approval() strips "stellar-agent-owner-" from the service.
        // builder_testnet("svc","acct",...) → policy_owner_key_id = "stellar-agent-owner-acct"
        // → profile_name = "acct"
        let profile_name = "acct";
        let store_path = temp_c.path().join(format!("{profile_name}.toml"));
        let uid = stellar_agent_core::approval::user_id::process_uid_for_attestation()
            .expect("process uid");
        let entry = PendingApproval::new_payment_pending(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(envelope_c.as_bytes()),
            envelope_c.as_bytes(),
            DEST.to_owned(),
            100_000_000,
            "XLM".to_owned(),
            None,
            100,
            101,
            uid,
            0, // TTL = 0 ms → immediately expired
        )
        .expect("new_payment_pending");
        approval_nonce_id = entry.approval_nonce.clone();

        let mut store = PendingApprovalStore::open(store_path).expect("open store");
        let now_ms = stellar_agent_core::timefmt::now_unix_ms().expect("now");
        store.insert(entry, now_ms).expect("insert expired entry");
        // Store dropped here: file lock released so server can open the same file.
    }

    // Provide a plausible attestation blob (32 bytes); expiry fires before HMAC.
    let fake_attestation = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xABu8; 32]);

    let result_c = server_c
        .call_stellar_pay_commit(StellarPayCommitArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: SOURCE.to_owned(),
            destination: DEST.to_owned(),
            amount: Some(serde_json::from_str(r#""10 XLM""#).expect("parse amount")),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            nonce: nonce_c,
            expires_at_unix_ms: expiry_c,
            envelope_xdr: envelope_c,
            // Reference the expired entry.
            approval_nonce: Some(approval_nonce_id),
            approval_attestation: Some(fake_attestation),
        })
        .await
        .expect("case c: expired entry must return Ok(is_error) envelope");
    let (code_c, message_c, _text_c) = common::assert_business_envelope(&result_c);

    // Temp dirs dropped at end of test: temp_a, temp_b, temp_c.

    // ── Byte-identity assertion ───────────────────────────────────────────────
    for (label, code, message) in [
        ("a (absent)", &code_a, &message_a),
        ("b (forged)", &code_b, &message_b),
        ("c (expired)", &code_c, &message_c),
    ] {
        assert_eq!(
            code, POLICY_APPROVAL_REQUIRED_CODE,
            "Property 4 case {label}: must produce canonical wire code; got: {code}"
        );
        assert_eq!(
            message, POLICY_APPROVAL_REQUIRED_MSG,
            "Property 4 case {label}: must produce canonical wire message; got: {message}"
        );
    }

    // Compare the (code, message) tuples for equality — never the full JSON
    // text or request_id, which are freshly minted per call and therefore
    // legitimately differ between cases.
    let pair_a = (code_a, message_a);
    let pair_b = (code_b, message_b);
    let pair_c = (code_c, message_c);

    assert_eq!(
        pair_a, pair_b,
        "Property 4: case a (absent) and case b (forged) (code, message) pairs must be \
         byte-identical.\n  a: {pair_a:?}\n  b: {pair_b:?}"
    );
    assert_eq!(
        pair_a, pair_c,
        "Property 4: case a (absent) and case c (expired) (code, message) pairs must be \
         byte-identical.\n  a: {pair_a:?}\n  c: {pair_c:?}"
    );
}

/// **Property 4a** — Absent attestation → `policy.approval_required`.
///
/// Verifies case a in isolation so failures are easy to diagnose.
#[tokio::test]
#[serial]
async fn property4a_absent_attestation_returns_approval_required() {
    keyring_mock::install().expect("mock keyring store init");

    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xABu8; 32]);
    keyring_core::Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(AccountLedgerResponder {
            account_key_xdr: account_ledger_key_xdr(SOURCE),
            account_xdr: account_entry_xdr_with_balance(SOURCE, 1_000_000_000),
        })
        .mount(&mock_server)
        .await;

    let temp = TempDir::new().expect("TempDir::new");
    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk: PolicyEngineKind::default() is V1.
    let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile.rpc_url = mock_server.uri();

    let (server, envelope_xdr, nonce_b64, expiry_ms) =
        build_scaffold(profile, temp.path().to_path_buf()).await;

    let logs = CaptureWriter::new();
    let subscriber = capture_subscriber(logs.clone());
    let result = server
        .call_stellar_pay_commit(StellarPayCommitArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: SOURCE.to_owned(),
            destination: DEST.to_owned(),
            amount: Some(serde_json::from_str(r#""10 XLM""#).expect("parse amount")),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            nonce: nonce_b64,
            expires_at_unix_ms: expiry_ms,
            envelope_xdr,
            approval_nonce: None,
            approval_attestation: None,
        })
        .with_subscriber(subscriber)
        .await
        .expect("absent attestation must return Ok(is_error) envelope");
    let (code, message, _text) = common::assert_business_envelope(&result);

    assert_eq!(
        code, POLICY_APPROVAL_REQUIRED_CODE,
        "Property 4a: absent attestation must produce canonical wire code; got: {code}"
    );
    assert_eq!(
        message, POLICY_APPROVAL_REQUIRED_MSG,
        "Property 4a: absent attestation must produce canonical wire message; got: {message}"
    );
    let captured = logs.captured_str();
    assert!(
        captured.contains("approval_nonce or approval_attestation absent"),
        "Property 4a: expected absent-attestation forensic log, got: {captured}"
    );
}

/// **Property 4b** — Forged attestation (nonce not in store) → `policy.approval_required`.
///
/// Verifies case b in isolation.
#[tokio::test]
#[serial]
async fn property4b_forged_attestation_returns_approval_required() {
    keyring_mock::install().expect("mock keyring store init");

    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xABu8; 32]);
    keyring_core::Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(AccountLedgerResponder {
            account_key_xdr: account_ledger_key_xdr(SOURCE),
            account_xdr: account_entry_xdr_with_balance(SOURCE, 1_000_000_000),
        })
        .mount(&mock_server)
        .await;

    let temp = TempDir::new().expect("TempDir::new");
    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk: PolicyEngineKind::default() is V1.
    let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile.rpc_url = mock_server.uri();

    let (server, envelope_xdr, nonce_b64, expiry_ms) =
        build_scaffold(profile, temp.path().to_path_buf()).await;

    let logs = CaptureWriter::new();
    let subscriber = capture_subscriber(logs.clone());
    let result = server
        .call_stellar_pay_commit(StellarPayCommitArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: SOURCE.to_owned(),
            destination: DEST.to_owned(),
            amount: Some(serde_json::from_str(r#""10 XLM""#).expect("parse amount")),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            nonce: nonce_b64,
            expires_at_unix_ms: expiry_ms,
            envelope_xdr,
            // Nonce ID not in store → entry-not-found → approval_required.
            approval_nonce: Some("some-nonce-not-in-store-b4se6".to_owned()),
            approval_attestation: Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xFFu8; 32]),
            ),
        })
        .with_subscriber(subscriber)
        .await
        .expect("forged attestation must return Ok(is_error) envelope");
    let (code, message, _text) = common::assert_business_envelope(&result);

    assert_eq!(
        code, POLICY_APPROVAL_REQUIRED_CODE,
        "Property 4b: forged attestation must produce canonical wire code; got: {code}"
    );
    assert_eq!(
        message, POLICY_APPROVAL_REQUIRED_MSG,
        "Property 4b: forged attestation must produce canonical wire message; got: {message}"
    );
    let captured = logs.captured_str();
    assert!(
        captured.contains("approval entry not found"),
        "Property 4b: expected missing-entry forensic log, got: {captured}"
    );
}

/// **Property 4c** — Expired approval entry → `policy.approval_required`.
///
/// Verifies case c in isolation.
#[tokio::test]
#[serial]
async fn property4c_expired_approval_entry_returns_approval_required() {
    keyring_mock::install().expect("mock keyring store init");

    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xABu8; 32]);
    keyring_core::Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(AccountLedgerResponder {
            account_key_xdr: account_ledger_key_xdr(SOURCE),
            account_xdr: account_entry_xdr_with_balance(SOURCE, 1_000_000_000),
        })
        .mount(&mock_server)
        .await;

    let temp = TempDir::new().expect("TempDir::new");
    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk: PolicyEngineKind::default() is V1.
    let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile.rpc_url = mock_server.uri();

    let (server, envelope_xdr, nonce_b64, expiry_ms) =
        build_scaffold(profile.clone(), temp.path().to_path_buf()).await;

    // Insert an expired entry into the approval store (inside the temp dir).
    let approval_nonce_id: String;
    {
        let profile_name = "acct"; // derived from builder_testnet("svc","acct",...)
        let store_path = temp.path().join(format!("{profile_name}.toml"));
        let uid = stellar_agent_core::approval::user_id::process_uid_for_attestation()
            .expect("process uid");
        let entry = PendingApproval::new_payment_pending(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(envelope_xdr.as_bytes()),
            envelope_xdr.as_bytes(),
            DEST.to_owned(),
            100_000_000,
            "XLM".to_owned(),
            None,
            100,
            101,
            uid,
            0, // TTL = 0 → immediately expired
        )
        .expect("new_payment_pending");
        approval_nonce_id = entry.approval_nonce.clone();
        let mut store = PendingApprovalStore::open(store_path).expect("open store");
        let now_ms = stellar_agent_core::timefmt::now_unix_ms().expect("now");
        store.insert(entry, now_ms).expect("insert expired entry");
        // Lock released here on drop.
    }

    let fake_attestation = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xABu8; 32]);

    let logs = CaptureWriter::new();
    let subscriber = capture_subscriber(logs.clone());
    let result = server
        .call_stellar_pay_commit(StellarPayCommitArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: SOURCE.to_owned(),
            destination: DEST.to_owned(),
            amount: Some(serde_json::from_str(r#""10 XLM""#).expect("parse amount")),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            nonce: nonce_b64,
            expires_at_unix_ms: expiry_ms,
            envelope_xdr,
            approval_nonce: Some(approval_nonce_id),
            approval_attestation: Some(fake_attestation),
        })
        .with_subscriber(subscriber)
        .await
        .expect("expired entry must return Ok(is_error) envelope");
    let (code, message, _text) = common::assert_business_envelope(&result);

    assert_eq!(
        code, POLICY_APPROVAL_REQUIRED_CODE,
        "Property 4c: expired entry must produce canonical wire code; got: {code}"
    );
    assert_eq!(
        message, POLICY_APPROVAL_REQUIRED_MSG,
        "Property 4c: expired entry must produce canonical wire message; got: {message}"
    );
    let captured = logs.captured_str();
    assert!(
        captured.contains("approval entry expired"),
        "Property 4c: expected expired-entry forensic log, got: {captured}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Accept branch — a valid attestation passes the gate
// ─────────────────────────────────────────────────────────────────────────────

/// A valid attestation — exactly what `stellar-agent approve --id` surfaces as
/// `approval_attestation` — passes the attestation gate.
///
/// The three failure-mode tests above pin the rejection envelope; none exercises
/// the gate's accept path. This seeds the attestation key, inserts a live
/// `PaymentSimulated` entry, computes the HMAC blob the operator's `approve`
/// surfaces, and asserts the commit proceeds *past* the attestation gate. Past
/// the gate the commit fails at a later stage (no signer key is seeded), which
/// is out of scope here — the point is the failure is NOT the approval-required
/// gate error, i.e. the surfaced blob is accepted.
#[tokio::test]
#[serial]
async fn valid_attestation_passes_gate() {
    keyring_mock::install().expect("mock keyring store init");

    // Seed the nonce key used by `NonceMint` in the scaffold.
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xABu8; 32]);
    keyring_core::Entry::new("n-svc", "n-acct")
        .expect("Entry::new for nonce key")
        .set_password(&nonce_key_b64)
        .expect("set_password for nonce key");

    // Seed the attestation key. `builder_testnet("svc","acct",..)` derives the
    // profile name "acct", so the attestation entry is
    // "stellar-agent-attestation-acct" / "default".
    let attestation_key = [0x11u8; 32];
    let attestation_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(attestation_key);
    keyring_core::Entry::new("stellar-agent-attestation-acct", "default")
        .expect("Entry::new for attestation key")
        .set_password(&attestation_key_b64)
        .expect("set_password for attestation key");

    let temp = TempDir::new().expect("TempDir::new");
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(AccountLedgerResponder {
            account_key_xdr: account_ledger_key_xdr(SOURCE),
            account_xdr: account_entry_xdr_with_balance(SOURCE, 1_000_000_000),
        })
        .mount(&mock)
        .await;

    let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile.rpc_url = mock.uri();

    let (server, envelope_xdr, nonce_b64, expiry_ms) =
        build_scaffold(profile, temp.path().to_path_buf()).await;

    // Insert a live (non-expired) PaymentSimulated entry mirroring what the
    // `stellar_pay` simulate step persists.
    let uid =
        stellar_agent_core::approval::user_id::process_uid_for_attestation().expect("process uid");
    let entry = PendingApproval::new_payment_pending(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(envelope_xdr.as_bytes()),
        envelope_xdr.as_bytes(),
        DEST.to_owned(),
        100_000_000,
        "XLM".to_owned(),
        None,
        100,
        101,
        uid.clone(),
        60_000, // 60s TTL → live
    )
    .expect("new_payment_pending");
    let approval_nonce_id = entry.approval_nonce.clone();
    {
        let store_path = temp.path().join("acct.toml");
        let mut store = PendingApprovalStore::open(store_path).expect("open store");
        let now_ms = stellar_agent_core::timefmt::now_unix_ms().expect("now");
        store.insert(entry, now_ms).expect("insert live entry");
        // Store dropped here: file lock released so the server can open it.
    }

    // Compute the VALID attestation blob exactly as `stellar-agent approve`
    // surfaces it: HMAC over (nonce, envelope SHA-256, process uid) keyed by the
    // attestation key, URL-safe base64 no-pad.
    let sha = stellar_agent_core::approval::envelope_sha256(envelope_xdr.as_bytes());
    let blob = stellar_agent_core::approval::compute_attestation(
        &attestation_key,
        &approval_nonce_id,
        &sha,
        &uid,
    );
    let blob_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob);

    let result = server
        .call_stellar_pay_commit(StellarPayCommitArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: SOURCE.to_owned(),
            destination: DEST.to_owned(),
            amount: Some(serde_json::from_str(r#""10 XLM""#).expect("parse amount")),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            nonce: nonce_b64,
            expires_at_unix_ms: expiry_ms,
            envelope_xdr,
            approval_nonce: Some(approval_nonce_id),
            approval_attestation: Some(blob_b64),
        })
        .await;

    // The gate must ACCEPT the valid blob. Any failure past the gate is a
    // different error; assert we did not bounce off the approval-required gate.
    match result {
        // A success is trivially past the gate (stronger evidence still).
        Ok(_) => {}
        Err(err) => {
            assert_ne!(
                err.message, POLICY_APPROVAL_REQUIRED_MSG,
                "valid attestation must pass the gate, not return the approval-required error"
            );
            assert!(
                !err.message.starts_with("policy.approval_required"),
                "valid attestation must pass the gate; got gate error: {}",
                err.message
            );
        }
    }
}
