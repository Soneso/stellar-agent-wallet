//! Testnet acceptance tests for `stellar_sep43_sign_and_submit_transaction`.
//!
//! These tests require a live testnet RPC endpoint and Friendbot access. They
//! are gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-mcp --features testnet-acceptance \
//!   --test sep43_sign_and_submit_transaction_testnet_acceptance
//! ```
//!
//! Under default `cargo test` (no `--features testnet-acceptance`), this file
//! compiles but all tests are compiled-out via `#[cfg(feature = "testnet-acceptance")]`.
//!
//! # Acceptance criteria
//!
//! - Signs and submits a self-payment transaction on testnet.
//! - Result carries `signedTxXdr`, `txHash` (64 lowercase hex chars),
//!   and `status: "success"`.
//! - Account sequence advances on-chain after submission.
//!
//! # Test isolation
//!
//! A fresh ed25519 keypair is generated per test using `rand_core::OsRng`;
//! the keypair is funded via Friendbot before use.  No pre-committed secret
//! key material appears in the source.
//!
//! # Process-global keyring
//!
//! All keyring-touching tests call `keyring_mock::install` before constructing
//! `WalletServer` and are serialised via `#[serial]` because the mock keyring
//! is process-global state.
//!
//! Exercises the WalletConnect v2 `stellar_signAndSubmitXDR` flow.

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{Sep43SignAndSubmitTransactionArgs, WalletServer};
use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
use stellar_agent_network::{StellarRpcClient, fetch_account};
use stellar_agent_test_support::keyring_mock;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";

/// Fee per operation in stroops. 100,000 stroops = 0.01 XLM; well within
/// Friendbot-funded account limits and generous for testnet.
const FEE_STROOPS: u32 = 100_000;

/// Self-payment amount: 10 XLM in stroops.
const SELF_PAYMENT_STROOPS: i64 = 100_000_000;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh ed25519 keypair using OS entropy.
///
/// Returns `(g_strkey, seed_bytes)`. Seed bytes are `Zeroizing`-wrapped so
/// they are cleared on drop.
fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    // `PublicKey::to_string()` returns `heapless::String<56>`; dereference to
    // `&str` then collect as `std::String`.
    let g_strkey: String = stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
        .to_string()
        .as_str()
        .to_owned();
    let seed = Zeroizing::new(signing_key.to_bytes());
    (g_strkey, seed)
}

/// Funds a testnet account via Friendbot.
///
/// Panics if the HTTP request fails or returns a non-2xx status.
async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = reqwest::get(&url)
        .await
        .expect("Friendbot HTTP request must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 200 for {g_strkey}; got {}",
        resp.status()
    );
}

/// Builds a `WalletServer` backed by an in-memory keyring mock for the given
/// keypair.
///
/// Installs the keyring mock, stores the signing key under the profile's
/// `mcp_signer_default` keyring entry, and constructs a testnet `WalletServer`
/// with a Noop policy engine (no on-disk policy file required).
fn build_test_server(g_strkey: &str, seed: &Zeroizing<[u8; 32]>) -> WalletServer {
    keyring_mock::install().expect("mock keyring store init");

    let mut profile =
        Profile::builder_testnet("stellar-agent", g_strkey, "stellar-agent-nonce", g_strkey)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();

    // Store the signing key in the mock keyring under the profile's signer entry.
    let signer_ref = &profile.mcp_signer_default;
    let entry = keyring_core::Entry::new(&signer_ref.service, &signer_ref.account)
        .expect("keyring mock entry construction must succeed");
    let s_strkey = stellar_strkey::ed25519::PrivateKey::from_payload(seed.as_ref())
        .expect("32-byte seed must encode as S-strkey")
        .as_unredacted()
        .to_string();
    entry
        .set_password(&s_strkey)
        .expect("keyring mock set_password must succeed");

    WalletServer::new(profile).expect("WalletServer::new must succeed with mock keyring")
}

/// Fetches the current sequence number for `g_strkey` via the testnet RPC.
async fn fetch_sequence(g_strkey: &str) -> i64 {
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client construction");
    let view = fetch_account(&client, g_strkey, &[])
        .await
        .expect("fetch_account must succeed for a funded account");
    view.sequence_number
}

/// Builds an unsigned self-payment `TransactionEnvelope` base64 XDR.
///
/// Uses `ClassicOpBuilder` with the given source account and sequence number.
/// The payment is from source to source (self-payment) for
/// `SELF_PAYMENT_STROOPS` native XLM.
fn build_self_payment_xdr(g_strkey: &str, sequence_number: i64) -> String {
    // Pass `sequence_number` (current on-chain value) directly.
    // `stellar_baselib::TransactionBuilder::build` auto-increments via
    // `Account::increment_sequence_number`; an explicit +1 would produce
    // CURRENT+2 → TxBadSeq.
    let mut builder =
        ClassicOpBuilder::new(g_strkey, sequence_number, TESTNET_PASSPHRASE, FEE_STROOPS);
    builder
        .payment(
            g_strkey,
            stellar_agent_core::StellarAmount::from_stroops(SELF_PAYMENT_STROOPS),
            &Asset::Native,
        )
        .expect("payment op construction must succeed for valid G-strkeys");
    builder
        .build()
        .expect("ClassicOpBuilder::build must succeed")
}

/// Extracts the first text item from a `CallToolResult`.
fn extract_text(result: rmcp::model::CallToolResult) -> String {
    result
        .content
        .into_iter()
        .find_map(|c| {
            if let rmcp::model::RawContent::Text(t) = c.raw {
                Some(t.text)
            } else {
                None
            }
        })
        .expect("result must contain a text content item")
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance tests
// ─────────────────────────────────────────────────────────────────────────────

/// Signs and submits a self-payment; asserts txHash + status + sequence
/// advancement.
///
/// Verifies the tool produces `{ signedTxXdr, txHash, status: "success" }` for
/// a real testnet transaction confirmed in a ledger, and that the account
/// sequence number advanced on-chain.
#[tokio::test]
#[serial]
async fn sign_and_submit_self_payment_succeeds() {
    // ── Fresh keypair + Friendbot funding ────────────────────────────────────
    let (g_strkey, seed) = fresh_keypair();
    fund_via_friendbot(&g_strkey).await;

    // ── Build the server with a mock keyring ─────────────────────────────────
    let server = build_test_server(&g_strkey, &seed);

    // ── Fetch sequence number BEFORE submission ───────────────────────────────
    let seq_before = fetch_sequence(&g_strkey).await;

    // ── Build unsigned self-payment envelope ─────────────────────────────────
    let unsigned_xdr = build_self_payment_xdr(&g_strkey, seq_before);

    // ── Call the tool via test-helper ─────────────────────────────────────────
    let args = Sep43SignAndSubmitTransactionArgs {
        chain_id: TESTNET_CHAIN_ID.to_owned(),
        transaction_xdr: unsigned_xdr,
        network_passphrase: None,
        address: None,
    };

    let result = server
        .call_stellar_sep43_sign_and_submit_transaction(args)
        .await
        .expect("call must return Ok(CallToolResult)");

    let is_error = result.is_error;
    let text = extract_text(result);

    // ── Assert: no tool-level error ──────────────────────────────────────────
    assert!(
        is_error != Some(true),
        "result must not be an error; is_error = {is_error:?}; text = {text}"
    );
    // `text` is consumed by JSON-parse below; keeping it bound here lets the
    // assertion message above include the wire response on failure (useful for
    // testnet debugging — friendbot rate, RPC flakiness, etc.).
    let envelope: serde_json::Value =
        serde_json::from_str(&text).expect("result text must be valid JSON");

    // The standard result envelope wraps the protocol payload under `data`.
    assert_eq!(
        envelope["ok"], true,
        "a confirmed sign-and-submit must return ok:true (got {envelope})"
    );
    assert!(
        envelope["request_id"]
            .as_str()
            .is_some_and(|r| !r.is_empty()),
        "the envelope must carry a non-empty request_id"
    );
    let response = &envelope["data"];

    // signedTxXdr is present and non-empty.
    let signed_tx_xdr = response["signedTxXdr"]
        .as_str()
        .expect("signedTxXdr must be a string");
    assert!(!signed_tx_xdr.is_empty(), "signedTxXdr must be non-empty");

    // txHash is 64 lowercase hex characters.
    let tx_hash = response["txHash"]
        .as_str()
        .expect("txHash must be a string");
    assert_eq!(
        tx_hash.len(),
        64,
        "txHash must be exactly 64 characters (got {})",
        tx_hash.len()
    );
    assert!(
        tx_hash
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "txHash must be lowercase hex (got {tx_hash})"
    );

    // status is "success".
    let status = response["status"]
        .as_str()
        .expect("status must be a string");
    assert_eq!(status, "success", "status must be 'success' (got {status})");

    // sequence number advanced on-chain.
    let seq_after = fetch_sequence(&g_strkey).await;
    assert!(
        seq_after > seq_before,
        "sequence must advance after submission: before={seq_before}, after={seq_after}"
    );
}

/// Error path: invalid `transaction_xdr` returns SEP-43 code -3 (InvalidXdr)
/// and does not panic or return a JSON-RPC error.
///
/// No Friendbot funding required — the error fires before any RPC call.
#[tokio::test]
#[serial]
async fn sign_and_submit_invalid_xdr_returns_sep43_error() {
    let (g_strkey, seed) = fresh_keypair();

    let server = build_test_server(&g_strkey, &seed);

    let args = Sep43SignAndSubmitTransactionArgs {
        chain_id: TESTNET_CHAIN_ID.to_owned(),
        transaction_xdr: "not-valid-base64-xdr".to_owned(),
        network_passphrase: None,
        address: None,
    };

    let result = server
        .call_stellar_sep43_sign_and_submit_transaction(args)
        .await
        .expect("tool must return Ok even on error");

    assert_eq!(
        result.is_error,
        Some(true),
        "invalid XDR must produce is_error = true"
    );

    let text = extract_text(result);
    let response: serde_json::Value =
        serde_json::from_str(&text).expect("error text must be valid JSON");

    // Sep43Error::InvalidXdr → code -3.
    let code = response["code"].as_i64().expect("code must be integer");
    assert_eq!(
        code, -3,
        "invalid XDR must return SEP-43 code -3 (got {code})"
    );

    let message = response["message"]
        .as_str()
        .expect("message must be a string");
    assert!(!message.is_empty(), "error message must be non-empty");
}

/// Error path: passphrase mismatch returns SEP-43 code -3 (InvalidNetworkPassphrase).
#[tokio::test]
#[serial]
async fn sign_and_submit_passphrase_mismatch_returns_sep43_error() {
    let (g_strkey, seed) = fresh_keypair();

    let server = build_test_server(&g_strkey, &seed);

    // Build a syntactically valid unsigned envelope; error fires during signing.
    let unsigned_xdr = build_self_payment_xdr(&g_strkey, 0);

    let args = Sep43SignAndSubmitTransactionArgs {
        chain_id: TESTNET_CHAIN_ID.to_owned(),
        transaction_xdr: unsigned_xdr,
        network_passphrase: Some("Public Global Stellar Network ; September 2015".to_owned()),
        address: None,
    };

    let result = server
        .call_stellar_sep43_sign_and_submit_transaction(args)
        .await
        .expect("tool must return Ok even on passphrase mismatch");

    assert_eq!(
        result.is_error,
        Some(true),
        "passphrase mismatch must produce is_error = true"
    );

    let text = extract_text(result);
    let response: serde_json::Value =
        serde_json::from_str(&text).expect("error text must be valid JSON");

    // Sep43Error::InvalidNetworkPassphrase → code -3.
    let code = response["code"].as_i64().expect("code must be integer");
    assert_eq!(
        code, -3,
        "passphrase mismatch must return SEP-43 code -3 (got {code})"
    );
}
