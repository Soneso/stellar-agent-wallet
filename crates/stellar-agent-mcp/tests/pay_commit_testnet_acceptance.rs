//! Testnet acceptance: the approval-gated payment commit completes on-chain.
//!
//! Closes the end-to-end gap noted in
//! `toolset_sign_payment_gated_testnet_acceptance.rs`: a payment the policy engine
//! gates with `RequireApproval` is simulated, approved, then committed and
//! submitted to the live testnet ledger. The operator's `approve` step surfaces
//! the HMAC attestation blob the commit requires; this test recomputes that blob
//! exactly as `approve` does and presents it to the commit.
//!
//! Flow:
//! 1. Fund a fresh account via Friendbot and wait until it is RPC-queryable.
//! 2. Simulate `stellar_pay` (Noop engine → Allow) to build an envelope from the
//!    live account state and obtain the `(envelope_xdr, nonce, expires)` triple.
//! 3. Switch to a `RequireApproval` engine so the commit must carry a verified
//!    attestation, and stage the `PaymentSimulated` approval the operator would
//!    have created with `approve`.
//! 4. Recompute the surfaced attestation blob and call `stellar_pay_commit`,
//!    which signs the envelope and submits it; assert an on-chain `tx_hash`.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-mcp --features testnet-acceptance \
//!   --test pay_commit_testnet_acceptance
//! ```

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serial_test::serial;
use stellar_agent_core::approval::store::PendingApproval;
use stellar_agent_core::approval::{
    PendingApprovalStore, compute_attestation, envelope_sha256, process_uid_for_attestation,
};
use stellar_agent_core::policy::v1::{
    AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
    Sep45SessionView,
};
use stellar_agent_core::policy::{
    ApprovalRequest, Decision, PolicyEngine, PolicyError, ToolDescriptor,
};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{StellarPayArgs, StellarPayCommitArgs, WalletServer};
use stellar_agent_network::{StellarRpcClient, fetch_account};
use stellar_agent_test_support::keyring_mock;
use tempfile::TempDir;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";
const FEE_STROOPS: u32 = 100_000;
const PAYMENT_STROOPS: i64 = 10_000_000; // 1 XLM

// ─────────────────────────────────────────────────────────────────────────────
// RequireApproval engine — forces the commit through the attestation gate
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
            "pay-testnet-approval".into(),
            600,
        )))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let g_strkey = stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
        .to_string()
        .as_str()
        .to_owned();
    (g_strkey, Zeroizing::new(signing_key.to_bytes()))
}

async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = reqwest::get(&url)
        .await
        .expect("Friendbot HTTP request must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 2xx for {g_strkey}; got {}",
        resp.status()
    );
}

/// Polls RPC until the freshly-funded account is queryable, tolerating
/// Friendbot/RPC eventual consistency.
async fn wait_until_queryable(g_strkey: &str) {
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    for _ in 0..30 {
        if fetch_account(&client, g_strkey, &[]).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("funded account {g_strkey} did not become RPC-queryable in time");
}

fn result_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .expect("tool result must carry text content");
    serde_json::from_str(text).expect("tool result text must be valid JSON")
}

fn seed_keyring(profile: &Profile, seed: &Zeroizing<[u8; 32]>, attestation_key: &[u8; 32]) {
    // Signing key.
    let signer_ref = &profile.mcp_signer_default;
    let s_strkey = stellar_strkey::ed25519::PrivateKey::from_payload(seed.as_ref())
        .expect("32-byte seed encodes as S-strkey")
        .as_unredacted()
        .to_string();
    keyring_core::Entry::new(&signer_ref.service, &signer_ref.account)
        .expect("signer keyring entry")
        .set_password(&s_strkey)
        .expect("set signing key");

    // Nonce key.
    let nonce_ref = &profile.mcp_nonce_key_alias;
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42u8; 32]);
    keyring_core::Entry::new(&nonce_ref.service, &nonce_ref.account)
        .expect("nonce keyring entry")
        .set_password(&nonce_key_b64)
        .expect("set nonce key");

    // Attestation key.
    let attest_ref = &profile.attestation_key_id;
    let attest_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(attestation_key);
    keyring_core::Entry::new(&attest_ref.service, &attest_ref.account)
        .expect("attestation keyring entry")
        .set_password(&attest_key_b64)
        .expect("set attestation key");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test
// ─────────────────────────────────────────────────────────────────────────────

/// Simulate → approve → commit, end-to-end, with the commit submitting a real
/// self-payment to the live testnet ledger under the attestation gate.
#[tokio::test]
#[serial]
async fn pay_with_approval_commits_and_submits_on_testnet() {
    keyring_mock::install().expect("mock keyring store init");

    let (g_strkey, seed) = fresh_keypair();
    fund_via_friendbot(&g_strkey).await;
    wait_until_queryable(&g_strkey).await;

    let attestation_key = [0x11u8; 32];
    let approval_dir = TempDir::new().expect("approval temp dir");

    // builder_testnet(_, derived_name, _, _) → profile name == g_strkey.
    let mut profile =
        Profile::builder_testnet("stellar-agent", &g_strkey, "stellar-agent-nonce", &g_strkey)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    seed_keyring(&profile, &seed, &attestation_key);

    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    server.set_approval_dir_for_test(approval_dir.path().to_path_buf());

    // ── 1. Simulate (Noop → Allow): build the envelope from live account state ──
    let sim = server
        .call_stellar_pay(StellarPayArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            source: g_strkey.clone(),
            destination: g_strkey.clone(),
            amount: Some(serde_json::from_str(r#""1 XLM""#).expect("amount")),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            classic_base: Some(FEE_STROOPS.to_string()),
        })
        .await
        .expect("simulate must succeed against funded account");
    let sim_json = result_json(&sim);
    assert!(
        sim_json["ok"].as_bool().unwrap_or(false),
        "simulate envelope must be ok: {sim_json}"
    );
    let envelope_xdr = sim_json["data"]["envelope_xdr"]
        .as_str()
        .expect("simulate must surface envelope_xdr")
        .to_owned();
    let nonce = sim_json["data"]["nonce"]
        .as_str()
        .expect("simulate must surface nonce")
        .to_owned();
    let expires_at_unix_ms = sim_json["data"]["expires_at_unix_ms"]
        .as_u64()
        .expect("simulate must surface expires_at_unix_ms");

    // ── 2. Switch to RequireApproval and stage the operator's approval ─────────
    server.set_policy_engine_for_test(Arc::new(RequireApprovalEngine));

    let uid = process_uid_for_attestation().expect("process uid");
    let entry = PendingApproval::new_payment_pending(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(envelope_xdr.as_bytes()),
        envelope_xdr.as_bytes(),
        g_strkey.clone(),
        PAYMENT_STROOPS,
        "XLM".to_owned(),
        None,
        FEE_STROOPS,
        1,
        uid.clone(),
        60_000, // 60s TTL → live for the commit
    )
    .expect("new_payment_pending");
    let approval_nonce = entry.approval_nonce.clone();
    {
        let store_path = approval_dir.path().join(format!("{g_strkey}.toml"));
        let mut store = PendingApprovalStore::open(store_path).expect("open store");
        let now_ms = stellar_agent_core::timefmt::now_unix_ms().expect("now");
        store.insert(entry, now_ms).expect("insert approval");
        // Store dropped: lock released so the commit gate can open it.
    }

    // The attestation blob exactly as `stellar-agent approve --id` surfaces it.
    let sha = envelope_sha256(envelope_xdr.as_bytes());
    let blob = compute_attestation(&attestation_key, &approval_nonce, &sha, &uid);
    let blob_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob);

    // ── 3. Commit: gate verifies the attestation, signs, and submits on-chain ──
    let commit = server
        .call_stellar_pay_commit(StellarPayCommitArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            source: g_strkey.clone(),
            destination: g_strkey.clone(),
            amount: Some(serde_json::from_str(r#""1 XLM""#).expect("amount")),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            nonce,
            expires_at_unix_ms,
            envelope_xdr,
            approval_nonce: Some(approval_nonce),
            approval_attestation: Some(blob_b64),
        })
        .await
        .expect("commit must pass the gate and submit on-chain");
    let commit_json = result_json(&commit);

    assert!(
        commit_json["ok"].as_bool().unwrap_or(false),
        "commit envelope must be ok (submitted on-chain): {commit_json}"
    );
    let tx_hash = commit_json["data"]["tx_hash"]
        .as_str()
        .expect("commit must report an on-chain tx_hash");
    assert_eq!(tx_hash.len(), 64, "tx_hash must be a 32-byte hex digest");
    assert!(
        commit_json["data"]["ledger"].as_u64().unwrap_or(0) > 0,
        "commit must report the ledger it was included in: {commit_json}"
    );
}
