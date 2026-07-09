//! Testnet acceptance: a sponsored `stellar_create_account` /
//! `stellar_create_account_commit` two-phase call creates a real account on
//! the live testnet ledger.
//!
//! Flow:
//! 1. Fund a fresh sponsor account via Friendbot and wait until it is
//!    RPC-queryable.
//! 2. Generate a fresh, unfunded destination keypair — `CreateAccount`
//!    requires the destination NOT already exist on the network.
//! 3. Simulate `stellar_create_account` (`Noop` engine on testnet → `Allow`)
//!    to build an envelope funding the destination from the sponsor, mint a
//!    nonce, and obtain the `(envelope_xdr, nonce, expires_at_unix_ms)` triple.
//! 4. Commit: sign and submit on-chain; confirm the destination account now
//!    exists with the sponsored starting balance.
//! 5. Assert the confirmed commit recorded a `value_action_submitted` audit
//!    row for `stellar_create_account_commit`.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-mcp --features testnet-acceptance \
//!   --test create_account_testnet_acceptance
//! ```

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]

use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{
    StellarCreateAccountArgs, StellarCreateAccountCommitArgs, WalletServer,
};
use stellar_agent_network::{StellarRpcClient, fetch_account};
use stellar_agent_test_support::keyring_mock;
use zeroize::Zeroizing;

mod common;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";
const FEE_STROOPS: u32 = 100_000;

/// Starting balance sponsored to the new destination account: 5 XLM.
const STARTING_BALANCE_STROOPS: i64 = 50_000_000;
/// `McpAmountArgument`-shaped JSON literal for [`STARTING_BALANCE_STROOPS`].
const STARTING_BALANCE_XLM_JSON: &str = "\"5 XLM\"";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (mirrors pay_commit_testnet_acceptance.rs / claim_commit_testnet_acceptance.rs)
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

fn seed_keyring(profile: &Profile, seed: &Zeroizing<[u8; 32]>) {
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

    // Audit-log chain-root HMAC key, so the commit's post-submit
    // `value_action_submitted` row is signed and lands.
    let audit_ref = &profile.audit_log_hash_chain_key_id;
    let audit_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x53u8; 32]);
    keyring_core::Entry::new(&audit_ref.service, &audit_ref.account)
        .expect("audit keyring entry")
        .set_password(&audit_key_b64)
        .expect("set audit key");
}

// ─────────────────────────────────────────────────────────────────────────────
// t1: sponsored create-account, simulate -> commit, on-chain
// ─────────────────────────────────────────────────────────────────────────────

/// A sponsor funds a fresh, previously non-existent destination account via
/// `stellar_create_account` / `stellar_create_account_commit`; the destination
/// exists on-chain afterward with the sponsored starting balance, and the
/// commit recorded a `value_action_submitted` audit row.
#[tokio::test]
#[serial]
async fn t1_sponsored_create_account_two_phase_happy_path() {
    keyring_mock::install().expect("mock keyring store init");

    let (sponsor_g, sponsor_seed) = fresh_keypair();
    fund_via_friendbot(&sponsor_g).await;
    wait_until_queryable(&sponsor_g).await;

    // Fresh destination keypair — must NOT be funded; CreateAccount requires
    // the destination not already exist on the network.
    let (destination_g, _destination_seed) = fresh_keypair();

    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");

    let mut profile = Profile::builder_testnet(
        "stellar-agent",
        &sponsor_g,
        "stellar-agent-nonce",
        &sponsor_g,
    )
    .with_noop_engine()
    .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    // Redirect the audit log to a test temp dir so the row can be read back.
    let audit_dir = tempfile::tempdir().expect("audit temp dir");
    profile.audit_log_path = audit_dir.path().join("audit.jsonl");
    seed_keyring(&profile, &sponsor_seed);

    let server = WalletServer::new(profile).expect("WalletServer::new");

    // ── Simulate ───────────────────────────────────────────────────────────
    let sim = server
        .call_stellar_create_account(StellarCreateAccountArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            source: sponsor_g.clone(),
            destination: destination_g.clone(),
            starting_balance: serde_json::from_str(STARTING_BALANCE_XLM_JSON)
                .expect("starting_balance parses as McpAmountArgument"),
            classic_base: Some(FEE_STROOPS.to_string()),
        })
        .await
        .expect("simulate must not error");
    let sim_json = result_json(&sim);
    assert!(
        sim_json["ok"].as_bool().unwrap_or(false),
        "Noop-engine simulate against a funded sponsor must be ok: {sim_json}"
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

    // ── Commit ─────────────────────────────────────────────────────────────
    let commit = server
        .call_stellar_create_account_commit(StellarCreateAccountCommitArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            source: sponsor_g.clone(),
            destination: destination_g.clone(),
            starting_balance: serde_json::from_str(STARTING_BALANCE_XLM_JSON)
                .expect("starting_balance parses as McpAmountArgument"),
            nonce,
            expires_at_unix_ms,
            envelope_xdr,
            approval_nonce: None,
            approval_attestation: None,
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

    // ── On-chain effect: the destination account now exists ────────────────
    let created = fetch_account(&client, &destination_g, &[])
        .await
        .expect("destination account must exist on-chain after the sponsored create");
    let created_balance = created
        .balances
        .first()
        .and_then(|b| b.balance_stroops().ok())
        .expect("newly created account must carry a native balance");
    assert_eq!(
        created_balance, STARTING_BALANCE_STROOPS,
        "destination's on-chain balance must equal the sponsored starting balance"
    );

    // The confirmed commit must have recorded a `value_action_submitted` row
    // for `stellar_create_account_commit`.
    let audit_rows: Vec<serde_json::Value> = std::io::BufRead::lines(std::io::BufReader::new(
        std::fs::File::open(audit_dir.path().join("audit.jsonl")).expect("audit log after commit"),
    ))
    .map(|line| serde_json::from_str(&line.expect("audit line")).expect("audit JSON row"))
    .collect();
    assert!(
        audit_rows.iter().any(|row| {
            row["kind"] == "value_action_submitted"
                && row["tool"] == "stellar_create_account_commit"
        }),
        "sponsored create-account commit must record a value_action_submitted row: {audit_rows:?}"
    );
}
