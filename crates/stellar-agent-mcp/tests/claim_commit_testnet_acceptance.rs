//! Testnet acceptance: the `stellar_claim` / `stellar_claim_commit` verb pair
//! against a live claimable balance.
//!
//! Flow (happy path):
//! 1. Fund a fresh creator and a fresh claimant via Friendbot and wait until
//!    both are RPC-queryable.
//! 2. The creator submits a `CreateClaimableBalance` transaction (native XLM,
//!    unconditional predicate, single claimant) built directly with
//!    `stellar-baselib` (production code has no balance-creation path by
//!    design; only a claim-side spine).
//! 3. Derive the created balance's canonical 72-hex id per CAP-23 from the
//!    creator's account id, the transaction's sequence number, and the
//!    operation index — no RPC result-XDR fetch is needed or available (the
//!    RPC client's inner handle is `pub(crate)`, and `SubmissionResult` does
//!    not carry the result XDR).
//! 4. Poll until the entry is fetchable (RPC propagation), then simulate
//!    `stellar_claim` under a `RequireApproval` policy engine so the tool's
//!    own approval-persist path runs, extract the surfaced approval nonce,
//!    recompute the attestation blob exactly as `stellar-agent approve`
//!    would, and call `stellar_claim_commit`.
//! 5. Assert the claim reaches ledger inclusion, the claimant's native balance
//!    increased, and the balance entry no longer exists.
//!
//! A companion test drives the predicate guard: a balance with an
//! already-expired `BeforeAbsoluteTime` predicate is refused before any
//! envelope is built or submitted.
//!
//! # Approval-store note
//!
//! `WalletServer::persist_claim_pending_approval` (the internal helper
//! `stellar_claim` calls when the policy engine requires approval) resolves
//! the approval-store directory via `default_approval_dir()` unconditionally
//! — it does not consult the `approval_dir_override` test hook that
//! `verify_attestation_gate` honours. Driving the real persist path therefore
//! means the pending-approval entry lands in the OS-conventional approval
//! directory, not a per-test `tempfile::TempDir`. The happy-path commit
//! removes its own entry on successful submission
//! (`stellar_claim_commit_impl`'s post-submit cleanup), so no state survives
//! a passing run.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-mcp --features testnet-acceptance \
//!   --test claim_commit_testnet_acceptance
//! ```

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]

use std::error::Error;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serial_test::serial;
use stellar_agent_claimable::entry::fetch_claimable_balance_entry;
use stellar_agent_claimable::id::BalanceId;
use stellar_agent_core::approval::{
    compute_attestation, envelope_sha256, process_uid_for_attestation,
};
use stellar_agent_core::policy::v1::{
    AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
    Sep45SessionView,
};
use stellar_agent_core::policy::{
    ApprovalRequest, Decision, PolicyEngine, PolicyError, ToolDescriptor,
};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{StellarClaimArgs, StellarClaimCommitArgs, WalletServer};
use stellar_agent_network::signing::SoftwareSigningKey;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::submit::SubmissionSignerKind;
use stellar_agent_network::{StellarRpcClient, fetch_account, submit_transaction_and_wait};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::testnet_helpers::create_claimable_balance;
use stellar_xdr::ClaimPredicate;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";

/// Per-operation fee, in stroops, for the creator's `CreateClaimableBalance` tx.
const CREATE_FEE_STROOPS_PER_OP: u32 = 100_000;

/// Amount locked in the claimable balance: 25 XLM.
const CLAIM_AMOUNT_STROOPS: i64 = 250_000_000;

/// A `BeforeAbsoluteTime` predicate bound far in the past (1970-01-12), used
/// to construct an already-unsatisfiable claimable balance in
/// `t2_predicate_expired_refused`.
const PAST_ABSOLUTE_TIME_UNIX_SECS: i64 = 1_000_000;

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
            "claim-testnet-approval".into(),
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
async fn wait_until_account_queryable(g_strkey: &str) {
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    for _ in 0..30 {
        if fetch_account(&client, g_strkey, &[]).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("funded account {g_strkey} did not become RPC-queryable in time");
}

/// Polls RPC until the given claimable-balance id is fetchable, tolerating
/// ledger-close / RPC propagation delay after the create tx is confirmed.
async fn wait_until_balance_queryable(client: &StellarRpcClient, id: &BalanceId) {
    for _ in 0..30 {
        if fetch_claimable_balance_entry(client, id).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!(
        "claimable balance {} did not become RPC-queryable in time",
        id.to_hex72()
    );
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

/// Fetches `account_id`'s current sequence number over `client`.
///
/// Takes an owned `account_id` (rather than `&str`) so the closure at the
/// call site produces a future with no lifetime tied to the per-call
/// argument — required for the `Fn(&str) -> FFut` trait bound in
/// [`create_claimable_balance`]'s dependency-injected `fetch_sequence`.
async fn fetch_testnet_sequence(
    client: &StellarRpcClient,
    account_id: String,
) -> Result<i64, Box<dyn Error + Send + Sync>> {
    Ok(fetch_account(client, &account_id, &[])
        .await?
        .sequence_number)
}

/// Signs `unsigned_b64` with a fresh [`SoftwareSigningKey`] built from `seed`.
async fn sign_testnet_envelope(
    unsigned_b64: String,
    seed: Zeroizing<[u8; 32]>,
    network_passphrase: String,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let signer = SoftwareSigningKey::new_from_bytes(*seed);
    Ok(attach_signature(&unsigned_b64, &signer, &network_passphrase).await?)
}

/// Submits `signed_b64` over `client` and waits for ledger confirmation.
async fn submit_testnet_signed_xdr(
    client: &StellarRpcClient,
    signed_b64: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    submit_transaction_and_wait(
        client,
        &signed_b64,
        Duration::from_secs(60),
        TESTNET_PASSPHRASE,
        Some(SubmissionSignerKind::Software),
    )
    .await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// t1: simulate -> approve -> commit, end-to-end, on-chain
// ─────────────────────────────────────────────────────────────────────────────

/// Simulate → approve → commit a real claimable balance on testnet, then
/// verify the balance credited the claimant and the entry is gone.
#[tokio::test]
#[serial]
async fn t1_claim_two_phase_happy_path() {
    keyring_mock::install().expect("mock keyring store init");

    let (creator_g, creator_seed) = fresh_keypair();
    let (claimant_g, claimant_seed) = fresh_keypair();
    fund_via_friendbot(&creator_g).await;
    fund_via_friendbot(&claimant_g).await;
    wait_until_account_queryable(&creator_g).await;
    wait_until_account_queryable(&claimant_g).await;

    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");

    let balance_id_hex72 = create_claimable_balance(
        &creator_g,
        &creator_seed,
        &claimant_g,
        CLAIM_AMOUNT_STROOPS,
        None, // Unconditional predicate.
        TESTNET_PASSPHRASE,
        CREATE_FEE_STROOPS_PER_OP,
        |account_id| fetch_testnet_sequence(&client, account_id.to_owned()),
        |unsigned_b64, seed, network_passphrase| {
            sign_testnet_envelope(unsigned_b64, seed, network_passphrase.to_owned())
        },
        |signed_b64| submit_testnet_signed_xdr(&client, signed_b64),
    )
    .await
    .expect("create_claimable_balance");
    let balance_id = BalanceId::parse(&balance_id_hex72).expect("balance id parses");
    wait_until_balance_queryable(&client, &balance_id).await;

    let claimant_balance_before = fetch_account(&client, &claimant_g, &[])
        .await
        .expect("claimant account fetch (pre-claim)")
        .balances
        .first()
        .and_then(|b| b.balance_stroops().ok())
        .expect("claimant must hold a native balance after Friendbot funding");

    let attestation_key = [0x22u8; 32];
    let mut profile = Profile::builder_testnet(
        "stellar-agent",
        &claimant_g,
        "stellar-agent-nonce",
        &claimant_g,
    )
    .with_noop_engine()
    .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    seed_keyring(&profile, &claimant_seed, &attestation_key);

    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    // Install RequireApproval BEFORE simulating so `stellar_claim`'s own
    // approval-persist path runs for real (see module docs).
    server.set_policy_engine_for_test(std::sync::Arc::new(RequireApprovalEngine));

    // ── 1. Simulate: build the envelope, run the claim guards, persist approval ──
    let sim = server
        .call_stellar_claim(StellarClaimArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            balance_id: balance_id_hex72.clone(),
            source_account: Some(claimant_g.clone()),
        })
        .await
        .expect("simulate must succeed against a live, claimable balance");
    let sim_json = result_json(&sim);
    assert!(
        sim_json["ok"].as_bool().unwrap_or(false),
        "simulate envelope must be ok: {sim_json}"
    );

    let preview = &sim_json["data"]["preview"];
    assert!(
        preview["asset_code"].is_null() && preview["asset_issuer"].is_null(),
        "preview must report the native asset (no code/issuer): {preview}"
    );
    assert_eq!(
        preview["amount_stroops"].as_i64(),
        Some(CLAIM_AMOUNT_STROOPS),
        "preview must report the locked amount: {preview}"
    );
    let claimants = preview["claimants"]
        .as_array()
        .expect("preview must carry a claimants array");
    assert_eq!(
        claimants.len(),
        1,
        "expected exactly one claimant: {preview}"
    );
    assert_eq!(
        claimants[0]["destination"].as_str(),
        Some(claimant_g.as_str()),
        "the sole claimant must be the claiming account: {preview}"
    );
    assert_eq!(
        preview["predicate_satisfied"].as_bool(),
        Some(true),
        "an unconditional predicate must be satisfied: {preview}"
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
    let approval_nonce = sim_json["data"]["approval"]["approval_nonce"]
        .as_str()
        .expect("RequireApproval policy must surface an approval block")
        .to_owned();

    // ── 2. Recompute the attestation blob exactly as `approve` would ───────────
    let uid = process_uid_for_attestation().expect("process uid");
    let sha = envelope_sha256(envelope_xdr.as_bytes());
    let blob = compute_attestation(&attestation_key, &approval_nonce, &sha, &uid);
    let blob_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob);

    // ── 3. Commit: gate verifies the attestation, signs, and submits on-chain ──
    let commit = server
        .call_stellar_claim_commit(StellarClaimCommitArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            balance_id: balance_id_hex72.clone(),
            source_account: Some(claimant_g.clone()),
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

    // ── 4. On-chain effects: claimant credited, entry gone ─────────────────────
    let claimant_balance_after = fetch_account(&client, &claimant_g, &[])
        .await
        .expect("claimant account fetch (post-claim)")
        .balances
        .first()
        .and_then(|b| b.balance_stroops().ok())
        .expect("claimant must still hold a native balance after claiming");
    assert!(
        claimant_balance_after > claimant_balance_before,
        "claimant native balance must strictly increase after claiming \
         (before={claimant_balance_before}, after={claimant_balance_after})"
    );

    let refetch = fetch_claimable_balance_entry(&client, &balance_id).await;
    let err = refetch.expect_err("claimed balance must no longer exist");
    assert_eq!(
        err.code(),
        "claim.balance_not_found",
        "a claimed balance must be gone from the ledger: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// t2: expired predicate refused before any envelope is built or submitted
// ─────────────────────────────────────────────────────────────────────────────

/// A balance whose sole claimant's predicate is already unsatisfiable is
/// refused by the claim guards; nothing is submitted.
#[tokio::test]
#[serial]
async fn t2_predicate_expired_refused() {
    keyring_mock::install().expect("mock keyring store init");

    let (creator_g, creator_seed) = fresh_keypair();
    let (claimant_g, claimant_seed) = fresh_keypair();
    fund_via_friendbot(&creator_g).await;
    fund_via_friendbot(&claimant_g).await;
    wait_until_account_queryable(&creator_g).await;
    wait_until_account_queryable(&claimant_g).await;

    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");

    let balance_id_hex72 = create_claimable_balance(
        &creator_g,
        &creator_seed,
        &claimant_g,
        CLAIM_AMOUNT_STROOPS,
        Some(ClaimPredicate::BeforeAbsoluteTime(
            PAST_ABSOLUTE_TIME_UNIX_SECS,
        )),
        TESTNET_PASSPHRASE,
        CREATE_FEE_STROOPS_PER_OP,
        |account_id| fetch_testnet_sequence(&client, account_id.to_owned()),
        |unsigned_b64, seed, network_passphrase| {
            sign_testnet_envelope(unsigned_b64, seed, network_passphrase.to_owned())
        },
        |signed_b64| submit_testnet_signed_xdr(&client, signed_b64),
    )
    .await
    .expect("create_claimable_balance");
    let balance_id = BalanceId::parse(&balance_id_hex72).expect("balance id parses");
    wait_until_balance_queryable(&client, &balance_id).await;

    let claimant_balance_before = fetch_account(&client, &claimant_g, &[])
        .await
        .expect("claimant account fetch (pre-attempt)")
        .balances
        .first()
        .and_then(|b| b.balance_stroops().ok())
        .expect("claimant must hold a native balance after Friendbot funding");

    let attestation_key = [0x33u8; 32];
    let mut profile = Profile::builder_testnet(
        "stellar-agent",
        &claimant_g,
        "stellar-agent-nonce",
        &claimant_g,
    )
    .with_noop_engine()
    .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    seed_keyring(&profile, &claimant_seed, &attestation_key);

    let server = WalletServer::new(profile).expect("WalletServer::new");

    let sim = server
        .call_stellar_claim(StellarClaimArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            balance_id: balance_id_hex72,
            source_account: Some(claimant_g.clone()),
        })
        .await
        .expect("the claim guard must return a tool-level error result, not an ErrorData");
    assert_eq!(
        sim.is_error,
        Some(true),
        "an expired predicate must be refused before an envelope is built"
    );
    let sim_json = result_json(&sim);
    assert_eq!(
        sim_json["error"]["code"].as_str(),
        Some("claim.predicate_not_satisfied"),
        "refusal must carry the predicate-not-satisfied wire code: {sim_json}"
    );

    let claimant_balance_after = fetch_account(&client, &claimant_g, &[])
        .await
        .expect("claimant account fetch (post-attempt)")
        .balances
        .first()
        .and_then(|b| b.balance_stroops().ok())
        .expect("claimant must still hold a native balance");
    assert_eq!(
        claimant_balance_before, claimant_balance_after,
        "a refused simulate must not move any funds"
    );
}
