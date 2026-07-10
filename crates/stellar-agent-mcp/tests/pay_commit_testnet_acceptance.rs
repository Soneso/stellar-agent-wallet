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
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
use stellar_agent_core::policy::v1::criteria::{Criterion, PerTxCapCriterion};
use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
use stellar_agent_core::policy::v1::{
    AccountIdentityView, AccountReservesView, CounterpartyCacheView, PolicyEngineV1,
    Sep10SessionView, Sep45SessionView,
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

    // Audit-log chain-root HMAC key, so the commit's post-submit
    // `value_action_submitted` row is signed and lands (the loader reads this
    // coordinate; without it the emission is a non-fatal no-op).
    let audit_ref = &profile.audit_log_hash_chain_key_id;
    let audit_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x33u8; 32]);
    keyring_core::Entry::new(&audit_ref.service, &audit_ref.account)
        .expect("audit keyring entry")
        .set_password(&audit_key_b64)
        .expect("set audit key");
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
    // Redirect the audit log to the test temp dir so the row can be read back.
    profile.audit_log_path = approval_dir.path().join("audit.jsonl");
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

    // The confirmed commit must have recorded a `value_action_submitted`
    // row for `stellar_pay_commit`, signed under the profile's audit chain-root
    // key (verifiable by `audit verify`).
    let audit_path = approval_dir.path().join("audit.jsonl");
    let audit_rows: Vec<serde_json::Value> = std::io::BufRead::lines(std::io::BufReader::new(
        std::fs::File::open(&audit_path).expect("audit log exists after commit"),
    ))
    .map(|line| serde_json::from_str(&line.expect("audit line")).expect("audit JSON row"))
    .collect();
    assert!(
        audit_rows.iter().any(|row| {
            row["kind"] == "value_action_submitted" && row["tool"] == "stellar_pay_commit"
        }),
        "commit must record a value_action_submitted row: {audit_rows:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// V1-engine variant: the audit row's leg content matches the submitted values
// ─────────────────────────────────────────────────────────────────────────────

/// Builds an `AllProfiles`-scoped, unsigned [`PolicyDocument`] with one
/// `Decision::Allow` `per_tx_cap` rule per tool name in `tools`, well above
/// `PAYMENT_STROOPS`.
///
/// `dispatch_gate` is invoked with the literal tool name at each dispatch
/// point (`"stellar_pay"` at simulate, `"stellar_pay_commit"` at commit), so
/// both must be covered for the commit step to reach on-chain submission.
fn per_tx_cap_document(tools: &[&str]) -> PolicyDocument {
    const CAP_STROOPS: i128 = 100_000_000_000; // 10 000 XLM
    let rules = tools
        .iter()
        .map(|tool| {
            let criterion: Box<dyn Criterion> =
                Box::new(PerTxCapCriterion::new("native".to_owned(), CAP_STROOPS));
            PolicyRule {
                r#match: RuleMatch {
                    tool: (*tool).to_owned(),
                    chain: "*".to_owned(),
                },
                criteria: vec![criterion],
                decision: Decision::Allow,
                allow_opaque_signing: false,
            }
        })
        .collect();
    PolicyDocument {
        version: 1,
        scope: ScopeId::AllProfiles,
        rules,
        signature: None,
    }
}

/// A `stellar_pay` self-payment under a `PolicyEngineV1` `per_tx_cap` rule
/// (rather than the `Noop` engine the happy-path test above uses) commits and
/// submits on the live testnet ledger, and the confirmed commit's
/// `value_action_submitted` audit row carries a `legs` entry whose content —
/// `action`, `amount`, `asset`, and the redacted `destination` — equals
/// exactly the values submitted on-chain, proving the row is built from the
/// same `ValueEffects` the V1 engine sized rather than a placeholder or
/// re-derived value.
#[tokio::test]
#[serial]
async fn pay_v1_engine_commit_records_matching_leg_content_on_testnet() {
    keyring_mock::install().expect("mock keyring store init");

    let (g_strkey, seed) = fresh_keypair();
    fund_via_friendbot(&g_strkey).await;
    wait_until_queryable(&g_strkey).await;

    let attestation_key = [0x61u8; 32];
    let mut profile =
        Profile::builder_testnet("stellar-agent", &g_strkey, "stellar-agent-nonce", &g_strkey)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    let audit_dir = tempfile::tempdir().expect("audit temp dir");
    profile.audit_log_path = audit_dir.path().join("audit.jsonl");
    seed_keyring(&profile, &seed, &attestation_key);

    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    let doc = per_tx_cap_document(&["stellar_pay", "stellar_pay_commit"]);
    server.set_policy_engine_for_test(Arc::new(PolicyEngineV1::new(doc, g_strkey.clone())));

    // ── Simulate ───────────────────────────────────────────────────────────
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
        .expect("simulate must not error");
    let sim_json = result_json(&sim);
    assert!(
        sim_json["ok"].as_bool().unwrap_or(false),
        "simulate under an allowing V1 per_tx_cap rule must be ok: {sim_json}"
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
            approval_nonce: None,
            approval_attestation: None,
        })
        .await
        .expect("commit must pass the gate and submit on-chain");
    let commit_json = result_json(&commit);
    assert!(
        commit_json["ok"].as_bool().unwrap_or(false),
        "commit under an allowing V1 per_tx_cap rule must be ok (submitted on-chain): \
         {commit_json}"
    );
    assert!(
        commit_json["data"]["tx_hash"].as_str().is_some(),
        "commit must report an on-chain tx_hash: {commit_json}"
    );

    // ── The value_action_submitted row's leg content matches the submitted
    // values ─────────────────────────────────────────────────────────────────
    let audit_rows: Vec<serde_json::Value> = std::io::BufRead::lines(std::io::BufReader::new(
        std::fs::File::open(audit_dir.path().join("audit.jsonl")).expect("audit log after commit"),
    ))
    .map(|line| serde_json::from_str(&line.expect("audit line")).expect("audit JSON row"))
    .collect();
    let row = audit_rows
        .iter()
        .find(|row| row["kind"] == "value_action_submitted" && row["tool"] == "stellar_pay_commit")
        .unwrap_or_else(|| {
            panic!("commit must record a value_action_submitted row: {audit_rows:?}")
        });

    let legs = row["legs"]
        .as_array()
        .expect("value_action_submitted row must carry a legs array");
    assert_eq!(
        legs.len(),
        1,
        "a single-leg native self-payment must record exactly one leg: {row}"
    );
    let leg = &legs[0];
    assert_eq!(
        leg["action"], "payment",
        "the leg action must be the payment kind the V1 engine sized: {leg}"
    );
    assert_eq!(
        leg["amount"].as_str(),
        Some(PAYMENT_STROOPS.to_string().as_str()),
        "the leg amount must equal the submitted payment amount: {leg}"
    );
    assert_eq!(
        leg["asset"].as_str(),
        Some("native"),
        "the leg asset must equal the submitted native asset: {leg}"
    );
    assert_eq!(
        leg["destination_redacted"].as_str(),
        Some(redact_strkey_first5_last5(&g_strkey).as_str()),
        "the leg destination must be the redacted form of the submitted destination: {leg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// V1-engine variant: `per_period_cap` denies a second live payment once the
// accumulated window exceeds the cap, proving the PERSISTED window-state
// store (not merely in-memory engine state) governs live testnet submits.
// ─────────────────────────────────────────────────────────────────────────────

/// Builds an `AllProfiles`-scoped, unsigned [`PolicyDocument`] with one
/// `Decision::Allow` `per_period_cap` rule (native, `window`, `cap_stroops`)
/// per tool name in `tools`. Mirrors [`per_tx_cap_document`]'s per-tool-name
/// coverage rationale: `dispatch_gate` is invoked with the literal tool name
/// at each dispatch point, so both `"stellar_pay"` (simulate) and
/// `"stellar_pay_commit"` (commit) must be covered.
fn per_period_cap_document(tools: &[&str], window: &str, cap_stroops: i128) -> PolicyDocument {
    let parsed_window = Window::parse(window).expect("valid window literal");
    let rules = tools
        .iter()
        .map(|tool| {
            let criterion: Box<dyn Criterion> = Box::new(PerPeriodCapCriterion::new(
                "native".to_owned(),
                parsed_window,
                cap_stroops,
            ));
            PolicyRule {
                r#match: RuleMatch {
                    tool: (*tool).to_owned(),
                    chain: "*".to_owned(),
                },
                criteria: vec![criterion],
                decision: Decision::Allow,
                allow_opaque_signing: false,
            }
        })
        .collect();
    PolicyDocument {
        version: 1,
        scope: ScopeId::AllProfiles,
        rules,
        signature: None,
    }
}

/// Two live `stellar_pay` self-payments (60 XLM each) under a `PolicyEngineV1`
/// `per_period_cap` rule (100 XLM cap, 1-day window): the first commits and
/// submits on-chain, which records the confirmed amount to the PERSISTED
/// window-state store; the second is DENIED at the simulate step because
/// `dispatch_gate_inner`'s window-state refresh re-hydrates that persisted
/// total before evaluating — 60 + 60 = 120 XLM exceeds the 100 XLM cap.
///
/// This is the live-network counterpart to
/// `pay_two_phase_per_period_cap_second_call_denied_by_persisted_window`
/// (`pay_integration.rs`, wiremock-backed): same shape, real testnet
/// Friendbot funding and RPC submission instead of a mock responder.
///
/// `STELLAR_AGENT_HOME` is overridden to a per-test temp directory so the
/// persisted window-state file (and its keyring-backed HMAC/generation
/// counter, itself routed through the mock keyring installed above) never
/// touches the operator's real OS state directory.
#[tokio::test]
#[serial]
async fn pay_v1_per_period_cap_second_payment_denied_by_persisted_window_on_testnet() {
    keyring_mock::install().expect("mock keyring store init");

    let home_dir = tempfile::TempDir::new().expect("tempdir");
    let _home_guard = stellar_agent_test_support::StellarAgentHomeGuard::new(home_dir.path());

    let (g_strkey, seed) = fresh_keypair();
    fund_via_friendbot(&g_strkey).await;
    wait_until_queryable(&g_strkey).await;

    let attestation_key = [0x71u8; 32];
    let mut profile =
        Profile::builder_testnet("stellar-agent", &g_strkey, "stellar-agent-nonce", &g_strkey)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    let audit_dir = tempfile::tempdir().expect("audit temp dir");
    profile.audit_log_path = audit_dir.path().join("audit.jsonl");
    seed_keyring(&profile, &seed, &attestation_key);

    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    let profile_name = server.profile_name_for_approval();
    let doc = per_period_cap_document(
        &["stellar_pay", "stellar_pay_commit"],
        "1d",
        1_000_000_000, // 100 XLM cap
    );
    server.set_policy_engine_for_test(Arc::new(PolicyEngineV1::new(doc, profile_name)));

    let pay_args = StellarPayArgs {
        chain_id: TESTNET_CHAIN_ID.to_owned(),
        source: g_strkey.clone(),
        destination: g_strkey.clone(),
        amount: Some(serde_json::from_str(r#""60 XLM""#).expect("amount")),
        amount_in_stroops: None,
        asset: "native".to_owned(),
        memo_text: None,
        memo_id: None,
        memo_hash_hex: None,
        memo_return_hex: None,
        classic_base: Some(FEE_STROOPS.to_string()),
    };

    // ── Payment 1: simulate -> commit -> submit succeeds on-chain ────────────
    let sim1 = server
        .call_stellar_pay(pay_args.clone())
        .await
        .expect("first simulate must not error");
    assert_ne!(
        sim1.is_error,
        Some(true),
        "first simulate (60 XLM, under the 100 XLM cap) must succeed: {}",
        result_json(&sim1)
    );
    let sim1_json = result_json(&sim1);
    let sim1_data = sim1_json
        .get("data")
        .expect("first simulate success carries data");
    let nonce1 = sim1_data
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .expect("nonce present")
        .to_owned();
    let expires1 = sim1_data
        .get("expires_at_unix_ms")
        .and_then(serde_json::Value::as_u64)
        .expect("expires_at_unix_ms present");
    let envelope1 = sim1_data
        .get("envelope_xdr")
        .and_then(serde_json::Value::as_str)
        .expect("envelope_xdr present")
        .to_owned();

    let commit1 = server
        .call_stellar_pay_commit(StellarPayCommitArgs {
            chain_id: pay_args.chain_id.clone(),
            source: pay_args.source.clone(),
            destination: pay_args.destination.clone(),
            amount: pay_args.amount.clone(),
            amount_in_stroops: pay_args.amount_in_stroops.clone(),
            asset: pay_args.asset.clone(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            nonce: nonce1,
            expires_at_unix_ms: expires1,
            envelope_xdr: envelope1,
            approval_nonce: None,
            approval_attestation: None,
        })
        .await
        .expect("first commit must not error");
    let commit1_json = result_json(&commit1);
    assert_ne!(
        commit1.is_error,
        Some(true),
        "first commit (60 XLM, under the 100 XLM cap) must submit on-chain: {commit1_json}"
    );
    assert!(
        commit1_json["data"]["tx_hash"].as_str().is_some(),
        "first commit must report an on-chain tx_hash: {commit1_json}"
    );

    // ── Payment 2: simulate is DENIED by the persisted window ────────────────
    let sim2 = server
        .call_stellar_pay(pay_args)
        .await
        .expect("second simulate must return a business-error result, not a protocol error");
    assert_eq!(
        sim2.is_error,
        Some(true),
        "second simulate (60 + 60 = 120 XLM, over the 100 XLM cap) must be denied"
    );
    let sim2_json = result_json(&sim2);
    assert_eq!(
        sim2_json["error"]["code"].as_str(),
        Some("policy.deny.per_period_cap_exceeded"),
        "second simulate must be denied specifically by per_period_cap, got: {sim2_json}"
    );
}
