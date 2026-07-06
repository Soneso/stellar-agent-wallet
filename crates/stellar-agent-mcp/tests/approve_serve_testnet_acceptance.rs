//! Testnet acceptance: the `approve serve` loopback HTTP inbox drives a real
//! payment approve/reject decision through to `stellar_pay_commit`.
//!
//! Mirrors `pay_commit_testnet_acceptance.rs` for the simulate → commit spine,
//! but the operator's decision is taken over real HTTP against the
//! `stellar-agent-approval-ui` server instead of hand-recomputing the HMAC
//! attestation: `stellar_pay` (under a `RequireApproval` policy) persists the
//! pending entry exactly as production does, the approval-inbox server is
//! started against the same store + attestation key, and a `reqwest` client
//! drives the bootstrap → session-cookie → CSRF → approve/reject flow a
//! browser would.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-mcp --features testnet-acceptance \
//!   --test approve_serve_testnet_acceptance
//! ```

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serial_test::serial;
use stellar_agent_approval_ui::{DecisionContext, ServeConfig, start_serve};
use stellar_agent_core::audit_log::writer::AuditWriter;
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
// RequireApproval engine — forces the simulate call to park a pending entry
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
            "approve-serve-testnet-approval".into(),
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

/// The account's current native (XLM) balance, in stroops.
async fn native_balance_stroops(g_strkey: &str) -> i64 {
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    let view = fetch_account(&client, g_strkey, &[])
        .await
        .expect("fetch_account must succeed for a funded, queryable account");
    view.balances
        .iter()
        .find(|b| b.asset.asset_type == "native")
        .map(|b| b.balance_stroops().expect("native balance parses"))
        .unwrap_or(0)
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

/// Extracts and parses the `<script type="application/json" id="{id}">...` data
/// island embedded by the approval-inbox HTML pages.
fn extract_json_island(html: &str, id: &str) -> serde_json::Value {
    let start_marker = format!("id=\"{id}\">");
    let start = html
        .find(&start_marker)
        .unwrap_or_else(|| panic!("data island '{id}' must be present in the page"))
        + start_marker.len();
    let rest = &html[start..];
    let end = rest
        .find("</script>")
        .expect("data island must be closed by </script>");
    serde_json::from_str(&rest[..end]).expect("data island must be valid JSON")
}

/// Builds and starts an approval-inbox server pointed at the same profile
/// store path and attestation key the `WalletServer` used, plus a fresh
/// tempdir-scoped audit log. Returns the handle, the base URL, and the
/// notification-count receiver (kept alive so watcher sends never error).
async fn start_serve_for_profile(
    server: &WalletServer,
    profile: &Profile,
    approval_dir: &TempDir,
) -> (
    stellar_agent_approval_ui::ServeHandle,
    String,
    tokio::sync::mpsc::UnboundedReceiver<usize>,
) {
    let profile_name = server.profile_name_for_approval();
    let store_path = approval_dir.path().join(format!("{profile_name}.toml"));
    let audit_path = approval_dir.path().join("audit.log");
    let audit_writer = Arc::new(StdMutex::new(
        AuditWriter::open(audit_path, None).expect("audit writer open"),
    ));
    let ctx = DecisionContext::new(
        profile_name,
        store_path,
        profile.attestation_key_id.clone(),
        audit_writer,
        None,
    );
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
    // notify_enabled = false: no OS toast side effects from an automated test.
    let config = ServeConfig::new(
        "127.0.0.1:0".parse().expect("loopback addr"),
        ctx,
        tx,
        false,
    );
    let handle = start_serve(config).await.expect("start_serve");
    let base = format!("http://127.0.0.1:{}", handle.local_addr().port());
    (handle, base, rx)
}

/// A `reqwest::Client` that does not auto-follow redirects, so the bootstrap
/// exchange's `303 See Other` + `Set-Cookie` can be observed directly, the
/// same posture the in-crate router tests take against the assembled router.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client")
}

/// Performs the one-time bootstrap exchange and returns the `name=value`
/// session-cookie header.
async fn bootstrap_session(client: &reqwest::Client, bootstrap_url: &str) -> String {
    let resp = client
        .get(bootstrap_url)
        .send()
        .await
        .expect("bootstrap GET must succeed");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::SEE_OTHER,
        "bootstrap exchange must redirect to /inbox"
    );
    let set_cookie = resp
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("bootstrap must set a session cookie")
        .to_str()
        .expect("cookie header is ASCII");
    set_cookie
        .split(';')
        .next()
        .expect("cookie header carries a name=value pair")
        .trim()
        .to_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: serve approve → commit submits on-chain
// ─────────────────────────────────────────────────────────────────────────────

/// Simulate under `RequireApproval` → operator approves via real HTTP against
/// `approve serve` → the surfaced attestation completes `stellar_pay_commit`
/// on the live testnet ledger.
#[tokio::test]
#[serial]
async fn t1_serve_approve_then_commit_on_testnet() {
    keyring_mock::install().expect("mock keyring store init");

    let (payer_g, payer_seed) = fresh_keypair();
    let (dest_g, _dest_seed) = fresh_keypair();
    fund_via_friendbot(&payer_g).await;
    fund_via_friendbot(&dest_g).await;
    wait_until_queryable(&payer_g).await;
    wait_until_queryable(&dest_g).await;

    let dest_balance_before = native_balance_stroops(&dest_g).await;

    let attestation_key = [0x11u8; 32];
    let approval_dir = TempDir::new().expect("approval temp dir");

    let mut profile =
        Profile::builder_testnet("stellar-agent", &payer_g, "stellar-agent-nonce", &payer_g)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    seed_keyring(&profile, &payer_seed, &attestation_key);

    let mut server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    server.set_approval_dir_for_test(approval_dir.path().to_path_buf());
    server.set_policy_engine_for_test(Arc::new(RequireApprovalEngine));

    // ── 1. Simulate under RequireApproval: production persists the pending ──
    //    entry itself (WalletServer::persist_pay_pending_approval), exactly as
    //    a live `stellar_pay` call under an operator-configured policy would.
    let sim = server
        .call_stellar_pay(StellarPayArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            source: payer_g.clone(),
            destination: dest_g.clone(),
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
        .expect("simulate must succeed against funded accounts");
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
    let approval_nonce = sim_json["data"]["approval"]["approval_nonce"]
        .as_str()
        .expect("RequireApproval simulate must surface an approval_nonce")
        .to_owned();

    // ── 2. Start the approval-inbox server against the same store + key ─────
    let (serve_handle, base, _rx) = start_serve_for_profile(&server, &profile, &approval_dir).await;
    let bootstrap_url = serve_handle.bootstrap_url();
    let client = http_client();

    // ── 3. Bootstrap → session cookie ────────────────────────────────────────
    let cookie = bootstrap_session(&client, &bootstrap_url).await;

    // Single-use: a second exchange of the same bootstrap token 404s.
    let replay = client
        .get(&bootstrap_url)
        .send()
        .await
        .expect("replayed bootstrap GET must complete");
    assert_eq!(
        replay.status(),
        reqwest::StatusCode::NOT_FOUND,
        "the bootstrap token must be single-use"
    );

    // ── 4. Inbox listing carries the parked payment summary ─────────────────
    let pending_resp = client
        .get(format!("{base}/pending.json"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .expect("pending.json GET must succeed");
    assert_eq!(pending_resp.status(), reqwest::StatusCode::OK);
    let pending_json: serde_json::Value = pending_resp
        .json()
        .await
        .expect("pending.json body must be JSON");
    let entries = pending_json["pending"]
        .as_array()
        .expect("pending.json carries a pending array");
    let parked = entries
        .iter()
        .find(|e| e["approval_nonce"] == approval_nonce)
        .unwrap_or_else(|| panic!("parked nonce must be listed in pending.json: {pending_json}"));
    assert_eq!(parked["summary"]["kind"], "payment");
    assert_eq!(parked["summary"]["to"], dest_g);
    assert_eq!(
        parked["summary"]["amount_stroops"],
        PAYMENT_STROOPS.to_string(),
        "the served pending.json carries amounts as decimal strings"
    );

    // ── 5. Detail page → extract the per-nonce CSRF token ────────────────────
    let detail_resp = client
        .get(format!("{base}/approval/{approval_nonce}"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .expect("detail GET must succeed");
    assert_eq!(detail_resp.status(), reqwest::StatusCode::OK);
    let detail_html = detail_resp.text().await.expect("detail body is text");
    assert!(detail_html.contains(&approval_nonce));
    let data_island = extract_json_island(&detail_html, "approval-data");
    let csrf = data_island["csrf"]
        .as_str()
        .expect("detail page surfaces the CSRF token")
        .to_owned();

    // ── 6. Approve over HTTP: mints the attestation via the real attest path ─
    let origin = base.clone();
    let approve_resp = client
        .post(format!("{base}/approval/{approval_nonce}/approve"))
        .header(reqwest::header::COOKIE, &cookie)
        .header(reqwest::header::ORIGIN, &origin)
        .header("X-Stellar-Approval-CSRF", &csrf)
        .send()
        .await
        .expect("approve POST must succeed");
    assert_eq!(approve_resp.status(), reqwest::StatusCode::OK);
    let approve_json: serde_json::Value = approve_resp
        .json()
        .await
        .expect("approve response body must be JSON");
    assert_eq!(approve_json["status"], "attested");
    let attestation_b64 = approve_json["attestation"]
        .as_str()
        .expect("payment approval surfaces an attestation blob")
        .to_owned();

    // Independently verify the surfaced blob against the attestation key —
    // never trust the server's own JSON without cross-checking the crypto.
    let sha = stellar_agent_core::approval::envelope_sha256(envelope_xdr.as_bytes());
    let uid = stellar_agent_core::approval::process_uid_for_attestation()
        .expect("process uid on test host");
    let attestation_bytes: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&attestation_b64)
        .expect("attestation decodes as base64")
        .try_into()
        .expect("attestation is 32 bytes");
    assert!(
        stellar_agent_core::approval::verify_attestation(
            &attestation_key,
            &approval_nonce,
            &sha,
            &uid,
            &attestation_bytes,
        ),
        "the HTTP-surfaced attestation must verify against the attestation key"
    );

    serve_handle.shutdown().await.expect("serve shutdown");

    // ── 7. Commit: gate verifies the attestation, signs, and submits on-chain ─
    let commit = server
        .call_stellar_pay_commit(StellarPayCommitArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            source: payer_g.clone(),
            destination: dest_g.clone(),
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
            approval_attestation: Some(attestation_b64),
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

    // ── 8. On-chain effect: the destination actually received the payment ───
    let dest_balance_after = native_balance_stroops(&dest_g).await;
    assert_eq!(
        dest_balance_after,
        dest_balance_before + PAYMENT_STROOPS,
        "destination balance must increase by exactly the committed payment"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: serve reject → commit refused, no on-chain submission
// ─────────────────────────────────────────────────────────────────────────────

/// Simulate under `RequireApproval` → operator rejects via real HTTP → the
/// commit is refused with the distinct `policy.approval_rejected` wire code
/// and no transaction reaches the ledger.
#[tokio::test]
#[serial]
async fn t2_serve_reject_then_commit_refused() {
    keyring_mock::install().expect("mock keyring store init");

    let (payer_g, payer_seed) = fresh_keypair();
    let (dest_g, _dest_seed) = fresh_keypair();
    fund_via_friendbot(&payer_g).await;
    fund_via_friendbot(&dest_g).await;
    wait_until_queryable(&payer_g).await;
    wait_until_queryable(&dest_g).await;

    let dest_balance_before = native_balance_stroops(&dest_g).await;

    let attestation_key = [0x22u8; 32];
    let approval_dir = TempDir::new().expect("approval temp dir");

    let mut profile =
        Profile::builder_testnet("stellar-agent", &payer_g, "stellar-agent-nonce", &payer_g)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    seed_keyring(&profile, &payer_seed, &attestation_key);

    let mut server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    server.set_approval_dir_for_test(approval_dir.path().to_path_buf());
    server.set_policy_engine_for_test(Arc::new(RequireApprovalEngine));

    // ── 1. Simulate under RequireApproval: parks the pending entry ───────────
    let sim = server
        .call_stellar_pay(StellarPayArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            source: payer_g.clone(),
            destination: dest_g.clone(),
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
        .expect("simulate must succeed against funded accounts");
    let sim_json = result_json(&sim);
    assert!(sim_json["ok"].as_bool().unwrap_or(false));
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
        .expect("RequireApproval simulate must surface an approval_nonce")
        .to_owned();

    // ── 2. Start the approval-inbox server, bootstrap, reject over HTTP ─────
    let (serve_handle, base, _rx) = start_serve_for_profile(&server, &profile, &approval_dir).await;
    let bootstrap_url = serve_handle.bootstrap_url();
    let client = http_client();
    let cookie = bootstrap_session(&client, &bootstrap_url).await;

    let detail_resp = client
        .get(format!("{base}/approval/{approval_nonce}"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .expect("detail GET must succeed");
    let detail_html = detail_resp.text().await.expect("detail body is text");
    let data_island = extract_json_island(&detail_html, "approval-data");
    let csrf = data_island["csrf"]
        .as_str()
        .expect("detail page surfaces the CSRF token")
        .to_owned();

    let reject_resp = client
        .post(format!("{base}/approval/{approval_nonce}/reject"))
        .header(reqwest::header::COOKIE, &cookie)
        .header(reqwest::header::ORIGIN, &base)
        .header("X-Stellar-Approval-CSRF", &csrf)
        .send()
        .await
        .expect("reject POST must succeed");
    assert_eq!(reject_resp.status(), reqwest::StatusCode::OK);
    let reject_json: serde_json::Value = reject_resp
        .json()
        .await
        .expect("reject response body must be JSON");
    assert_eq!(reject_json["status"], "rejected");

    // The rejection tombstone is not expired yet (1h TTL), so the default
    // (non-`include_expired`) pending.json listing — which filters only on
    // expiry, not on kind — still reports it. This is the real behaviour of
    // `routes::take_snapshot`, not an assumption.
    let pending_resp = client
        .get(format!("{base}/pending.json"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .expect("pending.json GET must succeed");
    let pending_json: serde_json::Value = pending_resp
        .json()
        .await
        .expect("pending.json body must be JSON");
    let tombstone = pending_json["pending"]
        .as_array()
        .expect("pending.json carries a pending array")
        .iter()
        .find(|e| e["approval_nonce"] == approval_nonce)
        .unwrap_or_else(|| {
            panic!("the rejected tombstone must still appear in pending.json: {pending_json}")
        });
    assert_eq!(tombstone["kind_name"], "Rejected");
    assert_eq!(tombstone["attested"], false);

    serve_handle.shutdown().await.expect("serve shutdown");

    // ── 3. Commit is refused: a live Rejected tombstone short-circuits the ───
    //    attestation gate before any hash/HMAC check runs, so any well-formed
    //    32-byte attestation blob reaches (and is refused by) that check.
    let bogus_attestation_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]);
    let commit_err = server
        .call_stellar_pay_commit(StellarPayCommitArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            source: payer_g.clone(),
            destination: dest_g.clone(),
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
            approval_attestation: Some(bogus_attestation_b64),
        })
        .await
        .expect_err("commit must be refused after an HTTP reject");
    assert!(
        commit_err.message.contains("policy.approval_rejected"),
        "commit refusal after reject must carry the distinct policy.approval_rejected wire \
         code, not the generic policy.approval_required: {}",
        commit_err.message
    );

    // ── 4. No on-chain effect: the destination balance is unchanged ─────────
    let dest_balance_after = native_balance_stroops(&dest_g).await;
    assert_eq!(
        dest_balance_after, dest_balance_before,
        "a refused commit must never move funds"
    );
}
