//! Testnet acceptance: `stellar_trustline` / `stellar_trustline_commit` adds a
//! real classic trustline on the live testnet ledger, under a
//! `minimum_reserve` policy rule that only passes if the gate's
//! `account_view` is genuinely populated with the source account's on-chain
//! balance.
//!
//! `MinimumReserveCriterion::evaluate` fails closed with
//! `PolicyError::CriterionEvaluationFailed` (wire code
//! `policy.criterion_evaluation_failed`) whenever `ctx.account_view` is `None`
//! — a missing wiring cannot silently pass as an allow. This test configures a
//! `minimum_reserve` rule (via an in-memory [`PolicyEngineV1`], mirroring
//! `policy_value_descriptor_testnet_acceptance.rs`) with a small margin the
//! just-funded source account comfortably satisfies. The simulate step
//! reaching `ok:true` — rather than `policy.criterion_evaluation_failed` — is
//! on-chain proof that the dispatch site supplies a real `account_view` built
//! from a live ledger fetch, not a stub. Both `stellar_trustline` and
//! `stellar_trustline_commit` cover the rule (`dispatch_gate_with_views` runs
//! at each dispatch point under its own tool name).
//!
//! The trustline targets the pinned testnet USDC issuer already used by
//! `trustline_integration.rs` (`stellar_agent_stablecoin::resolve`'s testnet
//! pin table) rather than inventing a new asset fixture.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-mcp --features testnet-acceptance \
//!   --test trustline_classic_testnet_acceptance
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
use stellar_agent_core::policy::Decision;
use stellar_agent_core::policy::v1::PolicyEngineV1;
use stellar_agent_core::policy::v1::criteria::{Criterion, MinimumReserveCriterion};
use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{StellarTrustlineArgs, StellarTrustlineCommitArgs, WalletServer};
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

/// `minimum_reserve` margin: 5 XLM. Comfortably below the ~10,000 XLM
/// Friendbot funds, so the rule is satisfied by the source account's real
/// on-chain balance.
const MINIMUM_RESERVE_MARGIN_STROOPS: i64 = 50_000_000;

/// Trustline limit: 100 USDC at 7 decimals.
const LIMIT_STROOPS: &str = "1000000000";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (mirrors trustline_integration.rs / policy_value_descriptor_testnet_acceptance.rs)
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
    let audit_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x54u8; 32]);
    keyring_core::Entry::new(&audit_ref.service, &audit_ref.account)
        .expect("audit keyring entry")
        .set_password(&audit_key_b64)
        .expect("set audit key");
}

/// Builds an `AllProfiles`-scoped, unsigned [`PolicyDocument`] with one
/// `Decision::Allow` `minimum_reserve` rule per tool name in `tools`.
///
/// `dispatch_gate_with_views` is invoked with the literal tool name at each
/// dispatch point (`"stellar_trustline"` at simulate,
/// `"stellar_trustline_commit"` at commit), so both must be covered for the
/// commit step to reach on-chain submission.
fn minimum_reserve_document(tools: &[&str], margin_stroops: i64) -> PolicyDocument {
    let rules = tools
        .iter()
        .map(|tool| {
            let criterion: Box<dyn Criterion> =
                Box::new(MinimumReserveCriterion::new(margin_stroops));
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

// ─────────────────────────────────────────────────────────────────────────────
// t1: classic trustline add, simulate -> commit, on-chain, under a satisfied
// minimum_reserve rule
// ─────────────────────────────────────────────────────────────────────────────

/// A fresh, Friendbot-funded account adds a trustline to the pinned testnet
/// USDC issuer via the simulate/commit pair, under a `minimum_reserve` rule
/// the account's real on-chain balance satisfies. The simulate and commit
/// steps both reaching `ok:true` (rather than
/// `policy.criterion_evaluation_failed`) proves `account_view` was populated
/// with real chain state at both dispatch points.
#[tokio::test]
#[serial]
async fn t1_classic_trustline_add_two_phase_happy_path_under_minimum_reserve_rule() {
    keyring_mock::install().expect("mock keyring store init");

    let (source_g, source_seed) = fresh_keypair();
    fund_via_friendbot(&source_g).await;
    wait_until_queryable(&source_g).await;

    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");

    let mut profile =
        Profile::builder_testnet("stellar-agent", &source_g, "stellar-agent-nonce", &source_g)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    // Redirect the audit log to a test temp dir so the row can be read back.
    let audit_dir = tempfile::tempdir().expect("audit temp dir");
    profile.audit_log_path = audit_dir.path().join("audit.jsonl");
    seed_keyring(&profile, &source_seed);

    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    let doc = minimum_reserve_document(
        &["stellar_trustline", "stellar_trustline_commit"],
        MINIMUM_RESERVE_MARGIN_STROOPS,
    );
    server.set_policy_engine_for_test(Arc::new(PolicyEngineV1::new(doc, source_g.clone())));

    // ── Simulate ───────────────────────────────────────────────────────────
    let sim = server
        .call_stellar_trustline(StellarTrustlineArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            from: source_g.clone(),
            asset: "USDC".to_owned(),
            limit_stroops: Some(LIMIT_STROOPS.to_owned()),
            classic_base: Some(FEE_STROOPS.to_string()),
        })
        .await
        .expect("simulate must not error");
    let sim_json = result_json(&sim);
    assert!(
        sim_json["ok"].as_bool().unwrap_or(false),
        "simulate under a satisfied minimum_reserve rule must be ok — a failure here \
         with policy.criterion_evaluation_failed would mean account_view was not \
         populated by the dispatch site: {sim_json}"
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
        .call_stellar_trustline_commit(StellarTrustlineCommitArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            from: source_g.clone(),
            nonce,
            expires_at_unix_ms,
            envelope_xdr,
            approval_nonce: None,
            approval_attestation: None,
        })
        .await
        .expect("commit must not error");
    let commit_json = result_json(&commit);
    assert!(
        commit_json["ok"].as_bool().unwrap_or(false),
        "commit under a satisfied minimum_reserve rule must be ok (submitted \
         on-chain) — a failure here with policy.criterion_evaluation_failed would \
         mean account_view was not populated at the commit dispatch point: {commit_json}"
    );
    let tx_hash = commit_json["data"]["tx_hash"]
        .as_str()
        .expect("commit must report an on-chain tx_hash");
    assert_eq!(tx_hash.len(), 64, "tx_hash must be a 32-byte hex digest");

    // ── On-chain effect: the trustline now exists with the requested limit ──
    let refreshed = fetch_account(&client, &source_g, &[])
        .await
        .expect("source account fetch after commit");
    let usdc_line = refreshed
        .balances
        .iter()
        .find(|b| {
            b.asset.asset_type == "USDC"
                && b.asset.issuer.as_deref()
                    == Some("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5")
        })
        .expect("a USDC trustline must now exist on the source account");
    let limit_stroops = usdc_line
        .limit
        .as_deref()
        .map(|decimal| {
            let with_unit = format!("{decimal} XLM");
            stellar_agent_core::StellarAmount::parse_with_unit(&with_unit)
                .expect("on-chain trustline limit parses as a 7-decimal amount")
                .as_stroops()
        })
        .expect("a trustline balance entry must carry a limit");
    assert_eq!(
        limit_stroops,
        LIMIT_STROOPS.parse::<i64>().expect("limit parses as i64"),
        "the on-chain trustline limit must equal the requested limit_stroops"
    );

    // The confirmed commit must have recorded a `value_action_submitted` row
    // for `stellar_trustline_commit`.
    let audit_rows: Vec<serde_json::Value> = std::io::BufRead::lines(std::io::BufReader::new(
        std::fs::File::open(audit_dir.path().join("audit.jsonl")).expect("audit log after commit"),
    ))
    .map(|line| serde_json::from_str(&line.expect("audit line")).expect("audit JSON row"))
    .collect();
    assert!(
        audit_rows.iter().any(|row| {
            row["kind"] == "value_action_submitted" && row["tool"] == "stellar_trustline_commit"
        }),
        "trustline commit must record a value_action_submitted row: {audit_rows:?}"
    );
}
