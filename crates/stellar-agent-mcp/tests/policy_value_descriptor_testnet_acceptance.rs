//! Testnet acceptance: the typed value descriptor sizes and gates a call end
//! to end, on the live testnet ledger.
//!
//! Value criteria (e.g. `per_tx_cap`) size a call from the typed
//! [`stellar_agent_core::policy::v1::ValueClass`] descriptor the dispatch gate
//! derives for the tool being called, not from raw JSON args. A `stellar_pay`
//! call resolves to `ValueClass::Value` (a sized debit leg the criterion can
//! compare against its cap); a raw-signing tool such as
//! `stellar_sep43_sign_and_submit_transaction` resolves to `ValueClass::Opaque`
//! (a value effect the wallet cannot decode). A value rule that matches an
//! opaque call denies it fail-closed
//! (`DenyReason::UnsizableValueEffect` / wire code
//! `policy.deny.unsizable_value_effect`) unless the rule carries the explicit
//! operator opt-in `allow_opaque_signing = true`, in which case the engine
//! downgrades the opaque value to read-only for that rule so the rule's own
//! `decision` governs.
//!
//! Four scenarios, each constructing its own [`PolicyEngineV1`] directly from
//! an in-memory [`PolicyDocument`] (no signed policy file on disk — see
//! `set_policy_engine_for_test`, the same substitution point
//! `tests/policy_v1_integration.rs` uses):
//!
//! 1. **Allow, on-chain submit.** A `stellar_pay` of native XLM under a
//!    `per_tx_cap` rule (well above the payment amount) simulates, commits,
//!    signs, and submits on the live testnet ledger; the on-chain result is
//!    confirmed exactly as `pay_commit_testnet_acceptance.rs` does. Because
//!    `dispatch_gate` is invoked with the literal tool name at each step
//!    (`"stellar_pay"` at simulate, `"stellar_pay_commit"` at commit — see
//!    `WalletServer::stellar_pay_commit_impl`), the document carries one
//!    `per_tx_cap` rule per tool name rather than a single rule matching only
//!    `"stellar_pay"`, so the value gate allows both dispatch points.
//! 2. **Deny, `per_tx_cap` exceeded.** A `stellar_pay` over a 1-stroop
//!    `per_tx_cap` returns the business-error envelope with wire code
//!    `policy.deny.per_tx_cap_exceeded` at the simulate step; no envelope is
//!    surfaced and no commit is attempted.
//! 3. **Deny, opaque unsizable.** A broad `tool = "*"` value rule (without the
//!    exemption) matches `stellar_sep43_sign_and_submit_transaction` — an
//!    `OpaqueSign` tool per the same `value::derive_value_class` match arm as
//!    `stellar_sep43_sign_transaction` — and denies it fail-closed with
//!    `policy.deny.unsizable_value_effect` before any keyring access, signing,
//!    or submission.
//! 4. **Allow, exemption.** The same broad rule with
//!    `allow_opaque_signing = true` passes the value gate; the call proceeds
//!    to sign and submit the same well-formed testnet envelope, confirming
//!    on-chain.
//!
//! Scenarios 3 and 4 exercise `stellar_sep43_sign_and_submit_transaction`
//! rather than the sign-only `stellar_sep43_sign_transaction`: the latter's
//! argument type is defined in a `pub(crate)` module
//! (`stellar_agent_mcp::tools::sep43_sign_transaction`) with no `pub use`
//! re-export in `server.rs`, so it is unreachable from an external
//! integration-test crate. `stellar_sep43_sign_and_submit_transaction` shares
//! the identical `ToolValueKind::OpaqueSign` registration and the identical
//! `value::derive_value_class` match arm
//! (`"stellar_sep43_sign_transaction" | "stellar_sep43_sign_and_submit_transaction"`),
//! so it exercises the same value-gate code path, and its argument type
//! (`Sep43SignAndSubmitTransactionArgs`) is re-exported from `server.rs` for
//! test use.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-mcp --features testnet-acceptance \
//!   --test policy_value_descriptor_testnet_acceptance
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
use stellar_agent_core::policy::v1::criteria::{Criterion, PerTxCapCriterion};
use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{
    Sep43SignAndSubmitTransactionArgs, StellarPayArgs, StellarPayCommitArgs, WalletServer,
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

/// `per_tx_cap` cap used by the ALLOW scenarios: 10 000 XLM, far above the
/// 1 XLM payment amount every scenario in this file uses.
const PER_TX_CAP_MAX_STROOPS: i64 = 100_000_000_000;

/// `per_tx_cap` cap used by the DENY scenario: 1 stroop, so any real payment
/// (or the opaque-sign scenarios' `max_stroops`, which is irrelevant once the
/// call is classified opaque) exceeds it.
const PER_TX_CAP_LOW_STROOPS: i64 = 1;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers — funding, keyring, result parsing (mirrors pay_commit_testnet_acceptance.rs)
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

    // Attestation key. Unused by these scenarios (none exercise
    // RequireApproval) but seeded for parity with the other testnet-acceptance
    // fixtures and in case a future scenario in this file needs it.
    let attest_ref = &profile.attestation_key_id;
    let attest_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(attestation_key);
    keyring_core::Entry::new(&attest_ref.service, &attest_ref.account)
        .expect("attestation keyring entry")
        .set_password(&attest_key_b64)
        .expect("set attestation key");
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers — value-gate policy document construction
// ─────────────────────────────────────────────────────────────────────────────

/// Builds an `AllProfiles`-scoped, unsigned [`PolicyDocument`] with one
/// `Decision::Allow` rule per `(tool, max_stroops, allow_opaque_signing)`
/// tuple, each carrying a single `per_tx_cap` criterion for the native asset.
///
/// `ScopeId::AllProfiles` matches any profile name, so the profile name passed
/// to [`PolicyEngineV1::new`] is not load-bearing for these tests.
fn per_tx_cap_document(rules: Vec<(&str, i64, bool)>) -> PolicyDocument {
    let rules = rules
        .into_iter()
        .map(|(tool, max_stroops, allow_opaque_signing)| {
            let criterion: Box<dyn Criterion> = Box::new(PerTxCapCriterion::new(
                "native".to_owned(),
                i128::from(max_stroops),
            ));
            PolicyRule {
                r#match: RuleMatch {
                    tool: tool.to_owned(),
                    chain: "*".to_owned(),
                },
                criteria: vec![criterion],
                decision: Decision::Allow,
                allow_opaque_signing,
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

/// Simulates a 1 XLM self-payment under whatever policy engine `server`
/// currently carries (the Noop engine at construction time — see
/// `Profile::builder_testnet(..).with_noop_engine()` in every test in this
/// file) and returns the unsigned `envelope_xdr`.
///
/// Used by the opaque-sign scenarios (3 and 4) to obtain a well-formed
/// testnet transaction envelope before the policy engine under test is
/// substituted in.
async fn simulate_self_payment_envelope(server: &WalletServer, g_strkey: &str) -> String {
    let sim = server
        .call_stellar_pay(StellarPayArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            source: g_strkey.to_owned(),
            destination: g_strkey.to_owned(),
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
        .expect("Noop-engine simulate must succeed against a funded account");
    let sim_json = result_json(&sim);
    assert!(
        sim_json["ok"].as_bool().unwrap_or(false),
        "Noop-engine simulate must be ok: {sim_json}"
    );
    sim_json["data"]["envelope_xdr"]
        .as_str()
        .expect("simulate must surface envelope_xdr")
        .to_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 1 — Allow: per_tx_cap under the payment amount, on-chain submit
// ─────────────────────────────────────────────────────────────────────────────

/// A `stellar_pay` of native XLM sized well under a `per_tx_cap` rule commits
/// and submits on the live testnet ledger.
#[tokio::test]
#[serial]
async fn value_gate_allow_per_tx_cap_commits_on_testnet() {
    keyring_mock::install().expect("mock keyring store init");

    let (g_strkey, seed) = fresh_keypair();
    fund_via_friendbot(&g_strkey).await;
    wait_until_queryable(&g_strkey).await;

    let attestation_key = [0x51u8; 32];
    let mut profile =
        Profile::builder_testnet("stellar-agent", &g_strkey, "stellar-agent-nonce", &g_strkey)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    seed_keyring(&profile, &seed, &attestation_key);

    let mut server = WalletServer::new(profile).expect("WalletServer::new");

    // One per_tx_cap Allow rule per dispatch-gate tool name: `dispatch_gate` is
    // invoked with "stellar_pay" at simulate time and "stellar_pay_commit" at
    // commit time (see `stellar_pay_commit_impl`), so both must be covered for
    // the commit step to reach on-chain submission.
    let doc = per_tx_cap_document(vec![
        ("stellar_pay", PER_TX_CAP_MAX_STROOPS, false),
        ("stellar_pay_commit", PER_TX_CAP_MAX_STROOPS, false),
    ]);
    server.set_policy_engine_for_test(Arc::new(PolicyEngineV1::new(doc, g_strkey.clone())));

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
        .expect("simulate under an allowing per_tx_cap value rule must succeed");
    let sim_json = result_json(&sim);
    assert!(
        sim_json["ok"].as_bool().unwrap_or(false),
        "simulate under an allowing per_tx_cap value rule must be ok: {sim_json}"
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
        .expect(
            "commit under an allowing per_tx_cap value rule must pass the gate and submit on-chain",
        );
    let commit_json = result_json(&commit);

    assert!(
        commit_json["ok"].as_bool().unwrap_or(false),
        "commit must be ok (submitted on-chain): {commit_json}"
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

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 2 — Deny: per_tx_cap exceeded, no commit attempted
// ─────────────────────────────────────────────────────────────────────────────

/// A `stellar_pay` of native XLM over a 1-stroop `per_tx_cap` denies
/// fail-closed at the simulate step; no envelope is surfaced.
#[tokio::test]
#[serial]
async fn value_gate_deny_per_tx_cap_exceeded_blocks_before_submit() {
    keyring_mock::install().expect("mock keyring store init");

    let (g_strkey, seed) = fresh_keypair();
    fund_via_friendbot(&g_strkey).await;
    wait_until_queryable(&g_strkey).await;

    let attestation_key = [0x52u8; 32];
    let mut profile =
        Profile::builder_testnet("stellar-agent", &g_strkey, "stellar-agent-nonce", &g_strkey)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    seed_keyring(&profile, &seed, &attestation_key);

    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    let doc = per_tx_cap_document(vec![("stellar_pay", PER_TX_CAP_LOW_STROOPS, false)]);
    server.set_policy_engine_for_test(Arc::new(PolicyEngineV1::new(doc, g_strkey.clone())));

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
        .expect("a policy deny must return the business-error envelope, not a protocol error");

    let (code, _message, text) = common::assert_business_envelope(&sim);
    assert_eq!(
        code, "policy.deny.per_tx_cap_exceeded",
        "1 XLM against a 1-stroop per_tx_cap must deny with policy.deny.per_tx_cap_exceeded; \
         got: {text}"
    );
    assert!(
        !text.contains("envelope_xdr"),
        "a denied simulate must not surface an envelope_xdr for the caller to commit: {text}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 3 — Deny: opaque unsizable, no signature or submission
// ─────────────────────────────────────────────────────────────────────────────

/// A broad `tool = "*"` value rule (without `allow_opaque_signing`) matches
/// `stellar_sep43_sign_and_submit_transaction` and denies it fail-closed with
/// `policy.deny.unsizable_value_effect` before any keyring access, signing, or
/// submission.
#[tokio::test]
#[serial]
async fn value_gate_deny_opaque_unsizable_blocks_raw_signing() {
    keyring_mock::install().expect("mock keyring store init");

    let (g_strkey, seed) = fresh_keypair();
    fund_via_friendbot(&g_strkey).await;
    wait_until_queryable(&g_strkey).await;

    let attestation_key = [0x53u8; 32];
    let mut profile =
        Profile::builder_testnet("stellar-agent", &g_strkey, "stellar-agent-nonce", &g_strkey)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    seed_keyring(&profile, &seed, &attestation_key);

    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    let envelope_xdr = simulate_self_payment_envelope(&server, &g_strkey).await;

    // Broad tool="*" value rule WITHOUT the opaque-signing exemption: an
    // OpaqueSign tool's value effect cannot be sized, so the criterion denies
    // it fail-closed regardless of max_stroops.
    let doc = per_tx_cap_document(vec![("*", PER_TX_CAP_MAX_STROOPS, false)]);
    server.set_policy_engine_for_test(Arc::new(PolicyEngineV1::new(doc, g_strkey.clone())));

    let result = server
        .call_stellar_sep43_sign_and_submit_transaction(Sep43SignAndSubmitTransactionArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            transaction_xdr: envelope_xdr,
            network_passphrase: None,
            address: None,
        })
        .await
        .expect(
            "the value-gate deny must return the business-error envelope, not a protocol error",
        );

    let (code, _message, text) = common::assert_business_envelope(&result);
    assert_eq!(
        code, "policy.deny.unsizable_value_effect",
        "an opaque-sign tool matched by a value rule without allow_opaque_signing must deny \
         with policy.deny.unsizable_value_effect; got: {text}"
    );
    assert!(
        !text.contains("signedTxXdr") && !text.contains("txHash"),
        "the fail-closed deny must fire before any signing or submission: {text}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 4 — Allow: allow_opaque_signing exemption, on-chain submit
// ─────────────────────────────────────────────────────────────────────────────

/// The same broad `tool = "*"` value rule as scenario 3, but with the explicit
/// operator opt-in `allow_opaque_signing = true`: the engine downgrades the
/// opaque value class to read-only for this rule, the `per_tx_cap` criterion
/// treats the call as not-applicable, and the rule's own `Allow` decision
/// governs — the call proceeds to sign and submit on the live testnet ledger.
#[tokio::test]
#[serial]
async fn value_gate_allow_opaque_signing_exemption_permits_raw_signing() {
    keyring_mock::install().expect("mock keyring store init");

    let (g_strkey, seed) = fresh_keypair();
    fund_via_friendbot(&g_strkey).await;
    wait_until_queryable(&g_strkey).await;

    let attestation_key = [0x54u8; 32];
    let mut profile =
        Profile::builder_testnet("stellar-agent", &g_strkey, "stellar-agent-nonce", &g_strkey)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    seed_keyring(&profile, &seed, &attestation_key);

    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    let envelope_xdr = simulate_self_payment_envelope(&server, &g_strkey).await;

    let doc = per_tx_cap_document(vec![("*", PER_TX_CAP_MAX_STROOPS, true)]);
    server.set_policy_engine_for_test(Arc::new(PolicyEngineV1::new(doc, g_strkey.clone())));

    let result = server
        .call_stellar_sep43_sign_and_submit_transaction(Sep43SignAndSubmitTransactionArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            transaction_xdr: envelope_xdr,
            network_passphrase: None,
            address: None,
        })
        .await
        .expect("the allow_opaque_signing exemption must pass the value gate and reach signing");

    assert_ne!(
        result.is_error,
        Some(true),
        "the exempted call must not surface a business-error envelope; is_error={:?}",
        result.is_error
    );
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .expect("tool result must carry text content");
    assert!(
        !text.contains("policy.deny.unsizable_value_effect"),
        "the allow_opaque_signing exemption must not deny with unsizable_value_effect: {text}"
    );
    let value: serde_json::Value =
        serde_json::from_str(text).expect("tool result text must be valid JSON");
    assert_eq!(
        value["status"], "success",
        "the exempted sign-and-submit must confirm on-chain: {text}"
    );
    let signed_xdr = value["signedTxXdr"]
        .as_str()
        .expect("a successful sign-and-submit must surface signedTxXdr");
    assert!(!signed_xdr.is_empty(), "signedTxXdr must not be empty");
    let tx_hash = value["txHash"]
        .as_str()
        .expect("a confirmed submission must surface txHash");
    assert_eq!(tx_hash.len(), 64, "txHash must be a 32-byte hex digest");
}
