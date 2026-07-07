//! Testnet acceptance: the `stellar_rule_create` / `stellar_rule_create_commit`
//! verb pair (Package D) against a live smart account.
//!
//! This test exercises the exact commit-path code the pre-submit deadline
//! (GH issue #31) bounds: `stellar_rule_create_commit` drives
//! `ContextRuleManager::install_rule`, which calls the free-function
//! `submit_signed_invoke` (`stellar-agent-smart-account/src/submit.rs`) to
//! submit a wallet self-call (`add_context_rule`). That path runs an initial
//! `fetch_account` + `simulate_transaction_envelope`, then re-simulates with
//! the signed auth entry attached (`resimulate_with_signed_auth`) before
//! signing the envelope and submitting. All four pre-submit RPC round-trips
//! share ONE collective deadline (`args.timeout`); the final submit+poll
//! stage keeps its own, separate `args.timeout` budget.
//!
//! Flow (happy path, end-to-end, on-chain):
//!
//! 1. Fund a fresh agent ed25519 keypair via Friendbot and wait until it is
//!    RPC-queryable.
//! 2. Deploy a smart account whose genesis `Signer::Delegated` bootstrap
//!    signer (rule 0) IS the agent key, so the agent's own keyring-held
//!    secret can authorize `add_context_rule` under `auth_rule_ids = [0]`.
//! 3. Build a testnet `Profile` whose `mcp_signer_default` is the agent
//!    keyring entry; seed the mock keyring with the agent seed and an
//!    attestation key.
//! 4. Propose a `RuleContext::Default` rule with a single fresh `Delegated`
//!    signer via `stellar_rule_create`, capturing `approval_nonce` and
//!    `proposal_sha256_hex`.
//! 5. Recompute the operator attestation exactly as `stellar-agent approve`
//!    does for a `RuleProposalSimulated` entry
//!    (`compute_attestation(key, nonce, proposal_sha256, process_uid)`,
//!    verified by `PendingApprovalStore::verify_rule_proposal_gate` — the
//!    dedicated rule-proposal gate, not the shared pay/claim attestation
//!    gate).
//! 6. Commit via `stellar_rule_create_commit`; assert the response reports a
//!    non-bootstrap `rule_id` and a 64-hex-char confirmed `tx_hash`.
//! 7. On-chain assert: `ContextRuleManager::get_rule` returns `Some(_)` for
//!    the newly installed rule.
//!
//! `stellar_rule_create` / `stellar_rule_create_commit` are called through
//! the `call_stellar_rule_create*` test helpers, which invoke the public MCP
//! tool handlers directly (bypassing the rmcp transport). This bypasses the
//! toolset-invocation dispatcher entirely, so no `ApprovalKind::
//! ToolsetFirstInvokeGate` entry is ever parked by this flow — that gate is
//! constructed only by `stellar-agent-toolsets-runtime`'s toolset-dispatch
//! path (`stellar_toolset_invoke`), which this test does not exercise.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-mcp --features "testnet-acceptance test-helpers" \
//!   --test rule_create_commit_testnet_acceptance
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
use rand_core::{OsRng, RngCore as _};
use serial_test::serial;
use stellar_agent_core::approval::{compute_attestation, process_uid_for_attestation};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{
    RuleCreateSignerArg, StellarRuleCreateArgs, StellarRuleCreateCommitArgs, WalletServer,
};
use stellar_agent_network::signing::SoftwareSigningKey;
use stellar_agent_network::{Signer, StellarRpcClient, fetch_account};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
};
use stellar_agent_smart_account::managers::rules::{
    ContextRuleManager, ContextRuleManagerConfig, parse_c_strkey_to_smart_account,
};
use stellar_agent_test_support::keyring_mock;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";

/// Deployment + install-rule submission timeout, in seconds — the same
/// `args.timeout` value `build_write_context_rule_manager`
/// (`stellar-agent-mcp/src/tools/rule_create.rs`) uses for the manager that
/// drives both propose-simulate and commit-install, and therefore the
/// pre-submit deadline budget the Step-2 fix bounds.
const DEPLOY_TIMEOUT_SECS: u64 = 120;

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

/// Deploys a fresh smart account whose genesis `Signer::Delegated` bootstrap
/// signer (context-rule 0) is `initial_signer_g`. Uses a separate,
/// independently funded deployer keypair. Returns the deployed C-strkey.
async fn deploy_smart_account_with_signer(initial_signer_g: &str) -> String {
    let (deployer_g, deployer_seed) = fresh_keypair();
    fund_via_friendbot(&deployer_g).await;
    wait_until_account_queryable(&deployer_g).await;

    let deployer_signer: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(deployer_seed));
    let deployer = DeployerKeypair::SecretEnv {
        var_name: "rule-create-commit-acceptance-generated".to_owned(),
        signer: deployer_signer,
    };

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let args = DeploymentArgs {
        deployer,
        initial_signer: initial_signer_g.to_owned(),
        salt,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(DEPLOY_TIMEOUT_SECS),
        fee: ResolvedFeePerOp {
            stroops: 1_000_000,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
        genesis_signer_scval_override: None,
    };
    deploy_smart_account(args, None)
        .await
        .expect("smart-account deployment must succeed on testnet")
        .smart_account
}

// ─────────────────────────────────────────────────────────────────────────────
// t1: propose -> approve -> commit, end-to-end, on-chain
// ─────────────────────────────────────────────────────────────────────────────

/// Propose, approve, and commit a real `add_context_rule` installation on
/// testnet, then verify the rule exists on-chain.
#[tokio::test]
#[serial]
async fn t1_rule_create_commit_happy_path() {
    keyring_mock::install().expect("mock keyring store init");

    // ── 1. Fresh agent keypair, funded and queryable ──────────────────────────
    let (agent_g, agent_seed) = fresh_keypair();
    fund_via_friendbot(&agent_g).await;
    wait_until_account_queryable(&agent_g).await;

    // ── 2. Deploy a smart account whose bootstrap (rule 0) signer is the agent ──
    let smart_account_c = deploy_smart_account_with_signer(&agent_g).await;
    let smart_account_sc = parse_c_strkey_to_smart_account(&smart_account_c)
        .expect("deployed smart-account C-strkey must parse");

    // ── 3. Build the profile + seed the keyring ───────────────────────────────
    let attestation_key = [0x51u8; 32];
    let mut profile =
        Profile::builder_testnet("stellar-agent", &agent_g, "stellar-agent-nonce", &agent_g)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    seed_keyring(&profile, &agent_seed, &attestation_key);

    let server = WalletServer::new(profile).expect("WalletServer::new");

    // ── 4. Propose: a default-context rule with one fresh Delegated signer ────
    let (new_rule_signer_g, _new_rule_signer_seed) = fresh_keypair();

    let propose = server
        .call_stellar_rule_create(StellarRuleCreateArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            smart_account: smart_account_c.clone(),
            context: "default".to_owned(),
            name: "issue31-accept".to_owned(),
            valid_until: None,
            signers: vec![RuleCreateSignerArg::Delegated {
                address: new_rule_signer_g,
            }],
            policies: vec![],
            auth_rule_ids: vec![0],
            accept_mutable_verifier: false,
            accept_unknown_verifier: false,
            accept_no_delegated_fallback: false,
        })
        .await
        .expect("propose must succeed against a live smart account");
    let propose_json = result_json(&propose);
    assert!(
        propose_json["ok"].as_bool().unwrap_or(false),
        "propose envelope must be ok: {propose_json}"
    );

    let approval_nonce = propose_json["data"]["approval_nonce"]
        .as_str()
        .expect("propose must surface approval_nonce")
        .to_owned();
    let proposal_sha256_hex = propose_json["data"]["proposal_sha256_hex"]
        .as_str()
        .expect("propose must surface proposal_sha256_hex")
        .to_owned();

    // ── 5. Recompute the attestation blob exactly as `approve` would ──────────
    let proposal_sha256: [u8; 32] = hex::decode(&proposal_sha256_hex)
        .expect("proposal_sha256_hex must be valid hex")
        .try_into()
        .expect("proposal_sha256_hex must decode to exactly 32 bytes");
    let uid = process_uid_for_attestation().expect("process uid");
    let blob = compute_attestation(&attestation_key, &approval_nonce, &proposal_sha256, &uid);
    let blob_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob);

    // ── 6. Commit: gate verifies the attestation, install_rule signs+submits ──
    let commit = server
        .call_stellar_rule_create_commit(StellarRuleCreateCommitArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            approval_nonce: approval_nonce.clone(),
            approval_attestation: Some(blob_b64),
        })
        .await
        .expect("commit must pass the gate and install on-chain");
    let commit_json = result_json(&commit);

    assert!(
        commit_json["ok"].as_bool().unwrap_or(false),
        "commit envelope must be ok (installed on-chain): {commit_json}"
    );
    let rule_id = commit_json["data"]["rule_id"]
        .as_u64()
        .expect("commit must report an installed rule_id");
    assert_ne!(
        rule_id, 0,
        "installed rule_id must differ from the bootstrap rule"
    );
    let tx_hash = commit_json["data"]["tx_hash"]
        .as_str()
        .expect("commit must report an on-chain tx_hash");
    assert_eq!(tx_hash.len(), 64, "tx_hash must be a 32-byte hex digest");

    // ── 7. On-chain assert: the installed rule is fetchable ───────────────────
    let manager = ContextRuleManager::new(ContextRuleManagerConfig::new(
        TESTNET_RPC_URL.to_owned(),
        TESTNET_PASSPHRASE.to_owned(),
        Duration::from_secs(DEPLOY_TIMEOUT_SECS),
        TESTNET_CHAIN_ID.to_owned(),
    ))
    .expect("ContextRuleManager construction must succeed");

    let rule_id_u32 = u32::try_from(rule_id).expect("rule_id fits u32");
    let rule_scval = manager
        .get_rule(smart_account_sc, rule_id_u32, &agent_g)
        .await
        .expect("get_rule must succeed")
        .expect("the newly installed rule must exist on-chain");
    assert!(
        matches!(rule_scval, stellar_xdr::ScVal::Map(_)),
        "the installed ContextRule must decode as an ScVal::Map: {rule_scval:?}"
    );
}
