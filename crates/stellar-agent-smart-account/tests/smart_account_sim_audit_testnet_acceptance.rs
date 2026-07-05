//! Testnet acceptance test for the simulation-audit gate.
//!
//! Verifies that the `verify_auth_entries_unchanged` tripwire wired into
//! `submit_signed_invoke` does NOT fire on the wallet's own happy path: a
//! real `InvokeHostFunction` submission against testnet must succeed end-to-end
//! with no false-positive `SaError::AuthMismatch`.
//!
//! Any batch touching the smart-account submit path MUST include an on-chain
//! submit phase against testnet in the same commit.
//!
//! # Acceptance criteria
//!
//! - **1.** Deploy a smart-account on testnet; install a context rule via
//!   `ContextRuleManager::install_rule`; the on-chain submit succeeds (no
//!   `SaError::AuthMismatch`).  This exercises `submit_signed_invoke` with the
//!   fingerprint-capture + verify tripwire active.
//! - **2.** `install_rule` returns a rule_id ≥ 1 (distinct from the
//!   bootstrap rule 0), confirming the on-chain transaction was applied.
//!
//! # Feature gate
//!
//! ```text
//! cargo test --features testnet-integration --test smart_account_sim_audit_testnet_acceptance
//! ```
//!

#![cfg(feature = "testnet-integration")]
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]

use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::{Signer, SoftwareSigningKey};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
};
use stellar_agent_smart_account::managers::rules::RuleContext;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRuleSignerInput,
    parse_c_strkey_to_smart_account, parse_g_strkey_to_signer_address,
};
use zeroize::Zeroizing;

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";

/// Funds an account via testnet Friendbot.
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

/// Generates a fresh ed25519 keypair and returns `(g_strkey, signer)`.
fn fresh_signer() -> (String, Box<dyn Signer + Send + Sync>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    (g_strkey, signer)
}

/// Generates a fresh deployer keypair wrapped in `DeployerKeypair::SecretEnv`.
fn fresh_deployer_keypair() -> (String, DeployerKeypair) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    let deployer = DeployerKeypair::SecretEnv {
        var_name: "testnet-acceptance-generated".to_owned(),
        signer,
    };
    (g_strkey, deployer)
}

/// Constructs a `ContextRuleManager` configured against testnet with an
/// uncapped session-rule horizon (so the install does not trigger `HorizonExceeded`).
fn fresh_manager() -> ContextRuleManager {
    ContextRuleManager::new(
        ContextRuleManagerConfig::new(
            TESTNET_RPC_URL.to_owned(),
            TESTNET_PASSPHRASE.to_owned(),
            Duration::from_secs(120),
            CHAIN_ID.to_owned(),
        )
        .with_session_rule_max_horizon_ledgers(u32::MAX),
    )
    .expect("ContextRuleManager construction must succeed")
}

/// Simulation-audit happy-path on testnet.
///
/// Deploys a fresh smart-account, installs a context rule via
/// `install_rule`, verifies the submission succeeds (the audit tripwire does
/// NOT fire), and confirms the returned rule_id ≥ 1.
///
/// The `verify_auth_entries_unchanged` tripwire in `submit_signed_invoke` is
/// exercised on a real on-chain `InvokeHostFunction` transaction.  A
/// `SaError::AuthMismatch` at any point would indicate a false-positive in the
/// byte-identity invariant.
#[tokio::test]
async fn sim_audit_happy_path_on_chain_submit() {
    // ── Setup: fresh signer + deployer, Friendbot-fund both ───────────────
    let (signer_g, signer_box) = fresh_signer();
    // Fund the signer — it pays gas fees as source-account for all submissions.
    // Friendbot issues ~10 000 XLM on testnet; check existence rather than a
    // specific balance threshold.
    fund_via_friendbot(&signer_g).await;

    // Deploy a fresh smart-account.  Uses the existing deploy path which has
    // its own testnet acceptance coverage; here we only need the C-strkey.
    let (deployer_g, deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&deployer_g).await;

    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let deploy_args = DeploymentArgs {
        deployer,
        initial_signer: signer_g.clone(),
        salt,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(120),
        fee: ResolvedFeePerOp {
            stroops: 1_000_000,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
    };
    let deploy_result = deploy_smart_account(deploy_args, None)
        .await
        .expect("smart-account deployment must succeed on testnet");
    let smart_account_strkey = deploy_result.smart_account;
    let smart_account = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed C-strkey must parse to ScAddress");

    // ── install_rule — exercises submit_signed_invoke with the audit gate ──
    // The fingerprint-capture + verify tripwire fires inside
    // submit_signed_invoke.  A successful submission proves the gate does NOT
    // false-positive on the wallet's own happy path.
    let manager = fresh_manager();
    let signer_addr = parse_g_strkey_to_signer_address(&signer_g)
        .expect("signer G-strkey must parse to ScAddress");
    // Rule name must be ≤ 20 bytes (OZ MAX_NAME_SIZE).
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "audit-acceptance".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![],
    );

    // Bootstrap rule (rule_id 0) authorises this install.
    let auth_rule_ids = vec![ContextRuleId::new(0)];
    let install_result = manager
        .install_rule(
            smart_account.clone(),
            definition,
            auth_rule_ids,
            signer_box.as_ref(),
            None, // audit_writer: None (no local audit log in acceptance tests)
            uuid::Uuid::new_v4().to_string(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect(
            "install_rule must succeed on testnet — \
             SaError::AuthMismatch here would indicate an audit-gate false-positive (byte-identity invariant broken)",
        );

    // ── rule_id must be ≥ 1 ──────────────────────────────────────────────
    let rule_id = install_result.rule_id;
    assert!(
        rule_id >= 1,
        "installed rule_id must be ≥ 1 (distinct from constructor bootstrap rule 0); \
         got {rule_id}"
    );
}
