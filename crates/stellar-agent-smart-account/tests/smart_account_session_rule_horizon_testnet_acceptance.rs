//! Testnet acceptance tests for session-rule horizon enforcement
//! at install and update.
//!
//! This test covers horizon enforcement in `managers/rules.rs`, CLI
//! orchestration, and `error.rs`.
//!
//! # Coverage
//!
//! | Fixture | Description |
//! |---------|-------------|
//! | [`h_a_install_horizon_exceeded`] | Deploy SA; invoke `smart-account rules create --valid-until <oversized>` via the release binary — must exit non-zero with `validation.session_rule_horizon_exceeded` BEFORE submit |
//! | [`h_b_update_horizon_exceeded`] | Deploy SA; install a permanent rule; invoke `smart-account rules set-valid-until <id> <oversized>` via the release binary — must exit non-zero with `validation.session_rule_horizon_exceeded` BEFORE submit |
//!
//! # Gating
//!
//! Feature flag: `testnet-integration`. Run with:
//!
//! ```text
//! cargo build --release -p stellar-agent-cli
//! cargo test --features testnet-integration --test smart_account_session_rule_horizon_testnet_acceptance
//! ```
//!
//! Tests require live testnet access and Friendbot funding. They are excluded
//! from default `cargo test` runs.
//!
//! If the release binary is not built, the tests log a skip message and
//! return without failing (matching the graceful-skip pattern from the caps
//! acceptance test). The binary smoke gate enforces that the binary is built
//! before sealing.
//!
//! # Reference cross-check
//!
//! - OZ `packages/accounts/src/smart_account/storage.rs:649-652` SHA `a9c4216`:
//!   `PastValidUntil = 3005` — OZ rejects `valid_until < current_ledger` on-chain
//!   but imposes no upper-horizon cap. The wallet-side cap is an off-chain
//!   discipline enforced before submission.
//! - OZ `packages/accounts/src/smart_account/storage.rs:786-787` SHA `a9c4216`:
//!   Same error path for `update_context_rule_valid_until`.
//!
//!

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::use_debug,
    clippy::print_stderr,
    reason = "test-only; panics and diagnostic output are acceptable in testnet acceptance tests"
)]

use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
};
use stellar_agent_smart_account::managers::rules::RuleContext;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRuleSignerInput,
    parse_c_strkey_to_smart_account, parse_g_strkey_to_signer_address,
};
use zeroize::Zeroizing;

// ── Network constants ─────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";
const FEE_STROOPS: u32 = 1_000_000;
const TIMEOUT_SECS: u64 = 120;

/// Oversized `valid_until` ledger sequence that will always exceed the default
/// 1 000-ledger horizon cap (`DEFAULT_SESSION_RULE_HORIZON_LEDGERS`).
///
/// Testnet ledger sequence is ~50M today. The value 4_000_000_000 is ~600 yrs
/// out, so `horizon = 4_000_000_000 - 50_000_000 = 3_950_000_000`, which greatly
/// exceeds the 1 000-ledger default. The refusal fires BEFORE the RPC call.
const OVERSIZED_VALID_UNTIL: u32 = 4_000_000_000;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn fresh_signer() -> (
    String,
    String,
    Box<dyn stellar_agent_network::Signer + Send + Sync>,
) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let s_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PrivateKey(signing_key.to_bytes()).as_unredacted()
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(stellar_agent_network::SoftwareSigningKey::new_from_zeroizing(seed));
    (g_strkey, s_strkey, signer)
}

fn fresh_deployer() -> (String, DeployerKeypair) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(stellar_agent_network::SoftwareSigningKey::new_from_zeroizing(seed));
    (
        g_strkey,
        DeployerKeypair::SecretEnv {
            var_name: "testnet-horizon-acceptance".to_owned(),
            signer,
        },
    )
}

async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = reqwest::get(&url)
        .await
        .expect("Friendbot HTTP must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 200 for {g_strkey}; got {}",
        resp.status()
    );
}

fn fresh_rule_manager() -> ContextRuleManager {
    ContextRuleManager::new(ContextRuleManagerConfig::new(
        TESTNET_RPC_URL.to_owned(),
        TESTNET_PASSPHRASE.to_owned(),
        Duration::from_secs(TIMEOUT_SECS),
        CHAIN_ID.to_owned(),
    ))
    .expect("ContextRuleManager::new must succeed")
}

async fn deploy_fresh_smart_account(signer_g: &str) -> String {
    let (deployer_g, deployer) = fresh_deployer();
    fund_via_friendbot(&deployer_g).await;

    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let result = deploy_smart_account(
        DeploymentArgs {
            deployer,
            initial_signer: signer_g.to_owned(),
            salt,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: ResolvedFeePerOp {
                stroops: FEE_STROOPS,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
        },
        None,
    )
    .await
    .expect("deploy_smart_account must succeed on testnet");

    result.smart_account
}

/// Locates the workspace-root-relative release binary path.
fn release_binary() -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root");
    workspace_root.join("target/release/stellar-agent")
}

// ── Install refused when valid_until exceeds horizon cap ─────────────────────

/// Deploy a fresh smart account, then invoke
/// `smart-account rules create --valid-until <oversized>` via the release binary.
///
/// The CLI must exit non-zero with `validation.session_rule_horizon_exceeded`
/// in the JSON envelope BEFORE any simulate/submit call, since the horizon check
/// fires in the manager before the divergence check.
///
/// # Design
///
/// The default cap is `DEFAULT_SESSION_RULE_HORIZON_LEDGERS = 1000` (≈ 80 min).
/// `OVERSIZED_VALID_UNTIL = 4_000_000_000` is ~600 yrs out from the current
/// testnet ledger, so `horizon = 4_000_000_000 - current_ledger ≫ 1000`.
///
/// # Graceful skip
///
/// If the release binary is not present, the test logs a skip message and
/// returns without failing.
///
#[tokio::test]
async fn h_a_install_horizon_exceeded() {
    // ── Locate the release binary ─────────────────────────────────────────────
    let binary = release_binary();
    if !binary.exists() {
        eprintln!(
            "[H-A] SKIP: release binary not found at {}. \
             Run `cargo build --release -p stellar-agent-cli` first.",
            binary.display()
        );
        return;
    }
    eprintln!("[H-A] using binary: {}", binary.display());

    // ── Step 1: Fresh signer + fund ───────────────────────────────────────────
    let (signer_g, signer_s, _signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;
    eprintln!("[H-A] signer funded: {}", &signer_g[..8]);

    // ── Step 2: Deploy fresh smart account ────────────────────────────────────
    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    eprintln!("[H-A] smart_account = {}", &sa_strkey[..8]);

    // ── Step 3: Invoke the binary with an oversized valid_until ──────────────
    let signer_env_var = "HA_HORIZON_TEST_OPERATOR_SKEY";
    let valid_until_str = OVERSIZED_VALID_UNTIL.to_string();

    eprintln!(
        "[H-A] invoking binary: smart-account rules create --account {} \
         --signer-delegated {} --name h-a-horizon-test --valid-until {} \
         --network testnet --rpc-url {} --signer-secret-env {}",
        sa_strkey, signer_g, valid_until_str, TESTNET_RPC_URL, signer_env_var
    );

    let output = std::process::Command::new(&binary)
        .args([
            "smart-account",
            "rules",
            "create",
            "--account",
            &sa_strkey,
            "--signer-delegated",
            &signer_g,
            "--name",
            "h-a-horizon-test",
            "--valid-until",
            &valid_until_str,
            "--auth-rule-id",
            "0",
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
            "--signer-secret-env",
            signer_env_var,
        ])
        .env(signer_env_var, &signer_s)
        .output()
        .expect("[H-A] spawn smart-account rules create");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("[H-A] exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!(
        "[H-A] stderr (first 512 chars): {}",
        stderr.chars().take(512).collect::<String>()
    );
    eprintln!("[H-A] stdout: {stdout}");

    // ── Step 4: Assert exit code is non-zero ─────────────────────────────────
    assert_ne!(
        output.status.code().unwrap_or(0),
        0,
        "[H-A] smart-account rules create must exit non-zero when valid_until exceeds horizon; \
         stdout: {stdout}"
    );

    // ── Step 5: Assert JSON envelope carries the typed horizon error ──────────
    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("[H-A] stdout must be valid JSON");

    assert_eq!(
        envelope["ok"],
        serde_json::Value::Bool(false),
        "[H-A] envelope.ok must be false; got: {envelope}"
    );

    assert_eq!(
        envelope["error"]["code"],
        serde_json::Value::String("validation.session_rule_horizon_exceeded".to_owned()),
        "[H-A] error.code must be 'validation.session_rule_horizon_exceeded'; got: {envelope}"
    );

    // Assert the error message names the horizon details.
    let error_message = envelope["error"]["message"].as_str().unwrap_or("");
    assert!(
        error_message.contains("horizon") || error_message.contains("ledger"),
        "[H-A] error.message must mention horizon/ledger; got: {error_message}"
    );

    eprintln!("[H-A] PASS: horizon-exceeded refusal verified at install path");
}

// ── `update_valid_until` refused when valid_until exceeds horizon cap ─────────

/// Deploy a fresh smart account, install a permanent context rule, then
/// invoke `smart-account rules set-valid-until <id> <oversized>` via the release binary.
///
/// The CLI must exit non-zero with `validation.session_rule_horizon_exceeded`
/// in the JSON envelope BEFORE any simulate/submit call.
///
/// # Design
///
/// The substrate setup installs a permanent rule (no expiry) to get a valid
/// `rule_id`. The actual horizon-refusal test uses the binary's `set-valid-until`
/// subcommand with `OVERSIZED_VALID_UNTIL`.
///
/// # Graceful skip
///
/// If the release binary is not present, the test logs a skip message and
/// returns without failing.
///
#[tokio::test]
async fn h_b_update_horizon_exceeded() {
    // ── Locate the release binary ─────────────────────────────────────────────
    let binary = release_binary();
    if !binary.exists() {
        eprintln!(
            "[H-B] SKIP: release binary not found at {}. \
             Run `cargo build --release -p stellar-agent-cli` first.",
            binary.display()
        );
        return;
    }
    eprintln!("[H-B] using binary: {}", binary.display());

    // ── Step 1: Fresh signer + fund ───────────────────────────────────────────
    let (signer_g, signer_s, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;
    eprintln!("[H-B] signer funded: {}", &signer_g[..8]);

    // ── Step 2: Deploy fresh smart account ────────────────────────────────────
    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    eprintln!("[H-B] smart_account = {}", &sa_strkey[..8]);

    // ── Step 3: Install a permanent (no valid_until) context rule ────────────
    // No valid_until → horizon check is skipped; u32::MAX is safe for setup.
    let manager = fresh_rule_manager();
    let sa_addr = parse_c_strkey_to_smart_account(&sa_strkey)
        .expect("[H-B] C-strkey must parse to ScAddress");
    let signer_addr = parse_g_strkey_to_signer_address(&signer_g)
        .expect("[H-B] G-strkey must parse to signer address");

    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "h-b-substrate".to_owned(),
        None, // permanent — no expiry
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![],
    );
    let auth_rule_ids = vec![ContextRuleId::new(0)];
    // No valid_until in definition → horizon check is skipped entirely;
    // the default cap does not apply to permanent rules.
    let install_out = manager
        .install_rule(
            sa_addr,
            definition,
            auth_rule_ids,
            signer_box.as_ref(),
            None,
            uuid::Uuid::new_v4().to_string(),
            false,
            false,
        )
        .await
        .expect("[H-B] install_rule must succeed (substrate setup)");

    let rule_id = install_out.rule_id;
    eprintln!("[H-B] substrate rule installed: rule_id = {rule_id}");

    // ── Step 4: Invoke the binary with an oversized valid_until ──────────────
    let signer_env_var = "HB_HORIZON_TEST_OPERATOR_SKEY";
    let rule_id_str = rule_id.to_string();
    let valid_until_str = OVERSIZED_VALID_UNTIL.to_string();

    eprintln!(
        "[H-B] invoking binary: smart-account rules set-valid-until --account {} \
         --rule-id {} --auth-rule-id 0 --valid-until {} --network testnet --rpc-url {} \
         --signer-secret-env {}",
        sa_strkey, rule_id_str, valid_until_str, TESTNET_RPC_URL, signer_env_var
    );

    // `--auth-rule-id 0` authorises via the bootstrap rule, which has no
    // threshold-policy and therefore bypasses the signer-divergence check.
    // This lets us reach the horizon-cap gate (which fires inside simulate)
    // without needing a pre-seeded audit-log baseline for rule 1.
    let output = std::process::Command::new(&binary)
        .args([
            "smart-account",
            "rules",
            "set-valid-until",
            "--account",
            &sa_strkey,
            "--rule-id",
            &rule_id_str,
            "--auth-rule-id",
            "0",
            "--valid-until",
            &valid_until_str,
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
            "--signer-secret-env",
            signer_env_var,
        ])
        .env(signer_env_var, &signer_s)
        .output()
        .expect("[H-B] spawn smart-account rules set-valid-until");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("[H-B] exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!(
        "[H-B] stderr (first 512 chars): {}",
        stderr.chars().take(512).collect::<String>()
    );
    eprintln!("[H-B] stdout: {stdout}");

    // ── Step 5: Assert exit code is non-zero ─────────────────────────────────
    assert_ne!(
        output.status.code().unwrap_or(0),
        0,
        "[H-B] smart-account rules set-valid-until must exit non-zero when valid_until \
         exceeds horizon; stdout: {stdout}"
    );

    // ── Step 6: Assert JSON envelope carries the typed horizon error ──────────
    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("[H-B] stdout must be valid JSON");

    assert_eq!(
        envelope["ok"],
        serde_json::Value::Bool(false),
        "[H-B] envelope.ok must be false; got: {envelope}"
    );

    assert_eq!(
        envelope["error"]["code"],
        serde_json::Value::String("validation.session_rule_horizon_exceeded".to_owned()),
        "[H-B] error.code must be 'validation.session_rule_horizon_exceeded'; got: {envelope}"
    );

    let error_message = envelope["error"]["message"].as_str().unwrap_or("");
    assert!(
        error_message.contains("horizon") || error_message.contains("ledger"),
        "[H-B] error.message must mention horizon/ledger; got: {error_message}"
    );

    // Assert rule_id_or_pending is Some(rule_id) in the error context
    // (update path sets rule_id_or_pending to Some(rule_id)).
    let error_data = &envelope["error"];
    if let Some(pending) = error_data.get("rule_id_or_pending") {
        assert_eq!(
            pending.as_u64(),
            Some(u64::from(rule_id)),
            "[H-B] error.rule_id_or_pending must be Some({rule_id}); got: {pending}"
        );
    }

    eprintln!("[H-B] PASS: horizon-exceeded refusal verified at update path");
}
