//! Testnet acceptance test for `ContextRuleManager::list_active_context_rules`.
//!
//! # Test: list_rules across sparse ID gap on testnet
//!
//! **`h1_list_rules_across_sparse_id_gap_on_testnet`**
//!
//! Deploys a fresh smart account on testnet.  Installs 3 additional context
//! rules (IDs 1, 2, 3 — the bootstrap rule is ID 0 from deploy).  Deletes
//! rule 1 via `delete_rule`.  Runs `list_active_context_rules`.
//!
//! Assertions:
//!
//! (a) Returned rule IDs are `[0, 2, 3]` in monotonic order.
//! (b) `rules.len() == 3` (active_count=3 after delete).
//! (c) `rules.len() + rules_skipped == 4` — total IDs scanned = 4
//!     (IDs 0,1,2,3; gap at ID 1 increments skipped by 1), which locks the
//!     early-exit semantics against the live NextId-allocation order.
//!     This verifies that the scan reached ID 3 and exited cleanly, not that
//!     it short-circuited at ID 2.
//! (d) The sparse-gap rule ID 1 triggers the `rules.rs:1142-1144`
//!     ContextRuleNotFound path end-to-end against the live RPC, exercising
//!     the `Error(Contract, #3000)` numeric discriminant decoding.
//!
//! # Gating
//!
//! Compiled only under `--features testnet-integration`:
//!
//! ```text
//! cargo test --features testnet-integration --test wallet_sa_list_rules_testnet_acceptance
//! ```
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

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::{Signer, SoftwareSigningKey};
use stellar_agent_smart_account::bindings::ContextRuleType;
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
};
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRuleSignerInput,
    DEFAULT_MAX_SCAN_ID, parse_c_strkey_to_smart_account, parse_g_strkey_to_signer_address,
};
use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;

// ── Constants ─────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";

// ── Helpers ───────────────────────────────────────────────────────────────────

fn rid() -> String {
    Uuid::new_v4().to_string()
}

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

fn tmp_audit_writer() -> (Arc<Mutex<AuditWriter>>, PathBuf, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter::open must succeed");
    (Arc::new(Mutex::new(writer)), path, dir)
}

fn fresh_manager_with_audit_writer(audit_writer: Arc<Mutex<AuditWriter>>) -> ContextRuleManager {
    ContextRuleManager::new(
        ContextRuleManagerConfig::new(
            TESTNET_RPC_URL.to_owned(),
            TESTNET_PASSPHRASE.to_owned(),
            Duration::from_secs(120),
            CHAIN_ID.to_owned(),
        )
        .with_audit_writer(audit_writer),
    )
    .expect("manager construction with audit writer must succeed")
}

/// Manager variant with no horizon cap (`u32::MAX`).
///
/// Required only for tests that install rules with a far-future `valid_until`
/// (e.g. the decoder regression-lock test that uses `LARGE_FUTURE_LEDGER = 999_999_999`).
/// The default cap (1000 ledgers) would block such installs before they reach the chain.
fn fresh_manager_uncapped_with_audit_writer(
    audit_writer: Arc<Mutex<AuditWriter>>,
) -> ContextRuleManager {
    ContextRuleManager::new(
        ContextRuleManagerConfig::new(
            TESTNET_RPC_URL.to_owned(),
            TESTNET_PASSPHRASE.to_owned(),
            Duration::from_secs(120),
            CHAIN_ID.to_owned(),
        )
        .with_audit_writer(audit_writer)
        .with_session_rule_max_horizon_ledgers(u32::MAX),
    )
    .expect("uncapped manager construction must succeed")
}

async fn deploy_fresh_smart_account_with_initial_signer(signer_g: &str) -> String {
    let (deployer_g, deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&deployer_g).await;

    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let args = DeploymentArgs {
        deployer,
        initial_signer: signer_g.to_owned(),
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
    let result = deploy_smart_account(args, None)
        .await
        .expect("smart-account deployment must succeed on testnet");
    result.smart_account
}

/// Installs a context rule on the smart account, returns the assigned rule_id.
async fn install_rule_with_name(
    manager: &ContextRuleManager,
    smart_account: &stellar_xdr::ScAddress,
    signer_addr: &stellar_xdr::ScAddress,
    signer: &(dyn Signer + Send + Sync),
    auth_rule_id: u32,
    name: &str,
) -> u32 {
    install_rule_with_name_and_valid_until(
        manager,
        smart_account,
        signer_addr,
        signer,
        auth_rule_id,
        name,
        None,
    )
    .await
}

/// Installs a context rule with an explicit `valid_until` override.
///
/// Used by the decoder regression-lock test to exercise the `Some(valid_until)`
/// decoder path end-to-end against the live RPC.
async fn install_rule_with_name_and_valid_until(
    manager: &ContextRuleManager,
    smart_account: &stellar_xdr::ScAddress,
    signer_addr: &stellar_xdr::ScAddress,
    signer: &(dyn Signer + Send + Sync),
    auth_rule_id: u32,
    name: &str,
    valid_until: Option<u32>,
) -> u32 {
    // The OpenZeppelin smart-account contract caps MAX_NAME_SIZE at 20 bytes.
    let definition = ContextRuleDefinition::new(
        ContextRuleType::Default,
        name.to_owned(),
        valid_until,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr.clone(),
        }],
        vec![],
    );
    let auth_rule_ids = vec![ContextRuleId::new(auth_rule_id)];
    let out = manager
        .install_rule(
            smart_account.clone(),
            definition,
            auth_rule_ids,
            signer,
            None,
            rid(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("install_rule must succeed on testnet");
    out.rule_id
}

// ─────────────────────────────────────────────────────────────────────────────
// list_rules across sparse-ID gap on testnet
// ─────────────────────────────────────────────────────────────────────────────

/// Deploy a fresh smart account, install 3 rules (IDs 1, 2, 3), delete
/// rule 1, run `list_active_context_rules`, assert sparse-ID correctness.
///
/// # Acceptance criteria
///
/// (a) `returned_ids == [0, 2, 3]` in monotonic order.
/// (b) `rules.len() == 3` (active_count=3 post-delete).
/// (c) `rules.len() + rules_skipped == 4` (IDs 0,1,2,3 scanned; gap at 1).
/// (d) The ContextRuleNotFound `Error(Contract, #3000)` path is exercised
///     end-to-end at the live RPC for the deleted rule ID.
#[tokio::test]
async fn h1_list_rules_across_sparse_id_gap_on_testnet() {
    // ── Setup: fresh signer + funded account ─────────────────────────────────
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    // ── Deploy fresh smart account (bootstrap rule = ID 0) ──────────────────
    let smart_account_strkey = deploy_fresh_smart_account_with_initial_signer(&signer_g).await;
    let smart_account = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed C-strkey must parse");

    eprintln!("smart_account = {smart_account_strkey}");

    let signer_addr = parse_g_strkey_to_signer_address(&signer_g)
        .expect("signer G-strkey must parse to ScAddress");

    let (audit_writer, _audit_log_path, _tmp_dir) = tmp_audit_writer();
    let manager = fresh_manager_with_audit_writer(Arc::clone(&audit_writer));

    // ── Install rules 1, 2, 3 (bootstrap rule 0 is already installed) ────────

    // Rule 1 — will be deleted to create the sparse-ID gap.
    let rule_1_id = install_rule_with_name(
        &manager,
        &smart_account,
        &signer_addr,
        signer_box.as_ref(),
        0,
        "pr8-rule-one",
    )
    .await;
    assert_eq!(
        rule_1_id, 1,
        "rule 1 must receive ID 1 from NextId allocation"
    );

    // Rule 2.
    let rule_2_id = install_rule_with_name(
        &manager,
        &smart_account,
        &signer_addr,
        signer_box.as_ref(),
        0,
        "pr8-rule-two",
    )
    .await;
    assert_eq!(rule_2_id, 2, "rule 2 must receive ID 2");

    // Rule 3.
    let rule_3_id = install_rule_with_name(
        &manager,
        &smart_account,
        &signer_addr,
        signer_box.as_ref(),
        0,
        "pr8-rule-three",
    )
    .await;
    assert_eq!(rule_3_id, 3, "rule 3 must receive ID 3");

    eprintln!("installed rules: [0, {rule_1_id}, {rule_2_id}, {rule_3_id}]");

    // ── Delete rule 1 to create the sparse-ID gap ─────────────────────────────
    // Auth: rule 1 can delete itself (or rule 0 if the SA was set up to allow it).
    // Per the OpenZeppelin smart-account contract, `remove_context_rule` requires
    // auth from the smart-account contract; the auth_rule_ids list must contain a rule whose
    // signers include our signer_g key. Rule 0 (bootstrap) has signer_g as Delegated.
    let auth_rule_ids_for_delete = vec![ContextRuleId::new(0)];
    manager
        .delete_rule(
            smart_account.clone(),
            rule_1_id,
            auth_rule_ids_for_delete,
            signer_box.as_ref(),
            None,
            rid(),
        )
        .await
        .expect("delete_rule(1) must succeed on testnet");

    eprintln!("deleted rule {rule_1_id}; sparse-ID gap created at ID {rule_1_id}");

    // ── Enumerate active rules via list_active_context_rules ──────────────────
    let result = manager
        .list_active_context_rules(smart_account.clone(), &signer_g, DEFAULT_MAX_SCAN_ID)
        .await
        .expect("list_active_context_rules must succeed after rule deletion");

    let returned_ids: Vec<u32> = result.rules.iter().map(|r| r.rule_id).collect();
    eprintln!(
        "list_active_context_rules: rules={returned_ids:?}, \
         rules_skipped={}, audit_log_missing={:?}",
        result.rules_skipped, result.audit_log_missing
    );

    // ── Assertion (a): returned IDs = [0, 2, 3] in monotonic order ───────────
    assert_eq!(
        returned_ids,
        vec![0, 2, 3],
        "returned rule IDs must be [0, 2, 3]; \
         a 0..3 loop would return [0, 2] (miss rule 3). \
         Got: {returned_ids:?}"
    );

    // ── Assertion (b): active_count = 3 ──────────────────────────────────────
    assert_eq!(
        result.rules.len(),
        3,
        "rules.len() must be 3 (active_count=3 after delete); \
         got {}",
        result.rules.len()
    );

    // ── Assertion (c): total IDs scanned = 4 (IDs 0,1,2,3) ──────────────────
    // rules.len() (3) + rules_skipped + gaps_seen = 4 total IDs scanned.
    // The sparse-gap signal at ID 1 contributes to `gaps_seen`, NOT `rules_skipped`.
    // This verifies the scan reached ID 3 before exiting, not ID 2.
    assert_eq!(
        result.rules.len() + result.rules_skipped + result.gaps_seen,
        4,
        "rules.len() + rules_skipped + gaps_seen must equal 4 \
         (IDs 0,1,2,3 scanned); got rules.len()={} + rules_skipped={} + \
         gaps_seen={} = {}",
        result.rules.len(),
        result.rules_skipped,
        result.gaps_seen,
        result.rules.len() + result.rules_skipped + result.gaps_seen
    );

    // ── Assertion (d): sparse-gap rule 1 triggered the NotFound path ─────────
    // Indirect: gaps_seen >= 1 confirms that at least one ID returned
    // Ok(None) — the ContextRuleNotFound discriminant-3000 path at
    // rules.rs:1142-1144.  Gaps live in `gaps_seen`, not `rules_skipped`.
    assert!(
        result.gaps_seen >= 1,
        "gaps_seen must be >= 1 (gap at ID 1 exercised the \
         ContextRuleNotFound path against the live RPC); got {}",
        result.gaps_seen
    );

    // ── Verify rule names and context_type_label ──────────────────────────────
    // Rule 0 (bootstrap) has a system-assigned name — check it's non-empty.
    assert!(
        !result.rules[0].name.is_empty(),
        "rule 0 name must be non-empty"
    );
    // Rules 2 and 3 have known names.
    assert_eq!(
        result.rules[1].name.as_str(),
        "pr8-rule-two",
        "rule 2 name must be 'pr8-rule-two'; got '{}'",
        result.rules[1].name
    );
    assert_eq!(
        result.rules[2].name.as_str(),
        "pr8-rule-three",
        "rule 3 name must be 'pr8-rule-three'; got '{}'",
        result.rules[2].name
    );

    for rule in &result.rules {
        assert_eq!(
            rule.context_type_label, "default",
            "all rules have context_type_label='default'; got '{}' for rule {}",
            rule.context_type_label, rule.rule_id
        );
    }

    eprintln!("PASSED: sparse-ID enumeration correct across deleted rule gap");
}

// ─────────────────────────────────────────────────────────────────────────────
// valid_until=Some(N) decoded correctly on testnet (decoder regression-lock)
// ─────────────────────────────────────────────────────────────────────────────

/// Install one rule with `valid_until = Some(future_ledger)` and verify the
/// `list_active_context_rules` decoder returns `Some(future_ledger)`.
///
/// # Decoder regression-lock
///
/// The `valid_until` decoder correctly handles the canonical soroban `Option<u32>` ABI:
/// - `None` → `ScVal::Void`
/// - `Some(n)` → `ScVal::U32(n)` (soroban-env-common/src/option.rs:3-16)
///
/// This testnet test installs a rule with `Some(valid_until)` and verifies the
/// live RPC response is decoded correctly end-to-end.
///
/// # Setup
///
/// - Deploy a fresh smart account.
/// - Install rule with `valid_until = Some(LARGE_FUTURE_LEDGER)` where
///   `LARGE_FUTURE_LEDGER = 999_999_999` (far-future; the account will be
///   rotated before this ledger is reached in practice).
///
/// # Assertions
///
/// - `enumeration.rules[1].valid_until == Some(LARGE_FUTURE_LEDGER)`.
/// - `enumeration.rules[0].valid_until == None` (bootstrap rule is permanent).
///
/// The decoder regression-lock relies on `soroban-env-common/src/option.rs:3-16`.
#[tokio::test]
async fn h2_valid_until_some_decoded_correctly_on_testnet() {
    // A far-future ledger sequence — large enough that it will not be reached
    // during testnet testing but representable as u32.
    const LARGE_FUTURE_LEDGER: u32 = 999_999_999;

    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let smart_account_strkey = deploy_fresh_smart_account_with_initial_signer(&signer_g).await;
    let smart_account = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed C-strkey must parse");

    eprintln!("smart_account = {smart_account_strkey}");

    let signer_addr = parse_g_strkey_to_signer_address(&signer_g)
        .expect("signer G-strkey must parse to ScAddress");

    let (audit_writer, _audit_log_path, _tmp_dir) = tmp_audit_writer();
    // Use an uncapped manager for the install step: LARGE_FUTURE_LEDGER is ~997M
    // ledgers ahead of current testnet, which exceeds the default 1000-ledger cap.
    // This test exercises the decoder (regression-lock), not horizon enforcement.
    let uncapped_manager = fresh_manager_uncapped_with_audit_writer(Arc::clone(&audit_writer));
    // Standard-capped manager for enumeration (no horizon check during list).
    let manager = fresh_manager_with_audit_writer(Arc::clone(&audit_writer));

    // Install rule 1 with valid_until = Some(LARGE_FUTURE_LEDGER).
    // The on-chain encode path uses encode_option_u32 (rules.rs:2398-2401)
    // which produces ScVal::U32(LARGE_FUTURE_LEDGER). The decoder must invert
    // this to Some(LARGE_FUTURE_LEDGER).
    let rule_1_id = install_rule_with_name_and_valid_until(
        &uncapped_manager,
        &smart_account,
        &signer_addr,
        signer_box.as_ref(),
        0,
        "h2-expiring-rule",
        Some(LARGE_FUTURE_LEDGER),
    )
    .await;
    assert_eq!(
        rule_1_id, 1,
        "rule 1 must receive ID 1 from NextId allocation"
    );

    eprintln!("installed rule 1 with valid_until=Some({LARGE_FUTURE_LEDGER})");

    // Enumerate all active rules.
    let result = manager
        .list_active_context_rules(smart_account.clone(), &signer_g, DEFAULT_MAX_SCAN_ID)
        .await
        .expect("list_active_context_rules must succeed");

    assert_eq!(
        result.rules.len(),
        2,
        "must return 2 rules (bootstrap + rule 1); got {}",
        result.rules.len()
    );

    // Bootstrap rule (ID 0) must have valid_until = None (permanent).
    assert_eq!(result.rules[0].rule_id, 0, "rules[0].rule_id must be 0");
    assert_eq!(
        result.rules[0].valid_until, None,
        "bootstrap rule must have valid_until=None; got {:?}",
        result.rules[0].valid_until
    );

    // Rule 1 must have valid_until = Some(LARGE_FUTURE_LEDGER).
    // Decoder regression-lock: the canonical decoder must return Some(n) from
    // ScVal::U32(n), not None or an error.
    assert_eq!(result.rules[1].rule_id, 1, "rules[1].rule_id must be 1");
    assert_eq!(
        result.rules[1].valid_until,
        Some(LARGE_FUTURE_LEDGER),
        "decoder regression-lock: valid_until must be Some({LARGE_FUTURE_LEDGER}); \
         got {:?}. If this fails, the decoder is using the wrong encoding — \
         it should accept ScVal::U32(n) directly per soroban-env-common/src/option.rs:3-16.",
        result.rules[1].valid_until
    );

    eprintln!("PASSED: valid_until=Some({LARGE_FUTURE_LEDGER}) decoded correctly from live RPC");
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI envelope shape for list-rules end-to-end
// ─────────────────────────────────────────────────────────────────────────────

/// Deploy a fresh smart account, install 3 rules (IDs 1, 2, 3), delete rule 1,
/// then invoke the `wallet sa list-rules` release binary and parse the JSON envelope.
///
/// This test verifies that the CLI envelope shape is correct end-to-end,
/// including:
///
/// - `rules` array contains entries with the required fields.
/// - `active_count` equals `rules.len()`.
/// - `scanned_id_range.start == 0`.
/// - `scanned_id_range.end == 4` (IDs 0, 1, 2, 3 scanned; gap at 1).
/// - `audit_log_missing` is present (empty because fresh audit log has no rows).
/// - Exit code is `0`.
///
/// # Pre-requisite
///
/// The release binary must be built before running this test:
///
/// ```text
/// cargo build --release -p stellar-agent-cli
/// cargo test --features testnet-integration \
///     --test wallet_sa_list_rules_testnet_acceptance h3_cli_envelope_shape
/// ```
///
#[tokio::test]
async fn h3_cli_envelope_shape_on_testnet() {
    // ── Locate the release binary ─────────────────────────────────────────────
    // CARGO_MANIFEST_DIR is the `crates/stellar-agent-smart-account` directory;
    // walk up two levels to reach the workspace root, then descend into the
    // release output directory.
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root");
    let binary = workspace_root.join("target/release/stellar-agent");

    if !binary.exists() {
        eprintln!(
            "SKIP: release binary not found at {}. \
             Run `cargo build --release -p stellar-agent-cli` first.",
            binary.display()
        );
        // Not a hard failure: the binary smoke gate is enforced separately.
        // Return gracefully so the full testnet acceptance run does not
        // gate-fail on a missing pre-built binary.
        return;
    }

    eprintln!("using binary: {}", binary.display());

    // ── Setup: fresh signer + funded account ─────────────────────────────────
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let smart_account_strkey = deploy_fresh_smart_account_with_initial_signer(&signer_g).await;
    let smart_account = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed C-strkey must parse");

    eprintln!("smart_account = {smart_account_strkey}");

    let signer_addr = parse_g_strkey_to_signer_address(&signer_g)
        .expect("signer G-strkey must parse to ScAddress");

    let (audit_writer, _audit_log_path, _tmp_dir) = tmp_audit_writer();
    let manager = fresh_manager_with_audit_writer(Arc::clone(&audit_writer));

    // ── Install rules 1, 2, 3 (bootstrap rule 0 is already installed) ────────
    let rule_1_id = install_rule_with_name(
        &manager,
        &smart_account,
        &signer_addr,
        signer_box.as_ref(),
        0,
        "h3-rule-one",
    )
    .await;
    assert_eq!(rule_1_id, 1, "rule 1 must receive ID 1");

    let rule_2_id = install_rule_with_name(
        &manager,
        &smart_account,
        &signer_addr,
        signer_box.as_ref(),
        0,
        "h3-rule-two",
    )
    .await;
    assert_eq!(rule_2_id, 2, "rule 2 must receive ID 2");

    let rule_3_id = install_rule_with_name(
        &manager,
        &smart_account,
        &signer_addr,
        signer_box.as_ref(),
        0,
        "h3-rule-three",
    )
    .await;
    assert_eq!(rule_3_id, 3, "rule 3 must receive ID 3");

    eprintln!("installed rules: [0, {rule_1_id}, {rule_2_id}, {rule_3_id}]");

    // ── Delete rule 1 to create the sparse-ID gap ─────────────────────────────
    let auth_rule_ids_for_delete = vec![ContextRuleId::new(0)];
    manager
        .delete_rule(
            smart_account.clone(),
            rule_1_id,
            auth_rule_ids_for_delete,
            signer_box.as_ref(),
            None,
            rid(),
        )
        .await
        .expect("delete_rule(1) must succeed on testnet");

    eprintln!("deleted rule {rule_1_id}; sparse-ID gap created");

    // ── Invoke the CLI binary ─────────────────────────────────────────────────
    let output = std::process::Command::new(&binary)
        .args([
            "wallet",
            "sa",
            "list-rules",
            "--account",
            &smart_account_strkey,
            "--rpc-url",
            TESTNET_RPC_URL,
            "--network",
            "testnet",
            "--output",
            "json",
        ])
        .output()
        .expect("CLI binary must execute without OS error");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("exit code: {}", output.status.code().unwrap_or(-1));
    // Char-boundary-safe truncation — byte-slicing UTF-8 at byte 512
    // panics when the boundary lands inside a multi-byte sequence.
    eprintln!(
        "stderr (first 512 chars): {}",
        stderr.chars().take(512).collect::<String>()
    );
    eprintln!("stdout: {stdout}");

    assert!(
        output.status.success(),
        "wallet sa list-rules must exit 0 on a valid account; \
         got exit code {}. stderr: {stderr}",
        output.status.code().unwrap_or(-1)
    );

    // ── Parse the JSON envelope ───────────────────────────────────────────────
    // The CLI wraps the result in an Envelope<ListRulesResult>.
    // Parse as serde_json::Value to avoid depending on CLI crate types.
    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");

    assert_eq!(
        envelope["ok"],
        serde_json::Value::Bool(true),
        "envelope.ok must be true; got: {envelope}"
    );

    let data = &envelope["data"];
    assert!(
        data.is_object(),
        "envelope.data must be an object; got: {data}"
    );

    // ── Assert (a): rules array contains 3 entries with IDs [0, 2, 3] ────────
    let rules = data["rules"]
        .as_array()
        .expect("data.rules must be an array");
    let rule_ids: Vec<u64> = rules
        .iter()
        .map(|r| r["rule_id"].as_u64().expect("rule_id must be a u64"))
        .collect();

    assert_eq!(
        rule_ids,
        vec![0u64, 2, 3],
        "rule_ids must be [0, 2, 3]; got {rule_ids:?}"
    );

    // Validate required fields are present in each rule entry.
    for rule in rules {
        assert!(
            rule.get("rule_id").is_some(),
            "rule entry must have rule_id field"
        );
        assert!(
            rule.get("name").is_some(),
            "rule entry must have name field"
        );
        assert!(
            rule.get("context_type_label").is_some(),
            "rule entry must have context_type_label field"
        );
        assert!(
            rule.get("signer_count").is_some(),
            "rule entry must have signer_count field"
        );
        assert!(
            rule.get("policy_count").is_some(),
            "rule entry must have policy_count field"
        );
    }

    // ── Assert (b): active_count == 3 ─────────────────────────────────────────
    // active_count is the on-chain `Count` value (distinct from rules.len()).
    // For this fixture (4 installed - 1 deleted), both should be 3.
    let active_count = data["active_count"]
        .as_u64()
        .expect("active_count must be a u64");
    assert_eq!(
        active_count, 3,
        "active_count must be 3 (on-chain Count); got {active_count}"
    );
    assert_eq!(
        active_count,
        rules.len() as u64,
        "active_count must equal rules.len() on a clean enumeration \
         (active_count={active_count}, rules.len()={})",
        rules.len()
    );

    // ── Assert (c): scanned_id_range.start == 0 and .end == 4 ────────────────
    let scanned = &data["scanned_id_range"];
    assert!(
        scanned.is_object(),
        "scanned_id_range must be an object; got: {scanned}"
    );

    let range_start = scanned["start"].as_u64().expect("start must be u64");
    let range_end = scanned["end"].as_u64().expect("end must be u64");

    assert_eq!(
        range_start, 0,
        "scanned_id_range.start must be 0; got {range_start}"
    );
    assert_eq!(
        range_end, 4,
        "scanned_id_range.end must be 4 (IDs 0,1,2,3 scanned; \
         gap at 1 means ID 3 was the last probe, so end=4); got {range_end}"
    );

    // ── Assert (d): audit_log_missing is present (array, may be empty) ────────
    assert!(
        data["audit_log_missing"].is_array(),
        "audit_log_missing must be present and an array; got: {data}"
    );

    // ── Assert (e): rules_skipped + gaps_seen are present ────────────────────
    // The skip surface is split — `rules_skipped` is anomalous-only
    // (Err during simulate), `gaps_seen` is legitimate sparse-gap (Ok(None)).
    let rules_skipped = data["rules_skipped"]
        .as_u64()
        .expect("rules_skipped must be a u64");
    let gaps_seen = data["gaps_seen"].as_u64().expect("gaps_seen must be a u64");

    // ── Assert (f): gap at ID 1 surfaces in gaps_seen, not rules_skipped ──────
    // This fixture deletes rule 1, so the live RPC returns
    // ContextRuleNotFound for ID 1 — the on-chain authoritative "deleted
    // rule" signal.  This counts as a legitimate gap.
    assert!(
        gaps_seen >= 1,
        "gaps_seen must be >= 1 (gap at ID 1 against live RPC); got {gaps_seen}"
    );

    eprintln!(
        "PASSED: active_count={active_count}, scanned=[{range_start}, {range_end}), \
         rules_skipped={rules_skipped} (anomalous), gaps_seen={gaps_seen} (legitimate), \
         rule_ids={rule_ids:?}"
    );
}
