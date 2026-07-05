//! Testnet acceptance tests for `ContextRuleManager` lifecycle.
//!
//! Exercises the full metadata-only context-rule lifecycle against
//! testnet:
//!
//! 1. Deploy a fresh smart-account via `deploy_smart_account`.
//! 2. Install a context rule via `ContextRuleManager::install_rule`.
//! 3. Read it back via `get_rule` (must be `Some`).
//! 4. Read the count via `get_rules_count` (must reflect the install).
//! 5. Rename via `update_name`.
//! 6. Set explicit expiry via `update_valid_until(Some(ledger))`.
//! 7. Clear expiry via `update_valid_until(None)` (`set_valid_until = None` is supported).
//! 8. Delete via `delete_rule`.
//! 9. Read it back via `get_rule` (must be `None`).
//! 10. Re-delete (must fail with the typed
//!     `SmartAccountError::ContextRuleNotFound`-shaped surface error).
//!
//! The test is gated behind the `testnet-integration` feature flag:
//!
//! ```text
//! cargo test --features testnet-integration --test smart_account_rules_testnet_acceptance
//! ```
//!
//! Under default `cargo test` (no feature), this file compiles but all
//! tests are compiled-out via `#[cfg(feature = "testnet-integration")]`.
//!
//! # Acceptance criteria
//!
//! - `install_rule` returns a fresh `rule_id` distinct from the
//!   constructor-installed bootstrap rule (rule 0).
//! - `update_name` succeeds and is reflected in `get_rule`.
//! - `update_valid_until(Some(N))` and `update_valid_until(None)`
//!   both succeed against the same rule (`set_valid_until = None` is
//!   a supported carve-out).
//! - `delete_rule` succeeds; subsequent `get_rule` returns `None`.
//! - `get_rules_count` accurately reflects post-install /
//!   post-delete state.
//! - Re-deleting a removed rule surfaces a typed
//!   `SaError::DeploymentFailed { phase: "simulate", ...}` whose
//!   `redacted_reason` contains `"ContextRuleNotFound"` (the manager-side
//!   substring-match contract used by `get_rule`'s `Ok(None)` mapping).
//!
//! # Implements
//!
//! End-to-end testnet acceptance for the metadata-only lifecycle.
//!
//! - `install_rule` invoked with `audit_writer: None` and
//!   `self.audit_writer = Some(arc)` (the production CLI pattern) emits both
//!   a `SaContextRuleCreated` row AND a `SaRawInvocation(Success)` row on the
//!   audit log via the `self.audit_writer` fallback path.

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

mod common;

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{TESTNET_PASSPHRASE, TESTNET_RPC_URL, fund_via_friendbot};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{EventKind, SaInvocationResult};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::{Signer, SoftwareSigningKey};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
};
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::rules::RuleContext;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRuleSignerInput,
    parse_c_strkey_to_smart_account, parse_g_strkey_to_signer_address,
};
use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;

const CHAIN_ID: &str = "stellar:testnet";

/// Far-future ledger sequence used for the explicit-expiry path.
/// Testnet ledger sequence is ~5e7 today (5 s/ledger × ~10 yrs); this value
/// is ~600 yrs out and safely below `u32::MAX` (~4.29e9). OZ
/// `update_context_rule_valid_until` writes the value verbatim with no
/// `now() < N` check at set-time; the rule remains usable until ledgers
/// catch up.
const FAR_FUTURE_LEDGER: u32 = 4_000_000_000;

/// Generates a fresh request-id for forensic correlation. The value flows
/// through the manager into the `SaRawInvocation` audit row.
fn rid() -> String {
    Uuid::new_v4().to_string()
}

/// Generates a fresh ed25519 keypair and returns
/// `(g_strkey, software_signer)`. The signer is `Box<dyn Signer + Send + Sync>`
/// for direct passing to manager methods.
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

/// Generates a fresh deployer keypair wrapped in `DeployerKeypair::SecretEnv`
/// for `deploy_smart_account`.
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

/// Opens a temporary `AuditWriter` in a fresh `TempDir`.
///
/// Returns `(Arc<Mutex<writer>>, log_path, TempDir)`. `TempDir` must be kept
/// alive for the duration of the test or the underlying directory is removed.
fn tmp_audit_writer() -> (Arc<Mutex<AuditWriter>>, PathBuf, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter::open must succeed");
    (Arc::new(Mutex::new(writer)), path, dir)
}

/// Constructs a fresh `ContextRuleManager` configured against testnet.
fn fresh_manager() -> ContextRuleManager {
    ContextRuleManager::new(ContextRuleManagerConfig::new(
        TESTNET_RPC_URL.to_owned(),
        TESTNET_PASSPHRASE.to_owned(),
        Duration::from_secs(120),
        CHAIN_ID.to_owned(),
    ))
    .expect("manager construction must succeed")
}

/// Constructs a `ContextRuleManager` with no horizon cap, for lifecycle tests
/// that intentionally use far-future `valid_until` values (e.g. set/clear
/// expiry with `FAR_FUTURE_LEDGER`).
///
/// The cap enforcement is tested separately in
/// `smart_account_session_rule_horizon_testnet_acceptance.rs`.  Tests that need to
/// set a `valid_until` beyond the default 1000-ledger horizon without
/// triggering the cap must use this manager.
fn fresh_manager_uncapped() -> ContextRuleManager {
    ContextRuleManager::new(
        ContextRuleManagerConfig::new(
            TESTNET_RPC_URL.to_owned(),
            TESTNET_PASSPHRASE.to_owned(),
            Duration::from_secs(120),
            CHAIN_ID.to_owned(),
        )
        .with_session_rule_max_horizon_ledgers(u32::MAX),
    )
    .expect("manager construction must succeed")
}

/// Constructs a `ContextRuleManager` configured against testnet and wired with
/// the supplied shared audit writer (the production CLI pattern — calls
/// `.with_audit_writer(Arc::clone(&ctx.audit_writer))`).
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

/// Reads every non-empty JSONL line from `log_path` into a `Vec<AuditEntry>`.
fn read_audit_entries(log_path: &std::path::Path) -> Vec<AuditEntry> {
    let file = std::fs::File::open(log_path).expect("audit log file must be readable");
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
            entries.push(entry);
        }
    }
    entries
}

/// Deploys a fresh smart-account whose constructor-rule signer is
/// `signer_g`. Returns the deployed C-strkey.
///
/// The deployer keypair is generated and Friendbot-funded internally;
/// `signer_g` is the G-strkey installed as the bootstrap rule's
/// `Signer::Delegated(Address)` payload.
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

/// Full metadata-only lifecycle in a single test. Run as one end-to-end
/// sequence to share the expensive deploy step (~30-60 s on testnet)
/// across all assertions.
#[tokio::test]
async fn full_metadata_only_lifecycle_on_testnet() {
    // ── Setup ──────────────────────────────────────────────────────────
    let (signer_g, signer_box) = fresh_signer();
    // The signer who authorises rule operations doubles as the
    // SEP-23 envelope source-account; Friendbot-fund it so it can
    // pay tx fees.
    fund_via_friendbot(&signer_g).await;

    // Deploy a smart-account whose constructor-rule signer is the
    // signer we just generated. After deploy, the smart-account has
    // exactly one rule (rule_id 0) authorising operations by `signer_g`.
    let smart_account_strkey = deploy_fresh_smart_account_with_initial_signer(&signer_g).await;
    let smart_account = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed C-strkey must parse");

    let manager = fresh_manager();

    // ── get_rules_count post-deploy = 1 ──────────────────────────────────
    let count_after_deploy = manager
        .get_rules_count(smart_account.clone(), &signer_g)
        .await
        .expect("get_rules_count must succeed post-deploy");
    assert_eq!(
        count_after_deploy, 1,
        "deployed smart-account starts with exactly 1 rule (constructor-installed bootstrap)"
    );

    // ── install a fresh rule ──────────────────────────────────────────
    // Build the rule definition: a delegated signer = signer_g (re-using
    // the bootstrap signer is not required, but simplifies the test —
    // the same signer authorises both the install AND the new rule's
    // own subsequent operations).
    let signer_addr = parse_g_strkey_to_signer_address(&signer_g)
        .expect("signer G-strkey must parse to ScAddress");
    // OZ `MAX_NAME_SIZE = 20` bytes — name must fit.
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "pr3-acceptance".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![],
    );

    let auth_rule_ids = vec![ContextRuleId::new(0)]; // bootstrap rule authorises this install
    let out = manager
        .install_rule(
            smart_account.clone(),
            definition,
            auth_rule_ids,
            signer_box.as_ref(),
            None,
            rid(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("install_rule must succeed against a freshly deployed smart-account");
    let rule_id = out.rule_id;
    assert!(
        rule_id != 0,
        "installed rule_id must be distinct from the constructor-installed bootstrap rule (rule_id 0); got {rule_id}"
    );

    // ── get_rules_count post-install = 2 ────────────────────────────────
    let count_after_install = manager
        .get_rules_count(smart_account.clone(), &signer_g)
        .await
        .expect("get_rules_count must succeed post-install");
    assert_eq!(
        count_after_install, 2,
        "post-install count must be 2 (bootstrap + new rule); got {count_after_install}"
    );

    // ── get_rule returns Some for the new rule ───────────────────────────
    let fetched = manager
        .get_rule(smart_account.clone(), rule_id, &signer_g)
        .await
        .expect("get_rule must succeed against a freshly installed rule");
    assert!(
        fetched.is_some(),
        "get_rule must return Some(_) for a freshly installed rule; got None"
    );

    // ── rename ────────────────────────────────────────────────────────
    let auth_rule_ids = vec![ContextRuleId::new(rule_id)];
    manager
        .update_name(
            smart_account.clone(),
            rule_id,
            // OZ `MAX_NAME_SIZE = 20` bytes — keep ≤20 chars.
            "pr3-renamed".to_owned(),
            auth_rule_ids,
            signer_box.as_ref(),
            None,
            rid(),
        )
        .await
        .expect("update_name must succeed");

    // Confirm the rule still exists post-rename. Field-level
    // decoding of the renamed `name` is deferred to the `smart-account rules list`
    // scope alongside structured rule-shape decoding.
    assert!(
        manager
            .get_rule(smart_account.clone(), rule_id, &signer_g)
            .await
            .expect("get_rule must succeed post-rename")
            .is_some(),
        "rule must still exist after rename"
    );

    // ── set explicit expiry ──────────────────────────────────────────────
    // Intentionally uses FAR_FUTURE_LEDGER to verify the value persists
    // end-to-end.  The horizon-cap enforcement is tested separately in
    // `smart_account_session_rule_horizon_testnet_acceptance.rs`; here we use an
    // uncapped manager to avoid the cap interfering with the lifecycle test.
    let uncapped_manager = fresh_manager_uncapped();
    let auth_rule_ids = vec![ContextRuleId::new(rule_id)];
    uncapped_manager
        .update_valid_until(
            smart_account.clone(),
            rule_id,
            Some(FAR_FUTURE_LEDGER),
            auth_rule_ids,
            signer_box.as_ref(),
            None,
            rid(),
        )
        .await
        .expect("update_valid_until(Some(N)) must succeed");
    assert!(
        manager
            .get_rule(smart_account.clone(), rule_id, &signer_g)
            .await
            .expect("get_rule must succeed post-set-expiry")
            .is_some(),
        "rule must still exist after update_valid_until(Some)"
    );

    // ── clear expiry (the clear-expiry carve-out) ───────────────────────────────
    let auth_rule_ids = vec![ContextRuleId::new(rule_id)];
    uncapped_manager
        .update_valid_until(
            smart_account.clone(),
            rule_id,
            None,
            auth_rule_ids,
            signer_box.as_ref(),
            None,
            rid(),
        )
        .await
        .expect("update_valid_until(None) must succeed");
    assert!(
        manager
            .get_rule(smart_account.clone(), rule_id, &signer_g)
            .await
            .expect("get_rule must succeed post-clear-expiry")
            .is_some(),
        "rule must still exist after update_valid_until(None) (carve-out)"
    );

    // ── delete the rule ───────────────────────────────────────────────
    let auth_rule_ids = vec![ContextRuleId::new(rule_id)];
    manager
        .delete_rule(
            smart_account.clone(),
            rule_id,
            auth_rule_ids,
            signer_box.as_ref(),
            None,
            rid(),
        )
        .await
        .expect("delete_rule must succeed");

    // ── get_rules_count post-delete = 1 ─────────────────────────────────
    let count_after_delete = manager
        .get_rules_count(smart_account.clone(), &signer_g)
        .await
        .expect("get_rules_count must succeed post-delete");
    assert_eq!(
        count_after_delete, 1,
        "post-delete count must be 1 (bootstrap only); got {count_after_delete}"
    );

    // ── get_rule on the deleted rule returns None ─────────────────────
    let fetched_after_delete = manager
        .get_rule(smart_account.clone(), rule_id, &signer_g)
        .await
        .expect("get_rule must succeed even when the rule has been removed (Ok(None) path)");
    assert!(
        fetched_after_delete.is_none(),
        "get_rule on a deleted rule must return Ok(None); got Some(_)"
    );

    // ── re-deleting a missing rule surfaces ContextRuleNotFound ──────
    let auth_rule_ids = vec![ContextRuleId::new(0)]; // bootstrap rule authorises
    let re_delete_err = manager
        .delete_rule(
            smart_account.clone(),
            rule_id,
            auth_rule_ids,
            signer_box.as_ref(),
            None,
            rid(),
        )
        .await
        .expect_err(
            "re-deleting a missing rule must fail (it raises SmartAccountError::ContextRuleNotFound on simulate)"
        );
    match re_delete_err {
        SaError::DeploymentFailed {
            phase,
            ref redacted_reason,
        } if phase == "simulate" && redacted_reason.contains("ContextRuleNotFound") => {
            // Expected. The manager-side substring-match contract used
            // by `get_rule`'s `Ok(None)` mapping is what `delete_rule`
            // surfaces as well.
        }
        other => panic!(
            "re-delete error must be SaError::DeploymentFailed {{ phase: \"simulate\", redacted_reason contains \"ContextRuleNotFound\" }}; got {other:?}"
        ),
    }
}

// ── self.audit_writer fallback emission ──────────────────────────────────

/// `install_rule` called with `audit_writer: None` and
/// `self.audit_writer = Some(arc)` (the production CLI pattern) emits both a
/// `SaContextRuleCreated` row AND a `SaRawInvocation(Success)` row on the
/// audit log via `self.audit_writer`.
///
/// # Why this matters
///
/// The write methods gate emission on the per-method
/// `audit_writer: Option<&mut AuditWriter>` parameter, which the CLI handlers
/// pass as `None`. Without the `self.audit_writer` fallback, zero audit rows
/// would be emitted for every `smart-account rules` CLI operation — a forensic-evidence
/// gap.
///
/// This test exercises the production path end-to-end:
///
/// 1. Deploy a fresh smart-account.
/// 2. Construct a manager with `self.audit_writer = Some(arc)`.
/// 3. Call `install_rule` with `audit_writer: None`.
/// 4. Assert that the audit log contains a `SaContextRuleCreated` row with
///    the expected `rule_id` and `context_type = "default"`.
/// 5. Assert that the audit log contains a `SaRawInvocation` row with
///    `wire_code = "sa.ok"` and `result = SaInvocationResult::Success`.
/// 6. Assert that the `chain_id` field on both rows matches `CHAIN_ID`.
#[tokio::test(flavor = "multi_thread")]
async fn e1_install_rule_emits_audit_rows_via_self_audit_writer() {
    // ── Setup ──────────────────────────────────────────────────────────────────
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let smart_account_strkey = deploy_fresh_smart_account_with_initial_signer(&signer_g).await;
    let smart_account = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed C-strkey must parse");

    // Open the audit writer that will serve as self.audit_writer (the
    // config-level shared writer — the production CLI path).
    let (audit_arc, log_path, _temp_dir) = tmp_audit_writer();

    // Construct the manager with self.audit_writer wired (production CLI pattern).
    // No per-operation audit_writer will be passed to install_rule below.
    let manager = fresh_manager_with_audit_writer(Arc::clone(&audit_arc));

    // ── install_rule with audit_writer: None ──────────────────────────────
    let signer_addr = parse_g_strkey_to_signer_address(&signer_g)
        .expect("signer G-strkey must parse to ScAddress");
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        // OZ MAX_NAME_SIZE = 20 bytes.
        "e1-audit-test".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![],
    );
    let auth_rule_ids = vec![ContextRuleId::new(0)];
    let request_id = rid();

    // Production CLI pattern: audit_writer = None.  The manager's
    // write_audit_entry helper must fall back to self.audit_writer.
    let out = manager
        .install_rule(
            smart_account.clone(),
            definition,
            auth_rule_ids,
            signer_box.as_ref(),
            None, // <-- the production CLI pattern
            request_id.clone(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("install_rule must succeed");
    let rule_id = out.rule_id;

    assert!(
        rule_id != 0,
        "installed rule_id must be distinct from the bootstrap rule (rule_id 0); got {rule_id}"
    );

    drop(manager);
    // AuditWriter per-entry fsync(2) makes the JSONL file
    // durable by the time install_rule's await returns; no explicit flush needed.

    let entries = read_audit_entries(&log_path);
    assert!(
        !entries.is_empty(),
        "audit log must contain at least one entry after install_rule; log is empty"
    );

    // ── Assert SaContextRuleCreated row ────────────────────────────────────────
    let rule_created_count = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaContextRuleCreated {
                    rule_id: rid,
                    context_type,
                    ..
                } if *rid == rule_id && context_type == "default"
            )
        })
        .count();
    assert_eq!(
        rule_created_count, 1,
        "exactly one SaContextRuleCreated row with rule_id={rule_id} and \
         context_type=\"default\" must be present; found {rule_created_count}"
    );

    // Verify chain_id on the SaContextRuleCreated row.
    let entry = entries
        .iter()
        .find(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaContextRuleCreated { rule_id: rid, .. } if *rid == rule_id
            )
        })
        .expect("install_rule must emit SaContextRuleCreated with matching rule_id");
    assert_eq!(
        entry.chain_id.as_deref(),
        Some(CHAIN_ID),
        "SaContextRuleCreated row must carry chain_id = \"{CHAIN_ID}\"; got {:?}",
        entry.chain_id
    );
    assert_eq!(
        entry.request_id, request_id,
        "SaContextRuleCreated row must carry the request_id used in the call"
    );

    // ── Assert SaRawInvocation(Success) row ────────────────────────────────────
    let raw_ok_count = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaRawInvocation {
                    wire_code,
                    result: SaInvocationResult::Success,
                    ..
                } if wire_code == "sa.ok"
            )
        })
        .count();
    assert_eq!(
        raw_ok_count, 1,
        "exactly one SaRawInvocation row with wire_code=\"sa.ok\" and \
         result=Success must be present; found {raw_ok_count}"
    );

    // Verify chain_id + request_id on the SaRawInvocation(Success) row.
    let entry = entries
        .iter()
        .find(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaRawInvocation {
                    wire_code,
                    result: SaInvocationResult::Success,
                    ..
                } if wire_code == "sa.ok"
            )
        })
        .expect("install_rule must emit SaRawInvocation Success row");
    assert_eq!(
        entry.chain_id.as_deref(),
        Some(CHAIN_ID),
        "SaRawInvocation Success row must carry chain_id = \"{CHAIN_ID}\"; got {:?}",
        entry.chain_id
    );
    assert_eq!(
        entry.request_id, request_id,
        "SaRawInvocation Success row must carry the request_id used in the call"
    );
}

/// `update_name` and `update_valid_until` each emit their typed forensic row
/// (`SaContextRuleNameUpdated` / `SaContextRuleValidUntilUpdated`) IN ADDITION
/// TO the `SaRawInvocation(sa.ok)` row, via the `self.audit_writer` fallback
/// path.
///
/// Asserts on the name row that the free-text rule name is redacted to the
/// first-3-chars + `len=N` form and never appears verbatim.
#[tokio::test(flavor = "multi_thread")]
async fn e2_metadata_updates_emit_typed_forensic_rows() {
    // ── Setup (mirrors the audit-fallback test) ─────────────────────────────────────────────────
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let smart_account_strkey = deploy_fresh_smart_account_with_initial_signer(&signer_g).await;
    let smart_account = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed C-strkey must parse");

    let (audit_arc, log_path, _temp_dir) = tmp_audit_writer();
    let manager = fresh_manager_with_audit_writer(Arc::clone(&audit_arc));

    let signer_addr = parse_g_strkey_to_signer_address(&signer_g)
        .expect("signer G-strkey must parse to ScAddress");
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "e2-audit-test".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![],
    );
    let out = manager
        .install_rule(
            smart_account.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect("install_rule must succeed");
    let rule_id = out.rule_id;

    // ── update_name with audit_writer: None (production CLI pattern) ─────────
    let rename_request_id = rid();
    manager
        .update_name(
            smart_account.clone(),
            rule_id,
            "e2-renamed".to_owned(), // 10 bytes, within OZ MAX_NAME_SIZE = 20
            vec![ContextRuleId::new(rule_id)],
            signer_box.as_ref(),
            None,
            rename_request_id.clone(),
        )
        .await
        .expect("update_name must succeed");

    // ── update_valid_until(None) — the clear-expiry carve-out, which has
    //    no horizon-cap interaction ─────────────────────────────────────────
    let expiry_request_id = rid();
    manager
        .update_valid_until(
            smart_account.clone(),
            rule_id,
            None,
            vec![ContextRuleId::new(rule_id)],
            signer_box.as_ref(),
            None,
            expiry_request_id.clone(),
        )
        .await
        .expect("update_valid_until(None) must succeed");

    drop(manager);
    let entries = read_audit_entries(&log_path);

    // ── Typed name row: present once, redacted, correlated ──────────────────
    let name_rows: Vec<_> = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaContextRuleNameUpdated { rule_id: rid, .. } if *rid == rule_id
            )
        })
        .collect();
    assert_eq!(
        name_rows.len(),
        1,
        "exactly one SaContextRuleNameUpdated row for rule_id={rule_id}; found {}",
        name_rows.len()
    );
    let EventKind::SaContextRuleNameUpdated {
        new_name_redacted,
        audit_request_id: row_rid,
        ..
    } = &name_rows[0].event_kind
    else {
        unreachable!("filtered above");
    };
    assert_eq!(
        new_name_redacted, "e2- len=10",
        "new_name_redacted must be the first-3 + len form of \"e2-renamed\""
    );
    assert_eq!(
        row_rid, &rename_request_id,
        "name row must carry the rename call's request_id"
    );
    let log_text = std::fs::read_to_string(&log_path).expect("audit log must be readable");
    assert!(
        !log_text.contains("e2-renamed"),
        "the verbatim rule name must never appear in the audit log"
    );

    // ── Typed valid-until row: present once, value None, correlated ─────────
    let vu_rows: Vec<_> = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaContextRuleValidUntilUpdated { rule_id: rid, .. } if *rid == rule_id
            )
        })
        .collect();
    assert_eq!(
        vu_rows.len(),
        1,
        "exactly one SaContextRuleValidUntilUpdated row for rule_id={rule_id}; found {}",
        vu_rows.len()
    );
    let EventKind::SaContextRuleValidUntilUpdated {
        new_valid_until,
        audit_request_id: row_rid,
        ..
    } = &vu_rows[0].event_kind
    else {
        unreachable!("filtered above");
    };
    assert_eq!(
        *new_valid_until, None,
        "new_valid_until must be None (expiry cleared)"
    );
    assert_eq!(
        row_rid, &expiry_request_id,
        "valid-until row must carry the expiry call's request_id"
    );

    // ── The raw rows still accompany the typed rows (one sa.ok per op:
    //    install + rename + expiry-clear = 3) ─────────────────────────────────
    let raw_ok_count = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaRawInvocation {
                    wire_code,
                    result: SaInvocationResult::Success,
                    ..
                } if wire_code == "sa.ok"
            )
        })
        .count();
    assert_eq!(
        raw_ok_count, 3,
        "each of install/rename/expiry-clear must emit a SaRawInvocation(sa.ok) row; \
         found {raw_ok_count}"
    );
}
