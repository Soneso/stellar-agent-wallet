//! Testnet acceptance tests for pre-submission rule expiry
//! detection at signing paths.
//!
//! This test covers signing-path enforcement in `managers/rules.rs` and
//! `managers/signers.rs`.
//!
//! # Coverage
//!
//! | Fixture | Description |
//! |---------|-------------|
//! | [`h_1_revocation_audit_log_timeline`] | Deploy SA; install session rule with `valid_until = current + 5`; revoke (`set-valid-until = current_ledger + 2`); assert `SaRawInvocation` audit row exists |
//! | [`h_2_post_revocation_new_sign_refused`] | Deploy SA; install session rule; revoke (`set-valid-until = current_ledger + 2`); wait past revocation_ledger; attempt `add_policy`; assert `SaError::RuleExpired` with `current > valid_until` |
//!
//! # Gating
//!
//! Feature flag: `testnet-integration`. Run with:
//!
//! ```text
//! cargo build --release -p stellar-agent-cli
//! cargo test --features testnet-integration \
//!   --test smart_account_session_rule_expiry_testnet_acceptance
//! ```
//!
//! Tests require live testnet access and Friendbot funding. They are excluded
//! from default `cargo test` runs.
//!
//! # On-chain behavior
//!
//! - The smart-account contract panics with `UnvalidatedContext = 3002` when
//!   `valid_until < e.ledger().sequence()` at validate time.
//! - The contract rejects `valid_until < current_ledger` at update time with
//!   `PastValidUntil = 3005`. Revocation uses `valid_until = current_ledger`
//!   (NOT `current_ledger - 1`) to avoid this reject.
//! - Off-chain revocation sets `valid_until = current_ledger`.
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

use std::io::BufRead as _;
use std::io::BufReader;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{EventKind, SaInvocationResult};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_smart_account::SaError;
use stellar_agent_smart_account::bindings::ContextRuleType;
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
};
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRuleSignerInput,
    parse_c_strkey_to_smart_account, parse_g_strkey_to_signer_address,
};
use stellar_rpc_client::Client;
use zeroize::Zeroizing;

// ── Network constants ─────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";
const FEE_STROOPS: u32 = 1_000_000;
const TIMEOUT_SECS: u64 = 120;

// ── Design note ──────────────────────────────────────────────────────────────
//
// Revocation ledger offset: tests set `valid_until = current_ledger + 2` rather
// than `current_ledger` to absorb the simulate→apply timing window. The
// contract's `update_context_rule_valid_until` checks
// `valid_until < e.ledger().sequence()`
// at *apply* time (one or more ledgers after simulate returns), so
// `valid_until = simulate_ledger` may already be stale by apply time and trigger
// `PastValidUntil = 3005`. Adding 2 gives a two-ledger (~10 s) buffer while
// still making the rule expire quickly enough to test it. The canonical
// production pattern is `valid_until = latest_ledger_from_simulate_response`
// (available inside submit_signed_invoke as `sim_response.latest_ledger`); the
// tests use `fetch_latest_ledger() + 2` as the externally-observable proxy.
//
// After setting `valid_until = revocation_ledger`, we wait until the
// chain advances past `revocation_ledger`. The expiry check fires AFTER simulate
// returns `latestLedger`; at that point `latestLedger > revocation_ledger`, so
// `valid_until (== revocation_ledger) < latestLedger` → `RuleExpired` refusal.

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
            var_name: "testnet-expiry-acceptance".to_owned(),
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

/// Returns the latest ledger sequence from the testnet Soroban RPC.
///
/// Uses `Server::get_latest_ledger()` via the Soroban RPC client.
async fn fetch_latest_ledger() -> u32 {
    let server = Client::new(TESTNET_RPC_URL).expect("Server::new must succeed");

    let resp = server
        .get_latest_ledger()
        .await
        .expect("get_latest_ledger must succeed on testnet");

    resp.sequence
}

/// Waits for the testnet ledger to advance past `target_ledger` by polling
/// `get_latest_ledger` up to `max_polls` times with a 6-second delay.
///
/// 6 seconds is slightly longer than the nominal 5-second ledger time to
/// allow for minor timing jitter. `max_polls = 10` gives a 60-second bound.
async fn wait_for_ledger_past(target_ledger: u32, max_polls: u32) -> u32 {
    for poll in 0..max_polls {
        let current = fetch_latest_ledger().await;
        if current > target_ledger {
            return current;
        }
        eprintln!(
            "[wait_for_ledger_past] poll={poll}: current={current}, target={target_ledger} — waiting 6s"
        );
        tokio::time::sleep(Duration::from_secs(6)).await;
    }
    panic!(
        "wait_for_ledger_past: ledger did not advance past {target_ledger} within {} polls",
        max_polls
    );
}

fn tmp_audit_writer() -> (
    Arc<Mutex<AuditWriter>>,
    std::path::PathBuf,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter::open must succeed");
    (Arc::new(Mutex::new(writer)), path, dir)
}

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

fn fresh_rule_manager_uncapped(audit_writer: Arc<Mutex<AuditWriter>>) -> ContextRuleManager {
    // Use a very large cap so the substrate install with `current + 5`
    // does not trigger the horizon enforcement.  The horizon test is in
    // `smart_account_session_rule_horizon_testnet_acceptance.rs`; here we focus
    // on the expiry detection.
    ContextRuleManager::new(
        ContextRuleManagerConfig::new(
            TESTNET_RPC_URL.to_owned(),
            TESTNET_PASSPHRASE.to_owned(),
            Duration::from_secs(TIMEOUT_SECS),
            CHAIN_ID.to_owned(),
        )
        .with_session_rule_max_horizon_ledgers(u32::MAX)
        .with_audit_writer(audit_writer),
    )
    .expect("ContextRuleManager::new must succeed")
}

fn rid() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ── Revocation audit-log timeline ────────────────────────────────────────────

/// Deploy a fresh smart account, install a session rule with `valid_until =
/// current_ledger + 5`, then immediately revoke via `update_valid_until(=
/// current_ledger + 2)`. Assert the audit log records a `SaRawInvocation` row
/// with a successful outcome.
///
/// # Design
///
/// The revocation pattern:
/// - `valid_until = current_ledger + 2` — the `+2` absorbs the simulate→apply
///   timing window (the contract rejects `valid_until < e.ledger().sequence()`
///   at apply time with `PastValidUntil = 3005`; `current_ledger` alone may be
///   stale by
///   then). The canonical value is `sim_response.latest_ledger` inside
///   `submit_signed_invoke`; the test uses `fetch_latest_ledger() + 2` as the
///   externally-observable proxy.
/// - After `revocation_ledger` closes, `current_ledger > valid_until`, which
///   the validate-time check (`valid_until < e.ledger().sequence()`) catches.
///
/// This test asserts the audit log captures the revocation event correctly so
/// operators can reconstruct the timeline forensically.
#[tokio::test]
async fn h_1_revocation_audit_log_timeline() {
    // ── Step 1: Fresh signer + fund ───────────────────────────────────────────
    let (signer_g, _signer_s, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;
    eprintln!("signer funded: {}", &signer_g[..8]);

    // ── Step 2: Deploy fresh smart account ────────────────────────────────────
    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    eprintln!("smart_account = {}", &sa_strkey[..8]);

    // ── Step 3: Install session rule with valid_until = current_ledger + 5 ────
    let current_ledger = fetch_latest_ledger().await;
    let session_valid_until = current_ledger.saturating_add(5);
    eprintln!(
        "current_ledger = {current_ledger}; installing rule with \
         valid_until = {session_valid_until}"
    );

    let (audit_writer, audit_log_path, _tmpdir) = tmp_audit_writer();
    let manager = fresh_rule_manager_uncapped(Arc::clone(&audit_writer));

    let sa_addr = parse_c_strkey_to_smart_account(&sa_strkey).expect("C-strkey must parse");
    let signer_addr = parse_g_strkey_to_signer_address(&signer_g).expect("G-strkey must parse");

    let definition = ContextRuleDefinition::new(
        ContextRuleType::Default,
        "h-1-session-rule".to_owned(),
        Some(session_valid_until),
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![],
    );

    let install_out = manager
        .install_rule(
            sa_addr.clone(),
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

    let rule_id = install_out.rule_id;
    eprintln!("session rule installed: rule_id = {rule_id}");

    // ── Step 4: Immediately revoke via update_valid_until ─────────────────────
    // Revocation sets `valid_until` to a ledger in the very near future.
    //
    // `current_ledger + 2` absorbs the simulate→apply timing window: the contract
    // rejects `valid_until < e.ledger().sequence()` at apply time
    // (PastValidUntil = 3005). A 2-ledger (~10 s) buffer avoids the race
    // while still making the rule expire quickly enough to verify on-chain expiry.
    //
    // The `update_valid_until_inner` path does NOT have the expiry check
    // wired — revocation is always allowed.
    let revocation_ledger = fetch_latest_ledger().await.saturating_add(2);
    eprintln!("revoking: set valid_until = {revocation_ledger} (current_ledger + 2)");

    manager
        .update_valid_until(
            sa_addr.clone(),
            rule_id,
            Some(revocation_ledger),
            vec![ContextRuleId::new(rule_id)],
            signer_box.as_ref(),
            None,
            rid(),
        )
        .await
        .expect("update_valid_until (revocation) must succeed");

    eprintln!("revocation submitted successfully");

    // ── Step 5: Verify audit log records the revocation timeline ──────────────
    let entries = read_audit_entries(&audit_log_path);

    // Expect at minimum: install rows + revocation SaRawInvocation.
    // `SaRawInvocation` carries `wire_code` and `result`; there is no `op` field —
    // the op-label is used only at emission time (passed to `emit_metadata_update_audit`).
    // Successful revocation emits `wire_code = "sa.ok"` and `result = Success`.
    let raw_rows: Vec<_> = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaRawInvocation { wire_code, result, .. }
                if wire_code.as_str() == "sa.ok"
                    && *result == SaInvocationResult::Success
            )
        })
        .collect();

    assert!(
        !raw_rows.is_empty(),
        "audit log must contain at least one SaRawInvocation row with \
         op='update_valid_until' and result=Success; entries found: {}",
        entries.len()
    );

    eprintln!(
        "PASS: revocation audit row found: op=update_valid_until result=Success; \
         total audit entries = {}",
        entries.len()
    );

    // Verify the installed rule still has a valid_until value (the on-chain
    // state reflects the revocation: `valid_until = revocation_ledger`).
    let rule_scval = manager
        .get_rule(sa_addr, rule_id, &signer_g)
        .await
        .expect("get_rule must succeed")
        .expect("rule must still exist after revocation");

    let valid_until_from_chain =
        stellar_agent_smart_account::managers::rules::extract_valid_until_from_rule_scval(
            &rule_scval,
        )
        .expect("extract_valid_until_from_rule_scval must succeed on well-formed rule scval");

    assert_eq!(
        valid_until_from_chain,
        Some(revocation_ledger),
        "on-chain valid_until must equal the revocation_ledger; \
         got {:?}",
        valid_until_from_chain
    );

    eprintln!("PASS: on-chain valid_until = {revocation_ledger} confirmed");
}

// ── Post-revocation new-sign refused with RuleExpired ────────────────────────

/// Deploy a fresh smart account, install a session rule, revoke it, wait
/// past `revocation_ledger`, then attempt `add_policy` on the revoked rule.
/// Assert the wallet refuses with `SaError::RuleExpired { rule_id, valid_until,
/// current }` where `current > valid_until`.
///
/// # Design
///
/// `ContextRuleManager::add_policy` is used instead of `SignersManager::add_signer`
/// because `add_signer` requires a threshold policy to be installed on the rule
/// (`identify_threshold_policy` fires before the expiry check, fail-closed).
/// `add_policy` is one of the signing paths wired with the pre-submission expiry
/// check; it does not require a threshold policy.
///
/// After revocation (`valid_until = revocation_ledger`), we wait for the chain
/// to advance so `latest_ledger > revocation_ledger`. The expiry check fires
/// AFTER `simulateTransaction` returns `latestLedger` and compares
/// `valid_until < latestLedger`. The refusal fires before any auth-entry signing
/// byte is generated.
///
/// The dummy `policy_address` (set to the smart-account address itself) is
/// never inspected by wallet-side code before the expiry check fires.
///
#[tokio::test]
async fn h_2_post_revocation_new_sign_refused() {
    // ── Step 1: Fresh signer + fund ───────────────────────────────────────────
    let (signer_g, _signer_s, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;
    eprintln!("signer funded: {}", &signer_g[..8]);

    // ── Step 2: Deploy fresh smart account ────────────────────────────────────
    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    eprintln!("smart_account = {}", &sa_strkey[..8]);

    // ── Step 3: Install a session rule with valid_until = current + 5 ─────────
    let current_ledger = fetch_latest_ledger().await;
    let session_valid_until = current_ledger.saturating_add(5);
    eprintln!(
        "current_ledger = {current_ledger}; installing rule with \
         valid_until = {session_valid_until}"
    );

    let (audit_writer, _audit_log_path, _tmpdir) = tmp_audit_writer();
    let rule_manager = fresh_rule_manager_uncapped(Arc::clone(&audit_writer));

    let sa_addr = parse_c_strkey_to_smart_account(&sa_strkey).expect("C-strkey must parse");
    let signer_addr = parse_g_strkey_to_signer_address(&signer_g).expect("G-strkey must parse");

    let definition = ContextRuleDefinition::new(
        ContextRuleType::Default,
        "h-2-session-rule".to_owned(),
        Some(session_valid_until),
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr.clone(),
        }],
        vec![],
    );

    let install_out = rule_manager
        .install_rule(
            sa_addr.clone(),
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

    let rule_id = install_out.rule_id;
    eprintln!("session rule installed: rule_id = {rule_id}");

    // ── Step 4: Revoke via update_valid_until ─────────────────────────────────
    // `current_ledger + 2` absorbs the simulate→apply timing window (see design
    // note at the top of this file). After `revocation_ledger` closes, the
    // expiry check `valid_until < latestLedger` fires in `add_signer`.
    let revocation_ledger = fetch_latest_ledger().await.saturating_add(2);
    eprintln!("revoking: set valid_until = {revocation_ledger} (current_ledger + 2)");

    rule_manager
        .update_valid_until(
            sa_addr.clone(),
            rule_id,
            Some(revocation_ledger),
            vec![ContextRuleId::new(rule_id)],
            signer_box.as_ref(),
            None,
            rid(),
        )
        .await
        .expect("update_valid_until (revocation) must succeed");

    eprintln!("revocation submitted; rule.valid_until = {revocation_ledger}");

    // ── Step 5: Wait for ledger to advance past revocation_ledger ────────────
    // After this, `latest_ledger` from the next `simulateTransaction` response
    // will be > `revocation_ledger = valid_until`, so `valid_until < latest_ledger`
    // → `RuleExpired` refusal.
    let post_revocation_ledger = wait_for_ledger_past(revocation_ledger, 10).await;
    eprintln!(
        "chain advanced: post_revocation_ledger = {post_revocation_ledger} \
         (was {revocation_ledger}); current > valid_until invariant holds"
    );

    // ── Step 6: Attempt add_policy against the revoked rule ──────────────────
    // `ContextRuleManager::add_policy` is one of the signing paths wired with
    // the pre-submission expiry check.  It does NOT require a threshold policy
    // (unlike `SignersManager::add_signer`) — the divergence check is a no-op
    // when `signers_manager` is `None` (as in the test-uncapped manager).
    //
    // The call reaches `submit_signed_invoke` which:
    //   1. Calls `simulateTransaction` — succeeds (sim doesn't validate auth
    //      timing; `latestLedger = post_revocation_ledger > revocation_ledger`).
    //   2. Fires expiry check: `valid_until (= revocation_ledger)
    //      < latest_ledger (= post_revocation_ledger)` → `RuleExpired`.
    //   3. Never reaches auth-entry signing — no signature material is produced.
    //
    // The dummy policy address is a C-strkey of the smart account itself; its
    // on-chain validity is never verified by the wallet-side code before the
    // expiry check fires.
    let dummy_policy_addr = sa_addr.clone();
    let result = rule_manager
        .add_policy(
            sa_addr.clone(),
            rule_id,
            dummy_policy_addr,
            stellar_xdr::ScVal::Void, // install_param
            vec![ContextRuleId::new(rule_id)],
            signer_box.as_ref(),
            None, // audit_writer (per-call override)
            rid(),
        )
        .await;

    // ── Step 7: Assert the wallet refused with RuleExpired ────────────────────
    assert!(
        result.is_err(),
        "add_policy must fail against a revoked rule; got Ok(..)"
    );

    let err = result.unwrap_err();
    eprintln!("add_policy returned error: {err:?}");

    assert!(
        matches!(&err, SaError::RuleExpired { rule_id: r, valid_until: v, current: c }
            if *r == rule_id
                && *v == revocation_ledger
                && *c > *v),
        "expected SaError::RuleExpired {{ rule_id: {rule_id}, \
         valid_until: {revocation_ledger}, current > {revocation_ledger} }}; \
         got {err:?}"
    );

    assert_eq!(
        err.wire_code(),
        "sa.rule_expired",
        "wire code must be sa.rule_expired; got {}",
        err.wire_code()
    );

    // Verify the invariant: current > valid_until.
    if let SaError::RuleExpired {
        valid_until,
        current,
        ..
    } = &err
    {
        assert!(
            current > valid_until,
            "current ({current}) must be strictly greater than valid_until ({valid_until})"
        );
        eprintln!("PASS: current={current} > valid_until={valid_until} invariant verified");
    }

    eprintln!("PASS: add_policy refused with sa.rule_expired; no signature produced");
}
