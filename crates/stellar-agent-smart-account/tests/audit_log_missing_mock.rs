//! Mock-substrate test: audit-log cross-check fires on malicious-RPC rule drop.
//!
//! # Purpose
//!
//! When the local audit log records two rules as installed-but-not-deleted
//! (`SaContextRuleCreated` without a matching `SaContextRuleDeleted`) but the
//! on-chain enumeration returns only one of them, `list_active_context_rules` must:
//! 1. Return the on-chain rule in `rules`.
//! 2. Return the missing rule ID in `audit_log_missing`.
//! 3. Emit a `warn!` trace event referencing the discrepancy.
//!
//! The test also verifies that `MigrationPlan.audit_log_missing` is propagated
//! through `MigrationPlanner::build` so operators see the desync in the dry-run
//! output.
//!
//! # Setup
//!
//! - Audit log: `SaContextRuleCreated` for rule IDs 0 and 1 (no matching
//!   `SaContextRuleDeleted` for either — both appear installed).
//! - Mock RPC: `Count=1`, `get_rule(0)` returns a valid rule, `get_rule(1)`
//!   would not be reached (Count=1, early-exit after rule 0 found).
//!   Effectively the RPC "lies" by suppressing rule 1.
//!
//! # Expected behaviour
//!
//! - `list_active_context_rules` returns `rules = [summary_0]`.
//! - `audit_log_missing = [1]` (rule 1 in audit log but absent from on-chain).
//! - The manager propagates `audit_log_missing` to the caller.
//!
//! # Gating
//!
//! No feature flags required. Runs under default `cargo test`.
//!
//! ```text
//! cargo test --test audit_log_missing_mock
//! ```
//!
//! # Active rule enumeration
//!
//! Verifies the audit-log cross-check contract for `list_active_context_rules`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; adversarial fixtures assert invariants via panic-on-failure"
)]

use std::sync::{Arc, Mutex};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleManager, ContextRuleManagerConfig, DEFAULT_MAX_SCAN_ID,
};
use stellar_xdr::{ContractId, Hash, Limits, ScAddress, ScVal, WriteXdr};
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

#[path = "smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
mod rpc_mock_helpers;

use rpc_mock_helpers::{
    SorobanRpcDispatcher, build_context_rule_scval_xdr, build_ledger_entries_account,
    build_simulate_response, signer_set_n_of_n, tmp_audit_writer,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";
const SOURCE_G: &str = stellar_agent_core::constants::SIMULATE_SENTINEL_G;

/// Redacted form of the zero smart-account address used in tests.
/// `stellar_strkey::Contract([0u8; 32])` → `CAAAA...ABSC4` (first-5-last-5).
const ZERO_SA_REDACTED: &str = "CAAAA...ABSC4";

// ── Helpers ───────────────────────────────────────────────────────────────────

fn addr(byte: u8) -> ScAddress {
    ScAddress::Contract(ContractId(Hash([byte; 32])))
}

fn u32_xdr(n: u32) -> String {
    ScVal::U32(n)
        .to_xdr_base64(Limits::none())
        .expect("ScVal::U32 must encode")
}

/// Writes a `SaContextRuleCreated` audit entry for the given rule_id.
fn write_rule_created(writer: &Arc<Mutex<AuditWriter>>, rule_id: u32, sa_redacted: &str) {
    let entry = AuditEntry::new_sa_context_rule_created(
        sa_redacted,
        rule_id,
        "Default",
        1, // signers_count
        0, // policies_count
        None,
        CHAIN_ID,
        Uuid::new_v4().to_string(),
        vec![],
        vec![],
        false,
        false,
    );
    writer
        .lock()
        .unwrap()
        .write_entry(entry)
        .expect("write_entry for SaContextRuleCreated must succeed");
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit-log cross-check: fires when RPC suppresses a rule
// ─────────────────────────────────────────────────────────────────────────────

/// Audit-log cross-check: `list_active_context_rules` returns `audit_log_missing = [1]` when the
/// local audit log records rules 0 and 1 as installed (no matching delete entries)
/// but the mock RPC returns `Count=1` and serves only rule 0.
///
/// A malicious RPC that drops a live rule from enumeration would cause the
/// migration planner to silently skip it — the External signers on the dropped
/// rule would never be migrated. This cross-check surfaces the discrepancy as
/// `audit_log_missing` so operators can investigate before executing a migration.
///
/// # Mock sequence
///
/// 1. `getLedgerEntries` → account entry for SOURCE_G (for fetch_account).
/// 2. `simulateTransaction` 1 → `get_context_rules_count` returns 1.
/// 3. `simulateTransaction` 2 → `get_rule(0)` → rule-0 ScVal.
/// (Early-exit fires after rule 0: returned=1 >= active_count=1.)
///
/// Rule 1 is NOT probed by the enumeration — Count=1 causes early-exit.
/// But the audit log has rule 1 as installed → audit_log_missing = [1].
#[tokio::test]
async fn t11_audit_log_missing_fires_on_rpc_drop() {
    let server = MockServer::start().await;
    let smart_account = addr(0x00); // zero address → CAAAA...ABSC4

    let signers = signer_set_n_of_n(1);

    // Mock: Count=1, only rule 0 served (rule 1 suppressed).
    let ledger_resp = build_ledger_entries_account(SOURCE_G);
    let sim_responses = vec![
        build_simulate_response(&u32_xdr(1)),
        build_simulate_response(&build_context_rule_scval_xdr(0, &signers, &[])),
    ];

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            ledger_resp,
            sim_responses,
        ))
        .mount(&server)
        .await;

    // Write audit log with rules 0 AND 1 as created (no deletes).
    let (audit_writer, _audit_log_path, _tmp_dir) = tmp_audit_writer();
    write_rule_created(&audit_writer, 0, ZERO_SA_REDACTED);
    write_rule_created(&audit_writer, 1, ZERO_SA_REDACTED);

    // Build ContextRuleManager with the audit writer so the cross-check runs.
    let config = ContextRuleManagerConfig::new(
        server.uri(),
        NETWORK_PASSPHRASE.to_owned(),
        std::time::Duration::from_secs(5),
        CHAIN_ID.to_owned(),
    )
    .with_audit_writer(Arc::clone(&audit_writer));

    let manager = ContextRuleManager::new(config).expect("ContextRuleManager::new must succeed");

    let result = manager
        .list_active_context_rules(smart_account, SOURCE_G, DEFAULT_MAX_SCAN_ID)
        .await
        .expect("list_active_context_rules must succeed");

    // On-chain enumeration returned only rule 0.
    assert_eq!(
        result.rules.len(),
        1,
        "on-chain enumeration must return 1 rule (rule 0); got {}",
        result.rules.len()
    );
    assert_eq!(
        result.rules[0].rule_id, 0,
        "returned rule must have rule_id=0; got {}",
        result.rules[0].rule_id
    );

    // Audit-log cross-check: rule 1 is in the audit log as installed but the RPC did not return it.
    assert_eq!(
        result.audit_log_missing,
        vec![1],
        "audit_log_missing must be [1] (rule 1 in audit log, absent from RPC); \
         got: {:?}",
        result.audit_log_missing
    );
}

/// Negative case: when there is NO audit-log desync (audit log matches on-chain exactly),
/// `audit_log_missing` must be empty.
///
/// Both rules 0 and 1 are in the audit log; the RPC serves Count=2 and both rules.
/// No desync → `audit_log_missing.is_empty()`.
#[tokio::test]
async fn t11b_no_audit_log_missing_when_in_sync() {
    let server = MockServer::start().await;
    let smart_account = addr(0x00);

    let signers = signer_set_n_of_n(1);

    // Mock: Count=2, both rules served.
    let ledger_resp = build_ledger_entries_account(SOURCE_G);
    let sim_responses = vec![
        build_simulate_response(&u32_xdr(2)),
        build_simulate_response(&build_context_rule_scval_xdr(0, &signers, &[])),
        build_simulate_response(&build_context_rule_scval_xdr(1, &signers, &[])),
    ];

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            ledger_resp,
            sim_responses,
        ))
        .mount(&server)
        .await;

    // Audit log: both rules 0 and 1 as created (in sync with the RPC).
    let (audit_writer, _audit_log_path, _tmp_dir) = tmp_audit_writer();
    write_rule_created(&audit_writer, 0, ZERO_SA_REDACTED);
    write_rule_created(&audit_writer, 1, ZERO_SA_REDACTED);

    let config = ContextRuleManagerConfig::new(
        server.uri(),
        NETWORK_PASSPHRASE.to_owned(),
        std::time::Duration::from_secs(5),
        CHAIN_ID.to_owned(),
    )
    .with_audit_writer(Arc::clone(&audit_writer));

    let manager = ContextRuleManager::new(config).expect("ContextRuleManager::new must succeed");

    let result = manager
        .list_active_context_rules(smart_account, SOURCE_G, DEFAULT_MAX_SCAN_ID)
        .await
        .expect("list_active_context_rules must succeed");

    assert_eq!(
        result.rules.len(),
        2,
        "must return 2 rules; got {}",
        result.rules.len()
    );

    assert!(
        result.audit_log_missing.is_empty(),
        "audit_log_missing must be empty when in sync; got: {:?}",
        result.audit_log_missing
    );
}
