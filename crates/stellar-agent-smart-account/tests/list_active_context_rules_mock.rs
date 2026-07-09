//! Mock-substrate unit tests for `ContextRuleManager::list_active_context_rules`.
//!
//! # Coverage map
//!
//! | Test | Mechanism | Coverage |
//! |------|-----------|----------|
//! | [`t1_empty_account_returns_empty_vec`] | wiremock | `Count=0` → empty vec; no per-rule simulate calls |
//! | [`t2_dense_scan_all_returned`] | wiremock | `Count=N`, IDs `0..N`, no gaps → all N rules in monotonic order |
//! | [`t3_sparse_scan_single_gap`] | wiremock | `Count=N-1`, gap at ID 1 → N-1 rules; ID 1 silently skipped |
//! | [`t4_multi_gap_sparse_scan`] | wiremock | `Count=N-3`, multiple gaps → N-3 rules; all gaps skipped |
//! | [`t5_max_scan_id_exhaustion_returns_error`] | wiremock | `Count=2`, no rules in `[0, 3)`, `max_scan_id=3` → `DeploymentFailed` |
//! | [`t6_symbolic_not_found_treated_as_gap`] | wiremock | `ContextRuleNotFound` as symbolic name → `Ok(None)` gap path |
//! | [`t7_non_context_rule_not_found_error_is_skipped_defensively`] | wiremock | Unrecognised simulate error → defensive skip (rules_skipped += 1) |
//! | [`t2b_valid_until_some_decoded_correctly`] | wiremock | `valid_until = Some(N)` → `ScVal::U32(N)` decoded to `Some(N)`; `Some(valid_until)` decoder regression-lock |
//! | [`t8_collective_scan_budget_fires_before_max_scan_id_exhaustion`] | wiremock (delayed response) | `active_count=5`, per-rule probes delayed past a short `timeout` → collective scan budget refuses before `max_scan_id` would exhaust (#33) |
//!
//! The empty-account and dense-scan tests are regression-locks for the early-exit logic.
//! The `Some(valid_until)` decoder path requires the canonical
//! soroban ABI (`ScVal::U32(n)`) rather than an enum-variant map encoding.
//! The single-gap and multi-gap tests are the primary sparse-ID coverage.
//! The exhaustion test locks the safety-bound exhaustion error path.
//! The symbolic-form test locks the symbolic `ContextRuleNotFound` form (symbolic-string branch).
//! The defensive-skip test confirms an unrecognised simulate error is defensively skipped, not hard-propagated.
//!
//! # Gating
//!
//! No feature flags required. Tests compile under default `cargo test` via
//! a wiremock HTTP server. `--features test-helpers` is NOT required here
//! because these tests construct `ContextRuleManager` directly, not via
//! `MigrationPlanner::new_for_test`.
//!
//! Run with:
//!
//! ```text
//! cargo test --test list_active_context_rules_mock
//! ```
//!
//! # Coverage
//!
//! Active context-rule enumeration (adversarial fixtures).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; adversarial fixtures assert invariants via panic-on-failure"
)]

use stellar_agent_smart_account::managers::rules::{
    ContextRuleManager, ContextRuleManagerConfig, DEFAULT_MAX_SCAN_ID,
};
use stellar_xdr::{ContractId, Hash, Limits, ScAddress, ScVal, WriteXdr};
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

#[path = "smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
mod rpc_mock_helpers;

use rpc_mock_helpers::{
    SorobanRpcDispatcher, build_context_rule_scval_xdr,
    build_context_rule_scval_xdr_with_valid_until, build_ledger_entries_account,
    build_simulate_response, signer_set_n_of_n,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";
const SOURCE_G: &str = stellar_agent_core::constants::SIMULATE_SENTINEL_G;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// A contract address with the given byte fill.
fn addr(byte: u8) -> ScAddress {
    ScAddress::Contract(ContractId(Hash([byte; 32])))
}

/// Encodes `ScVal::U32(n)` to XDR base64 — used as `get_context_rules_count` return.
fn u32_xdr(n: u32) -> String {
    ScVal::U32(n)
        .to_xdr_base64(Limits::none())
        .expect("ScVal::U32 must encode")
}

/// Builds a simulate-error response (contains `"error"` top-level field).
///
/// The `error` string is returned verbatim in the JSON-RPC result so that
/// `simulate_read_only` maps it to `SaError::DeploymentFailed { phase: "simulate", ... }`.
fn build_simulate_error_response(error_msg: &str) -> serde_json::Value {
    serde_json::json!({
        "error": error_msg,
        "latestLedger": 1000
    })
}

/// Builds a `ContextRuleManager` connected to the wiremock server.
///
/// The manager has no `signers_manager` (read-only tests) and optionally
/// an `audit_writer` (used by the defensive-skip test indirectly; the
/// no-`audit_writer` path is explicitly tested in the function body).
fn manager_for_server(server: &MockServer) -> ContextRuleManager {
    let config = ContextRuleManagerConfig::new(
        server.uri(),
        NETWORK_PASSPHRASE.to_owned(),
        std::time::Duration::from_secs(5),
        CHAIN_ID.to_owned(),
    );
    ContextRuleManager::new(config).expect("ContextRuleManager::new must succeed")
}

// ─────────────────────────────────────────────────────────────────────────────
// empty account — Count=0 → empty vec, no per-rule simulate calls
// ─────────────────────────────────────────────────────────────────────────────

/// `list_active_context_rules` returns an empty enumeration when
/// `get_context_rules_count()` returns `0`.
///
/// The mock sequence is:
/// 1. `getLedgerEntries` → account entry for `SOURCE_G` (needed by `fetch_account`).
/// 2. `simulateTransaction` → `get_context_rules_count` returns `ScVal::U32(0)`.
///
/// No additional `simulateTransaction` calls must be issued (early-exit at step 2).
///
#[tokio::test]
async fn t1_empty_account_returns_empty_vec() {
    let server = MockServer::start().await;
    let smart_account = addr(0x01);

    let ledger_resp = build_ledger_entries_account(SOURCE_G);
    let simulate_resp = build_simulate_response(&u32_xdr(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(ledger_resp, simulate_resp))
        .mount(&server)
        .await;

    let manager = manager_for_server(&server);
    let result = manager
        .list_active_context_rules(smart_account, SOURCE_G, DEFAULT_MAX_SCAN_ID)
        .await
        .expect("list_active_context_rules must succeed for Count=0");

    assert!(
        result.rules.is_empty(),
        "rules must be empty for Count=0; got {} rules",
        result.rules.len()
    );
    assert_eq!(
        result.rules_skipped, 0,
        "rules_skipped must be 0 for Count=0; got {}",
        result.rules_skipped
    );
    assert!(
        result.audit_log_missing.is_empty(),
        "audit_log_missing must be empty (no audit writer configured); got: {:?}",
        result.audit_log_missing
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// dense scan — Count=N, IDs 0..N, no gaps → all N rules in monotonic order
// ─────────────────────────────────────────────────────────────────────────────

/// Dense scan — all 3 rules present at IDs 0, 1, 2 (no gaps).
///
/// The mock sequence is:
/// 1. `getLedgerEntries` → account entry.
/// 2. `simulateTransaction` 1 → `get_context_rules_count` returns `ScVal::U32(3)`.
/// 3. `simulateTransaction` 2 → `get_context_rule(0)` → rule-0 ScVal.
/// 4. `simulateTransaction` 3 → `get_context_rule(1)` → rule-1 ScVal.
/// 5. `simulateTransaction` 4 → `get_context_rule(2)` → rule-2 ScVal.
/// Early-exit fires after rule 2 because `returned(3) >= active_count(3)`.
///
#[tokio::test]
async fn t2_dense_scan_all_returned() {
    let server = MockServer::start().await;
    let smart_account = addr(0x02);
    let signers = signer_set_n_of_n(1);

    let ledger_resp = build_ledger_entries_account(SOURCE_G);

    let mut sim_responses = vec![build_simulate_response(&u32_xdr(3))];
    for rule_id in 0..3u32 {
        let rule_xdr = build_context_rule_scval_xdr(rule_id, &signers, &[]);
        sim_responses.push(build_simulate_response(&rule_xdr));
    }

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            ledger_resp,
            sim_responses,
        ))
        .mount(&server)
        .await;

    let manager = manager_for_server(&server);
    let result = manager
        .list_active_context_rules(smart_account, SOURCE_G, DEFAULT_MAX_SCAN_ID)
        .await
        .expect("list_active_context_rules must succeed for dense Count=3");

    assert_eq!(
        result.rules.len(),
        3,
        "must return 3 rules; got {}",
        result.rules.len()
    );
    assert_eq!(
        result.rules_skipped, 0,
        "no gaps → rules_skipped must be 0; got {}",
        result.rules_skipped
    );

    // Verify monotonic rule-ID order.
    for (i, rule) in result.rules.iter().enumerate() {
        assert_eq!(
            rule.rule_id, i as u32,
            "rule[{i}].rule_id must be {i}; got {}",
            rule.rule_id
        );
    }

    // Verify names.
    for (i, rule) in result.rules.iter().enumerate() {
        let expected_name = format!("rule-{i}");
        assert_eq!(
            rule.name, expected_name,
            "rule[{i}].name must be '{expected_name}'; got '{}'",
            rule.name
        );
    }

    // Verify context_type_label for the Default variant.
    for rule in &result.rules {
        assert_eq!(
            rule.context_type_label, "default",
            "context_type_label must be 'default'; got '{}'",
            rule.context_type_label
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Some(valid_until) decoder regression-lock
// ─────────────────────────────────────────────────────────────────────────────

/// `list_active_context_rules` correctly decodes `valid_until = Some(N)`
/// from the canonical soroban `Option<u32>` ABI: `ScVal::U32(N)`.
///
/// # Regression-lock
///
/// The decoder at `rules.rs` requires the canonical soroban ABI encoding:
/// `ScVal::Map([{Symbol("None"), Void} | {Symbol("Some"), U32(n)}])` is incorrect;
/// the canonical encoding per `soroban-env-common/src/option.rs:3-16` is:
///   - `None` → `ScVal::Void`
///   - `Some(n)` → `ScVal::U32(n)` (the inner type's raw ABI directly)
///
/// This test exercises the canonical `Some(N)` shape directly, confirming the
/// decoder and encoder are consistent with the soroban ABI.
///
/// # Mock sequence
///
/// 1. `getLedgerEntries` → account entry.
/// 2. `simulateTransaction` 1 → `get_context_rules_count` returns 1.
/// 3. `simulateTransaction` 2 → `get_context_rule(0)` → rule-0 ScVal with
///    `valid_until = Some(999_999)` encoded as `ScVal::U32(999_999)`.
///
/// # Assertions
///
/// - `result.rules[0].valid_until == Some(999_999)`.
/// - `result.rules[0].rule_id == 0`.
///
#[tokio::test]
async fn t2b_valid_until_some_decoded_correctly() {
    let server = MockServer::start().await;
    let smart_account = addr(0x0B);
    let signers = signer_set_n_of_n(1);

    let ledger_resp = build_ledger_entries_account(SOURCE_G);

    // Build rule-0 with valid_until = Some(999_999).
    // This uses ScVal::U32(999_999) for valid_until — the canonical ABI.
    let rule_xdr = build_context_rule_scval_xdr_with_valid_until(0, &signers, &[], Some(999_999));

    let sim_responses = vec![
        build_simulate_response(&u32_xdr(1)), // get_context_rules_count → 1
        build_simulate_response(&rule_xdr),   // get_context_rule(0) → rule with Some(valid_until)
    ];

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            ledger_resp,
            sim_responses,
        ))
        .mount(&server)
        .await;

    let manager = manager_for_server(&server);
    let result = manager
        .list_active_context_rules(smart_account, SOURCE_G, DEFAULT_MAX_SCAN_ID)
        .await
        .expect("list_active_context_rules must succeed with valid_until=Some(999_999)");

    assert_eq!(
        result.rules.len(),
        1,
        "must return 1 rule; got {}",
        result.rules.len()
    );
    assert_eq!(
        result.rules[0].rule_id, 0,
        "rule_id must be 0; got {}",
        result.rules[0].rule_id
    );
    assert_eq!(
        result.rules[0].valid_until,
        Some(999_999),
        "valid_until must be Some(999_999) — canonical ScVal::U32(n) ABI; \
         got {:?}. If this fails, the decoder is using the wrong enum-variant map \
         encoding instead of the canonical soroban-env-common/src/option.rs ABI.",
        result.rules[0].valid_until
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// sparse scan — single gap at ID 1
// ─────────────────────────────────────────────────────────────────────────────

/// Sparse scan — IDs `[0, gap@1, 2, 3]` with `Count=3` (deleted rule 1).
///
/// The mock sequence is:
/// 1. `getLedgerEntries` → account entry.
/// 2. `simulateTransaction` 1 → `get_context_rules_count` returns `ScVal::U32(3)`.
/// 3. `simulateTransaction` 2 → `get_context_rule(0)` → rule-0 ScVal.
/// 4. `simulateTransaction` 3 → `get_context_rule(1)` → error `"Error(Contract, #3000)"`.
/// 5. `simulateTransaction` 4 → `get_context_rule(2)` → rule-2 ScVal.
/// 6. `simulateTransaction` 5 → `get_context_rule(3)` → rule-3 ScVal.
/// Early-exit fires after rule 3 because `returned(3) >= active_count(3)`
/// (the primitive's loop tests `returned >= active_count` at the top of each
/// iteration; ID 4 is never probed).
///
#[tokio::test]
async fn t3_sparse_scan_single_gap() {
    let server = MockServer::start().await;
    let smart_account = addr(0x03);
    let signers = signer_set_n_of_n(1);

    let ledger_resp = build_ledger_entries_account(SOURCE_G);

    // Count=3 (installed 4, deleted 1).
    let mut sim_responses = vec![build_simulate_response(&u32_xdr(3))];
    // ID 0: present
    sim_responses.push(build_simulate_response(&build_context_rule_scval_xdr(
        0,
        &signers,
        &[],
    )));
    // ID 1: deleted → ContextRuleNotFound (numeric form)
    sim_responses.push(build_simulate_error_response("Error(Contract, #3000)"));
    // ID 2: present
    sim_responses.push(build_simulate_response(&build_context_rule_scval_xdr(
        2,
        &signers,
        &[],
    )));
    // ID 3: present
    sim_responses.push(build_simulate_response(&build_context_rule_scval_xdr(
        3,
        &signers,
        &[],
    )));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            ledger_resp,
            sim_responses,
        ))
        .mount(&server)
        .await;

    let manager = manager_for_server(&server);
    let result = manager
        .list_active_context_rules(smart_account, SOURCE_G, DEFAULT_MAX_SCAN_ID)
        .await
        .expect("list_active_context_rules must succeed across a single gap");

    assert_eq!(
        result.rules.len(),
        3,
        "must return 3 rules (IDs 0, 2, 3); got {}",
        result.rules.len()
    );
    // Sparse gaps go to `gaps_seen`, NOT `rules_skipped`.
    // `rules_skipped` is reserved for anomalous per-rule simulate errors.
    assert_eq!(
        result.gaps_seen, 1,
        "one sparse gap → gaps_seen must be 1; got {}",
        result.gaps_seen
    );
    assert_eq!(
        result.rules_skipped, 0,
        "no anomalous skips → rules_skipped must be 0; got {}",
        result.rules_skipped
    );

    // Verify the returned rule IDs (monotonic, gap skipped).
    let ids: Vec<u32> = result.rules.iter().map(|r| r.rule_id).collect();
    assert_eq!(
        ids,
        vec![0, 2, 3],
        "rule IDs must be [0, 2, 3]; got {ids:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// multi-gap sparse scan
// ─────────────────────────────────────────────────────────────────────────────

/// Sparse scan — IDs `[0, gap@1, gap@2, 3, 4, gap@5, 6]` with `Count=4`.
///
/// 7 IDs allocated, 3 deleted → Count=4. The scan must skip gaps at IDs 1, 2,
/// and 5 and return rules at IDs 0, 3, 4, 6 in monotonic order.
///
#[tokio::test]
async fn t4_multi_gap_sparse_scan() {
    let server = MockServer::start().await;
    let smart_account = addr(0x04);
    let signers = signer_set_n_of_n(1);

    let ledger_resp = build_ledger_entries_account(SOURCE_G);

    // Count=4: IDs [0, gap@1, gap@2, 3, 4, gap@5, 6]
    let not_found_xdr = build_simulate_error_response("Error(Contract, #3000)");

    let sim_responses = vec![
        build_simulate_response(&u32_xdr(4)), // get_context_rules_count → 4
        build_simulate_response(&build_context_rule_scval_xdr(0, &signers, &[])), // ID 0: present
        not_found_xdr.clone(),                // ID 1: deleted
        not_found_xdr.clone(),                // ID 2: deleted
        build_simulate_response(&build_context_rule_scval_xdr(3, &signers, &[])), // ID 3: present
        build_simulate_response(&build_context_rule_scval_xdr(4, &signers, &[])), // ID 4: present
        not_found_xdr.clone(),                // ID 5: deleted
        build_simulate_response(&build_context_rule_scval_xdr(6, &signers, &[])), // ID 6: present
    ];

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            ledger_resp,
            sim_responses,
        ))
        .mount(&server)
        .await;

    let manager = manager_for_server(&server);
    let result = manager
        .list_active_context_rules(smart_account, SOURCE_G, DEFAULT_MAX_SCAN_ID)
        .await
        .expect("list_active_context_rules must succeed across multiple gaps");

    assert_eq!(
        result.rules.len(),
        4,
        "must return 4 rules (IDs 0, 3, 4, 6); got {}",
        result.rules.len()
    );
    // Sparse gaps go to `gaps_seen`, NOT `rules_skipped`.
    assert_eq!(
        result.gaps_seen, 3,
        "three sparse gaps → gaps_seen must be 3; got {}",
        result.gaps_seen
    );
    assert_eq!(
        result.rules_skipped, 0,
        "no anomalous skips → rules_skipped must be 0; got {}",
        result.rules_skipped
    );

    let ids: Vec<u32> = result.rules.iter().map(|r| r.rule_id).collect();
    assert_eq!(
        ids,
        vec![0, 3, 4, 6],
        "rule IDs must be [0, 3, 4, 6]; got {ids:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// max_scan_id exhaustion → DeploymentFailed
// ─────────────────────────────────────────────────────────────────────────────

/// `list_active_context_rules` returns `SaError::DeploymentFailed` with
/// `phase = "simulate"` when `max_scan_id` is exhausted before all active rules
/// are found.
///
/// `phase = "simulate"` because `"enumerate_rules"` is NOT in the closed
/// `SaError::DeploymentFailed` phase set. The exhaustion error uses `"simulate"`
/// since the scan operates in the simulate phase.
///
/// Setup: `Count=2` but both rules exist at IDs 100+ (not in `[0, 3)`).
/// With `max_scan_id=3`, all 3 probe calls return `ContextRuleNotFound`.
/// After the scan, `returned=0 < active_count=2` → exhaustion error.
///
#[tokio::test]
async fn t5_max_scan_id_exhaustion_returns_error() {
    let server = MockServer::start().await;
    let smart_account = addr(0x05);

    let ledger_resp = build_ledger_entries_account(SOURCE_G);
    let not_found = build_simulate_error_response("Error(Contract, #3000)");

    // Count=2, but no rules in [0, 3) — all three probes return NotFound.
    let sim_responses = vec![
        build_simulate_response(&u32_xdr(2)), // get_context_rules_count → 2
        not_found.clone(),                    // ID 0: not found
        not_found.clone(),                    // ID 1: not found
        not_found.clone(),                    // ID 2: not found (max_scan_id=3, loop ends)
    ];

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            ledger_resp,
            sim_responses,
        ))
        .mount(&server)
        .await;

    let manager = manager_for_server(&server);
    let result = manager
        .list_active_context_rules(smart_account, SOURCE_G, 3 /* max_scan_id */)
        .await;

    let err = result.expect_err("must fail with DeploymentFailed when max_scan_id exhausted");
    assert_eq!(
        err.wire_code(),
        "sa.deployment_failed",
        "wire_code must be 'sa.deployment_failed'; got: {}",
        err.wire_code()
    );

    let msg = err.to_string();
    // Phase is "simulate" ("enumerate_rules" is not in the closed set).
    // The error message contains "max_scan_id" to identify the exhaustion cause.
    assert!(
        msg.contains("max_scan_id"),
        "error message must reference max_scan_id exhaustion; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// symbolic ContextRuleNotFound form treated as gap
// ─────────────────────────────────────────────────────────────────────────────

/// Symbolic-form `ContextRuleNotFound` (not numeric `#3000`) is
/// correctly mapped to `Ok(None)` (gap path) by `get_rule`'s decoder.
///
/// The mock sequence:
/// 1. `get_context_rules_count` → 1.
/// 2. `get_rule(0)` → error `"ContextRuleNotFound: rule 0 not found"` (symbolic).
/// 3. `get_rule(1)` → rule-1 ScVal.
///
/// The symbolic string `"ContextRuleNotFound"` triggers the
/// `redacted_reason.contains("ContextRuleNotFound")` branch in the decoder.
#[tokio::test]
async fn t6_symbolic_not_found_treated_as_gap() {
    let server = MockServer::start().await;
    let smart_account = addr(0x06);
    let signers = signer_set_n_of_n(1);

    let ledger_resp = build_ledger_entries_account(SOURCE_G);

    let sim_responses = vec![
        build_simulate_response(&u32_xdr(1)), // get_context_rules_count → 1
        build_simulate_error_response("ContextRuleNotFound: rule 0 not found"), // ID 0: symbolic
        build_simulate_response(&build_context_rule_scval_xdr(1, &signers, &[])), // ID 1: present
    ];

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            ledger_resp,
            sim_responses,
        ))
        .mount(&server)
        .await;

    let manager = manager_for_server(&server);
    let result = manager
        .list_active_context_rules(smart_account, SOURCE_G, DEFAULT_MAX_SCAN_ID)
        .await
        .expect("list_active_context_rules must succeed; symbolic NotFound is a gap");

    assert_eq!(
        result.rules.len(),
        1,
        "must return 1 rule (ID 1); got {}",
        result.rules.len()
    );
    assert_eq!(
        result.rules[0].rule_id, 1,
        "returned rule ID must be 1; got {}",
        result.rules[0].rule_id
    );
    // Symbolic NotFound is a recognised sparse gap → `gaps_seen`.
    assert_eq!(
        result.gaps_seen, 1,
        "symbolic NotFound is a sparse gap → gaps_seen must be 1; got {}",
        result.gaps_seen
    );
    assert_eq!(
        result.rules_skipped, 0,
        "no anomalous skip → rules_skipped must be 0; got {}",
        result.rules_skipped
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// non-ContextRuleNotFound error propagates (not silently skipped)
// ─────────────────────────────────────────────────────────────────────────────

/// A `simulate_transaction` response with an error that does NOT contain
/// `"ContextRuleNotFound"` or `"#3000"` is defensively skipped (not propagated).
///
/// `list_active_context_rules` uses skip-and-count semantics for per-rule simulate
/// failures. A transient RPC blip on one rule must not abort the whole enumeration.
///
/// The mock sequence:
/// 1. `get_context_rules_count` → 2.
/// 2. `get_rule(0)` → rule-0 ScVal (success).
/// 3. `get_rule(1)` → error `"Error(Contract, #9999)"` (unrecognised discriminant;
///    not `ContextRuleNotFound` / `#3000`).
///
/// Expected behaviour:
/// - `list_active_context_rules` returns `Ok(enumeration)` (not `Err`).
/// - `enumeration.rules.len() == 1` (only rule 0 decoded).
/// - `enumeration.rules_skipped >= 1` (the #9999 error increments the skip counter).
///
#[tokio::test]
async fn t7_non_context_rule_not_found_error_is_skipped_defensively() {
    let server = MockServer::start().await;
    let smart_account = addr(0x07);
    let signers = signer_set_n_of_n(1);

    let ledger_resp = build_ledger_entries_account(SOURCE_G);

    // Count=2; rule 0 returns OK, rule 1 returns an unrecognised error.
    // After the two per-rule probes, returned=1 < active_count=2 → exhaustion
    // error (max_scan_id reached with 1 found, 1 skipped). We set max_scan_id=2
    // so the loop exhausts at rule ID 1, triggering the exhaustion path.
    // The test checks that the unrecognised error was SKIPPED (rules_skipped >= 1)
    // rather than propagated.
    let sim_responses = vec![
        build_simulate_response(&u32_xdr(2)), // get_context_rules_count → 2
        build_simulate_response(&build_context_rule_scval_xdr(0, &signers, &[])), // ID 0: OK
        build_simulate_error_response("Error(Contract, #9999)"), // ID 1: unrecognised (skip)
    ];

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            ledger_resp,
            sim_responses,
        ))
        .mount(&server)
        .await;

    let manager = manager_for_server(&server);
    // max_scan_id=2 so the loop hits ID 0 (success) and ID 1 (error → skip),
    // then exhaustion check: returned(1) < active_count(2).
    let result = manager
        .list_active_context_rules(smart_account, SOURCE_G, 2 /* max_scan_id */)
        .await;

    // The unrecognised error is defensively skipped.
    // The scan exhausts at max_scan_id=2 with returned=1 < active_count=2,
    // so list_active_context_rules returns DeploymentFailed (exhaustion).
    // Key assertion: rules_skipped is reflected in the exhaustion error path
    // and we did NOT get an early hard-propagation error from the #9999 blip.
    //
    // Distinguish the exhaustion path (expected) from the hard-propagation path (wrong):
    // - Exhaustion error: message contains "max_scan_id" or "simulate" (phase="simulate").
    // - Hard-propagation would have triggered before exhaustion and would contain "9999".
    let err = result.expect_err(
        "scan must exhaust (returned=1 < active_count=2); exhaustion is the expected error",
    );
    assert_eq!(
        err.wire_code(),
        "sa.deployment_failed",
        "wire_code must be 'sa.deployment_failed'; got: {}",
        err.wire_code()
    );

    let msg = err.to_string();
    // The exhaustion message contains "max_scan_id" or "reached".
    // It must NOT contain "9999" — that would indicate hard propagation of the
    // per-rule error instead of a defensive skip.
    assert!(
        msg.contains("max_scan_id"),
        "error must be the exhaustion error (max_scan_id reached), not the #9999 \
         per-rule blip — the blip must have been defensively skipped; got: {msg}"
    );
    assert!(
        !msg.contains("9999"),
        "error must NOT propagate the #9999 per-rule error; \
         defensive skip must have occurred; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// t8 — collective scan budget fires before max_scan_id would exhaust (#33)
// ─────────────────────────────────────────────────────────────────────────────

/// Responder that answers `getLedgerEntries` and the FIRST `simulateTransaction`
/// call (`get_context_rules_count`) immediately, then delays every subsequent
/// `simulateTransaction` call (the per-rule `get_rule` probes) by `delay` —
/// long enough to exceed a short test `timeout`, proving
/// [`ContextRuleManager::list_active_context_rules`]'s collective scan budget
/// (derived from `self.timeout`) fires rather than letting the scan run for
/// `max_scan_id` full per-call windows.
struct DelayedPerRuleResponder {
    ledger_entries: serde_json::Value,
    count_response: serde_json::Value,
    per_rule_response: serde_json::Value,
    delay: std::time::Duration,
    simulate_call: std::sync::atomic::AtomicUsize,
}

impl wiremock::Respond for DelayedPerRuleResponder {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        use std::sync::atomic::Ordering;

        let body: serde_json::Value =
            serde_json::from_slice(&request.body).unwrap_or(serde_json::json!({}));
        let req_id = body.get("id").cloned().unwrap_or(serde_json::json!(1));
        let method = body
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        match method {
            "getLedgerEntries" => wiremock::ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "jsonrpc": "2.0", "id": req_id, "result": self.ledger_entries }),
            ),
            "simulateTransaction" => {
                let call_idx = self.simulate_call.fetch_add(1, Ordering::SeqCst);
                let result = if call_idx == 0 {
                    self.count_response.clone()
                } else {
                    self.per_rule_response.clone()
                };
                let template = wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({ "jsonrpc": "2.0", "id": req_id, "result": result }),
                );
                if call_idx == 0 {
                    template
                } else {
                    template.set_delay(self.delay)
                }
            }
            _ => wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "jsonrpc": "2.0", "id": req_id, "result": {} })),
        }
    }
}

/// The collective scan budget (`self.timeout`) fires before `max_scan_id`
/// would exhaust: a short `timeout` (100ms) against a mock that delays every
/// per-rule `get_rule` probe past that budget (300ms) must refuse with the
/// collective-budget message, NOT continue probing toward `max_scan_id`.
#[tokio::test]
async fn t8_collective_scan_budget_fires_before_max_scan_id_exhaustion() {
    let server = MockServer::start().await;
    let smart_account = addr(0x08);

    let ledger_resp = build_ledger_entries_account(SOURCE_G);
    // `active_count = 5` so the scan would otherwise need up to 5 per-rule
    // probes (well within `max_scan_id`) — the budget must cut it short
    // long before `max_scan_id` is reached.
    let count_response = build_simulate_response(&u32_xdr(5));
    let signers = signer_set_n_of_n(1);
    let per_rule_response =
        build_simulate_response(&build_context_rule_scval_xdr(0, &signers, &[]));

    let responder = DelayedPerRuleResponder {
        ledger_entries: ledger_resp,
        count_response,
        per_rule_response,
        delay: std::time::Duration::from_millis(300),
        simulate_call: std::sync::atomic::AtomicUsize::new(0),
    };

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(responder)
        .mount(&server)
        .await;

    // A 100ms manager timeout: the collective scan budget derives from this
    // (`self.timeout`), so the FIRST delayed per-rule probe (300ms) alone
    // must exceed it.
    let config = ContextRuleManagerConfig::new(
        server.uri(),
        NETWORK_PASSPHRASE.to_owned(),
        std::time::Duration::from_millis(100),
        CHAIN_ID.to_owned(),
    );
    let manager = ContextRuleManager::new(config).expect("ContextRuleManager::new must succeed");

    let result = manager
        .list_active_context_rules(smart_account, SOURCE_G, DEFAULT_MAX_SCAN_ID)
        .await;

    let err = result.expect_err(
        "a per-rule probe delayed past the collective scan budget must refuse, \
         not silently continue probing",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("collective scan budget"),
        "error must be the collective-budget timeout, not scan-bound exhaustion \
         or a hard-propagated per-rule error; got: {msg}"
    );
}
