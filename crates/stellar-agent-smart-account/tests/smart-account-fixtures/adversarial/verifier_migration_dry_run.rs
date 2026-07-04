//! Mock-substrate tests for the migration planner.
//!
//! # Coverage map
//!
//! | Test | Mechanism | Coverage |
//! |------|-----------|----------|
//! | [`preflight_unknown_destination_via_planner`] | wiremock planner invocation | Pre-flight 1 rejects unlisted destination hash |
//! | [`preflight_mutable_destination_error_shape`] | wiremock planner invocation | `VerifierMigrationFailed { phase: "preflight_destination_mutable" }` wire code |
//! | [`revoked_destination_error_shape`] | wiremock planner invocation | `VerifierWasmRevoked` wire code |
//! | [`empty_plan_via_planner`] | wiremock planner invocation | `MigrationPlan::total_transaction_count() == 0` on zero-rule account |
//! | [`plan_total_tx_count_two_per_signer_step`] | wiremock planner invocation | `2 * signer_steps.len()` invariant per CAP-46 |
//!
//! All tests are end-to-end [`MigrationPlanner::build`] invocations against a
//! wiremock HTTP server.
//!
//! # Gating
//!
//! `--features test-helpers` enables the test-only struct constructors
//! (`MigrationPlan::new_for_test`, `RuleMigration::new_for_test`,
//! `SignerMigrationStep::new_for_test`).
//!
//! Wiremock tests additionally require `wiremock` in `[dev-dependencies]`
//! (already declared in `crates/stellar-agent-smart-account/Cargo.toml`).
//!
//! Run with:
//!
//! ```text
//! cargo test -p stellar-agent-smart-account --features test-helpers \
//!   --test adversarial_fixtures verifier_migration
//! ```
//!
//! # Implements
//!
//! Verifier diversification acceptance criteria for the migration planner.

use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::migration::MigrationPlanner;
use stellar_agent_smart_account::managers::signers::SignersManager;
use stellar_agent_smart_account::verifier_allowlist::{VERIFIER_ALLOWLIST, VerifierAuditStatus};
use stellar_xdr::LedgerEntryData;
use stellar_xdr::{
    ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint,
    Hash, Limits, ScAddress, ScContractInstance, ScMap, ScMapEntry, ScSymbol, ScVal, WriteXdr,
};
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::rpc_mock_helpers::{
    SOURCE_G, SorobanRpcDispatcher, account_entry_xdr, account_key_xdr,
    build_context_rule_external_signers_xdr, build_ledger_entries_account_and_contract,
    build_simulate_response, contract_instance_key_xdr, manager_two_url, tmp_audit_writer,
};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// OZ WebAuthn verifier v0.7.1 wasm hash — the legacy `VERIFIER_ALLOWLIST[1]`
/// entry (one of two Audited OZ entries; still recognised).
///
/// `vendor/oz-webauthn-verifier/v0.7.1/PROVENANCE.md` SHA-256 anchor.
/// OZ source SHA: `3f81125bed3114cc93f5fca6d13240082050269a` (tag v0.7.1).
const OZ_VERIFIER_HASH: [u8; 32] = [
    0x67, 0x80, 0x06, 0x90, 0x9b, 0x50, 0xc6, 0xc3, 0x65, 0xc0, 0x33, 0xf1, 0x37, 0x19, 0x7e, 0x91,
    0x0d, 0x83, 0x96, 0xa2, 0xc6, 0x8e, 0x92, 0x81, 0x32, 0x7a, 0x2e, 0xd7, 0xdb, 0xf4, 0xb2, 0x7a,
];

/// Unknown hash — not in `VERIFIER_ALLOWLIST`.
const UNKNOWN_HASH: [u8; 32] = [0xffu8; 32];

/// Test-only revoked verifier hash included in `VERIFIER_ALLOWLIST` under
/// `--features test-helpers`.
const TEST_REVOKED_HASH: [u8; 32] = [0xeeu8; 32];

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A contract address with the given byte fill.
fn addr(byte: u8) -> ScAddress {
    ScAddress::Contract(ContractId(Hash([byte; 32])))
}

/// Encodes `ScVal::U32(n)` to XDR base64 — used as the `get_context_rules_count` return.
fn u32_xdr(n: u32) -> String {
    ScVal::U32(n)
        .to_xdr_base64(Limits::none())
        .expect("ScVal::U32 must encode to XDR")
}

/// Builds a `getLedgerEntries` response with an account entry and a mutable
/// contract instance carrying an `Admin` storage key.
fn mutable_ledger_entries_account_and_contract(
    account_g: &str,
    contract: &ScAddress,
    wasm_hash: [u8; 32],
) -> serde_json::Value {
    let admin_holder = stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([0xaau8; 32])),
    ));
    // #[contracttype] encodes the unit enum variant `Admin` as
    // ScVal::Vec(Some(ScVec([Symbol]))) — soroban-sdk-macros-25.3.1
    // derive_enum.rs:298-303 / :363-367 (same form as the production matcher
    // in managers/verifiers.rs).
    let admin_symbol = ScVal::Symbol(ScSymbol(
        b"Admin"
            .to_vec()
            .try_into()
            .expect("Admin fits in ScSymbol"),
    ));
    let admin_entry = ScMapEntry {
        key: ScVal::Vec(Some(
            vec![admin_symbol]
                .try_into()
                .expect("single-element ScVec construction is infallible"),
        )),
        val: ScVal::Address(admin_holder),
    };
    let storage: ScMap = vec![admin_entry]
        .try_into()
        .expect("one storage entry fits");
    let instance = ScContractInstance {
        executable: ContractExecutable::Wasm(Hash(wasm_hash)),
        storage: Some(storage),
    };
    let entry_xdr = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: contract.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(instance),
    })
    .to_xdr_base64(Limits::none())
    .expect("mutable ContractInstance XDR must encode");

    serde_json::json!({
        "entries": [
            {
                "key": account_key_xdr(account_g),
                "xdr": account_entry_xdr(account_g, 100),
                "lastModifiedLedgerSeq": 100
            },
            {
                "key": contract_instance_key_xdr(contract),
                "xdr": entry_xdr,
                "lastModifiedLedgerSeq": 100
            }
        ],
        "latestLedger": 1000
    })
}

/// Builds a `SignersManager` backed by a wiremock server and returns it with the server.
///
/// Both primary and secondary RPC URLs point at the same server. The `_tmp_dir` returned
/// by `tmp_audit_writer` must be held by the caller for the duration of the test.
async fn manager_with_server(server: &MockServer) -> (SignersManager, tempfile::TempDir) {
    let (audit_writer, audit_log_path, tmp_dir) = tmp_audit_writer();
    let manager = manager_two_url(&server.uri(), &server.uri(), audit_writer, audit_log_path);
    (manager, tmp_dir)
}

// ─────────────────────────────────────────────────────────────────────────────
// preflight_destination_unknown — planner invocation (wiremock path)
// ─────────────────────────────────────────────────────────────────────────────

/// `MigrationPlanner::build` returns `VerifierMigrationFailed { phase: "preflight_destination_unknown" }`
/// when the mock RPC serves a destination verifier with a wasm hash that is NOT in
/// `VERIFIER_ALLOWLIST`.
///
/// # Mock sequence
///
/// `getLedgerEntries` → contract instance with `UNKNOWN_HASH` (32 × `0xff`).
/// Pre-flight 1 checks the hash against `VERIFIER_ALLOWLIST` and finds no match.
/// The planner returns `VerifierMigrationFailed { phase: "preflight_destination_unknown" }`.
///
/// No `simulateTransaction` call is issued (pre-flight fails before rule enumeration).
///
/// # Implements
///
/// Verifier diversification pre-flight gate 1: destination hash must be in the allowlist.
#[tokio::test]
async fn preflight_unknown_destination_via_planner() {
    let server = MockServer::start().await;

    // The mock destination verifier address.
    let dest_addr = addr(0xAB);

    // getLedgerEntries → contract instance with UNKNOWN_HASH (not in VERIFIER_ALLOWLIST) +
    // account entry for SOURCE_G (required by ContextRuleManager::simulate_read_only which
    // calls fetch_account before every simulateTransaction — including the pre-flight
    // fetch_observed_wasm_hash call).
    let ledger_resp = build_ledger_entries_account_and_contract(SOURCE_G, &dest_addr, UNKNOWN_HASH);
    let simulate_resp = build_simulate_response(&u32_xdr(0)); // would be get_context_rules_count

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(ledger_resp, simulate_resp))
        .mount(&server)
        .await;

    let (manager, _tmp_dir) = manager_with_server(&server).await;
    let planner = MigrationPlanner::new(&manager);

    let request_id = Uuid::new_v4().to_string();
    let smart_account = addr(0x01);
    // from_hash may be anything; only the dest hash matters for pre-flight 1.
    let from_hash = [0xABu8; 32];

    let result = planner
        .build(smart_account, from_hash, dest_addr, &request_id)
        .await;

    let err = result.expect_err("pre-flight 1 must reject UNKNOWN_HASH destination");

    // Wire code must be "sa.verifier_migration_failed".
    assert_eq!(
        err.wire_code(),
        "sa.verifier_migration_failed",
        "wire_code must be 'sa.verifier_migration_failed'; got: {}",
        err.wire_code()
    );

    // Phase must be "preflight_destination_unknown".
    let msg = err.to_string();
    assert!(
        msg.contains("preflight_destination_unknown"),
        "Display must contain 'preflight_destination_unknown'; got: {msg}"
    );
    assert!(
        msg.contains("VERIFIER_ALLOWLIST"),
        "Display must reference VERIFIER_ALLOWLIST; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// preflight_destination_mutable — planner invocation
// ─────────────────────────────────────────────────────────────────────────────

/// `MigrationPlanner::build` returns `VerifierMigrationFailed {
/// phase: "preflight_destination_mutable" }` when the destination verifier
/// contract has a non-zero `Admin` key in instance storage.
///
/// # Implements
///
/// Verifier diversification pre-flight gate 3: destination verifier must be immutable.
#[tokio::test]
async fn preflight_mutable_destination_error_shape() {
    let server = MockServer::start().await;
    let dest_addr = addr(0xBE);
    let ledger_resp =
        mutable_ledger_entries_account_and_contract(SOURCE_G, &dest_addr, OZ_VERIFIER_HASH);
    let simulate_resp = build_simulate_response(&u32_xdr(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(ledger_resp, simulate_resp))
        .mount(&server)
        .await;

    let (manager, _tmp_dir) = manager_with_server(&server).await;
    let planner = MigrationPlanner::new(&manager);
    let request_id = Uuid::new_v4().to_string();
    let result = planner
        .build(addr(0x01), [0xABu8; 32], dest_addr, &request_id)
        .await;

    let err = result.expect_err("mutable destination verifier must be refused");

    assert_eq!(
        err.wire_code(),
        "sa.verifier_migration_failed",
        "wire_code must be 'sa.verifier_migration_failed'"
    );

    let msg = err.to_string();
    assert!(
        msg.contains("preflight_destination_mutable"),
        "Display must contain the phase; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// revoked destination — planner invocation
// ─────────────────────────────────────────────────────────────────────────────

/// `MigrationPlanner::build` returns `VerifierWasmRevoked` when the
/// destination verifier hash maps to a `Revoked` allowlist entry.
///
/// Uses the `--features test-helpers` revoked fixture entry so production
/// allowlist contents remain unchanged.
///
/// # Implements
///
/// Verifier diversification pre-flight gate 2: destination verifier must not be revoked.
#[tokio::test]
async fn revoked_destination_error_shape() {
    let server = MockServer::start().await;
    let dest_addr = addr(0xEF);
    let ledger_resp =
        build_ledger_entries_account_and_contract(SOURCE_G, &dest_addr, TEST_REVOKED_HASH);
    let simulate_resp = build_simulate_response(&u32_xdr(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(ledger_resp, simulate_resp))
        .mount(&server)
        .await;

    let (manager, _tmp_dir) = manager_with_server(&server).await;
    let planner = MigrationPlanner::new(&manager);
    let request_id = Uuid::new_v4().to_string();
    let result = planner
        .build(addr(0x01), [0xABu8; 32], dest_addr, &request_id)
        .await;

    let err = result.expect_err("revoked destination verifier must be refused");

    assert_eq!(
        err.wire_code(),
        "sa.verifier_wasm_revoked",
        "wire_code must be 'sa.verifier_wasm_revoked'"
    );

    let msg = err.to_string();
    assert!(
        msg.contains("eeeeeeee"),
        "Display must contain the hash projection; got: {msg}"
    );
    assert!(
        matches!(err, SaError::VerifierWasmRevoked { .. }),
        "expected VerifierWasmRevoked, got {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// empty plan — planner invocation (wiremock path)
// ─────────────────────────────────────────────────────────────────────────────

/// `MigrationPlanner::build` returns an empty plan when the mock RPC serves
/// a destination verifier with the OZ WebAuthn hash (in `VERIFIER_ALLOWLIST`,
/// `Audited`, immutable) and `get_context_rules_count` returns `0`.
///
/// # Mock sequence
///
/// 1. `getLedgerEntries` (×2 parallel for two-RPC fetch_observed_wasm_hash) →
///    contract instance with `OZ_VERIFIER_HASH` + `storage: None` (immutable).
/// 2. `getLedgerEntries` (×2 parallel for detect_contract_mutability) →
///    same response (both use `ContractDataEntry`; `storage: None` → `Immutable`).
/// 3. `simulateTransaction` → `get_context_rules_count` returns `ScVal::U32(0)`.
///
/// Since primary and secondary point to the same mock server, the dispatcher
/// serves all `getLedgerEntries` calls with the same canned response.
///
/// # Assertions
///
/// - `plan.affected_rules.is_empty()` (no rules to scan).
/// - `plan.total_transaction_count() == 0`.
/// - `plan.warnings.is_empty()` (0 txs → no inter-tx hazard warning).
/// - `plan.destination_audit_status` is `Audited`.
/// - `plan.to_hash == OZ_VERIFIER_HASH`.
///
/// # Implements
///
/// Verifier diversification plan-build phase: zero-rule account produces an empty plan.
#[tokio::test]
async fn empty_plan_via_planner() {
    let server = MockServer::start().await;

    let dest_addr = addr(0xCD);

    // getLedgerEntries → OZ verifier hash (for fetch_observed_wasm_hash +
    // detect_contract_mutability) AND account entry for SOURCE_G (for fetch_account
    // inside ContextRuleManager::simulate_read_only → list_active_context_rules).
    let ledger_resp =
        build_ledger_entries_account_and_contract(SOURCE_G, &dest_addr, OZ_VERIFIER_HASH);

    // simulateTransaction → get_context_rules_count returns 0.
    let simulate_resp = build_simulate_response(&u32_xdr(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(ledger_resp, simulate_resp))
        .mount(&server)
        .await;

    let (manager, _tmp_dir) = manager_with_server(&server).await;
    let planner = MigrationPlanner::new(&manager);

    let request_id = Uuid::new_v4().to_string();
    let smart_account = addr(0x01);
    let from_hash = [0x11u8; 32];

    let plan = planner
        .build(smart_account, from_hash, dest_addr, &request_id)
        .await
        .expect("MigrationPlanner::build must succeed: OZ hash is Audited + Immutable");

    // Destination hash must be OZ hash.
    assert_eq!(
        plan.to_hash, OZ_VERIFIER_HASH,
        "plan.to_hash must match the OZ verifier hash served by the mock"
    );

    // to_hash must be in VERIFIER_ALLOWLIST (pre-flight 1 passed).
    let in_allowlist = VERIFIER_ALLOWLIST
        .iter()
        .any(|e| e.wasm_hash == plan.to_hash);
    assert!(in_allowlist, "plan.to_hash must be in VERIFIER_ALLOWLIST");

    // Destination audit status must be Audited (pre-flight 2 passed).
    assert!(
        matches!(
            plan.destination_audit_status,
            VerifierAuditStatus::Audited { .. }
        ),
        "destination_audit_status must be Audited; got: {:?}",
        plan.destination_audit_status
    );

    // No affected rules — get_context_rules_count returned 0.
    assert!(
        plan.affected_rules.is_empty(),
        "affected_rules must be empty when rule_count == 0"
    );

    // Total transaction count must be 0.
    assert_eq!(
        plan.total_transaction_count(),
        0,
        "total_transaction_count must be 0 for an empty affected_rules"
    );

    // No warnings for 0 transactions (threshold is > 2, not >= 2).
    assert!(
        plan.warnings.is_empty(),
        "warnings must be empty for a 0-tx plan; got: {:?}",
        plan.warnings
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// plan total tx count is 2 * signer_steps per CAP-46
// ─────────────────────────────────────────────────────────────────────────────

/// A full planner invocation with 3 affected rules and 2 External signers
/// per rule yields `total_transaction_count() == 12`.
///
/// CAP-46 permits exactly one
/// `InvokeHostFunctionOp` per Soroban transaction. Each signer migration step
/// is therefore a remove + add pair = 2 transactions.
///
/// OZ reference:
/// - `remove_signer` at `packages/accounts/src/smart_account/mod.rs:405-408`
///   (SHA `a9c4216`).
/// - `add_signer` at `packages/accounts/src/smart_account/mod.rs:374-377`
///   (SHA `a9c4216`).
///
/// # Implements
///
/// Verifier diversification transaction-count invariant: 2 transactions per signer step.
#[tokio::test]
async fn plan_total_tx_count_two_per_signer_step() {
    let server = MockServer::start().await;
    let smart_account = addr(0x01);
    let dest_addr = addr(0xCD);
    let key_data = [0xABu8; 32];

    let rule_0_xdr = build_context_rule_external_signers_xdr(0, &[10, 11], &dest_addr, &key_data);
    let rule_1_xdr = build_context_rule_external_signers_xdr(1, &[20, 21], &dest_addr, &key_data);
    let rule_2_xdr = build_context_rule_external_signers_xdr(2, &[30, 31], &dest_addr, &key_data);
    let ledger_resp =
        build_ledger_entries_account_and_contract(SOURCE_G, &dest_addr, OZ_VERIFIER_HASH);
    let sim_responses = vec![
        build_simulate_response(&u32_xdr(3)),
        build_simulate_response(&rule_0_xdr),
        build_simulate_response(&rule_1_xdr),
        build_simulate_response(&rule_2_xdr),
        build_simulate_response(&rule_0_xdr),
        build_simulate_response(&rule_1_xdr),
        build_simulate_response(&rule_2_xdr),
    ];

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            ledger_resp,
            sim_responses,
        ))
        .mount(&server)
        .await;

    let (manager, _tmp_dir) = manager_with_server(&server).await;
    let planner = MigrationPlanner::new(&manager).with_max_scan_id(10);
    let request_id = Uuid::new_v4().to_string();
    let plan = planner
        .build(smart_account, OZ_VERIFIER_HASH, dest_addr, &request_id)
        .await
        .expect("planner must build 3-rule, 6-signer-step migration plan");

    assert_eq!(plan.affected_rules.len(), 3, "must affect 3 rules");
    for rule in &plan.affected_rules {
        assert_eq!(
            rule.signer_steps.len(),
            2,
            "rule {} must contain two affected signer steps",
            rule.rule_id
        );
        assert_eq!(
            rule.transaction_count(),
            4,
            "rule {}: 2 signers -> 4 transactions",
            rule.rule_id
        );
    }
    assert_eq!(
        plan.total_transaction_count(),
        12,
        "3 rules * 2 signers * 2 tx per signer = 12 transactions"
    );
    assert!(
        !plan.warnings.is_empty(),
        "12-tx plan must produce inter-tx failure warning"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// sparse-ID migration planner (regression-lock for the gap-iteration bug)
// ─────────────────────────────────────────────────────────────────────────────

/// `MigrationPlanner::build` correctly identifies affected rules across a
/// sparse-ID gap via `collect_affected_rules`.
///
/// # Setup
///
/// - Smart account has `Count=2` active rules, IDs `[0, gap@1, 2]` (rule 1 was deleted).
/// - Both rules 0 and 2 contain one `External(dest_addr, key_data)` signer whose
///   verifier wasm hash is `OZ_VERIFIER_HASH` (served by the getLedgerEntries mock).
/// - `from_hash = OZ_VERIFIER_HASH` — both External signers match the migration source.
/// - `to_verifier_addr = dest_addr` with the same `OZ_VERIFIER_HASH` (allowlisted).
///
/// # Iteration invariant
///
/// `collect_affected_rules` delegates rule discovery to `list_active_context_rules`,
/// which scans `[0, max_scan_id)` and skips gaps. With `Count=2` and a gap at ID 1,
/// the scan returns summaries for IDs 0 and 2. `collect_affected_rules` then fetches
/// External signer data for BOTH and produces `affected_rules = [{rule_id: 0}, {rule_id: 2}]`.
///
/// # Mock sequence
///
/// `getLedgerEntries` → account entry (SOURCE_G) + dest-addr contract instance
///   (OZ_VERIFIER_HASH). This single response serves ALL getLedgerEntries calls:
///   - `fetch_observed_wasm_hash` (pre-flight 1, two-RPC consultation).
///   - `detect_contract_mutability` (pre-flight 3, two-RPC consultation).
///   - `fetch_account` inside `ContextRuleManager::simulate_read_only` (called
///     by `get_rules_count` + `get_rule` in `list_active_context_rules`).
///   - `fetch_observed_wasm_hash` for each External signer's verifier address.
///
/// `simulateTransaction` sequence:
///   1. `get_context_rules_count` → `ScVal::U32(2)`.
///   2. `get_rule(0)` → rule-0 ScVal (External signer, from `list_active_context_rules`).
///   3. `get_rule(1)` → error `"Error(Contract, #3000)"` (gap).
///   4. `get_rule(2)` → rule-2 ScVal (External signer, from `list_active_context_rules`).
///   5. `get_context_rule(0)` → rule-0 ScVal (from `fetch_external_signers_for_rule`).
///   6. `get_context_rule(2)` → rule-2 ScVal (from `fetch_external_signers_for_rule`).
///
/// # Assertions
///
/// - `plan.affected_rules.len() == 2` (not 1 as the pre-refactor iteration would produce).
/// - `plan.affected_rules[0].rule_id == 0`.
/// - `plan.affected_rules[1].rule_id == 2`.
/// - `plan.total_transaction_count() == 4` (1 External signer × 2 tx × 2 rules).
/// - `plan.rules_skipped_count == 1` (gap at ID 1 from list_active_context_rules).
///
/// # Implements
///
/// Active-rule enumeration: sparse-ID gap handling in `collect_affected_rules`.
#[tokio::test]
async fn t9_sparse_id_migration_planner() {
    let server = MockServer::start().await;

    let smart_account = addr(0x01);
    let dest_addr = addr(0xCD); // destination verifier — OZ_VERIFIER_HASH in getLedgerEntries

    // Key data for the External signers — 32 bytes.
    let key_data = [0xABu8; 32];

    // Both rules carry signer_id = 10 (External signer on each rule).
    let signer_ids = [10u32];
    let rule_0_xdr = build_context_rule_external_signers_xdr(0, &signer_ids, &dest_addr, &key_data);
    let rule_2_xdr = build_context_rule_external_signers_xdr(2, &signer_ids, &dest_addr, &key_data);

    // getLedgerEntries → account entry (for fetch_account in simulate_read_only)
    // + contract instance for dest_addr with OZ_VERIFIER_HASH.
    let ledger_resp =
        build_ledger_entries_account_and_contract(SOURCE_G, &dest_addr, OZ_VERIFIER_HASH);

    // simulateTransaction sequence:
    // [count=2, rule_0, notfound@1, rule_2, get_ctx_rule_0, get_ctx_rule_2]
    let not_found_resp = serde_json::json!({
        "error": "Error(Contract, #3000)",
        "latestLedger": 1000
    });
    let sim_responses = vec![
        build_simulate_response(&u32_xdr(2)), // get_context_rules_count → 2
        build_simulate_response(&rule_0_xdr), // get_rule(0) → rule-0 summary
        not_found_resp,                       // get_rule(1) → ContextRuleNotFound (gap)
        build_simulate_response(&rule_2_xdr), // get_rule(2) → rule-2 summary
        build_simulate_response(&rule_0_xdr), // get_context_rule(0) → External signer data
        build_simulate_response(&rule_2_xdr), // get_context_rule(2) → External signer data
    ];

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            ledger_resp,
            sim_responses,
        ))
        .mount(&server)
        .await;

    let (manager, _tmp_dir) = manager_with_server(&server).await;
    let planner = MigrationPlanner::new(&manager).with_max_scan_id(50);

    let request_id = Uuid::new_v4().to_string();
    // from_hash = OZ_VERIFIER_HASH: the External signers' verifier maps to this hash.
    let from_hash = OZ_VERIFIER_HASH;

    let plan = planner
        .build(smart_account, from_hash, dest_addr, &request_id)
        .await
        .expect(
            "MigrationPlanner::build must succeed: \
             OZ hash is Audited + Immutable + sparse-ID gap handled correctly",
        );

    // Core regression-lock: pre-refactor returned [{rule_id: 0}] only.
    // Post-refactor must return [{rule_id: 0}, {rule_id: 2}].
    assert_eq!(
        plan.affected_rules.len(),
        2,
        "affected_rules must contain both rules [0, 2]; \
         0..rule_count iteration would silently miss rule 2. \
         Got {} affected rules: {:?}",
        plan.affected_rules.len(),
        plan.affected_rules
            .iter()
            .map(|r| r.rule_id)
            .collect::<Vec<_>>()
    );

    assert_eq!(
        plan.affected_rules[0].rule_id, 0,
        "affected_rules[0].rule_id must be 0; got {}",
        plan.affected_rules[0].rule_id
    );
    assert_eq!(
        plan.affected_rules[1].rule_id, 2,
        "affected_rules[1].rule_id must be 2; got {}",
        plan.affected_rules[1].rule_id
    );

    // Each rule has 1 affected External signer → 2 tx each → 4 total.
    assert_eq!(
        plan.total_transaction_count(),
        4,
        "total_transaction_count must be 4 (2 rules × 1 signer × 2 tx); \
         got {}",
        plan.total_transaction_count()
    );

    // Gap at ID 1 → rules_skipped_count includes enumeration-phase skip.
    assert!(
        plan.rules_skipped_count >= 1,
        "rules_skipped_count must be >= 1 (gap at ID 1); got {}",
        plan.rules_skipped_count
    );
}
