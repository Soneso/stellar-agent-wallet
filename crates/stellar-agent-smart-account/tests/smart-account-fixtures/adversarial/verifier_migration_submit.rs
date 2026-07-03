//! Mock-substrate tests for the migration submit path.
//!
//! # Coverage map
//!
//! | Test | Mechanism | Coverage |
//! |------|-----------|----------|
//! | [`submit_returns_simulate_failure_on_first_step_when_rpc_simulate_errors`] | wiremock + `MigrationPlan::submit` | `VerifierMigrationFailed { phase: "submit_simulate" }` at `failed_step_index=0` |
//! | [`submit_send_failure_error_shape`] | wiremock + `MigrationPlan::submit` | `VerifierMigrationFailed { phase: "submit_send" }` wire code + display |
//! | [`submit_partial_failure_result_shape`] | wiremock + `MigrationPlan::submit` | partial failure when step 1 fails after step 0 succeeds |
//!
//! All tests invoke [`MigrationPlan::submit`] against a wiremock-backed
//! [`SignersManager`]. The send-failure and partial-failure tests use the
//! `test-helpers` submit shim to force deterministic send-phase outcomes
//! without constructing live Soroban auth entries by hand.
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
//! Verifier diversification acceptance criteria for the migration submit path.

use stellar_agent_network::SoftwareSigningKey;
use stellar_agent_smart_account::managers::migration::{
    MigrationPlan, RuleMigration, SignerMigrationStep,
};
use stellar_agent_smart_account::managers::signers::SignersManager;
use stellar_agent_smart_account::verifier_allowlist::VerifierAuditStatus;
use stellar_xdr::{ContractId, Hash, HostFunction, InvokeContractArgs, ScAddress, ScSymbol, VecM};
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::rpc_mock_helpers::{
    SorobanRpcDispatcher, build_ledger_entries_account, manager_two_url, tmp_audit_writer,
};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// OZ WebAuthn verifier v0.7.1 wasm hash — the only `VERIFIER_ALLOWLIST` entry.
///
/// `vendor/oz-webauthn-verifier/v0.7.1/PROVENANCE.md` SHA-256 anchor.
/// OZ source SHA: `3f81125bed3114cc93f5fca6d13240082050269a` (tag v0.7.1).
const OZ_VERIFIER_HASH: [u8; 32] = [
    0x67, 0x80, 0x06, 0x90, 0x9b, 0x50, 0xc6, 0xc3, 0x65, 0xc0, 0x33, 0xf1, 0x37, 0x19, 0x7e, 0x91,
    0x0d, 0x83, 0x96, 0xa2, 0xc6, 0x8e, 0x92, 0x81, 0x32, 0x7a, 0x2e, 0xd7, 0xdb, 0xf4, 0xb2, 0x7a,
];

/// Fixed ed25519 seed for the mock signer.
///
/// A deterministic seed so the G-strkey is reproducible; never used on any
/// live network.  Secret material stays in-process for the test only.
const MOCK_SIGNER_SEED: [u8; 32] = [
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
];

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A contract address with the given byte fill.
fn addr(byte: u8) -> ScAddress {
    ScAddress::Contract(ContractId(Hash([byte; 32])))
}

/// Builds a minimal but syntactically-valid `HostFunction::InvokeContract` for the
/// given entrypoint name.
///
/// The args are empty; only the function name and contract address matter for
/// the `extract_invoke_args` decode step inside `MigrationPlan::submit`.
///
/// # Byte-layout citation
///
/// `stellar_xdr::InvokeContractArgs` is the XDR-wire struct under
/// `HostFunction::InvokeContract`; no byte-layout citation needed (standard
/// XDR discriminant + struct encoding).
fn dummy_host_function(contract: &ScAddress, name: &str) -> HostFunction {
    HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: contract.clone(),
        function_name: ScSymbol::try_from(name).unwrap(),
        args: VecM::default(),
    })
}

/// Builds a `SignersManager` backed by the given wiremock server.
///
/// Both primary and secondary RPC URLs point at the same server. The `_tmp_dir`
/// returned by `tmp_audit_writer` must be held by the caller for the duration
/// of the test.
async fn manager_with_server(server: &MockServer) -> (SignersManager, tempfile::TempDir) {
    let (audit_writer, audit_log_path, tmp_dir) = tmp_audit_writer();
    let manager = manager_two_url(&server.uri(), &server.uri(), audit_writer, audit_log_path);
    (manager, tmp_dir)
}

/// Returns the G-strkey for the fixed `MOCK_SIGNER_SEED`.
///
/// `SoftwareSigningKey::public_key` is async, so we compute the G-strkey
/// directly via ed25519-dalek (both use the same seed → same key pair).
fn mock_signer_g() -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&MOCK_SIGNER_SEED);
    let verifying_key = signing_key.verifying_key();
    // `stellar_strkey` `Display` / `to_string` returns a `heapless::String<56>`,
    // not `std::string::String`.  Format through `{}` to get a heap-allocated copy.
    format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// simulate failure on first step — wiremock end-to-end
// ─────────────────────────────────────────────────────────────────────────────

/// `MigrationPlan::submit` returns `VerifierMigrationFailed { phase: "submit_simulate" }`
/// at `failed_step_index = Some(0)` when the mock RPC returns a simulate error.
///
/// # Mock sequence
///
/// 1. `getLedgerEntries` → account entry for the source G-key (so `fetch_account`
///    succeeds and the source-account sequence is available).
/// 2. `simulateTransaction` → `{"error": "mock-rpc-simulate-error", "latestLedger": 1000}`.
///    This causes `submit_signed_invoke` to return
///    `SaError::DeploymentFailed { phase: "simulate", ... }`, which
///    `submit_migration_step` re-maps to `VerifierMigrationFailed { phase: "submit_simulate" }`.
///
/// # Assertions
///
/// - `result.failed_step_index == Some(0)`.
/// - `result.successful_steps.is_empty()`.
/// - `result.total_steps_attempted == 1`.
/// - `result.failed_step_error` is `Some(SaError::VerifierMigrationFailed)` with
///   `phase == "submit_simulate"` in the Display string.
///
/// # Implements
///
/// Verifier diversification submit-simulate phase error path.
#[tokio::test]
async fn submit_returns_simulate_failure_on_first_step_when_rpc_simulate_errors() {
    let server = MockServer::start().await;

    let signer_g = mock_signer_g();

    // getLedgerEntries → valid account entry so fetch_account succeeds.
    let account_resp = build_ledger_entries_account(&signer_g);

    // simulateTransaction → error response.
    // `submit_signed_invoke` checks `sim_response.error.is_some()` and returns
    // `SaError::DeploymentFailed { phase: "simulate", ... }`.
    let simulate_resp = serde_json::json!({
        "error": "mock-rpc-simulate-error",
        "latestLedger": 1000
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(account_resp, simulate_resp))
        .mount(&server)
        .await;

    let (manager, _tmp_dir) = manager_with_server(&server).await;

    let smart_account = addr(0x01);

    // Build a plan with one affected rule containing one signer step.
    // The `remove_host_function` and `add_host_function` targets must be the
    // smart_account address (contract_address in InvokeContractArgs) so that
    // `extract_invoke_args` decodes them correctly.
    let step = SignerMigrationStep::new_for_test(
        10,
        "aabbccdd",
        dummy_host_function(&smart_account, "remove_signer"),
        dummy_host_function(&smart_account, "add_signer"),
    );
    let rule = RuleMigration::new_for_test(1, "aabbccdd", vec![step]);
    let plan = MigrationPlan::new_for_test(
        smart_account.clone(),
        [0x11u8; 32],
        OZ_VERIFIER_HASH,
        addr(0x02),
        vec![rule],
        VerifierAuditStatus::Audited {
            auditor: "OpenZeppelin",
            audited_at: "2025-11-01",
        },
        Uuid::new_v4().to_string(),
    );

    // Build a software signer from the fixed seed.
    use zeroize::Zeroizing;
    let seed = Zeroizing::new(MOCK_SIGNER_SEED);
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));

    let request_id = Uuid::new_v4().to_string();
    let result = plan.submit(signer.as_ref(), &manager, &request_id).await;

    // Assertion 1: failed at step 0.
    assert_eq!(
        result.failed_step_index,
        Some(0),
        "failed_step_index must be Some(0) when simulate fails on first step; got: {:?}",
        result.failed_step_index
    );

    // Assertion 2: no successful steps.
    assert!(
        result.successful_steps.is_empty(),
        "successful_steps must be empty when first step fails immediately; got: {:?}",
        result.successful_steps
    );

    // Assertion 3: total_steps_attempted == 1 (step 0 was attempted).
    assert_eq!(
        result.total_steps_attempted, 1,
        "total_steps_attempted must be 1 when first step fails; got {}",
        result.total_steps_attempted
    );

    // Assertion 4: the error is VerifierMigrationFailed with phase "submit_simulate".
    let err = result
        .failed_step_error
        .expect("failed_step_error must be Some when failed_step_index is Some");

    // Wire code must be "sa.verifier_migration_failed".
    assert_eq!(
        err.wire_code(),
        "sa.verifier_migration_failed",
        "wire_code must be 'sa.verifier_migration_failed'; got: {}",
        err.wire_code()
    );

    // Display must contain "submit_simulate".
    let msg = err.to_string();
    assert!(
        msg.contains("submit_simulate"),
        "Display must contain 'submit_simulate'; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// submit_send failure via MigrationPlan::submit
// ─────────────────────────────────────────────────────────────────────────────

/// `MigrationPlan::submit` returns `VerifierMigrationFailed { phase:
/// "submit_send" }` at `failed_step_index = Some(0)` when the send phase
/// fails on the first migration step.
///
/// # Implements
///
/// Verifier diversification submit-send phase error shape.
#[tokio::test]
async fn submit_send_failure_error_shape() {
    let server = MockServer::start().await;
    let signer_g = mock_signer_g();
    let account_resp = build_ledger_entries_account(&signer_g);
    let simulate_resp = serde_json::json!({
        "error": "mock-rpc-simulate-response-unused-by-test-helper",
        "latestLedger": 1000
    });
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(account_resp, simulate_resp))
        .mount(&server)
        .await;

    let (manager, _tmp_dir) = manager_with_server(&server).await;
    let smart_account = addr(0x01);
    let step = SignerMigrationStep::new_for_test(
        10,
        "aabbccdd",
        dummy_host_function(&smart_account, "remove_signer"),
        dummy_host_function(&smart_account, "add_signer"),
    );
    let rule = RuleMigration::new_for_test(1, "aabbccdd", vec![step]);
    let plan = MigrationPlan::new_for_test(
        smart_account,
        [0x11u8; 32],
        OZ_VERIFIER_HASH,
        addr(0x02),
        vec![rule],
        VerifierAuditStatus::Audited {
            auditor: "OpenZeppelin",
            audited_at: "2025-11-01",
        },
        Uuid::new_v4().to_string(),
    );
    use zeroize::Zeroizing;
    let seed = Zeroizing::new(MOCK_SIGNER_SEED);
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));

    let request_id = format!("mock-submit-send-failure-{}", Uuid::new_v4());
    let result = plan.submit(signer.as_ref(), &manager, &request_id).await;

    assert_eq!(result.failed_step_index, Some(0));
    assert!(result.successful_steps.is_empty());
    assert_eq!(result.total_steps_attempted, 1);
    let err = result
        .failed_step_error
        .expect("failed_step_error must be set");

    // Wire code must be "sa.verifier_migration_failed".
    assert_eq!(
        err.wire_code(),
        "sa.verifier_migration_failed",
        "wire_code must be 'sa.verifier_migration_failed'"
    );

    // Display must contain the phase.
    let msg = err.to_string();
    assert!(
        msg.contains("submit_send"),
        "Display must contain 'submit_send'; got: {msg}"
    );

    // Display must NOT contain "submit_simulate" (distinct phase).
    assert!(
        !msg.contains("submit_simulate"),
        "Display must NOT contain 'submit_simulate' for submit_send phase; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// partial failure via MigrationPlan::submit
// ─────────────────────────────────────────────────────────────────────────────

/// `MigrationPlan::submit` records one successful signer step and returns
/// `failed_step_index = Some(1)` when the second signer step fails.
///
/// # Partial-failure idempotency note
///
/// The partial-failure design allows re-running `MigrationPlanner::build` +
/// `submit` to resume from the last failed step: already-migrated signers
/// no longer match `from_hash`, so the planner emits a reduced plan covering
/// only the remaining affected signers.
///
/// # Implements
///
/// Verifier diversification partial-failure semantics for the submit path.
#[tokio::test]
async fn submit_partial_failure_result_shape() {
    let server = MockServer::start().await;
    let signer_g = mock_signer_g();
    let account_resp = build_ledger_entries_account(&signer_g);
    let simulate_resp = serde_json::json!({
        "error": "mock-rpc-simulate-response-unused-by-test-helper",
        "latestLedger": 1000
    });
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(account_resp, simulate_resp))
        .mount(&server)
        .await;

    let (manager, _tmp_dir) = manager_with_server(&server).await;
    let smart_account = addr(0x01);
    let step_0 = SignerMigrationStep::new_for_test(
        10,
        "aabbccdd",
        dummy_host_function(&smart_account, "remove_signer"),
        dummy_host_function(&smart_account, "add_signer"),
    );
    let step_1 = SignerMigrationStep::new_for_test(
        11,
        "aabbccdd",
        dummy_host_function(&smart_account, "remove_signer"),
        dummy_host_function(&smart_account, "add_signer"),
    );
    let rule = RuleMigration::new_for_test(1, "aabbccdd", vec![step_0, step_1]);
    let plan = MigrationPlan::new_for_test(
        smart_account,
        [0x11u8; 32],
        OZ_VERIFIER_HASH,
        addr(0x02),
        vec![rule],
        VerifierAuditStatus::Audited {
            auditor: "OpenZeppelin",
            audited_at: "2025-11-01",
        },
        Uuid::new_v4().to_string(),
    );
    use zeroize::Zeroizing;
    let seed = Zeroizing::new(MOCK_SIGNER_SEED);
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));

    let request_id = format!("mock-partial-submit-send-failure-{}", Uuid::new_v4());
    let result = plan.submit(signer.as_ref(), &manager, &request_id).await;

    // Assertion 1: failed_step_index == Some(1).
    assert_eq!(
        result.failed_step_index,
        Some(1),
        "failed_step_index must be Some(1)"
    );

    // Assertion 2: successful_steps.len() == 1 (step 0 succeeded).
    assert_eq!(
        result.successful_steps.len(),
        1,
        "successful_steps must have 1 entry (step 0 succeeded before failure at step 1)"
    );

    // Assertion 3: step 0 fields are accessible.
    let step = &result.successful_steps[0];
    assert_eq!(step.rule_id, 1, "step.rule_id must be 1");
    assert_eq!(step.signer_id, 10, "step.signer_id must be 10");
    assert_eq!(
        step.remove_tx_hash.len(),
        64,
        "step.remove_tx_hash must be a mock 64-char tx hash"
    );
    assert_eq!(
        step.add_tx_hash.len(),
        64,
        "step.add_tx_hash must be a mock 64-char tx hash"
    );

    // Assertion 4: failed_step_error carries the expected phase.
    let err = result
        .failed_step_error
        .expect("failed_step_error must be Some");
    let msg = err.to_string();
    assert!(
        msg.contains("submit_send"),
        "failed_step_error Display must contain 'submit_send'; got: {msg}"
    );

    // Assertion 5: total_steps_attempted == 2 (step 0 + step 1 both attempted).
    assert_eq!(
        result.total_steps_attempted, 2,
        "total_steps_attempted must be 2 (step 0 ok, step 1 failed)"
    );
    assert_eq!(
        result.failed_step_remove_tx_hash.as_deref(),
        None,
        "failed step remove hash is None because the second step fails before remove confirmation"
    );

    // Assertion 6: partial-failure invariant — successful_steps.len() == failed_step_index.
    //
    // This is the canonical postcondition of `MigrationPlan::submit`:
    // all steps prior to failure are in successful_steps.
    assert_eq!(
        result.successful_steps.len(),
        result.failed_step_index.unwrap(),
        "successful_steps.len() must equal failed_step_index for a \
         well-formed partial-failure result"
    );
}
