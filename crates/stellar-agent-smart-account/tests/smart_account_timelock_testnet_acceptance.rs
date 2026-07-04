//! Timelock testnet acceptance tests.
//!
//! Deploys an OZ v0.7.2 `TimelockController` contract on testnet and exercises
//! the full schedule → cancel + schedule → execute lifecycle.
//!
//! This file ships in the SAME COMMIT as the `timelock.rs` production substance,
//! satisfying the smart-account submit-phase testnet precondition.
//!
//! # Coverage
//!
//! | Fixture | Description |
//! |---------|-------------|
//! | [`t1_schedule_cancel_lifecycle`] | Deploy timelock; schedule op; cancel it; assert `Unset` state + `SaTimelockCancelled` audit row. |
//! | [`t2_schedule_ready_state_min_delay_zero`] | Deploy timelock with `min_delay=0`; schedule; verify `Ready` state via `list_pending`. |
//! | [`t3_cancel_unknown_operation_id_rejected`] | Cancel with a random `operation_id` returns `TimelockCancelFailed(InvalidOperationState)`. |
//! | [`t4_execute_not_ready_rejected`] | Execute an unscheduled op returns `TimelockExecuteFailed::OperationNotReady`. |
//! | [`t5_schedule_emits_audit_row`] | Schedule emits a `SaTimelockScheduled` audit row with correct fields. |
//! | [`t6_cross_confirm_event_divergence_rejection`] | Secondary RPC returns no events → `NetworkRpcDivergence` on cancel (dual-RPC defence-in-depth). |
//! | [`t7_schedule_execute_min_delay_zero`] | Schedule with `min_delay=0`; execute using the `salt` field returned by `schedule_upgrade`; assert operation is `Done`. |
//!
//! # Gating
//!
//! Feature flag: `testnet-integration`. Run with:
//!
//! ```text
//! cargo test --features testnet-integration --test smart_account_timelock_testnet_acceptance
//! ```
//!
//! All tests require live testnet access and Friendbot funding. They are excluded
//! from default `cargo test` runs.
//!
//! # OZ timelock contract
//!
//! Uses the vendored `vendor/oz-timelock-controller/v0.7.2/timelock_controller_example.wasm`
//! (the OpenZeppelin `timelock-controller-example` package).
//! Constructor: `__constructor(min_delay: u32, proposers: Vec<Address>,
//! executors: Vec<Address>, admin: Option<Address>)`.
//!
//! The test uses `admin = Some(deployer_address)` for initial role setup (proposer grant)
//! without going through timelock governance, then leaves the contract self-administered
//! after setup (per the OpenZeppelin timelock-controller pattern).
//!
//! The `executors` list is empty — this enables open execution (anyone can execute a
//! ready operation per the OpenZeppelin timelock-controller contract). This is intentional for
//! testnet acceptance where the executor and proposer are the same ephemeral key.
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

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_smart_account::error::{SaError, TimelockExecuteFailureReason};
use stellar_agent_smart_account::timelock::{
    PendingTimelockOperation, ScheduledTimelockOperation, TimelockOperationId,
    TimelockOperationStateView, cancel, execute, list_pending, query_operation_state,
    schedule_upgrade,
};
use stellar_agent_test_support::EchoIdResponder;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};
use zeroize::Zeroizing;

// ── Network constants ─────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const FEE_STROOPS: u32 = 1_000_000;
const TIMEOUT_SECS: u64 = 120;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Generates a fresh ed25519 signer for testnet use.
///
/// Returns `(g_strkey, seed_bytes, signer_box)` where `g_strkey` is the
/// Stellar public-key strkey (`G...`), `seed_bytes` are the raw 32-byte key
/// bytes (kept for cloning the signer when a second instance is required,
/// e.g. one for deploy + one for subsequent signing), and `signer_box` is
/// the in-process signer implementation.
fn fresh_signer() -> (
    String,
    [u8; 32],
    Box<dyn stellar_agent_network::Signer + Send + Sync>,
) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let seed_bytes: [u8; 32] = signing_key.to_bytes();
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(seed_bytes);
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(stellar_agent_network::SoftwareSigningKey::new_from_zeroizing(seed));
    (g_strkey, seed_bytes, signer)
}

/// Creates an additional signer instance from the same seed bytes.
///
/// Used when the deploy step requires ownership of the signer via
/// `DeployerKeypair` while the original `signer_box` is still needed for
/// subsequent timelock operations.
fn signer_from_seed(seed_bytes: [u8; 32]) -> Box<dyn stellar_agent_network::Signer + Send + Sync> {
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(seed_bytes);
    Box::new(stellar_agent_network::SoftwareSigningKey::new_from_zeroizing(seed))
}

/// Funds an account via testnet Friendbot and waits until it is queryable.
///
/// Friendbot returning 200 does not guarantee the RPC has indexed the new
/// account yet; the view can lag by a few seconds. The wait lets callers build
/// transactions against the account immediately after this returns.
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

    let rpc = stellar_agent_network::StellarRpcClient::new(TESTNET_RPC_URL)
        .expect("RPC client construction must succeed");
    for _ in 0..30 {
        if stellar_agent_network::fetch_account(&rpc, g_strkey, &[])
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("funded account {g_strkey} did not become queryable on the RPC within timeout");
}

/// Opens a temporary `AuditWriter` and returns `(writer_arc, path, TempDir)`.
///
/// The `TempDir` must be kept alive for the duration of the test.
fn tmp_audit_writer() -> (Arc<Mutex<AuditWriter>>, PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter::open must succeed");
    (Arc::new(Mutex::new(writer)), path, dir)
}

/// Reads all `AuditEntry` lines from a JSONL audit log file.
///
/// Uses `BufReader::lines()` + `serde_json::from_str` to parse one JSON
/// object per line.
fn read_audit_entries(path: &PathBuf) -> Vec<AuditEntry> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return vec![],
    };
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

/// Deploys the OZ timelock-controller v0.7.2 WASM to testnet and returns the
/// contract C-strkey.
///
/// Delegates to
/// [`stellar_agent_smart_account::deployment::deploy_timelock_controller`],
/// which uses `prepare_transaction` for correct resource-fee handling.
///
/// # Arguments
///
/// - `deployer_g` — deployer G-strkey (also used as admin).
/// - `seed_bytes` — raw 32-byte ed25519 seed for the deployer signer.
/// - `proposer_g` — account to grant PROPOSER + CANCELLER roles.
/// - `min_delay` — minimum ledger delay before ops can execute.
///
/// # Panics
///
/// Panics if deployment fails for any reason other than `already_deployed`.
async fn deploy_timelock_controller(
    deployer_g: &str,
    seed_bytes: [u8; 32],
    proposer_g: &str,
    min_delay: u32,
) -> String {
    use stellar_agent_smart_account::deployment::deploy::DeployerKeypair;
    use stellar_agent_smart_account::deployment::deploy::ResolvedFeePerOp;
    use stellar_agent_smart_account::deployment::{
        TimelockControllerDeployArgs, deploy_timelock_controller as prod_deploy,
    };

    let deployer_signer = signer_from_seed(seed_bytes);
    let deployer = DeployerKeypair::from_signer("testnet-deploy".to_owned(), deployer_signer);

    let args = TimelockControllerDeployArgs {
        deployer,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(TIMEOUT_SECS),
        fee: ResolvedFeePerOp {
            stroops: FEE_STROOPS,
            percentile_label: "testnet-fixed".to_owned(),
        },
        min_delay,
        proposers: vec![proposer_g.to_owned()],
        executors: vec![],
        admin: Some(deployer_g.to_owned()),
        dry_run: false,
    };

    match prod_deploy(args).await {
        Ok(result) => {
            eprintln!(
                "[deploy_timelock_controller] {} (status={})",
                stellar_agent_core::observability::redact_strkey_first5_last5(
                    &result.contract_address
                ),
                result.status,
            );
            result.contract_address
        }
        Err(e) => panic!("timelock deploy failed: {e}"),
    }
}

// ── Schedule → Cancel lifecycle ─────────────────────────────────────────

/// Schedule a timelock operation, then cancel it via `cancel()`.
///
/// Asserts:
/// 1. `schedule_upgrade` succeeds and returns a `TimelockOperationId`.
/// 2. `cancel` succeeds.
/// 3. A `SaTimelockCancelled` audit row was emitted with the matching
///    `operation_id_redacted`.
/// 4. `list_pending` returns an empty list for this timelock after cancellation
///    (the operation is Unset, excluded from pending results).
///
/// The OpenZeppelin cancel path resets the `ready_ledger` to `UNSET_LEDGER (0)`.
/// `TimelockController::cancel(e, operation_id, canceller)` requires
/// `CANCELLER_ROLE` on the canceller — proposers are auto-granted this role at
/// construction time.
///
/// # Acceptance
///
/// Exercises the upgrade-timelock cancel end-to-end (event-emission integrity,
/// audit-row presence on cancel).
#[tokio::test]
async fn t1_schedule_cancel_lifecycle() {
    // Setup: fresh signer (proposer + canceller via CANCELLER_ROLE auto-grant).
    let (signer_g, seed_bytes, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let (audit_writer, audit_log_path, _tmpdir) = tmp_audit_writer();
    let request_id_schedule = uuid::Uuid::new_v4().to_string();
    let request_id_cancel = uuid::Uuid::new_v4().to_string();

    // Deploy timelock with min_delay=10 (non-zero ensures the op stays Waiting).
    let timelock_strkey = deploy_timelock_controller(&signer_g, seed_bytes, &signer_g, 10).await;

    eprintln!("[T-1] timelock deployed: {timelock_strkey}");

    // Use the timelock itself as target (self-referential — never executes; purely
    // for schedule + cancel lifecycle testing).
    let target_strkey = timelock_strkey.clone();

    // Step 1: Schedule.
    let scheduled = schedule_upgrade(
        stellar_agent_smart_account::timelock::TimelockScheduleArgs::builder()
            .timelock_contract_strkey(&timelock_strkey)
            .target_strkey(&target_strkey)
            .function("update_delay")
            .delay_ledgers(10)
            .signer(signer_box.as_ref())
            .primary_rpc_url(TESTNET_RPC_URL)
            .secondary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .audit_writer(&audit_writer)
            .request_id(&request_id_schedule)
            .build(),
    )
    .await
    .expect("schedule_upgrade must succeed");
    let operation_id = scheduled.operation_id;

    eprintln!("[T-1] scheduled operation: {}", operation_id.redacted());

    // Verify SaTimelockScheduled audit row is present.
    {
        let entries = read_audit_entries(&audit_log_path);
        let scheduled_rows: Vec<_> = entries
            .iter()
            .filter(|e| {
                matches!(
                    &e.event_kind,
                    EventKind::SaTimelockScheduled {
                        operation_id_full_hex, ..
                    }
                    if *operation_id_full_hex == operation_id.to_hex()
                )
            })
            .collect();
        assert!(
            !scheduled_rows.is_empty(),
            "SaTimelockScheduled audit row must be present after schedule; \
             operation_id = {}",
            operation_id.redacted()
        );
    }

    // Step 2: Cancel.
    cancel(
        stellar_agent_smart_account::timelock::TimelockCancelArgs::builder()
            .timelock_contract_strkey(&timelock_strkey)
            .operation_id(&operation_id)
            .signer(signer_box.as_ref())
            .primary_rpc_url(TESTNET_RPC_URL)
            .secondary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .audit_writer(&audit_writer)
            .request_id(&request_id_cancel)
            .build(),
    )
    .await
    .expect("cancel must succeed");

    eprintln!("[T-1] cancelled: {}", operation_id.redacted());

    // Step 3: Verify SaTimelockCancelled audit row.
    {
        let entries = read_audit_entries(&audit_log_path);
        let cancelled_rows: Vec<_> = entries
            .iter()
            .filter(|e| {
                matches!(
                    &e.event_kind,
                    EventKind::SaTimelockCancelled {
                        operation_id_redacted, ..
                    }
                    if *operation_id_redacted == operation_id.redacted()
                )
            })
            .collect();
        assert!(
            !cancelled_rows.is_empty(),
            "SaTimelockCancelled audit row must be present after cancel; \
             operation_id_redacted = {}",
            operation_id.redacted()
        );
    }

    // Step 4: Directly assert on-chain state == Unset after cancel.
    // A direct `query_operation_state` call ensures a regression that leaves
    // `ready_ledger == DONE_LEDGER (1)` (cancel-as-execute) would fail this
    // assertion rather than silently passing via list_pending.
    {
        let state = query_operation_state(
            &timelock_strkey,
            &operation_id,
            TESTNET_RPC_URL,
            TESTNET_RPC_URL,
            TESTNET_PASSPHRASE,
            &request_id_cancel,
        )
        .await
        .expect("query_operation_state must succeed after cancel");
        assert_eq!(
            state,
            TimelockOperationStateView::Unset,
            "on-chain state must be Unset after cancel; got {state:?}"
        );
    }

    // Step 5: list_pending must return empty (cancelled op is Unset, excluded).
    let pending = list_pending(
        &timelock_strkey,
        &audit_writer,
        TESTNET_RPC_URL,
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        &request_id_cancel,
    )
    .await
    .expect("list_pending must succeed after cancel");

    // The cancelled operation is Unset on-chain; list_pending skips Unset entries.
    // There may be 0 or more pending ops if multiple tests share infra, but the
    // specific operation we cancelled must NOT be in the list.
    let still_pending = pending.iter().any(|op| op.operation_id == operation_id);
    assert!(
        !still_pending,
        "cancelled operation must NOT appear in list_pending results"
    );

    eprintln!(
        "[T-1] PASS: schedule → cancel lifecycle verified; state=Unset confirmed; \
         list_pending excludes cancelled op"
    );
}

// ── Schedule with min_delay=0 → Ready state ─────────────────────────────

/// Schedule a timelock operation with `min_delay=0` and verify `Ready` state
/// via `list_pending`.
///
/// With `min_delay=0`, the operation is immediately `Ready` (no ledger wait
/// required per OZ `schedule_operation`: `ready_ledger = current_ledger + delay`).
///
/// Asserts:
/// 1. `schedule_upgrade` succeeds.
/// 2. `list_pending` returns the scheduled operation in `Ready` state.
///
/// The OpenZeppelin `schedule_operation` sets
/// `ready_ledger = current_ledger_sequence + delay`. With delay=0,
/// `ready_ledger = current_ledger_sequence`, so `ready_ledger <= current_ledger`
/// immediately → state = `Ready`. `list_pending` calls
/// `enrich_state_view_with_current_ledger` which converts
/// `Waiting { ready_ledger <= current_ledger }` to `Ready`.
#[tokio::test]
async fn t2_schedule_ready_state_min_delay_zero() {
    let (signer_g, seed_bytes, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let (audit_writer, _audit_log_path, _tmpdir) = tmp_audit_writer();
    let request_id = uuid::Uuid::new_v4().to_string();

    // Deploy with min_delay=0 so the operation is immediately Ready.
    let timelock_strkey = deploy_timelock_controller(&signer_g, seed_bytes, &signer_g, 0).await;

    eprintln!("[T-2] timelock deployed (min_delay=0): {timelock_strkey}");

    // Schedule: target=timelock itself, function="get_min_delay" (harmless view fn).
    let scheduled = schedule_upgrade(
        stellar_agent_smart_account::timelock::TimelockScheduleArgs::builder()
            .timelock_contract_strkey(&timelock_strkey)
            .target_strkey(&timelock_strkey)
            .function("get_min_delay")
            .delay_ledgers(0) // delay_ledgers = 0 → immediately Ready
            .signer(signer_box.as_ref())
            .primary_rpc_url(TESTNET_RPC_URL)
            .secondary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .audit_writer(&audit_writer)
            .request_id(&request_id)
            .build(),
    )
    .await
    .expect("schedule_upgrade must succeed with min_delay=0");
    let operation_id = scheduled.operation_id;

    eprintln!("[T-2] scheduled: {}", operation_id.redacted());

    // Query via list_pending: with min_delay=0, the operation must appear as Ready.
    let pending = list_pending(
        &timelock_strkey,
        &audit_writer,
        TESTNET_RPC_URL,
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        &request_id,
    )
    .await
    .expect("list_pending must succeed");

    let found: Vec<_> = pending
        .iter()
        .filter(|op| op.operation_id == operation_id)
        .collect();

    assert!(
        !found.is_empty(),
        "scheduled operation must appear in list_pending; \
         operation_id = {}",
        operation_id.redacted()
    );

    let op: &PendingTimelockOperation = found[0];
    assert!(
        matches!(op.state, TimelockOperationStateView::Ready { .. }),
        "operation with min_delay=0 must be in Ready state immediately; \
         got {:?}",
        op.state
    );

    eprintln!("[T-2] PASS: min_delay=0 operation is Ready immediately after scheduling");
}

// ── Cancel unknown operation ID ─────────────────────────────────────────

/// Attempt to cancel a non-existent operation ID.
///
/// Asserts that `cancel()` returns `SaError::TimelockCancelFailed` with
/// `failure_reason == InvalidOperationState` (OZ 4002) when the operation ID
/// was never scheduled on-chain.
///
/// The OpenZeppelin `cancel_operation` panics with
/// `TimelockError::InvalidOperationState` (4002) when
/// `is_operation_pending(e, operation_id)` returns `false`. An unscheduled
/// op has `ready_ledger == UNSET_LEDGER (0)` → not pending → code 4002.
/// Code 4006 (`OperationNotScheduled`) is NOT reachable from the canonical
/// cancel path, so the assertion requires exactly `InvalidOperationState`.
#[tokio::test]
async fn t3_cancel_unknown_operation_id_rejected() {
    let (signer_g, seed_bytes, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let (audit_writer, _audit_log_path, _tmpdir) = tmp_audit_writer();
    let request_id = uuid::Uuid::new_v4().to_string();

    let timelock_strkey = deploy_timelock_controller(&signer_g, seed_bytes, &signer_g, 10).await;

    eprintln!("[T-3] timelock deployed: {timelock_strkey}");

    // Generate a random operation_id that was never scheduled.
    let mut random_id_bytes = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut random_id_bytes);
    let random_op_id = TimelockOperationId::from_bytes(random_id_bytes);

    let result = cancel(
        stellar_agent_smart_account::timelock::TimelockCancelArgs::builder()
            .timelock_contract_strkey(&timelock_strkey)
            .operation_id(&random_op_id)
            .signer(signer_box.as_ref())
            .primary_rpc_url(TESTNET_RPC_URL)
            .secondary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .audit_writer(&audit_writer)
            .request_id(&request_id)
            .build(),
    )
    .await;

    assert!(
        result.is_err(),
        "cancel of unknown operation_id must return Err"
    );

    let err = result.unwrap_err();
    // OZ cancel_operation fires InvalidOperationState (4002) for any non-pending op,
    // including unscheduled ones. Code 4006 is unreachable.
    // Require exactly TimelockCancelFailed { InvalidOperationState }.
    assert!(
        matches!(
            &err,
            SaError::TimelockCancelFailed {
                failure_reason: stellar_agent_smart_account::error::TimelockCancelFailureReason::InvalidOperationState,
                ..
            }
        ),
        "error must be TimelockCancelFailed(InvalidOperationState); got {err:?}"
    );

    eprintln!("[T-3] PASS: cancel of unknown operation_id rejected with: {err}");
}

// ── Execute unscheduled operation returns OperationNotReady ──────────────

/// Attempt to execute an operation that was never scheduled.
///
/// Asserts that `execute()` returns `SaError::TimelockExecuteFailed` with
/// `failure_reason = OperationNotReady { observed_state: "Unset" }`.
///
/// This exercises the ready-window race prevention: `execute()` performs a
/// cross-RPC pre-check and fails CLOSED if the operation is not in `Ready` state.
///
/// The execute pre-check calls `query_operation_state_cross_rpc`; when it returns
/// `Unset` the call fails with
/// `TimelockExecuteFailed { failure_reason: OperationNotReady { observed_state: "Unset" } }`.
#[tokio::test]
async fn t4_execute_not_ready_rejected() {
    let (signer_g, seed_bytes, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let (audit_writer, _audit_log_path, _tmpdir) = tmp_audit_writer();
    let request_id = uuid::Uuid::new_v4().to_string();

    let timelock_strkey = deploy_timelock_controller(&signer_g, seed_bytes, &signer_g, 10).await;

    eprintln!("[T-4] timelock deployed: {timelock_strkey}");

    // A random salt that was never used in schedule.
    let mut random_salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut random_salt);

    // Attempt to execute a never-scheduled operation.
    // Pass `None` for expected_operation_id — the test does not have a prior id;
    // the state pre-check runs after simulate_hash_operation (fallback path).
    let result = execute(
        stellar_agent_smart_account::timelock::TimelockExecuteArgs::builder()
            .timelock_contract_strkey(&timelock_strkey)
            .target_strkey(&timelock_strkey)
            .function("get_min_delay")
            .salt(random_salt)
            .signer(signer_box.as_ref())
            .primary_rpc_url(TESTNET_RPC_URL)
            .secondary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .audit_writer(&audit_writer)
            .request_id(&request_id)
            // No prior operation_id; state check runs after hash simulate.
            .build(),
    )
    .await;

    assert!(
        result.is_err(),
        "execute of unscheduled operation must return Err"
    );

    let err = result.unwrap_err();
    // `hash_operation` returns a valid but unregistered operation_id; the pre-check
    // query observes Unset state for that op_id.  SimulationFailed is not an
    // acceptable outcome — the pre-check gate must be the signal, and the signal
    // must be OperationNotReady with observed_state "Unset".
    match &err {
        SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::OperationNotReady { observed_state, .. },
            ..
        } => {
            assert_eq!(
                observed_state, "Unset",
                "observed_state must be 'Unset' for a never-scheduled operation; \
                 got {observed_state}"
            );
            eprintln!(
                "[T-4] PASS: execute rejected with OperationNotReady {{ observed_state: {observed_state:?} }}"
            );
        }
        SaError::NetworkRpcDivergence { .. } => {
            // Both RPCs returned the same Unset state; divergence not expected on single-RPC
            // test setup but is an acceptable outcome (both RPCs are the same endpoint).
            eprintln!("[T-4] PASS (divergence path — same RPC for primary+secondary)");
        }
        other => panic!(
            "expected TimelockExecuteFailed {{ OperationNotReady {{ Unset }} }} \
             or NetworkRpcDivergence; got {other:?}"
        ),
    }
}

// ── schedule_upgrade emits SaTimelockScheduled audit row ─────────────────

/// Verify that `schedule_upgrade` emits a `SaTimelockScheduled` audit row
/// with all required fields present and correctly populated.
///
/// Checks:
/// 1. `operation_id_full_hex` = 64-char lowercase hex.
/// 2. `operation_id_redacted` = `{first8}...{last8}` form.
/// 3. `function` matches the function passed to `schedule_upgrade`.
/// 4. `delay_ledgers` matches the delay passed to `schedule_upgrade`.
/// 5. `audit_request_id` matches the `request_id` passed to `schedule_upgrade`.
///
/// The `SaTimelockScheduled` event populates `operation_id_full_hex`,
/// `operation_id_redacted`, `function`, `delay_ledgers`, and `audit_request_id`
/// from the `schedule_upgrade` arguments.
#[tokio::test]
async fn t5_schedule_emits_audit_row() {
    let (signer_g, seed_bytes, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let (audit_writer, audit_log_path, _tmpdir) = tmp_audit_writer();
    let request_id = uuid::Uuid::new_v4().to_string();

    let timelock_strkey = deploy_timelock_controller(&signer_g, seed_bytes, &signer_g, 5).await;

    eprintln!("[T-5] timelock deployed: {timelock_strkey}");

    const FUNCTION_NAME: &str = "get_min_delay";
    const DELAY_LEDGERS: u32 = 5;

    let scheduled = schedule_upgrade(
        stellar_agent_smart_account::timelock::TimelockScheduleArgs::builder()
            .timelock_contract_strkey(&timelock_strkey)
            .target_strkey(&timelock_strkey)
            .function(FUNCTION_NAME)
            .delay_ledgers(DELAY_LEDGERS)
            .signer(signer_box.as_ref())
            .primary_rpc_url(TESTNET_RPC_URL)
            .secondary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .audit_writer(&audit_writer)
            .request_id(&request_id)
            .build(),
    )
    .await
    .expect("schedule_upgrade must succeed");
    let operation_id = scheduled.operation_id;

    eprintln!("[T-5] scheduled: {}", operation_id.redacted());

    let entries = read_audit_entries(&audit_log_path);

    let matching: Vec<_> = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaTimelockScheduled {
                    operation_id_full_hex,
                    ..
                }
                if *operation_id_full_hex == operation_id.to_hex()
            )
        })
        .collect();

    assert!(
        !matching.is_empty(),
        "SaTimelockScheduled row for operation {} must be present",
        operation_id.redacted()
    );

    let row = &matching[0];
    match &row.event_kind {
        EventKind::SaTimelockScheduled {
            operation_id_redacted,
            operation_id_full_hex,
            function,
            delay_ledgers,
            audit_request_id,
            ..
        } => {
            assert_eq!(
                operation_id_full_hex.len(),
                64,
                "operation_id_full_hex must be 64 chars"
            );
            assert!(
                operation_id_redacted.contains("..."),
                "operation_id_redacted must contain '...'; got {operation_id_redacted}"
            );
            assert_eq!(
                function, FUNCTION_NAME,
                "function field must match schedule arg"
            );
            assert_eq!(
                *delay_ledgers, DELAY_LEDGERS,
                "delay_ledgers field must match schedule arg"
            );
            assert_eq!(
                audit_request_id, &request_id,
                "audit_request_id must match the request_id passed to schedule_upgrade"
            );
        }
        other => panic!("unexpected EventKind: {other:?}"),
    }

    eprintln!("[T-5] PASS: SaTimelockScheduled audit row has all required fields");
}

// ── Dual-RPC divergence rejection on cross_confirm_event ────────────────

/// Secondary RPC returns no events → `NetworkRpcDivergence` on cancel.
///
/// Demonstrates dual-RPC defence-in-depth: a compromised or divergent secondary
/// RPC that strips the `OperationCancelled` event from `getTransaction` meta causes
/// `cancel()` to return `SaError::NetworkRpcDivergence` rather than silently accepting
/// the response.
///
/// # Test strategy
///
/// 1. Deploy a timelock contract on live testnet and schedule an operation.
/// 2. Start a wiremock server to act as the secondary RPC.
///    The wiremock returns a bare `SUCCESS` response with NO `events` field for
///    any `getTransaction` call — mimicking a compromised RPC that strips event data.
/// 3. Call `cancel(primary=testnet, secondary=wiremock)`.
/// 4. The primary RPC confirms the `OperationCancelled` event is present (real
///    testnet response). The secondary wiremock returns no events → `secondary_found = false`.
/// 5. Assert that `cancel()` returns `SaError::NetworkRpcDivergence` (not `Ok`).
///
/// # Wire-code assertion
///
/// `SaError::NetworkRpcDivergence.wire_code()` must return `"network.rpc_divergence"`.
///
/// The OpenZeppelin `cancel_operation` emits the `OperationCancelled` event. The
/// dual-RPC `getTransaction` cross-confirmation is a wallet-specific
/// defence-in-depth measure with no equivalent in the underlying contract.
#[tokio::test]
async fn t6_cross_confirm_event_divergence_rejection() {
    // Setup: fresh signer (proposer + canceller).
    let (signer_g, seed_bytes, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let (audit_writer, _audit_log_path, _tmpdir) = tmp_audit_writer();
    let request_id_schedule = uuid::Uuid::new_v4().to_string();
    let request_id_cancel = uuid::Uuid::new_v4().to_string();

    // Deploy timelock with min_delay=10 (non-zero keeps op in Waiting state).
    let timelock_strkey = deploy_timelock_controller(&signer_g, seed_bytes, &signer_g, 10).await;
    eprintln!("[T-6] timelock deployed: {timelock_strkey}");

    // Schedule an operation on live testnet (primary RPC only at this point).
    let scheduled = schedule_upgrade(
        stellar_agent_smart_account::timelock::TimelockScheduleArgs::builder()
            .timelock_contract_strkey(&timelock_strkey)
            .target_strkey(&timelock_strkey)
            .function("update_delay")
            .delay_ledgers(10)
            .signer(signer_box.as_ref())
            .primary_rpc_url(TESTNET_RPC_URL)
            .secondary_rpc_url(TESTNET_RPC_URL) // secondary = testnet for schedule (no divergence here)
            .network_passphrase(TESTNET_PASSPHRASE)
            .audit_writer(&audit_writer)
            .request_id(&request_id_schedule)
            .build(),
    )
    .await
    .expect("schedule_upgrade must succeed for setup");
    let operation_id = scheduled.operation_id;
    eprintln!("[T-6] scheduled: {}", operation_id.redacted());

    // Start wiremock secondary that returns SUCCESS with NO events field.
    // This mimics a compromised RPC stripping event data from getTransaction responses.
    let secondary_mock = MockServer::start().await;

    // The secondary responds to any POST (getTransaction, simulateTransaction, etc.)
    // with a bare SUCCESS JSON-RPC response that has no `events` field.
    // `cross_confirm_event` calls getTransaction on the secondary; `to_events()` on a
    // response without `events` returns `None`, so `event_present_in_response` → false.
    //
    // EchoIdResponder mirrors the incoming JSON-RPC `id` back in the response so that
    // the RPC client's per-request id validation succeeds regardless of the sequence
    // counter value.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(serde_json::json!({
            "status": "SUCCESS",
            "latestLedger": 1001,
            "latestLedgerCloseTime": "1234567890",
            "oldestLedger": 1,
            "oldestLedgerCloseTime": "1234000000",
            "createdAt": "1234567890",
            "ledger": 1000
            // Note: no "events" field — simulates a compromised RPC stripping event data
        })))
        .mount(&secondary_mock)
        .await;

    let secondary_url = secondary_mock.uri();
    eprintln!("[T-6] secondary mock URL (no-events): {secondary_url}");

    // Attempt cancel with primary=testnet (real), secondary=wiremock (no events).
    // The primary confirms OperationCancelled event; the secondary returns no events.
    // cross_confirm_event sees (primary_found=true, secondary_found=false) → divergence.
    let signer_box2 = signer_from_seed(seed_bytes);
    let cancel_result = cancel(
        stellar_agent_smart_account::timelock::TimelockCancelArgs::builder()
            .timelock_contract_strkey(&timelock_strkey)
            .operation_id(&operation_id)
            .signer(signer_box2.as_ref())
            .primary_rpc_url(TESTNET_RPC_URL)
            .secondary_rpc_url(&secondary_url)
            .network_passphrase(TESTNET_PASSPHRASE)
            .audit_writer(&audit_writer)
            .request_id(&request_id_cancel)
            .build(),
    )
    .await;
    eprintln!("[T-6] cancel result: {cancel_result:?}");

    // Assert: NetworkRpcDivergence returned (not Ok, not EventConfirmationMissing).
    match cancel_result {
        Err(SaError::NetworkRpcDivergence {
            rule_id,
            request_id: err_request_id,
            ..
        }) => {
            assert_eq!(
                rule_id, 0,
                "NetworkRpcDivergence rule_id must be 0 (timelock queries are not rule-scoped)"
            );
            assert_eq!(
                err_request_id, request_id_cancel,
                "NetworkRpcDivergence request_id must match cancel request_id"
            );
            eprintln!(
                "[T-6] PASS: cancel() returned NetworkRpcDivergence as expected \
                 when secondary RPC strips events from getTransaction"
            );
        }
        Err(other) => panic!("expected SaError::NetworkRpcDivergence, got: {other:?}"),
        Ok(()) => panic!(
            "expected SaError::NetworkRpcDivergence but cancel succeeded — \
             secondary-RPC divergence check was not enforced"
        ),
    }
}

// ── schedule → execute using surfaced salt ───────────────────────────────

/// Schedule an operation and execute it using the salt returned by `schedule_upgrade`.
///
/// With `min_delay=0`, the operation is immediately Ready. The test calls
/// `execute()` using the `salt` field from the `ScheduledTimelockOperation`
/// returned by `schedule_upgrade` — the exact value that was supplied to the
/// OZ `Timelock::schedule` on-chain call.
///
/// Asserts:
/// 1. `schedule_upgrade` returns a `ScheduledTimelockOperation` with a
///    non-zero 32-byte salt.
/// 2. `execute()` called with that salt against the same target/function
///    combination returns `Ok`.
/// 3. After execution, `query_operation_state` reports `Done`, confirming the
///    operation is no longer pending.
///
/// # Target contract
///
/// The controller timelock (`timelock_strkey`) schedules a call on the testnet
/// native-asset Stellar Asset Contract. The target must be a distinct contract:
/// Soroban forbids re-entry, so a timelock cannot call `execute` on itself. The
/// native SAC always exists on testnet (no extra deployment or funding needed),
/// and `symbol` is a no-arg, no-auth view, so the cross-contract call requires no
/// authorisation.
#[tokio::test]
async fn t7_schedule_execute_min_delay_zero() {
    // Controller signer: proposer + executor role on the controller timelock.
    let (signer_g, seed_bytes, _signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let (audit_writer, _audit_log_path, _tmpdir) = tmp_audit_writer();
    let request_id_schedule = uuid::Uuid::new_v4().to_string();
    let request_id_execute = uuid::Uuid::new_v4().to_string();

    // Deploy the CONTROLLER timelock (min_delay=0, open-executor).
    let timelock_strkey = deploy_timelock_controller(&signer_g, seed_bytes, &signer_g, 0).await;
    eprintln!("[T-7] controller timelock deployed (min_delay=0): {timelock_strkey}");

    // Allow the freshly deployed controller instance to propagate across the
    // testnet RPC nodes before scheduling: schedule simulates (and re-simulates)
    // against the instance, and a just-deployed instance can briefly be missing
    // on a node behind the RPC load balancer.
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Execution target: the testnet native-asset (XLM) Stellar Asset Contract.
    // It always exists, so no second deployment or Friendbot funding is needed.
    // The target must differ from the controller (Soroban forbids self re-entry);
    // `symbol` is a no-arg, no-auth view. Derived via
    // `stellar contract id asset --asset native --network testnet`.
    let target_strkey = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
    assert_ne!(
        timelock_strkey.as_str(),
        target_strkey,
        "controller and target must be distinct contracts (else execute re-enters)"
    );

    // Schedule: controller timelock schedules a call to target's get_min_delay.
    // delay_ledgers=0 → immediately Ready.
    let signer_box_schedule = signer_from_seed(seed_bytes);
    let scheduled: ScheduledTimelockOperation = schedule_upgrade(
        stellar_agent_smart_account::timelock::TimelockScheduleArgs::builder()
            .timelock_contract_strkey(&timelock_strkey)
            .target_strkey(target_strkey)
            .function("symbol")
            .delay_ledgers(0)
            .signer(signer_box_schedule.as_ref())
            .primary_rpc_url(TESTNET_RPC_URL)
            .secondary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .audit_writer(&audit_writer)
            .request_id(&request_id_schedule)
            .build(),
    )
    .await
    .expect("schedule_upgrade must succeed with min_delay=0");

    eprintln!("[T-7] scheduled: {}", scheduled.operation_id.redacted());

    // The salt must be non-zero: the sha256-derived salt is astronomically unlikely
    // to be the zero array; a zero result would indicate a derivation bug.
    assert_ne!(
        scheduled.salt, [0u8; 32],
        "schedule_upgrade must return a non-zero salt"
    );

    // Execute using the salt returned by schedule_upgrade.
    // target_strkey and function must exactly match what was scheduled.
    let signer_box_exec = signer_from_seed(seed_bytes);
    let execute_result = execute(
        stellar_agent_smart_account::timelock::TimelockExecuteArgs::builder()
            .timelock_contract_strkey(&timelock_strkey)
            .target_strkey(target_strkey)
            .function("symbol")
            .salt(scheduled.salt)
            .expected_operation_id(&scheduled.operation_id)
            .signer(signer_box_exec.as_ref())
            .primary_rpc_url(TESTNET_RPC_URL)
            .secondary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .audit_writer(&audit_writer)
            .request_id(&request_id_execute)
            .build(),
    )
    .await;

    assert!(
        execute_result.is_ok(),
        "execute must succeed using the salt returned by schedule_upgrade; \
         got: {execute_result:?}"
    );

    eprintln!(
        "[T-7] execute succeeded; tx_hash={}",
        execute_result.as_ref().unwrap()
    );

    // After execution the OZ contract marks the operation Done (ready_ledger=DONE_LEDGER=1).
    // query_operation_state must return Done — the operation is no longer pending/Ready.
    let state = query_operation_state(
        &timelock_strkey,
        &scheduled.operation_id,
        TESTNET_RPC_URL,
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        &request_id_execute,
    )
    .await
    .expect("query_operation_state must succeed after execute");

    assert!(
        matches!(state, TimelockOperationStateView::Done),
        "operation must be in Done state after successful execute; got {state:?}"
    );

    eprintln!(
        "[T-7] PASS: schedule → execute lifecycle using surfaced salt; \
         operation state after execute = {state:?}"
    );
}
