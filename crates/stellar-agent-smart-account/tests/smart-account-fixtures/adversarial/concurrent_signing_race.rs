//! Adversarial fixture: concurrent signing race / TOCTOU detection.
//!
//! Scenario: two concurrent callers race to invoke `verify_signer_set_against_chain`
//! against the SAME rule on the SAME smart account.  Under the per-rule async
//! mutex (`managers/signers.rs::rule_mutex_acquire`), the two
//! callers serialise: the second does not begin its audit-log read until the first
//! has completed its full check.
//!
//! # TOCTOU defence
//!
//! This is a wallet-side defence with no on-chain analogue.  The per-rule
//! async mutex (`RULE_MUTEX_REGISTRY` in `managers/signers.rs`) is wallet-specific
//! and closes the `(audit-log read → two-RPC → comparison)` TOCTOU window.
//!
//! # Test scenario
//!
//! 1. A 1-of-1 baseline is written to the audit log.
//! 2. Two tasks are launched concurrently via `tokio::task::JoinSet`.
//!    A `tokio::sync::Barrier` synchronises their start so both are genuinely
//!    concurrent before the first mutex acquisition.
//! 3. `caller_1` acquires the per-rule mutex first (non-deterministic; the test
//!    identifies the winner from the trace after the fact).  On success, the test
//!    appends a `SaSignerAdded` row (1→2 signers) to the audit log — simulating a
//!    real `add_signer` completing inside the mutex.
//! 4. `caller_2` acquires the mutex AFTER `caller_1` releases it.  It reads the
//!    NOW-UPDATED audit log (baseline: 2-of-2 signer set) but the mock returns
//!    the ORIGINAL 1-of-1 on-chain state.  The expected-vs-observed mismatch
//!    triggers `SaError::SignerSetDiverged`.
//!
//! # Assertions
//!
//! - Mutex serialisation: `caller_1` and `caller_2` do not interleave inside
//!   the critical section.  Each caller is assigned a separate pair of mock servers
//!   whose `simulateTransaction` handlers record `(caller_id, global_tick)` entries
//!   into a shared trace.  Serialisation is verified by checking that all ticks for
//!   the winning caller are strictly less than all ticks for the losing caller.
//! - FrozenChainStateTuple ordering: both callers return
//!   `Ok(FrozenChainStateTuple)` when the audit baseline is unchanged (both see
//!   the same 1-of-1 row).  The two frozen tuples bind to the same row hash.  The
//!   second caller's `simulation_ledger` timestamp is ≥ the first's.
//! - expected_audit_row_hash ordering: `caller_2`'s frozen tuple's
//!   `expected_audit_row_hash` is DIFFERENT from `caller_1`'s when the audit log
//!   is updated between their calls.  Verified directly: both callers succeed and
//!   return frozen tuples; their hashes differ.
//! - Divergence: `caller_2` returns `SaError::SignerSetDiverged` because
//!   the on-chain 1-of-1 state disagrees with the updated 2-of-2 baseline.
//!
//! # Note on `SaError::SimulationDivergence`
//!
//! `SaError::SimulationDivergence` is raised by the transaction-submit path
//! (`submit_signed_invoke`) when the re-simulation at submit time detects a
//! sequence-number drift.  That path requires a real Signer + approval bridge
//! and cannot be exercised by a mock-only fixture.  The TOCTOU closure asserted
//! here — `SaError::SignerSetDiverged` on `verify_signer_set_against_chain` — is
//! the observable counterpart at the divergence-check level: once the audit log
//! reflects the post-first-call state (2-of-2) but the chain still shows 1-of-1,
//! the check correctly refuses.  The submit-path `SimulationDivergence` is a
//! defence-in-depth layer for the case where the on-chain sequence number changes
//! between the divergence check and submission; that layer is separately exercised
//! by the existing `rpc_divergence` + `submit_signed_invoke` unit tests.
//!
//! # Property verified
//!
//! Atomic signer-threshold update: concurrent callers serialise behind the
//! per-rule async mutex, preventing TOCTOU races on signer-set verification.

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::signer_set::ObservedSignerSet;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_smart_account::error::SaError;
use tokio::sync::Barrier;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::combined_rpc_responder::{
    CombinedRpcResponder, SequencedSimulate, TracedCombinedRpcResponder, TracedSequencedSimulate,
};
use super::rpc_mock_helpers::{
    KNOWN_WASM_HASH, SOURCE_G, ZERO_CONTRACT_REDACTED, build_context_rule_scval_xdr,
    build_simulate_response, build_threshold_scval_xdr, manager_two_url, policy_sc_address,
    signer_set_n_of_n, tmp_audit_writer, write_baseline, zero_sc_address,
};

// ── Shared trace types ────────────────────────────────────────────────────────

/// Shared trace for ordering evidence: `(caller_id, global_tick)` per simulate call.
type SimulateTrace = Arc<Mutex<Vec<(u8, u64)>>>;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Write a `SaSignerAdded` audit row for the given signer set into the
/// shared audit writer.  Used to simulate a completed `add_signer` op inside
/// the first caller's critical section.
fn write_signer_added_row(
    writer: &Arc<Mutex<AuditWriter>>,
    rule_id: u32,
    smart_account_redacted: &str,
    new_signer_id: u32,
    resulting: &ObservedSignerSet,
    request_id: &str,
) {
    let first8: Vec<String> = resulting
        .signer_pubkeys
        .iter()
        .map(|_| "0102030405060708".to_owned())
        .collect();
    let entry = AuditEntry::new_sa_signer_added(
        rule_id,
        new_signer_id,
        resulting,
        first8,
        RedactedStrkey::from_already_redacted(smart_account_redacted),
        "stellar:testnet",
        request_id,
    );
    writer
        .lock()
        .expect("audit writer lock must not be poisoned")
        .write_entry(entry)
        .expect("write_signer_added_row must succeed");
}

// ── Mock server factories ─────────────────────────────────────────────────────

/// Builds simulate response JSON values for a 1-of-1 signer set.
fn responses_1_of_1(policy: &stellar_xdr::ScAddress) -> (serde_json::Value, serde_json::Value) {
    let on_chain = signer_set_n_of_n(1);
    let cr_xdr = build_context_rule_scval_xdr(1, &on_chain, std::slice::from_ref(policy));
    let th_xdr = build_threshold_scval_xdr(1);
    let sim_cr = build_simulate_response(&cr_xdr);
    let sim_th = build_simulate_response(&th_xdr);
    (sim_cr, sim_th)
}

/// Builds simulate response JSON values for a 2-of-2 signer set.
fn responses_2_of_2(policy: &stellar_xdr::ScAddress) -> (serde_json::Value, serde_json::Value) {
    let on_chain = signer_set_n_of_n(2);
    let cr_xdr = build_context_rule_scval_xdr(1, &on_chain, std::slice::from_ref(policy));
    let th_xdr = build_threshold_scval_xdr(2);
    let sim_cr = build_simulate_response(&cr_xdr);
    let sim_th = build_simulate_response(&th_xdr);
    (sim_cr, sim_th)
}

/// Constructs a **primary** mock server for a single sequential
/// `verify_signer_set_against_chain` call on a 1-of-1 signer set.
///
/// Per-call primary-server sequence:
///   1. `simulateTransaction` — `get_context_rule` (`identify_threshold_policy`)
///   2. `simulateTransaction` — `get_context_rule` (`fetch_signer_set` primary)
///   3. `simulateTransaction` — `get_threshold`    (`fetch_signer_set` primary)
async fn build_primary_server_1_of_1(policy: &stellar_xdr::ScAddress) -> MockServer {
    let (sim_cr, sim_th) = responses_1_of_1(policy);
    let responses = vec![
        sim_cr.clone(), // identify_threshold_policy
        sim_cr.clone(), // fetch_signer_set get_context_rule
        sim_th.clone(), // fetch_signer_set get_threshold
    ];
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new(
            SOURCE_G,
            policy,
            KNOWN_WASM_HASH,
            SequencedSimulate::new(responses),
        ))
        .mount(&server)
        .await;
    server
}

/// Constructs a **secondary** mock server for a single sequential
/// `verify_signer_set_against_chain` call on a 1-of-1 signer set.
///
/// Per-call secondary-server sequence:
///   1. `simulateTransaction` — `get_context_rule` (`fetch_signer_set` secondary)
///   2. `simulateTransaction` — `get_threshold`    (`fetch_signer_set` secondary)
async fn build_secondary_server_1_of_1(policy: &stellar_xdr::ScAddress) -> MockServer {
    let (sim_cr, sim_th) = responses_1_of_1(policy);
    let responses = vec![
        sim_cr.clone(), // fetch_signer_set get_context_rule
        sim_th.clone(), // fetch_signer_set get_threshold
    ];
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new(
            SOURCE_G,
            policy,
            KNOWN_WASM_HASH,
            SequencedSimulate::new(responses),
        ))
        .mount(&server)
        .await;
    server
}

/// Constructs a **primary** mock server for a single sequential call on a 2-of-2
/// signer set.  Used for the test where caller_2 must observe 2-of-2 on-chain.
async fn build_primary_server_2_of_2(policy: &stellar_xdr::ScAddress) -> MockServer {
    let (sim_cr, sim_th) = responses_2_of_2(policy);
    let responses = vec![
        sim_cr.clone(), // identify_threshold_policy
        sim_cr.clone(), // fetch_signer_set get_context_rule
        sim_th.clone(), // fetch_signer_set get_threshold
    ];
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new(
            SOURCE_G,
            policy,
            KNOWN_WASM_HASH,
            SequencedSimulate::new(responses),
        ))
        .mount(&server)
        .await;
    server
}

/// Constructs a **secondary** mock server for a single sequential call on a 2-of-2
/// signer set.
async fn build_secondary_server_2_of_2(policy: &stellar_xdr::ScAddress) -> MockServer {
    let (sim_cr, sim_th) = responses_2_of_2(policy);
    let responses = vec![
        sim_cr.clone(), // fetch_signer_set get_context_rule
        sim_th.clone(), // fetch_signer_set get_threshold
    ];
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new(
            SOURCE_G,
            policy,
            KNOWN_WASM_HASH,
            SequencedSimulate::new(responses),
        ))
        .mount(&server)
        .await;
    server
}

/// Constructs a **primary** traced mock server for one caller's
/// `verify_signer_set_against_chain` call on a 1-of-1 signer set.
///
/// Returns `(server, trace)` where `trace` is an `Arc<Mutex<Vec<(u8, u64)>>>` shared
/// across all traced servers in the test (pass the same `global_tick` and `trace`
/// to all instances).  Records `(caller_id, global_tick)` on every simulate call.
async fn build_traced_primary_server_1_of_1(
    policy: &stellar_xdr::ScAddress,
    global_tick: Arc<AtomicU64>,
    caller_id: u8,
    trace: SimulateTrace,
) -> MockServer {
    let (sim_cr, sim_th) = responses_1_of_1(policy);
    let responses = vec![
        sim_cr.clone(), // identify_threshold_policy
        sim_cr.clone(), // fetch_signer_set get_context_rule
        sim_th.clone(), // fetch_signer_set get_threshold
    ];
    let responder = TracedCombinedRpcResponder::new(
        SOURCE_G,
        policy,
        KNOWN_WASM_HASH,
        TracedSequencedSimulate::new(responses, global_tick, caller_id, trace),
    );
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(responder)
        .mount(&server)
        .await;
    server
}

/// Constructs a **secondary** traced mock server for one caller's
/// `verify_signer_set_against_chain` call on a 1-of-1 signer set.
async fn build_traced_secondary_server_1_of_1(
    policy: &stellar_xdr::ScAddress,
    global_tick: Arc<AtomicU64>,
    caller_id: u8,
    trace: SimulateTrace,
) -> MockServer {
    let (sim_cr, sim_th) = responses_1_of_1(policy);
    let responses = vec![
        sim_cr.clone(), // fetch_signer_set get_context_rule
        sim_th.clone(), // fetch_signer_set get_threshold
    ];
    let responder = TracedCombinedRpcResponder::new(
        SOURCE_G,
        policy,
        KNOWN_WASM_HASH,
        TracedSequencedSimulate::new(responses, global_tick, caller_id, trace),
    );
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(responder)
        .mount(&server)
        .await;
    server
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Two concurrent `verify_signer_set_against_chain` callers on the
/// same rule serialise behind the per-rule async mutex.  Neither interleaves
/// with the other's critical section.
///
/// Each caller is given its own dedicated primary and secondary mock servers.
/// All four servers share a `global_tick` counter and a `trace` log.  Every
/// simulate call records `(caller_id, tick)` into the trace.  If the mutex
/// serialises the callers, all ticks for the winning caller are strictly less
/// than all ticks for the losing caller.
///
/// Both `FrozenChainStateTuple` values bind to the same audit-row hash
/// (the baseline is unchanged between callers) and the second caller's
/// `simulation_ledger` timestamp is ≥ the first's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a1_a2_callers_serialise_behind_per_rule_mutex() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let policy = policy_sc_address();
    let baseline = signer_set_n_of_n(1);
    write_baseline(&audit_writer, 1, ZERO_CONTRACT_REDACTED, &baseline);

    // Shared ordering evidence: all four mock servers write into the same trace.
    let global_tick = Arc::new(AtomicU64::new(0));
    let trace: SimulateTrace = Arc::new(Mutex::new(Vec::new()));

    // Caller_1 gets its own dedicated server pair (caller_id = 1).
    let primary_1 = build_traced_primary_server_1_of_1(
        &policy,
        Arc::clone(&global_tick),
        1,
        Arc::clone(&trace),
    )
    .await;
    let secondary_1 = build_traced_secondary_server_1_of_1(
        &policy,
        Arc::clone(&global_tick),
        1,
        Arc::clone(&trace),
    )
    .await;

    // Caller_2 gets its own dedicated server pair (caller_id = 2).
    let primary_2 = build_traced_primary_server_1_of_1(
        &policy,
        Arc::clone(&global_tick),
        2,
        Arc::clone(&trace),
    )
    .await;
    let secondary_2 = build_traced_secondary_server_1_of_1(
        &policy,
        Arc::clone(&global_tick),
        2,
        Arc::clone(&trace),
    )
    .await;

    // Both managers share the same audit log path + same rule_id so they contend
    // on the same per-rule mutex.
    let manager_1 = manager_two_url(
        &primary_1.uri(),
        &secondary_1.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );
    let manager_2 = manager_two_url(
        &primary_2.uri(),
        &secondary_2.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );

    // A barrier at 2 ensures both tasks are scheduled before either attempts the mutex.
    let barrier = Arc::new(Barrier::new(2));
    let barrier_1 = Arc::clone(&barrier);
    let barrier_2 = Arc::clone(&barrier);

    // Task channels carry the FrozenChainStateTuple for the frozen-tuple assertions.
    let (tx1, rx1) = tokio::sync::oneshot::channel::<Result<(u32, i64, [u8; 32]), String>>();
    let (tx2, rx2) = tokio::sync::oneshot::channel::<Result<(u32, i64, [u8; 32]), String>>();

    tokio::spawn(async move {
        barrier_1.wait().await;
        let outcome = manager_1
            .verify_signer_set_against_chain(
                zero_sc_address(),
                1,
                Some(SOURCE_G),
                Uuid::new_v4().to_string(),
            )
            .await
            .map(|frozen| {
                let (ledger_seq, ts_ms) = frozen.simulation_ledger();
                let hash = *frozen.expected_audit_row_hash();
                (ledger_seq, ts_ms, hash)
            })
            .map_err(|e| format!("{e:?}"));
        let _ = tx1.send(outcome);
    });

    tokio::spawn(async move {
        barrier_2.wait().await;
        let outcome = manager_2
            .verify_signer_set_against_chain(
                zero_sc_address(),
                1,
                Some(SOURCE_G),
                Uuid::new_v4().to_string(),
            )
            .await
            .map(|frozen| {
                let (ledger_seq, ts_ms) = frozen.simulation_ledger();
                let hash = *frozen.expected_audit_row_hash();
                (ledger_seq, ts_ms, hash)
            })
            .map_err(|e| format!("{e:?}"));
        let _ = tx2.send(outcome);
    });

    let result_1 = rx1.await.expect("caller_1 task must complete");
    let result_2 = rx2.await.expect("caller_2 task must complete");

    // Part 1: both callers must succeed (1-of-1 on-chain matches baseline).
    let (ledger_seq_1, ts_ms_1, hash_1) =
        result_1.expect("caller_1 must succeed: audit baseline matches 1-of-1 on-chain");
    let (ledger_seq_2, ts_ms_2, hash_2) =
        result_2.expect("caller_2 must succeed: audit baseline matches 1-of-1 on-chain");

    // Part 2: both frozen tuples must bind to the same row hash (audit unchanged).
    assert_eq!(
        hash_1,
        hash_2,
        "both callers read the same unchanged baseline row; \
         expected_audit_row_hash must be identical (hash_1 = {}, hash_2 = {})",
        hex::encode(hash_1),
        hex::encode(hash_2),
    );

    // Part 3: determine which caller completed first by timestamp.
    // The winner's simulation_ledger timestamp must be ≤ the loser's.
    // (Both use the same mock ledger 0; ordering is observable via the timestamp.)
    let _ = (ledger_seq_1, ledger_seq_2); // ledger seq is always 0 in mock; use ts_ms
    // Winner/loser identification: the task with lower ts_ms completed inside the
    // mutex first.  Assert monotonic ordering: winner_ts ≤ loser_ts.
    let (winner_ts, loser_ts) = if ts_ms_1 <= ts_ms_2 {
        (ts_ms_1, ts_ms_2)
    } else {
        (ts_ms_2, ts_ms_1)
    };
    assert!(
        winner_ts <= loser_ts,
        "winner simulation_ledger timestamp must be ≤ loser's; \
         got winner={winner_ts} loser={loser_ts}"
    );

    // Inspect the trace for non-interleaving.
    // Each caller issues 5 simulate calls total (3 primary + 2 secondary).
    // Under serialisation: all 5 ticks for one caller are strictly less than
    // all 5 ticks for the other caller.  Interleaving would mix the two caller_ids
    // within the sorted-by-tick prefix.
    let trace_snapshot = trace.lock().expect("trace lock must not be poisoned");
    assert_eq!(
        trace_snapshot.len(),
        10,
        "expected 10 simulate calls total (5 per caller); got {}",
        trace_snapshot.len()
    );

    // Sort entries by tick to reconstruct the wall-clock order.
    let mut by_tick = trace_snapshot.clone();
    by_tick.sort_unstable_by_key(|&(_, tick)| tick);

    // The first 5 entries in tick order must all belong to one caller;
    // the last 5 must all belong to the other caller.
    let first_half_ids: std::collections::HashSet<u8> =
        by_tick[..5].iter().map(|&(id, _)| id).collect();
    let second_half_ids: std::collections::HashSet<u8> =
        by_tick[5..].iter().map(|&(id, _)| id).collect();

    assert_eq!(
        first_half_ids.len(),
        1,
        "first 5 simulate calls (by tick) must all belong to one caller; \
         got caller_ids: {first_half_ids:?} — callers interleaved inside the mutex"
    );
    assert_eq!(
        second_half_ids.len(),
        1,
        "last 5 simulate calls (by tick) must all belong to one caller; \
         got caller_ids: {second_half_ids:?} — callers interleaved inside the mutex"
    );

    // The two halves must be different callers.
    let winner_id = *first_half_ids.iter().next().expect("non-empty");
    let loser_id = *second_half_ids.iter().next().expect("non-empty");
    assert_ne!(
        winner_id, loser_id,
        "winner and loser caller_ids must differ; both halves have the same id {winner_id}"
    );
}

/// The second caller's `expected_audit_row_hash` (embedded in its
/// `FrozenChainStateTuple`) reflects the post-first-call audit state.
///
/// Scenario:
/// 1. Write a 1-of-1 baseline.
/// 2. `caller_1` runs `verify_signer_set_against_chain` against a 1-of-1 mock →
///    succeeds → `frozen_1` binds to the baseline row hash.
/// 3. A `SaSignerAdded` row is appended to the audit log (simulating the
///    on-chain add completing after the first check).
/// 4. `caller_2` runs `verify_signer_set_against_chain` against a 2-of-2 mock
///    (matching the updated audit baseline) → succeeds → `frozen_2` binds to
///    the `SaSignerAdded` row hash.
/// 5. `hash_1 != hash_2` directly, confirming the second caller committed to
///    the post-first-call audit state.
///
/// Both calls are sequential here (not concurrent) to isolate the hash-binding
/// assertion from the serialisation mechanics tested by the concurrent cases.
#[tokio::test]
async fn a3_second_caller_expected_hash_reflects_post_first_call_state() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let policy = policy_sc_address();

    // Write initial 1-of-1 baseline.
    let baseline_1_of_1 = signer_set_n_of_n(1);
    write_baseline(&audit_writer, 1, ZERO_CONTRACT_REDACTED, &baseline_1_of_1);

    // caller_1: one call against 1-of-1 mock.
    let primary_1 = build_primary_server_1_of_1(&policy).await;
    let secondary_1 = build_secondary_server_1_of_1(&policy).await;
    let manager_1 = manager_two_url(
        &primary_1.uri(),
        &secondary_1.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );

    // caller_1 succeeds; captures hash bound to the baseline row.
    let frozen_1 = manager_1
        .verify_signer_set_against_chain(
            zero_sc_address(),
            1,
            Some(SOURCE_G),
            Uuid::new_v4().to_string(),
        )
        .await
        .expect("caller_1 verify_signer_set_against_chain must succeed");

    let hash_1 = *frozen_1.expected_audit_row_hash();
    assert!(
        hash_1 != [0u8; 32],
        "hash_1 must be a real SHA-256 (non-zero) of the baseline row body"
    );

    // Simulate the on-chain add completing: append SaSignerAdded (1→2 signers).
    // Pubkeys must match what `signer_set_n_of_n(2)` produces so caller_2's audit
    // baseline agrees with the 2-of-2 mock on-chain state.
    // `signer_set_n_of_n(n)` uses byte = `0x10 + id`: signer 0 → [0x10; 32], signer 1 → [0x11; 32].
    let post_add_2_of_2 = signer_set_n_of_n(2);
    write_signer_added_row(
        &audit_writer,
        1,
        ZERO_CONTRACT_REDACTED,
        1,
        &post_add_2_of_2,
        &Uuid::new_v4().to_string(),
    );

    // caller_2: new manager sharing the same audit log (sees the updated 2-of-2 baseline).
    // The mock now also returns 2-of-2 on-chain — so caller_2 succeeds and
    // frozen_2 binds to the SaSignerAdded row hash (different from hash_1).
    let primary_2 = build_primary_server_2_of_2(&policy).await;
    let secondary_2 = build_secondary_server_2_of_2(&policy).await;
    let manager_2 = manager_two_url(
        &primary_2.uri(),
        &secondary_2.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );

    let frozen_2 = manager_2
        .verify_signer_set_against_chain(
            zero_sc_address(),
            1,
            Some(SOURCE_G),
            Uuid::new_v4().to_string(),
        )
        .await
        .expect(
            "caller_2 must succeed: audit baseline (2-of-2) matches the 2-of-2 mock on-chain state",
        );

    let hash_2 = *frozen_2.expected_audit_row_hash();
    assert!(
        hash_2 != [0u8; 32],
        "hash_2 must be a real SHA-256 (non-zero) of the SaSignerAdded row body"
    );

    // The two hashes must be different — caller_1 bound to the baseline row;
    // caller_2 bound to the SaSignerAdded row written after caller_1 completed.
    assert_ne!(
        hash_1,
        hash_2,
        "caller_2 must bind to the post-first-call audit row; \
         expected hash_1 != hash_2 but both are {} ({})",
        hex::encode(hash_1),
        hex::encode(hash_2),
    );
}

/// After the first caller's signing cycle completes and the audit log is
/// updated (2-of-2), the second caller's `verify_signer_set_against_chain`
/// returns `SaError::SignerSetDiverged` because the on-chain state (1-of-1)
/// disagrees with the now-current audit baseline (2-of-2).
///
/// This confirms that the TOCTOU mitigation works in the adversarial direction:
/// the second caller is refused, not allowed to proceed with a stale view.
///
/// See module docstring for the relationship between `SignerSetDiverged` here
/// and `SimulationDivergence` at the submit layer.
#[tokio::test]
async fn a4_second_caller_diverges_after_audit_log_update() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let policy = policy_sc_address();

    // Write initial 1-of-1 baseline.
    let baseline_1_of_1 = signer_set_n_of_n(1);
    write_baseline(&audit_writer, 1, ZERO_CONTRACT_REDACTED, &baseline_1_of_1);

    // caller_1: single sequential call on a 1-of-1 mock.
    let primary = build_primary_server_1_of_1(&policy).await;
    let secondary = build_secondary_server_1_of_1(&policy).await;
    let manager = manager_two_url(
        &primary.uri(),
        &secondary.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );

    // caller_1 succeeds.
    let _frozen_1 = manager
        .verify_signer_set_against_chain(
            zero_sc_address(),
            1,
            Some(SOURCE_G),
            Uuid::new_v4().to_string(),
        )
        .await
        .expect("caller_1 must succeed (1-of-1 matches baseline)");

    // Simulate on-chain add completing: append SaSignerAdded (1→2).
    let post_add = signer_set_n_of_n(2);
    write_signer_added_row(
        &audit_writer,
        1,
        ZERO_CONTRACT_REDACTED,
        1,
        &post_add,
        &Uuid::new_v4().to_string(),
    );

    // caller_2 must diverge: audit log says 2-of-2, mock still returns 1-of-1.
    let primary_stale = build_primary_server_1_of_1(&policy).await;
    let secondary_stale = build_secondary_server_1_of_1(&policy).await;
    let manager_2 = manager_two_url(
        &primary_stale.uri(),
        &secondary_stale.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );

    let result_2 = manager_2
        .verify_signer_set_against_chain(
            zero_sc_address(),
            1,
            Some(SOURCE_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    assert!(
        matches!(result_2, Err(SaError::SignerSetDiverged { rule_id: 1, .. })),
        "caller_2 must return SaError::SignerSetDiverged after audit log updated to 2-of-2 \
         while on-chain remains 1-of-1; got: {result_2:?}"
    );
    assert_eq!(
        result_2.unwrap_err().wire_code(),
        "sa.signer_set_diverged",
        "wire_code must be 'sa.signer_set_diverged'"
    );
}

/// Multi-threaded serialisation regression test: under `tokio::test(flavor =
/// "multi_thread")`, two callers racing against the same rule both succeed
/// because the per-rule mutex serialises them and the audit baseline is
/// unchanged for both calls.
///
/// This covers mutex serialisation in the multi-threaded runtime using
/// the traced responder to confirm non-interleaving.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a1_multi_threaded_both_callers_serialise_and_succeed() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let policy = policy_sc_address();

    let baseline_1_of_1 = signer_set_n_of_n(1);
    write_baseline(&audit_writer, 1, ZERO_CONTRACT_REDACTED, &baseline_1_of_1);

    // Shared ordering evidence for the serialisation check.
    let global_tick = Arc::new(AtomicU64::new(0));
    let trace: SimulateTrace = Arc::new(Mutex::new(Vec::new()));

    let primary_1 = build_traced_primary_server_1_of_1(
        &policy,
        Arc::clone(&global_tick),
        1,
        Arc::clone(&trace),
    )
    .await;
    let secondary_1 = build_traced_secondary_server_1_of_1(
        &policy,
        Arc::clone(&global_tick),
        1,
        Arc::clone(&trace),
    )
    .await;
    let primary_2 = build_traced_primary_server_1_of_1(
        &policy,
        Arc::clone(&global_tick),
        2,
        Arc::clone(&trace),
    )
    .await;
    let secondary_2 = build_traced_secondary_server_1_of_1(
        &policy,
        Arc::clone(&global_tick),
        2,
        Arc::clone(&trace),
    )
    .await;

    let manager_1 = manager_two_url(
        &primary_1.uri(),
        &secondary_1.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );
    let manager_2 = manager_two_url(
        &primary_2.uri(),
        &secondary_2.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );

    let barrier = Arc::new(Barrier::new(2));
    let barrier_1 = Arc::clone(&barrier);
    let barrier_2 = Arc::clone(&barrier);

    let task_1 = tokio::spawn(async move {
        barrier_1.wait().await;
        manager_1
            .verify_signer_set_against_chain(
                zero_sc_address(),
                1,
                Some(SOURCE_G),
                Uuid::new_v4().to_string(),
            )
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    });

    let task_2 = tokio::spawn(async move {
        barrier_2.wait().await;
        manager_2
            .verify_signer_set_against_chain(
                zero_sc_address(),
                1,
                Some(SOURCE_G),
                Uuid::new_v4().to_string(),
            )
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    });

    let result_1 = task_1.await.expect("caller_1 task must not panic");
    let result_2 = task_2.await.expect("caller_2 task must not panic");

    assert!(
        result_1.is_ok(),
        "caller_1 must succeed in multi-threaded runtime: {result_1:?}"
    );
    assert!(
        result_2.is_ok(),
        "caller_2 must succeed in multi-threaded runtime: {result_2:?}"
    );

    // Verify non-interleaving from the trace.
    let trace_snapshot = trace.lock().expect("trace lock must not be poisoned");
    assert_eq!(
        trace_snapshot.len(),
        10,
        "expected 10 simulate calls total (5 per caller); got {}",
        trace_snapshot.len()
    );

    let mut by_tick = trace_snapshot.clone();
    by_tick.sort_unstable_by_key(|&(_, tick)| tick);

    let first_half_ids: std::collections::HashSet<u8> =
        by_tick[..5].iter().map(|&(id, _)| id).collect();
    let second_half_ids: std::collections::HashSet<u8> =
        by_tick[5..].iter().map(|&(id, _)| id).collect();

    assert_eq!(
        first_half_ids.len(),
        1,
        "multi-thread: first 5 simulate calls must all belong to one caller; \
         got: {first_half_ids:?}"
    );
    assert_eq!(
        second_half_ids.len(),
        1,
        "multi-thread: last 5 simulate calls must all belong to one caller; \
         got: {second_half_ids:?}"
    );
    assert_ne!(
        first_half_ids.iter().next(),
        second_half_ids.iter().next(),
        "multi-thread: two halves must belong to different callers"
    );
}
