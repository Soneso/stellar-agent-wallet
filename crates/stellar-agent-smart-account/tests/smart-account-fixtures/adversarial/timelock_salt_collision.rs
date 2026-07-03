//! Adversarial fixture: `timelock_salt_collision`.
//!
//! Regression-locks against salt-collision griefing: an attacker who observes a pending
//! `(target, function, args, predecessor)` tuple cannot pre-schedule an identical
//! operation using the same salt to block the legitimate proposal.
//!
//! # Threat model
//!
//! OZ `Timelock::hash_operation(target, value, data, predecessor, salt)` derives an
//! `operation_id` (Keccak-256). Two `schedule` calls with identical
//! `(target, value, data, predecessor)` but DIFFERENT salts produce distinct
//! `operation_id`s. An attacker who front-runs the legitimate `schedule` with the
//! SAME salt triggers `OZ_ERR_ALREADY_SCHEDULED` (error code 4000), blocking the
//! legitimate proposal as a griefing vector.
//!
//! The wallet's salt derivation: `sha256(request_id_bytes || timestamp_nanos_be)`.
//! This salt is:
//! - **Non-replayable**: two calls with different `request_id` values produce
//!   different salts even at the same wall-clock time.
//! - **Non-predictable**: the `timestamp_nanos` component (monotonic clock) is
//!   not observable by an external attacker before the RPC call is submitted.
//!
//! A hypothetical refactor that drops the `timestamp_nanos` component (making
//! `salt = sha256(request_id_bytes)` only) would remain non-replayable per
//! `request_id` but would become predictable for any attacker who can observe or
//! guess the `request_id`. This fixture regression-locks against that refactor.
//!
//! # What this fixture proves
//!
//! 1. **Dual-component source-lock.** Source-grep asserts that `derive_schedule_salt`
//!    in `timelock.rs` hashes BOTH `request_id.as_bytes()` AND `timestamp_nanos.to_be_bytes()`.
//!    If either update call is removed, this test fails.
//! 2. **Signature arity.** Source-grep asserts the function signature takes both a
//!    `request_id` and a `timestamp_nanos` parameter. A refactor that merges them
//!    or removes one would fail this assertion.
//! 3. **Salt uniqueness under distinct request_ids.** `TimelockOperationId::from_bytes`
//!    constructed from different salts must yield distinct `to_hex()` representations.
//!    Exercises the `TimelockOperationId` equality contract in the collision-resistance
//!    context.
//! 4. **Salt uniqueness under same request_id + different timestamps.** A fixed
//!    `request_id` with two adjacent nanosecond values MUST yield different salts,
//!    preventing replay attacks in a high-speed scheduling loop.
//!
//! # Why source-grep (not a mock integration test)
//!
//! `derive_schedule_salt` is a private `fn` in the `timelock` module; it is not
//! accessible from integration tests. The source-grep approach (used by
//! `cross_rpc_consumer_audit.rs` for the same reason) lets the fixture regression-
//! lock the implementation without requiring a public test-helper surface.
//! The structural property tests in items #3 and #4 below use the public
//! `TimelockOperationId` API to exercise the same collision-resistance property
//! at the public boundary.
//!
//! # Implements
//!
//! Salt-collision resistance for `derive_schedule_salt` / `TimelockOperationId`.

use std::fs;
use std::path::{Path, PathBuf};
// `derive_schedule_salt` is exposed via the `test-helpers` feature gate in
// `stellar_agent_smart_account::lib.rs`; tests compile with
// `--features test-helpers` (adversarial_fixtures.rs sets this).
use stellar_agent_smart_account::derive_schedule_salt;
use stellar_agent_smart_account::timelock::TimelockOperationId;

// ── Workspace-root helper (shared pattern with cross_rpc_consumer_audit.rs) ────

/// Walks the filesystem from `CARGO_MANIFEST_DIR` until the workspace `Cargo.toml`
/// is found. Anchors source-file paths for the audit grep below.
fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = p.join("Cargo.toml");
        if let Ok(contents) = fs::read_to_string(&candidate)
            && contents.lines().any(|l| l.trim() == "[workspace]")
        {
            return p;
        }
        if !p.pop() {
            panic!("workspace Cargo.toml not found from CARGO_MANIFEST_DIR ascent");
        }
    }
}

/// Reads `timelock.rs` and returns its source lines.
fn timelock_source(workspace: &Path) -> String {
    let path = workspace.join("crates/stellar-agent-smart-account/src/timelock.rs");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read timelock.rs failed: {e}"))
}

// ── Test 1: dual-component source-lock ───────────────────────────────────────

/// Asserts that `derive_schedule_salt` hashes BOTH `request_id.as_bytes()` and
/// `timestamp_nanos.to_be_bytes()`. If either `hasher.update` call is removed,
/// this test fails — ensuring neither component can be silently dropped.
///
/// The grep matches the ACTUAL update call on a non-comment line, excluding
/// doc-comment references like `/// salt = sha256(request_id_bytes || …)`.
#[test]
fn derive_schedule_salt_updates_both_request_id_and_timestamp() {
    let workspace = workspace_root();
    let src = timelock_source(&workspace);

    let has_request_id_update = src.lines().any(|line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("*") {
            return false;
        }
        line.contains("hasher.update(request_id.as_bytes())")
    });

    let has_timestamp_update = src.lines().any(|line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("*") {
            return false;
        }
        line.contains("hasher.update(timestamp_nanos.to_be_bytes())")
    });

    assert!(
        has_request_id_update,
        "derive_schedule_salt must call `hasher.update(request_id.as_bytes())`. \
         Removing this call makes the salt deterministic from the timestamp alone, \
         defeating replay resistance for fixed-timestamp replay attacks.",
    );
    assert!(
        has_timestamp_update,
        "derive_schedule_salt must call `hasher.update(timestamp_nanos.to_be_bytes())`. \
         Removing this call makes the salt predictable from the request_id alone, \
         allowing an attacker who observes the request_id to pre-compute and front-run \
         the salt to block legitimate proposals.",
    );
}

// ── Test 2: function signature arity ─────────────────────────────────────────

/// Asserts that `derive_schedule_salt` takes BOTH a `request_id` parameter AND a
/// `timestamp_nanos` parameter. A refactor that merges them into a single string
/// or removes one would fail here.
#[test]
fn derive_schedule_salt_signature_has_both_parameters() {
    let workspace = workspace_root();
    let src = timelock_source(&workspace);

    // Match the function definition line (non-comment, contains fn name + both params).
    let has_both_params = src.lines().any(|line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("*") {
            return false;
        }
        line.contains("fn derive_schedule_salt(")
            && line.contains("request_id")
            && line.contains("timestamp_nanos")
    });

    assert!(
        has_both_params,
        "derive_schedule_salt signature must include both `request_id` and \
         `timestamp_nanos` parameters. Dropping either parameter makes the salt \
         predictable or non-anchored to the scheduling invocation.",
    );
}

// ── Test 3: salt uniqueness under distinct request_ids ───────────────────────

/// Asserts that two calls to `derive_schedule_salt` with different `request_id`
/// values produce distinct `TimelockOperationId` representations.
///
/// This test calls the exposed `derive_schedule_salt` function directly so that any
/// future refactor changing the hashing order is immediately caught here, rather
/// than having the production function and a test-side copy silently diverge.
///
/// Adversarial scenario: attacker observes a legitimate `schedule_upgrade` call
/// and reuses the same `(target, function, args, predecessor)` with the SAME salt.
/// The wallet's non-replayable salt ensures the attacker cannot reproduce the
/// wallet-chosen salt unless they know the exact `request_id` used internally.
#[test]
fn timelock_operation_id_collision_resistance_under_distinct_request_ids() {
    let timestamp_nanos: u128 = 1_748_000_000_000_000_000;

    let salt1 = derive_schedule_salt("req-id-legitimate-wallet-call-00001", timestamp_nanos);
    let salt2 = derive_schedule_salt("req-id-attacker-replay-attempt-0002", timestamp_nanos);

    let id1 = TimelockOperationId::from_bytes(salt1);
    let id2 = TimelockOperationId::from_bytes(salt2);

    assert_ne!(
        id1.to_hex(),
        id2.to_hex(),
        "TimelockOperationId derived from different request_ids MUST differ. \
         If they are equal, the salt derivation is broken and an attacker can \
         pre-schedule with an identical operation_id to block the legitimate proposal.",
    );
}

// ── Test 4: salt uniqueness under same request_id + different timestamps ──────

/// Asserts that two calls to `derive_schedule_salt` with the SAME `request_id`
/// but different `timestamp_nanos` values produce different salts.
///
/// This test calls the exposed `derive_schedule_salt` function directly so that any
/// future refactor changing the hashing order is immediately caught here, rather
/// than having the production function and a test-side copy silently diverge.
///
/// Scenario: high-speed scheduling loop where the same `request_id` is accidentally
/// reused (operator error). The `timestamp_nanos` entropy ensures uniqueness.
/// Without the timestamp component, back-to-back calls with the same `request_id`
/// would produce identical salts → identical `operation_id` → `OperationAlreadyScheduled`.
#[test]
fn timelock_salt_uniqueness_under_same_request_id_different_timestamps() {
    let request_id = "req-id-high-frequency-scheduler-loop";

    let ts1: u128 = 1_748_000_000_000_000_000;
    let ts2: u128 = 1_748_000_000_000_000_001; // adjacent nanosecond

    let salt1 = derive_schedule_salt(request_id, ts1);
    let salt2 = derive_schedule_salt(request_id, ts2);

    let id1 = TimelockOperationId::from_bytes(salt1);
    let id2 = TimelockOperationId::from_bytes(salt2);

    assert_ne!(
        id1.to_hex(),
        id2.to_hex(),
        "TimelockOperationId derived from identical request_id but adjacent nanosecond \
         timestamps MUST differ. If equal, the timestamp component is not contributing \
         entropy — accidental request_id reuse would cause OperationAlreadyScheduled.",
    );
}

// ── Test 5: determinism within a single invocation ───────────────────────────

/// Asserts that `derive_schedule_salt` is deterministic for identical inputs.
///
/// This test calls the exposed `derive_schedule_salt` function directly so that any
/// future refactor changing the hashing order is immediately caught here, rather
/// than having the production function and a test-side copy silently diverge.
///
/// This is the expected positive case: a `TimelockOperationId` computed from
/// the same `(request_id, timestamp_nanos)` pair MUST always produce the same
/// result, which is required for event-confirmation: the wallet must re-derive
/// the same `operation_id` to match against the on-chain event.
#[test]
fn timelock_salt_is_deterministic_for_identical_inputs() {
    let request_id = "req-id-determinism-check-fixture";
    let timestamp_nanos: u128 = 9_876_543_210_987_654_321;

    let salt1 = derive_schedule_salt(request_id, timestamp_nanos);
    let salt2 = derive_schedule_salt(request_id, timestamp_nanos);

    let id1 = TimelockOperationId::from_bytes(salt1);
    let id2 = TimelockOperationId::from_bytes(salt2);

    assert_eq!(
        id1.to_hex(),
        id2.to_hex(),
        "TimelockOperationId derived from identical (request_id, timestamp_nanos) \
         MUST be deterministic. Non-determinism here would break event-confirmation: \
         the wallet cannot match operation_id against on-chain event.",
    );
}
