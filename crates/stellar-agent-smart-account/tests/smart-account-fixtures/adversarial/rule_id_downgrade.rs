//! Adversarial fixture: simulation-divergence detection (rule-ID downgrade attack).
//!
//! Pre-signing simulation-divergence detection MUST refuse to sign when any of the 5
//! typed sub-codes fires. The malicious-sponsor / compromised-RPC vector
//! attempts to surface a different envelope at signing time than was
//! simulated; the divergence detector is the wallet's primary defence.
//! The on-chain `__check_auth` is the fallback for a compromised signing
//! client — a different threat class outside the divergence-detector scope.
//!
//! # Sub-case mapping (one `#[test]` per sub-code)
//!
//! | Sub-case | Mutation | Wire code |
//! |----------|----------|-----------|
//! | context_rule_ids | `envelope.context_rule_ids = [99]` post-sign | `simulation.divergence.context_rule_ids` |
//! | auth_contexts | reorder or extend `envelope.auth_contexts` | `simulation.divergence.auth_contexts` |
//! | network | substitute `envelope.network.ledger_protocol_version` | `simulation.divergence.network` |
//! | sequence | bump `envelope.sequence.source_account_sequence` | `simulation.divergence.sequence` |
//! | fee_envelope | bump `envelope.fee_envelope.resource_fee` | `simulation.divergence.fee_envelope` |
//!
//! # Relationship to inline unit tests at `signing/divergence.rs`
//!
//! The `crates/stellar-agent-smart-account/src/signing/divergence.rs` module
//! carries the same 5 sub-codes as inline `#[cfg(test)] mod tests` unit tests.
//! This adversarial fixture differs in two ways:
//!
//! 1. **Wire-code assertion.** Each sub-case asserts the full
//!    `SaError::wire_code()` string (`"simulation.divergence.<axis>"`),
//!    not just the typed `SimulationDivergenceSubCode` discriminant. A
//!    refactor that changes the wire-code mapping (e.g., reuses
//!    `"sa.simulation_divergence"` for all sub-codes) would silently pass
//!    the inline tests but fail this fixture.
//! 2. **Discoverability.** Lives under `tests/smart-account-fixtures/adversarial/`
//!    so security-review work can enumerate divergence-detector coverage by path.
//!
//! # Note on `source_account` mutation
//!
//! The divergence detector's contract is at the `SimulationContext`/`EnvelopeContext`
//! boundary, not the auth-digest signing boundary; `source_account` does not appear
//! as a top-level field on either struct. The closest analogue —
//! `SequenceContext::source_account_sequence` — is exercised by the sequence sub-case,
//! which fires `simulation.divergence.sequence`.
//! A test exercising the full sign-then-verify pipeline with `source_account` substitution
//! would require the wallet's higher-level signing path and is out of scope for this
//! divergence-detector fixture.

use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_smart_account::SaError;
use stellar_agent_smart_account::error::SimulationDivergenceSubCode;
use stellar_agent_smart_account::signing::divergence::{
    AuthContextFingerprint, EnvelopeContext, SimulationContext, detect_simulation_divergence,
    test_helpers::{baseline_simulation_context, matching_envelope_context},
};

/// Constructs matching simulation + envelope contexts representing the
/// non-adversarial baseline at the divergence-detector boundary via the
/// crate's `test_helpers` builders (the projection types are
/// `#[non_exhaustive]` and cannot be constructed via struct expression
/// from external integration tests). Per-sub-case tests mutate ONE field
/// on the envelope.
fn baseline_contexts() -> (SimulationContext, EnvelopeContext) {
    let simulation = baseline_simulation_context();
    let envelope = matching_envelope_context(&simulation);
    (simulation, envelope)
}

/// Asserts the result carries the expected sub-code AND wire code.
///
/// The wire-code assertion is materially stronger than the inline tests at
/// `signing/divergence.rs:226-275` which assert only the typed
/// `SimulationDivergenceSubCode` discriminant. A refactor collapsing the
/// 5 wire codes to a single `"sa.simulation_divergence"` would silently
/// pass the inline tests but fail this fixture.
fn assert_sub_code_and_wire_code(
    result: Result<(), SaError>,
    expected_sub_code: &SimulationDivergenceSubCode,
    expected_wire_code: &str,
) {
    let err = result.expect_err("divergence detector must reject the mutated envelope");
    let SaError::SimulationDivergence { sub_code, .. } = &err else {
        panic!(
            "expected SaError::SimulationDivergence; got {err:?} (wire_code: {})",
            err.wire_code()
        );
    };
    assert_eq!(
        sub_code, expected_sub_code,
        "sub_code mismatch: expected {expected_sub_code:?}, got {sub_code:?}",
    );
    assert_eq!(
        err.wire_code(),
        expected_wire_code,
        "wire_code mismatch: expected {expected_wire_code}, got {}",
        err.wire_code(),
    );
}

// ── context_rule_ids substitution ─────────────────────────────────────────────

/// The envelope's `context_rule_ids` differ from simulation's.
/// This is the canonical "rule-ID downgrade" attack: malicious sponsor
/// surfaces a rule-ID-99 envelope at signing time when simulation
/// returned rule-ID-42.
#[test]
fn t11a_context_rule_ids_substitution_rejected() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope.context_rule_ids = vec![ContextRuleId::new(99)];

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::ContextRuleIds,
        "simulation.divergence.context_rule_ids",
    );
}

// ── auth_contexts mutation (reorder or extend) ────────────────────────────────

/// The envelope's `auth_contexts` array differs from simulation's
/// (length-mismatch variant via extension; an additional invocation
/// surfaces at signing time that wasn't simulated).
#[test]
fn t11b_auth_contexts_extension_rejected() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope
        .auth_contexts
        .push(AuthContextFingerprint::new("invoke:ffffeeee".to_owned()));

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::AuthContexts,
        "simulation.divergence.auth_contexts",
    );
}

/// The envelope's `auth_contexts` array has the same length but
/// different content (reordering or fingerprint substitution).
#[test]
fn t11b_auth_contexts_fingerprint_substitution_rejected() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope.auth_contexts = vec![AuthContextFingerprint::new("invoke:ffffeeee".to_owned())];

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::AuthContexts,
        "simulation.divergence.auth_contexts",
    );
}

// ── network substitution ──────────────────────────────────────────────────────

/// The envelope's network identity differs from simulation's
/// (`ledger_protocol_version` substitution; sponsor steers signing toward
/// a different protocol version than was simulated).
#[test]
fn t11c_network_ledger_protocol_substitution_rejected() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope.network.ledger_protocol_version += 1;

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::Network,
        "simulation.divergence.network",
    );
}

/// The envelope's `chain_id_fingerprint` differs from simulation's
/// (chain-id-substitution attack — sponsor steers signing toward a network
/// with a different chain-id but otherwise-matching passphrase/protocol).
/// Locks the third `NetworkContext` field against future refactors that
/// special-case `passphrase_fingerprint` / `ledger_protocol_version` while
/// silently relaxing `chain_id_fingerprint` comparison (the
/// `#[derive(PartialEq)]` choke point is the current defence; this test
/// regression-locks it).
#[test]
fn t11c_network_chain_id_fingerprint_substitution_rejected() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope.network.chain_id_fingerprint = "ffffffff...00000000".to_owned();

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::Network,
        "simulation.divergence.network",
    );
}

/// The envelope's network passphrase fingerprint differs from simulation's
/// (network-substitution attack — sponsor steers signing toward a different
/// network than was simulated).
#[test]
fn t11c_network_passphrase_substitution_rejected() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope.network.passphrase_fingerprint = "futurenet".to_owned();

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::Network,
        "simulation.divergence.network",
    );
}

// ── sequence window mutation ───────────────────────────────────────────────────

/// The envelope's `source_account_sequence` exceeds simulation's
/// (sequence-window-violation attack — sponsor delays submission past the
/// simulated sequence).
#[test]
fn t11d_source_account_sequence_drift_rejected() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope.sequence.source_account_sequence += 1;

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::Sequence,
        "simulation.divergence.sequence",
    );
}

/// The envelope's `min_sequence_number` differs from simulation's
/// (sequence-fence substitution).
#[test]
fn t11d_min_sequence_number_substitution_rejected() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope.sequence.min_sequence_number = Some(0);

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::Sequence,
        "simulation.divergence.sequence",
    );
}

// ── fee envelope mutation ─────────────────────────────────────────────────────

/// The envelope's `resource_fee` differs from simulation's (fee
/// substitution — sponsor inflates the resource fee at signing time).
#[test]
fn t11e_resource_fee_substitution_rejected() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope.fee_envelope.resource_fee += 1;

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::FeeEnvelope,
        "simulation.divergence.fee_envelope",
    );
}

/// The envelope's `tx_fee` differs from simulation's (transaction
/// fee substitution).
#[test]
fn t11e_tx_fee_substitution_rejected() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope.fee_envelope.tx_fee += 1;

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::FeeEnvelope,
        "simulation.divergence.fee_envelope",
    );
}

// ── Comparator ordering regression-lock ───────────────────────────────────────

/// The divergence detector's comparison order is documented at
/// `signing/divergence.rs:104-105` as "context-rule IDs, auth contexts,
/// network, sequence, then fee envelope" with "first mismatch wins". A
/// future refactor that re-orders the comparisons would change which
/// sub-code fires when multiple fields diverge simultaneously. This test
/// asserts the documented ordering: when ALL 5 fields diverge, only
/// `ContextRuleIds` is reported.
#[test]
fn t11_comparator_ordering_context_rule_ids_fires_first() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope.context_rule_ids = vec![ContextRuleId::new(99)];
    envelope.auth_contexts = vec![AuthContextFingerprint::new("invoke:ffffeeee".to_owned())];
    envelope.network.ledger_protocol_version += 1;
    envelope.sequence.source_account_sequence += 1;
    envelope.fee_envelope.resource_fee += 1;

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::ContextRuleIds,
        "simulation.divergence.context_rule_ids",
    );
}

/// Without `context_rule_ids` divergence, `auth_contexts` fires next.
#[test]
fn t11_comparator_ordering_auth_contexts_fires_second() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope.auth_contexts = vec![AuthContextFingerprint::new("invoke:ffffeeee".to_owned())];
    envelope.network.ledger_protocol_version += 1;
    envelope.sequence.source_account_sequence += 1;
    envelope.fee_envelope.resource_fee += 1;

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::AuthContexts,
        "simulation.divergence.auth_contexts",
    );
}

/// Without `context_rule_ids` or `auth_contexts` divergence, `network`
/// fires next.
#[test]
fn t11_comparator_ordering_network_fires_third() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope.network.ledger_protocol_version += 1;
    envelope.sequence.source_account_sequence += 1;
    envelope.fee_envelope.resource_fee += 1;

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::Network,
        "simulation.divergence.network",
    );
}

/// With only `sequence` and `fee_envelope` divergence, `sequence` fires.
#[test]
fn t11_comparator_ordering_sequence_fires_fourth() {
    let (simulation, mut envelope) = baseline_contexts();
    envelope.sequence.source_account_sequence += 1;
    envelope.fee_envelope.resource_fee += 1;

    let result = detect_simulation_divergence(&simulation, &envelope);
    assert_sub_code_and_wire_code(
        result,
        &SimulationDivergenceSubCode::Sequence,
        "simulation.divergence.sequence",
    );
}

// The 5th comparator-ordering position (FeeEnvelope-last) is exercised by
// the single-mutation tests `t11e_resource_fee_substitution_rejected` and
// `t11e_tx_fee_substitution_rejected` above — when ONLY `fee_envelope`
// diverges (no prior axes), the comparator necessarily reaches FeeEnvelope
// last. Adding a "fires_fifth" ordering test would duplicate those single-
// mutation tests.
