//! Pre-signing simulation-divergence detection for smart-account auth entries.
//!
//! The detector compares a narrow, redaction-safe projection of the trusted
//! simulation result against the envelope-to-be-signed. It aborts signing before
//! signature bytes are produced when the two views diverge.

use stellar_agent_core::smart_account::rule_id::ContextRuleId;

use crate::SaError;
use crate::error::SimulationDivergenceSubCode;

/// Narrow projection of the simulation result used for pre-signing comparison.
///
/// Binds the simulated context-rule IDs to the envelope that will be signed.
/// Refuses Soroban auth-entry signing when simulation and submission context diverge.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SimulationContext {
    /// Rule IDs returned or selected during simulation, in auth-context order.
    pub context_rule_ids: Vec<ContextRuleId>,
    /// Redacted per-auth-context fingerprints, in invocation order.
    pub auth_contexts: Vec<AuthContextFingerprint>,
    /// Redacted network identity for the simulation view.
    pub network: NetworkContext,
    /// Source-account sequence window for the simulation view.
    pub sequence: SequenceContext,
    /// Fee envelope fields for the simulation view.
    pub fee_envelope: FeeEnvelopeContext,
}

/// Narrow projection of the envelope-to-be-signed used for divergence checks.
///
/// Binds the submitted context-rule IDs to the simulated context.
/// Refuses Soroban auth-entry signing when simulation and submission context diverge.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnvelopeContext {
    /// Rule IDs embedded into the envelope-to-be-signed, in auth-context order.
    pub context_rule_ids: Vec<ContextRuleId>,
    /// Redacted per-auth-context fingerprints, in invocation order.
    pub auth_contexts: Vec<AuthContextFingerprint>,
    /// Redacted network identity for the envelope view.
    pub network: NetworkContext,
    /// Source-account sequence window for the envelope view.
    pub sequence: SequenceContext,
    /// Fee envelope fields for the envelope view.
    pub fee_envelope: FeeEnvelopeContext,
}

/// Redacted fingerprint of one Soroban auth context.
///
/// The value is an operator-safe attribution token, not raw auth-context XDR.
/// Callers should pass a first-8-last-8 hash or equivalent short label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthContextFingerprint(String);

impl AuthContextFingerprint {
    /// Creates a redaction-safe auth-context fingerprint.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Returns the fingerprint string as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Redacted network identity fields used by the divergence detector.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkContext {
    /// Short passphrase or network-hash attribution label.
    pub passphrase_fingerprint: String,
    /// Soroban protocol or ledger protocol version used during simulation.
    pub ledger_protocol_version: u32,
    /// First-8-last-8 chain-id hash attribution label.
    pub chain_id_fingerprint: String,
}

/// Source-account sequence window used by the divergence detector.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SequenceContext {
    /// Source-account sequence number observed before signing.
    pub source_account_sequence: i64,
    /// Minimum sequence number accepted by the envelope, if one is present.
    pub min_sequence_number: Option<i64>,
}

/// Fee fields that must not change between simulation and signing.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct FeeEnvelopeContext {
    /// Transaction fee field.
    pub tx_fee: u32,
    /// Soroban resource fee or fee-bump resource fee field.
    pub resource_fee: u32,
}

/// Detects pre-signing simulation divergence.
///
/// Compares the simulation result's contextual fields against the
/// envelope-to-be-signed. First mismatch wins in deterministic order:
/// context-rule IDs, auth contexts, network, sequence, then fee envelope.
///
/// # Errors
///
/// Returns [`SaError::SimulationDivergence`] when a compared field differs.
pub fn detect_simulation_divergence(
    simulation: &SimulationContext,
    envelope: &EnvelopeContext,
) -> Result<(), SaError> {
    if simulation.context_rule_ids != envelope.context_rule_ids {
        return Err(divergence(
            SimulationDivergenceSubCode::ContextRuleIds,
            format!(
                "simulation rule_ids={}, envelope rule_ids={}",
                format_rule_ids(&simulation.context_rule_ids),
                format_rule_ids(&envelope.context_rule_ids)
            ),
        ));
    }

    if simulation.auth_contexts != envelope.auth_contexts {
        return Err(divergence(
            SimulationDivergenceSubCode::AuthContexts,
            format!(
                "auth_contexts differ: simulation_count={}, envelope_count={}",
                simulation.auth_contexts.len(),
                envelope.auth_contexts.len()
            ),
        ));
    }

    if simulation.network != envelope.network {
        return Err(divergence(
            SimulationDivergenceSubCode::Network,
            "network identity differs between simulation and envelope".to_owned(),
        ));
    }

    if simulation.sequence != envelope.sequence {
        return Err(divergence(
            SimulationDivergenceSubCode::Sequence,
            "sequence window differs between simulation and envelope".to_owned(),
        ));
    }

    if simulation.fee_envelope != envelope.fee_envelope {
        return Err(divergence(
            SimulationDivergenceSubCode::FeeEnvelope,
            "fee envelope differs between simulation and envelope".to_owned(),
        ));
    }

    Ok(())
}

fn divergence(sub_code: SimulationDivergenceSubCode, redacted_reason: String) -> SaError {
    SaError::SimulationDivergence {
        sub_code,
        redacted_reason,
    }
}

fn format_rule_ids(rule_ids: &[ContextRuleId]) -> String {
    let joined = rule_ids
        .iter()
        .map(|id| id.as_u32().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{joined}]")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only proptest strategy setup")]

    use proptest::prelude::*;

    use super::*;

    fn base_contexts() -> (SimulationContext, EnvelopeContext) {
        let simulation = SimulationContext {
            context_rule_ids: vec![ContextRuleId::new(42)],
            auth_contexts: vec![AuthContextFingerprint::new("invoke:abcd1234".to_owned())],
            network: NetworkContext {
                passphrase_fingerprint: "testnet".to_owned(),
                ledger_protocol_version: 23,
                chain_id_fingerprint: "00112233...aabbccdd".to_owned(),
            },
            sequence: SequenceContext {
                source_account_sequence: 100,
                min_sequence_number: Some(99),
            },
            fee_envelope: FeeEnvelopeContext {
                tx_fee: 100,
                resource_fee: 1000,
            },
        };
        let envelope = EnvelopeContext {
            context_rule_ids: simulation.context_rule_ids.clone(),
            auth_contexts: simulation.auth_contexts.clone(),
            network: simulation.network.clone(),
            sequence: simulation.sequence.clone(),
            fee_envelope: simulation.fee_envelope.clone(),
        };
        (simulation, envelope)
    }

    fn assert_sub_code(result: Result<(), SaError>, expected: &SimulationDivergenceSubCode) {
        assert!(
            matches!(
                result,
                Err(SaError::SimulationDivergence { sub_code, .. }) if sub_code == *expected
            ),
            "expected SimulationDivergence::{expected:?}",
        );
    }

    #[test]
    fn identical_contexts_are_ok() {
        let (simulation, envelope) = base_contexts();
        assert!(detect_simulation_divergence(&simulation, &envelope).is_ok());
    }

    #[test]
    fn context_rule_ids_mismatch_fires_first() {
        let (simulation, mut envelope) = base_contexts();
        envelope.context_rule_ids = vec![ContextRuleId::new(7)];
        assert_sub_code(
            detect_simulation_divergence(&simulation, &envelope),
            &SimulationDivergenceSubCode::ContextRuleIds,
        );
    }

    #[test]
    fn auth_contexts_mismatch_fires() {
        let (simulation, mut envelope) = base_contexts();
        envelope.auth_contexts = vec![AuthContextFingerprint::new("invoke:ffffeeee".to_owned())];
        assert_sub_code(
            detect_simulation_divergence(&simulation, &envelope),
            &SimulationDivergenceSubCode::AuthContexts,
        );
    }

    #[test]
    fn network_mismatch_fires() {
        let (simulation, mut envelope) = base_contexts();
        envelope.network.ledger_protocol_version += 1;
        assert_sub_code(
            detect_simulation_divergence(&simulation, &envelope),
            &SimulationDivergenceSubCode::Network,
        );
    }

    #[test]
    fn sequence_mismatch_fires() {
        let (simulation, mut envelope) = base_contexts();
        envelope.sequence.source_account_sequence += 1;
        assert_sub_code(
            detect_simulation_divergence(&simulation, &envelope),
            &SimulationDivergenceSubCode::Sequence,
        );
    }

    #[test]
    fn fee_envelope_mismatch_fires() {
        let (simulation, mut envelope) = base_contexts();
        envelope.fee_envelope.resource_fee += 1;
        assert_sub_code(
            detect_simulation_divergence(&simulation, &envelope),
            &SimulationDivergenceSubCode::FeeEnvelope,
        );
    }

    fn context_strategy() -> impl Strategy<Value = SimulationContext> {
        (
            prop::collection::vec(any::<u32>(), 0..8),
            prop::collection::vec("[a-f0-9]{8}", 0..8),
            "[a-z0-9 -]{1,32}",
            any::<u32>(),
            "[a-f0-9]{8}\\.\\.\\.[a-f0-9]{8}",
            any::<i64>(),
            prop::option::of(any::<i64>()),
            any::<u32>(),
            any::<u32>(),
        )
            .prop_map(
                |(
                    rule_ids,
                    auth_contexts,
                    passphrase_fingerprint,
                    ledger_protocol_version,
                    chain_id_fingerprint,
                    source_account_sequence,
                    min_sequence_number,
                    tx_fee,
                    resource_fee,
                )| SimulationContext {
                    context_rule_ids: rule_ids.into_iter().map(ContextRuleId::new).collect(),
                    auth_contexts: auth_contexts
                        .into_iter()
                        .map(AuthContextFingerprint::new)
                        .collect(),
                    network: NetworkContext {
                        passphrase_fingerprint,
                        ledger_protocol_version,
                        chain_id_fingerprint,
                    },
                    sequence: SequenceContext {
                        source_account_sequence,
                        min_sequence_number,
                    },
                    fee_envelope: FeeEnvelopeContext {
                        tx_fee,
                        resource_fee,
                    },
                },
            )
    }

    fn envelope_from(simulation: &SimulationContext) -> EnvelopeContext {
        EnvelopeContext {
            context_rule_ids: simulation.context_rule_ids.clone(),
            auth_contexts: simulation.auth_contexts.clone(),
            network: simulation.network.clone(),
            sequence: simulation.sequence.clone(),
            fee_envelope: simulation.fee_envelope.clone(),
        }
    }

    proptest! {
        #[test]
        fn identical_projections_never_false_positive(simulation in context_strategy()) {
            let envelope = envelope_from(&simulation);
            prop_assert!(detect_simulation_divergence(&simulation, &envelope).is_ok());
        }
    }
}

/// Test-only constructors for the divergence-detector's non-exhaustive
/// projection types. External integration tests (under `tests/`) cannot
/// use struct expressions to build `SimulationContext` / `EnvelopeContext`
/// because both are `#[non_exhaustive]`; this module exposes baseline
/// builders so adversarial fixtures can construct + mutate them via the
/// existing public field-access surface.
///
/// Gated under `#[cfg(any(test, feature = "test-helpers"))]` to prevent
/// test-only construction helpers from appearing in production builds.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::{
        AuthContextFingerprint, ContextRuleId, EnvelopeContext, FeeEnvelopeContext, NetworkContext,
        SequenceContext, SimulationContext,
    };

    /// Returns a baseline non-adversarial `SimulationContext` for use in
    /// divergence-detector adversarial fixtures. Callers should mutate the
    /// returned value to construct adversarial sub-cases.
    #[must_use]
    pub fn baseline_simulation_context() -> SimulationContext {
        SimulationContext {
            context_rule_ids: vec![ContextRuleId::new(42)],
            auth_contexts: vec![AuthContextFingerprint::new("invoke:abcd1234".to_owned())],
            network: NetworkContext {
                passphrase_fingerprint: "testnet".to_owned(),
                ledger_protocol_version: 23,
                chain_id_fingerprint: "00112233...aabbccdd".to_owned(),
            },
            sequence: SequenceContext {
                source_account_sequence: 100,
                min_sequence_number: Some(99),
            },
            fee_envelope: FeeEnvelopeContext {
                tx_fee: 100,
                resource_fee: 1000,
            },
        }
    }

    /// Returns an `EnvelopeContext` whose fields exactly match `simulation`.
    /// Callers should mutate the returned value to construct adversarial
    /// sub-cases.
    #[must_use]
    pub fn matching_envelope_context(simulation: &SimulationContext) -> EnvelopeContext {
        EnvelopeContext {
            context_rule_ids: simulation.context_rule_ids.clone(),
            auth_contexts: simulation.auth_contexts.clone(),
            network: simulation.network.clone(),
            sequence: simulation.sequence.clone(),
            fee_envelope: simulation.fee_envelope.clone(),
        }
    }
}
