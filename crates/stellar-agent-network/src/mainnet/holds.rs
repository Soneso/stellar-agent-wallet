//! Classified hold sizing for evaluations of one payment.

use stellar_agent_core::policy::v1::criteria::state_store::{WindowEntry, compose_window_entries};
use stellar_agent_core::policy::v1::{PolicyEngineV1, ValueClass};
use stellar_agent_core::policy::{Evaluation, PolicyError, ToolDescriptor};
use stellar_agent_core::profile::schema::Profile;

/// The value an evaluation permits: its evaluated effects, or read-only
/// when it carries none. Checking and sizing both read it.
#[must_use]
pub fn value_class(evaluation: &Evaluation) -> ValueClass {
    evaluation
        .value_effects
        .clone()
        .map_or(ValueClass::ReadOnly, ValueClass::Value)
}

/// Sizes each descriptor with its own evaluated effects before composing holds.
///
/// The caller must check that each evaluation permits the same payment and
/// comes from the same engine and captured policy instant. Recipient classes
/// stay attached to their evaluation. `None` preserves singleton accounting.
/// The result is input to atomic mint admission and conveys no authority.
///
/// # Errors
/// Returns the criterion sizing error or an inconsistent-composition error.
pub fn size_evaluated_holds(
    engine: &PolicyEngineV1,
    profile: &Profile,
    routed: (&ToolDescriptor, &Evaluation),
    outer: Option<(&ToolDescriptor, &Evaluation)>,
    now_ms: u64,
) -> Result<Vec<WindowEntry>, PolicyError> {
    let size = |(tool, evaluation): (&ToolDescriptor, &Evaluation)| {
        engine.size_window_entries(tool, profile, &value_class(evaluation), now_ms)
    };
    let routed = size(routed)?;
    let outer = outer.map(size).transpose()?;
    compose_window_entries(&routed, outer.as_deref())
}
