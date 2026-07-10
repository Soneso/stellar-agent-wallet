//! Shared helper for building a real (in-memory) `PolicyEngineV1` with a
//! `minimum_reserve` rule, for integration tests that need the ACTUAL engine
//! (not `MockPolicyEngine`, which ignores `account_view`/`identity_view`).
//!
//! Mirrors `trustline_classic_testnet_acceptance.rs`'s `minimum_reserve_document`
//! helper, generalised for reuse across pay/claim/create_account fixtures.

use stellar_agent_core::policy::Decision;
use stellar_agent_core::policy::v1::PolicyEngineV1;
use stellar_agent_core::policy::v1::criteria::{Criterion, MinimumReserveCriterion};
use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};

/// Builds a `PolicyEngineV1` with ONE `Decision::Allow` `minimum_reserve` rule
/// per tool name in `tools`, matched on `chain = "*"`.
///
/// `dispatch_gate_with_views` is invoked with the literal tool name at each
/// dispatch point (e.g. `"stellar_pay"` at simulate, `"stellar_pay_commit"` at
/// commit), so both must be covered for the commit step to see the SAME rule
/// simulate saw. `MinimumReserveCriterion::evaluate` fails closed
/// (`PolicyError::CriterionEvaluationFailed`) whenever `ctx.account_view` is
/// `None` — reaching `Decision::Allow` at a given dispatch point is direct
/// proof that call site supplied a real `account_view`.
#[allow(
    dead_code,
    reason = "shared integration-test helper; each test binary uses a subset"
)]
#[must_use]
pub fn minimum_reserve_engine(tools: &[&str], margin_stroops: i64) -> PolicyEngineV1 {
    let rules = tools
        .iter()
        .map(|tool| {
            let criterion: Box<dyn Criterion> =
                Box::new(MinimumReserveCriterion::new(margin_stroops));
            PolicyRule {
                r#match: RuleMatch {
                    tool: (*tool).to_owned(),
                    chain: "*".to_owned(),
                },
                criteria: vec![criterion],
                decision: Decision::Allow,
                allow_opaque_signing: false,
            }
        })
        .collect();
    let document = PolicyDocument {
        version: 1,
        scope: ScopeId::AllProfiles,
        rules,
        signature: None,
    };
    PolicyEngineV1::new(document, "default".into())
}
