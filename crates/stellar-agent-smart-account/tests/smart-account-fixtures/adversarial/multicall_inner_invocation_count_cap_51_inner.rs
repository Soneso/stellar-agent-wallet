//! Adversarial fixture: `multicall_inner_invocation_count_cap_51_inner`.
//!
//! Regression-locks the inner-invocation-count amplification defence: a
//! 51-inner bundle against a 50-cap criterion MUST be denied with
//! `DenyReason::InnerInvocationCountCapExceeded` via
//! `PolicyEngineV1::evaluate_bundle` dispatch (bundle-level evaluation).
//! Together with the boundary cases at 49/50/51 this also locks the
//! documented strict-greater-than-cap semantics from
//! `inner_invocation_count_cap.rs` (`if count > self.max_count`).
//!
//! # Coverage relationship to inline unit tests at `inner_invocation_count_cap.rs`
//!
//! The criterion module's inline tests cover the same boundary cases
//! (`count_over_cap_denies` at 51, `count_exactly_at_cap_passes` at 50,
//! `count_under_cap_passes` at 5). This adversarial fixture differs in
//! three ways:
//!
//! 1. **Amplification threat framing.** The inner-invocation-count cap
//!    defends against multicall amplification; the inline tests are
//!    kind-named only. This fixture's name + module rustdoc bind the test
//!    to the threat.
//! 2. **End-to-end dispatch via `PolicyEngineV1::evaluate_bundle`.** The
//!    inline tests call `criterion.evaluate(&ctx)` directly, bypassing the
//!    bundle-level dispatch + `is_bundle_level()` filtering. A refactor
//!    that breaks the bundle-level dispatch (e.g., skipping bundle-level
//!    evaluation for bundle-level criteria) would silently pass the inline
//!    tests but fail this fixture.
//! 3. **Discoverability.** Lives under
//!    `tests/smart-account-fixtures/adversarial/`.
//!
//! # Defence-in-depth relationship to host-side
//! `MULTICALL_BUNDLE_CAP` cap-check
//!
//! An independent host-side cap-check in `multicall.rs` fires BEFORE
//! policy evaluation. Even if the policy's `inner_invocation_count_cap`
//! criterion is omitted or raised to (say) 100, the host-side cap rejects
//! bundles with >50 inners. The two layers cover different failure modes:
//! - Policy-criterion path (this fixture): operator misconfigures cap.
//! - Host-side path: regression that loosens the trust-anchor ceiling.
//!
//! # Defence scope
//!
//! Inner-invocation-count cap enforcement: multicall amplification
//! defence via `PolicyEngineV1::evaluate_bundle`.

use serde_json::Value;
use stellar_agent_core::policy::v1::PolicyEngineV1;
use stellar_agent_core::policy::v1::bundle::{BundleStateOverlay, BundleView, InnerOpDescriptor};
use stellar_agent_core::policy::v1::criteria::inner_invocation_count_cap::InnerInvocationCountCapCriterion;
use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
use stellar_agent_core::policy::{Decision, DenyReason, McpToolRegistration, ToolDescriptor};
use stellar_agent_core::profile::schema::Profile;

const PROFILE_NAME: &str = "alice";

fn make_tool() -> ToolDescriptor {
    ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_multicall",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
    })
}

fn make_profile() -> Profile {
    Profile::builder_testnet(PROFILE_NAME, "acct", "n-svc", "n-acct").build()
}

fn generic_inner() -> InnerOpDescriptor {
    InnerOpDescriptor::Generic {
        target: "C-strkey".to_owned(),
        fn_name: "transfer".to_owned(),
    }
}

fn make_inners(count: usize) -> Vec<InnerOpDescriptor> {
    (0..count).map(|_| generic_inner()).collect()
}

fn build_engine_with_cap(max_count: u32) -> PolicyEngineV1 {
    let doc = PolicyDocument {
        version: 1,
        scope: ScopeId::Profile(PROFILE_NAME.into()),
        rules: vec![PolicyRule {
            r#match: RuleMatch {
                tool: "stellar_multicall".into(),
                chain: "*".into(),
            },
            criteria: vec![Box::new(InnerInvocationCountCapCriterion { max_count })],
            decision: Decision::Allow,
        }],
        signature: None,
    };
    PolicyEngineV1::new(doc, PROFILE_NAME.into())
}

// ── 51-inner amplification deny (canonical) ───────────────────────────────────

/// 51 inners vs cap=50 fires `InnerInvocationCountCapExceeded` via
/// `evaluate_bundle` dispatch.
#[test]
fn t9_51_inner_bundle_denied_via_evaluate_bundle() {
    let engine = build_engine_with_cap(50);
    let tool = make_tool();
    let profile = make_profile();
    let args = Value::Null;
    let inners = make_inners(51);
    let overlay = BundleStateOverlay::default();
    let view = BundleView {
        inners: &inners,
        overlay: &overlay,
    };

    let decision = engine
        .evaluate_bundle(&tool, &args, &profile, &view)
        .expect("evaluate_bundle must not error on count-cap deny");

    match decision {
        Decision::Deny(DenyReason::InnerInvocationCountCapExceeded { max, attempted }) => {
            assert_eq!(max, 50, "deny reason must carry max=50");
            assert_eq!(
                attempted, 51,
                "deny reason must carry attempted=51 (observed inner count)",
            );
        }
        other => panic!("expected Deny(InnerInvocationCountCapExceeded); got {other:?}"),
    }
}

// ── Boundary discipline (49/50/51) ────────────────────────────────────────────

/// Boundary minus 1 (49 inners vs cap=50) passes via `evaluate_bundle`.
#[test]
fn boundary_49_inner_bundle_allowed_via_evaluate_bundle() {
    let engine = build_engine_with_cap(50);
    let tool = make_tool();
    let profile = make_profile();
    let args = Value::Null;
    let inners = make_inners(49);
    let overlay = BundleStateOverlay::default();
    let view = BundleView {
        inners: &inners,
        overlay: &overlay,
    };

    let decision = engine
        .evaluate_bundle(&tool, &args, &profile, &view)
        .expect("evaluate_bundle must not error on count-cap pass");

    assert!(
        matches!(decision, Decision::Allow),
        "49 inners vs cap=50 must Allow; got {decision:?}",
    );
}

/// Boundary exactly at cap (50 inners vs cap=50) passes via `evaluate_bundle`
/// per strict-greater-than-cap semantics (`count > max_count` is the deny condition).
#[test]
fn boundary_50_inner_bundle_allowed_via_evaluate_bundle() {
    let engine = build_engine_with_cap(50);
    let tool = make_tool();
    let profile = make_profile();
    let args = Value::Null;
    let inners = make_inners(50);
    let overlay = BundleStateOverlay::default();
    let view = BundleView {
        inners: &inners,
        overlay: &overlay,
    };

    let decision = engine
        .evaluate_bundle(&tool, &args, &profile, &view)
        .expect("evaluate_bundle must not error on boundary case");

    assert!(
        matches!(decision, Decision::Allow),
        "50 inners vs cap=50 must Allow (strict > boundary); got {decision:?}",
    );
}
