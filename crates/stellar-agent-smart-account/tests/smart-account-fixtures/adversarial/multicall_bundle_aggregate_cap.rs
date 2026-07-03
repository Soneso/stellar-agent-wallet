//! Adversarial fixture: `multicall_bundle_aggregate_cap`.
//!
//! Regression-locks the split-and-scatter aggregate-cap defence:
//! a bundle of N small-individually but large-aggregate transfers MUST
//! be denied with `DenyReason::BundleAggregateCapExceeded` via
//! `PolicyEngineV1::evaluate_bundle` dispatch. The threat is the
//! "split-and-scatter" attack: each individual transfer is under the
//! per-tx cap, but the aggregate over the bundle exceeds the
//! operator-configured aggregate cap.
//!
//! # CAP-0033 stroop scale citation
//!
//! Per the Stellar protocol native-asset precision (CAP-0033):
//! `1 XLM = 10^7 stroops`. The SAC `transfer` ABI accepts the amount
//! in stroop-scale `i128`. This fixture uses USDC (a wrapped SAC token)
//! at unscaled `i128` units to avoid coupling to the native-asset
//! stroop scale; the aggregate cap is set in the same unscaled units.
//! XLM/stroops serve as a canonical example; the fixture's USDC variant
//! is equivalent for the bundle-level aggregate-cap criterion's contract
//! (`asset` field selects which token to sum; sums are unscaled `i128`
//! regardless of token).
//!
//! Reference for stroop constant: `stellar-baselib` constants module
//! (verify exact path at upstream-version-bump time per memory
//! `feedback_byte_layout_canonical_citation.md`).
//!
//! # Coverage relationship to inline tests at `bundle_aggregate_cap.rs`
//!
//! The criterion module has inline tests covering aggregate sum
//! semantics. This adversarial fixture adds:
//! 1. **Split-and-scatter threat framing** — discoverability under
//!    `adversarial/`.
//! 2. **End-to-end dispatch via `PolicyEngineV1::evaluate_bundle`** —
//!    inline tests call `criterion.evaluate(&ctx)` directly; this fixture
//!    exercises the bundle-level dispatch with `is_bundle_level()`
//!    filtering, regression-locking the dispatch separation.
//!
//! # Defence scope
//!
//! Bundle-level aggregate-cap enforcement: split-and-scatter amplification
//! defence via `PolicyEngineV1::evaluate_bundle`.

use serde_json::Value;
use stellar_agent_core::policy::v1::PolicyEngineV1;
use stellar_agent_core::policy::v1::bundle::{BundleStateOverlay, BundleView, InnerOpDescriptor};
use stellar_agent_core::policy::v1::criteria::bundle_aggregate_cap::BundleAggregateCapCriterion;
use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
use stellar_agent_core::policy::{Decision, DenyReason, McpToolRegistration, ToolDescriptor};
use stellar_agent_core::profile::schema::Profile;

const PROFILE_NAME: &str = "alice";
/// Canonical wrapped-SAC asset key matching the inline-tests pattern in
/// `bundle_aggregate_cap.rs`.
const USDC_ASSET: &str = "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
/// Sender G-strkey (deterministic fixture).
const ADDR_FROM: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
/// Recipient G-strkey (deterministic fixture).
const ADDR_TO: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

fn make_tool() -> ToolDescriptor {
    ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_multicall",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
    })
}

fn make_profile() -> Profile {
    Profile::builder_testnet(PROFILE_NAME, "acct", "n-svc", "n-acct").build()
}

fn token_transfer(asset: &str, amount: i128) -> InnerOpDescriptor {
    InnerOpDescriptor::TokenTransfer {
        asset: asset.to_owned(),
        from: ADDR_FROM.to_owned(),
        to: ADDR_TO.to_owned(),
        amount,
    }
}

fn build_engine_with_aggregate_cap(asset: &str, max_amount: i128) -> PolicyEngineV1 {
    let doc = PolicyDocument {
        version: 1,
        scope: ScopeId::Profile(PROFILE_NAME.into()),
        rules: vec![PolicyRule {
            r#match: RuleMatch {
                tool: "stellar_multicall".into(),
                chain: "*".into(),
            },
            criteria: vec![Box::new(BundleAggregateCapCriterion {
                asset: Some(asset.into()),
                max_amount,
            })],
            decision: Decision::Allow,
        }],
        signature: None,
    };
    PolicyEngineV1::new(doc, PROFILE_NAME.into())
}

// ── Split-and-scatter (10 × 5_000_000_000 = 50_000_000_000 vs cap=40_000_000_000) ──

/// Split-and-scatter canonical — 10 small transfers summing 50_000_000_000
/// vs cap 40_000_000_000 fires `BundleAggregateCapExceeded`.
///
/// Each individual transfer (5_000_000_000) is below the cap (it's just
/// 12.5% of cap), but the sum across the bundle exceeds the cap by 25%.
/// This is the split-and-scatter pattern the bundle-aggregate-cap
/// criterion defends against.
#[test]
fn t2_split_and_scatter_10x5b_denied_via_evaluate_bundle() {
    let engine = build_engine_with_aggregate_cap(USDC_ASSET, 40_000_000_000);
    let tool = make_tool();
    let profile = make_profile();
    let args = Value::Null;
    let inners: Vec<InnerOpDescriptor> = (0..10)
        .map(|_| token_transfer(USDC_ASSET, 5_000_000_000))
        .collect();
    let overlay = BundleStateOverlay::default();
    let view = BundleView {
        inners: &inners,
        overlay: &overlay,
    };

    let decision = engine
        .evaluate_bundle(&tool, &args, &profile, &view)
        .expect("evaluate_bundle must not error on aggregate-cap deny");

    match decision {
        Decision::Deny(DenyReason::BundleAggregateCapExceeded { max, sum, .. }) => {
            assert_eq!(
                max, 40_000_000_000,
                "deny reason must carry max=40_000_000_000"
            );
            assert_eq!(
                sum, 50_000_000_000,
                "deny reason must carry sum=50_000_000_000 (10x5_000_000_000)",
            );
        }
        other => panic!("expected Deny(BundleAggregateCapExceeded); got {other:?}"),
    }
}

// ── Below-cap allow (defensive-side: pre-attack threshold) ────────────────────

/// Bundle of 4 transfers summing 20_000_000_000 vs cap 40_000_000_000
/// is below cap and must Allow. Defensive companion to the deny test —
/// regression-locks against a criterion that always denies regardless
/// of sum.
#[test]
fn below_cap_4x5b_allowed_via_evaluate_bundle() {
    let engine = build_engine_with_aggregate_cap(USDC_ASSET, 40_000_000_000);
    let tool = make_tool();
    let profile = make_profile();
    let args = Value::Null;
    let inners: Vec<InnerOpDescriptor> = (0..4)
        .map(|_| token_transfer(USDC_ASSET, 5_000_000_000))
        .collect();
    let overlay = BundleStateOverlay::default();
    let view = BundleView {
        inners: &inners,
        overlay: &overlay,
    };

    let decision = engine
        .evaluate_bundle(&tool, &args, &profile, &view)
        .expect("evaluate_bundle must not error on aggregate-cap pass");

    assert!(
        matches!(decision, Decision::Allow),
        "sum=20_000_000_000 < cap=40_000_000_000 must Allow; got {decision:?}",
    );
}

// ── Exactly-at-cap boundary (strict > semantics) ──────────────────────────────

/// Bundle summing exactly the cap value (40_000_000_000) is allowed per
/// strict-greater-than-cap semantics (`sum > max_amount` is the deny condition).
#[test]
fn boundary_exactly_at_cap_allowed_via_evaluate_bundle() {
    let engine = build_engine_with_aggregate_cap(USDC_ASSET, 40_000_000_000);
    let tool = make_tool();
    let profile = make_profile();
    let args = Value::Null;
    let inners = vec![token_transfer(USDC_ASSET, 40_000_000_000)];
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
        "sum == max_amount must Allow (strict > boundary); got {decision:?}",
    );
}
