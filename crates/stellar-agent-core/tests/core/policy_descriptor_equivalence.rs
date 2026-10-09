//! Descriptor-read vs args-read equivalence for the migrated pay/create value
//! criteria.
//!
//! Step 2 of the value-descriptor migration flips `per_tx_cap`,
//! `per_period_cap`, `minimum_reserve`, and `counterparty_allowlist` to read
//! the typed value leg (derived at the gate from `args`) instead of parsing
//! `args` directly, for `stellar_pay` / `stellar_create_account` only. These
//! tests pin that the descriptor-read decision equals the decision the same
//! `args` imply, at the representative allow/deny boundaries the brief calls
//! out (cap boundary, reserve, allowlist hit/miss). The full per-criterion
//! suite (which encodes the args → decision expectations) passing unchanged is
//! the broader neutrality proof; this file is the focused demonstration.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; panics acceptable in integration tests"
)]

use serde_json::{Value, json};

use stellar_agent_core::policy::v1::criteria::Criterion;
use stellar_agent_core::policy::v1::criteria::counterparty_allowlist::{
    CounterpartyAllowlistCriterion, CounterpartyKind,
};
use stellar_agent_core::policy::v1::criteria::minimum_reserve::MinimumReserveCriterion;
use stellar_agent_core::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
use stellar_agent_core::policy::v1::criteria::per_tx_cap::PerTxCapCriterion;
use stellar_agent_core::policy::v1::value::derive_value_class;
use stellar_agent_core::policy::v1::{
    AccountReserveLookupError, AccountReservesView, EvalContext, PolicyStateStore,
};
use stellar_agent_core::policy::{Decision, DenyReason, McpToolRegistration, ToolDescriptor};
use stellar_agent_core::profile::schema::Profile;

const G_ALLOWED: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const G_DENIED: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

fn tool(name: &'static str) -> ToolDescriptor {
    ToolDescriptor::from_registration(&McpToolRegistration {
        name,
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: stellar_agent_core::policy::ToolValueKind::MovesValue,
    })
}

fn profile() -> Profile {
    Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
}

/// Builds a ctx whose value is derived from `args` exactly as the dispatch gate
/// derives it — the descriptor-read path under test.
fn descriptor_ctx<'a>(
    tool: &'a ToolDescriptor,
    args: &'a Value,
    profile: &'a Profile,
    store: &'a PolicyStateStore,
) -> EvalContext<'a> {
    EvalContext::new(tool, args, "alice", profile, store)
        .with_value(derive_value_class(tool.name.as_str(), args))
}

#[derive(Debug)]
struct MockAccountView {
    balance: i64,
    subentries: i64,
}

impl AccountReservesView for MockAccountView {
    fn reserves_stroops(&self, base_reserve: i64) -> i64 {
        (2 + self.subentries).saturating_mul(base_reserve)
    }
    fn balance_stroops(&self) -> Result<i64, AccountReserveLookupError> {
        Ok(self.balance)
    }
}

// ── per_tx_cap ────────────────────────────────────────────────────────────────

#[test]
fn per_tx_cap_pay_under_cap_allows() {
    let tool = tool("stellar_pay");
    let profile = profile();
    let store = PolicyStateStore::new();
    let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
    let args =
        json!({ "amount_stroops": "500000000", "asset": "native", "destination": G_ALLOWED });
    let ctx = descriptor_ctx(&tool, &args, &profile, &store);
    assert!(
        criterion.evaluate(&ctx).unwrap().is_none(),
        "50 XLM under a 100 XLM cap must allow via the derived descriptor"
    );
}

#[test]
fn per_tx_cap_pay_over_cap_denies() {
    let tool = tool("stellar_pay");
    let profile = profile();
    let store = PolicyStateStore::new();
    let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000);
    let args =
        json!({ "amount_stroops": "1500000000", "asset": "native", "destination": G_ALLOWED });
    let ctx = descriptor_ctx(&tool, &args, &profile, &store);
    assert!(
        matches!(
            criterion.evaluate(&ctx).unwrap(),
            Some(DenyReason::PerTxCapExceeded { .. })
        ),
        "150 XLM over a 100 XLM cap must deny via the derived descriptor"
    );
}

#[test]
fn per_tx_cap_pay_at_cap_boundary_allows() {
    let tool = tool("stellar_pay");
    let profile = profile();
    let store = PolicyStateStore::new();
    let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000);
    let args =
        json!({ "amount_stroops": "1000000000", "asset": "native", "destination": G_ALLOWED });
    let ctx = descriptor_ctx(&tool, &args, &profile, &store);
    assert!(
        criterion.evaluate(&ctx).unwrap().is_none(),
        "amount == cap is an inclusive bound and must allow"
    );
}

#[test]
fn per_tx_cap_create_over_cap_denies() {
    let tool = tool("stellar_create_account");
    let profile = profile();
    let store = PolicyStateStore::new();
    let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000);
    let args = json!({ "starting_balance_stroops": "1500000000", "destination": G_ALLOWED });
    let ctx = descriptor_ctx(&tool, &args, &profile, &store);
    assert!(
        matches!(
            criterion.evaluate(&ctx).unwrap(),
            Some(DenyReason::PerTxCapExceeded { .. })
        ),
        "150 XLM create over a 100 XLM native cap must deny"
    );
}

// ── per_period_cap ────────────────────────────────────────────────────────────

#[test]
fn per_period_cap_pay_over_cap_denies() {
    // per_period_cap shares the sole_value_leg read path with per_tx_cap; on an
    // empty window the period total is the attempted amount alone, so an
    // over-cap pay must deny purely on the derived leg amount.
    let tool = tool("stellar_pay");
    let profile = profile();
    let store = PolicyStateStore::new();
    let criterion =
        PerPeriodCapCriterion::new("native".into(), Window::parse("1d").unwrap(), 1_000_000_000);
    let args =
        json!({ "amount_stroops": "1500000000", "asset": "native", "destination": G_ALLOWED });
    let ctx = descriptor_ctx(&tool, &args, &profile, &store);
    assert!(
        matches!(
            criterion.evaluate(&ctx).unwrap(),
            Some(DenyReason::PerPeriodCapExceeded { .. })
        ),
        "150 XLM over a 100 XLM/day cap must deny via the derived descriptor"
    );
}

// ── minimum_reserve ───────────────────────────────────────────────────────────

#[test]
fn minimum_reserve_pay_above_reserve_allows() {
    let tool = tool("stellar_pay");
    let profile = profile();
    let store = PolicyStateStore::new();
    let criterion = MinimumReserveCriterion::new(5_000_000);
    let view = MockAccountView {
        balance: 2_000_000_000,
        subentries: 0,
    };
    let args =
        json!({ "amount_stroops": "1000000000", "asset": "native", "destination": G_ALLOWED });
    let ctx = descriptor_ctx(&tool, &args, &profile, &store).with_account_view(&view);
    assert!(
        criterion.evaluate(&ctx).unwrap().is_none(),
        "200 XLM balance sending 100 XLM must pass the reserve check"
    );
}

#[test]
fn minimum_reserve_pay_breach_denies() {
    let tool = tool("stellar_pay");
    let profile = profile();
    let store = PolicyStateStore::new();
    let criterion = MinimumReserveCriterion::new(5_000_000);
    let view = MockAccountView {
        balance: 120_000_000, // 12 XLM
        subentries: 0,
    };
    let args =
        json!({ "amount_stroops": "110000000", "asset": "native", "destination": G_ALLOWED });
    let ctx = descriptor_ctx(&tool, &args, &profile, &store).with_account_view(&view);
    assert!(
        matches!(
            criterion.evaluate(&ctx).unwrap(),
            Some(DenyReason::MinimumReserveBreached { .. })
        ),
        "the real debit from the derived leg must breach the reserve"
    );
}

// ── counterparty_allowlist ────────────────────────────────────────────────────

#[test]
fn counterparty_allowlist_g_account_hit_allows() {
    let tool = tool("stellar_pay");
    let profile = profile();
    let store = PolicyStateStore::new();
    let criterion = CounterpartyAllowlistCriterion::new(
        vec![CounterpartyKind::GAccount],
        vec![G_ALLOWED.into()],
    );
    let args =
        json!({ "amount_stroops": "100000000", "asset": "native", "destination": G_ALLOWED });
    let ctx = descriptor_ctx(&tool, &args, &profile, &store);
    assert!(
        criterion.evaluate(&ctx).unwrap().is_none(),
        "an allowlisted destination read from the derived leg must allow"
    );
}

#[test]
fn counterparty_allowlist_g_account_miss_denies() {
    let tool = tool("stellar_pay");
    let profile = profile();
    let store = PolicyStateStore::new();
    let criterion = CounterpartyAllowlistCriterion::new(
        vec![CounterpartyKind::GAccount],
        vec![G_ALLOWED.into()],
    );
    let args = json!({ "amount_stroops": "100000000", "asset": "native", "destination": G_DENIED });
    let ctx = descriptor_ctx(&tool, &args, &profile, &store);
    assert!(
        matches!(
            criterion.evaluate(&ctx).unwrap(),
            Some(DenyReason::CounterpartyDenied { .. })
        ),
        "a non-allowlisted destination read from the derived leg must deny"
    );
}

// ── engine-level parity (rule decision) ───────────────────────────────────────

/// The whole-engine decision for a configured native cap denies an over-cap
/// pay exactly as the criterion does, exercising the engine's own derivation
/// (the criterion never sees `args` for the amount).
#[test]
fn engine_derives_descriptor_and_denies_over_cap_pay() {
    use stellar_agent_core::policy::PolicyEngine;
    use stellar_agent_core::policy::v1::PolicyEngineV1;
    use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};

    let rule = PolicyRule {
        r#match: RuleMatch {
            tool: "stellar_pay".into(),
            chain: "*".into(),
        },
        criteria: vec![Box::new(PerTxCapCriterion::new(
            "native".into(),
            1_000_000_000,
        ))],
        decision: Decision::Allow,
        allow_opaque_signing: false,
    };
    let doc = PolicyDocument {
        version: 1,
        scope: ScopeId::AllProfiles,
        rules: vec![rule],
        signature: None,
    };
    let engine = PolicyEngineV1::new(doc, "alice".into());
    let profile = profile();
    let t = tool("stellar_pay");

    let args =
        json!({ "amount_stroops": "1500000000", "asset": "native", "destination": G_ALLOWED });
    let decision = engine
        .evaluate(&t, &args, &profile, None, None, None, None, None)
        .unwrap();
    assert!(
        matches!(
            decision,
            Decision::Deny(DenyReason::PerTxCapExceeded { .. })
        ),
        "engine must derive the value descriptor and deny the over-cap pay: {decision:?}"
    );
}
