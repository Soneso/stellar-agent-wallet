//! Privately owned state and borrowed observations for one policy instant.

use super::ToolDescriptor;
use super::v1::{
    AccountIdentityView, AccountReservesView, CounterpartyCacheView, PolicyStateStore,
    Sep10SessionView, Sep45SessionView, ValueClass,
};
use crate::profile::schema::Profile;

/// A private window image evaluated at one fixed policy instant.
///
/// Ownership consumes the hydrated store, leaving no external writer. Queries
/// retain the store's exposure, epoch and rolling-window semantics. This image
/// does not reserve headroom; durable admission must still recheck it.
#[derive(Debug)]
pub struct PolicyEvaluationSnapshot {
    pub(super) state: PolicyStateStore,
    now_ms: u64,
}

impl PolicyEvaluationSnapshot {
    /// Takes ownership of state hydrated at `now_ms`.
    #[must_use]
    pub fn new(state: PolicyStateStore, now_ms: u64) -> Self {
        Self { state, now_ms }
    }

    /// The instant used by hydration and every criterion in this image.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }
}

/// Immutable, descriptor-specific observations for a snapshot evaluation.
pub struct PolicyEvaluationInputs<'a> {
    /// The descriptor being evaluated.
    pub tool: &'a ToolDescriptor,
    /// Validated arguments for this descriptor.
    pub args: &'a serde_json::Value,
    /// Active profile.
    pub profile: &'a Profile,
    /// Already derived value, or `None` to derive it from the arguments.
    pub value: Option<ValueClass>,
    /// Source reserve observation.
    pub account_view: Option<&'a dyn AccountReservesView>,
    /// Destination identity observation.
    pub identity_view: Option<&'a dyn AccountIdentityView>,
    /// Frozen counterparty bindings; `None` means unavailable.
    pub counterparty_cache: Option<&'a dyn CounterpartyCacheView>,
    /// SEP-10 sessions.
    pub sep10_sessions: Option<&'a dyn Sep10SessionView>,
    /// SEP-45 sessions.
    pub sep45_sessions: Option<&'a dyn Sep45SessionView>,
    /// Whether account-dependent criteria may defer to final resolution.
    pub provisional: bool,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::mainnet::decision::{
        EvaluationScope, MainnetEvaluationRequest, evaluate_mainnet_in_snapshot,
    };
    use crate::mainnet::verified_policy::VerifiedPolicy;
    use crate::policy::v1::criteria::per_period_cap::Window;
    use crate::policy::v1::criteria::state_store::StateKey;
    use crate::policy::v1::criteria::{
        Criterion, PerPeriodCapCriterion, RateLimitCriterion, TotalBudgetCriterion,
    };
    use crate::policy::v1::{PolicyDocument, PolicyEngineV1, PolicyRule, RuleMatch, ScopeId};
    use crate::policy::{Decision, McpToolRegistration, PolicyEngine, ToolValueKind};
    use std::sync::{Arc, Barrier};

    #[test]
    #[serial_test::serial]
    fn snapshot_keeps_state_time_and_verified_provenance() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        const NOW: u64 = 4_000_000_000_000;
        let profile = Profile::builder_testnet("frame", "account", "nonce", "key").build();
        let tool = ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_pay",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: ToolValueKind::MovesValue,
        });
        let args = serde_json::json!({"asset": "native", "amount_stroops": "10"});
        let epoch = crate::mainnet::verified_policy::policy_digest(b"snapshot");
        for kind in ["count", "amount", "exposure", "epoch"] {
            let key = StateKey::new(
                "frame",
                1,
                match kind {
                    "count" => "rate_limit",
                    "epoch" => "total:native",
                    _ => "native",
                },
                if kind == "epoch" { 0 } else { 60 },
            );
            let seed = |state: &PolicyStateStore| match kind {
                "epoch" => {
                    state.append_epoch(&key, NOW - 1, 80, epoch).unwrap();
                    state.append_epoch(&key, NOW - 1, 900, [2; 32]).unwrap();
                }
                "exposure" => state
                    .append_exposure(
                        &key,
                        NOW - 120_000,
                        80,
                        "retained",
                        Some(NOW - 1),
                        Some(NOW + 60_000),
                    )
                    .unwrap(),
                "count" => state.append(&key, NOW - 60_000, 1).unwrap(),
                _ => state.append(&key, NOW - 60_000, 80).unwrap(),
            };
            let criterion: Box<dyn Criterion> = match kind {
                "count" => Box::new(RateLimitCriterion::new(Window::parse("1m").unwrap(), 2)),
                "epoch" => Box::new(TotalBudgetCriterion::new("native".into(), 100)),
                _ => Box::new(PerPeriodCapCriterion::new(
                    "native".into(),
                    Window::parse("1m").unwrap(),
                    100,
                )),
            };
            let engine = Arc::new(PolicyEngineV1::new_verified(
                PolicyDocument {
                    version: 1,
                    scope: ScopeId::AllProfiles,
                    signature: None,
                    rules: vec![PolicyRule {
                        r#match: RuleMatch {
                            tool: "stellar_pay".into(),
                            chain: "*".into(),
                        },
                        criteria: vec![criterion],
                        decision: Decision::Allow,
                        allow_opaque_signing: false,
                    }],
                },
                "frame".into(),
                PolicyStateStore::new(),
                b"snapshot",
            ));
            seed(engine.state_store());
            let state = PolicyStateStore::new();
            seed(&state);
            let snapshot = PolicyEvaluationSnapshot::new(state, NOW);
            let policy = VerifiedPolicy::from_verified(
                7,
                b"snapshot",
                [8; 32],
                Arc::clone(&engine),
                None,
                None,
            );
            assert_eq!(policy.contract_transfer_max_fee_stroops(), None);
            let evaluate = |snapshot: &PolicyEvaluationSnapshot| {
                evaluate_mainnet_in_snapshot(
                    &policy,
                    EvaluationScope::Classic,
                    snapshot,
                    MainnetEvaluationRequest {
                        chain_id: "stellar:testnet",
                        tool: &tool,
                        args: &args,
                        profile: &profile,
                        value: None,
                        account_view: None,
                        identity_view: None,
                        counterparty_cache: None,
                        sep10_sessions: None,
                        sep45_sessions: None,
                    },
                )
            };
            let first = evaluate(&snapshot).unwrap();
            assert_eq!(first.decision(), &Decision::Allow, "{kind}");
            let barrier = Arc::new(Barrier::new(2));
            std::thread::scope(|scope| {
                let updated = Arc::clone(&barrier);
                let engine = Arc::clone(&engine);
                let key = &key;
                scope.spawn(move || {
                    if kind == "epoch" {
                        engine
                            .state_store()
                            .append_epoch(key, NOW, 100, epoch)
                            .unwrap();
                    } else {
                        engine.state_store().append(key, NOW, 100).unwrap();
                        engine.state_store().append(key, NOW, 100).unwrap();
                    }
                    updated.wait();
                });
                barrier.wait();
            });
            let second = evaluate(&snapshot);
            assert_eq!(
                second.as_ref().map(|decision| decision.decision()).ok(),
                Some(first.decision()),
                "captured decision: {kind}"
            );
            let second = second.unwrap();
            assert_eq!(second.evaluated_at_ms(), NOW);
            assert_eq!(second.policy_digest(), policy.digest());
            assert_eq!(second.policy_sequence(), 7);
            assert_eq!(second.rule_index(), 0);
            assert_eq!(second.value_effects(), first.value_effects());
            assert!(
                matches!(
                    engine
                        .evaluate_full(&tool, &args, &profile, None, None, None, None, None, NOW)
                        .unwrap()
                        .decision,
                    Decision::Deny(_)
                ),
                "fresh state: {kind}"
            );
            if matches!(kind, "count" | "amount") {
                assert_eq!(
                    snapshot.state.query_window(&key, NOW).unwrap(),
                    (if kind == "count" { 1 } else { 80 }, 1)
                );
                let next = PolicyStateStore::new();
                seed(&next);
                assert_eq!(next.query_window(&key, NOW + 1).unwrap(), (0, 0));
            }
            if kind == "epoch" {
                assert_eq!(snapshot.state.query_epoch(&key, epoch).unwrap(), (80, 1));
                assert_eq!(snapshot.state.query_epoch(&key, [2; 32]).unwrap(), (900, 1));
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn snapshot_default_refuses_stateful_engines() {
        use crate::policy::PolicyError;
        struct Engine(Option<PolicyStateStore>);
        impl PolicyEngine for Engine {
            fn evaluate(
                &self,
                _: &ToolDescriptor,
                _: &serde_json::Value,
                _: &Profile,
                _: Option<&dyn AccountReservesView>,
                _: Option<&dyn AccountIdentityView>,
                _: Option<&dyn CounterpartyCacheView>,
                _: Option<&dyn Sep10SessionView>,
                _: Option<&dyn Sep45SessionView>,
                _: u64,
            ) -> Result<Decision, PolicyError> {
                Ok(Decision::Allow)
            }
            fn window_state_store(&self) -> Option<&PolicyStateStore> {
                self.0.as_ref()
            }
        }
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let profile = Profile::builder_testnet("frame", "account", "nonce", "key").build();
        let tool = ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_balances",
            destructive_hint: false,
            read_only_hint: true,
            chain_id_required: true,
            value_kind: ToolValueKind::ReadOnly,
        });
        let snapshot = PolicyEvaluationSnapshot::new(PolicyStateStore::new(), 123);
        let run = |engine: &Engine, provisional| {
            engine.evaluate_in_snapshot(
                PolicyEvaluationInputs {
                    tool: &tool,
                    args: &serde_json::Value::Null,
                    profile: &profile,
                    value: None,
                    account_view: None,
                    identity_view: None,
                    counterparty_cache: None,
                    sep10_sessions: None,
                    sep45_sessions: None,
                    provisional,
                },
                &snapshot,
            )
        };
        assert_eq!(run(&Engine(None), false).unwrap().decision, Decision::Allow);
        assert!(matches!(
            run(&Engine(Some(PolicyStateStore::new())), false),
            Err(PolicyError::Internal { .. })
        ));
        assert!(matches!(
            run(&Engine(None), true),
            Err(PolicyError::Internal { detail })
                if detail == "provisional snapshot evaluation requires an explicit value"
        ));
    }
}
