//! The provenance-bearing mainnet policy decision.
//!
//! [`evaluate_mainnet`] evaluates one call against a [`VerifiedPolicy`] at
//! one supplied instant and returns a [`MainnetDecision`]: the engine's
//! decision together with the facts that name where it came from (policy
//! digest and sequence, the deciding rule's document position, profile,
//! chain, evaluation instant, governing lifetime and scope). A denial, an
//! engine failure and a clock failure are a [`MainnetRefusal`] and never a
//! decision.
//!
//! A [`MainnetDecision`] has private fields and no public constructor outside
//! test builds, so holding one means [`evaluate_mainnet`] produced it from a
//! verified policy.
//!
//! [`evaluate_mainnet`]: crate::mainnet::decision::evaluate_mainnet
//! [`VerifiedPolicy`]: crate::mainnet::verified_policy::VerifiedPolicy
//! [`MainnetDecision`]: crate::mainnet::decision::MainnetDecision
//! [`MainnetRefusal`]: crate::mainnet::decision::MainnetRefusal

use crate::approval::governing_ttl_ms;
use crate::mainnet::verified_policy::VerifiedPolicy;
use crate::policy::v1::{
    AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
    Sep45SessionView, ValueClass, ValueEffects,
};
use crate::policy::{Decision, DenyReason, PolicyEngine, PolicyError, ToolDescriptor};
use crate::profile::schema::Profile;
use crate::wallet::WalletLifecycleError;

/// The scope an evaluation is made for.
///
/// `Classic` covers every write whose authority binds to its own transaction.
/// `X402Authenticated` covers the authenticated x402 flow, whose challenge
/// message is signed for one home domain by one tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationScope {
    /// A write whose authority binds to its own transaction.
    Classic,
    /// An authenticated x402 payment for `home_domain`, made by `tool`.
    X402Authenticated {
        /// The validated home domain of the paywalled resource.
        home_domain: String,
        /// The tool that makes the payment.
        tool: String,
    },
}

/// The scope a [`MainnetDecision`] grants authority for; the scope of the
/// evaluation that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityScope {
    /// A write whose authority binds to its own transaction.
    Classic,
    /// An authenticated x402 payment for `home_domain`, made by `tool`.
    X402Authenticated {
        /// The validated home domain of the paywalled resource.
        home_domain: String,
        /// The tool that makes the payment.
        tool: String,
    },
}

impl From<EvaluationScope> for AuthorityScope {
    fn from(scope: EvaluationScope) -> Self {
        match scope {
            EvaluationScope::Classic => Self::Classic,
            EvaluationScope::X402Authenticated { home_domain, tool } => {
                Self::X402Authenticated { home_domain, tool }
            }
        }
    }
}

/// Why a mainnet evaluation produced no decision.
#[derive(Debug)]
pub enum MainnetRefusal {
    /// The policy denied the call. `rule_index` is the document position of
    /// the deciding rule, and `None` for the default-deny when no rule
    /// matches.
    Denied {
        /// The document position of the denying rule.
        rule_index: Option<u32>,
        /// The typed denial.
        reason: DenyReason,
    },
    /// The engine failed to evaluate.
    Engine(PolicyError),
    /// The evaluation instant could not be sampled.
    Clock(WalletLifecycleError),
}

/// The provenance a mainnet audit row records for a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MainnetProvenance {
    /// The BLAKE3 digest of the policy's canonical bytes.
    pub policy_digest: [u8; 32],
    /// The signed policy sequence.
    pub policy_sequence: i64,
    /// The document position of the deciding rule.
    pub rule_index: u32,
    /// The evaluation instant in Unix milliseconds.
    pub evaluated_at_ms: u64,
}

/// A mainnet policy decision with its provenance.
///
/// The decision is `Allow` or `RequireApproval`; [`evaluate_mainnet`] reports
/// a denial as [`MainnetRefusal::Denied`]. An engine that grows a decision
/// variant this build does not know passes it through unchanged, and the
/// consumer refuses it.
#[derive(Debug, Clone)]
pub struct MainnetDecision {
    decision: Decision,
    value_effects: Option<ValueEffects>,
    policy_digest: [u8; 32],
    policy_sequence: i64,
    rule_index: u32,
    profile: String,
    chain_id: String,
    evaluated_at_ms: u64,
    governing_ttl_ms: u64,
    scope: AuthorityScope,
}

impl MainnetDecision {
    /// The engine's decision.
    #[must_use]
    pub fn decision(&self) -> &Decision {
        &self.decision
    }

    /// The value effects the engine sized, when the call moves value.
    #[must_use]
    pub fn value_effects(&self) -> Option<&ValueEffects> {
        self.value_effects.as_ref()
    }

    /// Takes the sized value effects out of the decision.
    #[must_use]
    pub fn take_value_effects(&mut self) -> Option<ValueEffects> {
        self.value_effects.take()
    }

    /// The BLAKE3 digest of the verified policy's canonical bytes.
    #[must_use]
    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    /// The verified policy's signed sequence.
    #[must_use]
    pub fn policy_sequence(&self) -> i64 {
        self.policy_sequence
    }

    /// The zero-based document position of the deciding rule.
    #[must_use]
    pub fn rule_index(&self) -> u32 {
        self.rule_index
    }

    /// The profile the engine evaluates for.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The CAIP-2 chain the caller evaluated for.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// The evaluation instant in Unix milliseconds.
    #[must_use]
    pub fn evaluated_at_ms(&self) -> u64 {
        self.evaluated_at_ms
    }

    /// The lifetime of the authority this decision grants, in milliseconds:
    /// [`crate::approval::MAINNET_POLICY_AUTHORITY_TTL_SECONDS`] for `Allow`
    /// and the rule's approval TTL for `RequireApproval`, lowered by every
    /// [`Self::bound_governing_ttl`].
    #[must_use]
    pub fn governing_ttl_ms(&self) -> u64 {
        self.governing_ttl_ms
    }

    /// The scope the decision grants authority for.
    #[must_use]
    pub fn scope(&self) -> &AuthorityScope {
        &self.scope
    }

    /// Lowers the governing lifetime to `ttl_ms` when that is shorter. The
    /// lifetime never rises, so a paired evaluation can only narrow the
    /// authority an earlier one granted.
    pub fn bound_governing_ttl(&mut self, ttl_ms: u64) {
        self.governing_ttl_ms = self.governing_ttl_ms.min(ttl_ms);
    }

    /// The provenance an audit row records for this decision.
    #[must_use]
    pub fn provenance(&self) -> MainnetProvenance {
        MainnetProvenance {
            policy_digest: self.policy_digest,
            policy_sequence: self.policy_sequence,
            rule_index: self.rule_index,
            evaluated_at_ms: self.evaluated_at_ms,
        }
    }

    /// Builds a decision from its parts, for tests of the consumers.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments, reason = "one argument per recorded fact")]
    #[must_use]
    pub fn for_test(
        decision: Decision,
        value_effects: Option<ValueEffects>,
        policy_digest: [u8; 32],
        policy_sequence: i64,
        rule_index: u32,
        profile: &str,
        chain_id: &str,
        evaluated_at_ms: u64,
        governing_ttl_ms: u64,
        scope: AuthorityScope,
    ) -> Self {
        Self {
            decision,
            value_effects,
            policy_digest,
            policy_sequence,
            rule_index,
            profile: profile.to_owned(),
            chain_id: chain_id.to_owned(),
            evaluated_at_ms,
            governing_ttl_ms,
            scope,
        }
    }
}

/// The inputs of one mainnet evaluation besides the policy, scope and
/// instant.
///
/// `value` is `Some` for a call whose value the caller resolved from the same
/// decoded operation it signs, and `None` for a call the engine sizes from
/// `args`.
pub struct MainnetEvaluationRequest<'a> {
    /// The CAIP-2 chain the call targets.
    pub chain_id: &'a str,
    /// The descriptor of the tool being called.
    pub tool: &'a ToolDescriptor,
    /// The tool arguments the engine evaluates.
    pub args: &'a serde_json::Value,
    /// The active profile.
    pub profile: &'a Profile,
    /// The resolved value of the call, when the caller resolved it.
    pub value: Option<ValueClass>,
    /// The account reserve view for the minimum-reserve criterion.
    pub account_view: Option<&'a dyn AccountReservesView>,
    /// The account identity view for the home-domain counterparty criterion.
    pub identity_view: Option<&'a dyn AccountIdentityView>,
    /// The resolved counterparty cache for the `home_domain_resolved`
    /// criterion.
    pub counterparty_cache: Option<&'a dyn CounterpartyCacheView>,
    /// The SEP-10 session view.
    pub sep10_sessions: Option<&'a dyn Sep10SessionView>,
    /// The SEP-45 session view.
    pub sep45_sessions: Option<&'a dyn Sep45SessionView>,
}

/// Evaluates a mainnet call against `policy` at `now_ms`.
///
/// The digest, sequence and engine come from the verified policy and the
/// profile from its engine; the caller supplies the chain, the scope and the
/// remaining inputs. `now_ms` is the one instant every criterion reads, and
/// the decision records it as [`MainnetDecision::evaluated_at_ms`].
///
/// # Errors
///
/// - [`MainnetRefusal::Denied`] when the policy denies the call, with the
///   typed reason and the denying rule's position.
/// - [`MainnetRefusal::Engine`] when the engine fails, when the deciding
///   rule's position does not fit a `u32`, or when a permitting decision
///   names no rule ([`PolicyError::Internal`] for both).
pub fn evaluate_mainnet(
    policy: &VerifiedPolicy,
    scope: EvaluationScope,
    now_ms: u64,
    request: MainnetEvaluationRequest<'_>,
) -> Result<MainnetDecision, MainnetRefusal> {
    let engine_arc = policy.engine();
    let profile = engine_arc.profile_name().to_owned();
    let engine: &dyn PolicyEngine = engine_arc.as_ref();
    let evaluation = match request.value {
        Some(value) => engine.evaluate_with_value_full(
            request.tool,
            request.args,
            request.profile,
            value,
            request.account_view,
            request.identity_view,
            request.counterparty_cache,
            request.sep10_sessions,
            request.sep45_sessions,
            now_ms,
        ),
        None => engine.evaluate_full(
            request.tool,
            request.args,
            request.profile,
            request.account_view,
            request.identity_view,
            request.counterparty_cache,
            request.sep10_sessions,
            request.sep45_sessions,
            now_ms,
        ),
    }
    .map_err(MainnetRefusal::Engine)?;
    let rule_index = evaluation
        .rule_ordinal
        .map(|ordinal| {
            u32::try_from(ordinal).map_err(|_| {
                MainnetRefusal::Engine(PolicyError::Internal {
                    detail: format!("rule position {ordinal} exceeds the provenance width"),
                })
            })
        })
        .transpose()?;
    if let Decision::Deny(reason) = evaluation.decision {
        return Err(MainnetRefusal::Denied { rule_index, reason });
    }
    let Some(rule_index) = rule_index else {
        return Err(MainnetRefusal::Engine(PolicyError::Internal {
            detail: "a permitting decision names no deciding rule".to_owned(),
        }));
    };
    let governing_ttl_ms = governing_ttl_ms(&evaluation);
    Ok(MainnetDecision {
        decision: evaluation.decision,
        value_effects: evaluation.value_effects,
        policy_digest: policy.digest(),
        policy_sequence: policy.sequence(),
        rule_index,
        profile,
        chain_id: request.chain_id.to_owned(),
        evaluated_at_ms: now_ms,
        governing_ttl_ms,
        scope: scope.into(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::policy::v1::criteria::{ApprovalAboveCriterion, Criterion, PerTxCapCriterion};
    use crate::policy::v1::{PolicyDocument, PolicyEngineV1, PolicyRule, RuleMatch, ScopeId};
    use crate::policy::{ApprovalRequest, McpToolRegistration, ToolValueKind};

    const NOW: u64 = 1_900_000_000_123;

    fn rule(tool: &str, criteria: Vec<Box<dyn Criterion>>, decision: Decision) -> PolicyRule {
        PolicyRule {
            r#match: RuleMatch {
                tool: tool.into(),
                chain: "*".into(),
            },
            criteria,
            decision,
            allow_opaque_signing: false,
        }
    }

    /// Rules 0 and 1 name other tools; rule 2 is the first `stellar_pay`
    /// rule, escalating above 100 stroops and denying above 500.
    fn policy() -> VerifiedPolicy {
        let rules = vec![
            rule("stellar_claim", vec![], Decision::Allow),
            rule(
                "stellar_trustline",
                vec![],
                Decision::Deny(DenyReason::ExplicitRuleDeny),
            ),
            rule(
                "stellar_pay",
                vec![
                    Box::new(ApprovalAboveCriterion::new("native".into(), 100)),
                    Box::new(PerTxCapCriterion::new("native".into(), 500)),
                ],
                Decision::Allow,
            ),
            rule("stellar_pay", vec![], Decision::Allow),
        ];
        let engine = Arc::new(PolicyEngineV1::new(
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                rules,
                signature: None,
            },
            "main".to_owned(),
        ));
        VerifiedPolicy::from_verified(7, b"decision", [9; 32], engine, None)
    }

    fn tool(name: &'static str) -> ToolDescriptor {
        ToolDescriptor::from_registration(&McpToolRegistration {
            name,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: if name == "stellar_pay" {
                ToolValueKind::MovesValue
            } else {
                ToolValueKind::ReadOnly
            },
        })
    }

    fn profile() -> Profile {
        Profile::builder_testnet("main", "acct", "n-svc", "n-acct").build()
    }

    fn evaluate(
        policy: &VerifiedPolicy,
        name: &'static str,
        amount: i64,
        valued: bool,
    ) -> Result<MainnetDecision, MainnetRefusal> {
        let descriptor = tool(name);
        let args = json!({"amount_stroops": amount.to_string(), "asset": "native"});
        let profile = profile();
        let value =
            valued.then(|| crate::policy::v1::value::derive_value_class(&descriptor.name, &args));
        evaluate_mainnet(
            policy,
            EvaluationScope::Classic,
            NOW,
            MainnetEvaluationRequest {
                chain_id: "stellar:pubnet",
                tool: &descriptor,
                args: &args,
                profile: &profile,
                value,
                account_view: None,
                identity_view: None,
                counterparty_cache: None,
                sep10_sessions: None,
                sep45_sessions: None,
            },
        )
    }

    /// The rule index is the document position before tool filtering, on
    /// both evaluation paths, through escalation and denial; the default-deny
    /// names no rule.
    #[test]
    #[serial_test::serial]
    fn mainnet_decision_carries_the_document_ordinal() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let policy = policy();
        for valued in [false, true] {
            let allowed = evaluate(&policy, "stellar_pay", 50, valued).unwrap();
            assert_eq!(allowed.decision(), &Decision::Allow, "valued={valued}");
            assert_eq!(allowed.rule_index(), 2, "valued={valued}");

            let escalated = evaluate(&policy, "stellar_pay", 200, valued).unwrap();
            assert!(
                matches!(escalated.decision(), Decision::RequireApproval(_)),
                "valued={valued}"
            );
            assert_eq!(escalated.rule_index(), 2, "valued={valued}");

            match evaluate(&policy, "stellar_pay", 600, valued) {
                Err(MainnetRefusal::Denied {
                    rule_index: Some(2),
                    reason: DenyReason::PerTxCapExceeded { .. },
                }) => {}
                other => panic!("valued={valued}: {other:?}"),
            }

            match evaluate(&policy, "stellar_trustline", 1, valued) {
                Err(MainnetRefusal::Denied {
                    rule_index: Some(1),
                    reason: DenyReason::ExplicitRuleDeny,
                }) => {}
                other => panic!("valued={valued}: {other:?}"),
            }

            match evaluate(&policy, "stellar_create_account", 1, valued) {
                Err(MainnetRefusal::Denied {
                    rule_index: None,
                    reason: DenyReason::NoMatchingRule,
                }) => {}
                other => panic!("valued={valued}: {other:?}"),
            }
        }
    }

    /// The decision records the verified policy's facts, the engine's
    /// profile, the caller's chain and scope, the supplied instant, and the
    /// governing lifetime of its decision kind.
    #[test]
    #[serial_test::serial]
    fn mainnet_decision_records_its_provenance() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let policy = policy();
        let allowed = evaluate(&policy, "stellar_pay", 50, false).unwrap();
        assert_eq!(allowed.policy_digest(), policy.digest());
        assert_eq!(allowed.policy_sequence(), 7);
        assert_eq!(allowed.profile(), "main");
        assert_eq!(allowed.chain_id(), "stellar:pubnet");
        assert_eq!(allowed.evaluated_at_ms(), NOW);
        assert_eq!(allowed.governing_ttl_ms(), 600_000);
        assert_eq!(allowed.scope(), &AuthorityScope::Classic);
        assert!(allowed.value_effects().is_some());
        assert_eq!(
            allowed.provenance(),
            MainnetProvenance {
                policy_digest: policy.digest(),
                policy_sequence: 7,
                rule_index: 2,
                evaluated_at_ms: NOW,
            }
        );

        let escalated = evaluate(&policy, "stellar_pay", 200, false).unwrap();
        let Decision::RequireApproval(request) = escalated.decision() else {
            panic!("expected an approval requirement");
        };
        assert_eq!(
            escalated.governing_ttl_ms(),
            u64::from(request.ttl_seconds) * 1_000
        );

        let descriptor = tool("stellar_pay");
        let args = json!({"amount_stroops": "50", "asset": "native"});
        let profile = profile();
        let scoped = evaluate_mainnet(
            &policy,
            EvaluationScope::X402Authenticated {
                home_domain: "pay.example.org".to_owned(),
                tool: "stellar_x402_authenticated_payment".to_owned(),
            },
            NOW,
            MainnetEvaluationRequest {
                chain_id: "stellar:pubnet",
                tool: &descriptor,
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
        .unwrap();
        assert_eq!(
            scoped.scope(),
            &AuthorityScope::X402Authenticated {
                home_domain: "pay.example.org".to_owned(),
                tool: "stellar_x402_authenticated_payment".to_owned(),
            }
        );
    }

    /// An engine failure is `Engine`, never a decision.
    #[test]
    #[serial_test::serial]
    fn an_engine_failure_is_an_engine_refusal() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let policy = policy();
        let descriptor = tool("stellar_pay");
        let profile = profile();
        let refusal = evaluate_mainnet(
            &policy,
            EvaluationScope::Classic,
            NOW,
            MainnetEvaluationRequest {
                chain_id: "stellar:pubnet",
                tool: &descriptor,
                args: &serde_json::Value::Null,
                profile: &profile,
                value: None,
                account_view: None,
                identity_view: None,
                counterparty_cache: None,
                sep10_sessions: None,
                sep45_sessions: None,
            },
        )
        .unwrap_err();
        assert!(matches!(refusal, MainnetRefusal::Engine(_)), "{refusal:?}");
    }

    /// `bound_governing_ttl` lowers the lifetime to the minimum and never
    /// raises it.
    #[test]
    fn bound_governing_ttl_never_raises() {
        let mut decision = MainnetDecision::for_test(
            Decision::RequireApproval(ApprovalRequest::new(String::new(), 300)),
            None,
            [1; 32],
            3,
            0,
            "main",
            "stellar:pubnet",
            NOW,
            300_000,
            AuthorityScope::Classic,
        );
        decision.bound_governing_ttl(600_000);
        assert_eq!(decision.governing_ttl_ms(), 300_000);
        decision.bound_governing_ttl(120_000);
        assert_eq!(decision.governing_ttl_ms(), 120_000);
        decision.bound_governing_ttl(u64::MAX);
        assert_eq!(decision.governing_ttl_ms(), 120_000);
        decision.bound_governing_ttl(0);
        assert_eq!(decision.governing_ttl_ms(), 0);
    }

    /// Every evaluation scope maps to the authority scope of the same shape.
    #[test]
    fn evaluation_scope_maps_to_the_same_authority_scope() {
        assert_eq!(
            AuthorityScope::from(EvaluationScope::Classic),
            AuthorityScope::Classic
        );
        assert_eq!(
            AuthorityScope::from(EvaluationScope::X402Authenticated {
                home_domain: "a.example".to_owned(),
                tool: "t".to_owned(),
            }),
            AuthorityScope::X402Authenticated {
                home_domain: "a.example".to_owned(),
                tool: "t".to_owned(),
            }
        );
    }
}
