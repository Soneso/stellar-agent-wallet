//! The authority a mainnet action proceeds under: an operator approval, or
//! the verified policy's own decision.
//!
//! [`MainnetAuthority::from_decision`] is the one way from a
//! [`MainnetDecision`] to an authority. An `Allow` without an approval
//! witness becomes [`MainnetAuthority::Policy`]; a decision with a witness
//! becomes [`MainnetAuthority::Approval`]; an approval requirement without a
//! witness is [`AuthorityError::ApprovalRequired`] and never policy
//! authority. The factory reads no clock: the policy authority governs from
//! the decision's evaluation instant for the decision's governing lifetime.
//!
//! A [`PolicyAuthority`] has private fields and is neither copied nor
//! persisted, like the approval witness:
//!
//! ```compile_fail,E0451
//! use stellar_agent_network::mainnet::authority::PolicyAuthority;
//! fn forge(p: PolicyAuthority) -> PolicyAuthority { PolicyAuthority { ..p } }
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authority::PolicyAuthority;
//! fn need<T: Clone>() {}
//! need::<PolicyAuthority>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authority::PolicyAuthority;
//! fn need<T: serde::Serialize>() {}
//! need::<PolicyAuthority>();
//! ```
//!
//! The import alone resolves:
//!
//! ```
//! use stellar_agent_network::mainnet::authority::PolicyAuthority;
//! fn need(_: Option<PolicyAuthority>) {}
//! need(None);
//! ```

use stellar_agent_core::approval::witness::{ApprovalExpectation, ApprovalWitness};
use stellar_agent_core::mainnet::decision::{AuthorityScope, MainnetDecision, MainnetRefusal};
use stellar_agent_core::policy::Decision;

use crate::policy_state::PolicyAuthorityBinding;

/// The authority one mainnet action proceeds under.
#[derive(Debug)]
pub enum MainnetAuthority<'w> {
    /// The verified policy allowed the action without an approval.
    Policy(PolicyAuthority),
    /// The operator approved the action.
    Approval(&'w ApprovalWitness),
}

/// An `Allow` decision of the verified policy, as authority for one action.
///
/// It records the decision's provenance and the end of the authority it
/// grants, `governing_until_ms`: the evaluation instant plus the decision's
/// governing lifetime. Only [`MainnetAuthority::from_decision`] produces one.
#[derive(Debug)]
pub struct PolicyAuthority {
    policy_digest: [u8; 32],
    policy_sequence: i64,
    rule_index: u32,
    profile: String,
    chain_id: String,
    evaluated_at_ms: u64,
    governing_until_ms: u64,
    scope: AuthorityScope,
}

impl PolicyAuthority {
    /// The BLAKE3 digest of the verified policy that decided.
    #[must_use]
    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    /// The signed sequence of that policy.
    #[must_use]
    pub fn policy_sequence(&self) -> i64 {
        self.policy_sequence
    }

    /// The zero-based document position of the deciding rule.
    #[must_use]
    pub fn rule_index(&self) -> u32 {
        self.rule_index
    }

    /// The profile the policy decided for.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The CAIP-2 chain the policy decided for.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// The evaluation instant, in Unix milliseconds.
    #[must_use]
    pub fn evaluated_at_ms(&self) -> u64 {
        self.evaluated_at_ms
    }

    /// The end of the authority, in Unix milliseconds; the authority holds
    /// strictly before it.
    #[must_use]
    pub fn governing_until_ms(&self) -> u64 {
        self.governing_until_ms
    }

    /// The scope the decision covers.
    #[must_use]
    pub fn scope(&self) -> &AuthorityScope {
        &self.scope
    }

    /// The binding an authorization record persists for this authority.
    #[must_use]
    pub fn binding(&self) -> PolicyAuthorityBinding {
        PolicyAuthorityBinding {
            policy_digest: self.policy_digest,
            policy_sequence: self.policy_sequence,
            rule_index: self.rule_index,
            evaluated_at_ms: self.evaluated_at_ms,
            governing_until_ms: self.governing_until_ms,
            scope: self.scope.clone(),
        }
    }
}

/// Why a decision gives no authority.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    /// The decision requires an approval and none was presented.
    #[error("the policy decision requires an approval")]
    ApprovalRequired,
    /// The decision cannot be authority: a decision this build does not
    /// map, or a governing end that overflows.
    #[error("mainnet authority internal error: {detail}")]
    Internal {
        /// Non-secret diagnostic.
        detail: String,
    },
}

/// Why an action that needs mainnet authority does not have it.
///
/// `E` is the refusal of the caller's own gate.
#[derive(Debug)]
pub enum AuthorityRefusal<E> {
    /// The decision requires an approval of `expectation`, which the caller
    /// asks the operator for.
    ApprovalRequired {
        /// What the approval must approve.
        expectation: ApprovalExpectation,
    },
    /// The caller's gate refused.
    Gate(E),
    /// The mainnet evaluation produced no decision.
    Refusal(MainnetRefusal),
    /// The decision gives no authority.
    Internal(AuthorityError),
}

impl<'w> MainnetAuthority<'w> {
    /// The authority `decision` gives, with the approval `witness` when one
    /// was presented.
    ///
    /// | Decision | Witness | Authority |
    /// |---|---|---|
    /// | `Allow` | none | [`MainnetAuthority::Policy`] |
    /// | `Allow` or `RequireApproval` | present | [`MainnetAuthority::Approval`] |
    /// | `RequireApproval` | none | [`AuthorityError::ApprovalRequired`] |
    /// | any other | either | [`AuthorityError::Internal`] |
    ///
    /// The policy authority governs until the decision's evaluation instant
    /// plus its governing lifetime. The factory takes no time input.
    ///
    /// # Errors
    ///
    /// [`AuthorityError::ApprovalRequired`] for an approval requirement
    /// without a witness, and [`AuthorityError::Internal`] for any other
    /// decision or a governing end that overflows `u64`.
    pub fn from_decision(
        decision: &MainnetDecision,
        witness: Option<&'w ApprovalWitness>,
    ) -> Result<Self, AuthorityError> {
        match (decision.decision(), witness) {
            (Decision::Allow, None) => {
                let governing_until_ms = decision
                    .evaluated_at_ms()
                    .checked_add(decision.governing_ttl_ms())
                    .ok_or_else(|| AuthorityError::Internal {
                        detail: "the governing end overflows".to_owned(),
                    })?;
                Ok(Self::Policy(PolicyAuthority {
                    policy_digest: decision.policy_digest(),
                    policy_sequence: decision.policy_sequence(),
                    rule_index: decision.rule_index(),
                    profile: decision.profile().to_owned(),
                    chain_id: decision.chain_id().to_owned(),
                    evaluated_at_ms: decision.evaluated_at_ms(),
                    governing_until_ms,
                    scope: decision.scope().clone(),
                }))
            }
            (Decision::Allow | Decision::RequireApproval(_), Some(witness)) => {
                Ok(Self::Approval(witness))
            }
            (Decision::RequireApproval(_), None) => Err(AuthorityError::ApprovalRequired),
            _ => Err(AuthorityError::Internal {
                detail: "the policy decision gives no mainnet authority".to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]

    use super::*;
    use stellar_agent_core::policy::{ApprovalRequest, DenyReason};

    const EVALUATED: u64 = 1_900_000_000_000;

    fn decision(kind: Decision, evaluated_at_ms: u64, ttl_ms: u64) -> MainnetDecision {
        MainnetDecision::for_test(
            kind,
            None,
            [4; 32],
            9,
            2,
            "main",
            "stellar:pubnet",
            evaluated_at_ms,
            ttl_ms,
            AuthorityScope::X402Authenticated {
                home_domain: "pay.example.org".to_owned(),
                tool: "stellar_x402_authenticated_payment".to_owned(),
            },
        )
    }

    fn require_approval() -> Decision {
        Decision::RequireApproval(ApprovalRequest::new(String::new(), 300))
    }

    /// An approval requirement without a witness is never policy authority.
    #[test]
    fn witness_free_require_approval_is_not_policy_authority() {
        let required = decision(require_approval(), EVALUATED, 300_000);
        assert_eq!(
            MainnetAuthority::from_decision(&required, None).unwrap_err(),
            AuthorityError::ApprovalRequired
        );
    }

    /// An approval witness makes the authority an approval for both
    /// permitting decisions.
    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial]
    fn a_witness_gives_approval_authority() {
        let fixture = crate::mainnet::fixtures::ResolverFixture::new();
        let witness = fixture.approval(&fixture.envelope, fixture.now, 600_000);
        for kind in [Decision::Allow, require_approval()] {
            let decided = decision(kind, EVALUATED, 600_000);
            match MainnetAuthority::from_decision(&decided, Some(&witness)).unwrap() {
                MainnetAuthority::Approval(approval) => {
                    assert!(std::ptr::eq(approval, &witness));
                }
                MainnetAuthority::Policy(_) => panic!("a witness gives approval authority"),
            }
        }
    }

    /// An `Allow` without a witness is policy authority carrying the
    /// decision's provenance, governing until the evaluation instant plus the
    /// bounded governing lifetime.
    #[test]
    fn allow_without_witness_is_policy_authority_until_the_bounded_lifetime() {
        let mut allowed = decision(Decision::Allow, EVALUATED, 600_000);
        allowed.bound_governing_ttl(90_000);
        let MainnetAuthority::Policy(policy) =
            MainnetAuthority::from_decision(&allowed, None).unwrap()
        else {
            panic!("an allow without a witness is policy authority");
        };
        assert_eq!(policy.governing_until_ms(), EVALUATED + 90_000);
        assert_eq!(policy.policy_digest(), [4; 32]);
        assert_eq!(policy.policy_sequence(), 9);
        assert_eq!(policy.rule_index(), 2);
        assert_eq!(policy.profile(), "main");
        assert_eq!(policy.chain_id(), "stellar:pubnet");
        assert_eq!(policy.evaluated_at_ms(), EVALUATED);
        assert_eq!(policy.scope(), allowed.scope());
        assert_eq!(
            policy.binding(),
            PolicyAuthorityBinding {
                policy_digest: [4; 32],
                policy_sequence: 9,
                rule_index: 2,
                evaluated_at_ms: EVALUATED,
                governing_until_ms: EVALUATED + 90_000,
                scope: allowed.scope().clone(),
            }
        );
    }

    /// A governing end past `u64::MAX` and a denial are internal errors.
    #[test]
    fn overflow_and_denial_are_internal() {
        let overflowing = decision(Decision::Allow, u64::MAX - 10, 600_000);
        assert!(matches!(
            MainnetAuthority::from_decision(&overflowing, None),
            Err(AuthorityError::Internal { .. })
        ));
        let denied = decision(Decision::Deny(DenyReason::ExplicitRuleDeny), EVALUATED, 0);
        assert!(matches!(
            MainnetAuthority::from_decision(&denied, None),
            Err(AuthorityError::Internal { .. })
        ));
    }
}
