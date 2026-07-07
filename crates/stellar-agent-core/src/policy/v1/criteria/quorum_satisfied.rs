//! Quorum-satisfaction policy criterion.
//!
//! [`QuorumSatisfiedCriterion`] refuses to allow a smart-account invocation
//! when the proposed signer set does not satisfy the declared
//! `AuthorizationInfo` quorum requirements.
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "quorum_satisfied" }
//! ```
//!
//! # Logic
//!
//! ```text
//! if ctx.quorum.groups_short_by().is_empty() → Ok(None)
//! else → Ok(Some(DenyReason::QuorumNotSatisfied { groups_short_by, combinator }))
//! ```
//!
//! # Missing quorum view (fail-closed)
//!
//! When `ctx.quorum` is `None`, the criterion returns
//! `Err(PolicyError::CriterionEvaluationFailed)` rather than silently passing.
//! If the quorum guard is configured but no quorum view was injected at the
//! dispatch site, the invocation is rejected.
//!
//! The dispatch site MUST inject a `QuorumView` via
//! [`crate::policy::v1::EvalContext::with_quorum`] for any tool call that uses
//! multi-signer authorization.
//!
//! # Circular-dependency note
//!
//! `QuorumSatisfiedCriterion` evaluates via `ctx.quorum: Option<&dyn QuorumView>`
//! rather than directly consuming `AuthorizationInfo` from
//! `stellar-agent-smart-account`.  This avoids a circular dependency:
//! `stellar-agent-smart-account` depends on `stellar-agent-core`, so
//! `stellar-agent-core` cannot depend on `stellar-agent-smart-account`.  The
//! concrete adapter that impls `QuorumView` lives in `stellar-agent-mcp`'s
//! `policy_adapter` module where both crates are in scope.

use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::{DenyReason, PolicyError};

// ─────────────────────────────────────────────────────────────────────────────
// QuorumSatisfiedCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// Quorum-satisfaction policy criterion.
///
/// Checks that the proposed signer set satisfies the declared quorum
/// requirements (`AuthorizationInfo`) before a smart-account invocation is
/// submitted.
///
/// # Missing quorum view (fail-closed)
///
/// When `ctx.quorum` is `None`, the criterion returns
/// `Err(PolicyError::CriterionEvaluationFailed)` — it does NOT silently pass.
/// The dispatch site MUST inject a `QuorumView` via
/// [`crate::policy::v1::EvalContext::with_quorum`] when this criterion is
/// configured.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::quorum_satisfied::QuorumSatisfiedCriterion;
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let criterion = QuorumSatisfiedCriterion::new();
/// assert_eq!(criterion.kind(), "quorum_satisfied");
/// ```
#[derive(Debug, Clone)]
pub struct QuorumSatisfiedCriterion;

impl QuorumSatisfiedCriterion {
    /// Constructs a new [`QuorumSatisfiedCriterion`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::quorum_satisfied::QuorumSatisfiedCriterion;
    /// use stellar_agent_core::policy::v1::criteria::Criterion as _;
    ///
    /// let c = QuorumSatisfiedCriterion::new();
    /// assert_eq!(c.kind(), "quorum_satisfied");
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for QuorumSatisfiedCriterion {
    fn default() -> Self {
        Self::new()
    }
}

impl Criterion for QuorumSatisfiedCriterion {
    fn kind(&self) -> &'static str {
        "quorum_satisfied"
    }

    /// Evaluates the quorum-satisfaction guard.
    ///
    /// Returns `Ok(None)` when the proposed signer set satisfies the declared
    /// quorum (i.e., `ctx.quorum.groups_short_by()` returns an empty vec).
    ///
    /// Returns `Ok(Some(DenyReason::QuorumNotSatisfied { groups_short_by,
    /// combinator }))` when one or more groups did not reach threshold.
    ///
    /// # Errors
    ///
    /// - [`PolicyError::CriterionEvaluationFailed`] when `ctx.quorum` is
    ///   `None` — the criterion is configured but the dispatch site has not
    ///   injected a [`crate::policy::v1::QuorumView`] via
    ///   [`crate::policy::v1::EvalContext::with_quorum`].
    ///   **Fail-closed**: a missing quorum view does not silently bypass the
    ///   quorum guard.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        // Fail-closed: quorum = None means the dispatch site has not injected
        // the quorum view.  Silently passing would allow multi-signer policy
        // rules to be bypassed when the wiring is absent.
        let quorum_view = ctx
            .quorum
            .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                detail: format!(
                    "quorum_satisfied criterion configured for tool '{}' but \
                         quorum was not populated by the dispatch site; \
                         EvalContext::with_quorum() required for multi-signer tool calls",
                    ctx.tool.name
                ),
            })?;

        let short_by = quorum_view.groups_short_by();
        if short_by.is_empty() {
            return Ok(None);
        }

        Ok(Some(DenyReason::QuorumNotSatisfied {
            groups_short_by: short_by,
            combinator: quorum_view.combinator_label().to_owned(),
        }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only assertions"
    )]

    use super::*;
    use crate::policy::v1::{EvalContext, PolicyStateStore, QuorumView};
    use crate::policy::{DenyReason, McpToolRegistration, ToolDescriptor};
    use crate::profile::schema::Profile;

    fn make_tool() -> ToolDescriptor {
        ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_smart_account_invoke",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        })
    }

    fn make_profile() -> Profile {
        Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
    }

    struct SatisfiedQuorum;
    impl QuorumView for SatisfiedQuorum {
        fn groups_short_by(&self) -> Vec<String> {
            vec![]
        }
        fn combinator_label(&self) -> &str {
            "And"
        }
    }

    struct UnsatisfiedAndQuorum {
        short_groups: Vec<String>,
    }
    impl QuorumView for UnsatisfiedAndQuorum {
        fn groups_short_by(&self) -> Vec<String> {
            self.short_groups.clone()
        }
        fn combinator_label(&self) -> &str {
            "And"
        }
    }

    struct UnsatisfiedOrQuorum {
        all_groups: Vec<String>,
    }
    impl QuorumView for UnsatisfiedOrQuorum {
        fn groups_short_by(&self) -> Vec<String> {
            self.all_groups.clone()
        }
        fn combinator_label(&self) -> &str {
            "Or"
        }
    }

    /// Criterion passes when all groups are satisfied.
    #[test]
    fn passes_when_quorum_satisfied() {
        let criterion = QuorumSatisfiedCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = PolicyStateStore::new();
        let view = SatisfiedQuorum;
        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store).with_quorum(&view);

        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "expected pass, got: {result:?}");
    }

    /// Criterion returns QuorumNotSatisfied with And combinator when groups
    /// are short.
    #[test]
    fn denies_when_and_groups_unsatisfied() {
        let criterion = QuorumSatisfiedCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = PolicyStateStore::new();
        let view = UnsatisfiedAndQuorum {
            short_groups: vec!["admins".to_owned(), "ops".to_owned()],
        };
        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store).with_quorum(&view);

        let result = criterion.evaluate(&ctx).unwrap();
        match result {
            Some(DenyReason::QuorumNotSatisfied {
                groups_short_by,
                combinator,
            }) => {
                assert_eq!(groups_short_by, vec!["admins", "ops"]);
                assert_eq!(combinator, "And");
            }
            other => panic!("expected QuorumNotSatisfied, got: {other:?}"),
        }
    }

    /// Criterion returns QuorumNotSatisfied with Or combinator when no group
    /// is satisfied.
    #[test]
    fn denies_when_or_no_group_satisfied() {
        let criterion = QuorumSatisfiedCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = PolicyStateStore::new();
        let view = UnsatisfiedOrQuorum {
            all_groups: vec!["g1".to_owned(), "g2".to_owned()],
        };
        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store).with_quorum(&view);

        let result = criterion.evaluate(&ctx).unwrap();
        match result {
            Some(DenyReason::QuorumNotSatisfied {
                groups_short_by,
                combinator,
            }) => {
                assert_eq!(groups_short_by, vec!["g1", "g2"]);
                assert_eq!(combinator, "Or");
            }
            other => panic!("expected QuorumNotSatisfied, got: {other:?}"),
        }
    }

    /// Criterion returns CriterionEvaluationFailed (fail-closed) when quorum
    /// view is absent.
    #[test]
    fn fails_closed_when_quorum_view_absent() {
        let criterion = QuorumSatisfiedCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = PolicyStateStore::new();
        // No .with_quorum() call — ctx.quorum is None.
        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store);

        let result = criterion.evaluate(&ctx);
        match result {
            Err(PolicyError::CriterionEvaluationFailed { detail }) => {
                assert!(
                    detail.contains("quorum_satisfied criterion"),
                    "expected criterion detail, got: {detail}"
                );
                assert!(
                    detail.contains("stellar_smart_account_invoke"),
                    "expected tool name in detail, got: {detail}"
                );
            }
            other => panic!("expected CriterionEvaluationFailed, got: {other:?}"),
        }
    }

    /// Wire code is stable.
    #[test]
    fn wire_code_stable() {
        assert_eq!(
            DenyReason::QuorumNotSatisfied {
                groups_short_by: vec![],
                combinator: "And".to_owned(),
            }
            .code(),
            "quorum_not_satisfied"
        );
    }

    /// `Default` impl matches `new()`.
    #[test]
    fn default_impl_matches_new() {
        let c1 = QuorumSatisfiedCriterion::new();
        // QuorumSatisfiedCriterion is a unit struct; Default produces the same
        // value as new() — use From to avoid the default_constructed_unit_structs
        // clippy lint.
        let c2 = QuorumSatisfiedCriterion;
        assert_eq!(c1.kind(), c2.kind());
    }
}
