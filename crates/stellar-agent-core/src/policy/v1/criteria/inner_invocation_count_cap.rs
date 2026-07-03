//! Inner invocation count cap criterion (multicall amplification defence).
//!
//! [`InnerInvocationCountCapCriterion`] limits the number of inner operations
//! within a multicall bundle.  It is a bundle-level criterion: it inspects
//! `ctx.bundle` rather than `ctx.args`.  When `ctx.bundle` is `None` (single-tx
//! path) the criterion passes unconditionally.
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "inner_invocation_count_cap", max_count = 50 }
//! ```
//!
//! # Default cap
//!
//! [`DEFAULT_INNER_INVOCATION_COUNT_CAP`] is 50.  Policy authors SHOULD
//! configure this criterion to a value appropriate for their use case; the
//! default is a safeguard against unbounded amplification.

use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::{DenyReason, PolicyError};

/// Default maximum number of inner invocations in a multicall bundle.
///
/// Guards against call-count amplification where a single multicall submits an
/// unbounded number of sub-invocations.
pub const DEFAULT_INNER_INVOCATION_COUNT_CAP: u32 = 50;

/// Inner invocation count cap criterion.
///
/// Denies any multicall bundle whose number of inner operations exceeds
/// `max_count`.  The single-tx path (`ctx.bundle == None`) always passes.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::inner_invocation_count_cap::{
///     InnerInvocationCountCapCriterion, DEFAULT_INNER_INVOCATION_COUNT_CAP,
/// };
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let c = InnerInvocationCountCapCriterion { max_count: DEFAULT_INNER_INVOCATION_COUNT_CAP };
/// assert_eq!(c.kind(), "inner_invocation_count_cap");
/// assert_eq!(c.max_count, 50);
/// ```
#[derive(Debug)]
pub struct InnerInvocationCountCapCriterion {
    /// Maximum number of inner operations permitted per bundle.
    pub max_count: u32,
}

impl Criterion for InnerInvocationCountCapCriterion {
    fn kind(&self) -> &'static str {
        "inner_invocation_count_cap"
    }

    /// Returns `true` — this criterion inspects the full bundle (all inners)
    /// and runs once at bundle-level.  It is skipped at per-inner evaluation;
    /// its `evaluate` already short-circuits with `Ok(None)` when `ctx.bundle`
    /// is `None`.
    fn is_bundle_level(&self) -> bool {
        true
    }

    /// Evaluates the inner invocation count cap.
    ///
    /// # Returns
    ///
    /// - `Ok(None)` — `ctx.bundle` is `None` (single-tx path) or the bundle
    ///   contains at most `max_count` inners.
    /// - `Ok(Some(DenyReason::InnerInvocationCountCapExceeded { .. }))` — the
    ///   bundle contains more than `max_count` inners.
    ///
    /// # Errors
    ///
    /// This criterion never returns `Err`; the return type is `Result` to
    /// satisfy the [`Criterion`] trait.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let Some(view) = ctx.bundle else {
            // Single-tx path: no bundle to evaluate.
            return Ok(None);
        };

        let count = u32::try_from(view.inners.len()).unwrap_or(u32::MAX);
        if count > self.max_count {
            return Ok(Some(DenyReason::InnerInvocationCountCapExceeded {
                max: self.max_count,
                attempted: count,
            }));
        }

        Ok(None)
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
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use crate::policy::v1::bundle::{BundleStateOverlay, BundleView, InnerOpDescriptor};
    use crate::policy::v1::criteria::state_store::PolicyStateStore;
    use crate::policy::{DenyReason, McpToolRegistration, ToolDescriptor};
    use crate::profile::schema::Profile;

    fn make_tool() -> ToolDescriptor {
        ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_multicall",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
        })
    }

    fn make_profile() -> Profile {
        Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
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

    fn make_ctx_with_bundle<'a>(
        tool: &'a ToolDescriptor,
        profile: &'a Profile,
        args: &'a serde_json::Value,
        store: &'a PolicyStateStore,
        view: Option<&'a BundleView<'a>>,
    ) -> EvalContext<'a> {
        EvalContext {
            tool,
            args,
            profile_name: "alice",
            profile,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: None,
            state_store: store,
            bundle: view,
        }
    }

    /// count=5 vs cap=50 — should pass.
    #[test]
    fn count_under_cap_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = make_inners(5);
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let criterion = InnerInvocationCountCapCriterion { max_count: 50 };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "5 inners vs cap=50 must pass");
    }

    /// count=51 vs cap=50 — should deny.
    #[test]
    fn count_over_cap_denies() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = make_inners(51);
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let criterion = InnerInvocationCountCapCriterion { max_count: 50 };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(
                result,
                Some(DenyReason::InnerInvocationCountCapExceeded {
                    max: 50,
                    attempted: 51
                })
            ),
            "51 inners vs cap=50 must deny with InnerInvocationCountCapExceeded"
        );
    }

    /// single-tx path (bundle=None) passes regardless of max_count.
    #[test]
    fn single_tx_path_bundle_none_always_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        // Even with a very low cap, bundle=None must pass.
        let criterion = InnerInvocationCountCapCriterion { max_count: 0 };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, None);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "bundle=None must always pass inner_invocation_count_cap"
        );
    }

    /// Exact cap boundary (count == max_count) must pass.
    #[test]
    fn count_exactly_at_cap_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = make_inners(50);
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let criterion = InnerInvocationCountCapCriterion { max_count: 50 };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "count == max_count must be allowed (strict > boundary)"
        );
    }
}
