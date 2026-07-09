//! Restrict-bundle-to-recognised-kinds criterion (ABI-bypass defence).
//!
//! [`RestrictBundleToRecognisedKindsCriterion`] fails-CLOSED on any bundle
//! containing a [`crate::policy::v1::bundle::InnerOpDescriptor::Generic`] inner.
//! When enabled, it ensures that only operations whose ABI shape has been
//! recognised by [`crate::policy::v1::bundle::decompose_bundle`] (currently:
//! SAC token transfers) are permitted in a multicall bundle.
//!
//! # Relationship to the value-summing bundle caps
//!
//! A rule carrying any value-summing bundle cap (`bundle_aggregate_cap`,
//! `bundle_per_tx_cap`, or `bundle_per_period_cap`) implicitly enforces this
//! criterion's Generic-rejection check at evaluation time
//! ([`crate::policy::v1::PolicyEngineV1::evaluate_bundle`]), regardless of
//! whether this criterion is present on the rule or, if present, its `enabled`
//! value. Those caps sum only `TokenTransfer` inners, so an invocation whose
//! ABI shape decodes as `Generic` contributes nothing to any of them; the
//! implicit check closes that bypass without requiring policy authors to
//! remember the pairing. (`bundle_rate_limit` counts `Generic` inners and is
//! not coupled.) The criterion remains independently configurable as a
//! standalone guard (rejecting `Generic` inners with no cap present).
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "restrict_bundle_to_recognised_kinds", enabled = true }
//! ```
//!
//! # Single-tx path
//!
//! When `ctx.bundle` is `None`, the criterion passes unconditionally.
//!

use crate::policy::v1::EvalContext;
use crate::policy::v1::bundle::InnerOpDescriptor;
use crate::policy::v1::criteria::Criterion;
use crate::policy::{DenyReason, PolicyError};

/// Restrict-bundle-to-recognised-kinds criterion.
///
/// When `enabled` is `true`, denies any bundle that contains at least one
/// [`InnerOpDescriptor::Generic`] inner.  When `enabled` is `false`, the
/// criterion is a no-op (passes every call).
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::restrict_bundle_to_recognised_kinds::RestrictBundleToRecognisedKindsCriterion;
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let c = RestrictBundleToRecognisedKindsCriterion { enabled: true };
/// assert_eq!(c.kind(), "restrict_bundle_to_recognised_kinds");
/// ```
#[derive(Debug)]
pub struct RestrictBundleToRecognisedKindsCriterion {
    /// Whether the criterion is active.  `false` disables it entirely; the
    /// criterion passes every call as if it were not configured.
    pub enabled: bool,
}

impl Criterion for RestrictBundleToRecognisedKindsCriterion {
    fn kind(&self) -> &'static str {
        "restrict_bundle_to_recognised_kinds"
    }

    /// Returns `true` — this criterion inspects all inners for `Generic`
    /// variants and runs once at bundle-level.  It is skipped at per-inner
    /// evaluation; its `evaluate` already short-circuits with `Ok(None)` when
    /// `ctx.bundle` is `None` or when `self.enabled` is `false`.
    fn is_bundle_level(&self) -> bool {
        true
    }

    /// Evaluates the restrict-bundle-to-recognised-kinds criterion.
    ///
    /// # Returns
    ///
    /// - `Ok(None)` — criterion is disabled, `ctx.bundle` is `None`, or all
    ///   inners are recognised (non-`Generic`).
    /// - `Ok(Some(DenyReason::BundleContainsGenericKind { inner_index }))` — the
    ///   first `Generic` inner was found at `inner_index`.
    ///
    /// # Errors
    ///
    /// This criterion never returns `Err`.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        if !self.enabled {
            return Ok(None);
        }

        let Some(view) = ctx.bundle else {
            // Single-tx path: no bundle.
            return Ok(None);
        };

        for (idx, inner) in view.inners.iter().enumerate() {
            if matches!(inner, InnerOpDescriptor::Generic { .. }) {
                return Ok(Some(DenyReason::BundleContainsGenericKind {
                    inner_index: u32::try_from(idx).unwrap_or(u32::MAX),
                }));
            }
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

    const ADDR_FROM: &str = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
    const ADDR_TO: &str = "GAYAB7BRFBAXDVIJQ4YKZM4N67M6XWUGUEFGQ23YVKSVP5KNYQVS3GL";

    fn make_tool() -> ToolDescriptor {
        ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_multicall",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        })
    }

    fn make_profile() -> Profile {
        Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
    }

    fn token_transfer() -> InnerOpDescriptor {
        InnerOpDescriptor::TokenTransfer {
            asset: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            from: ADDR_FROM.to_owned(),
            to: ADDR_TO.to_owned(),
            amount: 1_000_000_000,
        }
    }

    fn generic_inner() -> InnerOpDescriptor {
        InnerOpDescriptor::Generic {
            target: "CSTRKEY".to_owned(),
            fn_name: "unknown_fn".to_owned(),
        }
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
            value: crate::policy::v1::value::ValueClass::ReadOnly,
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

    /// T-A: enabled + all TokenTransfer → Allow.
    #[test]
    fn enabled_all_token_transfer_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = vec![token_transfer(), token_transfer(), token_transfer()];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let criterion = RestrictBundleToRecognisedKindsCriterion { enabled: true };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        assert!(
            criterion.evaluate(&ctx).unwrap().is_none(),
            "enabled + all TokenTransfer must pass"
        );
    }

    /// T-B: enabled + 1 Generic → Deny with correct inner_index.
    #[test]
    fn enabled_with_generic_denies() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = vec![token_transfer(), generic_inner(), token_transfer()];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let criterion = RestrictBundleToRecognisedKindsCriterion { enabled: true };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(
                result,
                Some(DenyReason::BundleContainsGenericKind { inner_index: 1 })
            ),
            "Generic at index 1 must produce BundleContainsGenericKind {{ inner_index: 1 }}"
        );
    }

    /// T-C: disabled + Generic → Allow.
    #[test]
    fn disabled_with_generic_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = vec![generic_inner(), generic_inner()];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let criterion = RestrictBundleToRecognisedKindsCriterion { enabled: false };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        assert!(
            criterion.evaluate(&ctx).unwrap().is_none(),
            "disabled criterion must pass even with Generic inners"
        );
    }

    /// Single-tx path (bundle=None) passes regardless of enabled state.
    #[test]
    fn single_tx_bundle_none_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let criterion = RestrictBundleToRecognisedKindsCriterion { enabled: true };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, None);
        assert!(
            criterion.evaluate(&ctx).unwrap().is_none(),
            "bundle=None must always pass"
        );
    }

    /// Reports the index of the FIRST Generic inner, not the last.
    #[test]
    fn reports_first_generic_index() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = vec![
            token_transfer(),
            token_transfer(),
            generic_inner(), // index 2
            generic_inner(), // index 3 — should NOT be reported
        ];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let criterion = RestrictBundleToRecognisedKindsCriterion { enabled: true };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(
                result,
                Some(DenyReason::BundleContainsGenericKind { inner_index: 2 })
            ),
            "must report the first Generic inner (index 2)"
        );
    }
}
