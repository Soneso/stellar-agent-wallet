//! Home-domain-resolved policy criterion.
//!
//! [`HomeDomainResolvedCriterion`] verifies that the destination account's
//! on-chain `home_domain` has a valid cached `stellar.toml` binding before
//! allowing a tool call.
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "home_domain_resolved" }
//! ```
//!
//! # Logic
//!
//! ```text
//! if ctx.identity_view is None
//!     → Err(CriterionEvaluationFailed)   [fail-closed; identity required]
//!
//! if ctx.identity_view.home_domain() is None
//!     → Ok(None)                          [pass; no home_domain to resolve]
//!
//! if ctx.counterparty_cache is None
//!     → Err(CriterionEvaluationFailed)   [fail-closed; cache required when
//!                                          home_domain is present]
//!
//! if ctx.counterparty_cache.has_resolved(home_domain)
//!     → Ok(None)                          [pass; binding cached]
//!
//! else
//!     → Ok(Some(DenyReason::HomeDomainNotResolved { home_domain }))
//! ```
//!
//! # Fail-closed posture
//!
//! When the criterion is configured:
//!
//! - A missing `identity_view` is an evaluator error (the criterion cannot
//!   determine the `home_domain` without an identity view).  Same fail-closed
//!   posture as `minimum_reserve`.
//! - A missing `counterparty_cache` is an evaluator error when a `home_domain`
//!   is present.  If the operator has configured this criterion, they intend
//!   the cache to be wired; absence is a dispatch-site bug.
//!
//! When the account has **no** `home_domain` set on-chain (field is `None`),
//! the criterion passes unconditionally — no `stellar.toml` resolution is
//! possible for accounts without a `home_domain`.
//!
//! # Cache keying
//!
//! The `CounterpartyCacheView` is keyed by `home_domain` string (not by
//! account_id).  A `CounterpartyCacheSnapshot` is constructed at dispatch time
//! from `CounterpartyResolver::list_cached()` so the criterion receives a
//! point-in-time view of which domains have been resolved.

use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::{DenyReason, PolicyError};

// ─────────────────────────────────────────────────────────────────────────────
// HomeDomainResolvedCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that the destination account's `home_domain` has a cached
/// `stellar.toml` binding before permitting the tool call.
///
/// Configured with `{ kind = "home_domain_resolved" }` in the policy TOML.
/// No additional fields.
///
/// # Missing views (fail-closed)
///
/// - When `ctx.identity_view` is `None`, the criterion returns
///   [`PolicyError::CriterionEvaluationFailed`] — it cannot determine the
///   `home_domain` without an identity view.
/// - When `ctx.counterparty_cache` is `None` AND the account has a
///   `home_domain`, the criterion returns
///   [`PolicyError::CriterionEvaluationFailed`] — the operator configured this
///   criterion, so the cache MUST be wired at the dispatch site.
///
/// When the account has no `home_domain` set on-chain, the criterion passes
/// unconditionally.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::home_domain_resolved::HomeDomainResolvedCriterion;
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let criterion = HomeDomainResolvedCriterion::new();
/// assert_eq!(criterion.kind(), "home_domain_resolved");
/// ```
#[derive(Debug, Clone)]
pub struct HomeDomainResolvedCriterion;

impl HomeDomainResolvedCriterion {
    /// Constructs a new [`HomeDomainResolvedCriterion`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::home_domain_resolved::HomeDomainResolvedCriterion;
    /// use stellar_agent_core::policy::v1::criteria::Criterion as _;
    ///
    /// let c = HomeDomainResolvedCriterion::new();
    /// assert_eq!(c.kind(), "home_domain_resolved");
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for HomeDomainResolvedCriterion {
    fn default() -> Self {
        Self::new()
    }
}

impl Criterion for HomeDomainResolvedCriterion {
    fn kind(&self) -> &'static str {
        "home_domain_resolved"
    }

    /// Evaluates the home-domain-resolved guard.
    ///
    /// Returns `Ok(None)` when:
    /// - The account has no `home_domain` on-chain (pass; nothing to resolve).
    /// - The account's `home_domain` is present in the counterparty cache.
    ///
    /// Returns `Ok(Some(DenyReason::HomeDomainNotResolved { home_domain }))`
    /// when the account has a `home_domain` that is not in the cache.
    ///
    /// # Errors
    ///
    /// - [`PolicyError::CriterionEvaluationFailed`] when `ctx.identity_view`
    ///   is `None` — the criterion requires an identity view to read the
    ///   on-chain `home_domain`.  **Fail-closed.**
    /// - [`PolicyError::CriterionEvaluationFailed`] when
    ///   `ctx.counterparty_cache` is `None` AND the account has a
    ///   `home_domain` — the operator configured this criterion so the cache
    ///   must be wired.  **Fail-closed.**
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        // Fail-closed: identity_view = None means the dispatch site has not
        // injected an identity view.  Without it we cannot read home_domain.
        let identity = ctx
            .identity_view
            .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                detail: format!(
                    "home_domain_resolved criterion configured for tool '{}' but \
                     identity_view was not populated by the dispatch site; \
                     EvalContext::with_identity_view() required",
                    ctx.tool.name
                ),
            })?;

        // If no home_domain is set on-chain, the criterion passes — there is
        // nothing to resolve.  Consistent with HOME_DOMAIN-absent semantics:
        // an account without a home_domain cannot have a stellar.toml.
        let Some(home_domain) = identity.home_domain() else {
            return Ok(None);
        };

        // Fail-closed: counterparty_cache = None when a home_domain is present
        // means the operator configured this criterion but the dispatch site did
        // not wire the cache snapshot.  Silently passing would bypass the guard.
        let cache =
            ctx.counterparty_cache
                .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "home_domain_resolved criterion configured for tool '{}' \
                     with on-chain home_domain '{}' but counterparty_cache was not \
                     populated by the dispatch site; \
                     EvalContext::with_counterparty_cache() required",
                        ctx.tool.name,
                        // home_domain is public infrastructure metadata; safe to include.
                        home_domain
                    ),
                })?;

        if cache.has_resolved(&home_domain) {
            return Ok(None);
        }

        Ok(Some(DenyReason::HomeDomainNotResolved { home_domain }))
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

    use std::collections::HashSet;

    use super::*;
    use crate::policy::v1::{
        AccountIdentityView, CounterpartyCacheView, EvalContext, PolicyStateStore,
    };
    use crate::policy::{DenyReason, McpToolRegistration, ToolDescriptor};
    use crate::profile::schema::Profile;

    fn make_tool() -> ToolDescriptor {
        ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_pay",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        })
    }

    fn make_profile() -> Profile {
        Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
    }

    // ── In-test mock types ────────────────────────────────────────────────────

    struct MockIdentityView {
        home_domain: Option<String>,
    }

    impl AccountIdentityView for MockIdentityView {
        fn home_domain(&self) -> Option<String> {
            self.home_domain.clone()
        }

        fn account_id(&self) -> &str {
            "GABC123456789012345678901234567890123456789012345678901234"
        }
    }

    struct MockCacheView {
        resolved: HashSet<String>,
    }

    impl MockCacheView {
        fn with_domains(domains: &[&str]) -> Self {
            Self {
                resolved: domains.iter().map(|s| (*s).to_owned()).collect(),
            }
        }
    }

    impl CounterpartyCacheView for MockCacheView {
        fn has_resolved(&self, home_domain: &str) -> bool {
            self.resolved.contains(home_domain)
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Criterion passes when the on-chain home_domain is in the cache.
    #[test]
    fn passes_when_home_domain_resolved_in_cache() {
        let criterion = HomeDomainResolvedCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = PolicyStateStore::new();
        let identity = MockIdentityView {
            home_domain: Some("circle.com".to_owned()),
        };
        let cache = MockCacheView::with_domains(&["circle.com"]);

        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
            .with_identity_view(&identity)
            .with_counterparty_cache(&cache);

        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "expected pass when home_domain is cached, got: {result:?}"
        );
    }

    /// Criterion denies when the on-chain home_domain is NOT in the cache.
    #[test]
    fn denies_when_home_domain_not_in_cache() {
        let criterion = HomeDomainResolvedCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = PolicyStateStore::new();
        let identity = MockIdentityView {
            home_domain: Some("unknown.example".to_owned()),
        };
        let cache = MockCacheView::with_domains(&["circle.com"]);

        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
            .with_identity_view(&identity)
            .with_counterparty_cache(&cache);

        let result = criterion.evaluate(&ctx).unwrap();
        match result {
            Some(DenyReason::HomeDomainNotResolved { home_domain }) => {
                assert_eq!(
                    home_domain, "unknown.example",
                    "deny must carry the unresolved home_domain"
                );
            }
            other => panic!("expected HomeDomainNotResolved, got: {other:?}"),
        }
    }

    /// Criterion passes when the account has no home_domain on-chain.
    ///
    /// An account without a home_domain cannot have a stellar.toml binding;
    /// the criterion must pass unconditionally rather than denying.
    #[test]
    fn passes_when_no_home_domain_on_chain() {
        let criterion = HomeDomainResolvedCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = PolicyStateStore::new();
        let identity = MockIdentityView { home_domain: None };
        // No cache needed because home_domain is absent.
        let cache = MockCacheView::with_domains(&[]);

        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
            .with_identity_view(&identity)
            .with_counterparty_cache(&cache);

        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "expected pass when no home_domain, got: {result:?}"
        );
    }

    /// Criterion returns CriterionEvaluationFailed (fail-closed) when
    /// counterparty_cache is absent but a home_domain is present.
    #[test]
    fn fails_closed_when_cache_absent_with_home_domain() {
        let criterion = HomeDomainResolvedCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = PolicyStateStore::new();
        let identity = MockIdentityView {
            home_domain: Some("circle.com".to_owned()),
        };

        // No .with_counterparty_cache() call — ctx.counterparty_cache is None.
        let ctx =
            EvalContext::new(&tool, &args, "alice", &profile, &store).with_identity_view(&identity);

        let result = criterion.evaluate(&ctx);
        match result {
            Err(PolicyError::CriterionEvaluationFailed { detail }) => {
                assert!(
                    detail.contains("home_domain_resolved criterion"),
                    "expected criterion detail, got: {detail}"
                );
                assert!(
                    detail.contains("stellar_pay"),
                    "expected tool name in detail, got: {detail}"
                );
            }
            other => panic!("expected CriterionEvaluationFailed, got: {other:?}"),
        }
    }

    /// Criterion returns CriterionEvaluationFailed (fail-closed) when
    /// identity_view is absent.
    #[test]
    fn fails_closed_when_identity_view_absent() {
        let criterion = HomeDomainResolvedCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = PolicyStateStore::new();
        let cache = MockCacheView::with_domains(&["circle.com"]);

        // No .with_identity_view() call — ctx.identity_view is None.
        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
            .with_counterparty_cache(&cache);

        let result = criterion.evaluate(&ctx);
        match result {
            Err(PolicyError::CriterionEvaluationFailed { detail }) => {
                assert!(
                    detail.contains("identity_view was not populated"),
                    "expected identity_view detail, got: {detail}"
                );
                assert!(
                    detail.contains("stellar_pay"),
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
            DenyReason::HomeDomainNotResolved {
                home_domain: "circle.com".into(),
            }
            .code(),
            "home_domain_not_resolved"
        );
    }

    /// `Default` impl matches `new()`.
    #[test]
    fn default_impl_matches_new() {
        let c1 = HomeDomainResolvedCriterion::new();
        let c2 = HomeDomainResolvedCriterion;
        assert_eq!(c1.kind(), c2.kind());
    }
}
