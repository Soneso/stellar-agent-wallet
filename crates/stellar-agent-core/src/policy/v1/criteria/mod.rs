//! Per-criterion evaluators for `PolicyEngineV1`.
//!
//! Each criterion implements [`Criterion`]: receives an [`EvalContext`], returns
//! `Ok(None)` on pass, `Ok(Some(reason))` on deny, or `Err(_)` on evaluator
//! error.
//!
//! # Criterion inventory
//!
//! | Module | Struct | Kind tag |
//! |---|---|---|
//! | `per_tx_cap` | `PerTxCapCriterion` | `"per_tx_cap"` |
//! | `per_period_cap` | `PerPeriodCapCriterion` | `"per_period_cap"` |
//! | `rate_limit` | `RateLimitCriterion` | `"rate_limit"` |
//! | `counterparty_allowlist` | `CounterpartyAllowlistCriterion` | `"counterparty_allowlist"` |
//! | `minimum_reserve` | `MinimumReserveCriterion` | `"minimum_reserve"` |
//! | `inner_invocation_count_cap` | `InnerInvocationCountCapCriterion` | `"inner_invocation_count_cap"` |
//! | `bundle_aggregate_cap` | `BundleAggregateCapCriterion` | `"bundle_aggregate_cap"` |
//! | `restrict_bundle_to_recognised_kinds` | `RestrictBundleToRecognisedKindsCriterion` | `"restrict_bundle_to_recognised_kinds"` |
//! | `bundle_per_period_cap` | `BundlePerPeriodCapCriterion` | `"bundle_per_period_cap"` |
//! | `bundle_per_tx_cap` | `BundlePerTxCapCriterion` | `"bundle_per_tx_cap"` |
//! | `bundle_rate_limit` | `BundleRateLimitCriterion` | `"bundle_rate_limit"` |
//! | `quorum_satisfied` | `QuorumSatisfiedCriterion` | `"quorum_satisfied"` |
//! | `home_domain_resolved` | `HomeDomainResolvedCriterion` | `"home_domain_resolved"` |
//! | `sep10_session_active` | `Sep10SessionActiveCriterion` | `"sep10_session_active"` |
//! | `sep45_session_active` | `Sep45SessionActiveCriterion` | `"sep45_session_active"` |

use crate::policy::v1::EvalContext;
use crate::policy::v1::bundle::{BundleStateOverlay, InnerOpDescriptor};
use crate::policy::{DenyReason, PolicyError};

pub(crate) mod amount_extract;
pub mod bundle_aggregate_cap;
pub mod bundle_per_period_cap;
pub mod bundle_per_tx_cap;
pub mod bundle_rate_limit;
pub mod counterparty_allowlist;
pub mod home_domain_resolved;
pub mod inner_invocation_count_cap;
pub mod minimum_reserve;
pub mod per_period_cap;
pub mod per_tx_cap;
pub mod quorum_satisfied;
pub mod rate_limit;
pub mod restrict_bundle_to_recognised_kinds;
pub mod sep10_session_active;
pub mod sep45_session_active;
pub mod state_store;

pub use bundle_aggregate_cap::BundleAggregateCapCriterion;
pub use bundle_per_period_cap::BundlePerPeriodCapCriterion;
pub use bundle_per_tx_cap::BundlePerTxCapCriterion;
pub use bundle_rate_limit::BundleRateLimitCriterion;
pub use counterparty_allowlist::CounterpartyAllowlistCriterion;
pub use home_domain_resolved::HomeDomainResolvedCriterion;
pub use inner_invocation_count_cap::InnerInvocationCountCapCriterion;
pub use minimum_reserve::MinimumReserveCriterion;
pub use per_period_cap::PerPeriodCapCriterion;
pub use per_tx_cap::PerTxCapCriterion;
pub use quorum_satisfied::QuorumSatisfiedCriterion;
pub use rate_limit::RateLimitCriterion;
pub use restrict_bundle_to_recognised_kinds::RestrictBundleToRecognisedKindsCriterion;
pub use sep10_session_active::Sep10SessionActiveCriterion;
pub use sep45_session_active::Sep45SessionActiveCriterion;
pub use state_store::PolicyStateStore;

/// A single policy criterion evaluated against an [`EvalContext`].
///
/// Implement this trait for each supported criterion kind.  The engine calls
/// [`Criterion::evaluate`] for every criterion in a matching rule, in
/// declaration order.  The first `Ok(Some(_))` stops evaluation and returns
/// the deny reason.
///
/// Implementations MUST be `Send + Sync` because the engine holds criteria
/// behind `Box<dyn Criterion>` inside an `Arc<PolicyEngineV1>`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::Criterion;
/// use stellar_agent_core::policy::v1::EvalContext;
/// use stellar_agent_core::policy::{DenyReason, PolicyError};
///
/// /// A criterion that always passes.
/// #[derive(Debug)]
/// struct AlwaysPass;
///
/// impl Criterion for AlwaysPass {
///     fn kind(&self) -> &'static str { "always_pass" }
///
///     fn evaluate(&self, _ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
///         Ok(None)
///     }
/// }
///
/// // Trait object usage:
/// let c: Box<dyn Criterion> = Box::new(AlwaysPass);
/// assert_eq!(c.kind(), "always_pass");
/// ```
///
pub trait Criterion: Send + Sync + std::fmt::Debug {
    /// Returns the snake_case kind tag (e.g. `"per_tx_cap"`).
    ///
    /// Used by the loader to map TOML criterion entries to the correct concrete
    /// type.
    fn kind(&self) -> &'static str;

    /// Evaluates the criterion against the call context.
    ///
    /// # Returns
    ///
    /// - `Ok(None)` — criterion passes; continue to the next criterion.
    /// - `Ok(Some(reason))` — criterion failed; deny with the given reason.
    /// - `Err(e)` — evaluator error; propagated as
    ///   [`PolicyError::CriterionEvaluationFailed`].
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when the evaluator
    /// encounters an internal error (e.g. state-store I/O failure).
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError>;

    /// Whether this criterion fires at bundle-level (after all inner
    /// evaluations complete, with the full inners slice and populated overlay
    /// available) rather than once per inner.
    ///
    /// Default `false` — most criteria are per-inner only.
    ///
    /// Bundle-level criteria (`inner_invocation_count_cap`,
    /// `bundle_aggregate_cap`, `restrict_bundle_to_recognised_kinds`, and
    /// the `bundle_*` variants) override to `true`.  These criteria inspect
    /// the full bundle and run once per bundle — they do NOT participate in
    /// per-inner evaluation (their `evaluate` impl already short-circuits when
    /// `ctx.bundle` is `None`).
    ///
    /// A criterion that returns `true` here is SKIPPED at per-inner evaluation
    /// entirely.  Implementations must ensure their `evaluate` is well-defined
    /// when called at bundle level (the short-circuit on `ctx.bundle.is_none()`
    /// is the standard approach for criteria that are purely bundle-scoped).
    ///
    /// # Security note
    ///
    /// Implementations MUST NOT return `true` here unless `evaluate` is
    /// genuinely bundle-scoped: a criterion that returns `true` is never called
    /// at per-inner evaluation, which means per-inner state (e.g. per-inner
    /// amount caps) is never enforced for that criterion.  Per-inner stateful
    /// criteria (`per_period_cap`, `rate_limit`) MUST keep the default `false`.
    fn is_bundle_level(&self) -> bool {
        false
    }

    /// Accumulates this criterion's per-inner state into the bundle overlay.
    ///
    /// Called by [`crate::policy::v1::PolicyEngineV1::evaluate_bundle`] AFTER
    /// the criterion's [`Self::evaluate`] returned `Ok(None)` (Allow) on an inner
    /// descriptor.  The criterion derives its OWN state key and amount to
    /// accumulate, ensuring that the write key matches the read key used in
    /// [`Self::evaluate`].
    ///
    /// # Design
    ///
    /// Each criterion derives its own state key and amount to accumulate,
    /// ensuring that the write key in `accumulate_overlay` matches the read key
    /// used in `evaluate`.  This prevents the engine from having to know the
    /// key shape of each criterion.
    ///
    /// # Default implementation
    ///
    /// No-op.  Stateless criteria and bundle-level criteria (which inspect the
    /// full bundle rather than accumulating per-inner) need not override this.
    /// Stateful per-inner criteria that participate in bundle evaluation override
    /// it: [`crate::policy::v1::criteria::per_period_cap::PerPeriodCapCriterion`]
    /// and [`crate::policy::v1::criteria::rate_limit::RateLimitCriterion`].
    ///
    /// # Security note
    ///
    /// Implementations MUST derive the state key in `accumulate_overlay`
    /// identically to the state key derived in `evaluate`.  Cross-criterion key
    /// pollution is the implementer's responsibility to avoid.
    fn accumulate_overlay(
        &self,
        _ctx: &EvalContext<'_>,
        _inner: &InnerOpDescriptor,
        _overlay: &mut BundleStateOverlay,
    ) {
        // Default: no-op.
    }

    /// Records this criterion's contribution to persisted window state after a
    /// CONFIRMED submit.
    ///
    /// Called by [`crate::policy::v1::PolicyEngineV1::record_confirmed`] (single-tx
    /// path) and [`crate::policy::v1::PolicyEngineV1::record_confirmed_bundle`]
    /// (multicall path) for every criterion of the rule that governed the
    /// decision — mirroring the SAME rule/criteria resolution `evaluate_inner`
    /// used, so recording only touches criteria that actually governed the call.
    ///
    /// Implementations append into `ctx.state_store` via the SAME [`state_store::StateKey`]
    /// derivation their `evaluate` uses (the read-key/write-key identity
    /// invariant, same discipline as [`Self::accumulate_overlay`]), and return
    /// every `(key, timestamp_ms, amount_or_count)` tuple appended so the
    /// caller can persist the identical entries to the on-disk store.
    ///
    /// Default: no-op (most criteria are not stateful). Stateful criteria
    /// (`per_period_cap`, `rate_limit`, `bundle_per_period_cap`,
    /// `bundle_rate_limit`) override this.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] on a state-store
    /// error (e.g. clock-skew or lock-poisoning) or a clock read failure.
    fn record_confirmed(
        &self,
        _ctx: &EvalContext<'_>,
    ) -> Result<Vec<(state_store::StateKey, u64, i128)>, PolicyError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use super::*;
    use crate::policy::v1::criteria::inner_invocation_count_cap::{
        DEFAULT_INNER_INVOCATION_COUNT_CAP, InnerInvocationCountCapCriterion,
    };
    use crate::policy::{McpToolRegistration, ToolDescriptor};
    use crate::profile::schema::Profile;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum BundleLevelCriterionKind {
        InnerInvocationCountCap,
        BundleAggregateCap,
        RestrictBundleToRecognisedKinds,
        BundlePerPeriodCap,
        BundlePerTxCap,
        BundleRateLimit,
    }

    impl BundleLevelCriterionKind {
        const ALL: &'static [Self] = &[
            Self::InnerInvocationCountCap,
            Self::BundleAggregateCap,
            Self::RestrictBundleToRecognisedKinds,
            Self::BundlePerPeriodCap,
            Self::BundlePerTxCap,
            Self::BundleRateLimit,
        ];

        fn criterion(self) -> Box<dyn Criterion> {
            use crate::policy::v1::criteria::bundle_per_period_cap::BundlePerPeriodCapCriterion;
            use crate::policy::v1::criteria::bundle_per_tx_cap::BundlePerTxCapCriterion;
            use crate::policy::v1::criteria::bundle_rate_limit::BundleRateLimitCriterion;
            use crate::policy::v1::criteria::per_period_cap::Window;
            match self {
                Self::InnerInvocationCountCap => Box::new(InnerInvocationCountCapCriterion {
                    max_count: DEFAULT_INNER_INVOCATION_COUNT_CAP,
                }),
                Self::BundleAggregateCap => Box::new(BundleAggregateCapCriterion {
                    asset: None,
                    max_amount: 1,
                }),
                Self::RestrictBundleToRecognisedKinds => {
                    Box::new(RestrictBundleToRecognisedKindsCriterion { enabled: true })
                }
                Self::BundlePerPeriodCap => Box::new(BundlePerPeriodCapCriterion::new(
                    "native".into(),
                    Window::parse("1d").unwrap(),
                    1,
                )),
                Self::BundlePerTxCap => Box::new(BundlePerTxCapCriterion::new("native".into(), 1)),
                Self::BundleRateLimit => Box::new(BundleRateLimitCriterion::new(
                    Window::parse("1m").unwrap(),
                    1,
                )),
            }
        }
    }

    fn single_tx_ctx<'a>(
        tool: &'a ToolDescriptor,
        args: &'a serde_json::Value,
        profile: &'a Profile,
        store: &'a PolicyStateStore,
    ) -> EvalContext<'a> {
        EvalContext::new(tool, args, "alice", profile, store)
    }

    #[test]
    fn bundle_level_criteria_short_circuit_on_single_tx_context() {
        let tool = ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_pay",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        });
        let args = serde_json::Value::Null;
        let profile = Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build();
        let store = PolicyStateStore::new();
        let ctx = single_tx_ctx(&tool, &args, &profile, &store);

        // COMPILE-CHECK: this assertion is the closed-set inventory of
        // bundle-level criteria. Adding a new bundle-level criterion requires
        // adding one enum variant and one constructor arm above.
        assert_eq!(BundleLevelCriterionKind::ALL.len(), 6);

        for kind in BundleLevelCriterionKind::ALL {
            let criterion = kind.criterion();
            assert!(
                criterion.is_bundle_level(),
                "{} must remain bundle-level",
                criterion.kind()
            );
            assert!(
                criterion.evaluate(&ctx).unwrap().is_none(),
                "{} must pass without bundle context",
                criterion.kind()
            );
        }
    }

    // ── Default is_bundle_level for per-inner criteria ─────────────────────────

    /// Per-inner criteria (per_tx_cap, per_period_cap, rate_limit) must return
    /// `false` from `is_bundle_level()`.  The engine uses this flag to skip
    /// them during Phase 2 bundle evaluation; returning `true` would cause the
    /// engine to never call them at per-inner evaluation and silently bypass the
    /// cap.
    #[test]
    fn per_inner_criteria_are_not_bundle_level() {
        use crate::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
        use crate::policy::v1::criteria::per_tx_cap::PerTxCapCriterion;
        use crate::policy::v1::criteria::rate_limit::RateLimitCriterion;

        let per_tx: Box<dyn Criterion> =
            Box::new(PerTxCapCriterion::new("native".into(), 1_000_000_000));
        let per_period: Box<dyn Criterion> = Box::new(PerPeriodCapCriterion::new(
            "native".into(),
            Window::parse("1d").unwrap(),
            1_000_000_000,
        ));
        let rate: Box<dyn Criterion> =
            Box::new(RateLimitCriterion::new(Window::parse("1m").unwrap(), 5));

        assert!(
            !per_tx.is_bundle_level(),
            "per_tx_cap must not be bundle-level"
        );
        assert!(
            !per_period.is_bundle_level(),
            "per_period_cap must not be bundle-level"
        );
        assert!(
            !rate.is_bundle_level(),
            "rate_limit must not be bundle-level"
        );
    }

    // ── Default accumulate_overlay is a no-op ─────────────────────────────────

    /// The `Criterion` default `accumulate_overlay` is a no-op.  An `AlwaysPass`
    /// criterion (which does not override `accumulate_overlay`) must leave the
    /// overlay unchanged after being called.
    #[test]
    fn default_accumulate_overlay_is_noop() {
        use crate::policy::v1::bundle::{BundleStateOverlay, InnerOpDescriptor};

        #[derive(Debug)]
        struct AlwaysPass;
        impl Criterion for AlwaysPass {
            fn kind(&self) -> &'static str {
                "always_pass"
            }
            fn evaluate(
                &self,
                _ctx: &EvalContext<'_>,
            ) -> Result<Option<crate::policy::DenyReason>, crate::policy::PolicyError> {
                Ok(None)
            }
        }

        let tool = ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_pay",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        });
        let args = serde_json::Value::Null;
        let profile = Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build();
        let store = PolicyStateStore::new();
        let ctx = single_tx_ctx(&tool, &args, &profile, &store);

        let inner = InnerOpDescriptor::Generic {
            target: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".into(),
            fn_name: "transfer".into(),
        };
        let mut overlay = BundleStateOverlay::default();

        // Verify overlay starts empty (get returns 0 for any key).
        use crate::policy::v1::criteria::state_store::StateKey;
        let key = StateKey::new("alice", 1, "native", 86_400);
        assert_eq!(overlay.get(&key), 0, "empty overlay must return 0");

        // Call accumulate_overlay on a default-impl criterion.
        let criterion: Box<dyn Criterion> = Box::new(AlwaysPass);
        criterion.accumulate_overlay(&ctx, &inner, &mut overlay);

        // Overlay must remain unchanged — the no-op default must not modify any key.
        assert_eq!(
            overlay.get(&key),
            0,
            "default accumulate_overlay must leave overlay unchanged"
        );
    }

    // ── kind() returns the correct tag for each per-inner criterion ────────────

    #[test]
    fn per_inner_criterion_kind_tags_are_correct() {
        use crate::policy::v1::criteria::minimum_reserve::MinimumReserveCriterion;
        use crate::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
        use crate::policy::v1::criteria::per_tx_cap::PerTxCapCriterion;
        use crate::policy::v1::criteria::rate_limit::RateLimitCriterion;

        let per_tx: Box<dyn Criterion> =
            Box::new(PerTxCapCriterion::new("native".into(), 1_000_000_000));
        let per_period: Box<dyn Criterion> = Box::new(PerPeriodCapCriterion::new(
            "native".into(),
            Window::parse("1h").unwrap(),
            5_000_000_000,
        ));
        let rate: Box<dyn Criterion> =
            Box::new(RateLimitCriterion::new(Window::parse("5m").unwrap(), 10));
        let min_reserve: Box<dyn Criterion> = Box::new(MinimumReserveCriterion::new(5_0000000));

        assert_eq!(per_tx.kind(), "per_tx_cap");
        assert_eq!(per_period.kind(), "per_period_cap");
        assert_eq!(rate.kind(), "rate_limit");
        assert_eq!(min_reserve.kind(), "minimum_reserve");
    }

    // ── Bundle-level kind tags are correct ────────────────────────────────────

    #[test]
    fn bundle_level_criterion_kind_tags_are_correct() {
        use crate::policy::v1::criteria::bundle_per_period_cap::BundlePerPeriodCapCriterion;
        use crate::policy::v1::criteria::bundle_per_tx_cap::BundlePerTxCapCriterion;
        use crate::policy::v1::criteria::bundle_rate_limit::BundleRateLimitCriterion;
        use crate::policy::v1::criteria::per_period_cap::Window;

        let inner_cap: Box<dyn Criterion> = Box::new(InnerInvocationCountCapCriterion {
            max_count: DEFAULT_INNER_INVOCATION_COUNT_CAP,
        });
        let agg_cap: Box<dyn Criterion> = Box::new(BundleAggregateCapCriterion {
            asset: None,
            max_amount: 1_000_000_000,
        });
        let restrict: Box<dyn Criterion> =
            Box::new(RestrictBundleToRecognisedKindsCriterion { enabled: true });
        let bpp: Box<dyn Criterion> = Box::new(BundlePerPeriodCapCriterion::new(
            "native".into(),
            Window::parse("1d").unwrap(),
            5_000_000_000,
        ));
        let bpt: Box<dyn Criterion> =
            Box::new(BundlePerTxCapCriterion::new("native".into(), 5_000_000_000));
        let brl: Box<dyn Criterion> = Box::new(BundleRateLimitCriterion::new(
            Window::parse("1m").unwrap(),
            5,
        ));

        assert_eq!(inner_cap.kind(), "inner_invocation_count_cap");
        assert_eq!(agg_cap.kind(), "bundle_aggregate_cap");
        assert_eq!(restrict.kind(), "restrict_bundle_to_recognised_kinds");
        assert_eq!(bpp.kind(), "bundle_per_period_cap");
        assert_eq!(bpt.kind(), "bundle_per_tx_cap");
        assert_eq!(brl.kind(), "bundle_rate_limit");
    }

    // ── Criterion trait object: Send + Sync ───────────────────────────────────

    /// Verify that `Box<dyn Criterion>` satisfies `Send + Sync` bounds, which
    /// the engine requires to hold criteria behind `Arc<PolicyEngineV1>`.
    #[test]
    fn criterion_trait_object_is_send_and_sync() {
        use crate::policy::v1::criteria::per_tx_cap::PerTxCapCriterion;

        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn Criterion>>();
        // Also verify the concrete type used by the engine.
        assert_send_sync::<PerTxCapCriterion>();
    }
}
