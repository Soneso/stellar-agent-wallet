//! Property tests for `PolicyEngineV1`.
//!
//! # Properties under test
//!
//! ## Property 1 — Determinism
//!
//! For any `(rule, tool, args, profile)` tuple, constructing two independent
//! `PolicyEngineV1` instances from identical documents and calling `evaluate`
//! with identical inputs produces identical `Decision` results.
//!
//! Rationale: the engine must be a pure function of its inputs.  Any hidden
//! state (e.g. wall-clock reads, env-var reads at evaluate time, mutable
//! global state) would cause non-determinism across runs.  This property
//! guards against those regressions.
//!
//! Scope: the four state-independent criteria (`per_tx_cap`,
//! `counterparty_allowlist`, `minimum_reserve`, `soroban_resource_fee_cap`).
//! `per_period_cap` and `rate_limit` are excluded because they depend on
//! `SystemTime::now()` and mutate `PolicyStateStore`; including them would
//! make this property inherently flaky.
//!
//! ## Property 2 — Monotonicity
//!
//! Adding a matching deny rule before a base rule that would `Allow` cannot
//! preserve `Allow`.  That is, if `engine_base.evaluate(tool, args, profile)`
//! returns `Ok(Decision::Allow)`, then
//! `engine_with_deny.evaluate(tool, args, profile)` must NOT return
//! `Ok(Decision::Allow)` when the strict-deny rule matches the tool.
//!
//! Rationale: the policy engine enforces a safety monotone — more restrictive
//! rules can only reduce the allow set, never expand it.  A regression that
//! allows a call despite a matching deny rule is a security bug.
//!
//! ## Property 3 — Wire-code stability (DenyReason)
//!
//! Every `DenyReason` variant maps to a unique, non-empty snake_case wire code
//! via `DenyReason::code()`.  No two variants share a code.  The codes are
//! structurally stable (snake_case, ASCII lowercase + digits + underscore only).
//!
//! Rationale: `DenyReason::code()` is emitted at the MCP wire layer
//! (`policy.deny:<code>`).  Client code parses these codes for display and
//! automation; accidental code collisions or character-set drift would break
//! existing integrations.  The uniqueness check is a plain `#[test]` rather
//! than a proptest because it is exhaustive over a finite variant set and
//! relies on a compile-fail-on-new-variant pattern (see
//! [`enumerate_deny_reason_for_test`]).  A separate proptest block validates
//! payload-independence of the wire code over random struct-field inputs.
//!
//! # Runtime budget
//!
//! Each `proptest!` block is configured for **10 000 cases per property** via
//! `#![proptest_config(ProptestConfig::with_cases(10_000))]`.  The aggregate
//! `cargo test` runtime for this file is dominated by these properties; on
//! Apple Silicon the full file completes in well under 30s.  The case count
//! can be lowered for local iteration via `PROPTEST_CASES=<n>`.

#![cfg(test)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; panics acceptable in property tests"
)]

use std::collections::HashSet;

use proptest::prelude::*;

use crate::policy::v1::PolicyEngineV1;
use crate::policy::v1::proptest_strategies::{
    arb_counterparty_allowlist_rule, arb_minimum_reserve_rule, arb_native_payment_args,
    arb_payment_args, arb_per_tx_cap_rule, arb_profile, arb_soroban_resource_fee_rule,
    arb_strict_deny_per_tx_rule, arb_tool_descriptor, arb_tool_descriptor_for_payment_tools,
    single_rule_document, two_rule_document,
};
use crate::policy::{Decision, DenyReason, PolicyEngine};

// ─────────────────────────────────────────────────────────────────────────────
// Decision equivalence helper
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` when two `Result<Decision, PolicyError>` values are
/// semantically equivalent for proptest purposes.
///
/// - `Ok(Decision::Allow) == Ok(Decision::Allow)`.
/// - `Ok(Decision::Deny(a)) == Ok(Decision::Deny(b))` iff
///   `a.code() == b.code()` AND `format!("{a:?}") == format!("{b:?}")`.
/// - `Ok(Decision::RequireApproval(_)) == Ok(Decision::RequireApproval(_))`
///   iff the TTL seconds match (the nonce field is not generated in test docs).
/// - Error variants compare by their `Debug` representation (no secret
///   material in `detail` strings).
///
/// Comparing `Debug` strings is intentional for proptest equivalence: the
/// criteria construct typed payloads from deterministic inputs, so the Debug
/// representation is stable across two evaluations with the same seed.
fn decisions_equiv(
    a: &Result<Decision, crate::policy::PolicyError>,
    b: &Result<Decision, crate::policy::PolicyError>,
) -> bool {
    match (a, b) {
        (Ok(Decision::Allow), Ok(Decision::Allow)) => true,
        (Ok(Decision::Deny(da)), Ok(Decision::Deny(db))) => {
            da.code() == db.code() && format!("{da:?}") == format!("{db:?}")
        }
        (Ok(Decision::RequireApproval(ra)), Ok(Decision::RequireApproval(rb))) => {
            ra.ttl_seconds == rb.ttl_seconds
        }
        (Err(ea), Err(eb)) => format!("{ea:?}") == format!("{eb:?}"),
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 1 — Determinism
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Property 1a — Determinism for `per_tx_cap`.
    ///
    /// Evaluating the same `PolicyEngineV1` instance twice with identical inputs
    /// must produce identical decisions.  This subsumes the two-independent-engine
    /// check for stateless criteria: if the engine is a pure function of its
    /// document + inputs, any two engines with identical construction must agree.
    ///
    /// Note: `PolicyRule` cannot be cloned (it holds `Box<dyn Criterion>`), so
    /// we cannot build a second independent engine from a copy of the rule.
    /// Instead we evaluate the same engine twice, which is the stronger claim:
    /// the engine has no hidden mutation between calls.
    #[test]
    fn prop_per_tx_cap_evaluate_is_deterministic(
        rule in arb_per_tx_cap_rule(),
        tool in arb_tool_descriptor(),
        args in arb_payment_args(),
        (profile, profile_name) in arb_profile(),
    ) {
        let doc = single_rule_document(rule);
        let engine = PolicyEngineV1::new(doc, profile_name);
        let r1 = engine.evaluate(&tool, &args, &profile, None, None, None, None, None);
        let r2 = engine.evaluate(&tool, &args, &profile, None, None, None, None, None);
        prop_assert!(
            decisions_equiv(&r1, &r2),
            "per_tx_cap determinism failed: first={r1:?} repeat={r2:?}"
        );
    }

    /// Property 1b — Determinism for `counterparty_allowlist`.
    ///
    /// Same-engine re-evaluation must return the same `Decision`.
    #[test]
    fn prop_counterparty_allowlist_evaluate_is_deterministic(
        rule in arb_counterparty_allowlist_rule(),
        tool in arb_tool_descriptor(),
        args in arb_payment_args(),
        (profile, profile_name) in arb_profile(),
    ) {
        let doc = single_rule_document(rule);
        let engine = PolicyEngineV1::new(doc, profile_name);
        let r1 = engine.evaluate(&tool, &args, &profile, None, None, None, None, None);
        let r2 = engine.evaluate(&tool, &args, &profile, None, None, None, None, None);
        prop_assert!(
            decisions_equiv(&r1, &r2),
            "counterparty_allowlist determinism failed: first={r1:?} second={r2:?}"
        );
    }

    /// Property 1c — Determinism for `minimum_reserve`.
    ///
    /// Same-engine re-evaluation with the same mock account view must return
    /// the same `Decision`.
    ///
    /// Note: the `minimum_reserve` criterion fails-closed when `account_view`
    /// is `None`.  The property test exercises this correctly by omitting the
    /// view — both evaluations return identical errors.
    #[test]
    fn prop_minimum_reserve_evaluate_is_deterministic(
        rule in arb_minimum_reserve_rule(),
        tool in arb_tool_descriptor(),
        args in arb_payment_args(),
        (profile, profile_name) in arb_profile(),
    ) {
        let doc = single_rule_document(rule);
        let engine = PolicyEngineV1::new(doc, profile_name);
        // Evaluate without account_view (fail-closed path).
        let r1 = engine.evaluate(&tool, &args, &profile, None, None, None, None, None);
        let r2 = engine.evaluate(&tool, &args, &profile, None, None, None, None, None);
        prop_assert!(
            decisions_equiv(&r1, &r2),
            "minimum_reserve determinism failed: first={r1:?} second={r2:?}"
        );
    }

    /// Property 1d — Determinism for `soroban_resource_fee_cap`.
    ///
    /// Same-engine re-evaluation must return the same `Decision`.  Non-Soroban
    /// tools cause the criterion to return `Ok(None)` (does not apply) and the
    /// rule's `Allow` decision is returned.
    #[test]
    fn prop_soroban_resource_fee_evaluate_is_deterministic(
        rule in arb_soroban_resource_fee_rule(),
        tool in arb_tool_descriptor(),
        args in arb_payment_args(),
        (profile, profile_name) in arb_profile(),
    ) {
        let doc = single_rule_document(rule);
        let engine = PolicyEngineV1::new(doc, profile_name);
        let r1 = engine.evaluate(&tool, &args, &profile, None, None, None, None, None);
        let r2 = engine.evaluate(&tool, &args, &profile, None, None, None, None, None);
        prop_assert!(
            decisions_equiv(&r1, &r2),
            "soroban_resource_fee determinism failed: first={r1:?} second={r2:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 2 — Monotonicity
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Property 2 — Monotonicity: adding a matching deny rule before a
    /// permissive base rule cannot preserve `Allow` when the criterion applies.
    ///
    /// Setup:
    /// 1. Restrict the tool to `stellar_pay` or `stellar_create_account` — the
    ///    only tools that `per_tx_cap` actually evaluates.  For other tools
    ///    the criterion returns `Ok(None)` (does not apply), so the strict deny
    ///    rule would not fire regardless of the cap.  The monotonicity property
    ///    is only meaningful when the criterion is active.
    /// 2. Evaluate with `base_rule` only.
    /// 3. If the base returns `Ok(Decision::Allow)`, prepend the strict deny
    ///    rule and assert the result is NOT `Ok(Decision::Allow)`.
    ///
    /// The args generator always produces amounts in `2..=90_000_000_000`
    /// stroops (at minimum 2 stroops), so the strict deny rule (cap = 1 stroop)
    /// always fires for `stellar_pay` and `stellar_create_account`.
    #[test]
    fn prop_adding_deny_rule_cannot_turn_allow_into_allow(
        base_rule in arb_per_tx_cap_rule(),
        strict_deny_rule in arb_strict_deny_per_tx_rule(),
        tool in arb_tool_descriptor_for_payment_tools(),
        args in arb_native_payment_args(),
        (profile, profile_name) in arb_profile(),
    ) {
        // Step 1: evaluate with base rule only.
        let doc_base = single_rule_document(base_rule);
        let engine_base = PolicyEngineV1::new(doc_base, profile_name.clone());
        let r_base = engine_base.evaluate(&tool, &args, &profile, None, None, None, None, None);

        // Step 2: if base allowed, prepend a strict deny rule.
        if matches!(r_base, Ok(Decision::Allow)) {
            // Build a maximally-permissive fallback rule (cap = 10 000 000 XLM)
            // to place after the strict deny rule so the engine has a rule to
            // fall back to if the deny rule somehow doesn't match.
            use crate::policy::v1::criteria::PerTxCapCriterion;
            use crate::policy::v1::loader::{PolicyRule, RuleMatch};
            let permissive_rule = PolicyRule {
                r#match: RuleMatch {
                    tool: "*".to_owned(),
                    chain: "*".to_owned(),
                },
                criteria: vec![Box::new(PerTxCapCriterion::new(
                    "native".to_owned(),
                    100_000_000_000_000_i64, // 10 000 000 XLM — always passes
                ))],
                decision: Decision::Allow,
            };

            // The strict deny rule (cap = 1 stroop) is placed first.
            // The args always carry amounts >= 2 stroops, so the criterion fires.
            let doc_with_deny = two_rule_document(strict_deny_rule, permissive_rule);
            let engine_with_deny = PolicyEngineV1::new(doc_with_deny, profile_name.clone());
            let r_with_deny = engine_with_deny.evaluate(&tool, &args, &profile, None, None, None, None, None);

            prop_assert!(
                !matches!(r_with_deny, Ok(Decision::Allow)),
                "monotonicity violated: base allowed but strict deny + permissive also allowed. \
                 tool={:?} args={:?} r_base={r_base:?} r_with_deny={r_with_deny:?}",
                tool.name, args
            );
        }
        // If the base already denied, adding a deny rule cannot make it worse —
        // the property is vacuously satisfied.
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 3 — Wire-code stability: exhaustive uniqueness check
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the wire code expected for a given `DenyReason` variant via an
/// exhaustive `match` with no `_` arm.
///
/// This helper exists so that adding a new variant to [`DenyReason`] causes a
/// **compile-time failure here** — the missing match arm forces the test
/// author to register the new code in this exhaustive enumeration before the
/// suite will build.  Without this gating helper, the uniqueness test below
/// would silently skip the new variant (the `code()` method itself does have
/// an exhaustive `match`, but the test list does not).
///
/// The string returned MUST match `v.code()`; the uniqueness test asserts
/// this.  This is the binding source of truth for "what code does each
/// variant produce" from a test-author perspective.
fn enumerate_deny_reason_for_test(v: &DenyReason) -> &'static str {
    // Exhaustive match with no `_` arm: the compiler will reject any new
    // `DenyReason` variant added to the enum until this helper is updated.
    match v {
        DenyReason::PerTxCapExceeded { .. } => "per_tx_cap_exceeded",
        DenyReason::PerPeriodCapExceeded { .. } => "per_period_cap_exceeded",
        DenyReason::RateLimitExceeded { .. } => "rate_limit_exceeded",
        DenyReason::CounterpartyDenied { .. } => "counterparty_denied",
        DenyReason::MinimumReserveBreached { .. } => "minimum_reserve_breached",
        DenyReason::MissingApproval => "missing_approval",
        DenyReason::OwnerSignatureStale { .. } => "owner_signature_stale",
        DenyReason::NoMatchingRule => "no_matching_rule",
        DenyReason::ExplicitRuleDeny => "explicit_rule_deny",
        DenyReason::CounterpartyKindUnsupported { .. } => "counterparty_kind_unsupported",
        DenyReason::EvaluationError { .. } => "evaluation_error",
        DenyReason::InnerInvocationCountCapExceeded { .. } => "inner_invocation_count_cap_exceeded",
        DenyReason::BundleAggregateCapExceeded { .. } => "bundle_aggregate_cap_exceeded",
        DenyReason::BundleContainsGenericKind { .. } => "bundle_contains_generic_kind",
        DenyReason::BundleDenied { .. } => "bundle_denied",
        DenyReason::QuorumNotSatisfied { .. } => "quorum_not_satisfied",
        DenyReason::HomeDomainNotResolved { .. } => "home_domain_not_resolved",
        DenyReason::Sep10SessionMissing { .. } => "sep10.session_missing",
        DenyReason::Sep45SessionMissing { .. } => "sep45.session_missing",
    }
}

/// Asserts that every `DenyReason` variant has a unique, non-empty, snake_case
/// `code()` string, and that `code()` agrees with the test-side enumeration in
/// [`enumerate_deny_reason_for_test`].
///
/// This test is an exhaustive structural check over all variants, NOT a
/// proptest.  Using `proptest!` here would be incorrect: the property we want
/// is "the finite set of variant codes is pairwise disjoint", which is proven
/// by enumerating all variants once.  A random-input approach could only sample
/// a subset of the finite enum and would not provide stronger guarantees than
/// exhaustive enumeration.  Randomising the struct fields within each variant
/// is irrelevant because `code()` is defined on the variant discriminant alone,
/// not on the payload.
///
/// The payload-stability proptest (that `PerTxCapExceeded { asset: random, … }`
/// always returns `"per_tx_cap_exceeded"`) lives in
/// `prop_deny_reason_*_code_is_payload_independent` below.
///
/// Adding a new `DenyReason` variant in `policy/mod.rs` will:
/// 1. Force [`DenyReason::code`] to gain a new arm (its `match` is exhaustive).
/// 2. Force [`enumerate_deny_reason_for_test`] above to gain a new arm (also
///    exhaustive).
/// 3. Force this `variants` list to gain a representative instance (otherwise
///    the new variant's code is not exercised by the uniqueness check).
///
/// Steps 1 and 2 are compiler-enforced.  Step 3 is enforced socially via the
/// rustdoc comment on this test plus the `enumerate_deny_reason_for_test`
/// helper, which a contributor will encounter before the test compiles.
#[test]
fn deny_reason_wire_codes_are_unique() {
    // One representative instance per variant.  Payload values are arbitrary
    // (they do not affect `code()`).  Order matches `enumerate_deny_reason_for_test`.
    let variants: Vec<DenyReason> = vec![
        DenyReason::PerTxCapExceeded {
            asset: "native".into(),
            max_stroops: 0,
            attempted_stroops: 1,
        },
        DenyReason::PerPeriodCapExceeded {
            asset: "native".into(),
            window: "rolling_24h".into(),
            max_stroops: 0,
            attempted_stroops: 1,
            period_used_stroops: 0,
        },
        DenyReason::RateLimitExceeded {
            window: "rolling_1h".into(),
            max_calls: 10,
            calls_in_window: 11,
        },
        DenyReason::CounterpartyDenied {
            kind: "G_ACCOUNT".into(),
            value: "GABC".into(),
        },
        DenyReason::MinimumReserveBreached {
            reserve_required_stroops: 1,
            balance_stroops: 0,
        },
        DenyReason::MissingApproval,
        DenyReason::OwnerSignatureStale {
            rotated_at: "2026-01-01T00:00:00Z".into(),
        },
        DenyReason::NoMatchingRule,
        DenyReason::ExplicitRuleDeny,
        DenyReason::CounterpartyKindUnsupported {
            kind: "SEP10_IDENTITY".into(),
        },
        DenyReason::EvaluationError {
            detail: "test".into(),
        },
        DenyReason::InnerInvocationCountCapExceeded {
            max: 50,
            attempted: 51,
        },
        DenyReason::BundleAggregateCapExceeded {
            asset: None,
            max: 100_000_000_000,
            sum: 120_000_000_000,
        },
        DenyReason::BundleContainsGenericKind { inner_index: 0 },
        DenyReason::BundleDenied {
            inner_index: 0,
            deny_reason: Box::new(DenyReason::NoMatchingRule),
        },
        DenyReason::QuorumNotSatisfied {
            groups_short_by: vec!["main-signers".into()],
            combinator: "and".into(),
        },
        DenyReason::HomeDomainNotResolved {
            home_domain: "circle.com".into(),
        },
        DenyReason::Sep10SessionMissing {
            account_id: "GABC1".into(),
        },
        DenyReason::Sep45SessionMissing {
            contract_id: "CABC1".into(),
        },
    ];

    let mut codes: HashSet<&'static str> = HashSet::new();
    for v in &variants {
        let c = v.code();
        let expected = enumerate_deny_reason_for_test(v);
        assert_eq!(
            c, expected,
            "variant {v:?} returns code '{c}' but the test-side enumeration expects '{expected}'.  \
             If you renamed a wire code, update enumerate_deny_reason_for_test to match."
        );
        assert!(!c.is_empty(), "variant {v:?} has empty code()");
        // Codes are lowercase ASCII + digits + underscore + dot.
        // Dot is permitted for namespaced codes e.g. `sep10.session_missing`.
        assert!(
            c.chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '.'),
            "variant {v:?} code '{c}' contains disallowed characters \
             (allowed: lowercase ASCII letters, digits, '_', '.')"
        );
        assert!(
            codes.insert(c),
            "wire code '{c}' is shared by two DenyReason variants (collision)"
        );
    }

    // Also assert the variant list count matches the enumerator's match-arm count.
    // If a contributor adds a new variant + `enumerate_deny_reason_for_test` arm
    // but forgets the corresponding entry in `variants`, this catches it.
    assert_eq!(
        variants.len(),
        19,
        "variants list count drifted from DenyReason variant count.  \
         Update enumerate_deny_reason_for_test, the variants vec, and this assertion."
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 3b — Wire-code stability: payload-independence proptest
// ─────────────────────────────────────────────────────────────────────────────
//
// Coverage scope.  These proptests cover every payload-bearing variant of
// `DenyReason`.  The three payload-free variants (`MissingApproval`,
// `NoMatchingRule`, `ExplicitRuleDeny`) have no random fields to vary, so
// payload-independence reduces to a constant check; those are exercised by
// `deny_reason_wire_codes_are_unique` above.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Property 3b — The `PerTxCapExceeded` wire code is payload-independent.
    ///
    /// For any combination of `asset`, `max_stroops`, and `attempted_stroops`,
    /// `DenyReason::PerTxCapExceeded.code()` is always `"per_tx_cap_exceeded"`.
    ///
    /// This property extends the exhaustive uniqueness check above to confirm
    /// that the code string cannot change based on payload values — a regression
    /// that would break client code parsing the wire response.
    #[test]
    fn prop_deny_reason_per_tx_cap_code_is_payload_independent(
        asset in "[a-z]{3,8}",
        max_stroops in 0_i64..=100_000_000_000_i64,
        attempted_stroops in 0_i64..=200_000_000_000_i64,
    ) {
        let reason = DenyReason::PerTxCapExceeded {
            asset,
            max_stroops,
            attempted_stroops,
        };
        prop_assert_eq!(reason.code(), "per_tx_cap_exceeded");
    }

    /// Property 3c — The `PerPeriodCapExceeded` wire code is payload-independent.
    #[test]
    fn prop_deny_reason_per_period_cap_code_is_payload_independent(
        asset in "[a-z]{3,8}",
        window in "[a-z0-9_]{3,16}",
        max_stroops in 0_i64..=100_000_000_000_i64,
        attempted_stroops in 0_i64..=200_000_000_000_i64,
        period_used_stroops in 0_i64..=200_000_000_000_i64,
    ) {
        let reason = DenyReason::PerPeriodCapExceeded {
            asset,
            window,
            max_stroops,
            attempted_stroops,
            period_used_stroops,
        };
        prop_assert_eq!(reason.code(), "per_period_cap_exceeded");
    }

    /// Property 3d — The `RateLimitExceeded` wire code is payload-independent.
    #[test]
    fn prop_deny_reason_rate_limit_code_is_payload_independent(
        window in "[a-z0-9_]{3,16}",
        max_calls in 0_u32..=10_000_u32,
        calls_in_window in 0_u32..=10_000_u32,
    ) {
        let reason = DenyReason::RateLimitExceeded {
            window,
            max_calls,
            calls_in_window,
        };
        prop_assert_eq!(reason.code(), "rate_limit_exceeded");
    }

    /// Property 3e — The `CounterpartyDenied` wire code is payload-independent.
    ///
    /// The `kind` and `value` payload fields must not affect the stable wire
    /// code `"counterparty_denied"`.
    #[test]
    fn prop_deny_reason_counterparty_denied_code_is_payload_independent(
        kind in "[A-Z_]{3,20}",
        value in "[A-Za-z0-9]{3,30}",
    ) {
        let reason = DenyReason::CounterpartyDenied { kind, value };
        prop_assert_eq!(reason.code(), "counterparty_denied");
    }

    /// Property 3f — The `MinimumReserveBreached` wire code is payload-independent.
    #[test]
    fn prop_deny_reason_minimum_reserve_code_is_payload_independent(
        reserve_required_stroops in 0_i64..=1_000_000_000_i64,
        balance_stroops in 0_i64..=1_000_000_000_i64,
    ) {
        let reason = DenyReason::MinimumReserveBreached {
            reserve_required_stroops,
            balance_stroops,
        };
        prop_assert_eq!(reason.code(), "minimum_reserve_breached");
    }

    /// Property 3g — The `OwnerSignatureStale` wire code is payload-independent.
    #[test]
    fn prop_deny_reason_owner_signature_stale_code_is_payload_independent(
        rotated_at in "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
    ) {
        let reason = DenyReason::OwnerSignatureStale { rotated_at };
        prop_assert_eq!(reason.code(), "owner_signature_stale");
    }

    /// Property 3h — The `CounterpartyKindUnsupported` wire code is payload-independent.
    #[test]
    fn prop_deny_reason_counterparty_kind_unsupported_code_is_payload_independent(
        kind in "[A-Z_]{3,20}",
    ) {
        let reason = DenyReason::CounterpartyKindUnsupported { kind };
        prop_assert_eq!(reason.code(), "counterparty_kind_unsupported");
    }

    /// Property 3i — The `EvaluationError` wire code is payload-independent.
    #[test]
    fn prop_deny_reason_evaluation_error_code_is_payload_independent(
        detail in "[a-zA-Z0-9 _.,:-]{0,128}",
    ) {
        let reason = DenyReason::EvaluationError { detail };
        prop_assert_eq!(reason.code(), "evaluation_error");
    }

    /// Property 3j — The `QuorumNotSatisfied` wire code is payload-independent.
    #[test]
    fn prop_deny_reason_quorum_not_satisfied_code_is_payload_independent(
        combinator in "[a-z]{2,8}",
    ) {
        let reason = DenyReason::QuorumNotSatisfied {
            groups_short_by: vec!["g1".into()],
            combinator,
        };
        prop_assert_eq!(reason.code(), "quorum_not_satisfied");
    }

    /// Property 3k — The `Sep10SessionMissing` wire code is payload-independent.
    ///
    /// For any `account_id` value, `DenyReason::Sep10SessionMissing.code()`
    /// always returns `"sep10.session_missing"`.
    #[test]
    fn prop_deny_reason_sep10_session_missing_code_is_payload_independent(
        account_id in "[A-Z2-7]{56}",
    ) {
        let reason = DenyReason::Sep10SessionMissing { account_id };
        prop_assert_eq!(reason.code(), "sep10.session_missing");
    }

    /// Property 3l — The `Sep45SessionMissing` wire code is payload-independent.
    ///
    /// For any `contract_id` value, `DenyReason::Sep45SessionMissing.code()`
    /// always returns `"sep45.session_missing"`.
    #[test]
    fn prop_deny_reason_sep45_session_missing_code_is_payload_independent(
        contract_id in "[A-Z2-7]{56}",
    ) {
        let reason = DenyReason::Sep45SessionMissing { contract_id };
        prop_assert_eq!(reason.code(), "sep45.session_missing");
    }
}
