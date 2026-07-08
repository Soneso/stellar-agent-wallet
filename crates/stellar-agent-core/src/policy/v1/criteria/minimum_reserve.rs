//! Minimum-reserve guard criterion.
//!
//! [`MinimumReserveCriterion`] refuses to allow a transaction that would leave
//! the source account below its Stellar minimum reserve plus a configured safety
//! margin.
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "minimum_reserve", margin_stroops = 5_0000000 }
//! ```
//!
//! # Logic
//!
//! `amount_stroops` is the sum of the call's native-XLM debit (outflow) legs,
//! read from the typed value descriptor ([`EvalContext::value`]); a token-only
//! move is not a native debit and does not reduce the native reserve (§7.4).
//!
//! ```text
//! reserve_required = account.reserves_stroops(BASE_RESERVE_STROOPS) + margin_stroops
//! post_balance     = pre_balance - (amount_stroops + fee_stroops)     [saturating]
//!
//! if post_balance < reserve_required → DenyReason::MinimumReserveBreached
//! ```
//!
//! # Missing account view (fail-closed)
//!
//! When `ctx.account_view` is `None`, the criterion returns
//! `Err(PolicyError::CriterionEvaluationFailed)` rather than silently passing.
//! The correct posture is fail-closed: if the guard is configured and the
//! required account state is absent, the transaction is rejected.
//!
//! The `AccountViewAdapter` wiring at per-tool dispatch sites is required
//! before any policy that includes `kind = "minimum_reserve"` can succeed at
//! runtime.
//!
//! # CAP-0073 note
//!
//! If CAP-0073 is accepted by the Stellar protocol, the reserve formula
//! `(2 + subentries) * base_reserve` may change.  Update
//! `AccountReservesView::reserves_stroops` at protocol release.

use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::v1::value::{ValueGate, classify_value};
use crate::policy::{DenyReason, PolicyError};
use crate::protocol_consts::BASE_RESERVE_STROOPS;

// ─────────────────────────────────────────────────────────────────────────────
// MinimumReserveCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// Minimum-reserve guard criterion.
///
/// Checks that the account balance after the transaction will be at least
/// `reserves_stroops(BASE_RESERVE_STROOPS) + margin_stroops`.
///
/// # Missing account view (fail-closed)
///
/// When `ctx.account_view` is `None`, the criterion returns
/// `Err(PolicyError::CriterionEvaluationFailed)` — it does NOT silently pass.
/// If the minimum-reserve guard is configured and the account state is
/// unavailable, the call is rejected.
///
/// The `AccountViewAdapter` wiring at per-tool dispatch sites is required
/// before policies containing `kind = "minimum_reserve"` can succeed at
/// runtime.
///
/// # CAP-0073 note
///
/// If CAP-0073 is accepted by the Stellar protocol, the reserve formula
/// `(2 + subentries) * base_reserve` may change.  Update
/// `AccountReservesView::reserves_stroops` at protocol release.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::minimum_reserve::MinimumReserveCriterion;
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let criterion = MinimumReserveCriterion::new(5_0000000);
/// assert_eq!(criterion.kind(), "minimum_reserve");
/// assert_eq!(criterion.margin_stroops(), 5_0000000);
/// ```
#[derive(Debug, Clone)]
pub struct MinimumReserveCriterion {
    /// Safety margin in stroops added to the protocol minimum reserve.
    margin_stroops: i64,
}

impl MinimumReserveCriterion {
    /// Constructs a new [`MinimumReserveCriterion`].
    ///
    /// `margin_stroops` is added to the protocol-computed
    /// `(2 + subentries) * BASE_RESERVE_STROOPS` floor.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::minimum_reserve::MinimumReserveCriterion;
    ///
    /// let criterion = MinimumReserveCriterion::new(1_0000000); // 1 XLM margin
    /// assert_eq!(criterion.margin_stroops(), 1_0000000);
    /// ```
    #[must_use]
    pub fn new(margin_stroops: i64) -> Self {
        Self { margin_stroops }
    }

    /// Returns the configured safety margin in stroops.
    #[must_use]
    pub fn margin_stroops(&self) -> i64 {
        self.margin_stroops
    }
}

impl Criterion for MinimumReserveCriterion {
    fn kind(&self) -> &'static str {
        "minimum_reserve"
    }

    /// Evaluates the minimum-reserve guard.
    ///
    /// Returns `Ok(None)` when the post-transaction balance is at or above the
    /// required reserve (`reserves_stroops + margin_stroops`).
    ///
    /// Returns `Ok(Some(DenyReason::MinimumReserveBreached))` when the
    /// post-transaction balance would fall below the required reserve.
    ///
    /// # Errors
    ///
    /// - [`PolicyError::CriterionEvaluationFailed`] when `ctx.account_view`
    ///   is `None` — the criterion is configured but the dispatch site has not
    ///   populated the account view.  **Fail-closed**: a missing account view
    ///   does not silently bypass the reserve guard.
    /// - [`PolicyError::CriterionEvaluationFailed`] when
    ///   `account_view.balance_stroops()` returns an error (balance
    ///   unreadable or parse failure).
    /// - [`PolicyError::CriterionEvaluationFailed`] when a native-XLM debit leg
    ///   of the value descriptor carries no resolvable amount — an unresolvable
    ///   native debit refuses rather than passing as a zero debit.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        // Fail-closed: account_view = None means the dispatch site has not
        // wired up the account state.  Silently passing would allow every
        // call to bypass the reserve guard when the wiring is absent.
        let account_view =
            ctx.account_view
                .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "minimum_reserve criterion configured for tool '{}' but \
                 account_view was not populated by the dispatch site; \
                 AccountViewAdapter wiring required to enable reserve checking at runtime",
                        ctx.tool.name
                    ),
                })?;

        let pre_balance =
            account_view
                .balance_stroops()
                .map_err(|e| PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "minimum_reserve: failed to read account balance for tool '{}': {e}",
                        ctx.tool.name
                    ),
                })?;

        let amount_stroops = match extract_amount_stroops(ctx)? {
            AmountOutcome::Debit(amount) => amount,
            AmountOutcome::Deny(reason) => return Ok(Some(reason)),
        };
        let fee_stroops = extract_fee_stroops(ctx);

        // The reserve compare and the DenyReason payload are i128 end-to-end
        // (no clamp): `amount_stroops` may already carry an i128 token
        // quantity, so `pre_balance`, `fee_stroops`, and
        // `reserve_required_stroops` (each still `i64` at their own source —
        // the account-view trait and the configured margin are unaffected by
        // this widening) are promoted here rather than narrowing the debit.
        let pre_balance = i128::from(pre_balance);
        let debit = amount_stroops.saturating_add(i128::from(fee_stroops));
        let post_balance = pre_balance.saturating_sub(debit);

        let reserve_required_stroops = i128::from(
            account_view
                .reserves_stroops(BASE_RESERVE_STROOPS)
                .saturating_add(self.margin_stroops),
        );

        if post_balance < reserve_required_stroops {
            return Ok(Some(DenyReason::MinimumReserveBreached {
                reserve_required_stroops,
                balance_stroops: pre_balance,
            }));
        }

        Ok(None)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome of resolving the transaction's native debit for the reserve
/// check.
enum AmountOutcome {
    /// The resolved native-XLM debit in stroops (0 for a genuinely value-less
    /// call; the reserve check still fires on the fee alone).
    ///
    /// `i128` because a native debit leg's amount can exceed `i64::MAX`.
    Debit(i128),
    /// The call's value effect cannot be sized; refuse fail-closed with this
    /// reason instead of computing a debit.
    Deny(DenyReason),
}

/// Extracts the transaction's native-XLM debit in stroops.
///
/// Drives off the shared [`classify_value`] gate (design §7.4, native-only):
///
/// - [`ValueGate::NotApplicable`] → [`AmountOutcome::Debit(0)`]: a genuinely
///   value-less call; the reserve check still fires on the fee alone via
///   [`extract_fee_stroops`].
/// - [`ValueGate::Deny`] → [`AmountOutcome::Deny`]: the call's value effect
///   cannot be sized (an unpopulated `MovesValue` tool, or an opaque-sign call
///   under a matched rule); the criterion returns this reason directly rather
///   than computing a debit.
/// - [`ValueGate::Effects`] → sums only the debit legs whose asset is the
///   canonical `"native"` ([`crate::policy::v1::value::ValueLeg::is_native_debit`]).
///   A non-native leg (a token-only move) contributes 0 to the reserve debit —
///   it does not reduce the native reserve. A native debit leg with an
///   unresolvable (`None`) amount is refused fail-closed: an unresolvable
///   server-derived amount must not be sized as a zero debit that would
///   silently bypass the reserve guard.
///
/// # Errors
///
/// Returns [`PolicyError::CriterionEvaluationFailed`] when a native debit leg
/// carries no resolvable amount.
fn extract_amount_stroops(ctx: &EvalContext<'_>) -> Result<AmountOutcome, PolicyError> {
    let effects = match classify_value(ctx) {
        ValueGate::NotApplicable => return Ok(AmountOutcome::Debit(0)),
        ValueGate::Deny(reason) => return Ok(AmountOutcome::Deny(reason)),
        ValueGate::Effects(effects) => effects,
    };

    let mut sum: i128 = 0;
    for leg in effects.legs() {
        if !leg.is_native_debit() {
            // A non-native debit (or a non-debit leg such as Claim/Trustline)
            // does not reduce the native reserve.
            continue;
        }
        let amount = leg
            .amount
            .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                detail: format!(
                    "minimum_reserve: unresolvable amount for a native debit leg of tool '{}'",
                    ctx.tool.name
                ),
            })?;
        sum = sum.saturating_add(amount);
    }

    Ok(AmountOutcome::Debit(sum))
}

/// Extracts the transaction fee in stroops from args.
///
/// Falls back to 0 when the field is absent (the classic base fee is added by
/// the transaction builder; for policy evaluation the conservative default
/// is to ignore it when not supplied).
fn extract_fee_stroops(ctx: &EvalContext<'_>) -> i64 {
    ctx.args
        .get("fee_stroops")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
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

    use serde_json::json;

    use super::*;
    use crate::policy::v1::criteria::state_store::PolicyStateStore;
    use crate::policy::v1::{AccountReserveLookupError, AccountReservesView, EvalContext};
    use crate::policy::{McpToolRegistration, ToolDescriptor};
    use crate::profile::schema::Profile;

    // ── Test double ──────────────────────────────────────────────────────────

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

    fn make_tool(tool_name: &'static str) -> ToolDescriptor {
        let reg = McpToolRegistration {
            name: tool_name,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        };
        ToolDescriptor::from_registration(&reg)
    }

    fn make_profile() -> Profile {
        Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
    }

    fn make_ctx<'a>(
        tool: &'a ToolDescriptor,
        profile: &'a Profile,
        args: &'a serde_json::Value,
        store: &'a PolicyStateStore,
        account_view: Option<&'a dyn AccountReservesView>,
    ) -> EvalContext<'a> {
        EvalContext {
            tool,
            args,
            profile_name: "alice",
            profile,
            // Mirror the dispatch gate: derive the value descriptor the
            // criterion now reads through ctx.value for pay/create.
            value: crate::policy::v1::value::derive_value_class(tool.name.as_str(), args),
            account_view,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: None,
            state_store: store,
            bundle: None,
        }
    }

    /// Verifies fail-closed behaviour: absent account_view returns an Err rather
    /// than silently passing.
    #[test]
    fn absent_account_view_fails_closed() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_0000000);
        let args = json!({ "amount": "10 XLM", "asset": "native" });
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, None);
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Err(PolicyError::CriterionEvaluationFailed { .. })),
            "absent account_view must produce CriterionEvaluationFailed (fail-closed), \
             got {result:?}"
        );
    }

    #[test]
    fn post_balance_above_reserve_passes() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_0000000); // 0.5 XLM margin

        // Account: balance 200 XLM, 0 subentries.
        // Reserve: (2+0) * 5_000_000 = 10_000_000 + 5_000_000 margin = 15_000_000 stroops.
        // Sending 100 XLM: post_balance = 2_000_000_000 - 1_000_000_000 = 1_000_000_000 > 15_000_000.
        let view = MockAccountView {
            balance: 2_000_000_000, // 200 XLM
            subentries: 0,
        };
        let args = json!({ "amount": "100 XLM", "asset": "native" });
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "200 XLM balance sending 100 XLM should pass reserve check"
        );
    }

    #[test]
    fn post_balance_below_reserve_breaches() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_0000000); // 0.5 XLM margin

        // Account: balance 12 XLM, 0 subentries.
        // Reserve: 15_000_000 stroops (10_000_000 protocol + 5_000_000 margin).
        // Sending 11 XLM: post_balance = 120_000_000 - 110_000_000 = 10_000_000 < 15_000_000.
        let view = MockAccountView {
            balance: 120_000_000, // 12 XLM
            subentries: 0,
        };
        let args = json!({ "amount": "11 XLM", "asset": "native" });
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::MinimumReserveBreached { .. })),
            "12 XLM balance sending 11 XLM should breach the reserve"
        );
    }

    #[test]
    fn saturating_sub_on_amount_exceeding_balance_still_catches_breach() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(0); // no margin

        // Sending more than balance: saturating_sub floors to 0 which is
        // below the protocol reserve of 10_000_000 stroops.
        let view = MockAccountView {
            balance: 50_000_000, // 5 XLM
            subentries: 0,
        };
        let args = json!({ "amount": "100 XLM", "asset": "native" });
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::MinimumReserveBreached { .. })),
            "amount > balance with saturating_sub should still breach reserve"
        );
    }

    #[test]
    fn margin_adds_to_reserve_requirement() {
        let store = PolicyStateStore::new();
        // Large margin to test it's correctly added.
        let criterion = MinimumReserveCriterion::new(50_000_000); // 5 XLM margin

        // Balance 30 XLM, 0 subentries.
        // Reserve: (2+0)*5_000_000 = 10_000_000 + 50_000_000 margin = 60_000_000.
        // Sending 10 XLM: post = 300_000_000 - 100_000_000 = 200_000_000 > 60_000_000 → passes.
        let view = MockAccountView {
            balance: 300_000_000,
            subentries: 0,
        };
        let args = json!({ "amount": "10 XLM", "asset": "native" });
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "should pass with sufficient margin");
    }

    #[test]
    fn exact_reserve_boundary_passes() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_000_000);

        let view = MockAccountView {
            balance: 120_000_000,
            subentries: 0,
        };
        // Balance 12 XLM, 0 subentries.
        // Reserve: (2+0)*5_000_000 = 10_000_000 + 5_000_000 margin = 15_000_000.
        // Sending 104_990_000 bare stroops + 10_000 fee leaves exactly 15_000_000.
        let args = json!({
            "amount": "104990000", // bare-stroops form intentionally exercises parser fallback.
            "asset": "native",
            "fee_stroops": 10_000
        });
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "post balance exactly equal to required reserve must pass"
        );
    }

    #[test]
    fn create_account_starting_balance_participates_in_reserve_check() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_000_000);

        let view = MockAccountView {
            balance: 120_000_000,
            subentries: 0,
        };
        let args = json!({ "starting_balance": "11 XLM" });
        let tool = make_tool("stellar_create_account");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::MinimumReserveBreached { .. })),
            "create-account starting_balance must be counted as the transaction debit"
        );
    }

    #[test]
    fn fee_stroops_can_push_post_balance_below_reserve() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_000_000);

        let view = MockAccountView {
            balance: 120_000_000,
            subentries: 0,
        };
        // Balance 12 XLM, 0 subentries.
        // Reserve: (2+0)*5_000_000 = 10_000_000 + 5_000_000 margin = 15_000_000.
        // Sending 104_990_000 bare stroops + 10_001 fee leaves 14_999_999.
        let args = json!({
            "amount": "104990000", // bare-stroops form intentionally exercises parser fallback.
            "asset": "native",
            "fee_stroops": 10_001
        });
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::MinimumReserveBreached { .. })),
            "fee_stroops must participate in the reserve debit"
        );
    }

    #[test]
    fn extract_fee_stroops_returns_configured_value() {
        let store = PolicyStateStore::new();
        let args = json!({ "amount": "1 XLM", "asset": "native", "fee_stroops": 12_345 });
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, None);

        assert_eq!(extract_fee_stroops(&ctx), 12_345);
    }

    // ── Real production args shapes ───────────────────────────────────────────
    // The native-XLM debit is sized from the descriptor's outflow leg (resolved
    // from `amount_stroops` / `starting_balance_stroops`); a leg whose amount is
    // unresolvable denies rather than counting a 0 debit.

    /// A commit-time `stellar_pay_commit` authoritative_args shape that breaches
    /// the reserve on its native debit is denied.
    #[test]
    fn pay_commit_authoritative_args_shape_breach_is_caught() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_000_000);

        let view = MockAccountView {
            balance: 120_000_000, // 12 XLM
            subentries: 0,
        };
        // Reserve: (2+0)*5_000_000 = 10_000_000 + 5_000_000 margin = 15_000_000.
        // Sending 11 XLM (110_000_000 stroops): post = 120_000_000 - 110_000_000
        // = 10_000_000 < 15_000_000 → breach.
        let args = json!({
            "source": "GAAA",
            "total_fee_stroops": 100u32,
            "destination": "GBBB",
            "amount_stroops": "110000000",
            "asset": "XLM",
            "memo": serde_json::Value::Null,
        });
        let tool = make_tool("stellar_pay_commit");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::MinimumReserveBreached { .. })),
            "the real debit from amount_stroops must be seen, not silently \
             defaulted to 0: {result:?}"
        );
    }

    /// Simulate-time `stellar_create_account` args_value shape (only
    /// `starting_balance_stroops`, never the legacy `starting_balance` key)
    /// breaches the reserve on the real debit.
    #[test]
    fn create_account_simulate_resolved_only_shape_breach_is_now_caught() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_000_000);

        let view = MockAccountView {
            balance: 120_000_000,
            subentries: 0,
        };
        let args = json!({
            "chain_id": "stellar:testnet",
            "source": "GAAA",
            "destination": "GBBB",
            "starting_balance_stroops": "110000000",
        });
        let tool = make_tool("stellar_create_account");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::MinimumReserveBreached { .. })),
            "the real debit from starting_balance_stroops must be seen: {result:?}"
        );
    }

    /// Commit-time `stellar_create_account_commit` authoritative_args shape.
    #[test]
    fn create_account_commit_authoritative_args_shape_breach_is_now_caught() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_000_000);

        let view = MockAccountView {
            balance: 120_000_000,
            subentries: 0,
        };
        let args = json!({
            "source": "GAAA",
            "total_fee_stroops": 100u32,
            "destination": "GBBB",
            "starting_balance_stroops": "110000000",
        });
        let tool = make_tool("stellar_create_account_commit");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::MinimumReserveBreached { .. })),
            "the real debit must be seen at commit time too: {result:?}"
        );
    }

    /// Regression: the legacy unit-string-only shape must still evaluate to
    /// the identical verdict as before this re-point.
    #[test]
    fn legacy_starting_balance_only_shape_still_evaluates_identically() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_000_000);

        let view = MockAccountView {
            balance: 120_000_000,
            subentries: 0,
        };
        let args = json!({ "starting_balance": "11 XLM" });
        let tool = make_tool("stellar_create_account");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::MinimumReserveBreached { .. })),
            "legacy-only shape must still breach identically to before this re-point"
        );
    }

    /// Version-crossing: a resolved key carrying a legacy JSON number must
    /// still parse correctly.
    #[test]
    fn version_crossing_numeric_amount_stroops_still_parses() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_000_000);

        let view = MockAccountView {
            balance: 120_000_000,
            subentries: 0,
        };
        let args = json!({ "amount_stroops": 110_000_000i64, "asset": "native" });
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::MinimumReserveBreached { .. })),
            "numeric amount_stroops must still be seen as the real debit"
        );
    }

    /// A genuinely amount-less tool still gets the 0-default fail-open
    /// posture (the reserve check fires on the fee alone, via
    /// `extract_fee_stroops`, not on a fabricated amount).
    #[test]
    fn genuinely_amount_less_tool_still_defaults_amount_to_zero() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_000_000);

        let view = MockAccountView {
            balance: 120_000_000,
            subentries: 0,
        };
        let args = json!({});
        let tool = make_tool("stellar_balances");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "an amount-less tool with ample balance must pass (0 debit + 0 fee)"
        );
    }

    /// A present-but-malformed resolved-key amount is refused, not treated as a
    /// 0 debit: a native-XLM debit leg whose amount cannot be resolved denies
    /// fail-closed rather than bypassing the reserve guard.
    #[test]
    fn malformed_resolved_key_amount_is_refused_not_silently_zeroed() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_000_000);

        let view = MockAccountView {
            balance: 120_000_000,
            subentries: 0,
        };
        let args = json!({
            "source": "GAAA",
            "total_fee_stroops": 100u32,
            "destination": "GBBB",
            "amount_stroops": "not-a-number",
            "asset": "XLM",
            "memo": serde_json::Value::Null,
        });
        let tool = make_tool("stellar_pay_commit");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Err(PolicyError::CriterionEvaluationFailed { .. })),
            "a malformed amount_stroops value must refuse (CriterionEvaluationFailed), \
             not silently pass with a 0 debit: {result:?}"
        );
    }

    // ── Fail-closed value-descriptor matrix ─────────────────────────────────

    /// Constructs a `ToolDescriptor` with an explicit `value_kind` (rather
    /// than the fixed `ReadOnly` of [`make_tool`]).
    fn make_tool_with_kind(
        tool_name: &'static str,
        value_kind: crate::policy::ToolValueKind,
    ) -> ToolDescriptor {
        let reg = McpToolRegistration {
            name: tool_name,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind,
        };
        ToolDescriptor::from_registration(&reg)
    }

    /// A `MovesValue` tool the descriptor derivation has not classified
    /// (`derive_value_class` falls through to `ReadOnly` for any name outside
    /// its match arms) must deny fail-closed rather than passing silently.
    #[test]
    fn moves_value_tool_with_unpopulated_effects_denies_unsizable() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_000_000);
        let view = MockAccountView {
            balance: 120_000_000,
            subentries: 0,
        };
        let args = json!({});
        let tool = make_tool_with_kind(
            "stellar_blend_lend",
            crate::policy::ToolValueKind::MovesValue,
        );
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Ok(Some(DenyReason::UnsizableValueEffect { .. }))),
            "a MovesValue tool with no resolved effects must deny fail-closed, got {result:?}"
        );
    }

    /// An opaque-signing call on the single-tx path must deny fail-closed.
    #[test]
    fn opaque_sign_call_denies_unsizable_on_single_tx() {
        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_000_000);
        let view = MockAccountView {
            balance: 120_000_000,
            subentries: 0,
        };
        let args = json!({});
        let tool = make_tool("stellar_sep43_sign_transaction");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Ok(Some(DenyReason::UnsizableValueEffect { .. }))),
            "an opaque-signing call must deny fail-closed on the single-tx path, got {result:?}"
        );
    }

    /// A token-only (non-native) debit leg must NOT reduce the native
    /// reserve: the reserve check sees a 0 debit and passes on a balance that
    /// would otherwise breach if the token amount were (incorrectly) counted
    /// as a native debit.
    #[test]
    fn token_only_non_native_debit_leg_does_not_reduce_native_reserve() {
        use crate::policy::v1::value::{ActionKind, ValueClass, ValueEffects, ValueLeg};

        let store = PolicyStateStore::new();
        let criterion = MinimumReserveCriterion::new(5_000_000);

        // Balance 12 XLM, 0 subentries. Reserve required: 15_000_000 stroops.
        // A native debit of this size (110_000_000) would breach
        // (post = 10_000_000 < 15_000_000); a non-native debit of the same
        // size must NOT be counted, leaving post = pre_balance (120_000_000)
        // which passes.
        let view = MockAccountView {
            balance: 120_000_000,
            subentries: 0,
        };
        let leg = ValueLeg {
            kind: ActionKind::Payment,
            amount: Some(110_000_000),
            asset: Some("USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN".to_owned()),
            destination: Some("GBBB".to_owned()),
        };
        let args = json!({});
        let tool = make_tool("stellar_multicall");
        let profile = make_profile();
        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
            .with_account_view(&view)
            .with_value(ValueClass::Value(ValueEffects::single(leg)));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "a token-only debit must not reduce the native reserve; got {result:?}"
        );
    }
}
