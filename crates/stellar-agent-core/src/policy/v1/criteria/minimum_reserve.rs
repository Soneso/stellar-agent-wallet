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
use crate::policy::v1::criteria::amount_extract::extract_pay_or_create_account_stroops;
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
    /// - [`PolicyError::CriterionEvaluationFailed`] when a present
    ///   `amount_stroops` / `starting_balance_stroops` (or legacy `amount` /
    ///   `starting_balance`) field fails to parse — a malformed
    ///   server-derived amount refuses rather than passing as a zero debit.
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

        let amount_stroops = extract_amount_stroops(ctx)?;
        let fee_stroops = extract_fee_stroops(ctx);

        // Compute post-balance using saturating arithmetic to avoid wrapping on
        // underflow (e.g. if amount exceeds balance — the reserve check will
        // catch this case correctly since post_balance will be 0 or very small).
        let debit = amount_stroops.saturating_add(fee_stroops);
        let post_balance = pre_balance.saturating_sub(debit);

        let reserve_required_stroops = account_view
            .reserves_stroops(BASE_RESERVE_STROOPS)
            .saturating_add(self.margin_stroops);

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

/// Extracts the transaction amount in stroops from args.
///
/// For `stellar_pay(_commit)` and `stellar_create_account(_commit)`, resolves
/// the amount via [`extract_pay_or_create_account_stroops`] (resolved
/// `amount_stroops` / `starting_balance_stroops` key first, legacy
/// unit-string key as fallback) — every args shape these tools produce in
/// production carries the resolved key, so the reserve guard sees the real
/// debit on every path (simulate AND commit).
///
/// # Invariant
///
/// [`extract_pay_or_create_account_stroops`] distinguishes `Err` (a
/// recognised tool's amount field IS present but malformed) from `Ok(None)`
/// (the tool is not one this criterion knows how to extract a debit for, or
/// — for pay/create_account — genuinely carries neither key). This function
/// preserves that distinction rather than collapsing both to a silent 0:
///
/// - `Ok(Some(stroops))` → the real debit.
/// - `Ok(None)` → a genuinely amount-less tool; defaults to 0 (fail-open ONLY
///   here, matching the pre-existing "fee-only" fallback posture — the
///   reserve check still fires on the fee alone via `extract_fee_stroops`).
/// - `Err(_)` → a server-derived amount field is present but malformed; this
///   is propagated as [`PolicyError::CriterionEvaluationFailed`] (refuse),
///   the same fail-closed posture `per_tx_cap` / `per_period_cap` apply to
///   the identical condition. Silently treating a malformed amount as 0 would
///   let an attacker suppress the reserve debit by corrupting the field.
///
/// # Errors
///
/// Returns [`PolicyError::CriterionEvaluationFailed`] when a present resolved
/// or legacy amount field fails to parse.
fn extract_amount_stroops(ctx: &EvalContext<'_>) -> Result<i64, PolicyError> {
    match ctx.tool.name.as_str() {
        "stellar_pay"
        | "stellar_pay_commit"
        | "stellar_create_account"
        | "stellar_create_account_commit" => {
            // Read the resolved debit from the value leg the gate derived. A
            // pay/create leg with an unresolvable (`None`) amount is refused
            // (fail-closed None-is-deny): an unresolvable server-derived amount
            // must not be sized as a zero debit that would silently bypass the
            // reserve guard. The leg's asset is not consulted: the reserve debit
            // is asset-agnostic — every leg amount counts against the native
            // reserve.
            let leg = ctx.value.sole_value_leg().ok_or_else(|| {
                PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "minimum_reserve: value descriptor not populated for tool '{}'",
                        ctx.tool.name
                    ),
                }
            })?;
            let amount = leg
                .amount
                .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "minimum_reserve: unresolvable amount for tool '{}'",
                        ctx.tool.name
                    ),
                })?;
            i64::try_from(amount).map_err(|_| PolicyError::CriterionEvaluationFailed {
                detail: format!(
                    "minimum_reserve: amount {amount} exceeds i64 range for tool '{}'",
                    ctx.tool.name
                ),
            })
        }
        // Other tools keep the current args path: a genuinely amount-less tool
        // resolves to a 0 debit (the reserve check still fires on the fee).
        _ => Ok(extract_pay_or_create_account_stroops(ctx, "minimum_reserve")?.unwrap_or(0)),
    }
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

    // ── Real production args shapes (resolved-key re-point; closes the
    // pre-existing FAIL-OPEN where the absent legacy key silently counted the
    // debit as 0) ────────────────────────────────────────────────────────────

    /// Commit-time `stellar_pay_commit` authoritative_args shape breaches the
    /// reserve on the real debit — before this re-point, the absent "amount"
    /// key silently defaulted to 0 and this call would have passed.
    #[test]
    fn pay_commit_authoritative_args_shape_breach_is_now_caught() {
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

    /// A present-but-malformed resolved-key amount must be refused, not
    /// silently treated as a 0 debit. Before this fix, `extract_amount_stroops`
    /// swallowed `Err` from the shared extractor via `.ok().flatten().unwrap_or(0)`,
    /// which would have let a corrupted `amount_stroops` field bypass the
    /// reserve guard entirely.
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
}
