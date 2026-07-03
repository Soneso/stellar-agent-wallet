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

        let amount_stroops = extract_amount_stroops(ctx);
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
/// Returns 0 when the field is absent or unparseable (fail-open for fee-only
/// transactions; the reserve check will still fire on the fee alone).
fn extract_amount_stroops(ctx: &EvalContext<'_>) -> i64 {
    let tool = ctx.tool.name.as_str();
    let amount_str = match tool {
        "stellar_pay" | "stellar_pay_commit" => ctx
            .args
            .get("amount")
            .and_then(|v| v.as_str())
            .unwrap_or("0 XLM"),
        "stellar_create_account" | "stellar_create_account_commit" => ctx
            .args
            .get("starting_balance")
            .and_then(|v| v.as_str())
            .unwrap_or("0 XLM"),
        _ => "0 XLM",
    };

    crate::amount::StellarAmount::parse_with_unit(amount_str)
        .or_else(|_| crate::amount::StellarAmount::parse_stroops(amount_str))
        .map(|a| a.as_stroops())
        .unwrap_or(0)
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
}
