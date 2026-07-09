//! Bridges [`AccountView`] to the
//! `stellar_agent_core::policy::v1::AccountReservesView` and
//! `stellar_agent_core::policy::v1::AccountIdentityView` traits used by the
//! policy criteria.
//!
//! # Why this lives here
//!
//! `AccountView` is defined in this crate (`stellar-agent-network`), and this
//! crate already depends on `stellar-agent-core` (where the two traits are
//! defined) — implementing a `stellar-agent-core` trait for an
//! `stellar-agent-network` type from within `stellar-agent-network` requires
//! no new dependency edge and is orphan-rule-compliant (the type is local).
//! Both `stellar-agent-mcp` and `stellar-agent-cli` already depend on this
//! crate, so hosting the adapter here lets both consume it directly instead
//! of duplicating it. `stellar-agent-mcp::policy_adapter` re-exports
//! [`AccountViewAdapter`] from here so its existing public path is
//! unchanged.
//!
//! # Trait split
//!
//! `AccountIdentityView` is split from `AccountReservesView` to eliminate the
//! silent-fail `home_domain()` default.  `AccountViewAdapter` implements both
//! traits.  Callers that need HOME_DOMAIN injection supply the adapter as
//! `identity_view`; callers that need reserve data supply it as `account_view`.
//!
//! # Per-tool wiring
//!
//! `stellar_pay` and `stellar_create_account` (MCP) and `pay` / `claim` /
//! `accounts create` (CLI) fetch the source account and pass this adapter as
//! `account_view` (consumed by the `minimum_reserve` criterion). `pay` (both
//! MCP and CLI) additionally fetches the destination account and passes its
//! adapter as `identity_view` (consumed by `home_domain_resolved`);
//! `create_account` (both MCP and CLI) passes `None` for `identity_view`
//! because the destination does not yet exist.
//!
//! Call sites that do not fetch an account call the plain
//! `dispatch_gate` / `evaluate` path, which passes `None` for both views — so
//! a V1 policy that configures `minimum_reserve` or `home_domain_resolved`
//! for such a call fails closed (the criterion returns
//! `PolicyError::CriterionEvaluationFailed` when its view is absent, denying
//! rather than allowing the call).

use stellar_agent_core::policy::v1::{
    AccountIdentityView, AccountReserveLookupError, AccountReservesView,
};

use crate::AccountView;

// ─────────────────────────────────────────────────────────────────────────────
// AccountViewAdapter
// ─────────────────────────────────────────────────────────────────────────────

/// Adapts an [`AccountView`] reference to the
/// [`AccountReservesView`] trait expected by the minimum-reserve criterion.
///
/// Wrap an `&AccountView` in `AccountViewAdapter::new` and pass it as
/// `Some(&adapter)` for `EvalContext.account_view` when the minimum-reserve
/// criterion is active.  The caller must have already fetched the
/// `AccountView` from the network before constructing the context.
///
/// # Per-call-site wiring
///
/// The actual call-site population (MCP tool handlers and CLI commands
/// constructing this adapter and passing it in) is a separate concern.  See
/// the module-level note.
///
/// # Examples
///
/// ```
/// use stellar_agent_network::policy_view::AccountViewAdapter;
/// use stellar_agent_network::{AccountView, AssetView, BalanceView, ThresholdsView};
/// use stellar_agent_core::policy::v1::AccountReservesView;
/// use stellar_agent_core::BASE_RESERVE_STROOPS;
///
/// let view = AccountView::new(
///     "GABC".to_owned(),
///     1,
///     3,
///     vec![BalanceView::new(
///         AssetView::native(),
///         "100.0000000".to_owned(),
///         None,
///         "0.0000000".to_owned(),
///         "0.0000000".to_owned(),
///     )],
///     ThresholdsView::new(1, 0, 0, 0),
///     vec![],
///     None,
///     None,
/// );
/// let adapter = AccountViewAdapter::new(&view);
/// // (2 + 3) * 5_000_000 = 25_000_000
/// assert_eq!(adapter.reserves_stroops(BASE_RESERVE_STROOPS), 25_000_000);
/// let stroops = adapter.balance_stroops();
/// assert!(stroops.is_ok());
/// assert_eq!(stroops.unwrap(), 1_000_000_000); // 100 XLM in stroops
/// ```
pub struct AccountViewAdapter<'a>(pub &'a AccountView);

impl<'a> AccountViewAdapter<'a> {
    /// Constructs a new adapter wrapping the given account view reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::policy_view::AccountViewAdapter;
    /// use stellar_agent_network::{AccountView, AssetView, BalanceView, ThresholdsView};
    ///
    /// let view = AccountView::new(
    ///     "GABC".to_owned(),
    ///     1,
    ///     0,
    ///     vec![BalanceView::new(
    ///         AssetView::native(),
    ///         "10.0000000".to_owned(),
    ///         None,
    ///         "0.0000000".to_owned(),
    ///         "0.0000000".to_owned(),
    ///     )],
    ///     ThresholdsView::new(1, 0, 0, 0),
    ///     vec![],
    ///     None,
    ///     None,
    /// );
    /// let adapter = AccountViewAdapter::new(&view);
    /// ```
    #[must_use]
    pub fn new(view: &'a AccountView) -> Self {
        Self(view)
    }
}

impl AccountReservesView for AccountViewAdapter<'_> {
    /// Delegates to [`AccountView::reserves_stroops`], which computes
    /// `(2 + subentry_count) * base_reserve_stroops` with saturating arithmetic.
    fn reserves_stroops(&self, base_reserve_stroops: i64) -> i64 {
        self.0.reserves_stroops(base_reserve_stroops)
    }

    /// Returns the native XLM balance in stroops from the first native entry
    /// in `AccountView.balances`.
    ///
    /// # Errors
    ///
    /// - Returns [`AccountReserveLookupError`] with detail `"no native balance
    ///   entry"` if `balances` is empty or if the first entry is not a native
    ///   XLM entry.
    /// - Returns [`AccountReserveLookupError`] with the parse error detail if
    ///   `BalanceView::balance_stroops()` fails (malformed balance string or
    ///   negative value).
    fn balance_stroops(&self) -> Result<i64, AccountReserveLookupError> {
        self.0
            .balances
            .first()
            .filter(|b| b.asset.asset_type == "native")
            .ok_or_else(|| AccountReserveLookupError {
                detail: "no native balance entry".to_owned(),
            })
            .and_then(|b| {
                b.balance_stroops().map_err(|e| AccountReserveLookupError {
                    detail: e.to_string(),
                })
            })
    }
}

impl AccountIdentityView for AccountViewAdapter<'_> {
    /// Returns the account's `home_domain` field, delegating to
    /// `AccountView.home_domain`.
    ///
    /// `None` when the on-chain `AccountEntry.home_domain` was empty or
    /// contained non-ASCII bytes at projection time (see `project_home_domain`
    /// in this crate).
    ///
    /// `home_domain` lives on `AccountIdentityView` (a required impl), not on
    /// `AccountReservesView`.
    fn home_domain(&self) -> Option<String> {
        self.0.home_domain.clone()
    }

    /// Returns the account's G-strkey.
    ///
    /// Delegates to `AccountView.account_id`.
    fn account_id(&self) -> &str {
        &self.0.account_id
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
    use crate::{AssetView, BalanceView, ThresholdsView};
    use stellar_agent_core::BASE_RESERVE_STROOPS;

    fn make_view(balance: &str, subentry_count: u32) -> AccountView {
        AccountView::new(
            "GABC123456789012345678901234567890123456789012345678901234".to_owned(),
            1,
            subentry_count,
            vec![BalanceView::new(
                AssetView::native(),
                balance.to_owned(),
                None,
                "0.0000000".to_owned(),
                "0.0000000".to_owned(),
            )],
            ThresholdsView::new(1, 0, 0, 0),
            vec![],
            None,
            None,
        )
    }

    // ── account_view_adapter_reserves_stroops_passes_through ─────────────────

    /// Verifies that `AccountViewAdapter::reserves_stroops` passes the call
    /// through to `AccountView::reserves_stroops` unchanged.
    #[test]
    fn account_view_adapter_reserves_stroops_passes_through() {
        let view = make_view("100.0000000", 5);
        let adapter = AccountViewAdapter::new(&view);
        // (2 + 5) * 5_000_000 = 35_000_000
        assert_eq!(adapter.reserves_stroops(BASE_RESERVE_STROOPS), 35_000_000);
    }

    // ── account_view_adapter_balance_stroops_native_only ─────────────────────

    /// Verifies the adapter reads the first native balance entry correctly.
    #[test]
    fn account_view_adapter_balance_stroops_native_only() {
        let view = make_view("100.0000000", 0);
        let adapter = AccountViewAdapter::new(&view);
        // 100 XLM = 1_000_000_000 stroops.
        assert_eq!(adapter.balance_stroops().unwrap(), 1_000_000_000_i64);
    }

    // ── account_view_adapter_no_native_balance_returns_err ───────────────────

    /// Verifies the adapter returns a typed Err when the balances list is empty.
    #[test]
    fn account_view_adapter_no_native_balance_returns_err() {
        let view = AccountView::new(
            "GABC".to_owned(),
            1,
            0,
            vec![], // no balances at all
            ThresholdsView::new(1, 0, 0, 0),
            vec![],
            None,
            None,
        );
        let adapter = AccountViewAdapter::new(&view);
        let result = adapter.balance_stroops();
        assert!(result.is_err(), "empty balances must return Err");
        let err = result.unwrap_err();
        assert!(
            err.detail.contains("no native balance entry"),
            "error must mention missing entry; got: {}",
            err.detail
        );
    }

    /// Verifies the adapter returns a typed Err when the first balance is non-native.
    #[test]
    fn account_view_adapter_non_native_first_balance_returns_err() {
        let view = AccountView::new(
            "GABC".to_owned(),
            1,
            1,
            vec![BalanceView::new(
                AssetView::credit(
                    "USDC",
                    "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
                ),
                "50.0000000".to_owned(),
                Some("1000.0000000".to_owned()),
                "0.0000000".to_owned(),
                "0.0000000".to_owned(),
            )],
            ThresholdsView::new(1, 0, 0, 0),
            vec![],
            None,
            None,
        );
        let adapter = AccountViewAdapter::new(&view);
        let result = adapter.balance_stroops();
        assert!(result.is_err(), "non-native first entry must return Err");
    }

    /// Zero XLM balance round-trips without error.
    #[test]
    fn account_view_adapter_zero_balance_round_trips() {
        let view = make_view("0.0000000", 0);
        let adapter = AccountViewAdapter::new(&view);
        assert_eq!(adapter.balance_stroops().unwrap(), 0_i64);
    }

    // ── account_view_adapter_identity ────────────────────────────────────────

    /// Verifies that the `AccountIdentityView` impl over `AccountViewAdapter`
    /// returns the expected `home_domain` string when the underlying
    /// `AccountView` has the field set.
    ///
    /// Also verifies that `home_domain()` returns `None` when the field is
    /// absent.  `home_domain` lives on `AccountIdentityView`, not
    /// `AccountReservesView`.
    #[test]
    fn account_view_adapter_home_domain_returns_field_via_identity_view() {
        use stellar_agent_core::policy::v1::AccountIdentityView;

        let view_with_domain = AccountView::new(
            "GABC123456789012345678901234567890123456789012345678901234".to_owned(),
            1,
            0,
            vec![BalanceView::new(
                AssetView::native(),
                "50.0000000".to_owned(),
                None,
                "0.0000000".to_owned(),
                "0.0000000".to_owned(),
            )],
            ThresholdsView::new(1, 0, 0, 0),
            vec![],
            Some("circle.com".to_owned()),
            None,
        );
        let adapter = AccountViewAdapter::new(&view_with_domain);
        assert_eq!(
            adapter.home_domain().as_deref(),
            Some("circle.com"),
            "home_domain must be surfaced via AccountIdentityView::home_domain"
        );
        assert_eq!(
            adapter.account_id(),
            "GABC123456789012345678901234567890123456789012345678901234",
            "account_id must be surfaced via AccountIdentityView::account_id"
        );

        // Verify None round-trips.
        let view_no_domain = make_view("10.0000000", 0);
        let adapter_no_domain = AccountViewAdapter::new(&view_no_domain);
        assert!(
            adapter_no_domain.home_domain().is_none(),
            "None home_domain must return None from AccountIdentityView::home_domain"
        );
    }
}
