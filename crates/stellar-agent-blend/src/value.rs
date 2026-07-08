//! Value-carrying policy-gate leg construction for the `lend` verb.
//!
//! [`blend_value_legs`] is shared by the `stellar_blend_lend` MCP tool and the
//! `stellar-agent lend` CLI subcommand, so both verbs size their
//! `PolicyEngine::evaluate_with_value` gate from the identical mapping of
//! [`BlendRequest`] discriminants to [`ValueLeg`]s.  Both call sites pass the
//! SAME parsed `BlendRequest` vector they later place into `LendArgs` and sign
//! — the single-decode invariant: the effect sized by policy is exactly the
//! effect signed.

use crate::abi::{BlendRequest, RequestType};
use stellar_agent_core::policy::v1::{ActionKind, ValueLeg};

// ─────────────────────────────────────────────────────────────────────────────
// blend_value_legs — pure leg-construction helper (single-decode invariant)
// ─────────────────────────────────────────────────────────────────────────────

/// Builds one [`ValueLeg`] per `reqs` entry for the `lend` verb's
/// value-carrying policy gate.
///
/// Direction mapping (debit = value leaving the wallet into the pool):
///
/// | `RequestType` | `ActionKind` | `amount` |
/// |---|---|---|
/// | `Supply`, `SupplyCollateral`, `Repay` | [`ActionKind::Lend`] | `Some(req.amount)` |
/// | `Withdraw`, `WithdrawCollateral`, `Borrow` | [`ActionKind::LendWithdraw`] | `Some(req.amount)` |
/// | `FillUserLiquidationAuction`, `FillBadDebtAuction`, `FillInterestAuction`, `DeleteLiquidationAuction` | [`ActionKind::LendWithdraw`] | `None` |
///
/// The four liquidation discriminants (6-9) are unreachable via the `lend`
/// verb — both call sites refuse request types > 5 before this function runs.
/// They map to the non-debit shape deliberately: a fill request's
/// `req.amount` is a fill PERCENTAGE, not a token debit in stroops, so it must
/// never be summed by a value cap. Whoever wires a `liquidate` verb must model
/// the auction's actual token movement explicitly rather than reuse this
/// mapping.
///
/// `asset` is `Some(req.address.clone())` only when
/// [`BlendRequest::is_asset_address`] is `true` (the lending discriminants
/// 0-5); the liquidation discriminants' `address` is a liquidatee/backstop
/// account, not a reserve token, so `asset` is `None` for those.
/// `destination` is `pool` for every leg.
///
/// Callers pass the SAME `reqs` vector that is later placed into `LendArgs`
/// and signed — the single-decode invariant. This is a pure function so it
/// can be unit-tested directly without exercising the async handler.
#[must_use]
pub fn blend_value_legs(reqs: &[BlendRequest], pool: &str) -> Vec<ValueLeg> {
    reqs.iter()
        .map(|req| {
            let (kind, amount) = match req.request_type {
                RequestType::Supply | RequestType::SupplyCollateral | RequestType::Repay => {
                    (ActionKind::Lend, Some(req.amount))
                }
                RequestType::Withdraw | RequestType::WithdrawCollateral | RequestType::Borrow => {
                    (ActionKind::LendWithdraw, Some(req.amount))
                }
                // Liquidation verbs (6-9) are unreachable here (the `lend` verb
                // refuses request types > 5). `req.amount` for a fill is a
                // PERCENTAGE, not a stroops debit, so these map to the
                // non-debit shape and must never be summed by a value cap; a
                // future `liquidate` verb must model the auction's token
                // movement explicitly.
                RequestType::FillUserLiquidationAuction
                | RequestType::FillBadDebtAuction
                | RequestType::FillInterestAuction
                | RequestType::DeleteLiquidationAuction => (ActionKind::LendWithdraw, None),
            };
            let asset = req.is_asset_address().then(|| req.address.clone());
            ValueLeg {
                kind,
                amount,
                asset,
                destination: Some(pool.to_owned()),
            }
        })
        .collect()
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
        reason = "test-only fixture construction"
    )]
    use super::blend_value_legs;
    use crate::abi::{BlendRequest, RequestType};
    use stellar_agent_core::policy::v1::ActionKind;

    #[test]
    fn blend_value_legs_maps_outflow_kinds_to_lend_with_matching_amount_and_asset() {
        const POOL: &str = "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF";
        const ASSET: &str = "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU";

        for rt in [
            RequestType::Supply,
            RequestType::SupplyCollateral,
            RequestType::Repay,
        ] {
            let req = BlendRequest::new(rt, ASSET, 250_000_000_i128);
            let legs = blend_value_legs(std::slice::from_ref(&req), POOL);
            assert_eq!(legs.len(), 1);
            let leg = &legs[0];
            assert_eq!(leg.kind, ActionKind::Lend, "{rt:?} must map to Lend");
            assert!(leg.kind.carries_debit(), "{rt:?} must carry a debit");
            // Single-decode invariant: the leg amount is exactly the on-chain
            // `Request.amount` the operation carries — no independent re-parse.
            assert_eq!(leg.amount, Some(req.amount));
            assert_eq!(leg.asset.as_deref(), Some(ASSET));
            assert_eq!(leg.destination.as_deref(), Some(POOL));
        }
    }

    #[test]
    fn blend_value_legs_maps_inflow_kinds_to_lend_withdraw_non_debit() {
        const POOL: &str = "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF";
        const ASSET: &str = "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU";

        for rt in [
            RequestType::Withdraw,
            RequestType::WithdrawCollateral,
            RequestType::Borrow,
        ] {
            let req = BlendRequest::new(rt, ASSET, 100_000_000_i128);
            let legs = blend_value_legs(std::slice::from_ref(&req), POOL);
            assert_eq!(legs.len(), 1);
            let leg = &legs[0];
            assert_eq!(
                leg.kind,
                ActionKind::LendWithdraw,
                "{rt:?} must map to LendWithdraw"
            );
            assert!(
                !leg.kind.carries_debit(),
                "{rt:?} must not be treated as a spendable-balance debit"
            );
            assert_eq!(leg.amount, Some(req.amount));
            assert_eq!(leg.asset.as_deref(), Some(ASSET));
        }
    }

    #[test]
    fn blend_value_legs_delete_liquidation_auction_carries_no_amount() {
        const POOL: &str = "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF";
        const LIQUIDATEE: &str = "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD";

        let req = BlendRequest::new(RequestType::DeleteLiquidationAuction, LIQUIDATEE, 0_i128);
        let legs = blend_value_legs(std::slice::from_ref(&req), POOL);
        assert_eq!(legs.len(), 1);
        assert_eq!(legs[0].kind, ActionKind::LendWithdraw);
        assert_eq!(legs[0].amount, None, "delete-auction moves no value");
        assert_eq!(
            legs[0].asset, None,
            "the address field is a liquidatee, not a reserve asset"
        );
    }

    #[test]
    fn blend_value_legs_mixed_request_call_yields_correct_direction_per_leg() {
        const POOL: &str = "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF";
        const ASSET_A: &str = "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU";
        const ASSET_B: &str = "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD";

        let reqs = vec![
            BlendRequest::new(RequestType::Supply, ASSET_A, 500_000_000_i128),
            BlendRequest::new(RequestType::Borrow, ASSET_B, 100_000_000_i128),
        ];
        let legs = blend_value_legs(&reqs, POOL);
        assert_eq!(legs.len(), 2);

        assert_eq!(legs[0].kind, ActionKind::Lend);
        assert!(legs[0].kind.carries_debit(), "Supply is an outflow");
        assert_eq!(legs[0].amount, Some(500_000_000_i128));
        assert_eq!(legs[0].asset.as_deref(), Some(ASSET_A));

        assert_eq!(legs[1].kind, ActionKind::LendWithdraw);
        assert!(
            !legs[1].kind.carries_debit(),
            "Borrow is an inflow, not a spendable-balance debit"
        );
        assert_eq!(legs[1].amount, Some(100_000_000_i128));
        assert_eq!(legs[1].asset.as_deref(), Some(ASSET_B));
    }
}
