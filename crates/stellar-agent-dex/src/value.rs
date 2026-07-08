//! Value-carrying policy-gate leg construction for the `trade` verb.
//!
//! [`dex_trade_value_leg`] is shared by the `stellar_dex_trade` MCP tool and
//! the `stellar-agent trade` CLI subcommand, so both verbs size their
//! `PolicyEngine::evaluate_with_value` gate from the identical send-side leg.
//! Both call sites pass the SAME parsed `qty_in` / canonicalised path they
//! later place into `TradeArgs` and sign — the single-decode invariant: the
//! effect sized by policy is exactly the effect signed.

use stellar_agent_core::policy::v1::{ActionKind, ValueLeg};

// ─────────────────────────────────────────────────────────────────────────────
// dex_trade_value_leg — pure leg-construction helper (single-decode invariant)
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the single debit [`ValueLeg`] for the `trade` verb's
/// value-carrying policy gate.
///
/// The leg carries the SEND side of the swap — the value leaving the wallet
/// — never the receive side: `amount = Some(qty_in)`, `asset` is the send
/// asset (`canonical_path`'s first element), and `destination` is the
/// Soroswap router address (the only on-chain counterparty contract this
/// call is ever routed through).
///
/// `canonical_path` may (structurally) be shorter than 2 elements at this
/// call site — the `[2, 5]` length bound is enforced later, inside
/// `DexSwapAdapter::submit` — so `asset` degrades to `None` rather than
/// panicking when `canonical_path` is empty; the adapter's own length check
/// still fail-closes the call before any signing occurs.
///
/// Callers pass the SAME `qty_in` / `canonical_path` used to construct
/// `TradeArgs` — the single-decode invariant. This is a pure function so it
/// can be unit-tested directly without exercising the async handler.
#[must_use]
pub fn dex_trade_value_leg(
    qty_in: i128,
    canonical_path: &[String],
    router_address: &str,
) -> ValueLeg {
    ValueLeg {
        kind: ActionKind::DexTrade,
        amount: Some(qty_in),
        asset: canonical_path.first().cloned(),
        destination: Some(router_address.to_owned()),
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
        reason = "test-only fixture construction"
    )]
    use super::dex_trade_value_leg;
    use stellar_agent_core::policy::v1::ActionKind;

    #[test]
    fn dex_trade_value_leg_carries_send_side_amount_asset_and_router_destination() {
        const ROUTER: &str = "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD";
        let canonical_path = vec![
            "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU".to_owned(),
            "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD".to_owned(),
        ];
        let qty_in = 9_007_199_254_740_993_i128;

        let leg = dex_trade_value_leg(qty_in, &canonical_path, ROUTER);

        assert_eq!(leg.kind, ActionKind::DexTrade);
        assert!(leg.kind.carries_debit(), "the send side is a debit");
        // Single-decode invariant: the leg amount is exactly `qty_in`, the same
        // integer placed into `TradeArgs.amount_in`.
        assert_eq!(leg.amount, Some(qty_in));
        assert_eq!(leg.asset.as_deref(), Some(canonical_path[0].as_str()));
        assert_eq!(leg.destination.as_deref(), Some(ROUTER));
    }

    #[test]
    fn dex_trade_value_leg_does_not_carry_the_receive_side() {
        const ROUTER: &str = "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD";
        let canonical_path = vec![
            "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU".to_owned(),
            "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD".to_owned(),
        ];
        let leg = dex_trade_value_leg(1_000_000_i128, &canonical_path, ROUTER);
        assert_ne!(
            leg.asset.as_deref(),
            Some(canonical_path[1].as_str()),
            "the leg must not carry the receive-side (last) path element"
        );
    }

    #[test]
    fn dex_trade_value_leg_empty_path_degrades_asset_to_none_without_panicking() {
        const ROUTER: &str = "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD";
        let leg = dex_trade_value_leg(1_000_000_i128, &[], ROUTER);
        assert_eq!(leg.amount, Some(1_000_000_i128));
        assert_eq!(leg.asset, None);
        assert_eq!(leg.destination.as_deref(), Some(ROUTER));
    }
}
