//! Value-carrying policy-gate leg construction for the `vault` verb.
//!
//! [`vault_deposit_value_legs`] / [`vault_withdraw_value_leg`] are shared by
//! the `stellar_defindex_vault_deposit` / `stellar_defindex_vault_withdraw`
//! MCP tools and the `stellar-agent vault deposit` / `stellar-agent vault
//! withdraw` CLI subcommands, so all four call sites size their
//! `PolicyEngine::evaluate_with_value` gate from the identical mapping. Every
//! call site passes the SAME parsed amounts vector (deposit) or shares value
//! (withdraw) later placed into `VaultDepositArgs` / `VaultWithdrawArgs` and
//! signed — the single-decode invariant: the effect sized by policy is
//! exactly the effect signed.

use stellar_agent_core::policy::v1::{ActionKind, ValueLeg};

// ─────────────────────────────────────────────────────────────────────────────
// vault_deposit_value_legs / vault_withdraw_value_leg — pure leg-construction
// helpers (single-decode invariant)
// ─────────────────────────────────────────────────────────────────────────────

/// Builds one debit [`ValueLeg`] per deposited asset for the `vault deposit`
/// verb's value-carrying policy gate.
///
/// `amounts_desired` and `asset_addresses` are zipped 1:1 by index — the
/// caller MUST have already confirmed (via
/// [`crate::abi::VaultDepositArgs::validate_against_asset_count`])
/// that both slices carry the vault's on-chain asset count. Any length
/// mismatch is truncated to the shorter slice by [`Iterator::zip`] rather
/// than panicking — a defensive fallback only, since the caller-side length
/// check is the authoritative gate.
///
/// Every leg is [`ActionKind::VaultDeposit`] (a debit: value leaving the
/// wallet into the vault) with `destination = vault_address`.
///
/// Callers pass the SAME `amounts_desired` vector later placed into the
/// `VaultDepositArgs` signed by the adapter, and `asset_addresses` derived
/// from the SAME PIN-VERIFIED `read_vault_assets` result used to validate the
/// amounts length — the single-decode invariant. This is a pure function so
/// it can be unit-tested directly without exercising the async handler.
#[must_use]
pub fn vault_deposit_value_legs(
    amounts_desired: &[i128],
    asset_addresses: &[String],
    vault_address: &str,
) -> Vec<ValueLeg> {
    amounts_desired
        .iter()
        .zip(asset_addresses.iter())
        .map(|(amount, asset)| ValueLeg {
            kind: ActionKind::VaultDeposit,
            amount: Some(*amount),
            asset: Some(asset.clone()),
            destination: Some(vault_address.to_owned()),
        })
        .collect()
}

/// Builds the single [`ValueLeg`] for the `vault withdraw` verb's
/// value-carrying policy gate.
///
/// `kind` is [`ActionKind::VaultWithdraw`] — a redemption that returns funds
/// to the wallet, not a spendable-balance debit
/// ([`ActionKind::carries_debit`] is `false`). `amount` is honestly the
/// number of vault shares redeemed (not an underlying-asset amount); value
/// caps and `minimum_reserve` skip non-debit legs, so this amount is
/// reported for counterparty/asset visibility only, never used to size a
/// debit. `asset` is `None`: a withdrawal returns a basket of underlying
/// assets (`min_amounts_out` spans the vault's whole asset set), so no
/// single token id represents "the" asset, and the vault-share token id
/// itself is out of scope for this step.
///
/// Callers pass the SAME `withdraw_shares` value later placed into the
/// `VaultWithdrawArgs` signed by the adapter — the single-decode invariant.
/// This is a pure function so it can be unit-tested directly without
/// exercising the async handler.
#[must_use]
pub fn vault_withdraw_value_leg(withdraw_shares: i128, vault_address: &str) -> ValueLeg {
    ValueLeg {
        kind: ActionKind::VaultWithdraw,
        amount: Some(withdraw_shares),
        asset: None,
        destination: Some(vault_address.to_owned()),
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
    use super::{vault_deposit_value_legs, vault_withdraw_value_leg};
    use stellar_agent_core::policy::v1::ActionKind;

    #[test]
    fn vault_deposit_value_legs_one_leg_per_asset_with_matching_amount_and_asset() {
        const VAULT: &str = "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN";
        let asset_a = "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU".to_owned();
        let asset_b = "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD".to_owned();
        let amounts_desired = vec![250_000_000_i128, 9_007_199_254_740_993_i128];
        let asset_addresses = vec![asset_a.clone(), asset_b.clone()];

        let legs = vault_deposit_value_legs(&amounts_desired, &asset_addresses, VAULT);

        assert_eq!(legs.len(), 2);
        for (leg, (expected_amount, expected_asset)) in legs
            .iter()
            .zip(amounts_desired.iter().zip(asset_addresses.iter()))
        {
            assert_eq!(leg.kind, ActionKind::VaultDeposit);
            assert!(leg.kind.carries_debit(), "a vault deposit is a debit");
            // Single-decode invariant: the leg amount is exactly the
            // `amounts_desired` entry later placed into `VaultDepositArgs`.
            assert_eq!(leg.amount, Some(*expected_amount));
            assert_eq!(leg.asset.as_deref(), Some(expected_asset.as_str()));
            assert_eq!(leg.destination.as_deref(), Some(VAULT));
        }
    }

    #[test]
    fn vault_deposit_value_legs_empty_amounts_yields_no_legs() {
        const VAULT: &str = "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN";
        let legs = vault_deposit_value_legs(&[], &[], VAULT);
        assert!(legs.is_empty());
    }

    #[test]
    fn vault_withdraw_value_leg_carries_shares_as_amount_no_asset_non_debit() {
        const VAULT: &str = "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN";
        let withdraw_shares = 9_007_199_254_740_993_i128;

        let leg = vault_withdraw_value_leg(withdraw_shares, VAULT);

        assert_eq!(leg.kind, ActionKind::VaultWithdraw);
        assert!(
            !leg.kind.carries_debit(),
            "a vault withdrawal returns funds; it is not a spendable-balance debit"
        );
        // Single-decode invariant: the leg amount is exactly `withdraw_shares`,
        // the same integer placed into `VaultWithdrawArgs.withdraw_shares`.
        assert_eq!(leg.amount, Some(withdraw_shares));
        assert_eq!(leg.asset, None);
        assert_eq!(leg.destination.as_deref(), Some(VAULT));
    }
}
