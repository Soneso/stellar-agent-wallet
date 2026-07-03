//! Typed vault operation preview for DeFindex.
//!
//! # What this module does
//!
//! Produces the [`VaultOperationPreview`] struct used to build the
//! `DefiPreview` summary string.  The preview includes:
//!
//! - Operation (deposit or withdraw), vault address (redacted), network.
//! - Amount(s) with slippage floors.
//! - Four role disclosures (first-5-last-5 redacted) with self-managed /
//!   delegated label.
//! - Per-strategy Blend-strategy annotation (via WASM-hash match).
//! - Upgradable flag status.

use stellar_agent_core::observability::redact_strkey_first5_last5;

use crate::abi::{VaultDepositArgs, VaultWithdrawArgs, WalletAssetStrategySet};
use crate::roles::{VaultManagementMode, VaultRolesSnapshot};

/// Operation kind for the vault preview.
#[derive(Debug, Clone)]
pub enum VaultOperation {
    /// Deposit operation.
    Deposit,
    /// Withdraw operation.
    Withdraw,
}

impl std::fmt::Display for VaultOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultOperation::Deposit => write!(f, "deposit"),
            VaultOperation::Withdraw => write!(f, "withdraw"),
        }
    }
}

/// Typed vault operation preview.
///
/// Built from verified on-chain data (roles + assets) plus the caller args.
/// Used to populate the `DefiPreview` summary string.
#[derive(Debug, Clone)]
pub struct VaultOperationPreview {
    /// Operation kind.
    pub operation: VaultOperation,
    /// First-5-last-5 redacted vault address.
    pub vault_redacted: String,
    /// Network identifier.
    pub network: String,
    /// Whether the vault is upgradable.
    pub is_upgradable: bool,
    /// Role disclosure.
    pub roles: VaultRolesSnapshot,
    /// Management mode relative to the depositor/withdrawer address.
    pub management_mode: VaultManagementMode,
    /// Asset/strategy set from on-chain (with Blend detection applied).
    pub assets: Vec<WalletAssetStrategySet>,
    /// For deposit: amounts_desired.
    pub amounts: Vec<i128>,
    /// For deposit: amounts_min / for withdraw: min_amounts_out.
    pub amounts_floor: Vec<i128>,
    /// For withdraw: the share count to burn.
    pub withdraw_shares: Option<i128>,
    /// Whether invest-on-deposit is requested.
    pub invest: Option<bool>,
}

impl VaultOperationPreview {
    /// Builds a deposit preview.
    #[must_use]
    pub fn from_deposit(
        args: &VaultDepositArgs,
        network: &str,
        is_upgradable: bool,
        roles: VaultRolesSnapshot,
        assets: Vec<WalletAssetStrategySet>,
    ) -> Self {
        let management_mode = roles.management_mode(&args.from_address);
        Self {
            operation: VaultOperation::Deposit,
            vault_redacted: redact_strkey_first5_last5(&args.vault_address),
            network: network.to_owned(),
            is_upgradable,
            roles,
            management_mode,
            assets,
            amounts: args.amounts_desired.clone(),
            amounts_floor: args.amounts_min.clone(),
            withdraw_shares: None,
            invest: Some(args.invest),
        }
    }

    /// Builds a withdraw preview.
    #[must_use]
    pub fn from_withdraw(
        args: &VaultWithdrawArgs,
        network: &str,
        is_upgradable: bool,
        roles: VaultRolesSnapshot,
        assets: Vec<WalletAssetStrategySet>,
    ) -> Self {
        let management_mode = roles.management_mode(&args.from_address);
        Self {
            operation: VaultOperation::Withdraw,
            vault_redacted: redact_strkey_first5_last5(&args.vault_address),
            network: network.to_owned(),
            is_upgradable,
            roles,
            management_mode,
            assets,
            amounts: Vec::new(),
            amounts_floor: args.min_amounts_out.clone(),
            withdraw_shares: Some(args.withdraw_shares),
            invest: None,
        }
    }

    /// Returns a human-readable one-line summary of the preview.
    ///
    /// Uses first-5-last-5 redacted addresses throughout.  Full addresses
    /// NEVER appear.
    #[must_use]
    pub fn summary(&self) -> String {
        // The preview is built only on the proceeding path (after the gate's
        // upgradable eval passed), so an `upgradable:true` vault here is either
        // self-managed (exempt) or proceeded under a per-invocation
        // override — NOT refused.  Label it by which, never "REFUSED".
        let upgradable_label = if self.is_upgradable {
            match &self.management_mode {
                VaultManagementMode::SelfManaged => "upgradable=true(self-managed:exempt)",
                _ => "upgradable=true(non-self-managed:override-required)",
            }
        } else {
            "upgradable=false"
        };

        let management_label = match &self.management_mode {
            VaultManagementMode::SelfManaged => "self-managed",
            VaultManagementMode::Delegated {
                third_party_emergency_manager,
                third_party_rebalance_manager,
            } => {
                if *third_party_emergency_manager && *third_party_rebalance_manager {
                    "delegated(em+rm)"
                } else if *third_party_emergency_manager {
                    "delegated(em)"
                } else {
                    "delegated(rm)"
                }
            }
            VaultManagementMode::NotManager => "not-manager",
        };

        let blend_count = self
            .assets
            .iter()
            .flat_map(|a| a.strategies.iter())
            .filter(|s| s.is_blend_strategy)
            .count();

        let blend_label = if blend_count > 0 {
            format!(" blend_strategies={blend_count}")
        } else {
            String::new()
        };

        match &self.operation {
            VaultOperation::Deposit => {
                let amounts_str: String = self
                    .amounts
                    .iter()
                    .zip(self.amounts_floor.iter())
                    .enumerate()
                    .map(|(i, (d, m))| format!("[{i}] desired={d} min={m}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "vault=deposit vault={} network={} {upgradable_label} {management_label}{blend_label} amounts=[{amounts_str}] roles={}",
                    self.vault_redacted,
                    self.network,
                    self.roles.disclosure_summary(),
                )
            }
            VaultOperation::Withdraw => {
                let shares = self.withdraw_shares.unwrap_or(0);
                let min_str: String = self
                    .amounts_floor
                    .iter()
                    .enumerate()
                    .map(|(i, m)| format!("[{i}] min={m}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "vault=withdraw vault={} network={} {upgradable_label} {management_label}{blend_label} shares={shares} min_out=[{min_str}] roles={}",
                    self.vault_redacted,
                    self.network,
                    self.roles.disclosure_summary(),
                )
            }
        }
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

    use super::*;
    use crate::abi::{VaultDepositArgs, WalletStrategy};
    use stellar_agent_core::observability::redact_strkey_first5_last5;

    const VAULT: &str = "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN";
    const FROM: &str = "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD";

    fn test_roles() -> VaultRolesSnapshot {
        VaultRolesSnapshot {
            manager: Some(FROM.to_owned()),
            manager_redacted: Some(redact_strkey_first5_last5(FROM)),
            emergency_manager: Some(FROM.to_owned()),
            emergency_manager_redacted: Some(redact_strkey_first5_last5(FROM)),
            rebalance_manager: Some(FROM.to_owned()),
            rebalance_manager_redacted: Some(redact_strkey_first5_last5(FROM)),
            vault_fee_receiver: Some(FROM.to_owned()),
            vault_fee_receiver_redacted: Some(redact_strkey_first5_last5(FROM)),
        }
    }

    fn test_assets(blend: bool) -> Vec<WalletAssetStrategySet> {
        vec![WalletAssetStrategySet {
            address: "CBSOMEASSET1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            strategies: vec![WalletStrategy {
                address: "CBSOMESTRAT1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                name: "blend_fixed_xlm_usdc".to_owned(),
                paused: false,
                is_blend_strategy: blend,
            }],
        }]
    }

    fn deposit_args() -> VaultDepositArgs {
        VaultDepositArgs {
            vault_address: VAULT.to_owned(),
            amounts_desired: vec![1_000_000],
            amounts_min: vec![900_000],
            from_address: FROM.to_owned(),
            invest: false,
            override_upgradable: false,
        }
    }

    // ── Summary does not contain full addresses ───────────────────────────────

    #[test]
    fn deposit_summary_does_not_leak_full_address() {
        let preview = VaultOperationPreview::from_deposit(
            &deposit_args(),
            "testnet",
            false,
            test_roles(),
            test_assets(false),
        );
        let summary = preview.summary();
        assert!(
            !summary.contains(VAULT),
            "full vault address must not appear in summary: {summary}"
        );
        assert!(
            !summary.contains(FROM),
            "full from address must not appear in summary: {summary}"
        );
    }

    // ── Upgradable label appears in summary ───────────────────────────────────

    #[test]
    fn upgradable_true_self_managed_shows_exempt_label() {
        // `test_roles()` sets manager == emergency == rebalance == FROM, so the
        // mode is SelfManaged → exempt from the upgrade refusal. The
        // preview is built only on the proceeding path, so the label must NOT
        // say "REFUSED".
        let preview = VaultOperationPreview::from_deposit(
            &deposit_args(),
            "testnet",
            true, // upgradable=true
            test_roles(),
            test_assets(false),
        );
        let summary = preview.summary();
        assert!(
            summary.contains("upgradable=true(self-managed:exempt)"),
            "self-managed upgradable:true must show exempt label, not REFUSED: {summary}"
        );
        assert!(
            !summary.contains("REFUSED"),
            "a proceeding self-managed vault must never show REFUSED: {summary}"
        );
    }

    // ── Withdraw preview ──────────────────────────────────────────────────────

    #[test]
    fn withdraw_summary_does_not_leak_full_address() {
        use crate::abi::VaultWithdrawArgs;

        let withdraw_args = VaultWithdrawArgs {
            vault_address: VAULT.to_owned(),
            withdraw_shares: 5_000_000i128,
            min_amounts_out: vec![4_500_000i128],
            from_address: FROM.to_owned(),
            override_upgradable: false,
        };

        let preview = VaultOperationPreview::from_withdraw(
            &withdraw_args,
            "testnet",
            false,
            test_roles(),
            test_assets(false),
        );

        let summary = preview.summary();

        // Full vault address must NOT appear.
        assert!(
            !summary.contains(VAULT),
            "full vault address must not appear in withdraw summary: {summary}"
        );
        // Full from address must NOT appear.
        assert!(
            !summary.contains(FROM),
            "full from address must not appear in withdraw summary: {summary}"
        );

        // shares= value must appear in the summary string.
        assert!(
            summary.contains("shares=5000000"),
            "withdraw shares count must appear in summary: {summary}"
        );

        // min_out floor value must appear in the summary string.
        assert!(
            summary.contains("4500000"),
            "min_out floor value must appear in summary: {summary}"
        );

        // Operation must be Withdraw.
        assert!(
            matches!(preview.operation, VaultOperation::Withdraw),
            "operation must be Withdraw"
        );
    }

    // ── Blend strategy label ──────────────────────────────────────────────────

    #[test]
    fn blend_strategy_count_appears_in_summary() {
        let preview = VaultOperationPreview::from_deposit(
            &deposit_args(),
            "testnet",
            false,
            test_roles(),
            test_assets(true), // has blend strategy
        );
        let summary = preview.summary();
        assert!(
            summary.contains("blend_strategies=1"),
            "blend strategy count must appear: {summary}"
        );
    }
}
