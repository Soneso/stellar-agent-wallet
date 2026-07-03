//! Wallet-authored DeFindex vault ABI types.
//!
//! # ABI provenance
//!
//! All type names and field orderings are derived from the canonical DeFindex
//! vault interface at
//! `vault/src/interface.rs` (GPL-3.0, interface-bind only).
//!
//! ## `deposit` signature
//!
//! ```text
//! fn deposit(
//!     e: Env,
//!     amounts_desired: Vec<i128>,
//!     amounts_min: Vec<i128>,
//!     from: Address,
//!     invest: bool,
//! ) -> Result<(Vec<i128>, i128, Option<Vec<Option<AssetInvestmentAllocation>>>), ContractError>
//! ```
//!
//! Source: the DeFindex vault `interface.rs` `deposit` declaration.
//!
//! ## `withdraw` signature
//!
//! ```text
//! fn withdraw(
//!     e: Env,
//!     df_amount: i128,       // trait: df_amount; impl: withdraw_shares
//!     min_amounts_out: Vec<i128>,
//!     from: Address,
//! ) -> Result<Vec<i128>, ContractError>
//! ```
//!
//! Source: the DeFindex vault `interface.rs` `withdraw` declaration (trait) and
//! the `lib.rs` implementation (parameter name `withdraw_shares`).  The
//! POSITIONAL order is what matters for ScVal arg vector construction — not the
//! parameter name difference between trait and impl.
//!
//! ## `AssetStrategySet` model
//!
//! ```text
//! struct AssetStrategySet { address: Address, strategies: Vec<Strategy> }
//! struct Strategy { address: Address, name: String, paused: bool }
//! ```
//!
//! Source: the DeFindex `common/src/models.rs` model definitions.
//!
//! # `min_out` required field
//!
//! The `min_amounts_out` field on withdraw args (and `amounts_min` on deposit)
//! MUST be provided by the caller.  Length MUST equal the number of assets
//! in the vault (PIN-VERIFIED on-chain count).  Absence or length mismatch is
//! a structural pre-sign refuse — the wallet NEVER defaults to zero slippage.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// VaultDepositArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Typed arguments for the DeFindex vault `deposit` function.
///
/// Corresponds to `VaultTrait::deposit` in the DeFindex vault `interface.rs`.
///
/// # Field order (positional ScVal encoding)
///
/// The `InvokeContractArgs.args` vector is positional (NOT sorted).
/// Deposit call argument order:
///   1. `amounts_desired: Vec<i128>`
///   2. `amounts_min: Vec<i128>`
///   3. `from: Address`
///   4. `invest: bool`
///
/// The `Env` parameter is implicit and not encoded in the call args.
///
/// # `amounts_min` required
///
/// Length MUST equal the number of assets in the vault.  The wallet refuses
/// to sign if this constraint is violated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultDepositArgs {
    /// C-strkey address of the vault contract.
    pub vault_address: String,
    /// Desired deposit amounts, one per vault asset, in asset-native units.
    /// Index order matches `get_assets()` asset order.
    pub amounts_desired: Vec<i128>,
    /// Minimum accepted deposit amounts (slippage floor), one per vault asset.
    /// REQUIRED; must have same length as `amounts_desired`.
    pub amounts_min: Vec<i128>,
    /// Depositing account address (smart-account C-strkey).
    pub from_address: String,
    /// Whether to immediately invest the deposited funds into strategies.
    pub invest: bool,
    /// Whether to allow proceeding when the vault is marked upgradable:true
    /// (posture override; off by default).
    #[serde(default)]
    pub override_upgradable: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// VaultWithdrawArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Typed arguments for the DeFindex vault `withdraw` function.
///
/// Corresponds to `VaultTrait::withdraw` in the DeFindex vault `interface.rs`
/// (trait uses `df_amount`; the implementation uses `withdraw_shares`).
///
/// # Field order (positional ScVal encoding)
///
/// The `InvokeContractArgs.args` vector is positional (NOT sorted).
/// Withdraw call argument order:
///   1. `df_amount (withdraw_shares): i128`
///   2. `min_amounts_out: Vec<i128>`
///   3. `from: Address`
///
/// The `Env` parameter is implicit and not encoded in the call args.
///
/// # `min_amounts_out` required
///
/// Length MUST equal the number of assets in the vault.  The wallet refuses
/// to sign if this constraint is violated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultWithdrawArgs {
    /// C-strkey address of the vault contract.
    pub vault_address: String,
    /// Number of vault shares (dfTokens) to burn and redeem.
    /// Named `df_amount` in the trait, `withdraw_shares` in the impl.
    pub withdraw_shares: i128,
    /// Minimum accepted out-amounts, one per vault asset.
    /// REQUIRED; must have same length as the vault's asset count.
    pub min_amounts_out: Vec<i128>,
    /// Withdrawing account address (smart-account C-strkey).
    pub from_address: String,
    /// Whether to allow proceeding when the vault is marked upgradable:true
    /// (posture override; off by default).
    #[serde(default)]
    pub override_upgradable: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// WalletAssetStrategy / WalletAssetStrategySet
// ─────────────────────────────────────────────────────────────────────────────

/// Wallet-side representation of a single vault strategy entry.
///
/// Mirrors `common::models::Strategy` from the DeFindex `common/src/models.rs`.
/// Used in the typed preview display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletStrategy {
    /// C-strkey address of the strategy contract.
    pub address: String,
    /// Caller-supplied name (untrusted — NEVER used for Blend-strategy detection).
    pub name: String,
    /// Whether the strategy is currently paused.
    pub paused: bool,
    /// Whether this strategy was detected as a Blend strategy via WASM-hash match.
    #[serde(default)]
    pub is_blend_strategy: bool,
}

/// Wallet-side representation of a vault asset + strategy set entry.
///
/// Mirrors `common::models::AssetStrategySet` from the DeFindex
/// `common/src/models.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAssetStrategySet {
    /// C-strkey address of the asset contract (Stellar Asset Contract).
    pub address: String,
    /// Strategies managing this asset.
    pub strategies: Vec<WalletStrategy>,
}

// ─────────────────────────────────────────────────────────────────────────────
// VaultAbiError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when validating vault ABI types.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VaultAbiError {
    /// `amounts_min` length does not match `amounts_desired` length on a
    /// pure structural check (before on-chain asset count is known).
    #[error(
        "deposit: amounts_min length {amounts_min_len} != amounts_desired length {amounts_desired_len} (structural refuse)"
    )]
    DepositLengthMismatch {
        /// Length of `amounts_desired`.
        amounts_desired_len: usize,
        /// Length of `amounts_min`.
        amounts_min_len: usize,
    },

    /// `amounts_desired` or `amounts_min` length does not match the
    /// PIN-VERIFIED on-chain vault asset count.
    ///
    /// Both vectors must have exactly one entry per vault asset.
    #[error(
        "deposit: amounts_desired length {amounts_desired_len} or amounts_min length \
         {amounts_min_len} != expected vault asset count {expected_asset_count} (structural refuse)"
    )]
    DepositAmountsLengthMismatch {
        /// Length of `amounts_desired`.
        amounts_desired_len: usize,
        /// Length of `amounts_min`.
        amounts_min_len: usize,
        /// PIN-VERIFIED on-chain vault asset count.
        expected_asset_count: usize,
    },

    /// `min_amounts_out` length does not match expected vault asset count.
    #[error(
        "withdraw: min_amounts_out length {actual_len} != vault asset count {expected_len} (structural refuse)"
    )]
    WithdrawMinLengthMismatch {
        /// Expected length (vault asset count from on-chain).
        expected_len: usize,
        /// Actual length provided by caller.
        actual_len: usize,
    },

    /// `amounts_desired` or `amounts_min` is empty.
    #[error("deposit: amounts_desired must not be empty")]
    DepositAmountsEmpty,

    /// `withdraw_shares` is zero or negative.
    #[error("withdraw: withdraw_shares must be positive (got {shares})")]
    WithdrawSharesNotPositive {
        /// The zero or negative share count.
        shares: i128,
    },

    /// `min_amounts_out` is empty.
    #[error("withdraw: min_amounts_out must not be empty")]
    WithdrawMinAmountsEmpty,
}

impl VaultDepositArgs {
    /// Validates the structural constraints on deposit args.
    ///
    /// Checks that `amounts_desired` is non-empty and that `amounts_min` has the
    /// same length as `amounts_desired`.  Does NOT validate against the on-chain
    /// asset count (that happens after the ordered gate reads instance storage).
    ///
    /// # Errors
    ///
    /// Returns [`VaultAbiError`] when structural constraints are violated.
    pub fn validate_structure(&self) -> Result<(), VaultAbiError> {
        if self.amounts_desired.is_empty() {
            return Err(VaultAbiError::DepositAmountsEmpty);
        }
        if self.amounts_min.len() != self.amounts_desired.len() {
            return Err(VaultAbiError::DepositLengthMismatch {
                amounts_desired_len: self.amounts_desired.len(),
                amounts_min_len: self.amounts_min.len(),
            });
        }
        Ok(())
    }

    /// Validates both `amounts_desired` and `amounts_min` lengths against the
    /// PIN-VERIFIED on-chain vault asset count.
    ///
    /// A DeFindex deposit requires exactly one desired amount AND one minimum
    /// amount per vault asset.  Both vectors MUST equal `expected_asset_count`.
    ///
    /// Called after the ordered gate reads `get_assets()`.
    ///
    /// # Errors
    ///
    /// Returns [`VaultAbiError::DepositAmountsLengthMismatch`] when either
    /// `amounts_desired` or `amounts_min` length differs from `expected_asset_count`.
    pub fn validate_against_asset_count(
        &self,
        expected_asset_count: usize,
    ) -> Result<(), VaultAbiError> {
        let desired_len = self.amounts_desired.len();
        let min_len = self.amounts_min.len();
        if desired_len != expected_asset_count || min_len != expected_asset_count {
            return Err(VaultAbiError::DepositAmountsLengthMismatch {
                amounts_desired_len: desired_len,
                amounts_min_len: min_len,
                expected_asset_count,
            });
        }
        Ok(())
    }
}

impl VaultWithdrawArgs {
    /// Validates the structural constraints on withdraw args.
    ///
    /// Checks that `withdraw_shares` is positive and `min_amounts_out` is
    /// non-empty.  Does NOT check against on-chain asset count (that happens
    /// after the ordered gate reads `get_assets()`).
    ///
    /// # Errors
    ///
    /// Returns [`VaultAbiError`] when structural constraints are violated.
    pub fn validate_structure(&self) -> Result<(), VaultAbiError> {
        if self.withdraw_shares <= 0 {
            return Err(VaultAbiError::WithdrawSharesNotPositive {
                shares: self.withdraw_shares,
            });
        }
        if self.min_amounts_out.is_empty() {
            return Err(VaultAbiError::WithdrawMinAmountsEmpty);
        }
        Ok(())
    }

    /// Validates `min_amounts_out` length against the PIN-VERIFIED on-chain asset count.
    ///
    /// Called after the ordered gate reads `get_assets()`.
    ///
    /// # Errors
    ///
    /// Returns [`VaultAbiError`] when the length does not match the on-chain count.
    pub fn validate_against_asset_count(
        &self,
        expected_asset_count: usize,
    ) -> Result<(), VaultAbiError> {
        if self.min_amounts_out.len() != expected_asset_count {
            return Err(VaultAbiError::WithdrawMinLengthMismatch {
                expected_len: expected_asset_count,
                actual_len: self.min_amounts_out.len(),
            });
        }
        Ok(())
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

    fn test_deposit_args(desired_len: usize, min_len: usize) -> VaultDepositArgs {
        VaultDepositArgs {
            vault_address: "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN".to_owned(),
            amounts_desired: vec![1_000_000; desired_len],
            amounts_min: vec![900_000; min_len],
            from_address: "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD".to_owned(),
            invest: false,
            override_upgradable: false,
        }
    }

    fn test_withdraw_args(shares: i128, min_out_len: usize) -> VaultWithdrawArgs {
        VaultWithdrawArgs {
            vault_address: "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN".to_owned(),
            withdraw_shares: shares,
            min_amounts_out: vec![900_000; min_out_len],
            from_address: "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD".to_owned(),
            override_upgradable: false,
        }
    }

    // ── Deposit structural validation ────────────────────────────────────────

    #[test]
    fn deposit_valid_args_pass() {
        let args = test_deposit_args(2, 2);
        assert!(args.validate_structure().is_ok());
    }

    #[test]
    fn deposit_empty_amounts_refuses() {
        let args = test_deposit_args(0, 0);
        assert!(
            matches!(
                args.validate_structure(),
                Err(VaultAbiError::DepositAmountsEmpty)
            ),
            "empty amounts_desired must refuse"
        );
    }

    #[test]
    fn deposit_min_length_mismatch_refuses() {
        let args = test_deposit_args(2, 3);
        assert!(
            matches!(
                args.validate_structure(),
                Err(VaultAbiError::DepositLengthMismatch { .. })
            ),
            "min length mismatch must refuse"
        );
    }

    #[test]
    fn deposit_asset_count_mismatch_refuses() {
        // amounts_desired=2, amounts_min=2 but expected=3 → both mismatch.
        let args = test_deposit_args(2, 2);
        assert!(
            matches!(
                args.validate_against_asset_count(3),
                Err(VaultAbiError::DepositAmountsLengthMismatch {
                    amounts_desired_len: 2,
                    amounts_min_len: 2,
                    expected_asset_count: 3
                })
            ),
            "asset count mismatch must refuse"
        );
    }

    #[test]
    fn deposit_asset_count_desired_mismatch_only_refuses() {
        // amounts_desired=1, amounts_min=3, expected=3 → desired differs.
        let args = test_deposit_args(1, 3);
        assert!(
            matches!(
                args.validate_against_asset_count(3),
                Err(VaultAbiError::DepositAmountsLengthMismatch {
                    amounts_desired_len: 1,
                    amounts_min_len: 3,
                    expected_asset_count: 3
                })
            ),
            "amounts_desired length mismatch alone must refuse"
        );
    }

    #[test]
    fn deposit_asset_count_min_mismatch_only_refuses() {
        // amounts_desired=3, amounts_min=1, expected=3 → min differs.
        let args = test_deposit_args(3, 1);
        assert!(
            matches!(
                args.validate_against_asset_count(3),
                Err(VaultAbiError::DepositAmountsLengthMismatch {
                    amounts_desired_len: 3,
                    amounts_min_len: 1,
                    expected_asset_count: 3
                })
            ),
            "amounts_min length mismatch alone must refuse"
        );
    }

    #[test]
    fn deposit_asset_count_both_correct_passes() {
        let args = test_deposit_args(2, 2);
        assert!(
            args.validate_against_asset_count(2).is_ok(),
            "both vectors matching asset count must pass"
        );
    }

    // ── Withdraw structural validation ───────────────────────────────────────

    #[test]
    fn withdraw_valid_args_pass() {
        let args = test_withdraw_args(1_000_000, 2);
        assert!(args.validate_structure().is_ok());
    }

    #[test]
    fn withdraw_zero_shares_refuses() {
        let args = test_withdraw_args(0, 2);
        assert!(
            matches!(
                args.validate_structure(),
                Err(VaultAbiError::WithdrawSharesNotPositive { shares: 0 })
            ),
            "zero shares must refuse"
        );
    }

    #[test]
    fn withdraw_negative_shares_refuses() {
        let args = test_withdraw_args(-1, 2);
        assert!(
            matches!(
                args.validate_structure(),
                Err(VaultAbiError::WithdrawSharesNotPositive { shares: -1 })
            ),
            "negative shares must refuse"
        );
    }

    #[test]
    fn withdraw_empty_min_out_refuses() {
        let args = test_withdraw_args(1_000_000, 0);
        assert!(
            matches!(
                args.validate_structure(),
                Err(VaultAbiError::WithdrawMinAmountsEmpty)
            ),
            "empty min_amounts_out must refuse"
        );
    }

    #[test]
    fn withdraw_asset_count_mismatch_refuses() {
        let args = test_withdraw_args(1_000_000, 2);
        assert!(
            matches!(
                args.validate_against_asset_count(3),
                Err(VaultAbiError::WithdrawMinLengthMismatch { .. })
            ),
            "asset count mismatch must refuse"
        );
    }
}
