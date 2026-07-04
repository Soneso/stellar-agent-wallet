//! ScVal encoding for DeFindex vault ABI types.
//!
//! # What this module does
//!
//! Converts [`VaultDepositArgs`] and [`VaultWithdrawArgs`] into
//! `stellar_xdr::ScVal` argument vectors for use as Soroban contract
//! invocation arguments.
//!
//! # Byte-layout claims
//!
//! ## `deposit(amounts_desired, amounts_min, from, invest)`
//!
//! Arguments are positional (NOT sorted) per the DeFindex vault interface:
//!   1. `amounts_desired: Vec<i128>` → `ScVal::Vec([ScVal::I128(...), ...])`
//!   2. `amounts_min: Vec<i128>` → `ScVal::Vec([ScVal::I128(...), ...])`
//!   3. `from: Address` → `ScVal::Address(ScAddress::Contract(...))`
//!   4. `invest: bool` → `ScVal::Bool(b)`
//!
//! `i128` encoding per soroban-sdk (confirmed via `stellar-xdr/src/types.rs`):
//! `ScVal::I128(Int128Parts { hi: i64, lo: u64 })` where `lo = v as u64` and
//! `hi = (v >> 64) as i64`.
//!
//! ## `withdraw(df_amount, min_amounts_out, from)`
//!
//! Arguments are positional per the DeFindex vault interface (trait and impl):
//!   1. `df_amount (withdraw_shares): i128` → `ScVal::I128(...)`
//!   2. `min_amounts_out: Vec<i128>` → `ScVal::Vec([ScVal::I128(...), ...])`
//!   3. `from: Address` → `ScVal::Address(ScAddress::Contract(...))`
//!
//! # Address encoding
//!
//! Smart-account addresses are C-strkeys (contract addresses).
//! Encoding: `ScAddress::Contract(ContractId(Hash([32 bytes])))`
//! via `stellar_strkey::Contract::from_string`.

use stellar_agent_defi::scval::{contract_strkey_to_sc_address, encode_i128};
use stellar_xdr::{ScVal, ScVec, VecM};
use thiserror::Error;

use crate::abi::{VaultDepositArgs, VaultWithdrawArgs};

// ─────────────────────────────────────────────────────────────────────────────
// VaultScValError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when encoding vault args to `ScVal`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VaultScValError {
    /// The vault or account address is not a valid Stellar strkey.
    #[error("invalid address (not a C-strkey): {reason}")]
    InvalidAddress {
        /// Non-sensitive reason string.
        reason: String,
    },
    /// A `VecM` collection exceeded the maximum XDR length.
    #[error("ScVal VecM overflow: {detail}")]
    VecTooLong {
        /// Non-sensitive description.
        detail: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// encode_vault_deposit_args
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes [`VaultDepositArgs`] as a `Vec<ScVal>` for `InvokeContractArgs.args`.
///
/// Argument order (positional, per the DeFindex vault interface):
/// `[amounts_desired, amounts_min, from, invest]`
///
/// # Errors
///
/// Returns [`VaultScValError`] if any address is invalid or any `VecM` overflows.
pub fn encode_vault_deposit_args(args: &VaultDepositArgs) -> Result<Vec<ScVal>, VaultScValError> {
    let amounts_desired_scval = encode_i128_vec(&args.amounts_desired, "amounts_desired")?;
    let amounts_min_scval = encode_i128_vec(&args.amounts_min, "amounts_min")?;
    let from_scval = encode_c_strkey_address(&args.from_address)?;
    let invest_scval = ScVal::Bool(args.invest);

    Ok(vec![
        amounts_desired_scval,
        amounts_min_scval,
        from_scval,
        invest_scval,
    ])
}

// ─────────────────────────────────────────────────────────────────────────────
// encode_vault_withdraw_args
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes [`VaultWithdrawArgs`] as a `Vec<ScVal>` for `InvokeContractArgs.args`.
///
/// Argument order (positional, per the DeFindex vault interface):
/// `[df_amount, min_amounts_out, from]`
///
/// # Errors
///
/// Returns [`VaultScValError`] if any address is invalid or any `VecM` overflows.
pub fn encode_vault_withdraw_args(args: &VaultWithdrawArgs) -> Result<Vec<ScVal>, VaultScValError> {
    let df_amount_scval = encode_i128(args.withdraw_shares);
    let min_amounts_out_scval = encode_i128_vec(&args.min_amounts_out, "min_amounts_out")?;
    let from_scval = encode_c_strkey_address(&args.from_address)?;

    Ok(vec![df_amount_scval, min_amounts_out_scval, from_scval])
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes a C-strkey (contract address starting with 'C') as
/// `ScVal::Address(ScAddress::Contract(...))`.
///
/// Smart-account wallet addresses are contract addresses.
///
/// # Errors
///
/// Returns [`VaultScValError::InvalidAddress`] if `strkey` is not a valid
/// `C`-prefixed contract strkey.
pub fn encode_c_strkey_address(strkey: &str) -> Result<ScVal, VaultScValError> {
    let sc_addr =
        contract_strkey_to_sc_address(strkey).map_err(|e| VaultScValError::InvalidAddress {
            reason: format!("{e}"),
        })?;
    Ok(ScVal::Address(sc_addr))
}

/// Encodes a `Vec<i128>` as `ScVal::Vec([ScVal::I128(...), ...])`.
fn encode_i128_vec(values: &[i128], field_name: &str) -> Result<ScVal, VaultScValError> {
    let scval_items: Vec<ScVal> = values.iter().copied().map(encode_i128).collect();
    let vec_m: VecM<ScVal> = scval_items
        .try_into()
        .map_err(|_| VaultScValError::VecTooLong {
            detail: format!("{field_name} VecM overflow"),
        })?;
    Ok(ScVal::Vec(Some(ScVec(vec_m))))
}

/// Encodes a `Vec<ScVal>` as the outer `VecM<ScVal>` for `InvokeContractArgs.args`.
///
/// Both the caller and `InvokeContractArgs` use `stellar_xdr` types, so no
/// XDR round-trip is needed — the values are passed through directly.
///
/// # Errors
///
/// Returns [`VaultScValError::VecTooLong`] if the `VecM` overflows.
pub fn args_to_vecm(args: Vec<ScVal>) -> Result<VecM<ScVal>, VaultScValError> {
    args.try_into().map_err(|_| VaultScValError::VecTooLong {
        detail: "InvokeContractArgs args VecM overflow".to_owned(),
    })
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
    use crate::abi::{VaultDepositArgs, VaultWithdrawArgs};

    const VAULT_ADDRESS: &str = "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN";
    const FROM_ADDRESS: &str = "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD";

    fn deposit_args() -> VaultDepositArgs {
        VaultDepositArgs {
            vault_address: VAULT_ADDRESS.to_owned(),
            amounts_desired: vec![1_000_000_000i128],
            amounts_min: vec![900_000_000i128],
            from_address: FROM_ADDRESS.to_owned(),
            invest: false,
            override_upgradable: false,
        }
    }

    fn withdraw_args() -> VaultWithdrawArgs {
        VaultWithdrawArgs {
            vault_address: VAULT_ADDRESS.to_owned(),
            withdraw_shares: 5_000_000i128,
            min_amounts_out: vec![4_500_000i128],
            from_address: FROM_ADDRESS.to_owned(),
            override_upgradable: false,
        }
    }

    // ── Deposit encoding ─────────────────────────────────────────────────────

    #[test]
    fn deposit_encodes_four_args_in_order() {
        let args = deposit_args();
        let encoded = encode_vault_deposit_args(&args).unwrap();
        assert_eq!(encoded.len(), 4, "deposit must produce 4 args");

        // arg[0] = amounts_desired (ScVal::Vec)
        assert!(
            matches!(encoded[0], ScVal::Vec(Some(_))),
            "arg[0] must be Vec"
        );
        // arg[1] = amounts_min (ScVal::Vec)
        assert!(
            matches!(encoded[1], ScVal::Vec(Some(_))),
            "arg[1] must be Vec"
        );
        // arg[2] = from (ScVal::Address)
        assert!(
            matches!(encoded[2], ScVal::Address(_)),
            "arg[2] must be Address"
        );
        // arg[3] = invest (ScVal::Bool)
        assert_eq!(encoded[3], ScVal::Bool(false), "arg[3] must be Bool(false)");
    }

    #[test]
    fn deposit_i128_value_round_trips() {
        let v: i128 = 1_000_000_000;
        let scval = encode_i128(v);
        match scval {
            ScVal::I128(parts) => {
                let reconstructed = ((parts.hi as i128) << 64) | (parts.lo as i128);
                assert_eq!(reconstructed, v);
            }
            other => panic!("expected I128; got {other:?}"),
        }
    }

    #[test]
    fn deposit_negative_i128_round_trips() {
        let v: i128 = -500_000_000;
        let scval = encode_i128(v);
        match scval {
            ScVal::I128(parts) => {
                let reconstructed = ((parts.hi as i128) << 64) | (parts.lo as i128);
                assert_eq!(reconstructed, v);
            }
            other => panic!("expected I128; got {other:?}"),
        }
    }

    // ── Withdraw encoding ────────────────────────────────────────────────────

    #[test]
    fn withdraw_encodes_three_args_in_order() {
        let args = withdraw_args();
        let encoded = encode_vault_withdraw_args(&args).unwrap();
        assert_eq!(encoded.len(), 3, "withdraw must produce 3 args");

        // arg[0] = df_amount/withdraw_shares (ScVal::I128)
        assert!(matches!(encoded[0], ScVal::I128(_)), "arg[0] must be I128");
        // arg[1] = min_amounts_out (ScVal::Vec)
        assert!(
            matches!(encoded[1], ScVal::Vec(Some(_))),
            "arg[1] must be Vec"
        );
        // arg[2] = from (ScVal::Address)
        assert!(
            matches!(encoded[2], ScVal::Address(_)),
            "arg[2] must be Address"
        );
    }

    // ── Address encoding ─────────────────────────────────────────────────────

    #[test]
    fn invalid_address_returns_error() {
        let result = encode_c_strkey_address("not-a-strkey");
        assert!(
            matches!(result, Err(VaultScValError::InvalidAddress { .. })),
            "invalid address must return error"
        );
    }

    #[test]
    fn g_strkey_address_returns_error() {
        // A valid G-strkey (ed25519 public key, all-zero 32-byte key) is NOT a
        // contract C-strkey.  `encode_c_strkey_address` must reject it because
        // it only accepts C-prefixed contract strkeys.
        let result =
            encode_c_strkey_address("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF");
        assert!(
            matches!(result, Err(VaultScValError::InvalidAddress { .. })),
            "G-strkey must return InvalidAddress"
        );
    }
}
