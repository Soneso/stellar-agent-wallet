//! ScVal encoding for Soroswap router ABI types.
//!
//! # What this module does
//!
//! Converts Rust-typed swap and quote arguments into the
//! `stellar_xdr::ScVal` forms expected
//! by the Soroswap router on-chain contract.
//!
//! # Byte-layout claim
//!
//! The `swap_exact_tokens_for_tokens` function arguments are positional
//! (NOT a `#[contracttype]` struct), so they encode as an ordered
//! `InvokeContractArgs.args` vector — NOT a sorted `ScVal::Map`.
//!
//! Arg order: `[amount_in, amount_out_min, path, to, deadline]`.
//!
//! Cited from `soroban-sdk-macros src/derive_fn.rs`:
//! parameters in a `#[contractimpl]` fn are passed as `ScVal` items in
//! **declaration order** in `InvokeContractArgs.args`.  The trait signature at
//! `soroswap-core contracts/router/src/lib.rs`:
//!
//! ```text
//! fn swap_exact_tokens_for_tokens(
//!   e: Env,
//!   amount_in: i128,
//!   amount_out_min: i128,
//!   path: Vec<Address>,
//!   to: Address,
//!   deadline: u64,
//! ) -> Result<Vec<i128>, ...>
//! ```
//!
//! ScVal encoding per type:
//! - `amount_in: i128`       → `ScVal::I128(Int128Parts { hi, lo })`.
//! - `amount_out_min: i128`  → `ScVal::I128(Int128Parts { hi, lo })`.
//! - `path: Vec<Address>`    → `ScVal::Vec(Some([ScVal::Address(...), ...]))`.
//! - `to: Address`           → `ScVal::Address(ScAddress::Contract(...))`.
//! - `deadline: u64`         → `ScVal::U64(value)`.
//!
//! `router_get_amounts_out` args: `[amount_in, path]` (same encoding rules).
//! Trait at `soroswap-core contracts/router/src/lib.rs`.
//!
//! # Behaviour
//!
//! An absolute `amount_out_min` is required in the encoded call. Path addresses
//! must be canonicalised before encoding.

use stellar_xdr::{ContractId, Hash, Int128Parts, ScAddress, ScVal, ScVec, VecM};

// ─────────────────────────────────────────────────────────────────────────────
// DexScValError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when encoding Soroswap ABI arguments to `ScVal`.
///
/// All variants carry non-sensitive diagnostic information.  The `Display`
/// impl never leaks a full `C…` address or hash.
///
/// # Display invariant
///
/// Every variant below is reviewed: none echoes a full address or hash in
/// its `Display` message.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DexScValError {
    /// A contract address in the swap path is not a valid C-strkey.
    ///
    /// The message carries only a generic strkey-parse reason; it never echoes
    /// any portion of the supplied address.
    #[error("invalid path address (not a C-strkey): {reason}")]
    InvalidPathAddress {
        /// Non-sensitive reason.
        reason: String,
    },

    /// The `to` (recipient) address is not a valid C-strkey.
    #[error("invalid 'to' address (not a C-strkey): {reason}")]
    InvalidToAddress {
        /// Non-sensitive reason.
        reason: String,
    },

    /// A `VecM` collection exceeded the XDR maximum length.
    #[error("XDR VecM overflow: {detail}")]
    VecTooLong {
        /// Non-sensitive description.
        detail: &'static str,
    },

    /// XDR serialisation failed.
    #[error("ScVal XDR encoding failed: {detail}")]
    XdrEncode {
        /// Non-sensitive detail.
        detail: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Encode swap_exact_tokens_for_tokens args
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes the positional arguments for `swap_exact_tokens_for_tokens`.
///
/// Returns a `Vec<stellar_xdr::ScVal>` in declaration order:
/// `[amount_in, amount_out_min, path, to, deadline]`.
///
/// The caller MUST ensure:
/// - All path addresses are already canonicalised to C-strkeys (via
///   [`crate::sac::canonicalise_path`]).
/// - `to_address` is a C-strkey.
/// - `amount_in > 0`, `deadline > now` (validated upstream by the adapter).
///
/// # Byte-layout claim
///
/// Positional args, declaration order.  Cited from
/// `soroban-sdk-macros src/derive_fn.rs`.
/// Trait at `soroswap-core contracts/router/src/lib.rs`.
///
/// # Errors
///
/// Returns [`DexScValError`] if any address is invalid or VecM overflow occurs.
pub fn encode_swap_args(
    amount_in: i128,
    amount_out_min: i128,
    path: &[String],
    to_address: &str,
    deadline: u64,
) -> Result<Vec<ScVal>, DexScValError> {
    let amount_in_scval = encode_i128(amount_in);
    let amount_out_min_scval = encode_i128(amount_out_min);
    let path_scval = encode_path_as_stellar_scval(path)?;
    let to_scval =
        stellar_c_strkey_to_sc_val(to_address).map_err(|e| DexScValError::InvalidToAddress {
            reason: e.to_string(),
        })?;
    let deadline_scval = encode_u64(deadline);

    Ok(vec![
        amount_in_scval,
        amount_out_min_scval,
        path_scval,
        to_scval,
        deadline_scval,
    ])
}

/// Encodes the positional arguments for `router_get_amounts_out`.
///
/// Returns a `Vec<stellar_xdr::ScVal>` in declaration order:
/// `[amount_in, path]`.
///
/// # Byte-layout claim
///
/// Positional args, declaration order.  Cited from
/// `soroban-sdk-macros src/derive_fn.rs`.
/// Trait at `soroswap-core contracts/router/src/lib.rs`.
///
/// # Errors
///
/// Returns [`DexScValError`] if any path address is invalid or VecM overflow occurs.
pub fn encode_get_amounts_out_args(
    amount_in: i128,
    path: &[String],
) -> Result<Vec<ScVal>, DexScValError> {
    let amount_in_scval = encode_i128(amount_in);
    let path_scval = encode_path_as_stellar_scval(path)?;
    Ok(vec![amount_in_scval, path_scval])
}

// ─────────────────────────────────────────────────────────────────────────────
// Encode individual types
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes a path of C-strkey addresses as `stellar_xdr::ScVal::Vec`.
///
/// # Errors
///
/// Returns [`DexScValError::InvalidPathAddress`] on an invalid address, or
/// [`DexScValError::VecTooLong`] on VecM overflow.
fn encode_path_as_stellar_scval(path: &[String]) -> Result<ScVal, DexScValError> {
    let mut vals: Vec<ScVal> = Vec::with_capacity(path.len());
    for addr in path {
        vals.push(stellar_c_strkey_to_sc_val(addr)?);
    }
    let vec_m: VecM<ScVal> = vals.try_into().map_err(|_| DexScValError::VecTooLong {
        detail: "path VecM too long for ScVec",
    })?;
    Ok(ScVal::Vec(Some(ScVec(vec_m))))
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes `i128` as `stellar_xdr::ScVal::I128`.
fn encode_i128(v: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: (v >> 64) as i64,
        lo: v as u64,
    })
}

/// Encodes `u64` as `stellar_xdr::ScVal::U64`.
fn encode_u64(v: u64) -> ScVal {
    ScVal::U64(v)
}

/// Encodes a C-strkey as `stellar_xdr::ScVal::Address(Contract(...))`.
fn stellar_c_strkey_to_sc_val(address: &str) -> Result<ScVal, DexScValError> {
    let contract = stellar_strkey::Contract::from_string(address).map_err(|e| {
        DexScValError::InvalidPathAddress {
            reason: e.to_string(),
        }
    })?;
    let sc_addr = ScAddress::Contract(ContractId(Hash(contract.0)));
    Ok(ScVal::Address(sc_addr))
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

    // Testnet XLM SAC and USDC SAC (from soroswap-core/public/tokens.json).
    const XLM_SAC: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
    const USDC_SAC: &str = "CB3TLW74NBIOT3BUWOZ3TUM6RFDF6A4GVIRUQRQZABG5KPOUL4JJOV2F";
    const ROUTER: &str = "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD";

    // ── encode_swap_args arg-count and order ─────────────────────────────────

    #[test]
    fn encode_swap_args_produces_five_elements() {
        let args = encode_swap_args(
            1_000_000_000,
            990_000_000,
            &[XLM_SAC.to_owned(), USDC_SAC.to_owned()],
            ROUTER,
            9_999_999_999,
        )
        .expect("valid args");
        assert_eq!(args.len(), 5, "swap args must have exactly 5 elements");
    }

    #[test]
    fn encode_swap_args_first_is_i128() {
        let args = encode_swap_args(
            1_000_000_000,
            990_000_000,
            &[XLM_SAC.to_owned(), USDC_SAC.to_owned()],
            ROUTER,
            9_999_999_999,
        )
        .expect("valid args");
        assert!(
            matches!(args[0], ScVal::I128(_)),
            "arg[0] (amount_in) must be ScVal::I128"
        );
    }

    #[test]
    fn encode_swap_args_second_is_i128() {
        let args = encode_swap_args(
            1_000_000_000,
            990_000_000,
            &[XLM_SAC.to_owned(), USDC_SAC.to_owned()],
            ROUTER,
            9_999_999_999,
        )
        .expect("valid args");
        assert!(
            matches!(args[1], ScVal::I128(_)),
            "arg[1] (amount_out_min) must be ScVal::I128"
        );
    }

    #[test]
    fn encode_swap_args_third_is_vec() {
        let args = encode_swap_args(
            1_000_000_000,
            990_000_000,
            &[XLM_SAC.to_owned(), USDC_SAC.to_owned()],
            ROUTER,
            9_999_999_999,
        )
        .expect("valid args");
        assert!(
            matches!(args[2], ScVal::Vec(_)),
            "arg[2] (path) must be ScVal::Vec"
        );
    }

    #[test]
    fn encode_swap_args_fourth_is_address() {
        let args = encode_swap_args(
            1_000_000_000,
            990_000_000,
            &[XLM_SAC.to_owned(), USDC_SAC.to_owned()],
            ROUTER,
            9_999_999_999,
        )
        .expect("valid args");
        assert!(
            matches!(args[3], ScVal::Address(_)),
            "arg[3] (to) must be ScVal::Address"
        );
    }

    #[test]
    fn encode_swap_args_fifth_is_u64() {
        let args = encode_swap_args(
            1_000_000_000,
            990_000_000,
            &[XLM_SAC.to_owned(), USDC_SAC.to_owned()],
            ROUTER,
            9_999_999_999,
        )
        .expect("valid args");
        assert!(
            matches!(args[4], ScVal::U64(_)),
            "arg[4] (deadline) must be ScVal::U64"
        );
    }

    // ── amount_in round-trip ─────────────────────────────────────────────────

    #[test]
    fn amount_in_round_trips_via_i128_parts() {
        let amount_in: i128 = 1_234_567_890_123_456_789;
        let args = encode_swap_args(
            amount_in,
            990_000_000,
            &[XLM_SAC.to_owned(), USDC_SAC.to_owned()],
            ROUTER,
            9_999_999_999,
        )
        .expect("valid args");
        if let ScVal::I128(parts) = &args[0] {
            let decoded = ((parts.hi as i128) << 64) | (parts.lo as i128);
            assert_eq!(
                decoded, amount_in,
                "amount_in must round-trip via Int128Parts"
            );
        } else {
            panic!("expected ScVal::I128 for amount_in");
        }
    }

    // ── encode_get_amounts_out_args ─────────────────────────────────────────

    #[test]
    fn encode_get_amounts_out_args_produces_two_elements() {
        let args =
            encode_get_amounts_out_args(1_000_000_000, &[XLM_SAC.to_owned(), USDC_SAC.to_owned()])
                .expect("valid args");
        assert_eq!(
            args.len(),
            2,
            "get_amounts_out args must have exactly 2 elements"
        );
    }

    // ── invalid address is refused ──────────────────────────────────────────

    #[test]
    fn invalid_path_address_returns_error() {
        let result = encode_swap_args(
            1_000_000_000,
            990_000_000,
            &[XLM_SAC.to_owned(), "NOTACONTRACT".to_owned()],
            ROUTER,
            9_999_999_999,
        );
        assert!(result.is_err(), "invalid path address must return error");
    }

    #[test]
    fn invalid_to_address_returns_error() {
        let result = encode_swap_args(
            1_000_000_000,
            990_000_000,
            &[XLM_SAC.to_owned(), USDC_SAC.to_owned()],
            "GNOTACONTRACT",
            9_999_999_999,
        );
        assert!(
            matches!(result, Err(DexScValError::InvalidToAddress { .. })),
            "G-strkey 'to' must return InvalidToAddress"
        );
    }

    // ── error Display does not leak full address ─────────────────────────────

    #[test]
    fn invalid_to_address_display_no_full_leak() {
        // Drive the production path: a full G-strkey `to` is invalid (a C-strkey
        // is required) and must surface InvalidToAddress whose Display does not
        // echo the supplied address.
        let bad_to = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let err = encode_swap_args(
            1_000_000_000,
            990_000_000,
            &[XLM_SAC.to_owned(), USDC_SAC.to_owned()],
            bad_to,
            9_999_999_999,
        )
        .expect_err("G-strkey 'to' must error");
        let display = err.to_string();
        assert!(
            !display.contains(bad_to),
            "error display must not echo the full supplied address: {display}"
        );
    }
}
