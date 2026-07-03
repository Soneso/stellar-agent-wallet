//! On-chain `router_get_amounts_out` quote and pre-sign slippage re-verify.
//!
//! # What this module does
//!
//! Calls `router_get_amounts_out(amount_in, path)` on the Soroswap router via
//! a read-only simulate transaction and decodes the `Vec<i128>` return value.
//!
//! # Slippage re-verify
//!
//! [`reverify_slippage`] is the pre-sign re-check.  It:
//!
//! 1. Re-fetches the on-chain quote immediately before signing.
//! 2. Checks that the expected output amount >= `amount_out_min`.
//!
//! The freshness guarantee is the immediate re-fetch itself: `fetch_quote` is
//! called unconditionally inside `reverify_slippage`, so the quote checked is
//! always the one just fetched.  The on-chain `amount_out_min` enforced by the
//! router at execution time is the hard floor.
//!
//! Fail-closed: an absent quote or one below the absolute floor → refuse.
//!
//! NOTE: this is a sandwich/front-run floor check using the SAME
//! `get_amounts_out` routine the swap uses.  It is NOT an independent price
//! oracle; an independent price-oracle sanity check is deferred.
//!
//! # ABI provenance
//!
//! `router_get_amounts_out(amount_in, path)`:
//! - Trait at `soroswap-core contracts/router/src/lib.rs`.
//! - Impl at `soroswap-core contracts/router/src/lib.rs`:
//!   `soroswap_library::get_amounts_out(e, factory, amount_in, path)`.
//! - Returns `Result<Vec<i128>, _>`.
//!
//! The slippage re-verify re-fetches the on-chain quote before signing and
//! fails closed.

use stellar_agent_defi::simulate::{
    SimulateError, decode_i128_scval, scval_variant_name, simulate_invoke_returning_scval,
};
use stellar_xdr::ScVal;
use tracing::debug;

use crate::scval::encode_get_amounts_out_args;

// ─────────────────────────────────────────────────────────────────────────────
// QuoteError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by the on-chain quote fetch or slippage re-verify gate.
///
/// All variants carry non-sensitive diagnostic information.  The `Display`
/// impl never leaks a full `C…` address or private data.
///
/// # Sibling-variant Display audit
///
/// Every variant below is reviewed: none echoes a full address.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum QuoteError {
    /// ScVal argument encoding failed.
    #[error("quote argument encoding failed: {reason}")]
    ArgEncoding {
        /// Non-sensitive reason.
        reason: String,
    },

    /// The simulate transaction could not be built.
    #[error("quote simulate-tx build failed: {reason}")]
    TxBuildFailed {
        /// Non-sensitive reason.
        reason: String,
    },

    /// The `router_get_amounts_out` simulate call failed.
    #[error("router_get_amounts_out simulate failed: {reason}")]
    SimulateFailed {
        /// Non-sensitive reason (no RPC URL in message).
        reason: String,
    },

    /// The simulate returned no result value.
    #[error("router_get_amounts_out simulate returned no result")]
    NoResult,

    /// The return value could not be decoded as `Vec<i128>`.
    #[error("router_get_amounts_out return value decode failed: {reason}")]
    DecodeFailed {
        /// Non-sensitive reason.
        reason: String,
    },

    /// The expected output amount is below `amount_out_min`.
    ///
    /// Fail-closed on slippage.
    #[error(
        "slippage exceeded: expected output {expected_out} < minimum {amount_out_min}; \
         refuse sign"
    )]
    SlippageExceeded {
        /// Expected output from the on-chain quote.
        expected_out: i128,
        /// Caller-supplied minimum.
        amount_out_min: i128,
    },

    /// The quote path returned fewer amounts than expected (should be path.len()).
    #[error("router_get_amounts_out returned {got} amounts for path of length {expected}")]
    AmountsLengthMismatch {
        /// Number of amounts returned.
        got: usize,
        /// Number expected (= path length).
        expected: usize,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// QuoteResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of an on-chain `router_get_amounts_out` call.
///
/// The `amounts` vector has one entry per token in the path:
/// `amounts[0]` = `amount_in`, `amounts[n-1]` = expected output.
#[derive(Debug, Clone)]
pub struct QuoteResult {
    /// Per-hop amounts returned by `get_amounts_out`.
    /// `amounts.last()` is the expected output for the swap.
    pub amounts: Vec<i128>,
}

impl QuoteResult {
    /// Returns the expected output amount (last element of `amounts`).
    ///
    /// Returns `None` if `amounts` is empty.
    #[must_use]
    pub fn expected_out(&self) -> Option<i128> {
        self.amounts.last().copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// fetch_quote
// ─────────────────────────────────────────────────────────────────────────────

/// Calls `router_get_amounts_out(amount_in, path)` via a read-only simulate.
///
/// Returns a [`QuoteResult`] with the per-hop amounts.
///
/// # Arguments
///
/// - `router_address` — Soroswap router C-strkey.
/// - `amount_in` — exact input token amount.
/// - `path` — canonicalised token path (C-strkeys).
/// - `rpc_url` — primary Soroban RPC URL.
/// - `network_passphrase` — Stellar network passphrase.
///
/// # Errors
///
/// Returns [`QuoteError`] on any encoding, simulate, or decode failure.
pub async fn fetch_quote(
    router_address: &str,
    amount_in: i128,
    path: &[String],
    rpc_url: &str,
    network_passphrase: &str,
) -> Result<QuoteResult, QuoteError> {
    // Encode `router_get_amounts_out` args: [amount_in, path].
    let args =
        encode_get_amounts_out_args(amount_in, path).map_err(|e| QuoteError::ArgEncoding {
            reason: e.to_string(),
        })?;

    // Invoke via the shared read-only simulate scaffold in stellar-agent-defi.
    let result_scval = simulate_invoke_returning_scval(
        router_address,
        "router_get_amounts_out",
        args,
        rpc_url,
        network_passphrase,
    )
    .await
    .map_err(|e| match e {
        SimulateError::InvalidAddress { reason } => QuoteError::TxBuildFailed { reason },
        SimulateError::SimulateFailed { reason } => QuoteError::SimulateFailed { reason },
        SimulateError::SimulateError { reason } => QuoteError::SimulateFailed {
            reason: format!("simulation returned error: {reason}"),
        },
        SimulateError::NoResult => QuoteError::NoResult,
        SimulateError::DecodeFailed { reason } => QuoteError::DecodeFailed { reason },
        // SimulateError is #[non_exhaustive]; forward any future variants as SimulateFailed.
        other => QuoteError::SimulateFailed {
            reason: format!("simulate call failed: {other}"),
        },
    })?;

    let amounts = decode_amounts_vec(&result_scval)?;

    if amounts.len() != path.len() {
        return Err(QuoteError::AmountsLengthMismatch {
            got: amounts.len(),
            expected: path.len(),
        });
    }

    debug!(
        router_redacted = tracing::field::display(
            stellar_agent_core::observability::redact_strkey_first5_last5(router_address)
        ),
        amount_in,
        path_len = path.len(),
        amounts_len = amounts.len(),
        "router_get_amounts_out quote fetched"
    );

    Ok(QuoteResult { amounts })
}

// ─────────────────────────────────────────────────────────────────────────────
// reverify_slippage
// ─────────────────────────────────────────────────────────────────────────────

/// Pre-sign slippage re-verify gate.
///
/// Re-fetches the on-chain quote immediately before signing, then checks
/// that the expected output >= `amount_out_min`.
///
/// Fail-closed: returns `Err` when the slippage floor is not met or on any
/// quote-fetch failure.
///
/// # Freshness guarantee
///
/// Freshness comes from the immediate re-fetch: `fetch_quote` is called
/// unconditionally at the start of this function, so the quote checked is the
/// one just fetched.  The on-chain `amount_out_min` enforced by the router at
/// execution time is the hard floor.
///
/// # Errors
///
/// Returns [`QuoteError`] on any failure.
pub async fn reverify_slippage(
    router_address: &str,
    amount_in: i128,
    amount_out_min: i128,
    path: &[String],
    rpc_url: &str,
    network_passphrase: &str,
) -> Result<QuoteResult, QuoteError> {
    // Re-fetch immediately: the freshness guarantee is the immediate re-fetch,
    // not a post-fetch age check.  See function-level rustdoc for rationale.
    let quote = fetch_quote(router_address, amount_in, path, rpc_url, network_passphrase).await?;

    // Slippage check: expected output must meet the absolute floor.
    let expected_out = quote.expected_out().ok_or(QuoteError::NoResult)?;
    check_slippage(expected_out, amount_out_min)?;

    debug!(expected_out, amount_out_min, "slippage re-verify: PASS");

    Ok(quote)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Enforces the slippage floor: the expected output must be at least
/// `amount_out_min`.
///
/// # Errors
///
/// Returns [`QuoteError::SlippageExceeded`] when `expected_out < amount_out_min`.
fn check_slippage(expected_out: i128, amount_out_min: i128) -> Result<(), QuoteError> {
    if expected_out < amount_out_min {
        return Err(QuoteError::SlippageExceeded {
            expected_out,
            amount_out_min,
        });
    }
    Ok(())
}

/// Decodes a `Vec<i128>` from the `router_get_amounts_out` return value.
///
/// The router returns `ScVal::Vec(Some([ScVal::I128(...), ...]))`.
///
/// # ABI provenance
///
/// Return type is `Vec<i128>` (Rust), which encodes as `ScVal::Vec` with
/// each element `ScVal::I128(Int128Parts)` per soroban-sdk.
fn decode_amounts_vec(val: &ScVal) -> Result<Vec<i128>, QuoteError> {
    match val {
        ScVal::Vec(Some(vec)) => vec
            .iter()
            .enumerate()
            .map(|(i, item)| {
                decode_i128_scval(item).map_err(|e| QuoteError::DecodeFailed {
                    reason: format!("amounts[{i}]: {e}"),
                })
            })
            .collect(),
        ScVal::Void => Err(QuoteError::NoResult),
        other => Err(QuoteError::DecodeFailed {
            reason: format!(
                "expected ScVal::Vec for amounts, got {}",
                scval_variant_name(other)
            ),
        }),
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

    // ── QuoteResult helpers ──────────────────────────────────────────────────

    #[test]
    fn quote_result_expected_out_returns_last() {
        let q = QuoteResult {
            amounts: vec![1_000_000_000, 980_000_000, 970_000_000],
        };
        assert_eq!(q.expected_out(), Some(970_000_000));
    }

    #[test]
    fn quote_result_expected_out_empty() {
        let q = QuoteResult { amounts: vec![] };
        assert_eq!(q.expected_out(), None);
    }

    // ── decode_amounts_vec ───────────────────────────────────────────────────

    #[test]
    fn decode_amounts_vec_success() {
        use stellar_xdr::{Int128Parts, ScVec, VecM};

        let amounts_scval: Vec<i128> = vec![1_000_000_000, 990_000_000];
        let sc_items: Vec<ScVal> = amounts_scval
            .iter()
            .map(|&v| {
                ScVal::I128(Int128Parts {
                    hi: (v >> 64) as i64,
                    lo: v as u64,
                })
            })
            .collect();
        let vec_m: VecM<ScVal> = sc_items.try_into().unwrap();
        let val = ScVal::Vec(Some(ScVec(vec_m)));
        let decoded = decode_amounts_vec(&val).unwrap();
        assert_eq!(decoded, vec![1_000_000_000i128, 990_000_000i128]);
    }

    #[test]
    fn decode_amounts_vec_void_returns_no_result() {
        let result = decode_amounts_vec(&ScVal::Void);
        assert!(matches!(result, Err(QuoteError::NoResult)));
    }

    #[test]
    fn decode_amounts_vec_wrong_type_returns_error() {
        let result = decode_amounts_vec(&ScVal::U32(42));
        assert!(
            matches!(result, Err(QuoteError::DecodeFailed { .. })),
            "non-Vec ScVal must return DecodeFailed"
        );
    }

    #[test]
    fn decode_amounts_vec_non_i128_element_returns_error() {
        use stellar_xdr::{Int128Parts, ScVec, VecM};
        // A Vec whose second element is not I128 must fail with DecodeFailed
        // naming the offending index.
        let items: Vec<ScVal> = vec![ScVal::I128(Int128Parts { hi: 0, lo: 100 }), ScVal::U32(7)];
        let vec_m: VecM<ScVal> = items.try_into().unwrap();
        let val = ScVal::Vec(Some(ScVec(vec_m)));
        match decode_amounts_vec(&val) {
            Err(QuoteError::DecodeFailed { reason }) => {
                assert!(
                    reason.contains("amounts[1]"),
                    "decode error must name the offending index: {reason}"
                );
            }
            other => panic!("expected DecodeFailed, got {other:?}"),
        }
    }

    // ── SlippageExceeded Display audit ───────────────────────────────────────

    #[test]
    fn slippage_exceeded_display_no_sensitive_leak() {
        let err = QuoteError::SlippageExceeded {
            expected_out: 900_000_000,
            amount_out_min: 950_000_000,
        };
        let display = err.to_string();
        // Must contain amounts but not any address.
        assert!(
            display.contains("900000000"),
            "display must mention expected_out"
        );
        assert!(
            display.contains("950000000"),
            "display must mention amount_out_min"
        );
    }

    // ── check_slippage boundary cases ────────────────────────────────────────

    #[test]
    fn check_slippage_at_floor_passes() {
        assert!(
            check_slippage(1_000, 1_000).is_ok(),
            "expected == min must pass"
        );
    }

    #[test]
    fn check_slippage_above_floor_passes() {
        assert!(
            check_slippage(1_001, 1_000).is_ok(),
            "expected > min must pass"
        );
    }

    #[test]
    fn check_slippage_below_floor_refused() {
        assert!(
            matches!(
                check_slippage(999, 1_000),
                Err(QuoteError::SlippageExceeded {
                    expected_out: 999,
                    amount_out_min: 1_000,
                })
            ),
            "expected < min must return SlippageExceeded"
        );
    }
}
