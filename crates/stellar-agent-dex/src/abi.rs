//! Wallet-authored Soroswap router ABI types.
//!
//! # What this module does
//!
//! Re-declares the public Soroswap router ABI types as wallet-authored Rust
//! types.  No Soroswap source is vendored; these are independent re-declarations
//! of the wire interface, cited to the canonical source.
//!
//! # ABI provenance
//!
//! Cited from `soroswap-core contracts/router/src/lib.rs`:
//!
//! - Trait `swap_exact_tokens_for_tokens`:
//!   `fn swap_exact_tokens_for_tokens(e, amount_in: i128, amount_out_min: i128,`
//!   `path: Vec<Address>, to: Address, deadline: u64) -> Result<Vec<i128>, _>`
//! - Impl: single `to.require_auth()`; then `ensure_deadline`;
//!   then `get_amounts_out`; then final-amount >= `amount_out_min` check.
//! - Trait `router_get_amounts_out`:
//!   `fn router_get_amounts_out(e, amount_in: i128, path: Vec<Address>) -> Result<Vec<i128>, _>`
//! - Impl: calls `soroswap_library::get_amounts_out(e, factory, amount_in, path)`.
//! - `ensure_deadline`: panics when `ledger_timestamp >= deadline`.
//!
//! # ScVal encoding citation
//!
//! The `swap_exact_tokens_for_tokens` arguments are positional (NOT a
//! `#[contracttype]` struct), so they encode as an ordered `InvokeContractArgs.args`
//! vector, NOT a sorted `ScVal::Map`.  Arg order:
//! `[amount_in, amount_out_min, path, to, deadline]`.
//!
//! Per `soroban-sdk-macros src/derive_fn.rs`: function
//! parameters in a `#[contractimpl]` fn are passed as `ScVal` items in
//! **declaration order** in `InvokeContractArgs.args`.
//!
//! - `amount_in: i128` → `ScVal::I128(Int128Parts { hi, lo })`.
//! - `amount_out_min: i128` → `ScVal::I128(Int128Parts { hi, lo })`.
//! - `path: Vec<Address>` → `ScVal::Vec(Some([ScVal::Address(...), ...]))`.
//! - `to: Address` → `ScVal::Address(ScAddress::Contract(...))`.
//! - `deadline: u64` → `ScVal::U64(value)`.
//!
//! `router_get_amounts_out` args: `[amount_in, path]` (same encoding rules).
//!
//! # Percent-string refusal
//!
//! The `amount_out_min` field is a required `i128`.  Any attempt to pass a
//! percent string is a structural refusal at the parse boundary (`i128` type).
//! The wallet does NOT convert a percent to an absolute on the caller's behalf.
//!
//! # Behaviour
//!
//! Requires an absolute `amount_out_min`; uses a typed path with ambiguous
//! inputs refused; bounds the `u64` deadline.

/// Maximum deadline offset in seconds from now.
///
/// A deadline that is more than `MAX_DEADLINE_OFFSET_SECS` seconds in the
/// future is refused as excessively far.  Prevents an agent from accidentally
/// setting year 2999 as the deadline.
///
/// Enforces a bounded Unix deadline.
pub const MAX_DEADLINE_OFFSET_SECS: u64 = 3_600; // 1 hour

/// Default deadline offset in seconds from the current time.
///
/// Applied when the caller passes `deadline: None`.
///
/// Default is `now + 300s`.
pub const DEFAULT_DEADLINE_OFFSET_SECS: u64 = 300;

/// Minimum path length for a swap (input token + at least one output token).
pub const MIN_PATH_LEN: usize = 2;

/// Maximum path length.  Arbitrarily bounded to prevent abuse.
pub const MAX_PATH_LEN: usize = 5;

// ─────────────────────────────────────────────────────────────────────────────
// TradeArgs — typed arguments for the `trade` verb
// ─────────────────────────────────────────────────────────────────────────────

/// Typed arguments for the Soroswap `trade` (swap) verb.
///
/// Passed as `&dyn Any` through the `DefiAdapter::preview` / `submit` boundary;
/// the downcast is fail-closed.
///
/// # Slippage
///
/// `amount_out_min` is a **required absolute** `i128`.  Passing a percent string
/// is structurally unrepresentable — use [`TradeArgs::amount_out_min`] only.
///
/// # Behaviour
///
/// Requires an explicit absolute `amount_out_min`, a bounded deadline, and an
/// explicit swap path.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TradeArgs {
    /// The wallet smart-account address submitting the operation.
    ///
    /// Must be a **C-strkey** (contract address).  G-strkeys are not
    /// supported: the wallet smart-account is always deployed as a contract
    /// (C-strkey).  Validated early by `validate_trade_args`, which parses it
    /// with `stellar_strkey::Contract::from_string` (rejecting G-strkeys).
    ///
    /// This is the `to` address in the router `swap_exact_tokens_for_tokens`
    /// call (soroswap-core contracts/router/src/lib.rs).
    pub from_address: String,

    /// Exact amount of input tokens to swap (in the input token's native base
    /// units, `7` decimals for standard SAC tokens).
    ///
    /// Must be positive (`> 0`).
    pub amount_in: i128,

    /// Minimum amount of output tokens to receive.
    ///
    /// This is an **absolute floor**.  A
    /// percent string is a structural refusal at the parse boundary (`i128` type).
    /// The wallet does NOT compute a percent into an absolute on the caller's
    /// behalf; the caller must derive the absolute from a prior `quote`.
    pub amount_out_min: i128,

    /// Ordered token addresses in the swap path (minimum 2, maximum 5).
    ///
    /// First element is the input token, last element is the output token.
    /// Intermediate elements are hop tokens if a direct pair does not exist.
    ///
    /// Each element must be a valid SEP-41/SAC contract address (C-strkey) or
    /// a classic asset `CODE:ISSUER` that canonicalises to a SAC.
    ///
    /// Canonicalisation runs BEFORE policy eval / allowlist / path-build.
    pub path: Vec<String>,

    /// Optional Unix timestamp deadline (seconds).
    ///
    /// When `None`, the wallet uses `now + DEFAULT_DEADLINE_OFFSET_SECS`.
    ///
    /// The value is refused when `> now + MAX_DEADLINE_OFFSET_SECS`.
    /// The value is refused when `<= now` (already expired).
    ///
    /// On-chain enforcement: Soroswap router `ensure_deadline`
    /// at `contracts/router/src/lib.rs`.
    #[serde(default)]
    pub deadline: Option<u64>,
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

    /// Verifies that a percent string (e.g. `"50%"`) fails JSON deserialization
    /// into `TradeArgs.amount_out_min: i128`.
    ///
    /// This is the structural refusal of explicit slippage: the `i128` type
    /// enforces the refusal at the parse boundary.
    #[test]
    fn percent_string_fails_deserialization_into_i128() {
        let json = serde_json::json!({
            "from_address": "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD",
            "amount_in": 10_000_000_i128,
            "amount_out_min": "50%",  // percent string — must fail
            "path": ["CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"]
        });
        let result = serde_json::from_value::<TradeArgs>(json);
        assert!(
            result.is_err(),
            "percent string '50%' must fail deserialization into TradeArgs.amount_out_min (i128)"
        );
    }

    /// Verifies that a valid absolute `amount_out_min` deserializes correctly.
    #[test]
    fn absolute_amount_out_min_deserializes() {
        let json = serde_json::json!({
            "from_address": "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD",
            "amount_in": 10_000_000_i128,
            "amount_out_min": 9_800_000_i128,
            "path": ["CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"]
        });
        let args = serde_json::from_value::<TradeArgs>(json).unwrap();
        assert_eq!(args.amount_out_min, 9_800_000);
    }
}
