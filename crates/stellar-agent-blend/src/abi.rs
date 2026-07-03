//! Wallet-authored Blend ABI types.
//!
//! # What this module does
//!
//! Re-declares the public Blend pool ABI types as wallet-authored Rust types.
//! No AGPL Blend source is vendored; these are independent re-declarations
//! of the wire interface, cited to the canonical source.
//!
//! # ABI provenance — v1 (primary)
//!
//! Cited from `blend-contracts`:
//! - `pool/src/pool/actions.rs` — `Request { request_type, address, amount }` struct.
//! - `pool/src/pool/actions.rs` — `RequestType` discriminants 0-9.
//! - `pool/src/pool/actions.rs` — `from_u32` PANICS on >9 (wallet refuses pre-sign).
//!
//! # ABI provenance — v2 (confirmed identical)
//!
//! Cited from `blend-contracts-v2`:
//! - `pool/src/pool/actions.rs` — `Request` struct fields IDENTICAL to v1.
//! - `pool/src/pool/actions.rs` — `RequestType` discriminants IDENTICAL to v1.
//! - `pool/src/pool/actions.rs` — `from_u32` panics on >9; wallet refuses pre-sign.
//!
//! The v2 `Request` struct has the same three fields (`request_type: u32`,
//! `address: Address`, `amount: i128`) and the same `RequestType` discriminant
//! set (0-9).  `submit` signature is also identical
//! (`pool/src/contract.rs` v2 == `pool/src/contract.rs` v1).
//! v2 adds `submit_with_allowance` and `flash_loan` (additive, out of scope).
//!
//! A single `BlendRequest`/`RequestType` binding therefore serves BOTH v1 and
//! v2 pools; no separate v2 binding is required.
//!
//! # ScVal encoding citation (distinct from type-declaration citation)
//!
//! The `BlendRequest → ScVal` encoding is governed by the soroban-sdk
//! `#[contracttype]` struct derive, which sorts fields **alphabetically by
//! field name** and encodes each as `ScVal::Map { key: ScSymbol(name), val }`.
//!
//! Cited from
//! `soroban-sdk` (25.3.0):
//! `soroban-sdk-macros/src/derive_struct.rs` —
//! `.sorted_by_key(|field| field.ident.as_ref().unwrap().to_string())`.
//!
//! Field name sort order for `Request { address, amount, request_type }`:
//!   `address` < `amount` < `request_type` (lexicographic).
//!
//! The `#[repr(u32)]` enum `RequestType` is NOT a `#[contracttype]` — it is
//! stored as a plain `u32` in the struct field, so its discriminant encodes as
//! `ScVal::U32(discriminant)`.
//!
//! # Unknown-discriminant refusal
//!
//! Any `request_type` value outside 0-9 is REFUSED by
//! [`RequestType::try_from_u32`] with [`BlendAbiError::UnknownRequestType`].
//! This is fail-closed: the wallet never delegates rejection to the on-chain
//! `from_u32` panic (`blend-contracts pool/src/pool/actions.rs`).

use crate::scval::BlendScValError;

// ─────────────────────────────────────────────────────────────────────────────
// BlendRequest — wallet-authored re-declaration of Blend pool Request
// ─────────────────────────────────────────────────────────────────────────────

/// Wallet-authored re-declaration of the Blend pool `Request` struct.
///
/// Matches the wire shape of `blend-contracts pool/src/pool/actions.rs`
/// (v1) and `blend-contracts-v2 pool/src/pool/actions.rs`
/// (v2) — fields are identical in both versions.
///
/// # ScVal encoding
///
/// When converted to `ScVal::Map` for a `submit` invocation, fields are
/// sorted **alphabetically by field name** per the soroban-sdk `#[contracttype]`
/// struct derive at
/// `soroban-sdk soroban-sdk-macros/src/derive_struct.rs`:
/// `address` → `amount` → `request_type`.
///
/// # Examples
///
/// ```
/// use stellar_agent_blend::abi::{BlendRequest, RequestType};
///
/// let req = BlendRequest::new(RequestType::Supply, "CAAAA…AAAAB", 5_000_000_000);
/// assert_eq!(req.request_type, RequestType::Supply);
/// assert_eq!(req.amount, 5_000_000_000);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlendRequest {
    /// The type of request (discriminant 0-9, cited to
    /// `blend-contracts pool/src/pool/actions.rs`).
    pub request_type: RequestType,
    /// Asset address or liquidation-counterparty address (C-strkey).
    ///
    /// For lending operations (0-5), this is the reserve asset address.
    /// For liquidation operations (6-9), this is the user/backstop/liquidatee
    /// address (never a reserve asset).
    pub address: String,
    /// Amount in the asset's native base unit.
    pub amount: i128,
}

impl BlendRequest {
    /// Constructs a `BlendRequest`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_blend::abi::{BlendRequest, RequestType};
    ///
    /// let req = BlendRequest::new(RequestType::Borrow, "CAAAA…BBBBB", 1_000_000_000);
    /// assert_eq!(req.request_type, RequestType::Borrow);
    /// ```
    #[must_use]
    pub fn new(request_type: RequestType, address: impl Into<String>, amount: i128) -> Self {
        Self {
            request_type,
            address: address.into(),
            amount,
        }
    }

    /// Validates this request for the `lend` verb before encoding or signing.
    ///
    /// Fail-closed gate that callers MUST run before the request is encoded or
    /// signed: it refuses liquidation discriminants (6-9), which require the
    /// dedicated `liquidate` verb, and rejects an empty address or a
    /// non-positive amount.
    ///
    /// # Errors
    ///
    /// - [`BlendAbiError::LiquidationVerbRequired`] for a liquidation discriminant.
    /// - [`BlendAbiError::InvalidField`] for an empty address or non-positive amount.
    pub fn validate(&self) -> Result<(), BlendAbiError> {
        self.request_type.assert_lend_verb_allowed()?;
        if self.address.is_empty() {
            return Err(BlendAbiError::InvalidField {
                reason: "request address must not be empty".to_owned(),
            });
        }
        if self.amount <= 0 {
            return Err(BlendAbiError::InvalidField {
                reason: "request amount must be a positive integer".to_owned(),
            });
        }
        Ok(())
    }

    /// Returns `true` if the `address` field refers to a reserve asset for this
    /// request type.
    ///
    /// Returns `true` only for the lending operations (0-5); liquidation
    /// operations (6-9) carry a user/backstop/liquidatee address, not an asset.
    #[must_use]
    pub fn is_asset_address(&self) -> bool {
        matches!(
            self.request_type,
            RequestType::Supply
                | RequestType::Withdraw
                | RequestType::SupplyCollateral
                | RequestType::WithdrawCollateral
                | RequestType::Borrow
                | RequestType::Repay
        )
    }

    /// Human-readable label for the `address` field contextualised by type.
    ///
    /// Returns `"asset"` for the lending operations (0-5) and `"liquidatee"` as
    /// a generic non-asset label for the liquidation operations (6-9); since the
    /// `lend` verb refuses 6-9, this label is informational only.
    #[must_use]
    pub fn address_label(&self) -> &'static str {
        if self.is_asset_address() {
            "asset"
        } else {
            "liquidatee"
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RequestType — wallet-authored enum matching Blend discriminants 0-9
// ─────────────────────────────────────────────────────────────────────────────

/// Wallet-authored re-declaration of the Blend pool `RequestType` enum.
///
/// Discriminants cited from
/// `blend-contracts pool/src/pool/actions.rs` (v1)
/// and confirmed identical at
/// `blend-contracts-v2 pool/src/pool/actions.rs` (v2):
///
/// | Discriminant | Variant |
/// |---|---|
/// | 0 | [`Supply`][RequestType::Supply] |
/// | 1 | [`Withdraw`][RequestType::Withdraw] |
/// | 2 | [`SupplyCollateral`][RequestType::SupplyCollateral] |
/// | 3 | [`WithdrawCollateral`][RequestType::WithdrawCollateral] |
/// | 4 | [`Borrow`][RequestType::Borrow] |
/// | 5 | [`Repay`][RequestType::Repay] |
/// | 6 | [`FillUserLiquidationAuction`][RequestType::FillUserLiquidationAuction] |
/// | 7 | [`FillBadDebtAuction`][RequestType::FillBadDebtAuction] |
/// | 8 | [`FillInterestAuction`][RequestType::FillInterestAuction] |
/// | 9 | [`DeleteLiquidationAuction`][RequestType::DeleteLiquidationAuction] |
///
/// Any value >9 is rejected by [`RequestType::try_from_u32`] with
/// [`BlendAbiError::UnknownRequestType`] — the wallet never delegates this
/// check to the on-chain `from_u32` panic.
///
/// `#[non_exhaustive]`: a future Blend protocol version could add a discriminant,
/// so external consumers must keep a wildcard arm; the wallet's own matches
/// enumerate all current 0-9 variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
#[non_exhaustive]
pub enum RequestType {
    /// Supply tokens to the pool's reserve (discriminant 0).
    ///
    /// Cited from `blend-contracts pool/src/pool/actions.rs`.
    Supply = 0,
    /// Withdraw tokens from the pool's reserve (discriminant 1).
    ///
    /// Cited from `blend-contracts pool/src/pool/actions.rs`.
    Withdraw = 1,
    /// Supply tokens as collateral (discriminant 2).
    ///
    /// Cited from `blend-contracts pool/src/pool/actions.rs`.
    SupplyCollateral = 2,
    /// Withdraw tokens from collateral (discriminant 3).
    ///
    /// Cited from `blend-contracts pool/src/pool/actions.rs`.
    WithdrawCollateral = 3,
    /// Borrow tokens from the pool's reserve (discriminant 4).
    ///
    /// Cited from `blend-contracts pool/src/pool/actions.rs`.
    Borrow = 4,
    /// Repay a borrow (discriminant 5).
    ///
    /// Cited from `blend-contracts pool/src/pool/actions.rs`.
    Repay = 5,
    /// Fill a user liquidation auction (discriminant 6).
    ///
    /// Cited from `blend-contracts pool/src/pool/actions.rs`.
    FillUserLiquidationAuction = 6,
    /// Fill a bad-debt auction (discriminant 7).
    ///
    /// Cited from `blend-contracts pool/src/pool/actions.rs`.
    FillBadDebtAuction = 7,
    /// Fill an interest auction (discriminant 8).
    ///
    /// Cited from `blend-contracts pool/src/pool/actions.rs`.
    FillInterestAuction = 8,
    /// Cancel/delete a user liquidation auction (discriminant 9).
    ///
    /// Cited from `blend-contracts pool/src/pool/actions.rs`.
    DeleteLiquidationAuction = 9,
}

impl RequestType {
    /// Converts a `u32` discriminant to a [`RequestType`].
    ///
    /// Returns [`BlendAbiError::UnknownRequestType`] for any value outside 0-9.
    /// This is fail-closed: the wallet refuses pre-sign rather than delegating
    /// to the on-chain `from_u32` panic at
    /// `blend-contracts pool/src/pool/actions.rs`.
    ///
    /// # Errors
    ///
    /// Returns [`BlendAbiError::UnknownRequestType`] when `value > 9`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_blend::abi::{RequestType, BlendAbiError};
    ///
    /// let supply = RequestType::try_from_u32(0).expect("0 is Supply");
    /// assert_eq!(supply, RequestType::Supply);
    /// let err = RequestType::try_from_u32(10);
    /// assert!(err.is_err());
    /// ```
    pub fn try_from_u32(value: u32) -> Result<Self, BlendAbiError> {
        match value {
            0 => Ok(RequestType::Supply),
            1 => Ok(RequestType::Withdraw),
            2 => Ok(RequestType::SupplyCollateral),
            3 => Ok(RequestType::WithdrawCollateral),
            4 => Ok(RequestType::Borrow),
            5 => Ok(RequestType::Repay),
            6 => Ok(RequestType::FillUserLiquidationAuction),
            7 => Ok(RequestType::FillBadDebtAuction),
            8 => Ok(RequestType::FillInterestAuction),
            9 => Ok(RequestType::DeleteLiquidationAuction),
            _ => Err(BlendAbiError::UnknownRequestType {
                discriminant: value,
            }),
        }
    }

    /// Returns the `u32` discriminant of this request type.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_blend::abi::RequestType;
    ///
    /// assert_eq!(RequestType::Supply.discriminant(), 0);
    /// assert_eq!(RequestType::DeleteLiquidationAuction.discriminant(), 9);
    /// ```
    #[must_use]
    pub fn discriminant(self) -> u32 {
        self as u32
    }

    /// Returns `Ok(())` when this `RequestType` is permitted on the `lend` verb
    /// (discriminants 0-5), or `Err` when it is a liquidation discriminant
    /// (6-9).
    ///
    /// Liquidation operations (6-9) require the dedicated `liquidate` verb,
    /// which provides a distinct approval surface flagging liquidation risk.
    /// Routing them through `lend` would bypass that surface.
    ///
    /// # Errors
    ///
    /// Returns [`BlendAbiError::LiquidationVerbRequired`] for discriminants 6-9.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_blend::abi::{RequestType, BlendAbiError};
    ///
    /// assert!(RequestType::Supply.assert_lend_verb_allowed().is_ok());
    /// assert!(RequestType::Repay.assert_lend_verb_allowed().is_ok());
    /// let err = RequestType::FillUserLiquidationAuction.assert_lend_verb_allowed();
    /// assert!(matches!(err, Err(BlendAbiError::LiquidationVerbRequired { .. })));
    /// ```
    pub fn assert_lend_verb_allowed(self) -> Result<(), BlendAbiError> {
        match self {
            RequestType::Supply
            | RequestType::Withdraw
            | RequestType::SupplyCollateral
            | RequestType::WithdrawCollateral
            | RequestType::Borrow
            | RequestType::Repay => Ok(()),
            // Discriminants 6-9 are liquidation operations. They require the
            // dedicated `liquidate` verb, which provides a distinct approval
            // surface for liquidation risk.
            RequestType::FillUserLiquidationAuction
            | RequestType::FillBadDebtAuction
            | RequestType::FillInterestAuction
            | RequestType::DeleteLiquidationAuction => {
                Err(BlendAbiError::LiquidationVerbRequired {
                    discriminant: self.discriminant(),
                })
            }
        }
    }

    /// Returns a human-readable verb label for this request type.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_blend::abi::RequestType;
    ///
    /// assert_eq!(RequestType::Supply.verb(), "supply");
    /// assert_eq!(RequestType::FillUserLiquidationAuction.verb(), "fill_liquidation");
    /// ```
    #[must_use]
    pub fn verb(self) -> &'static str {
        match self {
            RequestType::Supply => "supply",
            RequestType::Withdraw => "withdraw",
            RequestType::SupplyCollateral => "supply_collateral",
            RequestType::WithdrawCollateral => "withdraw_collateral",
            RequestType::Borrow => "borrow",
            RequestType::Repay => "repay",
            RequestType::FillUserLiquidationAuction => "fill_liquidation",
            RequestType::FillBadDebtAuction => "fill_bad_debt",
            RequestType::FillInterestAuction => "fill_interest",
            RequestType::DeleteLiquidationAuction => "cancel_liquidation",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LendArgs — typed arguments for the `lend` verb
// ─────────────────────────────────────────────────────────────────────────────

/// Typed arguments for the Blend `lend` verb.
///
/// Passed as `&dyn Any` through the `DefiAdapter::preview` / `submit` boundary;
/// the downcast is fail-closed.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LendArgs {
    /// The pool contract address (C-strkey).
    pub pool_address: String,
    /// The wallet smart-account address submitting the operation (C-strkey).
    pub from_address: String,
    /// The list of requests to submit.
    pub requests: Vec<BlendRequest>,
    /// Whether to override oracle staleness (default `false`).
    ///
    /// When `true`, the operation proceeds even if the Reflector timestamp
    /// exceeds the default 600s threshold; a distinct
    /// `oracle.staleness_overridden` audit event is unconditionally emitted.
    /// Non-overridable refusals (pin-verify, oracle allowlist) are unaffected.
    #[serde(default)]
    pub override_oracle_staleness: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// BlendAbiError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when constructing or validating Blend ABI types.
///
/// All variants carry non-sensitive diagnostic information; the
/// `Display` impl never leaks addresses, hashes, or signing material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlendAbiError {
    /// The `request_type` discriminant is not in the 0-9 range.
    ///
    /// Cited to `blend-contracts pool/src/pool/actions.rs`:
    /// `from_u32` panics on >9 with `PoolError::BadRequest`.
    /// The wallet refuses pre-sign with this typed error instead.
    #[error("unknown Blend request_type discriminant: {discriminant} (valid range is 0-9)")]
    UnknownRequestType {
        /// The unrecognised discriminant value.
        discriminant: u32,
    },

    /// A `BlendRequest` field is invalid (empty address, zero amount, etc.).
    ///
    /// # Note on `reason`
    ///
    /// The `reason` string MUST NOT contain addresses, hashes, keys, or other
    /// sensitive data.  It is surfaced in tool responses.
    #[error("invalid Blend request field: {reason}")]
    InvalidField {
        /// Non-sensitive reason string.
        reason: String,
    },

    /// A liquidation discriminant (6-9) was submitted to the `lend` verb.
    ///
    /// Liquidation operations require the dedicated `liquidate` verb, which
    /// provides a distinct approval surface flagging liquidation risk.
    #[error(
        "Blend request_type {discriminant} is a liquidation operation (6-9); \
         use the `liquidate` verb — the `lend` verb permits only \
         lending operations (0-5: supply/withdraw/supply_collateral/\
         withdraw_collateral/borrow/repay)"
    )]
    LiquidationVerbRequired {
        /// The liquidation discriminant that was submitted.
        discriminant: u32,
    },

    /// ScVal encoding failed.
    #[error("Blend ScVal encoding error: {0}")]
    ScValEncoding(#[from] BlendScValError),
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

    // ── Unknown-discriminant refusal ──

    #[test]
    fn unknown_discriminant_10_refused() {
        let err = RequestType::try_from_u32(10).expect_err("10 must be refused");
        assert!(matches!(
            err,
            BlendAbiError::UnknownRequestType { discriminant: 10 }
        ));
    }

    #[test]
    fn unknown_discriminant_max_refused() {
        let err = RequestType::try_from_u32(u32::MAX).expect_err("max u32 must be refused");
        assert!(matches!(
            err,
            BlendAbiError::UnknownRequestType {
                discriminant: u32::MAX
            }
        ),);
    }

    #[test]
    fn all_valid_discriminants_0_to_9_accepted() {
        for i in 0u32..=9 {
            assert!(
                RequestType::try_from_u32(i).is_ok(),
                "discriminant {i} must be accepted"
            );
        }
    }

    #[test]
    fn request_type_discriminant_round_trips() {
        for i in 0u32..=9 {
            let rt = RequestType::try_from_u32(i).unwrap();
            assert_eq!(rt.discriminant(), i, "discriminant must round-trip for {i}");
        }
    }

    // ── address_label contextualisation ──────────────────────────────────────

    #[test]
    fn supply_address_is_asset() {
        let req = BlendRequest::new(RequestType::Supply, "CAAAA…B", 100);
        assert_eq!(req.address_label(), "asset");
        assert!(req.is_asset_address());
    }

    #[test]
    fn fill_liquidation_address_is_liquidatee() {
        let req = BlendRequest::new(RequestType::FillUserLiquidationAuction, "CAAAA…B", 100);
        assert_eq!(req.address_label(), "liquidatee");
        assert!(!req.is_asset_address());
    }

    #[test]
    fn delete_liquidation_address_is_liquidatee() {
        let req = BlendRequest::new(RequestType::DeleteLiquidationAuction, "CAAAA…B", 0);
        assert_eq!(req.address_label(), "liquidatee");
        assert!(!req.is_asset_address());
    }

    // ── Verb labels ──────────────────────────────────────────────────────────

    #[test]
    fn verb_labels_are_correct() {
        assert_eq!(RequestType::Supply.verb(), "supply");
        assert_eq!(RequestType::Withdraw.verb(), "withdraw");
        assert_eq!(RequestType::SupplyCollateral.verb(), "supply_collateral");
        assert_eq!(
            RequestType::WithdrawCollateral.verb(),
            "withdraw_collateral"
        );
        assert_eq!(RequestType::Borrow.verb(), "borrow");
        assert_eq!(RequestType::Repay.verb(), "repay");
        assert_eq!(
            RequestType::FillUserLiquidationAuction.verb(),
            "fill_liquidation"
        );
        assert_eq!(RequestType::FillBadDebtAuction.verb(), "fill_bad_debt");
        assert_eq!(RequestType::FillInterestAuction.verb(), "fill_interest");
        assert_eq!(
            RequestType::DeleteLiquidationAuction.verb(),
            "cancel_liquidation"
        );
    }

    // ── UnknownRequestType Display includes the rejected discriminant + 0-9 range ──

    #[test]
    fn unknown_discriminant_error_display_contains_value() {
        let err = RequestType::try_from_u32(42).expect_err("42 is unknown");
        let display = err.to_string();
        assert!(
            display.contains("42"),
            "display must contain discriminant value"
        );
        assert!(display.contains("0-9"), "display must cite valid range");
    }

    // ── assert_lend_verb_allowed: lending ops (0-5) pass; liquidation (6-9) refuse ──

    #[test]
    fn lend_verb_permits_all_lending_ops() {
        for rt in [
            RequestType::Supply,
            RequestType::Withdraw,
            RequestType::SupplyCollateral,
            RequestType::WithdrawCollateral,
            RequestType::Borrow,
            RequestType::Repay,
        ] {
            assert!(
                rt.assert_lend_verb_allowed().is_ok(),
                "lend verb must permit {:?} (discriminant {})",
                rt,
                rt.discriminant()
            );
        }
    }

    /// Discriminant 6 (FillUserLiquidationAuction) must be refused on the
    /// `lend` verb with `LiquidationVerbRequired`, pointing callers to the
    /// dedicated `liquidate` verb.
    #[test]
    fn lend_verb_refuses_discriminant_6_fill_user_liquidation_auction() {
        let err = RequestType::FillUserLiquidationAuction
            .assert_lend_verb_allowed()
            .expect_err("discriminant 6 must be refused on lend verb");
        assert!(
            matches!(
                err,
                BlendAbiError::LiquidationVerbRequired { discriminant: 6 }
            ),
            "expected LiquidationVerbRequired {{ discriminant: 6 }}, got {err:?}"
        );
        // The error message must direct callers to the dedicated liquidate verb.
        let display = err.to_string();
        assert!(
            display.contains("liquidate"),
            "error display must direct callers to the liquidate verb; got: {display}"
        );
    }

    #[test]
    fn lend_verb_refuses_all_liquidation_discriminants_7_8_9() {
        for rt in [
            RequestType::FillBadDebtAuction,
            RequestType::FillInterestAuction,
            RequestType::DeleteLiquidationAuction,
        ] {
            let err = rt
                .assert_lend_verb_allowed()
                .expect_err(&format!("{rt:?} must be refused on lend verb"));
            assert!(
                matches!(err, BlendAbiError::LiquidationVerbRequired { .. }),
                "expected LiquidationVerbRequired for {rt:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn validate_accepts_lending_and_refuses_liquidation_and_bad_fields() {
        const ADDR: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        // Lending discriminants 0-5 with valid fields pass validation.
        for rt in [
            RequestType::Supply,
            RequestType::Withdraw,
            RequestType::SupplyCollateral,
            RequestType::WithdrawCollateral,
            RequestType::Borrow,
            RequestType::Repay,
        ] {
            assert!(
                BlendRequest::new(rt, ADDR, 1).validate().is_ok(),
                "{rt:?} with a valid address and positive amount must validate"
            );
        }
        // Liquidation discriminants 6-9 are refused with LiquidationVerbRequired.
        for rt in [
            RequestType::FillUserLiquidationAuction,
            RequestType::FillBadDebtAuction,
            RequestType::FillInterestAuction,
            RequestType::DeleteLiquidationAuction,
        ] {
            let err = BlendRequest::new(rt, ADDR, 1)
                .validate()
                .expect_err("a liquidation discriminant must be refused on the lend verb");
            assert!(
                matches!(err, BlendAbiError::LiquidationVerbRequired { .. }),
                "{rt:?} must yield LiquidationVerbRequired, got {err:?}"
            );
        }
        // Empty address and non-positive amounts are refused with InvalidField.
        for (req, label) in [
            (
                BlendRequest::new(RequestType::Supply, "", 1),
                "empty address",
            ),
            (
                BlendRequest::new(RequestType::Supply, ADDR, 0),
                "zero amount",
            ),
            (
                BlendRequest::new(RequestType::Supply, ADDR, -5),
                "negative amount",
            ),
        ] {
            let err = req
                .validate()
                .expect_err(&format!("{label} must be refused"));
            assert!(
                matches!(err, BlendAbiError::InvalidField { .. }),
                "{label} must yield InvalidField, got {err:?}"
            );
        }
    }
}
