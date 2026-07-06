//! Typed trustline preview (TrustlinePreview).
//!
//! `TrustlinePreview` is the typed, JSON-serialisable preview surface for a
//! proposed `ChangeTrust` operation.  It is produced before any on-chain
//! submission and presented to the operator for confirmation.
//!
//! # Content
//!
//! - Asset: code + issuer (full issuer in machine-readable fields; display-layer
//!   rendering should redact to first-5-last-5).
//! - Issuer flags: `AccountFlagsView` projection for clawback gate state and
//!   `auth_revocable` informational line.
//! - Clawback gate decision: one of `Proceed` / `RefuseWithWarning` /
//!   `Refuse` (see `clawback_gate`).
//!
//! # No raw XDR
//!
//! `TrustlinePreview` does NOT include raw XDR bytes.  The bridge / verb
//! handler builds the `ChangeTrust` envelope separately via `ClassicOpBuilder`
//! after the preview is accepted.
//!

use serde::{Deserialize, Serialize};
use stellar_agent_network::account::AccountFlagsView;

use crate::flags::{GateDecision, clawback_gate};
use crate::resolve::ResolvedAsset;

// ─────────────────────────────────────────────────────────────────────────────
// TrustlinePreview
// ─────────────────────────────────────────────────────────────────────────────

/// A typed, JSON-serialisable preview of a proposed `ChangeTrust` operation.
///
/// Produced by [`TrustlinePreview::build`] from a `ResolvedAsset` and the live
/// `AccountFlagsView`.  Carried to the operator for final confirmation before
/// the `stellar_trustline_commit` path submits the envelope.
///
/// # Non-exhaustive
///
/// New fields (e.g. decimal-resolved amounts, SEP-1 TOML) will be added
/// without breaking the serialised shape.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustlinePreview {
    /// The asset code, canonical uppercase.
    pub code: String,

    /// The canonical issuer G-strkey.
    ///
    /// Full G-strkey (not redacted) for machine-readable consumers.
    /// Display-layer rendering SHOULD redact to first-5-last-5.
    pub issuer: String,

    /// The trustline limit in stroops.
    ///
    /// `None` indicates the default maximum limit (`i64::MAX`, per Stellar
    /// convention when no explicit limit is supplied).
    ///
    /// Encoded as a decimal string on the wire (`serde(with =
    /// "stellar_agent_core::wire_stroops::i64_opt")`): a JSON number backed
    /// by `f64` cannot represent an `i64` stroop limit exactly once it
    /// exceeds `2^53`. The field's Rust type stays `Option<i64>` for
    /// internal use.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "stellar_agent_core::wire_stroops::i64_opt"
    )]
    pub limit_stroops: Option<i64>,

    /// Whether this asset was resolved through the pin table.
    pub is_pinned: bool,

    /// Live issuer flag disclosure.
    ///
    /// `None` when the flag fetch failed (the `gate_decision` will be `Refuse`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_flags: Option<AccountFlagsView>,

    /// The clawback gate decision for this trustline.
    ///
    /// Derived from `issuer_flags` and the wallet opt-in state.
    /// Callers MUST check this field before proceeding to submission.
    pub gate_decision: GateDecisionView,
}

/// A serialisable view of [`GateDecision`] for JSON output.
///
/// Bridges the non-serialisable `GateDecision` enum (which references static
/// str fields) to a JSON-compatible form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GateDecisionView {
    /// Trustline creation can proceed.
    Proceed,
    /// Trustline refused with the named clawback warning.
    RefuseWithWarning {
        /// The warning text.
        warning: String,
    },
    /// Trustline refused unconditionally (flag-fetch failure or similar).
    Refuse {
        /// Human-readable reason.
        reason: String,
    },
}

impl From<GateDecision> for GateDecisionView {
    fn from(d: GateDecision) -> Self {
        match d {
            GateDecision::Proceed => Self::Proceed,
            GateDecision::RefuseWithWarning { warning } => Self::RefuseWithWarning {
                warning: warning.to_owned(),
            },
            GateDecision::Refuse { reason } => Self::Refuse {
                reason: reason.to_owned(),
            },
        }
    }
}

impl TrustlinePreview {
    /// Builds a `TrustlinePreview` from a resolved asset, live flags, and opt-in state.
    ///
    /// # Parameters
    ///
    /// - `asset`: denomination-resolved asset from [`crate::resolve::resolve_denomination`].
    /// - `limit_stroops`: optional explicit trustline limit in stroops.  `None`
    ///   means the wallet will use `i64::MAX` (the Stellar default unlimited trustline).
    /// - `flags`: live issuer flag projection from `AccountView.account_flags: Option<AccountFlagsView>`.
    ///   `None` when the flag fetch failed (gate fail-closes).
    /// - `opt_in_present`: whether a wallet-controlled
    ///   `ApprovalKind::TrustlineClawbackOptIn` record exists.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::account::AccountFlagsView;
    /// use stellar_agent_stablecoin::preview::{GateDecisionView, TrustlinePreview};
    /// use stellar_agent_stablecoin::resolve::ResolvedAsset;
    ///
    /// let asset = ResolvedAsset {
    ///     code: "USDC".to_owned(),
    ///     issuer: "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_owned(),
    ///     is_pinned: true,
    /// };
    /// let flags = AccountFlagsView::from_raw(0x2); // revocable only
    /// let preview = TrustlinePreview::build(asset, None, Some(&flags), false);
    /// assert_eq!(preview.code, "USDC");
    /// assert!(matches!(preview.gate_decision, GateDecisionView::Proceed));
    /// ```
    #[must_use]
    pub fn build(
        asset: ResolvedAsset,
        limit_stroops: Option<i64>,
        flags: Option<&AccountFlagsView>,
        opt_in_present: bool,
    ) -> Self {
        let gate = clawback_gate(flags, opt_in_present);
        Self {
            code: asset.code,
            issuer: asset.issuer,
            limit_stroops,
            is_pinned: asset.is_pinned,
            issuer_flags: flags.cloned(),
            gate_decision: gate.into(),
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
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use super::*;

    fn make_asset(code: &str, issuer: &str, is_pinned: bool) -> ResolvedAsset {
        ResolvedAsset {
            code: code.to_owned(),
            issuer: issuer.to_owned(),
            is_pinned,
        }
    }

    const TESTNET_USDC_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

    #[test]
    fn preview_no_clawback_gate_proceed() {
        let asset = make_asset("USDC", TESTNET_USDC_ISSUER, true);
        let flags = AccountFlagsView::from_raw(0x2); // revocable
        let preview = TrustlinePreview::build(asset, None, Some(&flags), false);
        assert_eq!(preview.code, "USDC");
        assert_eq!(preview.issuer, TESTNET_USDC_ISSUER);
        assert!(preview.is_pinned);
        assert!(preview.issuer_flags.is_some());
        assert!(matches!(preview.gate_decision, GateDecisionView::Proceed));
        assert!(preview.limit_stroops.is_none());
    }

    #[test]
    fn preview_clawback_no_opt_in_refuse_with_warning() {
        let asset = make_asset("MYTOKEN", TESTNET_USDC_ISSUER, false);
        let flags = AccountFlagsView::from_raw(0x8); // clawback only
        let preview = TrustlinePreview::build(asset, None, Some(&flags), false);
        assert!(matches!(
            preview.gate_decision,
            GateDecisionView::RefuseWithWarning { .. }
        ));
    }

    #[test]
    fn preview_clawback_with_opt_in_proceed() {
        let asset = make_asset("MYTOKEN", TESTNET_USDC_ISSUER, false);
        let flags = AccountFlagsView::from_raw(0x8); // clawback only
        let preview = TrustlinePreview::build(asset, None, Some(&flags), true);
        assert!(matches!(preview.gate_decision, GateDecisionView::Proceed));
    }

    #[test]
    fn preview_fetch_failed_refuse() {
        let asset = make_asset("USDC", TESTNET_USDC_ISSUER, true);
        let preview = TrustlinePreview::build(asset, None, None, false);
        assert!(preview.issuer_flags.is_none());
        assert!(matches!(
            preview.gate_decision,
            GateDecisionView::Refuse { .. }
        ));
    }

    #[test]
    fn preview_with_explicit_limit() {
        let asset = make_asset("USDC", TESTNET_USDC_ISSUER, true);
        let flags = AccountFlagsView::from_raw(0x0);
        let limit = 1_000_000_000i64; // 100 USDC at 7 decimals
        let preview = TrustlinePreview::build(asset, Some(limit), Some(&flags), false);
        assert_eq!(preview.limit_stroops, Some(1_000_000_000));

        let json = serde_json::to_value(&preview).unwrap();
        assert_eq!(
            json["limit_stroops"], "1000000000",
            "limit_stroops must serialize as a decimal string"
        );
    }

    #[test]
    fn preview_limit_stroops_omitted_from_json_when_none() {
        let asset = make_asset("USDC", TESTNET_USDC_ISSUER, true);
        let flags = AccountFlagsView::from_raw(0x0);
        let preview = TrustlinePreview::build(asset, None, Some(&flags), false);

        let json = serde_json::to_value(&preview).unwrap();
        assert!(json.get("limit_stroops").is_none());

        // The `with = "...::i64_opt"` custom deserializer suppresses serde's
        // implicit missing-field-means-None for `Option<T>`; `#[serde(default)]`
        // restores it. Without it, deserializing this None-produced,
        // field-omitted JSON would fail with "missing field `limit_stroops`".
        let round_tripped: TrustlinePreview = serde_json::from_value(json)
            .expect("omitted limit_stroops must deserialize back to None, not error");
        assert_eq!(round_tripped.limit_stroops, None);
    }

    #[test]
    fn preview_limit_stroops_round_trips_i64_max() {
        let asset = make_asset("USDC", TESTNET_USDC_ISSUER, true);
        let flags = AccountFlagsView::from_raw(0x0);
        let preview = TrustlinePreview::build(asset, Some(i64::MAX), Some(&flags), false);

        let json = serde_json::to_value(&preview).unwrap();
        assert_eq!(json["limit_stroops"], "9223372036854775807");
        let round_tripped: TrustlinePreview = serde_json::from_value(json).unwrap();
        assert_eq!(round_tripped.limit_stroops, Some(i64::MAX));
    }

    #[test]
    fn gate_decision_view_serde_roundtrip() {
        let cases = vec![
            GateDecisionView::Proceed,
            GateDecisionView::RefuseWithWarning {
                warning: "some warning".to_owned(),
            },
            GateDecisionView::Refuse {
                reason: "fetch failed".to_owned(),
            },
        ];
        for case in cases {
            let json = serde_json::to_string(&case).unwrap();
            let back: GateDecisionView = serde_json::from_str(&json).unwrap();
            assert_eq!(case, back, "serde round-trip failed for: {json}");
        }
    }
}
