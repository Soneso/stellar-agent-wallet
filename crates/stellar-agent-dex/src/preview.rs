//! Typed preview for the Soroswap `trade` (swap) verb.
//!
//! # What this module does
//!
//! Produces a [`SwapPreview`] for a [`TradeArgs`] invocation: a typed,
//! JSON-default preview with the swap parameters in human-readable form.
//!
//! # No-escape-hatch discipline
//!
//! [`SwapPreview`] has NO raw-vector or opaque-calldata field.  Every field
//! is typed and human-renderable.
//!
//! # Behavior
//!
//! The preview carries the absolute `amount_out_min`, the canonicalised path,
//! and the deadline as typed, human-readable fields.

use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_defi::adapter::DefiPreview;

use crate::abi::TradeArgs;

// ─────────────────────────────────────────────────────────────────────────────
// SwapPreview
// ─────────────────────────────────────────────────────────────────────────────

/// Typed preview for a Soroswap `trade` (swap) verb invocation.
///
/// Embedded in [`stellar_agent_defi::adapter::DefiPreview`] as the
/// typed preview payload.
///
/// # No-escape-hatch
///
/// Contains NO raw-vector or opaque-calldata field.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct SwapPreview {
    /// First-5-last-5 redacted router address.
    pub router_address_redacted: String,
    /// First-5-last-5 redacted sender/recipient address.
    pub from_address_redacted: String,
    /// Exact input token amount (native base units).
    pub amount_in: i128,
    /// Minimum output token amount (absolute floor, required).
    pub amount_out_min: i128,
    /// Canonicalised path: first-5-last-5 of each C-strkey for display.
    ///
    /// Full addresses are redacted.
    pub path_redacted: Vec<String>,
    /// Deadline Unix timestamp (seconds).
    pub deadline: u64,
    /// Network identifier (e.g. `"stellar:testnet"`).
    pub network: String,
    /// Expected output amount from the on-chain quote, if available.
    ///
    /// `None` when the quote was not fetched at preview time (e.g. quote-only
    /// flow with no pre-sign re-verify).  The pre-sign reverify fills this for
    /// the signing flow.
    pub expected_out: Option<i128>,
}

// ─────────────────────────────────────────────────────────────────────────────
// build_swap_preview
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a [`SwapPreview`] and wraps it in a [`DefiPreview`].
///
/// The `router_address` is the pinned Soroswap router for the network.
/// The `canonical_path` must already be canonicalised (C-strkeys).
/// The `resolved_deadline` is the final Unix timestamp (already resolved from
/// the `TradeArgs`; `None` → `now + DEFAULT_DEADLINE_OFFSET_SECS`).
///
/// # Arguments
///
/// - `args` — validated and deadline-resolved `TradeArgs`.
/// - `router_address` — pinned router C-strkey for display.
/// - `canonical_path` — canonicalised (C-strkeys) path for display.
/// - `resolved_deadline` — final deadline Unix timestamp.
/// - `network` — network identifier (e.g. `"stellar:testnet"`).
/// - `expected_out` — on-chain quote output amount, if available.
#[must_use]
pub fn build_swap_preview(
    args: &TradeArgs,
    router_address: &str,
    canonical_path: &[String],
    resolved_deadline: u64,
    network: &str,
    expected_out: Option<i128>,
) -> (SwapPreview, DefiPreview) {
    let router_redacted = redact_strkey_first5_last5(router_address);
    let from_redacted = redact_strkey_first5_last5(&args.from_address);
    let path_redacted: Vec<String> = canonical_path
        .iter()
        .map(|addr| redact_strkey_first5_last5(addr))
        .collect();

    let swap_preview = SwapPreview {
        router_address_redacted: router_redacted.clone(),
        from_address_redacted: from_redacted,
        amount_in: args.amount_in,
        amount_out_min: args.amount_out_min,
        path_redacted,
        deadline: resolved_deadline,
        network: network.to_owned(),
        expected_out,
    };

    // The DefiPreview summary is derived from the typed SwapPreview so the typed
    // preview is the single source of truth for the human-facing summary.
    let summary = preview_summary(&swap_preview);
    let defi_preview = DefiPreview::new("soroswap", "trade", network, router_redacted, summary);

    (swap_preview, defi_preview)
}

/// Returns a human-readable one-line summary of a [`SwapPreview`].
///
/// Used as the `summary` field in [`stellar_agent_defi::adapter::DefiPreview`].
#[must_use]
pub fn preview_summary(preview: &SwapPreview) -> String {
    format!(
        "Swap {} (min out: {}) via Soroswap ({}-hop path) on {}",
        preview.amount_in,
        preview.amount_out_min,
        preview.path_redacted.len().saturating_sub(1),
        preview.network,
    )
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

    fn make_trade_args() -> TradeArgs {
        TradeArgs {
            from_address: "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD".to_owned(),
            amount_in: 1_000_000_000,
            amount_out_min: 990_000_000,
            path: vec![
                "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".to_owned(),
                "CB3TLW74NBIOT3BUWOZ3TUM6RFDF6A4GVIRUQRQZABG5KPOUL4JJOV2F".to_owned(),
            ],
            deadline: Some(9_999_999_999),
        }
    }

    #[test]
    fn swap_preview_contains_correct_amount_in() {
        let args = make_trade_args();
        let (preview, _) = build_swap_preview(
            &args,
            "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD",
            &args.path,
            9_999_999_999,
            "stellar:testnet",
            None,
        );
        assert_eq!(preview.amount_in, args.amount_in);
    }

    #[test]
    fn swap_preview_contains_correct_amount_out_min() {
        let args = make_trade_args();
        let (preview, _) = build_swap_preview(
            &args,
            "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD",
            &args.path,
            9_999_999_999,
            "stellar:testnet",
            None,
        );
        assert_eq!(preview.amount_out_min, args.amount_out_min);
    }

    #[test]
    fn defi_preview_protocol_is_soroswap() {
        let args = make_trade_args();
        let (_, defi_preview) = build_swap_preview(
            &args,
            "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD",
            &args.path,
            9_999_999_999,
            "stellar:testnet",
            None,
        );
        assert_eq!(defi_preview.protocol, "soroswap");
        assert_eq!(defi_preview.verb, "trade");
    }

    #[test]
    fn router_address_is_redacted_in_preview() {
        let router = "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD";
        let args = make_trade_args();
        let (preview, defi_preview) = build_swap_preview(
            &args,
            router,
            &args.path,
            9_999_999_999,
            "stellar:testnet",
            None,
        );
        // Full address must not appear in redacted fields.
        assert!(
            !preview.router_address_redacted.contains(router),
            "router address must be redacted in SwapPreview"
        );
        assert!(
            !defi_preview.contract_address_redacted.contains(router),
            "router address must be redacted in DefiPreview"
        );
    }

    #[test]
    fn path_addresses_are_redacted_in_preview() {
        let full_addr = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
        let args = make_trade_args();
        let (preview, _) = build_swap_preview(
            &args,
            "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD",
            &args.path,
            9_999_999_999,
            "stellar:testnet",
            None,
        );
        for redacted in &preview.path_redacted {
            assert!(
                !redacted.contains(full_addr),
                "full address must not appear in path_redacted"
            );
        }
    }

    #[test]
    fn from_address_is_redacted_in_preview() {
        let full_addr = "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD";
        let args = make_trade_args();
        let (preview, _) = build_swap_preview(
            &args,
            full_addr,
            &args.path,
            9_999_999_999,
            "stellar:testnet",
            None,
        );
        assert!(
            !preview.from_address_redacted.contains(full_addr),
            "from address must be redacted in SwapPreview"
        );
    }

    #[test]
    fn defi_preview_summary_is_derived_from_swap_preview() {
        let args = make_trade_args();
        let (preview, defi_preview) = build_swap_preview(
            &args,
            "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD",
            &args.path,
            9_999_999_999,
            "stellar:testnet",
            None,
        );
        assert_eq!(
            defi_preview.summary,
            preview_summary(&preview),
            "DefiPreview summary must be derived from the typed SwapPreview"
        );
        assert!(
            defi_preview.summary.contains(&args.amount_in.to_string()),
            "summary must mention amount_in"
        );
        assert!(
            defi_preview.summary.contains("Soroswap"),
            "summary must name the venue"
        );
    }

    #[test]
    fn expected_out_is_propagated() {
        let args = make_trade_args();
        let (preview, _) = build_swap_preview(
            &args,
            "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD",
            &args.path,
            9_999_999_999,
            "stellar:testnet",
            Some(995_000_000),
        );
        assert_eq!(preview.expected_out, Some(995_000_000));
    }
}
