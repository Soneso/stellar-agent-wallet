//! Typed preview for Blend lending operations.
//!
//! # What this module does
//!
//! Produces a [`BlendLendPreview`] for a set of [`BlendRequest`]s: a typed,
//! JSON-default preview with request-type-labelled request entries, contextual
//! `address` labelling (asset vs liquidatee per type), and a display-only
//! post-op health-factor estimate.
//!
//! # No-escape-hatch discipline
//!
//! [`BlendLendPreview`] has NO raw-vector or opaque-calldata field.  Every
//! field is typed and human-renderable; this is a type-level guarantee.
//!
//! # Health-factor display
//!
//! The HF is DISPLAY-ONLY — it NEVER gates signing.  A successful simulate of
//! the actual `submit` IS the fail-closed health gate.  The HF display field
//! carries arming-aware labelling:
//! - `HfStatus::NotArmed` — no liabilities; the chain HF check did not arm.
//! - `HfStatus::Unavailable` — the HF could not be computed from simulate results.
//! - `HfStatus::ArmedAndPassed { hf_ratio }` — reserved for a simulate-result
//!   projection of a passed chain check.  The adapter's `preview` currently
//!   emits only `Unavailable`; `NotArmed`/`ArmedAndPassed` are reserved for a
//!   future submit-time simulate projection.
//!
//! # Behavior
//!
//! Produces the typed `Vec<Request>` preview with a display-only health
//! factor.

use crate::abi::BlendRequest;
use stellar_agent_core::observability::redact_strkey_first5_last5;

// ─────────────────────────────────────────────────────────────────────────────
// BlendLendPreview
// ─────────────────────────────────────────────────────────────────────────────

/// Typed preview for a Blend `lend` verb invocation.
///
/// Produced by [`build_blend_lend_preview`] and embedded in
/// [`stellar_agent_defi::adapter::DefiPreview`].
///
/// # No-escape-hatch
///
/// Contains NO raw-vector or opaque-calldata field; every field is typed and
/// human-renderable.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct BlendLendPreview {
    /// First-5-last-5 redacted pool address.
    pub pool_address_redacted: String,
    /// From account (first-5-last-5 redacted).
    pub from_address_redacted: String,
    /// The typed request entries.
    pub requests: Vec<BlendRequestEntry>,
    /// Post-op health-factor display (display only; never gates signing).
    pub health_factor: HfStatus,
    /// Oracle staleness info (display only).
    pub oracle_staleness_secs: Option<u64>,
}

/// A single request entry in the preview.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct BlendRequestEntry {
    /// Human-readable verb (e.g. `"supply"`, `"borrow"`, `"repay"`).
    pub verb: String,
    /// First-5-last-5 redacted address (asset or liquidatee per type).
    pub address_redacted: String,
    /// Label for the address field: `"asset"` or `"liquidatee"`.
    pub address_label: String,
    /// Amount in the asset's native base unit.
    pub amount: i128,
}

/// Arming-aware health-factor status (display only).
///
/// Distinguishes "guard armed and passed" from "guard not armed (no
/// liabilities)".
///
/// Carry only the HF ratio; no oracle address, full hash, or signing material.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum HfStatus {
    /// Reserved for a simulate-result projection of a passed chain HF check
    /// (position has liabilities and simulated successfully).  The adapter does
    /// not currently produce this variant.
    ///
    /// `hf_ratio` is the predicted post-op health factor * 1e7 (Blend's
    /// internal representation).  Display-only; NEVER gates signing.
    ArmedAndPassed {
        /// Health factor ratio (7-decimal fixed-point, as returned by Blend's
        /// `PositionData::calculate_from_positions`, display only).
        hf_ratio: i128,
    },
    /// The chain HF check was not armed because the operation has no
    /// liabilities after simulation.
    ///
    /// Cited from `blend-contracts pool/src/pool/submit.rs`:
    /// `if check_health && new_from_state.has_liabilities()`.
    NotArmed,
    /// The post-op HF could not be computed from the simulate result.
    Unavailable,
}

// ─────────────────────────────────────────────────────────────────────────────
// build_blend_lend_preview
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a [`BlendLendPreview`] from typed arguments.
///
/// # Redaction
///
/// All C-strkeys are redacted to first-5-last-5.
/// Amounts are user-facing-by-design in the preview and are NOT redacted.
#[must_use]
pub fn build_blend_lend_preview(
    pool_address: &str,
    from_address: &str,
    requests: &[BlendRequest],
    health_factor: HfStatus,
    oracle_staleness_secs: Option<u64>,
) -> BlendLendPreview {
    let pool_address_redacted = redact_strkey_first5_last5(pool_address);
    let from_address_redacted = redact_strkey_first5_last5(from_address);

    let request_entries = requests
        .iter()
        .map(|req| BlendRequestEntry {
            verb: req.request_type.verb().to_owned(),
            address_redacted: redact_strkey_first5_last5(&req.address),
            address_label: req.address_label().to_owned(),
            amount: req.amount,
        })
        .collect();

    BlendLendPreview {
        pool_address_redacted,
        from_address_redacted,
        requests: request_entries,
        health_factor,
        oracle_staleness_secs,
    }
}

/// Returns a human-readable one-line summary of a [`BlendLendPreview`].
///
/// Used as the `summary` field in [`stellar_agent_defi::adapter::DefiPreview`].
#[must_use]
pub fn preview_summary(preview: &BlendLendPreview) -> String {
    if preview.requests.is_empty() {
        return format!(
            "Blend lend: 0 requests on pool {}",
            preview.pool_address_redacted
        );
    }
    let first = &preview.requests[0];
    if preview.requests.len() == 1 {
        format!(
            "Blend {}: {} {} on pool {}",
            first.verb.as_str(),
            first.amount,
            first.address_label.as_str(),
            preview.pool_address_redacted
        )
    } else {
        format!(
            "Blend {}: {} requests on pool {}",
            first.verb.as_str(),
            preview.requests.len(),
            preview.pool_address_redacted
        )
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
    use crate::abi::RequestType;

    const POOL: &str = "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF";
    const FROM: &str = "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD";
    const ASSET: &str = "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU";

    fn make_supply_request() -> BlendRequest {
        BlendRequest::new(RequestType::Supply, ASSET, 5_000_000_000)
    }

    // ── Preview construction ─────────────────────────────────────────────────

    #[test]
    fn preview_redacts_addresses() {
        let preview = build_blend_lend_preview(
            POOL,
            FROM,
            &[make_supply_request()],
            HfStatus::NotArmed,
            Some(100),
        );
        // Pool address must be redacted (first-5-last-5)
        assert!(!preview.pool_address_redacted.contains(POOL));
        // Redacted form is first-5 + "..." + last-5: CCEBV...44HGF for this pool.
        assert!(
            preview.pool_address_redacted.starts_with("CCEBV"),
            "starts_with CCEBV: {}",
            preview.pool_address_redacted
        );
        assert!(
            preview.pool_address_redacted.contains("..."),
            "must contain ellipsis separator"
        );
        // Request address must also be redacted
        assert!(!preview.requests[0].address_redacted.contains(ASSET));
    }

    #[test]
    fn supply_request_entry_has_correct_labels() {
        let preview = build_blend_lend_preview(
            POOL,
            FROM,
            &[make_supply_request()],
            HfStatus::NotArmed,
            None,
        );
        let entry = &preview.requests[0];
        assert_eq!(entry.verb, "supply".to_owned());
        assert_eq!(entry.address_label, "asset".to_owned());
        assert_eq!(entry.amount, 5_000_000_000i128);
    }

    #[test]
    fn liquidation_request_entry_has_liquidatee_label() {
        let req = BlendRequest::new(RequestType::FillUserLiquidationAuction, ASSET, 1_000_000);
        let preview = build_blend_lend_preview(POOL, FROM, &[req], HfStatus::NotArmed, None);
        let entry = &preview.requests[0];
        assert_eq!(entry.verb, "fill_liquidation".to_owned());
        assert_eq!(entry.address_label, "liquidatee".to_owned());
    }

    // ── No-escape-hatch: preview serialises to typed fields only ─────────────

    #[test]
    fn preview_json_has_no_raw_or_opaque_field() {
        let preview = build_blend_lend_preview(
            POOL,
            FROM,
            &[make_supply_request()],
            HfStatus::ArmedAndPassed {
                hf_ratio: 1_5000000,
            },
            Some(100),
        );
        let json = serde_json::to_value(&preview).expect("serialize");
        let obj = json.as_object().expect("object");
        for key in obj.keys() {
            assert!(
                !key.contains("raw") && !key.contains("opaque") && !key.contains("extra"),
                "escape-hatch field found in preview JSON: {key}"
            );
        }
    }

    // ── HfStatus variants ────────────────────────────────────────────────────

    #[test]
    fn hf_not_armed_serialises() {
        let preview = build_blend_lend_preview(POOL, FROM, &[], HfStatus::NotArmed, None);
        let json = serde_json::to_string(&preview).expect("serialize");
        assert!(
            json.contains("NotArmed"),
            "HfStatus::NotArmed must serialise"
        );
    }

    #[test]
    fn hf_armed_and_passed_carries_ratio() {
        let hf = HfStatus::ArmedAndPassed {
            hf_ratio: 1_2345678,
        };
        let json = serde_json::to_value(&hf).expect("serialize");
        // Must contain hf_ratio field
        assert!(
            json["ArmedAndPassed"]["hf_ratio"].as_i64() == Some(1_2345678),
            "hf_ratio must be present in ArmedAndPassed serialisation"
        );
    }

    // ── Preview summary ──────────────────────────────────────────────────────

    #[test]
    fn preview_summary_single_request() {
        let preview = build_blend_lend_preview(
            POOL,
            FROM,
            &[make_supply_request()],
            HfStatus::NotArmed,
            None,
        );
        let summary = preview_summary(&preview);
        assert!(summary.contains("supply"), "summary must contain verb");
        assert!(
            summary.contains("CCEBV"),
            "summary must contain redacted pool address prefix: {summary}"
        );
    }
}
