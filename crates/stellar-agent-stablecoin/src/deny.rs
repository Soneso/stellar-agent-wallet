//! USDT hard-refusal rule.
//!
//! Any trustline whose asset code equals `USDT` (exact canonical-uppercase +
//! case-variants such as `usdt`, `Usdt`) is refused with the named warning
//! [`USDT_REFUSAL_WARNING`], regardless of supplied issuer.
//!
//! # Scope (narrow by design)
//!
//! Only exact `USDT` variants are in scope.  Adjacent codes — `USDT0`, `TETHER`,
//! `USD T` — are deliberately NOT in the hard-deny set: `USDT0` is a real
//! distinct asset and substring heuristics produce false positives.  Those codes
//! fail-closed via the denomination resolver's default refusal (unpinned bare
//! code / lookalike denylist) with the denomination-reason error.
//!
//! There is no agent-suppliable override for USDT at v1.

// ─────────────────────────────────────────────────────────────────────────────
// Warning constant
// ─────────────────────────────────────────────────────────────────────────────

/// Warning displayed when USDT is refused.
pub const USDT_REFUSAL_WARNING: &str = "USDT-on-Stellar-lookalike-risk";

// ─────────────────────────────────────────────────────────────────────────────
// Rule function
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` when `code` triggers the USDT hard-refusal rule.
///
/// Matches exact `USDT` and its case variants (e.g. `usdt`, `Usdt`).
/// Does NOT match adjacent codes such as `USDT0` or `TETHER`.
///
/// # Rationale
///
/// USDT has no canonical issuer on Stellar — multiple assets with this code
/// exist, each presenting counterparty-impersonation risk.  An agent or
/// user receiving "USDT" as a bare code from an untrusted source cannot
/// reliably determine which issuer is intended, creating a systematic lookalike
/// risk.  Hard refusal is the safest posture at v1.  Adjacent codes such as
/// `USDT0` are distinct assets and are handled by the denominator resolver's
/// normal unpinned-bare-code / denylist paths.
///
/// There is no agent-suppliable override for USDT.
///
/// # Examples
///
/// ```
/// use stellar_agent_stablecoin::deny::is_usdt;
///
/// assert!(is_usdt("USDT"));
/// assert!(is_usdt("usdt"));
/// assert!(is_usdt("Usdt"));
/// assert!(!is_usdt("USDT0"));
/// assert!(!is_usdt("TETHER"));
/// assert!(!is_usdt("USDC"));
/// ```
#[must_use]
pub fn is_usdt(code: &str) -> bool {
    code.eq_ignore_ascii_case("USDT")
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

    #[test]
    fn usdt_exact_upper() {
        assert!(is_usdt("USDT"));
    }

    #[test]
    fn usdt_lower() {
        assert!(is_usdt("usdt"));
    }

    #[test]
    fn usdt_mixed() {
        assert!(is_usdt("Usdt"));
        assert!(is_usdt("uSDT"));
    }

    #[test]
    fn usdt0_not_denied() {
        assert!(!is_usdt("USDT0"));
    }

    #[test]
    fn tether_not_denied() {
        assert!(!is_usdt("TETHER"));
    }

    #[test]
    fn usdc_not_denied() {
        assert!(!is_usdt("USDC"));
    }

    #[test]
    fn eurc_not_denied() {
        assert!(!is_usdt("EURC"));
    }

    #[test]
    fn empty_not_denied() {
        assert!(!is_usdt(""));
    }

    #[test]
    fn usd_space_t_not_denied() {
        // Substring / padded variants are not in scope.
        assert!(!is_usdt("USD T"));
        assert!(!is_usdt("USDT "));
        assert!(!is_usdt(" USDT"));
    }

    #[test]
    fn warning_constant_matches_spec() {
        assert_eq!(USDT_REFUSAL_WARNING, "USDT-on-Stellar-lookalike-risk");
    }
}
