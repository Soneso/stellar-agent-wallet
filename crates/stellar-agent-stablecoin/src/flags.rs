//! Clawback gate decision for trustline creation.
//!
//! `clawback_gate` is a pure function that maps issuer flag state + wallet-
//! controlled opt-in to a `GateDecision`.  The flag projection itself is
//! `stellar_agent_network::account::AccountFlagsView`, which is produced by
//! `fetch_account` from `AccountEntry.flags` at trustline-creation time.
//!
//! # Fail-closed invariant
//!
//! A flag-fetch failure (the caller passes `flags = None`) MUST fail-close the
//! gate: the wallet cannot confirm the issuer is clawback-safe, so it refuses.
//! A dropped RPC query can never downgrade a trustline to "assumed safe."
//!
//! # Disclosure policy
//!
//! - `auth_clawback_enabled = true` WITHOUT wallet opt-in → `RefuseWithWarning`
//!   (the named clawback warning).
//! - `auth_clawback_enabled = true` WITH wallet opt-in → `Proceed`.
//! - `auth_clawback_enabled = false` → `Proceed` (flag absent).
//! - `auth_revocable = true` → informational disclosure only, does NOT gate.
//!   Gating on revocability would friction-wall the Circle happy path: both
//!   mainnet USDC and EURC issuers are `revocable = true, clawback = false`
//!   as of 2026-06-11.

use stellar_agent_network::account::AccountFlagsView;

// ─────────────────────────────────────────────────────────────────────────────
// Named clawback warning
// ─────────────────────────────────────────────────────────────────────────────

/// Named clawback warning displayed when a trustline would be created with an
/// issuer that has `AUTH_CLAWBACK_ENABLED_FLAG` set.
///
/// Shown in the typed trustline refusal when no wallet opt-in is present.
pub const CLAWBACK_WARNING: &str =
    "issuer-clawback-enabled — this issuer can recover tokens from your trustline";

// ─────────────────────────────────────────────────────────────────────────────
// GateDecision
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome of the clawback gate decision function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// Proceed with trustline creation.  No clawback concern.
    Proceed,

    /// Refuse the trustline with the named clawback warning.
    ///
    /// The wallet caller must surface `CLAWBACK_WARNING` to the user.
    /// The gate can be cleared by recording a `TrustlineClawbackOptIn` in the
    /// approval store and re-attempting (`opt_in_present = true`).
    RefuseWithWarning {
        /// The warning text (always [`CLAWBACK_WARNING`]).
        warning: &'static str,
    },

    /// Refuse unconditionally — the flag state could not be confirmed
    /// (flag-fetch failure; fail-closed).
    ///
    /// The wallet caller must surface this as a hard error (not just a warning)
    /// because a dropped RPC query cannot be treated as "assumed safe."
    Refuse {
        /// Human-readable reason for the unconditional refusal.
        reason: &'static str,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Clawback gate
// ─────────────────────────────────────────────────────────────────────────────

/// Decides whether to proceed with trustline creation based on issuer flags.
///
/// # Parameters
///
/// - `flags`: the issuer's live flag projection from `AccountView.account_flags`.
///   `None` means the flag fetch FAILED — the gate fail-closes unconditionally.
/// - `opt_in_present`: whether a wallet-controlled
///   `ApprovalKind::TrustlineClawbackOptIn` record exists for this trustline.
///   This is NOT an agent-suppliable bool; it must be derived from the approval
///   store by the verb handler.
///
/// # Decision table
///
/// | flags | opt_in_present | decision |
/// |-------|---------------|----------|
/// | `None` (fetch failed) | any | `Refuse { reason: … }` (fail-closed) |
/// | `auth_clawback_enabled = false` | any | `Proceed` |
/// | `auth_clawback_enabled = true` | `false` | `RefuseWithWarning { CLAWBACK_WARNING }` |
/// | `auth_clawback_enabled = true` | `true` | `Proceed` |
///
/// `auth_revocable` is disclosed via `AccountFlagsView` in the trustline preview
/// but does NOT influence this gate (both Circle issuers are
/// `revocable = true, clawback = false` live).
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```
/// use stellar_agent_network::account::AccountFlagsView;
/// use stellar_agent_stablecoin::flags::{GateDecision, CLAWBACK_WARNING, clawback_gate};
///
/// // Fetch succeeded; clawback disabled — proceed unconditionally.
/// let flags = AccountFlagsView::from_raw(0x2); // revocable only
/// assert_eq!(clawback_gate(Some(&flags), false), GateDecision::Proceed);
///
/// // Clawback enabled, no opt-in — refuse with warning.
/// let flags_cb = AccountFlagsView::from_raw(0xA); // revocable | clawback
/// assert!(matches!(
///     clawback_gate(Some(&flags_cb), false),
///     GateDecision::RefuseWithWarning { .. }
/// ));
///
/// // Clawback enabled, opt-in present — proceed.
/// assert_eq!(clawback_gate(Some(&flags_cb), true), GateDecision::Proceed);
///
/// // Fetch failed — fail-closed unconditionally.
/// assert!(matches!(clawback_gate(None, false), GateDecision::Refuse { .. }));
/// ```
#[must_use]
pub fn clawback_gate(flags: Option<&AccountFlagsView>, opt_in_present: bool) -> GateDecision {
    match flags {
        None => GateDecision::Refuse {
            reason: "issuer flag fetch failed — cannot confirm clawback safety (fail-closed)",
        },
        Some(f) => {
            if f.auth_clawback_enabled {
                if opt_in_present {
                    GateDecision::Proceed
                } else {
                    GateDecision::RefuseWithWarning {
                        warning: CLAWBACK_WARNING,
                    }
                }
            } else {
                // clawback not enabled — proceed regardless of revocable/required/immutable.
                GateDecision::Proceed
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — truth table for clawback_gate
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

    // Helper: build a flags view from a tuple.
    fn flags(required: bool, revocable: bool, immutable: bool, clawback: bool) -> AccountFlagsView {
        let mut raw: u32 = 0;
        if required {
            raw |= 0x1;
        }
        if revocable {
            raw |= 0x2;
        }
        if immutable {
            raw |= 0x4;
        }
        if clawback {
            raw |= 0x8;
        }
        AccountFlagsView::from_raw(raw)
    }

    // ── AccountFlagsView::from_raw (used by clawback gate) ────────────────────

    #[test]
    fn from_raw_all_zero() {
        let v = AccountFlagsView::from_raw(0);
        assert!(!v.auth_required);
        assert!(!v.auth_revocable);
        assert!(!v.auth_immutable);
        assert!(!v.auth_clawback_enabled);
    }

    #[test]
    fn from_raw_all_set() {
        let v = AccountFlagsView::from_raw(0xF);
        assert!(v.auth_required);
        assert!(v.auth_revocable);
        assert!(v.auth_immutable);
        assert!(v.auth_clawback_enabled);
    }

    #[test]
    fn from_raw_clawback_only() {
        let v = AccountFlagsView::from_raw(0x8);
        assert!(!v.auth_required);
        assert!(!v.auth_revocable);
        assert!(!v.auth_immutable);
        assert!(v.auth_clawback_enabled);
    }

    #[test]
    fn from_raw_revocable_only() {
        let v = AccountFlagsView::from_raw(0x2);
        assert!(!v.auth_required);
        assert!(v.auth_revocable);
        assert!(!v.auth_immutable);
        assert!(!v.auth_clawback_enabled);
    }

    // ── clawback_gate truth table ─────────────────────────────────────────────

    #[test]
    fn gate_fetch_failed_refuse_regardless_of_opt_in_false() {
        // Fetch failed, no opt-in → fail-closed Refuse.
        assert!(matches!(
            clawback_gate(None, false),
            GateDecision::Refuse { .. }
        ));
    }

    #[test]
    fn gate_fetch_failed_refuse_regardless_of_opt_in_true() {
        // Fetch failed, opt-in present → still fail-closed Refuse.
        assert!(matches!(
            clawback_gate(None, true),
            GateDecision::Refuse { .. }
        ));
    }

    #[test]
    fn gate_no_clawback_no_opt_in_proceed() {
        // clawback = false → Proceed (revocable informational only).
        let f = flags(false, true, false, false); // revocable = true, clawback = false
        assert_eq!(clawback_gate(Some(&f), false), GateDecision::Proceed);
    }

    #[test]
    fn gate_no_clawback_with_opt_in_proceed() {
        let f = flags(false, false, false, false);
        assert_eq!(clawback_gate(Some(&f), true), GateDecision::Proceed);
    }

    #[test]
    fn gate_clawback_enabled_no_opt_in_refuse_with_warning() {
        let f = flags(false, true, false, true);
        let decision = clawback_gate(Some(&f), false);
        assert_eq!(
            decision,
            GateDecision::RefuseWithWarning {
                warning: CLAWBACK_WARNING
            }
        );
    }

    #[test]
    fn gate_clawback_enabled_with_opt_in_proceed() {
        let f = flags(false, true, false, true);
        assert_eq!(clawback_gate(Some(&f), true), GateDecision::Proceed);
    }

    #[test]
    fn gate_revocable_only_proceed_without_opt_in() {
        // Revocable does NOT gate (see module doc).
        let f = flags(false, true, false, false);
        assert_eq!(clawback_gate(Some(&f), false), GateDecision::Proceed);
    }

    #[test]
    fn gate_all_flags_no_opt_in_refuse_with_warning() {
        // All flags set including clawback — RefuseWithWarning without opt-in.
        let f = flags(true, true, true, true);
        assert!(matches!(
            clawback_gate(Some(&f), false),
            GateDecision::RefuseWithWarning { .. }
        ));
    }

    #[test]
    fn gate_all_flags_with_opt_in_proceed() {
        // All flags set, opt-in present — Proceed.
        let f = flags(true, true, true, true);
        assert_eq!(clawback_gate(Some(&f), true), GateDecision::Proceed);
    }

    #[test]
    fn clawback_warning_constant_has_expected_prefix() {
        assert!(CLAWBACK_WARNING.starts_with("issuer-clawback-enabled"));
    }

    // ── Circle mainnet live-flags simulation ──────────────────────────────────

    #[test]
    fn circle_mainnet_usdc_flags_no_clawback_proceed() {
        // Live mainnet USDC flags (2026-06-11): revocable = true, clawback = false.
        let f = AccountFlagsView::from_raw(0x2); // AUTH_REVOCABLE_FLAG
        assert!(f.auth_revocable);
        assert!(!f.auth_clawback_enabled);
        assert_eq!(clawback_gate(Some(&f), false), GateDecision::Proceed);
    }
}
