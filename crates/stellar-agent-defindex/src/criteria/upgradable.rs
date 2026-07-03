//! Upgradable-flag criterion for DeFindex vault operations.
//!
//! # What this module does
//!
//! Implements the `vault_upgradable` criterion: refuses signing when the vault
//! is marked upgradable:true and the caller has NOT set `override_upgradable`.
//!
//! # Upgradable posture and self-managed exemption
//!
//! Refusal is required when a vault is upgradable:true for
//! delegated-manager vaults.  **Self-managed vaults are exempt**: when the
//! depositor IS the Manager AND no third-party holds EmergencyManager or
//! RebalanceManager, the vault cannot be upgraded against the depositor's
//! interest without their own key.  The criterion passes for self-managed vaults
//! regardless of the `upgradable:true` flag.
//!
//! For all other management modes (`NotManager`, `Delegated`), the
//! refusal applies: upgradable:true vaults are refused unless
//! `override_upgradable = true`.
//!
//! # Mode-aware evaluation order
//!
//! `evaluate` receives the `VaultManagementMode` AFTER roles are read (step 3
//! of the ordered trust gate).  This is the correct order: mode is computed
//! from the on-chain roles, so the refusal logic is mode-aware.
//!
//! # Override semantics
//!
//! When `override_upgradable = true` (and the vault is NOT self-managed), the
//! criterion emits the `vault.upgradable_override` audit event
//! (EMIT-THEN-RETURN, mirroring the `oracle.staleness_overridden` pattern at
//! `stellar-agent-defi::oracle_staleness`) and returns `Ok(())`.
//!
//! # Fail-closed
//!
//! Absent flag = upgradable:true (the contract defaults the missing flag to
//! `true` via `.unwrap_or(true)`) — this criterion aligns: absent = REFUSE
//! (unless self-managed or override is set).

// ─────────────────────────────────────────────────────────────────────────────
// UpgradableDenialReason
// ─────────────────────────────────────────────────────────────────────────────

/// The reason returned when the upgradable criterion refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpgradableDenialReason {
    /// The vault is upgradable (upgradable:true) and the caller did not set
    /// `override_upgradable`.
    VaultUpgradable,
}

impl std::fmt::Display for UpgradableDenialReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpgradableDenialReason::VaultUpgradable => {
                write!(
                    f,
                    "vault.upgradable_refused: vault is marked upgradable=true (use override_upgradable=true to proceed)"
                )
            }
        }
    }
}

/// Token proving that [`proceed_with_upgradable_override`] was called and the
/// audit event was emitted.
///
/// Constructing this type outside this module is impossible (the `_private`
/// field is not `pub`).
#[derive(Debug)]
pub struct UpgradableOverrideToken {
    _private: (),
}

/// Emits the `vault.upgradable_override` audit event and returns an override token.
///
/// The proceed path on upgradable override is reachable ONLY through this
/// function — it ALWAYS emits the audit event before returning (EMIT-THEN-RETURN
/// pattern, mirroring `proceed_with_staleness_override`).
pub fn proceed_with_upgradable_override() -> UpgradableOverrideToken {
    tracing::warn!(
        event = "vault.upgradable_override",
        "vault upgradable override: proceeding with upgradable=true vault (operator override)"
    );
    UpgradableOverrideToken { _private: () }
}

// ─────────────────────────────────────────────────────────────────────────────
// UpgradableEvalExt
// ─────────────────────────────────────────────────────────────────────────────

/// Extension for evaluating the upgradable flag in the dispatch flow.
///
/// `evaluate` returns `Ok(())` when the vault is NOT upgradable (or override
/// is granted, or the vault is self-managed), and `Err(reason)` otherwise.
///
/// # Mode-aware evaluation
///
/// Self-managed vaults (depositor == Manager, no third-party EM/RM) are EXEMPT
/// from the upgradable refusal.  All other modes
/// (`NotManager`, `Delegated`) are subject to the refusal.
///
/// # Fail-closed
///
/// When `is_upgradable = true`, `override_upgradable = false`, and the vault is
/// NOT self-managed, refuses.
pub struct UpgradableEvalExt;

impl UpgradableEvalExt {
    /// Evaluates the upgradable flag with management-mode awareness.
    ///
    /// - `is_upgradable`: value read from vault instance storage (absent = `true`).
    /// - `override_upgradable`: caller opt-in to bypass the upgradable refusal.
    /// - `management_mode`: computed from on-chain roles (step 3 of ordered gate).
    ///
    /// Self-managed vaults (`VaultManagementMode::SelfManaged`) are always exempt
    /// from the upgradable refusal; `override_upgradable` is ignored for them.
    ///
    /// # Errors
    ///
    /// Returns [`UpgradableDenialReason::VaultUpgradable`] when the vault is
    /// upgradable, the mode is NOT self-managed, and no override was provided.
    pub fn evaluate(
        is_upgradable: bool,
        override_upgradable: bool,
        management_mode: &crate::roles::VaultManagementMode,
    ) -> Result<(), UpgradableDenialReason> {
        if !is_upgradable {
            return Ok(());
        }

        // Self-managed vaults: the depositor controls all fund-affecting roles;
        // an upgrade requires their own key — the upgradable refusal does not apply.
        if matches!(
            management_mode,
            crate::roles::VaultManagementMode::SelfManaged
        ) {
            return Ok(());
        }

        if override_upgradable {
            // EMIT-THEN-RETURN: unconditionally emit before proceeding.
            let _token = proceed_with_upgradable_override();
            Ok(())
        } else {
            Err(UpgradableDenialReason::VaultUpgradable)
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
        reason = "test-only fixture construction"
    )]

    use super::*;
    use crate::roles::VaultManagementMode;

    fn not_manager() -> VaultManagementMode {
        VaultManagementMode::NotManager
    }

    fn self_managed() -> VaultManagementMode {
        VaultManagementMode::SelfManaged
    }

    fn delegated() -> VaultManagementMode {
        VaultManagementMode::Delegated {
            third_party_emergency_manager: true,
            third_party_rebalance_manager: false,
        }
    }

    // ── Non-upgradable vault always passes ───────────────────────────────────

    #[test]
    fn non_upgradable_vault_passes() {
        let result = UpgradableEvalExt::evaluate(false, false, &not_manager());
        assert!(result.is_ok(), "upgradable=false must pass: {result:?}");
    }

    #[test]
    fn non_upgradable_vault_passes_even_with_override_false() {
        let result = UpgradableEvalExt::evaluate(false, false, &delegated());
        assert!(result.is_ok());
    }

    // ── Upgradable delegated vault refuses without override ──────────────────

    #[test]
    fn upgradable_delegated_vault_refuses_without_override() {
        let result = UpgradableEvalExt::evaluate(true, false, &delegated());
        assert!(
            matches!(result, Err(UpgradableDenialReason::VaultUpgradable)),
            "upgradable=true delegated without override must refuse: {result:?}"
        );
    }

    // ── Upgradable not-manager vault refuses without override ────────────────

    #[test]
    fn upgradable_not_manager_vault_refuses_without_override() {
        let result = UpgradableEvalExt::evaluate(true, false, &not_manager());
        assert!(
            matches!(result, Err(UpgradableDenialReason::VaultUpgradable)),
            "upgradable=true not-manager without override must refuse: {result:?}"
        );
    }

    // ── Upgradable self-managed vault is EXEMPT ──────────────────────────────

    #[test]
    fn upgradable_self_managed_vault_exempt() {
        let result = UpgradableEvalExt::evaluate(true, false, &self_managed());
        assert!(
            result.is_ok(),
            "upgradable=true self-managed must pass without override (self-managed exemption): {result:?}"
        );
    }

    // ── Upgradable vault with override emits audit and proceeds ─────────────

    #[test]
    fn upgradable_vault_with_override_proceeds() {
        let result = UpgradableEvalExt::evaluate(true, true, &delegated());
        assert!(
            result.is_ok(),
            "upgradable=true with override must proceed: {result:?}"
        );
    }

    // ── Display carries no vault address ─────────────────────────────────────

    #[test]
    fn upgradable_denial_display_contains_posture_code() {
        let reason = UpgradableDenialReason::VaultUpgradable;
        let display = reason.to_string();
        assert!(
            display.contains("vault.upgradable_refused"),
            "must contain error code: {display}"
        );
        assert!(
            display.contains("override_upgradable"),
            "must reference the override option: {display}"
        );
    }
}
