//! DeFindex vault role getter reads and self-managed detection.
//!
//! # What this module does
//!
//! Provides [`read_vault_roles`] — step 3 of the ordered trust gate — which
//! reads all four role addresses from the vault's instance storage and
//! constructs a [`VaultRolesSnapshot`].
//!
//! # Role data keys
//!
//! `RolesDataKey` is a `#[contracttype]` enum with four unit variants
//! defined by the DeFindex vault access module:
//!
//! ```text
//! enum RolesDataKey {
//!     EmergencyManager, // Role: 0
//!     VaultFeeReceiver, // Role: 1
//!     Manager,          // Role: 2
//!     RebalanceManager, // Role: 3
//! }
//! ```
//!
//! Each variant encodes as `ScVal::Vec([Symbol("EmergencyManager")])`, etc.,
//! per the `soroban-sdk-macros 22.0.3` unit-variant encoding (same as
//! `DataKey::Upgradable`).
//!
//! All four are stored in instance storage (same as `DataKey::Upgradable`).
//!
//! # Self-managed detection
//!
//! A vault is **self-managed** when the `depositor` address (`from` arg) equals
//! `Manager` AND neither `EmergencyManager` nor `RebalanceManager` holds a
//! DIFFERENT address.  `VaultFeeReceiver` is disclose-only.
//!
//! If the vault has a third-party `EmergencyManager` or `RebalanceManager`,
//! it is **delegated** and the wallet emits a disclosure warning.

use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_xdr_limits::untrusted_decode_limits;
use stellar_strkey::Contract;
use stellar_xdr::{
    ContractDataDurability, Hash, LedgerEntryData, LedgerKey, LedgerKeyContractData, ReadXdr,
    ScAddress, ScVal,
};

use crate::storage::{VaultStorageFetchError, build_unit_variant_scval_key, sc_address_to_strkey};

// ─────────────────────────────────────────────────────────────────────────────
// VaultRolesSnapshot
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot of the four DeFindex vault roles, read after the ordered gate passes.
///
/// Holds first-5-last-5 redacted versions of each role address for display,
/// plus the raw C-strkey for self-managed comparison.
#[derive(Debug, Clone)]
pub struct VaultRolesSnapshot {
    /// C-strkey address of the Manager role.
    pub manager: Option<String>,
    /// First-5-last-5 redacted Manager address for display.
    pub manager_redacted: Option<String>,
    /// C-strkey address of the EmergencyManager role.
    pub emergency_manager: Option<String>,
    /// First-5-last-5 redacted EmergencyManager address for display.
    pub emergency_manager_redacted: Option<String>,
    /// C-strkey address of the RebalanceManager role.
    pub rebalance_manager: Option<String>,
    /// First-5-last-5 redacted RebalanceManager address for display.
    pub rebalance_manager_redacted: Option<String>,
    /// C-strkey address of the VaultFeeReceiver role (disclose-only).
    pub vault_fee_receiver: Option<String>,
    /// First-5-last-5 redacted VaultFeeReceiver address for display.
    pub vault_fee_receiver_redacted: Option<String>,
}

/// Whether the vault is self-managed or has third-party role holders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultManagementMode {
    /// The depositor is the Manager and no third-party holds EmergencyManager
    /// or RebalanceManager.
    SelfManaged,
    /// A third-party address holds EmergencyManager, RebalanceManager, or both.
    Delegated {
        /// Whether EmergencyManager is held by a third party.
        third_party_emergency_manager: bool,
        /// Whether RebalanceManager is held by a third party.
        third_party_rebalance_manager: bool,
    },
    /// The depositor address does not match the Manager role.
    NotManager,
}

impl VaultRolesSnapshot {
    /// Determines the management mode for `depositor_address`.
    ///
    /// Returns [`VaultManagementMode::NotManager`] when the depositor is not
    /// the Manager.  Returns [`VaultManagementMode::SelfManaged`] when the
    /// depositor is the Manager and neither EmergencyManager nor
    /// RebalanceManager is held by a different address.
    #[must_use]
    pub fn management_mode(&self, depositor_address: &str) -> VaultManagementMode {
        // Check if depositor is Manager.
        let is_manager = self.manager.as_deref() == Some(depositor_address);

        if !is_manager {
            return VaultManagementMode::NotManager;
        }

        // Check for third-party EmergencyManager or RebalanceManager.
        let third_party_em = self
            .emergency_manager
            .as_deref()
            .is_some_and(|em| em != depositor_address);
        let third_party_rm = self
            .rebalance_manager
            .as_deref()
            .is_some_and(|rm| rm != depositor_address);

        if third_party_em || third_party_rm {
            VaultManagementMode::Delegated {
                third_party_emergency_manager: third_party_em,
                third_party_rebalance_manager: third_party_rm,
            }
        } else {
            VaultManagementMode::SelfManaged
        }
    }

    /// Returns a human-readable summary of the roles snapshot.
    ///
    /// Uses first-5-last-5 redacted addresses so full addresses never appear.
    #[must_use]
    pub fn disclosure_summary(&self) -> String {
        format!(
            "manager={} emergency_manager={} rebalance_manager={} fee_receiver={}",
            self.manager_redacted.as_deref().unwrap_or("absent"),
            self.emergency_manager_redacted
                .as_deref()
                .unwrap_or("absent"),
            self.rebalance_manager_redacted
                .as_deref()
                .unwrap_or("absent"),
            self.vault_fee_receiver_redacted
                .as_deref()
                .unwrap_or("absent"),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// read_vault_roles
// ─────────────────────────────────────────────────────────────────────────────

/// Reads all four vault role addresses from the vault's instance storage.
///
/// This is **step 3** of the ordered trust gate.  Called ONLY after
/// `verify_defindex_vault_wasm` (step 1) and `read_vault_upgradable_flag`
/// (step 2) have both passed.
///
/// Reads the contract instance entry once via `getLedgerEntries`, then
/// extracts all four role keys from the instance storage map.
///
/// # Errors
///
/// Returns [`VaultStorageFetchError`] on any RPC or XDR failure.
pub async fn read_vault_roles(
    vault_address: &str,
    primary_rpc: &StellarRpcClient,
) -> Result<VaultRolesSnapshot, VaultStorageFetchError> {
    // ── 1. Build instance storage ledger key ─────────────────────────────────
    let contract = Contract::from_string(vault_address).map_err(|e| {
        VaultStorageFetchError::InvalidAddress {
            reason: format!("{e}"),
        }
    })?;
    let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(stellar_xdr::ContractId(Hash(contract.0))),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });

    // ── 2. Get ledger entries (single RPC call) ───────────────────────────────
    let response = primary_rpc
        .get_ledger_entries(&[instance_key])
        .await
        .map_err(|e| VaultStorageFetchError::LedgerFetchFailed {
            reason: format!("{e}"),
        })?;

    let entries = response.entries.unwrap_or_default();
    if entries.is_empty() {
        return Err(VaultStorageFetchError::InstanceNotFound);
    }

    // ── 3. Decode the first entry as LedgerEntryData ─────────────────────────
    // Bound depth + length: the RPC server is untrusted; `untrusted_decode_limits`
    // bounds depth (500) and length (input byte count), refusing a depth-bomb DoS.
    let entry_data = LedgerEntryData::from_xdr_base64(
        &entries[0].xdr,
        untrusted_decode_limits(entries[0].xdr.len()),
    )
    .map_err(|e| VaultStorageFetchError::XdrError {
        reason: format!("LedgerEntryData decode: {e}"),
    })?;

    let contract_data = match entry_data {
        LedgerEntryData::ContractData(cd) => cd,
        _ => {
            return Err(VaultStorageFetchError::XdrError {
                reason: "expected ContractData".to_owned(),
            });
        }
    };

    let instance = match contract_data.val {
        ScVal::ContractInstance(ci) => ci,
        _ => {
            return Err(VaultStorageFetchError::XdrError {
                reason: "expected ScVal::ContractInstance".to_owned(),
            });
        }
    };

    let storage_map = instance.storage.unwrap_or_default();

    // ── 4. Extract each role from the instance storage map ──────────────────
    let manager = extract_address_from_map(&storage_map, "Manager")?;
    let emergency_manager = extract_address_from_map(&storage_map, "EmergencyManager")?;
    let rebalance_manager = extract_address_from_map(&storage_map, "RebalanceManager")?;
    let vault_fee_receiver = extract_address_from_map(&storage_map, "VaultFeeReceiver")?;

    // ── 5. Build snapshot with redacted displays ─────────────────────────────
    Ok(VaultRolesSnapshot {
        manager_redacted: manager.as_deref().map(redact_strkey_first5_last5),
        emergency_manager_redacted: emergency_manager.as_deref().map(redact_strkey_first5_last5),
        rebalance_manager_redacted: rebalance_manager.as_deref().map(redact_strkey_first5_last5),
        vault_fee_receiver_redacted: vault_fee_receiver
            .as_deref()
            .map(redact_strkey_first5_last5),
        manager,
        emergency_manager,
        rebalance_manager,
        vault_fee_receiver,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts an `Address` ScVal from an instance storage map by unit-variant key name.
///
/// Returns `None` if the key is absent.
fn extract_address_from_map(
    storage_map: &stellar_xdr::ScMap,
    variant_name: &str,
) -> Result<Option<String>, VaultStorageFetchError> {
    let key = build_unit_variant_scval_key(variant_name)?;
    for entry in storage_map.0.iter() {
        if entry.key == key {
            return match &entry.val {
                ScVal::Address(sc_addr) => {
                    let strkey = sc_address_to_strkey(sc_addr)?;
                    Ok(Some(strkey))
                }
                other => Err(VaultStorageFetchError::XdrError {
                    reason: format!("role '{variant_name}' value is not ScVal::Address: {other:?}"),
                }),
            };
        }
    }
    Ok(None)
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

    const DEPOSITOR: &str = "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD";
    const THIRD_PARTY: &str = "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF";

    fn snapshot_self_managed() -> VaultRolesSnapshot {
        VaultRolesSnapshot {
            manager: Some(DEPOSITOR.to_owned()),
            manager_redacted: Some(redact_strkey_first5_last5(DEPOSITOR)),
            emergency_manager: Some(DEPOSITOR.to_owned()),
            emergency_manager_redacted: Some(redact_strkey_first5_last5(DEPOSITOR)),
            rebalance_manager: Some(DEPOSITOR.to_owned()),
            rebalance_manager_redacted: Some(redact_strkey_first5_last5(DEPOSITOR)),
            vault_fee_receiver: Some(DEPOSITOR.to_owned()),
            vault_fee_receiver_redacted: Some(redact_strkey_first5_last5(DEPOSITOR)),
        }
    }

    fn snapshot_delegated_em() -> VaultRolesSnapshot {
        VaultRolesSnapshot {
            manager: Some(DEPOSITOR.to_owned()),
            manager_redacted: Some(redact_strkey_first5_last5(DEPOSITOR)),
            emergency_manager: Some(THIRD_PARTY.to_owned()),
            emergency_manager_redacted: Some(redact_strkey_first5_last5(THIRD_PARTY)),
            rebalance_manager: Some(DEPOSITOR.to_owned()),
            rebalance_manager_redacted: Some(redact_strkey_first5_last5(DEPOSITOR)),
            vault_fee_receiver: Some(DEPOSITOR.to_owned()),
            vault_fee_receiver_redacted: Some(redact_strkey_first5_last5(DEPOSITOR)),
        }
    }

    fn snapshot_not_manager() -> VaultRolesSnapshot {
        VaultRolesSnapshot {
            manager: Some(THIRD_PARTY.to_owned()),
            manager_redacted: Some(redact_strkey_first5_last5(THIRD_PARTY)),
            emergency_manager: Some(THIRD_PARTY.to_owned()),
            emergency_manager_redacted: Some(redact_strkey_first5_last5(THIRD_PARTY)),
            rebalance_manager: Some(THIRD_PARTY.to_owned()),
            rebalance_manager_redacted: Some(redact_strkey_first5_last5(THIRD_PARTY)),
            vault_fee_receiver: Some(THIRD_PARTY.to_owned()),
            vault_fee_receiver_redacted: Some(redact_strkey_first5_last5(THIRD_PARTY)),
        }
    }

    // ── Self-managed detection ────────────────────────────────────────────────

    #[test]
    fn depositor_is_manager_all_same_returns_self_managed() {
        let snap = snapshot_self_managed();
        assert_eq!(
            snap.management_mode(DEPOSITOR),
            VaultManagementMode::SelfManaged
        );
    }

    #[test]
    fn depositor_is_manager_but_third_party_em_returns_delegated() {
        let snap = snapshot_delegated_em();
        assert_eq!(
            snap.management_mode(DEPOSITOR),
            VaultManagementMode::Delegated {
                third_party_emergency_manager: true,
                third_party_rebalance_manager: false,
            }
        );
    }

    #[test]
    fn depositor_is_not_manager_returns_not_manager() {
        let snap = snapshot_not_manager();
        assert_eq!(
            snap.management_mode(DEPOSITOR),
            VaultManagementMode::NotManager
        );
    }

    // ── Disclosure summary redacts addresses ─────────────────────────────────

    #[test]
    fn disclosure_summary_does_not_contain_full_address() {
        let snap = snapshot_self_managed();
        let summary = snap.disclosure_summary();
        assert!(
            !summary.contains(DEPOSITOR),
            "full address must not appear in disclosure summary: {summary}"
        );
        // First-5-last-5 of DEPOSITOR (CAJJZ...GXBD) should appear.
        assert!(
            summary.contains("CAJJZ"),
            "redacted prefix must appear: {summary}"
        );
    }
}
