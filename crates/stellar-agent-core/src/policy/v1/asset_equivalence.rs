//! Asset identity shared by policy restrictions and accounting.

use super::value::asset_normalise;
use crate::asset_id::{AssetIdError, CanonicalAsset};

/// Parses an allowlist identity, including the explicit native spelling.
///
/// # Errors
/// Refuses unpinned codes, native aliases, and malformed addresses.
pub fn pinned_asset(value: &str) -> Result<CanonicalAsset, AssetIdError> {
    if value == "native" {
        Ok(CanonicalAsset::Native)
    } else {
        CanonicalAsset::parse_threshold_key(value)
    }
}

/// The identity that keys a total-budget allocation of `asset` on the network
/// of `network_passphrase`. Every spelling of one asset maps to one identity.
///
/// The native asset and its asset contract map to `native`. An issued asset
/// and its asset contract map to that contract's address. Any other contract
/// keeps its address, and an unparsable value keeps its normalised text.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::asset_id::CanonicalAsset;
/// use stellar_agent_core::policy::v1::asset_equivalence::total_budget_identity;
/// use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
///
/// let sac = CanonicalAsset::Native.sac_contract_id(TESTNET_PASSPHRASE).unwrap();
/// assert_eq!(total_budget_identity(&sac, TESTNET_PASSPHRASE), "native");
/// assert_eq!(total_budget_identity("XLM", TESTNET_PASSPHRASE), "native");
/// ```
#[must_use]
pub fn total_budget_identity(asset: &str, network_passphrase: &str) -> String {
    let normalised = asset_normalise(asset);
    match pinned_asset(&normalised) {
        Ok(CanonicalAsset::Native) => "native".to_owned(),
        Ok(classic @ CanonicalAsset::Classic { .. }) => classic
            .sac_contract_id(network_passphrase)
            .unwrap_or(normalised),
        Ok(CanonicalAsset::Contract(id)) => {
            if CanonicalAsset::Native
                .sac_contract_id(network_passphrase)
                .is_some_and(|native| native == id)
            {
                "native".to_owned()
            } else {
                id
            }
        }
        Err(_) => normalised,
    }
}

/// Compares native aliases, pinned identities, and their network-specific SACs.
#[must_use]
pub fn assets_equivalent(a: &str, b: &str, network_passphrase: &str) -> bool {
    let a = asset_normalise(a);
    let b = asset_normalise(b);
    if a == b {
        return true;
    }
    let (Ok(a), Ok(b)) = (pinned_asset(&a), pinned_asset(&b)) else {
        return false;
    };
    match (&a, &b) {
        (CanonicalAsset::Contract(id), _) => {
            b.sac_contract_id(network_passphrase).as_ref() == Some(id)
        }
        (_, CanonicalAsset::Contract(id)) => {
            a.sac_contract_id(network_passphrase).as_ref() == Some(id)
        }
        _ => false,
    }
}
