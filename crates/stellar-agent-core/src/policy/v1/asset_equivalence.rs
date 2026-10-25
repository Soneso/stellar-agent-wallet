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
