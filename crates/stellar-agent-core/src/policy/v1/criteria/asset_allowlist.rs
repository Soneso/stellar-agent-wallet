//! Restricts value legs to explicitly pinned asset identities.

use super::Criterion;
use crate::policy::v1::{
    EvalContext,
    asset_equivalence::{assets_equivalent, pinned_asset},
    value::{ActionKind, ValueGate, classify_value},
};
use crate::policy::{DenyReason, PolicyError};

/// An allowlist of native, classic issuer-pinned, or contract assets.
#[derive(Debug, Clone)]
pub struct AssetAllowlistCriterion {
    assets: Vec<String>,
}

impl AssetAllowlistCriterion {
    /// Builds an allowlist of pinned identities.
    ///
    /// # Errors
    /// Refuses empty lists or an entry without a pinned identity.
    pub fn new(assets: Vec<String>) -> Result<Self, PolicyError> {
        if assets.is_empty() || assets.iter().any(|asset| pinned_asset(asset).is_err()) {
            return Err(PolicyError::PolicyFileParseFailed {
                detail: "asset_allowlist requires nonempty pinned assets".into(),
            });
        }
        Ok(Self { assets })
    }
}

impl Criterion for AssetAllowlistCriterion {
    fn kind(&self) -> &'static str {
        "asset_allowlist"
    }

    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let effects = match classify_value(ctx) {
            ValueGate::NotApplicable => return Ok(None),
            ValueGate::Deny(reason) => return Ok(Some(reason)),
            ValueGate::Effects(effects) => effects,
        };
        for leg in effects.legs() {
            let Some(asset) = leg.asset.as_deref() else {
                // A trustline leg without an asset is a liquidity pool share,
                // which no allowlist entry can name.
                if leg.kind == ActionKind::Trustline {
                    return Ok(Some(DenyReason::AssetNotAllowlisted));
                }
                continue;
            };
            if !self
                .assets
                .iter()
                .any(|allowed| assets_equivalent(asset, allowed, &ctx.profile.network_passphrase))
            {
                return Ok(Some(DenyReason::AssetNotAllowlisted));
            }
        }
        Ok(None)
    }
}
