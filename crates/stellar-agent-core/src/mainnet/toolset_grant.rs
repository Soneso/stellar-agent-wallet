//! The checked toolset grant facts a restricted mainnet payment binds.
//!
//! The toolsets runtime implements
//! [`ToolsetGrantEvidence`](crate::mainnet::toolset_grant::ToolsetGrantEvidence) for its grant
//! lease, which derives every fact from its checked invocation and token.
//! Implementing the trait is a trusted contract: an implementation must own
//! the coordination locks that keep its grant and installation unchanged
//! while it lives, and must never take a fact from handler arguments.

use crate::asset_id::{AssetIdError, CanonicalAsset};
use crate::mainnet::fact::FactDigest;

/// Label of the toolset restriction's fact digest.
pub const FACT_LABEL_TOOLSET_RESTRICTION: &[u8] =
    b"stellar-agent-authz-fact:toolset-restriction:v1";

/// The facts of one checked grant and the exact invocation it was leased for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolsetGrantFacts<'a> {
    /// The stored grant identifier.
    pub grant_id: &'a str,
    /// The grant's original expiry in Unix milliseconds; nothing renews it.
    pub expires_at_unix_ms: u64,
    /// The authenticated installation identifier.
    pub install_id: &'a str,
    /// The installed package version.
    pub package_version: &'a str,
    /// The installed package SHA-256, as lowercase hex.
    pub package_shasum: &'a str,
    /// The profile whose grant store holds the grant.
    pub profile_name: &'a str,
    /// The CAIP-2 chain the grant is attested for.
    pub chain_id: &'a str,
    /// The raw toolset name of the invocation.
    pub toolset_name: &'a str,
    /// The raw action name of the invocation.
    pub action: &'a str,
    /// The invocation's exact destination, including any muxed ID.
    pub destination: &'a str,
    /// The invocation's asset spelling.
    pub asset: &'a str,
    /// The invocation's amount in stroops.
    pub amount_stroops: i64,
}

impl ToolsetGrantFacts<'_> {
    /// The invocation's asset identity, with `XLM` and `native` one asset.
    ///
    /// # Errors
    /// Returns the asset parser's error for an unrecognized spelling.
    pub fn canonical_asset(&self) -> Result<CanonicalAsset, AssetIdError> {
        CanonicalAsset::parse_payment_asset(self.asset)
    }

    /// The fact digest under [`FACT_LABEL_TOOLSET_RESTRICTION`].
    ///
    /// Fields, in order: `lp` of the grant ID, `u64be` of the original
    /// expiry, `lp` of the install ID, version, and shasum, `lp` of the
    /// profile, chain, toolset, action, and destination, `lp` of the
    /// canonical asset's display form, and `i64be` of the amount. Equivalent
    /// asset spellings therefore give one digest.
    #[must_use]
    pub fn fact_digest(&self, asset: &CanonicalAsset) -> [u8; 32] {
        let mut digest = FactDigest::new(FACT_LABEL_TOOLSET_RESTRICTION);
        digest
            .bytes(self.grant_id.as_bytes())
            .u64(self.expires_at_unix_ms)
            .bytes(self.install_id.as_bytes())
            .bytes(self.package_version.as_bytes())
            .bytes(self.package_shasum.as_bytes())
            .bytes(self.profile_name.as_bytes())
            .bytes(self.chain_id.as_bytes())
            .bytes(self.toolset_name.as_bytes())
            .bytes(self.action.as_bytes())
            .bytes(self.destination.as_bytes())
            .bytes(asset.to_string().as_bytes())
            .i64(self.amount_stroops);
        digest.finish()
    }
}

/// Evidence of a live, checked toolset grant.
///
/// The value owns whatever keeps the grant and its installation unchanged
/// while it lives; dropping it releases them.
pub trait ToolsetGrantEvidence: Send + Sync {
    /// The facts the evidence was checked for.
    fn facts(&self) -> ToolsetGrantFacts<'_>;
}
