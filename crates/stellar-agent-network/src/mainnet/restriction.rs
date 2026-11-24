//! The toolset restriction a classic mainnet payment resolution binds.

use super::refusal::require;
use super::{MainnetAuthorizationError, MainnetPrecondition as P};
use stellar_agent_core::mainnet::toolset_grant::{ToolsetGrantEvidence, ToolsetGrantFacts};

/// Live toolset grant evidence restricting one classic mainnet payment.
///
/// The restriction owns its evidence, so the evidence's locks live as long
/// as the restriction does: through nonce verification and resolution, then
/// inside the minted authorization until submission starts, and then in the
/// submission's scope until it returns after the outcome.
pub struct ToolsetRestriction {
    evidence: Box<dyn ToolsetGrantEvidence>,
}

impl std::fmt::Debug for ToolsetRestriction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolsetRestriction")
            .field("grant_id", &self.facts().grant_id)
            .finish_non_exhaustive()
    }
}

impl ToolsetRestriction {
    /// Takes ownership of checked grant evidence.
    #[must_use]
    pub fn new(evidence: Box<dyn ToolsetGrantEvidence>) -> Self {
        Self { evidence }
    }

    /// The facts the evidence was checked for.
    #[must_use]
    pub fn facts(&self) -> ToolsetGrantFacts<'_> {
        self.evidence.facts()
    }

    /// Requires the grant's original end to lie after `now_ms`.
    ///
    /// # Errors
    /// [`MainnetPrecondition::ToolsetGrantExpired`](P::ToolsetGrantExpired)
    /// at or after the end.
    pub fn check_unexpired(&self, now_ms: u64) -> Result<(), MainnetAuthorizationError> {
        require(
            now_ms < self.facts().expires_at_unix_ms,
            P::ToolsetGrantExpired,
        )
    }

    /// Binds the restriction to the resolution's context, consumer, and
    /// authoritative payment arguments at `now_ms`.
    ///
    /// The consumer must be the MCP payment commit and the action
    /// `stellar_pay_commit`. Profile and chain equal the context, the
    /// destination equals the decoded destination exactly, the asset equals
    /// it canonically, and the amount equals it. The grant must not have
    /// expired. `detail` receives the escaped raw toolset and action.
    #[cfg(feature = "mainnet-write")]
    pub(crate) fn bind(
        &self,
        context: &crate::MainnetWriteContext,
        consumer: super::MainnetConsumer,
        args: &serde_json::Value,
        now_ms: u64,
        detail: &mut Option<String>,
    ) -> Result<RestrictionBinding, MainnetAuthorizationError> {
        use stellar_agent_core::asset_id::CanonicalAsset;
        use stellar_agent_core::profile::caip2::Caip2;
        let facts = self.facts();
        *detail = Some(format!(
            "toolset \"{}\" action \"{}\"",
            facts.toolset_name.escape_debug(),
            facts.action.escape_debug()
        ));
        require(
            consumer == super::MainnetConsumer::McpPay && facts.action == "stellar_pay_commit",
            P::ToolsetRestrictionConsumer,
        )?;
        let asset = facts
            .canonical_asset()
            .map_err(|_| MainnetAuthorizationError::Refused(P::ToolsetRestrictionMismatch))?;
        require(
            facts.profile_name == context.profile_name()
                && facts.chain_id.parse::<Caip2>().ok() == Some(context.chain())
                && args["destination"].as_str() == Some(facts.destination)
                && args["asset"]
                    .as_str()
                    .and_then(|text| CanonicalAsset::parse_payment_asset(text).ok())
                    .as_ref()
                    == Some(&asset)
                && args["amount_stroops"]
                    .as_str()
                    .and_then(|amount| amount.parse::<i64>().ok())
                    == Some(facts.amount_stroops),
            P::ToolsetRestrictionMismatch,
        )?;
        self.check_unexpired(now_ms)?;
        Ok(RestrictionBinding {
            fact_digest: facts.fact_digest(&asset),
            end_ms: facts.expires_at_unix_ms,
        })
    }
}

#[cfg(all(test, feature = "mainnet-write"))]
#[path = "restriction_tests.rs"]
pub(crate) mod tests;

/// What a bound restriction adds to the mint it restricts.
#[cfg(feature = "mainnet-write")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct RestrictionBinding {
    /// The restriction's fact digest, for the bindings digest.
    pub(crate) fact_digest: [u8; 32],
    /// The grant's original end, which bounds the authorization.
    pub(crate) end_ms: u64,
}
