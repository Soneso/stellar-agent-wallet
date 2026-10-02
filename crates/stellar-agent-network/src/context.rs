//! Network identity shared by a command's transaction stages.

use stellar_agent_core::profile::{caip2::Caip2, schema::Profile};

use crate::redact_url_authority;

/// The network identity resolved once at command entry and passed to stages
/// that build, simulate, sign, or submit.
///
/// `stellar_agent_smart_account::signing::divergence::NetworkContext` is an
/// unrelated type that carries divergence fingerprints.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkContext {
    /// The resolved CAIP-2 chain identity.
    pub chain_id: Caip2,
    /// The primary RPC endpoint.
    pub rpc_url: String,
    /// The secondary RPC endpoint selected by the command.
    pub secondary_rpc_url: Option<String>,
}

impl NetworkContext {
    /// Copies the chain identity and primary endpoint from the profile.
    /// The secondary endpoint starts unset.
    #[must_use]
    pub fn from_profile(profile: &Profile) -> Self {
        Self::from_flags(profile.chain_id, profile.rpc_url.clone())
    }

    /// Takes the chain identity and primary endpoint from command flags.
    /// The secondary endpoint starts unset.
    #[must_use]
    pub fn from_flags(chain_id: Caip2, rpc_url: String) -> Self {
        Self {
            chain_id,
            rpc_url,
            secondary_rpc_url: None,
        }
    }

    /// Sets or clears the secondary endpoint selected by the command.
    #[must_use]
    pub fn with_secondary(mut self, secondary_rpc_url: Option<String>) -> Self {
        self.secondary_rpc_url = secondary_rpc_url;
        self
    }

    /// Returns the canonical passphrase derived from the chain identity.
    #[must_use]
    pub fn network_passphrase(&self) -> &'static str {
        self.chain_id.network_passphrase()
    }
}

impl std::fmt::Debug for NetworkContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkContext")
            .field("chain_id", &self.chain_id)
            .field("rpc_url", &redact_url_authority(&self.rpc_url))
            .field(
                "secondary_rpc_url",
                &self.secondary_rpc_url.as_deref().map(redact_url_authority),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_agent_core::profile::caip2::{MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};

    fn profile(chain: Caip2) -> Profile {
        let builder = if chain.is_mainnet() {
            Profile::builder_mainnet_named("context", "s", "a", "n", "a")
        } else {
            Profile::builder_testnet_named("context", "s", "a", "n", "a")
        };
        let mut profile = builder.rpc_url("https://primary.example").build();
        profile.secondary_rpc_url = Some("https://profile-secondary.example".to_owned());
        profile
    }

    #[test]
    fn from_profile_copies_identity_without_secondary() {
        for chain in [Caip2::Testnet, Caip2::Mainnet] {
            let profile = profile(chain);
            let context = NetworkContext::from_profile(&profile);
            assert_eq!(context.chain_id, chain);
            assert_eq!(context.rpc_url, profile.rpc_url);
            assert_eq!(context.secondary_rpc_url, None);
        }
    }

    #[test]
    fn from_flags_copies_identity_without_secondary() {
        let context =
            NetworkContext::from_flags(Caip2::Mainnet, "https://flags.example".to_owned());
        assert_eq!(context.chain_id, Caip2::Mainnet);
        assert_eq!(context.rpc_url, "https://flags.example");
        assert_eq!(context.secondary_rpc_url, None);
    }

    #[test]
    fn with_secondary_sets_and_clears_command_endpoint() {
        let context = NetworkContext::from_profile(&profile(Caip2::Testnet))
            .with_secondary(Some("https://command-secondary.example".to_owned()));
        assert_eq!(
            context.secondary_rpc_url.as_deref(),
            Some("https://command-secondary.example")
        );
        assert_eq!(context.with_secondary(None).secondary_rpc_url, None);
    }

    #[test]
    fn testnet_passphrase_is_canonical() {
        assert_eq!(
            NetworkContext::from_profile(&profile(Caip2::Testnet)).network_passphrase(),
            TESTNET_PASSPHRASE
        );
    }

    #[test]
    fn mainnet_passphrase_is_derived_from_chain() {
        let mut profile = profile(Caip2::Mainnet);
        profile.network_passphrase = "not the passphrase".to_owned();
        assert_eq!(
            NetworkContext::from_profile(&profile).network_passphrase(),
            MAINNET_PASSPHRASE
        );
    }

    #[test]
    fn debug_redacts_both_urls() {
        let context = NetworkContext::from_flags(Caip2::Testnet,
            "https://PRIMARY-USER:PRIMARY-PASS@primary.example/PRIMARY-PATH?key=PRIMARY-QUERY".to_owned())
            .with_secondary(Some("https://SECONDARY-USER:SECONDARY-PASS@secondary.example/SECONDARY-PATH?key=SECONDARY-QUERY".to_owned()));
        let debug = format!("{context:?}");
        for sentinel in [
            "PRIMARY-USER",
            "PRIMARY-PASS",
            "PRIMARY-PATH",
            "PRIMARY-QUERY",
            "SECONDARY-USER",
            "SECONDARY-PASS",
            "SECONDARY-PATH",
            "SECONDARY-QUERY",
        ] {
            assert!(
                !debug.contains(sentinel),
                "Debug leaked {sentinel}: {debug}"
            );
        }
        assert!(debug.contains("https://primary.example"));
        assert!(debug.contains("https://secondary.example"));
    }
}
