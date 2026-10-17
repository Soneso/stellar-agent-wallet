//! Network identity shared by a command's transaction stages.

use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::{
    caip2::Caip2,
    schema::{Profile, ProviderRole},
};

use crate::client::StellarRpcClient;
use crate::redact_url_authority;
use crate::rpc_endpoint::{RpcCredentialBinding, rpc_client};

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
    /// The keyring credential the profile configures for its primary
    /// endpoint, bound to the profile's `rpc_url`.
    primary_credential: Option<RpcCredentialBinding>,
}

impl NetworkContext {
    /// Copies the chain identity and both endpoints from the profile, and
    /// binds the credential its primary provider record names, if any.
    #[must_use]
    pub fn from_profile(profile: &Profile) -> Self {
        let mut context = Self::new(profile.chain_id, profile.rpc_url.clone())
            .with_secondary(profile.secondary_rpc_url.clone());
        context.primary_credential = RpcCredentialBinding::for_role(profile, ProviderRole::Primary);
        context
    }

    /// A context from its chain identity and primary endpoint; the secondary
    /// endpoint starts unset and no credential is bound.
    #[must_use]
    pub fn new(chain_id: Caip2, rpc_url: String) -> Self {
        Self {
            chain_id,
            rpc_url,
            secondary_rpc_url: None,
            primary_credential: None,
        }
    }

    /// Builds the client for the primary endpoint, [`Self::rpc_url`].
    ///
    /// The client carries the profile's primary credential only while
    /// `rpc_url` still equals the profile's `rpc_url` byte for byte; a
    /// command that overrode the endpoint gets a client without one, and no
    /// keyring entry is opened.
    ///
    /// # Errors
    ///
    /// The errors of [`crate::profile_rpc_client`]: a keyring code such as
    /// `auth.keyring_not_found`, `network.rpc_credential_refused` for a
    /// stored value the wallet refuses or a credential the client cannot
    /// send, and `network.rpc_unreachable` when the transport refuses the
    /// URL.
    pub fn primary_client(&self) -> Result<StellarRpcClient, WalletError> {
        rpc_client(&self.rpc_url, self.primary_credential.as_ref())
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
            .field("primary_credential", &self.primary_credential)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test-only; unwraps are acceptable in unit tests"
    )]

    use super::*;
    use stellar_agent_core::profile::caip2::{MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};

    fn profile(chain: Caip2) -> Profile {
        let primary = "https://primary.example";
        let builder = if chain.is_mainnet() {
            Profile::builder_mainnet_named("context", primary, "s", "a", "n", "a")
        } else {
            Profile::builder_testnet_named("context", "s", "a", "n", "a").rpc_url(primary)
        };
        let mut profile = builder.build();
        profile.secondary_rpc_url = Some("https://profile-secondary.example".to_owned());
        profile
    }

    #[test]
    fn from_profile_copies_identity_and_secondary() {
        for chain in [Caip2::Testnet, Caip2::Mainnet] {
            let mut profile = profile(chain);
            let context = NetworkContext::from_profile(&profile);
            assert_eq!(context.chain_id, chain);
            assert_eq!(context.rpc_url, profile.rpc_url);
            assert_eq!(context.secondary_rpc_url, profile.secondary_rpc_url);
            profile.secondary_rpc_url = None;
            assert_eq!(
                NetworkContext::from_profile(&profile).secondary_rpc_url,
                None
            );
        }
    }

    /// The primary credential of the profile binds to its `rpc_url`; a
    /// context from `new` and a profile without a record bind none.
    #[test]
    fn from_profile_binds_the_primary_credential() {
        use stellar_agent_core::profile::schema::{
            KeyringEntryRef, PrimaryProviderRecord, RpcCredentialPlacement,
        };
        let entry = KeyringEntryRef::new("stellar-agent-rpc-context", "primary");
        for chain in [Caip2::Testnet, Caip2::Mainnet] {
            let mut profile = profile(chain);
            assert_eq!(
                NetworkContext::from_profile(&profile).primary_credential,
                None
            );
            profile.providers = Some(stellar_agent_core::profile::schema::Providers::default());
            profile.providers.as_mut().unwrap().primary = Some(
                PrimaryProviderRecord::new("Primary", "primary.example")
                    .with_credential(entry.clone(), RpcCredentialPlacement::Path {}),
            );
            let context = NetworkContext::from_profile(&profile);
            let binding = context.primary_credential.as_ref().unwrap();
            assert_eq!(binding.url, profile.rpc_url);
            assert_eq!(binding.entry, entry);
            assert_eq!(binding.placement, RpcCredentialPlacement::Path {});
            assert!(format!("{context:?}").contains("stellar-agent-rpc-context"));
        }
        assert_eq!(
            NetworkContext::new(Caip2::Testnet, "https://primary.example".to_owned())
                .primary_credential,
            None
        );
    }

    #[test]
    fn new_copies_identity_without_secondary() {
        let context = NetworkContext::new(Caip2::Mainnet, "https://flags.example".to_owned());
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
        let context = NetworkContext::new(Caip2::Testnet,
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
