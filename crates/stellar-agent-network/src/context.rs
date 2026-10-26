//! Network identity shared by a command's transaction stages.

use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::{
    caip2::Caip2,
    schema::{Profile, ProviderRole},
};

use crate::client::StellarRpcClient;
use crate::redact_url_authority;
use crate::rpc_endpoint::{RpcCredentialBinding, rpc_client};

/// Test transport routes from an endpoint host to the URL its requests go to.
///
/// A route's host and an endpoint's host compare as
/// [`stellar_agent_core::profile::schema::same_provider_host`] compares them,
/// so the letter case of a host and one trailing dot do not distinguish a
/// route. A client built through a route keeps the endpoint URL as its
/// identity and carries no credential; an endpoint whose host has no route
/// builds the ordinary client.
#[cfg(any(test, feature = "test-hooks"))]
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct TestTransportRoutes(Vec<(String, String)>);

#[cfg(any(test, feature = "test-hooks"))]
impl TestTransportRoutes {
    /// Routes for `(host, transport URL)` pairs.
    #[cfg_attr(
        not(any(test, feature = "mainnet-write")),
        expect(
            dead_code,
            reason = "routes are installed through the mainnet write context"
        )
    )]
    pub(crate) fn new(routes: &[(&str, &str)]) -> Self {
        Self(
            routes
                .iter()
                .map(|(host, transport)| (format!("https://{host}/"), (*transport).to_owned()))
                .collect(),
        )
    }

    /// The transport URL of the route for the host of `endpoint`.
    pub(crate) fn transport_for(&self, endpoint: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(host_url, _)| {
                stellar_agent_core::profile::schema::same_provider_host(endpoint, host_url)
            })
            .map(|(_, transport)| transport.as_str())
    }

    /// The routed client for `endpoint`, or `None` when its host has no
    /// route.
    pub(crate) fn client(&self, endpoint: &str) -> Option<Result<StellarRpcClient, WalletError>> {
        self.transport_for(endpoint)
            .map(|transport| StellarRpcClient::with_test_transport(endpoint, transport))
    }
}

#[cfg(any(test, feature = "test-hooks"))]
impl std::fmt::Debug for TestTransportRoutes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(host_url, transport)| {
                (
                    redact_url_authority(host_url),
                    redact_url_authority(transport),
                )
            }))
            .finish()
    }
}

/// The network identity resolved once at command entry and passed to stages
/// that build, simulate, sign, or submit.
///
/// `stellar_agent_smart_account::signing::divergence::NetworkContext` is an
/// unrelated type that carries divergence fingerprints.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkContext {
    #[cfg(any(test, feature = "test-hooks"))]
    test_transport_routes: TestTransportRoutes,
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
            #[cfg(any(test, feature = "test-hooks"))]
            test_transport_routes: TestTransportRoutes::default(),
        }
    }

    /// The test transport routes every client this context builds consults.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn test_transport_routes(&self) -> &TestTransportRoutes {
        &self.test_transport_routes
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
        #[cfg(any(test, feature = "test-hooks"))]
        if let Some(client) = self.test_transport_routes.client(&self.rpc_url) {
            return client;
        }
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

/// Endpoint flags supplied at a mainnet command boundary.
#[derive(Debug, Default, Clone, Copy)]
pub struct MainnetEndpointFlags {
    /// An explicit chain selection, which must name mainnet.
    pub network: Option<Caip2>,
    /// Whether the primary URL was overridden.
    pub rpc_url: bool,
    /// Whether the secondary URL was overridden.
    pub secondary_rpc_url: bool,
}

/// A validated, overlay-free mainnet profile selected by an explicit flag.
pub struct MainnetWriteContext {
    #[cfg(feature = "mainnet-write")]
    profile_name: String,
    #[cfg(feature = "mainnet-write")]
    snapshot: Profile,
    #[cfg(feature = "mainnet-write")]
    authority: String,
    #[cfg(feature = "mainnet-write")]
    primary_credential: Option<RpcCredentialBinding>,
    #[cfg(all(feature = "mainnet-write", any(test, feature = "test-hooks")))]
    test_transport_routes: TestTransportRoutes,
    #[cfg(not(feature = "mainnet-write"))]
    never: Never,
}

#[cfg(not(feature = "mainnet-write"))]
enum Never {}

impl NetworkContext {
    /// Loads the stored mainnet profile after validating its explicit selection.
    ///
    /// # Errors
    /// Returns `network.mainnet_write_forbidden` for a refused selection or
    /// disabled feature, and the profile loader error for an unreadable profile.
    pub fn mainnet_write(
        merged: &Profile,
        resolved: &stellar_agent_core::profile::name::ResolvedProfileName,
        profiles_dir: &std::path::Path,
        flags: MainnetEndpointFlags,
    ) -> Result<MainnetWriteContext, WalletError> {
        #[cfg(feature = "mainnet-write")]
        {
            MainnetWriteContext::build(merged, resolved, profiles_dir, flags).map_err(|error| {
                match error {
                    crate::mainnet::refusal::AuthorizedPathError::Refused(precondition) => {
                        tracing::warn!(
                            path = "mainnet_write_context",
                            precondition = precondition.label(),
                            "mainnet write context refused"
                        );
                        stellar_agent_core::error::NetworkError::MainnetWriteForbidden.into()
                    }
                    crate::mainnet::refusal::AuthorizedPathError::Wallet(error) => error,
                }
            })
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            let _ = (merged, resolved, profiles_dir, flags);
            Err(stellar_agent_core::error::NetworkError::MainnetWriteForbidden.into())
        }
    }
}

impl MainnetWriteContext {
    #[cfg(feature = "mainnet-write")]
    pub(crate) fn build(
        merged: &Profile,
        resolved: &stellar_agent_core::profile::name::ResolvedProfileName,
        profiles_dir: &std::path::Path,
        flags: MainnetEndpointFlags,
    ) -> Result<Self, crate::mainnet::refusal::AuthorizedPathError> {
        use crate::mainnet::refusal::{MainnetPrecondition as P, require};
        use stellar_agent_core::error::ValidationError;
        use stellar_agent_core::profile::{
            loader::{ProfileLoadError, load_from_dir_without_overlays},
            name::{ProfileNameSource, profile_name_mismatch_refusal},
        };
        require(
            resolved.source == ProfileNameSource::Flag,
            P::NameSourceNotFlag,
        )?;
        require(resolved.name != "default", P::DefaultProfile)?;
        require(
            !flags.rpc_url
                && !flags.secondary_rpc_url
                && flags.network.is_none_or(Caip2::is_mainnet),
            P::EndpointFlagRefused,
        )?;
        let snapshot = load_from_dir_without_overlays(&resolved.name, profiles_dir, None).map_err(
            |error| match error {
                ProfileLoadError::NotFound { name, .. } => {
                    WalletError::Validation(ValidationError::ProfileNotFound { name })
                }
                other => WalletError::Validation(ValidationError::ConfigInvalid {
                    component: "profile",
                    reason: stellar_agent_core::observability::redact_path_in_message(&format!(
                        "the stored profile cannot be read: {other}"
                    )),
                }),
            },
        )?;
        require(snapshot.chain_id.is_mainnet(), P::ChainNotMainnet)?;
        require(
            profile_name_mismatch_refusal(&snapshot, &resolved.name).is_none(),
            P::DerivedNameMismatch,
        )?;
        require(
            merged.chain_id == snapshot.chain_id && merged.rpc_url == snapshot.rpc_url,
            P::DiskViewMismatch,
        )?;
        Ok(Self {
            profile_name: resolved.name.clone(),
            authority: redact_url_authority(&snapshot.rpc_url),
            primary_credential: RpcCredentialBinding::for_role(&snapshot, ProviderRole::Primary),
            snapshot,
            #[cfg(any(test, feature = "test-hooks"))]
            test_transport_routes: TestTransportRoutes::default(),
        })
    }

    #[cfg(not(feature = "mainnet-write"))]
    pub(crate) fn absurd(&self) -> ! {
        match self.never {}
    }

    /// The explicitly selected profile name.
    #[must_use]
    pub fn profile_name(&self) -> &str {
        #[cfg(feature = "mainnet-write")]
        {
            &self.profile_name
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            self.absurd()
        }
    }

    /// The validated chain identity.
    #[must_use]
    pub fn chain(&self) -> Caip2 {
        #[cfg(feature = "mainnet-write")]
        {
            self.snapshot.chain_id
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            self.absurd()
        }
    }

    /// The stored endpoint authority, with credentials and paths removed.
    #[must_use]
    pub fn authority(&self) -> &str {
        #[cfg(feature = "mainnet-write")]
        {
            &self.authority
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            self.absurd()
        }
    }

    /// The canonical network passphrase.
    #[must_use]
    pub fn network_passphrase(&self) -> &'static str {
        self.chain().network_passphrase()
    }

    /// The validated stored profile, without environment overlays.
    #[must_use]
    pub fn profile(&self) -> &Profile {
        #[cfg(feature = "mainnet-write")]
        {
            &self.snapshot
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            self.absurd()
        }
    }

    #[cfg_attr(
        not(feature = "mainnet-write"),
        expect(dead_code, reason = "uninhabited without mainnet writes")
    )]
    pub(crate) fn signer_coordinate(
        &self,
    ) -> &stellar_agent_core::profile::schema::KeyringEntryRef {
        &self.profile().mcp_signer_default
    }

    /// Builds a fresh primary client with the stored credential binding.
    ///
    /// # Errors
    /// Returns the RPC client or keyring error when construction fails.
    pub fn primary_client(&self) -> Result<StellarRpcClient, WalletError> {
        #[cfg(feature = "mainnet-write")]
        {
            #[cfg(any(test, feature = "test-hooks"))]
            if let Some(client) = self.test_transport_routes.client(&self.snapshot.rpc_url) {
                return client;
            }
            rpc_client(&self.snapshot.rpc_url, self.primary_credential.as_ref())
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            self.absurd()
        }
    }

    /// The network identity of the stored profile for stages that take a
    /// [`NetworkContext`], such as the bound witness producers.
    ///
    /// The chain, both endpoints and the primary credential binding are the
    /// snapshot's, and every client the returned context builds, the oracle
    /// client of a witness included, is built as this context builds its own.
    #[must_use]
    pub fn network_context(&self) -> NetworkContext {
        #[cfg(feature = "mainnet-write")]
        {
            let network = NetworkContext::from_profile(&self.snapshot);
            #[cfg(any(test, feature = "test-hooks"))]
            let network = NetworkContext {
                test_transport_routes: self.test_transport_routes.clone(),
                ..network
            };
            network
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            self.absurd()
        }
    }

    /// Routes the requests of every client this context builds by endpoint
    /// host, `routes` pairing a host with the transport URL its requests go
    /// to, while each client keeps the profile's endpoint URL as its
    /// identity. A host without a route builds the ordinary client.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    #[must_use]
    pub fn with_test_transport_routes(self, routes: &[(&str, &str)]) -> Self {
        #[cfg(feature = "mainnet-write")]
        {
            Self {
                test_transport_routes: TestTransportRoutes::new(routes),
                ..self
            }
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            let _ = routes;
            self.absurd()
        }
    }
}

impl std::fmt::Debug for MainnetWriteContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(feature = "mainnet-write")]
        {
            let mut debug = f.debug_struct("MainnetWriteContext");
            debug
                .field("profile_name", &self.profile_name)
                .field("chain", &self.chain())
                .field("authority", &self.authority);
            #[cfg(any(test, feature = "test-hooks"))]
            debug.field("test_transport_routes", &self.test_transport_routes);
            debug.finish_non_exhaustive()
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            let _ = f;
            self.absurd()
        }
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
    fn stored_context_profile() -> (
        tempfile::TempDir,
        Profile,
        stellar_agent_core::profile::name::ResolvedProfileName,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut profile = Profile::builder_mainnet_named(
            "context",
            "https://rpc.example.invalid",
            "signer",
            "key",
            "nonce",
            "key",
        )
        .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        stellar_agent_core::profile::loader::save_to_dir("context", &profile, dir.path()).unwrap();
        (
            dir,
            profile,
            stellar_agent_core::profile::name::ResolvedProfileName::from_flag("context"),
        )
    }

    #[test]
    fn mainnet_write_refuses_without_reading_inputs() {
        let (dir, profile, resolved) = stored_context_profile();
        let error = NetworkContext::mainnet_write(
            &profile,
            &resolved,
            &dir.path().join("absent"),
            MainnetEndpointFlags::default(),
        )
        .unwrap_err();
        #[cfg(not(feature = "mainnet-write"))]
        assert_eq!(error.code(), "network.mainnet_write_forbidden");
        #[cfg(feature = "mainnet-write")]
        assert_eq!(error.code(), "validation.profile_not_found");
    }

    #[cfg(feature = "mainnet-write")]
    fn refusal(
        profile: &Profile,
        resolved: &stellar_agent_core::profile::name::ResolvedProfileName,
        dir: &std::path::Path,
        flags: MainnetEndpointFlags,
    ) -> crate::mainnet::MainnetPrecondition {
        match MainnetWriteContext::build(profile, resolved, dir, flags).unwrap_err() {
            crate::mainnet::refusal::AuthorizedPathError::Refused(p) => p,
            error => unreachable!("{error:?}"),
        }
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    fn context_accepts_flag_named_mainnet_profile() {
        let (dir, profile, resolved) = stored_context_profile();
        let context = NetworkContext::mainnet_write(
            &profile,
            &resolved,
            dir.path(),
            MainnetEndpointFlags {
                network: Some(Caip2::Mainnet),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(context.profile_name(), "context");
        assert_eq!(context.chain(), Caip2::Mainnet);
        assert_eq!(context.authority(), "https://rpc.example.invalid");
        assert_eq!(context.profile().rpc_url, profile.rpc_url);
        assert_eq!(context.signer_coordinate(), &profile.mcp_signer_default);
        assert_eq!(context.network_passphrase(), MAINNET_PASSPHRASE);
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    fn context_refuses_env_and_default_sources() {
        use stellar_agent_core::profile::name::ProfileNameSource;
        let (dir, profile, mut resolved) = stored_context_profile();
        for source in [ProfileNameSource::Env, ProfileNameSource::Default] {
            resolved.source = source;
            assert_eq!(
                refusal(
                    &profile,
                    &resolved,
                    dir.path(),
                    MainnetEndpointFlags::default()
                ),
                crate::mainnet::MainnetPrecondition::NameSourceNotFlag
            );
        }
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    fn context_refuses_default_name() {
        let (dir, profile, mut resolved) = stored_context_profile();
        resolved.name = "default".into();
        assert_eq!(
            refusal(
                &profile,
                &resolved,
                dir.path(),
                MainnetEndpointFlags::default()
            ),
            crate::mainnet::MainnetPrecondition::DefaultProfile
        );
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    fn context_refuses_endpoint_flags() {
        let (dir, profile, resolved) = stored_context_profile();
        for flags in [
            MainnetEndpointFlags {
                network: Some(Caip2::Testnet),
                ..Default::default()
            },
            MainnetEndpointFlags {
                rpc_url: true,
                ..Default::default()
            },
            MainnetEndpointFlags {
                secondary_rpc_url: true,
                ..Default::default()
            },
        ] {
            assert_eq!(
                refusal(&profile, &resolved, dir.path(), flags),
                crate::mainnet::MainnetPrecondition::EndpointFlagRefused
            );
        }
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    fn context_refuses_merged_view_differing_from_disk() {
        let (dir, profile, resolved) = stored_context_profile();
        let mut merged = profile.clone();
        merged.rpc_url = "https://other.invalid".into();
        assert_eq!(
            refusal(
                &merged,
                &resolved,
                dir.path(),
                MainnetEndpointFlags::default()
            ),
            crate::mainnet::MainnetPrecondition::DiskViewMismatch
        );
        merged = profile;
        merged.chain_id = Caip2::Testnet;
        assert_eq!(
            refusal(
                &merged,
                &resolved,
                dir.path(),
                MainnetEndpointFlags::default()
            ),
            crate::mainnet::MainnetPrecondition::DiskViewMismatch
        );
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    fn context_refuses_testnet_snapshot() {
        let (dir, _, resolved) = stored_context_profile();
        let profile = Profile::builder_testnet_named("context", "s", "a", "n", "a").build();
        stellar_agent_core::profile::loader::save_to_dir("context", &profile, dir.path()).unwrap();
        assert_eq!(
            refusal(
                &profile,
                &resolved,
                dir.path(),
                MainnetEndpointFlags::default()
            ),
            crate::mainnet::MainnetPrecondition::ChainNotMainnet
        );
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    fn context_refuses_derived_name_mismatch() {
        let (dir, mut profile, resolved) = stored_context_profile();
        profile.policy_owner_key_id =
            stellar_agent_core::profile::schema::KeyringEntryRef::default_owner_key("other");
        stellar_agent_core::profile::loader::save_to_dir("context", &profile, dir.path()).unwrap();
        assert_eq!(
            refusal(
                &profile,
                &resolved,
                dir.path(),
                MainnetEndpointFlags::default()
            ),
            crate::mainnet::MainnetPrecondition::DerivedNameMismatch
        );
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    async fn network_context_routes_the_primary() {
        use stellar_agent_test_support::{EchoIdResponder, signed_envelope::get_network_result};
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::body_partial_json(
            serde_json::json!({"method": "getNetwork"}),
        ))
        .respond_with(EchoIdResponder::new(get_network_result(MAINNET_PASSPHRASE)))
        .mount(&server)
        .await;
        let (dir, profile, resolved) = stored_context_profile();
        let context =
            NetworkContext::mainnet_write(&profile, &resolved, dir.path(), Default::default())
                .unwrap()
                .with_test_transport_routes(&[("rpc.example.invalid", &server.uri())]);
        let network = context.network_context();
        assert_eq!(network.rpc_url, "https://rpc.example.invalid");
        let client = network.primary_client().unwrap();
        assert_eq!(client.url(), "https://rpc.example.invalid");
        assert_eq!(client.transport_base_url(), format!("{}/", server.uri()));
        let identity = client
            .mainnet_endpoint_identity(
                tokio::time::Instant::now() + std::time::Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(identity.authority(), context.authority());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    fn unmapped_host_uses_the_profile_endpoint() {
        let (dir, profile, resolved) = stored_context_profile();
        let context =
            NetworkContext::mainnet_write(&profile, &resolved, dir.path(), Default::default())
                .unwrap()
                .with_test_transport_routes(&[("other.example.invalid", "http://127.0.0.1:9")]);
        for client in [
            context.primary_client().unwrap(),
            context.network_context().primary_client().unwrap(),
        ] {
            assert_eq!(client.url(), "https://rpc.example.invalid");
            assert_eq!(
                client.transport_base_url(),
                "https://rpc.example.invalid:443/"
            );
        }
    }

    #[test]
    fn route_host_ignores_case_and_one_trailing_dot() {
        for (endpoint, route) in [
            ("https://RPC.Example.Invalid./", "rpc.example.invalid"),
            ("https://rpc.example.invalid", "RPC.EXAMPLE.INVALID."),
        ] {
            let context = NetworkContext {
                test_transport_routes: TestTransportRoutes::new(&[(route, "http://127.0.0.1:9")]),
                ..NetworkContext::new(Caip2::Mainnet, endpoint.to_owned())
            };
            let client = context.primary_client().unwrap();
            assert_eq!(client.url(), endpoint);
            assert_eq!(client.transport_base_url(), "http://127.0.0.1:9/");
        }
        let context = NetworkContext {
            test_transport_routes: TestTransportRoutes::new(&[(
                "rpc.example.invalid",
                "http://127.0.0.1:9",
            )]),
            ..NetworkContext::new(
                Caip2::Mainnet,
                "https://rpc.example.invalid.evil/".to_owned(),
            )
        };
        assert_eq!(
            context.primary_client().unwrap().transport_base_url(),
            "https://rpc.example.invalid.evil:443/"
        );
    }
}
