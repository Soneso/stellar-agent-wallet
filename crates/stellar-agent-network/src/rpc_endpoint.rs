//! Provider credentials of RPC clients built for a profile's endpoints.
//!
//! A profile's provider record for a role can name a keyring entry and a
//! placement for that role's endpoint. A binding pairs the role's endpoint
//! URL (`Profile::role_url`) with the credential its record names
//! (`Providers::credential`). A client built through this module carries
//! that credential only when the caller's URL equals the profile's URL for
//! the role byte for byte. The credential is read from the keyring when the
//! client is built. An overriding URL, such as a CLI flag or an agent's tool
//! input, therefore never receives the credential of the endpoint the profile
//! attests. Without a matching binding no keyring entry is opened.

use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, Profile, ProviderRole, RpcCredentialPlacement,
};

use crate::client::StellarRpcClient;
use crate::keyring::read_rpc_credential;
use crate::redact::redact_url_authority;

/// The keyring credential a profile configures for one role's endpoint.
///
/// Holds the role's endpoint URL as the profile states it, the keyring entry,
/// and the placement; never the credential value. `Debug` prints the URL as
/// scheme, host, and port only, because a URL may hold a key in its path or
/// query.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RpcCredentialBinding {
    /// The endpoint URL the credential belongs to.
    pub(crate) url: String,
    /// The keyring entry holding the credential.
    pub(crate) entry: KeyringEntryRef,
    /// Where requests carry the credential.
    pub(crate) placement: RpcCredentialPlacement,
}

impl RpcCredentialBinding {
    /// The binding of `role` in `profile`: the role's endpoint URL (`rpc_url`,
    /// `secondary_rpc_url`, or `oracle_provider_url`) with the credential its
    /// provider record names.
    ///
    /// Returns `None` when the role has no URL, no record, or a record
    /// without a credential.
    #[must_use]
    pub(crate) fn for_role(profile: &Profile, role: ProviderRole) -> Option<Self> {
        let url = profile.role_url(role)?;
        let (entry, placement) = profile.providers.as_ref()?.credential(role)?;
        Some(Self {
            url: url.to_owned(),
            entry: entry.clone(),
            placement: placement.clone(),
        })
    }
}

impl std::fmt::Debug for RpcCredentialBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcCredentialBinding")
            .field("url", &redact_url_authority(&self.url))
            .field("entry", &self.entry)
            .field("placement", &self.placement)
            .finish()
    }
}

/// Builds the RPC client for `url`.
///
/// When `binding` belongs to `url`, compared byte for byte, the credential
/// is read from the keyring and the client carries it
/// ([`StellarRpcClient::with_credential`]). Otherwise the client carries no
/// credential and no keyring entry is opened.
///
/// # Errors
///
/// - The keyring errors of [`read_rpc_credential`]: `auth.keyring_not_found`
///   naming `service/account`, the other keyring codes, and
///   [`NetworkError::RpcCredentialInvalid`].
/// - [`NetworkError::RpcCredentialUnusable`] when the credential cannot be
///   sent to the endpoint.
/// - [`NetworkError::RpcUnreachable`] when the transport refuses the URL.
///
/// [`is_credential_error`] tells the credential failures from the transport
/// failure.
pub(crate) fn rpc_client(
    url: &str,
    binding: Option<&RpcCredentialBinding>,
) -> Result<StellarRpcClient, WalletError> {
    match binding {
        Some(binding) if binding.url == url => {
            let value = read_rpc_credential(&binding.entry)?;
            StellarRpcClient::with_credential(url, &binding.placement, value)
        }
        _ => StellarRpcClient::new(url),
    }
}

/// Builds the RPC client for `url` with the credential `profile` configures
/// for `role`.
///
/// When `url` equals the role's URL in `profile` byte for byte and the role's
/// provider record names a credential, the credential is read from the
/// keyring and the client carries it
/// ([`StellarRpcClient::with_credential`]). Otherwise the client carries no
/// credential and no keyring entry is opened.
///
/// # Errors
///
/// - The keyring errors of [`read_rpc_credential`]: `auth.keyring_not_found`
///   naming `service/account`, the other keyring codes, and
///   [`NetworkError::RpcCredentialInvalid`].
/// - [`NetworkError::RpcCredentialUnusable`] when the credential cannot be
///   sent to the endpoint.
/// - [`NetworkError::RpcUnreachable`] when the transport refuses the URL.
///
/// [`is_credential_error`] tells the credential failures from the transport
/// failure.
pub fn profile_rpc_client(
    profile: &Profile,
    role: ProviderRole,
    url: &str,
) -> Result<StellarRpcClient, WalletError> {
    rpc_client(url, RpcCredentialBinding::for_role(profile, role).as_ref())
}

/// Whether a client construction failure concerns the credential rather
/// than the transport: a keyring failure, a stored value the wallet refuses,
/// or a credential the client cannot send.
///
/// Every transport construction failure is
/// [`NetworkError::RpcUnreachable`], so the split is exact.
#[must_use]
pub fn is_credential_error(error: &WalletError) -> bool {
    matches!(
        error,
        WalletError::Auth(_)
            | WalletError::Network(
                NetworkError::RpcCredentialInvalid { .. }
                    | NetworkError::RpcCredentialUnusable { .. }
            )
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use stellar_agent_core::profile::schema::{PrimaryProviderRecord, ProviderRecord};
    use stellar_agent_test_support::keyring_mock;

    use super::*;

    const PRIMARY: &str = "https://primary.example/rpc";

    struct RestoreStore(Option<Arc<keyring_core::CredentialStore>>);

    impl RestoreStore {
        fn new() -> Self {
            Self(keyring_core::unset_default_store())
        }
    }

    impl Drop for RestoreStore {
        fn drop(&mut self) {
            keyring_core::unset_default_store();
            if let Some(store) = self.0.take() {
                keyring_core::set_default_store(store);
            }
        }
    }

    fn entry(role: &str) -> KeyringEntryRef {
        KeyringEntryRef::new("stellar-agent-rpc-unit", role)
    }

    fn header() -> RpcCredentialPlacement {
        RpcCredentialPlacement::Header {
            name: "X-API-Key".to_owned(),
        }
    }

    fn profile() -> Profile {
        let mut profile = Profile::builder_testnet_named("unit", "s", "a", "n", "a")
            .rpc_url(PRIMARY)
            .oracle_provider_url(url::Url::parse("https://oracle.example").unwrap())
            .primary_provider(
                PrimaryProviderRecord::new("Primary", "primary.example")
                    .with_credential(entry("primary"), header()),
            )
            .secondary_provider(
                ProviderRecord::new("Secondary", "secondary.example", true)
                    .with_credential(entry("secondary"), RpcCredentialPlacement::Path {}),
            )
            .oracle_provider(
                ProviderRecord::new("Oracle", "oracle.example", true).with_credential(
                    entry("oracle"),
                    RpcCredentialPlacement::Query {
                        name: "apikey".to_owned(),
                    },
                ),
            )
            .build();
        profile.secondary_rpc_url = Some("https://secondary.example".to_owned());
        profile
    }

    /// Installs a mock store holding `value` at the primary entry, counting
    /// every read of that entry.
    fn counted_store(value: Option<&str>) -> Arc<AtomicUsize> {
        let reads = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reads);
        let primary = entry("primary");
        keyring_mock::install_with_read_hooks(vec![keyring_mock::ReadHook::new(
            &primary.service,
            &primary.account,
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        )])
        .unwrap();
        if let Some(value) = value {
            keyring_core::Entry::new(&primary.service, &primary.account)
                .unwrap()
                .set_password(value)
                .unwrap();
        }
        reads
    }

    #[test]
    fn binding_follows_its_role() {
        let profile = profile();
        for (role, url, account, placement) in [
            (ProviderRole::Primary, PRIMARY, "primary", header()),
            (
                ProviderRole::Secondary,
                "https://secondary.example",
                "secondary",
                RpcCredentialPlacement::Path {},
            ),
            (
                ProviderRole::Oracle,
                "https://oracle.example/",
                "oracle",
                RpcCredentialPlacement::Query {
                    name: "apikey".to_owned(),
                },
            ),
        ] {
            let binding = RpcCredentialBinding::for_role(&profile, role).unwrap();
            assert_eq!(binding.url, url, "{role}");
            assert_eq!(binding.entry, entry(account), "{role}");
            assert_eq!(binding.placement, placement, "{role}");
        }

        let mut without_url = profile.clone();
        without_url.secondary_rpc_url = None;
        without_url.oracle_provider_url = None;
        assert_eq!(
            RpcCredentialBinding::for_role(&without_url, ProviderRole::Secondary),
            None
        );
        assert_eq!(
            RpcCredentialBinding::for_role(&without_url, ProviderRole::Oracle),
            None
        );

        let mut without_credential = profile.clone();
        without_credential.providers.as_mut().unwrap().primary =
            Some(PrimaryProviderRecord::new("Primary", "primary.example"));
        assert_eq!(
            RpcCredentialBinding::for_role(&without_credential, ProviderRole::Primary),
            None
        );
        let mut without_records = profile;
        without_records.providers = None;
        assert_eq!(
            RpcCredentialBinding::for_role(&without_records, ProviderRole::Primary),
            None
        );
    }

    /// Without a binding the client is built without any keyring read.
    #[test]
    #[serial_test::serial]
    fn no_binding_makes_no_keyring_call() {
        let _restore = RestoreStore::new();
        let reads = counted_store(Some("value"));
        let client = rpc_client(PRIMARY, None).unwrap();
        assert_eq!(client.url(), PRIMARY);
        let mut plain = profile();
        plain.providers = None;
        profile_rpc_client(&plain, ProviderRole::Primary, PRIMARY).unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    /// A URL other than the profile's, by any byte, gets no credential and
    /// opens no keyring entry.
    #[test]
    #[serial_test::serial]
    fn overridden_url_gets_no_credential() {
        let _restore = RestoreStore::new();
        let reads = counted_store(None);
        let binding = RpcCredentialBinding::for_role(&profile(), ProviderRole::Primary).unwrap();
        for url in [
            "https://other.example/rpc",
            "https://primary.example/rpc/",
            "https://PRIMARY.example/rpc",
            "https://primary.example:443/rpc",
        ] {
            let client = rpc_client(url, Some(&binding)).unwrap();
            assert_eq!(client.url(), url);
        }
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    /// The profile's own URL reads the credential once and builds; a missing
    /// entry reports the keyring code, classified as a credential error.
    #[test]
    #[serial_test::serial]
    fn equal_override_keeps_the_credential() {
        let _restore = RestoreStore::new();
        let reads = counted_store(Some("Bearer abc"));
        let profile = profile();
        let client = profile_rpc_client(&profile, ProviderRole::Primary, PRIMARY).unwrap();
        assert_eq!(client.url(), PRIMARY);
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        let error = profile_rpc_client(&profile, ProviderRole::Oracle, "https://oracle.example/")
            .err()
            .unwrap();
        assert_eq!(error.code(), "auth.keyring_not_found");
        assert!(
            error.to_string().contains("stellar-agent-rpc-unit/oracle"),
            "{error}"
        );
        assert!(is_credential_error(&error));
    }

    #[test]
    fn credential_errors_are_classified() {
        use stellar_agent_core::error::AuthError;
        use stellar_agent_core::profile::schema::RpcCredentialDefect;
        let credential = [
            WalletError::Auth(AuthError::KeyringNotFound {
                name: "s/a".to_owned(),
            }),
            WalletError::Network(NetworkError::RpcCredentialInvalid {
                entry: "s/a".to_owned(),
                reason: RpcCredentialDefect::Empty,
            }),
            WalletError::Network(NetworkError::RpcCredentialUnusable {
                reason: RpcCredentialDefect::Userinfo,
            }),
        ];
        for error in &credential {
            assert!(is_credential_error(error), "{error:?}");
        }
        let transport = rpc_client("https://archive example.com", None)
            .err()
            .unwrap();
        for error in [
            transport,
            WalletError::Network(NetworkError::RpcCredentialRejected {
                url: "https://h".to_owned(),
                status: 401,
            }),
        ] {
            assert!(!is_credential_error(&error), "{error:?}");
        }
    }

    /// `Debug` prints the authority of the URL, the entry, and the placement,
    /// and no path or query of the URL.
    #[test]
    fn binding_debug_redacts_the_url() {
        let mut profile = profile();
        profile.rpc_url = "https://primary.example/PATH-SENTINEL?key=QUERY-SENTINEL".to_owned();
        let binding = RpcCredentialBinding::for_role(&profile, ProviderRole::Primary).unwrap();
        let rendered = format!("{binding:?}");
        assert!(rendered.contains("https://primary.example"), "{rendered}");
        assert!(rendered.contains("stellar-agent-rpc-unit"), "{rendered}");
        assert!(rendered.contains("X-API-Key"), "{rendered}");
        for leaked in ["PATH-SENTINEL", "QUERY-SENTINEL"] {
            assert!(!rendered.contains(leaked), "{rendered}");
        }
    }
}
