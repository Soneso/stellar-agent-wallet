//! What an RPC endpoint reports about itself, and the protocol rule the wallet
//! applies to that report.
//!
//! [`StellarRpcClient::endpoint_identity`](crate::StellarRpcClient::endpoint_identity)
//! asks the endpoint `getNetwork` and returns an [`EndpointIdentity`] only
//! after the network checks and [`check_protocol_version`] pass. No other code
//! builds one. Holding a value then means those checks passed against the
//! endpoint it names, through the client whose identity it carries.

use std::ops::RangeInclusive;

use stellar_agent_core::error::NetworkError;
use stellar_agent_core::profile::caip2::Caip2;

/// The Stellar protocol versions this release supports.
///
/// A release adds a version to this range only after its testnet acceptance
/// tests ran against that version. [`check_protocol_version`] refuses a
/// mainnet endpoint outside the range and logs a warning for any other
/// network.
pub const SUPPORTED_PROTOCOL_VERSIONS: RangeInclusive<u32> = 29..=29;

/// What an RPC endpoint reports about itself, after the wallet checks it.
///
/// The endpoint's passphrase matches the one the caller expects, and its
/// protocol version passes [`check_protocol_version`]. The type has no public
/// constructor, and two independent barriers keep it from being forged
/// outside this crate: it is `#[non_exhaustive]`, and its fields are private.
///
/// ```compile_fail,E0639
/// use stellar_agent_network::EndpointIdentity;
/// fn forge(p: EndpointIdentity) -> EndpointIdentity { EndpointIdentity { ..p } }
/// ```
///
/// Each field is private on its own:
///
/// ```compile_fail,E0616
/// use stellar_agent_network::EndpointIdentity;
/// fn inspect(p: &EndpointIdentity) { let _ = &p.authority; }
/// ```
///
/// ```compile_fail,E0616
/// use stellar_agent_network::EndpointIdentity;
/// fn inspect(p: &EndpointIdentity) { let _ = &p.chain_id; }
/// ```
///
/// ```compile_fail,E0616
/// use stellar_agent_network::EndpointIdentity;
/// fn inspect(p: &EndpointIdentity) { let _ = &p.protocol_version; }
/// ```
///
/// ```compile_fail,E0616
/// use stellar_agent_network::EndpointIdentity;
/// fn inspect(p: &EndpointIdentity) { let _ = &p.client_id; }
/// ```
///
/// No test constructor exists:
///
/// ```compile_fail,E0599
/// use stellar_agent_network::EndpointIdentity;
/// fn main() { let _ = EndpointIdentity::for_tests(None, 29, "https://rpc.example.invalid"); }
/// ```
///
/// The import and the getters resolve, so the snippets above fail on the
/// barrier they name and not on the path:
///
/// ```
/// use stellar_agent_network::EndpointIdentity;
/// fn inspect(p: &EndpointIdentity) -> (u64, &str, u32) {
///     (p.client_id(), p.authority(), p.protocol_version())
/// }
/// let _ = inspect;
/// ```
///
/// The identity implements none of `Serialize`, `Deserialize`, or `Default`:
///
/// ```compile_fail,E0277
/// use stellar_agent_network::EndpointIdentity;
/// fn need<T: serde::Serialize>() {}
/// need::<EndpointIdentity>();
/// ```
///
/// ```compile_fail,E0277
/// use stellar_agent_network::EndpointIdentity;
/// fn need<T: serde::de::DeserializeOwned>() {}
/// need::<EndpointIdentity>();
/// ```
///
/// ```compile_fail,E0277
/// use stellar_agent_network::EndpointIdentity;
/// fn need<T: Default>() {}
/// need::<EndpointIdentity>();
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointIdentity {
    chain_id: Option<Caip2>,
    protocol_version: u32,
    authority: String,
    client_id: u64,
}

impl EndpointIdentity {
    /// Builds the identity of an endpoint whose answer passed every check,
    /// through the client whose identity is `client_id`.
    pub(crate) fn checked(
        chain_id: Option<Caip2>,
        protocol_version: u32,
        authority: String,
        client_id: u64,
    ) -> Self {
        Self {
            chain_id,
            protocol_version,
            authority,
            client_id,
        }
    }

    /// The identity of the client the checks ran through, as
    /// [`StellarRpcClient::id`](crate::StellarRpcClient::id) reports it.
    #[must_use]
    pub fn client_id(&self) -> u64 {
        self.client_id
    }

    /// The fact digest under `stellar-agent-authz-fact:endpoint:v1`.
    ///
    /// Fields, in order: the optional chain as its CAIP-2 text
    /// (`lp(chain)`), `u32be(protocol_version)`, `lp(authority)`, and
    /// `u64be(client_id)`.
    #[must_use]
    pub fn fact_digest(&self) -> [u8; 32] {
        use stellar_agent_core::mainnet::fact::{FACT_LABEL_ENDPOINT, FactDigest};
        let mut digest = FactDigest::new(FACT_LABEL_ENDPOINT);
        digest.present(self.chain_id.is_some());
        if let Some(chain) = self.chain_id {
            digest.bytes(chain.caip2_str().as_bytes());
        }
        digest
            .u32(self.protocol_version)
            .bytes(self.authority.as_bytes())
            .u64(self.client_id);
        digest.finish()
    }

    /// The chain the endpoint's passphrase names: `Some` for testnet and
    /// mainnet, `None` for any other network.
    #[must_use]
    pub fn chain_id(&self) -> Option<Caip2> {
        self.chain_id
    }

    /// The protocol version the endpoint reported.
    #[must_use]
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// The endpoint's scheme, host, and port, the form every RPC error
    /// carries. It never holds userinfo, a path, or a query.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }
}

/// An oracle client whose endpoint reported the mainnet passphrase and a
/// protocol version the protocol rule accepts for mainnet.
///
/// [`MainnetOracle::verify`] is the only public constructor, and the
/// crate's single-request form of it is the only other one. Both ask the
/// endpoint `getNetwork` through the client and return a value only when the
/// answer names mainnet and passes [`check_protocol_version`]. The settlement steps
/// that release or confirm a mainnet submission on the oracle's word take
/// this type rather than a bare client, so an oracle endpoint that serves
/// another network, or whose identity could not be read, is never asked for
/// that evidence.
///
/// ```compile_fail,E0451
/// use stellar_agent_network::{MainnetOracle, StellarRpcClient};
/// fn forge(client: &StellarRpcClient) -> MainnetOracle<'_> { MainnetOracle { client } }
/// ```
#[derive(Clone, Copy)]
pub struct MainnetOracle<'a> {
    client: &'a crate::StellarRpcClient,
}

impl<'a> MainnetOracle<'a> {
    /// Checks that `client`'s endpoint serves mainnet, with the identity
    /// probe's retries bounded by `deadline`.
    ///
    /// # Errors
    ///
    /// `network.witness_unavailable` naming the oracle when the endpoint
    /// reports another network, an unsupported protocol version, or no
    /// identity before `deadline`; `network.rpc_credential_refused` when it
    /// answers HTTP 401 or 403.
    pub async fn verify(
        client: &'a crate::StellarRpcClient,
        deadline: tokio::time::Instant,
    ) -> Result<Self, stellar_agent_core::error::WalletError> {
        client
            .mainnet_endpoint_identity(deadline)
            .await
            .map_err(|error| {
                crate::cross_check::identity_error(error, &client.url.authority(), Caip2::Mainnet)
            })?;
        Ok(Self { client })
    }

    /// [`Self::verify`] with exactly one `getNetwork` request and no retry,
    /// for a caller that charges every request it sends against an
    /// allowance.
    ///
    /// # Errors
    ///
    /// As [`Self::verify`].
    pub(crate) async fn verify_once(
        client: &'a crate::StellarRpcClient,
        deadline: tokio::time::Instant,
    ) -> Result<Self, stellar_agent_core::error::WalletError> {
        client
            .mainnet_endpoint_identity_once(deadline)
            .await
            .map_err(|error| {
                crate::cross_check::identity_error(error, &client.url.authority(), Caip2::Mainnet)
            })?;
        Ok(Self { client })
    }

    /// The verified client.
    #[must_use]
    pub fn client(self) -> &'a crate::StellarRpcClient {
        self.client
    }
}

impl std::fmt::Debug for MainnetOracle<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MainnetOracle")
            .field("authority", &self.client.url.authority())
            .finish()
    }
}

/// Applies the protocol rule to the version an endpoint reported.
///
/// A version inside [`SUPPORTED_PROTOCOL_VERSIONS`] passes. Outside it, a
/// mainnet endpoint is refused: mainnet value must not move under a protocol
/// the release was not tested against. Any other network, testnet or one whose
/// passphrase names no known chain, passes with one warning that carries the
/// version and the range. Testnet upgrades ahead of mainnet, and a test
/// network stays usable through that window.
///
/// # Errors
///
/// [`NetworkError::UnsupportedProtocolVersion`] when `chain` is mainnet and
/// `version` is outside [`SUPPORTED_PROTOCOL_VERSIONS`].
///
/// # Examples
///
/// ```
/// use stellar_agent_core::profile::caip2::Caip2;
/// use stellar_agent_network::{SUPPORTED_PROTOCOL_VERSIONS, check_protocol_version};
///
/// let supported = *SUPPORTED_PROTOCOL_VERSIONS.end();
/// assert!(check_protocol_version(Some(Caip2::Mainnet), supported).is_ok());
/// assert!(check_protocol_version(Some(Caip2::Mainnet), supported + 1).is_err());
/// assert!(check_protocol_version(Some(Caip2::Testnet), supported + 1).is_ok());
/// ```
pub fn check_protocol_version(chain: Option<Caip2>, version: u32) -> Result<(), NetworkError> {
    if SUPPORTED_PROTOCOL_VERSIONS.contains(&version) {
        return Ok(());
    }
    let supported_min = *SUPPORTED_PROTOCOL_VERSIONS.start();
    let supported_max = *SUPPORTED_PROTOCOL_VERSIONS.end();
    if chain.is_some_and(Caip2::is_mainnet) {
        return Err(NetworkError::UnsupportedProtocolVersion {
            protocol_version: version,
            supported_min,
            supported_max,
        });
    }
    tracing::warn!(
        protocol_version = version,
        supported_min,
        supported_max,
        chain = chain.map_or("other", Caip2::caip2_str),
        "the RPC endpoint runs a protocol version outside the supported range; \
         continuing because the network is not mainnet"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use std::collections::BTreeMap;

    use stellar_agent_test_support::WarningCapture;

    use super::*;

    /// The fact digest follows the documented layout, against a vector
    /// computed independently, and names the client.
    #[test]
    fn the_fact_digest_follows_the_layout() {
        let identity = EndpointIdentity::checked(
            Some(Caip2::Mainnet),
            29,
            "https://rpc.example.org".to_owned(),
            7,
        );
        assert_eq!(identity.client_id(), 7);
        assert_eq!(
            stellar_agent_core::hex::encode(&identity.fact_digest()),
            "9c9639a9968b49f4bf0d97c1c067370cdb4a445f2d654d6e2fb879f6a468c196"
        );
        let other_client = EndpointIdentity::checked(
            Some(Caip2::Mainnet),
            29,
            "https://rpc.example.org".to_owned(),
            8,
        );
        assert_ne!(other_client.fact_digest(), identity.fact_digest());
        let no_chain = EndpointIdentity::checked(None, 29, "https://rpc.example.org".to_owned(), 7);
        assert_ne!(no_chain.fact_digest(), identity.fact_digest());
    }

    fn with_warnings<T>(f: impl FnOnce() -> T) -> (T, Vec<BTreeMap<String, String>>) {
        let (warnings, _guard) = WarningCapture::capture(None);
        (f(), warnings.seen())
    }

    fn assert_refused(version: u32) {
        let (result, warnings) =
            with_warnings(|| check_protocol_version(Some(Caip2::Mainnet), version));
        match result {
            Err(NetworkError::UnsupportedProtocolVersion {
                protocol_version,
                supported_min,
                supported_max,
            }) => {
                assert_eq!(protocol_version, version);
                assert_eq!(supported_min, 29);
                assert_eq!(supported_max, 29);
            }
            other => panic!("mainnet at version {version} must refuse; got {other:?}"),
        }
        assert!(
            warnings.is_empty(),
            "a refusal is the outcome, not a warning: {warnings:?}"
        );
    }

    fn assert_one_warning(chain: Option<Caip2>, version: u32) {
        let (result, warnings) = with_warnings(|| check_protocol_version(chain, version));
        assert!(
            result.is_ok(),
            "{chain:?} at version {version} must pass; got {result:?}"
        );
        assert_eq!(
            warnings.len(),
            1,
            "{chain:?} at version {version} must warn once: {warnings:?}"
        );
        let warning = &warnings[0];
        assert_eq!(
            warning.get("protocol_version").map(String::as_str),
            Some(version.to_string().as_str())
        );
        assert_eq!(warning.get("supported_min").map(String::as_str), Some("29"));
        assert_eq!(warning.get("supported_max").map(String::as_str), Some("29"));
    }

    #[test]
    fn mainnet_inside_the_range_passes_without_a_warning() {
        let (result, warnings) = with_warnings(|| check_protocol_version(Some(Caip2::Mainnet), 29));
        assert!(result.is_ok(), "{result:?}");
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn mainnet_below_the_range_refuses() {
        assert_refused(28);
    }

    #[test]
    fn mainnet_above_the_range_refuses() {
        assert_refused(30);
    }

    #[test]
    fn testnet_outside_the_range_passes_with_one_warning() {
        assert_one_warning(Some(Caip2::Testnet), 30);
    }

    #[test]
    fn another_network_outside_the_range_passes_with_one_warning() {
        assert_one_warning(None, 30);
    }

    #[test]
    fn any_network_inside_the_range_passes_without_a_warning() {
        for chain in [Some(Caip2::Testnet), None] {
            let (result, warnings) = with_warnings(|| check_protocol_version(chain, 29));
            assert!(result.is_ok(), "{chain:?}: {result:?}");
            assert!(warnings.is_empty(), "{chain:?}: {warnings:?}");
        }
    }
}
