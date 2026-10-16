//! What an RPC endpoint reports about itself, and the protocol rule the wallet
//! applies to that report.
//!
//! [`StellarRpcClient::endpoint_identity`](crate::StellarRpcClient::endpoint_identity)
//! asks the endpoint `getNetwork` and returns an [`EndpointIdentity`] only
//! after the network checks and [`check_protocol_version`] pass. Outside the
//! `test-helpers` feature, no other code in this crate builds one. Holding a
//! value then means those checks pass against the endpoint it names.

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
/// protocol version passes [`check_protocol_version`]. Outside the `test-helpers`
/// feature, the type has no public constructor. Its private fields prevent
/// struct-literal construction outside this crate:
///
/// ```compile_fail
/// use stellar_agent_network::EndpointIdentity;
///
/// let forged = EndpointIdentity {
///     chain_id: None,
///     protocol_version: 29,
///     authority: String::from("https://rpc.example.com:443"),
/// };
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointIdentity {
    chain_id: Option<Caip2>,
    protocol_version: u32,
    authority: String,
}

impl EndpointIdentity {
    /// Builds the identity of an endpoint whose answer passed every check.
    pub(crate) fn checked(
        chain_id: Option<Caip2>,
        protocol_version: u32,
        authority: String,
    ) -> Self {
        Self {
            chain_id,
            protocol_version,
            authority,
        }
    }

    /// Builds an identity for a test in another crate.
    ///
    /// Only available under the `test-helpers` feature. Production code
    /// receives an identity from
    /// [`StellarRpcClient::endpoint_identity`](crate::StellarRpcClient::endpoint_identity)
    /// alone.
    #[cfg(feature = "test-helpers")]
    #[must_use]
    pub fn for_tests(
        chain_id: Option<Caip2>,
        protocol_version: u32,
        authority: impl Into<String>,
    ) -> Self {
        Self::checked(chain_id, protocol_version, authority.into())
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
