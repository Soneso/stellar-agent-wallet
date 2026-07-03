//! Protocol constants for the x402 Exact Stellar payment scheme.
//!
//! USDC SAC addresses and network-passphrase mappings are the single
//! source of truth for this crate.  They are verified against the
//! @x402/stellar reference implementation.
//!
//! # Network string translation
//!
//! The x402 wire protocol uses `"stellar:pubnet"` for the Stellar mainnet.
//! The in-tree `stellar-agent-core` [`Caip2`] enum uses `"stellar:mainnet"` and
//! does not recognise `"stellar:pubnet"`.  This module owns the translation:
//! [`x402_network_to_passphrase`] and [`x402_network_to_caip2`] map x402 wire
//! strings to the internal representation AFTER which `Caip2::network_passphrase`
//! is safe to call.

use stellar_agent_core::profile::caip2::Caip2;

use crate::X402Error;

// ─────────────────────────────────────────────────────────────────────────────
// USDC SAC contract addresses
// ─────────────────────────────────────────────────────────────────────────────

/// USDC SAC contract address on Stellar pubnet.
///
/// Verified against the @x402/stellar reference implementation and Circle's
/// canonical issuer documentation.
pub const USDC_PUBNET_SAC: &str = "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75";

/// USDC SAC contract address on Stellar testnet.
///
/// Verified against the @x402/stellar reference implementation.
pub const USDC_TESTNET_SAC: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

// ─────────────────────────────────────────────────────────────────────────────
// x402 wire network strings
// ─────────────────────────────────────────────────────────────────────────────

/// x402 wire network identifier for Stellar pubnet.
///
/// Verified against the @x402/stellar reference implementation.
///
/// NOTE: This differs from the `stellar-agent-core` `Caip2::Mainnet` string
/// (`"stellar:mainnet"`).  Always go through [`x402_network_to_caip2`] when
/// mapping to internal representation.
pub const X402_STELLAR_PUBNET: &str = "stellar:pubnet";

/// x402 wire network identifier for Stellar testnet.
///
/// Verified against the @x402/stellar reference implementation.
pub const X402_STELLAR_TESTNET: &str = "stellar:testnet";

// ─────────────────────────────────────────────────────────────────────────────
// Network translation functions
// ─────────────────────────────────────────────────────────────────────────────

/// Maps an x402 wire network string to a Stellar network passphrase.
///
/// Accepts only the two supported x402 Stellar network identifiers:
/// - `"stellar:pubnet"` → `"Public Global Stellar Network ; September 2015"`
/// - `"stellar:testnet"` → `"Test SDF Network ; September 2015"`
///
/// All other strings return [`X402Error::UnsupportedNetwork`].
///
/// # Errors
///
/// - [`X402Error::UnsupportedNetwork`] — if `network` is not one of the two
///   accepted x402 Stellar network identifiers.
///
/// # Examples
///
/// ```
/// use stellar_agent_x402::constants::x402_network_to_passphrase;
///
/// let p = x402_network_to_passphrase("stellar:pubnet").unwrap();
/// assert_eq!(p, "Public Global Stellar Network ; September 2015");
///
/// let p = x402_network_to_passphrase("stellar:testnet").unwrap();
/// assert_eq!(p, "Test SDF Network ; September 2015");
///
/// assert!(x402_network_to_passphrase("evm:1").is_err());
/// ```
pub fn x402_network_to_passphrase(network: &str) -> Result<&'static str, X402Error> {
    x402_network_to_caip2(network).map(Caip2::network_passphrase)
}

/// Maps an x402 wire network string to the internal [`Caip2`] enum.
///
/// Accepts only the two supported x402 Stellar network identifiers:
/// - `"stellar:pubnet"` → [`Caip2::Mainnet`]
/// - `"stellar:testnet"` → [`Caip2::Testnet`]
///
/// This is the ONLY authorised translation point between x402 wire strings and
/// the internal `Caip2` representation.
///
/// # Errors
///
/// - [`X402Error::UnsupportedNetwork`] — if `network` is not one of the two
///   accepted x402 Stellar network identifiers.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::profile::caip2::Caip2;
/// use stellar_agent_x402::constants::x402_network_to_caip2;
///
/// assert_eq!(x402_network_to_caip2("stellar:pubnet").unwrap(), Caip2::Mainnet);
/// assert_eq!(x402_network_to_caip2("stellar:testnet").unwrap(), Caip2::Testnet);
/// assert!(x402_network_to_caip2("evm:1").is_err());
/// ```
pub fn x402_network_to_caip2(network: &str) -> Result<Caip2, X402Error> {
    match network {
        X402_STELLAR_PUBNET => Ok(Caip2::Mainnet),
        X402_STELLAR_TESTNET => Ok(Caip2::Testnet),
        other => Err(X402Error::UnsupportedNetwork {
            network: other.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps acceptable in unit tests"
    )]

    use super::*;
    use stellar_agent_core::profile::caip2::Caip2;

    // ── x402_network_to_passphrase round-trip ─────────────────────────────────

    #[test]
    fn pubnet_maps_to_mainnet_passphrase() {
        let p = x402_network_to_passphrase("stellar:pubnet")
            .expect("stellar:pubnet must map to mainnet passphrase");
        assert_eq!(p, "Public Global Stellar Network ; September 2015");
    }

    #[test]
    fn testnet_maps_to_testnet_passphrase() {
        let p = x402_network_to_passphrase("stellar:testnet")
            .expect("stellar:testnet must map to testnet passphrase");
        assert_eq!(p, "Test SDF Network ; September 2015");
    }

    #[test]
    fn unsupported_network_is_rejected() {
        assert!(x402_network_to_passphrase("evm:1").is_err());
        assert!(x402_network_to_passphrase("stellar:mainnet").is_err());
        assert!(x402_network_to_passphrase("").is_err());
    }

    // ── x402_network_to_caip2 round-trip ─────────────────────────────────────

    #[test]
    fn pubnet_maps_to_caip2_mainnet() {
        assert_eq!(
            x402_network_to_caip2("stellar:pubnet").unwrap(),
            Caip2::Mainnet
        );
    }

    #[test]
    fn testnet_maps_to_caip2_testnet() {
        assert_eq!(
            x402_network_to_caip2("stellar:testnet").unwrap(),
            Caip2::Testnet
        );
    }

    #[test]
    fn caip2_mainnet_string_is_rejected_by_x402_mapper() {
        // "stellar:mainnet" is NOT a valid x402 wire string.
        let err = x402_network_to_caip2("stellar:mainnet").unwrap_err();
        assert!(matches!(err, X402Error::UnsupportedNetwork { .. }));
    }

    // ── USDC SAC address format checks ────────────────────────────────────────

    #[test]
    fn usdc_pubnet_sac_is_c_strkey() {
        assert!(USDC_PUBNET_SAC.starts_with('C'));
        assert_eq!(USDC_PUBNET_SAC.len(), 56);
    }

    #[test]
    fn usdc_testnet_sac_is_c_strkey() {
        assert!(USDC_TESTNET_SAC.starts_with('C'));
        assert_eq!(USDC_TESTNET_SAC.len(), 56);
    }
}
