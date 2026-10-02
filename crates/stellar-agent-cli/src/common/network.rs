//! [`TargetNetwork`] is the clap network selector for CLI commands.
//!
//! It parses network names case-insensitively and converts to [`Caip2`] for
//! the chain identifier and network passphrase.
//!
//! # Two-layer mainnet defence
//!
//! The CLI-layer structural rejection (`args.network == TargetNetwork::Mainnet`)
//! remains in every write command alongside the network-layer passphrase
//! comparison. `TargetNetwork::Mainnet` exists in the type system so the
//! rejection is an explicit, test-exercisable code path.

use std::fmt;
use std::str::FromStr;

use stellar_agent_core::profile::caip2::Caip2;
pub(crate) use stellar_agent_core::profile::caip2::TESTNET_RPC_URL;

/// Shared network selector for all write subcommands (`pay`, `accounts create`).
///
/// `Mainnet` exists as a first-class variant so the structural rejection in
/// each command's `run` function is a concrete, test-exercisable code path.
///
/// # Examples
///
/// ```text
/// // TargetNetwork::from_str("testnet") == Ok(TargetNetwork::Testnet)
/// // TargetNetwork::from_str("mainnet") == Ok(TargetNetwork::Mainnet)
/// // TargetNetwork::from_str("futurenet") == Err(...)
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetNetwork {
    /// Stellar testnet — the only accepted value for write commands.
    Testnet,
    /// Stellar mainnet — **structurally rejected** at command `run` time.
    ///
    /// Kept as a first-class variant so the CLI-layer rejection is an
    /// explicit, tested code path rather than dead code.
    Mainnet,
}

impl From<TargetNetwork> for Caip2 {
    fn from(network: TargetNetwork) -> Self {
        match network {
            TargetNetwork::Testnet => Self::Testnet,
            TargetNetwork::Mainnet => Self::Mainnet,
        }
    }
}

impl TargetNetwork {
    /// Returns the CAIP-2 chain identifier for this CLI selector.
    #[must_use]
    pub fn caip2(self) -> Caip2 {
        self.into()
    }

    /// Returns the network passphrase string for this network.
    ///
    /// Callers pass this to `submit_transaction_and_wait` and
    /// `fund_with_friendbot` as the second-layer passphrase guard.
    ///
    /// # Examples
    ///
    /// ```text
    /// // TargetNetwork::Testnet.passphrase() == "Test SDF Network ; September 2015"
    /// // TargetNetwork::Mainnet.passphrase() == "Public Global Stellar Network ; September 2015"
    /// ```
    #[must_use]
    pub fn passphrase(&self) -> &'static str {
        self.caip2().network_passphrase()
    }
}

impl FromStr for TargetNetwork {
    type Err = String;

    /// Parses a network name case-insensitively.
    ///
    /// # Errors
    ///
    /// Returns a `String` error if the input is not `"testnet"` or `"mainnet"`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "testnet" => Ok(Self::Testnet),
            "mainnet" => Ok(Self::Mainnet),
            other => Err(format!(
                "unknown network '{other}'; only 'testnet' and 'mainnet' are recognized"
            )),
        }
    }
}

impl fmt::Display for TargetNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Testnet => f.write_str("testnet"),
            Self::Mainnet => f.write_str("mainnet"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn target_network_from_str_round_trips() {
        assert_eq!(
            TargetNetwork::from_str("testnet").unwrap(),
            TargetNetwork::Testnet
        );
        assert_eq!(
            TargetNetwork::from_str("TESTNET").unwrap(),
            TargetNetwork::Testnet
        );
        assert_eq!(
            TargetNetwork::from_str("Testnet").unwrap(),
            TargetNetwork::Testnet
        );
        assert_eq!(
            TargetNetwork::from_str("mainnet").unwrap(),
            TargetNetwork::Mainnet
        );
        assert_eq!(
            TargetNetwork::from_str("MAINNET").unwrap(),
            TargetNetwork::Mainnet
        );
    }

    #[test]
    fn target_network_from_str_unknown_is_error() {
        let err = TargetNetwork::from_str("futurenet").unwrap_err();
        assert!(
            err.contains("futurenet"),
            "error must include the unknown token"
        );
        assert!(TargetNetwork::from_str("").is_err());
    }

    #[test]
    fn target_network_display_lowercase() {
        assert_eq!(TargetNetwork::Testnet.to_string(), "testnet");
        assert_eq!(TargetNetwork::Mainnet.to_string(), "mainnet");
    }

    #[test]
    fn target_network_passphrase_values() {
        assert_eq!(
            TargetNetwork::Testnet.passphrase(),
            "Test SDF Network ; September 2015"
        );
        assert_eq!(
            TargetNetwork::Mainnet.passphrase(),
            "Public Global Stellar Network ; September 2015"
        );
    }

    #[test]
    fn target_network_caip2_maps_both_variants() {
        assert_eq!(TargetNetwork::Testnet.caip2(), Caip2::Testnet);
        assert_eq!(TargetNetwork::Mainnet.caip2(), Caip2::Mainnet);
        assert_eq!(
            crate::commands::policy_engine::caip2_chain_id_for_network(TargetNetwork::Mainnet),
            "stellar:mainnet"
        );
    }
}
