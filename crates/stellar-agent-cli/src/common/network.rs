//! [`TargetNetwork`] enum — shared network selector for all write subcommands.
//!
//! Unifies the network selector across `pay`, `accounts create`, and
//! `profile init`.
//! Implements `FromStr` + `Display` so clap can use it with
//! `default_value = "testnet"`.
//!
//! # Passphrase constants
//!
//! `TESTNET_PASSPHRASE` and `MAINNET_PASSPHRASE` are co-located here as the
//! **canonical CLI-layer source** and exposed on `TargetNetwork::passphrase()`.
//!
//! Design decision — passphrase location:
//!
//! `stellar-agent-network::friendbot` already carries its own `const
//! MAINNET_PASSPHRASE` for the network-layer structural rejection check. That
//! constant is `pub(crate)` and lives at the network layer where it is used as
//! a runtime guard (not as a user-facing string). We do NOT pull the CLI crate
//! into the network crate — that would invert the dependency direction. Instead:
//!
//! - The canonical wire-format constants live here (CLI layer, co-located with
//!   `TargetNetwork::passphrase()`).
//! - The network-layer constant in `friendbot.rs` remains independent for the
//!   guard comparison; it is a private `const` not exposed to external callers.
//!   The values are identical and stable (protocol-level strings); they are NOT
//!   shared at the source level to avoid making the network crate depend on the
//!   CLI crate.
//!
//! Callers that need the passphrase for submission call
//! `args.network.passphrase()`. This collapses the per-command
//! `network_passphrase(network)` helper to a single method call.
//!
//! # Two-layer mainnet defence
//!
//! The CLI-layer structural rejection (`args.network == TargetNetwork::Mainnet`)
//! remains in every write command alongside the network-layer passphrase
//! comparison. `TargetNetwork::Mainnet` exists in the type system so the
//! rejection is an explicit, test-exercisable code path.

use std::fmt;
use std::str::FromStr;

/// Stellar testnet network passphrase.
///
/// Used by `TargetNetwork::Testnet` in [`TargetNetwork::passphrase`] and as
/// the default passphrase for testnet write commands.
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Stellar mainnet network passphrase.
///
/// Exposed publicly so the embed example and any future external consumers can
/// reference the canonical constant without hard-coding the string.
/// For the CLI write commands, mainnet is **structurally rejected before this
/// passphrase is ever used** — it is present for completeness and for the
/// network-layer passphrase comparison guard in `submit_transaction_and_wait`.
pub const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

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

impl TargetNetwork {
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
        match self {
            Self::Testnet => TESTNET_PASSPHRASE,
            // Mainnet is structurally rejected before this is reached for
            // write commands, but the value is correct so a passphrase
            // comparison in the network layer still fires correctly.
            Self::Mainnet => MAINNET_PASSPHRASE,
        }
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
    fn target_network_passphrase_matches_exported_constants() {
        assert_eq!(TargetNetwork::Testnet.passphrase(), TESTNET_PASSPHRASE);
        assert_eq!(TargetNetwork::Mainnet.passphrase(), MAINNET_PASSPHRASE);
    }
}
