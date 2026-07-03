//! CAIP-2 chain-ID enum and network-resolution helpers.
//!
//! [`Caip2`] is the canonical network selector for MCP tools and profile-config
//! fields.  It maps a CAIP-2 string (`stellar:testnet`, `stellar:mainnet`) to a
//! `(rpc_url, network_passphrase)` pair at profile-load time.
//!
//! # Invariants
//!
//! - Default RPC URLs are compile-time constants.  They can be overridden by an
//!   explicit `rpc_url` field in the profile TOML.
//! - Network passphrases are never overridden from profile config — they are
//!   protocol constants derived from the chain ID.
//!
//! # Examples
//!
//! ```
//! use stellar_agent_core::profile::caip2::Caip2;
//!
//! let chain = Caip2::Testnet;
//! assert_eq!(chain.network_passphrase(), "Test SDF Network ; September 2015");
//! assert_eq!(chain.caip2_str(), "stellar:testnet");
//! ```

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::profile::schema::Profile;

/// Default RPC URL for Stellar testnet (Soroban/RPC endpoint).
pub const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

/// Default RPC URL for Stellar mainnet (Soroban/RPC endpoint).
///
/// This intentionally points at Stellar Validation Cloud's public mainnet RPC
/// endpoint. It is a third-party default, not a protocol constant; operators
/// can and should override it in profile config or CLI flags when they require
/// a different provider. Do not change this default casually because profile
/// resolution and CLI help text rely on a stable fallback URL.
pub const MAINNET_RPC_URL: &str = "https://mainnet.stellar.validationcloud.io/v1/stellar";

/// Stellar testnet network passphrase.
///
/// Canonical wire-format constant per the Stellar protocol specification.
/// The CLI layer also exposes this value at
/// `stellar_agent_cli::common::network::TESTNET_PASSPHRASE`; both are kept
/// as independent `pub const` definitions to avoid a dep-direction inversion
/// between core and cli.
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Stellar mainnet network passphrase.
///
/// Canonical wire-format constant per the Stellar protocol specification.
/// The CLI layer also exposes this value at
/// `stellar_agent_cli::common::network::MAINNET_PASSPHRASE`; both are kept
/// as independent `pub const` definitions to avoid a dep-direction inversion
/// between core and cli.
pub const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// CAIP-2 chain identifier for the Stellar blockchain networks.
///
/// The enum is `#[non_exhaustive]` so future variants (`stellar:futurenet`,
/// `stellar:custom`) can be added without breaking existing match arms.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::profile::caip2::Caip2;
/// use std::str::FromStr;
///
/// let c = Caip2::from_str("stellar:testnet").unwrap();
/// assert_eq!(c, Caip2::Testnet);
/// assert_eq!(c.to_string(), "stellar:testnet");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Caip2 {
    /// Stellar testnet (`stellar:testnet`).
    #[serde(rename = "stellar:testnet")]
    Testnet,
    /// Stellar mainnet (`stellar:mainnet`).
    #[serde(rename = "stellar:mainnet")]
    Mainnet,
}

impl Caip2 {
    /// Returns `true` when this chain ID refers to mainnet.
    ///
    /// Used by the `NoopPolicyEngine` to gate destructive MCP tools.
    #[must_use]
    pub fn is_mainnet(self) -> bool {
        matches!(self, Self::Mainnet)
    }

    /// Returns the canonical CAIP-2 string representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::caip2::Caip2;
    ///
    /// assert_eq!(Caip2::Testnet.caip2_str(), "stellar:testnet");
    /// assert_eq!(Caip2::Mainnet.caip2_str(), "stellar:mainnet");
    /// ```
    #[must_use]
    pub fn caip2_str(self) -> &'static str {
        match self {
            Self::Testnet => "stellar:testnet",
            Self::Mainnet => "stellar:mainnet",
        }
    }

    /// Returns the Stellar network passphrase for this chain.
    ///
    /// Network passphrases are protocol constants and cannot be overridden per
    /// profile config.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::caip2::Caip2;
    ///
    /// assert_eq!(
    ///     Caip2::Testnet.network_passphrase(),
    ///     "Test SDF Network ; September 2015",
    /// );
    /// ```
    #[must_use]
    pub fn network_passphrase(self) -> &'static str {
        match self {
            Self::Testnet => TESTNET_PASSPHRASE,
            Self::Mainnet => MAINNET_PASSPHRASE,
        }
    }

    /// Returns the default Soroban RPC URL for this chain.
    ///
    /// The returned value can be overridden by an explicit `rpc_url` field in
    /// the profile TOML.  When the profile omits `rpc_url`, this default is
    /// used.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::caip2::{Caip2, TESTNET_RPC_URL};
    ///
    /// assert_eq!(Caip2::Testnet.default_rpc_url(), TESTNET_RPC_URL);
    /// ```
    #[must_use]
    pub fn default_rpc_url(self) -> &'static str {
        match self {
            Self::Testnet => TESTNET_RPC_URL,
            Self::Mainnet => MAINNET_RPC_URL,
        }
    }
}

impl fmt::Display for Caip2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.caip2_str())
    }
}

impl FromStr for Caip2 {
    type Err = Caip2ParseError;

    /// Parses a CAIP-2 chain ID string.
    ///
    /// Accepted values (case-sensitive): `"stellar:testnet"`, `"stellar:mainnet"`.
    ///
    /// # Errors
    ///
    /// Returns [`Caip2ParseError::Unknown`] for any unrecognised string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stellar:testnet" => Ok(Self::Testnet),
            "stellar:mainnet" => Ok(Self::Mainnet),
            other => Err(Caip2ParseError::Unknown(other.to_owned())),
        }
    }
}

/// Errors returned by [`Caip2::from_str`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Caip2ParseError {
    /// The CAIP-2 string was not recognised.
    ///
    /// Supported values: `stellar:testnet` and `stellar:mainnet`.
    #[error(
        "unknown CAIP-2 chain ID '{0}'; supported values: \
         stellar:testnet, stellar:mainnet"
    )]
    Unknown(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain-ID validator
// ─────────────────────────────────────────────────────────────────────────────

/// Validates that the CAIP-2 `chain_id` argument matches the profile's
/// configured chain ID.
///
/// Parses `chain_id_arg` via [`Caip2::from_str`] and compares the result
/// against `profile.chain_id`.  Rejects mismatches so agents cannot address
/// a testnet tool call at a mainnet profile or vice versa.
///
/// Used by MCP tool handlers such as `stellar_balances` and `stellar_friendbot`;
/// callers map the returned error to `rmcp::ErrorData::invalid_params`.
///
/// # Errors
///
/// - [`ChainIdValidationError::ParseError`] — `chain_id_arg` is not a
///   recognised CAIP-2 string.
/// - [`ChainIdValidationError::Mismatch`] — the parsed chain ID does not
///   match `profile.chain_id`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::profile::caip2::validate_chain_id_matches_profile;
/// use stellar_agent_core::profile::schema::Profile;
///
/// let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct").build();
/// assert!(validate_chain_id_matches_profile("stellar:testnet", &profile).is_ok());
/// assert!(validate_chain_id_matches_profile("stellar:mainnet", &profile).is_err());
/// assert!(validate_chain_id_matches_profile("invalid", &profile).is_err());
/// ```
pub fn validate_chain_id_matches_profile(
    chain_id_arg: &str,
    profile: &Profile,
) -> Result<(), ChainIdValidationError> {
    let parsed: Caip2 = chain_id_arg.parse()?;
    if parsed != profile.chain_id {
        return Err(ChainIdValidationError::Mismatch {
            arg: chain_id_arg.to_owned(),
            profile: profile.chain_id.to_string(),
        });
    }
    Ok(())
}

/// Errors returned by [`validate_chain_id_matches_profile`].
///
/// Callers in `stellar-agent-mcp` map these to
/// `rmcp::ErrorData::invalid_params` (not `internal_error`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChainIdValidationError {
    /// The CAIP-2 chain ID argument could not be parsed.
    #[error("invalid CAIP-2 chain_id argument: {0}")]
    ParseError(#[from] Caip2ParseError),

    /// The parsed chain ID does not match the profile's chain ID.
    #[error("chain_id argument '{arg}' does not match profile chain_id '{profile}'")]
    Mismatch {
        /// The chain ID supplied in the tool call argument.
        arg: String,
        /// The chain ID configured in the profile.
        profile: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn from_str_testnet() {
        let c = Caip2::from_str("stellar:testnet").unwrap();
        assert_eq!(c, Caip2::Testnet);
    }

    #[test]
    fn from_str_mainnet() {
        let c = Caip2::from_str("stellar:mainnet").unwrap();
        assert_eq!(c, Caip2::Mainnet);
    }

    #[test]
    fn from_str_unknown_is_error() {
        let err = Caip2::from_str("stellar:futurenet").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("stellar:futurenet"), "error: {msg}");
    }

    #[test]
    fn display_round_trips() {
        for c in [Caip2::Testnet, Caip2::Mainnet] {
            let s = c.to_string();
            let back = Caip2::from_str(&s).unwrap();
            assert_eq!(c, back);
        }
    }

    #[test]
    fn is_mainnet() {
        assert!(!Caip2::Testnet.is_mainnet());
        assert!(Caip2::Mainnet.is_mainnet());
    }

    #[test]
    fn passphrase_constants() {
        assert_eq!(
            Caip2::Testnet.network_passphrase(),
            "Test SDF Network ; September 2015"
        );
        assert_eq!(
            Caip2::Mainnet.network_passphrase(),
            "Public Global Stellar Network ; September 2015"
        );
    }

    #[test]
    fn serde_round_trip() {
        let c = Caip2::Testnet;
        let json = serde_json::to_string(&c).unwrap();
        let back: Caip2 = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn serde_mainnet_round_trip() {
        let c = Caip2::Mainnet;
        let json = serde_json::to_string(&c).unwrap();
        let back: Caip2 = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // ── validate_chain_id_matches_profile tests ───────────────────────────────

    fn testnet_profile() -> Profile {
        Profile::builder_testnet("svc", "acct", "n-svc", "n-acct").build()
    }

    fn mainnet_profile() -> Profile {
        Profile::builder_mainnet("svc", "acct", "n-svc", "n-acct").build()
    }

    #[test]
    fn validate_chain_id_testnet_matches_testnet_profile() {
        assert!(
            validate_chain_id_matches_profile("stellar:testnet", &testnet_profile()).is_ok(),
            "testnet chain_id must match testnet profile"
        );
    }

    #[test]
    fn validate_chain_id_mainnet_matches_mainnet_profile() {
        assert!(
            validate_chain_id_matches_profile("stellar:mainnet", &mainnet_profile()).is_ok(),
            "mainnet chain_id must match mainnet profile"
        );
    }

    #[test]
    fn validate_chain_id_mismatch_testnet_arg_mainnet_profile() {
        let result = validate_chain_id_matches_profile("stellar:testnet", &mainnet_profile());
        assert!(
            matches!(result, Err(ChainIdValidationError::Mismatch { .. })),
            "testnet arg against mainnet profile must produce Mismatch: {result:?}"
        );
    }

    #[test]
    fn validate_chain_id_mismatch_mainnet_arg_testnet_profile() {
        let result = validate_chain_id_matches_profile("stellar:mainnet", &testnet_profile());
        assert!(
            matches!(result, Err(ChainIdValidationError::Mismatch { .. })),
            "mainnet arg against testnet profile must produce Mismatch: {result:?}"
        );
    }

    #[test]
    fn validate_chain_id_invalid_caip2_string() {
        let result = validate_chain_id_matches_profile("invalid-caip2", &testnet_profile());
        assert!(
            matches!(result, Err(ChainIdValidationError::ParseError(_))),
            "invalid CAIP-2 string must produce ParseError: {result:?}"
        );
    }

    #[test]
    fn validate_chain_id_mismatch_error_message_contains_both_values() {
        let result = validate_chain_id_matches_profile("stellar:testnet", &mainnet_profile());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("stellar:testnet"),
            "error message must name the arg: {msg}"
        );
        assert!(
            msg.contains("stellar:mainnet"),
            "error message must name the profile chain_id: {msg}"
        );
    }
}
