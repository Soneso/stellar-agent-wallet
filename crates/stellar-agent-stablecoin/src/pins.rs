//! Stablecoin issuer-account pin table.
//!
//! Pins assert IDENTITY (which G-account is the canonical issuer of a given
//! stablecoin on a given network). They do NOT assert mutable on-chain flags
//! such as `auth_clawback_enabled` — flags are fetched live at trustline-creation
//! time (see `flags::clawback_gate`).
//!
//! # Canonical sources (captured 2026-06-11)
//!
//! - **USDC mainnet**: Circle docs
//!   <https://developers.circle.com/stablecoins/usdc-contract-addresses> +
//!   on-chain `home_domain = circle.com` (verified live 2026-06-11).
//! - **USDC testnet**: same Circle docs page.
//! - **EURC mainnet**: Circle docs
//!   <https://developers.circle.com/stablecoins/eurc-contract-addresses> +
//!   on-chain `home_domain = circle.com` (verified live 2026-06-11).
//! - **EURC testnet**: same EURC docs page.
//! - **EURAU**: not pinnable. The only live on-chain `EURAU` issuers have
//!   `home_domain = world.lumenvaultx.org` and `home_domain = xlmassets.org` —
//!   neither is AllUnity (DWS/Galaxy/Flow Traders). Pinning either would be the
//!   exact failure the pin exists to prevent. See `KNOWN_LOOKALIKES` for the
//!   explicit denylist entries.
//!
//! # Live-flag-fetch invariant
//!
//! `auth_clawback_enabled` is NOT a pin attribute.  Live chain data shows
//! `auth_clawback_enabled = false` for both USDC and EURC mainnet issuers as of
//! 2026-06-11.  Clawback disclosure MUST come from a live flag fetch at trustline
//! time, never a hardcoded pin attribute.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// NetworkId
// ─────────────────────────────────────────────────────────────────────────────

/// The Stellar network the stablecoin operation targets.
///
/// Discriminates between mainnet and testnet issuer pins.  The wallet's
/// network passphrase (from the active profile) is used to derive this at
/// the call site via [`NetworkId::from_passphrase`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkId {
    /// Stellar Public Network — `"Public Global Stellar Network ; September 2015"`.
    Mainnet,
    /// Stellar Testnet — `"Test SDF Network ; September 2015"`.
    Testnet,
}

impl NetworkId {
    /// Derives the `NetworkId` from a Stellar network passphrase.
    ///
    /// Returns `None` when the passphrase does not match either known network.
    /// The caller should propagate this as a resolver error for unsupported
    /// networks.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_stablecoin::pins::NetworkId;
    ///
    /// let n = NetworkId::from_passphrase("Public Global Stellar Network ; September 2015");
    /// assert_eq!(n, Some(NetworkId::Mainnet));
    ///
    /// let t = NetworkId::from_passphrase("Test SDF Network ; September 2015");
    /// assert_eq!(t, Some(NetworkId::Testnet));
    ///
    /// let u = NetworkId::from_passphrase("unknown network");
    /// assert_eq!(u, None);
    /// ```
    #[must_use]
    pub fn from_passphrase(passphrase: &str) -> Option<Self> {
        match passphrase {
            "Public Global Stellar Network ; September 2015" => Some(Self::Mainnet),
            "Test SDF Network ; September 2015" => Some(Self::Testnet),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// USDC pins
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical USDC issuer on Stellar mainnet.
///
/// Source: Circle docs <https://developers.circle.com/stablecoins/usdc-contract-addresses>
/// + on-chain `home_domain = circle.com` (verified 2026-06-11).
///
/// Live flags (2026-06-11): `auth_revocable = true`, `auth_clawback_enabled = false`.
/// Flags are NOT pin attributes; they are fetched live at trustline time.
pub const USDC_MAINNET_ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// Canonical USDC issuer on Stellar testnet.
///
/// Source: Circle docs <https://developers.circle.com/stablecoins/usdc-contract-addresses>.
pub const USDC_TESTNET_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

// ─────────────────────────────────────────────────────────────────────────────
// EURC pins
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical EURC issuer on Stellar mainnet.
///
/// Source: Circle docs <https://developers.circle.com/stablecoins/eurc-contract-addresses>
/// + on-chain `home_domain = circle.com` (verified 2026-06-11).
///
/// Live flags (2026-06-11): `auth_revocable = true`, `auth_clawback_enabled = false`.
/// Flags are NOT pin attributes; they are fetched live at trustline time.
pub const EURC_MAINNET_ISSUER: &str = "GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2";

/// Canonical EURC issuer on Stellar testnet.
///
/// Source: Circle docs <https://developers.circle.com/stablecoins/eurc-contract-addresses>.
pub const EURC_TESTNET_ISSUER: &str = "GB3Q6QDZYTHWT7E5PVS3W7FUT5GVAFC5KSZFFLPU25GO7VTC3NM2ZTVO";

// ─────────────────────────────────────────────────────────────────────────────
// Known-lookalike denylist (counterparty-impersonation)
// ─────────────────────────────────────────────────────────────────────────────

/// A `(code, issuer)` pair for the known-lookalike denylist.
///
/// Entries are refused with a named `counterparty-lookalike` warning by
/// [`crate::resolve::resolve_denomination`] on the explicit `code+issuer` path
/// only.  A bare code that is not in the pin table (e.g. `EURAU`) is refused as
/// [`crate::resolve::ResolveError::UnpinnedBareCode`] before the denylist is
/// consulted; the denylist check is reached only when an explicit issuer is
/// supplied.
///
/// The denylist is seeded from live on-chain data (2026-06-11).  New entries
/// MUST cite the canonical source (on-chain `home_domain`) in comments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookalikeEntry {
    /// Asset code.
    pub code: &'static str,
    /// Issuer G-strkey.
    pub issuer: &'static str,
    /// On-chain `home_domain` of the lookalike issuer, for disclosure.
    pub home_domain: &'static str,
}

/// Known lookalike entries.
///
/// Seeded with the two live EURAU lookalikes (neither is AllUnity):
/// - `GCMHT…HNFT`: on-chain `home_domain = world.lumenvaultx.org`
/// - `GCPW5…CBSC`: on-chain `home_domain = xlmassets.org`
///
/// Both are refused unconditionally.  EURAU is not pinnable — its live on-chain
/// assets are lookalikes — so bare-code EURAU is also refused as an unpinned
/// bare code by the resolver.
pub const KNOWN_LOOKALIKES: &[LookalikeEntry] = &[
    LookalikeEntry {
        code: "EURAU",
        issuer: "GCMHTNLK3N2QYQENZTJAKO34J3GGNL26BILAWPWVRB37JLV7TXDBHNFT",
        home_domain: "world.lumenvaultx.org",
    },
    LookalikeEntry {
        code: "EURAU",
        issuer: "GCPW5C27VOZ4T74ERBEAUW2O7TXRZ5CNMRN7CCDVI477FXRWULBACBSC",
        home_domain: "xlmassets.org",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// Resolver helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the canonical issuer G-strkey for `(code, network)`, if pinned.
///
/// Returns `None` when there is no pin for the given code on the given network
/// (e.g. `EURAU` on any network, or any code that is not USDC/EURC).
///
/// # Examples
///
/// ```
/// use stellar_agent_stablecoin::pins::{NetworkId, pinned_issuer};
///
/// let issuer = pinned_issuer("USDC", NetworkId::Testnet);
/// assert_eq!(issuer, Some("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"));
/// ```
#[must_use]
pub fn pinned_issuer(code: &str, network: NetworkId) -> Option<&'static str> {
    match (code, network) {
        ("USDC", NetworkId::Mainnet) => Some(USDC_MAINNET_ISSUER),
        ("USDC", NetworkId::Testnet) => Some(USDC_TESTNET_ISSUER),
        ("EURC", NetworkId::Mainnet) => Some(EURC_MAINNET_ISSUER),
        ("EURC", NetworkId::Testnet) => Some(EURC_TESTNET_ISSUER),
        // EURAU is not pinnable — its live on-chain assets are lookalikes.
        _ => None,
    }
}

/// Returns `true` when `(code, issuer)` is in the known-lookalike denylist.
///
/// Comparison is case-sensitive for the issuer (G-strkeys are canonically
/// uppercase and length-validated).  The code comparison uses the same case
/// as the caller supplies; callers in [`crate::resolve`] normalise to uppercase
/// before calling this function.
///
/// # Examples
///
/// ```
/// use stellar_agent_stablecoin::pins::is_known_lookalike;
///
/// assert!(is_known_lookalike(
///     "EURAU",
///     "GCMHTNLK3N2QYQENZTJAKO34J3GGNL26BILAWPWVRB37JLV7TXDBHNFT",
/// ));
/// assert!(!is_known_lookalike("USDC", "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"));
/// ```
#[must_use]
pub fn is_known_lookalike(code: &str, issuer: &str) -> bool {
    KNOWN_LOOKALIKES
        .iter()
        .any(|e| e.code == code && e.issuer == issuer)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn network_id_from_passphrase_mainnet() {
        let n = NetworkId::from_passphrase("Public Global Stellar Network ; September 2015");
        assert_eq!(n, Some(NetworkId::Mainnet));
    }

    #[test]
    fn network_id_from_passphrase_testnet() {
        let n = NetworkId::from_passphrase("Test SDF Network ; September 2015");
        assert_eq!(n, Some(NetworkId::Testnet));
    }

    #[test]
    fn network_id_from_passphrase_unknown() {
        assert_eq!(NetworkId::from_passphrase("unknown"), None);
        assert_eq!(NetworkId::from_passphrase(""), None);
    }

    #[test]
    fn pinned_issuer_usdc_mainnet() {
        assert_eq!(
            pinned_issuer("USDC", NetworkId::Mainnet),
            Some("GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN")
        );
    }

    #[test]
    fn pinned_issuer_usdc_testnet() {
        assert_eq!(
            pinned_issuer("USDC", NetworkId::Testnet),
            Some("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5")
        );
    }

    #[test]
    fn pinned_issuer_eurc_mainnet() {
        assert_eq!(
            pinned_issuer("EURC", NetworkId::Mainnet),
            Some("GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2")
        );
    }

    #[test]
    fn pinned_issuer_eurc_testnet() {
        assert_eq!(
            pinned_issuer("EURC", NetworkId::Testnet),
            Some("GB3Q6QDZYTHWT7E5PVS3W7FUT5GVAFC5KSZFFLPU25GO7VTC3NM2ZTVO")
        );
    }

    #[test]
    fn pinned_issuer_eurau_not_pinned() {
        // EURAU is not pinnable — its live on-chain assets are lookalikes.
        assert_eq!(pinned_issuer("EURAU", NetworkId::Mainnet), None);
        assert_eq!(pinned_issuer("EURAU", NetworkId::Testnet), None);
    }

    #[test]
    fn pinned_issuer_unknown_code() {
        assert_eq!(pinned_issuer("UNKNOWN", NetworkId::Mainnet), None);
    }

    #[test]
    fn known_lookalikes_table_has_two_eurau_entries() {
        assert_eq!(KNOWN_LOOKALIKES.len(), 2);
        assert!(KNOWN_LOOKALIKES.iter().all(|e| e.code == "EURAU"));
    }

    #[test]
    fn is_known_lookalike_true_for_eurau_entries() {
        assert!(is_known_lookalike(
            "EURAU",
            "GCMHTNLK3N2QYQENZTJAKO34J3GGNL26BILAWPWVRB37JLV7TXDBHNFT"
        ));
        assert!(is_known_lookalike(
            "EURAU",
            "GCPW5C27VOZ4T74ERBEAUW2O7TXRZ5CNMRN7CCDVI477FXRWULBACBSC"
        ));
    }

    #[test]
    fn is_known_lookalike_false_for_pinned_issuers() {
        assert!(!is_known_lookalike("USDC", USDC_MAINNET_ISSUER));
        assert!(!is_known_lookalike("EURC", EURC_MAINNET_ISSUER));
    }

    #[test]
    fn lookalike_entries_have_home_domains() {
        let entry0 = &KNOWN_LOOKALIKES[0];
        assert_eq!(entry0.home_domain, "world.lumenvaultx.org");
        let entry1 = &KNOWN_LOOKALIKES[1];
        assert_eq!(entry1.home_domain, "xlmassets.org");
    }
}
