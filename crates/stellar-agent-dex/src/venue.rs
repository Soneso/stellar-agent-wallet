//! Venue allowlist for the Soroswap DEX adapter.
//!
//! # What this module does
//!
//! Maintains the per-network router-address allowlist and provides
//! [`check_venue_allowed`], which refuses any router address that is not on
//! the allowlist.
//!
//! # Current venues
//!
//! Only the Soroswap ROUTER-DIRECT path is wired.  Aquarius and Phoenix
//! are deferred.
//!
//! # Allowlist policy
//!
//! Fail-closed: any `router_address` NOT present in the allowlist for the
//! given `network` returns `Err(VenueError::NotAllowlisted)`.  The caller
//! cannot distinguish "not in list" from "list absent" — both refuse.
//!
//! # Behaviour
//!
//! Soroswap-only venue allowlist; Aquarius and Phoenix are deferred.

use crate::pins::{SOROSWAP_ROUTER_ADDRESS_PUBNET, SOROSWAP_ROUTER_ADDRESS_TESTNET};
use stellar_agent_core::observability::redact_strkey_first5_last5;

// ─────────────────────────────────────────────────────────────────────────────
// VenueError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by the venue-allowlist check.
///
/// All variants carry non-sensitive diagnostic information.  The `Display`
/// impl never leaks a full `C…` address.
///
/// # Display invariant
///
/// Every variant below is reviewed: none echoes a full address in its
/// `Display` message.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VenueError {
    /// The router address is not on the allowlist for this network.
    ///
    /// Fail-closed.
    #[error(
        "router address {router_redacted} is not on the Soroswap venue allowlist \
         for network {network}"
    )]
    NotAllowlisted {
        /// First-5-last-5 redacted router address.
        router_redacted: String,
        /// Network identifier.
        network: String,
    },

    /// The network identifier is not recognised.
    #[error("unrecognised network for venue allowlist: {network}")]
    UnrecognisedNetwork {
        /// Network identifier.
        network: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Allowlist
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the venue allowlist (router addresses) for `network`.
///
/// Returns `None` if the network is not recognised.
///
/// # Scope
///
/// Only Soroswap router addresses are listed.  Aquarius and Phoenix are
/// deferred.
fn allowlist_for_network(network: &str) -> Option<&'static [&'static str]> {
    // Each slice contains exactly the pinned Soroswap router for the network.
    // Aquarius/Phoenix remain deferred.
    match network {
        "stellar:testnet" | "testnet" => Some(&[SOROSWAP_ROUTER_ADDRESS_TESTNET] as &[&str]),
        "stellar:pubnet" | "pubnet" | "mainnet" => {
            Some(&[SOROSWAP_ROUTER_ADDRESS_PUBNET] as &[&str])
        }
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// check_venue_allowed
// ─────────────────────────────────────────────────────────────────────────────

/// Checks whether `router_address` is on the venue allowlist for `network`.
///
/// Returns `Ok(())` only when the router address is present.  Any other
/// outcome is `Err` (fail-closed).
///
/// # Errors
///
/// - [`VenueError::UnrecognisedNetwork`] — `network` is not known.
/// - [`VenueError::NotAllowlisted`] — router not on the allowlist.
///
/// # Behaviour
///
/// Enforces the Soroswap venue allowlist (fail-closed).
pub fn check_venue_allowed(router_address: &str, network: &str) -> Result<(), VenueError> {
    let allowlist =
        allowlist_for_network(network).ok_or_else(|| VenueError::UnrecognisedNetwork {
            network: network.to_owned(),
        })?;

    if allowlist.contains(&router_address) {
        Ok(())
    } else {
        Err(VenueError::NotAllowlisted {
            router_redacted: redact_strkey_first5_last5(router_address),
            network: network.to_owned(),
        })
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
        clippy::panic,
        reason = "test-only fixture construction"
    )]

    use super::*;

    #[test]
    fn soroswap_testnet_router_is_allowed() {
        assert!(
            check_venue_allowed(SOROSWAP_ROUTER_ADDRESS_TESTNET, "stellar:testnet").is_ok(),
            "Soroswap testnet router must be on the allowlist"
        );
    }

    #[test]
    fn soroswap_testnet_alt_network_key() {
        assert!(
            check_venue_allowed(SOROSWAP_ROUTER_ADDRESS_TESTNET, "testnet").is_ok(),
            "testnet alt key must be recognised"
        );
    }

    #[test]
    fn soroswap_pubnet_router_is_allowed() {
        assert!(
            check_venue_allowed(SOROSWAP_ROUTER_ADDRESS_PUBNET, "stellar:pubnet").is_ok(),
            "Soroswap pubnet router must be on the allowlist"
        );
    }

    #[test]
    fn unknown_address_is_refused() {
        let result = check_venue_allowed(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "stellar:testnet",
        );
        assert!(
            matches!(result, Err(VenueError::NotAllowlisted { .. })),
            "unknown router address must be refused"
        );
    }

    #[test]
    fn unrecognised_network_is_refused() {
        let result = check_venue_allowed(SOROSWAP_ROUTER_ADDRESS_TESTNET, "stellar:futurenet");
        assert!(
            matches!(result, Err(VenueError::UnrecognisedNetwork { .. })),
            "unrecognised network must return UnrecognisedNetwork"
        );
    }

    #[test]
    fn error_display_no_full_address_leak() {
        let err = VenueError::NotAllowlisted {
            router_redacted: redact_strkey_first5_last5(SOROSWAP_ROUTER_ADDRESS_TESTNET),
            network: "stellar:testnet".to_owned(),
        };
        let display = err.to_string();
        assert!(
            !display.contains(SOROSWAP_ROUTER_ADDRESS_TESTNET),
            "error display must not contain full address"
        );
    }
}
