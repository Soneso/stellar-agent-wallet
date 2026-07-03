//! SEP-43 `getNetwork` method dispatch.
//!
//! Returns the active network name and passphrase from the loaded profile.
//!
//! Reference: SEP-43 v1.2.1 `getNetwork`. Wallets-Kit canonical response shape:
//! `{ network: string; networkPassphrase: string }`.

use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_core::profile::schema::Profile;

use crate::error::Sep43Error;

/// Dispatches the SEP-43 `getNetwork` method.
///
/// Returns `{ "network": "...", "networkPassphrase": "..." }` from the
/// active profile configuration. The `network` field is derived from the
/// `chain_id` CAIP-2 identifier:
///
/// - `stellar:testnet` → `"TESTNET"`
/// - `stellar:mainnet` → `"PUBLIC"`
/// - other → the full CAIP-2 chain identifier unchanged
///
/// This derivation mirrors the Wallets-Kit convention used in
/// Stellar-Wallets-Kit `freighter.module.ts`.
///
/// # Errors
///
/// This method does not return errors in the current implementation; the
/// profile's `network_passphrase` and `chain_id` are validated at profile
/// load time. The `Result` return type is retained for trait-compliance.
///
/// # Panics
///
/// Never panics.
pub fn dispatch(profile: &Profile) -> Result<serde_json::Value, Sep43Error> {
    let passphrase = profile.network_passphrase.as_str();
    let network = chain_id_to_network_name(profile.chain_id);
    Ok(serde_json::json!({
        "network": network,
        "networkPassphrase": passphrase,
    }))
}

/// Converts a [`Caip2`] chain identifier to a human-readable network name.
///
/// - [`Caip2::Testnet`] → `"TESTNET"`
/// - [`Caip2::Mainnet`] → `"PUBLIC"`
///
/// [`Caip2`] is `#[non_exhaustive]`; any future variant falls back to its CAIP-2
/// identifier string until a canonical network name is added here.
fn chain_id_to_network_name(chain_id: Caip2) -> &'static str {
    match chain_id {
        Caip2::Testnet => "TESTNET",
        Caip2::Mainnet => "PUBLIC",
        _ => chain_id.caip2_str(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn dispatch_testnet_returns_correct_network_fields() {
        use stellar_agent_core::profile::schema::Profile;

        let profile = Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct").build();
        let result = dispatch(&profile).unwrap();
        assert_eq!(result["network"], "TESTNET");
        let passphrase = result["networkPassphrase"].as_str().unwrap();
        assert!(
            passphrase.contains("Test SDF"),
            "expected testnet passphrase, got: {passphrase}"
        );
    }

    #[test]
    fn dispatch_mainnet_returns_correct_network_fields() {
        use stellar_agent_core::profile::schema::Profile;

        let profile = Profile::builder_mainnet("svc", "acct", "nonce-svc", "nonce-acct").build();
        let result = dispatch(&profile).unwrap();
        assert_eq!(result["network"], "PUBLIC");
        let passphrase = result["networkPassphrase"].as_str().unwrap();
        assert!(
            passphrase.contains("Public Global"),
            "expected mainnet passphrase, got: {passphrase}"
        );
    }

    #[test]
    fn chain_id_to_network_name_testnet() {
        assert_eq!(chain_id_to_network_name(Caip2::Testnet), "TESTNET");
    }

    #[test]
    fn chain_id_to_network_name_mainnet() {
        assert_eq!(chain_id_to_network_name(Caip2::Mainnet), "PUBLIC");
    }
}
