//! SEP-43 `getAddress` method dispatch.
//!
//! Returns the active wallet address (G-key from `profile.mcp_signer_default.account`).
//!
//! Reference: SEP-43 v1.2.1 `getAddress`. Wallets-Kit canonical response shape:
//! `{ address: string }`.

use stellar_agent_core::profile::schema::Profile;

use crate::{address::resolve_active_address, error::Sep43Error};

/// Dispatches the SEP-43 `getAddress` method.
///
/// Returns `{ "address": "G..." }` per SEP-43 v1.2.1 `getAddress`.
///
/// Uses `profile.mcp_signer_default.account` as the active address (G-key).
/// Smart-account C-key routing is not handled by this path.
///
/// # Errors
///
/// - [`Sep43Error::MissingAddress`] — `mcp_signer_default.account` is empty.
/// - [`Sep43Error::InvalidAddress`] — `mcp_signer_default.account` is not a
///   valid G/C/M strkey.
///
/// # Panics
///
/// Never panics.
pub fn dispatch(profile: &Profile) -> Result<serde_json::Value, Sep43Error> {
    let (address, _kind) = resolve_active_address(profile)?;
    Ok(serde_json::json!({ "address": address }))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn dispatch_empty_account_returns_missing_address() {
        use stellar_agent_core::profile::schema::Profile;

        // An empty account string causes resolve_active_address to return
        // MissingAddress before attempting strkey parsing.
        let profile = Profile::builder_testnet("svc", "", "nonce-svc", "nonce-acct").build();
        let err = dispatch(&profile).unwrap_err();
        assert!(
            matches!(err, Sep43Error::MissingAddress),
            "empty account must return MissingAddress, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
    }

    #[test]
    fn dispatch_g_strkey_account_returns_address_json() {
        use stellar_agent_core::profile::schema::Profile;

        let profile = Profile::builder_testnet(
            "svc",
            "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI",
            "nonce-svc",
            "nonce-acct",
        )
        .build();
        let result = dispatch(&profile).unwrap();
        assert_eq!(
            result["address"],
            "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI"
        );
    }

    // ── Coverage for C-strkey and M-strkey dispatch paths ────────────────────
    //
    // The existing G-strkey test covers the Ok path for ClassicG. The tests
    // below cover SmartAccountC and MuxedM, reaching the same Ok return via
    // different input shapes (all resolve through resolve_active_address).

    #[test]
    fn dispatch_c_strkey_account_returns_address_json() {
        use stellar_agent_core::profile::schema::Profile;

        let c_strkey: String = stellar_strkey::Contract([0x03u8; 32])
            .to_string()
            .to_string();
        let profile =
            Profile::builder_testnet("svc", c_strkey.as_str(), "nonce-svc", "nonce-acct").build();
        let result = dispatch(&profile).unwrap();
        assert_eq!(result["address"].as_str().unwrap(), c_strkey.as_str());
    }

    #[test]
    fn dispatch_m_strkey_account_returns_address_json() {
        use stellar_agent_core::profile::schema::Profile;

        let m_strkey: String = stellar_strkey::ed25519::MuxedAccount {
            id: 7777u64,
            ed25519: [0x06u8; 32],
        }
        .to_string()
        .to_string();
        let profile =
            Profile::builder_testnet("svc", m_strkey.as_str(), "nonce-svc", "nonce-acct").build();
        let result = dispatch(&profile).unwrap();
        assert_eq!(result["address"].as_str().unwrap(), m_strkey.as_str());
    }
}
