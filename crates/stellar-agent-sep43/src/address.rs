//! Active address resolution and strkey validation for SEP-43 methods.
//!
//! Provides the address-kind discriminant [`ActiveAddressType`], the profile-
//! driven resolver [`resolve_active_address`], and the input-validation helper
//! [`validate_strkey`].
//!
//! # Address kinds
//!
//! Per SEP-43 `getAddress`:
//! - `ClassicG` — standard ed25519 public key (`G...`, 56 chars)
//! - `SmartAccountC` — contract account (`C...`, 56 chars)
//! - `MuxedM` — muxed account (`M...`, longer)
//!
//! The active address is the strkey from `profile.mcp_signer_default.account`
//! and may be a `G`, `C`, or `M` strkey. The signing paths require a G-key; the
//! smart-account (`C...`) signing flow is not handled here.

use stellar_agent_core::profile::schema::Profile;
use stellar_strkey::Strkey;

use crate::error::Sep43Error;

/// Discriminated union of Stellar active-address kinds.
///
/// Used by [`resolve_active_address`] and [`validate_strkey`] to convey
/// the kind of the resolved or validated address.
///
/// # Examples
///
/// ```
/// use stellar_agent_sep43::ActiveAddressType;
///
/// let kind = ActiveAddressType::ClassicG;
/// assert_eq!(kind, ActiveAddressType::ClassicG);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveAddressType {
    /// Classic Stellar account — ed25519 public key, `G...` 56-char strkey.
    ClassicG,
    /// Smart account — contract account, `C...` 56-char strkey.
    SmartAccountC,
    /// Muxed account — `M...` strkey with embedded account ID.
    MuxedM,
}

/// Resolves the active wallet address and its kind from the active profile.
///
/// Uses `profile.mcp_signer_default.account` as the active `G...` key.
/// Smart-account C-key routing is not handled by this path.
///
/// # Errors
///
/// - [`Sep43Error::MissingAddress`] — `mcp_signer_default.account` is empty.
/// - [`Sep43Error::InvalidAddress`] — `mcp_signer_default.account` is not a
///   valid `G...`, `C...`, or `M...` strkey.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_core::profile::schema::Profile;
/// use stellar_agent_sep43::{resolve_active_address, ActiveAddressType};
///
/// # fn example(profile: &Profile) -> Result<(), stellar_agent_sep43::Sep43Error> {
/// let (address, kind) = resolve_active_address(profile)?;
/// assert_eq!(kind, ActiveAddressType::ClassicG);
/// assert!(address.starts_with('G'));
/// # Ok(())
/// # }
/// ```
pub fn resolve_active_address(
    profile: &Profile,
) -> Result<(String, ActiveAddressType), Sep43Error> {
    let account = profile.mcp_signer_default.account.as_str();
    if account.is_empty() {
        return Err(Sep43Error::MissingAddress);
    }
    let kind = validate_strkey(account)?;
    Ok((account.to_owned(), kind))
}

/// Validates a strkey string and returns its [`ActiveAddressType`].
///
/// Accepts `G...` (ed25519 public key), `C...` (contract), and `M...`
/// (muxed) strkeys. Rejects all other forms (secret keys `S...`, pre-auth
/// `T...`, hash-x `X...`, etc.) with [`Sep43Error::InvalidAddress`].
///
/// # Errors
///
/// - [`Sep43Error::InvalidAddress`] — the string is not a valid Stellar strkey,
///   or is a strkey variant not appropriate as a signing address (e.g. `S...`
///   secret key).
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```
/// use stellar_agent_sep43::{validate_strkey, ActiveAddressType};
///
/// // Valid G-strkey (testnet fixture, not mainnet)
/// let result = validate_strkey("GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI");
/// assert!(matches!(result, Ok(ActiveAddressType::ClassicG)));
///
/// // Invalid
/// assert!(validate_strkey("not-a-strkey").is_err());
/// ```
pub fn validate_strkey(addr: &str) -> Result<ActiveAddressType, Sep43Error> {
    match Strkey::from_string(addr) {
        Ok(Strkey::PublicKeyEd25519(_)) => Ok(ActiveAddressType::ClassicG),
        Ok(Strkey::Contract(_)) => Ok(ActiveAddressType::SmartAccountC),
        Ok(Strkey::MuxedAccountEd25519(_)) => Ok(ActiveAddressType::MuxedM),
        Ok(_) => Err(Sep43Error::InvalidAddress {
            detail: "address kind is not a valid signing address (expected G, C, or M strkey)"
                .to_owned(),
            expected_type: "G-strkey, C-strkey, or M-strkey",
        }),
        Err(e) => Err(Sep43Error::InvalidAddress {
            detail: format!("strkey parse failed: {e}"),
            expected_type: "G-strkey, C-strkey, or M-strkey",
        }),
    }
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

    /// A well-known testnet G-strkey fixture (public, non-secret).
    const TESTNET_G_STRKEY: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

    #[test]
    fn validate_strkey_g_key_returns_classic_g() {
        let result = validate_strkey(TESTNET_G_STRKEY).unwrap();
        assert_eq!(result, ActiveAddressType::ClassicG);
    }

    #[test]
    fn validate_strkey_invalid_string_returns_invalid_address() {
        let err = validate_strkey("not-a-strkey").unwrap_err();
        assert!(matches!(err, Sep43Error::InvalidAddress { .. }));
        assert_eq!(err.sep43_code(), -3);
    }

    #[test]
    fn validate_strkey_empty_returns_invalid_address() {
        let err = validate_strkey("").unwrap_err();
        assert!(matches!(err, Sep43Error::InvalidAddress { .. }));
    }

    #[test]
    fn validate_strkey_short_prefix_returns_invalid_address() {
        let err = validate_strkey("GAAAA").unwrap_err();
        assert!(matches!(err, Sep43Error::InvalidAddress { .. }));
    }

    #[test]
    fn validate_strkey_has_correct_sep43_code_for_invalid() {
        let err = validate_strkey("bad").unwrap_err();
        assert_eq!(err.sep43_code(), -3);
    }

    #[test]
    fn resolve_active_address_returns_g_strkey_for_classic_account() {
        use stellar_agent_core::profile::schema::Profile;

        // Build a G-strkey deterministically from fixed bytes so the expected
        // value is an independent oracle (not derived from the code under test).
        let g_strkey: String = stellar_strkey::ed25519::PublicKey([0x11u8; 32])
            .to_string()
            .to_string();
        let profile =
            Profile::builder_testnet("svc", g_strkey.as_str(), "nonce-svc", "nonce-acct").build();

        let (addr, kind) = resolve_active_address(&profile)
            .expect("resolve_active_address must succeed for a valid G-strkey account");

        assert_eq!(kind, ActiveAddressType::ClassicG, "kind must be ClassicG");
        assert!(addr.starts_with('G'), "address must start with 'G': {addr}");
        assert_eq!(addr, g_strkey, "address must equal the enrolled G-strkey");
    }

    #[test]
    fn active_address_type_is_copy() {
        let a = ActiveAddressType::ClassicG;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn active_address_type_debug() {
        let s = format!("{:?}", ActiveAddressType::SmartAccountC);
        assert_eq!(s, "SmartAccountC");
    }

    // ── validate_strkey: C-strkey and M-strkey branches ──────────────────────

    #[test]
    fn validate_strkey_c_strkey_returns_smart_account_c() {
        // Encode a contract C-strkey from 32 bytes.
        // Double to_string(): first returns heapless string, second gives String.
        let c_strkey: String = stellar_strkey::Contract([0x01u8; 32])
            .to_string()
            .to_string();
        let result = validate_strkey(&c_strkey).unwrap();
        assert_eq!(result, ActiveAddressType::SmartAccountC);
    }

    #[test]
    fn validate_strkey_m_strkey_returns_muxed_m() {
        // Build a valid M-strkey using stellar_strkey::ed25519::MuxedAccount.
        let m_strkey: String = stellar_strkey::ed25519::MuxedAccount {
            id: 1234u64,
            ed25519: [0x04u8; 32],
        }
        .to_string()
        .to_string();
        assert!(
            m_strkey.starts_with('M'),
            "M-strkey must start with 'M': {m_strkey}"
        );
        let result = validate_strkey(&m_strkey).unwrap();
        assert_eq!(result, ActiveAddressType::MuxedM);
    }

    #[test]
    fn validate_strkey_unexpected_kind_returns_invalid_address() {
        // A PreAuthTx `T`-strkey is a valid Stellar strkey but is not a valid
        // signing address type (not G, C, or M). It falls into the `Ok(_)` catch-all
        // arm of validate_strkey, exercising the "unexpected kind" branch.
        use crate::error::Sep43Error;

        let t_strkey: String = stellar_strkey::PreAuthTx([0xABu8; 32])
            .to_string()
            .to_string();
        assert!(
            t_strkey.starts_with('T'),
            "PreAuthTx strkey must start with 'T': {t_strkey}"
        );

        let err = validate_strkey(&t_strkey).unwrap_err();
        assert!(
            matches!(err, Sep43Error::InvalidAddress { .. }),
            "T-strkey must return InvalidAddress, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
        let Sep43Error::InvalidAddress {
            ref detail,
            ref expected_type,
        } = err
        else {
            panic!("expected InvalidAddress");
        };
        assert!(
            detail.contains("not a valid signing address"),
            "detail must mention signing address: {detail}"
        );
        assert!(
            expected_type.contains("G-strkey"),
            "expected_type: {expected_type}"
        );
    }

    // ── resolve_active_address: C-strkey and M-strkey ─────────────────────────

    #[test]
    fn resolve_active_address_c_strkey_returns_smart_account_c() {
        use stellar_agent_core::profile::schema::Profile;

        let c_strkey: String = stellar_strkey::Contract([0x02u8; 32])
            .to_string()
            .to_string();
        let profile =
            Profile::builder_testnet("svc", c_strkey.as_str(), "nonce-svc", "nonce-acct").build();
        let (addr, kind) = resolve_active_address(&profile).unwrap();
        assert_eq!(kind, ActiveAddressType::SmartAccountC);
        assert_eq!(addr, c_strkey);
    }

    #[test]
    fn resolve_active_address_m_strkey_returns_muxed_m() {
        use stellar_agent_core::profile::schema::Profile;

        let m_strkey: String = stellar_strkey::ed25519::MuxedAccount {
            id: 9999u64,
            ed25519: [0x05u8; 32],
        }
        .to_string()
        .to_string();
        let profile =
            Profile::builder_testnet("svc", m_strkey.as_str(), "nonce-svc", "nonce-acct").build();
        let (addr, kind) = resolve_active_address(&profile).unwrap();
        assert_eq!(kind, ActiveAddressType::MuxedM);
        assert_eq!(addr, m_strkey);
    }

    #[test]
    fn resolve_active_address_empty_account_returns_missing_address() {
        use stellar_agent_core::profile::schema::Profile;

        let profile = Profile::builder_testnet("svc", "", "nonce-svc", "nonce-acct").build();
        let err = resolve_active_address(&profile).unwrap_err();
        assert!(
            matches!(err, crate::error::Sep43Error::MissingAddress),
            "empty account must return MissingAddress, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
    }
}
