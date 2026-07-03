//! SEP-43 `signMessage` method dispatch.
//!
//! Signs an arbitrary UTF-8 string message and returns the base64-encoded
//! signature with the signer's address.
//!
//! Reference: SEP-43 v1.2.1 `signMessage`. Wallets-Kit canonical response shape:
//! `{ signedMessage: string; signerAddress?: string }`.
//!
//! # Signing
//!
//! The message is treated as UTF-8 bytes and signed with the SEP-53 scheme
//! (`SHA256("Stellar Signed Message:\n" ‖ message)`); the 64-byte ed25519
//! signature is returned base64-encoded (matching reference SEP-43 wallets).

use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::signing::Signer;

use crate::{address::validate_strkey, error::Sep43Error, signing::sign_message_bytes};

/// Dispatches the SEP-43 `signMessage` method.
///
/// Signs the UTF-8 `message` with the SEP-53 scheme and returns
/// `{ "signedMessage": "<base64>", "signerAddress": "G..." }`.
///
/// # Argument validation
///
/// - If `network_passphrase` is `Some`, it must equal
///   `profile.network_passphrase`; mismatch → [`Sep43Error::InvalidNetworkPassphrase`].
///   The passphrase is a validation gate only: it is not mixed into the signed
///   bytes. Message signing remains network-independent per SEP-43 v1.2.1.
/// - If `address` is `Some`, it must be a valid strkey AND must equal the
///   signing key's G-strkey; mismatch → [`Sep43Error::InvalidAddress`].
/// - An empty or oversized `message` → [`Sep43Error::InvalidMessage`].
///
/// # Errors
///
/// - [`Sep43Error::InvalidNetworkPassphrase`] — provided passphrase does not
///   match the profile's.
/// - [`Sep43Error::InvalidAddress`] — provided `address` is not a valid strkey
///   or does not match the signing key.
/// - [`Sep43Error::InvalidMessage`] — `message` is empty or exceeds the
///   SEP-53 maximum length.
/// - [`Sep43Error::UserRejected`] — signer user-rejection.
/// - [`Sep43Error::SignerUnavailable`] — signer wallet-state error.
///
/// # Panics
///
/// Never panics.
pub async fn dispatch(
    profile: &Profile,
    signer: &(dyn Signer + Send + Sync),
    message: &str,
    network_passphrase: Option<&str>,
    address: Option<&str>,
) -> Result<serde_json::Value, Sep43Error> {
    // Network-passphrase guard: fail-closed if the client supplies a mismatched
    // passphrase. The passphrase is not mixed into the signed bytes; this is a
    // caller-intent validation gate only.
    if let Some(provided) = network_passphrase
        && provided != profile.network_passphrase
    {
        return Err(Sep43Error::InvalidNetworkPassphrase {
            detail: format!(
                "provided passphrase does not match profile: \
                 expected {:?}, got {provided:?}",
                profile.network_passphrase
            ),
        });
    }

    // The optional address must name the key that will actually sign. This
    // refuses C/M addresses on this G-only path (they cannot equal a G-strkey).
    if let Some(addr) = address {
        validate_strkey(addr)?;
        let signer_pubkey =
            signer
                .public_key()
                .await
                .map_err(|e| Sep43Error::SignerUnavailable {
                    detail: format!("public_key fetch failed: {e}"),
                })?;
        let signer_g = stellar_strkey::ed25519::PublicKey(signer_pubkey.0)
            .to_string()
            .to_string();
        if addr != signer_g {
            return Err(Sep43Error::InvalidAddress {
                detail: format!(
                    "provided address does not match the signing key (expected {signer_g:?})"
                ),
                expected_type: "G-strkey matching the signing key",
            });
        }
    }

    let (signature_b64, signer_address) = sign_message_bytes(message.as_bytes(), signer).await?;

    Ok(serde_json::json!({
        "signedMessage": signature_b64,
        "signerAddress": signer_address,
    }))
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

    use stellar_agent_core::profile::schema::Profile;
    use stellar_agent_network::signing::Signer as _;
    use stellar_agent_network::signing::SoftwareSigningKey;

    use super::*;

    fn testnet_profile() -> Profile {
        Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct").build()
    }

    #[tokio::test]
    async fn dispatch_empty_message_returns_error() {
        let profile = testnet_profile();
        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let err = dispatch(&profile, &key, "", None, None).await.unwrap_err();
        assert!(
            matches!(err, Sep43Error::InvalidMessage { .. }),
            "got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
    }

    #[tokio::test]
    async fn dispatch_nonempty_message_returns_signed_message() {
        use base64::Engine as _;

        let profile = testnet_profile();
        let key = SoftwareSigningKey::new_from_bytes([99u8; 32]);
        let result = dispatch(&profile, &key, "hello sep43", None, None)
            .await
            .unwrap();
        let b64_sig = result["signedMessage"].as_str().unwrap();
        // Base64-decode the signature; must be exactly 64 bytes.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(b64_sig)
            .expect("signedMessage must be valid base64");
        assert_eq!(sig_bytes.len(), 64, "signedMessage must decode to 64 bytes");
        let signer_addr = result["signerAddress"].as_str().unwrap();
        assert!(signer_addr.starts_with('G'), "signer addr: {signer_addr}");
    }

    #[tokio::test]
    async fn dispatch_passphrase_none_succeeds() {
        use base64::Engine as _;

        // network_passphrase = None must not be treated as a mismatch.
        let profile = testnet_profile();
        let key = SoftwareSigningKey::new_from_bytes([0x50u8; 32]);
        let result = dispatch(&profile, &key, "hello none-passphrase", None, None)
            .await
            .expect("dispatch with None passphrase must succeed");
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(result["signedMessage"].as_str().unwrap())
            .expect("signedMessage must be valid base64");
        assert_eq!(sig_bytes.len(), 64, "signedMessage must decode to 64 bytes");
    }

    #[tokio::test]
    async fn dispatch_passphrase_correct_succeeds() {
        use base64::Engine as _;

        // network_passphrase = Some(<correct>) must pass the guard and sign.
        let profile = testnet_profile();
        let key = SoftwareSigningKey::new_from_bytes([0x51u8; 32]);
        let result = dispatch(
            &profile,
            &key,
            "hello correct-passphrase",
            Some("Test SDF Network ; September 2015"),
            None,
        )
        .await
        .expect("dispatch with matching passphrase must succeed");
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(result["signedMessage"].as_str().unwrap())
            .expect("signedMessage must be valid base64");
        assert_eq!(sig_bytes.len(), 64, "signedMessage must decode to 64 bytes");
    }

    #[tokio::test]
    async fn dispatch_passphrase_mismatch_returns_error() {
        // network_passphrase = Some(<wrong>) must be rejected fail-closed before
        // any signing attempt.  Mirrors the equivalent test in sign_transaction.
        let profile = testnet_profile();
        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let err = dispatch(
            &profile,
            &key,
            "hello mismatch",
            Some("Public Global Stellar Network ; September 2015"),
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, Sep43Error::InvalidNetworkPassphrase { .. }),
            "got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
    }

    #[tokio::test]
    async fn dispatch_invalid_address_arg_returns_error() {
        let profile = testnet_profile();
        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let err = dispatch(&profile, &key, "hello", None, Some("not-a-strkey"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep43Error::InvalidAddress { .. }),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_address_matches_active_signer_ok() {
        use base64::Engine as _;

        // The address-validation success branch: provided address is a valid
        // G-strkey matching the signer's own key.
        let profile = testnet_profile();
        let key = SoftwareSigningKey::new_from_bytes([0x90u8; 32]);
        let pk = key.public_key().await.unwrap();
        let g_strkey: String = stellar_strkey::ed25519::PublicKey(pk.0)
            .to_string()
            .to_string();

        let result = dispatch(
            &profile,
            &key,
            "hello dispatch",
            None,
            Some(g_strkey.as_str()),
        )
        .await
        .expect("dispatch with matching address must succeed");

        let b64_sig = result["signedMessage"].as_str().unwrap();
        // Base64-decode the signature; must be exactly 64 bytes.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(b64_sig)
            .expect("signedMessage must be valid base64");
        assert_eq!(sig_bytes.len(), 64, "signedMessage must decode to 64 bytes");
        let signer_addr = result["signerAddress"].as_str().unwrap();
        assert!(signer_addr.starts_with('G'), "signer addr: {signer_addr}");
    }

    #[tokio::test]
    async fn dispatch_address_mismatch_returns_invalid_address() {
        // The address-mismatch guard: a valid G-strkey arg that is NOT the
        // signer's own key must return InvalidAddress unconditionally.
        //
        // Signer seed [0x91u8; 32] produces a G-key that differs from the
        // literal fixture below; assert_ne! verifies this is a true mismatch
        // (the test is not vacuous).
        let profile = testnet_profile();
        let key = SoftwareSigningKey::new_from_bytes([0x91u8; 32]);
        let pk = key.public_key().await.unwrap();
        let signer_g = stellar_strkey::ed25519::PublicKey(pk.0)
            .to_string()
            .to_string();

        let other_g = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
        assert_ne!(
            signer_g.as_str(),
            other_g,
            "signer key must differ from the fixture address for this test to be non-vacuous"
        );

        let err = dispatch(&profile, &key, "hello", None, Some(other_g))
            .await
            .unwrap_err();

        assert!(
            matches!(err, Sep43Error::InvalidAddress { .. }),
            "mismatched address must return InvalidAddress, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
    }
}
