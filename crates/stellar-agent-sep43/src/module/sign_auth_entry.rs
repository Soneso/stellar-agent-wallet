//! SEP-43 `signAuthEntry` method dispatch.
//!
//! Signs a base64 XDR `HashIdPreimage::SorobanAuthorization` preimage with the
//! active profile's signing key and returns the base64 raw signature plus the
//! signer's address.
//!
//! Reference: SEP-43 v1.2.1 `signAuthEntry`. Wallets-Kit canonical response
//! shape `{ signedAuthEntry: string; signerAddress?: string }`, where
//! `signedAuthEntry` is the base64-encoded 64-byte ed25519 signature over
//! `SHA256(preimage)`. The requester assembles the signature into the final
//! `SorobanAuthorizationEntry`.

use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::signing::Signer;

use crate::{address::validate_strkey, error::Sep43Error, signing::sign_soroban_auth_entry};

/// Dispatches the SEP-43 `signAuthEntry` method.
///
/// Signs the `preimage_xdr` (a base64 `HashIdPreimage::SorobanAuthorization`)
/// with the active profile signer and returns
/// `{ "signedAuthEntry": "<base64 signature>", "signerAddress": "G..." }`.
///
/// # Argument validation
///
/// - If `network_passphrase` is `Some`, it must equal
///   `profile.network_passphrase`; mismatch → [`Sep43Error::InvalidNetworkPassphrase`].
/// - If `address` is `Some`, it must be a valid strkey AND must equal the
///   signing key's G-strkey; mismatch → [`Sep43Error::InvalidAddress`].
///
/// # Errors
///
/// - [`Sep43Error::InvalidNetworkPassphrase`] — passphrase mismatch, or the
///   preimage's `network_id` does not match the active network.
/// - [`Sep43Error::InvalidAddress`] — provided `address` is not a valid strkey
///   or does not match the signing key.
/// - [`Sep43Error::InvalidXdr`] — `preimage_xdr` is not valid base64 or not a
///   well-formed `HashIdPreimage`.
/// - [`Sep43Error::MalformedAuthEntry`] — the preimage is not the
///   `SorobanAuthorization` variant.
/// - [`Sep43Error::UserRejected`] — signer user-rejection.
/// - [`Sep43Error::SignerUnavailable`] — signer wallet-state error.
///
/// # Panics
///
/// Never panics.
pub async fn dispatch(
    profile: &Profile,
    signer: &(dyn Signer + Send + Sync),
    preimage_xdr: &str,
    network_passphrase: Option<&str>,
    address: Option<&str>,
) -> Result<serde_json::Value, Sep43Error> {
    // Validate the optional address argument shape first (no signer I/O).
    if let Some(addr) = address {
        validate_strkey(addr)?;
    }

    // The signing key is always an ed25519 G-key; resolve its G-strkey once for
    // both the optional-address guard and the response.
    let signer_pubkey = signer
        .public_key()
        .await
        .map_err(|e| Sep43Error::SignerUnavailable {
            detail: format!("public_key fetch failed: {e}"),
        })?;
    let signer_address = stellar_strkey::ed25519::PublicKey(signer_pubkey.0)
        .to_string()
        .to_string();

    // The optional address must name the key that will actually sign. This
    // refuses C/M addresses on this G-only path (they cannot equal a G-strkey).
    if let Some(addr) = address
        && addr != signer_address
    {
        return Err(Sep43Error::InvalidAddress {
            detail: format!(
                "provided address does not match the signing key (expected {signer_address:?})"
            ),
            expected_type: "G-strkey matching the signing key",
        });
    }

    let signature_b64 = sign_soroban_auth_entry(
        preimage_xdr,
        signer,
        &profile.network_passphrase,
        network_passphrase,
    )
    .await?;

    Ok(serde_json::json!({
        "signedAuthEntry": signature_b64,
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

    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    use stellar_agent_core::profile::schema::Profile;
    use stellar_agent_network::signing::Signer as _;
    use stellar_agent_network::signing::SoftwareSigningKey;

    use super::*;

    fn testnet_profile() -> Profile {
        Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct").build()
    }

    const TESTNET: &str = "Test SDF Network ; September 2015";

    /// Builds a `HashIdPreimage::SorobanAuthorization` preimage for `passphrase`
    /// and returns its base64 XDR.  Uses a minimal `ContractFn` invocation.
    fn minimal_soroban_auth_preimage_xdr(passphrase: &str) -> String {
        use stellar_xdr::{
            ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits,
            ScAddress, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, WriteXdr,
        };

        let network_id = Hash(Sha256::digest(passphrase.as_bytes()).into());
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(stellar_xdr::InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0xAAu8; 32]))),
                function_name: "test_fn".try_into().expect("short fn name"),
                args: vec![].try_into().expect("empty args"),
            }),
            sub_invocations: vec![].try_into().expect("empty sub-invocations"),
        };
        HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id,
            nonce: 99999,
            signature_expiration_ledger: 10000,
            invocation,
        })
        .to_xdr_base64(Limits::none())
        .expect("soroban auth preimage must encode")
    }

    #[tokio::test]
    async fn dispatch_invalid_xdr_returns_error() {
        let profile = testnet_profile();
        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let err = dispatch(&profile, &key, "not-valid-xdr", None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, Sep43Error::InvalidXdr { .. }), "got: {err:?}");
        assert_eq!(err.sep43_code(), -3);
    }

    #[tokio::test]
    async fn dispatch_passphrase_mismatch_returns_error() {
        let profile = testnet_profile();
        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let err = dispatch(
            &profile,
            &key,
            "AAAA",
            Some("Public Global Stellar Network ; September 2015"),
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, Sep43Error::InvalidNetworkPassphrase { .. }),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_invalid_address_arg_returns_error() {
        let profile = testnet_profile();
        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let err = dispatch(&profile, &key, "AAAA", None, Some("not-a-strkey"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep43Error::InvalidAddress { .. }),
            "got: {err:?}"
        );
    }

    /// SUCCESS: dispatch returns `{ signedAuthEntry: <base64 sig>, signerAddress: G... }`.
    /// Base64-decode `signedAuthEntry` to 64 bytes and independently verify the
    /// signature over `SHA256(preimage_bytes)`.
    #[tokio::test]
    async fn dispatch_success_returns_signed_auth_entry_and_signer_address() {
        use ed25519_dalek::{Signature, VerifyingKey};

        let key = SoftwareSigningKey::new_from_bytes([0x80u8; 32]);
        let pk = key.public_key().await.unwrap();
        let preimage_b64 = minimal_soroban_auth_preimage_xdr(TESTNET);

        let profile = testnet_profile();
        let result = dispatch(&profile, &key, &preimage_b64, None, None)
            .await
            .expect("dispatch must succeed with a valid preimage");

        let signed_entry_b64 = result["signedAuthEntry"].as_str().unwrap();
        let signer_addr = result["signerAddress"].as_str().unwrap();

        // signedAuthEntry must decode to exactly 64 bytes.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(signed_entry_b64)
            .expect("signedAuthEntry must be valid base64");
        assert_eq!(sig_bytes.len(), 64, "signedAuthEntry must be 64 bytes");
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();

        // Independently verify the signature over SHA256(preimage_bytes).
        let preimage_bytes = base64::engine::general_purpose::STANDARD
            .decode(&preimage_b64)
            .expect("preimage must be valid base64");
        let digest: [u8; 32] = Sha256::digest(&preimage_bytes).into();

        let vk = VerifyingKey::from_bytes(&pk.0).expect("signer pubkey must be valid ed25519");
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify_strict(&digest, &sig)
            .expect("signature must verify against SHA256(preimage_bytes)");

        assert!(signer_addr.starts_with('G'), "signer addr: {signer_addr}");
    }

    #[tokio::test]
    async fn dispatch_address_matches_active_signer_ok() {
        let key = SoftwareSigningKey::new_from_bytes([0x81u8; 32]);
        let pk = key.public_key().await.unwrap();
        let g_strkey: String = stellar_strkey::ed25519::PublicKey(pk.0)
            .to_string()
            .to_string();
        let preimage_b64 = minimal_soroban_auth_preimage_xdr(TESTNET);

        let profile =
            Profile::builder_testnet("svc", g_strkey.as_str(), "nonce-svc", "nonce-acct").build();

        let result = dispatch(&profile, &key, &preimage_b64, None, Some(g_strkey.as_str()))
            .await
            .expect("dispatch with matching address arg must succeed");

        // signedAuthEntry must decode to exactly 64 bytes.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(result["signedAuthEntry"].as_str().unwrap())
            .expect("signedAuthEntry must be valid base64");
        assert_eq!(sig_bytes.len(), 64, "signedAuthEntry must be 64 bytes");
        assert!(result["signerAddress"].as_str().unwrap().starts_with('G'));
    }

    /// Address mismatch: valid preimage + a valid G-strkey that differs from the
    /// signer's own key → strict `Sep43Error::InvalidAddress`, no disjunction.
    #[tokio::test]
    async fn dispatch_address_mismatch_returns_invalid_address() {
        let key = SoftwareSigningKey::new_from_bytes([0x82u8; 32]);
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

        let profile = Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct").build();
        // Use a valid preimage so the only possible error is InvalidAddress.
        let preimage_b64 = minimal_soroban_auth_preimage_xdr(TESTNET);

        let err = dispatch(&profile, &key, &preimage_b64, None, Some(other_g))
            .await
            .unwrap_err();

        assert!(
            matches!(err, Sep43Error::InvalidAddress { .. }),
            "address-mismatch guard must return InvalidAddress, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
    }
}
