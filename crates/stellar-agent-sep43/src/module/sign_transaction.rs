//! SEP-43 `signTransaction` method dispatch.
//!
//! Signs a base64-encoded `TransactionEnvelope` XDR and returns the signed
//! envelope with the signer's address.
//!
//! Reference: SEP-43 v1.2.1 `signTransaction`. Wallets-Kit canonical response shape:
//! `{ signedTxXdr: string; signerAddress?: string }`.
//!
//! # Supported envelope types
//!
//! This method handles `TransactionEnvelope::Tx` (V1) and
//! `TransactionEnvelope::TxFeeBump` envelopes via the SEP-23
//! `attach_signature` call site.  Legacy `TxV0` envelopes are rejected with
//! `Sep43Error::InvalidXdr`.  Smart-account submit-path routing is not handled
//! by this path.
//!
//! # `TransactionEnvelope` byte layout
//!
//! stellar-xdr `TransactionEnvelope` — Tx variant (`TransactionV1Envelope`)
//! contains `VecM<DecoratedSignature, 20>` for the signatures list.

use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::signing::Signer;

use crate::{address::validate_strkey, error::Sep43Error, signing::sign_classic_transaction};

/// Dispatches the SEP-43 `signTransaction` method.
///
/// Signs the `transaction_xdr` with the active profile signer and returns
/// `{ "signedTxXdr": "...", "signerAddress": "G..." }`.
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
/// - [`Sep43Error::InvalidNetworkPassphrase`] — passphrase mismatch.
/// - [`Sep43Error::InvalidAddress`] — provided `address` is not a valid strkey
///   or does not match the signing key.
/// - [`Sep43Error::InvalidXdr`] — `transaction_xdr` is not a valid base64
///   `TransactionEnvelope`, or is a legacy `TxV0` envelope.
/// - [`Sep43Error::UserRejected`] — the signer returned a user-rejection error.
/// - [`Sep43Error::SignerUnavailable`] — the signer is in an unusable state.
///
/// # Panics
///
/// Never panics.
pub async fn dispatch(
    profile: &Profile,
    signer: &(dyn Signer + Send + Sync),
    transaction_xdr: &str,
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

    let signed_xdr = sign_classic_transaction(
        transaction_xdr,
        signer,
        &profile.network_passphrase,
        network_passphrase,
    )
    .await?;

    Ok(serde_json::json!({
        "signedTxXdr": signed_xdr,
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
        assert_eq!(err.sep43_code(), -3);
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

    /// Builds a minimal valid unsigned `TransactionEnvelope::Tx` (V1) for
    /// sign_transaction dispatch tests.
    fn minimal_tx_v1_xdr(source_pk: &[u8; 32]) -> String {
        use stellar_xdr::{
            BumpSequenceOp, Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions,
            SequenceNumber, TimeBounds, TimePoint, Transaction, TransactionEnvelope,
            TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
        };

        let source = MuxedAccount::Ed25519(Uint256(*source_pk));
        let op = Operation {
            source_account: None,
            body: OperationBody::BumpSequence(BumpSequenceOp {
                bump_to: SequenceNumber(99),
            }),
        };
        let tx = Transaction {
            source_account: source,
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(0),
                max_time: TimePoint(0),
            }),
            memo: Memo::None,
            operations: vec![op]
                .try_into()
                .expect("single op must fit VecM<Operation,100>"),
            ext: TransactionExt::V0,
        };
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![]
                .try_into()
                .expect("empty sigs must fit VecM<DecoratedSignature,20>"),
        })
        .to_xdr_base64(Limits::none())
        .expect("minimal V1 envelope must encode")
    }

    #[tokio::test]
    async fn dispatch_success_returns_signed_tx_xdr_and_signer_address() {
        use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};

        let key = SoftwareSigningKey::new_from_bytes([0x70u8; 32]);
        let pk = key.public_key().await.unwrap();
        let unsigned_xdr = minimal_tx_v1_xdr(&pk.0);

        let profile = testnet_profile();
        let result = dispatch(&profile, &key, &unsigned_xdr, None, None)
            .await
            .expect("dispatch must succeed with valid V1 envelope");

        let signed_xdr = result["signedTxXdr"].as_str().unwrap();
        let signer_addr = result["signerAddress"].as_str().unwrap();

        // Exactly one DecoratedSignature must be attached.
        let env = TransactionEnvelope::from_xdr_base64(signed_xdr, Limits::none()).unwrap();
        let TransactionEnvelope::Tx(v1) = env else {
            panic!("expected Tx envelope");
        };
        assert_eq!(
            v1.signatures.len(),
            1,
            "exactly one signature must be attached"
        );
        assert!(
            signer_addr.starts_with('G'),
            "signer address: {signer_addr}"
        );
    }

    #[tokio::test]
    async fn dispatch_address_matches_active_signer_ok() {
        use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};

        let key = SoftwareSigningKey::new_from_bytes([0x71u8; 32]);
        let pk = key.public_key().await.unwrap();
        let g_strkey: String = stellar_strkey::ed25519::PublicKey(pk.0)
            .to_string()
            .to_string();

        let unsigned_xdr = minimal_tx_v1_xdr(&pk.0);
        let profile =
            Profile::builder_testnet("svc", g_strkey.as_str(), "nonce-svc", "nonce-acct").build();

        let result = dispatch(&profile, &key, &unsigned_xdr, None, Some(g_strkey.as_str()))
            .await
            .expect("dispatch with matching address arg must succeed");

        let signed_xdr = result["signedTxXdr"].as_str().unwrap();
        let env = TransactionEnvelope::from_xdr_base64(signed_xdr, Limits::none()).unwrap();
        let TransactionEnvelope::Tx(v1) = env else {
            panic!("expected Tx envelope");
        };
        assert_eq!(v1.signatures.len(), 1);
    }

    #[tokio::test]
    async fn dispatch_address_mismatch_returns_invalid_address() {
        // The address-mismatch guard fires when the `address` arg is a valid
        // G-strkey that does not equal the signer's own key. Using a valid
        // envelope (not garbage XDR) ensures the only reachable error is
        // InvalidAddress — the XDR decode cannot fail, so no InvalidXdr fallback
        // is possible.
        //
        // Signer seed [0x72u8; 32] produces a G-key that differs from the
        // fixture literal; assert_ne! verifies the mismatch is real.
        let key = SoftwareSigningKey::new_from_bytes([0x72u8; 32]);
        let pk = key.public_key().await.unwrap();
        let signer_g = stellar_strkey::ed25519::PublicKey(pk.0)
            .to_string()
            .to_string();

        let other_strkey = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
        assert_ne!(
            signer_g.as_str(),
            other_strkey,
            "signer key must differ from the fixture address for this test to be non-vacuous"
        );

        let profile = Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct").build();
        let valid_xdr = minimal_tx_v1_xdr(&pk.0);

        let err = dispatch(&profile, &key, &valid_xdr, None, Some(other_strkey))
            .await
            .unwrap_err();

        assert!(
            matches!(err, Sep43Error::InvalidAddress { .. }),
            "address-mismatch guard must return InvalidAddress, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
    }

    /// Builds a minimal `TransactionEnvelope::TxFeeBump` whose `fee_source` is
    /// the provided public key.  The inner `Tx` is a minimal V1 envelope.
    fn minimal_fee_bump_xdr(fee_source_pk: &[u8; 32]) -> String {
        use stellar_xdr::{
            FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
            FeeBumpTransactionInnerTx, Limits, Memo, MuxedAccount, Preconditions, SequenceNumber,
            Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256,
            WriteXdr,
        };

        let inner_v1 = TransactionV1Envelope {
            tx: Transaction {
                source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
                fee: 100,
                seq_num: SequenceNumber(1),
                cond: Preconditions::None,
                memo: Memo::None,
                operations: vec![].try_into().expect("empty ops"),
                ext: TransactionExt::V0,
            },
            signatures: vec![].try_into().expect("empty sigs"),
        };
        TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: MuxedAccount::Ed25519(Uint256(*fee_source_pk)),
                fee: 200,
                inner_tx: FeeBumpTransactionInnerTx::Tx(inner_v1),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: vec![].try_into().expect("empty sigs"),
        })
        .to_xdr_base64(Limits::none())
        .expect("fee-bump envelope must encode")
    }

    /// A `TransactionEnvelope::TxFeeBump` is signed correctly and the attached
    /// signature verifies over the SEP-23 `TxFeeBump`-tagged
    /// `TransactionSignaturePayload` hash.
    #[tokio::test]
    async fn dispatch_fee_bump_envelope_is_signed() {
        use ed25519_dalek::{Signature, VerifyingKey};
        use sha2::{Digest, Sha256};
        use stellar_xdr::{
            Hash, Limits, ReadXdr, TransactionEnvelope, TransactionSignaturePayload,
            TransactionSignaturePayloadTaggedTransaction, WriteXdr,
        };

        let key = SoftwareSigningKey::new_from_bytes([0x73u8; 32]);
        let pk = key.public_key().await.unwrap();
        let fb_xdr = minimal_fee_bump_xdr(&pk.0);

        let profile = testnet_profile();
        let result = dispatch(&profile, &key, &fb_xdr, None, None)
            .await
            .expect("dispatch must succeed for TxFeeBump envelope");

        let signed_xdr = result["signedTxXdr"].as_str().unwrap();

        // Decode and assert the result is a TxFeeBump with exactly one signature.
        let signed_env = TransactionEnvelope::from_xdr_base64(signed_xdr, Limits::none())
            .expect("signed fee-bump envelope must decode");
        let TransactionEnvelope::TxFeeBump(ref fb) = signed_env else {
            panic!("expected TransactionEnvelope::TxFeeBump, got: {signed_env:?}");
        };
        assert_eq!(
            fb.signatures.len(),
            1,
            "exactly one signature must be attached"
        );

        // Cryptographic verification: reconstruct the SEP-23 TxFeeBump-tagged
        // payload independently and verify the attached signature.
        //
        // Unsigned envelope is decoded from the original fb_xdr to extract the
        // FeeBumpTransaction value without the (empty) signatures list.
        let unsigned_env = TransactionEnvelope::from_xdr_base64(&fb_xdr, Limits::none())
            .expect("unsigned fee-bump envelope must decode");
        let TransactionEnvelope::TxFeeBump(ref unsigned_fb) = unsigned_env else {
            panic!("expected TxFeeBump when decoding fixture");
        };
        let passphrase = "Test SDF Network ; September 2015";
        let network_id = Hash(Sha256::digest(passphrase.as_bytes()).into());
        let tagged =
            TransactionSignaturePayloadTaggedTransaction::TxFeeBump(unsigned_fb.tx.clone());
        let payload_xdr = TransactionSignaturePayload {
            network_id,
            tagged_transaction: tagged,
        }
        .to_xdr(Limits::none())
        .expect("TransactionSignaturePayload must encode");
        let signing_hash: [u8; 32] = Sha256::digest(&payload_xdr).into();

        let raw_sig: [u8; 64] = fb.signatures[0]
            .signature
            .as_slice()
            .try_into()
            .expect("signature must be 64 bytes");

        let vk = VerifyingKey::from_bytes(&pk.0).expect("signer pubkey must be valid ed25519");
        let sig = Signature::from_bytes(&raw_sig);
        vk.verify_strict(&signing_hash, &sig)
            .expect("fee-bump signature must verify against the SEP-23 TxFeeBump payload hash");
    }
}
