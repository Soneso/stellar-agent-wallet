//! SEP-23 envelope signing helper.
//!
//! `attach_signature` is the single call site for SEP-23
//! payload-construction + signature-attachment logic. Both
//! `ClassicOpBuilder::build_and_sign` and the CLI `pay.rs::sign_envelope`
//! function delegate here.
//!
//! # Signing discipline
//!
//! The helper decodes the base64 envelope, constructs the SEP-23
//! `TransactionSignaturePayload`, SHA-256 hashes it, calls
//! `signer.sign_tx_payload` exactly once, attaches the resulting
//! `DecoratedSignature`, and re-encodes the signed envelope as base64.
//! Signing is fully off-chain.
//!
//! Retries in the submit layer operate on the already-signed bytes;
//! this function is never called again after initial signing.

use sha2::{Digest, Sha256};
use stellar_agent_core::error::{ProtocolError, WalletError};
use stellar_xdr::{
    DecoratedSignature, Hash, Limits, ReadXdr, Signature, SignatureHint, TransactionEnvelope,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction, WriteXdr,
};

use crate::signing::Signer;

/// Decodes a base64 `TransactionEnvelope`, attaches an ed25519 signature
/// constructed via `signer`, and returns the re-encoded signed envelope.
///
/// This is the single SEP-23 signing call site. It handles both `Tx` (V1) and
/// `TxFeeBump` envelopes (the SEP-23 tagged-transaction variants); legacy `TxV0`
/// envelopes are rejected.
///
/// # Errors
///
/// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`] if
///   the envelope cannot be decoded or re-encoded, or is a legacy `TxV0`
///   envelope.
/// - [`WalletError::Auth`] or [`WalletError::WalletState`] from the signer.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::signing::SoftwareSigningKey;
/// use stellar_agent_network::signing::envelope_signing::attach_signature;
///
/// # async fn run(unsigned_xdr: &str) -> Result<(), stellar_agent_core::WalletError> {
/// let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
/// let signed = attach_signature(unsigned_xdr, &key, "Test SDF Network ; September 2015").await?;
/// # Ok(()) }
/// ```
pub async fn attach_signature(
    unsigned_envelope_xdr: &str,
    signer: &dyn Signer,
    network_passphrase: &str,
) -> Result<String, WalletError> {
    // The unsigned envelope is caller-supplied and untrusted; bounded limits
    // prevent a deeply nested auth-invocation tree from exhausting the stack.
    let mut envelope = TransactionEnvelope::from_xdr_base64(
        unsigned_envelope_xdr,
        stellar_agent_xdr_limits::untrusted_decode_limits(unsigned_envelope_xdr.len()),
    )
    .map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("failed to decode TransactionEnvelope: {e}"),
        })
    })?;

    // SEP-23 covers V1 `Tx` and `TxFeeBump` envelopes. The tagged transaction
    // selects the matching payload variant; legacy V0 envelopes are rejected.
    let network_id_hash = Hash(Sha256::digest(network_passphrase.as_bytes()).into());
    let tagged_tx = match &envelope {
        TransactionEnvelope::Tx(v1) => {
            TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx.clone())
        }
        TransactionEnvelope::TxFeeBump(fb) => {
            TransactionSignaturePayloadTaggedTransaction::TxFeeBump(fb.tx.clone())
        }
        TransactionEnvelope::TxV0(_) => {
            return Err(WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: "legacy V0 transaction envelopes are not supported; \
                         use a V1 Tx or TxFeeBump envelope"
                    .to_owned(),
            }));
        }
    };

    let sig_payload = TransactionSignaturePayload {
        network_id: network_id_hash,
        tagged_transaction: tagged_tx,
    };

    let payload_bytes = sig_payload.to_xdr(Limits::none()).map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("TransactionSignaturePayload XDR encode failed: {e}"),
        })
    })?;

    // SHA-256 the payload and invoke the signer exactly once.
    let tx_hash: [u8; 32] = Sha256::digest(&payload_bytes).into();
    let sig_bytes = signer.sign_tx_payload(&tx_hash).await?;

    // The hint is the last 4 bytes of the 32-byte public key.
    let public_key = signer.public_key().await?;
    let hint_bytes: [u8; 4] = [
        public_key.0[28],
        public_key.0[29],
        public_key.0[30],
        public_key.0[31],
    ];

    let decorated = DecoratedSignature {
        hint: SignatureHint(hint_bytes),
        // sig_bytes is [u8; 64]; BytesM<64> only exposes a fallible TryFrom, so
        // the conversion is mapped through `?` even though it cannot fail here.
        signature: Signature(sig_bytes.to_vec().try_into().map_err(|_| {
            WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: "signature is not 64 bytes".to_owned(),
            })
        })?),
    };

    // Append the decorated signature to the matching envelope's signature list.
    let too_many = |_| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: "too many signatures for VecM<DecoratedSignature, 20>".to_owned(),
        })
    };
    match &mut envelope {
        TransactionEnvelope::Tx(v1) => {
            let mut sigs: Vec<DecoratedSignature> = v1.signatures.to_vec();
            sigs.push(decorated);
            v1.signatures = sigs.try_into().map_err(too_many)?;
        }
        TransactionEnvelope::TxFeeBump(fb) => {
            let mut sigs: Vec<DecoratedSignature> = fb.signatures.to_vec();
            sigs.push(decorated);
            fb.signatures = sigs.try_into().map_err(too_many)?;
        }
        TransactionEnvelope::TxV0(_) => {
            return Err(WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: "legacy V0 transaction envelopes are not supported".to_owned(),
            }));
        }
    }

    envelope.to_xdr_base64(Limits::none()).map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("signed TransactionEnvelope XDR base64 encode failed: {e}"),
        })
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]
mod tests {
    use super::*;
    use crate::signing::SoftwareSigningKey;
    use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
    use sha2::{Digest, Sha256};
    use stellar_agent_core::error::{ProtocolError, WalletError};
    use stellar_xdr::{
        FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
        FeeBumpTransactionInnerTx, Hash, Limits, Memo, MuxedAccount, Preconditions, ReadXdr,
        SequenceNumber, Transaction, TransactionEnvelope, TransactionExt,
        TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction, TransactionV0,
        TransactionV0Envelope, TransactionV0Ext, TransactionV1Envelope, Uint256, WriteXdr,
    };

    // ── Fixture helpers ───────────────────────────────────────────────────────

    const TESTNET: &str = "Test SDF Network ; September 2015";
    const MAINNET: &str = "Public Global Stellar Network ; September 2015";

    /// Builds a minimal, unsigned `TransactionEnvelope::Tx` (V1) containing a
    /// single Payment operation and returns its base64 XDR.
    ///
    /// The source account is derived from seed `[1u8; 32]` (public test fixture).
    fn unsigned_v1_envelope_b64() -> String {
        use stellar_agent_core::StellarAmount;

        let mut builder = crate::builder::ClassicOpBuilder::new(
            // G-strkey for seed [1u8; 32] via ed25519-dalek:
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
            101,
            TESTNET,
            100,
        );
        builder
            .payment(
                "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
                StellarAmount::from_stroops(10_000_000),
                &crate::builder::Asset::Native,
            )
            .expect("payment op");
        builder.build().expect("build unsigned envelope")
    }

    /// Builds a `TransactionEnvelope::TxV0` and returns its base64 XDR.
    fn v0_envelope_b64() -> String {
        let envelope = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx: TransactionV0 {
                source_account_ed25519: Uint256([0u8; 32]),
                fee: 100,
                seq_num: SequenceNumber(1),
                time_bounds: None,
                memo: Memo::None,
                operations: vec![].try_into().expect("empty ops"),
                ext: TransactionV0Ext::V0,
            },
            signatures: vec![].try_into().expect("empty sigs"),
        });
        envelope.to_xdr_base64(Limits::none()).expect("encode v0")
    }

    /// Builds a `TransactionEnvelope::TxFeeBump` and returns its base64 XDR.
    fn fee_bump_envelope_b64() -> String {
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
        let fb_envelope = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: MuxedAccount::Ed25519(Uint256([0u8; 32])),
                fee: 200,
                inner_tx: FeeBumpTransactionInnerTx::Tx(inner_v1),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: vec![].try_into().expect("empty sigs"),
        });
        fb_envelope
            .to_xdr_base64(Limits::none())
            .expect("encode fee-bump")
    }

    // ── Happy-path tests ──────────────────────────────────────────────────────

    /// `attach_signature` on a valid unsigned V1 envelope returns a base64
    /// string that decodes to a `TransactionEnvelope::Tx` with exactly one
    /// `DecoratedSignature`.
    #[tokio::test]
    async fn happy_path_produces_one_decorated_signature() {
        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let unsigned = unsigned_v1_envelope_b64();

        let signed = attach_signature(&unsigned, &key, TESTNET)
            .await
            .expect("attach_signature must succeed");

        let envelope = TransactionEnvelope::from_xdr_base64(&signed, Limits::none())
            .expect("signed envelope must decode");

        match envelope {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(
                    v1.signatures.len(),
                    1,
                    "exactly one DecoratedSignature expected"
                );
            }
            other => panic!(
                "expected TransactionEnvelope::Tx, got discriminant {:?}",
                other.discriminant()
            ),
        }
    }

    /// The attached signature is a valid ed25519 signature over the SEP-23
    /// `TransactionSignaturePayload` hash.
    ///
    /// Verifies end-to-end: construct the same SEP-23 payload, SHA-256 hash it,
    /// and assert the attached signature verifies under the signer's public key.
    #[tokio::test]
    async fn attached_signature_verifies_under_sep23_payload() {
        let seed = [3u8; 32];
        let key = SoftwareSigningKey::new_from_bytes(seed);
        let unsigned = unsigned_v1_envelope_b64();

        let signed_b64 = attach_signature(&unsigned, &key, TESTNET)
            .await
            .expect("attach_signature must succeed");

        // Reconstruct the SEP-23 hash independently.
        let unsigned_env =
            TransactionEnvelope::from_xdr_base64(&unsigned, Limits::none()).expect("decode");
        let tx = match &unsigned_env {
            TransactionEnvelope::Tx(v1) => v1.tx.clone(),
            _ => panic!("expected Tx"),
        };
        let network_id_hash = Hash(Sha256::digest(TESTNET.as_bytes()).into());
        let tagged_tx = TransactionSignaturePayloadTaggedTransaction::Tx(tx);
        let sig_payload = TransactionSignaturePayload {
            network_id: network_id_hash,
            tagged_transaction: tagged_tx,
        };
        let payload_bytes = sig_payload.to_xdr(Limits::none()).expect("encode payload");
        let expected_hash: [u8; 32] = Sha256::digest(&payload_bytes).into();

        // Extract the attached signature from the signed envelope.
        let signed_env = TransactionEnvelope::from_xdr_base64(&signed_b64, Limits::none())
            .expect("decode signed");
        let sig_bytes = match &signed_env {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(v1.signatures.len(), 1);
                v1.signatures[0].signature.0.as_slice().to_vec()
            }
            _ => panic!("expected Tx"),
        };

        // Verify with ed25519-dalek.
        let pk_strkey = key.public_key().await.expect("public_key");
        let vk = VerifyingKey::from_bytes(&pk_strkey.0).expect("verifying key");
        let sig_arr: [u8; 64] = sig_bytes.try_into().expect("signature must be 64 bytes");
        let sig = DalekSignature::from_bytes(&sig_arr);
        vk.verify(&expected_hash, &sig)
            .expect("signature must verify against reconstructed SEP-23 payload hash");
    }

    /// The hint bytes are the last 4 bytes of the ed25519 public key.
    ///
    /// Stellar hint convention: `DecoratedSignature.hint = public_key[28..32]`.
    #[tokio::test]
    async fn hint_bytes_are_last_four_bytes_of_public_key() {
        let key = SoftwareSigningKey::new_from_bytes([7u8; 32]);
        let unsigned = unsigned_v1_envelope_b64();

        let signed_b64 = attach_signature(&unsigned, &key, TESTNET)
            .await
            .expect("attach_signature must succeed");

        let expected_pk = key.public_key().await.expect("public_key");
        let expected_hint: [u8; 4] = expected_pk.0[28..32].try_into().expect("slice len");

        let signed_env =
            TransactionEnvelope::from_xdr_base64(&signed_b64, Limits::none()).expect("decode");
        match &signed_env {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(v1.signatures.len(), 1, "exactly one signature");
                assert_eq!(
                    v1.signatures[0].hint.0, expected_hint,
                    "hint must be last 4 bytes of public key"
                );
            }
            _ => panic!("expected Tx"),
        }
    }

    /// `attach_signature` is deterministic: the same key, passphrase, and
    /// unsigned envelope always produce the identical signed base64 string.
    ///
    /// ed25519 is a deterministic signature scheme (RFC 8032 §5.1); this test
    /// confirms the SEP-23 payload construction path is also deterministic.
    #[tokio::test]
    async fn signing_is_deterministic() {
        let key = SoftwareSigningKey::new_from_bytes([42u8; 32]);
        let unsigned = unsigned_v1_envelope_b64();

        let signed_1 = attach_signature(&unsigned, &key, TESTNET)
            .await
            .expect("first call");
        let signed_2 = attach_signature(&unsigned, &key, TESTNET)
            .await
            .expect("second call");

        assert_eq!(
            signed_1, signed_2,
            "identical inputs must produce identical signed envelopes"
        );
    }

    /// Different network passphrases produce different signatures over the same
    /// envelope and key.
    ///
    /// The SEP-23 `TransactionSignaturePayload.network_id` is `SHA-256(passphrase)`,
    /// so a different passphrase changes the pre-image and therefore the hash and
    /// the ed25519 signature.
    #[tokio::test]
    async fn different_passphrase_produces_different_signature() {
        let key = SoftwareSigningKey::new_from_bytes([5u8; 32]);
        let unsigned = unsigned_v1_envelope_b64();

        let signed_testnet = attach_signature(&unsigned, &key, TESTNET)
            .await
            .expect("testnet sign");
        let signed_mainnet = attach_signature(&unsigned, &key, MAINNET)
            .await
            .expect("mainnet sign");

        // Different network_id hash → different SEP-23 payload hash → different signature.
        assert_ne!(
            signed_testnet, signed_mainnet,
            "different passphrases must produce different signatures"
        );
    }

    /// Two sequential calls to `attach_signature` accumulate two signatures.
    ///
    /// The second call operates on the already-signed envelope from the first
    /// call. Both `DecoratedSignature` entries must be present and have the
    /// correct hints for their respective signing keys.
    #[tokio::test]
    async fn sequential_sign_accumulates_signatures() {
        let key_a = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let key_b = SoftwareSigningKey::new_from_bytes([2u8; 32]);
        let unsigned = unsigned_v1_envelope_b64();

        let once_signed = attach_signature(&unsigned, &key_a, TESTNET)
            .await
            .expect("first sign");
        let twice_signed = attach_signature(&once_signed, &key_b, TESTNET)
            .await
            .expect("second sign");

        let envelope =
            TransactionEnvelope::from_xdr_base64(&twice_signed, Limits::none()).expect("decode");

        match envelope {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(
                    v1.signatures.len(),
                    2,
                    "two sequential signers must produce two DecoratedSignatures"
                );
                // Verify hints match the respective public keys.
                let pk_a = key_a.public_key().await.expect("pk_a");
                let pk_b = key_b.public_key().await.expect("pk_b");
                let hint_a: [u8; 4] = pk_a.0[28..32].try_into().expect("4 bytes");
                let hint_b: [u8; 4] = pk_b.0[28..32].try_into().expect("4 bytes");
                assert_eq!(v1.signatures[0].hint.0, hint_a, "first hint must be key_a");
                assert_eq!(v1.signatures[1].hint.0, hint_b, "second hint must be key_b");
            }
            _ => panic!("expected Tx"),
        }
    }

    /// The 21st call to `attach_signature` on the same envelope triggers a
    /// `WalletError::Protocol(ProtocolError::XdrCodecFailed)` with a detail
    /// message containing "too many signatures".
    ///
    /// `VecM<DecoratedSignature, 20>` is the Stellar XDR limit.
    #[tokio::test]
    async fn twenty_first_signature_exceeds_stellar_limit() {
        let key = SoftwareSigningKey::new_from_bytes([9u8; 32]);
        let unsigned = unsigned_v1_envelope_b64();

        // Attach 20 signatures using the same key (no real uniqueness required;
        // the limit check fires on the count, not on uniqueness of signers).
        let mut current = unsigned;
        for i in 0..20 {
            current = attach_signature(&current, &key, TESTNET)
                .await
                .unwrap_or_else(|e| panic!("signature {i} failed: {e:?}"));
        }

        // The 21st call must fail with XdrCodecFailed / too many signatures.
        let err = attach_signature(&current, &key, TESTNET)
            .await
            .expect_err("21st signature must exceed VecM<_, 20> limit");

        assert!(
            matches!(
                &err,
                WalletError::Protocol(ProtocolError::XdrCodecFailed { detail })
                    if detail.contains("too many signatures")
            ),
            "expected XdrCodecFailed with 'too many signatures', got: {err:?}"
        );
    }

    // ── Error-path tests ──────────────────────────────────────────────────────

    /// Invalid base64 returns `WalletError::Protocol(ProtocolError::XdrCodecFailed)`
    /// with a detail containing "failed to decode TransactionEnvelope".
    #[tokio::test]
    async fn invalid_base64_returns_xdr_codec_failed() {
        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);

        let err = attach_signature("not-valid-base64!!!", &key, TESTNET)
            .await
            .expect_err("invalid base64 must fail");

        assert!(
            matches!(
                &err,
                WalletError::Protocol(ProtocolError::XdrCodecFailed { detail })
                    if detail.contains("failed to decode TransactionEnvelope")
            ),
            "expected XdrCodecFailed with decode message, got: {err:?}"
        );
    }

    /// Valid base64 that does not decode to any recognized XDR type returns
    /// `XdrCodecFailed` with "failed to decode TransactionEnvelope".
    #[tokio::test]
    async fn random_base64_not_xdr_returns_xdr_codec_failed() {
        use base64::Engine as _;
        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        // 64 random bytes that are valid base64 but not a valid TransactionEnvelope XDR.
        let garbage_b64 = base64::engine::general_purpose::STANDARD.encode([0xAA_u8; 64]);

        let err = attach_signature(&garbage_b64, &key, TESTNET)
            .await
            .expect_err("garbage XDR must fail");

        assert!(
            matches!(
                &err,
                WalletError::Protocol(ProtocolError::XdrCodecFailed { detail })
                    if detail.contains("failed to decode TransactionEnvelope")
            ),
            "expected XdrCodecFailed for garbage XDR bytes, got: {err:?}"
        );
    }

    /// A `TransactionEnvelope::TxV0` (legacy format) is rejected with
    /// `XdrCodecFailed`.
    ///
    /// TxV0 is a legacy format from before Protocol 13 and is not part of the
    /// SEP-23 tagged-transaction set. `attach_signature` rejects it immediately
    /// to prevent signing a format the network no longer accepts.
    #[tokio::test]
    async fn txv0_envelope_returns_xdr_codec_failed() {
        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let v0_b64 = v0_envelope_b64();

        let err = attach_signature(&v0_b64, &key, TESTNET)
            .await
            .expect_err("TxV0 must be rejected");

        assert!(
            matches!(
                &err,
                WalletError::Protocol(ProtocolError::XdrCodecFailed { detail })
                    if detail.contains("legacy V0")
            ),
            "expected XdrCodecFailed mentioning legacy V0, got: {err:?}"
        );
    }

    /// A `TransactionEnvelope::TxFeeBump` is signed over the SEP-23
    /// `TxFeeBump`-tagged payload, and the attached signature verifies under the
    /// signer's public key.
    #[tokio::test]
    async fn txfeebump_envelope_is_signed_over_feebump_payload() {
        let seed = [5u8; 32];
        let key = SoftwareSigningKey::new_from_bytes(seed);
        let fb_b64 = fee_bump_envelope_b64();

        let signed_b64 = attach_signature(&fb_b64, &key, TESTNET)
            .await
            .expect("fee-bump envelope must be signed");

        // Reconstruct the SEP-23 hash over the TxFeeBump-tagged payload.
        let unsigned_env =
            TransactionEnvelope::from_xdr_base64(&fb_b64, Limits::none()).expect("decode");
        let fb_tx = match &unsigned_env {
            TransactionEnvelope::TxFeeBump(fb) => fb.tx.clone(),
            _ => panic!("expected TxFeeBump"),
        };
        let network_id_hash = Hash(Sha256::digest(TESTNET.as_bytes()).into());
        let tagged_tx = TransactionSignaturePayloadTaggedTransaction::TxFeeBump(fb_tx);
        let sig_payload = TransactionSignaturePayload {
            network_id: network_id_hash,
            tagged_transaction: tagged_tx,
        };
        let payload_bytes = sig_payload.to_xdr(Limits::none()).expect("encode payload");
        let expected_hash: [u8; 32] = Sha256::digest(&payload_bytes).into();

        // Extract the attached signature from the signed fee-bump envelope.
        let signed_env = TransactionEnvelope::from_xdr_base64(&signed_b64, Limits::none())
            .expect("decode signed");
        let sig_bytes = match &signed_env {
            TransactionEnvelope::TxFeeBump(fb) => {
                assert_eq!(
                    fb.signatures.len(),
                    1,
                    "exactly one signature on the fee-bump"
                );
                fb.signatures[0].signature.0.as_slice().to_vec()
            }
            _ => panic!("expected TxFeeBump"),
        };

        let pk_strkey = key.public_key().await.expect("public_key");
        let vk = VerifyingKey::from_bytes(&pk_strkey.0).expect("verifying key");
        let sig_arr: [u8; 64] = sig_bytes.try_into().expect("signature must be 64 bytes");
        let sig = DalekSignature::from_bytes(&sig_arr);
        vk.verify(&expected_hash, &sig)
            .expect("fee-bump signature must verify over the TxFeeBump SEP-23 payload");
    }

    /// The attached signature is exactly 64 bytes (ed25519 wire format).
    #[tokio::test]
    async fn attached_signature_is_64_bytes() {
        let key = SoftwareSigningKey::new_from_bytes([11u8; 32]);
        let unsigned = unsigned_v1_envelope_b64();

        let signed_b64 = attach_signature(&unsigned, &key, TESTNET)
            .await
            .expect("must succeed");

        let env =
            TransactionEnvelope::from_xdr_base64(&signed_b64, Limits::none()).expect("decode");
        match env {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(v1.signatures.len(), 1);
                assert_eq!(
                    v1.signatures[0].signature.0.len(),
                    64,
                    "ed25519 signature must be exactly 64 bytes"
                );
            }
            _ => panic!("expected Tx"),
        }
    }

    /// Signing with two different keys over the same unsigned envelope produces
    /// two different signatures (sanity-check that key uniqueness is preserved).
    #[tokio::test]
    async fn different_keys_produce_different_signatures() {
        let key_a = SoftwareSigningKey::new_from_bytes([10u8; 32]);
        let key_b = SoftwareSigningKey::new_from_bytes([20u8; 32]);
        let unsigned = unsigned_v1_envelope_b64();

        let signed_a = attach_signature(&unsigned, &key_a, TESTNET)
            .await
            .expect("key_a sign");
        let signed_b = attach_signature(&unsigned, &key_b, TESTNET)
            .await
            .expect("key_b sign");

        // Different keys over the same transaction must produce different envelopes.
        assert_ne!(
            signed_a, signed_b,
            "different signing keys must produce different decorated signatures"
        );
    }

    /// The output envelope is valid XDR and decodes symmetrically:
    /// re-encoding the decoded envelope produces the same base64 bytes.
    #[tokio::test]
    async fn signed_envelope_round_trips_to_identical_bytes() {
        let key = SoftwareSigningKey::new_from_bytes([13u8; 32]);
        let unsigned = unsigned_v1_envelope_b64();

        let signed_b64 = attach_signature(&unsigned, &key, TESTNET)
            .await
            .expect("sign");

        let env =
            TransactionEnvelope::from_xdr_base64(&signed_b64, Limits::none()).expect("decode");
        let re_encoded = env.to_xdr_base64(Limits::none()).expect("re-encode");

        assert_eq!(
            signed_b64, re_encoded,
            "decoded-then-re-encoded envelope must be byte-for-byte identical"
        );
    }

    // ── Depth-bomb regression ─────────────────────────────────────────────────

    /// A `TransactionEnvelope` carrying a 600-deep `sub_invocations` chain is
    /// rejected by `attach_signature` before the signer is invoked.
    ///
    /// The bounded decoder at the start of `attach_signature` caps recursion at
    /// 500 and returns an `XdrCodecFailed` error, so the signer is never
    /// reached and the test stack is not exhausted.
    ///
    /// The deep fixture is encoded with `Limits::none()` (write-side; writing
    /// 600 levels fits the test stack). Only the bounded production path decodes.
    #[tokio::test]
    async fn attach_signature_deep_sub_invocations_rejected_before_signer() {
        use stellar_xdr::{
            ContractId, InvokeContractArgs, InvokeHostFunctionOp, ScAddress,
            SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
            SorobanCredentials,
        };

        let leaf_fn = SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([0xABu8; 32]))),
            function_name: "g".try_into().expect("short name"),
            args: stellar_xdr::VecM::default(),
        });

        // Build the 600-deep chain iteratively (outermost built last).
        let mut inner = SorobanAuthorizedInvocation {
            function: leaf_fn.clone(),
            sub_invocations: stellar_xdr::VecM::default(),
        };
        for _ in 0..599 {
            inner = SorobanAuthorizedInvocation {
                function: leaf_fn.clone(),
                sub_invocations: vec![inner].try_into().expect("single-element VecM"),
            };
        }

        let auth_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: inner,
        };

        let invoke_op = stellar_xdr::Operation {
            source_account: None,
            body: stellar_xdr::OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: stellar_xdr::HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([0xCDu8; 32]))),
                    function_name: "go".try_into().expect("short name"),
                    args: stellar_xdr::VecM::default(),
                }),
                auth: vec![auth_entry].try_into().expect("single-entry VecM"),
            }),
        };

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([1u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![invoke_op].try_into().expect("single op"),
            ext: TransactionExt::V0,
        };
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: stellar_xdr::VecM::default(),
        });

        // Encode with Limits::none() (write-side; does not decode).
        let deep_b64 = envelope
            .to_xdr_base64(Limits::none())
            .expect("encoding a deep structure must succeed");

        let key = SoftwareSigningKey::new_from_bytes([99u8; 32]);
        let result = attach_signature(&deep_b64, &key, TESTNET).await;

        assert!(
            result.is_err(),
            "a 600-deep sub_invocations chain must be rejected by attach_signature"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                WalletError::Protocol(ProtocolError::XdrCodecFailed { .. })
            ),
            "expected XdrCodecFailed from depth-exceeded decode, got: {err:?}"
        );
    }
}
