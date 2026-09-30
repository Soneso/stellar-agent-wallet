//! Low-level signing dispatch for SEP-43 methods.
//!
//! Provides the three signing primitives consumed by the method modules:
//!
//! - [`sign_classic_transaction`]: SEP-23 envelope signing for
//!   `signTransaction` over classic `TransactionEnvelope::Tx` entries.
//! - [`sign_soroban_auth_entry`]: SEP-43 `signAuthEntry` signing over the
//!   `HashIdPreimage` of an authorization entry (envelope type 9
//!   `SorobanAuthorization` or type 10 `SorobanAuthorizationWithAddress`),
//!   returning a base64 raw signature.
//! - [`sign_message_bytes`]: SEP-53 message signing for `signMessage`, an
//!   ed25519 signature via `sign_tx_payload` over
//!   `SHA256("Stellar Signed Message:\n" ‖ message)`.
//!
//! # Canonical byte-layout references
//!
//! - stellar-xdr `TransactionEnvelope`: `Tx` variant carries
//!   `VecM<DecoratedSignature, 20>` for the signatures list.
//!
//! - stellar-xdr `HashIdPreimageSorobanAuthorization` (envelope type 9):
//!   preimage layout `{ network_id, nonce, signature_expiration_ledger,
//!   invocation }`; `HashIdPreimageSorobanAuthorizationWithAddress` (envelope
//!   type 10, CAP-71): `{ network_id, nonce, signature_expiration_ledger,
//!   address, invocation }`. The received preimage bytes are SHA-256-hashed to
//!   produce the auth-entry signing payload.
//!
//! # Call-site discipline
//!
//! - [`sign_classic_transaction`] delegates to
//!   `stellar_agent_network::signing::envelope_signing::attach_signature`:
//!   the single SEP-23 signing call site.
//! - [`sign_soroban_auth_entry`] invokes
//!   `Signer::sign_soroban_address_auth_payload` over the SHA-256 of the
//!   supplied preimage bytes: the auth-entry signing primitive.
//! - [`sign_message_bytes`] computes the SEP-53 message digest then invokes
//!   `Signer::sign_tx_payload` (the payload domain is the SEP-53 message digest,
//!   not a SEP-23 transaction, but the ed25519 primitive is identical).
//!
//! # No HTTP/HTTPS client surface
//!
//! This module MUST NOT introduce any `reqwest`, `ureq`, or similar HTTP
//! client dependency. Interop is stdio-based via MCP tools.

use base64::Engine as _;
use sha2::{Digest, Sha256};
use stellar_agent_core::error::WalletError;
use stellar_agent_core::observability::redact::redact_strkey_first5_last5;
use stellar_agent_network::signing::Signer;
use stellar_agent_soroban_auth::preimage_parts;
use stellar_xdr::{AccountId, HashIdPreimage, PublicKey, ReadXdr, ScAddress, Uint256};

use crate::error::Sep43Error;

/// Signs a classic `TransactionEnvelope` XDR string.
///
/// Decodes the base64 `TransactionEnvelope`, computes the SEP-23
/// `TransactionSignaturePayload` hash, calls `Signer::sign_tx_payload` exactly
/// once, attaches the resulting `DecoratedSignature`, and re-encodes as base64.
///
/// Delegates to
/// `stellar_agent_network::signing::envelope_signing::attach_signature`
/// (the single SEP-23 signing call site).
///
/// # Network passphrase validation
///
/// If `network_passphrase_override` is `Some`, it must equal the
/// `expected_network_passphrase` exactly. Mismatch returns
/// [`Sep43Error::InvalidNetworkPassphrase`] before any signing attempt.
///
/// # Errors
///
/// - [`Sep43Error::InvalidNetworkPassphrase`] — provided passphrase does not
///   match the profile's.
/// - [`Sep43Error::InvalidXdr`] — `transaction_xdr` is not a valid
///   base64-encoded `TransactionEnvelope`.
/// - [`Sep43Error::UserRejected`] — the signer returned a user-rejection error.
/// - [`Sep43Error::SignerUnavailable`] — the signer returned a
///   wallet-state error.
///
/// # Panics
///
/// Never panics.
pub async fn sign_classic_transaction(
    transaction_xdr: &str,
    signer: &(dyn Signer + Send + Sync),
    expected_network_passphrase: &str,
    network_passphrase_override: Option<&str>,
) -> Result<String, Sep43Error> {
    // Network-passphrase guard: fail-closed if the client supplies a mismatched
    // passphrase.
    if let Some(provided) = network_passphrase_override
        && provided != expected_network_passphrase
    {
        return Err(Sep43Error::InvalidNetworkPassphrase {
            detail: format!(
                "provided passphrase does not match profile: \
                 expected {expected_network_passphrase:?}, got {provided:?}"
            ),
        });
    }

    stellar_agent_network::signing::envelope_signing::attach_signature(
        transaction_xdr,
        signer,
        expected_network_passphrase,
    )
    .await
    .map_err(wallet_error_to_sep43)
}

/// Signs a SEP-43 `signAuthEntry` request over an authorization-entry preimage.
///
/// Per the SEP-43 / Stellar-Wallets-Kit `signAuthEntry` contract, the input is
/// the base64 XDR `HashIdPreimage` of the authorization entry and the output is
/// the base64-encoded raw 64-byte ed25519 signature over `SHA256(preimage_bytes)`
/// of the received bytes. The requester assembles the signature into the final
/// `SorobanAuthorizationEntry`.
///
/// Two preimage cases are signed:
///
/// - envelope type 9, `HashIdPreimage::SorobanAuthorization`, the preimage of
///   `SorobanCredentials::Address` entries;
/// - envelope type 10, `HashIdPreimage::SorobanAuthorizationWithAddress`, the
///   CAP-71 preimage of `SorobanCredentials::AddressV2` entries. It carries the
///   credential's address, and the signature is bound to that address.
///
/// Every other `HashIdPreimage` case is refused. The preimage does not carry
/// the credential arm: a type 10 preimage is signed only when it is bound to
/// `ScAddress::Account(expected_signer)`, whichever credential type the entry
/// uses, and a preimage bound to any other address, including another
/// account, a contract or a muxed account, is refused with `InvalidAddress`
/// before any signing attempt.
///
/// # Validation order
///
/// 1. If `network_passphrase_override` is `Some`, it must equal
///    `expected_network_passphrase`.
/// 2. The input must be base64 and decode, under untrusted-input limits, as a
///    `HashIdPreimage`.
/// 3. The preimage must be envelope type 9 or 10.
/// 4. Its `network_id` must equal `SHA256(expected_network_passphrase)`.
/// 5. A type 10 preimage must be bound to `expected_signer`.
///
/// `expected_signer` must be the public key of `signer`. Callers already hold
/// it, so the address check needs no second signer round-trip.
///
/// # Errors
///
/// - [`Sep43Error::InvalidNetworkPassphrase`]: passphrase override mismatch, or
///   the preimage's `network_id` does not match the active network.
/// - [`Sep43Error::InvalidXdr`]: the input is not valid base64 or not a
///   well-formed `HashIdPreimage`.
/// - [`Sep43Error::MalformedAuthEntry`]: the preimage is neither envelope
///   type 9 nor envelope type 10.
/// - [`Sep43Error::InvalidAddress`]: a type 10 preimage is bound to an address
///   other than `ScAddress::Account(expected_signer)`.
/// - [`Sep43Error::UserRejected`]: signer user-rejection.
/// - [`Sep43Error::SignerUnavailable`]: signer wallet-state error.
///
/// # Panics
///
/// Never panics.
pub async fn sign_soroban_auth_entry(
    preimage_xdr: &str,
    signer: &(dyn Signer + Send + Sync),
    expected_signer: &stellar_strkey::ed25519::PublicKey,
    expected_network_passphrase: &str,
    network_passphrase_override: Option<&str>,
) -> Result<String, Sep43Error> {
    // Network-passphrase guard.
    if let Some(provided) = network_passphrase_override
        && provided != expected_network_passphrase
    {
        return Err(Sep43Error::InvalidNetworkPassphrase {
            detail: format!(
                "provided passphrase does not match profile: \
                 expected {expected_network_passphrase:?}, got {provided:?}"
            ),
        });
    }

    // Decode the base64 preimage XDR.
    let preimage_bytes = base64::engine::general_purpose::STANDARD
        .decode(preimage_xdr)
        .map_err(|e| Sep43Error::InvalidXdr {
            detail: format!("authorization entry preimage is not valid base64: {e}"),
        })?;

    // The preimage is caller-supplied and untrusted; bounded limits prevent a
    // deeply nested SorobanAuthorizedInvocation chain from exhausting the stack.
    let preimage = HashIdPreimage::from_xdr(
        &preimage_bytes,
        stellar_agent_xdr_limits::untrusted_decode_limits(preimage_bytes.len()),
    )
    .map_err(|e| Sep43Error::InvalidXdr {
        detail: format!("failed to decode HashIdPreimage: {e}"),
    })?;
    let Some((_, network_id, bound_address)) = preimage_parts(&preimage) else {
        return Err(Sep43Error::MalformedAuthEntry {
            detail: "preimage is not a Soroban authorization HashIdPreimage \
                     (envelope type 9 or 10)"
                .to_owned(),
        });
    };
    let expected_network_id: [u8; 32] =
        Sha256::digest(expected_network_passphrase.as_bytes()).into();
    if network_id != expected_network_id {
        return Err(Sep43Error::InvalidNetworkPassphrase {
            detail: "authorization entry preimage network_id does not match the active network"
                .to_owned(),
        });
    }

    // A type 10 preimage binds the signature to its address; sign only for the
    // signing key's own account address.
    if let Some(bound_address) = bound_address {
        let signer_address = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
            Uint256(expected_signer.0),
        )));
        if *bound_address != signer_address {
            let expected = expected_signer.to_string();
            return Err(Sep43Error::InvalidAddress {
                detail: format!(
                    "authorization preimage is bound to another address (expected the signing \
                     key {})",
                    redact_strkey_first5_last5(expected.as_str())
                ),
                expected_type: "G-strkey matching the signing key",
            });
        }
    }

    // Sign SHA-256 of the received bytes with the auth-entry signing primitive.
    let payload: [u8; 32] = Sha256::digest(&preimage_bytes).into();
    let sig_bytes = signer
        .sign_soroban_address_auth_payload(&payload)
        .await
        .map_err(wallet_error_to_sep43)?;

    // Return the base64-encoded raw 64-byte signature.
    Ok(base64::engine::general_purpose::STANDARD.encode(sig_bytes))
}

/// Signs an arbitrary message byte slice for SEP-43 `signMessage`.
///
/// Computes the SEP-53 message digest `SHA256("Stellar Signed Message:\n" ‖
/// message_bytes)` and calls `Signer::sign_tx_payload` on the resulting 32-byte
/// digest. The prefix is the domain separator that makes the signature
/// verifiable by any SEP-53 verifier (including
/// [`stellar_agent_sep53::verify_message`]) and matches the message-signing
/// scheme used by reference SEP-43 wallets.
///
/// The returned tuple is `(base64_signature, signer_address_g_strkey)`, where
/// the signature is the base64-encoded raw 64-byte ed25519 signature. The
/// SEP-43 spec text says "HEX-encoded", but the reference wallets
/// (Freighter / Stellar-Wallets-Kit) base64-encode the signature; this crate
/// matches the reference behaviour for interoperability.
///
/// # Message validation
///
/// - Returns [`Sep43Error::InvalidMessage`] if `message_bytes` is empty or
///   exceeds [`stellar_agent_sep53::MAX_MESSAGE_BYTES`].
///
/// # Errors
///
/// - [`Sep43Error::InvalidMessage`] — `message_bytes` is empty or too large.
/// - [`Sep43Error::UserRejected`] — signer user-rejection.
/// - [`Sep43Error::SignerUnavailable`] — signer wallet-state error.
///
/// # Panics
///
/// Never panics.
pub async fn sign_message_bytes(
    message_bytes: &[u8],
    signer: &(dyn Signer + Send + Sync),
) -> Result<(String, String), Sep43Error> {
    if message_bytes.is_empty() {
        return Err(Sep43Error::InvalidMessage {
            detail: "message must not be empty".to_owned(),
        });
    }
    if message_bytes.len() > stellar_agent_sep53::MAX_MESSAGE_BYTES {
        return Err(Sep43Error::InvalidMessage {
            detail: format!(
                "message exceeds the maximum of {} bytes",
                stellar_agent_sep53::MAX_MESSAGE_BYTES
            ),
        });
    }

    // Reuse the sep53 crate's single SEP-53 digest implementation
    // (SHA-256("Stellar Signed Message:\n" ‖ message)) so the two SEPs cannot
    // diverge; the signature is verifiable by any SEP-53 verifier.
    let digest = stellar_agent_sep53::message_digest(message_bytes);

    // sign_tx_payload is the raw 32-byte ed25519 primitive; the payload domain
    // here is the SEP-53 message digest, not a SEP-23 transaction payload.
    let sig_bytes = signer
        .sign_tx_payload(&digest)
        .await
        .map_err(wallet_error_to_sep43)?;

    let public_key = signer.public_key().await.map_err(wallet_error_to_sep43)?;

    // Encode the signer's public key as a G-strkey.
    let signer_address = stellar_strkey::ed25519::PublicKey(public_key.0)
        .to_string()
        .to_string();

    // Return the base64-encoded raw 64-byte signature.
    let signed_message = base64::engine::general_purpose::STANDARD.encode(sig_bytes);
    Ok((signed_message, signer_address))
}

/// Maps a [`WalletError`] to a [`Sep43Error`].
fn wallet_error_to_sep43(e: WalletError) -> Sep43Error {
    use stellar_agent_core::error::{AuthError, WalletError as WE};
    match e {
        WE::Auth(AuthError::HardwareUserRefused) => Sep43Error::UserRejected {
            reason: "user declined on hardware device".to_owned(),
        },
        WE::Auth(_) => Sep43Error::UserRejected {
            reason: "signing request rejected".to_owned(),
        },
        WE::WalletState(ws) => Sep43Error::SignerUnavailable {
            detail: format!("wallet state error: {ws}"),
        },
        WE::Protocol(p) => Sep43Error::InvalidXdr {
            detail: format!("XDR codec operation failed: {p}"),
        },
        other => Sep43Error::SignerUnavailable {
            detail: format!("signer error: {other}"),
        },
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

    // ── Fixture helpers ───────────────────────────────────────────────────────

    const TESTNET: &str = "Test SDF Network ; September 2015";

    /// Builds a minimal valid `TransactionEnvelope::Tx` (V1) XDR for signing
    /// tests.  The envelope carries a single `BUMP_SEQUENCE` operation sourced
    /// from the provided public key bytes.
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
                bump_to: SequenceNumber(42),
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
                .expect("one operation must fit VecM<Operation,100>"),
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

    /// The minimal `ContractFn` invocation (no arguments, no sub-invocations)
    /// both preimage fixtures carry.
    fn minimal_invocation() -> stellar_xdr::SorobanAuthorizedInvocation {
        use stellar_xdr::{
            ContractId, Hash, ScAddress, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
        };

        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(stellar_xdr::InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0xA0u8; 32]))),
                function_name: "test_invoke".try_into().expect("short fn name"),
                args: vec![].try_into().expect("empty args"),
            }),
            sub_invocations: vec![].try_into().expect("empty sub-invocations"),
        }
    }

    /// Builds a `HashIdPreimage::SorobanAuthorization` (envelope type 9)
    /// preimage for `passphrase` and returns its base64 XDR.
    fn minimal_soroban_auth_preimage_xdr(passphrase: &str) -> String {
        use stellar_xdr::{
            Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits, WriteXdr,
        };

        HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: Hash(Sha256::digest(passphrase.as_bytes()).into()),
            nonce: 0x1234_5678,
            signature_expiration_ledger: 9999,
            invocation: minimal_invocation(),
        })
        .to_xdr_base64(Limits::none())
        .expect("soroban auth preimage must encode")
    }

    /// Builds a `HashIdPreimage::SorobanAuthorizationWithAddress` (envelope
    /// type 10) preimage for `passphrase` bound to `address`, with the same
    /// nonce, expiration and invocation as
    /// [`minimal_soroban_auth_preimage_xdr`], and returns its base64 XDR.
    fn minimal_soroban_auth_v2_preimage_xdr(passphrase: &str, address: ScAddress) -> String {
        use stellar_xdr::{
            Hash, HashIdPreimage, HashIdPreimageSorobanAuthorizationWithAddress, Limits, WriteXdr,
        };

        HashIdPreimage::SorobanAuthorizationWithAddress(
            HashIdPreimageSorobanAuthorizationWithAddress {
                network_id: Hash(Sha256::digest(passphrase.as_bytes()).into()),
                nonce: 0x1234_5678,
                signature_expiration_ledger: 9999,
                address,
                invocation: minimal_invocation(),
            },
        )
        .to_xdr_base64(Limits::none())
        .expect("soroban auth v2 preimage must encode")
    }

    /// `ScAddress::Account` of an ed25519 public key.
    fn account_address(key: &stellar_strkey::ed25519::PublicKey) -> ScAddress {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key.0))))
    }

    /// Returns `SHA256(base64-decoded preimage)`, computed independently of the
    /// production path.
    fn preimage_hash(preimage_b64: &str) -> [u8; 32] {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(preimage_b64)
            .expect("preimage must be valid base64");
        Sha256::digest(&bytes).into()
    }

    /// Decodes a base64 signature returned by `sign_soroban_auth_entry`.
    fn decode_signature(signature_b64: &str) -> ed25519_dalek::Signature {
        let bytes: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .expect("returned signature must be valid base64")
            .try_into()
            .expect("signature must be 64 bytes");
        ed25519_dalek::Signature::from_bytes(&bytes)
    }

    /// Delegating signer that counts signature requests, so refusal tests can
    /// prove no signature is produced.
    struct CountingSigner {
        inner: stellar_agent_network::signing::SoftwareSigningKey,
        signatures: std::sync::atomic::AtomicUsize,
    }

    impl CountingSigner {
        fn new(seed: [u8; 32]) -> Self {
            Self {
                inner: stellar_agent_network::signing::SoftwareSigningKey::new_from_bytes(seed),
                signatures: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn count(&self) -> usize {
            self.signatures.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn record(&self) {
            self.signatures
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl Signer for CountingSigner {
        async fn sign_tx_payload(&self, payload: &[u8; 32]) -> Result<[u8; 64], WalletError> {
            self.record();
            self.inner.sign_tx_payload(payload).await
        }

        async fn sign_auth_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], WalletError> {
            self.record();
            self.inner.sign_auth_digest(digest).await
        }

        async fn sign_soroban_address_auth_payload(
            &self,
            payload: &[u8; 32],
        ) -> Result<[u8; 64], WalletError> {
            self.record();
            self.inner.sign_soroban_address_auth_payload(payload).await
        }

        async fn sign_webauthn_assertion(
            &self,
            auth_digest: &[u8; 32],
            credential_id: &[u8],
        ) -> Result<stellar_agent_network::signing::WebAuthnAssertion, WalletError> {
            self.record();
            self.inner
                .sign_webauthn_assertion(auth_digest, credential_id)
                .await
        }

        async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
            self.inner.public_key().await
        }
    }

    // ── sign_classic_transaction ──────────────────────────────────────────────

    #[test]
    fn sign_classic_transaction_passphrase_mismatch_returns_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            use stellar_agent_network::signing::SoftwareSigningKey;
            let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
            let err = sign_classic_transaction(
                "AAAA",
                &key,
                TESTNET,
                Some("Public Global Stellar Network ; September 2015"),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, Sep43Error::InvalidNetworkPassphrase { .. }),
                "got: {err:?}"
            );
        });
    }

    #[test]
    fn sign_classic_transaction_invalid_xdr_returns_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            use stellar_agent_network::signing::SoftwareSigningKey;
            let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
            let err = sign_classic_transaction("not-valid-xdr!!!", &key, TESTNET, None)
                .await
                .unwrap_err();
            assert!(matches!(err, Sep43Error::InvalidXdr { .. }), "got: {err:?}");
        });
    }

    #[tokio::test]
    async fn sign_classic_transaction_success_attaches_one_decorated_signature() {
        use ed25519_dalek::{Signature, VerifyingKey};
        use stellar_agent_network::signing::SoftwareSigningKey;
        use stellar_xdr::{
            Hash, Limits, ReadXdr, TransactionEnvelope, TransactionSignaturePayload,
            TransactionSignaturePayloadTaggedTransaction, WriteXdr,
        };

        let seed = [0x55u8; 32];
        let key = SoftwareSigningKey::new_from_bytes(seed);
        let pk = key.public_key().await.unwrap();
        let unsigned_xdr = minimal_tx_v1_xdr(&pk.0);

        let signed_xdr = sign_classic_transaction(&unsigned_xdr, &key, TESTNET, None)
            .await
            .expect("sign_classic_transaction must succeed with valid inputs");

        let signed_env = TransactionEnvelope::from_xdr_base64(&signed_xdr, Limits::none())
            .expect("signed envelope must decode");
        let TransactionEnvelope::Tx(ref v1) = signed_env else {
            panic!("expected TransactionEnvelope::Tx");
        };
        assert_eq!(
            v1.signatures.len(),
            1,
            "exactly one DecoratedSignature must be attached"
        );

        // Cryptographic verification: reconstruct the SEP-23 payload independently
        // and verify the attached signature against it.
        let network_id = Hash(Sha256::digest(TESTNET.as_bytes()).into());
        let tagged = TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx.clone());
        let payload_xdr = TransactionSignaturePayload {
            network_id,
            tagged_transaction: tagged,
        }
        .to_xdr(Limits::none())
        .expect("TransactionSignaturePayload must encode");
        let signing_hash: [u8; 32] = Sha256::digest(&payload_xdr).into();

        let raw_sig: [u8; 64] = v1.signatures[0]
            .signature
            .as_slice()
            .try_into()
            .expect("DecoratedSignature.signature must be 64 bytes");

        let vk = VerifyingKey::from_bytes(&pk.0).expect("signer pubkey must be valid ed25519");
        let sig = Signature::from_bytes(&raw_sig);
        vk.verify_strict(&signing_hash, &sig)
            .expect("attached DecoratedSignature must verify against the SEP-23 payload hash");
    }

    #[tokio::test]
    async fn sign_classic_transaction_passphrase_override_matches_ok() {
        use stellar_agent_network::signing::SoftwareSigningKey;
        use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};

        let seed = [0x56u8; 32];
        let key = SoftwareSigningKey::new_from_bytes(seed);
        let pk = key.public_key().await.unwrap();
        let unsigned_xdr = minimal_tx_v1_xdr(&pk.0);

        let result = sign_classic_transaction(&unsigned_xdr, &key, TESTNET, Some(TESTNET))
            .await
            .expect("matching passphrase override must succeed");

        let env = TransactionEnvelope::from_xdr_base64(&result, Limits::none()).unwrap();
        let TransactionEnvelope::Tx(v1) = env else {
            panic!("expected Tx envelope");
        };
        assert_eq!(v1.signatures.len(), 1);
    }

    // ── sign_soroban_auth_entry: invalid/not-base64 ───────────────────────────

    #[test]
    fn sign_soroban_auth_entry_invalid_xdr_returns_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            use stellar_agent_network::signing::SoftwareSigningKey;
            let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
            let pk = key.public_key().await.unwrap();
            let err = sign_soroban_auth_entry("not-valid-xdr!!!", &key, &pk, TESTNET, None)
                .await
                .unwrap_err();
            assert!(matches!(err, Sep43Error::InvalidXdr { .. }), "got: {err:?}");
            assert_eq!(err.sep43_code(), -3);
        });
    }

    /// Valid base64 that is not a well-formed `HashIdPreimage` → `InvalidXdr`.
    #[tokio::test]
    async fn sign_soroban_auth_entry_valid_base64_random_bytes_returns_invalid_xdr() {
        use stellar_agent_network::signing::SoftwareSigningKey;

        let key = SoftwareSigningKey::new_from_bytes([2u8; 32]);
        let pk = key.public_key().await.unwrap();
        // 32 random bytes that encode as valid base64 but not valid XDR.
        let garbage_b64 = base64::engine::general_purpose::STANDARD.encode([0xDE_u8; 32]);
        let err = sign_soroban_auth_entry(&garbage_b64, &key, &pk, TESTNET, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep43Error::InvalidXdr { .. }),
            "random non-XDR bytes must return InvalidXdr, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
    }

    /// A valid `HashIdPreimage` that is neither Soroban authorization case
    /// (envelope type 9 or 10) returns `MalformedAuthEntry`.
    #[tokio::test]
    async fn sign_soroban_auth_entry_wrong_variant_returns_malformed_auth_entry() {
        use stellar_agent_network::signing::SoftwareSigningKey;
        use stellar_xdr::{
            AccountId, Hash, HashIdPreimage, HashIdPreimageContractId, HashIdPreimageOperationId,
            Limits, PublicKey, SequenceNumber, Uint256, WriteXdr,
        };

        let key = SoftwareSigningKey::new_from_bytes([3u8; 32]);
        let pk = key.public_key().await.unwrap();

        // Build a HashIdPreimage::OpId: a valid case that is not a Soroban
        // authorization preimage.
        let op_id_preimage = HashIdPreimage::OpId(HashIdPreimageOperationId {
            source_account: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32]))),
            seq_num: SequenceNumber(1),
            op_num: 0,
        });
        let wrong_variant_b64 = op_id_preimage
            .to_xdr_base64(Limits::none())
            .expect("OpId preimage must encode");

        let err = sign_soroban_auth_entry(&wrong_variant_b64, &key, &pk, TESTNET, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep43Error::MalformedAuthEntry { .. }),
            "an OpId HashIdPreimage must return MalformedAuthEntry, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);

        // Also verify with ContractId variant for breadth.
        let contract_id_preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
            network_id: Hash([0u8; 32]),
            contract_id_preimage: stellar_xdr::ContractIdPreimage::Address(
                stellar_xdr::ContractIdPreimageFromAddress {
                    address: stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(Hash(
                        [0u8; 32],
                    ))),
                    salt: Uint256([0u8; 32]),
                },
            ),
        });
        let contract_id_b64 = contract_id_preimage
            .to_xdr_base64(Limits::none())
            .expect("ContractId preimage must encode");
        let err2 = sign_soroban_auth_entry(&contract_id_b64, &key, &pk, TESTNET, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err2, Sep43Error::MalformedAuthEntry { .. }),
            "ContractId HashIdPreimage must return MalformedAuthEntry, got: {err2:?}"
        );
        assert_eq!(err2.sep43_code(), -3);
    }

    /// A `SorobanAuthorization` preimage whose `network_id` does not match the
    /// active passphrase → `InvalidNetworkPassphrase`.
    #[tokio::test]
    async fn sign_soroban_auth_entry_wrong_network_id_returns_invalid_network_passphrase() {
        use stellar_agent_network::signing::SoftwareSigningKey;
        use stellar_xdr::{
            ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits,
            ScAddress, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, WriteXdr,
        };

        let key = SoftwareSigningKey::new_from_bytes([4u8; 32]);
        let pk = key.public_key().await.unwrap();
        let wrong_passphrase = "wrong passphrase";
        let active_passphrase = TESTNET;

        // Build a SorobanAuthorization preimage with network_id = SHA256("wrong passphrase").
        let wrong_network_id = Hash(Sha256::digest(wrong_passphrase.as_bytes()).into());
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: wrong_network_id,
            nonce: 1,
            signature_expiration_ledger: 100,
            invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(stellar_xdr::InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([0xBBu8; 32]))),
                    function_name: "fn".try_into().expect("short fn name"),
                    args: vec![].try_into().expect("empty args"),
                }),
                sub_invocations: vec![].try_into().expect("empty sub-invocations"),
            },
        });
        let preimage_b64 = preimage
            .to_xdr_base64(Limits::none())
            .expect("preimage must encode");

        let err = sign_soroban_auth_entry(&preimage_b64, &key, &pk, active_passphrase, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep43Error::InvalidNetworkPassphrase { .. }),
            "wrong network_id must return InvalidNetworkPassphrase, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
    }

    #[tokio::test]
    async fn sign_soroban_auth_entry_passphrase_mismatch_returns_error() {
        use stellar_agent_network::signing::SoftwareSigningKey;

        let key = SoftwareSigningKey::new_from_bytes([0x40u8; 32]);
        let pk = key.public_key().await.unwrap();
        let err = sign_soroban_auth_entry(
            "AAAA",
            &key,
            &pk,
            TESTNET,
            Some("Public Global Stellar Network ; September 2015"),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, Sep43Error::InvalidNetworkPassphrase { .. }),
            "got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
    }

    /// SUCCESS: build a valid preimage, sign it, base64-decode the returned
    /// signature to `[u8; 64]`, and independently verify it with ed25519-dalek
    /// over `SHA256(preimage_bytes)`.  The oracle does NOT call the production
    /// function to compute the expected digest.
    #[tokio::test]
    async fn sign_soroban_auth_entry_success_signature_verifies() {
        use ed25519_dalek::{Signature, VerifyingKey};
        use stellar_agent_network::signing::SoftwareSigningKey;

        let seed = [0x50u8; 32];
        let key = SoftwareSigningKey::new_from_bytes(seed);
        let pk = key.public_key().await.unwrap();

        let preimage_b64 = minimal_soroban_auth_preimage_xdr(TESTNET);

        let sig_b64 = sign_soroban_auth_entry(&preimage_b64, &key, &pk, TESTNET, None)
            .await
            .expect("sign_soroban_auth_entry must succeed with a valid preimage");

        // Decode the returned base64 signature → exactly 64 bytes.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .expect("returned signature must be valid base64");
        assert_eq!(
            sig_bytes.len(),
            64,
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        );
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();

        // Independent oracle: decode the preimage bytes and compute SHA256(preimage_bytes).
        // This does NOT reuse the production function's internal computation.
        let preimage_bytes = base64::engine::general_purpose::STANDARD
            .decode(&preimage_b64)
            .expect("preimage must be valid base64");
        let digest: [u8; 32] = Sha256::digest(&preimage_bytes).into();

        let vk = VerifyingKey::from_bytes(&pk.0).expect("signer pubkey must be valid ed25519");
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify_strict(&digest, &sig)
            .expect("signature must verify against SHA256(preimage_bytes)");
    }

    // ── sign_soroban_auth_entry: envelope type 10 (CAP-71) ────────────────────

    /// A type 10 preimage bound to the signing key's account signs, and the
    /// signature verifies over `SHA256(preimage_bytes)`.
    #[tokio::test]
    async fn sign_soroban_auth_entry_case_10_bound_to_signer_signs() {
        use ed25519_dalek::VerifyingKey;

        let signer = CountingSigner::new([0x70u8; 32]);
        let pk = signer.public_key().await.unwrap();
        let preimage_b64 = minimal_soroban_auth_v2_preimage_xdr(TESTNET, account_address(&pk));

        let sig_b64 = sign_soroban_auth_entry(&preimage_b64, &signer, &pk, TESTNET, None)
            .await
            .expect("a type 10 preimage bound to the signing key must sign");

        let vk = VerifyingKey::from_bytes(&pk.0).expect("signer pubkey must be valid ed25519");
        vk.verify_strict(&preimage_hash(&preimage_b64), &decode_signature(&sig_b64))
            .expect("signature must verify against SHA256(preimage_bytes)");
        assert_eq!(signer.count(), 1, "exactly one signature must be requested");
    }

    /// The type 9 and type 10 preimages of the same entry fields hash to
    /// different payloads, and a signature over one does not verify against the
    /// other. This demonstrates the domain separation between the two
    /// credential versions.
    #[tokio::test]
    async fn sign_soroban_auth_entry_case_9_and_case_10_signatures_do_not_cross_verify() {
        use ed25519_dalek::VerifyingKey;
        use stellar_agent_network::signing::SoftwareSigningKey;

        let key = SoftwareSigningKey::new_from_bytes([0x71u8; 32]);
        let pk = key.public_key().await.unwrap();
        let v1_b64 = minimal_soroban_auth_preimage_xdr(TESTNET);
        let v2_b64 = minimal_soroban_auth_v2_preimage_xdr(TESTNET, account_address(&pk));
        let (v1_hash, v2_hash) = (preimage_hash(&v1_b64), preimage_hash(&v2_b64));
        assert_ne!(v1_hash, v2_hash, "the two preimage hashes must differ");

        let v1_sig = decode_signature(
            &sign_soroban_auth_entry(&v1_b64, &key, &pk, TESTNET, None)
                .await
                .expect("type 9 preimage must sign"),
        );
        let v2_sig = decode_signature(
            &sign_soroban_auth_entry(&v2_b64, &key, &pk, TESTNET, None)
                .await
                .expect("type 10 preimage must sign"),
        );

        let vk = VerifyingKey::from_bytes(&pk.0).expect("signer pubkey must be valid ed25519");
        vk.verify_strict(&v1_hash, &v1_sig)
            .expect("type 9 signature must verify against the type 9 hash");
        vk.verify_strict(&v2_hash, &v2_sig)
            .expect("type 10 signature must verify against the type 10 hash");
        assert!(
            vk.verify_strict(&v1_hash, &v2_sig).is_err(),
            "a type 10 signature must not verify against the type 9 hash"
        );
        assert!(
            vk.verify_strict(&v2_hash, &v1_sig).is_err(),
            "a type 9 signature must not verify against the type 10 hash"
        );
    }

    /// Asserts a type 10 preimage bound to `address` is refused with
    /// `InvalidAddress` before any signature is requested, and that the detail
    /// names the signing key in redacted form only.
    async fn assert_case_10_address_refused(address: ScAddress, seed: [u8; 32]) {
        let signer = CountingSigner::new(seed);
        let pk = signer.public_key().await.unwrap();
        let preimage_b64 = minimal_soroban_auth_v2_preimage_xdr(TESTNET, address);

        let err = sign_soroban_auth_entry(&preimage_b64, &signer, &pk, TESTNET, None)
            .await
            .unwrap_err();

        let Sep43Error::InvalidAddress {
            ref detail,
            expected_type,
        } = err
        else {
            panic!("a type 10 preimage bound to another address must refuse, got: {err:?}");
        };
        let signer_g = pk.to_string();
        let signer_g = signer_g.as_str();
        assert!(
            detail.contains(&format!("{}...{}", &signer_g[..5], &signer_g[51..])),
            "detail must name the redacted signing key: {detail}"
        );
        assert!(
            !detail.contains(signer_g),
            "detail must not print the full address: {detail}"
        );
        assert_eq!(expected_type, "G-strkey matching the signing key");
        assert_eq!(err.sep43_code(), -3);
        assert_eq!(err.wire_code(), "sep43.invalid_address");
        assert_eq!(signer.count(), 0, "a refused preimage must not be signed");
    }

    #[tokio::test]
    async fn sign_soroban_auth_entry_case_10_bound_to_another_account_refuses() {
        let other = stellar_strkey::ed25519::PublicKey([0x99u8; 32]);
        assert_case_10_address_refused(account_address(&other), [0x72u8; 32]).await;
    }

    #[tokio::test]
    async fn sign_soroban_auth_entry_case_10_bound_to_a_contract_refuses() {
        let contract =
            ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash([0x73u8; 32])));
        assert_case_10_address_refused(contract, [0x73u8; 32]).await;
    }

    /// A muxed account wrapping the signing key's own ed25519 key is a
    /// different `ScAddress`; the signature would be bound to the muxed
    /// address, so it is refused.
    #[tokio::test]
    async fn sign_soroban_auth_entry_case_10_bound_to_muxed_own_key_refuses() {
        use stellar_agent_network::signing::SoftwareSigningKey;

        let seed = [0x74u8; 32];
        let pk = SoftwareSigningKey::new_from_bytes(seed)
            .public_key()
            .await
            .unwrap();
        let muxed = ScAddress::MuxedAccount(stellar_xdr::MuxedEd25519Account {
            id: 7,
            ed25519: Uint256(pk.0),
        });
        assert_case_10_address_refused(muxed, seed).await;
    }

    /// A type 10 preimage with a foreign `network_id` refuses with
    /// `InvalidNetworkPassphrase`, whether it is bound to the signing key or to
    /// another account: the network check runs before the address check.
    #[tokio::test]
    async fn sign_soroban_auth_entry_case_10_wrong_network_id_refuses() {
        let signer = CountingSigner::new([0x75u8; 32]);
        let pk = signer.public_key().await.unwrap();
        let other = stellar_strkey::ed25519::PublicKey([0x99u8; 32]);

        for address in [account_address(&pk), account_address(&other)] {
            let preimage_b64 = minimal_soroban_auth_v2_preimage_xdr("wrong passphrase", address);
            let err = sign_soroban_auth_entry(&preimage_b64, &signer, &pk, TESTNET, None)
                .await
                .unwrap_err();
            assert!(
                matches!(err, Sep43Error::InvalidNetworkPassphrase { .. }),
                "wrong network_id must return InvalidNetworkPassphrase, got: {err:?}"
            );
            assert_eq!(err.sep43_code(), -3);
        }
        assert_eq!(signer.count(), 0, "a refused preimage must not be signed");
    }

    // ── sign_message_bytes ────────────────────────────────────────────────────

    #[test]
    fn sign_message_bytes_empty_returns_invalid_message() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            use stellar_agent_network::signing::SoftwareSigningKey;
            let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
            let err = sign_message_bytes(&[], &key).await.unwrap_err();
            assert!(matches!(err, Sep43Error::InvalidMessage { .. }));
            assert_eq!(err.sep43_code(), -3);
        });
    }

    /// SUCCESS: base64-decode the returned signature to `[u8; 64]`, then
    /// independently verify it (hardcoded prefix literal as oracle) and via
    /// the sep53 interop oracle.
    #[tokio::test]
    async fn sign_message_bytes_signature_verifies_with_dalek() {
        use ed25519_dalek::{Signature, VerifyingKey};
        use stellar_agent_network::signing::SoftwareSigningKey;

        let key = SoftwareSigningKey::new_from_bytes([0x53u8; 32]);
        let pk = key.public_key().await.unwrap();
        let message = b"Hello, World!";

        let (b64_sig, addr) = sign_message_bytes(message, &key)
            .await
            .expect("sign_message_bytes must succeed with non-empty message");

        // The returned signer address must match the signer's public key.
        let expected_addr = stellar_strkey::ed25519::PublicKey(pk.0)
            .to_string()
            .to_string();
        assert_eq!(addr, expected_addr, "addr must match signer public key");

        // Base64-decode the signature — must be exactly 64 bytes.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64_sig)
            .expect("returned signature must be valid base64");
        assert_eq!(sig_bytes.len(), 64, "signature must be 64 bytes");
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();

        // Independent oracle: hardcoded prefix literal (NOT sep53::PREFIX constant)
        // so this test does not tautologically pass if the constant were wrong.
        let mut h = Sha256::new();
        h.update(b"Stellar Signed Message:\n");
        h.update(message);
        let digest: [u8; 32] = h.finalize().into();

        let vk = VerifyingKey::from_bytes(&pk.0).expect("signer pubkey must be valid ed25519");
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify_strict(&digest, &sig)
            .expect("signature must verify against the SEP-53 prefixed digest");

        // Interop oracle: the signature must also verify via the independent sep53 verifier.
        stellar_agent_sep53::verify_message(
            message,
            &sig_arr,
            &stellar_strkey::ed25519::PublicKey(pk.0),
        )
        .expect("signature must pass the sep53 independent verifier");
    }

    #[tokio::test]
    async fn sign_message_bytes_oversized_returns_invalid_message() {
        use stellar_agent_network::signing::SoftwareSigningKey;

        let key = SoftwareSigningKey::new_from_bytes([0x61u8; 32]);
        let oversized = vec![0u8; stellar_agent_sep53::MAX_MESSAGE_BYTES + 1];
        let err = sign_message_bytes(&oversized, &key).await.unwrap_err();
        assert!(
            matches!(err, Sep43Error::InvalidMessage { .. }),
            "oversized message must return InvalidMessage, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
    }

    // ── wallet_error_to_sep43 arm coverage ───────────────────────────────────

    #[test]
    fn wallet_error_to_sep43_hardware_refused_maps_to_user_rejected() {
        use stellar_agent_core::error::{AuthError, WalletError};

        let err = wallet_error_to_sep43(WalletError::Auth(AuthError::HardwareUserRefused));
        assert!(
            matches!(err, Sep43Error::UserRejected { .. }),
            "HardwareUserRefused must map to UserRejected, got: {err:?}"
        );
        let Sep43Error::UserRejected { ref reason } = err else {
            panic!("expected UserRejected");
        };
        assert!(
            reason.contains("hardware") || reason.contains("declined"),
            "reason must mention hardware or declined: {reason}"
        );
        assert_eq!(err.sep43_code(), -4);
    }

    #[test]
    fn wallet_error_to_sep43_other_auth_maps_to_user_rejected() {
        use stellar_agent_core::error::{AuthError, WalletError};

        let err = wallet_error_to_sep43(WalletError::Auth(AuthError::KeyringLocked));
        assert!(
            matches!(err, Sep43Error::UserRejected { .. }),
            "non-hardware AuthError must map to UserRejected, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -4);
    }

    #[test]
    fn wallet_error_to_sep43_wallet_state_maps_to_signer_unavailable() {
        use stellar_agent_core::error::{WalletError, WalletStateError};

        let err =
            wallet_error_to_sep43(WalletError::WalletState(WalletStateError::HardwareNotFound));
        assert!(
            matches!(err, Sep43Error::SignerUnavailable { .. }),
            "WalletState error must map to SignerUnavailable, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -1);
    }

    #[test]
    fn wallet_error_to_sep43_protocol_maps_to_invalid_xdr() {
        use stellar_agent_core::error::{ProtocolError, WalletError};

        let err = wallet_error_to_sep43(WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: "xdr decode failed".to_owned(),
        }));
        assert!(
            matches!(err, Sep43Error::InvalidXdr { .. }),
            "Protocol error must map to InvalidXdr, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
    }

    #[test]
    fn wallet_error_to_sep43_other_maps_to_signer_unavailable() {
        use stellar_agent_core::error::{NetworkError, WalletError};

        let err = wallet_error_to_sep43(WalletError::Network(
            NetworkError::FriendbotMainnetForbidden,
        ));
        assert!(
            matches!(err, Sep43Error::SignerUnavailable { .. }),
            "catch-all WalletError must map to SignerUnavailable, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -1);
    }

    // ── Depth-bomb regression ─────────────────────────────────────────────────

    /// A `HashIdPreimage::SorobanAuthorization` with a 600-deep
    /// `sub_invocations` chain is rejected by `sign_soroban_auth_entry` with
    /// `InvalidXdr` and does NOT exhaust the stack.
    ///
    /// The depth (600) exceeds `XDR_DECODE_MAX_DEPTH` (500). The bounded
    /// decoder in `sign_soroban_auth_entry` returns an error before the signer
    /// is reached.
    ///
    /// The fixture is encoded with `Limits::none()` (write-side; writing 600
    /// levels fits the test stack). Only the bounded production path decodes it.
    #[tokio::test]
    async fn sign_soroban_auth_entry_deep_sub_invocations_rejected() {
        use stellar_agent_network::signing::SoftwareSigningKey;
        use stellar_xdr::{
            ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits,
            ScAddress, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, VecM, WriteXdr,
        };

        let leaf_fn = SorobanAuthorizedFunction::ContractFn(stellar_xdr::InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([0xABu8; 32]))),
            function_name: "h".try_into().expect("short name"),
            args: VecM::default(),
        });

        // Build a 600-deep chain iteratively (innermost first, wrap outward).
        let mut inner = SorobanAuthorizedInvocation {
            function: leaf_fn.clone(),
            sub_invocations: VecM::default(),
        };
        for _ in 0..599 {
            inner = SorobanAuthorizedInvocation {
                function: leaf_fn.clone(),
                sub_invocations: vec![inner].try_into().expect("single-element VecM"),
            };
        }

        // Build a SorobanAuthorization preimage using the deep invocation.
        let network_id = Hash(Sha256::digest(TESTNET.as_bytes()).into());
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id,
            nonce: 0x9999_8888,
            signature_expiration_ledger: 5000,
            invocation: inner,
        });

        // ENCODE with Limits::none() — write-side; does not invoke the bounded
        // read path. Writing 600 levels of nesting fits the test stack.
        let deep_b64 = preimage
            .to_xdr_base64(Limits::none())
            .expect("encoding a deep structure must succeed");

        let key = SoftwareSigningKey::new_from_bytes([0xBBu8; 32]);
        let pk = key.public_key().await.unwrap();
        let result = sign_soroban_auth_entry(&deep_b64, &key, &pk, TESTNET, None).await;

        assert!(
            result.is_err(),
            "a 600-deep SorobanAuthorizedInvocation chain must be rejected"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, Sep43Error::InvalidXdr { .. }),
            "expected InvalidXdr from depth-exceeded decode, got: {err:?}"
        );
        assert_eq!(
            err.sep43_code(),
            -3,
            "depth-exceeded decode must map to SEP-43 error code -3 (client-invalid)"
        );
    }
}
