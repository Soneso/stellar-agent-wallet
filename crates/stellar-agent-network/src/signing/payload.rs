//! Typed signing payloads: the 32-byte values a [`Signer`] signs.
//!
//! Every ed25519 method of [`Signer`] takes one of these types, never raw
//! bytes, so the type of a payload names its domain and the constructor that
//! produced it checked the network it commits to.
//!
//! | Type | Bytes | Signed by | Constructors |
//! |---|---|---|---|
//! | [`TxSigningPayload`] | the SEP-23 transaction hash, `SHA-256(network_id ‖ TransactionSignaturePayloadTaggedTransaction)` | [`Signer::sign_tx_payload`] | [`TxSigningPayload::for_envelope`], [`TxSigningPayload::for_tagged`] |
//! | [`SorobanAuthPayload`] | `SHA-256` of a Soroban authorization `HashIdPreimage` (envelope type 9 or 10) | [`Signer::sign_soroban_address_auth_payload`] | [`SorobanAuthPayload::from_preimage`], and [`SorobanAuthPayload::authorized`] for mainnet |
//! | [`SmartAccountAuthDigest`] | `SHA-256(signature_payload ‖ context_rule_ids_xdr)` | [`Signer::sign_auth_digest`], [`Signer::sign_webauthn_assertion`] | [`SmartAccountAuthDigest::new`] |
//! | [`MessagePayload`] | the SEP-53 digest, `SHA-256("Stellar Signed Message:\n" ‖ message)` | [`Signer::sign_message`] | [`MessagePayload::sep53`] |
//!
//! Each type wraps a private `[u8; 32]`. No type has a constructor from raw
//! bytes, and none implements `From`, `Default`, `Deref`, or serde, so a value
//! exists only as its constructor computed it.
//!
//! # Mainnet
//!
//! The public constructors of a transaction payload, a Soroban payload, and a
//! smart-account digest refuse the mainnet network with
//! `network.mainnet_write_forbidden`. A mainnet payload exists only under a
//! mainnet authorization:
//!
//! - A mainnet transaction payload is built by this crate's authorized
//!   transaction signing, `attach_signature_authorized`, after the checks of a
//!   [`MainnetTxSignAuthorization`], which binds the transaction hash.
//! - A mainnet Soroban payload is built by [`SorobanAuthPayload::authorized`],
//!   which takes a [`MainnetSorobanIntentAuthorization`] by value. It returns a
//!   [`MainnetSorobanAuthPayload`], which is neither `Copy` nor `Clone`,
//!   carries the authorization, exposes no bytes, and is consumed by its one
//!   signing call, [`MainnetSorobanAuthPayload::sign`]. One authorization
//!   therefore yields at most one signature, over the one preimage it binds.
//!
//! A smart-account digest has no mainnet constructor: the smart-account
//! manager refuses mainnet before it signs. A SEP-53 message digest carries no
//! network; the wallet's message-signing paths refuse a mainnet profile before
//! they build one.
//!
//! So every [`Signer`], the public keyring handle included, signs a mainnet
//! transaction or Soroban authorization payload only under a mainnet
//! authorization.
//!
//! # Domains
//!
//! The four domains are separate types, so a message digest cannot be signed
//! as a transaction hash and the reverse. The bytes are domain-separated as
//! well: a SEP-23 or Soroban preimage opens with a 32-byte network id or an
//! envelope type, and a SEP-53 preimage with its 24-byte ASCII prefix.
//!
//! # Compile-time contract
//!
//! The public keyring handle signs only a typed payload:
//!
//! ```compile_fail,E0308
//! use stellar_agent_network::keyring::KeyringSignHandle;
//! async fn sign(handle: &KeyringSignHandle) {
//!     let _ = handle.sign_tx_payload(&[0u8; 32]).await;
//! }
//! ```
//!
//! Neither do the other ed25519 methods of the trait take raw bytes:
//!
//! ```compile_fail,E0308
//! use stellar_agent_network::signing::{Signer, SoftwareSigningKey};
//! async fn sign(key: &SoftwareSigningKey) {
//!     let _ = Signer::sign_auth_digest(key, &[0u8; 32]).await;
//! }
//! ```
//!
//! ```compile_fail,E0308
//! use stellar_agent_network::signing::{Signer, SoftwareSigningKey};
//! async fn sign(key: &SoftwareSigningKey) {
//!     let _ = Signer::sign_soroban_address_auth_payload(key, &[0u8; 32]).await;
//! }
//! ```
//!
//! No payload is built from raw bytes outside this crate:
//!
//! ```compile_fail,E0451
//! use stellar_agent_network::signing::payload::TxSigningPayload;
//! let _ = TxSigningPayload { bytes: [0u8; 32], mainnet_signer: None };
//! ```
//!
//! ```compile_fail,E0451
//! use stellar_agent_network::signing::payload::SorobanAuthPayload;
//! let _ = SorobanAuthPayload { bytes: [0u8; 32], mainnet_signer: None };
//! ```
//!
//! ```compile_fail,E0423
//! use stellar_agent_network::signing::payload::SmartAccountAuthDigest;
//! let _ = SmartAccountAuthDigest([0u8; 32]);
//! ```
//!
//! ```compile_fail,E0423
//! use stellar_agent_network::signing::payload::MessagePayload;
//! let _ = MessagePayload([0u8; 32]);
//! ```
//!
//! A message digest is not a transaction payload, and a transaction payload is
//! not a message:
//!
//! ```compile_fail,E0308
//! use stellar_agent_network::signing::payload::MessagePayload;
//! use stellar_agent_network::signing::{Signer, SoftwareSigningKey};
//! async fn sign(signer: &SoftwareSigningKey) {
//!     let _ = signer.sign_tx_payload(&MessagePayload::sep53(b"m")).await;
//! }
//! ```
//!
//! ```compile_fail,E0308
//! use stellar_agent_network::signing::payload::TxSigningPayload;
//! use stellar_agent_network::signing::{Signer, SoftwareSigningKey};
//! async fn sign(signer: &SoftwareSigningKey, tx_payload: &TxSigningPayload) {
//!     let _ = signer.sign_message(tx_payload).await;
//! }
//! ```
//!
//! The mainnet transaction constructor is private to this crate:
//!
//! ```compile_fail,E0624
//! use stellar_agent_network::mainnet::authorization::MainnetTxSignAuthorization;
//! use stellar_agent_network::signing::payload::TxSigningPayload;
//! fn build(envelope: &stellar_xdr::TransactionEnvelope, authorization: &MainnetTxSignAuthorization) {
//!     let _ = TxSigningPayload::authorized(envelope, authorization);
//! }
//! ```
//!
//! A mainnet Soroban payload is neither `Clone` nor `Copy`, is not built from
//! its parts, and signs once:
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::signing::payload::MainnetSorobanAuthPayload;
//! fn need<T: Clone>() {}
//! need::<MainnetSorobanAuthPayload>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::signing::payload::MainnetSorobanAuthPayload;
//! fn need<T: Copy>() {}
//! need::<MainnetSorobanAuthPayload>();
//! ```
//!
//! ```compile_fail,E0451
//! use stellar_agent_network::mainnet::authorization::MainnetSorobanIntentAuthorization;
//! use stellar_agent_network::signing::payload::{MainnetSorobanAuthPayload, SorobanAuthPayload};
//! fn build(payload: SorobanAuthPayload, authorization: MainnetSorobanIntentAuthorization) {
//!     let _ = MainnetSorobanAuthPayload { payload, authorization };
//! }
//! ```
//!
//! ```compile_fail,E0382
//! use stellar_agent_network::signing::Signer;
//! use stellar_agent_network::signing::payload::MainnetSorobanAuthPayload;
//! fn sign_twice(payload: MainnetSorobanAuthPayload, signer: &(dyn Signer + Send + Sync)) {
//!     let _ = payload.sign(signer);
//!     let _ = payload.sign(signer);
//! }
//! ```
//!
//! The public names resolve, so each snippet above fails on the barrier it
//! names and not on the path. A testnet transaction payload signs and
//! verifies:
//!
//! ```
//! use stellar_agent_network::signing::payload::{
//!     MainnetSorobanAuthPayload, MessagePayload, SmartAccountAuthDigest, SorobanAuthPayload,
//!     TxSigningPayload,
//! };
//! use stellar_agent_network::signing::{Signer, SoftwareSigningKey};
//! use stellar_xdr::{
//!     Memo, MuxedAccount, Preconditions, SequenceNumber, Transaction, TransactionEnvelope,
//!     TransactionExt, TransactionV1Envelope, Uint256,
//! };
//!
//! # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
//! let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
//!     tx: Transaction {
//!         source_account: MuxedAccount::Ed25519(Uint256([1; 32])),
//!         fee: 100,
//!         seq_num: SequenceNumber(1),
//!         cond: Preconditions::None,
//!         memo: Memo::None,
//!         operations: Default::default(),
//!         ext: TransactionExt::V0,
//!     },
//!     signatures: Default::default(),
//! });
//! let payload =
//!     TxSigningPayload::for_envelope(&envelope, "Test SDF Network ; September 2015").unwrap();
//! let key = SoftwareSigningKey::new_from_bytes([7; 32]);
//! let signature = key.sign_tx_payload(&payload).await.unwrap();
//! let public_key = key.public_key().await.unwrap();
//! ed25519_dalek::VerifyingKey::from_bytes(&public_key.0)
//!     .unwrap()
//!     .verify_strict(payload.as_bytes(), &ed25519_dalek::Signature::from_bytes(&signature))
//!     .unwrap();
//! # let _ = (
//! #     std::marker::PhantomData::<MainnetSorobanAuthPayload>,
//! #     std::marker::PhantomData::<SorobanAuthPayload>,
//! #     std::marker::PhantomData::<SmartAccountAuthDigest>,
//! #     MessagePayload::sep53(b"m"),
//! # );
//! # });
//! ```

use sha2::{Digest as _, Sha256};
use stellar_agent_core::error::{NetworkError, ProtocolError, WalletError};
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_soroban_auth::{AuthPreimageError, auth_signature_payload, preimage_parts};
use stellar_xdr::{
    AccountId, Hash, HashIdPreimage, Limits, PublicKey, ScAddress, TransactionEnvelope,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction, Uint256, WriteXdr,
};

use crate::mainnet::authorization::{
    MainnetSignedSorobanIntent, MainnetSorobanIntentAuthorization, MainnetTxSignAuthorization,
};
use crate::mainnet::refusal::{AuthorizedPathError, require};
use crate::mainnet::soroban::check_preimage_against_authorization;
use crate::mainnet::{
    MainnetAuthorizationError, MainnetConsumer, MainnetPrecondition as P, SignerRole,
};
use crate::signing::Signer;
use crate::signing::verify_binding::signature_verifies;
use crate::submit::MAINNET_PASSPHRASE;

/// The SEP-53 message prefix: exactly 24 ASCII bytes,
/// `"Stellar Signed Message:\n"`.
pub const SEP53_MESSAGE_PREFIX: &[u8] = b"Stellar Signed Message:\n";

/// The SEP-23 signing payload of a transaction: the transaction hash under
/// the network the payload was built for.
///
/// Built by [`TxSigningPayload::for_envelope`] or
/// [`TxSigningPayload::for_tagged`], which refuse mainnet; the mainnet payload
/// is built only under a transaction authorization. It binds the authorization's
/// agent signer public key. The keyring, software, and hardware signers refuse
/// a binding to another key. The payload is neither `Copy` nor `Clone`.
///
/// A signer callback cannot retain an owned copy of the borrowed payload:
///
/// ```compile_fail,E0507
/// use stellar_agent_network::signing::{Signer, SoftwareSigningKey, TxSigningPayload};
/// # use stellar_agent_network::signing::{MessagePayload, SmartAccountAuthDigest, SorobanAuthPayload, WebAuthnAssertion};
/// # use stellar_agent_core::WalletError;
/// struct Callback(SoftwareSigningKey);
/// #[async_trait::async_trait]
/// impl Signer for Callback {
///     async fn sign_tx_payload(
///         &self, payload: &TxSigningPayload,
///     ) -> Result<[u8; 64], WalletError> {
///         let saved = *payload;
///         self.0.sign_tx_payload(&saved).await
///     }
/// #   async fn sign_soroban_address_auth_payload(&self, p: &SorobanAuthPayload) -> Result<[u8; 64], WalletError> { self.0.sign_soroban_address_auth_payload(p).await }
/// #   async fn sign_auth_digest(&self, p: &SmartAccountAuthDigest) -> Result<[u8; 64], WalletError> { self.0.sign_auth_digest(p).await }
/// #   async fn sign_message(&self, p: &MessagePayload) -> Result<[u8; 64], WalletError> { self.0.sign_message(p).await }
/// #   async fn sign_webauthn_assertion(&self, p: &SmartAccountAuthDigest, id: &[u8]) -> Result<WebAuthnAssertion, WalletError> { self.0.sign_webauthn_assertion(p, id).await }
/// #   async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> { self.0.public_key().await }
/// }
/// ```
///
/// Cloning the borrowed payload cannot produce an owned payload:
///
/// ```compile_fail,E0308
/// use stellar_agent_network::signing::TxSigningPayload;
/// fn retain(payload: &TxSigningPayload) -> TxSigningPayload {
///     payload.clone()
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct TxSigningPayload {
    /// The digest computed from the domain preimage.
    bytes: [u8; 32],
    /// The authorized agent key for a mainnet payload.
    mainnet_signer: Option<[u8; 32]>,
}

impl TxSigningPayload {
    /// The SEP-23 payload of a V1 `Tx` or a `TxFeeBump` envelope under
    /// `network_passphrase`.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Network`] wrapping
    ///   [`NetworkError::MainnetWriteForbidden`] for the mainnet passphrase,
    ///   before the envelope is read.
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
    ///   for a legacy `TxV0` envelope, or when the payload does not encode.
    pub fn for_envelope(
        envelope: &TransactionEnvelope,
        network_passphrase: &str,
    ) -> Result<Self, WalletError> {
        refuse_mainnet_passphrase(network_passphrase)?;
        Ok(Self {
            bytes: envelope_hash(envelope, network_passphrase)?,
            mainnet_signer: None,
        })
    }

    /// The SEP-23 payload of a tagged transaction under `network_passphrase`:
    /// the outer payload of a fee bump, which is built before its envelope.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Network`] wrapping
    ///   [`NetworkError::MainnetWriteForbidden`] for the mainnet passphrase.
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
    ///   when the payload does not encode.
    pub fn for_tagged(
        tagged: &TransactionSignaturePayloadTaggedTransaction,
        network_passphrase: &str,
    ) -> Result<Self, WalletError> {
        refuse_mainnet_passphrase(network_passphrase)?;
        Ok(Self {
            bytes: tagged_hash(tagged, network_passphrase)?,
            mainnet_signer: None,
        })
    }

    /// The mainnet payload of a `Tx` envelope, under `authorization`.
    ///
    /// Refuses a fee bump, which is a domain of its own, as a binding
    /// mismatch and a legacy `TxV0` envelope as an XDR codec failure. Then
    /// requires the authorization's chain to be mainnet and the hash under the
    /// mainnet passphrase to be the bound transaction hash. The caller runs
    /// the authorization's other checks.
    pub(crate) fn authorized(
        envelope: &TransactionEnvelope,
        authorization: &MainnetTxSignAuthorization,
    ) -> Result<Self, AuthorizedPathError> {
        if matches!(envelope, TransactionEnvelope::TxFeeBump(_)) {
            return Err(AuthorizedPathError::Refused(P::BindingMismatch));
        }
        authorization.check_chain(Caip2::Mainnet)?;
        let hash = envelope_hash(envelope, MAINNET_PASSPHRASE)?;
        authorization.check_tx_hash(&hash)?;
        Ok(Self {
            bytes: hash,
            mainnet_signer: Some(authorization.signer_public_key()),
        })
    }

    /// The 32 payload bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Checks the binding before the keyring, software, or hardware signer signs.
    pub(crate) async fn check_mainnet_binding(
        &self,
        signer: &dyn Signer,
    ) -> Result<(), WalletError> {
        check_mainnet_binding(self.mainnet_signer, signer, "sign_tx_payload").await
    }

    /// A payload bound to `signer`, for this crate's trusted-signer tests.
    #[cfg(test)]
    pub(crate) fn bound_for_test(bytes: [u8; 32], signer: [u8; 32]) -> Self {
        Self {
            bytes,
            mainnet_signer: Some(signer),
        }
    }

    /// A payload over `bytes`, for this crate's tests of the signers.
    #[cfg(test)]
    pub(crate) fn from_bytes_for_test(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            mainnet_signer: None,
        }
    }
}

/// The signature payload of a Soroban address-credentials authorization
/// entry: `SHA-256` of its `HashIdPreimage` XDR, envelope type 9 or 10.
///
/// Built by [`SorobanAuthPayload::from_preimage`], which refuses mainnet. A
/// mainnet payload is borrowed only during [`MainnetSorobanAuthPayload::sign`]
/// and binds the authorization's agent signer public key. The keyring, software,
/// and hardware signers refuse a binding to another key. The payload is
/// neither `Copy` nor `Clone`.
///
/// A signer callback cannot retain an owned copy of the borrowed payload:
///
/// ```compile_fail,E0507
/// use stellar_agent_network::signing::{Signer, SoftwareSigningKey, SorobanAuthPayload};
/// # use stellar_agent_network::signing::{MessagePayload, SmartAccountAuthDigest, TxSigningPayload, WebAuthnAssertion};
/// # use stellar_agent_core::WalletError;
/// struct Callback(SoftwareSigningKey);
/// #[async_trait::async_trait]
/// impl Signer for Callback {
///     async fn sign_soroban_address_auth_payload(
///         &self, payload: &SorobanAuthPayload,
///     ) -> Result<[u8; 64], WalletError> {
///         let saved = *payload;
///         self.0.sign_soroban_address_auth_payload(&saved).await
///     }
/// #   async fn sign_tx_payload(&self, p: &TxSigningPayload) -> Result<[u8; 64], WalletError> { self.0.sign_tx_payload(p).await }
/// #   async fn sign_auth_digest(&self, p: &SmartAccountAuthDigest) -> Result<[u8; 64], WalletError> { self.0.sign_auth_digest(p).await }
/// #   async fn sign_message(&self, p: &MessagePayload) -> Result<[u8; 64], WalletError> { self.0.sign_message(p).await }
/// #   async fn sign_webauthn_assertion(&self, p: &SmartAccountAuthDigest, id: &[u8]) -> Result<WebAuthnAssertion, WalletError> { self.0.sign_webauthn_assertion(p, id).await }
/// #   async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> { self.0.public_key().await }
/// }
/// ```
///
/// Cloning the borrowed payload cannot produce an owned payload:
///
/// ```compile_fail,E0308
/// use stellar_agent_network::signing::SorobanAuthPayload;
/// fn retain(payload: &SorobanAuthPayload) -> SorobanAuthPayload {
///     payload.clone()
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct SorobanAuthPayload {
    /// The digest computed from the domain preimage.
    bytes: [u8; 32],
    /// The authorized agent key for a mainnet payload.
    mainnet_signer: Option<[u8; 32]>,
}

impl SorobanAuthPayload {
    /// `SHA-256` of the XDR of `preimage`, a Soroban authorization preimage
    /// (envelope type 9 `SorobanAuthorization` or type 10
    /// `SorobanAuthorizationWithAddress`) for a network other than mainnet.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
    ///   for a preimage of another type, or when the preimage does not encode.
    /// - [`WalletError::Network`] wrapping
    ///   [`NetworkError::MainnetWriteForbidden`] when the preimage's network
    ///   id is mainnet's.
    pub fn from_preimage(preimage: &HashIdPreimage) -> Result<Self, WalletError> {
        refuse_mainnet_preimage(preimage)?;
        Ok(Self {
            bytes: preimage_hash(preimage)?,
            mainnet_signer: None,
        })
    }

    /// The mainnet payload of `preimage` under `authorization`, which it takes
    /// by value.
    ///
    /// In order, before any key access and without reading a caller-supplied
    /// time:
    ///
    /// 1. A type 10 preimage must be bound to the account of the
    ///    authorization's signer ([`MainnetPrecondition::PreimageAddress`]).
    /// 2. `expected_signer` must be the authorization's signer
    ///    ([`MainnetPrecondition::SignerKeyMismatch`]).
    /// 3. The preimage must be the one the authorization covers, for
    ///    `consumer`, on the mainnet clock [`crate::mainnet::clock::now_ms`]:
    ///    its type, chain, consuming verb, expiry, the intent digest of its
    ///    invocation, and the entry's nonce and signature expiration ledger,
    ///    through [`check_preimage_against_authorization`].
    ///
    /// On a refusal the authorization is dropped. On success the returned
    /// payload carries it; [`MainnetSorobanAuthPayload::sign`] is the only
    /// use of either.
    ///
    /// # Errors
    ///
    /// - [`AuthorizedPayloadError::Refused`] naming the broken precondition.
    /// - [`AuthorizedPayloadError::Wallet`] with `wallet.clock_error` when the
    ///   clock cannot be read, or with
    ///   [`ProtocolError::XdrCodecFailed`] when the preimage does not encode.
    ///
    /// [`MainnetPrecondition::PreimageAddress`]: crate::mainnet::MainnetPrecondition::PreimageAddress
    /// [`MainnetPrecondition::SignerKeyMismatch`]: crate::mainnet::MainnetPrecondition::SignerKeyMismatch
    pub fn authorized(
        preimage: &HashIdPreimage,
        consumer: MainnetConsumer,
        expected_signer: &[u8; 32],
        authorization: MainnetSorobanIntentAuthorization,
    ) -> Result<MainnetSorobanAuthPayload, AuthorizedPayloadError> {
        let Some((_, network_id, bound_address)) = preimage_parts(preimage) else {
            return Err(MainnetAuthorizationError::Refused(P::BindingMismatch).into());
        };
        let bound_key = authorization.signer_public_key();
        if let Some(address) = bound_address {
            require(*address == account_address(&bound_key), P::PreimageAddress)?;
        }
        require(*expected_signer == bound_key, P::SignerKeyMismatch)?;
        let now_ms = crate::mainnet::clock::now_ms()?;
        check_preimage_against_authorization(
            &authorization,
            consumer,
            preimage,
            &network_id,
            now_ms,
        )?;
        Ok(MainnetSorobanAuthPayload {
            payload: Self {
                bytes: preimage_hash(preimage)?,
                mainnet_signer: Some(bound_key),
            },
            authorization,
        })
    }

    /// The 32 payload bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Checks the binding before the keyring, software, or hardware signer signs.
    pub(crate) async fn check_mainnet_binding(
        &self,
        signer: &dyn Signer,
    ) -> Result<(), WalletError> {
        check_mainnet_binding(
            self.mainnet_signer,
            signer,
            "sign_soroban_address_auth_payload",
        )
        .await
    }

    /// A payload over `bytes`, for this crate's tests of the signers.
    #[cfg(test)]
    pub(crate) fn from_bytes_for_test(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            mainnet_signer: None,
        }
    }

    /// A payload bound to `signer`, for this crate's trusted-signer tests.
    #[cfg(test)]
    pub(crate) fn bound_for_test(bytes: [u8; 32], signer: [u8; 32]) -> Self {
        Self {
            bytes,
            mainnet_signer: Some(signer),
        }
    }
}

/// A mainnet Soroban authorization payload together with the authorization
/// it was checked against.
///
/// Built only by [`SorobanAuthPayload::authorized`]. It is neither `Copy` nor
/// `Clone`, exposes no payload bytes, and its one method,
/// [`MainnetSorobanAuthPayload::sign`], consumes it.
pub struct MainnetSorobanAuthPayload {
    payload: SorobanAuthPayload,
    authorization: MainnetSorobanIntentAuthorization,
}

impl MainnetSorobanAuthPayload {
    /// Signs the payload once with `signer` and returns the signature with
    /// the [`MainnetSignedSorobanIntent`] that takes the authorization's
    /// place.
    ///
    /// The signer's reported public key must be the authorization's agent
    /// signer before it is asked to sign; that is the first call on `signer`,
    /// and the signature is the second. The signature must verify under that
    /// key over the payload before it is returned. The authorization must
    /// also be fresh on the trusted clock immediately before signing.
    ///
    /// # Errors
    ///
    /// - [`AuthorizedPayloadError::Refused`] naming
    ///   [`MainnetPrecondition::SignerKeyMismatch`],
    ///   [`MainnetPrecondition::SignerRoleMismatch`], or
    ///   [`MainnetPrecondition::SignatureInvalid`].
    /// - [`AuthorizedPayloadError::Refused`] when the authorization is expired,
    ///   not yet valid, or has inconsistent expiry bounds.
    /// - [`AuthorizedPayloadError::Wallet`] with the signer's or clock's error.
    ///
    /// [`MainnetPrecondition::SignerKeyMismatch`]: crate::mainnet::MainnetPrecondition::SignerKeyMismatch
    /// [`MainnetPrecondition::SignerRoleMismatch`]: crate::mainnet::MainnetPrecondition::SignerRoleMismatch
    /// [`MainnetPrecondition::SignatureInvalid`]: crate::mainnet::MainnetPrecondition::SignatureInvalid
    pub async fn sign(
        self,
        signer: &(dyn Signer + Send + Sync),
    ) -> Result<([u8; 64], MainnetSignedSorobanIntent), AuthorizedPayloadError> {
        let public_key = signer.public_key().await?;
        self.authorization
            .check_signer(&public_key.0, SignerRole::AgentSigner)?;
        self.authorization
            .check_not_expired(crate::mainnet::clock::now_ms()?)?;
        let signature = signer
            .sign_soroban_address_auth_payload(&self.payload)
            .await?;
        require(
            signature_verifies(&public_key.0, self.payload.as_bytes(), &signature),
            P::SignatureInvalid,
        )?;
        Ok((signature, self.authorization.into_signed()))
    }
}

impl std::fmt::Debug for MainnetSorobanAuthPayload {
    /// The authorization's identity prefix; the payload bytes are not shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MainnetSorobanAuthPayload")
            .field("authorization", &self.authorization)
            .finish_non_exhaustive()
    }
}

/// The failure of building or signing a [`MainnetSorobanAuthPayload`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthorizedPayloadError {
    /// A check of the authorization refused.
    #[error(transparent)]
    Refused(#[from] MainnetAuthorizationError),
    /// The clock, the encoding, or the signer failed.
    #[error(transparent)]
    Wallet(#[from] WalletError),
}

impl AuthorizedPayloadError {
    /// The agent-facing error. A refused precondition is logged under `path`
    /// with its label and becomes `network.mainnet_authorization_refused`; a
    /// wallet error passes through unchanged.
    #[must_use]
    pub fn report(self, path: &'static str) -> WalletError {
        match self {
            Self::Refused(error) => error.report(path),
            Self::Wallet(error) => error,
        }
    }
}

/// The digest an OpenZeppelin smart account's `__check_auth` verifies:
/// `SHA-256(signature_payload ‖ context_rule_ids_xdr)`, where
/// `signature_payload` is the `SHA-256` of the entry's authorization preimage.
///
/// Built by [`SmartAccountAuthDigest::new`], which refuses mainnet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmartAccountAuthDigest([u8; 32]);

impl SmartAccountAuthDigest {
    /// The digest of the Soroban authorization `preimage` (envelope type 9 or
    /// 10) bound to `context_rule_ids_xdr`, through
    /// `stellar_agent_core::smart_account::auth_digest::compute_auth_digest`.
    ///
    /// `context_rule_ids_xdr` is the XDR of the rule ids as
    /// `stellar_agent_core::smart_account::rule_id::encode_context_rule_ids`
    /// produces it.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`]
    ///   for a preimage of another type, or when the preimage does not encode.
    /// - [`WalletError::Network`] wrapping
    ///   [`NetworkError::MainnetWriteForbidden`] when the preimage's network
    ///   id is mainnet's.
    pub fn new(
        preimage: &HashIdPreimage,
        context_rule_ids_xdr: &[u8],
    ) -> Result<Self, WalletError> {
        refuse_mainnet_preimage(preimage)?;
        let signature_payload = preimage_hash(preimage)?;
        let digest = stellar_agent_core::smart_account::auth_digest::compute_auth_digest(
            &signature_payload,
            context_rule_ids_xdr,
        );
        Ok(Self(*digest.as_bytes()))
    }

    /// The 32 digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A digest over `bytes`, for this crate's tests of the signers.
    #[cfg(test)]
    pub(crate) fn from_bytes_for_test(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// The SEP-53 digest of a message:
/// `SHA-256("Stellar Signed Message:\n" ‖ message)`.
///
/// The digest carries no network. The prefix separates it from every SEP-23
/// and Soroban preimage, which open with a network id or an envelope type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessagePayload([u8; 32]);

impl MessagePayload {
    /// The SEP-53 digest of `message`, single-round `SHA-256` over
    /// [`SEP53_MESSAGE_PREFIX`] followed by the message bytes.
    #[must_use]
    pub fn sep53(message: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(SEP53_MESSAGE_PREFIX);
        hasher.update(message);
        Self(hasher.finalize().into())
    }

    /// The 32 digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Checks a payload's mainnet signer binding. Unbound payloads need no key lookup.
async fn check_mainnet_binding(
    mainnet_signer: Option<[u8; 32]>,
    signer: &dyn Signer,
    path: &'static str,
) -> Result<(), WalletError> {
    if let Some(bound_key) = mainnet_signer {
        let public_key = signer.public_key().await?;
        require(public_key.0 == bound_key, P::SignerKeyMismatch)
            .map_err(|error| error.report(path))?;
    }
    Ok(())
}

/// Refuses the mainnet passphrase.
fn refuse_mainnet_passphrase(network_passphrase: &str) -> Result<(), WalletError> {
    if network_passphrase == MAINNET_PASSPHRASE {
        return Err(WalletError::Network(NetworkError::MainnetWriteForbidden));
    }
    Ok(())
}

/// Requires `preimage` to be a Soroban authorization preimage whose network
/// id is not mainnet's.
fn refuse_mainnet_preimage(preimage: &HashIdPreimage) -> Result<(), WalletError> {
    let Some((_, network_id, _)) = preimage_parts(preimage) else {
        return Err(WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: "preimage is not a Soroban authorization HashIdPreimage \
                     (envelope type 9 or 10)"
                .to_owned(),
        }));
    };
    if network_id == <[u8; 32]>::from(Sha256::digest(MAINNET_PASSPHRASE.as_bytes())) {
        return Err(WalletError::Network(NetworkError::MainnetWriteForbidden));
    }
    Ok(())
}

/// The account address of an ed25519 key.
fn account_address(key: &[u8; 32]) -> ScAddress {
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(*key))))
}

/// `SHA-256` of the XDR of `preimage`.
fn preimage_hash(preimage: &HashIdPreimage) -> Result<[u8; 32], WalletError> {
    auth_signature_payload(preimage).map_err(|error| {
        let detail = match error {
            AuthPreimageError::Encode { detail } => detail,
            other => other.to_string(),
        };
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("HashIdPreimage XDR encode failed: {detail}"),
        })
    })
}

/// The SEP-23 hash of a V1 `Tx` or `TxFeeBump` envelope; a legacy `TxV0`
/// envelope is refused.
fn envelope_hash(
    envelope: &TransactionEnvelope,
    network_passphrase: &str,
) -> Result<[u8; 32], WalletError> {
    let tagged = match envelope {
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
    tagged_hash(&tagged, network_passphrase)
}

/// The SEP-23 hash of `tagged` under `network_passphrase`:
/// `SHA-256(TransactionSignaturePayload)`.
fn tagged_hash(
    tagged: &TransactionSignaturePayloadTaggedTransaction,
    network_passphrase: &str,
) -> Result<[u8; 32], WalletError> {
    let payload = TransactionSignaturePayload {
        network_id: Hash(Sha256::digest(network_passphrase.as_bytes()).into()),
        tagged_transaction: tagged.clone(),
    };
    let bytes = payload.to_xdr(Limits::none()).map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("TransactionSignaturePayload XDR encode failed: {e}"),
        })
    })?;
    Ok(Sha256::digest(&bytes).into())
}

// The fixtures and refusal cases live separately to keep the signing boundary readable.
#[cfg(test)]
mod tests;
