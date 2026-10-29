//! Signing abstractions for the Stellar agent wallet.
//!
//! Exposes the `Signer` trait and two concrete implementations:
//! `SoftwareSigningKey` (ed25519 secret key held in a `secrecy::SecretBox`)
//! and `HardwareSigningKey` (delegates to a connected Ledger device via
//! `stellar_ledger::LedgerSigner<TransportNativeHID>`).
//!
//! The public alias `SigningKey` re-exports `SoftwareSigningKey` for
//! crate-internal compatibility.
//!
//! # Design choice: trait (A) over enum (B)
//!
//! `Signer` is a `#[async_trait]` trait rather than a `SigningKey` enum
//! wrapping the two concrete types. Rationale:
//!
//! - **Testability without feature-flag contamination.** Tests can supply any
//!   `impl Signer` — including a `MockSigner` — without pulling in HID
//!   transport or conditional compilation flags.
//! - **Extensibility.** A future smart-account signing path (multi-sig,
//!   passkey) implements `Signer` without touching the enum arms and without
//!   breaking callers that hold `&dyn Signer`.
//! - **API boundary.** `ClassicOpBuilder::build_and_sign`,
//!   `envelope_signing::attach_signature` and the other signing points take
//!   `&dyn Signer`, so the concrete type is invisible to the calling crate.
//!   Submission takes an already signed envelope and no signer. An enum would
//!   need to be `pub` in full and would expose the `HardwareSigningKey`
//!   concrete type at the module boundary even when callers do not need it.
//! - **Parity with `stellar-ledger`.** `stellar_ledger::signer::Blob` is
//!   already a trait; mirroring that style keeps the two surfaces parallel.
//!
//! The downside of (A) — `async-trait` overhead and the `dyn` allocation — is
//! acceptable: signing is not on a hot loop path. `async-trait` is already a
//! direct dep of `stellar-ledger` and is declared workspace-wide.
//!
//! # Secret-material discipline
//!
//! Raw secret bytes are accessible only via
//! `SoftwareSigningKey::expose_secret_for_signing`. That method is `pub(crate)`
//! and is called by the crate-private raw primitive `SoftwareSigningKey::sign_raw`
//! and by `SoftwareSigningKey::public_key` only.
//!
//! `HardwareSigningKey` never holds secret bytes; the device retains the key.
//!
//! # Typed payloads
//!
//! Every ed25519 method of [`Signer`] takes a payload type of the
//! [`payload`] module, never raw bytes. The constructors of those types refuse
//! mainnet; a mainnet transaction or Soroban authorization payload is built
//! only under a mainnet authorization. See the [`payload`] module for the
//! domains and the compile-time contract.

pub mod envelope_signing;
pub mod hardware;
pub mod payload;
pub mod software;
pub mod source;
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_doubles;
pub(crate) mod verify_binding;
pub mod wallet;

pub use hardware::HardwareSigningKey;
pub use payload::{
    AuthorizedPayloadError, MainnetSorobanAuthPayload, MessagePayload, SmartAccountAuthDigest,
    SorobanAuthPayload, TxSigningPayload,
};
pub use software::SoftwareSigningKey;

/// Crate-internal alias: `SigningKey` resolves to `SoftwareSigningKey`.
///
/// New code should use `SoftwareSigningKey` directly to signal intent clearly.
pub use software::SoftwareSigningKey as SigningKey;

use async_trait::async_trait;
use stellar_agent_core::error::WalletError;

/// Abstraction over a signing operation that produces a 64-byte ed25519
/// signature from a typed 32-byte payload.
///
/// Implemented by [`SoftwareSigningKey`] (ed25519 key in memory) and
/// [`HardwareSigningKey`] (Ledger device over HID).  Callers take
/// `&(dyn Signer + Send + Sync)` or `impl Signer` so the concrete type is
/// invisible at the call site.
///
/// Each ed25519 method takes the payload type of its domain from the
/// [`payload`] module. The types are distinct, so a payload of one domain
/// cannot reach the method of another, and their constructors refuse mainnet
/// unless a mainnet authorization produced the payload. Every method is
/// required, so each implementation states what it does for each domain.
///
/// # Errors
///
/// Every implementation maps its errors into the [`WalletError`] taxonomy so
/// callers have a uniform error type.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::signing::{MessagePayload, Signer, SoftwareSigningKey};
///
/// # async fn example() -> Result<(), stellar_agent_core::WalletError> {
/// let key = SoftwareSigningKey::new_from_bytes([0u8; 32]);
/// let payload = MessagePayload::sep53(b"hello");
/// let sig = key.sign_message(&payload).await?;
/// assert_eq!(sig.len(), 64);
/// # Ok(()) }
/// ```
#[async_trait]
pub trait Signer: Send + Sync {
    /// Signs a SEP-23 transaction payload and returns a 64-byte ed25519
    /// signature.
    ///
    /// # Payload contract
    ///
    /// `payload` is `SHA-256(network_id ‖ TransactionSignaturePayloadTaggedTransaction)`
    /// of a V1 `Tx` or a `TxFeeBump`, built by
    /// [`TxSigningPayload::for_envelope`] or [`TxSigningPayload::for_tagged`]
    /// for a network other than mainnet, or by the crate's authorized
    /// transaction signing under a mainnet transaction authorization.
    ///
    /// The signing call sites:
    ///
    /// - `envelope_signing::attach_signature`: SEP-23 transaction envelope
    ///   signing, reached from `ClassicOpBuilder::build_and_sign`,
    ///   `ClassicOpBuilder::build_and_sign_multi`, and SEP-43
    ///   `signTransaction` (`stellar_agent_sep43::signing::sign_classic_transaction`).
    ///   Its mainnet sibling `envelope_signing::attach_signature_authorized`
    ///   signs under a transaction authorization after the authorization's
    ///   checks.
    /// - `fee_bump::build_and_sign_fee_bump`: the outer payload of a fee bump
    ///   (`TransactionSignaturePayloadTaggedTransaction::TxFeeBump`, CAP-0015),
    ///   built around the signed inner transaction after its fee source is
    ///   checked against the signer's key.
    ///
    /// A hardware signer in blind-signing mode signs the 32 bytes it receives;
    /// the payload type is what ties them to a transaction. The keyring,
    /// software, and hardware signers refuse a mainnet payload bound to
    /// another signer key with `network.mainnet_authorization_refused`.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Auth`] — the user refused on a hardware device
    ///   (`HardwareUserRefused`).
    /// - [`WalletError::WalletState`] — device not found, wrong app, timeout,
    ///   or blind signing disabled.
    /// - [`WalletError::Protocol`] — XDR or decoding failure in the signing
    ///   payload construction path.
    /// - [`WalletError::Internal`] — BIP-32 path encoding failure or other
    ///   unexpected state.
    async fn sign_tx_payload(&self, payload: &TxSigningPayload) -> Result<[u8; 64], WalletError>;

    /// Signs a smart-account auth digest, returning the 64-byte ed25519
    /// signature.
    ///
    /// # Payload contract
    ///
    /// `digest` is `SHA-256(signature_payload ‖ context_rule_ids_xdr)`, built
    /// by [`SmartAccountAuthDigest::new`] for a network other than mainnet.
    ///
    /// The call sites are the smart-account entry assemblers in
    /// `stellar_agent_smart_account::managers::auth_entry`:
    /// `complete_authorization_entry`,
    /// `complete_authorization_entry_multi_signer`, and the mixed-signer
    /// collector `collect_mixed_signer_entries`.
    ///
    /// # Errors
    ///
    /// Same variants as [`Signer::sign_tx_payload`].
    async fn sign_auth_digest(
        &self,
        digest: &SmartAccountAuthDigest,
    ) -> Result<[u8; 64], WalletError>;

    /// Signs a Soroban address-credentials authorization-entry payload,
    /// returning the 64-byte ed25519 signature.
    ///
    /// # Payload contract
    ///
    /// `payload` is the SHA-256 of the XDR of a Soroban authorization
    /// preimage for an entry whose credential `address` is a Stellar account
    /// (G-key):
    ///
    /// - `HashIdPreimage::SorobanAuthorization { network_id, nonce,
    ///   signature_expiration_ledger, invocation }` (envelope type 9) for
    ///   `SorobanCredentials::Address`;
    /// - `HashIdPreimage::SorobanAuthorizationWithAddress { network_id, nonce,
    ///   signature_expiration_ledger, address, invocation }` (envelope type
    ///   10, CAP-71) for `SorobanCredentials::AddressV2`.
    ///
    /// It is built by [`SorobanAuthPayload::from_preimage`] for a network
    /// other than mainnet, or inside a [`MainnetSorobanAuthPayload`] under a
    /// mainnet Soroban intent authorization. A mainnet payload is borrowed
    /// only during the wrapper's consuming call and binds the authorization's
    /// agent signer key. The keyring, software, and hardware implementations
    /// refuse a binding to another key with `network.mainnet_authorization_refused`.
    ///
    /// The signing call sites:
    ///
    /// - `stellar_agent_sep43::signing::sign_soroban_auth_entry`: the SEP-43
    ///   `signAuthEntry` G-key path. The x402 and MPP payment paths reach
    ///   this method through it.
    /// - [`MainnetSorobanAuthPayload::sign`]: the mainnet path, reached from
    ///   `stellar_agent_sep43::signing::sign_soroban_auth_entry_authorized`.
    /// - `build_and_sign_delegated_g_key_entry` in
    ///   `stellar_agent_smart_account::managers::auth_entry`: the Delegated
    ///   G-key auth entry that OZ smart accounts require alongside the
    ///   smart-account entry whenever the validating context rule includes
    ///   `Signer::Delegated(addr)` where `addr` is a Stellar G-key.
    /// - The per-entry signing loop in
    ///   `stellar_agent_smart_account::timelock_submit`: the G-key address
    ///   entries of a timelock operation.
    ///
    /// # Errors
    ///
    /// Same variants as [`Signer::sign_tx_payload`], plus
    /// `network.mainnet_authorization_refused` for a mainnet binding to
    /// another signer key.
    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &SorobanAuthPayload,
    ) -> Result<[u8; 64], WalletError>;

    /// Signs a SEP-53 message digest, returning the 64-byte ed25519
    /// signature.
    ///
    /// # Payload contract
    ///
    /// `payload` is `SHA-256("Stellar Signed Message:\n" ‖ message)`, built by
    /// [`MessagePayload::sep53`]. The digest carries no network; the callers
    /// refuse a mainnet profile before they build it.
    ///
    /// The signing call sites are `stellar_agent_sep53::sign_message` and
    /// SEP-43 `signMessage` (`stellar_agent_sep43::signing::sign_message_bytes`),
    /// which sign the same digest.
    ///
    /// # Errors
    ///
    /// Same variants as [`Signer::sign_tx_payload`]; a signer that does not
    /// sign messages returns [`WalletError::Auth`] wrapping
    /// `AuthError::SignerKindMismatch`.
    async fn sign_message(&self, payload: &MessagePayload) -> Result<[u8; 64], WalletError>;

    /// Signs a WebAuthn assertion over the auth digest.
    ///
    /// Implements the `External` arm of the OZ smart-account `Signer` enum
    /// (`Signer::External(verifier, key_data)`). The call:
    ///
    /// 1. Locates the credential by `credential_id` in the wallet's keyring-core
    ///    credential store (passkey-credential records persisted by
    ///    `stellar-agent credentials add-passkey`).
    /// 2. Consumes the assertion produced by the browser-handoff approval
    ///    bridge: the operator runs the WebAuthn ceremony in their browser via
    ///    the wallet-owned approval spine, the bridge persists the resulting
    ///    assertion (`authenticator_data`, `client_data_json`,
    ///    `signature_compact`, `credential_id`) in the `PendingApproval`
    ///    record, and the signer reads it from there.
    /// 3. Consumes the compact low-S signature normalised by the bridge via
    ///    `stellar_agent_smart_account::webauthn::sig_normalize::normalize_der_to_compact_low_s`.
    /// 4. Off-chain pre-verifies via
    ///    `stellar_agent_smart_account::webauthn::pre_verifier::pre_verify_assertion`
    ///    (compact 64-byte r||s required by the COSE verifier).
    /// 5. Returns the [`WebAuthnAssertion`] payload the auth-entry builder
    ///    consumes.
    ///
    /// # Single-call-site invariant
    ///
    /// `sign_webauthn_assertion` is called exclusively from
    /// `stellar_agent_smart_account::managers::auth_entry::complete_authorization_entry`,
    /// mirroring the `sign_auth_digest` and `sign_soroban_address_auth_payload`
    /// invariants. Direct call sites outside that path violate the single-call-site
    /// invariant and are rejected by repository gate rules.
    ///
    /// # Signing flow
    ///
    /// The canonical signing flow calls
    /// `webauthnProvider.authenticate(authDigest, allowCredentials)` followed
    /// by a signature-normalisation step.
    /// This implementation mirrors that flow via a browser-handoff approval
    /// spine instead of a platform-native authenticator, because RP-ID domain
    /// binding is incompatible with `cargo install`-distributed CLI binaries
    /// (no Apple Associated Domains entitlement, no AASA hosting).
    ///
    /// # Errors
    ///
    /// - [`WalletError::Auth`] — variants:
    ///   - `AuthError::SignerKindMismatch` — signer kind cannot produce
    ///     WebAuthn assertions (returned by `SoftwareSigningKey`,
    ///     `HardwareSigningKey`, `KeyringSignHandle`; only `PasskeySignHandle`
    ///     produces them).
    ///   - `AuthError::HardwareUserRefused` — the operator refused or timed
    ///     out the browser-handoff WebAuthn ceremony (passkey signers).
    /// - [`WalletError::WalletState`] — credential not found in the keyring
    ///   credential store, platform authenticator unavailable, etc.
    /// - [`WalletError::Internal`] — unexpected XDR / WebAuthn-pre-verifier
    ///   failure.
    async fn sign_webauthn_assertion(
        &self,
        auth_digest: &SmartAccountAuthDigest,
        credential_id: &[u8],
    ) -> Result<WebAuthnAssertion, WalletError>;

    /// Returns the ed25519 public key corresponding to this signing identity.
    ///
    /// For software keys this is derived deterministically from the secret
    /// seed.  For hardware keys this is fetched from the device at the
    /// configured HD path. The Stellar Ledger app at the `stellar-cli` 26.0.0
    /// release target does not prompt the user for a plain `GET_PUBLIC_KEY`
    /// call (P1=0x00). Other firmware versions may behave differently.
    ///
    /// # Errors
    ///
    /// Same variants as [`Signer::sign_tx_payload`] minus `HardwareUserRefused`
    /// (fetching the public key does not prompt the user for approval).
    async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError>;
}

/// Wallet-side mirror of the OZ on-chain `WebAuthnSigData`.
///
/// Returned by [`Signer::sign_webauthn_assertion`] and consumed by the
/// External-arm encoder in `stellar_agent_smart_account::webauthn::sig_data`
/// (`encode_webauthn_sig_data_scval`).
///
/// # Placement rationale
///
/// The struct lives in `stellar-agent-network` next to the `Signer` trait so
/// the trait method's return type is in-crate; the smart-account-side encoders
/// re-export via `pub use` for ergonomic callers within
/// `stellar-agent-smart-account`.
///
/// # Fields
///
/// - `signature_compact`: 64-byte raw r||s (low-S enforced wallet-side as
///   malleability hardening; on-chain `secp256r1_verify` does not reject
///   high-S).
/// - `authenticator_data`: raw authenticator data per W3C WebAuthn-2 §6.1.
/// - `client_data_json`: raw `clientDataJSON` per W3C WebAuthn-2 §5.8.1.1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebAuthnAssertion {
    /// 64-byte compact secp256r1 signature (raw r||s, low-S enforced
    /// wallet-side).
    ///
    /// Low-S is enforced wallet-side as a malleability-hardening measure.
    /// The on-chain OZ verifier calls `secp256r1_verify` via
    /// `p256::ecdsa::VerifyingKey::verify_prehash`, which accepts both low-S
    /// and high-S signatures, so the wallet-side normalisation is hardening,
    /// not an on-chain requirement.
    pub signature_compact: [u8; 64],
    /// Raw authenticator data bytes per W3C WebAuthn-2 §6.1.
    ///
    /// Minimum 37 bytes. Byte 32 carries the flags field (UP | UV | BE | BS bits).
    pub authenticator_data: Vec<u8>,
    /// Raw `clientDataJSON` bytes per W3C WebAuthn-2 §5.8.1.1.
    ///
    /// Must contain `"type":"webauthn.get"` and a `challenge` field whose
    /// value is `base64url(auth_digest[0..32])`, validated on-chain by the OZ
    /// WebAuthn verifier.
    pub client_data_json: Vec<u8>,
}
