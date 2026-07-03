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
//! - **API boundary.** `ClassicOpBuilder::sign` and
//!   `submit_transaction_and_wait` take `&(dyn Signer + Send + Sync)`, so the
//!   concrete type is invisible to the calling crate. An enum would need to be
//!   `pub` in full and would expose the `HardwareSigningKey` concrete type at
//!   the module boundary even when callers do not need it.
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
//! and is called by `SoftwareSigningKey::sign_tx_payload` and
//! `SoftwareSigningKey::public_key` only.
//!
//! `HardwareSigningKey` never holds secret bytes; the device retains the key.

pub mod envelope_signing;
pub mod hardware;
pub mod software;
pub mod source;
pub mod wallet;

pub use hardware::HardwareSigningKey;
pub use software::SoftwareSigningKey;

/// Crate-internal alias: `SigningKey` resolves to `SoftwareSigningKey`.
///
/// New code should use `SoftwareSigningKey` directly to signal intent clearly.
pub use software::SoftwareSigningKey as SigningKey;

use async_trait::async_trait;
use stellar_agent_core::error::WalletError;

/// Abstraction over a signing operation that produces a 64-byte ed25519
/// signature from a 32-byte transaction hash payload.
///
/// Implemented by [`SoftwareSigningKey`] (ed25519 key in memory) and
/// [`HardwareSigningKey`] (Ledger device over HID).  Callers take
/// `&(dyn Signer + Send + Sync)` or `impl Signer` so the concrete type is
/// invisible at the call site.
///
/// # Errors
///
/// Every implementation maps its errors into the [`WalletError`] taxonomy so
/// callers have a uniform error type.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::signing::{Signer, SoftwareSigningKey};
///
/// # async fn example() -> Result<(), stellar_agent_core::WalletError> {
/// let key = SoftwareSigningKey::new_from_bytes([0u8; 32]);
/// let payload = [0u8; 32];
/// let sig = key.sign_tx_payload(&payload).await?;
/// assert_eq!(sig.len(), 64);
/// # Ok(()) }
/// ```
#[async_trait]
pub trait Signer: Send + Sync {
    /// Signs a 32-byte transaction hash payload and returns a 64-byte
    /// ed25519 signature.
    ///
    /// # Payload contract
    ///
    /// The `payload` MUST be the SEP-23 transaction-signing payload:
    /// `sha256(network_id_bytes || TransactionSignaturePayloadTaggedTransaction_XDR)`.
    ///
    /// The implementation does NOT validate the preimage. Passing a
    /// mis-constructed hash produces a cryptographically valid signature
    /// over the wrong message that the network will reject at submission
    /// (or, worse, for hardware signers in blind-signing mode, the device
    /// signs whatever 32 bytes arrive without validation).
    ///
    /// Sanctioned call sites:
    ///
    /// - **Primary:** `ClassicOpBuilder::sign` — SEP-23 transaction envelope
    ///   signing via `envelope_signing::attach_signature`.
    /// - **Secondary — SEP-43 `signTransaction`:**
    ///   `stellar_agent_sep43::signing::sign_classic_transaction` — delegates to
    ///   `attach_signature`, which is the primary call site; this is therefore an
    ///   indirect secondary use, not a raw duplicate.
    /// - **Secondary — SEP-43 `signMessage`:**
    ///   `stellar_agent_sep43::signing::sign_message_bytes` — the payload is
    ///   `sha256(message_bytes)`. The ed25519 primitive is identical but the
    ///   payload domain is "message hash", NOT a SEP-23 transaction-signing
    ///   payload. The domain separation is documented in `sign_message_bytes`.
    /// - **Secondary — SEP-53 `sign_message`:**
    ///   `stellar_agent_sep53::sign_message` — the payload is
    ///   `sha256("Stellar Signed Message:\n" || message_bytes)`, the SEP-53
    ///   prefixed digest. Domain-separated from the SEP-23 tx payload by the
    ///   24-byte ASCII prefix `"Stellar Signed Message:\n"` vs the 32-byte
    ///   `network_id` / Soroban `HashIDPreimage` header that opens every
    ///   SEP-23 / Soroban preimage. The prefix makes cross-domain preimage
    ///   collision cryptographically infeasible. See SEP-53 §3.
    /// - **Secondary — fee-bump outer-envelope signing:**
    ///   `fee_bump::build_and_sign_fee_bump` — signs the SEP-23 `TxFeeBump`-tagged
    ///   payload (`TransactionSignaturePayloadTaggedTransaction::TxFeeBump`,
    ///   `EnvelopeType::TxFeeBump`). The ed25519 primitive and the
    ///   `sha256(network_id ‖ XDR)` preimage mechanism are identical; only the
    ///   tagged-transaction variant differs (`TxFeeBump` vs `Tx`), giving the
    ///   fee-bump its own network-id-bound hash distinct from the inner tx hash.
    ///   A separate signing site is required because `attach_signature` is
    ///   hard-wired to `TaggedTransaction::Tx` and rejects non-`Tx` envelopes.
    ///   See CAP-0015.
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
    async fn sign_tx_payload(&self, payload: &[u8; 32]) -> Result<[u8; 64], WalletError>;

    /// Signs a 32-byte smart-account auth-digest, returning the 64-byte
    /// ed25519 signature.
    ///
    /// # Payload contract
    ///
    /// The `digest` MUST be the output of
    /// `stellar_agent_core::smart_account::auth_digest::compute_auth_digest`,
    /// i.e. `sha256(signature_payload || encode_context_rule_ids(rule_ids))`.
    /// This is a DIFFERENT payload class from [`Signer::sign_tx_payload`]'s
    /// SEP-23 transaction-signing payload; the two methods MUST NOT be
    /// substituted for each other.
    ///
    /// Cryptographically the primitive is identical (32-byte ed25519 sign
    /// → 64-byte signature). The split is a call-site discipline: smart-account
    /// auth-entry assembly invokes `sign_auth_digest`, classic transaction
    /// signing invokes `sign_tx_payload`.
    ///
    /// The single call site is
    /// `stellar_agent_smart_account::managers::auth_entry::complete_authorization_entry`.
    ///
    /// # Errors
    ///
    /// Same variants as [`Signer::sign_tx_payload`].
    async fn sign_auth_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], WalletError>;

    /// Signs a 32-byte Soroban address-credentials authorization-entry
    /// signature_payload, returning the 64-byte ed25519 signature.
    ///
    /// # Payload contract
    ///
    /// The `payload` MUST be the standard Soroban auth-entry signing
    /// payload: `sha256(HashIdPreimage::SorobanAuthorization { network_id,
    /// nonce, signature_expiration_ledger, invocation }.to_xdr())`. This is
    /// the payload signed by SorobanAuthorizationEntry credentials of type
    /// `SorobanCredentials::Address` whose `address` is a Stellar account
    /// (G-key).
    ///
    /// # Distinct from sibling primitives
    ///
    /// - [`Signer::sign_tx_payload`] signs a SEP-23 transaction-envelope
    ///   payload.
    /// - [`Signer::sign_auth_digest`] signs an OZ smart-account auth-digest
    ///   that binds context-rule IDs into the standard Soroban
    ///   signature_payload.
    /// - This method signs the standard Soroban auth-entry signature_payload
    ///   (no rule-ID binding); used for the secondary "Delegated G-key"
    ///   auth entry that OZ smart accounts require alongside the
    ///   smart-account entry whenever the validating context rule includes
    ///   `Signer::Delegated(addr)` where `addr` is a Stellar G-key.
    ///
    /// All three methods MUST NOT be substituted for each other.
    /// Cryptographically the primitive is identical (32-byte ed25519 sign
    /// → 64-byte signature); the split is a call-site discipline.
    ///
    /// Sanctioned call sites:
    ///
    /// - **Primary:** `build_and_sign_delegated_g_key_entry` in
    ///   `stellar_agent_smart_account::managers::rules` — the Delegated G-key
    ///   auth-entry path in the OZ smart-account manager.
    /// - **Secondary — SEP-43 `signAuthEntry`:**
    ///   `stellar_agent_sep43::signing::sign_soroban_auth_entry` —
    ///   the SEP-43 G-key auth-entry signing path. The preimage is
    ///   `HashIdPreimage::SorobanAuthorization` per SEP-45 / SEP-43
    ///   cross-protocol convention. The ed25519 primitive is identical.
    ///
    /// # Errors
    ///
    /// Same variants as [`Signer::sign_tx_payload`].
    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &[u8; 32],
    ) -> Result<[u8; 64], WalletError>;

    /// Signs a WebAuthn assertion over the auth-digest.
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
        auth_digest: &[u8; 32],
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
/// External-arm encoders in `stellar_agent_smart_account::webauthn::sig_data`
/// (`encode_webauthn_sig_data_scval` / `encode_webauthn_signature_value_bytes`).
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
