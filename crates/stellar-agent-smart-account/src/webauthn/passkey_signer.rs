//! `PasskeySignHandle` — the `Signer` impl that produces WebAuthn assertions
//! from pre-obtained assertion bytes.
//!
//! This is the fourth `Signer` implementation (alongside `SoftwareSigningKey`,
//! `HardwareSigningKey`, and `KeyringSignHandle`) and the only one that
//! implements `sign_webauthn_assertion` to produce an actual assertion. The
//! other three return `AuthError::SignerKindMismatch` (they are ed25519-only).
//!
//! Symmetrically, `PasskeySignHandle` returns `AuthError::SignerKindMismatch`
//! for `sign_tx_payload`, `sign_auth_digest`, `sign_soroban_address_auth_payload`,
//! and `public_key` — it is a passkey-only signer with no ed25519 surface.
//!
//! # Architecture
//!
//! `PasskeySignHandle` holds an `assertion: AssertionInput`: the WebAuthn
//! ceremony bytes are bound at construction time, having been produced by the
//! browser-handoff path (`stellar-agent-webauthn-bridge`) and stored in the
//! approval spine via `ApprovalKind::SignWithPasskey`. The trait method
//! signature on `Signer::sign_webauthn_assertion` is unchanged.
//!
//! # Step ordering rationale
//!
//! The bridge normalises browser DER into compact low-S form before storing
//! `AssertionInput`; this signer pipeline runs `pre_verify → return` over that
//! compact 64-byte `r||s` signature.
//!
//! The `key_data` checked on-chain is the 65-byte pubkey + credential-ID
//! suffix stored in `PasskeyCredentialRecord`.
//!
//! # Security
//!
//! `PasskeySignHandle` is silent at `info` level regarding credential-specific
//! bytes. `assertion_input.signature_compact`, `client_data_json`, and `credential_id`
//! MUST NOT be interpolated into any `tracing::*!` macro call. The `Debug` impl
//! on `AssertionInput` redacts to length-only.
//! The `SaPasskeySignatureNormalised` audit-log event fires at the signing-manager
//! call site, not here.

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use stellar_agent_core::error::{AuthError, WalletError};
use stellar_agent_network::signing::{Signer, WebAuthnAssertion};
use stellar_strkey::ed25519::PublicKey;

use crate::SaError;
use crate::webauthn::pre_verifier::pre_verify_assertion;
#[cfg(test)]
use crate::webauthn::sig_normalize::normalize_der_to_compact_low_s;

// ─────────────────────────────────────────────────────────────────────────────
// AssertionInput — re-exported from stellar-agent-core
// ─────────────────────────────────────────────────────────────────────────────

/// Bytes produced by a successful WebAuthn ceremony, consumed by
/// [`PasskeySignHandle::sign_webauthn_assertion`].
///
/// Located in `stellar_agent_core::approval::AssertionInput` so that
/// `PendingApproval` (in `stellar-agent-core`) can hold
/// `Option<AssertionInput>` without creating a circular crate dependency
/// (`stellar-agent-smart-account` already depends on `stellar-agent-core`).
/// Re-exported here for source compatibility with callers that import
/// `stellar_agent_smart_account::webauthn::passkey_signer::AssertionInput`.
pub use stellar_agent_core::approval::AssertionInput;

// ─────────────────────────────────────────────────────────────────────────────
// Credential record
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata for a single passkey credential stored in the wallet's keyring-core
/// credential store.
///
/// The credential record binds the platform-assigned `credential_id` (the
/// lookup key used in the WebAuthn allow-credentials list) to the
/// `public_key_uncompressed` (the secp256r1 public key returned at registration,
/// needed for off-chain pre-verification) and the `rp_id` (required by every
/// WebAuthn operation).
///
/// The `rp_id_hash` field (`sha256(rp_id)`) is pre-computed at construction
/// time so `pre_verify_assertion` can validate authenticator-data's RP-ID
/// hash field without recomputing on every signing call.
///
/// # Byte-layout invariant
///
/// `public_key_uncompressed` is a 65-byte uncompressed secp256r1 point:
/// `0x04 || X[32] || Y[32]`. Canonical source: SEC1 X9.62 §2.3.3.
#[derive(Debug, Clone)]
pub struct PasskeyCredentialRecord {
    /// The credential identifier assigned by the platform authenticator at
    /// registration time. Typically 16–64 bytes.
    ///
    /// Used to restrict a WebAuthn ceremony to this specific credential. Also
    /// forms the credential-ID suffix of the External-arm `key_data` bytes in
    /// the OZ Signer encoding
    /// (`key_data = pubkey_65_bytes || credential_id_bytes`).
    pub credential_id: Vec<u8>,

    /// The 65-byte uncompressed secp256r1 public key (`0x04 || X[32] || Y[32]`).
    ///
    /// Layout per SEC1 X9.62 §2.3.3 (65 bytes):
    /// - Byte 0: `0x04` (uncompressed point tag).
    /// - Bytes 1..33: X coordinate (big-endian).
    /// - Bytes 33..65: Y coordinate (big-endian).
    ///
    /// Used by `pre_verify_assertion` (step 7: `COSEKey::verify_signature`)
    /// to validate the signature off-chain before chain-submission.
    pub public_key_uncompressed: [u8; 65],

    /// Relying-party identifier string (e.g. `"stellar.agent.wallet"`).
    ///
    /// Must match the `rp_id` used at credential registration time.
    pub rp_id: String,

    /// SHA-256 hash of `rp_id` (pre-computed at construction time).
    ///
    /// Used by `pre_verify_assertion` step 3 (RP-ID-hash check) to validate
    /// the first 32 bytes of `authenticator_data` against the expected RP.
    /// Pre-computed to avoid recomputing on every signing call.
    ///
    /// Canonical source for the authenticator-data RP-ID-hash field:
    /// W3C WebAuthn Level 2 §6.1 (rpIdHash at bytes 0..32 of authenticatorData).
    pub rp_id_hash: [u8; 32],
}

impl PasskeyCredentialRecord {
    /// Construct a `PasskeyCredentialRecord`, computing `rp_id_hash` from
    /// `rp_id` via SHA-256.
    ///
    /// # Parameters
    ///
    /// - `credential_id`: the credential identifier from the registration result.
    /// - `public_key_uncompressed`: the 65-byte uncompressed secp256r1 public key.
    /// - `rp_id`: the relying-party identifier string.
    #[must_use]
    pub fn new(
        credential_id: Vec<u8>,
        public_key_uncompressed: [u8; 65],
        rp_id: impl Into<String>,
    ) -> Self {
        let rp_id = rp_id.into();
        let rp_id_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
        Self {
            credential_id,
            public_key_uncompressed,
            rp_id,
            rp_id_hash,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PasskeySignHandle
// ─────────────────────────────────────────────────────────────────────────────

/// A `Signer` implementation that produces WebAuthn assertions from pre-obtained
/// assertion bytes.
///
/// `PasskeySignHandle` is the only `Signer` implementation that actually
/// fulfils `sign_webauthn_assertion`. All other `Signer` implementations
/// (`SoftwareSigningKey`, `HardwareSigningKey`, `KeyringSignHandle`) return
/// `AuthError::SignerKindMismatch` for this method.
///
/// Conversely, `PasskeySignHandle` returns `AuthError::SignerKindMismatch`
/// for all ed25519-only methods: `sign_tx_payload`, `sign_auth_digest`,
/// `sign_soroban_address_auth_payload`, and `public_key`.
///
/// # Construction
///
/// Constructed by the signing manager (`managers/credentials.rs`) after
/// reading an `AssertionInput` from the approval store's
/// `ApprovalKind::SignWithPasskey` arm. Each signing call constructs a
/// one-shot handle bound to a specific `(credential, assertion)` pair;
/// no shared mutable state.
///
/// # Single-call-site invariant
///
/// `PasskeySignHandle::sign_webauthn_assertion` is the single implementation
/// of the `sign_webauthn_assertion` trait method that produces assertions.
/// It MUST only be invoked via `complete_authorization_entry` in
/// `crates/stellar-agent-smart-account/src/managers/auth_entry.rs`.
/// A CI gate enforces this single-call-site constraint.
///
/// # Signing flow
///
/// `PasskeySignHandle` performs the canonical WebAuthn signing flow: credential
/// lookup, normalise, build the WebAuthn signature, and pass it to the
/// auth-entry signer.
///
/// Intentional divergence: the canonical flow calls the platform authenticator
/// inline. The wallet's browser-handoff architecture decouples the ceremony
/// (done by the browser before this method is called) from the signing pipeline
/// (this method). The bytes consumed here are identical to what the
/// authenticator returns; the difference is only in the acquisition path.
pub struct PasskeySignHandle {
    /// The credential metadata bound to this handle.
    ///
    /// Provides the public key needed for off-chain pre-verification and the
    /// `rp_id_hash` for the RP-ID-hash check in `pre_verify_assertion`.
    credential: PasskeyCredentialRecord,
    /// The WebAuthn assertion bytes obtained from the browser ceremony.
    ///
    /// Bound at construction time from the approval-store `SignWithPasskey`
    /// record. Contains `credential_id`, `authenticator_data`,
    /// `client_data_json`, and compact low-S `signature_compact`.
    ///
    /// Security: the `Debug` impl on `AssertionInput` redacts to length-only.
    /// This field MUST NOT be logged.
    assertion: AssertionInput,
}

impl PasskeySignHandle {
    /// Construct a `PasskeySignHandle`.
    ///
    /// # Parameters
    ///
    /// - `credential`: the credential metadata record (loaded from the
    ///   keyring-core credential store by the signing manager).
    /// - `assertion`: the WebAuthn assertion bytes produced by the
    ///   browser-handoff ceremony and stored in the approval spine
    ///   (`ApprovalKind::SignWithPasskey`).
    #[must_use]
    pub fn new(credential: PasskeyCredentialRecord, assertion: AssertionInput) -> Self {
        Self {
            credential,
            assertion,
        }
    }
}

impl std::fmt::Debug for PasskeySignHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not print credential bytes in debug output. Show only the
        // credential_id length and the rp_id.
        f.debug_struct("PasskeySignHandle")
            .field("credential.rp_id", &self.credential.rp_id)
            .field(
                "credential.credential_id_len",
                &self.credential.credential_id.len(),
            )
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Map an [`SaError`] from the pre-verifier or sig-normaliser into a
/// [`WalletError`].
///
/// Takes `SaError` by value so `map_err(map_sa_error)` works without a closure
/// wrapper. `wire_code()` and `to_string()` are `&self` methods, but the owned
/// form is required by the `map_err` adapter.
#[allow(
    clippy::needless_pass_by_value,
    reason = "map_err requires Fn(E) -> F; ownership is needed for the adapter, not the body"
)]
fn map_sa_error(err: SaError) -> WalletError {
    WalletError::SmartAccount {
        wire_code: err.wire_code(),
        message: err.to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WalletStateError variants used by PasskeySignHandle (conversion stubs)
// ─────────────────────────────────────────────────────────────────────────────

// `WalletStateError::PasskeyCredentialNotFound`,
// `WalletStateError::PlatformAuthenticatorUnavailable`, and
// `WalletStateError::PlatformAuthenticatorError` are defined in
// `stellar_agent_core::error::WalletStateError` and remain there because
// downstream consumers may reference them at the `WalletStateError` level.
// The signing pipeline does not construct these variants; they are reserved for
// callers that detect authenticator-side conditions independently. Removing
// public enum variants is a semver-breaking change that requires a separate
// decision.

// ─────────────────────────────────────────────────────────────────────────────
// Signer impl
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl Signer for PasskeySignHandle {
    /// Not implemented for passkey signers.
    ///
    /// Returns [`AuthError::SignerKindMismatch`] with
    /// `signer_kind = "passkey"`, `requested_primitive = "sign_tx_payload"`.
    /// Classic transaction signing requires an ed25519 key; passkey signers
    /// are secp256r1 and bound to the WebAuthn authentication path only.
    ///
    /// # Errors
    ///
    /// Always returns `Err(WalletError::Auth(AuthError::SignerKindMismatch))`.
    async fn sign_tx_payload(&self, _payload: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        Err(WalletError::Auth(AuthError::SignerKindMismatch {
            signer_kind: "passkey",
            requested_primitive: "sign_tx_payload",
        }))
    }

    /// Not implemented for passkey signers.
    ///
    /// Returns [`AuthError::SignerKindMismatch`] with
    /// `signer_kind = "passkey"`, `requested_primitive = "sign_auth_digest"`.
    /// The `sign_auth_digest` primitive produces a 64-byte ed25519 signature;
    /// passkey signers produce WebAuthn assertions through `sign_webauthn_assertion`.
    ///
    /// # Errors
    ///
    /// Always returns `Err(WalletError::Auth(AuthError::SignerKindMismatch))`.
    async fn sign_auth_digest(&self, _digest: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        Err(WalletError::Auth(AuthError::SignerKindMismatch {
            signer_kind: "passkey",
            requested_primitive: "sign_auth_digest",
        }))
    }

    /// Not implemented for passkey signers.
    ///
    /// Returns [`AuthError::SignerKindMismatch`] with
    /// `signer_kind = "passkey"`, `requested_primitive = "sign_soroban_address_auth_payload"`.
    /// This primitive produces an ed25519 signature for the Delegated G-key
    /// secondary auth entry path; passkey signers do not participate in that path.
    ///
    /// # Errors
    ///
    /// Always returns `Err(WalletError::Auth(AuthError::SignerKindMismatch))`.
    async fn sign_soroban_address_auth_payload(
        &self,
        _payload: &[u8; 32],
    ) -> Result<[u8; 64], WalletError> {
        Err(WalletError::Auth(AuthError::SignerKindMismatch {
            signer_kind: "passkey",
            requested_primitive: "sign_soroban_address_auth_payload",
        }))
    }

    /// Produce a WebAuthn assertion over the `auth_digest` using the bound
    /// assertion bytes.
    ///
    /// # Pipeline (implementation-correct order)
    ///
    /// 1. Validate that `credential_id` matches `self.credential.credential_id`
    ///    and `self.assertion.credential_id`. If either mismatches, return
    ///    [`AuthError::SignerKindMismatch`] with `requested_primitive =
    ///    "sign_webauthn_assertion:credential_id_mismatch"`.
    /// 2. Copy the already-normalised compact 64-byte r||s signature from
    ///    `self.assertion.signature_compact`.
    /// 3. Off-chain pre-verify via [`pre_verify_assertion`]. Catches malformed
    ///    assertions before chain-submission (negative-path gate).
    /// 4. Return `WebAuthnAssertion { signature_compact, authenticator_data,
    ///    client_data_json }`.
    ///
    /// # Bridge normalisation
    ///
    /// The bridge normalises browser DER to compact low-S form before storing
    /// `AssertionInput`, so this signer consumes the same compact 64-byte r||s
    /// form required by `pre_verify_assertion` and the Soroban signature data.
    ///
    /// # Single-call-site invariant
    ///
    /// This method MUST only be invoked via `complete_authorization_entry`
    /// in `crates/stellar-agent-smart-account/src/managers/auth_entry.rs`.
    /// Direct invocation from any other site is prohibited; a CI gate enforces
    /// this constraint.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Auth`] `AuthError::SignerKindMismatch` — `credential_id`
    ///   does not match the bound credential or assertion.
    /// - [`WalletError::SmartAccount`] `"sa.webauthn_assertion_invalid:*"` — off-chain
    ///   pre-verifier rejected the assertion.
    ///
    /// # Security
    ///
    /// No byte arrays from `auth_digest`, `credential_id`, the assertion bytes,
    /// or the compact signature are logged in this method.
    ///
    async fn sign_webauthn_assertion(
        &self,
        auth_digest: &[u8; 32],
        credential_id: &[u8],
    ) -> Result<WebAuthnAssertion, WalletError> {
        // Step 1: Validate credential_id matches the bound credential and assertion.
        //
        // Using constant-time comparison is not required here because
        // credential IDs are public identifiers (they are sent to the
        // authenticator in cleartext in the allow_credentials list). A
        // timing-based mismatch oracle on credential IDs provides no useful
        // advantage to an attacker. The comparison is a fast path sanity check.
        if credential_id != self.credential.credential_id.as_slice() {
            return Err(WalletError::Auth(AuthError::SignerKindMismatch {
                signer_kind: "passkey",
                requested_primitive: "sign_webauthn_assertion:credential_id_mismatch",
            }));
        }
        if credential_id != self.assertion.credential_id.as_slice() {
            return Err(WalletError::Auth(AuthError::SignerKindMismatch {
                signer_kind: "passkey",
                requested_primitive: "sign_webauthn_assertion:credential_id_mismatch",
            }));
        }

        // Step 2: Copy compact + low-S signature bytes recorded by the bridge.
        //
        // `AssertionInput::new` enforces the 64-byte shape.
        let compact_bytes: [u8; 64] = self
            .assertion
            .signature_compact
            .as_slice()
            .try_into()
            .map_err(|_| WalletError::SmartAccount {
                wire_code: "sa.webauthn_assertion_invalid",
                message: "webauthn assertion signature must be 64 bytes".to_owned(),
            })?;

        // Step 3: Off-chain pre-verification.
        //
        // Validates the assertion against the known public key and rp_id_hash
        // before chain-submission. Catches malformed assertions (wrong RP-ID
        // hash, UV bit unset, challenge mismatch, invalid signature) without
        // burning a testnet/mainnet round-trip.
        pre_verify_assertion(
            auth_digest,
            &self.credential.public_key_uncompressed,
            &self.assertion.authenticator_data,
            &self.assertion.client_data_json,
            &compact_bytes,
            &self.credential.rp_id_hash,
        )
        .map_err(map_sa_error)?;

        // Step 4: Return the WebAuthnAssertion.
        Ok(WebAuthnAssertion {
            signature_compact: compact_bytes,
            authenticator_data: self.assertion.authenticator_data.clone(),
            client_data_json: self.assertion.client_data_json.clone(),
        })
    }

    /// Not available for passkey signers.
    ///
    /// Passkey signers hold a secp256r1 public key, not an ed25519 public key.
    /// The secp256r1 public key is exposed through the
    /// `PasskeyCredentialRecord::public_key_uncompressed` field (accessible
    /// at credential-store lookup time), not through this trait method.
    ///
    /// Returns [`AuthError::SignerKindMismatch`] with
    /// `signer_kind = "passkey"`, `requested_primitive = "public_key"`.
    ///
    /// # Errors
    ///
    /// Always returns `Err(WalletError::Auth(AuthError::SignerKindMismatch))`.
    async fn public_key(&self) -> Result<PublicKey, WalletError> {
        Err(WalletError::Auth(AuthError::SignerKindMismatch {
            signer_kind: "passkey",
            requested_primitive: "public_key",
        }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::expect_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only")]

    use super::*;
    use stellar_agent_core::error::{AuthError, WalletError};
    use stellar_agent_network::signing::Signer;

    // ── Test fixtures ─────────────────────────────────────────────────────────

    const TEST_CREDENTIAL_ID: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
    const TEST_AUTH_DIGEST: [u8; 32] = [0x01u8; 32];
    const TEST_RP_ID: &str = "test.stellar.agent.wallet";

    /// Minimal 37-byte authenticatorData (rpIdHash[32] || flags[1] || signCount[4]).
    ///
    /// Byte 32 = 0x05 (UP=1, UV=1, BE=0, BS=0).
    /// Per W3C WebAuthn Level 2 §6.1.
    ///
    /// rpIdHash = sha256("test.stellar.agent.wallet") pre-computed.
    fn test_authenticator_data() -> Vec<u8> {
        let rp_id_hash: [u8; 32] = sha2::Sha256::digest(TEST_RP_ID.as_bytes()).into();
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(0x05); // UP=1, UV=1
        auth_data.extend_from_slice(&[0u8; 4]); // signCount = 0
        auth_data
    }

    /// A valid `clientDataJSON` for `sign_webauthn_assertion` with challenge =
    /// base64url(TEST_AUTH_DIGEST).
    ///
    /// The challenge field must be base64url-no-pad of the auth_digest bytes per
    /// `pre_verifier.rs` step 2.
    fn test_client_data_json() -> Vec<u8> {
        use base64::Engine as _;
        let challenge_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(TEST_AUTH_DIGEST);
        let json = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge_b64}","origin":"https://test.stellar.agent.wallet"}}"#
        );
        json.into_bytes()
    }

    /// Build a valid P-256 test signing key, credential record, and a matching
    /// real DER signature for `TEST_AUTH_DIGEST` signed over the webauthn
    /// message (`authenticator_data || sha256(client_data_json)`).
    ///
    /// Returns `(credential_record, signing_key, der_signature)`.
    fn test_signing_setup() -> (PasskeyCredentialRecord, p256::ecdsa::SigningKey, Vec<u8>) {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;
        use rand_core::OsRng;
        use sha2::Digest;

        let signing_key = SigningKey::random(&mut OsRng);
        let public_key_uncompressed: [u8; 65] = {
            let ep = signing_key.verifying_key().to_encoded_point(false);
            ep.as_bytes()
                .try_into()
                .expect("P-256 uncompressed point is 65 bytes")
        };

        let credential = PasskeyCredentialRecord::new(
            TEST_CREDENTIAL_ID.to_vec(),
            public_key_uncompressed,
            TEST_RP_ID,
        );

        // Compute the webauthn-message prehash: authenticator_data || sha256(client_data_json).
        let auth_data = test_authenticator_data();
        let client_data = test_client_data_json();
        let client_data_hash: [u8; 32] = Sha256::digest(&client_data).into();

        let mut message = Vec::with_capacity(auth_data.len() + 32);
        message.extend_from_slice(&auth_data);
        message.extend_from_slice(&client_data_hash);

        let msg_hash: [u8; 32] = Sha256::digest(&message).into();

        let sig: p256::ecdsa::Signature = signing_key
            .sign_prehash(&msg_hash)
            .expect("sign_prehash must succeed");
        let der_bytes = sig.to_der().as_bytes().to_vec();

        (credential, signing_key, der_bytes)
    }

    /// Build a synthetic `AssertionInput` fixture from the test signing setup.
    ///
    /// Constructs the assertion bytes directly from known-good test data, matching
    /// what the browser-handoff bridge (`stellar-agent-webauthn-bridge`) would
    /// produce for a successful WebAuthn ceremony. The assertion bytes are
    /// constructed directly without a platform-authenticator intermediary.
    fn test_assertion_input(der_signature: &[u8]) -> AssertionInput {
        let (normalised_sig, _was_high_s) =
            normalize_der_to_compact_low_s(der_signature).expect("test DER must normalise");
        AssertionInput::new(
            TEST_CREDENTIAL_ID.to_vec(),
            test_authenticator_data(),
            test_client_data_json(),
            normalised_sig.as_bytes().to_vec(),
        )
        .expect("test compact signature must be 64 bytes")
    }

    // ── Happy-path test ───────────────────────────────────────────────────────

    /// Verify that `PasskeySignHandle::sign_webauthn_assertion` returns a
    /// `WebAuthnAssertion` with a normalised compact signature on the happy path.
    ///
    /// Constructs `PasskeySignHandle::new(credential, assertion_input)` directly
    /// with a synthetic `AssertionInput` fixture (real P-256 signature generated by
    /// `test_signing_setup`) so the pre-verifier round-trip completes successfully.
    #[tokio::test]
    async fn passkey_sign_handle_returns_webauthn_assertion_on_happy_path() {
        let (credential, _signing_key, der_signature) = test_signing_setup();
        let assertion = test_assertion_input(&der_signature);
        let handle = PasskeySignHandle::new(credential, assertion);

        let result = handle
            .sign_webauthn_assertion(&TEST_AUTH_DIGEST, TEST_CREDENTIAL_ID)
            .await;

        let assertion = result.expect("happy-path must succeed");
        assert_eq!(
            assertion.signature_compact.len(),
            64,
            "compact signature must be 64 bytes"
        );
        assert_eq!(assertion.authenticator_data, test_authenticator_data());
        assert_eq!(assertion.client_data_json, test_client_data_json());
    }

    // ── credential_id mismatch (arg vs credential) ────────────────────────────

    /// Verify that `sign_webauthn_assertion` returns `SignerKindMismatch` when
    /// the provided `credential_id` arg does not match the bound credential record.
    #[tokio::test]
    async fn passkey_sign_handle_credential_id_mismatch_refuses() {
        let (credential, _signing_key, der_signature) = test_signing_setup();
        let assertion = test_assertion_input(&der_signature);
        let handle = PasskeySignHandle::new(credential, assertion);

        let wrong_id = &[0xFF, 0xFF, 0xFF, 0xFF];
        let err = handle
            .sign_webauthn_assertion(&TEST_AUTH_DIGEST, wrong_id)
            .await
            .expect_err("credential_id mismatch must return error");

        assert!(
            matches!(
                err,
                WalletError::Auth(AuthError::SignerKindMismatch {
                    signer_kind: "passkey",
                    requested_primitive: "sign_webauthn_assertion:credential_id_mismatch",
                })
            ),
            "expected SignerKindMismatch:credential_id_mismatch, got: {err:?}",
        );
    }

    // ── credential_id mismatch (arg vs assertion) ─────────────────────────────

    /// Verify that `sign_webauthn_assertion` returns `SignerKindMismatch` when
    /// the provided `credential_id` arg matches `self.credential.credential_id`
    /// but mismatches `self.assertion.credential_id`.
    ///
    /// Covers the second `credential_id` consistency check (between the bound
    /// `PasskeyCredentialRecord` and the captured `AssertionInput`). A mismatch
    /// here would indicate the browser-handoff bridge ferried an assertion for
    /// a different credential than the one bound to the handle, which the
    /// signer must refuse before invoking the pre-verifier.
    #[tokio::test]
    async fn passkey_sign_handle_assertion_credential_id_mismatch_refuses() {
        let (credential, _signing_key, der_signature) = test_signing_setup();

        // Construct an AssertionInput whose credential_id differs from the
        // bound credential record; the first check (arg vs credential) passes,
        // the second check (arg vs assertion) must fire.
        let mut mismatched_assertion = test_assertion_input(&der_signature);
        mismatched_assertion.credential_id = vec![0x11, 0x22, 0x33, 0x44];

        let handle = PasskeySignHandle::new(credential, mismatched_assertion);

        let err = handle
            .sign_webauthn_assertion(&TEST_AUTH_DIGEST, TEST_CREDENTIAL_ID)
            .await
            .expect_err("assertion credential_id mismatch must return error");

        assert!(
            matches!(
                err,
                WalletError::Auth(AuthError::SignerKindMismatch {
                    signer_kind: "passkey",
                    requested_primitive: "sign_webauthn_assertion:credential_id_mismatch",
                })
            ),
            "expected SignerKindMismatch:credential_id_mismatch, got: {err:?}",
        );
    }

    // ── pre_verify failure propagates ─────────────────────────────────────────

    /// Verify that a malformed `client_data_json` (wrong challenge bytes) causes
    /// the pre-verifier to reject the assertion, which propagates as a
    /// `SmartAccount` wallet error with wire code `sa.webauthn_assertion_invalid`.
    #[tokio::test]
    async fn passkey_sign_handle_pre_verify_failure_propagates() {
        let (credential, _signing_key, der_signature) = test_signing_setup();

        // Bad client_data_json: challenge is all zeros (not base64url(TEST_AUTH_DIGEST)).
        let bad_client_data = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"https://test.stellar.agent.wallet"}"#.to_vec();

        let assertion = AssertionInput::new(
            TEST_CREDENTIAL_ID.to_vec(),
            test_authenticator_data(),
            bad_client_data,
            normalize_der_to_compact_low_s(&der_signature)
                .expect("test DER must normalise")
                .0
                .as_bytes()
                .to_vec(),
        )
        .expect("test compact signature must be 64 bytes");
        let handle = PasskeySignHandle::new(credential, assertion);

        let err = handle
            .sign_webauthn_assertion(&TEST_AUTH_DIGEST, TEST_CREDENTIAL_ID)
            .await
            .expect_err("bad challenge must cause pre-verify failure");

        // The pre-verifier returns sa.webauthn_assertion_invalid:*
        assert!(
            matches!(err, WalletError::SmartAccount { wire_code, .. } if wire_code.starts_with("sa.webauthn_assertion_invalid")),
            "expected sa.webauthn_assertion_invalid:*, got: {err:?}",
        );
    }

    // ── ed25519-primitive refusals ────────────────────────────────────────────

    /// Verify that `sign_tx_payload` returns `SignerKindMismatch` for passkey signers.
    #[tokio::test]
    async fn passkey_sign_handle_refuses_sign_tx_payload() {
        let (credential, _signing_key, der_signature) = test_signing_setup();
        let assertion = test_assertion_input(&der_signature);
        let handle = PasskeySignHandle::new(credential, assertion);

        let err = handle
            .sign_tx_payload(&[0u8; 32])
            .await
            .expect_err("sign_tx_payload must refuse");

        assert!(
            matches!(
                err,
                WalletError::Auth(AuthError::SignerKindMismatch {
                    signer_kind: "passkey",
                    requested_primitive: "sign_tx_payload",
                })
            ),
            "expected SignerKindMismatch(passkey, sign_tx_payload), got: {err:?}",
        );
    }

    /// Verify that `sign_auth_digest` returns `SignerKindMismatch` for passkey signers.
    #[tokio::test]
    async fn passkey_sign_handle_refuses_sign_auth_digest() {
        let (credential, _signing_key, der_signature) = test_signing_setup();
        let assertion = test_assertion_input(&der_signature);
        let handle = PasskeySignHandle::new(credential, assertion);

        let err = handle
            .sign_auth_digest(&[0u8; 32])
            .await
            .expect_err("sign_auth_digest must refuse");

        assert!(
            matches!(
                err,
                WalletError::Auth(AuthError::SignerKindMismatch {
                    signer_kind: "passkey",
                    requested_primitive: "sign_auth_digest",
                })
            ),
            "expected SignerKindMismatch(passkey, sign_auth_digest), got: {err:?}",
        );
    }

    /// Verify that `sign_soroban_address_auth_payload` returns `SignerKindMismatch`.
    #[tokio::test]
    async fn passkey_sign_handle_refuses_sign_soroban_address_auth_payload() {
        let (credential, _signing_key, der_signature) = test_signing_setup();
        let assertion = test_assertion_input(&der_signature);
        let handle = PasskeySignHandle::new(credential, assertion);

        let err = handle
            .sign_soroban_address_auth_payload(&[0u8; 32])
            .await
            .expect_err("sign_soroban_address_auth_payload must refuse");

        assert!(
            matches!(
                err,
                WalletError::Auth(AuthError::SignerKindMismatch {
                    signer_kind: "passkey",
                    requested_primitive: "sign_soroban_address_auth_payload",
                })
            ),
            "expected SignerKindMismatch(passkey, sign_soroban_address_auth_payload), got: {err:?}",
        );
    }

    /// Verify that `public_key` returns `SignerKindMismatch` for passkey signers.
    #[tokio::test]
    async fn passkey_sign_handle_refuses_public_key() {
        let (credential, _signing_key, der_signature) = test_signing_setup();
        let assertion = test_assertion_input(&der_signature);
        let handle = PasskeySignHandle::new(credential, assertion);

        let err = handle
            .public_key()
            .await
            .expect_err("public_key must refuse");

        assert!(
            matches!(
                err,
                WalletError::Auth(AuthError::SignerKindMismatch {
                    signer_kind: "passkey",
                    requested_primitive: "public_key",
                })
            ),
            "expected SignerKindMismatch(passkey, public_key), got: {err:?}",
        );
    }

    // ── AssertionInput Debug redaction ────────────────────────────────────────

    /// Verify that `AssertionInput`'s `Debug` impl only emits length fields,
    /// not raw bytes (no credential/signature bytes in tracing output).
    #[test]
    fn assertion_input_debug_is_redacted() {
        let assertion = AssertionInput::new(
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            vec![0x01; 37],
            b"{}".to_vec(),
            vec![0x02; 64],
        )
        .expect("64-byte compact signature must be accepted");
        let debug_str = format!("{assertion:?}");

        // Must not contain the raw credential_id bytes as a Rust Debug slice/array
        // literal. The bytes [0xDE, 0xAD, 0xBE, 0xEF] would appear as "de, ad, be, ef"
        // or similar if the Vec<u8> were printed directly by the default Debug impl.
        // We check for the decimal form (222 = 0xDE) that `{:?}` uses for u8 slices;
        // none of our length-4 field values can be 222.
        assert!(
            !debug_str.contains("222"),
            "credential_id byte 0xDE (222) must not appear in Debug output; got: {debug_str}"
        );
        assert!(
            !debug_str.contains("173"),
            "credential_id byte 0xAD (173) must not appear in Debug output; got: {debug_str}"
        );
        // Must contain the length fields.
        assert!(
            debug_str.contains("credential_id_len"),
            "Debug must contain credential_id_len"
        );
        assert!(
            debug_str.contains("signature_compact_len"),
            "Debug must contain signature_compact_len"
        );
    }
}
