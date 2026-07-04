//! Software WebAuthn authenticator for tests — produces valid and
//! adversarial assertions without a real platform authenticator.
//!
//! Precedented cross-crate p256 signing pattern: mirrors the fixture in
//! `stellar-agent-webauthn-bridge/tests/integration_callbacks.rs`
//! (`valid_assertion_fixture`), generalised here into a reusable, parametric
//! builder so adversarial variants (wrong challenge, wrong RP-ID, UV-absent,
//! arbitrary sign counter) share one signing implementation instead of
//! hand-rolled byte arrays per test.
//!
//! Compiled only under `#[cfg(any(test, feature = "test-helpers"))]` — never
//! present in a production binary.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::SecretKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use sha2::{Digest as _, Sha256};

use crate::wire::{AssertionResponseWire, AssertionWire};

/// WebAuthn `authenticatorData` flag bits (W3C WebAuthn Level 2 §6.1).
pub const FLAG_UP: u8 = 0x01;
/// User-verified bit.
pub const FLAG_UV: u8 = 0x04;
/// Backup-eligible bit.
pub const FLAG_BE: u8 = 0x08;
/// Backup-state bit.
pub const FLAG_BS: u8 = 0x10;

/// A software authenticator backed by a fixed, deterministic P-256 keypair.
///
/// Deterministic (not randomly generated) so `pubkey_uncompressed()` is
/// stable across test runs — tests enroll this exact public key into the
/// operator-credential store fixture.
pub struct SoftwareAuthenticator {
    signing_key: SigningKey,
    pubkey_uncompressed: [u8; 65],
    credential_id_b64url: String,
}

impl SoftwareAuthenticator {
    /// Constructs a software authenticator with a fixed keypair derived from
    /// `seed` (32 bytes) and the given credential id.
    ///
    /// # Panics
    ///
    /// Never panics in practice: `SecretKey::from_slice` only fails for a
    /// seed that is not a valid P-256 scalar (zero or >= the curve order),
    /// which no fixed test seed used in this crate's test suite is.
    #[must_use]
    pub fn new(seed: [u8; 32], credential_id_b64url: impl Into<String>) -> Self {
        #[allow(
            clippy::expect_used,
            reason = "test-only; a well-formed 32-byte seed always yields a valid P-256 secret key"
        )]
        let secret_key = SecretKey::from_slice(&seed).expect("valid P-256 seed");
        let signing_key = SigningKey::from(&secret_key);
        let pubkey_point = secret_key.public_key().to_encoded_point(false);
        let mut pubkey_uncompressed = [0u8; 65];
        pubkey_uncompressed.copy_from_slice(pubkey_point.as_bytes());
        Self {
            signing_key,
            pubkey_uncompressed,
            credential_id_b64url: credential_id_b64url.into(),
        }
    }

    /// The 65-byte uncompressed SEC1 public key for this authenticator.
    #[must_use]
    pub fn pubkey_uncompressed(&self) -> [u8; 65] {
        self.pubkey_uncompressed
    }

    /// The base64url public-key form used by `OperatorApprovalCredential`.
    #[must_use]
    pub fn pubkey_uncompressed_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.pubkey_uncompressed)
    }

    /// The credential id this authenticator presents.
    #[must_use]
    pub fn credential_id_b64url(&self) -> &str {
        &self.credential_id_b64url
    }

    /// Produces a WebAuthn assertion over `challenge`, with full control
    /// over every field that can be adversarially mutated.
    ///
    /// `flags` is the raw `authenticatorData` flags byte — pass
    /// `FLAG_UP | FLAG_UV` for a normal assertion, or omit `FLAG_UV` to
    /// produce a UV-absent adversarial assertion.
    ///
    /// # Panics
    ///
    /// Never panics in practice: signing a fixed-size digest with the
    /// authenticator's own valid key cannot fail.
    #[must_use]
    #[allow(clippy::too_many_arguments, reason = "adversarial-fixture builder")]
    pub fn sign_assertion(
        &self,
        challenge: &[u8; 32],
        rp_id: &str,
        origin: &str,
        flags: u8,
        sign_count: u32,
    ) -> AssertionWire {
        let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
        )
        .into_bytes();

        let mut authenticator_data = vec![0u8; 37];
        authenticator_data[..32].copy_from_slice(&Sha256::digest(rp_id.as_bytes()));
        authenticator_data[32] = flags;
        authenticator_data[33..37].copy_from_slice(&sign_count.to_be_bytes());

        let client_hash = Sha256::digest(&client_data_json);
        let mut sig_payload = Vec::with_capacity(authenticator_data.len() + 32);
        sig_payload.extend_from_slice(&authenticator_data);
        sig_payload.extend_from_slice(&client_hash);
        let digest = Sha256::digest(&sig_payload);

        #[allow(
            clippy::expect_used,
            reason = "test-only; signing a fixed-size digest with a valid key never fails"
        )]
        let signature: Signature = self
            .signing_key
            .sign_prehash(&digest)
            .expect("prehash signing never fails for a valid key");
        let signature = signature.normalize_s().unwrap_or(signature);
        let signature_der = signature.to_der().as_bytes().to_vec();

        AssertionWire {
            id: self.credential_id_b64url.clone(),
            response: AssertionResponseWire {
                authenticator_data: URL_SAFE_NO_PAD.encode(&authenticator_data),
                client_data_json: URL_SAFE_NO_PAD.encode(&client_data_json),
                signature: URL_SAFE_NO_PAD.encode(&signature_der),
            },
        }
    }

    /// A normal, valid assertion: UP + UV set, the given sign counter.
    #[must_use]
    pub fn sign_valid(
        &self,
        challenge: &[u8; 32],
        rp_id: &str,
        origin: &str,
        sign_count: u32,
    ) -> AssertionWire {
        self.sign_assertion(challenge, rp_id, origin, FLAG_UP | FLAG_UV, sign_count)
    }
}
