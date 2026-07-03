//! [`AssertionInput`] — the byte bundle produced by a WebAuthn ceremony.
//!
//! Defined in `stellar-agent-core` so that
//! `stellar-agent-core::approval::store::PendingApproval` can hold an
//! `Option<AssertionInput>` without creating a circular crate dependency.
//! `stellar-agent-smart-account::webauthn::passkey_signer` re-exports this
//! type via `use stellar_agent_core::approval::AssertionInput;`.
//!
//! # Security
//!
//! The `Debug` impl redacts every byte field to its length.  A stray
//! `tracing::debug!(?assertion_input)` therefore emits only integer lengths,
//! not raw credential or signature bytes.

use serde::{Deserialize, Serialize};

use crate::approval::ApprovalError;

const P256_HALF_ORDER_BE: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// Bytes produced by a successful WebAuthn ceremony, consumed by
/// `PasskeySignHandle::sign_webauthn_assertion`.
///
/// The bridge crate populates this from a browser-driven ceremony and writes
/// it into the approval store as part of `ApprovalKind::SignWithPasskey`.
/// The signing manager reads it back and threads it through
/// `Signer::sign_webauthn_assertion`.
///
/// # Fields
///
/// - `credential_id`: the credential identifier returned by the platform
///   authenticator, confirming which stored credential was used.
/// - `authenticator_data`: raw authenticator data per W3C WebAuthn Level 2
///   §6.1 (minimum 37 bytes). Bytes 0..32 are the RP-ID hash.
/// - `client_data_json`: raw `clientDataJSON` per W3C WebAuthn Level 2
///   §5.8.1.1. Must contain `"type":"webauthn.get"` and
///   `"challenge":<base64url(auth_digest)>`.
/// - `signature_compact`: compact 64-byte big-endian r || s, low-S
///   normalised. The `pre_verify_assertion` substrate consumes this form;
///   callers MUST normalise DER inputs first via
///   `signature_normalize::normalize_der_to_compact_low_s`.
///
/// # Security
///
/// `signature_compact`, `client_data_json`, and `credential_id` MUST NOT be
/// interpolated into any `tracing::*!` macro. The `Debug` impl below
/// redacts to length-only. Any caller that logs an `AssertionInput` value
/// will see only field-length integers in the output.
///
/// # Serialisation
///
/// `Serialize` / `Deserialize` are derived so the approval store can persist
/// a `SignWithPasskey` entry with `passkey_assertion: Some(AssertionInput)` to
/// TOML. Byte fields use serde's default `Vec<u8>` TOML representation
/// (array of integers).
///
/// # Future fields
///
/// `#[non_exhaustive]` permits adding future WebAuthn assertion fields
/// (`user_handle`, `extension_results`, `transports`) without breaking
/// downstream struct-literal construction sites.
///
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AssertionInput {
    /// The credential identifier returned by the authenticator. Typically
    /// 16–64 bytes. Validated against `PasskeyCredentialRecord::credential_id`
    /// at signing time.
    pub credential_id: Vec<u8>,
    /// Raw authenticator data per W3C WebAuthn Level 2 §6.1 (minimum 37 bytes).
    ///
    /// Security: MUST NOT be interpolated into tracing events.
    pub authenticator_data: Vec<u8>,
    /// Raw `clientDataJSON` per W3C WebAuthn Level 2 §5.8.1.1.
    ///
    /// Security: MUST NOT be interpolated into tracing events.
    pub client_data_json: Vec<u8>,
    /// Compact 64-byte big-endian r || s ECDSA-secp256r1 signature, low-S
    /// normalised.
    ///
    /// The `pre_verify_assertion` substrate consumes this form; callers MUST
    /// normalise DER inputs first via
    /// `signature_normalize::normalize_der_to_compact_low_s`.
    ///
    /// Security: MUST NOT be interpolated into tracing events.
    pub signature_compact: Vec<u8>,
}

impl AssertionInput {
    /// Constructs an `AssertionInput` from the four raw WebAuthn ceremony byte
    /// fields produced by the browser-handoff bridge.
    ///
    /// `#[non_exhaustive]` blocks external struct-literal construction; this
    /// constructor is the canonical entry point for external crates
    /// (stellar-agent-smart-account, stellar-agent-webauthn-bridge).
    /// # Errors
    ///
    /// Returns [`ApprovalError::Invalid`] when `signature_compact` is not
    /// exactly 64 bytes or is not low-S normalised.
    pub fn new(
        credential_id: Vec<u8>,
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
        signature_compact: Vec<u8>,
    ) -> Result<Self, ApprovalError> {
        validate_signature_compact(&signature_compact)?;

        Ok(Self {
            credential_id,
            authenticator_data,
            client_data_json,
            signature_compact,
        })
    }
}

pub(crate) fn validate_signature_compact(signature_compact: &[u8]) -> Result<(), ApprovalError> {
    if signature_compact.len() != 64 {
        return Err(ApprovalError::Invalid {
            reason: format!(
                "AssertionInput.signature_compact MUST be 64 bytes (r||s big-endian); got {}",
                signature_compact.len()
            ),
        });
    }

    if signature_compact[32..] > P256_HALF_ORDER_BE[..] {
        return Err(ApprovalError::Invalid {
            reason: "AssertionInput.signature_compact MUST be low-S normalised".to_owned(),
        });
    }

    Ok(())
}

impl std::fmt::Debug for AssertionInput {
    /// Redacted `Debug` impl: shows byte-length fields only.
    ///
    /// A stray `tracing::debug!(?assertion_input)` would otherwise emit the
    /// full byte arrays (no credential / signature bytes in tracing events).
    /// Field lengths are sufficient for operator diagnostics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssertionInput")
            .field("credential_id_len", &self.credential_id.len())
            .field("authenticator_data_len", &self.authenticator_data.len())
            .field("client_data_json_len", &self.client_data_json.len())
            .field("signature_compact_len", &self.signature_compact.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    #[test]
    fn debug_redacts_all_byte_fields() {
        let input = AssertionInput {
            credential_id: vec![0xAA; 20],
            authenticator_data: vec![0xBB; 37],
            client_data_json: vec![0xCC; 100],
            signature_compact: vec![0xDD; 64],
        };
        let debug_str = format!("{input:?}");
        // Lengths must appear.
        assert!(
            debug_str.contains("credential_id_len: 20"),
            "credential_id_len missing"
        );
        assert!(
            debug_str.contains("authenticator_data_len: 37"),
            "authenticator_data_len missing"
        );
        assert!(
            debug_str.contains("client_data_json_len: 100"),
            "client_data_json_len missing"
        );
        assert!(
            debug_str.contains("signature_compact_len: 64"),
            "signature_compact_len missing"
        );
        // Raw bytes must NOT appear (AA, BB, CC, DD sequences).
        assert!(
            !debug_str.contains("170"),
            "raw byte 0xAA (170) must not appear in Debug"
        );
        assert!(
            !debug_str.contains("credential_id: ["),
            "raw credential_id bytes must not appear in Debug"
        );
    }

    #[test]
    fn serde_roundtrip() {
        let input = AssertionInput {
            credential_id: vec![1, 2, 3],
            authenticator_data: vec![4, 5, 6],
            client_data_json: vec![7, 8, 9],
            signature_compact: vec![10; 64],
        };
        let serialised = toml::to_string(&input).expect("serialise");
        let deserialised: AssertionInput = toml::from_str(&serialised).expect("deserialise");
        assert_eq!(input.credential_id, deserialised.credential_id);
        assert_eq!(input.authenticator_data, deserialised.authenticator_data);
        assert_eq!(input.client_data_json, deserialised.client_data_json);
        assert_eq!(input.signature_compact, deserialised.signature_compact);
    }

    #[test]
    fn new_accepts_64_byte_signature_compact() {
        let input = AssertionInput::new(vec![1], vec![2], vec![3], vec![4; 64])
            .expect("64-byte compact signature must be accepted");

        assert_eq!(input.signature_compact.len(), 64);
    }

    #[test]
    fn new_rejects_63_byte_signature_compact() {
        let err = AssertionInput::new(vec![1], vec![2], vec![3], vec![4; 63])
            .expect_err("63-byte compact signature must be rejected");

        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }

    #[test]
    fn new_rejects_65_byte_signature_compact() {
        let err = AssertionInput::new(vec![1], vec![2], vec![3], vec![4; 65])
            .expect_err("65-byte compact signature must be rejected");

        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }

    #[test]
    fn new_rejects_high_s_signature_compact() {
        let err = AssertionInput::new(vec![1], vec![2], vec![3], vec![0xff; 64])
            .expect_err("high-S compact signature must be rejected");

        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }
}
