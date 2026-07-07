//! Typed error enum for SEP-53 message sign/verify operations.
//!
//! All error variants are fail-closed: they represent failures that MUST cause
//! the SEP-53 operation to return an error to the caller. None of the variants
//! echo secret material.
//!
//! `Sep53Error` is `#[non_exhaustive]`: external crates matching on it must
//! include a wildcard arm. No `test_helpers` module is needed here because every
//! variant is constructible via struct syntax outside the crate.

/// Errors produced by SEP-53 message sign/verify operations.
///
/// The enum is `#[non_exhaustive]`; downstream crates must match with a
/// wildcard arm. Display messages MUST NOT expose raw signature bytes, private
/// key material, or other secret information.
///
/// # Display discipline
///
/// - `VerificationFailed` does NOT include the invalid signature bytes or the
///   message content to avoid amplifying potential secret material.
/// - `SigningFailed { reason }` MUST NOT be populated with raw key bytes or
///   signature bytes by callers.
/// - `MessageTooLarge` includes only the length values, which are not secret.
/// - `InvalidPublicKey` includes only a parse-error description, not the raw
///   bytes.
///
/// # Examples
///
/// ```
/// use stellar_agent_sep53::Sep53Error;
///
/// let err = Sep53Error::VerificationFailed;
/// assert!(err.to_string().contains("verification failed"));
///
/// let err = Sep53Error::MessageTooLarge { len: 70000, max: 65536 };
/// assert!(err.to_string().contains("70000"));
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Sep53Error {
    /// The supplied public key bytes are not a valid ed25519 public key.
    ///
    /// Returned when `VerifyingKey::from_bytes` fails during point
    /// decompression in [`super::verify_message`].
    ///
    /// # Errors
    ///
    /// Returned from [`super::verify_message`].
    ///
    /// # Redaction invariant
    ///
    /// `detail` MUST NOT contain raw key bytes or secret material. It is
    /// surfaced verbatim at Display sites.
    #[error("invalid public key: {detail}")]
    InvalidPublicKey {
        /// Non-secret description of the key parse failure.
        ///
        /// Redaction invariant: this field MUST NOT contain raw key/seed/signature
        /// bytes; it is surfaced verbatim at Display sites.
        detail: String,
    },

    /// The signature bytes do not represent a structurally valid ed25519
    /// signature (e.g. non-canonical or malformed encoding).
    ///
    /// Distinct from [`Sep53Error::VerificationFailed`]: this variant indicates
    /// that the 64 bytes cannot be parsed as a signature structure at all.
    /// In practice, ed25519-dalek 2.x `Signature::from_bytes` is infallible
    /// (it always produces a `Signature` from 64 bytes), so this variant is
    /// reserved for future stricter validation or library changes.
    ///
    /// # Errors
    ///
    /// Reserved for structural signature parse failure.
    ///
    /// # Redaction invariant
    ///
    /// `detail` MUST NOT contain raw signature bytes or other secret material.
    /// It is surfaced verbatim at Display sites.
    #[error("invalid signature encoding: {detail}")]
    InvalidSignature {
        /// Non-secret description of the signature encoding failure.
        detail: String,
    },

    /// The signature did not verify against the given message and public key.
    ///
    /// The signature is structurally valid but does not authenticate the
    /// message under the supplied public key. This is the canonical failure
    /// mode for tampered messages, wrong keys, or non-SEP-53 signatures.
    ///
    /// # Errors
    ///
    /// Returned from [`super::verify_message`].
    ///
    /// # Redaction invariant
    ///
    /// Display does NOT include the signature bytes or message content. The
    /// caller can log the message separately if needed; the error carries no
    /// potentially-secret payload.
    #[error("SEP-53 signature verification failed")]
    VerificationFailed,

    /// The signing operation failed.
    ///
    /// Returned when [`super::sign_message`] calls `Signer::sign_tx_payload`
    /// and the signer returns an error (hardware timeout, keyring unavailable,
    /// etc.).
    ///
    /// # Errors
    ///
    /// Returned from [`super::sign_message`].
    ///
    /// # Redaction invariant
    ///
    /// `reason` MUST NOT contain raw signature bytes, private key bytes, or
    /// seed phrases. It is surfaced verbatim at Display sites and MUST be a
    /// non-secret description of the signer error.
    #[error("signing failed: {reason}")]
    SigningFailed {
        /// Non-secret description of the signing failure.
        ///
        /// Redaction invariant: this field MUST NOT contain raw key/seed/signature
        /// bytes; it is surfaced verbatim at Display sites.
        reason: String,
    },

    /// The message exceeds the maximum allowed length.
    ///
    /// Returned when `message.len()` exceeds [`super::MAX_MESSAGE_BYTES`] in
    /// either [`super::sign_message`] or [`super::verify_message`].
    ///
    /// # Errors
    ///
    /// Returned from [`super::sign_message`] and [`super::verify_message`].
    #[error("message too large: got {len} bytes, maximum is {max} bytes")]
    MessageTooLarge {
        /// Actual message length in bytes.
        len: usize,
        /// Maximum allowed message length in bytes ([`super::MAX_MESSAGE_BYTES`]).
        max: usize,
    },

    /// A message-signing request targeted a mainnet profile.
    ///
    /// The SEP-53 message-signing MCP tool returns a signature the caller can use
    /// externally; on a mainnet profile it is refused structurally before any key
    /// access, so no signature is produced. This is a client-invalid request: the
    /// operation is not serviceable on the active network.
    ///
    /// # Errors
    ///
    /// Constructed by the MCP consumer layer at tool entry; not returned by the
    /// crate's own sign/verify functions.
    ///
    /// # Redaction invariant
    ///
    /// `detail` MUST NOT contain raw key/seed/signature bytes; it is surfaced
    /// verbatim at Display sites. It carries the canonical
    /// `network.mainnet_write_forbidden` wire code so this refusal correlates with
    /// the CLI, submit-layer, SEP-43, and x402 signing guards.
    #[error("mainnet signing forbidden: {detail}")]
    MainnetSigningForbidden {
        /// Non-secret description of the refusal, carrying the canonical
        /// `network.mainnet_write_forbidden` wire code.
        detail: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn verification_failed_display_does_not_contain_secret_bytes() {
        let err = Sep53Error::VerificationFailed;
        let s = err.to_string();
        // The display should say "verification failed" but not echo any bytes.
        assert!(
            s.contains("verification failed"),
            "VerificationFailed display must contain 'verification failed': {s}"
        );
        // Ensure no raw hex bytes in the message (no 0x prefix, no 64-char hex run).
        assert!(
            !s.contains("0x"),
            "VerificationFailed display must not contain hex prefixes: {s}"
        );
    }

    #[test]
    fn message_too_large_display_contains_lengths() {
        let err = Sep53Error::MessageTooLarge {
            len: 70000,
            max: 65536,
        };
        let s = err.to_string();
        assert!(s.contains("70000"), "display must contain len: {s}");
        assert!(s.contains("65536"), "display must contain max: {s}");
    }

    #[test]
    fn signing_failed_display_contains_reason() {
        let err = Sep53Error::SigningFailed {
            reason: "keyring unavailable".to_owned(),
        };
        let s = err.to_string();
        assert!(
            s.contains("keyring unavailable"),
            "display must contain reason: {s}"
        );
    }

    #[test]
    fn invalid_public_key_display_contains_detail() {
        let err = Sep53Error::InvalidPublicKey {
            detail: "point decompression failed".to_owned(),
        };
        let s = err.to_string();
        assert!(
            s.contains("point decompression failed"),
            "display must contain detail: {s}"
        );
    }

    #[test]
    fn mainnet_signing_forbidden_display_carries_canonical_wire_code() {
        let err = Sep53Error::MainnetSigningForbidden {
            detail: "signing is structurally refused on mainnet (network.mainnet_write_forbidden)"
                .to_owned(),
        };
        let s = err.to_string();
        assert!(
            s.contains("mainnet signing forbidden"),
            "display must name the refusal: {s}"
        );
        assert!(
            s.contains("network.mainnet_write_forbidden"),
            "display must carry the canonical wire code: {s}"
        );
    }
}
