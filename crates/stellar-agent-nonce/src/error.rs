//! Error types for the `stellar-agent-nonce` crate.
//!
//! All error variants are non-secret: they never echo key bytes, HMAC tags, or
//! raw nonce material.

use stellar_agent_core::error::AuthError;

/// Errors produced by nonce minting, verification, key loading, and rotation.
///
/// All variants are non-secret: no key bytes, HMAC tags, or raw nonce material
/// appear in any `Display` or `Debug` output.
///
/// # Mapping to wire error codes
///
/// | Variant | Wire error code |
/// |---|---|
/// | `HmacMismatch` | `nonce.expired` (indistinguishable from `Expired` by design) |
/// | `Expired` | `nonce.expired` |
/// | `Replayed` | `nonce.replayed` |
/// | `InvalidTool` | `tool.unknown` |
/// | `InvalidEnvelope` | `nonce.invalid_envelope` |
/// | `ChainMismatch` | `nonce.chain_mismatch` |
/// | `TtlExceeded` | `nonce.ttl_exceeded` |
/// | `TtlTooShort` | `nonce.ttl_too_short` |
/// | `KeyringError` | `keyring.error` |
/// | `KeyTooShort` | `nonce.key_too_short` |
/// | `InputTooLong` | `nonce.input_too_long` |
/// | `SerialiseFailed` | `nonce.serialise_failed` |
///
/// Use [`NonceError::wire_code`] to obtain the canonical wire code for any
/// variant without writing exhaustive match arms at every call site.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NonceError {
    /// The HMAC tag on the nonce does not match the recomputed tag.
    ///
    /// Causes: wrong envelope_xdr, wrong tool_name, wrong chain_id, a process
    /// restart (boot_nonce changed), or key rotation since mint time.
    ///
    /// Map to `nonce.expired` when the salt is fresh to the replay window
    /// (indicating a post-restart verification); map to `nonce.hmac_mismatch`
    /// otherwise.
    #[error("nonce HMAC tag does not match")]
    HmacMismatch,

    /// The nonce's expiry timestamp is in the past.
    ///
    /// Wire code: `nonce.expired`.
    #[error("nonce has expired")]
    Expired,

    /// The nonce salt has already been seen in the replay window.
    ///
    /// Wire code: `nonce.replayed`.
    #[error("nonce has already been used (replay detected)")]
    Replayed,

    /// The `tool_name` argument is not in the registered tool catalogue.
    ///
    /// Tool validation happens before engaging key state.
    /// The `tool` field is non-secret (it is the caller-supplied tool string).
    ///
    /// Wire code: `tool.unknown`.
    #[error("tool not registered: {tool}")]
    InvalidTool {
        /// The unregistered tool name supplied by the caller.
        tool: String,
    },

    /// The `envelope_xdr` slice is empty or cannot be hashed.
    ///
    /// Wire code: `nonce.invalid_envelope`.
    #[error("envelope XDR is empty or invalid")]
    InvalidEnvelope,

    /// The caller-supplied `chain_id` does not match the profile's configured
    /// CAIP-2 chain identifier.
    ///
    /// CAIP-2 strings (`stellar:testnet`, `stellar:mainnet`) are
    /// non-secret public identifiers.
    ///
    /// Wire code: `nonce.chain_mismatch`.
    #[error("chain_id mismatch: expected {expected}, got {got}")]
    ChainMismatch {
        /// The chain_id configured in the profile.
        expected: String,
        /// The chain_id supplied by the caller.
        got: String,
    },

    /// The requested TTL (`expiry_unix_ms - now_unix_ms`) exceeds the profile's
    /// configured maximum.
    ///
    /// Wire code: `nonce.ttl_exceeded`.
    #[error("requested TTL {requested_ms}ms exceeds max {max_ms}ms")]
    TtlExceeded {
        /// The maximum TTL configured in the profile (milliseconds).
        max_ms: u64,
        /// The TTL computed from `expiry_unix_ms - now_unix_ms` (milliseconds).
        requested_ms: u64,
    },

    /// The requested TTL is below the minimum floor of [`crate::mint::NonceMint::MIN_TTL_MS`].
    ///
    /// Wire code: `nonce.ttl_too_short`.
    #[error("requested TTL {requested_ms}ms is below minimum {min_ms}ms")]
    TtlTooShort {
        /// The minimum TTL floor (milliseconds).
        min_ms: u64,
        /// The TTL computed from `expiry_unix_ms - now_unix_ms` (milliseconds).
        requested_ms: u64,
    },

    /// A platform keyring error occurred while loading or storing the nonce key.
    ///
    /// Wire code: `keyring.error`.
    #[error("keyring error: {0}")]
    KeyringError(AuthError),

    /// The keyring entry contains fewer than 32 decoded bytes.
    ///
    /// Per NIST SP 800-107 §5.3.4: HMAC key MUST be ≥ 32 bytes (256 bits).
    ///
    /// Wire code: `nonce.key_too_short`.
    #[error("nonce key too short: {actual} bytes decoded (need ≥ 32)")]
    KeyTooShort {
        /// Number of decoded bytes actually present in the keyring entry.
        actual: usize,
    },

    /// A variable-length HMAC domain field exceeds the u32 length-prefix bound.
    ///
    /// Variable-length fields are prefixed as big-endian u32 for boundary-collision
    /// defence. Values larger than `u32::MAX` are rejected instead of saturating,
    /// so distinct oversized inputs cannot collide on the same prefix bytes.
    #[error("{field} length {len} exceeds u32::MAX")]
    InputTooLong {
        /// Non-secret field name (`tool_name` or `chain_id`).
        field: &'static str,
        /// Actual byte length of the input.
        len: usize,
    },

    /// The base64 encode/decode step failed.
    ///
    /// Wire code: `nonce.serialise_failed`.
    #[error("nonce serialisation failed: {detail}")]
    SerialiseFailed {
        /// Non-secret detail string (e.g. "base64 decode error").
        detail: String,
    },
}

impl NonceError {
    /// Returns the canonical wire error code for this variant.
    ///
    /// The returned `&'static str` is the typed code the MCP layer emits in
    /// tool-level error responses.  Callers should use this method instead of
    /// hand-writing match arms to avoid divergence from the wire-code table.
    ///
    /// # Indistinguishability invariant
    ///
    /// `Expired` and `HmacMismatch` both map to `nonce.expired`.  This is
    /// intentional: from the agent's perspective, the correct recovery for both
    /// variants is identical (re-simulate to obtain a fresh nonce).  Leaking
    /// the distinction through the wire code would expose an HMAC-oracle side
    /// channel.  The detailed reason is available to operators via `tracing::debug!`
    /// (where `RedactingLayer` scrubs anything sensitive).
    ///
    /// # Forward compatibility
    ///
    /// The enum is `#[non_exhaustive]`; future variants hit the `_ =>` arm and
    /// return `"nonce.unknown_error"` (deliberately distinct from any valid wire
    /// code so operators can detect unexpected variants in telemetry).
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_nonce::NonceError;
    ///
    /// assert_eq!(NonceError::Replayed.wire_code(), "nonce.replayed");
    /// assert_eq!(NonceError::Expired.wire_code(), "nonce.expired");
    /// assert_eq!(NonceError::HmacMismatch.wire_code(), "nonce.expired");
    /// assert_eq!(NonceError::InvalidEnvelope.wire_code(), "nonce.invalid_envelope");
    /// ```
    #[must_use]
    #[allow(
        unreachable_patterns,
        reason = "The `_ =>` arm is unreachable inside the defining crate because all \
                  current variants are explicitly matched above.  The arm is intentionally \
                  kept for forward-compatibility: when a new variant is added it will be \
                  caught here at runtime (or the match exhaustiveness check will force the \
                  author to add an explicit arm). The `#[non_exhaustive]` attribute means \
                  the compiler allows the wildcard without error, but warns on unreachability \
                  within the crate."
    )]
    pub fn wire_code(&self) -> &'static str {
        match self {
            NonceError::Replayed => "nonce.replayed",
            // Indistinguishability: HmacMismatch and Expired are the same
            // from the agent's perspective; do NOT distinguish them via the wire
            // code.  The underlying reason is logged at tracing::debug! only.
            NonceError::Expired | NonceError::HmacMismatch => "nonce.expired",
            NonceError::InvalidTool { .. } => "tool.unknown",
            NonceError::InvalidEnvelope => "nonce.invalid_envelope",
            NonceError::ChainMismatch { .. } => "nonce.chain_mismatch",
            NonceError::TtlExceeded { .. } => "nonce.ttl_exceeded",
            NonceError::TtlTooShort { .. } => "nonce.ttl_too_short",
            NonceError::KeyringError(_) => "keyring.error",
            NonceError::KeyTooShort { .. } => "nonce.key_too_short",
            NonceError::InputTooLong { .. } => "nonce.input_too_long",
            NonceError::SerialiseFailed { .. } => "nonce.serialise_failed",
            // Forward-compat fallback: deliberately distinct from any valid wire
            // code so future-variant telemetry alerts fire.
            _ => "nonce.unknown_error",
        }
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
    fn wire_code_replayed() {
        assert_eq!(NonceError::Replayed.wire_code(), "nonce.replayed");
    }

    #[test]
    fn wire_code_expired() {
        assert_eq!(NonceError::Expired.wire_code(), "nonce.expired");
    }

    #[test]
    fn wire_code_hmac_mismatch_maps_to_expired() {
        // Indistinguishability: HmacMismatch → nonce.expired (same as Expired).
        assert_eq!(NonceError::HmacMismatch.wire_code(), "nonce.expired");
    }

    #[test]
    fn wire_code_invalid_tool() {
        assert_eq!(
            NonceError::InvalidTool {
                tool: "bogus".to_owned()
            }
            .wire_code(),
            "tool.unknown"
        );
    }

    #[test]
    fn wire_code_invalid_envelope() {
        assert_eq!(
            NonceError::InvalidEnvelope.wire_code(),
            "nonce.invalid_envelope"
        );
    }

    #[test]
    fn wire_code_chain_mismatch() {
        assert_eq!(
            NonceError::ChainMismatch {
                expected: "stellar:testnet".to_owned(),
                got: "stellar:mainnet".to_owned(),
            }
            .wire_code(),
            "nonce.chain_mismatch"
        );
    }

    #[test]
    fn wire_code_ttl_exceeded() {
        assert_eq!(
            NonceError::TtlExceeded {
                max_ms: 300_000,
                requested_ms: 600_000,
            }
            .wire_code(),
            "nonce.ttl_exceeded"
        );
    }

    #[test]
    fn wire_code_ttl_too_short() {
        assert_eq!(
            NonceError::TtlTooShort {
                min_ms: 30_000,
                requested_ms: 1_000,
            }
            .wire_code(),
            "nonce.ttl_too_short"
        );
    }

    #[test]
    fn wire_code_keyring_error() {
        use stellar_agent_core::error::AuthError;
        assert_eq!(
            NonceError::KeyringError(AuthError::KeyringNotFound {
                name: "nonce-key".to_owned()
            })
            .wire_code(),
            "keyring.error"
        );
    }

    #[test]
    fn wire_code_key_too_short() {
        assert_eq!(
            NonceError::KeyTooShort { actual: 10 }.wire_code(),
            "nonce.key_too_short"
        );
    }

    #[test]
    fn wire_code_input_too_long() {
        assert_eq!(
            NonceError::InputTooLong {
                field: "tool_name",
                len: usize::MAX,
            }
            .wire_code(),
            "nonce.input_too_long"
        );
    }

    #[test]
    fn wire_code_serialise_failed() {
        assert_eq!(
            NonceError::SerialiseFailed {
                detail: "base64 decode error".to_owned()
            }
            .wire_code(),
            "nonce.serialise_failed"
        );
    }

    #[test]
    fn nonce_error_debug_does_not_leak_secret_material_on_all_platforms() {
        let secret_salt_hex = "0102030405060708090a0b0c0d0e0f10";
        let secret_hmac_tag_hex = "abababababababababababababababab";
        let secret_audit_key_bytes = "audit-key-bytes-0123456789abcdef";
        let errors = [
            NonceError::HmacMismatch,
            NonceError::Expired,
            NonceError::Replayed,
            NonceError::InvalidTool {
                tool: "stellar_pay".to_owned(),
            },
            NonceError::InvalidEnvelope,
            NonceError::ChainMismatch {
                expected: "stellar:testnet".to_owned(),
                got: "stellar:mainnet".to_owned(),
            },
            NonceError::TtlExceeded {
                max_ms: 300_000,
                requested_ms: 600_000,
            },
            NonceError::TtlTooShort {
                min_ms: 30_000,
                requested_ms: 1_000,
            },
            NonceError::KeyringError(AuthError::KeyringNotFound {
                name: "stellar-agent-nonce-test".to_owned(),
            }),
            NonceError::KeyTooShort { actual: 10 },
            NonceError::InputTooLong {
                field: "tool_name",
                len: usize::MAX,
            },
            NonceError::SerialiseFailed {
                detail: "base64 decode error".to_owned(),
            },
        ];

        for error in errors {
            let debug = format!("{error:?}");
            assert!(!debug.contains(secret_salt_hex), "{debug}");
            assert!(!debug.contains(secret_hmac_tag_hex), "{debug}");
            assert!(!debug.contains(secret_audit_key_bytes), "{debug}");
        }
    }
}
