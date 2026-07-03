//! Hash-chain primitives — SHA-256 chain computation and HMAC root signing.
//!
//! Provides:
//! - [`ZERO_BLOCK_HASH`] — the `previous_entry_hash` used by the first entry
//!   per file (SHA-256 of 32 zero bytes).
//! - [`compute_entry_hash`] — computes `SHA-256(canonical_body || prev_hash)`.
//! - [`sign_chain_root`] — HMAC-SHA256 signature over the first entry's body
//!   (the chain root) using the per-profile audit key.
//! - [`verify_chain_root`] — verifies the HMAC tag on a chain root.
//!
//! # Hash chain mechanism
//!
//! ```text
//! current_entry_hash = SHA-256(canonical_json(entry \ previous_entry_hash)
//!                              || previous_entry_hash)
//! ```
//!
//! The first entry uses `previous_entry_hash = SHA-256([0u8; 32])`.
//!
//! # HMAC root signature
//!
//! The first entry per file (the chain root) is additionally signed with
//! `HMAC-SHA256(audit_key, canonical_body)` where `audit_key` is fetched from
//! the keyring entry `stellar-agent-audit-<profile>`.  Subsequent entries
//! chain off the previous entry hash; no per-entry signature is needed.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

// ── Constants ─────────────────────────────────────────────────────────────────

/// `previous_entry_hash` for the first entry per file.
///
/// Computed as `SHA-256([0u8; 32])` (32 zero bytes).
/// Pre-computed at compile time as a `&str` in the format `sha256:<hex>`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::chain::ZERO_BLOCK_HASH;
///
/// assert!(ZERO_BLOCK_HASH.starts_with("sha256:"));
/// assert_eq!(ZERO_BLOCK_HASH.len(), 71); // "sha256:" + 64 hex chars
/// ```
pub const ZERO_BLOCK_HASH: &str =
    "sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925";

// Verified: SHA-256([0u8; 32]) = 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925

// ── Hash computation ──────────────────────────────────────────────────────────

/// Computes the current entry hash from its canonical body and the previous
/// entry hash.
///
/// `current_entry_hash = SHA-256(canonical_body || prev_hash_bytes)`
///
/// where `canonical_body` is the result of
/// [`AuditEntry::canonical_json_body`](super::entry::AuditEntry::canonical_json_body)
/// and `prev_hash_bytes` is the 32-byte decoded form of `previous_entry_hash`.
///
/// Returns `"sha256:<hex>"`.
///
/// # Errors
///
/// Returns an error if `previous_entry_hash` does not have the format
/// `sha256:<64-hex-chars>`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::chain::{compute_entry_hash, ZERO_BLOCK_HASH};
///
/// let body = b"{}";
/// let hash = compute_entry_hash(body, ZERO_BLOCK_HASH).unwrap();
/// assert!(hash.starts_with("sha256:"));
/// ```
pub fn compute_entry_hash(
    canonical_body: &[u8],
    previous_entry_hash: &str,
) -> Result<String, HashError> {
    let prev_bytes = decode_hash(previous_entry_hash)?;

    let mut hasher = Sha256::new();
    hasher.update(canonical_body);
    hasher.update(prev_bytes);
    let digest = hasher.finalize();

    Ok(format!("sha256:{}", hex::encode(digest)))
}

// ── HMAC root signing ─────────────────────────────────────────────────────────

/// Signs the chain-root canonical body with `HMAC-SHA256(key, body)`.
///
/// The tag is returned as a `sha256:<hex>` string for storage alongside the
/// first entry.  The caller is responsible for storing the tag in a trusted
/// location (e.g. the per-profile `.root_hmac` sidecar file in the audit
/// directory).
///
/// # Arguments
///
/// - `key_bytes` — the 32-byte HMAC key from the keyring entry
///   `stellar-agent-audit-<profile>`.
/// - `canonical_body` — the canonical JSON body of the first entry.
///
/// # Errors
///
/// Returns [`HmacError::InvalidKeyLength`] if `key_bytes` is not exactly
/// 32 bytes (the expected key length for HMAC-SHA256).
///
pub fn sign_chain_root(key_bytes: &[u8], canonical_body: &[u8]) -> Result<String, HmacError> {
    let mut mac = HmacSha256::new_from_slice(key_bytes).map_err(|_| HmacError::InvalidKeyLength)?;
    mac.update(canonical_body);
    let tag = mac.finalize().into_bytes();
    Ok(format!("sha256:{}", hex::encode(tag)))
}

/// Verifies an HMAC-SHA256 chain-root tag.
///
/// Performs constant-time comparison of the expected tag against the provided
/// `tag_hex` (format: `sha256:<hex>`).
///
/// # Errors
///
/// - [`HmacError::InvalidKeyLength`] if `key_bytes` is not 32 bytes.
/// - [`HmacError::InvalidTagFormat`] if `tag_hex` is malformed.
/// - [`HmacError::TagMismatch`] if the tag does not match (constant-time).
///
pub fn verify_chain_root(
    key_bytes: &[u8],
    canonical_body: &[u8],
    tag_hex: &str,
) -> Result<(), HmacError> {
    let tag_bytes = decode_hash(tag_hex).map_err(|_| HmacError::InvalidTagFormat)?;

    let mut mac = HmacSha256::new_from_slice(key_bytes).map_err(|_| HmacError::InvalidKeyLength)?;
    mac.update(canonical_body);
    let expected = mac.finalize().into_bytes();

    // Constant-time comparison via `subtle`.
    if expected.ct_eq(&tag_bytes).into() {
        Ok(())
    } else {
        Err(HmacError::TagMismatch)
    }
}

// ── Hex helpers ───────────────────────────────────────────────────────────────

/// Decode a `"sha256:<64-hex-chars>"` string to 32 bytes.
pub(crate) fn decode_hash(s: &str) -> Result<[u8; 32], HashError> {
    let hex_part = s.strip_prefix("sha256:").ok_or(HashError::InvalidFormat)?;
    if hex_part.len() != 64 {
        return Err(HashError::InvalidFormat);
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_part, &mut out).map_err(|_| HashError::InvalidHex)?;
    Ok(out)
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors that can occur during hash computation.
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    /// The hash string was not in the expected `sha256:<hex>` format.
    #[error("invalid hash format: expected 'sha256:<64-hex-chars>'")]
    InvalidFormat,
    /// The hex part of the hash string was not valid hexadecimal.
    #[error("invalid hex in hash string")]
    InvalidHex,
}

/// Errors that can occur during HMAC signing or verification.
#[derive(Debug, thiserror::Error)]
pub enum HmacError {
    /// The HMAC key was not the expected length.
    #[error("invalid HMAC key length")]
    InvalidKeyLength,
    /// The tag format was invalid.
    #[error("invalid HMAC tag format")]
    InvalidTagFormat,
    /// The HMAC tag did not match (constant-time comparison failed).
    #[error("HMAC tag mismatch")]
    TagMismatch,
}

// ── hex encoding helper (avoid extra dep) ────────────────────────────────────
//
// The `hex` crate is not in the workspace; this private module covers only
// `encode` + `decode_to_slice` for the `sha256:<hex>` format used here.
// Adding a dep for two small functions with no external API surface is not
// warranted.

mod hex {
    /// Encode bytes as lowercase hex string.
    pub(super) fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Decode a lowercase hex string into a fixed-size byte array.
    ///
    /// Returns `Err(())` if the string length is wrong, contains non-hex
    /// characters, or contains uppercase hex letters (strict lowercase only).
    pub(super) fn decode_to_slice(s: &str, out: &mut [u8]) -> Result<(), ()> {
        if s.len() != out.len() * 2 {
            return Err(());
        }
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_nibble(chunk[0]).ok_or(())?;
            let lo = hex_nibble(chunk[1]).ok_or(())?;
            out[i] = (hi << 4) | lo;
        }
        Ok(())
    }

    /// Returns the nibble value for a lowercase hex digit, or `None` if the
    /// byte is not a valid lowercase hex character.
    ///
    /// Uppercase `A–F` are rejected (strict lowercase enforcement).
    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            // Uppercase intentionally rejected (strict lowercase).
            _ => None,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    use super::*;

    #[test]
    fn zero_block_hash_format() {
        assert!(ZERO_BLOCK_HASH.starts_with("sha256:"));
        assert_eq!(ZERO_BLOCK_HASH.len(), 71);
    }

    #[test]
    fn zero_block_hash_value_correct() {
        // Independently verify SHA-256([0u8; 32]).
        let mut hasher = Sha256::new();
        hasher.update([0u8; 32]);
        let digest = hasher.finalize();
        let expected = format!("sha256:{}", super::hex::encode(digest));
        assert_eq!(ZERO_BLOCK_HASH, expected);
    }

    #[test]
    fn compute_entry_hash_deterministic() {
        let body = b"test body";
        let h1 = compute_entry_hash(body, ZERO_BLOCK_HASH).unwrap();
        let h2 = compute_entry_hash(body, ZERO_BLOCK_HASH).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_entry_hash_changes_on_body_mutation() {
        let h1 = compute_entry_hash(b"body1", ZERO_BLOCK_HASH).unwrap();
        let h2 = compute_entry_hash(b"body2", ZERO_BLOCK_HASH).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_entry_hash_changes_on_prev_hash_mutation() {
        // A different previous_entry_hash (same format, different value).
        let other_prev = "sha256:0000000000000000000000000000000000000000000000000000000000000001";
        let h1 = compute_entry_hash(b"body", ZERO_BLOCK_HASH).unwrap();
        let h2 = compute_entry_hash(b"body", other_prev).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn hmac_sign_verify_round_trip() {
        let key = [0x42u8; 32];
        let body = b"canonical body";
        let tag = sign_chain_root(&key, body).unwrap();
        assert!(tag.starts_with("sha256:"));
        assert!(verify_chain_root(&key, body, &tag).is_ok());
    }

    #[test]
    fn hmac_verify_fails_on_wrong_key() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let body = b"body";
        let tag = sign_chain_root(&key1, body).unwrap();
        assert!(verify_chain_root(&key2, body, &tag).is_err());
    }

    #[test]
    fn hmac_verify_fails_on_tampered_body() {
        let key = [0x42u8; 32];
        let tag = sign_chain_root(&key, b"original").unwrap();
        assert!(verify_chain_root(&key, b"tampered", &tag).is_err());
    }

    #[test]
    fn invalid_hash_format_error() {
        let err = compute_entry_hash(b"body", "badformat");
        assert!(err.is_err());
    }

    // ── hex helper unit tests ─────────────────────────────────────────────────

    #[test]
    fn hex_encode_empty() {
        assert_eq!(super::hex::encode([] as [u8; 0]), "");
    }

    #[test]
    fn hex_encode_single_byte() {
        assert_eq!(super::hex::encode([0xABu8]), "ab");
    }

    #[test]
    fn hex_encode_multi_byte() {
        assert_eq!(super::hex::encode([0x00u8, 0xFF, 0x80]), "00ff80");
    }

    #[test]
    fn hex_decode_valid() {
        let mut out = [0u8; 2];
        assert!(super::hex::decode_to_slice("dead", &mut out).is_ok());
        assert_eq!(out, [0xDE, 0xAD]);
    }

    #[test]
    fn hex_decode_invalid_char_rejected() {
        let mut out = [0u8; 1];
        assert!(super::hex::decode_to_slice("zz", &mut out).is_err());
    }

    #[test]
    fn hex_decode_uppercase_rejected() {
        let mut out = [0u8; 1];
        // Uppercase must be rejected (strict lowercase).
        assert!(super::hex::decode_to_slice("AB", &mut out).is_err());
    }

    #[test]
    fn hex_decode_odd_length_rejected() {
        let mut out = [0u8; 1];
        assert!(super::hex::decode_to_slice("a", &mut out).is_err());
    }
}
