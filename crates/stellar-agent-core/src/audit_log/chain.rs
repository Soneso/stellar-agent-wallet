//! Hash-chain primitives — SHA-256 chain computation and HMAC root signing.
//!
//! Provides:
//! - [`ZERO_BLOCK_HASH`] — the `previous_entry_hash` used by the first entry
//!   per file (SHA-256 of 32 zero bytes).
//! - [`compute_entry_hash`] — computes `SHA-256(canonical_body || prev_hash)`.
//! - [`sign_chain_root`] — HMAC-SHA256 signature over the first entry's body
//!   (the chain root) using the per-profile audit key.
//! - [`verify_chain_root`] — verifies the HMAC tag on a chain root.
//! - [`derive_entry_tag_key`], [`compute_entry_tag`] and [`check_entry_tag`]:
//!   the keyed per-entry tag that authenticates an entry and, through its hash,
//!   the whole chain before it.
//!
//! # Hash chain mechanism
//!
//! ```text
//! current_entry_hash = SHA-256(canonical_json(entry \ {previous_entry_hash, entry_tag})
//!                              || previous_entry_hash)
//! ```
//!
//! The first entry uses `previous_entry_hash = SHA-256([0u8; 32])`.
//!
//! # HMAC root signature
//!
//! The first entry per file (the chain root) is additionally signed with
//! `HMAC-SHA256(audit_key, canonical_body)` where `audit_key` is fetched from
//! the keyring entry `stellar-agent-audit-<profile>`. The root tag covers that
//! first entry only.
//!
//! # Entry tags
//!
//! A writer holding the audit key also tags every entry it writes:
//!
//! ```text
//! K_e       = HMAC-SHA256(audit_key, "stellar-agent-audit-entry-key:v1")
//! entry_tag = "sha256:" || hex(HMAC-SHA256(K_e, "stellar-agent-audit-entry:v1" || entry_hash))
//! ```
//!
//! `entry_hash` is the 32 raw bytes of the entry's chain hash, which covers its
//! canonical body and its predecessor's hash. A valid tag on an entry therefore
//! authenticates every entry before it in the chain, and binds the entry to its
//! position: the same body and tag re-chained onto another predecessor has a
//! different hash and fails the check. The tag sits outside the canonical body,
//! so it changes no entry hash, anchor, root tag or outbox head. `K_e` keeps
//! entry tags apart from root tags, which are an HMAC over a body under the
//! audit key itself.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

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

// ── Entry tags ───────────────────────────────────────────────────────────────

/// Label the entry-tag key is derived under.
const ENTRY_TAG_KEY_LABEL: &[u8] = b"stellar-agent-audit-entry-key:v1";

/// Label that prefixes the entry hash in every entry tag.
const ENTRY_TAG_LABEL: &[u8] = b"stellar-agent-audit-entry:v1";

/// The key entry tags are computed under, derived from the audit key.
///
/// The bytes are zeroed on drop and never printed: `Debug` shows
/// `EntryTagKey(..)`.
#[derive(Clone)]
pub struct EntryTagKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for EntryTagKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EntryTagKey(..)")
    }
}

impl EntryTagKey {
    /// The derived key bytes, for the fixed-vector test.
    #[cfg(test)]
    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derives the entry-tag key `K_e = HMAC-SHA256(audit_key,
/// "stellar-agent-audit-entry-key:v1")`.
///
/// The derivation keeps entry tags apart from chain-root tags, which are an
/// HMAC under the audit key itself.
#[must_use]
pub fn derive_entry_tag_key(audit_key: &[u8; 32]) -> EntryTagKey {
    let mut mac = keyed_mac(audit_key);
    mac.update(ENTRY_TAG_KEY_LABEL);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&mac.finalize().into_bytes());
    EntryTagKey(key)
}

/// An HMAC-SHA256 instance keyed with the 32 bytes of `key`.
///
/// HMAC accepts a key of any length, so the keyed constructor cannot fail.
#[allow(
    clippy::expect_used,
    reason = "HMAC-SHA256 key initialisation with a 32-byte key is infallible"
)]
fn keyed_mac(key: &[u8; 32]) -> HmacSha256 {
    HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts a key of any length")
}

/// The raw entry-tag MAC over the 32 bytes of `entry_hash`.
fn entry_tag_bytes(key: &EntryTagKey, entry_hash: &[u8; 32]) -> [u8; 32] {
    let mut mac = keyed_mac(&key.0);
    mac.update(ENTRY_TAG_LABEL);
    mac.update(entry_hash);
    mac.finalize().into_bytes().into()
}

/// Computes the entry tag of the entry whose chain hash is `entry_hash`.
///
/// Returns `"sha256:"` followed by the lowercase hex of
/// `HMAC-SHA256(K_e, "stellar-agent-audit-entry:v1" || entry_hash_bytes)`,
/// where `entry_hash_bytes` are the 32 bytes `entry_hash` encodes.
///
/// # Errors
///
/// [`HashError`] when `entry_hash` is not `sha256:<64 lowercase hex>`.
pub fn compute_entry_tag(key: &EntryTagKey, entry_hash: &str) -> Result<String, HashError> {
    let hash = decode_hash(entry_hash)?;
    Ok(encode_hash(&entry_tag_bytes(key, &hash)))
}

/// The outcome of checking one entry's tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryTagCheck {
    /// The tag verifies under the key.
    Valid,
    /// The entry carries no tag.
    Missing,
    /// The entry carries a tag that is malformed or does not verify.
    Mismatch,
}

impl EntryTagCheck {
    /// `missing` or `mismatch`, the reason a failing check reports; `None`
    /// for a valid tag.
    #[must_use]
    pub fn failure_reason(self) -> Option<&'static str> {
        match self {
            Self::Valid => None,
            Self::Missing => Some("missing"),
            Self::Mismatch => Some("mismatch"),
        }
    }
}

/// Checks `tag` against the tag of the entry whose chain hash is `entry_hash`.
///
/// `None` is [`EntryTagCheck::Missing`]. A tag that is not `sha256:` followed
/// by 64 lowercase hex digits, and a tag that does not verify, are
/// [`EntryTagCheck::Mismatch`]; so is any tag when `entry_hash` itself does not
/// decode. The comparison is constant time.
#[must_use]
pub fn check_entry_tag(key: &EntryTagKey, entry_hash: &str, tag: Option<&str>) -> EntryTagCheck {
    let Some(tag) = tag else {
        return EntryTagCheck::Missing;
    };
    let (Ok(hash), Ok(tag)) = (decode_hash(entry_hash), decode_hash(tag)) else {
        return EntryTagCheck::Mismatch;
    };
    if entry_tag_bytes(key, &hash).ct_eq(&tag).into() {
        EntryTagCheck::Valid
    } else {
        EntryTagCheck::Mismatch
    }
}

// ── Hex helpers ───────────────────────────────────────────────────────────────

/// Encodes 32 bytes as the `"sha256:<64 lowercase hex chars>"` string every
/// entry hash uses; the inverse of [`decode_hash`].
pub(crate) fn encode_hash(bytes: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(bytes))
}

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

    #[test]
    fn entry_tag_matches_the_fixed_vector() {
        let mut audit_key = [0u8; 32];
        for (index, byte) in audit_key.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        let key = derive_entry_tag_key(&audit_key);
        assert_eq!(
            super::hex::encode(key.bytes()),
            "ba3a16ac6a201914eb6182bad98467bffa516c8318c59cd6102bb46b425a81c2"
        );
        let tag = compute_entry_tag(&key, ZERO_BLOCK_HASH).unwrap();
        assert_eq!(
            tag,
            "sha256:4f5e4b9f20269cdc58d0ff9a0e2c7df9152009320c4fe297392695f7c31021d0"
        );
        assert_eq!(
            check_entry_tag(&key, ZERO_BLOCK_HASH, Some(&tag)),
            EntryTagCheck::Valid
        );
        assert_eq!(format!("{key:?}"), "EntryTagKey(..)");
    }

    #[test]
    fn check_entry_tag_reports_missing_and_mismatch() {
        let key = derive_entry_tag_key(&[0x42; 32]);
        let tag = compute_entry_tag(&key, ZERO_BLOCK_HASH).unwrap();
        assert_eq!(
            check_entry_tag(&key, ZERO_BLOCK_HASH, None),
            EntryTagCheck::Missing
        );
        let hex = tag.strip_prefix("sha256:").unwrap();
        let flipped_digit = {
            let mut chars: Vec<char> = hex.chars().collect();
            chars[10] = if chars[10] == '0' { '1' } else { '0' };
            format!("sha256:{}", chars.into_iter().collect::<String>())
        };
        let uppercase = format!("sha256:{}", hex.to_uppercase());
        let short = format!("sha256:{}", &hex[..63]);
        let unprefixed = hex.to_owned();
        for refused in [flipped_digit, uppercase, short, unprefixed] {
            assert_eq!(
                check_entry_tag(&key, ZERO_BLOCK_HASH, Some(&refused)),
                EntryTagCheck::Mismatch,
                "{refused}"
            );
        }
        let other_key = derive_entry_tag_key(&[0x43; 32]);
        assert_eq!(
            check_entry_tag(&other_key, ZERO_BLOCK_HASH, Some(&tag)),
            EntryTagCheck::Mismatch
        );
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
