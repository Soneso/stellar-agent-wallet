//! Typed hex-codec helpers.
//!
//! Centralises `encode` / `decode_hex32` for deployment, CLI, and test helpers.
//! No external `hex` crate is used; the implementation is self-contained to
//! preserve the typed-error discipline and avoid an additional dependency.

use thiserror::Error;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors from hex decoding operations.
///
/// All variants carry only non-secret context (lengths, char positions,
/// char values). No secret material ever flows through hex decode paths in
/// the deployment module — salt and deployer keys are binary values that
/// arrive already validated; hex decode is applied only to user-supplied
/// `--salt-hex` strings and to compile-time WASM-hash constants.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum HexDecodeError {
    /// Input length was not exactly `expected * 2` hex characters.
    #[error("hex input has wrong length: expected {expected} bytes ({} hex chars), got {actual} chars", expected * 2)]
    InvalidLength {
        /// Expected number of output bytes (not hex chars).
        expected: usize,
        /// Actual number of input characters.
        actual: usize,
    },

    /// A character at `offset` is not a valid lowercase or uppercase hex digit.
    ///
    /// `offset` is the 0-based index into the hex string (not into the output).
    /// `ch` is the invalid character. Neither field carries secret material —
    /// the offset identifies a position in the user-supplied hex string, and the
    /// character is the non-hex byte at that position.
    #[error("invalid hex character '{ch}' at offset {offset}")]
    InvalidChar {
        /// 0-based offset into the hex string.
        offset: usize,
        /// The invalid character.
        ch: char,
    },
}

// ── Public functions ──────────────────────────────────────────────────────────

/// Encodes `bytes` as lowercase hex without external `hex` crate dependency.
///
/// Allocates exactly `bytes.len() * 2` chars.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::hex::encode;
///
/// assert_eq!(encode(&[0x0f, 0xab]), "0fab");
/// assert_eq!(encode(&[]), "");
/// ```
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// Decodes a 64-char hex string into exactly 32 bytes.
///
/// Accepts both lowercase and uppercase hex digits.
///
/// # Errors
///
/// - [`HexDecodeError::InvalidLength`] if `hex.len() != 64`.
/// - [`HexDecodeError::InvalidChar`] if any character is not a valid hex digit.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::hex::decode_hex32;
///
/// let result = decode_hex32("0000000000000000000000000000000000000000000000000000000000000000");
/// assert_eq!(result.unwrap(), [0u8; 32]);
///
/// let err = decode_hex32("short");
/// assert!(err.is_err());
/// ```
pub fn decode_hex32(hex: &str) -> Result<[u8; 32], HexDecodeError> {
    if hex.len() != 64 {
        return Err(HexDecodeError::InvalidLength {
            expected: 32,
            actual: hex.len(),
        });
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = char_to_nibble(chunk[0]).ok_or_else(|| HexDecodeError::InvalidChar {
            offset: i * 2,
            ch: chunk[0] as char,
        })?;
        let lo = char_to_nibble(chunk[1]).ok_or_else(|| HexDecodeError::InvalidChar {
            offset: i * 2 + 1,
            ch: chunk[1] as char,
        })?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn char_to_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Redacts a hex string to `"first8...last8"` form.
///
/// Used for WASM hashes, transaction hashes, and salt values in audit-log
/// entries and tracing events. Returns `"<short>"` for inputs shorter than
/// 16 hex characters.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::hex::redact_hex_first8_last8;
///
/// let h = "06186e938a0ba1585a5d8a6d2ec802f3d184aaf9ec298d8c8aece50ca56cb239";
/// assert_eq!(redact_hex_first8_last8(h), "06186e93...a56cb239");
/// assert_eq!(redact_hex_first8_last8("short"), "<short>");
/// ```
#[must_use]
pub fn redact_hex_first8_last8(hex: &str) -> String {
    if hex.len() >= 16 {
        format!("{}...{}", &hex[..8], &hex[hex.len() - 8..])
    } else {
        "<short>".to_owned()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use super::*;

    #[test]
    fn encode_empty_input() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn encode_single_byte() {
        assert_eq!(encode(&[0x0f]), "0f");
        assert_eq!(encode(&[0xff]), "ff");
        assert_eq!(encode(&[0x00]), "00");
    }

    #[test]
    fn encode_known_vector() {
        assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn encode_all_zeros_32_bytes() {
        let expected = "0".repeat(64);
        assert_eq!(encode(&[0u8; 32]), expected);
    }

    #[test]
    fn decode_hex32_all_zeros() {
        let hex = "0".repeat(64);
        assert_eq!(decode_hex32(&hex).unwrap(), [0u8; 32]);
    }

    #[test]
    fn decode_hex32_all_ff() {
        let hex = "f".repeat(64);
        assert_eq!(decode_hex32(&hex).unwrap(), [0xff_u8; 32]);
    }

    #[test]
    fn decode_hex32_uppercase_accepted() {
        let hex = "FF".repeat(32);
        assert_eq!(decode_hex32(&hex).unwrap(), [0xff_u8; 32]);
    }

    #[test]
    fn decode_hex32_mixed_case_accepted() {
        // All chars valid; mixed case.
        let hex = "0A".repeat(32);
        let result = decode_hex32(&hex).unwrap();
        assert!(result.iter().all(|&b| b == 0x0a));
    }

    #[test]
    fn decode_hex32_wrong_length_too_short() {
        let err = decode_hex32("abc").unwrap_err();
        assert!(matches!(
            err,
            HexDecodeError::InvalidLength {
                expected: 32,
                actual: 3
            }
        ));
    }

    #[test]
    fn decode_hex32_wrong_length_too_long() {
        let hex = "0".repeat(65);
        let err = decode_hex32(&hex).unwrap_err();
        assert!(
            matches!(
                err,
                HexDecodeError::InvalidLength {
                    expected: 32,
                    actual: 65
                }
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn decode_hex32_invalid_char_at_offset() {
        // 'z' at position 2.
        let hex = format!("00z{}", "0".repeat(61));
        let err = decode_hex32(&hex).unwrap_err();
        assert!(
            matches!(err, HexDecodeError::InvalidChar { offset: 2, ch: 'z' }),
            "got: {err:?}"
        );
    }

    #[test]
    fn encode_decode_round_trip() {
        let input = [
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c,
        ];
        let encoded = encode(&input);
        assert_eq!(encoded.len(), 64);
        let decoded = decode_hex32(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn hex_decode_error_display_invalid_length() {
        let err = HexDecodeError::InvalidLength {
            expected: 32,
            actual: 10,
        };
        let s = format!("{err}");
        assert!(s.contains("10"), "actual must appear: {s}");
        assert!(s.contains("32"), "expected bytes must appear: {s}");
    }

    #[test]
    fn hex_decode_error_display_invalid_char() {
        let err = HexDecodeError::InvalidChar { offset: 5, ch: 'z' };
        let s = format!("{err}");
        assert!(s.contains('z'), "char must appear: {s}");
        assert!(s.contains('5'), "offset must appear: {s}");
    }

    // ── redact_hex_first8_last8 ───────────────────────────────────────────────

    #[test]
    fn redact_empty_returns_short() {
        assert_eq!(redact_hex_first8_last8(""), "<short>");
    }

    #[test]
    fn redact_length_15_boundary_returns_short() {
        // 15 chars < 16 threshold.
        assert_eq!(redact_hex_first8_last8("a1b2c3d4e5f6789"), "<short>");
    }

    #[test]
    fn redact_length_16_boundary_returns_first8_last8() {
        // Exactly 16 chars: first 8 and last 8 are the same 16 chars split at the midpoint.
        let input = "aabbccdd11223344";
        let result = redact_hex_first8_last8(input);
        // first8 = "aabbccdd", last8 = "11223344"
        assert_eq!(result, "aabbccdd...11223344");
    }

    #[test]
    fn redact_64_char_sha256_hash() {
        let h = "06186e938a0ba1585a5d8a6d2ec802f3d184aaf9ec298d8c8aece50ca56cb239";
        let result = redact_hex_first8_last8(h);
        assert_eq!(result, "06186e93...a56cb239");
    }

    #[test]
    fn redact_produces_19_char_string_for_typical_hash() {
        // 8 + "..." (3) + 8 = 19 chars.
        let h = "deadbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161718";
        let result = redact_hex_first8_last8(h);
        assert_eq!(result.len(), 19);
        assert!(result.starts_with("deadbeef"), "{result}");
        assert!(result.ends_with("15161718"), "{result}");
    }
}
