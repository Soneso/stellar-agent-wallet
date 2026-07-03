//! SHA-256 hash verification for toolset packages.
//!
//! ## Design
//!
//! - The package is read ONCE through a [`Read::take`] guard capped at
//!   [`crate::MAX_PACKAGE_BYTES`] + 1.  If the limit is exceeded, reading is
//!   aborted immediately and [`ToolsetInstallError::PackageTooLarge`] is returned
//!   without buffering the full input.
//! - The verified bytes are accumulated in a single in-memory buffer; SHA-256
//!   is computed over that buffer.  The same buffer is later passed to the
//!   extractor ("read once, one buffer").  This prevents TOCTOU attacks where
//!   an attacker swaps the file between hash and extract.
//! - The computed hex digest is compared to the trusted `expected_hex` string
//!   with [`subtle::ConstantTimeEq`].  The comparison is over PUBLIC data (the
//!   hash is not secret); `subtle` is used for uniformity/defence-in-depth, NOT
//!   because a timing leak here is exploitable.

use std::io::Read;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{MAX_PACKAGE_BYTES, ToolsetInstallError};

/// Computes SHA-256 of `data` and returns the lowercase hex digest (64 chars).
///
/// Used at install time to hash the extracted `TOOLSET.md` bytes for
/// dispatch-time content re-verification.
///
/// The result is stored in [`crate::pin::ToolsetPinRecord::toolset_md_shasum`] and
/// compared on every dispatch against the live `TOOLSET.md` on disk to detect
/// post-install tampering.
///
/// # Examples
///
/// ```
/// use stellar_agent_toolsets_install::sha256_hex_of;
///
/// let digest = sha256_hex_of(b"hello");
/// assert_eq!(digest.len(), 64);
/// assert!(digest.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
/// ```
pub fn sha256_hex_of(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Reads `reader` into a buffer (capped at [`MAX_PACKAGE_BYTES`]), computes
/// SHA-256, and compares to `expected_hex` using constant-time equality.
///
/// Returns the buffer on success so it can be reused for extraction without
/// re-opening the source.
///
/// # Errors
///
/// - [`ToolsetInstallError::PackageTooLarge`] — source is larger than
///   [`MAX_PACKAGE_BYTES`].
/// - [`ToolsetInstallError::Io`] — underlying read error.
/// - [`ToolsetInstallError::HashMismatch`] — SHA-256 ≠ `expected_hex`.
///
/// # Examples
///
/// ```rust,ignore
/// // read_and_verify_hash is pub(crate); tested via unit tests in hash.rs.
/// ```
pub(crate) fn read_and_verify_hash(
    reader: impl Read,
    expected_hex: &str,
) -> Result<Vec<u8>, ToolsetInstallError> {
    // Cap reading at MAX_PACKAGE_BYTES + 1 so that a source of exactly
    // MAX_PACKAGE_BYTES succeeds while MAX_PACKAGE_BYTES + 1 triggers the
    // too-large path.
    let cap = MAX_PACKAGE_BYTES;
    let mut limited = reader.take((cap as u64) + 1);

    let mut buf: Vec<u8> = Vec::with_capacity(cap.min(64 * 1024));
    limited
        .read_to_end(&mut buf)
        .map_err(ToolsetInstallError::from_io)?;

    if buf.len() > cap {
        return Err(ToolsetInstallError::PackageTooLarge { cap });
    }

    // Compute SHA-256 over the buffer.
    let mut hasher = Sha256::new();
    hasher.update(&buf);
    let digest = hasher.finalize();
    let computed_hex = hex::encode(digest);

    // Constant-time comparison over the hex strings.
    // Both are ASCII strings of equal length (64 bytes for SHA-256 hex).
    // ConstantTimeEq is used for uniformity (defence-in-depth); the hash
    // is not secret — timing leakage here is not exploitable.
    let matches = bool::from(computed_hex.as_bytes().ct_eq(expected_hex.as_bytes()));

    if !matches {
        return Err(ToolsetInstallError::HashMismatch);
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use sha2::{Digest, Sha256};

    use super::*;

    fn sha256_hex(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    #[test]
    fn correct_hash_succeeds() {
        let data = b"hello toolset package";
        let hex = sha256_hex(data);
        let buf = read_and_verify_hash(data.as_ref(), &hex).unwrap();
        assert_eq!(buf, data.as_slice());
    }

    #[test]
    fn wrong_hash_returns_mismatch() {
        let data = b"hello toolset package";
        let wrong_hex = "a".repeat(64);
        let err = read_and_verify_hash(data.as_ref(), &wrong_hex).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::HashMismatch),
            "expected HashMismatch, got: {err:?}"
        );
    }

    #[test]
    fn package_too_large_returns_error() {
        // Create a reader that would deliver more than MAX_PACKAGE_BYTES.
        // We use a slice just over the cap.
        let big = vec![0u8; MAX_PACKAGE_BYTES + 1];
        let correct_hex = sha256_hex(&big); // won't matter; size check is first
        let err = read_and_verify_hash(big.as_slice(), &correct_hex).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::PackageTooLarge { .. }),
            "expected PackageTooLarge, got: {err:?}"
        );
    }

    #[test]
    fn exact_max_size_succeeds() {
        let data = vec![0u8; MAX_PACKAGE_BYTES];
        let hex = sha256_hex(&data);
        let buf = read_and_verify_hash(data.as_slice(), &hex).unwrap();
        assert_eq!(buf.len(), MAX_PACKAGE_BYTES);
    }
}
