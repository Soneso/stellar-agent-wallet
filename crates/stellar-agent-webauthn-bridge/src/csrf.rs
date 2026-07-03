//! CSRF token type for the WebAuthn browser-handoff bridge.
//!
//! Provides [`CsrfToken`], a 32-byte `OsRng`-sourced random nonce bound to a
//! single approval-store entry.  The token is hex-encoded (64 lowercase ASCII
//! characters) only at URL-emission time; raw bytes are never printed or
//! logged.
//!
//! # Security invariants
//!
//! - Equality MUST be tested via [`CsrfToken::ct_eq`], which uses
//!   [`subtle::ConstantTimeEq`].  Direct `==` / `.eq()` comparisons are
//!   prohibited to avoid timing-leak comparisons.
//! - The `Debug` implementation is redacted: it shows `CsrfToken { _len: 32 }`
//!   only and never exposes raw bytes or the hex string.
//! - The `Clone` implementation is provided for the approval-store copy path;
//!   callers must not store multiple live copies across trust boundaries.

use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq as _;

// ─────────────────────────────────────────────────────────────────────────────
// CsrfToken
// ─────────────────────────────────────────────────────────────────────────────

/// A 32-byte CSRF token sourced from `rand_core::OsRng`, bound to an
/// approval-store entry.
///
/// # Security invariants
///
/// Comparison MUST use [`CsrfToken::ct_eq`]; `==` is not implemented.  Raw
/// bytes are never exposed via `Debug` or `Display`.  Hex encoding is only
/// for URL emission.
///
/// # Examples
///
/// ```
/// use stellar_agent_webauthn_bridge::CsrfToken;
/// use subtle::ConstantTimeEq as _;
///
/// let token = CsrfToken::generate();
/// let hex = token.to_hex();
/// assert_eq!(hex.len(), 64);
///
/// let parsed = CsrfToken::from_hex(&hex).expect("roundtrip");
/// let equal: bool = token.ct_eq(&parsed).into();
/// assert!(equal);
/// ```
#[derive(Clone)]
pub struct CsrfToken([u8; 32]);

impl CsrfToken {
    /// Generate a fresh 32-byte CSRF token from `rand_core::OsRng`.
    ///
    /// Each call produces an independent, unpredictable token.
    ///
    /// In the wallet, production CSRF tokens are minted by
    /// `stellar_agent_core::approval::generate_csrf_token` when the pending
    /// approval is created; the bridge only reconstructs tokens from stored
    /// bytes ([`Self::from_bytes`]) and parses submitted tokens
    /// ([`Self::from_hex`]). This constructor is provided for completeness and
    /// for tests.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Hex-encode the token for URL emission (64 lowercase hex characters).
    ///
    /// The returned string is suitable for inclusion in HTML attributes or HTTP
    /// headers.  It contains no shell metacharacters, newlines, or non-ASCII
    /// bytes.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Constructs a `CsrfToken` from a 32-byte array.
    ///
    /// No validation is needed: any 32-byte value is valid CSRF-token
    /// contents. Use [`Self::generate`] for fresh tokens; this constructor is
    /// for reconstituting already-existing bytes from the approval store.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse a hex-encoded token.
    ///
    /// Used at the bridge POST handler call site to decode the
    /// `X-Stellar-Approval-CSRF` header value.
    ///
    /// # Errors
    ///
    /// Returns [`CsrfTokenParseError::WrongLength`] when `s` is not exactly 64
    /// characters.  Returns [`CsrfTokenParseError::NonHexChar`] when `s`
    /// contains a character outside `[0-9a-fA-F]`.
    pub fn from_hex(s: &str) -> Result<Self, CsrfTokenParseError> {
        let actual = s.len();
        if actual != 64 {
            return Err(CsrfTokenParseError::WrongLength { actual });
        }
        // Find the first non-hex character and report its byte offset.
        if let Some(offset) = s.bytes().position(|b| !b.is_ascii_hexdigit()) {
            return Err(CsrfTokenParseError::NonHexChar { offset });
        }
        let decoded = hex::decode(s).map_err(|_| {
            // hex::decode failing here would be a logic error (already validated
            // each character above), but we must handle the Result.
            CsrfTokenParseError::NonHexChar { offset: 0 }
        })?;
        // Invariant: decoded has exactly 32 bytes because s passed the
        // 64-hex-char length + charset checks above, so copy_from_slice cannot
        // panic.
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        Ok(Self(arr))
    }

    /// Constant-time equality comparison via [`subtle::ConstantTimeEq`].
    ///
    /// Returns a [`subtle::Choice`] which can be converted to `bool` via
    /// `.into()` at the call site.  Direct `==` comparison of token bytes is
    /// deliberately not provided.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_webauthn_bridge::CsrfToken;
    ///
    /// let a = CsrfToken::generate();
    /// let b = a.clone();
    /// let equal: bool = a.ct_eq(&b).into();
    /// assert!(equal);
    /// ```
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl std::fmt::Debug for CsrfToken {
    /// Redacted `Debug` implementation: never emits token bytes.
    ///
    /// Shows `CsrfToken { _len: 32 }` only; never emits raw bytes or the hex
    /// representation of the token contents.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsrfToken")
            .field("_len", &self.0.len())
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CsrfTokenParseError
// ─────────────────────────────────────────────────────────────────────────────

/// Error type returned by [`CsrfToken::from_hex`].
///
/// `#[non_exhaustive]`: future parser tightening (e.g. rejecting uppercase hex
/// digits explicitly) may add new variants, and existing match-arm callers must
/// continue to compile.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum CsrfTokenParseError {
    /// The input string is not exactly 64 hex characters.
    #[error("csrf token must be exactly 64 hex characters, got {actual} characters")]
    WrongLength {
        /// Actual character count received.
        actual: usize,
    },

    /// The input string contains a non-hex character.
    #[error("csrf token contains non-hex character at byte offset {offset}")]
    NonHexChar {
        /// Byte offset of the first non-hex character.
        offset: usize,
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
        clippy::panic,
        reason = "test-only"
    )]
    use super::*;

    #[test]
    fn generate_fills_token_with_rng_bytes() {
        // The 32-byte length is a compile-time invariant of the `[u8; 32]`
        // field, so asserting it would be vacuous. Instead assert the token is
        // not the all-zero array — i.e. `OsRng::fill_bytes` actually ran. This
        // fails if the RNG fill were dropped (probability of a genuine all-zero
        // draw is 2^-256).
        let token = CsrfToken::generate();
        assert_ne!(
            token.0, [0u8; 32],
            "generate() must fill the token with RNG bytes, not leave it zeroed"
        );
    }

    #[test]
    fn generate_produces_distinct_values() {
        let a = CsrfToken::generate();
        let b = CsrfToken::generate();
        // Use ct_eq (never ==); Choice(0) means not equal.
        let same: bool = a.ct_eq(&b).into();
        assert!(!same, "two independently generated tokens should differ");
    }

    #[test]
    fn to_hex_returns_64_lowercase_hex_chars() {
        let hex = CsrfToken::generate().to_hex();
        assert_eq!(hex.len(), 64, "expected 64 hex chars, got {}", hex.len());
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "expected all lowercase hex chars, got: {hex}"
        );
    }

    #[test]
    fn from_hex_roundtrip_succeeds() {
        let original = CsrfToken::generate();
        let hex = original.to_hex();
        let parsed = CsrfToken::from_hex(&hex).expect("roundtrip should succeed");
        let equal: bool = original.ct_eq(&parsed).into();
        assert!(equal, "roundtrip produced a different token");
    }

    #[test]
    fn from_bytes_roundtrips_through_hex() {
        let token = CsrfToken::from_bytes([0xAA; 32]);
        assert_eq!(token.to_hex(), "aa".repeat(32));
    }

    #[test]
    fn from_hex_rejects_empty() {
        let err = CsrfToken::from_hex("").unwrap_err();
        assert!(
            matches!(err, CsrfTokenParseError::WrongLength { actual: 0 }),
            "expected WrongLength(0), got: {err}"
        );
    }

    #[test]
    fn from_hex_rejects_short_63() {
        let short = "a".repeat(63);
        let err = CsrfToken::from_hex(&short).unwrap_err();
        assert!(
            matches!(err, CsrfTokenParseError::WrongLength { actual: 63 }),
            "expected WrongLength(63), got: {err}"
        );
    }

    #[test]
    fn from_hex_rejects_long_65() {
        let long = "a".repeat(65);
        let err = CsrfToken::from_hex(&long).unwrap_err();
        assert!(
            matches!(err, CsrfTokenParseError::WrongLength { actual: 65 }),
            "expected WrongLength(65), got: {err}"
        );
    }

    #[test]
    fn from_hex_rejects_non_hex_char() {
        // Build a 64-char string with a non-hex char at offset 31.
        let mut s = "a".repeat(64);
        // Replace the character at byte offset 31 with 'z' (non-hex).
        s.replace_range(31..32, "z");
        let err = CsrfToken::from_hex(&s).unwrap_err();
        assert!(
            matches!(err, CsrfTokenParseError::NonHexChar { offset: 31 }),
            "expected NonHexChar{{offset:31}}, got: {err}"
        );
    }

    #[test]
    fn ct_eq_matches_for_clone() {
        let token = CsrfToken::generate();
        let clone = token.clone();
        let equal: bool = token.ct_eq(&clone).into();
        assert!(equal, "clone should be ct_eq to original");
    }

    #[test]
    fn ct_eq_mismatches_for_distinct() {
        let a = CsrfToken::generate();
        let b = CsrfToken::generate();
        let equal: bool = a.ct_eq(&b).into();
        assert!(!equal, "two distinct tokens should not be ct_eq");
    }

    #[test]
    fn debug_is_redacted() {
        let token = CsrfToken::generate();
        let rendered = format!("{token:?}");
        // Must contain the redacted shape marker.
        assert!(
            rendered.contains("_len"),
            "Debug must show _len field, got: {rendered}"
        );
        // Must NOT contain the hex representation of the token bytes.
        let hex = token.to_hex();
        assert!(
            !rendered.contains(&hex),
            "Debug must not expose raw hex bytes, got: {rendered}"
        );
        // Sanity: the full rendered form matches the expected redacted pattern.
        assert!(
            rendered.contains("CsrfToken"),
            "Debug must name the type, got: {rendered}"
        );
    }
}
