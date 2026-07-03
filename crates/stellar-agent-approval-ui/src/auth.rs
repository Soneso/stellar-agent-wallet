//! Session and CSRF primitives for the approval-inbox server.
//!
//! The approval-inbox server replaces the WebAuthn bridge's
//! URL-token-on-every-route model with a one-time bootstrap-token exchange for
//! an `HttpOnly` session cookie:
//!
//! - A 32-byte [`OpaqueToken`] bootstrap token is minted at server start and
//!   emitted once as `GET /bootstrap/<hex>`. On the first successful exchange
//!   it is consumed (single use) and a fresh 32-byte session id + a 32-byte
//!   per-session CSRF key are minted.
//! - Every other route requires the session cookie, whose value is compared in
//!   constant time against the stored session id. Absent / malformed / mismatch
//!   collapse to the same "not found" posture.
//! - State-changing POSTs additionally carry
//!   `hex(HMAC-SHA256(csrf_key, approval_nonce_bytes))` in the
//!   `X-Stellar-Approval-CSRF` header, recomputed server-side over the nonce
//!   from the URL path and compared in constant time.
//!
//! All comparisons go through [`subtle::ConstantTimeEq`]; token bytes are never
//! logged and the [`OpaqueToken`] `Debug` impl is redacted.

use hmac::{Hmac, KeyInit as _, Mac as _};
use rand_core::{OsRng, RngCore as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

/// Name of the session cookie set after a successful bootstrap exchange.
pub(crate) const SESSION_COOKIE_NAME: &str = "stellar_agent_approval_session";

/// Request header carrying the per-nonce CSRF value on state-changing POSTs.
pub(crate) const CSRF_HEADER_NAME: &str = "x-stellar-approval-csrf";

type HmacSha256 = Hmac<Sha256>;

/// An opaque 32-byte token sourced from `rand_core::OsRng`.
///
/// Used for the single-use bootstrap token and the session id. Comparison MUST
/// use [`OpaqueToken::ct_eq`]; `==` is deliberately not implemented. Raw bytes
/// are never exposed via `Debug`; hex is only for URL / cookie emission.
#[derive(Clone)]
pub(crate) struct OpaqueToken([u8; 32]);

impl OpaqueToken {
    /// Generate a fresh 32-byte token from `rand_core::OsRng`.
    pub(crate) fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Hex-encode the token (64 lowercase hex characters) for URL / cookie use.
    pub(crate) fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a 64-character lowercase-or-uppercase hex string into a token.
    ///
    /// Returns `None` when the input is not exactly 64 hex characters.
    pub(crate) fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 || s.bytes().any(|b| !b.is_ascii_hexdigit()) {
            return None;
        }
        let decoded = hex::decode(s).ok()?;
        let mut arr = [0u8; 32];
        if decoded.len() != 32 {
            return None;
        }
        arr.copy_from_slice(&decoded);
        Some(Self(arr))
    }

    /// Constant-time equality comparison via [`subtle::ConstantTimeEq`].
    pub(crate) fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl std::fmt::Debug for OpaqueToken {
    /// Redacted `Debug`: shows only the byte length, never the token contents.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpaqueToken")
            .field("_len", &self.0.len())
            .finish()
    }
}

/// The live session minted during a successful bootstrap exchange.
///
/// Only one session exists per server run in practice — the bootstrap token is
/// single-use — so the CSRF key is effectively per-run.
#[derive(Clone)]
pub(crate) struct SessionState {
    /// Session id compared against the cookie value in constant time.
    pub(crate) session_id: OpaqueToken,
    /// Per-session key for the per-nonce CSRF HMAC.
    pub(crate) csrf_key: [u8; 32],
}

impl SessionState {
    /// Mint a fresh session: a random session id and a random CSRF key.
    pub(crate) fn generate() -> Self {
        let mut csrf_key = [0u8; 32];
        OsRng.fill_bytes(&mut csrf_key);
        Self {
            session_id: OpaqueToken::generate(),
            csrf_key,
        }
    }
}

/// In-memory authentication state for the server.
///
/// Held behind a single mutex; no async work happens while the guard is held.
pub(crate) struct AuthState {
    /// The single-use bootstrap token; `None` once consumed.
    pub(crate) bootstrap: Option<OpaqueToken>,
    /// The live session; `None` until a bootstrap exchange succeeds.
    pub(crate) session: Option<SessionState>,
}

impl AuthState {
    /// Create fresh auth state carrying the given single-use bootstrap token.
    pub(crate) fn new(bootstrap: OpaqueToken) -> Self {
        Self {
            bootstrap: Some(bootstrap),
            session: None,
        }
    }
}

/// Computes `hex(HMAC-SHA256(csrf_key, approval_nonce_bytes))`.
///
/// This is the value embedded in rendered pages and required back on POSTs. It
/// binds a CSRF value to a specific nonce so a value minted for one approval
/// cannot authorise an action on another.
pub(crate) fn compute_csrf(csrf_key: &[u8; 32], approval_nonce: &str) -> String {
    // `new_from_slice` fails only for a zero-length key; `&[u8; 32]` is always
    // 32 bytes, so initialisation is infallible here.
    #[allow(
        clippy::expect_used,
        reason = "HMAC key init with a 32-byte array is infallible"
    )]
    let mut mac = HmacSha256::new_from_slice(csrf_key)
        .expect("HMAC key init with a 32-byte array is infallible");
    mac.update(approval_nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verifies a submitted CSRF hex value against the recomputed HMAC for `nonce`.
///
/// Returns `true` only when the submitted value decodes to the exact 32-byte
/// HMAC of `approval_nonce` under `csrf_key`, compared in constant time.
pub(crate) fn verify_csrf(csrf_key: &[u8; 32], approval_nonce: &str, submitted_hex: &str) -> bool {
    let expected = compute_csrf(csrf_key, approval_nonce);
    if submitted_hex.len() != expected.len() {
        return false;
    }
    expected.as_bytes().ct_eq(submitted_hex.as_bytes()).into()
}

/// Extracts the session-cookie value from a `Cookie` request header, if present.
///
/// Parses the standard `name=value; name2=value2` cookie syntax and returns the
/// value of [`SESSION_COOKIE_NAME`]. Returns `None` when the header is absent,
/// non-ASCII, or does not carry the session cookie.
pub(crate) fn session_cookie_value(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=')
            && name.trim() == SESSION_COOKIE_NAME
        {
            return Some(value.trim().to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    #[test]
    fn opaque_token_hex_roundtrip() {
        let t = OpaqueToken::generate();
        let hex = t.to_hex();
        assert_eq!(hex.len(), 64);
        let parsed = OpaqueToken::from_hex(&hex).expect("roundtrip");
        assert!(t.ct_eq(&parsed));
    }

    #[test]
    fn opaque_token_from_hex_rejects_wrong_length() {
        assert!(OpaqueToken::from_hex("abcd").is_none());
        assert!(OpaqueToken::from_hex(&"a".repeat(63)).is_none());
        assert!(OpaqueToken::from_hex(&"a".repeat(65)).is_none());
    }

    #[test]
    fn opaque_token_from_hex_rejects_non_hex() {
        let mut s = "a".repeat(64);
        s.replace_range(10..11, "z");
        assert!(OpaqueToken::from_hex(&s).is_none());
    }

    #[test]
    fn opaque_token_distinct_values_differ() {
        let a = OpaqueToken::generate();
        let b = OpaqueToken::generate();
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn opaque_token_debug_is_redacted() {
        let t = OpaqueToken::generate();
        let rendered = format!("{t:?}");
        assert!(rendered.contains("_len"));
        assert!(!rendered.contains(&t.to_hex()));
    }

    #[test]
    fn csrf_roundtrip_verifies() {
        let key = [0x11u8; 32];
        let nonce = "AAAAAAAAAAAABBBBBBBBBB";
        let value = compute_csrf(&key, nonce);
        assert_eq!(value.len(), 64);
        assert!(verify_csrf(&key, nonce, &value));
    }

    #[test]
    fn csrf_rejects_wrong_nonce() {
        let key = [0x22u8; 32];
        let value = compute_csrf(&key, "nonce-one-000000000000");
        assert!(!verify_csrf(&key, "nonce-two-000000000000", &value));
    }

    #[test]
    fn csrf_rejects_wrong_key() {
        let nonce = "CCCCCCCCCCCCDDDDDDDDDD";
        let value = compute_csrf(&[0x33u8; 32], nonce);
        assert!(!verify_csrf(&[0x44u8; 32], nonce, &value));
    }

    #[test]
    fn csrf_rejects_malformed_value() {
        let key = [0x55u8; 32];
        let nonce = "EEEEEEEEEEEEFFFFFFFFFF";
        assert!(!verify_csrf(&key, nonce, "not-hex"));
        assert!(!verify_csrf(&key, nonce, ""));
    }

    #[test]
    fn session_cookie_value_parses_named_cookie() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("other=1; {SESSION_COOKIE_NAME}=deadbeef; last=2")
                .parse()
                .unwrap(),
        );
        assert_eq!(session_cookie_value(&headers).as_deref(), Some("deadbeef"));
    }

    #[test]
    fn session_cookie_value_absent_is_none() {
        let headers = axum::http::HeaderMap::new();
        assert!(session_cookie_value(&headers).is_none());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::COOKIE, "foo=bar".parse().unwrap());
        assert!(session_cookie_value(&headers).is_none());
    }
}
