//! Session and CSRF primitives for the remote-approval HTTP surface.
//!
//! Structurally the same design as the loopback approval-inbox server's
//! session model (`stellar-agent-approval-ui`'s private `auth` module): an
//! opaque, constant-time-compared session id in an `HttpOnly` cookie, plus a
//! per-nonce CSRF HMAC. Written fresh in this crate (the loopback crate's
//! module is private) rather than shared, with one deliberate difference:
//! there is no bootstrap-URL-token exchange here. The passkey login ceremony
//! itself establishes the session — a network-exposed listener cannot use a
//! bootstrap token embedded in a URL the operator would have to receive
//! out-of-band over an already-trusted channel, defeating the point of the
//! passkey ceremony.
//!
//! The session cookie is `HttpOnly; Secure; SameSite=Strict` — `Secure` is
//! added relative to the loopback server's cookie because this listener is
//! genuinely served over TLS to a non-`localhost` origin, where `Secure` is
//! both meaningful and required by modern browsers for `SameSite=Strict`
//! cross-context robustness.

use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit as _, Mac as _};
use rand_core::{OsRng, RngCore as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

/// Name of the session cookie set after a successful login ceremony.
pub const SESSION_COOKIE_NAME: &str = "stellar_agent_remote_approval_session";

/// Request header carrying the per-nonce CSRF value on state-changing POSTs.
pub const CSRF_HEADER_NAME: &str = "x-stellar-remote-approval-csrf";

/// Absolute session lifetime, independent of activity.
///
/// A session older than this is treated exactly like no session at all (see
/// [`SessionState::is_expired`] and its use in `crate::routes::require_session`)
/// — the operator must complete a fresh passkey login ceremony to keep
/// approving or rejecting actions. There is no idle-timeout renewal: the
/// clock starts at [`SessionState::generate`] and never resets.
pub const SESSION_ABSOLUTE_TTL: Duration = Duration::from_secs(30 * 60);

type HmacSha256 = Hmac<Sha256>;

/// An opaque 32-byte token sourced from `rand_core::OsRng`.
///
/// Comparison MUST use [`OpaqueToken::ct_eq`]; `==` is deliberately not
/// implemented. Raw bytes are never exposed via `Debug`.
#[derive(Clone)]
pub struct OpaqueToken([u8; 32]);

impl OpaqueToken {
    /// Generate a fresh 32-byte token from `rand_core::OsRng`.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Hex-encode the token (64 lowercase hex characters) for cookie use.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a 64-character hex string into a token.
    ///
    /// Returns `None` when the input is not exactly 64 hex characters.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
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

    /// Constant-time equality comparison.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl std::fmt::Debug for OpaqueToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpaqueToken")
            .field("_len", &self.0.len())
            .finish()
    }
}

/// A live session minted after a successful login ceremony.
#[derive(Clone)]
pub struct SessionState {
    /// Session id compared against the cookie value in constant time.
    pub session_id: OpaqueToken,
    /// Per-session key for the per-nonce CSRF HMAC.
    pub csrf_key: [u8; 32],
    /// Credential ID (base64url) of the operator this session authenticated
    /// as — threaded into `ApproverIdentity::PasskeyCredential` and the
    /// audit pseudonym for every action taken under this session.
    pub credential_id_b64url: String,
    /// When this session was minted — the anchor for [`Self::is_expired`].
    created_at: Instant,
}

impl SessionState {
    /// Mint a fresh session bound to `credential_id_b64url`, anchored at the
    /// current time.
    #[must_use]
    pub fn generate(credential_id_b64url: impl Into<String>) -> Self {
        Self::new_at(credential_id_b64url, Instant::now())
    }

    /// Mint a fresh session bound to `credential_id_b64url`, anchored at
    /// `created_at`.
    ///
    /// Test-only: lets a test construct an already-expired session
    /// deterministically, without depending on wall-clock sleeps. Never
    /// compiled into a production binary.
    #[must_use]
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn generate_at(credential_id_b64url: impl Into<String>, created_at: Instant) -> Self {
        Self::new_at(credential_id_b64url, created_at)
    }

    fn new_at(credential_id_b64url: impl Into<String>, created_at: Instant) -> Self {
        let mut csrf_key = [0u8; 32];
        OsRng.fill_bytes(&mut csrf_key);
        Self {
            session_id: OpaqueToken::generate(),
            csrf_key,
            credential_id_b64url: credential_id_b64url.into(),
            created_at,
        }
    }

    /// Returns `true` once [`SESSION_ABSOLUTE_TTL`] has elapsed since this
    /// session was minted.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= SESSION_ABSOLUTE_TTL
    }
}

/// Computes `hex(HMAC-SHA256(csrf_key, approval_nonce_bytes))`.
///
/// # Panics
///
/// Never panics: `HmacSha256::new_from_slice` only fails for a zero-length
/// key, and `csrf_key` is always exactly 32 bytes by its `[u8; 32]` type.
#[must_use]
pub fn compute_csrf(csrf_key: &[u8; 32], approval_nonce: &str) -> String {
    #[allow(
        clippy::expect_used,
        reason = "HMAC key init with a 32-byte array is infallible"
    )]
    let mut mac = HmacSha256::new_from_slice(csrf_key)
        .expect("HMAC key init with a 32-byte array is infallible");
    mac.update(approval_nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verifies a submitted CSRF hex value against the recomputed HMAC for
/// `nonce`, in constant time.
#[must_use]
pub fn verify_csrf(csrf_key: &[u8; 32], approval_nonce: &str, submitted_hex: &str) -> bool {
    let expected = compute_csrf(csrf_key, approval_nonce);
    if submitted_hex.len() != expected.len() {
        return false;
    }
    expected.as_bytes().ct_eq(submitted_hex.as_bytes()).into()
}

/// Extracts the session-cookie value from a `Cookie` request header, if
/// present.
#[must_use]
pub fn session_cookie_value(headers: &axum::http::HeaderMap) -> Option<String> {
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

/// Renders the `Set-Cookie` header value for a freshly-minted session.
///
/// `HttpOnly` (no JS access), `Secure` (TLS-only transmission — real over a
/// genuine network-exposed HTTPS origin), `SameSite=Strict` (never sent on
/// cross-site navigation), `Path=/`.
#[must_use]
pub fn session_set_cookie_header(session_id_hex: &str) -> String {
    format!("{SESSION_COOKIE_NAME}={session_id_hex}; HttpOnly; Secure; SameSite=Strict; Path=/")
}

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
    }

    #[test]
    fn opaque_token_distinct_values_differ() {
        let a = OpaqueToken::generate();
        let b = OpaqueToken::generate();
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn csrf_roundtrip_verifies() {
        let key = [0x11u8; 32];
        let nonce = "AAAAAAAAAAAABBBBBBBBBB";
        let value = compute_csrf(&key, nonce);
        assert!(verify_csrf(&key, nonce, &value));
    }

    #[test]
    fn csrf_rejects_wrong_nonce() {
        let key = [0x22u8; 32];
        let value = compute_csrf(&key, "nonce-one");
        assert!(!verify_csrf(&key, "nonce-two", &value));
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
    fn set_cookie_header_carries_secure_and_strict_flags() {
        let header = session_set_cookie_header("abc123");
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Strict"));
    }

    #[test]
    fn fresh_session_is_not_expired() {
        let session = SessionState::generate("cred-1");
        assert!(!session.is_expired());
    }

    #[test]
    fn session_past_absolute_ttl_is_expired() {
        let created_at = Instant::now() - SESSION_ABSOLUTE_TTL - Duration::from_secs(1);
        let session = SessionState::generate_at("cred-1", created_at);
        assert!(session.is_expired());
    }
}
