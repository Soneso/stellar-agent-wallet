//! Session and CSRF primitives for the approval-inbox and operator-enrollment
//! servers.
//!
//! Both loopback servers replace the WebAuthn bridge's URL-token-on-every-route
//! model with a one-time bootstrap-token exchange:
//!
//! - A 32-byte [`OpaqueToken`] bootstrap token is minted at server start and
//!   emitted once as `GET /bootstrap/<hex>`. On the first successful exchange
//!   it is consumed (single use) and a [`SessionState`] is minted: a session
//!   id, a per-session CSRF key, and a separate session proof.
//! - The session id travels in an `HttpOnly` cookie whose name carries a
//!   random per-listener suffix. Every other route requires that cookie,
//!   compared in constant time; absent, malformed, mismatched, and expired
//!   sessions collapse to the same "not found" posture.
//! - The session proof is delivered once, in the body of the successful
//!   bootstrap response, and the page's script keeps it in `sessionStorage`.
//!   Browser cookies are scoped to a host, not to a port, so another listener
//!   on the same loopback host name can receive the cookie; `sessionStorage`
//!   is scoped to the full origin (scheme, host and port), so that listener
//!   cannot read the proof. No route that a cookie alone authorizes ever
//!   returns the proof again.
//! - State-changing POSTs carry the proof in the `X-Session-Proof` header and
//!   `hex(HMAC-SHA256(csrf_key, nonce))` in the `X-Stellar-Approval-CSRF`
//!   header; both are compared in constant time.
//! - A session expires [`SESSION_IDLE_TIMEOUT`] after its last recorded
//!   activity or [`SESSION_ABSOLUTE_TIMEOUT`] after the bootstrap exchange,
//!   whichever comes first, measured on the monotonic clock. An expired
//!   session is cleared and never revived; the bootstrap token is already
//!   spent, so a new session needs a new server run. Only a request that
//!   passes the proof and CSRF checks records activity: cookie-only reads,
//!   background polls and failed attempts do not.
//!
//! A stolen cookie therefore cannot mutate, but it can still read what the
//! cookie authorizes until the session expires.
//!
//! All comparisons go through [`subtle::ConstantTimeEq`]; token bytes are never
//! logged and the [`OpaqueToken`] `Debug` impl is redacted.

use std::time::{Duration, Instant};

use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use hmac::{Hmac, KeyInit as _, Mac as _};
use rand_core::{OsRng, RngCore as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

/// Request header carrying the per-nonce CSRF value on state-changing POSTs.
pub(crate) const CSRF_HEADER_NAME: &str = "x-stellar-approval-csrf";

/// Request header carrying the session proof on state-changing POSTs.
pub(crate) const SESSION_PROOF_HEADER_NAME: &str = "x-session-proof";

/// Idle limit: a session with no recorded activity for this long expires.
pub(crate) const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Absolute limit: a session expires this long after the bootstrap exchange,
/// whatever its activity.
pub(crate) const SESSION_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(8 * 60 * 60);

/// `Max-Age` of the session cookie, in seconds: the absolute limit. The
/// server-side idle and absolute checks stay authoritative; the attribute
/// only stops a browser from presenting a cookie no server would accept.
pub(crate) const SESSION_COOKIE_MAX_AGE_SECS: u64 = SESSION_ABSOLUTE_TIMEOUT.as_secs();

type HmacSha256 = Hmac<Sha256>;

/// An opaque 32-byte token sourced from `rand_core::OsRng`.
///
/// Used for the single-use bootstrap token, the session id and the session
/// proof. Comparison MUST use [`OpaqueToken::ct_eq`]; `==` is deliberately not
/// implemented. Raw bytes are never exposed via `Debug`; hex is only for URL,
/// cookie and bootstrap-page emission.
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

/// Which loopback server a session belongs to.
///
/// Fixes the cookie-name prefix, the `sessionStorage` key the bootstrap page
/// stores the proof under, and the page the bootstrap page navigates to, so
/// the two servers never share a cookie name or a storage key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionPurpose {
    /// The approval inbox (`approve serve`).
    Inbox,
    /// The interactive operator enrollment (`approve operator enroll --interactive`).
    OperatorEnroll,
}

impl SessionPurpose {
    /// The cookie-name prefix; each listener appends a random suffix.
    fn cookie_name_prefix(self) -> &'static str {
        match self {
            Self::Inbox => "stellar_agent_approval_session_",
            Self::OperatorEnroll => "stellar_agent_operator_enroll_session_",
        }
    }

    /// The `sessionStorage` key holding the proof. The browser scripts read
    /// the same literal.
    pub(crate) fn proof_storage_key(self) -> &'static str {
        match self {
            Self::Inbox => "stellar-agent-approval-session-proof",
            Self::OperatorEnroll => "stellar-agent-operator-enroll-session-proof",
        }
    }

    /// The fixed page the bootstrap page navigates to once the proof is
    /// stored.
    pub(crate) fn landing_path(self) -> &'static str {
        match self {
            Self::Inbox => "/inbox",
            Self::OperatorEnroll => "/enroll",
        }
    }
}

/// A live session minted during a successful bootstrap exchange.
///
/// Only one session exists per server run: the bootstrap token is single-use,
/// so the CSRF key and the proof are per-run as well.
#[derive(Clone)]
pub(crate) struct SessionState {
    /// Session id compared against the cookie value in constant time.
    pub(crate) session_id: OpaqueToken,
    /// Per-session key for the per-nonce CSRF HMAC.
    pub(crate) csrf_key: [u8; 32],
    /// Origin-scoped proof required on every state-changing request. Leaves
    /// the server exactly once, in the successful bootstrap response.
    pub(crate) session_proof: OpaqueToken,
    /// When the bootstrap exchange minted this session; anchors the absolute
    /// limit.
    pub(crate) created_at: Instant,
    /// The last proof-and-CSRF-authorized request; anchors the idle limit.
    pub(crate) last_activity_at: Instant,
}

impl SessionState {
    /// Mint a fresh session at `now`: random session id, CSRF key and proof.
    pub(crate) fn generate(now: Instant) -> Self {
        let mut csrf_key = [0u8; 32];
        OsRng.fill_bytes(&mut csrf_key);
        Self {
            session_id: OpaqueToken::generate(),
            csrf_key,
            session_proof: OpaqueToken::generate(),
            created_at: now,
            last_activity_at: now,
        }
    }

    /// `true` once `now` reaches the idle deadline or the absolute deadline.
    ///
    /// A deadline that does not fit in an [`Instant`] counts as reached, so an
    /// arithmetic overflow fails closed.
    pub(crate) fn is_expired(&self, now: Instant) -> bool {
        let reached = |start: Instant, limit: Duration| {
            start
                .checked_add(limit)
                .is_none_or(|deadline| now >= deadline)
        };
        reached(self.last_activity_at, SESSION_IDLE_TIMEOUT)
            || reached(self.created_at, SESSION_ABSOLUTE_TIMEOUT)
    }

    /// `true` iff `submitted` is the hex form of this session's proof,
    /// compared in constant time.
    pub(crate) fn verify_proof(&self, submitted: &str) -> bool {
        OpaqueToken::from_hex(submitted).is_some_and(|token| self.session_proof.ct_eq(&token))
    }
}

/// In-memory authentication state for one loopback server.
///
/// Held behind a single mutex; no async work happens while the guard is held.
/// Expiry checks and activity updates both happen under that mutex.
pub(crate) struct AuthState {
    /// The single-use bootstrap token; `None` once consumed.
    pub(crate) bootstrap: Option<OpaqueToken>,
    /// The live session; `None` until a bootstrap exchange succeeds, and
    /// `None` again once it expires.
    pub(crate) session: Option<SessionState>,
    /// The session cookie name: the purpose prefix plus a random suffix, so
    /// two listeners on one host name never overwrite each other's cookie.
    cookie_name: String,
    /// The server this state belongs to.
    purpose: SessionPurpose,
    /// The monotonic time source for expiry.
    clock: SessionClock,
}

impl AuthState {
    /// Create fresh auth state carrying the given single-use bootstrap token.
    pub(crate) fn new(bootstrap: OpaqueToken, purpose: SessionPurpose) -> Self {
        Self::with_clock(bootstrap, purpose, SessionClock::system())
    }

    /// [`Self::new`] with an explicit clock.
    pub(crate) fn with_clock(
        bootstrap: OpaqueToken,
        purpose: SessionPurpose,
        clock: SessionClock,
    ) -> Self {
        let mut suffix = [0u8; 8];
        OsRng.fill_bytes(&mut suffix);
        Self {
            bootstrap: Some(bootstrap),
            session: None,
            cookie_name: format!("{}{}", purpose.cookie_name_prefix(), hex::encode(suffix)),
            purpose,
            clock,
        }
    }

    /// The current monotonic time from this state's clock.
    pub(crate) fn now(&self) -> Instant {
        self.clock.now()
    }

    /// The session cookie name this listener sets and reads.
    #[cfg(test)]
    pub(crate) fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    /// The server this state belongs to.
    pub(crate) fn purpose(&self) -> SessionPurpose {
        self.purpose
    }

    /// Exchanges the bootstrap token for a fresh session at `now`.
    ///
    /// Returns the new session only when `submitted_hex` matches the unspent
    /// bootstrap token in constant time. The token is consumed by that first
    /// match, so every later exchange returns `None`.
    pub(crate) fn exchange_bootstrap(
        &mut self,
        submitted_hex: &str,
        now: Instant,
    ) -> Option<SessionState> {
        let submitted = OpaqueToken::from_hex(submitted_hex)?;
        let matches = self
            .bootstrap
            .as_ref()
            .is_some_and(|stored| stored.ct_eq(&submitted));
        if !matches {
            return None;
        }
        self.bootstrap = None;
        let session = SessionState::generate(now);
        self.session = Some(session.clone());
        Some(session)
    }

    /// Recovers the live session iff `headers` carry its cookie and it has
    /// not expired at `now`.
    ///
    /// An expired session is cleared here, whoever asks, and never revived.
    /// Reading the session never records activity.
    pub(crate) fn require_session(
        &mut self,
        headers: &HeaderMap,
        now: Instant,
    ) -> Option<SessionState> {
        let session = self.session.as_ref()?;
        if session.is_expired(now) {
            self.session = None;
            return None;
        }
        let cookie = session_cookie_value(headers, &self.cookie_name)?;
        let submitted = OpaqueToken::from_hex(&cookie)?;
        session
            .session_id
            .ct_eq(&submitted)
            .then(|| session.clone())
    }

    /// Records activity at `now` for the session identified by `session_id`.
    ///
    /// Returns `false`, recording nothing, when no session is live, the id
    /// does not match, or the session has expired by `now` (it is then
    /// cleared). Activity moves only the idle deadline, never the absolute
    /// one.
    pub(crate) fn record_activity(&mut self, session_id: &OpaqueToken, now: Instant) -> bool {
        let Some(session) = self.session.as_mut() else {
            return false;
        };
        if !session.session_id.ct_eq(session_id) {
            return false;
        }
        if session.is_expired(now) {
            self.session = None;
            return false;
        }
        session.last_activity_at = session.last_activity_at.max(now);
        true
    }

    /// The `Set-Cookie` value for `session`: `HttpOnly; SameSite=Strict;
    /// Path=/` and a `Max-Age` of the absolute limit.
    pub(crate) fn set_cookie_value(&self, session: &SessionState) -> String {
        format!(
            "{}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_COOKIE_MAX_AGE_SECS}",
            self.cookie_name,
            session.session_id.to_hex()
        )
    }
}

/// Monotonic time source for session expiry.
///
/// Production state reads [`Instant::now`]. Unit tests substitute a manual
/// clock so the idle and absolute boundaries are exercised exactly, without
/// sleeping and without subtracting from an [`Instant`] near the platform's
/// epoch.
#[derive(Clone, Default)]
pub(crate) struct SessionClock {
    #[cfg(test)]
    manual: Option<std::sync::Arc<std::sync::Mutex<Instant>>>,
}

impl SessionClock {
    /// The system monotonic clock.
    pub(crate) fn system() -> Self {
        Self::default()
    }

    /// The current time on this clock.
    pub(crate) fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(manual) = &self.manual {
            return *manual
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        Instant::now()
    }

    /// A manual clock starting at the current instant.
    #[cfg(test)]
    pub(crate) fn manual() -> Self {
        Self {
            manual: Some(std::sync::Arc::new(std::sync::Mutex::new(Instant::now()))),
        }
    }

    /// Moves a manual clock forward by `by`.
    #[cfg(test)]
    pub(crate) fn advance(&self, by: Duration) {
        #[allow(clippy::expect_used, reason = "test-only clock on a manual instance")]
        let manual = self.manual.as_ref().expect("advance needs a manual clock");
        let mut now = manual
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *now += by;
    }
}

/// A `403 Forbidden` with the `session_proof_invalid` JSON body.
pub(crate) fn session_proof_invalid() -> Response {
    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({"error": "session_proof_invalid"}).to_string(),
    )
        .into_response()
}

/// Verifies the `X-Session-Proof` header against `session`'s proof.
///
/// A missing, non-ASCII, malformed or wrong proof yields the
/// `session_proof_invalid` response.
#[allow(
    clippy::result_large_err,
    reason = "the Err variant is the ready-to-return axum Response for the proof rejection; boxing would only add an allocation on the reject path"
)]
pub(crate) fn require_session_proof(
    session: &SessionState,
    headers: &HeaderMap,
) -> Result<(), Response> {
    let submitted = headers
        .get(SESSION_PROOF_HEADER_NAME)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(session_proof_invalid)?;
    if session.verify_proof(submitted) {
        Ok(())
    } else {
        Err(session_proof_invalid())
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

/// Extracts the value of the cookie named `cookie_name` from a `Cookie`
/// request header, if present.
///
/// Parses the standard `name=value; name2=value2` cookie syntax. Returns
/// `None` when the header is absent, non-ASCII, or does not carry that cookie.
pub(crate) fn session_cookie_value(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=')
            && name.trim() == cookie_name
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
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "other=1; stellar_agent_approval_session_00=deadbeef; last=2"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            session_cookie_value(&headers, "stellar_agent_approval_session_00").as_deref(),
            Some("deadbeef")
        );
        assert!(session_cookie_value(&headers, "stellar_agent_approval_session_01").is_none());
    }

    #[test]
    fn session_cookie_value_absent_is_none() {
        let headers = HeaderMap::new();
        assert!(session_cookie_value(&headers, "name").is_none());
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "foo=bar".parse().unwrap());
        assert!(session_cookie_value(&headers, "name").is_none());
    }

    // ── Session lifetime ────────────────────────────────────────────────

    /// One second, the resolution the boundary tests step by.
    const TICK: Duration = Duration::from_secs(1);

    /// An auth state with a live session minted at the manual clock's start,
    /// and the cookie header that presents it.
    fn live_session() -> (AuthState, SessionClock, HeaderMap, SessionState) {
        let clock = SessionClock::manual();
        let bootstrap = OpaqueToken::generate();
        let bootstrap_hex = bootstrap.to_hex();
        let mut auth = AuthState::with_clock(bootstrap, SessionPurpose::Inbox, clock.clone());
        let session = auth
            .exchange_bootstrap(&bootstrap_hex, clock.now())
            .expect("the unspent bootstrap token exchanges");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{}={}", auth.cookie_name(), session.session_id.to_hex())
                .parse()
                .unwrap(),
        );
        (auth, clock, headers, session)
    }

    /// The idle limit holds one tick before the deadline and refuses exactly
    /// at it; the refusal clears the session for good.
    #[test]
    fn idle_expiry_boundary() {
        let (mut auth, clock, headers, _session) = live_session();
        clock.advance(SESSION_IDLE_TIMEOUT - TICK);
        assert!(auth.require_session(&headers, clock.now()).is_some());
        clock.advance(TICK);
        assert!(auth.require_session(&headers, clock.now()).is_none());
        assert!(auth.session.is_none(), "an expired session is cleared");
        // Going back in time cannot revive it.
        assert!(auth.require_session(&headers, auth.now() - TICK).is_none());
    }

    /// Recorded activity moves the idle deadline: activity one tick before
    /// the idle limit keeps the session for another full idle period.
    #[test]
    fn activity_moves_only_the_idle_deadline() {
        let (mut auth, clock, headers, session) = live_session();
        clock.advance(SESSION_IDLE_TIMEOUT - TICK);
        assert!(auth.record_activity(&session.session_id, clock.now()));
        clock.advance(SESSION_IDLE_TIMEOUT - TICK);
        assert!(auth.require_session(&headers, clock.now()).is_some());
        clock.advance(TICK);
        assert!(auth.require_session(&headers, clock.now()).is_none());
    }

    /// Reading the session is not activity: a session read every minute
    /// still expires at the idle deadline counted from the bootstrap.
    #[test]
    fn reading_the_session_does_not_extend_idle() {
        let (mut auth, clock, headers, _session) = live_session();
        for _ in 0..14 {
            clock.advance(Duration::from_secs(60));
            assert!(auth.require_session(&headers, clock.now()).is_some());
        }
        clock.advance(Duration::from_secs(60));
        assert!(auth.require_session(&headers, clock.now()).is_none());
    }

    /// The absolute limit holds one tick before the deadline and refuses
    /// exactly at it, however often activity was recorded.
    #[test]
    fn absolute_expiry_boundary() {
        let (mut auth, clock, headers, session) = live_session();
        let step = Duration::from_secs(10 * 60);
        let mut elapsed = Duration::ZERO;
        while elapsed + step < SESSION_ABSOLUTE_TIMEOUT {
            clock.advance(step);
            elapsed += step;
            assert!(auth.record_activity(&session.session_id, clock.now()));
        }
        clock.advance(SESSION_ABSOLUTE_TIMEOUT - elapsed - TICK);
        assert!(auth.record_activity(&session.session_id, clock.now()));
        assert!(auth.require_session(&headers, clock.now()).is_some());
        clock.advance(TICK);
        assert!(!auth.record_activity(&session.session_id, clock.now()));
        assert!(auth.require_session(&headers, clock.now()).is_none());
        assert!(auth.session.is_none());
    }

    #[test]
    fn record_activity_refuses_a_foreign_session_id() {
        let (mut auth, clock, _headers, session) = live_session();
        clock.advance(TICK);
        assert!(!auth.record_activity(&OpaqueToken::generate(), clock.now()));
        let live = auth.session.as_ref().unwrap();
        assert_eq!(live.last_activity_at, session.last_activity_at);
    }

    #[test]
    fn bootstrap_exchanges_once() {
        let clock = SessionClock::manual();
        let bootstrap = OpaqueToken::generate();
        let hex = bootstrap.to_hex();
        let mut auth = AuthState::with_clock(bootstrap, SessionPurpose::Inbox, clock.clone());
        assert!(
            auth.exchange_bootstrap(&"0".repeat(64), clock.now())
                .is_none()
        );
        assert!(auth.exchange_bootstrap(&hex, clock.now()).is_some());
        assert!(auth.exchange_bootstrap(&hex, clock.now()).is_none());
    }

    #[test]
    fn proof_verification_is_exact() {
        let session = SessionState::generate(Instant::now());
        assert!(session.verify_proof(&session.session_proof.to_hex()));
        assert!(session.verify_proof(&session.session_proof.to_hex().to_uppercase()));
        assert!(!session.verify_proof(&session.session_id.to_hex()));
        assert!(!session.verify_proof(""));
        assert!(!session.verify_proof("not-hex"));
        assert!(!session.verify_proof(&OpaqueToken::generate().to_hex()));
    }

    #[test]
    fn require_session_proof_reads_the_proof_header() {
        let session = SessionState::generate(Instant::now());
        let mut headers = HeaderMap::new();
        assert!(require_session_proof(&session, &headers).is_err());
        headers.insert(
            SESSION_PROOF_HEADER_NAME,
            OpaqueToken::generate().to_hex().parse().unwrap(),
        );
        assert!(require_session_proof(&session, &headers).is_err());
        headers.insert(
            SESSION_PROOF_HEADER_NAME,
            session.session_proof.to_hex().parse().unwrap(),
        );
        assert!(require_session_proof(&session, &headers).is_ok());
    }

    /// Two listeners never share a cookie name, and the two servers use
    /// distinct prefixes and storage keys.
    #[test]
    fn cookie_names_are_distinct_per_listener_and_purpose() {
        let a = AuthState::new(OpaqueToken::generate(), SessionPurpose::Inbox);
        let b = AuthState::new(OpaqueToken::generate(), SessionPurpose::Inbox);
        let e = AuthState::new(OpaqueToken::generate(), SessionPurpose::OperatorEnroll);
        assert_ne!(a.cookie_name(), b.cookie_name());
        assert!(
            a.cookie_name()
                .starts_with("stellar_agent_approval_session_")
        );
        assert!(
            e.cookie_name()
                .starts_with("stellar_agent_operator_enroll_session_")
        );
        assert_ne!(
            SessionPurpose::Inbox.proof_storage_key(),
            SessionPurpose::OperatorEnroll.proof_storage_key()
        );
    }
}
