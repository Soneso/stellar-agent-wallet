//! SEP-10 JWT session holder with decoded claim accessors.
//!
//! [`Sep10Session`] holds the decoded claims from a server-issued JWT. Parsing
//! is intentionally minimal: the crate hand-rolls JWT segment splitting +
//! base64-url decode + `serde_json` claim extraction WITHOUT signature
//! verification.
//!
//! # No JWT signature verification
//!
//! The JWT is issued by the SEP-10 server over HTTPS. The client trusts the JWT
//! issuer via TLS: the server's TLS certificate authenticates the connection.
//! Signature verification inside the client would require the server's HS256 /
//! RS256 key to be known to the client, which contradicts the spec's design
//! (SEP-10 v3.4.1).
//!
//! # `sub` claim format
//!
//! The `sub` claim has three possible formats (SEP-10 v3.4.1):
//! 1. Plain G-key: `"G...WXYZ"` — use [`Sep10Session::account_id`].
//! 2. G-key with memo: `"G...WXYZ:17509749319012223907"` — use
//!    [`Sep10Session::account_id`] for the G-key prefix and
//!    [`Sep10Session::memo`] for the u64 memo.
//! 3. Muxed M-key: `"M..."` — use [`Sep10Session::account_id`] directly
//!    (full muxed strkey).

use base64::{
    Engine as _, alphabet,
    engine::{GeneralPurpose, general_purpose::NO_PAD},
};
use serde::Deserialize;

use crate::error::Sep10Error;

/// Base64 URL-safe no-padding engine for JWT segment decoding.
///
/// JWT uses URL-safe base64 without padding per RFC 7519 §2.
static BASE64_URL_NO_PAD: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, NO_PAD);

/// A parsed and decoded SEP-10 JWT session.
///
/// Constructed via [`Sep10Session::parse`]. Fields reflect the decoded JWT
/// claims as specified in SEP-10 v3.4.1. The raw JWT string is retained so
/// callers can forward it to downstream anchors.
#[derive(Clone)]
pub struct Sep10Session {
    /// The raw JWT string, retained for forwarding to downstream anchor
    /// endpoints that require bearer-token authentication.
    pub jwt: String,

    /// The `sub` (subject) claim — identifies the authenticated Stellar account.
    ///
    /// Format per SEP-10 v3.4.1:
    /// - Plain G-key: `"G..."`
    /// - G-key with memo: `"G...:17509749319012223907"`
    /// - Muxed M-key: `"M..."`
    ///
    /// Use [`Sep10Session::account_id`] to extract the account portion and
    /// [`Sep10Session::memo`] to extract the memo if present.
    pub sub: String,

    /// The `iss` (issuer) claim — URI identifying the SEP-10 server.
    pub iss: String,

    /// The `iat` (issued-at) claim — Unix timestamp of JWT issuance.
    pub iat: u64,

    /// The `exp` (expiration) claim — Unix timestamp after which the JWT
    /// must not be accepted.
    pub exp: u64,

    /// The `client_domain` claim — present if the challenge included a
    /// `client_domain` ManageData operation.
    pub client_domain: Option<String>,
}

impl std::fmt::Debug for Sep10Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sep10Session")
            .field("jwt", &redact_jwt_for_debug(&self.jwt))
            .field("sub", &self.sub)
            .field("iss", &self.iss)
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .field("client_domain", &self.client_domain)
            .finish()
    }
}

fn redact_jwt_for_debug(jwt: &str) -> String {
    // chars()-based slicing so that Debug never panics on non-ASCII JWT values.
    // A JWT with ≤ 16 chars cannot yield a meaningful first-8-last-8 redaction.
    let char_count = jwt.chars().count();
    if char_count <= 16 {
        return "<redacted>".to_owned();
    }
    let first: String = jwt.chars().take(8).collect();
    let last: String = jwt
        .chars()
        .rev()
        .take(8)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{first}...{last}")
}

/// The longest token, in bytes, that [`Sep10Session::parse`] accepts.
///
/// A SEP-10 token carries a handful of short claims; the bound keeps a
/// server-chosen token from growing without limit on its way into a tool
/// result.
const MAX_JWT_BYTES: usize = 8192;

/// The detail of a token that is not in compact JWT form.
const NOT_A_COMPACT_JWT: &str = "token answer is not a compact JWT";

/// Whether `segment` holds only base64url characters (`A-Z`, `a-z`, `0-9`,
/// `-`, `_`), the alphabet of a compact JWT segment.
fn is_base64url_segment(segment: &str) -> bool {
    segment
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Internal serde struct for JWT payload claim extraction.
///
/// All fields are `Option` except `sub`, `iss`, `iat`, `exp` which are
/// required by SEP-10 v3.4.1.
#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: String,
    iss: String,
    iat: u64,
    exp: u64,
    client_domain: Option<String>,
}

impl Sep10Session {
    /// Parses a SEP-10 JWT and decodes its claims.
    ///
    /// Splits the JWT on `'.'`, base64-url-decodes the middle (payload) segment,
    /// and extracts `sub`, `iss`, `iat`, `exp`, and optional `client_domain`
    /// claims via `serde_json`.
    ///
    /// Does NOT verify the JWT signature. The trust model assumes the JWT was
    /// received over a TLS-authenticated connection from the SEP-10 server:
    /// the server's TLS certificate authenticates the channel, and the JWT
    /// content is trusted because the channel is trusted. This method must not
    /// be called with JWTs obtained from any source that is not a direct
    /// TLS-authenticated SEP-10 server response.
    ///
    /// The token must be in compact form: at most 8192 bytes, a
    /// non-empty header and payload segment, and only base64url characters in
    /// every segment. The stored token therefore holds only those characters
    /// and the two dots.
    ///
    /// # Errors
    ///
    /// - [`Sep10Error::JwtParseError`] with the detail `token answer is not a
    ///   compact JWT` if the token is longer than 8192 bytes, has an
    ///   empty header or payload segment, or has a character outside the
    ///   base64url alphabet in any segment.
    /// - [`Sep10Error::JwtParseError`] if the JWT does not have exactly 3
    ///   base64-separated segments (header.payload.signature).
    /// - [`Sep10Error::JwtParseError`] if the payload segment cannot be
    ///   base64-url-decoded.
    /// - [`Sep10Error::JwtParseError`] if the payload is not valid UTF-8 JSON.
    /// - [`Sep10Error::JwtParseError`] if required claims (`sub`, `iss`, `iat`,
    ///   `exp`) are missing or have wrong types.
    /// - [`Sep10Error::JwtParseError`] if the `sub` claim contains a `:`
    ///   separator but the portion after it is not a valid `u64` memo.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_sep10::Sep10Session;
    ///
    /// // Construct a minimal valid JWT (header.payload.signature).
    /// let payload_json = r#"{"sub":"GABCDEFG","iss":"https://example.com","iat":1000,"exp":2000}"#;
    /// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    /// let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    /// let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    /// let jwt = format!("{}.{}.fakesignature", header_b64, payload_b64);
    ///
    /// let session = Sep10Session::parse(&jwt).unwrap();
    /// assert_eq!(session.sub, "GABCDEFG");
    /// assert_eq!(session.iss, "https://example.com");
    /// assert_eq!(session.exp, 2000);
    /// assert!(!session.is_expired(1500));
    /// assert!(session.is_expired(2001));
    /// ```
    pub fn parse(jwt: &str) -> Result<Self, Sep10Error> {
        if jwt.len() > MAX_JWT_BYTES {
            return Err(Sep10Error::JwtParseError {
                detail: NOT_A_COMPACT_JWT.to_owned(),
            });
        }
        // Split into exactly 3 segments: header.payload.signature.
        let parts: Vec<&str> = jwt.splitn(4, '.').collect();
        if parts.len() != 3 {
            return Err(Sep10Error::JwtParseError {
                detail: format!(
                    "JWT must have exactly 3 dot-separated segments; got {}",
                    parts.len()
                ),
            });
        }
        // The signature segment may be empty (an unsecured JWT); the header
        // and the payload may not.
        if parts[0].is_empty()
            || parts[1].is_empty()
            || !parts.iter().all(|segment| is_base64url_segment(segment))
        {
            return Err(Sep10Error::JwtParseError {
                detail: NOT_A_COMPACT_JWT.to_owned(),
            });
        }
        let payload_b64 = parts[1];

        // Base64-url decode the payload segment.
        let payload_bytes =
            BASE64_URL_NO_PAD
                .decode(payload_b64)
                .map_err(|e| Sep10Error::JwtParseError {
                    detail: format!("JWT payload base64-url decode failed: {e}"),
                })?;

        // Parse the JSON payload into JwtClaims.
        let claims: JwtClaims =
            serde_json::from_slice(&payload_bytes).map_err(|e| Sep10Error::JwtParseError {
                detail: format!("JWT payload JSON parse failed: {e}"),
            })?;

        // Validate the `sub` claim format.
        // When `sub` contains a `:` separator the portion after it must be a
        // valid `u64` memo. Silent `None` from a malformed memo would
        // mis-bind the session to the wrong account.
        if let Some(colon_idx) = claims.sub.find(':') {
            let memo_str = &claims.sub[colon_idx + 1..];
            memo_str
                .parse::<u64>()
                .map_err(|_| Sep10Error::JwtParseError {
                    detail: format!("malformed memo in sub claim: {memo_str:?} is not a valid u64"),
                })?;
        }

        Ok(Self {
            jwt: jwt.to_owned(),
            sub: claims.sub,
            iss: claims.iss,
            iat: claims.iat,
            exp: claims.exp,
            client_domain: claims.client_domain,
        })
    }

    /// Returns `true` if the session has expired at `now_unix`.
    ///
    /// Per RFC 7519 §4.1.4: the JWT must not be accepted on or after the `exp`
    /// time. Returns `true` when `now_unix >= self.exp`.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_sep10::Sep10Session;
    ///
    /// let payload = r#"{"sub":"GABC","iss":"https://example.com","iat":1000,"exp":2000}"#;
    /// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    /// let header = URL_SAFE_NO_PAD.encode("{}");
    /// let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    /// let jwt = format!("{}.{}.sig", header, payload_b64);
    /// let session = Sep10Session::parse(&jwt).unwrap();
    ///
    /// assert!(!session.is_expired(1999));
    /// assert!(session.is_expired(2000));
    /// assert!(session.is_expired(9999));
    /// ```
    #[must_use]
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.exp
    }

    /// Returns the Stellar account identifier from the `sub` claim.
    ///
    /// Handles all three `sub` formats from SEP-10 v3.4.1:
    ///
    /// - Plain G-key (`"G..."`) — returns the full `sub`.
    /// - G-key with memo (`"G...:17509749319012223907"`) — returns the G-key
    ///   prefix (before the first `:`).
    /// - Muxed M-key (`"M..."`) — returns the full `sub` (M-keys encode the
    ///   memo in the strkey itself; there is no `:` separator).
    ///
    /// The returned account is the server-issued `sub` claim. It is validated
    /// only for memo format (`:` separator); strict strkey validation is
    /// intentionally not applied here, matching the TLS-trust model for JWT
    /// parsing (see [`Sep10Session::parse`]).
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_sep10::Sep10Session;
    /// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    ///
    /// // Plain G-key
    /// let p = r#"{"sub":"GABC","iss":"https://x.com","iat":0,"exp":9999}"#;
    /// let b64 = URL_SAFE_NO_PAD.encode(p);
    /// let jwt = format!("{}.{}.sig", URL_SAFE_NO_PAD.encode("{}"), b64);
    /// let s = Sep10Session::parse(&jwt).unwrap();
    /// assert_eq!(s.account_id(), "GABC");
    ///
    /// // G-key with memo
    /// let p2 = r#"{"sub":"GABC:12345","iss":"https://x.com","iat":0,"exp":9999}"#;
    /// let b64_2 = URL_SAFE_NO_PAD.encode(p2);
    /// let jwt2 = format!("{}.{}.sig", URL_SAFE_NO_PAD.encode("{}"), b64_2);
    /// let s2 = Sep10Session::parse(&jwt2).unwrap();
    /// assert_eq!(s2.account_id(), "GABC");
    /// assert_eq!(s2.memo(), Some(12345));
    /// ```
    #[must_use]
    pub fn account_id(&self) -> &str {
        // If sub contains ':', return the prefix (G-key with memo case).
        // M-keys do not contain ':', so they are returned as-is.
        match self.sub.find(':') {
            Some(idx) => &self.sub[..idx],
            None => &self.sub,
        }
    }

    /// Returns the numeric memo from the `sub` claim, if present.
    ///
    /// The memo is present only when `sub` is in the `"G...:MEMO"` format.
    /// M-key subjects do not carry a separate memo (the memo is encoded in
    /// the M-key ID).
    ///
    /// Returns `None` if there is no `:` separator. The memo portion is
    /// guaranteed to be a valid `u64` because [`Sep10Session::parse`] rejects
    /// malformed memo values at construction time.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_sep10::Sep10Session;
    /// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    ///
    /// let p = r#"{"sub":"GABC:17509749319012223907","iss":"https://x.com","iat":0,"exp":9999}"#;
    /// let b64 = URL_SAFE_NO_PAD.encode(p);
    /// let jwt = format!("{}.{}.sig", URL_SAFE_NO_PAD.encode("{}"), b64);
    /// let s = Sep10Session::parse(&jwt).unwrap();
    /// assert_eq!(s.memo(), Some(17_509_749_319_012_223_907));
    /// ```
    #[must_use]
    pub fn memo(&self) -> Option<u64> {
        let colon_idx = self.sub.find(':')?;
        self.sub[colon_idx + 1..].parse::<u64>().ok()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    fn build_jwt(sub: &str, exp: u64) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = serde_json::json!({
            "sub": sub,
            "iss": "https://testanchor.stellar.org",
            "iat": 1_700_000_000u64,
            "exp": exp,
        })
        .to_string();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
        format!("{header}.{payload_b64}.fakesignature")
    }

    fn build_jwt_with_client_domain(sub: &str, exp: u64, client_domain: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = serde_json::json!({
            "sub": sub,
            "iss": "https://testanchor.stellar.org",
            "iat": 1_700_000_000u64,
            "exp": exp,
            "client_domain": client_domain,
        })
        .to_string();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
        format!("{header}.{payload_b64}.fakesignature")
    }

    // ── Plain G-key sub ───────────────────────────────────────────────────────

    #[test]
    fn parse_plain_g_key_sub() {
        let jwt = build_jwt("GABCDEFGHIJKLMNOP", 9_999_999_999);
        let session = Sep10Session::parse(&jwt).unwrap();
        assert_eq!(session.sub, "GABCDEFGHIJKLMNOP");
        assert_eq!(session.account_id(), "GABCDEFGHIJKLMNOP");
        assert_eq!(session.memo(), None);
        assert_eq!(session.iss, "https://testanchor.stellar.org");
        assert!(!session.is_expired(1_700_000_001));
    }

    // ── G-key with memo sub ───────────────────────────────────────────────────

    #[test]
    fn parse_g_key_with_memo_sub() {
        let jwt = build_jwt("GABC:17509749319012223907", 9_999_999_999);
        let session = Sep10Session::parse(&jwt).unwrap();
        assert_eq!(session.sub, "GABC:17509749319012223907");
        assert_eq!(session.account_id(), "GABC");
        assert_eq!(session.memo(), Some(17_509_749_319_012_223_907u64));
    }

    // ── Muxed M-key sub ───────────────────────────────────────────────────────

    #[test]
    fn parse_muxed_m_key_sub() {
        // M-keys don't have ':' separators — account_id returns the full M-key.
        let muxed_key =
            "MAAAAAAAAAAAAAB7BQ2L7E2W3YWBWNZN3V7JQUQPKGDM7GV7V72J3GNYFQ4MAAAAAAAAAPC2L2ZFK4";
        let jwt = build_jwt(muxed_key, 9_999_999_999);
        let session = Sep10Session::parse(&jwt).unwrap();
        assert_eq!(session.account_id(), muxed_key);
        assert_eq!(session.memo(), None);
    }

    // ── Expiry detection ──────────────────────────────────────────────────────

    #[test]
    fn expired_session_detected() {
        let jwt = build_jwt("GABC", 1_000);
        let session = Sep10Session::parse(&jwt).unwrap();
        assert!(session.is_expired(1_000), "at exp boundary must be expired");
        assert!(session.is_expired(1_001), "past exp must be expired");
        assert!(!session.is_expired(999), "before exp must not be expired");
    }

    // ── client_domain claim ───────────────────────────────────────────────────

    #[test]
    fn parse_client_domain_claim() {
        let jwt = build_jwt_with_client_domain("GABC", 9_999_999_999, "client.example.com");
        let session = Sep10Session::parse(&jwt).unwrap();
        assert_eq!(session.client_domain, Some("client.example.com".to_owned()));
    }

    #[test]
    fn no_client_domain_when_absent() {
        let jwt = build_jwt("GABC", 9_999_999_999);
        let session = Sep10Session::parse(&jwt).unwrap();
        assert_eq!(session.client_domain, None);
    }

    // ── Malformed JWT rejection ───────────────────────────────────────────────

    #[test]
    fn reject_malformed_jwt_two_segments() {
        let err = Sep10Session::parse("header.payload").unwrap_err();
        assert!(
            matches!(err, Sep10Error::JwtParseError { .. }),
            "expected JwtParseError got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.jwt_parse_error");
    }

    #[test]
    fn reject_malformed_jwt_non_base64_payload() {
        let err = Sep10Session::parse("header.!!!invalid_base64!!!.sig").unwrap_err();
        assert!(
            matches!(
                err,
                Sep10Error::JwtParseError { ref detail }
                    if detail == "token answer is not a compact JWT"
            ),
            "expected the compact-JWT refusal, got {err:?}"
        );
    }

    /// A payload segment made only of base64url characters that still does
    /// not decode (a single character cannot encode a byte) is refused by
    /// the decoder, not by the alphabet check.
    #[test]
    fn payload_in_the_alphabet_that_does_not_decode_is_refused() {
        let err = Sep10Session::parse("aGVhZA.A.sig").unwrap_err();
        assert!(
            matches!(
                err,
                Sep10Error::JwtParseError { ref detail }
                    if detail.starts_with("JWT payload base64-url decode failed")
            ),
            "expected the payload decode refusal, got {err:?}"
        );
    }

    /// A token whose signature segment holds a control character is refused
    /// with the fixed text; a valid token with an empty signature passes.
    #[test]
    fn token_with_a_non_base64url_segment_is_refused() {
        let valid = build_jwt("GABC", 9_999_999_999);
        let (head, _signature) = valid.rsplit_once('.').unwrap();
        for bad in [
            format!("{head}.sig\u{1b}[2Jnature"),
            format!("{head}.sig nature"),
            format!("{head}.sig+/="),
            format!("{head}.sig\u{e9}"),
            format!("hd\u{202e}r.{}", valid.split('.').nth(1).unwrap()) + ".sig",
        ] {
            let err = Sep10Session::parse(&bad).unwrap_err();
            assert!(
                matches!(
                    err,
                    Sep10Error::JwtParseError { ref detail }
                        if detail == "token answer is not a compact JWT"
                ),
                "{bad:?}: {err:?}"
            );
        }
        let header = valid.split('.').next().unwrap();
        let payload = valid.split('.').nth(1).unwrap();
        for empty in [
            format!(".{payload}.sig"),
            format!("{header}..sig"),
            "..".to_owned(),
        ] {
            let err = Sep10Session::parse(&empty).unwrap_err();
            assert!(
                matches!(
                    err,
                    Sep10Error::JwtParseError { ref detail }
                        if detail == "token answer is not a compact JWT"
                ),
                "{empty:?}: {err:?}"
            );
        }
        let unsigned = format!("{head}.");
        assert_eq!(Sep10Session::parse(&unsigned).unwrap().sub, "GABC");
    }

    /// A token of more than 8192 bytes is refused with the fixed text, even
    /// when its segments are well formed; a token at the bound is parsed.
    #[test]
    fn token_over_8192_bytes_is_refused() {
        let valid = build_jwt("GABC", 9_999_999_999);
        let (head, _signature) = valid.rsplit_once('.').unwrap();
        let at_bound = format!("{head}.{}", "s".repeat(MAX_JWT_BYTES - head.len() - 1));
        assert_eq!(at_bound.len(), MAX_JWT_BYTES);
        assert!(Sep10Session::parse(&at_bound).is_ok());

        let over = format!("{at_bound}s");
        let err = Sep10Session::parse(&over).unwrap_err();
        assert!(
            matches!(
                err,
                Sep10Error::JwtParseError { ref detail }
                    if detail == "token answer is not a compact JWT"
            ),
            "{err:?}"
        );
        assert_eq!(MAX_JWT_BYTES, 8192);
    }

    #[test]
    fn reject_missing_required_claims() {
        // Payload missing the 'sub' field
        let payload = serde_json::json!({
            "iss": "https://example.com",
            "iat": 1000u64,
            "exp": 9999u64,
        })
        .to_string();
        let header = URL_SAFE_NO_PAD.encode("{}");
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
        let jwt = format!("{header}.{payload_b64}.sig");
        let err = Sep10Session::parse(&jwt).unwrap_err();
        assert!(
            matches!(err, Sep10Error::JwtParseError { .. }),
            "expected JwtParseError for missing sub claim; got {err:?}"
        );
    }

    // ── jwt stored verbatim ───────────────────────────────────────────────────

    #[test]
    fn jwt_field_stores_raw_token() {
        let raw = build_jwt("GABC", 9_999_999_999);
        let session = Sep10Session::parse(&raw).unwrap();
        assert_eq!(session.jwt, raw);
    }

    #[test]
    fn debug_redacts_raw_jwt() {
        let raw = build_jwt("GABC", 9_999_999_999);
        let session = Sep10Session::parse(&raw).unwrap();
        let debug = format!("{session:?}");

        assert!(!debug.contains(&raw), "Debug must not expose full JWT");
        assert!(
            debug.contains("..."),
            "Debug must include first-8-last-8 redaction marker: {debug}"
        );
        assert!(
            !debug.contains(&raw[8..raw.len() - 8]),
            "Debug must not expose the JWT middle segment: {debug}"
        );
    }

    /// Regression lock: a JWT with `exp: 1700000000.5` (float) must be
    /// rejected because `JwtClaims.exp` is typed as `u64`.
    #[test]
    fn reject_float_exp_claim() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload_json =
            r#"{"sub":"GABCDEFG","iss":"https://example.com","iat":1000,"exp":1700000000.5}"#;
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
        let jwt = format!("{header}.{payload_b64}.fakesignature");
        let err = Sep10Session::parse(&jwt).unwrap_err();
        assert!(
            matches!(err, Sep10Error::JwtParseError { .. }),
            "expected JwtParseError for float exp claim, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.jwt_parse_error");
    }

    /// Regression lock: a `sub` claim containing `:` but a non-integer memo
    /// must be rejected at parse time, not silently treated as `None`.
    #[test]
    fn reject_malformed_memo_in_sub() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = serde_json::json!({
            "sub": "GABCDEFGHIJKLMNOP:not-a-number",
            "iss": "https://testanchor.stellar.org",
            "iat": 1_700_000_000u64,
            "exp": 9_999_999_999u64,
        })
        .to_string();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
        let jwt = format!("{header}.{payload_b64}.fakesignature");
        let err = Sep10Session::parse(&jwt).unwrap_err();
        assert!(
            matches!(err, Sep10Error::JwtParseError { ref detail } if detail.contains("malformed memo")),
            "expected JwtParseError with 'malformed memo' detail, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.jwt_parse_error");
    }

    /// A `sub` claim with a valid `:MEMO` format must parse successfully
    /// and `memo()` must return the correct u64.
    #[test]
    fn accept_valid_memo_in_sub() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = serde_json::json!({
            "sub": "GABCDEFGHIJKLMNOP:42",
            "iss": "https://testanchor.stellar.org",
            "iat": 1_700_000_000u64,
            "exp": 9_999_999_999u64,
        })
        .to_string();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
        let jwt = format!("{header}.{payload_b64}.fakesignature");
        let session = Sep10Session::parse(&jwt).unwrap();
        assert_eq!(session.account_id(), "GABCDEFGHIJKLMNOP");
        assert_eq!(session.memo(), Some(42));
    }
}
