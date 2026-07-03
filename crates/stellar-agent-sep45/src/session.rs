//! SEP-45 JWT session holder with decoded claim accessors.
//!
//! [`Sep45Session`] holds the decoded claims from a server-issued JWT after a
//! successful SEP-45 web authentication flow. Parsing is intentionally minimal:
//! the crate hand-rolls JWT segment splitting + base64-url decode +
//! `serde_json` claim extraction WITHOUT signature verification.
//!
//! # No JWT signature verification
//!
//! Per the SEP-45 JWT session schema: the JWT is issued by the SEP-45 server
//! over HTTPS. The client trusts the JWT issuer via TLS (the server's TLS
//! certificate authenticates the connection). Signature verification inside
//! the client would require the server's HS256 / RS256 key to be known to
//! the client, which contradicts the spec's design.
//!
//! # `sub` claim format
//!
//! The `sub` claim ALWAYS identifies a contract account using a C-prefix
//! strkey (per the SEP-45 JWT session schema). Unlike SEP-10, there is no
//! G-key / M-key / memo variant — SEP-45 is exclusively for contract accounts.
//! A `sub` value that fails `stellar_strkey::Contract::from_string` validation
//! is rejected at parse time, which ensures the value is a correctly-encoded
//! 56-character C-strkey (not merely a string starting with the letter "C").
//!
use base64::{
    Engine as _, alphabet,
    engine::{GeneralPurpose, general_purpose::NO_PAD},
};
use serde::Deserialize;

use crate::error::Sep45Error;

// stellar_strkey is used to validate the `sub` claim is a well-formed C-strkey.
use stellar_strkey::Contract as ContractStrkey;

/// Base64 URL-safe no-padding engine for JWT segment decoding.
///
/// JWT uses URL-safe base64 without padding per RFC 7519 §2.
static BASE64_URL_NO_PAD: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, NO_PAD);

/// A parsed and decoded SEP-45 JWT session.
///
/// Constructed via [`Sep45Session::parse`]. Fields reflect the decoded JWT
/// claims as specified in the SEP-45 JWT session schema. The raw JWT string
/// is retained so callers can forward it to downstream services.
///
#[derive(Clone)]
pub struct Sep45Session {
    /// The raw JWT string, retained for forwarding to downstream services
    /// that require bearer-token authentication.
    pub jwt: String,

    /// The `sub` (subject) claim — always a C-prefix contract strkey
    /// per the SEP-45 JWT session schema.
    ///
    /// Use [`Sep45Session::contract_id`] to access this value.
    pub sub: String,

    /// The `iss` (issuer) claim — URI identifying the SEP-45 server.
    pub iss: String,

    /// The `iat` (issued-at) claim — Unix timestamp of JWT issuance.
    pub iat: u64,

    /// The `exp` (expiration) claim — Unix timestamp after which the JWT
    /// must not be accepted.
    pub exp: u64,

    /// The `client_domain` claim — present if the challenge included a
    /// `client_domain` entry (per the SEP-45 JWT session schema).
    pub client_domain: Option<String>,
}

impl std::fmt::Debug for Sep45Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sep45Session")
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
    // Use chars()-based slicing (mirroring `redact_strkey_first5_last5`) so
    // that `Debug` never panics on a non-ASCII JWT value, however unlikely.
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

/// Internal serde struct for JWT payload claim extraction.
///
/// All fields are `Option` except `sub`, `iss`, `iat`, `exp` which are
/// required by the SEP-45 JWT session schema.
#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: String,
    iss: String,
    iat: u64,
    exp: u64,
    client_domain: Option<String>,
}

impl Sep45Session {
    /// Parses a SEP-45 JWT and decodes its claims.
    ///
    /// Splits the JWT on `'.'`, base64-url-decodes the middle (payload)
    /// segment, and extracts `sub`, `iss`, `iat`, `exp`, and optional
    /// `client_domain` claims via `serde_json`.
    ///
    /// Does NOT verify the JWT signature — see module-level documentation for
    /// the rationale and the `# Security` section below.
    ///
    /// # Errors
    ///
    /// - [`Sep45Error::JwtParseError`] if the JWT does not have exactly 3
    ///   base64-separated segments (header.payload.signature).
    /// - [`Sep45Error::JwtParseError`] if the payload segment cannot be
    ///   base64-url-decoded.
    /// - [`Sep45Error::JwtParseError`] if the payload is not valid UTF-8 JSON.
    /// - [`Sep45Error::JwtParseError`] if required claims (`sub`, `iss`, `iat`,
    ///   `exp`) are missing or have wrong types.
    /// - [`Sep45Error::JwtParseError`] if `iat` or `exp` are floating-point
    ///   values (serde rejects them since `iat`/`exp` are typed as `u64`).
    /// - [`Sep45Error::JwtParseError`] if the `sub` claim is not a
    ///   well-formed C-strkey contract account per `stellar_strkey::Contract`
    ///   validation — SEP-45 requires a contract account C-strkey
    ///   (per the SEP-45 JWT session schema).
    ///
    /// # Security
    ///
    /// **JWT signature is NOT verified by this method.** The trust model assumes
    /// the JWT was received over a TLS-authenticated connection from the SEP-45
    /// server: the server's TLS certificate authenticates the channel, and the
    /// JWT content is trusted because the channel is trusted. Future operators
    /// MUST NOT rely on JWT integrity beyond TLS-channel integrity — in
    /// particular, this method must not be called with JWTs obtained from any
    /// source that is not a direct TLS-authenticated SEP-45 server response.
    /// Callers MUST NOT use JWTs obtained from any source other than a direct
    /// TLS-authenticated SEP-45 server response.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_sep45::Sep45Session;
    ///
    /// // Construct a minimal valid JWT (header.payload.signature).
    /// // sub must be a well-formed C-strkey contract account per the SEP-45 JWT session schema.
    /// const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    /// let payload_json = format!(
    ///     r#"{{"sub":"{CONTRACT}","iss":"https://example.com","iat":1000,"exp":2000}}"#
    /// );
    /// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    /// let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    /// let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    /// let jwt = format!("{}.{}.fakesignature", header_b64, payload_b64);
    ///
    /// let session = Sep45Session::parse(&jwt).unwrap();
    /// assert_eq!(session.sub, CONTRACT);
    /// assert_eq!(session.iss, "https://example.com");
    /// assert_eq!(session.exp, 2000);
    /// assert!(!session.is_expired(1500));
    /// assert!(session.is_expired(2001));
    /// ```
    pub fn parse(jwt: &str) -> Result<Self, Sep45Error> {
        // Split into exactly 3 segments: header.payload.signature.
        let parts: Vec<&str> = jwt.splitn(4, '.').collect();
        if parts.len() != 3 {
            return Err(Sep45Error::JwtParseError {
                detail: format!(
                    "JWT must have exactly 3 dot-separated segments; got {}",
                    parts.len()
                ),
            });
        }
        let payload_b64 = parts[1];

        // Base64-url decode the payload segment.
        let payload_bytes =
            BASE64_URL_NO_PAD
                .decode(payload_b64)
                .map_err(|e| Sep45Error::JwtParseError {
                    detail: format!("JWT payload base64-url decode failed: {e}"),
                })?;

        // Parse the JSON payload into JwtClaims.
        // serde_json will reject float exp/iat values because the target types
        // are u64 — fractional timestamps are rejected by design.
        let claims: JwtClaims =
            serde_json::from_slice(&payload_bytes).map_err(|e| Sep45Error::JwtParseError {
                detail: format!("JWT payload JSON parse failed: {e}"),
            })?;

        // Validate the `sub` claim per the SEP-45 JWT session schema.
        // SEP-45 sub MUST be a well-formed C-strkey contract account. Using
        // `stellar_strkey::Contract::from_string` ensures checksum and encoding
        // correctness, not merely that the first character is 'C'.
        ContractStrkey::from_string(&claims.sub).map_err(|e| Sep45Error::JwtParseError {
            detail: format!(
                "sub claim must be a C-strkey contract account for SEP-45; \
                 strkey parse failed: {e}",
            ),
        })?;

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
    /// Per RFC 7519 §4.1.4: the JWT MUST NOT be accepted on or after the `exp`
    /// time. This method returns `true` when `now_unix >= self.exp`.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_sep45::Sep45Session;
    ///
    /// const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    /// let payload = format!(
    ///     r#"{{"sub":"{CONTRACT}","iss":"https://example.com","iat":1000,"exp":2000}}"#
    /// );
    /// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    /// let header = URL_SAFE_NO_PAD.encode("{}");
    /// let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    /// let jwt = format!("{}.{}.sig", header, payload_b64);
    /// let session = Sep45Session::parse(&jwt).unwrap();
    ///
    /// assert!(!session.is_expired(1999));
    /// assert!(session.is_expired(2000));
    /// assert!(session.is_expired(9999));
    /// ```
    #[must_use]
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.exp
    }

    /// Returns the contract account identifier from the `sub` claim.
    ///
    /// Per the SEP-45 JWT session schema the `sub` of a SEP-45 JWT is always a
    /// C-prefix contract account strkey. There are no memo variants or muxed
    /// account variants — the full `sub` value IS the contract ID.
    ///
    /// The returned value is guaranteed to start with `"C"` because
    /// [`Sep45Session::parse`] rejects any other `sub` format at construction
    /// time.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_sep45::Sep45Session;
    /// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    ///
    /// const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    /// let p = format!(r#"{{"sub":"{CONTRACT}","iss":"https://x.com","iat":0,"exp":9999}}"#);
    /// let b64 = URL_SAFE_NO_PAD.encode(p.as_bytes());
    /// let jwt = format!("{}.{}.sig", URL_SAFE_NO_PAD.encode("{}"), b64);
    /// let s = Sep45Session::parse(&jwt).unwrap();
    /// assert_eq!(s.contract_id(), CONTRACT);
    /// ```
    #[must_use]
    pub fn contract_id(&self) -> &str {
        &self.sub
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

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

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

    // Valid C-strkeys used throughout the test suite.
    const CONTRACT_A: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    const CONTRACT_B: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    // ── C-strkey sub — happy path ─────────────────────────────────────────────

    #[test]
    fn parse_c_strkey_sub() {
        let jwt = build_jwt(CONTRACT_A, 9_999_999_999);
        let session = Sep45Session::parse(&jwt).unwrap();
        assert_eq!(session.sub, CONTRACT_A);
        assert_eq!(session.contract_id(), CONTRACT_A);
        assert_eq!(session.iss, "https://testanchor.stellar.org");
        assert!(!session.is_expired(1_700_000_001));
    }

    // ── contract_id accessor ──────────────────────────────────────────────────

    #[test]
    fn contract_id_returns_full_sub() {
        let jwt = build_jwt(CONTRACT_B, 9_999_999_999);
        let session = Sep45Session::parse(&jwt).unwrap();
        assert_eq!(session.contract_id(), CONTRACT_B);
        // contract_id() must equal sub (no suffix stripping as in SEP-10 G:memo)
        assert_eq!(session.contract_id(), session.sub.as_str());
    }

    // ── Expiry detection ──────────────────────────────────────────────────────

    #[test]
    fn expiry_boundary_conditions() {
        let jwt = build_jwt(CONTRACT_A, 1_000);
        let session = Sep45Session::parse(&jwt).unwrap();
        assert!(session.is_expired(1_000), "at exp boundary must be expired");
        assert!(session.is_expired(1_001), "past exp must be expired");
        assert!(!session.is_expired(999), "before exp must not be expired");
    }

    // ── client_domain claim ───────────────────────────────────────────────────

    #[test]
    fn parse_client_domain_claim() {
        let jwt = build_jwt_with_client_domain(CONTRACT_A, 9_999_999_999, "wallet.example.com");
        let session = Sep45Session::parse(&jwt).unwrap();
        assert_eq!(session.client_domain, Some("wallet.example.com".to_owned()));
    }

    #[test]
    fn no_client_domain_when_absent() {
        let jwt = build_jwt(CONTRACT_A, 9_999_999_999);
        let session = Sep45Session::parse(&jwt).unwrap();
        assert_eq!(session.client_domain, None);
    }

    // ── JWT raw token preserved ───────────────────────────────────────────────

    #[test]
    fn jwt_field_stores_raw_token() {
        let raw = build_jwt(CONTRACT_A, 9_999_999_999);
        let session = Sep45Session::parse(&raw).unwrap();
        assert_eq!(session.jwt, raw);
    }

    #[test]
    fn debug_redacts_raw_jwt() {
        let raw = build_jwt(CONTRACT_A, 9_999_999_999);
        let session = Sep45Session::parse(&raw).unwrap();
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

    // ── Malformed JWT rejection ───────────────────────────────────────────────

    #[test]
    fn reject_malformed_jwt_two_segments() {
        let err = Sep45Session::parse("header.payload").unwrap_err();
        assert!(
            matches!(err, Sep45Error::JwtParseError { .. }),
            "expected JwtParseError got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.jwt_parse_error");
    }

    #[test]
    fn reject_malformed_jwt_non_base64_payload() {
        let err = Sep45Session::parse("header.!!!invalid_base64!!!.sig").unwrap_err();
        assert!(
            matches!(err, Sep45Error::JwtParseError { .. }),
            "expected JwtParseError got {err:?}"
        );
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
        let err = Sep45Session::parse(&jwt).unwrap_err();
        assert!(
            matches!(err, Sep45Error::JwtParseError { .. }),
            "expected JwtParseError for missing sub claim; got {err:?}"
        );
    }

    // ── Float exp claim rejection ─────────────────────────────────────────────

    /// Regression-lock against `#[serde(default)]` or `serde_json::Number`
    /// handling changes that might silently coerce a float `exp` to an
    /// integer. A JWT with `exp: 1700000000.5` (float) must be rejected
    /// because `JwtClaims.exp` is typed as `u64`.
    #[test]
    fn reject_float_exp_claim() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload_json = format!(
            r#"{{"sub":"{CONTRACT_A}","iss":"https://example.com","iat":1000,"exp":1700000000.5}}"#
        );
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let jwt = format!("{header}.{payload_b64}.fakesignature");
        let err = Sep45Session::parse(&jwt).unwrap_err();
        assert!(
            matches!(err, Sep45Error::JwtParseError { .. }),
            "expected JwtParseError for float exp claim, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.jwt_parse_error");
    }

    // ── Non-C-strkey sub rejection ────────────────────────────────────────────

    /// SEP-45 `sub` must be a C-prefix contract account strkey.
    /// G-key, M-key, or arbitrary strings must be rejected.
    #[test]
    fn reject_g_key_sub() {
        let jwt = build_jwt("GABCDEFGHIJKLMNOP", 9_999_999_999);
        let err = Sep45Session::parse(&jwt).unwrap_err();
        assert!(
            matches!(err, Sep45Error::JwtParseError { ref detail } if detail.contains("C-strkey")),
            "expected JwtParseError with C-strkey detail for G-key sub, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.jwt_parse_error");
    }

    #[test]
    fn reject_m_key_sub() {
        let muxed =
            "MAAAAAAAAAAAAAB7BQ2L7E2W3YWBWNZN3V7JQUQPKGDM7GV7V72J3GNYFQ4MAAAAAAAAAPC2L2ZFK4";
        let jwt = build_jwt(muxed, 9_999_999_999);
        let err = Sep45Session::parse(&jwt).unwrap_err();
        assert!(
            matches!(err, Sep45Error::JwtParseError { ref detail } if detail.contains("C-strkey")),
            "expected JwtParseError with C-strkey detail for M-key sub, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.jwt_parse_error");
    }

    #[test]
    fn reject_arbitrary_string_sub() {
        let jwt = build_jwt("not-a-strkey-at-all", 9_999_999_999);
        let err = Sep45Session::parse(&jwt).unwrap_err();
        assert!(
            matches!(err, Sep45Error::JwtParseError { ref detail } if detail.contains("C-strkey")),
            "expected JwtParseError for non-C-strkey sub, got {err:?}"
        );
    }

    /// A string that starts with 'C' but is NOT a valid C-strkey (wrong
    /// length / bad checksum) must be rejected via strkey validation.
    #[test]
    fn reject_c_prefix_but_invalid_strkey_sub() {
        // "CABC" starts with 'C' but fails stellar_strkey::Contract checksum.
        let jwt = build_jwt("CABC", 9_999_999_999);
        let err = Sep45Session::parse(&jwt).unwrap_err();
        assert!(
            matches!(err, Sep45Error::JwtParseError { ref detail } if detail.contains("C-strkey")),
            "expected JwtParseError for C-prefix but invalid strkey, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.jwt_parse_error");
    }
}
