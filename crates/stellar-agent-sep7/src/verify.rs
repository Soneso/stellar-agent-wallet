//! SEP-7 origin_domain signature verification.
//!
//! # What this module does
//!
//! Implements the SEP-7 anti-phishing origin_domain flow.
//!
//! - Step 1: If `origin_domain` is absent — no verification, `signature_status = absent`.
//! - Step 2: If `origin_domain` present but `signature` absent — security red flag,
//!   `signature_status = missing_required`.
//! - Step 3: If both present — validate FQDN, **FETCH FRESH** stellar.toml
//!   (anti-phishing freshness per `sep-0007.md`; calls `fetch_stellar_toml`
//!   directly rather than a caching resolver), extract `URI_REQUEST_SIGNING_KEY`,
//!   build the signature payload, ed25519-verify, and return `verified` or `failed`.
//!
//! # Signature payload byte layout
//!
//! ```text
//! [0x00] × 35 bytes   — leading null prefix
//! [0x04]              — type discriminant (1 byte)
//! "stellar.sep.7 - URI Scheme" (26 bytes UTF-8)
//! <uri-bytes>         — the URI string WITHOUT the &signature=... param
//! ```
//!
//! Byte-layout citations:
//! - Flutter `URIScheme.dart`: `payloadStart[35] = 4; b.add(payloadStart); b.add(url8List)`.
//! - iOS `URISchemeValidator.swift`: `payloadStart[35] = 4` (same layout).
//! - Python stellar-sdk `stellar_uri.py`:
//!   `b"\0"*35 + b"\4" + b"stellar.sep.7 - URI Scheme" + data.encode()`.
//!
//! NOTE: ed25519 signs/verifies the raw payload bytes directly — there is NO
//! additional pre-hash step in the SEP-7 specification.  The 32-byte prefix
//! structure uses byte `4` as a domain-separator.
//!
//! # Anti-phishing freshness
//!
//! Per `sep-0007.md`, wallets SHOULD NOT cache `stellar.toml` files for URI
//! signature verification.  This module calls `fetch_stellar_toml` directly
//! (the non-cached path), bypassing any caching resolver.

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use stellar_agent_network::counterparty::{fetch::fetch_stellar_toml, parser::parse_minimal_sep1};

use crate::error::Sep7Error;
use crate::parse::strip_signature_param;

/// SEP-7 signature verification verdict.
///
/// Distinguishes the five possible states for the `origin_domain` / `signature`
/// combination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Both `origin_domain` and `signature` present; verification passed.
    Verified,
    /// Both `origin_domain` and `signature` present; verification failed.
    Failed,
    /// `origin_domain` present but `signature` absent — security red flag per
    /// `sep-0007.md`.
    MissingRequired,
    /// `origin_domain` absent; no verification performed.
    Absent,
    /// Both `origin_domain` and `signature` are present, but the caller used
    /// [`crate::parse_uri`] (parse-only, `verify_origin = false`) so no live
    /// verification was performed.
    ///
    /// Wire value: `"not_checked"`.
    ///
    /// This is distinct from [`SignatureStatus::Absent`] (which means no signature was supplied
    /// at all).  The preview must not represent this as verified or trusted.
    NotChecked,
}

impl SignatureStatus {
    /// Returns the wire string used in the JSON preview output.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Failed => "failed",
            Self::MissingRequired => "missing_required",
            Self::Absent => "absent",
            Self::NotChecked => "not_checked",
        }
    }
}

/// Verifies the SEP-7 origin_domain signature against an already-fetched
/// stellar.toml body.
///
/// Single source of truth for the post-fetch verification logic:
/// TOML parse → `URI_REQUEST_SIGNING_KEY` extraction → signature
/// base64-decode (URL-safe no-pad first, then standard) → payload build
/// → `VerifyingKey::verify`.
///
/// [`verify_origin_signature`] calls this after its fresh fetch.  The
/// `test-helpers` re-export allows tests to inject a stellar.toml body
/// without re-implementing the decode order or key-extraction logic.
///
/// # Parameters
///
/// - `uri` — the complete original URI string (including `signature=`; the
///   function strips it before building the payload).
/// - `origin_domain` — for error messages (authority-only hint, scheme+host only).
/// - `signature_b64` — the URL-decoded signature string; `None` yields
///   [`SignatureStatus::MissingRequired`].
/// - `toml_body` — the raw stellar.toml body text (already fetched).
///
/// # Errors
///
/// Returns [`Sep7Error`] on TOML parse failure, missing/invalid
/// `URI_REQUEST_SIGNING_KEY`, or non-base64 / wrong-length signature bytes.
///
/// # Panics
///
/// Never panics.
// `pub` visibility: the function is safe to call directly (it just skips the
// HTTP fetch step). The `lib.rs` re-export is gated on `test-helpers` so
// callers in production builds cannot reach this path via the crate API, but
// the symbol itself is unrestricted to allow `pub use` from lib.rs.
pub fn verify_against_toml_body(
    uri: &str,
    origin_domain: &str,
    signature_b64: Option<&str>,
    toml_body: &str,
) -> Result<SignatureStatus, Sep7Error> {
    // Signature absent → security red flag (matches verify_origin_signature).
    let sig_b64 = match signature_b64 {
        None => return Ok(SignatureStatus::MissingRequired),
        Some(s) => s,
    };

    // Parse the TOML body to extract URI_REQUEST_SIGNING_KEY.
    let minimal = parse_minimal_sep1(toml_body).map_err(|e| {
        tracing::warn!(
            authority = %origin_domain,
            error = %e,
            "SEP-7 stellar.toml parse failed for origin_domain"
        );
        Sep7Error::TomlFetchFailed {
            authority_hint: format!("{origin_domain}/.well-known/stellar.toml"),
        }
    })?;

    let signing_key_str = minimal
        .uri_request_signing_key
        .as_deref()
        .ok_or(Sep7Error::SigningKeyNotInToml)?;

    // Decode the URI_REQUEST_SIGNING_KEY from G-strkey to raw ed25519 bytes.
    let pk_bytes =
        stellar_strkey::ed25519::PublicKey::from_string(signing_key_str).map_err(|_| {
            Sep7Error::SignatureVerificationFailed {
                detail: "URI_REQUEST_SIGNING_KEY in stellar.toml is not a valid G-strkey"
                    .to_owned(),
            }
        })?;

    let verifying_key = VerifyingKey::from_bytes(&pk_bytes.0).map_err(|_| {
        Sep7Error::SignatureVerificationFailed {
            detail: "URI_REQUEST_SIGNING_KEY could not be decoded as an ed25519 public key"
                .to_owned(),
        }
    })?;

    // Build the signature payload.
    let payload = build_signature_payload(uri);

    // Decode the base64 signature.
    // Try URL-safe no-pad first, then standard base64.  All callers go through
    // this function, so there is no second copy of the decode order.
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(sig_b64))
        .map_err(|_| Sep7Error::SignatureVerificationFailed {
            detail: "signature is not valid base64".to_owned(),
        })?;

    let sig_arr: [u8; 64] =
        sig_bytes
            .try_into()
            .map_err(|_| Sep7Error::SignatureVerificationFailed {
                detail: "signature must be exactly 64 bytes after base64 decode".to_owned(),
            })?;

    let signature = Signature::from_bytes(&sig_arr);

    match verifying_key.verify(&payload, &signature) {
        Ok(()) => Ok(SignatureStatus::Verified),
        Err(_) => Ok(SignatureStatus::Failed),
    }
}

/// Verifies the SEP-7 origin_domain signature, performing a fresh
/// stellar.toml fetch (non-cached).
///
/// # Parameters
///
/// - `uri` — the complete original URI string (including the `signature=`
///   parameter if present; the function strips it internally before building
///   the payload).
/// - `origin_domain` — the parsed, validated FQDN from the URI.
/// - `signature_b64` — the URL-decoded signature string (standard or URL-safe
///   base64); `None` if the `signature` parameter was absent.
///
/// # Returns
///
/// - [`SignatureStatus::Absent`] if `origin_domain` is `None`.
/// - [`SignatureStatus::MissingRequired`] if `origin_domain` is `Some` but
///   `signature_b64` is `None`.
/// - [`SignatureStatus::Verified`] or [`SignatureStatus::Failed`] for the
///   cryptographic check.
///
/// # Errors
///
/// Returns [`Sep7Error`] on fetch failures, key-not-in-toml, or when the
/// signature cannot be decoded at all.
///
/// # Panics
///
/// Never panics.
pub async fn verify_origin_signature(
    uri: &str,
    origin_domain: Option<&str>,
    signature_b64: Option<&str>,
) -> Result<SignatureStatus, Sep7Error> {
    let domain = match origin_domain {
        None => return Ok(SignatureStatus::Absent),
        Some(d) => d,
    };

    // origin_domain present but signature absent — security red flag.
    // `verify_against_toml_body` also handles this, but we return early here
    // so we do not perform a network fetch for an obviously-invalid request.
    if signature_b64.is_none() {
        return Ok(SignatureStatus::MissingRequired);
    }

    // Fetch fresh stellar.toml — NOT the cache.
    // Anti-phishing freshness per sep-0007.md.
    let body = fetch_stellar_toml(domain).await.map_err(|e| {
        tracing::warn!(
            authority = %domain,
            error = %e,
            "SEP-7 stellar.toml fetch failed for origin_domain"
        );
        Sep7Error::TomlFetchFailed {
            // Authority-only hint (scheme+host); full URL is not exposed.
            authority_hint: format!("{domain}/.well-known/stellar.toml"),
        }
    })?;

    // Delegate to the single post-fetch verify path.
    verify_against_toml_body(uri, domain, signature_b64, &body)
}

/// Builds the SEP-7 signature payload bytes.
///
/// Layout (matches Flutter, iOS, and Python Stellar SDK implementations):
/// ```text
/// [0x00] × 35  — 35 leading null bytes
/// [0x04]       — 1 byte type discriminant
/// "stellar.sep.7 - URI Scheme"  — 26 UTF-8 bytes
/// <uri_without_signature>       — URI bytes without &signature=...
/// ```
///
/// # Byte-layout citations
///
/// - Flutter `URIScheme.dart`:
///   `payloadStart = Uint8List(36); payloadStart[35] = 4;
///    b.add(payloadStart); b.add(url8List)` where `url8List` is
///   `(uriSchemePrefix + url).codeUnits` and `uriSchemePrefix = "stellar.sep.7 - URI Scheme"`.
/// - Python stellar-sdk `stellar_uri.py`:
///   `b"\0"*35 + b"\4" + b"stellar.sep.7 - URI Scheme" + data.encode()`.
pub fn build_signature_payload(uri: &str) -> Vec<u8> {
    // Strip &signature=... before building payload.
    let uri_without_sig = strip_signature_param(uri);

    const PREFIX: &[u8] = b"stellar.sep.7 - URI Scheme";
    // Total prefix: 35 zero bytes + 0x04 + "stellar.sep.7 - URI Scheme" = 62 bytes.
    let mut payload = Vec::with_capacity(36 + PREFIX.len() + uri_without_sig.len());
    // 35 zero bytes.
    payload.extend_from_slice(&[0u8; 35]);
    // Byte 36: type discriminant 0x04.
    payload.push(0x04);
    // The prefix string.
    payload.extend_from_slice(PREFIX);
    // The URI bytes (without signature param).
    payload.extend_from_slice(uri_without_sig.as_bytes());
    payload
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

    const SEP7_URI_PREFIX: &[u8] = b"stellar.sep.7 - URI Scheme";

    #[test]
    fn payload_structure_matches_spec() {
        let uri = "web+stellar:pay?destination=GABC&origin_domain=example.com&signature=abc";
        let payload = build_signature_payload(uri);

        // First 35 bytes must be 0x00.
        assert!(payload[..35].iter().all(|&b| b == 0x00));
        // Byte 36 (index 35) must be 0x04.
        assert_eq!(payload[35], 0x04);
        // Bytes 36..62 must be the prefix string.
        assert_eq!(&payload[36..62], SEP7_URI_PREFIX);
        // Remaining bytes must be the URI without the signature param.
        let stripped = strip_signature_param(uri);
        assert_eq!(&payload[62..], stripped.as_bytes());
    }

    #[test]
    fn payload_prefix_length_is_62() {
        // 35 zero bytes + 0x04 byte + 26-char prefix = 62 bytes.
        assert_eq!(SEP7_URI_PREFIX.len(), 26);
        // Total payload prefix = 35 + 1 + 26 = 62.
        let empty_payload = build_signature_payload("web+stellar:pay?destination=G");
        assert!(empty_payload.len() >= 62);
    }

    #[test]
    fn signature_status_as_str() {
        assert_eq!(SignatureStatus::Verified.as_str(), "verified");
        assert_eq!(SignatureStatus::Failed.as_str(), "failed");
        assert_eq!(
            SignatureStatus::MissingRequired.as_str(),
            "missing_required"
        );
        assert_eq!(SignatureStatus::Absent.as_str(), "absent");
        assert_eq!(SignatureStatus::NotChecked.as_str(), "not_checked");
    }

    // ── verify_against_toml_body error branches ──────────────────────────────

    const VALID_URI: &str = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &origin_domain=example.com";

    #[test]
    fn toml_body_signature_none_yields_missing_required() {
        // signature_b64 = None triggers the early-return MissingRequired path.
        let result = verify_against_toml_body(
            VALID_URI,
            "example.com",
            None,
            "URI_REQUEST_SIGNING_KEY = \"GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\"\n",
        )
        .unwrap();
        assert_eq!(
            result,
            SignatureStatus::MissingRequired,
            "None signature_b64 must return MissingRequired before any toml parse"
        );
    }

    #[test]
    fn toml_body_malformed_toml_returns_toml_fetch_failed() {
        // A TOML body that fails parsing must return TomlFetchFailed.
        let err = verify_against_toml_body(
            VALID_URI,
            "example.com",
            Some("dGVzdA=="), // valid base64 "test" — passes b64 decode
            "= not valid toml =",
        )
        .unwrap_err();
        assert!(
            matches!(err, crate::error::Sep7Error::TomlFetchFailed { .. }),
            "malformed TOML body must return TomlFetchFailed, got: {err:?}"
        );
    }

    // NOTE: The G-strkey validation at verify.rs lines 154-160 (stellar_strkey
    // decode) and lines 162-167 (VerifyingKey::from_bytes) are effectively dead
    // code when called via verify_against_toml_body: parse_minimal_sep1 in
    // stellar-agent-network validates URI_REQUEST_SIGNING_KEY as a valid
    // Stellar G-strkey before returning it, so an invalid key value causes
    // parse_minimal_sep1 to return TomlInvalid (mapped to TomlFetchFailed)
    // before reaching those lines.  Similarly, stellar_strkey guarantees a
    // valid 32-byte ed25519 public key representation, so VerifyingKey::from_bytes
    // on those 32 bytes cannot fail.  These branches remain as defensive
    // belt-and-suspenders guards; they are not reachable through the current
    // upstream validation chain.

    #[test]
    fn toml_body_non_base64_signature_returns_verification_failed() {
        // A signature string that is not valid base64 (either URL-safe or standard)
        // must return SignatureVerificationFailed.
        let toml = "URI_REQUEST_SIGNING_KEY = \"GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\"\n";
        let err =
            verify_against_toml_body(VALID_URI, "example.com", Some("!!!not-base64!!!"), toml)
                .unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::Sep7Error::SignatureVerificationFailed { ref detail }
                    if detail.contains("not valid base64")
            ),
            "non-base64 signature must return SignatureVerificationFailed with 'not valid base64', got: {err:?}"
        );
    }

    #[test]
    fn toml_body_wrong_length_signature_returns_verification_failed() {
        // A signature that decodes from base64 but is not 64 bytes must
        // return SignatureVerificationFailed with "exactly 64 bytes".
        use base64::Engine as _;
        let toml = "URI_REQUEST_SIGNING_KEY = \"GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\"\n";
        // Encode 10 bytes — valid base64 but wrong length.
        let short_sig = base64::engine::general_purpose::STANDARD.encode([0u8; 10]);
        let err =
            verify_against_toml_body(VALID_URI, "example.com", Some(&short_sig), toml).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::Sep7Error::SignatureVerificationFailed { ref detail }
                    if detail.contains("exactly 64 bytes")
            ),
            "wrong-length signature must return SignatureVerificationFailed with '64 bytes', got: {err:?}"
        );
    }

    // ── verify_origin_signature early returns (no network) ───────────────────

    #[tokio::test]
    async fn origin_signature_none_domain_returns_absent() {
        // origin_domain = None → Absent before any network I/O.
        let status = verify_origin_signature(VALID_URI, None, Some("anysig"))
            .await
            .unwrap();
        assert_eq!(
            status,
            SignatureStatus::Absent,
            "None origin_domain must return Absent without any fetch"
        );
    }

    #[tokio::test]
    async fn origin_signature_some_domain_no_sig_returns_missing_required() {
        // origin_domain present, signature_b64 = None → MissingRequired before fetch.
        let status = verify_origin_signature(VALID_URI, Some("example.com"), None)
            .await
            .unwrap();
        assert_eq!(
            status,
            SignatureStatus::MissingRequired,
            "Some domain + None signature must return MissingRequired without any fetch"
        );
    }
}
