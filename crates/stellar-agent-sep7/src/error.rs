//! Error types for the `stellar-agent-sep7` crate.
//!
//! # What this module does
//!
//! Provides [`Sep7Error`] — the single typed error enum for all SEP-7
//! URI parsing, validation, and signature verification failures.  Every
//! variant carries enough context for the operator to diagnose the problem
//! without leaking sensitive material.
//!
//! # Display safety
//!
//! Variants that embed external-derived strings (e.g. domain names, callback
//! URLs) expose only the scheme+host (authority component); path, query, and
//! fragment are never included.  The `TomlFetchFailed` variant discards the
//! fetched URL entirely and shows only a fixed placeholder
//! (`"<origin-domain>/stellar.toml"`).

use thiserror::Error;

/// All errors produced by the `stellar-agent-sep7` crate.
///
/// This enum is `#[non_exhaustive]` so future variants do not break callers
/// that match on it.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Sep7Error {
    /// The URI is not a valid `web+stellar:` URI or cannot be parsed.
    #[error("malformed SEP-7 URI: {detail}")]
    MalformedUri {
        /// Human-readable description of the structural problem.
        detail: String,
    },

    /// The operation after `web+stellar:` is not `tx` or `pay`.
    #[error("unknown SEP-7 operation: {operation:?}; expected 'tx' or 'pay'")]
    UnknownOperation {
        /// The unrecognised operation token.
        operation: String,
    },

    /// A required parameter was absent.
    ///
    /// `xdr` is required for `tx`; `destination` is required for `pay`.
    #[error("SEP-7 missing required parameter: {param}")]
    MissingRequiredParam {
        /// Name of the absent parameter.
        param: &'static str,
    },

    /// A parameter was present but its value is invalid.
    #[error("SEP-7 invalid parameter value for '{param}': {detail}")]
    InvalidParamValue {
        /// Name of the invalid parameter.
        param: &'static str,
        /// Description of the validation failure (must not contain the raw value).
        detail: String,
    },

    /// The `msg` parameter exceeds 300 characters before URL-encoding.
    ///
    /// Per `sep-0007.md`.
    #[error("SEP-7 'msg' too long: {len} characters; maximum is 300")]
    MsgTooLong {
        /// Actual decoded length in characters.
        len: usize,
    },

    /// The `chain` field depth exceeds the 7-level maximum.
    ///
    /// Per `sep-0007.md`.
    #[error("SEP-7 'chain' nesting depth {depth} exceeds the maximum of 7 levels")]
    TooManyChainLevels {
        /// Actual nesting depth encountered.
        depth: u8,
    },

    /// The `origin_domain` is present but syntactically invalid as an FQDN.
    ///
    /// IPs, double-dots, leading underscores, and non-LDH characters are
    /// all rejected.
    #[error("SEP-7 origin_domain is not a valid FQDN: {detail}")]
    InvalidOriginDomain {
        /// Description of the validation failure.
        detail: String,
    },

    /// The fresh stellar.toml fetch for `origin_domain` failed.
    ///
    /// The fetch URL is not included in the Display output; only a fixed
    /// authority-only placeholder is shown to avoid leaking redirect targets
    /// or query strings.
    #[error("SEP-7 stellar.toml fetch failed for origin_domain: {authority_hint}")]
    TomlFetchFailed {
        /// Authority-only hint (`<domain>/.well-known/stellar.toml`) for
        /// operator diagnostics.  Never includes the full fetched URL.
        authority_hint: String,
    },

    /// The stellar.toml was fetched successfully but `URI_REQUEST_SIGNING_KEY`
    /// is absent.
    ///
    /// Per `sep-0007.md`, the key must exist in the toml for verification to succeed.
    #[error("SEP-7 origin_domain stellar.toml does not contain URI_REQUEST_SIGNING_KEY")]
    SigningKeyNotInToml,

    /// Ed25519 signature verification failed.
    ///
    /// This covers both structural signature failures (wrong length, not
    /// base64) and cryptographic mismatches (wrong key, tampered payload).
    #[error("SEP-7 signature verification failed: {detail}")]
    SignatureVerificationFailed {
        /// Non-leaking description of the failure mode.
        detail: String,
    },

    /// `origin_domain` is present but `signature` is absent.
    ///
    /// Per `sep-0007.md`, a URI that claims an origin but omits the signature
    /// is an anti-phishing red flag — the wallet MUST NOT treat the request as trusted.
    #[error(
        "SEP-7 'origin_domain' is present but 'signature' is absent; \
         this URI is NOT verified and must be treated as untrusted"
    )]
    SignatureMissingWithOriginDomain,
}
