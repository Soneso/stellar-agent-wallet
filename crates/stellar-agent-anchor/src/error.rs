//! Typed error enum for the `stellar-agent-anchor` crate.
//!
//! # What this module does
//!
//! Provides [`AnchorError`] — the single typed error for all anchor discovery
//! and SEP-24 / SEP-6 client failures.  Every variant carries enough context
//! for the operator to diagnose the problem without leaking sensitive material.
//! URLs are redacted to authority-only (`scheme://host[:port]`) in all Display
//! output; JWTs never appear in any error variant.

use thiserror::Error;

/// All errors produced by the `stellar-agent-anchor` crate.
///
/// This enum is `#[non_exhaustive]` so future variants do not break callers
/// that match on it.  Every variant produces a non-leaking `Display` string:
/// URL fields show only `scheme://host[:port]`; JWTs are never included.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AnchorError {
    /// The supplied anchor domain is syntactically invalid.
    ///
    /// Requires ≥2 DNS labels (FQDN), lowercase LDH, no IP addresses.
    #[error("invalid anchor domain: {detail}")]
    InvalidAnchorDomain {
        /// Description of the syntax failure.  Must not echo the raw value.
        detail: String,
    },

    /// The resolved `TRANSFER_SERVER*` host does not match the operator-supplied
    /// anchor domain or any subdomain of it.
    ///
    /// This is the same-domain SSRF bind: a malicious anchor `stellar.toml`
    /// advertising a `TRANSFER_SERVER*` that points to an unrelated host is
    /// rejected before any fetch to that host is attempted.
    ///
    /// The mismatched URL is NOT included; only the `anchor_domain` hint and the
    /// `resolved_host` authority are surfaced.
    #[error(
        "transfer server host {resolved_host:?} does not match anchor domain \
         {anchor_domain:?} (same-domain SSRF bind rejected)"
    )]
    TransferServerHostMismatch {
        /// The operator-supplied anchor domain (e.g. `"testanchor.stellar.org"`).
        anchor_domain: String,
        /// The authority (host and optional port) of the resolved `TRANSFER_SERVER*` URL.
        resolved_host: String,
    },

    /// An HTTP request to the anchor endpoint failed.
    ///
    /// The full URL is redacted to authority-only.
    #[error("anchor fetch failed at {authority_hint}: {detail}")]
    AnchorFetchFailed {
        /// Authority-only hint for the endpoint that was unreachable.
        authority_hint: String,
        /// Non-leaking description of the transport failure.
        detail: String,
    },

    /// The anchor returned a response body that could not be decoded.
    ///
    /// The URL is redacted to authority-only.
    #[error("anchor response decode failed at {authority_hint}: {detail}")]
    AnchorResponseDecodeFailed {
        /// Authority-only hint for the endpoint.
        authority_hint: String,
        /// Description of the decode failure.
        detail: String,
    },

    /// The anchor returned a non-200 HTTP status code.
    #[error("anchor returned HTTP {status} at {authority_hint}")]
    HttpStatusError {
        /// Authority-only hint for the endpoint.
        authority_hint: String,
        /// The HTTP status code returned.
        status: u16,
    },

    /// The SEP-24 interactive endpoint returned a response whose `type` field
    /// was not `"interactive_customer_info_needed"`.
    ///
    /// Per SEP-24 §5.4: the only valid response type for the interactive
    /// deposit/withdraw endpoints is `"interactive_customer_info_needed"`.
    #[error(
        "SEP-24 unexpected response type: expected \
         'interactive_customer_info_needed', got {response_type:?}"
    )]
    Sep24UnexpectedResponseType {
        /// The `type` field value returned by the anchor.
        response_type: String,
    },

    /// An anchor URL supplied directly (without an anchor domain) uses a
    /// non-HTTPS scheme or is not a valid URL.
    #[error("direct transfer server URL is invalid or non-HTTPS: {detail}")]
    InvalidDirectUrl {
        /// Description of the validation failure.
        detail: String,
    },
}
