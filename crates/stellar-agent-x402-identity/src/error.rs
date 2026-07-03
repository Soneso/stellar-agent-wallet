//! Typed error enum for the x402 counterparty-identity gate.
//!
//! # What this module does
//!
//! Defines [`IdentityError`], the single typed error returned by
//! [`crate::gate::resolve_and_verify_counterparty`].  Every variant carries
//! a machine-readable Display that is **non-leaky**: fetch URLs are
//! authority-only, JWT material is never surfaced, and ephemeral
//! seeds are never mentioned.
//!
//! # URL redaction discipline
//!
//! - Fetch URLs: authority (`host[:port]`) only — no path, no query, no
//!   fragment.  Prevents operator URLs and resource paths from leaking into
//!   operator logs.
//! - JWT: never included in any error variant.  The JWT is the product of a
//!   successful gate run; on failure there is no JWT to leak.
//! - Ephemeral seed: the `auth_with_ephemeral_key` function owns the seed
//!   and destroys it via `ZeroizeOnDrop`; this module never touches it.

use thiserror::Error;

/// Typed error for the counterparty-identity pre-payment gate.
///
/// Returned by [`crate::gate::resolve_and_verify_counterparty`] and
/// [`crate::gate::resolve_and_verify_counterparty_at`] (test seam).
///
/// All variants implement non-leaky `Display`: fetch URLs are authority-only;
/// JWT material is never included; ephemeral key seeds are never surfaced.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum IdentityError {
    /// The operator-supplied `home_domain` is syntactically invalid.
    ///
    /// This is a caller-input error (the domain fails LDH / length / ASCII
    /// validation before any network I/O).  It is distinct from
    /// [`HomeDomainUnresolvable`](Self::HomeDomainUnresolvable) which represents
    /// a reachability failure after a valid domain was accepted.
    ///
    /// Display: the sanitised detail string from the underlying validator.
    #[error("x402-identity: home domain is invalid: {detail}")]
    HomeDomainInvalid {
        /// Sanitised validation failure detail, safe to log.
        detail: String,
    },

    /// The operator-supplied `home_domain` could not be resolved or the HTTPS
    /// connection to `https://<home_domain>/.well-known/stellar.toml` failed.
    ///
    /// Display: authority-only URL hint (no path/query/fragment).
    #[error(
        "x402-identity: home domain unreachable: stellar.toml fetch failed \
         (authority: {authority})"
    )]
    HomeDomainUnresolvable {
        /// Redacted URL authority (`host[:port]`), safe to log.
        authority: String,
    },

    /// `stellar.toml` was fetched but could not be parsed as valid TOML or
    /// failed the structural validation (e.g. oversized body, invalid UTF-8,
    /// non-string field type).
    ///
    /// The `reason` field carries a sanitised parse-error summary; it never
    /// embeds raw attacker-controlled TOML scalar values (the parser's own
    /// `sanitize_invalid_value` guards that boundary).
    #[error("x402-identity: stellar.toml parse failed (authority: {authority}): {reason}")]
    TomlFetchFailed {
        /// Redacted URL authority (`host[:port]`), safe to log.
        authority: String,
        /// Sanitised parse-error reason, safe to log.
        reason: String,
    },

    /// The parsed `stellar.toml` has no `WEB_AUTH_ENDPOINT` field.
    ///
    /// SEP-10 requires `WEB_AUTH_ENDPOINT` for the web-auth challenge/response
    /// round-trip.  Absence aborts before any payment is built.
    #[error(
        "x402-identity: stellar.toml for '{home_domain}' is missing \
         WEB_AUTH_ENDPOINT — cannot perform SEP-10 counterparty verification"
    )]
    WebAuthEndpointMissing {
        /// The operator-supplied home domain.
        home_domain: String,
    },

    /// The parsed `stellar.toml` has no `SIGNING_KEY` field.
    ///
    /// SEP-10 challenge validation requires the server `SIGNING_KEY` to verify
    /// that the challenge was signed by the home domain's key.  Absence
    /// aborts before any payment is built.
    #[error(
        "x402-identity: stellar.toml for '{home_domain}' is missing SIGNING_KEY \
         — cannot verify SEP-10 server identity"
    )]
    SigningKeyMissing {
        /// The operator-supplied home domain.
        home_domain: String,
    },

    /// The `WEB_AUTH_ENDPOINT` host is not the same registrable domain as
    /// `home_domain` or a subdomain of it.
    ///
    /// Prevents a malicious `stellar.toml` from redirecting the SEP-10
    /// challenge request to an arbitrary host.  The same-domain bind
    /// requires the endpoint host to be `home_domain` or a subdomain of it.
    ///
    /// Display: host values only (never full URLs).
    #[error(
        "x402-identity: WEB_AUTH_ENDPOINT host '{endpoint_host}' is not the \
         home domain '{home_domain}' or a subdomain (SSRF bind rejected)"
    )]
    WebAuthEndpointHostMismatch {
        /// The `WEB_AUTH_ENDPOINT` URL host extracted from the TOML value.
        endpoint_host: String,
        /// The operator-supplied home domain.
        home_domain: String,
    },

    /// The SEP-10 ephemeral-key challenge/response cycle failed.
    ///
    /// This variant maps all [`stellar_agent_sep10::Sep10Error`] sub-variants —
    /// HTTP errors on the challenge GET, challenge validation failures (wrong
    /// server key, expired window, bad nonce, etc.), and JWT parse failures.
    ///
    /// The `reason` field carries a machine-readable summary safe to log.  It
    /// NEVER contains the JWT string (there is no JWT on failure).
    #[error("x402-identity: SEP-10 counterparty authentication failed: {reason}")]
    Sep10AuthFailed {
        /// Sanitised failure reason from [`stellar_agent_sep10::Sep10Error`],
        /// safe to log.
        reason: String,
    },
}

impl IdentityError {
    /// Returns a stable machine-readable code for this error variant.
    ///
    /// Safe to emit in structured log events and error envelopes.  The code
    /// never contains URL paths, JWT fragments, or key material.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use stellar_agent_x402_identity::IdentityError;
    ///
    /// let err = IdentityError::WebAuthEndpointMissing {
    ///     home_domain: "example.com".to_owned(),
    /// };
    /// assert_eq!(err.wire_code(), "identity.web_auth_endpoint_missing");
    /// ```
    #[must_use]
    pub fn wire_code(&self) -> &'static str {
        match self {
            Self::HomeDomainInvalid { .. } => "identity.home_domain_invalid",
            Self::HomeDomainUnresolvable { .. } => "identity.home_domain_unresolvable",
            Self::TomlFetchFailed { .. } => "identity.toml_fetch_failed",
            Self::WebAuthEndpointMissing { .. } => "identity.web_auth_endpoint_missing",
            Self::SigningKeyMissing { .. } => "identity.signing_key_missing",
            Self::WebAuthEndpointHostMismatch { .. } => "identity.web_auth_endpoint_host_mismatch",
            Self::Sep10AuthFailed { .. } => "identity.sep10_auth_failed",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// URL authority-only redactor
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts the authority component (`host[:port]`) from a URL string.
///
/// Used by the gate to produce redaction-compliant log tokens: the authority
/// identifies the remote endpoint without exposing path, query, or fragment.
///
/// Returns `"<redacted>"` when the URL cannot be parsed (fail-safe; prevents
/// the raw URL from appearing in logs via the fallback path).
///
/// # Panics
///
/// Never panics.
#[must_use]
pub(crate) fn authority_hint(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| {
            let host = u.host_str()?;
            match u.port() {
                Some(port) => Some(format!("{host}:{port}")),
                None => Some(host.to_owned()),
            }
        })
        .unwrap_or_else(|| "<redacted>".to_owned())
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
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    // ── authority_hint ─────────────────────────────────────────────────────────

    #[test]
    fn authority_hint_strips_path_and_query() {
        let hint = authority_hint("https://auth.example.com/sep10/auth?foo=bar");
        assert_eq!(hint, "auth.example.com");
    }

    #[test]
    fn authority_hint_includes_port_when_non_default() {
        let hint = authority_hint("https://auth.example.com:8443/sep10");
        assert_eq!(hint, "auth.example.com:8443");
    }

    #[test]
    fn authority_hint_returns_redacted_on_invalid_url() {
        let hint = authority_hint("not_a_url");
        assert_eq!(hint, "<redacted>");
    }

    #[test]
    fn authority_hint_returns_redacted_on_empty_string() {
        let hint = authority_hint("");
        assert_eq!(hint, "<redacted>");
    }

    // ── wire_code coverage ─────────────────────────────────────────────────────

    #[test]
    fn wire_code_is_stable_and_non_empty_for_all_variants() {
        let variants: &[IdentityError] = &[
            IdentityError::HomeDomainInvalid {
                detail: "contains uppercase".to_owned(),
            },
            IdentityError::HomeDomainUnresolvable {
                authority: "example.com".to_owned(),
            },
            IdentityError::TomlFetchFailed {
                authority: "example.com".to_owned(),
                reason: "parse error".to_owned(),
            },
            IdentityError::WebAuthEndpointMissing {
                home_domain: "example.com".to_owned(),
            },
            IdentityError::SigningKeyMissing {
                home_domain: "example.com".to_owned(),
            },
            IdentityError::WebAuthEndpointHostMismatch {
                endpoint_host: "evil.org".to_owned(),
                home_domain: "example.com".to_owned(),
            },
            IdentityError::Sep10AuthFailed {
                reason: "challenge expired".to_owned(),
            },
        ];
        for err in variants {
            let code = err.wire_code();
            assert!(!code.is_empty(), "wire_code must be non-empty: {err:?}");
            assert!(
                code.starts_with("identity."),
                "wire_code must start with 'identity.': {code}"
            );
        }
    }

    // ── Display non-leaky checks ──────────────────────────────────────────────

    /// Verify that Display for HomeDomainUnresolvable does NOT include a full
    /// URL path or query — authority-only is the contract.
    #[test]
    fn home_domain_unresolvable_display_is_authority_only() {
        let err = IdentityError::HomeDomainUnresolvable {
            authority: "example.com".to_owned(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("example.com"),
            "display must include authority: {msg}"
        );
        // Must not include path fragments that would indicate full URL leakage.
        assert!(
            !msg.contains("/.well-known/"),
            "display must NOT include URL path: {msg}"
        );
    }

    /// Verify that Display for Sep10AuthFailed does NOT include JWT fragments.
    #[test]
    fn sep10_auth_failed_display_never_includes_jwt() {
        let jwt_like = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJHQUJDIn0.sig";
        let err = IdentityError::Sep10AuthFailed {
            reason: "challenge validation failed".to_owned(),
        };
        let msg = err.to_string();
        // The reason field is caller-controlled (from Sep10Error::Display, which
        // is also redaction-safe).  The JWT itself is never an input to this variant.
        assert!(
            !msg.contains(jwt_like),
            "display must NOT include JWT material: {msg}"
        );
    }
}
