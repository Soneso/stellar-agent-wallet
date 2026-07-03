//! Same-domain SSRF bind for anchor transfer-server URLs.
//!
//! # What this module does
//!
//! Provides [`assert_same_domain_or_https_fqdn`] which enforces the
//! same-domain SSRF guard:
//!
//! > Before fetching `/info` or the interactive endpoint, the crate MUST
//! > assert the resolved `TRANSFER_SERVER*` host is the operator-supplied
//! > anchor domain OR a subdomain of it.
//!
//! The LEADING DOT in the subdomain check is load-bearing:
//! `ends_with(&format!(".{anchor_domain}"))` not `ends_with(anchor_domain)`.
//! The naive `ends_with("anchor.org")` would allow `evil-anchor.org` to
//! match `anchor.org`.
//!
//! # Two-mode operation
//!
//! When `anchor_domain` is supplied, the resolved `TRANSFER_SERVER*` host
//! must exactly match the anchor domain or be a subdomain of it.
//! The `anchor_domain` itself is validated as a public FQDN (≥2 labels, LDH)
//! before the suffix comparison so that an empty or malformed domain cannot
//! degenerate the bind (e.g. `Some("")` would make `subdomain_suffix = "."`
//! and every host ending in `.` would match).
//!
//! When `anchor_domain` is `None` (direct URL input), the URL must be HTTPS
//! and the host must be a public FQDN (≥2 labels, not an IP address).
//!
//! # PSL-free
//!
//! No `publicsuffix` dependency.  The trust anchor is the operator-typed
//! domain, not an extracted eTLD+1.  The binding is a string-level check
//! against the operator-typed value.

use stellar_agent_network::counterparty::validation::is_valid_ldh_home_domain;

use crate::error::AnchorError;

/// Validates a `TRANSFER_SERVER*` URL against the same-domain SSRF bind.
///
/// When `anchor_domain` is `Some(domain)`, asserts:
/// - `domain` is a valid lowercase LDH public FQDN (≥2 labels, not an IP).
///   An empty, single-label, or syntactically invalid domain is rejected with
///   [`AnchorError::InvalidAnchorDomain`] before any URL parse is attempted.
///   This prevents degenerate suffix matches (e.g. `Some("")` → `"."` suffix
///   that matches every host ending in `.`).
/// - The URL is HTTPS.
/// - The URL host equals `domain` OR ends with `".{domain}"` (subdomain).
///   The LEADING DOT prevents `evil-anchor.org` from matching `anchor.org`.
///
/// When `anchor_domain` is `None` (direct URL input), asserts:
/// - The URL is HTTPS.
/// - The URL host is a public FQDN (≥2 labels, not an IP address).
///
/// # Errors
///
/// - [`AnchorError::InvalidAnchorDomain`] — supplied `anchor_domain` is empty,
///   a single label, an IP address, or otherwise invalid as a public FQDN.
/// - [`AnchorError::InvalidDirectUrl`] — URL is not HTTPS, cannot be parsed,
///   or (in `None` mode) the host is an IP or single-label name.
/// - [`AnchorError::TransferServerHostMismatch`] — host does not match the
///   anchor domain or any subdomain of it.
// `pub(crate)` in production; promoted to `pub` when `test-helpers` is enabled
// so integration tests can call it directly.
pub fn assert_same_domain_or_https_fqdn(
    transfer_server_url: &str,
    anchor_domain: Option<&str>,
) -> Result<(), AnchorError> {
    let parsed =
        url::Url::parse(transfer_server_url).map_err(|_| AnchorError::InvalidDirectUrl {
            detail: "transfer server URL is not a valid URL".to_owned(),
        })?;

    // Must be HTTPS in all cases.
    if parsed.scheme() != "https" {
        return Err(AnchorError::InvalidDirectUrl {
            detail: format!(
                "transfer server URL must use https://, got '{}'",
                parsed.scheme()
            ),
        });
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| AnchorError::InvalidDirectUrl {
            detail: "transfer server URL has no host".to_owned(),
        })?;

    // Strip a single trailing dot from the URL host (RFC 1034 FQDN trailing-dot
    // form) before comparison.  A URL like `https://anchor.org./info` is
    // technically valid DNS syntax; stripping the dot gives the canonical form
    // we compare anchor_domain against.
    let host = host.strip_suffix('.').unwrap_or(host);

    match anchor_domain {
        Some(domain) => {
            // SEC: Validate anchor_domain itself BEFORE building the suffix
            // pattern.  Without this, `Some("")` makes `subdomain_suffix = "."`
            // and ANY host ending in `.` would suffix-match (bind degenerates).
            // `Some(".")` or other single-character domains would similarly
            // create overly broad matches.  The fix: reject any anchor_domain
            // that is not a valid public FQDN (same check as direct-URL mode).
            validate_public_fqdn(domain).map_err(|_| AnchorError::InvalidAnchorDomain {
                detail: format!(
                    "anchor_domain '{domain}' is not a valid public FQDN; \
                     must be a lowercase LDH hostname with ≥2 labels and no IP address"
                ),
            })?;

            // Same-domain SSRF bind.
            // EXACT match: `host == domain`
            // SUBDOMAIN match: `host.ends_with(".{domain}")` (LEADING DOT is load-bearing)
            //
            // The leading-dot form `.{domain}` prevents `evil-anchor.org` from
            // matching `anchor.org`:
            //   "evil-anchor.org".ends_with(".anchor.org") == false   ← correct
            //   "transfer.anchor.org".ends_with(".anchor.org") == true ← correct
            //   "anchor.org" == "anchor.org"                  ← exact match covers it
            let subdomain_suffix = format!(".{domain}");
            let is_same_or_subdomain = host == domain || host.ends_with(subdomain_suffix.as_str());

            if !is_same_or_subdomain {
                return Err(AnchorError::TransferServerHostMismatch {
                    anchor_domain: domain.to_owned(),
                    resolved_host: host.to_owned(),
                });
            }
        }
        None => {
            // Direct URL input: require a public FQDN (≥2 labels, not an IP).
            validate_public_fqdn(host)?;
        }
    }

    Ok(())
}

/// Validates a host string as a public FQDN.
///
/// Requirements:
/// - Not an IP address (rejects `192.168.1.1`, `::1`, etc.)
/// - Not a purely numeric dot-separated sequence.
/// - ≥2 labels (rejects `localhost`, `consul`, `metadata`).
/// - Valid lowercase LDH syntax via `is_valid_ldh_home_domain`.
fn validate_public_fqdn(host: &str) -> Result<(), AnchorError> {
    // Reject IP addresses.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err(AnchorError::InvalidDirectUrl {
            detail: format!("'{host}' is an IP address, not a valid FQDN"),
        });
    }

    // Reject purely numeric dot-separated strings.
    let all_labels_numeric = host
        .split('.')
        .all(|label| !label.is_empty() && label.chars().all(|c| c.is_ascii_digit()));
    if all_labels_numeric {
        return Err(AnchorError::InvalidDirectUrl {
            detail: format!("'{host}' consists of numeric labels only; must be a valid FQDN"),
        });
    }

    // Require ≥2 labels (interior dot).
    let label_count = host.split('.').filter(|l| !l.is_empty()).count();
    if label_count < 2 {
        return Err(AnchorError::InvalidDirectUrl {
            detail: format!(
                "'{host}' is a single-label hostname; a valid FQDN requires at least two labels"
            ),
        });
    }

    // Validate LDH syntax.
    if !is_valid_ldh_home_domain(host) {
        return Err(AnchorError::InvalidDirectUrl {
            detail: format!("'{host}' is not a valid lowercase RFC 1035 LDH FQDN"),
        });
    }

    Ok(())
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

    // ── Same-domain SSRF bind tests ───────────────────────────────────────────

    /// Adversarial test: `TRANSFER_SERVER` host differs from anchor domain.
    ///
    /// A `TRANSFER_SERVER` pointing to a different host than the anchor domain
    /// must be rejected before any fetch is attempted.
    #[test]
    fn transfer_server_host_mismatch_is_rejected() {
        let result = assert_same_domain_or_https_fqdn(
            "https://cdn.example.com/sep6",
            Some("testanchor.stellar.org"),
        );
        assert!(
            matches!(result, Err(AnchorError::TransferServerHostMismatch { .. })),
            "host mismatch must return TransferServerHostMismatch; got: {result:?}"
        );
    }

    /// Adversarial test: `evil-anchor.org` must NOT match `anchor.org`.
    ///
    /// The LEADING DOT is load-bearing: naive `ends_with('anchor.org')` would
    /// allow `evil-anchor.org` to match.
    #[test]
    fn evil_anchor_does_not_match_anchor_org() {
        let result =
            assert_same_domain_or_https_fqdn("https://evil-anchor.org/sep6", Some("anchor.org"));
        assert!(
            matches!(result, Err(AnchorError::TransferServerHostMismatch { .. })),
            "evil-anchor.org must NOT match anchor.org; got: {result:?}"
        );
    }

    /// Subdomain test: `transfer.anchor.org` MUST match `anchor.org`.
    #[test]
    fn subdomain_transfer_anchor_org_is_accepted() {
        let result = assert_same_domain_or_https_fqdn(
            "https://transfer.anchor.org/sep6",
            Some("anchor.org"),
        );
        assert!(
            result.is_ok(),
            "transfer.anchor.org must be accepted as a subdomain of anchor.org; got: {result:?}"
        );
    }

    /// Exact match: `anchor.org` must match `anchor.org`.
    #[test]
    fn exact_match_anchor_domain_is_accepted() {
        let result =
            assert_same_domain_or_https_fqdn("https://anchor.org/sep6", Some("anchor.org"));
        assert!(
            result.is_ok(),
            "anchor.org must match anchor.org (exact); got: {result:?}"
        );
    }

    /// Multi-level subdomain `a.b.anchor.org` must match `anchor.org`.
    #[test]
    fn multi_level_subdomain_is_accepted() {
        let result =
            assert_same_domain_or_https_fqdn("https://a.b.anchor.org/sep6", Some("anchor.org"));
        assert!(
            result.is_ok(),
            "a.b.anchor.org must be accepted as a subdomain of anchor.org; got: {result:?}"
        );
    }

    /// HTTP (not HTTPS) is rejected even when host matches.
    #[test]
    fn http_scheme_is_rejected() {
        let result = assert_same_domain_or_https_fqdn("http://anchor.org/sep6", Some("anchor.org"));
        assert!(
            matches!(result, Err(AnchorError::InvalidDirectUrl { .. })),
            "http:// must be rejected; got: {result:?}"
        );
    }

    // ── anchor_domain validation tests ───────────────────────────────────────

    /// SEC: empty anchor_domain MUST be rejected.
    ///
    /// Without this guard, `Some("")` → `subdomain_suffix = "."` and ANY host
    /// ending in `.` would suffix-match (bind degenerates).
    #[test]
    fn empty_anchor_domain_is_rejected() {
        let result =
            assert_same_domain_or_https_fqdn("https://transfer.example.com/sep6", Some(""));
        assert!(
            matches!(result, Err(AnchorError::InvalidAnchorDomain { .. })),
            "empty anchor_domain must return InvalidAnchorDomain; got: {result:?}"
        );
    }

    /// SEC: single-dot anchor_domain MUST be rejected.
    ///
    /// `Some(".")` → `subdomain_suffix = ".."` — still overly broad.
    #[test]
    fn dot_only_anchor_domain_is_rejected() {
        let result =
            assert_same_domain_or_https_fqdn("https://transfer.example.com/sep6", Some("."));
        assert!(
            matches!(result, Err(AnchorError::InvalidAnchorDomain { .. })),
            "single-dot anchor_domain must return InvalidAnchorDomain; got: {result:?}"
        );
    }

    /// SEC: single-label anchor_domain is rejected (no interior dot).
    #[test]
    fn single_label_anchor_domain_is_rejected() {
        let result =
            assert_same_domain_or_https_fqdn("https://transfer.example.com/sep6", Some("example"));
        assert!(
            matches!(result, Err(AnchorError::InvalidAnchorDomain { .. })),
            "single-label anchor_domain must be rejected; got: {result:?}"
        );
    }

    /// SEC: IP address as anchor_domain is rejected.
    #[test]
    fn ip_anchor_domain_is_rejected() {
        let result =
            assert_same_domain_or_https_fqdn("https://192.168.1.1/sep6", Some("192.168.1.1"));
        assert!(
            matches!(result, Err(AnchorError::InvalidAnchorDomain { .. })),
            "IP anchor_domain must be rejected; got: {result:?}"
        );
    }

    // ── Trailing-dot host stripping ───────────────────────────────────────────

    /// URL host with trailing dot (`anchor.org.`) is canonicalised before
    /// comparison.  RFC 1034 allows a trailing dot in fully-qualified domain
    /// names; stripping it before comparing makes `anchor.org.` == `anchor.org`.
    #[test]
    fn trailing_dot_host_is_accepted_after_strip() {
        // `url` crate preserves the trailing dot in host_str() for URLs like
        // `https://anchor.org./`.  We strip it before comparing.
        let result =
            assert_same_domain_or_https_fqdn("https://anchor.org./sep6", Some("anchor.org"));
        assert!(
            result.is_ok(),
            "host 'anchor.org.' (trailing dot) must match 'anchor.org' after strip; got: {result:?}"
        );
    }

    // ── Direct URL mode (anchor_domain = None) ────────────────────────────────

    #[test]
    fn direct_url_valid_fqdn_is_accepted() {
        let result = assert_same_domain_or_https_fqdn("https://transfer.example.com/sep6", None);
        assert!(
            result.is_ok(),
            "valid FQDN must be accepted; got: {result:?}"
        );
    }

    #[test]
    fn direct_url_ip_address_is_rejected() {
        let result = assert_same_domain_or_https_fqdn("https://192.168.1.1/sep6", None);
        assert!(
            matches!(result, Err(AnchorError::InvalidDirectUrl { .. })),
            "IP address must be rejected in direct-URL mode; got: {result:?}"
        );
    }

    #[test]
    fn direct_url_single_label_is_rejected() {
        let result = assert_same_domain_or_https_fqdn("https://localhost/sep6", None);
        assert!(
            matches!(result, Err(AnchorError::InvalidDirectUrl { .. })),
            "single-label 'localhost' must be rejected in direct-URL mode; got: {result:?}"
        );
    }

    #[test]
    fn direct_url_internal_metadata_rejected() {
        // `metadata` is a single-label name often used for cloud metadata endpoints.
        let result = assert_same_domain_or_https_fqdn("https://metadata/sep6", None);
        assert!(
            matches!(result, Err(AnchorError::InvalidDirectUrl { .. })),
            "metadata single-label must be rejected; got: {result:?}"
        );
    }

    /// Internal IP `169.254.169.254` must be rejected in direct-URL mode.
    #[test]
    fn direct_url_link_local_ip_is_rejected() {
        let result = assert_same_domain_or_https_fqdn("https://169.254.169.254/sep6", None);
        assert!(
            matches!(result, Err(AnchorError::InvalidDirectUrl { .. })),
            "169.254.169.254 must be rejected; got: {result:?}"
        );
    }
}
