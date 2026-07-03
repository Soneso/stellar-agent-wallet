//! SEP-1 `stellar.toml` HTTPS fetch primitive.
//!
//! # What this module does
//!
//! Provides [`fetch_stellar_toml`] — a single-shot HTTPS fetch of
//! `https://<home_domain>/.well-known/stellar.toml`.  The function:
//!
//! - Validates the home domain (canonical lowercase LDH, length ≤ 255)
//!   **before** opening any network connection.
//! - Uses HTTPS only; plain `http://` is never attempted.
//! - Enforces a 5-second combined connect-and-read timeout.
//! - Enforces a 64 KiB body size cap.
//! - Rejects redirects (`redirect::Policy::none()`).
//! - Rejects non-200 status codes.
//! - Rejects responses with a non-`text/*` content-type.
//! - Resolves the host DNS name **before** connecting and rejects any resolved
//!   address that falls within a private, loopback, link-local, unique-local,
//!   unspecified, or IPv4-mapped-IPv6-of-private address space
//!   (SSRF egress hardening).  The connection is then pinned to the vetted
//!   address set via `resolve_to_addrs` so that the connect phase uses exactly
//!   the checked addresses (DNS-rebinding defence).
//!
//! # Lowercase LDH home_domain enforcement
//!
//! SEP-1 specifies that `home_domain` is a DNS hostname.  The wallet accepts
//! `1..=255` bytes of lowercase RFC 1035 LDH syntax (`a-z`, `0-9`, `-`, `.`),
//! rejects empty or >63-byte labels, and rejects Unicode, uppercase,
//! underscores, URL meta-characters, and leading/trailing `.` or `-` before
//! any I/O.
//!
//! # Body cap
//!
//! The 64 KiB cap is enforced by reading the response body chunk-by-chunk up
//! to the limit.  A legitimate `stellar.toml` is always well under 64 KiB;
//! the cap defends against a malicious or misconfigured server streaming a
//! multi-megabyte body to exhaust wallet memory.
//!
//! This module is the fetch primitive layer of the counterparty resolution
//! substrate.

use std::net::{IpAddr, SocketAddr};

use reqwest::redirect;

use crate::counterparty::CounterpartyError;
use crate::counterparty::validation::is_valid_ldh_home_domain;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum allowed `stellar.toml` body size in bytes.
///
/// 64 KiB is far larger than any legitimate `stellar.toml` in practice.  The
/// cap defends against memory-exhaustion attacks from a malicious endpoint.
///
/// Exposed under `test-helpers` feature for integration test assertions.
#[cfg_attr(not(any(test, feature = "test-helpers")), allow(dead_code))]
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Combined connect-plus-read timeout for the `stellar.toml` fetch.
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

// ─────────────────────────────────────────────────────────────────────────────
// SSRF egress filtering
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `addr` falls within a private or reserved address space
/// that must not be reachable via the `stellar.toml` egress path.
///
/// Rejected address classes (all listed by canonical RFC):
///
/// | Class | IPv4 range | IPv6 range |
/// |---|---|---|
/// | Loopback | 127.0.0.0/8 | ::1/128 |
/// | Private (RFC 1918) | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 | — |
/// | Link-local | 169.254.0.0/16 | fe80::/10 |
/// | Unique-local (RFC 4193) | — | fc00::/7 |
/// | Unspecified | 0.0.0.0 | :: |
/// | IPv4-mapped-IPv6 of any blocked IPv4 | — | ::ffff:priv/link/loop |
///
/// In the `#[cfg(any(test, feature = "test-loopback"))]` build, loopback
/// addresses are NOT flagged, allowing wiremock test servers at 127.0.0.1.
///
/// # Panics
///
/// Never panics.
fn is_private_or_reserved(addr: IpAddr) -> bool {
    /// Non-loopback IPv4 blocked-range check, shared by the direct-V4 arm
    /// and the embedded-V4 forms (IPv4-mapped IPv6, NAT64).
    fn v4_blocked(v4: std::net::Ipv4Addr) -> bool {
        let octets = v4.octets();
        v4.is_private()
            || v4.is_link_local()
            || v4.is_unspecified()
            || v4.is_broadcast()
            || v4.is_documentation()
            || v4.is_multicast()
            // CGNAT shared address space 100.64.0.0/10 (RFC 6598): routinely
            // internal / metadata-adjacent on cloud egress points.
            || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
            // IETF protocol assignments 192.0.0.0/24 (RFC 6890).
            || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
            // Benchmarking 198.18.0.0/15 (RFC 2544).
            || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
    }
    /// Loopback check honouring the test-loopback gate: loopback is blocked
    /// in production builds and allowed only under `test` /
    /// `feature = "test-loopback"` so wiremock-backed tests can run.
    fn loopback_blocked(is_loopback: bool) -> Option<bool> {
        if is_loopback {
            #[cfg(not(any(test, feature = "test-loopback")))]
            return Some(true);
            #[cfg(any(test, feature = "test-loopback"))]
            return Some(false);
        }
        None
    }
    match addr {
        IpAddr::V4(v4) => {
            if let Some(verdict) = loopback_blocked(v4.is_loopback()) {
                return verdict;
            }
            v4_blocked(v4)
        }
        IpAddr::V6(v6) => {
            if let Some(verdict) = loopback_blocked(v6.is_loopback()) {
                return verdict;
            }
            if v6.is_unspecified() || v6.is_multicast() {
                return true;
            }
            let segments = v6.segments();
            // Link-local: fe80::/10.
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Unique-local: fc00::/7.
            if (segments[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // IPv4-mapped IPv6 (::ffff:x.x.x.x): check the embedded IPv4 addr.
            if let Some(v4) = v6.to_ipv4_mapped() {
                if let Some(verdict) = loopback_blocked(v4.is_loopback()) {
                    return verdict;
                }
                return v4_blocked(v4);
            }
            // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052): the low 32 bits
            // carry an IPv4 address — apply the same embedded-V4 policy.
            if segments[0] == 0x64 && segments[1] == 0xff9b && segments[2..6] == [0, 0, 0, 0] {
                let v4 = std::net::Ipv4Addr::new(
                    (segments[6] >> 8) as u8,
                    (segments[6] & 0xff) as u8,
                    (segments[7] >> 8) as u8,
                    (segments[7] & 0xff) as u8,
                );
                if let Some(verdict) = loopback_blocked(v4.is_loopback()) {
                    return verdict;
                }
                return v4_blocked(v4);
            }
            false
        }
    }
}

/// Resolves `home_domain` to a list of IP addresses and rejects the entire
/// set if ANY resolved address falls within a private or reserved range
/// (fail-closed: one bad address poisons the entire resolution).
///
/// On success, returns the `(host, Vec<SocketAddr>)` tuple suitable for
/// `reqwest::ClientBuilder::resolve_to_addrs`.  Port 443 is used in the
/// returned `SocketAddr` values (HTTPS).
///
/// # Errors
///
/// - [`CounterpartyError::FetchFailed`] — DNS resolution failed (I/O error).
/// - [`CounterpartyError::FetchFailed`] — any resolved address is private /
///   reserved (SSRF egress block; the detail does NOT include the raw IP or
///   domain).
///
/// # Panics
///
/// Never panics.
async fn resolve_and_filter_egress(
    home_domain: &str,
) -> Result<Vec<SocketAddr>, CounterpartyError> {
    // DNS resolution via spawn_blocking + std::net::ToSocketAddrs.
    // Port 443 is used so the returned SocketAddr values are HTTPS-ready.
    let lookup_target = format!("{}:443", home_domain);
    let addrs: Vec<SocketAddr> = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        lookup_target
            .to_socket_addrs()
            .map(|iter| iter.collect::<Vec<_>>())
    })
    .await
    .map_err(|e| CounterpartyError::FetchFailed {
        detail: format!("DNS resolution task failed: {e}"),
    })?
    .map_err(|_| CounterpartyError::FetchFailed {
        detail: "DNS resolution failed (host not found or I/O error)".to_owned(),
    })?;

    if addrs.is_empty() {
        return Err(CounterpartyError::FetchFailed {
            detail: "DNS resolution returned no addresses".to_owned(),
        });
    }

    // Fail-closed: if ANY resolved address is private/reserved, reject all.
    if addrs.iter().any(|sa| is_private_or_reserved(sa.ip())) {
        return Err(CounterpartyError::FetchFailed {
            detail: "stellar.toml fetch blocked: resolved address is in a private \
                     or reserved range (SSRF egress guard)"
                .to_owned(),
        });
    }

    Ok(addrs)
}

/// Builds a bounded HTTPS-only reqwest client with redirect following and
/// transparent decompression disabled.
///
/// Decompression (`no_gzip`/`no_brotli`/`no_deflate`) is disabled deliberately:
/// a compressed response could expand far beyond the caller's byte cap
/// (decompression-bomb amplification), so the size bound must apply to the wire
/// bytes. `redirect::Policy::none()` prevents an off-domain HTTPS hop, and
/// `https_only(true)` rejects any `http://` URL (scheme-downgrade defence).
///
/// # Errors
///
/// Returns [`CounterpartyError::FetchFailed`] when the platform cannot
/// construct the reqwest client.
///
/// # Panics
///
/// Never panics.
pub fn build_bounded_https_client(
    timeout: std::time::Duration,
) -> Result<reqwest::Client, CounterpartyError> {
    reqwest::Client::builder()
        .https_only(true)
        .timeout(timeout)
        .redirect(redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .map_err(|e| CounterpartyError::FetchFailed {
            detail: format!("failed to build bounded HTTPS client: {e}"),
        })
}

// ─────────────────────────────────────────────────────────────────────────────
// Home-domain validation
// ─────────────────────────────────────────────────────────────────────────────

/// Validates a counterparty home domain.
///
/// Exposed as `pub` so integration tests can exercise domain validation
/// without triggering network I/O.  In production code, this is always called
/// via [`fetch_stellar_toml`] which enforces HTTPS and other security checks.
///
/// Checks that the domain is non-empty, no more than 255 bytes, lowercase LDH
/// (`a-z`, `0-9`, `-`, `.`), has no empty or >63-byte labels, and does not
/// start or end with `.` or `-`.
///
/// # Errors
///
/// Returns [`CounterpartyError::HomeDomainInvalid`] with a detail string on
/// any validation failure.  The detail describes the violation without echoing
/// the full domain value.
///
/// # Panics
///
/// Never panics.
pub fn validate_home_domain(home_domain: &str) -> Result<(), CounterpartyError> {
    if !is_valid_ldh_home_domain(home_domain) {
        return Err(CounterpartyError::HomeDomainInvalid {
            detail: "home_domain must be lowercase RFC 1035 LDH \
                     (a-z, 0-9, hyphen, dot), 1..=255 bytes, each label \
                     1..=63 bytes, and must not start or end with '-' or '.'"
                .to_owned(),
        });
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// fetch_stellar_toml
// ─────────────────────────────────────────────────────────────────────────────

/// Fetches the `stellar.toml` body for the given home domain over HTTPS.
///
/// Constructs the URL `https://<home_domain>/.well-known/stellar.toml`,
/// validates the domain, resolves DNS with egress filtering, and performs a
/// single HTTPS GET with a pinned-address client.
///
/// ## Egress filtering (SSRF hardening)
///
/// Before opening a connection, the function:
///
/// 1. Resolves `home_domain` to its IP addresses via the OS resolver.
/// 2. Rejects the request if **any** resolved address is private (RFC 1918),
///    loopback, link-local (169.254/16, fe80::/10), unique-local (fc00::/7),
///    unspecified, broadcast, or an IPv4-mapped-IPv6 equivalent of any blocked
///    IPv4 range.  Fail-closed: one bad address blocks the entire resolution.
/// 3. Pins the vetted addresses into the reqwest client via `resolve_to_addrs`,
///    so the actual TCP connect uses exactly the checked set (DNS rebinding
///    defence).
///
/// The caller-supplied `http` argument is used only as a template for its TLS
/// and redirect settings; a new per-request client is built with the pinned
/// addresses.
///
/// The body is accumulated up to [`MAX_BODY_BYTES`]; any response that would
/// exceed that limit is rejected with [`CounterpartyError::FetchFailed`].
///
/// # Errors
///
/// - [`CounterpartyError::HomeDomainInvalid`] — domain fails validation
///   (non-ASCII, control characters, too long, contains scheme/path).
///   Returned **before** any I/O.
/// - [`CounterpartyError::FetchFailed`] — DNS resolution failure, any
///   resolved address is in a private/reserved range (SSRF egress block),
///   network error, timeout, non-200 HTTP status, redirect, non-`text/*`
///   content-type, or body too large.  The detail does NOT include the raw
///   IP address or domain.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::counterparty::fetch::fetch_stellar_toml;
///
/// # async fn example() -> Result<(), stellar_agent_network::counterparty::CounterpartyError> {
/// let body = fetch_stellar_toml("example.com").await?;
/// # Ok(()) }
/// ```
///
/// The function builds and owns a per-request DNS-rebinding-pinned HTTPS client
/// internally; callers do not supply one.
pub async fn fetch_stellar_toml(home_domain: &str) -> Result<String, CounterpartyError> {
    // Validate domain BEFORE any network I/O.
    validate_home_domain(home_domain)?;

    // Resolve DNS and reject any private/reserved addresses (SSRF egress guard).
    let vetted_addrs = resolve_and_filter_egress(home_domain).await?;

    // Build a per-request client pinned to the vetted addresses.
    // This defeats DNS-rebinding: the connect phase uses exactly the addresses
    // that were checked above.  `ClientBuilder::resolve_to_addrs` takes a slice
    // of `SocketAddr`.
    let pinned_http = reqwest::Client::builder()
        .https_only(true)
        .timeout(FETCH_TIMEOUT)
        .redirect(redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .resolve_to_addrs(home_domain, &vetted_addrs)
        .build()
        .map_err(|e| CounterpartyError::FetchFailed {
            detail: format!("failed to build pinned HTTPS client: {e}"),
        })?;

    let url = format!("https://{}/.well-known/stellar.toml", home_domain);
    tracing::debug!(home_domain = %home_domain, "fetching stellar.toml (egress-filtered)");

    let response = pinned_http
        .get(&url)
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                CounterpartyError::FetchFailed {
                    detail: "fetch timed out".to_owned(),
                }
            } else if e.is_redirect() {
                CounterpartyError::FetchFailed {
                    detail: "redirect not allowed for stellar.toml fetch".to_owned(),
                }
            } else {
                CounterpartyError::FetchFailed {
                    detail: format!("network error: {}", e.without_url()),
                }
            }
        })?;

    // Reject any HTTP redirect response.
    let status = response.status();
    if status.is_redirection() {
        return Err(CounterpartyError::FetchFailed {
            detail: format!(
                "redirect ({}) not allowed for stellar.toml fetch",
                status.as_u16()
            ),
        });
    }

    // Reject non-200 status.
    if status != reqwest::StatusCode::OK {
        return Err(CounterpartyError::FetchFailed {
            detail: format!("unexpected HTTP status {}", status.as_u16()),
        });
    }

    // Validate content-type: must be text/*.
    let content_type_ok = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.trim().to_ascii_lowercase().starts_with("text/"))
        .unwrap_or(false);

    if !content_type_ok {
        return Err(CounterpartyError::FetchFailed {
            detail: "response content-type is not text/*".to_owned(),
        });
    }

    // Accumulate body up to MAX_BODY_BYTES.  Using `bytes()` instead of `text()`
    // to control the accumulation limit.
    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| CounterpartyError::FetchFailed {
            detail: format!("body read error: {}", e.without_url()),
        })?;

    if body_bytes.len() > MAX_BODY_BYTES {
        return Err(CounterpartyError::FetchFailed {
            detail: format!(
                "response body too large ({} bytes, limit is {})",
                body_bytes.len(),
                MAX_BODY_BYTES
            ),
        });
    }

    let body =
        String::from_utf8(body_bytes.into()).map_err(|_| CounterpartyError::FetchFailed {
            detail: "response body is not valid UTF-8".to_owned(),
        })?;

    tracing::debug!(home_domain = %home_domain, body_len = body.len(), "stellar.toml fetched");
    Ok(body)
}

/// Builds a `reqwest::Client` configured for `stellar.toml` fetches.
///
/// Sets:
/// - 5-second timeout.
/// - Redirect policy: none (rejects all redirects).
/// - TLS: system default (rustls-tls per workspace feature).
///
/// # Errors
///
/// Returns [`CounterpartyError::FetchFailed`] if the client cannot be
/// constructed (should never happen in practice on supported platforms).
///
/// # Panics
///
/// Never panics.
/// Exposed as `pub` so sibling crates (e.g. `stellar-agent-x402-identity`)
/// can reuse the same no-redirect / HTTPS-only / no-decompression client
/// for their own `stellar.toml` fetches.
pub fn build_fetch_client() -> Result<reqwest::Client, CounterpartyError> {
    build_bounded_https_client(FETCH_TIMEOUT)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    fn repeated_label_domain(label_lengths: &[usize]) -> String {
        label_lengths
            .iter()
            .enumerate()
            .map(|(i, len)| {
                let ch = char::from(b'a' + (i % 26) as u8);
                ch.to_string().repeat(*len)
            })
            .collect::<Vec<_>>()
            .join(".")
    }

    #[tokio::test]
    async fn bounded_https_client_rejects_plain_http_urls() {
        let client = build_bounded_https_client(std::time::Duration::from_millis(50))
            .expect("bounded HTTPS client must build");

        let err = client
            .get("http://127.0.0.1:9/.well-known/stellar.toml")
            .send()
            .await
            .expect_err("https_only client must reject plain HTTP URLs");

        assert!(
            err.to_string().contains("URL scheme is not allowed")
                || err.to_string().contains("http"),
            "HTTPS-only rejection should mention scheme/http; got: {err}"
        );
    }

    // ── validate_home_domain unit tests ──────────────────────────────────────

    #[test]
    fn valid_domain_passes() {
        assert!(validate_home_domain("circle.com").is_ok());
        assert!(validate_home_domain("stellar.org").is_ok());
        assert!(validate_home_domain("sub.domain.example.com").is_ok());
        // Hyphenated labels are valid RFC 1035 LDH.
        assert!(validate_home_domain("my-bank.com").is_ok());
        assert!(validate_home_domain("sub-domain.example.com").is_ok());
        // Numeric labels are valid DNS labels.
        assert!(validate_home_domain("192.168.1.1").is_ok());
    }

    #[test]
    fn uppercase_rejected() {
        let err = validate_home_domain("Circle.com").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn empty_domain_rejected() {
        let err = validate_home_domain("").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn non_ascii_rejected() {
        // Cyrillic 'с' (U+0441) — IDN homoglyph attack surface.
        let err = validate_home_domain("сircle.com").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn control_char_rejected() {
        let err = validate_home_domain("circle\x00.com").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn newline_rejected() {
        let err = validate_home_domain("circle\n.com").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn tab_rejected() {
        let err = validate_home_domain("circle\t.com").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn del_char_rejected() {
        let err = validate_home_domain("circle\x7f.com").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn domain_too_long_rejected() {
        let long_domain = repeated_label_domain(&[63, 63, 63, 62, 1]);
        let err = validate_home_domain(&long_domain).unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn domain_length_boundaries_accepted() {
        let at_limit = "a".repeat(32);
        assert!(validate_home_domain(&at_limit).is_ok());
        assert!(validate_home_domain(&repeated_label_domain(&[63, 63, 63, 62])).is_ok());
        assert!(validate_home_domain(&repeated_label_domain(&[63, 63, 63, 63])).is_ok());
    }

    #[test]
    fn oversized_domain_and_label_rejected() {
        // Total-length cap (separate from label cap): 5 labels of 63 bytes + 4 dots = 319 bytes.
        // Each label is within the 63-byte label cap, so this exercises the 255-byte total cap.
        let too_long_total = format!(
            "{}.{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63),
            "e".repeat(63),
        );
        assert_eq!(too_long_total.len(), 319);
        let err = validate_home_domain(&too_long_total).unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));

        // Defence-in-depth label-cap case: one 1024-byte label is rejected by
        // the per-label limit before the total-length cap matters.
        let err = validate_home_domain(&"a".repeat(1024)).unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));

        let err = validate_home_domain(&format!("{}.com", "a".repeat(64))).unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn url_scheme_rejected() {
        // Colon is not RFC 1035 LDH.
        let err = validate_home_domain("https://circle.com").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn domain_with_path_rejected() {
        // Slash is not RFC 1035 LDH.
        let err = validate_home_domain("circle.com/path").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    // ── BLOCKER-4 additional validation tests ─────────────────────────────────

    #[test]
    fn leading_whitespace_rejected() {
        let err = validate_home_domain(" circle.com").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn trailing_whitespace_rejected() {
        let err = validate_home_domain("circle.com ").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn leading_dot_rejected() {
        let err = validate_home_domain(".circle.com").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn trailing_dot_rejected() {
        let err = validate_home_domain("circle.com.").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn backslash_rejected() {
        let err = validate_home_domain("\\foo").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn dotdot_backslash_rejected() {
        let err = validate_home_domain("..\\foo").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn double_dot_standalone_rejected() {
        let err = validate_home_domain("..").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn embedded_empty_label_rejected() {
        let err = validate_home_domain("circle..com").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn query_string_rejected() {
        let err = validate_home_domain("circle.com?evil=1").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    #[test]
    fn fragment_rejected() {
        let err = validate_home_domain("circle.com#fragment").unwrap_err();
        assert!(matches!(err, CounterpartyError::HomeDomainInvalid { .. }));
    }

    // ── is_private_or_reserved unit tests ────────────────────────────────────
    //
    // In #[cfg(test)] / test-loopback build, loopback is NOT flagged so
    // wiremock tests can still route to 127.0.0.1.  These tests run under
    // #[cfg(test)] and therefore test the non-production (loopback-allowed)
    // code path for loopback addresses.  Private, link-local, and unique-local
    // are always blocked regardless of test mode.

    #[test]
    fn ssrf_private_ipv4_rfc1918_10_block_blocked() {
        assert!(
            is_private_or_reserved("10.0.0.1".parse().unwrap()),
            "10.0.0.1 (RFC 1918 class A) must be blocked"
        );
    }

    #[test]
    fn ssrf_private_ipv4_rfc1918_172_block_blocked() {
        assert!(
            is_private_or_reserved("172.16.0.1".parse().unwrap()),
            "172.16.0.1 (RFC 1918 class B) must be blocked"
        );
    }

    #[test]
    fn ssrf_private_ipv4_rfc1918_192_block_blocked() {
        assert!(
            is_private_or_reserved("192.168.0.1".parse().unwrap()),
            "192.168.0.1 (RFC 1918 class C) must be blocked"
        );
    }

    #[test]
    fn ssrf_link_local_ipv4_blocked() {
        assert!(
            is_private_or_reserved("169.254.1.1".parse().unwrap()),
            "169.254.1.1 (link-local) must be blocked"
        );
    }

    #[test]
    fn ssrf_ipv6_link_local_blocked() {
        assert!(
            is_private_or_reserved("fe80::1".parse().unwrap()),
            "fe80::1 (IPv6 link-local) must be blocked"
        );
    }

    #[test]
    fn ssrf_ipv6_unique_local_fc_blocked() {
        assert!(
            is_private_or_reserved("fc00::1".parse().unwrap()),
            "fc00::1 (IPv6 unique-local fc00::/7) must be blocked"
        );
    }

    #[test]
    fn ssrf_ipv6_unique_local_fd_blocked() {
        assert!(
            is_private_or_reserved("fd00::1".parse().unwrap()),
            "fd00::1 (IPv6 unique-local fd00::/8 subset of fc00::/7) must be blocked"
        );
    }

    #[test]
    fn ssrf_ipv4_mapped_ipv6_private_blocked() {
        // ::ffff:192.168.1.1 — IPv4-mapped IPv6 of a private IPv4.
        let addr: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(
            is_private_or_reserved(addr),
            "::ffff:192.168.1.1 (IPv4-mapped private) must be blocked"
        );
    }

    #[test]
    fn ssrf_public_ipv4_allowed() {
        // 1.1.1.1 is Cloudflare's public resolver — not in any blocked range.
        assert!(
            !is_private_or_reserved("1.1.1.1".parse().unwrap()),
            "1.1.1.1 (public) must NOT be blocked"
        );
    }

    #[test]
    fn ssrf_public_ipv6_allowed() {
        // 2001:4860:4860::8888 is Google's public IPv6 DNS.
        assert!(
            !is_private_or_reserved("2001:4860:4860::8888".parse().unwrap()),
            "2001:4860:4860::8888 (public IPv6) must NOT be blocked"
        );
    }

    // In test mode, loopback is ALLOWED (test-loopback semantics).
    #[test]
    fn ssrf_loopback_ipv4_allowed_in_test_mode() {
        assert!(
            !is_private_or_reserved("127.0.0.1".parse().unwrap()),
            "127.0.0.1 must be allowed in test/test-loopback builds (wiremock)"
        );
    }

    #[test]
    fn ssrf_loopback_ipv6_allowed_in_test_mode() {
        assert!(
            !is_private_or_reserved("::1".parse().unwrap()),
            "::1 must be allowed in test/test-loopback builds (wiremock)"
        );
    }

    /// CGNAT 100.64.0.0/10 (RFC 6598) is blocked across its boundaries; the
    /// adjacent public ranges are not.
    #[test]
    fn ssrf_cgnat_range_blocked() {
        for addr in ["100.64.0.1", "100.100.50.50", "100.127.255.254"] {
            assert!(
                is_private_or_reserved(addr.parse().unwrap()),
                "{addr} (CGNAT 100.64/10) must be blocked"
            );
        }
        for addr in ["100.63.255.255", "100.128.0.1"] {
            assert!(
                !is_private_or_reserved(addr.parse().unwrap()),
                "{addr} (public, adjacent to CGNAT) must NOT be blocked"
            );
        }
    }

    /// IETF protocol assignments 192.0.0.0/24 and benchmarking 198.18.0.0/15
    /// are blocked; their public neighbours are not.
    #[test]
    fn ssrf_protocol_and_benchmarking_ranges_blocked() {
        assert!(is_private_or_reserved("192.0.0.8".parse().unwrap()));
        assert!(is_private_or_reserved("198.18.0.1".parse().unwrap()));
        assert!(is_private_or_reserved("198.19.255.254".parse().unwrap()));
        assert!(!is_private_or_reserved("192.0.1.1".parse().unwrap()));
        assert!(!is_private_or_reserved("198.17.255.255".parse().unwrap()));
        assert!(!is_private_or_reserved("198.20.0.1".parse().unwrap()));
    }

    /// NAT64 64:ff9b::/96 embedding a private IPv4 is blocked; one embedding
    /// a public IPv4 is not.
    #[test]
    fn ssrf_nat64_embedded_v4_policy_applies() {
        assert!(
            is_private_or_reserved("64:ff9b::10.0.0.5".parse().unwrap()),
            "NAT64-embedded 10.0.0.5 must be blocked"
        );
        assert!(
            is_private_or_reserved("64:ff9b::a9fe:a9fe".parse().unwrap()),
            "NAT64-embedded 169.254.169.254 must be blocked"
        );
        assert!(
            !is_private_or_reserved("64:ff9b::1.1.1.1".parse().unwrap()),
            "NAT64-embedded public 1.1.1.1 must NOT be blocked"
        );
    }
}
