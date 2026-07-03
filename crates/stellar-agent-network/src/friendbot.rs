//! Friendbot account funding via HTTP GET, and URL allow-list validation.
//!
//! `fund_with_friendbot` makes a single async HTTP GET to the Stellar
//! Friendbot endpoint via `reqwest`. Mainnet is rejected structurally —
//! the function returns
//! `WalletError::Network(NetworkError::FriendbotMainnetForbidden)` before
//! any network call when the passphrase matches the Stellar mainnet
//! network passphrase.
//!
//! # URL allow-listing
//!
//! `validate_friendbot_url` enforces a compile-time constant allow-list of
//! permitted Friendbot hosts (`ALLOWED_FRIENDBOT_HOSTS`).  Non-HTTPS URLs
//! and hosts not on the list are rejected with a typed [`FriendbotUrlError`].
//! The validation applies to both the MCP tool and the CLI command (with a
//! CLI-only `--friendbot-url-unchecked` escape for test/development use).

use serde::{Deserialize, Serialize};

use stellar_agent_core::error::{NetworkError, WalletError};

use crate::redact::{redact_rpc_error, redact_url_authority};

/// Mainnet passphrase — structurally rejected for Friendbot calls.
const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

// ─────────────────────────────────────────────────────────────────────────────
// Friendbot URL allow-list
// ─────────────────────────────────────────────────────────────────────────────

/// Allowed Friendbot host names.
///
/// Only HTTPS requests to these hosts are accepted by [`validate_friendbot_url`].
/// The list is a `pub const` array of `&'static str` so it can be compared
/// statically without heap allocation.
///
/// Entries: the SDF testnet Friendbot and the SDF futurenet Friendbot.
/// Per-profile host customisation is deferred to a future release.
///
/// # Security note
///
/// The MCP tool rejects unconditionally any URL not on this list.
/// The CLI command adds a `--friendbot-url-unchecked` escape hatch for
/// development use.
pub const ALLOWED_FRIENDBOT_HOSTS: &[&str] =
    &["friendbot.stellar.org", "friendbot-futurenet.stellar.org"];

/// Errors returned by [`validate_friendbot_url`] and
/// [`validate_friendbot_url_allowing_loopback`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FriendbotUrlError {
    /// The URL could not be parsed.
    #[error("invalid friendbot URL: {0}")]
    InvalidUrl(String),

    /// The URL scheme is not HTTPS.
    #[error("non-HTTPS friendbot URL not allowed: {0}")]
    NonHttps(String),

    /// The URL's host is not in the allow-list.
    #[error("friendbot host '{host}' not in allow-list (allowed: {allowed})")]
    HostNotAllowed {
        /// The rejected host.
        host: String,
        /// Human-readable list of allowed hosts.
        allowed: String,
    },

    /// The URL contains embedded credentials (userinfo).
    ///
    /// Friendbot URLs must not contain a `user:password@host` component.
    /// Embedded credentials can leak into logs and error envelopes.
    #[error("{0}")]
    CredentialsInUrl(String),
}

/// Validates a Friendbot endpoint URL against the production allow-list.
///
/// Accepts only URLs with:
/// 1. HTTPS scheme.
/// 2. A host name present in [`ALLOWED_FRIENDBOT_HOSTS`].
///
/// This function is used by the MCP `stellar_friendbot` tool and (by default)
/// the CLI `friendbot` command.  The MCP tool has no escape hatch; the CLI
/// command adds `--friendbot-url-unchecked` for development/test use.
///
/// # Errors
///
/// - [`FriendbotUrlError::InvalidUrl`] — the URL cannot be parsed.
/// - [`FriendbotUrlError::NonHttps`] — the scheme is not `https`.
/// - [`FriendbotUrlError::HostNotAllowed`] — the host is not in
///   [`ALLOWED_FRIENDBOT_HOSTS`].
///
/// # Examples
///
/// ```
/// use stellar_agent_network::friendbot::validate_friendbot_url;
///
/// assert!(validate_friendbot_url("https://friendbot.stellar.org").is_ok());
/// assert!(validate_friendbot_url("http://friendbot.stellar.org").is_err());
/// assert!(validate_friendbot_url("https://evil.example.com").is_err());
/// ```
pub fn validate_friendbot_url(url: &str) -> Result<(), FriendbotUrlError> {
    validate_friendbot_url_inner(url, false)
}

/// Validates a Friendbot URL, additionally allowing loopback addresses.
///
/// Identical to [`validate_friendbot_url`] except that `127.0.0.1` and
/// `localhost` are also accepted as hosts.  This variant is used **only in
/// tests** where a wiremock server binds to localhost.
///
/// This function is available in tests (via `#[cfg(test)]`) or when the
/// `test-loopback` feature is enabled.  Production builds that do not enable
/// the feature will not see this symbol.
///
/// # Errors
///
/// Same as [`validate_friendbot_url`] except loopback hosts are accepted.
///
/// # Examples
///
/// ```
/// # #[cfg(any(test, feature = "test-loopback"))]
/// # {
/// use stellar_agent_network::friendbot::validate_friendbot_url_allowing_loopback;
///
/// // Wiremock binds to 127.0.0.1; this variant accepts it.
/// assert!(validate_friendbot_url_allowing_loopback(
///     "http://127.0.0.1:9999/friendbot"
/// ).is_ok());
/// assert!(validate_friendbot_url_allowing_loopback(
///     "http://localhost:8888"
/// ).is_ok());
/// // Non-loopback, non-allowlisted hosts are still rejected.
/// assert!(validate_friendbot_url_allowing_loopback(
///     "https://evil.example.com"
/// ).is_err());
/// # }
/// ```
#[cfg(any(test, feature = "test-loopback"))]
#[doc(hidden)]
pub fn validate_friendbot_url_allowing_loopback(url: &str) -> Result<(), FriendbotUrlError> {
    validate_friendbot_url_inner(url, true)
}

/// Re-export of the userinfo-stripping display redactor.
///
/// The canonical definition lives in [`crate::redact`] next to
/// [`crate::redact::redact_url_authority`] so the two URL redaction
/// semantics are co-located; this re-export keeps the
/// `friendbot::redact_url_userinfo` import path stable for callers.
pub use crate::redact::redact_url_userinfo;

/// Returns the default Friendbot URL for the given CAIP-2 chain, or `None`
/// if the chain has no known Friendbot endpoint.
///
/// The MCP tool uses this when `friendbot_url` is not supplied by the caller.
/// The returned URL is always in [`ALLOWED_FRIENDBOT_HOSTS`] — callers do not
/// need additional validation for the default path.  The unit test
/// `default_friendbot_urls_are_all_in_allowlist` mechanically asserts this
/// by-construction invariant for every chain variant that returns `Some`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::profile::caip2::Caip2;
/// use stellar_agent_network::friendbot::default_friendbot_url;
///
/// assert_eq!(
///     default_friendbot_url(Caip2::Testnet),
///     Some("https://friendbot.stellar.org"),
/// );
/// assert_eq!(default_friendbot_url(Caip2::Mainnet), None);
/// ```
#[must_use]
pub fn default_friendbot_url(
    chain: stellar_agent_core::profile::caip2::Caip2,
) -> Option<&'static str> {
    use stellar_agent_core::profile::caip2::Caip2;
    match chain {
        Caip2::Testnet => Some("https://friendbot.stellar.org"),
        Caip2::Mainnet => None,
        // Forward-compat: any future chain variant has no default Friendbot.
        _ => None,
    }
}

/// Internal implementation shared by the public validation functions.
///
/// When `allow_loopback` is `true`, `127.0.0.1` and `localhost` are accepted
/// regardless of scheme (wiremock in tests uses plain HTTP on loopback).
fn validate_friendbot_url_inner(url: &str, allow_loopback: bool) -> Result<(), FriendbotUrlError> {
    let parsed =
        url::Url::parse(url).map_err(|e| FriendbotUrlError::InvalidUrl(format!("{url}: {e}")))?;

    // Reject URLs with embedded credentials before evaluating anything else.
    // Userinfo in a URL can leak into logs and error envelopes.  The check
    // fires for both username-only and username:password forms.  This is
    // defence-in-depth even for the loopback path used in tests; well-formed
    // wiremock URLs never carry credentials.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FriendbotUrlError::CredentialsInUrl(
            // Do NOT echo the URL itself in the error message — that would
            // defeat the purpose of rejecting it.
            "friendbot URL must not contain userinfo (user:pass@host)".to_owned(),
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| FriendbotUrlError::InvalidUrl(format!("{url}: missing host")))?;

    // Allow loopback for test environments (wiremock binds to 127.0.0.1).
    if allow_loopback && (host == "127.0.0.1" || host == "localhost") {
        return Ok(());
    }

    // Reject non-HTTPS (except when loopback is requested and the host
    // matched above — but we only reach here for non-loopback hosts).
    if parsed.scheme() != "https" {
        return Err(FriendbotUrlError::NonHttps(url.to_owned()));
    }

    // Verify host is allow-listed.  The `url` crate normalises ASCII hostnames
    // to lower-case per WHATWG URL spec §4.1, so `host` is already lower-case
    // for plain ASCII names.  We use eq_ignore_ascii_case as defence-in-depth
    // for any code path that constructs a host string without going through
    // the parser.
    let host_lower = host.to_ascii_lowercase();
    let allowed = ALLOWED_FRIENDBOT_HOSTS
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&host_lower));
    if !allowed {
        let allowed_list = ALLOWED_FRIENDBOT_HOSTS.join(", ");
        return Err(FriendbotUrlError::HostNotAllowed {
            host: host.to_owned(),
            allowed: allowed_list,
        });
    }

    Ok(())
}

/// The result of a successful Friendbot funding request.
///
/// Contains the transaction hash, the funded account ID, and the Friendbot
/// endpoint URL that was used for confirmation and table rendering.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendbotResult {
    /// The transaction hash of the Friendbot funding transaction.
    pub tx_hash: String,

    /// The account ID that was funded.
    pub account_id: String,

    /// The Friendbot endpoint URL that was called.
    ///
    /// Included in the result so that table renderers and log consumers can
    /// report which endpoint was used without requiring the caller to
    /// separately track the URL.
    pub friendbot_url_used: String,
}

/// Funds a testnet account via the Stellar Friendbot HTTP endpoint.
///
/// Makes a single async HTTP GET to `{friendbot_url}?addr={account_id}`
/// via `reqwest`. The caller awaits the future; the CLI binary runs under
/// `#[tokio::main]`.
///
/// Mainnet is rejected structurally before any network call: if
/// `network_passphrase` equals the Stellar mainnet passphrase or if
/// `friendbot_url` is `None`, the function returns an appropriate error.
///
/// # Errors
///
/// - [`WalletError::Network`] wrapping [`NetworkError::FriendbotMainnetForbidden`]
///   if `network_passphrase` matches the Stellar mainnet passphrase.
/// - [`WalletError::Network`] wrapping [`NetworkError::RpcUnreachable`] if
///   the Friendbot HTTP endpoint is unreachable or returns an error.
/// - [`WalletError::Network`] wrapping [`NetworkError::AccountNotFound`] if
///   the Friendbot response cannot be parsed (unexpected Friendbot response).
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::fund_with_friendbot;
///
/// # async fn run() -> Result<(), stellar_agent_core::WalletError> {
/// let result = fund_with_friendbot(
///     "https://friendbot.stellar.org",
///     "GABC...XYZ",
///     "Test SDF Network ; September 2015",
/// ).await?;
/// println!("funded with tx: {}", result.tx_hash);
/// # Ok(()) }
/// ```
pub async fn fund_with_friendbot(
    friendbot_url: &str,
    account_id: &str,
    network_passphrase: &str,
) -> Result<FriendbotResult, WalletError> {
    // Structural mainnet rejection — no network call on mainnet.
    if network_passphrase == MAINNET_PASSPHRASE {
        return Err(WalletError::Network(
            NetworkError::FriendbotMainnetForbidden,
        ));
    }

    let url = format!("{friendbot_url}?addr={account_id}");

    tracing::debug!(
        account_id = %crate::account::redact_account_id(account_id),
        "fund_with_friendbot: GET {friendbot_url}",
    );

    let response = reqwest::get(&url).await.map_err(|e| {
        WalletError::Network(NetworkError::RpcUnreachable {
            url: redact_url_authority(friendbot_url),
            // redact_rpc_error strips any URL authority (including userinfo)
            // that reqwest may embed in the transport-error Display.
            reason: redact_rpc_error(&e.to_string()),
        })
    })?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        return Err(WalletError::Network(NetworkError::RpcUnreachable {
            url: redact_url_authority(friendbot_url),
            reason: format!("Friendbot returned HTTP {status}"),
        }));
    }

    // Parse the Friendbot JSON response. The response shape is:
    // `{"_links": {...}, "hash": "...", ...}` — we only need the hash.
    let body: serde_json::Value = response.json().await.map_err(|e| {
        WalletError::Network(NetworkError::RpcUnreachable {
            url: redact_url_authority(friendbot_url),
            // redact_rpc_error applied for defence-in-depth.
            reason: format!(
                "Friendbot response parse error: {}",
                redact_rpc_error(&e.to_string())
            ),
        })
    })?;

    let tx_hash = body
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            // A 200 OK Friendbot response without a `hash` field is
            // structurally unexpected: either the upstream API changed or
            // the endpoint is not a real Friendbot. Report as an RPC-layer
            // error rather than fabricating a "unknown" success — a
            // malicious / malfunctioning mirror could otherwise return an
            // empty JSON body and have the wallet report success.
            WalletError::Network(NetworkError::RpcUnreachable {
                url: redact_url_authority(friendbot_url),
                reason: "Friendbot response missing `hash` field".to_owned(),
            })
        })?
        .to_owned();

    Ok(FriendbotResult {
        tx_hash,
        account_id: account_id.to_owned(),
        friendbot_url_used: friendbot_url.to_owned(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; assertions via unwrap/expect are idiomatic in unit tests"
    )]

    use super::*;

    #[tokio::test]
    async fn mainnet_rejected_before_network_call() {
        let result =
            fund_with_friendbot("https://friendbot.stellar.org", "GABC", MAINNET_PASSPHRASE).await;
        assert!(
            matches!(
                result,
                Err(WalletError::Network(
                    NetworkError::FriendbotMainnetForbidden
                ))
            ),
            "expected FriendbotMainnetForbidden, got: {result:?}"
        );
    }

    // ── validate_friendbot_url tests ──────────────────────────────────────────

    #[test]
    fn allowlisted_testnet_host_accepted() {
        assert!(
            validate_friendbot_url("https://friendbot.stellar.org").is_ok(),
            "testnet Friendbot must be in the allow-list"
        );
    }

    #[test]
    fn allowlisted_futurenet_host_accepted() {
        assert!(
            validate_friendbot_url("https://friendbot-futurenet.stellar.org").is_ok(),
            "futurenet Friendbot must be in the allow-list"
        );
    }

    #[test]
    fn non_allowlisted_host_rejected() {
        let result = validate_friendbot_url("https://evil.example.com/friendbot");
        assert!(
            matches!(result, Err(FriendbotUrlError::HostNotAllowed { .. })),
            "non-allowlisted host must be rejected: {result:?}"
        );
    }

    #[test]
    fn http_scheme_rejected() {
        let result = validate_friendbot_url("http://friendbot.stellar.org");
        assert!(
            matches!(result, Err(FriendbotUrlError::NonHttps(_))),
            "non-HTTPS URL must be rejected: {result:?}"
        );
    }

    #[test]
    fn malformed_url_rejected() {
        let result = validate_friendbot_url("not-a-url");
        assert!(
            matches!(result, Err(FriendbotUrlError::InvalidUrl(_))),
            "malformed URL must be rejected: {result:?}"
        );
    }

    #[test]
    fn url_with_path_still_checks_host() {
        assert!(
            validate_friendbot_url("https://friendbot.stellar.org/some/path").is_ok(),
            "URL with path is ok if host is allowlisted"
        );
        let result = validate_friendbot_url("https://attacker.example.com/friendbot.stellar.org");
        assert!(
            result.is_err(),
            "path component cannot bypass host check: {result:?}"
        );
    }

    #[test]
    fn loopback_accepted_with_loopback_validator() {
        assert!(
            validate_friendbot_url_allowing_loopback("http://127.0.0.1:9999/friendbot").is_ok(),
            "loopback validator must accept 127.0.0.1"
        );
        assert!(
            validate_friendbot_url_allowing_loopback("http://localhost:8888").is_ok(),
            "loopback validator must accept localhost"
        );
    }

    #[test]
    fn loopback_rejected_by_production_validator() {
        let result = validate_friendbot_url("http://127.0.0.1:9999/friendbot");
        assert!(
            result.is_err(),
            "production validator must reject loopback URL: {result:?}"
        );
    }

    #[test]
    fn non_loopback_non_allowlisted_rejected_by_loopback_validator() {
        let result = validate_friendbot_url_allowing_loopback("https://evil.example.com/friendbot");
        assert!(
            result.is_err(),
            "loopback validator must still reject non-allowlisted non-loopback: {result:?}"
        );
    }

    // ── userinfo (credentials-in-URL) rejection tests ─────────────────────────

    #[test]
    fn userinfo_username_only_rejected() {
        let result = validate_friendbot_url("https://user@friendbot.stellar.org/");
        assert!(
            matches!(result, Err(FriendbotUrlError::CredentialsInUrl(_))),
            "username-only userinfo must be rejected: {result:?}"
        );
    }

    #[test]
    fn userinfo_username_password_rejected() {
        let result = validate_friendbot_url("https://user:pass@friendbot.stellar.org/");
        assert!(
            matches!(result, Err(FriendbotUrlError::CredentialsInUrl(_))),
            "user:password userinfo must be rejected: {result:?}"
        );
    }

    #[test]
    fn userinfo_with_allowlisted_host_rejected() {
        // Even an allow-listed host paired with userinfo must be rejected — the
        // userinfo check fires before the allow-list check.
        let result =
            validate_friendbot_url("https://attacker:secret@friendbot.stellar.org/?addr=G123");
        assert!(
            matches!(result, Err(FriendbotUrlError::CredentialsInUrl(_))),
            "allow-listed host with userinfo must be rejected: {result:?}"
        );
        // Error message must not echo the URL.
        if let Err(FriendbotUrlError::CredentialsInUrl(msg)) = result {
            assert!(
                !msg.contains("attacker"),
                "error message must not reveal credentials: {msg}"
            );
            assert!(
                !msg.contains("secret"),
                "error message must not reveal credentials: {msg}"
            );
        }
    }

    // ── redact_url_userinfo tests ─────────────────────────────────────────────

    #[test]
    fn redact_url_userinfo_strips_user_password() {
        let result = redact_url_userinfo("https://user:pass@friendbot.stellar.org/");
        assert_eq!(
            result, "https://friendbot.stellar.org/",
            "userinfo must be stripped"
        );
    }

    #[test]
    fn redact_url_userinfo_passes_clean_url_unchanged() {
        // Note: the url crate normalises https://... to include a trailing slash.
        let result = redact_url_userinfo("https://friendbot.stellar.org");
        assert_eq!(
            result, "https://friendbot.stellar.org/",
            "clean URL without userinfo must pass through (normalised)"
        );
    }

    #[test]
    fn redact_url_userinfo_passes_malformed_url_unchanged_string() {
        // Defensive: malformed input must never panic; returns original string.
        let input = "not-a-url";
        let result = redact_url_userinfo(input);
        assert_eq!(result, input, "malformed URL must be returned unchanged");
    }

    // ── default_friendbot_url unit tests ──────────────────────────────────────

    #[test]
    fn default_friendbot_url_testnet_returns_sdf_endpoint() {
        use stellar_agent_core::profile::caip2::Caip2;
        let url = default_friendbot_url(Caip2::Testnet);
        assert_eq!(
            url,
            Some("https://friendbot.stellar.org"),
            "testnet default must be the SDF testnet endpoint"
        );
    }

    #[test]
    fn default_friendbot_url_mainnet_returns_none() {
        use stellar_agent_core::profile::caip2::Caip2;
        let url = default_friendbot_url(Caip2::Mainnet);
        assert!(url.is_none(), "mainnet must have no default Friendbot URL");
    }

    /// Every default Friendbot URL returned by `default_friendbot_url` must be
    /// in the allow-list.  This mechanically asserts the by-construction
    /// invariant for all chain variants that return `Some`.
    #[test]
    fn default_friendbot_urls_are_all_in_allowlist() {
        use stellar_agent_core::profile::caip2::Caip2;
        for chain in [Caip2::Testnet, Caip2::Mainnet] {
            if let Some(default_url) = default_friendbot_url(chain) {
                assert!(
                    validate_friendbot_url(default_url).is_ok(),
                    "default friendbot URL for {:?} ({}) is NOT in the allow-list — \
                     this is a by-construction invariant violation",
                    chain,
                    default_url
                );
            }
        }
    }

    // ── case-insensitive host comparison tests ────────────────────────────────

    #[test]
    fn uppercase_host_accepted() {
        assert!(
            validate_friendbot_url("https://FRIENDBOT.STELLAR.ORG/").is_ok(),
            "all-uppercase allow-listed host must be accepted"
        );
    }

    #[test]
    fn mixed_case_host_accepted() {
        assert!(
            validate_friendbot_url("https://FriendBot.Stellar.Org/").is_ok(),
            "mixed-case allow-listed host must be accepted"
        );
    }

    /// The `url` crate preserves trailing dots in hostname strings — it does
    /// NOT strip them per WHATWG URL spec §4.2 host parsing.  A trailing-dot
    /// host `friendbot.stellar.org.` is therefore NOT equivalent to
    /// `friendbot.stellar.org` after parsing and is rejected by the allow-list.
    ///
    /// This behaviour is intentional as a security property: unexpected hostname
    /// syntax variants should fail closed rather than be silently normalised.
    #[test]
    fn trailing_dot_host_rejected_not_in_allowlist() {
        // The url crate preserves "friendbot.stellar.org." with the trailing
        // dot; the parsed host_str() includes the dot and does NOT match
        // "friendbot.stellar.org" in the allow-list — correctly rejected.
        let result = validate_friendbot_url("https://friendbot.stellar.org./");
        assert!(
            result.is_err(),
            "trailing-dot host is NOT normalised by the url crate and must be rejected: {result:?}"
        );
    }

    #[test]
    fn default_port_accepted() {
        assert!(
            validate_friendbot_url("https://friendbot.stellar.org:443/").is_ok(),
            "explicit default HTTPS port 443 must be accepted"
        );
    }

    /// IDN homograph: the `url` crate normalises Punycode hosts via IDNA.
    /// A cyrillic-lookalike host serialises to `xn--...` which does NOT match
    /// `friendbot.stellar.org`, so it is correctly rejected.
    #[test]
    fn idn_homograph_cyrillic_rejected() {
        // "friendbоt.stellar.org" with cyrillic 'о' (U+043E) instead of latin
        // 'o' (U+006F).  After IDNA processing the host becomes something like
        // "xn--friendbt-qxa.stellar.org" which is not in the allow-list.
        let result = validate_friendbot_url("https://friendb\u{043E}t.stellar.org/");
        assert!(
            result.is_err(),
            "IDN homograph with cyrillic 'о' must be rejected: {result:?}"
        );
    }

    // ── explicit scheme rejection tests ───────────────────────────────────────

    #[test]
    fn ftp_scheme_rejected() {
        let result = validate_friendbot_url("ftp://friendbot.stellar.org/");
        assert!(
            matches!(result, Err(FriendbotUrlError::NonHttps(_))),
            "ftp:// scheme must be rejected with NonHttps: {result:?}"
        );
    }

    #[test]
    fn file_scheme_rejected() {
        // file:///etc/passwd has no host, so it fails with InvalidUrl
        // (missing host) rather than NonHttps — both are error outcomes.
        // The important property is that it is rejected.
        let result = validate_friendbot_url("file:///etc/passwd");
        assert!(
            result.is_err(),
            "file:// scheme must be rejected: {result:?}"
        );
    }

    #[test]
    fn data_uri_rejected() {
        // data: URIs have no host; they fail at the host_str() check.
        let result = validate_friendbot_url("data:text/html,<script>alert(1)</script>");
        assert!(result.is_err(), "data: URI must be rejected: {result:?}");
    }

    #[test]
    fn javascript_scheme_rejected() {
        // javascript: pseudo-URIs are not valid URLs and fail at parse time.
        let result = validate_friendbot_url("javascript:alert(1)");
        assert!(
            result.is_err(),
            "javascript: scheme must be rejected: {result:?}"
        );
    }

    // ── host-emptiness edge cases ─────────────────────────────────────────────

    #[test]
    fn empty_host_in_https_url_rejected() {
        // https://./path has an empty host — must be rejected.
        let result = validate_friendbot_url("https://./path");
        assert!(
            result.is_err(),
            "https:// URL with empty/dot-only host must be rejected: {result:?}"
        );
    }

    // ── reqwest-reason redaction hardening ───────────────────────────────────

    /// Verifies that the `redact_rpc_error` function strips `user:pass@` from
    /// a reqwest-style error string before it enters `RpcUnreachable.reason`.
    ///
    /// Credentials embedded in a URL that reqwest's `Display` may include must
    /// not reach the error envelope.
    #[test]
    fn reqwest_error_string_with_userinfo_is_redacted() {
        // Simulate a reqwest error Display that embeds a credentialed URL.
        let raw_error = "error sending request for url (https://user:s3cr3t@friendbot.stellar.org/?addr=GABC): connection refused";
        let redacted = redact_rpc_error(raw_error);

        assert!(
            !redacted.contains("s3cr3t"),
            "secret must be stripped from reason"
        );
        assert!(
            !redacted.contains("user:"),
            "username must be stripped from reason"
        );
        assert!(
            redacted.contains("friendbot.stellar.org"),
            "host must be preserved: {redacted}"
        );
        assert!(
            redacted.contains("connection refused"),
            "non-URL context must be preserved: {redacted}"
        );
    }

    #[test]
    fn reqwest_error_string_without_url_is_unchanged() {
        let raw_error = "operation timed out after 30s";
        let redacted = redact_rpc_error(raw_error);
        assert_eq!(
            redacted, raw_error,
            "plain error strings must pass through unchanged"
        );
    }
}
