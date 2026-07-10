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

use std::time::Duration;

use serde::{Deserialize, Serialize};

use stellar_agent_core::error::{NetworkError, WalletError};

use crate::account::fetch_account;
use crate::client::StellarRpcClient;
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

    /// Milliseconds elapsed between the Friendbot HTTP response and the
    /// funded account first becoming visible on the queried RPC endpoint.
    ///
    /// [`fund_with_friendbot`] does not return `Ok` until the funded account
    /// is RPC-queryable, so this field is present precisely because
    /// verification succeeded; it exists to give operators and log consumers
    /// visibility into the RPC's propagation lag on a per-call basis, rather
    /// than only when it is slow enough to be noticed some other way.
    pub funding_confirmed_after_ms: u64,
}

/// Upper bound on the number of `fetch_account` polls after a successful
/// Friendbot HTTP response, before [`fund_with_friendbot`] gives up and
/// reports [`NetworkError::FriendbotFundingNotConfirmed`].
const FUNDING_VERIFICATION_MAX_POLLS: u32 = 10;

/// Delay before each verification poll after the first (which fires
/// immediately following the Friendbot HTTP response). Capped exponential
/// backoff; the 9 delays here plus the 10 polls in
/// [`FUNDING_VERIFICATION_MAX_POLLS`] sum to roughly 30 seconds of total
/// verification window.
const FUNDING_VERIFICATION_BACKOFF: [Duration; 9] = [
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(3),
    Duration::from_secs(4),
    Duration::from_secs(4),
    Duration::from_secs(5),
    Duration::from_secs(5),
    Duration::from_secs(5),
];

/// Polls `fetch_account` against `rpc_url` until `account_id` is queryable,
/// bounded by [`FUNDING_VERIFICATION_MAX_POLLS`] / [`FUNDING_VERIFICATION_BACKOFF`].
///
/// Returns the elapsed time on success. This is a read-side wait only — it
/// never rebuilds or resubmits anything, so it carries none of the
/// re-signing implications a submit-side retry would.
///
/// # Errors
///
/// Returns [`WalletError::Network`] wrapping
/// [`NetworkError::FriendbotFundingNotConfirmed`] if the account was simply
/// absent for the whole verification window; the last poll's own error when
/// the window exhausts on anything other than account absence (e.g. a
/// persistently unreachable or misconfigured RPC — propagation lag and a
/// broken RPC are different operator problems and must read differently); or
/// a client-construction error if `rpc_url` cannot be parsed.
async fn verify_funding_landed(rpc_url: &str, account_id: &str) -> Result<Duration, WalletError> {
    verify_funding_landed_with(
        rpc_url,
        account_id,
        FUNDING_VERIFICATION_MAX_POLLS,
        &FUNDING_VERIFICATION_BACKOFF,
    )
    .await
}

/// [`verify_funding_landed`] with caller-supplied poll count and backoff
/// schedule. Production goes through the wrapper above with the module
/// constants; tests inject millisecond-scale schedules so the exhausted-window
/// paths run without real multi-second sleeps. `backoff` must hold at least
/// `max_polls - 1` entries.
async fn verify_funding_landed_with(
    rpc_url: &str,
    account_id: &str,
    max_polls: u32,
    backoff: &[Duration],
) -> Result<Duration, WalletError> {
    let client = StellarRpcClient::new(rpc_url)?;
    let start = std::time::Instant::now();
    // Polling continues through transport errors — an RPC blip mid-window is
    // the same environmental condition the verification exists to absorb —
    // but the FINAL failure must not misreport a persistently unreachable or
    // misconfigured RPC as propagation lag: if the last poll's failure was
    // anything other than the account being absent, that error is surfaced
    // instead of `FriendbotFundingNotConfirmed`.
    let mut last_error: Option<WalletError> = None;
    for attempt in 0..max_polls {
        if attempt > 0 {
            tokio::time::sleep(backoff[(attempt - 1) as usize]).await;
        }
        match fetch_account(&client, account_id, &[]).await {
            Ok(_) => return Ok(start.elapsed()),
            Err(e) => last_error = Some(e),
        }
    }
    match last_error {
        Some(WalletError::Network(NetworkError::AccountNotFound { .. })) | None => Err(
            WalletError::Network(NetworkError::FriendbotFundingNotConfirmed {
                account_id: account_id.to_owned(),
                waited_secs: start.elapsed().as_secs(),
            }),
        ),
        Some(other) => Err(other),
    }
}

/// Funds a testnet account via the Stellar Friendbot HTTP endpoint, and
/// verifies the funding landed before returning.
///
/// Makes a single async HTTP GET to `{friendbot_url}?addr={account_id}`
/// via `reqwest`. The caller awaits the future; the CLI binary runs under
/// `#[tokio::main]`. On a successful HTTP response, polls `rpc_url` via
/// `fetch_account` until the funded account is queryable (see
/// [`verify_funding_landed`]) — Friendbot's HTTP response confirms the
/// funding transaction was submitted, not that it has propagated to the
/// queried RPC endpoint, and callers that build a follow-on transaction
/// against an unpropagated account fail with a confusing `TxNoAccount`
/// downstream. This verification is a read-side wait only: it never
/// resubmits or rebuilds anything.
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
/// - [`WalletError::Network`] wrapping [`NetworkError::FriendbotFundingNotConfirmed`]
///   if the funded account never becomes queryable on `rpc_url` within the
///   verification window.
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
///     "https://soroban-testnet.stellar.org",
/// ).await?;
/// println!("funded with tx: {}", result.tx_hash);
/// # Ok(()) }
/// ```
pub async fn fund_with_friendbot(
    friendbot_url: &str,
    account_id: &str,
    network_passphrase: &str,
    rpc_url: &str,
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

    let confirmed_after = verify_funding_landed(rpc_url, account_id).await?;

    Ok(FriendbotResult {
        tx_hash,
        account_id: account_id.to_owned(),
        friendbot_url_used: friendbot_url.to_owned(),
        funding_confirmed_after_ms: u64::try_from(confirmed_after.as_millis()).unwrap_or(u64::MAX),
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
        let result = fund_with_friendbot(
            "https://friendbot.stellar.org",
            "GABC",
            MAINNET_PASSPHRASE,
            "http://127.0.0.1:1",
        )
        .await;
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

    // ── funding-verification tests (account-present / account-absent) ────────

    /// A successful Friendbot HTTP response followed by the account becoming
    /// queryable on the FIRST verification poll succeeds immediately, with
    /// `funding_confirmed_after_ms` populated.
    #[tokio::test(flavor = "current_thread")]
    async fn verification_succeeds_when_account_is_immediately_present() {
        use stellar_agent_test_support::EchoIdResponder;
        use stellar_agent_test_support::xdr_fixtures::{account_entry_xdr, account_ledger_key_xdr};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let address = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
        let mock_server = MockServer::start().await;
        let expected_hash = "abc123def456abc123def456abc123def456abc123def456abc123def456abc1";

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "hash": expected_hash,
                "_links": {}
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(serde_json::json!({
                "entries": [
                    {
                        "key": account_ledger_key_xdr(address),
                        "xdr": account_entry_xdr(address, 100_000_000_000, 0),
                        "lastModifiedLedgerSeq": 100
                    }
                ],
                "latestLedger": 100
            })))
            .mount(&mock_server)
            .await;

        let result = fund_with_friendbot(
            &mock_server.uri(),
            address,
            TESTNET_PASSPHRASE_FOR_TESTS,
            &mock_server.uri(),
        )
        .await
        .expect("verification must succeed when the account is already present");

        assert_eq!(result.tx_hash, expected_hash);
    }

    /// A successful Friendbot HTTP response, but the account NEVER becomes
    /// queryable on the RPC, exhausts the bounded verification window and
    /// returns `FriendbotFundingNotConfirmed` rather than a false success.
    #[tokio::test(flavor = "current_thread")]
    async fn verification_fails_when_account_never_becomes_present() {
        use stellar_agent_test_support::EchoIdResponder;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer};

        let address = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
        let mock_server = MockServer::start().await;

        // Every verification poll gets a well-formed getLedgerEntries response
        // with NO entries — `fetch_account` maps that to `AccountNotFound`, so
        // the exhausted window reports genuine account absence.
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(serde_json::json!({
                "entries": [],
                "latestLedger": 100
            })))
            .mount(&mock_server)
            .await;

        // Millisecond-scale injected schedule: same code path as the
        // production wrapper, without its ~30s of real backoff.
        let result = verify_funding_landed_with(
            &mock_server.uri(),
            address,
            3,
            &[Duration::from_millis(1), Duration::from_millis(1)],
        )
        .await;

        assert!(
            matches!(
                result,
                Err(WalletError::Network(
                    NetworkError::FriendbotFundingNotConfirmed { .. }
                ))
            ),
            "expected FriendbotFundingNotConfirmed after the bounded window, got: {result:?}"
        );
    }

    /// A persistently BROKEN RPC (every poll an unmatched 404 → transport
    /// error, never a well-formed "no entries" response) exhausts the window
    /// and surfaces the transport error itself — a misconfigured or
    /// unreachable RPC must not be misreported as funding propagation lag.
    #[tokio::test(flavor = "current_thread")]
    async fn verification_surfaces_transport_error_over_not_confirmed() {
        use wiremock::MockServer;

        let address = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
        // No mocks mounted at all: every poll gets wiremock's unmatched 404.
        let mock_server = MockServer::start().await;

        let result = verify_funding_landed_with(
            &mock_server.uri(),
            address,
            3,
            &[Duration::from_millis(1), Duration::from_millis(1)],
        )
        .await;

        assert!(
            result.is_err(),
            "verification against a broken RPC must not succeed, got: {result:?}"
        );
        assert!(
            !matches!(
                result,
                Err(WalletError::Network(
                    NetworkError::FriendbotFundingNotConfirmed { .. }
                ))
            ),
            "a persistent transport error must surface as itself, not as \
             FriendbotFundingNotConfirmed: {result:?}"
        );
    }

    /// Testnet passphrase, named distinctly from [`MAINNET_PASSPHRASE`] to
    /// keep the verification tests self-contained.
    const TESTNET_PASSPHRASE_FOR_TESTS: &str = "Test SDF Network ; September 2015";

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
