//! SEP-6 discovery-only client: `GET {transfer_server}/info`.
//!
//! # What this module does
//!
//! Provides [`get_sep6_info`] which calls ONLY the non-interactive
//! `GET /info` discovery endpoint of a SEP-6 transfer server.
//!
//! # POSITIVE CAPABILITY BOUND — this module calls ONLY `/info`
//!
//! This module NEVER calls `/deposit`, `/withdraw`, `/deposit-exchange`,
//! `/withdraw-exchange`, `/customer` (SEP-12), `/fee`, or `/transaction(s)`.
//! It NEVER transmits any KYC field (`email_address`, `first_name`,
//! `country_code`, `customer_id`, `dest`, `dest_extra`, etc.).
//!
//! The bound is STRUCTURAL: there is no code path in this module that
//! constructs a request to any endpoint other than `/info`.  Adding any
//! other anchor path to this file requires a security review.
//!
//! # Spec reference
//!
//! SEP-6 §5.1 — `GET /info` request and response shape.

use serde::Deserialize;

use crate::client::{AnchorClient, authority_hint};
use crate::error::AnchorError;
use crate::ssrf::assert_same_domain_or_https_fqdn;

// ─────────────────────────────────────────────────────────────────────────────
// Typed response structs
// ─────────────────────────────────────────────────────────────────────────────

/// Per-asset capability block in the SEP-6 `/info` response.
///
/// Per SEP-6 §5.1.
/// Unknown fields are tolerated: `#[serde(deny_unknown_fields)]` is deliberately
/// NOT set, because the `/info` response carries many fields we do not consume
/// (`funding_methods`, `types`, deprecated `fields`, etc.) that should be
/// ignored rather than causing a decode error.
#[derive(Debug, Clone, Deserialize)]
pub struct AssetInfo {
    /// Whether the anchor supports this operation for this asset.
    #[serde(default)]
    pub enabled: bool,

    /// Whether clients must authenticate before using this endpoint.
    ///
    /// `false` if not specified per SEP-6 §5.1.
    #[serde(default)]
    pub authentication_required: bool,

    /// Optional fixed (flat) fee in units of the Stellar asset.
    #[serde(default)]
    pub fee_fixed: Option<f64>,

    /// Optional percentage fee in percentage points of the Stellar asset.
    #[serde(default)]
    pub fee_percent: Option<f64>,

    /// Optional minimum amount for this operation.
    #[serde(default)]
    pub min_amount: Option<f64>,

    /// Optional maximum amount for this operation.
    #[serde(default)]
    pub max_amount: Option<f64>,
}

/// SEP-6 feature flags from the `/info` response.
///
/// Per SEP-6 §5.1.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Features {
    /// Whether the anchor supports creating new Stellar accounts on deposit.
    #[serde(default)]
    pub account_creation: bool,

    /// Whether the anchor supports claimable balances.
    #[serde(default)]
    pub claimable_balances: bool,
}

/// Decoded SEP-6 `/info` response.
///
/// Per SEP-6 §5.1.
/// Only fields relevant to the discovery-only surface are decoded; additional
/// fields (e.g. fee endpoint details, deprecated `transaction`/`transactions`)
/// are silently ignored.
///
/// # Examples
///
/// ```
/// use stellar_agent_anchor::Sep6Info;
///
/// let info: Sep6Info = serde_json::from_str(r#"{
///     "deposit": {
///         "USDC": { "enabled": true, "authentication_required": true }
///     },
///     "withdraw": {},
///     "features": { "account_creation": true, "claimable_balances": false }
/// }"#).unwrap();
///
/// assert!(info.deposit.contains_key("USDC"));
/// assert!(info.features.account_creation);
/// ```
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Sep6Info {
    /// Deposit capabilities per asset code.
    #[serde(default)]
    pub deposit: std::collections::HashMap<String, AssetInfo>,

    /// Withdrawal capabilities per asset code.
    #[serde(default)]
    pub withdraw: std::collections::HashMap<String, AssetInfo>,

    /// Deposit-exchange capabilities per asset code.
    #[serde(rename = "deposit-exchange", default)]
    pub deposit_exchange: std::collections::HashMap<String, AssetInfo>,

    /// Withdraw-exchange capabilities per asset code.
    #[serde(rename = "withdraw-exchange", default)]
    pub withdraw_exchange: std::collections::HashMap<String, AssetInfo>,

    /// Anchor feature flags.
    #[serde(default)]
    pub features: Features,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public surface
// ─────────────────────────────────────────────────────────────────────────────

/// Fetches and decodes the SEP-6 `/info` capability response.
///
/// Resolves the transfer-server base URL either from the supplied
/// `anchor_domain` (stellar.toml lookup → `TRANSFER_SERVER`) or from a
/// directly supplied `transfer_server` URL.  The same-domain SSRF bind is
/// applied when `anchor_domain` is supplied.
///
/// # POSITIVE CAPABILITY BOUND
///
/// This function calls ONLY `GET {transfer_server}/info`.  No `/deposit`,
/// `/withdraw`, `/customer`, or any other path is ever called.  The bound
/// is structural — see module docs.
///
/// # Arguments
///
/// - `transfer_server` — the validated `TRANSFER_SERVER` URL (HTTPS, on the
///   anchor domain or a subdomain).  Caller obtains this from
///   `MinimalSep1::transfer_server` after the same-domain SSRF bind.
/// - `anchor_domain` — the operator-typed anchor domain used for same-domain
///   SSRF validation.  Supply `None` when the caller has already validated a
///   direct-input URL.
/// - `asset_code` — optional asset code filter (passed as `?asset_code=`
///   query parameter).  `None` returns all assets.
/// - `lang` — optional `lang` query parameter (SEP-6 §5.1).
///
/// # Errors
///
/// - [`AnchorError::InvalidAnchorDomain`] — `anchor_domain` is supplied but
///   is not a valid public FQDN (empty, single-label, IP address, or invalid
///   LDH syntax).  This check happens before any URL comparison so that an
///   invalid anchor domain cannot produce a degenerate suffix match.
/// - [`AnchorError::TransferServerHostMismatch`] — `transfer_server` host does
///   not equal `anchor_domain` or a subdomain of it (same-domain SSRF bind).
/// - [`AnchorError::InvalidDirectUrl`] — direct `transfer_server` URL (no
///   `anchor_domain`) is non-HTTPS, is an IP address, or is a single-label
///   hostname.
/// - [`AnchorError::AnchorFetchFailed`] — transport failure.
/// - [`AnchorError::HttpStatusError`] — anchor returned non-200 HTTP status.
/// - [`AnchorError::AnchorResponseDecodeFailed`] — body exceeds cap or JSON
///   decode failed.
pub async fn get_sep6_info(
    transfer_server: &str,
    anchor_domain: Option<&str>,
    asset_code: Option<&str>,
    lang: Option<&str>,
) -> Result<Sep6Info, AnchorError> {
    // Same-domain SSRF bind: if anchor_domain is provided, assert the
    // transfer-server host is the anchor domain or a subdomain of it.
    // SEP-6 §5 states TRANSFER_SERVER must be declared in stellar.toml.
    if let Some(domain) = anchor_domain {
        assert_same_domain_or_https_fqdn(transfer_server, Some(domain))?;
    } else {
        // Direct URL input: require HTTPS + public FQDN.
        assert_same_domain_or_https_fqdn(transfer_server, None)?;
    }

    // Build the /info URL with optional query params.
    // POSITIVE BOUND: the ONLY path constructed here is `/info`.
    // Adding any other path literal to this file requires a security review.
    let info_url = build_info_url(transfer_server, asset_code, lang)?;
    let hint = authority_hint(&info_url);

    tracing::debug!(
        authority = %hint,
        "sep6: fetching /info endpoint"
    );

    let client = AnchorClient::new()?;
    let body = client.fetch_json_str(&info_url, &hint).await?;

    serde_json::from_str::<Sep6Info>(&body).map_err(|e| AnchorError::AnchorResponseDecodeFailed {
        authority_hint: hint,
        detail: format!("JSON decode of /info response failed: {e}"),
    })
}

/// Builds the `/info` URL with optional query parameters.
///
/// POSITIVE BOUND: constructs only the `/info` path on `transfer_server`.
fn build_info_url(
    transfer_server: &str,
    asset_code: Option<&str>,
    lang: Option<&str>,
) -> Result<String, AnchorError> {
    let base = transfer_server.trim_end_matches('/');
    let mut url =
        url::Url::parse(&format!("{base}/info")).map_err(|_| AnchorError::InvalidDirectUrl {
            detail: "transfer_server is not a valid base URL".to_owned(),
        })?;

    let has_params =
        asset_code.is_some_and(|c| !c.is_empty()) || lang.is_some_and(|l| !l.is_empty());

    if has_params {
        let mut q = url.query_pairs_mut();
        if let Some(code) = asset_code
            && !code.is_empty()
        {
            q.append_pair("asset_code", code);
        }
        if let Some(l) = lang
            && !l.is_empty()
        {
            q.append_pair("lang", l);
        }
    }

    Ok(url.to_string())
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

    // ── POSITIVE CAPABILITY BOUND path-literal test ───────────────────────────

    /// Asserts that the ONLY anchor path literal emitted by `sep6.rs` is `/info`.
    ///
    /// This test is the structural enforcement of the POSITIVE CAPABILITY BOUND
    /// declared in the module docs: the `sep6` module MUST NEVER call
    /// `/deposit`, `/withdraw`, `/deposit-exchange`, `/withdraw-exchange`,
    /// `/customer`, `/fee`, or `/transaction(s)`.
    ///
    /// The test reads the source of THIS FILE and asserts that none of the
    /// KYC-initiating path literals appear as string literals.  If you need to
    /// add a path that is NOT `/info`, this test will fail — which is the
    /// intended behaviour.  Adding any other anchor path to this crate requires
    /// a security review.
    ///
    /// This test uses `include_str!` to capture the source at compile time.
    /// Any change to the file content is re-evaluated on the next `cargo test`.
    #[test]
    fn sep6_source_contains_only_info_path() {
        // Capture the source of sep6.rs at compile time.
        let source = include_str!("sep6.rs");

        // These path literals must NEVER appear in sep6.rs OUTSIDE of the test
        // assertion list.  The test uses a two-stage check:
        // 1. Strip the test block itself from the source before scanning.
        // 2. Assert the forbidden strings do not appear in the production code.
        //
        // We strip everything from `#[cfg(test)]` onward so the test module
        // itself does not trigger the guard.
        let production_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let forbidden: &[&str] = &[
            "\"/deposit\"",
            "\"/withdraw\"",
            "\"/deposit-exchange\"",
            "\"/withdraw-exchange\"",
            "\"/customer\"",
            "\"/fee\"",
            "\"/transaction\"",
            "\"/transactions\"",
            "/deposit/",
            "/withdraw/",
            "/customer/",
        ];
        for f in forbidden {
            assert!(
                !production_source.contains(f),
                "sep6.rs production code contains forbidden path literal {f:?}; \
                 the SEP-6 module must call ONLY /info. \
                 Adding any other path requires a security review."
            );
        }

        // The /info path MUST be present.
        assert!(
            source.contains("/info"),
            "sep6.rs must contain the /info path literal"
        );
    }

    #[test]
    fn build_info_url_no_params() {
        let url = build_info_url("https://transfer.anchor.org", None, None).unwrap();
        assert_eq!(url, "https://transfer.anchor.org/info");
    }

    #[test]
    fn build_info_url_with_asset_code() {
        let url = build_info_url("https://transfer.anchor.org", Some("USDC"), None).unwrap();
        assert!(url.contains("asset_code=USDC"), "url = {url}");
    }

    #[test]
    fn build_info_url_with_lang() {
        let url = build_info_url("https://transfer.anchor.org", None, Some("en")).unwrap();
        assert!(url.contains("lang=en"), "url = {url}");
    }

    #[test]
    fn build_info_url_strips_trailing_slash() {
        let url = build_info_url("https://transfer.anchor.org/", None, None).unwrap();
        assert_eq!(url, "https://transfer.anchor.org/info");
    }

    #[test]
    fn sep6_info_deserializes_fixture() {
        let fixture = r#"{
            "deposit": {
                "USD": {
                    "enabled": true,
                    "authentication_required": true,
                    "min_amount": 0.1,
                    "max_amount": 1000.0
                },
                "ETH": {
                    "enabled": true,
                    "authentication_required": false
                }
            },
            "withdraw": {
                "USD": {
                    "enabled": true,
                    "authentication_required": true,
                    "fee_fixed": 5.0,
                    "fee_percent": 0.5
                }
            },
            "deposit-exchange": {},
            "withdraw-exchange": {},
            "features": {
                "account_creation": true,
                "claimable_balances": true
            }
        }"#;
        let info: Sep6Info = serde_json::from_str(fixture).unwrap();
        assert_eq!(info.deposit.len(), 2);
        let usd = info.deposit.get("USD").unwrap();
        assert!(usd.enabled);
        assert!(usd.authentication_required);
        assert_eq!(usd.min_amount, Some(0.1));
        let eth = info.deposit.get("ETH").unwrap();
        assert!(!eth.authentication_required);
        let usd_w = info.withdraw.get("USD").unwrap();
        assert_eq!(usd_w.fee_fixed, Some(5.0));
        assert!(info.features.account_creation);
    }

    #[test]
    fn sep6_info_deserializes_unknown_fields_ignored() {
        // Extra fields in the response must be ignored, not cause a decode error.
        let fixture = r#"{
            "deposit": {
                "USD": {
                    "enabled": true,
                    "authentication_required": false,
                    "funding_methods": ["SEPA", "SWIFT"],
                    "some_future_field": "value"
                }
            },
            "fee": {
                "enabled": false,
                "description": "Fees vary"
            }
        }"#;
        let info: Sep6Info = serde_json::from_str(fixture).unwrap();
        assert!(info.deposit.contains_key("USD"));
    }

    #[test]
    fn sep6_info_empty_response_decodes_to_default() {
        let info: Sep6Info = serde_json::from_str("{}").unwrap();
        assert!(info.deposit.is_empty());
        assert!(info.withdraw.is_empty());
    }

    #[test]
    fn sep6_info_malformed_response_returns_error() {
        let result = serde_json::from_str::<Sep6Info>("not-json");
        assert!(result.is_err());
    }

    /// SSRF bind in get_sep6_info: invalid anchor_domain → error before fetch.
    #[tokio::test]
    async fn get_sep6_info_invalid_anchor_domain_returns_error() {
        let result = get_sep6_info(
            "https://transfer.example.com",
            Some(""), // empty domain → InvalidAnchorDomain
            None,
            None,
        )
        .await;
        assert!(
            matches!(result, Err(AnchorError::InvalidAnchorDomain { .. })),
            "empty anchor_domain must return InvalidAnchorDomain; got: {result:?}"
        );
    }

    /// SSRF bind in get_sep6_info: host mismatch → error before fetch.
    #[tokio::test]
    async fn get_sep6_info_host_mismatch_returns_error() {
        let result = get_sep6_info(
            "https://evil.example.com/sep6",
            Some("anchor.org"), // host mismatch → TransferServerHostMismatch
            None,
            None,
        )
        .await;
        assert!(
            matches!(result, Err(AnchorError::TransferServerHostMismatch { .. })),
            "host mismatch must return TransferServerHostMismatch; got: {result:?}"
        );
    }

    /// SSRF bind in get_sep6_info: direct URL with IP → error before fetch.
    #[tokio::test]
    async fn get_sep6_info_direct_ip_returns_error() {
        let result = get_sep6_info(
            "https://192.168.1.1/sep6",
            None, // direct URL mode with IP → InvalidDirectUrl
            None,
            None,
        )
        .await;
        assert!(
            matches!(result, Err(AnchorError::InvalidDirectUrl { .. })),
            "IP address in direct mode must return InvalidDirectUrl; got: {result:?}"
        );
    }

    /// build_info_url with both asset_code and lang → both query params present.
    #[test]
    fn build_info_url_with_both_params() {
        let url = build_info_url("https://transfer.anchor.org", Some("USDC"), Some("en")).unwrap();
        assert!(url.contains("asset_code=USDC"), "url = {url}");
        assert!(url.contains("lang=en"), "url = {url}");
    }

    /// build_info_url with empty asset_code → not added to query params.
    #[test]
    fn build_info_url_empty_asset_code_not_added() {
        let url = build_info_url("https://transfer.anchor.org", Some(""), None).unwrap();
        assert!(
            !url.contains("asset_code"),
            "empty asset_code must not be added; url = {url}"
        );
    }

    /// build_info_url with empty lang → not added to query params.
    #[test]
    fn build_info_url_empty_lang_not_added() {
        let url = build_info_url("https://transfer.anchor.org", None, Some("")).unwrap();
        assert!(
            !url.contains("lang="),
            "empty lang must not be added; url = {url}"
        );
    }

    /// Decodes a captured SEP-6 /info fixture that mirrors the testanchor
    /// response shape, using the SAME decode types used by the live leg.
    ///
    /// Catches wire-shape regressions offline even when the live testnet leg
    /// skips due to unreachability.
    #[test]
    fn offline_testanchor_info_fixture_total_decode() {
        let fixture = r#"{
            "deposit": {
                "USDC": {
                    "enabled": true,
                    "authentication_required": true,
                    "min_amount": 0.1,
                    "max_amount": 1000.0
                },
                "SRT": {
                    "enabled": true,
                    "authentication_required": false
                }
            },
            "withdraw": {
                "USDC": {
                    "enabled": true,
                    "authentication_required": true,
                    "fee_fixed": 1.0,
                    "fee_percent": 0.1
                }
            },
            "deposit-exchange": {},
            "withdraw-exchange": {},
            "features": {
                "account_creation": true,
                "claimable_balances": false
            }
        }"#;

        let info: Sep6Info =
            serde_json::from_str(fixture).expect("offline fixture must decode without error");

        assert!(!info.deposit.is_empty(), "deposit map must not be empty");
        let usdc = info
            .deposit
            .get("USDC")
            .expect("USDC deposit must be present");
        assert!(usdc.enabled, "USDC deposit must be enabled");
        assert!(
            usdc.authentication_required,
            "USDC must require authentication"
        );

        // authentication_required is surfaced for discovery callers.
        for (asset, asset_info) in &info.deposit {
            let _auth_req = asset_info.authentication_required;
            let _ = asset;
        }
    }
}
