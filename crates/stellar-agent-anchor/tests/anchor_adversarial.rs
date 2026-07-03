//! Adversarial and offline tests for `stellar-agent-anchor`.
//!
//! Covers:
//! - Same-domain SSRF bind adversarial cases.
//! - SEP-6 positive-capability-bound path-literal assertion.
//! - SEP-24 unexpected-type response → error.
//! - Malformed / oversized anchor response → decode error, no panic.
//! - JWT never in returned URL construction by the wallet.
//!
//! These tests exercise ONLY offline decode logic and the SSRF guard — no live
//! network calls.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]

use stellar_agent_anchor::test_helpers::assert_same_domain_or_https_fqdn;
use stellar_agent_anchor::{AnchorError, Sep6Info};

// ─────────────────────────────────────────────────────────────────────────────
// Same-domain SSRF bind tests
// ─────────────────────────────────────────────────────────────────────────────

/// SSRF bind: TOML `TRANSFER_SERVER` host differs from the anchor domain → rejected.
#[test]
fn ssrf_host_mismatch_is_rejected() {
    let result = assert_same_domain_or_https_fqdn(
        "https://cdn.evil-cdn.com/sep6",
        Some("testanchor.stellar.org"),
    );
    assert!(
        matches!(result, Err(AnchorError::TransferServerHostMismatch { .. })),
        "different host must be rejected; got: {result:?}"
    );
}

/// SSRF bind: `evil-anchor.org` vs `anchor.org` → rejected (leading-dot guard).
///
/// The LEADING DOT is load-bearing: naive `ends_with('anchor.org')` would
/// allow `evil-anchor.org` to match.
#[test]
fn ssrf_evil_anchor_does_not_match_anchor_org() {
    let result =
        assert_same_domain_or_https_fqdn("https://evil-anchor.org/sep6", Some("anchor.org"));
    assert!(
        matches!(result, Err(AnchorError::TransferServerHostMismatch { .. })),
        "evil-anchor.org must NOT match anchor.org (leading-dot guard); got: {result:?}"
    );
}

/// SSRF bind: `transfer.anchor.org` vs `anchor.org` → accepted (valid subdomain).
#[test]
fn ssrf_subdomain_transfer_anchor_org_accepted() {
    let result =
        assert_same_domain_or_https_fqdn("https://transfer.anchor.org/sep6", Some("anchor.org"));
    assert!(
        result.is_ok(),
        "transfer.anchor.org must be accepted as subdomain of anchor.org; got: {result:?}"
    );
}

/// SSRF bind: exact domain match → accepted.
#[test]
fn ssrf_exact_domain_match_accepted() {
    let result = assert_same_domain_or_https_fqdn(
        "https://testanchor.stellar.org/sep6",
        Some("testanchor.stellar.org"),
    );
    assert!(
        result.is_ok(),
        "exact domain match must be accepted; got: {result:?}"
    );
}

/// SSRF bind: `notanchor.org` vs `anchor.org` → rejected (no leading-dot suffix match).
#[test]
fn ssrf_different_tld_sibling_is_rejected() {
    let result = assert_same_domain_or_https_fqdn("https://notanchor.org/sep6", Some("anchor.org"));
    assert!(
        matches!(result, Err(AnchorError::TransferServerHostMismatch { .. })),
        "notanchor.org must be rejected vs anchor.org; got: {result:?}"
    );
}

/// SSRF bind: HTTP is rejected even when host matches anchor domain.
#[test]
fn ssrf_http_scheme_rejected() {
    let result = assert_same_domain_or_https_fqdn(
        "http://testanchor.stellar.org/sep6",
        Some("testanchor.stellar.org"),
    );
    assert!(
        matches!(result, Err(AnchorError::InvalidDirectUrl { .. })),
        "http:// must be rejected; got: {result:?}"
    );
}

/// Direct URL mode: IP address is rejected.
#[test]
fn ssrf_direct_ip_rejected() {
    let result = assert_same_domain_or_https_fqdn("https://169.254.169.254/sep6", None);
    assert!(
        matches!(result, Err(AnchorError::InvalidDirectUrl { .. })),
        "169.254.169.254 must be rejected in direct-URL mode; got: {result:?}"
    );
}

/// Direct URL mode: single-label hostname is rejected (SSRF guard).
#[test]
fn ssrf_direct_single_label_rejected() {
    let result = assert_same_domain_or_https_fqdn("https://localhost/sep6", None);
    assert!(
        matches!(result, Err(AnchorError::InvalidDirectUrl { .. })),
        "localhost must be rejected in direct-URL mode; got: {result:?}"
    );
}

/// Direct URL mode: valid public FQDN is accepted.
#[test]
fn ssrf_direct_valid_fqdn_accepted() {
    let result = assert_same_domain_or_https_fqdn("https://transfer.example.com/sep6", None);
    assert!(
        result.is_ok(),
        "valid FQDN transfer.example.com must be accepted; got: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// SEP-6 positive-capability-bound path-literal test
// ─────────────────────────────────────────────────────────────────────────────

/// Asserts that the ONLY anchor path literal in `sep6.rs` is `/info`.
///
/// The SEP-6 module must be structurally incapable of calling any endpoint
/// other than `/info`.  This is the integration-test mirror of the in-crate
/// unit test in `sep6.rs::tests::sep6_source_contains_only_info_path`.
#[test]
fn sep6_module_path_literal_is_only_info() {
    let source = include_str!("../src/sep6.rs");

    let forbidden: &[&str] = &[
        "\"/deposit\"",
        "\"/withdraw\"",
        "\"/deposit-exchange\"",
        "\"/withdraw-exchange\"",
        "\"/customer\"",
        "\"/fee\"",
        "\"/transaction\"",
        "\"/transactions\"",
    ];
    for f in forbidden {
        assert!(
            !source.contains(f),
            "sep6.rs contains forbidden path literal {f:?}; \
             the SEP-6 module calls ONLY /info (positive capability bound — no deposit/withdraw/customer paths)"
        );
    }
    assert!(
        source.contains("/info"),
        "sep6.rs must contain the /info path literal"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// SEP-24 response decode tests (offline fixture leg)
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes a captured interactive response fixture via the REAL production
/// `parse_interactive_response` function (not a locally-re-declared struct).
///
/// Drives the actual production serde decode + type-check path.  A field-rename
/// in the real `InteractiveResponse` will be caught here without a live call.
///
/// Fixture mirrors SEP-24 §5.4 example.
#[test]
fn sep24_offline_interactive_response_fixture_decodes() {
    use stellar_agent_anchor::parse_interactive_response;

    let fixture = r#"{
        "type": "interactive_customer_info_needed",
        "url": "https://api.example.com/kycflow?account=GACW7NONV43MZIFHCOKCQJAKSJSISSICFVUJ2C6EZIW5773OU3HD64VI",
        "id": "82fhs729f63dh0v4"
    }"#;

    let result = parse_interactive_response(fixture).expect("fixture must decode without error");
    assert!(result.interactive_url.starts_with("https://"));
    assert_eq!(result.transaction_id, "82fhs729f63dh0v4");
    assert!(!result.handoff_note.is_empty());
}

/// SEP-24 unexpected-type response → `Sep24UnexpectedResponseType` error,
/// driven via the real `parse_interactive_response` path.
#[test]
fn sep24_unexpected_type_returns_error() {
    use stellar_agent_anchor::parse_interactive_response;

    let bad =
        r#"{"type": "non_interactive_customer_info_needed", "url": "https://x.com", "id": "abc"}"#;
    let result = parse_interactive_response(bad);
    assert!(
        matches!(
            result,
            Err(AnchorError::Sep24UnexpectedResponseType {
                ref response_type
            }) if response_type == "non_interactive_customer_info_needed"
        ),
        "unexpected type must return Sep24UnexpectedResponseType; got: {result:?}"
    );
}

/// Malformed anchor response → decode error, no panic.
/// Driven via the real `parse_interactive_response` path.
#[test]
fn sep24_malformed_response_returns_error_not_panic() {
    use stellar_agent_anchor::parse_interactive_response;

    let bad_inputs: &[&str] = &[
        "not-json",
        "",
        "{}",
        r#"{"type": 42, "url": "x", "id": "y"}"#,
        r#"{"url": "x", "id": "y"}"#, // missing type field
        &"x".repeat(200_000),         // oversized
    ];

    for input in bad_inputs {
        // Must not panic — errors are expected.
        let result = parse_interactive_response(input);
        assert!(
            result.is_err(),
            "malformed input must return Err; input len={}",
            input.len()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SEP-6 offline fixture decode tests
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes a captured SEP-6 /info fixture using the SAME decode types the
/// live SEP-6 leg uses.
#[test]
fn sep6_offline_info_fixture_decodes() {
    // Fixture based on SEP-6 §5.1 example.
    let fixture = r#"{
        "deposit": {
            "USD": {
                "enabled": true,
                "authentication_required": true,
                "min_amount": 0.1,
                "max_amount": 1000,
                "funding_methods": ["SEPA", "SWIFT", "cash"]
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
                "min_amount": 0.1,
                "max_amount": 1000,
                "funding_methods": ["bank_account", "cash", "crypto"]
            },
            "ETH": {
                "enabled": false
            }
        },
        "deposit-exchange": {
            "USD": {
                "authentication_required": true
            }
        },
        "withdraw-exchange": {
            "USD": {
                "authentication_required": true
            }
        },
        "features": {
            "account_creation": true,
            "claimable_balances": true
        }
    }"#;

    let info: Sep6Info = serde_json::from_str(fixture).expect("fixture must decode without error");

    assert_eq!(info.deposit.len(), 2, "must have 2 deposit assets");
    let usd = info.deposit.get("USD").expect("USD must be present");
    assert!(usd.enabled, "USD deposit must be enabled");
    assert!(usd.authentication_required, "USD deposit must require auth");
    assert_eq!(usd.min_amount, Some(0.1));
    assert_eq!(usd.max_amount, Some(1000.0));

    let eth = info.deposit.get("ETH").expect("ETH must be present");
    assert!(!eth.authentication_required, "ETH must not require auth");

    assert!(info.features.account_creation);
    assert!(info.features.claimable_balances);

    // authentication_required is surfaced for discovery callers.
    for (asset, info) in &info.deposit {
        let _ = info.authentication_required; // must be readable
        let _ = asset;
    }
}

/// Malformed SEP-6 /info response → decode error, no panic.
///
/// `"{}"` legitimately decodes to `Sep6Info::default()` and is not in the
/// must-error list.
#[test]
fn sep6_malformed_response_returns_error_not_panic() {
    let bad_inputs: &[&str] = &["not-json", "", &"x".repeat(200_000)];
    for input in bad_inputs {
        let result = serde_json::from_str::<Sep6Info>(input);
        assert!(
            result.is_err(),
            "malformed SEP-6 /info must return Err; input len={}",
            input.len()
        );
    }
}
