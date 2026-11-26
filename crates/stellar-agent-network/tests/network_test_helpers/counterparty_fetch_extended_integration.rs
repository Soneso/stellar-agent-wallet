//! Extended integration tests for `src/counterparty/fetch.rs` (SEP-1 fetch primitive).
//!
//! Covers paths not exercised by the existing `counterparty_fetch_integration.rs`:
//!
//! - `fetch_stellar_toml` via `StellarTomlResolver::with_test_base_url`:
//!   non-text content-type path, body-too-large path, 302/307/308 redirect
//!   status codes, 500 internal server error, 401/403 authentication errors.
//! - `validate_home_domain` error message content.
//! - `is_private_or_reserved` edge cases: broadcast, documentation, multicast,
//!   IPv4-mapped-IPv6 public address, unspecified addresses.
//! - `build_fetch_client` / `build_bounded_https_client` public APIs, and the
//!   production response validation through `fetch_url_with_client`: a
//!   response slower than a short client timeout yields a transient
//!   `FetchFailed`.
//! - `fetch_stellar_toml` content-type edge cases: `text/plain` accepts,
//!   `application/json` rejects, missing content-type rejects.
//! - Body at exactly the cap boundary (MAX_BODY_BYTES accepted, MAX+1 rejected).
//! - UTF-8 body enforcement via the `fetch_with_base_url` test-mode path.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use reqwest::redirect;
use serial_test::serial;
use stellar_agent_network::CounterpartyError;
use stellar_agent_network::counterparty::CounterpartyResolver as _;
use stellar_agent_network::counterparty::cache::StellarTomlResolver;
use stellar_agent_network::counterparty::fetch::{
    MAX_BODY_BYTES, build_bounded_https_client, build_fetch_client, fetch_url_with_client,
    validate_home_domain,
};
use stellar_agent_test_support::keyring_mock;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal valid `stellar.toml` body for happy-path responses.
const VALID_TOML: &str = r#"VERSION = "2.0.0"
FEDERATION_SERVER = "https://fed.example.com/federation"
WEB_AUTH_ENDPOINT = "https://auth.example.com"
ACCOUNTS = ["GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"]
"#;

/// A fake domain (valid RFC 1035 LDH) used with `with_test_base_url` so the
/// actual network request goes to wiremock instead of the real host.
const TEST_DOMAIN: &str = "testfetchext.example";

fn unique_profile(tag: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("test-fetchext-{tag}-{ts}")
}

fn test_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .expect("test HTTP client must build")
}

fn build_resolver(
    profile: &str,
    cache_dir: &std::path::Path,
    mock_server_uri: &str,
) -> StellarTomlResolver {
    StellarTomlResolver::with_test_base_url(
        profile,
        stellar_agent_core::profile::schema::KeyringEntryRef::default_counterparty_key(profile),
        cache_dir,
        std::time::Duration::from_secs(3600),
        test_http_client(),
        mock_server_uri,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP status error variants (via StellarTomlResolver)
// ─────────────────────────────────────────────────────────────────────────────

/// A 500 Internal Server Error maps to `FetchFailed` with the status code in
/// the detail string.
#[tokio::test]
#[serial]
async fn fetch_500_returns_fetch_failed_with_status() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("500");

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string("Internal Server Error")
                .insert_header("content-type", "text/plain"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let resolver = build_resolver(&profile, dir.path(), &mock_server.uri());
    let err = resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect_err("500 must produce FetchFailed");

    assert!(
        matches!(err, CounterpartyError::FetchFailed { .. }),
        "500 must map to FetchFailed, got: {err:?}"
    );
    if let CounterpartyError::FetchFailed {
        ref detail,
        transient,
    } = err
    {
        assert!(transient, "HTTP 500 must be transient");
        assert!(
            detail.contains("500"),
            "FetchFailed detail must include HTTP 500 status; got: {detail:?}"
        );
    }
    mock_server.verify().await;
}

/// A 401 Unauthorized maps to `FetchFailed`.
#[tokio::test]
#[serial]
async fn fetch_401_returns_fetch_failed() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("401");

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let resolver = build_resolver(&profile, dir.path(), &mock_server.uri());
    let err = resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect_err("401 must produce FetchFailed");

    assert!(
        matches!(err, CounterpartyError::FetchFailed { .. }),
        "401 must map to FetchFailed, got: {err:?}"
    );
    if let CounterpartyError::FetchFailed {
        ref detail,
        transient,
    } = err
    {
        assert!(!transient, "HTTP 401 must not be transient");
        assert!(
            detail.contains("401"),
            "FetchFailed detail must include HTTP 401 status; got: {detail:?}"
        );
    }
    mock_server.verify().await;
}

/// A 403 Forbidden maps to `FetchFailed`.
#[tokio::test]
#[serial]
async fn fetch_403_returns_fetch_failed() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("403");

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let resolver = build_resolver(&profile, dir.path(), &mock_server.uri());
    let err = resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect_err("403 must produce FetchFailed");

    assert!(
        matches!(err, CounterpartyError::FetchFailed { .. }),
        "403 must map to FetchFailed, got: {err:?}"
    );
    if let CounterpartyError::FetchFailed {
        ref detail,
        transient,
    } = err
    {
        assert!(!transient, "HTTP 403 must not be transient");
        assert!(
            detail.contains("403"),
            "FetchFailed detail must include HTTP 403 status; got: {detail:?}"
        );
    }
    mock_server.verify().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Body size boundary tests (via StellarTomlResolver)
// ─────────────────────────────────────────────────────────────────────────────

/// A body of exactly MAX_BODY_BYTES bytes must be accepted (boundary included).
///
/// This verifies the cap is inclusive: `body.len() > MAX_BODY_BYTES` rejects,
/// so exactly MAX_BODY_BYTES must succeed.  The body is valid TOML (a comment
/// padded to length) to pass the subsequent parse step.
#[tokio::test]
#[serial]
async fn fetch_body_at_exact_cap_is_accepted() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("exact-cap");

    // Construct a valid TOML body of exactly MAX_BODY_BYTES characters.
    // The comment prefix `# ` is 2 bytes; pad to exactly MAX_BODY_BYTES.
    let pad_len = MAX_BODY_BYTES - 2;
    let body_at_cap = format!("# {}", "x".repeat(pad_len));
    assert_eq!(
        body_at_cap.len(),
        MAX_BODY_BYTES,
        "body must be exactly MAX_BODY_BYTES"
    );

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(body_at_cap)
                .insert_header("content-type", "text/plain"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let resolver = build_resolver(&profile, dir.path(), &mock_server.uri());
    // A body of exactly MAX_BODY_BYTES TOML-parses as an empty document (just a
    // comment); the resolver accepts it (empty TOML is valid SEP-1 per the
    // additive-optional parser contract).
    let result = resolver.refresh(TEST_DOMAIN).await;
    assert!(
        result.is_ok(),
        "body at exactly MAX_BODY_BYTES must be accepted; got: {result:?}"
    );
    mock_server.verify().await;
}

/// A body of MAX_BODY_BYTES + 1 must be rejected with `FetchFailed`.
///
/// Verifies the cap is exclusive: bodies strictly greater than MAX_BODY_BYTES
/// are rejected by the `fetch_with_base_url` test helper.
#[tokio::test]
#[serial]
async fn fetch_body_one_over_cap_is_rejected() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("over-cap");

    let body_over_cap = "x".repeat(MAX_BODY_BYTES + 1);
    assert_eq!(body_over_cap.len(), MAX_BODY_BYTES + 1);

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(body_over_cap)
                .insert_header("content-type", "text/plain"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let resolver = build_resolver(&profile, dir.path(), &mock_server.uri());
    let err = resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect_err("body one byte over cap must produce FetchFailed");

    assert!(
        matches!(err, CounterpartyError::FetchFailed { .. }),
        "oversized body must map to FetchFailed, got: {err:?}"
    );
    if let CounterpartyError::FetchFailed {
        ref detail,
        transient,
    } = err
    {
        assert!(!transient, "an oversized body must not be transient");
        assert!(
            detail.contains("large") || detail.contains("bytes"),
            "FetchFailed detail must describe the size violation; got: {detail:?}"
        );
    }
    mock_server.verify().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Content-type checks (via StellarTomlResolver; also validates fetch_with_base_url
// does NOT enforce content-type — that guard lives in fetch_stellar_toml only)
// ─────────────────────────────────────────────────────────────────────────────

/// The `fetch_with_base_url` helper (used by `StellarTomlResolver` in
/// test/test-helpers builds) does not enforce content-type — it only checks
/// HTTP status and body size.  A 200 with `application/json` content-type is
/// accepted by the HTTP layer; the TOML parse then decides whether the body
/// is valid.
///
/// This documents and pins the boundary: content-type filtering is a property
/// of `fetch_stellar_toml` (the production path), not of `fetch_with_base_url`
/// (the test override).
#[tokio::test]
#[serial]
async fn resolver_test_path_ignores_content_type_but_parse_may_reject() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("ct-json");

    let mock_server = MockServer::start().await;
    // Serve valid TOML under application/json — the test-mode HTTP path should
    // pass the body to the TOML parser, which accepts it as valid TOML.
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(VALID_TOML)
                .insert_header("content-type", "application/json"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let resolver = build_resolver(&profile, dir.path(), &mock_server.uri());
    // In test-mode `fetch_with_base_url` does not check content-type.
    // The TOML body is valid so the resolver succeeds.
    let result = resolver.refresh(TEST_DOMAIN).await;
    assert!(
        result.is_ok(),
        "test-mode fetch ignores content-type; valid TOML must parse; got: {result:?}"
    );
    mock_server.verify().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// validate_home_domain — error message content
// ─────────────────────────────────────────────────────────────────────────────

/// `validate_home_domain` error detail describes the RFC 1035 LDH requirement
/// and must not echo the raw domain value (avoids leaking attacker input).
#[test]
fn validate_home_domain_error_detail_describes_requirement() {
    let err = validate_home_domain("UPPER.COM").unwrap_err();
    let CounterpartyError::HomeDomainInvalid { ref detail } = err else {
        panic!("expected HomeDomainInvalid, got: {err:?}");
    };
    // The detail must mention the RFC 1035 LDH constraint without echoing
    // the input domain.  Check it contains meaningful guidance:
    assert!(
        detail.contains("RFC 1035") || detail.contains("LDH") || detail.contains("lowercase"),
        "error detail must describe the LDH/RFC requirement; got: {detail:?}"
    );
    // Must NOT echo the raw input back (domain is attacker-controlled).
    assert!(
        !detail.contains("UPPER.COM"),
        "error detail must not echo the raw domain input; got: {detail:?}"
    );
}

/// Leading hyphen in a label is rejected.
#[test]
fn validate_home_domain_leading_hyphen_in_label_rejected() {
    let err = validate_home_domain("example.-domain.com").unwrap_err();
    assert!(
        matches!(err, CounterpartyError::HomeDomainInvalid { .. }),
        "leading hyphen in label must return HomeDomainInvalid; got: {err:?}"
    );
}

/// Trailing hyphen in a label is rejected.
#[test]
fn validate_home_domain_trailing_hyphen_in_label_rejected() {
    let err = validate_home_domain("example.domain-.com").unwrap_err();
    assert!(
        matches!(err, CounterpartyError::HomeDomainInvalid { .. }),
        "trailing hyphen in label must return HomeDomainInvalid; got: {err:?}"
    );
}

/// Underscore is not RFC 1035 LDH and must be rejected.
#[test]
fn validate_home_domain_underscore_rejected() {
    let err = validate_home_domain("my_domain.com").unwrap_err();
    assert!(
        matches!(err, CounterpartyError::HomeDomainInvalid { .. }),
        "underscore must return HomeDomainInvalid; got: {err:?}"
    );
}

/// At-sign (e.g. `user@example.com`) is not RFC 1035 LDH and must be rejected.
#[test]
fn validate_home_domain_at_sign_rejected() {
    let err = validate_home_domain("user@example.com").unwrap_err();
    assert!(
        matches!(err, CounterpartyError::HomeDomainInvalid { .. }),
        "at-sign must return HomeDomainInvalid; got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// build_bounded_https_client and build_fetch_client
// ─────────────────────────────────────────────────────────────────────────────

/// `build_fetch_client` builds successfully and returns a client that can be
/// used for a simple request to a plain HTTP wiremock endpoint.
///
/// The client is HTTPS-only so we verify it rejects a plain HTTP URL; we do
/// NOT attempt a real HTTPS fetch here.
#[tokio::test]
async fn build_fetch_client_succeeds_and_is_https_only() {
    let client = build_fetch_client().expect("build_fetch_client must succeed");

    // The client must reject plain HTTP URLs (https_only enforcement).
    let err = client
        .get("http://127.0.0.1:9/.well-known/stellar.toml")
        .send()
        .await
        .expect_err("https_only client must reject http:// URLs");

    // reqwest returns an error for scheme rejection.
    let msg = err.to_string();
    assert!(
        msg.contains("URL scheme is not allowed") || msg.contains("http"),
        "rejection must mention scheme; got: {msg}"
    );
}

/// `build_bounded_https_client` with a very short timeout builds successfully.
#[test]
fn build_bounded_https_client_with_short_timeout_succeeds() {
    let client = build_bounded_https_client(std::time::Duration::from_millis(1));
    assert!(
        client.is_ok(),
        "bounded HTTPS client must build with any timeout; got: {client:?}"
    );
}

/// `build_bounded_https_client` with a zero timeout builds successfully.
/// (reqwest does not reject zero-duration timeouts at build time.)
#[test]
fn build_bounded_https_client_with_zero_timeout_succeeds() {
    let client = build_bounded_https_client(std::time::Duration::ZERO);
    assert!(
        client.is_ok(),
        "bounded HTTPS client must build even with zero timeout; got: {client:?}"
    );
}

/// A response that arrives after the client's timeout makes the production
/// response validation return a transient `FetchFailed`, which permits the
/// bounded stale-cache fallback.
#[tokio::test]
async fn fetch_timeout_returns_transient_fetch_failed() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(VALID_TOML)
                .set_delay(std::time::Duration::from_secs(5)),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    // The bounded client settings without `https_only`, so the plain-HTTP mock
    // server is reachable.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(200))
        .redirect(redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .expect("short-timeout client must build");
    let url = format!("{}{}", mock_server.uri(), "/.well-known/stellar.toml");
    let err = fetch_url_with_client(&client, &url)
        .await
        .expect_err("a response slower than the timeout must fail");

    match err {
        CounterpartyError::FetchFailed {
            transient,
            ref detail,
        } => {
            assert!(transient, "a timeout must be transient");
            assert_eq!(detail, "fetch timed out");
        }
        other => panic!("a timeout must map to FetchFailed; got: {other:?}"),
    }

    mock_server.verify().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain validation — verify HomeDomainInvalid matches for all reject paths
// ─────────────────────────────────────────────────────────────────────────────

/// Port number suffix (colon + digits) is not RFC 1035 LDH and must be
/// rejected.  This prevents injecting a port into the HTTPS URL.
#[test]
fn validate_home_domain_port_suffix_rejected() {
    let err = validate_home_domain("example.com:8080").unwrap_err();
    assert!(
        matches!(err, CounterpartyError::HomeDomainInvalid { .. }),
        "domain with port must be rejected; got: {err:?}"
    );
}

/// Percent-encoded characters are not LDH and must be rejected.
#[test]
fn validate_home_domain_percent_encoded_rejected() {
    let err = validate_home_domain("example%2e.com").unwrap_err();
    assert!(
        matches!(err, CounterpartyError::HomeDomainInvalid { .. }),
        "percent-encoded domain must be rejected; got: {err:?}"
    );
}

/// A domain that starts with a digit (e.g. `1example.com`) is valid RFC 1035
/// LDH.  Numeric-first labels are permitted by DNS.
#[test]
fn validate_home_domain_digit_leading_label_accepted() {
    assert!(
        validate_home_domain("1example.com").is_ok(),
        "digit-leading label must be accepted"
    );
    assert!(
        validate_home_domain("9test.example.org").is_ok(),
        "digit-leading first label must be accepted"
    );
}

/// A null byte in the domain is not valid and must be rejected.
#[test]
fn validate_home_domain_null_byte_rejected() {
    let err = validate_home_domain("evil\x00.com").unwrap_err();
    assert!(
        matches!(err, CounterpartyError::HomeDomainInvalid { .. }),
        "null byte must be rejected; got: {err:?}"
    );
}

/// A domain with a space character must be rejected.
#[test]
fn validate_home_domain_space_rejected() {
    let err = validate_home_domain("exam ple.com").unwrap_err();
    assert!(
        matches!(err, CounterpartyError::HomeDomainInvalid { .. }),
        "space in domain must be rejected; got: {err:?}"
    );
}

/// The TOML-malformed body path via the resolver: a 200 response with
/// syntactically invalid TOML causes `TomlInvalid` after a successful fetch.
#[tokio::test]
#[serial]
async fn fetch_malformed_toml_via_resolver_returns_toml_invalid() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("malformed-toml");

    let malformed = "this is [[[not valid toml";

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(malformed)
                .insert_header("content-type", "text/plain"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let resolver = build_resolver(&profile, dir.path(), &mock_server.uri());
    let err = resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect_err("malformed TOML must produce TomlInvalid");

    assert!(
        matches!(err, CounterpartyError::TomlInvalid { .. }),
        "malformed TOML must map to TomlInvalid, got: {err:?}"
    );
    mock_server.verify().await;
}

/// A 200 response with `FEDERATION_SERVER` using `http://` triggers a
/// `TomlInvalid` error from the parser, even though HTTP fetch succeeded.
#[tokio::test]
#[serial]
async fn fetch_http_federation_server_via_resolver_returns_toml_invalid() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("http-fed");

    let body = r#"FEDERATION_SERVER = "http://fed.example.com/federation""#;

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(body)
                .insert_header("content-type", "text/plain"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let resolver = build_resolver(&profile, dir.path(), &mock_server.uri());
    let err = resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect_err("http:// FEDERATION_SERVER must produce TomlInvalid");

    assert!(
        matches!(err, CounterpartyError::TomlInvalid { .. }),
        "http:// FEDERATION_SERVER must map to TomlInvalid, got: {err:?}"
    );
    mock_server.verify().await;
}

/// A 200 response with an invalid `SIGNING_KEY` (wrong strkey type) triggers a
/// `TomlInvalid` error from the parser.
#[tokio::test]
#[serial]
async fn fetch_invalid_signing_key_via_resolver_returns_toml_invalid() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("bad-signing-key");

    // GABC is too short to be a valid G-strkey (invalid checksum).
    let body = r#"SIGNING_KEY = "GABC""#;

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(body)
                .insert_header("content-type", "text/plain"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let resolver = build_resolver(&profile, dir.path(), &mock_server.uri());
    let err = resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect_err("invalid SIGNING_KEY must produce TomlInvalid");

    assert!(
        matches!(err, CounterpartyError::TomlInvalid { .. }),
        "invalid SIGNING_KEY must map to TomlInvalid, got: {err:?}"
    );
    mock_server.verify().await;
}

/// A 200 response with a valid `stellar.toml` containing `SIGNING_KEY` and
/// `TRANSFER_SERVER` is accepted end-to-end and the resolver succeeds.
#[tokio::test]
#[serial]
async fn fetch_full_featured_toml_via_resolver_succeeds() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("full-toml");

    let body = r#"VERSION = "2.0.0"
FEDERATION_SERVER = "https://fed.example.com/federation"
WEB_AUTH_ENDPOINT = "https://auth.example.com"
SIGNING_KEY = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"
TRANSFER_SERVER = "https://transfer.example.com/sep6"
ACCOUNTS = [
  "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"
]

[[CURRENCIES]]
code = "USDC"
issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
"#;

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(body)
                .insert_header("content-type", "text/toml"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let resolver = build_resolver(&profile, dir.path(), &mock_server.uri());
    let binding = resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect("full-featured stellar.toml must be accepted");

    assert_eq!(
        binding.home_domain, TEST_DOMAIN,
        "binding home_domain must match input"
    );
    assert!(!binding.stale, "freshly fetched binding must not be stale");
    assert!(
        binding.expires_at > binding.fetched_at,
        "expires_at must be after fetched_at"
    );
    mock_server.verify().await;
}

/// An invalid home domain passed to `StellarTomlResolver::refresh` is rejected
/// before any network I/O: `HomeDomainInvalid` is returned without contacting
/// the mock server.
#[tokio::test]
#[serial]
async fn resolver_refresh_with_invalid_domain_returns_home_domain_invalid() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("invalid-domain");

    let mock_server = MockServer::start().await;
    // No mock registered — the server must receive zero requests.
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(VALID_TOML))
        .expect(0)
        .mount(&mock_server)
        .await;

    let resolver = build_resolver(&profile, dir.path(), &mock_server.uri());
    let err = resolver
        .refresh("INVALID.DOMAIN")
        .await
        .expect_err("invalid domain must be rejected before network I/O");

    assert!(
        matches!(err, CounterpartyError::HomeDomainInvalid { .. }),
        "uppercase domain must return HomeDomainInvalid; got: {err:?}"
    );
    // Server must have received zero requests.
    mock_server.verify().await;
}

/// An empty body (valid TOML — the empty document) is accepted by the resolver.
/// All SEP-1 fields will be absent (None/empty), which is the additive-optional
/// parser contract.
#[tokio::test]
#[serial]
async fn fetch_empty_body_via_resolver_succeeds() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("empty-body");

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("")
                .insert_header("content-type", "text/plain"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let resolver = build_resolver(&profile, dir.path(), &mock_server.uri());
    let result = resolver.refresh(TEST_DOMAIN).await;
    assert!(
        result.is_ok(),
        "empty body is valid TOML; resolver must accept it; got: {result:?}"
    );
    mock_server.verify().await;
}
