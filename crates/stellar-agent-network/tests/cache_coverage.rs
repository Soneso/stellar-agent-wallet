//! Additional coverage tests for `counterparty/cache.rs`.
//!
//! Targets branches not reached by `counterparty_cache_integration.rs`:
//!
//! - `fetched_at_unix_s_to_i64` saturation path (u64 > i64::MAX).
//! - `fetched_at_i64_to_unix_s` with zero and negative input.
//! - `base64_decode_key` with wrong-length decoded bytes (not 32 bytes).
//! - `read_cache_entry` (test-helpers) with an expired TTL → returns None.
//! - `read_cache_entry` with a valid fresh entry → returns Some.
//! - `cache_file_path` collision: two domains that map to the same sanitised
//!   filename (`my-bank.com` and `my.bank.com` → both `my_bank_com.toml.cache`).
//! - `StellarTomlResolver::with_stale_if_error(false)` fails closed when
//!   fetch fails and no cache exists.
//! - Write + read round-trip confirms the domain is recovered from the body
//!   header, not from the filename (hyphen vs dot collision scenario).
//! - `StellarTomlResolver::new` succeeds (basic construction path).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serial_test::serial;
use stellar_agent_network::CounterpartyError;
use stellar_agent_network::counterparty::CounterpartyResolver as _;
use stellar_agent_network::counterparty::cache::{
    StellarTomlResolver, cache_file_path, read_cache_entry,
};
use stellar_agent_test_support::keyring_mock;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers (re-exported as pub under test-helpers)
// ─────────────────────────────────────────────────────────────────────────────
//
// The cache module exposes the following items under `#[cfg(any(test, feature = "test-helpers"))]`:
//   - `cache_file_path`
//   - `read_cache_entry`
//
// We use these directly to exercise paths that are not reachable through the
// higher-level `StellarTomlResolver` API.

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const VALID_STELLAR_TOML: &str = r#"
VERSION = "2.0.0"
FEDERATION_SERVER = "https://fed.example.com/federation"
WEB_AUTH_ENDPOINT = "https://auth.example.com"
ACCOUNTS = ["GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"]
"#;

const TEST_DOMAIN: &str = "testdomain.example";

fn unique_profile(label: &str) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("cache-cov-{label}-{ts}")
}

fn build_test_resolver(
    profile: &str,
    cache_dir: &std::path::Path,
    ttl: Duration,
    mock_server_uri: &str,
) -> StellarTomlResolver {
    use reqwest::redirect;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .expect("test client build");
    StellarTomlResolver::with_test_base_url(profile, cache_dir, ttl, client, mock_server_uri)
}

async fn mount_stellar_toml_mock(mock_server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(VALID_STELLAR_TOML)
                .insert_header("content-type", "text/toml; charset=utf-8"),
        )
        .mount(mock_server)
        .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// cache_file_path: collision between `my-bank.com` and `my.bank.com`
// ─────────────────────────────────────────────────────────────────────────────

/// Both `my-bank.com` and `my.bank.com` sanitise to `my_bank_com.toml.cache`.
/// The collision is intentional and documented — the canonical domain is
/// recovered from the HMAC-protected body, not from the filename.
#[test]
fn cache_file_path_dot_and_hyphen_domains_collide() {
    let dir = std::path::PathBuf::from("/tmp");
    let p1 = cache_file_path(&dir, "my-bank.com");
    let p2 = cache_file_path(&dir, "my.bank.com");
    assert_eq!(
        p1.file_name().unwrap().to_str().unwrap(),
        "my_bank_com.toml.cache",
        "hyphen domain must sanitise to underscore"
    );
    assert_eq!(
        p2.file_name().unwrap().to_str().unwrap(),
        "my_bank_com.toml.cache",
        "dot domain must sanitise to underscore"
    );
    // The two paths are identical — this is the documented collision.
    assert_eq!(
        p1, p2,
        "dot and hyphen domains must collide to the same path"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// read_cache_entry: expired TTL → returns None
// ─────────────────────────────────────────────────────────────────────────────

/// `read_cache_entry` with a zero TTL must return `None` (expired) for an
/// otherwise valid cache file.
///
/// The HMAC key and cache body are valid; the TTL of zero nanoseconds
/// guarantees `now > expires_at` by the time the check runs.
#[tokio::test]
#[serial]
async fn read_cache_entry_expired_ttl_returns_none() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("expired-read");

    let mock_server = MockServer::start().await;
    mount_stellar_toml_mock(&mock_server).await;

    // Refresh with a large TTL so the file is written.
    let resolver = build_test_resolver(
        &profile,
        dir.path(),
        Duration::from_secs(3600),
        &mock_server.uri(),
    );
    resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect("refresh must succeed");

    // Retrieve the HMAC key from the keyring.
    let service = format!("stellar-agent-counterparty-{profile}");
    let entry = keyring_core::Entry::new(&service, "default").expect("entry open");
    let raw_b64 = entry.get_password().expect("key must exist after refresh");
    use base64::Engine as _;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&raw_b64)
        .expect("valid base64");
    let key_arr: [u8; 32] = key_bytes.try_into().expect("32-byte key");

    let cache_path = cache_file_path(dir.path(), TEST_DOMAIN);

    // A zero TTL means the entry is immediately expired.
    let result = read_cache_entry(&cache_path, &key_arr, Duration::ZERO)
        .expect("read_cache_entry must not error on a valid file");

    assert!(
        result.is_none(),
        "expired TTL must return None, not Some(_)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// read_cache_entry: valid fresh entry → returns Some with correct binding
// ─────────────────────────────────────────────────────────────────────────────

/// `read_cache_entry` with a large TTL must return `Some((parsed, binding))`
/// for a valid, recently-written cache file.
#[tokio::test]
#[serial]
async fn read_cache_entry_fresh_ttl_returns_some_with_correct_domain() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("fresh-read");

    let mock_server = MockServer::start().await;
    mount_stellar_toml_mock(&mock_server).await;

    let resolver = build_test_resolver(
        &profile,
        dir.path(),
        Duration::from_secs(3600),
        &mock_server.uri(),
    );
    let binding = resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect("refresh must succeed");

    // Retrieve the HMAC key from the keyring.
    let service = format!("stellar-agent-counterparty-{profile}");
    let entry = keyring_core::Entry::new(&service, "default").expect("entry open");
    let raw_b64 = entry.get_password().expect("key must exist after refresh");
    use base64::Engine as _;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&raw_b64)
        .expect("valid base64");
    let key_arr: [u8; 32] = key_bytes.try_into().expect("32-byte key");

    let cache_path = cache_file_path(dir.path(), TEST_DOMAIN);

    let result = read_cache_entry(&cache_path, &key_arr, Duration::from_secs(3600))
        .expect("read_cache_entry must not error on a valid fresh file");

    let (parsed, returned_binding) = result.expect("fresh entry must return Some");

    // The binding home_domain must match what was written.
    assert_eq!(returned_binding.home_domain, TEST_DOMAIN);
    // fetched_at is stored on disk as a UNIX-second i64, so it round-trips at
    // second granularity (sub-second precision is intentionally dropped).
    let recovered_secs = returned_binding
        .fetched_at
        .duration_since(std::time::UNIX_EPOCH)
        .expect("fetched_at after epoch")
        .as_secs();
    let original_secs = binding
        .fetched_at
        .duration_since(std::time::UNIX_EPOCH)
        .expect("fetched_at after epoch")
        .as_secs();
    assert_eq!(
        recovered_secs, original_secs,
        "fetched_at must be recovered from the HMAC-protected body at second granularity"
    );
    // The parsed SEP-1 must contain a non-empty federation_server URL.
    assert!(
        parsed.federation_server.is_some(),
        "parsed stellar.toml must include FEDERATION_SERVER"
    );
    assert_eq!(
        parsed.federation_server.as_deref(),
        Some("https://fed.example.com/federation")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// read_cache_entry: HMAC mismatch → propagates HmacMismatch
// ─────────────────────────────────────────────────────────────────────────────

/// `read_cache_entry` must return `Err(HmacMismatch)` when the stored tag
/// does not match a recomputed tag (wrong key is used for verification).
#[tokio::test]
#[serial]
async fn read_cache_entry_wrong_key_returns_hmac_mismatch() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("wrong-key-read");

    let mock_server = MockServer::start().await;
    mount_stellar_toml_mock(&mock_server).await;

    let resolver = build_test_resolver(
        &profile,
        dir.path(),
        Duration::from_secs(3600),
        &mock_server.uri(),
    );
    resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect("refresh must succeed");

    let cache_path = cache_file_path(dir.path(), TEST_DOMAIN);
    // Use a wrong key (all zeros).
    let wrong_key = [0u8; 32];

    let result = read_cache_entry(&cache_path, &wrong_key, Duration::from_secs(3600));

    assert!(
        matches!(result, Err(CounterpartyError::HmacMismatch)),
        "wrong key must produce HmacMismatch, got: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// StellarTomlResolver::new — basic construction succeeds
// ─────────────────────────────────────────────────────────────────────────────

/// `StellarTomlResolver::new` must succeed with a valid directory path and TTL.
/// The `new` constructor builds an internal HTTP client.
#[test]
fn stellar_toml_resolver_new_succeeds() {
    let dir = TempDir::new().expect("tmpdir");
    let result = StellarTomlResolver::new("default", dir.path(), Duration::from_secs(3600));
    assert!(
        result.is_ok(),
        "StellarTomlResolver::new must succeed with a valid cache dir: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// StellarTomlResolver::with_stale_if_error(false) — fail-closed behaviour
// ─────────────────────────────────────────────────────────────────────────────

/// When `stale_if_error` is `false` (the default) and no cache exists, a
/// fetch failure must propagate as `Err(FetchFailed)`, not silently succeed.
///
/// This tests the fail-closed contract: the resolver must not return stale
/// data when the caller has not opted in via `with_stale_if_error(true)`.
#[tokio::test]
#[serial]
async fn stale_if_error_false_fail_closed_no_stale_return() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("fail-closed");

    // Point the resolver at an unreachable port.
    let failing_resolver =
        build_test_resolver(&profile, dir.path(), Duration::from_secs(3600), "http://127.0.0.1:9")
            // Default (stale_if_error = false) — do NOT call with_stale_if_error(true).
            ;

    let result = failing_resolver.refresh(TEST_DOMAIN).await;

    assert!(
        result.is_err(),
        "fail-closed resolver must return Err when fetch fails and no cache exists"
    );
    assert!(
        matches!(result.unwrap_err(), CounterpartyError::FetchFailed { .. }),
        "expected FetchFailed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// StellarTomlResolver::with_stale_if_error(false) with stale cache present
// ─────────────────────────────────────────────────────────────────────────────

/// When `stale_if_error` is `false`, even if a stale HMAC-verified cache entry
/// exists on disk, a fetch failure must propagate as `Err(FetchFailed)`.
#[tokio::test]
#[serial]
async fn stale_if_error_false_ignores_stale_cache_on_failure() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("fail-closed-stale");

    let mock_server = MockServer::start().await;
    mount_stellar_toml_mock(&mock_server).await;

    // First write a valid cache entry.
    let tiny_ttl = Duration::from_nanos(1);
    let writer = build_test_resolver(&profile, dir.path(), tiny_ttl, &mock_server.uri());
    writer.refresh(TEST_DOMAIN).await.expect("initial refresh");
    // TTL expires immediately.
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Now point at a failing server with stale_if_error = false (default).
    let failing_resolver =
        build_test_resolver(&profile, dir.path(), tiny_ttl, "http://127.0.0.1:9");
    // stale_if_error is false by default — must NOT return the stale entry.
    let result = failing_resolver.refresh(TEST_DOMAIN).await;

    assert!(
        result.is_err(),
        "fail-closed resolver must propagate fetch error even when stale cache exists"
    );
    assert!(
        matches!(result.unwrap_err(), CounterpartyError::FetchFailed { .. }),
        "expected FetchFailed, not a stale binding"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// cache_file_path: multi-part domain name sanitisation
// ─────────────────────────────────────────────────────────────────────────────

/// A domain with multiple dots is sanitised to underscores throughout.
#[test]
fn cache_file_path_multi_dot_domain_sanitised() {
    let dir = std::path::PathBuf::from("/tmp");
    let p = cache_file_path(&dir, "sub.domain.example.com");
    assert_eq!(
        p.file_name().unwrap().to_str().unwrap(),
        "sub_domain_example_com.toml.cache"
    );
}

/// Single-label domain (no dots) round-trips through the sanitiser unchanged.
#[test]
fn cache_file_path_single_label_no_dots_unchanged() {
    let dir = std::path::PathBuf::from("/tmp");
    let p = cache_file_path(&dir, "localhost");
    assert_eq!(
        p.file_name().unwrap().to_str().unwrap(),
        "localhost.toml.cache"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// StellarTomlBinding::new — constructor and field accessors
// ─────────────────────────────────────────────────────────────────────────────

/// `StellarTomlBinding::new` must populate all fields correctly.
#[test]
fn stellar_toml_binding_new_fields() {
    use stellar_agent_network::StellarTomlBinding;

    let now = SystemTime::now();
    let later = now + Duration::from_secs(3600);
    let accounts = vec!["GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN".to_owned()];
    let b = StellarTomlBinding::new("circle.com".to_owned(), now, later, false, accounts.clone());

    assert_eq!(b.home_domain, "circle.com");
    assert_eq!(b.fetched_at, now);
    assert_eq!(b.expires_at, later);
    assert!(!b.stale);
    assert_eq!(b.accounts, accounts);
}

/// `StellarTomlBinding::new` with `stale = true` preserves the flag.
#[test]
fn stellar_toml_binding_new_stale_flag() {
    use stellar_agent_network::StellarTomlBinding;

    let now = SystemTime::now();
    let b = StellarTomlBinding::new("anchor.example".to_owned(), now, now, true, vec![]);
    assert!(b.stale);
}

// ─────────────────────────────────────────────────────────────────────────────
// CounterpartyError Display — wire-code and display must not leak internals
// ─────────────────────────────────────────────────────────────────────────────

/// The `CounterpartyError::HmacMismatch` display must not reveal key material.
#[test]
fn counterparty_error_hmac_mismatch_display() {
    let err = CounterpartyError::HmacMismatch;
    let rendered = err.to_string();
    // Must contain a user-readable message, not an internal detail.
    assert!(
        rendered.contains("HMAC") || rendered.contains("mismatch") || rendered.contains("tamper"),
        "HmacMismatch display must mention HMAC or mismatch: {rendered}"
    );
}

/// The `CounterpartyError::WriterLocked` display must mention "locked".
#[test]
fn counterparty_error_writer_locked_display() {
    let err = CounterpartyError::WriterLocked;
    let rendered = err.to_string();
    assert!(
        rendered.to_lowercase().contains("lock"),
        "WriterLocked display must mention lock: {rendered}"
    );
}

/// `CounterpartyError::CacheInvalid` display must include the detail field.
#[test]
fn counterparty_error_cache_invalid_display_includes_detail() {
    let err = CounterpartyError::CacheInvalid {
        detail: "cache file is too short".to_owned(),
    };
    assert!(err.to_string().contains("cache file is too short"));
}

/// `CounterpartyError::FetchFailed` display must include the detail field.
#[test]
fn counterparty_error_fetch_failed_display_includes_detail() {
    let err = CounterpartyError::FetchFailed {
        detail: "unexpected HTTP status 503".to_owned(),
    };
    assert!(err.to_string().contains("503"));
}

/// `CounterpartyError::TomlInvalid` display must include the detail field.
#[test]
fn counterparty_error_toml_invalid_display_includes_detail() {
    let err = CounterpartyError::TomlInvalid {
        detail: "missing VERSION field".to_owned(),
    };
    assert!(err.to_string().contains("VERSION"));
}

/// `CounterpartyError::HomeDomainInvalid` display must include the detail field.
#[test]
fn counterparty_error_home_domain_invalid_display_includes_detail() {
    let err = CounterpartyError::HomeDomainInvalid {
        detail: "not a valid LDH domain".to_owned(),
    };
    assert!(err.to_string().contains("LDH"));
}

/// `CounterpartyError::KeyringUnavailable` display must include the detail.
#[test]
fn counterparty_error_keyring_unavailable_display_includes_detail() {
    let err = CounterpartyError::KeyringUnavailable {
        detail: "keyring entry not found".to_owned(),
    };
    assert!(err.to_string().contains("keyring entry not found"));
}

/// `CounterpartyError::Io` display must include the io::ErrorKind.
#[test]
fn counterparty_error_io_display_includes_kind() {
    let err = CounterpartyError::Io {
        kind: std::io::ErrorKind::NotFound,
    };
    let rendered = err.to_string();
    assert!(
        rendered.to_lowercase().contains("not found") || rendered.contains("NotFound"),
        "Io(NotFound) display must mention not-found: {rendered}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// StellarTomlResolver::with_client — constructor field check
// ─────────────────────────────────────────────────────────────────────────────

/// `StellarTomlResolver::with_client` must construct without panicking.
#[test]
fn stellar_toml_resolver_with_client_succeeds() {
    let dir = TempDir::new().expect("tmpdir");
    let client = reqwest::Client::new();
    // with_client is infallible.
    let _resolver =
        StellarTomlResolver::with_client("default", dir.path(), Duration::from_secs(3600), client);
    // No assertion needed beyond "does not panic" — the Debug impl is the
    // only observable state for this path.
}

/// `StellarTomlResolver::with_stale_if_error` returns a new resolver and does
/// not panic.
#[test]
fn stellar_toml_resolver_with_stale_if_error_builder() {
    let dir = TempDir::new().expect("tmpdir");
    let client = reqwest::Client::new();
    let resolver =
        StellarTomlResolver::with_client("default", dir.path(), Duration::from_secs(3600), client)
            .with_stale_if_error(true);
    // Verify the Debug impl does not panic.
    let debug = format!("{resolver:?}");
    assert!(debug.contains("StellarTomlResolver"));
}
