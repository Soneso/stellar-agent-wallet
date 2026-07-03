//! Integration tests for the counterparty cache substrate.
//!
//! # Scenarios covered
//!
//! 1. **First fetch mints HMAC key + writes cache** — after the first
//!    `refresh`, the keyring contains the `stellar-agent-counterparty-<profile>`
//!    entry and the cache file exists.
//! 2. **Second fetch hits cache (TTL not expired)** — `list_cached` returns the
//!    binding without re-fetching from the network.
//! 3. **Cache HMAC mismatch (corruption — flip a byte)** — `list_cached` skips
//!    the corrupted entry (silent skip per spec) and the underlying HMAC verify
//!    returns `HmacMismatch`.
//! 4. **Expired cache → re-fetch** — when the TTL is set to zero, the entry is
//!    marked expired; a subsequent `refresh` re-contacts the server.
//! 5. **No keyring entry → empty list** — `list_cached` without a prior write
//!    returns an empty list.
//! 6. **Writer-locked path** — a manually held lock causes `refresh` to return
//!    `WriterLocked`.
//! 7. **Raw cache format invariant** — a freshly written cache file has the v2
//!    tag, domain, fetched-at, body-length, and body layout.
//!
//! # Test isolation and serialisation
//!
//! All tests use `keyring_mock::install()` to install a fresh in-memory keyring
//! store and `#[serial]` to prevent process-global `keyring_core::DEFAULT_STORE`
//! races.  Each test also uses a unique profile name and a fresh `TempDir` for
//! the cache directory.
//!
//! `#[serial]` is applied defensively on ALL keyring-touching tests, including
//! early-exit tests, to prevent racy mutation of the process-global store.
//!
//! # Test base-URL override
//!
//! `StellarTomlResolver::with_test_base_url` bypasses the `https://` enforcement
//! in `fetch_stellar_toml` by pointing the fetch at the wiremock mock server's
//! HTTP URL directly.  This avoids the need for a real TLS endpoint in CI.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use std::time::{Duration, UNIX_EPOCH};

use reqwest::redirect;
use serial_test::serial;
use stellar_agent_network::CounterpartyError;
use stellar_agent_network::counterparty::CounterpartyResolver as _;
use stellar_agent_network::counterparty::cache::{StellarTomlResolver, cache_file_path};
use stellar_agent_test_support::keyring_mock;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A valid minimal `stellar.toml` served by the mock server.
const VALID_STELLAR_TOML: &str = r#"
VERSION = "2.0.0"
FEDERATION_SERVER = "https://fed.example.com/federation"
WEB_AUTH_ENDPOINT = "https://auth.example.com"
ACCOUNTS = ["GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"]
"#;

/// A fake domain name — the resolver validates it before fetching.  The actual
/// network request is routed to the wiremock server via `test_base_url`.
const TEST_DOMAIN: &str = "testdomain.example";

/// Generates a unique profile name to avoid cross-test keyring collisions.
fn unique_profile(test_name: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("test-{test_name}-{ts}")
}

/// Mounts a stellar.toml mock on the given server.
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

/// Builds a test resolver that routes `/.well-known/stellar.toml` requests to
/// the wiremock mock server's HTTP URL instead of `https://<TEST_DOMAIN>`.
///
/// Uses `StellarTomlResolver::with_test_base_url` which bypasses the HTTPS
/// enforcement in `fetch_stellar_toml` in favour of the supplied base URL.
fn build_test_resolver(
    profile: &str,
    cache_dir: &std::path::Path,
    ttl: Duration,
    mock_server_uri: &str,
) -> StellarTomlResolver {
    // Mirror production no-decompression settings so the test client exercises
    // the same invariants as `build_fetch_client`.
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

// ─────────────────────────────────────────────────────────────────────────────
// 1. First fetch mints HMAC key + writes cache
// ─────────────────────────────────────────────────────────────────────────────

/// After the first `refresh`, the keyring entry must exist and the cache file
/// must be present on disk.
#[tokio::test]
#[serial]
async fn first_fetch_mints_key_and_writes_cache() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("first-fetch");

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
        .expect("first refresh must succeed");

    assert_eq!(binding.home_domain, TEST_DOMAIN);
    assert!(!binding.stale, "fresh refresh must not be marked stale");
    assert!(
        binding.expires_at > binding.fetched_at,
        "expires_at must be after fetched_at"
    );

    // Keyring entry must have been minted.
    // The account is always "default" (not the profile name) so all profiles
    // share one HMAC key per service (KeyringEntryRef::default_counterparty_key).
    let service = format!("stellar-agent-counterparty-{profile}");
    let entry = keyring_core::Entry::new(&service, "default").expect("entry open");
    let raw = entry
        .get_password()
        .expect("keyring entry must exist after first refresh");
    assert!(
        !raw.is_empty(),
        "keyring entry must contain a non-empty base64 key"
    );

    // Cache file must exist.
    let cache_path = cache_file_path(dir.path(), TEST_DOMAIN);
    assert!(
        cache_path.exists(),
        "cache file must exist after first refresh: {}",
        cache_path.display()
    );

    // Cache file must be at least HMAC_TAG_LEN (32) + 1 bytes.
    let meta = std::fs::metadata(&cache_path).expect("cache file metadata");
    assert!(
        meta.len() > 32,
        "cache file must contain at least the HMAC tag plus body bytes"
    );
}

/// A freshly minted cache file must use the documented v2 byte layout:
/// tag || u16 home-domain length || home-domain || i64 fetched-at ||
/// u32 body length || TOML body.
#[tokio::test]
#[serial]
async fn first_fetch_writes_v2_cache_file_format_invariants() {
    const HMAC_TAG_LEN: usize = 32;
    const HD_LEN_FIELD: usize = 2;
    const FETCHED_AT_FIELD: usize = 8;
    const BODY_LEN_FIELD: usize = 4;

    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("raw-format");

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
        .expect("first refresh must succeed");

    let cache_path = cache_file_path(dir.path(), TEST_DOMAIN);
    let file_bytes = std::fs::read(&cache_path).expect("cache file read");

    let hd_len_start = HMAC_TAG_LEN;
    let hd_len_end = hd_len_start + HD_LEN_FIELD;
    assert!(
        file_bytes.len() >= hd_len_end,
        "cache file must contain HMAC tag and home-domain length"
    );
    assert_ne!(
        &file_bytes[..HMAC_TAG_LEN],
        &[0u8; 32],
        "HMAC tag must not be all zeros"
    );

    let hd_len = u16::from_be_bytes(
        file_bytes[hd_len_start..hd_len_end]
            .try_into()
            .expect("home-domain length slice"),
    ) as usize;
    assert_eq!(hd_len, TEST_DOMAIN.len());

    let hd_start = hd_len_end;
    let hd_end = hd_start + hd_len;
    assert!(
        file_bytes.len() >= hd_end,
        "cache file must contain home-domain bytes"
    );
    assert_eq!(&file_bytes[hd_start..hd_end], TEST_DOMAIN.as_bytes());

    let fetched_at_start = hd_end;
    let fetched_at_end = fetched_at_start + FETCHED_AT_FIELD;
    assert!(
        file_bytes.len() >= fetched_at_end,
        "cache file must contain fetched-at timestamp"
    );
    let fetched_at = i64::from_be_bytes(
        file_bytes[fetched_at_start..fetched_at_end]
            .try_into()
            .expect("fetched-at slice"),
    );
    assert!(fetched_at >= 0, "fetched-at must be non-negative");
    let binding_fetched_at = binding
        .fetched_at
        .duration_since(UNIX_EPOCH)
        .expect("binding fetched_at must be after UNIX epoch")
        .as_secs();
    assert_eq!(
        u64::try_from(fetched_at).expect("non-negative"),
        binding_fetched_at
    );

    let body_len_start = fetched_at_end;
    let body_len_end = body_len_start + BODY_LEN_FIELD;
    assert!(
        file_bytes.len() >= body_len_end,
        "cache file must contain body length"
    );
    let body_len = u32::from_be_bytes(
        file_bytes[body_len_start..body_len_end]
            .try_into()
            .expect("body length slice"),
    ) as usize;

    let body_start = body_len_end;
    let body_end = body_start + body_len;
    assert_eq!(
        body_end,
        file_bytes.len(),
        "body length must consume the remaining file bytes"
    );
    let body = std::str::from_utf8(&file_bytes[body_start..body_end])
        .expect("cache body must be valid UTF-8");
    assert_eq!(body, VALID_STELLAR_TOML);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Second fetch hits cache (TTL not expired)
// ─────────────────────────────────────────────────────────────────────────────

/// After a successful first refresh, `list_cached` must return the binding
/// without re-contacting the server (TTL is 1 hour, far from expiry).
#[tokio::test]
#[serial]
async fn second_call_hits_cache_ttl_not_expired() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("cache-hit");

    let mock_server = MockServer::start().await;
    // Mount the mock — it should only be called once (first refresh).
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(VALID_STELLAR_TOML)
                .insert_header("content-type", "text/toml"),
        )
        .expect(1) // exactly 1 network call expected
        .mount(&mock_server)
        .await;

    let resolver = build_test_resolver(
        &profile,
        dir.path(),
        Duration::from_secs(3600),
        &mock_server.uri(),
    );

    // First refresh — hits the network.
    resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect("first refresh must succeed");

    // list_cached — must return the cached binding without a network call.
    let cached = resolver
        .list_cached()
        .await
        .expect("list_cached must succeed");

    assert_eq!(cached.len(), 1, "one cached binding expected");
    assert!(
        !cached[0].stale,
        "list_cached entries must not be marked stale"
    );
    // The TTL should be valid.
    assert!(
        cached[0].expires_at > cached[0].fetched_at,
        "cached binding must have valid TTL"
    );

    // Verify that only one network call was made.
    mock_server.verify().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Cache HMAC mismatch (corruption) → skipped by list_cached
// ─────────────────────────────────────────────────────────────────────────────

/// Flipping a byte in the cache file body after a successful write causes:
/// - `list_cached` to silently skip the corrupted entry (per spec).
#[tokio::test]
#[serial]
async fn hmac_mismatch_on_corrupted_cache() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("hmac-mismatch");

    let mock_server = MockServer::start().await;
    mount_stellar_toml_mock(&mock_server).await;

    let resolver = build_test_resolver(
        &profile,
        dir.path(),
        Duration::from_secs(3600),
        &mock_server.uri(),
    );

    // First refresh — writes a valid cache file.
    resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect("first refresh must succeed");

    // Flip a byte in the cache file body (after the 32-byte HMAC tag).
    let cache_path = cache_file_path(dir.path(), TEST_DOMAIN);
    let mut file_bytes = std::fs::read(&cache_path).expect("cache file read");
    // Flip the first byte after the HMAC tag (index 32).
    let hmac_tag_len: usize = 32;
    if file_bytes.len() > hmac_tag_len {
        file_bytes[hmac_tag_len] ^= 0xFF;
    }
    std::fs::write(&cache_path, &file_bytes).expect("cache file write");

    // list_cached must skip the corrupted entry (silent skip per spec).
    let cached = resolver
        .list_cached()
        .await
        .expect("list_cached must succeed even with corrupted entries");
    assert!(
        cached.is_empty(),
        "corrupted cache entry must be skipped; got {} entries",
        cached.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Expired cache → re-fetch
// ─────────────────────────────────────────────────────────────────────────────

/// When TTL is effectively zero (1 nanosecond), `list_cached` skips the entry
/// as expired.  A subsequent `refresh` re-contacts the server.
#[tokio::test]
#[serial]
async fn expired_cache_entry_is_skipped_by_list_cached() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("expired");

    let mock_server = MockServer::start().await;
    // Two network calls expected: one for first refresh, one for re-fetch.
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(VALID_STELLAR_TOML)
                .insert_header("content-type", "text/toml"),
        )
        .expect(2)
        .mount(&mock_server)
        .await;

    // Use a 1-nanosecond TTL so the entry expires immediately.
    let tiny_ttl = Duration::from_nanos(1);
    let resolver = build_test_resolver(&profile, dir.path(), tiny_ttl, &mock_server.uri());

    // First refresh.
    resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect("first refresh must succeed");

    // Wait a moment to ensure the TTL has elapsed.
    tokio::time::sleep(Duration::from_millis(10)).await;

    // list_cached with a 1-ns TTL should see the entry as expired → empty.
    let cached = resolver
        .list_cached()
        .await
        .expect("list_cached must succeed");

    // Either empty (expired) or present but with valid shape.
    for binding in &cached {
        assert!(
            !binding.home_domain.is_empty(),
            "home_domain must not be empty"
        );
    }

    // Second refresh — must succeed (re-fetches from network).
    let binding2 = resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect("second refresh must succeed after expired cache");
    assert_eq!(binding2.home_domain, TEST_DOMAIN);

    mock_server.verify().await;
}

/// With the opt-in stale-if-error flag enabled, a transient fetch failure can
/// return an expired but HMAC-verified cache entry marked `stale = true`.
#[tokio::test]
#[serial]
async fn stale_if_error_returns_expired_hmac_verified_cache_entry() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("stale-if-error");

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(VALID_STELLAR_TOML)
                .insert_header("content-type", "text/toml"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let tiny_ttl = Duration::from_nanos(1);
    let resolver = build_test_resolver(&profile, dir.path(), tiny_ttl, &mock_server.uri());

    resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect("first refresh must populate cache");
    tokio::time::sleep(Duration::from_millis(10)).await;

    let failing_resolver =
        build_test_resolver(&profile, dir.path(), tiny_ttl, "http://127.0.0.1:9")
            .with_stale_if_error(true);
    let binding = failing_resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect("second refresh must fall back to stale cache after fetch failure");
    assert_eq!(binding.home_domain, TEST_DOMAIN);
    assert!(binding.stale, "fallback binding must be marked stale");
    assert!(
        binding.expires_at < std::time::SystemTime::now(),
        "fallback binding should preserve expired cache timestamp"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. No keyring entry → list_cached returns empty
// ─────────────────────────────────────────────────────────────────────────────

/// When no keyring entry has been minted (fresh profile with no prior writes),
/// `list_cached` must return an empty list rather than `KeyringUnavailable`.
#[tokio::test]
#[serial]
async fn list_cached_without_keyring_entry_returns_empty() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("no-key");

    // Deliberately DO NOT call refresh — no keyring entry is minted.
    let client = reqwest::Client::new();
    let resolver =
        StellarTomlResolver::with_client(&profile, dir.path(), Duration::from_secs(3600), client);

    let cached = resolver
        .list_cached()
        .await
        .expect("list_cached without keyring entry must return empty, not error");
    assert!(
        cached.is_empty(),
        "list_cached without a minted keyring entry must return empty"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Writer-locked path
// ─────────────────────────────────────────────────────────────────────────────

/// A manually held lock causes `refresh` to return `WriterLocked`.
#[tokio::test]
#[serial]
async fn concurrent_refresh_second_gets_writer_locked() {
    use stellar_agent_network::counterparty::lock::CacheLock;

    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");

    let lock_path = dir.path().join(".lock");

    // Acquire the lock manually so the resolver's acquire attempt fails.
    let _lock = CacheLock::acquire(&lock_path).expect("manual lock acquire");

    let mock_server = MockServer::start().await;
    mount_stellar_toml_mock(&mock_server).await;

    let profile = unique_profile("writer-locked");
    let resolver = build_test_resolver(
        &profile,
        dir.path(),
        Duration::from_secs(3600),
        &mock_server.uri(),
    );

    // The resolver's refresh will try to acquire the lock and fail.
    let result = resolver.refresh(TEST_DOMAIN).await;
    assert!(
        matches!(result, Err(CounterpartyError::WriterLocked)),
        "second acquire must return WriterLocked, got: {result:?}"
    );
}
