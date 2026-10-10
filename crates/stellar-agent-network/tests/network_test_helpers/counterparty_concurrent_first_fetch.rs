//! Concurrent first-fetch race tests for the counterparty cache substrate.
//!
//! # Scenarios covered
//!
//! 1. **Two tasks race first-fetch** — one wins; the other gets
//!    [`CounterpartyError::WriterLocked`]; the cache file is structurally
//!    coherent after both complete (HMAC verifies on a third read).
//! 2. **Sequential writes maintain HMAC coherence** — two sequential `refresh`
//!    calls both write a coherent cache file.
//!
//! # Test isolation and serialisation
//!
//! All tests are annotated `#[serial]` to prevent concurrent mutation of the
//! process-global `keyring_core::DEFAULT_STORE`.  Each test installs a fresh
//! in-memory mock store via `keyring_mock::install()` and uses a unique
//! `TempDir` for cache isolation.
//!
//! # Test base-URL override
//!
//! `StellarTomlResolver::with_test_base_url` bypasses the `https://`
//! enforcement in `fetch_stellar_toml` so the test can route requests to the
//! wiremock HTTP server without a real TLS endpoint.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use std::time::Duration;

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

const VALID_STELLAR_TOML: &str = r#"
VERSION = "2.0.0"
FEDERATION_SERVER = "https://fed.example.com/federation"
WEB_AUTH_ENDPOINT = "https://auth.example.com"
ACCOUNTS = ["GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"]
"#;

const TEST_DOMAIN: &str = "concurrent.example";

fn unique_profile(tag: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("test-concurrent-{tag}-{ts}")
}

/// Creates a resolver that routes fetch requests to the mock server's HTTP URL.
///
/// The client mirrors production no-decompression settings: test clients apply
/// `.no_gzip().no_brotli().no_deflate()` to exercise the same invariant as
/// `build_fetch_client`.
fn build_resolver(
    profile: &str,
    cache_dir: &std::path::Path,
    mock_server_uri: &str,
) -> StellarTomlResolver {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .expect("test client build");

    StellarTomlResolver::with_test_base_url(
        profile,
        cache_dir,
        Duration::from_secs(3600),
        client,
        mock_server_uri,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Two tasks race first-fetch
// ─────────────────────────────────────────────────────────────────────────────

/// Spawns two `tokio::task`s that both call `refresh` on the same domain /
/// same cache directory at the same time.  The single-writer flock ensures
/// that:
///
/// - At least one task writes the cache file successfully.
/// - If a lock collision occurs, the loser receives [`CounterpartyError::WriterLocked`].
/// - After both tasks complete, a third read of the cache file verifies that
///   the HMAC is coherent (the winner's write was atomic and complete).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn two_tasks_race_first_fetch_one_wins_one_locked() {
    keyring_mock::install().expect("mock keyring init");

    let dir = TempDir::new().expect("tmpdir");
    let dir_path = dir.path().to_path_buf();
    let profile = unique_profile("race");

    let mock_server = MockServer::start().await;
    // The mock server may be called once or twice — both outcomes are valid.
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(VALID_STELLAR_TOML)
                .insert_header("content-type", "text/toml"),
        )
        .mount(&mock_server)
        .await;

    let mock_uri = mock_server.uri();

    // Build two independent resolvers sharing the same cache directory.
    let resolver_a = build_resolver(&profile, &dir_path, &mock_uri);
    let resolver_b = build_resolver(&profile, &dir_path, &mock_uri);

    // Synchronise tasks at the lock-acquisition point.
    use std::sync::Arc;
    use tokio::sync::Barrier;
    let barrier = Arc::new(Barrier::new(2));
    let barrier_a = Arc::clone(&barrier);
    let barrier_b = Arc::clone(&barrier);

    let handle_a = tokio::task::spawn(async move {
        barrier_a.wait().await;
        resolver_a.refresh(TEST_DOMAIN).await
    });

    let handle_b = tokio::task::spawn(async move {
        barrier_b.wait().await;
        resolver_b.refresh(TEST_DOMAIN).await
    });

    let result_a = handle_a.await.expect("task A must not panic");
    let result_b = handle_b.await.expect("task B must not panic");

    let a_ok = result_a.is_ok();
    let b_ok = result_b.is_ok();
    let a_locked = matches!(result_a, Err(CounterpartyError::WriterLocked));
    let b_locked = matches!(result_b, Err(CounterpartyError::WriterLocked));

    // At least one must have succeeded.
    assert!(a_ok || b_ok, "at least one task must succeed");

    // Log the outcome for diagnostics.
    if a_ok && b_ok {
        // Both succeeded — no lock collision on this run.
    } else {
        assert!(
            (a_ok && b_locked) || (b_ok && a_locked),
            "exactly one must win and one must be WriterLocked; A ok={a_ok} locked={a_locked}, B ok={b_ok} locked={b_locked}"
        );
    }

    // Third read: the cache file must exist and have a valid HMAC.
    let cache_path = cache_file_path(&dir_path, TEST_DOMAIN);
    assert!(
        cache_path.exists(),
        "cache file must exist after the winning task completes"
    );

    let file_bytes = std::fs::read(&cache_path).expect("cache file read");
    // v1 format: tag(32) + u16_hd_len(2) + hd_bytes + body_bytes.
    assert!(
        file_bytes.len() > 32 + 2 + 1,
        "cache file must be longer than the v1 header ({} bytes)",
        file_bytes.len()
    );

    // Verify HMAC coherence using read_cache_entry (which calls verify_hmac_v1
    // with the v1 context-labelled HMAC input — avoids duplicating that logic here).
    // The keyring account is always "default", not the profile name.
    let service = format!("stellar-agent-counterparty-{profile}");
    let entry = keyring_core::Entry::new(&service, "default").expect("entry open");
    let raw_key = entry.get_password().expect("keyring entry must exist");

    use base64::Engine as _;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&raw_key)
        .expect("key must decode from base64");

    // read_cache_entry verifies the v1 HMAC internally (context label + home_domain + body).
    use stellar_agent_network::counterparty::cache::read_cache_entry;
    let cache_result = read_cache_entry(
        &cache_path,
        &key_bytes,
        std::time::Duration::from_secs(3600),
    );
    assert!(
        cache_result.is_ok(),
        "read_cache_entry must succeed (v1 HMAC coherent) after concurrent first-fetch race; got: {cache_result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Sequential writes maintain HMAC coherence
// ─────────────────────────────────────────────────────────────────────────────

/// Two sequential `refresh` calls must both write a coherent cache file.
/// The second write atomically replaces the first.  After both, the HMAC
/// must still verify.
#[tokio::test]
#[serial]
async fn sequential_refreshes_maintain_hmac_coherence() {
    keyring_mock::install().expect("mock keyring init");

    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("sequential");

    let mock_server = MockServer::start().await;
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

    let resolver = build_resolver(&profile, dir.path(), &mock_server.uri());

    resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect("first refresh must succeed");

    resolver
        .refresh(TEST_DOMAIN)
        .await
        .expect("second refresh must succeed");

    // Verify HMAC coherence after both writes.
    let cache_path = cache_file_path(dir.path(), TEST_DOMAIN);

    // The keyring account is always "default", not the profile name.
    let service = format!("stellar-agent-counterparty-{profile}");
    let entry = keyring_core::Entry::new(&service, "default").expect("entry open");
    let raw_key = entry.get_password().expect("keyring entry must exist");

    use base64::Engine as _;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&raw_key)
        .expect("key decode");

    // read_cache_entry verifies the v1 HMAC internally:
    // context label + u16 hd_len + hd_bytes + u32 body_len + body.
    use stellar_agent_network::counterparty::cache::read_cache_entry;
    let cache_result = read_cache_entry(
        &cache_path,
        &key_bytes,
        std::time::Duration::from_secs(3600),
    );
    assert!(
        cache_result.is_ok(),
        "read_cache_entry must succeed (v1 HMAC coherent) after sequential refreshes; got: {cache_result:?}"
    );

    mock_server.verify().await;
}
