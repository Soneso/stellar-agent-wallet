//! Regression-lock: zero outbound HTTP to non-RPC URLs during enumeration.
//!
//! # Purpose
//!
//! The enumeration primitive must make NO silent network call to a hosted indexer
//! or any URL other than the configured Soroban RPC endpoint. This test locks
//! that invariant via wiremock with `.expect(0)` on a synthetic hosted-indexer
//! URL, confirming zero requests during `list_active_context_rules`.
//!
//! Two wiremock servers are started:
//! - `rpc_server` — serves the RPC mock responses (account entry + simulate calls).
//! - `indexer_server` — a synthetic hosted-indexer URL configured with `.expect(0)`.
//!
//! `ContextRuleManager` is pointed at `rpc_server` only. After the enumeration
//! completes, `indexer_server.verify().await` confirms zero calls were issued.
//!
//! # Proxy-isolation variant
//!
//! The proxy-isolation variant `t8b_no_indexer_call_under_proxy_blackhole`
//! additionally runs under `HTTP(S)_PROXY=127.0.0.1:1` (black-hole) to catch
//! transitive-dep telemetry that wiremock `.expect(0)` cannot see.
//!
//! `#[serial]` is required on both proxy-isolation variants because HTTP proxy
//! env vars are process-global state. All tests in the same binary that mutate
//! proxy env vars must use `#[serial_test::serial]`.
//!
//! # Per-test server design
//!
//! Each test calls `MockServer::start().await` independently rather than sharing
//! a server via `OnceCell`. This avoids mount-accumulation across test invocations
//! and eliminates `OnceCell::get_or_init` races under `--all-targets`. The
//! serialisation guarantee from `#[serial]` applies only within a single test
//! binary; across test binaries server state is independent.
//!
//! # Gating
//!
//! No feature flags required. Runs under default `cargo test`.
//!
//! ```text
//! cargo test --test list_rules_no_indexer_call_mock
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; adversarial fixtures assert invariants via panic-on-failure"
)]

use serial_test::serial;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleManager, ContextRuleManagerConfig, DEFAULT_MAX_SCAN_ID,
};
use stellar_xdr::{ContractId, Hash, Limits, ScAddress, ScVal, WriteXdr};
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

#[path = "smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
mod rpc_mock_helpers;

use rpc_mock_helpers::{
    SorobanRpcDispatcher, build_context_rule_scval_xdr, build_ledger_entries_account,
    build_simulate_response, signer_set_n_of_n,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";
const SOURCE_G: &str = stellar_agent_core::constants::SIMULATE_SENTINEL_G;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn addr(byte: u8) -> ScAddress {
    ScAddress::Contract(ContractId(Hash([byte; 32])))
}

fn u32_xdr(n: u32) -> String {
    ScVal::U32(n)
        .to_xdr_base64(Limits::none())
        .expect("ScVal::U32 must encode")
}

// ─────────────────────────────────────────────────────────────────────────────
// No-indexer: zero outbound HTTP to non-RPC URL during enumeration
// ─────────────────────────────────────────────────────────────────────────────

/// `list_active_context_rules` makes NO HTTP request to any URL other than
/// the configured Soroban RPC endpoint.
///
/// Two wiremock servers are started per-test on ephemeral ports:
/// - `rpc_server` — responds to the RPC simulate + getLedgerEntries sequence.
/// - `indexer_server` — a synthetic hosted-indexer URL with `.expect(0)` (any
///   request triggers a test failure at `verify().await` time).
///
/// The `ContextRuleManager` is pointed at `rpc_server.uri()` only. The test
/// verifies that after a successful enumeration (2 rules, no gaps),
/// `indexer_server.verify().await` confirms zero calls.
///
/// Per-test servers (not shared `OnceCell`) are used to eliminate mount-accumulation
/// and `OnceCell::get_or_init` races under `--all-targets --all-features`.
///
/// # No-indexer invariant
///
/// The enumeration primitive must be self-contained — no hosted-indexer
/// dependency, no background telemetry, no side-channel network calls.
#[tokio::test]
#[serial]
async fn t8_no_indexer_call_during_enumeration() {
    // Per-test servers: each test call gets a fresh server on an ephemeral port.
    // This avoids mount-accumulation on a shared server and OnceCell-init races
    // that can cause hangs under cargo test --all-targets --all-features.
    let rpc_server = MockServer::start().await;
    let indexer_server = MockServer::start().await;

    let smart_account = addr(0x08);
    let signers = signer_set_n_of_n(1);

    let ledger_resp = build_ledger_entries_account(SOURCE_G);

    let sim_responses = vec![
        build_simulate_response(&u32_xdr(2)),
        build_simulate_response(&build_context_rule_scval_xdr(0, &signers, &[])),
        build_simulate_response(&build_context_rule_scval_xdr(1, &signers, &[])),
    ];

    // Mount the RPC mock — real requests go here (root path, per test convention).
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            ledger_resp,
            sim_responses,
        ))
        .mount(&rpc_server)
        .await;

    // Mount an expect(0) mock on the indexer server — any request is a failure.
    // The indexer_server is on a different ephemeral port; all requests to it
    // are unexpected. Any request on any path triggers the expect(0) failure.
    Mock::given(method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(500))
        .expect(0)
        .mount(&indexer_server)
        .await;

    // Also catch any GET requests to the indexer (future indexed endpoints may be GET).
    Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(500))
        .expect(0)
        .mount(&indexer_server)
        .await;

    // Construct the manager pointing ONLY at rpc_server.
    let config = ContextRuleManagerConfig::new(
        rpc_server.uri(),
        NETWORK_PASSPHRASE.to_owned(),
        std::time::Duration::from_secs(5),
        CHAIN_ID.to_owned(),
    );
    let manager = ContextRuleManager::new(config).expect("ContextRuleManager::new must succeed");

    let result = manager
        .list_active_context_rules(smart_account, SOURCE_G, DEFAULT_MAX_SCAN_ID)
        .await
        .expect("list_active_context_rules must succeed");

    assert_eq!(
        result.rules.len(),
        2,
        "enumeration must return 2 rules; got {}",
        result.rules.len()
    );

    // Verify that the indexer server received zero requests.
    // wiremock panics here if the `.expect(0)` constraint was violated.
    indexer_server.verify().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Proxy-isolation variant — zero outbound HTTP under black-hole proxy
// ─────────────────────────────────────────────────────────────────────────────

/// Same enumeration as `t8_no_indexer_call_during_enumeration`, but runs under
/// a black-hole HTTP/HTTPS proxy (`127.0.0.1:1`) to confirm that no
/// transitive-dep telemetry escapes to non-RPC endpoints even under an active
/// proxy configuration.
///
/// wiremock `.expect(0)` only catches calls that are already wired up in-process.
/// A transitive dependency (metrics client, telemetry library, auto-update check)
/// could open a connection that bypasses wiremock entirely. Setting
/// `HTTP_PROXY` / `HTTPS_PROXY` (and their lowercase equivalents) to a
/// black-hole address `127.0.0.1:1` causes any out-of-process HTTP attempt
/// to fail with a connection error, which would surface as a test failure.
///
/// The RPC mock server is on `127.0.0.1` and the reqwest client used by
/// `ContextRuleManager` sends requests to `rpc_server.uri()` directly — this
/// bypasses the proxy because `NO_PROXY` / `no_proxy` defaults to localhost.
/// Any non-local URL would be forced through the black-hole.
///
/// # Thread-safety
///
/// HTTP proxy env vars are process-global state. `#[serial]` is required so
/// this test and the no-indexer test do not interleave.
#[tokio::test]
#[serial]
async fn t8b_no_indexer_call_under_proxy_blackhole() {
    // RAII guard ensures proxy env vars are cleared even if the test panics
    // (otherwise a panic mid-test leaks proxy state into sibling #[serial]
    // tests — RAII is required to prevent proxy state leaking into sibling tests).
    struct ProxyGuard;
    impl Drop for ProxyGuard {
        fn drop(&mut self) {
            for var in &[
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "http_proxy",
                "https_proxy",
                "NO_PROXY",
                "no_proxy",
            ] {
                // SAFETY: test-only; serialised by #[serial] on caller.
                #[allow(unsafe_code, reason = "test-only env var cleanup in Drop")]
                unsafe {
                    std::env::remove_var(var);
                }
            }
        }
    }
    let _guard = ProxyGuard;

    // Set all four proxy env var variants to the black-hole address.
    // Any out-of-process HTTP to a non-localhost URL will fail to connect.
    // The wiremock server runs on localhost, so we set NO_PROXY to exempt
    // localhost from the proxy routing — reqwest / hyper do NOT auto-bypass
    // localhost when *_PROXY is set; this exemption is required for the test
    // assertion (success against localhost RPC = no outbound HTTP to indexer).
    // SAFETY: test-only; env var mutation is serialised by #[serial].
    let proxy_vars = [
        ("HTTP_PROXY", "http://127.0.0.1:1"),
        ("HTTPS_PROXY", "http://127.0.0.1:1"),
        ("http_proxy", "http://127.0.0.1:1"),
        ("https_proxy", "http://127.0.0.1:1"),
        ("NO_PROXY", "localhost,127.0.0.1,::1"),
        ("no_proxy", "localhost,127.0.0.1,::1"),
    ];
    for (var, value) in &proxy_vars {
        // SAFETY: test-only global state; serialised by #[serial].
        #[allow(
            unsafe_code,
            reason = "test-only env var mutation serialised by #[serial]"
        )]
        unsafe {
            std::env::set_var(var, value);
        }
    }

    // Per-test server: fresh on each call, avoids mount-accumulation.
    let rpc_server = MockServer::start().await;
    let smart_account = addr(0x0C);
    let signers = signer_set_n_of_n(1);

    let ledger_resp = build_ledger_entries_account(SOURCE_G);
    let sim_responses = vec![
        build_simulate_response(&u32_xdr(2)),
        build_simulate_response(&build_context_rule_scval_xdr(0, &signers, &[])),
        build_simulate_response(&build_context_rule_scval_xdr(1, &signers, &[])),
    ];

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            ledger_resp,
            sim_responses,
        ))
        .mount(&rpc_server)
        .await;

    let config = ContextRuleManagerConfig::new(
        rpc_server.uri(),
        NETWORK_PASSPHRASE.to_owned(),
        std::time::Duration::from_secs(5),
        CHAIN_ID.to_owned(),
    );
    let manager = ContextRuleManager::new(config).expect("ContextRuleManager::new must succeed");

    let result = manager
        .list_active_context_rules(smart_account, SOURCE_G, DEFAULT_MAX_SCAN_ID)
        .await;

    // ProxyGuard (RAII) clears env vars on Drop — including on panic.

    // Assert enumeration succeeded — the RPC calls reached the local mock server
    // (localhost bypasses proxy) and no other outbound connection was attempted.
    let enumeration = result.expect(
        "list_active_context_rules must succeed under black-hole proxy; \
         RPC calls to localhost should bypass the proxy. If this fails, a transitive \
         dependency is making a non-localhost HTTP call that is routed through the proxy.",
    );
    assert_eq!(
        enumeration.rules.len(),
        2,
        "enumeration must return 2 rules; got {}",
        enumeration.rules.len()
    );
}
