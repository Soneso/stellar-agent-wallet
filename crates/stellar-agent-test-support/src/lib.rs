//! Test harness for log-capture, secret-leakage assertions, and Stellar test
//! fixtures.
//!
//! ## What this crate provides
//!
//! - [`log_capture`] + [`secret_patterns`] — capture the bytes a `tracing`
//!   fmt layer writes during a test and assert that no secret material
//!   (Stellar S-strkeys, BIP-39 mnemonic words, sensitive field values) appears
//!   in them.
//! - [`WarningCapture`] records the fields of each warning a test emits.
//! - [`keyring_mock`] — redirect `keyring_core` calls to an in-memory store
//!   during unit tests, so no OS keychain dialog appears in `cargo test`.
//! - [`xdr_fixtures`], [`testnet_strkeys`], `verifier_registry`,
//!   [`echo_id_responder`] — Stellar XDR / strkey fixtures and HTTP/contract
//!   test doubles for consumer crates' tests.
//! - [`rpc_request_count`] counts a mock server's requests for one RPC method.
//! - [`second_loopback_host`] names a loopback mock server under a second
//!   host, reached through a forwarder on both loopback families, for the
//!   secondary endpoint of a smart-account signing path.
//! - [`signed_envelope`] — envelopes whose signatures are real and whose
//!   source accounts are answerable by a mocked `getLedgerEntries`, for tests
//!   that exercise a submit path.
//! - [`auth_tree_rpc`]: a mocked RPC endpoint whose simulation hands an
//!   authorizing address an invocation tree the test chooses, for tests that
//!   drive a whole adapter submit flow.
//! - `testnet_helpers`: live-network helpers (Friendbot funding, RPC) for
//!   consumer crates' testnet-acceptance tests; behind the `testnet-helpers`
//!   feature and exercised only by those live tests.
//! - [`env_guard::StellarAgentHomeGuard`] — RAII guard overriding
//!   `STELLAR_AGENT_HOME` for tests that exercise the wallet's
//!   home-directory resolution; callers serialise with `#[serial]`.
//! - [`profile_fixtures`] — profile-TOML bytes shared by both binaries'
//!   process-level tests, so a parity assertion compares one file rather than
//!   two hand-copied literals. Its
//!   [`unique_profile_name`](profile_fixtures::unique_profile_name) gives each
//!   test a profile name no other test shares.
//! - [`env_guard::ProfileEnvVarGuard`] — RAII guard clearing
//!   `STELLAR_AGENT_PROFILE` for in-process tests that exercise the
//!   "no profile was named" branch; callers serialise with `#[serial]`.
//! - [`connection_counter::ConnectionCounter`] counts the connections a
//!   loopback TCP listener accepts, for tests that assert no contact with an
//!   `https://` endpoint.
//! - [`webauthn::TestAuthenticator`] signs real ES256 WebAuthn assertions
//!   with a fixed P-256 key, for tests of the assertion verifiers.
//! - [`source_order`] asserts that one call sits between two others inside a
//!   production function, for tests that pin the order of a read, an
//!   acquisition, and a signer load.
//! - [`rejected_value`] asserts that an error and its source chain never
//!   repeat a value the wallet rejected.
//!
//! This crate is consumed only as a `[dev-dependencies]` entry
//! (`publish = false`); it is never a runtime dependency, so its `pub` helpers
//! carry no production reachability.
//!
//! ## Cargo features
//!
//! - `test-helpers` — XDR fixtures + wiremock doubles (heavier deps).
//! - `testnet-helpers` — live-network helpers (network-only).
//! - `verifier-registry` — WebAuthn-verifier WASM registry.
//! - `wiremock-helpers` — HTTP test doubles.

#[cfg(feature = "test-helpers")]
pub mod auth_tree_rpc;
pub mod connection_counter;
#[cfg(feature = "wiremock-helpers")]
pub mod echo_id_responder;
pub mod env_guard;
pub mod keyring_mock;
pub mod log_capture;
#[cfg(feature = "test-helpers")]
mod loopback_forwarder;
pub mod profile_fixtures;
pub mod rejected_value;
pub mod sandbox;
pub mod secret_patterns;
#[cfg(feature = "test-helpers")]
pub mod signed_envelope;
pub mod source_order;
#[cfg(feature = "testnet-helpers")]
pub mod testnet_helpers;
pub mod testnet_strkeys;
#[cfg(any(feature = "test-helpers", feature = "testnet-helpers"))]
pub mod timing;
#[cfg(feature = "verifier-registry")]
pub mod verifier_registry;
#[cfg(feature = "test-helpers")]
pub mod webauthn;
#[cfg(feature = "test-helpers")]
pub mod xdr_fixtures;

mod bip39_english;

pub use connection_counter::ConnectionCounter;
#[cfg(feature = "test-helpers")]
pub use echo_id_responder::SubmissionEchoResponder;
#[cfg(feature = "wiremock-helpers")]
pub use echo_id_responder::{EchoIdResponder, KeyedLedgerEntriesResponder, rpc_request_count};
pub use env_guard::{ProfileEnvVarGuard, StellarAgentHomeGuard};
pub use log_capture::{
    CaptureWriter, RAW_TRANSPORT_LOG_TARGET, RedactionStrictSubscriber, WarningCapture,
    inert_dispatcher, with_captured_logs,
};
pub use secret_patterns::assert_no_secret_bytes;
#[cfg(feature = "test-helpers")]
pub use signed_envelope::{
    SignedTestEnvelope, SignedTestEnvelopeBuilder, send_transaction_hash_hex, transaction_hash_hex,
};

/// Returns the hexadecimal SHA-256 digest of a fixture file.
///
/// # Panics
/// Panics if the fixture file cannot be read.
#[cfg(feature = "test-helpers")]
#[must_use]
#[allow(
    clippy::expect_used,
    reason = "an unreadable fixture fails the calling test"
)]
pub fn file_sha256(path: &std::path::Path) -> String {
    use sha2::{Digest as _, Sha256};
    signed_envelope::hex(&Sha256::digest(
        std::fs::read(path).expect("fixture file is readable"),
    ))
}

/// Names the second testnet Soroban RPC endpoint of the live suites.
pub const TESTNET_SECONDARY_RPC_URL_ENV: &str = "STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL";

/// The second testnet RPC endpoint of a live suite that signs a smart-account
/// authorization, from [`TESTNET_SECONDARY_RPC_URL_ENV`].
///
/// A smart-account signature rests on a ledger observation from a host other
/// than the primary's, and only the operator can name a second provider, so
/// the suite has no default.
///
/// # Panics
///
/// Panics when the variable is unset, empty, or not an `http` or `https` URL.
#[must_use]
pub fn testnet_secondary_rpc_url() -> &'static str {
    static URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    URL.get_or_init(|| {
        let url = std::env::var(TESTNET_SECONDARY_RPC_URL_ENV).unwrap_or_default();
        assert!(
            !url.trim().is_empty(),
            "{TESTNET_SECONDARY_RPC_URL_ENV} must name a testnet Soroban RPC endpoint on a host \
             other than the primary's"
        );
        assert!(
            url.starts_with("https://") || url.starts_with("http://"),
            "{TESTNET_SECONDARY_RPC_URL_ENV} must be an http or https URL"
        );
        url
    })
}

/// The URL of a loopback mock server under a second host name.
///
/// A smart-account signing path refuses a secondary endpoint on the primary's
/// host, so a test whose endpoints may report the same answers keeps one mock
/// server and passes this URL as the secondary. The URL keeps the scheme and
/// path of `uri` and names `localhost` at the port of a forwarder that copies
/// every connection to the mock.
///
/// The mock listens on `127.0.0.1` alone and `localhost` may resolve to `::1`
/// first, so `localhost` at the mock's own port can reach another process's
/// listener on `[::1]`. The forwarder listens on one port of both loopback
/// families, or on `127.0.0.1` alone on a host without an IPv6 loopback. It
/// runs on a runtime of its own, so a test that blocks its thread while a
/// subprocess uses the URL is served. One forwarder serves each mock port for
/// the rest of the process.
///
/// # Panics
///
/// Panics when `uri` is not an `http` or `https` URL on `127.0.0.1` with a
/// port, the form a `wiremock` server reports, or when the forwarder cannot
/// be set up.
#[cfg(feature = "test-helpers")]
#[must_use]
pub fn second_loopback_host(uri: &str) -> String {
    let (scheme, rest) = uri
        .split_once("://")
        .filter(|(scheme, _)| matches!(*scheme, "http" | "https"))
        .unwrap_or_else(|| panic_on_uri(uri));
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let mock_port = authority
        .strip_prefix("127.0.0.1:")
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or_else(|| panic_on_uri(uri));
    let port = loopback_forwarder::forwarder_port(mock_port);
    format!("{scheme}://localhost:{port}{path}")
}

/// Fails the calling test on a URL [`second_loopback_host`] cannot take.
#[cfg(feature = "test-helpers")]
#[allow(
    clippy::panic,
    reason = "a fixture that cannot be set up fails the calling test"
)]
fn panic_on_uri(uri: &str) -> ! {
    panic!("second_loopback_host takes a loopback mock URL with a port, got {uri}")
}
