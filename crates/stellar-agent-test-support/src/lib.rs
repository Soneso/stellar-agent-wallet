//! Test harness for log-capture, secret-leakage assertions, and Stellar test
//! fixtures.
//!
//! ## What this crate provides
//!
//! - [`log_capture`] + [`secret_patterns`] — capture the bytes a `tracing`
//!   fmt layer writes during a test and assert that no secret material
//!   (Stellar S-strkeys, BIP-39 mnemonic words, sensitive field values) appears
//!   in them.
//! - [`keyring_mock`] — redirect `keyring_core` calls to an in-memory store
//!   during unit tests, so no OS keychain dialog appears in `cargo test`.
//! - [`xdr_fixtures`], [`testnet_strkeys`], [`verifier_registry`],
//!   [`echo_id_responder`] — Stellar XDR / strkey fixtures and HTTP/contract
//!   test doubles for consumer crates' tests.
//! - [`testnet_helpers`] — live-network helpers (Friendbot funding, RPC) for
//!   consumer crates' testnet-acceptance tests; behind the `testnet-helpers`
//!   feature and exercised only by those live tests.
//! - [`env_guard::StellarAgentHomeGuard`] — RAII guard overriding
//!   `STELLAR_AGENT_HOME` for tests that exercise the wallet's
//!   home-directory resolution; callers serialise with `#[serial]`.
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

#[cfg(feature = "wiremock-helpers")]
pub mod echo_id_responder;
pub mod env_guard;
pub mod keyring_mock;
pub mod log_capture;
pub mod secret_patterns;
#[cfg(feature = "testnet-helpers")]
pub mod testnet_helpers;
pub mod testnet_strkeys;
#[cfg(feature = "verifier-registry")]
pub mod verifier_registry;
#[cfg(feature = "test-helpers")]
pub mod xdr_fixtures;

mod bip39_english;

#[cfg(feature = "wiremock-helpers")]
pub use echo_id_responder::EchoIdResponder;
pub use env_guard::StellarAgentHomeGuard;
pub use log_capture::{CaptureWriter, RedactionStrictSubscriber, with_captured_logs};
pub use secret_patterns::assert_no_secret_bytes;
