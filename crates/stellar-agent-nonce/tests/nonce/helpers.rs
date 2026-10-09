//! Shared test helpers for stellar-agent-nonce integration tests.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::needless_borrows_for_generic_args,
    reason = "test-only helpers; panics and expects acceptable in test support code"
)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::Entry as KeyringEntry;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_nonce::{Nonce, NonceVerifyRequest, ReplayWindow};
use stellar_agent_test_support::keyring_mock;

/// Initialises the mock keyring store.
///
/// Each call replaces the process-global default credential store with a
/// fresh empty mock (see [`stellar_agent_test_support::keyring_mock::install`]).
/// Tests that share state across calls within the same process must not rely
/// on prior entries surviving; combine with `#[serial]` from `serial_test`
/// when ordering matters.
pub fn init_mock() {
    keyring_mock::install().expect("mock keyring store init failed");
}

/// Seeds a 32-byte nonce key into the keyring for the given profile.
///
/// `key_bytes` must be exactly 32 bytes.
pub fn seed_key(profile: &Profile, key_bytes: &[u8; 32]) {
    let entry_ref = &profile.mcp_nonce_key_alias;
    let encoded = URL_SAFE_NO_PAD.encode(key_bytes);
    let entry =
        KeyringEntry::new(&entry_ref.service, &entry_ref.account).expect("entry construction");
    entry.set_password(&encoded).expect("set_password");
}

/// Creates a test profile with a unique nonce-key alias.
pub fn make_profile(label: &str) -> Profile {
    Profile::builder_testnet(
        "stellar-agent-signer",
        label,
        format!("stellar-agent-nonce-{label}"),
        label,
    )
    .build()
}

/// A [`ToolCatalogue`] impl that accepts exactly the named tools.
pub struct StaticCatalogue(pub &'static [&'static str]);

impl stellar_agent_nonce::ToolCatalogue for StaticCatalogue {
    fn is_registered(&self, tool_name: &str) -> bool {
        self.0.contains(&tool_name)
    }
}

/// A catalogue that always rejects tools but does NOT engage key state.
pub struct RejectAllCatalogue;

impl stellar_agent_nonce::ToolCatalogue for RejectAllCatalogue {
    fn is_registered(&self, _: &str) -> bool {
        false
    }
}

/// Returns a future expiry 5 minutes from an arbitrary epoch (test-stable).
pub fn far_future_expiry() -> u64 {
    // 2030-01-01 00:05:00 UTC in milliseconds — safe test epoch.
    1_893_456_300_000u64
}

/// Returns a past expiry (always expired).
pub fn past_expiry() -> u64 {
    1_000u64
}

/// A "now" value that is in the past relative to `far_future_expiry`.
pub fn now_before_expiry() -> u64 {
    1_893_456_000_000u64
}

/// Builds a nonce verification request for integration tests.
#[allow(clippy::too_many_arguments)]
pub fn verify_request<'a>(
    replay_window: &'a mut ReplayWindow,
    nonce: &'a Nonce,
    envelope_xdr: &'a [u8],
    expiry_unix_ms: u64,
    tool_name: &'a str,
    chain_id: &'a str,
    now_unix_ms: u64,
) -> NonceVerifyRequest<'a> {
    NonceVerifyRequest {
        replay_window,
        nonce,
        envelope_xdr,
        expiry_unix_ms,
        tool_name,
        chain_id,
        now_unix_ms,
    }
}
