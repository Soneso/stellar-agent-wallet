//! Shared helpers for testnet acceptance tests in this crate.
//!
//! Each test file that requires live testnet access uses `mod common;` to
//! pull in these constants and the `fund_via_friendbot` helper, so the
//! endpoint set and funding flow have a single definition per crate.
//!
//! Only compiled when the `testnet-integration` feature is active; callers
//! guard the top of their file with `#![cfg(feature = "testnet-integration")]`.

#![cfg(feature = "testnet-integration")]
#![allow(dead_code, reason = "helpers are selectively used across test files")]

/// Soroban RPC endpoint for SDF testnet.
pub const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

/// Friendbot endpoint for testnet account funding.
pub const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

/// Network passphrase for SDF testnet.
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Ensures an account is funded via testnet Friendbot.
///
/// Friendbot refuses to fund an account that already exists, answering 400
/// with an "account already funded to starting balance" detail; for this
/// helper's postcondition (the account exists and holds XLM) that state is
/// success. Fixed well-known accounts such as the interop deployer hit it on
/// every run after their first funding. Panics if the HTTP request fails or
/// Friendbot answers with anything else.
pub async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = reqwest::get(&url)
        .await
        .expect("Friendbot HTTP request must succeed");
    let status = resp.status();
    if status.is_success() {
        return;
    }
    let body = resp.text().await.unwrap_or_default();
    assert!(
        status == reqwest::StatusCode::BAD_REQUEST && body.contains("account already funded"),
        "Friendbot must fund {g_strkey}; got {status}: {body}"
    );
}
