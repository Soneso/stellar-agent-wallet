//! Live testnet integration tests for `fetch_account`.
//!
//! All tests in this file are marked `#[ignore]` — they are excluded from CI
//! and must be run manually against the live Stellar testnet:
//!
//! ```text
//! cargo test -p stellar-agent-network --test balances_live -- --ignored
//! ```
//!
//! The testnet RPC endpoint (`https://soroban-testnet.stellar.org`) may be
//! unavailable; these tests are expected to be flaky in offline or testnet-
//! reset scenarios and are never relied on for CI green/red status.
//!
//! # What it verifies
//!
//! Exercises the end-to-end path (live RPC → XDR decode → AccountView),
//! confirming that a friendbot-funded account returns a populated balances
//! list including native XLM.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; assertions via unwrap/expect are idiomatic in integration tests"
)]

use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_network::{Asset, StellarRpcClient, fetch_account};

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

/// A known-funded testnet account (the SDF test account used across the
/// ecosystem's testnet documentation). This account maintains a non-zero
/// XLM balance on Stellar testnet.
///
/// If this test starts failing, the account may have been reset.
/// Use Friendbot to re-fund it: `curl
/// "https://friendbot.stellar.org?addr=GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR"`.
const KNOWN_FUNDED_ACCOUNT: &str = "GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR";

/// A valid G-strkey that is almost certainly unfunded on testnet.
/// Derived from key bytes [0xfe, 0x00, ..., 0x00].
const LIKELY_UNFUNDED_ACCOUNT: &str = "GD7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2HQ";

#[tokio::test]
#[ignore]
async fn live_fetch_funded_account_returns_native_balance() {
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet URL must be valid");

    let account = fetch_account(&client, KNOWN_FUNDED_ACCOUNT, &[])
        .await
        .expect("live fetch_account must succeed for a known-funded testnet account");

    assert_eq!(account.account_id, KNOWN_FUNDED_ACCOUNT);
    assert!(
        !account.balances.is_empty(),
        "funded account must have at least one balance"
    );
    assert_eq!(
        account.balances[0].asset.asset_type, "native",
        "first balance must be native XLM"
    );
    // Balance must be a positive decimal.
    let parsed: f64 = account.balances[0]
        .balance
        .parse()
        .expect("balance must parse as f64");
    assert!(
        parsed > 0.0,
        "live funded account must have positive XLM balance"
    );

    #[allow(clippy::print_stdout, reason = "test diagnostic output")]
    {
        println!(
            "live test: {} has {} XLM (seq {})",
            account.account_id, account.balances[0].balance, account.sequence_number
        );
    }
}

#[tokio::test]
#[ignore]
async fn live_fetch_unfunded_account_returns_not_found() {
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet URL must be valid");

    let result = fetch_account(&client, LIKELY_UNFUNDED_ACCOUNT, &[]).await;

    assert!(result.is_err(), "unfunded account must return an error");
    assert!(
        matches!(
            result.unwrap_err(),
            WalletError::Network(NetworkError::AccountNotFound { .. })
        ),
        "error must be AccountNotFound"
    );
}

/// Live test: query a non-existent trustline.
///
/// Sends a USDC trustline key alongside the account key for a known-funded
/// account that does not hold a USDC trustline. The expected result is that
/// the native XLM balance is present and the USDC entry is absent from
/// `balances` (absent trustlines are omitted, not surfaced as zero).
///
/// Run manually: `cargo test -p stellar-agent-network --test balances_live -- --ignored`.
#[tokio::test]
#[ignore]
async fn live_fetch_trustline_not_held_is_omitted() {
    // The SDF test account is unlikely to hold a USDC trustline.
    // USDC on Stellar testnet (centre.io testnet issuer).
    let usdc_issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
    let asset = Asset::parse(&format!("USDC:{usdc_issuer}")).expect("valid asset spec");

    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet URL must be valid");

    let account = fetch_account(&client, KNOWN_FUNDED_ACCOUNT, &[asset])
        .await
        .expect("account must exist on testnet");

    // Native XLM is always present.
    assert!(
        !account.balances.is_empty(),
        "funded account must have at least one balance"
    );
    assert_eq!(
        account.balances[0].asset.asset_type, "native",
        "first balance must be native XLM"
    );

    // The USDC trustline should NOT be present (the account does not trust it).
    let usdc_present = account
        .balances
        .iter()
        .any(|b| b.asset.asset_type == "USDC");
    assert!(
        !usdc_present,
        "USDC trustline should be absent for an account that does not hold it"
    );

    #[allow(clippy::print_stdout, reason = "test diagnostic output")]
    {
        println!(
            "live test: {} has {} balances (USDC absent as expected)",
            account.account_id,
            account.balances.len()
        );
    }
}
