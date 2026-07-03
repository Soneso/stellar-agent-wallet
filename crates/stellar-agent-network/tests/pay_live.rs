//! Live testnet integration test for the pay command.
//!
//! Gated with `#[ignore]` — run manually with:
//!
//! ```text
//! cargo test -p stellar-agent-network --test pay_live -- --ignored
//! ```
//!
//! # Prerequisites
//!
//! Set the following environment variables before running:
//!
//! - `STELLAR_AGENT_TEST_SECRET_ENV` — the name of an env var holding the
//!   S-strkey for the source account (e.g. `SOURCE_SECRET`).
//! - `SOURCE_SECRET` (or whatever `STELLAR_AGENT_TEST_SECRET_ENV` names) —
//!   the S-strkey for a funded testnet source account.
//! - `STELLAR_AGENT_TEST_SOURCE` — the G-strkey of the source account.
//! - `STELLAR_AGENT_TEST_DEST` — the G-strkey of the destination account.
//!
//! Both accounts must exist on testnet. The source must have at least 1.01 XLM
//! (to cover the payment + reserve + fee).
//!
//! # What it verifies
//!
//! A human-initiated `stellar-agent pay` round-trip confirmed by the testnet
//! RPC `getTransaction` returning `"SUCCESS"`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "live test; panics, unwraps, and println are acceptable in manually-run integration tests"
)]

use std::time::Duration;
use zeroize::Zeroizing;

use stellar_agent_core::StellarAmount;
use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
use stellar_agent_network::signing::software::SoftwareSigningKey;
use stellar_agent_network::{StellarRpcClient, fetch_account, submit_transaction_and_wait};

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Live testnet payment round-trip.
///
/// Requires funded accounts set via environment variables (see module doc).
/// Verifies that the transaction is submitted and confirmed on testnet.
#[tokio::test]
#[ignore = "requires funded testnet accounts and env vars; run manually"]
async fn live_payment_round_trip() {
    let source_gstrkey = std::env::var("STELLAR_AGENT_TEST_SOURCE")
        .expect("STELLAR_AGENT_TEST_SOURCE env var must be set");
    let dest_gstrkey = std::env::var("STELLAR_AGENT_TEST_DEST")
        .expect("STELLAR_AGENT_TEST_DEST env var must be set");
    let secret_var = std::env::var("STELLAR_AGENT_TEST_SECRET_ENV")
        .expect("STELLAR_AGENT_TEST_SECRET_ENV env var must be set");
    let s_strkey: Zeroizing<String> = Zeroizing::new(
        std::env::var(&secret_var).unwrap_or_else(|_| panic!("{secret_var} env var must be set")),
    );

    // Parse the S-strkey.
    // stellar_strkey::ed25519::PrivateKey is Copy and has no Drop/Zeroize.
    // We must explicitly zeroize the original local after copying the bytes.
    let mut private_key =
        stellar_strkey::ed25519::PrivateKey::from_string(&s_strkey).expect("valid S-strkey");
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(private_key.0);
    // Explicitly zeroize the original local; PrivateKey is Copy with no
    // Drop/Zeroize, so two copies exist until this point.
    zeroize::Zeroize::zeroize(&mut private_key.0);
    drop(s_strkey); // Release the heap String holding the S-strkey.
    let signer = SoftwareSigningKey::new_from_zeroizing(seed);

    // Fetch source account to get sequence number.
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("valid URL");
    let account = fetch_account(&client, &source_gstrkey, &[])
        .await
        .expect("source account must exist on testnet");

    // Build a 0.001 XLM payment.
    let amount = StellarAmount::from_stroops(1_000); // 0.0001 XLM
    let mut builder = ClassicOpBuilder::new(
        &source_gstrkey,
        account.sequence_number + 1,
        TESTNET_PASSPHRASE,
        100,
    );
    builder
        .payment(&dest_gstrkey, amount, &Asset::Native)
        .expect("payment op");

    let signed_xdr = builder
        .build_and_sign(&signer)
        .await
        .expect("sign must succeed");

    // Submit and wait.
    let result = submit_transaction_and_wait(
        &client,
        &signed_xdr,
        Duration::from_secs(60),
        TESTNET_PASSPHRASE,
        None,
    )
    .await
    .expect("transaction must confirm");

    println!(
        "live_payment_round_trip: confirmed in ledger {} tx_hash {}",
        result.ledger, result.tx_hash
    );
    assert_eq!(result.tx_hash.len(), 64, "tx_hash must be 64-char hex");
    assert!(result.ledger > 0, "ledger must be non-zero");
}
