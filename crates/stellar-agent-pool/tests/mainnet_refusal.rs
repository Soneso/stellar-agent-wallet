//! `submit_pooled` refuses mainnet before it acquires a channel or copies the
//! pool master seed.
//!
//! The seed is a concrete value no signer double can count, so the copy site
//! counts its copies under the `test-hooks` feature. The two tests run
//! serially in this binary, which holds no other caller of `submit_pooled`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use serial_test::serial;
use stellar_agent_core::WalletError;
use stellar_agent_core::error::NetworkError;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::signing::Signer as _;
use stellar_agent_pool::derive::derive_channel_signer;
use stellar_agent_pool::pool::ChannelPool;
use stellar_agent_pool::submit::{SEED_COPIES, submit_pooled};
use stellar_agent_pool::{ChannelRecord, PoolError};
use wiremock::MockServer;
use zeroize::Zeroizing;

const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const DEST_KEY: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
const CHANNEL_INDEX: u32 = 1;

fn seed() -> Zeroizing<[u8; 64]> {
    Zeroizing::new([7u8; 64])
}

/// A pool of one free channel whose key derives from [`seed`].
async fn pool() -> ChannelPool {
    let signer = derive_channel_signer(seed(), CHANNEL_INDEX).unwrap();
    let key = format!("{}", signer.public_key().await.unwrap());
    ChannelPool::from_records(vec![ChannelRecord::new(CHANNEL_INDEX, &key)], vec![100]).unwrap()
}

/// Submits one payment through `pool` against `server` under `passphrase`
/// and returns the result with the number of seed copies the call made.
async fn submit(
    pool: &ChannelPool,
    server: &MockServer,
    passphrase: &str,
) -> (Result<(), PoolError>, usize) {
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let fixture = common::RecorderFixture::new();
    let before = SEED_COPIES.load(Ordering::SeqCst);
    let result = submit_pooled(
        pool,
        &client,
        &seed(),
        passphrase,
        100,
        Duration::from_secs(1),
        &fixture.recorder(),
        |builder| {
            let _ = builder.payment(
                DEST_KEY,
                stellar_agent_core::StellarAmount::from_stroops(1),
                &stellar_agent_network::builder::Asset::Native,
            );
        },
    )
    .await
    .map(|_| ());
    (result, SEED_COPIES.load(Ordering::SeqCst) - before)
}

/// A mainnet passphrase is refused with the network's write refusal before
/// a channel is acquired, the seed is copied, or a request is made.
#[tokio::test]
#[serial]
async fn submit_pooled_refuses_mainnet_before_the_seed_copy() {
    let pool = pool().await;
    let server = MockServer::start().await;

    let (result, copies) = submit(&pool, &server, MAINNET_PASSPHRASE).await;

    assert!(
        matches!(
            result,
            Err(PoolError::Wallet(WalletError::Network(
                NetworkError::MainnetWriteForbidden
            )))
        ),
        "got: {result:?}"
    );
    assert_eq!(copies, 0, "no seed copy before the refusal");
    assert_eq!(pool.free_count(), 1);
    assert_eq!(pool.in_flight_count(), 0);
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// On testnet the same call copies the seed once before its submission
/// fails at the endpoint, so the counter above counts the copy.
#[tokio::test]
#[serial]
async fn submit_pooled_copies_the_seed_once_on_testnet() {
    let pool = pool().await;
    let server = MockServer::start().await;

    let (result, copies) = submit(&pool, &server, TESTNET_PASSPHRASE).await;

    assert!(result.is_err(), "the mock endpoint serves nothing");
    assert_eq!(copies, 1);
}
