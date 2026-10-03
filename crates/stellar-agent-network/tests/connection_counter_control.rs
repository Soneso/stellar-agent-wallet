//! Positive control for `stellar_agent_test_support::ConnectionCounter`.
//!
//! The CLI's mainnet refusal tests persist an `https://` loopback endpoint
//! and assert that the counter accepted no connection. That zero means "no
//! contact" only if the counter does count a connection the wallet's RPC
//! client makes, TLS handshake included. This test makes one and counts it.

#![allow(clippy::expect_used, reason = "test-only fixture setup")]

use stellar_agent_network::StellarRpcClient;
use stellar_agent_test_support::ConnectionCounter;

#[tokio::test]
async fn the_counter_counts_a_stellar_rpc_client_connection() {
    let counter = ConnectionCounter::start().expect("loopback listener");
    assert_eq!(counter.accepted().expect("connection count"), 0);

    let client = StellarRpcClient::new(&counter.https_uri()).expect("client for the counter");
    let result = client.get_health().await;

    assert!(
        result.is_err(),
        "the counter closes every connection, so the request cannot succeed"
    );
    assert_eq!(
        counter.accepted().expect("connection count"),
        1,
        "the client's one TLS connection attempt must be counted"
    );
}
