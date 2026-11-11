//! The pre-send budget on the real clock: the reads before the send run under
//! it, not under the submission's timeout, so a read slower than the timeout
//! still reaches the send.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration test; panics/unwraps acceptable"
)]

use std::time::Duration;

use serde_json::json;
use stellar_agent_network::{PRE_SEND_BUDGET, StellarRpcClient, submit_transaction_and_wait};
use stellar_agent_test_support::signed_envelope::{
    SignedTestEnvelope, TESTNET_PASSPHRASE, get_network_result,
};
use stellar_agent_test_support::{EchoIdResponder, rpc_request_count};
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// Answers as `inner` does, after `delay`.
struct Delayed {
    inner: EchoIdResponder,
    delay: Duration,
}

impl Respond for Delayed {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.inner.respond(request).set_delay(self.delay)
    }
}

/// Mounts one answer for `rpc_method`.
async fn mount(server: &MockServer, rpc_method: &str, answer: impl Respond + 'static) {
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": rpc_method })))
        .respond_with(answer)
        .mount(server)
        .await;
}

/// An identity probe that answers after two seconds, past the one-second
/// timeout and well inside the budget, still reaches the send, and the
/// submission confirms after one send.
#[tokio::test]
async fn an_identity_probe_slower_than_the_timeout_still_sends() {
    let timeout = Duration::from_secs(1);
    let delay = Duration::from_secs(2);
    assert!(delay > timeout && delay < PRE_SEND_BUDGET);
    let envelope = SignedTestEnvelope::for_source([0x43; 32]);
    let server = MockServer::start().await;
    mount(
        &server,
        "getNetwork",
        Delayed {
            inner: EchoIdResponder::new(get_network_result(TESTNET_PASSPHRASE)),
            delay,
        },
    )
    .await;
    mount(
        &server,
        "getLedgerEntries",
        EchoIdResponder::new(envelope.ledger_entries_result()),
    )
    .await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "sendTransaction" })))
        .respond_with(EchoIdResponder::new(json!({
            "hash": envelope.tx_hash_hex(),
            "status": "PENDING",
            "latestLedger": 1000,
            "latestLedgerCloseTime": "1699999999"
        })))
        .expect(1)
        .named("one send")
        .mount(&server)
        .await;
    mount(
        &server,
        "getTransaction",
        EchoIdResponder::new(json!({
            "status": "SUCCESS",
            "txHash": envelope.tx_hash_hex(),
            "ledger": 4567,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": null,
            "resultMetaXdr": null
        })),
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        timeout,
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await
    .expect("the slow probe still reaches the send");

    assert_eq!(result.tx_hash, envelope.tx_hash_hex());
    assert_eq!(result.ledger, 4567);
    assert_eq!(rpc_request_count(&server, "sendTransaction").await, 1);
    server.verify().await;
}
