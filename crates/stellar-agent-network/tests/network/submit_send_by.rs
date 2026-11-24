//! The send-by instant of `submit_transaction_and_wait_sent_by`.
//!
//! The identity probe and signer-set read end at the send-by instant. The
//! instant is checked again after the pre-send record, and before every
//! resend of the same bytes. A record written for a submission that is not
//! sent is reported as unsent; a resend refused after a send leaves the
//! record unresolved. The confirmation poll runs past the instant, under the
//! submission's own timeout.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration test; panics/unwraps acceptable"
)]

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use stellar_agent_core::error::WalletError;
use stellar_agent_network::{
    PreSendStage, SentByError, StellarRpcClient, SubmissionIntent, SubmissionOutcome,
    SubmissionRecorder, SubmissionResult, submit_transaction_and_wait_sent_by,
};
use stellar_agent_test_support::signed_envelope::{
    SignedTestEnvelope, TESTNET_PASSPHRASE, get_network_result,
};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

/// Seed of the envelope's source account. A public test fixture, never a
/// production key.
const SOURCE_SEED: [u8; 32] = [0x2c; 32];

/// The ledger the confirmation reports.
const CONFIRMED_LEDGER: u32 = 4567;

/// The submission's own timeout in every case: far beyond the send-by
/// instant.
const TIMEOUT: Duration = Duration::from_secs(30);

/// How far ahead of the call the send-by instant lies.
const SEND_BY: Duration = Duration::from_secs(1);

/// Outlasts [`SEND_BY`].
const PAST_SEND_BY: Duration = Duration::from_secs(3);

/// Answers every method of one submission, delaying the method `slow` names,
/// and answers the first `pending_polls` confirmation polls `NOT_FOUND`.
struct Rpc {
    ledger_entries: Value,
    tx_hash: String,
    slow: Option<(&'static str, Duration)>,
    pending_polls: usize,
    polls: AtomicUsize,
}

impl Respond for Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let method = body["method"].as_str().unwrap();
        let result = match method {
            "getNetwork" => get_network_result(TESTNET_PASSPHRASE),
            "getLedgerEntries" => self.ledger_entries.clone(),
            "sendTransaction" => json!({
                "hash": self.tx_hash,
                "status": "PENDING",
                "latestLedger": 1000,
                "latestLedgerCloseTime": "1699999999"
            }),
            "getTransaction" if self.polls.fetch_add(1, Ordering::SeqCst) < self.pending_polls => {
                json!({
                    "status": "NOT_FOUND",
                    "latestLedger": 1000,
                    "latestLedgerCloseTime": "1700000001",
                    "oldestLedger": 900,
                    "ledgerRetentionWindow": 100
                })
            }
            "getTransaction" => json!({
                "status": "SUCCESS",
                "txHash": self.tx_hash,
                "ledger": CONFIRMED_LEDGER,
                "createdAt": "1700000000",
                "envelopeXdr": null,
                "resultXdr": null,
                "resultMetaXdr": null
            }),
            other => panic!("unexpected RPC method: {other}"),
        };
        let template = ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}));
        match self.slow {
            Some((slow, delay)) if slow == method => template.set_delay(delay),
            _ => template,
        }
    }
}

/// A recorder whose pre-send record takes `pre_send_delay`, keeping every
/// outcome it is handed.
#[derive(Default)]
struct Recorder {
    pre_send_delay: Duration,
    pre_sends: AtomicUsize,
    outcomes: Mutex<Vec<SubmissionOutcome>>,
    /// The send-by instant of every recorded intent.
    send_bys: Mutex<Vec<Option<u64>>>,
}

#[async_trait::async_trait]
impl SubmissionRecorder for Recorder {
    async fn pre_send(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        self.pre_sends.fetch_add(1, Ordering::SeqCst);
        self.send_bys.lock().unwrap().push(intent.send_by_ms);
        tokio::time::sleep(self.pre_send_delay).await;
        Ok(())
    }

    async fn outcome(&self, _intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        self.outcomes.lock().unwrap().push(outcome.clone());
    }
}

/// What one submission did.
struct Run {
    result: Result<SubmissionResult, SentByError>,
    elapsed: Duration,
    sends: usize,
    /// The hash of the submitted transaction.
    #[cfg(feature = "test-hooks")]
    tx_hash: String,
}

/// Submits a signed envelope with its send-by instant [`SEND_BY`] ahead,
/// against an endpoint that delays the method `slow` names and answers the
/// first `pending_polls` polls `NOT_FOUND`.
async fn submit(
    slow: Option<(&'static str, Duration)>,
    pending_polls: usize,
    recorder: &Recorder,
) -> Run {
    let envelope = SignedTestEnvelope::for_source_with_sequence(SOURCE_SEED, 1001);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(Rpc {
            ledger_entries: envelope.ledger_entries_result(),
            tx_hash: envelope.tx_hash_hex().to_owned(),
            slow,
            pending_polls,
            polls: AtomicUsize::new(0),
        })
        .mount(&server)
        .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let started = tokio::time::Instant::now();
    let result = submit_transaction_and_wait_sent_by(
        &client,
        envelope.envelope_xdr(),
        started + SEND_BY,
        TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(recorder),
        None,
    )
    .await;
    let elapsed = started.elapsed();
    let sends = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| {
            serde_json::from_slice::<Value>(&request.body)
                .is_ok_and(|body| body["method"] == "sendTransaction")
        })
        .count();
    Run {
        result,
        elapsed,
        sends,
        #[cfg(feature = "test-hooks")]
        tx_hash: envelope.tx_hash_hex().to_owned(),
    }
}

/// Asserts that the instant passed at `stage`, that the call returned at the
/// instant rather than after the slow step, and that nothing was sent.
fn assert_elapsed_at(run: &Run, stage: PreSendStage) {
    match &run.result {
        Err(SentByError::Elapsed {
            stage: reported,
            sent_tx_hash,
        }) => {
            assert_eq!(*reported, stage);
            assert_eq!(*sent_tx_hash, None, "{stage:?}: nothing was sent");
        }
        other => panic!("expected the send-by refusal at {stage:?}, got {other:?}"),
    }
    assert!(
        run.elapsed < PAST_SEND_BY,
        "{stage:?}: the step is cut at the instant, after {:?}",
        run.elapsed
    );
    assert_eq!(run.sends, 0, "{stage:?}: nothing is sent");
}

#[tokio::test]
async fn an_identity_probe_past_the_send_by_instant_sends_nothing() {
    let recorder = Recorder::default();

    let run = submit(Some(("getNetwork", PAST_SEND_BY)), 0, &recorder).await;

    assert_elapsed_at(&run, PreSendStage::EndpointIdentity);
    assert_eq!(
        recorder.pre_sends.load(Ordering::SeqCst),
        0,
        "nothing is recorded"
    );
}

#[tokio::test]
async fn a_signer_set_read_past_the_send_by_instant_sends_nothing() {
    let recorder = Recorder::default();

    let run = submit(Some(("getLedgerEntries", PAST_SEND_BY)), 0, &recorder).await;

    assert_elapsed_at(&run, PreSendStage::SignatureBinding);
    assert_eq!(
        recorder.pre_sends.load(Ordering::SeqCst),
        0,
        "nothing is recorded"
    );
}

/// The instant is checked immediately before `sendTransaction`: a pre-send
/// record that outlasts it sends nothing and is reported as unsent under the
/// timeout code.
#[tokio::test]
async fn a_record_past_the_send_by_instant_sends_nothing_and_is_reported_as_unsent() {
    let recorder = Recorder {
        pre_send_delay: PAST_SEND_BY,
        ..Recorder::default()
    };

    let run = submit(None, 0, &recorder).await;

    match &run.result {
        Err(SentByError::Elapsed {
            stage,
            sent_tx_hash,
        }) => {
            assert_eq!(*stage, PreSendStage::Send);
            assert_eq!(*sent_tx_hash, None, "nothing was sent");
        }
        other => panic!("expected the send-by refusal before the send, got {other:?}"),
    }
    assert_eq!(run.sends, 0, "nothing is sent");
    assert_eq!(recorder.pre_sends.load(Ordering::SeqCst), 1);
    let outcomes = recorder.outcomes.lock().unwrap();
    let [SubmissionOutcome::NotSent { code, .. }] = outcomes.as_slice() else {
        panic!("one unsent outcome: {outcomes:?}")
    };
    assert_eq!(code, "network.rpc_timeout");
}

/// The recorded intent carries the caller's send-by instant in Unix
/// milliseconds.
#[tokio::test]
async fn the_intent_carries_the_callers_send_by() {
    let recorder = Recorder::default();
    let before = stellar_agent_core::timefmt::now_unix_ms().unwrap();

    let run = submit(None, 0, &recorder).await;

    assert!(run.result.is_ok(), "{:?}", run.result.err());
    let after = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    let send_by = u64::try_from(SEND_BY.as_millis()).unwrap();
    let send_bys = recorder.send_bys.lock().unwrap();
    let [Some(send_by_ms)] = send_bys.as_slice() else {
        panic!("one intent with a send-by instant: {send_bys:?}")
    };
    // The conversion reads the clock and the remaining duration in whole
    // milliseconds, so it may fall a few milliseconds short of the instant.
    assert!(
        (before + send_by - 5..=after + send_by).contains(send_by_ms),
        "{send_by_ms} lies {SEND_BY:?} ahead of the call, between {before} and {after}"
    );
}

/// A send that starts before the instant and whose answer is lost to a
/// transport failure is not followed by a resend after the instant: the
/// resend the backoff schedules is refused at the send stage. The first send
/// may have reached the network, so its record stays unresolved and the
/// refusal names the transaction.
#[cfg(feature = "test-hooks")]
#[tokio::test]
async fn a_resend_past_the_send_by_instant_is_refused_and_the_record_stays_unresolved() {
    struct Lost;
    impl Drop for Lost {
        fn drop(&mut self) {
            stellar_agent_network::submit::lose_send_answers_on_this_thread(0);
        }
    }
    let recorder = Recorder::default();
    let _lost = Lost;
    stellar_agent_network::submit::lose_send_answers_on_this_thread(1);

    let run = submit(Some(("sendTransaction", PAST_SEND_BY)), 0, &recorder).await;

    match &run.result {
        Err(SentByError::Elapsed {
            stage,
            sent_tx_hash,
        }) => {
            assert_eq!(*stage, PreSendStage::Send);
            assert_eq!(sent_tx_hash.as_deref(), Some(run.tx_hash.as_str()));
        }
        other => panic!("expected the send-by refusal of the resend, got {other:?}"),
    }
    assert_eq!(run.sends, 1, "no resend reaches the endpoint");
    assert_eq!(recorder.pre_sends.load(Ordering::SeqCst), 1);
    let outcomes = recorder.outcomes.lock().unwrap();
    assert!(
        matches!(
            outcomes.as_slice(),
            [SubmissionOutcome::TransportAfterSend { .. }]
        ),
        "the record stays unresolved: {outcomes:?}"
    );
}

/// The instant bounds the steps before the send only: a confirmation that
/// arrives after it, within the submission's timeout, is accepted.
#[tokio::test]
async fn the_confirmation_poll_runs_past_the_send_by_instant() {
    let recorder = Recorder::default();

    let run = submit(None, 1, &recorder).await;

    match &run.result {
        Ok(confirmed) => assert_eq!(confirmed.ledger, CONFIRMED_LEDGER),
        Err(error) => panic!("the submission confirms: {error:?}"),
    }
    assert!(
        run.elapsed > SEND_BY,
        "the confirmation arrives after the instant: {:?}",
        run.elapsed
    );
    assert_eq!(run.sends, 1);
    let outcomes = recorder.outcomes.lock().unwrap();
    assert!(
        matches!(outcomes.as_slice(), [SubmissionOutcome::Success { .. }]),
        "{outcomes:?}"
    );
}
