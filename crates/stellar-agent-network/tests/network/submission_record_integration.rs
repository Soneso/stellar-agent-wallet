//! What the submit layer records, and when, against a mocked Stellar RPC
//! endpoint.
//!
//! The record is written before the transaction is sent and settled against
//! what the network answered. These tests pin the order of the two checks that
//! write it, the outcome each exit reports, and what each outcome leaves
//! behind.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use serial_test::serial;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_core::audit_log::test_helpers::verified_audit_entries;
use stellar_agent_core::audit_log::tip_anchor::{
    InMemoryTipAnchorStore, KeyedAuditAccess, TipAnchorStore,
};
use stellar_agent_core::audit_log::{AuditEntry, AuditOutbox, AuditWriter, NewToolInvocation};
use stellar_agent_core::error::{SubmissionError, WalletError};
use stellar_agent_core::policy::v1::criteria::state_store::{StateKey, WindowEntry, WindowLimit};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_agent_network::policy_state::PersistedWindowStore;
use stellar_agent_network::submit::submit_transaction_and_wait;
use stellar_agent_network::{
    StellarRpcClient, SubmissionIntent, SubmissionOutcome, SubmissionRecorder,
    WalletSubmissionRecorder,
};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::signed_envelope::{
    SignedTestEnvelope, TESTNET_PASSPHRASE, get_network_result,
};
use stellar_agent_test_support::{EchoIdResponder, rpc_request_count};
use tempfile::TempDir;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);
// Timeout is observed between two-second confirmation polls.
const TIMEOUT_DEADLINE: Duration = Duration::from_secs(1);
const TIMEOUT_OUTER_BOUND: Duration = Duration::from_secs(4);
const SUBMISSION_LEDGER: u32 = 1_000;

/// What the recorder was asked to do, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    PreSend,
    Outcome(SubmissionOutcome),
}

/// The wallet's recorder, with every call it receives written down.
///
/// Wrapping the real recorder rather than standing in for it means the
/// receipt, the reservation and the returned refusals are the production ones;
/// the log only says which of them ran.
struct RecordingRecorder<'a> {
    inner: WalletSubmissionRecorder<'a>,
    calls: Arc<Mutex<Vec<Call>>>,
}

#[async_trait]
impl SubmissionRecorder for RecordingRecorder<'_> {
    async fn pre_send(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        self.calls.lock().unwrap().push(Call::PreSend);
        self.inner.pre_send(intent).await
    }

    async fn outcome(&self, intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Outcome(outcome.clone()));
        self.inner.outcome(intent, outcome).await;
    }
}

fn test_profile(name: &str) -> Profile {
    let mut p = Profile::builder_testnet(name, "acct", "n-svc", "n-acct").build();
    p.policy_window_state_key_id = KeyringEntryRef::default_policy_window_state_key(name);
    p
}

fn state_key(profile_name: &str) -> StateKey {
    StateKey::new(profile_name, 1, "native", 86_400)
}

/// One entry under a cap far above what these tests reserve.
///
/// These tests pin what the recorder writes at each exit, not what the window
/// admits, so no reservation they take is refused by its own limit.
fn entry(profile_name: &str, ts_ms: u64, amount: i128) -> WindowEntry {
    WindowEntry::new(
        state_key(profile_name),
        ts_ms,
        amount,
        WindowLimit::Amount {
            asset: "native".to_owned(),
            window: "1d".to_owned(),
            max_stroops: 1_000_000,
        },
    )
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// Everything one submission needs: a profile, a receipt store and a window
/// file, all under temporary state.
struct Fixture {
    _dir: TempDir,
    _receipt_dir: TempDir,
    profile: Profile,
    profile_name: String,
    receipts: ReceiptStore,
    window: PersistedWindowStore,
    /// The window store's sidecar lock file, which a test holds to make the
    /// reservation write fail.
    window_lock_path: std::path::PathBuf,
}

fn fixture(name: &str) -> Fixture {
    keyring_mock::install().unwrap();
    let dir = TempDir::new().unwrap();
    let receipt_dir = TempDir::new().unwrap();
    let window_path = dir.path().join(format!("{name}.window"));
    let window_lock_path = dir.path().join(format!("{name}.window.lock"));
    Fixture {
        profile: test_profile(name),
        profile_name: name.to_owned(),
        receipts: ReceiptStore::open_at(receipt_dir.path(), name).unwrap(),
        window: PersistedWindowStore::at_path(window_path),
        window_lock_path,
        _dir: dir,
        _receipt_dir: receipt_dir,
    }
}

/// Holds the window store's sidecar lock for as long as it is alive, which is
/// what makes `record_pending` refuse.
fn hold_window_lock(path: &std::path::Path) -> std::fs::File {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .expect("the sidecar lock file must open");
    file.try_lock().expect("the lock must be free");
    file
}

impl Fixture {
    fn recorder(&self, calls: &Arc<Mutex<Vec<Call>>>) -> RecordingRecorder<'_> {
        RecordingRecorder {
            inner: WalletSubmissionRecorder::new(
                &self.profile,
                self.profile_name.clone(),
                "stellar_pay_commit",
                Some("stellar:testnet".to_owned()),
                stellar_agent_core::audit_log::PolicyDecision::Allow,
                Vec::new(),
                vec![entry(&self.profile_name, now_ms(), 500)],
                self.receipts.clone(),
                self.window.clone(),
                None,
                None,
                "test-request",
                now_ms(),
            ),
            calls: Arc::clone(calls),
        }
    }

    /// A recorder whose window entry carries `max_stroops`, so the reservation
    /// write decides admission rather than waving every amount through.
    fn capped_recorder<'a>(
        &'a self,
        calls: &Arc<Mutex<Vec<Call>>>,
        audit: Arc<Mutex<stellar_agent_core::audit_log::AuditWriter>>,
        amount: i128,
        max_stroops: i128,
    ) -> RecordingRecorder<'a> {
        RecordingRecorder {
            inner: WalletSubmissionRecorder::new(
                &self.profile,
                self.profile_name.clone(),
                "stellar_pay_commit",
                Some("stellar:testnet".to_owned()),
                stellar_agent_core::audit_log::PolicyDecision::Allow,
                Vec::new(),
                vec![WindowEntry::new(
                    state_key(&self.profile_name),
                    now_ms(),
                    amount,
                    WindowLimit::Amount {
                        asset: "native".to_owned(),
                        window: "1d".to_owned(),
                        max_stroops,
                    },
                )],
                self.receipts.clone(),
                self.window.clone(),
                Some(audit),
                None,
                "test-request",
                now_ms(),
            ),
            calls: Arc::clone(calls),
        }
    }

    fn reservation_is_open(&self, envelope_hash: &str) -> bool {
        self.window
            .pending_reservations(&self.profile)
            .unwrap()
            .iter()
            .any(|r| r.id == envelope_hash)
    }
}

/// Mounts the two reads the submit path makes before it sends.
async fn mount_pre_send(server: &MockServer, envelope: &SignedTestEnvelope) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(rpc_ok(get_network_result(TESTNET_PASSPHRASE)))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getLedgerEntries"})))
        .respond_with(rpc_ok_with_latest_ledger(
            envelope.ledger_entries_result(),
            SUBMISSION_LEDGER,
        ))
        .mount(server)
        .await;
}

/// Wraps a fixed result in a JSON-RPC envelope carrying the request's own id,
/// which the client requires.
fn rpc_ok(result: serde_json::Value) -> EchoIdResponder {
    EchoIdResponder::new(result)
}

/// A `getLedgerEntries` answer reporting `latest_ledger`, which is the ledger
/// the submission that follows is recorded against.
fn rpc_ok_with_latest_ledger(mut result: serde_json::Value, latest_ledger: u32) -> EchoIdResponder {
    if let Some(object) = result.as_object_mut() {
        object.insert("latestLedger".to_owned(), json!(latest_ledger));
    }
    rpc_ok(result)
}

async fn mount_send_pending(server: &MockServer, hash: &str) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(rpc_ok(json!({
            "hash": hash,
            "status": "PENDING",
            "latestLedger": 1_001,
            "latestLedgerCloseTime": "1699999999",
        })))
        .mount(server)
        .await;
}

async fn mount_get_not_found(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(rpc_ok(json!({
            "status": "NOT_FOUND",
            "latestLedger": 1_002,
            "oldestLedger": 1,
        })))
        .mount(server)
        .await;
}

/// A `TransactionResult` reporting `txINSUFFICIENT_FEE`, which is what a
/// definitive send-step refusal carries.
fn insufficient_fee_result_xdr() -> String {
    use stellar_xdr::{
        Limits, TransactionResult, TransactionResultExt, TransactionResultResult, WriteXdr,
    };
    TransactionResult {
        fee_charged: 0,
        result: TransactionResultResult::TxInsufficientFee,
        ext: TransactionResultExt::V0,
    }
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// A first submission against an empty store reaches `sendTransaction`.
///
/// The replay-identity check runs before the receipt is written, so it cannot
/// find the receipt this very submission is about to write. Swapping the two
/// makes this submission refuse itself.
#[tokio::test]
#[serial]
async fn a_first_submission_reaches_the_send() {
    let fx = fixture("record-first");
    let envelope = SignedTestEnvelope::for_source([0x21; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_send_pending(&server, envelope.tx_hash_hex()).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(rpc_ok(json!({
            "status": "SUCCESS",
            "latestLedger": 1_002,
            "ledger": 1_002,
        })))
        .mount(&server)
        .await;

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.recorder(&calls);
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let result = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(&recorder),
    )
    .await;

    assert!(
        result.is_ok(),
        "a first submission must reach the send and confirm: {result:?}"
    );
    let calls = calls.lock().unwrap().clone();
    assert_eq!(calls[0], Call::PreSend, "the record is written first");
    assert!(
        matches!(calls[1], Call::Outcome(SubmissionOutcome::Success { .. })),
        "a confirmed submission reports Success; got {calls:?}"
    );
}

/// Confirmation carries the applying ledger time through the recorder; a
/// missing close time keeps the debit pending even when the receipt succeeds.
#[tokio::test]
#[serial]
async fn submission_confirmation_dates_spend_only_from_created_at() {
    for created_at in [Some((now_ms() / 1000) as i64), None] {
        let fx = fixture("record-close-time");
        let envelope = SignedTestEnvelope::for_source([0x29; 32]);
        let server = MockServer::start().await;
        mount_pre_send(&server, &envelope).await;
        mount_send_pending(&server, envelope.tx_hash_hex()).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":"getTransaction"})))
            .respond_with(rpc_ok(json!({"status":"SUCCESS", "latestLedger":1002,
                "ledger":1002, "createdAt":created_at.map(|t| t.to_string())})))
            .mount(&server)
            .await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorder = fx.recorder(&calls);
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        submit_transaction_and_wait(
            &client,
            envelope.envelope_xdr(),
            SUBMIT_TIMEOUT,
            TESTNET_PASSPHRASE,
            None,
            Some(&recorder),
        )
        .await
        .unwrap();
        assert_eq!(
            fx.window.pending_reservations(&fx.profile).unwrap().len(),
            usize::from(created_at.is_none())
        );
        assert!(
            matches!(&calls.lock().unwrap()[1], Call::Outcome(SubmissionOutcome::Success { created_at: received, .. }) if *received == created_at)
        );
    }
}

/// A refusal before the send never writes a record: the endpoint identity
/// probe and the signature-binding check run first, and neither has sent
/// anything.
#[tokio::test]
#[serial]
async fn a_pre_send_refusal_writes_no_record() {
    let fx = fixture("record-refused");
    let envelope = SignedTestEnvelope::for_source([0x22; 32]);
    let server = MockServer::start().await;
    // The endpoint reports a network the caller did not declare.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(rpc_ok(get_network_result("Some Other Network ; 2015")))
        .mount(&server)
        .await;

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.recorder(&calls);
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let result = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(&recorder),
    )
    .await;

    assert!(
        result.is_err(),
        "a wrong endpoint must refuse the submission"
    );
    assert!(
        calls.lock().unwrap().is_empty(),
        "nothing was sent, so nothing is recorded: {:?}",
        calls.lock().unwrap()
    );
    assert!(
        fx.receipts
            .get(&envelope_hash(&envelope))
            .unwrap()
            .is_none(),
        "a refused submission leaves no receipt"
    );
}

/// A `latestLedger` that names no ledger is refused before the send: the
/// submission would be recorded against a ledger the retention guard cannot
/// check, so nothing is sent and nothing is recorded.
#[tokio::test]
#[serial]
async fn a_latest_ledger_that_names_no_ledger_refuses_before_the_send() {
    for latest_ledger in [json!(0), json!(u64::from(u32::MAX) + 1), json!(-1)] {
        let fx = fixture("record-latest-ledger");
        let envelope = SignedTestEnvelope::for_source([0x23; 32]);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({"method": "getNetwork"})))
            .respond_with(rpc_ok(get_network_result(TESTNET_PASSPHRASE)))
            .mount(&server)
            .await;
        let mut entries = envelope.ledger_entries_result();
        entries["latestLedger"] = latest_ledger.clone();
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({"method": "getLedgerEntries"})))
            .respond_with(rpc_ok(entries))
            .mount(&server)
            .await;
        mount_send_pending(&server, envelope.tx_hash_hex()).await;

        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorder = fx.recorder(&calls);
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let err = submit_transaction_and_wait(
            &client,
            envelope.envelope_xdr(),
            SUBMIT_TIMEOUT,
            TESTNET_PASSPHRASE,
            None,
            Some(&recorder),
        )
        .await
        .expect_err("a latestLedger that names no ledger must refuse");

        assert_eq!(
            err.code(),
            "network.rpc_response_malformed",
            "latestLedger {latest_ledger}: {err}"
        );
        assert_eq!(
            rpc_request_count(&server, "sendTransaction").await,
            0,
            "latestLedger {latest_ledger}: nothing is sent"
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "latestLedger {latest_ledger}: nothing is recorded: {:?}",
            calls.lock().unwrap()
        );
        let hash = envelope_hash(&envelope);
        assert!(
            fx.receipts.get(&hash).unwrap().is_none(),
            "latestLedger {latest_ledger}: no receipt"
        );
        assert!(
            !fx.reservation_is_open(&hash),
            "latestLedger {latest_ledger}: no reservation"
        );
    }
}

/// A submission the endpoint accepts and never confirms reports a timeout and
/// leaves everything it recorded standing.
#[tokio::test]
#[serial]
async fn a_timeout_reports_the_local_hash_and_leaves_the_record_standing() {
    let fx = fixture("record-timeout");
    let envelope = SignedTestEnvelope::for_source([0x23; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_send_pending(&server, envelope.tx_hash_hex()).await;
    mount_get_not_found(&server).await;

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.recorder(&calls);
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let err = tokio::time::timeout(
        TIMEOUT_OUTER_BOUND,
        submit_transaction_and_wait(
            &client,
            envelope.envelope_xdr(),
            TIMEOUT_DEADLINE,
            TESTNET_PASSPHRASE,
            None,
            Some(&recorder),
        ),
    )
    .await
    .expect("submission must finish within the outer timeout bound")
    .expect_err("a submission that never confirms must report a timeout");

    match &err {
        WalletError::Submission(SubmissionError::TxTimeout { tx_hash, .. }) => {
            assert_eq!(
                tx_hash,
                envelope.tx_hash_hex(),
                "the timeout carries the hash computed from the envelope, in full"
            );
        }
        other => panic!("expected submission.tx_timeout; got {other:?}"),
    }
    assert!(
        err.message().ends_with(
            "; its outcome is unknown: settle it by its transaction hash and do not resubmit"
        ),
        "the deadline exit names the recovery: {}",
        err.message()
    );

    let calls = calls.lock().unwrap().clone();
    assert_eq!(calls[0], Call::PreSend);
    assert!(
        matches!(&calls[1], Call::Outcome(SubmissionOutcome::Timeout { tx_hash }) if tx_hash == envelope.tx_hash_hex()),
        "a timeout reports Timeout; got {calls:?}"
    );

    let hash = envelope_hash(&envelope);
    let receipt = fx.receipts.get(&hash).unwrap().unwrap();
    assert_eq!(
        receipt.status,
        ReceiptStatus::Pending,
        "a timeout settles nothing"
    );
    assert!(receipt.submitted, "the bytes were sent");
    assert!(
        fx.reservation_is_open(&hash),
        "the reservation stands until reconciliation or an operator settles it"
    );
}

/// An endpoint reporting a hash that does not describe the transaction that
/// was sent leaves the record standing and reports both hashes.
#[tokio::test]
#[serial]
async fn a_hash_mismatch_reports_both_hashes_and_leaves_the_record_standing() {
    let fx = fixture("record-mismatch");
    let envelope = SignedTestEnvelope::for_source([0x24; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_send_pending(&server, &"9".repeat(64)).await;

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.recorder(&calls);
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let err = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(&recorder),
    )
    .await
    .expect_err("a hash that describes something else must be reported");

    match &err {
        WalletError::Submission(SubmissionError::HashMismatch { local, server }) => {
            assert_eq!(local, envelope.tx_hash_hex());
            assert_eq!(server, &"9".repeat(64));
        }
        other => panic!("expected submission.hash_mismatch; got {other:?}"),
    }

    let hash = envelope_hash(&envelope);
    assert_eq!(
        fx.receipts.get(&hash).unwrap().unwrap().status,
        ReceiptStatus::Pending,
        "the receipt stays keyed on the local hash and stays pending"
    );
    assert!(fx.reservation_is_open(&hash));
}

/// A send that never completes leaves the outcome unknown: the record stands
/// and the caller gets the timeout shape, which is what the recovery protocol
/// is written against.
///
/// The send happens exactly once. Under the pinned RPC client an HTTP 500 on
/// `sendTransaction` is a `TransactionSubmissionFailed` the retry classifier
/// does not retry, so the submit path's retry loop never re-sends it.
#[tokio::test]
#[serial]
async fn a_transport_failure_after_the_record_returns_the_timeout_shape() {
    let fx = fixture("record-transport");
    let envelope = SignedTestEnvelope::for_source([0x25; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .named("sendTransaction is sent exactly once")
        .mount(&server)
        .await;

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.recorder(&calls);
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let err = tokio::time::timeout(
        TIMEOUT_OUTER_BOUND,
        submit_transaction_and_wait(
            &client,
            envelope.envelope_xdr(),
            TIMEOUT_DEADLINE,
            TESTNET_PASSPHRASE,
            None,
            Some(&recorder),
        ),
    )
    .await
    .expect("submission must finish within the outer timeout bound")
    .expect_err("a send that never completes must report an unknown outcome");

    assert_eq!(
        err.code(),
        "submission.tx_timeout",
        "the layer cannot tell a refused connection from a lost response, so the outcome is \
         reported as unknown rather than as a failure"
    );

    let calls = calls.lock().unwrap().clone();
    assert_eq!(calls[0], Call::PreSend);
    assert!(
        matches!(
            calls[1],
            Call::Outcome(SubmissionOutcome::TransportAfterSend { .. })
        ),
        "a send that did not complete reports TransportAfterSend; got {calls:?}"
    );

    let hash = envelope_hash(&envelope);
    let receipt = fx.receipts.get(&hash).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Pending);
    assert!(
        receipt.submitted,
        "the bytes may have been transmitted, so the receipt is not abandonable"
    );
    assert!(
        fx.reservation_is_open(&hash),
        "nothing clears a reservation on a transport error"
    );
}

/// A definitive refusal at the send step moves no value: the reservation goes
/// back, the receipt records the failure, and the caller gets the refusal
/// itself rather than a timeout.
#[tokio::test]
#[serial]
async fn a_refused_send_releases_the_reservation_and_frees_the_sequence() {
    let fx = fixture("record-rejected");
    let envelope = SignedTestEnvelope::for_source([0x26; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(rpc_ok(json!({
            "status": "ERROR",
            "hash": envelope.tx_hash_hex(),
            "latestLedger": 1_001,
            "latestLedgerCloseTime": "1699999999",
            "errorResultXdr": insufficient_fee_result_xdr(),
        })))
        .mount(&server)
        .await;

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.recorder(&calls);
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let err = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(&recorder),
    )
    .await
    .expect_err("a definitively refused send must report the refusal");

    assert_eq!(
        err.code(),
        "submission.tx_malformed",
        "the network refused the bytes, which is not a timeout"
    );

    let calls = calls.lock().unwrap().clone();
    assert_eq!(calls[0], Call::PreSend);
    assert!(
        matches!(calls[1], Call::Outcome(SubmissionOutcome::Rejected { .. })),
        "a definitive refusal reports Rejected; got {calls:?}"
    );

    let hash = envelope_hash(&envelope);
    assert!(
        matches!(
            fx.receipts.get(&hash).unwrap().unwrap().status,
            ReceiptStatus::Failed { .. }
        ),
        "the receipt records the refusal"
    );
    assert!(
        !fx.reservation_is_open(&hash),
        "nothing was queued, so the reservation goes back"
    );

    // A rebuilt envelope at the same sequence is not refused as a duplicate:
    // the refused one can never apply.
    let rebuilt = SignedTestEnvelope::builder([0x26; 32])
        .amount_stroops(7_654_321)
        .build();
    assert_ne!(
        rebuilt.envelope_xdr(),
        envelope.envelope_xdr(),
        "the rebuilt envelope must differ, the way a rebuild makes it differ"
    );
    let calls2 = Arc::new(Mutex::new(Vec::new()));
    let retry = submit_transaction_and_wait(
        &client,
        rebuilt.envelope_xdr(),
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(&fx.recorder(&calls2)),
    )
    .await;
    assert_eq!(
        retry.as_ref().err().map(WalletError::code),
        Some("submission.tx_malformed"),
        "a refused send frees the sequence, so the retry reaches the network again and is \
         refused on its own terms: {retry:?}"
    );
}

/// A second submission for a sequence a pending receipt holds is refused
/// whatever bytes it carries: the fee moves with live fee stats, so the
/// envelope hash is not what makes a duplicate recognisable.
#[tokio::test]
#[serial]
async fn a_second_submission_at_a_pending_sequence_is_refused() {
    let fx = fixture("record-duplicate");
    let envelope = SignedTestEnvelope::for_source([0x27; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_send_pending(&server, envelope.tx_hash_hex()).await;
    mount_get_not_found(&server).await;

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.recorder(&calls);
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let first = tokio::time::timeout(
        TIMEOUT_OUTER_BOUND,
        submit_transaction_and_wait(
            &client,
            envelope.envelope_xdr(),
            TIMEOUT_DEADLINE,
            TESTNET_PASSPHRASE,
            None,
            Some(&recorder),
        ),
    )
    .await
    .expect("submission must finish within the outer timeout bound");
    assert_eq!(
        first
            .expect_err("the mocked endpoint never confirms")
            .code(),
        "submission.tx_timeout"
    );

    // A rebuilt envelope for the same intent: same source and sequence, a
    // different fee, and therefore different bytes.
    let rebuilt = SignedTestEnvelope::builder([0x27; 32])
        .amount_stroops(7_654_321)
        .build();
    assert_ne!(rebuilt.envelope_xdr(), envelope.envelope_xdr());

    let calls2 = Arc::new(Mutex::new(Vec::new()));
    let err = submit_transaction_and_wait(
        &client,
        rebuilt.envelope_xdr(),
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(&fx.recorder(&calls2)),
    )
    .await
    .expect_err("a second submission at a pending sequence must be refused");

    match &err {
        WalletError::Submission(SubmissionError::TxAlreadySubmitted { hash }) => {
            assert_eq!(
                hash,
                envelope.tx_hash_hex(),
                "the refusal names the transaction to reconcile"
            );
        }
        other => panic!("expected submission.tx_already_submitted; got {other:?}"),
    }
    assert_eq!(
        calls2.lock().unwrap().len(),
        1,
        "the refusal happens in pre_send, so no outcome is recorded"
    );
    assert!(
        fx.receipts.get(&envelope_hash(&rebuilt)).unwrap().is_none(),
        "a refused submission writes no receipt of its own"
    );
}

/// `SHA-256` over the signed envelope XDR, the key the receipt is stored
/// under.
fn envelope_hash(envelope: &SignedTestEnvelope) -> String {
    stellar_agent_network::envelope_hash_hex(envelope.envelope_xdr())
}

/// A reservation that cannot be written leaves nothing behind, and the retry
/// the refusal invites is admitted at the same sequence.
///
/// The refusal says nothing was sent, so a receipt left holding the pair would
/// make the retry refuse itself as a duplicate with no verb able to free it.
#[tokio::test]
#[serial]
async fn a_reservation_failure_unwinds_and_the_retry_is_admitted() {
    let fx = fixture("record-unwind-reservation");
    let envelope = SignedTestEnvelope::for_source([0x31; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(rpc_ok(
            json!({"hash": envelope.tx_hash_hex(), "status": "PENDING"}),
        ))
        .expect(0)
        .mount(&server)
        .await;

    let held = hold_window_lock(&fx.window_lock_path);

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.recorder(&calls);
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let result = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(&recorder),
    )
    .await;

    let err = result.expect_err("a reservation that cannot be written refuses the send");
    assert_eq!(
        err.code(),
        "submission.record_unavailable",
        "nothing was sent, and the refusal says so: {err:?}"
    );
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[Call::PreSend],
        "no outcome is reported for a submission that was never sent"
    );

    let envelope_hash = stellar_agent_network::envelope_hash_hex(envelope.envelope_xdr());
    assert!(
        fx.receipts.get(&envelope_hash).unwrap().is_none(),
        "the receipt for an unsent submission is removed"
    );
    assert!(
        fx.receipts
            .find_pending_by_source_sequence(envelope.source(), envelope.sequence())
            .unwrap()
            .is_none(),
        "the sequence is free for the retry the refusal invites"
    );

    // The retry, once the condition that refused it is gone.
    drop(held);
    let server2 = MockServer::start().await;
    mount_pre_send(&server2, &envelope).await;
    mount_send_pending(&server2, envelope.tx_hash_hex()).await;
    mount_get_not_found(&server2).await;
    let calls2 = Arc::new(Mutex::new(Vec::new()));
    let recorder2 = fx.recorder(&calls2);
    let client2 = StellarRpcClient::new(&server2.uri()).unwrap();
    let retry = tokio::time::timeout(
        TIMEOUT_OUTER_BOUND,
        submit_transaction_and_wait(
            &client2,
            envelope.envelope_xdr(),
            TIMEOUT_DEADLINE,
            TESTNET_PASSPHRASE,
            None,
            Some(&recorder2),
        ),
    )
    .await
    .expect("submission must finish within the outer timeout bound");

    let retry_err = retry.expect_err("the mocked endpoint never confirms");
    assert_eq!(
        retry_err.code(),
        "submission.tx_timeout",
        "the retry reaches the send: {retry_err:?}"
    );
    assert!(
        fx.reservation_is_open(&envelope_hash),
        "the retry takes the reservation the first attempt could not"
    );
}

/// A receipt that cannot be marked submitted refuses the send and unwinds the
/// same way.
///
/// `submitted` is the flag that says the bytes left. Setting it and then
/// failing would leave a receipt no operator verb can clear, for a transaction
/// the network never saw.
#[cfg(feature = "test-hooks")]
#[tokio::test]
#[serial]
async fn a_mark_submitted_failure_unwinds_and_sends_nothing() {
    use std::sync::atomic::Ordering;

    let fx = fixture("record-unwind-mark");
    let envelope = SignedTestEnvelope::for_source([0x32; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(rpc_ok(
            json!({"hash": envelope.tx_hash_hex(), "status": "PENDING"}),
        ))
        .expect(0)
        .mount(&server)
        .await;

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.recorder(&calls);
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    stellar_agent_network::submission_record::FAIL_MARK_SUBMITTED.store(true, Ordering::Release);
    let result = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(&recorder),
    )
    .await;
    stellar_agent_network::submission_record::FAIL_MARK_SUBMITTED.store(false, Ordering::Release);

    let err = result.expect_err("a receipt that cannot be marked submitted refuses the send");
    assert_eq!(err.code(), "submission.record_unavailable");
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[Call::PreSend],
        "no outcome is reported for a submission that was never sent"
    );

    let envelope_hash = stellar_agent_network::envelope_hash_hex(envelope.envelope_xdr());
    assert!(
        fx.receipts.get(&envelope_hash).unwrap().is_none(),
        "the receipt for an unsent submission is removed"
    );
    assert!(
        !fx.reservation_is_open(&envelope_hash),
        "the reservation the attempt took is released"
    );
    assert!(
        fx.receipts
            .find_pending_by_source_sequence(envelope.source(), envelope.sequence())
            .unwrap()
            .is_none(),
        "the sequence is free for the retry the refusal invites"
    );
}

/// A muxed transaction source reaches the send, with and without a recorder.
///
/// The mux id selects a sub-account for memo purposes; the sequence the
/// network enforces replay protection on belongs to the account beneath it,
/// which is what the replay identity reports.
#[tokio::test]
#[serial]
async fn a_muxed_source_reaches_the_send() {
    let fx = fixture("record-muxed");
    let envelope = SignedTestEnvelope::builder([0x33; 32])
        .muxed_source_id(42)
        .build();
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_send_pending(&server, envelope.tx_hash_hex()).await;
    mount_get_not_found(&server).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    // Without a recorder: the replay identity is read on every submission.
    let bare = tokio::time::timeout(
        TIMEOUT_OUTER_BOUND,
        submit_transaction_and_wait(
            &client,
            envelope.envelope_xdr(),
            TIMEOUT_DEADLINE,
            TESTNET_PASSPHRASE,
            None,
            None,
        ),
    )
    .await
    .expect("submission must finish within the outer timeout bound");
    let bare_err = bare.expect_err("the mocked endpoint never confirms");
    assert_eq!(
        bare_err.code(),
        "submission.tx_timeout",
        "a muxed source must not be refused before the send: {bare_err:?}"
    );

    // With one: the record is keyed on the underlying account.
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.recorder(&calls);
    let recorded = tokio::time::timeout(
        TIMEOUT_OUTER_BOUND,
        submit_transaction_and_wait(
            &client,
            envelope.envelope_xdr(),
            TIMEOUT_DEADLINE,
            TESTNET_PASSPHRASE,
            None,
            Some(&recorder),
        ),
    )
    .await
    .expect("submission must finish within the outer timeout bound");
    let recorded_err = recorded.expect_err("the mocked endpoint never confirms");
    assert_eq!(recorded_err.code(), "submission.tx_timeout");

    let envelope_hash = stellar_agent_network::envelope_hash_hex(envelope.envelope_xdr());
    let receipt = fx.receipts.get(&envelope_hash).unwrap().unwrap();
    assert_eq!(
        receipt.source,
        envelope.source(),
        "the receipt names the account beneath the mux id"
    );
    assert_eq!(receipt.sequence, envelope.sequence());
}

/// An unexpected `getTransaction` status after the send reports the timeout
/// shape, so the agent gets the hash it needs to reconcile.
///
/// The record is settled as an unknown outcome either way; what this pins is
/// that the caller is told which transaction to ask about.
#[tokio::test]
#[serial]
async fn an_unexpected_poll_status_reports_the_timeout_shape() {
    let fx = fixture("record-poll-status");
    let envelope = SignedTestEnvelope::for_source([0x34; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_send_pending(&server, envelope.tx_hash_hex()).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(rpc_ok(json!({
            "status": "SOMETHING_ELSE",
            "latestLedger": 1_002,
        })))
        .mount(&server)
        .await;

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.recorder(&calls);
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let result = tokio::time::timeout(
        TIMEOUT_OUTER_BOUND,
        submit_transaction_and_wait(
            &client,
            envelope.envelope_xdr(),
            TIMEOUT_DEADLINE,
            TESTNET_PASSPHRASE,
            None,
            Some(&recorder),
        ),
    )
    .await
    .expect("submission must finish within the outer timeout bound");

    let err = result.expect_err("an unexpected status is not a confirmation");
    assert_eq!(
        err.code(),
        "submission.tx_timeout",
        "the outcome is unknown, and the caller is told which transaction to ask about: {err:?}"
    );
    match &err {
        WalletError::Submission(SubmissionError::TxTimeout { tx_hash, .. }) => {
            assert_eq!(tx_hash, envelope.tx_hash_hex());
        }
        other => panic!("expected a timeout carrying the hash; got {other:?}"),
    }
    let calls = calls.lock().unwrap().clone();
    assert!(
        matches!(
            calls.last(),
            Some(Call::Outcome(SubmissionOutcome::TransportAfterSend { .. }))
        ),
        "the record is settled as an unknown outcome; got {calls:?}"
    );

    let envelope_hash = stellar_agent_network::envelope_hash_hex(envelope.envelope_xdr());
    assert!(
        fx.reservation_is_open(&envelope_hash),
        "an unknown outcome leaves the reservation standing"
    );
}

#[derive(Clone, Copy)]
enum AuditAppendFailure {
    Truncated,
    Rewritten,
    Io,
}

/// Drives a submission against an audit log that `failure` made unusable
/// after the writer opened it, and checks that the tip-anchor check before
/// the pending row refuses it: the refusal carries the code the condition
/// names, and nothing is written, not even a receipt file.
async fn assert_audit_append_refusal(failure: AuditAppendFailure) {
    use base64::Engine as _;
    use stellar_agent_core::audit_log::{
        AuditEntry, AuditWriter, NewToolInvocation, PolicyDecision,
    };

    let mut fx = fixture("record-audit-append");
    let audit_dir = fx._dir.path().join("audit");
    let audit_path = audit_dir.join("log.jsonl");
    fx.profile.audit_log_path = audit_path.clone();
    let coordinate = &fx.profile.audit_log_hash_chain_key_id;
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([4_u8; 32]))
        .unwrap();
    let access = stellar_agent_network::keyring::keyed_audit_access(
        &fx.profile,
        &fx.profile_name,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    )
    .unwrap();
    let mut writer = AuditWriter::open(audit_path.clone(), Some(access)).unwrap();
    writer
        .write_entry(AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "stellar_pay_commit",
            "stellar:testnet",
            Vec::new(),
            PolicyDecision::Allow,
            "audit-request",
        )))
        .unwrap();
    let original = std::fs::read(&audit_path).unwrap();
    // Where the log now lives, and the bytes it holds, which the refusal
    // must leave as they are.
    let (log_now, log_bytes) = match failure {
        AuditAppendFailure::Truncated => {
            std::fs::write(&audit_path, b"").unwrap();
            (audit_path.clone(), Vec::new())
        }
        AuditAppendFailure::Rewritten => {
            let mut changed = original.clone();
            let offset = changed
                .windows(b"audit-request".len())
                .position(|bytes| bytes == b"audit-request")
                .unwrap();
            changed[offset] = b'A';
            std::fs::write(&audit_path, &changed).unwrap();
            (audit_path.clone(), changed)
        }
        AuditAppendFailure::Io => {
            let held = fx._dir.path().join("held-audit");
            std::fs::rename(&audit_dir, &held).unwrap();
            std::fs::write(&audit_dir, b"a file cannot be traversed as a directory").unwrap();
            (held.join("log.jsonl"), original.clone())
        }
    };
    let audit = Arc::new(Mutex::new(writer));
    let recorder = WalletSubmissionRecorder::new(
        &fx.profile,
        fx.profile_name.clone(),
        "stellar_pay_commit",
        Some("stellar:testnet".to_owned()),
        stellar_agent_core::audit_log::PolicyDecision::Allow,
        Vec::new(),
        vec![entry(&fx.profile_name, now_ms(), 500)],
        fx.receipts.clone(),
        fx.window.clone(),
        Some(audit),
        None,
        "test-request",
        now_ms(),
    );
    let envelope = SignedTestEnvelope::for_source([0x62; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let error = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(&recorder),
    )
    .await
    .expect_err("an unusable audit log refuses before the send");
    match failure {
        AuditAppendFailure::Truncated | AuditAppendFailure::Rewritten => {
            let reason = match failure {
                AuditAppendFailure::Truncated => "the log is shorter than the writer's last append",
                _ => "the entry at the writer's last append is not the one it wrote",
            };
            assert_eq!(error.code(), "audit.tip_anchor_mismatch", "{error:?}");
            let WalletError::Validation(
                stellar_agent_core::error::ValidationError::AuditTipAnchorMismatch {
                    profile,
                    reason: actual,
                },
            ) = &error
            else {
                panic!("typed audit refusal: {error:?}")
            };
            assert_eq!(actual, reason);
            assert_eq!(profile, &fx.profile_name);
            assert!(error.message().contains("stellar-agent audit reanchor"));
        }
        AuditAppendFailure::Io => {
            assert_eq!(error.code(), "submission.record_unavailable", "{error:?}");
            assert!(
                error
                    .message()
                    .contains("the audit log is not ready for the pending value-action row"),
                "{error:?}"
            );
        }
    }
    assert!(
        !fx.receipts.file_path().unwrap().exists(),
        "the refusal comes before the receipt gate, so no receipt file is written"
    );
    let hash = stellar_agent_network::envelope_hash_hex(envelope.envelope_xdr());
    assert!(fx.receipts.get(&hash).unwrap().is_none());
    assert!(!fx.reservation_is_open(&hash));
    assert_eq!(
        std::fs::read(&log_now).unwrap(),
        log_bytes,
        "no row is written"
    );
}

#[tokio::test]
#[serial]
async fn a_truncated_audit_log_refuses_with_the_rollback_code_before_the_receipt() {
    assert_audit_append_refusal(AuditAppendFailure::Truncated).await;
}

#[tokio::test]
#[serial]
async fn a_rewritten_audit_log_refuses_with_the_rollback_code_before_the_receipt() {
    assert_audit_append_refusal(AuditAppendFailure::Rewritten).await;
}

#[tokio::test]
#[serial]
async fn an_untraversable_audit_directory_refuses_as_record_unavailable_before_the_receipt() {
    assert_audit_append_refusal(AuditAppendFailure::Io).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// The audit tip anchor covers the pending row
// ─────────────────────────────────────────────────────────────────────────────

/// The refusal sentence of the tip-anchor check before the pending row.
const BEFORE_ROW: &str = "the audit log is not ready for the pending value-action row";

/// The refusal sentence of the tip-anchor check right after the pending row.
const AFTER_ROW: &str = "the pending value-action row is not covered by the audit tip anchor";

/// A keyed audit writer for `fx` whose tip anchor lives in `store`, so a test
/// scripts which anchor writes fail.
fn anchored_audit(
    fx: &mut Fixture,
    store: &Arc<InMemoryTipAnchorStore>,
) -> Arc<Mutex<AuditWriter>> {
    let audit_path = fx._dir.path().join("audit").join("log.jsonl");
    fx.profile.audit_log_path = audit_path.clone();
    let access = KeyedAuditAccess::new(
        zeroize::Zeroizing::new([0x6a; 32]),
        Arc::clone(store) as Arc<dyn TipAnchorStore>,
    );
    Arc::new(Mutex::new(
        AuditWriter::open(audit_path, Some(access)).unwrap(),
    ))
}

impl Fixture {
    /// A recorder that writes through `audit` and takes no reservation, as a
    /// policy without a stateful criterion does.
    fn unwindowed_recorder<'a>(
        &'a self,
        calls: &Arc<Mutex<Vec<Call>>>,
        audit: Arc<Mutex<AuditWriter>>,
    ) -> RecordingRecorder<'a> {
        RecordingRecorder {
            inner: WalletSubmissionRecorder::new(
                &self.profile,
                self.profile_name.clone(),
                "stellar_pay_commit",
                Some("stellar:testnet".to_owned()),
                stellar_agent_core::audit_log::PolicyDecision::Allow,
                Vec::new(),
                Vec::new(),
                self.receipts.clone(),
                self.window.clone(),
                Some(audit),
                None,
                "test-request",
                now_ms(),
            ),
            calls: Arc::clone(calls),
        }
    }
}

/// An audit row that names no submission.
fn unrelated_row(request_id: &str) -> AuditEntry {
    AuditEntry::new_tool_invocation(NewToolInvocation::new(
        "stellar_balance",
        "stellar:testnet",
        Vec::new(),
        stellar_agent_core::audit_log::PolicyDecision::Allow,
        request_id,
    ))
}

/// A consent row, the only kind the audit outbox queues.
fn consent_row(request_id: &str) -> AuditEntry {
    AuditEntry::new_approval_attested(
        "PaymentSimulated",
        "stellar_pay_commit",
        None,
        "ABCDEFGHIJKLMNOPQRSTUV",
        "cli",
        request_id,
    )
}

/// Mounts a `sendTransaction` answer that must never be asked for.
async fn mount_no_send(server: &MockServer, envelope: &SignedTestEnvelope) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(rpc_ok(
            json!({"hash": envelope.tx_hash_hex(), "status": "PENDING"}),
        ))
        .expect(0)
        .named("nothing is sent")
        .mount(server)
        .await;
}

/// Mounts the reads, one accepted send, and a confirmation.
async fn mount_confirmed_send(server: &MockServer, envelope: &SignedTestEnvelope) {
    mount_pre_send(server, envelope).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(rpc_ok(json!({
            "hash": envelope.tx_hash_hex(),
            "status": "PENDING",
            "latestLedger": 1_001,
            "latestLedgerCloseTime": "1699999999",
        })))
        .expect(1)
        .named("one send")
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(rpc_ok(json!({
            "status": "SUCCESS",
            "latestLedger": 1_002,
            "ledger": 1_002,
        })))
        .mount(server)
        .await;
}

/// Submits `envelope` through `recorder` against `server`.
async fn submit(
    server: &MockServer,
    envelope: &SignedTestEnvelope,
    recorder: &RecordingRecorder<'_>,
) -> Result<stellar_agent_network::submit::SubmissionResult, WalletError> {
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(recorder),
    )
    .await
}

/// The kinds of the verified rows that name `envelope_hash`, in log order.
fn kinds_for(audit: &Arc<Mutex<AuditWriter>>, envelope_hash: &str) -> Vec<EventKind> {
    verified_audit_entries(audit)
        .into_iter()
        .filter(|entry| entry.envelope_hash.as_deref() == Some(envelope_hash))
        .map(|entry| entry.event_kind)
        .collect()
}

/// The failure code of a `value_action_failed` row, or `None` for any other
/// kind.
fn failed_code(kind: &EventKind) -> Option<&str> {
    match kind {
        EventKind::ValueActionFailed { code, .. } => Some(code.as_str()),
        _ => None,
    }
}

/// A tip anchor left behind and still unwritable refuses the submission
/// before anything for it is written: no receipt file, no row, no
/// reservation, and nothing sent.
#[tokio::test]
#[serial]
async fn an_anchor_behind_before_the_pending_row_refuses_with_nothing_written() {
    let mut fx = fixture("record-anchor-before");
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let audit = anchored_audit(&mut fx, &store);
    // An unrelated row's anchor write and its immediate retry fail, which
    // leaves the anchor behind; the third failure is the repair the check
    // before the pending row attempts.
    store.fail_next_writes(3);
    audit
        .lock()
        .unwrap()
        .write_entry(unrelated_row("before-row"))
        .unwrap();
    let log_bytes = std::fs::read(&fx.profile.audit_log_path).unwrap();

    let envelope = SignedTestEnvelope::for_source([0x63; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_no_send(&server, &envelope).await;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.capped_recorder(&calls, Arc::clone(&audit), 500, 1_000_000);
    let error = submit(&server, &envelope, &recorder)
        .await
        .expect_err("a tip anchor that cannot be repaired refuses the send");

    assert_eq!(error.code(), "submission.record_unavailable", "{error:?}");
    assert!(error.message().contains(BEFORE_ROW), "{error:?}");
    assert!(
        error.message().contains("audit.tip_anchor_unavailable"),
        "the refusal names the anchor condition: {error:?}"
    );
    assert_eq!(calls.lock().unwrap().as_slice(), &[Call::PreSend]);
    assert!(
        !fx.receipts.file_path().unwrap().exists(),
        "no receipt file is written"
    );
    assert_eq!(
        std::fs::read(&fx.profile.audit_log_path).unwrap(),
        log_bytes,
        "no row is written"
    );
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty(),
        "no reservation is taken"
    );
}

/// A pending row the tip anchor does not cover is closed, its reservation
/// released, and its receipt removed, and nothing is sent.
///
/// The pending row's anchor write, its immediate retry, and the repair under
/// the guard right after the row all fail. The reservation's duplicate check
/// has passed by then, so the row and the reservation are this submission's.
/// The closing row is a plain append: it repairs the anchor for the pending
/// row first and then anchors itself.
#[tokio::test]
#[serial]
async fn an_uncovered_pending_row_is_closed_and_its_reservation_released() {
    let mut fx = fixture("record-anchor-after");
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let audit = anchored_audit(&mut fx, &store);
    let envelope = SignedTestEnvelope::for_source([0x64; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_no_send(&server, &envelope).await;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.capped_recorder(&calls, Arc::clone(&audit), 500, 1_000_000);
    store.fail_next_writes(3);
    let error = submit(&server, &envelope, &recorder)
        .await
        .expect_err("a pending row the anchor does not cover refuses the send");

    assert_eq!(error.code(), "submission.record_unavailable", "{error:?}");
    assert!(error.message().contains(AFTER_ROW), "{error:?}");
    assert!(
        error.message().contains("audit.tip_anchor_unavailable"),
        "{error:?}"
    );
    assert_eq!(calls.lock().unwrap().as_slice(), &[Call::PreSend]);
    let hash = envelope_hash(&envelope);
    assert!(
        fx.receipts.get(&hash).unwrap().is_none(),
        "the receipt is removed"
    );
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty(),
        "the reservation is released"
    );
    let kinds = kinds_for(&audit, &hash);
    assert_eq!(kinds.len(), 2, "{kinds:?}");
    assert!(
        matches!(kinds[0], EventKind::ValueActionPending { .. }),
        "{kinds:?}"
    );
    assert_eq!(
        failed_code(&kinds[1]),
        Some("submission.record_unavailable"),
        "the closing row carries the refusal's code: {kinds:?}"
    );
    let anchored: Vec<u64> = store.writes().iter().map(|a| a.entry_count).collect();
    assert_eq!(
        anchored,
        vec![1, 2, 3],
        "the open anchors the boundary row; the closing append repairs the pending \
         row's anchor, then anchors itself"
    );
}

/// Without window entries a pending row the tip anchor does not cover is
/// closed and its receipt removed.
///
/// The receipt gate recorded a new receipt, so no other receipt carries the
/// hash when the row is closed.
#[tokio::test]
#[serial]
async fn an_uncovered_pending_row_without_window_entries_is_closed() {
    let mut fx = fixture("record-anchor-unwindowed");
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let audit = anchored_audit(&mut fx, &store);
    let envelope = SignedTestEnvelope::for_source([0x65; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_no_send(&server, &envelope).await;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.unwindowed_recorder(&calls, Arc::clone(&audit));
    store.fail_next_writes(3);
    let error = submit(&server, &envelope, &recorder)
        .await
        .expect_err("a pending row the anchor does not cover refuses the send");

    assert_eq!(error.code(), "submission.record_unavailable", "{error:?}");
    assert!(error.message().contains(AFTER_ROW), "{error:?}");
    assert_eq!(calls.lock().unwrap().as_slice(), &[Call::PreSend]);
    let hash = envelope_hash(&envelope);
    assert!(
        fx.receipts.file_path().unwrap().exists(),
        "the receipt gate recorded a receipt"
    );
    assert!(
        fx.receipts.get(&hash).unwrap().is_none(),
        "the receipt is removed"
    );
    let kinds = kinds_for(&audit, &hash);
    assert_eq!(kinds.len(), 2, "{kinds:?}");
    assert!(
        matches!(kinds[0], EventKind::ValueActionPending { .. }),
        "{kinds:?}"
    );
    assert_eq!(
        failed_code(&kinds[1]),
        Some("submission.record_unavailable"),
        "{kinds:?}"
    );
}

/// The repair under the guard right after the pending row lets the
/// submission proceed when it succeeds: the row is covered, one send goes
/// out, and no closing row is written.
#[tokio::test]
#[serial]
async fn a_pending_row_covered_by_the_repair_after_it_is_sent() {
    let mut fx = fixture("record-anchor-repaired");
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let audit = anchored_audit(&mut fx, &store);
    let envelope = SignedTestEnvelope::for_source([0x66; 32]);
    let server = MockServer::start().await;
    mount_confirmed_send(&server, &envelope).await;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.capped_recorder(&calls, Arc::clone(&audit), 500, 1_000_000);
    // The pending row's anchor write and its immediate retry fail; the
    // repair right after the row succeeds.
    store.fail_next_writes(2);
    let result = submit(&server, &envelope, &recorder).await;
    assert!(
        result.is_ok(),
        "the repaired anchor lets the send proceed: {result:?}"
    );

    let hash = envelope_hash(&envelope);
    let kinds = kinds_for(&audit, &hash);
    assert_eq!(kinds.len(), 2, "{kinds:?}");
    assert!(
        matches!(kinds[0], EventKind::ValueActionPending { .. }),
        "{kinds:?}"
    );
    assert!(
        matches!(kinds[1], EventKind::ValueActionSubmitted { .. }),
        "no closing row precedes the outcome: {kinds:?}"
    );
}

/// A reservation the window refuses for a reason other than a duplicate keeps
/// its own refusal and code when the anchor check also failed, and the row is
/// closed under that code.
#[tokio::test]
#[serial]
async fn a_policy_refusal_at_the_reservation_outranks_an_uncovered_pending_row() {
    let mut fx = fixture("record-anchor-denied");
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let audit = anchored_audit(&mut fx, &store);
    let envelope = SignedTestEnvelope::for_source([0x67; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_no_send(&server, &envelope).await;
    let calls = Arc::new(Mutex::new(Vec::new()));
    // 600 against a cap of 500: the reservation write refuses.
    let recorder = fx.capped_recorder(&calls, Arc::clone(&audit), 600, 500);
    store.fail_next_writes(3);
    let error = submit(&server, &envelope, &recorder)
        .await
        .expect_err("the window cannot admit this submission");

    assert_eq!(
        error.code(),
        "policy.deny.per_period_cap_exceeded",
        "{error:?}"
    );
    assert_eq!(calls.lock().unwrap().as_slice(), &[Call::PreSend]);
    let hash = envelope_hash(&envelope);
    assert!(fx.receipts.get(&hash).unwrap().is_none());
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty(),
        "the refused reservation holds nothing"
    );
    let kinds = kinds_for(&audit, &hash);
    assert_eq!(kinds.len(), 2, "{kinds:?}");
    assert_eq!(
        failed_code(&kinds[1]),
        Some("policy.deny.per_period_cap_exceeded"),
        "{kinds:?}"
    );
}

/// Submits with one consent row queued in the audit outbox and `failures`
/// scripted anchor-write failures, and returns the result with the kinds of
/// every verified row.
///
/// The pending row's append drains the queued row first. Its anchor write
/// and retry fail twice, the pending row's own pre-append retry once, its
/// anchor write and retry twice, and the repair right after the row once:
/// six failures reach the refusal, and with five the repair succeeds.
async fn submit_after_a_queued_outbox_row(
    name: &str,
    seed: u8,
    failures: usize,
) -> (
    Result<stellar_agent_network::submit::SubmissionResult, WalletError>,
    Vec<EventKind>,
) {
    let mut fx = fixture(name);
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let audit = anchored_audit(&mut fx, &store);
    AuditOutbox::for_log(&fx.profile.audit_log_path, store.clone())
        .append(&consent_row("queued-consent"))
        .unwrap();
    let envelope = SignedTestEnvelope::for_source([seed; 32]);
    let server = MockServer::start().await;
    if failures >= 6 {
        mount_pre_send(&server, &envelope).await;
        mount_no_send(&server, &envelope).await;
    } else {
        mount_confirmed_send(&server, &envelope).await;
    }
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.capped_recorder(&calls, Arc::clone(&audit), 500, 1_000_000);
    store.fail_next_writes(failures);
    let result = submit(&server, &envelope, &recorder).await;
    let kinds = verified_audit_entries(&audit)
        .into_iter()
        .map(|entry| entry.event_kind)
        .collect();
    (result, kinds)
}

/// An outbox row the pending append drains ahead of the row is covered by the
/// check right after the row too: six failed anchor writes refuse the send.
#[tokio::test]
#[serial]
async fn a_drained_outbox_row_left_uncovered_refuses_the_send() {
    let (result, kinds) =
        submit_after_a_queued_outbox_row("record-anchor-drain-refused", 0x68, 6).await;
    let error = result.expect_err("six failed anchor writes leave the rows uncovered");
    assert_eq!(error.code(), "submission.record_unavailable", "{error:?}");
    assert!(error.message().contains(AFTER_ROW), "{error:?}");
    assert_eq!(kinds.len(), 4, "{kinds:?}");
    assert!(
        matches!(kinds[0], EventKind::AuditEntryTagsStarted { .. }),
        "the open appends the boundary row: {kinds:?}"
    );
    assert!(
        matches!(kinds[1], EventKind::ApprovalAttested { .. }),
        "the queued row lands first after the boundary: {kinds:?}"
    );
    assert!(
        matches!(kinds[2], EventKind::ValueActionPending { .. }),
        "{kinds:?}"
    );
    assert_eq!(
        failed_code(&kinds[3]),
        Some("submission.record_unavailable"),
        "{kinds:?}"
    );
}

/// With one failure fewer the repair right after the row covers both the
/// drained row and the pending row, and the send proceeds.
#[tokio::test]
#[serial]
async fn a_drained_outbox_row_covered_by_the_repair_lets_the_send_proceed() {
    let (result, kinds) =
        submit_after_a_queued_outbox_row("record-anchor-drain-repaired", 0x69, 5).await;
    assert!(result.is_ok(), "the repair covers both rows: {result:?}");
    assert_eq!(kinds.len(), 4, "{kinds:?}");
    assert!(
        matches!(kinds[1], EventKind::ApprovalAttested { .. }),
        "{kinds:?}"
    );
    assert!(
        matches!(kinds[2], EventKind::ValueActionPending { .. }),
        "{kinds:?}"
    );
    assert!(
        matches!(kinds[3], EventKind::ValueActionSubmitted { .. }),
        "{kinds:?}"
    );
}

/// A pending row that cannot be appended after the tip-anchor check passed
/// refuses the send and removes the receipt the gate recorded; no row and no
/// reservation exist.
///
/// A complete outbox line past the recorded commitment refuses the drain the
/// append runs first, and the check before the row reads no outbox.
#[tokio::test]
#[serial]
async fn a_pending_row_append_failure_after_the_anchor_check_unwinds_the_receipt() {
    let mut fx = fixture("record-anchor-append");
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let audit = anchored_audit(&mut fx, &store);
    let outbox = AuditOutbox::for_log(&fx.profile.audit_log_path, store.clone());
    std::fs::write(outbox.path(), b"not an audit entry\n").unwrap();
    let envelope = SignedTestEnvelope::for_source([0x6b; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_no_send(&server, &envelope).await;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.capped_recorder(&calls, Arc::clone(&audit), 500, 1_000_000);
    let error = submit(&server, &envelope, &recorder)
        .await
        .expect_err("a pending row that cannot be appended refuses the send");

    assert_eq!(error.code(), "submission.record_unavailable", "{error:?}");
    assert!(
        error
            .message()
            .contains("the pending value-action row could not be appended"),
        "{error:?}"
    );
    assert!(
        error.message().contains("audit.outbox_rows_missing"),
        "{error:?}"
    );
    assert_eq!(calls.lock().unwrap().as_slice(), &[Call::PreSend]);
    let hash = envelope_hash(&envelope);
    assert!(
        fx.receipts.file_path().unwrap().exists(),
        "the receipt gate recorded a receipt"
    );
    assert!(
        fx.receipts.get(&hash).unwrap().is_none(),
        "the receipt is removed"
    );
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty()
    );
    let kinds: Vec<EventKind> = verified_audit_entries(&audit)
        .into_iter()
        .map(|entry| entry.event_kind)
        .collect();
    assert!(
        matches!(kinds.as_slice(), [EventKind::AuditEntryTagsStarted { .. }]),
        "no row is written past the boundary row: {kinds:?}"
    );
}

/// A second submission the window can no longer admit is refused at the
/// reservation, under the policy code the gate reports for the same reason.
///
/// Both recorders carry entries a gate admitted against the state each read.
/// The reservation write is where the second one meets the first one's open
/// hold, and the refusal unwinds the way every other pre-send refusal does:
/// the receipt goes, the pending row is closed out, the sequence is free, and
/// nothing reaches the endpoint.
#[tokio::test]
#[serial]
async fn a_reservation_the_window_cannot_admit_is_refused_as_a_policy_denial() {
    use base64::Engine as _;
    use stellar_agent_core::audit_log::AuditWriter;
    use stellar_agent_core::audit_log::reader::{
        ValueActionSettlement, try_value_action_settlement,
    };
    use stellar_agent_core::audit_log::schema::EventKind;
    use stellar_agent_core::audit_log::test_helpers::verified_audit_entries_from_path;

    let mut fx = fixture("record-admission");
    let audit_path = fx._dir.path().join("audit").join("log.jsonl");
    fx.profile.audit_log_path = audit_path.clone();
    let coordinate = &fx.profile.audit_log_hash_chain_key_id;
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]))
        .unwrap();
    let access = stellar_agent_network::keyring::keyed_audit_access(
        &fx.profile,
        &fx.profile_name,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    )
    .unwrap();
    let audit = Arc::new(Mutex::new(
        AuditWriter::open(audit_path.clone(), Some(access)).unwrap(),
    ));

    // The first submission reaches the send and is never confirmed, so its
    // reservation stands and holds 600 of the 1000-stroop cap.
    let first = SignedTestEnvelope::for_source([0x41; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &first).await;
    mount_send_pending(&server, first.tx_hash_hex()).await;
    mount_get_not_found(&server).await;
    let first_calls = Arc::new(Mutex::new(Vec::new()));
    let first_recorder = fx.capped_recorder(&first_calls, Arc::clone(&audit), 600, 1_000);
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let first_result = tokio::time::timeout(
        TIMEOUT_OUTER_BOUND,
        submit_transaction_and_wait(
            &client,
            first.envelope_xdr(),
            TIMEOUT_DEADLINE,
            TESTNET_PASSPHRASE,
            None,
            Some(&first_recorder),
        ),
    )
    .await
    .expect("submission must finish within the outer timeout bound");
    assert_eq!(
        first_result
            .expect_err("the mocked endpoint never confirms")
            .code(),
        "submission.tx_timeout",
        "the first submission reaches the send"
    );
    assert!(fx.reservation_is_open(&envelope_hash(&first)));

    // The second submission was admissible against the state its gate read,
    // and 600 + 600 no longer fits the cap.
    let second = SignedTestEnvelope::for_source([0x42; 32]);
    let second_server = MockServer::start().await;
    mount_pre_send(&second_server, &second).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(rpc_ok(
            json!({"hash": second.tx_hash_hex(), "status": "PENDING"}),
        ))
        .expect(0)
        .mount(&second_server)
        .await;

    let second_calls = Arc::new(Mutex::new(Vec::new()));
    let second_recorder = fx.capped_recorder(&second_calls, Arc::clone(&audit), 600, 1_000);
    let second_client = StellarRpcClient::new(&second_server.uri()).unwrap();
    let refused = submit_transaction_and_wait(
        &second_client,
        second.envelope_xdr(),
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(&second_recorder),
    )
    .await
    .expect_err("the window can no longer admit this submission");

    assert_eq!(
        refused.code(),
        "policy.deny.per_period_cap_exceeded",
        "the refusal names the code the gate names for the same reason: {refused:?}"
    );
    match &refused {
        WalletError::PolicyDenied { reason } => match reason.as_ref() {
            stellar_agent_core::policy::DenyReason::PerPeriodCapExceeded {
                max_stroops,
                attempted_stroops,
                period_used_stroops,
                ..
            } => {
                assert_eq!(*max_stroops, 1_000);
                assert_eq!(*attempted_stroops, 600);
                assert_eq!(*period_used_stroops, 600);
            }
            other => panic!("expected PerPeriodCapExceeded, got {other:?}"),
        },
        other => panic!("expected a typed policy denial, got {other:?}"),
    }

    assert_eq!(
        second_calls.lock().unwrap().as_slice(),
        &[Call::PreSend],
        "no outcome is reported for a submission that was never sent"
    );
    let second_hash = envelope_hash(&second);
    assert!(
        fx.receipts.get(&second_hash).unwrap().is_none(),
        "the receipt for the refused submission is removed"
    );
    assert!(
        fx.receipts
            .find_pending_by_source_sequence(second.source(), second.sequence())
            .unwrap()
            .is_none(),
        "the sequence the refused submission would have consumed is free"
    );
    assert!(
        !fx.reservation_is_open(&second_hash),
        "the refused submission holds no reservation"
    );
    assert_eq!(
        fx.window.pending_reservations(&fx.profile).unwrap().len(),
        1,
        "only the admitted submission's reservation stands"
    );
    drop(first_recorder);
    drop(second_recorder);
    assert!(
        matches!(
            try_value_action_settlement(&audit.lock().unwrap(), &second_hash).unwrap(),
            ValueActionSettlement::Settled
        ),
        "the pending row the refused submission wrote is closed out"
    );
    drop(audit);
    // The row that closes the pending row names the refusal that stopped the
    // submission, so the audit log records a cap refusal as the policy denial
    // it is.
    let closing_code = verified_audit_entries_from_path(&audit_path)
        .into_iter()
        .find_map(|entry| {
            if entry.envelope_hash.as_deref() != Some(second_hash.as_str()) {
                return None;
            }
            match entry.event_kind {
                EventKind::ValueActionFailed { code, .. } => Some(code),
                _ => None,
            }
        })
        .expect("the closing row for the refused submission");
    assert_eq!(
        closing_code, "policy.deny.per_period_cap_exceeded",
        "the closing audit row carries the refusal's own code"
    );
}

/// A resend of bytes whose receipt was lost is refused before the send and
/// writes no row.
///
/// The receipt gate admits the resend because the receipt is gone, but the
/// window file still holds the original's reservation under the same envelope
/// hash. The resend is refused with the transaction to reconcile, before its
/// pending row: the original's pending row stays owed, so the settled row its
/// own reconciliation writes is the one that closes it. The cap is far above
/// both amounts, so admission does not decide this.
#[tokio::test]
#[serial]
async fn a_resend_after_a_lost_receipt_is_refused_before_the_send() {
    use base64::Engine as _;
    use stellar_agent_core::audit_log::AuditWriter;
    use stellar_agent_core::audit_log::reader::{
        ValueActionSettlement, try_value_action_settlement,
    };
    use stellar_agent_core::audit_log::schema::EventKind;
    use stellar_agent_core::audit_log::test_helpers::verified_audit_entries_from_path;

    let mut fx = fixture("record-resend");
    let audit_path = fx._dir.path().join("audit").join("log.jsonl");
    fx.profile.audit_log_path = audit_path.clone();
    let coordinate = &fx.profile.audit_log_hash_chain_key_id;
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([8_u8; 32]))
        .unwrap();
    let access = stellar_agent_network::keyring::keyed_audit_access(
        &fx.profile,
        &fx.profile_name,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    )
    .unwrap();
    let audit = Arc::new(Mutex::new(
        AuditWriter::open(audit_path.clone(), Some(access)).unwrap(),
    ));

    // The original reaches the send and is never confirmed.
    let original = SignedTestEnvelope::for_source([0x43; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &original).await;
    mount_send_pending(&server, original.tx_hash_hex()).await;
    mount_get_not_found(&server).await;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.capped_recorder(&calls, Arc::clone(&audit), 600, 1_000_000);
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let first = tokio::time::timeout(
        TIMEOUT_OUTER_BOUND,
        submit_transaction_and_wait(
            &client,
            original.envelope_xdr(),
            TIMEOUT_DEADLINE,
            TESTNET_PASSPHRASE,
            None,
            Some(&recorder),
        ),
    )
    .await
    .expect("submission must finish within the outer timeout bound");
    assert_eq!(
        first
            .expect_err("the mocked endpoint never confirms")
            .code(),
        "submission.tx_timeout"
    );
    let hash = envelope_hash(&original);

    // The receipt is lost; the reservation stands.
    std::fs::remove_file(fx.receipts.file_path().unwrap()).unwrap();
    assert!(fx.receipts.get(&hash).unwrap().is_none());
    assert!(fx.reservation_is_open(&hash));

    let resend_server = MockServer::start().await;
    mount_pre_send(&resend_server, &original).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(rpc_ok(
            json!({"hash": original.tx_hash_hex(), "status": "PENDING"}),
        ))
        .expect(0)
        .named("the resend is refused before the send")
        .mount(&resend_server)
        .await;
    let resend_calls = Arc::new(Mutex::new(Vec::new()));
    let resend_recorder = fx.capped_recorder(&resend_calls, Arc::clone(&audit), 600, 1_000_000);
    let resend_client = StellarRpcClient::new(&resend_server.uri()).unwrap();
    let refused = submit_transaction_and_wait(
        &resend_client,
        original.envelope_xdr(),
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(&resend_recorder),
    )
    .await
    .expect_err("a resend of bytes the window holds must be refused");

    match &refused {
        WalletError::Submission(SubmissionError::TxAlreadySubmitted { hash: tx_hash }) => {
            assert_eq!(
                tx_hash,
                original.tx_hash_hex(),
                "the refusal names the transaction"
            );
        }
        other => panic!("expected submission.tx_already_submitted; got {other:?}"),
    }
    assert_eq!(
        resend_calls.lock().unwrap().as_slice(),
        &[Call::PreSend],
        "the refusal happens in pre_send"
    );
    assert!(
        fx.receipts.get(&hash).unwrap().is_none(),
        "the refused resend leaves no receipt of its own"
    );
    assert_eq!(
        fx.window.pending_reservations(&fx.profile).unwrap().len(),
        1,
        "the bytes are counted once"
    );

    drop(recorder);
    drop(resend_recorder);
    assert!(
        matches!(
            try_value_action_settlement(&audit.lock().unwrap(), &hash).unwrap(),
            ValueActionSettlement::Owed(_)
        ),
        "the original's settlement stays owed"
    );
    drop(audit);
    let rows: Vec<EventKind> = verified_audit_entries_from_path(&audit_path)
        .into_iter()
        .filter(|entry| entry.envelope_hash.as_deref() == Some(hash.as_str()))
        .map(|entry| entry.event_kind)
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "only the original's pending row names the bytes: {rows:?}"
    );
    assert!(
        matches!(rows[0], EventKind::ValueActionPending { .. }),
        "{rows:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The submission deadline bounds the confirmation poll
// ─────────────────────────────────────────────────────────────────────────────

/// The hang every held-open request below uses: far past the deadline, so a
/// request left to run would overrun it by seconds.
const HANG: Duration = Duration::from_secs(10);

/// What a deadline exit may add to the deadline: the timeout record and
/// scheduling. Smaller than the one-second overrun of an unclamped
/// two-second poll sleep.
const DEADLINE_MARGIN: Duration = Duration::from_millis(500);

/// Answers like `inner`, after `delay`.
struct Delayed<R> {
    inner: R,
    delay: Duration,
}

impl<R: wiremock::Respond> wiremock::Respond for Delayed<R> {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        self.inner.respond(request).set_delay(self.delay)
    }
}

/// Submits `envelope` under [`TIMEOUT_DEADLINE`] against `server`, which must
/// answer the reads before the send and the send itself, and checks that the
/// submission ended at the deadline with the timeout outcome and its record
/// standing.
async fn assert_timeout_at_the_deadline(
    fx: &Fixture,
    envelope: &SignedTestEnvelope,
    server: &MockServer,
) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = fx.recorder(&calls);
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let started = std::time::Instant::now();
    let err = tokio::time::timeout(
        HANG,
        submit_transaction_and_wait(
            &client,
            envelope.envelope_xdr(),
            TIMEOUT_DEADLINE,
            TESTNET_PASSPHRASE,
            None,
            Some(&recorder),
        ),
    )
    .await
    .expect("the submission must end before the held-open request would")
    .expect_err("a submission that never confirms must report a timeout");
    let elapsed = started.elapsed();

    assert!(
        elapsed < TIMEOUT_DEADLINE + DEADLINE_MARGIN,
        "the submission must end at its {TIMEOUT_DEADLINE:?} deadline; elapsed {elapsed:?}"
    );
    match &err {
        WalletError::Submission(SubmissionError::TxTimeout { tx_hash, .. }) => {
            assert_eq!(tx_hash, envelope.tx_hash_hex());
        }
        other => panic!("expected submission.tx_timeout; got {other:?}"),
    }
    let calls = calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            Call::PreSend,
            Call::Outcome(SubmissionOutcome::Timeout {
                tx_hash: envelope.tx_hash_hex().to_owned(),
            }),
        ],
        "the deadline exit records the timeout and nothing else"
    );
    let hash = envelope_hash(envelope);
    let receipt = fx.receipts.get(&hash).unwrap().unwrap();
    assert_eq!(
        receipt.status,
        ReceiptStatus::Pending,
        "a timeout settles nothing"
    );
    assert!(receipt.submitted, "the bytes were sent");
    assert!(
        fx.reservation_is_open(&hash),
        "the reservation stands until reconciliation"
    );
}

/// A poll request the endpoint holds open past the deadline is cut at the
/// deadline, and the submission reports the timeout it reports for any
/// unconfirmed transaction.
#[tokio::test]
#[serial]
async fn a_poll_request_held_past_the_deadline_is_cut_at_the_deadline() {
    let fx = fixture("record-poll-held");
    let envelope = SignedTestEnvelope::for_source([0x26; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_send_pending(&server, envelope.tx_hash_hex()).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(Delayed {
            inner: rpc_ok(json!({"status": "NOT_FOUND", "latestLedger": 1_002, "oldestLedger": 1})),
            delay: HANG,
        })
        .mount(&server)
        .await;

    assert_timeout_at_the_deadline(&fx, &envelope, &server).await;
    assert_eq!(rpc_request_count(&server, "getTransaction").await, 1);
}

/// The sleep after a `NOT_FOUND` ends at the deadline rather than a full poll
/// interval later, and no poll request reaches the endpoint after it.
#[tokio::test]
#[serial]
async fn the_sleep_after_a_not_found_ends_at_the_deadline() {
    let fx = fixture("record-poll-sleep");
    let envelope = SignedTestEnvelope::for_source([0x27; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_send_pending(&server, envelope.tx_hash_hex()).await;
    mount_get_not_found(&server).await;

    assert_timeout_at_the_deadline(&fx, &envelope, &server).await;
    assert_eq!(
        rpc_request_count(&server, "getTransaction").await,
        1,
        "no poll request reaches the endpoint after the sleep that ended at the deadline"
    );
}

/// The sleep after a transient poll error ends at the deadline rather than
/// a full poll interval later, and no poll request reaches the endpoint
/// after it.
#[tokio::test]
#[serial]
async fn the_sleep_after_a_transient_poll_error_ends_at_the_deadline() {
    let fx = fixture("record-poll-transient");
    let envelope = SignedTestEnvelope::for_source([0x28; 32]);
    let server = MockServer::start().await;
    mount_pre_send(&server, &envelope).await;
    mount_send_pending(&server, envelope.tx_hash_hex()).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    assert_timeout_at_the_deadline(&fx, &envelope, &server).await;
    assert_eq!(
        rpc_request_count(&server, "getTransaction").await,
        1,
        "no poll request reaches the endpoint after the sleep that ended at the deadline"
    );
}
