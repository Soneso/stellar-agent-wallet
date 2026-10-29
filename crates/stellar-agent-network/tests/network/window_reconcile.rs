//! The release rule a reconciliation pass applies to open spending-window
//! reservations, against a mocked Stellar RPC endpoint.
//!
//! A reservation is taken before a transaction is sent and counts against the
//! operator's caps while it stands. These tests pin what settles it and what
//! does not:
//!
//! - `SUCCESS` confirms; `FAILED` releases.
//! - `NOT_FOUND` releases only when the transaction can no longer apply: its
//!   sequence has been consumed, or its time bound has passed. The release
//!   records that evidence on the receipt and reports the submission as
//!   settled, so the caller writes its settled row.
//! - A `NOT_FOUND` from an endpoint whose retention window no longer covers the
//!   submission proves nothing, so the reservation stands and the receipt is
//!   marked ambiguous.
//! - A pass is bounded: at most `RECONCILE_BUDGET` reservations, oldest first,
//!   none younger than `RECONCILE_MIN_AGE_MS`.
//! - Nothing releases a reservation on a transport error, and the pass reports
//!   the first endpoint failure it met.
//! - The receipt is never evidence: release evidence a receipt carries is
//!   found again on the chain before anything is released.
//! - Confirmed spend is never dated before its reservation was taken.
//! - On a mainnet profile the primary's `FAILED` and `NOT_FOUND` settle
//!   nothing alone: the oracle's own answer, and the oracle's retention,
//!   chain time and account sequence, decide.
//! - Reconciliation never sends: no pass calls `sendTransaction`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::sync::{Arc, Mutex};

use serde_json::json;
use serial_test::serial;
use stellar_agent_core::policy::v1::criteria::state_store::{
    PolicyStateStore, StateKey, WindowEntry, WindowLimit,
};
use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore, ReleaseEvidence};
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::policy_state::{
    PersistedWindowStore, RECONCILE_BUDGET, RECONCILE_MIN_AGE_MS, ReconcileFailure,
    ReconcileFailureKind, SettledSubmission, SubmissionHold,
};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::signed_envelope::{
    TESTNET_PASSPHRASE, account_id_for_seed, get_network_result, ledger_entries_result_for,
};
use tempfile::TempDir;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// A submission ledger comfortably inside the mocked retention window.
const SUBMISSION_LEDGER: u32 = 1_000;

/// The `now_ms` every test passes.
///
/// Taken from the real clock because the store prunes records older than its
/// one-week retention ceiling on every write, against the same clock: a
/// timestamp far from the present would be pruned before a pass could see it.
fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the system clock must be after the unix epoch")
            .as_millis(),
    )
    .expect("the current time must fit in u64 milliseconds")
}

/// A timestamp old enough for a reservation taken then to be settleable.
fn due_since(now: u64) -> u64 {
    now - RECONCILE_MIN_AGE_MS
}

fn test_profile(name: &str) -> Profile {
    let mut p = Profile::builder_testnet(name, "acct", "n-svc", "n-acct").build();
    p.policy_window_state_key_id = KeyringEntryRef::default_policy_window_state_key(name);
    p
}

fn mainnet_profile(name: &str) -> Profile {
    let mut p = Profile::builder_mainnet_named(
        name,
        "https://rpc.example",
        "reconcile-signer",
        "acct",
        "n-svc",
        "n-acct",
    )
    .build();
    p.policy_window_state_key_id = KeyringEntryRef::default_policy_window_state_key(name);
    p
}

fn state_key(profile_name: &str) -> StateKey {
    StateKey::new(profile_name, 1, "native", 86_400)
}

/// The cap every reservation these tests take is admitted under.
///
/// These tests pin what settles an open reservation, not what admits one, so
/// the cap sits far above every amount they reserve and no reservation is
/// refused at the write.
fn window_limit() -> WindowLimit {
    WindowLimit::Amount {
        asset: "native".to_owned(),
        window: "1d".to_owned(),
        max_stroops: 1_000_000,
    }
}

/// One entry for the tests' single bucket.
fn entry(profile_name: &str, ts_ms: u64, amount: i128) -> WindowEntry {
    WindowEntry::new(state_key(profile_name), ts_ms, amount, window_limit())
}

fn reservation(id: &str, source: &str, sequence: i64, pending_since_ms: u64) -> SubmissionHold {
    SubmissionHold {
        id: id.to_owned(),
        tx_hash: id.to_owned(),
        source: source.to_owned(),
        sequence,
        max_time: 0,
        pending_since_ms,
        submission_ledger: SUBMISSION_LEDGER,
        operator_required: false,
    }
}

/// Counts every JSON-RPC method the endpoint is asked, so a pass's round-trip
/// budget can be asserted rather than assumed.
#[derive(Clone, Default)]
struct MethodCounts {
    calls: Arc<Mutex<Vec<String>>>,
}

impl MethodCounts {
    fn count(&self, rpc_method: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.as_str() == rpc_method)
            .count()
    }
}

/// Answers a fixed body and records the method it was asked.
struct CountingResponder {
    result: serde_json::Value,
    counts: MethodCounts,
}

impl Respond for CountingResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body)
            .unwrap_or_else(|_| json!({}));
        if let Some(rpc_method) = body.get("method").and_then(serde_json::Value::as_str) {
            self.counts
                .calls
                .lock()
                .unwrap()
                .push(rpc_method.to_owned());
        }
        let id = body.get("id").cloned().unwrap_or_else(|| json!(1));
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": id, "result": self.result.clone()}))
            .insert_header("content-type", "application/json")
    }
}

async fn mount(
    server: &MockServer,
    rpc_method: &str,
    result: serde_json::Value,
    counts: &MethodCounts,
) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({ "method": rpc_method })))
        .respond_with(CountingResponder {
            result,
            counts: counts.clone(),
        })
        .mount(server)
        .await;
}

/// Mounts a counted `sendTransaction` answer, so a test can assert that a
/// reconciliation pass never sends.
async fn mount_send_guard(server: &MockServer, counts: &MethodCounts) {
    mount(
        server,
        "sendTransaction",
        json!({"hash": "0".repeat(64), "status": "PENDING", "latestLedger": 2_000}),
        counts,
    )
    .await;
}

fn health(oldest_ledger: u32) -> serde_json::Value {
    json!({
        "status": "healthy",
        "latestLedger": 2_000,
        "oldestLedger": oldest_ledger,
        "ledgerRetentionWindow": 2_000 - oldest_ledger,
    })
}

fn ledgers(close: u64, oldest_close: u64) -> serde_json::Value {
    json!({"latestLedger": 2_000, "latestLedgerCloseTime": close.to_string(),
        "oldestLedger": 1, "oldestLedgerCloseTime": oldest_close,
        "cursor": "2000", "ledgers": []})
}

/// A `getTransaction` body for `status`, with no result XDR.
fn get_transaction(status: &str) -> serde_json::Value {
    json!({
        "status": status,
        "latestLedger": 2_000,
        "oldestLedger": 1,
        "ledger": if status == "SUCCESS" { Some(1_500) } else { None },
        "createdAt": if status == "SUCCESS" { Some((now_ms() / 1_000).to_string()) } else { None },
    })
}

/// A `getTransaction` FAILED body carrying a real `txMALFORMED` result.
fn get_transaction_failed() -> serde_json::Value {
    json!({
        "status": "FAILED",
        "latestLedger": 2_000,
        "oldestLedger": 1,
        "resultXdr": "AAAAAAAAAGT////wAAAAAA==",
    })
}

/// Opens a store and a receipt store over fresh temporary state.
struct Fixture {
    _dir: TempDir,
    _receipt_dir: TempDir,
    profile: Profile,
    profile_name: String,
    window: PersistedWindowStore,
    receipts: ReceiptStore,
    /// The receipt store's backing file, which a test corrupts to make a read
    /// of it fail.
    receipt_file: std::path::PathBuf,
}

fn fixture(name: &str) -> Fixture {
    fixture_for(name, test_profile(name))
}

/// A fixture over a mainnet profile, whose primary's negative answers need
/// the oracle.
fn mainnet_fixture(name: &str) -> Fixture {
    fixture_for(name, mainnet_profile(name))
}

fn fixture_for(name: &str, profile: Profile) -> Fixture {
    keyring_mock::install().unwrap();
    let dir = TempDir::new().unwrap();
    let receipt_dir = TempDir::new().unwrap();
    let window = PersistedWindowStore::at_path(dir.path().join(format!("{name}.window")));
    let receipts = ReceiptStore::open_at(receipt_dir.path(), name).unwrap();
    let receipt_file = receipt_dir.path().join(format!("{name}.json"));
    Fixture {
        _dir: dir,
        _receipt_dir: receipt_dir,
        profile,
        profile_name: name.to_owned(),
        window,
        receipts,
        receipt_file,
    }
}

/// A `getLedgerEntries` body reporting `source`'s account at `sequence`.
fn account_at_sequence(source: &str, sequence: i64) -> serde_json::Value {
    use stellar_xdr::{LedgerEntryData, Limits, ReadXdr, SequenceNumber, WriteXdr};
    let mut result = ledger_entries_result_for(&[source]);
    let xdr = &mut result["entries"][0]["xdr"];
    let mut data = LedgerEntryData::from_xdr_base64(xdr.as_str().unwrap(), Limits::none()).unwrap();
    let LedgerEntryData::Account(account) = &mut data else {
        panic!("the fixture reports an account entry");
    };
    account.seq_num = SequenceNumber(sequence);
    *xdr = json!(data.to_xdr_base64(Limits::none()).unwrap());
    result
}

impl Fixture {
    fn take_reservation(&self, now: u64, reservation: &SubmissionHold, amount: i128) {
        self.window
            .record_pending(
                &self.profile,
                &[entry(&self.profile_name, now, amount)],
                reservation,
            )
            .unwrap();
        self.receipts
            .try_begin(
                &reservation.id,
                &reservation.tx_hash,
                &reservation.source,
                reservation.sequence,
                reservation.max_time,
                reservation.submission_ledger,
            )
            .unwrap();
        self.receipts.mark_submitted(&reservation.id).unwrap();
    }

    fn window_total(&self, now: u64) -> (i128, u32) {
        let dest = PolicyStateStore::new();
        self.window
            .load_into(&self.profile_name, &self.profile, &dest)
            .unwrap();
        dest.query_window(&state_key(&self.profile_name), now + 1_000)
            .unwrap()
    }
}

/// `SUCCESS` turns the reservation into recorded spend and finalizes the
/// receipt.
#[tokio::test]
#[serial]
async fn success_confirms_the_reservation_and_finalizes_the_receipt() {
    let now = now_ms();
    let fx = fixture("reconcile-success");
    let source = account_id_for_seed([0x11; 32]);
    let res = reservation(&"a".repeat(64), &source, 7, due_since(now));
    fx.take_reservation(now, &res, 500);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    mount(
        &server,
        "getTransaction",
        get_transaction("SUCCESS"),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.confirmed, 1, "a SUCCESS answer confirms: {report:?}");
    // The pass holds no audit writer, so it reports what it settled and the
    // caller writes the value-action row each one is owed.
    assert_eq!(
        report.settled.len(),
        1,
        "a confirmed submission is owed a settled row: {report:?}"
    );
    assert_eq!(report.settled[0].status, ReceiptStatus::Success);
    assert_eq!(report.settled[0].ledger, Some(1_500));
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fx.window_total(now),
        (500, 1),
        "confirmed spend keeps counting against the window"
    );
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Success);
    assert_eq!(receipt.ledger, Some(1_500));
}

/// A `SUCCESS` answer whose result meta the wallet cannot decode (a
/// `TransactionMeta` with discriminant 99) settles the reservation from its
/// status, ledger and `createdAt`, read as received.
#[tokio::test]
#[serial]
async fn success_with_undecodable_meta_confirms_the_reservation() {
    let now = now_ms();
    let fx = fixture("reconcile-success-undecodable-meta");
    let source = account_id_for_seed([0x13; 32]);
    let res = reservation(&"a9".repeat(32), &source, 7, due_since(now));
    fx.take_reservation(now, &res, 500);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getTransaction",
        json!({
            "status": "SUCCESS",
            "latestLedger": 2_000,
            "oldestLedger": 1,
            "ledger": 1_500,
            "createdAt": (now / 1_000).to_string(),
            "resultMetaXdr": "AAAAYw==",
        }),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(
        report.confirmed, 1,
        "a SUCCESS answer confirms whatever its meta: {report:?}"
    );
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty()
    );
    assert_eq!(fx.window_total(now), (500, 1));
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Success);
    assert_eq!(receipt.ledger, Some(1_500));
}

/// Confirmed spend is dated from the applying ledger's close time, not from
/// the clock at settlement: a reservation taken two days ago, whose ledger
/// closed just after, leaves the one-day window as soon as it confirms.
#[tokio::test]
#[serial]
async fn success_dates_the_spend_from_the_applying_ledger_close_time() {
    let now = now_ms();
    let fx = fixture("reconcile-success-close-time");
    let source = account_id_for_seed([0x12; 32]);
    let res = reservation(&"a8".repeat(32), &source, 7, due_since(now));
    let two_days_ago = now / 1_000 - 2 * 86_400;
    // Taken a second before the applying ledger closed.
    fx.take_reservation(two_days_ago * 1_000 - 1_000, &res, 500);
    assert_eq!(
        fx.window_total(now),
        (500, 1),
        "the hold counts until settled"
    );

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getTransaction",
        json!({
            "status": "SUCCESS",
            "latestLedger": 2_000,
            "oldestLedger": 1,
            "ledger": 1_500,
            "createdAt": two_days_ago.to_string(),
        }),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.confirmed, 1, "a SUCCESS answer confirms: {report:?}");
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fx.window_total(now),
        (0, 0),
        "spend applied two days ago is outside a one-day window"
    );
    assert_eq!(
        fx.window_total(two_days_ago * 1_000),
        (500, 1),
        "the same spend counts inside the window of the ledger that applied it"
    );
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Success);
}

/// `FAILED` releases the reservation and finalizes the receipt failed: the
/// transaction applied and moved nothing.
#[tokio::test]
#[serial]
async fn failed_releases_the_reservation_and_finalizes_the_receipt() {
    let now = now_ms();
    let fx = fixture("reconcile-failed");
    let source = account_id_for_seed([0x12; 32]);
    let res = reservation(&"b".repeat(64), &source, 7, due_since(now));
    fx.take_reservation(now, &res, 500);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    mount(&server, "getTransaction", get_transaction_failed(), &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.released, 1, "a FAILED answer releases: {report:?}");
    assert_eq!(
        report.settled.len(),
        1,
        "an on-chain failure is owed a settled row: {report:?}"
    );
    assert!(matches!(
        report.settled[0].status,
        ReceiptStatus::Failed { .. }
    ));
    assert_eq!(
        fx.window_total(now),
        (0, 0),
        "a failed transaction moved nothing, so it stops counting"
    );
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert!(
        matches!(receipt.status, ReceiptStatus::Failed { .. }),
        "the receipt records the failure; got {:?}",
        receipt.status
    );
}

/// `NOT_FOUND` with the sequence consumed releases: the endpoint would still
/// remember the transaction and does not report it, so whatever consumed that
/// sequence was something else.
#[tokio::test]
#[serial]
async fn not_found_with_a_consumed_sequence_releases() {
    let now = now_ms();
    let fx = fixture("reconcile-consumed");
    let source = account_id_for_seed([0x13; 32]);
    // The ledger fixture reports the account at sequence 1, so a reservation
    // that needs sequence 1 is one whose sequence has been consumed.
    let res = reservation(&"c".repeat(64), &source, 1, due_since(now));
    fx.take_reservation(now, &res, 500);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(1), &counts).await;
    // The source account's sequence has reached the one the transaction needs.
    mount(
        &server,
        "getLedgerEntries",
        ledger_entries_result_for(&[&source]),
        &counts,
    )
    .await;
    mount_send_guard(&server, &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(
        report.released, 1,
        "a consumed sequence means the transaction can no longer apply: {report:?}"
    );
    assert_eq!(fx.window_total(now), (0, 0));
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(
        receipt.status,
        ReceiptStatus::Ambiguous,
        "the release rests on the endpoint's honesty, so the outcome is recorded as unknown"
    );
    assert_eq!(
        receipt.release_code,
        Some(ReleaseEvidence::SequenceConsumed),
        "the receipt keeps the evidence, so a later run can write the settled row"
    );
    assert_eq!(
        report.settled,
        vec![SettledSubmission {
            envelope_hash: res.id.clone(),
            tx_hash: res.tx_hash.clone(),
            status: ReceiptStatus::Ambiguous,
            release_code: Some(ReleaseEvidence::SequenceConsumed),
            ledger: None,
        }],
        "the release is owed a settled row under its evidence"
    );
    assert_eq!(
        counts.count("sendTransaction"),
        0,
        "reconciliation never sends"
    );
}

/// Ledger close time strictly past maxTime requires a fresh NOT_FOUND before
/// release, because the reserved transaction may have applied during observation.
#[tokio::test]
#[serial]
async fn not_found_with_a_passed_time_bound_releases() {
    let now = now_ms();
    let fx = fixture("reconcile-maxtime");
    let source = account_id_for_seed([0x14; 32]);
    let mut res = reservation(&"d".repeat(64), &source, 7, due_since(now));
    res.max_time = now / 1_000 - 10;
    fx.take_reservation(now, &res, 500);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(1), &counts).await;
    mount(&server, "getLedgers", ledgers(now / 1_000, 1), &counts).await;
    mount_send_guard(&server, &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(
        report.released, 1,
        "a passed time bound releases: {report:?}"
    );
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Ambiguous);
    assert_eq!(
        receipt.release_code,
        Some(ReleaseEvidence::TimeBoundPassed),
        "the receipt keeps the evidence, so a later run can write the settled row"
    );
    assert_eq!(report.settled.len(), 1, "{report:?}");
    assert_eq!(report.settled[0].status, ReceiptStatus::Ambiguous);
    assert_eq!(
        report.settled[0].release_code,
        Some(ReleaseEvidence::TimeBoundPassed)
    );
    assert_eq!(
        report.endpoint_failure, None,
        "every read answered: {report:?}"
    );
    assert_eq!(
        counts.count("sendTransaction"),
        0,
        "reconciliation never sends"
    );
    assert_eq!(
        counts.count("getLedgerEntries"),
        0,
        "a passed time bound settles the reservation without an account read"
    );
    assert_eq!(
        counts.count("getTransaction"),
        2,
        "release requires a fresh answer"
    );
    assert_eq!(counts.count("getLedgers"), 1);
    assert_eq!(report.rpc_calls, 4, "both observations consume RPC budget");
}

/// An unconsumed sequence keeps the reservation at the time bound itself:
/// ledger close time must strictly exceed maxTime to rule out application.
#[tokio::test]
#[serial]
async fn not_found_with_an_unconsumed_sequence_keeps_the_reservation() {
    let now = now_ms();
    let fx = fixture("reconcile-keep");
    let source = account_id_for_seed([0x15; 32]);
    // `ledger_entries_result_for` reports sequence 1, so a reservation at
    // sequence 9 still needs a sequence the account has not reached.
    let mut res = reservation(&"e".repeat(64), &source, 9, due_since(now));
    res.max_time = now / 1_000 - 10;
    fx.take_reservation(now, &res, 500);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(1), &counts).await;
    mount(
        &server,
        "getLedgerEntries",
        ledger_entries_result_for(&[&source]),
        &counts,
    )
    .await;
    mount(&server, "getLedgers", ledgers(res.max_time, 1), &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(
        report.kept_pending, 1,
        "a transaction that can still apply keeps its reservation: {report:?}"
    );
    assert_eq!(
        report.endpoint_failure, None,
        "the hold stands on the endpoint's answers, not on a failure: {report:?}"
    );
    assert_eq!(fx.window_total(now), (500, 1));
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Pending
    );
}

/// A `NOT_FOUND` from an endpoint that no longer holds the submission's ledger
/// range proves nothing, so the reservation stands and the receipt is marked
/// ambiguous, without release evidence, for an operator.
#[tokio::test]
#[serial]
async fn not_found_past_the_retention_floor_keeps_the_reservation() {
    let now = now_ms();
    let fx = fixture("reconcile-retention");
    let source = account_id_for_seed([0x16; 32]);
    let res = reservation(&"f".repeat(64), &source, 7, due_since(now));
    fx.take_reservation(now, &res, 500);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    // The endpoint's retention floor is above the submission ledger.
    mount(&server, "getHealth", health(SUBMISSION_LEDGER + 1), &counts).await;
    mount(
        &server,
        "getLedgerEntries",
        ledger_entries_result_for(&[&source]),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(
        report.retention_expired, 1,
        "the endpoint cannot answer for this transaction: {report:?}"
    );
    assert_eq!(
        fx.window_total(now),
        (500, 1),
        "the reservation stands until an operator resolves it"
    );
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Ambiguous);
    assert_eq!(
        receipt.release_code, None,
        "a closed retention window records no release evidence"
    );
    assert!(
        report.settled.is_empty(),
        "an unknown outcome owes no settled row: {report:?}"
    );
    assert_eq!(
        counts.count("getLedgerEntries"),
        0,
        "the retention boundary settles the question before the account is read"
    );
}

/// A pass touches at most `RECONCILE_BUDGET` reservations, oldest first, and
/// none younger than `RECONCILE_MIN_AGE_MS`.
#[tokio::test]
#[serial]
async fn a_pass_is_bounded_and_takes_the_oldest_due_reservations() {
    let now = now_ms();
    let fx = fixture("reconcile-budget");
    let source = account_id_for_seed([0x17; 32]);

    // Seven due reservations, and one too young to be settleable.
    for index in 0..7_u8 {
        let id = format!("{index:064}");
        let age_ms = RECONCILE_MIN_AGE_MS + u64::from(index) * 1_000;
        fx.take_reservation(now, &reservation(&id, &source, 7, now - age_ms), 10);
    }
    let young = format!("{:064}", 99_u8);
    fx.take_reservation(
        now,
        &reservation(&young, &source, 7, now - RECONCILE_MIN_AGE_MS + 1),
        10,
    );

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    mount(
        &server,
        "getTransaction",
        get_transaction("SUCCESS"),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(
        report.examined, RECONCILE_BUDGET,
        "a pass settles at most the budget: {report:?}"
    );
    assert_eq!(
        counts.count("getTransaction"),
        RECONCILE_BUDGET,
        "one round trip per settled reservation, and no more"
    );

    // The oldest five were settled; the two younger due ones and the
    // not-yet-due one still stand.
    let open = fx.window.pending_reservations(&fx.profile).unwrap();
    let open_ids: Vec<&str> = open.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(open_ids.len(), 3, "three reservations must still stand");
    assert!(
        open_ids.contains(&young.as_str()),
        "a reservation younger than the minimum age is never touched"
    );
    assert!(
        open_ids.contains(&format!("{:064}", 1_u8).as_str())
            && open_ids.contains(&format!("{:064}", 0_u8).as_str()),
        "the two youngest due reservations are left for the next pass: {open_ids:?}"
    );
}

/// An endpoint that cannot be reached settles nothing: every reservation
/// stands, because counting one that may still apply is the safe direction.
#[tokio::test]
#[serial]
async fn a_transport_failure_settles_nothing() {
    let now = now_ms();
    let fx = fixture("reconcile-transport");
    let source = account_id_for_seed([0x18; 32]);
    let res = reservation(&"1".repeat(64), &source, 7, due_since(now));
    fx.take_reservation(now, &res, 500);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(
        report.kept_pending, 1,
        "an unreachable endpoint settles nothing: {report:?}"
    );
    let failure = report
        .endpoint_failure
        .as_ref()
        .expect("the pass reports the failure that left the reservation standing");
    assert!(
        failure.reason.starts_with("getTransaction failed: "),
        "{failure:?}"
    );
    assert_eq!(fx.window_total(now), (500, 1));
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Pending
    );
}

/// A reservation named by an operator is settled with no budget and no
/// minimum age.
#[tokio::test]
#[serial]
async fn reconcile_one_settles_a_named_reservation_whatever_its_age() {
    let now = now_ms();
    let fx = fixture("reconcile-named");
    let source = account_id_for_seed([0x19; 32]);
    // Younger than the minimum age a background pass requires.
    let res = reservation(&"2".repeat(64), &source, 7, now - 1_000);
    fx.take_reservation(now, &res, 500);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    mount(
        &server,
        "getTransaction",
        get_transaction("SUCCESS"),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let due = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();
    assert_eq!(
        due.examined, 0,
        "a background pass does not touch a reservation this young"
    );

    let named = fx
        .window
        .reconcile_one(&fx.profile, &client, None, Some(&fx.receipts), &res.id, now)
        .await
        .unwrap();
    assert_eq!(
        named.confirmed, 1,
        "a named reservation is settled whatever its age: {named:?}"
    );
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Success
    );
}

/// A reservation whose receipt already records an unknown outcome is out of
/// the budget's way, so younger ones are reached.
///
/// Those records are the oldest in the file and the endpoint cannot answer for
/// them. Leaving them in the selection would spend the whole budget on the
/// same few on every pass.
#[tokio::test]
#[serial]
async fn reservations_the_endpoint_cannot_answer_for_do_not_hold_the_budget() {
    let now = now_ms();
    let fx = fixture("reconcile-starve");
    let source = account_id_for_seed([0x21; 32]);

    // Five older reservations already marked ambiguous, and one younger one
    // the chain has confirmed.
    for index in 0..5_u8 {
        let id = format!("{index:064}");
        let age_ms = RECONCILE_MIN_AGE_MS + 100_000 + u64::from(index) * 1_000;
        fx.take_reservation(now, &reservation(&id, &source, 7, now - age_ms), 10);
        fx.receipts
            .finalize(&id, ReceiptStatus::Ambiguous, None)
            .unwrap();
    }
    let younger = format!("{:064}", 50_u8);
    fx.take_reservation(
        now,
        &reservation(&younger, &source, 8, now - RECONCILE_MIN_AGE_MS - 1_000),
        10,
    );

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    mount(
        &server,
        "getTransaction",
        get_transaction("SUCCESS"),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(
        report.examined, 1,
        "only the reservation the endpoint can still answer for is examined: {report:?}"
    );
    assert_eq!(report.confirmed, 1, "and it is settled: {report:?}");
    assert_eq!(
        fx.receipts.get(&younger).unwrap().unwrap().status,
        ReceiptStatus::Success,
        "the younger reservation was reached"
    );
}

/// The automatic pass finishes a release whose window write failed after its
/// receipt checkpoint, by finding the evidence again on the chain, and keeps
/// the evidence the checkpoint recorded.
#[tokio::test]
#[serial]
async fn the_automatic_pass_finishes_a_checkpointed_evidence_release() {
    let now = now_ms();
    let fx = fixture("reconcile-release-checkpoint");
    let source = account_id_for_seed([0x37; 32]);
    let mut res = reservation(&"7c".repeat(32), &source, 1, due_since(now));
    res.max_time = now / 1_000 - 10;
    fx.take_reservation(now, &res, 500);
    let held = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(
            fx._dir
                .path()
                .join(format!("{}.window.lock", fx.profile_name)),
        )
        .unwrap();
    held.try_lock().unwrap();

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(1), &counts).await;
    mount(&server, "getLedgers", ledgers(now / 1_000, 1), &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    assert!(matches!(
        fx.window
            .reconcile_one(&fx.profile, &client, None, Some(&fx.receipts), &res.id, now)
            .await,
        Err(stellar_agent_network::policy_state::WindowStoreError::WriterLocked)
    ));
    let checkpoint = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(
        checkpoint.release_code,
        Some(ReleaseEvidence::TimeBoundPassed)
    );
    assert_eq!(fx.window_total(now), (500, 1));
    drop(held);

    // The checkpoint is not evidence: the pass asks the endpoint again, and
    // the time bound it finds passed releases the reservation.
    counts.calls.lock().unwrap().clear();
    server.reset().await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(1), &counts).await;
    mount(&server, "getLedgers", ledgers(now / 1_000, 1), &counts).await;
    mount_send_guard(&server, &counts).await;
    // The durable receipt needs no second write, even while its writer is busy.
    let held_receipt = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(fx.receipts.lock_file_path().unwrap())
        .unwrap();
    held_receipt.try_lock().unwrap();
    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();
    assert_eq!(report.examined, 1);
    assert_eq!(report.released, 1);
    assert_eq!(report.receipt_write_failed, 0);
    assert_eq!(report.settled.len(), 1);
    assert_eq!(report.settled[0].release_code, checkpoint.release_code);
    assert_eq!(fx.receipts.get(&res.id).unwrap().unwrap(), checkpoint);
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty()
    );
    assert_eq!(fx.window_total(now), (0, 0));
    assert_eq!(
        counts.count("getTransaction"),
        2,
        "the first answer and the fresh one after the evidence"
    );
    assert_eq!(report.rpc_calls, counts.calls.lock().unwrap().len());
    assert!(report.rpc_calls > 0);
    assert_eq!(counts.count("sendTransaction"), 0);
}

/// Release evidence a receipt recorded does not release a reservation whose
/// submission ledger the endpoint no longer holds: the evidence cannot be
/// found again, so the reservation stands for the operator and the pass
/// reports it retention-expired.
#[tokio::test]
#[serial]
async fn a_checkpointed_evidence_release_beyond_retention_keeps_the_reservation() {
    let now = now_ms();
    let fx = fixture("reconcile-release-retention");
    let source = account_id_for_seed([0x38; 32]);
    let res = reservation(&"7d".repeat(32), &source, 1, due_since(now));
    fx.take_reservation(now, &res, 500);
    fx.receipts
        .finalize_released(&res.id, ReleaseEvidence::TimeBoundPassed)
        .unwrap();
    let checkpoint = fx.receipts.get(&res.id).unwrap().unwrap();

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(SUBMISSION_LEDGER + 1), &counts).await;
    mount(&server, "getLedgers", ledgers(now / 1_000, 1), &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();
    assert_eq!(report.examined, 1);
    assert_eq!(report.released, 0, "{report:?}");
    assert_eq!(report.retention_expired, 1, "{report:?}");
    assert!(report.settled.is_empty(), "{report:?}");
    assert_eq!(
        fx.window.pending_reservations(&fx.profile).unwrap(),
        *std::slice::from_ref(&res),
        "the reservation stands for the operator"
    );
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Ambiguous);
    assert_eq!(receipt.release_code, checkpoint.release_code);
    assert_eq!(counts.count("getTransaction"), 1);
    assert_eq!(report.rpc_calls, counts.calls.lock().unwrap().len());
}

/// A pending reservation older than the retention ceiling is kept.
///
/// It holds the operator's cap for a submission whose outcome is still
/// unknown. Dropping it would stop that spend counting while its receipt still
/// reports pending, and would take the record out of reconciliation's reach.
#[tokio::test]
#[serial]
async fn a_pending_reservation_is_not_pruned_by_age() {
    let now = now_ms();
    let fx = fixture("reconcile-prune");
    let source = account_id_for_seed([0x22; 32]);

    let ancient = format!("{:064}", 1_u8);
    // Two weeks back, well past the one-week retention ceiling.
    let ancient_ts = now - 14 * 24 * 60 * 60 * 1_000;
    fx.window
        .record_pending(
            &fx.profile,
            &[entry(&fx.profile_name, ancient_ts, 10)],
            &reservation(&ancient, &source, 7, ancient_ts),
        )
        .unwrap();

    // A later write is what runs the prune.
    let fresh = format!("{:064}", 2_u8);
    fx.window
        .record_pending(
            &fx.profile,
            &[entry(&fx.profile_name, now, 10)],
            &reservation(&fresh, &source, 8, now),
        )
        .unwrap();

    let open = fx.window.pending_reservations(&fx.profile).unwrap();
    assert!(
        open.iter().any(|r| r.id == ancient),
        "a pending reservation outlives the retention window: {open:?}"
    );
    assert_eq!(
        fx.window_total(now),
        (20, 2),
        "old pending spend holds headroom"
    );
    fx.window
        .confirm(&fx.profile, &ancient, Some((now / 1_000) as i64))
        .unwrap();
    assert_eq!(
        fx.window_total(now),
        (20, 2),
        "confirmation ages from ledger close"
    );
    assert_eq!(
        fx.window_total(now + 86_400_000),
        (10, 1),
        "only confirmed spend ages out"
    );
    fx.window.release(&fx.profile, &fresh).unwrap();
    assert_eq!(
        fx.window_total(now + 86_400_000),
        (0, 0),
        "release removes the unresolved debit"
    );
}

/// A reservation without a receipt uses the chain's transaction answer and
/// retention boundary when deciding whether a consumed sequence releases it,
/// and a release restores the receipt with the evidence that released it.
#[tokio::test]
#[serial]
async fn an_orphaned_reservation_is_released_once_its_sequence_is_consumed() {
    let now = now_ms();
    let fx = fixture("reconcile-orphan");
    let source = account_id_for_seed([0x23; 32]);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(1), &counts).await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    // `ledger_entries_result_for` reports the account at sequence 1.
    mount(
        &server,
        "getLedgerEntries",
        ledger_entries_result_for(&[&source]),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    // Sequence 9 is one the account has not reached, so the reservation
    // stands: a replacement at that number may be in flight and the cap has to
    // account for it.
    let unconsumed = format!("{:064}", 3_u8);
    fx.window
        .record_pending(
            &fx.profile,
            &[entry(&fx.profile_name, now, 10)],
            &reservation(&unconsumed, &source, 9, due_since(now)),
        )
        .unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();
    assert_eq!(
        report.kept_pending, 1,
        "an unconsumed sequence keeps the orphan: {report:?}"
    );
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .iter()
            .any(|r| r.id == unconsumed),
        "the reservation stands"
    );
    fx.window.release(&fx.profile, &unconsumed).unwrap();

    // Sequence 1 is the one the account reports, so the transaction it
    // reserved for can no longer apply.
    let consumed = format!("{:064}", 4_u8);
    fx.window
        .record_pending(
            &fx.profile,
            &[entry(&fx.profile_name, now, 10)],
            &reservation(&consumed, &source, 1, due_since(now)),
        )
        .unwrap();

    let report2 = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();
    assert_eq!(
        report2.released, 1,
        "a consumed sequence releases the orphan: {report2:?}"
    );
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty(),
        "the hold is gone"
    );
    let restored = fx
        .receipts
        .get(&consumed)
        .unwrap()
        .expect("a release on evidence restores the missing receipt");
    assert_eq!(restored.status, ReceiptStatus::Ambiguous);
    assert_eq!(
        restored.release_code,
        Some(ReleaseEvidence::SequenceConsumed)
    );
    assert_eq!(restored.tx_hash, consumed);
    assert_eq!(restored.source, source);
    assert_eq!(restored.sequence, 1);
    assert!(
        restored.submitted,
        "the restored receipt records a sent transaction"
    );
    assert_eq!(
        report2.settled.len(),
        1,
        "the release is owed a settled row under its evidence: {report2:?}"
    );
    assert_eq!(
        report2.settled[0].release_code,
        Some(ReleaseEvidence::SequenceConsumed)
    );
}

/// A receipt store that cannot be read keeps every reservation, and asks the
/// chain nothing.
///
/// A local read failure leaves the submission identity unresolved, so the
/// operator's cap continues to account for the reservation.
#[tokio::test]
#[serial]
async fn an_unreadable_receipt_store_keeps_every_reservation() {
    let now = now_ms();
    let fx = fixture("reconcile-unreadable");
    let source = account_id_for_seed([0x24; 32]);
    let id = format!("{:064}", 5_u8);

    // A live reservation with a receipt: a submission that was sent and whose
    // confirmation never arrived.
    fx.take_reservation(now, &reservation(&id, &source, 1, due_since(now)), 10);

    // The file the store reads is no longer JSON.
    std::fs::write(&fx.receipt_file, b"{ not json").unwrap();
    assert!(
        fx.receipts.get(&id).is_err(),
        "the fixture must make a receipt read fail"
    );

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(1), &counts).await;
    // The account has reached the sequence the transaction needs, which is the
    // orphan branch's release condition.
    mount(
        &server,
        "getLedgerEntries",
        ledger_entries_result_for(&[&source]),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(
        report.released, 0,
        "a local read error releases nothing: {report:?}"
    );
    assert_eq!(report.kept_pending, 1, "the reservation stands: {report:?}");
    assert_eq!(
        counts.count("getTransaction"),
        0,
        "the pass asks the chain nothing about a reservation it cannot read the receipt for"
    );
    assert_eq!(
        counts.count("getLedgerEntries"),
        0,
        "and reads no account either"
    );
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .iter()
            .any(|r| r.id == id),
        "the hold is still counted against the operator's caps"
    );
}

/// A transaction can consume its sequence between the transaction and account reads.
#[tokio::test]
#[serial]
async fn transaction_landing_during_sequence_read_keeps_its_debit() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let now = now_ms();
    let fx = fixture("reconcile-sequence-race");
    let source = account_id_for_seed([0x25; 32]);
    let res = reservation(&"a5".repeat(32), &source, 1, due_since(now));
    fx.take_reservation(now, &res, 500);
    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    let queries = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&queries);
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(move |request: &Request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let status = if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                "NOT_FOUND"
            } else {
                "SUCCESS"
            };
            ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": body["id"], "result": get_transaction(status)
            }))
        })
        .mount(&server)
        .await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(1), &counts).await;
    mount(
        &server,
        "getLedgerEntries",
        ledger_entries_result_for(&[&source]),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.confirmed, 1);
    assert_eq!(report.released, 0);
    assert_eq!(fx.window_total(now), (500, 1));
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Success
    );
    assert_eq!(queries.load(Ordering::SeqCst), 2);
    assert_eq!(counts.count("getLedgerEntries"), 1);
}

/// The reservation retains enough identity to settle spend after receipt-file loss.
#[tokio::test]
#[serial]
async fn lost_receipt_success_preserves_spend_and_restores_identity() {
    let now = now_ms();
    let fx = fixture("reconcile-lost-receipt");
    let source = account_id_for_seed([0x26; 32]);
    let res = reservation(&"a6".repeat(32), &source, 1, due_since(now));
    fx.take_reservation(now, &res, 500);
    std::fs::remove_file(&fx.receipt_file).unwrap();
    assert!(fx.receipts.get(&res.id).unwrap().is_none());

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getTransaction",
        get_transaction("SUCCESS"),
        &counts,
    )
    .await;
    mount(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        &counts,
    )
    .await;
    mount(
        &server,
        "getLedgerEntries",
        ledger_entries_result_for(&[&source]),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.confirmed, 1);
    assert_eq!(report.released, 0);
    assert_eq!(fx.window_total(now), (500, 1));
    let receipt = fx.receipts.find_by_tx_hash(&res.tx_hash).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Success);
    assert_eq!(receipt.source, source);
    assert_eq!(receipt.sequence, res.sequence);
    assert!(receipt.submitted);
    assert_eq!(counts.count("getTransaction"), 1);
    assert_eq!(counts.count("getLedgerEntries"), 0);
    assert_eq!(report.settled.len(), 1);
}

/// Receipt-file loss does not remove the endpoint retention boundary.
#[tokio::test]
#[serial]
async fn lost_receipt_outside_retention_keeps_the_reservation() {
    let now = now_ms();
    let fx = fixture("reconcile-lost-retention");
    let source = account_id_for_seed([0x27; 32]);
    let mut res = reservation(&"a7".repeat(32), &source, 1, due_since(now));
    res.max_time = now / 1_000 - 10;
    fx.take_reservation(now, &res, 500);
    std::fs::remove_file(&fx.receipt_file).unwrap();
    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(SUBMISSION_LEDGER + 1), &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();
    assert_eq!(report.released, 0);
    assert_eq!(fx.window_total(now), (500, 1));
    assert_eq!(
        fx.window.pending_reservations(&fx.profile).unwrap().len(),
        1
    );
    assert_eq!(counts.count("getTransaction"), 1);
    assert_eq!(counts.count("getHealth"), 1);
    assert_eq!(counts.count("getLedgerEntries"), 0);
}

/// A success answer without an applying ledger time cannot date the spend.
#[tokio::test]
#[serial]
async fn confirmation_without_a_valid_close_time_keeps_the_hold() {
    let now = now_ms();
    let fx = fixture("confirm-no-time");
    let res = reservation(
        &"f".repeat(64),
        &account_id_for_seed([0x23; 32]),
        7,
        due_since(now),
    );
    fx.take_reservation(now, &res, 23);
    for time in [None, Some(0), Some(-1), Some(i64::MAX)] {
        fx.window.confirm(&fx.profile, &res.id, time).unwrap();
        assert_eq!(
            fx.window.pending_reservations(&fx.profile).unwrap().len(),
            1
        );
        assert_eq!(fx.window_total(now + 86_400_000), (23, 1));
    }
}

/// Host time controls eligibility; only a valid chain observation can expire a bound.
#[tokio::test]
#[serial]
async fn host_clock_ahead_and_invalid_chain_times_keep_headroom() {
    for (close_delta, oldest_delta) in [(0, 0), (-10, -20), (10, 20)] {
        let now = now_ms();
        let fx = fixture("chain-clock-validation");
        let source = account_id_for_seed([0x30; 32]);
        let mut res = reservation(&"b0".repeat(32), &source, 9, due_since(now));
        res.max_time = now / 1_000;
        fx.take_reservation(now, &res, 50);
        let counts = MethodCounts::default();
        let server = MockServer::start().await;
        mount(
            &server,
            "getTransaction",
            get_transaction("NOT_FOUND"),
            &counts,
        )
        .await;
        mount(&server, "getHealth", health(1), &counts).await;
        let close = if close_delta == 0 {
            0
        } else {
            res.max_time.saturating_add_signed(close_delta)
        };
        let oldest = if oldest_delta == 0 {
            0
        } else {
            res.max_time.saturating_add_signed(oldest_delta)
        };
        mount(&server, "getLedgers", ledgers(close, oldest), &counts).await;
        mount(
            &server,
            "getLedgerEntries",
            ledger_entries_result_for(&[&source]),
            &counts,
        )
        .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let report = fx
            .window
            .reconcile_due(
                &fx.profile,
                &client,
                None,
                Some(&fx.receipts),
                now + 30 * 86_400_000,
                RECONCILE_BUDGET,
            )
            .await
            .unwrap();
        assert_eq!(
            report.kept_pending, 1,
            "invalid or unexpired chain time keeps the hold"
        );
        assert_eq!(fx.window_total(now), (50, 1));
        assert_eq!(counts.count("getTransaction"), 1);
    }
}

/// A fresh definitive answer at an expired bound settles the chain's outcome.
#[tokio::test]
#[serial]
async fn time_bound_fresh_answer_settles_success_and_failure() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for status in ["SUCCESS", "FAILED"] {
        let now = now_ms();
        let fx = fixture("chain-time-race");
        let mut res = reservation(
            &"b1".repeat(32),
            &account_id_for_seed([0x31; 32]),
            9,
            due_since(now),
        );
        res.max_time = now / 1_000 - 1;
        fx.take_reservation(now, &res, 51);
        let counts = MethodCounts::default();
        let server = MockServer::start().await;
        let queries = Arc::new(AtomicUsize::new(0));
        let observed = queries.clone();
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":"getTransaction"})))
            .respond_with(move |request: &Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let result = if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                    get_transaction("NOT_FOUND")
                } else if status == "FAILED" {
                    get_transaction_failed()
                } else {
                    get_transaction(status)
                };
                ResponseTemplate::new(200)
                    .set_body_json(json!({"jsonrpc":"2.0", "id":body["id"], "result":result}))
            })
            .mount(&server)
            .await;
        mount(&server, "getHealth", health(1), &counts).await;
        mount(&server, "getLedgers", ledgers(now / 1_000, 1), &counts).await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let report = fx
            .window
            .reconcile_due(
                &fx.profile,
                &client,
                None,
                Some(&fx.receipts),
                now,
                RECONCILE_BUDGET,
            )
            .await
            .unwrap();
        assert_eq!(queries.load(Ordering::SeqCst), 2);
        let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
        if status == "SUCCESS" {
            assert_eq!(report.confirmed, 1);
            assert_eq!(fx.window_total(now), (51, 1));
            assert_eq!(receipt.status, ReceiptStatus::Success);
        } else {
            assert_eq!(report.released, 1);
            assert_eq!(fx.window_total(now), (0, 0));
            assert!(matches!(receipt.status, ReceiptStatus::Failed { .. }));
        }
    }
}

/// An unavailable chain clock closes the time arm while sequence settlement remains usable.
/// The six-second outer deadline bounds the two-second ledger observation.
#[tokio::test]
#[serial]
async fn unavailable_ledgers_leave_sequence_settlement_available() {
    for sequence in [9, 1] {
        let now = now_ms();
        let fx = fixture("ledgers-unavailable");
        let source = account_id_for_seed([0x32; 32]);
        let mut res = reservation(&"b2".repeat(32), &source, sequence, due_since(now));
        res.max_time = now / 1_000 - 10;
        fx.take_reservation(now, &res, 52);
        let counts = MethodCounts::default();
        let server = MockServer::start().await;
        mount(
            &server,
            "getTransaction",
            get_transaction("NOT_FOUND"),
            &counts,
        )
        .await;
        mount(&server, "getHealth", health(1), &counts).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":"getLedgers"})))
            .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(20)))
            .mount(&server)
            .await;
        mount(
            &server,
            "getLedgerEntries",
            ledger_entries_result_for(&[&source]),
            &counts,
        )
        .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let report = tokio::time::timeout(
            std::time::Duration::from_secs(6),
            fx.window.reconcile_due(
                &fx.profile,
                &client,
                None,
                Some(&fx.receipts),
                now,
                RECONCILE_BUDGET,
            ),
        )
        .await
        .expect("ledger observation must be bounded")
        .unwrap();
        assert_eq!(report.released, usize::from(sequence == 1));
        assert_eq!(report.kept_pending, usize::from(sequence == 9));
        assert_eq!(counts.count("getLedgerEntries"), 1);
    }
}

/// Six receiptless holds beyond retention cannot starve a younger answerable submission.
/// Operator markers retain their identity, debit, and selection state across restart.
#[tokio::test]
#[serial]
async fn orphan_markers_survive_restart_and_free_the_next_pass_budget() {
    let now = now_ms();
    let fx = fixture("orphan-budget");
    let source = account_id_for_seed([0x33; 32]);
    for index in 1..=7 {
        let mut res = reservation(
            &format!("{index:064x}"),
            &source,
            index,
            due_since(now) - (8 - index) as u64 * 1000,
        );
        res.submission_ledger = if index == 7 { 1_500 } else { 1_000 };
        fx.window
            .record_pending(&fx.profile, &[entry(&fx.profile_name, now, 10)], &res)
            .unwrap();
    }
    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"getTransaction"})))
        .respond_with(|request: &Request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let status = if body["params"]["hash"] == format!("{:064x}", 7) {
                "SUCCESS"
            } else {
                "NOT_FOUND"
            };
            ResponseTemplate::new(200).set_body_json(
                json!({"jsonrpc":"2.0", "id":body["id"], "result":get_transaction(status)}),
            )
        })
        .mount(&server)
        .await;
    mount(&server, "getHealth", health(1_200), &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let first = fx
        .window
        .reconcile_due(&fx.profile, &client, None, Some(&fx.receipts), now, 5)
        .await
        .unwrap();
    assert_eq!(first.examined, 5);
    assert_eq!(first.retention_expired, 5);
    let reopened = PersistedWindowStore::at_path(fx._dir.path().join("orphan-budget.window"));
    let held = reopened.pending_reservations(&fx.profile).unwrap();
    assert_eq!(held.iter().filter(|r| r.operator_required).count(), 5);
    assert_eq!(fx.window_total(now), (70, 7));
    let second = reopened
        .reconcile_due(&fx.profile, &client, None, Some(&fx.receipts), now, 5)
        .await
        .unwrap();
    assert_eq!(second.examined, 2);
    assert_eq!(second.confirmed, 1);
    assert_eq!(second.retention_expired, 1);
    let third = reopened
        .reconcile_due(&fx.profile, &client, None, Some(&fx.receipts), now, 5)
        .await
        .unwrap();
    assert_eq!(third.examined, 0);
    assert_eq!(third.rpc_calls, 0);
}

/// An unsuccessful durable marker write is reported and leaves the hold selectable.
#[tokio::test]
#[serial]
async fn failed_orphan_marker_write_keeps_the_reservation_selectable() {
    let now = now_ms();
    let fx = fixture("orphan-marker-failure");
    let res = reservation(
        &"b3".repeat(32),
        &account_id_for_seed([0x33; 32]),
        7,
        due_since(now),
    );
    fx.window
        .record_pending(&fx.profile, &[entry(&fx.profile_name, now, 53)], &res)
        .unwrap();
    let lock = std::fs::OpenOptions::new()
        .write(true)
        .open(fx._dir.path().join("orphan-marker-failure.window.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(1200), &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let result = fx
        .window
        .reconcile_due(&fx.profile, &client, None, Some(&fx.receipts), now, 5)
        .await;
    assert!(
        matches!(
            result,
            Err(stellar_agent_network::policy_state::WindowStoreError::WriterLocked)
        ),
        "{result:?}"
    );
    assert!(!fx.window.pending_reservations(&fx.profile).unwrap()[0].operator_required);
    assert_eq!(fx.window_total(now), (53, 1));
    drop(lock);
    let next = fx
        .window
        .reconcile_due(&fx.profile, &client, None, Some(&fx.receipts), now, 5)
        .await
        .unwrap();
    assert_eq!(next.examined, 1);
    assert_eq!(next.retention_expired, 1);
    assert!(fx.window.pending_reservations(&fx.profile).unwrap()[0].operator_required);
}

/// One ledger observation serves all due reservations and is charged once.
#[tokio::test]
#[serial]
async fn chain_observation_is_shared_and_charged_once_per_pass() {
    let now = now_ms();
    let fx = fixture("shared-chain-observation");
    let source = account_id_for_seed([0x34; 32]);
    for index in 1..=2 {
        let mut res = reservation(&format!("{index:064x}"), &source, 9, due_since(now));
        res.max_time = now / 1_000 - 10;
        fx.take_reservation(now, &res, 54);
    }
    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(1), &counts).await;
    mount(&server, "getLedgers", ledgers(now / 1_000, 1), &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let report = fx
        .window
        .reconcile_due(&fx.profile, &client, None, Some(&fx.receipts), now, 2)
        .await
        .unwrap();
    assert_eq!(report.released, 2);
    assert_eq!(report.rpc_calls, 6);
    assert_eq!(counts.count("getHealth"), 1);
    assert_eq!(counts.count("getLedgers"), 1);
    assert_eq!(counts.count("getTransaction"), 4);
    let requests = server.received_requests().await.unwrap();
    let body = requests
        .iter()
        .map(|r| serde_json::from_slice::<serde_json::Value>(&r.body).unwrap())
        .find(|r| r["method"] == "getLedgers")
        .unwrap();
    assert_eq!(body["params"]["startLedger"], 2000);
    assert_eq!(body["params"]["pagination"]["limit"], 1);
}

/// An endpoint failure is reported, and a later successful read in the same
/// pass does not clear it.
///
/// The ledger observation fails, which closes the time arm, and the account
/// read that follows succeeds with an unconsumed sequence. The reservation
/// stands either way; the report says the endpoint could not answer, so a
/// caller does not read the hold as a transaction that can still apply.
#[tokio::test]
#[serial]
async fn an_endpoint_failure_survives_a_later_successful_read() {
    let now = now_ms();
    let fx = fixture("reconcile-failure-channel");
    let source = account_id_for_seed([0x35; 32]);
    let mut res = reservation(&"b5".repeat(32), &source, 9, due_since(now));
    res.max_time = now / 1_000 - 10;
    fx.take_reservation(now, &res, 55);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(1), &counts).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getLedgers"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    mount(
        &server,
        "getLedgerEntries",
        ledger_entries_result_for(&[&source]),
        &counts,
    )
    .await;
    mount_send_guard(&server, &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_one(&fx.profile, &client, None, Some(&fx.receipts), &res.id, now)
        .await
        .unwrap();

    assert_eq!(report.kept_pending, 1, "{report:?}");
    assert_eq!(
        counts.count("getLedgerEntries"),
        1,
        "the account read after the failure succeeded"
    );
    let failure = report
        .endpoint_failure
        .expect("the ledger observation failure is reported after the account read");
    assert!(
        failure.reason.starts_with("getLedgers failed: "),
        "{failure:?}"
    );
    let authority = server.uri();
    assert_eq!(failure.endpoint, authority);
    assert_eq!(
        failure.to_network_error().to_string(),
        format!(
            "RPC endpoint '{authority}' is unreachable: {}",
            failure.reason
        )
    );
    assert_eq!(fx.window_total(now), (55, 1));
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Pending
    );
    assert_eq!(
        counts.count("sendTransaction"),
        0,
        "reconciliation never sends"
    );
}

/// A receipt write is the checkpoint before a reservation can settle.
async fn assert_receipt_checkpoint(status: &str, missing: bool) {
    let now = now_ms();
    let fx = fixture("reconcile-checkpoint");
    let source = account_id_for_seed([0x36; 32]);
    let res = reservation(&"6a".repeat(32), &source, 1, due_since(now));
    fx.take_reservation(now, &res, 500);
    if missing {
        std::fs::remove_file(&fx.receipt_file).unwrap();
    }
    let before = fx.receipts.get(&res.id).unwrap();
    let held = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(fx.receipts.lock_file_path().unwrap())
        .unwrap();
    held.try_lock().unwrap();

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(&server, "getTransaction", get_transaction(status), &counts).await;
    mount(&server, "getHealth", health(1), &counts).await;
    mount(&server, "getLedgers", ledgers(now / 1_000, 1), &counts).await;
    mount(
        &server,
        "getLedgerEntries",
        ledger_entries_result_for(&[&source]),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let report = fx
        .window
        .reconcile_one(&fx.profile, &client, None, Some(&fx.receipts), &res.id, now)
        .await
        .unwrap();
    assert_eq!(report.receipt_write_failed, 1, "{report:?}");
    assert_eq!(report.released, 0);
    assert_eq!(report.confirmed, 0);
    assert!(report.settled.is_empty());
    assert_eq!(
        fx.window.pending_reservations(&fx.profile).unwrap(),
        *std::slice::from_ref(&res)
    );
    assert_eq!(fx.receipts.get(&res.id).unwrap(), before);
    drop(held);

    let retried = fx
        .window
        .reconcile_one(&fx.profile, &client, None, Some(&fx.receipts), &res.id, now)
        .await
        .unwrap();
    assert_eq!(retried.receipt_write_failed, 0);
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty()
    );
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    if status == "SUCCESS" {
        assert_eq!(retried.confirmed, 1);
        assert_eq!(receipt.status, ReceiptStatus::Success);
        assert_eq!(fx.window_total(now), (500, 1));
    } else {
        assert_eq!(retried.released, 1);
        assert_eq!(receipt.status, ReceiptStatus::Ambiguous);
        assert_eq!(
            receipt.release_code,
            Some(ReleaseEvidence::SequenceConsumed)
        );
    }
}

/// An evidence release retries its receipt checkpoint before releasing the hold.
#[tokio::test]
#[serial]
async fn an_evidence_release_waits_for_its_receipt_and_retries() {
    assert_receipt_checkpoint("NOT_FOUND", false).await;
}

/// A successful transaction retries its receipt checkpoint before confirming spend.
#[tokio::test]
#[serial]
async fn a_success_waits_for_its_receipt_and_retries() {
    assert_receipt_checkpoint("SUCCESS", false).await;
}

/// An orphan release waits for a durable reconstructed receipt.
#[tokio::test]
#[serial]
async fn a_missing_receipt_must_be_restored_before_release() {
    assert_receipt_checkpoint("NOT_FOUND", true).await;
}

// ── Confirmed spend is never dated before its reservation ────────────────

/// A `SUCCESS` whose close time is earlier than the reservation itself is
/// not a time the chain can produce: the spend counts from the reservation,
/// so a backdated answer cannot take it out of the window.
#[tokio::test]
#[serial]
async fn a_backdated_success_keeps_the_spend_in_the_window() {
    let now = now_ms();
    let fx = fixture("reconcile-success-backdated");
    let source = account_id_for_seed([0x15; 32]);
    let res = reservation(&"a9".repeat(32), &source, 7, due_since(now));
    fx.take_reservation(now, &res, 500);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    let two_days_ago = now / 1_000 - 2 * 86_400;
    mount(
        &server,
        "getTransaction",
        json!({
            "status": "SUCCESS",
            "latestLedger": 2_000,
            "oldestLedger": 1,
            "ledger": 1_500,
            "createdAt": two_days_ago.to_string(),
        }),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.confirmed, 1, "{report:?}");
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fx.window_total(now),
        (500, 1),
        "the spend counts in the window from the time it was reserved"
    );
}

// ── A submission ledger of 0 ─────────────────────────────────────────────

/// A reservation recorded against ledger 0 carries no retention boundary, so
/// a `NOT_FOUND` with a consumed sequence releases nothing.
#[tokio::test]
#[serial]
async fn a_reservation_without_a_submission_ledger_never_releases_on_not_found() {
    let now = now_ms();
    let fx = fixture("reconcile-ledger-zero");
    let source = account_id_for_seed([0x16; 32]);
    let mut res = reservation(&"aa".repeat(32), &source, 1, due_since(now));
    res.submission_ledger = 0;
    fx.take_reservation(now, &res, 500);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    // An endpoint that reports its retention from ledger 0 holds every
    // ledger, so the retention boundary alone does not stop a release.
    mount(&server, "getHealth", health(0), &counts).await;
    // The fixture account sits at sequence 1, the one the reservation needs.
    mount(
        &server,
        "getLedgerEntries",
        ledger_entries_result_for(&[&source]),
        &counts,
    )
    .await;
    mount_send_guard(&server, &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.kept_pending, 1, "{report:?}");
    assert_eq!(report.released, 0, "{report:?}");
    assert!(report.settled.is_empty(), "{report:?}");
    assert_eq!(
        fx.window.pending_reservations(&fx.profile).unwrap(),
        *std::slice::from_ref(&res)
    );
    assert_eq!(fx.window_total(now), (500, 1));
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Pending
    );
}

// ── The receipt is never evidence ────────────────────────────────────────

/// Rewrites the receipt file the way anything with write access to it can:
/// the entry of `id` reads ambiguous, with `release_code` as its evidence.
fn forge_released_receipt(fx: &Fixture, id: &str, release_code: &str) {
    let mut map: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fx.receipt_file).unwrap()).unwrap();
    let entry = map
        .get_mut(id)
        .expect("the receipt file holds the submission's entry");
    entry["status"] = json!({ "state": "ambiguous" });
    entry["release_code"] = json!(release_code);
    std::fs::write(&fx.receipt_file, serde_json::to_vec_pretty(&map).unwrap()).unwrap();
    let forged = fx.receipts.get(id).unwrap().unwrap();
    assert_eq!(forged.status, ReceiptStatus::Ambiguous, "the forgery reads");
    assert_eq!(
        forged.release_code.map(ReleaseEvidence::code),
        Some(release_code)
    );
}

/// A receipt edited to claim a release releases nothing: the pass asks the
/// endpoint, which reports the transaction unknown with its sequence
/// unconsumed and no time bound, so the reservation and its debit stand.
#[tokio::test]
#[serial]
async fn a_forged_release_code_does_not_release_the_reservation() {
    let now = now_ms();
    let fx = fixture("reconcile-forged-not-found");
    let source = account_id_for_seed([0x17; 32]);
    // The fixture account sits at sequence 1; the transaction needs 7.
    let res = reservation(&"ab".repeat(32), &source, 7, due_since(now));
    fx.take_reservation(now, &res, 500);
    forge_released_receipt(&fx, &res.id, "submission.sequence_consumed");

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getTransaction",
        get_transaction("NOT_FOUND"),
        &counts,
    )
    .await;
    mount(&server, "getHealth", health(1), &counts).await;
    mount(&server, "getLedgers", ledgers(now / 1_000, 1), &counts).await;
    mount(
        &server,
        "getLedgerEntries",
        ledger_entries_result_for(&[&source]),
        &counts,
    )
    .await;
    mount_send_guard(&server, &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.examined, 1, "the forged receipt is selected");
    assert_eq!(report.released, 0, "{report:?}");
    assert_eq!(report.kept_pending, 1, "{report:?}");
    assert!(report.settled.is_empty(), "{report:?}");
    assert_eq!(
        fx.window.pending_reservations(&fx.profile).unwrap(),
        *std::slice::from_ref(&res)
    );
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
    assert_eq!(
        counts.count("getTransaction"),
        1,
        "the chain is asked about it"
    );
    assert_eq!(counts.count("sendTransaction"), 0);
}

/// A receipt edited to claim a release does not stop the chain's `SUCCESS`
/// from confirming the spend.
#[tokio::test]
#[serial]
async fn a_forged_release_code_does_not_stop_a_success_confirming() {
    let now = now_ms();
    let fx = fixture("reconcile-forged-success");
    let source = account_id_for_seed([0x18; 32]);
    let res = reservation(&"ac".repeat(32), &source, 7, due_since(now));
    fx.take_reservation(now, &res, 500);
    forge_released_receipt(&fx, &res.id, "submission.time_bound_passed");

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount(
        &server,
        "getTransaction",
        get_transaction("SUCCESS"),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.confirmed, 1, "{report:?}");
    assert_eq!(report.released, 0, "{report:?}");
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Success
    );
}

// ── Mainnet: the oracle witnesses the primary's negative answers ─────────

/// A `getTransaction` FAILED body carrying `result` as its result.
fn get_transaction_failed_with(result: stellar_xdr::TransactionResultResult) -> serde_json::Value {
    use stellar_xdr::{Limits, TransactionResult, TransactionResultExt, WriteXdr};
    let result = TransactionResult {
        fee_charged: 0,
        result,
        ext: TransactionResultExt::V0,
    }
    .to_xdr_base64(Limits::none())
    .unwrap();
    json!({
        "status": "FAILED",
        "latestLedger": 2_000,
        "oldestLedger": 1,
        "resultXdr": result,
    })
}

/// A mock primary and a mock oracle, each with its own method counts.
struct Endpoints {
    primary: MockServer,
    primary_counts: MethodCounts,
    oracle: MockServer,
    oracle_counts: MethodCounts,
}

impl Endpoints {
    /// A primary and an oracle that both report the mainnet passphrase.
    async fn start() -> Self {
        Self::with_oracle_identity(get_network_result(MAINNET_PASSPHRASE)).await
    }

    /// A primary that reports the mainnet passphrase and an oracle that
    /// answers `getNetwork` with `identity`.
    async fn with_oracle_identity(identity: serde_json::Value) -> Self {
        let endpoints = Self::without_oracle_identity().await;
        endpoints.oracle_answers("getNetwork", identity).await;
        endpoints
    }

    /// A primary that reports the mainnet passphrase and an oracle with no
    /// `getNetwork` answer yet.
    async fn without_oracle_identity() -> Self {
        let endpoints = Self {
            primary: MockServer::start().await,
            primary_counts: MethodCounts::default(),
            oracle: MockServer::start().await,
            oracle_counts: MethodCounts::default(),
        };
        endpoints
            .primary_answers("getNetwork", get_network_result(MAINNET_PASSPHRASE))
            .await;
        endpoints
    }

    /// A primary that reports the mainnet passphrase and an oracle that
    /// reports it after `delay`, failing its first `getNetwork` with HTTP 500
    /// when `fail_first` is set.
    async fn with_oracle_identity_after(delay: std::time::Duration, fail_first: bool) -> Self {
        let endpoints = Self::without_oracle_identity().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({ "method": "getNetwork" })))
            .respond_with(IdentityResponder {
                counts: endpoints.oracle_counts.clone(),
                delay,
                fail_next: std::sync::atomic::AtomicBool::new(fail_first),
            })
            .mount(&endpoints.oracle)
            .await;
        endpoints
    }

    /// The requests the primary and the oracle received together.
    async fn requests_sent(&self) -> usize {
        self.primary.received_requests().await.unwrap().len()
            + self.oracle.received_requests().await.unwrap().len()
    }

    async fn primary_answers(&self, rpc_method: &str, result: serde_json::Value) {
        mount(&self.primary, rpc_method, result, &self.primary_counts).await;
    }

    async fn oracle_answers(&self, rpc_method: &str, result: serde_json::Value) {
        mount(&self.oracle, rpc_method, result, &self.oracle_counts).await;
    }

    fn clients(&self) -> (StellarRpcClient, StellarRpcClient) {
        (
            StellarRpcClient::new(&self.primary.uri()).unwrap(),
            StellarRpcClient::new(&self.oracle.uri()).unwrap(),
        )
    }
}

/// Answers `getNetwork` with the mainnet identity after `delay`, failing
/// the next request with HTTP 500 while `fail_next` is set, and records each
/// request.
struct IdentityResponder {
    counts: MethodCounts,
    delay: std::time::Duration,
    fail_next: std::sync::atomic::AtomicBool,
}

impl Respond for IdentityResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.counts
            .calls
            .lock()
            .unwrap()
            .push("getNetwork".to_owned());
        let failing = self
            .fail_next
            .swap(false, std::sync::atomic::Ordering::SeqCst);
        if failing {
            return ResponseTemplate::new(500);
        }
        let id = serde_json::from_slice::<serde_json::Value>(&request.body)
            .ok()
            .and_then(|body| body.get("id").cloned())
            .unwrap_or_else(|| json!(1));
        ResponseTemplate::new(200)
            .set_body_json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": get_network_result(MAINNET_PASSPHRASE),
            }))
            .insert_header("content-type", "application/json")
            .set_delay(self.delay)
    }
}

/// A primary that reports `FAILED` for a transaction the oracle reports
/// applied settles nothing on its own word: the oracle's `SUCCESS`
/// confirms the spend.
#[tokio::test]
#[serial]
async fn a_mainnet_failed_answer_the_oracle_reports_applied_confirms() {
    let now = now_ms();
    let fx = mainnet_fixture("reconcile-mainnet-oracle-success");
    let source = account_id_for_seed([0x41; 32]);
    let res = reservation(&"b1".repeat(32), &source, 7, due_since(now));
    fx.take_reservation(now, &res, 500);

    let endpoints = Endpoints::start().await;
    endpoints
        .primary_answers("getTransaction", get_transaction_failed())
        .await;
    endpoints
        .oracle_answers("getTransaction", get_transaction("SUCCESS"))
        .await;
    let (primary, oracle) = endpoints.clients();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &primary,
            Some(&oracle),
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.confirmed, 1, "{report:?}");
    assert_eq!(report.released, 0, "{report:?}");
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Success
    );
    assert_eq!(endpoints.oracle_counts.count("getTransaction"), 1);
}

/// The oracle's own `FAILED` releases the reservation, under the oracle's
/// failure code: the primary's `txMALFORMED` would read `ledger.op_failed`,
/// the oracle's `txBAD_SEQ` reads `submission.sequence_number_stale`.
#[tokio::test]
#[serial]
async fn a_mainnet_failed_answer_the_oracle_confirms_releases() {
    let now = now_ms();
    let fx = mainnet_fixture("reconcile-mainnet-oracle-failed");
    let source = account_id_for_seed([0x42; 32]);
    let res = reservation(&"b2".repeat(32), &source, 7, due_since(now));
    fx.take_reservation(now, &res, 500);

    let endpoints = Endpoints::start().await;
    endpoints
        .primary_answers("getTransaction", get_transaction_failed())
        .await;
    endpoints
        .oracle_answers(
            "getTransaction",
            get_transaction_failed_with(stellar_xdr::TransactionResultResult::TxBadSeq),
        )
        .await;
    let (primary, oracle) = endpoints.clients();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &primary,
            Some(&oracle),
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.released, 1, "{report:?}");
    assert_eq!(fx.window_total(now), (0, 0));
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Failed {
            code: "submission.sequence_number_stale".to_owned()
        },
        "the receipt carries the oracle's code"
    );
}

/// A primary `FAILED` with an oracle that cannot answer, and with no oracle
/// at all, keeps the reservation and reports why.
#[tokio::test]
#[serial]
async fn a_mainnet_failed_answer_without_an_oracle_answer_stands() {
    for with_oracle in [true, false] {
        let now = now_ms();
        let fx = mainnet_fixture(if with_oracle {
            "reconcile-mainnet-oracle-down"
        } else {
            "reconcile-mainnet-no-oracle"
        });
        let source = account_id_for_seed([0x43; 32]);
        let res = reservation(&"b3".repeat(32), &source, 7, due_since(now));
        fx.take_reservation(now, &res, 500);

        // The oracle answers nothing it is asked.
        let endpoints = Endpoints::start().await;
        endpoints
            .primary_answers("getTransaction", get_transaction_failed())
            .await;
        let (primary, oracle) = endpoints.clients();

        let report = fx
            .window
            .reconcile_due(
                &fx.profile,
                &primary,
                with_oracle.then_some(&oracle),
                Some(&fx.receipts),
                now,
                RECONCILE_BUDGET,
            )
            .await
            .unwrap();

        assert_eq!(report.kept_pending, 1, "{report:?}");
        assert_eq!(report.released, 0, "{report:?}");
        assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
        assert_eq!(
            fx.receipts.get(&res.id).unwrap().unwrap().status,
            ReceiptStatus::Pending
        );
        let failure = report
            .endpoint_failure
            .expect("the missing witness is reported");
        if with_oracle {
            assert_eq!(failure.kind, ReconcileFailureKind::Unreachable);
            assert_eq!(
                failure.endpoint,
                endpoints.oracle.uri(),
                "the oracle is named"
            );
            assert!(
                failure.reason.starts_with("getTransaction failed: "),
                "{failure:?}"
            );
        } else {
            assert_eq!(failure.kind, ReconcileFailureKind::OracleNotConfigured);
            assert_eq!(
                stellar_agent_core::error::WalletError::Network(failure.to_network_error()).code(),
                "network.witness_unavailable"
            );
        }
    }
}

/// The release rule reads the oracle's account sequence, not the primary's:
/// a sequence the primary reports consumed releases nothing while the oracle
/// reports it unconsumed.
#[tokio::test]
#[serial]
async fn a_mainnet_release_reads_the_sequence_from_the_oracle() {
    let now = now_ms();
    let fx = mainnet_fixture("reconcile-mainnet-oracle-sequence");
    let source = account_id_for_seed([0x44; 32]);
    let res = reservation(&"b4".repeat(32), &source, 5, due_since(now));
    fx.take_reservation(now, &res, 500);

    let endpoints = Endpoints::start().await;
    endpoints
        .primary_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    endpoints.primary_answers("getHealth", health(1)).await;
    endpoints
        .primary_answers("getLedgers", ledgers(now / 1_000, 1))
        .await;
    endpoints
        .primary_answers("getLedgerEntries", account_at_sequence(&source, 9))
        .await;
    endpoints
        .oracle_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    endpoints.oracle_answers("getHealth", health(1)).await;
    endpoints
        .oracle_answers("getLedgers", ledgers(now / 1_000, 1))
        .await;
    endpoints
        .oracle_answers("getLedgerEntries", account_at_sequence(&source, 3))
        .await;
    let (primary, oracle) = endpoints.clients();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &primary,
            Some(&oracle),
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.kept_pending, 1, "{report:?}");
    assert_eq!(report.released, 0, "{report:?}");
    assert_eq!(report.endpoint_failure, None, "{report:?}");
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
    assert_eq!(endpoints.oracle_counts.count("getLedgerEntries"), 1);
    assert_eq!(
        endpoints.primary_counts.count("getLedgerEntries"),
        0,
        "the primary's sequence is never read"
    );
    assert_eq!(
        endpoints.primary_counts.count("getHealth"),
        0,
        "nor its retention"
    );
}

/// The oracle's `NOT_FOUND`, asked again after the evidence, releases once
/// the time bound has passed on the oracle's latest ledger.
#[tokio::test]
#[serial]
async fn a_mainnet_release_on_the_oracle_time_bound() {
    let now = now_ms();
    let fx = mainnet_fixture("reconcile-mainnet-oracle-time");
    let source = account_id_for_seed([0x45; 32]);
    let mut res = reservation(&"b5".repeat(32), &source, 5, due_since(now));
    res.max_time = now / 1_000 - 10;
    fx.take_reservation(now, &res, 500);

    let endpoints = Endpoints::start().await;
    endpoints
        .primary_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    endpoints
        .oracle_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    endpoints.oracle_answers("getHealth", health(1)).await;
    endpoints
        .oracle_answers("getLedgers", ledgers(now / 1_000, 1))
        .await;
    endpoints
        .oracle_answers("getLedgerEntries", account_at_sequence(&source, 9))
        .await;
    let (primary, oracle) = endpoints.clients();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &primary,
            Some(&oracle),
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.released, 1, "{report:?}");
    assert_eq!(fx.window_total(now), (0, 0));
    assert_eq!(
        report.settled[0].release_code,
        Some(ReleaseEvidence::TimeBoundPassed)
    );
    assert_eq!(
        endpoints.oracle_counts.count("getTransaction"),
        2,
        "the oracle's first answer and its fresh one"
    );
    assert_eq!(endpoints.primary_counts.count("getTransaction"), 1);
}

/// `tx status` settles a mainnet reservation on the oracle's consumed
/// sequence within its one-reservation allowance: the primary's transaction
/// answer, the oracle's identity, its transaction answer, its retention and
/// chain time, its account and its fresh answer.
#[tokio::test]
#[serial]
async fn a_named_mainnet_reservation_releases_on_the_oracle_sequence() {
    let now = now_ms();
    let fx = mainnet_fixture("reconcile-mainnet-oracle-one");
    let source = account_id_for_seed([0x46; 32]);
    let res = reservation(&"b6".repeat(32), &source, 5, due_since(now));
    fx.take_reservation(now, &res, 500);

    let endpoints = Endpoints::start().await;
    endpoints
        .primary_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    endpoints
        .oracle_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    endpoints.oracle_answers("getHealth", health(1)).await;
    endpoints
        .oracle_answers("getLedgers", ledgers(now / 1_000, 1))
        .await;
    endpoints
        .oracle_answers("getLedgerEntries", account_at_sequence(&source, 9))
        .await;
    let (primary, oracle) = endpoints.clients();

    let report = fx
        .window
        .reconcile_one(
            &fx.profile,
            &primary,
            Some(&oracle),
            Some(&fx.receipts),
            &res.id,
            now,
        )
        .await
        .unwrap();

    assert_eq!(report.released, 1, "{report:?}");
    assert_eq!(report.rpc_calls, 7, "{report:?}");
    assert_eq!(
        report.settled[0].release_code,
        Some(ReleaseEvidence::SequenceConsumed)
    );
    assert_eq!(fx.window_total(now), (0, 0));
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Ambiguous);
    assert_eq!(
        receipt.release_code,
        Some(ReleaseEvidence::SequenceConsumed)
    );
}

/// Mounts on the oracle every answer the `NOT_FOUND` release rule would
/// release `source`'s reservation on: `NOT_FOUND`, a retention floor below
/// the submission ledger, a chain time past every time bound and a consumed
/// sequence.
async fn oracle_would_release(endpoints: &Endpoints, now: u64, source: &str) {
    endpoints
        .oracle_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    endpoints.oracle_answers("getHealth", health(1)).await;
    endpoints
        .oracle_answers("getLedgers", ledgers(now / 1_000, 1))
        .await;
    endpoints
        .oracle_answers("getLedgerEntries", account_at_sequence(source, 9))
        .await;
}

/// An oracle that reports the testnet passphrase is no witness for a
/// mainnet reservation, however its answers read: its `NOT_FOUND` with a
/// consumed sequence and a passed time bound releases nothing, its
/// transaction is never asked, and the pass checks its identity once for
/// both reservations.
#[tokio::test]
#[serial]
async fn a_mainnet_oracle_on_another_network_settles_nothing() {
    let now = now_ms();
    let fx = mainnet_fixture("reconcile-mainnet-oracle-testnet");
    let source = account_id_for_seed([0x47; 32]);
    let mut first = reservation(&"b7".repeat(32), &source, 5, due_since(now));
    first.max_time = now / 1_000 - 10;
    let second = reservation(&"b8".repeat(32), &source, 6, due_since(now));
    fx.take_reservation(now, &first, 500);
    fx.take_reservation(now, &second, 300);

    let endpoints = Endpoints::with_oracle_identity(get_network_result(TESTNET_PASSPHRASE)).await;
    endpoints
        .primary_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    oracle_would_release(&endpoints, now, &source).await;
    let (primary, oracle) = endpoints.clients();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &primary,
            Some(&oracle),
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();

    assert_eq!(report.kept_pending, 2, "{report:?}");
    assert_eq!(report.released, 0, "{report:?}");
    assert_eq!(fx.window_total(now), (800, 2), "the debits stay");
    for res in [&first, &second] {
        assert_eq!(
            fx.receipts.get(&res.id).unwrap().unwrap().status,
            ReceiptStatus::Pending
        );
    }
    let failure = report
        .endpoint_failure
        .expect("the unverified oracle is reported");
    assert_eq!(failure.kind, ReconcileFailureKind::OracleNetworkMismatch);
    assert_eq!(
        failure.endpoint,
        endpoints.oracle.uri(),
        "the oracle is named"
    );
    assert_witness_reason(&failure, &endpoints, "IdentityNetworkMismatch");
    assert_eq!(
        endpoints.oracle_counts.count("getNetwork"),
        1,
        "once per pass"
    );
    assert_eq!(
        endpoints.oracle_counts.count("getTransaction"),
        0,
        "an unverified oracle is never asked about the transaction"
    );
    assert_eq!(endpoints.oracle_counts.count("getLedgerEntries"), 0);
}

/// An oracle whose identity cannot be read is no witness either: its
/// `NOT_FOUND` with a consumed sequence releases nothing, and the pass
/// reports the unread identity.
#[tokio::test]
#[serial]
async fn a_mainnet_oracle_whose_identity_cannot_be_read_settles_nothing() {
    let now = now_ms();
    let fx = mainnet_fixture("reconcile-mainnet-oracle-anonymous");
    let source = account_id_for_seed([0x48; 32]);
    let res = reservation(&"b9".repeat(32), &source, 5, due_since(now));
    fx.take_reservation(now, &res, 500);

    // A `getNetwork` answer without a passphrase does not decode.
    let endpoints = Endpoints::with_oracle_identity(json!({ "protocolVersion": 29 })).await;
    endpoints
        .primary_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    oracle_would_release(&endpoints, now, &source).await;
    let (primary, oracle) = endpoints.clients();

    let report = fx
        .window
        .reconcile_one(
            &fx.profile,
            &primary,
            Some(&oracle),
            Some(&fx.receipts),
            &res.id,
            now,
        )
        .await
        .unwrap();

    assert_eq!(report.kept_pending, 1, "{report:?}");
    assert_eq!(report.released, 0, "{report:?}");
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
    let failure = report
        .endpoint_failure
        .expect("the unread identity is reported");
    assert_eq!(
        failure.kind,
        ReconcileFailureKind::OracleIdentityUnavailable
    );
    assert_eq!(
        failure.endpoint,
        endpoints.oracle.uri(),
        "the oracle is named"
    );
    assert_eq!(
        stellar_agent_core::error::WalletError::Network(failure.to_network_error()).code(),
        "network.witness_unavailable"
    );
    assert_eq!(endpoints.oracle_counts.count("getTransaction"), 0);
}

/// Asserts that `failure` reports `network.witness_unavailable` with the
/// typed reason `expected` naming the oracle's authority.
fn assert_witness_reason(failure: &ReconcileFailure, endpoints: &Endpoints, expected: &str) {
    use stellar_agent_core::error::{
        NetworkError, WalletError, WitnessUnavailableReason as Reason,
    };
    let error = failure.to_network_error();
    let (reason, authority) = match &error {
        NetworkError::WitnessUnavailable {
            reason: Reason::IdentityNetworkMismatch { authority },
        } => ("IdentityNetworkMismatch", authority),
        NetworkError::WitnessUnavailable {
            reason: Reason::IdentityProtocolUnsupported { authority },
        } => ("IdentityProtocolUnsupported", authority),
        NetworkError::WitnessUnavailable {
            reason: Reason::IdentityUnavailable { authority },
        } => ("IdentityUnavailable", authority),
        other => panic!("expected an oracle identity reason, got {other:?}"),
    };
    assert_eq!(reason, expected, "{error}");
    assert_eq!(authority, &endpoints.oracle.uri(), "the oracle is named");
    assert_eq!(
        WalletError::Network(error).code(),
        "network.witness_unavailable"
    );
}

/// An oracle that reports mainnet under a protocol version the protocol rule
/// refuses for mainnet is no witness: its `NOT_FOUND` with a consumed
/// sequence releases nothing, and the pass reports the unsupported protocol
/// under its own kind and reason.
#[tokio::test]
#[serial]
async fn a_mainnet_oracle_on_an_unsupported_protocol_settles_nothing() {
    let now = now_ms();
    let fx = mainnet_fixture("reconcile-mainnet-oracle-protocol");
    let source = account_id_for_seed([0x49; 32]);
    let res = reservation(&"ba".repeat(32), &source, 5, due_since(now));
    fx.take_reservation(now, &res, 500);

    let mut identity = get_network_result(MAINNET_PASSPHRASE);
    identity["protocolVersion"] = json!(1);
    let endpoints = Endpoints::with_oracle_identity(identity).await;
    endpoints
        .primary_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    oracle_would_release(&endpoints, now, &source).await;
    let (primary, oracle) = endpoints.clients();

    let report = fx
        .window
        .reconcile_one(
            &fx.profile,
            &primary,
            Some(&oracle),
            Some(&fx.receipts),
            &res.id,
            now,
        )
        .await
        .unwrap();

    assert_eq!(report.kept_pending, 1, "{report:?}");
    assert_eq!(report.released, 0, "{report:?}");
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
    let failure = report
        .endpoint_failure
        .expect("the unsupported protocol is reported");
    assert_eq!(
        failure.kind,
        ReconcileFailureKind::OracleProtocolUnsupported
    );
    assert_witness_reason(&failure, &endpoints, "IdentityProtocolUnsupported");
    assert_eq!(endpoints.oracle_counts.count("getTransaction"), 0);
}

/// The pass reads the oracle's identity with one request and does not
/// retry it, so every request the pass sends is one it counts: an identity
/// request that fails once keeps the reservation within the allowance, and
/// the next pass, whose identity request succeeds, releases it on the
/// consumed sequence with its own count still equal to the requests sent.
#[tokio::test]
#[serial]
async fn an_oracle_identity_request_that_fails_is_counted_and_not_retried() {
    let now = now_ms();
    let fx = mainnet_fixture("reconcile-mainnet-oracle-identity-500");
    let source = account_id_for_seed([0x4a; 32]);
    let res = reservation(&"bb".repeat(32), &source, 5, due_since(now));
    fx.take_reservation(now, &res, 500);

    let endpoints = Endpoints::with_oracle_identity_after(std::time::Duration::ZERO, true).await;
    endpoints
        .primary_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    oracle_would_release(&endpoints, now, &source).await;
    let (primary, oracle) = endpoints.clients();
    let allowance = 4 + 3;

    let first = fx
        .window
        .reconcile_one(
            &fx.profile,
            &primary,
            Some(&oracle),
            Some(&fx.receipts),
            &res.id,
            now,
        )
        .await
        .unwrap();

    let sent_first = endpoints.requests_sent().await;
    assert_eq!(first.rpc_calls, sent_first, "{first:?}");
    assert!(sent_first <= allowance, "{sent_first}");
    assert_eq!(first.kept_pending, 1, "{first:?}");
    assert_eq!(first.released, 0, "{first:?}");
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
    let failure = first
        .endpoint_failure
        .expect("the failed identity request is reported");
    assert_eq!(
        failure.kind,
        ReconcileFailureKind::OracleIdentityUnavailable
    );
    assert_witness_reason(&failure, &endpoints, "IdentityUnavailable");
    assert_eq!(endpoints.oracle_counts.count("getNetwork"), 1, "no retry");

    let second = fx
        .window
        .reconcile_one(
            &fx.profile,
            &primary,
            Some(&oracle),
            Some(&fx.receipts),
            &res.id,
            now,
        )
        .await
        .unwrap();

    let sent_second = endpoints.requests_sent().await - sent_first;
    assert_eq!(second.rpc_calls, sent_second, "{second:?}");
    assert!(sent_second <= allowance, "{sent_second}");
    assert_eq!(second.released, 1, "{second:?}");
    assert_eq!(
        second.settled[0].release_code,
        Some(ReleaseEvidence::SequenceConsumed)
    );
    assert_eq!(fx.window_total(now), (0, 0));
}

/// An oracle whose identity answer arrives late is no witness, and the pass
/// does not wait for it: the identity request ends at the pass's own
/// two-second bound, the reservation stands, and the oracle's transaction is
/// never asked.
#[tokio::test]
#[serial]
async fn a_mainnet_oracle_whose_identity_answers_late_settles_nothing() {
    const IDENTITY_BOUND: std::time::Duration = std::time::Duration::from_secs(2);
    let now = now_ms();
    let fx = mainnet_fixture("reconcile-mainnet-oracle-identity-late");
    let source = account_id_for_seed([0x4b; 32]);
    let res = reservation(&"bc".repeat(32), &source, 5, due_since(now));
    fx.take_reservation(now, &res, 500);

    let endpoints =
        Endpoints::with_oracle_identity_after(std::time::Duration::from_secs(30), false).await;
    endpoints
        .primary_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    oracle_would_release(&endpoints, now, &source).await;
    let (primary, oracle) = endpoints.clients();

    let started = std::time::Instant::now();
    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &primary,
            Some(&oracle),
            Some(&fx.receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed < IDENTITY_BOUND + std::time::Duration::from_millis(1500),
        "the identity bound ends the wait: {elapsed:?}"
    );
    assert_eq!(report.kept_pending, 1, "{report:?}");
    assert_eq!(report.released, 0, "{report:?}");
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
    let failure = report
        .endpoint_failure
        .expect("the unanswered identity is reported");
    assert_eq!(
        failure.kind,
        ReconcileFailureKind::OracleIdentityUnavailable
    );
    assert_eq!(endpoints.oracle_counts.count("getTransaction"), 0);
}
