//! The rules a reconciliation pass applies to open spending-window
//! reservations, against a mocked Stellar RPC endpoint.
//!
//! A reservation is taken before a transaction is sent and counts against the
//! operator's caps while it stands. These tests pin what a pass records, and
//! that no endpoint report frees possible spending:
//!
//! - `SUCCESS` is recorded as a report; the spend keeps counting through the
//!   transaction's accounting horizon and is never dated before its
//!   reservation was taken.
//! - A reported failure or missing transaction does not release possible
//!   spending: `FAILED`, and `NOT_FOUND` with a consumed sequence or a passed
//!   time bound, keep the reservation, leave the receipt pending and owe no
//!   failed row.
//! - A `NOT_FOUND` from an endpoint whose retention window no longer covers the
//!   submission proves nothing, so the reservation stands and the receipt is
//!   marked ambiguous.
//! - A reservation ends at its accounting horizon, its execution bound plus
//!   the window's duration, or by an operator's acknowledged clear.
//! - A pass is bounded: at most `RECONCILE_BUDGET` reservations, oldest first,
//!   none younger than `RECONCILE_MIN_AGE_MS`.
//! - A transport error changes nothing, and the pass reports the first
//!   endpoint failure it met.
//! - The receipt is never evidence: a release code it carries releases
//!   nothing.
//! - On a mainnet profile the primary's `FAILED` and `NOT_FOUND` decide
//!   nothing alone: the oracle's own answers, retention, chain time and
//!   account sequence are the ones read.
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
use stellar_agent_core::policy::state_lock::window_lock_path;
use stellar_agent_core::policy::v1::criteria::state_store::{
    PolicyStateStore, StateKey, WindowEntry, WindowLimit,
};
use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore, ReleaseEvidence};
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::policy_state::{
    PersistedWindowStore, RECONCILE_BUDGET, RECONCILE_MIN_AGE_MS, ReconcileReport, SubmissionHold,
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
        chain_scope: stellar_agent_network::policy_state::ChainScope::for_chain(
            stellar_agent_core::profile::caip2::Caip2::Testnet,
        ),
        id: id.to_owned(),
        tx_hash: id.to_owned(),
        source: source.to_owned(),
        sequence,
        max_time: 0,
        pending_since_ms,
        submission_ledger: SUBMISSION_LEDGER,
        submission_anchor: None,
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
        let reservation = &SubmissionHold {
            chain_scope: stellar_agent_network::policy_state::ChainScope::for_chain(
                self.profile.chain_id,
            ),
            ..reservation.clone()
        };
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

/// A `SUCCESS` report keeps the reservation counted as possible spending and
/// records the report on the receipt; it owes no authenticated settled row.
#[tokio::test]
#[serial]
async fn success_report_keeps_the_reservation_and_finalizes_the_receipt() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

    assert_eq!(
        report.confirmed, 1,
        "a SUCCESS answer is counted as a report: {report:?}"
    );
    assert!(
        report.settled.is_empty(),
        "endpoint reports owe no authenticated chain fact"
    );
    assert!(
        !fx.window
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
/// `TransactionMeta` with discriminant 99) is recorded as a report from its
/// status and ledger, and the reservation keeps counting.
#[tokio::test]
#[serial]
async fn success_with_undecodable_meta_keeps_the_reservation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
        "a SUCCESS answer is counted whatever its meta: {report:?}"
    );
    assert!(
        !fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty()
    );
    assert_eq!(fx.window_total(now), (500, 1));
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Success);
    assert_eq!(receipt.ledger, Some(1_500));
}

/// A reported close time does not backdate the spend: an untimed reservation
/// taken two days ago, whose reported ledger closed just after, keeps counting
/// now as well as inside the window of that ledger.
#[tokio::test]
#[serial]
async fn success_report_does_not_backdate_spend() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

    assert_eq!(
        report.confirmed, 1,
        "a SUCCESS answer is counted as a report: {report:?}"
    );
    assert!(
        !fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fx.window_total(now),
        (500, 1),
        "untimed reported success retains possible spending"
    );
    assert_eq!(
        fx.window_total(two_days_ago * 1_000),
        (500, 1),
        "the same spend counts inside the window of the ledger that applied it"
    );
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Success);
}

/// A `FAILED` report retains the reservation: the receipt stays pending with
/// no release code, and no settled submission owes a failed row.
#[tokio::test]
#[serial]
async fn failed_retains_the_reservation_and_writes_no_failed_row() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

    assert_eq!(report.released, 0);
    assert!(report.settled.is_empty());
    assert_eq!(fx.window_total(now), (500, 1));
    assert_eq!(
        fx.window.pending_reservations(&fx.profile).unwrap().len(),
        1
    );
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Pending);
    assert_eq!(receipt.release_code, None);
    assert_eq!(counts.count("sendTransaction"), 0);
}

/// `NOT_FOUND` with the sequence consumed retains the reservation: absence
/// does not prove that this transaction did not consume the sequence.
#[tokio::test]
#[serial]
async fn not_found_with_a_consumed_sequence_retains_the_reservation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

    assert_eq!(report.released, 0);
    assert!(report.settled.is_empty());
    assert_eq!(fx.window_total(now), (500, 1));
    assert_eq!(
        fx.window.pending_reservations(&fx.profile).unwrap().len(),
        1
    );
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Pending);
    assert_eq!(receipt.release_code, None);
    assert_eq!(counts.count("sendTransaction"), 0);
}

/// Ledger close time strictly past maxTime prompts a fresh answer, and a fresh
/// `NOT_FOUND` keeps the reservation: the transaction may have applied during
/// the observation.
#[tokio::test]
#[serial]
async fn not_found_with_a_passed_time_bound_retains_the_reservation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

    assert_eq!(report.released, 0);
    assert!(report.settled.is_empty());
    assert_eq!(fx.window_total(now), (500, 1));
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Pending);
    assert_eq!(receipt.release_code, None);
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
        "a passed time bound needs no account read"
    );
    assert_eq!(
        counts.count("getTransaction"),
        2,
        "a passed time bound asks for a fresh answer"
    );
    assert_eq!(counts.count("getLedgers"), 1);
    assert_eq!(report.rpc_calls, 4, "both observations consume RPC budget");
}

/// An unconsumed sequence keeps the reservation at the time bound itself:
/// ledger close time must strictly exceed maxTime to rule out application.
#[tokio::test]
#[serial]
async fn not_found_with_an_unconsumed_sequence_keeps_the_reservation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    assert_eq!(open_ids.len(), 8, "every exposure remains held");
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

/// A reservation named by an operator is examined with no budget and no
/// minimum age.
#[tokio::test]
#[serial]
async fn reconcile_one_examines_a_named_reservation_whatever_its_age() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
        "a named reservation is examined whatever its age: {named:?}"
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

/// A blocked window commit leaves the receipt untouched. The next automatic
/// pass commits the expiry on the local horizon alone, its obligation survives
/// a receipt failure, and a projection-only retry rebuilds the receipt without
/// another endpoint call or send.
#[tokio::test]
#[serial]
async fn the_automatic_pass_finishes_a_checkpointed_accounting_expiry() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let now = now_ms();
    let fx = fixture("reconcile-release-checkpoint");
    let source = account_id_for_seed([0x37; 32]);
    let mut res = reservation(&"7c".repeat(32), &source, 1, due_since(now));
    res.max_time = now / 1_000 - 86_401;
    fx.take_reservation(now, &res, 500);
    let held = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(window_lock_path(
            &fx._dir.path().join(format!("{}.window", fx.profile_name)),
            &fx.profile.policy_window_state_key_id,
        ))
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
    assert_eq!(checkpoint.status, ReceiptStatus::Pending);
    assert_eq!(checkpoint.release_code, None, "no receipt checkpoint");
    assert!(
        fx.window
            .owed_accounting_expiries(&fx.profile)
            .unwrap()
            .is_empty()
    );
    drop(held);

    // The horizon has passed on the host clock, so the next pass expires the
    // accounting without asking the endpoint.
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
    // The expiry commits even while the receipt writer is busy.
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
    assert_eq!(report.receipt_write_failed, 1);
    assert_eq!(report.settled.len(), 1);
    let decision_id = report.settled[0].decision_id.clone();
    assert_eq!(fx.receipts.get(&res.id).unwrap().unwrap(), checkpoint);
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty()
    );
    assert_eq!(fx.window_total(now), (0, 0));
    let owed = fx.window.owed_accounting_expiries(&fx.profile).unwrap();
    assert_eq!(owed.unacknowledged, vec![decision_id.clone()]);
    assert_eq!(owed.unprojected, vec![decision_id.clone()]);
    drop(held_receipt);

    let projected = stellar_agent_network::policy_state::project_accounting_expiries(
        &fx.window,
        &fx.profile,
        Some(&fx.receipts),
    )
    .unwrap();
    assert_eq!(projected.projected, 1);
    let rebuilt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(rebuilt.status, ReceiptStatus::Ambiguous);
    assert_eq!(
        rebuilt.release_code,
        Some(ReleaseEvidence::AccountingExpired)
    );
    assert_eq!(
        rebuilt.settlement_decision_id.as_deref(),
        Some(decision_id.as_str())
    );
    assert_eq!(
        fx.window
            .owed_accounting_expiries(&fx.profile)
            .unwrap()
            .unacknowledged,
        vec![decision_id],
        "the audit event stays owed"
    );
    assert_eq!(
        counts.count("getTransaction"),
        0,
        "local accounting expiry needs no endpoint evidence"
    );
    assert_eq!(report.rpc_calls, counts.calls.lock().unwrap().len());
    assert_eq!(report.rpc_calls, 0);
    assert_eq!(counts.count("sendTransaction"), 0);
}

/// Release evidence a receipt recorded does not release a reservation whose
/// submission ledger the endpoint no longer holds: the evidence cannot be
/// found again, so the reservation stands for the operator and the pass
/// reports it retention-expired.
#[tokio::test]
#[serial]
async fn a_checkpointed_evidence_release_beyond_retention_keeps_the_reservation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
        (20, 2),
        "untimed success preserves exposure"
    );
    fx.window
        .apply_accounting_decision(
            &fx.profile,
            fx.window
                .operator_clear_decision(&fx.profile, &fresh, true, true)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        fx.window_total(now + 86_400_000),
        (10, 1),
        "explicit clear removes only its own exposure"
    );
}

/// A reservation without a receipt stands whether or not its sequence is
/// consumed: absence with a consumed sequence proves nothing, so no receipt is
/// restored and the debit keeps counting.
#[tokio::test]
#[serial]
async fn an_orphaned_reservation_stands_after_its_sequence_is_consumed() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    fx.window
        .apply_accounting_decision(
            &fx.profile,
            fx.window
                .operator_clear_decision(&fx.profile, &unconsumed, true, true)
                .unwrap(),
        )
        .unwrap();

    // Sequence 1 is the one the account reports: it is consumed, which does
    // not show that this transaction did not consume it.
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
    assert_eq!(report2.released, 0);
    assert!(report2.settled.is_empty());
    let holds = fx.window.pending_reservations(&fx.profile).unwrap();
    assert_eq!(holds.len(), 1);
    assert_eq!(holds[0].id, consumed);
    assert_eq!(holds[0].source, source);
    assert_eq!(holds[0].sequence, 1);
    assert!(fx.receipts.get(&consumed).unwrap().is_none());
    assert_eq!(fx.window_total(now), (10, 1));
}

/// A local receipt read failure refuses the clear and keeps the reservation
/// counted against the operator's caps without querying the chain.
///
/// The report carries the JSON read error as a receipt failure.
#[tokio::test]
#[serial]
async fn a_local_receipt_read_failure_refuses_clear_and_keeps_the_reservation_counted() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let now = now_ms();
    let fx = fixture("reconcile-unreadable");
    let source = account_id_for_seed([0x24; 32]);
    let id = format!("{:064}", 5_u8);

    // A live reservation with a receipt: a submission that was sent and whose
    // confirmation never arrived.
    fx.take_reservation(now, &reservation(&id, &source, 1, due_since(now)), 10);

    // The receipt file contains invalid JSON.
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
    assert_eq!(report.receipt_write_failed, 1, "{report:?}");
    assert_eq!(report.kept_pending, 0, "{report:?}");
    assert!(
        report
            .receipt_write_error
            .as_deref()
            .is_some_and(|error| error.starts_with("receipt store JSON error")),
        "the report carries the JSON read failure: {report:?}"
    );
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    assert!(report.settled.is_empty());
}

/// Receipt-file loss does not remove the endpoint retention boundary.
#[tokio::test]
#[serial]
async fn lost_receipt_outside_retention_keeps_the_reservation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

/// Before the accounting horizon, invalid ledger times and absence retain
/// exposure.
#[tokio::test]
#[serial]
async fn host_clock_ahead_and_invalid_chain_times_keep_headroom() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
                now + 60_000,
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

/// A fresh answer at an expired bound records a `SUCCESS` report and keeps
/// the reservation on `FAILED`; neither releases it.
#[tokio::test]
#[serial]
async fn time_bound_fresh_answer_records_success_and_retains_failure() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
            assert_eq!(report.released, 0);
            assert_eq!(fx.window_total(now), (51, 1));
            assert_eq!(receipt.status, ReceiptStatus::Pending);
            assert!(report.settled.is_empty());
        }
    }
}

/// An unavailable chain clock closes the time arm while sequence settlement remains usable.
/// The six-second outer deadline bounds the two-second ledger observation.
#[tokio::test]
#[serial]
async fn unavailable_ledgers_leave_sequence_settlement_available() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
        assert_eq!(report.released, 0);
        assert_eq!(report.kept_pending, 1);
        assert_eq!(counts.count("getLedgerEntries"), 1);
    }
}

/// Six receiptless holds beyond retention cannot starve a younger answerable submission.
/// Operator markers retain their identity, debit, and selection state across restart.
#[tokio::test]
#[serial]
async fn orphan_markers_survive_restart_and_free_the_next_pass_budget() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
        .open(window_lock_path(
            &fx._dir.path().join("orphan-marker-failure.window"),
            &fx.profile.policy_window_state_key_id,
        ))
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    assert_eq!(
        report.released, 0,
        "absence after the bound releases nothing"
    );
    assert_eq!(report.kept_pending, 2, "{report:?}");
    assert_eq!(fx.window_total(now), (108, 2));
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

/// Opens the receipt writer lock so every receipt write refuses until the
/// returned file is dropped.
fn hold_receipt_lock(fx: &Fixture) -> std::fs::File {
    let held = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(fx.receipts.lock_file_path().unwrap())
        .unwrap();
    held.try_lock().unwrap();
    held
}

/// Mounts the endpoint answers one reconciliation pass reads.
async fn mount_reconcile_answers(
    server: &MockServer,
    counts: &MethodCounts,
    status: &str,
    now: u64,
    source: &str,
) {
    mount(server, "getTransaction", get_transaction(status), counts).await;
    mount(server, "getHealth", health(1), counts).await;
    mount(server, "getLedgers", ledgers(now / 1_000, 1), counts).await;
    mount(
        server,
        "getLedgerEntries",
        ledger_entries_result_for(&[source]),
        counts,
    )
    .await;
}

/// A reported success waits for its receipt write before the window records it.
#[tokio::test]
#[serial]
async fn a_success_waits_for_its_receipt_and_retries() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let now = now_ms();
    let fx = fixture("reconcile-checkpoint");
    let source = account_id_for_seed([0x36; 32]);
    let res = reservation(&"6a".repeat(32), &source, 1, due_since(now));
    fx.take_reservation(now, &res, 500);
    let before = fx.receipts.get(&res.id).unwrap();
    let held = hold_receipt_lock(&fx);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount_reconcile_answers(&server, &counts, "SUCCESS", now, &source).await;
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
    assert_eq!(retried.confirmed, 1);
    assert!(retried.settled.is_empty(), "a success owes no expiry event");
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Success
    );
    assert_eq!(fx.window_total(now), (500, 1));
    assert!(
        fx.window
            .owed_accounting_expiries(&fx.profile)
            .unwrap()
            .is_empty()
    );
}

/// An accounting expiry commits ahead of its receipt projection: a refused
/// receipt write leaves one committed expiry with one owed identifier, and the
/// retry projects that identifier without a second expiry.
async fn assert_expiry_commits_before_projection(missing: bool) {
    let now = now_ms();
    let fx = fixture("reconcile-expiry-projection");
    let source = account_id_for_seed([0x36; 32]);
    let mut res = reservation(&"6b".repeat(32), &source, 1, due_since(now));
    res.max_time = now / 1000 - 86_401;
    fx.take_reservation(now, &res, 500);
    if missing {
        std::fs::remove_file(&fx.receipt_file).unwrap();
    }
    let before = fx.receipts.get(&res.id).unwrap();
    let held = hold_receipt_lock(&fx);

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount_reconcile_answers(&server, &counts, "NOT_FOUND", now, &source).await;
    mount_send_guard(&server, &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let report = fx
        .window
        .reconcile_one(&fx.profile, &client, None, Some(&fx.receipts), &res.id, now)
        .await
        .unwrap();
    assert_eq!(report.released, 1, "{report:?}");
    assert_eq!(report.receipt_write_failed, 1, "{report:?}");
    let [settled] = report.settled.as_slice() else {
        panic!("one committed expiry: {report:?}");
    };
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty()
    );
    assert_eq!(fx.window_total(now), (0, 0));
    assert_eq!(fx.receipts.get(&res.id).unwrap(), before);
    let owed = fx.window.owed_accounting_expiries(&fx.profile).unwrap();
    assert_eq!(owed.unacknowledged, vec![settled.decision_id.clone()]);
    assert_eq!(owed.unprojected, vec![settled.decision_id.clone()]);
    drop(held);

    let retried = fx
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
    assert_eq!(retried.released, 0, "no second expiry: {retried:?}");
    let projected = stellar_agent_network::policy_state::project_accounting_expiries(
        &fx.window,
        &fx.profile,
        Some(&fx.receipts),
    )
    .unwrap();
    assert_eq!(projected.projected, 1);
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Ambiguous);
    assert_eq!(
        receipt.release_code,
        Some(ReleaseEvidence::AccountingExpired)
    );
    assert_eq!(
        receipt.settlement_decision_id.as_deref(),
        Some(settled.decision_id.as_str())
    );
    let owed = fx.window.owed_accounting_expiries(&fx.profile).unwrap();
    assert_eq!(owed.unacknowledged, vec![settled.decision_id.clone()]);
    assert!(owed.unprojected.is_empty());
    assert_eq!(counts.count("sendTransaction"), 0);
}

/// An accounting expiry commits before its receipt write, which then retries.
#[tokio::test]
#[serial]
async fn an_accounting_expiry_commits_before_its_receipt_and_retries() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    assert_expiry_commits_before_projection(false).await;
}

/// A missing receipt cannot prevent an accounting expiry or lose its owed
/// event; the projection rebuilds the receipt from the committed record.
#[tokio::test]
#[serial]
async fn a_missing_receipt_is_rebuilt_after_accounting_expiry() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    assert_expiry_commits_before_projection(true).await;
}

// ── Confirmed spend is never dated before its reservation ────────────────

/// A `SUCCESS` whose close time is earlier than the reservation itself is
/// not a time the chain can produce: the spend counts from the reservation,
/// so a backdated answer cannot take it out of the window.
#[tokio::test]
#[serial]
async fn a_backdated_success_keeps_the_spend_in_the_window() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
        !fx.window
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

/// The accounting-expiry decision identifier, encoded independently of the
/// production helper: SHA-256 over the label, the length-prefixed CAIP-2
/// chain, the passphrase hash, the length-prefixed reservation, the big-endian
/// generation and the length-prefixed disposition.
fn expected_decision_id(
    chain: &str,
    passphrase: &str,
    reservation: &str,
    generation: u64,
) -> String {
    use sha2::{Digest, Sha256};
    let prefixed = |digest: &mut Sha256, bytes: &[u8]| {
        digest.update(u32::try_from(bytes.len()).unwrap().to_be_bytes());
        digest.update(bytes);
    };
    let mut digest = Sha256::new();
    digest.update(b"stellar-agent-accounting-expiry:v1");
    prefixed(&mut digest, chain.as_bytes());
    digest.update(Sha256::digest(passphrase.as_bytes()));
    prefixed(&mut digest, reservation.as_bytes());
    digest.update(generation.to_be_bytes());
    prefixed(&mut digest, b"accounting_expired");
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The identifier encoding is pinned by one known-answer vector.
#[test]
fn the_decision_id_encoding_has_a_known_answer() {
    assert_eq!(
        expected_decision_id("stellar:testnet", TESTNET_PASSPHRASE, &"ab".repeat(32), 7),
        "c9118296dcb79eefe2dadabf09d0ef8f0037e10aa9bcd08aa5ee8687f1541b93"
    );
}

/// A forged release code yields no audit event of its own: genuine accounting
/// expiry commits its decision, delivery appends exactly one verified
/// `submission_accounting_expired` row under the authenticated identifier, and
/// the projection overwrites the forged code with the accounting code.
#[tokio::test]
#[serial]
#[cfg(feature = "test-hooks")]
async fn authentic_decision_overrides_forged_release_code() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use base64::Engine as _;
    use stellar_agent_core::audit_log::{AuditWriter, EventKind};

    let now = now_ms();
    let _clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(now);
    let mut fx = fixture("reconcile-authentic-expiry");
    let audit_path = fx._dir.path().join("audit").join("log.jsonl");
    fx.profile.audit_log_path = audit_path.clone();
    let coordinate = &fx.profile.audit_log_hash_chain_key_id;
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([5_u8; 32]))
        .unwrap();
    let source = account_id_for_seed([0x19; 32]);
    let mut res = reservation(&"ad".repeat(32), &source, 7, due_since(now));
    res.max_time = now / 1_000 - 86_401;
    fx.take_reservation(now, &res, 500);
    forge_released_receipt(&fx, &res.id, "submission.sequence_consumed");

    let counts = MethodCounts::default();
    let server = MockServer::start().await;
    mount_reconcile_answers(&server, &counts, "NOT_FOUND", now, &source).await;
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
    assert_eq!(report.released, 1, "{report:?}");
    let [settled] = report.settled.as_slice() else {
        panic!("one committed expiry: {report:?}");
    };

    let access = stellar_agent_network::keyring::keyed_audit_access(
        &fx.profile,
        &fx.profile_name,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    )
    .unwrap();
    let mut writer = AuditWriter::open(audit_path.clone(), Some(access)).unwrap();
    let delivered = stellar_agent_network::policy_state::deliver_accounting_expiries(
        &mut writer,
        &fx.window,
        &fx.profile,
        &fx.profile_name,
        Some(&fx.receipts),
    )
    .unwrap();
    assert_eq!(delivered.appended, 1, "{delivered:?}");
    assert_eq!(delivered.acknowledged, 1, "{delivered:?}");
    drop(writer);

    let entries =
        stellar_agent_core::audit_log::test_helpers::verified_audit_entries_from_path(&audit_path);
    let expiries: Vec<_> = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.event_kind,
                EventKind::SubmissionAccountingExpired { .. }
            )
        })
        .collect();
    let [row] = expiries.as_slice() else {
        panic!("exactly one verified expiry row: {entries:?}");
    };
    let EventKind::SubmissionAccountingExpired {
        decision_id,
        generation,
        observed_at_ms,
        accounting_until_ms,
        code,
        chain_outcome,
        ..
    } = &row.event_kind
    else {
        unreachable!("filtered on the kind");
    };
    assert_eq!(row.envelope_hash.as_deref(), Some(res.id.as_str()));
    assert_eq!(code, "submission.accounting_expired");
    assert_eq!(chain_outcome, "unknown");
    assert_eq!(decision_id, &settled.decision_id);
    assert_eq!(
        decision_id,
        &expected_decision_id("stellar:testnet", TESTNET_PASSPHRASE, &res.id, *generation)
    );
    assert_eq!(*observed_at_ms, now);
    assert_eq!(*accounting_until_ms, res.max_time * 1_000 + 86_400_000);
    assert!(
        entries.iter().all(|entry| !matches!(
            entry.event_kind,
            EventKind::ValueActionFailed { .. } | EventKind::ValueActionSubmitted { .. }
        )),
        "no outcome row is written"
    );

    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Ambiguous);
    assert_eq!(
        receipt.release_code,
        Some(ReleaseEvidence::AccountingExpired)
    );
    assert_eq!(
        receipt.settlement_decision_id.as_deref(),
        Some(decision_id.as_str())
    );
    assert!(
        fx.window
            .pending_reservations(&fx.profile)
            .unwrap()
            .is_empty()
    );
    assert!(
        fx.window
            .owed_accounting_expiries(&fx.profile)
            .unwrap()
            .is_empty()
    );
    assert_eq!(counts.count("sendTransaction"), 0);
}

/// A receipt edited to claim a release releases nothing: the pass asks the
/// endpoint, which reports the transaction unknown with its sequence
/// unconsumed and no time bound, so the reservation and its debit stand.
#[tokio::test]
#[serial]
async fn a_forged_release_code_does_not_release_the_reservation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
/// applied settles nothing: a mainnet pass sends no legacy request, the
/// debit stays and the receipt stays pending until recovery decides.
#[tokio::test]
#[serial]
async fn a_mainnet_failed_answer_the_oracle_reports_applied_confirms() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

    assert_no_legacy_settlement(&report, &endpoints).await;
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Pending
    );
}

/// The oracle's own `FAILED`, behind the primary's, retains the reservation:
/// the debit stays and the receipt stays pending.
#[tokio::test]
#[serial]
async fn a_mainnet_failed_answer_the_oracle_confirms_retains_the_reservation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

    assert_eq!(report.released, 0, "{report:?}");
    assert_eq!(fx.window_total(now), (500, 1));
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Pending,
        "the receipt stays pending"
    );
}

/// A primary `FAILED` with an oracle that cannot answer, and with no oracle
/// at all, keeps the reservation without a legacy request.
#[tokio::test]
#[serial]
async fn a_mainnet_failed_answer_without_an_oracle_answer_stands() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
        assert_no_legacy_settlement(&report, &endpoints).await;
        assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
        assert_eq!(
            fx.receipts.get(&res.id).unwrap().unwrap().status,
            ReceiptStatus::Pending
        );
    }
}

/// A consumed sequence on either endpoint settles nothing: neither account
/// nor retention is read, and the reservation stands.
#[tokio::test]
#[serial]
async fn a_mainnet_sequence_observation_reads_the_oracle() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    assert_no_legacy_settlement(&report, &endpoints).await;
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
    for counts in [&endpoints.oracle_counts, &endpoints.primary_counts] {
        assert_eq!(counts.count("getLedgerEntries"), 0);
        assert_eq!(counts.count("getHealth"), 0);
    }
}

/// A passed time bound retains the reservation: the hold and the receipt
/// stand, and no endpoint is asked.
#[tokio::test]
#[serial]
async fn a_mainnet_oracle_time_bound_retains_the_reservation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

    assert_eq!(report.released, 0, "{report:?}");
    assert_eq!(fx.window_total(now), (500, 1));
    assert!(report.settled.is_empty());
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Pending
    );
    assert_no_legacy_settlement(&report, &endpoints).await;
}

/// `tx status` of a mainnet reservation sends no legacy request: the
/// reservation and its pending receipt stand.
#[tokio::test]
#[serial]
async fn a_named_mainnet_reservation_stands_on_the_oracle_sequence() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

    assert_eq!(report.released, 0, "{report:?}");
    assert_no_legacy_settlement(&report, &endpoints).await;
    assert!(report.settled.is_empty());
    assert_eq!(fx.window_total(now), (500, 1));
    let receipt = fx.receipts.get(&res.id).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Pending);
    assert_eq!(receipt.release_code, None);
}

/// Mounts on the oracle every absence observation for `source`'s
/// reservation: `NOT_FOUND`, a retention floor below the submission ledger, a
/// chain time past every time bound and a consumed sequence.
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

/// An oracle that reports the testnet passphrase settles nothing for two
/// mainnet reservations, however its answers read: neither its identity nor
/// its transaction is asked, and both reservations stand.
#[tokio::test]
#[serial]
async fn a_mainnet_oracle_on_another_network_settles_nothing() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    assert_no_legacy_settlement(&report, &endpoints).await;
    assert_eq!(fx.window_total(now), (800, 2), "the debits stay");
    for res in [&first, &second] {
        assert_eq!(
            fx.receipts.get(&res.id).unwrap().unwrap().status,
            ReceiptStatus::Pending
        );
    }
    assert_eq!(endpoints.oracle_counts.count("getNetwork"), 0);
}

/// An oracle whose identity cannot be read settles nothing either: the pass
/// asks neither endpoint and the reservation stands.
#[tokio::test]
#[serial]
async fn a_mainnet_oracle_whose_identity_cannot_be_read_settles_nothing() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    assert_no_legacy_settlement(&report, &endpoints).await;
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
}

/// Asserts that a mainnet pass settled nothing on chain answers: every
/// examined reservation stays pending, neither endpoint received a legacy
/// request, and no endpoint failure is reported.
async fn assert_no_legacy_settlement(report: &ReconcileReport, endpoints: &Endpoints) {
    assert_eq!(report.kept_pending, report.examined, "{report:?}");
    assert_eq!(report.confirmed, 0, "{report:?}");
    assert_eq!(report.released, 0, "{report:?}");
    assert!(report.settled.is_empty(), "{report:?}");
    assert_eq!(report.rpc_calls, 0, "{report:?}");
    assert_eq!(report.endpoint_failure, None, "{report:?}");
    assert_eq!(endpoints.requests_sent().await, 0, "no legacy request");
}

/// An oracle that reports an unsupported protocol settles nothing: the pass
/// asks neither endpoint and the reservation stands.
#[tokio::test]
#[serial]
async fn a_mainnet_oracle_on_an_unsupported_protocol_settles_nothing() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    assert_no_legacy_settlement(&report, &endpoints).await;
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
}

/// Two passes over a mainnet reservation whose oracle identity fails once
/// send no request and count none, and the reservation stands after each.
#[tokio::test]
#[serial]
async fn an_oracle_identity_request_that_fails_is_counted_and_not_retried() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

    assert_eq!(first.kept_pending, 1, "{first:?}");
    assert_no_legacy_settlement(&first, &endpoints).await;
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");

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

    assert_no_legacy_settlement(&second, &endpoints).await;
    assert_eq!(fx.window_total(now), (500, 1));
}

/// An oracle whose identity answer would arrive late holds nothing up: the
/// pass asks no endpoint, returns within the bound and the reservation stands.
#[tokio::test]
#[serial]
async fn a_mainnet_oracle_whose_identity_answers_late_settles_nothing() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
        "the pass does not wait for the oracle: {elapsed:?}"
    );
    assert_eq!(report.kept_pending, 1, "{report:?}");
    assert_no_legacy_settlement(&report, &endpoints).await;
    assert_eq!(fx.window_total(now), (500, 1), "the debit stays");
}

/// An edited profile cannot select weaker settlement trust for an admitted debit.
#[tokio::test]
#[serial]
async fn chain_flip_refuses_before_reconciliation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = mainnet_fixture("chain-flip");
    let now = now_ms();
    let hold = reservation(
        &"ca".repeat(32),
        &account_id_for_seed([0x33; 32]),
        7,
        due_since(now),
    );
    fx.take_reservation(now, &hold, 500);
    let before = std::fs::read(fx._dir.path().join("chain-flip.window")).unwrap();
    let receipt = std::fs::read(&fx.receipt_file).unwrap();
    let primary = MockServer::start().await;
    let oracle = MockServer::start().await;
    let counts = MethodCounts::default();
    mount(
        &primary,
        "getTransaction",
        get_transaction("FAILED"),
        &counts,
    )
    .await;
    mount(
        &oracle,
        "getTransaction",
        get_transaction("FAILED"),
        &counts,
    )
    .await;
    let client = StellarRpcClient::new(&primary.uri()).unwrap();
    let witness = StellarRpcClient::new(&oracle.uri()).unwrap();
    let mut edited = fx.profile.clone();
    edited.chain_id = stellar_agent_core::profile::caip2::Caip2::Testnet;
    for result in [
        fx.window
            .reconcile_one(
                &edited,
                &client,
                Some(&witness),
                Some(&fx.receipts),
                &hold.id,
                now,
            )
            .await,
        fx.window
            .reconcile_due(&edited, &client, Some(&witness), Some(&fx.receipts), now, 5)
            .await,
    ] {
        assert!(matches!(
            result,
            Err(stellar_agent_network::policy_state::WindowStoreError::ChainMismatch)
        ));
    }
    assert!(primary.received_requests().await.unwrap().is_empty());
    assert!(oracle.received_requests().await.unwrap().is_empty());
    assert_eq!(
        std::fs::read(fx._dir.path().join("chain-flip.window")).unwrap(),
        before
    );
    assert_eq!(std::fs::read(&fx.receipt_file).unwrap(), receipt);
    assert_eq!(fx.window_total(now), (500, 1));
}

#[tokio::test]
#[serial]
async fn inflated_primary_anchor_and_delayed_absence_retain_exposure() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let now = now_ms();
    let fx = mainnet_fixture("inflated-anchor");
    let source = account_id_for_seed([0x31; 32]);
    let mut hold = reservation(&"a1".repeat(32), &source, 1, due_since(now));
    hold.submission_ledger = 90_000;
    fx.take_reservation(now, &hold, 500);
    let endpoints = Endpoints::start().await;
    endpoints
        .primary_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    endpoints
        .oracle_answers("getTransaction", get_transaction("NOT_FOUND"))
        .await;
    // The oracle retains ledgers 50 000 to 60 000, so the primary's inflated
    // submission ledger sits above its retention floor.
    endpoints
        .oracle_answers(
            "getHealth",
            json!({
                "status": "healthy",
                "latestLedger": 60_000,
                "oldestLedger": 50_000,
                "ledgerRetentionWindow": 10_000,
            }),
        )
        .await;
    endpoints
        .oracle_answers(
            "getLedgers",
            json!({"latestLedger": 60_000, "latestLedgerCloseTime": (now / 1000).to_string(),
                "oldestLedger": 50_000, "oldestLedgerCloseTime": 1,
                "cursor": "60000", "ledgers": []}),
        )
        .await;
    endpoints
        .oracle_answers("getLedgerEntries", account_at_sequence(&source, 10))
        .await;
    let (primary, oracle) = endpoints.clients();
    let report = fx
        .window
        .reconcile_one(
            &fx.profile,
            &primary,
            Some(&oracle),
            Some(&fx.receipts),
            &hold.id,
            now + 86_400_000,
        )
        .await
        .unwrap();
    assert_eq!(report.released, 0);
    assert!(report.settled.is_empty());
    assert_eq!(fx.window_total(now + 86_400_000), (500, 1));
    assert_eq!(
        fx.receipts.get(&hold.id).unwrap().unwrap().status,
        ReceiptStatus::Pending
    );
    assert!(
        fx.window.pending_reservations(&fx.profile).unwrap()[0]
            .submission_anchor
            .is_none()
    );
}

#[cfg(feature = "test-hooks")]
async fn reported_success_keeps_short_window(delayed: bool) {
    let now = now_ms();
    let fx = fixture("reported-success-window");
    let source = account_id_for_seed([0x32; 32]);
    let mut hold = reservation(&"a2".repeat(32), &source, 1, now);
    hold.max_time = now / 1000 + 120;
    let bound = hold.max_time * 1000;
    let key = StateKey::new(&fx.profile_name, 1, "native", 60);
    fx.window
        .record_pending(
            &fx.profile,
            &[WindowEntry::new(key.clone(), now, 500, window_limit())],
            &hold,
        )
        .unwrap();
    fx.receipts
        .try_begin(
            &hold.id,
            &hold.tx_hash,
            &hold.source,
            hold.sequence,
            hold.max_time,
            1000,
        )
        .unwrap();
    let server = MockServer::start().await;
    let counts = MethodCounts::default();
    let mut answer = get_transaction("SUCCESS");
    answer["createdAt"] = json!((now / 1000).to_string());
    mount(&server, "getTransaction", answer, &counts).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let observed = if delayed { bound + 30_000 } else { now };
    let _clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(observed);
    let report = fx
        .window
        .reconcile_one(
            &fx.profile,
            &client,
            None,
            Some(&fx.receipts),
            &hold.id,
            observed,
        )
        .await
        .unwrap();
    assert_eq!(report.confirmed, 1);
    assert!(report.settled.is_empty());
    let state = PolicyStateStore::new();
    fx.window
        .load_into(&fx.profile_name, &fx.profile, &state)
        .unwrap();
    let until = observed.max(bound) + 60_000;
    assert_eq!(state.query_window(&key, until).unwrap(), (500, 1));
    assert_eq!(state.query_window(&key, until + 1).unwrap(), (0, 0));
}

#[tokio::test]
#[serial]
#[cfg(feature = "test-hooks")]
async fn delayed_success_does_not_backdate_accounting() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    reported_success_keeps_short_window(true).await;
}

#[tokio::test]
#[serial]
#[cfg(feature = "test-hooks")]
async fn early_success_retains_deadline_plus_short_window() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    reported_success_keeps_short_window(false).await;
}

async fn assert_negative_answers(answers: Vec<serde_json::Value>) {
    for (index, answer) in answers.into_iter().enumerate() {
        let now = now_ms();
        let fx = mainnet_fixture("negative-matrix");
        let source = account_id_for_seed([0x33; 32]);
        let mut hold = reservation(&format!("{:064x}", index + 1), &source, 1, due_since(now));
        hold.max_time = now / 1000 + 120;
        fx.take_reservation(now, &hold, 500);
        let endpoints = Endpoints::start().await;
        endpoints
            .primary_answers("getTransaction", get_transaction("NOT_FOUND"))
            .await;
        endpoints.oracle_answers("getTransaction", answer).await;
        endpoints.oracle_answers("getHealth", health(1)).await;
        endpoints
            .oracle_answers("getLedgers", ledgers(hold.max_time + 1, 1))
            .await;
        endpoints
            .oracle_answers("getLedgerEntries", account_at_sequence(&source, 10))
            .await;
        let (primary, oracle) = endpoints.clients();
        let report = fx
            .window
            .reconcile_one(
                &fx.profile,
                &primary,
                Some(&oracle),
                Some(&fx.receipts),
                &hold.id,
                now,
            )
            .await
            .unwrap();
        assert_eq!(report.released, 0);
        assert!(report.settled.is_empty());
        assert_eq!(fx.window_total(now), (500, 1));
        assert_eq!(
            fx.receipts.get(&hold.id).unwrap().unwrap().status,
            ReceiptStatus::Pending
        );
    }
}

#[tokio::test]
#[serial]
async fn hostile_oracle_failure_retains_executable_spending() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    assert_negative_answers(vec![get_transaction_failed()]).await;
}

#[tokio::test]
#[serial]
async fn malformed_failure_and_absence_retain_exposure() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    assert_negative_answers(vec![json!({"status": "FAILED", "latestLedger": 2000, "oldestLedger": 1, "resultXdr": "malformed"}), get_transaction("NOT_FOUND")]).await;
}
