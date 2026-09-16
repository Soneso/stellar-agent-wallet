//! The release rule a reconciliation pass applies to open spending-window
//! reservations, against a mocked Stellar RPC endpoint.
//!
//! A reservation is taken before a transaction is sent and counts against the
//! operator's caps while it stands. These tests pin what settles it and what
//! does not:
//!
//! - `SUCCESS` confirms; `FAILED` releases.
//! - `NOT_FOUND` releases only when the transaction can no longer apply: its
//!   sequence has been consumed, or its time bound has passed.
//! - A `NOT_FOUND` from an endpoint whose retention window no longer covers the
//!   submission proves nothing, so the reservation stands and the receipt is
//!   marked ambiguous.
//! - A pass is bounded: at most `RECONCILE_BUDGET` reservations, oldest first,
//!   none younger than `RECONCILE_MIN_AGE_MS`.
//! - Nothing releases a reservation on a transport error.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::sync::{Arc, Mutex};

use serde_json::json;
use serial_test::serial;
use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::policy_state::{
    PersistedWindowStore, RECONCILE_BUDGET, RECONCILE_MIN_AGE_MS, WindowReservation,
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

fn state_key(profile_name: &str) -> StateKey {
    StateKey::new(profile_name, 1, "native", 86_400)
}

fn reservation(id: &str, source: &str, sequence: i64, pending_since_ms: u64) -> WindowReservation {
    WindowReservation {
        id: id.to_owned(),
        tx_hash: id.to_owned(),
        source: source.to_owned(),
        sequence,
        max_time: 0,
        pending_since_ms,
        submission_ledger: SUBMISSION_LEDGER,
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

fn health(oldest_ledger: u32) -> serde_json::Value {
    json!({
        "status": "healthy",
        "latestLedger": 2_000,
        "oldestLedger": oldest_ledger,
        "ledgerRetentionWindow": 2_000 - oldest_ledger,
    })
}

/// A `getTransaction` body for `status`, with no result XDR.
fn get_transaction(status: &str) -> serde_json::Value {
    json!({
        "status": status,
        "latestLedger": 2_000,
        "oldestLedger": 1,
        "ledger": if status == "SUCCESS" { Some(1_500) } else { None },
    })
}

/// A `getTransaction` FAILED body carrying a real `txBadSeq` result.
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
    keyring_mock::install().unwrap();
    let dir = TempDir::new().unwrap();
    let receipt_dir = TempDir::new().unwrap();
    let profile = test_profile(name);
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

impl Fixture {
    fn take_reservation(&self, now: u64, reservation: &WindowReservation, amount: i128) {
        self.window
            .record_pending(
                &self.profile,
                &[(state_key(&self.profile_name), now, amount)],
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
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
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
}

/// `NOT_FOUND` with a passed time bound releases without asking about the
/// account: a transaction past its `maxTime` cannot apply whatever the
/// sequence is.
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
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
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
    assert_eq!(
        counts.count("getLedgerEntries"),
        0,
        "a passed time bound settles the reservation without a second read"
    );
}

/// `NOT_FOUND` with the sequence still unconsumed and no time bound settles
/// nothing: the transaction can still apply.
#[tokio::test]
#[serial]
async fn not_found_with_an_unconsumed_sequence_keeps_the_reservation() {
    let now = now_ms();
    let fx = fixture("reconcile-keep");
    let source = account_id_for_seed([0x15; 32]);
    // `ledger_entries_result_for` reports sequence 1, so a reservation at
    // sequence 9 still needs a sequence the account has not reached.
    let res = reservation(&"e".repeat(64), &source, 9, due_since(now));
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
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
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
    assert_eq!(fx.window_total(now), (500, 1));
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Pending
    );
}

/// A `NOT_FOUND` from an endpoint that no longer holds the submission's ledger
/// range proves nothing, so the reservation stands and the receipt is marked
/// ambiguous for an operator.
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
    assert_eq!(
        fx.receipts.get(&res.id).unwrap().unwrap().status,
        ReceiptStatus::Ambiguous
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
        .reconcile_one(&fx.profile, &client, Some(&fx.receipts), &res.id, now)
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
            &[(state_key(&fx.profile_name), ancient_ts, 10)],
            &reservation(&ancient, &source, 7, ancient_ts),
        )
        .unwrap();

    // A later write is what runs the prune.
    let fresh = format!("{:064}", 2_u8);
    fx.window
        .record_pending(
            &fx.profile,
            &[(state_key(&fx.profile_name), now, 10)],
            &reservation(&fresh, &source, 8, now),
        )
        .unwrap();

    let open = fx.window.pending_reservations(&fx.profile).unwrap();
    assert!(
        open.iter().any(|r| r.id == ancient),
        "a pending reservation outlives the retention window: {open:?}"
    );
}

/// A reservation whose receipt is gone is released once its transaction can no
/// longer apply, and stands until then.
///
/// It arises when a submission that was never sent unwound and the release
/// step failed while the receipt removal succeeded. No verb addresses it: the
/// operator clear refuses it for want of a record, and a pending record is not
/// pruned by age. Nothing was sent, so the release rests on the same
/// exactness as everywhere else.
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
            &[(state_key(&fx.profile_name), now, 10)],
            &reservation(&unconsumed, &source, 9, due_since(now)),
        )
        .unwrap();

    let report = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
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
            &[(state_key(&fx.profile_name), now, 10)],
            &reservation(&consumed, &source, 1, due_since(now)),
        )
        .unwrap();

    let report2 = fx
        .window
        .reconcile_due(
            &fx.profile,
            &client,
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
    assert!(
        fx.receipts.get(&consumed).unwrap().is_none(),
        "nothing was sent, so no receipt is written for it"
    );
    assert!(
        report2.settled.is_empty(),
        "a release the chain never confirmed owes no audit row: {report2:?}"
    );
}

/// A receipt store that cannot be read keeps every reservation, and asks the
/// chain nothing.
///
/// The orphan branch releases on a consumed sequence without a chain round
/// trip, which is right for a reservation the store reports as having no
/// receipt. A store that cannot be read has said no such thing, and a
/// landed-but-timed-out submission sits at exactly the consumed sequence that
/// branch releases on. Conflating the two would release real spend from the
/// operator's caps on the strength of a local file error.
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
