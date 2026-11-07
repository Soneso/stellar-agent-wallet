//! `stellar-agent tx receipt clear` and `tx status` against a mocked
//! endpoint.
//!
//! `--acknowledge` records the operator's decision; clearing establishes no
//! chain outcome. The verb asks the endpoint first and reconciles before it
//! decides. A reported success for a bounded transaction is not the
//! operator's to clear. A reported failure is not either, except for a
//! submission without a held reservation or on a mainnet profile without an
//! oracle; such a failure clears only after its time bound. One that can
//! still apply is refused. An endpoint that cannot answer is not a license to
//! clear either. A
//! reported failure or missing transaction does not release possible
//! spending. An authenticated hold without a time bound is cleared only with
//! `--acknowledge-unbounded` as well, whatever the endpoint reports. No path
//! sends the transaction again, which every responder here counts.
//!
//! Driven as subprocesses of the real binary so the printed envelope is the
//! one an operator sees. The CLI crate has no `[lib]` target.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics and unwraps are acceptable"
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend,
/// so no child process can reach the login keychain.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

const PROFILE: &str = "clear-guard";
const ENVELOPE_HASH: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const TX_HASH: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const SOURCE: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

/// The current time in unix seconds.
fn now_secs() -> u64 {
    stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000
}

/// The JSON-RPC methods a responder was asked, and the sends among them.
///
/// Observed by the parent process, so a test asserts that a subprocess never
/// sent.
#[derive(Clone, Default)]
struct RpcLog {
    methods: Arc<Mutex<Vec<String>>>,
    sends: Arc<AtomicUsize>,
}

impl RpcLog {
    fn record(&self, rpc_method: &str) {
        if rpc_method == "sendTransaction" {
            self.sends.fetch_add(1, Ordering::SeqCst);
        }
        self.methods.lock().unwrap().push(rpc_method.to_owned());
    }

    fn sends(&self) -> usize {
        self.sends.load(Ordering::SeqCst)
    }

    fn count(&self, rpc_method: &str) -> usize {
        self.methods
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.as_str() == rpc_method)
            .count()
    }
}

/// Answers every `getTransaction` with one fixed status, and every other read
/// a reconciliation makes with a valid answer.
///
/// `getLedgerEntries` reports the source account at sequence 1, so a receipt
/// at sequence 1 is one whose sequence another transaction consumed, and a
/// receipt at sequence 7 one whose sequence is unconsumed. The submission
/// ledger every fixture records (1 000) is inside the retention window unless
/// `floor` is raised above it.
#[derive(Clone)]
struct FixedStatusRpc {
    status: &'static str,
    /// The retention floor `getHealth` reports.
    floor: u32,
    /// The latest ledger close time `getLedgers` reports, unix seconds.
    close_time: u64,
    /// Answers `getLedgers` with HTTP 500.
    fail_ledgers: bool,
    /// Reports that the source account has no ledger entry.
    source_absent: bool,
    /// Alternates the initial status with a successful reconciliation answer.
    reconcile_success: bool,
    /// A profile home whose audit directory is moved aside, once, when the
    /// first `getLedgerEntries` arrives: an audit log that stops being
    /// appendable after the verb acquired its writer.
    break_audit: Option<PathBuf>,
    broken: Arc<AtomicBool>,
    log: RpcLog,
}

impl FixedStatusRpc {
    fn new(status: &'static str) -> Self {
        Self {
            status,
            floor: 1,
            close_time: now_secs(),
            fail_ledgers: false,
            source_absent: false,
            reconcile_success: false,
            break_audit: None,
            broken: Arc::new(AtomicBool::new(false)),
            log: RpcLog::default(),
        }
    }

    async fn mount(&self, server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(self.clone())
            .mount(server)
            .await;
    }
}

impl Respond for FixedStatusRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or_else(|_| json!({}));
        let req_id = body.get("id").cloned().unwrap_or_else(|| json!(1));
        let rpc_method = body["method"].as_str().unwrap_or_default().to_owned();
        self.log.record(&rpc_method);
        let result = match rpc_method.as_str() {
            "getHealth" => json!({
                "status": "healthy",
                "latestLedger": 2_000,
                "oldestLedger": self.floor,
                "ledgerRetentionWindow": 2_000 - self.floor,
            }),
            "getLedgers" if self.fail_ledgers => return ResponseTemplate::new(500),
            "getLedgers" => json!({
                "latestLedger": 2_000,
                "oldestLedger": 1,
                "latestLedgerCloseTime": self.close_time.to_string(),
                "oldestLedgerCloseTime": 1,
                "cursor": "2000",
                "ledgers": [],
            }),
            "getLedgerEntries" if self.source_absent => {
                json!({"latestLedger": 2_000, "entries": []})
            }
            "getLedgerEntries" => {
                if let Some(home) = &self.break_audit
                    && !self.broken.swap(true, Ordering::SeqCst)
                {
                    std::fs::rename(home.join("audit"), home.join("audit-held")).unwrap();
                    std::fs::write(home.join("audit"), b"not a directory").unwrap();
                }
                let mut entries =
                    stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[
                        SOURCE,
                    ]);
                entries["latestLedger"] = json!(2_000);
                entries
            }
            "getNetwork" => stellar_agent_test_support::signed_envelope::get_network_result(
                stellar_agent_test_support::signed_envelope::TESTNET_PASSPHRASE,
            ),
            "sendTransaction" => return ResponseTemplate::new(500),
            // Each clear reads status first, then reads it again for reconciliation.
            _ => match if self.reconcile_success
                && self.log.count("getTransaction").is_multiple_of(2)
            {
                "SUCCESS"
            } else {
                self.status
            } {
                "SUCCESS" => json!({
                    "status": "SUCCESS",
                    "latestLedger": 1_002,
                    "oldestLedger": 1,
                    "ledger": 1_001,
                    "createdAt": now_secs().to_string(),
                }),
                other => json!({
                    "status": other,
                    "latestLedger": 1_002,
                    "oldestLedger": 1,
                }),
            },
        };
        ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }))
    }
}

/// Starts an endpoint answered by `rpc`.
async fn endpoint(rpc: &FixedStatusRpc) -> MockServer {
    let server = MockServer::start().await;
    rpc.mount(&server).await;
    server
}

fn run_cli(home: &Path, args: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env_remove("STELLAR_AGENT_PROFILE")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .output()
        .expect("stellar-agent binary must run");

    let code = output.status.code().expect("process must exit with a code");
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let last = stdout
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or_else(|| panic!("expected an envelope on stdout; stderr={stderr}"));
    let json: Value =
        serde_json::from_str(last).unwrap_or_else(|e| panic!("stdout must be JSON ({e}): {last}"));
    (code, json)
}

/// Writes a persisted profile pointing at `rpc_url`, mints its audit key, and
/// seeds a sent-but-unanswered submission receipt with no time bound, at a
/// sequence the source account has not consumed.
fn fixture(home: &Path, rpc_url: &str) {
    fixture_with_approval(home, rpc_url, None);
}

/// Writes the profile and seeds a sent receipt for `ENVELOPE_HASH` at
/// `sequence` with time bound `max_time`.
fn fixture_with(home: &Path, rpc_url: &str, sequence: i64, max_time: u64) {
    write_profile(home, rpc_url);
    let receipts = ReceiptStore::open_at(&home.join("receipts"), PROFILE).unwrap();
    receipts
        .begin_submission(ENVELOPE_HASH, TX_HASH, SOURCE, sequence, max_time, 1_000)
        .unwrap();
    receipts.mark_submitted(ENVELOPE_HASH).unwrap();
}

fn fixture_with_approval(home: &Path, rpc_url: &str, approval_nonce: Option<&str>) {
    write_profile(home, rpc_url);
    let receipts = ReceiptStore::open_at(&home.join("receipts"), PROFILE).unwrap();
    receipts
        .begin_submission_with_approval(ENVELOPE_HASH, TX_HASH, SOURCE, 7, 0, 1_000, approval_nonce)
        .unwrap();
    receipts.mark_submitted(ENVELOPE_HASH).unwrap();
}

/// Writes a persisted profile pointing at `rpc_url` and mints its audit key.
fn write_profile(home: &Path, rpc_url: &str) {
    let dir = home.join("profiles");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{PROFILE}.toml")),
        format!(
            "version = 2\n\
             chain_id = \"stellar:testnet\"\n\
             rpc_url = \"{rpc_url}\"\n\n\
             [mcp_signer_default]\n\
             service = \"stellar-agent-signer\"\n\
             account = \"default\"\n\n\
             [mcp_nonce_key_alias]\n\
             service = \"stellar-agent-nonce\"\n\
             account = \"default\"\n\n\
             [audit_log_hash_chain_key_id]\n\
             service = \"stellar-agent-audit-{PROFILE}\"\n\
             account = \"default\"\n\n\
             [policy_owner_key_id]\n\
             service = \"stellar-agent-owner-{PROFILE}\"\n\
             account = \"default\"\n\n\
             [attestation_key_id]\n\
             service = \"stellar-agent-attestation-{PROFILE}\"\n\
             account = \"default\"\n\n\
             [counterparty_cache_key_id]\n\
             service = \"stellar-agent-counterparty-{PROFILE}\"\n\
             account = \"default\"\n\n\
             [policy]\n\
             engine = \"noop\"\n"
        ),
    )
    .unwrap();

    let (code, envelope) = run_cli(home, &["profile", "rotate-audit-key", PROFILE]);
    assert_eq!(code, 0, "rotate-audit-key must succeed: {envelope}");
}

#[tokio::test]
async fn tx_status_completes_owed_approval_consumption_once() {
    use stellar_agent_core::approval::{
        ApprovalKind, ConsumedOutcome, PendingApproval, PendingApprovalStore,
    };
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("SUCCESS");
    let server = endpoint(&rpc).await;
    let entry = PendingApproval::new_payment_pending(
        "AAAAAgAAAAA=".to_owned(),
        b"payment",
        SOURCE.to_owned(),
        50,
        "XLM".to_owned(),
        None,
        100,
        7,
        stellar_agent_core::approval::process_uid_for_attestation().unwrap(),
        60_000,
    )
    .unwrap();
    let nonce = entry.approval_nonce.clone();
    let approval_path = home
        .path()
        .join("approvals")
        .join(format!("{PROFILE}.toml"));
    {
        let mut store = PendingApprovalStore::open(approval_path.clone()).unwrap();
        store
            .insert(entry, stellar_agent_core::timefmt::now_unix_ms().unwrap())
            .unwrap();
    }
    fixture_with_approval(home.path(), &server.uri(), Some(&nonce));
    let receipts = ReceiptStore::open_at(&home.path().join("receipts"), PROFILE).unwrap();
    assert!(
        !receipts
            .get(ENVELOPE_HASH)
            .unwrap()
            .unwrap()
            .approval_consumed
    );
    for _ in 0..2 {
        let (code, envelope) = run_cli(
            home.path(),
            &["tx", "status", TX_HASH, "--profile", PROFILE],
        );
        assert_eq!(code, 0, "{envelope}");
        assert_eq!(envelope["data"]["chain_status"], "SUCCESS");
    }
    assert!(
        receipts
            .get(ENVELOPE_HASH)
            .unwrap()
            .unwrap()
            .approval_consumed
    );
    let store = PendingApprovalStore::open(approval_path).unwrap();
    assert!(matches!(
        &store.get(&nonce).unwrap().kind,
        ApprovalKind::Consumed { tx_hash, outcome: ConsumedOutcome::Confirmed, .. }
            if tx_hash == TX_HASH
    ));
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// The rows the profile's audit log holds.
fn audit_rows(home: &Path) -> Vec<String> {
    std::fs::read_to_string(home.join("audit").join(format!("{PROFILE}.jsonl")))
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(std::string::ToString::to_string)
        .collect()
}

/// How many operator-clear rows the log holds.
fn cleared_rows(home: &Path) -> usize {
    audit_rows(home)
        .iter()
        .filter(|l| l.contains("submission_receipt_cleared"))
        .count()
}

/// The rows of `kind` the profile's audit log holds, parsed.
fn rows_of_kind(home: &Path, kind: &str) -> Vec<Value> {
    audit_rows(home)
        .iter()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| row["kind"] == kind)
        .collect()
}

/// Runs `tx receipt clear` for `ENVELOPE_HASH` with both acknowledgements,
/// the form an untimed authenticated hold needs.
fn clear_unbounded(home: &Path) -> (i32, Value) {
    run_cli(
        home,
        &[
            "tx",
            "receipt",
            "clear",
            ENVELOPE_HASH,
            "--acknowledge",
            "--acknowledge-unbounded",
            "--profile",
            PROFILE,
        ],
    )
}

/// Runs `tx receipt clear` for `ENVELOPE_HASH`, with or without the
/// acknowledgement.
fn clear(home: &Path, acknowledge: bool) -> (i32, Value) {
    let mut args = vec![
        "tx",
        "receipt",
        "clear",
        ENVELOPE_HASH,
        "--profile",
        PROFILE,
    ];
    if acknowledge {
        args.push("--acknowledge");
    }
    run_cli(home, &args)
}

/// The receipt the store holds for `ENVELOPE_HASH`.
fn receipt(home: &Path) -> stellar_agent_core::profile::receipt::SubmissionReceipt {
    ReceiptStore::open_at(&home.join("receipts"), PROFILE)
        .unwrap()
        .get(ENVELOPE_HASH)
        .unwrap()
        .unwrap()
}

/// The endpoint says the transaction reached a ledger, so the operator does
/// not get to declare it never moved value.
#[tokio::test]
async fn a_submission_the_chain_answered_for_is_not_cleared_by_an_operator() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("SUCCESS");
    let server = endpoint(&rpc).await;
    fixture(home.path(), &server.uri());

    let (code, envelope) = run_cli(
        home.path(),
        &[
            "tx",
            "receipt",
            "clear",
            ENVELOPE_HASH,
            "--acknowledge",
            "--profile",
            PROFILE,
        ],
    );

    assert_eq!(
        code, 1,
        "a confirmed transaction is not clearable: {envelope}"
    );
    assert_eq!(
        envelope["error"]["code"].as_str(),
        Some("submission.not_clearable"),
        "the refusal names the condition: {envelope}"
    );

    let receipts = ReceiptStore::open_at(&home.path().join("receipts"), PROFILE).unwrap();
    let receipt = receipts.get(ENVELOPE_HASH).unwrap().unwrap();
    assert!(
        receipt.submitted,
        "the record is untouched by a refused clear: {receipt:?}"
    );
    assert_eq!(
        receipt.status,
        stellar_agent_core::profile::receipt::ReceiptStatus::Pending,
        "the record is untouched by a refused clear"
    );
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// The endpoint cannot account for the transaction, which is the state the
/// operator verb exists for.
#[tokio::test]
async fn a_submission_the_endpoint_cannot_account_for_is_cleared() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    fixture(home.path(), &server.uri());

    let (code, envelope) = run_cli(
        home.path(),
        &[
            "tx",
            "receipt",
            "clear",
            ENVELOPE_HASH,
            "--acknowledge",
            "--profile",
            PROFILE,
        ],
    );

    assert_eq!(
        code, 0,
        "an unaccounted submission is clearable: {envelope}"
    );
    assert_eq!(envelope["data"]["cleared_from"].as_str(), Some("pending"));

    let receipts = ReceiptStore::open_at(&home.path().join("receipts"), PROFILE).unwrap();
    let receipt = receipts.get(ENVELOPE_HASH).unwrap().unwrap();
    assert_eq!(
        receipt.status,
        stellar_agent_core::profile::receipt::ReceiptStatus::ClearedByOperator
    );

    let rows = std::fs::read_to_string(home.path().join("audit").join(format!("{PROFILE}.jsonl")))
        .unwrap_or_default();
    assert!(
        rows.contains("submission_receipt_cleared"),
        "the clear is recorded: {rows}"
    );
    let cleared = rows_of_kind(home.path(), "submission_receipt_cleared");
    assert_eq!(cleared.len(), 1);
    assert!(
        cleared[0].get("evidence").is_none(),
        "an untimed submission's outcome is unknown, and the row says so: {}",
        cleared[0]
    );
    assert!(
        rows_of_kind(home.path(), "value_action_failed").is_empty(),
        "a clear with an unknown outcome writes no settled row"
    );
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// Without `--acknowledge` the verb refuses whatever the chain says.
#[tokio::test]
async fn a_clear_without_the_acknowledgement_is_refused() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    fixture(home.path(), &server.uri());

    let (code, envelope) = run_cli(
        home.path(),
        &[
            "tx",
            "receipt",
            "clear",
            ENVELOPE_HASH,
            "--profile",
            PROFILE,
        ],
    );

    assert_eq!(code, 1);
    assert_eq!(
        envelope["error"]["code"].as_str(),
        Some("submission.acknowledgement_required")
    );
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// A re-run on an already-cleared receipt writes no row and releases nothing.
///
/// Every precondition is evaluated before the first side effect, so a clear
/// the verb will refuse leaves the wallet as it found it. The endpoint still
/// reports `NOT_FOUND`, which is what made the first clear legitimate, so only
/// the receipt's own state stops the second.
#[tokio::test]
async fn a_re_run_on_a_cleared_receipt_writes_no_row() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    fixture(home.path(), &server.uri());

    let args = [
        "tx",
        "receipt",
        "clear",
        ENVELOPE_HASH,
        "--acknowledge",
        "--profile",
        PROFILE,
    ];
    let (first_code, first) = run_cli(home.path(), &args);
    assert_eq!(first_code, 0, "the first clear succeeds: {first}");
    let rows_after_first = cleared_rows(home.path());
    assert_eq!(rows_after_first, 1, "one clear, one row");

    let (second_code, second) = run_cli(home.path(), &args);
    assert_eq!(
        second_code, 1,
        "a cleared receipt is not cleared twice: {second}"
    );
    assert_eq!(
        second["error"]["code"].as_str(),
        Some("submission.not_clearable"),
        "the refusal names the receipt's state: {second}"
    );
    assert_eq!(
        cleared_rows(home.path()),
        1,
        "a refused clear writes no row: {:?}",
        audit_rows(home.path())
    );
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// A receipt whose transaction the chain confirmed writes no row either.
///
/// The local rule admits a `Pending` receipt, so this one is stopped by the
/// chain answer, and it is stopped before anything is released or written.
#[tokio::test]
async fn a_pending_receipt_the_chain_confirmed_writes_no_row() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("SUCCESS");
    let server = endpoint(&rpc).await;
    fixture(home.path(), &server.uri());

    let (code, envelope) = run_cli(
        home.path(),
        &[
            "tx",
            "receipt",
            "clear",
            ENVELOPE_HASH,
            "--acknowledge",
            "--profile",
            PROFILE,
        ],
    );

    assert_eq!(
        code, 1,
        "a confirmed transaction is not clearable: {envelope}"
    );
    assert_eq!(
        cleared_rows(home.path()),
        0,
        "a refused clear writes no row: {:?}",
        audit_rows(home.path())
    );
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// A receipt that records its submission as never sent does not clear the
/// authenticated hold of a transaction whose time bound is still open.
///
/// A process killed between the record and the send leaves this shape. The
/// receipt's unsent state is unauthenticated, so only the bound ends the
/// exposure: the clear is refused and the hold, the receipt and the log stay
/// as they were. A receipt without a hold is cleared on its unsent state; see
/// `untimed_and_unsent_clears_do_not_need_a_ledger_time`.
#[tokio::test]
#[serial_test::serial]
async fn an_unsent_receipt_does_not_clear_its_open_bounded_hold() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    fixture(home.path(), &server.uri());

    let receipts_dir = home.path().join("receipts");
    let unsent = "3333333333333333333333333333333333333333333333333333333333333333";
    {
        let receipts = ReceiptStore::open_at(&receipts_dir, PROFILE).unwrap();
        receipts
            .begin_submission(unsent, TX_HASH, SOURCE, 9, now_secs() + 86_400, 1_000)
            .unwrap();
        assert!(!receipts.get(unsent).unwrap().unwrap().submitted);
    }

    let (window, profile) = seed_window(home.path(), unsent, 9, now_secs() + 86_400);
    let before = audit_rows(home.path());
    let (refused, _) = run_cli(
        home.path(),
        &["tx", "receipt", "clear", unsent, "--profile", PROFILE],
    );
    assert_eq!(refused, 1);
    assert!(window.holds_reservation(&profile, unsent).unwrap());

    let (code, envelope) = run_cli(
        home.path(),
        &[
            "tx",
            "receipt",
            "clear",
            unsent,
            "--acknowledge",
            "--profile",
            PROFILE,
        ],
    );

    assert_eq!(code, 1, "{envelope}");
    assert_eq!(envelope["error"]["code"], "submission.still_pending");
    assert_eq!(window.pending_reservations(&profile).unwrap().len(), 1);
    let receipt = ReceiptStore::open_at(&receipts_dir, PROFILE)
        .unwrap()
        .get(unsent)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Pending);
    assert!(!receipt.submitted);
    assert_eq!(audit_rows(home.path()), before);
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// A record settled as a success whose transaction has left the endpoint's
/// retention is refused, and writes no row.
///
/// This is the state that makes the ordering load-bearing. The endpoint has
/// forgotten the transaction, so the chain check passes; only the record's own
/// state stops the clear, and it has to stop it before the reservation is
/// released and the row is written. A verb that checked the state last would
/// record a clear it then refuses.
#[tokio::test]
async fn a_settled_record_the_endpoint_forgot_is_refused_and_writes_no_row() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    fixture(home.path(), &server.uri());

    // A record the chain answered for once, whose transaction has since fallen
    // out of the endpoint's retention window.
    let settled = "5555555555555555555555555555555555555555555555555555555555555555";
    {
        let receipts = ReceiptStore::open_at(&home.path().join("receipts"), PROFILE).unwrap();
        receipts
            .begin_submission(settled, TX_HASH, SOURCE, 11, 0, 1_000)
            .unwrap();
        receipts.mark_submitted(settled).unwrap();
        receipts
            .finalize(
                settled,
                stellar_agent_core::profile::receipt::ReceiptStatus::Success,
                None,
            )
            .unwrap();
    }

    let (code, envelope) = run_cli(
        home.path(),
        &[
            "tx",
            "receipt",
            "clear",
            settled,
            "--acknowledge",
            "--profile",
            PROFILE,
        ],
    );

    assert_eq!(code, 1, "a settled record is not clearable: {envelope}");
    assert_eq!(
        envelope["error"]["code"].as_str(),
        Some("submission.not_clearable"),
        "the refusal comes from the record's own state: {envelope}"
    );
    assert_eq!(
        cleared_rows(home.path()),
        0,
        "nothing is recorded for a clear that was refused: {:?}",
        audit_rows(home.path())
    );

    let receipts = ReceiptStore::open_at(&home.path().join("receipts"), PROFILE).unwrap();
    assert!(
        matches!(
            receipts.get(settled).unwrap().unwrap().status,
            stellar_agent_core::profile::receipt::ReceiptStatus::Success
        ),
        "the record is untouched"
    );
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// Answers transaction and retention queries independently, and records the
/// methods it is asked.
#[derive(Clone)]
struct OrphanRpc {
    status: &'static str,
    floor: u32,
    log: RpcLog,
}

impl OrphanRpc {
    fn new(status: &'static str, floor: u32) -> Self {
        Self {
            status,
            floor,
            log: RpcLog::default(),
        }
    }
}

impl Respond for OrphanRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        self.log.record(body["method"].as_str().unwrap_or_default());
        let result = match body["method"].as_str() {
            Some("getHealth") => json!({"status":"healthy", "latestLedger":2000,
                "oldestLedger": self.floor, "ledgerRetentionWindow":2000-self.floor}),
            Some("getLedgers") => json!({"latestLedger":2000,"oldestLedger":self.floor,
                "latestLedgerCloseTime":"100", "oldestLedgerCloseTime":1, "cursor":"2000", "ledgers":[]}),
            _ => json!({"status":self.status,"latestLedger":2000,"oldestLedger":self.floor,
                "ledger": if self.status == "SUCCESS" { Some(1500) } else { None },
                "createdAt": if self.status == "SUCCESS" {
                    Some((stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000).to_string())
                } else { None }}),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc":"2.0","id":body["id"],"result":result}))
    }
}

/// Seeds an orphaned reservation whose execution bound passed an hour ago on
/// the host clock and at the endpoint's latest ledger close time.
fn bounded_orphan_fixture(
    home: &Path,
    rpc_url: &str,
) -> (
    stellar_agent_network::policy_state::PersistedWindowStore,
    stellar_agent_core::profile::schema::Profile,
) {
    let bound = now_secs() - 3_600;
    fixture_with(home, rpc_url, 7, bound);
    let seeded = seed_window(home, ENVELOPE_HASH, 7, bound);
    std::fs::remove_file(home.join(format!("receipts/{PROFILE}.json"))).unwrap();
    seeded
}

/// Seeds a real authenticated window using the subprocesses' encrypted
/// keyring, then removes the receipt, leaving an orphaned reservation.
fn orphan_fixture(
    home: &Path,
    rpc_url: &str,
) -> (
    stellar_agent_network::policy_state::PersistedWindowStore,
    stellar_agent_core::profile::schema::Profile,
) {
    let (window, profile) = windowed_fixture(home, rpc_url, 7);
    std::fs::remove_file(home.join(format!("receipts/{PROFILE}.json"))).unwrap();
    (window, profile)
}

/// Writes the profile, seeds a sent untimed receipt at `sequence`, and takes
/// a due reservation for it in a real authenticated window, written through
/// the subprocesses' encrypted keyring.
fn windowed_fixture(
    home: &Path,
    rpc_url: &str,
    sequence: i64,
) -> (
    stellar_agent_network::policy_state::PersistedWindowStore,
    stellar_agent_core::profile::schema::Profile,
) {
    fixture_with(home, rpc_url, sequence, 0);
    seed_window(home, ENVELOPE_HASH, sequence, 0)
}

fn seed_window(
    home: &Path,
    id: &str,
    sequence: i64,
    max_time: u64,
) -> (
    stellar_agent_network::policy_state::PersistedWindowStore,
    stellar_agent_core::profile::schema::Profile,
) {
    seed_window_for(home, id, TX_HASH, sequence, max_time)
}

/// Takes a due reservation for the submission `id` with transaction hash
/// `tx_hash` in a real authenticated window, written through the
/// subprocesses' encrypted keyring.
fn seed_window_for(
    home: &Path,
    id: &str,
    tx_hash: &str,
    sequence: i64,
    max_time: u64,
) -> (
    stellar_agent_network::policy_state::PersistedWindowStore,
    stellar_agent_core::profile::schema::Profile,
) {
    use stellar_agent_core::policy::v1::criteria::state_store::{
        StateKey, WindowEntry, WindowLimit,
    };
    use stellar_agent_headless_keyring::{crypto::ProtectionMode, store::HeadlessStore};
    use stellar_agent_network::policy_state::{PersistedWindowStore, SubmissionHold};
    keyring_core::set_default_store(Arc::new(HeadlessStore::new(
        home.join("headless-keyring/store.keyring"),
        ProtectionMode::EnvKey(Arc::new(zeroize::Zeroizing::new(std::array::from_fn(
            |i| i as u8,
        )))),
    )));
    let profile = stellar_agent_core::profile::loader::load_from_path(
        PROFILE,
        &home.join(format!("profiles/{PROFILE}.toml")),
        None,
    )
    .unwrap();
    let window = PersistedWindowStore::at_path(home.join(format!("policy/{PROFILE}.window")));
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    let res = SubmissionHold {
        chain_scope: stellar_agent_network::policy_state::ChainScope::for_chain(profile.chain_id),
        id: id.to_owned(),
        tx_hash: tx_hash.to_owned(),
        source: SOURCE.to_owned(),
        sequence,
        max_time,
        pending_since_ms: now - 400_000,
        submission_ledger: 1000,
        submission_anchor: None,
        operator_required: false,
    };
    window
        .record_pending(
            &profile,
            &[WindowEntry::new(
                StateKey::new(PROFILE, 1, "native", 86_400),
                now,
                75,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000_000,
                },
            )],
            &res,
        )
        .unwrap();
    (window, profile)
}

/// Asks the window for a second reservation of `amount` stroops under the
/// one-day cap the fixtures hold. Returns whether it was admitted; a refusal
/// must be the cap's.
fn admits(
    window: &stellar_agent_network::policy_state::PersistedWindowStore,
    profile: &stellar_agent_core::profile::schema::Profile,
    amount: i128,
) -> bool {
    use stellar_agent_core::policy::v1::criteria::state_store::{
        StateKey, WindowEntry, WindowLimit,
    };
    use stellar_agent_network::policy_state::{ChainScope, SubmissionHold, WindowStoreError};
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    let outcome = window.record_pending(
        profile,
        &[WindowEntry::new(
            StateKey::new(PROFILE, 1, "native", 86_400),
            now,
            amount,
            WindowLimit::Amount {
                asset: "native".to_owned(),
                window: "1d".to_owned(),
                max_stroops: 1_000_000,
            },
        )],
        &SubmissionHold {
            chain_scope: ChainScope::for_chain(profile.chain_id),
            id: "5555555555555555555555555555555555555555555555555555555555555555".to_owned(),
            tx_hash: "6666666666666666666666666666666666666666666666666666666666666666".to_owned(),
            source: SOURCE.to_owned(),
            sequence: 99,
            max_time: 0,
            pending_since_ms: now,
            submission_ledger: 1000,
            submission_anchor: None,
            operator_required: false,
        },
    );
    match outcome {
        Ok(_) => true,
        Err(WindowStoreError::PolicyDenied { .. }) => false,
        Err(other) => panic!("the admission must succeed or meet the cap: {other}"),
    }
}

/// Clears the orphan for `ENVELOPE_HASH` with both acknowledgements: an
/// untimed orphan needs `--acknowledge-unbounded`, and a bounded one ignores
/// it.
fn orphan_clear(home: &Path) -> (i32, Value) {
    clear_unbounded(home)
}

/// Orphan recovery preserves authenticated identity and provenance, writes one
/// operator audit row, and releases the debit without inventing approval metadata.
#[tokio::test]
#[serial_test::serial]
async fn orphan_clear_recovers_identity_and_releases_headroom() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = OrphanRpc::new("NOT_FOUND", 1200);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(rpc.clone())
        .mount(&server)
        .await;
    let (window, profile) = orphan_fixture(home.path(), &server.uri());
    let (code, data) = orphan_clear(home.path());
    assert_eq!(code, 0, "{data}");
    assert_eq!(data["data"]["reservation_released"], true);
    let receipts = ReceiptStore::open_at(&home.path().join("receipts"), PROFILE).unwrap();
    let receipt = receipts.get(ENVELOPE_HASH).unwrap().unwrap();
    assert_eq!(receipt.status.label(), "cleared_by_operator");
    assert!(receipt.recovered_from_reservation);
    assert_eq!(receipt.tx_hash, TX_HASH);
    assert_eq!(receipt.source, SOURCE);
    assert_eq!(receipt.sequence, 7);
    assert_eq!(receipt.recorded_at_ledger, 1000);
    assert!(receipt.approval_nonce.is_none());
    assert!(!receipt.approval_consumed);
    assert!(window.pending_reservations(&profile).unwrap().is_empty());
    assert_eq!(cleared_rows(home.path()), 1);
    orphan_clear(home.path());
    assert_eq!(cleared_rows(home.path()), 1);
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// Only an absent transaction beyond retention permits reconstruction of an
/// orphan with an execution bound, even once that bound has passed.
#[tokio::test]
#[serial_test::serial]
async fn answerable_or_in_retention_bounded_orphans_are_not_cleared() {
    for (status, floor) in [
        ("SUCCESS", 1200),
        ("FAILED", 1200),
        ("NOT_FOUND", 1000),
        ("PENDING", 1200),
    ] {
        let home = tempfile::TempDir::new().unwrap();
        let rpc = OrphanRpc::new(status, floor);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(rpc.clone())
            .mount(&server)
            .await;
        let (window, profile) = bounded_orphan_fixture(home.path(), &server.uri());
        let (code, data) = orphan_clear(home.path());
        assert_eq!(code, 1, "{status} {floor}: {data}");
        assert_eq!(data["error"]["code"], "submission.not_clearable");
        assert_eq!(window.pending_reservations(&profile).unwrap().len(), 1);
        assert!(
            ReceiptStore::open_at(&home.path().join("receipts"), PROFILE)
                .unwrap()
                .get(ENVELOPE_HASH)
                .unwrap()
                .is_none()
        );
        assert_eq!(cleared_rows(home.path()), 0);
        assert_eq!(rpc.log.sends(), 0, "{status} {floor}: the verb never sends");
    }
}

/// An untimed orphan is cleared on its authenticated hold with both
/// acknowledgements whatever the endpoint reports. With `--acknowledge` alone,
/// recovery and reconciliation may run, but the clear is refused and the hold
/// remains.
#[tokio::test]
#[serial_test::serial]
async fn an_untimed_orphan_is_cleared_with_both_acknowledgements_whatever_the_endpoint_reports() {
    for (status, floor) in [
        ("SUCCESS", 1200),
        ("FAILED", 1200),
        ("NOT_FOUND", 1000),
        ("PENDING", 1200),
    ] {
        let home = tempfile::TempDir::new().unwrap();
        let rpc = OrphanRpc::new(status, floor);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(rpc.clone())
            .mount(&server)
            .await;
        let (window, profile) = orphan_fixture(home.path(), &server.uri());

        let (code, data) = clear(home.path(), true);
        assert_eq!(code, 1, "{status} {floor}: {data}");
        assert_eq!(data["error"]["code"], "submission.unbounded_exposure");
        assert_eq!(window.pending_reservations(&profile).unwrap().len(), 1);
        assert_eq!(cleared_rows(home.path()), 0);

        let (code, data) = orphan_clear(home.path());
        assert_eq!(code, 0, "{status} {floor}: {data}");
        assert_eq!(data["data"]["reservation_released"], true);
        assert!(window.pending_reservations(&profile).unwrap().is_empty());
        let receipt = receipt(home.path());
        assert_eq!(receipt.status, ReceiptStatus::ClearedByOperator);
        assert!(receipt.recovered_from_reservation);
        let rows = rows_of_kind(home.path(), "submission_receipt_cleared");
        assert_eq!(rows.len(), 1, "{status} {floor}: {rows:?}");
        assert_eq!(rows[0]["reservation_released"], true);
        assert_eq!(rows[0]["unbounded_exposure"], true);
        assert_eq!(rpc.log.sends(), 0, "{status} {floor}: the verb never sends");
    }
}

/// The durable recovery receipt is the crash checkpoint before reservation
/// release. A new process finishes from either side of release and records one clear.
#[tokio::test]
#[serial_test::serial]
async fn clear_resumes_after_recovered_receipt_write_before_release() {
    for released_before_retry in [false, true] {
        let home = tempfile::TempDir::new().unwrap();
        let rpc = OrphanRpc::new("NOT_FOUND", 1200);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(rpc.clone())
            .mount(&server)
            .await;
        let (window, profile) = orphan_fixture(home.path(), &server.uri());
        let lock = std::fs::OpenOptions::new()
            .write(true)
            .open(stellar_agent_core::policy::state_lock::window_lock_path(
                &home.path().join(format!("policy/{PROFILE}.window")),
                &profile.policy_window_state_key_id,
            ))
            .unwrap();
        lock.try_lock().unwrap();
        let (interrupted, error) = orphan_clear(home.path());
        assert_eq!(
            interrupted, 1,
            "release must stop at the held lock: {error}"
        );
        let recovered = ReceiptStore::open_at(&home.path().join("receipts"), PROFILE)
            .unwrap()
            .get(ENVELOPE_HASH)
            .unwrap()
            .expect("recovery receipt precedes release");
        assert!(recovered.recovered_from_reservation);
        assert_eq!(recovered.status.label(), "ambiguous");
        drop(lock);
        assert_eq!(window.pending_reservations(&profile).unwrap().len(), 1);
        if released_before_retry {
            window
                .apply_accounting_decision(
                    &profile,
                    window
                        .operator_clear_decision(&profile, ENVELOPE_HASH, true, true)
                        .unwrap(),
                )
                .unwrap();
        }
        let (code, data) = orphan_clear(home.path());
        assert_eq!(code, 0, "{data}");
        assert!(window.pending_reservations(&profile).unwrap().is_empty());
        let receipt = ReceiptStore::open_at(&home.path().join("receipts"), PROFILE)
            .unwrap()
            .get(ENVELOPE_HASH)
            .unwrap()
            .unwrap();
        assert!(receipt.recovered_from_reservation);
        assert_eq!(receipt.status.label(), "cleared_by_operator");
        assert_eq!(cleared_rows(home.path()), 1);
        assert_eq!(rpc.log.sends(), 0, "the verb never sends");
    }
}

/// Status exposes an authenticated orphan marker while keeping the debit held.
#[tokio::test]
#[serial_test::serial]
async fn tx_status_reports_an_orphan_requiring_operator_recovery() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = OrphanRpc::new("NOT_FOUND", 1200);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(rpc.clone())
        .mount(&server)
        .await;
    let (window, profile) = orphan_fixture(home.path(), &server.uri());
    let (code, data) = run_cli(
        home.path(),
        &["tx", "status", TX_HASH, "--profile", PROFILE],
    );
    assert_eq!(code, 0, "{data}");
    assert_eq!(data["data"]["reservation"]["envelope_hash"], ENVELOPE_HASH);
    assert_eq!(data["data"]["reservation"]["operator_required"], true);
    let held = window.pending_reservations(&profile).unwrap();
    assert_eq!(held.len(), 1);
    assert!(held[0].operator_required);
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// Recovery requires a readable receipt store, authenticated window state,
/// and explicit acknowledgement before the first durable write.
#[tokio::test]
#[serial_test::serial]
async fn orphan_recovery_preconditions_leave_state_untouched() {
    for condition in ["unreadable_receipt", "bad_hmac", "no_acknowledgement"] {
        let home = tempfile::TempDir::new().unwrap();
        let rpc = OrphanRpc::new("NOT_FOUND", 1200);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(rpc.clone())
            .mount(&server)
            .await;
        let (_window, _profile) = orphan_fixture(home.path(), &server.uri());
        let window_path = home.path().join(format!("policy/{PROFILE}.window"));
        let receipt_path = home.path().join(format!("receipts/{PROFILE}.json"));
        if condition == "unreadable_receipt" {
            std::fs::write(&receipt_path, b"invalid json").unwrap();
        }
        if condition == "bad_hmac" {
            let mut bytes = std::fs::read(&window_path).unwrap();
            bytes[0] ^= 1;
            std::fs::write(&window_path, bytes).unwrap();
        }
        let original_window = std::fs::read(&window_path).unwrap();
        let original_receipts = std::fs::read(&receipt_path).ok();
        let (code, data) = if condition == "no_acknowledgement" {
            run_cli(
                home.path(),
                &[
                    "tx",
                    "receipt",
                    "clear",
                    ENVELOPE_HASH,
                    "--profile",
                    PROFILE,
                ],
            )
        } else {
            orphan_clear(home.path())
        };
        assert_eq!(code, 1, "{condition}: {data}");
        assert_eq!(
            data["error"]["code"],
            if condition == "no_acknowledgement" {
                "submission.acknowledgement_required"
            } else {
                "submission.record_unavailable"
            }
        );
        assert_eq!(std::fs::read(&window_path).unwrap(), original_window);
        assert_eq!(std::fs::read(&receipt_path).ok(), original_receipts);
        assert_eq!(cleared_rows(home.path()), 0);
        assert_eq!(rpc.log.sends(), 0, "{condition}: the verb never sends");
    }
}

/// A success report restores an orphan receipt while retaining exposure and
/// leaving authenticated outcome audit rows absent.
#[tokio::test]
#[serial_test::serial]
async fn tx_status_surfaces_a_restored_orphan_receipt_without_settlement() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = OrphanRpc::new("SUCCESS", 1200);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(rpc.clone())
        .mount(&server)
        .await;
    let (window, profile) = orphan_fixture(home.path(), &server.uri());
    let args = ["tx", "status", TX_HASH, "--profile", PROFILE];
    let (code, data) = run_cli(home.path(), &args);
    assert_eq!(code, 0, "{data}");
    assert_eq!(data["data"]["record"]["status"], "success");
    assert_eq!(data["data"]["record"]["reservation_open"], true);
    assert_eq!(window.pending_reservations(&profile).unwrap().len(), 1);
    assert_eq!(
        audit_rows(home.path())
            .iter()
            .filter(|row| row.contains("value_action_submitted"))
            .count(),
        0
    );
    let (code, data) = run_cli(home.path(), &args);
    assert_eq!(code, 0, "{data}");
    assert_eq!(
        audit_rows(home.path())
            .iter()
            .filter(|row| row.contains("value_action_submitted"))
            .count(),
        0
    );
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

// ─────────────────────────────────────────────────────────────────────────────
// The decision after reconciliation
// ─────────────────────────────────────────────────────────────────────────────

/// A consumed sequence leaves the outcome unknown; clear records only the
/// operator acknowledgement.
#[tokio::test]
async fn a_negative_observation_writes_only_the_clear_acknowledgement() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    // Sequence 1 is the one the account reports: another transaction used it.
    fixture_with(home.path(), &server.uri(), 1, 0);

    let (code, envelope) = clear(home.path(), true);

    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["data"]["cleared_from"], "pending");
    let cleared = receipt(home.path());
    assert_eq!(cleared.status, ReceiptStatus::ClearedByOperator);
    assert_eq!(
        cleared.release_code, None,
        "absence does not create a release reason"
    );
    let rows: Vec<Value> = audit_rows(home.path())
        .iter()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|row: &Value| row["envelope_hash"] == ENVELOPE_HASH)
        .collect();
    let kinds: Vec<&str> = rows.iter().map(|r| r["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        ["submission_receipt_cleared"],
        "only the operator acknowledgement is recorded: {rows:?}"
    );
    assert!(rows[0].get("evidence").is_none());
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// A retention gap does not clear a bounded transaction that can still apply.
#[tokio::test]
async fn a_receipt_beyond_retention_keeps_its_open_execution_bound() {
    let home = tempfile::TempDir::new().unwrap();
    let mut rpc = FixedStatusRpc::new("NOT_FOUND");
    rpc.floor = 1_200;
    let server = endpoint(&rpc).await;
    // An open time bound and an unconsumed sequence: only the closed retention
    // window makes this receipt clearable.
    fixture_with(home.path(), &server.uri(), 7, now_secs() + 86_400);

    let (code, envelope) = clear(home.path(), true);

    assert_eq!(code, 1, "{envelope}");
    assert_eq!(envelope["error"]["code"], "submission.still_pending");
    let cleared = receipt(home.path());
    assert_eq!(cleared.status, ReceiptStatus::Ambiguous);
    assert_eq!(cleared.release_code, None);
    let rows = rows_of_kind(home.path(), "submission_receipt_cleared");
    assert!(rows.is_empty());
    assert!(rows_of_kind(home.path(), "value_action_failed").is_empty());
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// A sent transaction whose time bound is still open and whose sequence is
/// unconsumed can still apply, so the clear is refused and changes nothing.
#[tokio::test]
#[serial_test::serial]
async fn a_sent_receipt_whose_time_bound_is_open_is_still_pending() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    let max_time = now_secs() + 86_400;
    fixture_with(home.path(), &server.uri(), 7, max_time);
    let (window, profile) = seed_window(home.path(), ENVELOPE_HASH, 7, max_time);

    let (code, envelope) = clear(home.path(), true);

    assert_eq!(code, 1, "{envelope}");
    assert_eq!(envelope["error"]["code"], "submission.still_pending");
    let message = envelope["error"]["message"].as_str().unwrap();
    assert!(
        message.contains(&format!("maxTime {max_time}")),
        "the refusal names the time bound: {message}"
    );
    let unchanged = receipt(home.path());
    assert_eq!(unchanged.status, ReceiptStatus::Pending);
    assert_eq!(unchanged.release_code, None);
    assert_eq!(cleared_rows(home.path()), 0);
    assert!(rows_of_kind(home.path(), "value_action_failed").is_empty());
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
    assert!(window.holds_reservation(&profile, ENVELOPE_HASH).unwrap());
}

/// Without the acknowledgement the refusal names the next step from the
/// record, and nothing is reconciled.
#[tokio::test]
async fn without_the_acknowledgement_the_next_step_comes_from_the_record() {
    for (max_time, next_step) in [
        (now_secs() + 86_400, "run 'stellar-agent tx status"),
        (0, "pass --acknowledge"),
    ] {
        let home = tempfile::TempDir::new().unwrap();
        let rpc = FixedStatusRpc::new("NOT_FOUND");
        let server = endpoint(&rpc).await;
        fixture_with(home.path(), &server.uri(), 7, max_time);

        let (code, envelope) = clear(home.path(), false);

        assert_eq!(code, 1, "{envelope}");
        assert_eq!(
            envelope["error"]["code"],
            "submission.acknowledgement_required"
        );
        let message = envelope["error"]["message"].as_str().unwrap();
        assert!(message.contains(next_step), "maxTime {max_time}: {message}");
        assert_eq!(
            rpc.log.count("getHealth") + rpc.log.count("getLedgerEntries"),
            0,
            "nothing is reconciled without the acknowledgement"
        );
        assert_eq!(receipt(home.path()).status, ReceiptStatus::Pending);
        assert_eq!(rpc.log.sends(), 0, "the verb never sends");
    }
}

/// An audit writer that cannot be acquired refuses the clear before anything
/// is reconciled or changed.
#[tokio::test]
#[serial_test::serial]
async fn an_audit_refusal_reconciles_nothing_and_changes_nothing() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    fixture_with(home.path(), &server.uri(), 1, 0);
    let (window, profile) = seed_window(home.path(), ENVELOPE_HASH, 1, 0);
    std::fs::rename(home.path().join("audit"), home.path().join("audit-held")).unwrap();
    std::fs::write(home.path().join("audit"), b"not a directory").unwrap();

    let (code, envelope) = clear(home.path(), true);

    assert_eq!(code, 1, "{envelope}");
    let refusal = envelope["error"]["code"].as_str().unwrap();
    assert!(refusal.starts_with("audit."), "{envelope}");
    assert_eq!(
        rpc.log.count("getHealth") + rpc.log.count("getLedgerEntries"),
        0,
        "the audit refusal precedes the reconciliation"
    );
    let unchanged = receipt(home.path());
    assert_eq!(unchanged.status, ReceiptStatus::Pending);
    assert_eq!(unchanged.release_code, None);
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
    assert!(window.holds_reservation(&profile, ENVELOPE_HASH).unwrap());
}

/// A reconciliation read that fails is reported as an endpoint failure, and a
/// later successful read does not turn it into a transaction that can still
/// apply.
#[tokio::test]
async fn a_reconciliation_endpoint_failure_refuses_the_clear() {
    let home = tempfile::TempDir::new().unwrap();
    let mut rpc = FixedStatusRpc::new("NOT_FOUND");
    rpc.fail_ledgers = true;
    let server = endpoint(&rpc).await;
    // Without the failure this receipt is the still-pending case.
    fixture_with(home.path(), &server.uri(), 7, now_secs() + 86_400);

    let (code, envelope) = clear(home.path(), true);

    assert_eq!(code, 1, "{envelope}");
    assert_eq!(
        envelope["error"]["code"], "network.rpc_unreachable",
        "the code tx status reports for an endpoint it cannot ask: {envelope}"
    );
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap()
            .contains("getLedgers failed"),
        "{envelope}"
    );
    assert_eq!(
        rpc.log.count("getLedgerEntries"),
        1,
        "the account read after the failure succeeded"
    );
    assert_eq!(receipt(home.path()).status, ReceiptStatus::Pending);
    assert_eq!(cleared_rows(home.path()), 0);
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// A clear acknowledgement that cannot be appended leaves the receipt
/// clearable; retry records one clear and no endpoint-derived failure.
#[tokio::test]
async fn a_failed_clear_append_is_retried_without_a_failure_row() {
    let home = tempfile::TempDir::new().unwrap();
    let mut rpc = FixedStatusRpc::new("NOT_FOUND");
    rpc.break_audit = Some(home.path().to_path_buf());
    let server = endpoint(&rpc).await;
    fixture_with(home.path(), &server.uri(), 1, 0);

    let (code, envelope) = clear(home.path(), true);

    assert_eq!(code, 1, "{envelope}");
    assert!(
        envelope["error"]["code"]
            .as_str()
            .unwrap()
            .starts_with("audit."),
        "the refusal is the audit error: {envelope}"
    );
    let released = receipt(home.path());
    assert_eq!(released.status, ReceiptStatus::Pending);
    assert_eq!(
        released.release_code, None,
        "the receipt stays clearable with an unknown outcome"
    );

    std::fs::remove_file(home.path().join("audit")).unwrap();
    std::fs::rename(home.path().join("audit-held"), home.path().join("audit")).unwrap();
    assert!(rows_of_kind(home.path(), "value_action_failed").is_empty());
    assert_eq!(cleared_rows(home.path()), 0);

    let (code, envelope) = clear(home.path(), true);

    assert_eq!(code, 0, "{envelope}");
    let settled = rows_of_kind(home.path(), "value_action_failed");
    assert!(settled.is_empty(), "{settled:?}");
    let cleared = rows_of_kind(home.path(), "submission_receipt_cleared");
    assert_eq!(cleared.len(), 1, "one clear row: {cleared:?}");
    assert!(cleared[0].get("evidence").is_none());
    assert_eq!(
        receipt(home.path()).status,
        ReceiptStatus::ClearedByOperator
    );
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

// ─────────────────────────────────────────────────────────────────────────────
// Release evidence through tx status and the gate pass
// ─────────────────────────────────────────────────────────────────────────────

/// Sequence and time observations leave the outcome pending and produce no
/// failure row, including on repeated status calls.
#[tokio::test]
async fn tx_status_does_not_promote_negative_observations_to_failure() {
    let now = now_secs();
    for (sequence, max_time, code) in [
        (1, 0, "submission.sequence_consumed"),
        // The time bound passed before the latest ledger closed; the sequence
        // is unconsumed.
        (7, now - 100, "submission.time_bound_passed"),
    ] {
        let home = tempfile::TempDir::new().unwrap();
        let rpc = FixedStatusRpc::new("NOT_FOUND");
        let server = endpoint(&rpc).await;
        fixture_with(home.path(), &server.uri(), sequence, max_time);

        let status = ["tx", "status", TX_HASH, "--profile", PROFILE];
        let (exit, envelope) = run_cli(home.path(), &status);

        assert_eq!(exit, 0, "{code}: {envelope}");
        assert_eq!(envelope["data"]["record"]["status"], "pending");
        assert!(envelope["data"]["record"]["release_code"].is_null());
        let failed = rows_of_kind(home.path(), "value_action_failed");
        assert!(failed.is_empty(), "{code}: {failed:?}");

        let (exit, envelope) = run_cli(home.path(), &status);
        assert_eq!(exit, 0, "{code}: {envelope}");
        assert_eq!(
            rows_of_kind(home.path(), "value_action_failed").len(),
            0,
            "{code}: a rerun writes no failure row"
        );
        assert_eq!(rpc.log.sends(), 0, "{code}: the verb never sends");
    }
}

/// Runs a `pay` that the gate's reconciliation pass reaches and that is then
/// refused, for its unparseable fee, before anything is built or signed.
fn pay_refused_after_the_reconcile_pass(home: &Path) -> (i32, Value) {
    let destination = stellar_agent_test_support::signed_envelope::account_id_for_seed([9; 32]);
    run_cli(
        home,
        &[
            "pay",
            &destination,
            "1 XLM",
            "--source",
            SOURCE,
            "--fee",
            "not-a-fee",
            "--profile",
            PROFILE,
        ],
    )
}

/// Asserts that a run of [`pay_refused_after_the_reconcile_pass`] ended on its
/// unparseable fee.
fn assert_refused_on_the_fee(code: i32, envelope: &Value) {
    assert_eq!(code, 1, "{envelope}");
    assert_eq!(
        envelope["error"]["code"], "validation.amount_malformed",
        "the run refuses on the fee: {envelope}"
    );
    let message = envelope["error"]["message"].as_str().unwrap();
    assert!(message.contains("--fee"), "{message}");
    assert!(
        !message.contains("not-a-fee"),
        "the refusal names the argument, never the rejected value: {message}"
    );
}

/// The gate pass retains untimed exposure on a consumed sequence and never sends.
#[tokio::test]
#[serial_test::serial]
async fn the_gate_pass_retains_negative_exposure_and_never_sends() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    let (window, profile) = windowed_fixture(home.path(), &server.uri(), 1);

    let (code, envelope) = pay_refused_after_the_reconcile_pass(home.path());

    assert_refused_on_the_fee(code, &envelope);
    assert!(
        window.pending_reservations(&profile).unwrap().len() == 1,
        "the pass retains the reservation"
    );
    assert_eq!(receipt(home.path()).release_code, None);
    let failed = rows_of_kind(home.path(), "value_action_failed");
    assert!(failed.is_empty(), "{failed:?}");
    assert_eq!(rpc.log.sends(), 0, "the gate pass never sends");
}

/// An unavailable audit log does not turn a negative observation into an
/// owed failure row; status retains the debit when the log becomes available.
#[tokio::test]
#[serial_test::serial]
async fn a_negative_gate_observation_does_not_owe_an_audit_failure() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    let (window, profile) = windowed_fixture(home.path(), &server.uri(), 1);
    std::fs::rename(home.path().join("audit"), home.path().join("audit-held")).unwrap();
    std::fs::write(home.path().join("audit"), b"not a directory").unwrap();

    let (code, envelope) = pay_refused_after_the_reconcile_pass(home.path());

    assert_refused_on_the_fee(code, &envelope);
    assert_eq!(window.pending_reservations(&profile).unwrap().len(), 1);
    assert_eq!(
        receipt(home.path()).release_code,
        None,
        "the receipt has no definitive failure evidence"
    );
    std::fs::remove_file(home.path().join("audit")).unwrap();
    std::fs::rename(home.path().join("audit-held"), home.path().join("audit")).unwrap();
    assert!(rows_of_kind(home.path(), "value_action_failed").is_empty());

    let (code, envelope) = run_cli(
        home.path(),
        &["tx", "status", TX_HASH, "--profile", PROFILE],
    );

    assert_eq!(code, 0, "{envelope}");
    assert!(envelope["data"]["record"]["release_code"].is_null());
    let failed = rows_of_kind(home.path(), "value_action_failed");
    assert!(failed.is_empty(), "{failed:?}");
    assert_eq!(rpc.log.sends(), 0, "neither run sends");
}

/// An unavailable ledger time permits both the untimed and the unsent clear.
#[tokio::test]
async fn untimed_and_unsent_clears_do_not_need_a_ledger_time() {
    for sent in [true, false] {
        let home = tempfile::TempDir::new().unwrap();
        let mut rpc = FixedStatusRpc::new("NOT_FOUND");
        rpc.fail_ledgers = true;
        let server = endpoint(&rpc).await;
        fixture_with(home.path(), &server.uri(), 7, 0);
        if !sent {
            let receipts = ReceiptStore::open_at(&home.path().join("receipts"), PROFILE).unwrap();
            std::fs::remove_file(receipts.file_path().unwrap()).unwrap();
            receipts
                .begin_submission(
                    ENVELOPE_HASH,
                    TX_HASH,
                    SOURCE,
                    7,
                    now_secs() + 86_400,
                    1_000,
                )
                .unwrap();
        }
        let (code, envelope) = clear(home.path(), true);
        assert_eq!(code, 0, "sent={sent}: {envelope}");
        assert_eq!(
            receipt(home.path()).status,
            ReceiptStatus::ClearedByOperator
        );
        assert!(
            rows_of_kind(home.path(), "submission_receipt_cleared")[0]
                .get("evidence")
                .is_none()
        );
        assert_eq!(rpc.log.count("getLedgers"), 1);
        assert_eq!(rpc.log.sends(), 0);
    }
}

/// An absent account leaves the sequence unknown and permits the untimed clear.
#[tokio::test]
async fn an_absent_source_account_leaves_an_untimed_outcome_unknown() {
    let home = tempfile::TempDir::new().unwrap();
    let mut rpc = FixedStatusRpc::new("NOT_FOUND");
    rpc.source_absent = true;
    let server = endpoint(&rpc).await;
    fixture(home.path(), &server.uri());
    let (code, envelope) = clear(home.path(), true);
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(
        receipt(home.path()).status,
        ReceiptStatus::ClearedByOperator
    );
    assert!(
        rows_of_kind(home.path(), "submission_receipt_cleared")[0]
            .get("evidence")
            .is_none()
    );
    assert_eq!(rpc.log.count("getLedgerEntries"), 1);
    assert_eq!(rpc.log.sends(), 0);
}

/// A clear waits for the receipt checkpoint, and a retry records the reported
/// success: the untimed hold then needs both acknowledgements, with which it
/// is cleared.
#[tokio::test]
#[serial_test::serial]
async fn a_clear_refuses_a_success_whose_receipt_write_failed_and_retries() {
    let home = tempfile::TempDir::new().unwrap();
    let mut rpc = FixedStatusRpc::new("NOT_FOUND");
    rpc.reconcile_success = true;
    let server = endpoint(&rpc).await;
    let (window, profile) = windowed_fixture(home.path(), &server.uri(), 7);
    let receipts = ReceiptStore::open_at(&home.path().join("receipts"), PROFILE).unwrap();
    let held = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(receipts.lock_file_path().unwrap())
        .unwrap();
    held.try_lock().unwrap();
    let before = audit_rows(home.path());

    let (code, envelope) = clear(home.path(), true);
    assert_eq!(code, 1, "{envelope}");
    assert_eq!(envelope["error"]["code"], "submission.record_unavailable");
    assert_eq!(audit_rows(home.path()), before);
    assert_eq!(receipt(home.path()).status, ReceiptStatus::Pending);
    assert!(window.holds_reservation(&profile, ENVELOPE_HASH).unwrap());
    drop(held);

    let (code, envelope) = clear(home.path(), true);
    assert_eq!(code, 1, "{envelope}");
    assert_eq!(envelope["error"]["code"], "submission.unbounded_exposure");
    assert_eq!(receipt(home.path()).status, ReceiptStatus::Success);
    assert_eq!(window.pending_reservations(&profile).unwrap().len(), 1);
    assert_eq!(audit_rows(home.path()), before);

    let (code, envelope) = clear_unbounded(home.path());
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["data"]["cleared_from"], "success");
    assert_eq!(envelope["data"]["reservation_released"], true);
    assert_eq!(
        receipt(home.path()).status,
        ReceiptStatus::ClearedByOperator
    );
    assert!(window.pending_reservations(&profile).unwrap().is_empty());
    assert_eq!(cleared_rows(home.path()), 1);
    assert_eq!(rpc.log.sends(), 0);
}

/// An untimed transaction the endpoint reports as successful keeps its hold
/// on testnet as on mainnet. `--acknowledge` alone is refused; with
/// `--acknowledge-unbounded` as well the clear releases the hold, records
/// that release, and the window admits again.
#[tokio::test]
#[serial_test::serial]
async fn a_testnet_untimed_success_is_cleared_only_with_both_acknowledgements() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("SUCCESS");
    let server = endpoint(&rpc).await;
    let (window, profile) = windowed_fixture(home.path(), &server.uri(), 7);
    assert!(
        !admits(&window, &profile, 999_950),
        "the hold occupies the cap"
    );

    let (code, envelope) = clear(home.path(), true);
    assert_eq!(code, 1, "{envelope}");
    assert_eq!(envelope["error"]["code"], "submission.unbounded_exposure");
    assert_eq!(receipt(home.path()).status, ReceiptStatus::Success);
    assert_eq!(window.pending_reservations(&profile).unwrap().len(), 1);
    assert_eq!(cleared_rows(home.path()), 0);
    assert!(
        !admits(&window, &profile, 999_950),
        "a refused clear leaves the hold counted"
    );

    let (code, envelope) = clear_unbounded(home.path());
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["data"]["cleared_from"], "success");
    assert_eq!(envelope["data"]["reservation_released"], true);
    assert_eq!(
        receipt(home.path()).status,
        ReceiptStatus::ClearedByOperator
    );
    assert!(window.pending_reservations(&profile).unwrap().is_empty());
    let rows = rows_of_kind(home.path(), "submission_receipt_cleared");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["envelope_hash"], ENVELOPE_HASH);
    assert_eq!(rows[0]["reservation_released"], true);
    assert_eq!(rows[0]["unbounded_exposure"], true);
    assert!(
        admits(&window, &profile, 999_950),
        "the cleared hold stops counting"
    );
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// Fails only the post-send receipt write while the real recorder confirms spend.
struct ReceiptWriteFailure<'a> {
    recorder: stellar_agent_network::WalletSubmissionRecorder<'a>,
    receipts: ReceiptStore,
}

#[async_trait::async_trait]
impl stellar_agent_network::SubmissionRecorder for ReceiptWriteFailure<'_> {
    async fn pre_send(
        &self,
        intent: &stellar_agent_network::SubmissionIntent,
    ) -> Result<(), stellar_agent_core::WalletError> {
        self.recorder.pre_send(intent).await
    }

    async fn outcome(
        &self,
        intent: &stellar_agent_network::SubmissionIntent,
        outcome: &stellar_agent_network::SubmissionOutcome,
    ) {
        let held = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.receipts.lock_file_path().unwrap())
            .unwrap();
        held.try_lock().unwrap();
        self.recorder.outcome(intent, outcome).await;
    }
}

/// Status repairs a post-send receipt failure without an authenticated outcome
/// row, keeping exposure unchanged across retries.
#[tokio::test]
#[serial_test::serial]
async fn tx_status_repairs_a_post_send_receipt_failure_without_counting_twice() {
    use stellar_agent_core::audit_log::PolicyDecision;
    use stellar_agent_core::policy::v1::criteria::state_store::{
        PolicyStateStore, StateKey, WindowEntry, WindowLimit,
    };
    use stellar_agent_network::{StellarRpcClient, WalletSubmissionRecorder};
    use stellar_agent_test_support::EchoIdResponder;
    use stellar_agent_test_support::signed_envelope::{
        SignedTestEnvelope, TESTNET_PASSPHRASE, get_network_result,
    };
    use wiremock::matchers::body_partial_json;

    let home = tempfile::TempDir::new().unwrap();
    let server = MockServer::start().await;
    let signed = SignedTestEnvelope::for_source([0x38; 32]);
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    for (rpc_method, result) in [
        ("getNetwork", get_network_result(TESTNET_PASSPHRASE)),
        ("getLedgerEntries", signed.ledger_entries_result()),
        (
            "sendTransaction",
            json!({
                "hash": signed.tx_hash_hex(), "status": "PENDING",
                "latestLedger": 1001, "latestLedgerCloseTime": (now / 1_000).to_string(),
            }),
        ),
        (
            "getTransaction",
            json!({
                "status": "SUCCESS", "latestLedger": 1002, "ledger": 1002,
                "createdAt": (now / 1_000).to_string(),
            }),
        ),
    ] {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": rpc_method})))
            .respond_with(EchoIdResponder::new(result))
            .mount(&server)
            .await;
    }
    let (window, profile) = windowed_fixture(home.path(), &server.uri(), 7);
    window
        .apply_accounting_decision(
            &profile,
            window
                .operator_clear_decision(&profile, ENVELOPE_HASH, true, true)
                .unwrap(),
        )
        .unwrap();
    std::fs::remove_file(home.path().join(format!("receipts/{PROFILE}.json"))).unwrap();
    let receipts = ReceiptStore::open_at(&home.path().join("receipts"), PROFILE).unwrap();
    let key = StateKey::new(PROFILE, 1, "native", 86_400);
    // No post-send audit writer: status repairs the receipt without an outcome fact.
    let recorder = ReceiptWriteFailure {
        recorder: WalletSubmissionRecorder::new(
            &profile,
            PROFILE,
            "stellar_pay_commit",
            Some("stellar:testnet".to_owned()),
            PolicyDecision::Allow,
            vec![],
            vec![WindowEntry::new(
                key.clone(),
                now,
                500,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000_000,
                },
            )],
            receipts.clone(),
            window.clone(),
            None,
            None,
            "receipt-repair",
            now,
        ),
        receipts: receipts.clone(),
    };
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    stellar_agent_network::submit::submit_transaction_and_wait(
        &client,
        signed.envelope_xdr(),
        std::time::Duration::from_secs(5),
        TESTNET_PASSPHRASE,
        None,
        Some(&recorder),
    )
    .await
    .unwrap();
    let checkpoint = receipts
        .find_by_tx_hash(signed.tx_hash_hex())
        .unwrap()
        .unwrap();
    assert_eq!(checkpoint.status, ReceiptStatus::Pending);
    assert_eq!(window.pending_reservations(&profile).unwrap().len(), 1);
    assert!(rows_of_kind(home.path(), "value_action_submitted").is_empty());
    let confirmed_window =
        std::fs::read(home.path().join(format!("policy/{PROFILE}.window"))).unwrap();
    for _ in 0..2 {
        let (code, data) = run_cli(
            home.path(),
            &["tx", "status", signed.tx_hash_hex(), "--profile", PROFILE],
        );
        assert_eq!(code, 0, "{data}");
        assert_eq!(data["data"]["record"]["status"], "success");
        assert_eq!(data["data"]["record"]["reservation_open"], true);
        assert_eq!(
            receipts
                .get(&checkpoint.envelope_hash)
                .unwrap()
                .unwrap()
                .status,
            ReceiptStatus::Success
        );
        let rows = rows_of_kind(home.path(), "value_action_submitted");
        assert!(rows.is_empty(), "{rows:?}");
        let state = PolicyStateStore::new();
        window.load_into(PROFILE, &profile, &state).unwrap();
        assert_eq!(state.query_window(&key, now + 1_000).unwrap(), (500, 1));
        assert_eq!(
            std::fs::read(home.path().join(format!("policy/{PROFILE}.window"))).unwrap(),
            confirmed_window
        );
    }
    assert_eq!(
        stellar_agent_test_support::rpc_request_count(&server, "sendTransaction").await,
        1
    );
}

/// Status and acknowledged clear refuse an edited network before any RPC or final row.
#[tokio::test]
#[serial_test::serial]
async fn chain_flip_cannot_clear_original_hold() {
    let primary = MockServer::start().await;
    let oracle = MockServer::start().await;
    let rpc = FixedStatusRpc::new("FAILED");
    rpc.mount(&primary).await;
    rpc.mount(&oracle).await;
    let home = tempfile::tempdir().unwrap();
    fixture(home.path(), &primary.uri());
    let path = home.path().join(format!("profiles/{PROFILE}.toml"));
    let testnet = std::fs::read_to_string(&path).unwrap();
    let mainnet = testnet
        .replace("stellar:testnet", "stellar:mainnet")
        .replace(&primary.uri(), "https://primary.example");
    std::fs::write(&path, mainnet).unwrap();
    let (window, original) = seed_window(home.path(), ENVELOPE_HASH, 7, 0);
    std::fs::write(&path, testnet).unwrap();
    let window_path = home.path().join(format!("policy/{PROFILE}.window"));
    let before = std::fs::read(&window_path).unwrap();
    let receipt_path = home.path().join(format!("receipts/{PROFILE}.json"));
    let receipt_before = std::fs::read(&receipt_path).unwrap();
    let audit_before = audit_rows(home.path());
    for receipt_bytes in [receipt_before.as_slice(), b"unreadable receipt"] {
        std::fs::write(&receipt_path, receipt_bytes).unwrap();
        for arguments in [
            vec!["tx", "status", TX_HASH],
            vec!["tx", "receipt", "clear", ENVELOPE_HASH, "--acknowledge"],
            vec![
                "tx",
                "receipt",
                "clear",
                ENVELOPE_HASH,
                "--acknowledge",
                "--acknowledge-unbounded",
            ],
        ] {
            let mut arguments = arguments;
            arguments.extend(["--profile", PROFILE]);
            let (code, body) = run_cli(home.path(), &arguments);
            assert_ne!(code, 0, "{body}");
            assert_eq!(
                body["error"]["code"], "policy.window_chain_mismatch",
                "{body}"
            );
            assert_eq!(std::fs::read(&window_path).unwrap(), before);
            assert_eq!(std::fs::read(&receipt_path).unwrap(), receipt_bytes);
            assert_eq!(audit_rows(home.path()), audit_before);
        }
    }
    assert_eq!(window.pending_reservations(&original).unwrap().len(), 1);
    assert!(primary.received_requests().await.unwrap().is_empty());
    assert!(oracle.received_requests().await.unwrap().is_empty());
}

/// The spending the window counts for the fixtures' bucket.
fn counted(
    window: &stellar_agent_network::policy_state::PersistedWindowStore,
    profile: &stellar_agent_core::profile::schema::Profile,
) -> (i128, u32) {
    use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
    let state = PolicyStateStore::new();
    window.load_into(PROFILE, profile, &state).unwrap();
    state
        .query_window(
            &StateKey::new(PROFILE, 1, "native", 86_400),
            stellar_agent_core::timefmt::now_unix_ms().unwrap() + 1_000,
        )
        .unwrap()
}

/// Forged receipts create no settlement rows through `tx status`. Two status
/// calls preserve authentic holds and counted amounts. The forged cases are a
/// receipt edited to `Failed` over an authentic untimed hold and a fabricated
/// `Failed` receipt with no hold. An ambiguous receipt with a release code and
/// a success report are the controls.
#[tokio::test]
#[serial_test::serial]
async fn tx_status_forged_receipts_create_no_settlement_rows() {
    for (label, endpoint_status, held) in [
        ("edited-failed", "FAILED", true),
        ("fabricated-failed", "FAILED", false),
        ("ambiguous-released", "NOT_FOUND", true),
        ("success", "SUCCESS", true),
    ] {
        let home = tempfile::TempDir::new().unwrap();
        let rpc = FixedStatusRpc::new(endpoint_status);
        let server = endpoint(&rpc).await;
        fixture_with(home.path(), &server.uri(), 7, 0);
        let window = held.then(|| seed_window(home.path(), ENVELOPE_HASH, 7, 0));
        let receipts = ReceiptStore::open_at(&home.path().join("receipts"), PROFILE).unwrap();
        match label {
            "edited-failed" | "fabricated-failed" => receipts
                .finalize(
                    ENVELOPE_HASH,
                    ReceiptStatus::Failed {
                        code: "ledger.op_failed".to_owned(),
                    },
                    Some(1_001),
                )
                .unwrap(),
            "ambiguous-released" => receipts
                .finalize_released(
                    ENVELOPE_HASH,
                    stellar_agent_core::profile::receipt::ReleaseEvidence::SequenceConsumed,
                )
                .unwrap(),
            _ => {}
        }
        let before = window.as_ref().map(|(window, profile)| {
            (
                window.pending_reservations(profile).unwrap(),
                counted(window, profile),
            )
        });

        for _ in 0..2 {
            let (code, envelope) = run_cli(
                home.path(),
                &["tx", "status", TX_HASH, "--profile", PROFILE],
            );
            assert_eq!(code, 0, "{label}: {envelope}");
            let record = &envelope["data"]["record"];
            assert_eq!(
                record["settlement_evidence"], "unavailable",
                "{label}: {envelope}"
            );
            assert!(
                record["settlement_decision_id"].is_null(),
                "{label}: {envelope}"
            );
        }

        for kind in [
            "value_action_failed",
            "value_action_submitted",
            "submission_accounting_expired",
        ] {
            let rows = rows_of_kind(home.path(), kind);
            assert!(rows.is_empty(), "{label}: {kind}: {rows:?}");
        }
        match (&window, before) {
            (Some((window, profile)), Some((holds, counted_before))) => {
                assert_eq!(
                    window.pending_reservations(profile).unwrap(),
                    holds,
                    "{label}: the hold stands"
                );
                assert_eq!(holds.len(), 1, "{label}");
                assert_eq!(counted(window, profile), counted_before, "{label}");
                assert_eq!(counted_before, (75, 1), "{label}");
                assert!(
                    window.owed_accounting_expiries(profile).unwrap().is_empty(),
                    "{label}: no accounting decision"
                );
            }
            _ => assert!(
                !home
                    .path()
                    .join(format!("policy/{PROFILE}.window"))
                    .exists(),
                "{label}: no reservation or decision is created"
            ),
        }
        assert_eq!(rpc.log.sends(), 0, "{label}: the verb never sends");
    }
}

/// Commits the accounting expiry of every due hold in `window` through an
/// ordinary pass without the receipt store, and returns the one committed
/// decision identifier. Delivery and projection stay owed.
async fn commit_expiry(
    window: &stellar_agent_network::policy_state::PersistedWindowStore,
    profile: &stellar_agent_core::profile::schema::Profile,
    rpc_url: &str,
) -> String {
    let client = stellar_agent_network::StellarRpcClient::new(rpc_url).unwrap();
    let report = window
        .reconcile_due(
            profile,
            &client,
            None,
            None,
            stellar_agent_core::timefmt::now_unix_ms().unwrap(),
            stellar_agent_network::policy_state::RECONCILE_BUDGET,
        )
        .await
        .unwrap();
    let [settled] = report.settled.as_slice() else {
        panic!("one committed expiry: {report:?}");
    };
    settled.decision_id.clone()
}

/// The `submission_accounting_expired` rows naming `decision_id`.
fn expiry_rows(home: &Path, decision_id: &str) -> usize {
    rows_of_kind(home, "submission_accounting_expired")
        .iter()
        .filter(|row| row["decision_id"] == decision_id)
        .count()
}

/// A delivered accounting event whose receipt projection is still owed
/// completes on a `tx status` run that cannot acquire the audit writer. The
/// output carries the projected record and the run appends no row.
#[tokio::test]
#[serial_test::serial]
async fn tx_status_completes_a_projection_without_the_audit_writer() {
    use stellar_agent_core::audit_log::{AuditWriter, BindingCheck};

    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    let max_time = now_secs() - 86_401;
    fixture_with(home.path(), &server.uri(), 7, max_time);
    let (window, mut profile) = seed_window(home.path(), ENVELOPE_HASH, 7, max_time);
    profile.audit_log_path = home.path().join("audit").join(format!("{PROFILE}.jsonl"));
    let decision_id = commit_expiry(&window, &profile, &server.uri()).await;

    // The event is delivered and acknowledged without the receipt store, so
    // only the projection stays owed.
    {
        let access = stellar_agent_network::keyring::keyed_audit_access(
            &profile,
            PROFILE,
            BindingCheck::Enforce,
        )
        .unwrap();
        let mut writer = AuditWriter::open(profile.audit_log_path.clone(), Some(access)).unwrap();
        let delivered = stellar_agent_network::policy_state::deliver_accounting_expiries(
            &mut writer,
            &window,
            &profile,
            PROFILE,
            None,
        )
        .unwrap();
        assert_eq!(
            (
                delivered.appended,
                delivered.acknowledged,
                delivered.projected
            ),
            (1, 1, 0),
            "{delivered:?}"
        );
    }
    let owed = window.owed_accounting_expiries(&profile).unwrap();
    assert!(owed.unacknowledged.is_empty(), "{owed:?}");
    assert_eq!(owed.unprojected, vec![decision_id.clone()]);

    // The audit chain key is absent, so no audit writer can be acquired.
    let coordinate = profile.audit_log_hash_chain_key_id.clone();
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .delete_credential()
        .unwrap();
    let rows_before = audit_rows(home.path());

    let (code, envelope) = run_cli(
        home.path(),
        &["tx", "status", TX_HASH, "--profile", PROFILE],
    );

    assert_eq!(code, 0, "{envelope}");
    let record = &envelope["data"]["record"];
    assert_eq!(record["settlement_evidence"], "unavailable", "{envelope}");
    assert_eq!(
        record["settlement_decision_id"],
        decision_id.as_str(),
        "{envelope}"
    );
    assert_eq!(
        record["release_code"], "submission.accounting_expired",
        "{envelope}"
    );
    assert_eq!(record["status"], "ambiguous", "{envelope}");
    assert!(
        window
            .owed_accounting_expiries(&profile)
            .unwrap()
            .is_empty(),
        "the projection completes"
    );
    assert_eq!(
        audit_rows(home.path()),
        rows_before,
        "the run appends no row"
    );
    assert_eq!(expiry_rows(home.path(), &decision_id), 1);
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// A `tx status` run whose own reconciliation refuses still delivers the
/// obligations of earlier runs before it renders the refusal.
#[tokio::test]
#[serial_test::serial]
async fn a_refused_tx_status_delivers_old_obligations() {
    const OLD_ENVELOPE_HASH: &str =
        "33333333333333333333333333333333333333333333333333333333333333cc";
    const OLD_TX_HASH: &str = "44444444444444444444444444444444444444444444444444444444444444dd";

    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    let max_time = now_secs() - 86_401;
    fixture_with(home.path(), &server.uri(), 7, max_time);
    let (window, profile) =
        seed_window_for(home.path(), OLD_ENVELOPE_HASH, OLD_TX_HASH, 5, max_time);
    let old = commit_expiry(&window, &profile, &server.uri()).await;
    seed_window(home.path(), ENVELOPE_HASH, 7, max_time);

    let lock = stellar_agent_core::policy::state_lock::WindowStoreLock::acquire_for(
        window.path(),
        &profile.policy_window_state_key_id,
    )
    .unwrap();
    let status = ["tx", "status", TX_HASH, "--profile", PROFILE];
    let (code, refused) = run_cli(home.path(), &status);
    assert_ne!(code, 0, "{refused}");
    assert_eq!(
        refused["error"]["code"], "submission.record_unavailable",
        "{refused}"
    );
    assert_eq!(
        expiry_rows(home.path(), &old),
        1,
        "the old event is appended before the refusal renders"
    );
    drop(lock);

    let (code, envelope) = run_cli(home.path(), &status);
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(
        envelope["data"]["record"]["release_code"], "submission.accounting_expired",
        "{envelope}"
    );
    assert_eq!(expiry_rows(home.path(), &old), 1, "no second row");
    assert_eq!(
        rows_of_kind(home.path(), "submission_accounting_expired").len(),
        2,
        "each decision has one row"
    );
    assert!(
        window
            .owed_accounting_expiries(&profile)
            .unwrap()
            .unacknowledged
            .is_empty()
    );
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}
