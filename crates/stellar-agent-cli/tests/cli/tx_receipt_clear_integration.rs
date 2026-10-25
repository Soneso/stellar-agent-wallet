//! `stellar-agent tx receipt clear` and `tx status` against a mocked
//! endpoint.
//!
//! Clearing a submission record states that the transaction did not move
//! value, and the wallet cannot establish that on its own. The endpoint can,
//! so the verb asks it first and reconciles before it decides: a transaction
//! the chain has answered for is settled by reconciliation, not by an
//! operator; one released on chain evidence gets its settled row before the
//! clear; one that can still apply is refused; and an endpoint that cannot
//! answer is not a licence to clear either. No path sends the transaction
//! again, which every responder here counts.
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
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore, ReleaseEvidence};
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

/// A submission the wallet recorded and never sent is clearable, and clearing
/// it frees the pair.
///
/// A process killed between the record and the send leaves exactly this shape.
/// It holds its source account's sequence, and the sequence never advances
/// because nothing applied, so every rebuild at that number is refused.
#[tokio::test]
#[serial_test::serial]
async fn a_submission_that_was_never_sent_is_cleared() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    fixture(home.path(), &server.uri());

    // A receipt recorded and never sent, with a time bound that is still open
    // and a sequence the account has not consumed: only its unsent state
    // makes it clearable.
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

    assert_eq!(code, 0, "an unsent submission is clearable: {envelope}");
    assert!(!window.holds_reservation(&profile, unsent).unwrap());
    let receipts = ReceiptStore::open_at(&receipts_dir, PROFILE).unwrap();
    assert_eq!(
        receipts.get(unsent).unwrap().unwrap().status,
        stellar_agent_core::profile::receipt::ReceiptStatus::ClearedByOperator
    );
    let outcome = receipts
        .begin_submission(
            "4444444444444444444444444444444444444444444444444444444444444444",
            TX_HASH,
            SOURCE,
            9,
            0,
            1_000,
        )
        .unwrap();
    assert!(
        matches!(
            outcome,
            stellar_agent_core::profile::receipt::BeginSubmissionOutcome::Recorded
        ),
        "clearing frees the pair the unsent receipt held; got {outcome:?}"
    );
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// A settled record whose transaction the endpoint no longer reports is
/// refused, and writes no row.
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
                stellar_agent_core::profile::receipt::ReceiptStatus::Failed {
                    code: "submission.on_chain_failed".to_owned(),
                },
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
            stellar_agent_core::profile::receipt::ReceiptStatus::Failed { .. }
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
        id: id.to_owned(),
        tx_hash: TX_HASH.to_owned(),
        source: SOURCE.to_owned(),
        sequence,
        max_time,
        pending_since_ms: now - 400_000,
        submission_ledger: 1000,
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

fn orphan_clear(home: &Path) -> (i32, Value) {
    run_cli(
        home,
        &[
            "tx",
            "receipt",
            "clear",
            ENVELOPE_HASH,
            "--acknowledge",
            "--profile",
            PROFILE,
        ],
    )
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

/// Only an absent transaction beyond retention permits orphan reconstruction.
#[tokio::test]
#[serial_test::serial]
async fn answerable_or_in_retention_orphans_are_not_cleared() {
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
            .open(home.path().join(format!("policy/{PROFILE}.window.lock")))
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
            window.release(&profile, ENVELOPE_HASH).unwrap();
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

/// A definitive answer can restore an orphan's receipt during status lookup;
/// the resulting receipt and its one settlement audit row must be visible.
#[tokio::test]
#[serial_test::serial]
async fn tx_status_surfaces_a_restored_orphan_receipt_and_settlement_row() {
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
    assert_eq!(data["data"]["record"]["reservation_open"], false);
    assert!(window.pending_reservations(&profile).unwrap().is_empty());
    assert_eq!(
        audit_rows(home.path())
            .iter()
            .filter(|row| row.contains("value_action_submitted"))
            .count(),
        1
    );
    let (code, data) = run_cli(home.path(), &args);
    assert_eq!(code, 0, "{data}");
    assert_eq!(
        audit_rows(home.path())
            .iter()
            .filter(|row| row.contains("value_action_submitted"))
            .count(),
        1
    );
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

// ─────────────────────────────────────────────────────────────────────────────
// The decision after reconciliation
// ─────────────────────────────────────────────────────────────────────────────

/// A reservation the clear's reconciliation releases on chain evidence gets
/// its settled row before the clear, and the clear row names the evidence.
#[tokio::test]
async fn an_evidence_release_writes_the_settled_row_before_the_clear() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    // Sequence 1 is the one the account reports: another transaction used it.
    fixture_with(home.path(), &server.uri(), 1, 0);

    let (code, envelope) = clear(home.path(), true);

    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["data"]["cleared_from"], "ambiguous");
    let cleared = receipt(home.path());
    assert_eq!(cleared.status, ReceiptStatus::ClearedByOperator);
    assert_eq!(
        cleared.release_code,
        Some(ReleaseEvidence::SequenceConsumed),
        "the cleared receipt keeps the reason its reservation was released"
    );
    let rows: Vec<Value> = audit_rows(home.path())
        .iter()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|row: &Value| row["envelope_hash"] == ENVELOPE_HASH)
        .collect();
    let kinds: Vec<&str> = rows.iter().map(|r| r["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        ["value_action_failed", "submission_receipt_cleared"],
        "the settled row precedes the clear: {rows:?}"
    );
    assert_eq!(rows[0]["code"], "submission.sequence_consumed");
    assert_eq!(rows[1]["evidence"], "submission.sequence_consumed");
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

/// An ambiguous receipt whose retention window closed is cleared with an
/// unknown outcome, whatever its time bound.
#[tokio::test]
async fn a_receipt_beyond_retention_is_cleared_with_an_unknown_outcome() {
    let home = tempfile::TempDir::new().unwrap();
    let mut rpc = FixedStatusRpc::new("NOT_FOUND");
    rpc.floor = 1_200;
    let server = endpoint(&rpc).await;
    // An open time bound and an unconsumed sequence: only the closed retention
    // window makes this receipt clearable.
    fixture_with(home.path(), &server.uri(), 7, now_secs() + 86_400);

    let (code, envelope) = clear(home.path(), true);

    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["data"]["cleared_from"], "ambiguous");
    let cleared = receipt(home.path());
    assert_eq!(cleared.status, ReceiptStatus::ClearedByOperator);
    assert_eq!(cleared.release_code, None);
    let rows = rows_of_kind(home.path(), "submission_receipt_cleared");
    assert_eq!(rows.len(), 1);
    assert!(rows[0].get("evidence").is_none(), "{}", rows[0]);
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

/// A settled row that cannot be appended refuses the clear and leaves the
/// receipt clearable; the retry writes one settled row and one clear row.
#[tokio::test]
async fn a_failed_settlement_append_is_retried_without_a_second_row() {
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
    assert_eq!(released.status, ReceiptStatus::Ambiguous);
    assert_eq!(
        released.release_code,
        Some(ReleaseEvidence::SequenceConsumed),
        "the receipt keeps its evidence and stays clearable"
    );

    std::fs::remove_file(home.path().join("audit")).unwrap();
    std::fs::rename(home.path().join("audit-held"), home.path().join("audit")).unwrap();
    assert!(rows_of_kind(home.path(), "value_action_failed").is_empty());
    assert_eq!(cleared_rows(home.path()), 0);

    let (code, envelope) = clear(home.path(), true);

    assert_eq!(code, 0, "{envelope}");
    let settled = rows_of_kind(home.path(), "value_action_failed");
    assert_eq!(settled.len(), 1, "one settled row: {settled:?}");
    assert_eq!(settled[0]["code"], "submission.sequence_consumed");
    let cleared = rows_of_kind(home.path(), "submission_receipt_cleared");
    assert_eq!(cleared.len(), 1, "one clear row: {cleared:?}");
    assert_eq!(cleared[0]["evidence"], "submission.sequence_consumed");
    assert_eq!(
        receipt(home.path()).status,
        ReceiptStatus::ClearedByOperator
    );
    assert_eq!(rpc.log.sends(), 0, "the verb never sends");
}

// ─────────────────────────────────────────────────────────────────────────────
// Release evidence through tx status and the gate pass
// ─────────────────────────────────────────────────────────────────────────────

/// `tx status` writes the settled row under each release code, reports it on
/// the record, and a rerun writes no second row.
#[tokio::test]
async fn tx_status_writes_the_settled_row_under_each_release_code() {
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
        assert_eq!(envelope["data"]["record"]["status"], "ambiguous");
        assert_eq!(envelope["data"]["record"]["release_code"], code);
        let failed = rows_of_kind(home.path(), "value_action_failed");
        assert_eq!(failed.len(), 1, "{code}: {failed:?}");
        assert_eq!(failed[0]["code"], code);
        assert_eq!(failed[0]["envelope_hash"], ENVELOPE_HASH);

        let (exit, envelope) = run_cli(home.path(), &status);
        assert_eq!(exit, 0, "{code}: {envelope}");
        assert_eq!(
            rows_of_kind(home.path(), "value_action_failed").len(),
            1,
            "{code}: a rerun writes no second row"
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
            "1",
            "--source",
            SOURCE,
            "--fee",
            "not-a-fee",
            "--profile",
            PROFILE,
        ],
    )
}

/// The gate pass a value verb runs releases a due reservation on chain
/// evidence, writes its settled row under the evidence's code, and never
/// sends.
#[tokio::test]
#[serial_test::serial]
async fn the_gate_pass_settles_on_evidence_and_never_sends() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    let (window, profile) = windowed_fixture(home.path(), &server.uri(), 1);

    let (code, envelope) = pay_refused_after_the_reconcile_pass(home.path());

    assert_eq!(code, 1, "{envelope}");
    assert!(
        window.pending_reservations(&profile).unwrap().is_empty(),
        "the pass released the reservation"
    );
    assert_eq!(
        receipt(home.path()).release_code,
        Some(ReleaseEvidence::SequenceConsumed)
    );
    let failed = rows_of_kind(home.path(), "value_action_failed");
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0]["code"], "submission.sequence_consumed");
    assert_eq!(rpc.log.sends(), 0, "the gate pass never sends");
}

/// A gate pass that cannot write the settled row leaves the reason on the
/// receipt, and the next `tx status` writes the row under it.
#[tokio::test]
#[serial_test::serial]
async fn a_release_reason_left_by_a_gate_pass_is_written_by_tx_status() {
    let home = tempfile::TempDir::new().unwrap();
    let rpc = FixedStatusRpc::new("NOT_FOUND");
    let server = endpoint(&rpc).await;
    let (window, profile) = windowed_fixture(home.path(), &server.uri(), 1);
    std::fs::rename(home.path().join("audit"), home.path().join("audit-held")).unwrap();
    std::fs::write(home.path().join("audit"), b"not a directory").unwrap();

    let (code, envelope) = pay_refused_after_the_reconcile_pass(home.path());

    assert_eq!(code, 1, "{envelope}");
    assert!(window.pending_reservations(&profile).unwrap().is_empty());
    assert_eq!(
        receipt(home.path()).release_code,
        Some(ReleaseEvidence::SequenceConsumed),
        "the receipt keeps the reason the row is owed"
    );
    std::fs::remove_file(home.path().join("audit")).unwrap();
    std::fs::rename(home.path().join("audit-held"), home.path().join("audit")).unwrap();
    assert!(rows_of_kind(home.path(), "value_action_failed").is_empty());

    let (code, envelope) = run_cli(
        home.path(),
        &["tx", "status", TX_HASH, "--profile", PROFILE],
    );

    assert_eq!(code, 0, "{envelope}");
    assert_eq!(
        envelope["data"]["record"]["release_code"],
        "submission.sequence_consumed"
    );
    let failed = rows_of_kind(home.path(), "value_action_failed");
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0]["code"], "submission.sequence_consumed");
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

/// A clear waits for the receipt checkpoint and recognizes success on retry.
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
    assert_eq!(envelope["error"]["code"], "submission.not_clearable");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap()
            .contains("settled by reconciliation")
    );
    assert_eq!(receipt(home.path()).status, ReceiptStatus::Success);
    assert!(window.pending_reservations(&profile).unwrap().is_empty());
    assert_eq!(audit_rows(home.path()), before);
    assert_eq!(rpc.log.sends(), 0);
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

/// Status repairs a post-send receipt failure and writes the missing settlement
/// once, keeping the recorder's confirmed window spend unchanged across retries.
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
    window.release(&profile, ENVELOPE_HASH).unwrap();
    std::fs::remove_file(home.path().join(format!("receipts/{PROFILE}.json"))).unwrap();
    let receipts = ReceiptStore::open_at(&home.path().join("receipts"), PROFILE).unwrap();
    let key = StateKey::new(PROFILE, 1, "native", 86_400);
    // No post-send audit writer: status owes the outcome row as well as the receipt.
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
    assert!(window.pending_reservations(&profile).unwrap().is_empty());
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
        assert_eq!(data["data"]["record"]["reservation_open"], false);
        assert_eq!(
            receipts
                .get(&checkpoint.envelope_hash)
                .unwrap()
                .unwrap()
                .status,
            ReceiptStatus::Success
        );
        let rows = rows_of_kind(home.path(), "value_action_submitted");
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["envelope_hash"], checkpoint.envelope_hash);
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
