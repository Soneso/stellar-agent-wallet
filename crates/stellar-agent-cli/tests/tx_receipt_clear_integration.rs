//! `stellar-agent tx receipt clear` against a mocked endpoint.
//!
//! Clearing a submission record states that the transaction did not move
//! value, and the wallet cannot establish that on its own. The endpoint can,
//! so the verb asks it first: a transaction the chain has answered for is
//! settled by reconciliation, not by an operator, and an endpoint that cannot
//! answer is not a licence to clear either.
//!
//! Driven as subprocesses of the real binary so the printed envelope is the
//! one an operator sees. The CLI crate has no `[lib]` target.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics and unwraps are acceptable"
)]

use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};
use stellar_agent_core::profile::receipt::ReceiptStore;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend,
/// so no child process can reach the login keychain.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

const PROFILE: &str = "clear-guard";
const ENVELOPE_HASH: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const TX_HASH: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const SOURCE: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

/// Answers every `getTransaction` with one fixed status.
struct FixedStatusRpc {
    status: &'static str,
}

impl Respond for FixedStatusRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or_else(|_| json!({}));
        let req_id = body.get("id").cloned().unwrap_or_else(|| json!(1));
        let result = match self.status {
            "SUCCESS" => json!({
                "status": "SUCCESS",
                "latestLedger": 1_002,
                "oldestLedger": 1,
                "ledger": 1_001,
            }),
            other => json!({
                "status": other,
                "latestLedger": 1_002,
                "oldestLedger": 1,
            }),
        };
        ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }))
    }
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
/// seeds a sent-but-unanswered submission receipt.
fn fixture(home: &Path, rpc_url: &str) {
    fixture_with_approval(home, rpc_url, None);
}

fn fixture_with_approval(home: &Path, rpc_url: &str, approval_nonce: Option<&str>) {
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

    let receipts = ReceiptStore::open_at(&home.join("receipts"), PROFILE).unwrap();
    receipts
        .begin_submission_with_approval(ENVELOPE_HASH, TX_HASH, SOURCE, 7, 0, 1_000, approval_nonce)
        .unwrap();
    receipts.mark_submitted(ENVELOPE_HASH).unwrap();
}

#[tokio::test]
async fn tx_status_completes_owed_approval_consumption_once() {
    use stellar_agent_core::approval::{
        ApprovalKind, ConsumedOutcome, PendingApproval, PendingApprovalStore,
    };
    let home = tempfile::TempDir::new().unwrap();
    let rpc = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(FixedStatusRpc { status: "SUCCESS" })
        .mount(&rpc)
        .await;
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
    fixture_with_approval(home.path(), &rpc.uri(), Some(&nonce));
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

/// The endpoint says the transaction reached a ledger, so the operator does
/// not get to declare it never moved value.
#[tokio::test]
async fn a_submission_the_chain_answered_for_is_not_cleared_by_an_operator() {
    let home = tempfile::TempDir::new().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(FixedStatusRpc { status: "SUCCESS" })
        .mount(&server)
        .await;
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
}

/// The endpoint cannot account for the transaction, which is the state the
/// operator verb exists for.
#[tokio::test]
async fn a_submission_the_endpoint_cannot_account_for_is_cleared() {
    let home = tempfile::TempDir::new().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(FixedStatusRpc {
            status: "NOT_FOUND",
        })
        .mount(&server)
        .await;
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
}

/// Without `--acknowledge` the verb refuses whatever the chain says.
#[tokio::test]
async fn a_clear_without_the_acknowledgement_is_refused() {
    let home = tempfile::TempDir::new().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(FixedStatusRpc {
            status: "NOT_FOUND",
        })
        .mount(&server)
        .await;
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
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(FixedStatusRpc {
            status: "NOT_FOUND",
        })
        .mount(&server)
        .await;
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
}

/// A receipt whose transaction the chain confirmed writes no row either.
///
/// The local rule admits a `Pending` receipt, so this one is stopped by the
/// chain answer, and it is stopped before anything is released or written.
#[tokio::test]
async fn a_pending_receipt_the_chain_confirmed_writes_no_row() {
    let home = tempfile::TempDir::new().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(FixedStatusRpc { status: "SUCCESS" })
        .mount(&server)
        .await;
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
}

/// A submission the wallet recorded and never sent is clearable, and clearing
/// it frees the pair.
///
/// A process killed between the record and the send leaves exactly this shape.
/// It holds its source account's sequence, and the sequence never advances
/// because nothing applied, so every rebuild at that number is refused.
#[tokio::test]
async fn a_submission_that_was_never_sent_is_cleared() {
    let home = tempfile::TempDir::new().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(FixedStatusRpc {
            status: "NOT_FOUND",
        })
        .mount(&server)
        .await;
    fixture(home.path(), &server.uri());

    // Undo the fixture's send flag: this receipt was recorded and never sent.
    let receipts_dir = home.path().join("receipts");
    let unsent = "3333333333333333333333333333333333333333333333333333333333333333";
    {
        let receipts = ReceiptStore::open_at(&receipts_dir, PROFILE).unwrap();
        receipts
            .begin_submission(unsent, TX_HASH, SOURCE, 9, 0, 1_000)
            .unwrap();
        assert!(!receipts.get(unsent).unwrap().unwrap().submitted);
    }

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
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(FixedStatusRpc {
            status: "NOT_FOUND",
        })
        .mount(&server)
        .await;
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
}
