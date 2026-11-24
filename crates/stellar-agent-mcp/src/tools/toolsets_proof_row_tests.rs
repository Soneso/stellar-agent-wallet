//! Proof-matrix rows of the public toolset payment commit,
//! `stellar_toolset_invoke/stellar_pay_commit`, on mainnet.
//!
//! Each test drives the toolset route through the parent module's `Run`
//! harness and asserts one claim of the release proof matrix for that row.

use super::*;
use stellar_agent_core::approval::subject::{SubjectKind, approval_subject_classic};
use stellar_agent_network::policy_state::{
    ApprovalState, ApprovalStatus, BusinessId, OperationStatus, OperationView, SlotKind,
};

/// The operation view under the business id of `args`.
fn operation(run: &Run, args: &Value) -> OperationView {
    OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile())
        .view(&BusinessId::parse(args["business_id"].as_str().unwrap()).unwrap())
        .unwrap()
        .expect("the preparation opens the operation record")
}

/// The transaction of the envelope `xdr`.
fn transaction(xdr: &str) -> stellar_xdr::Transaction {
    use stellar_xdr::{Limits, ReadXdr as _, TransactionEnvelope};
    match TransactionEnvelope::from_xdr_base64(xdr, Limits::none()).unwrap() {
        TransactionEnvelope::Tx(envelope) => envelope.tx,
        _ => panic!("a classic envelope"),
    }
}

/// A run whose outer toolset rule requires a 120-second consent and whose
/// routed payment rules allow.
async fn outer_consent_run() -> Run {
    Run::with_policy(
        "require_approval",
        "allow",
        &["propose-transaction", "sign-payment"],
        |raw| outer_lifetime(&raw, 120),
    )
    .await
}

/// A fresh toolset preparation of `run`, under a new business id, whose
/// outer consent queues an inbox entry: the commit arguments without a proof
/// and the queued entry.
async fn queued(run: &Run) -> (Value, stellar_agent_core::approval::PendingApproval) {
    let args = Tool::Pay.prepare_args(&run.f);
    let prepared = run.prepare_route(&args, true).await;
    assert_eq!(prepared["ok"], true, "{prepared}");
    let nonce = prepared["data"]["approval"]["approval_nonce"]
        .as_str()
        .expect("the outer rule queues a consent")
        .to_owned();
    let entry = run
        .pending()
        .into_iter()
        .find(|entry| entry.approval_nonce == nonce)
        .expect("the queued entry");
    (run.commit_args(args, &prepared), entry)
}

/// The seed reads, the minted authorizations and the sends of `run` so far;
/// a refused commit leaves all three unchanged.
fn effects(run: &Run) -> (u32, usize, usize) {
    (
        run.f.seed_reads.load(Ordering::SeqCst),
        authorizations(&run.f).len(),
        run.control.sent().len(),
    )
}

/// A mainnet toolset commit needs a presence-verified approval bound to the
/// signed policy. A proof over a forged assertion refuses with the uniform
/// approval refusal before any key access, for each forgery. The genuine
/// presence-verified proof sends once, and a repeat sends nothing more. A
/// consent given before a policy re-sign authorizes nothing after it: the
/// running server refuses mainnet writes, and a server started on the
/// re-signed policy refuses the proof uniformly.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn the_toolset_commit_needs_a_presence_verified_approval_of_the_signed_policy() {
    use crate::tools::mainnet_presence_tests::{
        Diagnostics, FORGED, FORGED_PROOF_REFUSAL, assert_uniform, forge,
    };
    let mut run = outer_consent_run().await;
    let diagnostics = Diagnostics::install();
    run.grant(run.f.envelope.destination());
    for forged in FORGED {
        let context = format!("{forged:?}");
        let (mut commit, entry) = queued(&run).await;
        run.f.attest(&entry);
        commit["approval_nonce"] = entry.approval_nonce.clone().into();
        commit["approval_attestation"] = forge(&run.f, &entry.approval_nonce, forged).into();
        let before = effects(&run);
        let result = run.commit_route(commit, true).await;
        assert_uniform(&context, &result);
        diagnostics.assert_refused_with(&context, FORGED_PROOF_REFUSAL);
        assert_eq!(effects(&run), before, "{context}: nothing signs or sends");
    }
    assert!(run.control.sent().is_empty());

    let (mut commit, entry) = queued(&run).await;
    commit["approval_nonce"] = entry.approval_nonce.clone().into();
    commit["approval_attestation"] = run.f.attest(&entry).into();
    let sent = run.commit_route(commit.clone(), true).await;
    assert_eq!(sent["ok"], true, "{sent}");
    assert_eq!(run.control.sent().len(), 1);
    assert_eq!(authorizations(&run.f).len(), 1);
    let replay = run.commit_route(commit, true).await;
    assert_eq!(replay["data"]["status"], "replayed", "{replay}");
    assert_eq!(run.control.sent().len(), 1, "the repeat sends nothing");

    let (mut stale, entry) = queued(&run).await;
    stale["approval_nonce"] = entry.approval_nonce.clone().into();
    stale["approval_attestation"] = run.f.attest(&entry).into();
    super::super::common::tests::mainnet::Fixture::write_policy(
        &run.f.raw.replace("sequence = 7", "sequence = 8"),
    );
    let before = effects(&run);
    let refused = run.commit_route(stale.clone(), true).await;
    assert_eq!(
        refused["error"]["code"], "network.mainnet_write_forbidden",
        "the running server: {refused}"
    );
    assert_eq!(effects(&run), before, "the running server signs nothing");
    run.restart();
    let refused = run.commit_route(stale, true).await;
    assert_uniform("re-signed policy", &refused);
    diagnostics.assert_refused_with("re-signed policy", "approval.presence_policy_unavailable");
    assert_eq!(effects(&run), before, "the restarted server signs nothing");
}

/// A toolset-first record binds the exact envelope text. The toolset
/// preparation opens an envelope record, and both its inbox entry and its
/// durable approval record bind the subject of the prepared envelope, not an
/// intent digest. The attested toolset commit signs that envelope's
/// transaction unchanged and sends it once.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn a_toolset_first_record_binds_the_exact_envelope_text() {
    let run = outer_consent_run().await;
    let args = Tool::Pay.prepare_args(&run.f);
    let prepared = run.prepare_route(&args, true).await;
    assert_eq!(prepared["ok"], true, "{prepared}");
    let envelope = prepared["data"]["envelope_xdr"]
        .as_str()
        .unwrap()
        .to_owned();
    let view = operation(&run, &args);
    assert_eq!(view.slot_kind, SlotKind::Envelope, "a toolset-first record");
    let entries = run.pending();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].subject_kind, SubjectKind::EnvelopeText);
    let record = ApprovalStatus::new(&run.f.server.window_store, run.f.server.security_profile())
        .find_by_nonce(&entries[0].approval_nonce)
        .unwrap()
        .expect("the preparation opens the durable record")
        .record;
    assert_eq!(record.operation_id, view.operation_id);
    assert_eq!(record.subject_kind, SubjectKind::EnvelopeText);
    assert_eq!(
        record.subject,
        approval_subject_classic(&envelope),
        "the record binds the prepared envelope text"
    );
    assert_ne!(
        record.subject, view.intent_digest,
        "the record binds no intent digest"
    );

    run.grant(args["destination"].as_str().unwrap());
    let mut commit = run.commit_args(args, &prepared);
    commit["approval_nonce"] = entries[0].approval_nonce.clone().into();
    commit["approval_attestation"] = run.f.attest(&entries[0]).into();
    let sent = run.commit_route(commit, true).await;
    assert_eq!(sent["ok"], true, "{sent}");
    let sent = run.control.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        transaction(&sent[0]),
        transaction(&envelope),
        "the commit signs the bound envelope's transaction"
    );
}

/// The durable approval record of `nonce` on the running server of `run`.
fn durable(run: &Run, nonce: &str) -> stellar_agent_network::policy_state::WireApproval {
    ApprovalStatus::new(&run.f.server.window_store, run.f.server.security_profile())
        .find_by_nonce(nonce)
        .unwrap()
        .expect("the approval has its durable record")
        .record
}

/// The waiting window end, the consent instant and the execution window end
/// of `record`.
fn windows(record: &stellar_agent_network::policy_state::WireApproval) -> (u64, u64, u64) {
    let consent = record.consent.as_ref().expect("the record holds a consent");
    (
        record.waiting_expires_at_ms,
        consent.consent_at_ms,
        consent.execution_expires_at_ms,
    )
}

/// A toolset approval keeps its state and its waiting and execution windows
/// across a restart. The queued record is pending with its waiting window; the
/// consent adds the execution window and keeps the waiting one. A restarted
/// server reads the same record and inbox entry and commits under it on the
/// toolset route. The consumed record keeps both windows across another
/// restart, and a repeat then sends nothing.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn a_toolset_approval_keeps_its_state_and_windows_across_restart() {
    let mut run = outer_consent_run().await;
    run.grant(run.f.envelope.destination());
    let (mut commit, entry) = queued(&run).await;
    let nonce = entry.approval_nonce.clone();
    let waiting = durable(&run, &nonce);
    assert_eq!(waiting.state, ApprovalState::Pending);
    assert!(waiting.consent.is_none(), "the queued record waits");
    assert_eq!(waiting.waiting_expires_at_ms, entry.expires_at_unix_ms);
    run.restart();
    assert_eq!(durable(&run, &nonce), waiting, "the waiting record");

    commit["approval_nonce"] = nonce.clone().into();
    commit["approval_attestation"] = run.f.attest(&entry).into();
    let consented = durable(&run, &nonce);
    assert_eq!(consented.state, ApprovalState::Pending);
    assert_eq!(windows(&consented).0, waiting.waiting_expires_at_ms);
    assert!(windows(&consented).2 > windows(&consented).1);
    let stored = run
        .pending()
        .into_iter()
        .find(|stored| stored.approval_nonce == nonce)
        .unwrap();
    run.restart();
    assert_eq!(durable(&run, &nonce), consented, "the consented record");
    let restored = run
        .pending()
        .into_iter()
        .find(|restored| restored.approval_nonce == nonce)
        .unwrap();
    assert_eq!(
        (restored.created_at_unix_ms, restored.expires_at_unix_ms),
        (stored.created_at_unix_ms, stored.expires_at_unix_ms),
        "the inbox entry keeps its waiting window"
    );
    let sent = run.commit_route(commit.clone(), true).await;
    assert_eq!(sent["ok"], true, "{sent}");
    assert_eq!(run.control.sent().len(), 1);
    let consumed = durable(&run, &nonce);
    assert_eq!(consumed.state, ApprovalState::Consumed);
    assert_eq!(windows(&consumed), windows(&consented));
    run.restart();
    assert_eq!(durable(&run, &nonce), consumed, "the consumed record");
    let replay = run.commit_route(commit, true).await;
    assert_eq!(replay["data"]["status"], "replayed", "{replay}");
    assert_eq!(run.control.sent().len(), 1, "the repeat sends nothing");
}

/// The rows of `run`'s audit log of `kind`.
fn rows(run: &Run, kind: &str) -> Vec<Value> {
    std::fs::read_to_string(&run.f.server.security_profile().audit_log_path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| row["kind"] == kind)
        .collect()
}

/// The rows of `run`'s audit log whose kind starts with `value_action`.
fn value_rows(run: &Run) -> Vec<Value> {
    std::fs::read_to_string(&run.f.server.security_profile().audit_log_path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| {
            row["kind"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("value_action"))
        })
        .collect()
}

/// A revoked approval refuses the toolset commit. The toolset-queued approval
/// is attested, then its durable record is revoked through the recorder,
/// the store transition `approve revoke` runs. The attested toolset commit
/// then refuses `approval.revoked`, reads no seed, mints and sends nothing,
/// appends no value row and no revocation row, and the record stays revoked.
/// The revocation's audit row is written by `approve revoke`, which the
/// cell's CLI ref drives.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn a_revoked_approval_refuses_the_toolset_commit() {
    use stellar_agent_network::policy_state::approvals::ApprovalRecorder;
    let run = outer_consent_run().await;
    run.grant(run.f.envelope.destination());
    let (mut commit, entry) = queued(&run).await;
    commit["approval_nonce"] = entry.approval_nonce.clone().into();
    commit["approval_attestation"] = run.f.attest(&entry).into();
    let record = durable(&run, &entry.approval_nonce);
    {
        let server = &run.f.server;
        let (writer, _readiness) = server.write_audit().unwrap();
        let mut writer = writer.lock().unwrap();
        let revoked = ApprovalRecorder::new(
            &server.window_store,
            server.security_profile(),
            &mut *writer,
            "revoke",
        )
        .revoke(record.id)
        .unwrap();
        assert_eq!(revoked.record.state, ApprovalState::Revoked);
    }
    let revocations = rows(&run, "approval_revoked");
    let values = value_rows(&run);
    let before = effects(&run);
    let refused = run.commit_route(commit, true).await;
    assert_eq!(refused["error"]["code"], "approval.revoked", "{refused}");
    assert_eq!(effects(&run), before, "nothing signs or sends");
    assert!(run.control.sent().is_empty());
    assert_eq!(value_rows(&run), values, "no value row");
    assert_eq!(rows(&run, "approval_revoked"), revocations);
    assert_eq!(
        durable(&run, &entry.approval_nonce).state,
        ApprovalState::Revoked
    );
}

/// A refused toolset preparation preserves the committed settlement and audit
/// evidence of an older retained operation and adds no payment effect. An
/// older envelope operation's window ends one millisecond after it opens; the
/// clock then passes that end, and a toolset preparation whose destination
/// read refuses, unreachable or with a refused credential, answers that code.
/// The older operation stays expired in a reopened store with its
/// `operation_transition` row, and the refused preparation leaves no
/// operation, protocol nonce, approval, authorization, hold, receipt, value
/// row, seed read or send.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn a_refused_toolset_preparation_preserves_the_prior_settlement() {
    use stellar_agent_network::policy_state::{
        OpenRequest, OperationKind, OperationState, OperationTool, PersistedWindowStore,
    };
    for (status, code) in [
        (0, "network.rpc_unreachable"),
        (401, "network.rpc_credential_refused"),
    ] {
        let run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
        let f = &run.f;
        let now = stellar_agent_network::mainnet::clock::now_ms().unwrap();
        let _clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(now);
        let old_id = BusinessId::parse("toolset-settlement-before-refusal").unwrap();
        f.server
            .operation_step(|recorder| {
                recorder
                    .open(&OpenRequest {
                        business_id: old_id.clone(),
                        tool: OperationTool::StellarPay,
                        kind: OperationKind::Pay,
                        intent: stellar_agent_network::operation_entry::envelope_slot(
                            &[9; 32],
                            f.envelope.envelope_xdr(),
                            now / 1000 + 120,
                        ),
                        envelope_xdr: Some(f.envelope.envelope_xdr().to_owned()),
                        prepared_decision: None,
                        rule_ttl_ms: Some(1),
                    })
                    .map_err(stellar_agent_network::operation_entry::operation_refusal)
            })
            .unwrap();
        let _later = stellar_agent_network::mainnet::clock::set_now_ms_for_test(now + 2);
        let args = Tool::Pay.prepare_args(f);
        *run.control.refused_key.lock().unwrap() = Some((
            stellar_agent_test_support::xdr_fixtures::account_ledger_key_xdr(
                f.envelope.destination(),
            ),
            status,
        ));
        let nonce_reads = f.nonce_reads.load(Ordering::SeqCst);
        let result = run.prepare_route(&args, true).await;
        assert_eq!(result["error"]["code"], code, "{result}");
        assert_eq!(
            f.nonce_reads.load(Ordering::SeqCst),
            nonce_reads,
            "{code}: the refused preparation mints no protocol nonce"
        );
        let reopened = PersistedWindowStore::for_profile("operator");
        let statuses = OperationStatus::new(&reopened, f.server.security_profile());
        assert_eq!(
            statuses.view(&old_id).unwrap().unwrap().state,
            OperationState::Expired,
            "{code}: the prior operation settles durably"
        );
        let new_id = BusinessId::parse(args["business_id"].as_str().unwrap()).unwrap();
        assert!(statuses.view(&new_id).unwrap().is_none(), "{code}");
        let transitions = rows(&run, "operation_transition");
        assert!(
            transitions
                .iter()
                .any(|row| row.to_string().contains("expired")),
            "{code}: the settlement audit row is durable: {transitions:?}"
        );
        assert!(value_rows(&run).is_empty(), "{code}: no value row");
        assert!(
            super::super::common::tests::mainnet::ledger(f)
                .unwrap()
                .get("authorizations")
                .is_none(),
            "{code}: no authorization is minted"
        );
        assert!(
            reopened
                .pending_reservations(f.server.security_profile())
                .unwrap()
                .is_empty(),
            "{code}: no hold"
        );
        assert!(
            stellar_agent_core::profile::receipt::ReceiptStore::open("operator")
                .unwrap()
                .all()
                .unwrap()
                .is_empty(),
            "{code}: no receipt"
        );
        assert!(run.pending().is_empty(), "{code}: no approval");
        assert_eq!(f.seed_reads.load(Ordering::SeqCst), 0, "{code}");
        assert_eq!(run.control.count("sendTransaction"), 0, "{code}");
    }
}

/// A mainnet approval of the toolset commit given at the signed HTTPS origin
/// commits. The server restarts on a policy that pins the signed origin, the
/// toolset preparation queues its approval, the fixture credential consents
/// at that origin on the remote surface, and the toolset commit with that
/// attestation sends once and spends the approval.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn a_consent_at_the_signed_origin_commits_the_toolset_payment() {
    use crate::tools::mainnet_presence_tests::{signed_origin_consent, signed_origin_policy};
    let mut run = outer_consent_run().await;
    super::super::common::tests::mainnet::Fixture::write_policy(&signed_origin_policy(&run.f.raw));
    run.restart();
    run.grant(run.f.envelope.destination());
    let (mut commit, entry) = queued(&run).await;
    let blob = signed_origin_consent(&run.f, &entry);
    let consents: Vec<_> = rows(&run, "approval_attested")
        .into_iter()
        .filter(|row| row["origin"] == "serve-remote")
        .collect();
    assert_eq!(consents.len(), 1, "{consents:?}");
    assert!(
        entry
            .approval_nonce
            .starts_with(consents[0]["nonce_prefix"].as_str().unwrap())
    );
    commit["approval_nonce"] = entry.approval_nonce.clone().into();
    commit["approval_attestation"] = blob.into();
    let sent = run.commit_route(commit, true).await;
    assert_eq!(sent["ok"], true, "{sent}");
    assert_eq!(run.control.sent().len(), 1);
    assert_eq!(authorizations(&run.f).len(), 1);
    assert_eq!(
        durable(&run, &entry.approval_nonce).state,
        ApprovalState::Consumed
    );
}

/// The policy `raw` of an outer consent run with an allowing rule for the
/// transaction status tool.
fn with_status_rule(raw: &str) -> String {
    let mut raw = outer_lifetime(raw, 120);
    raw.push_str(
        "\n[[rules]]\nmatch = {tool = \"stellar_transaction_status\", chain = \"stellar:mainnet\"}\n\
         criteria = []\ndecision = \"allow\"\n",
    );
    raw
}

/// One `stellar_transaction_status` call of `business_id` on `run`'s server.
async fn operation_status(run: &Run, business_id: &str) -> Value {
    wire(
        &run.f
            .server
            .call_stellar_transaction_status(crate::server::StellarTransactionStatusArgs {
                chain_id: "stellar:mainnet".to_owned(),
                tx_hash: None,
                business_id: Some(business_id.to_owned()),
                retry_recovery: false,
            })
            .await
            .unwrap(),
    )
}

/// The operation status of a toolset commit reports state, attempts,
/// recovery and the next safe step. While its toolset-queued approval waits,
/// the operation awaits that pending approval with no attempt. After the
/// attested toolset commit whose transaction stays unconfirmed, it reports
/// `sent_outcome_unknown`, one attempt with the sent hash, that transition,
/// and the attempt's recovery result with its next action, `TargetedStatus`.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn the_toolset_commit_reports_its_operation_and_next_step() {
    let run = Run::with_policy(
        "require_approval",
        "allow",
        &["propose-transaction", "sign-payment"],
        |raw| with_status_rule(&raw),
    )
    .await;
    run.control
        .transaction_unknown
        .store(true, Ordering::SeqCst);
    run.grant(run.f.envelope.destination());
    let (mut commit, entry) = queued(&run).await;
    let business_id = commit["business_id"].as_str().unwrap().to_owned();

    let waiting = operation_status(&run, &business_id).await;
    assert_eq!(waiting["ok"], true, "{waiting}");
    let operation = &waiting["data"]["operation"];
    assert_eq!(operation["state"], "awaiting_approval", "{waiting}");
    assert_eq!(operation["attempts"], serde_json::json!([]), "{waiting}");
    assert_eq!(operation["approval"]["state"], "pending", "{waiting}");

    commit["approval_nonce"] = entry.approval_nonce.clone().into();
    commit["approval_attestation"] = run.f.attest(&entry).into();
    let sent = run.commit_route(commit, true).await;
    assert_eq!(sent["error"]["code"], "submission.tx_timeout", "{sent}");
    let tx_hash = sent["error"]["details"]["tx_hash"].clone();
    assert!(tx_hash.is_string(), "{sent}");
    let view = operation_status(&run, &business_id).await;
    assert_eq!(view["ok"], true, "{view}");
    let operation = &view["data"]["operation"];
    assert_eq!(operation["state"], "sent_outcome_unknown", "{view}");
    assert_eq!(operation["attempts"].as_array().map_or(0, Vec::len), 1);
    assert_eq!(operation["attempts"][0]["state"], "sent_outcome_unknown");
    assert_eq!(operation["attempts"][0]["tx_hash"], tx_hash);
    assert_eq!(
        operation["last_transition"]["kind"], "sent_outcome_unknown",
        "{view}"
    );
    let recovery = &view["data"]["recovery"]["attempts"][0];
    assert_eq!(recovery["tx_hash"], tx_hash, "{view}");
    assert_eq!(recovery["result"], "NeedsEvidence", "{view}");
    assert_eq!(recovery["next_action"], "TargetedStatus", "{view}");
}

/// The full name of the lock-order test, which its child processes run.
const LOCK_ORDER_TEST: &str = "tools::toolsets_mainnet_tests::proof_rows::the_toolset_commit_takes_its_locks_across_processes_in_order";

/// The exit code of a `probe` child that finds the install writer lock busy.
const LOCK_BUSY: i32 = 10;
/// The exit code of a `probe` child that finds the install writer lock free.
const LOCK_FREE: i32 = 11;

/// A child process of the lock-order test in `mode` over the toolsets
/// `root`: `hold` takes the install writer lock, prints `HOLDING`, and on a
/// `return` line drops it and returns, or on an `exit` line exits holding
/// it; `probe` exits [`LOCK_BUSY`] or [`LOCK_FREE`]. Neither code is one a
/// test harness run gives.
fn lock_child(mode: &str, root: &std::path::Path) -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", LOCK_ORDER_TEST, "--nocapture"])
        .env("TOOLSET_LOCK_ORDER_MODE", mode)
        .env("TOOLSET_LOCK_ORDER_ROOT", root);
    command
}

/// Starts a `hold` child over `root` and returns it once it holds the lock.
fn spawn_holder(root: &std::path::Path) -> std::process::Child {
    use std::io::BufRead as _;
    let mut holder = lock_child("hold", root);
    holder
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = holder.spawn().unwrap();
    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0, "the writer locks");
        if line.trim() == "HOLDING" {
            break;
        }
    }
    child.stdout = Some(reader.into_inner());
    child
}

/// Ends the `hold` child `holder` with `ending`: `return` drops the lock,
/// `exit` ends the process holding it.
async fn end_holder(mut holder: std::process::Child, ending: &str) {
    use std::io::Write as _;
    holder
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{ending}\n").as_bytes())
        .unwrap();
    let output = tokio::task::spawn_blocking(move || holder.wait_with_output().unwrap())
        .await
        .unwrap();
    assert!(output.status.success(), "{ending}: the writer ends");
}

/// Asserts that the toolset commit of `run` refused in `case` before its
/// protocol nonce was used: the nonce key was not read since `nonce_reads`,
/// nothing entered the replay window, and no seed was read, nothing minted
/// and nothing sent.
async fn assert_refused_before_the_nonce(run: &Run, case: &str, nonce_reads: u32) {
    assert_eq!(
        run.f.nonce_reads.load(Ordering::SeqCst),
        nonce_reads,
        "{case}: no nonce use under the other writer"
    );
    assert!(run.f.server.replay_window.lock().await.is_empty(), "{case}");
    assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0, "{case}");
    assert!(authorizations(&run.f).is_empty(), "{case}");
    assert!(run.control.sent().is_empty(), "{case}");
}

/// The process lock order of the admitted toolset payment: lease, then
/// nonce, then send.
///
/// A writer in another process holding the toolset install lock from the
/// start refuses the toolset commit `toolset.coordination_busy` at the
/// invocation entry. A writer that takes the lock in another process after
/// the commit has passed the entry, at the commit's first endpoint request,
/// makes the commit's own lease refuse `toolset.coordination_busy`, before
/// the nonce: the nonce key is not read, nothing enters the replay window,
/// and nothing is minted or sent. Once the writer returns, or its process
/// exits holding the lock, the same commit sends once. At the moment it reads
/// the nonce key, a writer in another process finds the lock busy and the
/// replay window holds no nonce, so the lease precedes the nonce; during the
/// send the lock is still busy and the nonce is used; after it the lock is
/// free.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn the_toolset_commit_takes_its_locks_across_processes_in_order() {
    use std::io::Write as _;
    if let (Ok(mode), Ok(root)) = (
        std::env::var("TOOLSET_LOCK_ORDER_MODE"),
        std::env::var("TOOLSET_LOCK_ORDER_ROOT"),
    ) {
        let root = std::path::PathBuf::from(root);
        if mode == "probe" {
            let busy = stellar_agent_toolsets_install::lock_toolsets(&root).is_err();
            std::process::exit(if busy { LOCK_BUSY } else { LOCK_FREE });
        }
        let lock = stellar_agent_toolsets_install::lock_toolsets(&root).unwrap();
        writeln!(std::io::stdout(), "HOLDING").unwrap();
        std::io::stdout().flush().unwrap();
        let mut signal = String::new();
        std::io::stdin().read_line(&mut signal).unwrap();
        if signal == "exit\n" {
            std::process::exit(0);
        }
        drop(lock);
        return;
    }
    for ending in ["return", "exit"] {
        let run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
        let args = Tool::Pay.prepare_args(&run.f);
        let prepared = run.prepare_route(&args, false).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        run.grant(args["destination"].as_str().unwrap());
        let commit = run.commit_args(args, &prepared);
        let root = run.root.path().to_owned();

        let entry_root = root.clone();
        let holder = tokio::task::spawn_blocking(move || spawn_holder(&entry_root))
            .await
            .unwrap();
        let nonce_reads = run.f.nonce_reads.load(Ordering::SeqCst);
        let busy = run.commit_route(commit.clone(), true).await;
        assert_eq!(
            busy["error"]["code"], "toolset.coordination_busy",
            "{ending} at the entry: {busy}"
        );
        assert_refused_before_the_nonce(&run, &format!("{ending} at the entry"), nonce_reads).await;
        end_holder(holder, ending).await;

        let late = Arc::new(std::sync::Mutex::new(None));
        let taken = Arc::clone(&late);
        let late_root = root.clone();
        *run.control.on_request.lock().unwrap() = Some(Arc::new(move |_: &str| {
            let mut taken = taken.lock().unwrap();
            if taken.is_none() {
                *taken = Some(spawn_holder(&late_root));
            }
        }));
        let busy = run.commit_route(commit.clone(), true).await;
        *run.control.on_request.lock().unwrap() = None;
        let holder = late
            .lock()
            .unwrap()
            .take()
            .expect("the commit reaches an endpoint request after the entry");
        assert_eq!(
            busy["error"]["code"], "toolset.coordination_busy",
            "{ending} at the lease: {busy}"
        );
        assert_refused_before_the_nonce(&run, &format!("{ending} at the lease"), nonce_reads).await;
        end_holder(holder, ending).await;

        let at_nonce = Arc::new(std::sync::Mutex::new(Vec::new()));
        let nonce_seen = Arc::clone(&at_nonce);
        let nonce_root = root.clone();
        let nonce_window = Arc::clone(&run.f.server.replay_window);
        super::super::common::tests::mainnet::observe(&run.f.on_nonce_read, move || {
            let status = lock_child("probe", &nonce_root).status().unwrap();
            let window_empty = nonce_window
                .try_lock()
                .is_ok_and(|window| window.is_empty());
            nonce_seen
                .lock()
                .unwrap()
                .push((status.code(), window_empty));
        });
        let during = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = Arc::clone(&during);
        let probe_root = root.clone();
        let replay_window = Arc::clone(&run.f.server.replay_window);
        *run.control.on_request.lock().unwrap() = Some(Arc::new(move |method: &str| {
            if method != "sendTransaction" {
                return;
            }
            let status = lock_child("probe", &probe_root).status().unwrap();
            let nonce_used = replay_window
                .try_lock()
                .is_ok_and(|window| !window.is_empty());
            observed.lock().unwrap().push((status.code(), nonce_used));
        }));
        let sent = run.commit_route(commit, true).await;
        *run.control.on_request.lock().unwrap() = None;
        *run.f.on_nonce_read.lock().unwrap() = None;
        assert_eq!(sent["ok"], true, "{ending}: {sent}");
        assert_eq!(run.control.sent().len(), 1, "{ending}");
        assert_eq!(authorizations(&run.f).len(), 1, "{ending}");
        let at_nonce = at_nonce.lock().unwrap().clone();
        assert!(
            !at_nonce.is_empty(),
            "{ending}: the commit reads the nonce key"
        );
        assert!(
            at_nonce.iter().all(|seen| *seen == (Some(LOCK_BUSY), true)),
            "{ending}: at each nonce key read the lease holds the lock and no nonce is used yet: \
             {at_nonce:?}"
        );
        assert_eq!(
            *during.lock().unwrap(),
            vec![(Some(LOCK_BUSY), true)],
            "{ending}: during the send the lease holds the lock and the nonce is used"
        );
        assert_eq!(
            lock_child("probe", &root).status().unwrap().code(),
            Some(LOCK_FREE),
            "{ending}: the lock is free after the send"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// sizing.accounting_inputs_mainnet
// ─────────────────────────────────────────────────────────────────────────────

/// `raw` with one accounting input sized for one 10-stroop payment of the
/// fixture on the rules of `names`: the unlisted budget of the rule's
/// counterparty list, which then lists no destination, a total budget, or a
/// balance floor at the fixture balance less one and a half payments of
/// 10 stroops and a 100-stroop fee.
fn accounting_input(raw: &str, input: &str, names: &[&str]) -> String {
    const BALANCE: i64 = 100_000_000_000;
    let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
    for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
        if !rule["match"]["tool"]
            .as_str()
            .is_some_and(|tool| names.contains(&tool))
        {
            continue;
        }
        let criteria = rule["criteria"].as_array_mut().unwrap();
        let added = match input {
            "unlisted" => {
                for criterion in criteria.iter_mut() {
                    let criterion = criterion.as_inline_table_mut().unwrap();
                    if criterion["kind"].as_str() == Some("counterparty_allowlist") {
                        criterion.insert(
                            "allowlist",
                            toml_edit::Value::Array(toml_edit::Array::new()),
                        );
                        let mut budget = toml_edit::InlineTable::new();
                        for (key, value) in
                            [("mode", "budget"), ("asset", "native"), ("window", "1d")]
                        {
                            budget.insert(key, value.into());
                        }
                        budget.insert("per_tx_stroops", 10_i64.into());
                        budget.insert("per_period_stroops", 10_i64.into());
                        criterion.insert("unlisted", budget.into());
                    }
                }
                continue;
            }
            "total" => {
                "{ kind = \"total_budget\", asset = \"native\", max_stroops = 10 }".to_owned()
            }
            _ => format!(
                "{{ kind = \"balance_floor\", min_stroops = \"{}\" }}",
                BALANCE - 165
            ),
        };
        criteria.push(added.parse::<toml_edit::Value>().unwrap());
    }
    doc.to_string()
}

/// The number of records of each bucket of `run`'s window.
fn bucket_rows(run: &Run) -> std::collections::BTreeMap<String, usize> {
    super::super::common::tests::mainnet::ledger(&run.f).map_or_else(Default::default, |state| {
        state["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|bucket| {
                (
                    bucket["bucket"].as_str().unwrap().to_owned(),
                    bucket["records"].as_array().unwrap().len(),
                )
            })
            .collect()
    })
}

/// The unlisted counter, the budget epoch and the balance floor size the
/// toolset commit from persisted accounting after a restart.
///
/// Each input runs on its own fixture whose allowing rules carry it sized
/// for one 10-stroop payment: the unlisted budget and the total budget on
/// the outer toolset rule and the routed commit rule, and the floor on both
/// routed payment rules over a covered window. The first toolset commit
/// sends; the server restarts; the second toolset commit refuses with the
/// input's refusal and sends nothing. The second payment is prepared through
/// the toolset before the first commit, except over the unlisted budget:
/// there a mainnet payment escalates to a per-payment approval, which the
/// commit queues for the operation its own process prepared, so that payment
/// is prepared after the restart, and its commit without a proof refuses
/// `policy.approval_required`. Over the total budget it refuses
/// `policy.deny.total_budget_exhausted`, and under the floor the first
/// payment's retained debit and fee cross the floor the second fits alone,
/// `account.floor_refused`. Every bucket keeps the one record of the sent
/// commit, and the refusal adds none.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn the_toolset_commit_sizes_its_second_payment_from_persisted_accounting() {
    let mut failures = Vec::new();
    for (input, names, refusal) in [
        (
            "unlisted",
            &["stellar_pay_commit", "stellar_toolset_invoke"][..],
            "policy.approval_required",
        ),
        (
            "total",
            &["stellar_pay_commit", "stellar_toolset_invoke"][..],
            "policy.deny.total_budget_exhausted",
        ),
        (
            "floor",
            &["stellar_pay", "stellar_pay_commit"][..],
            "account.floor_refused",
        ),
    ] {
        let mut run = Run::with_policy(
            "allow",
            "allow",
            &["propose-transaction", "sign-payment"],
            |raw| accounting_input(&raw, input, names),
        )
        .await;
        if input == "floor" {
            super::super::common::tests::mainnet::cover_native_history(&run.f);
        }
        // A toolset commit that requires approval binds the operation its
        // own process prepared, so the unlisted case prepares its second
        // payment after the restart.
        let after_restart = input == "unlisted";
        let first = Tool::Pay.prepare_args(&run.f);
        run.grant(first["destination"].as_str().unwrap());
        let second = Tool::Pay.prepare_args(&run.f);
        let first_prepared = run.prepare_route(&first, true).await;
        let mut second_prepared = if after_restart {
            Value::Null
        } else {
            run.prepare_route(&second, true).await
        };
        if first_prepared["ok"] != true || (!after_restart && second_prepared["ok"] != true) {
            failures.push(format!(
                "{input}: preparations: {first_prepared} and {second_prepared}"
            ));
            continue;
        }
        let sent = run
            .commit_route(run.commit_args(first, &first_prepared), true)
            .await;
        let sends = run.control.sent().len();
        let window = bucket_rows(&run);
        run.restart();
        if after_restart {
            second_prepared = run.prepare_route(&second, true).await;
            if second_prepared["ok"] != true {
                failures.push(format!(
                    "{input}: preparation after the restart: {second_prepared}"
                ));
                continue;
            }
        }
        let refused = run
            .commit_route(run.commit_args(second, &second_prepared), true)
            .await;
        if sent["ok"] != true || sends != 1 {
            failures.push(format!(
                "{input}: first toolset commit, {sends} sent: {sent}"
            ));
        }
        if refused["error"]["code"] != refusal || run.control.sent().len() != sends {
            failures.push(format!(
                "{input}: second toolset commit after the restart, {} sent: {refused}",
                run.control.sent().len()
            ));
        }
        if window.is_empty() || window.values().any(|records| *records != 1) {
            failures.push(format!("{input}: window after the sent commit {window:?}"));
        }
        if bucket_rows(&run) != window {
            failures.push(format!(
                "{input}: the refusal changed the window {window:?} to {:?}",
                bucket_rows(&run)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
