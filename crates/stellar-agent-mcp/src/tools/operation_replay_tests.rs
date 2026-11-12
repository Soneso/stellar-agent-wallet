//! Business ids at the MCP value tools.
//!
//! A mainnet value call names its operation with a business id. A retry
//! under a retained id answers with the stored state and does no new work:
//! no signature, no mint, no send and no value audit row. Another intent
//! under the same id refuses and leaves the record as it is, and a commit
//! under another id refuses. A mainnet call without an id refuses once the
//! refusals a call with one gives have passed, before any record. Off
//! mainnet the id is validated and echoed, and no record exists.
//! The rows drive the four classic tools, the x402 payment and the
//! authenticated x402 payment of a routed mainnet fixture.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only fixture construction and assertions"
)]

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::common::tests::fresh_business_id;
use super::common::tests::mainnet::{
    ClassicRun, Fixture, Tool, X402Run, authorizations, fixture_entries, ledger, mount_rpc,
    observe, put, stored_approval, wire, x402_args,
};
use super::x402_authenticated_mainnet_tests::{HOME, Run as AuthenticatedRun, signings};

/// The operation records of the fixture's window file.
fn records(f: &Fixture) -> Vec<Value> {
    ledger(f)
        .and_then(|state| state["operations"]["records"].as_array().cloned())
        .unwrap_or_default()
}

/// The one operation record under `business_id`.
fn record(f: &Fixture, business_id: &str) -> Value {
    let found: Vec<Value> = records(f)
        .into_iter()
        .filter(|record| record["business_id"] == business_id)
        .collect();
    assert_eq!(found.len(), 1, "one record under {business_id}: {found:?}");
    found[0].clone()
}

/// The operations section of the fixture's window file.
fn operations(f: &Fixture) -> Value {
    ledger(f).map_or(Value::Null, |state| state["operations"].clone())
}

/// The fixture's audit log as written.
fn audit_text(f: &Fixture) -> String {
    std::fs::read_to_string(&f.server.security_profile().audit_log_path).unwrap_or_default()
}

/// Asserts that `result` answers with the stored state of `stored`, the
/// record under `business_id`, and returns that state's wire name.
fn assert_replay(context: &str, result: &Value, business_id: &str, stored: &Value) -> String {
    assert_eq!(result["ok"], true, "{context}: {result}");
    let data = &result["data"];
    assert_eq!(data["status"], "replayed", "{context}: {result}");
    assert_eq!(data["business_id"], business_id, "{context}: {result}");
    assert_eq!(data["operation"]["id"], stored["id"], "{context}: {result}");
    assert_eq!(
        data["operation"]["state"], stored["state"],
        "{context}: {result}"
    );
    let state = stored["state"].as_str().unwrap().to_owned();
    let next = match state.as_str() {
        "sending" | "sent_outcome_unknown" | "prepared" => "wait",
        _ => "none",
    };
    assert_eq!(data["next"], next, "{context}: {result}");
    assert!(
        data.get("envelope_xdr").is_none() && data.get("paymentSignature").is_none(),
        "{context}: a replay carries no new work: {result}"
    );
    state
}

/// Everything a retried call must leave as it is: the signer calls, the
/// mints, the operation records and the audit log.
#[derive(Debug, PartialEq)]
struct Effects {
    seed_reads: u32,
    authorizations: Vec<Value>,
    operations: Value,
    audit: String,
}

impl Effects {
    fn of(f: &Fixture) -> Self {
        Self {
            seed_reads: f.seed_reads.load(Ordering::SeqCst),
            authorizations: authorizations(f),
            operations: operations(f),
            audit: audit_text(f),
        }
    }
}

/// The preparation arguments of `tool` on `run`'s fixture under
/// `business_id`.
fn prepare_args(run: &ClassicRun, business_id: &str) -> Value {
    let mut args = run.tool.prepare_args(&run.f);
    args["business_id"] = json!(business_id);
    args
}

/// A classic run prepared and approved under `business_id`.
async fn classic_run(tool: Tool, business_id: &str) -> ClassicRun {
    let id = business_id.to_owned();
    ClassicRun::with(
        tool,
        |raw| raw,
        |_| {},
        move |args| {
            args["business_id"] = json!(id);
        },
    )
    .await
}

/// The commit arguments of `run` with a protocol nonce minted now, so a
/// second commit presents an unused one.
fn fresh_commit_args(run: &ClassicRun) -> Value {
    run.commit_args_for(
        run.args["envelope_xdr"].as_str().unwrap(),
        &run.entry.approval_nonce,
        run.args["approval_attestation"].as_str().unwrap(),
    )
}

/// The request methods a classic call sends before its lookup answers: the
/// endpoint identity probe alone.
const BEFORE_LOOKUP: [&str; 1] = ["getNetwork"];

/// The x402 payment arguments of `run` under `business_id`, approved when
/// `approval` is set.
fn x402_args_under(
    f: &Fixture,
    approval: Option<(&str, &str)>,
    business_id: &str,
) -> crate::server::X402CreatePaymentArgs {
    let mut args = x402_args(f, approval);
    args.business_id = Some(business_id.to_owned());
    args
}

/// Runs the x402 preparation call under `business_id` and attests its
/// pending approval.
async fn x402_prepare_under(run: &X402Run, business_id: &str) -> (String, String) {
    let prepared = run
        .pay_with(x402_args_under(&run.f, None, business_id))
        .await;
    assert_eq!(prepared["ok"], true, "{prepared}");
    assert_eq!(prepared["data"]["business_id"], business_id, "{prepared}");
    let nonce = prepared["data"]["approval"]["approval_nonce"]
        .as_str()
        .unwrap()
        .to_owned();
    let entry = stored_approval(&run.f, &nonce).unwrap();
    (nonce, run.f.attest(&entry))
}

/// The authenticated x402 arguments of `run` for [`HOME`] under
/// `business_id`.
fn authenticated_args_under(
    run: &AuthenticatedRun,
    approval: Option<(&str, &str)>,
    business_id: &str,
) -> crate::server::X402AuthenticatedPaymentArgs {
    let mut args = run.args(HOME, approval);
    args.business_id = Some(business_id.to_owned());
    args
}

/// Runs the authenticated preparation call under `business_id` and attests
/// its pending approval.
async fn authenticated_prepare_under(
    run: &AuthenticatedRun,
    business_id: &str,
) -> (String, String) {
    let prepared = run
        .call(authenticated_args_under(run, None, business_id))
        .await;
    assert_eq!(prepared["ok"], true, "{prepared}");
    assert_eq!(prepared["data"]["business_id"], business_id, "{prepared}");
    let nonce = prepared["data"]["approval"]["approval_nonce"]
        .as_str()
        .unwrap()
        .to_owned();
    let entry = stored_approval(&run.f, &nonce).unwrap();
    (nonce, run.f.attest(&entry))
}

/// The payment requirements of `f` for `amount` base units, as the tools
/// receive them.
fn requirements_for(f: &Fixture, amount: &str) -> String {
    let mut requirements = serde_json::to_value(f.requirements()).unwrap();
    requirements["amount"] = json!(amount);
    serde_json::to_string(&requirements).unwrap()
}

/// A retry under a retained business id answers with the stored operation and
/// does no new work, for each value kind. The retries are the preparation and
/// the identical commit of the four classic tools after their commit, the x402
/// payment and the authenticated x402 payment. No signer call, mint,
/// `sendTransaction` request, record change or audit row follows the first run,
/// and a retried commit sends nothing past the endpoint probe. The first
/// preparation and the first commit or payment each name the business id in
/// their result.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn retried_business_id_returns_the_stored_operation_for_every_kind() {
    for tool in Tool::ALL {
        let id = fresh_business_id();
        let run = classic_run(tool, &id).await;
        assert_eq!(
            run.prepared["business_id"],
            id.as_str(),
            "{tool:?} prepare: {}",
            run.prepared
        );
        let committed = run.commit().await;
        assert_eq!(committed["ok"], true, "{tool:?}: {committed}");
        assert_eq!(
            committed["data"]["business_id"],
            id.as_str(),
            "{tool:?} commit: {committed}"
        );
        assert_eq!(run.control.count("sendTransaction"), 1, "{tool:?}");
        let stored = record(&run.f, &id);
        let before = Effects::of(&run.f);

        run.control.clear();
        run.oracle_control.clear();
        let prepared = wire(&tool.prepare(&run.f.server, &prepare_args(&run, &id)).await);
        let context = format!("{tool:?} prepare");
        assert_replay(&context, &prepared, &id, &stored);
        assert_eq!(
            run.control.methods(),
            BEFORE_LOOKUP,
            "{context}: the retry builds nothing"
        );
        assert_eq!(Effects::of(&run.f), before, "{context}");

        run.oracle_control.clear();
        let recommitted = run.commit().await;
        let context = format!("{tool:?} commit");
        assert_replay(&context, &recommitted, &id, &stored);
        assert_eq!(
            run.control.methods(),
            BEFORE_LOOKUP,
            "{context}: the retry verifies no approval and rebuilds nothing"
        );
        assert!(run.oracle_control.methods().is_empty(), "{context}");
        assert_eq!(Effects::of(&run.f), before, "{context}");
    }

    let run = X402Run::new().await;
    let id = fresh_business_id();
    let approval = x402_prepare_under(&run, &id).await;
    let paid = run
        .pay_with(x402_args_under(
            &run.f,
            Some((&approval.0, &approval.1)),
            &id,
        ))
        .await;
    assert_eq!(paid["ok"], true, "x402: {paid}");
    assert_eq!(paid["data"]["business_id"], id.as_str(), "x402: {paid}");
    let stored = record(&run.f, &id);
    assert_eq!(stored["state"], "payload_released", "x402: {stored}");
    let before = Effects::of(&run.f);
    let retried = run
        .pay_with(x402_args_under(
            &run.f,
            Some((&approval.0, &approval.1)),
            &id,
        ))
        .await;
    assert_replay("x402", &retried, &id, &stored);
    assert_eq!(run.simulations(), 0, "x402: nothing is simulated");
    assert_eq!(Effects::of(&run.f), before, "x402");

    let run = AuthenticatedRun::new().await;
    let id = fresh_business_id();
    let approval = authenticated_prepare_under(&run, &id).await;
    let paid = run
        .call(authenticated_args_under(
            &run,
            Some((&approval.0, &approval.1)),
            &id,
        ))
        .await;
    assert_eq!(paid["ok"], true, "authenticated x402: {paid}");
    assert_eq!(
        paid["data"]["business_id"],
        id.as_str(),
        "authenticated x402: {paid}"
    );
    assert_eq!(signings().len(), 1, "authenticated x402");
    let stored = record(&run.f, &id);
    let before = Effects::of(&run.f);
    let posts = run.double.posts().await;
    run.control.clear();
    let retried = run
        .call(authenticated_args_under(
            &run,
            Some((&approval.0, &approval.1)),
            &id,
        ))
        .await;
    assert_replay("authenticated x402", &retried, &id, &stored);
    assert!(signings().is_empty(), "authenticated x402: nothing signs");
    assert_eq!(run.double.posts().await, posts, "authenticated x402");
    assert_eq!(
        run.control.count("simulateTransaction"),
        0,
        "authenticated x402"
    );
    assert_eq!(Effects::of(&run.f), before, "authenticated x402");
}

/// A preparation retried under the id of a waiting record returns the envelope
/// that record stores. It does so also once the clock moved past the second
/// that bounds a rebuilt envelope's time bounds.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn retried_prepare_returns_the_stored_envelope() {
    for tool in Tool::ALL {
        let id = fresh_business_id();
        let run = classic_run(tool, &id).await;
        let stored = record(&run.f, &id);
        assert_eq!(stored["state"], "prepared", "{tool:?}: {stored}");
        assert_eq!(
            stored["envelope_xdr"], run.args["envelope_xdr"],
            "{tool:?}: the record binds the prepared envelope"
        );
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let prepared = wire(&tool.prepare(&run.f.server, &prepare_args(&run, &id)).await);
        assert_eq!(prepared["ok"], true, "{tool:?}: {prepared}");
        assert_eq!(
            prepared["data"]["envelope_xdr"], run.args["envelope_xdr"],
            "{tool:?}: the stored envelope returns"
        );
        assert_eq!(record(&run.f, &id), stored, "{tool:?}: the record stays");
        assert_eq!(records(&run.f).len(), 1, "{tool:?}: no second record");
    }
}

/// Another intent under the business id of a retained operation refuses with
/// `operation.business_id_conflict`, for each value kind. Nothing signs or
/// sends, no authorization is minted, and the operation records stay
/// byte-identical.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn another_intent_under_the_same_business_id_refuses_for_every_kind() {
    for tool in Tool::ALL {
        let id = fresh_business_id();
        let run = classic_run(tool, &id).await;
        let before = Effects::of(&run.f);
        let mut args = prepare_args(&run, &id);
        if tool == Tool::Claim {
            // A claim is named by its balance; another one is another claim.
            args["balance_id"] = json!(OTHER_BALANCE.repeat(32));
        } else {
            args["fee"] = json!("200");
        }
        run.control.clear();
        let result = wire(&tool.prepare(&run.f.server, &args).await);
        assert_eq!(result["ok"], false, "{tool:?}: {result}");
        assert_eq!(
            result["error"]["code"], "operation.business_id_conflict",
            "{tool:?}: {result}"
        );
        assert_eq!(
            run.control.methods(),
            BEFORE_LOOKUP,
            "{tool:?}: nothing is read past the probe"
        );
        assert_eq!(Effects::of(&run.f), before, "{tool:?}");
    }

    let run = X402Run::new().await;
    let id = fresh_business_id();
    x402_prepare_under(&run, &id).await;
    let before = Effects::of(&run.f);
    let mut args = x402_args_under(&run.f, None, &id);
    args.payment_required = requirements_for(&run.f, "11");
    let result = run.pay_with(args).await;
    assert_eq!(result["ok"], false, "x402: {result}");
    assert_eq!(
        result["error"]["code"], "operation.business_id_conflict",
        "x402: {result}"
    );
    assert!(run.control.methods().is_empty(), "x402: nothing is sent");
    assert_eq!(Effects::of(&run.f), before, "x402");

    let run = AuthenticatedRun::new().await;
    let id = fresh_business_id();
    authenticated_prepare_under(&run, &id).await;
    let before = Effects::of(&run.f);
    let posts = run.double.posts().await;
    let mut args = authenticated_args_under(&run, None, &id);
    args.payment_required = requirements_for(&run.f, "11");
    let result = run.call(args).await;
    assert_eq!(result["ok"], false, "authenticated x402: {result}");
    assert_eq!(
        result["error"]["code"], "operation.business_id_conflict",
        "authenticated x402: {result}"
    );
    assert!(signings().is_empty(), "authenticated x402: nothing signs");
    assert_eq!(run.double.posts().await, posts, "authenticated x402");
    assert_eq!(Effects::of(&run.f), before, "authenticated x402");
}

/// A claim of the same balance by another claimant under the business id of a
/// retained claim refuses with `operation.business_id_conflict`. The claimant
/// is the effective source, so the retry names another source account. Nothing
/// is read past the probe and nothing signs, mints or sends.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_claim_by_another_claimant_under_the_same_business_id_conflicts() {
    let id = fresh_business_id();
    let run = classic_run(Tool::Claim, &id).await;
    let committed = run.commit().await;
    assert_eq!(committed["ok"], true, "{committed}");
    let before = Effects::of(&run.f);
    let mut args = prepare_args(&run, &id);
    let claimant = stellar_strkey::ed25519::PublicKey([0x42; 32])
        .to_string()
        .as_str()
        .to_owned();
    assert_ne!(args["source_account"], json!(claimant));
    args["source_account"] = json!(claimant);
    run.control.clear();
    let result = wire(&Tool::Claim.prepare(&run.f.server, &args).await);
    assert_eq!(result["ok"], false, "{result}");
    assert_eq!(
        result["error"]["code"], "operation.business_id_conflict",
        "{result}"
    );
    assert_eq!(
        run.control.methods(),
        BEFORE_LOOKUP,
        "nothing is read past the probe"
    );
    assert_eq!(Effects::of(&run.f), before);
}

/// The byte pattern of a second claimable balance's hash.
const OTHER_BALANCE: &str = "cd";

/// The fixture's ledger entries with its claimable balance passed through
/// `edit`.
fn entries_with_balance(
    f: &Fixture,
    edit: impl FnOnce(&mut stellar_xdr::ClaimableBalanceEntry),
) -> Vec<Value> {
    use stellar_xdr::{LedgerEntryData, Limits, ReadXdr as _, WriteXdr as _};
    let mut entries = fixture_entries(f);
    let mut edit = Some(edit);
    for entry in &mut entries {
        let data = LedgerEntryData::from_xdr_base64(entry["xdr"].as_str().unwrap(), Limits::none())
            .unwrap();
        if let LedgerEntryData::ClaimableBalance(mut balance) = data {
            (edit
                .take()
                .expect("the fixture holds one claimable balance"))(&mut balance);
            entry["xdr"] = json!(
                LedgerEntryData::ClaimableBalance(balance)
                    .to_xdr_base64(Limits::none())
                    .unwrap()
            );
        }
    }
    assert!(edit.is_none(), "the fixture holds a claimable balance");
    entries
}

/// The fixture's ledger entries with a second claimable balance beside its
/// own, the same balance under the hash [`OTHER_BALANCE`] repeats.
fn entries_with_second_balance(f: &Fixture) -> Vec<Value> {
    use stellar_xdr::{
        ClaimableBalanceId, Hash, LedgerEntryData, LedgerKey, LedgerKeyClaimableBalance, Limits,
        ReadXdr as _, WriteXdr as _,
    };
    let mut entries = fixture_entries(f);
    let id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xcd; 32]));
    let second = entries
        .iter()
        .find_map(|entry| {
            match LedgerEntryData::from_xdr_base64(entry["xdr"].as_str().unwrap(), Limits::none()) {
                Ok(LedgerEntryData::ClaimableBalance(mut balance)) => {
                    balance.balance_id = id.clone();
                    let mut second = entry.clone();
                    second["key"] = json!(
                        LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                            balance_id: id.clone(),
                        })
                        .to_xdr_base64(Limits::none())
                        .unwrap()
                    );
                    second["xdr"] = json!(
                        LedgerEntryData::ClaimableBalance(balance)
                            .to_xdr_base64(Limits::none())
                            .unwrap()
                    );
                    Some(second)
                }
                _ => None,
            }
        })
        .expect("the fixture holds a claimable balance");
    entries.push(second);
    entries
}

/// A claim preparation retried after its balance left the ledger answers with
/// the stored claim under its business id and does no new work. A preparation
/// under an unknown id keeps the ledger's refusal.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_claim_retry_after_its_balance_left_replays_the_stored_claim() {
    use stellar_xdr::{LedgerEntryData, Limits, ReadXdr as _};
    let id = fresh_business_id();
    let run = classic_run(Tool::Claim, &id).await;
    let committed = run.commit().await;
    assert_eq!(committed["ok"], true, "{committed}");
    let stored = record(&run.f, &id);
    let without_balance: Vec<Value> = fixture_entries(&run.f)
        .into_iter()
        .filter(|entry| {
            !matches!(
                LedgerEntryData::from_xdr_base64(entry["xdr"].as_str().unwrap(), Limits::none()),
                Ok(LedgerEntryData::ClaimableBalance(_))
            )
        })
        .collect();
    *run.control.entries.lock().unwrap() = Some(without_balance);
    let before = Effects::of(&run.f);

    let prepared = wire(
        &Tool::Claim
            .prepare(&run.f.server, &prepare_args(&run, &id))
            .await,
    );
    assert_replay("claim", &prepared, &id, &stored);
    assert_eq!(Effects::of(&run.f), before);

    let other = wire(
        &Tool::Claim
            .prepare(&run.f.server, &prepare_args(&run, &fresh_business_id()))
            .await,
    );
    assert_eq!(other["error"]["code"], "claim.balance_not_found", "{other}");
    assert_eq!(Effects::of(&run.f), before, "no record opens");
}

/// A retained claim of unknown outcome answers with its stored state once its
/// predicate expired, and does no new work. The lookup precedes the balance
/// read and the predicate check, whose answer changed once the claim ran. A
/// preparation under an unknown id keeps the predicate refusal.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_retained_claim_replays_after_its_predicate_expires() {
    let id = fresh_business_id();
    let run = classic_run(Tool::Claim, &id).await;
    let committed = run.commit().await;
    assert_eq!(committed["ok"], true, "{committed}");
    let stored = record(&run.f, &id);
    assert_eq!(stored["state"], "sent_outcome_unknown", "{stored}");
    *run.control.entries.lock().unwrap() = Some(entries_with_balance(&run.f, |balance| {
        for claimant in balance.claimants.iter_mut() {
            let stellar_xdr::Claimant::ClaimantTypeV0(claimant) = claimant;
            claimant.predicate = stellar_xdr::ClaimPredicate::BeforeAbsoluteTime(1);
        }
    }));
    let before = Effects::of(&run.f);

    run.control.clear();
    let prepared = wire(
        &Tool::Claim
            .prepare(&run.f.server, &prepare_args(&run, &id))
            .await,
    );
    assert_eq!(
        assert_replay("claim", &prepared, &id, &stored),
        "sent_outcome_unknown"
    );
    assert_eq!(prepared["data"]["next"], "wait", "{prepared}");
    assert_eq!(
        run.control.methods(),
        BEFORE_LOOKUP,
        "the balance is not read"
    );
    assert_eq!(Effects::of(&run.f), before);

    let fresh = fresh_business_id();
    let pass_from = stellar_agent_network::mainnet::clock::now_ms().unwrap();
    let other = wire(
        &Tool::Claim
            .prepare(&run.f.server, &prepare_args(&run, &fresh))
            .await,
    );
    let pass_to = stellar_agent_network::mainnet::clock::now_ms().unwrap();
    assert_eq!(
        other["error"]["code"], "claim.predicate_not_satisfied",
        "{other}"
    );
    let after = Effects::of(&run.f);
    assert_eq!(after.seed_reads, before.seed_reads);
    assert_eq!(after.authorizations, before.authorizations);
    assert_eq!(
        after.audit, before.audit,
        "the recovery state appends no row"
    );
    assert_only_recovery_state_changes(
        &after.operations,
        &before.operations,
        &fresh,
        pass_from..=pass_to,
    );
}

/// A call under the fresh id `fresh` refuses after the reconciliation pass.
/// That pass evaluates the stored attempt, which waits in
/// `sent_outcome_unknown` with no sequence release.
///
/// No record or tombstone opens and the record count stays. The whole
/// operations object keeps its earlier value apart from the stored attempt's
/// recovery state, which is its first. The fixture's ledger pages hold no
/// entries, so the state is `evidence_pending` with detail
/// `malformed_history`. Both cursors stay at the attempt's lower bound,
/// ledger 100, and the pass time falls inside `pass_ms`.
fn assert_only_recovery_state_changes(
    after: &Value,
    before: &Value,
    fresh: &str,
    pass_ms: std::ops::RangeInclusive<u64>,
) {
    assert_only_stored_recovery_changes(after, before, fresh, pass_ms, 100);
}

/// The check of [`assert_only_recovery_state_changes`] with the attempt's
/// lower bound `cursor`.
fn assert_only_stored_recovery_changes(
    after: &Value,
    before: &Value,
    fresh: &str,
    pass_ms: std::ops::RangeInclusive<u64>,
    cursor: u64,
) {
    let count = |operations: &Value| operations["records"].as_array().map(Vec::len);
    assert_eq!(count(after), count(before), "the record count stays");
    for section in ["records", "tombstones"] {
        assert!(
            after[section]
                .as_array()
                .into_iter()
                .flatten()
                .all(|entry| entry["business_id"] != fresh),
            "nothing opens under {fresh} in {section}"
        );
    }
    assert!(
        before["records"][0]["attempts"][0]
            .get("recovery")
            .is_none()
    );
    let mut unchanged = after.clone();
    let mut recovery = unchanged["records"][0]["attempts"][0]
        .as_object_mut()
        .unwrap()
        .remove("recovery")
        .unwrap();
    assert_eq!(
        &unchanged, before,
        "only the stored attempt's recovery state changes"
    );
    let pass_at = recovery
        .as_object_mut()
        .unwrap()
        .remove("last_pass_at_ms")
        .and_then(|value| value.as_u64())
        .unwrap();
    assert!(pass_ms.contains(&pass_at), "{pass_at} in {pass_ms:?}");
    assert_eq!(
        recovery,
        json!({
            "diagnostic": {"text": "malformed_history"},
            "disagreements": 0,
            "last_outcome": "evidence_pending",
            "primary_cursor": cursor,
            "witness_cursor": cursor,
        })
    );
}

/// The recovery check refuses a tombstone under the fresh id, a changed
/// tombstone under another id and a changed record field; the designed
/// change alone passes.
#[test]
fn the_recovery_check_refuses_every_change_outside_the_recovery_state() {
    let before = json!({
        "records": [{"business_id": "stored", "state": "sent_outcome_unknown", "attempts": [{"index": 1}]}],
        "tombstones": [{"business_id": "old", "state": "succeeded"}],
    });
    let mut after = before.clone();
    after["records"][0]["attempts"][0]["recovery"] = json!({
        "diagnostic": {"text": "malformed_history"},
        "disagreements": 0,
        "last_outcome": "evidence_pending",
        "last_pass_at_ms": 5,
        "primary_cursor": 7,
        "witness_cursor": 7,
    });
    let check = |after: &Value| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_only_stored_recovery_changes(after, &before, "fresh", 0..=10, 7);
        }))
        .is_ok()
    };
    assert!(check(&after));
    let mut fresh_tombstone = after.clone();
    fresh_tombstone["tombstones"]
        .as_array_mut()
        .unwrap()
        .push(json!({"business_id": "fresh", "state": "failed"}));
    let mut changed_tombstone = after.clone();
    changed_tombstone["tombstones"][0]["state"] = json!("failed");
    let mut changed_record = after.clone();
    changed_record["records"][0]["state"] = json!("failed");
    for altered in [fresh_tombstone, changed_tombstone, changed_record] {
        assert!(!check(&altered), "{altered}");
    }
}

/// A retry while the first commit waits for its send to answer finds the
/// attempt `Sending` with its exposure committed. It answers with that state,
/// reads no signing seed and sends nothing, and the first commit then
/// completes.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_retry_while_sending_replays_without_signing() {
    for tool in Tool::ALL {
        let id = fresh_business_id();
        let run = classic_run(tool, &id).await;
        run.control.send_delay_ms.store(2_000, Ordering::SeqCst);
        let server = run.f.server.clone();
        let args = run.args.clone();
        let commit = tokio::spawn(async move { tool.commit(&server, args).await });
        let waited = std::time::Instant::now();
        while run.control.count("sendTransaction") == 0 {
            assert!(
                waited.elapsed() < Duration::from_secs(30),
                "{tool:?}: the commit sends"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let stored = record(&run.f, &id);
        assert_eq!(stored["state"], "sending", "{tool:?}: {stored}");
        assert!(
            stored["attempts"][0]["exposure"].is_object(),
            "{tool:?}: the send follows the committed exposure: {stored}"
        );
        let seed_reads = run.seed_reads();
        let prepared = wire(&tool.prepare(&run.f.server, &prepare_args(&run, &id)).await);
        assert_replay(&format!("{tool:?}"), &prepared, &id, &stored);
        assert_eq!(run.seed_reads(), seed_reads, "{tool:?}: nothing signs");
        assert_eq!(run.control.count("sendTransaction"), 1, "{tool:?}");

        let committed = wire(&commit.await.unwrap().unwrap());
        assert_eq!(committed["ok"], true, "{tool:?}: {committed}");
        assert_eq!(run.control.count("sendTransaction"), 1, "{tool:?}");
    }
}

/// The attempt is committed as `Sending` before the signature. At the signer's
/// read of its seed, the record under the commit's business id holds one
/// attempt in `Sending` with no exposure.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn begin_attempt_commits_sending_before_the_signature() {
    for tool in Tool::ALL {
        let id = fresh_business_id();
        let run = classic_run(tool, &id).await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let at_signature = Arc::clone(&seen);
        let path = run.f.server.window_store.path().to_path_buf();
        observe(&run.f.on_seed_read, move || {
            let bytes = std::fs::read(&path).unwrap();
            let state: Value = serde_json::from_slice(&bytes[32..]).unwrap();
            at_signature
                .lock()
                .unwrap()
                .push(state["operations"].clone());
        });
        let committed = run.commit().await;
        assert_eq!(committed["ok"], true, "{tool:?}: {committed}");
        let seen = seen.lock().unwrap().clone();
        assert!(!seen.is_empty(), "{tool:?}: the commit signs");
        let section = &seen[0];
        let at_signature: Vec<&Value> = section["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|record| record["business_id"] == id.as_str())
            .collect();
        assert_eq!(at_signature.len(), 1, "{tool:?}: {section}");
        let at_signature = at_signature[0];
        assert_eq!(at_signature["state"], "sending", "{tool:?}: {at_signature}");
        let attempts = at_signature["attempts"].as_array().unwrap();
        assert_eq!(attempts.len(), 1, "{tool:?}: {at_signature}");
        assert!(
            attempts[0].get("exposure").is_none(),
            "{tool:?}: the exposure follows the signature: {at_signature}"
        );
    }
}

/// The window state at `path`, as the fixture's store wrote it.
fn window_state(path: &std::path::Path) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    Some(serde_json::from_slice(&bytes[32..]).unwrap())
}

/// The first attempt of the record under `business_id` in `state`, and
/// the authorization that attempt links, when both exist.
fn attempt_and_intent(state: &Value, business_id: &str) -> Option<(Value, Value)> {
    let record = state["operations"]["records"]
        .as_array()?
        .iter()
        .find(|record| record["business_id"] == business_id)?;
    let attempt = record["attempts"].as_array()?.first()?.clone();
    let intent = state["authorizations"]
        .as_array()?
        .iter()
        .find(|auth| auth["id"] == attempt["authorization_id"])?
        .clone();
    Some((attempt, intent))
}

/// The `operation_transition` audit rows of operation `operation_id`.
fn transition_rows(f: &Fixture, operation_id: &Value) -> Vec<Value> {
    audit_text(f)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| row["kind"] == "operation_transition" && row["operation_id"] == *operation_id)
        .collect()
}

/// An x402 run prepared under `business_id`, with its approval.
async fn x402_run_under(business_id: &str) -> (X402Run, (String, String)) {
    let run = X402Run::new().await;
    let approval = x402_prepare_under(&run, business_id).await;
    (run, approval)
}

/// The payment call of `run` under `business_id` with `approval`.
async fn x402_pay_under(run: &X402Run, approval: &(String, String), business_id: &str) -> Value {
    run.pay_with(x402_args_under(
        &run.f,
        Some((&approval.0, &approval.1)),
        business_id,
    ))
    .await
}

/// The x402 attempt is committed as `Sending` after the intent mint and before
/// the signature, in one commit that records both steps. At the signer's read
/// of its seed the record holds one attempt in `Sending` without an exposure,
/// and the intent is claimed. The audit rows of the `authorized` and `sending`
/// steps carry one commit id the record retains.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn x402_before_sign_commits_authorized_and_sending_together() {
    let id = fresh_business_id();
    let (run, approval) = x402_run_under(&id).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let at_signature = Arc::clone(&seen);
    let path = run.f.server.window_store.path().to_path_buf();
    observe(&run.f.on_seed_read, move || {
        at_signature
            .lock()
            .unwrap()
            .push(window_state(&path).unwrap());
    });
    let paid = x402_pay_under(&run, &approval, &id).await;
    *run.f.on_seed_read.lock().unwrap() = None;
    assert_eq!(paid["ok"], true, "{paid}");

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "one seed read");
    let state = &seen[0];
    let records: Vec<&Value> = state["operations"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["business_id"] == id.as_str())
        .collect();
    assert_eq!(records.len(), 1, "{state}");
    assert_eq!(records[0]["state"], "sending", "{state}");
    assert_eq!(
        records[0]["attempts"].as_array().unwrap().len(),
        1,
        "{state}"
    );
    let (attempt, intent) = attempt_and_intent(state, &id).unwrap();
    assert!(
        attempt.get("exposure").is_none(),
        "the exposure follows the signature: {attempt}"
    );
    assert_eq!(intent["state"], "claimed", "{intent}");

    let stored = record(&run.f, &id);
    let rows = transition_rows(&run.f, &stored["id"]);
    let commits_of = |step: &str| -> Vec<Value> {
        rows.iter()
            .filter(|row| row["step"] == step)
            .map(|row| row["commit_id"].clone())
            .collect()
    };
    let authorized = commits_of("authorized");
    assert_eq!(authorized.len(), 1, "{rows:?}");
    assert_eq!(
        authorized,
        commits_of("sending"),
        "one commit records both steps: {rows:?}"
    );
    assert!(
        stored["commit_ids"]
            .as_array()
            .unwrap()
            .contains(&authorized[0]),
        "{stored}"
    );
}

/// The x402 exposure commits after the intent consumption and before the signed
/// re-simulation, the first request that carries the signed entries. At that
/// request the attempt holds its x402 exposure of the intent, which is used. No
/// window state the payment reads holds the exposure while the intent is still
/// unconsumed.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn x402_exposure_commits_after_consumption_before_signed_simulation() {
    let id = fresh_business_id();
    let (run, approval) = x402_run_under(&id).await;
    let snapshots = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&snapshots);
    let path = run.f.server.window_store.path().to_path_buf();
    observe(&run.f.on_window_key_read, move || {
        if let Some(state) = window_state(&path) {
            seen.lock().unwrap().push(state);
        }
    });
    let paid = x402_pay_under(&run, &approval, &id).await;
    *run.f.on_window_key_read.lock().unwrap() = None;
    assert_eq!(paid["ok"], true, "{paid}");

    let at_simulation = run.control.state_at_signed_simulation();
    assert_eq!(at_simulation.len(), 1, "one signed simulation");
    let (attempt, intent) = attempt_and_intent(&at_simulation[0], &id).unwrap();
    let exposure = &attempt["exposure"]["identity"]["x402"];
    assert!(
        exposure.is_object(),
        "the exposure precedes the signed simulation: {attempt}"
    );
    assert_eq!(
        exposure["authorization_id"], attempt["authorization_id"],
        "{attempt}"
    );
    assert_eq!(
        intent["state"], "used",
        "the intent is consumed before the signed simulation: {intent}"
    );

    let snapshots = snapshots.lock().unwrap().clone();
    let exposed: Vec<(Value, Value)> = snapshots
        .iter()
        .filter_map(|state| attempt_and_intent(state, &id))
        .filter(|(attempt, _)| attempt.get("exposure").is_some())
        .collect();
    assert!(!exposed.is_empty(), "a later step reads the exposure");
    for (attempt, intent) in &exposed {
        assert_eq!(
            intent["state"], "used",
            "the exposure follows the consumption: {attempt} {intent}"
        );
    }
}

/// An x402 attempt ends by its outcome. A returned payload records
/// `payload_released`. A signer failure, before the exposure, records
/// `not_sent` with the failure's code. A refused signed re-simulation, after
/// the exposure, records `sent_outcome_unknown`.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn x402_payload_and_error_outcomes() {
    let id = fresh_business_id();
    let (run, approval) = x402_run_under(&id).await;
    let paid = x402_pay_under(&run, &approval, &id).await;
    assert_eq!(paid["ok"], true, "{paid}");
    assert!(paid["data"]["paymentSignature"].is_string(), "{paid}");
    let released = record(&run.f, &id);
    assert_eq!(released["state"], "payload_released", "{released}");
    assert!(
        released["attempts"][0]["exposure"].is_object(),
        "{released}"
    );

    let id = fresh_business_id();
    let (run, approval) = x402_run_under(&id).await;
    let key = &run.f.server.security_profile().mcp_signer_default;
    keyring_core::Entry::new(&key.service, &key.account)
        .unwrap()
        .delete_credential()
        .unwrap();
    let failed = x402_pay_under(&run, &approval, &id).await;
    assert_eq!(
        failed["error"]["code"], "x402.auth_entry_sign_failed",
        "{failed}"
    );
    let not_sent = record(&run.f, &id);
    assert_eq!(not_sent["state"], "not_sent", "{not_sent}");
    assert_eq!(
        not_sent["result"]["error_code"], "x402.auth_entry_sign_failed",
        "{not_sent}"
    );
    assert!(
        not_sent["attempts"][0].get("exposure").is_none(),
        "{not_sent}"
    );

    let id = fresh_business_id();
    let (run, approval) = x402_run_under(&id).await;
    run.control.resimulation_error.store(true, Ordering::SeqCst);
    let failed = x402_pay_under(&run, &approval, &id).await;
    assert_eq!(
        failed["error"]["code"], "x402.rpc_simulate_failed",
        "{failed}"
    );
    let unknown = record(&run.f, &id);
    assert_eq!(unknown["state"], "sent_outcome_unknown", "{unknown}");
    assert!(unknown["attempts"][0]["exposure"].is_object(), "{unknown}");
}

/// A commit naming a business id other than its preparation's refuses with
/// `operation.business_id_mismatch` before anything signs or sends. It refuses
/// both an id no record carries and the id of another prepared operation. The
/// commit under the preparation's id then proceeds.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn commit_with_another_business_id_refuses_with_mismatch() {
    for tool in Tool::ALL {
        let id = fresh_business_id();
        let run = classic_run(tool, &id).await;
        // The other operation is another payment, account creation,
        // trustline or claim, so its envelope differs.
        let other = fresh_business_id();
        let mut other_args = prepare_args(&run, &other);
        match tool {
            Tool::Pay => other_args["amount_in_stroops"] = json!("11"),
            Tool::CreateAccount => other_args["starting_balance"] = json!("2 XLM"),
            Tool::Trustline => other_args["limit_stroops"] = json!("11"),
            Tool::Claim => {
                *run.control.entries.lock().unwrap() = Some(entries_with_second_balance(&run.f));
                other_args["balance_id"] = json!(OTHER_BALANCE.repeat(32));
            }
        }
        let prepared = wire(&tool.prepare(&run.f.server, &other_args).await);
        assert_eq!(prepared["ok"], true, "{tool:?}: {prepared}");
        assert_ne!(
            record(&run.f, &other)["envelope_xdr"],
            record(&run.f, &id)["envelope_xdr"],
            "{tool:?}: each record binds its own envelope"
        );
        let before = Effects::of(&run.f);
        for named in [fresh_business_id(), other.clone()] {
            let mut args = fresh_commit_args(&run);
            args["business_id"] = json!(named);
            let result = run.commit_with(args).await;
            assert_eq!(result["ok"], false, "{tool:?} {named}: {result}");
            assert_eq!(
                result["error"]["code"], "operation.business_id_mismatch",
                "{tool:?} {named}: {result}"
            );
            assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
            assert_eq!(Effects::of(&run.f), before, "{tool:?} {named}");
        }
        let committed = run.commit().await;
        assert_eq!(committed["ok"], true, "{tool:?}: {committed}");
    }
}

/// Commits an envelope that differs from `run`'s own by its fee, which no
/// record binds, under `run`'s business id. Asserts that the commit
/// refuses with `operation.business_id_conflict` before the approval is
/// verified, the envelope rebuilt or a nonce consumed. The protocol nonce is
/// observed in the server's replay window: recording it afterwards succeeds
/// only when the commit left it unspent.
async fn assert_foreign_envelope_conflicts(run: &ClassicRun, context: &str) {
    let foreign = run.crafted(|tx| tx.fee += 1);
    let approval_nonce = foreign["approval_nonce"].as_str().unwrap().to_owned();
    let protocol_nonce =
        stellar_agent_nonce::Nonce::from_base64(foreign["nonce"].as_str().unwrap()).unwrap();
    let protocol_expiry = foreign["expires_at_unix_ms"].as_u64().unwrap();
    let before = Effects::of(&run.f);
    let result = run.commit_with(foreign).await;
    assert_eq!(result["ok"], false, "{context}: {result}");
    assert_eq!(
        result["error"]["code"], "operation.business_id_conflict",
        "{context}: {result}"
    );
    assert_eq!(
        run.control.methods(),
        BEFORE_LOOKUP,
        "{context}: no approval is verified and nothing is rebuilt"
    );
    let server = &run.f.server;
    let recorded = server.nonce_mint.record_verified_nonce(
        &mut *server.replay_window.lock().await,
        &protocol_nonce,
        protocol_expiry,
    );
    assert!(
        recorded.is_ok(),
        "{context}: the protocol nonce stays unspent: {recorded:?}"
    );
    assert!(run.oracle_control.methods().is_empty(), "{context}");
    assert_eq!(Effects::of(&run.f), before, "{context}: no mint");
    assert!(
        !super::common::tests::mainnet::is_consumed(
            &stored_approval(&run.f, &approval_nonce).unwrap()
        ),
        "{context}: the approval stays unspent"
    );
}

/// A commit under the business id of a retained record whose envelope is not
/// the commit's refuses with `operation.business_id_conflict`, also when no
/// record binds the commit's own envelope. It replays nothing, and the
/// refusal comes before the approval is verified or its nonce consumed.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_commit_of_an_envelope_a_retained_record_does_not_bind_conflicts() {
    for tool in Tool::ALL {
        let id = fresh_business_id();
        let run = classic_run(tool, &id).await;
        let committed = run.commit().await;
        assert_eq!(committed["ok"], true, "{tool:?}: {committed}");
        assert_eq!(record(&run.f, &id)["state"], "sent_outcome_unknown");
        assert_foreign_envelope_conflicts(&run, &format!("{tool:?}")).await;
    }
}

/// A commit under the business id of a waiting record whose envelope is not
/// the commit's refuses with `operation.business_id_conflict`, also when no
/// record binds the commit's own envelope. The refusal comes before the
/// approval is verified, the envelope rebuilt or its nonce consumed. The
/// record's own commit then proceeds.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_commit_of_an_envelope_a_waiting_record_does_not_bind_conflicts() {
    for tool in Tool::ALL {
        let id = fresh_business_id();
        let run = classic_run(tool, &id).await;
        assert_foreign_envelope_conflicts(&run, &format!("{tool:?}")).await;
        let committed = run.commit().await;
        assert_eq!(committed["ok"], true, "{tool:?}: {committed}");
        assert_eq!(record(&run.f, &id)["state"], "sent_outcome_unknown");
    }
}

/// A classic run under `business_id` whose commit ended `not_sent` before any
/// send, with the store's clock held past the terminal retention so the record
/// reads as a tombstone. The preparation names `fee` when one is given. The
/// guard holds the clock.
async fn compacted_run(
    tool: Tool,
    business_id: &str,
    fee: Option<&'static str>,
) -> (
    ClassicRun,
    stellar_agent_network::mainnet::clock::TestClockGuard,
) {
    use stellar_agent_network::policy_state::{BusinessId, OperationStatus};
    let id = business_id.to_owned();
    let run = ClassicRun::with(
        tool,
        |raw| raw,
        |_| {},
        move |args| {
            args["business_id"] = json!(id);
            if let Some(fee) = fee {
                args["fee"] = json!(fee);
            }
        },
    )
    .await;
    let key = &run.f.server.security_profile().mcp_signer_default;
    let seed = keyring_core::Entry::new(&key.service, &key.account).unwrap();
    let stored = seed.get_password().unwrap();
    seed.delete_credential().unwrap();
    let first = run.commit().await;
    seed.set_password(&stored).unwrap();
    assert_eq!(
        first["error"]["code"], "auth.keyring_not_found",
        "{tool:?}: {first}"
    );
    assert_eq!(record(&run.f, business_id)["state"], "not_sent", "{tool:?}");

    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    let clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(
        now + stellar_agent_network::policy_state::operations::TERMINAL_RETENTION_MS + 60_000,
    );
    let view = OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile())
        .view(&BusinessId::parse(business_id).unwrap())
        .unwrap()
        .unwrap();
    assert!(view.compacted, "{tool:?}: the record reads as a tombstone");
    (run, clock)
}

/// A commit under the business id of a tombstone, with other request facts in
/// an envelope no record binds, refuses with `operation.business_id_conflict`.
/// The tombstone keeps only its slot kind and intent digest, and the
/// envelope's identity is not that digest. Nothing is read past the probe and
/// nothing mints.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_commit_of_other_facts_under_a_tombstone_conflicts() {
    for tool in Tool::ALL {
        let id = fresh_business_id();
        let (run, _clock) = compacted_run(tool, &id, None).await;
        let foreign = run.crafted(|tx| tx.memo = stellar_xdr::Memo::Id(7));
        let before = Effects::of(&run.f);
        let result = run.commit_with(foreign).await;
        assert_eq!(result["ok"], false, "{tool:?}: {result}");
        assert_eq!(
            result["error"]["code"], "operation.business_id_conflict",
            "{tool:?}: {result}"
        );
        assert_eq!(run.control.methods(), BEFORE_LOOKUP, "{tool:?}");
        assert_eq!(Effects::of(&run.f), before, "{tool:?}");
    }
}

/// A commit retried under the business id of a tombstone whose slot kind is
/// not `Envelope` refuses with `operation.business_id_conflict`. The
/// tombstone's digest is the envelope's identity, yet only an envelope
/// tombstone answers a classic commit. Nothing is read past the probe and
/// nothing mints.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_commit_under_a_tombstone_of_another_slot_kind_conflicts() {
    use stellar_agent_network::policy_state::{
        BusinessId, OperationAudit, OperationRecorder, SlotKind,
    };
    /// The slot-kind step commits no audit row, so this sink is never called.
    struct NoRows;
    impl OperationAudit for NoRows {
        fn append(&mut self, _: stellar_agent_core::audit_log::AuditEntry) -> Result<(), String> {
            Err("the slot-kind step appends no audit row".to_owned())
        }
    }
    for tool in Tool::ALL {
        let id = fresh_business_id();
        let (run, _clock) = compacted_run(tool, &id, None).await;
        let mut audit = NoRows;
        let stored = OperationRecorder::new(
            &run.f.server.window_store,
            run.f.server.security_profile(),
            &mut audit,
            "slot-kind",
        )
        .set_tombstone_slot_kind_for_test(&BusinessId::parse(&id).unwrap(), SlotKind::X402)
        .unwrap();
        assert!(stored, "{tool:?}: the tombstone exists");
        let before = Effects::of(&run.f);
        let result = run.commit().await;
        assert_eq!(result["ok"], false, "{tool:?}: {result}");
        assert_eq!(
            result["error"]["code"], "operation.business_id_conflict",
            "{tool:?}: {result}"
        );
        assert_eq!(run.control.methods(), BEFORE_LOOKUP, "{tool:?}");
        assert_eq!(Effects::of(&run.f), before, "{tool:?}");
    }
}

/// A commit retried under the business id of a tombstone, with the facts and
/// the envelope of its preparation, answers with the stored operation. It
/// does so before the approval is verified, and nothing is read past the
/// probe, minted or sent.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_commit_retried_under_its_tombstone_replays() {
    for tool in Tool::ALL {
        let id = fresh_business_id();
        let (run, _clock) = compacted_run(tool, &id, None).await;
        let before = Effects::of(&run.f);
        let result = run.commit().await;
        assert_eq!(result["ok"], true, "{tool:?}: {result}");
        assert_eq!(result["data"]["status"], "replayed", "{tool:?}: {result}");
        assert_eq!(result["data"]["business_id"], id.as_str(), "{tool:?}");
        assert_eq!(
            result["data"]["operation"]["state"], "not_sent",
            "{tool:?}: {result}"
        );
        assert_eq!(run.control.methods(), BEFORE_LOOKUP, "{tool:?}");
        assert_eq!(Effects::of(&run.f), before, "{tool:?}");
    }
}

/// A commit retried under the business id of a tombstone whose preparation
/// named an explicit fee answers with the stored operation. The explicit fee
/// differs from the cap bound, so only the identity under the envelope's own
/// fee per operation matches the tombstone. A claim names no fee.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_commit_retried_under_a_tombstone_of_an_explicit_fee_replays() {
    use stellar_agent_network::fees::ClassicFeeChoice;
    const FEE: &str = "137";
    for tool in [Tool::Pay, Tool::CreateAccount, Tool::Trustline] {
        let id = fresh_business_id();
        let (run, _clock) = compacted_run(tool, &id, Some(FEE)).await;
        let profile = run.f.server.security_profile();
        let guard = run
            .f
            .server
            .mainnet_write_admission(stellar_agent_network::mainnet::MainnetConsumer::McpPay)
            .ok()
            .unwrap();
        let cap = stellar_agent_network::operation_entry::fee_bound(
            profile.classic_max_fee_per_op_stroops,
            guard
                .policy
                .mainnet()
                .map(|body| body.classic_max_fee_per_op_stroops),
            ClassicFeeChoice::ProfileDefault,
        )
        .unwrap();
        assert_ne!(cap.to_string(), FEE, "{tool:?}: the cap bound differs");
        let before = Effects::of(&run.f);
        let result = run.commit().await;
        assert_eq!(result["ok"], true, "{tool:?}: {result}");
        assert_eq!(result["data"]["status"], "replayed", "{tool:?}: {result}");
        assert_eq!(
            result["data"]["operation"]["state"], "not_sent",
            "{tool:?}: {result}"
        );
        assert_eq!(run.control.methods(), BEFORE_LOOKUP, "{tool:?}");
        assert_eq!(Effects::of(&run.f), before, "{tool:?}");
    }
}

/// The identities a commit's envelope carries are those of its tool's kind
/// alone. For each kind the prepared envelope yields the digest its record
/// binds under that kind, and no identity under any other kind.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn commit_identities_follow_the_tool_kind() {
    use stellar_agent_network::policy_state::{BusinessId, OperationKind, OperationStatus};
    let kinds = [
        OperationKind::Pay,
        OperationKind::CreateAccount,
        OperationKind::Trustline,
        OperationKind::Claim,
    ];
    for tool in Tool::ALL {
        let id = fresh_business_id();
        let run = classic_run(tool, &id).await;
        let profile = run.f.server.security_profile();
        let view = OperationStatus::new(&run.f.server.window_store, profile)
            .view(&BusinessId::parse(&id).unwrap())
            .unwrap()
            .unwrap();
        let guard = run
            .f
            .server
            .mainnet_write_admission(stellar_agent_network::mainnet::MainnetConsumer::McpPay)
            .ok()
            .unwrap();
        let envelope = run.args["envelope_xdr"].as_str().unwrap();
        for kind in kinds {
            let identities = stellar_agent_network::operation_entry::commit_identities(
                profile,
                guard.policy,
                kind,
                envelope,
            );
            if Some(kind) == view.kind {
                assert!(
                    identities.contains(&view.intent_digest),
                    "{tool:?} {kind:?}"
                );
            } else {
                assert!(identities.is_empty(), "{tool:?} {kind:?}: {identities:?}");
            }
        }
    }
}

/// Removes `args`' business id, or sets it to `raw`.
fn with_raw_id(mut args: Value, raw: Option<&str>) -> Value {
    match raw {
        Some(raw) => args["business_id"] = json!(raw),
        None => drop(args.as_object_mut().unwrap().remove("business_id")),
    }
    args
}

/// A mainnet call without a business id refuses with
/// `validation.business_id_required`, and one with a malformed id with
/// `validation.business_id_invalid`, for each value kind. The check follows the
/// refusals a call with an id gives. An endpoint serving another network
/// refuses a classic call without an id with the code it gives a call with one.
/// Invalid payment requirements refuse an x402 call the same way. No refusal
/// reads past the endpoint probe, mints or opens a record.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn mainnet_call_without_business_id_refuses_for_every_kind() {
    for tool in Tool::ALL {
        let id = fresh_business_id();
        let run = classic_run(tool, &id).await;
        let before = Effects::of(&run.f);
        for (raw, code) in [
            (None, "validation.business_id_required"),
            (Some("two words"), "validation.business_id_invalid"),
        ] {
            let context = format!("{tool:?} {raw:?}");
            run.control.clear();
            let args = with_raw_id(prepare_args(&run, &id), raw);
            let prepared = wire(&tool.prepare(&run.f.server, &args).await);
            assert_eq!(prepared["error"]["code"], code, "{context}: {prepared}");
            assert_eq!(run.control.methods(), BEFORE_LOOKUP, "{context}");

            let committed = run
                .commit_with(with_raw_id(fresh_commit_args(&run), raw))
                .await;
            assert_eq!(committed["error"]["code"], code, "{context}: {committed}");
            assert_eq!(run.control.methods(), BEFORE_LOOKUP, "{context}");
            assert_eq!(Effects::of(&run.f), before, "{context}");
        }

        run.control.testnet_passphrase.store(true, Ordering::SeqCst);
        let named = wire(&tool.prepare(&run.f.server, &prepare_args(&run, &id)).await);
        let endpoint = named["error"]["code"].as_str().unwrap().to_owned();
        assert!(
            endpoint.starts_with("network."),
            "{tool:?}: the probe refuses: {named}"
        );
        let unnamed = wire(
            &tool
                .prepare(&run.f.server, &with_raw_id(prepare_args(&run, &id), None))
                .await,
        );
        assert_eq!(unnamed["error"]["code"], endpoint, "{tool:?}: {unnamed}");
        let named = run.commit_with(fresh_commit_args(&run)).await;
        assert_eq!(named["error"]["code"], endpoint, "{tool:?}: {named}");
        let unnamed = run
            .commit_with(with_raw_id(fresh_commit_args(&run), None))
            .await;
        assert_eq!(unnamed["error"]["code"], endpoint, "{tool:?}: {unnamed}");
        run.control
            .testnet_passphrase
            .store(false, Ordering::SeqCst);
        assert_eq!(Effects::of(&run.f), before, "{tool:?}");
    }

    let run = X402Run::new().await;
    let before = Effects::of(&run.f);
    for (raw, code) in [
        (None, "validation.business_id_required"),
        (Some(""), "validation.business_id_required"),
        (Some("two words"), "validation.business_id_invalid"),
    ] {
        let mut args = x402_args(&run.f, Some((&run.nonce, &run.attestation)));
        args.business_id = raw.map(str::to_owned);
        let result = run.pay_with(args).await;
        assert_eq!(result["error"]["code"], code, "x402 {raw:?}: {result}");
        assert!(run.control.methods().is_empty(), "x402 {raw:?}");
        assert_eq!(Effects::of(&run.f), before, "x402 {raw:?}");
    }
    let invalid = |business_id: Option<String>| {
        let mut args = x402_args(&run.f, Some((&run.nonce, &run.attestation)));
        args.payment_required = "{}".to_owned();
        args.business_id = business_id;
        args
    };
    let named = run.pay_with(invalid(Some(fresh_business_id()))).await;
    let requirements = named["error"]["code"].as_str().unwrap().to_owned();
    assert!(requirements.starts_with("x402."), "x402: {named}");
    let unnamed = run.pay_with(invalid(None)).await;
    assert_eq!(unnamed["error"]["code"], requirements, "x402: {unnamed}");
    assert_eq!(Effects::of(&run.f), before, "x402");

    let run = AuthenticatedRun::new().await;
    let approval = run.prepare().await;
    let before = Effects::of(&run.f);
    let posts = run.double.posts().await;
    for (raw, code) in [
        (None, "validation.business_id_required"),
        (Some("two words"), "validation.business_id_invalid"),
    ] {
        let mut args = run.args(HOME, Some((&approval.0, &approval.1)));
        args.business_id = raw.map(str::to_owned);
        run.control.clear();
        let result = run.call(args).await;
        assert_eq!(
            result["error"]["code"], code,
            "authenticated x402 {raw:?}: {result}"
        );
        assert!(signings().is_empty(), "authenticated x402 {raw:?}");
        assert_eq!(run.double.posts().await, posts, "authenticated x402");
        assert!(run.control.methods().is_empty(), "authenticated x402");
        assert_eq!(Effects::of(&run.f), before, "authenticated x402 {raw:?}");
    }
    let invalid = |business_id: Option<String>| {
        let mut args = run.args(HOME, Some((&approval.0, &approval.1)));
        args.payment_required = "{}".to_owned();
        args.business_id = business_id;
        args
    };
    let named = run.call(invalid(Some(fresh_business_id()))).await;
    let requirements = named["error"]["code"].as_str().unwrap().to_owned();
    assert!(
        requirements.starts_with("x402."),
        "authenticated x402: {named}"
    );
    let unnamed = run.call(invalid(None)).await;
    assert_eq!(
        unnamed["error"]["code"], requirements,
        "authenticated x402: {unnamed}"
    );
    assert!(signings().is_empty(), "authenticated x402");
    assert_eq!(Effects::of(&run.f), before, "authenticated x402");
}

/// A testnet server serving the fixture's ledger through `rpc`, whose
/// endpoint reports testnet, with the fixture's signer as its enrolled
/// signer and an x402 identity session.
async fn testnet_server(f: &Fixture, rpc: &wiremock::MockServer) -> crate::server::WalletServer {
    use stellar_agent_core::profile::schema::signer_identity_entry_ref;
    use stellar_agent_core::profile::signer_identity::SignerIdentityRecord;
    let control = mount_rpc(f, rpc).await;
    control.testnet_passphrase.store(true, Ordering::SeqCst);
    // The x402 tools pay from the signer entry's account, so the entry is
    // named by the signer's address.
    let signer = stellar_agent_test_support::signed_envelope::account_id_for_seed([42; 32]);
    let profile = stellar_agent_core::profile::schema::Profile::builder_testnet_named(
        "replay-testnet",
        "stellar-agent-signer-replay-testnet",
        &signer,
        "stellar-agent-nonce-replay-testnet",
        "default",
    )
    .rpc_url(rpc.uri())
    .with_noop_engine()
    .build();
    for key in [
        &profile.policy_window_state_key_id,
        &profile.audit_log_hash_chain_key_id,
        &profile.attestation_key_id,
        &profile.mcp_nonce_key_alias,
    ] {
        stellar_agent_network::keyring::rotate_keyring_secret_32(&key.service, &key.account)
            .unwrap();
    }
    put(
        &profile.mcp_signer_default,
        &stellar_strkey::Unredacted(&stellar_strkey::ed25519::PrivateKey([42; 32])).to_string(),
    );
    put(
        &signer_identity_entry_ref(&profile.mcp_signer_default),
        &SignerIdentityRecord::agent(
            ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                .verifying_key()
                .to_bytes(),
            "replay-testnet",
            stellar_agent_core::profile::caip2::Caip2::Testnet,
        )
        .render()
        .unwrap(),
    );
    let mut server = crate::server::WalletServer::new(profile).unwrap();
    server.set_x402_identity_session_for_test(
        "header.payload.signature".to_owned(),
        stellar_agent_test_support::signed_envelope::account_id_for_seed([1; 32]),
        Vec::new(),
    );
    server
}

/// The fixture's payment requirements on testnet.
fn testnet_requirements(f: &Fixture) -> String {
    let mut requirements = serde_json::to_value(f.requirements()).unwrap();
    requirements["network"] = json!("stellar:testnet");
    serde_json::to_string(&requirements).unwrap()
}

/// On testnet every value tool validates a supplied business id, echoes it in
/// its result, and keeps no record of it. The tools are the four classic
/// preparations, their commits and both x402 payment tools. The window file
/// holds no operation, and a malformed id refuses.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn testnet_echoes_the_business_id_and_creates_no_record() {
    let f = Fixture::new(|raw| raw);
    let rpc = wiremock::MockServer::start().await;
    let server = testnet_server(&f, &rpc).await;
    for tool in Tool::ALL {
        let mut args = tool.prepare_args(&f);
        args["chain_id"] = json!("stellar:testnet");
        args["business_id"] = json!("order-7");
        let prepared = wire(&tool.prepare(&server, &args).await);
        assert_eq!(prepared["ok"], true, "{tool:?}: {prepared}");
        assert_eq!(prepared["data"]["business_id"], "order-7", "{tool:?}");
        assert!(prepared["data"]["envelope_xdr"].is_string(), "{tool:?}");

        let mut commit = args.clone();
        for field in ["envelope_xdr", "nonce", "expires_at_unix_ms"] {
            commit[field] = prepared["data"][field].clone();
        }
        commit["business_id"] = json!("two words");
        let refused = wire(&tool.commit(&server, commit.clone()).await.unwrap());
        assert_eq!(
            refused["error"]["code"], "validation.business_id_invalid",
            "{tool:?} commit: {refused}"
        );
        commit["business_id"] = json!("order-7");
        let committed = wire(&tool.commit(&server, commit).await.unwrap());
        assert_eq!(committed["ok"], true, "{tool:?} commit: {committed}");
        assert_eq!(
            committed["data"]["business_id"], "order-7",
            "{tool:?} commit"
        );

        args["business_id"] = json!("two words");
        let refused = wire(&tool.prepare(&server, &args).await);
        assert_eq!(
            refused["error"]["code"], "validation.business_id_invalid",
            "{tool:?}: {refused}"
        );
    }

    for raw in ["order-8", "two words"] {
        let paid = wire(
            &server
                .call_stellar_x402_create_payment(crate::server::X402CreatePaymentArgs {
                    payment_required: testnet_requirements(&f),
                    chain_id: "stellar:testnet".to_owned(),
                    address: None,
                    approval_nonce: None,
                    approval_attestation: None,
                    business_id: Some(raw.to_owned()),
                })
                .await
                .unwrap(),
        );
        let authenticated = wire(
            &server
                .call_stellar_x402_authenticated_payment(
                    crate::server::X402AuthenticatedPaymentArgs {
                        payment_required: testnet_requirements(&f),
                        chain_id: "stellar:testnet".to_owned(),
                        home_domain: HOME.to_owned(),
                        address: None,
                        approval_nonce: None,
                        approval_attestation: None,
                        business_id: Some(raw.to_owned()),
                    },
                )
                .await
                .unwrap(),
        );
        for (context, result) in [("x402", &paid), ("authenticated x402", &authenticated)] {
            if raw == "order-8" {
                assert_eq!(result["ok"], true, "{context}: {result}");
                assert_eq!(result["data"]["business_id"], raw, "{context}: {result}");
            } else {
                assert_eq!(
                    result["error"]["code"], "validation.business_id_invalid",
                    "{context}: {result}"
                );
            }
        }
    }

    let window = std::fs::read(server.window_store.path()).ok();
    let operations = window
        .map(|bytes| serde_json::from_slice::<Value>(&bytes[32..]).unwrap()["operations"].clone());
    assert!(
        operations.is_none_or(|operations| operations.is_null()),
        "testnet keeps no operation record"
    );
}
