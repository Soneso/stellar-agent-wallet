//! Canonical activation of the MCP payment, create-account, trustline and
//! claim tools.
//!
//! On mainnet these preparations store the lasting intent under the business
//! id and open an intent-digest approval only when one is required. Their
//! commits look the id up, rebuild the envelope from the stored intent and
//! sign without the preparation's process nonce, envelope or expiry. Payment
//! opens its approval through its own producer, which keeps the recovery
//! binding of the prepared envelope. An envelope record keeps the envelope
//! route, which requires all three fields.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only fixture construction and assertions"
)]

use serde_json::{Value, json};
use stellar_agent_core::approval::subject::SubjectKind;
use stellar_agent_core::approval::{IntentAsset, IntentPayload};
use stellar_agent_network::policy_state::{
    ApprovalState, ApprovalStatus, BusinessId, LookupOutcome, OperationState, OperationStatus,
    OperationView, SlotKind,
};

use super::common::tests::mainnet::{
    ClassicRun, Fixture, Tool, authorizations, fixture_entries, wire,
};

/// The operation view under the run's business id.
fn view(run: &ClassicRun) -> OperationView {
    let id = BusinessId::parse(run.args["business_id"].as_str().unwrap()).unwrap();
    OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile())
        .view(&id)
        .unwrap()
        .unwrap()
}

/// The validated stored intent of the run's operation.
fn stored_intent(run: &ClassicRun) -> stellar_agent_core::approval::ClassicIntent {
    let server = &run.f.server;
    let id = BusinessId::parse(run.args["business_id"].as_str().unwrap()).unwrap();
    let Some(LookupOutcome::Resumable(handle)) = server
        .operation_step(|recorder| {
            recorder
                .lookup(&id)
                .map_err(stellar_agent_network::operation_entry::operation_refusal)
        })
        .unwrap()
    else {
        panic!("the run's operation is resumable")
    };
    stellar_agent_network::operation_entry::preparation_intent(
        &handle,
        server.security_profile(),
        server.current_mainnet_policy().unwrap(),
    )
    .unwrap()
    .expect("a canonical slot validates")
}

/// The lasting payload `tool`'s fixture arguments name.
fn expected_payload(tool: Tool, f: &Fixture) -> IntentPayload {
    match tool {
        Tool::CreateAccount => IntentPayload::CreateAccount {
            destination: f.envelope.destination().to_owned(),
            starting_balance_stroops: 10_000_000,
        },
        Tool::Trustline => IntentPayload::Trustline {
            issuer: stellar_agent_test_support::signed_envelope::account_id_for_seed([7; 32]),
            code: "USD".to_owned(),
            limit_stroops: 10,
        },
        Tool::Claim => IntentPayload::Claim {
            balance_id: format!("00000000{}", "ab".repeat(32)),
            claimant: f.envelope.source().to_owned(),
            asset: IntentAsset::Native,
            amount_stroops: 10,
        },
        Tool::Pay => IntentPayload::Pay {
            destination: f.envelope.destination().to_owned(),
            asset: IntentAsset::Native,
            amount_stroops: 10,
        },
    }
}

/// The run's commit arguments without the preparation's envelope, process
/// nonce and expiry.
fn nonce_free(run: &ClassicRun) -> Value {
    let mut args = run.args.clone();
    for field in ["envelope_xdr", "nonce", "expires_at_unix_ms"] {
        args.as_object_mut().unwrap().remove(field);
    }
    args
}

/// Each canonical preparation stores the full lasting intent and, under an
/// approval requirement, opens one intent-digest record of that intent over
/// an intent-digest inbox entry; a retry keeps the one operation and
/// approval. Under `Allow` no approval record opens.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn mcp_four_classics_prepare_canonical_records() {
    for tool in Tool::ALL {
        let run = ClassicRun::new(tool).await;
        assert_eq!(
            run.entry.subject_kind,
            SubjectKind::IntentDigest,
            "{tool:?}"
        );
        let operation = view(&run);
        assert_eq!(operation.slot_kind, SlotKind::Canonical, "{tool:?}");
        let intent = stored_intent(&run);
        assert_eq!(
            *intent.payload(),
            expected_payload(tool, &run.f),
            "{tool:?}"
        );
        assert_eq!(
            operation.intent_digest,
            *intent.digest().as_bytes(),
            "{tool:?}"
        );
        let record =
            ApprovalStatus::new(&run.f.server.window_store, run.f.server.security_profile())
                .find_by_operation(operation.operation_id)
                .unwrap()
                .expect("an approval requirement opens the record")
                .record;
        assert_eq!(record.subject_kind, SubjectKind::IntentDigest, "{tool:?}");
        assert_eq!(record.subject, *intent.digest().as_bytes(), "{tool:?}");
        assert_eq!(record.kind, intent.approved_kind(), "{tool:?}");
        assert_eq!(record.nonce, run.entry.approval_nonce, "{tool:?}");

        let mut retry = tool.prepare_args(&run.f);
        retry["business_id"] = run.args["business_id"].clone();
        let retried =
            super::common::tests::mainnet::wire(&tool.prepare(&run.f.server, &retry).await);
        assert_eq!(retried["ok"], true, "{tool:?}: {retried}");
        assert_eq!(
            view(&run).operation_id,
            operation.operation_id,
            "{tool:?}: a retry keeps the operation"
        );
        assert_eq!(
            ApprovalStatus::new(&run.f.server.window_store, run.f.server.security_profile())
                .find_by_operation(operation.operation_id)
                .unwrap()
                .unwrap()
                .record
                .nonce,
            run.entry.approval_nonce,
            "{tool:?}: a retry keeps the approval"
        );

        let allowed = ClassicRun::allowed(tool).await;
        let operation = view(&allowed);
        assert_eq!(operation.slot_kind, SlotKind::Canonical, "{tool:?} allow");
        assert!(
            ApprovalStatus::new(
                &allowed.f.server.window_store,
                allowed.f.server.security_profile(),
            )
            .find_by_operation(operation.operation_id)
            .unwrap()
            .is_none(),
            "{tool:?}: Allow opens no approval record"
        );
    }
}

/// The transaction of the signed envelope `xdr`.
fn sent_transaction(xdr: &str) -> stellar_xdr::Transaction {
    use stellar_xdr::{Limits, ReadXdr as _, TransactionEnvelope};
    match TransactionEnvelope::from_xdr_base64(xdr, Limits::none()).unwrap() {
        TransactionEnvelope::Tx(envelope) => envelope.tx,
        _ => panic!("a classic envelope"),
    }
}

/// A canonical commit pays the fee per operation of the envelope its
/// preparation stored: a payment, create-account and trustline prepared at
/// 200 stroops send 200.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_canonical_commit_pays_the_prepared_fee() {
    for tool in [Tool::Pay, Tool::CreateAccount, Tool::Trustline] {
        let run =
            ClassicRun::with(tool, |raw| raw, |_| {}, |args| args["fee"] = json!("200")).await;
        assert_eq!(
            sent_transaction(run.args["envelope_xdr"].as_str().unwrap()).fee,
            200,
            "{tool:?}: the prepared envelope"
        );
        let result = run.commit_with(nonce_free(&run)).await;
        assert_eq!(result["ok"], true, "{tool:?}: {result}");
        let sent = run.control.sent();
        assert_eq!(sent.len(), 1, "{tool:?}");
        assert_eq!(
            sent_transaction(&sent[0]).fee,
            200,
            "{tool:?}: the sent envelope"
        );
    }
}

/// A canonical claim commit pays the fee per operation of the envelope its
/// record stores. A claim preparation takes no fee argument, so the record is
/// seeded: its intent and envelope carry 200 stroops, above the fee the
/// fixture's claim preparation selects. The commit rebuilds the envelope, takes
/// a fresh sequence, and sends 200.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_canonical_claim_commit_pays_the_prepared_fee() {
    use stellar_agent_core::audit_log::PolicyDecision;
    use stellar_agent_network::fees::ClassicFeeChoice;
    use stellar_agent_network::operation_entry::{IntentBaseFacts, Preparation};
    use stellar_agent_network::policy_state::{OperationKind, OperationTool};
    let run = ClassicRun::allowed(Tool::Claim).await;
    let server = &run.f.server;
    let selected = sent_transaction(run.args["envelope_xdr"].as_str().unwrap()).fee;
    assert_ne!(selected, 200, "the preparation selects another fee");
    let prepared = stored_intent(&run);
    let intent = stellar_agent_network::operation_entry::classic_intent(
        IntentBaseFacts::new(
            server.security_profile(),
            prepared.base().source(),
            server.current_mainnet_policy().unwrap(),
            ClassicFeeChoice::Explicit(200),
            prepared.base().memo().clone(),
        ),
        prepared.payload().clone(),
    )
    .unwrap();
    let id = BusinessId::parse("claim-prepared-fee").unwrap();
    let operation = server
        .prepare_entry(
            id.clone(),
            Preparation::Canonical {
                intent: Box::new(intent.clone()),
                decision: PolicyDecision::Allow,
                rule_ttl_ms: Some(300_000),
            },
        )
        .unwrap();
    let envelope = stellar_agent_network::operation_entry::intent_envelope(
        &intent,
        server.context.network_passphrase(),
        2,
        200,
        stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000 + 120,
    )
    .unwrap();
    server
        .prepared_envelope(
            Some(&operation),
            OperationTool::StellarClaim,
            OperationKind::Claim,
            envelope,
        )
        .unwrap();
    let mut args = nonce_free(&run);
    args["business_id"] = json!(id.as_str());
    let result = run.commit_with(args).await;
    assert_eq!(result["ok"], true, "{result}");
    let sent = run.control.sent();
    assert_eq!(sent.len(), 1);
    let sent = sent_transaction(&sent[0]);
    assert_eq!(sent.fee, 200, "the sent envelope pays the stored fee");
    assert_eq!(
        sent.seq_num.0,
        sent_transaction(run.args["envelope_xdr"].as_str().unwrap())
            .seq_num
            .0,
        "the rebuild takes the source's next sequence, not the stored one"
    );
}

/// The rebuild's fee refusal on the commit route names the prepared envelope
/// as the fee's source. The record is seeded: its intent bounds the fee at 99
/// stroops and its envelope pays 100, within the current caps, so the
/// commit's own fee check passes and the rebuild refuses. Nothing is minted
/// or sent and no attempt begins.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn the_rebuilt_fee_refusal_names_the_prepared_envelope() {
    use stellar_agent_core::audit_log::PolicyDecision;
    use stellar_agent_core::error::{DerivedFee, FeeSource, ValidationError};
    use stellar_agent_network::fees::ClassicFeeChoice;
    use stellar_agent_network::operation_entry::{IntentBaseFacts, Preparation};
    use stellar_agent_network::policy_state::{OperationKind, OperationTool};
    let run = ClassicRun::allowed(Tool::CreateAccount).await;
    let server = &run.f.server;
    let prepared = stored_intent(&run);
    let intent = stellar_agent_network::operation_entry::classic_intent(
        IntentBaseFacts::new(
            server.security_profile(),
            prepared.base().source(),
            server.current_mainnet_policy().unwrap(),
            ClassicFeeChoice::Explicit(99),
            prepared.base().memo().clone(),
        ),
        prepared.payload().clone(),
    )
    .unwrap();
    let id = BusinessId::parse("rebuilt-fee-source").unwrap();
    let operation = server
        .prepare_entry(
            id.clone(),
            Preparation::Canonical {
                intent: Box::new(intent.clone()),
                decision: PolicyDecision::Allow,
                rule_ttl_ms: Some(300_000),
            },
        )
        .unwrap();
    let envelope = stellar_agent_network::operation_entry::intent_envelope(
        &intent,
        server.context.network_passphrase(),
        2,
        100,
        stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000 + 120,
    )
    .unwrap();
    server
        .prepared_envelope(
            Some(&operation),
            OperationTool::StellarCreateAccount,
            OperationKind::CreateAccount,
            envelope,
        )
        .unwrap();
    let mut args = nonce_free(&run);
    args["business_id"] = json!(id.as_str());
    let refused = run.commit_with(args).await;
    assert_eq!(
        refused["error"]["code"], "fees.percentile_exceeds_cap",
        "{refused}"
    );
    let source = FeeSource::Envelope;
    let text = ValidationError::FeeAboveCap {
        per_op: DerivedFee::new(100, &source),
        cap: 99,
        fee_source: source,
    }
    .to_string();
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .contains(&text),
        "{text}: {refused}"
    );
    assert_eq!(run.control.count("sendTransaction"), 0);
    assert!(authorizations(&run.f).is_empty(), "nothing is minted");
    let view = OperationStatus::new(&server.window_store, server.security_profile())
        .view(&id)
        .unwrap()
        .unwrap();
    assert_eq!(view.attempts, 0, "no attempt begins");
}

/// The fixture's ledger entries with the source account's sequence set to
/// `sequence`.
fn entries_with_source_sequence(f: &Fixture, sequence: i64) -> Vec<Value> {
    use stellar_xdr::{LedgerEntryData, Limits, ReadXdr as _, SequenceNumber, WriteXdr as _};
    let source = f.envelope.source().to_owned();
    fixture_entries(f)
        .into_iter()
        .map(|mut entry| {
            if let Ok(LedgerEntryData::Account(mut account)) =
                LedgerEntryData::from_xdr_base64(entry["xdr"].as_str().unwrap(), Limits::none())
                && account.account_id.to_string() == source
            {
                account.seq_num = SequenceNumber(sequence);
                entry["xdr"] = json!(
                    LedgerEntryData::Account(account)
                        .to_xdr_base64(Limits::none())
                        .unwrap()
                );
            }
            entry
        })
        .collect()
}

/// Two canonical commits of one source in a row: the second reads the
/// source once the endpoint shows the sequence the first consumed, so it
/// sends the next sequence. The double answers the first account read of
/// the second commit with the sequence before the first commit and every
/// later read with the advanced one.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn consecutive_canonical_commits_wait_for_the_sequence_floor() {
    let run = ClassicRun::new(Tool::CreateAccount).await;
    let (second, _) = run.prepare_again().await;
    let first = run.commit_with(nonce_free(&run)).await;
    assert_eq!(first["ok"], true, "{first}");
    let consumed = sent_transaction(&run.control.sent()[0]).seq_num.0;

    let advanced = entries_with_source_sequence(&run.f, consumed);
    let reads = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let (primary, oracle) = (run.control.clone(), run.oracle_control.clone());
    run.control.on_request(move |method| {
        if method == "getLedgerEntries"
            && reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1
        {
            *primary.entries.lock().unwrap() = Some(advanced.clone());
            *oracle.entries.lock().unwrap() = Some(advanced.clone());
        }
    });
    let mut args = second;
    for field in ["envelope_xdr", "nonce", "expires_at_unix_ms"] {
        args.as_object_mut().unwrap().remove(field);
    }
    let result = run.commit_with(args).await;
    assert_eq!(result["ok"], true, "{result}");
    let sent = run.control.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent_transaction(&sent[0]).seq_num.0,
        consumed + 1,
        "the second commit takes the next sequence"
    );
}

/// A canonical commit 200 seconds after its preparation, past the prepared
/// envelope's 120-second deadline, signs under both authorities. The source
/// sequence rose by five in the ledger since the preparation; the sent
/// envelope takes the next one, and its deadline is 120 seconds after the
/// moved mainnet clock. Its operations are the operations the stored intent
/// builds.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_late_canonical_commit_takes_a_fresh_sequence_and_deadline() {
    use std::sync::atomic::Ordering;
    for tool in Tool::ALL {
        for required in [true, false] {
            let context = format!("{tool:?} approval required {required}");
            let run = if required {
                ClassicRun::new(tool).await
            } else {
                ClassicRun::allowed(tool).await
            };
            let prepared = sent_transaction(run.args["envelope_xdr"].as_str().unwrap());
            let stellar_xdr::Preconditions::Time(bounds) = &prepared.cond else {
                panic!("{context}: the prepared envelope carries time bounds")
            };
            let prepared_end = bounds.max_time.0;
            let intent_operations = sent_transaction(
                &stellar_agent_network::operation_entry::intent_envelope(
                    &stored_intent(&run),
                    run.f.server.context.network_passphrase(),
                    1,
                    100,
                    1,
                )
                .unwrap(),
            )
            .operations
            .to_vec();
            let raised = prepared.seq_num.0 + 4;
            let entries = entries_with_source_sequence(&run.f, raised);
            *run.control.entries.lock().unwrap() = Some(entries.clone());
            *run.oracle_control.entries.lock().unwrap() = Some(entries);

            let system_secs = stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000;
            let now_secs = system_secs + 200;
            let _clock =
                stellar_agent_network::mainnet::clock::set_now_ms_for_test(now_secs * 1_000);
            for control in [&run.control, &run.oracle_control] {
                control.health_lead_secs.store(200, Ordering::SeqCst);
            }
            let result = run.commit_with(nonce_free(&run)).await;
            assert_eq!(result["ok"], true, "{context}: {result}");
            let sent = run.control.sent();
            assert_eq!(sent.len(), 1, "{context}");
            let sent = sent_transaction(&sent[0]);
            assert_eq!(sent.seq_num.0, raised + 1, "{context}: the fresh sequence");
            let stellar_xdr::Preconditions::Time(bounds) = &sent.cond else {
                panic!("{context}: the sent envelope carries time bounds")
            };
            assert_eq!(
                bounds.max_time.0,
                now_secs + 120,
                "{context}: the fresh deadline"
            );
            assert!(bounds.max_time.0 > prepared_end + 120, "{context}");
            assert_eq!(
                sent.operations.to_vec(),
                intent_operations,
                "{context}: the signed operations are the stored intent's"
            );
        }
    }
}

/// One `stellar_transaction_status` call of `tx_hash` on the run's server.
async fn transaction_status(run: &ClassicRun, tx_hash: &str) -> Value {
    let status = run
        .f
        .server
        .call_stellar_transaction_status(crate::server::StellarTransactionStatusArgs {
            chain_id: "stellar:mainnet".to_owned(),
            tx_hash: Some(tx_hash.to_owned()),
            business_id: None,
            retry_recovery: false,
        })
        .await
        .unwrap();
    super::common::tests::mainnet::wire(&status)
}

/// A canonical commit leaves its inbox tombstone owed after the send, and a
/// status call while the operation is neither terminal nor past its
/// execution expiry keeps it owed, so a successor attempt can still use the
/// consent. Once the mainnet clock passes that expiry, the status call
/// writes the tombstone: the inbox approval is spent on the sent
/// transaction's hash.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn the_status_call_writes_the_owed_tombstone() {
    use super::common::tests::mainnet::{is_consumed, stored_approval};
    use std::sync::atomic::Ordering;
    for tool in Tool::ALL {
        let run = ClassicRun::with(
            tool,
            |raw| {
                raw + "\n[[rules]]\nmatch = { tool = \"stellar_transaction_status\", \
                       chain = \"stellar:mainnet\" }\ncriteria = []\ndecision = \"allow\"\n"
            },
            |_| {},
            |_| {},
        )
        .await;
        let committed = run.commit_with(nonce_free(&run)).await;
        assert_eq!(committed["ok"], true, "{tool:?}: {committed}");
        let tx_hash = committed["data"]["tx_hash"].as_str().unwrap().to_owned();
        let nonce = &run.entry.approval_nonce;
        assert!(
            !is_consumed(&stored_approval(&run.f, nonce).unwrap()),
            "{tool:?}: the tombstone is owed after the send"
        );
        let early = transaction_status(&run, &tx_hash).await;
        assert_eq!(early["ok"], true, "{tool:?}: {early}");
        assert_eq!(
            view(&run).state,
            OperationState::SentOutcomeUnknown,
            "{tool:?}"
        );
        assert!(
            !is_consumed(&stored_approval(&run.f, nonce).unwrap()),
            "{tool:?}: the tombstone stays owed before the execution expiry"
        );

        let expired_secs = view(&run).execution_expires_at_ms.unwrap() / 1_000 + 200;
        let system_secs = stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000;
        let _clock =
            stellar_agent_network::mainnet::clock::set_now_ms_for_test(expired_secs * 1_000);
        for control in [&run.control, &run.oracle_control] {
            control
                .health_lead_secs
                .store(expired_secs - system_secs, Ordering::SeqCst);
        }
        let late = transaction_status(&run, &tx_hash).await;
        assert_eq!(late["ok"], true, "{tool:?}: {late}");
        let approval = stored_approval(&run.f, nonce).unwrap();
        let stellar_agent_core::approval::ApprovalKind::Consumed { tx_hash: spent, .. } =
            &approval.kind
        else {
            panic!("{tool:?}: the status call writes the tombstone: {approval:?}")
        };
        assert_eq!(
            *spent, tx_hash,
            "{tool:?}: the approval is spent on the sent hash"
        );
    }
}

/// The stored record of the run's operation in the window file.
fn stored_record(run: &ClassicRun) -> Value {
    let window = super::common::tests::mainnet::ledger(&run.f).unwrap();
    window["operations"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["business_id"] == run.args["business_id"])
        .cloned()
        .unwrap()
}

/// A same-nonce successor. A canonical commit whose transaction both
/// endpoints answer as not found stays of unknown outcome. Once the moved
/// mainnet clock passes its deadline, the server's own recovery pass, run
/// at the dispatch of a preparation under another id, proves a checked
/// non-inclusion from the ledger past the deadline and the source sequence
/// below the attempt's, and projects it. The nonce-free commit under the
/// first id then admits a successor attempt under the same approval nonce
/// and sends it. The row runs for the four tools under both authorities.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn a_same_nonce_successor_admits_after_a_checked_non_inclusion() {
    use std::sync::atomic::Ordering;
    for tool in Tool::ALL {
        for required in [true, false] {
            let context = format!("{tool:?} approval required {required}");
            let run = if required {
                ClassicRun::new(tool).await
            } else {
                ClassicRun::allowed(tool).await
            };
            let first = run.commit_with(nonce_free(&run)).await;
            assert_eq!(first["ok"], true, "{context}: {first}");
            let first_sent = sent_transaction(&run.control.sent()[0]);
            let stored = stored_record(&run);
            assert_eq!(
                stored["state"], "sent_outcome_unknown",
                "{context}: {stored}"
            );
            let max_time = stored["attempts"][0]["exposure"]["identity"]["classic"]["max_time"]
                .as_u64()
                .unwrap();

            let due_secs = max_time + 7;
            let system_secs = stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000;
            let _clock =
                stellar_agent_network::mainnet::clock::set_now_ms_for_test(due_secs * 1_000);
            for control in [&run.control, &run.oracle_control] {
                control
                    .health_lead_secs
                    .store(due_secs - system_secs, Ordering::SeqCst);
                control.transaction_unknown.store(true, Ordering::SeqCst);
                control.ledger_history.store(true, Ordering::SeqCst);
            }
            let other = tool
                .prepare(&run.f.server, &tool.prepare_args(&run.f))
                .await;
            let other = super::common::tests::mainnet::wire(&other);
            assert_eq!(other["ok"], true, "{context}: {other}");
            let decided = stored_record(&run);
            assert_eq!(decided["state"], "not_included", "{context}: {decided}");
            let decision = &decided["attempts"][0]["decision"];
            assert_eq!(decision["projected"], true, "{context}: {decision}");
            assert!(decision["evidence_digest"].is_string(), "{context}");
            for control in [&run.control, &run.oracle_control] {
                control.transaction_unknown.store(false, Ordering::SeqCst);
                control.ledger_history.store(false, Ordering::SeqCst);
            }

            // The raw answer, so a refusal of any form fails this assertion
            // with its text.
            let answer = super::common::tests::mainnet::answer_text(
                &run.commit_raw(nonce_free(&run)).await.unwrap(),
            );
            let successor: Value = serde_json::from_str(&answer).unwrap_or(Value::Null);
            assert_eq!(successor["ok"], true, "{context}: {answer}");
            let sent = run.control.sent();
            assert_eq!(sent.len(), 1, "{context}: one successor send");
            let successor_sent = sent_transaction(&sent[0]);
            assert_eq!(
                successor_sent.seq_num, first_sent.seq_num,
                "{context}: the successor takes the unconsumed sequence"
            );
            let records = authorizations(&run.f);
            assert_eq!(records.len(), 2, "{context}: {records:?}");
            if required {
                assert!(
                    records
                        .iter()
                        .all(|record| record["approval_nonce"] == run.entry.approval_nonce),
                    "{context}: one approval nonce: {records:?}"
                );
            }
            assert_eq!(view(&run).attempts, 2, "{context}");
        }
    }
}

/// The negative row of the same-nonce successor. With the mainnet clock 2
/// seconds before the first attempt's deadline and both endpoints answering
/// the transaction as not found, the recovery pass proves nothing: the
/// record stays of unknown outcome, the commit answers with its stored state,
/// sends nothing, and the record keeps one attempt. The row runs for the
/// four tools under both authorities.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn a_commit_before_the_first_deadline_sends_nothing() {
    use std::sync::atomic::Ordering;
    for tool in Tool::ALL {
        for required in [true, false] {
            let context = format!("{tool:?} approval required {required}");
            let run = if required {
                ClassicRun::new(tool).await
            } else {
                ClassicRun::allowed(tool).await
            };
            let first = run.commit_with(nonce_free(&run)).await;
            assert_eq!(first["ok"], true, "{context}: {first}");
            let max_time =
                stored_record(&run)["attempts"][0]["exposure"]["identity"]["classic"]["max_time"]
                    .as_u64()
                    .unwrap();
            let _clock = move_mainnet_clock(&run, (max_time - 2) * 1_000);
            for control in [&run.control, &run.oracle_control] {
                control.transaction_unknown.store(true, Ordering::SeqCst);
                control.ledger_history.store(true, Ordering::SeqCst);
            }
            let other = super::common::tests::mainnet::wire(
                &tool
                    .prepare(&run.f.server, &tool.prepare_args(&run.f))
                    .await,
            );
            assert_eq!(other["ok"], true, "{context}: {other}");
            assert_eq!(
                stored_record(&run)["state"],
                "sent_outcome_unknown",
                "{context}: the pass before the deadline proves nothing"
            );
            let repeat = run.commit_with(nonce_free(&run)).await;
            assert_eq!(repeat["data"]["status"], "replayed", "{context}: {repeat}");
            assert_eq!(run.control.count("sendTransaction"), 0, "{context}");
            assert_eq!(view(&run).attempts, 1, "{context}");
        }
    }
}

/// The deadline of the signed envelope `xdr`, in Unix seconds.
fn sent_deadline(xdr: &str) -> u64 {
    match sent_transaction(xdr).cond {
        stellar_xdr::Preconditions::Time(bounds) => bounds.max_time.0,
        _ => panic!("the sent envelope carries time bounds"),
    }
}

/// Moves the mainnet authorization clock, and the close time both doubles'
/// health reads report, to `now_ms`. The policy clock keeps the host time.
fn move_mainnet_clock(
    run: &ClassicRun,
    now_ms: u64,
) -> stellar_agent_network::mainnet::clock::TestClockGuard {
    let system_secs = stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000;
    for control in [&run.control, &run.oracle_control] {
        control.health_lead_secs.store(
            (now_ms / 1_000).saturating_sub(system_secs),
            std::sync::atomic::Ordering::SeqCst,
        );
    }
    stellar_agent_network::mainnet::clock::set_now_ms_for_test(now_ms)
}

/// The last whole second strictly before `end_ms`, in Unix seconds: the
/// authority holds strictly before its end.
fn last_second_before(end_ms: u64) -> u64 {
    if end_ms.is_multiple_of(1_000) {
        end_ms / 1_000 - 1
    } else {
        end_ms / 1_000
    }
}

/// Installs a wallet clock on this thread that reads the host time with its
/// milliseconds set to `millis`, so every instant the wallet records falls
/// at that offset from a whole second.
fn clock_at_millis(millis: u64) -> stellar_agent_core::timefmt::test_clock::Guard {
    stellar_agent_core::timefmt::test_clock::install(std::sync::Arc::new(
        stellar_agent_core::timefmt::MockClock::new(move || {
            let host = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis();
            Ok(u64::try_from(host).unwrap() / 1_000 * 1_000 + millis)
        }),
    ))
}

/// A rebuilt deadline is the earlier of 120 seconds after the rebuild and
/// the last whole second strictly before the authority's end. Under an
/// approval the end is the approval's execution end. Here the consent, and
/// so that end, falls half a second past a whole second: a commit 60 seconds
/// before the end sends an envelope whose deadline is that whole second.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn the_rebuilt_deadline_never_passes_the_approval_authority() {
    let _wallet_clock = clock_at_millis(500);
    for tool in Tool::ALL {
        let run = ClassicRun::new(tool).await;
        let end_ms =
            ApprovalStatus::new(&run.f.server.window_store, run.f.server.security_profile())
                .find_by_nonce(&run.entry.approval_nonce)
                .unwrap()
                .unwrap()
                .record
                .consent
                .expect("the fixture consents")
                .execution_expires_at_ms;
        assert_eq!(end_ms % 1_000, 500, "{tool:?}: a fractional end");
        let _clock = move_mainnet_clock(&run, end_ms - 60_000);
        let result = run.commit_with(nonce_free(&run)).await;
        assert_eq!(result["ok"], true, "{tool:?}: {result}");
        let sent = run.control.sent();
        assert_eq!(sent.len(), 1, "{tool:?}");
        assert_eq!(
            sent_deadline(&sent[0]),
            end_ms / 1_000,
            "{tool:?}: the deadline is the whole second before the execution end"
        );
        assert_eq!(sent_deadline(&sent[0]), last_second_before(end_ms));
    }
}

/// Under policy authority the end is the commit decision's governing end,
/// 600 seconds after its evaluation instant. The commit evaluates on the
/// wallet clock, here at a whole second, while its authorization clock
/// stands 540 seconds later. The rebuild runs 60 seconds before an end of
/// whole seconds, so the sent deadline is one second before that end.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn the_rebuilt_deadline_never_passes_the_policy_authority() {
    let _wallet_clock = clock_at_millis(0);
    for tool in Tool::ALL {
        let run = ClassicRun::allowed(tool).await;
        let rebuild_ms = stellar_agent_core::timefmt::now_unix_ms().unwrap() + 540_000;
        let _clock = move_mainnet_clock(&run, rebuild_ms);
        let result = run.commit_with(nonce_free(&run)).await;
        assert_eq!(result["ok"], true, "{tool:?}: {result}");
        let records = authorizations(&run.f);
        assert_eq!(records.len(), 1, "{tool:?}");
        let end_ms = records[0]["policy_authority"]["governing_until_ms"]
            .as_u64()
            .unwrap();
        assert_eq!(end_ms % 1_000, 0, "{tool:?}: an end of whole seconds");
        assert!(
            end_ms / 1_000 < rebuild_ms / 1_000 + 120,
            "{tool:?}: the end comes before 120 seconds after the rebuild"
        );
        let sent = run.control.sent();
        assert_eq!(sent.len(), 1, "{tool:?}");
        assert_eq!(
            sent_deadline(&sent[0]),
            end_ms / 1_000 - 1,
            "{tool:?}: the deadline is one second before the governing end"
        );
        assert_eq!(sent_deadline(&sent[0]), last_second_before(end_ms));
    }
}

/// The boundary of the first rebuild: a commit exactly 120 seconds before
/// an end of whole seconds rebuilds with a deadline equal to that end, which
/// the authority does not cover. The commit rebuilds under the end and sends
/// the second before it; the resolver refuses a deadline at the end. The
/// policy clock stands still at a whole second during the commit, so the
/// governing end is known before it.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn a_first_rebuild_at_the_authority_end_rebuilds_under_it() {
    for tool in Tool::ALL {
        let run = ClassicRun::allowed(tool).await;
        let evaluated_ms = stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000 * 1_000;
        let end_ms = evaluated_ms + 600_000;
        let _wallet_clock = stellar_agent_core::timefmt::test_clock::install(std::sync::Arc::new(
            stellar_agent_core::timefmt::MockClock::new(move || Ok(evaluated_ms)),
        ));
        let _clock = move_mainnet_clock(&run, end_ms - 120_000);
        let result = run.commit_with(nonce_free(&run)).await;
        assert_eq!(result["ok"], true, "{tool:?}: {result}");
        let records = authorizations(&run.f);
        assert_eq!(
            records[0]["policy_authority"]["governing_until_ms"], end_ms,
            "{tool:?}: the governing end"
        );
        let sent = run.control.sent();
        assert_eq!(sent.len(), 1, "{tool:?}");
        assert_eq!(
            sent_deadline(&sent[0]),
            end_ms / 1_000 - 1,
            "{tool:?}: the deadline is the second before the end"
        );
    }
}

/// A frozen wallet clock at `now_ms` on this thread.
fn frozen_wallet_clock(now_ms: u64) -> stellar_agent_core::timefmt::test_clock::Guard {
    stellar_agent_core::timefmt::test_clock::install(std::sync::Arc::new(
        stellar_agent_core::timefmt::MockClock::new(move || Ok(now_ms)),
    ))
}

/// A successor's deadline never passes the record's execution end. Under
/// policy authority the first commit, evaluated at a whole second, sets the
/// record's execution end 600 seconds later. After its checked non-inclusion
/// the successor commit takes a fresh decision 10 seconds later, whose own
/// end lies 10 seconds past the record's. Begun 60 seconds before the
/// record's end, the successor sends the second before that end.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn a_successor_stays_inside_the_record_execution_window() {
    use std::sync::atomic::Ordering;
    let tool = Tool::CreateAccount;
    let run = ClassicRun::allowed(tool).await;
    let first_ms = stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000 * 1_000;
    let record_end_ms = first_ms + 600_000;
    let wallet_clock = frozen_wallet_clock(first_ms);
    let first = run.commit_with(nonce_free(&run)).await;
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(
        view(&run).execution_expires_at_ms,
        Some(record_end_ms),
        "the first authority sets the record's execution end"
    );
    let max_time =
        stored_record(&run)["attempts"][0]["exposure"]["identity"]["classic"]["max_time"]
            .as_u64()
            .unwrap();

    let recovery_clock = move_mainnet_clock(&run, (max_time + 7) * 1_000);
    for control in [&run.control, &run.oracle_control] {
        control.transaction_unknown.store(true, Ordering::SeqCst);
        control.ledger_history.store(true, Ordering::SeqCst);
    }
    let other = super::common::tests::mainnet::wire(
        &tool
            .prepare(&run.f.server, &tool.prepare_args(&run.f))
            .await,
    );
    assert_eq!(other["ok"], true, "{other}");
    assert_eq!(stored_record(&run)["state"], "not_included");
    for control in [&run.control, &run.oracle_control] {
        control.transaction_unknown.store(false, Ordering::SeqCst);
        control.ledger_history.store(false, Ordering::SeqCst);
    }
    drop(recovery_clock);
    drop(wallet_clock);

    let _wallet_clock = frozen_wallet_clock(first_ms + 10_000);
    let _clock = move_mainnet_clock(&run, record_end_ms - 60_000);
    let successor = run.commit_with(nonce_free(&run)).await;
    assert_eq!(successor["ok"], true, "{successor}");
    let records = authorizations(&run.f);
    assert_eq!(records.len(), 2, "{records:?}");
    assert!(
        records.iter().any(
            |record| record["policy_authority"]["governing_until_ms"] == record_end_ms + 10_000
        ),
        "the successor's own decision ends 10 seconds after the record: {records:?}"
    );
    let sent = run.control.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent_deadline(&sent[0]),
        record_end_ms / 1_000 - 1,
        "the successor's deadline is the second before the record's execution end"
    );
    assert_eq!(view(&run).attempts, 2);
}

/// A rebuilt deadline is the last whole second before the authority's end
/// when that end comes first. The policy clock stands 30 seconds behind the
/// host, on a whole second plus 500 ms, so the commit decision's governing
/// end, 600 seconds later, ends both authorities: under an approval it comes
/// before the consent's execution end. A commit 60 seconds before that end
/// sends the whole second before it.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn the_rebuilt_deadline_is_the_last_whole_second_before_the_authority_end() {
    for tool in Tool::ALL {
        for required in [true, false] {
            let context = format!("{tool:?} approval required {required}");
            let run = if required {
                ClassicRun::new(tool).await
            } else {
                ClassicRun::allowed(tool).await
            };
            let host_ms = stellar_agent_core::timefmt::now_unix_ms().unwrap();
            let policy_ms = (host_ms / 1_000 - 30) * 1_000 + 500;
            let end_ms = policy_ms + 600_000;
            let _policy =
                stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(
                    policy_ms,
                );
            let _clock = move_mainnet_clock(&run, end_ms - 60_000);
            let result = run.commit_with(nonce_free(&run)).await;
            assert_eq!(result["ok"], true, "{context}: {result}");
            let sent = run.control.sent();
            assert_eq!(sent.len(), 1, "{context}");
            assert_eq!(
                sent_deadline(&sent[0]),
                end_ms / 1_000,
                "{context}: the last whole second before the authority's end"
            );
        }
    }
}

/// Each of `changes` applied to the run's nonce-free commit refuses
/// `operation.business_id_conflict` and sends nothing.
async fn assert_conflicts(run: &ClassicRun, changes: &[(&str, Value)], stage: &str) {
    for (field, value) in changes {
        let mut args = nonce_free(run);
        args[*field] = value.clone();
        let refused = run.commit_with(args).await;
        assert_eq!(
            refused["error"]["code"], "operation.business_id_conflict",
            "{:?} {stage} {field}: {refused}",
            run.tool
        );
        assert_eq!(run.control.count("sendTransaction"), 0, "{:?}", run.tool);
    }
}

/// After a server restart, each canonical commit signs and sends without
/// the preparation's envelope, process nonce and expiry. A commit whose
/// lasting argument differs from the stored intent refuses before anything
/// is sent, and a repeat after success, with a nonce no server minted,
/// answers with the stored state.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn mcp_four_classics_restart_without_process_nonce() {
    for tool in Tool::ALL {
        let mut run = ClassicRun::new(tool).await;
        run.restart().unwrap();
        let other = stellar_agent_test_support::signed_envelope::account_id_for_seed([9; 32]);
        let issuer = stellar_agent_test_support::signed_envelope::account_id_for_seed([7; 32]);
        let changes = match tool {
            Tool::Pay => vec![
                ("destination", json!(other)),
                ("amount_in_stroops", json!("11")),
                ("asset", json!(format!("USD:{issuer}"))),
                ("memo_text", json!("other")),
            ],
            Tool::CreateAccount => vec![
                ("destination", json!(other)),
                ("starting_balance", json!("2 XLM")),
            ],
            Tool::Trustline => vec![("from", json!(other))],
            Tool::Claim => vec![
                ("source_account", json!(other)),
                ("balance_id", json!("cd".repeat(32))),
            ],
        };
        assert_conflicts(&run, &changes, "waiting").await;

        let result = run.commit_with(nonce_free(&run)).await;
        assert_eq!(result["ok"], true, "{tool:?}: {result}");
        assert!(result["data"]["tx_hash"].is_string(), "{tool:?}: {result}");
        assert_eq!(run.control.count("sendTransaction"), 1, "{tool:?}");

        let mut repeat = nonce_free(&run);
        repeat["nonce"] = json!("not-a-minted-nonce");
        let replayed = run.commit_with(repeat).await;
        assert_eq!(
            replayed["data"]["status"], "replayed",
            "{tool:?}: {replayed}"
        );
        assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
        assert_conflicts(&run, &changes, "retained").await;
    }
}

/// Each canonical tool runs the whole path under both authorities: one send
/// of a rebuilt envelope under one authorization record, which names the
/// approval under an approval requirement and none under `Allow`; the
/// approval record is consumed; a repeat sends nothing.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn mcp_canonical_full_path_matrix() {
    for tool in Tool::ALL {
        for required in [true, false] {
            let context = format!("{tool:?} approval required {required}");
            let run = if required {
                ClassicRun::new(tool).await
            } else {
                ClassicRun::allowed(tool).await
            };
            let result = run.commit_with(nonce_free(&run)).await;
            assert_eq!(result["ok"], true, "{context}: {result}");
            assert_eq!(run.control.count("sendTransaction"), 1, "{context}");
            assert_eq!(run.seed_reads(), 1, "{context}: one signature");
            let records = authorizations(&run.f);
            assert_eq!(records.len(), 1, "{context}: {records:?}");
            let operation = view(&run);
            assert_eq!(operation.attempts, 1, "{context}");
            let approval =
                ApprovalStatus::new(&run.f.server.window_store, run.f.server.security_profile())
                    .find_by_operation(operation.operation_id)
                    .unwrap();
            if required {
                assert_eq!(
                    records[0]["approval_nonce"], run.entry.approval_nonce,
                    "{context}: {records:?}"
                );
                assert_eq!(
                    approval.unwrap().record.state,
                    ApprovalState::Consumed,
                    "{context}"
                );
            } else {
                assert!(records[0]["approval_nonce"].is_null(), "{context}");
                assert!(approval.is_none(), "{context}");
            }
            let repeat = run.commit_with(nonce_free(&run)).await;
            assert_eq!(repeat["data"]["status"], "replayed", "{context}: {repeat}");
            assert_eq!(run.control.count("sendTransaction"), 0, "{context}");
        }
    }
}

/// The claimable balance entries of the fixture with the balance's amount
/// set to `amount`.
fn entries_with_claim_amount(f: &Fixture, amount: i64) -> Vec<Value> {
    use stellar_xdr::{LedgerEntryData, Limits, ReadXdr as _, WriteXdr as _};
    fixture_entries(f)
        .into_iter()
        .map(|mut entry| {
            if let Ok(LedgerEntryData::ClaimableBalance(mut balance)) =
                LedgerEntryData::from_xdr_base64(entry["xdr"].as_str().unwrap(), Limits::none())
            {
                balance.amount = amount;
                entry["xdr"] = json!(
                    LedgerEntryData::ClaimableBalance(balance)
                        .to_xdr_base64(Limits::none())
                        .unwrap()
                );
            }
            entry
        })
        .collect()
}

/// The fixture's ledger entries with `edit` applied to each entry's data.
fn entries_edited(f: &Fixture, edit: impl Fn(&mut stellar_xdr::LedgerEntryData)) -> Vec<Value> {
    use stellar_xdr::{LedgerEntryData, Limits, ReadXdr as _, WriteXdr as _};
    fixture_entries(f)
        .into_iter()
        .map(|mut entry| {
            let mut data =
                LedgerEntryData::from_xdr_base64(entry["xdr"].as_str().unwrap(), Limits::none())
                    .unwrap();
            edit(&mut data);
            entry["xdr"] = json!(data.to_xdr_base64(Limits::none()).unwrap());
            entry
        })
        .collect()
}

/// The canonical commit `args` of `run` against the ledger `entries`, which
/// both the primary and the oracle answer, refuses with `code` before
/// anything is minted or sent.
async fn assert_canonical_refusal(run: &ClassicRun, args: Value, entries: Vec<Value>, code: &str) {
    *run.control.entries.lock().unwrap() = Some(entries.clone());
    *run.oracle_control.entries.lock().unwrap() = Some(entries);
    let refused = run.commit_with(args).await;
    assert_eq!(refused["error"]["code"], code, "{:?}: {refused}", run.tool);
    assert_eq!(run.control.count("sendTransaction"), 0, "{code}");
    assert!(
        authorizations(&run.f).is_empty(),
        "{code}: nothing is minted"
    );
    assert_eq!(view(run).attempts, 0, "{code}: no attempt begins");
    *run.control.entries.lock().unwrap() = None;
    *run.oracle_control.entries.lock().unwrap() = None;
}

/// A retained canonical record replays only for its own tool: after a
/// create-account under an id has been sent, a trustline commit of the same
/// source under that id refuses `operation.business_id_conflict` and sends
/// nothing, as it does while the create-account record waits.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_retained_record_of_another_tool_refuses_the_conflict() {
    let run = ClassicRun::allowed(Tool::Trustline).await;
    let create = Tool::CreateAccount.prepare_args(&run.f);
    let prepared = super::common::tests::mainnet::wire(
        &Tool::CreateAccount.prepare(&run.f.server, &create).await,
    );
    assert_eq!(prepared["ok"], true, "{prepared}");
    run.control.clear();
    let sent = super::common::tests::mainnet::wire(
        &Tool::CreateAccount
            .commit(&run.f.server, create.clone())
            .await
            .unwrap(),
    );
    assert_eq!(sent["ok"], true, "{sent}");
    assert!(sent["data"]["tx_hash"].is_string(), "{sent}");

    let mut args = nonce_free(&run);
    args["business_id"] = create["business_id"].clone();
    let refused = run.commit_with(args).await;
    assert_eq!(
        refused["error"]["code"], "operation.business_id_conflict",
        "{refused}"
    );
    assert_eq!(run.control.count("sendTransaction"), 0);
    let id = BusinessId::parse(create["business_id"].as_str().unwrap()).unwrap();
    let record = OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile())
        .view(&id)
        .unwrap()
        .unwrap();
    assert_eq!(
        record.attempts, 1,
        "the create-account record keeps its attempt"
    );
}

/// The canonical commits repeat the gates of the envelope route on the
/// ledger read at commit: an issuer that enabled clawback after the
/// trustline preparation refuses `trustline.clawback_opt_in_required`; a
/// balance whose claimant changed refuses `claim.not_claimant`, and one whose
/// predicate no longer holds `claim.predicate_not_satisfied`. A trustline
/// commit under the id of a create-account intent of the same source refuses
/// `operation.business_id_conflict`.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn canonical_commits_repeat_the_ledger_gates() {
    use stellar_xdr::{AccountFlags, ClaimPredicate, Claimant, LedgerEntryData};
    let issuer = stellar_agent_test_support::signed_envelope::account_id_for_seed([7; 32]);
    let other = stellar_agent_test_support::signed_envelope::account_id_for_seed([9; 32]);

    let run = ClassicRun::allowed(Tool::Trustline).await;
    let clawback = entries_edited(&run.f, |data| {
        if let LedgerEntryData::Account(account) = data
            && account.account_id.to_string() == issuer
        {
            account.flags |= AccountFlags::ClawbackEnabledFlag as u32;
        }
    });
    assert_canonical_refusal(
        &run,
        nonce_free(&run),
        clawback,
        "trustline.clawback_opt_in_required",
    )
    .await;
    let mut create = Tool::CreateAccount.prepare_args(&run.f);
    let prepared = super::common::tests::mainnet::wire(
        &Tool::CreateAccount.prepare(&run.f.server, &create).await,
    );
    assert_eq!(prepared["ok"], true, "{prepared}");
    let mut args = nonce_free(&run);
    args["business_id"] = create["business_id"].take();
    let refused = run.commit_with(args).await;
    assert_eq!(
        refused["error"]["code"], "operation.business_id_conflict",
        "{refused}"
    );
    assert_eq!(run.control.count("sendTransaction"), 0);

    let run = ClassicRun::allowed(Tool::Claim).await;
    let claimant = |predicate: Option<ClaimPredicate>, destination: Option<&str>| {
        let run = &run;
        entries_edited(&run.f, move |data| {
            if let LedgerEntryData::ClaimableBalance(balance) = data {
                let mut claimants = balance.claimants.to_vec();
                let Claimant::ClaimantTypeV0(first) = &mut claimants[0];
                if let Some(predicate) = &predicate {
                    first.predicate = predicate.clone();
                }
                if let Some(destination) = destination {
                    first.destination = destination.parse().unwrap();
                }
                balance.claimants = claimants.try_into().unwrap();
            }
        })
    };
    assert_canonical_refusal(
        &run,
        nonce_free(&run),
        claimant(None, Some(&other)),
        "claim.not_claimant",
    )
    .await;
    assert_canonical_refusal(
        &run,
        nonce_free(&run),
        claimant(Some(ClaimPredicate::BeforeAbsoluteTime(1)), None),
        "claim.predicate_not_satisfied",
    )
    .await;
}

/// A canonical refusal reaches the MCP result with its wire code: a claim
/// whose balance amount changed after the preparation renders
/// `simulation.divergence` and nothing is minted or sent; a business id
/// outside printable ASCII refuses `validation.business_id_invalid`.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn canonical_refusals_reach_the_mcp_result() {
    let run = ClassicRun::allowed(Tool::Claim).await;
    let entries = entries_with_claim_amount(&run.f, 11);
    *run.control.entries.lock().unwrap() = Some(entries.clone());
    *run.oracle_control.entries.lock().unwrap() = Some(entries);
    let result = run.commit_with(nonce_free(&run)).await;
    assert_eq!(result["error"]["code"], "simulation.divergence", "{result}");
    assert_eq!(run.control.count("sendTransaction"), 0);
    assert!(authorizations(&run.f).is_empty(), "nothing is minted");
    assert_eq!(view(&run).attempts, 0, "no attempt begins");

    // An id that does not parse names no canonical record, so the commit
    // keeps the envelope route, whose business id check refuses it.
    let mut args = run.args.clone();
    args["business_id"] = json!("commande-\u{e9}t\u{e9}");
    let refused = run.commit_with(args).await;
    assert_eq!(
        refused["error"]["code"], "validation.business_id_invalid",
        "{refused}"
    );
}

/// On mainnet a commit without the envelope fields names its record by its
/// business id, so an id that names no canonical record refuses with the
/// id's own code: a missing id `validation.business_id_required`, a malformed
/// one `validation.business_id_invalid`, an id without a record
/// `operation.business_id_mismatch`, and an unreadable window the refusal
/// the envelope route's policy gate gives for it.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn nonce_free_commits_resolve_their_business_id() {
    for tool in Tool::ALL {
        let run = ClassicRun::allowed(tool).await;
        for (id, code) in [
            (None, "validation.business_id_required"),
            (Some("two words"), "validation.business_id_invalid"),
            (Some("no-such-operation"), "operation.business_id_mismatch"),
        ] {
            let mut args = nonce_free(&run);
            match id {
                Some(id) => args["business_id"] = json!(id),
                None => {
                    args.as_object_mut().unwrap().remove("business_id");
                }
            }
            let refused = run.commit_with(args).await;
            assert_eq!(refused["error"]["code"], code, "{tool:?} {id:?}: {refused}");
        }
        std::fs::write(run.f.server.window_store.path(), b"not a window").unwrap();
        let mut full = run.args.clone();
        full["business_id"] = json!("no-such-operation");
        let envelope_route = run.commit_with(full).await;
        assert_eq!(
            envelope_route["error"]["code"], "policy.engine_required",
            "{tool:?}: {envelope_route}"
        );
        let mut args = nonce_free(&run);
        args["business_id"] = json!("no-such-operation");
        let refused = run.commit_with(args).await;
        assert_eq!(
            refused["error"], envelope_route["error"],
            "{tool:?}: the envelope route's refusal: {refused}"
        );
        assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
    }
}

/// A G destination and an M address of it with the ID 0 and with
/// `u64::MAX` are three lasting intents: each preparation stores the
/// destination as supplied under its own digest, and its commit sends to
/// that destination, returns it, and records its hash in the audit leg.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn pay_destination_spellings_are_distinct_intents() {
    let mut digests = Vec::new();
    for muxed_id in [None, Some(0), Some(u64::MAX)] {
        let run = ClassicRun::with(
            Tool::Pay,
            |raw| raw,
            |_| {},
            |args| {
                if let Some(id) = muxed_id {
                    let key = stellar_strkey::ed25519::PublicKey::from_string(
                        args["destination"].as_str().unwrap(),
                    )
                    .unwrap()
                    .0;
                    args["destination"] = json!(
                        stellar_strkey::ed25519::MuxedAccount { ed25519: key, id }
                            .to_string()
                            .as_str()
                    );
                }
            },
        )
        .await;
        let destination = run.args["destination"].as_str().unwrap().to_owned();
        let operation = view(&run);
        assert_eq!(operation.slot_kind, SlotKind::Canonical, "{destination}");
        let intent = stored_intent(&run);
        let IntentPayload::Pay {
            destination: stored,
            ..
        } = intent.payload()
        else {
            panic!("a payment intent expected")
        };
        assert_eq!(*stored, destination);
        digests.push(operation.intent_digest);
        let result = run.commit_with(nonce_free(&run)).await;
        assert_eq!(result["ok"], true, "{destination}: {result}");
        assert_eq!(
            result["data"]["destination"], destination,
            "{destination}: {result}"
        );
        let sent = run.control.sent();
        assert_eq!(sent.len(), 1, "{destination}");
        let sent = sent_transaction(&sent[0]);
        let stellar_xdr::OperationBody::Payment(payment) = &sent.operations[0].body else {
            panic!("a payment expected")
        };
        let sent_destination = match &payment.destination {
            stellar_xdr::MuxedAccount::Ed25519(key) => stellar_strkey::ed25519::PublicKey(key.0)
                .to_string()
                .as_str()
                .to_owned(),
            stellar_xdr::MuxedAccount::MuxedEd25519(muxed) => {
                stellar_strkey::ed25519::MuxedAccount {
                    ed25519: muxed.ed25519.0,
                    id: muxed.id,
                }
                .to_string()
                .as_str()
                .to_owned()
            }
        };
        assert_eq!(sent_destination, destination);
        let hash = {
            use sha2::Digest as _;
            stellar_agent_core::hex::encode(&sha2::Sha256::digest(destination.as_bytes()))
        };
        let log = std::fs::read_to_string(&run.f.server.profile.audit_log_path).unwrap();
        assert!(
            log.contains(&format!("\"destination_sha256\":\"{hash}\"")),
            "{destination}: the audit leg records the complete destination's hash"
        );
    }
    digests.sort_unstable();
    digests.dedup();
    assert_eq!(digests.len(), 3, "one intent per spelling");
}

/// The response to one `tools/call` of `name` with `arguments` on a session
/// with a copy of `server`.
async fn transport_call(
    server: &crate::server::WalletServer,
    name: &str,
    arguments: Value,
) -> Value {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
    let frame = |message: Value| {
        let mut bytes = serde_json::to_vec(&message).unwrap();
        bytes.push(b'\n');
        bytes
    };
    let (client, server_side) = tokio::io::duplex(1 << 20);
    let (read, write) = tokio::io::split(server_side);
    let served = server.clone();
    let session = tokio::spawn(async move {
        let _ = crate::transport::serve_on(
            served,
            crate::transport::BoundedTransport::over(read, write),
        )
        .await;
    });
    let (client_read, mut client_write) = tokio::io::split(client);
    let mut lines = tokio::io::BufReader::new(client_read).lines();
    client_write
        .write_all(&frame(
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": { "name": "canonical-commit", "version": "0" } } }),
        ))
        .await
        .unwrap();
    lines.next_line().await.unwrap().expect("initialize result");
    client_write
        .write_all(&frame(
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        ))
        .await
        .unwrap();
    client_write
        .write_all(&frame(
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": name, "arguments": arguments } }),
        ))
        .await
        .unwrap();
    let response = lines.next_line().await.unwrap().expect("tool response");
    client_write.shutdown().await.unwrap();
    drop(lines);
    session.abort();
    serde_json::from_str(&response).unwrap()
}

/// An envelope record on mainnet keeps the envelope contract. Over the
/// transport, a commit that omits its envelope, protocol nonce or nonce
/// expiry answers the tool's fixed argument refusal, the result a payment
/// commit without them gives; nothing is sent and the record stays as it
/// was. A present empty envelope refuses `simulation.divergence`, and a
/// present empty nonce or zero expiry the uniform nonce refusal.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn envelope_records_keep_the_nonce_contract() {
    for tool in Tool::ALL {
        let run = ClassicRun::new(tool).await.envelope_route();
        for field in ["nonce", "envelope_xdr", "expires_at_unix_ms"] {
            let mut args = run.args.clone();
            args.as_object_mut().unwrap().remove(field);
            let response = transport_call(&run.f.server, tool.commit_name(), args).await;
            let result = &response["result"];
            assert_eq!(result["isError"], true, "{tool:?} {field}: {response}");
            assert_eq!(
                result["content"][0]["text"],
                format!(
                    "{}: the arguments have a missing field or a field of the wrong type or value",
                    tool.commit_name()
                ),
                "{tool:?} {field}: {response}"
            );
        }
        for (field, value, code) in [
            ("envelope_xdr", json!(""), "simulation.divergence"),
            ("nonce", json!(""), "nonce.expired"),
            ("expires_at_unix_ms", json!(0), "nonce.expired"),
        ] {
            let mut args = run.args.clone();
            args[field] = value;
            let refused = run.commit_with(args).await;
            assert_eq!(
                refused["error"]["code"], code,
                "{tool:?} {field}: {refused}"
            );
        }
        assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
        let id = BusinessId::parse(run.args["business_id"].as_str().unwrap()).unwrap();
        let operation =
            OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile())
                .view(&id)
                .unwrap()
                .unwrap();
        assert_eq!(operation.slot_kind, SlotKind::Envelope, "{tool:?}");
        assert_eq!(operation.attempts, 0, "{tool:?}");
    }
}

/// A fault after the payment's inbox entry is written and before its
/// approval record opens leaves the entry and its recovery binding; after a
/// restart the retried preparation recovers the same approval nonce, opens
/// one record over the canonical slot and adds no entry.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn pay_prepare_recovers_its_nonce_after_a_fault_before_the_record_opens() {
    use stellar_agent_network::policy_state::store::commit_faults::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
        observe_commit,
    };
    fn nonces(run: &ClassicRun) -> Vec<String> {
        stellar_agent_core::approval::PendingApprovalStore::open(
            run.f
                .server
                .resolve_approval_dir()
                .unwrap()
                .join(format!("{}.toml", run.f.server.profile_name_for_approval())),
        )
        .unwrap()
        .snapshot(stellar_agent_core::timefmt::now_unix_ms().unwrap())
        .into_iter()
        .map(|entry| entry.approval_nonce)
        .collect()
    }
    fn record(
        run: &ClassicRun,
        operation: stellar_agent_network::policy_state::OperationId,
    ) -> Option<stellar_agent_network::policy_state::ApprovalView> {
        ApprovalStatus::new(&run.f.server.window_store, run.f.server.security_profile())
            .find_by_operation(operation)
            .unwrap()
    }
    let mut run = ClassicRun::new(Tool::Pay).await;
    let before = nonces(&run);
    let mut args = Tool::Pay.prepare_args(&run.f);
    args["business_id"] = json!(crate::tools::common::tests::fresh_business_id());
    // The preparation's first commit opens the operation; the fault stops
    // the next one, the approval record's open, before its counter moves.
    let observer = observe_commit(|point| {
        if point == COMMIT_FAULT_AFTER_COUNTER {
            std::mem::forget(arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED));
        }
    });
    let faulted = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
    drop(observer);
    assert_eq!(
        faulted["error"]["code"], "submission.record_unavailable",
        "{faulted}"
    );
    let id = BusinessId::parse(args["business_id"].as_str().unwrap()).unwrap();
    let operation =
        OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile())
            .view(&id)
            .unwrap()
            .unwrap();
    assert_eq!(operation.slot_kind, SlotKind::Canonical);
    assert!(
        record(&run, operation.operation_id).is_none(),
        "no record opened"
    );
    let after = nonces(&run);
    let [written] = after
        .iter()
        .filter(|nonce| !before.contains(nonce))
        .collect::<Vec<_>>()[..]
    else {
        panic!("one entry outlives the fault: {after:?}")
    };
    let written = written.clone();

    run.restart().unwrap();
    let retried = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
    assert_eq!(retried["ok"], true, "{retried}");
    assert_eq!(
        retried["data"]["approval"]["approval_nonce"], written,
        "the retry recovers the nonce: {retried}"
    );
    let record = record(&run, operation.operation_id).unwrap().record;
    assert_eq!(record.nonce, written);
    assert_eq!(record.subject_kind, SubjectKind::IntentDigest);
    assert_eq!(record.subject, operation.intent_digest);
    assert_eq!(nonces(&run), after, "the retry adds no entry");
}
