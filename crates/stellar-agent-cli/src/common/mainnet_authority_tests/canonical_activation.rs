//! The classic verbs on mainnet prepare canonical records, rebuild their
//! envelope after the confirmation, and continue envelope records with their
//! stored envelope.

#![allow(clippy::expect_used, reason = "test assertions")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use serde_json::{Value, json};
use stellar_agent_core::approval::subject::SubjectKind;
use stellar_agent_core::error::{DerivedFee, FeeSource, ValidationError};
use stellar_agent_network::policy_state::{
    ApprovalStatus, BusinessId, OperationStatus, OperationView, PersistedWindowStore, SlotKind,
};
use stellar_xdr::{Limits, ReadXdr as _, TransactionEnvelope};

use super::{Verb, claim, create, pay, trustline};
use crate::common::mainnet_write_fixture::{AGENT_SEED, MainnetFixture};
use crate::test_rpc::ClassicRpc;

/// How many sends another wallet makes from the agent while the run waits.
const OTHER_SENDS: i64 = 7;
/// The fee per operation the endpoints report from the rebuild on.
const MOVED_FEE: u32 = 300;

fn agent() -> String {
    stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED)
}

/// A `getFeeStats` answer whose every percentile is `fee`.
fn fee_stats(fee: u32) -> Value {
    let fee = fee.to_string();
    let stats = json!({
        "max": fee, "min": fee, "mode": fee, "p10": fee, "p20": fee, "p30": fee,
        "p40": fee, "p50": fee, "p60": fee, "p70": fee, "p80": fee, "p90": fee,
        "p95": fee, "p99": fee, "transactionCount": "10", "ledgerCount": 5
    });
    json!({ "sorobanInclusionFee": stats, "inclusionFee": stats, "latestLedger": 1001 })
}

/// The ledger the oracle reports its entries at from the move on.
const MOVED_ORACLE_LEDGER: u32 = 1500;

/// The endpoints of a run that moves on while it waits: from the primary's
/// second readiness check on, the rebuild's, the agent's sequence is
/// [`OTHER_SENDS`] higher on both endpoints, the fees are `fee` (first
/// [`MOVED_FEE`]) and the oracle reports its entries at
/// [`MOVED_ORACLE_LEDGER`].
#[derive(Clone)]
struct Moves {
    moved: Arc<AtomicBool>,
    fee: Arc<AtomicU32>,
    /// The fee reads the primary answered before the move.
    prepared_fee_reads: Arc<AtomicUsize>,
    /// The oracle's entry reads before and after the move.
    oracle_reads_before: Arc<AtomicUsize>,
    oracle_reads_after: Arc<AtomicUsize>,
}

impl Moves {
    fn new() -> Self {
        Self {
            moved: Arc::default(),
            fee: Arc::new(AtomicU32::new(MOVED_FEE)),
            prepared_fee_reads: Arc::default(),
            oracle_reads_before: Arc::default(),
            oracle_reads_after: Arc::default(),
        }
    }

    fn endpoints(&self, verb: Verb) -> (ClassicRpc, ClassicRpc) {
        let (primary, oracle) = (verb.ledger(), verb.ledger());
        let (advance_primary, advance_oracle) = (primary.clone(), oracle.clone());
        let moves = self.clone();
        let primary = primary.with_script(move |method, index, _| {
            if method == "getHealth" && index == 1 {
                advance_primary.advance_sequence(&agent(), OTHER_SENDS);
                advance_oracle.advance_sequence(&agent(), OTHER_SENDS);
                advance_oracle.report_entries_ledger(MOVED_ORACLE_LEDGER);
                moves.moved.store(true, Ordering::SeqCst);
            }
            if method != "getFeeStats" {
                return None;
            }
            if moves.moved.load(Ordering::SeqCst) {
                Some(fee_stats(moves.fee.load(Ordering::SeqCst)))
            } else {
                moves.prepared_fee_reads.fetch_add(1, Ordering::SeqCst);
                None
            }
        });
        let moves = self.clone();
        let oracle = oracle.with_script(move |method, _, _| {
            if method == "getLedgerEntries" {
                if moves.moved.load(Ordering::SeqCst) {
                    &moves.oracle_reads_after
                } else {
                    &moves.oracle_reads_before
                }
                .fetch_add(1, Ordering::SeqCst);
            }
            None
        });
        (primary, oracle)
    }
}

/// Runs `verb` under `business_id` with an automatic fee.
async fn run(verb: Verb, fixture: &MainnetFixture, business_id: &str) -> (i32, Value) {
    run_with_fee(verb, fixture, business_id, Some("auto")).await
}

/// Runs `verb` under `business_id` with `fee` as its fee argument, or
/// without one for `None`.
async fn run_with_fee(
    verb: Verb,
    fixture: &MainnetFixture,
    business_id: &str,
    fee: Option<&str>,
) -> (i32, Value) {
    let id = Some(business_id.to_owned());
    let fee = fee.map(str::to_owned);
    let rendered = |code| {
        let documents = crate::common::render::take_rendered_for_test();
        (code, documents.into_iter().last().unwrap_or(Value::Null))
    };
    crate::common::render::take_rendered_for_test();
    match verb {
        Verb::Pay => {
            let mut args = pay::mainnet_args(fixture);
            (args.business_id, args.fee) = (id, fee);
            rendered(pay::run_code(fixture, &args).await)
        }
        Verb::Claim => {
            let mut args = claim::mainnet_args(fixture);
            (args.business_id, args.fee) = (id, fee);
            let run = claim::run(fixture, &args).await;
            (run.code, run.envelope)
        }
        Verb::Create => {
            let mut args = create::mainnet_args(fixture);
            (args.business_id, args.fee) = (id, fee);
            rendered(create::run_code(fixture, &args).await)
        }
        Verb::Trustline => {
            let mut args = trustline::mainnet_args(fixture);
            (args.business_id, args.classic_base) = (id, fee);
            let run = trustline::run(fixture, &args).await;
            (run.code, run.envelope)
        }
    }
}

/// The source sequence and the total fee of a transaction envelope.
fn sequence_and_fee(envelope: &str) -> (i64, u32) {
    let TransactionEnvelope::Tx(tx) =
        TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap()
    else {
        panic!("a transaction envelope")
    };
    (tx.tx.seq_num.0, tx.tx.fee)
}

/// The deadline of a transaction envelope, in Unix seconds.
fn deadline(envelope: &str) -> u64 {
    let TransactionEnvelope::Tx(tx) =
        TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap()
    else {
        panic!("a transaction envelope")
    };
    let stellar_xdr::Preconditions::Time(bounds) = tx.tx.cond else {
        panic!("a deadline")
    };
    bounds.max_time.0
}

/// The record or tombstone `business_id` names.
fn operation(fixture: &MainnetFixture, business_id: &str) -> OperationView {
    OperationStatus::new(
        &PersistedWindowStore::for_profile(fixture.name),
        &fixture.profile(),
    )
    .view(&BusinessId::parse(business_id).unwrap())
    .unwrap()
    .expect("the run opened a record")
}

/// The rule of `verb` with `decision`.
fn rules(verb: Verb, approval: bool) -> Vec<String> {
    vec![verb.rule(
        if approval {
            "require_approval"
        } else {
            "allow"
        },
        "",
    )]
}

const REBUILD_NAMES: [[&str; 2]; 4] = [
    [
        "canonical-rebuild-pay-allow",
        "canonical-rebuild-pay-approval",
    ],
    [
        "canonical-rebuild-claim-allow",
        "canonical-rebuild-claim-approval",
    ],
    [
        "canonical-rebuild-create-allow",
        "canonical-rebuild-create-approval",
    ],
    [
        "canonical-rebuild-trustline-allow",
        "canonical-rebuild-trustline-approval",
    ],
];

/// Each verb prepares a canonical record from the endpoint's state at the
/// preparation, then signs an envelope rebuilt from the stored intent after
/// the decision: the sequence another wallet advanced meanwhile, the fee the
/// endpoint reports now, and a fresh oracle check, whose outcome the result
/// reports. Under an approval rule the consent is a version 6 consent to the
/// intent.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn cli_four_classics_rebuild_after_consent() {
    for (verb, names) in Verb::ALL.into_iter().zip(REBUILD_NAMES) {
        for (approval, name) in [false, true].into_iter().zip(names) {
            let moves = Moves::new();
            let (primary, oracle) = moves.endpoints(verb);
            let fixture = verb
                .spec(name)
                .primary(primary)
                .oracle(oracle)
                .rules(rules(verb, approval))
                .build()
                .await;
            let id = crate::common::business_entry::fresh_business_id();
            let (code, result) = run(verb, &fixture, &id).await;
            assert_eq!(code, 0, "{name}: {result}");
            assert!(
                moves.prepared_fee_reads.load(Ordering::SeqCst) > 0,
                "{name}: the preparation built before the endpoints moved"
            );
            let sent = fixture.sent_envelopes().await;
            assert_eq!(sent.len(), 1, "{name}");
            fixture.assert_signed_by_agent(&sent[0]);
            assert_eq!(
                sequence_and_fee(&sent[0]),
                (
                    crate::test_rpc::ACCOUNT_SEQUENCE + OTHER_SENDS + 1,
                    MOVED_FEE
                ),
                "{name}: the signed envelope takes the sequence and fee read after the decision"
            );
            // The verb's check before the confirmation and the rebuild's read
            // the same observations; the 2 XLM create stays below the native
            // threshold, so neither check reads the oracle's entries.
            let before = moves.oracle_reads_before.load(Ordering::SeqCst);
            assert_eq!(before > 0, !matches!(verb, Verb::Create), "{name}");
            assert_eq!(
                moves.oracle_reads_after.load(Ordering::SeqCst),
                before,
                "{name}: the rebuild reads the oracle again"
            );
            if !matches!(verb, Verb::Create) {
                assert_eq!(
                    result["data"]["cross_check"]["ledger"], MOVED_ORACLE_LEDGER,
                    "{name}: the result reports the rebuild's oracle check: {result}"
                );
            }
            if matches!(verb, Verb::Pay | Verb::Create) {
                assert_eq!(
                    result["data"]["selected_fee_per_op_stroops"],
                    MOVED_FEE.to_string(),
                    "{name}: {result}"
                );
            }
            let view = operation(&fixture, &id);
            assert_eq!(view.slot_kind, SlotKind::Canonical, "{name}");
            assert_eq!(view.attempts, 1, "{name}");
            if approval {
                assert_eq!(fixture.ceremonies().len(), 1, "{name}");
                let record = ApprovalStatus::new(
                    &PersistedWindowStore::for_profile(fixture.name),
                    &fixture.profile(),
                )
                .find_by_operation(view.operation_id)
                .unwrap()
                .expect("an approval record")
                .record;
                assert_eq!(record.subject_kind, SubjectKind::IntentDigest, "{name}");
                assert_eq!(record.subject, view.intent_digest, "{name}");
            } else {
                fixture.assert_no_consent_ceremony();
            }
        }
    }
}

/// The fee the endpoints report after the confirmation, above the signed
/// cap of 500 stroops per operation.
const FEE_ABOVE_CAP: u32 = 600;

/// The text of the fee-cap refusal of `per_op` stroops above `cap` from
/// `fee_source`.
fn cap_text(per_op: u32, cap: u32, fee_source: FeeSource) -> String {
    ValidationError::FeeAboveCap {
        per_op: DerivedFee::new(per_op, &fee_source),
        cap,
        fee_source,
    }
    .to_string()
}

/// A fee above the cap at the rebuild refuses before any side effect: the
/// withheld sentence, nothing sent, no authorization, no attempt, and the
/// approval unspent. The refusal names the percentile the automatic fee
/// selected. Once the fee is back under the cap the same business id
/// completes with the consent already given.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_rebuilt_fee_above_the_cap_refuses_before_any_side_effect() {
    let names = [
        "canonical-cap-pay",
        "canonical-cap-claim",
        "canonical-cap-create",
        "canonical-cap-trustline",
    ];
    for (verb, name) in Verb::ALL.into_iter().zip(names) {
        let moves = Moves::new();
        moves.fee.store(FEE_ABOVE_CAP, Ordering::SeqCst);
        let (primary, oracle) = moves.endpoints(verb);
        let fixture = verb
            .spec(name)
            .primary(primary)
            .oracle(oracle)
            .rules(rules(verb, true))
            .build()
            .await;
        let id = crate::common::business_entry::fresh_business_id();
        let (code, result) = run(verb, &fixture, &id).await;
        assert_eq!(code, 1, "{name}: {result}");
        assert_eq!(
            result["error"]["code"], "fees.percentile_exceeds_cap",
            "{name}: {result}"
        );
        let message = result["error"]["message"].as_str().unwrap();
        assert!(
            message.ends_with("The signature was withheld and nothing was sent."),
            "{name}: {result}"
        );
        let selected = FeeSource::Selected {
            percentile: "p95".to_owned(),
        };
        assert!(
            message.contains(&cap_text(FEE_ABOVE_CAP, 500, selected)),
            "{name}: the refusal names the selected percentile: {result}"
        );
        assert!(fixture.sent_envelopes().await.is_empty(), "{name}");
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        assert!(fixture.open_authorizations(now).is_empty(), "{name}");
        let view = operation(&fixture, &id);
        assert_eq!(view.attempts, 0, "{name}");
        let record = ApprovalStatus::new(
            &PersistedWindowStore::for_profile(fixture.name),
            &fixture.profile(),
        )
        .find_by_operation(view.operation_id)
        .unwrap()
        .expect("an approval record")
        .record;
        assert_eq!(
            record.state,
            stellar_agent_network::policy_state::ApprovalState::Pending,
            "{name}: the approval stays unspent"
        );
        moves.fee.store(MOVED_FEE, Ordering::SeqCst);
        let (code, result) = run(verb, &fixture, &id).await;
        assert_eq!(code, 0, "{name}: {result}");
        let sent = fixture.sent_envelopes().await;
        assert_eq!(sent.len(), 1, "{name}");
        assert_eq!(sequence_and_fee(&sent[0]).1, MOVED_FEE, "{name}");
        assert_eq!(
            fixture.ceremonies().len(),
            1,
            "{name}: the consent is reused"
        );
    }
}

/// The signed cap per operation below the verbs' 100-stroop default fee.
const CAP_BELOW_DEFAULT: u32 = 50;

/// A run without a fee whose default fee is above the cap refuses before any
/// side effect, and the refusal names the verb's own default: the built-in
/// fee of `pay`, `claim` and `accounts create`, the profile's fee of
/// `trustline`. A run with an explicit fee above the cap names that fee.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_fee_above_the_cap_names_the_verbs_fee_source() {
    let names = [
        ["canonical-source-pay", "canonical-source-pay-explicit"],
        ["canonical-source-claim", "canonical-source-claim-explicit"],
        [
            "canonical-source-create",
            "canonical-source-create-explicit",
        ],
        [
            "canonical-source-trustline",
            "canonical-source-trustline-explicit",
        ],
    ];
    for (verb, [default_name, explicit_name]) in Verb::ALL.into_iter().zip(names) {
        let default_source = if matches!(verb, Verb::Trustline) {
            FeeSource::ProfileDefault
        } else {
            FeeSource::CommandDefault
        };
        for (name, fee, per_op, fee_source) in [
            (default_name, None, 100, default_source),
            (explicit_name, Some("60"), 60, FeeSource::Explicit),
        ] {
            let fixture = verb
                .spec(name)
                .signed_fee_cap(CAP_BELOW_DEFAULT)
                .rules(rules(verb, true))
                .build()
                .await;
            let id = crate::common::business_entry::fresh_business_id();
            let (code, result) = run_with_fee(verb, &fixture, &id, fee).await;
            assert_eq!(code, 1, "{name}: {result}");
            assert_eq!(
                result["error"]["code"], "fees.percentile_exceeds_cap",
                "{name}: {result}"
            );
            let expected = cap_text(per_op, CAP_BELOW_DEFAULT, fee_source);
            assert!(
                result["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains(&expected),
                "{name}: the refusal names `{expected}`: {result}"
            );
            assert!(fixture.sent_envelopes().await.is_empty(), "{name}");
            let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
            assert!(fixture.open_authorizations(now).is_empty(), "{name}");
            fixture.assert_no_consent_ceremony();
        }
    }
}

/// A trustline record resumed after the profile's fee rose above the cap
/// passes the check of its stored envelope, and its rebuild refuses before
/// any side effect, naming the profile's fee as the source.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_rebuilt_profile_fee_above_the_cap_names_the_profile() {
    let name = "canonical-source-trustline-resumed";
    // The rebuild's readiness check, the primary's second, finds the
    // endpoint unhealthy; every later check finds it healthy.
    let primary = Verb::Trustline.ledger().with_script(|method, index, _| {
        (method == "getHealth" && index == 1).then(|| {
            json!({
                "status": "unhealthy",
                "latestLedger": 2000,
                "oldestLedger": 1,
                "ledgerRetentionWindow": 1999,
            })
        })
    });
    let fixture = Verb::Trustline
        .spec(name)
        .primary(primary)
        .rules(rules(Verb::Trustline, false))
        .build()
        .await;
    let id = crate::common::business_entry::fresh_business_id();
    let (code, result) = run_with_fee(Verb::Trustline, &fixture, &id, None).await;
    assert_eq!(
        code, 1,
        "the first rebuild finds the endpoint unready: {result}"
    );
    let mut profile = fixture.profile();
    profile.classic_fee_per_op_stroops = Some(FEE_ABOVE_CAP);
    stellar_agent_core::profile::loader::save_to_dir(
        fixture.name,
        &profile,
        &stellar_agent_core::profile::schema::default_profile_dir().unwrap(),
    )
    .unwrap();
    let (code, result) = run_with_fee(Verb::Trustline, &fixture, &id, None).await;
    assert_eq!(code, 1, "{result}");
    assert_eq!(
        result["error"]["code"], "fees.percentile_exceeds_cap",
        "{result}"
    );
    let message = result["error"]["message"].as_str().unwrap();
    assert!(
        message.ends_with("The signature was withheld and nothing was sent."),
        "the rebuild refuses: {result}"
    );
    let expected = cap_text(FEE_ABOVE_CAP, 500, FeeSource::ProfileDefault);
    assert!(
        message.contains(&expected),
        "the refusal names `{expected}`: {result}"
    );
    assert!(fixture.sent_envelopes().await.is_empty());
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    assert!(fixture.open_authorizations(now).is_empty());
    assert_eq!(operation(&fixture, &id).attempts, 0);
}

/// A run that refuses after its record opens and before the confirmation
/// leaves the record with the policy's decision and its waiting interval:
/// the rule's 300 seconds under an approval rule, the store's 600-second
/// default otherwise.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_record_refused_before_the_confirmation_keeps_its_decision() {
    for (approval, name, decision, waiting_ms) in [
        (false, "canonical-decision-allow", "allow", 600_000),
        (
            true,
            "canonical-decision-approval",
            "require_approval",
            300_000,
        ),
    ] {
        // The oracle reports another balance, so the verb's own oracle
        // check after the bind refuses.
        let fixture = Verb::Claim
            .spec(name)
            .oracle(claim::ledger(true, 100_000_001))
            .rules(rules(Verb::Claim, approval))
            .build()
            .await;
        let id = crate::common::business_entry::fresh_business_id();
        let (code, result) = run(Verb::Claim, &fixture, &id).await;
        assert_eq!(code, 1, "{name}: {result}");
        assert_eq!(result["error"]["code"], "simulation.divergence", "{name}");
        fixture.assert_no_consent_ceremony();
        let view = operation(&fixture, &id);
        assert_eq!(view.slot_kind, SlotKind::Canonical, "{name}");
        assert_eq!(view.attempts, 0, "{name}");
        assert_eq!(
            view.waiting_expires_at_ms,
            view.created_at_ms.map(|at| at + waiting_ms),
            "{name}"
        );
        let record = fixture.window_body()["operations"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["business_id"] == id.as_str())
            .cloned()
            .unwrap();
        assert_eq!(record["prepared_decision"], decision, "{name}");
    }
}

/// A canonical begin whose commit fails mints nothing: the run refuses
/// before any signature, no authorization and no attempt exist, and the
/// approval stays unspent, so the same business id then completes once.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_refused_canonical_begin_leaves_no_authorization() {
    use stellar_agent_network::policy_state::store::commit_faults::{
        COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
    };
    let fixture = Verb::Pay
        .spec("canonical-begin-refused")
        .rules(rules(Verb::Pay, true))
        .build()
        .await;
    let id = crate::common::business_entry::fresh_business_id();
    let armed = std::rc::Rc::new(std::cell::RefCell::new(None));
    let slot = std::rc::Rc::clone(&armed);
    let hook = crate::common::mainnet_write::consent_test::on_witness(fixture.name, move |_, _| {
        // The begin is the next window commit after the consent check.
        *slot.borrow_mut() = Some(arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED));
    });
    let (code, result) = run(Verb::Pay, &fixture, &id).await;
    drop(hook);
    assert!(
        armed.borrow().is_some(),
        "the consent check armed the fault"
    );
    drop(armed.borrow_mut().take());
    assert_eq!(code, 1, "{result}");
    assert_eq!(
        result["error"]["code"], "submission.record_unavailable",
        "the begin took the fault: {result}"
    );
    assert!(fixture.sent_envelopes().await.is_empty());
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    assert!(
        fixture.open_authorizations(now).is_empty(),
        "nothing minted"
    );
    let view = operation(&fixture, &id);
    assert_eq!(view.attempts, 0, "no attempt");
    let record = || {
        ApprovalStatus::new(
            &PersistedWindowStore::for_profile(fixture.name),
            &fixture.profile(),
        )
        .find_by_operation(view.operation_id)
        .unwrap()
        .expect("an approval record")
        .record
    };
    assert_eq!(
        record().state,
        stellar_agent_network::policy_state::ApprovalState::Pending,
        "the approval stays unspent"
    );
    let (code, result) = run(Verb::Pay, &fixture, &id).await;
    assert_eq!(code, 0, "the same business id completes: {result}");
    assert_eq!(fixture.sent_envelopes().await.len(), 1);
    assert_eq!(fixture.ceremonies().len(), 1, "the consent is reused");
    assert_eq!(operation(&fixture, &id).attempts, 1);
}

/// Opens under `id` an envelope record of the payment the pay verb's
/// arguments name, over an envelope whose deadline is `max_time_s`, as an
/// earlier version prepared it, and returns that stored envelope.
fn open_envelope_record(fixture: &MainnetFixture, id: &str, max_time_s: u64) -> String {
    use stellar_agent_core::approval::{IntentAsset, IntentPayload, MemoFact};
    use stellar_agent_network::operation_entry::{
        IntentBaseFacts, Preparation, classic_intent, intent_envelope,
    };
    use stellar_agent_network::policy_state::{OperationKind, OperationRecorder, OperationTool};
    let profile = fixture.profile();
    let policy = crate::commands::policy_engine::load_mainnet_policy_engine(
        "pay",
        "policy.engine_unavailable",
        &crate::common::mainnet_write::mainnet_context(
            &profile,
            &stellar_agent_core::profile::name::resolve_profile_name(Some(fixture.name)),
            stellar_agent_network::MainnetEndpointFlags::default(),
        )
        .unwrap(),
        stellar_agent_core::profile::name::ProfileNameSource::Flag,
        &crate::common::mainnet_write::mainnet_profiles_dir().unwrap(),
    )
    .unwrap();
    let intent = classic_intent(
        IntentBaseFacts::new(
            &profile,
            &fixture.agent.g,
            &policy.verified,
            stellar_agent_network::fees::ClassicFeeChoice::Auto(
                stellar_agent_network::fees::FeePercentile::P95,
            ),
            MemoFact::None,
        ),
        IntentPayload::Pay {
            destination: crate::common::mainnet_write_fixture::DESTINATION.to_owned(),
            asset: IntentAsset::Native,
            amount_stroops: 10_000_000,
        },
    )
    .unwrap();
    let stored = intent_envelope(
        &intent,
        profile.chain_id.network_passphrase(),
        crate::test_rpc::ACCOUNT_SEQUENCE,
        100,
        max_time_s,
    )
    .unwrap();
    {
        let writer = crate::commands::submission_record::accounting_audit_writer(
            &profile,
            fixture.name,
            crate::common::profile_access::ProfileOrigin::Persisted,
        )
        .unwrap();
        let mut writer = writer.lock().unwrap();
        Preparation::Envelope(*intent.digest().as_bytes())
            .open(
                &mut OperationRecorder::new(
                    &PersistedWindowStore::for_profile(fixture.name),
                    &profile,
                    &mut *writer,
                    "legacy-open",
                ),
                BusinessId::parse(id).unwrap(),
                OperationTool::CliPay,
                OperationKind::Pay,
                &stored,
            )
            .unwrap();
    }
    stored
}

/// The current wall clock in Unix seconds.
fn now_s() -> u64 {
    stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000
}

/// A business id whose record binds an exact envelope continues with that
/// envelope under a verb that prepares canonical records: the run signs the
/// stored transaction, never a rebuilt one, and the record stays an envelope
/// record.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn legacy_binding_is_never_promoted() {
    let fixture = Verb::Pay
        .spec("canonical-legacy-binding")
        .rules(rules(Verb::Pay, false))
        .build()
        .await;
    let id = crate::common::business_entry::fresh_business_id();
    let stored = open_envelope_record(&fixture, &id, now_s() + 90);
    let (code, result) = run(Verb::Pay, &fixture, &id).await;
    assert_eq!(code, 0, "{result}");
    let sent = fixture.sent_envelopes().await;
    assert_eq!(sent.len(), 1);
    let (TransactionEnvelope::Tx(signed), TransactionEnvelope::Tx(unsigned)) = (
        TransactionEnvelope::from_xdr_base64(&sent[0], Limits::none()).unwrap(),
        TransactionEnvelope::from_xdr_base64(&stored, Limits::none()).unwrap(),
    ) else {
        panic!("transaction envelopes")
    };
    assert_eq!(signed.tx, unsigned.tx, "the stored transaction is signed");
    let view = operation(&fixture, &id);
    assert_eq!(view.slot_kind, SlotKind::Envelope, "never promoted");
    assert_eq!(view.attempts, 1);
}

/// The confirmation of an envelope record shows its stored envelope with the
/// latest ledger the build's readiness check observed, after the fee lines
/// and before the consent line.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn an_envelope_record_summary_names_the_ledger() {
    let fixture = Verb::Pay
        .spec("canonical-legacy-summary")
        .rules(rules(Verb::Pay, true))
        .build()
        .await;
    let id = crate::common::business_entry::fresh_business_id();
    open_envelope_record(&fixture, &id, now_s() + 90);
    let (code, result) = run(Verb::Pay, &fixture, &id).await;
    assert_eq!(code, 0, "{result}");
    let summaries = fixture.summaries();
    assert_eq!(summaries.len(), 1, "{summaries:?}");
    let lines: Vec<&str> = summaries[0].lines().collect();
    let at = lines
        .iter()
        .position(|line| line.starts_with("Ledger 2000, closed "))
        .unwrap_or_else(|| panic!("the summary names the ledger: {lines:?}"));
    assert!(lines[at - 1].starts_with("Fee cap: "), "{lines:?}");
    assert_eq!(
        lines[at + 1],
        crate::common::mainnet_confirm::CONSENT_LINE,
        "{lines:?}"
    );
    assert!(lines[at].ends_with(" s ago"), "{lines:?}");
}

/// An envelope record whose stored deadline has passed is never rebuilt. A
/// deadline already past at the lookup expires the record, which replays
/// as `expired`. A deadline that passes during the confirmation refuses at
/// the resolver with `deadline_elapsed` before any signer is resolved. In
/// neither case is anything sent.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn an_elapsed_envelope_record_refuses_before_signing() {
    use crate::common::mainnet_write_fixture::{CLOCK_LEAD_MS, refusal_warnings};
    use crate::common::signer_ceremony::signer_resolutions_on_this_thread;
    let fixture = Verb::Pay
        .spec("canonical-legacy-expired")
        .rules(rules(Verb::Pay, false))
        .build()
        .await;
    let id = crate::common::business_entry::fresh_business_id();
    open_envelope_record(&fixture, &id, now_s() - 10);
    let (code, result) = run(Verb::Pay, &fixture, &id).await;
    assert_eq!(code, 1, "{result}");
    assert_eq!(result["data"]["operation"]["state"], "expired", "{result}");
    assert!(fixture.sent_envelopes().await.is_empty());

    let mut fixture = Verb::Pay
        .spec("canonical-legacy-elapsed")
        .rules(rules(Verb::Pay, true))
        .build()
        .await;
    let start_ms = stellar_agent_core::timefmt::now_unix_ms().unwrap() + CLOCK_LEAD_MS;
    let clock = std::rc::Rc::new(stellar_agent_network::mainnet::clock::set_now_ms_for_test(
        start_ms,
    ));
    fixture.present_past_the_deadline(std::rc::Rc::clone(&clock));
    let id = crate::common::business_entry::fresh_business_id();
    open_envelope_record(&fixture, &id, start_ms / 1000 + 60);
    let resolutions = signer_resolutions_on_this_thread();
    let (capture, _guard) = stellar_agent_test_support::WarningCapture::capture(None);
    let (code, result) = run(Verb::Pay, &fixture, &id).await;
    drop(clock);
    assert_eq!(code, 1, "{result}");
    assert_eq!(
        result["error"]["code"], "network.mainnet_authorization_refused",
        "{result}"
    );
    assert_eq!(
        refusal_warnings(&capture, "resolve_tx_sign"),
        vec!["\"deadline_elapsed\"".to_owned()]
    );
    assert_eq!(signer_resolutions_on_this_thread(), resolutions);
    assert!(fixture.sent_envelopes().await.is_empty());
    assert_eq!(operation(&fixture, &id).slot_kind, SlotKind::Envelope);
}

/// A claim whose balance changed after the decision refuses with
/// `simulation.divergence` before any signature, and a business id outside
/// the printable ASCII range refuses typed before any record opens.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn canonical_refusals_cross_the_cli_surface() {
    // From the rebuild's readiness check on, the primary reports the balance
    // with another amount; the oracle keeps the one the preparation read.
    let changing = || {
        let rebuilding = AtomicBool::new(false);
        let (key, changed) =
            crate::commands::claim::tests::claimable_entry_with(&agent(), 99_999_999);
        Verb::Claim
            .ledger()
            .with_script(move |method, index, body| {
                if method == "getHealth" && index == 1 {
                    rebuilding.store(true, Ordering::SeqCst);
                }
                (method == "getLedgerEntries"
                    && rebuilding.load(Ordering::SeqCst)
                    && body["params"]["keys"] == json!([key]))
                .then(|| {
                    json!({
                        "entries": [{ "key": key, "xdr": changed, "lastModifiedLedgerSeq": 1000 }],
                        "latestLedger": 1001
                    })
                })
            })
    };
    for approval in [false, true] {
        let name = if approval {
            "canonical-divergence-approval"
        } else {
            "canonical-divergence-allow"
        };
        let fixture = Verb::Claim
            .spec(name)
            .primary(changing())
            .rules(rules(Verb::Claim, approval))
            .build()
            .await;
        let id = crate::common::business_entry::fresh_business_id();
        let (code, result) = run(Verb::Claim, &fixture, &id).await;
        assert_eq!(code, 1, "{name}: {result}");
        assert_eq!(
            result["error"]["code"], "simulation.divergence",
            "{name}: {result}"
        );
        assert!(
            result["error"]["message"]
                .as_str()
                .unwrap()
                .ends_with("The signature was withheld and nothing was sent."),
            "{name}: {result}"
        );
        assert!(fixture.sent_envelopes().await.is_empty(), "{name}");
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        assert!(fixture.open_authorizations(now).is_empty(), "{name}");
        assert_eq!(operation(&fixture, &id).attempts, 0, "{name}");
    }
    let fixture = Verb::Claim.spec("canonical-business-id-text").build().await;
    let (code, result) = run(Verb::Claim, &fixture, "commande-é-7").await;
    assert_eq!(code, 1, "{result}");
    assert_eq!(result["error"]["code"], "validation.business_id_invalid");
    assert!(
        OperationStatus::new(
            &PersistedWindowStore::for_profile(fixture.name),
            &fixture.profile()
        )
        .list_since(0)
        .unwrap()
        .is_empty(),
        "no record opens"
    );
}

/// The clock of [`rebuilt_deadline_row`], in Unix
/// milliseconds: the wallet's clock and the close time the endpoints report.
static DEADLINE_CLOCK_MS: AtomicU64 = AtomicU64::new(0);

fn deadline_close_secs() -> u64 {
    DEADLINE_CLOCK_MS.load(Ordering::SeqCst) / 1000
}

/// The rebuilt envelope's deadline is the earlier of 120 seconds after the
/// rebuild and the last whole second before the authority's end, which holds
/// strictly before it: a rebuild 60 seconds before that end sends an envelope
/// whose deadline is that second. Under policy authority the end is the allow
/// decision's 600-second governing end, here at a whole second, so the
/// deadline is one second before it.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn the_rebuilt_deadline_never_passes_the_policy_authority() {
    rebuilt_deadline_row(false, "canonical-deadline-allow", 600_000, 0).await;
}

/// [`the_rebuilt_deadline_never_passes_the_policy_authority`] under an
/// approval rule: the end is the approval's execution end, bounded by its
/// 300-second rule, here half a second past a whole second, so the deadline
/// is that whole second.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn the_rebuilt_deadline_never_passes_the_approval_authority() {
    rebuilt_deadline_row(true, "canonical-deadline-approval", 300_000, 500).await;
}

/// Runs a payment prepared `offset_ms` after a whole second, whose rebuild
/// happens 60 seconds before the end of its authority, `authority_ms` after
/// the preparation, and asserts the sent envelope's deadline is the last
/// whole second before that end.
async fn rebuilt_deadline_row(
    approval: bool,
    name: &'static str,
    authority_ms: u64,
    offset_ms: u64,
) {
    let start = stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000 * 1000 + offset_ms;
    let _clock = stellar_agent_core::timefmt::test_clock::install(Arc::new(
        stellar_agent_core::timefmt::MockClock::new(
            || Ok(DEADLINE_CLOCK_MS.load(Ordering::SeqCst)),
        ),
    ));
    DEADLINE_CLOCK_MS.store(start, Ordering::SeqCst);
    let end_ms = start + authority_ms;
    // The rebuild's readiness check is the primary's second; the clock
    // reaches 60 seconds before the authority's end there.
    let primary = Verb::Pay
        .ledger()
        .with_close_clock(deadline_close_secs)
        .with_script(move |method, index, _| {
            if method == "getHealth" && index == 1 {
                DEADLINE_CLOCK_MS.store(end_ms - 60_000, Ordering::SeqCst);
            }
            None
        });
    let fixture = Verb::Pay
        .spec(name)
        .primary(primary)
        .oracle(Verb::Pay.ledger().with_close_clock(deadline_close_secs))
        .rules(rules(Verb::Pay, approval))
        .build()
        .await;
    let id = crate::common::business_entry::fresh_business_id();
    let (code, result) = run(Verb::Pay, &fixture, &id).await;
    assert_eq!(code, 0, "{name}: {result}");
    let sent = fixture.sent_envelopes().await;
    assert_eq!(sent.len(), 1, "{name}");
    let last_second_before_end = if end_ms.is_multiple_of(1000) {
        end_ms / 1000 - 1
    } else {
        end_ms / 1000
    };
    assert_eq!(
        deadline(&sent[0]),
        last_second_before_end,
        "{name}: the deadline is the last second before the authority's end"
    );
}

/// The clock of [`a_successor_stays_inside_the_record_execution_window`], in
/// Unix milliseconds: the wallet's clock and the close time the endpoints
/// report.
static SUCCESSOR_CLOCK_MS: AtomicU64 = AtomicU64::new(0);
/// Whether the endpoints answer the transaction as not found and serve the
/// ledger history a recovery pass reads.
static SUCCESSOR_ABSENT: AtomicBool = AtomicBool::new(false);

fn successor_close_secs() -> u64 {
    SUCCESSOR_CLOCK_MS.load(Ordering::SeqCst) / 1000
}

/// While [`SUCCESSOR_ABSENT`] holds, a `NOT_FOUND` transaction with its
/// close times and a `getLedgers` page of the requested ledger, closed at
/// the clock.
fn successor_script(method: &str, _: usize, body: &Value) -> Option<Value> {
    if !SUCCESSOR_ABSENT.load(Ordering::SeqCst) {
        return None;
    }
    let close = successor_close_secs().to_string();
    match method {
        "getTransaction" => Some(json!({
            "status": "NOT_FOUND", "latestLedger": 2000, "oldestLedger": 1,
            "latestLedgerCloseTime": close, "oldestLedgerCloseTime": "1"
        })),
        "getLedgers" => {
            let start = body["params"]["startLedger"].as_u64().unwrap_or(2000);
            Some(json!({
                "latestLedger": 2000, "oldestLedger": 1, "latestLedgerCloseTime": close,
                "oldestLedgerCloseTime": 1, "cursor": "2000",
                "ledgers": [{"sequence": start, "ledgerCloseTime": close,
                    "hash": "00".repeat(32), "headerXdr": "", "metadataXdr": ""}]
            }))
        }
        _ => None,
    }
}

/// A successor's deadline never passes the record's execution end. Under
/// policy authority a payment's first attempt, decided at a whole second,
/// sets the record's execution end 600 seconds later; both endpoints answer
/// its transaction as not found. Past its deadline the CLI's recovery pass
/// proves the non-inclusion. A successor under the same id, decided and
/// rebuilt 60 seconds before the record's end, holds a decision of its own
/// that ends 540 seconds after the record's, and sends the second before the
/// record's end.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_successor_stays_inside_the_record_execution_window() {
    let name = "canonical-successor-window";
    let start = stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000 * 1000;
    let record_end_ms = start + 600_000;
    SUCCESSOR_CLOCK_MS.store(start, Ordering::SeqCst);
    SUCCESSOR_ABSENT.store(true, Ordering::SeqCst);
    let _clock = stellar_agent_core::timefmt::test_clock::install(Arc::new(
        stellar_agent_core::timefmt::MockClock::new(|| {
            Ok(SUCCESSOR_CLOCK_MS.load(Ordering::SeqCst))
        }),
    ));
    let endpoint = || {
        Verb::Pay
            .ledger()
            .with_close_clock(successor_close_secs)
            .entries_at_readiness_ledger()
            .with_script(successor_script)
    };
    let primary_endpoint = endpoint();
    let fixture = Verb::Pay
        .spec(name)
        .primary(primary_endpoint.clone())
        .oracle(endpoint())
        .submit_timeout_seconds(1)
        .rules(rules(Verb::Pay, false))
        .build()
        .await;
    let id = crate::common::business_entry::fresh_business_id();
    let (_, first) = run(Verb::Pay, &fixture, &id).await;
    let sent = fixture.sent_envelopes().await;
    assert_eq!(sent.len(), 1, "{name}: {first}");
    let record = operation(&fixture, &id);
    assert_eq!(
        record.state,
        stellar_agent_network::policy_state::OperationState::SentOutcomeUnknown,
        "{name}: {first}"
    );
    assert_eq!(
        record.execution_expires_at_ms,
        Some(record_end_ms),
        "{name}"
    );

    // The primary counts an accepted send as a consumed sequence; the
    // transaction it never included consumed none.
    primary_endpoint.advance_sequence(&agent(), -1);
    SUCCESSOR_CLOCK_MS.store((deadline(&sent[0]) + 7) * 1000, Ordering::SeqCst);
    let primary = stellar_agent_network::StellarRpcClient::new(&fixture.primary.uri()).unwrap();
    let oracle = stellar_agent_network::StellarRpcClient::new(&fixture.oracle.uri()).unwrap();
    crate::commands::submission_record::reconcile_open_reservations(
        &fixture.profile(),
        fixture.name,
        crate::common::profile_access::ProfileOrigin::Persisted,
        &primary,
        Some(&oracle),
        SUCCESSOR_CLOCK_MS.load(Ordering::SeqCst),
        None,
    )
    .await;
    assert_eq!(
        operation(&fixture, &id).state,
        stellar_agent_network::policy_state::OperationState::NotIncluded,
        "{name}: the recovery pass proves the non-inclusion"
    );

    SUCCESSOR_ABSENT.store(false, Ordering::SeqCst);
    SUCCESSOR_CLOCK_MS.store(record_end_ms - 60_000, Ordering::SeqCst);
    let (code, result) = run(Verb::Pay, &fixture, &id).await;
    SUCCESSOR_ABSENT.store(false, Ordering::SeqCst);
    assert_eq!(code, 0, "{name}: {result}");
    let sent = fixture.sent_envelopes().await;
    assert_eq!(sent.len(), 2, "{name}");
    assert_eq!(
        deadline(&sent[1]),
        record_end_ms / 1000 - 1,
        "{name}: the successor's deadline is the second before the record's execution end"
    );
    assert_eq!(operation(&fixture, &id).attempts, 2, "{name}");
}

/// The clock of [`cli_canonical_full_path_matrix`], in Unix milliseconds:
/// the wallet's clock and the close time the endpoints report.
static MATRIX_CLOCK_MS: AtomicU64 = AtomicU64::new(0);

fn matrix_close_secs() -> u64 {
    MATRIX_CLOCK_MS.load(Ordering::SeqCst) / 1000
}

const MATRIX_NAMES: [[&str; 2]; 4] = [
    [
        "canonical-matrix-pay-allow",
        "canonical-matrix-pay-approval",
    ],
    [
        "canonical-matrix-claim-allow",
        "canonical-matrix-claim-approval",
    ],
    [
        "canonical-matrix-create-allow",
        "canonical-matrix-create-approval",
    ],
    [
        "canonical-matrix-trustline-allow",
        "canonical-matrix-trustline-approval",
    ],
];

/// Each verb under each authority: a first run decides, and consents under
/// an approval rule a minute after the preparation, then refuses at the
/// rebuild's readiness check. 320 seconds after the preparation, past the
/// 300-second waiting interval and 40 seconds before the end of the
/// execution interval that the consent started, the same business id
/// completes with one signature and no second consent; the signed deadline
/// is the last whole second before that end. In the moved rows another
/// wallet's sends advance the
/// agent's sequence on both endpoints between the runs: the resumed record
/// still completes, signed at the account's current sequence.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn cli_canonical_full_path_matrix() {
    let start = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    let retry_at = start + 320_000;
    MATRIX_CLOCK_MS.store(start, Ordering::SeqCst);
    let _clock = stellar_agent_core::timefmt::test_clock::install(Arc::new(
        stellar_agent_core::timefmt::MockClock::new(|| Ok(MATRIX_CLOCK_MS.load(Ordering::SeqCst))),
    ));
    for (verb, names) in Verb::ALL.into_iter().zip(MATRIX_NAMES) {
        let rows = [false, true].into_iter().flat_map(|moved| {
            [false, true]
                .into_iter()
                .zip(names)
                .map(move |(approval, name)| (moved, approval, name))
        });
        for (moved, approval, name) in rows {
            let name: &'static str = if moved {
                Box::leak(format!("{name}-moved").into_boxed_str())
            } else {
                name
            };
            MATRIX_CLOCK_MS.store(start, Ordering::SeqCst);
            let unready = |rpc: ClassicRpc| {
                rpc.with_close_clock(matrix_close_secs)
                    .with_script(|method, index, _| {
                        (method == "getHealth" && index == 1).then(|| {
                            json!({
                                "status": "unhealthy",
                                "latestLedger": 2000,
                                "oldestLedger": 1,
                                "ledgerRetentionWindow": 1999,
                                "oldestLedgerCloseTime": 1,
                                "latestLedgerCloseTime": matrix_close_secs()
                            })
                        })
                    })
            };
            let (primary, oracle) = (verb.ledger(), verb.ledger());
            let (advance_primary, advance_oracle) = (primary.clone(), oracle.clone());
            let mut fixture = verb
                .spec(name)
                .primary(unready(primary))
                .oracle(oracle.with_close_clock(matrix_close_secs))
                .rules(rules(verb, approval))
                .build()
                .await;
            let mut answer = crate::common::mainnet_presence::driver::fixture_credential();
            fixture.present_with(move |ceremony| {
                MATRIX_CLOCK_MS.fetch_add(60_000, Ordering::SeqCst);
                answer(ceremony)
            });
            let id = crate::common::business_entry::fresh_business_id();
            let (code, result) = run(verb, &fixture, &id).await;
            assert_eq!(code, 1, "{name}: {result}");
            assert!(fixture.sent_envelopes().await.is_empty(), "{name}");
            let now = MATRIX_CLOCK_MS.load(Ordering::SeqCst);
            assert!(fixture.open_authorizations(now).is_empty(), "{name}");
            if moved {
                advance_primary.advance_sequence(&agent(), OTHER_SENDS);
                advance_oracle.advance_sequence(&agent(), OTHER_SENDS);
            }
            MATRIX_CLOCK_MS.store(retry_at, Ordering::SeqCst);
            let (code, result) = run(verb, &fixture, &id).await;
            assert_eq!(code, 0, "{name}: {result}");
            let sent = fixture.sent_envelopes().await;
            assert_eq!(sent.len(), 1, "{name}");
            crate::common::mainnet_write_fixture::assert_deadline_bound(&sent[0], retry_at);
            assert_eq!(
                sequence_and_fee(&sent[0]).0,
                crate::test_rpc::ACCOUNT_SEQUENCE + if moved { OTHER_SENDS } else { 0 } + 1,
                "{name}: signed at the account's current sequence"
            );
            assert_eq!(operation(&fixture, &id).attempts, 1, "{name}");
            if approval {
                assert_eq!(fixture.ceremonies().len(), 1, "{name}: one consent");
                let entry = &fixture.pending_entries()[0];
                assert!(
                    entry.expires_at_unix_ms < retry_at,
                    "{name}: the waiting interval ended before the signature"
                );
                assert_eq!(
                    deadline(&sent[0]),
                    (start + 60_000 + 300_000 - 1) / 1000,
                    "{name}: the deadline is the last second before the execution end"
                );
            } else {
                fixture.assert_no_consent_ceremony();
            }
        }
    }
}
