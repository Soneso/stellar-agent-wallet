use super::*;
use stellar_agent_core::approval::{
    ClassicIntent, IntentAsset, IntentPayload, MemoFact, subject::SubjectKind,
};
use stellar_agent_network::operation_entry::{
    IntentBaseFacts, OpenedEntry, Preparation, classic_intent, intent_envelope,
};
use stellar_agent_network::policy_state::{
    BusinessId, OperationKind, OperationRecorder, OperationTool, RowProvenance,
};

#[cfg(test)]
pub(crate) fn staged(
    fixture: &MainnetConsentFixture,
    context: &MainnetWriteContext,
    kind: usize,
    memo: MemoFact,
    limit: i64,
) -> (ClassicIntent, MainnetWriteSummary, OperationHandle) {
    staged_as(fixture, context, kind, memo, limit, "canonical-consent", 37)
}

/// [`staged`] under `business_id`, paying `amount` for a payment.
fn staged_as(
    fixture: &MainnetConsentFixture,
    context: &MainnetWriteContext,
    kind: usize,
    memo: MemoFact,
    limit: i64,
    business_id: &str,
    amount: i64,
) -> (ClassicIntent, MainnetWriteSummary, OperationHandle) {
    let source = context.profile().mcp_signer_default.account.clone();
    let destination = stellar_strkey::ed25519::PublicKey([6; 32])
        .to_string()
        .to_string();
    let issued = IntentAsset::Issued {
        code: "UsD".into(),
        issuer: destination.clone(),
    };
    let (payload, consumer, tool, operation) = match kind {
        0 => (
            IntentPayload::Pay {
                destination,
                asset: issued,
                amount_stroops: amount,
            },
            MainnetConsumer::CliPay,
            OperationTool::CliPay,
            OperationKind::Pay,
        ),
        1 => (
            IntentPayload::CreateAccount {
                destination,
                starting_balance_stroops: 53,
            },
            MainnetConsumer::CliCreateAccount,
            OperationTool::CliAccountsCreate,
            OperationKind::CreateAccount,
        ),
        2 => (
            IntentPayload::Trustline {
                issuer: destination,
                code: "UsD".into(),
                limit_stroops: limit,
            },
            MainnetConsumer::CliTrustline,
            OperationTool::CliTrustline,
            OperationKind::Trustline,
        ),
        _ => (
            IntentPayload::Claim {
                balance_id: format!("00000000{}", "09".repeat(32)),
                claimant: source.clone(),
                asset: issued,
                amount_stroops: 71,
            },
            MainnetConsumer::CliClaim,
            OperationTool::CliClaim,
            OperationKind::Claim,
        ),
    };
    let intent = classic_intent(
        IntentBaseFacts::new(
            context.profile(),
            &source,
            &fixture.current_policy(),
            stellar_agent_network::fees::ClassicFeeChoice::Explicit(500),
            memo,
        ),
        payload,
    )
    .unwrap();
    let envelope = intent_envelope(
        &intent,
        context.profile().chain_id.network_passphrase(),
        89,
        100,
        clock_now().unwrap() / 1000 + 600,
    )
    .unwrap();
    let summary = MainnetWriteSummary::from_envelope(&envelope, consumer, 500).unwrap();
    let store = PersistedWindowStore::for_profile(context.profile_name());
    let OpenedEntry::Resume(handle) = Preparation::Canonical {
        intent: Box::new(intent.clone()),
        decision: PolicyDecision::RequireApproval,
        rule_ttl_ms: Some(120_000),
    }
    .open(
        &mut OperationRecorder::new(&store, context.profile(), &mut NoRows, "canonical-open"),
        BusinessId::parse(business_id).unwrap(),
        tool,
        operation,
        &envelope,
    )
    .unwrap() else {
        panic!("new canonical operation")
    };
    (intent, summary, handle)
}

#[cfg(test)]
async fn confirm_staged(
    fixture: &MainnetConsentFixture,
    context: &MainnetWriteContext,
    summary: &MainnetWriteSummary,
    handle: &OperationHandle,
) -> Result<ApprovalWitness, WalletError> {
    confirm_mainnet_write(
        summary,
        ConfirmDecision::RequireApproval { ttl_ms: 120_000 },
        context,
        &fixture.current_policy(),
        &fixture.store_path(),
        Some(handle),
        PolicyDecision::RequireApproval,
        &governing(context, &fixture.current_policy(), 120_000),
    )
    .await
}

pub(crate) fn park_staged(
    fixture: &MainnetConsentFixture,
    context: &MainnetWriteContext,
    intent: &ClassicIntent,
    summary: &MainnetWriteSummary,
    handle: &OperationHandle,
) -> PendingApproval {
    let mut entry = summary
        .pending(process_uid_for_attestation().unwrap(), 120_000)
        .unwrap();
    stellar_agent_network::operation_entry::stage_pending(&mut entry, Some(intent), 120_000)
        .unwrap();
    let facts = pending_approval_facts(&entry, handle, intent.approved_kind(), [0; 32], 120_000);
    // An enforced kind parks as its integrated producer does: initialized
    // evidence and a reservation before the inbox entry.
    let start = if stellar_agent_network::policy_state::approvals::delivery_enforced(
        context.profile_name(),
        intent.approved_kind(),
    ) {
        start_integrated(
            context,
            &fixture.store_path(),
            handle,
            entry,
            &facts,
            PolicyDecision::RequireApproval,
        )
        .map(|(start, _)| start)
    } else {
        start_durable(
            context,
            &fixture.store_path(),
            handle,
            entry,
            &facts,
            PolicyDecision::RequireApproval,
        )
    };
    match start.unwrap() {
        DurableStart::Ceremony(entry) => *entry,
        _ => panic!("fresh preparation"),
    }
}

#[tokio::test]
#[serial_test::serial]
async fn canonical_recovery_keeps_signed_clocks() {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    for kind in 0..4 {
        for approve in [false, true] {
            let (mut fixture, context, _) =
                confirmation_fixture(&format!("canonical-clocks-{kind}-{approve}"));
            // The listed kinds take the integrated route.
            fixture.enforce_listed();
            let time = Arc::new(AtomicU64::new(clock_now().unwrap()));
            let read = time.clone();
            let _clock = stellar_agent_core::timefmt::test_clock::install(Arc::new(
                stellar_agent_core::timefmt::MockClock::new(
                    move || Ok(read.load(Ordering::SeqCst)),
                ),
            ));
            let (intent, summary, handle) = staged(&fixture, &context, kind, MemoFact::None, 0);
            let entry = park_staged(&fixture, &context, &intent, &summary, &handle);
            time.fetch_add(60_000, Ordering::SeqCst);
            let consent_at = time.load(Ordering::SeqCst);
            let policy = fixture.current_policy();
            let presence = fixture.intent_presence(&entry, &policy, &intent);
            let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
            let OperatorRowSink::Writer(writer) =
                acquire_operator_row_sink(fixture.profile(), fixture.name()).unwrap()
            else {
                panic!("fixture writer")
            };
            // A listed kind is attested as its integrated producer attests,
            // with the publication handoff its recovery requires.
            let auth = stellar_agent_core::approval::ConsentAuthorization::Mainnet {
                presence,
                policy: &policy,
            };
            if stellar_agent_network::policy_state::approvals::consent_evidence_enforced(
                intent.approved_kind(),
            ) {
                stellar_agent_core::approval::attest::attest_and_persist_with_row(
                    &mut store,
                    &entry,
                    &stellar_agent_core::approval::mainnet_fixtures::ATTESTATION_KEY,
                    &fixture.binding(),
                    stellar_agent_core::approval::Surface::Cli,
                    ConsentAudit::Writer(&mut writer.lock().unwrap()),
                    auth,
                    |_, _| unreachable!(),
                )
                .unwrap();
            } else {
                stellar_agent_core::approval::attest_and_persist(
                    &mut store,
                    &entry,
                    &stellar_agent_core::approval::mainnet_fixtures::ATTESTATION_KEY,
                    &fixture.binding(),
                    stellar_agent_core::approval::Surface::Cli,
                    ConsentAudit::Writer(&mut writer.lock().unwrap()),
                    auth,
                    |_, _| unreachable!(),
                )
                .unwrap();
            }
            drop(store);
            if approve {
                time.store(entry.expires_at_unix_ms + 1, Ordering::SeqCst);
                crate::common::render::take_rendered_for_test();
                let code =
                    crate::commands::approve::run::run(crate::commands::approve::run::RunArgs {
                        id: Some(entry.approval_nonce.clone()),
                        profile: Some(fixture.name().into()),
                        yes: false,
                        open_by_operator: false,
                    })
                    .await;
                let output = crate::common::render::take_rendered_for_test();
                assert_eq!(code, 1);
                assert_eq!(
                    output.last().unwrap()["error"]["code"],
                    "approval.expired",
                    "approve preserves the expired inbox response after durable recovery"
                );
                let consent = durable_record(&context, &handle)
                    .unwrap()
                    .consent
                    .expect("approve recovery records canonical consent for every kind");
                assert_eq!(consent.consent_at_ms, consent_at);
                // Published recovery keeps the original sink from the
                // verified handoff; compatibility recovery records it as
                // recovered.
                let enforced =
                    stellar_agent_network::policy_state::approvals::consent_evidence_enforced(
                        intent.approved_kind(),
                    );
                assert_eq!(consent.delivery.is_some(), enforced, "kind {kind}");
                assert_eq!(
                    consent.payload.unwrap().row_provenance,
                    Some(if enforced {
                        RowProvenance::Written
                    } else {
                        RowProvenance::Recovered
                    }),
                    "kind {kind}"
                );
                assert_eq!(
                    consent_rows(&context),
                    1,
                    "approve recovery adds no consent row"
                );
            }
            for at in [
                entry.expires_at_unix_ms,
                entry.expires_at_unix_ms + 1,
                consent_at + 119_999,
            ] {
                time.store(at, Ordering::SeqCst);
                let witness = confirm_staged(&fixture, &context, &summary, &handle)
                    .await
                    .expect("recover after waiting end before execution end");
                assert_eq!(
                    (
                        witness.created_at_ms(),
                        witness.expires_at_ms(),
                        witness.consent_at_ms(),
                        witness.execution_expires_at_ms()
                    ),
                    (
                        entry.created_at_unix_ms,
                        entry.expires_at_unix_ms,
                        consent_at,
                        consent_at + 120_000
                    ),
                    "restart preserves all signed and effective clocks"
                );
            }
            for at in [consent_at - 1, consent_at + 120_000, consent_at + 120_001] {
                time.store(at, Ordering::SeqCst);
                assert_eq!(
                    confirm_staged(&fixture, &context, &summary, &handle)
                        .await
                        .unwrap_err()
                        .code(),
                    "approval.expired",
                    "recovery refuses outside execution interval"
                );
            }
        }
    }
}

/// A crash after a canonical record opens and before its inbox entry's first
/// write leaves the record without an entry. The retry, a minute later,
/// queues a new entry over the decision's whole lifetime, and its consent to
/// the stored intent admits the operation, for each of the four verbs.
#[tokio::test]
#[serial_test::serial]
async fn canonical_retry_after_a_lost_first_entry_admits_its_consent() {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    for kind in 0..4 {
        let (fixture, context, _) = confirmation_fixture(&format!("canonical-lost-entry-{kind}"));
        let time = Arc::new(AtomicU64::new(clock_now().unwrap()));
        let read = time.clone();
        let _clock = stellar_agent_core::timefmt::test_clock::install(Arc::new(
            stellar_agent_core::timefmt::MockClock::new(move || Ok(read.load(Ordering::SeqCst))),
        ));
        let (intent, summary, handle) = staged(&fixture, &context, kind, MemoFact::None, 0);
        assert!(inbox(&fixture).is_empty(), "the crash wrote no entry");
        assert!(durable_record(&context, &handle).is_none());
        time.fetch_add(60_000, Ordering::SeqCst);
        let retried_at = time.load(Ordering::SeqCst);
        let _driver = driver::install(driver::fixture_credential());
        let witness = confirm_staged(&fixture, &context, &summary, &handle)
            .await
            .expect("the retry's consent admits the canonical record");
        assert_eq!(witness.kind(), intent.approved_kind());
        let record = durable_record(&context, &handle).unwrap();
        assert_eq!(record.subject, *intent.digest().as_bytes());
        assert_eq!(
            (record.created_at_ms, record.rule_ttl_ms),
            (retried_at, 120_000),
            "the retry's entry keeps the decision's whole lifetime"
        );
        assert!(record.consent.is_some());
        assert_eq!(inbox(&fixture).len(), 1);
    }
}

/// Under integrated delivery, an intent entry that names the operation's
/// nonce, kind and signed clocks but carries another envelope as its
/// challenge refuses with `approval.attestation_invalid` before any
/// ceremony, and no consent commits.
#[tokio::test]
#[serial_test::serial]
async fn integrated_intent_entry_of_another_envelope_refuses() {
    let (fixture, context, _) = confirmation_fixture("canonical-integrated-challenge");
    let (intent, summary, handle) = staged(&fixture, &context, 0, MemoFact::None, 0);
    let parked = park_staged(&fixture, &context, &intent, &summary, &handle);
    let other = intent_envelope(
        &intent,
        context.profile().chain_id.network_passphrase(),
        90,
        100,
        clock_now().unwrap() / 1000 + 600,
    )
    .unwrap();
    let mut swapped = MainnetWriteSummary::from_envelope(&other, MainnetConsumer::CliPay, 500)
        .unwrap()
        .pending(parked.process_uid.clone(), 120_000)
        .unwrap();
    stellar_agent_network::operation_entry::stage_pending(&mut swapped, Some(&intent), 120_000)
        .unwrap();
    swapped.approval_nonce = parked.approval_nonce.clone();
    swapped.created_at_unix_ms = parked.created_at_unix_ms;
    swapped.expires_at_unix_ms = parked.expires_at_unix_ms;
    {
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        store.remove(&parked.approval_nonce).unwrap();
        store
            .insert(swapped.clone(), swapped.created_at_unix_ms)
            .unwrap();
    }
    let _enabled = stellar_agent_network::policy_state::approvals::ConsentEvidenceEnforcementGuard::new(
        context.profile_name(),
        intent.approved_kind(),
    );
    let _driver = driver::install(driver::fixture_credential());
    let refused = confirm_staged(&fixture, &context, &summary, &handle)
        .await
        .unwrap_err();
    assert_eq!(refused.code(), "approval.attestation_invalid", "{refused:?}");
    assert!(driver::ceremonies().is_empty(), "no presence");
    assert!(durable_record(&context, &handle).unwrap().consent.is_none());
}

#[tokio::test]
#[serial_test::serial]
async fn canonical_queued_consent_retains_the_exact_reference() {
    let (fixture, context, _) = confirmation_fixture("canonical-queued");
    let (_, summary, handle) = staged(&fixture, &context, 0, MemoFact::None, 0);
    let held = std::rc::Rc::new(std::cell::RefCell::new(None));
    let slot = held.clone();
    let profile = context.profile().clone();
    let name = context.profile_name().to_owned();
    let mut answer = driver::fixture_credential();
    let _driver = driver::install(Box::new(move |ceremony| {
        use stellar_agent_core::audit_log::writer::AuditWriterRegistry;
        AuditWriterRegistry::remove_for_test(&name);
        *slot.borrow_mut() = Some(
            AuditWriterRegistry::get_or_open_keyed(
                "canonical-server",
                &profile.audit_log_path,
                stellar_agent_network::keyring::keyed_audit_access(
                    &profile,
                    &name,
                    stellar_agent_core::audit_log::BindingCheck::Enforce,
                )
                .unwrap(),
            )
            .unwrap(),
        );
        answer(ceremony)
    }));
    confirm_staged(&fixture, &context, &summary, &handle)
        .await
        .unwrap();
    let payload = durable_record(&context, &handle)
        .unwrap()
        .consent
        .unwrap()
        .payload
        .unwrap();
    assert!(
        payload.outbox_row.is_some(),
        "canonical consent keeps queued reference"
    );
    assert_eq!(payload.row_provenance, None);
    let again = confirm_staged(&fixture, &context, &summary, &handle)
        .await
        .unwrap();
    assert_eq!(
        durable_record(&context, &handle)
            .unwrap()
            .consent
            .unwrap()
            .payload
            .unwrap(),
        payload,
        "recovery retains exact queued payload and reference"
    );
    assert_eq!(again.nonce(), inbox(&fixture)[0].approval_nonce);
    assert_eq!(consent_rows(&context), 0);
}

#[tokio::test]
#[serial_test::serial]
async fn canonical_consent_summary_and_completion() {
    // The renderer supports the full XDR memo range.
    let (fixture, context, _) = confirmation_fixture("canonical-wide-memo");
    let (wide, _, _) = staged(&fixture, &context, 0, MemoFact::Id(u64::MAX), 0);
    let mut rendered = Vec::new();
    crate::common::intent_summary::write(&wide, &mut rendered).unwrap();
    assert!(
        String::from_utf8(rendered)
            .unwrap()
            .contains(&format!("Memo: id {}", u64::MAX)),
        "full unsigned memo renders without narrowing"
    );
    drop(context);
    drop(fixture);
    for kind in 0..4 {
        for (memo_index, (memo, expected_memo)) in [
            (MemoFact::None, "none".to_owned()),
            (MemoFact::Text("café".into()), "text \"café\"".into()),
            (MemoFact::Id(u64::MAX), format!("id {}", u64::MAX)),
            (MemoFact::Hash([1; 32]), format!("hash {}", "01".repeat(32))),
            (
                MemoFact::Return([2; 32]),
                format!("return {}", "02".repeat(32)),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let (mut fixture, context, _) =
                confirmation_fixture(&format!("canonical-cli-{kind}-{memo_index}"));
            // The listed kinds take the integrated route.
            fixture.enforce_listed();
            let limit = if matches!(memo, MemoFact::None) {
                0
            } else {
                i64::MAX
            };
            let (intent, summary, handle) = staged(&fixture, &context, kind, memo, limit);
            clear_shown_summaries();
            let _driver = driver::install(driver::fixture_credential());
            let witness = confirm_staged(&fixture, &context, &summary, &handle)
                .await
                .expect("canonical direct consent succeeds");
            let rendered = shown_summaries().pop().unwrap();
            for expected in [
                format!("Memo: {expected_memo}"),
                "Fee at most: 500 stroops".into(),
                format!("Source: {}", intent.base().source()),
                "Chain: stellar:mainnet".into(),
                "Policy: ".into(),
            ] {
                assert!(
                    rendered.contains(&expected),
                    "canonical summary contains {expected}: {rendered}"
                );
            }
            let expected = match kind {
                0 => "Amount: 37 stroops",
                1 => "Starting balance: 53 stroops",
                2 if limit == 0 => "Limit: 0 stroops (removes the trustline)",
                2 => "Limit: unlimited",
                _ => "Amount: 71 stroops",
            };
            assert!(
                rendered.contains(expected),
                "lasting value summary: {rendered}"
            );
            if kind == 3 {
                assert!(
                    rendered.contains("Claimant: ")
                        && rendered.contains("Balance ID: B")
                        && rendered.contains("Asset: UsD:")
                );
            }
            for ephemeral in ["Sequence", "Fee: 100", "not known to the wallet"] {
                assert!(
                    !rendered.contains(ephemeral),
                    "canonical summary omits {ephemeral}"
                );
            }
            assert_eq!(witness.subject(), *intent.digest().as_bytes());
            assert_eq!(witness.subject_kind(), SubjectKind::IntentDigest);
            let record = durable_record(&context, &handle).unwrap();
            assert_eq!(
                record.consent.as_ref().unwrap().delivery.is_some(),
                stellar_agent_network::policy_state::approvals::consent_evidence_enforced(
                    intent.approved_kind()
                ),
                "kind {kind}: the listed kind publishes delivery"
            );
            assert_eq!(record.subject, *intent.digest().as_bytes());
            let consent = record.consent.expect("success follows durable consent");
            assert_eq!(
                consent.execution_expires_at_ms,
                consent.consent_at_ms + 120_000
            );
            let payload = consent.payload.unwrap();
            assert_eq!(payload.row_provenance, Some(RowProvenance::Written));
            assert_eq!(inbox(&fixture)[0].attestation_version, 6, "CLI persists V6");
            assert_eq!(
                payload.challenge_subject,
                Some(approval_subject_classic(&summary.envelope))
            );
        }
    }
    for kind in 0..4 {
        let (mut fixture, context, _) =
            confirmation_fixture(&format!("canonical-approve-{kind}"));
        // The listed kinds take the integrated route.
        fixture.enforce_listed();
        let (intent, summary, handle) = staged(&fixture, &context, kind, MemoFact::Id(17), 0);
        let entry = park_staged(&fixture, &context, &intent, &summary, &handle);
        let _driver = driver::install(driver::fixture_credential());
        crate::common::render::take_rendered_for_test();
        clear_shown_summaries();
        let code = crate::commands::approve::run::run(crate::commands::approve::run::RunArgs {
            id: Some(entry.approval_nonce.clone()),
            profile: Some(fixture.name().into()),
            yes: false,
            open_by_operator: false,
        })
        .await;
        let output = crate::common::render::take_rendered_for_test();
        assert_eq!(code, 0, "approve canonical stored subject: {output:?}");
        let rendered = shown_summaries().pop().expect("approve shows the intent");
        let lasting = match kind {
            0 => "Amount: 37 stroops",
            1 => "Starting balance: 53 stroops",
            2 => "Limit: 0 stroops (removes the trustline)",
            _ => "Amount: 71 stroops",
        };
        for expected in ["Fee at most: 500 stroops", "Memo: id 17", lasting] {
            assert!(
                rendered.contains(expected),
                "approve summary contains {expected}: {rendered}"
            );
        }
        for ephemeral in ["Sequence", "Fee: 100"] {
            assert!(
                !rendered.contains(ephemeral),
                "approve summary omits {ephemeral}: {rendered}"
            );
        }
        let consent = durable_record(&context, &handle).unwrap().consent;
        assert!(consent.is_some(), "approve success follows durable consent");
        assert_eq!(
            consent.unwrap().delivery.is_some(),
            stellar_agent_network::policy_state::approvals::consent_evidence_enforced(
                intent.approved_kind()
            ),
            "kind {kind}: the listed kind publishes delivery"
        );
        assert_eq!(inbox(&fixture)[0].attestation_version, 6);
    }
    // The entry of another operation presented under this operation's
    // durable link proves nothing for it.
    let (fixture, context, _) = confirmation_fixture("canonical-approve-swapped");
    let (intent, summary, handle) = staged(&fixture, &context, 0, MemoFact::None, 0);
    let entry = park_staged(&fixture, &context, &intent, &summary, &handle);
    let (other_intent, other_summary, other_handle) =
        staged_as(&fixture, &context, 0, MemoFact::None, 0, "canonical-other", 41);
    let other = park_staged(
        &fixture,
        &context,
        &other_intent,
        &other_summary,
        &other_handle,
    );
    {
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        store.remove(&entry.approval_nonce).unwrap();
        let mut swapped = other.clone();
        swapped.approval_nonce = entry.approval_nonce.clone();
        store
            .insert(swapped.clone(), swapped.created_at_unix_ms)
            .unwrap();
    }
    let _driver = driver::install(driver::fixture_credential());
    crate::common::render::take_rendered_for_test();
    let code = crate::commands::approve::run::run(crate::commands::approve::run::RunArgs {
        id: Some(entry.approval_nonce.clone()),
        profile: Some(fixture.name().into()),
        yes: false,
        open_by_operator: false,
    })
    .await;
    let output = crate::common::render::take_rendered_for_test();
    assert_eq!(code, 1, "{output:?}");
    assert_eq!(
        output.last().unwrap()["error"]["code"],
        "approval.wrong_kind",
        "a swapped durable link refuses"
    );
    assert!(driver::ceremonies().is_empty(), "no presence for a swap");
    assert!(durable_record(&context, &handle).unwrap().consent.is_none());
}

#[tokio::test]
#[serial_test::serial]
async fn canonical_consent_commit_preserves_provenance_and_order() {
    {
        let (fixture, context, _) = confirmation_fixture("canonical-row-gap");
        let (_, summary, handle) = staged(&fixture, &context, 0, MemoFact::None, 0);
        let _driver = driver::install(driver::fixture_credential());
        stellar_agent_core::approval::attest::consent_test_seam::on_written(
            &fixture.store_path(),
            || panic!("test crash after consent row"),
        );
        assert!(
            until_crash(confirm_staged(&fixture, &context, &summary, &handle))
                .await
                .is_err()
        );
        stellar_agent_core::audit_log::writer::AuditWriterRegistry::remove_for_test(
            context.profile_name(),
        );
        let before = inbox(&fixture).remove(0);
        assert!(before.attestation_blob_b64.is_none());
        assert!(durable_record(&context, &handle).unwrap().consent.is_none());
        let witness = confirm_staged(&fixture, &context, &summary, &handle)
            .await
            .unwrap();
        assert_eq!(
            witness.nonce(),
            before.approval_nonce,
            "row-only restart keeps nonce"
        );
        assert_eq!(
            consent_rows(&context),
            2,
            "row-only crash needs a second consent row"
        );
        assert_eq!(driver::ceremonies().len(), 2);
        assert!(durable_record(&context, &handle).unwrap().consent.is_some());
    }
    use stellar_agent_core::policy::state_lock::{lock_requests, window_lock_path};
    use stellar_agent_network::policy_state::store::commit_faults::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
        observe_commit,
    };
    for fault in [COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_AFTER_COUNTER] {
        let (fixture, context, _) = confirmation_fixture(&format!("canonical-restart-{fault}"));
        let (_, summary, handle) = staged(&fixture, &context, 0, MemoFact::None, 0);
        let _driver = driver::install(driver::fixture_credential());
        let path = fixture.store_path();
        let lock = window_lock_path(
            PersistedWindowStore::for_profile(fixture.name()).path(),
            &fixture.profile().policy_window_state_key_id,
        );
        let held = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = held.clone();
        let locks = lock_requests::observe(move |requested| {
            if requested == lock && PendingApprovalStore::open(path.clone()).is_err() {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let mut commits = 0;
        let observed = observe_commit(move |point| {
            if point == fault {
                commits += 1;
                if commits == 2 {
                    std::mem::forget(arm_accounting_fault(point));
                }
            }
        });
        let result = confirm_staged(&fixture, &context, &summary, &handle).await;
        assert!(result.is_err(), "failed consent commit exposes no witness");
        drop(observed);
        let entry = inbox(&fixture).remove(0);
        let receipt = entry
            .mainnet_presence
            .clone()
            .expect("attestation survives commit fault");
        let witness = confirm_staged(&fixture, &context, &summary, &handle)
            .await
            .unwrap();
        let record = durable_record(&context, &handle).unwrap();
        let consent = record.consent.unwrap();
        assert_eq!(witness.created_at_ms(), entry.created_at_unix_ms);
        assert_eq!(witness.expires_at_ms(), entry.expires_at_unix_ms);
        assert_eq!(
            witness.consent_at_ms(),
            receipt.verified_at_unix_ms(),
            "restart never retimes receipt"
        );
        assert_eq!(consent_rows(&context), 1, "recovery writes no consent row");
        assert_eq!(
            driver::ceremonies().len(),
            1,
            "recovery needs no second presence"
        );
        let expected = if fault == COMMIT_FAULT_AFTER_PREPARED {
            RowProvenance::Recovered
        } else {
            RowProvenance::Written
        };
        assert_eq!(consent.payload.unwrap().row_provenance, Some(expected));
        let bytes =
            std::fs::read(PersistedWindowStore::for_profile(fixture.name()).path()).unwrap();
        confirm_staged(&fixture, &context, &summary, &handle)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(PersistedWindowStore::for_profile(fixture.name()).path()).unwrap(),
            bytes,
            "repeat is byte-identical"
        );
        drop(locks);
        assert_eq!(
            held.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no window lock while inbox is held"
        );
    }
}

/// `approve revoke` after the waiting expiry of an attested, uncommitted
/// canonical approval writes `Revoked` and appends its audit row; the next
/// run of the command refuses `approval.revoked` and commits no consent.
#[tokio::test]
#[serial_test::serial]
async fn revoke_after_waiting_expiry_stops_the_recovered_consent() {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    let (fixture, context, _) = confirmation_fixture("late-revoke");
    let _unenforced =
        stellar_agent_network::policy_state::approvals::ConsentEvidenceDisableGuard::every_kind(
            fixture.name(),
        );
    let time = Arc::new(AtomicU64::new(clock_now().unwrap()));
    let read = time.clone();
    let _clock = stellar_agent_core::timefmt::test_clock::install(Arc::new(
        stellar_agent_core::timefmt::MockClock::new(move || Ok(read.load(Ordering::SeqCst))),
    ));
    let (intent, summary, handle) = staged(&fixture, &context, 0, MemoFact::None, 0);
    let entry = park_staged(&fixture, &context, &intent, &summary, &handle);
    // The operator consents one minute into the two-minute waiting window.
    time.fetch_add(60_000, Ordering::SeqCst);
    let policy = fixture.current_policy();
    let presence = fixture.intent_presence(&entry, &policy, &intent);
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    let OperatorRowSink::Writer(writer) =
        acquire_operator_row_sink(fixture.profile(), fixture.name()).unwrap()
    else {
        panic!("fixture writer")
    };
    // The inbox attestation persists; the durable consent commit does not
    // run, as after a crash between the two durable writes.
    stellar_agent_core::approval::attest_and_persist(
        &mut store,
        &entry,
        &stellar_agent_core::approval::mainnet_fixtures::ATTESTATION_KEY,
        &fixture.binding(),
        stellar_agent_core::approval::Surface::Cli,
        ConsentAudit::Writer(&mut writer.lock().unwrap()),
        stellar_agent_core::approval::ConsentAuthorization::Mainnet {
            presence,
            policy: &policy,
        },
        |_, _| unreachable!(),
    )
    .unwrap();
    drop(store);
    drop(writer);
    assert!(durable_record(&context, &handle).unwrap().consent.is_none());

    // The waiting window ends, and the owner revokes the approval.
    let revoked_at = entry.expires_at_unix_ms + 1;
    time.store(revoked_at, Ordering::SeqCst);
    crate::common::render::take_rendered_for_test();
    let code = crate::commands::approve::revoke::run(crate::commands::approve::revoke::RevokeArgs {
        id: entry.approval_nonce.clone(),
        profile: Some(fixture.name().into()),
        output: stellar_agent_core::envelope::OutputFormat::Json,
    })
    .await;
    let output = crate::common::render::take_rendered_for_test();
    assert_eq!(code, 0, "the revocation reports success: {output:?}");
    let view = &output.last().unwrap()["data"];
    assert_eq!(view["state"], "revoked", "{output:?}");
    assert_eq!(view["revoked_at_ms"], revoked_at, "{output:?}");
    let record = durable_record(&context, &handle).unwrap();
    assert_eq!(
        record.state,
        stellar_agent_network::policy_state::approvals::ApprovalState::Revoked,
        "the revocation writes the record"
    );
    let audit = std::fs::read_to_string(fixture.audit_path()).unwrap();
    let row: serde_json::Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
    assert_eq!(row["kind"], "approval_revoked");

    // The next run of the same command refuses, and no consent commits.
    let refused = confirm_staged(&fixture, &context, &summary, &handle).await;
    assert_eq!(
        refused.as_ref().map(drop).unwrap_err().code(),
        "approval.revoked",
        "{refused:?}"
    );
    let record = durable_record(&context, &handle).unwrap();
    assert!(record.consent.is_none(), "no consent commits after the revocation");
    assert_eq!(record.revoked_at_ms, Some(revoked_at));
}
