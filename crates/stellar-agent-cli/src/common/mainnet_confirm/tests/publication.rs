#[cfg(test)]
mod tests {
    use super::super::*;
    use stellar_agent_core::audit_log::{
        BindingCheck, MAX_EVIDENCE_ENTRIES, writer::AuditWriterRegistry,
    };
    use stellar_agent_network::policy_state::approvals::{
        ConsentDeliveryV1, ConsentEvidenceEnforcementGuard, UnreadableSiblingProfile,
    };
    use stellar_agent_network::policy_state::store::commit_faults::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
        observe_commit,
    };

    fn enabled(
        context: &MainnetWriteContext,
        kind: ApprovedKind,
    ) -> ConsentEvidenceEnforcementGuard {
        ConsentEvidenceEnforcementGuard::new(context.profile_name(), kind)
    }

    fn fill_scope(context: &MainnetWriteContext) {
        let profile = context.profile();
        let name = context.profile_name();
        let OperatorRowSink::Writer(writer) = acquire_operator_row_sink(profile, name).unwrap()
        else {
            panic!("writer")
        };
        writer
            .lock()
            .unwrap()
            .initialize_consent_evidence()
            .unwrap();
        crate::common::approval_fixture::seed_foreign_evidence(
            profile,
            name,
            0xee,
            MAX_EVIDENCE_ENTRIES,
        );
    }

    fn summary_for(envelope: &str, verb: usize) -> MainnetWriteSummary {
        use stellar_xdr::*;
        let TransactionEnvelope::Tx(mut tx) =
            TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap()
        else {
            unreachable!()
        };
        let consumer = match verb {
            0 => MainnetConsumer::CliPay,
            1 => {
                tx.tx.operations = vec![Operation {
                    source_account: None,
                    body: OperationBody::CreateAccount(CreateAccountOp {
                        destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([5; 32]))),
                        starting_balance: 10_000_000,
                    }),
                }]
                .try_into()
                .unwrap();
                MainnetConsumer::CliCreateAccount
            }
            2 => {
                tx.tx.operations = vec![Operation {
                    source_account: None,
                    body: OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                        balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([3; 32])),
                    }),
                }]
                .try_into()
                .unwrap();
                MainnetConsumer::CliClaim
            }
            _ => {
                return MainnetWriteSummary::from_envelope(
                    &trustline_envelope(envelope, *b"USD\0", b""),
                    MainnetConsumer::CliTrustline,
                    500,
                )
                .unwrap();
            }
        };
        MainnetWriteSummary::from_envelope(
            &TransactionEnvelope::Tx(tx)
                .to_xdr_base64(Limits::none())
                .unwrap(),
            consumer,
            500,
        )
        .unwrap()
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn confirmation_reserves_before_request() {
        for verb in 0..4 {
            let (fixture, context, envelope) =
                confirmation_fixture(&format!("publication-capacity-{verb}"));
            let summary = summary_for(&envelope, verb);
            let _enabled = enabled(&context, summary.kind);
            fill_scope(&context);
            clear_shown_summaries();
            let _presence = driver::install(driver::fixture_credential());
            let handle = prepared_operation(&context, "capacity", &summary.envelope);
            for mode in ["first-queued", "direct", "existing-queued"] {
                if mode != "direct" {
                    AuditWriterRegistry::remove_for_test(context.profile_name());
                    AuditWriterRegistry::get_or_open_keyed(
                        "capacity-holder",
                        &context.profile().audit_log_path,
                        stellar_agent_network::keyring::keyed_audit_access(
                            context.profile(),
                            context.profile_name(),
                            BindingCheck::Enforce,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                }
                let result = confirm_mainnet_write(
                    &summary,
                    ConfirmDecision::RequireApproval { ttl_ms: 300_000 },
                    &context,
                    &fixture.current_policy(),
                    &fixture.store_path(),
                    Some(&handle),
                    PolicyDecision::RequireApproval,
                    &governing(&context, &fixture.current_policy(), 300_000),
                )
                .await;
                let error = result.unwrap_err();
                if mode == "first-queued" {
                    assert!(error.to_string().contains("audit.writer_locked"));
                }
                assert_eq!(
                    error.code(),
                    if mode == "first-queued" {
                        "audit.chain_key_unavailable"
                    } else {
                        "approval.evidence_capacity"
                    },
                    "verb {verb}"
                );
                assert!(shown_summaries().is_empty(), "reservation precedes display");
                assert!(
                    inbox(&fixture).is_empty(),
                    "reservation precedes inbox insertion"
                );
                assert!(
                    driver::ceremonies().is_empty(),
                    "reservation precedes presence"
                );
                assert_eq!(
                    durable_record(&context, &handle).is_some(),
                    mode != "first-queued",
                    "refusal retains the committed pending identity"
                );
                AuditWriterRegistry::remove_for_test("capacity-holder");
            }
        }
        for mode in ["present", "missing", "edited"] {
            let missing = mode == "missing";
            let (fixture, context, envelope) =
                confirmation_fixture(&format!("publication-winner-{mode}"));
            let _enabled = enabled(&context, ApprovedKind::Payment);
            let handle = prepared_operation(&context, "winner", &envelope);
            let refused_presence = driver::install(Box::new(|_| {
                Err(WalletError::Approval(
                    ApprovalFailure::PresenceBrowserRequired,
                ))
            }));
            let error = durable(&fixture, &context, &envelope, &handle, 300_000)
                .await
                .unwrap_err();
            drop(refused_presence);
            assert_eq!(error.code(), "approval.presence_browser_required");
            let winner = durable_record(&context, &handle).unwrap();
            assert!(winner.consent.is_none());
            assert!(inbox(&fixture)[0].attestation_blob_b64.is_none());
            let outbox = consent_outbox(context.profile(), context.profile_name()).unwrap();
            let deadline = stellar_agent_core::audit_log::EvidenceReservation::deadline(
                winner.waiting_expires_at_ms,
                winner.rule_ttl_ms,
            )
            .unwrap();
            assert!(
                outbox
                    .reserve_evidence(winner.id, deadline, winner.created_at_ms)
                    .is_ok()
            );
            if missing {
                pending_store(&fixture).remove(&winner.nonce).unwrap();
            }
            if mode == "edited" {
                let mut store = pending_store(&fixture);
                let mut edited = store.get(&winner.nonce).unwrap().clone();
                edited.expires_at_unix_ms -= 1;
                store.remove(&winner.nonce).unwrap();
                let created = edited.created_at_unix_ms;
                store.insert(edited, created).unwrap();
            }
            let _presence = driver::install(driver::fixture_credential());
            let result = durable(&fixture, &context, &envelope, &handle, 900_000).await;
            if missing {
                assert_eq!(result.unwrap_err().code(), "approval.not_found");
                assert!(driver::ceremonies().is_empty());
                assert!(inbox(&fixture).is_empty());
            } else if mode == "edited" {
                assert_eq!(
                    result.unwrap_err().code(),
                    "approval.attestation_invalid",
                    "a linked entry whose signed facts changed refuses"
                );
                assert!(driver::ceremonies().is_empty());
            } else {
                assert_eq!(
                    result.unwrap().nonce(),
                    winner.nonce,
                    "the committed winner governs the retry"
                );
                let retained = durable_record(&context, &handle).unwrap();
                assert_eq!(retained.facts(), winner.facts());
                assert_eq!(driver::ceremonies().len(), 1);
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn producer_routes_share_the_kind_capability() {
        for verb in 0..4 {
            let (fixture, context, envelope) =
                confirmation_fixture(&format!("publication-selector-{verb}"));
            let summary = summary_for(&envelope, verb);
            let _enabled =
                ConsentEvidenceEnforcementGuard::new(context.profile_name(), summary.kind);
            clear_shown_summaries();
            let _presence = driver::install(driver::fixture_credential());
            let handle = prepared_operation(&context, "inventory", &summary.envelope);
            let unreadable = UnreadableSiblingProfile::plant();
            let result = confirm_mainnet_write(
                &summary,
                ConfirmDecision::RequireApproval { ttl_ms: 300_000 },
                &context,
                &fixture.current_policy(),
                &fixture.store_path(),
                Some(&handle),
                PolicyDecision::RequireApproval,
                &governing(&context, &fixture.current_policy(), 300_000),
            )
            .await;
            assert!(result.is_err(), "the enabled route must call admission");
            let error = result.unwrap_err();
            assert_eq!(
                error.code(),
                "audit.outbox_evidence_unusable",
                "the enabled route must call admission"
            );
            assert!(
                error
                    .to_string()
                    .contains("owner scope shared or unreadable")
            );
            assert!(inbox(&fixture).is_empty());
            assert!(shown_summaries().is_empty());
            assert!(driver::ceremonies().is_empty());
            assert_eq!(durable_record(&context, &handle), None);
            drop(unreadable);
            drop(_enabled);
            confirm_mainnet_write(
                &summary,
                ConfirmDecision::RequireApproval { ttl_ms: 300_000 },
                &context,
                &fixture.current_policy(),
                &fixture.store_path(),
                Some(&handle),
                PolicyDecision::RequireApproval,
                &governing(&context, &fixture.current_policy(), 300_000),
            )
            .await
            .unwrap();
            assert!(
                consent_outbox(context.profile(), context.profile_name())
                    .unwrap()
                    .evidence()
                    .unwrap()
                    .is_none(),
                "disabled producers never initialize evidence"
            );
        }
    }

    /// Switches ownership during presence, forcing the real queued sink.
    fn queued_presence(
        context: &MainnetWriteContext,
    ) -> crate::common::mainnet_presence::driver::DriverGuard {
        let mut answer = driver::fixture_credential();
        let profile = context.profile().clone();
        let name = context.profile_name().to_owned();
        let mut holding = false;
        driver::install(Box::new(move |ceremony| {
            if !holding {
                AuditWriterRegistry::remove_for_test(&name);
                AuditWriterRegistry::get_or_open_keyed(
                    "publication-holder",
                    &profile.audit_log_path,
                    stellar_agent_network::keyring::keyed_audit_access(
                        &profile,
                        &name,
                        BindingCheck::Enforce,
                    )
                    .unwrap(),
                )
                .unwrap();
                holding = true;
            }
            answer(ceremony)
        }))
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn confirmation_publication_precedes_witness() {
        for queued in [false, true] {
            for seam in [0, COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_AFTER_COUNTER] {
                let (fixture, context, envelope) =
                    confirmation_fixture(&format!("publication-witness-{queued}-{seam}"));
                let _enabled = enabled(&context, ApprovedKind::Payment);
                let _presence = if queued {
                    queued_presence(&context)
                } else {
                    driver::install(driver::fixture_credential())
                };
                let handle = prepared_operation(&context, "publication", &envelope);
                let mut commits = 0;
                let observed = observe_commit(move |point| {
                    if point == COMMIT_FAULT_AFTER_PREPARED {
                        commits += 1;
                    }
                    if commits == 2 && point == seam {
                        std::mem::forget(arm_accounting_fault(point));
                    }
                });
                let result = durable(&fixture, &context, &envelope, &handle, 300_000).await;
                drop(observed);
                assert!(
                    durable_record(&context, &handle).is_some(),
                    "the pending record survives: {result:?}"
                );
                let record = durable_record(&context, &handle).unwrap();
                if seam == COMMIT_FAULT_AFTER_PREPARED {
                    assert_eq!(
                        result.unwrap_err().code(),
                        "submission.record_unavailable",
                        "failed publication returns no witness"
                    );
                    assert!(record.consent.is_none());
                } else {
                    assert_eq!(result.unwrap().nonce(), record.nonce);
                    let consent = record.consent.unwrap();
                    assert_eq!(
                        consent.delivery.unwrap(),
                        if queued {
                            ConsentDeliveryV1::queued(record.id)
                        } else {
                            ConsentDeliveryV1::direct_anchored(record.id)
                        }
                    );
                    let reference = consent.payload.unwrap().outbox_row;
                    assert_eq!(reference.is_some(), queued);
                    if let Some(reference) = reference {
                        assert_eq!(consent_rows(&context), 0);
                        let writer = AuditWriterRegistry::get_or_open_keyed(
                            "publication-holder",
                            &context.profile().audit_log_path,
                            stellar_agent_network::keyring::keyed_audit_access(
                                context.profile(),
                                context.profile_name(),
                                BindingCheck::Enforce,
                            )
                            .unwrap(),
                        )
                        .unwrap();
                        let mut writer = writer.lock().unwrap();
                        writer.drain_outbox().unwrap();
                        assert_eq!(
                            consent_rows(&context),
                            1,
                            "acquisition or the explicit drain appends once"
                        );
                        assert!(
                            writer
                                .outbox_evidence()
                                .unwrap()
                                .unwrap()
                                .contains_delivered(&record.id, &reference),
                            "queued append binds the reserved identity"
                        );
                    }
                }
                AuditWriterRegistry::remove_for_test("publication-holder");
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn unpublished_consent_recovers_exact_delivery() {
        for queued in [false, true] {
            let (fixture, context, envelope) =
                confirmation_fixture(&format!("publication-recovery-{queued}"));
            let _enabled = enabled(&context, ApprovedKind::Payment);
            let _presence = if queued {
                queued_presence(&context)
            } else {
                driver::install(driver::fixture_credential())
            };
            let handle = prepared_operation(&context, "recovery", &envelope);
            crash_after_attestation(&fixture, &context, &envelope, &handle).await;
            let entry = inbox(&fixture).remove(0);
            let publication = stellar_agent_core::approval::verify_consent_publication(
                &entry,
                &stellar_agent_core::approval::mainnet_fixtures::ATTESTATION_KEY,
                &fixture.binding(),
            )
            .unwrap();
            let before_rows = consent_rows(&context);
            let witness = durable(&fixture, &context, &envelope, &handle, 300_000)
                .await
                .unwrap();
            let record = durable_record(&context, &handle).unwrap();
            let consent = record.consent.unwrap();
            assert_eq!(
                consent.payload.as_ref().unwrap().outbox_row.as_ref(),
                publication.outbox_row()
            );
            assert_eq!(
                consent.delivery.unwrap(),
                if queued {
                    ConsentDeliveryV1::queued(record.id)
                } else {
                    ConsentDeliveryV1::direct_anchored(record.id)
                },
                "recovery preserves the verified sink"
            );
            assert_eq!(
                consent.consent_at_ms,
                entry.mainnet_presence.unwrap().verified_at_unix_ms()
            );
            assert_eq!(witness.nonce(), entry.approval_nonce);
            assert_eq!(consent_rows(&context), before_rows);
            assert_eq!(
                driver::ceremonies().len(),
                1,
                "recovery performs no ceremony"
            );
            AuditWriterRegistry::remove_for_test("publication-holder");
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn unpublished_consent_requires_the_original_handoff() {
        let foreign = {
            let (fixture, context, envelope) = confirmation_fixture("publication-handoff-source");
            let _enabled = enabled(&context, ApprovedKind::Payment);
            let _presence = driver::install(driver::fixture_credential());
            let handle = prepared_operation(&context, "source", &envelope);
            durable(&fixture, &context, &envelope, &handle, 300_000)
                .await
                .unwrap();
            inbox(&fixture).remove(0).consent_publication
        };
        for mode in ["missing", "edited", "foreign"] {
            let (fixture, context, envelope) =
                confirmation_fixture(&format!("publication-handoff-{mode}"));
            let _enabled = enabled(&context, ApprovedKind::Payment);
            let _presence = driver::install(driver::fixture_credential());
            let handle = prepared_operation(&context, "handoff", &envelope);
            crash_after_attestation(&fixture, &context, &envelope, &handle).await;
            let authentic = inbox(&fixture).remove(0);
            let mut changed = authentic.clone();
            changed.consent_publication = if mode == "edited" {
                let mut raw = serde_json::to_value(&changed.consent_publication).unwrap();
                raw["tag"] = serde_json::json!("00".repeat(32));
                Some(serde_json::from_value(raw).unwrap())
            } else if mode == "foreign" {
                foreign.clone()
            } else {
                None
            };
            let replace = |entry: PendingApproval| {
                let mut store = pending_store(&fixture);
                store.remove(&entry.approval_nonce).unwrap();
                let created = entry.created_at_unix_ms;
                store.insert(entry, created).unwrap();
            };
            replace(changed);
            let refused = durable(&fixture, &context, &envelope, &handle, 300_000).await;
            assert!(
                refused.is_err(),
                "missing, edited or foreign handoffs never publish"
            );
            assert_eq!(refused.unwrap_err().code(), "approval.attestation_invalid");
            assert!(durable_record(&context, &handle).unwrap().consent.is_none());
            replace(authentic);
            durable(&fixture, &context, &envelope, &handle, 300_000)
                .await
                .unwrap();
            assert_eq!(driver::ceremonies().len(), 1);
            assert_eq!(consent_rows(&context), 1);
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn publication_requests_no_window_lock_while_inbox_held() {
        use stellar_agent_core::policy::state_lock::lock_requests;
        let (fixture, context, envelope) = confirmation_fixture("publication-locks");
        let _enabled = enabled(&context, ApprovedKind::Payment);
        let _presence = driver::install(driver::fixture_credential());
        let handle = prepared_operation(&context, "locks", &envelope);
        let OperatorRowSink::Writer(writer) =
            acquire_operator_row_sink(context.profile(), context.profile_name()).unwrap()
        else {
            panic!("writer")
        };
        let mut commits = 0;
        let committed = observe_commit(move |point| {
            if point == COMMIT_FAULT_AFTER_PREPARED {
                commits += 1;
                if commits == 2 {
                    assert!(
                        writer.try_lock().is_ok(),
                        "publication releases the writer before the window commit"
                    );
                }
            }
        });
        let pending = fixture.store_path();
        let observed = lock_requests::observe(move |_| {
            assert!(
                PendingApprovalStore::open(pending.clone()).is_ok(),
                "a window lock request must find the inbox free"
            );
        });
        durable(&fixture, &context, &envelope, &handle, 300_000)
            .await
            .unwrap();
        durable(&fixture, &context, &envelope, &handle, 300_000)
            .await
            .unwrap();
        drop(observed);
        drop(committed);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn reserved_row_only_crash_respects_existing_binding() {
        use stellar_agent_core::approval::attest::consent_test_seam;
        use stellar_agent_core::audit_log::outbox::test_seam;
        for state in ["queued", "delivered", "missing", "direct"] {
            let (fixture, context, envelope) =
                confirmation_fixture(&format!("publication-row-{state}"));
            let _enabled = enabled(&context, ApprovedKind::Payment);
            let _presence = if state == "direct" {
                driver::install(driver::fixture_credential())
            } else {
                queued_presence(&context)
            };
            let handle = prepared_operation(&context, "row-only", &envelope);
            let queue =
                stellar_agent_core::audit_log::outbox_path(&context.profile().audit_log_path);
            if state == "missing" {
                test_seam::arm_partial_write(&queue, 5);
                assert!(
                    durable(&fixture, &context, &envelope, &handle, 300_000)
                        .await
                        .is_err()
                );
                test_seam::disarm(&queue);
            } else {
                consent_test_seam::on_written(&fixture.store_path(), || panic!("stop after row"));
                assert!(
                    until_crash(durable(&fixture, &context, &envelope, &handle, 300_000))
                        .await
                        .is_err()
                );
            }
            AuditWriterRegistry::remove_for_test(context.profile_name());
            let record = durable_record(&context, &handle).unwrap();
            assert!(record.consent.is_none());
            assert!(
                inbox(&fixture)[0].consent_publication.is_none(),
                "a row alone supplies no grant"
            );
            if state == "delivered" {
                let writer = AuditWriterRegistry::get_or_open_keyed(
                    "publication-holder",
                    &context.profile().audit_log_path,
                    stellar_agent_network::keyring::keyed_audit_access(
                        context.profile(),
                        context.profile_name(),
                        BindingCheck::Enforce,
                    )
                    .unwrap(),
                )
                .unwrap();
                writer.lock().unwrap().drain_outbox().unwrap();
            }
            let result = durable(&fixture, &context, &envelope, &handle, 300_000).await;
            if matches!(state, "queued" | "delivered") {
                assert!(
                    result.is_err(),
                    "{state} evidence refuses a different consent row"
                );
                assert_eq!(result.unwrap_err().code(), "audit.outbox_evidence_unusable");
                assert!(inbox(&fixture)[0].attestation_blob_b64.is_none());
                assert!(durable_record(&context, &handle).unwrap().consent.is_none());
                assert_eq!(
                    stellar_agent_core::audit_log::inspect_outbox(
                        &context.profile().audit_log_path
                    )
                    .unwrap()
                    .pending,
                    usize::from(state == "queued"),
                    "the queued row stays present throughout the retry"
                );
                assert_eq!(consent_rows(&context), usize::from(state == "delivered"));
            } else {
                assert_eq!(
                    result.unwrap().nonce(),
                    record.nonce,
                    "permitted retry retains the admitted identity"
                );
            }
            AuditWriterRegistry::remove_for_test("publication-holder");
        }
    }
}
