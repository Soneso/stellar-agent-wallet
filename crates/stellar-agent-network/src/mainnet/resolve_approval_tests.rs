#[derive(Default)]
struct ApprovalRows;
impl crate::policy_state::OperationAudit for ApprovalRows {
    fn append(&mut self, _: stellar_agent_core::audit_log::AuditEntry) -> Result<(), String> {
        Ok(())
    }
}

fn current_record_fixture(soroban: bool) -> ResolverFixture {
    let mut f = if soroban {
        soroban_fixture()
    } else {
        ResolverFixture::new()
    };
    f.now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    f.clock.set(f.now);
    f.envelope = changed_envelope(&f, |tx| {
        tx.tx.cond = Preconditions::Time(stellar_xdr::TimeBounds {
            min_time: stellar_xdr::TimePoint(0),
            max_time: stellar_xdr::TimePoint(f.now / 1000 + 120),
        })
    });
    f
}

fn durable_record(f: &ResolverFixture, witness: &ApprovalWitness, consent: bool) -> OperationLink {
    use crate::policy_state::{
        ApprovalRecorder, BusinessId, ConsentPayload, ConsentRow, IntentSlot, OpenOutcome,
        OpenRequest, OperationKind, OperationRecorder, OperationTool, PendingApprovalFacts,
    };
    use base64::Engine as _;
    if let Some(link) = f.link(witness.nonce()) {
        assert!(consent, "the fixture records consent with the approval");
        return link;
    }
    let mut rows = ApprovalRows;
    let OpenOutcome::New(handle) = OperationRecorder::new(&f.window, &f.profile, &mut rows, "open")
        .open(&OpenRequest {
            business_id: BusinessId::parse(witness.nonce()).unwrap(),
            tool: OperationTool::CliPay,
            kind: OperationKind::Pay,
            intent: IntentSlot::Envelope {
                intent_digest: [1; 32],
                unsigned_envelope_sha256:
                    stellar_agent_core::approval::subject::approval_subject_classic(&f.envelope),
                max_time: 0,
            },
            envelope_xdr: Some(f.envelope.clone()),
            prepared_decision: None,
            rule_ttl_ms: Some(witness.expires_at_ms() - witness.created_at_ms()),
        })
        .unwrap()
    else {
        panic!("new operation")
    };
    let mut recorder = ApprovalRecorder::new(&f.window, &f.profile, &mut rows, "approval");
    let view = recorder
        .open_pending(
            handle.id(),
            &PendingApprovalFacts {
                nonce: witness.nonce().to_owned(),
                kind: witness.kind(),
                subject_kind: witness.subject_kind(),
                subject: witness.subject(),
                intent_digest: [1; 32],
                created_at_ms: witness.created_at_ms(),
                waiting_expires_at_ms: witness.expires_at_ms(),
                rule_ttl_ms: witness.expires_at_ms() - witness.created_at_ms(),
            },
            stellar_agent_core::audit_log::PolicyDecision::RequireApproval,
        )
        .unwrap();
    if consent {
        let path = f.dir.path().join(format!(
            "{}-{}.toml",
            witness.nonce(),
            stellar_agent_core::hex::encode(&witness.subject())
        ));
        let inbox = stellar_agent_core::approval::PendingApprovalStore::open(path).unwrap();
        let entry = inbox.get(witness.nonce()).unwrap();
        let blob = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(entry.attestation_blob_b64.as_ref().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        recorder
            .record_consent(
                view.record.id,
                witness,
                &ConsentPayload::new(
                    blob,
                    entry.mainnet_presence.clone().unwrap(),
                    entry.process_uid.clone(),
                    ConsentRow::Written,
                ),
            )
            .unwrap();
    }
    OperationLink {
        operation_id: handle.id(),
        attempt_index: 1,
    }
}

/// The first attempt of a second open operation, which names no record.
fn other_operation(f: &ResolverFixture) -> OperationLink {
    use crate::policy_state::{
        BusinessId, IntentSlot, OpenOutcome, OpenRequest, OperationKind, OperationRecorder,
        OperationTool,
    };
    let OpenOutcome::New(handle) =
        OperationRecorder::new(&f.window, &f.profile, &mut ApprovalRows, "open")
            .open(&OpenRequest {
                business_id: BusinessId::parse("another-operation").unwrap(),
                tool: OperationTool::CliPay,
                kind: OperationKind::Pay,
                intent: IntentSlot::Envelope {
                    intent_digest: [2; 32],
                    unsigned_envelope_sha256: [2; 32],
                    max_time: 0,
                },
                envelope_xdr: None,
                prepared_decision: None,
                rule_ttl_ms: Some(600_000),
            })
            .unwrap()
    else {
        panic!("new operation")
    };
    OperationLink {
        operation_id: handle.id(),
        attempt_index: 1,
    }
}

fn record_facts(
    f: &ResolverFixture,
    witness: &ApprovalWitness,
) -> stellar_agent_core::approval::witness::ApprovalFacts {
    crate::policy_state::ApprovalStatus::new(&f.window, &f.profile)
        .facts_by_nonce(witness.nonce())
        .unwrap()
        .unwrap()
}

fn revoke_record(f: &ResolverFixture, witness: &ApprovalWitness) {
    let id = record_facts(f, witness).record().id;
    crate::policy_state::ApprovalRecorder::new(&f.window, &f.profile, &mut ApprovalRows, "revoke")
        .revoke(id)
        .unwrap();
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn consumed_resolver_refusals_precede_expiry_for_another_operation() {
    use crate::policy_state::{OperationRecorder, OperationState, TransitionEvidence};
    for case in ["expired", "released", "early"] {
        let f = current_record_fixture(false);
        let witness = f.approval(&f.envelope, f.now, 600_000);
        let link = durable_record(&f, &witness, true);
        f.clock.set(witness.consent_at_ms());
        let server = f.server().await;
        let rpc_url = url::Url::parse(&f.profile.rpc_url).unwrap();
        let context = f.context_with_routes(&[(rpc_url.host_str().unwrap(), &server.uri())]);
        let client = context.primary_client().unwrap();
        let authority = f.approval_authority(&witness);
        let mut req = request(&f, &context, &client, &authority);
        req.operation = Some(link);
        resolve_tx_sign(req).await.unwrap();
        match case {
            "expired" => f.clock.set(witness.expires_at_ms()),
            "early" => f.clock.set(witness.consent_at_ms() - 1),
            _ => {
                OperationRecorder::new(&f.window, &f.profile, &mut ApprovalRows, "close")
                    .transition(
                        link.operation_id,
                        None,
                        OperationState::Expired,
                        &TransitionEvidence::default(),
                    )
                    .unwrap();
                assert!(
                    record_facts(&f, &witness)
                        .record()
                        .consent
                        .as_ref()
                        .unwrap()
                        .payload
                        .is_none()
                );
            }
        }
        let facts = record_facts(&f, &witness);
        let now = super::super::clock::now_ms().unwrap();
        assert_eq!(
            enabled::check_approval_facts(Some(&facts), &witness, None, now),
            Err(MainnetAuthorizationError::Refused(P::ApprovalNonceReused)),
            "consumed nonce reuse precedes expiry: {case}"
        );
        assert_eq!(
            enabled::check_approval_facts(
                Some(&facts),
                &witness,
                Some(link.operation_id),
                now
            ),
            Err(MainnetAuthorizationError::Refused(P::ApprovalExpired)),
            "the same operation keeps its expiry refusal: {case}"
        );
        let envelope = changed_envelope(&f, |tx| {
            tx.tx.cond = Preconditions::Time(stellar_xdr::TimeBounds {
                min_time: stellar_xdr::TimePoint(0),
                max_time: stellar_xdr::TimePoint(now / 1000 + 120),
            })
        });
        let mut req = request(&f, &context, &client, &authority);
        req.operation = None;
        req.unsigned_envelope_xdr = &envelope;
        let before = f.wire();
        assert_refused(
            resolve_tx_sign(req).await,
            P::ApprovalNonceReused,
            &f,
            &before,
        );
    }
}

#[test]
#[serial_test::serial]
fn durable_envelope_authority_keeps_signed_expiry() {
    let f = current_record_fixture(false);
    let witness = f.approval(&f.envelope, f.now - 60_000, 300_000);
    durable_record(&f, &witness, true);
    let facts = record_facts(&f, &witness);
    let payload = facts
        .record()
        .consent
        .as_ref()
        .unwrap()
        .payload
        .as_ref()
        .unwrap();
    let durable = stellar_agent_core::approval::witness::verify_durable_approval(
        Some(&facts),
        &payload.attestation,
        &f.profile,
        f.context.profile_name(),
        &stellar_agent_core::approval::witness::ApprovalExpectation {
            kind: witness.kind(),
            subject: witness.subject(),
        },
        &f.policy,
        witness.consent_at_ms(),
    )
    .unwrap();
    assert!(
        durable.execution_expires_at_ms() > durable.expires_at_ms(),
        "fixture separates execution and signed expiry"
    );
    let decision = f.captured_decision();
    let MainnetAuthority::Approval(authority) =
        MainnetAuthority::from_decision(&decision, Some(&durable)).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        authority.expires_at_ms(),
        durable.expires_at_ms(),
        "EnvelopeText authority uses signed expiry"
    );
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn resolver_state_matrix() {
    for soroban in [false, true] {
        for case in [
            "live",
            "waiting",
            "waiting-ended",
            "revoked",
            "revoked-expired",
            "expired",
            "other-operation",
            "consumed",
        ] {
            let f = current_record_fixture(soroban);
            f.record_approvals.set(!case.starts_with("waiting"));
            let root = root(&f);
            let intent = intent(&root);
            let witness = if soroban {
                intent_approval(&f, &root, None)
            } else {
                f.approval(&f.envelope, f.now, 600_000)
            };
            let link = durable_record(&f, &witness, !case.starts_with("waiting"));
            let at = witness.consent_at_ms();
            f.clock.set(at);
            if case.starts_with("revoked") {
                revoke_record(&f, &witness);
            }
            if matches!(case, "expired" | "waiting-ended" | "revoked-expired") {
                f.clock.set(witness.expires_at_ms());
            }
            let expected = match case {
                "waiting" => Some(P::ApprovalConsentMissing),
                "revoked" | "revoked-expired" => Some(P::ApprovalRevoked),
                "expired" | "waiting-ended" => Some(P::ApprovalExpired),
                "other-operation" => Some(P::ApprovalNonceReused),
                _ => None,
            };
            let operation = if case == "other-operation" {
                Some(other_operation(&f))
            } else {
                Some(link)
            };
            let facts = record_facts(&f, &witness);
            assert_eq!(
                enabled::check_approval_facts(
                    Some(&facts),
                    &witness,
                    operation.map(|link| link.operation_id),
                    super::super::clock::now_ms().unwrap()
                ),
                expected.map_or(Ok(()), |p| Err(MainnetAuthorizationError::Refused(p))),
                "facts state {case}"
            );
            let server = f.server().await;
            let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
            let client = context.primary_client().unwrap();
            let authority = f.approval_authority(&witness);
            // Classic envelope deadlines precede approval checks. Keep that deadline live
            // while preserving the witness's original subject for the state refusal.
            let envelope = if matches!(case, "expired" | "waiting-ended" | "revoked-expired") {
                changed_envelope(&f, |tx| {
                    tx.tx.cond = Preconditions::Time(stellar_xdr::TimeBounds {
                        min_time: stellar_xdr::TimePoint(0),
                        max_time: stellar_xdr::TimePoint(witness.expires_at_ms() / 1000 + 120),
                    })
                })
            } else {
                f.envelope.clone()
            };
            let resolve = || async {
                if soroban {
                    let mut req = intent_request(&f, &context, &client, &intent, &authority);
                    req.operation = operation;
                    resolve_soroban_intent(req).await.map(|_| ())
                } else {
                    let mut req = request(&f, &context, &client, &authority);
                    req.unsigned_envelope_xdr = &envelope;
                    req.operation = operation;
                    resolve_tx_sign(req).await.map(|_| ())
                }
            };
            let before = f.wire();
            assert_eq!(
                resolve().await,
                expected.map_or(Ok(()), |p| Err(MainnetAuthorizationError::Refused(p))),
                "resolver state {case}, soroban {soroban}"
            );
            if expected.is_some() {
                assert_eq!(f.wire(), before, "resolver refusal writes nothing");
            }
            if case == "consumed" {
                let facts = record_facts(&f, &witness);
                assert!(
                    enabled::check_approval_facts(
                        Some(&facts),
                        &witness,
                        Some(link.operation_id),
                        at
                    )
                    .is_ok()
                );
                assert_eq!(
                    resolve().await,
                    Err(MainnetAuthorizationError::Refused(P::DuplicateOpen))
                );
                revoke_record(&f, &witness);
                assert_eq!(
                    resolve().await,
                    Err(MainnetAuthorizationError::Refused(P::ApprovalRevoked)),
                    "revocation after resolver admission is decisive"
                );
            }
        }
    }
}

#[test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
fn facts_comparisons_refuse_alone() {
    use stellar_agent_core::approval::witness::ApprovalFacts;
    let f = current_record_fixture(false);
    let witness = f.approval(&f.envelope, f.now, 600_000);
    let link = durable_record(&f, &witness, true);
    f.clock.set(witness.consent_at_ms());
    let facts = record_facts(&f, &witness);
    let other = f.approval(&f.envelope, f.now, 600_000);
    let other_link = durable_record(&f, &other, true);
    f.clock.set(other.consent_at_ms());
    assert_eq!(
        enabled::check_approval_facts(
            Some(&record_facts(&f, &other)),
            &witness,
            Some(other_link.operation_id),
            other.consent_at_ms()
        ),
        Err(MainnetAuthorizationError::Refused(P::ApprovalNonce)),
        "isolated nonce comparison with another authenticated record"
    );
    for (case, expected) in [
        ("kind", P::ApprovalKindMismatch),
        ("subject", P::ApprovalSubjectMismatch),
        ("created", P::ApprovalExpiry),
        ("expiry", P::ApprovalExpiry),
        ("policy", P::ApprovalPolicyMismatch),
        ("receipt", P::ApprovalReceiptMismatch),
    ] {
        // The facts constructor isolates inconsistent retained facts that storage or
        // the proof producer refuses before the resolver comparison.
        let mut record = facts.record().clone();
        match case {
            "kind" => record.kind = ApprovedKind::Claim,
            "subject" => record.subject[0] ^= 1,
            "created" => record.created_at_ms -= 1,
            "expiry" => record.expires_at_ms += 1,
            "receipt" => record.consent.as_mut().unwrap().receipt_sha256[0] ^= 1,
            "policy" => {
                let payload = record.consent.as_mut().unwrap().payload.as_mut().unwrap();
                let mut value = serde_json::to_value(&payload.receipt).unwrap();
                value["policy_digest_hex"] = serde_json::json!("ab".repeat(32));
                payload.receipt = serde_json::from_value(value).unwrap();
            }
            _ => unreachable!(),
        }
        let changed = ApprovalFacts::new(facts.profile().to_owned(), facts.chain(), record);
        assert_eq!(
            enabled::check_approval_facts(
                Some(&changed),
                &witness,
                Some(link.operation_id),
                witness.consent_at_ms()
            ),
            Err(MainnetAuthorizationError::Refused(expected)),
            "isolated {case} comparison"
        );
    }
    let uppercase = witness.nonce().to_ascii_uppercase();
    assert_eq!(
        crate::policy_state::ApprovalStatus::new(&f.window, &f.profile)
            .facts_by_nonce(&uppercase)
            .unwrap()
            .is_some(),
        uppercase == witness.nonce(),
        "nonce lookup is case sensitive"
    );
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn legacy_envelope_keeps_its_rule_bound() {
    let f = current_record_fixture(false);
    let witness = f.approval(&f.envelope, f.now, 601_000);
    let link = durable_record(&f, &witness, true);
    f.clock.set(witness.consent_at_ms());
    let server = f.server().await;
    let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
    let client = context.primary_client().unwrap();
    let authority = f.approval_authority(&witness);
    let mut req = request(&f, &context, &client, &authority);
    req.operation = Some(link);
    let before = f.wire();
    assert_refused(
        resolve_tx_sign(req).await,
        P::ApprovalTtlExceedsRule,
        &f,
        &before,
    );
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn gates_never_fall_back_to_the_inbox() {
    let f = current_record_fixture(false);
    let witness = f.approval(&f.envelope, f.now, 600_000);
    let link = durable_record(&f, &witness, true);
    f.clock.set(witness.consent_at_ms());
    let before = f.wire();
    let mut bytes = std::fs::read(f.window.path()).unwrap();
    bytes[0] ^= 1;
    std::fs::write(f.window.path(), &bytes).unwrap();
    let server = f.server().await;
    let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
    let client = context.primary_client().unwrap();
    let authority = f.approval_authority(&witness);
    let mut req = request(&f, &context, &client, &authority);
    req.operation = Some(link);
    assert_refused(resolve_tx_sign(req).await, P::StoreUnavailable, &f, &before);
    use stellar_agent_core::policy::{
        McpToolRegistration, NoopPolicyEngine, PolicyEngine as _, ToolDescriptor, ToolValueKind,
    };
    let descriptor = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_balances",
        destructive_hint: false,
        read_only_hint: true,
        chain_id_required: true,
        value_kind: ToolValueKind::ReadOnly,
    });
    let evaluation = NoopPolicyEngine
        .evaluate_full(
            &descriptor,
            &serde_json::Value::Null,
            &f.profile,
            None,
            None,
            None,
            None,
            None,
            witness.consent_at_ms(),
        )
        .unwrap();
    assert_eq!(
        enabled::final_checks(
            &context,
            &f.policy,
            &authority,
            witness.subject(),
            witness.kind(),
            stellar_agent_core::approval::store::governing_ttl_ms(&evaluation),
            &f.audit(),
            &f.signer,
            witness.consent_at_ms(),
            &f.window,
            Some(link)
        ),
        Err(MainnetAuthorizationError::Refused(P::StoreUnavailable)),
        "facts read failure refuses before mint"
    );
    // A valid admitting inbox entry beside a readable store without its
    // record refuses as missing.
    drop(f);
    let f = current_record_fixture(false);
    f.record_approvals.set(false);
    let witness = f.approval(&f.envelope, f.now, 600_000);
    let link = other_operation(&f);
    let server = f.server().await;
    let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
    let client = context.primary_client().unwrap();
    let authority = f.approval_authority(&witness);
    let mut req = request(&f, &context, &client, &authority);
    req.operation = Some(link);
    let before = f.wire();
    assert_refused(resolve_tx_sign(req).await, P::ApprovalNotFound, &f, &before);
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn released_payload_refuses_as_expired() {
    use crate::policy_state::{
        ApprovalStatus, OperationRecorder, OperationState, TransitionEvidence,
    };
    let f = current_record_fixture(false);
    let witness = f.approval(&f.envelope, f.now, 600_000);
    let link = durable_record(&f, &witness, true);
    f.clock.set(witness.consent_at_ms());
    OperationRecorder::new(&f.window, &f.profile, &mut ApprovalRows, "close")
        .transition(
            link.operation_id,
            None,
            OperationState::Expired,
            &TransitionEvidence::default(),
        )
        .unwrap();
    let facts = record_facts(&f, &witness);
    assert!(facts.record().consent.as_ref().unwrap().payload.is_none());
    assert_eq!(
        enabled::check_approval_facts(
            Some(&facts),
            &witness,
            Some(link.operation_id),
            witness.consent_at_ms()
        ),
        Err(MainnetAuthorizationError::Refused(P::ApprovalExpired)),
        "released payload refuses at the facts check"
    );
    let server = f.server().await;
    let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
    let client = context.primary_client().unwrap();
    let authority = f.approval_authority(&witness);
    let mut req = request(&f, &context, &client, &authority);
    req.operation = Some(link);
    let before = f.wire();
    assert_refused(resolve_tx_sign(req).await, P::ApprovalExpired, &f, &before);
    assert!(
        ApprovalStatus::new(&f.window, &f.profile)
            .find_by_nonce(witness.nonce())
            .unwrap()
            .is_some(),
        "released records remain inspectable"
    );
    revoke_record(&f, &witness);
    assert_eq!(
        enabled::check_approval_facts(
            Some(&record_facts(&f, &witness)),
            &witness,
            Some(link.operation_id),
            witness.consent_at_ms()
        ),
        Err(MainnetAuthorizationError::Refused(P::ApprovalRevoked))
    );
    let other = f.approval(&f.envelope, f.now, 600_000);
    let other_link = durable_record(&f, &other, true);
    f.clock.set(other.consent_at_ms());
    let authority = f.approval_authority(&other);
    let mut req = request(&f, &context, &client, &authority);
    req.operation = Some(other_link);
    assert!(
        resolve_tx_sign(req).await.is_ok(),
        "another record in the same file still authorizes"
    );
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn policy_path_reads_no_record() {
    let f = ResolverFixture::new();
    let server = f.server().await;
    let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
    let client = context.primary_client().unwrap();
    let authority = policy_authority(&f, AuthorityScope::Classic, f.now, 30_000);
    let audit = f.audit().fresh_facts().unwrap();
    let auth = resolve_tx_sign(request(&f, &context, &client, &authority))
        .await
        .unwrap();
    assert_eq!(
        crate::policy_state::approvals::facade_calls::count(f.window.path()),
        0,
        "Policy resolution reads no approval record"
    );
    assert_eq!(auth.expires_at_ms(), f.now + 30_000);
    assert!(
        auth.check_audit(&audit.log_path_digest, audit.anchored_count, &audit.segment)
            .is_ok()
    );
    let record = &f.wire()["authorizations"][0];
    assert_eq!(
        record["policy_authority"]["governing_until_ms"],
        f.now + 30_000
    );
    assert!(record.get("approval_nonce").is_none());
}

#[test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
fn header_preserves_bindings_and_bounds() {
    use super::super::digest::BindingFacts;
    use crate::policy_state::{DomainBinding, MintAuthority, MintRequest};
    let f = current_record_fixture(false);
    let witness = f.approval(&f.envelope, f.now, 600_000);
    let link = durable_record(&f, &witness, true);
    f.clock.set(witness.consent_at_ms());
    let client = f.context.primary_client().unwrap();
    let endpoint = crate::EndpointIdentity::checked(
        Some(f.profile.chain_id),
        29,
        f.context.authority().to_owned(),
        client.id(),
    );
    let audit = f.audit();
    let facts = BindingFacts {
        endpoint: Some(endpoint.fact_digest()),
        signer: f.signer.fact_digest(),
        policy: f.policy.fact_digest(),
        enablement: f.enablement.fact_digest(),
        witness: None,
        reservation: None,
        authority: witness.fact_digest(),
        audit: audit.fact_digest(),
        restriction: None,
    };
    let request = MintRequest {
        intent_digest: None,
        predecessor: None,
        approval_operation: None,
        chain: f.profile.chain_id,
        binding: DomainBinding::Transaction {
            unsigned_envelope_sha256: witness.subject(),
            tx_hash: [2; 32],
            source: f.source.source().to_owned(),
            sequence: 2,
        },
        consumer: MainnetConsumer::CliPay,
        policy_sequence: f.policy.sequence(),
        policy_digest: f.policy.digest(),
        authority: MintAuthority::Approval {
            nonce: witness.nonce().to_owned(),
            expires_at_ms: u64::MAX,
        },
        chain_deadline_ms: None,
        restriction_end_ms: None,
        authorization_ttl_ms: 2_000_000,
        bindings: facts,
        holds: vec![],
        parent: None,
        operation: Some(link),
        floor: None,
        native_reservation: None,
    };
    let minted = f.window.mint_authorization(&f.profile, &request).unwrap();
    let id = minted.id;
    let header = super::super::mint::header(
        &f.context,
        &f.window,
        &request,
        minted,
        &endpoint,
        &f.signer,
        &f.enablement,
        None,
        audit,
    );
    let mut digest = Sha256::new();
    digest.update(b"stellar-agent-authz-bindings:v1");
    digest.update([1]);
    digest.update(endpoint.fact_digest());
    digest.update(f.signer.fact_digest());
    digest.update(f.policy.fact_digest());
    digest.update(f.enablement.fact_digest());
    digest.update([0, 0]);
    digest.update(witness.fact_digest());
    digest.update(header.audit.fact_digest());
    let digest: [u8; 32] = digest.finalize().into();
    assert_eq!(
        header.bindings_digest, digest,
        "header binds the independently ordered proofs"
    );
    assert_eq!(
        header.expires_at_ms,
        witness.expires_at_ms(),
        "header keeps the durable envelope cap"
    );
    assert_eq!(header.issued_at_ms, witness.consent_at_ms());
    assert_eq!(header.id, id);
    assert_eq!(header.policy.digest, f.policy.digest());
    assert_eq!(header.signer.public_key, f.signer.public_key());
    let bytes = std::fs::read(f.window.path()).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes[32..]).unwrap();
    let record = &value["authorizations"][0];
    assert_eq!(
        record["bindings_digest"],
        stellar_agent_core::hex::encode(&digest)
    );
    assert_eq!(record["expires_ms"], header.expires_at_ms);
    assert_eq!(record["operation"], serde_json::to_value(link).unwrap());
    assert_eq!(record["approval_nonce"], witness.nonce());
}

#[test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
fn intent_restart_seam() {
    use crate::policy_state::{
        ApprovalStatus, AttemptAuthorization, AttemptEnvelope, AttemptRequest, BusinessId,
        DomainBinding, LookupOutcome, MintAuthority, MintRequest, OperationRecorder,
    };
    use stellar_agent_core::policy::{
        Decision, McpToolRegistration, NoopPolicyEngine, PolicyEngine as _, ToolDescriptor,
        ToolValueKind,
    };
    let fx = crate::policy_state::approvals::durable_tests::IntentFx::new(300_000);
    let now = fx.facts.record().expires_at_ms + 1;
    fx.clock.set(now);
    let decision = fx.decision(Decision::Allow, 1_000, now);
    let witness = fx.verify(&fx.facts, &decision, now).unwrap();
    let context = crate::NetworkContext::mainnet_write(
        fx.fixture.profile(),
        &stellar_agent_core::profile::name::ResolvedProfileName::from_flag(fx.fixture.name()),
        &fx.fixture.home().join("profiles"),
        crate::MainnetEndpointFlags::default(),
    )
    .unwrap();
    let descriptor = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_balances",
        destructive_hint: false,
        read_only_hint: true,
        chain_id_required: true,
        value_kind: ToolValueKind::ReadOnly,
    });
    let evaluation = NoopPolicyEngine
        .evaluate_full(
            &descriptor,
            &serde_json::Value::Null,
            fx.fixture.profile(),
            None,
            None,
            None,
            None,
            None,
            now,
        )
        .unwrap();
    let check = enabled::approval_checks(
        &context,
        &fx.policy,
        &witness,
        witness.subject(),
        witness.kind(),
        stellar_agent_core::approval::store::governing_ttl_ms(&evaluation),
        now,
    );
    assert!(
        check.is_ok(),
        "intent witness survives waiting expiry under its execution bound"
    );
    let store = PersistedWindowStore::at_path(
        stellar_agent_core::profile::schema::default_policy_window_state_path_for(
            fx.fixture.name(),
        ),
    );
    let facts = ApprovalStatus::new(&store, fx.fixture.profile())
        .facts_by_nonce(witness.nonce())
        .unwrap()
        .unwrap();
    let mut rows = ApprovalRows;
    let mut recorder = OperationRecorder::new(&store, fx.fixture.profile(), &mut rows, "restart");
    // The raw mint isolates the retained-record execution bound from resolution.
    let link = OperationLink {
        operation_id: crate::policy_state::OperationId::from_bytes(facts.record().operation_id),
        attempt_index: 1,
    };
    assert!(
        enabled::check_approval_facts(
            Some(&facts),
            &witness,
            Some(link.operation_id),
            now
        )
        .is_ok()
    );
    let mint = MintRequest {
        intent_digest: Some(facts.record().intent_digest),
        predecessor: None,
        approval_operation: None,
        chain: fx.fixture.profile().chain_id,
        binding: DomainBinding::Transaction {
            unsigned_envelope_sha256: [1; 32],
            tx_hash: [2; 32],
            source: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".to_owned(),
            sequence: 1,
        },
        consumer: MainnetConsumer::CliPay,
        policy_sequence: fx.policy.sequence(),
        policy_digest: fx.policy.digest(),
        authority: MintAuthority::Approval {
            nonce: witness.nonce().to_owned(),
            expires_at_ms: witness.execution_expires_at_ms(),
        },
        chain_deadline_ms: None,
        restriction_end_ms: None,
        authorization_ttl_ms: 120_000,
        bindings: super::super::digest::BindingFacts {
            endpoint: None,
            signer: [1; 32],
            policy: [2; 32],
            enablement: [3; 32],
            witness: None,
            reservation: None,
            authority: [4; 32],
            audit: [5; 32],
            restriction: None,
        },
        holds: vec![],
        parent: None,
        operation: None,
        floor: None,
        native_reservation: None,
    };
    let mut first = mint.clone();
    first.operation = Some(link);
    first.authorization_ttl_ms = 1;
    fx.clock.set(witness.consent_at_ms());
    let mut without_digest = first.clone();
    without_digest.intent_digest = None;
    // Only the attempt's begin mints for a canonical operation: the public
    // mint refuses with and without the intent digest and writes nothing.
    for raw in [&without_digest, &first] {
        let before = std::fs::read(store.path()).unwrap();
        assert!(
            matches!(
                store.mint_authorization(fx.fixture.profile(), raw),
                Err(crate::policy_state::WindowStoreError::AuthorizationRefused {
                    precondition: P::IntentMismatch,
                })
            ),
            "a public canonical mint refuses IntentMismatch (digest {:?})",
            raw.intent_digest.is_some()
        );
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
    }
    fx.clock.set(now);
    let Some(LookupOutcome::Resumable(handle)) = recorder
        .lookup(&BusinessId::parse("durable-intent").unwrap())
        .unwrap()
    else {
        panic!("resumable intent")
    };
    let result = recorder.begin_attempt(
        &handle,
        &AttemptRequest {
            envelope: Some(AttemptEnvelope {
                xdr: "AAAA".to_owned(),
                unsigned_envelope_sha256: [1; 32],
            }),
            authorization: AttemptAuthorization::Mint(Box::new(mint)),
            send_by_ms: u64::MAX,
        },
    );
    assert!(result.is_ok(), "raw operation mint survives waiting expiry");
}

/// The path of the inbox store [`ResolverFixture::attested`] consents `witness` in.
fn inbox_path(f: &ResolverFixture, witness: &ApprovalWitness) -> std::path::PathBuf {
    f.dir.path().join(format!(
        "{}-{}.toml",
        witness.nonce(),
        stellar_agent_core::hex::encode(&witness.subject())
    ))
}

/// The x402 parts every message and authenticated intent test shares.
struct X402Parts {
    root: stellar_xdr::SorobanAuthorizedInvocation,
    message: super::super::message::MessageFacts,
}

fn x402_parts(f: &ResolverFixture, content: u8) -> X402Parts {
    X402Parts {
        root: x402_root(f),
        message: message_facts([content; 32], EPHEMERAL),
    }
}

/// Resolves a message signing under `witness` with the approval identity
/// `identity`.
fn message_under(
    f: &ResolverFixture,
    parts: &X402Parts,
    witness: &ApprovalWitness,
    identity: Option<crate::policy_state::OperationId>,
) -> Result<MainnetMessageSignAuthorization, MainnetAuthorizationError> {
    let intent = x402_intent(&parts.root, MainnetConsumer::X402Authenticated);
    let authority = f.approval_authority(witness);
    let mut req = f.message_request(&intent, &parts.message, &authority);
    req.approval_operation = identity;
    resolve_message_sign(req)
}

/// Resolves an authenticated intent under `witness` continuing `receipt`
/// for the operation `operation`.
async fn authenticated_under(
    f: &ResolverFixture,
    parts: &X402Parts,
    witness: &ApprovalWitness,
    receipt: Option<&super::super::message::MessageUseReceipt>,
    operation: Option<OperationLink>,
) -> Result<MainnetSorobanIntentAuthorization, MainnetAuthorizationError> {
    let server = f.server().await;
    let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
    let client = context.primary_client().unwrap();
    let consumer = if receipt.is_some() {
        MainnetConsumer::X402Authenticated
    } else {
        MainnetConsumer::X402Create
    };
    let intent = x402_intent(&parts.root, consumer);
    let authority = f.approval_authority(witness);
    let mut req = intent_request(f, &context, &client, &intent, &authority);
    req.authenticated = receipt;
    req.operation = operation;
    resolve_soroban_intent(req).await
}

#[tokio::test]
#[serial_test::serial]
async fn missing_record_refuses_with_its_own_precondition() {
    use crate::policy_state::ApprovalStatus;
    use stellar_agent_core::approval::PendingApprovalStore;
    // A transaction approval with a consented inbox entry and no record,
    // in a store without a file and then beside another operation.
    let f = ResolverFixture::new();
    f.record_approvals.set(false);
    let witness = f.approval(&f.envelope, f.now, 600_000);
    let inbox = inbox_path(&f, &witness);
    assert!(
        PendingApprovalStore::open(inbox.clone())
            .unwrap()
            .get(witness.nonce())
            .unwrap()
            .attestation_blob_b64
            .is_some(),
        "the inbox entry admits on its own"
    );
    let server = f.server().await;
    let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
    let client = context.primary_client().unwrap();
    let authority = f.approval_authority(&witness);
    for with_file in [false, true] {
        let operation = with_file.then(|| other_operation(&f));
        assert_eq!(f.window_path().exists(), with_file);
        let before = f.wire();
        let bytes = std::fs::read(f.window_path()).ok();
        for _ in 0..2 {
            let mut req = request(&f, &context, &client, &authority);
            req.operation = operation;
            assert_refused(
                resolve_tx_sign(req).await,
                P::ApprovalNotFound,
                &f,
                &before,
            );
            assert_eq!(
                std::fs::read(f.window_path()).ok(),
                bytes,
                "a repeated refusal writes nothing: file {with_file}"
            );
        }
    }
    // The entry an older build left keeps its inbox lifecycle.
    let mut store = PendingApprovalStore::open(inbox).unwrap();
    assert!(store.get(witness.nonce()).is_some(), "the entry stays listed");
    assert!(
        store
            .reject(
                witness.nonce(),
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
                600_000
            )
            .unwrap(),
        "the entry stays rejectable"
    );
    // A policy authority reads no record and still resolves.
    let policy = policy_authority(&f, AuthorityScope::Classic, f.now, 30_000);
    resolve_tx_sign(request(&f, &context, &client, &policy))
        .await
        .unwrap();

    // One identity in two spellings: another case selects no record.
    f.record_approvals.set(true);
    let recorded = f.approval(&f.envelope, f.now, 600_000);
    let upper = recorded.nonce().to_ascii_uppercase();
    if upper != recorded.nonce() {
        let facts = ApprovalStatus::new(&f.window, &f.profile)
            .facts_by_nonce(&upper)
            .unwrap();
        assert!(facts.is_none(), "the nonce lookup is exact");
        assert_eq!(
            enabled::check_approval_facts(
                facts.as_ref(),
                &recorded,
                f.link(recorded.nonce()).map(|link| link.operation_id),
                f.now
            ),
            Err(MainnetAuthorizationError::Refused(P::ApprovalNotFound))
        );
    }

    // The plain intent, the authenticated intent and the message.
    drop(f);
    let f = x402_fixture();
    let parts = x402_parts(&f, 1);
    let receipt = f.message_receipt(&parts.root, &parts.message);
    f.record_approvals.set(false);
    let plain = f.x402_approval(&parts.root, None, f.now);
    let authenticated = f.x402_approval(&parts.root, Some(MESSAGE_HOME_DOMAIN), f.now);
    let link = other_operation(&f);
    let before = f.wire();
    assert_refused(
        authenticated_under(&f, &parts, &plain, None, Some(link)).await,
        P::ApprovalNotFound,
        &f,
        &before,
    );
    assert_refused(
        authenticated_under(&f, &parts, &authenticated, Some(&receipt), Some(link)).await,
        P::ApprovalNotFound,
        &f,
        &before,
    );
    let other = x402_parts(&f, 2);
    assert_refused(
        message_under(&f, &other, &authenticated, Some(link.operation_id)),
        P::ApprovalNotFound,
        &f,
        &before,
    );
}

/// The message branch keeps its own checks first, then compares the
/// retained record with the identity it carries; the comparison rows are
/// refusals only the resolver makes, each with a live record and the
/// correct identity.
#[tokio::test]
#[serial_test::serial]
async fn message_branch_state_matrix() {
    use crate::policy_state::approvals::facade_calls;
    use stellar_agent_core::approval::{PendingApproval, witness::ApprovedKind};
    for case in [
        "kind",
        "subject",
        "signed-times",
        "receipt",
        "live",
        "waiting",
        "waiting-ended",
        "revoked",
        "revoked-expired",
        "expired",
        "other-operation",
        "consumed",
        "missing",
    ] {
        let f = x402_fixture();
        let parts = x402_parts(&f, 1);
        let intent = x402_intent(&parts.root, MainnetConsumer::X402Authenticated);
        let x402_entry = |home: Option<&str>| {
            let mut entry = PendingApproval::new_x402_pending(
                &intent.network_id,
                &parts.root,
                home.map(str::to_owned),
                "1000".into(),
                600_000,
            )
            .unwrap();
            entry.created_at_unix_ms = f.now;
            entry.expires_at_unix_ms = f.now + 600_000;
            entry
        };
        let subject_of = |home: Option<&str>| {
            use stellar_agent_core::approval::subject::{
                approval_subject_x402_authenticated, soroban_intent_digest,
            };
            approval_subject_x402_authenticated(
                &soroban_intent_digest(&intent.network_id, &parts.root).unwrap(),
                home.unwrap(),
            )
        };
        let mut presented = x402_entry(Some(MESSAGE_HOME_DOMAIN));
        f.record_approvals
            .set(!matches!(case, "waiting" | "waiting-ended" | "missing"));
        // The comparison rows record another witness of the same nonce, so
        // the retained record differs from the presented witness in one fact.
        let witness = match case {
            "kind" | "subject" | "signed-times" | "receipt" => {
                let recorded = match case {
                    "kind" => f.approval(&f.envelope, f.now, 600_000),
                    "subject" => f.attested(
                        &x402_entry(Some("other.example.com")),
                        ApprovedKind::X402Payment,
                        subject_of(Some("other.example.com")),
                    ),
                    _ => f.attested(
                        &presented,
                        ApprovedKind::X402Payment,
                        subject_of(Some(MESSAGE_HOME_DOMAIN)),
                    ),
                };
                // The presented witness comes from its own inbox entry.
                let _ = std::fs::remove_file(inbox_path(&f, &recorded));
                presented.approval_nonce = recorded.nonce().to_owned();
                if case == "signed-times" {
                    presented.created_at_unix_ms -= 1;
                    presented.expires_at_unix_ms -= 1;
                }
                f.record_approvals.set(false);
                f.attested(
                    &presented,
                    ApprovedKind::X402Payment,
                    subject_of(Some(MESSAGE_HOME_DOMAIN)),
                )
            }
            _ => f.attested(
                &presented,
                ApprovedKind::X402Payment,
                subject_of(Some(MESSAGE_HOME_DOMAIN)),
            ),
        };
        let mut identity = f.link(witness.nonce()).map(|link| link.operation_id);
        if matches!(case, "waiting" | "waiting-ended") {
            identity = Some(durable_record(&f, &witness, false).operation_id);
        }
        if case == "missing" {
            identity = Some(other_operation(&f).operation_id);
        }
        match case {
            "revoked" | "revoked-expired" => revoke_record(&f, &witness),
            "other-operation" => identity = Some(other_operation(&f).operation_id),
            "consumed" => {
                message_under(&f, &x402_parts(&f, 2), &witness, identity).unwrap();
            }
            _ => {}
        }
        if matches!(case, "waiting-ended" | "revoked-expired" | "expired") {
            f.clock.set(witness.expires_at_ms());
        }
        // The message's own checks precede the record: a signed expiry
        // refuses there, whatever the record holds.
        let expected = match case {
            "live" => None,
            "waiting" => Some(P::ApprovalConsentMissing),
            "waiting-ended" | "revoked-expired" | "expired" => Some(P::ApprovalExpired),
            "revoked" => Some(P::ApprovalRevoked),
            "other-operation" | "consumed" => Some(P::ApprovalNonceReused),
            "missing" => Some(P::ApprovalNotFound),
            "kind" => Some(P::ApprovalKindMismatch),
            "subject" => Some(P::ApprovalSubjectMismatch),
            "signed-times" => Some(P::ApprovalExpiry),
            _ => Some(P::ApprovalReceiptMismatch),
        };
        let before = f.wire();
        let reads = facade_calls::count(f.window.path());
        let result = message_under(&f, &parts, &witness, identity);
        match expected {
            None => {
                result.unwrap();
            }
            Some(expected) => assert_refused(result, expected, &f, &before),
        }
        let expected_reads = usize::from(!matches!(case, "waiting-ended" | "revoked-expired" | "expired"));
        assert_eq!(
            facade_calls::count(f.window.path()) - reads,
            expected_reads,
            "the message branch reads its record once: {case}"
        );
    }
}

#[test]
#[serial_test::serial]
fn message_mint_without_identity_refuses() {
    use crate::policy_state::approvals::facade_calls;
    let f = x402_fixture();
    let parts = x402_parts(&f, 1);
    let witness = f.x402_approval(&parts.root, Some(MESSAGE_HOME_DOMAIN), f.now);
    let before = f.wire();
    let reads = facade_calls::count(f.window.path());
    assert_refused(
        message_under(&f, &parts, &witness, None),
        P::ApprovalNonceReused,
        &f,
        &before,
    );
    assert_eq!(facade_calls::count(f.window.path()) - reads, 1);
    assert_eq!(
        record_facts(&f, &witness).record().disposition,
        stellar_agent_core::approval::witness::ApprovalDisposition::Pending,
        "the record stays unconsumed"
    );
    assert!(
        f.wire()["authorizations"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "no message authorization exists"
    );
}

/// A revocation after the message proof consumed the record refuses the
/// authenticated payment at the resolver, as every other revoked case does.
/// Without a revocation, the payment under the used message proof mints and
/// the mint caps it at the retained bound.
#[tokio::test]
#[serial_test::serial]
async fn used_parent_payment_refuses_after_revocation() {
    for case in [
        "used-then-revoked",
        "revoked-before-use",
        "wrong-parent",
        "wrong-operation",
        "plain",
        "used",
        "at-cap",
        "before-consent",
    ] {
        let f = x402_fixture();
        let parts = x402_parts(&f, 1);
        let witness = f.x402_approval(&parts.root, Some(MESSAGE_HOME_DOMAIN), f.now);
        let link = f.link(witness.nonce()).unwrap();
        if case == "revoked-before-use" {
            revoke_record(&f, &witness);
            let before = f.wire();
            assert_refused(
                message_under(&f, &parts, &witness, Some(link.operation_id)),
                P::ApprovalRevoked,
                &f,
                &before,
            );
            continue;
        }
        let receipt = if case == "wrong-parent" {
            let other = x402_parts(&f, 2);
            let another = f.x402_approval(&other.root, Some(MESSAGE_HOME_DOMAIN), f.now);
            f.message_receipt_for(&other.root, &other.message, &another)
        } else {
            f.message_receipt_for(&parts.root, &parts.message, &witness)
        };
        let consumed_at = record_facts(&f, &witness).record().consumed_at_ms;
        assert_eq!(
            consumed_at.is_some(),
            case != "wrong-parent",
            "the message consumes only its own record"
        );
        // The revocation lands between the message and the payment.
        let revoked = !matches!(case, "used" | "at-cap" | "before-consent");
        if revoked {
            revoke_record(&f, &witness);
        }
        let cap = record_facts(&f, &witness)
            .record()
            .consent
            .as_ref()
            .unwrap()
            .execution_expires_at_ms
            .min(witness.expires_at_ms());
        let (receipt, operation, expected) = match case {
            "used-then-revoked" => (Some(&receipt), Some(link), Some(P::ApprovalRevoked)),
            "used" => (Some(&receipt), Some(link), None),
            "wrong-parent" => (Some(&receipt), Some(link), Some(P::ApprovalRevoked)),
            "wrong-operation" => (
                Some(&receipt),
                Some(other_operation(&f)),
                Some(P::ApprovalRevoked),
            ),
            "plain" => (None, Some(link), Some(P::ApprovalRevoked)),
            "at-cap" => {
                f.clock.set(cap);
                (Some(&receipt), Some(link), Some(P::ApprovalExpired))
            }
            _ => {
                let consent_at = record_facts(&f, &witness)
                    .record()
                    .consent
                    .as_ref()
                    .unwrap()
                    .consent_at_ms;
                f.clock.set(consent_at - 1);
                (Some(&receipt), Some(link), Some(P::ApprovalExpired))
            }
        };
        let before = f.wire();
        let result = authenticated_under(&f, &parts, &witness, receipt, operation).await;
        match expected {
            None => {
                let auth = result.unwrap();
                assert!(auth.expires_at_ms() <= cap, "the mint caps at the record");
                let facts = record_facts(&f, &witness);
                assert_eq!(
                    facts.record().disposition,
                    stellar_agent_core::approval::witness::ApprovalDisposition::Consumed
                );
                assert_eq!(
                    facts.record().consumed_at_ms,
                    consumed_at,
                    "the record keeps its first consumption"
                );
                // At the cap the facts check refuses the used record.
                f.clock.set(cap);
                let facts = record_facts(&f, &witness);
                assert_eq!(
                    enabled::check_approval_facts(
                        Some(&facts),
                        &witness,
                        Some(link.operation_id),
                        cap
                    ),
                    Err(MainnetAuthorizationError::Refused(P::ApprovalExpired))
                );
            }
            Some(expected) => assert_refused(result, expected, &f, &before),
        }
        if case == "used-then-revoked" {
            // The resolver's own facts check refuses the consumed, revoked
            // record for its operation, before the mint's check.
            let facts = record_facts(&f, &witness);
            assert_eq!(
                enabled::check_approval_facts(
                    Some(&facts),
                    &witness,
                    Some(link.operation_id),
                    witness.consent_at_ms()
                ),
                Err(MainnetAuthorizationError::Refused(P::ApprovalRevoked))
            );
        }
    }
}

/// Message consumption leaves the operation waiting with no link and no
/// authority; the authenticated payment child then takes the record cap,
/// and its link sets the operation's authority and execution expiry.
#[tokio::test]
#[serial_test::serial]
async fn message_mint_leaves_the_operation_waiting() {
    use crate::policy_state::{OperationRecorder, OperationState};
    let f = x402_fixture();
    let parts = x402_parts(&f, 1);
    let witness = f.x402_approval(&parts.root, Some(MESSAGE_HOME_DOMAIN), f.now);
    let link = f.link(witness.nonce()).unwrap();
    let receipt = f.message_receipt_for(&parts.root, &parts.message, &witness);
    let facts = record_facts(&f, &witness);
    assert_eq!(
        facts.record().disposition,
        stellar_agent_core::approval::witness::ApprovalDisposition::Consumed
    );
    assert_eq!(facts.record().operation_id, *link.operation_id.as_bytes());
    let wire = f.wire();
    let message = wire["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["domain"] == "message")
        .unwrap()
        .clone();
    assert!(
        message.get("operation").is_none_or(serde_json::Value::is_null),
        "the message authorization stores no operation link"
    );
    let waiting = |f: &ResolverFixture| {
        let lookup = |wire: &serde_json::Value| {
            wire["operations"]["records"]
                .as_array()
                .unwrap()
                .iter()
                .find(|record| record["id"] == serde_json::to_value(link.operation_id).unwrap())
                .unwrap()
                .clone()
        };
        lookup(&f.wire())
    };
    let record = waiting(&f);
    assert_eq!(
        record["state"],
        serde_json::to_value(OperationState::AwaitingApproval).unwrap()
    );
    assert!(record.get("authority").is_none_or(serde_json::Value::is_null));
    assert!(
        record["attempts"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    let cap = facts
        .record()
        .consent
        .as_ref()
        .unwrap()
        .execution_expires_at_ms
        .min(witness.expires_at_ms());
    let auth = authenticated_under(&f, &parts, &witness, Some(&receipt), Some(link))
        .await
        .unwrap();
    assert!(auth.expires_at_ms() <= cap);
    // The child's link adopts the authority at the next locked step.
    OperationRecorder::new(&f.window, &f.profile, &mut ApprovalRows, "adopt")
        .lookup(&crate::policy_state::BusinessId::parse(witness.nonce()).unwrap())
        .unwrap();
    let record = waiting(&f);
    assert!(
        !record["authority"].is_null(),
        "the linked child adopts the authority"
    );
    let execution = record["execution_expires_at_ms"].as_u64().unwrap();
    assert!(
        auth.expires_at_ms() <= execution && execution <= cap,
        "{} {execution} {cap}",
        auth.expires_at_ms()
    );
}

#[test]
#[serial_test::serial]
fn second_message_mint_refuses_reuse() {
    let f = x402_fixture();
    let parts = x402_parts(&f, 1);
    let witness = f.x402_approval(&parts.root, Some(MESSAGE_HOME_DOMAIN), f.now);
    let identity = f.link(witness.nonce()).map(|link| link.operation_id);
    message_under(&f, &parts, &witness, identity).unwrap();
    let before = f.wire();
    for content in [2, 3] {
        assert_refused(
            message_under(&f, &x402_parts(&f, content), &witness, identity),
            P::ApprovalNonceReused,
            &f,
            &before,
        );
    }
    let holders = f.wire()["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["approval_nonce"] == witness.nonce())
        .count();
    assert_eq!(holders, 1, "one authorization holds the nonce");
}
