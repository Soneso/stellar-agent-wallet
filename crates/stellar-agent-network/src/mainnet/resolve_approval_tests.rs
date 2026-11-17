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
            enabled::check_approval_facts(Some(&facts), &witness, Some(link), now),
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
                None
            } else {
                Some(link)
            };
            let facts = record_facts(&f, &witness);
            assert_eq!(
                enabled::check_approval_facts(
                    Some(&facts),
                    &witness,
                    operation,
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
                    enabled::check_approval_facts(Some(&facts), &witness, Some(link), at).is_ok()
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
            Some(other_link),
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
                Some(link),
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
            &evaluation,
            &f.audit(),
            &f.signer,
            witness.consent_at_ms(),
            &f.window,
            Some(link)
        ),
        Err(MainnetAuthorizationError::Refused(P::StoreUnavailable)),
        "facts read failure refuses before mint"
    );
}

#[tokio::test]
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
        enabled::check_approval_facts(Some(&facts), &witness, Some(link), witness.consent_at_ms()),
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
            Some(link),
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
    fx._clock.set(now);
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
        &evaluation,
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
    assert!(enabled::check_approval_facts(Some(&facts), &witness, Some(link), now).is_ok());
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
    fx._clock.set(witness.consent_at_ms());
    let mut without_digest = first.clone();
    without_digest.intent_digest = None;
    assert!(
        matches!(
            store.mint_authorization(fx.fixture.profile(), &without_digest),
            Err(crate::policy_state::WindowStoreError::AuthorizationRefused {
                precondition: P::IntentMismatch,
            })
        ),
        "canonical mint without an intent digest refuses IntentMismatch"
    );
    store
        .mint_authorization(fx.fixture.profile(), &first)
        .unwrap();
    fx._clock.set(now);
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
