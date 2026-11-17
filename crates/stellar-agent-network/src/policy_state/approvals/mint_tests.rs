fn mint_refusal<T: std::fmt::Debug>(
    result: &Result<T, WindowStoreError>,
    expected: MainnetPrecondition,
) {
    assert!(
        matches!(result, Err(WindowStoreError::AuthorizationRefused { precondition }) if *precondition == expected),
        "expected {expected:?}, got {result:?}"
    );
}

#[test]
#[serial]
fn mint_refusals_follow_the_record_order() {
    for case in [
        "revoked",
        "waiting",
        "waiting-ended",
        "expired",
        "released",
        "other-operation",
        "early",
    ] {
        let mut fx = Fx::new(300_000);
        fx.open();
        if !case.starts_with("waiting") {
            fx.consent();
        }
        let at = fx.payload.receipt.verified_at_unix_ms();
        let mut request = fx.mint_request();
        request.authorization_ttl_ms = 0;
        request.operation = None;
        let expected = match case {
            "revoked" => {
                let id = fx.id();
                fx.recorder().revoke(id).unwrap();
                fx.clock.set(at + 400_000);
                MainnetPrecondition::ApprovalRevoked
            }
            "waiting" => MainnetPrecondition::ApprovalConsentMissing,
            "waiting-ended" | "expired" => {
                fx.clock.set(at + 400_000);
                MainnetPrecondition::ApprovalExpired
            }
            "released" => {
                OperationRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "close")
                    .transition(
                        fx.operation,
                        None,
                        OperationState::Expired,
                        &super::super::operations::TransitionEvidence::default(),
                    )
                    .unwrap();
                MainnetPrecondition::ApprovalExpired
            }
            "early" => {
                fx.clock.set(at - 1);
                MainnetPrecondition::ApprovalExpired
            }
            _ => MainnetPrecondition::ApprovalNonceReused,
        };
        let before = fx.bytes();
        for _ in 0..2 {
            mint_refusal(
                &fx.store.mint_authorization(fx.fixture.profile(), &request),
                expected,
            );
            assert_eq!(fx.bytes(), before, "refused mint writes nothing: {case}");
        }
        request.chain = stellar_agent_core::profile::caip2::Caip2::Testnet;
        mint_refusal(
            &fx.store.mint_authorization(fx.fixture.profile(), &request),
            MainnetPrecondition::ChainNotMainnet,
        );
        request.chain = fx.fixture.profile().chain_id;
        request.authority = MintAuthority::Policy(super::super::ledger::PolicyAuthorityBinding {
            policy_digest: request.policy_digest,
            policy_sequence: request.policy_sequence,
            rule_index: 0,
            evaluated_at_ms: at,
            governing_until_ms: at + 900_000,
            scope: stellar_agent_core::mainnet::decision::AuthorityScope::Classic,
        });
        mint_refusal(
            &fx.store.mint_authorization(fx.fixture.profile(), &request),
            MainnetPrecondition::LifetimeInvalid,
        );
        assert_eq!(fx.bytes(), before, "Policy refusal preserves bytes");
    }
}

#[test]
#[serial]
fn consumed_mint_refusals_precede_expiry_for_another_operation() {
    for case in ["expired", "released", "early"] {
        let mut fx = Fx::new(300_000);
        fx.open();
        fx.consent();
        fx.store
            .mint_authorization(fx.fixture.profile(), &fx.mint_request())
            .unwrap();
        let at = fx.payload.receipt.verified_at_unix_ms();
        match case {
            "expired" => fx.clock.set(at + 400_000),
            "early" => fx.clock.set(at - 1),
            _ => {
                OperationRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "close")
                    .transition(
                        fx.operation,
                        None,
                        OperationState::Expired,
                        &super::super::operations::TransitionEvidence::default(),
                    )
                    .unwrap();
                assert!(fx.view().record.consent.unwrap().payload.is_none());
            }
        }
        let mut request = fx.mint_request();
        request.operation = None;
        let before = fx.bytes();
        mint_refusal(
            &fx.store.mint_authorization(fx.fixture.profile(), &request),
            MainnetPrecondition::ApprovalNonceReused,
        );
        assert_eq!(fx.bytes(), before, "refused reuse writes nothing: {case}");
    }
}

#[test]
#[serial]
fn mint_caps_at_the_record_execution_expiry() {
    for offset in [0, 899_999, 900_000, 900_001] {
        let mut fx = Fx::new(86_400_000);
        fx.open();
        let consent = fx.consent().record.consent.unwrap();
        let end = consent.consent_at_ms + 900_000;
        assert_eq!(consent.execution_expires_at_ms, end);
        fx.clock.set(consent.consent_at_ms + offset);
        let mut request = fx.mint_request();
        request.authorization_ttl_ms = 2_000_000;
        let before = fx.bytes();
        let result = fx.store.mint_authorization(fx.fixture.profile(), &request);
        if offset < 900_000 {
            assert_eq!(
                result.unwrap().expires_at_ms,
                end,
                "authorization ends at durable execution bound"
            );
        } else {
            mint_refusal(&result, MainnetPrecondition::ApprovalExpired);
            assert_eq!(fx.bytes(), before);
        }
    }
}

#[test]
#[serial]
fn envelope_mint_caps_at_the_signed_expiry() {
    for child in [false, true] {
        let mut fx = Fx::x402(300_000);
        fx.open();
        let consent = fx.consent().record.consent.unwrap();
        let end = fx.facts.waiting_expires_at_ms;
        assert!(
            end < consent.execution_expires_at_ms,
            "consent follows creation"
        );
        let mut request = fx.mint_request();
        request.authorization_ttl_ms = 600_000;
        request.consumer = MainnetConsumer::X402Create;
        request.binding = DomainBinding::Soroban {
            intent_digest: fx.facts.intent_digest,
        };
        if child {
            let parent = fx
                .store
                .mint_authorization(fx.fixture.profile(), &request)
                .unwrap();
            use super::super::ledger::{ConsumeExpect, ConsumptionBinding};
            use crate::mainnet::{AuditFacts, RecomputedFacts};
            let audit = AuditFacts {
                log_path_digest: [1; 32],
                segment: [2; 32],
                anchored_count: 1,
            };
            let expect = ConsumeExpect::new(
                fx.fixture.name().to_owned(),
                request.chain,
                request.consumer,
                request.binding.clone(),
                request.policy_sequence,
                request.policy_digest,
                request.authority.clone(),
                None,
                parent.bindings_digest,
                audit,
                &RecomputedFacts {
                    content_digest: request.binding.content_digest(),
                    entries_digest: crate::mainnet::digest::entries_digest(&[]),
                    audit,
                },
            );
            fx.store
                .consume_authorization(
                    fx.fixture.profile(),
                    parent.id,
                    &expect,
                    &ConsumptionBinding::RetainedIntent {
                        intent_digest: fx.facts.intent_digest,
                    },
                )
                .unwrap();
            request.parent = Some(parent.id);
            request.operation = None;
            request.binding = DomainBinding::X402Submit {
                final_envelope_sha256: [8; 32],
                root_invocation_digest: [9; 32],
            };
        }
        let minted = fx
            .store
            .mint_authorization(fx.fixture.profile(), &request)
            .unwrap();
        assert_eq!(
            minted.expires_at_ms, end,
            "envelope and child retain the signed bound"
        );
        if child {
            let mut next = request.clone();
            next.binding = DomainBinding::X402Submit {
                final_envelope_sha256: [10; 32],
                root_invocation_digest: [9; 32],
            };
            // Before the record cap, a lifetime that ends at the decision
            // time is invalid.
            let mut short = next.clone();
            short.chain_deadline_ms = Some(end - 1);
            fx.clock.set(end - 1);
            mint_refusal(
                &fx.store.mint_authorization(fx.fixture.profile(), &short),
                MainnetPrecondition::LifetimeInvalid,
            );
            // At the record cap, the record refuses first.
            fx.clock.set(end);
            mint_refusal(
                &fx.store.mint_authorization(fx.fixture.profile(), &next),
                MainnetPrecondition::ApprovalExpired,
            );
        }
    }
}

pub(in crate::policy_state) fn approval_handle(
    fx: &mut Fx,
) -> super::super::operations::OperationHandle {
    let outcome = OperationRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "lookup")
        .lookup(&BusinessId::parse("order-1").unwrap())
        .unwrap()
        .unwrap();
    let super::super::operations::LookupOutcome::Resumable(handle) = outcome else {
        panic!("resumable operation")
    };
    handle
}

fn begin_approval(
    fx: &mut Fx,
    request: MintRequest,
) -> Result<super::super::operations::AttemptStarted, WindowStoreError> {
    let handle = approval_handle(fx);
    begin_step_mint(fx, &handle, request)
}

/// Begins an attempt of `handle` whose authorization mints `request`.
pub(in crate::policy_state) fn begin_step_mint(
    fx: &mut Fx,
    handle: &super::super::operations::OperationHandle,
    request: MintRequest,
) -> Result<super::super::operations::AttemptStarted, WindowStoreError> {
    use super::super::operations::{AttemptAuthorization, AttemptEnvelope, AttemptRequest};
    OperationRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "begin").begin_attempt(
        handle,
        &AttemptRequest {
            envelope: Some(AttemptEnvelope {
                xdr: "AAAA".to_owned(),
                unsigned_envelope_sha256: [1; 32],
            }),
            authorization: AttemptAuthorization::Mint(Box::new(request)),
            send_by_ms: u64::MAX,
        },
    )
}

#[test]
#[serial]
fn operation_mint_uses_admitted_identity() {
    let mut fx = Fx::new(86_400_000);
    fx.open();
    fx.consent();
    let mut request = fx.mint_request();
    request.operation = None;
    assert!(
        begin_approval(&mut fx, request).is_ok(),
        "operation handle supplies the approval identity"
    );
}

#[test]
#[serial]
fn consent_keeps_waiting_until_first_mint() {
    for route in ["begin", "adopt-live", "sweep", "waiting-expiry"] {
        let mut fx = Fx::new(86_400_000);
        fx.open();
        let end = fx.consent().record.consent.unwrap().execution_expires_at_ms;
        assert_eq!(
            fx.wire().operations.as_ref().unwrap().records[0].state,
            OperationState::AwaitingApproval
        );
        let mut request = fx.mint_request();
        request.authorization_ttl_ms = 1;
        match route {
            "begin" => {
                begin_approval(&mut fx, request).unwrap();
            }
            "waiting-expiry" => {
                fx.clock.set(fx.facts.waiting_expires_at_ms);
                OperationRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "expire")
                    .expire_due(fx.facts.waiting_expires_at_ms)
                    .unwrap();
                assert!(
                    fx.wire().operations.as_ref().unwrap().records[0]
                        .state
                        .is_terminal()
                );
                continue;
            }
            _ => {
                fx.store
                    .mint_authorization(fx.fixture.profile(), &request)
                    .unwrap();
                if route == "sweep" {
                    fx.clock.set(fx.payload.receipt.verified_at_unix_ms() + 2);
                }
                approval_handle(&mut fx);
            }
        }
        let before = fx.wire().operations.as_ref().unwrap().records[0].execution_expires_at_ms;
        assert_eq!(before, Some(end), "adoption uses durable consent: {route}");
        fx.clock.set(end - 1);
        OperationRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "lookup")
            .lookup(&BusinessId::parse("order-1").unwrap())
            .unwrap();
        assert_eq!(
            fx.wire().operations.as_ref().unwrap().records[0].execution_expires_at_ms,
            before,
            "adoption never renews execution"
        );
    }
}

#[test]
#[serial]
fn remint_runs_only_through_the_operation_route() {
    let mut fx = Fx::new(86_400_000);
    fx.open();
    fx.consent();
    let request = fx.mint_request();
    fx.store
        .mint_authorization(fx.fixture.profile(), &request)
        .unwrap();
    fx.clock
        .set(fx.payload.receipt.verified_at_unix_ms() + request.authorization_ttl_ms + 1);
    approval_handle(&mut fx);
    let before = fx.bytes();
    let mut public_retry = request.clone();
    let DomainBinding::Transaction { tx_hash, .. } = &mut public_retry.binding else {
        panic!("transaction")
    };
    *tx_hash = [5; 32];
    mint_refusal(
        &fx.store
            .mint_authorization(fx.fixture.profile(), &public_retry),
        MainnetPrecondition::ApprovalNonceReused,
    );
    assert_eq!(fx.bytes(), before);
    let first = fx.view().record.consumed_at_ms;
    let mut raw = request;
    raw.operation = None;
    assert!(
        begin_approval(&mut fx, raw).is_ok(),
        "only operation lineage admits an unused remint"
    );
    assert_eq!(
        fx.view().record.consumed_at_ms,
        first,
        "remint keeps the first consumption time"
    );
}

#[test]
#[serial]
fn approval_and_authorization_commit_together_after_restart() {
    use super::super::store::commit_faults::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
    };
    for point in [COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_AFTER_COUNTER] {
        let mut fx = Fx::new(300_000);
        fx.open();
        fx.consent();
        let request = fx.mint_request();
        let fault = arm_accounting_fault(point);
        assert!(
            fx.store
                .mint_authorization(fx.fixture.profile(), &request)
                .is_err()
        );
        drop(fault);
        let restarted = PersistedWindowStore::at_path(fx.store.path().to_owned());
        let wire = restarted
            .read_for_inspection(fx.fixture.profile())
            .unwrap()
            .unwrap();
        let consumed = wire.approvals.as_ref().unwrap().records[0].state == ApprovalState::Consumed;
        assert_eq!(
            consumed,
            !wire.authorizations.is_empty(),
            "consumption and mint commit atomically"
        );
        assert_eq!(consumed, point == COMMIT_FAULT_AFTER_COUNTER);
        let retry = restarted.mint_authorization(fx.fixture.profile(), &request);
        if consumed {
            mint_refusal(&retry, MainnetPrecondition::DuplicateOpen);
        } else {
            retry.unwrap();
        }
        let wire = restarted
            .read_for_inspection(fx.fixture.profile())
            .unwrap()
            .unwrap();
        assert_eq!(
            wire.authorizations.len(),
            1,
            "restart and retry have one effect"
        );
        assert_eq!(
            wire.approvals.as_ref().unwrap().records[0].state,
            ApprovalState::Consumed
        );
    }
}

#[test]
#[serial]
fn malformed_approval_images_refuse_inspection_and_mint() {
    use hmac::{Hmac, KeyInit as _, Mac as _};
    for case in ["duplicate", "missing", "unknown"] {
        let mut fx = Fx::new(300_000);
        fx.open();
        fx.consent();
        let mut value = serde_json::to_value(fx.wire()).unwrap();
        let generation = value["generation"].clone();
        let records = value["approvals"]["records"].as_array_mut().unwrap();
        match case {
            "duplicate" => {
                let another = records[0].clone();
                records.push(another);
            }
            "missing" => {
                records[0].as_object_mut().unwrap().remove("nonce");
            }
            _ => {
                records[0]["unknown_field"] = serde_json::json!(true);
            }
        }
        // Authenticated malformed files cannot be written by the public facades.
        // Keep the commitment coherent so duplication is the only defect.
        let body = if case == "duplicate" {
            serde_json::to_vec(&serde_json::from_value::<WireFile>(value).unwrap()).unwrap()
        } else {
            serde_json::to_vec(&value).unwrap()
        };
        let key =
            crate::keyring::load_hmac_key_32(&fx.fixture.profile().policy_window_state_key_id)
                .unwrap();
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key.as_ref()).unwrap();
        mac.update(b"stellar-agent-policy-window/v1/body\x00");
        mac.update(&body);
        let mut bytes = mac.finalize().into_bytes().to_vec();
        bytes.extend(body);
        std::fs::write(fx.store.path(), &bytes).unwrap();
        let coordinate = super::super::store::generation_entry_ref(fx.fixture.profile());
        let commitment = serde_json::json!({
            "generation": generation,
            "body_sha256": stellar_agent_core::hex::encode(
                &<sha2::Sha256 as sha2::Digest>::digest(&bytes[32..]))
        });
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .set_password(&commitment.to_string())
            .unwrap();
        let read =
            ApprovalStatus::new(&fx.store, fx.fixture.profile()).facts_by_nonce(&fx.facts.nonce);
        assert!(read.is_err(), "malformed approval image: {case}");
        let read = read.unwrap_err();
        let mint = fx
            .store
            .mint_authorization(fx.fixture.profile(), &fx.mint_request())
            .unwrap_err();
        #[cfg(feature = "mainnet-write")]
        assert!(
            matches!(
                read,
                WindowStoreError::MainnetStateUnverifiable {
                    defect: super::super::store::StateDefect::Malformed
                }
            ),
            "malformed approval image: {read:?}"
        );
        #[cfg(not(feature = "mainnet-write"))]
        assert!(
            matches!(read, WindowStoreError::Invalid { .. }),
            "malformed approval image: {read:?}"
        );
        assert_eq!(
            std::mem::discriminant(&read),
            std::mem::discriminant(&mint),
            "inspection and mint refuse the same malformed image: {case}"
        );
        assert_eq!(read.to_string(), mint.to_string());
        assert_eq!(std::fs::read(fx.store.path()).unwrap(), bytes);
    }
}
