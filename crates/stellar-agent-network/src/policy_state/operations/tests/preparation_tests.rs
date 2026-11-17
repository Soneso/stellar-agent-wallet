use super::*;
use crate::operation_entry::{
    ClassicEntry, IdentityFacts, IntentBaseFacts, OpenedEntry, Preparation, classic_intent,
    lookup_canonical,
};
use stellar_agent_core::approval::{ClassicIntent, IntentAsset, IntentPayload, MemoFact};

const SOURCE: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

fn base() -> IntentBaseFacts<'static> {
    IntentBaseFacts {
        chain_id: "stellar:mainnet",
        source: SOURCE,
        policy_digest: [7; 32],
        signed_fee_cap: Some(500),
        profile_fee_cap: None,
        fee_choice: crate::fees::ClassicFeeChoice::ProfileDefault,
        memo: MemoFact::Id(u64::MAX),
    }
}

fn payloads() -> Vec<(OperationTool, OperationKind, IntentPayload)> {
    vec![
        (
            OperationTool::CliPay,
            OperationKind::Pay,
            IntentPayload::Pay {
                destination: SOURCE.to_owned(),
                asset: IntentAsset::Native,
                amount_stroops: 1,
            },
        ),
        (
            OperationTool::CliAccountsCreate,
            OperationKind::CreateAccount,
            IntentPayload::CreateAccount {
                destination: SOURCE.to_owned(),
                starting_balance_stroops: 1,
            },
        ),
        (
            OperationTool::CliTrustline,
            OperationKind::Trustline,
            IntentPayload::Trustline {
                issuer: SOURCE.to_owned(),
                code: "UsD".to_owned(),
                limit_stroops: i64::MAX,
            },
        ),
        (
            OperationTool::CliClaim,
            OperationKind::Claim,
            IntentPayload::Claim {
                balance_id: format!("00000000{}", "09".repeat(32)),
                asset: IntentAsset::Native,
                amount_stroops: 17,
                claimant: SOURCE.to_owned(),
            },
        ),
    ]
}

fn preparation(intent: ClassicIntent) -> Preparation {
    Preparation::Canonical {
        intent: Box::new(intent),
        decision: PolicyDecision::Allow,
        rule_ttl_ms: Some(300_000),
    }
}

fn open(fx: &mut Fx, name: &str, intent: ClassicIntent) -> OperationHandle {
    let p = preparation(intent);
    match p
        .open(
            &mut fx.recorder(),
            BusinessId::parse(name).unwrap(),
            OperationTool::CliClaim,
            OperationKind::Claim,
            "retained-challenge-envelope",
        )
        .unwrap()
    {
        OpenedEntry::Resume(handle) => handle,
        other => panic!("expected retained handle: {other:?}"),
    }
}

#[test]
#[serial]
fn canonical_prepare_stores_full_intent() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new();
    for (index, (tool, kind, payload)) in payloads().into_iter().enumerate() {
        for (n, decision) in [PolicyDecision::Allow, PolicyDecision::RequireApproval]
            .into_iter()
            .enumerate()
        {
            let intent = classic_intent(base(), payload.clone()).unwrap();
            let p = Preparation::Canonical {
                intent: Box::new(intent.clone()),
                decision: decision.clone(),
                rule_ttl_ms: Some(300_000),
            };
            let result = p.open(
                &mut fx.recorder(),
                BusinessId::parse(&format!("intent-{index}-{n}")).unwrap(),
                tool,
                kind,
                "original-envelope",
            );
            assert!(
                result.is_ok(),
                "canonical preparation accepts full intent: {result:?}"
            );
            let OpenedEntry::Resume(handle) = result.unwrap() else {
                panic!()
            };
            let record = fx.record(handle.id());
            assert_eq!(
                record.intent.intent_digest(),
                *intent.digest().as_bytes(),
                "full intent digest"
            );
            assert_eq!(
                record.intent,
                IntentSlot::Canonical {
                    intent_digest: *intent.digest().as_bytes(),
                    intent: serde_json::json!(intent)
                },
                "full intent round trip"
            );
            assert_eq!(
                record.prepared_decision,
                Some(serde_json::json!(decision)),
                "prepare decision is retained"
            );
            assert_eq!(record.envelope_xdr.as_deref(), Some("original-envelope"));
        }
    }
    let mut payment_digests = std::collections::HashSet::new();
    for muxed_id in [0, 7] {
        let destination = stellar_strkey::ed25519::MuxedAccount {
            ed25519: stellar_strkey::ed25519::PublicKey::from_string(SOURCE)
                .unwrap()
                .0,
            id: muxed_id,
        }
        .to_string()
        .to_string();
        let intent = classic_intent(
            base(),
            IntentPayload::Pay {
                destination: destination.clone(),
                asset: IntentAsset::Native,
                amount_stroops: 1,
            },
        )
        .unwrap();
        let OpenedEntry::Resume(handle) = preparation(intent)
            .open(
                &mut fx.recorder(),
                BusinessId::parse(&format!("muxed-{muxed_id}")).unwrap(),
                OperationTool::CliPay,
                OperationKind::Pay,
                "original-envelope",
            )
            .unwrap()
        else {
            panic!()
        };
        let IntentSlot::Canonical {
            intent,
            intent_digest,
        } = handle.intent()
        else {
            panic!()
        };
        assert_eq!(
            intent["payload"]["pay"]["destination"], destination,
            "staged payment keeps exact destination"
        );
        assert!(
            payment_digests.insert(*intent_digest),
            "muxed ids select different lasting intents"
        );
    }
    let mut hashes = std::collections::HashSet::new();
    for asset in [
        IntentAsset::Native,
        IntentAsset::Issued {
            code: "UsD".into(),
            issuer: SOURCE.into(),
        },
    ] {
        for amount_stroops in [1, i64::MAX] {
            let intent = classic_intent(
                base(),
                IntentPayload::Claim {
                    balance_id: format!("00000000{}", "09".repeat(32)),
                    asset: asset.clone(),
                    amount_stroops,
                    claimant: SOURCE.into(),
                },
            )
            .unwrap();
            let handle = open(&mut fx, &format!("claim-{}", hashes.len()), intent);
            assert!(
                hashes.insert(handle.intent().intent_digest()),
                "claim asset and amount both bind"
            );
        }
    }
}

#[test]
#[serial]
fn canonical_business_id_conflicts_on_changed_facts() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new();
    let (_, _, payload) = payloads().remove(0);
    let intent = classic_intent(base(), payload.clone()).unwrap();
    let id = BusinessId::parse("lasting-facts").unwrap();
    let p = preparation(intent.clone());
    let OpenedEntry::Resume(original) = p
        .open(
            &mut fx.recorder(),
            id.clone(),
            OperationTool::CliPay,
            OperationKind::Pay,
            "first",
        )
        .unwrap()
    else {
        panic!()
    };
    assert!(
        matches!(p.lookup(&mut fx.recorder(), &id).unwrap(), ClassicEntry::Resume(h) if h.id() == original.id())
    );
    for field in ["source", "chain", "policy", "payload", "memo", "fee"] {
        let mut facts = base();
        let mut changed = payload.clone();
        match field {
            "source" => facts.source = crate::operation_entry::tests::DESTINATION,
            "chain" => facts.chain_id = "stellar:testnet",
            "policy" => facts.policy_digest = [8; 32],
            "payload" => {
                if let IntentPayload::Pay { amount_stroops, .. } = &mut changed {
                    *amount_stroops += 1;
                }
            }
            "memo" => facts.memo = MemoFact::Text(u64::MAX.to_string()),
            "fee" => facts.fee_choice = crate::fees::ClassicFeeChoice::Explicit(499),
            _ => unreachable!(),
        }
        let changed = preparation(classic_intent(facts, changed).unwrap());
        let before = file_bytes(&fx);
        assert!(
            matches!(changed.lookup(&mut fx.recorder(), &id), Err(error) if error.code() == "operation.business_id_conflict"),
            "lookup {field}"
        );
        assert_eq!(
            changed
                .open(
                    &mut fx.recorder(),
                    id.clone(),
                    OperationTool::CliPay,
                    OperationKind::Pay,
                    "loser"
                )
                .unwrap_err()
                .code(),
            "operation.business_id_conflict",
            "locked open {field}"
        );
        assert_eq!(file_bytes(&fx), before, "conflicting facts write nothing");
    }
    let OpenedEntry::Resume(winner) = p
        .open(
            &mut fx.recorder(),
            id,
            OperationTool::CliPay,
            OperationKind::Pay,
            "loser",
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        winner.id(),
        original.id(),
        "concurrent open keeps the winner"
    );
    assert_eq!(winner.envelope_xdr(), Some("first"));
}

#[test]
#[serial]
fn canonical_business_id_replays_without_balance_read() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new();
    let (_, _, payload) = payloads().pop().unwrap();
    let intent = classic_intent(base(), payload.clone()).unwrap();
    let handle = open(&mut fx, "claim", intent.clone());
    let id = BusinessId::parse("claim").unwrap();
    let IntentPayload::Claim {
        balance_id,
        claimant,
        ..
    } = payload.clone()
    else {
        panic!()
    };
    let partial = IdentityFacts::Claim {
        balance_id,
        claimant,
    };
    assert!(
        matches!(lookup_canonical(&mut fx.recorder(), &id, base(), partial.clone()), Ok(ClassicEntry::Resume(h)) if h.id() == handle.id()),
        "partial claim resumes using stored value"
    );
    fx.clock.set(T0 + 300_000);
    let ClassicEntry::Replay(terminal) =
        lookup_canonical(&mut fx.recorder(), &id, base(), partial.clone()).unwrap()
    else {
        panic!()
    };
    assert_eq!(terminal.intent_digest, *intent.digest().as_bytes());
    assert_eq!(terminal.state, OperationState::Expired);
    fx.rewrite(|wire| {
        wire.operations.as_mut().unwrap().records[0].result = Some(OperationResult {
            error_code: Some("operation.expired".into()),
            ..OperationResult::default()
        });
    });
    let ClassicEntry::Replay(repeated) =
        lookup_canonical(&mut fx.recorder(), &id, base(), partial.clone()).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        repeated.result.unwrap().error_code.as_deref(),
        Some("operation.expired"),
        "retained claim returns its stored outcome without a balance read"
    );
    fx.clock.set(T0 - 1);
    assert!(
        matches!(lookup_canonical(&mut fx.recorder(), &id, base(), partial.clone()).unwrap(), ClassicEntry::Replay(v) if v.state == OperationState::Expired),
        "clock rollback does not revive a retained claim"
    );
    fx.rewrite(|wire| {
        let section = wire.operations.as_mut().unwrap();
        let record = section.records.remove(0);
        section.tombstones.push(record.tombstone());
    });
    assert_eq!(
        lookup_canonical(&mut fx.recorder(), &id, base(), partial)
            .unwrap_err()
            .code(),
        "operation.business_id_conflict",
        "compacted partial claim refuses"
    );
    assert!(
        matches!(lookup_canonical(&mut fx.recorder(), &id, base(), IdentityFacts::Intent(payload)).unwrap(), ClassicEntry::Replay(v) if v.compacted && v.intent_digest == terminal.intent_digest),
        "full facts still replay the tombstone"
    );
}

#[test]
#[serial]
fn canonical_staging_does_not_promote_legacy() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new();
    let (_, _, payload) = payloads().remove(0);
    let intent = classic_intent(base(), payload).unwrap();
    let id = BusinessId::parse("legacy").unwrap();
    let envelope = crate::operation_entry::intent_envelope(
        &intent,
        "Public Global Stellar Network ; September 2015",
        1,
        100,
        T0 / 1000 + 120,
    )
    .unwrap();
    let legacy = Preparation::Envelope(*intent.digest().as_bytes());
    legacy
        .open(
            &mut fx.recorder(),
            id.clone(),
            OperationTool::CliPay,
            OperationKind::Pay,
            &envelope,
        )
        .unwrap();
    assert!(matches!(
        legacy.lookup(&mut fx.recorder(), &id).unwrap(),
        ClassicEntry::Resume(_)
    ));
    let canonical = preparation(intent);
    assert!(
        matches!(canonical.lookup(&mut fx.recorder(), &id), Err(error) if error.code() == "operation.business_id_conflict"),
        "equal digest cannot promote Envelope"
    );
    assert_eq!(
        canonical
            .open(
                &mut fx.recorder(),
                id.clone(),
                OperationTool::CliPay,
                OperationKind::Pay,
                &envelope
            )
            .unwrap_err()
            .code(),
        "operation.business_id_conflict"
    );
    fx.clock.set(T0 + 120_000);
    assert!(
        matches!(
            legacy.lookup(&mut fx.recorder(), &id).unwrap(),
            ClassicEntry::Replay(_)
        ),
        "legacy expires with its exact envelope"
    );
}

fn pending(
    intent: &ClassicIntent,
    envelope: &str,
) -> stellar_agent_core::approval::PendingApproval {
    use stellar_agent_core::approval::PendingApproval;
    let mut entry = match intent.payload() {
        IntentPayload::Pay {
            destination,
            asset: _,
            amount_stroops,
        } => PendingApproval::new_payment_pending(
            envelope.into(),
            envelope.as_bytes(),
            destination.clone(),
            *amount_stroops,
            "XLM".into(),
            None,
            100,
            1,
            "1000".into(),
            300_000,
        )
        .unwrap(),
        IntentPayload::CreateAccount {
            destination,
            starting_balance_stroops,
        } => PendingApproval::new_payment_pending(
            envelope.into(),
            envelope.as_bytes(),
            destination.clone(),
            *starting_balance_stroops,
            "XLM".into(),
            None,
            100,
            1,
            "1000".into(),
            300_000,
        )
        .unwrap(),
        IntentPayload::Trustline {
            issuer,
            code,
            limit_stroops,
        } => PendingApproval::new_trustline_pending(
            envelope.into(),
            envelope.as_bytes(),
            SOURCE.into(),
            code.clone(),
            issuer.clone(),
            Some(*limit_stroops),
            100,
            1,
            "1000".into(),
            300_000,
        )
        .unwrap(),
        IntentPayload::Claim {
            balance_id,
            amount_stroops,
            claimant,
            ..
        } => PendingApproval::new_claim_pending(
            envelope.into(),
            envelope.as_bytes(),
            balance_id.clone(),
            stellar_strkey::ClaimableBalance::V0([9; 32])
                .to_string()
                .to_string(),
            "XLM".into(),
            *amount_stroops,
            claimant.clone(),
            100,
            1,
            "1000".into(),
            300_000,
        )
        .unwrap(),
        IntentPayload::ContractPay { .. } => {
            unreachable!("classic_intent refuses a contract payment")
        }
    };
    entry.created_at_unix_ms = T0;
    entry.expires_at_unix_ms = T0 + 120_000;
    entry
}

#[test]
#[serial]
fn canonical_pending_record_binds_intent_and_signed_interval() {
    use crate::operation_entry::{pending_approval_facts, stage_pending};
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new();
    for (index, (tool, kind, payload)) in payloads().into_iter().enumerate() {
        let intent = classic_intent(base(), payload).unwrap();
        let envelope = crate::operation_entry::intent_envelope(
            &intent,
            "Public Global Stellar Network ; September 2015",
            1,
            100,
            T0 / 1000 + 60,
        )
        .unwrap();
        let OpenedEntry::Resume(handle) = preparation(intent.clone())
            .open(
                &mut fx.recorder(),
                BusinessId::parse(&format!("pending-{index}")).unwrap(),
                tool,
                kind,
                &envelope,
            )
            .unwrap()
        else {
            panic!()
        };
        assert!(
            fx.wire()
                .approvals
                .as_ref()
                .is_none_or(|s| s.records.len() == index),
            "Allow opens no approval record"
        );
        let mut entry = pending(&intent, &envelope);
        stage_pending(&mut entry, Some(&intent), 300_000).unwrap();
        assert_eq!(
            entry.subject_kind,
            stellar_agent_core::approval::subject::SubjectKind::IntentDigest,
            "new entry is intent tagged before insertion"
        );
        let facts = pending_approval_facts(
            &entry,
            &handle,
            intent.approved_kind(),
            crate::operation_entry::unsigned_envelope_sha256(&envelope),
            entry.expires_at_unix_ms - entry.created_at_unix_ms,
        );
        let record = crate::policy_state::ApprovalRecorder::new(
            &fx.store,
            &fx.profile,
            &mut fx.sink,
            "pending",
        )
        .open_pending(handle.id(), &facts, PolicyDecision::RequireApproval)
        .unwrap()
        .record;
        assert_eq!(
            record.subject,
            *intent.digest().as_bytes(),
            "record subject is full intent"
        );
        assert_eq!(
            record.rule_ttl_ms, 120_000,
            "signed interval wins over requested TTL"
        );
        assert_eq!(
            (record.created_at_ms, record.waiting_expires_at_ms),
            (T0, T0 + 120_000)
        );
        assert_eq!(
            fx.record(handle.id()).waiting_expires_at_ms,
            T0 + 120_000,
            "canonical waiting ignores original envelope deadline"
        );
        let mut overflow = entry.clone();
        overflow.created_at_unix_ms = u64::MAX - 1;
        overflow.expires_at_unix_ms = u64::MAX;
        assert!(
            matches!(stage_pending(&mut overflow, Some(&intent), 300_000),
                Err(error) if error.code() == "approval.clock_error"),
            "saturated pending construction refuses"
        );
        let overflow_open = Preparation::Canonical {
            intent: Box::new(intent.clone()),
            decision: PolicyDecision::Allow,
            rule_ttl_ms: Some(u64::MAX),
        }
        .open(
            &mut fx.recorder(),
            BusinessId::parse(&format!("overflow-{index}")).unwrap(),
            tool,
            kind,
            &envelope,
        );
        assert!(
            matches!(overflow_open, Err(error) if error.code() == "submission.record_unavailable"),
            "canonical operation waiting overflow refuses before insertion"
        );
    }
}

#[test]
#[serial]
fn intent_handoff_authenticates_the_link() {
    use crate::operation_entry::{
        CanonicalUse, intent_for_consent, pending_approval_facts, stage_pending,
    };
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new();
    let (_, _, payload) = payloads().remove(0);
    let intent = classic_intent(base(), payload).unwrap();
    let envelope = crate::operation_entry::intent_envelope(
        &intent,
        "Public Global Stellar Network ; September 2015",
        1,
        100,
        T0 / 1000 + 60,
    )
    .unwrap();
    let OpenedEntry::Resume(handle) = preparation(intent.clone())
        .open(
            &mut fx.recorder(),
            BusinessId::parse("handoff").unwrap(),
            OperationTool::CliPay,
            OperationKind::Pay,
            &envelope,
        )
        .unwrap()
    else {
        panic!()
    };
    let mut entry = pending(&intent, &envelope);
    stage_pending(&mut entry, Some(&intent), 300_000).unwrap();
    let facts = pending_approval_facts(&entry, &handle, intent.approved_kind(), [0; 32], 120_000);
    crate::policy_state::ApprovalRecorder::new(&fx.store, &fx.profile, &mut fx.sink, "pending")
        .open_pending(handle.id(), &facts, PolicyDecision::RequireApproval)
        .unwrap();
    let scope = CanonicalUse {
        chain_id: "stellar:mainnet",
        source: SOURCE,
        policy_digest: [7; 32],
    };
    assert_eq!(
        intent_for_consent(&fx.store, &fx.profile, &entry, &scope).unwrap(),
        Some(intent.clone())
    );
    let (_, _, claim) = payloads().remove(3);
    let mut wrong_kind = entry.clone();
    wrong_kind.kind = pending(&classic_intent(base(), claim).unwrap(), &envelope).kind;
    assert!(
        intent_for_consent(&fx.store, &fx.profile, &wrong_kind, &scope).is_err(),
        "handoff refuses the wrong inbox kind"
    );
    let original = fx.wire();
    for case in [
        "link",
        "subject",
        "slot-digest",
        "record-digest",
        "malformed",
        "unknown",
        "envelope",
        "revoked",
    ] {
        let mut changed = original.clone();
        let operation = &mut changed.operations.as_mut().unwrap().records[0];
        let approval = &mut changed.approvals.as_mut().unwrap().records[0];
        match case {
            "link" => operation.approval_record_id = None,
            "subject" => approval.subject[0] ^= 1,
            "slot-digest" => {
                if let IntentSlot::Canonical { intent, .. } = &mut operation.intent {
                    *intent = serde_json::to_value(
                        classic_intent(
                            base(),
                            IntentPayload::Pay {
                                destination: SOURCE.into(),
                                asset: IntentAsset::Native,
                                amount_stroops: 2,
                            },
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    let parsed: ClassicIntent = serde_json::from_value(intent.clone()).unwrap();
                    approval.subject = *parsed.digest().as_bytes();
                }
            }
            "record-digest" => approval.intent_digest[0] ^= 1,
            "malformed" => {
                if let IntentSlot::Canonical { intent, .. } = &mut operation.intent {
                    *intent = serde_json::json!({});
                }
            }
            "unknown" => {
                if let IntentSlot::Canonical { intent, .. } = &mut operation.intent {
                    intent["unexpected"] = true.into();
                }
            }
            "envelope" => operation.envelope_xdr = Some("another challenge".into()),
            "revoked" => {
                approval.state = crate::policy_state::ApprovalState::Revoked;
                approval.revoked_at_ms = Some(T0);
            }
            _ => unreachable!(),
        }
        fx.store.seal_unchecked_for_test(&fx.profile, &changed);
        assert!(
            intent_for_consent(&fx.store, &fx.profile, &entry, &scope).is_err(),
            "handoff refuses {case}"
        );
        fx.store.seal_unchecked_for_test(&fx.profile, &original);
        assert_eq!(
            intent_for_consent(&fx.store, &fx.profile, &entry, &scope).unwrap(),
            Some(intent.clone()),
            "fresh authenticated read after {case}"
        );
    }
    for changed in [
        CanonicalUse {
            chain_id: "stellar:testnet",
            ..scope
        },
        CanonicalUse {
            source: crate::operation_entry::tests::DESTINATION,
            ..scope
        },
        CanonicalUse {
            policy_digest: [8; 32],
            ..scope
        },
    ] {
        assert!(
            intent_for_consent(&fx.store, &fx.profile, &entry, &changed).is_err(),
            "admitted scope must match"
        );
    }
    let mut missing = entry.clone();
    missing.approval_nonce = "missing".into();
    assert!(
        intent_for_consent(&fx.store, &fx.profile, &missing, &scope).is_err(),
        "canonical entry requires its linked record"
    );
    missing.subject_kind = stellar_agent_core::approval::subject::SubjectKind::EnvelopeText;
    assert_eq!(
        intent_for_consent(&fx.store, &fx.profile, &missing, &scope).unwrap(),
        None,
        "legacy absence stays distinct"
    );
}
