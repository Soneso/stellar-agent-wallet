#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use super::tests::Fx;
use super::*;
use base64::Engine as _;
use serial_test::serial;
use stellar_agent_core::approval::witness::{ApprovalExpectation, verify_durable_approval};
use stellar_agent_core::approval::{
    intent::ClassicIntent, witness::verify_durable_intent_approval,
};
use stellar_agent_core::error::WalletError;
use stellar_agent_core::mainnet::{
    decision::{AuthorityScope, MainnetDecision},
    verified_policy::VerifiedPolicy,
};
use stellar_agent_core::policy::{Decision, DenyReason};
use stellar_agent_core::profile::caip2::Caip2;

fn facts(fx: &Fx) -> ApprovalFacts {
    ApprovalStatus::new(&fx.store, fx.fixture.profile())
        .facts_by_nonce(&fx.facts.nonce)
        .unwrap()
        .unwrap()
}

fn changed(facts: &ApprovalFacts, edit: impl FnOnce(&mut ApprovalRecordFacts)) -> ApprovalFacts {
    // Core constructors isolate negative inputs that authenticated storage rejects.
    let mut record = facts.record().clone();
    edit(&mut record);
    ApprovalFacts::new(facts.profile().to_owned(), facts.chain(), record)
}

fn verify(
    fx: &Fx,
    facts: Option<&ApprovalFacts>,
    blob: &[u8; 32],
    now: u64,
) -> Result<ApprovalWitness, WalletError> {
    verify_durable_approval(
        facts,
        blob,
        fx.fixture.profile(),
        fx.fixture.name(),
        &ApprovalExpectation {
            kind: fx.facts.kind,
            subject: fx.facts.subject,
        },
        &fx.fixture.current_policy(),
        now,
    )
}

fn refusal(result: Result<ApprovalWitness, WalletError>, code: &str, message: &str) {
    assert!(result.is_err(), "expected refusal {code}: {message}");
    let error = result.unwrap_err();
    assert_eq!(error.code(), code);
    assert_eq!(error.to_string(), message);
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn durable_facts_match_the_record_and_read_without_writing() {
    let mut fx = Fx::new(300_000);
    assert!(
        ApprovalStatus::new(&fx.store, fx.fixture.profile())
            .facts_by_nonce(&fx.facts.nonce)
            .unwrap()
            .is_none()
    );
    fx.open();
    assert!(facts(&fx).record().consent.is_none());
    fx.payload.outbox_row = Some(
        serde_json::from_value(serde_json::json!({
            "g": 3, "s": 7, "digest": format!("sha256:{}", "ab".repeat(32)),
        }))
        .unwrap(),
    );
    fx.payload.row_provenance = None;
    let record = fx.consent().record;
    let before = fx.bytes();
    let generation = fx.wire().generation;
    let expected = ApprovalFacts::new(
        fx.fixture.name().to_owned(),
        Caip2::Mainnet,
        ApprovalRecordFacts {
            id: record.id,
            operation_id: *record.operation_id.as_bytes(),
            nonce: record.nonce.clone(),
            disposition: ApprovalDisposition::Pending,
            consumed_at_ms: None,
            revoked_at_ms: None,
            kind: record.kind,
            subject_kind: record.subject_kind,
            subject: record.subject,
            intent_digest: record.intent_digest,
            created_at_ms: record.created_at_ms,
            expires_at_ms: record.waiting_expires_at_ms,
            rule_ttl_ms: record.rule_ttl_ms,
            consent: Some(ApprovalConsentFacts {
                consent_at_ms: record.consent.as_ref().unwrap().consent_at_ms,
                execution_expires_at_ms: record.consent.as_ref().unwrap().execution_expires_at_ms,
                receipt_sha256: fx.payload.receipt.digest().unwrap(),
                payload: Some(ApprovalPayloadFacts {
                    attestation: fx.payload.attestation,
                    receipt: fx.payload.receipt.clone(),
                    process_uid: fx.payload.process_uid.clone(),
                    challenge_subject: None,
                    outbox_row: fx.payload.outbox_row,
                }),
            }),
        },
    );
    let inbox_path = fx.fixture.home().join("first.toml");
    let mut inbox =
        stellar_agent_core::approval::store::PendingApprovalStore::open(inbox_path).unwrap();
    let mut entry = inbox.get(&record.nonce).unwrap().clone();
    inbox.remove(&record.nonce).unwrap();
    entry.created_at_unix_ms += 1;
    inbox.insert(entry, record.created_at_ms).unwrap();
    assert_eq!(
        facts(&fx),
        expected,
        "projection uses durable signed fields"
    );
    inbox.remove(&record.nonce).unwrap();
    assert_eq!(facts(&fx), expected, "collected inbox is irrelevant");
    assert!(
        verify(
            &fx,
            Some(&facts(&fx)),
            &fx.payload.attestation,
            record.consent.as_ref().unwrap().consent_at_ms
        )
        .is_ok(),
        "durable proof verifies with a collected and locked inbox"
    );
    assert_eq!(fx.bytes(), before);
    assert_eq!(fx.wire().generation, generation);
    let consent = expected.record().consent.as_ref().unwrap();
    fx.store
        .mint_authorization(fx.fixture.profile(), &fx.mint_request())
        .unwrap();
    let consumed = facts(&fx);
    assert_eq!(consumed.record().disposition, ApprovalDisposition::Consumed);
    assert_eq!(
        consumed.record().consumed_at_ms,
        Some(consent.consent_at_ms)
    );
    fx.clock.set(consent.consent_at_ms + 1);
    let id = fx.id();
    fx.recorder().revoke(id).unwrap();
    let revoked = facts(&fx);
    assert_eq!(revoked.record().disposition, ApprovalDisposition::Revoked);
    assert_eq!(revoked.record().consumed_at_ms, Some(consent.consent_at_ms));
    assert_eq!(
        revoked.record().revoked_at_ms,
        Some(consent.consent_at_ms + 1)
    );
    let before = fx.bytes();
    fx.clock.set(consent.execution_expires_at_ms);
    let released = facts(&fx);
    assert!(
        released
            .record()
            .consent
            .as_ref()
            .unwrap()
            .payload
            .is_none()
    );
    assert_eq!(
        released.record().consent.as_ref().unwrap().receipt_sha256,
        consent.receipt_sha256
    );
    assert_eq!(fx.bytes(), before, "pruning is local to inspection");
    let mut other = fx.fixture.profile().clone();
    other.chain_id = Caip2::Testnet;
    assert!(
        ApprovalStatus::new(&fx.store, &other)
            .facts_by_nonce(&record.nonce)
            .is_err()
    );
    let mut corrupt = before;
    corrupt[0] ^= 1;
    std::fs::write(fx.store.path(), corrupt).unwrap();
    assert!(
        ApprovalStatus::new(&fx.store, fx.fixture.profile())
            .facts_by_nonce(&record.nonce)
            .is_err()
    );
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn durable_witness_state_matrix() {
    let mut fx = Fx::new(300_000);
    fx.open();
    let no_consent = facts(&fx);
    fx.consent();
    let original = facts(&fx);
    let at = original.record().consent.as_ref().unwrap().consent_at_ms;
    let blob = fx.payload.attestation;
    let wrong_clock = changed(&original, |r| {
        r.consent.as_mut().unwrap().consent_at_ms -= 1
    });
    refusal(
        verify(&fx, Some(&wrong_clock), &blob, at),
        "approval.attestation_invalid",
        "the consent clocks do not match the signed facts",
    );
    refusal(
        verify(&fx, None, &blob, at),
        "approval.not_found",
        "no durable approval record for that nonce",
    );
    refusal(
        verify(&fx, Some(&no_consent), &blob, at),
        "approval.presence_required",
        "Mainnet consent requires a verified assertion from an approval credential in the owner-signed policy; use the local passkey approval page.",
    );
    refusal(
        verify(
            &fx,
            Some(&no_consent),
            &blob,
            no_consent.record().expires_at_ms,
        ),
        "approval.expired",
        "the consent is outside the waiting window",
    );
    let released = changed(&original, |r| r.consent.as_mut().unwrap().payload = None);
    refusal(
        verify(&fx, Some(&released), &blob, at),
        "approval.expired",
        "the approval is outside its execution window",
    );
    for base in [&original, &released, &no_consent] {
        let revoked = changed(base, |r| {
            r.disposition = ApprovalDisposition::Revoked;
            r.revoked_at_ms = Some(at);
        });
        refusal(
            verify(&fx, Some(&revoked), &blob, at + 1_000_000),
            "approval.revoked",
            "this approval has been revoked",
        );
    }
    fx.store
        .mint_authorization(fx.fixture.profile(), &fx.mint_request())
        .unwrap();
    let consumed = facts(&fx);
    assert!(
        verify(&fx, Some(&consumed), &blob, at).is_ok(),
        "retained consumed consent verifies"
    );
    let revoked_consumed = changed(&consumed, |r| r.disposition = ApprovalDisposition::Revoked);
    refusal(
        verify(&fx, Some(&revoked_consumed), &blob, at),
        "approval.revoked",
        "this approval has been revoked",
    );
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn durable_scope_and_policy_are_current() {
    let mut fx = Fx::new(300_000);
    fx.open();
    fx.consent();
    let original = facts(&fx);
    let at = fx.payload.receipt.verified_at_unix_ms();
    let policy = fx.fixture.current_policy();
    let (control, control_blob) =
        scope_proof(&original, &policy, fx.fixture.name(), Caip2::Mainnet);
    assert!(
        verify(&fx, Some(&control), &control_blob, at).is_ok(),
        "independent envelope challenge verifies"
    );
    for (name, chain) in [
        ("other", Caip2::Mainnet),
        (fx.fixture.name(), Caip2::Testnet),
    ] {
        let (foreign, blob) = scope_proof(&original, &policy, name, chain);
        refusal(
            verify(&fx, Some(&foreign), &blob, at),
            "approval.binding_mismatch",
            "the durable approval has another profile or chain",
        );
    }
    let mut testnet = fx.fixture.profile().clone();
    testnet.chain_id = Caip2::Testnet;
    let expected = ApprovalExpectation {
        kind: fx.facts.kind,
        subject: fx.facts.subject,
    };
    let (foreign, blob) = scope_proof(&original, &policy, fx.fixture.name(), Caip2::Testnet);
    refusal(
        verify_durable_approval(
            Some(&foreign),
            &blob,
            &testnet,
            fx.fixture.name(),
            &expected,
            &policy,
            at,
        ),
        "approval.binding_mismatch",
        "the durable approval has another profile or chain",
    );
    for (kind, subject, code) in [
        (ApprovedKind::Claim, fx.facts.subject, "approval.wrong_kind"),
        (fx.facts.kind, [0x98; 32], "approval.attestation_invalid"),
    ] {
        let result = verify_durable_approval(
            Some(&original),
            &fx.payload.attestation,
            fx.fixture.profile(),
            fx.fixture.name(),
            &ApprovalExpectation { kind, subject },
            &policy,
            at,
        );
        assert!(result.is_err(), "expected subject refusal {code}");
        assert_eq!(result.unwrap_err().code(), code);
    }
    assert_eq!(
        verify_durable_approval(
            Some(&original),
            &fx.payload.attestation,
            &testnet,
            fx.fixture.name(),
            &expected,
            &policy,
            at
        )
        .unwrap_err()
        .code(),
        "approval.binding_mismatch"
    );
    assert_eq!(
        verify_durable_approval(
            None,
            &fx.payload.attestation,
            &testnet,
            fx.fixture.name(),
            &expected,
            &policy,
            at
        )
        .unwrap_err()
        .code(),
        "approval.not_found"
    );
    let body = std::fs::read_to_string(fx.fixture.policy_path()).unwrap();
    fx.fixture.write_signed(
        &body
            .split("[signature]")
            .next()
            .unwrap()
            .replace("sequence = 1", "sequence = 2"),
    );
    assert_eq!(
        verify_durable_approval(
            Some(&original),
            &fx.payload.attestation,
            fx.fixture.profile(),
            fx.fixture.name(),
            &expected,
            &policy,
            at
        )
        .unwrap_err()
        .code(),
        "approval.presence_policy_unavailable"
    );
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn presented_attestation_must_match_the_record() {
    let mut fx = Fx::new(300_000);
    fx.open();
    fx.consent();
    let original = facts(&fx);
    let at = fx.payload.receipt.verified_at_unix_ms();
    let mut forged = fx.payload.attestation;
    forged[0] ^= 1;
    refusal(
        verify(&fx, Some(&original), &forged, at),
        "approval.attestation_invalid",
        "the attestation does not verify",
    );
    let mut inbox = stellar_agent_core::approval::store::PendingApprovalStore::open(
        fx.fixture.home().join("first.toml"),
    )
    .unwrap();
    let mut entry = inbox.get(&fx.facts.nonce).unwrap().clone();
    entry.attestation_blob_b64 = None;
    entry.attested_approver = None;
    entry.mainnet_presence = None;
    inbox.remove(&fx.facts.nonce).unwrap();
    drop(inbox);
    let (other_inbox, _) = fx.fixture.consent(&entry);
    let other_receipt = other_inbox
        .get(&entry.approval_nonce)
        .unwrap()
        .mainnet_presence
        .clone()
        .unwrap();
    let foreign = stellar_agent_core::approval::compute_attestation_v5(
        &stellar_agent_core::approval::mainnet_fixtures::ATTESTATION_KEY,
        &fx.fixture.binding(),
        &fx.facts.nonce,
        &fx.facts.subject,
        &fx.payload.process_uid,
        &AttestedLifetime::new(
            "PaymentSimulated",
            fx.facts.created_at_ms,
            fx.facts.waiting_expires_at_ms,
        ),
        &AttestedApprover::MainnetPasskey {
            credential_id_b64url: other_receipt.credential_id_b64url(),
        },
        &other_receipt,
    );
    refusal(
        verify(&fx, Some(&original), &foreign, at),
        "approval.attestation_invalid",
        "the attestation does not verify",
    );
    let inconsistent = changed(&original, |r| {
        let consent = r.consent.as_mut().unwrap();
        consent.consent_at_ms = other_receipt.verified_at_unix_ms();
        consent.execution_expires_at_ms = consent.consent_at_ms + r.rule_ttl_ms;
        let payload = consent.payload.as_mut().unwrap();
        payload.receipt = other_receipt.clone();
        payload.attestation = foreign;
    });
    refusal(
        verify(
            &fx,
            Some(&inconsistent),
            &foreign,
            other_receipt.verified_at_unix_ms(),
        ),
        "approval.attestation_invalid",
        "the attestation does not verify",
    );
    let valid = changed(&inconsistent, |r| {
        r.consent.as_mut().unwrap().receipt_sha256 = other_receipt.digest().unwrap()
    });
    assert!(
        verify(
            &fx,
            Some(&valid),
            &foreign,
            other_receipt.verified_at_unix_ms()
        )
        .is_ok()
    );
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn durable_envelope_bounds_refuse_alone() {
    for ttl in [300_000, 86_400_000] {
        let mut fx = Fx::new(ttl);
        fx.open();
        fx.consent();
        let original = facts(&fx);
        let c = original.record().consent.as_ref().unwrap();
        let end = original
            .record()
            .expires_at_ms
            .min(c.execution_expires_at_ms);
        assert!(verify(&fx, Some(&original), &fx.payload.attestation, end - 1).is_ok());
        for at in [end, end + 1] {
            let text = if ttl == 300_000 {
                "the approval is outside its lifetime"
            } else {
                "the approval is outside its execution window"
            };
            refusal(
                verify(&fx, Some(&original), &fx.payload.attestation, at),
                "approval.expired",
                text,
            );
        }
        refusal(
            verify(
                &fx,
                Some(&original),
                &fx.payload.attestation,
                original.record().created_at_ms - 1,
            ),
            "approval.expired",
            "the approval is outside its lifetime",
        );
        let earlier = changed(&original, |r| {
            r.consent.as_mut().unwrap().execution_expires_at_ms = end - 10
        });
        refusal(
            verify(&fx, Some(&earlier), &fx.payload.attestation, end - 10),
            "approval.expired",
            "the approval is outside its execution window",
        );
        assert_eq!(
            verify(&fx, Some(&original), &fx.payload.attestation, end - 1)
                .unwrap()
                .challenge_subject(),
            None
        );
    }
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn missing_intent_challenge_refuses_before_retention() {
    let mut fx = Fx::new(300_000);
    fx.facts.subject_kind = SubjectKind::IntentDigest;
    // This negative combination cannot come from the producer. A valid V6 HMAC
    // isolates the missing witness field from the later payload authentication.
    fx.payload.attestation = stellar_agent_core::approval::compute_attestation_v6(
        &stellar_agent_core::approval::mainnet_fixtures::ATTESTATION_KEY,
        &fx.fixture.binding(),
        &fx.facts.nonce,
        &fx.facts.subject,
        &fx.payload.process_uid,
        &AttestedLifetime::new(
            "PaymentSimulated",
            fx.facts.created_at_ms,
            fx.facts.waiting_expires_at_ms,
        ),
        &AttestedApprover::MainnetPasskey {
            credential_id_b64url: fx.payload.receipt.credential_id_b64url(),
        },
        &fx.payload.receipt,
    );
    fx.open();
    let id = fx.id();
    let before = fx.bytes();
    let result = ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "request")
        .record_consent(id, &fx.witness, &fx.payload);
    assert!(
        result.is_err(),
        "a missing witness challenge cannot record consent"
    );
    let error = result.unwrap_err();
    assert!(
        matches!(error, WindowStoreError::UnexpectedState { detail } if detail == "the intent witness lacks its challenge subject")
    );
    assert_eq!(fx.bytes(), before);
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn durable_x402_envelope_record_verifies() {
    let mut fx = Fx::x402(300_000);
    fx.open();
    let id = fx.id();
    let consent = ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "x402")
        .record_consent(id, &fx.witness, &fx.payload);
    assert!(
        consent.is_ok(),
        "durable x402 consent retains the kind scope"
    );
    let verified = verify(
        &fx,
        Some(&facts(&fx)),
        &fx.payload.attestation,
        fx.payload.receipt.verified_at_unix_ms(),
    );
    assert!(verified.is_ok(), "durable x402 envelope verifies");
    let witness = verified.unwrap();
    assert_eq!(witness.kind(), ApprovedKind::X402Payment);
    assert_eq!(witness.kind().kind_name(), "X402Payment");
}

pub(crate) struct IntentFx {
    pub(crate) fixture: stellar_agent_core::approval::mainnet_fixtures::MainnetConsentFixture,
    intent: ClassicIntent,
    pub(crate) facts: ApprovalFacts,
    pub(crate) policy: VerifiedPolicy,
    blob: [u8; 32],
    pub(crate) _clock: crate::mainnet::clock::TestClockGuard,
}

impl IntentFx {
    pub(crate) fn new(ttl: u64) -> Self {
        use super::super::operations::{
            BusinessId, IntentSlot, OpenOutcome, OpenRequest, OperationKind, OperationTool,
        };
        let fixture = stellar_agent_core::approval::mainnet_fixtures::MainnetConsentFixture::new(
            "durable-intent",
        );
        let policy = fixture.current_policy();
        let (mut entry, intent) = fixture.intent_payment(ttl);
        entry.created_at_unix_ms -= 60_000;
        entry.expires_at_unix_ms -= 60_000;
        let (inbox, surfaced) = fixture.intent_consent(&entry, &intent);
        let blob = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(surfaced.unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let receipt = inbox
            .get(&entry.approval_nonce)
            .unwrap()
            .mainnet_presence
            .clone()
            .unwrap();
        let at = receipt.verified_at_unix_ms();
        let witness = stellar_agent_core::approval::witness::verify_intent_approval(
            &inbox,
            fixture.profile(),
            fixture.name(),
            &entry.approval_nonce,
            &blob,
            &intent,
            &fixture.decision(ttl),
            &policy,
            at,
        )
        .unwrap();
        let clock = crate::mainnet::clock::set_now_ms_for_test(at);
        let store = PersistedWindowStore::at_path(
            stellar_agent_core::profile::schema::default_policy_window_state_path_for(
                fixture.name(),
            ),
        );
        let mut rows = super::tests::Rows::default();
        let OpenOutcome::New(handle) =
            OperationRecorder::new(&store, fixture.profile(), &mut rows, "request")
                .open(&OpenRequest {
                    business_id: BusinessId::parse("durable-intent").unwrap(),
                    tool: OperationTool::CliPay,
                    kind: OperationKind::Pay,
                    intent: IntentSlot::Canonical {
                        intent_digest: *intent.digest().as_bytes(),
                        intent: serde_json::json!({"op":"pay"}),
                    },
                    envelope_xdr: None,
                    prepared_decision: None,
                    rule_ttl_ms: Some(ttl),
                })
                .unwrap()
        else {
            panic!("new operation");
        };
        let pending = PendingApprovalFacts {
            nonce: entry.approval_nonce.clone(),
            kind: witness.kind(),
            subject_kind: SubjectKind::IntentDigest,
            subject: witness.subject(),
            intent_digest: *intent.digest().as_bytes(),
            created_at_ms: entry.created_at_unix_ms,
            waiting_expires_at_ms: entry.expires_at_unix_ms,
            rule_ttl_ms: ttl,
        };
        let mut recorder = ApprovalRecorder::new(&store, fixture.profile(), &mut rows, "request");
        let record = recorder
            .open_pending(handle.id(), &pending, PolicyDecision::RequireApproval)
            .unwrap()
            .record;
        recorder
            .record_consent(
                record.id,
                &witness,
                &ConsentPayload::new(
                    blob,
                    receipt,
                    entry.process_uid.clone(),
                    ConsentRow::Written,
                ),
            )
            .unwrap();
        let facts = ApprovalStatus::new(&store, fixture.profile())
            .facts_by_nonce(&entry.approval_nonce)
            .unwrap()
            .unwrap();
        drop(inbox);
        Self {
            fixture,
            intent,
            facts,
            policy,
            blob,
            _clock: clock,
        }
    }

    pub(crate) fn decision(&self, decision: Decision, ttl: u64, at: u64) -> MainnetDecision {
        MainnetDecision::for_test(
            decision,
            None,
            self.policy.digest(),
            self.policy.sequence(),
            0,
            self.fixture.name(),
            Caip2::Mainnet.caip2_str(),
            at,
            ttl,
            AuthorityScope::Classic,
        )
    }

    fn at(&self) -> u64 {
        self.facts.record().consent.as_ref().unwrap().consent_at_ms
    }

    pub(crate) fn verify(
        &self,
        facts: &ApprovalFacts,
        decision: &MainnetDecision,
        at: u64,
    ) -> Result<ApprovalWitness, WalletError> {
        verify_durable_intent_approval(
            Some(facts),
            &self.blob,
            self.fixture.profile(),
            self.fixture.name(),
            &self.intent,
            decision,
            &self.policy,
            at,
        )
    }
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn durable_intent_clocks_and_signed_digest_survive_retry() {
    use sha2::Digest as _;
    for (ttl, window) in [(300_000, 300_000), (86_400_000, 900_000)] {
        let fx = IntentFx::new(ttl);
        let decision = fx.fixture.decision(ttl);
        let r = fx.facts.record();
        let at = fx.at();
        let end = at + window;
        assert!(at > r.created_at_ms);
        for retry in [at, end - 1] {
            let witness = fx.verify(&fx.facts, &decision, retry).unwrap();
            assert_eq!(witness.consent_at_ms(), at, "retry preserves consent");
            assert_eq!(
                witness.execution_expires_at_ms(),
                end,
                "signed TTL caps execution"
            );
            assert_eq!(witness.created_at_ms(), r.created_at_ms);
            assert_eq!(witness.expires_at_ms(), r.expires_at_ms);
            let mut bytes = b"stellar-agent-authz-fact:approval:v1".to_vec();
            for value in [
                fx.fixture.name().as_bytes(),
                Caip2::Mainnet.caip2_str().as_bytes(),
                r.nonce.as_bytes(),
            ] {
                bytes.extend(u32::try_from(value.len()).unwrap().to_be_bytes());
                bytes.extend(value);
            }
            bytes.push(1);
            bytes.extend(r.subject);
            bytes.extend(r.created_at_ms.to_be_bytes());
            bytes.extend(r.expires_at_ms.to_be_bytes());
            bytes.extend(r.consent.as_ref().unwrap().receipt_sha256);
            bytes.extend(fx.policy.digest());
            let independent: [u8; 32] = sha2::Sha256::digest(&bytes).into();
            assert_eq!(
                witness.fact_digest(),
                independent,
                "digest uses signed times"
            );
        }
        for retry in [at - 1, end, end + 1] {
            refusal(
                fx.verify(&fx.facts, &decision, retry),
                "approval.expired",
                "the approval is outside its execution window",
            );
        }
        if ttl == 300_000 {
            for retry in [r.expires_at_ms - 1, r.expires_at_ms, r.expires_at_ms + 1] {
                assert!(
                    fx.verify(&fx.facts, &decision, retry).is_ok(),
                    "timely consent survives waiting expiry"
                );
            }
        }
    }
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn durable_intent_allow_preserves_approval_and_producer_contract() {
    use crate::mainnet::authority::MainnetAuthority;
    let fx = IntentFx::new(300_000);
    let allow = fx.decision(Decision::Allow, 1_000, fx.at() + 2_000);
    let result = fx.verify(&fx.facts, &allow, fx.at() + 2_000);
    assert!(result.is_ok(), "Allow uses the signed execution lifetime");
    let witness = result.unwrap();
    assert_eq!(witness.execution_expires_at_ms(), fx.at() + 300_000);
    assert!(
        matches!(
            MainnetAuthority::from_decision(&allow, Some(&witness)).unwrap(),
            MainnetAuthority::Approval(_)
        ),
        "supplied proof keeps Approval authority"
    );
    for decision in [
        fx.fixture.decision(301_000),
        fx.decision(Decision::Deny(DenyReason::NoMatchingRule), 300_000, fx.at()),
        MainnetDecision::for_test(
            Decision::Allow,
            None,
            fx.policy.digest(),
            fx.policy.sequence(),
            0,
            "another-profile",
            Caip2::Mainnet.caip2_str(),
            fx.at(),
            300_000,
            AuthorityScope::Classic,
        ),
    ] {
        refusal(
            fx.verify(&fx.facts, &decision, fx.at()),
            "approval.attestation_invalid",
            "the decision does not govern this approval",
        );
    }
    let inbox =
        stellar_agent_core::approval::store::PendingApprovalStore::open(fx.fixture.store_path())
            .unwrap();
    let producer_allow = fx.decision(Decision::Allow, 300_000, fx.at());
    refusal(
        stellar_agent_core::approval::witness::verify_intent_approval(
            &inbox,
            fx.fixture.profile(),
            fx.fixture.name(),
            &fx.facts.record().nonce,
            &fx.blob,
            &fx.intent,
            &producer_allow,
            &fx.policy,
            fx.at(),
        ),
        "approval.attestation_invalid",
        "the decision does not govern this approval",
    );
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn durable_subject_dispatch_and_receipt_challenge() {
    let fx = IntentFx::new(300_000);
    let decision = fx.fixture.decision(300_000);
    assert!(
        fx.verify(&fx.facts, &decision, fx.at()).is_ok(),
        "original challenge subject verifies"
    );
    let payload = fx
        .facts
        .record()
        .consent
        .as_ref()
        .unwrap()
        .payload
        .as_ref()
        .unwrap();
    assert_ne!(payload.challenge_subject, Some(fx.facts.record().subject));
    assert_independent_challenge(&fx);
    let wrong_challenge = changed(&fx.facts, |r| {
        r.consent
            .as_mut()
            .unwrap()
            .payload
            .as_mut()
            .unwrap()
            .challenge_subject = Some(r.subject)
    });
    assert_eq!(
        fx.verify(&wrong_challenge, &decision, fx.at())
            .unwrap_err()
            .code(),
        "approval.presence_invalid"
    );
    let expected = ApprovalExpectation {
        kind: ApprovedKind::Payment,
        subject: fx.facts.record().subject,
    };
    assert_eq!(
        verify_durable_approval(
            Some(&fx.facts),
            &fx.blob,
            fx.fixture.profile(),
            fx.fixture.name(),
            &expected,
            &fx.policy,
            fx.at()
        )
        .unwrap_err()
        .code(),
        "approval.wrong_kind"
    );
    for (subject_kind, kind) in [
        (SubjectKind::EnvelopeText, ApprovedKind::Payment),
        (SubjectKind::IntentDigest, ApprovedKind::X402Payment),
    ] {
        let crossed = changed(&fx.facts, |r| {
            r.subject_kind = subject_kind;
            r.kind = kind;
        });
        assert_eq!(
            fx.verify(&crossed, &decision, fx.at()).unwrap_err().code(),
            "approval.wrong_kind"
        );
    }
    for field in ["version", "assertion"] {
        let mut record = fx.facts.record().clone();
        let consent = record.consent.as_mut().unwrap();
        let payload = consent.payload.as_mut().unwrap();
        let mut json = serde_json::to_value(&payload.receipt).unwrap();
        if field == "version" {
            json["version"] = 1.into();
        } else {
            let byte = json["assertion"]["signature_compact"][63].as_u64().unwrap();
            json["assertion"]["signature_compact"][63] = (byte ^ 1).into();
        }
        payload.receipt = serde_json::from_value(json).unwrap();
        consent.receipt_sha256 = payload.receipt.digest().unwrap();
        payload.attestation = stellar_agent_core::approval::compute_attestation_v6(
            &stellar_agent_core::approval::mainnet_fixtures::ATTESTATION_KEY,
            &fx.fixture.binding(),
            &record.nonce,
            &record.subject,
            &payload.process_uid,
            &AttestedLifetime::new(
                "PaymentSimulated",
                record.created_at_ms,
                record.expires_at_ms,
            ),
            &AttestedApprover::MainnetPasskey {
                credential_id_b64url: payload.receipt.credential_id_b64url(),
            },
            &payload.receipt,
        );
        let blob = payload.attestation;
        let forged = ApprovalFacts::new(fx.facts.profile().to_owned(), fx.facts.chain(), record);
        assert_eq!(
            verify_durable_intent_approval(
                Some(&forged),
                &blob,
                fx.fixture.profile(),
                fx.fixture.name(),
                &fx.intent,
                &decision,
                &fx.policy,
                fx.at()
            )
            .unwrap_err()
            .code(),
            "approval.presence_invalid",
            "receipt {field}"
        );
    }
}

fn assert_independent_challenge(fx: &IntentFx) {
    let receipt = &fx
        .facts
        .record()
        .consent
        .as_ref()
        .unwrap()
        .payload
        .as_ref()
        .unwrap()
        .receipt;
    let json = serde_json::to_value(receipt).unwrap();
    let client_bytes: Vec<u8> =
        serde_json::from_value(json["assertion"]["client_data_json"].clone()).unwrap();
    let client: serde_json::Value = serde_json::from_slice(&client_bytes).unwrap();
    assert_eq!(
        client["challenge"],
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(independent_challenge(&fx.facts, &fx.policy)),
        "independent challenge preimage"
    );
}

// Independent fixture preimages for receipts without a certificate pin.
fn independent_challenge(facts: &ApprovalFacts, policy: &VerifiedPolicy) -> [u8; 32] {
    use sha2::Digest as _;
    use stellar_agent_core::approval::presence::MAINNET_APPROVAL_RP_ID;
    let record = facts.record();
    let payload = record.consent.as_ref().unwrap().payload.as_ref().unwrap();
    let receipt = &payload.receipt;
    let json = serde_json::to_value(receipt).unwrap();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let intent = record.subject_kind == SubjectKind::IntentDigest;
    let mut preimage = if intent {
        b"stellar-agent-wallet/intent-challenge/v1".to_vec()
    } else {
        b"stellar-agent-mainnet-presence:v1".to_vec()
    };
    preimage.extend(b64.decode(json["random_b64url"].as_str().unwrap()).unwrap());
    let lp = |bytes: &mut Vec<u8>, value: &[u8]| {
        bytes.extend(u32::try_from(value.len()).unwrap().to_be_bytes());
        bytes.extend(value);
    };
    for value in [
        receipt.request_id(),
        record.nonce.as_str(),
        facts.profile(),
        facts.chain().caip2_str(),
        "PaymentSimulated",
    ] {
        lp(&mut preimage, value.as_bytes());
    }
    preimage.extend(if intent {
        payload.challenge_subject.unwrap()
    } else {
        record.subject
    });
    lp(&mut preimage, payload.process_uid.as_bytes());
    preimage.extend(record.created_at_ms.to_be_bytes());
    preimage.extend(record.expires_at_ms.to_be_bytes());
    preimage.extend(policy.sequence().to_be_bytes());
    preimage.extend(policy.digest());
    preimage.extend(policy.owner());
    if intent {
        preimage.push(1);
        preimage.extend(record.subject);
    }
    lp(&mut preimage, MAINNET_APPROVAL_RP_ID.as_bytes());
    lp(&mut preimage, receipt.expected_origin().as_bytes());
    if intent {
        preimage.push(0);
    }
    preimage.extend(receipt.issued_at_unix_ms().to_be_bytes());
    preimage.extend(receipt.expires_at_unix_ms().to_be_bytes());
    sha2::Sha256::digest(preimage).into()
}

fn scope_proof(
    original: &ApprovalFacts,
    policy: &VerifiedPolicy,
    name: &str,
    chain: Caip2,
) -> (ApprovalFacts, [u8; 32]) {
    use stellar_agent_core::approval::{
        mainnet_fixtures::ATTESTATION_KEY, presence::MAINNET_APPROVAL_RP_ID,
    };
    use stellar_agent_test_support::webauthn::{FLAG_UP, FLAG_UV, fixture_authenticator};
    // The producer refuses foreign scope. Sign both proofs independently so
    // removing the scope check admits them instead of reaching another refusal.
    let facts = ApprovalFacts::new(name.to_owned(), chain, original.record().clone());
    let challenge = independent_challenge(&facts, policy);
    let mut record = facts.record().clone();
    let consent = record.consent.as_mut().unwrap();
    let payload = consent.payload.as_mut().unwrap();
    let assertion = fixture_authenticator().assert(
        challenge,
        payload.receipt.expected_origin(),
        MAINNET_APPROVAL_RP_ID,
        FLAG_UP | FLAG_UV,
        1,
    );
    let mut json = serde_json::to_value(&payload.receipt).unwrap();
    json["assertion"] = serde_json::json!({
        "credential_id": assertion.credential_id, "authenticator_data": assertion.authenticator_data,
        "client_data_json": assertion.client_data_json, "signature_compact": assertion.signature_compact,
    });
    payload.receipt = serde_json::from_value(json).unwrap();
    consent.receipt_sha256 = payload.receipt.digest().unwrap();
    let blob = stellar_agent_core::approval::compute_attestation_v5(
        &ATTESTATION_KEY,
        &AttestationBinding::new(name, chain.caip2_str()),
        &record.nonce,
        &record.subject,
        &payload.process_uid,
        &AttestedLifetime::new(
            "PaymentSimulated",
            record.created_at_ms,
            record.expires_at_ms,
        ),
        &AttestedApprover::MainnetPasskey {
            credential_id_b64url: payload.receipt.credential_id_b64url(),
        },
        &payload.receipt,
    );
    payload.attestation = blob;
    (ApprovalFacts::new(name.to_owned(), chain, record), blob)
}
