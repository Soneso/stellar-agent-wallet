//! Decision authority at every classic CLI value boundary.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]

use serde_json::{Value, json};
use stellar_agent_core::policy::v1::{canonical::canonical_bytes, signature::digest};

use crate::commands::accounts::create::tests::mainnet_full as create;
use crate::commands::claim::tests::mainnet_full as claim;
use crate::commands::pay::tests::mainnet_full as pay;
use crate::commands::trustline::tests::mainnet_full as trustline;
use crate::common::mainnet_write_fixture::{
    AGENT_SEED, DESTINATION, ISSUER, MainnetFixture, Spec, claim_rule, create_rule, pay_rule,
    trustline_rule,
};
use crate::common::signer_ceremony::signer_resolutions_on_this_thread;
use crate::test_rpc::ClassicRpc;

#[derive(Clone, Copy)]
enum Verb {
    Pay,
    Claim,
    Create,
    Trustline,
}

impl Verb {
    const ALL: [Self; 4] = [Self::Pay, Self::Claim, Self::Create, Self::Trustline];

    fn rule(self, decision: &str, extra: &str) -> String {
        match self {
            Self::Pay => pay_rule(decision, extra),
            Self::Claim => claim_rule(decision, extra),
            Self::Create => create_rule(decision, extra),
            Self::Trustline => trustline_rule(decision, extra),
        }
    }

    fn index(self) -> u32 {
        match self {
            Self::Pay => 0,
            Self::Create => 1,
            Self::Claim => 2,
            Self::Trustline => 3,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Pay => "pay",
            Self::Claim => "claim",
            Self::Create => "accounts create",
            Self::Trustline => "trustline",
        }
    }

    fn tool(self) -> &'static str {
        match self {
            Self::Pay => "stellar_pay",
            Self::Claim => "stellar_claim",
            Self::Create => "stellar_create_account",
            Self::Trustline => "stellar_trustline",
        }
    }

    fn ledger(self) -> ClassicRpc {
        let agent = stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
        match self {
            Self::Pay | Self::Create => ClassicRpc::mainnet(&[&agent, DESTINATION, ISSUER]),
            Self::Claim => claim::ledger(true, 100_000_000),
            Self::Trustline => trustline::ledger(true, 0),
        }
    }

    fn spec(self, name: &'static str) -> Spec {
        Spec::new(name).primary(self.ledger()).oracle(self.ledger())
    }

    async fn run(self, fixture: &MainnetFixture) -> (i32, Value) {
        self.run_as(fixture, None).await
    }

    /// Runs the verb on `fixture` under `business_id`, or under a fresh id.
    async fn run_as(self, fixture: &MainnetFixture, business_id: Option<&str>) -> (i32, Value) {
        let id = |args_id: &mut Option<String>| {
            if let Some(business_id) = business_id {
                *args_id = Some(business_id.to_owned());
            }
        };
        match self {
            Self::Pay => {
                let mut args = pay::mainnet_args(fixture);
                id(&mut args.business_id);
                crate::common::render::take_rendered_for_test();
                let code = pay::run_code(fixture, &args).await;
                let documents = crate::common::render::take_rendered_for_test();
                assert_eq!(documents.len(), 1, "one stdout envelope");
                (code, documents.into_iter().next().unwrap())
            }
            Self::Claim => {
                let mut args = claim::mainnet_args(fixture);
                id(&mut args.business_id);
                let r = claim::run(fixture, &args).await;
                (r.code, r.envelope)
            }
            Self::Create => {
                let mut args = create::mainnet_args(fixture);
                id(&mut args.business_id);
                crate::common::render::take_rendered_for_test();
                let code = create::run_code(fixture, &args).await;
                let documents = crate::common::render::take_rendered_for_test();
                assert_eq!(documents.len(), 1, "one stdout envelope");
                (code, documents.into_iter().next().unwrap())
            }
            Self::Trustline => {
                let mut args = trustline::mainnet_args(fixture);
                id(&mut args.business_id);
                let r = trustline::run(fixture, &args).await;
                (r.code, r.envelope)
            }
        }
    }
}

/// Records queued delivery for the witness's record, then drops the queued
/// row from the outbox, so delivery cannot be proven. Production publication
/// cannot lose the row after the commit; this fixture builds that state.
fn record_dropped_delivery_fixture(
    profile: &stellar_agent_core::profile::Profile,
    witness: &stellar_agent_core::approval::witness::ApprovalWitness,
) {
    use stellar_agent_core::audit_log::{AuditEntry, AuditOutbox, BindingCheck};
    use stellar_agent_network::policy_state::PersistedWindowStore;
    use stellar_agent_network::policy_state::approvals::{
        ApprovalRecorder, ApprovalStatus, ConsentDeliveryV1,
        seed_existing_consent_delivery_for_test,
    };
    let name = witness.profile();
    let store = PersistedWindowStore::for_profile(name);
    let record = ApprovalStatus::new(&store, profile)
        .find_by_nonce(witness.nonce())
        .unwrap()
        .unwrap()
        .record;
    let id = record.id;
    let writer = crate::commands::value_audit::require_value_audit_writer(profile, name).unwrap();
    let mut writer = writer.lock().unwrap();
    writer.initialize_consent_evidence().unwrap();
    let (key, anchor) =
        stellar_agent_network::keyring::keyed_audit_access(profile, name, BindingCheck::Enforce)
            .unwrap()
            .into_parts();
    let outbox = AuditOutbox::for_log_keyed(&profile.audit_log_path, anchor, key.clone());
    let reservation = outbox
        .reserve_evidence(
            id,
            stellar_agent_core::audit_log::EvidenceReservation::deadline(
                record.waiting_expires_at_ms,
                record.rule_ttl_ms,
            )
            .unwrap(),
            witness.consent_at_ms(),
        )
        .unwrap();
    let reference = outbox
        .clone()
        .with_evidence_reservation(reservation)
        .append_queued(&AuditEntry::new_approval_attested(
            witness.kind().kind_name(),
            "stellar_pay_commit",
            None,
            witness.nonce(),
            "cli",
            "delivery-fixture",
        ))
        .unwrap();
    std::fs::write(
        outbox.path(),
        stellar_agent_core::audit_log::outbox::test_seam::generation_line(
            &key,
            reference.generation(),
        ),
    )
    .unwrap();
    seed_existing_consent_delivery_for_test(
        &mut ApprovalRecorder::new(&store, profile, &mut *writer, "fixture"),
        id,
        Some(reference),
        ConsentDeliveryV1::queued(id),
    )
    .unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn all_value_verbs_require_delivered_consent() {
    use stellar_agent_core::approval::witness::ApprovedKind;
    use stellar_agent_network::policy_state::approvals::ConsentEvidenceEnforcementGuard;
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let names = [
        ["delivery-pay-missing", "delivery-pay-allow"],
        ["delivery-claim-missing", "delivery-claim-allow"],
        ["delivery-create-missing", "delivery-create-allow"],
        ["delivery-trust-missing", "delivery-trust-allow"],
    ];
    for (verb, names) in Verb::ALL.into_iter().zip(names) {
        let kind = match verb {
            Verb::Pay | Verb::Create => ApprovedKind::Payment,
            Verb::Claim => ApprovedKind::Claim,
            Verb::Trustline => ApprovedKind::Trustline,
        };
        let fixture = verb.spec(names[0]).build().await;
        let enabled = std::rc::Rc::new(std::cell::RefCell::new(None));
        let at_consumer = enabled.clone();
        let hook = crate::common::mainnet_write::consent_test::on_witness(
            fixture.name,
            move |profile, witness| {
                record_dropped_delivery_fixture(profile, witness);
                at_consumer.replace(Some(ConsentEvidenceEnforcementGuard::new(
                    witness.profile(),
                    kind,
                )));
            },
        );
        let before = signer_resolutions_on_this_thread();
        let (code, envelope) = verb.run(&fixture).await;
        assert_eq!(code, 1, "missing delivery: {envelope}");
        assert_eq!(
            envelope["error"]["code"], "approval.consent_undelivered",
            "{envelope}"
        );
        assert_eq!(
            signer_resolutions_on_this_thread(),
            before,
            "delivery precedes the signer"
        );
        assert!(fixture.sent_envelopes().await.is_empty());
        assert!(
            fixture
                .open_authorizations(stellar_agent_core::timefmt::now_unix_ms().unwrap())
                .is_empty()
        );
        drop(hook);
        drop(enabled);
        let fixture = verb
            .spec(names[1])
            .rules(vec![verb.rule("allow", "")])
            .build()
            .await;
        let profile = fixture.profile();
        let _enabled = ConsentEvidenceEnforcementGuard::new(fixture.name, kind);
        let writer =
            crate::commands::value_audit::require_value_audit_writer(&profile, fixture.name)
                .unwrap();
        writer
            .lock()
            .unwrap()
            .initialize_consent_evidence()
            .unwrap();
        let (key, anchor) = stellar_agent_network::keyring::keyed_audit_access(
            &profile,
            fixture.name,
            stellar_agent_core::audit_log::BindingCheck::Enforce,
        )
        .unwrap()
        .into_parts();
        stellar_agent_core::audit_log::outbox::test_seam::conflicting_evidence(
            &profile.audit_log_path,
            &key,
        )
        .unwrap();
        let outbox = stellar_agent_core::audit_log::AuditOutbox::for_log_keyed(
            &profile.audit_log_path,
            anchor,
            key,
        );
        assert!(
            outbox
                .evidence_time_floor()
                .unwrap_err()
                .to_string()
                .contains("owner rollback")
        );
        let queries = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = queries.clone();
        let _query_hook = stellar_agent_core::audit_log::outbox::test_seam::on_delivery_query(
            &profile.audit_log_path,
            move || {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            },
        );
        let (code, result) = verb.run(&fixture).await;
        assert_eq!(code, 0, "Allow beside rollback evidence: {result}");
        assert_eq!(
            queries.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "Allow reads no evidence"
        );
        fixture.assert_no_consent_ceremony();
    }
}

/// With delivery enforced from preparation on, each value verb publishes its
/// consent through the production producer and resolves its signer exactly
/// once. A revocation or a submission receipt between the consent commit and the
/// authority refuses with its exact envelope and exit 1, before the signer,
/// with nothing sent and no open authorization.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn cli_durable_state_envelopes() {
    use crate::common::mainnet_confirm::commit_test;
    use crate::common::mainnet_confirm::tests::committed::{hold_receipt, revoke};
    use stellar_agent_core::approval::witness::ApprovedKind;
    use stellar_agent_network::policy_state::approvals::ConsentEvidenceEnforcementGuard;
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let names = [
        ["state-pay-ok", "state-pay-revoked", "state-pay-spent"],
        ["state-claim-ok", "state-claim-revoked", "state-claim-spent"],
        [
            "state-create-ok",
            "state-create-revoked",
            "state-create-spent",
        ],
        ["state-trust-ok", "state-trust-revoked", "state-trust-spent"],
    ];
    for (verb, names) in Verb::ALL.into_iter().zip(names) {
        let kind = match verb {
            Verb::Pay | Verb::Create => ApprovedKind::Payment,
            Verb::Claim => ApprovedKind::Claim,
            Verb::Trustline => ApprovedKind::Trustline,
        };
        for (state, name) in [None, Some("approval.revoked"), Some("approval.consumed")]
            .into_iter()
            .zip(names)
        {
            let fixture = verb.spec(name).build().await;
            let _enabled = ConsentEvidenceEnforcementGuard::new(fixture.name, kind);
            let profile = fixture.profile();
            let owner = fixture.name.to_owned();
            let committed = std::rc::Rc::new(std::cell::RefCell::new(String::new()));
            let slot = committed.clone();
            let _hook = commit_test::after_commit(fixture.name, move |nonce| {
                slot.replace(nonce.to_owned());
                match state {
                    Some("approval.revoked") => revoke(&profile, &owner, nonce),
                    Some(_) => hold_receipt(&owner, nonce),
                    None => {}
                }
            });
            let before = signer_resolutions_on_this_thread();
            let (code, envelope) = verb.run(&fixture).await;
            let Some(expected) = state else {
                assert_eq!(code, 0, "{} published consent: {envelope}", verb.name());
                assert_eq!(
                    signer_resolutions_on_this_thread(),
                    before + 1,
                    "{}: one signer resolution",
                    verb.name()
                );
                assert_eq!(fixture.sent_envelopes().await.len(), 1);
                continue;
            };
            let message = if expected == "approval.revoked" {
                "this approval has been revoked"
            } else {
                "this approval was already spent on a submission"
            };
            assert_eq!(code, 1, "{} {expected}: {envelope}", verb.name());
            assert_eq!(envelope["ok"], false, "{envelope}");
            assert_eq!(envelope["error"]["code"], expected, "{envelope}");
            assert_eq!(envelope["error"]["message"], message, "{envelope}");
            let nonce = committed.borrow().clone();
            assert!(!nonce.is_empty(), "the consent committed");
            assert!(!envelope.to_string().contains(&nonce), "{envelope}");
            assert_eq!(signer_resolutions_on_this_thread(), before);
            assert!(fixture.sent_envelopes().await.is_empty());
            assert!(
                fixture
                    .open_authorizations(stellar_agent_core::timefmt::now_unix_ms().unwrap())
                    .is_empty()
            );
        }
    }
}

/// The approval kind a verb's consent records.
fn approved_kind(verb: Verb) -> stellar_agent_core::approval::witness::ApprovedKind {
    use stellar_agent_core::approval::witness::ApprovedKind;
    match verb {
        Verb::Pay | Verb::Create => ApprovedKind::Payment,
        Verb::Claim => ApprovedKind::Claim,
        Verb::Trustline => ApprovedKind::Trustline,
    }
}

#[cfg(test)]
mod canonical_activation;

/// The delivered-consent boundary, which holds the audit writer from a second
/// registry name; the source scans read this module as test code.
#[cfg(test)]
mod delivered {
    use super::*;

    /// With delivery enforced from preparation on, each value verb publishes its
    /// consent through the production producer, directly or queued, and signs
    /// only after the drain delivers it. A queued consent is published while
    /// another holder keeps the audit writer through the ceremony; the holder
    /// releases it after the consent commit, and the drain then anchors the row.
    /// A revocation after the committed-consent check refuses at the locked
    /// mint: no signer, nothing sent and no open authorization.
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn cli_delivered_consent_before_signing() {
        use crate::common::mainnet_confirm::commit_test;
        use crate::common::mainnet_confirm::tests::committed::revoke;
        use crate::common::mainnet_presence::driver;
        use stellar_agent_core::audit_log::writer::AuditWriterRegistry;
        use stellar_agent_network::policy_state::approvals::ConsentEvidenceEnforcementGuard;
        use stellar_agent_network::policy_state::{ApprovalStatus, PersistedWindowStore};
        const HOLDER: &str = "delivery-holder";
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let names = [
            [
                "published-pay-direct",
                "published-pay-queued",
                "published-pay-revoked",
            ],
            [
                "published-claim-direct",
                "published-claim-queued",
                "published-claim-revoked",
            ],
            [
                "published-create-direct",
                "published-create-queued",
                "published-create-revoked",
            ],
            [
                "published-trust-direct",
                "published-trust-queued",
                "published-trust-revoked",
            ],
        ];
        for (verb, names) in Verb::ALL.into_iter().zip(names) {
            let kind = approved_kind(verb);
            for (queued, name) in [(false, names[0]), (true, names[1])] {
                let mut fixture = verb.spec(name).build().await;
                let _enabled = ConsentEvidenceEnforcementGuard::new(fixture.name, kind);
                let holder = std::rc::Rc::new(std::cell::RefCell::new(None));
                if queued {
                    let profile = fixture.profile();
                    let owner = fixture.name.to_owned();
                    let slot = holder.clone();
                    let mut answer = driver::fixture_credential();
                    fixture.present_with(move |ceremony| {
                        AuditWriterRegistry::remove_for_test(&owner);
                        *slot.borrow_mut() = Some(
                            AuditWriterRegistry::get_or_open_keyed(
                                HOLDER,
                                &profile.audit_log_path,
                                stellar_agent_network::keyring::keyed_audit_access(
                                    &profile,
                                    &owner,
                                    stellar_agent_core::audit_log::BindingCheck::Enforce,
                                )
                                .unwrap(),
                            )
                            .unwrap(),
                        );
                        answer(ceremony)
                    });
                }
                let profile = fixture.profile();
                let owner = fixture.name.to_owned();
                let released = holder.clone();
                let row = std::rc::Rc::new(std::cell::Cell::new(None));
                let seen = row.clone();
                let _hook = commit_test::after_commit(fixture.name, move |nonce| {
                    let store = PersistedWindowStore::for_profile(&owner);
                    let payload = ApprovalStatus::new(&store, &profile)
                        .find_by_nonce(nonce)
                        .unwrap()
                        .unwrap()
                        .record
                        .consent
                        .unwrap()
                        .payload
                        .unwrap();
                    seen.set(Some(payload.outbox_row.is_some()));
                    drop(released.borrow_mut().take());
                    AuditWriterRegistry::remove_for_test(HOLDER);
                });
                let before = signer_resolutions_on_this_thread();
                let (code, envelope) = verb.run(&fixture).await;
                assert_eq!(code, 0, "{} queued={queued}: {envelope}", verb.name());
                assert_eq!(
                    row.get(),
                    Some(queued),
                    "{}: the record retains the queued reference only when queued",
                    verb.name()
                );
                assert!(signer_resolutions_on_this_thread() > before);
                assert_eq!(fixture.sent_envelopes().await.len(), 1, "{}", verb.name());
            }

            let fixture = verb.spec(names[2]).build().await;
            let _enabled = ConsentEvidenceEnforcementGuard::new(fixture.name, kind);
            let profile = fixture.profile();
            let owner = fixture.name.to_owned();
            let _revoke = crate::common::mainnet_write::consent_test::on_witness(
                fixture.name,
                move |_, witness| revoke(&profile, &owner, witness.nonce()),
            );
            let before = signer_resolutions_on_this_thread();
            let (code, envelope) = verb.run(&fixture).await;
            assert_eq!(
                code,
                1,
                "{} revoked after the check: {envelope}",
                verb.name()
            );
            assert_eq!(
                envelope["error"]["code"], "network.mainnet_authorization_refused",
                "{envelope}"
            );
            assert_eq!(signer_resolutions_on_this_thread(), before);
            assert!(fixture.sent_envelopes().await.is_empty());
            assert!(
                fixture
                    .open_authorizations(stellar_agent_core::timefmt::now_unix_ms().unwrap())
                    .is_empty()
            );
        }
    }
}

/// The CLI producer and consumer rows of the activation matrix: each listed
/// kind's value verb runs under the compiled kind list, with the fixture's
/// opt-outs dropped and no enforcement guard. The confirmation publishes
/// direct delivery and the command signs and sends once. When the evidence
/// image becomes unusable before the consumer's check, the command refuses
/// with the check's refusal before the signer and sends nothing. Payment
/// runs both of its verbs. X402 payment has no CLI value verb; the MCP
/// matrix runs both x402 tools.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn activation_matrix_consumer_rows() {
    use crate::common::unenforced_fixture::listed_kinds;
    use stellar_agent_core::approval::witness::ApprovedKind;
    use stellar_agent_network::policy_state::approvals::delivery_enforced;
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for kind in listed_kinds() {
        let rows: &[(Verb, [&str; 2])] = match kind {
            ApprovedKind::Payment => &[
                (Verb::Pay, ["matrix-pay-ok", "matrix-pay-unusable"]),
                (Verb::Create, ["matrix-create-ok", "matrix-create-unusable"]),
            ],
            ApprovedKind::Claim => &[(Verb::Claim, ["matrix-claim-ok", "matrix-claim-unusable"])],
            ApprovedKind::Trustline => &[(
                Verb::Trustline,
                ["matrix-trust-ok", "matrix-trust-unusable"],
            )],
            ApprovedKind::X402Payment => &[],
            other => panic!("no value verb row for {other:?}"),
        };
        for (unusable, name, verb) in rows.iter().flat_map(|&(verb, names)| {
            [false, true]
                .into_iter()
                .zip(names)
                .map(move |(unusable, name)| (unusable, name, verb))
        }) {
            let mut fixture = verb.spec(name).build().await;
            fixture.enforce_listed();
            assert!(
                delivery_enforced(fixture.name, kind),
                "{kind:?} {name}: the compiled kind list enforces"
            );
            let _hook = unusable.then(|| {
                crate::common::mainnet_write::consent_test::on_witness(
                    fixture.name,
                    |profile, _| {
                        for suffix in [".outbox.evidence.0", ".outbox.evidence.1"] {
                            let mut path = profile.audit_log_path.as_os_str().to_os_string();
                            path.push(suffix);
                            std::fs::write(std::path::PathBuf::from(path), b"invalid image")
                                .unwrap();
                        }
                    },
                )
            });
            let before = signer_resolutions_on_this_thread();
            let (code, envelope) = verb.run(&fixture).await;
            if unusable {
                assert_eq!(code, 1, "{kind:?} {name}: {envelope}");
                assert_eq!(
                    envelope["error"]["code"], "audit.outbox_evidence_unusable",
                    "{kind:?} {name}: the consumer's delivery check refuses: {envelope}"
                );
                assert_eq!(
                    signer_resolutions_on_this_thread(),
                    before,
                    "{kind:?} {name}: delivery precedes the signer"
                );
                assert!(
                    fixture.sent_envelopes().await.is_empty(),
                    "{kind:?} {name}: nothing is sent"
                );
            } else {
                assert_eq!(code, 0, "{kind:?} {name}: {envelope}");
                assert_eq!(
                    fixture.sent_envelopes().await.len(),
                    1,
                    "{kind:?} {name}: one send"
                );
                let window =
                    stellar_agent_network::policy_state::PersistedWindowStore::for_profile(name);
                let record = stellar_agent_network::policy_state::ApprovalStatus::new(
                    &window,
                    &fixture.profile(),
                )
                .find_by_nonce(&fixture.ceremonies()[0].nonce)
                .unwrap()
                .unwrap()
                .record;
                assert_eq!(
                    record.consent.unwrap().delivery,
                    Some(stellar_agent_network::policy_state::approvals::ConsentDeliveryV1::direct_anchored(record.id)),
                    "{kind:?} {name}: the confirmation publishes direct delivery"
                );
            }
        }
    }
}

/// Asserts the governing policy facts on the pending value row.
pub(crate) fn assert_provenance(fixture: &MainnetFixture, approval: bool, index: u32) {
    let raw = std::fs::read_to_string(fixture.policy_path()).unwrap();
    let expected = stellar_agent_core::hex::encode(&digest(&canonical_bytes(&raw).unwrap()));
    assert_eq!(expected.len(), 64);
    let rows = fixture.audit_rows("value_action_pending");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["policy_digest"], expected);
    assert_eq!(rows[0]["rule_index"], index);
    assert_eq!(
        rows[0]["policy_decision"],
        if approval {
            "require_approval"
        } else {
            "allow"
        }
    );
}

/// Asserts that the one inbox approval stays attested and unconsumed after a
/// canonical send: its tombstone waits until the operation ends or its
/// execution window passes, so a successor attempt keeps the consent.
pub(crate) fn assert_consumption_owed(fixture: &MainnetFixture) {
    let entries = fixture.pending_entries();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert!(entries[0].attested, "{entries:?}");
    assert!(
        entries[0].kind_name.ends_with("Simulated"),
        "the approval is not tombstoned at the send: {entries:?}"
    );
}

/// Asserts signature, authority, consent, and audit properties after submission.
pub(crate) async fn assert_authorized(fixture: &MainnetFixture, approval: bool, index: u32) {
    let sent = fixture.sent_envelopes().await;
    assert_eq!(sent.len(), 1);
    fixture.assert_signed_by_agent(&sent[0]);
    assert_provenance(fixture, approval, index);
    let body = fixture.window_body();
    let records = body["authorizations"].as_array().unwrap();
    assert!(!records.is_empty());
    for record in records {
        assert_eq!(
            record.get("policy_authority").is_none(),
            approval,
            "{record}"
        );
        assert_eq!(record.get("approval_nonce").is_some(), approval, "{record}");
    }
    if approval {
        assert_eq!(fixture.summaries().len(), 1);
        assert_eq!(fixture.audit_rows("approval_attested").len(), 1);
        assert_consumption_owed(fixture);
    } else {
        fixture.assert_no_consent_ceremony();
        assert!(fixture.pending_entries().is_empty());
        assert!(fixture.audit_rows("approval_attested").is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_value_verb_follows_the_decision() {
    let names = [
        [
            "authority-pay-allow",
            "authority-pay-approval",
            "authority-pay-refused",
        ],
        [
            "authority-claim-allow",
            "authority-claim-approval",
            "authority-claim-refused",
        ],
        [
            "authority-create-allow",
            "authority-create-approval",
            "authority-create-refused",
        ],
        [
            "authority-trustline-allow",
            "authority-trustline-approval",
            "authority-trustline-refused",
        ],
    ];
    for (verb, names) in Verb::ALL.into_iter().zip(names) {
        for (row, name) in names.into_iter().enumerate() {
            let approval = row != 0;
            let spec = verb.spec(name);
            let spec = if approval {
                spec
            } else {
                spec.rules(vec![verb.rule("allow", "")])
            };
            let mut fixture = spec.build().await;
            fixture.present_with(crate::common::mainnet_presence::driver::credential(
                stellar_agent_test_support::webauthn::fixture_authenticator(),
                if row == 1 { 5 } else { 1 },
            ));
            let before = signer_resolutions_on_this_thread();
            let (code, envelope) = verb.run(&fixture).await;
            if row == 2 {
                assert_eq!(code, 1, "{envelope}");
                assert_eq!(envelope["error"]["code"], "approval.presence_invalid");
                assert_eq!(signer_resolutions_on_this_thread(), before);
                assert!(fixture.sent_envelopes().await.is_empty());
                assert_eq!(
                    fixture.pending_entries().len(),
                    1,
                    "the parked entry stays with its durable record"
                );
                assert!(fixture.audit_rows("approval_attested").is_empty());
            } else {
                assert_eq!(code, 0, "{envelope}");
                assert_eq!(signer_resolutions_on_this_thread(), before + 1);
                assert_authorized(&fixture, approval, if approval { verb.index() } else { 0 })
                    .await;
            }
            assert_eq!(fixture.ceremonies().len(), usize::from(approval));
        }
    }
    for (verb, name) in Verb::ALL.into_iter().zip([
        "authority-pay-hold",
        "authority-claim-hold",
        "authority-create-hold",
        "authority-trustline-hold",
    ]) {
        let fixture = verb
            .spec(name)
            .rules(vec![verb.rule("allow", "")])
            .primary(verb.ledger().with_script(|method, _, _| {
                (method == "getTransaction").then(|| {
                    json!({
                        "status": "FAILED", "latestLedger": 1006, "oldestLedger": 1,
                        "resultXdr": "AAAAAAAAAGT////7AAAAAA=="
                    })
                })
            }))
            .build()
            .await;
        let (code, envelope) = verb.run(&fixture).await;
        assert_eq!(code, 1, "{envelope}");
        assert_eq!(envelope["error"]["code"], "submission.tx_timeout");
        assert_eq!(fixture.pending_reservations(), 1);
        assert_authorized(&fixture, false, 0).await;
    }
}

/// The presence answers a mainnet commit of every value verb meets: each
/// assertion the signed policy does not verify refuses before any signer
/// resolution and any send, and the pinned, user-verified assertion over
/// the issued challenge signs once. The production loopback listener,
/// answered without user verification, refuses the same way.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_value_verb_needs_presence_verified_against_the_signed_policy() {
    use crate::common::mainnet_presence::driver::{
        Driver, credential, fixture_credential, over_another_challenge,
    };
    use stellar_agent_core::error::{ApprovalFailure, WalletError};
    use stellar_agent_test_support::webauthn::{
        FLAG_UP, FLAG_UV, TestAuthenticator, fixture_authenticator,
    };
    /// A presence answer: its label, the driver that gives it, and the
    /// refusal code it meets, or `None` when the commit signs.
    type Answer = (&'static str, fn() -> Driver, Option<&'static str>);
    let answers: [Answer; 5] = [
        (
            "canceled",
            || Box::new(|_| Err(WalletError::Approval(ApprovalFailure::PresenceCanceled))),
            Some("approval.presence_canceled"),
        ),
        (
            "challenge",
            || over_another_challenge(fixture_credential()),
            Some("approval.presence_invalid"),
        ),
        (
            "unverified",
            || credential(fixture_authenticator(), FLAG_UP),
            Some("approval.presence_invalid"),
        ),
        (
            "unpinned",
            || {
                credential(
                    TestAuthenticator::from_seed([0x33; 32], vec![0x44; 16]),
                    FLAG_UP | FLAG_UV,
                )
            },
            Some("approval.presence_invalid"),
        ),
        ("pinned", fixture_credential, None),
    ];
    let mut failures = Vec::new();
    for verb in Verb::ALL {
        for (answer, driver, refusal) in answers {
            let name: &'static str =
                Box::leak(format!("presence-{}-{answer}", verb.tool()).into_boxed_str());
            let mut fixture = verb.spec(name).build().await;
            fixture.present_with(driver());
            let before = signer_resolutions_on_this_thread();
            let (code, envelope) = verb.run(&fixture).await;
            let ceremonies = fixture.ceremonies().len();
            let resolved = signer_resolutions_on_this_thread() - before;
            let sent = fixture.sent_envelopes().await.len();
            let attested = fixture.audit_rows("approval_attested").len();
            let held = match refusal {
                Some(refusal) => {
                    code == 1
                        && envelope["error"]["code"] == refusal
                        && resolved == 0
                        && sent == 0
                        && attested == 0
                }
                None => code == 0 && resolved == 1 && sent == 1 && attested == 1,
            };
            if !held || ceremonies != 1 {
                failures.push(format!(
                    "{} {answer}: exit {code}, {ceremonies} ceremonies, {resolved} signers, \
                     {sent} sent, {attested} attested: {envelope}",
                    verb.name()
                ));
            } else if refusal.is_none() {
                assert_authorized(&fixture, true, verb.index()).await;
            }
        }
        // The production loopback listener, answered with user presence and
        // no user verification, which the core verifier refuses.
        let name: &'static str =
            Box::leak(format!("presence-{}-listener", verb.tool()).into_boxed_str());
        let mut fixture = verb.spec(name).build().await;
        fixture.present_in_browser(FLAG_UP);
        let before = signer_resolutions_on_this_thread();
        let (code, envelope) = verb.run(&fixture).await;
        let resolved = signer_resolutions_on_this_thread() - before;
        let sent = fixture.sent_envelopes().await.len();
        let attested = fixture.audit_rows("approval_attested").len();
        if code != 1
            || envelope["error"]["code"] != "approval.presence_invalid"
            || resolved != 0
            || sent != 0
            || attested != 0
        {
            failures.push(format!(
                "{} listener: exit {code}, {resolved} signers, {sent} sent, \
                 {attested} attested: {envelope}",
                verb.name()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn require_approval_pending_row_carries_provenance() {
    for (verb, name) in Verb::ALL.into_iter().zip([
        "provenance-pay",
        "provenance-claim",
        "provenance-create",
        "provenance-trustline",
    ]) {
        let fixture = verb.spec(name).build().await;
        let (code, envelope) = verb.run(&fixture).await;
        assert_eq!(code, 0, "{envelope}");
        assert_provenance(&fixture, true, verb.index());
    }
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn cli_policy_refusals_render_once_at_the_boundary() {
    use crate::commands::policy_engine::{
        claim_policy_args, create_policy_args, evaluate_mainnet_policy, load_mainnet_policy_engine,
        pay_policy_args, trustline_policy_args,
    };
    use crate::common::mainnet_confirm::render_authority_refusal;
    use crate::common::mainnet_write::{mainnet_context, mainnet_profiles_dir};
    use crate::common::mainnet_write_fixture::{NEW_ACCOUNT, TRUSTLINE_ASSET};
    use stellar_agent_core::mainnet::decision::MainnetRefusal;
    use stellar_agent_core::policy::ToolValueKind;
    use stellar_agent_core::profile::name::{ProfileNameSource, resolve_profile_name};
    use stellar_agent_network::mainnet::authority::AuthorityRefusal;
    let names = [
        [
            "boundary-pay-deny",
            "boundary-pay-engine",
            "boundary-pay-clock",
        ],
        [
            "boundary-claim-deny",
            "boundary-claim-engine",
            "boundary-claim-clock",
        ],
        [
            "boundary-create-deny",
            "boundary-create-engine",
            "boundary-create-clock",
        ],
        [
            "boundary-trustline-deny",
            "boundary-trustline-engine",
            "boundary-trustline-clock",
        ],
    ];
    for (verb, names) in Verb::ALL.into_iter().zip(names) {
        for (case, name) in names.into_iter().enumerate() {
            let extra = if case == 1 {
                "{ kind = \"sep10_session_active\" },".to_owned()
            } else {
                String::new()
            };
            let fixture = verb
                .spec(name)
                .rules(vec![
                    verb.rule(if case == 0 { "deny" } else { "allow" }, &extra),
                ])
                .build()
                .await;
            let context = mainnet_context(
                &fixture.profile(),
                &resolve_profile_name(Some(name)),
                Default::default(),
            )
            .unwrap();
            let policy = load_mainnet_policy_engine(
                verb.name(),
                "policy.engine_unavailable",
                &context,
                ProfileNameSource::Flag,
                &mainnet_profiles_dir().unwrap(),
            )
            .unwrap();
            let args = match verb {
                Verb::Pay => pay_policy_args(10_000_000, "native", DESTINATION),
                Verb::Claim => claim_policy_args("00000000"),
                Verb::Create => create_policy_args(20_000_000, NEW_ACCOUNT),
                Verb::Trustline => trustline_policy_args(&fixture.agent.g, TRUSTLINE_ASSET),
            };
            let _clock = (case == 2).then(stellar_agent_core::policy::v1::criteria::state_store::set_policy_clock_error_for_test);
            let Err(refusal) = evaluate_mainnet_policy(
                &policy.verified,
                context.profile(),
                verb.tool(),
                ToolValueKind::MovesValue,
                context.chain().caip2_str(),
                &args,
                None,
                None,
            ) else {
                panic!("the evaluation must refuse")
            };
            match (&refusal, case) {
                (AuthorityRefusal::Refusal(MainnetRefusal::Denied { .. }), 0)
                | (AuthorityRefusal::Refusal(MainnetRefusal::Engine(_)), 1)
                | (AuthorityRefusal::Refusal(MainnetRefusal::Clock(_)), 2) => {}
                _ => panic!("unexpected typed refusal: {refusal:?}"),
            }
            let (code, message) = match case {
                0 => ("policy.deny.explicit_rule_deny", format!("{} operation denied by operator policy", verb.name())),
                1 => ("policy.engine_required", format!("criterion evaluation failed: sep10_session_active criterion configured for tool '{}' but sep10_sessions view was not populated by the dispatch site; EvalContext::with_sep10_sessions() required", verb.tool())),
                _ => ("wallet.clock_error", "system clock error: wallet clock error: policy clock unavailable (test injection)".to_owned()),
            };
            let mut envelope = render_authority_refusal(verb.name(), refusal);
            envelope.request_id = "guard".to_owned();
            let expected = format!(
                "{{\"ok\":false,\"error\":{{\"code\":\"{code}\",\"message\":\"{message}\"}},\"request_id\":\"guard\"}}"
            );
            assert_eq!(serde_json::to_string(&envelope).unwrap(), expected);
            let mut out = Vec::new();
            assert_eq!(
                crate::common::render::write_envelope(&mut out, &envelope, 1),
                1
            );
            assert_eq!(
                serde_json::from_slice::<Value>(&out).unwrap(),
                serde_json::from_str::<Value>(&expected).unwrap()
            );
            {
                let (exit, mut rendered) = verb.run(&fixture).await;
                assert_eq!(exit, 1, "{rendered}");
                rendered["request_id"] = json!("guard");
                let mut expected: Value = serde_json::from_str(&expected).unwrap();
                if matches!(verb, Verb::Claim) {
                    expected["error"]["details"] = json!({"preview": {
                        "amount_display": "10.0000000", "amount_stroops": "100000000",
                        "asset_code": null, "asset_issuer": null,
                        "balance_id_hex72": format!("00000000{}", "ab".repeat(32)),
                        "balance_id_strkey": "BAAKXK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK6UVM",
                        "claimants": [{"destination": fixture.agent.g, "predicate_kind": "Unconditional"}],
                        "clawback_enabled": false, "is_claimant": true, "predicate_satisfied": true,
                        "window": {"valid_from": null, "valid_until": null}
                    }});
                }
                assert_eq!(rendered, expected);
                fixture.assert_no_consent_ceremony();
                assert!(fixture.sent_envelopes().await.is_empty());
            }
        }
    }
    let source = include_str!("../commands/policy_engine.rs");
    let start = source
        .find("pub(crate) fn evaluate_mainnet_policy(")
        .unwrap();
    let body = &source[start..start + source[start..].find("\n}\n").unwrap()];
    assert!(!body.contains("Envelope"));
    assert!(!body.contains("render_authority_refusal"));
    assert!(!body.contains("unexpected_decision()"));
    assert!(body.contains("MainnetAuthority::from_decision(&decision, None)"));
    assert!(body.contains("AuthorityRefusal::Internal(error)"));
    for source in [
        include_str!("../commands/pay.rs"),
        include_str!("../commands/claim.rs"),
        include_str!("../commands/trustline.rs"),
        include_str!("../commands/accounts/create.rs"),
    ] {
        let start = source
            .find("let evaluation = match evaluate_mainnet_policy(")
            .unwrap();
        let boundary = &source[start..start + source[start..].find("\n    };").unwrap()];
        assert_eq!(boundary.matches("render_authority_refusal(").count(), 1);
    }
}

/// Under a decision that requires approval, every mainnet value verb refuses
/// without a valid attestation before any signer resolution: a presence-only
/// assertion, an assertion of a credential the signed policy does not list,
/// and a canceled ceremony each refuse with their presence code, record no
/// consent and send nothing. The pinned credential's assertion then commits.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_value_verb_refuses_without_a_valid_attestation_before_the_signer() {
    use stellar_agent_core::error::{ApprovalFailure, WalletError};
    use stellar_agent_test_support::webauthn::{
        FLAG_UP, FLAG_UV, TestAuthenticator, fixture_authenticator,
    };
    let names = [
        "attestation-required-pay",
        "attestation-required-claim",
        "attestation-required-create",
        "attestation-required-trustline",
    ];
    for (verb, name) in Verb::ALL.into_iter().zip(names) {
        let mut fixture = verb.spec(name).build().await;
        let cases: [(&str, &str, crate::common::mainnet_presence::driver::Driver); 3] = [
            (
                "presence only",
                "approval.presence_invalid",
                crate::common::mainnet_presence::driver::credential(
                    fixture_authenticator(),
                    FLAG_UP,
                ),
            ),
            (
                "unpinned credential",
                "approval.presence_invalid",
                crate::common::mainnet_presence::driver::credential(
                    TestAuthenticator::from_seed([0x33; 32], vec![0x44; 16]),
                    FLAG_UP | FLAG_UV,
                ),
            ),
            (
                "canceled ceremony",
                "approval.presence_canceled",
                Box::new(|_| Err(WalletError::Approval(ApprovalFailure::PresenceCanceled))),
            ),
        ];
        for (case, code, driver) in cases {
            let context = format!("{} {case}", verb.name());
            fixture.present_with(driver);
            let before = signer_resolutions_on_this_thread();
            let (exit, envelope) = verb.run(&fixture).await;
            assert_eq!(exit, 1, "{context}: {envelope}");
            assert_eq!(envelope["error"]["code"], code, "{context}: {envelope}");
            assert_eq!(
                signer_resolutions_on_this_thread(),
                before,
                "{context}: no signer resolution"
            );
            assert!(fixture.sent_envelopes().await.is_empty(), "{context}");
            assert!(
                fixture.audit_rows("approval_attested").is_empty(),
                "{context}: no consent"
            );
        }
        fixture.present_with(crate::common::mainnet_presence::driver::fixture_credential());
        let before = signer_resolutions_on_this_thread();
        let (exit, envelope) = verb.run(&fixture).await;
        assert_eq!(exit, 0, "{} attested: {envelope}", verb.name());
        assert_eq!(signer_resolutions_on_this_thread(), before + 1);
        assert_eq!(fixture.sent_envelopes().await.len(), 1, "{}", verb.name());
    }
}

/// Asserts a refusal with `code` before the confirmation: no signer
/// resolution, no ceremony, no pending entry and nothing sent.
async fn assert_refused_before_confirmation(
    context: &str,
    fixture: &MainnetFixture,
    exit: i32,
    envelope: &Value,
    code: &str,
    signers_before: usize,
) {
    assert_eq!(exit, 1, "{context}: {envelope}");
    assert_eq!(envelope["error"]["code"], code, "{context}: {envelope}");
    assert_eq!(
        signer_resolutions_on_this_thread(),
        signers_before,
        "{context}: no signer resolution"
    );
    assert!(fixture.ceremonies().is_empty(), "{context}: no ceremony");
    assert!(
        fixture.pending_entries().is_empty(),
        "{context}: no pending entry"
    );
    assert!(fixture.sent_envelopes().await.is_empty(), "{context}");
}

/// A mainnet-write build refuses every mainnet value verb when the signed
/// policy or its enablement is missing: a signed policy without the
/// `[mainnet]` table, a removed policy file and a removed enablement entry
/// each refuse before the confirmation and any signer. With the removed
/// file or entry put back, the same verb commits.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_value_verb_refuses_without_the_signed_policy_or_enablement() {
    let names = [
        [
            "unsigned-pay-table",
            "unsigned-pay-file",
            "unsigned-pay-enable",
        ],
        [
            "unsigned-claim-table",
            "unsigned-claim-file",
            "unsigned-claim-enable",
        ],
        [
            "unsigned-create-table",
            "unsigned-create-file",
            "unsigned-create-enable",
        ],
        [
            "unsigned-trustline-table",
            "unsigned-trustline-file",
            "unsigned-trustline-enable",
        ],
    ];
    for (verb, [table, file, enable]) in Verb::ALL.into_iter().zip(names) {
        let context = format!("{} without the mainnet table", verb.name());
        let fixture = verb.spec(table).pre_enable().build().await;
        let before = signer_resolutions_on_this_thread();
        let (exit, envelope) = verb.run(&fixture).await;
        assert_refused_before_confirmation(
            &context,
            &fixture,
            exit,
            &envelope,
            "network.mainnet_write_forbidden",
            before,
        )
        .await;
        drop(fixture);

        let context = format!("{} without the policy file", verb.name());
        let mut fixture = verb.spec(file).build().await;
        let policy = std::fs::read(fixture.policy_path()).unwrap();
        std::fs::remove_file(fixture.policy_path()).unwrap();
        let before = signer_resolutions_on_this_thread();
        let (exit, envelope) = verb.run(&fixture).await;
        assert_refused_before_confirmation(
            &context,
            &fixture,
            exit,
            &envelope,
            match verb {
                Verb::Trustline => "trustline.policy_engine_unavailable",
                _ => "policy.engine_unavailable",
            },
            before,
        )
        .await;
        std::fs::write(fixture.policy_path(), policy).unwrap();
        fixture.present_with(crate::common::mainnet_presence::driver::fixture_credential());
        let (exit, envelope) = verb.run(&fixture).await;
        assert_eq!(exit, 0, "{context} restored: {envelope}");
        assert_eq!(fixture.sent_envelopes().await.len(), 1, "{context}");
        drop(fixture);

        let context = format!("{} without the enablement", verb.name());
        let mut fixture = verb.spec(enable).build().await;
        let entry = stellar_agent_core::profile::schema::mainnet_enablement_entry_ref(
            &fixture.profile().policy_window_state_key_id,
        );
        let value = keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .get_password()
            .unwrap();
        fixture.delete_keyring_entry(&entry);
        let before = signer_resolutions_on_this_thread();
        let (exit, envelope) = verb.run(&fixture).await;
        assert_refused_before_confirmation(
            &context,
            &fixture,
            exit,
            &envelope,
            "profile.mainnet_enablement_invalid",
            before,
        )
        .await;
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .set_password(&value)
            .unwrap();
        fixture.present_with(crate::common::mainnet_presence::driver::fixture_credential());
        let (exit, envelope) = verb.run(&fixture).await;
        assert_eq!(exit, 0, "{context} restored: {envelope}");
        assert_eq!(fixture.sent_envelopes().await.len(), 1, "{context}");
    }
}

/// A browser at the signed HTTPS origin, talking to the listener a value
/// verb binds.
struct SignedBrowser {
    client: reqwest::Client,
    address: std::net::SocketAddr,
    cookie: String,
}

impl SignedBrowser {
    /// Waits for the verb's listener to bind and logs in with the fixture
    /// passkey.
    async fn login() -> Self {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let address = loop {
            if let Some(address) = crate::common::mainnet_presence::bound_listener::take() {
                break address;
            }
            assert!(std::time::Instant::now() < deadline, "the listener binds");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        let mut browser = Self {
            client: reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap(),
            address,
            cookie: String::new(),
        };
        let options: Value = browser
            .request("POST", "/login/challenge")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let assertion = Self::assert(&options, 1);
        let response = browser
            .request("POST", "/login/assertion")
            .json(
                &json!({"assertion": {"id": assertion["credential_id_b64url"], "response": {
                "authenticator_data": assertion["authenticator_data_b64url"],
                "client_data_json": assertion["client_data_json_b64url"],
                "signature": assertion["signature_der_b64url"]}}}),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "login");
        browser.cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        browser
    }

    fn request(&self, method: &str, path: &str) -> reqwest::RequestBuilder {
        use stellar_agent_core::approval::mainnet_fixtures::SIGNED_ORIGIN;
        self.client
            .request(
                method.parse().unwrap(),
                format!("https://{}{path}", self.address),
            )
            .header("host", SIGNED_ORIGIN.trim_start_matches("https://"))
            .header("origin", SIGNED_ORIGIN)
            .header("cookie", &self.cookie)
    }

    /// The fixture passkey's assertion over the challenge of `options` at
    /// the signed origin, with sign count `count`.
    fn assert(options: &Value, count: u32) -> Value {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use stellar_agent_core::approval::mainnet_fixtures::{SIGNED_ORIGIN, SIGNED_RP_ID};
        let assertion = stellar_agent_test_support::webauthn::fixture_authenticator().assert(
            URL_SAFE_NO_PAD
                .decode(options["challenge"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            SIGNED_ORIGIN,
            SIGNED_RP_ID,
            stellar_agent_test_support::webauthn::FLAG_UP
                | stellar_agent_test_support::webauthn::FLAG_UV,
            count,
        );
        json!({
            "request_id": options["request_id"],
            "credential_id_b64url": URL_SAFE_NO_PAD.encode(assertion.credential_id),
            "authenticator_data_b64url": URL_SAFE_NO_PAD.encode(assertion.authenticator_data),
            "client_data_json_b64url": URL_SAFE_NO_PAD.encode(assertion.client_data_json),
            "signature_der_b64url": URL_SAFE_NO_PAD.encode(assertion.signature_der),
        })
    }

    /// Consents to `nonce` on its page: the challenge for the shown view,
    /// then the passkey's assertion.
    async fn consent(&self, nonce: &str) {
        let html = self
            .request("GET", &format!("/approval/{nonce}"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let page: Value = serde_json::from_str(
            html.split("id=\"presence-data\"")
                .nth(1)
                .unwrap()
                .split_once('>')
                .unwrap()
                .1
                .split("</script>")
                .next()
                .unwrap(),
        )
        .unwrap();
        let csrf = page["csrf"].as_str().unwrap();
        let action = |name: &str, body: &Value| {
            self.request("POST", &format!("/approval/{nonce}/{name}"))
                .header("x-stellar-approval-csrf", csrf)
                .json(body)
                .send()
        };
        let response = action(
            "challenge",
            &json!({"consent_view_digest": page["consent_view_digest"]}),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), 200, "challenge");
        let options: Value = response.json().await.unwrap();
        let response = action("assertion", &Self::assert(&options, 2))
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "assertion");
    }
}

/// On every mainnet value verb, an approval given at the signed HTTPS
/// origin commits. The signed policy names the origin and the pin of the
/// listener's certificate; the verb binds that listener, the fixture passkey
/// consents on its page, and the verb records its own version 6 consent,
/// with origin `cli-mainnet-confirm`, whose presence names the signed origin
/// and relying party. It signs once and sends once. The canonical send keeps
/// the approval unconsumed; the repair at the operation's execution end
/// writes its tombstone.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn every_value_verb_commits_on_consent_at_the_signed_origin() {
    for (verb, name) in Verb::ALL.into_iter().zip([
        "signed-pay",
        "signed-claim",
        "signed-create",
        "signed-trustline",
    ]) {
        let context = verb.name();
        let mut fixture = verb.spec(name).signed_origin().build().await;
        fixture.present_at_signed_origin();
        crate::common::mainnet_presence::bound_listener::take();
        let before = signer_resolutions_on_this_thread();
        let id = crate::common::business_entry::fresh_business_id();
        let run = verb.run_as(&fixture, Some(&id));
        let browser = async {
            let browser = SignedBrowser::login().await;
            let nonce = fixture.pending_entries()[0].approval_nonce.clone();
            browser.consent(&nonce).await;
            nonce
        };
        tokio::pin!(run, browser);
        // The verb's answer ends the run; a verb that refuses before its
        // listener binds ends it without the browser.
        let mut consented = None;
        let (exit, envelope) = loop {
            tokio::select! {
                result = &mut run => break result,
                nonce = &mut browser, if consented.is_none() => consented = Some(nonce),
            }
        };
        assert_eq!(exit, 0, "{context}: {envelope}");
        let nonce = consented.unwrap_or_else(|| panic!("{context}: the browser consented"));
        assert_eq!(signer_resolutions_on_this_thread(), before + 1, "{context}");
        assert_eq!(fixture.sent_envelopes().await.len(), 1, "{context}");
        let rows = fixture.audit_rows("approval_attested");
        assert_eq!(rows.len(), 1, "{context}: {rows:?}");
        assert!(
            nonce.starts_with(rows[0]["nonce_prefix"].as_str().unwrap()),
            "{context}: {rows:?}"
        );
        assert_eq!(
            rows[0]["origin"], "cli-mainnet-confirm",
            "{context}: the verb records its own consent: {rows:?}"
        );
        let presence = &rows[0]["mainnet_presence"];
        assert_eq!(
            presence["webauthn_origin"],
            stellar_agent_core::approval::mainnet_fixtures::SIGNED_ORIGIN,
            "{context}: the consent comes from the signed origin: {rows:?}"
        );
        assert_eq!(
            presence["rp_id"],
            stellar_agent_core::approval::mainnet_fixtures::SIGNED_RP_ID,
            "{context}: {rows:?}"
        );
        // The canonical send keeps its approval for a successor attempt:
        // the operation is neither terminal nor past its execution end
        // (`policy_state/operations.rs`, `approval_kept_for_retry`), so the
        // send's repair returns before the tombstone
        // (`submission_record.rs`, `repair_approval_consumption`).
        let simulated = match verb {
            Verb::Pay | Verb::Create => "PaymentSimulated",
            Verb::Claim => "ClaimSimulated",
            Verb::Trustline => "TrustlineSimulated",
        };
        let entries = fixture.pending_entries();
        assert_eq!(entries.len(), 1, "{context}: {entries:?}");
        assert_eq!(
            entries[0].kind_name, simulated,
            "{context}: the send keeps the approval"
        );
        let store = stellar_agent_core::approval::open_with_retry(
            &fixture.approval_store_path(),
            stellar_agent_core::approval::DEFAULT_RETRY_ATTEMPTS,
            stellar_agent_core::approval::DEFAULT_RETRY_BACKOFF,
        )
        .unwrap();
        // A canonical entry's subject is the intent digest
        // (`operation_entry/preparation.rs`, `stage_pending`), whose mainnet
        // consent layout is version 6 (`approval/attestation.rs`,
        // `MAINNET_INTENT_ATTESTATION_VERSION`, chosen by
        // `mainnet_attestation_version`).
        assert_eq!(
            store.get(&nonce).unwrap().attestation_version,
            6,
            "{context}: the consent is a version 6 intent attestation"
        );
        drop(store);

        // The repair `tx status` runs, with the arguments it passes, at the
        // last millisecond of the operation's execution window and at its end.
        let window =
            stellar_agent_network::policy_state::PersistedWindowStore::for_profile(fixture.name);
        let profile = fixture.profile();
        let end = stellar_agent_network::policy_state::OperationStatus::new(&window, &profile)
            .view(&stellar_agent_network::policy_state::BusinessId::parse(&id).unwrap())
            .unwrap()
            .unwrap_or_else(|| panic!("{context}: the run opened a record"))
            .execution_expires_at_ms
            .unwrap_or_else(|| panic!("{context}: the consent set the execution end"));
        let receipts =
            stellar_agent_core::profile::receipt::ReceiptStore::open(fixture.name).unwrap();
        let held: Vec<_> = receipts
            .all()
            .unwrap()
            .into_iter()
            .filter(|receipt| receipt.approval_nonce.as_deref() == Some(nonce.as_str()))
            .collect();
        assert_eq!(held.len(), 1, "{context}: the sent receipt holds the nonce");
        let approval_dir = fixture.approval_store_path().parent().unwrap().to_owned();
        let clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(end - 1);
        let repair = || {
            stellar_agent_network::submission_record::repair_approval_consumption(
                &receipts,
                &held[0].envelope_hash,
                &approval_dir,
                fixture.name,
                Some((&window, &profile)),
            )
        };
        repair().unwrap_or_else(|e| panic!("{context}: {e}"));
        // Inside the execution window the hold stands: `now < end` in
        // `approval_kept_for_retry`.
        assert_eq!(
            fixture.pending_entries()[0].kind_name,
            simulated,
            "{context}: the tombstone stays owed inside the execution window"
        );
        clock.set(end);
        repair().unwrap_or_else(|e| panic!("{context}: {e}"));
        // At the execution end the hold ends (`now < end` is false), so the
        // repair writes the tombstone
        // (`record_sent_consumption` in `repair_approval_consumption`).
        assert_eq!(
            fixture.pending_entries()[0].kind_name,
            "Consumed",
            "{context}: the repair at the execution end consumes the approval"
        );
        drop(clock);
    }
}

/// The durable approval record of `nonce` on `fixture`.
fn durable_record(
    fixture: &MainnetFixture,
    nonce: &str,
) -> stellar_agent_network::policy_state::WireApproval {
    use stellar_agent_network::policy_state::{ApprovalStatus, PersistedWindowStore};
    ApprovalStatus::new(
        &PersistedWindowStore::for_profile(fixture.name),
        &fixture.profile(),
    )
    .find_by_nonce(nonce)
    .unwrap()
    .unwrap_or_else(|| panic!("{nonce}: the durable record exists"))
    .record
}

/// Ends the process-wide state of `fixture`'s profile, as a new CLI process
/// starts without it: the cached audit writer of the profile name goes.
fn restart(fixture: &MainnetFixture) {
    stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test(fixture.name);
}

/// On every mainnet value verb, a presence-verified approval keeps its state
/// and its waiting and execution windows across a restart.
///
/// A canceled ceremony leaves the durable record pending; after a restart
/// the same business id runs its ceremony on the same entry, which keeps
/// the record's waiting window. During that run another writer takes the
/// window-state lock once the consent is recorded, so the run refuses
/// before its authorization mint and leaves the record consented; after a
/// restart the same business id commits without a new ceremony under that
/// consent and its execution window. The consumed record keeps both windows
/// across another restart.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_value_verb_keeps_its_approval_across_a_restart() {
    use stellar_agent_core::error::{ApprovalFailure, WalletError};
    use stellar_agent_network::policy_state::ApprovalState;
    for (verb, name) in Verb::ALL.into_iter().zip([
        "durable-mainnet-pay",
        "durable-mainnet-claim",
        "durable-mainnet-create",
        "durable-mainnet-trustline",
    ]) {
        let context = verb.name();
        let id = "durable-approval";
        let mut fixture = verb.spec(name).build().await;

        fixture.present_with(|_: &crate::common::mainnet_presence::driver::Ceremony| {
            Err(WalletError::Approval(ApprovalFailure::PresenceCanceled))
        });
        let (exit, envelope) = verb.run_as(&fixture, Some(id)).await;
        assert_eq!(exit, 1, "{context} canceled: {envelope}");
        let entries = fixture.pending_entries();
        assert_eq!(entries.len(), 1, "{context}: {entries:?}");
        let nonce = entries[0].approval_nonce.clone();
        let waiting = durable_record(&fixture, &nonce);
        assert_eq!(waiting.state, ApprovalState::Pending, "{context}");
        assert!(waiting.consent.is_none(), "{context}");

        restart(&fixture);
        let consented_nonce = consent_without_commit(verb, &mut fixture, id).await;
        assert_eq!(
            consented_nonce, nonce,
            "{context}: the restarted run consents to the same entry"
        );
        let ceremonies = fixture.ceremonies();
        assert_eq!(ceremonies.len(), 1, "{context}: {ceremonies:?}");
        assert_eq!(
            ceremonies[0].nonce, nonce,
            "{context}: the restarted run consents to the same entry"
        );
        let consented = durable_record(&fixture, &nonce);
        assert_eq!(consented.id, waiting.id, "{context}");
        assert_eq!(consented.state, ApprovalState::Pending, "{context}");
        assert!(consented.consent.is_some(), "{context}: consented");
        assert_eq!(
            (consented.created_at_ms, consented.waiting_expires_at_ms),
            (waiting.created_at_ms, waiting.waiting_expires_at_ms),
            "{context}: the waiting window holds across the restart"
        );

        restart(&fixture);
        let before = signer_resolutions_on_this_thread();
        let (exit, envelope) = verb.run_as(&fixture, Some(id)).await;
        assert_eq!(exit, 0, "{context} after the restart: {envelope}");
        assert_eq!(
            fixture.ceremonies().len(),
            1,
            "{context}: the stored consent needs no new ceremony"
        );
        assert_eq!(signer_resolutions_on_this_thread(), before + 1, "{context}");
        assert_eq!(fixture.sent_envelopes().await.len(), 1, "{context}");
        let consumed = durable_record(&fixture, &nonce);
        assert_eq!(consumed.state, ApprovalState::Consumed, "{context}");
        let windows = |record: &stellar_agent_network::policy_state::WireApproval| {
            let consent = record.consent.as_ref().unwrap();
            (
                record.waiting_expires_at_ms,
                consent.consent_at_ms,
                consent.execution_expires_at_ms,
            )
        };
        assert_eq!(windows(&consumed), windows(&consented), "{context}");

        restart(&fixture);
        let (exit, envelope) = verb.run_as(&fixture, Some(id)).await;
        // A replay of an open outcome exits with the unknown-outcome code.
        assert_eq!(
            envelope["data"]["operation"]["state"], "sent_outcome_unknown",
            "{context} replay: {envelope}"
        );
        assert_eq!(exit, 1, "{context} replay: {envelope}");
        assert_eq!(
            envelope["data"]["status"], "replayed",
            "{context}: {envelope}"
        );
        assert_eq!(fixture.sent_envelopes().await.len(), 1, "{context}");
        assert_eq!(
            durable_record(&fixture, &nonce),
            consumed,
            "{context}: the consumed record holds across the restart"
        );
    }
}

/// On every mainnet value verb, a consumed approval authorizes no second
/// commit, by the verb's structure. After a committed run, a rerun under the
/// same business id replays the stored operation: no ceremony, no signer
/// resolution, no send and no second value row. A run under a new business
/// id opens its own approval and, without that approval's consent, refuses
/// with no signer resolution, no send and no value row, so the first
/// approval authorizes nothing beyond its own operation.
///
/// Each row runs on its own local task, and the test reports every row that
/// fails.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_value_verb_commits_under_its_approval_once() {
    let mut failures = Vec::new();
    for (verb, name) in Verb::ALL.into_iter().zip([
        "single-use-pay",
        "single-use-claim",
        "single-use-create",
        "single-use-trustline",
    ]) {
        let local = tokio::task::LocalSet::new();
        let outcome = local
            .run_until(async { tokio::task::spawn_local(single_use_row(verb, name)).await })
            .await;
        if let Err(error) = outcome {
            let payload = error.into_panic();
            let text = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| {
                    payload
                        .downcast_ref::<&str>()
                        .map(|text| (*text).to_owned())
                })
                .unwrap_or_default();
            failures.push(format!("{}: {text}", verb.name()));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// One row of [`every_value_verb_commits_under_its_approval_once`].
async fn single_use_row(verb: Verb, name: &'static str) {
    use stellar_agent_core::error::{ApprovalFailure, WalletError};
    use stellar_agent_network::policy_state::ApprovalState;
    {
        let context = verb.name();
        // One ledger answers both endpoints, so the oracle sees the
        // sequence the first send advanced.
        let ledger = verb.ledger();
        let mut fixture = Spec::new(name)
            .primary(ledger.clone())
            .oracle(ledger)
            .build()
            .await;
        let (exit, envelope) = verb.run_as(&fixture, Some("single-use-first")).await;
        assert_eq!(exit, 0, "{context} first run: {envelope}");
        let ceremonies = fixture.ceremonies();
        assert_eq!(ceremonies.len(), 1, "{context}: {ceremonies:?}");
        let first = ceremonies[0].nonce.clone();
        let consumed = durable_record(&fixture, &first);
        assert_eq!(consumed.state, ApprovalState::Consumed, "{context}");
        assert_eq!(fixture.sent_envelopes().await.len(), 1, "{context}");
        let values = value_rows(&fixture);
        assert!(
            !values.is_empty(),
            "{context}: the commit wrote its value rows"
        );

        restart(&fixture);
        let before = signer_resolutions_on_this_thread();
        let (exit, envelope) = verb.run_as(&fixture, Some("single-use-first")).await;
        // A replay of an open outcome exits with the unknown-outcome code.
        assert_eq!(
            envelope["data"]["operation"]["state"], "sent_outcome_unknown",
            "{context} same id: {envelope}"
        );
        assert_eq!(exit, 1, "{context} same id: {envelope}");
        assert_eq!(
            envelope["data"]["status"], "replayed",
            "{context} same id: {envelope}"
        );
        assert_eq!(
            signer_resolutions_on_this_thread(),
            before,
            "{context} same id: no signer"
        );
        assert_eq!(
            fixture.ceremonies().len(),
            1,
            "{context} same id: no ceremony"
        );
        assert_eq!(
            fixture.sent_envelopes().await.len(),
            1,
            "{context} same id: nothing sent"
        );
        assert_eq!(
            value_rows(&fixture),
            values,
            "{context} same id: no value row"
        );

        restart(&fixture);
        fixture.present_with(|_: &crate::common::mainnet_presence::driver::Ceremony| {
            Err(WalletError::Approval(ApprovalFailure::PresenceCanceled))
        });
        let before = signer_resolutions_on_this_thread();
        let (exit, envelope) = verb.run_as(&fixture, Some("single-use-second")).await;
        assert_eq!(exit, 1, "{context} new id: {envelope}");
        assert_eq!(
            envelope["error"]["code"], "approval.presence_canceled",
            "{context} new id: {envelope}"
        );
        let ceremonies = fixture.ceremonies();
        assert_eq!(ceremonies.len(), 1, "{context} new id: {ceremonies:?}");
        assert_ne!(
            ceremonies[0].nonce, first,
            "{context} new id: its own approval"
        );
        let second = durable_record(&fixture, &ceremonies[0].nonce);
        assert_ne!(second.id, consumed.id, "{context} new id: its own record");
        assert_eq!(second.state, ApprovalState::Pending, "{context} new id");
        assert!(second.consent.is_none(), "{context} new id: no consent");
        assert_eq!(
            signer_resolutions_on_this_thread(),
            before,
            "{context} new id: no signer"
        );
        assert_eq!(
            fixture.sent_envelopes().await.len(),
            1,
            "{context} new id: nothing sent"
        );
        assert_eq!(
            value_rows(&fixture),
            values,
            "{context} new id: no value row"
        );
        assert_eq!(
            durable_record(&fixture, &first),
            consumed,
            "{context}: the first approval stays consumed"
        );
    }
}

/// Runs `verb` under `business_id` on `fixture` with the presence of the
/// fixture credential, while another writer takes the window-state lock
/// once the consent is recorded, so the run ends with its approval
/// consented and before its authorization mint. Returns the approval nonce.
async fn consent_without_commit(
    verb: Verb,
    fixture: &mut MainnetFixture,
    business_id: &str,
) -> String {
    let held = std::rc::Rc::new(std::cell::RefCell::new(None));
    let holder = held.clone();
    let window = fixture.window_path();
    let key = fixture.profile().policy_window_state_key_id.clone();
    let _hook =
        crate::common::mainnet_write::consent_test::on_witness(fixture.name, move |_, _| {
            holder.replace(Some(
                stellar_agent_core::policy::state_lock::WindowStoreLock::acquire_for(&window, &key)
                    .unwrap(),
            ));
        });
    fixture.present_with(crate::common::mainnet_presence::driver::fixture_credential());
    let (exit, envelope) = verb.run_as(fixture, Some(business_id)).await;
    held.replace(None);
    assert_eq!(
        exit,
        1,
        "{} beside the lock holder: {envelope}",
        verb.name()
    );
    assert!(fixture.sent_envelopes().await.is_empty(), "{}", verb.name());
    let entries = fixture.pending_entries();
    assert_eq!(entries.len(), 1, "{}: {entries:?}", verb.name());
    entries[0].approval_nonce.clone()
}

/// Revokes the approval `nonce` of `fixture` through `approve revoke` and
/// asserts that it exits 0 with the revoked view.
async fn revoke_through_the_cli(fixture: &MainnetFixture, nonce: &str) {
    crate::common::render::take_rendered_for_test();
    let exit =
        crate::commands::approve::revoke::run(crate::commands::approve::revoke::RevokeArgs {
            id: nonce.to_owned(),
            profile: Some(fixture.name.to_owned()),
            output: stellar_agent_core::envelope::OutputFormat::Json,
        })
        .await;
    let rendered = crate::common::render::take_rendered_for_test();
    assert_eq!(exit, 0, "approve revoke: {rendered:?}");
    assert_eq!(rendered.len(), 1, "{rendered:?}");
    assert_eq!(rendered[0]["data"]["state"], "revoked", "{rendered:?}");
}

/// The rows of `fixture`'s audit log whose kind starts with `value_action`.
fn value_rows(fixture: &MainnetFixture) -> Vec<Value> {
    std::fs::read_to_string(&fixture.profile().audit_log_path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| {
            row["kind"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("value_action"))
        })
        .collect()
}

/// Asserts the one `approval_revoked` row of `fixture`, for `nonce`.
fn assert_one_revocation_row(context: &str, fixture: &MainnetFixture, nonce: &str) {
    let rows = fixture.audit_rows("approval_revoked");
    assert_eq!(rows.len(), 1, "{context}: {rows:?}");
    assert!(
        nonce.starts_with(rows[0]["nonce_prefix"].as_str().unwrap()),
        "{context}: {rows:?}"
    );
}

/// On every mainnet value verb, a revoked approval refuses the commit, and
/// its revocation leaves an audit row. The verb's run records a
/// presence-verified consent and ends before its mint; `approve revoke`
/// revokes the durable record and appends one `approval_revoked` row for
/// that approval; the run under the same business id then refuses, resolves
/// no signer, sends nothing and appends no value row.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_value_verb_refuses_a_revoked_approval() {
    for (verb, name) in Verb::ALL.into_iter().zip([
        "revoked-pay",
        "revoked-claim",
        "revoked-create",
        "revoked-trustline",
    ]) {
        let context = verb.name();
        let id = "revoked-approval";
        let mut fixture = verb.spec(name).build().await;
        let nonce = consent_without_commit(verb, &mut fixture, id).await;
        assert!(
            fixture.audit_rows("approval_revoked").is_empty(),
            "{context}"
        );
        revoke_through_the_cli(&fixture, &nonce).await;
        assert_one_revocation_row(context, &fixture, &nonce);
        let values = value_rows(&fixture);
        let before = signer_resolutions_on_this_thread();
        let (exit, envelope) = verb.run_as(&fixture, Some(id)).await;
        assert_eq!(exit, 1, "{context}: {envelope}");
        // The committed-record check after the consent refuses a revoked
        // record with the wallet error, before the resolver.
        assert_eq!(
            envelope["error"]["code"], "approval.revoked",
            "{context}: {envelope}"
        );
        assert_eq!(
            signer_resolutions_on_this_thread(),
            before,
            "{context}: no signer"
        );
        assert!(
            fixture.sent_envelopes().await.is_empty(),
            "{context}: nothing sent"
        );
        assert_eq!(value_rows(&fixture), values, "{context}: no value row");
        assert_one_revocation_row(context, &fixture, &nonce);
    }
}

/// The answer to an x402 `simulateTransaction` request: the payer's unsigned
/// authorization entry for the transfer on the first simulation, none on the
/// signed one, and the resources of a minimal invocation.
fn x402_simulation(body: &Value) -> Value {
    use stellar_xdr::{
        HostFunction, LedgerFootprint, Limits, OperationBody, ReadXdr as _, ScVal,
        SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, SorobanCredentials, SorobanResources, SorobanTransactionData,
        SorobanTransactionDataExt, TransactionEnvelope, VecM, WriteXdr as _,
    };
    let TransactionEnvelope::Tx(envelope) = TransactionEnvelope::from_xdr_base64(
        body["params"]["transaction"].as_str().unwrap(),
        Limits::none(),
    )
    .unwrap() else {
        panic!("a version 1 envelope")
    };
    let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
        panic!("an invocation")
    };
    let HostFunction::InvokeContract(invoke) = &op.host_function else {
        panic!("a contract invocation")
    };
    let ScVal::Address(payer) = &invoke.args[0] else {
        panic!("the payer")
    };
    let auth = if op.auth.is_empty() {
        vec![
            SorobanAuthorizationEntry {
                credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                    address: payer.clone(),
                    nonce: 7,
                    signature_expiration_ledger: 0,
                    signature: ScVal::Void,
                }),
                root_invocation: SorobanAuthorizedInvocation {
                    function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
                    sub_invocations: VecM::default(),
                },
            }
            .to_xdr_base64(Limits::none())
            .unwrap(),
        ]
    } else {
        Vec::new()
    };
    let data = SorobanTransactionData {
        ext: SorobanTransactionDataExt::V0,
        resources: SorobanResources {
            footprint: LedgerFootprint {
                read_only: VecM::default(),
                read_write: VecM::default(),
            },
            instructions: 1000,
            disk_read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee: 1000,
    };
    json!({"transactionData": data.to_xdr_base64(Limits::none()).unwrap(),
        "minResourceFee": "1000", "latestLedger": 2000,
        "results": [{"auth": auth, "xdr": ScVal::Void.to_xdr_base64(Limits::none()).unwrap()}]})
}

/// The home domain of the authenticated x402 payment.
const SEP10_HOME: &str = "anchor.example.com";

/// The SEP-10 server key of [`SEP10_HOME`].
fn sep10_server_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x11; 32])
}

/// A mainnet SEP-10 challenge for `client_key`, signed by the server key.
fn sep10_challenge(client_key: [u8; 32]) -> String {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    use sha2::Digest as _;
    use stellar_xdr::{
        BytesM, DataValue, DecoratedSignature, Hash, Limits, ManageDataOp, Memo, MuxedAccount,
        Operation, OperationBody, Preconditions, SequenceNumber, SignatureHint, String64, StringM,
        TimeBounds, TimePoint, Transaction, TransactionEnvelope, TransactionExt,
        TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
        TransactionV1Envelope, Uint256, VecM, WriteXdr as _,
    };
    let server = sep10_server_key();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let name = |text: &str| -> String64 {
        StringM::<64>::try_from(text.as_bytes().to_vec())
            .unwrap()
            .into()
    };
    let value = |bytes: &[u8]| DataValue(BytesM::<64>::try_from(bytes.to_vec()).unwrap());
    let server_account = MuxedAccount::Ed25519(Uint256(server.verifying_key().to_bytes()));
    let nonce = base64::engine::general_purpose::STANDARD.encode([0x55u8; 48]);
    let operations: VecM<Operation, 100> = vec![
        Operation {
            source_account: Some(MuxedAccount::Ed25519(Uint256(client_key))),
            body: OperationBody::ManageData(ManageDataOp {
                data_name: name(&format!("{SEP10_HOME} auth")),
                data_value: Some(value(nonce.as_bytes())),
            }),
        },
        Operation {
            source_account: Some(server_account.clone()),
            body: OperationBody::ManageData(ManageDataOp {
                data_name: name("web_auth_domain"),
                data_value: Some(value(b"127.0.0.1")),
            }),
        },
    ]
    .try_into()
    .unwrap();
    let tx = Transaction {
        source_account: server_account,
        fee: 100,
        seq_num: SequenceNumber(0),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(now - 60),
            max_time: TimePoint(now + 900),
        }),
        memo: Memo::None,
        operations,
        ext: TransactionExt::V0,
    };
    let payload = TransactionSignaturePayload {
        network_id: Hash(
            sha2::Sha256::digest(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE.as_bytes())
                .into(),
        ),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
    };
    let hash: [u8; 32] = sha2::Sha256::digest(payload.to_xdr(Limits::none()).unwrap()).into();
    let signature = DecoratedSignature {
        hint: SignatureHint(
            server.verifying_key().to_bytes()[28..32]
                .try_into()
                .unwrap(),
        ),
        signature: server.sign(&hash).to_bytes().to_vec().try_into().unwrap(),
    };
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![signature].try_into().unwrap(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// A SEP-10 server for [`SEP10_HOME`] whose stellar.toml names its web auth
/// endpoint and whose endpoint answers each challenge request.
async fn sep10_double() -> wiremock::MockServer {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let server = wiremock::MockServer::start().await;
    let signing_key =
        stellar_strkey::ed25519::PublicKey(sep10_server_key().verifying_key().to_bytes())
            .to_string();
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "SIGNING_KEY = \"{signing_key}\"\nWEB_AUTH_ENDPOINT = \"https://{SEP10_HOME}/auth\"\n"
        )))
        .mount(&server)
        .await;
    let challenged = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let served = std::sync::Arc::clone(&challenged);
    Mock::given(method("GET"))
        .and(path("/auth"))
        .respond_with(move |request: &wiremock::Request| {
            let account = request
                .url
                .query_pairs()
                .find(|(name, _)| name == "account")
                .map(|(_, value)| value.into_owned())
                .unwrap();
            let client = stellar_strkey::ed25519::PublicKey::from_string(&account)
                .unwrap()
                .0;
            *served.lock().unwrap() = account;
            ResponseTemplate::new(200).set_body_json(json!({
                "transaction": sep10_challenge(client),
                "network_passphrase": stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE,
            }))
        })
        .mount(&server)
        .await;
    // The token exchange answers a session for the account the last
    // challenge named.
    Mock::given(method("POST"))
        .and(path("/auth"))
        .respond_with(move |_: &wiremock::Request| {
            use base64::Engine as _;
            let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                json!({
                    "sub": *challenged.lock().unwrap(),
                    "iss": format!("https://{SEP10_HOME}"),
                    "iat": 0,
                    "exp": 9_999_999_999_u64,
                })
                .to_string(),
            );
            ResponseTemplate::new(200)
                .set_body_json(json!({ "token": format!("header.{claims}.sig") }))
        })
        .mount(&server)
        .await;
    server
}

/// One MCP classic commit row, run against the CLI's mainnet fixture.
#[derive(Clone, Copy, Debug)]
enum McpTool {
    Pay,
    Claim,
    CreateAccount,
    Trustline,
}

impl McpTool {
    const ALL: [Self; 4] = [Self::Pay, Self::Claim, Self::CreateAccount, Self::Trustline];

    /// The CLI verb whose ledger and rules serve the tool.
    fn verb(self) -> Verb {
        match self {
            Self::Pay => Verb::Pay,
            Self::Claim => Verb::Claim,
            Self::CreateAccount => Verb::Create,
            Self::Trustline => Verb::Trustline,
        }
    }

    /// The verb's rule requiring approval, for the preparation name and the
    /// commit name.
    fn rules(self) -> Vec<String> {
        let rule = self.verb().rule("require_approval", "");
        let tool = self.verb().tool();
        vec![
            rule.clone(),
            rule.replace(&format!("\"{tool}\""), &format!("\"{tool}_commit\"")),
        ]
    }

    /// The preparation arguments under a fresh business id.
    fn prepare_args(self, fixture: &MainnetFixture) -> Value {
        use crate::common::mainnet_write_fixture::{NEW_ACCOUNT, TRUSTLINE_ASSET};
        let mut args = match self {
            Self::Pay => json!({"source": fixture.agent.g, "destination": DESTINATION,
                "amount_in_stroops": "10000000", "asset": "native", "fee": "100"}),
            Self::Claim => json!({"source_account": fixture.agent.g,
                "balance_id": "ab".repeat(32)}),
            Self::CreateAccount => json!({"source": fixture.agent.g, "destination": NEW_ACCOUNT,
                "starting_balance": "2 XLM", "fee": "100"}),
            Self::Trustline => json!({"from": fixture.agent.g, "asset": TRUSTLINE_ASSET,
                "fee": "100"}),
        };
        args["chain_id"] = json!("stellar:mainnet");
        args["business_id"] = json!(crate::common::business_entry::fresh_business_id());
        args
    }

    async fn prepare(
        self,
        server: &stellar_agent_mcp::server::WalletServer,
        args: &Value,
    ) -> Value {
        let args = args.clone();
        let result = match self {
            Self::Pay => {
                server
                    .call_stellar_pay(serde_json::from_value(args).unwrap())
                    .await
            }
            Self::Claim => {
                server
                    .call_stellar_claim(serde_json::from_value(args).unwrap())
                    .await
            }
            Self::CreateAccount => {
                server
                    .call_stellar_create_account(serde_json::from_value(args).unwrap())
                    .await
            }
            Self::Trustline => {
                server
                    .call_stellar_trustline(serde_json::from_value(args).unwrap())
                    .await
            }
        };
        tool_json(&result.unwrap())
    }

    async fn commit(self, server: &stellar_agent_mcp::server::WalletServer, args: Value) -> Value {
        let result = match self {
            Self::Pay => {
                server
                    .call_stellar_pay_commit(serde_json::from_value(args).unwrap())
                    .await
            }
            Self::Claim => {
                server
                    .call_stellar_claim_commit(serde_json::from_value(args).unwrap())
                    .await
            }
            Self::CreateAccount => {
                server
                    .call_stellar_create_account_commit(serde_json::from_value(args).unwrap())
                    .await
            }
            Self::Trustline => {
                server
                    .call_stellar_trustline_commit(serde_json::from_value(args).unwrap())
                    .await
            }
        };
        tool_json(&result.unwrap())
    }
}

/// The JSON envelope of a tool result.
fn tool_json(result: &impl serde::Serialize) -> Value {
    let result = serde_json::to_value(result).unwrap();
    serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap()
}

/// The MCP server of `fixture`'s profile, routed to its endpoints.
fn mcp_server(fixture: &MainnetFixture) -> stellar_agent_mcp::server::WalletServer {
    use crate::common::mainnet_write_fixture::{ORACLE_HOST, PRIMARY_HOST};
    stellar_agent_mcp::server::WalletServer::new_with_selection_and_routes_for_test(
        fixture.profile(),
        stellar_agent_core::profile::name::ProfileNameSource::Flag,
        &stellar_agent_core::profile::schema::default_profile_dir().unwrap(),
        &[
            (PRIMARY_HOST, fixture.primary.uri().as_str()),
            (ORACLE_HOST, fixture.oracle.uri().as_str()),
        ],
    )
    .unwrap()
}

/// Records the operator's presence-verified consent to `nonce` through
/// `approve --id`, and returns its attestation.
async fn approve_through_the_cli(fixture: &mut MainnetFixture, nonce: &str) -> String {
    use clap::Parser as _;
    #[derive(clap::Parser)]
    struct Approve {
        #[command(flatten)]
        args: crate::commands::approve::ApproveArgs,
    }
    fixture.present_with(crate::common::mainnet_presence::driver::fixture_credential());
    crate::common::render::take_rendered_for_test();
    let parsed =
        Approve::try_parse_from(["approve", "--id", nonce, "--profile", fixture.name]).unwrap();
    let exit = crate::commands::approve::dispatch(parsed.args).await;
    let rendered = crate::common::render::take_rendered_for_test();
    assert_eq!(exit, 0, "approve --id: {rendered:?}");
    stellar_agent_core::approval::PendingApprovalStore::open(fixture.approval_store_path())
        .unwrap()
        .get(nonce)
        .unwrap()
        .attestation_blob_b64
        .clone()
        .unwrap()
}

/// On every MCP classic commit row, a revoked approval refuses the commit,
/// and its revocation leaves an audit row. The tool's preparation stores its
/// approval, `approve --id` records the presence-verified consent, and
/// `approve revoke` revokes the durable record with one `approval_revoked`
/// row for that approval. The commit with that approval then refuses before
/// its signer: the signing seed is gone, so a commit that reached it would
/// answer with a keyring refusal. Nothing is sent and no value row is
/// appended.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_mcp_commit_refuses_a_revoked_approval() {
    for (tool, name) in McpTool::ALL.into_iter().zip([
        "mcp-revoked-pay",
        "mcp-revoked-claim",
        "mcp-revoked-create",
        "mcp-revoked-trustline",
    ]) {
        let context = format!("{tool:?}");
        let mut fixture = tool.verb().spec(name).rules(tool.rules()).build().await;
        let server = mcp_server(&fixture);
        let args = tool.prepare_args(&fixture);
        let prepared = tool.prepare(&server, &args).await;
        assert_eq!(prepared["ok"], true, "{context}: {prepared}");
        let data = &prepared["data"];
        let nonce = data["approval"]["approval_nonce"]
            .as_str()
            .unwrap_or_else(|| panic!("{context}: {prepared}"))
            .to_owned();
        let attestation = approve_through_the_cli(&mut fixture, &nonce).await;
        revoke_through_the_cli(&fixture, &nonce).await;
        assert_one_revocation_row(&context, &fixture, &nonce);

        let mut commit = args.clone();
        for field in ["envelope_xdr", "nonce", "expires_at_unix_ms"] {
            commit[field] = data[field].clone();
        }
        commit["approval_nonce"] = json!(nonce);
        commit["approval_attestation"] = json!(attestation);
        fixture.delete_keyring_entry(&fixture.profile().mcp_signer_default);
        let values = value_rows(&fixture);
        let result = tool.commit(&server, commit).await;
        assert_eq!(result["ok"], false, "{context}: {result}");
        // The durable proof gate answers a revoked record with the wallet
        // error.
        assert_eq!(
            result["error"]["code"], "approval.revoked",
            "{context}: {result}"
        );
        assert!(
            fixture.sent_envelopes().await.is_empty(),
            "{context}: nothing sent"
        );
        assert_eq!(value_rows(&fixture), values, "{context}: no value row");
        assert_one_revocation_row(&context, &fixture, &nonce);
    }
    for authenticated in [false, true] {
        x402_refuses_a_revoked_approval(authenticated).await;
    }
}

/// One x402 MCP row on its own fixture: the plain payment, or with
/// `authenticated` the authenticated payment for [`SEP10_HOME`], under a
/// rule that requires approval for the tool, with one business id.
struct X402Row {
    authenticated: bool,
    fixture: MainnetFixture,
    server: stellar_agent_mcp::server::WalletServer,
    _sep10: wiremock::MockServer,
    requirements: String,
    business_id: String,
}

impl X402Row {
    /// The row on a fixture named `name`; with `signed_origin`, its signed
    /// policy names the signed HTTPS origin.
    async fn new(authenticated: bool, name: &'static str, signed_origin: bool) -> Self {
        let tool = if authenticated {
            "stellar_x402_authenticated_payment"
        } else {
            "stellar_x402_create_payment"
        };
        let token = stellar_strkey::Contract([3; 32]).to_string().to_string();
        let rule = Verb::Pay
            .rule("require_approval", "")
            .replace("\"stellar_pay\"", &format!("\"{tool}\""))
            .replace("\"native\"", &format!("\"{token}\""));
        let simulating = || {
            Verb::Pay.ledger().with_script(|method, _, body| {
                (method == "simulateTransaction").then(|| x402_simulation(body))
            })
        };
        let spec = Verb::Pay
            .spec(name)
            .rules(vec![rule])
            .primary(simulating())
            .oracle(simulating());
        let fixture = if signed_origin {
            spec.signed_origin()
        } else {
            spec
        }
        .build()
        .await;
        // The payment of the token needs a witness threshold, which this
        // below-threshold amount stays under.
        let directory = stellar_agent_core::profile::schema::default_profile_dir().unwrap();
        let mut stored =
            stellar_agent_core::profile::loader::load_from_dir(fixture.name, &directory, None)
                .unwrap();
        stored.cross_check_thresholds =
            serde_json::from_value(json!({ token.clone(): "10000000000" })).unwrap();
        stellar_agent_core::profile::loader::save_to_dir(fixture.name, &stored, &directory)
            .unwrap();
        let mut server = mcp_server(&fixture);
        let sep10 = sep10_double().await;
        if authenticated {
            server.set_x402_identity_transport_for_test(
                sep10.uri(),
                reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .unwrap(),
                Some(format!("{}/auth", sep10.uri())),
            );
        }
        let requirements = json!({"scheme": "exact", "network": "stellar:pubnet", "asset": token,
            "amount": "10", "payTo": DESTINATION, "maxTimeoutSeconds": 60,
            "extra": {"areFeesSponsored": true}})
        .to_string();
        Self {
            authenticated,
            fixture,
            server,
            _sep10: sep10,
            requirements,
            business_id: crate::common::business_entry::fresh_business_id(),
        }
    }

    /// The row's name in a message.
    fn context(&self) -> &'static str {
        if self.authenticated {
            "authenticated x402"
        } else {
            "x402"
        }
    }

    /// The payment arguments, with the approval `proof` when given.
    fn args(&self, proof: Option<(&str, &str)>) -> Value {
        let mut args = json!({"payment_required": self.requirements,
            "chain_id": "stellar:mainnet",
            "approval_nonce": proof.map(|(nonce, _)| nonce),
            "approval_attestation": proof.map(|(_, attestation)| attestation),
            "business_id": self.business_id});
        if self.authenticated {
            args["home_domain"] = json!(SEP10_HOME);
        }
        args
    }

    /// Calls the row's tool handler with `args`.
    async fn pay(&self, args: Value) -> Value {
        let result = if self.authenticated {
            self.server
                .call_stellar_x402_authenticated_payment(serde_json::from_value(args).unwrap())
                .await
        } else {
            self.server
                .call_stellar_x402_create_payment(serde_json::from_value(args).unwrap())
                .await
        };
        tool_json(&result.unwrap())
    }

    /// Runs the preparation call, which stores the approval, and returns
    /// its nonce.
    async fn prepare(&self) -> String {
        let prepared = self.pay(self.args(None)).await;
        prepared["data"]["approval"]["approval_nonce"]
            .as_str()
            .unwrap_or_else(|| panic!("{}: {prepared}", self.context()))
            .to_owned()
    }
}

/// The x402 rows of [`every_mcp_commit_refuses_a_revoked_approval`]: the
/// plain payment, or with `authenticated` the authenticated payment for its
/// home domain.
async fn x402_refuses_a_revoked_approval(authenticated: bool) {
    let name = if authenticated {
        "mcp-revoked-x402-authenticated"
    } else {
        "mcp-revoked-x402"
    };
    let mut row = X402Row::new(authenticated, name, false).await;
    let context = row.context();
    let nonce = row.prepare().await;
    let attestation = approve_through_the_cli(&mut row.fixture, &nonce).await;
    let fixture = &row.fixture;
    revoke_through_the_cli(fixture, &nonce).await;
    assert_one_revocation_row(context, fixture, &nonce);
    fixture.delete_keyring_entry(&fixture.profile().mcp_signer_default);
    let values = value_rows(fixture);
    let result = row.pay(row.args(Some((&nonce, &attestation)))).await;
    assert_eq!(result["ok"], false, "{context}: {result}");
    // The durable proof gate answers a revoked record with the wallet error.
    assert_eq!(
        result["error"]["code"], "approval.revoked",
        "{context}: {result}"
    );
    assert!(
        result["data"].get("paymentSignature").is_none(),
        "{context}: {result}"
    );
    assert!(
        fixture.sent_envelopes().await.is_empty(),
        "{context}: nothing sent"
    );
    assert_eq!(value_rows(fixture), values, "{context}: no value row");
    assert!(
        fixture.audit_rows("x402_payment_authorized").is_empty(),
        "{context}: no authorized payment row"
    );
    assert_one_revocation_row(context, fixture, &nonce);
}

/// Records the operator's consent to `nonce` through `approve --id` on
/// `fixture`, whose signed policy names the signed HTTPS origin: the command
/// binds that origin's listener, and the fixture passkey logs in and
/// consents on the approval's page. Returns the attestation, or the
/// command's refusal.
async fn approve_at_the_signed_origin(
    fixture: &mut MainnetFixture,
    nonce: &str,
) -> Result<String, String> {
    use clap::Parser as _;
    #[derive(clap::Parser)]
    struct Approve {
        #[command(flatten)]
        args: crate::commands::approve::ApproveArgs,
    }
    fixture.present_at_signed_origin();
    crate::common::mainnet_presence::bound_listener::take();
    crate::common::render::take_rendered_for_test();
    let parsed =
        Approve::try_parse_from(["approve", "--id", nonce, "--profile", fixture.name]).unwrap();
    let approve = crate::commands::approve::dispatch(parsed.args);
    let browser = async {
        SignedBrowser::login().await.consent(nonce).await;
    };
    tokio::pin!(approve, browser);
    // The command's answer ends the run, also before the browser reads the
    // listener's last response; a command that refuses before its listener
    // binds ends it without the browser. The consent row the caller checks
    // shows where the consent came from.
    let mut browsed = false;
    let exit = loop {
        tokio::select! {
            exit = &mut approve => break exit,
            () = &mut browser, if !browsed => browsed = true,
        }
    };
    let rendered = crate::common::render::take_rendered_for_test();
    if exit != 0 {
        return Err(format!("approve --id exited {exit}: {rendered:?}"));
    }
    Ok(
        stellar_agent_core::approval::PendingApprovalStore::open(fixture.approval_store_path())
            .unwrap()
            .get(nonce)
            .unwrap()
            .attestation_blob_b64
            .clone()
            .unwrap(),
    )
}

/// The failures of the one consent row a signed-origin approval of `nonce`
/// leaves on `fixture`: an `approval_attested` row from the `approve`
/// command's surface, `cli`, whose presence names the signed origin and its
/// relying party.
fn signed_origin_consent_failures(
    context: &str,
    fixture: &MainnetFixture,
    nonce: &str,
) -> Vec<String> {
    use stellar_agent_core::approval::mainnet_fixtures::{SIGNED_ORIGIN, SIGNED_RP_ID};
    let rows = fixture.audit_rows("approval_attested");
    let [row] = rows.as_slice() else {
        return vec![format!("{context}: one consent row: {rows:?}")];
    };
    let presence = &row["mainnet_presence"];
    let holds = row["nonce_prefix"]
        .as_str()
        .is_some_and(|prefix| nonce.starts_with(prefix))
        && row["origin"] == "cli"
        && presence["webauthn_origin"] == SIGNED_ORIGIN
        && presence["rp_id"] == SIGNED_RP_ID;
    if holds {
        Vec::new()
    } else {
        vec![format!(
            "{context}: a consent from the signed origin's listener: nonce prefix {}, \
             origin {}, webauthn origin {}, rp id {}",
            row["nonce_prefix"], row["origin"], presence["webauthn_origin"], presence["rp_id"]
        )]
    }
}

/// On every MCP value row, an approval given at the signed HTTPS origin
/// commits. The tool's handler prepares and stores the approval;
/// `approve --id` binds the listener of the origin the signed policy names,
/// and the fixture passkey logs in and consents on the approval's page over
/// its signed browser fixture. The consent row comes from the command's
/// surface, its presence names the signed origin and relying party, and the
/// commit through the tool's handler with that approval succeeds: a classic
/// commit sends once, and an x402 payment returns its signature with one
/// authorized row.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_mcp_row_commits_on_consent_at_the_signed_origin() {
    let mut failures = Vec::new();
    for (tool, name) in McpTool::ALL.into_iter().zip([
        "mcp-signed-pay",
        "mcp-signed-claim",
        "mcp-signed-create",
        "mcp-signed-trustline",
    ]) {
        let context = format!("{tool:?}");
        let mut fixture = tool
            .verb()
            .spec(name)
            .rules(tool.rules())
            .signed_origin()
            .build()
            .await;
        let server = mcp_server(&fixture);
        let args = tool.prepare_args(&fixture);
        let prepared = tool.prepare(&server, &args).await;
        let data = &prepared["data"];
        let nonce = data["approval"]["approval_nonce"]
            .as_str()
            .unwrap_or_else(|| panic!("{context}: {prepared}"))
            .to_owned();
        let attestation = match approve_at_the_signed_origin(&mut fixture, &nonce).await {
            Ok(attestation) => attestation,
            Err(refusal) => {
                failures.push(format!("{context}: {refusal}"));
                continue;
            }
        };
        let mut commit = args.clone();
        for field in ["envelope_xdr", "nonce", "expires_at_unix_ms"] {
            commit[field] = data[field].clone();
        }
        commit["approval_nonce"] = json!(nonce);
        commit["approval_attestation"] = json!(attestation);
        let result = tool.commit(&server, commit).await;
        let sent = fixture.sent_envelopes().await.len();
        if result["ok"] != true || sent != 1 {
            failures.push(format!("{context}: commit, {sent} sent: {result}"));
        }
        failures.extend(signed_origin_consent_failures(&context, &fixture, &nonce));
    }
    for (authenticated, name) in [
        (false, "mcp-signed-x402"),
        (true, "mcp-signed-x402-authenticated"),
    ] {
        let mut row = X402Row::new(authenticated, name, true).await;
        let context = row.context();
        let nonce = row.prepare().await;
        let attestation = match approve_at_the_signed_origin(&mut row.fixture, &nonce).await {
            Ok(attestation) => attestation,
            Err(refusal) => {
                failures.push(format!("{context}: {refusal}"));
                continue;
            }
        };
        let result = row.pay(row.args(Some((&nonce, &attestation)))).await;
        let authorized = row.fixture.audit_rows("x402_payment_authorized").len();
        if result["ok"] != true
            || !result["data"]["paymentSignature"].is_string()
            || authorized != 1
        {
            failures.push(format!(
                "{context}: payment, {authorized} authorized rows: {result}"
            ));
        }
        failures.extend(signed_origin_consent_failures(
            context,
            &row.fixture,
            &nonce,
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[cfg(test)]
mod publication {
    use super::*;
    use stellar_agent_core::approval::witness::ApprovedKind;
    use stellar_agent_core::audit_log::MAX_EVIDENCE_ENTRIES;
    use stellar_agent_network::policy_state::PersistedWindowStore;
    use stellar_agent_network::policy_state::approvals::{
        ApprovalStatus, ConsentEvidenceEnforcementGuard, UnreadableSiblingProfile,
    };

    fn fill_scope(fixture: &MainnetFixture) {
        let profile = fixture.profile();
        let writer =
            crate::commands::value_audit::require_value_audit_writer(&profile, fixture.name)
                .unwrap();
        writer
            .lock()
            .unwrap()
            .initialize_consent_evidence()
            .unwrap();
        crate::common::approval_fixture::seed_foreign_evidence(
            &profile,
            fixture.name,
            0xdd,
            MAX_EVIDENCE_ENTRIES,
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn all_value_verbs_reserve_before_ceremony() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let names = [
            [
                "publication-pay-full",
                "publication-pay-unready",
                "publication-pay-enabled",
                "publication-pay-disabled",
            ],
            [
                "publication-claim-full",
                "publication-claim-unready",
                "publication-claim-enabled",
                "publication-claim-disabled",
            ],
            [
                "publication-create-full",
                "publication-create-unready",
                "publication-create-enabled",
                "publication-create-disabled",
            ],
            [
                "publication-trust-full",
                "publication-trust-unready",
                "publication-trust-enabled",
                "publication-trust-disabled",
            ],
        ];
        for (verb, names) in Verb::ALL.into_iter().zip(names) {
            let kind = match verb {
                Verb::Pay | Verb::Create => ApprovedKind::Payment,
                Verb::Claim => ApprovedKind::Claim,
                Verb::Trustline => ApprovedKind::Trustline,
            };
            for (mode, name) in names.into_iter().enumerate() {
                let fixture = verb.spec(name).build().await;
                let _enabled =
                    (mode != 3).then(|| ConsentEvidenceEnforcementGuard::new(name, kind));
                let _unready = (mode == 1).then(UnreadableSiblingProfile::plant);
                if mode == 0 || mode == 3 {
                    fill_scope(&fixture);
                }
                let before = signer_resolutions_on_this_thread();
                let (code, envelope) = verb.run(&fixture).await;
                if mode < 2 {
                    assert_eq!(code, 1, "admission refuses the real command: {envelope}");
                    assert_eq!(
                        envelope["error"]["code"],
                        if mode == 0 {
                            "approval.evidence_capacity"
                        } else {
                            "audit.outbox_evidence_unusable"
                        },
                        "the command preserves the admission refusal: {envelope}"
                    );
                    assert!(
                        fixture.summaries().is_empty(),
                        "admission precedes command display"
                    );
                    assert!(
                        fixture.ceremonies().is_empty(),
                        "admission precedes command presence"
                    );
                    assert!(
                        fixture.pending_entries().is_empty(),
                        "admission precedes inbox insertion"
                    );
                    assert!(fixture.audit_rows("approval_attested").is_empty());
                    assert_eq!(signer_resolutions_on_this_thread(), before);
                    assert!(fixture.sent_envelopes().await.is_empty());
                    assert!(
                        fixture
                            .open_authorizations(
                                stellar_agent_core::timefmt::now_unix_ms().unwrap()
                            )
                            .is_empty()
                    );
                } else {
                    assert_eq!(code, 0, "command publication succeeds: {envelope}");
                    assert_eq!(fixture.ceremonies().len(), 1);
                    assert_eq!(fixture.audit_rows("approval_attested").len(), 1);
                    assert_eq!(fixture.sent_envelopes().await.len(), 1);
                    let window = PersistedWindowStore::for_profile(name);
                    let record = ApprovalStatus::new(&window, &fixture.profile())
                        .find_by_nonce(&fixture.ceremonies()[0].nonce)
                        .unwrap()
                        .unwrap()
                        .record;
                    let consent = record.consent.unwrap();
                    assert_eq!(
                        consent.delivery.is_some(),
                        mode == 2,
                        "only integrated commands publish delivery"
                    );
                    if let Some(delivery) = consent.delivery {
                        assert_eq!(delivery, stellar_agent_network::policy_state::approvals::ConsentDeliveryV1::direct_anchored(record.id));
                    }
                }
            }
        }
    }
}
