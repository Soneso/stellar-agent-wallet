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
        match self {
            Self::Pay => {
                crate::common::render::take_rendered_for_test();
                let code = pay::run_code(fixture, &pay::mainnet_args(fixture)).await;
                let documents = crate::common::render::take_rendered_for_test();
                assert_eq!(documents.len(), 1, "one stdout envelope");
                (code, documents.into_iter().next().unwrap())
            }
            Self::Claim => {
                let r = claim::run(fixture, &claim::mainnet_args(fixture)).await;
                (r.code, r.envelope)
            }
            Self::Create => {
                crate::common::render::take_rendered_for_test();
                let code = create::run_code(fixture, &create::mainnet_args(fixture)).await;
                let documents = crate::common::render::take_rendered_for_test();
                assert_eq!(documents.len(), 1, "one stdout envelope");
                (code, documents.into_iter().next().unwrap())
            }
            Self::Trustline => {
                let r = trustline::run(fixture, &trustline::mainnet_args(fixture)).await;
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
