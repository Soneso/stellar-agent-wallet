//! Durable consent of mainnet value approvals decided in the inbox.

use stellar_agent_approval_ui::decision::{ConsentRecording, ConsentRowSource, VerifiedConsent};
use stellar_agent_core::approval::witness::ApprovedKind;
use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::Profile;
use stellar_agent_network::operation_entry::{
    ConsentAdmission, commit_consent, witnessed_completion, witnessed_publication_completion,
};
use stellar_agent_network::policy_state::{ConsentPayload, ConsentRow, PersistedWindowStore};

/// The consent recording of the profile's durable approval records.
pub(super) struct DurableConsents {
    store: PersistedWindowStore,
    profile: Profile,
    name: String,
}

impl DurableConsents {
    pub(super) fn new(name: &str, profile: &Profile) -> Self {
        Self {
            store: PersistedWindowStore::for_profile(name),
            profile: profile.clone(),
            name: name.to_owned(),
        }
    }
}

impl DurableConsents {
    /// The precheck of `entry`. With `skip_committed`, a record that already
    /// holds consent ends it before the reacquisition, as the CLI recovery
    /// does.
    fn check(
        &self,
        entry: &stellar_agent_core::approval::PendingApproval,
        skip_committed: bool,
    ) -> Result<(), WalletError> {
        let record =
            stellar_agent_network::policy_state::ApprovalStatus::new(&self.store, &self.profile)
                .find_by_nonce(&entry.approval_nonce)
                .map_err(stellar_agent_network::operation_entry::operation_refusal)?
                .ok_or_else(|| {
                    WalletError::Approval(stellar_agent_core::ApprovalFailure::NotFound {
                        detail: "no durable approval record for that nonce".to_owned(),
                    })
                })?
                .record;
        if skip_committed && record.consent.is_some() {
            return Ok(());
        }
        if self.publishes(record.kind) {
            ConsentAdmission::reacquire(
                &self.store,
                &self.profile,
                record.operation_id,
                &record.facts(),
                &crate::common::consent::consent_outbox(&self.profile, &self.name)?,
            )?;
        }
        Ok(())
    }
}

impl ConsentRecording for DurableConsents {
    /// For a published kind, the record's evidence slot is reacquired with
    /// its authenticated facts through the keyed outbox, which takes no
    /// window lock and no audit writer.
    fn precheck(
        &self,
        entry: &stellar_agent_core::approval::PendingApproval,
    ) -> Result<(), WalletError> {
        self.check(entry, false)
    }

    /// A record that already holds consent needs no reservation: the
    /// completion finds the commit and answers as the CLI recovery does.
    fn precheck_completion(
        &self,
        entry: &stellar_agent_core::approval::PendingApproval,
    ) -> Result<(), WalletError> {
        self.check(entry, true)
    }

    /// The mainnet check repeats the one the shared decision applies before
    /// it asks; it is defense in depth, so this adapter never publishes off
    /// mainnet whatever its caller checked.
    fn publishes(&self, kind: ApprovedKind) -> bool {
        self.profile.chain_id.is_mainnet()
            && stellar_agent_network::policy_state::approvals::delivery_enforced(&self.name, kind)
    }

    /// Reads the record that names the consent's nonce, then commits the
    /// consent under the window lock alone; the commit checks the witness
    /// against the record. A verified publication handoff supplies the
    /// delivery and the queued reference. An entry without a record keeps the
    /// path of an approval prepared before records existed, so nothing is
    /// written.
    fn complete(&self, consent: VerifiedConsent, row: ConsentRowSource) -> Result<(), WalletError> {
        let payload = ConsentPayload::new(
            consent.attestation,
            consent.receipt,
            consent.process_uid,
            match row {
                ConsentRowSource::Written => ConsentRow::Written,
                ConsentRowSource::Recovered => ConsentRow::Recovered,
            },
        );
        if let Some(publication) = &consent.publication {
            let completion = witnessed_publication_completion(
                &self.store,
                &self.profile,
                consent.witness,
                payload,
                publication,
            )?;
            return commit_consent(&self.store, &self.profile, &completion).map(drop);
        }
        match witnessed_completion(&self.store, &self.profile, consent.witness, payload)? {
            Some(completion) => commit_consent(&self.store, &self.profile, &completion).map(drop),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions"
    )]

    use std::sync::{Arc, Mutex};

    use serde_json::{Value, json};
    use stellar_agent_approval_ui::decision::{
        Decision, Outcome, RequestIdentity, RevocationAccess, apply_decision,
    };
    use stellar_agent_core::approval::witness::ApprovedKind;
    use stellar_agent_core::approval::{
        ConsentAudit, ConsentAuthorization, PendingApproval, PendingApprovalStore, Surface,
        approval_view_digest, attest::attest_and_persist_with_row, attest_and_persist,
        mainnet_fixtures::ATTESTATION_KEY, verify_consent_publication,
    };
    use stellar_agent_core::policy::state_lock::{lock_requests, window_lock_path};
    use stellar_agent_network::mainnet::MainnetPrecondition;
    use stellar_agent_network::policy_state::approvals::{
        ConsentDeliveryV1, ConsentEvidenceEnforcementGuard, UnreadableSiblingProfile,
    };
    use stellar_agent_network::policy_state::store::commit_faults::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
        observe_commit,
    };
    use stellar_agent_network::policy_state::{RowProvenance, WindowStoreError};

    use super::super::revoke::tests::{Browser, Fixture, island, mint_audit_key, signed_fixture};
    use super::{ConsentRecording as _, DurableConsents};

    /// The guards of a published payment consent.
    type Published = (
        ConsentEvidenceEnforcementGuard,
        Option<UnreadableSiblingProfile>,
    );

    /// Publishes `f`'s payment consents: the scoped kind capability, an
    /// unreadable sibling profile unless the scope is `ready`, a keyed log
    /// with initialized evidence, and a keyed serving writer.
    async fn publish(f: &mut Fixture, ready: bool) -> Published {
        mint_audit_key(f.core.name()).await;
        f.keyed_writer().initialize_consent_evidence().unwrap();
        f.keyed = true;
        (
            ConsentEvidenceEnforcementGuard::new(f.core.name(), ApprovedKind::Payment),
            (!ready).then(UnreadableSiblingProfile::plant),
        )
    }

    /// The direct delivery of `f`'s record.
    fn direct(f: &Fixture) -> Option<ConsentDeliveryV1> {
        Some(ConsentDeliveryV1::direct_anchored(f.view().record.id))
    }

    /// Fills `f`'s evidence scope with `count` foreign reservations.
    fn fill(f: &Fixture, count: usize) {
        crate::common::approval_fixture::seed_foreign_evidence(
            f.core.profile(),
            f.core.name(),
            0xee,
            count,
        );
    }

    /// The challenge options of `nonce` through `browser`, and the page's
    /// CSRF token.
    async fn challenge(browser: &Browser, nonce: &str) -> (Value, String) {
        let page = island(&browser.page(nonce).await, "presence-data");
        let csrf = page["csrf"].as_str().unwrap().to_owned();
        let options = browser
            .action(
                nonce,
                &csrf,
                "challenge",
                &json!({"consent_view_digest": page["consent_view_digest"]}),
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        (options, csrf)
    }

    /// Answers `options` with the fixture passkey and returns the HTTP
    /// status, the response body and the assertion.
    async fn assert_once(
        browser: &Browser,
        nonce: &str,
        options: &Value,
        csrf: &str,
    ) -> (u16, Value, Value) {
        let assertion = browser.signed_assertion(options, 0, options["rp_id"].as_str().unwrap());
        let (status, body) = answer(browser, nonce, csrf, &assertion).await;
        (status, body, assertion)
    }

    /// Posts `assertion` and returns the HTTP status and the response body.
    async fn answer(browser: &Browser, nonce: &str, csrf: &str, assertion: &Value) -> (u16, Value) {
        let response = browser
            .action(nonce, csrf, "assertion", assertion)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    /// The state an attestation by another handle leaves when that handle
    /// stops before the durable consent: the entry attested through the
    /// production attester with its row, and the record without consent.
    fn attested_without_consent(f: &Fixture) -> PendingApproval {
        let policy = f.core.current_policy();
        let mut store = PendingApprovalStore::open(f.core.store_path()).unwrap();
        attest_and_persist(
            &mut store,
            &f.entry,
            &ATTESTATION_KEY,
            &f.core.binding(),
            Surface::Serve,
            ConsentAudit::Writer(&mut f.core.audit_writer()),
            ConsentAuthorization::Mainnet {
                presence: f.core.presence(&f.entry, &policy),
                policy: &policy,
            },
            |_, _| Err("no toolset grant in a mainnet consent".to_owned()),
        )
        .unwrap();
        store.get(&f.entry.approval_nonce).unwrap().clone()
    }

    /// The state a strict `approve --id` leaves when it stops before the
    /// durable consent: the entry attested with its anchored row and its
    /// publication handoff, and the record without consent.
    fn strictly_attested_without_consent(f: &Fixture) -> PendingApproval {
        let policy = f.core.current_policy();
        let mut store = PendingApprovalStore::open(f.core.store_path()).unwrap();
        let mut writer = if f.keyed {
            f.keyed_writer()
        } else {
            f.core.audit_writer()
        };
        let (_, reference) = attest_and_persist_with_row(
            &mut store,
            &f.entry,
            &ATTESTATION_KEY,
            &f.core.binding(),
            Surface::Cli,
            ConsentAudit::Writer(&mut writer),
            ConsentAuthorization::Mainnet {
                presence: f.presence(),
                policy: &policy,
            },
            |_, _| Err("no toolset grant in a mainnet consent".to_owned()),
        )
        .unwrap();
        assert!(reference.is_none(), "the direct writer anchors the row");
        store.get(&f.entry.approval_nonce).unwrap().clone()
    }

    /// The window file's bytes.
    fn window(f: &Fixture) -> Vec<u8> {
        std::fs::read(f.store.path()).unwrap()
    }

    #[tokio::test]
    #[serial_test::serial]
    #[serial_test::serial(mainnet_clock)]
    async fn inbox_precheck_requires_a_real_record_in_both_listeners() {
        for signed in [false, true] {
            let (mut f, _tls) = if signed {
                let (f, tls) = signed_fixture();
                (f, Some(tls))
            } else {
                (Fixture::new(), None)
            };
            f.entry = f.core.payment(300_000);
            PendingApprovalStore::open(f.core.store_path())
                .unwrap()
                .insert(f.entry.clone(), f.entry.created_at_unix_ms)
                .unwrap();
            let before = window(&f);
            let (listener, browser) = Browser::start(&f, signed).await;
            let page = browser.page(&f.entry.approval_nonce).await;
            let data = island(&page, "presence-data");
            let response = browser
                .action(
                    &f.entry.approval_nonce,
                    data["csrf"].as_str().unwrap(),
                    "challenge",
                    &json!({"consent_view_digest": data["consent_view_digest"]}),
                )
                .send()
                .await
                .unwrap();
            let status = response.status();
            let body: Value = response.json().await.unwrap();
            assert_eq!(status, 200);
            assert_eq!(
                body["status"], "not_found",
                "real durable precheck refuses before a challenge: {body}"
            );
            assert!(body.get("challenge").is_none());
            assert_eq!(window(&f), before);
            assert_eq!(attested_rows(&f), 0);
            listener.shutdown().await;
        }
    }

    /// Approves `entry` through the context `serve` installs, under a fresh
    /// verified presence, as the loopback inbox's assertion route does.
    fn approve(f: &Fixture, entry: &PendingApproval) -> Outcome {
        let context = f.context();
        apply_decision(
            &context,
            Decision::Approve {
                nonce: entry.approval_nonce.clone(),
                shown_view_digest: Some(
                    approval_view_digest(entry, &context.context.binding()).unwrap(),
                ),
            },
            RequestIdentity::Mainnet(f.core.presence(entry, &f.core.current_policy())),
        )
    }

    /// The approval rows naming `f`'s entry in its audit log.
    fn attested_rows(f: &Fixture) -> usize {
        std::fs::read_to_string(f.core.audit_path())
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains("\"approval_attested\""))
            .count()
    }

    /// A consent through either listener that `serve` starts commits to the
    /// durable record before the attestation response. The record names its
    /// row `written`, and its first mint then succeeds. A published consent
    /// also commits its verified direct delivery; a compatibility consent
    /// commits none.
    #[tokio::test]
    #[serial_test::serial]
    async fn serve_installs_the_consent_adapter_for_both_listeners() {
        for (signed, published) in [(false, false), (true, false), (false, true), (true, true)] {
            let (mut f, _files) = if signed {
                let (f, files) = signed_fixture();
                (f, Some(files))
            } else {
                (Fixture::new(), None)
            };
            let _published = if published {
                Some(publish(&mut f, true).await)
            } else {
                None
            };
            let nonce = f.entry.approval_nonce.clone();
            let (listener, browser) = Browser::start(&f, signed).await;
            let page = island(&browser.page(&nonce).await, "presence-data");
            let csrf = page["csrf"].as_str().unwrap().to_owned();
            let options: Value = browser
                .action(
                    &nonce,
                    &csrf,
                    "challenge",
                    &json!({"consent_view_digest": page["consent_view_digest"]}),
                )
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let assertion =
                browser.signed_assertion(&options, 0, options["rp_id"].as_str().unwrap());
            let response = browser
                .action(&nonce, &csrf, "assertion", &assertion)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200, "{signed}");
            let body: Value = response.json().await.unwrap();
            assert_eq!(body["status"], "attested", "{signed}: {body}");
            let consent = f.view().record.consent.expect("durable consent");
            assert_eq!(
                consent.payload.as_ref().unwrap().row_provenance,
                Some(RowProvenance::Written),
                "{signed}"
            );
            assert_eq!(
                consent.delivery,
                if published { direct(&f) } else { None },
                "{signed}: the published route commits its verified delivery"
            );
            f.clock.set(consent.consent_at_ms);
            f.store
                .mint_authorization(f.core.profile(), &f.mint())
                .unwrap();
            listener.shutdown().await;
        }
    }

    /// A value entry that no durable record names keeps the inbox path of an
    /// approval prepared before records existed: it attests and the window
    /// file keeps its bytes.
    #[test]
    #[serial_test::serial]
    fn inbox_consent_without_a_record_keeps_todays_path() {
        let f = Fixture::new();
        let entry = f.core.payment(300_000);
        PendingApprovalStore::open(f.core.store_path())
            .unwrap()
            .insert(entry.clone(), entry.created_at_unix_ms)
            .unwrap();
        let window = std::fs::read(f.store.path()).unwrap();
        let outcome = approve(&f, &entry);
        assert!(
            matches!(
                outcome,
                Outcome::Attested {
                    attestation: Some(_),
                    ..
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(std::fs::read(f.store.path()).unwrap(), window);
    }

    /// The consent commit runs after the inbox store is released: inside the
    /// window commit, another handle opens the inbox store.
    #[test]
    #[serial_test::serial]
    fn consent_paths_hold_no_inbox_lock_across_the_window_commit() {
        let f = Fixture::new();
        let opened = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let seen = std::rc::Rc::clone(&opened);
        let path = f.core.store_path();
        let observed = observe_commit(move |point| {
            if point == COMMIT_FAULT_AFTER_PREPARED {
                seen.borrow_mut()
                    .push(PendingApprovalStore::open(path.clone()).is_ok());
            }
        });
        let outcome = approve(&f, &f.entry);
        drop(observed);
        assert!(matches!(outcome, Outcome::Attested { .. }), "{outcome:?}");
        assert_eq!(*opened.borrow(), [true]);
        assert!(f.view().record.consent.is_some());
    }

    /// A crash inside the consent commit leaves an attested entry and a record
    /// without consent, and the approve reports no attestation. A repeated
    /// approve completes the consent from the stored receipt as `recovered`,
    /// writes no second row, and keeps its refusal.
    #[test]
    #[serial_test::serial]
    fn a_crashed_consent_commit_recovers_without_a_second_row() {
        let f = Fixture::new();
        let crash = arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED);
        assert_eq!(approve(&f, &f.entry), Outcome::Unavailable);
        drop(crash);
        let stored = PendingApprovalStore::open(f.core.store_path())
            .unwrap()
            .get(&f.entry.approval_nonce)
            .unwrap()
            .clone();
        assert!(stored.attestation_blob_b64.is_some());
        assert!(f.view().record.consent.is_none());
        assert_eq!(attested_rows(&f), 1);
        let outcome = approve(&f, &f.entry);
        assert!(
            matches!(
                outcome,
                Outcome::PresenceRefused {
                    code: "approval.presence_consumed",
                    ..
                }
            ),
            "{outcome:?}"
        );
        let consent = f.view().record.consent.expect("recovered consent");
        assert_eq!(
            consent.consent_at_ms,
            stored.mainnet_presence.unwrap().verified_at_unix_ms()
        );
        assert_eq!(
            consent.payload.unwrap().row_provenance,
            Some(RowProvenance::Recovered)
        );
        assert_eq!(attested_rows(&f), 1);
    }

    /// No consent path requests the window lock while it holds the inbox
    /// store or the policy admission: a fresh approve through the loopback
    /// listener, a retry of its assertion, the stored page and a repeated
    /// approve, compatibility and published alike. The observer sees every
    /// request for the fixture's window lock and tries the inbox store and
    /// the lock itself at that moment, so the completion's commit finds both
    /// released.
    #[tokio::test]
    #[serial_test::serial]
    async fn consent_requests_no_window_lock_while_the_inbox_is_held() {
        for published in [true, false] {
            consent_window_lock_order(published).await;
        }
    }

    async fn consent_window_lock_order(published: bool) {
        let mut f = Fixture::new();
        let _published = if published {
            Some(publish(&mut f, true).await)
        } else {
            None
        };
        let nonce = f.entry.approval_nonce.clone();
        let lock = window_lock_path(f.store.path(), &f.core.profile().policy_window_state_key_id);
        let inbox = f.core.store_path();
        let requests = Arc::new(Mutex::new((0_usize, 0_usize, 0_usize)));
        let seen = Arc::clone(&requests);
        let observed = lock_requests::observe(move |path| {
            if path == lock {
                let held = PendingApprovalStore::open(inbox.clone()).is_err();
                // The policy admission is a guard of this lock file, so a
                // request it still holds finds the file locked.
                let admitted =
                    std::fs::File::open(&lock).is_ok_and(|file| file.try_lock().is_err());
                let mut counts = seen.lock().unwrap();
                counts.0 += 1;
                counts.1 += usize::from(held);
                counts.2 += usize::from(admitted);
            }
        });
        let (listener, browser) = Browser::start(&f, false).await;
        let page = island(&browser.page(&nonce).await, "presence-data");
        let csrf = page["csrf"].as_str().unwrap().to_owned();
        let options: Value = browser
            .action(
                &nonce,
                &csrf,
                "challenge",
                &json!({"consent_view_digest": page["consent_view_digest"]}),
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let assertion = browser.signed_assertion(&options, 0, options["rp_id"].as_str().unwrap());
        let fresh = browser
            .action(&nonce, &csrf, "assertion", &assertion)
            .send()
            .await
            .unwrap();
        assert_eq!(fresh.status(), 200);
        let retry = browser
            .action(&nonce, &csrf, "assertion", &assertion)
            .send()
            .await
            .unwrap();
        assert_ne!(retry.status(), 200);
        browser.page(&nonce).await;
        listener.shutdown().await;
        // The repeat opens its own serving writer once the listener's is gone.
        let repeated = approve(&f, &f.entry);
        assert!(
            matches!(
                repeated,
                Outcome::PresenceRefused {
                    code: "approval.presence_consumed",
                    ..
                }
            ),
            "{repeated:?}"
        );
        drop(observed);
        let (requested, while_held, while_admitted) = *requests.lock().unwrap();
        assert!(requested > 0, "the observer sees the window lock");
        assert_eq!(
            while_held, 0,
            "window lock requests while the inbox is held"
        );
        assert_eq!(
            while_admitted, 0,
            "window lock requests, the completion's commit among them, while the admission is held"
        );
        let consent = f.view().record.consent.expect("durable consent");
        assert_eq!(consent.delivery, if published { direct(&f) } else { None });
    }

    /// A crash after the consent row and before the attestation leaves one row,
    /// an unattested entry and a record without consent. The next approve
    /// attests and commits one consent; the two rows name the same nonce.
    /// A published consent behaves the same and commits its direct delivery.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_crash_after_the_row_approves_again_with_one_consent() {
        for published in [false, true] {
            let mut f = Fixture::new();
            let _published = if published {
                Some(publish(&mut f, true).await)
            } else {
                None
            };
            stellar_agent_core::approval::attest::consent_test_seam::on_written(
                &f.core.store_path(),
                || panic!("the process stops after the consent row"),
            );
            let crashed =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| approve(&f, &f.entry)));
            assert!(crashed.is_err(), "{published}");
            assert_eq!(attested_rows(&f), 1, "{published}");
            assert!(f.view().record.consent.is_none(), "{published}");
            let outcome = approve(&f, &f.entry);
            assert!(
                matches!(
                    outcome,
                    Outcome::Attested {
                        attestation: Some(_),
                        ..
                    }
                ),
                "{published}: {outcome:?}"
            );
            let consent = f.view().record.consent.expect("one durable consent");
            assert_eq!(
                consent.payload.as_ref().unwrap().row_provenance,
                Some(RowProvenance::Written),
                "{published}"
            );
            assert_eq!(
                consent.delivery,
                if published { direct(&f) } else { None },
                "{published}"
            );
            assert_eq!(attested_rows(&f), 2, "{published}");
        }
    }

    /// A crash after the attestation and before the consent commit leaves an
    /// attested entry. The stored page recovers the consent from the stored
    /// receipt once; a second page writes nothing and no route writes a row.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_crash_after_the_attestation_recovers_once() {
        let f = Fixture::new();
        let stored = attested_without_consent(&f);
        let blob = stored.attestation_blob_b64.clone().unwrap();
        assert!(f.view().record.consent.is_none());
        let (listener, browser) = Browser::start(&f, false).await;
        assert!(browser.page(&f.entry.approval_nonce).await.contains(&blob));
        let consent = f.view().record.consent.expect("recovered consent");
        assert_eq!(
            consent.consent_at_ms,
            stored.mainnet_presence.unwrap().verified_at_unix_ms()
        );
        assert_eq!(
            consent.payload.unwrap().row_provenance,
            Some(RowProvenance::Recovered)
        );
        let bytes = window(&f);
        assert!(browser.page(&f.entry.approval_nonce).await.contains(&blob));
        assert_eq!(window(&f), bytes);
        assert_eq!(attested_rows(&f), 1);
        listener.shutdown().await;
    }

    /// The inbox's own consent is a compatibility consent and stores no
    /// publication handoff, while its recording commits consent.
    #[test]
    #[serial_test::serial]
    fn an_inbox_consent_stores_no_publication_handoff() {
        let f = Fixture::new();
        let outcome = approve(&f, &f.entry);
        assert!(matches!(outcome, Outcome::Attested { .. }), "{outcome:?}");
        let stored = PendingApprovalStore::open(f.core.store_path())
            .unwrap()
            .get(&f.entry.approval_nonce)
            .unwrap()
            .clone();
        assert!(stored.mainnet_presence.is_some());
        assert!(stored.consent_publication.is_none());
        assert!(f.view().record.consent.unwrap().delivery.is_none());
    }

    /// A strict consent attested without its durable commit keeps the
    /// publication handoff it stored beside the blob and receipt. A repeated
    /// approve and the stored page complete the consent as `recovered`
    /// without delivery facts, and leave the inbox file's bytes unchanged.
    #[tokio::test]
    #[serial_test::serial]
    async fn inbox_recovery_keeps_a_stored_publication_handoff() {
        let f = Fixture::new();
        let stored = strictly_attested_without_consent(&f);
        assert!(stored.consent_publication.is_some());
        let verified =
            verify_consent_publication(&stored, &ATTESTATION_KEY, &f.core.binding()).unwrap();
        assert!(verified.is_direct_anchored());
        assert!(f.view().record.consent.is_none());
        let inbox = std::fs::read(f.core.store_path()).unwrap();
        let outcome = approve(&f, &f.entry);
        assert!(
            matches!(
                outcome,
                Outcome::PresenceRefused {
                    code: "approval.presence_consumed",
                    ..
                }
            ),
            "{outcome:?}"
        );
        let consent = f.view().record.consent.expect("recovered consent");
        assert_eq!(
            consent.payload.as_ref().unwrap().row_provenance,
            Some(RowProvenance::Recovered)
        );
        assert!(consent.delivery.is_none());
        assert_eq!(std::fs::read(f.core.store_path()).unwrap(), inbox);
        let bytes = window(&f);
        let (listener, browser) = Browser::start(&f, false).await;
        let blob = stored.attestation_blob_b64.clone().unwrap();
        assert!(browser.page(&f.entry.approval_nonce).await.contains(&blob));
        listener.shutdown().await;
        assert_eq!(window(&f), bytes);
        assert_eq!(std::fs::read(f.core.store_path()).unwrap(), inbox);
        assert_eq!(attested_rows(&f), 1);
    }

    /// A crash after the generation commit leaves the consent durable, and
    /// the approve reports no attestation. A repeated approve changes nothing
    /// and keeps its refusal.
    #[test]
    #[serial_test::serial]
    fn a_crash_after_the_commit_keeps_one_consent() {
        let f = Fixture::new();
        let crash = arm_accounting_fault(COMMIT_FAULT_AFTER_COUNTER);
        assert_eq!(approve(&f, &f.entry), Outcome::Unavailable);
        drop(crash);
        let consent = f.view().record.consent.expect("the committed consent");
        let bytes = window(&f);
        let outcome = approve(&f, &f.entry);
        assert!(
            matches!(
                outcome,
                Outcome::PresenceRefused {
                    code: "approval.presence_consumed",
                    ..
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(f.view().record.consent, Some(consent));
        assert_eq!(window(&f), bytes);
        assert_eq!(attested_rows(&f), 1);
    }

    /// A restart with a clock earlier than the record, or later than both of
    /// its windows, recovers the consent at the stored receipt's time, never
    /// at the restart clock. Under the earlier clock no mint admits it yet;
    /// under the later one the record reads expired and no mint admits it.
    /// Neither writes a row.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_restart_clock_neither_revives_nor_releases_early() {
        for later in [false, true] {
            let f = Fixture::new();
            let stored = attested_without_consent(&f);
            let blob = stored.attestation_blob_b64.clone().unwrap();
            let verified_at = stored.mainnet_presence.unwrap().verified_at_unix_ms();
            f.clock.set(if later {
                verified_at + 900_001
            } else {
                f.entry.created_at_unix_ms - 1
            });
            let (listener, browser) = Browser::start(&f, false).await;
            assert!(browser.page(&f.entry.approval_nonce).await.contains(&blob));
            let view = f.view();
            assert_eq!(view.expired, later, "{later}");
            let consent = view.record.consent.expect("recovered consent");
            assert_eq!(consent.consent_at_ms, verified_at, "{later}");
            let refused = f.store.mint_authorization(f.core.profile(), &f.mint());
            assert!(
                matches!(
                    refused,
                    Err(WindowStoreError::AuthorizationRefused {
                        precondition: MainnetPrecondition::ApprovalExpired
                    })
                ),
                "{later}: {refused:?}"
            );
            assert_eq!(attested_rows(&f), 1);
            listener.shutdown().await;
        }
    }

    /// Two stored pages served at once both recover the same consent: one
    /// consent, both pages show the blob, and no row is written.
    #[tokio::test]
    #[serial_test::serial]
    async fn competing_recoveries_record_one_consent() {
        let f = Fixture::new();
        let stored = attested_without_consent(&f);
        let blob = stored.attestation_blob_b64.clone().unwrap();
        let (listener, browser) = Browser::start(&f, false).await;
        let (first, second) = tokio::join!(
            browser.page(&f.entry.approval_nonce),
            browser.page(&f.entry.approval_nonce)
        );
        assert!(first.contains(&blob) && second.contains(&blob));
        let consent = f.view().record.consent.expect("one consent");
        assert_eq!(
            consent.consent_at_ms,
            stored.mainnet_presence.unwrap().verified_at_unix_ms()
        );
        assert_eq!(attested_rows(&f), 1);
        listener.shutdown().await;
    }

    /// A record that can no longer take consent (revoked after the
    /// attestation) refuses the recovery: the stored page shows no blob and
    /// the record keeps every lifecycle path, a revocation lookup and a no-op
    /// repeat, while its mint refuses as revoked.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_unusable_record_hides_the_blob_and_keeps_its_lifecycle() {
        let f = Fixture::new();
        let stored = attested_without_consent(&f);
        let blob = stored.attestation_blob_b64.unwrap();
        RevocationAccess::revoke(&f.access(), &f.entry.approval_nonce, Surface::Cli, None).unwrap();
        let bytes = window(&f);
        let (listener, browser) = Browser::start(&f, false).await;
        assert!(!browser.page(&f.entry.approval_nonce).await.contains(&blob));
        assert_eq!(window(&f), bytes);
        assert!(f.view().record.consent.is_none());
        listener.shutdown().await;
        let access = f.access();
        let view = RevocationAccess::lookup(&access, &f.entry.approval_nonce).unwrap();
        assert_eq!(view.state, "revoked");
        assert_eq!(
            RevocationAccess::revoke(&access, &f.entry.approval_nonce, Surface::Cli, None).unwrap(),
            view
        );
        assert_eq!(window(&f), bytes);
        assert!(matches!(
            f.store.mint_authorization(f.core.profile(), &f.mint()),
            Err(WindowStoreError::AuthorizationRefused {
                precondition: MainnetPrecondition::ApprovalRevoked
            })
        ));
    }

    /// A published value entry gets a challenge in either listener only while
    /// its record's evidence reservation can be reacquired. An unready scope
    /// and a full scope issue none and leave the window file unchanged. With
    /// one free slot, the first challenge reserves it and a repeated one
    /// reacquires the same slot at capacity. A refused challenge answers
    /// HTTP 503 with status `unavailable`. Pins are not repeated here: the precheck refuses them
    /// in `ConsentAdmission::reacquire`, which the network test
    /// `routed_admission_refuses_pins_and_orphans` pins. The missing record
    /// is `inbox_precheck_requires_a_real_record_in_both_listeners`.
    #[tokio::test]
    #[serial_test::serial]
    #[serial_test::serial(mainnet_clock)]
    async fn inbox_challenge_requires_reservation_in_both_listeners() {
        for signed in [false, true] {
            for mode in ["inventory", "capacity", "reserved"] {
                let (mut f, _files) = if signed {
                    let (f, files) = signed_fixture();
                    (f, Some(files))
                } else {
                    (Fixture::new(), None)
                };
                let _published = publish(&mut f, mode != "inventory").await;
                let max = stellar_agent_core::audit_log::MAX_EVIDENCE_ENTRIES;
                fill(&f, if mode == "capacity" { max } else { max - 1 });
                let before = window(&f);
                let (listener, browser) = Browser::start(&f, signed).await;
                let nonce = &f.entry.approval_nonce;
                for _ in 0..2 {
                    let page = island(&browser.page(nonce).await, "presence-data");
                    let response = browser
                        .action(
                            nonce,
                            page["csrf"].as_str().unwrap(),
                            "challenge",
                            &json!({"consent_view_digest": page["consent_view_digest"]}),
                        )
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(
                        response.status(),
                        if mode == "reserved" { 200 } else { 503 },
                        "{signed} {mode}"
                    );
                    let options: Value = response.json().await.unwrap();
                    assert_eq!(
                        options.get("challenge").is_some(),
                        mode == "reserved",
                        "{signed} {mode}: a challenge needs the reservation: {options}"
                    );
                    if mode != "reserved" {
                        assert_eq!(
                            options["status"], "unavailable",
                            "{signed} {mode}: a refused admission answers unavailable"
                        );
                    }
                }
                assert_eq!(window(&f), before, "{signed} {mode}");
                assert_eq!(attested_rows(&f), 0);
                listener.shutdown().await;
            }
        }
    }

    /// A fresh published consent in either listener attests strictly and
    /// answers `attested` only after its direct delivery commits. A failed
    /// publication answers without the blob and commits no consent, while
    /// the entry keeps its attestation and verified handoff. A scope that
    /// becomes unready after the challenge refuses before the row and the
    /// attestation.
    #[tokio::test]
    #[serial_test::serial]
    async fn inbox_fresh_publication_precedes_blob() {
        for signed in [false, true] {
            for mode in ["published", "fault", "inventory"] {
                let fail = mode == "fault";
                let (mut f, _files) = if signed {
                    let (f, files) = signed_fixture();
                    (f, Some(files))
                } else {
                    (Fixture::new(), None)
                };
                let _published = publish(&mut f, true).await;
                let nonce = f.entry.approval_nonce.clone();
                let (listener, browser) = Browser::start(&f, signed).await;
                let (options, csrf) = challenge(&browser, &nonce).await;
                let _unready = (mode == "inventory").then(UnreadableSiblingProfile::plant);
                let fault = fail.then(|| arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED));
                let (_, body, _) = assert_once(&browser, &nonce, &options, &csrf).await;
                drop(fault);
                listener.shutdown().await;
                let stored = PendingApprovalStore::open(f.core.store_path())
                    .unwrap()
                    .get(&nonce)
                    .unwrap()
                    .clone();
                if mode == "inventory" {
                    assert_ne!(body["status"], "attested", "{signed}: {body}");
                    assert!(
                        stored.attestation_blob_b64.is_none(),
                        "{signed}: the repeated admission check precedes the attestation"
                    );
                    assert_eq!(attested_rows(&f), 0);
                    continue;
                }
                let blob = stored.attestation_blob_b64.clone().unwrap();
                assert!(
                    stored.consent_publication.is_some(),
                    "{signed} {fail}: strict attestation"
                );
                let consent = f.view().record.consent;
                if fail {
                    assert_ne!(body["status"], "attested", "{signed}: {body}");
                    assert!(!body.to_string().contains(&blob), "{signed}: {body}");
                    assert!(consent.is_none(), "{signed}");
                } else {
                    assert_eq!(
                        body["status"], "attested",
                        "{signed}: a published consent answers after its delivery commits: {body}"
                    );
                    assert_eq!(consent.unwrap().delivery, direct(&f), "{signed}");
                }
                assert_eq!(attested_rows(&f), 1);
            }
        }
    }

    /// A repeated approve of a published, attested entry without durable
    /// consent completes it from the verified handoff before its unchanged
    /// consumed refusal: original receipt time, direct delivery, no new row.
    /// A scope that becomes unready after the attestation fails the
    /// reacquisition with `audit.outbox_evidence_unusable`, so the repeat
    /// answers unavailable and commits no consent.
    #[tokio::test]
    #[serial_test::serial]
    async fn inbox_repeat_publishes_before_consumed() {
        let mut f = Fixture::new();
        let _published = publish(&mut f, true).await;
        let stored = strictly_attested_without_consent(&f);
        let unready = UnreadableSiblingProfile::plant();
        assert_eq!(
            DurableConsents::new(f.core.name(), f.core.profile())
                .precheck(&stored)
                .unwrap_err()
                .code(),
            "audit.outbox_evidence_unusable"
        );
        let outcome = approve(&f, &f.entry);
        assert!(matches!(outcome, Outcome::Unavailable), "{outcome:?}");
        assert!(
            f.view().record.consent.is_none(),
            "inventory: the repeat reacquires before it publishes"
        );
        assert_eq!(attested_rows(&f), 1);
        drop(unready);
        let outcome = approve(&f, &f.entry);
        assert!(
            matches!(
                outcome,
                Outcome::PresenceRefused {
                    code: "approval.presence_consumed",
                    ..
                }
            ),
            "{outcome:?}"
        );
        let consent = f
            .view()
            .record
            .consent
            .expect("the repeat publishes before its refusal");
        assert_eq!(consent.delivery, direct(&f));
        assert_eq!(
            consent.consent_at_ms,
            stored.mainnet_presence.unwrap().verified_at_unix_ms()
        );
        assert_eq!(attested_rows(&f), 1);
    }

    /// A consumed assertion retry in either listener completes a published
    /// grant whose first publication failed, once, before the consumed
    /// refusal: no challenge is issued and one row remains.
    #[tokio::test]
    #[serial_test::serial]
    async fn inbox_consumed_retry_publishes_once() {
        for signed in [false, true] {
            let (mut f, _files) = if signed {
                let (f, files) = signed_fixture();
                (f, Some(files))
            } else {
                (Fixture::new(), None)
            };
            let _published = publish(&mut f, true).await;
            let nonce = f.entry.approval_nonce.clone();
            let (listener, browser) = Browser::start(&f, signed).await;
            let (options, csrf) = challenge(&browser, &nonce).await;
            let fault = arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED);
            let (_, first, assertion) = assert_once(&browser, &nonce, &options, &csrf).await;
            drop(fault);
            assert_ne!(first["status"], "attested", "{signed}: {first}");
            assert!(f.view().record.consent.is_none());
            let (status, retry) = answer(&browser, &nonce, &csrf, &assertion).await;
            listener.shutdown().await;
            assert_ne!(
                status, 200,
                "{signed}: the retry keeps its refusal: {retry}"
            );
            assert!(retry.get("challenge").is_none());
            let consent = f
                .view()
                .record
                .consent
                .expect("the consumed retry publishes the grant");
            assert_eq!(consent.delivery, direct(&f), "{signed}");
            assert_eq!(attested_rows(&f), 1);
        }
    }

    /// The stored page of a published, attested entry shows its blob in
    /// either listener only after the verified handoff publishes. A missing
    /// or edited handoff and a failed commit hide the blob and commit
    /// nothing; a later page with the authentic handoff publishes without a
    /// second row. A scope that becomes unready after the attestation fails
    /// the reacquisition, so the page hides the blob until it is ready again.
    /// A scope that becomes unready after the commit leaves a committed
    /// consent shown: a later page shows the blob and a repeated approve
    /// answers `approval.presence_consumed`, as the CLI recovery does.
    #[tokio::test]
    #[serial_test::serial]
    async fn stored_page_requires_exact_publication() {
        for signed in [false, true] {
            for mode in [
                "authentic",
                "missing",
                "edited",
                "fault",
                "inventory",
                "committed",
            ] {
                let commits = matches!(mode, "authentic" | "committed");
                let (mut f, _files) = if signed {
                    let (f, files) = signed_fixture();
                    (f, Some(files))
                } else {
                    (Fixture::new(), None)
                };
                let _published = publish(&mut f, true).await;
                let authentic = strictly_attested_without_consent(&f);
                let blob = authentic.attestation_blob_b64.clone().unwrap();
                let replace = |entry: PendingApproval| {
                    let mut store = PendingApprovalStore::open(f.core.store_path()).unwrap();
                    store.remove(&entry.approval_nonce).unwrap();
                    let created = entry.created_at_unix_ms;
                    store.insert(entry, created).unwrap();
                };
                let mut changed = authentic.clone();
                match mode {
                    "missing" => changed.consent_publication = None,
                    "edited" => {
                        let mut raw = serde_json::to_value(&changed.consent_publication).unwrap();
                        raw["tag"] = json!("00".repeat(32));
                        changed.consent_publication = Some(serde_json::from_value(raw).unwrap());
                    }
                    _ => {}
                }
                replace(changed);
                let mut unready = (mode == "inventory").then(UnreadableSiblingProfile::plant);
                let (listener, browser) = Browser::start(&f, signed).await;
                let fault =
                    (mode == "fault").then(|| arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED));
                let shown = browser.page(&f.entry.approval_nonce).await.contains(&blob);
                drop(fault);
                assert_eq!(shown, commits, "{signed} {mode}");
                assert_eq!(
                    f.view().record.consent.is_some(),
                    commits,
                    "{signed} {mode}"
                );
                if mode == "committed" {
                    unready = Some(UnreadableSiblingProfile::plant());
                    assert!(
                        browser.page(&f.entry.approval_nonce).await.contains(&blob),
                        "{signed}: a committed consent shows in an unready scope"
                    );
                } else if !commits {
                    drop(unready.take());
                    replace(authentic.clone());
                    assert!(browser.page(&f.entry.approval_nonce).await.contains(&blob));
                }
                listener.shutdown().await;
                if mode == "committed" {
                    let committed = f.view().record.consent;
                    let context = f.context();
                    let outcome = apply_decision(
                        &context,
                        Decision::Approve {
                            nonce: f.entry.approval_nonce.clone(),
                            shown_view_digest: Some(
                                approval_view_digest(&f.entry, &context.context.binding()).unwrap(),
                            ),
                        },
                        RequestIdentity::Mainnet(f.presence()),
                    );
                    assert!(
                        matches!(
                            outcome,
                            Outcome::PresenceRefused {
                                code: "approval.presence_consumed",
                                ..
                            }
                        ),
                        "{signed}: {outcome:?}"
                    );
                    assert_eq!(f.view().record.consent, committed, "{signed}");
                }
                assert_eq!(
                    f.view().record.consent.unwrap().delivery,
                    direct(&f),
                    "{signed} {mode}"
                );
                assert_eq!(attested_rows(&f), 1);
            }
        }
    }
}
