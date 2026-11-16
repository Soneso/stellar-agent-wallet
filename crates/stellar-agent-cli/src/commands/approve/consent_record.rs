//! Durable consent of mainnet value approvals decided in the inbox.

use stellar_agent_approval_ui::decision::{ConsentRecording, ConsentRowSource, VerifiedConsent};
use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::Profile;
use stellar_agent_network::operation_entry::{commit_consent, witnessed_completion};
use stellar_agent_network::policy_state::{ConsentPayload, ConsentRow, PersistedWindowStore};

/// The consent recording of the profile's durable approval records.
pub(super) struct DurableConsents {
    store: PersistedWindowStore,
    profile: Profile,
}

impl DurableConsents {
    pub(super) fn new(name: &str, profile: &Profile) -> Self {
        Self {
            store: PersistedWindowStore::for_profile(name),
            profile: profile.clone(),
        }
    }
}

impl ConsentRecording for DurableConsents {
    /// Reads the record that names the consent's nonce, then commits the
    /// consent under the window lock alone; the commit checks the witness
    /// against the record. An entry without a record keeps the path of an
    /// approval prepared before records existed, so nothing is written.
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
    use stellar_agent_core::approval::{
        ConsentAudit, ConsentAuthorization, PendingApproval, PendingApprovalStore, Surface,
        approval_view_digest, attest::attest_and_persist_with_row, attest_and_persist,
        mainnet_fixtures::ATTESTATION_KEY, verify_consent_publication,
    };
    use stellar_agent_core::policy::state_lock::{lock_requests, window_lock_path};
    use stellar_agent_network::mainnet::MainnetPrecondition;
    use stellar_agent_network::policy_state::store::commit_faults::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
        observe_commit,
    };
    use stellar_agent_network::policy_state::{RowProvenance, WindowStoreError};

    use super::super::revoke::tests::{Browser, Fixture, island, signed_fixture};

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
        let (_, reference) = attest_and_persist_with_row(
            &mut store,
            &f.entry,
            &ATTESTATION_KEY,
            &f.core.binding(),
            Surface::Cli,
            ConsentAudit::Writer(&mut f.core.audit_writer()),
            ConsentAuthorization::Mainnet {
                presence: f.core.presence(&f.entry, &policy),
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
    /// row `written`, and its first mint then succeeds.
    #[tokio::test]
    #[serial_test::serial]
    async fn serve_installs_the_consent_adapter_for_both_listeners() {
        for signed in [false, true] {
            let (f, _files) = if signed {
                let (f, files) = signed_fixture();
                (f, Some(files))
            } else {
                (Fixture::new(), None)
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
    /// store: a fresh approve through the loopback listener, a retry of its
    /// assertion and the stored page. The observer sees every request for the
    /// fixture's window lock and tries the inbox store at that moment.
    #[tokio::test]
    #[serial_test::serial]
    async fn consent_requests_no_window_lock_while_the_inbox_is_held() {
        let f = Fixture::new();
        let nonce = f.entry.approval_nonce.clone();
        let lock = window_lock_path(f.store.path(), &f.core.profile().policy_window_state_key_id);
        let inbox = f.core.store_path();
        let requests = Arc::new(Mutex::new((0_usize, 0_usize)));
        let seen = Arc::clone(&requests);
        let observed = lock_requests::observe(move |path| {
            if path == lock {
                let held = PendingApprovalStore::open(inbox.clone()).is_err();
                let mut counts = seen.lock().unwrap();
                counts.0 += 1;
                counts.1 += usize::from(held);
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
        drop(observed);
        let (requested, while_held) = *requests.lock().unwrap();
        assert!(requested > 0, "the observer sees the window lock");
        assert_eq!(
            while_held, 0,
            "window lock requests while the inbox is held"
        );
        assert!(f.view().record.consent.is_some());
    }

    /// A crash after the consent row and before the attestation leaves one row,
    /// an unattested entry and a record without consent. The next approve
    /// attests and commits one consent; the two rows name the same nonce.
    #[test]
    #[serial_test::serial]
    fn a_crash_after_the_row_approves_again_with_one_consent() {
        let f = Fixture::new();
        stellar_agent_core::approval::attest::consent_test_seam::on_written(
            &f.core.store_path(),
            || panic!("the process stops after the consent row"),
        );
        let crashed =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| approve(&f, &f.entry)));
        assert!(crashed.is_err());
        assert_eq!(attested_rows(&f), 1);
        assert!(f.view().record.consent.is_none());
        let outcome = approve(&f, &f.entry);
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
        let consent = f.view().record.consent.expect("one durable consent");
        assert_eq!(
            consent.payload.unwrap().row_provenance,
            Some(RowProvenance::Written)
        );
        assert_eq!(attested_rows(&f), 2);
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
}
