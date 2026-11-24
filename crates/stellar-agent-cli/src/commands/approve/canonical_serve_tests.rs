use super::*;
use crate::common::mainnet_confirm::tests::{
    canonical_consent_tests::{park_staged, staged},
    confirmation_fixture,
};
use stellar_agent_approval_ui::decision::{
    Decision, IntentLookup, Outcome, RequestIdentity, apply_decision,
};
use stellar_agent_core::approval::{
    ApprovalContext, MemoFact, PendingApprovalStore, PresenceListener, approval_view_digest,
    issue_mainnet_intent_presence, mainnet_fixtures::MainnetConsentFixture,
    verify_mainnet_presence,
};
use stellar_agent_network::policy_state::{ApprovalStatus, PersistedWindowStore, RowProvenance};

#[test]
#[serial_test::serial]
fn canonical_installed_provider_and_completion_use_authenticated_records() {
    for signed in [false, true] {
        for kind in 0..4 {
            let (mut fixture, context, _) =
                confirmation_fixture(&format!("canonical-serve-{signed}-{kind}"));
            let credential = stellar_agent_test_support::webauthn::fixture_authenticator();
            if signed {
                fixture.sign_signed_origin_policy(
                    &[&credential],
                    &stellar_agent_core::approval::mainnet_fixtures::SIGNED_CERT_SPKI_SHA256,
                );
            }
            let (intent, summary, handle) = staged(&fixture, &context, kind, MemoFact::None, 0);
            let entry = park_staged(&fixture, &context, &intent, &summary, &handle);
            let current = fixture.authority().load_current().unwrap();
            let lookup = crate::common::mainnet_presence::StoredIntents::new(
                &fixture.store_path(),
                fixture.name(),
            );
            assert_eq!(
                lookup.lookup(&entry.approval_nonce, &current).unwrap(),
                Some(intent.clone()),
                "binary reads authenticated stored intent"
            );
            let (orphan, _) = fixture.intent_payment(120_000);
            PendingApprovalStore::open(fixture.store_path())
                .unwrap()
                .insert(orphan.clone(), orphan.created_at_unix_ms)
                .unwrap();
            assert_eq!(
                lookup
                    .lookup(&orphan.approval_nonce, &current)
                    .unwrap_err()
                    .code(),
                "approval.wrong_kind",
                "missing canonical record refuses"
            );
            let approval_context = ApprovalContext::from_profile(fixture.name(), fixture.profile());
            let listener =
                stellar_agent_core::approval::ListenerIdentity::capture(current.policy()).ok();
            let origin = MainnetConsentFixture::origin();
            let pending = issue_mainnet_intent_presence(
                &entry,
                &approval_context.binding(),
                current.policy(),
                if signed {
                    PresenceListener::SignedOrigin(listener.as_ref().unwrap())
                } else {
                    PresenceListener::Loopback(&origin)
                },
                Some(&intent),
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
                std::time::Instant::now(),
            )
            .unwrap();
            let assertion = MainnetConsentFixture::sign_issued(&credential, &pending);
            let presence = verify_mainnet_presence(
                pending,
                MainnetConsentFixture::input(&assertion),
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
                std::time::Instant::now(),
            )
            .unwrap();
            let crate::common::consent::OperatorRowSink::Writer(writer) =
                crate::common::consent::acquire_operator_row_sink(
                    fixture.profile(),
                    fixture.name(),
                )
                .unwrap()
            else {
                panic!("fixture writer")
            };
            let decision = install_durable_access(
                DecisionContext::new(
                    approval_context.clone(),
                    fixture.store_path(),
                    fixture.profile().attestation_key_id.clone(),
                    stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile(
                        fixture.name(),
                        fixture.profile(),
                    ),
                    writer,
                    None,
                )
                .with_mainnet_authority(fixture.authority()),
                fixture.name(),
                fixture.profile(),
            );
            let path = fixture.store_path();
            let lock = stellar_agent_core::policy::state_lock::window_lock_path(
                PersistedWindowStore::for_profile(fixture.name()).path(),
                &fixture.profile().policy_window_state_key_id,
            );
            let held = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let seen = held.clone();
            let observed =
                stellar_agent_core::policy::state_lock::lock_requests::observe(move |requested| {
                    if requested == lock && PendingApprovalStore::open(path.clone()).is_err() {
                        seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            let outcome = apply_decision(
                &decision,
                Decision::Approve {
                    nonce: entry.approval_nonce.clone(),
                    shown_view_digest: Some(
                        approval_view_digest(&entry, &approval_context.binding()).unwrap(),
                    ),
                },
                if signed {
                    RequestIdentity::SignedOrigin(presence)
                } else {
                    RequestIdentity::Mainnet(presence)
                },
            );
            assert!(
                matches!(outcome, Outcome::Attested { .. }),
                "installed canonical completion: {outcome:?}"
            );
            drop(observed);
            assert_eq!(
                held.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "installed completion releases inbox before window lock"
            );
            let record = ApprovalStatus::new(
                &PersistedWindowStore::for_profile(fixture.name()),
                fixture.profile(),
            )
            .find_by_operation(handle.id())
            .unwrap()
            .unwrap()
            .record;
            assert_eq!(record.subject, *intent.digest().as_bytes());
            assert_eq!(
                record.consent.unwrap().payload.unwrap().row_provenance,
                Some(RowProvenance::Written),
                "installed adapter commits written consent"
            );
        }
    }
}
