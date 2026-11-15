//! Real recorder refusals shared by command and tool adapter tests.
#![allow(clippy::unwrap_used, clippy::panic, reason = "fixture assertions")]

use super::*;
use crate::{SubmissionRecorder, WalletSubmissionRecorder};
use stellar_agent_core::audit_log::PolicyDecision;
use stellar_agent_core::policy::v1::{CheckedSizing, SizingBasis};

#[cfg(test)]
pub(in crate::policy_state) fn append_closed_intent(
    wire: &mut WireFile,
    epoch: [u8; 32],
    amount: i128,
    observed: u64,
) {
    let mut plan = crate::signed_intent::test_helpers::intent_fixture_plan(98, 1)
        .0
        .with_envelope_max_ledger(100)
        .unwrap();
    plan.facts.chain_scope = wire.chain_scope.unwrap();
    plan.facts.purpose = Some(IntentPurpose::Invoke);
    let entry = WindowEntry::new(
        StateKey::new("intent", 1, "total:native", 0),
        observed - 1,
        amount,
        WindowLimit::Total {
            asset: "native".into(),
            max_stroops: i128::MAX,
        },
    )
    .with_epoch(Some(epoch));
    let (proof, _) =
        install_intent_admission(wire, &plan.with_legs(&[entry]), observed - 1).unwrap();
    let intent = wire
        .signed_intents
        .iter_mut()
        .find(|i| Some(&i.intent_id) == proof.intent_id.as_ref())
        .unwrap();
    intent.generation = wire.generation;
    intent.expiry_observed_at_ms = Some(observed);
    intent.accounting_until_ms = Some(observed);
    intent.witness_lower = Some(101);
    intent.witness_upper = Some(102);
    wire.version = WIRE_VERSION_TOTAL_INTENTS;
}

/// Obtains a refusal from checked admission or final-envelope binding.
/// The caller holds a marked state sandbox and the serial test lock.
///
/// # Panics
/// Panics when the fixture fails to construct its intended refusal.
pub async fn recorder_refusal(case: &str) -> stellar_agent_core::WalletError {
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let profile = Profile::builder_testnet_named(
        "intent-adapter",
        "intent-adapter-owner",
        "account",
        "intent-adapter-nonce",
        "account",
    )
    .build();
    let store = PersistedWindowStore::at_path(dir.path().join("intent.window"));
    let _clock = crate::mainnet::clock::set_now_ms_for_test(1000);
    let pin_scope = PinScope::for_profile(store.path(), &profile);
    {
        let lock = WindowStoreLock::acquire_for(store.path(), &profile.policy_window_state_key_id)
            .unwrap();
        pin::write_for_test(
            &lock,
            &pin_scope,
            &pin::Pin::new(1, [0xd1; 32], [11; 32]).unwrap(),
        )
        .unwrap();
    }
    let entries = vec![
        WindowEntry::new(
            StateKey::new("intent-adapter", 1, "total:native", 0),
            1000,
            6,
            WindowLimit::Total {
                asset: "native".into(),
                max_stroops: 10,
            },
        )
        .with_epoch(Some([0xd1; 32])),
    ];
    let (plan, envelope) = crate::signed_intent::test_helpers::intent_fixture_plan(1, 60);
    let plan = plan.with_legs(&entries);
    let receipts = ReceiptStore::open_at(dir.path(), "intent-adapter").unwrap();
    let recorder = WalletSubmissionRecorder::new(
        &profile,
        "intent-adapter",
        "test",
        Some("stellar:testnet".into()),
        PolicyDecision::Allow,
        vec![],
        entries.clone(),
        receipts,
        store.clone(),
        None,
        None,
        "検証-é",
        1000,
    )
    .with_signing_sizing(CheckedSizing::for_test(SizingBasis::MeasuredValue, entries).unwrap());
    let proof = recorder.admit_signed_intent(&plan).await.unwrap();
    match case {
        "unavailable" => {
            let entry = pin_scope.pin_entry_ref();
            keyring_core::Entry::new(&entry.service, &entry.account)
                .unwrap()
                .set_password("不正-é")
                .unwrap();
        }
        "stale" => {
            let lock =
                WindowStoreLock::acquire_for(store.path(), &profile.policy_window_state_key_id)
                    .unwrap();
            pin::write_for_test(
                &lock,
                &pin_scope,
                &pin::Pin::new(2, [0xd2; 32], [11; 32]).unwrap(),
            )
            .unwrap();
        }
        "retired" => {
            let mut wire = store.read_for_inspection(&profile).unwrap().unwrap();
            wire.retired_total_epoch = Some([0xd1; 32]);
            let (key, _) = store.load_or_mint_key(&profile).unwrap();
            store.write_atomic(&key, &wire).unwrap();
            write_generation(&generation_entry_ref(&profile), &wire).unwrap();
        }
        "exhausted" => {
            return recorder
                .admit_signed_intent(
                    &crate::signed_intent::test_helpers::intent_fixture_plan(2, 60).0,
                )
                .await
                .err()
                .unwrap();
        }
        "binding" => {
            let exposure = proof.expose();
            let (_, other) = crate::signed_intent::test_helpers::intent_fixture_plan(2, 60);
            let facts =
                crate::BindFacts::from_envelope(&other, Caip2::Testnet.network_passphrase())
                    .unwrap();
            let intent = crate::SubmissionIntent {
                chain_scope: plan.chain_scope(),
                envelope_hash: facts.envelope_hash,
                tx_hash: facts.tx_hash,
                source: plan.facts.envelope_source.clone(),
                sequence: 2,
                max_time: 0,
                submission_ledger: 1,
                submission_anchor: None,
                send_by_ms: None,
                destinations: Default::default(),
            };
            let result = recorder
                .pre_send_bound(&intent, &crate::IntentBinding::new(&exposure, &other))
                .await;
            assert!(result.is_err(), "changed envelope sequence refuses binding");
            return result.err().unwrap();
        }
        "invalid" => {
            std::fs::write(store.path(), b"invalid authenticated state").unwrap();
        }
        _ => panic!("unknown refusal fixture"),
    }
    let _ = envelope;
    recorder.admit_signed_intent(&plan).await.err().unwrap()
}

/// Exercises total-only or mixed receipt bookkeeping through the recorder.
/// The caller holds a marked state sandbox and the serial test lock.
///
/// # Panics
/// Panics when an admission, binding, or exact amount assertion fails.
pub async fn assert_linked_recorder(mixed: bool) {
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let profile = Profile::builder_testnet_named(
        "intent",
        "intent-recorder",
        "account",
        "intent-nonce",
        "account",
    )
    .build();
    let store = PersistedWindowStore::at_path(dir.path().join("intent.window"));
    let _clock = crate::mainnet::clock::set_now_ms_for_test(1000);
    {
        let lock = WindowStoreLock::acquire_for(store.path(), &profile.policy_window_state_key_id)
            .unwrap();
        pin::write_for_test(
            &lock,
            &PinScope::for_profile(store.path(), &profile),
            &pin::Pin::new(1, [0xd1; 32], [11; 32]).unwrap(),
        )
        .unwrap();
    }
    let (fixture, envelope) = crate::signed_intent::test_helpers::intent_fixture_plan(1, 60);
    let total_key = StateKey::new("intent", 1, "total:native", 0);
    let mut entries = vec![
        WindowEntry::new(
            total_key.clone(),
            1000,
            6,
            WindowLimit::Total {
                asset: "native".into(),
                max_stroops: 10,
            },
        )
        .with_epoch(Some([0xd1; 32])),
    ];
    if mixed {
        entries.push(fixture.legs()[0].clone());
    }
    let plan = fixture.with_legs(&entries);
    let receipts = ReceiptStore::open_at(dir.path(), "intent").unwrap();
    let recorder = WalletSubmissionRecorder::new(
        &profile,
        "intent",
        "test",
        Some("stellar:testnet".into()),
        PolicyDecision::Allow,
        vec![],
        entries.clone(),
        receipts,
        store.clone(),
        None,
        None,
        "検証-é",
        1000,
    )
    .with_signing_sizing(CheckedSizing::for_test(SizingBasis::MeasuredValue, entries).unwrap());
    let exposure = recorder.admit_signed_intent(&plan).await.unwrap().expose();
    let facts =
        crate::BindFacts::from_envelope(&envelope, Caip2::Testnet.network_passphrase()).unwrap();
    let intent = crate::SubmissionIntent {
        chain_scope: plan.chain_scope(),
        envelope_hash: facts.envelope_hash,
        tx_hash: facts.tx_hash,
        source: plan.facts.envelope_source.clone(),
        sequence: 1,
        max_time: 0,
        submission_ledger: 1,
        submission_anchor: None,
        send_by_ms: None,
        destinations: Default::default(),
    };
    let binding = crate::IntentBinding::new(&exposure, &envelope);
    recorder.pre_send_bound(&intent, &binding).await.unwrap();
    assert_eq!(
        recorder
            .pre_send_bound(&intent, &binding)
            .await
            .unwrap_err()
            .code(),
        "submission.tx_already_submitted"
    );
    let wire = store.read_for_inspection(&profile).unwrap().unwrap();
    assert_eq!(total_in_file(&wire, &total_key, [0xd1; 32]).unwrap().0, 6);
    let memory = PolicyStateStore::new();
    store.load_into("intent", &profile, &memory).unwrap();
    assert_eq!(memory.query_epoch(&total_key, [0xd1; 32]).unwrap().0, 6);
    if mixed {
        assert_eq!(
            memory
                .query_window(&StateKey::new("intent", 1, "native", 60), 1000)
                .unwrap(),
            (60, 1)
        );
    }
}
